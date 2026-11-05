#!/usr/bin/env python3
"""Focused fail-closed tests for the VM-side GCP remote proof-action helper.

Tests use a TEST_ONLY fixture host. They never open live sockets, never invoke
gcloud, and never point ProductionHost at a fake runner that can emit PASS.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

TOOLS = Path(__file__).resolve().parent
ACTION_CONTRACT_PATH = TOOLS / "gcp_proof_action_contract.json"


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


subject = load_module("gcp_proof_remote_action_under_test", TOOLS / "gcp_proof_remote_action.py")


def test_shared_action_contract_matches_remote_helper_keys() -> None:
    contract = json.loads(ACTION_CONTRACT_PATH.read_text(encoding="ascii"))
    assert contract["contract"] == "winsvpn-gcp-proof-action-data-v1"
    assert contract["schema_version"] == 1
    assert {
        action: sorted(keys)
        for action, keys in subject.REMOTE_HELPER_DATA_KEYS.items()
    } == {
        action: sorted(record["remote_helper_data_keys"])
        for action, record in contract["actions"].items()
    }

PROJECT = "winsproof123"
FLEET = "123456789abc"
CONTROL = "proof-control-a1"
WINN3 = "proof-winn3-a1"
COVER = "proof-cover-a1"
RUN = "run-20260823-a"
SESSION = "session-20260823-a"
CORR = "correlation-20260823-a"
CLIENT_BUILD = "c" * 64
CHALLENGE = "b" * 64
START_UTC = "2026-08-24T12:00:00Z"
HANDSHAKE_UNIX = int(datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc).timestamp())
INSTANCE_ID = "1234567890123456789"
BOOT_ID = "11111111-1111-4111-8111-111111111111"
PROCESS_NONCE = "0123456789abcdef0123456789abcdef"
PROCESS_STARTED = "2026-08-24T11:00:00Z"
AWG_PEER = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
XRAY_USER = "proof-user"
HELPER_BYTES = b"#!/usr/bin/python3\nfixture-helper\n"
BROKER_BYTES = b"#!/usr/bin/python3\nfixture-broker\n"
WINN3_RX_BEFORE = 1000
WINN3_TX_BEFORE = 2000
WINN3_RX_AFTER = 11234
WINN3_TX_AFTER = 14567
WINN3_RX_DELTA = WINN3_RX_AFTER - WINN3_RX_BEFORE
WINN3_TX_DELTA = WINN3_TX_AFTER - WINN3_TX_BEFORE
AWG_RX_BEFORE = 500
AWG_TX_BEFORE = 600
AWG_RX_AFTER = 2500
AWG_TX_AFTER = 3600
XRAY_UPLINK_BEFORE = 700
XRAY_DOWNLINK_BEFORE = 800
XRAY_UPLINK_AFTER = 4700
XRAY_DOWNLINK_AFTER = 5800
ENVELOPE_KEYS = {
    "action",
    "boot_id",
    "challenge",
    "contract",
    "correlation_id",
    "data",
    "effect_kind",
    "effect_sha256",
    "ended_utc",
    "evidence",
    "fixture_only",
    "helper_hashes",
    "instance",
    "instance_id",
    "operation",
    "phase",
    "project",
    "request_sha256",
    "role",
    "run_id",
    "schema_version",
    "session_id",
    "started_utc",
    "state_sha256",
    "transaction",
}
EVIDENCE_KEYS = {
    "attempt_acknowledgements",
    "attempt_journal_after",
    "attempt_journal_after_awg",
    "attempt_journal_before",
    "awg_peers",
    "boot_id",
    "challenge",
    "client_build_identity",
    "ended_monotonic_ns",
    "instance",
    "instance_id",
    "interface_counters",
    "process_identity",
    "request_sha256",
    "role",
    "services",
    "started_monotonic_ns",
    "winn3_status",
    "xray_stats",
}
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
)


class FixtureAttemptBrokerIdentity:
    def __init__(self, host: "FixtureHost") -> None:
        payload = host.files.get(subject.ATTEMPT_BROKER_PATH)
        if type(payload) is not bytes or not payload:
            raise subject.RemoteActionError("attempt-broker executable is absent or unsafe")
        self._host = host
        self._payload = payload
        self._closed = False
        self._finished = False
        host.broker_holds += 1

    def finish(self) -> str:
        if self._closed or self._finished:
            raise subject.RemoteActionError("attempt-broker identity use is invalid")
        if self._host.files.get(subject.ATTEMPT_BROKER_PATH) != self._payload:
            raise subject.RemoteActionError("attempt-broker executable changed during use")
        self._finished = True
        self._host.broker_finishes += 1
        return subject.sha256_bytes(self._payload)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._host.broker_closes += 1


class FixtureHost:
    TEST_ONLY = True

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.file_queues: dict[str, list[bytes]] = {}
        self.commands: dict[tuple[str, ...], list[subject.CommandResult]] = {}
        self.command_defaults: dict[tuple[str, ...], subject.CommandResult] = {}
        self.http: dict[str, bytes] = {}
        self.runs: list[tuple[str, ...]] = []
        self.reads: list[str] = []
        self.writes: list[str] = []
        self.http_calls: list[str] = []
        self.protocol_attempts: list[tuple[str, str]] = []
        self.broker_holds = 0
        self.broker_finishes = 0
        self.broker_closes = 0
        self._mono = 1_000_000_000
        self._utc_index = 0
        self._lock = False

    def acquire_action_lock(self) -> None:
        if self._lock:
            raise subject.RemoteActionError("concurrent remote action is forbidden")
        self._lock = True

    def release_action_lock(self) -> None:
        self._lock = False

    def require_helper_identity_binding(self, record: dict[str, Any]) -> None:
        payload = self.files.get(subject.INSTALL_PATH)
        if not payload:
            raise subject.RemoteActionError("installed remote proof-action helper is unreadable")
        if (
            record["sha256"] != subject.sha256_bytes(payload)
            or record["bytes"] != len(payload)
            or record["path"] != subject.INSTALL_PATH
        ):
            raise subject.RemoteActionError("remote proof-action helper identity is stale")

    def monotonic_ns(self) -> int:
        self._mono += 10_000_000_000
        return self._mono

    def utc_now(self) -> str:
        stamp = datetime(
            2026, 8, 24, 12, 0, min(self._utc_index * 10, 59), tzinfo=timezone.utc
        )
        self._utc_index += 1
        return stamp.strftime("%Y-%m-%dT%H:%M:%SZ")

    def exists(self, path: str) -> bool:
        subject._forbid_credential_path(path)
        return path in self.files or bool(self.file_queues.get(path))

    def read_file(self, path: str) -> bytes:
        subject._forbid_credential_path(path)
        self.reads.append(path)
        queued = self.file_queues.get(path)
        if queued:
            return queued.pop(0)
        if path not in self.files:
            raise subject.RemoteActionError(f"local file {path} is unreadable")
        data = self.files[path]
        if not data:
            raise subject.RemoteActionError(f"local file {path} is empty")
        return data

    def write_file(self, path: str, data: bytes, mode: int) -> None:
        subject._forbid_credential_path(path)
        subject._forbid_uncontained_write(path)
        self.files[path] = data
        self.writes.append(path)

    def run(self, argv: list[str]) -> subject.CommandResult:
        key = tuple(argv)
        self.runs.append(key)
        queued = self.commands.get(key)
        if queued:
            return queued.pop(0)
        if key in self.command_defaults:
            return self.command_defaults[key]
        return subject.CommandResult(b"", b"absent\n", 127)

    def http_get(self, path: str) -> bytes:
        if path not in subject.ALLOWED_HTTP_PATHS:
            raise subject.RemoteActionError("http path is not allowlisted")
        self.http_calls.append(path)
        if path not in self.http:
            raise subject.RemoteActionError("local hub probe failed")
        return self.http[path]

    def hash_executable(self, path: str) -> str:
        return subject.sha256_bytes(self.read_file(path))

    def hold_attempt_broker_identity(self) -> FixtureAttemptBrokerIdentity:
        return FixtureAttemptBrokerIdentity(self)

    def require_root_owned_evidence(self, path: str) -> None:
        if not self.exists(path):
            raise subject.RemoteActionError(f"evidence file {path} is unreadable")

    def read_root_owned_evidence(self, path: str) -> bytes:
        self.require_root_owned_evidence(path)
        return self.read_file(path)

    def read_gateway_status_evidence(self, path: str) -> bytes:
        if path != subject.WINN3_STATUS_PATHS["data-winn3"]:
            raise subject.RemoteActionError("gateway status path is not the exact proof path")
        return self.read_file(path)

    def trigger_protocol_attempt(
        self, request: dict[str, Any], protocol: str, node: str
    ) -> dict[str, Any]:
        self.protocol_attempts.append((protocol, node))
        if request["action"] in {
            "connect-primary",
            "connect-cover-awg",
            "connect-cover-xray",
            "probe-winn3-block",
            "probe-cover-withdrawn",
        }:
            before = []
            if subject.ATTEMPT_JOURNAL_PATH in self.files:
                before = json.loads(
                    self.files[subject.ATTEMPT_JOURNAL_PATH].decode("ascii")
                )["events"]
            ordinal = len(before)
            result = (
                "failed"
                if protocol == "winn3"
                and request["action"] in {"probe-winn3-block", "probe-cover-withdrawn"}
                else "connected"
            )
            started = attempt_event(
                protocol,
                "started",
                "pending",
                self._mono + (ordinal + 1) * 1_000_000_000,
                ordinal + 1,
                node=node,
                action=request["action"],
            )
            finished = attempt_event(
                protocol,
                "finished",
                result,
                self._mono + (ordinal + 2) * 1_000_000_000,
                ordinal + 2,
                node=node,
                action=request["action"],
            )
            self.files[subject.ATTEMPT_JOURNAL_PATH] = dumps(
                attempt_journal([*before, started, finished])
            )
        return {
            "action": request["action"],
            "contract": subject.ATTEMPT_ACK_CONTRACT,
            "correlation_id": request["correlation_id"],
            "node": node,
            "protocol": protocol,
            "session_id": request["session_id"],
            "state": "completed",
        }


def dumps(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def proc_net_dev(counters: dict[str, tuple[int, int]]) -> bytes:
    lines = [
        "Inter-|   Receive                                                |  Transmit",
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed",
    ]
    for name, (rx, tx) in counters.items():
        lines.append(
            f"  {name}: {rx} 1 0 0 0 0 0 0 {tx} 1 0 0 0 0 0 0"
        )
    return ("\n".join(lines) + "\n").encode("ascii")


def ip_link_stats(counters: dict[str, tuple[int, int]]) -> bytes:
    rows = [
        {
            "ifname": name,
            "stats64": {"rx": {"bytes": rx}, "tx": {"bytes": tx}},
        }
        for name, (rx, tx) in counters.items()
    ]
    return json.dumps(rows, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def argv_for(action: str, **overrides: str) -> list[str]:
    phase = overrides.get("phase") or (
        subject.PHASE_MUTATE if action in subject.MUTATING_ACTIONS else subject.PHASE_EXERCISE
    )
    allowed = subject.ACTION_PHASE_ROLES[(action, phase)]
    role = overrides.get("role")
    if role is None:
        assert len(allowed) == 1
        role = next(iter(allowed))
    instance = overrides.get("instance") or {
        "control": CONTROL,
        "data-cover": COVER,
        "data-winn3": WINN3,
    }[role]
    values = {
        "schema-version": "4",
        "action": action,
        "phase": phase,
        "project": PROJECT,
        "instance": instance,
        "role": role,
        "fleet-id": FLEET,
        "run-id": RUN,
        "session-id": SESSION,
        "correlation-id": CORR,
        "client-build-identity": CLIENT_BUILD,
        "challenge": CHALLENGE,
    }
    values.update(overrides)
    if "request-hash" not in overrides:
        values["request-hash"] = subject.request_digest(
            {
                "action": values["action"],
                "challenge": values["challenge"],
                "client_build_identity": values["client-build-identity"],
                "contract": subject.REQUEST_CONTRACT,
                "correlation_id": values["correlation-id"],
                "fleet_id": values["fleet-id"],
                "instance": values["instance"],
                "phase": values["phase"],
                "project": values["project"],
                "role": values["role"],
                "run_id": values["run-id"],
                "schema_version": 4,
                "session_id": values["session-id"],
            }
        )
    return [f"--{name}={values[name]}" for name in subject.REQUEST_FLAG_ORDER]


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


def winn3_status(
    *,
    forward: bool = True,
    ready: bool = True,
    delivered: int = 12,
    reflected: int = 0,
    writes: int = 12,
    sequence: int = 9,
    process_id: int = 2001,
    process_nonce: str = PROCESS_NONCE,
    process_started_utc: str = PROCESS_STARTED,
    observed_utc: str = "2026-08-24T12:00:10Z",
    observed_monotonic_ns: int | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "boot_id": BOOT_ID,
        "contract": subject.WINN3_STATUS_CONTRACT,
        "event": "posture",
        "forward": forward,
        "inner_packets_delivered": delivered,
        "observed_utc": observed_utc,
        "observed_monotonic_ns": (
            observed_monotonic_ns
            if observed_monotonic_ns is not None
            else max(sequence, 1) * 1_000_000_000
        ),
        "process_id": process_id,
        "process_nonce": process_nonce,
        "process_start_ticks": 4242,
        "process_started_utc": process_started_utc,
        "ready": ready,
        "reflected": reflected,
        "rx_device_writes": writes,
        "schema_version": 2,
        "sequence": sequence,
    }
    if extra:
        record.update(extra)
    return record


def attempt_journal(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "contract": subject.ATTEMPT_JOURNAL_CONTRACT,
        "events": events,
    }


def attempt_event(
    protocol: str,
    phase: str,
    result: str,
    monotonic_ns: int,
    second: int,
    *,
    node: str = COVER,
    action: str = "probe-awg-block",
) -> dict[str, Any]:
    return {
        "action": action,
        "correlation_id": CORR,
        "monotonic_ns": monotonic_ns,
        "node": node,
        "phase": phase,
        "protocol": protocol,
        "result": result,
        "session_id": SESSION,
        "utc": f"2026-08-24T12:00:0{second}Z",
    }


def valid_fallback_events() -> list[dict[str, Any]]:
    return [
        attempt_event("awg", "started", "pending", 12_000_000_000, 1),
        attempt_event("awg", "finished", "failed", 13_000_000_000, 2),
        attempt_event("xray", "started", "pending", 14_000_000_000, 3),
        attempt_event("xray", "finished", "connected", 15_000_000_000, 4),
    ]


def session_state(
    *,
    control_id: str,
    protocol: str,
    node: str,
    state: str,
    monotonic_ns: int = 1,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "contract": subject.STATE_CONTRACT,
        "run_id": RUN,
        "session_id": SESSION,
        "correlation_id": CORR,
        "fleet_id": FLEET,
        "control_id": control_id,
        "protocol": protocol,
        "node": node,
        "state": state,
        "monotonic_ns": monotonic_ns,
        "updated_utc": START_UTC,
    }


def proc_stat(pid: int, starttime: int = 4242, name: str = "svc") -> bytes:
    tail = ["S", "1", str(pid), str(pid), "0", "-1"] + ["0"] * 13 + [str(starttime)]
    return f"{pid} ({name}) {' '.join(tail)}\n".encode("ascii")


def xray_stats(uplink: int, downlink: int, user: str = XRAY_USER) -> bytes:
    return dumps(
        {
            "stat": [
                {"name": f"user>>>{user}>>>traffic>>>uplink", "value": str(uplink)},
                {"name": f"user>>>{user}>>>traffic>>>downlink", "value": str(downlink)},
            ]
        }
    )


def awg_handshake_bytes(stamp: int, peer: str = AWG_PEER) -> bytes:
    return f"{peer} {stamp}\n".encode("ascii")


def awg_transfer_bytes(rx: int, tx: int, peer: str = AWG_PEER) -> bytes:
    return f"{peer}\t{rx}\t{tx}\n".encode("ascii")


def show_unit(unit: str, pid: int, fragment: str) -> bytes:
    return (
        f"Id={unit}\nFragmentPath={fragment}\nMainPID={pid}\nActiveState=active\n"
    ).encode("ascii")


def seed_unit(host: FixtureHost, unit: str, pid: int, fragment: str, exe: bytes) -> None:
    comm = {
        "wins-hub.service": "wins-hub",
        "winn3-gateway.service": "winn3-gateway",
        "xray.service": "xray",
        "docker.service": "dockerd",
    }.get(unit, "svc")
    host.command_defaults[(subject.BIN_SYSTEMCTL, "is-active", unit)] = subject.CommandResult(
        b"active\n"
    )
    host.command_defaults[
        (
            subject.BIN_SYSTEMCTL,
            "show",
            unit,
            "--no-pager",
            "--property=Id,FragmentPath,MainPID,ActiveState",
        )
    ] = subject.CommandResult(show_unit(unit, pid, fragment))
    host.files[fragment] = b"[Unit]\nDescription=fixture unit\n"
    host.files[f"/proc/{pid}/exe"] = exe
    host.files[f"/proc/{pid}/stat"] = proc_stat(pid, name=comm)
    host.files[f"/proc/{pid}/comm"] = (comm + "\n").encode("ascii")


def queue_snapshots(
    host: FixtureHost,
    before: dict[str, tuple[int, int]],
    after: dict[str, tuple[int, int]],
    middle: dict[str, tuple[int, int]] | None = None,
) -> None:
    snapshots = [before, after] if middle is None else [before, middle, after]
    host.file_queues[subject.PROC_NET_DEV] = [proc_net_dev(item) for item in snapshots]
    host.commands[(subject.BIN_IP, "-json", "-s", "link")] = [
        subject.CommandResult(ip_link_stats(item)) for item in snapshots
    ]


def seed_network_defaults(host: FixtureHost) -> None:
    empty = subject.CommandResult(b"[]")
    host.command_defaults[(subject.BIN_IP, "-json", "addr")] = empty
    host.command_defaults[(subject.BIN_IP, "-json", "route")] = empty
    host.command_defaults[(subject.BIN_SS, "-H", "-lnt")] = subject.CommandResult(
        b"LISTEN 0 128 127.0.0.1:8000 0.0.0.0:*\n"
    )
    host.command_defaults[(subject.BIN_SS, "-H", "-lnu")] = subject.CommandResult(b"")


def seed_hub(host: FixtureHost) -> None:
    host.http["/healthz"] = dumps({"service": "wins-hub"})
    host.http["/nodes"] = dumps(
        {
            "nodes": [
                {
                    "slug": WINN3,
                    "carrier": "winn3",
                    "protocol_version": "winn/3",
                    "reachable": True,
                },
                {
                    "slug": COVER,
                    "carrier": "amneziawg",
                    "protocol_version": "winn/1",
                    "reachable": True,
                },
            ]
        }
    )


def seed_descriptor(host: FixtureHost, payload: bytes | None = None) -> bytes:
    if payload is None:
        payload = dumps({"node": WINN3})
    envelope = {
        "payload": base64.b64encode(payload).decode("ascii"),
        "sig": base64.b64encode(b"winn3-descriptor-signature").decode("ascii"),
    }
    raw = dumps(envelope)
    host.files[subject.DESCRIPTOR_PATH] = raw
    host.files[subject.DESCRIPTOR_PUBKEY_PATH] = (
        b"-----BEGIN PUBLIC KEY-----\nfixture-g1\n-----END PUBLIC KEY-----\n"
    )
    host.command_defaults[
        (
            subject.BIN_OPENSSL,
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            subject.DESCRIPTOR_PUBKEY_PATH,
            "-rawin",
            "-in",
            subject.DESCRIPTOR_PAYLOAD_PATH,
            "-sigfile",
            subject.DESCRIPTOR_SIG_PATH,
        )
    ] = subject.CommandResult(b"Signature Verified\n")
    return raw


def seed_nft(host: FixtureHost, table: str, path: str, *, restore: bool = False) -> None:
    if restore:
        host.command_defaults[
            (subject.BIN_NFT, "delete", "table", "inet", table)
        ] = subject.CommandResult(b"")
        host.command_defaults[(subject.BIN_NFT, "list", "table", "inet", table)] = (
            subject.CommandResult(b"", b"Error: No such file or directory\n", 1)
        )
        return
    host.command_defaults[(subject.BIN_NFT, "-f", path)] = subject.CommandResult(b"")
    host.command_defaults[(subject.BIN_NFT, "list", "table", "inet", table)] = subject.CommandResult(
        f"table inet {table} {{\n}}\n".encode("ascii")
    )


def seed_awg(
    host: FixtureHost,
    *,
    handshake: int = 0,
    rx_before: int = AWG_RX_BEFORE,
    tx_before: int = AWG_TX_BEFORE,
    rx_after: int | None = None,
    tx_after: int | None = None,
    samples: int = 2,
) -> None:
    if rx_after is None:
        rx_after = rx_before
    if tx_after is None:
        tx_after = tx_before
    handshakes = [
        subject.CommandResult(awg_handshake_bytes(handshake)) for _ in range(samples)
    ]
    transfers = [
        subject.CommandResult(awg_transfer_bytes(rx_before, tx_before)),
        *[
            subject.CommandResult(awg_transfer_bytes(rx_after, tx_after))
            for _ in range(samples - 1)
        ],
    ]
    host.commands[
        (subject.BIN_AWG, "show", subject.AWG_IFACE, "latest-handshakes")
    ] = handshakes
    host.commands[(subject.BIN_AWG, "show", subject.AWG_IFACE, "transfer")] = transfers
    host.command_defaults[
        (subject.BIN_AWG, "show", subject.AWG_IFACE, "latest-handshakes")
    ] = subject.CommandResult(awg_handshake_bytes(handshake))
    host.command_defaults[(subject.BIN_AWG, "show", subject.AWG_IFACE, "transfer")] = (
        subject.CommandResult(awg_transfer_bytes(rx_after, tx_after))
    )


def seed_xray_stats(
    host: FixtureHost,
    *,
    uplink_before: int = XRAY_UPLINK_BEFORE,
    downlink_before: int = XRAY_DOWNLINK_BEFORE,
    uplink_after: int | None = None,
    downlink_after: int | None = None,
    samples: int = 2,
) -> None:
    if uplink_after is None:
        uplink_after = uplink_before
    if downlink_after is None:
        downlink_after = downlink_before
    queued = [
        subject.CommandResult(xray_stats(uplink_before, downlink_before)),
        *[
            subject.CommandResult(xray_stats(uplink_after, downlink_after))
            for _ in range(samples - 1)
        ],
    ]
    host.commands[subject.XRAY_STATSQUERY_ARGV] = queued
    host.command_defaults[subject.XRAY_STATSQUERY_ARGV] = subject.CommandResult(
        xray_stats(uplink_after, downlink_after)
    )


def helper_identity_record(role: str, instance: str) -> dict[str, Any]:
    return {
        "bytes": len(HELPER_BYTES),
        "candidate_id": "d" * 64,
        "contract": subject.HELPER_IDENTITY_CONTRACT,
        "fleet_id": FLEET,
        "instance": instance,
        "kind": subject.HELPER_IDENTITY_KIND,
        "mode": subject.HELPER_INSTALL_MODE,
        "path": subject.INSTALL_PATH,
        "required_roles": list(subject.HELPER_REQUIRED_ROLES),
        "role": role,
        "schema_version": 1,
        "sha256": subject.sha256_bytes(HELPER_BYTES),
        "source_path": subject.HELPER_SOURCE_PATH,
        "st_dev": 1,
        "st_ino": 1,
    }


def seed_identity(host: FixtureHost) -> None:
    host.files[subject.INSTANCE_ID_PATH] = (INSTANCE_ID + "\n").encode("ascii")
    host.files[subject.BOOT_ID_PATH] = (BOOT_ID + "\n").encode("ascii")
    host.files[subject.INSTALL_PATH] = HELPER_BYTES
    host.files[subject.ATTEMPT_BROKER_PATH] = BROKER_BYTES


def installed_broker_tree(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "root"
    broker = root / subject.ATTEMPT_BROKER_PATH.removeprefix("/")
    broker.parent.mkdir(parents=True)
    current = root
    current.chmod(0o755)
    for component in ("usr", "local", "libexec"):
        current = current / component
        current.chmod(0o755)
    broker.write_bytes(BROKER_BYTES)
    broker.chmod(subject.ATTEMPT_BROKER_INSTALL_MODE)
    return root, broker


def make_host(
    role: str,
    *,
    before: dict[str, tuple[int, int]] | None = None,
    after: dict[str, tuple[int, int]] | None = None,
    status: dict[str, Any] | None = None,
    state: dict[str, Any] | None = None,
    attempts: tuple[list[dict[str, Any]], list[dict[str, Any]]] | None = None,
) -> FixtureHost:
    host = FixtureHost()
    host.files[subject.ROLE_FILE] = (role + "\n").encode("ascii")
    instance = {
        "control": CONTROL,
        "data-cover": COVER,
        "data-winn3": WINN3,
    }[role]
    host.files[subject.MARKER_PATH] = dumps(
        {
            "fleet_id": FLEET,
            "instance": instance,
            "role": role,
        }
    )
    host.files[subject.FLEET_BINDING_PATH] = dumps(fleet_binding())
    seed_identity(host)
    host.files[subject.HELPER_IDENTITY_PATH] = subject.canonical_bytes(
        helper_identity_record(role, instance)
    )
    idle = {"lo": (100, 100)}
    if role == "data-winn3":
        idle = {"lo": (100, 100), "winn3gw0": (WINN3_RX_BEFORE, WINN3_TX_BEFORE)}
    if attempts is not None:
        queue_snapshots(
            host,
            before or idle,
            after or idle,
            before or idle,
        )
    else:
        snapshot = after or before or idle
        host.file_queues[subject.PROC_NET_DEV] = [proc_net_dev(snapshot)]
        host.files[subject.PROC_NET_DEV] = proc_net_dev(snapshot)
        host.command_defaults[(subject.BIN_IP, "-json", "-s", "link")] = subject.CommandResult(
            ip_link_stats(snapshot)
        )
        host.commands[(subject.BIN_IP, "-json", "-s", "link")] = [
            subject.CommandResult(ip_link_stats(snapshot))
        ]
    seed_network_defaults(host)
    seed_hub(host)
    seed_descriptor(host)
    seed_awg(host, samples=3 if attempts is not None else 2)
    seed_xray_stats(host, samples=3 if attempts is not None else 2)
    if role == "control":
        seed_unit(
            host,
            "wins-hub.service",
            1001,
            "/lib/systemd/system/wins-hub.service",
            b"\x7fELFhub\n",
        )
    elif role == "data-winn3":
        seed_unit(
            host,
            "winn3-gateway.service",
            2001,
            "/lib/systemd/system/winn3-gateway.service",
            b"\x7fELFwinn3\n",
        )
        host.files["/usr/local/libexec/winn/winn3-gateway"] = b"\x7fELFwinn3-bin\n"
        for unit in subject.DATA_WINN3_FORBIDDEN_UNITS:
            host.command_defaults[
                (
                    subject.BIN_SYSTEMCTL,
                    "show",
                    unit,
                    "--no-pager",
                    "--property=Id,LoadState",
                )
            ] = subject.CommandResult(
                f"Id={unit}\nLoadState=not-found\n".encode("ascii")
            )
    elif role == "data-cover":
        seed_unit(
            host,
            "xray.service",
            3001,
            "/lib/systemd/system/xray.service",
            b"\x7fELFxray\n",
        )
        seed_unit(
            host,
            "docker.service",
            3002,
            "/lib/systemd/system/docker.service",
            b"\x7fELFdocker\n",
        )
        host.files["/usr/local/bin/xray"] = b"\x7fELFxray-bin\n"
    if status is not None:
        host.files[subject.WINN3_STATUS_PATHS["data-winn3"]] = dumps(status)
        host.file_queues[subject.WINN3_STATUS_PATHS["data-winn3"]] = [dumps(status)]
    if attempts is not None:
        intermediate = attempts[1][:2]
        host.file_queues[subject.ATTEMPT_JOURNAL_PATH] = [
            dumps(attempt_journal(attempts[0])),
            dumps(attempt_journal(intermediate)),
            dumps(attempt_journal(attempts[1])),
        ]
    if state is not None:
        host.files[subject.SESSION_STATE_PATH] = subject.canonical_bytes(state)
    return host


def assert_recorded_argv_is_closed(host: FixtureHost) -> None:
    for argv in host.runs:
        joined = " ".join(argv)
        assert argv[0] in {
            subject.BIN_IP,
            subject.BIN_SYSTEMCTL,
            subject.BIN_SS,
            subject.BIN_NFT,
            subject.BIN_AWG,
            subject.BIN_OPENSSL,
            subject.BIN_XRAY,
        }
        for token in FORBIDDEN_ARGV_TOKENS:
            assert token not in argv
            if token == "-c":
                continue
            assert f" {token} " not in f" {joined} "
        assert "sh -c" not in joined
        assert CONTROL not in argv
        assert WINN3 not in argv
        assert COVER not in argv
        assert "999999" not in argv
        assert "--bytes-rx" not in argv
        assert "--success" not in argv
        assert "--command" not in argv
        assert "--host" not in argv
        assert "--port" not in argv
        assert "--path" not in argv
    for path in host.http_calls:
        assert path in subject.ALLOWED_HTTP_PATHS
    for path in host.reads + host.writes:
        assert path not in subject.CREDENTIAL_PATHS
        assert not path.startswith("/root/vpn_auth")
        assert not path.startswith("/home/")
        assert not path.startswith("/etc/nginx/sites-enabled/")
        assert not path.startswith("/var/lib/postgresql/")
        assert "/etc/winn/credentials" not in path


def decode_ok(code: int, stdout: bytes, stderr: bytes, host: FixtureHost) -> dict[str, Any]:
    assert code == 0
    assert stderr == b""
    assert stdout.endswith(b"\n")
    stdout.decode("ascii")
    envelope = json.loads(stdout.decode("ascii"))
    assert set(envelope) == ENVELOPE_KEYS
    assert envelope["schema_version"] == 4
    assert envelope["contract"] == subject.TEST_RESPONSE_CONTRACT
    assert envelope["fixture_only"] is True
    assert envelope["challenge"] == CHALLENGE
    assert envelope["instance_id"] == INSTANCE_ID
    assert envelope["boot_id"] == BOOT_ID
    assert envelope["helper_hashes"]["remote"] == subject.sha256_bytes(HELPER_BYTES)
    expected_helper_hashes = {"remote"}
    if (
        envelope["role"] == "control"
        and envelope["phase"] == subject.PHASE_EXERCISE
        and envelope["action"] in subject.ATTEMPT_ACK_ACTIONS
    ):
        expected_helper_hashes.add("attempt_broker")
    assert set(envelope["helper_hashes"]) == expected_helper_hashes
    assert envelope["transaction"]["contract"] == subject.TRANSACTION_CONTRACT
    assert envelope["transaction"]["nonce"] == CHALLENGE
    assert envelope["transaction"]["kind"] == envelope["effect_kind"]
    assert subject.HEX64_RE.fullmatch(envelope["transaction"]["response_sha256"])
    assert envelope["transaction"]["response_sha256"] == subject.sha256_bytes(
        subject.canonical_bytes(envelope["transaction"]["response"])
    )
    assert envelope["evidence"]["challenge"] == CHALLENGE
    assert envelope["evidence"]["instance_id"] == INSTANCE_ID
    assert envelope["evidence"]["boot_id"] == BOOT_ID
    assert set(envelope["evidence"]) == EVIDENCE_KEYS
    assert envelope["request_sha256"] == envelope["evidence"]["request_sha256"]
    assert subject.HEX64_RE.fullmatch(envelope["request_sha256"])
    assert envelope["fixture_only"] is True
    assert envelope["effect_sha256"] == subject.effect_digest(envelope)
    assert subject.HEX64_RE.fullmatch(envelope["state_sha256"])
    subject.forbid_pass_tokens(envelope)
    for key in ("pass", "passed", "ok", "success", "verdict", "acceptance"):
        assert key not in envelope
        if envelope["data"] is not None:
            assert key not in envelope["data"]
    assert_recorded_argv_is_closed(host)
    return envelope


def run_action(action: str, host: FixtureHost, argv: list[str] | None = None) -> tuple[int, bytes, bytes]:
    try:
        request = subject.parse_argv(argv if argv is not None else argv_for(action))
        envelope = subject.execute(request, host)
        return 0, subject.canonical_bytes(envelope), b""
    except subject.RemoteActionError as exc:
        return subject.REFUSAL_EXIT, b"", (str(exc) + "\n").encode("ascii")


def test_route_decision_binds_signed_winn3_node() -> None:
    host = make_host("control")
    descriptor = host.files[subject.DESCRIPTOR_PATH]
    code, stdout, stderr = run_action("route-decision", host)
    envelope = decode_ok(code, stdout, stderr, host)
    assert envelope["effect_kind"] == "observation"
    assert envelope["operation"] == "query-signed-route-decision"
    assert envelope["data"] == {
        "served_carrier": "winn3",
        "descriptor_node": WINN3,
        "selected_node": WINN3,
        "descriptor_sha256": hashlib.sha256(descriptor).hexdigest(),
        "signature_state": "verified",
        "canary_state": "reachable",
    }
    assert envelope["instance"] == CONTROL
    assert envelope["role"] == "control"


def test_route_decision_rejects_signed_descriptor_for_a_different_node() -> None:
    host = make_host("control")
    seed_descriptor(host, dumps({"node": COVER}))
    code, stdout, stderr = run_action("route-decision", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"does not match the selected Winn3 node" in stderr


@pytest.mark.parametrize(
    ("payload", "error"),
    (
        (b'{"node":"proof-winn3-a1","node":"proof-cover-a1"}', b"duplicate JSON key"),
        (b'{"node":', b"not strict ASCII JSON"),
        (dumps([{"node": WINN3}]), b"payload must be an object"),
        (dumps({"endpoint": "198.51.100.1:443"}), b"node identity is ambiguous"),
        (dumps({"node": 7}), b"node identity is invalid"),
        (dumps({"node": "Proof-Winn3-A1"}), b"node identity is invalid"),
    ),
    ids=(
        "duplicate-node",
        "malformed-json",
        "non-object",
        "missing-node",
        "non-string-node",
        "non-canonical-node",
    ),
)
def test_route_decision_rejects_malformed_signed_descriptor_payloads(
    payload: bytes, error: bytes
) -> None:
    host = make_host("control")
    seed_descriptor(host, payload)
    code, stdout, stderr = run_action("route-decision", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert error in stderr


@pytest.mark.parametrize("alias", ("Node", "descriptor_node", "selected_node"))
def test_route_decision_rejects_ambiguous_signed_descriptor_identity_aliases(
    alias: str,
) -> None:
    host = make_host("control")
    seed_descriptor(host, dumps({"node": WINN3, alias: WINN3}))
    code, stdout, stderr = run_action("route-decision", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"node identity is ambiguous" in stderr


def test_connect_primary_observe_emits_status_v2_and_real_interface() -> None:
    host = make_host(
        "data-winn3",
        status=winn3_status(),
        after={"lo": (100, 100), "winn3gw0": (WINN3_RX_AFTER, WINN3_TX_AFTER)},
    )
    code, stdout, stderr = run_action(
        "connect-primary", host, argv_for("connect-primary", phase="observe-after")
    )
    envelope = decode_ok(code, stdout, stderr, host)
    assert envelope["phase"] == "observe-after"
    assert envelope["role"] == "data-winn3"
    assert envelope["data"] is None
    status = envelope["evidence"]["winn3_status"]
    assert status["contract"] == subject.WINN3_STATUS_CONTRACT
    assert status["schema_version"] == 2
    assert status["process_nonce"] == PROCESS_NONCE
    assert status["process_id"] == 2001
    assert envelope["evidence"]["process_identity"]["pid"] == 2001
    assert envelope["evidence"]["interface_counters"] == {
        "winn3gw0": {"rx": WINN3_RX_AFTER, "tx": WINN3_TX_AFTER}
    }
    assert "winn3" not in envelope["evidence"]["interface_counters"]
    assert "bytes_rx" not in (envelope["data"] or {})


def test_connect_primary_status_v2_identity_and_counter_deltas() -> None:
    before_host = make_host(
        "data-winn3",
        status=winn3_status(
            delivered=11,
            writes=11,
            sequence=9,
            observed_utc="2026-08-24T12:00:00Z",
        ),
        after={"lo": (100, 100), "winn3gw0": (WINN3_RX_BEFORE, WINN3_TX_BEFORE)},
    )
    after_host = make_host(
        "data-winn3",
        status=winn3_status(
            delivered=12,
            writes=12,
            sequence=10,
            observed_utc="2026-08-24T12:00:10Z",
        ),
        after={"lo": (100, 100), "winn3gw0": (WINN3_RX_AFTER, WINN3_TX_AFTER)},
    )
    before_env = decode_ok(
        *run_action(
            "connect-primary",
            before_host,
            argv_for("connect-primary", phase="observe-before"),
        ),
        before_host,
    )
    after_env = decode_ok(
        *run_action(
            "connect-primary",
            after_host,
            argv_for("connect-primary", phase="observe-after"),
        ),
        after_host,
    )
    delta = subject.winn3_status_delta(
        before_env["evidence"]["winn3_status"], after_env["evidence"]["winn3_status"]
    )
    assert delta == {
        "inner_packets_delivered": 1,
        "rx_device_writes": 1,
        "sequence": 1,
    }
    assert (
        before_env["evidence"]["winn3_status"]["process_nonce"]
        == after_env["evidence"]["winn3_status"]["process_nonce"]
    )
    rx = (
        after_env["evidence"]["interface_counters"]["winn3gw0"]["rx"]
        - before_env["evidence"]["interface_counters"]["winn3gw0"]["rx"]
    )
    assert rx == WINN3_RX_DELTA
    assert rx >= delta["rx_device_writes"]


def test_winn3_status_v2_extended_identity_fails_closed() -> None:
    wrong_boot = make_host(
        "data-winn3",
        status=winn3_status(extra={"boot_id": "22222222-2222-4222-8222-222222222222"}),
    )
    code, stdout, stderr = run_action(
        "connect-primary", wrong_boot, argv_for("connect-primary", phase="observe-after")
    )
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"boot id does not match" in stderr

    wrong_start = make_host(
        "data-winn3", status=winn3_status(extra={"process_start_ticks": 4243})
    )
    code, stdout, stderr = run_action(
        "connect-primary", wrong_start, argv_for("connect-primary", phase="observe-after")
    )
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"process start does not match" in stderr

    before = winn3_status(sequence=9, observed_monotonic_ns=9_000_000_000)
    after = winn3_status(
        sequence=10,
        observed_utc="2026-08-24T12:00:11Z",
        observed_monotonic_ns=9_000_000_000,
    )
    with pytest.raises(subject.RemoteActionError, match="monotonic observation"):
        subject.winn3_status_delta(before, after)


def test_connect_primary_exercise_triggers_attempt_on_control() -> None:
    host = make_host("control")
    code, stdout, stderr = run_action("connect-primary", host)
    envelope = decode_ok(code, stdout, stderr, host)
    assert envelope["phase"] == "exercise"
    assert envelope["role"] == "control"
    assert envelope["data"]["attempts"] == [
        {"protocol": "winn3", "node": WINN3, "result": "connected"}
    ]
    assert envelope["evidence"]["winn3_status"] is None
    assert envelope["evidence"]["interface_counters"] is None
    assert host.protocol_attempts == [("winn3", WINN3)]
    assert envelope["helper_hashes"]["attempt_broker"] == subject.sha256_bytes(BROKER_BYTES)
    assert (host.broker_holds, host.broker_finishes, host.broker_closes) == (1, 1, 1)
    assert envelope["transaction"]["protocol"] == "winn3"


@pytest.mark.parametrize("action", sorted(subject.ATTEMPT_ACK_ACTIONS))
def test_every_attempt_ack_action_requires_exact_control_exercise_broker_identity(
    action: str,
) -> None:
    assert subject.requires_attempt_broker_identity(
        {"action": action, "phase": subject.PHASE_EXERCISE, "role": "control"}
    )
    assert not subject.requires_attempt_broker_identity(
        {"action": action, "phase": subject.PHASE_OBSERVE_BEFORE, "role": "control"}
    )
    assert not subject.requires_attempt_broker_identity(
        {"action": action, "phase": subject.PHASE_EXERCISE, "role": "data-winn3"}
    )


def test_route_only_action_preserves_exact_remote_only_helper_hashes() -> None:
    host = make_host("control")
    envelope = decode_ok(*run_action("route-decision", host), host)
    assert envelope["helper_hashes"] == {
        "remote": subject.sha256_bytes(HELPER_BYTES)
    }
    assert (host.broker_holds, host.broker_finishes, host.broker_closes) == (0, 0, 0)


@pytest.mark.parametrize(
    "token",
    (
        "--attempt-broker-path=/tmp/substituted-broker",
        "--attempt-broker-sha256=" + "0" * 64,
        "--attempt-broker-sha256=" + "9" * 64,
        "--helper-hashes=attempt_broker:arbitrary",
    ),
)
def test_attempt_broker_identity_argument_injection_is_rejected(token: str) -> None:
    host = make_host("control")
    code, stdout, stderr = run_action(
        "connect-primary", host, argv_for("connect-primary") + [token]
    )
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"forbidden" in stderr or b"missing or extra" in stderr
    assert host.protocol_attempts == []
    assert (host.broker_holds, host.broker_finishes, host.broker_closes) == (0, 0, 0)


@pytest.mark.parametrize("hostile_digest", ("0" * 64, "9" * 64))
def test_attempt_broker_identity_ignores_environment_and_path_hash_substitution(
    monkeypatch: pytest.MonkeyPatch,
    hostile_digest: str,
) -> None:
    monkeypatch.setenv("WINSVPN_GCP_PROOF_ATTEMPT_BROKER_PATH", "/tmp/substituted")
    monkeypatch.setenv("WINSVPN_GCP_PROOF_ATTEMPT_BROKER_SHA256", hostile_digest)
    monkeypatch.setenv("ATTEMPT_BROKER_SHA256", hostile_digest)
    host = make_host("control")
    original_hash = host.hash_executable
    hash_queries: list[str] = []

    def hostile_path_hash(path: str) -> str:
        hash_queries.append(path)
        if path == subject.ATTEMPT_BROKER_PATH:
            return hostile_digest
        return original_hash(path)

    host.hash_executable = hostile_path_hash  # type: ignore[method-assign]
    envelope = decode_ok(*run_action("connect-primary", host), host)
    assert subject.ATTEMPT_BROKER_PATH not in hash_queries
    assert envelope["helper_hashes"]["attempt_broker"] == subject.sha256_bytes(
        BROKER_BYTES
    )
    assert envelope["helper_hashes"]["attempt_broker"] != hostile_digest


def test_absent_attempt_broker_refuses_before_protocol_use() -> None:
    host = make_host("control")
    del host.files[subject.ATTEMPT_BROKER_PATH]
    code, stdout, stderr = run_action("connect-primary", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"attempt-broker executable is absent" in stderr
    assert host.protocol_attempts == []
    assert (host.broker_holds, host.broker_finishes, host.broker_closes) == (0, 0, 0)


def test_attempt_broker_mutation_during_ack_use_refuses_and_closes_binding() -> None:
    host = make_host("control")
    original_trigger = host.trigger_protocol_attempt

    def mutating_trigger(
        request: dict[str, Any], protocol: str, node: str
    ) -> dict[str, Any]:
        acknowledgement = original_trigger(request, protocol, node)
        host.files[subject.ATTEMPT_BROKER_PATH] = BROKER_BYTES + b"mutated\n"
        return acknowledgement

    host.trigger_protocol_attempt = mutating_trigger  # type: ignore[method-assign]
    code, stdout, stderr = run_action("connect-primary", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"attempt-broker executable changed during use" in stderr
    assert host.protocol_attempts == [("winn3", WINN3)]
    assert (host.broker_holds, host.broker_finishes, host.broker_closes) == (1, 0, 1)


def test_attempt_broker_hash_is_committed_to_signed_transcript_closure() -> None:
    host = make_host("control")
    envelope = decode_ok(*run_action("connect-primary", host), host)
    assert set(envelope["helper_hashes"]) == {"attempt_broker", "remote"}
    assert envelope["effect_sha256"] == subject.effect_digest(envelope)

    substituted = json.loads(subject.canonical_bytes(envelope))
    substituted["helper_hashes"]["attempt_broker"] = "9" * 64
    assert subject.effect_digest(substituted) != envelope["effect_sha256"]

    missing = json.loads(subject.canonical_bytes(envelope))
    del missing["helper_hashes"]["attempt_broker"]
    assert subject.effect_digest(missing) != envelope["effect_sha256"]


def test_wrong_attempt_ack_phase_or_role_refuses_before_broker_binding() -> None:
    wrong_role = make_host("data-winn3", status=winn3_status())
    code, stdout, stderr = run_action(
        "connect-primary",
        wrong_role,
        argv_for("connect-primary", role="data-winn3", instance=WINN3),
    )
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"unexpected role" in stderr
    assert wrong_role.broker_holds == 0

    wrong_phase = make_host("control")
    argv = argv_for("connect-primary")
    argv[2] = "--phase=mutate"
    code, stdout, stderr = run_action("connect-primary", wrong_phase, argv)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"unexpected phase" in stderr
    assert wrong_phase.broker_holds == 0


def test_connect_cover_awg_observe_emits_peer_handshake_and_transfer() -> None:
    host = make_host("data-cover")
    seed_awg(
        host,
        handshake=HANDSHAKE_UNIX,
        rx_before=AWG_RX_AFTER,
        tx_before=AWG_TX_AFTER,
        samples=1,
    )
    code, stdout, stderr = run_action(
        "connect-cover-awg", host, argv_for("connect-cover-awg", phase="observe-after")
    )
    envelope = decode_ok(code, stdout, stderr, host)
    assert envelope["data"] is None
    assert envelope["evidence"]["awg_peers"] == [
        {
            "public_key": AWG_PEER,
            "latest_handshake_unix": HANDSHAKE_UNIX,
            "rx": AWG_RX_AFTER,
            "tx": AWG_TX_AFTER,
        }
    ]
    assert (subject.BIN_AWG, "show", "awg0", "transfer") in host.runs
    assert (subject.BIN_AWG, "show", "awg0", "latest-handshakes") in host.runs


def test_connect_cover_awg_exercise_binds_cover_node() -> None:
    host = make_host("control")
    code, stdout, stderr = run_action("connect-cover-awg", host)
    envelope = decode_ok(code, stdout, stderr, host)
    assert envelope["data"] == {
        "protocol": "awg",
        "node": COVER,
        "result": "connected",
    }
    assert envelope["transaction"]["protocol"] == "awg"
    assert envelope["evidence"]["awg_peers"] is None


def test_connect_cover_xray_observe_emits_exact_user_stats() -> None:
    host = make_host("data-cover")
    seed_xray_stats(
        host,
        uplink_before=XRAY_UPLINK_AFTER,
        downlink_before=XRAY_DOWNLINK_AFTER,
        samples=1,
    )
    code, stdout, stderr = run_action(
        "connect-cover-xray", host, argv_for("connect-cover-xray", phase="observe-after")
    )
    envelope = decode_ok(code, stdout, stderr, host)
    assert envelope["evidence"]["xray_stats"] == {
        "user": XRAY_USER,
        "uplink": XRAY_UPLINK_AFTER,
        "downlink": XRAY_DOWNLINK_AFTER,
    }
    assert subject.XRAY_STATSQUERY_ARGV in host.runs


def test_connect_cover_xray_exercise_binds_cover_node() -> None:
    host = make_host("control")
    code, stdout, stderr = run_action("connect-cover-xray", host)
    envelope = decode_ok(code, stdout, stderr, host)
    assert envelope["data"] == {"protocol": "xray", "node": COVER, "result": "connected"}
    assert envelope["transaction"]["protocol"] == "xray"


def test_inject_awg_block_is_remote_mutation_on_cover() -> None:
    host = make_host("data-cover")
    seed_nft(host, subject.NFT_AWG_TABLE, subject.NFT_AWG_FILE)
    code, stdout, stderr = run_action("inject-awg-block", host)
    envelope = decode_ok(code, stdout, stderr, host)
    assert envelope["effect_kind"] == "remote_mutation"
    assert envelope["role"] == "data-cover"
    assert envelope["instance"] == COVER
    assert envelope["data"] == {
        "control_id": "negative-awg-block",
        "protocol": "awg",
        "state": "blocked",
    }
    assert subject.NFT_AWG_FILE in host.writes
    stored = json.loads(host.files[subject.SESSION_STATE_PATH].decode("ascii"))
    assert stored["state"] == "blocked"
    assert stored["node"] == COVER
    assert stored["monotonic_ns"] >= 1_000_000_000


def test_probe_awg_block_requires_awg_failure_then_xray_on_cover() -> None:
    events = valid_fallback_events()
    host = make_host("control", attempts=([], events))
    code, stdout, stderr = run_action("probe-awg-block", host)
    envelope = decode_ok(code, stdout, stderr, host)
    assert envelope["role"] == "control"
    assert envelope["phase"] == "exercise"
    assert envelope["data"]["control_id"] == "negative-awg-block"
    assert envelope["data"]["attempts"] == [
        {"protocol": "awg", "node": COVER, "result": "blocked"},
        {"protocol": "xray", "node": COVER, "result": "connected"},
    ]
    assert envelope["data"]["attempt_events"] == events
    assert envelope["evidence"]["attempt_journal_after"]["events"] == events
    assert host.protocol_attempts == [("awg", COVER), ("xray", COVER)]
    assert (host.broker_holds, host.broker_finishes, host.broker_closes) == (1, 1, 1)
    assert envelope["data"]["attempts"][0]["node"] == envelope["data"]["attempts"][1]["node"]
    assert envelope["data"]["attempts"][0]["node"] != WINN3
    assert envelope["transaction"]["protocol"] == "awg-xray-fallback"


def test_restore_awg_requires_matching_session_state() -> None:
    host = make_host(
        "data-cover",
        state=session_state(
            control_id="negative-awg-block", protocol="awg", node=COVER, state="blocked"
        ),
    )
    seed_nft(host, subject.NFT_AWG_TABLE, subject.NFT_AWG_FILE, restore=True)
    code, stdout, stderr = run_action("restore-awg", host)
    envelope = decode_ok(code, stdout, stderr, host)
    assert envelope["effect_kind"] == "remote_mutation"
    assert envelope["data"] == {
        "control_id": "negative-awg-block",
        "protocol": "awg",
        "state": "restored",
    }


def test_inject_and_restore_winn3_block_on_data_winn3() -> None:
    host = make_host("data-winn3")
    seed_nft(host, subject.NFT_WINN3_TABLE, subject.NFT_WINN3_FILE)
    code, stdout, stderr = run_action("inject-winn3-block", host)
    envelope = decode_ok(code, stdout, stderr, host)
    assert envelope["instance"] == WINN3
    assert envelope["data"] == {
        "control_id": "negative-winn3-block",
        "protocol": "winn3",
        "state": "blocked",
    }
    host2 = make_host(
        "data-winn3",
        state=session_state(
            control_id="negative-winn3-block", protocol="winn3", node=WINN3, state="blocked"
        ),
    )
    seed_nft(host2, subject.NFT_WINN3_TABLE, subject.NFT_WINN3_FILE, restore=True)
    code, stdout, stderr = run_action("restore-winn3", host2)
    envelope = decode_ok(code, stdout, stderr, host2)
    assert envelope["data"]["state"] == "restored"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("correlation_id", "correlation-20260823-wrong"),
        ("protocol", "winn3"),
        ("node", WINN3),
        ("updated_utc", "not-a-timestamp"),
    ),
)
def test_restore_awg_rejects_misbinding_session_state(field: str, value: str) -> None:
    state = session_state(
        control_id="negative-awg-block",
        protocol="awg",
        node=COVER,
        state="blocked",
    )
    state[field] = value
    host = make_host("data-cover", state=state)
    seed_nft(host, subject.NFT_AWG_TABLE, subject.NFT_AWG_FILE, restore=True)

    code, stdout, stderr = run_action("restore-awg", host)

    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"session state is stale" in stderr or b"timestamp" in stderr
    assert (subject.BIN_NFT, "delete", "table", "inet", subject.NFT_AWG_TABLE) not in host.runs


def test_protocol_failure_refuses_synthetic_interface_evidence() -> None:
    snapshot = {
        "counters": {
            "lo": {"rx": 100, "tx": 100},
        }
    }
    with pytest.raises(subject.RemoteActionError, match="synthetic interface evidence is not accepted"):
        subject.protocol_failed(snapshot, snapshot, "winn3")
    with pytest.raises(subject.RemoteActionError, match="synthetic interface evidence is not accepted"):
        subject.iface_delta(snapshot, snapshot, "awg")
    with pytest.raises(subject.RemoteActionError, match="synthetic interface evidence is not accepted"):
        subject.require_attempt_interface(snapshot, snapshot, "xray")


def test_probe_winn3_block_falls_back_to_cover_awg() -> None:
    host = make_host("control")
    code, stdout, stderr = run_action("probe-winn3-block", host)
    envelope = decode_ok(code, stdout, stderr, host)
    assert envelope["data"]["attempts"] == [
        {"protocol": "winn3", "node": WINN3, "result": "blocked"},
        {"protocol": "awg", "node": COVER, "result": "connected"},
    ]
    assert envelope["data"]["attempts"][0]["node"] != envelope["data"]["attempts"][1]["node"]
    assert host.protocol_attempts == [("winn3", WINN3), ("awg", COVER)]


def test_cover_withdraw_and_downgrade_refusal() -> None:
    host = make_host("control")
    seed_nft(host, subject.NFT_COVER_TABLE, subject.NFT_COVER_FILE)
    code, stdout, stderr = run_action("withdraw-cover", host)
    envelope = decode_ok(code, stdout, stderr, host)
    assert envelope["effect_kind"] == "remote_mutation"
    assert envelope["data"] == {
        "control_id": "negative-cover-withdrawn",
        "node": COVER,
        "state": "withdrawn",
    }
    probe_host = make_host(
        "control",
        state=session_state(
            control_id="negative-cover-withdrawn",
            protocol="",
            node=COVER,
            state="withdrawn",
        ),
    )
    code, stdout, stderr = run_action("probe-cover-withdrawn", probe_host)
    envelope = decode_ok(code, stdout, stderr, probe_host)
    data = envelope["data"]
    assert {key: value for key, value in data.items() if key != "attempt_events"} == {
        "control_id": "negative-cover-withdrawn",
        "attempts": [{"protocol": "winn3", "node": WINN3, "result": "blocked"}],
        "refusal_code": "same_node_downgrade_refused",
        "same_node_downgrade_attempts": 0,
    }
    assert [
        (event["protocol"], event["node"], event["phase"], event["result"])
        for event in data["attempt_events"]
    ] == [
        ("winn3", WINN3, "started", "pending"),
        ("winn3", WINN3, "finished", "failed"),
    ]
    restore_host = make_host(
        "control",
        state=session_state(
            control_id="negative-cover-withdrawn",
            protocol="",
            node=COVER,
            state="withdrawn",
        ),
    )
    seed_nft(restore_host, subject.NFT_COVER_TABLE, subject.NFT_COVER_FILE, restore=True)
    code, stdout, stderr = run_action("restore-cover", restore_host)
    envelope = decode_ok(code, stdout, stderr, restore_host)
    assert envelope["data"]["state"] == "restored"


def test_teardown_check_resource_identity_matches_go_client() -> None:
    host = make_host("control")
    code, stdout, stderr = run_action("teardown-check", host)
    envelope = decode_ok(code, stdout, stderr, host)
    identity = {
        "instances": [CONTROL, WINN3, COVER],
        "network": f"pf-{FLEET}-net",
        "subnets": [
            f"pf-{FLEET}-sn-control",
            f"pf-{FLEET}-sn-data-winn3",
            f"pf-{FLEET}-sn-data-cover",
        ],
        "firewalls": [
            f"pf-{FLEET}-admin-ssh",
            f"pf-{FLEET}-control-http",
            f"pf-{FLEET}-cover-in",
            f"pf-{FLEET}-winn3-in",
        ],
    }
    assert envelope["data"]["expected_resources"] == identity
    assert envelope["data"]["observed_resources"] == identity
    assert envelope["data"]["unexpected_targets"] == []
    assert envelope["data"]["foreign_resource_ids"] == []
    assert envelope["data"]["credential_files_read"] == []
    assert envelope["data"]["production_resources_touched"] == []
    assert isinstance(envelope["data"]["expected_resources"]["network"], str)


@pytest.mark.parametrize(
    "token",
    [
        "--command=/bin/sh",
        "--cmd=id",
        "--shell=/bin/bash",
        "--host=evil.example",
        "--port=22",
        "--path=/etc/passwd",
        "--bytes-rx=999999",
        "--bytes-tx=1",
        "--success=true",
        "--ok=1",
        "--pass=true",
        "--result=connected",
        "--script=/tmp/x.sh",
    ],
)
def test_caller_supplied_command_path_host_or_success_tokens_are_rejected(token: str) -> None:
    host = make_host("control")
    argv = argv_for("route-decision") + [token]
    code, stdout, stderr = run_action("route-decision", host, argv)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"forbidden" in stderr or b"missing or extra" in stderr
    assert host.runs == []


@pytest.mark.parametrize(
    "value",
    [
        "proof-control-a1;reboot",
        "proof-control-a1|nc",
        "proof-control-a1$(id)",
        "proof-control-a1`id`",
        "proof-control-a1&&id",
        "proof-control-a1 /bin/sh",
    ],
)
def test_shell_fragments_in_instance_are_rejected(value: str) -> None:
    host = make_host("control")
    code, stdout, stderr = run_action(
        "route-decision", host, argv_for("route-decision", instance=value)
    )
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"unsafe" in stderr
    assert host.runs == []


def test_reordered_or_partial_argv_is_rejected() -> None:
    host = make_host("control")
    good = argv_for("route-decision")
    reordered = [good[1], good[0], *good[2:]]
    missing = good[:-1]
    extra = good + ["--schema-version=1"]
    for argv in (reordered, missing, extra):
        code, stdout, stderr = run_action("route-decision", host, argv)
        assert code == subject.REFUSAL_EXIT
        assert stdout == b""
        assert stderr


def test_unsupported_action_and_unexpected_role_fail_closed() -> None:
    host = make_host("control")
    eval_argv = argv_for("route-decision")
    eval_argv[1] = "--action=eval"
    code, stdout, stderr = run_action("route-decision", host, eval_argv)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"unsupported action" in stderr
    code, stdout, stderr = run_action(
        "route-decision",
        host,
        argv_for("route-decision", role="data-cover", instance=COVER),
    )
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"unexpected role" in stderr
    host.files[subject.ROLE_FILE] = b"data-winn3\n"
    code, stdout, stderr = run_action("route-decision", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"unexpected role" in stderr


def test_synthetic_success_boolean_in_status_is_rejected() -> None:
    host = make_host(
        "data-winn3",
        status=winn3_status(extra={"success": True}),
    )
    code, stdout, stderr = run_action(
        "connect-primary", host, argv_for("connect-primary", phase="observe-after")
    )
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"forbidden pass token" in stderr or b"schema fields" in stderr


def test_reflection_mode_and_zero_winn3_counters_fail_closed() -> None:
    reflected = make_host(
        "data-winn3",
        status=winn3_status(delivered=0, reflected=9, writes=0),
    )
    code, stdout, stderr = run_action(
        "connect-primary", reflected, argv_for("connect-primary", phase="observe-after")
    )
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"reflection mode" in stderr
    zero = make_host(
        "data-winn3",
        status=winn3_status(delivered=0, reflected=0, writes=0, sequence=0),
    )
    code, stdout, stderr = run_action(
        "connect-primary", zero, argv_for("connect-primary", phase="observe-after")
    )
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"sequence" in stderr
    not_forward = make_host(
        "data-winn3",
        status=winn3_status(forward=False),
    )
    code, stdout, stderr = run_action(
        "connect-primary", not_forward, argv_for("connect-primary", phase="observe-after")
    )
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""


def test_synthetic_winn3_interface_is_not_accepted_as_proof() -> None:
    host = make_host(
        "data-winn3",
        status=winn3_status(),
        after={"lo": (100, 100), "winn3": (WINN3_RX_AFTER, WINN3_TX_AFTER)},
    )
    code, stdout, stderr = run_action(
        "connect-primary", host, argv_for("connect-primary", phase="observe-after")
    )
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"synthetic interface evidence is not accepted" in stderr


def test_unchanged_real_interface_still_requires_status_v2() -> None:
    host = make_host(
        "data-winn3",
        status=winn3_status(),
        after={"lo": (100, 100), "winn3gw0": (WINN3_RX_BEFORE, WINN3_TX_BEFORE)},
    )
    code, stdout, stderr = run_action(
        "connect-primary", host, argv_for("connect-primary", phase="observe-after")
    )
    envelope = decode_ok(code, stdout, stderr, host)
    assert envelope["evidence"]["interface_counters"]["winn3gw0"]["rx"] == WINN3_RX_BEFORE
    assert envelope["evidence"]["winn3_status"]["inner_packets_delivered"] == 12


def test_proc_and_ip_counter_disagreement_fails_closed() -> None:
    host = make_host("data-winn3", status=winn3_status())
    after = {"lo": (100, 100), "winn3gw0": (WINN3_RX_AFTER, WINN3_TX_AFTER)}
    disagreed = {"lo": (100, 100), "winn3gw0": (WINN3_RX_BEFORE + 1, WINN3_TX_BEFORE)}
    host.file_queues[subject.PROC_NET_DEV] = [proc_net_dev(after)]
    host.command_defaults[(subject.BIN_IP, "-json", "-s", "link")] = subject.CommandResult(
        ip_link_stats(disagreed)
    )
    host.commands[(subject.BIN_IP, "-json", "-s", "link")] = [
        subject.CommandResult(ip_link_stats(disagreed))
    ]
    code, stdout, stderr = run_action(
        "connect-primary", host, argv_for("connect-primary", phase="observe-after")
    )
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"disagree" in stderr


def test_awg_after_xray_success_is_not_awg_first_failure() -> None:
    events = valid_fallback_events()
    host = make_host("control", attempts=([], events))
    host.file_queues[subject.ATTEMPT_JOURNAL_PATH] = [
        dumps(attempt_journal([])),
        dumps(attempt_journal(events)),
        dumps(attempt_journal(events)),
    ]
    code, stdout, stderr = run_action("probe-awg-block", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert (
        b"exact AWG-first fallback attempt sequence is absent" in stderr
        or b"attempt sequence is invalid" in stderr
        or b"did not append atomically" in stderr
    )


def test_absent_awg_journal_plus_unrelated_cover_observe_fails() -> None:
    host = make_host("control")
    code, stdout, stderr = run_action("probe-awg-block", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"attempt journal is absent" in stderr


def test_xray_attempt_before_awg_attempt_fails() -> None:
    events = valid_fallback_events()
    events[0], events[2] = events[2], events[0]
    host = make_host("control", attempts=([], events))
    code, stdout, stderr = run_action("probe-awg-block", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"attempt sequence is invalid" in stderr or b"journal is stale" in stderr


def test_no_timestamped_awg_attempt_fails() -> None:
    host = make_host("control")
    code, stdout, stderr = run_action("probe-awg-block", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"attempt journal is absent" in stderr


def test_stale_positive_winn3_status_identity_change_fails_across_observations() -> None:
    before_host = make_host(
        "data-winn3",
        status=winn3_status(delivered=11, writes=11, sequence=9, process_nonce=PROCESS_NONCE),
    )
    after_host = make_host(
        "data-winn3",
        status=winn3_status(
            delivered=12,
            writes=12,
            sequence=10,
            process_nonce="ffffffffffffffffffffffffffffffff",
        ),
    )
    before_env = decode_ok(
        *run_action(
            "connect-primary",
            before_host,
            argv_for("connect-primary", phase="observe-before"),
        ),
        before_host,
    )
    after_env = decode_ok(
        *run_action(
            "connect-primary",
            after_host,
            argv_for("connect-primary", phase="observe-after"),
        ),
        after_host,
    )
    with pytest.raises(subject.RemoteActionError, match="process identity changed"):
        subject.winn3_status_delta(
            before_env["evidence"]["winn3_status"], after_env["evidence"]["winn3_status"]
        )


def test_unrelated_interface_delta_cannot_replace_winn3_evidence() -> None:
    host = make_host(
        "data-winn3",
        status=winn3_status(),
        after={"lo": (100, 100), "eth0": (5000, 7000)},
    )
    code, stdout, stderr = run_action(
        "connect-primary", host, argv_for("connect-primary", phase="observe-after")
    )
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"Winn3 interface counter evidence is missing" in stderr


def test_same_node_fleet_binding_is_rejected() -> None:
    host = make_host("control")
    binding = fleet_binding()
    binding["data-cover"]["instance"] = WINN3
    host.files[subject.FLEET_BINDING_PATH] = dumps(binding)
    code, stdout, stderr = run_action("route-decision", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"distinct" in stderr


def test_handlers_refuse_same_node_fallback_even_if_binding_were_equal() -> None:
    binding = fleet_binding()
    binding["data-cover"]["instance"] = WINN3
    nodes = [
        {"slug": WINN3, "carrier": "amneziawg", "protocol_version": "winn/1", "reachable": True}
    ]
    with pytest.raises(subject.RemoteActionError, match="same-node"):
        subject.require_cover_node(nodes, binding)
    host = make_host("control")
    host.http["/nodes"] = dumps(
        {
            "nodes": [
                {
                    "slug": WINN3,
                    "carrier": "amneziawg",
                    "protocol_version": "winn/1",
                    "reachable": True,
                }
            ]
        }
    )
    with pytest.raises(subject.RemoteActionError, match="same-node"):
        subject.handle_probe_awg_block(
            host,
            {"role": "control", "action": "probe-awg-block", "instance": CONTROL,
             "correlation_id": CORR, "session_id": SESSION},
            binding,
            attempt_journal([]),
            attempt_journal(valid_fallback_events()[:2]),
            attempt_journal(valid_fallback_events()),
            11_000_000_000,
            21_000_000_000,
            datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc),
            datetime(2026, 8, 24, 12, 0, 10, tzinfo=timezone.utc),
        )


def test_duplicate_json_and_malformed_files_fail_closed() -> None:
    host = make_host("data-winn3", status=winn3_status())
    host.files[subject.WINN3_STATUS_PATHS["data-winn3"]] = (
        b'{"contract":"winsvpn-gcp-proof-winn3-status-v2","contract":"dup",'
        b'"event":"posture","forward":true,"ready":true,"inner_packets_delivered":1,'
        b'"reflected":0,"rx_device_writes":1,"schema_version":2,'
        b'"boot_id":"11111111-1111-4111-8111-111111111111",'
        b'"process_id":2001,"process_nonce":"0123456789abcdef0123456789abcdef",'
        b'"process_start_ticks":4242,"observed_monotonic_ns":9000000000,'
        b'"process_started_utc":"2026-08-24T11:00:00Z","observed_utc":"2026-08-24T12:00:10Z",'
        b'"sequence":9}'
    )
    host.file_queues[subject.WINN3_STATUS_PATHS["data-winn3"]] = [
        host.files[subject.WINN3_STATUS_PATHS["data-winn3"]]
    ]
    code, stdout, stderr = run_action(
        "connect-primary", host, argv_for("connect-primary", phase="observe-after")
    )
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"duplicate JSON key" in stderr
    host2 = make_host("control")
    host2.files[subject.FLEET_BINDING_PATH] = b"{not-json"
    code, stdout, stderr = run_action("route-decision", host2)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"JSON" in stderr


def test_stale_marker_binding_and_session_state_fail_closed() -> None:
    host = make_host("control")
    host.files[subject.MARKER_PATH] = dumps(
        {"fleet_id": "aaaaaaaaaaaa", "instance": CONTROL, "role": "control"}
    )
    code, stdout, stderr = run_action("route-decision", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"stale" in stderr
    host = make_host("control")
    binding = fleet_binding()
    binding["fleet_id"] = "bbbbbbbbbbbb"
    host.files[subject.FLEET_BINDING_PATH] = dumps(binding)
    code, stdout, stderr = run_action("route-decision", host)
    assert code == subject.REFUSAL_EXIT
    assert b"stale" in stderr
    host = make_host(
        "data-cover",
        state=session_state(
            control_id="negative-awg-block",
            protocol="awg",
            node=COVER,
            state="blocked",
            monotonic_ns=9_000_000_000_000,
        ),
    )
    seed_nft(host, subject.NFT_AWG_TABLE, subject.NFT_AWG_FILE, restore=True)
    code, stdout, stderr = run_action("restore-awg", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"stale" in stderr


def test_duplicate_inject_is_rejected() -> None:
    host = make_host(
        "data-cover",
        state=session_state(
            control_id="negative-awg-block", protocol="awg", node=COVER, state="blocked"
        ),
    )
    seed_nft(host, subject.NFT_AWG_TABLE, subject.NFT_AWG_FILE)
    code, stdout, stderr = run_action("inject-awg-block", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"duplicate" in stderr


def test_absent_ip_and_ss_fail_closed() -> None:
    host = make_host("control")
    host.command_defaults.pop((subject.BIN_IP, "-json", "addr"))
    host.commands.pop((subject.BIN_IP, "-json", "-s", "link"), None)
    code, stdout, stderr = run_action("route-decision", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"absent tool" in stderr
    host = make_host("control")
    host.command_defaults[(subject.BIN_SS, "-H", "-lnt")] = subject.CommandResult(
        b"", b"ss: command not found\n", 127
    )
    code, stdout, stderr = run_action("teardown-check", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"absent tool" in stderr


def test_execute_rejects_extra_request_fields_including_synthetic_facts() -> None:
    host = make_host("control")
    request = subject.parse_argv(argv_for("connect-primary"))
    request["bytes_rx"] = 999999
    request["success"] = True
    request["attempts"] = [{"protocol": "winn3", "node": WINN3, "result": "connected"}]
    with pytest.raises(subject.RemoteActionError, match="schema fields|forbidden"):
        subject.execute(request, host)


def test_allowlist_rejects_arbitrary_commands() -> None:
    host = make_host("control")
    with pytest.raises(subject.RemoteActionError, match="not allowlisted"):
        subject.run_allowlisted(host, ("/bin/sh", "-c", "id"))
    with pytest.raises(subject.RemoteActionError, match="not allowlisted"):
        subject.run_allowlisted(host, (subject.BIN_AWG, "show", "awg0", "; reboot"))
    with pytest.raises(subject.RemoteActionError, match="not allowlisted"):
        subject.run_allowlisted(
            host, (subject.BIN_NFT, "-f", "/tmp/evil.nft")
        )
    assert host.runs == []


def test_child_command_allowlist_has_no_shell_or_unused_docker_exec() -> None:
    commands = subject.allowlisted_commands()
    assert commands
    for argv in commands:
        assert argv
        assert argv[0] in {
            subject.BIN_AWG,
            subject.BIN_IP,
            subject.BIN_NFT,
            subject.BIN_OPENSSL,
            subject.BIN_SS,
            subject.BIN_SYSTEMCTL,
            subject.BIN_XRAY,
        }
        joined = " ".join(argv)
        assert "docker exec" not in joined
        assert "nginx.service" not in joined
        assert "/bin/sh" not in joined
        assert " -c " not in f" {joined} "


def test_credential_and_production_paths_are_unreadable() -> None:
    host = FixtureHost()
    for path in (
        "/root/vpn_auth.env",
        "/root/vpn_auth/.env",
        "/etc/winn/credentials",
        "/home/ubuntu/.ssh/id_rsa",
        "/etc/nginx/sites-enabled/default",
        "/var/lib/postgresql/16/main/PG_VERSION",
    ):
        with pytest.raises(subject.RemoteActionError, match="credential|production"):
            host.read_file(path)
        with pytest.raises(subject.RemoteActionError, match="credential|production"):
            host.write_file(path, b"x", 0o600)


def test_production_host_cannot_emit_pass_from_this_workstation() -> None:
    code, stdout, stderr = subject.run_argv(argv_for("route-decision"))
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert stderr.endswith(b"\n")
    stderr.decode("ascii")
    assert b"PASS" not in stderr
    exit_code = subject.main(argv_for("connect-primary"))
    assert exit_code == subject.REFUSAL_EXIT


def test_test_only_host_cannot_emit_production_output(monkeypatch: pytest.MonkeyPatch) -> None:
    host = make_host("control")
    monkeypatch.setenv("WINS_GCP_PROOF_REMOTE_PRODUCTION", "1")
    code, stdout, stderr = subject.run_argv(argv_for("route-decision"), host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"test host cannot emit production output" in stderr


def test_test_only_host_contract_is_nonproduction_without_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("WINS_GCP_PROOF_REMOTE_PRODUCTION", raising=False)
    host = make_host("control")
    code, stdout, stderr = subject.run_argv(argv_for("route-decision"), host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"test host cannot emit production output" in stderr


def test_returned_evidence_is_complete_and_reconstructable() -> None:
    host = make_host("control")
    code, stdout, stderr = run_action("teardown-check", host)
    envelope = decode_ok(code, stdout, stderr, host)
    evidence = envelope["evidence"]
    assert set(evidence) == EVIDENCE_KEYS
    assert set(evidence["services"]) == {"binaries", "forbidden", "units"}
    assert evidence["started_monotonic_ns"] < evidence["ended_monotonic_ns"]
    unit = evidence["services"]["units"]["wins-hub.service"]
    assert subject.HEX64_RE.fullmatch(unit["fragment_sha256"])
    assert subject.HEX64_RE.fullmatch(unit["executable_sha256"])
    assert evidence["process_identity"]["pid"] == unit["main_pid"]
    assert evidence["process_identity"]["comm"] == "wins-hub"
    assert evidence["winn3_status"] is None
    assert evidence["interface_counters"] is None
    assert evidence["awg_peers"] is None
    assert evidence["xray_stats"] is None
    assert envelope["state_sha256"] == subject.sha256_bytes(
        subject.canonical_bytes(evidence)
    )
    assert envelope["transaction"]["protocol"] == "scope"


@pytest.mark.parametrize("monotonic_values", [(7, 7), (1, 121_000_000_002)])
def test_equal_or_excessive_monotonic_interval_fails(
    monotonic_values: tuple[int, int],
) -> None:
    host = make_host("control")
    values = iter(monotonic_values)
    host.monotonic_ns = lambda: next(values)  # type: ignore[method-assign]
    code, stdout, stderr = run_action("teardown-check", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"monotonic action interval" in stderr


@pytest.mark.parametrize(
    ("kind", "name"),
    [("unit", name) for name in subject.DATA_WINN3_FORBIDDEN_UNITS]
    + [("binary", name) for name in subject.DATA_WINN3_FORBIDDEN_BINARIES],
)
def test_data_winn3_forbidden_xray_or_docker_component_fails(
    kind: str, name: str
) -> None:
    host = make_host("data-winn3")
    if kind == "unit":
        host.command_defaults[
            (
                subject.BIN_SYSTEMCTL,
                "show",
                name,
                "--no-pager",
                "--property=Id,LoadState",
            )
        ] = subject.CommandResult(f"Id={name}\nLoadState=loaded\n".encode("ascii"))
    else:
        host.files[name] = b"forbidden executable\n"
    code, stdout, stderr = run_action("inject-winn3-block", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"forbidden component is present" in stderr


def test_production_presence_check_does_not_hide_symlinks(tmp_path: Path) -> None:
    target = tmp_path / "docker-real"
    target.write_bytes(b"binary\n")
    link = tmp_path / "docker"
    link.symlink_to(target)
    assert subject.ProductionHost().exists(str(link)) is True


def test_main_always_constructs_production_host(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[Any] = []

    class GuardHost(subject.ProductionHost):
        def __init__(self) -> None:
            seen.append(self)
            super().__init__()

    monkeypatch.setattr(subject, "ProductionHost", GuardHost)
    assert subject.main(argv_for("route-decision")) == subject.REFUSAL_EXIT
    assert len(seen) == 1
    assert seen[0].TEST_ONLY is False


def test_effect_digest_is_canonical_and_excludes_its_own_field() -> None:
    host = make_host("control")
    code, stdout, stderr = run_action("teardown-check", host)
    envelope = decode_ok(code, stdout, stderr, host)
    again = subject.effect_digest(envelope)
    assert again == envelope["effect_sha256"]
    mutated = dict(envelope)
    mutated["data"] = dict(envelope["data"])
    mutated["data"]["unexpected_targets"] = ["synthetic"]
    assert subject.effect_digest(mutated) != envelope["effect_sha256"]


def test_state_digest_golden_matches_go_without_html_escaping() -> None:
    payload = {"b": "<&>", "a": 1}
    assert subject.canonical_bytes(payload) == b'{"a":1,"b":"<&>"}\n'
    assert subject.sha256_bytes(subject.canonical_bytes(payload)) == (
        "9bf946e6d8c9356d24da798d774308edd6827759ffe313608cd1809c03ce18ae"
    )


def test_monotonic_timestamps_are_bound_into_state_digest() -> None:
    host = make_host("control")
    code, stdout, stderr = run_action("teardown-check", host)
    envelope = decode_ok(code, stdout, stderr, host)
    assert envelope["started_utc"] < envelope["ended_utc"]
    assert envelope["state_sha256"] != envelope["effect_sha256"]
    assert host._mono > 1_000_000_000


def test_missing_challenge_or_request_hash_fails_closed() -> None:
    host = make_host("control")
    code, stdout, stderr = run_action(
        "route-decision", host, argv_for("route-decision")[:-1]
    )
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"missing or extra" in stderr
    bad = argv_for("route-decision", **{"request-hash": "a" * 64})
    code, stdout, stderr = run_action("route-decision", host, bad)
    assert code == subject.REFUSAL_EXIT
    assert b"request hash mismatch" in stderr


def test_xray_inbound_and_aggregate_stats_are_rejected() -> None:
    host = make_host("data-cover")
    host.command_defaults[subject.XRAY_STATSQUERY_ARGV] = subject.CommandResult(
        dumps(
            {
                "stat": [
                    {"name": "inbound>>>api>>>traffic>>>uplink", "value": "9"},
                    {"name": "inbound>>>api>>>traffic>>>downlink", "value": "8"},
                ]
            }
        )
    )
    host.commands[subject.XRAY_STATSQUERY_ARGV] = [
        host.command_defaults[subject.XRAY_STATSQUERY_ARGV]
    ]
    code, stdout, stderr = run_action(
        "connect-cover-xray", host, argv_for("connect-cover-xray", phase="observe-after")
    )
    assert code == subject.REFUSAL_EXIT
    assert b"aggregate" in stderr or b"exact user" in stderr


def test_awg_peer_transfer_is_required() -> None:
    host = make_host("data-cover")
    host.command_defaults[
        (subject.BIN_AWG, "show", subject.AWG_IFACE, "latest-handshakes")
    ] = subject.CommandResult(awg_handshake_bytes(HANDSHAKE_UNIX))
    host.command_defaults[(subject.BIN_AWG, "show", subject.AWG_IFACE, "transfer")] = (
        subject.CommandResult(b"")
    )
    host.commands[(subject.BIN_AWG, "show", subject.AWG_IFACE, "latest-handshakes")] = [
        subject.CommandResult(awg_handshake_bytes(HANDSHAKE_UNIX))
    ]
    host.commands[(subject.BIN_AWG, "show", subject.AWG_IFACE, "transfer")] = [
        subject.CommandResult(b"")
    ]
    code, stdout, stderr = run_action(
        "connect-cover-awg", host, argv_for("connect-cover-awg", phase="observe-after")
    )
    assert code == subject.REFUSAL_EXIT
    assert b"AWG peer identity is absent" in stderr or b"malformed" in stderr


def test_boot_instance_and_process_bindings_are_required() -> None:
    host = make_host("control")
    del host.files[subject.BOOT_ID_PATH]
    code, stdout, stderr = run_action("teardown-check", host)
    assert code == subject.REFUSAL_EXIT
    assert b"boot id" in stderr or b"unreadable" in stderr
    host = make_host("control")
    del host.files[subject.INSTANCE_ID_PATH]
    code, stdout, stderr = run_action("teardown-check", host)
    assert code == subject.REFUSAL_EXIT
    assert b"instance id is absent" in stderr
    host = make_host("control")
    del host.files["/proc/1001/comm"]
    code, stdout, stderr = run_action("teardown-check", host)
    assert code == subject.REFUSAL_EXIT
    assert b"process identity" in stderr or b"unreadable" in stderr


def test_nonce_bound_transaction_is_reconstructable() -> None:
    host = make_host("control")
    envelope = decode_ok(*run_action("route-decision", host), host)
    response = envelope["transaction"]["response"]
    assert response == envelope["data"]
    assert envelope["transaction"]["nonce"] == CHALLENGE
    assert envelope["transaction"]["response_sha256"] == subject.sha256_bytes(
        subject.canonical_bytes(response)
    )
    observe_host = make_host("data-winn3", status=winn3_status())
    observe = decode_ok(
        *run_action(
            "connect-primary",
            observe_host,
            argv_for("connect-primary", phase="observe-after"),
        ),
        observe_host,
    )
    assert observe["data"] is None
    assert observe["transaction"]["nonce"] == CHALLENGE
    assert observe["transaction"]["response"]["phase"] == "observe-after"
    assert observe["transaction"]["response"]["instance_id"] == INSTANCE_ID


def test_nft_cleanup_remains_deterministic() -> None:
    host = make_host("data-cover")
    seed_nft(host, subject.NFT_AWG_TABLE, subject.NFT_AWG_FILE)
    first = decode_ok(*run_action("inject-awg-block", host), host)
    restore_host = make_host(
        "data-cover",
        state=session_state(
            control_id="negative-awg-block", protocol="awg", node=COVER, state="blocked"
        ),
    )
    seed_nft(restore_host, subject.NFT_AWG_TABLE, subject.NFT_AWG_FILE, restore=True)
    second = decode_ok(*run_action("restore-awg", restore_host), restore_host)
    again_host = make_host(
        "data-cover",
        state=session_state(
            control_id="negative-awg-block", protocol="awg", node=COVER, state="blocked"
        ),
    )
    seed_nft(again_host, subject.NFT_AWG_TABLE, subject.NFT_AWG_FILE, restore=True)
    third = decode_ok(*run_action("restore-awg", again_host), again_host)
    assert first["data"] == {
        "control_id": "negative-awg-block",
        "protocol": "awg",
        "state": "blocked",
    }
    assert second["data"] == third["data"]
    assert second["data"]["state"] == "restored"
    assert (subject.BIN_NFT, "delete", "table", "inet", subject.NFT_AWG_TABLE) in (
        restore_host.runs
    )


def test_rfc3339nano_utc_parsing_is_exact_to_nanoseconds() -> None:
    earlier = "2026-08-24T12:00:10.123456788Z"
    later = "2026-08-24T12:00:10.123456789Z"
    one_ns = "2026-08-24T12:00:00.000000001Z"
    two_ns = "2026-08-24T12:00:00.000000002Z"
    assert subject.parse_utc(earlier) < subject.parse_utc(later)
    assert subject.parse_utc(one_ns) < subject.parse_utc(two_ns)
    assert subject.parse_utc(later) > subject.parse_utc(earlier)
    assert subject.parse_utc(one_ns) != subject.parse_utc(two_ns)
    assert subject.parse_utc("2026-08-24T12:00:00.123Z") == subject.parse_utc(
        "2026-08-24T12:00:00.123000000Z"
    )
    assert subject.parse_utc("2026-08-24T12:00:00Z") == subject.parse_utc(
        "2026-08-24T12:00:00.000000000Z"
    )
    whole = datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc)
    assert subject.parse_utc(one_ns) > whole
    assert subject.parse_utc(one_ns) != whole
    assert subject.parse_utc("2026-08-24T12:00:00Z") == whole
    delta = subject.parse_utc(two_ns) - subject.parse_utc(one_ns)
    assert delta.total_seconds() == 1 / 1_000_000_000
    assert subject.format_rfc3339_nano(subject.parse_utc(one_ns).unix_ns) == one_ns
    assert subject.format_rfc3339_nano(subject.parse_utc(later).unix_ns) == later


@pytest.mark.parametrize(
    "value",
    [
        "2026-08-24T12:00:10+00:00",
        "2026-08-24T12:00:10.123456789+00:00",
        "2026-08-24T12:00:10.123456789-00:00",
        "2026-08-24T12:00:10.123456789z",
        "2026-08-24T12:00:10.1234567890Z",
        "2026-08-24T12:00:10Z ",
        "2026-08-24 12:00:10Z",
        "2026-02-30T00:00:00Z",
        "2026-08-24T24:00:00Z",
    ],
)
def test_rfc3339nano_rejects_non_canonical_or_non_z_timestamps(value: str) -> None:
    with pytest.raises(subject.RemoteActionError, match="canonical UTC|UTC Z form"):
        subject.parse_utc(value)


def test_winn3_status_delta_accepts_one_nanosecond_progress() -> None:
    before = winn3_status(
        delivered=11,
        writes=11,
        sequence=9,
        observed_utc="2026-08-24T12:00:10.123456788Z",
        observed_monotonic_ns=9_000_000_000,
    )
    after = winn3_status(
        delivered=12,
        writes=12,
        sequence=10,
        observed_utc="2026-08-24T12:00:10.123456789Z",
        observed_monotonic_ns=10_000_000_000,
    )
    assert subject.winn3_status_delta(before, after) == {
        "inner_packets_delivered": 1,
        "rx_device_writes": 1,
        "sequence": 1,
    }


def test_winn3_status_delta_rejects_one_nanosecond_reversal() -> None:
    before = winn3_status(
        delivered=11,
        writes=11,
        sequence=9,
        observed_utc="2026-08-24T12:00:10.123456789Z",
        observed_monotonic_ns=9_000_000_000,
    )
    after = winn3_status(
        delivered=12,
        writes=12,
        sequence=10,
        observed_utc="2026-08-24T12:00:10.123456788Z",
        observed_monotonic_ns=10_000_000_000,
    )
    with pytest.raises(
        subject.RemoteActionError, match="observation is not strictly ordered"
    ):
        subject.winn3_status_delta(before, after)


def _nano_attempt_events(stamps: tuple[str, str, str, str]) -> list[dict[str, Any]]:
    events = valid_fallback_events()
    for event, stamp in zip(events, stamps, strict=True):
        event["utc"] = stamp
    return events


@pytest.mark.parametrize(
    "mutation",
    (
        lambda events: events[:1],
        lambda events: [{**events[0], "result": "connected"}, *events[1:]],
        lambda events: [events[0], {**events[1], "node": WINN3}, *events[2:]],
        lambda events: [events[0], events[1], {**events[2], "monotonic_ns": 1}, events[3]],
        lambda events: [events[0], events[1], {**events[2], "utc": events[1]["utc"]}, events[3]],
    ),
)
def test_attempt_journal_rejects_malformed_historical_prefix(mutation: Any) -> None:
    events = mutation(valid_fallback_events())
    host = make_host("control")
    host.files[subject.ATTEMPT_JOURNAL_PATH] = subject.canonical_bytes(
        attempt_journal(events)
    )
    with pytest.raises(subject.RemoteActionError, match="invalid|stale|strictly ordered"):
        subject.load_attempt_journal(host, required=True)


def test_attempt_utc_accepts_sub_microsecond_order() -> None:
    stamps = (
        "2026-08-24T12:00:01.000000001Z",
        "2026-08-24T12:00:01.000000002Z",
        "2026-08-24T12:00:01.000000003Z",
        "2026-08-24T12:00:01.000000004Z",
    )
    events = _nano_attempt_events(stamps)
    observed = subject.require_awg_then_xray_attempts(
        attempt_journal([]),
        attempt_journal(events[:2]),
        attempt_journal(events),
        {"action": "probe-awg-block", "correlation_id": CORR, "session_id": SESSION},
        node=COVER,
        started_mono=11_000_000_000,
        ended_mono=16_000_000_000,
        started=subject.parse_utc("2026-08-24T12:00:01.000000000Z"),
        ended=subject.parse_utc("2026-08-24T12:00:01.000000005Z"),
    )
    assert [event["utc"] for event in observed] == list(stamps)


def test_attempt_utc_rejects_sub_microsecond_reversal() -> None:
    events = _nano_attempt_events(
        (
            "2026-08-24T12:00:01.000000002Z",
            "2026-08-24T12:00:01.000000001Z",
            "2026-08-24T12:00:01.000000003Z",
            "2026-08-24T12:00:01.000000004Z",
        )
    )
    with pytest.raises(
        subject.RemoteActionError,
        match="UTC timestamps are not strictly ordered",
    ):
        subject.require_awg_then_xray_attempts(
            attempt_journal([]),
            attempt_journal(events[:2]),
            attempt_journal(events),
            {"action": "probe-awg-block", "correlation_id": CORR, "session_id": SESSION},
            node=COVER,
            started_mono=11_000_000_000,
            ended_mono=16_000_000_000,
            started=subject.parse_utc("2026-08-24T12:00:01.000000000Z"),
            ended=subject.parse_utc("2026-08-24T12:00:01.000000005Z"),
        )


def test_read_regular_bounds_output() -> None:
    with tempfile.NamedTemporaryFile(delete=False) as handle:
        handle.write(b"A" * (subject.MAX_OUTPUT + 1))
        name = handle.name
    try:
        with pytest.raises(subject.RemoteActionError, match="too large"):
            subject._read_regular(name, "tmp")
    finally:
        os.unlink(name)


def test_hash_executable_refuses_helper_symlink() -> None:
    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        real = root / "real"
        real.write_bytes(HELPER_BYTES)
        link = root / "link"
        link.symlink_to(real)
        with pytest.raises(
            subject.RemoteActionError, match="regular single-link file|unreadable"
        ):
            subject.ProductionHost().hash_executable(str(link))


def test_attempt_broker_held_descriptor_rehashes_exact_bytes_after_use(
    tmp_path: Path,
) -> None:
    root, _broker = installed_broker_tree(tmp_path)
    held = subject._hold_attempt_broker_at_root(
        os.fspath(root), subject.ATTEMPT_BROKER_PATH
    )
    try:
        assert held.finish() == subject.sha256_bytes(BROKER_BYTES)
    finally:
        held.close()


def test_attempt_broker_fixed_path_rejects_absence_and_wrong_path(tmp_path: Path) -> None:
    root, broker = installed_broker_tree(tmp_path)
    broker.unlink()
    with pytest.raises(subject.RemoteActionError, match="absent or unsafe"):
        subject._hold_attempt_broker_at_root(
            os.fspath(root), subject.ATTEMPT_BROKER_PATH
        )
    with pytest.raises(subject.RemoteActionError, match="path is not fixed"):
        subject._hold_attempt_broker_at_root(
            os.fspath(root),
            "/usr/local/libexec/substituted-attempt-broker",
        )


@pytest.mark.parametrize("substitution", ("symlink", "hardlink"))
def test_attempt_broker_rejects_symlink_or_hardlink_substitution(
    tmp_path: Path,
    substitution: str,
) -> None:
    root, broker = installed_broker_tree(tmp_path)
    if substitution == "symlink":
        real = broker.with_name("broker-real")
        broker.replace(real)
        broker.symlink_to(real.name)
    else:
        os.link(broker, broker.with_name("broker-alias"))
    with pytest.raises(
        subject.RemoteActionError,
        match="protected regular single-link file|absent or unsafe",
    ):
        subject._hold_attempt_broker_at_root(
            os.fspath(root), subject.ATTEMPT_BROKER_PATH
        )


def test_attempt_broker_rejects_writable_ancestry_and_file(tmp_path: Path) -> None:
    ancestry_root, _broker = installed_broker_tree(tmp_path / "ancestry")
    (ancestry_root / "usr" / "local").chmod(0o775)
    with pytest.raises(subject.RemoteActionError, match="ancestry is unsafe"):
        subject._hold_attempt_broker_at_root(
            os.fspath(ancestry_root), subject.ATTEMPT_BROKER_PATH
        )

    file_root, writable_broker = installed_broker_tree(tmp_path / "file")
    writable_broker.chmod(0o755)
    with pytest.raises(subject.RemoteActionError, match="protected regular single-link"):
        subject._hold_attempt_broker_at_root(
            os.fspath(file_root), subject.ATTEMPT_BROKER_PATH
        )


def test_attempt_broker_held_descriptor_rejects_path_replacement(tmp_path: Path) -> None:
    root, broker = installed_broker_tree(tmp_path)
    held = subject._hold_attempt_broker_at_root(
        os.fspath(root), subject.ATTEMPT_BROKER_PATH
    )
    replacement = broker.with_name("broker-replacement")
    replacement.write_bytes(BROKER_BYTES)
    replacement.chmod(subject.ATTEMPT_BROKER_INSTALL_MODE)
    os.replace(replacement, broker)
    try:
        with pytest.raises(
            subject.RemoteActionError,
            match="path changed|protected regular single-link",
        ):
            held.finish()
    finally:
        held.close()


def test_attempt_broker_held_descriptor_rejects_ancestry_replacement(
    tmp_path: Path,
) -> None:
    root, broker = installed_broker_tree(tmp_path)
    held = subject._hold_attempt_broker_at_root(
        os.fspath(root), subject.ATTEMPT_BROKER_PATH
    )
    old_parent = broker.parent.with_name("libexec-original")
    broker.parent.replace(old_parent)
    broker.parent.mkdir(mode=0o755)
    substituted = broker.parent / broker.name
    substituted.write_bytes(BROKER_BYTES)
    substituted.chmod(subject.ATTEMPT_BROKER_INSTALL_MODE)
    try:
        with pytest.raises(subject.RemoteActionError, match="ancestry changed"):
            held.finish()
    finally:
        held.close()


def test_attempt_broker_held_descriptor_rejects_in_place_byte_mutation(
    tmp_path: Path,
) -> None:
    root, broker = installed_broker_tree(tmp_path)
    broker.chmod(0o755)
    writer_fd = os.open(broker, os.O_RDWR)
    broker.chmod(subject.ATTEMPT_BROKER_INSTALL_MODE)
    held = subject._hold_attempt_broker_at_root(
        os.fspath(root), subject.ATTEMPT_BROKER_PATH
    )
    try:
        os.pwrite(writer_fd, b"X", 0)
        os.fsync(writer_fd)
        with pytest.raises(subject.RemoteActionError, match="changed"):
            held.finish()
    finally:
        held.close()
        os.close(writer_fd)


def test_attempt_broker_held_descriptor_rejects_metadata_and_ctime_drift(
    tmp_path: Path,
) -> None:
    root, broker = installed_broker_tree(tmp_path)
    held = subject._hold_attempt_broker_at_root(
        os.fspath(root), subject.ATTEMPT_BROKER_PATH
    )
    before = broker.stat()
    os.utime(
        broker,
        ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000),
    )
    try:
        with pytest.raises(subject.RemoteActionError, match="path changed|changed during use"):
            held.finish()
    finally:
        held.close()


def test_production_run_bounds_output() -> None:
    with tempfile.NamedTemporaryFile(delete=False) as handle:
        handle.write(b"B" * (subject.MAX_OUTPUT + 1))
        name = handle.name
    try:
        with pytest.raises(subject.RemoteActionError, match="too large"):
            subject.ProductionHost().run(["/bin/cat", name])
    finally:
        os.unlink(name)


@pytest.mark.parametrize("stream_fd", [1, 2])
def test_production_run_kills_streaming_output_before_child_continues(
    monkeypatch: pytest.MonkeyPatch, stream_fd: int
) -> None:
    monkeypatch.setattr(subject, "MAX_OUTPUT", 64 * 1024)
    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        marker = root / "child-continued"
        writer = root / "writer.py"
        writer.write_text(
            "import os\n"
            "import pathlib\n"
            "import sys\n"
            "fd = int(sys.argv[1])\n"
            "for _ in range(1024):\n"
            "    os.write(fd, b'X' * 65536)\n"
            "pathlib.Path(sys.argv[2]).write_bytes(b'unsafe')\n",
            encoding="ascii",
        )
        with pytest.raises(subject.RemoteActionError, match="too large"):
            subject.ProductionHost().run(
                [sys.executable, str(writer), str(stream_fd), str(marker)]
            )
        assert not marker.exists()


def test_validate_request_rejects_non_canonical_instance() -> None:
    request = subject.parse_argv(argv_for("route-decision"))
    request["instance"] = "Proof-Control-A1"
    request["request_sha256"] = subject.request_digest(request)
    with pytest.raises(subject.RemoteActionError, match="instance is invalid"):
        subject.validate_request(request)


def test_write_file_refuses_uncontained_path() -> None:
    host = make_host("control")
    with pytest.raises(subject.RemoteActionError, match="not contained"):
        host.write_file("/tmp/evil.payload", b"payload\n", 0o600)
    with pytest.raises(subject.RemoteActionError, match="not contained|too large"):
        subject._atomic_write("/tmp/evil.payload", b"payload\n", 0o600)


def test_marker_extra_identity_keys_fail_closed() -> None:
    host = make_host("control")
    marker = json.loads(host.files[subject.MARKER_PATH].decode("ascii"))
    marker["role_alias"] = "core"
    host.files[subject.MARKER_PATH] = dumps(marker)
    code, stdout, stderr = run_action("route-decision", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"schema fields" in stderr


def test_descriptor_payload_swap_during_verify_fails() -> None:
    host = make_host("control")
    original = host.read_file

    def swapped(path: str) -> bytes:
        data = original(path)
        if path == subject.DESCRIPTOR_PAYLOAD_PATH and path in host.writes:
            return b"swapped-payload"
        return data

    host.read_file = swapped  # type: ignore[method-assign]
    code, stdout, stderr = run_action("route-decision", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"changed while being verified" in stderr


def test_duplicate_withdraw_cover_is_rejected() -> None:
    host = make_host(
        "control",
        state=session_state(
            control_id="negative-cover-withdrawn",
            protocol="",
            node=COVER,
            state="withdrawn",
        ),
    )
    seed_nft(host, subject.NFT_COVER_TABLE, subject.NFT_COVER_FILE)
    code, stdout, stderr = run_action("withdraw-cover", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"duplicate" in stderr
    assert (subject.BIN_NFT, "-f", subject.NFT_COVER_FILE) not in host.runs


def test_replayed_request_hash_is_rejected() -> None:
    host = make_host("control")
    first = decode_ok(*run_action("route-decision", host), host)
    assert first["action"] == "route-decision"
    code, stdout, stderr = run_action("route-decision", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"replayed request is forbidden" in stderr


def test_concurrent_action_lock_fails_closed() -> None:
    host = make_host("control")
    host.acquire_action_lock()
    code, stdout, stderr = run_action("route-decision", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"concurrent remote action is forbidden" in stderr
    host.release_action_lock()
    envelope = decode_ok(*run_action("route-decision", host), host)
    assert envelope["operation"] == "query-signed-route-decision"


def test_helper_identity_mismatch_fails_closed() -> None:
    host = make_host("control")
    record = helper_identity_record("control", CONTROL)
    record["role"] = "data-cover"
    host.files[subject.HELPER_IDENTITY_PATH] = subject.canonical_bytes(record)
    code, stdout, stderr = run_action("route-decision", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"helper identity" in stderr or b"stale" in stderr

    host = make_host("control")
    del host.files[subject.HELPER_IDENTITY_PATH]
    code, stdout, stderr = run_action("route-decision", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"unreadable" in stderr or b"helper identity" in stderr

    host = make_host("control")
    record = helper_identity_record("control", CONTROL)
    record["sha256"] = "a" * 64
    host.files[subject.HELPER_IDENTITY_PATH] = subject.canonical_bytes(record)
    code, stdout, stderr = run_action("route-decision", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"stale" in stderr


def test_unit_fragment_outside_systemd_paths_fails() -> None:
    host = make_host("control")
    host.command_defaults[
        (
            subject.BIN_SYSTEMCTL,
            "show",
            "wins-hub.service",
            "--no-pager",
            "--property=Id,FragmentPath,MainPID,ActiveState",
        )
    ] = subject.CommandResult(
        show_unit("wins-hub.service", 1001, "/tmp/wins-hub.service")
    )
    code, stdout, stderr = run_action("teardown-check", host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"not contained" in stderr


def test_o_nofollow_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
    with pytest.raises(subject.RemoteActionError, match="O_NOFOLLOW is required"):
        subject._nofollow_flags()
