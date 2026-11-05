#!/usr/bin/env python3
"""Deterministic Smart Boost packet stress simulator.

This exercises the encrypted frame format and the packet reordering behavior
used by the Android SmartBoostEngine and the data-plane wins-boostd daemon.
It intentionally simulates jitter, duplication, loss, and cross-path reorder.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import random
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"WBST"
TYPE_DATA = 1
HEADER = struct.Struct("!4sBBQ12s")
AAD_SIZE = 14


class FrameCodec:
    def __init__(self, key_text: str) -> None:
        try:
            key = base64.b64decode(key_text)
        except Exception:
            key = b""
        if len(key) not in (16, 24, 32):
            key = hashlib.sha256(key_text.encode("utf-8")).digest()
        self.aes = AESGCM(key)

    def encrypt(self, frame_type: int, path_id: int, frame_seq: int, payload: bytes) -> bytes:
        nonce = os.urandom(12)
        header = HEADER.pack(MAGIC, frame_type, path_id & 0xFF, frame_seq, nonce)
        return header + self.aes.encrypt(nonce, payload, header[:AAD_SIZE])

    def decrypt(self, packet: bytes) -> tuple[int, int, int, bytes] | None:
        if len(packet) < HEADER.size:
            return None
        magic, frame_type, path_id, frame_seq, nonce = HEADER.unpack(packet[: HEADER.size])
        if magic != MAGIC:
            return None
        try:
            payload = self.aes.decrypt(nonce, packet[HEADER.size :], packet[:AAD_SIZE])
        except Exception:
            return None
        return frame_type, path_id, frame_seq, payload


class ReorderBuffer:
    def __init__(self, wait_ms: int, max_packets: int) -> None:
        self.expected = 1
        self.pending: dict[int, tuple[bytes, float]] = {}
        self.wait_ms = wait_ms
        self.max_packets = max_packets

    def push(self, frame_seq: int, payload: bytes, now_ms: float) -> list[tuple[int, bytes]]:
        if frame_seq < self.expected:
            return []
        self.pending.setdefault(frame_seq, (payload, now_ms))
        return self._drain(now_ms)

    def flush_expired(self, now_ms: float) -> list[tuple[int, bytes]]:
        if not self.pending:
            return []
        first_seq = min(self.pending)
        _, created_ms = self.pending[first_seq]
        if (
            len(self.pending) > self.max_packets
            or now_ms - created_ms > self.wait_ms
        ):
            self.expected = first_seq
            return self._drain(now_ms)
        return []

    def has_pending(self) -> bool:
        return bool(self.pending)

    def _drain(self, now_ms: float) -> list[tuple[int, bytes]]:
        ready: list[tuple[int, bytes]] = []
        while self.expected in self.pending:
            seq = self.expected
            payload, _ = self.pending.pop(seq)
            ready.append((seq, payload))
            self.expected += 1
        if not ready and self.pending:
            first_seq = min(self.pending)
            _, created_ms = self.pending[first_seq]
            if len(self.pending) > self.max_packets or now_ms - created_ms > self.wait_ms:
                self.expected = first_seq
                return self._drain(now_ms)
        return ready


@dataclass(frozen=True)
class PathProfile:
    path_id: int
    base_ms: int
    jitter_ms: int
    loss_rate: float
    duplicate_rate: float


@dataclass(frozen=True)
class Event:
    arrive_ms: float
    packet: bytes
    original_seq: int
    duplicate: bool = False


def payload_for(seq: int, size: int) -> bytes:
    prefix = struct.pack("!QI", seq, size)
    filler = hashlib.sha256(prefix).digest()
    body = bytearray()
    while len(body) < size:
        body.extend(filler)
        filler = hashlib.sha256(filler).digest()
    return prefix + bytes(body[:size])


def simulate(args: argparse.Namespace, profiles: list[PathProfile]) -> dict[str, int | float]:
    rng = random.Random(args.seed)
    codec = FrameCodec(args.key)
    events: list[Event] = []
    lost: set[int] = set()
    duplicate_count = 0

    for seq in range(1, args.packets + 1):
        profile = min(
            profiles,
            key=lambda item: rng.random() + (item.base_ms / 1000.0),
        )
        if rng.random() < profile.loss_rate:
            lost.add(seq)
            continue
        payload = payload_for(seq, args.payload_size)
        frame = codec.encrypt(TYPE_DATA, profile.path_id, seq, payload)
        send_ms = seq * args.send_interval_ms
        delay = profile.base_ms + rng.randint(0, profile.jitter_ms)
        events.append(Event(send_ms + delay, frame, seq))
        if rng.random() < profile.duplicate_rate:
            duplicate_count += 1
            events.append(
                Event(
                    send_ms + delay + rng.randint(1, profile.jitter_ms + 1),
                    frame,
                    seq,
                    True,
                )
            )

    rng.shuffle(events)
    events.sort(key=lambda item: (item.arrive_ms, rng.random()))

    reorder = ReorderBuffer(args.reorder_wait_ms, args.reorder_max_packets)
    delivered: list[int] = []
    payload_failures = 0
    decrypt_failures = 0
    last_now = 0

    for event in events:
        last_now = max(last_now, event.arrive_ms)
        decoded = codec.decrypt(event.packet)
        if not decoded:
            decrypt_failures += 1
            continue
        frame_type, _, frame_seq, payload = decoded
        if frame_type != TYPE_DATA:
            continue
        for seq, ready in reorder.push(frame_seq, payload, last_now):
            if ready != payload_for(seq, args.payload_size):
                payload_failures += 1
            delivered.append(seq)
        for seq, ready in reorder.flush_expired(last_now):
            if ready != payload_for(seq, args.payload_size):
                payload_failures += 1
            delivered.append(seq)

    shutdown_now = last_now + args.reorder_wait_ms + 1
    shutdown_flushes = 0
    while reorder.has_pending() and shutdown_flushes < args.packets:
        for seq, ready in reorder.flush_expired(shutdown_now):
            if ready != payload_for(seq, args.payload_size):
                payload_failures += 1
            delivered.append(seq)
        shutdown_now += args.reorder_wait_ms + 1
        shutdown_flushes += 1

    delivered_set = set(delivered)
    expected_set = set(range(1, args.packets + 1)) - lost
    duplicate_delivery = len(delivered) - len(delivered_set)
    out_of_order = sum(1 for a, b in zip(delivered, delivered[1:]) if b <= a)
    missing = len(expected_set - delivered_set)
    unexpected = len(delivered_set - expected_set)

    return {
        "packets": args.packets,
        "sent_events": len(events),
        "lost": len(lost),
        "duplicates_in_network": duplicate_count,
        "delivered": len(delivered),
        "missing": missing,
        "unexpected": unexpected,
        "duplicate_delivery": duplicate_delivery,
        "out_of_order_delivery": out_of_order,
        "decrypt_failures": decrypt_failures,
        "payload_failures": payload_failures,
    }


def default_profiles(args: argparse.Namespace) -> list[PathProfile]:
    return [
        PathProfile(1, args.wifi_base_ms, args.wifi_jitter_ms, args.wifi_loss, args.duplicate_rate),
        PathProfile(2, args.cell_base_ms, args.cell_jitter_ms, args.cell_loss, args.duplicate_rate),
    ]


def apply_profile(args: argparse.Namespace) -> None:
    if args.profile == "clean":
        args.packets = args.packets or 4000
        args.wifi_base_ms = 18
        args.wifi_jitter_ms = 24
        args.wifi_loss = 0.0
        args.cell_base_ms = 38
        args.cell_jitter_ms = 32
        args.cell_loss = 0.0
        args.duplicate_rate = 0.004
    elif args.profile == "lossy":
        args.packets = args.packets or 8000
        args.wifi_base_ms = 24
        args.wifi_jitter_ms = 90
        args.wifi_loss = 0.003
        args.cell_base_ms = 45
        args.cell_jitter_ms = 140
        args.cell_loss = 0.006
        args.duplicate_rate = 0.012
    elif args.profile == "asymmetric":
        args.packets = args.packets or 10000
        args.wifi_base_ms = 22
        args.wifi_jitter_ms = 80
        args.wifi_loss = 0.002
        args.cell_base_ms = 95
        args.cell_jitter_ms = 155
        args.cell_loss = 0.006
        args.duplicate_rate = 0.01
    elif args.profile == "bursty":
        args.packets = args.packets or 12000
        args.send_interval_ms = 0.18
        args.wifi_base_ms = 26
        args.wifi_jitter_ms = 95
        args.wifi_loss = 0.002
        args.cell_base_ms = 62
        args.cell_jitter_ms = 165
        args.cell_loss = 0.006
        args.duplicate_rate = 0.018
    elif args.profile == "v3-adaptive":
        args.packets = args.packets or 16000
        args.send_interval_ms = 0.12
        args.wifi_base_ms = 18
        args.wifi_jitter_ms = 125
        args.wifi_loss = 0.0015
        args.cell_base_ms = 54
        args.cell_jitter_ms = 210
        args.cell_loss = 0.0045
        args.duplicate_rate = 0.022


def main() -> int:
    parser = argparse.ArgumentParser(description="Stress-test Smart Boost frame ordering locally.")
    parser.add_argument(
        "--profile",
        choices=["custom", "clean", "lossy", "asymmetric", "bursty", "v3-adaptive"],
        default="lossy",
    )
    parser.add_argument("--packets", type=int)
    parser.add_argument("--payload-size", type=int, default=1180)
    parser.add_argument("--send-interval-ms", type=float, default=0.35)
    parser.add_argument("--seed", type=int, default=20260630)
    parser.add_argument("--key", default="wins-smart-boost-local-stress-key")
    parser.add_argument("--reorder-wait-ms", type=int, default=240)
    parser.add_argument("--reorder-max-packets", type=int, default=2048)
    parser.add_argument("--wifi-base-ms", type=int, default=24)
    parser.add_argument("--wifi-jitter-ms", type=int, default=90)
    parser.add_argument("--wifi-loss", type=float, default=0.003)
    parser.add_argument("--cell-base-ms", type=int, default=45)
    parser.add_argument("--cell-jitter-ms", type=int, default=140)
    parser.add_argument("--cell-loss", type=float, default=0.006)
    parser.add_argument("--duplicate-rate", type=float, default=0.012)
    args = parser.parse_args()
    apply_profile(args)
    if args.packets is None:
        args.packets = 8000

    result = simulate(args, default_profiles(args))
    print(f"profile: {args.profile}")
    for key, value in result.items():
        print(f"{key}: {value}")

    failures = [
        result["missing"],
        result["unexpected"],
        result["duplicate_delivery"],
        result["out_of_order_delivery"],
        result["decrypt_failures"],
        result["payload_failures"],
    ]
    if any(int(item) != 0 for item in failures):
        print("RESULT: FAIL")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
