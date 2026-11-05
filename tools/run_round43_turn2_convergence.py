#!/usr/bin/env python3
"""Round 43 Turn 2: Cross-Examination and Convergence Debate.

Circulates Turn 1 positions and Arbiter ground-truth findings to all three standing podiums:
  1. Gemini 3.8 Flash High (agy CLI, --effort high)
  2. Claude Opus 5 extra-high (claude CLI, --effort high)
  3. GPT-5.6 Sol Pro extra-high (OpenRouter, openai/gpt-5.6-sol-pro, service_tier: flex)

Adheres strictly to the Iterative Convergence Debate Protocol (ICDP §13).
Zero em/en dashes as connectors. Zero AI cliches. Bold top-level list keys only.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import pathlib
import subprocess
import threading
import time

_tools_dir = pathlib.Path(__file__).parent.resolve()
import sys
sys.path.insert(0, str(_tools_dir))
import run_round43_debate as r43

REPO_ROOT = r43.REPO_ROOT
DOCS_EVIDENCE = r43.DOCS_EVIDENCE
ROUND43_DIR = r43.ROUND43_DIR
TURN2_DIR = ROUND43_DIR / "turn2-cross"
TURN2_DIR.mkdir(parents=True, exist_ok=True)
RAW_OUTPUT = DOCS_EVIDENCE / "debate_round43_turn2_raw.json"

CACHE_LOCK = threading.Lock()


def load_cache() -> dict:
    with CACHE_LOCK:
        if RAW_OUTPUT.exists():
            try:
                return json.loads(RAW_OUTPUT.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}


def update_cache(key: str, value: str):
    with CACHE_LOCK:
        cache = {}
        if RAW_OUTPUT.exists():
            try:
                cache = json.loads(RAW_OUTPUT.read_text(encoding="utf-8"))
            except Exception:
                cache = {}
        cache[key] = value
        RAW_OUTPUT.write_text(json.dumps(cache, indent=2), encoding="utf-8")


ARBITER_FINDINGS = """# ARBITER GROUND-TRUTH VERIFICATIONS & CLARIFICATIONS FOR TURN 2

1. **Unanimous Treaty Convergence on OI-3 (Option 2)**:
   All three standing podiums (Gemini 3.8 Flash High, Claude Opus 5, and GPT-5.6 Sol Pro) independently and unanimously agreed that Option 2 is architecturally and mathematically superior to Option 1:
   - `core.MaxBatchSize = 32` remains frozen for crypto worker pool dispatch (`jobs [MaxBatchSize]cryptoJob`), preserving L1 data cache locality (43.9 KiB working set per Oryon core) and avoiding `sendMu` lock hold latency spikes (4.8 µs at 32 packets vs 30.4 µs at 256 packets).
   - In `winn3/driver/loop.go`, carrier transmit batch capacity is decoupled from crypto batch size via `carrierBatchCapacity = 256` (or `MaxTxBatchSize = 256`), polling the session outbox in up to 8 non-blocking chunks of 32 datagrams (`TxBatchesPerSend = 8`) before issuing a single `batchCarrier.SendBatch` call.
   - If the session outbox contains fewer than 256 datagrams, `loop.drain` exits immediately, adding zero transmission latency.

2. **Unanimous Alignment on OI-1 (Proposal A vs Proposal B)**:
   All three podiums unanimously rejected Proposal B (`UDP_SEGMENT` / GSO) due to ChaCha20-Poly1305 variable message lengths, PMTU discovery fragility, and Android driver inconsistency.
   All three podiums agree on Proposal A (expanding `sendmmsg` carrier batch to 256 datagrams).
   The Arbiter accepts Opus 5's arithmetic proof: widening `sendmmsg` from 32 to 256 reduces syscall frequency by 87.5% (from 2,845/s to 355.6/s) and saves ~0.27 µs per packet of fixed entry cost. While this alone does not retire the entire 15.17 µs per packet gap, it is a required foundational prerequisite.
   The Arbiter confirms live ground truth on socket buffering: `carrier/udp_socket_buffers.go` sets `DefaultUDPSocketBufferBytes = 8 MiB`. On the S26 Ultra, `net.core.wmem_max = 8 MiB`, and `getsockopt(SO_SNDBUF)` verifies the socket is granted the full 8 MiB. A 256-datagram batch requires ~652 KiB of skb memory (7.8% of socket buffer), eliminating any risk of partial writes from buffer exhaustion.

3. **Ground Truth on OI-2 (toEngine Channel Lifecycle in cmd/winn-datapath)**:
   In response to Sol Pro's disclosure requirements:
   - In `winn3_frame.go`: `flushInboundBatch(batch *[][]byte)` passes `*batch` to `device.offerBatch(*batch)`. Each packet slice is allocated from `packetPool` via `allocPacket(payload)` and copied. After `offerBatch` returns, `*batch = (*batch)[:0]`. The producer never reuses the packet buffers or slice headers after enqueue.
   - In `winn3_frame_device.go`: `offerBatch` currently pushes each packet individually to `toEngine chan []byte` with capacity 65,536.
   - In `ReadBatch(bufs [][]byte)`: the consumer pulls from `toEngine`, copies each packet into caller buffers, and immediately recycles the buffer via `d.recycle(pkt)` back into `packetPool`.
   - In Run 15 telemetry: `d.droppedToEngine` was 0 across all 419,954,688 bytes.
   - Podiums are asked whether to implement `carrierBatchCapacity = 256` in `loop.go` first (OI-1A and OI-3 Option 2, which requires zero channel refactoring and touches only `loop.go`), or include the batched descriptor ring in this round.

4. **Unanimous Confirmation of OI-4 (Downlink Freeze Invariant)**:
   Downlink datapath, buffer allocations, and measurement formulas remain 100% frozen (Treaty Rounds 35 and 38). Option 2 ensures `core/batch.go`, `session/batch.go`, `tun.pumpOutboundBatch`, and Kotlin `outboundPump` remain completely untouched.
"""


def build_turn2_packet() -> str:
    parts = [
        "# ROUND 43 TURN 2: CROSS-EXAMINATION AND CONVERGENCE PACKET\n",
        ARBITER_FINDINGS,
        "\n---",
        "\n## PEER PODIUM SUBMISSIONS (TURN 1 FULL TEXTS)\n",
    ]
    for seat in r43.SEAT_KEYS:
        fname = f"{seat.replace('claude-opus5', 'opus5')}_turn1.md"
        p = r43.TURN1_DIR / fname
        if p.exists():
            parts.append(f"### === TURN 1 SUBMISSION: {seat} ===\n\n{p.read_text(encoding='utf-8')}\n\n")

    mandate = """
---

## TURN 2 MANDATE FOR ALL THREE PODIUMS

1. Steelman the opposing podiums: identify the strongest points raised by peer podiums (specifically Opus 5's mathematical proof that sendmmsg widening retires 0.27 us/packet rather than 15.17 us/packet, Sol Pro's precise descriptor lifecycle requirements, and Gemini's L1 cache and sendMu lock analysis).
2. State whether peer reasoning and Arbiter ground-truth clarifications change your position.
3. Cast your final convergence vote on each item (OI-1, OI-2, OI-3, OI-4):
   - Explicitly vote AGREE or DISAGREE: <one concrete falsifiable technical reason>.
4. Provide the final ratified surgical code diffs for immediate application upon unanimity.
5. Rules: Strictly zero em dashes (U+2014) or en dashes (U+2013) as connectors. Strictly zero AI cliches. Restrict bold styling to top-level list keys only.
"""
    parts.append(mandate)
    return r43.clean_text("\n".join(parts))


def stage2():
    print("=== ROUND 43 TURN 2 DISPATCH ===", flush=True)
    packet = build_turn2_packet()
    packet_file = TURN2_DIR / "packet.txt"
    packet_file.write_text(packet, encoding="utf-8")
    packet_sha = hashlib.sha256(packet.encode("utf-8")).hexdigest()
    print(f"Turn 2 packet written: {len(packet)} bytes, sha256: {packet_sha}", flush=True)

    cache = load_cache()
    tasks = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        for seat in r43.SEAT_KEYS:
            key = f"r43_turn2_{seat}"
            if cache.get(key):
                print(f"[{seat}] using cached turn 2 response", flush=True)
                continue
            if seat == "agy":
                print(f"[{seat}] dispatching Gemini 3.8 Flash High (Turn 2)...", flush=True)
                tasks[key] = (seat, ex.submit(r43.query_agy, packet, "turn2"))
            elif seat == "claude-opus5":
                print(f"[{seat}] dispatching Claude Opus 5 (Turn 2 high effort)...", flush=True)
                tasks[key] = (seat, ex.submit(r43.query_claude, packet, "turn2"))
            else:
                print(f"[{seat}] dispatching GPT-5.6 Sol Pro (Turn 2 high effort flex)...", flush=True)
                tasks[key] = (seat, ex.submit(r43.query_openrouter, packet, r43.SYSTEM_SEATS[seat]))

        for key, (seat, fut) in tasks.items():
            print(f"Waiting for [{seat}] (Turn 2)...", flush=True)
            result = fut.result()
            update_cache(key, result)
            seat_file_name = f"{seat.replace('claude-opus5', 'opus5')}_turn2.md"
            (TURN2_DIR / seat_file_name).write_text(f"# Turn 2 Verdict: {seat}\n\n{result}\n", encoding="utf-8")
            (DOCS_EVIDENCE / f"debate_round43_stage2_{seat.replace('claude-opus5', 'opus5')}.md").write_text(
                f"# Turn 2 Verdict: {seat}\n\n{result}\n", encoding="utf-8"
            )
            print(f"-> [{seat}] Turn 2 completed: {len(result)} bytes", flush=True)

    print("=== ROUND 43 TURN 2 DISPATCH COMPLETE ===", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Round 43 Turn 2 Convergence Runner")
    parser.add_argument("--turn2", action="store_true", default=True, help="Run Turn 2 dispatch")
    args = parser.parse_args()
    if args.turn2:
        stage2()


if __name__ == "__main__":
    main()
