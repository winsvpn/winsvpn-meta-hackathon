#!/usr/bin/env python3
"""Round 44 Turn 2: Cross-Examination and Convergence Debate.

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
import run_round44_debate as r44

REPO_ROOT = r44.REPO_ROOT
DOCS_EVIDENCE = r44.DOCS_EVIDENCE
ROUND44_DIR = r44.ROUND44_DIR
TURN2_DIR = ROUND44_DIR / "turn2-cross"
TURN2_DIR.mkdir(parents=True, exist_ok=True)
RAW_OUTPUT = DOCS_EVIDENCE / "debate_round44_turn2_raw.json"

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


ARBITER_FINDINGS = """# ARBITER GROUND-TRUTH VERIFICATIONS & CLARIFICATIONS FOR ROUND 44 TURN 2

1. **Unanimous Consensus on OI-1 (Lock-Batched Ring Buffer)**:
   - All three podiums (Gemini 3.8 Flash High, Claude Opus 5, and GPT-5.6 Sol Pro) independently and unanimously voted AGREE on replacing `toEngine chan []byte` with a dedicated circular ring buffer (`toEngineRing`).
   - The council proves from first principles that batching 512-packet pushes and 256-packet pops reduces synchronization frequency by 341.3x (from 182,083 down to 533.4 lock acquisitions/sec at wire speed), eliminating cross-core cache-line ping-ponging on `hchan.lock`.
   - Ring capacity remains `winn3FrameQueueDepth = 65536`.
   - Condition variable mechanics: `r.cond.Signal()` on push, `r.cond.Broadcast()` on `Close()`.
   - Closing semantics: `Close()` sets `closed = true` and broadcasts; `popBatch` continues draining any buffered packets until `count == 0`, returning `errWinn3DeviceClosed` only when empty and closed. Unconsumed packets arriving after closure are recycled to `packetPool`.

2. **Consensus Resolution on OI-2 (Preserving Zero-Allocation packetPool in Stage B)**:
   - Both Opus 5 and Sol Pro voted DISAGREE on altering intermediate memory copying in Stage B, providing mathematical proof:
     * Three memory copies of 1,373 bytes on Snapdragon 8 Elite Oryon cores take ~0.16 to 0.47 µs per packet, consuming <0.7% of LPDDR5X DRAM bandwidth.
     * Bypassing Copy 2 would break the frozen `tun.BatchDevice` contract (`ReadBatch(bufs [][]byte) ([]int, error)`).
     * Direct slice lending without a full ownership transfer and release protocol risks dangerous buffer aliasing and race conditions.
   - Gemini, Opus 5, and Sol Pro converge on the recommendation: PRESERVE the existing `packetPool` allocation and copying in Stage B. Zero changes to `tun.BatchDevice` or `session/driver.go`.

3. **Arbiter Factual Resolution on OI-3 (Gateway 4-Tuple Hashing Already Shipped)**:
   - Opus 5 hypothesized that if the gateway hashed only source IP, all 32 speedtest streams would collapse onto 1 of the 4 TUN queues, and proposed 4-tuple hashing as the necessary remedy.
   - The Arbiter confirms live codebase ground truth from `cmd/winn3-gateway/forward_linux.go` lines 272-286:
     ```go
     if src, _, ok := ipv4SourceDestination(pkt); ok && src.Is4() {
         a := src.As4()
         idx = int(a[3]) % len(s.files)
         if len(pkt) >= 28 && (pkt[9] == 6 || pkt[9] == 17) {
             ihl := int(pkt[0]&0x0f) * 4
             if len(pkt) >= ihl+4 {
                 srcPort := int(pkt[ihl])<<8 | int(pkt[ihl+1])
                 dstPort := int(pkt[ihl+2])<<8 | int(pkt[ihl+3])
                 h := int(a[3]) ^ (srcPort >> 2) ^ dstPort
                 if h < 0 { h = -h }
                 idx = h % len(s.files)
             }
         }
     }
     ```
     The Canada production gateway ALREADY hashes the inner TCP 4-tuple (`srcPort >> 2 ^ dstPort`), distributing the 32 streams evenly across all 4 TUN descriptors!
   - All three podiums agree that no gateway code modifications are required for Stage B.

4. **Unanimous Confirmation of OI-4 (Downlink Freeze Invariant)**:
   - Downlink datapath (`toHost chan []byte`, `take()`, `tryTake()`, `WritePacket()`, `pumpOutboundBatch`, `outboundPump`, and all measurement parameters) remains 100% frozen.
   - Per Opus 5 and Sol Pro's factual correction, docket references to downlink performance are strictly bound to measured reality (673 Mbps sustained in Run 16).
"""


def build_turn2_packet() -> str:
    parts = [
        "# ROUND 44 TURN 2: CROSS-EXAMINATION AND CONVERGENCE PACKET\n",
        ARBITER_FINDINGS,
        "\n---",
        "\n## PEER PODIUM SUBMISSIONS (TURN 1 FULL TEXTS)\n",
    ]
    for seat in r44.SEAT_KEYS:
        fname = f"{seat.replace('claude-opus5', 'opus5')}_turn1.md"
        p = r44.TURN1_DIR / fname
        if p.exists():
            parts.append(f"### === TURN 1 SUBMISSION: {seat} ===\n\n{p.read_text(encoding='utf-8')}\n\n")

    mandate = """
---

## TURN 2 MANDATE FOR ALL THREE PODIUMS

1. Steelman the opposing podiums: identify the strongest technical arguments raised by peer podiums regarding ring buffer concurrency, memory ownership, condition variable signaling, and CPU cache locality.
2. State whether peer reasoning and Arbiter ground-truth verifications change your position.
3. Cast your final convergence vote on each item (OI-1, OI-2, OI-3, OI-4):
   - Explicitly vote AGREE or DISAGREE: <one concrete falsifiable technical reason>.
4. Provide the final ratified surgical code diffs for immediate application upon unanimity.
5. Rules: Strictly zero em dashes (U+2014) or en dashes (U+2013) as connectors. Strictly zero AI cliches. Restrict bold styling to top-level list keys only.
"""
    parts.append(mandate)
    return r44.clean_text("\n".join(parts))


def stage2():
    print("=== ROUND 44 TURN 2 DISPATCH ===", flush=True)
    packet = build_turn2_packet()
    packet_file = TURN2_DIR / "packet.txt"
    packet_file.write_text(packet, encoding="utf-8")
    packet_sha = hashlib.sha256(packet.encode("utf-8")).hexdigest()
    print(f"Turn 2 packet written: {len(packet)} bytes, sha256: {packet_sha}", flush=True)

    cache = load_cache()
    tasks = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        for seat in r44.SEAT_KEYS:
            key = f"r44_turn2_{seat}"
            if cache.get(key):
                print(f"[{seat}] using cached turn 2 response", flush=True)
                continue
            if seat == "agy":
                print(f"[{seat}] dispatching Gemini 3.8 Flash High (Turn 2)...", flush=True)
                tasks[key] = (seat, ex.submit(r44.query_agy, packet, "turn2"))
            elif seat == "claude-opus5":
                print(f"[{seat}] dispatching Claude Opus 5 (Turn 2 high effort)...", flush=True)
                tasks[key] = (seat, ex.submit(r44.query_claude, packet, "turn2"))
            else:
                print(f"[{seat}] dispatching GPT-5.6 Sol Pro (Turn 2 high effort flex)...", flush=True)
                tasks[key] = (seat, ex.submit(r44.query_openrouter, packet, r44.SYSTEM_SEATS[seat]))

        for key, (seat, fut) in tasks.items():
            print(f"Waiting for [{seat}] (Turn 2)...", flush=True)
            result = fut.result()
            update_cache(key, result)
            seat_file_name = f"{seat.replace('claude-opus5', 'opus5')}_turn2.md"
            (TURN2_DIR / seat_file_name).write_text(f"# Turn 2 Verdict: {seat}\n\n{result}\n", encoding="utf-8")
            (DOCS_EVIDENCE / f"debate_round44_stage2_{seat.replace('claude-opus5', 'opus5')}.md").write_text(
                f"# Turn 2 Verdict: {seat}\n\n{result}\n", encoding="utf-8"
            )
            print(f"-> [{seat}] Turn 2 completed: {len(result)} bytes", flush=True)

    print("=== ROUND 44 TURN 2 DISPATCH COMPLETE ===", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Round 44 Turn 2 Convergence Runner")
    parser.add_argument("--turn2", action="store_true", default=True, help="Run Turn 2 dispatch")
    args = parser.parse_args()
    if args.turn2:
        stage2()


if __name__ == "__main__":
    main()
