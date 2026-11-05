#!/usr/bin/env python3
"""Round 42 Turn 2: Cross-Examination and Convergence Debate.

Circulates Turn 1 positions and Arbiter ground-truth findings to all three standing podiums:
  1. Gemini 3.8 Flash High (agy CLI, --effort high)
  2. Claude Opus 5 extra-high (claude CLI, --effort high)
  3. GPT-5.6 Sol Pro extra-high (OpenRouter, openai/gpt-5.6-sol-pro, effort high)

Adheres strictly to the Iterative Convergence Debate Protocol (ICDP).
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
import run_round42_wirespeed_debate as r42

REPO_ROOT = r42.REPO_ROOT
DOCS_EVIDENCE = r42.DOCS_EVIDENCE
ROUND42_DIR = r42.ROUND42_DIR
TURN2_DIR = ROUND42_DIR / "turn2-cross"
TURN2_DIR.mkdir(parents=True, exist_ok=True)
RAW_OUTPUT = DOCS_EVIDENCE / "debate_round42_turn2_raw.json"

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

1. **OI-1 Ground Truth on queueEpoch (Resolving Sol Pro's Concern)**:
   In `WinnV3AndroidTun.kt`, inspection confirms `queueEpoch` is ONLY incremented in `rebindDevice` (line 851) and `close()` (line 894). It is NEVER modified on normal producer publishes (`runBurstReaderBulk` lines 598-605). Normal producer publishes simply update `count += reserved; enqueuedCount += reserved; state.notifyAll()`. Therefore, normal packet production does NOT cause an epoch mismatch in Phase 3.
   Furthermore, the Arbiter adopts Opus 5 and Sol Pro's essential safety requirement: in Phase 3, if `queueEpoch != epoch || readerGeneration.get() != generation || closed.get()`, the consumer must clear the batch (`batch.clear()`) and return without delivery, ensuring zero torn or duplicated frames can ever be returned.

2. **OI-2 Ground Truth on Downlink Freeze (Unanimous Treaty Alignment)**:
   All three podiums agreed that class defaults in `WinnV3PacketBatch.kt` must remain 256 packets and 512 KiB to ensure the frozen downlink path (`outboundPump`) remains 100% untouched.
   The 512-packet / 1024 KiB batch is instantiated explicitly in `WinnV3Bridge.kt` for `inboundPump` only.
   `WinnV3PacketBatch.kt` preconditions are widened to `require(packetCapacity in 1..512)` and `require(byteCapacity in ... 2 * 1024 * 1024)` to permit the 512-packet instance.
   `winn3/tun/tun.go` `pumpOutboundBatch` (`const batchSize = 256`) remains 100% UNTOUCHED to avoid core engine churn.
   `LocalSocket` buffer size is set to 2 MiB (accepted by kernel sysctl `wmem_max = 8 MiB`).
   `winn3_frame.go`: `inboundBatch` slice capacity expanded to 512.

3. **OI-3 Ground Truth on Memory Safety & Channel Optimization**:
   All three podiums unanimously rejected Option A (bypassing `allocPacket` while sharing `r.buffer`) as an unsafe data race with subsequent `reader.Read()`.
   For Option B (batch channel descriptors over `toEngine`), both Opus 5 and Sol Pro provided concrete implementations.
   Podiums are asked to decide on execution order: land the verified OI-1 and OI-2 changes first (which directly resolve the consumer lock contention and double batch size with zero Go core changes), or include Option B in this deployment.

4. **OI-4 Invariant Confirmation**:
   Downlink datapath, buffer allocations, and measurement mathematics remain 100% frozen.
   All 601 Android unit tests and Go tests must pass cleanly.
"""


def build_turn2_packet() -> str:
    parts = [
        "# ROUND 42 TURN 2: CROSS-EXAMINATION AND CONVERGENCE PACKET\n",
        ARBITER_FINDINGS,
        "\n---",
        "\n## PEER PODIUM SUBMISSIONS (TURN 1 FULL TEXTS)\n",
    ]
    for seat in r42.SEAT_KEYS:
        fname = f"{seat.replace('claude-opus5', 'opus5')}_turn1.md"
        p = r42.TURN1_DIR / fname
        if p.exists():
            parts.append(f"### === TURN 1 SUBMISSION: {seat} ===\n\n{p.read_text(encoding='utf-8')}\n\n")

    mandate = """
---

## TURN 2 MANDATE FOR ALL THREE PODIUMS

1. Steelman the opposing podiums: identify the strongest points raised by peer podiums (specifically Opus 5's finding on clearing the batch on epoch mismatch, Sol Pro's analysis of transition serialization, and Gemini's analysis of LocalSocket buffer alignment).
2. State whether peer reasoning and Arbiter ground-truth clarifications change your position.
3. Cast your final convergence vote on each item (OI-1, OI-2, OI-3, OI-4):
   - Explicitly vote AGREE or DISAGREE: <one concrete falsifiable technical reason>.
4. Provide the final ratified surgical code diffs for immediate application upon unanimity.
5. Rules: Strictly zero em dashes (U+2014) or en dashes (U+2013) as connectors. Strictly zero AI cliches. Restrict bold styling to top-level list keys only.
"""
    parts.append(mandate)
    return r42.clean_text("\n".join(parts))


def stage2():
    print("=== ROUND 42 TURN 2 DISPATCH ===", flush=True)
    packet = build_turn2_packet()
    packet_file = TURN2_DIR / "packet.txt"
    packet_file.write_text(packet, encoding="utf-8")
    packet_sha = hashlib.sha256(packet.encode("utf-8")).hexdigest()
    print(f"Turn 2 packet written: {len(packet)} bytes, sha256: {packet_sha}", flush=True)

    cache = load_cache()
    tasks = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        for seat in r42.SEAT_KEYS:
            key = f"r42_turn2_{seat}"
            if cache.get(key):
                print(f"[{seat}] using cached turn 2 response", flush=True)
                continue
            if seat == "agy":
                print(f"[{seat}] dispatching Gemini 3.8 Flash High (Turn 2)...", flush=True)
                tasks[key] = (seat, ex.submit(r42.query_agy, packet, "turn2"))
            elif seat == "claude-opus5":
                print(f"[{seat}] dispatching Claude Opus 5 (Turn 2 high effort)...", flush=True)
                tasks[key] = (seat, ex.submit(r42.query_claude, packet, "turn2"))
            else:
                print(f"[{seat}] dispatching GPT-5.6 Sol Pro (Turn 2 high effort flex)...", flush=True)
                tasks[key] = (seat, ex.submit(r42.query_openrouter, packet, r42.SYSTEM_SEATS[seat]))

        for key, (seat, fut) in tasks.items():
            print(f"Waiting for [{seat}] (Turn 2)...", flush=True)
            result = fut.result()
            update_cache(key, result)
            seat_file_name = f"{seat.replace('claude-opus5', 'opus5')}_turn2.md"
            (TURN2_DIR / seat_file_name).write_text(f"# Turn 2 Verdict: {seat}\n\n{result}\n", encoding="utf-8")
            (DOCS_EVIDENCE / f"debate_round42_stage2_{seat.replace('claude-opus5', 'opus5')}.md").write_text(
                f"# Turn 2 Verdict: {seat}\n\n{result}\n", encoding="utf-8"
            )
            print(f"-> [{seat}] Turn 2 completed: {len(result)} bytes", flush=True)

    print("=== ROUND 42 TURN 2 DISPATCH COMPLETE ===", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Round 42 Turn 2 Convergence Runner")
    parser.add_argument("--turn2", action="store_true", default=True, help="Run Turn 2 dispatch")
    args = parser.parse_args()
    if args.turn2:
        stage2()


if __name__ == "__main__":
    main()
