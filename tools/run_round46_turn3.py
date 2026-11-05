#!/usr/bin/env python3
"""Round 46 Turn 3: Convergence Vote on Amended Text.

Dispatches Turn 3 vote packet with amended OI-4 text incorporating Sol Pro and Opus 5
arithmetic on reverse-path TCP ACK delay bounds.
Seats: Gemini 3.8 Flash High (agy), Claude Opus 5 (claude-opus5), GPT-5.6 Sol Pro (solpro).
Strictly zero em/en dashes as connectors. Strictly zero AI cliches. Bold top-level list keys only.
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

REPO_ROOT = pathlib.Path("/Users/owner/xprize/winsvpnv3").resolve()
DOCS_EVIDENCE = REPO_ROOT / "docs" / "evidence"
ROUND46_DIR = REPO_ROOT / ".agent" / "debates" / "round46-client-ingress-bdp"
TURN3_DIR = ROUND46_DIR / "turn3-convergence"
TURN3_DIR.mkdir(parents=True, exist_ok=True)
RAW_OUTPUT = DOCS_EVIDENCE / "debate_round46_turn3_raw.json"

SEAT_AGY_CWD = pathlib.Path("/tmp/r46_seat_agy_turn3")
SEAT_CLAUDE_CWD = pathlib.Path("/tmp/r46_seat_claude_turn3")

import sys
sys.path.insert(0, str(REPO_ROOT / "tools"))
from run_round46_turn2 import (
    clean_text,
    get_openrouter_key,
    query_openrouter,
    write_receipt,
    SYSTEM_SEATS,
    SEAT_KEYS,
)

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

def build_turn3_packet() -> str:
    return """# MULTI-MODEL DEBATE ROUND 46 TURN 3: FINAL CONVERGENCE VOTE

## ARBITER AMENDMENT TO OI-4 BASED ON TURN 2 CROSS-EXAMINATION
In Turn 2, Podium 3 (GPT-5.6 Sol Pro) correctly noted that while all downlink payload code components remain 100% frozen, claiming absolute behavioral immutability for the downlink path overlooks that reverse-path TCP ACKs for downlink flows traverse `toEngineRing`. Sol Pro demonstrated that a 1+15 ACK burst triggers an immediate wake under `lowWater = 16` rather than waiting for 32 packets, altering reverse ACK residence time.
Podium 2 (Claude Opus 5) proved from first principles that at sustained 675 Mbps downlink (30,726.5 ACKs/sec, 32.55 µs interval), accumulating 16 ACKs takes 520.8 µs, which exceeds `maxPark = 250 µs`. Thus, the 250 µs park deadline binds identically before and after, bounding reverse ACK delay to 0.385% of RTT (65 ms) and downlink steady-state throughput impact to 0.383%.
The Arbiter amends the title and specification of OI-4 to explicitly reflect this code-freeze and reverse-ACK latency bound.

---

## ENUMERATED OPEN ITEMS FOR FINAL TURN 3 CONVERGENCE VOTE

### OI-1: Handset TCP Sockets & Ingest Server BDP Window Scaling
* Set `socket.sendBufferSize = 1048576` (1 MiB) on each of the 32 upload worker sockets in `MainActivity.kt:1530` before `socket.connect(...)`.
* Include readback logging on worker 0: `android.util.Log.i("WinnUpload", "sndbuf_req=1048576 sndbuf_eff=${socket.sendBufferSize}")`.
* Preserve Linux TCP autotuning on the Canada gateway ingest listener in `speedtest_ingest.go` without hardcoding `SO_RCVBUF`.
* Confirm BDP arithmetic: 1,000 Mbps at 65 ms RTT requires 8.125 MB total in-flight; 32 streams require 253.9 KB each; 1 MiB send buffer provides 4.13x headroom.

### OI-2: Ingress Pipeline Architecture & IPC Preservation
* Retain `LocalSocket` (`AF_UNIX`) stream transport in Stage D, preserving the existing Kotlin `outboundPump` and downlink `tun0` write path in strict compliance with the Downlink Code Freeze Invariant.
* Defer SCM_RIGHTS TUN descriptor handover to Stage E after formal promotion barrier and atomic descriptor hot-swap protocols are designed.
* In `cmd/winn-datapath/winn3_frame.go`, flush `inboundBatch` immediately whenever `bufInput == nil || bufInput.Buffered() < duplex.HeaderSize` to avoid holding partial batches before potentially blocking reads.

### OI-3: Transmit Drain Gating (txDrainGate) Parameter Calibration & Instrumentation
* Recalibrate `lowWater = 16` (lowered from 32) in `cmd/winn-datapath/winn3_to_engine_ring.go`.
* Retain `maxPark = 250 * time.Microsecond`.
* Retain signaling condition: `if oldCount == 0 || (oldCount < r.lowWater && newCount >= r.lowWater) { r.signalNotify() }`.
* Add atomic ring telemetry counters to `winn3ToEngineRing`: `wakeThreshold`, `wakeZero`, `wakePark`, `popLenSum`, `popCalls` to measure true batch occupancy and wake attribution directly at the ring boundary.

### OI-4: Downlink Datapath Code and Payload Architecture Freeze Invariant
* All Stage D modifications are strictly confined to the upload/transmit pipeline (`MainActivity.kt`, `winn3_to_engine_ring.go`, `winn3_frame.go`).
* `RecvBatch`, `outboundPump`, `toHost`, `fromEngine`, downlink crypto workers, and measurement mathematics remain 100% frozen in code and architecture in strict compliance with Treaty Rounds 35, 38, 43, 44, and 45.
* It is acknowledged that reverse-path TCP ACKs for downlink flows traverse `toEngineRing`; the 250 µs `maxPark` ceiling bounds worst-case ACK delay to 0.385% of path RTT (65 ms), and `lowWater = 16` shortens ACK residence time during burst arrivals without altering steady-state ACK latency bounds.

---

## MANDATE FOR TURN 3
Cast an explicit final convergence vote on each item (OI-1, OI-2, OI-3, OI-4):
Format:
- **OI-1**: AGREE or DISAGREE: <one concrete falsifiable reason>
- **OI-2**: AGREE or DISAGREE: <one concrete falsifiable reason>
- **OI-3**: AGREE or DISAGREE: <one concrete falsifiable reason>
- **OI-4**: AGREE or DISAGREE: <one concrete falsifiable reason>

Zero em dashes or en dashes as connectors. Ban AI cliches. Restrict bold styling to top-level list keys only.
"""

def query_agy_turn3(prompt: str) -> str:
    SEAT_AGY_CWD.mkdir(parents=True, exist_ok=True)
    stdin_text = (
        "The complete Round 46 Turn 3 convergence packet follows. Read it and output your final votes only.\n\n"
        + prompt
    )
    for attempt in range(5):
        try:
            proc = subprocess.Popen(
                [
                    "agy",
                    "--effort", "high",
                    "--disable-slash-commands",
                    "--output-format", "text",
                    "--print", "Answer the prompt provided on standard input.",
                ],
                cwd=str(SEAT_AGY_CWD),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            out_bytes, err_bytes = proc.communicate(stdin_text.encode("utf-8"), timeout=900)
            out = out_bytes.decode("utf-8", errors="replace").strip()
            err = err_bytes.decode("utf-8", errors="replace")
            if proc.returncode != 0 or not out:
                if "RESOURCE_EXHAUSTED" in err or "429" in err:
                    time.sleep(min(60, 15 * (attempt + 1)))
                    continue
                write_receipt("agy", "turn3", prompt, err[:2000], f"fail rc={proc.returncode}")
                raise RuntimeError(f"agy failed rc={proc.returncode}: {err[:400]}")
            write_receipt("agy", "turn3", prompt, out, "ok")
            return clean_text(out)
        except subprocess.TimeoutExpired:
            time.sleep(10)
    raise RuntimeError("agy turn 3 failed after retries")

def query_claude_turn3(prompt: str) -> str:
    SEAT_CLAUDE_CWD.mkdir(parents=True, exist_ok=True)
    stdin_text = (
        "The complete Round 46 Turn 3 convergence packet follows. Output your final votes only.\n\n"
        + prompt
    )
    run_cli = True
    out = ""
    try:
        proc = subprocess.Popen(
            [
                "claude",
                "-p",
                "--model", "opus",
                "--effort", "high",
                "--tools", "",
                "--output-format", "text",
            ],
            cwd=str(SEAT_CLAUDE_CWD),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        out_bytes, err_bytes = proc.communicate(stdin_text.encode("utf-8"), timeout=900)
        out = out_bytes.decode("utf-8", errors="replace").strip()
        err = err_bytes.decode("utf-8", errors="replace")
        if proc.returncode != 0 or not out or "weekly limit" in out.lower():
            run_cli = False
    except Exception:
        run_cli = False

    if not run_cli:
        print("[claude-opus5] CLI quota reached, falling back to OpenRouter anthropic/claude-opus-5...", flush=True)
        return query_openrouter(
            prompt,
            SYSTEM_SEATS["claude-opus5"],
            seat="claude-opus5",
            model="anthropic/claude-opus-5",
        )

    write_receipt("claude-opus5", "turn3", prompt, out, "ok")
    return clean_text(out)

def stage3():
    print("=== ROUND 46 TURN 3 CONVERGENCE DISPATCH ===", flush=True)
    t3_packet = build_turn3_packet()
    packet_file = TURN3_DIR / "packet.txt"
    packet_file.write_text(t3_packet, encoding="utf-8")
    packet_sha = hashlib.sha256(t3_packet.encode("utf-8")).hexdigest()
    print(f"Turn 3 packet written: {len(t3_packet)} bytes, sha256: {packet_sha}", flush=True)

    cache = load_cache()

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futures_map = {}
        for seat in SEAT_KEYS:
            key = f"r46_turn3_{seat}"
            if cache.get(key):
                print(f"[{seat}] using cached turn 3 response", flush=True)
                continue
            if seat == "agy":
                print(f"[{seat}] dispatching Gemini 3.8 Flash High (Turn 3)...", flush=True)
                fut = ex.submit(query_agy_turn3, t3_packet)
                futures_map[fut] = (key, seat)
            elif seat == "claude-opus5":
                print(f"[{seat}] dispatching Claude Opus 5 (Turn 3)...", flush=True)
                fut = ex.submit(query_claude_turn3, t3_packet)
                futures_map[fut] = (key, seat)
            else:
                print(f"[{seat}] dispatching GPT-5.6 Sol Pro (Turn 3 flex)...", flush=True)
                fut = ex.submit(query_openrouter, t3_packet, SYSTEM_SEATS[seat], seat=seat)
                futures_map[fut] = (key, seat)

        for fut in concurrent.futures.as_completed(futures_map):
            key, seat = futures_map[fut]
            try:
                result = fut.result()
                update_cache(key, result)
                seat_file_name = f"{seat.replace('claude-opus5', 'opus5')}_turn3.md"
                (TURN3_DIR / seat_file_name).write_text(f"# Turn 3 Final Vote: {seat}\n\n{result}\n", encoding="utf-8")
                (DOCS_EVIDENCE / f"debate_round46_stage3_{seat.replace('claude-opus5', 'opus5')}.md").write_text(
                    f"# Turn 3 Final Vote: {seat}\n\n{result}\n", encoding="utf-8"
                )
                print(f"-> [{seat}] completed: {len(result)} bytes", flush=True)
            except Exception as e:
                print(f"-> [{seat}] error: {e}", flush=True)
                raise

    print("=== ROUND 46 TURN 3 DISPATCH COMPLETE ===", flush=True)

def main():
    parser = argparse.ArgumentParser(description="Round 46 Turn 3 Runner")
    args = parser.parse_args()
    stage3()

if __name__ == "__main__":
    main()
