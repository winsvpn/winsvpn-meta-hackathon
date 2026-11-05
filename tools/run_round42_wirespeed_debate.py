#!/usr/bin/env python3
"""Round 42: Android Winn v3 Uplink Wire-Speed Optimization (>1,000 Mbps).

Dispatches the Round 42 docket to the three standing podiums:
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
import ipaddress
import json
import os
import pathlib
import re
import socket
import ssl
import subprocess
import threading
import time
import urllib.parse
import urllib.request

REPO_ROOT = pathlib.Path("/Users/owner/xprize/winsvpnv3").resolve()
DOCS_EVIDENCE = REPO_ROOT / "docs" / "evidence"
DOCS_EVIDENCE.mkdir(parents=True, exist_ok=True)
ROUND42_DIR = REPO_ROOT / ".agent" / "debates" / "round42-uplink-wirespeed"
TURN1_DIR = ROUND42_DIR / "turn1-opening"
TURN1_DIR.mkdir(parents=True, exist_ok=True)
RAW_OUTPUT = DOCS_EVIDENCE / "debate_round42_raw.json"

SEAT_AGY_CWD = pathlib.Path("/tmp/r42_seat_agy")
SEAT_CLAUDE_CWD = pathlib.Path("/tmp/r42_seat_claude")

OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
EGRESS_HOST_ALLOWLIST = {"openrouter.ai"}

CACHE_LOCK = threading.Lock()
RECEIPT_LOCK = threading.Lock()


def get_openrouter_key() -> str:
    env_key = os.environ.get("OPENROUTER_API_KEY")
    if env_key:
        return env_key.strip()
    auth_file = pathlib.Path.home() / ".local" / "share" / "opencode" / "auth.json"
    if auth_file.exists():
        try:
            data = json.loads(auth_file.read_text(encoding="utf-8"))
            key = data.get("openrouter", {}).get("key")
            if key:
                return key.strip()
        except Exception:
            pass
    raise RuntimeError("OpenRouter API key not found")


def clean_text(text: str) -> str:
    return text.replace("\u2014", ": ").replace("\u2013", "-")


def validate_egress_url(endpoint: str):
    parsed = urllib.parse.urlparse(endpoint)
    if parsed.scheme != "https" or parsed.hostname not in EGRESS_HOST_ALLOWLIST:
        raise RuntimeError(f"egress endpoint failed allowlist: {endpoint}")
    addr_infos = socket.getaddrinfo(parsed.hostname, 443, proto=socket.IPPROTO_TCP)
    for info in addr_infos:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise RuntimeError(f"egress host resolves to forbidden address class: {ip}")


def build_verified_tls_context():
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        system_bundle = pathlib.Path("/etc/ssl/cert.pem")
        if system_bundle.exists():
            return ssl.create_default_context(cafile=str(system_bundle))
        return ssl.create_default_context()


def write_receipt(seat: str, stage: str, packet: str, output: str, status: str):
    rec = {
        "ts_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "seat": seat,
        "stage": stage,
        "packet_sha256": hashlib.sha256(packet.encode("utf-8")).hexdigest(),
        "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        "output_bytes": len(output.encode("utf-8")),
        "status": status,
    }
    with RECEIPT_LOCK:
        with open(ROUND42_DIR / "receipts.raw.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")


def query_openrouter(
    prompt: str,
    system_role: str,
    max_tokens: int = 16000,
    model: str = "openai/gpt-5.6-sol-pro",
    reasoning_effort: str = "high",
) -> str:
    validate_egress_url(OPENROUTER_ENDPOINT)
    key = get_openrouter_key()
    tls_ctx = build_verified_tls_context()
    for attempt in range(8):
        payload = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system_role},
                {"role": "user", "content": prompt},
            ],
            "provider": {"order": ["OpenAI"], "allow_fallbacks": True},
            "reasoning": {"effort": reasoning_effort},
            "service_tier": "flex",
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            OPENROUTER_ENDPOINT,
            data=data,
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://winsvpn.org",
                "X-Title": "Winthos Debate Round 42 Wirespeed Optimization",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=600, context=tls_ctx) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                if "error" in res_data:
                    print(f"[solpro] upstream error (attempt {attempt+1}): {res_data['error'].get('message')}", flush=True)
                    time.sleep(min(45, 8 * (attempt + 1)))
                    continue
                choice = res_data["choices"][0]["message"]
                content = (choice.get("content") or choice.get("reasoning") or "").strip()
                if content:
                    write_receipt("solpro", "turn1", prompt, content, "ok")
                    return clean_text(content)
        except Exception as e:
            print(f"[solpro] attempt {attempt+1} failed: {e}", flush=True)
            time.sleep(min(45, 8 * (attempt + 1)))
    write_receipt("solpro", "turn1", prompt, "", "fail")
    raise RuntimeError("solpro query failed after retries")


def query_agy(prompt: str, stage: str = "turn1") -> str:
    SEAT_AGY_CWD.mkdir(parents=True, exist_ok=True)
    stdin_text = (
        "The complete Round 42 debate packet follows after this line. Read all of it, then "
        "complete the mandate it contains. Reply with your verdict and exact diffs only.\n\n"
        + prompt
    )
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
        out_bytes, err_bytes = proc.communicate(stdin_text.encode("utf-8"), timeout=1500)
    except subprocess.TimeoutExpired:
        write_receipt("agy", stage, prompt, "", "timeout")
        raise RuntimeError("agy timed out")
    out = out_bytes.decode("utf-8", errors="replace").strip()
    err = err_bytes.decode("utf-8", errors="replace")
    if proc.returncode != 0 or not out:
        write_receipt("agy", stage, prompt, err[:2000], f"fail rc={proc.returncode}")
        raise RuntimeError(f"agy failed rc={proc.returncode}: {err[:400]}")
    write_receipt("agy", stage, prompt, out, "ok")
    return clean_text(out)


def query_claude(prompt: str, stage: str = "turn1") -> str:
    SEAT_CLAUDE_CWD.mkdir(parents=True, exist_ok=True)
    stdin_text = (
        "The complete Round 42 debate packet follows after this line. Read all of it, then "
        "complete the mandate it contains. Do not use any tools. Reply with your "
        "verdict, first-principles arithmetic, and exact diffs only.\n\n" + prompt
    )
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
        out_bytes, err_bytes = proc.communicate(stdin_text.encode("utf-8"), timeout=1500)
    except subprocess.TimeoutExpired:
        write_receipt("claude-opus5", stage, prompt, "", "timeout")
        raise RuntimeError("claude timed out")
    out = out_bytes.decode("utf-8", errors="replace").strip()
    err = err_bytes.decode("utf-8", errors="replace")
    if proc.returncode != 0 or not out:
        write_receipt("claude-opus5", stage, prompt, err[:2000], f"fail rc={proc.returncode}")
        raise RuntimeError(f"claude failed rc={proc.returncode}: {err[:400]}")
    write_receipt("claude-opus5", stage, prompt, out, "ok")
    return clean_text(out)


SYSTEM_SEATS = {
    "agy": (
        "You are Podium 1 (Gemini 3.8 Flash High) in the Iterative Convergence Debate Protocol (ICDP). "
        "You are evaluating the Android Winn Protocol v3 Uplink Wire-Speed Optimization docket. "
        "Examine all Open Items (OI-1 through OI-4) independently. Provide concrete architectural reasoning, "
        "first-principles arithmetic, exact surgical code diffs, and an explicit vote per item (AGREE or "
        "DISAGREE: <one concrete falsifiable technical reason>). "
        "Zero em dashes or en dashes as connectors. Ban AI cliches. Restrict bold styling to top-level list keys only."
    ),
    "claude-opus5": (
        "You are Podium 2 (Claude Opus 5) in the Iterative Convergence Debate Protocol (ICDP). "
        "You are evaluating the Android Winn Protocol v3 Uplink Wire-Speed Optimization docket. "
        "Examine all Open Items (OI-1 through OI-4) independently. Provide concrete architectural reasoning, "
        "first-principles arithmetic, exact surgical code diffs, and an explicit vote per item (AGREE or "
        "DISAGREE: <one concrete falsifiable technical reason>). "
        "Zero em dashes or en dashes as connectors. Ban AI cliches. Restrict bold styling to top-level list keys only."
    ),
    "solpro": (
        "You are Podium 3 (GPT-5.6 Sol Pro) in the Iterative Convergence Debate Protocol (ICDP). "
        "You are evaluating the Android Winn Protocol v3 Uplink Wire-Speed Optimization docket. "
        "Examine all Open Items (OI-1 through OI-4) independently. Provide concrete architectural reasoning, "
        "first-principles arithmetic, exact surgical code diffs, and an explicit vote per item (AGREE or "
        "DISAGREE: <one concrete falsifiable technical reason>). "
        "Zero em dashes or en dashes as connectors. Ban AI cliches. Restrict bold styling to top-level list keys only."
    ),
}

SEAT_KEYS = ["agy", "claude-opus5", "solpro"]


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


DOCKET_PACKET = """# MULTI-MODEL DEBATE ROUND 42: ANDROID WINN V3 UPLINK WIRE-SPEED OPTIMIZATION (>1,000 MBPS)

## 1. CONTEXT, EMPIRICAL EVIDENCE & OBSERVED STATE

Live physical testing of Winn Protocol v3 on a retail Samsung Galaxy S26 Ultra (SM-S948U1, Snapdragon 8 Elite: 2x Oryon prime cores at 4.74 GHz, 6x Oryon performance cores at 3.63 GHz, Wi-Fi 7 MLO) against the Canada production gateway (<NODE_CANADA_IP>:9111, UDP RTT ~65 ms) was conducted across successive iterations.

### 1.1 Speedtest Run 14 Empirical Results
* Downlink throughput: 650 Mbps reported, live flowing throughput peaked at 848.1 Mbps.
* Uplink throughput: 415.5 Mbps reported (415,498,240 bytes over 8,000 ms across 32 concurrent HTTP streams over the inner raw socket at 10.10.0.1:8455, all HTTP 200).
* Engine telemetry: Zero dropped packets (tx_dropped_sink=0, tx_dropped_closed=3 initial bootstrap only), zero socket errors.
* Progression: Uplink rose from 255 Mbps in Run 13 to 415.5 Mbps in Run 14 after applying:
  1. Removal of heap scratch copy in WinnV3AndroidTun.kt (copying direct from staging ByteBuffer into ring slab).
  2. Decoupling producer reservation in runBurstReaderBulk outside synchronized(state) with queueEpoch publish protection.
  3. Sizing LocalSocket send/receive buffers to 1 MiB.
  4. Sizing outer socket UDP buffers to 16 MiB.
* Remaining Gap: Uplink is at 415.5 Mbps, below the target of symmetrical wire speed (>1,000 Mbps).

### 1.2 System & Network Measurements
* S26 Ultra Kernel Sysctls (verified live via adb):
  - net.core.wmem_max = 8388608 (8 MiB)
  - net.core.rmem_max = 16777216 (16 MiB)
  - net.core.wmem_default = 229376 (224 KiB)
  - net.core.rmem_default = 229376 (224 KiB)
  - net.ipv4.tcp_wmem = 2097152 / 4194304 / 8388608 (2 MiB min, 4 MiB default, 8 MiB max)
  - net.ipv4.tcp_rmem = 2097152 / 4194304 / 16777216 (2 MiB min, 4 MiB default, 16 MiB max)
* Canada Gateway Sysctls (verified live via ssh):
  - net.core.wmem_max = 134217728 (128 MiB)
  - net.core.rmem_max = 134217728 (128 MiB)
  - net.ipv4.tcp_wmem = 4096 / 65536 / 67108864 (64 MiB max)
  - net.ipv4.tcp_rmem = 4096 / 87380 / 67108864 (64 MiB max)
* Network Path Verification:
  - 32 concurrent streams with 4 MiB default client TCP window provide 128 MiB aggregate send window, easily saturating 1 Gbps at 65 ms RTT.
  - Zero dropped packets at the engine sink confirms the bottleneck is datapath throughput and batch scheduling, not network congestion or packet loss.

---

## 2. DETAILED PIPELINE TRACE & BOTTLENECK ANALYSIS

### 2.1 Consumer Monitor Contention in WinnV3AndroidTun.kt
In WinnV3AndroidTun.kt, while runBurstReaderBulk was decoupled, readOutgoingBatch still holds synchronized(state) during its entire batch framing and memory copy loop:

```kotlin
override fun readOutgoingBatch(batch: WinnV3PacketBatch): Int = synchronized(state) {
    batch.clear()
    if (!awaitPacket()) return@synchronized -1
    batch.generation = readerGeneration.get()
    while (count > 0 && batch.canAppend(lengths[head])) {
        // Full framing and payload copy executed under synchronized(state)
        batch.append(WinnFraming.OP_INBOUND, slab, head * packetCapacity, lengths[head])
        head = (head + 1) % queueDepth
        count--
    }
    if (batch.count == 0) throw IOException("Winn tun batch destination too small")
    batch.count
}
```

When a batch of 256 packets (~350 KiB) is framed, batch.append performs 5 binary put calls plus System.arraycopy for each packet. During this copy duration, runBurstReaderBulk is blocked on synchronized(state) when attempting to reserve slots or publish newly drained packets.

### 2.2 Batch Granularity Across the LocalSocket Stream Boundary
* WinnV3PacketBatch default configuration:
  `val packetCapacity: Int = 256`, `byteCapacity: Int = 512 * 1024` (512 KiB).
* WinnV3AndroidTun.kt burst configuration:
  `const val MAX_BURST_PACKETS = 512`.
* Go frame server (winn3_frame.go):
  `inboundBatch := make([][]byte, 0, 256)`
  Drains up to 256 packets before calling flushInboundBatch.
* tun.go:
  `pumpOutboundBatch` uses `const batchSize = 256`.
At 1,000 Mbps (91,041 packets/sec with 1373 MTU), 256-packet batches require ~356 AF_UNIX write/read iterations per second. Expanding to 512 packets reduces this to ~178 iterations per second, halving kernel context switches and channel synchronization events.

### 2.3 Go Frame Inbound Memory Copies & Channel Dispatch
Inside cmd/winn-datapath/winn3_frame.go and winn3_frame_device.go:
1. `reader.Read()` reads payload into internal `r.buffer`.
2. `allocPacket(pay)` allocates a 2048-byte slab from `packetPool` and copies payload via `copy(cp, src)`.
3. `offerBatch` pushes 2048-byte pointers into `toEngine chan []byte` (depth 65536) one packet at a time.
4. In `winn3_frame_device.go`: `ReadBatch` reads from `toEngine` channel one packet at a time, executes `copy(bufs[idx], pkt)`, and recycles `pkt` back to `packetPool`.
5. In `session/driver.go`: `EnqueueBatch` executes `copy(p, inner)` into `d.data`.
Total in Go engine alone: three memory copies and two channel dispatch operations per packet.

---

## 3. OPERATIVE ITEMS FOR DEBATE (OI-1 THROUGH OI-4)

### OI-1: Two-Phase Consumer Reservation & Decoupling in readOutgoingBatch
* Proposal: Decouple readOutgoingBatch in WinnV3AndroidTun.kt using a two-phase reservation protocol:
  - Phase 1 (under synchronized(state)): Check awaitPacket(). Determine how many packets fit in batch. Record claimHead = head and claimCount. Capture epoch = queueEpoch. Do NOT advance head or decrement count yet (ensuring producer cannot overwrite these slots).
  - Phase 2 (outside synchronized(state)): Iterate 0 until claimCount, calling batch.append from slab at (claimHead + i) % queueDepth.
  - Phase 3 (under synchronized(state)): If queueEpoch == epoch && readerGeneration.get() == generation && !closed.get(), advance head = (claimHead + claimCount) % queueDepth and decrement count -= claimCount. If waiters > 0, notifyAll.
* Mandate: Analyze thread safety, memory visibility guarantees under JMM, race conditions against rebind/close/discard, and impact on reader thread stalls.

### OI-2: Expanding Batch Sizing Across LocalSocket Stream Boundary
* Proposal: Expand batch capacity from 256 packets (512 KiB) to 512 packets (1024 KiB, 1 MiB):
  1. In WinnV3PacketBatch.kt: set default packetCapacity = 512, byteCapacity = 1024 * 1024 (1 MiB), updating class preconditions.
  2. In WinnV3Bridge.kt: use 512-capacity batch.
  3. In winn3_frame.go: expand inboundBatch slice capacity to 512.
  4. In winn3/tun/tun.go: expand pumpOutboundBatch batchSize to 512.
* Mandate: Evaluate memory footprint, buffer alignment with 1 MiB LocalSocket buffer, reduction in write/read syscalls, and potential latency implications.

### OI-3: Go Inbound Datapath Copy Reduction & Channel Optimization
* Proposal: Evaluate opportunities in winn3_frame.go and winn3_frame_device.go to reduce intermediate memory copies and channel contention.
  - Option A: Retain per-packet channel push but evaluate whether packetPool copy in allocPacket can be eliminated or batched.
  - Option B: Batch channel dispatch (e.g. passing [][]byte batch slices through the channel instead of individual packet sends/receives).
* Mandate: Provide first-principles analysis of Go channel synchronization cost vs memory copy cost, test compatibility, and risk of data races.

### OI-4: Architectural & Invariant Preservation
* Mandatory Constraints:
  - Downlink datapath, buffer allocations, and measurement mathematics remain 100% frozen (Treaty Rounds 35 & 38).
  - All 601 Android unit tests must pass.
  - All Go tests across winn_protocol_experimental must pass.
  - Wire framing between Kotlin and Go must remain bit-identical.
  - Zero forbidden imports or API-level gate violations.
* Mandate: Confirm compliance with all constraints and define concrete verification commands.

---

## 4. MANDATE FOR ALL THREE PODIUMS

Every podium must independently analyze all four open items (OI-1 through OI-4) and provide:
1. First-principles arithmetic and architectural analysis.
2. Exact recommended surgical code diffs.
3. Explicit vote per item: AGREE or DISAGREE: <one concrete falsifiable technical reason>.
4. Projected throughput impact on physical Samsung Galaxy S26 Ultra against Canada gateway.
"""


def stage1():
    print("=== ROUND 42 TURN 1 DISPATCH ===", flush=True)
    packet = clean_text(DOCKET_PACKET)
    packet_file = TURN1_DIR / "packet.txt"
    packet_file.write_text(packet, encoding="utf-8")
    packet_sha = hashlib.sha256(packet.encode("utf-8")).hexdigest()
    print(f"Docket packet written: {len(packet)} bytes, sha256: {packet_sha}", flush=True)

    cache = load_cache()
    tasks = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        for seat in SEAT_KEYS:
            key = f"r42_turn1_{seat}"
            if cache.get(key):
                print(f"[{seat}] using cached turn 1 response", flush=True)
                continue
            if seat == "agy":
                print(f"[{seat}] dispatching Gemini 3.8 Flash High...", flush=True)
                tasks[key] = (seat, ex.submit(query_agy, packet, "turn1"))
            elif seat == "claude-opus5":
                print(f"[{seat}] dispatching Claude Opus 5 (high effort)...", flush=True)
                tasks[key] = (seat, ex.submit(query_claude, packet, "turn1"))
            else:
                print(f"[{seat}] dispatching GPT-5.6 Sol Pro (high effort flex)...", flush=True)
                tasks[key] = (seat, ex.submit(query_openrouter, packet, SYSTEM_SEATS[seat]))

        for key, (seat, fut) in tasks.items():
            print(f"Waiting for [{seat}]...", flush=True)
            result = fut.result()
            update_cache(key, result)
            seat_file_name = f"{seat.replace('claude-opus5', 'opus5')}_turn1.md"
            (TURN1_DIR / seat_file_name).write_text(f"# Turn 1 Verdict: {seat}\n\n{result}\n", encoding="utf-8")
            (DOCS_EVIDENCE / f"debate_round42_stage1_{seat.replace('claude-opus5', 'opus5')}.md").write_text(
                f"# Turn 1 Verdict: {seat}\n\n{result}\n", encoding="utf-8"
            )
            print(f"-> [{seat}] completed: {len(result)} bytes", flush=True)

    print("=== ROUND 42 TURN 1 DISPATCH COMPLETE ===", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Round 42 Uplink Wire-Speed Debate Runner")
    parser.add_argument("--turn1", action="store_true", default=True, help="Run Turn 1 dispatch")
    args = parser.parse_args()
    if args.turn1:
        stage1()


if __name__ == "__main__":
    main()
