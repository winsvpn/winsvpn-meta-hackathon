#!/usr/bin/env python3
"""Round 43: Android Winn v3 Uplink Wire-Speed Optimization (>1,000 Mbps).

Dispatches the Round 43 docket to the three standing podiums:
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
ROUND43_DIR = REPO_ROOT / ".agent" / "debates" / "round43-wirespeed-pipeline"
TURN1_DIR = ROUND43_DIR / "turn1-opening"
TURN1_DIR.mkdir(parents=True, exist_ok=True)
RAW_OUTPUT = DOCS_EVIDENCE / "debate_round43_raw.json"

SEAT_AGY_CWD = pathlib.Path("/tmp/r43_seat_agy")
SEAT_CLAUDE_CWD = pathlib.Path("/tmp/r43_seat_claude")

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
        with open(ROUND43_DIR / "receipts.raw.jsonl", "a", encoding="utf-8") as f:
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
                "X-Title": "Winthos Debate Round 43 Wirespeed Pipeline",
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
        "The complete Round 43 debate packet follows after this line. Read all of it, then "
        "complete the mandate it contains. Reply with your verdict, first-principles arithmetic, "
        "and exact diffs only.\n\n"
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
        "The complete Round 43 debate packet follows after this line. Read all of it, then "
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


DOCKET_PACKET = """# MULTI-MODEL DEBATE ROUND 43: ANDROID WINN V3 UPLINK WIRE-SPEED SCALING (>1,000 MBPS)

## 1. CONTEXT, EMPIRICAL EVIDENCE & OBSERVED STATE

Following the Round 42 unanimous treaty ratification, the two-phase non-blocking batch claim was deployed to the physical retail Samsung Galaxy S26 Ultra (SM-S948U1, Snapdragon 8 Elite: 2x Oryon prime cores at 4.74 GHz, 6x Oryon performance cores at 3.63 GHz, Wi-Fi 7 MLO, kernel 6.12.30-android16) and tested live against the Canada production gateway (<NODE_CANADA_IP>:9111, UDP RTT ~65 ms).

### 1.1 Speedtest Run 15 Empirical Results
* Downlink throughput: 663 Mbps sustained, instantaneous datapath flow peaked at 1,432.3 Mbps.
* Uplink throughput: 420.0 Mbps sustained (419,954,688 bytes delivered in 8,000 ms across 32 concurrent HTTP streams to gateway tunnel ingest 10.10.0.1:8455).
* Socket & error telemetry: Zero dropped packets (tx_dropped_sink=0), zero socket errors, all 32 HTTP streams completed with HTTP 200.
* Empirical vs analytical validation: The measured 420.0 Mbps matches Opus 5's analytical upper bound prediction (420.2 Mbps) within 0.05%. This confirms that the Kotlin monitor lock contention between the burst reader and batch pump was eliminated.
* Remaining gap: To reach >1,000 Mbps symmetrical wire speed (125,000,000 B/s = 91,041.5 pps at 1373 B inner MTU), the aggregate wall-clock budget per packet is 10.984 µs. Run 15 achieved 26.14 µs per packet (38,255 pps). A residual 15.16 µs per packet must be retired.

---

## 2. DETAILED PIPELINE TRACE & BOTTLENECK ANALYSIS

### 2.1 The Go Engine Loop Drain Cap (winn3/driver/loop.go)
In `winn3/driver/loop.go`, the loop drains the session outbox onto the carrier:
```go
if batchCarrier, isBatch := c.(carrier.BatchCarrier); isBatch {
    batchLimit := len(l.writeBatchMsgs)
    if batchLimit > session.MaxBatchSize {
        batchLimit = session.MaxBatchSize
    }
    // ...
    count, pollErr := l.sess.PollBatchInto(l.writeBatchBufs[:batchLimit])
    // ...
    n, err := batchCarrier.SendBatch(cctx, l.writeBatchMsgs[sent:count])
}
```
Currently:
* `session.MaxBatchSize = core.MaxBatchSize = 32`.
* `writeBatchBufs` and `writeBatchMsgs` are sized to `batchCapacity = session.MaxBatchSize = 32`.
* Even though Kotlin `WinnV3AndroidTun` and `inboundPump` now deliver 512-packet batches across the LocalSocket, the Go driver loop polls and transmits at most 32 datagrams per `SendBatch` call.
* At 1,000 Mbps (91,041 datagrams/sec), a batch limit of 32 forces 2,845 `sendmmsg` syscalls/sec and 2,845 Go scheduler poll cycles/sec.
* Widening `writeBatchMsgs` and the carrier batch to 256 or 512 datagrams reduces `sendmmsg` invocations to 356/sec (256-batch) or 178/sec (512-batch), slashing syscall context switching and core scheduling overhead by up to 93.8%.

### 2.2 The toEngine Channel Queue Bottleneck (winn3_frame_device.go)
In `cmd/winn-datapath/winn3_frame_device.go`:
```go
func (d *winn3FrameDevice) offerBatch(packets [][]byte) error {
    for _, pkt := range packets {
        d.push(d.toEngine, pkt, &d.droppedToEngine, false)
    }
    return nil
}
```
* `toEngine` is a `chan []byte` with capacity 65,536.
* Every single packet in the 512-packet batch is pushed individually onto the Go channel.
* At 1 Gbps, this produces 91,041 channel push operations and 91,041 channel pop operations (182,082 channel operations per second), contending on channel mutexes and triggering goroutine park/unpark transitions across OS threads.
* Replacing scalar `chan []byte` with batched carrier slices (e.g. `type InboundBatchCarrier struct { Packets [][]byte; Count int }` or `chan [][]byte`) collapses channel transitions from 182,082/sec to 356/sec.

### 2.3 core.MaxBatchSize and CryptoPool Sizing (winn3/core/batch.go)
* `core.MaxBatchSize` is hardcoded to 32.
* `CryptoPool` has `jobs [MaxBatchSize]cryptoJob` and `queue chan int` sized to 32.
* `Session.PollBatchInto(slots [][]byte)` rejects `len(slots) > MaxBatchSize`.
* If `core.MaxBatchSize` is widened to 256 or 512, does the crypto worker pool scale safely?
* Notice: on the Snapdragon 8 Elite, there are 8 CPU cores (2 prime + 6 performance). Parallel AEAD encryption over a batch of 64, 128, or 256 packets across 8 worker goroutines can maximize SIMD/crypto throughput.
* However, what is the optimal `core.MaxBatchSize`? Can `session.MaxBatchSize` decouple carrier batch size from crypto batch size, or should `core.MaxBatchSize` be scaled directly?

### 2.4 Gateway Ingress Pipeline Assessment
On the Canada production gateway (`cmd/winn3-gateway`):
* `cover_demux.go`: `splitUDP.pumpBatch` uses `demuxBatchSize = 64` and `recvmmsg`.
* `main.go`: `server.readLoopEntered` calls `s.conn.ReadFromUDPAddrPort(buf)` one datagram at a time.
* `deliverSessionDatagram` calls `ps.pipe.Deliver(buf)` one datagram at a time into `p.inbox chan *[]byte`.
* `ps.loop` drains `p.inbox` via `batchCarrier.RecvBatch` and calls `deliverReceiveBatch`, which calls `l.sess.DeliverBatch` and then `l.deliverInner(p) -> t.deliver(p) -> t.dev.WritePacket(p.body)` synchronously to the Linux TUN interface.
* Is the gateway currently saturated at 420 Mbps, or is the client-side Go datapath transmission loop the sole active bottleneck?

---

## 3. OPEN ITEMS (OI-1 THROUGH OI-4) FOR ADJUDICATION

### OI-1: Outer UDP Transmit Batching & GSO on Client
* **Proposal A (Vector sendmmsg Expansion)**: Expand `batchCapacity` in `winn3/driver/loop.go` from 32 to 256 (or 512). Ensure `carrier.UDP.SendBatch` and `RawBatchConn.WriteBatch` execute `sendmmsg` with up to 256/512 messages per call.
* **Proposal B (UDP GSO / UDP_SEGMENT)**: Use Linux UDP generic segmentation offload (`unix.UDP_SEGMENT`) where supported to coalesce multiple MTU datagrams into a single large UDP buffer.
* **Questions**:
  1. Is Proposal A (`sendmmsg` expansion to 256 or 512) sufficient to achieve >1,000 Mbps without the complexity and PMTU pitfalls of `UDP_SEGMENT`?
  2. What is the verified memory impact of 256 or 512 `BatchMsg` structures and iovecs in `loop.go` and `udp_batch_unix.go`?
  3. Does kernel `wmem_max = 8 MiB` on the S26 Ultra safely accommodate the widened transmit batch?

### OI-2: Inbound Batch Carrier Channel (toEngine Optimization)
* **Proposal**: Replace the per-packet `toEngine chan []byte` in `cmd/winn-datapath/winn3_frame_device.go` with a batched channel carrier (e.g. `chan [][]byte` or preallocated batch descriptor ring).
* **Questions**:
  1. What is the exact memory ownership and pool recycling lifecycle for packets across the channel?
  2. How is credit accounting and drop policy maintained?
  3. What is the exact per-packet CPU time retired by this change?

### OI-3: Sizing core.MaxBatchSize and Driver Drain Batch
* **Proposal**: Determine whether to:
  - Option 1: Scale `core.MaxBatchSize` from 32 to 64, 128, or 256 across `core/batch.go`, `session/batch.go`, and driver loops.
  - Option 2: Keep `core.MaxBatchSize = 32` for crypto batches, but decouple carrier transmit batching in `driver/loop.go` by allowing `loop.drain` to accumulate multiple crypto batches into a single outer `SendBatch` of 256 datagrams.
* **Questions**:
  1. What are the cache-locality, memory, and cryptographic latency implications of scaling `core.MaxBatchSize`?
  2. Does Option 1 or Option 2 provide cleaner architectural isolation? Provide exact arithmetic.

### OI-4: Downlink Freeze Invariant Verification (Treaty Rounds 35 & 38)
* **Invariant**: Downlink datapath, buffer allocations, and measurement mathematics remain 100% frozen.
* **Questions**:
  1. Do any proposed changes to `core.MaxBatchSize`, `loop.go`, or carrier batching alter the downlink receive path (`outboundPump`, `pumpOutboundBatch`, or `RecvBatch`)?
  2. How do we guarantee that downlink wire speed (>1,000 Mbps) remains completely unaffected?

---

## 4. MANDATE FOR ALL THREE PODIUMS

1. Provide independent, first-principles arithmetic for all claims. Compute exact pps, per-packet time budgets, and expected throughput.
2. Provide concrete architectural reasoning for each Open Item (OI-1 through OI-4).
3. Cast an explicit vote on each item:
   - Vote format: `AGREE` or `DISAGREE: <one concrete falsifiable technical reason>`.
4. Provide exact surgical code diffs for all proposed changes with zero placeholders.
5. Rules: Strictly zero em dashes (U+2014) or en dashes (U+2013) as connectors. Strictly zero AI cliches. Restrict bold styling to top-level list keys only.
"""


def stage1():
    print("=== ROUND 43 TURN 1 DISPATCH ===", flush=True)
    packet_file = TURN1_DIR / "packet.txt"
    packet_file.write_text(DOCKET_PACKET, encoding="utf-8")
    packet_sha = hashlib.sha256(DOCKET_PACKET.encode("utf-8")).hexdigest()
    print(f"Docket packet written: {len(DOCKET_PACKET)} bytes, sha256: {packet_sha}", flush=True)

    cache = load_cache()
    tasks = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        for seat in SEAT_KEYS:
            key = f"r43_turn1_{seat}"
            if cache.get(key):
                print(f"[{seat}] using cached turn 1 response", flush=True)
                continue
            if seat == "agy":
                print(f"[{seat}] dispatching Gemini 3.8 Flash High (Turn 1)...", flush=True)
                tasks[key] = (seat, ex.submit(query_agy, DOCKET_PACKET, "turn1"))
            elif seat == "claude-opus5":
                print(f"[{seat}] dispatching Claude Opus 5 (Turn 1 high effort)...", flush=True)
                tasks[key] = (seat, ex.submit(query_claude, DOCKET_PACKET, "turn1"))
            else:
                print(f"[{seat}] dispatching GPT-5.6 Sol Pro (Turn 1 high effort flex)...", flush=True)
                tasks[key] = (seat, ex.submit(query_openrouter, DOCKET_PACKET, SYSTEM_SEATS[seat]))

        for key, (seat, fut) in tasks.items():
            print(f"Waiting for [{seat}] (Turn 1)...", flush=True)
            result = fut.result()
            update_cache(key, result)
            seat_file_name = f"{seat.replace('claude-opus5', 'opus5')}_turn1.md"
            (TURN1_DIR / seat_file_name).write_text(f"# Turn 1 Submission: {seat}\n\n{result}\n", encoding="utf-8")
            (DOCS_EVIDENCE / f"debate_round43_stage1_{seat.replace('claude-opus5', 'opus5')}.md").write_text(
                f"# Turn 1 Submission: {seat}\n\n{result}\n", encoding="utf-8"
            )
            print(f"-> [{seat}] completed: {len(result)} bytes", flush=True)

    print("=== ROUND 43 TURN 1 DISPATCH COMPLETE ===", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Round 43 Debate Runner")
    parser.add_argument("--stage1", action="store_true", default=True, help="Run Turn 1 dispatch")
    args = parser.parse_args()
    if args.stage1:
        stage1()


if __name__ == "__main__":
    main()
