#!/usr/bin/env python3
"""Round 44: Android Winn v3 Uplink Wire-Speed Optimization (>1,000 Mbps) Stage B.

Dispatches the Round 44 docket to the three standing podiums:
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
ROUND44_DIR = REPO_ROOT / ".agent" / "debates" / "round44-frame-queue-optimization"
TURN1_DIR = ROUND44_DIR / "turn1-opening"
TURN1_DIR.mkdir(parents=True, exist_ok=True)
RAW_OUTPUT = DOCS_EVIDENCE / "debate_round44_raw.json"

SEAT_AGY_CWD = pathlib.Path("/tmp/r44_seat_agy")
SEAT_CLAUDE_CWD = pathlib.Path("/tmp/r44_seat_claude")

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
        with open(ROUND44_DIR / "receipts.raw.jsonl", "a", encoding="utf-8") as f:
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
                "X-Title": "Winthos Debate Round 44 Frame Queue Optimization",
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
        "The complete Round 44 debate packet follows after this line. Read all of it, then "
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
        "The complete Round 44 debate packet follows after this line. Read all of it, then "
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
        "You are evaluating the Android Winn Protocol v3 Uplink Wire-Speed Optimization Stage B docket. "
        "Examine all Open Items (OI-1 through OI-4) independently. Provide concrete architectural reasoning, "
        "first-principles arithmetic, exact surgical code diffs, and an explicit vote per item (AGREE or "
        "DISAGREE: <one concrete falsifiable technical reason>). "
        "Zero em dashes or en dashes as connectors. Ban AI cliches. Restrict bold styling to top-level list keys only."
    ),
    "claude-opus5": (
        "You are Podium 2 (Claude Opus 5) in the Iterative Convergence Debate Protocol (ICDP). "
        "You are evaluating the Android Winn Protocol v3 Uplink Wire-Speed Optimization Stage B docket. "
        "Examine all Open Items (OI-1 through OI-4) independently. Provide concrete architectural reasoning, "
        "first-principles arithmetic, exact surgical code diffs, and an explicit vote per item (AGREE or "
        "DISAGREE: <one concrete falsifiable technical reason>). "
        "Zero em dashes or en dashes as connectors. Ban AI cliches. Restrict bold styling to top-level list keys only."
    ),
    "solpro": (
        "You are Podium 3 (GPT-5.6 Sol Pro) in the Iterative Convergence Debate Protocol (ICDP). "
        "You are evaluating the Android Winn Protocol v3 Uplink Wire-Speed Optimization Stage B docket. "
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


DOCKET_PACKET = """# MULTI-MODEL DEBATE ROUND 44: ANDROID WINN V3 UPLINK WIRE-SPEED SCALING STAGE B (>1,000 MBPS)

## 1. CONTEXT, EMPIRICAL EVIDENCE & OBSERVED STATE

Following the Round 43 unanimous treaty ratification, the Stage A optimizations (carrier transmit batch size expanded to 256 datagrams and 8-batch outbox drain loop accumulation in `winn3/driver/loop.go` and `winn3/carrier/udp_batch_unix.go`) were deployed to the physical retail Samsung Galaxy S26 Ultra (SM-S948U1, Snapdragon 8 Elite: 2x Oryon prime cores at 4.74 GHz, 6x Oryon performance cores at 3.63 GHz, Wi-Fi 7 MLO, Linux kernel 6.12.30-android16) and evaluated live against the Canada production gateway (<NODE_CANADA_IP>:9111, UDP RTT ~65 ms).

### 1.1 Speedtest Run 16 Empirical Results
* Downlink throughput: 673 Mbps sustained (Run 15 was 663 Mbps, confirming 100% preservation of the Downlink Freeze Invariant).
* Uplink throughput: 389.7 Mbps median (Iteration 1: 389.7 Mbps, Iteration 2: 349.8 Mbps, Iteration 3: 399.6 Mbps; delivered 389,677,056 bytes in 8,000 ms across 32 concurrent HTTP streams to gateway ingest 10.10.0.1:8455).
* Socket and error telemetry: Zero dropped packets (tx_dropped_sink=0), zero socket write errors (send_failed=0), zero packet truncation across 5,921,499 received packets and 2,572,521 transmitted packets. All 32 HTTP streams completed with HTTP 200 responses.
* Confirmation of Opus 5 Prediction 1: Expanding outer carrier `sendmmsg` from 32 to 256 datagrams reduced syscall frequency from 2,845 to 356 calls/sec, but only retired 0.273 µs per packet of fixed syscall entry overhead. Out of the 15.17 µs per packet gap, 0.27 µs represents ~1.8% of the required savings. The empirical 389.7-399.6 Mbps confirms Opus 5's analytical upper bound prediction (~424 Mbps for Stage A alone).
* Remaining gap to wire speed: At 1,000 Mbps wire speed (125,000,000 B/s = 91,041.5 pps at 1,373 B inner MTU), the total per-packet budget is 10.984 µs. Run 16 achieved 28.18 µs per packet (35,476 pps). A residual ~17.20 µs per packet must be retired.

---

## 2. DETAILED PIPELINE TRACE: THE FRAME DEVICE BOTTLENECK

Stage B targets the frame device interface between the host IPC frame reader and the tun engine (`cmd/winn-datapath/winn3_frame_device.go` and `winn3_frame.go`).

### 2.1 The Scalar Channel Contention Bottleneck (winn3_frame_device.go)
In `cmd/winn-datapath/winn3_frame_device.go`:
```go
func (d *winn3FrameDevice) offerBatch(packets [][]byte) error {
    // ...
    for _, pkt := range packets {
        if len(pkt) > d.mtu {
            d.oversize.Add(1)
            d.recycle(pkt)
            continue
        }
        d.push(d.toEngine, pkt, &d.droppedToEngine, false)
    }
    return nil
}
```
And in `ReadBatch(bufs [][]byte)`:
```go
func (d *winn3FrameDevice) ReadBatch(bufs [][]byte) ([]int, error) {
    // ...
    select {
    case pkt, ok := <-d.toEngine:
        first = pkt
    // ...
    }
    n0 := copy(bufs[0], first)
    d.recycle(first)
    lengths = append(lengths, n0)

    for len(lengths) < len(bufs) {
        select {
        case pkt, ok := <-d.toEngine:
            // ...
            ni := copy(bufs[idx], pkt)
            d.recycle(pkt)
            lengths = append(lengths, ni)
        default:
            // ...
            return lengths, nil
        }
    }
    // ...
}
```
* `toEngine` is currently a `chan []byte` with capacity 65,536.
* In `offerBatch`: up to 512 packets from the host are pushed onto `toEngine` one by one. Every push acquires and releases the internal Go channel mutex (`hchan.lock`).
* In `ReadBatch`: up to 256 packets are popped from `toEngine` one by one via `select` statements. Every pop acquires and releases the channel mutex (`hchan.lock`).
* Frequency at line rate: At 1,000 Mbps (91,041 pps), this channel forces 91,041 push operations and 91,041 pop operations per second (182,082 channel lock acquisitions per second).
* Inter-core contention: The frame reader goroutine (`serve`) and the outbound pump goroutine (`tun.pumpOutboundBatch`) run on separate Oryon CPU cores. 182,082 cross-core channel mutex acquisitions per second cause severe cache line bouncing on `hchan.lock`, CPU thread parking/unparking, and scheduler latency.

### 2.2 Triple Payload Memory Copy Churn
Trace of payload bytes from host to wire on uplink:
1. `winn3_frame.go`: `reader.Read()` reads frame into internal `r.buffer`. `allocPacket(payload)` allocates a 2,048-byte buffer from `packetPool` and copies `payload` into it (Copy 1: 125 MB/s at 1 Gbps).
2. `winn3_frame_device.go`: `ReadBatch` pops `pkt`, executes `copy(bufs[idx], pkt)` to transfer into caller-provided `bufs[idx]`, and recycles `pkt` back to `packetPool` (Copy 2: 125 MB/s at 1 Gbps).
3. `winn3/session/driver.go`: `EnqueueBatch` pops `inner` from `bufs`, calls `p := d.getDataBuf(len(inner))`, and executes `copy(p, inner)` (Copy 3: 125 MB/s at 1 Gbps).
* Total memory copy bandwidth: At 1,000 Mbps wire speed, inner payload bytes are copied 3 times in Go heap memory, consuming 375 MB/s of memory bus bandwidth before encryption even begins.

### 2.3 Gateway Ingress Pipeline Headroom (<NODE_CANADA_IP>:9111)
* Gateway components:
  - `cover_demux.go`: `splitUDP.pumpBatch` uses `demuxBatchSize = 64` and `recvmmsg`.
  - `forward_linux.go`: `sharedGatewayTun` uses `gatewayTunBatchSize = 256`, 4 multi-queue descriptors, and IP source-hashing write distribution.
  - `speedtest_ingest.go`: `speedtestIngestServer` handles `/speedtest/up` via `io.Copy(io.Discard, body)` across up to 64 concurrent streams.
* Run 16 telemetry on physical hardware demonstrated 0 drops across 2,572,521 transmitted packets and 389,677,056 bytes.
* Headroom question: Does the gateway need any tuning to absorb 1,000 Mbps, or is the bottleneck entirely client-side?

---

## 3. OPEN ITEMS (OI-1 THROUGH OI-4) FOR ADJUDICATION

### OI-1: Replacing toEngine chan []byte with a Lock-Batched Ring Buffer
* **Proposal**: In `winn3_frame_device.go`, replace `toEngine chan []byte` with a dedicated circular ring buffer:
  - Structure:
    ```go
    type toEngineRing struct {
        mu      sync.Mutex
        cond    *sync.Cond
        storage [][]byte
        head    int
        tail    int
        count   int
        closed  bool
    }
    ```
  - Sizing: `storage` sized to `winn3FrameQueueDepth = 65536`.
  - Push batching: `offerBatch(packets [][]byte)` acquires `mu.Lock()` ONCE for the entire batch (up to 512 packets). It enqueues all packets in a tight loop, applying tail drop if capacity is exceeded, signals `cond.Signal()` (or `Broadcast()`), and releases `mu.Unlock()`.
  - Pop batching: `ReadBatch(bufs [][]byte)` acquires `mu.Lock()` ONCE. If empty, waits on `cond.Wait()`. Drains up to `len(bufs)` (256) packets from the ring in a single step under that single lock, then releases `mu.Unlock()`.
* **Questions**:
  1. What is the exact CPU time saved per packet by reducing lock acquisitions from 182,082/sec to 356/sec (512-push / 256-pop)?
  2. How should closing semantics and graceful drain be handled so unconsumed packets are not leaked or dropped prematurely?
  3. Does `cond.Signal()` vs `cond.Broadcast()` matter given single-consumer single-producer architecture?

### OI-2: Minimizing Intermediate Memory Copy Churn
* **Proposal**: Analyze whether intermediate copying between `allocPacket` and `ReadBatch` can be safely avoided.
* **Constraints**:
  - `tun.BatchDevice` specifies `ReadBatch(bufs [][]byte) ([]int, error)`. `bufs` is caller-allocated by `pumpOutboundBatch` (`bufs[i] = make([]byte, MaxIPPacket)`).
  - `duplex.Reader.Read()` reuses `r.buffer` for each frame, so `payload` cannot be referenced across subsequent `Read()` calls without copying.
* **Questions**:
  1. Can `winn3_frame.go` read directly into preallocated buffers, or is `packetPool` recycling already optimal?
  2. Does replacing channel operations in OI-1 alleviate the memory contention sufficiently to reach >1,000 Mbps? Provide exact arithmetic.

### OI-3: Gateway Ingress Pipeline Audit (<NODE_CANADA_IP>:9111)
* **Assessment**: Audit the gateway ingress pipeline (`splitUDP.pumpBatch`, `sharedGatewayTun.write`, `speedtest_ingest.go`).
* **Questions**:
  1. At 91,041 pps (1,000 Mbps), does the gateway `sharedGatewayTun.write` (with 4 multi-queue descriptors) or `speedtestIngestServer` experience any queue starvation or lock contention?
  2. Does the gateway require any modification to sustain >1,000 Mbps uplink, or is it already verified capable?

### OI-4: Downlink Freeze Invariant Verification (Treaty Rounds 35 & 38)
* **Invariant**: Downlink datapath, buffer allocations, and measurement mathematics remain 100% frozen.
* **Verification**:
  1. Does the replacement of `toEngine` leave `toHost chan []byte`, `take()`, `tryTake()`, and `WritePacket()` completely untouched?
  2. Confirm that downlink wire speed (>1,000 Mbps) is completely decoupled from `toEngine`.

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
    print("=== ROUND 44 TURN 1 DISPATCH ===", flush=True)
    packet_file = TURN1_DIR / "packet.txt"
    packet_file.write_text(DOCKET_PACKET, encoding="utf-8")
    packet_sha = hashlib.sha256(DOCKET_PACKET.encode("utf-8")).hexdigest()
    print(f"Docket packet written: {len(DOCKET_PACKET)} bytes, sha256: {packet_sha}", flush=True)

    cache = load_cache()
    tasks = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        for seat in SEAT_KEYS:
            key = f"r44_turn1_{seat}"
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
            (DOCS_EVIDENCE / f"debate_round44_stage1_{seat.replace('claude-opus5', 'opus5')}.md").write_text(
                f"# Turn 1 Submission: {seat}\n\n{result}\n", encoding="utf-8"
            )
            print(f"-> [{seat}] completed: {len(result)} bytes", flush=True)

    print("=== ROUND 44 TURN 1 DISPATCH COMPLETE ===", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Round 44 Debate Runner")
    parser.add_argument("--stage1", action="store_true", default=True, help="Run Turn 1 dispatch")
    args = parser.parse_args()
    if args.stage1:
        stage1()


if __name__ == "__main__":
    main()
