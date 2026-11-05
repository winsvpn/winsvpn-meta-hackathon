#!/usr/bin/env python3
"""Round 46: Android Winn v3 Uplink Wire-Speed Optimization (>1,000 Mbps) Stage D.

Dispatches the Round 46 docket to the three standing podiums:
  1. Gemini 3.8 Flash High (agy CLI, --effort high)
  2. Claude Opus 5 extra-high (claude CLI or OpenRouter anthropic/claude-opus-5 fallback)
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
ROUND46_DIR = REPO_ROOT / ".agent" / "debates" / "round46-client-ingress-bdp"
TURN1_DIR = ROUND46_DIR / "turn1-opening"
TURN1_DIR.mkdir(parents=True, exist_ok=True)
RAW_OUTPUT = DOCS_EVIDENCE / "debate_round46_raw.json"

SEAT_AGY_CWD = pathlib.Path("/tmp/r46_seat_agy")
SEAT_CLAUDE_CWD = pathlib.Path("/tmp/r46_seat_claude")

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
        with open(ROUND46_DIR / "receipts.raw.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")


def query_openrouter(
    prompt: str,
    system_role: str,
    seat: str = "solpro",
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
        }
        if "openai" in model:
            payload["provider"] = {"order": ["OpenAI"], "allow_fallbacks": True}
            payload["reasoning"] = {"effort": reasoning_effort}
            payload["service_tier"] = "flex"
        elif "anthropic" in model:
            payload["provider"] = {"allow_fallbacks": True}

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            OPENROUTER_ENDPOINT,
            data=data,
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://winsvpn.org",
                "X-Title": "Winthos Debate Round 46 Client Ingress BDP Scaling",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=600, context=tls_ctx) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                if "error" in res_data:
                    print(f"[{seat}] upstream error (attempt {attempt+1}): {res_data['error'].get('message')}", flush=True)
                    time.sleep(min(45, 8 * (attempt + 1)))
                    continue
                choice = res_data["choices"][0]["message"]
                content = (choice.get("content") or choice.get("reasoning") or "").strip()
                if content:
                    write_receipt(seat, "turn1", prompt, content, "ok")
                    return clean_text(content)
        except Exception as e:
            print(f"[{seat}] attempt {attempt+1} failed: {e}", flush=True)
            time.sleep(min(45, 8 * (attempt + 1)))
    write_receipt(seat, "turn1", prompt, "", "fail")
    raise RuntimeError(f"{seat} query failed after retries")


def query_agy(prompt: str, stage: str = "turn1") -> str:
    SEAT_AGY_CWD.mkdir(parents=True, exist_ok=True)
    stdin_text = (
        "The complete Round 46 debate packet follows after this line. Read all of it, then "
        "complete the mandate it contains. Reply with your verdict, first-principles arithmetic, "
        "and exact diffs only.\n\n"
        + prompt
    )
    for attempt in range(6):
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
            out = out_bytes.decode("utf-8", errors="replace").strip()
            err = err_bytes.decode("utf-8", errors="replace")
            if proc.returncode != 0 or not out:
                if "RESOURCE_EXHAUSTED" in err or "429" in err:
                    print(f"[agy] quota 429 (attempt {attempt+1}), backing off...", flush=True)
                    time.sleep(min(120, 20 * (attempt + 1)))
                    continue
                write_receipt("agy", stage, prompt, err[:2000], f"fail rc={proc.returncode}")
                raise RuntimeError(f"agy failed rc={proc.returncode}: {err[:400]}")
            write_receipt("agy", stage, prompt, out, "ok")
            return clean_text(out)
        except subprocess.TimeoutExpired:
            print(f"[agy] attempt {attempt+1} timed out", flush=True)
            time.sleep(10)
    write_receipt("agy", stage, prompt, "", "timeout")
    raise RuntimeError("agy failed after retries")


def query_claude(prompt: str, stage: str = "turn1") -> str:
    SEAT_CLAUDE_CWD.mkdir(parents=True, exist_ok=True)
    stdin_text = (
        "The complete Round 46 debate packet follows after this line. Read all of it, then "
        "complete the mandate it contains. Do not use any tools. Reply with your "
        "verdict, first-principles arithmetic, and exact diffs only.\n\n" + prompt
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
        out_bytes, err_bytes = proc.communicate(stdin_text.encode("utf-8"), timeout=1500)
        out = out_bytes.decode("utf-8", errors="replace").strip()
        err = err_bytes.decode("utf-8", errors="replace")
        if proc.returncode != 0 or not out or "weekly limit" in out.lower():
            run_cli = False
    except (subprocess.TimeoutExpired, Exception):
        run_cli = False

    if not run_cli:
        print("[claude-opus5] CLI quota reached, falling back to OpenRouter anthropic/claude-opus-5...", flush=True)
        return query_openrouter(
            prompt,
            SYSTEM_SEATS["claude-opus5"],
            seat="claude-opus5",
            model="anthropic/claude-opus-5",
        )

    write_receipt("claude-opus5", stage, prompt, out, "ok")
    return clean_text(out)


SYSTEM_SEATS = {
    "agy": (
        "You are Podium 1 (Gemini 3.8 Flash High) in the Iterative Convergence Debate Protocol (ICDP). "
        "You are evaluating the Android Winn Protocol v3 Uplink Wire-Speed Optimization Stage D docket. "
        "Examine all Open Items (OI-1 through OI-4) independently. Provide concrete architectural reasoning, "
        "first-principles arithmetic, exact surgical code diffs, and an explicit vote per item (AGREE or "
        "DISAGREE: <one concrete falsifiable technical reason>). "
        "Zero em dashes or en dashes as connectors. Ban AI cliches. Restrict bold styling to top-level list keys only."
    ),
    "claude-opus5": (
        "You are Podium 2 (Claude Opus 5) in the Iterative Convergence Debate Protocol (ICDP). "
        "You are evaluating the Android Winn Protocol v3 Uplink Wire-Speed Optimization Stage D docket. "
        "Examine all Open Items (OI-1 through OI-4) independently. Provide concrete architectural reasoning, "
        "first-principles arithmetic, exact surgical code diffs, and an explicit vote per item (AGREE or "
        "DISAGREE: <one concrete falsifiable technical reason>). "
        "Zero em dashes or en dashes as connectors. Ban AI cliches. Restrict bold styling to top-level list keys only."
    ),
    "solpro": (
        "You are Podium 3 (GPT-5.6 Sol Pro) in the Iterative Convergence Debate Protocol (ICDP). "
        "You are evaluating the Android Winn Protocol v3 Uplink Wire-Speed Optimization Stage D docket. "
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


DOCKET_PACKET = """# MULTI-MODEL DEBATE ROUND 46: ANDROID WINN V3 UPLINK WIRE-SPEED SCALING (>1,000 MBPS) STAGE D: CLIENT INGRESS, TCP CONGESTION & IPC PIPELINE

## 1. CONTEXT, EMPIRICAL EVIDENCE & OBSERVED STATE

Following Round 45 unanimous treaty ratification, the Stage C optimizations (Transmit Drain Gating `txDrainGate` in `cmd/winn-datapath/winn3_to_engine_ring.go` and UDP Segmentation Offload GSO probing in `winn3/carrier/udp_gso_linux.go`) were packaged via Flutter `--dart-define` compilation and deployed to the physical retail Samsung Galaxy S26 Ultra (SM-S948U1, Snapdragon 8 Elite: 2x Oryon prime cores at 4.32 GHz, 6x Oryon performance cores at 3.53 GHz, Wi-Fi 7 MLO, Linux kernel 6.12.30-android16) and evaluated live against the Canada production gateway (<NODE_CANADA_IP>:9111, UDP RTT ~65 ms).

### 1.1 Speedtest Run 18 Empirical Results
* Downlink throughput:
  - Iteration 1: 675 Mbps sustained UI (in-flight engine peak: 1,607.9 Mbps, 3.9 GB transferred in 5s).
  - Iteration 2: 611 Mbps sustained UI (in-flight engine peak: 1,375.5 Mbps, 9.4 GB cumulative).
  - Downlink Freeze Invariant 100% preserved and verified.
* Uplink throughput:
  - Iteration 1: 401 Mbps sustained UI (in-flight engine peak: ~850 Mbps, 884.2 MB transferred in 8s).
  - Iteration 2: 366 Mbps sustained UI (1.7 GB cumulative in 8s).
  - Plateau: Stage C maintained upload between 366 and 401 Mbps sustained.
* Carrier socket batching telemetry:
  - Received packets: 3,937,342 (100% offered, 0 lost).
  - Transmitted packets: 1,719,899 across 711,887 carrier socket calls.
  - Batch occupancy ratio: 1,719,899 / 711,887 = 2.4158 packets per message sent (increased from 1.5806 in Run 17, a 52.8% improvement).
  - Ring buffer tail drops: 0 (tx_dropped_sink=0).
  - Socket send failures: 0 (send_failed=0).
  - Socket receive failures: 0 (recv_failed=0).
  - Zero oversize drops, zero kernel buffer overflows, zero migrations.

### 1.2 The Asymmetry Paradox
* Downlink achieves >1,600 Mbps burst and 675 Mbps sustained over the identical physical Wi-Fi 7 radio, kernel network stack, Snapdragon 8 Elite SoC, and ChaCha20-Poly1305 cryptographic primitives.
* Uplink remains bounded at ~366 to 401 Mbps sustained despite zero packet loss, zero ring drops, and zero socket send failures across millions of datagrams.
* The bottleneck is therefore NOT in the outer carrier network, packet loss, or Wi-Fi PHY rate (4,322 Mbps Rx / 3,843 Mbps Tx).
* The bottleneck sits squarely in the UPSTREAM CLIENT INGRESS PIPELINE: from the application traffic generator through the Android OS kernel, TUN interface, JNI/JVM layer, IPC channel, and Go engine queueing.

---

## 2. ANATOMY OF THE UPSTREAM CLIENT INGRESS PIPELINE

### 2.1 Handset Application Sockets & TCP Window Scaling (`MainActivity.kt`)
* The speedtest client (`MainActivity.kt:1525-1555`) spawns 32 parallel worker threads, each creating a `java.net.Socket()`.
* Each socket sets `socket.tcpNoDelay = true`, connects to the inner router `10.10.0.1:8455` over the tunnel, and writes 128 KB byte chunks in a loop: `out.write(chunk)`.
* Crucially, `socket.sendBufferSize` is NEVER set. It remains at the Android JVM/OS default.
* First-Principles Bandwidth-Delay Product (BDP) Analysis:
  - Target Bitrate: 1,000 Mbps = 125,000,000 B/s.
  - Canada Gateway RTT: 65 ms = 0.065 s.
  - Total Required In-Flight BDP: 125,000,000 B/s * 0.065 s = 8,125,000 bytes (~7.75 MiB).
  - Across 32 streams, each stream must sustain a BDP of 8,125,000 / 32 = 253,906 bytes (~248 KiB).
  - If default socket buffer or autotuning limits initial window expansion or clamps TCP send windows on Android `tun0`, the 32 streams saturate at ~12 Mbps each, producing the observed 366-401 Mbps aggregate ceiling!

### 2.2 The Three-Copy JVM & IPC Channel Boundary
* Trace of every uplink packet from user space to wire:
  1. Handset Kernel TCP Stack: Emits 1,373-byte IP packets into `tun0` queue.
  2. Native C++ Bulk Reader (`winn_tun_bulk.cpp`): Calls `read(fd, slot, width)` for each packet into direct ByteBuffer `staging`.
  3. Kotlin Ring Buffer Copy (`WinnV3AndroidTun.kt:587`): Copies payload from `staging` into Kotlin heap byte array `this.slab`:
     `staging.get(this.slab, slot * packetCapacity, len)` [Copy 1].
  4. Kotlin Inbound Pump (`WinnV3Bridge.kt` / `WinnV3AndroidTun.kt:809`): Copies from `this.slab` into `WinnV3PacketBatch` with 16-byte framing header [Copy 2].
  5. LocalSocket IPC Write (`WinnV3PacketBatch.kt:165`): Writes batch bytes across `AF_UNIX` stream socket (`output.write`).
  6. Go Engine Socket Read (`winn3_frame.go:297`): `reader.Read()` parses framing header.
  7. Go Heap Allocation & Copy (`winn3_frame.go:241`): `allocPacket(payload)` executes `copy(cp, src)` into Go `packetPool` slice [Copy 3].
  8. Go Ring Buffer: Pushes slice pointer into `toEngineRing`.
  9. Go Session Loop: Dequeues, encrypts with ChaCha20-Poly1305.
  10. Outer Carrier: Sends via outer UDP socket.
* Total copies: THREE memory copies, TWO thread context switches in Kotlin, and ONE full inter-process `AF_UNIX` pipe round-trip per packet!
* At wire speed (91,041 pps):
  91,041 * 3 = 273,123 buffer copies per second of ~1.4 KB payloads = 375 MB/s of memory churn across L1/L2 caches and JVM garbage collector boundaries.

### 2.3 Transmit Drain Gating Timer Parking (`toEngineRing.go`)
* In Round 45, `popBatch` in `toEngineRing.go` introduced `lowWater = 32` and `maxPark = 250 µs`.
* When `r.count < 32`, the reader parks on a timer for up to 250 µs waiting for burst packets.
* However, in `pushBatch` and `pushOne`, the notification is only fired if `oldCount == 0` or `newCount >= r.lowWater`.
* If packets trickle in batches smaller than 32 (e.g. 5 to 10 packets), the consumer waits for the full 250 µs timer expiration before draining.
* 711,887 socket messages in 8 seconds indicates an average interval of ~11.2 µs per carrier write, but batch occupancy remained at 2.41 packets per message.

---

## 3. OPEN ITEMS (OI-1 THROUGH OI-4) FOR ADJUDICATION

### OI-1: Handset TCP Sockets & Ingest Server BDP Window Scaling
* **Question 1.1**: Does configuring explicit socket send buffers (e.g. `socket.sendBufferSize = 1048576` / 1 MiB or 2 MiB) on each of the 32 upload worker sockets in `MainActivity.kt` enable the Linux TCP stack to expand the congestion window to the required 254 KiB per stream?
* **Question 1.2**: In `cmd/winn3-gateway/speedtest_ingest.go`, does the gateway ingest server (`handleUpload`) or Linux TCP stack impose any receive window ceiling? Should `ReadBufferSize` or `SO_RCVBUF` be explicitly enlarged on the gateway listener?
* **Question 1.3**: Provide exact first-principles BDP arithmetic showing the relationship between socket buffer allocation, RTT (65 ms), stream count (32 vs 16 vs 8), and achievable aggregate throughput.

### OI-2: Eliminating IPC Copies & Streamlining the Ingress Pipeline
* **Question 2.1**: Can the promoted TUN file descriptor be passed directly to the Go process via SCM_RIGHTS (similar to how `-receive-fd` passes the outer UDP socket), allowing `winn-datapath` to read directly from `tun0` and eliminating the Kotlin `TunRead` thread, the JVM byte copies, and the `LocalSocket` (`AF_UNIX`) transport entirely?
* **Question 2.2**: If TUN descriptor handover is adopted, how should `winn3_frame.go` handle the transition from bootstrap to promoted descriptor without dropping connections?
* **Question 2.3**: If `LocalSocket` (`AF_UNIX`) must be retained, how can the three memory copies (JVM staging -> Kotlin slab -> PacketBatch -> Go allocPacket) be reduced to zero-copy or single-copy?

### OI-3: Transmit Drain Gating (txDrainGate) Parameter Calibration
* **Question 3.1**: Why did Run 18 achieve 2.41 packets per socket message instead of the targeted 16-32 packets?
* **Question 3.2**: Is `maxPark = 250 µs` too conservative, creating artificial throughput throttling when input rates vary? Should `maxPark` be calibrated to 50 µs or 100 µs, and `lowWater` to 8 or 16?
* **Question 3.3**: Should `pushBatch` signal immediately if `r.count > 0`, avoiding the timer park entirely when the consumer is active?

### OI-4: Downlink Freeze Invariant 100% Preservation
* **Question 4.1**: Verify that all proposed changes in Round 46 apply exclusively to the transmit/uplink pipeline (`tx`), client socket generation, and ingress queues.
* **Question 4.2**: Reaffirm that `RecvBatch`, `outboundPump`, `toHost`, `fromEngine`, downlink crypto workers, and measurement mathematics remain 100% frozen.

---

## 4. MANDATE FOR ALL THREE PODIUMS
1. Provide independent, first-principles arithmetic for all claims. Compute exact pps, per-packet time budgets, BDP limits, and expected throughput.
2. Provide concrete architectural reasoning for each Open Item (OI-1 through OI-4).
3. Cast an explicit vote on each item:
   - Vote format: `AGREE` or `DISAGREE: <one concrete falsifiable technical reason>`.
4. Provide exact surgical code diffs for all proposed changes with zero placeholders.
5. Rules: Strictly zero em dashes (U+2014) or en dashes (U+2013) as connectors. Strictly zero AI cliches. Restrict bold styling to top-level list keys only.
"""


def stage1():
    print("=== ROUND 46 TURN 1 DISPATCH ===", flush=True)
    packet_file = TURN1_DIR / "packet.txt"
    packet_file.write_text(DOCKET_PACKET, encoding="utf-8")
    packet_sha = hashlib.sha256(DOCKET_PACKET.encode("utf-8")).hexdigest()
    print(f"Docket packet written: {len(DOCKET_PACKET)} bytes, sha256: {packet_sha}", flush=True)

    cache = load_cache()

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futures_map = {}
        for seat in SEAT_KEYS:
            key = f"r46_turn1_{seat}"
            if cache.get(key):
                print(f"[{seat}] using cached turn 1 response", flush=True)
                continue
            if seat == "agy":
                print(f"[{seat}] dispatching Gemini 3.8 Flash High (Turn 1)...", flush=True)
                fut = ex.submit(query_agy, DOCKET_PACKET, "turn1")
                futures_map[fut] = (key, seat)
            elif seat == "claude-opus5":
                print(f"[{seat}] dispatching Claude Opus 5 (Turn 1 high effort)...", flush=True)
                fut = ex.submit(query_claude, DOCKET_PACKET, "turn1")
                futures_map[fut] = (key, seat)
            else:
                print(f"[{seat}] dispatching GPT-5.6 Sol Pro (Turn 1 high effort flex)...", flush=True)
                fut = ex.submit(query_openrouter, DOCKET_PACKET, SYSTEM_SEATS[seat], seat=seat)
                futures_map[fut] = (key, seat)

        for fut in concurrent.futures.as_completed(futures_map):
            key, seat = futures_map[fut]
            try:
                result = fut.result()
                update_cache(key, result)
                seat_file_name = f"{seat.replace('claude-opus5', 'opus5')}_turn1.md"
                (TURN1_DIR / seat_file_name).write_text(f"# Turn 1 Submission: {seat}\n\n{result}\n", encoding="utf-8")
                (DOCS_EVIDENCE / f"debate_round46_stage1_{seat.replace('claude-opus5', 'opus5')}.md").write_text(
                    f"# Turn 1 Submission: {seat}\n\n{result}\n", encoding="utf-8"
                )
                print(f"-> [{seat}] completed: {len(result)} bytes", flush=True)
            except Exception as e:
                print(f"-> [{seat}] error: {e}", flush=True)
                raise

    print("=== ROUND 46 TURN 1 DISPATCH COMPLETE ===", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Round 46 Debate Runner")
    parser.add_argument("--stage1", action="store_true", default=True, help="Run Turn 1 dispatch")
    args = parser.parse_args()
    if args.stage1:
        stage1()


if __name__ == "__main__":
    main()
