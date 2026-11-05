#!/usr/bin/env python3
"""Round 45: Android Winn v3 Uplink Wire-Speed Optimization (>1,000 Mbps) Stage C.

Dispatches the Round 45 docket to the three standing podiums:
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
ROUND45_DIR = REPO_ROOT / ".agent" / "debates" / "round45-superframe-coalescing"
TURN1_DIR = ROUND45_DIR / "turn1-opening"
TURN1_DIR.mkdir(parents=True, exist_ok=True)
RAW_OUTPUT = DOCS_EVIDENCE / "debate_round45_raw.json"

SEAT_AGY_CWD = pathlib.Path("/tmp/r45_seat_agy")
SEAT_CLAUDE_CWD = pathlib.Path("/tmp/r45_seat_claude")

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
        with open(ROUND45_DIR / "receipts.raw.jsonl", "a", encoding="utf-8") as f:
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
                "X-Title": "Winthos Debate Round 45 Super-Frame Coalescing",
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
        "The complete Round 45 debate packet follows after this line. Read all of it, then "
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
        "The complete Round 45 debate packet follows after this line. Read all of it, then "
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
        "You are evaluating the Android Winn Protocol v3 Uplink Wire-Speed Optimization Stage C docket. "
        "Examine all Open Items (OI-1 through OI-4) independently. Provide concrete architectural reasoning, "
        "first-principles arithmetic, exact surgical code diffs, and an explicit vote per item (AGREE or "
        "DISAGREE: <one concrete falsifiable technical reason>). "
        "Zero em dashes or en dashes as connectors. Ban AI cliches. Restrict bold styling to top-level list keys only."
    ),
    "claude-opus5": (
        "You are Podium 2 (Claude Opus 5) in the Iterative Convergence Debate Protocol (ICDP). "
        "You are evaluating the Android Winn Protocol v3 Uplink Wire-Speed Optimization Stage C docket. "
        "Examine all Open Items (OI-1 through OI-4) independently. Provide concrete architectural reasoning, "
        "first-principles arithmetic, exact surgical code diffs, and an explicit vote per item (AGREE or "
        "DISAGREE: <one concrete falsifiable technical reason>). "
        "Zero em dashes or en dashes as connectors. Ban AI cliches. Restrict bold styling to top-level list keys only."
    ),
    "solpro": (
        "You are Podium 3 (GPT-5.6 Sol Pro) in the Iterative Convergence Debate Protocol (ICDP). "
        "You are evaluating the Android Winn Protocol v3 Uplink Wire-Speed Optimization Stage C docket. "
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


DOCKET_PACKET = """# MULTI-MODEL DEBATE ROUND 45: ANDROID WINN V3 UPLINK WIRE-SPEED SCALING STAGE C (>1,000 MBPS)

## 1. CONTEXT, EMPIRICAL EVIDENCE & OBSERVED STATE

Following Round 44 unanimous treaty ratification, the Stage B optimizations (replacing the scalar Go channel `toEngine chan []byte` with a lock-batched circular ring buffer `toEngineRing` with 512 push / 256 pop in `cmd/winn-datapath/winn3_frame_device.go`) were deployed to the physical retail Samsung Galaxy S26 Ultra (SM-S948U1, Snapdragon 8 Elite: 2x Oryon prime cores at 4.32 GHz, 6x Oryon performance cores at 3.53 GHz, Wi-Fi 7 MLO, Linux kernel 6.12.30-android16) and evaluated live against the Canada production gateway (<NODE_CANADA_IP>:9111, UDP RTT ~65 ms).

### 1.1 Speedtest Run 17 Empirical Results
* Downlink throughput:
  - Iteration 1: 616 Mbps UI (in-flight engine peak: 1,604.1 Mbps).
  - Iteration 2: 686 Mbps UI (in-flight engine peak: 1,714.4 Mbps).
  - Downlink Freeze Invariant 100% preserved and verified.
* Uplink throughput:
  - Iteration 1: 426 Mbps UI (in-flight engine peak: 872.7 Mbps).
  - Iteration 2: 418 Mbps UI (in-flight engine peak: 883.3 Mbps).
  - Plateau: Stage B raised sustained upload from 389.7 Mbps to 426.0 Mbps (median ~422 Mbps).
* Datapath and error telemetry:
  - Received packets: 4,049,268 (100% offered, 0 lost).
  - Transmitted packets: 1,811,929 across 1,146,349 carrier socket calls.
  - Ring buffer tail drops: 0 (tx_dropped_sink=0).
  - Socket send failures: 0 (send_failed=0).
  - Socket receive failures: 0 (recv_failed=0).
  - Canada production gateway inner packets delivered: 39,285,962 with zero errors.

### 1.2 Throughput Progression Summary Across Stages
* Baseline: ~350 Mbps (~25,491 pps, 39.23 µs per packet).
* Stage A (Run 16): 389.7 Mbps (~28,382 pps, 35.23 µs per packet). Widened carrier `sendmmsg` to 256 datagrams and added drain outbox accumulation. Retired 0.27 µs per packet of syscall entry overhead.
* Stage B (Run 17): 426.0 Mbps (~31,026 pps, 32.23 µs per packet, burst to ~64,000 pps at 880 Mbps). Replaced scalar Go channel with `toEngineRing`, eliminating 181,549 lock acquisitions/sec and cross-core cache line bouncing.
* Remaining gap to wire speed:
  - Wire speed target (>1,000 Mbps at 1,373 B MTU): 125,000,000 B/s / 1,373 B = 91,041.5 pps.
  - Total per-packet budget at wire speed: 1,000,000 µs / 91,041.5 pps = 10.984 µs.
  - Current Run 17 sustained budget: 32.23 µs per packet (or ~25.77 µs at peak burst).
  - Residual gap to retire: 32.23 - 10.984 = 21.25 µs per packet (or ~14.79 µs from burst).

---

## 2. ANATOMY OF THE RESIDUAL BOTTLENECK

With inter-core Go channel contention eliminated in Stage B and outer socket batching established in Stage A, empirical profiling isolates the residual 14-21 µs bottleneck to per-packet kernel/user transitions and single-packet framing boundaries:

### 2.1 Linux Kernel TUN Single-Packet `read()` Syscall Boundary
* In `android/app/src/main/cpp/winn_tun_bulk.cpp`, `Java_org_winsvpn_app_WinnV3TunBulkRead_readBatch` executes:
  ```cpp
  for (int i = 0; i < maxPackets; i++) {
      uint8_t* slot = slab + static_cast<size_t>(i) * width;
      ssize_t n = read(fd, slot, width);
      ...
  }
  ```
* While wrapped inside a single JNI call from Kotlin, `read(fd, slot, width)` is an individual POSIX syscall into the Linux kernel TUN driver for EVERY packet.
* At 91,041 pps, 91,041 `read()` syscalls per second are executed. In Linux 6.12 on ARM64, each TUN `read()` takes ~2.0 to 4.5 µs in kernel entry, wait queue check, `sk_buff` dequeue, `copy_to_user`, and kernel exit. This consumes 182-410 ms of CPU per second per core.

### 2.2 IPC Frame Serialization Boundary (Kotlin to Go Datapath)
* In `WinnV3Bridge.kt`, `inboundPump` reads from `WinnV3AndroidIpPacketSeam` and writes to `WinnV3PacketBatch`.
* Packets cross from Java/Kotlin user space into `libwinnengine.so` over an IPC channel (Unix domain socket or pipe) where `cmd/winn-datapath/winn3_frame.go` parses frames one by one via `allocPacket(payload)`.
* Every packet carries a 16-byte `WinnFraming.OP_INBOUND` header and requires parsing before being offered to `toEngineRing`.

### 2.3 Wire Packet Sizing & Single-Datagram Crypto Framing
* In `winn_protocol_experimental/winn3/session/driver.go:1980-1994`:
  ```go
  for len(d.data) > 0 {
      p := d.data[0]
      if used+frameHeaderSize+len(p) > budget {
          break
      }
      next, err := core.AppendFrame(plain, core.FrameData, p)
      ...
  }
  ```
* Currently, `budget := d.cfg.maxPayload()` is capped to ~1,373 bytes (`MaxMessageSize = 1402`). Because one 1,373-byte packet plus 3-byte frame header (1,376 bytes) exceeds the 1,373-byte budget, EXACTLY ONE inner IP packet is packed into each Winn v3 wire message.
* Each packet requires:
  1. Separate AEAD encryption (`ChaCha20-Poly1305`).
  2. Separate outer datagram construction.
  3. Separate outer UDP packet traversal through the Linux network stack and Wi-Fi driver.

---

## 3. OPEN ITEMS (OI-1 THROUGH OI-4) FOR ADJUDICATION

### OI-1: Super-Frame Coalescing Architecture & Layer Selection
* **Discovery**: `core.ParseFrames` in `winn3/core/frame.go` ALREADY parses multiple `FrameData` frames from a single decrypted plaintext buffer in a loop:
  ```go
  func parseFrames(out []Frame, b []byte, allocate bool) ([]Frame, error) {
      for len(b) > 0 {
          ...
          out = append(out, Frame{Type: t, Value: b[frameHeaderSize : frameHeaderSize+n : frameHeaderSize+n]})
          b = b[frameHeaderSize+n:]
      }
      return out, nil
  }
  ```
  The protocol wire format ALREADY natively supports multi-packet transport messages without protocol changes.
* **Proposals for Coalescing**:
  - **Mechanism A (Protocol Super-Frames / Multi-Frame Messages)**:
    Allow `driver.go` to pack N inner IP packets (e.g. N = 2 to 4) into a single transport message plaintext if outer MTU or carrier segmentation permits.
  - **Mechanism B (Carrier UDP Generic Segmentation Offload - `UDP_SEGMENT` / GSO)**:
    In `winn3/carrier/udp_batch_unix.go`, utilize Linux `UDP_SEGMENT` socket control messages to send super-buffers (up to 64 KB) containing multiple outer datagrams, offloading segmentation to the Linux kernel/NIC hardware.
  - **Mechanism C (TUN Bulk Aggregation & IPC Optimization)**:
    Optimize the Kotlin TUN read and IPC pipe boundary to eliminate per-packet syscall and copy overhead between Android OS and `libwinnengine.so`.
* **Questions**:
  1. Which mechanism (A, B, C, or combination) provides the highest reduction in per-packet CPU overhead on the Snapdragon 8 Elite?
  2. What is the exact mathematical retirement of CPU time per packet for each option?
  3. Can Mechanism A (packing multiple `FrameData` frames) be used with standard path MTUs, or does it require carrier-level fragmentation / GSO?

### OI-2: Linux Kernel & Android 16 Handset Capabilities Probe
* **Platform**: Retail Samsung Galaxy S26 Ultra (`SM-S948U1`, Linux kernel `6.12.30-android16`, Snapdragon 8 Elite, Wi-Fi 7 MLO).
* **Questions**:
  1. Does Android 16's Linux 6.12 kernel support `UDP_SEGMENT` on non-root Wi-Fi sockets without privilege errors?
  2. Does Android `VpnService` support `IFF_VNET_HDR` or any multi-packet read mechanism on its TUN file descriptor, or is `read()` strictly limited to one IP packet per call by Android framework architecture?
  3. Given that TUN `read()` on Android is single-packet, what is the maximum achievable throughput if TUN `read()` remains 1 packet per syscall? Provide exact arithmetic.

### OI-3: Gateway Ingress Parity & Demux Sizing (<NODE_CANADA_IP>:9111)
* **Gateway components**:
  - `cmd/winn3-gateway/cover_demux.go`: `splitUDP.pumpBatch` reads incoming packets with `recvmmsg`.
  - `cmd/winn3-gateway/forward_linux.go`: `sharedGatewayTun.write` writes packets into `winn3gw0`.
  - `cmd/winn3-gateway/speedtest_ingest.go`: HTTP POST `/speedtest/up`.
* **Questions**:
  1. If client sends multi-frame messages or larger datagrams, does the gateway `demuxReadBufferSize` (currently 2048 bytes) truncate them?
  2. Does the gateway TUN interface `winn3gw0` support receiving multiple frames from a single decrypted message and writing them to TUN descriptors?
  3. What modifications, if any, are required on the Canada production gateway to sustain >1,000 Mbps uplink?

### OI-4: Downlink Freeze Invariant 100% Preservation (Treaty Rounds 35 & 38)
* **Invariant**: Downlink datapath, buffer allocations, and measurement mathematics remain 100% frozen.
* **Questions**:
  1. Verify that all proposed Stage C modifications apply exclusively to the transmit/uplink pipeline (`tx`).
  2. Confirm that `RecvBatch`, `outboundPump`, `toHost`, `fromEngine`, and downlink crypto job pools remain completely untouched.

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
    print("=== ROUND 45 TURN 1 DISPATCH ===", flush=True)
    packet_file = TURN1_DIR / "packet.txt"
    packet_file.write_text(DOCKET_PACKET, encoding="utf-8")
    packet_sha = hashlib.sha256(DOCKET_PACKET.encode("utf-8")).hexdigest()
    print(f"Docket packet written: {len(DOCKET_PACKET)} bytes, sha256: {packet_sha}", flush=True)

    cache = load_cache()
    tasks = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futures_map = {}
        for seat in SEAT_KEYS:
            key = f"r45_turn1_{seat}"
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
                fut = ex.submit(query_openrouter, DOCKET_PACKET, SYSTEM_SEATS[seat])
                futures_map[fut] = (key, seat)

        for fut in concurrent.futures.as_completed(futures_map):
            key, seat = futures_map[fut]
            try:
                result = fut.result()
                update_cache(key, result)
                seat_file_name = f"{seat.replace('claude-opus5', 'opus5')}_turn1.md"
                (TURN1_DIR / seat_file_name).write_text(f"# Turn 1 Submission: {seat}\n\n{result}\n", encoding="utf-8")
                (DOCS_EVIDENCE / f"debate_round45_stage1_{seat.replace('claude-opus5', 'opus5')}.md").write_text(
                    f"# Turn 1 Submission: {seat}\n\n{result}\n", encoding="utf-8"
                )
                print(f"-> [{seat}] completed: {len(result)} bytes", flush=True)
            except Exception as e:
                print(f"-> [{seat}] error: {e}", flush=True)
                raise

    print("=== ROUND 45 TURN 1 DISPATCH COMPLETE ===", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Round 45 Debate Runner")
    parser.add_argument("--stage1", action="store_true", default=True, help="Run Turn 1 dispatch")
    args = parser.parse_args()
    if args.stage1:
        stage1()


if __name__ == "__main__":
    main()
