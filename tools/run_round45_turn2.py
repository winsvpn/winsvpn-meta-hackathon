#!/usr/bin/env python3
"""Round 45 Turn 2: Cross-Examination and Convergence.

Dispatches the Turn 2 packet with all three Turn 1 opening positions
to Gemini 3.8 Flash High (agy) and GPT-5.6 Sol Pro (solpro).
Claude Opus 5 Turn 1 is circulated from receipts.
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
ROUND45_DIR = REPO_ROOT / ".agent" / "debates" / "round45-superframe-coalescing"
TURN1_DIR = ROUND45_DIR / "turn1-opening"
TURN2_DIR = ROUND45_DIR / "turn2-cross-examination"
TURN2_DIR.mkdir(parents=True, exist_ok=True)
RAW_OUTPUT = DOCS_EVIDENCE / "debate_round45_turn2_raw.json"

SEAT_AGY_CWD = pathlib.Path("/tmp/r45_seat_agy_turn2")
SEAT_SOLPRO_CWD = pathlib.Path("/tmp/r45_seat_solpro_turn2")

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
                "X-Title": "Winthos Debate Round 45 Turn 2 Convergence",
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
                    write_receipt("solpro", "turn2", prompt, content, "ok")
                    return clean_text(content)
        except Exception as e:
            print(f"[solpro] attempt {attempt+1} failed: {e}", flush=True)
            time.sleep(min(45, 8 * (attempt + 1)))
    write_receipt("solpro", "turn2", prompt, "", "fail")
    raise RuntimeError("solpro query failed after retries")


def query_agy(prompt: str, stage: str = "turn2") -> str:
    SEAT_AGY_CWD.mkdir(parents=True, exist_ok=True)
    stdin_text = (
        "The complete Round 45 Turn 2 cross-examination packet follows after this line. Read all of it, then "
        "complete the mandate it contains. Reply with your cross-examination steelman, first-principles arithmetic, "
        "exact diffs, and explicit convergence vote on each open item (AGREE or DISAGREE: <one concrete falsifiable reason>).\n\n"
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


SYSTEM_SEATS = {
    "agy": (
        "You are Podium 1 (Gemini 3.8 Flash High) in the Iterative Convergence Debate Protocol (ICDP). "
        "You are participating in Round 45 Turn 2 (Cross-Examination and Convergence) for Android Winn v3 "
        "Uplink Wire-Speed Scaling Stage C. Steelman the peer podiums, evaluate the synthesized open items, "
        "provide first-principles arithmetic, exact surgical code diffs, and cast an explicit convergence vote "
        "on each item (AGREE or DISAGREE: <one concrete falsifiable technical reason>). "
        "Zero em dashes or en dashes as connectors. Ban AI cliches. Restrict bold styling to top-level list keys only."
    ),
    "solpro": (
        "You are Podium 3 (GPT-5.6 Sol Pro) in the Iterative Convergence Debate Protocol (ICDP). "
        "You are participating in Round 45 Turn 2 (Cross-Examination and Convergence) for Android Winn v3 "
        "Uplink Wire-Speed Scaling Stage C. Steelman the peer podiums, evaluate the synthesized open items, "
        "provide first-principles arithmetic, exact surgical code diffs, and cast an explicit convergence vote "
        "on each item (AGREE or DISAGREE: <one concrete falsifiable technical reason>). "
        "Zero em dashes or en dashes as connectors. Ban AI cliches. Restrict bold styling to top-level list keys only."
    ),
}


def build_turn2_packet() -> str:
    agy_t1 = (TURN1_DIR / "agy_turn1.md").read_text(encoding="utf-8")
    opus5_t1 = (TURN1_DIR / "opus5_turn1.md").read_text(encoding="utf-8")
    solpro_t1 = (TURN1_DIR / "solpro_turn1.md").read_text(encoding="utf-8")

    return f"""# MULTI-MODEL DEBATE ROUND 45 TURN 2: CROSS-EXAMINATION & CONVERGENCE

## ARBITER SYNTHESIS OF TURN 1 POSITIONS

All three independent podiums have submitted complete Turn 1 positions. The Arbiter certifies the following unanimous findings from Turn 1:

1. **Rejection of Mechanism A (Super-Datagram Outer Coalescing)**:
   All three podiums independently and unanimously rejected Mechanism A.
   - 2 full 1,373-byte frames in one UDP packet produces a 2,806 to 2,809-byte IP datagram against a 1,500-byte path MTU, triggering fatal IP fragmentation or PMTU blackholing across the 65 ms internet transit to Canada.
   - A multi-frame message >2,048 bytes would be truncated by standard UDP receive buffers without authenticated buffer expansion.
   - Small-frame packing within MaxMessageSize (1,402 bytes) is already implemented in `driver.go:1980-1994` and requires no protocol change.

2. **Resolution of the Single-Packet TUN Read Premise**:
   All three podiums verified through arithmetic that single-packet TUN `read()` is not the binding bottleneck. At 4.5 µs per read, single-core capacity is 222,222 pps (2,441 Mbps), well above the 91,041.5 pps target, as confirmed by the S26 Ultra's demonstrated 1,714.4 Mbps downlink peak across the same JNI/TUN boundary.

3. **Discovery of Carrier Batch Starvation (1.58 Packets per sendmmsg)**:
   In Speedtest Run 17 telemetry, 1,811,929 datagrams were sent across 1,146,349 socket calls: an average of only 1.58 packets per `sendmmsg` call against a 256-wide batch buffer.
   The carrier drain thread woke on every individual push to `toEngineRing` / `toEngineCond.Signal()`, finding only 1 or 2 packets queued and flushing immediately.
   Both Opus 5 and Gemini converged on introducing `txDrainGate` (a bounded coalescing window of lowWater=32 or maxPark=250 µs) in conjunction with `UDP_SEGMENT` / GSO (Mechanism B).

4. **Gateway Ingress Parity and Zero Demux Truncation**:
   Because Mechanism B (UDP_SEGMENT) emits individual MTU-bounded UDP datagrams (<= 1,402 bytes) over the wire, the gateway demux buffer (`demuxReadBufferSize`) requires zero modifications, zero memory slab expansion, and experiences zero truncation.

5. **Downlink Freeze Invariant 100% Preservation**:
   All proposed changes are strictly transmit-side. Downlink datapath, buffers, allocations, and measurement mathematics remain 100% frozen.

---

## ENUMERATED OPEN ITEMS FOR CONVERGENCE VOTE

### OI-1: Transmit Coalescing Architecture & Layer Selection
Reject Mechanism A (packing multiple full-MTU frames into an outer UDP datagram exceeding path MTU 1,500 B).
Adopt Mechanism B (kernel UDP segmentation offload via `UDP_SEGMENT` / GSO) paired with transmit drain gating (`txDrainGate`) to prevent carrier batch starvation and coalesce packets into optimal socket batches.
Preserve the existing small-frame packing loop in `driver.go:1980-1994` without wire-format changes.

### OI-2: Linux Kernel 6.12 Capability and Handset Safety
Single-packet TUN `read()` is not the binding ceiling (theoretical single-reader ceiling is 222,222 pps / 2.44 Gbps at 4.5 µs, corroborated by 1,714 Mbps downlink peak).
`UDP_SEGMENT` (SOL_UDP=17, UDP_SEGMENT=103) is supported on Linux 6.12.30 (Android 16), but must be safely probed at socket initialization with automatic, zero-overhead runtime fallback to the existing 256-wide `sendmmsg` batch writer on any kernel rejection or unsupported network interface.

### OI-3: Gateway Demux Sizing and Zero-Truncation Invariant
Under Mechanism B (UDP_SEGMENT), gateway demux sizing remains frozen and requires zero modifications, as every emitted datagram remains at or below 1,402 bytes, causing zero datagram truncation and zero memory slab expansion.

### OI-4: Downlink Freeze Invariant 100% Preservation
All Stage C modifications are strictly transmit-side (uplink pipeline, `toEngineRing` / `txDrainGate`, carrier GSO / `sendmmsg` batching).
The downlink datapath (`RecvBatch`, `outboundPump`, `toHost`, `fromEngine`, downlink crypto worker pools, downlink buffer allocations, and measurement mathematics) remains 100% frozen in strict compliance with Treaty Rounds 35, 38, 43, and 44.

---

## FULL TURN 1 SUBMISSIONS CIRCULATED FOR CROSS-EXAMINATION

### PODIUM 1 (Gemini 3.8 Flash High) TURN 1 SUBMISSION:
```markdown
{agy_t1}
```

---

### PODIUM 2 (Claude Opus 5) TURN 1 SUBMISSION:
```markdown
{opus5_t1}
```

---

### PODIUM 3 (GPT-5.6 Sol Pro) TURN 1 SUBMISSION:
```markdown
{solpro_t1}
```

---

## TURN 2 MANDATE FOR EACH PODIUM

1. **Peer Steelman**:
   Present the strongest version of why the other podiums reasoned as they did. Name the single strongest point in each peer view. State whether that reasoning changes your own position and why.
2. **Convergence Vote**:
   Cast an explicit vote on each enumerated open item (OI-1, OI-2, OI-3, OI-4):
   Format: `AGREE` or `DISAGREE: <one concrete falsifiable reason>`.
3. **Ratified Code Implementation**:
   Provide the complete, source-complete Go implementation for the ratified Stage C components (`udp_gso_linux.go`, `tx_drain_gate.go` or integration into `winn3_to_engine_ring.go` / `winn3_frame_device.go`).
"""


def stage2():
    packet = build_turn2_packet()
    packet_file = TURN2_DIR / "packet.txt"
    packet_file.write_text(packet, encoding="utf-8")
    print(f"Turn 2 packet written: {len(packet)} bytes, sha256: {hashlib.sha256(packet.encode('utf-8')).hexdigest()}", flush=True)

    cache = load_cache()
    active_seats = ["agy", "solpro"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        futures_map = {}
        for seat in active_seats:
            key = f"r45_turn2_{seat}"
            if cache.get(key):
                print(f"[{seat}] using cached turn 2 response", flush=True)
                continue
            if seat == "agy":
                print(f"[{seat}] dispatching Gemini 3.8 Flash High (Turn 2 cross-examination)...", flush=True)
                fut = ex.submit(query_agy, packet, "turn2")
                futures_map[fut] = (key, seat)
            else:
                print(f"[{seat}] dispatching GPT-5.6 Sol Pro (Turn 2 cross-examination flex)...", flush=True)
                fut = ex.submit(query_openrouter, packet, SYSTEM_SEATS[seat])
                futures_map[fut] = (key, seat)

        for fut in concurrent.futures.as_completed(futures_map):
            key, seat = futures_map[fut]
            try:
                result = fut.result()
                update_cache(key, result)
                seat_file_name = f"{seat}_turn2.md"
                (TURN2_DIR / seat_file_name).write_text(f"# Turn 2 Submission: {seat}\n\n{result}\n", encoding="utf-8")
                (DOCS_EVIDENCE / f"debate_round45_stage2_{seat}.md").write_text(
                    f"# Turn 2 Submission: {seat}\n\n{result}\n", encoding="utf-8"
                )
                print(f"-> [{seat}] completed: {len(result)} bytes", flush=True)
            except Exception as e:
                print(f"-> [{seat}] error: {e}", flush=True)
                raise

    print("=== ROUND 45 TURN 2 DISPATCH COMPLETE ===", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Round 45 Turn 2 Runner")
    parser.add_argument("--stage2", action="store_true", default=True, help="Run Turn 2 cross-examination")
    args = parser.parse_args()
    if args.stage2:
        stage2()


if __name__ == "__main__":
    main()
