#!/usr/bin/env python3
"""Round 46 Turn 2: Cross-Examination and Convergence.

Dispatches the Turn 2 packet with all three Turn 1 opening positions
to Gemini 3.8 Flash High (agy), Claude Opus 5 (claude/openrouter fallback),
and GPT-5.6 Sol Pro (solpro).
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
TURN2_DIR = ROUND46_DIR / "turn2-cross-examination"
TURN2_DIR.mkdir(parents=True, exist_ok=True)
RAW_OUTPUT = DOCS_EVIDENCE / "debate_round46_turn2_raw.json"

SEAT_AGY_CWD = pathlib.Path("/tmp/r46_seat_agy_turn2")
SEAT_CLAUDE_CWD = pathlib.Path("/tmp/r46_seat_claude_turn2")

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
                "X-Title": "Winthos Debate Round 46 Turn 2 Convergence",
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
                    write_receipt(seat, "turn2", prompt, content, "ok")
                    return clean_text(content)
        except Exception as e:
            print(f"[{seat}] attempt {attempt+1} failed: {e}", flush=True)
            time.sleep(min(45, 8 * (attempt + 1)))
    write_receipt(seat, "turn2", prompt, "", "fail")
    raise RuntimeError(f"{seat} turn 2 query failed after retries")


def query_agy(prompt: str, stage: str = "turn2") -> str:
    SEAT_AGY_CWD.mkdir(parents=True, exist_ok=True)
    stdin_text = (
        "The complete Round 46 Turn 2 debate packet follows after this line. Read all of it, then "
        "complete the mandate it contains. Reply with your steelmanning, convergence verdict, "
        "first-principles arithmetic, and exact diffs only.\n\n"
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


def query_claude(prompt: str, stage: str = "turn2") -> str:
    SEAT_CLAUDE_CWD.mkdir(parents=True, exist_ok=True)
    stdin_text = (
        "The complete Round 46 Turn 2 debate packet follows after this line. Read all of it, then "
        "complete the mandate it contains. Do not use any tools. Reply with your "
        "steelmanning, convergence verdict, first-principles arithmetic, and exact diffs only.\n\n" + prompt
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
        "You are evaluating Round 46 Turn 2 Cross-Examination for Android Winn Protocol v3 Uplink Wire-Speed "
        "Scaling Stage D. Steelman the peer podiums, evaluate the synthesized open items, provide first-principles "
        "arithmetic, exact surgical code diffs, and cast an explicit convergence vote on each item (AGREE or "
        "DISAGREE: <one concrete falsifiable technical reason>). "
        "Zero em dashes or en dashes as connectors. Ban AI cliches. Restrict bold styling to top-level list keys only."
    ),
    "claude-opus5": (
        "You are Podium 2 (Claude Opus 5) in the Iterative Convergence Debate Protocol (ICDP). "
        "You are evaluating Round 46 Turn 2 Cross-Examination for Android Winn Protocol v3 Uplink Wire-Speed "
        "Scaling Stage D. Steelman the peer podiums, evaluate the synthesized open items, provide first-principles "
        "arithmetic, exact surgical code diffs, and cast an explicit convergence vote on each item (AGREE or "
        "DISAGREE: <one concrete falsifiable technical reason>). "
        "Zero em dashes or en dashes as connectors. Ban AI cliches. Restrict bold styling to top-level list keys only."
    ),
    "solpro": (
        "You are Podium 3 (GPT-5.6 Sol Pro) in the Iterative Convergence Debate Protocol (ICDP). "
        "You are evaluating Round 46 Turn 2 Cross-Examination for Android Winn Protocol v3 Uplink Wire-Speed "
        "Scaling Stage D. Steelman the peer podiums, evaluate the synthesized open items, provide first-principles "
        "arithmetic, exact surgical code diffs, and cast an explicit convergence vote on each item (AGREE or "
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


def build_turn2_packet() -> str:
    agy_t1 = (TURN1_DIR / "agy_turn1.md").read_text(encoding="utf-8")
    opus5_t1 = (TURN1_DIR / "opus5_turn1.md").read_text(encoding="utf-8")
    solpro_t1 = (TURN1_DIR / "solpro_turn1.md").read_text(encoding="utf-8")

    return f"""# MULTI-MODEL DEBATE ROUND 46 TURN 2: CROSS-EXAMINATION & CONVERGENCE

## ARBITER SYNTHESIS OF TURN 1 POSITIONS

All three independent podiums have submitted complete Turn 1 positions. The Arbiter certifies the following unanimous findings from Turn 1:

1. **Bandwidth-Delay Product (BDP) Clamping Mathematical Proof (OI-1)**:
   All three podiums independently converged on the identical BDP arithmetic:
   - At 1,000 Mbps line rate and 65 ms RTT to the Canada production gateway, total in-flight data must reach 8,125,000 bytes (7.7485 MiB).
   - Across the 32 parallel upload worker sockets in `MainActivity.kt`, each stream requires 253,906.25 bytes (~248 KiB) in flight.
   - Handset worker sockets currently create bare `java.net.Socket()` instances without setting `socket.sendBufferSize`.
   - On Android virtual interfaces (`tun0`), the unconfigured initial send buffer and autotuning clamp in-flight unacknowledged data to ~96 to 101 KiB per stream, capping each stream at ~11.8 to 12.5 Mbps (101,000 * 8 / 0.065 = ~12.4 Mbps).
   - 32 streams at ~12 Mbps aggregate to 32 * 12 = 384 Mbps, matching the empirical 366-401 Mbps plateau in Run 18 with 98.4% precision.
   - Setting `socket.sendBufferSize = 1048576` (1 MiB) per stream provides a 4.13x BDP headroom ratio (1,048,576 / 253,906 = 4.13), unlocking up to 4.1 Gbps aggregate window ceiling.
   - Furthermore, all podiums agree that `SO_RCVBUF` should NOT be hardcoded on the gateway listener in `speedtest_ingest.go`, because doing so locks the receive window and disables Linux kernel dynamic autotuning (`tcp_rmem` max 6-16 MiB).

2. **Resolution of TUN Handover vs Downlink Freeze Invariant (OI-2)**:
   - While SCM_RIGHTS TUN descriptor handover to the Go engine is conceptually desirable, agy and Sol Pro proved that attempting it in Stage D risks breaking the Downlink Freeze Invariant because downlink `tun0` writes are executed in Kotlin by `outboundPump` / `WinnV3AndroidTunDevice.writeIncomingBatch`.
   - Transferring `tun0` ownership to Go would require either an atomic descriptor hot-swap protocol during staged Android `VpnService` promotion (bootstrap fd=84 swapped to promoted fd=102) or redirecting downlink writes to Go.
   - Empirical inspection of `/proc/net/dev` on the physical handset confirms zero packet drops on `tun1` (3,942,378 rx packets, 1,725,802 tx packets, 0 drops).
   - Consensus: Preserve `LocalSocket` (`AF_UNIX`) in Stage D to preserve 100% stability and zero regression to the Downlink Freeze Invariant.

3. **Transmit Drain Gating Threshold Recalibration (OI-3)**:
   - All podiums confirmed that at 1,000 Mbps line rate, accumulating 32 packets takes 351.49 µs under a smooth arrival profile, which exceeds the 250 µs timer parking deadline (`maxPark`).
   - At 400 Mbps, accumulating 32 packets takes 878.72 µs.
   - Consequently, the reader was timing out on the 250 µs timer with only ~2.4 packets accumulated, explaining the 2.41 batch ratio in Run 18.
   - Consensus: Recalibrate `lowWater` from 32 to 16 packets (16 * 1,373 = 21,968 bytes). At 1 Gbps, 16 packets accumulate in 175.74 µs, safely ahead of the 250 µs deadline.
   - Retain `maxPark = 250 µs` to prevent packet starvation on sparse traffic, while preserving signaling on empty-to-nonempty transition or crossing `lowWater`.
   - In `winn3_frame.go:373`, ensure `flushInboundBatch` immediately empties the batch into `toEngineRing` whenever the Unix socket buffer drains.

4. **Downlink Freeze Invariant 100% Preservation (OI-4)**:
   - All changes apply strictly to the transmit/uplink path (`MainActivity.kt` upload worker sockets, `toEngineRing.go` lowWater constant, `winn3_frame.go` inbound flush).
   - Downlink datapath, buffers, allocations, and measurement mathematics remain 100% frozen.

---

## ENUMERATED OPEN ITEMS FOR CONVERGENCE VOTE

### OI-1: Handset TCP Sockets & Ingest Server BDP Window Scaling
* Set `socket.sendBufferSize = 1048576` (1 MiB) on each of the 32 upload worker sockets in `MainActivity.kt:1530` before `socket.connect(...)`.
* Preserve Linux TCP autotuning on the Canada gateway ingest listener in `speedtest_ingest.go` without hardcoding `SO_RCVBUF`.
* Confirm BDP arithmetic: 1,000 Mbps at 65 ms RTT requires 8.125 MB total in-flight; 32 streams require 253.9 KB each; 1 MiB send buffer provides 4.13x headroom.

### OI-2: Ingress Pipeline Architecture & IPC Preservation
* Retain `LocalSocket` (`AF_UNIX`) stream transport in Stage D, preserving the existing Kotlin `outboundPump` and downlink `tun0` write path in strict compliance with the Downlink Freeze Invariant.
* Defer SCM_RIGHTS TUN descriptor handover to Stage E after formal promotion barrier and atomic descriptor hot-swap protocols are designed.
* Add immediate `flushInboundBatch` in `cmd/winn-datapath/winn3_frame.go` when the Unix socket input buffer is empty.

### OI-3: Transmit Drain Gating (txDrainGate) Parameter Calibration
* Recalibrate `lowWater = 16` (lowered from 32) in `cmd/winn-datapath/winn3_to_engine_ring.go`.
* Retain `maxPark = 250 * time.Microsecond`.
* Retain signaling condition: `if oldCount == 0 || (oldCount < r.lowWater && newCount >= r.lowWater) {{ r.signalNotify() }}`.

### OI-4: Downlink Freeze Invariant 100% Preservation
* All Stage D modifications are strictly confined to the upload/transmit pipeline (`MainActivity.kt`, `winn3_to_engine_ring.go`, `winn3_frame.go`).
* `RecvBatch`, `outboundPump`, `toHost`, `fromEngine`, downlink crypto workers, and measurement mathematics remain 100% frozen in strict compliance with Treaty Rounds 35, 38, 43, 44, and 45.

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

## MANDATE FOR TURN 2
1. Steelman the peer podiums: present the strongest technical points made by the other two podiums.
2. Review the Arbiter's synthesized Open Items (OI-1 through OI-4).
3. Cast an explicit convergence vote on each item:
   - Vote format: `AGREE` or `DISAGREE: <one concrete falsifiable technical reason>`.
4. Rules: Strictly zero em dashes (U+2014) or en dashes (U+2013) as connectors. Strictly zero AI cliches. Restrict bold styling to top-level list keys only.
"""


def stage2():
    print("=== ROUND 46 TURN 2 DISPATCH ===", flush=True)
    t2_packet = build_turn2_packet()
    packet_file = TURN2_DIR / "packet.txt"
    packet_file.write_text(t2_packet, encoding="utf-8")
    packet_sha = hashlib.sha256(t2_packet.encode("utf-8")).hexdigest()
    print(f"Turn 2 packet written: {len(t2_packet)} bytes, sha256: {packet_sha}", flush=True)

    cache = load_cache()

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futures_map = {}
        for seat in SEAT_KEYS:
            key = f"r46_turn2_{seat}"
            if cache.get(key):
                print(f"[{seat}] using cached turn 2 response", flush=True)
                continue
            if seat == "agy":
                print(f"[{seat}] dispatching Gemini 3.8 Flash High (Turn 2)...", flush=True)
                fut = ex.submit(query_agy, t2_packet, "turn2")
                futures_map[fut] = (key, seat)
            elif seat == "claude-opus5":
                print(f"[{seat}] dispatching Claude Opus 5 (Turn 2 high effort)...", flush=True)
                fut = ex.submit(query_claude, t2_packet, "turn2")
                futures_map[fut] = (key, seat)
            else:
                print(f"[{seat}] dispatching GPT-5.6 Sol Pro (Turn 2 high effort flex)...", flush=True)
                fut = ex.submit(query_openrouter, t2_packet, SYSTEM_SEATS[seat], seat=seat)
                futures_map[fut] = (key, seat)

        for fut in concurrent.futures.as_completed(futures_map):
            key, seat = futures_map[fut]
            try:
                result = fut.result()
                update_cache(key, result)
                seat_file_name = f"{seat.replace('claude-opus5', 'opus5')}_turn2.md"
                (TURN2_DIR / seat_file_name).write_text(f"# Turn 2 Submission: {seat}\n\n{result}\n", encoding="utf-8")
                (DOCS_EVIDENCE / f"debate_round46_stage2_{seat.replace('claude-opus5', 'opus5')}.md").write_text(
                    f"# Turn 2 Submission: {seat}\n\n{result}\n", encoding="utf-8"
                )
                print(f"-> [{seat}] completed: {len(result)} bytes", flush=True)
            except Exception as e:
                print(f"-> [{seat}] error: {e}", flush=True)
                raise

    print("=== ROUND 46 TURN 2 DISPATCH COMPLETE ===", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Round 46 Turn 2 Runner")
    parser.add_argument("--stage2", action="store_true", default=True, help="Run Turn 2 dispatch")
    args = parser.parse_args()
    if args.stage2:
        stage2()


if __name__ == "__main__":
    main()
