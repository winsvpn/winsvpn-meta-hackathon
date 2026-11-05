#!/usr/bin/env python3
"""
Winthos Presidential Council Docket Round 3:
Analyzing Empirical Plateau at 215 Mbps on Physical S26 Ultra vs 1,284 Mbps Download
"""

import json
import os
import pathlib
import ssl
import sys
import time
import urllib.request

REPO_ROOT = pathlib.Path("/Users/owner/xprize/winsvpnv3").resolve()
DOCS_EVIDENCE = REPO_ROOT / "docs" / "evidence"
DOCS_EVIDENCE.mkdir(parents=True, exist_ok=True)
OUTPUT_FILE = DOCS_EVIDENCE / "tripartite_round3_empirical_bottleneck.json"

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
    # Strictly remove em dashes and en dashes
    return text.replace("\u2014", ": ").replace("\u2013", "-")

def query_model(model_name: str, prompt: str, system_role: str, provider_order=None) -> str:
    key = get_openrouter_key()
    ctx = ssl._create_unverified_context()
    payload = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": system_role},
            {"role": "user", "content": prompt},
        ],
    }
    if provider_order:
        payload["provider"] = {"order": provider_order, "allow_fallbacks": True}
    if "sol-pro" in model_name:
        payload["reasoning"] = {"effort": "high"}
    elif "glm" in model_name:
        payload["reasoning"] = {"effort": "high"}

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=data,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://winsvpn.org",
            "X-Title": "Winthos Presidential Council Round 3",
        },
    )
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=300) as resp:
                res = json.loads(resp.read().decode("utf-8"))
                content = res["choices"][0]["message"]["content"]
                return clean_text(content)
        except Exception as e:
            print(f"[{model_name}] Attempt {attempt+1} failed: {e}", file=sys.stderr, flush=True)
            time.sleep(4 * (attempt + 1))
    raise RuntimeError(f"Failed to query {model_name}")

DOCKET_PROMPT = """
TRI-PARTITE PRESIDENTIAL COUNCIL DOCKET: ROUND 3
SUBJECT: Empirical Upload Saturation Plateau at 215 Mbps on Physical Samsung Galaxy S26 Ultra (SM-S948U1) vs 1,284 Mbps Download Wire Speed over 2000 Mbps Symmetrical Fiber to aicore Gateway (192.168.4.36:9111).

NEW EMPIRICAL TELEMETRY AND BENCHMARK RESULTS (Physical S26 Ultra, Snapdragon 8 Gen 5 / Elite):
1. Ookla Speedtest Benchmark with Treaty v2.0 (Option A Frame Device Aggregation in ReadBatch):
   - Download: 1,284 Mbps (2,078,886 rx packets received in 2,061,951 messages = 1.008 packets/message).
   - Upload: 126 Mbps (46,177 tx packets sent in 46,160 messages = 1.000 packets/message).
   - Latency: 15 ms idle ping, 1 ms jitter. Underlay ping is 12 ms. Latency is completely preserved.
   - Status counters: tx_dropped_closed: 3, rx_dropped_closed: 0, tx_dropped_invalid: 15, tx_dropped_sink: 0, tx_dropped_oversize: 0. Zero drops!

2. Direct Controlled Upload to aicore Gateway Sink (10.10.0.1:5203, eliminating internet WAN variance):
   - 1 stream: 60.86 Mbps (7.6 MB/s).
   - 4 concurrent streams: 212.69 Mbps.
   - 8 concurrent streams: 215.74 Mbps. (Identical ceiling at ~215 Mbps).
   - Gateway status: 0 UDP rcvbuf errors, 0 dropped packets, FQ qdisc with qlen 10000, 4 multiqueues, MTU 1373.
   - CPU profiling on S26 Ultra during 8-stream 215 Mbps upload:
     CPU is 719% IDLE (out of 800% on 8 cores).
     libwinnengine.so: 3.2% CPU.
     org.winsvpn.app.debug (Kotlin VpnService): 6.4% CPU.
     All worker threads (TunRead, Inbound, Outbound, Go carrier) spend >90% of their time in kernel wait channels.

3. Complete Datapath Anatomy Comparison:
   A. Download Path (1,284 Mbps, 133,000 pkts/sec):
      - Gateway reads tun -> encrypts -> sendmmsg (64 pkts).
      - S26 Ultra: recvmmsg in readLoop -> ChaCha20 decrypts 64 pkts -> writes to toHost channel.
      - winn3FrameServer.pump: reads toHost -> writes to buffered AF_UNIX stream socket (512 KB buffer).
      - Kotlin WinsVPN-WinnV3-Outbound: batchTransport.readBatch(batch) reads up to 256 packets in ONE syscall -> batchedSeam.writeIncomingBatch writes to tun device.
      - Result: 1,284 Mbps wire speed.

   B. Upload Path (Capped at 215 Mbps, ~19,000 pkts/sec):
      - Android kernel tun delivers packet to Kotlin.
      - WinnV3AndroidTun.kt runBurstReader():
        Calls device.readNonBlocking(scratchBuffers[batchCount]).
        Because Linux TCP stack paces packets, packet 0 succeeds, packet 1 immediately returns EAGAIN.
        The loop breaks on kernelEmpty=true after 1 packet!
        Enqueues 1 packet into slab, notifies InboundPump.
      - InboundPump wakes up:
        Takes 1 packet from slab, writes 1 packet (with 16-byte WNN3 header) to LocalSocket, and calls output.flush()!
      - Go engine winn3_frame.go:
        Reads 1 frame from AF_UNIX stream socket.
        Calls device.offer(payload), which puts 1 packet into d.toEngine channel.
      - tun.Tunnel.pumpOutboundBatch:
        Calls bDev.ReadBatch(bufs).
        Currently in winn3_frame_device.go:
        ReadBatch copies packet 0 (1373 bytes).
        shouldFlushReadBatch(1373, 1373, 1) returns false.
        arms readBatchTimer for 1000 us (1 ms).
        Waits on select { case pkt := <-d.toEngine: ... case <-deadlineC: ... }.
        If no packets arrive within 1ms, it flushes 1 packet.
        Even when multi-stream is running, every batch pays this or gets flushed after 1-2 packets.
      - driver.Loop.drain:
        Calls l.sess.PollBatchInto.
        In pollDataBatch: budget is maxPayload() = 1376 bytes.
        Since each IP packet is 1373 bytes, 1373 + 3 = 1376. A second packet CANNOT fit inside 1376 bytes.
        So pollDataBatch creates N separate BatchMsg structures (each containing 1 inner packet).
        Calls batchCarrier.SendBatch(l.writeBatchMsgs[:count]), which executes SYS_SENDMMSG with N datagrams.

4. Core Mathematical and Architectural Questions for the Council:
   Q1: Why is the upload capped at 215 Mbps across 4 and 8 streams when CPU is 719% idle and physical Wi-Fi 7 PHY is 2,400 Mbps?
   Q2: Is the 1000us timer in ReadBatch actually acting as a 1ms stall penalty on TCP congestion window and ACK clocking, throttling the pipeline?
   Q3: In Kotlin WinnV3AndroidTun.kt, is the immediate break on EAGAIN in runBurstReader forcing single-packet IPC writes to the Go engine over LocalSocket? If so, how should Kotlin burst reading or IPC buffering be structured?
   Q4: What is the exact, ratified surgical implementation to unlock 800 to 1,200+ Mbps upload speed matching download?

MANDATE & CONSTRAINTS:
- High burstiness: mix punchy decisive statements with compound analytical proofs.
- Strictly ZERO em dashes or en dashes. Use colons, commas, periods, or parentheses.
- Ban AI cliches: delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary.
- Provide exact code diffs and configuration changes.
"""

def main():
    print("=== Submitting Docket Round 3 to Presidential Council ===")
    
    sys_glm = (
        "You are serving as Podium 1 (GLM 5.3 Flash, Max Thinking) under the Winthos Presidential Council Protocol. "
        "Adhere strictly to: high burstiness, zero em dashes or en dashes (use colons, commas, periods, parentheses), "
        "zero AI cliches (delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary). "
        "Deliver complete mathematical proofs, exact bottleneck identification, and verified code diffs."
    )
    
    sys_sol = (
        "You are serving as Podium 2 (GPT-5.6 Sol Pro, Extra High Thinking) under the Winthos Presidential Council Protocol. "
        "Adhere strictly to: high burstiness, zero em dashes or en dashes (use colons, commas, periods, parentheses), "
        "zero AI cliches (delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary). "
        "Deliver complete mathematical proofs, exact bottleneck identification, and verified code diffs."
    )

    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "round": 3
    }

    print("[1/2] Consulting Podium 1: GLM 5.3 Flash (BaseTen fp8)...", flush=True)
    results["glm_5_3_flash"] = query_model("z-ai/glm-5.3-flash", DOCKET_PROMPT, sys_glm, ["BaseTen"])
    print(f"-> GLM 5.3 Flash response captured ({len(results['glm_5_3_flash'])} bytes)\n")

    print("[2/2] Consulting Podium 2: GPT-5.6 Sol Pro (OpenAI flex)...", flush=True)
    results["gpt_5_6_sol_pro"] = query_model("openai/gpt-5.6-sol-pro", DOCKET_PROMPT, sys_sol, ["OpenAI", "Azure"])
    print(f"-> GPT-5.6 Sol Pro response captured ({len(results['gpt_5_6_sol_pro'])} bytes)\n")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"Deliberations successfully saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
