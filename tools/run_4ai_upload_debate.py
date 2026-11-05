#!/usr/bin/env python3
"""
Winthos Permanent Four-AI Presidential Debate Protocol (Upload Wire-Speed Optimization)
Target: Symmetrical Multi-Gbps Wire-Speed (Upload ~2000 Mbps matching Download) on 2 Gbps Fiber
Hardware: Samsung Galaxy S26 Ultra (SM-S948U1, REDACTED_SERIAL) to aicore gateway (192.168.4.36:9111)

Podiums:
  Podium 1: Antigravity (Council Chair, Gemini 3.8 Flash High Thinking)
  Podium 2: GPT-5.6 Sol Pro (OpenAI, OpenRouter openai/gpt-5.6-sol-pro)
  Podium 3: Claude Opus 5 (Anthropic, Claude Code CLI --model opus --effort high)
  Podium 4: Claude Fable 5.1 (Anthropic, Claude Code CLI --model claude-fable-5-1 --effort high)
"""

import hashlib
import json
import os
import pathlib
import ssl
import subprocess
import sys
import time
import urllib.request

REPO_ROOT = pathlib.Path("/Users/owner/xprize/winsvpnv3").resolve()
DOCS_EVIDENCE = REPO_ROOT / "docs" / "evidence"
DOCS_EVIDENCE.mkdir(parents=True, exist_ok=True)


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
    raise RuntimeError("OpenRouter API key not found in environment or ~/.local/share/opencode/auth.json")


def clean_text(text: str) -> str:
    return text.replace("\u2014", ": ").replace("\u2013", "-")


def query_openrouter_model(model_name: str, prompt: str, system_role: str, max_tokens: int = 4000) -> str:
    key = get_openrouter_key()
    ctx = ssl._create_unverified_context()
    payload = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": system_role},
            {"role": "user", "content": prompt},
        ],
    }
    if "sol-pro" in model_name:
        payload["provider"] = {"order": ["OpenAI", "Azure"], "allow_fallbacks": True}
        payload["reasoning"] = {"effort": "high"}
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=data,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://winsvpn.org",
            "X-Title": "Winthos Presidential Debate Upload Asymmetry Audit",
        },
    )
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=300) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                choice = res_data["choices"][0]["message"]
                content = choice.get("content", "").strip()
                return clean_text(content)
        except Exception as e:
            print(f"[{model_name}] Attempt {attempt+1} failed: {e}", file=sys.stderr, flush=True)
            time.sleep(5 * (attempt + 1))
    raise RuntimeError(f"OpenRouter query for {model_name} failed after 5 attempts")


def query_claude_model(model_name: str, prompt: str, system_role: str) -> str:
    key = get_openrouter_key()
    env = os.environ.copy()
    env["ANTHROPIC_BASE_URL"] = "https://openrouter.ai/api"
    env["ANTHROPIC_AUTH_TOKEN"] = key
    env["ANTHROPIC_API_KEY"] = ""

    cmd = [
        "/Users/owner/.local/bin/claude",
        "--bare",
        "--model",
        model_name,
        "--effort",
        "high",
        "-p",
        f"{system_role}\n\nUSER PROMPT:\n{prompt}",
    ]
    for attempt in range(3):
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT),
                timeout=240,
                env=env,
            )
            if proc.returncode == 0:
                return clean_text(proc.stdout.strip())
            print(
                f"[{model_name}] Return code {proc.returncode}: {proc.stderr}",
                file=sys.stderr,
                flush=True,
            )
            time.sleep(5)
        except Exception as e:
            print(f"[{model_name}] Attempt {attempt+1} failed: {e}", file=sys.stderr, flush=True)
            time.sleep(5)
    raise RuntimeError(f"Claude query for {model_name} failed after 3 attempts")


DEBATE_TOPIC = """
DELIBERATION TOPIC:
Resolve the severe upload asymmetry (67.2 Mbps upload vs 1,103 Mbps download) on Winn Protocol v3 running over a 2000 Mbps symmetrical fiber connection between a Samsung Galaxy S26 Ultra (SM-S948U1, serial REDACTED_SERIAL, Wi-Fi 7) and the aicore gateway (192.168.4.36:9111, AMD Ryzen 7 PRO 8845HS, 92 GB RAM).

EMPIRICAL TELEMETRY AND CODEPATH FINDINGS:
1. Physical Network & Hardware:
   - S26 Ultra Wi-Fi 7 PHY link: >2,400 Mbps.
   - Symmetrical WAN fiber line: 2,000 Mbps upload, 2,000 Mbps download.
   - Ping S26 Ultra to aicore tunnel IP (10.10.0.1): 4 packets, 0% loss, avg RTT 20.8 ms.
   - Direct raw TCP stream over tunnel: 100 MB in 5.04s (160 Mbps single stream).
   - Gateway status: 2,335,036 downlink packets delivered, 702,069 uplink packets received, 0 dropped, 0 UDP rcvbuf errors.
   - Client status: 2,310,027 rx packets, 719,344 tx packets, 0 tx dropped sink, 0 send failed.

2. Go Engine (winn_protocol_experimental/cmd/winn-datapath):
   - In winn3_frame.go outerSocket(): The client adopts the Java VpnService UDP socket descriptor via SCM_RIGHTS and calls net.FilePacketConn(file). However, it NEVER calls conn.SetWriteBuffer() or conn.SetReadBuffer(). On Android, Linux sets wmem_default to 229,376 bytes (224 KB). 224 KB holds ~150 packets. At 1+ Gbps line rates, bursts quickly exhaust this 224 KB buffer, causing ENOBUFS socket backpressure and collapsing the TCP congestion window. Sysctl net.core.wmem_max allows up to 8,388,608 bytes (8 MB), so calling SetWriteBuffer(8*1024*1024) expands buffer headroom by 36.5x.
   - In winn3_frame.go handleInbound(): s.mu.Lock() is acquired and released for EVERY incoming packet just to read s.device. At 100,000 pps, this is 100,000 mutex lock acquisitions/sec on the mobile CPU.
   - In winn3_frame_device.go ReadBatch(): lengths := make([]int, 0, len(bufs)) is allocated on the heap on every single batch read, creating garbage collector churn.
   - In winn3/tun/tun.go: pumpOutboundBatch batchSize is 64. Downlink uses 128.

3. Android VpnService Layer (android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt):
   - In runBurstReader(): Each packet inside while (drained < MAX_BURST_PACKETS) enters and exits synchronized(state). This creates hundreds of thousands of JVM monitor acquisitions per second.
   - In WinnV3AndroidIpPacketSeam: Default queueDepth is 4096. winn3FrameQueueDepth in Go is 8192.

4. Gateway Linux Stack (aicore, 192.168.4.36):
   - iptables mangle table on aicore contains:
     -A WINVPN-CORE-MANGLE -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1241:65535 -j TCPMSS --set-mss 1240
     This unconditionally clamps ALL forwarded TCP connections to MSS 1240 bytes. On winn3gw0 (MTU 1373), the natural MSS is 1333 bytes. Dynamic clamping (--clamp-mss-to-pmtu) on FORWARD for winn3gw0 prevents fragmentation while allowing full 1333 byte TCP MSS.
   - winn3gw0 txqueuelen is 2048. Raising txqueuelen to 8192 prevents egress queue overflow.

MANDATE:
Deliver your independent analysis and specific code, config, and parameter determinations.
Rules:
1. High burstiness: mix short decisive statements with analytical reasoning.
2. Strictly ZERO em dashes or en dashes. Use colons, commas, periods, or parentheses.
3. Ban AI cliches: delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary.
4. Provide complete, exact code diffs and configuration commands.
"""


def main():
    print("=== STARTING WINTHOS FOUR-AI LIVE PRESIDENTIAL DEBATE ROUND ===")
    print("Target: Symmetrical Multi-Gbps Wire-Speed on 2 Gbps Fiber")
    print("Podiums: Antigravity, GPT-5.6 Sol Pro, Claude Opus 5, Fable 5.1\n")

    system_sol = (
        "You are serving as Podium 2 (GPT-5.6 Sol Pro) under the Winthos Permanent "
        "Presidential Debate Protocol v4.0. Adhere strictly to the cadence mandate: "
        "high burstiness, alternating short decisive assertions with compound analytical proofs, "
        "strictly ZERO em dashes or en dashes (use periods, commas, colons, or parentheses instead), "
        "ban all AI cliches (delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary). "
        "Every claim must be backed by empirical proof or mathematical derivations."
    )

    system_opus = (
        "You are serving as Podium 3 (Claude Opus 5) under the Winthos Permanent "
        "Presidential Debate Protocol v4.0. Adhere strictly to the cadence mandate: "
        "high burstiness, alternating short decisive assertions with compound analytical proofs, "
        "strictly ZERO em dashes or en dashes (use periods, commas, colons, or parentheses instead), "
        "ban all AI cliches (delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary). "
        "Provide direct code diffs, exact sysctls, and socket configurations."
    )

    system_fable = (
        "You are serving as Podium 4 (Claude Fable 5.1) under the Winthos Permanent "
        "Presidential Debate Protocol v4.0. Adhere strictly to the cadence mandate: "
        "high burstiness, alternating short decisive assertions with compound analytical proofs, "
        "strictly ZERO em dashes or en dashes (use periods, commas, colons, or parentheses instead), "
        "ban all AI cliches (delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary). "
        "Deliver rigorous kernel datapath and VpnService analysis."
    )

    output_path = DOCS_EVIDENCE / "debate_upload_asymmetry_4ai_raw.json"
    cache = {}
    if output_path.exists():
        try:
            with open(output_path, "r", encoding="utf-8") as f:
                cache = json.load(f)
        except Exception:
            cache = {}

    if "sol_pro" not in cache or not cache["sol_pro"]:
        print("[1/3] Querying Podium 2: GPT-5.6 Sol Pro (OpenAI)...", flush=True)
        cache["sol_pro"] = query_openrouter_model("openai/gpt-5.6-sol-pro", DEBATE_TOPIC, system_sol)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
        print(f"-> Sol Pro response captured ({len(cache['sol_pro'])} bytes)\n")
    else:
        print(f"[1/3] Using cached Podium 2: GPT-5.6 Sol Pro ({len(cache['sol_pro'])} bytes)\n")

    if "opus_5" not in cache or not cache["opus_5"]:
        print("[2/3] Querying Podium 3: Claude Opus 5 (Anthropic)...", flush=True)
        cache["opus_5"] = query_claude_model("anthropic/claude-opus-5", DEBATE_TOPIC, system_opus)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
        print(f"-> Claude Opus response captured ({len(cache['opus_5'])} bytes)\n")
    else:
        print(f"[2/3] Using cached Podium 3: Claude Opus 5 ({len(cache['opus_5'])} bytes)\n")

    if "fable_51" not in cache or not cache["fable_51"]:
        print("[3/3] Querying Podium 4: Claude Fable 5.1 (Anthropic)...", flush=True)
        cache["fable_51"] = query_claude_model("anthropic/claude-fable-5.1", DEBATE_TOPIC, system_fable)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
        print(f"-> Fable 5.1 response captured ({len(cache['fable_51'])} bytes)\n")
    else:
        print(f"[3/3] Using cached Podium 4: Claude Fable 5.1 ({len(cache['fable_51'])} bytes)\n")

    cache["timestamp"] = time.time()
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)

    print(f"Raw debate responses saved to {output_path}")


if __name__ == "__main__":
    main()
