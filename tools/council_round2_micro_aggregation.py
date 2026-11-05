#!/usr/bin/env python3
"""
Council Round 2: Bounded Micro-Aggregation for Wire-Speed Upload Vectorization.
Podium 1: GLM 5.3 Flash (BaseTen fp8, Max Thinking)
Podium 2: GPT-5.6 Sol Pro (OpenAI flex, Extra High Thinking)
"""

import json
import os
import pathlib
import ssl
import sys
import time
import urllib.request
import certifi

REPO_ROOT = pathlib.Path("/Users/owner/xprize/winsvpnv3").resolve()
DOCS_EVIDENCE = REPO_ROOT / "docs" / "evidence"


def get_openrouter_key() -> str:
    env_key = os.environ.get("OPENROUTER_API_KEY")
    if env_key:
        return env_key.strip()
    auth_file = pathlib.Path.home() / ".local" / "share" / "opencode" / "auth.json"
    if auth_file.exists():
        data = json.loads(auth_file.read_text(encoding="utf-8"))
        return data.get("openrouter", {}).get("key").strip()
    raise RuntimeError("No key")


def clean_text(text: str) -> str:
    return text.replace("\u2014", ": ").replace("\u2013", "-")


def query_model(model: str, effort: str, provider: dict, prompt: str, system_role: str) -> str:
    key = get_openrouter_key()
    ctx = ssl.create_default_context(cafile=certifi.where())
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_role},
            {"role": "user", "content": prompt},
        ],
        "provider": provider,
        "reasoning": {"effort": effort},
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=data,
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    for attempt in range(5):
        try:
            print(f"[{model}] Querying (attempt {attempt+1})...", flush=True)
            with urllib.request.urlopen(req, context=ctx, timeout=300) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                content = res_data["choices"][0]["message"]["content"].strip()
                print(f"[{model}] Success.", flush=True)
                return clean_text(content)
        except Exception as e:
            print(f"[{model}] Failed: {e}", file=sys.stderr, flush=True)
            time.sleep(3 * (attempt + 1))
    raise RuntimeError(f"{model} failed")


def main():
    system_role = (
        "You are an elite network systems and kernel datapath architect on the Winthos Presidential Council. "
        "Rules: Zero em dashes or en dashes (use colons, commas, periods, or parentheses). Zero AI clichés. "
        "Analyze the empirical speedtest telemetry and provide exact, surgical code solutions."
    )

    prompt = """
# Council Docket Round 2: Eliminating the 2-Packet Fragmentation via Bounded Micro-Aggregation

## Empirical Test Run Telemetry (Samsung Galaxy S26 Ultra to aicore 192.168.4.36:9111)
- Download: 1,225 Mbps (wire speed achieved)
- Upload: 46.5 Mbps to 139 Mbps
- Telemetry Counters during Saturation:
  - rx_packets: 1,791,955
  - tx_packets: 336,200
  - messages_sent: 151,173
  - Ratio: 336,200 / 151,173 = 2.22 packets per outer carrier message!
  - tx_dropped_sink: 0
  - send_failed: 0

## The Mechanism
1. In `winn3_frame_device.go`: `ReadBatch` blocks on the first packet. When packet 0 arrives, `ReadBatch` immediately loops for subsequent packets (`i = 1..len(bufs)`).
2. Because the TCP sender paces packets, subsequent packets arrive 10 to 50 microseconds later.
3. The non-blocking `default:` case in `ReadBatch` calls `runtime.Gosched()`, which yields the goroutine for ~1 microsecond. If the second packet hasn't arrived yet, `ReadBatch` immediately returns `lengths` of size 1 or 2!
4. This returned batch of 1 or 2 packets is passed to `pumpOutboundBatch`, which calls `bSink.SendDataBatch(outPackets)`, which enqueues 1 or 2 packets into the session and immediately signals `l.signalWake()`.
5. `Loop.drain` wakes up instantly, drains those 1 or 2 packets from the session, and calls `batchCarrier.SendBatch` with only 1 or 2 packets!
6. Each outer UDP send has ~184 microseconds of serialization and Wi-Fi 7 frame aggregation/ACK latency. Transmitting 1 to 2 packets per outer message mathematically caps upload goodput at ~70 to 120 Mbps!

## Deliberation Questions
1. Where should bounded micro-aggregation be placed?
   Option A: In `winn3_frame_device.go:ReadBatch` (e.g. if `i < 32`, wait with a small micro-timer or deadline like 50 to 100 microseconds).
   Option B: In `winn3/driver/loop.go:drain` (e.g. if `count < 32`, do not send immediately; wait up to 100 microseconds for more packets before firing `SendBatch`).
   Option C: In Kotlin `WinnV3AndroidTun.kt` / `WinnV3Bridge.kt` before writing the batch across the LocalSocket.
2. What is the optimal micro-aggregation delay (e.g. 50us, 100us, 200us) that saturates carrier batches to 32-64 packets while keeping ping under 15ms?
3. Provide the exact, surgical code modification.
"""

    glm = query_model(
        "z-ai/glm-5.3-flash",
        "max",
        {"order": ["BaseTen"], "quantizations": ["fp8"], "allow_fallbacks": True},
        prompt,
        system_role,
    )
    sol = query_model(
        "openai/gpt-5.6-sol-pro",
        "xhigh",
        {"order": ["OpenAI"], "allow_fallbacks": True},
        prompt,
        system_role,
    )

    data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "round": 2,
        "glm_5_3_flash": glm,
        "gpt_5_6_sol_pro": sol,
    }
    out_file = DOCS_EVIDENCE / "tripartite_round2_micro_aggregation.json"
    out_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"Round 2 results written to {out_file}", flush=True)


if __name__ == "__main__":
    main()
