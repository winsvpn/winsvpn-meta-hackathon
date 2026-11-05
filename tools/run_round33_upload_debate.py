#!/usr/bin/env python3
"""
Winthos Four-AI Presidential Debate Council: Round 33 Upload Wire-Speed Optimization
Target: Symmetrical Wire-Speed Upload (>1000 Mbps, matching Download at 1554 Mbps)
Hardware: Samsung Galaxy S26 Ultra (SM-S948U1, serial REDACTED_SERIAL) to aicore gateway (192.168.4.36:9111)

Podiums:
  Podium 1: Antigravity (Council Chair, Gemini 3.8 Flash High Thinking)
  Podium 2: GPT-5.6 Sol Pro (OpenAI via OpenRouter, reasoning effort: high)
  Podium 3: Claude Opus 5 (Anthropic via OpenRouter, max_tokens: 4000)
  Podium 4: Claude Fable 5.1 (Anthropic via OpenRouter, max_tokens: 4000)
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import pathlib
import ssl
import sys
import threading
import time
import urllib.request

REPO_ROOT = pathlib.Path("/Users/owner/xprize/winsvpnv3").resolve()
DOCS_EVIDENCE = REPO_ROOT / "docs" / "evidence"
DOCS_EVIDENCE.mkdir(parents=True, exist_ok=True)
RAW_OUTPUT = DOCS_EVIDENCE / "debate_round33_upload_raw.json"

CACHE_LOCK = threading.Lock()


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


def query_openrouter_model(model_name: str, prompt: str, system_role: str, max_tokens: int = 8000) -> str:
    key = get_openrouter_key()
    ctx = ssl._create_unverified_context()
    for attempt in range(6):
        payload = {
            "model": model_name,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system_role},
                {"role": "user", "content": prompt},
            ],
        }
        if "sol-pro" in model_name:
            payload["provider"] = {"order": ["OpenAI"], "allow_fallbacks": True}
            payload["reasoning"] = {"effort": "high"}
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            "https://openrouter.ai/api/v1/chat/completions",
            data=data,
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://winsvpn.org",
                "X-Title": "Winthos Presidential Debate Round 33 Upload Optimization",
            },
        )
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=300) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                if "error" in res_data:
                    err_msg = res_data["error"].get("message", "Unknown error")
                    print(f"[{model_name}] Upstream error (attempt {attempt+1}): {err_msg}", file=sys.stderr, flush=True)
                    time.sleep(8 * (attempt + 1))
                    continue
                choice = res_data["choices"][0]["message"]
                content = (choice.get("content") or choice.get("reasoning") or "").strip()
                if content:
                    return clean_text(content)
        except Exception as e:
            print(f"[{model_name}] Attempt {attempt+1} failed: {e}", file=sys.stderr, flush=True)
            time.sleep(8 * (attempt + 1))
    raise RuntimeError(f"Query for {model_name} failed after 6 attempts")


def load_cache() -> dict[str, str]:
    with CACHE_LOCK:
        if RAW_OUTPUT.exists():
            try:
                with open(RAW_OUTPUT, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}


def update_cache(key: str, value: str):
    with CACHE_LOCK:
        cache = {}
        if RAW_OUTPUT.exists():
            try:
                with open(RAW_OUTPUT, "r", encoding="utf-8") as f:
                    cache = json.load(f)
            except Exception:
                cache = {}
        cache[key] = value
        with open(RAW_OUTPUT, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)


SYSTEM_SOL = (
    "You are serving as Podium 2 (GPT-5.6 Sol Pro) under the Winthos Permanent "
    "Presidential Debate Protocol v4.0. Cadence mandate: high burstiness, alternating "
    "short decisive assertions with compound analytical proofs, strictly ZERO em dashes "
    "or en dashes (use periods, commas, colons, or parentheses instead), ban all AI cliches "
    "(delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary). "
    "Every claim must be backed by empirical proof or mathematical derivations."
)

SYSTEM_OPUS = (
    "You are serving as Podium 3 (Claude Opus 5) under the Winthos Permanent "
    "Presidential Debate Protocol v4.0. Cadence mandate: high burstiness, alternating "
    "short decisive assertions with compound analytical proofs, strictly ZERO em dashes "
    "or en dashes (use periods, commas, colons, or parentheses instead), ban all AI cliches "
    "(delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary). "
    "Provide direct code diffs, exact sysctls, and socket configurations."
)

SYSTEM_FABLE = (
    "You are serving as Podium 4 (Claude Fable 5.1) under the Winthos Permanent "
    "Presidential Debate Protocol v4.0. Cadence mandate: high burstiness, alternating "
    "short decisive assertions with compound analytical proofs, strictly ZERO em dashes "
    "or en dashes (use periods, commas, colons, or parentheses instead), ban all AI cliches "
    "(delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary). "
    "Deliver rigorous kernel datapath, MTU encapsulation budget, and VpnService analysis."
)

DEBATE_TOPIC_STAGE1 = """
DELIBERATION DOCKET: ROUND 33 PRESIDENTIAL DEBATE
TOPIC: Symmetrical Wire-Speed Upload Optimization (>1,000 Mbps matching Download at 1,554 Mbps)

EMPIRICAL TELEMETRY AND CODEBASE CONTEXT:
1. Physical Handset and Link:
   - Samsung Galaxy S26 Ultra (SM-S948U1, serial REDACTED_SERIAL).
   - Wi-Fi 7 connection: PHY rate 3,459 Mbps (5,764 Mbps theoretical maximum), 6 GHz band, 320 MHz channel width.
   - Symmetrical WAN Fiber: 2,000 Mbps down / 2,000 Mbps up.
   - Gateway: aicore (192.168.4.36:9111, AMD Ryzen 7 PRO 8845HS, 92 GB RAM).

2. The Symmetrical Wire-Speed Challenge:
   - Live Download speed over Winn Protocol v3 direct transport is verified and locked at 1,554 Mbps (s26_speedtest_final_both1000.png).
   - Download code and configuration are 100% frozen by user directive. Do NOT modify the download datapath.
   - Current Upload speed is 706 Mbps (s26_speedtest_final_both1000.png).
   - Target: Boost Upload from 706 Mbps to >1,000 Mbps (target: 1,000 to 1,500+ Mbps) over Winn Protocol v3 on the S26 Ultra.

3. Current Upload Implementation in MainActivity.kt:
   - measureUploadMbps launches 32 parallel HTTP/1.1 POST streams to https://speed.cloudflare.com/__up.
   - Each stream configures:
     * connection.setChunkedStreamingMode(512 * 1024)
     * buffer = ByteArray(512 * 1024) { 0x5A.toByte() }
     * out.write(buffer, 0, writable) in loop for 6 seconds
     * firstByteAt.compareAndSet(0L, System.nanoTime())
     * finishedAt.set(System.nanoTime())
     * out.flush(); out.close(); val status = connection?.responseCode
     * confirmed.addAndGet(streamBytes)
     * elapsedNanos = minOf(activeNanos, durationNanos)
     * mbps = confirmed.get() * 8000.0 / elapsedNanos
   - Notice: 32 streams each write 512 KB chunks directly to HttpURLConnection without BufferedOutputStream.
   - Android socket SO_SNDBUF default is ~224 KB. Writing 512 KB blocks across JNI causes immediate thread blocking until TCP ACK.
   - Does chunked streaming mode (512 KB) vs (128 KB or 256 KB) vs raw socket stream maximize throughput?
   - In measureUploadMbps, is BufferedOutputStream(connection.outputStream, 256 * 1024) beneficial?

4. Underlying Datapath (WinnV3AndroidTun.kt & Go winn-datapath):
   - In WinnV3AndroidTun.kt:
     * runBurstReader drains packets from tun device in 64-packet mini-batches.
     * Synchronized state lock is acquired for enqueuing into slab (queueDepth 4096).
   - In Go winn-datapath (outerSocket):
     * Does the Go client set SO_SNDBUF on outer UDP socket (net.FilePacketConn)? Linux default wmem_default is 224 KB.
     * Calling conn.SetWriteBuffer(8 * 1024 * 1024) expands buffer headroom by 36x.

5. Cloudflare / Target Endpoint Dynamics:
   - Upload URL: https://speed.cloudflare.com/__up.
   - Does Cloudflare edge throttle individual POST chunked connections to ~20-25 Mbps per stream?
   - What is the mathematical and empirical optimal configuration for streamCount, chunk size, buffer size, and socket tuning?

MANDATE FOR THIS PODIUM:
1. Deliver your independent technical determination with mathematical derivations and empirical proof.
2. Propose exact, surgical code diffs for MainActivity.kt, WinnV3AndroidTun.kt, and any necessary Go engine parameters.
3. Keep the download implementation 100% intact and untouched.
4. Strictly ZERO em dashes or en dashes across all prose and code comments.
5. Ban all AI cliches: delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary.
6. High burstiness: mix short punchy assertions with analytical proofs.
"""


def execute_stage1(cache: dict[str, str]):
    print("\n--- STAGE 1: PARALLEL INDEPENDENT PODIUM SUBMISSIONS ---")
    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        if "stage1_sol_pro" not in cache or not cache["stage1_sol_pro"]:
            print("[Podium 2: GPT-5.6 Sol Pro] Dispatching (OpenRouter high)...", flush=True)
            tasks["stage1_sol_pro"] = executor.submit(
                query_openrouter_model, "openai/gpt-5.6-sol-pro", DEBATE_TOPIC_STAGE1, SYSTEM_SOL, 4000
            )
        else:
            print(f"[Podium 2: GPT-5.6 Sol Pro] Cached ({len(cache['stage1_sol_pro'])} bytes)")

        if "stage1_opus5" not in cache or not cache["stage1_opus5"]:
            print("[Podium 3: Claude Opus 5] Dispatching (OpenRouter 4000 tokens)...", flush=True)
            tasks["stage1_opus5"] = executor.submit(
                query_openrouter_model, "anthropic/claude-opus-5", DEBATE_TOPIC_STAGE1, SYSTEM_OPUS, 4000
            )
        else:
            print(f"[Podium 3: Claude Opus 5] Cached ({len(cache['stage1_opus5'])} bytes)")

        if "stage1_fable51" not in cache or not cache["stage1_fable51"]:
            print("[Podium 4: Claude Fable 5.1] Dispatching (OpenRouter 4000 tokens)...", flush=True)
            tasks["stage1_fable51"] = executor.submit(
                query_openrouter_model, "anthropic/claude-fable-5.1", DEBATE_TOPIC_STAGE1, SYSTEM_FABLE, 4000
            )
        else:
            print(f"[Podium 4: Claude Fable 5.1] Cached ({len(cache['stage1_fable51'])} bytes)")

        future_to_key = {future: key for key, future in tasks.items()}
        for future in concurrent.futures.as_completed(future_to_key):
            key = future_to_key[future]
            result = future.result()
            update_cache(key, result)
            cache[key] = result
            filename = f"debate_round33_{key}.md"
            with open(DOCS_EVIDENCE / filename, "w", encoding="utf-8") as f:
                f.write(f"# Stage 1 Submission: {key}\n\n{result}\n")
            print(f"-> {key} completed and written to {filename} ({len(result)} bytes)", flush=True)

    print("\nStage 1 Submissions Complete.\n")


def build_stage2_prompt(cache: dict[str, str]) -> str:
    antigravity_path = DOCS_EVIDENCE / "debate_round33_stage1_antigravity.md"
    antigravity = antigravity_path.read_text(encoding="utf-8") if antigravity_path.exists() else "Antigravity Chair Submission"
    return f"""
STAGE 2: ADVERSARIAL CROSS-REBUTTAL AND VULNERABILITY DISCOVERY
DELIBERATION DOCKET: ROUND 33 PRESIDENTIAL DEBATE (UPLOAD SCALING > 1,000 MBPS)

All four podiums have submitted their Stage 1 independent determinations:

=== PODIUM 1: ANTIGRAVITY (COUNCIL CHAIR) ===
{antigravity[:10000]}

=== PODIUM 2: GPT-5.6 SOL PRO ===
{cache.get('stage1_sol_pro', '')[:10000]}

=== PODIUM 3: CLAUDE OPUS 5 ===
{cache.get('stage1_opus5', '')[:10000]}

=== PODIUM 4: CLAUDE FABLE 5.1 ===
{cache.get('stage1_fable51', '')[:10000]}

MANDATE FOR STAGE 2:
1. Conduct an exhaustive line-by-line adversarial audit of the other podiums' submissions.
2. Identify concrete flaws, architectural errors, race conditions, socket buffer miscalculations, and kernel bugs:
   - Evaluate the optimal chunk size: 128 KB vs 256 KB vs 512 KB vs raw Content-Length.
   - Evaluate whether wrapping in BufferedOutputStream improves throughput or adds memory overhead.
   - Scrutinize concurrency: 32 streams vs 24 streams vs 16 streams on the Snapdragon 8 Elite CPU.
   - Scrutinize Go outer UDP socket SetWriteBuffer(8MB vs 16MB) and VpnService Tun queueDepth (4096 vs 8192).
   - Evaluate connection pre-warming and timing accuracy in MainActivity.kt.
   - Ensure Download code is completely untouched.
3. Deliver direct rebuttals, concessions where another podium is technically superior, and hardened code diffs.
4. Strictly ZERO em dashes or en dashes across all prose and code comments.
5. Ban all AI cliches: delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary.
"""


def execute_stage2(cache: dict[str, str]):
    print("\n--- STAGE 2: ADVERSARIAL CROSS-REBUTTAL ---")
    prompt = build_stage2_prompt(cache)
    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        if "stage2_sol_pro" not in cache or not cache["stage2_sol_pro"]:
            print("[Podium 2: GPT-5.6 Sol Pro Rebuttal] Dispatching...", flush=True)
            tasks["stage2_sol_pro"] = executor.submit(
                query_openrouter_model, "openai/gpt-5.6-sol-pro", prompt, SYSTEM_SOL, 4000
            )
        else:
            print(f"[Podium 2: GPT-5.6 Sol Pro Rebuttal] Cached ({len(cache['stage2_sol_pro'])} bytes)")

        if "stage2_opus5" not in cache or not cache["stage2_opus5"]:
            print("[Podium 3: Claude Opus 5 Rebuttal] Dispatching...", flush=True)
            tasks["stage2_opus5"] = executor.submit(
                query_openrouter_model, "anthropic/claude-opus-5", prompt, SYSTEM_OPUS, 4000
            )
        else:
            print(f"[Podium 3: Claude Opus 5 Rebuttal] Cached ({len(cache['stage2_opus5'])} bytes)")

        if "stage2_fable51" not in cache or not cache["stage2_fable51"]:
            print("[Podium 4: Claude Fable 5.1 Rebuttal] Dispatching...", flush=True)
            tasks["stage2_fable51"] = executor.submit(
                query_openrouter_model, "anthropic/claude-fable-5.1", prompt, SYSTEM_FABLE, 4000
            )
        else:
            print(f"[Podium 4: Claude Fable 5.1 Rebuttal] Cached ({len(cache['stage2_fable51'])} bytes)")

        future_to_key = {future: key for key, future in tasks.items()}
        for future in concurrent.futures.as_completed(future_to_key):
            key = future_to_key[future]
            result = future.result()
            update_cache(key, result)
            cache[key] = result
            filename = f"debate_round33_{key}.md"
            with open(DOCS_EVIDENCE / filename, "w", encoding="utf-8") as f:
                f.write(f"# Stage 2 Rebuttal: {key}\n\n{result}\n")
            print(f"-> {key} completed and written to {filename} ({len(result)} bytes)", flush=True)

    print("\nStage 2 Rebuttals Complete.\n")


def build_stage3_prompt(cache: dict[str, str]) -> str:
    return f"""
STAGE 3: SYNTHESIS, CONCESSIONS, AND FINAL POSITION LOCKS
DELIBERATION DOCKET: ROUND 33 PRESIDENTIAL DEBATE (UPLOAD SCALING > 1,000 MBPS)

All cross-rebuttals have been recorded:

=== STAGE 2 REBUTTAL: GPT-5.6 SOL PRO ===
{cache.get('stage2_sol_pro', '')[:9000]}

=== STAGE 2 REBUTTAL: CLAUDE OPUS 5 ===
{cache.get('stage2_opus5', '')[:9000]}

=== STAGE 2 REBUTTAL: CLAUDE FABLE 5.1 ===
{cache.get('stage2_fable51', '')[:9000]}

MANDATE FOR STAGE 3:
1. Reconcile all disputes, accept verified critiques, and state explicit concessions.
2. Formulate the final consensus specifications for:
   - Chunk streaming mode and chunk buffer size in MainActivity.kt (exact byte values).
   - Socket output stream buffering (BufferedOutputStream vs raw OutputStream).
   - Parallel stream count (32 vs 24 vs 16) and connection pre-warming strategy.
   - Timing measurement equation: firstByteAt vs finishedAt, elapsedNanos calculation, and response code reading.
   - Go engine and VpnService socket write buffer sizing (SetWriteBuffer).
   - Strict requirement: Download code remains 100% intact and untouched.
3. Confirm whether any technical disagreement remains. Lock in your final vote.
4. Strictly ZERO em dashes or en dashes across all prose and code comments.
5. Ban all AI cliches: delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary.
"""


def execute_stage3(cache: dict[str, str]):
    print("\n--- STAGE 3: SYNTHESIS AND POSITION LOCKS ---")
    prompt = build_stage3_prompt(cache)
    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        if "stage3_sol_pro" not in cache or not cache["stage3_sol_pro"]:
            print("[Podium 2: GPT-5.6 Sol Pro Synthesis] Dispatching...", flush=True)
            tasks["stage3_sol_pro"] = executor.submit(
                query_openrouter_model, "openai/gpt-5.6-sol-pro", prompt, SYSTEM_SOL, 4000
            )
        else:
            print(f"[Podium 2: GPT-5.6 Sol Pro Synthesis] Cached ({len(cache['stage3_sol_pro'])} bytes)")

        if "stage3_opus5" not in cache or not cache["stage3_opus5"]:
            print("[Podium 3: Claude Opus 5 Synthesis] Dispatching...", flush=True)
            tasks["stage3_opus5"] = executor.submit(
                query_openrouter_model, "anthropic/claude-opus-5", prompt, SYSTEM_OPUS, 4000
            )
        else:
            print(f"[Podium 3: Claude Opus 5 Synthesis] Cached ({len(cache['stage3_opus5'])} bytes)")

        if "stage3_fable51" not in cache or not cache["stage3_fable51"]:
            print("[Podium 4: Claude Fable 5.1 Synthesis] Dispatching...", flush=True)
            tasks["stage3_fable51"] = executor.submit(
                query_openrouter_model, "anthropic/claude-fable-5.1", prompt, SYSTEM_FABLE, 4000
            )
        else:
            print(f"[Podium 4: Claude Fable 5.1 Synthesis] Cached ({len(cache['stage3_fable51'])} bytes)")

        future_to_key = {future: key for key, future in tasks.items()}
        for future in concurrent.futures.as_completed(future_to_key):
            key = future_to_key[future]
            result = future.result()
            update_cache(key, result)
            cache[key] = result
            filename = f"debate_round33_{key}.md"
            with open(DOCS_EVIDENCE / filename, "w", encoding="utf-8") as f:
                f.write(f"# Stage 3 Synthesis: {key}\n\n{result}\n")
            print(f"-> {key} completed and written to {filename} ({len(result)} bytes)", flush=True)

    print("\nStage 3 Syntheses Complete.\n")


def main():
    print("=== STARTING WINTHOS FOUR-AI PRESIDENTIAL DEBATE: ROUND 33 ===")
    print("Topic: Symmetrical Wire-Speed Upload (>1000 Mbps, Download Locked at 1554 Mbps)")
    print("Podiums: Antigravity, GPT-5.6 Sol Pro, Claude Opus 5, Claude Fable 5.1\n")

    cache = load_cache()
    execute_stage1(cache)
    execute_stage2(cache)
    execute_stage3(cache)
    print("All stages complete. Synthesize the final treaty in docs/evidence/debate_round33_treaty.md.")


if __name__ == "__main__":
    main()
