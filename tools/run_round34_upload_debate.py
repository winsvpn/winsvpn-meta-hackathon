#!/usr/bin/env python3
"""
Winthos Four-AI Presidential Debate Council: Round 34 Upload Wire-Speed Optimization
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
RAW_OUTPUT = DOCS_EVIDENCE / "debate_round34_upload_raw.json"

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
    for attempt in range(12):
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
                "X-Title": "Winthos Presidential Debate Round 34 Upload Optimization",
            },
        )
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=360) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                if "error" in res_data:
                    err_msg = res_data["error"].get("message", "Unknown error")
                    print(f"[{model_name}] Upstream error (attempt {attempt+1}): {err_msg}", flush=True)
                    time.sleep(min(30, 6 * (attempt + 1)))
                    continue
                choice = res_data["choices"][0]["message"]
                content = (choice.get("content") or choice.get("reasoning") or "").strip()
                if content:
                    return clean_text(content)
        except Exception as e:
            print(f"[{model_name}] Attempt {attempt+1} failed: {e}", flush=True)
            time.sleep(min(30, 6 * (attempt + 1)))
    raise RuntimeError(f"Query for {model_name} failed after 12 attempts")


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
DELIBERATION DOCKET: ROUND 34 PRESIDENTIAL DEBATE
TOPIC: Symmetrical Wire-Speed Upload (>1,000 Mbps with Download Locked at 1,554 Mbps)

EMPIRICAL TELEMETRY AND ROUND 33 POST-MORTEM:
1. Physical Handset and Transport Link:
   - Samsung Galaxy S26 Ultra (SM-S948U1, serial REDACTED_SERIAL).
   - Wi-Fi 7 connection: PHY rate 3,459 Mbps (5,764 Mbps maximum), 6 GHz band, 320 MHz channel width.
   - Symmetrical WAN Fiber: 2,000 Mbps down / 2,000 Mbps up.
   - Gateway: aicore (192.168.4.36:9111, AMD Ryzen 7 PRO 8845HS, 92 GB RAM).

2. Verified Facts:
   - Live Download speed over Winn Protocol v3 direct transport is verified and locked at 1,507 to 1,554 Mbps on screen.
   - Download code and configuration are 100% frozen by user directive. Do NOT modify the download datapath.
   - During Round 33 live testing of the upload leg:
     * tx_packets on the tun interface remained frozen at 91,367; zero payload bytes crossed the wire from measureUploadMbps.
     * In MainActivity.kt, connection.outputStream to https://speed.cloudflare.com/__up threw exceptions during connection setup.
     * Exceptions were silently caught by `catch (_: Exception) {}`, causing outputStream to remain null.
     * All 32 worker threads immediately returned. confirmed.get() was 0.
     * MethodChannel returned null to Dart.
     * Dart's _measureUploadMbps fell back to pure-Dart _measureSingleUploadMbps, launching 32 concurrent Dart HttpClient POSTs simultaneously.
     * This connection burst overwhelmed the single-threaded Dart runtime and desynchronized the tunnel session, producing `winn-engine: winn-debug: [winn3_frame.loop.Run] exited cleanly` and tunnel teardown.

3. Core Root Causes Identified:
   a) User-Agent & Missing Headers:
      In MainActivity.kt:
      connection.setRequestProperty("User-Agent", "WinsVPN-Speedtest/${BuildConfig.VERSION_NAME}")
      Cloudflare edge blocks or challenges non-browser User-Agents on /__up.
      Meanwhile, lib/main.dart sends:
      - User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
      - Origin: https://speed.cloudflare.com
      - Referer: https://speed.cloudflare.com/
      - Sec-Fetch-Site: same-origin
      - Sec-Fetch-Mode: cors
      - Accept: */*
   b) Query Parameter Pollution:
      In MainActivity.kt:speedTestStreamUrl:
      Appended `?r=${System.nanoTime()}-$streamIndex-$sequence` to `/__up`.
      Cloudflare speed test upload handler expects POST directly to canonical `https://speed.cloudflare.com/__up` without query params.
   c) Silent Exception Swallowing:
      Empty `catch (_: Exception) {}` hides socket connection failures.
   d) Unthrottled 32-Stream Burst:
      32 threads simultaneously calling connection.outputStream at the exact same microsecond causes CPU scheduling spikes and socket pool contention.
      Staggering connection starts (e.g. 2 ms per stream) or evaluating 24 streams reduces contention.
   e) Dart Fallback Storm:
      Dart falling back to 32 unthrottled Dart HttpClient streams when native upload returns null causes tunnel termination.

MANDATE FOR THIS PODIUM:
1. Deliver your independent technical determination with mathematical derivations and empirical proof.
2. Evaluate header alignment, canonical upload URL, stream count (16 vs 24 vs 32), connection stagger pacing, and logging.
3. Propose exact, surgical code diffs for MainActivity.kt and lib/main.dart.
4. Keep the download implementation 100% intact and untouched.
5. Strictly ZERO em dashes or en dashes across all prose and code comments.
6. Ban all AI cliches: delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary.
7. High burstiness: mix short punchy assertions with analytical proofs.
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
            filename = f"debate_round34_{key}.md"
            with open(DOCS_EVIDENCE / filename, "w", encoding="utf-8") as f:
                f.write(f"# Stage 1 Submission: {key}\n\n{result}\n")
            print(f"-> {key} completed and written to {filename} ({len(result)} bytes)", flush=True)

    print("\nStage 1 Submissions Complete.\n")


def build_stage2_prompt(cache: dict[str, str]) -> str:
    antigravity_path = DOCS_EVIDENCE / "debate_round34_stage1_antigravity.md"
    antigravity = antigravity_path.read_text(encoding="utf-8") if antigravity_path.exists() else "Antigravity Chair Submission"
    return f"""
STAGE 2: ADVERSARIAL CROSS-REBUTTAL AND VULNERABILITY DISCOVERY
DELIBERATION DOCKET: ROUND 34 PRESIDENTIAL DEBATE (UPLOAD SCALING > 1,000 MBPS)

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
2. Evaluate:
   - Exact HTTP headers in MainActivity.kt: Origin, Referer, Sec-Fetch-Site, Sec-Fetch-Mode, Accept, Chrome User-Agent vs Brand User-Agent.
   - URL handling in speedTestStreamUrl: strictly canonical https://speed.cloudflare.com/__up without query strings.
   - Stream concurrency: 16 vs 24 vs 32 streams. Is 24 streams safer against OkHttp connection pool exhaustion while delivering >1,000 Mbps, or does 32 streams with 2 ms stagger succeed?
   - Logging in MainActivity.kt: using android.util.Log.w without crashing.
   - Guard in lib/main.dart: preventing the destructive 32-stream pure-Dart HttpClient fallback storm when native upload returns null during active VPN.
   - Zero modifications to the download datapath.
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
            filename = f"debate_round34_{key}.md"
            with open(DOCS_EVIDENCE / filename, "w", encoding="utf-8") as f:
                f.write(f"# Stage 2 Rebuttal: {key}\n\n{result}\n")
            print(f"-> {key} completed and written to {filename} ({len(result)} bytes)", flush=True)

    print("\nStage 2 Rebuttals Complete.\n")


def build_stage3_prompt(cache: dict[str, str]) -> str:
    return f"""
STAGE 3: SYNTHESIS, CONCESSIONS, AND FINAL POSITION LOCKS
DELIBERATION DOCKET: ROUND 34 PRESIDENTIAL DEBATE (UPLOAD SCALING > 1,000 MBPS)

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
   - Header profile in MainActivity.kt: exact header keys and values.
   - Canonical URL in speedTestStreamUrl: exact logic.
   - Stream count (24 vs 32) and stagger timing (2 ms vs 5 ms vs 0 ms).
   - Chunk buffer sizing (256 KB) and streaming mode.
   - Exception handling and logging in MainActivity.kt.
   - Dart fallback guard in lib/main.dart.
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
        errors = {}
        for future in concurrent.futures.as_completed(future_to_key):
            key = future_to_key[future]
            try:
                result = future.result()
                update_cache(key, result)
                cache[key] = result
                filename = f"debate_round34_{key}.md"
                with open(DOCS_EVIDENCE / filename, "w", encoding="utf-8") as f:
                    f.write(f"# Stage 3 Synthesis: {key}\n\n{result}\n")
                print(f"-> {key} completed and written to {filename} ({len(result)} bytes)", flush=True)
            except Exception as e:
                print(f"-> {key} failed: {e}", flush=True)
                errors[key] = e

        if errors:
            # Retry any failed model sequentially
            for key, err in errors.items():
                print(f"Retrying {key} sequentially...", flush=True)
                model_map = {
                    "stage3_sol_pro": ("openai/gpt-5.6-sol-pro", SYSTEM_SOL),
                    "stage3_opus5": ("anthropic/claude-opus-5", SYSTEM_OPUS),
                    "stage3_fable51": ("anthropic/claude-fable-5.1", SYSTEM_FABLE),
                }
                m_name, m_sys = model_map[key]
                result = query_openrouter_model(m_name, prompt, m_sys, 4000)
                update_cache(key, result)
                cache[key] = result
                filename = f"debate_round34_{key}.md"
                with open(DOCS_EVIDENCE / filename, "w", encoding="utf-8") as f:
                    f.write(f"# Stage 3 Synthesis: {key}\n\n{result}\n")
                print(f"-> {key} completed upon retry and written to {filename} ({len(result)} bytes)", flush=True)

    print("\nStage 3 Syntheses Complete.\n")


def main():
    print("=== STARTING WINTHOS FOUR-AI PRESIDENTIAL DEBATE: ROUND 34 ===")
    print("Topic: Symmetrical Wire-Speed Upload (>1000 Mbps, Download Locked at 1554 Mbps)")
    print("Podiums: Antigravity, GPT-5.6 Sol Pro, Claude Opus 5, Claude Fable 5.1\n")

    cache = load_cache()
    execute_stage1(cache)
    execute_stage2(cache)
    execute_stage3(cache)
    print("All stages complete. Synthesize the final treaty in docs/evidence/debate_round34_treaty.md.")


if __name__ == "__main__":
    main()
