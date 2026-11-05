#!/usr/bin/env python3
"""
Winthos Four-AI Presidential Debate Council: Round 32 Wire-Speed Optimization
Target: Symmetrical Multi-Gbps Wire Speed for Single VPN (1000-2000 Mbps) & Double VPN (500-1500 Mbps via aicore 1st Hop)
Parallel Execution Architecture:
  Podium 1: Antigravity (Council Chair, Gemini 3.8 Flash High Thinking)
  Podium 2: GPT-5.6 Sol Pro (OpenAI via OpenRouter, service_tier: flex, effort: xhigh)
  Podium 3: Claude Opus 5 (Anthropic Claude Code CLI, --model opus --effort xhigh --tools "")
  Podium 4: Claude Fable 5.1 (Anthropic Claude Code CLI, --model claude-fable-5-1 --effort high --tools "")
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import pathlib
import ssl
import subprocess
import sys
import threading
import time
import urllib.request

REPO_ROOT = pathlib.Path("/Users/owner/xprize/winsvpnv3").resolve()
DOCS_EVIDENCE = REPO_ROOT / "docs" / "evidence"
DOCS_EVIDENCE.mkdir(parents=True, exist_ok=True)
RAW_OUTPUT = DOCS_EVIDENCE / "debate_round32_raw.json"

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
    for attempt in range(8):
        # Prefer flex service tier, but allow fallback if flex is rate-limited upstream
        tier = "flex" if attempt < 4 else "auto"
        payload = {
            "model": model_name,
            "messages": [
                {"role": "system", "content": system_role},
                {"role": "user", "content": prompt},
            ],
            "provider": {"order": ["OpenAI"], "allow_fallbacks": True},
            "service_tier": tier,
            "reasoning": {"effort": "xhigh"},
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            "https://openrouter.ai/api/v1/chat/completions",
            data=data,
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://winsvpn.org",
                "X-Title": "Winthos Presidential Debate Round 32",
            },
        )
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=300) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                if "error" in res_data:
                    err_msg = res_data["error"].get("message", "Unknown error")
                    print(f"[{model_name}] Upstream status (attempt {attempt+1}): {err_msg}", file=sys.stderr, flush=True)
                    time.sleep(10 * (attempt + 1))
                    continue
                choice = res_data["choices"][0]["message"]
                content = choice.get("content", "").strip()
                if content:
                    return clean_text(content)
        except Exception as e:
            print(f"[{model_name}] Attempt {attempt+1} failed: {e}", file=sys.stderr, flush=True)
            time.sleep(10 * (attempt + 1))
    raise RuntimeError(f"OpenRouter query for {model_name} failed after multiple attempts")


def query_claude_cli(model_name: str, prompt: str, system_role: str, effort: str = "xhigh") -> str:
    sys_prompt = (
        f"{system_role}\n\n"
        "You are participating in an elite presidential debate council. You do not have access to any external tools or bash commands. "
        "Do NOT output any tool calls, json blocks for tool calls, or action requests. "
        "Write your entire submission directly in pure markdown prose, mathematical formulas, and code blocks."
    )
    cmd = [
        "/Users/owner/.local/bin/claude",
        "--tools",
        "",
        "--system-prompt",
        sys_prompt,
        "--model",
        model_name,
        "--effort",
        effort,
        "-p",
        prompt,
    ]
    for attempt in range(4):
        try:
            print(f"[Claude CLI {model_name}] Launching subprocess attempt {attempt+1} (effort: {effort}, timeout: 900s)...", file=sys.stderr, flush=True)
            proc = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT),
                timeout=900,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                cleaned = clean_text(proc.stdout.strip())
                # Ensure it did not just emit a tool call block
                if not cleaned.startswith("**Tool Call:") and "<invoke name=" not in cleaned:
                    return cleaned
                print(f"[Claude CLI {model_name}] Received unexpected tool call block; retrying attempt {attempt+1}...", file=sys.stderr, flush=True)
            print(
                f"[Claude CLI {model_name}] Return code {proc.returncode}: {proc.stderr[:300]}",
                file=sys.stderr,
                flush=True,
            )
            time.sleep(5)
        except subprocess.TimeoutExpired:
            print(f"[Claude CLI {model_name}] Attempt {attempt+1} timed out after 900s", file=sys.stderr, flush=True)
            time.sleep(5)
        except Exception as e:
            print(f"[Claude CLI {model_name}] Attempt {attempt+1} failed: {e}", file=sys.stderr, flush=True)
            time.sleep(5)
    raise RuntimeError(f"Claude CLI query for {model_name} failed after attempts")


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
DELIBERATION DOCKET: ROUND 32 PRESIDENTIAL DEBATE
TOPIC: Symmetrical Multi-Gbps Wire Speed for Single VPN (1,000 to 2,000 Mbps) and Double VPN (500 to 1,500 Mbps via aicore 1st Hop)

EMPIRICAL BASELINE AND RECENT RESULTS:
1. Physical Handset:
   - Samsung Galaxy S26 Ultra (SM-S948U1, serial REDACTED_SERIAL).
   - Wi-Fi 7 connection to 10 Gbps LAN / 2 Gbps Symmetrical Fiber WAN.
   - Initial Download Plateau: 425 Mbps (upload reached 1,135 to 1,705 Mbps).
   - Following Stage 1 optimization (WriteOutboundBatch in Go, 8MB LocalSocket buffers, 1MB Kotlin batch accumulator, 60us spin-wait on TUN EAGAIN):
     * 16-stream Download SpeedBench: 1,345.38 Mbps (1.35 Gbps).
     * 16-stream Upload SpeedBench: 1,135.35 Mbps (1.14 Gbps).
     * 16-stream Simultaneous Bidirectional: DL 1,347.18 Mbps + UL 1,122.62 Mbps = 2,469.80 Mbps combined wire speed.
     * Public Ookla Speedtest: 637 Mbps download (peaked at 692.36 Mbps), 549 Mbps upload, 12 ms ping.
     * Zero engine packet drops across 3.73 million packets.

2. Problem Statement for Single VPN Scaling to 2,000 Mbps:
   - Push Single VPN throughput from 1.35 Gbps to the full 2.0 Gbps theoretical wire limit.
   - Evaluate UDP GSO (UDP_SEGMENT) on transmit and UDP GRO (UDP_GRO) on receive in Go and Linux.
   - Socket buffer sizing: scaling SO_RCVBUF / SO_SNDBUF from 8 MB to 16 MB.
   - Zero-copy lock-free ring buffers between Go datapath and TUN descriptor.

3. Problem Statement for Fleet-Wide Double VPN Scaling to 500 - 1,500 Mbps:
   - Hop 1: Handset (10.10.0.14) -> aicore (192.168.4.36:9111, inner 10.10.0.1).
   - Ingress Multiprotocol on aicore: must accept all user-facing protocols (Winn v3 on UDP 9111, Winn v1 AWG on UDP 51820 with XRay fallback).
   - Hop 2: aicore -> Remote Fleet Exit Node (Canada ca1 <NODE_CANADA_IP>, Germany de1 <NODE_GERMANY_IP>, Spain <NODE_SPAIN_IP>, Kansas Core <KANSAS_HUB_IP>).
   - Egress from aicore to Exit Node must use Winn Protocol v3.
   - MTU Budget and Fragmentation:
     * Handset inner MTU: 1373 bytes.
     * Hop 1 terminates on aicore, decapsulating into kernel IP packet on winn3gw0.
     * Hop 2 re-encapsulates packet into Winn Protocol v3 to the exit node.
     * Path MTU Discovery and MSS clamping: exact iptables/nftables mangle rules on aicore to prevent fragmentation.
   - Kernel Packet Forwarding on aicore:
     * Fast-path routing between winn3gw0 (Hop 1) and egress interface (Hop 2).
     * FQ qdisc pacing, txqueuelen scaling, and RPS/XPS CPU core steering.

MANDATE FOR THIS PODIUM:
1. Deliver your independent technical determination with mathematical derivations (Level 3) and empirical proof (Level 1).
2. Propose exact Go engine code diffs, Kotlin Android host modifications, and Linux gateway sysctls/iptables.
3. Strictly ZERO em dashes or en dashes across all prose and code comments.
4. Ban AI cliches: delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary.
5. High burstiness: mix short punchy assertions with analytical proofs.
"""


def execute_stage1(cache: dict[str, str]):
    print("\n--- STAGE 1: PARALLEL INDEPENDENT PODIUM SUBMISSIONS ---")
    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        if "stage1_sol_pro" not in cache or not cache["stage1_sol_pro"]:
            print("[Podium 2: GPT-5.6 Sol Pro] Dispatching (OpenRouter flex xhigh)...", flush=True)
            tasks["stage1_sol_pro"] = executor.submit(
                query_openrouter_model, "openai/gpt-5.6-sol-pro", DEBATE_TOPIC_STAGE1, SYSTEM_SOL
            )
        else:
            print(f"[Podium 2: GPT-5.6 Sol Pro] Cached ({len(cache['stage1_sol_pro'])} bytes)")

        if "stage1_opus5" not in cache or not cache["stage1_opus5"]:
            print("[Podium 3: Claude Opus 5] Dispatching (Claude CLI --effort xhigh)...", flush=True)
            tasks["stage1_opus5"] = executor.submit(
                query_claude_cli, "opus", DEBATE_TOPIC_STAGE1, SYSTEM_OPUS, "xhigh"
            )
        else:
            print(f"[Podium 3: Claude Opus 5] Cached ({len(cache['stage1_opus5'])} bytes)")

        if "stage1_fable51" not in cache or not cache["stage1_fable51"]:
            print("[Podium 4: Claude Fable 5.1] Dispatching (Claude CLI --effort high)...", flush=True)
            tasks["stage1_fable51"] = executor.submit(
                query_claude_cli, "claude-fable-5-1", DEBATE_TOPIC_STAGE1, SYSTEM_FABLE, "high"
            )
        else:
            print(f"[Podium 4: Claude Fable 5.1] Cached ({len(cache['stage1_fable51'])} bytes)")

        future_to_key = {future: key for key, future in tasks.items()}
        for future in concurrent.futures.as_completed(future_to_key):
            key = future_to_key[future]
            result = future.result()
            update_cache(key, result)
            cache[key] = result
            filename = f"debate_round32_{key}.md"
            with open(DOCS_EVIDENCE / filename, "w", encoding="utf-8") as f:
                f.write(f"# Stage 1 Submission: {key}\n\n{result}\n")
            print(f"-> {key} completed and written to {filename} ({len(result)} bytes)", flush=True)

    print("\nStage 1 Submissions Complete.\n")


def build_stage2_prompt(cache: dict[str, str]) -> str:
    antigravity = (DOCS_EVIDENCE / "debate_round32_stage1_antigravity.md").read_text(encoding="utf-8")
    return f"""
STAGE 2: ADVERSARIAL CROSS-REBUTTAL AND VULNERABILITY DISCOVERY
DELIBERATION DOCKET: ROUND 32 PRESIDENTIAL DEBATE

All four podiums have submitted their Stage 1 independent determinations:

=== PODIUM 1: ANTIGRAVITY (COUNCIL CHAIR) ===
{antigravity}

=== PODIUM 2: GPT-5.6 SOL PRO ===
{cache.get('stage1_sol_pro', '')[:12000]}

=== PODIUM 3: CLAUDE OPUS 5 ===
{cache.get('stage1_opus5', '')[:12000]}

=== PODIUM 4: CLAUDE FABLE 5.1 ===
{cache.get('stage1_fable51', '')[:12000]}

MANDATE FOR STAGE 2:
1. Conduct an exhaustive line-by-line adversarial audit of the other podiums' submissions.
2. Identify concrete flaws, architectural errors, race conditions, socket buffer miscalculations, and kernel bugs:
   - Evaluate Sol Pro's SPSC ring buffer: does it handle goroutine parking correctly under heavy tun read backpressure?
   - Evaluate Opus 5's and Fable 5.1's proposed UDP GSO and UDP GRO implementations.
   - Evaluate Android VpnService descriptor lifecycle: detachFd() vs dup() vs direct SCM_RIGHTS unix domain socket passing.
   - Scrutinize the Double VPN serial routing on aicore: verify whether MASQUERADE vs pure policy routing is required for Kansas Core, Canada ca1, Germany de1, and Spain.
   - Audit MTU calculations and TCP MSS clamping rules.
3. Deliver direct rebuttals, concessions where another podium is technically superior, and hardened code diffs.
4. Strictly ZERO em dashes or en dashes.
5. Ban AI cliches: delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary.
6. High burstiness: mix short punchy assertions with analytical proofs.
"""


def execute_stage2(cache: dict[str, str]):
    print("\n--- STAGE 2: PARALLEL ADVERSARIAL CROSS-REBUTTAL ---")
    prompt = build_stage2_prompt(cache)
    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        if "stage2_sol_pro" not in cache or not cache["stage2_sol_pro"]:
            print("[Podium 2: GPT-5.6 Sol Pro] Dispatching Rebuttal (flex xhigh)...", flush=True)
            tasks["stage2_sol_pro"] = executor.submit(
                query_openrouter_model, "openai/gpt-5.6-sol-pro", prompt, SYSTEM_SOL
            )
        else:
            print(f"[Podium 2: GPT-5.6 Sol Pro Rebuttal] Cached ({len(cache['stage2_sol_pro'])} bytes)")

        if "stage2_opus5" not in cache or not cache["stage2_opus5"]:
            print("[Podium 3: Claude Opus 5] Dispatching Rebuttal (xhigh)...", flush=True)
            tasks["stage2_opus5"] = executor.submit(
                query_claude_cli, "opus", prompt, SYSTEM_OPUS, "xhigh"
            )
        else:
            print(f"[Podium 3: Claude Opus 5 Rebuttal] Cached ({len(cache['stage2_opus5'])} bytes)")

        if "stage2_fable51" not in cache or not cache["stage2_fable51"]:
            print("[Podium 4: Claude Fable 5.1] Dispatching Rebuttal (high)...", flush=True)
            tasks["stage2_fable51"] = executor.submit(
                query_claude_cli, "claude-fable-5-1", prompt, SYSTEM_FABLE, "high"
            )
        else:
            print(f"[Podium 4: Claude Fable 5.1 Rebuttal] Cached ({len(cache['stage2_fable51'])} bytes)")

        future_to_key = {future: key for key, future in tasks.items()}
        for future in concurrent.futures.as_completed(future_to_key):
            key = future_to_key[future]
            result = future.result()
            update_cache(key, result)
            cache[key] = result
            filename = f"debate_round32_{key}.md"
            with open(DOCS_EVIDENCE / filename, "w", encoding="utf-8") as f:
                f.write(f"# Stage 2 Rebuttal: {key}\n\n{result}\n")
            print(f"-> {key} completed and written to {filename} ({len(result)} bytes)", flush=True)

    print("\nStage 2 Rebuttals Complete.\n")


def build_stage3_prompt(cache: dict[str, str]) -> str:
    return f"""
STAGE 3: SYNTHESIS, CONCESSIONS, AND UNANIMOUS POSITION LOCK
DELIBERATION DOCKET: ROUND 32 PRESIDENTIAL DEBATE

The cross-rebuttals from Stage 2 are now recorded:

=== STAGE 2 REBUTTAL: GPT-5.6 SOL PRO ===
{cache.get('stage2_sol_pro', '')[:10000]}

=== STAGE 2 REBUTTAL: CLAUDE OPUS 5 ===
{cache.get('stage2_opus5', '')[:10000]}

=== STAGE 2 REBUTTAL: CLAUDE FABLE 5.1 ===
{cache.get('stage2_fable51', '')[:10000]}

MANDATE FOR STAGE 3:
1. Reconcile all disputes, accept verified critiques, and state explicit concessions.
2. Formulate the final consensus specifications for:
   - UDP GSO and UDP GRO Go implementation (cmsg level SOL_UDP, segment size validation, individual packet AEAD encryption before batching).
   - Socket buffer sizing (16 MB SO_RCVBUF / SO_SNDBUF, rmem_max / wmem_max sysctls).
   - Mobile Client Fast-Path: Android TUN non-blocking read/write loops, descriptor ownership, and untimed partial wake lock.
   - Double VPN routing on aicore: dynamic route lookups for Kansas Core, Canada ca1, Germany de1, and Spain, TCPMSS clamping to PMTU, and FQ qdisc pacing.
   - Ingress multiprotocol demux on aicore (Winn v3, Winn v1 AWG, XRay fallback).
3. Confirm whether any technical disagreement remains. Lock in your final vote.
4. Strictly ZERO em dashes or en dashes.
5. Ban AI cliches: delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary.
"""


def execute_stage3(cache: dict[str, str]):
    print("\n--- STAGE 3: PARALLEL SYNTHESIS & POSITION LOCK ---")
    prompt = build_stage3_prompt(cache)
    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        if "stage3_sol_pro" not in cache or not cache["stage3_sol_pro"]:
            print("[Podium 2: GPT-5.6 Sol Pro] Dispatching Synthesis (flex xhigh)...", flush=True)
            tasks["stage3_sol_pro"] = executor.submit(
                query_openrouter_model, "openai/gpt-5.6-sol-pro", prompt, SYSTEM_SOL
            )
        else:
            print(f"[Podium 2: GPT-5.6 Sol Pro Synthesis] Cached ({len(cache['stage3_sol_pro'])} bytes)")

        if "stage3_opus5" not in cache or not cache["stage3_opus5"]:
            print("[Podium 3: Claude Opus 5] Dispatching Synthesis (xhigh)...", flush=True)
            tasks["stage3_opus5"] = executor.submit(
                query_claude_cli, "opus", prompt, SYSTEM_OPUS, "xhigh"
            )
        else:
            print(f"[Podium 3: Claude Opus 5 Synthesis] Cached ({len(cache['stage3_opus5'])} bytes)")

        if "stage3_fable51" not in cache or not cache["stage3_fable51"]:
            print("[Podium 4: Claude Fable 5.1] Dispatching Synthesis (high)...", flush=True)
            tasks["stage3_fable51"] = executor.submit(
                query_claude_cli, "claude-fable-5-1", prompt, SYSTEM_FABLE, "high"
            )
        else:
            print(f"[Podium 4: Claude Fable 5.1 Synthesis] Cached ({len(cache['stage3_fable51'])} bytes)")

        future_to_key = {future: key for key, future in tasks.items()}
        for future in concurrent.futures.as_completed(future_to_key):
            key = future_to_key[future]
            result = future.result()
            update_cache(key, result)
            cache[key] = result
            filename = f"debate_round32_{key}.md"
            with open(DOCS_EVIDENCE / filename, "w", encoding="utf-8") as f:
                f.write(f"# Stage 3 Synthesis: {key}\n\n{result}\n")
            print(f"-> {key} completed and written to {filename} ({len(result)} bytes)", flush=True)

    print("\nStage 3 Synthesis Complete.\n")


def main():
    print("=== STARTING WINTHOS FOUR-AI PRESIDENTIAL DEBATE COUNCIL (ROUND 32) ===")
    print("Targets: Single VPN 1000-2000 Mbps, Double VPN 500-1500 Mbps via aicore 1st Hop")
    print("Podiums: Antigravity, GPT-5.6 Sol Pro, Claude Opus 5, Claude Fable 5.1")
    print("Mode: TRUE PARALLEL EXECUTION (concurrent.futures)\n")

    cache = load_cache()

    # Stage 1: Parallel Independent Submissions
    execute_stage1(cache)

    # Stage 2: Parallel Adversarial Cross-Rebuttals
    execute_stage2(cache)

    # Stage 3: Parallel Synthesis & Position Lock
    execute_stage3(cache)

    print("\n=== ALL DEBATE STAGES 1-3 COMPLETE ===")
    print("Ready for Council Chair Stage 4 Treaty Ratification.\n")


if __name__ == "__main__":
    main()
