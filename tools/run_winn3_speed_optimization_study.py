#!/usr/bin/env python3
"""Run Independent Winn Protocol v3 Speed Optimization Deep Study via Codex CLI.

Models engaged:
- Astra: gpt-6-astra (extra high reasoning)
- 5.6 Sol: gpt-5.6-sol (extra high reasoning)

Workspaces:
- /Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra
- /Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/sol

Target:
Boost Winn Protocol v3 throughput, latency, and CPU efficiency to match or
surpass AmneziaWG (AWG) wire-speed performance.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = REPO_ROOT / "docs" / "evidence"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

LANE_ROOT = Path("/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes")
STREAM_DIR = Path(os.environ.get("SPEED_STUDY_STREAM_DIR", "/tmp/winn3_speed_study_streams"))
STREAM_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_TIMEOUT_SECONDS = int(os.environ.get("SPEED_STUDY_TIMEOUT", "21600"))

MODELS = [
    # (key, model slug, display name, lane directory name, report file name)
    ("astra", "gpt-6-astra", "Astra", "astra", "winn3_speed_astra_study.md"),
    ("sol", "gpt-5.6-sol", "5.6 Sol", "sol", "winn3_speed_sol_study.md"),
]

EXCLUDES = [
    ".git",
    "build",
    ".dart_tool",
    "__pycache__",
    "*.pyc",
    ".wrangler",
    ".a12",
    "docs/evidence/*_round*",
    "docs/evidence/astra_*",
    "docs/evidence/round*",
    "docs/evidence/codex_*",
]


def sync_speed_lane(lane: str) -> Path:
    dst = LANE_ROOT / lane
    dst.mkdir(parents=True, exist_ok=True)
    cmd = ["rsync", "-a", "--delete"]
    for exc in EXCLUDES:
        cmd.extend(["--exclude", exc])
    cmd.extend([f"{REPO_ROOT}/", f"{dst}/"])
    print(f"Syncing {REPO_ROOT} -> {dst}...", flush=True)
    subprocess.run(cmd, check=True)
    src_index = REPO_ROOT / ".git" / "index"
    dst_git = dst / ".git"
    if not dst_git.exists() and (REPO_ROOT / ".git").exists():
        dst_git.mkdir(parents=True, exist_ok=True)
        # Copy minimal git structure for tools that inspect git
        for item in ["config", "HEAD", "description"]:
            p = REPO_ROOT / ".git" / item
            if p.exists():
                shutil.copy2(p, dst_git / item)
    if src_index.exists() and dst_git.is_dir():
        shutil.copy2(src_index, dst_git / "index")
        print(f"Lane {lane} .git/index synchronized.", flush=True)
    print(f"Lane {lane} synchronized successfully.", flush=True)
    return dst


def build_speed_prompt(model_name: str, lane_dir: Path, out_path: Path) -> str:
    return f"""You are {model_name}, conducting an exhaustive, high-reasoning systems engineering and performance optimization study on Winn Protocol v3 in {lane_dir}.

MISSION:
Our user is currently running Winn Protocol v1 (AmneziaWG primary, XRay fallback) because AmneziaWG (AWG) is significantly faster and achieves wire-speed throughput with near-zero CPU overhead.
The goal is to re-architect and optimize Winn Protocol v3 so that it becomes AS FAST AS AWG OR FASTER, while maintaining its post-quantum forward secrecy (ML-KEM-768), classical X25519 security, and anti-censorship properties.

YOUR TASK:
Inspect the Winn Protocol v3 codebase in {lane_dir}/winn_protocol_experimental/ (including winn3/driver, winn3/carrier, winn3/session, winn3/core, winn3/tun, winn3/gateway, and client bindings).
Analyze the throughput bottlenecks, memory allocations, CPU cycle consumers, locking contention, and syscall overheads that cause Winn v3 to lag behind AmneziaWG.
Produce an authoritative, deep technical study report with exact code diffs, architecture diagrams, benchmark comparisons, and implementation steps.

WRITE YOUR COMPLETE REPORT DIRECTLY TO:
{out_path}

KEY INVESTIGATION & OPTIMIZATION DOMAINS:

1. Zero-Allocation Data Path & GC Pressure Elimination:
   - Identify every per-packet heap allocation across winn3/core/session.go (Seal, openCounterLocked), winn3/carrier/udp.go (Recv, Send), winn3/driver/loop.go (drain, readLoop), and winn3/session/.
   - Detail how to eliminate per-packet allocations down to ZERO allocs/op using sync.Pool, contiguous pre-allocated packet rings, and in-place AEAD sealing/opening (aead.Seal(dst[:0], ...)).
   - Analyze memory cache locality, L1/L2 cache misses, and garbage collector pressure under 1 Gbps+ packet streams (90,000+ packets/sec).

2. Multi-Core Parallel Crypto Execution Pipelines:
   - WireGuard/AWG distributes packet encryption and decryption across GOMAXPROCS parallel worker goroutines while preserving sequential wire/TUN order using ring queues.
   - Winn v3 currently performs ChaCha20-Poly1305 encryption and decryption sequentially inside single readLoop and writeLoop goroutines under mutex locks (sendMu, recvMu).
   - Design a lock-free or low-overhead parallel worker pool architecture for Winn v3 that scales linearly across all CPU cores without breaking replay window ordering or epoch ratchet synchronizations.

3. Demux Token Generation & Replay Window Optimization:
   - demuxToken() in winn3/core/replay.go currently executes hmac.New(sha256.New, key) on EVERY packet, allocating hash objects and executing 2 SHA-256 compression blocks per packet.
   - Propose vectorized or precomputed alternatives (e.g. precomputed HMAC inner/outer state, SipHash/AES-NI/ChaCha pseudorandom function tokens, or hardware SHA-256 extensions).
   - In tokenWindow, replace the Go map[DemuxToken]uint64 with an O(1) cache-line-friendly circular bitmap or segmented ring filter, eliminating map locks and memory expansion.

4. Kernel I/O Batching & Syscall Overhead:
   - AWG uses UDP Generic Segmentation Offload (GSO) and Generic Receive Offload (GRO) to batch up to 64 packets into a single 64KB kernel syscall.
   - Winn v3 UDP carrier currently executes ReadFromUDP and WriteToUDP one packet at a time, with per-packet armRead/armWrite timer synchronization.
   - Design UDP batching using recvmmsg/sendmmsg (or golang.org/x/net/ipv4.PacketConn BatchReader/BatchWriter) and GSO/GRO support.

5. Client TUN/TAP and Platform Driver Integration:
   - Evaluate client TUN adapters across Android (VpnService fd), Windows (Wintun ring buffers), macOS (NetworkExtension packet arrays), and Linux.
   - Multi-queue TUN support and direct user-kernel memory ring mappings.

6. Concrete Benchmarks & Verification:
   - Provide concrete Go benchmark suites (in testing.B format) measuring throughput (MB/s), packet rate (Mpps), ns/op, B/op, and allocs/op.
   - Present exact, compilable Go code diffs for winn3/core, winn3/carrier, winn3/session, and winn3/driver.

REPORT FORMAT REQUIREMENTS:
- Save your complete findings and implementation plan to {out_path}.
- Use clean Markdown.
- Strict anti-AI formatting: pure LF, never use em dashes or en dashes (use colons, commas, periods, or parentheses instead).
- Ban AI filler words and hollow prose. Write direct engineering text.
- Provide exhaustive, production-grade technical depth with exact file paths and line citations.
"""


def _clean(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n").replace("\u2014", ": ").replace("\u2013", "-")


def _stream_reader(pipe, stream_path: Path, parsed: dict) -> None:
    with open(stream_path, "a", encoding="utf-8") as out:
        for line in iter(pipe.readline, ""):
            out.write(line)
            out.flush()
            line_str = line.strip()
            if not line_str:
                continue
            try:
                obj = json.loads(line_str)
                event_type = obj.get("type")
                if event_type == "item.reasoning.chunk":
                    chunk = obj.get("chunk", "")
                    if chunk:
                        parsed["reasoning"].append(chunk)
                elif event_type == "item.reasoning.delta":
                    delta = obj.get("delta", "")
                    if delta:
                        parsed["reasoning"].append(delta)
                elif event_type == "item.content.chunk":
                    chunk = obj.get("chunk", "")
                    if chunk:
                        parsed["messages"].append(chunk)
                elif event_type == "item.content.delta":
                    delta = obj.get("delta", "")
                    if delta:
                        parsed["messages"].append(delta)
                elif event_type == "response.done":
                    usage = obj.get("response", {}).get("usage", {})
                    if usage:
                        parsed["usage"] = usage
            except Exception:
                pass


def _write_report(out_path: Path, model_name: str, model_slug: str, lane_report_path: Path,
                  parsed: dict, returncode: int | None, timeout_seconds: int, timed_out: bool,
                  failure_note: str = "") -> int:
    content = ""
    if lane_report_path.exists():
        try:
            content = lane_report_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            pass

    if not content and parsed["messages"]:
        content = "".join(parsed["messages"])

    reasoning = "".join(parsed["reasoning"])
    clean_content = _clean(content)
    clean_reasoning = _clean(reasoning)

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    report_text = f"# Winn Protocol v3 Speed Optimization Deep Study: {model_name}\n\n"
    report_text += f"- **Model**: `{model_slug}` (extra high reasoning)\n"
    report_text += f"- **Completed**: {now_utc}\n"
    report_text += f"- **Exit code**: {returncode}\n"
    report_text += f"- **Wall clock limit**: {timeout_seconds}s (timed out: {timed_out})\n"
    if failure_note:
        report_text += f"- **Note**: {failure_note}\n"
    report_text += "\n"

    if clean_reasoning:
        report_text += f"## Reasoning Trace\n\n```\n{clean_reasoning}\n```\n\n"

    report_text += (
        "## Deep Study Report & Implementation Plan\n\n"
        + (clean_content if clean_content else "(no content captured; inspect stream log)")
        + "\n"
    )

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    return len(clean_content)


def run_speed_study(key: str, model_slug: str, model_name: str, lane_name: str, report_name: str) -> None:
    lane_dir = sync_speed_lane(lane_name)
    out_path = EVIDENCE_DIR / report_name
    lane_report_path = lane_dir / "docs" / "evidence" / report_name
    lane_report_path.parent.mkdir(parents=True, exist_ok=True)
    stream_path = STREAM_DIR / f"{key}_stream.jsonl"
    stderr_path = STREAM_DIR / f"{key}_stderr.log"
    timeout_seconds = DEFAULT_TIMEOUT_SECONDS

    print(f"[{model_name}] Starting Winn v3 speed study using {model_slug} with extra high reasoning...", flush=True)
    print(f"[{model_name}] Workspace: {lane_dir}", flush=True)
    print(f"[{model_name}] Stream log: {stream_path}", flush=True)

    if lane_report_path.exists():
        lane_report_path.unlink()

    cmd = [
        "codex", "exec",
        "-m", model_slug,
        "-c", "model_reasoning_effort=\"xhigh\"",
        "-c", "model_reasoning_summary=\"detailed\"",
        "--dangerously-bypass-approvals-and-sandbox",
        "--json",
        "--ephemeral",
        "--skip-git-repo-check",
        "-C", str(lane_dir),
        "-"
    ]

    parsed = {"reasoning": [], "messages": [], "usage": {}}
    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        reader = threading.Thread(
            target=_stream_reader, args=(proc.stdout, stream_path, parsed), daemon=True
        )
        reader.start()
        stderr_reader = threading.Thread(
            target=_stream_reader,
            args=(proc.stderr, stderr_path, {"reasoning": [], "messages": [], "usage": {}}),
            daemon=True,
        )
        stderr_reader.start()

        prompt = build_speed_prompt(model_name, lane_dir, lane_report_path)
        proc.stdin.write(prompt)
        proc.stdin.close()

        timed_out = False
        try:
            returncode = proc.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            print(f"[{model_name}] Timeout limit of {timeout_seconds}s reached. Terminating.", flush=True)
            proc.kill()
            returncode = proc.wait(timeout=120)

        reader.join(timeout=60)
        stderr_reader.join(timeout=30)

        n_chars = _write_report(out_path, model_name, model_slug, lane_report_path, parsed,
                                returncode, timeout_seconds, timed_out)
        status = "timed out" if timed_out else "completed"
        print(f"[{model_name}] Speed study {status}. Report: {out_path} ({n_chars} content chars, "
              f"{len(parsed['reasoning'])} reasoning chunks)", flush=True)

    except Exception as exc:
        if proc is not None and proc.poll() is None:
            proc.kill()
        print(f"[{model_name}] Execution error: {exc}", flush=True)
        _write_report(out_path, model_name, model_slug, lane_report_path, parsed, None, timeout_seconds,
                      False, failure_note=f"execution failed: {exc}")


def main() -> None:
    print("Launching Winn Protocol v3 Speed Optimization Deep Study (Astra & 5.6 Sol)...", flush=True)
    threads = []
    for key, model_slug, model_name, lane_name, report_name in MODELS:
        t = threading.Thread(
            target=run_speed_study,
            args=(key, model_slug, model_name, lane_name, report_name),
            daemon=False,
        )
        t.start()
        threads.append((model_name, t))
        time.sleep(2)  # brief stagger to avoid simultaneous disk contention

    for model_name, t in threads:
        t.join()

    print("All Winn Protocol v3 speed optimization studies finished. Check docs/evidence for reports.", flush=True)


if __name__ == "__main__":
    main()
