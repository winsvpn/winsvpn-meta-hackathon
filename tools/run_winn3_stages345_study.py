#!/usr/bin/env python3
"""Run Independent Winn Protocol v3 Stages 3, 4, 5 Systems Study via Codex CLI.

Models engaged:
- Astra: gpt-6-astra (extra high reasoning)
- 5.6 Sol: gpt-5.6-sol (extra high reasoning)

Workspaces:
- /Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra
- /Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/sol

Target:
Implement and verify Stages 3, 4, and 5 of the Winn Protocol v3 performance roadmap:
- Stage 3: Socket Lifetime & UDP Batching (recvmmsg/sendmmsg, UDP GSO/GRO)
- Stage 4: Native Host TUN Bridges (Apple batched packet arrays, Android zero-copy TUN, Windows direct ring)
- Stage 5: Multi-Core Parallel Crypto Execution (ordered workers, monotonic nonces, epoch rekey barriers)
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
STREAM_DIR = Path(os.environ.get("SPEED_STUDY_STREAM_DIR", "/tmp/winn3_stages345_streams"))
STREAM_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_TIMEOUT_SECONDS = int(os.environ.get("SPEED_STUDY_TIMEOUT", "21600"))

MODELS = [
    # (key, model slug, display name, lane directory name, report file name)
    ("astra", "gpt-6-astra", "Astra", "astra", "winn3_stages345_astra_study.md"),
    ("sol", "gpt-5.6-sol", "5.6 Sol", "sol", "winn3_stages345_sol_study.md"),
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
        for item in ["config", "HEAD", "description"]:
            p = REPO_ROOT / ".git" / item
            if p.exists():
                shutil.copy2(p, dst_git / item)
    if src_index.exists() and dst_git.is_dir():
        shutil.copy2(src_index, dst_git / "index")
        print(f"Lane {lane} .git/index synchronized.", flush=True)
    print(f"Lane {lane} synchronized successfully.", flush=True)
    return dst


def build_stages345_prompt(model_name: str, lane_dir: Path, out_path: Path) -> str:
    return f"""You are {model_name}, conducting an exhaustive systems engineering and implementation study for Stages 3, 4, and 5 of the Winn Protocol v3 performance roadmap in {lane_dir}.

MISSION CONTEXT:
Phases 1 and 2 of the Winn Protocol v3 wire-speed parity roadmap are successfully completed and verified:
- demuxPRF and replay token verification: 0 B/op, 0 allocs/op, 12.70 Mpps at 78 ns/op.
- Datapath crypto and session buffers: SealInto, OpenInto, OpenAtInto, pool reuse, driver/loop scratch buffers: 0 B/op, 0 allocs/op, 532.86 MB/s (Apple M5 Max single core).
- All race tests pass clean under go test -race ./winn3/...

However, end-to-end throughput in the Win's VPN client app (on physical devices) is currently capped around 200+ Mbps (~25 MB/s) due to three remaining system-level bottlenecks:
1. Kernel syscall context switching (single packet read/write per syscall on UDP and TUN).
2. Native host bridge impedance (packet copying across Kotlin FileInputStream/ArrayBlockingQueue on Android, singleton Swift readPackets/writePackets calls on Apple, and loopback UDP relay on Windows).
3. Single-threaded crypto serialization (all encryption and decryption serialized in single read/write loops).

YOUR MISSION FOR STAGES 3, 4, AND 5:
Provide the authoritative implementation architecture, exact compilable code diffs, and verification suites for:

STAGE 3: SOCKET LIFETIME & UDP BATCHING (recvmmsg / sendmmsg, UDP GSO / GRO):
- Design and implement a zero-allocation BatchCarrier interface in winn_protocol_experimental/winn3/carrier/:
  * BatchMsg descriptor struct holding slice buffers, remote addr, flags, and byte counts.
  * RecvBatch(ctx context.Context, msgs []BatchMsg) (int, error) and SendBatch(ctx context.Context, msgs []BatchMsg) (int, error).
  * Implementation on Linux / Android / Darwin utilizing golang.org/x/net/ipv4 and ipv6 PacketConn.ReadBatch / WriteBatch or reviewed raw recvmmsg / sendmmsg.
  * Integration into winn3/driver/loop.go: readLoop and drain batching up to 16/32 packets per syscall.
  * Linux UDP_SEGMENT (GSO) and GRO receive handling, preserving exact independently authenticated Winn datagrams and 65,507-byte IPv4 ceilings.
  * Removal of per-packet timer cancellation allocation by binding cancellation to socket generation lifetime.

STAGE 4: NATIVE HOST TUN BRIDGES (Apple, Android, Windows):
- Apple (macOS & iOS):
  * In apple/WinsTunnelCore/WinsWinn3Datapath.swift and winn_protocol_experimental/cdatapath/winn_datapath_winn3.go:
  * Replace single-packet WinsWinn3EnqueuePacket with batched ABI WinsWinn3EnqueuePackets accepting an array of packet descriptors and count in one foreign call.
  * Implement batched inbound dequeue returning an array of packets for a single writePackets([Data], withProtocols: [NSNumber]) call.
- Android:
  * In android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt and WinnV3Bridge.kt:
  * Eliminate the per-packet FileInputStream.read() -> ArrayBlockingQueue<ByteArray> -> framed socket IPC bottleneck.
  * Provide batched framed buffer reads/writes or direct native TUN FD ownership.
- Windows:
  * In windows/winn3_engine/relay.go and main_windows.go:
  * Eliminate the inner-IP loopback UDP relay that shuttles packets between Wintun and the Winn engine.
  * Provide direct ring buffer handoff or in-process memory queue.

STAGE 5: MULTI-CORE PARALLEL CRYPTO EXECUTION:
- In winn_protocol_experimental/winn3/session/driver.go and winn3/driver/loop.go:
  * Worker pool bounded by runtime.GOMAXPROCS(0) for parallel encryption and decryption.
  * Strict sequential counter reservation on the main session thread (preserves monotonic nonces, anti-replay window, and byte rekey accounting).
  * Parallel ChaCha20-Poly1305 Seal/Open execution.
  * Strict ordered ticket completion emission into carrier batch queues (preserves arrival/emission ordering).
  * Strict epoch rekey barrier: flush and retire old-epoch workers before installing new epoch keys.

REPORT FORMAT REQUIREMENTS:
- Save your complete findings, architecture, and exact code diffs directly to {out_path}.
- Use clean Markdown with pure LF line endings.
- Never use em dashes or en dashes (use colons, commas, periods, or parentheses instead).
- Ban AI clichés (avoid "delve", "testament", "tapestry", "crucial", "leverage", "furthermore", "moreover", "in summary").
- Provide complete, compilable Go, Swift, and Kotlin code diffs with exact file paths and line citations.
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
    report_text = f"# Winn Protocol v3 Stages 3, 4, 5 Systems Engineering Study: {model_name}\n\n"
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


def run_stages345_study(key: str, model_slug: str, model_name: str, lane_name: str, report_name: str) -> None:
    lane_dir = sync_speed_lane(lane_name)
    out_path = EVIDENCE_DIR / report_name
    lane_report_path = lane_dir / "docs" / "evidence" / report_name
    lane_report_path.parent.mkdir(parents=True, exist_ok=True)
    stream_path = STREAM_DIR / f"{key}_stream.jsonl"
    stderr_path = STREAM_DIR / f"{key}_stderr.log"
    timeout_seconds = DEFAULT_TIMEOUT_SECONDS

    print(f"[{model_name}] Starting Winn v3 Stages 3, 4, 5 study using {model_slug} with extra high reasoning...", flush=True)
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

        prompt = build_stages345_prompt(model_name, lane_dir, lane_report_path)
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
        print(f"[{model_name}] Stages 3, 4, 5 study {status}. Report: {out_path} ({n_chars} content chars, "
              f"{len(parsed['reasoning'])} reasoning chunks)", flush=True)

    except Exception as exc:
        if proc is not None and proc.poll() is None:
            proc.kill()
        print(f"[{model_name}] Execution error: {exc}", flush=True)
        _write_report(out_path, model_name, model_slug, lane_report_path, parsed, None, timeout_seconds,
                      False, failure_note=f"execution failed: {exc}")


def main() -> None:
    print("Launching Winn Protocol v3 Stages 3, 4, 5 Systems Study (Astra & 5.6 Sol)...", flush=True)
    threads = []
    for key, model_slug, model_name, lane_name, report_name in MODELS:
        t = threading.Thread(
            target=run_stages345_study,
            args=(key, model_slug, model_name, lane_name, report_name),
            daemon=False,
        )
        t.start()
        threads.append((model_name, t))
        time.sleep(2)

    for model_name, t in threads:
        t.join()

    print("All Stages 3, 4, 5 studies finished. Check docs/evidence for reports.", flush=True)


if __name__ == "__main__":
    main()
