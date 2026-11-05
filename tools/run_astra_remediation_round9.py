#!/usr/bin/env python3
"""Run Astra (gpt-6-astra) via Codex CLI to fix all verified Round 9 defects in /Users/owner/xprize/winsvpnv3.

Usage:
    python3 tools/run_astra_remediation_round9.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LOG_PATH = Path("/tmp/astra_remediation_round9.log")
STREAM_PATH = Path("/tmp/astra_remediation_round9_stream.jsonl")

REMEDIATION_PROMPT = """You are Astra (gpt-6-astra), the lead security engineer and remediation architect for the WinsVPN ecosystem.

Your mission: Fix all verified defects discovered during the Round 9 Tripartite Deep Audit directly in the repository at /Users/owner/xprize/winsvpnv3.
You have full write access and execution privileges in this workspace.

MANDATORY EXECUTION RULES:
1. NEVER use em dashes (—) or en dashes (–). Use colons, commas, periods, or parentheses instead.
2. Ban AI cliches: delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary.
3. Code completeness: NEVER use ellipsis comments or placeholders (no '// ... rest of code', no '/* same as before */'). Provide 100% complete, compilable, production-ready replacement code or exact targeted diffs.
4. Surgical modifications: Modify ONLY the necessary lines and functions. Preserve existing architecture and formatting.
5. Pure LF line endings (0 CRLF).
6. Verification: Proactively run commands to verify your changes. You must run:
   - flutter analyze --no-pub
   - flutter test --no-pub
   - python3 server/test_control_plane_deepseek_round2.py
   - python3 server/test_control_plane_round4.py
   - python3 server/test_control_plane_round5.py
   - python3 server/test_control_plane_round6.py
   - python3 server/test_control_plane_round7.py
   - python3 server/test_control_plane_round8.py
   - python3 server/test_winn3_descriptor_hub.py
   - python3 server/test_account_deletion_hub.py
   - python3 tools/website_security_audit.py
   - sh tools/verify_rulings.sh
   - python3 tools/verify_apple_method_channel_contract.py
   - python3 tools/test_apple_standalone_v3_wiring.py
   - cd winn_protocol_experimental && go test ./...

TARGET DEFECTS TO REMEDIATE:

1. Winn v3 Gateway Active Authority Enforcement (Astra A9-01):
   - Files:
     * winn_protocol_experimental/cmd/winn3-gateway/peer_registry.go
     * winn_protocol_experimental/cmd/winn3-gateway/forward.go
     * winn_protocol_experimental/cmd/winn3-gateway/main.go
   - Fix:
     * In peerRegistry: Add notAfter map[[32]byte]int64, refreshMu sync.Mutex, lastCheck time.Time, lastFile os.FileInfo, refreshErr error.
     * Add refresh() error that checks mtime and size of registry file with 1-second rate limit.
     * In innerForPeer: check r.refresh() != nil, check expires, present := r.notAfter[key], and reject if !present || (expires != 0 && time.Now().Unix() >= expires).
     * In forwardTable: add registry *peerRegistry field. In lookup(addr), if t.registry != nil, get session := loop.Session(), call expected, allowed := t.registry.innerForPeer(session.PeerStatic()), and if !allowed || expected != addr, return nil, false.
     * In main.go: wire table.registry = registry before starting tun.

2. Server Control Plane: Expiration Selection vs Enforcement Synchronization (Astra A9-02):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Location: expire_account_runtime_if_due and sweep_expired_account_runtime (lines ~18367-18465)
   - Fix:
     * In expire_account_runtime_if_due: change utcnow() > expires_at to utcnow() >= expires_at.
     * In sweep_expired_account_runtime: define local expiration_due(value) -> int calling parse_iso_datetime(value) and returning int(expires_at is None or expires_at <= now). Register conn.create_function("wins_account_expiration_due", 1, expiration_due, deterministic=True). Replace lexical comparison with wins_account_expiration_due(u.expiration_date)=1.

3. Server Control Plane: Rollback Standalone v3 Admission on Registry Publication Failure (Astra A9-04):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Location: _verify_account_sync around line 20930-20955
   - Fix: Do not call conn.commit() before sync_winn3_registry_to_node. If sync_winn3_registry_to_node fails, call conn.rollback(), then mark node management status failed in a separate transaction, and raise HTTPException 503. Only call conn.commit() when publication succeeds.

4. Server Control Plane: Offload Event-Loop Blocking Operations (Astra A9-06, Daybreak DB-05, Sol SOL-04):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Locations:
     * site_ai_chat: change if site_rate_limited(...) to if await asyncio.to_thread(site_rate_limited, request, limit=20):
     * Check any remaining async def routes that execute synchronous SQLite or blocking network operations and offload them via await asyncio.to_thread(...) or ensure thread pool execution.

5. Linux Runner: Monotonic Deadline & Process-Group Containment in RunArgv (Astra A9-05, Sol SOL-05):
   - File: linux/runner/linux_tunnel_backend.cc
   - Location: RunArgv (lines ~326-455)
   - Fix:
     * Add timeout parameter with 15-second default: std::chrono::milliseconds timeout = std::chrono::seconds(15).
     * Set POSIX_SPAWN_SETPGROUP with posix_spawnattr_setpgroup(&attributes, 0).
     * Set O_NONBLOCK on pipe_fds[0].
     * Use monotonic deadline = steady_clock::now() + timeout.
     * Use poll() and waitpid(pid, &status, WNOHANG) in a non-blocking poll loop.
     * If deadline reached, set timed_out = true, send kill(-pid, SIGTERM), poll with 2-second grace period, if still not reaped send kill(-pid, SIGKILL), reap with waitpid, and set exit_status = 124.

6. iOS Memory Watchdog: Strict 15 MiB Physical Footprint Ceiling (Daybreak DB-04, Sol SOL-03):
   - File: ios/PacketTunnel/PacketTunnelProvider.swift
   - Fix:
     * Define winnStrictPhysicalFootprintCeilingBytes = 15 * 1024 * 1024 and winnMemoryWatchdogIntervalSeconds = 1.0.
     * Implement startWinnMemoryWatchdog(lifecycleToken:) and stopWinnMemoryWatchdog().
     * Periodically sample physicalFootprintBytes(). If footprint >= 15 MiB, call cancelTunnelWithError with code 1038 and stop watchdog.
     * Start watchdog when session starts; stop watchdog on teardown and cancellation.

7. Server Control Plane: Legacy SPA Window Firewall Custody (Daybreak DB-06, Sol SOL-08):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Fix: In legacy SPA handling, direct rules to WINVPN-HUB-INPUT instead of raw INPUT. Use systemd-run with transient timer for 20s expiry or offloaded async timer with proper cleanup.

8. Apple Wiring Test Oracle Alignment (Daybreak DB-03):
   - File: tools/test_apple_standalone_v3_wiring.py
   - Fix: Update assertion from validateUniqueWinnNodeBindings to validateUniqueWinnSecurityBindings.

Execute all repairs now, run all test suites, and report the results.
"""


def _stream_reader(stream, sink_path: Path, parsed: dict) -> None:
    try:
        with open(sink_path, "w", encoding="utf-8") as sink:
            for raw_line in stream:
                sink.write(raw_line)
                if not raw_line.endswith("\n"):
                    sink.write("\n")
                sink.flush()
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except Exception:
                    continue
                t = data.get("type")
                if t == "item.completed":
                    item = data.get("item", {})
                    itype = item.get("type")
                    if itype == "reasoning":
                        text = item.get("text", "")
                        if text:
                            parsed["reasoning"].append(text)
                            print(".", end="", flush=True)
                    elif itype == "agent_message":
                        text = item.get("text", "")
                        if text:
                            parsed["messages"].append(text)
                            print(f"\n[Astra] {text[:120]}...", flush=True)
                elif t == "turn.completed":
                    parsed["usage"] = data.get("usage", {})
    except Exception as exc:
        parsed["error"] = repr(exc)
    finally:
        try:
            stream.close()
        except Exception:
            pass


def main() -> None:
    print("================================================================", flush=True)
    print("Launching Astra (gpt-6-astra) Round 9 Remediation via Codex CLI...", flush=True)
    print("Repository Root:", REPO_ROOT, flush=True)
    print("Log Path:", LOG_PATH, flush=True)
    print("Stream Path:", STREAM_PATH, flush=True)
    print("================================================================", flush=True)

    cmd = [
        "codex", "exec",
        "-m", "gpt-6-astra",
        "-c", 'model_reasoning_effort="xhigh"',
        "-c", 'model_reasoning_summary="detailed"',
        "--dangerously-bypass-approvals-and-sandbox",
        "--json",
        "--ephemeral",
        "--skip-git-repo-check",
        "-C", str(REPO_ROOT),
        "-"
    ]

    parsed = {"reasoning": [], "messages": [], "usage": {}}
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    t_stdout = threading.Thread(target=_stream_reader, args=(proc.stdout, STREAM_PATH, parsed), daemon=True)
    t_stdout.start()

    proc.stdin.write(REMEDIATION_PROMPT)
    proc.stdin.close()

    try:
        ret = proc.wait(timeout=10800)
    except subprocess.TimeoutExpired:
        print("[Astra] Timeout expired. Killing process.", flush=True)
        proc.kill()
        ret = proc.wait()

    t_stdout.join(timeout=30)
    print(f"[Astra] Remediation finished with exit code {ret}.", flush=True)
    if parsed["messages"]:
        print("\n--- Astra Final Output ---", flush=True)
        print(parsed["messages"][-1], flush=True)


if __name__ == "__main__":
    main()
