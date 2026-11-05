#!/usr/bin/env python3
"""Run Astra (gpt-6-astra) via Codex CLI to fix all verified Round 6 defects in /Users/owner/xprize/winsvpnv3.

Usage:
    python3 tools/run_astra_remediation_round6.py
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
LOG_PATH = Path("/tmp/astra_remediation_round6.log")
STREAM_PATH = Path("/tmp/astra_remediation_round6_stream.jsonl")

REMEDIATION_PROMPT = """You are Astra (gpt-6-astra), the lead security engineer and remediation architect for the WinsVPN ecosystem.

Your mission: Fix all verified defects discovered during the Round 6 Tripartite Deep Audit directly in the repository at /Users/owner/xprize/winsvpnv3.
You have full write access and execution privileges in this workspace.

MANDATORY EXECUTION RULES:
1. NEVER use em dashes (—) or en dashes (–). Use colons, commas, periods, or parentheses instead.
2. Ban AI cliches: delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary.
3. Code completeness: NEVER use ellipsis comments or placeholders (no '// ... rest of code', no '/* same as before */'). Provide 100% complete, compilable, production-ready replacement code or exact targeted diffs.
4. Surgical modifications: Modify ONLY the necessary lines and functions. Preserve existing architecture and formatting.
5. Verification: Proactively run commands to verify your changes. You must run:
   - flutter analyze --no-pub
   - flutter test --no-pub
   - python3 server/test_control_plane_deepseek_round2.py
   - python3 server/test_control_plane_round4.py
   - python3 server/test_control_plane_round5.py
   - python3 server/test_winn3_descriptor_hub.py
   - python3 tools/website_security_audit.py

TARGET DEFECTS TO REMEDIATE:

1. Android: Refuse Xray Before Child Launch and Side Effects (SOL-02):
   - File: android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt
   - Defect: onStartCommand derives xrayEnabled near line 1181 and starts the Xray child process via startXrayTransportIfNeeded(config) near line 1224 before reaching the later check that refuses an unprotected Xray carrier socket.
   - Fix:
     Move the universal unsupported-carrier refusal BEFORE startXrayTransportIfNeeded(config):
     if (xrayEnabled) {
         logError("Refusing Xray mode before carrier launch because its socket is not individually protected. No DNS lookup or carrier process was started.")
         refuseWinn3Start(winn3Requested, winn3StartToken, winn3StartGeneration)
         clearRestartConfig()
         executeTunnelTeardown()
         return START_NOT_STICKY
     }
     Remove the late check around line 1433 so refusal happens unconditionally before any DNS lookup or process launch.

2. Android: Guard ACTION_CONNECT Against Timed-Out Teardown (SOL-03):
   - File: android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt
   - Defect: For ACTION_CONNECT, the service awaits teardown up to 2500 ms via awaitTeardown(2500L), but discards the return value and proceeds to reset mutable state while the prior teardown thread may still be running.
   - Fix:
     if (action == "ACTION_CONNECT") {
         if (tearingDown || isTeardownInProgress()) {
             Log.i("WinsVpnService", "ACTION_CONNECT received while teardown is in flight; awaiting completion.")
             if (!awaitTeardown(2500L)) {
                 Log.e(
                     "WinsVpnService",
                     "Refusing ACTION_CONNECT because the prior teardown did not finish within 2500 ms.",
                 )
                 return START_NOT_STICKY
             }
         }
     }

3. Linux: Clean Native Tunnel Teardown on Normal and Signal Exit (LNX-01 / SOL-04):
   - Files:
     * linux/runner/linux_tunnel_backend.h
     * linux/runner/linux_tunnel_backend.cc
     * linux/runner/my_application.cc
     * linux/runner/main.cc
   - Defect: Classical AWG, Xray, cgroups, and firewall rules survive normal window exit, SIGINT, or SIGTERM because StopTunnel() is only called from the Flutter stopTunnel method channel.
   - Fix:
     * In linux_tunnel_backend.h: declare bool ShutdownLinuxTunnelBackend(std::string* error);
     * In linux_tunnel_backend.cc: track g_tunnel_session_committed (set to true on successful StartTunnel, false on successful StopTunnel). Implement:
       bool ShutdownLinuxTunnelBackend(std::string* error) {
           if (!g_tunnel_session_committed) return true;
           return StopTunnel(error);
       }
     * In my_application.cc: in my_application_shutdown(GApplication* application):
       std::string error;
       if (!ShutdownLinuxTunnelBackend(&error)) {
           g_warning("Linux tunnel shutdown cleanup failed: %s", error.c_str());
       }
     * In main.cc: include <glib-unix.h>. Implement QuitApplicationFromUnixSignal(gpointer user_data) that calls g_application_quit(G_APPLICATION(user_data)). Register g_unix_signal_add for SIGINT and SIGTERM with app before g_application_run.

4. Control Plane: Offload Logout Handlers to Worker Threads (DB-01):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Defect: /free/logout and /logout are async def endpoints that run synchronous with get_db() transactions directly on the FastAPI event loop, blocking concurrent requests under contention.
   - Fix:
     Implement free_logout_device_sync and logout_device_sync helper functions.
     In /free/logout: parse request body, then call await asyncio.to_thread(free_logout_device_sync, background_tasks, request, dev).
     In /logout: parse request body, then call await asyncio.to_thread(logout_device_sync, background_tasks, request, acc, dev).

5. Control Plane: Validate BTCPay Checkout URL Origin (SOL-05):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Defect: _crypto_create_invoice_sync accepts any checkoutLink from the BTCPay response without checking that its HTTPS origin matches the configured BTCPAY_URL.
   - Fix:
     Implement validated_btcpay_checkout_url(raw_url: str) -> str:
     Parse raw_url, check scheme == 'https', no userinfo, valid hostname, and verify normalized origin matches normalized BTCPAY_URL. If mismatch or invalid, raise ValueError and log warning.

6. Control Plane: Deterministic SQLite Close for Security Events (SOL-07):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Defect: with sqlite3.connect(SECURITY_EVENTS_DB) in record_security_event and update_security_event_email_status commits transactions but does not close connections deterministically.
   - Fix:
     Import closing from contextlib.
     Use with closing(sqlite3.connect(SECURITY_EVENTS_DB, timeout=10)) as conn: with conn: in both functions.

7. Release and Test Assurance:
   - Ensure winn_protocol_experimental/internal/carrier/h3_receive_window_test.go is tracked in git.
   - Run flutter test --no-pub to verify 100% of Flutter/Dart unit tests pass.
   - Rebuild extension/dist/wins-vpn-companion-chrome.zip via python3 build.py chrome.

Execute all repairs now, run all verifications, and report the results.
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
                    elif itype == "agent_message":
                        text = item.get("text", "")
                        if text:
                            parsed["messages"].append(text)
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
    print("Launching Astra (gpt-6-astra) Round 6 Remediation via Codex CLI...", flush=True)
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
