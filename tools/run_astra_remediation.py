#!/usr/bin/env python3
"""Run Astra (gpt-6-astra) via Codex CLI to fix all verified Round 4 defects in /Users/owner/xprize/winsvpnv3.

Usage:
    python3 tools/run_astra_remediation.py
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
LOG_PATH = Path("/tmp/astra_remediation.log")
STREAM_PATH = Path("/tmp/astra_remediation_stream.jsonl")

REMEDIATION_PROMPT = """You are Astra (gpt-6-astra), the lead security engineer and remediation architect for the WinsVPN ecosystem.

Your mission: Fix all verified defects discovered during the Round 4 Tripartite Deep Audit directly in the repository at /Users/owner/xprize/winsvpnv3.
You have full write access and execution privileges in this workspace.

MANDATORY EXECUTION RULES:
1. NEVER use em dashes (—) or en dashes (–). Use colons, commas, periods, or parentheses instead.
2. Ban AI cliches: delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary.
3. Code completeness: NEVER use ellipsis comments or placeholders (no '// ... rest of code', no '/* same as before */'). Provide 100% complete, compilable, production-ready replacement code or exact targeted diffs.
4. Surgical modifications: Modify ONLY the necessary lines and functions. Preserve existing architecture and formatting.
5. Verification: Proactively run commands to verify your changes. You must run:
   - flutter analyze --no-pub
   - python3 server/test_control_plane_deepseek_round2.py
   - python3 tools/website_security_audit.py

TARGET DEFECTS TO REMEDIATE:

1. Control Plane Single-Use Activation Key Consumption:
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Location: _verify_account_impl (around line 19870-19910)
   - Bug: require_verify_authorization returns "enrollment" or "device", but the return value is discarded and verify_and_consume_activation_secret(conn, acc, presented) is never called. This allows activation keys to be replayed across multiple devices.
   - Fix:
     In require_verify_authorization:
       authorization_kind = require_verify_authorization(...)
     When authorization_kind == "enrollment":
       presented = fastapi_request.headers.get("x-wins-activation", "").strip()
       if not verify_and_consume_activation_secret(conn, acc, presented):
           raise HTTPException(
               status_code=401,
               detail="Activation key is invalid, expired, or already used.",
           )

2. Offload Blocking Control Plane Operations to Worker Threads:
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Location: wait_for_core_assignment_ready, payment_redirect, render_referral_landing, _verify_account_impl, free_status, verify_free_access
   - Bug: Synchronous SQLite and blocking time.sleep operations run on the FastAPI event loop, blocking concurrent async requests.
   - Fix: Wrap synchronous blocking logic in sync helper functions and call them using `await asyncio.to_thread(_helper_sync, ...)`.

3. Pseudonymize Untrusted Account Identifier in Verify Logs:
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Location: _verify_account_impl (around line 19680)
   - Bug: logger.info prints raw login.account_number before authorization, allowing log injection via newlines.
   - Fix: Log account_hash=security_event_hash(normalize_account_number(login.account_number)).

4. Linux Child Engine Pipe Teardown Deadlock and SIGPIPE:
   - Files:
     * linux/runner/main.cc
     * linux/runner/linux_winn_host.cc
     * linux/runner/linux_winn3_host.cc
   - Bug: Blocking write() to engine stdin deadlocks UI thread when child pipe is full. Unhandled SIGPIPE terminates the Flutter process.
   - Fix:
     * In linux/runner/main.cc: add #include <csignal> and `std::signal(SIGPIPE, SIG_IGN);` in main().
     * In linux/runner/linux_winn_host.cc and linux/runner/linux_winn3_host.cc:
       Implement non-blocking WriteEnginePipeAll(int fd, const uint8_t* data, size_t size) using fcntl(O_NONBLOCK) and poll() with a 5000ms deadline. Use WriteEnginePipeAll for child stdin writes instead of WriteAll.

5. Android minSdk and Native Key-Custody Annotations:
   - Files:
     * android/app/build.gradle.kts
     * android/app/src/main/kotlin/org/winsvpn/app/WinnV3Keys.kt
     * android/app/src/main/AndroidManifest.xml
   - Bug: minSdk = 24 is below the java.nio.file floor (API 26), causing lint errors and potential crashes on API 24/25. Native methods in WinnV3Keys.kt lack @RequiresApi(Build.VERSION_CODES.R). ProfileInstallReceiver triggers MissingClass on removal.
   - Fix:
     * In android/app/build.gradle.kts: set minSdk = 26.
     * In android/app/src/main/kotlin/org/winsvpn/app/WinnV3Keys.kt:
       Add imports for android.os.Build, androidx.annotation.ChecksSdkIntAtLeast, androidx.annotation.RequiresApi.
       Annotate nativeDirOpsAvailable() with @ChecksSdkIntAtLeast(api = Build.VERSION_CODES.R).
       Annotate nativeBindDirectory, nativeBindStaleDirectory, nativeCreateExclusive, nativeEntryHasPlaintext, nativeBindStaleChild, openHeld, duplicateCloexec with @RequiresApi(Build.VERSION_CODES.R).
     * In android/app/src/main/AndroidManifest.xml:
       Add tools:ignore="MissingClass" to ProfileInstallReceiver removal.

6. Shared Dart Conflicting Protocol Version Alias Conflict:
   - Files:
     * lib/winn_protocol_dispatch.dart
     * lib/main.dart
   - Bug: _normalizeVpnConfig drops conflicting protocol_version / protocolversion aliases using first-wins lookup before strict anti-downgrade validation can reject the mismatch.
   - Fix:
     * In lib/winn_protocol_dispatch.dart: expose strictWinnProtocolVersionForTunnelConfig(config) and copyWinnProtocolVersionAliases(dest: dest, raw: raw) that copies all present version keys into dest.
     * In lib/main.dart: use copyWinnProtocolVersionAliases and strictWinnProtocolVersionForTunnelConfig to fail closed on alias conflict.

7. Apple Proof-Stage Engine Stop Ownership:
   - Files:
     * ios/PacketTunnel/PacketTunnelProvider.swift
     * macos/PacketTunnel/PacketTunnelProvider.swift
   - Bug: Proving-stage engine and datapath objects are nil during probe convergence and are not registered in stopTunnel.
   - Fix:
     Add provingPacketEngine and provingWinn3Datapath properties to both providers. Register them under lifecycleGate before convergence, and cancel/stop them in stopTunnel.

8. Windows Protected Named Pipe Prefix:
   - File: windows/runner/windows_tunnel_service_protocol.h
   - Bug: Fixed pipe name \\\\.\\pipe\\WinsVPN.TunnelManager.v1 can be pre-created by unprivileged interactive users when the service is stopped.
   - Fix: Use protected prefix:
     constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\ProtectedPrefix\\Administrators\\WinsVPN.TunnelManager.v1";

Execute these repairs now. Run tests to confirm all verifications pass cleanly.
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
                            print(f"[Astra Reasoning] {text[:120]}...", flush=True)
                    elif itype == "agent_message":
                        text = item.get("text", "")
                        if text:
                            parsed["messages"].append(text)
                            print(f"[Astra Message] {text[:160]}...", flush=True)
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
    print("Launching Astra (gpt-6-astra) Remediation via Codex CLI...", flush=True)
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
