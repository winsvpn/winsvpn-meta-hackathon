#!/usr/bin/env python3
"""Run Astra (gpt-6-astra) via Codex CLI to fix all verified Round 8 defects in /Users/owner/xprize/winsvpnv3.

Usage:
    python3 tools/run_astra_remediation_round8.py
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
LOG_PATH = Path("/tmp/astra_remediation_round8.log")
STREAM_PATH = Path("/tmp/astra_remediation_round8_stream.jsonl")

REMEDIATION_PROMPT = """You are Astra (gpt-6-astra), the lead security engineer and remediation architect for the WinsVPN ecosystem.

Your mission: Fix all verified defects discovered during the Round 8 Tripartite Deep Audit directly in the repository at /Users/owner/xprize/winsvpnv3.
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
   - python3 server/test_winn3_descriptor_hub.py
   - python3 server/test_account_deletion_hub.py
   - python3 tools/website_security_audit.py
   - sh tools/verify_rulings.sh
   - python3 tools/verify_apple_method_channel_contract.py

TARGET DEFECTS TO REMEDIATE:

1. Browser Extensions: Rebuild Firefox and Edge extension packages (SOL-H2):
   - Command: python3 extension/build.py edge firefox
   - Verify:
     python3 extension/build.py --verify edge extension/dist/wins-vpn-companion-edge.zip
     python3 extension/build.py --verify firefox extension/dist/wins-vpn-companion-firefox.zip

2. Server Control Plane: Expiration Fail-Closed in Customer Exports (Astra A01):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Locations: active_core_assignment_payloads, winn3_peer_registry_document, resync_active_peers_to_node
   - Fix: Require successfully parsed future ISO datetime. If expires_at is None or expires_at <= now, continue/skip. In winn3_peer_registry_document, calculate not_after = int(expires_at.timestamp()) and remove fallback to 0.

3. Server Control Plane: Durable Device Revocation on All Deletion Paths (Astra A02):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Locations:
     * _verify_account_sync duplicate device replacement (lines ~20390, ~20410)
     * _verify_account_sync old_peer_to_remove (line ~20560)
     * hoppy_agent_device_limit_reset (lines ~28230-28290)
     * hoppy_agent_device_revoke (lines ~28290-28350)
   - Fix: Call queue_peer_revocation(conn, node_ip, client_key, background_tasks) inside the database transaction so peer removals are durably queued and committed before background tasks execute.

4. Server Control Plane: PayPal Capture State and Confirmation Hardening (Astra A03):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Location: _wallet_capture_sync (lines ~19530-19590)
   - Fix: Check existing_event. If not first_attempt, require existing_event["status"] == "processed". Recheck via GET /v2/checkout/orders/{order_id} using paypal_json_request to ensure status is COMPLETED. If not COMPLETED, mark failed in paypal_events and raise HTTPException 409. When capturing fresh order, if result status != "COMPLETED", mark failed in paypal_events and raise 409 (or 502 if empty).

5. Server Control Plane: Durable v3 Registry Refresh Queue & Triggers (Astra A06):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Fix:
     * Add create_winn3_registry_refresh_table(conn) creating winn3_registry_refreshes (node_slug TEXT PRIMARY KEY, attempts INTEGER DEFAULT 0, next_attempt_at REAL DEFAULT 0) with triggers on devices (INSERT, DELETE, UPDATE of location_slug, winn3_static_public, winn3_inner_v4) and users (UPDATE of status, expiration_date).
     * Add drain_winn3_registry_refreshes(limit: int = 4) to publish pending node registries with backoff.
     * Call create_winn3_registry_refresh_table(conn) in ensure_schema.
     * Call await asyncio.to_thread(drain_winn3_registry_refreshes) in background_account_expiry_sweep.
     * In sync_winn3_registry_to_node, ensure serialization with mutations: if not conn.in_transaction, execute BEGIN IMMEDIATE, else update winn3_registry_refreshes attempts.

6. Server Control Plane: Convert No-Await FastAPI Routes to Synchronous def (SOL-H3):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Fix: For all 70 route functions in embedded main.py that are declared async def but contain no await/async for/async with, change async def to def so FastAPI automatically offloads them to its thread pool rather than blocking the single event loop during synchronous SQLite transactions.

7. Linux Runner: Absolute Executable Path Resolution for Power Protection (Astra A04 / SOL-M2):
   - File: linux/runner/linux_tunnel_backend.cc
   - Location: StartTunnelPowerProtection and StopTunnelPowerProtection
   - Fix: Resolve systemctl, systemd-run, systemd-inhibit, and sleep via Which(...). If any required binary path is empty, return early. Pass the resolved absolute binary paths to RunArgv.

8. Android VpnTunnelService: Startup Wake Lock Only (Daybreak DB-04):
   - File: android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt
   - Fix: Replace WAKE_LOCK_TIMEOUT_MS = 10 * 60 * 1000L with STARTUP_WAKE_LOCK_TIMEOUT_MS = 60_000L. Acquire startup wake lock for 60 seconds at startup. Remove the periodic reacquisition check in the watchdog loop (if (tunnelWakeLock?.isHeld != true) acquireTunnelWakeLock()).

9. Android VpnTunnelService: Fail Closed on Split-Tunnel Package Exclusion Errors (SOL-M4):
   - File: android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt
   - Location: applyUserExcludedApplications()
   - Fix: In the general catch (e: Exception) block, log error and throw IllegalStateException("Android refused a required split-tunnel package exclusion", e).

10. Dart Client: Stop Advertising Unsupported Xray Transport on Android (SOL-M1):
    - File: lib/main.dart
    - Locations: ~11596, ~11720, ~12186
    - Fix: Change "supports_xray": true to "supports_xray": !Platform.isAndroid.

11. Android Test: Align Release Identity Contract Test (SOL-L3 / DB-04):
    - File: android/app/src/test/kotlin/org/winsvpn/app/AndroidReleaseIdentityContractTest.kt
    - Fix: Update assertions from 1.0.15+30 (TV 3002) to 1.0.16+33 (TV 3302) to match android/app/build.gradle.kts.

12. Verification Tooling & Posture Rulings:
    - tools/verify_rulings.sh (Astra A07): Update stripped() function to use Python to properly strip multiline block comments without stripping markdown headings.
    - tools/verify_apple_method_channel_contract.py (Astra A10): Remove obsolete deleteVpnConfig and readVpnConfig entries from DART_METHOD_ALLOWLIST.
    - tools/verify_shipped_native_artifact_freshness.py (DB-02): Update Debian non-upload dictionary from 1.0.15+30 (wins-vpn_1.0.15-30_amd64.deb) to 1.0.16+33 (wins-vpn_1.0.16-33_amd64.deb).
    - web/index.html (DB-03): Update tvOS description text to:
      <span>Standalone Native tvOS Client: A native Win's VPN tvOS application is not available and is not part of the current release scope. Apple TV users can use the setup methods above.</span>
    - Git index: Ensure winn_protocol_experimental/internal/carrier/h3_receive_window_test.go is added to git.

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
    print("Launching Astra (gpt-6-astra) Round 8 Remediation via Codex CLI...", flush=True)
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
