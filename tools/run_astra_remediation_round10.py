#!/usr/bin/env python3
"""Run Astra (gpt-6-astra) via Codex CLI to fix all verified Round 10 defects in /Users/owner/xprize/winsvpnv3.

Usage:
    python3 tools/run_astra_remediation_round10.py
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
LOG_PATH = Path("/tmp/astra_remediation_round10.log")
STREAM_PATH = Path("/tmp/astra_remediation_round10_stream.jsonl")

REMEDIATION_PROMPT = """You are Astra (gpt-6-astra), the lead security engineer and remediation architect for the WinsVPN ecosystem.

Your mission: Fix all verified defects discovered during the Round 10 Tripartite Deep Audit directly in the repository at /Users/owner/xprize/winsvpnv3.
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
   - python3 server/test_control_plane_round9.py
   - python3 server/test_winn3_descriptor_hub.py
   - python3 server/test_account_deletion_hub.py
   - python3 server/test_donor_acknowledgment_hub.py
   - python3 tools/website_security_audit.py
   - sh tools/verify_rulings.sh
   - python3 tools/verify_apple_method_channel_contract.py
   - python3 tools/test_apple_standalone_v3_wiring.py
   - python3 tools/test_windows_awg_runtime_validation.py
   - cd winn_protocol_experimental && go test ./...

TARGET DEFECTS TO REMEDIATE:

1. Server Control Plane: Winn v3 Key Rotation on Device Slot Replacement (Astra A10-01):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Location: _verify_account_sync around line 20520-20540
   - Fix: When replacing an existing device row, rotate/clear v3 material so an evicted device's old v3 keys are not retained in the device table and are revoked from the gateway registry:
     rotate_winn3_identity = (
         old_device_id != login.device_id
         or (requested_client_public_key and requested_client_public_key != old_public_key)
         or (not login.free_access and authorization_kind == "enrollment")
     )
     if rotate_winn3_identity:
         conn.execute(
             "UPDATE devices SET winn3_inner_v4=NULL, winn3_static_private=NULL, winn3_static_public=NULL WHERE device_id=?",
             (old_device_id,),
         )
         for field in ("winn3_inner_v4", "winn3_static_private", "winn3_static_public"):
             device_cfg[field] = ""

2. Server Control Plane: Durable Peer Revocation Authority Check (Astra A10-02):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Location: drain_peer_revocation_outbox (around line 18400-18450)
   - Fix: Define peer_has_current_authority(conn, node_ip, public_key) -> bool checking if the device key/node is currently authorized for an active user. In drain_peer_revocation_outbox, process one item per BEGIN IMMEDIATE transaction: if peer_has_current_authority is true, delete the queue row (the peer is now authorized); otherwise call remove_peer_from_node and delete or update attempts.

3. Server Control Plane: Rollback on Old Node Sync Failure During Location Move (Astra A10-03):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Location: _verify_account_sync (around lines 21000-21060)
   - Fix: Do not commit conn before old node sync. If old node sync fails, call conn.rollback(), queue durable registry refresh for both nodes (repair_slug in (node["slug"], old_location_slug)), mark old node management status failed, and raise HTTPException 503. Only call conn.commit() when BOTH new and old node synchronization succeed.

4. Winn v3 Gateway: Evict Stale Session Owner on Address Reassignment (Astra A10-04):
   - File: winn_protocol_experimental/cmd/winn3-gateway/forward.go
   - Location: forwardTable.learn
   - Fix: If addr already has an owner loop in t.byAddr, check whether the existing owner still has registry authority for that address using t.registry.innerForPeer(session.PeerStatic()). If the existing owner is no longer authorized (or has an address mismatch), evict the existing loop and learn the new session loop.

5. Native Messaging Host: Fail Closed on Empty Origin Configuration (Astra A10-05):
   - File: tools/native_messaging/host/bin/wins_bridge_host.dart
   - Location: line 165 (_originAuthorized getter)
   - Fix: Change allowedOrigins.isEmpty || allowedOrigins.contains(_callerOrigin) to allowedOrigins.isNotEmpty && allowedOrigins.contains(_callerOrigin).

6. Linux Runner: Power Inhibitor Teardown on Standalone Winn v3 Disconnect (Daybreak DB-04):
   - File: linux/runner/linux_tunnel_backend.cc
   - Location: line ~4475 (standalone Winn v3 disconnect handler)
   - Fix: Call StopTunnelPowerProtection(); alongside StopLinuxBypassSlice(); so winsvpn-power-inhibit.service is stopped immediately upon standalone disconnect.

7. Donor Hub Test: Async/Sync Handler Invocation Compatibility (Daybreak DB-07):
   - File: server/test_donor_acknowledgment_hub.py
   - Location: admin route test invocations (lines ~800-1170)
   - Fix: Implement call_handler(handler, *args, **kwargs) that checks if inspect.isawaitable(result): return harness.asyncio.run(result) else return result. Use call_handler for the synchronous admin routes so TypeError is not raised.

8. Windows Test Oracles: Align SDDL and Installer Path Assertions (Daybreak DB-08):
   - File: tools/test_windows_awg_runtime_validation.py: update kSystemAdminDaclSddl assertion to kSystemAdminDirectorySddl and kSystemAdminFileSddl.
   - File: tools/test_windows_arm64_release_readiness.py: update assertions to match the current sealed release directory layout.

9. Browser Extension: StartReady Catch for Unhandled Promise Rejections (Sol SOL-L2):
   - File: extension/src/background/background.js
   - Fix: Define startReady() calling ready().catch((error) => { controller.lastError = ...; }). Use startReady() in onInstalled, onStartup, and top-level listener setup. Rebuild and verify extension packages via python3 extension/build.py all.

10. Control Plane Security Events DB: Connection PRAGMA Configuration (Sol SOL-P1):
    - File: server/wins_control_plane_setup_ONETOUCH.sh
    - Location: ensure_security_events_db / security events connection initialization
    - Fix: Configure PRAGMA journal_mode=WAL, PRAGMA synchronous=NORMAL, PRAGMA busy_timeout=10000, PRAGMA foreign_keys=ON on security events database connections.

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
    print("Launching Astra (gpt-6-astra) Round 10 Remediation via Codex CLI...", flush=True)
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
