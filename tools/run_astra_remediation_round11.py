#!/usr/bin/env python3
"""Run Astra (gpt-6-astra) via Codex CLI to fix all verified Round 11 defects in /Users/owner/xprize/winsvpnv3.

Usage:
    python3 tools/run_astra_remediation_round11.py
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
LOG_PATH = Path("/tmp/astra_remediation_round11.log")
STREAM_PATH = Path("/tmp/astra_remediation_round11_stream.jsonl")

REMEDIATION_PROMPT = """You are Astra (gpt-6-astra), the lead security engineer and remediation architect for the WinsVPN ecosystem.

Your mission: Fix all verified defects discovered during the Round 11 Tripartite Deep Audit directly in the repository at /Users/owner/xprize/winsvpnv3.
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
   - python3 server/test_control_plane_round10.py
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

1. Server Control Plane: Double VPN Activation Deferral & Uncertain AWG Rollback (Astra A11-01, A11-02, A11-03):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Locations:
     * verify_and_consume_activation_secret: add consume: bool = True parameter. If not consume, return matches without updating activation_secret_used_at.
     * _verify_account_sync:
       - For double_vpn, call verify_and_consume_activation_secret(conn, acc, presented, consume=not bool(login.double_vpn)) and store deferred_activation_secret = presented.
       - If sync_peer_to_node fails, call conn.rollback(), queue_peer_revocation(conn, node_ssh_host, device_cfg.get("client_public_key") or ""), mark node failed, and commit.
       - After Core readiness wait, revalidate under conn.execute("BEGIN IMMEDIATE"): re-read current device token hash, user status, expiration date, and assignment revision. If invalid or changed, raise HTTPException 409 ("Double VPN enrollment changed while preparing. Please retry.").
       - Before returning success response, if deferred_activation_secret, call verify_and_consume_activation_secret(conn, acc, deferred_activation_secret) and raise 401 if invalid.

2. Winn v3 Gateway: O(1) Key Lookup Performance (Astra A11-07):
   - File: winn_protocol_experimental/cmd/winn3-gateway/peer_registry.go
   - Location: innerForPeer(peer []byte)
   - Fix: Replace the linear scan over r.byKey with a direct map lookup:
     addr, allowed := r.byKey[candidate]
     if !allowed { return netip.Addr{}, false }
     expires, present := r.notAfter[candidate]
     if !present || (expires != 0 && time.Now().Unix() >= expires) { return netip.Addr{}, false }
     return addr, true

3. Native Messaging Host & Origin Provisioning (Astra A11-04, Daybreak DB-01, DB-02):
   - File: tools/native_messaging/native_host_layout.py
     * In install_manifest, ensure allowed_origins.txt is written alongside the native host manifest with the allowed browser extension origins.
   - File: tools/native_messaging/host/bin/wins_bridge_host.dart
     * In argument parsing / origin resolution: accept Firefox native messaging launch arguments (Firefox passes manifest path and extension ID) in addition to chrome-extension:// origins.

4. Linux Runner: Redact Winn v3 Status Stderr Logging (Daybreak DB-03):
   - File: linux/runner/linux_tunnel_backend.cc
   - Location: lines ~4032-4039 (promotion refusal path)
   - Fix: Do not log raw LinuxWinn3EngineStatusJson() to stderr. Use ExtractJsonCounters(winsvpn::winn3host::LinuxWinn3EngineStatusJson(), {"max_datagram", "queue_depth", "queue_length", "uptime_ms", "tx_datagrams", "tx_bytes", "tx_rejected", "rx_datagrams", "rx_bytes", "rx_dropped", "rx_oversize", "rx_foreign_sender"}) so sensitive endpoints and session IDs are never dumped to stderr.

5. Flutter TV Focus Node Lifecycle (Daybreak DB-06):
   - File: lib/owned_keyboard_listener.dart (create this file)
     * Implement OwnedKeyboardListener (StatefulWidget) creating FocusNode in initState() and disposing it in dispose().
   - Files: lib/tv_dpad_support.dart, lib/vpn_power_control.dart, lib/main.dart
     * Replace inline FocusNode(skipTraversal: true) allocations inside build() with OwnedKeyboardListener.

6. Linux Runner: Stop Session-Wide Power Inhibitor (Daybreak DB-07):
   - File: linux/runner/linux_tunnel_backend.cc
   - Location: StartTunnelPowerProtection call in StartTunnel
   - Fix: Do not keep an infinite sleep inhibit running for the entire session. Remove StartTunnelPowerProtection() from the steady-state connected path, while preserving StopTunnelPowerProtection() on disconnect to clean up any units.

7. Linux Split-Bypass Sleep Binary Path Resolution (Sol SOL-L1):
   - File: linux/runner/linux_tunnel_backend.cc
   - Location: split-bypass sleep invocations
   - Fix: Resolve Which("sleep") rather than hardcoding /usr/bin/sleep.

8. Git Index Tracking:
   - Ensure all newly created Go tests in winn_protocol_experimental/ are staged with git add so test custody passes.

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
    print("Launching Astra (gpt-6-astra) Round 11 Remediation via Codex CLI...", flush=True)
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
