#!/usr/bin/env python3
"""Run Astra (gpt-6-astra) via Codex CLI to fix all verified Round 7 defects in /Users/owner/xprize/winsvpnv3.

Usage:
    python3 tools/run_astra_remediation_round7.py
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
LOG_PATH = Path("/tmp/astra_remediation_round7.log")
STREAM_PATH = Path("/tmp/astra_remediation_round7_stream.jsonl")

REMEDIATION_PROMPT = """You are Astra (gpt-6-astra), the lead security engineer and remediation architect for the WinsVPN ecosystem.

Your mission: Fix all verified defects discovered during the Round 7 Tripartite Deep Audit directly in the repository at /Users/owner/xprize/winsvpnv3.
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
   - python3 server/test_control_plane_round6.py
   - python3 server/test_winn3_descriptor_hub.py
   - python3 tools/website_security_audit.py

TARGET DEFECTS TO REMEDIATE:

1. Server Control Plane: Monero Multi-Source Price Consensus (Astra F02):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Location: resolve_monero_usd_per_xmr
   - Fix: Group quotes by origin hostname to prevent duplicate origins from counting twice. Reject non-finite decimals. When >= 2 independent quotes exist, require deviation between max and min to not exceed MONERO_PRICE_MAX_DEVIATION. Compute median (or average of two middle values). Only allow 1 quote if baseline exists and is within bounds.

2. Server Control Plane: Durable Stale Peer Revocation Queue (Astra F03):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Location: cleanup_stale_devices
   - Fix: Use queue_peer_revocation(conn, node_ip, client_key, background_tasks) instead of bare background_tasks.add_task so peer removal obligations are recorded in the database transaction.

3. Server Control Plane: Rotate Device Bearer on Slot Replacement Enrollment (Astra F04):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Location: _verify_account_sync (around line 20305-20340)
   - Fix: When authorization_kind == "enrollment", always generate a fresh plaintext device bearer and store its token hash in the device row, returning the bearer token in the admission response.

4. Server Control Plane: Rollback Admission on Node Sync Failure (Astra F05):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Location: _verify_account_sync (sync_peer_to_node failure handling)
   - Fix: If sync_peer_to_node fails, rollback conn before recording node failure so single-use activation keys are not marked consumed on an unreachable node.

5. Server Control Plane: Offload Account Deletion Endpoints to Worker Threads (Astra F09 / Daybreak DB-01):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Location: /account/delete, /account/delete/confirm, /account/delete/cancel, /account/delete/status
   - Fix: Parse request body on event loop, then offload database operations to sync helpers called via await asyncio.to_thread(...).

6. Server Control Plane: Require Device Auth Token for Account Status (Daybreak DB-04):
   - Files:
     * server/wins_control_plane_setup_ONETOUCH.sh
     * lib/main.dart
   - Fix:
     * In server: in _account_status_sync, require status_request.device_id and call require_device_auth_token(conn, acc, dev_id, request, action="account status").
     * In lib/main.dart: ensure account status check sends the device auth token header (x-wins-device-token / Authorization Bearer).

7. Server Control Plane: Fail Closed on Malformed Expiration Date (Daybreak DB-05):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Location: expire_account_runtime_if_due and _verify_account_sync
   - Fix: If expiration_date is present and parse_iso_datetime returns None, or if status == 'active' and (not raw_expiration or expires_at is None or utcnow() > expires_at), treat as expired immediately.

8. Server Control Plane: Strictly Validate and Bound parse_duration (Daybreak DB-12):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Location: parse_duration
   - Fix: Define DurationParseError. Accept lifetime, life, 10y, or regex ([1-9][0-9]{0,3})([dmy]) with limits: d <= 3650, m <= 120, y <= 10. Reject unparseable strings with 400 Bad Request instead of defaulting to 1 month.

9. Linux Runner: Power Inhibition via Transient systemd Unit (Daybreak DB-07 / Sol M-1):
   - File: linux/runner/linux_tunnel_backend.cc
   - Fix: Replace PID file management in StartTunnelPowerProtection and StopTunnelPowerProtection with systemd-run --user --unit=winsvpn-power-inhibit.service and systemctl --user stop winsvpn-power-inhibit.service.

10. Linux Runner: Socket Buffer Comparison Normalization (Astra F11):
    - File: linux/runner/linux_tunnel_backend.cc
    - Fix: In socket buffer verification, account for the Linux kernel doubling SO_RCVBUF / SO_SNDBUF values so a full grant is not misdiagnosed.

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
    print("Launching Astra (gpt-6-astra) Round 7 Remediation via Codex CLI...", flush=True)
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
