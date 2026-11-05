#!/usr/bin/env python3
"""Run Astra (gpt-6-astra) via Codex CLI to fix all verified Round 12 defects in /Users/owner/xprize/winsvpnv3.

Usage:
    python3 tools/run_astra_remediation_round12.py
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
LOG_PATH = Path("/tmp/astra_remediation_round12.log")
STREAM_PATH = Path("/tmp/astra_remediation_round12_stream.jsonl")

REMEDIATION_PROMPT = """You are Astra (gpt-6-astra), the lead security engineer and remediation architect for the WinsVPN ecosystem.

Your mission: Fix all verified defects discovered during the Round 12 Tripartite Deep Audit directly in the repository at /Users/owner/xprize/winsvpnv3.
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
   - python3 server/test_control_plane_round11.py
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

1. Server Control Plane: Move Ordinary AWG Installation After Route Validation & Ensure Rollback Revocation (Astra A12-01):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - In ordinary AWG admission: perform all deterministic route, obfuscation, capability, and descriptor eligibility checks BEFORE installing the remote AWG peer.
   - If remote installation fails or times out, ensure conn.rollback() is followed by queue_peer_revocation for the attempted peer key and committed.

2. Server Control Plane: Double VPN Activation Lease Concurrency Lock (Sol SOL-M1):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Prevent concurrent Double VPN preparation requests with the same activation secret from racing. When validating with consume=False, establish an in-flight reservation or lease state so a second concurrent request fails with 409 Conflict.

3. Webhook Idempotency & In-Flight Reservation Ordering (Astra A12-02):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - In BTCPay and PayPal webhook handlers: ensure in-flight payment reservations and duplicate delivery callbacks are handled idempotently without dropping retries or premature acknowledgment.

4. Lifetime Invoice Price Binding (Astra A12-03):
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - When provisioning lifetime accounts from paid invoices: verify payment amount against the invoice's bound purchase price rather than re-querying the current live catalog price.

5. Security Alert Monitor Checkpoint Advancement (Astra A12-06):
   - In generated security alert monitor: advance journal checkpoint only after a successful journal read, never before or on read errors.

6. Triage SQLite Connection Lifecycle (Astra A12-07):
   - In triage and alert helpers: ensure SQLite connections are explicitly closed upon exit rather than relying on garbage collection.

7. Native-Messaging Test Isolation (Sol SOL-M3):
   - Files: tools/native_messaging/test_native_host_registration.py and tools/test_linux_native_host_delivery.py
   - Ensure tests isolate OWNER_IDENTITY_ENV and WINSVPN_BROWSER_EXTENSION_IDENTITY_RECEIPT using temporary directories so host environment identity is not read.

8. Go Test Timing & Hygiene (Sol SOL-L1, SOL-L3, Daybreak):
   - File: winn_protocol_experimental/cmd/winn3-gateway/peer_registry_test.go (or peer_registry_round11_test.go)
   - Ensure time boundary in expiry tests is robust against clock resolution/sleep jitter.
   - Ensure pubspec.yaml and all modified files have LF line endings (0 CRLF).

Produce a comprehensive remediation report at docs/evidence/round12_remediation.md when finished.
"""


def _stream_reader(pipe, stream_path: Path, parsed: dict) -> None:
    stream = stream_path.open("w", encoding="utf-8")
    try:
        for line in iter(pipe.readline, ""):
            stream.write(line)
            stream.flush()
            line_s = line.strip()
            if not line_s:
                continue
            try:
                data = json.loads(line_s)
            except json.JSONDecodeError:
                continue
            event_type = data.get("type")
            if event_type == "item.completed":
                item = data.get("item", {})
                itype = item.get("type")
                if itype == "reasoning":
                    parsed["reasoning"].append(item.get("text", ""))
                elif itype == "agent_message":
                    parsed["messages"].append(item.get("text", ""))
            elif event_type == "turn.completed":
                usage = data.get("usage", {})
                if usage:
                    parsed["usage"] = usage
    except Exception as exc:
        parsed["error"] = repr(exc)
    finally:
        try:
            stream.close()
        except Exception:
            pass


def main() -> None:
    print("================================================================", flush=True)
    print("Launching Astra (gpt-6-astra) Round 12 Remediation via Codex CLI...", flush=True)
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
