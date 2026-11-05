#!/usr/bin/env python3
"""Autonomous Tripartite Audit & Remediation Loop.

Orchestrates:
1. Pre-audit verification (flutter analyze, server tests, security audit).
2. Synchronization of codebase to isolated audit lanes.
3. Execution of Tripartite Deep Audit across Daybreak Blue, Astra, and 5.6 Sol.
4. Parsing and extraction of verdicts from the new audit round.
5. Invoking Astra remediation if defects remain.

Usage:
    python3 tools/run_tripartite_cycle.py [--round 5]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LANE_ROOT = Path("/Users/owner/.gemini/antigravity/scratch/winsvpnv3_audit_lanes")
EVIDENCE_DIR = REPO_ROOT / "docs" / "evidence"


def run_checks() -> bool:
    print("\n--- Running Core Verifications ---", flush=True)
    cmds = [
        ("flutter analyze", ["flutter", "analyze", "--no-pub"]),
        ("server control plane test", [sys.executable, "server/test_control_plane_deepseek_round2.py"]),
        ("website security audit", [sys.executable, "tools/website_security_audit.py"]),
    ]
    for name, cmd in cmds:
        print(f"Running {name}...", flush=True)
        res = subprocess.run(cmd, cwd=REPO_ROOT)
        if res.returncode != 0:
            print(f"FAILED: {name} exited with code {res.returncode}", flush=True)
            return False
        print(f"PASSED: {name}", flush=True)
    return True


def sync_lanes() -> None:
    print("\n--- Synchronizing Audit Lanes ---", flush=True)
    res = subprocess.run([sys.executable, "tools/sync_lanes.py"], cwd=REPO_ROOT)
    if res.returncode != 0:
        raise RuntimeError(f"Syncing lanes failed with code {res.returncode}")


def run_tripartite_audit(round_num: int) -> bool:
    print(f"\n--- Launching Round {round_num} Tripartite Deep Audit ---", flush=True)
    stream_dir = f"/tmp/codex_audit_streams_round{round_num}"
    os.environ["CODEX_STREAM_DIR"] = stream_dir
    os.environ["CODEX_AUDIT_SUFFIX"] = f"_round{round_num}"

    cmd = [sys.executable, "tools/run_codex_tripartite_audit.py"]
    res = subprocess.run(cmd, cwd=REPO_ROOT)
    if res.returncode != 0:
        print(f"Audit runner exited with code {res.returncode}", flush=True)
        return False
    return True


def parse_round_verdicts(round_num: int) -> dict:
    print(f"\n--- Evaluating Round {round_num} Audit Results ---", flush=True)
    models = ["astra", "sol", "opus_5"]
    results = {}

    for m in models:
        report_path = EVIDENCE_DIR / f"codex_{m}_audit_round{round_num}.md"
        if not report_path.exists():
            report_path = EVIDENCE_DIR / f"codex_{m}_audit.md"

        if not report_path.exists():
            results[m] = {"status": "MISSING", "critical": -1, "high": -1}
            continue

        text = report_path.read_text(encoding="utf-8", errors="replace")
        critical_count = len(re.findall(r"(?i)\bcritical\b", text))
        high_count = len(re.findall(r"(?i)\bhigh\b", text))
        no_go = "NO-GO" in text

        results[m] = {
            "status": "NO-GO" if no_go else "PASS",
            "critical_matches": critical_count,
            "high_matches": high_count,
            "path": str(report_path),
            "chars": len(text),
        }
        print(f"[{m}] Status: {'NO-GO' if no_go else 'PASS'} (Length: {len(text)} chars)", flush=True)

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Run autonomous audit cycle")
    parser.add_argument("--round", type=int, default=5, help="Audit round number")
    args = parser.parse_args()

    round_num = args.round
    print(f"Starting Autonomous Cycle for Round {round_num}...", flush=True)

    if not run_checks():
        print("Pre-audit verifications failed. Aborting lane sync and audit launch.", flush=True)
        sys.exit(1)

    sync_lanes()
    success = run_tripartite_audit(round_num)
    if not success:
        print("Tripartite audit execution failed.", flush=True)
        sys.exit(1)

    verdicts = parse_round_verdicts(round_num)
    print("\nSummary of Round Results:", json.dumps(verdicts, indent=2), flush=True)


if __name__ == "__main__":
    main()
