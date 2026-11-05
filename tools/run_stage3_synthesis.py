#!/usr/bin/env python3
"""
Winthos Permanent Three-AI Presidential Debate Protocol (Stage 3: Synthesis & Position Lock)
Target: Multi-Gbps Wire-Speed Across Winn v3, AWG, and XRay
"""

import json
import os
import pathlib
import ssl
import subprocess
import sys
import time

REPO_ROOT = pathlib.Path("/Users/owner/xprize/winsvpnv3").resolve()
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DOCS_EVIDENCE = REPO_ROOT / "docs" / "evidence"

from tools.run_presidential_debate_speed import (
    build_stage3_prompt, query_sol_pro
)

def load_stage2_transcripts() -> str:
    parts = []
    for podium, filename in [
        ("Podium 1: Antigravity (Council Chair)", "debate_speed_stage2_antigravity.md"),
        ("Podium 2: GPT-5.6 Sol Pro", "debate_speed_stage2_sol_pro.md"),
        ("Podium 3: Claude Opus 5", "debate_speed_stage2_opus5.md"),
    ]:
        f = DOCS_EVIDENCE / filename
        if f.exists():
            parts.append(f"### {podium} Stage 2 Cross-Rebuttal:\n{f.read_text(encoding='utf-8')}\n")
    return "\n---\n".join(parts)

def run_sol_pro_stage3():
    stage2_text = load_stage2_transcripts()
    prompt = build_stage3_prompt("Podium 2: GPT-5.6 Sol Pro", stage2_text)
    print("[Stage 3] Querying Sol Pro Position Lock...", flush=True)
    res = query_sol_pro(prompt, effort="high")
    out = DOCS_EVIDENCE / "debate_speed_stage3_sol_pro.md"
    out.write_text(res, encoding="utf-8")
    print(f"[Stage 3] Sol Pro Position Lock completed ({len(res)} chars)", flush=True)
    return res

def run_opus5_stage3():
    stage2_text = load_stage2_transcripts()
    prompt = build_stage3_prompt("Podium 3: Claude Opus 5", stage2_text)
    prompt_file = pathlib.Path("/tmp/stage3_prompt_opus.txt")
    prompt_file.write_text(prompt, encoding="utf-8")
    print("[Stage 3] Querying Claude Opus 5 Position Lock via CLI...", flush=True)
    cmd = [
        "/Users/owner/.local/bin/claude",
        "-p",
        "-",
        "--model",
        "opus",
        "--effort",
        "max",
    ]
    with open(prompt_file, "r", encoding="utf-8") as pf:
        proc = subprocess.run(
            cmd,
            stdin=pf,
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            timeout=420,
        )
    if proc.returncode != 0:
        raise RuntimeError(f"Claude Opus Stage 3 failed: {proc.stderr}")
    res = proc.stdout.strip()
    out = DOCS_EVIDENCE / "debate_speed_stage3_opus5.md"
    out.write_text(res, encoding="utf-8")
    print(f"[Stage 3] Claude Opus 5 Position Lock completed ({len(res)} chars)", flush=True)
    return res

if __name__ == "__main__":
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f_sol = executor.submit(run_sol_pro_stage3)
        f_opus = executor.submit(run_opus5_stage3)
        concurrent.futures.wait([f_sol, f_opus])
    print("Stage 3 position locks completed.")
