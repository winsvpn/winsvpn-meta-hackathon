#!/usr/bin/env python3
"""
Winthos Permanent Three-AI Presidential Debate Protocol (Stage 2: Cross-Podium Rebuttal)
Target: Multi-Gbps Wire-Speed Across Winn v3, AWG, and XRay
Podiums:
  Podium 1: Antigravity (Council Chair, Gemini 3.8 Flash High Thinking)
  Podium 2: GPT-5.6 Sol Pro (OpenAI, OpenRouter openai/gpt-5.6-sol-pro)
  Podium 3: Claude Opus 5 (Anthropic, Claude Code CLI --model opus --effort max)
"""

import json
import os
import pathlib
import ssl
import subprocess
import sys
import time
import urllib.request

REPO_ROOT = pathlib.Path("/Users/owner/xprize/winsvpnv3").resolve()
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DOCS_EVIDENCE = REPO_ROOT / "docs" / "evidence"

ANTIGRAVITY_S1 = (DOCS_EVIDENCE / "debate_speed_stage1_antigravity.md").read_text(encoding="utf-8")
SOL_PRO_S1 = (DOCS_EVIDENCE / "debate_speed_stage1_sol_pro.md").read_text(encoding="utf-8")
OPUS5_S1 = (DOCS_EVIDENCE / "debate_speed_stage1_opus5.md").read_text(encoding="utf-8")

from tools.run_presidential_debate_speed import (
    build_stage2_prompt, get_openrouter_key, query_sol_pro
)

def run_sol_pro_stage2():
    prompt = build_stage2_prompt(
        "Podium 2: GPT-5.6 Sol Pro",
        "Podium 1: Antigravity (Council Chair)",
        ANTIGRAVITY_S1,
        "Podium 3: Claude Opus 5",
        OPUS5_S1,
    )
    print("[Stage 2] Querying Sol Pro Cross-Rebuttal...", flush=True)
    res = query_sol_pro(prompt, effort="high")
    out = DOCS_EVIDENCE / "debate_speed_stage2_sol_pro.md"
    out.write_text(res, encoding="utf-8")
    print(f"[Stage 2] Sol Pro Cross-Rebuttal completed ({len(res)} chars)", flush=True)
    return res

def run_opus5_stage2():
    prompt = build_stage2_prompt(
        "Podium 3: Claude Opus 5",
        "Podium 1: Antigravity (Council Chair)",
        ANTIGRAVITY_S1,
        "Podium 2: GPT-5.6 Sol Pro",
        SOL_PRO_S1,
    )
    prompt_file = pathlib.Path("/tmp/stage2_prompt_opus.txt")
    prompt_file.write_text(prompt, encoding="utf-8")
    print("[Stage 2] Querying Claude Opus 5 Cross-Rebuttal via CLI...", flush=True)
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
        raise RuntimeError(f"Claude Opus Stage 2 failed: {proc.stderr}")
    res = proc.stdout.strip()
    out = DOCS_EVIDENCE / "debate_speed_stage2_opus5.md"
    out.write_text(res, encoding="utf-8")
    print(f"[Stage 2] Claude Opus 5 Cross-Rebuttal completed ({len(res)} chars)", flush=True)
    return res

if __name__ == "__main__":
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f_sol = executor.submit(run_sol_pro_stage2)
        f_opus = executor.submit(run_opus5_stage2)
        concurrent.futures.wait([f_sol, f_opus])
    print("Stage 2 cross-podium rebuttals completed.")
