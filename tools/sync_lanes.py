#!/usr/bin/env python3
"""Synchronize repository tree to the tripartite audit lanes."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LANE_ROOT = Path("/Users/owner/.gemini/antigravity/scratch/winsvpnv3_audit_lanes")
LANES = ["astra", "sol", "opus"]

EXCLUDES = [
    ".git",
    "build",
    ".dart_tool",
    "__pycache__",
    "*.pyc",
    ".wrangler",
    ".a12",
    "docs/evidence/*_round*",
    "docs/evidence/astra_*",
    "docs/evidence/round*",
    "docs/evidence/codex_*",
    ".codex*",
    ".pytest_cache",
    ".venv*",
]


def sync_lane(lane: str) -> None:
    dst = LANE_ROOT / lane
    dst.mkdir(parents=True, exist_ok=True)
    cmd = ["rsync", "-a", "--delete"]
    for exc in EXCLUDES:
        cmd.extend(["--exclude", exc])
    cmd.extend([f"{REPO_ROOT}/", f"{dst}/"])
    print(f"Syncing {REPO_ROOT} -> {dst}...")
    subprocess.run(cmd, check=True)
    src_index = REPO_ROOT / ".git" / "index"
    src_objects = REPO_ROOT / ".git" / "objects"
    dst_git = dst / ".git"
    if src_index.exists() and dst_git.is_dir():
        shutil.copy2(src_index, dst_git / "index")
        print(f"Lane {lane} .git/index synchronized.")
    if src_objects.exists() and dst_git.is_dir():
        subprocess.run(["rsync", "-a", f"{src_objects}/", f"{dst_git / 'objects'}/"], check=True)
        print(f"Lane {lane} .git/objects synchronized.")
    print(f"Lane {lane} synchronized successfully.")


def main() -> None:
    print(f"Synchronizing {len(LANES)} audit lanes from {REPO_ROOT}...")
    for lane in LANES:
        sync_lane(lane)
    print("All audit lanes synchronized.")


if __name__ == "__main__":
    main()
