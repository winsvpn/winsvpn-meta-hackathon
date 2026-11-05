#!/usr/bin/env python3
"""Fail closed when a non-ignored project path has no documented role.

This is intentionally a classification/authority check, not a content or
release-readiness substitute.  It makes the repository-wide file-purpose index
machine-enforceable so a newly copied top-level tree cannot silently become an
authoritative build or deployment input.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INDEX_PATH = ROOT / "docs" / "PROJECT_FILE_PURPOSE_INDEX_20260715.md"

AUTHORITATIVE_ROOTS = {
    ".github",
    "android",
    "app_store",
    "apple",
    "assets",
    "cloudflare",
    "docs",
    "installer",
    "ios",
    "legal",
    "lib",
    "linux",
    "macos",
    "netlify",
    "server",
    "test",
    "tools",
    "web",
    "windows",
}

REFERENCE_ROOTS = {
    "Gemini Antigravity",
    "Google Response",
    "Hay",
    "Update",
    "Wifi & Cellular combo",
    "drop_in",
    "handoffs",
    "play_console_assets",
    "wins-backend",
    "wins_vpn_handoffs",
}

GENERATED_OR_EVIDENCE_ROOTS = {
    "active-gateway",
    "release",
}

AUTHORITATIVE_ROOT_FILES = {
    ".env.example",
    ".gitattributes",
    ".gitignore",
    ".metadata",
    "AGENTS.md",
    "NEW_MACBOOK_M5_PRO_CONTINUATION_20260721.txt",
    "README_FINAL_DEPLOYMENT.md",
    "SECURITY_NOTES_FINAL.md",
    "analysis_options.yaml",
    "netlify.toml",
    "pubspec.lock",
    "pubspec.yaml",
}

DOCUMENTATION_OR_REFERENCE_FILES = {
    "1 Month Subscription.txt",
    "1 Year Subscription.txt",
    "GitHub Gist.txt",
    "LikeVPS Japan.png",
    "Personal Subscription.txt",
    "README.md",
    "SECURITY_AND_BUGFREE_RECOMMENDATIONS.txt",
    "SECURITY_BUG_REVIEW_DEEP_20260720.txt",
    "TEST_REPORT_FINAL.txt",
    "Wins_VPN_Server_Blueprint_v2.pdf",
    "chat logs.txt",
    "final iptables.txt",
    "trocadero-where-see-eiffel-tower-sparkle-best-view-paris-photographer-001.webp",
    "upcloud_singapore_public_key.pub",
}

LEGACY_COMPATIBILITY_FILES = {
    "backup_keys.example.txt",
    "backup_to_gdrive.sh",
    "decoder.sh",
    "optimize_vps.sh",
    "test_auth_logic.py",
    "weekly_maintenance.sh",
}

SENSITIVE_HISTORY_REMEDIATION_FILES = {
    "backup keys.txt",
    "main_b64.txt",
}

FORBIDDEN_UNIGNORED_ROOT_ARTIFACT_SUFFIXES = {".obj"}
FORBIDDEN_UNIGNORED_ROOT_ARTIFACT_NAMES = {"wins-vpn-linux-x64.tar.gz"}


def git_paths() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
    )
    return sorted({line.strip() for line in result.stdout.splitlines() if line.strip()})


def tracked_path_count() -> int:
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
    )
    return len({line.strip() for line in result.stdout.splitlines() if line.strip()})


def documented_inventory_counts() -> tuple[int, int]:
    text = INDEX_PATH.read_text(encoding="utf-8")
    tracked = re.search(r"- ([\d,]+) Git-tracked files;", text)
    all_paths = re.search(r"- ([\d,]+) tracked or untracked non-ignored paths;", text)
    if not tracked or not all_paths:
        raise RuntimeError(f"Inventory snapshot counts are missing from {INDEX_PATH}")
    return int(tracked.group(1).replace(",", "")), int(all_paths.group(1).replace(",", ""))


def classify(path: str) -> str | None:
    normalized = path.replace("\\", "/")
    top = normalized.split("/", 1)[0]
    if "/" in normalized:
        if top in AUTHORITATIVE_ROOTS:
            return "authoritative-source-or-documentation"
        if top in REFERENCE_ROOTS:
            return "reference-or-historical"
        if top in GENERATED_OR_EVIDENCE_ROOTS:
            return "generated-or-release-evidence"
        return None
    if normalized in AUTHORITATIVE_ROOT_FILES:
        return "authoritative-root"
    if normalized in DOCUMENTATION_OR_REFERENCE_FILES:
        return "documentation-or-reference"
    if normalized in LEGACY_COMPATIBILITY_FILES:
        return "legacy-compatibility-entrypoint"
    if normalized in SENSITIVE_HISTORY_REMEDIATION_FILES:
        return "sensitive-history-remediation"
    return None


def is_forbidden_root_artifact(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return "/" not in normalized and (
        Path(normalized).suffix.lower() in FORBIDDEN_UNIGNORED_ROOT_ARTIFACT_SUFFIXES
        or normalized in FORBIDDEN_UNIGNORED_ROOT_ARTIFACT_NAMES
    )


def self_test() -> int:
    cases = {
        "lib/main.dart": "authoritative-source-or-documentation",
        "Update/lib/main.dart": "reference-or-historical",
        "wins_vpn_handoffs/reviewer-report.md": "reference-or-historical",
        "release/linux/bin/wins-vpn": "generated-or-release-evidence",
        "pubspec.yaml": "authoritative-root",
        "NEW_MACBOOK_M5_PRO_CONTINUATION_20260721.txt": "authoritative-root",
        "README.md": "documentation-or-reference",
        "SECURITY_AND_BUGFREE_RECOMMENDATIONS.txt": "documentation-or-reference",
        "backup_to_gdrive.sh": "legacy-compatibility-entrypoint",
        "backup keys.txt": "sensitive-history-remediation",
        "new-unreviewed-root/file.txt": None,
        "new-unreviewed-root.txt": None,
    }
    for path, expected in cases.items():
        actual = classify(path)
        if actual != expected:
            raise AssertionError(f"classifier mismatch for {path}: {actual!r} != {expected!r}")
    if not is_forbidden_root_artifact("windows_tunnel_backend.obj"):
        raise AssertionError("root .obj artifact was not rejected")
    if not is_forbidden_root_artifact("wins-vpn-linux-x64.tar.gz"):
        raise AssertionError("root Linux archive was not rejected")
    if is_forbidden_root_artifact("web/downloads/wins-vpn-linux-x64.tar.gz"):
        raise AssertionError("gated website artifact was incorrectly treated as a root artifact")
    print("PROJECT FILE INVENTORY SELF-TEST: PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="emit the summary as JSON")
    parser.add_argument("--self-test", action="store_true", help="exercise fail-closed classifier cases")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    paths = git_paths()
    tracked_count = tracked_path_count()
    documented_tracked, documented_all_paths = documented_inventory_counts()
    unknown: list[str] = []
    forbidden_artifacts: list[str] = []
    restored_sensitive: list[str] = []
    count_mismatches: list[str] = []
    counts: Counter[str] = Counter()

    for path in paths:
        category = classify(path)
        if category is None:
            unknown.append(path)
        else:
            counts[category] += 1

        normalized = path.replace("\\", "/")
        if is_forbidden_root_artifact(normalized):
            forbidden_artifacts.append(normalized)
        if normalized in SENSITIVE_HISTORY_REMEDIATION_FILES and (ROOT / normalized).exists():
            restored_sensitive.append(normalized)

    if documented_tracked != tracked_count:
        count_mismatches.append(
            f"documented Git-tracked count {documented_tracked} != current {tracked_count}"
        )
    if documented_all_paths != len(paths):
        count_mismatches.append(
            f"documented non-ignored path count {documented_all_paths} != current {len(paths)}"
        )

    report = {
        "schema": 1,
        "tracked_path_count": tracked_count,
        "documented_tracked_path_count": documented_tracked,
        "path_count": len(paths),
        "documented_path_count": documented_all_paths,
        "classified_count": len(paths) - len(unknown),
        "categories": dict(sorted(counts.items())),
        "unknown_paths": unknown,
        "forbidden_unignored_root_artifacts": forbidden_artifacts,
        "restored_sensitive_history_files": restored_sensitive,
        "inventory_count_mismatches": count_mismatches,
    }

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            "Project inventory coverage: "
            f"{report['classified_count']}/{report['path_count']} non-ignored paths classified."
        )
        for category, count in report["categories"].items():
            print(f"  {category}: {count}")
        for label, values in (
            ("Unclassified path", unknown),
            ("Generated root artifact is not ignored", forbidden_artifacts),
            ("Deleted sensitive-history file was restored", restored_sensitive),
            ("Inventory snapshot is stale", count_mismatches),
        ):
            for value in values:
                print(f"ERROR: {label}: {value}", file=sys.stderr)

    return 1 if unknown or forbidden_artifacts or restored_sensitive or count_mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
