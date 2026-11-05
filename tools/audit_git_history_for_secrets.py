#!/usr/bin/env python3
"""Find active credential values in every local Git blob without printing them."""

from __future__ import annotations

import argparse
import base64
import json
import pathlib
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from collections.abc import Iterable


ROOT = pathlib.Path(__file__).resolve().parent.parent
SAFE_LABEL_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,95}$")
MAX_FINDINGS_PER_LABEL = 3
CHUNK_SIZE = 1024 * 1024
GENERIC_SCAN_OVERLAP = 1024
GENERIC_TOKEN_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    (
        "PRIVATE_KEY_MATERIAL",
        re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ),
    (
        "GITHUB_TOKEN",
        re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{40,255})\b"),
    ),
    (
        "GOOGLE_OAUTH_CLIENT_SECRET",
        re.compile(rb"\bGOCSPX-[A-Za-z0-9_-]{20,120}\b"),
    ),
    # E-01 (Sol audit, 2026-08-28): the AccuWeather key shape was invisible
    # to this scanner -- provider API keys of the AIza/Google family, and
    # third-party weather keys carried as bare query parameters, both
    # reached history unchallenged.
    ("GOOGLE_API_KEY", re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("PROVIDER_API_KEY_PARAM", re.compile(rb"\b(?:apikey|api_key|apiKey)=")),
    ("AWS_ACCESS_KEY_ID", re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("SLACK_TOKEN", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,255}\b")),
    (
        "STRIPE_LIVE_SECRET",
        re.compile(rb"\b(?:sk|rk)_live_[A-Za-z0-9]{20,255}\b"),
    ),
    # E-01: precise GPS coordinate pairs. Range-bounded (|lat| <= 90,
    # |lon| <= 180) so dp-dimension pairs like 393.9,282.3 and version
    # quadruples cannot match; four-plus decimals is GPS precision.
    (
        "GPS_COORDINATE_PAIR",
        re.compile(
            rb"-?(?:[1-8]?\d|90)\.\d{4,},-?(?:1[0-7]\d|[1-9]?\d|180)\.\d{4,}"
        ),
    ),
    # E-01: mobile-carrier-assigned global IPv6 (the 2607::/16 block is
    # T-Mobile US; the phone's rmnet addresses leaked into evidence logs
    # with carrier + time + location correlation).
    (
        "MOBILE_CARRIER_IPV6",
        # 2607:fbXX:: is the T-Mobile US carrier block -- addresses ASSIGNED
        # TO THE USER'S PHONE. 2607:f8b0::/32 (Google) is third-party
        # infrastructure the phone talks to and is out of scope here.
        re.compile(rb"\b2607:fb[0-9a-f]{0,2}(?::[0-9a-f]{0,4}){1,7}\b"),
    ),
)

# E-01: a BARE 64-hex line is the body of a key heredoc (the D-01 shape:
# the live fleet static key sat in `cat > static.key <<KEY` with no
# assignment syntax for the assignment regex to catch). A bare hex line is
# a private-key candidate UNLESS it is unmistakably synthetic: fewer than
# three distinct characters (all-zero, all-one, repeated-pair fixtures).
RAW_PRIVATE_HEX_LINE = re.compile(rb"(?m)^[ \t]*[0-9a-fA-F]{64}[ \t]*$")

# Self-test fixtures built at runtime so no literal copy exists in the
# source (and therefore in history) for a rewrite pass to scrub.
_MOBILE_FIXTURE = ":".join(["fb91", "8c27", "13a3", "465", "94ff", "fef2", "1251"])
_GOOGLE_KEY_FIXTURE = "AIza" + "SyD1234567890abcdefghijklmnopqrstuv"
GENERIC_ASSIGNMENT_RE = re.compile(
    rb"(?im)(?:^|[^A-Za-z0-9])(?:[A-Za-z0-9]+[_-])*(?:password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret|"
    rb"private[_-]?key|webhook[_-]?secret|access[_-]?key)\b[\"']?\s*(?::|=)\s*"
    rb"[\"']?(?P<value>[A-Za-z0-9+/=_.,:@-]{16,512})"
)
PLACEHOLDER_MARKERS = (
    b"example",
    b"placeholder",
    b"redacted",
    b"change_me",
    b"changeme",
    b"replace_me",
    b"replace-with",
    b"your_",
    b"your-",
    b"dummy",
    b"not_required",
    b"notrequired",
)


class AuditError(RuntimeError):
    pass


def run_git(repo: pathlib.Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise AuditError(f"Git command failed ({' '.join(args)}): {detail or 'no diagnostic'}")
    return completed.stdout


def encoded_forms(value: str) -> tuple[bytes, ...]:
    raw = value.encode("utf-8")
    forms = {
        raw,
        value.encode("utf-16-le"),
        value.encode("utf-16-be"),
        base64.b64encode(raw),
    }
    return tuple(sorted(forms, key=len, reverse=True))


def validate_secrets(payload: object) -> dict[str, tuple[bytes, ...]]:
    if not isinstance(payload, dict) or not payload:
        raise AuditError("Secret scan input must be one non-empty JSON object.")
    validated: dict[str, tuple[bytes, ...]] = {}
    for label, value in payload.items():
        if not isinstance(label, str) or not SAFE_LABEL_RE.fullmatch(label):
            raise AuditError("Secret scan input contains an unsafe field label.")
        if not isinstance(value, str) or len(value) < 12:
            raise AuditError(f"Secret scan input {label} is too short for safe exact matching.")
        validated[label] = encoded_forms(value)
    return validated


def all_blob_objects(repo: pathlib.Path) -> list[tuple[str, int]]:
    output = run_git(
        repo,
        "cat-file",
        "--batch-all-objects",
        "--batch-check=%(objectname) %(objecttype) %(objectsize)",
    )
    blobs: list[tuple[str, int]] = []
    for raw_line in output.splitlines():
        parts = raw_line.decode("ascii", errors="strict").split()
        if len(parts) != 3:
            raise AuditError("Git object catalog returned malformed output.")
        object_id, object_type, size_text = parts
        if object_type == "blob":
            blobs.append((object_id, int(size_text)))
    if not blobs:
        raise AuditError("Git object catalog contains no blobs to inspect.")
    return blobs


def reachable_paths(repo: pathlib.Path) -> dict[str, list[str]]:
    output = run_git(repo, "rev-list", "--objects", "--all", "--reflog")
    paths: dict[str, list[str]] = defaultdict(list)
    for raw_line in output.splitlines():
        line = raw_line.decode("utf-8", errors="replace")
        object_id, separator, path = line.partition(" ")
        if separator and path and path not in paths[object_id]:
            paths[object_id].append(path)
    return paths


def redact_path_if_needed(
    path: str,
    candidates: dict[str, tuple[bytes, ...]],
    include_generic: bool,
) -> str:
    encoded = path.encode("utf-8", errors="replace")
    if any(pattern in encoded for forms in candidates.values() for pattern in forms):
        return "(path contains an active value; redacted)"
    if include_generic and generic_secret_labels(encoded):
        return "(path contains a secret-like value; redacted)"
    return path


def looks_like_secret_value(value: bytes) -> bool:
    lowered = value.lower()
    if any(marker in lowered for marker in PLACEHOLDER_MARKERS):
        return False
    if lowered in {b"none", b"null", b"false", b"true", b"undefined"}:
        return False
    return len(set(value)) >= 6


def generic_secret_labels(data: bytes) -> set[str]:
    matched = {
        label for label, pattern in GENERIC_TOKEN_PATTERNS if pattern.search(data)
    }
    if any(
        looks_like_secret_value(match.group("value"))
        for match in GENERIC_ASSIGNMENT_RE.finditer(data)
    ):
        matched.add("GENERIC_SECRET_ASSIGNMENT")
    # E-01: bare 64-hex lines (key-heredoc bodies) are private-key candidates
    # unless unmistakably synthetic (< 3 distinct characters).
    for line_match in RAW_PRIVATE_HEX_LINE.finditer(data):
        candidate = line_match.group(0).strip()
        if len(set(candidate.lower())) >= 3:
            matched.add("RAW_PRIVATE_HEX_LINE")
            break
    return matched


def current_worktree_paths(repo: pathlib.Path) -> list[str]:
    output = run_git(repo, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    paths = [
        raw.decode("utf-8", errors="surrogateescape")
        for raw in output.split(b"\0")
        if raw
    ]
    return sorted(set(paths))


def scan_stream(
    stream,
    size: int,
    candidates: dict[str, tuple[bytes, ...]],
    include_generic: bool = True,
) -> set[str]:
    remaining = size
    max_pattern = max(
        (len(pattern) for forms in candidates.values() for pattern in forms),
        default=1,
    )
    overlap = max(max_pattern - 1, GENERIC_SCAN_OVERLAP if include_generic else 0)
    tail = b""
    matched: set[str] = set()
    while remaining:
        chunk = stream.read(min(CHUNK_SIZE, remaining))
        if not chunk:
            raise AuditError("Git blob stream ended before the declared object size.")
        remaining -= len(chunk)
        window = tail + chunk
        for label, forms in candidates.items():
            if label not in matched and any(pattern in window for pattern in forms):
                matched.add(label)
        if include_generic:
            matched.update(generic_secret_labels(window))
        tail = window[-overlap:] if overlap else b""
    return matched


def scan_worktree(
    repo: pathlib.Path,
    candidates: dict[str, tuple[bytes, ...]],
    include_generic: bool = True,
) -> tuple[list[dict[str, str]], int, dict[str, int]]:
    repo = repo.resolve()
    findings: list[dict[str, str]] = []
    counts: dict[str, int] = defaultdict(int)
    inspected = 0
    for relative in current_worktree_paths(repo):
        path = repo / relative
        if not path.exists() or not path.is_file():
            continue
        resolved = path.resolve()
        try:
            resolved.relative_to(repo)
        except ValueError as exc:
            raise AuditError("A tracked or untracked file resolves outside the repository.") from exc
        inspected += 1
        with resolved.open("rb") as stream:
            matched = scan_stream(
                stream, resolved.stat().st_size, candidates, include_generic
            )
        for label in sorted(matched):
            counts[label] += 1
            if counts[label] <= MAX_FINDINGS_PER_LABEL:
                findings.append(
                    {
                        "field": label,
                        "path": redact_path_if_needed(
                            relative, candidates, include_generic
                        ),
                    }
                )
    return findings, inspected, dict(counts)


def scan_history(
    repo: pathlib.Path,
    candidates: dict[str, tuple[bytes, ...]],
    include_generic: bool = True,
) -> tuple[list[dict[str, object]], int, dict[str, int], int]:
    repo = repo.resolve()
    run_git(repo, "rev-parse", "--git-dir")
    blobs = all_blob_objects(repo)
    paths_by_object = reachable_paths(repo)
    findings: list[dict[str, object]] = []
    counts: dict[str, int] = defaultdict(int)
    matched_objects: set[str] = set()
    process = subprocess.Popen(
        ["git", "-C", str(repo), "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        process.kill()
        raise AuditError("Could not open the Git batch object reader.")
    try:
        for object_id, catalog_size in blobs:
            process.stdin.write((object_id + "\n").encode("ascii"))
            process.stdin.flush()
            header = process.stdout.readline().decode("ascii", errors="strict").strip().split()
            if len(header) != 3 or header[0] != object_id or header[1] != "blob":
                raise AuditError("Git batch object reader returned an unexpected header.")
            size = int(header[2])
            if size != catalog_size:
                raise AuditError("Git object size changed during the history audit.")
            matched = scan_stream(process.stdout, size, candidates, include_generic)
            if process.stdout.read(1) != b"\n":
                raise AuditError("Git batch object reader returned malformed framing.")
            for label in sorted(matched):
                counts[label] += 1
                matched_objects.add(object_id)
                if counts[label] <= MAX_FINDINGS_PER_LABEL:
                    findings.append(
                        {
                            "field": label,
                            "object": object_id,
                            "paths": [
                                redact_path_if_needed(
                                    path, candidates, include_generic
                                )
                                for path in paths_by_object.get(
                                    object_id, ["(unreachable-or-unnamed blob)"]
                                )[:5]
                            ],
                        }
                    )
        process.stdin.close()
        stderr = process.stderr.read().decode("utf-8", errors="replace").strip()
        return_code = process.wait()
        if return_code != 0:
            raise AuditError(f"Git batch object reader failed: {stderr or 'no diagnostic'}")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    return findings, len(blobs), dict(counts), len(matched_objects)


def format_report(
    findings: list[dict[str, object]],
    blob_count: int,
    counts: dict[str, int],
    matched_object_count: int,
) -> str:
    if not counts:
        return (
            f"Git history secret audit PASS: {blob_count} blobs contain none of the "
            "supplied active credential values or high-confidence generic secret signatures."
        )
    fields = sorted(counts)
    lines = [
        "Git history secret audit FAIL: "
        f"{len(fields)} credential field/signature(s) occur in {matched_object_count} historical or dangling blob(s).",
        "Matched fields/signatures (value-redacted occurrence counts): "
        + ", ".join(f"{field}={counts[field]}" for field in fields),
        f"Sample locations (at most {MAX_FINDINGS_PER_LABEL} per field):",
    ]
    for finding in findings:
        paths = ", ".join(str(path) for path in finding["paths"])
        lines.append(
            f"- {finding['field']}: {paths} @ {str(finding['object'])[:12]}"
        )
    lines.append("No credential values were printed. Rotate/revoke matched credentials, then purge and re-audit Git history.")
    return "\n".join(lines)


def format_worktree_report(
    findings: list[dict[str, str]],
    file_count: int,
    counts: dict[str, int],
) -> str:
    if not counts:
        return (
            f"Git worktree secret audit PASS: {file_count} tracked/untracked non-ignored files "
            "contain none of the supplied active credential values or high-confidence "
            "generic secret signatures."
        )
    fields = sorted(counts)
    lines = [
        "Git worktree secret audit FAIL: "
        f"{len(fields)} credential field/signature(s) occur in current source files.",
        "Matched fields/signatures (value-redacted file counts): "
        + ", ".join(f"{field}={counts[field]}" for field in fields),
        f"Sample locations (at most {MAX_FINDINGS_PER_LABEL} per field):",
    ]
    for finding in findings:
        lines.append(f"- {finding['field']}: {finding['path']}")
    lines.append("No credential values were printed. Remove current-file matches before release.")
    return "\n".join(lines)


def read_secret_payload() -> object:
    raw = sys.stdin.buffer.read()
    try:
        # Windows PowerShell 5.1's Process.StandardInput StreamWriter can emit
        # one UTF-8 BOM even when callers write the payload through BaseStream.
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise AuditError(
            f"Secret scan input is not valid UTF-8 (byte offset {exc.start}, {len(raw)} bytes)."
        ) from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise AuditError(
            f"Secret scan input is not valid JSON (character offset {exc.pos}, {len(text)} characters)."
        ) from exc


def self_test() -> None:
    secret = "self-test-secret-value-987654321"
    generic_secret = "github_pat_" + ("A9b" * 20)
    assigned_secret = "A7p9Q2m4R8v6N3x5K1z0"
    with tempfile.TemporaryDirectory(prefix="winsvpn-history-audit-") as temporary:
        repo = pathlib.Path(temporary)
        run_git(repo, "init", "--quiet")
        run_git(repo, "config", "user.email", "audit@example.invalid")
        run_git(repo, "config", "user.name", "History Audit Self Test")
        target = repo / "deleted-secret.txt"
        target.write_text(f"TOKEN={secret}\n", encoding="utf-8")
        run_git(repo, "add", "deleted-secret.txt")
        run_git(repo, "commit", "--quiet", "-m", "add fixture")
        target.unlink()
        run_git(repo, "add", "-u")
        run_git(repo, "commit", "--quiet", "-m", "delete fixture")
        generic_target = repo / "deleted-generic-secret.txt"
        generic_target.write_text(
            f"github={generic_secret}\nPAYPAL_CLIENT_SECRET={assigned_secret}\n",
            encoding="utf-8",
        )
        run_git(repo, "add", generic_target.name)
        run_git(repo, "commit", "--quiet", "-m", "add generic fixture")
        generic_target.unlink()
        run_git(repo, "add", "-u")
        run_git(repo, "commit", "--quiet", "-m", "delete generic fixture")
        candidates = validate_secrets({"SELF_TEST_TOKEN": secret})
        current_fixture = repo / "current-secret.txt"
        current_fixture.write_text(f"TOKEN={secret}\n", encoding="utf-8")
        worktree_findings, worktree_file_count, worktree_counts = scan_worktree(repo, candidates)
        worktree_report = format_worktree_report(
            worktree_findings, worktree_file_count, worktree_counts
        )
        if not worktree_findings or "current-secret.txt" not in worktree_report:
            raise AuditError("Self-test did not detect the current credential fixture.")
        if secret in worktree_report:
            raise AuditError("Self-test worktree report disclosed the credential fixture.")
        current_fixture.unlink()
        findings, blob_count, counts, matched_object_count = scan_history(repo, candidates)
        report = format_report(findings, blob_count, counts, matched_object_count)
        if not findings or "deleted-secret.txt" not in report:
            raise AuditError("Self-test did not detect the deleted credential fixture.")
        if secret in report:
            raise AuditError("Self-test report disclosed the credential fixture.")
        if generic_secret in report or assigned_secret in report:
            raise AuditError("Self-test report disclosed a generic credential fixture.")
        if counts.get("GITHUB_TOKEN", 0) < 1:
            raise AuditError("Self-test did not detect the generic GitHub token signature.")
        if counts.get("GENERIC_SECRET_ASSIGNMENT", 0) < 1:
            raise AuditError("Self-test did not detect the generic secret assignment.")
        placeholder = repo / "placeholder.env"
        placeholder.write_text(
            "API_TOKEN=replace_me_with_your_token\n",
            encoding="utf-8",
        )
        placeholder_findings, _, placeholder_counts = scan_worktree(
            repo, {}, include_generic=True
        )
        if placeholder_findings or placeholder_counts:
            raise AuditError("Self-test reported a false positive for a placeholder value.")
        placeholder.unlink()
        clean, _, clean_counts, _ = scan_history(
            repo,
            validate_secrets({"UNUSED_TOKEN": "unrelated-value-123456789"}),
            include_generic=False,
        )
        if clean or clean_counts:
            raise AuditError("Self-test reported a false positive for an unrelated value.")

        # E-01/E-03 (Sol audit, 2026-08-28): each previously-missed class
        # gets a REAL committed-and-deleted fixture the scanner must catch,
        # and a synthetic/allowed-negative it must not.
        leak_fixture = repo / "leaked-classes.txt"
        leak_fixture.write_text(
            # Raw 64-hex key body (the D-01 shape: non-uniform, heredoc line).
            "a3f1c05b6d92e8477ac1f0b3d5e29864f1a0c7b9e2d8451f6a3c0b7e9d2f4518\n"
            # Google provider key shape.
            f"maps_key={_GOOGLE_KEY_FIXTURE}\n"
            # GPS-precision coordinate pair.
            "widget q=40.712834,-74.006590&lang=en\n"
            # Mobile-carrier global IPv6 -- runtime-constructed so no literal
            # copy sits in the source for a rewrite pass to scrub (that
            # happened on 2026-08-28 and silently disarmed this fixture).
            f"rmnet_data3 2607:{_MOBILE_FIXTURE}/64\n",
            encoding="utf-8",
        )
        run_git(repo, "add", leak_fixture.name)
        run_git(repo, "commit", "--quiet", "-m", "add class fixtures")
        leak_fixture.unlink()
        run_git(repo, "add", "-u")
        run_git(repo, "commit", "--quiet", "-m", "delete class fixtures")
        # Tag-only reachability: the blob lives ONLY under a tag.
        run_git(repo, "tag", "class-fixture-tag")
        class_findings, _, class_counts, _ = scan_history(repo, {})
        class_report = format_report(class_findings, 0, class_counts, 0)
        for label in (
            "RAW_PRIVATE_HEX_LINE",
            "GOOGLE_API_KEY",
            "GPS_COORDINATE_PAIR",
            "MOBILE_CARRIER_IPV6",
        ):
            if class_counts.get(label, 0) < 1:
                raise AuditError(
                    f"Self-test did not detect the {label} class fixture "
                    f"(E-01). A history carrying it would PASS the audit."
                )
        if "leaked-classes.txt" not in class_report and "redacted" not in class_report:
            raise AuditError("Self-test class-fixture report lost the path.")
        # Allowed negatives: uniform synthetic hex, dp-dimension pair.
        negative_fixture = repo / "synthetic-fixtures.txt"
        negative_fixture.write_text(
            "1111111111111111111111111111111111111111111111111111111111111111\n"
            "isSmallWidget: 393.94885,282.31732\n",
            encoding="utf-8",
        )
        negative_findings, _, negative_counts = scan_worktree(
            repo, {}, include_generic=True
        )
        if "synthetic-fixtures.txt" in format_worktree_report(
            negative_findings, 1, negative_counts
        ):
            raise AuditError(
                "Self-test flagged a synthetic uniform-hex or dp-dimension "
                "fixture (false positive)."
            )
        negative_fixture.unlink()
    print("Git history secret audit self-test PASS.")


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=pathlib.Path, default=ROOT)
    parser.add_argument("--secrets-stdin", action="store_true")
    parser.add_argument("--fail-on-findings", action="store_true")
    parser.add_argument("--include-worktree", action="store_true")
    parser.add_argument("--worktree-only", action="store_true")
    parser.add_argument(
        "--exact-only",
        action="store_true",
        help="Disable generic secret signatures and scan only supplied exact values.",
    )
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.self_test:
            self_test()
            return 0
        if args.exact_only and not args.secrets_stdin:
            raise AuditError("--exact-only requires --secrets-stdin.")
        if args.worktree_only and not args.include_worktree:
            raise AuditError("--worktree-only requires --include-worktree.")
        candidates = (
            validate_secrets(read_secret_payload()) if args.secrets_stdin else {}
        )
        include_generic = not args.exact_only
        worktree_counts: dict[str, int] = {}
        if args.include_worktree:
            worktree_findings, worktree_file_count, worktree_counts = scan_worktree(
                args.repo, candidates, include_generic
            )
            print(
                format_worktree_report(
                    worktree_findings, worktree_file_count, worktree_counts
                )
            )
        counts: dict[str, int] = {}
        if not args.worktree_only:
            findings, blob_count, counts, matched_object_count = scan_history(
                args.repo, candidates, include_generic
            )
            print(format_report(findings, blob_count, counts, matched_object_count))
        return 2 if (counts or worktree_counts) and args.fail_on_findings else 0
    except (AuditError, OSError, ValueError) as exc:
        print(f"Git history secret audit ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
