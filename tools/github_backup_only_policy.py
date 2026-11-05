#!/usr/bin/env python3
"""Fail-closed local policy: GitHub is cloud backup, never an execution platform.

Workflow files may remain in the repository so a clone still has the backup
copy of GitHub metadata. Every YAML workflow, including Linux, must be one
manual refusal sentinel with exactly one job and one step. The step may only
emit static refusal text and terminate with the fixed command ``exit 64``.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys


REQUIRED_WORKFLOWS = frozenset(
    {
        "apple-winn3-and-abi.yml",
        "build-android-debug.yml",
        "build-android-satellites.yml",
        "build-apple-shells.yml",
        "build-linux-release.yml",
        "dart-analyze-test.yml",
        "go-winn-protocol.yml",
        "native-standalone-tests.yml",
        "test-and-validate.yml",
        "windows-tunnel-service-compile.yml",
        "winn3-conformance.yml",
    }
)
ALLOWED_TRIGGERS = frozenset({"workflow_dispatch"})
ALLOWED_TOP_LEVEL_KEYS = frozenset(
    {"name", "on", "permissions", "concurrency", "jobs"}
)
ALLOWED_JOB_KEYS = frozenset({"name", "runs-on", "timeout-minutes", "steps"})
ALLOWED_STEP_KEYS = frozenset({"name", "shell", "run"})
REQUIRED_ACTIVE_MARKERS = (
    "contents: read",
    "exit 64",
)
FORBIDDEN_ACTIVE_SUBSTRINGS = (
    "id-token:",
    "oidc",
    "upload-artifact",
    "download-artifact",
    "actions/checkout",
    "actions/cache",
    "actions/setup-",
    "actions/upload",
    "actions/download",
    "actions/deploy",
    "actions/create-release",
    "actions/attest",
    "softprops/",
    "peaceiris/",
    "subosito/",
    "docker/login",
    "github-pages",
    "gh release",
    "sign-blob",
    "verify-blob",
    "sign_staged",
    "cosign ",
    "sigstore",
    "environment:",
    "contents: write",
    "packages: write",
    "actions: write",
    "id-token: write",
    "attestations:",
    "deployments:",
    "continue-on-error",
    "pull_request_target",
    "workflow_call",
    "repository_dispatch",
    "workflow_run",
)
FORBIDDEN_ACTIVE_COMMANDS = (
    "flutter",
    "gradle",
    "gradlew",
    "xcodebuild",
    "go test",
    "go build",
    "go vet",
    "gofmt",
    "cargo ",
    "npm ",
    "pip install",
    "apt-get",
    "sdkmanager",
    "dotnet ",
    "msbuild",
    "clang-cl",
    "gh ",
    "gcloud ",
    "aws ",
    "az ",
    "docker ",
    "cosign",
)
_KEY_LINE = re.compile(r"^('([^']+)'|\"([^\"]+)\"|([^:#{}[\]]+))\s*:(.*)$")
_PERMISSION_WRITE = re.compile(
    r"^(contents|packages|actions|id-token|attestations|deployments|pages|"
    r"pull-requests|issues|checks|statuses|security-events)\s*:\s*write$"
)
_STATIC_STDERR_ECHO = re.compile(r'^echo "[A-Za-z0-9 .,()\'/:_-]+" >&2$')
_CANONICAL_REFUSAL_SCRIPT = (
    "set -euo pipefail\n"
    "{first_message}\n"
    "{second_message}\n"
    "exit 64\n"
)


def _strip_yaml_comment(line: str) -> str:
    in_single = False
    in_double = False
    escaped = False
    for index, char in enumerate(line):
        if in_double:
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == '"':
                in_double = False
            continue
        if in_single:
            if char == "'":
                in_single = False
            continue
        if char == "'":
            in_single = True
            continue
        if char == '"':
            in_double = True
            continue
        if char == "#":
            return line[:index].rstrip()
    return line.rstrip()


def active_lines(text: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    literal_run_indent: int | None = None
    for raw in text.splitlines():
        expanded = raw.replace("\t", "    ")
        raw_indent = len(expanded) - len(expanded.lstrip(" "))
        if literal_run_indent is not None:
            if not expanded.strip():
                continue
            if raw_indent > literal_run_indent:
                lines.append((raw_indent, expanded.strip()))
                continue
            literal_run_indent = None
        stripped = _strip_yaml_comment(expanded)
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        content = stripped.strip()
        lines.append((indent, content))
        key, rest = _mapping_key(content)
        if key == "run" and rest in {"|", "|-", "|+"}:
            literal_run_indent = indent
    return lines


def _strip_sequence_prefix(content: str) -> str:
    if content.startswith("- "):
        return content[2:].strip()
    if content == "-":
        return ""
    return content


def _mapping_key(content: str) -> tuple[str | None, str]:
    match = _KEY_LINE.match(_strip_sequence_prefix(content))
    if not match:
        return None, content
    key = match.group(2) or match.group(3) or match.group(4)
    rest = (match.group(5) or "").strip()
    if key is None:
        return None, content
    return key.strip(), rest


def _block_after(lines: list[tuple[int, str]], key: str) -> tuple[str, list[tuple[int, str]]]:
    capturing = False
    inline = ""
    block: list[tuple[int, str]] = []
    parent_indent: int | None = None
    for indent, content in lines:
        if not capturing:
            found_key, rest = _mapping_key(content)
            if found_key == key:
                capturing = True
                parent_indent = indent
                inline = rest
            continue
        if parent_indent is not None and indent <= parent_indent:
            break
        block.append((indent, content))
    return inline, block


def _flow_items(value: str) -> list[str]:
    inner = value.strip()
    if inner.startswith("[") and inner.endswith("]"):
        inner = inner[1:-1]
    elif inner.startswith("{") and inner.endswith("}"):
        inner = inner[1:-1]
    items: list[str] = []
    for part in inner.split(","):
        token = part.strip().strip("'\"")
        if not token:
            continue
        key, _rest = _mapping_key(token) if ":" in token else (token, "")
        items.append(key or token)
    return items


def workflow_triggers(text: str) -> set[str]:
    lines = active_lines(text)
    inline, block = _block_after(lines, "on")
    names: set[str] = set()
    if inline:
        if inline.startswith("[") or inline.startswith("{"):
            names.update(_flow_items(inline))
        else:
            names.add(inline.strip("'\" "))
    if block:
        child_indent = min(indent for indent, _ in block)
        for indent, content in block:
            if indent != child_indent:
                continue
            item = _strip_sequence_prefix(content)
            key, rest = _mapping_key(content)
            if key is None:
                if item.startswith("[") or item.startswith("{"):
                    names.update(_flow_items(item))
                elif item:
                    names.add(item.strip("'\""))
                continue
            if key == "<<":
                names.add("yaml-merge")
            else:
                names.add(key)
            if rest.startswith("[") or rest.startswith("{"):
                names.update(_flow_items(rest))
    return {name for name in names if name}


def _active_text(text: str) -> str:
    return "\n".join(content for _indent, content in active_lines(text))


def _has_run_exit_64(text: str) -> bool:
    lines = active_lines(text)
    in_run = False
    run_indent = 0
    for indent, content in lines:
        key, rest = _mapping_key(content)
        if key == "run":
            if re.search(r"\bexit\s+64\b", rest):
                return True
            in_run = rest in {"|", "|-", "|+", ">", ">-", ">+", ""}
            run_indent = indent
            continue
        if in_run:
            if indent <= run_indent:
                in_run = False
            elif re.search(r"\bexit\s+64\b", content):
                return True
    return False


def _direct_entries(
    lines: list[tuple[int, str]],
    start: int,
    end: int,
    parent_indent: int,
) -> tuple[int | None, list[tuple[int, str, str, str]]]:
    child_indents = [
        indent for indent, _content in lines[start:end] if indent > parent_indent
    ]
    if not child_indents:
        return None, []
    direct_indent = min(child_indents)
    entries: list[tuple[int, str, str, str]] = []
    for index in range(start, end):
        indent, content = lines[index]
        if indent != direct_indent:
            continue
        if content.startswith("-"):
            entries.append((index, "<sequence>", "", content))
            continue
        key, rest = _mapping_key(content)
        entries.append((index, key or "<scalar>", rest, content))
    return direct_indent, entries


def _entry_end(
    lines: list[tuple[int, str]], index: int, limit: int
) -> int:
    indent = lines[index][0]
    for cursor in range(index + 1, limit):
        if lines[cursor][0] <= indent:
            return cursor
    return limit


def _duplicate_keys(entries: list[tuple[int, str, str, str]]) -> set[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for _index, key, _rest, _content in entries:
        if key in seen:
            duplicates.add(key)
        seen.add(key)
    return duplicates


def _is_exact_scalar(value: str, expected: str) -> bool:
    return value in {expected, f"'{expected}'", f'"{expected}"'}


def _raw_literal_run_scalar(text: str) -> str | None:
    source = text.splitlines(keepends=True)
    candidates: list[str] = []
    cursor = 0
    while cursor < len(source):
        raw = source[cursor]
        if "\t" in raw:
            return None
        line = raw.rstrip("\r\n")
        stripped = _strip_yaml_comment(line)
        indent = len(stripped) - len(stripped.lstrip(" "))
        key, rest = _mapping_key(stripped.strip())
        if key != "run":
            cursor += 1
            continue
        if rest != "|":
            return None
        body_indent = indent + 2
        body: list[str] = []
        cursor += 1
        while cursor < len(source):
            body_raw = source[cursor]
            if "\t" in body_raw:
                return None
            body_line = body_raw.rstrip("\r\n")
            body_line_indent = len(body_line) - len(body_line.lstrip(" "))
            if body_line.strip() and body_line_indent <= indent:
                break
            if not body_line.strip():
                body.append("\n")
                cursor += 1
                continue
            if body_line_indent != body_indent:
                return None
            body.append(body_line[body_indent:] + "\n")
            cursor += 1
        while body and body[-1] == "\n":
            body.pop()
        candidates.append("".join(body))
    if len(candidates) != 1:
        return None
    return candidates[0]


def _strict_refusal_script(text: str) -> bool:
    scalar = _raw_literal_run_scalar(text)
    if scalar is None:
        return False
    lines = scalar.splitlines()
    if len(lines) != 4:
        return False
    first_message = lines[1]
    second_message = lines[2]
    if _STATIC_STDERR_ECHO.fullmatch(first_message) is None:
        return False
    if _STATIC_STDERR_ECHO.fullmatch(second_message) is None:
        return False
    canonical = _CANONICAL_REFUSAL_SCRIPT.format(
        first_message=first_message,
        second_message=second_message,
    )
    return scalar == canonical


def _structural_problems(text: str, filename: str) -> list[str]:
    prefix = f"{filename}: "
    lines = active_lines(text)
    if not lines:
        return [prefix + "workflow is empty"]
    problems: list[str] = []

    top_indent, top = _direct_entries(lines, 0, len(lines), -1)
    if top_indent != 0:
        return [prefix + "top-level workflow mapping must start at indentation zero"]
    duplicate_top = _duplicate_keys(top)
    if duplicate_top:
        problems.append(
            prefix + "duplicate top-level key(s): " + ", ".join(sorted(duplicate_top))
        )
    unknown_top = sorted({entry[1] for entry in top} - ALLOWED_TOP_LEVEL_KEYS)
    if unknown_top:
        problems.append(
            prefix + "unexpected top-level key(s): " + ", ".join(unknown_top)
        )

    permissions_entries = [entry for entry in top if entry[1] == "permissions"]
    if len(permissions_entries) != 1:
        problems.append(
            prefix + "must contain exactly one top-level permissions mapping"
        )
    else:
        permissions_index, _key, permissions_rest, _content = permissions_entries[0]
        permissions_end = _entry_end(lines, permissions_index, len(lines))
        if permissions_rest:
            problems.append(prefix + "permissions must be exactly {contents: read}")
        else:
            _indent, scopes = _direct_entries(
                lines,
                permissions_index + 1,
                permissions_end,
                lines[permissions_index][0],
            )
            if (
                len(scopes) != 1
                or scopes[0][1] != "contents"
                or not _is_exact_scalar(scopes[0][2], "read")
                or _entry_end(lines, scopes[0][0], permissions_end)
                != scopes[0][0] + 1
            ):
                problems.append(prefix + "permissions must be exactly {contents: read}")

    on_entries = [entry for entry in top if entry[1] == "on"]
    if len(on_entries) != 1:
        problems.append(prefix + "must contain exactly one top-level on mapping")
    else:
        on_index, _key, on_rest, _content = on_entries[0]
        on_end = _entry_end(lines, on_index, len(lines))
        if on_rest:
            scalar = on_rest.strip("'\"")
            if scalar != "workflow_dispatch" or on_end != on_index + 1:
                problems.append(prefix + "on must contain only workflow_dispatch")
        else:
            _indent, triggers = _direct_entries(
                lines, on_index + 1, on_end, lines[on_index][0]
            )
            if (
                len(triggers) != 1
                or triggers[0][1] != "workflow_dispatch"
                or triggers[0][2] not in {"", "{}"}
                or _entry_end(lines, triggers[0][0], on_end) != triggers[0][0] + 1
            ):
                problems.append(prefix + "on must contain only workflow_dispatch")

    jobs_entries = [entry for entry in top if entry[1] == "jobs"]
    if len(jobs_entries) != 1:
        problems.append(prefix + "must contain exactly one top-level jobs mapping")
        return problems
    jobs_index, _key, jobs_rest, _content = jobs_entries[0]
    jobs_end = _entry_end(lines, jobs_index, len(lines))
    if jobs_rest:
        problems.append(prefix + "jobs must be a block mapping")
        return problems
    _indent, jobs = _direct_entries(
        lines, jobs_index + 1, jobs_end, lines[jobs_index][0]
    )
    if (
        len(jobs) != 1
        or jobs[0][1] in {"<sequence>", "<scalar>"}
        or jobs[0][2]
    ):
        problems.append(prefix + "must contain exactly one job")
        return problems

    job_index = jobs[0][0]
    job_end = _entry_end(lines, job_index, jobs_end)
    _indent, job_fields = _direct_entries(
        lines, job_index + 1, job_end, lines[job_index][0]
    )
    duplicate_job = _duplicate_keys(job_fields)
    unknown_job = sorted({entry[1] for entry in job_fields} - ALLOWED_JOB_KEYS)
    if duplicate_job:
        problems.append(prefix + "duplicate job key(s): " + ", ".join(sorted(duplicate_job)))
    if unknown_job:
        problems.append(prefix + "unexpected job key(s): " + ", ".join(unknown_job))
    runs_on_entries = [entry for entry in job_fields if entry[1] == "runs-on"]
    if (
        len(runs_on_entries) != 1
        or not _is_exact_scalar(runs_on_entries[0][2], "ubuntu-24.04")
        or _entry_end(lines, runs_on_entries[0][0], job_end)
        != runs_on_entries[0][0] + 1
    ):
        problems.append(prefix + "single refusal job runs-on must be exactly ubuntu-24.04")
    timeout_entries = [entry for entry in job_fields if entry[1] == "timeout-minutes"]
    if (
        len(timeout_entries) != 1
        or not _is_exact_scalar(timeout_entries[0][2], "5")
        or _entry_end(lines, timeout_entries[0][0], job_end)
        != timeout_entries[0][0] + 1
    ):
        problems.append(prefix + "single refusal job timeout-minutes must be exactly 5")
    steps_entries = [entry for entry in job_fields if entry[1] == "steps"]
    if len(steps_entries) != 1 or steps_entries[0][2]:
        problems.append(prefix + "job must contain exactly one block steps list")
        return problems

    steps_index = steps_entries[0][0]
    steps_end = _entry_end(lines, steps_index, job_end)
    step_indent, step_items = _direct_entries(
        lines, steps_index + 1, steps_end, lines[steps_index][0]
    )
    if (
        step_indent is None
        or len(step_items) != 1
        or step_items[0][1] != "<sequence>"
    ):
        problems.append(prefix + "must contain exactly one step")
        return problems

    step_index = step_items[0][0]
    first_key, first_rest = _mapping_key(lines[step_index][1])
    if first_key is None:
        problems.append(prefix + "step must be a mapping")
        return problems
    step_fields: list[tuple[int, str, str, str]] = [
        (step_index, first_key, first_rest, lines[step_index][1])
    ]
    if step_index + 1 < steps_end:
        nested_indent, nested = _direct_entries(
            lines, step_index + 1, steps_end, lines[step_index][0]
        )
        if nested_indent is not None:
            step_fields.extend(nested)
    duplicate_step = _duplicate_keys(step_fields)
    unknown_step = sorted({entry[1] for entry in step_fields} - ALLOWED_STEP_KEYS)
    if duplicate_step:
        problems.append(prefix + "duplicate step key(s): " + ", ".join(sorted(duplicate_step)))
    if unknown_step:
        problems.append(prefix + "unexpected step key(s): " + ", ".join(unknown_step))
    shell_entries = [entry for entry in step_fields if entry[1] == "shell"]
    if (
        len(shell_entries) != 1
        or not _is_exact_scalar(shell_entries[0][2], "bash")
        or _entry_end(lines, shell_entries[0][0], steps_end)
        != shell_entries[0][0] + 1
    ):
        problems.append(prefix + "single refusal step shell must be exactly bash")
    run_entries = [entry for entry in step_fields if entry[1] == "run"]
    if len(run_entries) != 1:
        problems.append(prefix + "single refusal step must contain exactly one run command")
        return problems
    _run_index, _key, _run_rest, _content = run_entries[0]
    if not _strict_refusal_script(text):
        problems.append(
            prefix
            + "run must byte-match the canonical refusal script: safe preamble, two static stderr messages, then exit 64"
        )
    return problems


def problems_for_workflow(text: str, filename: str = "workflow.yml") -> list[str]:
    prefix = f"{filename}: "
    problems: list[str] = []
    if not text.strip():
        return [prefix + "workflow is empty"]

    problems.extend(_structural_problems(text, filename))
    active = _active_text(text)
    lowered = active.lower()
    triggers = workflow_triggers(text)
    if not triggers:
        problems.append(prefix + "no GitHub event trigger")
    unexpected = sorted(triggers - ALLOWED_TRIGGERS)
    if unexpected:
        problems.append(
            prefix + "executable or extra trigger(s): " + ", ".join(unexpected)
        )
    if "workflow_dispatch" not in triggers and "workflow_dispatch:" not in lowered:
        problems.append(prefix + "manual sentinel trigger workflow_dispatch is missing")

    for marker in REQUIRED_ACTIVE_MARKERS:
        if marker not in lowered:
            problems.append(prefix + f"missing required sentinel marker {marker!r}")

    if not _has_run_exit_64(text):
        problems.append(prefix + "refusal job does not exit 64")

    for _indent, content in active_lines(text):
        item = _strip_sequence_prefix(content)
        key, rest = _mapping_key(content)
        if key == "uses" or item.lower().startswith("uses:"):
            problems.append(prefix + f"hosted action is forbidden: {content}")
        if key == "if":
            problems.append(prefix + "conditional job/step skip is forbidden")
        if key == "environment":
            problems.append(prefix + "deployment environment is forbidden")
        permission_line = item if key is None else f"{key}: {rest}" if rest else item
        if _PERMISSION_WRITE.match(permission_line):
            problems.append(prefix + f"write permission is forbidden: {content}")

    for forbidden in FORBIDDEN_ACTIVE_SUBSTRINGS:
        if forbidden in lowered:
            problems.append(prefix + f"retained hosted authority: {forbidden}")
    for forbidden in FORBIDDEN_ACTIVE_COMMANDS:
        if forbidden in lowered:
            problems.append(prefix + f"hosted command is forbidden: {forbidden}")

    if "${{ secrets." in lowered or "${{ vars." in lowered:
        problems.append(prefix + "hosted secrets or variables are forbidden")
    # Deduplicate while preserving order.
    seen: set[str] = set()
    unique: list[str] = []
    for problem in problems:
        if problem in seen:
            continue
        seen.add(problem)
        unique.append(problem)
    return unique


def workflow_paths(root: pathlib.Path) -> list[pathlib.Path]:
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return []
    paths = [
        path
        for path in sorted(workflow_dir.iterdir())
        if path.is_file()
        and not path.is_symlink()
        and path.suffix.lower() in {".yml", ".yaml"}
    ]
    return paths


def check_repository(
    root: pathlib.Path,
    *,
    required: frozenset[str] = REQUIRED_WORKFLOWS,
) -> list[str]:
    workflow_dir = root / ".github" / "workflows"
    problems: list[str] = []
    if not workflow_dir.is_dir():
        return ["missing .github/workflows; GitHub backup sentinels are absent"]

    paths = workflow_paths(root)
    names = {path.name for path in paths}
    missing = sorted(required - names)
    if missing:
        problems.append(
            "required backup sentinel(s) missing: " + ", ".join(missing)
        )

    for path in paths:
        relative = path.relative_to(root).as_posix()
        problems.extend(
            problems_for_workflow(path.read_text(encoding="utf-8"), relative)
        )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Refuse GitHub workflow execution authority locally."
    )
    parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[1],
        help="repository root to scan",
    )
    args = parser.parse_args(argv)
    problems = check_repository(args.root.resolve())
    if problems:
        print("GitHub backup-only policy REJECTED:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 73
    print(
        "PASS GitHub is backup storage only: all workflows are inert "
        "manual sentinels"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
