#!/usr/bin/env python3
"""Run the complete deterministic release-critical Python test suite.

Two invocation conventions coexist in tools/: most ``tools/test_*.py`` files do bare,
sibling-relative imports (`import some_module`) and must run as a direct
script so `tools/` itself is on sys.path[0]; a handful instead do
package-qualified imports (`from tools import some_module` / `from
tools.some_module import ...` / `import tools.some_module`) and must run as
`python3 -m tools.test_x` so the repo root is on sys.path[0] instead. Running a file
the wrong way fails with a ModuleNotFoundError that has nothing to do
with the test itself, so this picks the invocation per file instead of
guessing one convention for all of them.  Newer release suites use pytest
functions and fixtures, so they are invoked through pytest instead.

Files named test_*.py can also be executable verification utilities rather
than ordinary unittest entry points. When such a utility declares required
argparse subcommands, the runner invokes its explicit --self-test entry point
instead of executing the CLI without a command. A required-subcommand utility
without an explicit self-test entry point is rejected fail-closed.

Discovery is intentionally a short allowlist of release-owned roots, not a
repository-wide recursive scan. Server control-plane unit suites and the exact
website download-policy test are release-critical and explicitly included.
Deployment, documentation evidence, and staging-hub tests remain separately
governed operational suites. Fixture/testdata descendants are excluded even
inside an allowed root. This keeps the suite stable, prevents helper fixtures
from being treated as tests, and makes a newly added release test fail closed in
the G19 gate through this same runner.
"""

from __future__ import annotations

import ast
import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = ROOT / "tools"
TIMEOUT_SECONDS = 120
ACTIVE_CUSTODY_ENV = frozenset(
    {
        "WINS_RELEASE_PYTHON_RUNTIME",
        "WINS_RELEASE_PYTHON_RUNTIME_ID",
        "WINS_RELEASE_PYTHON_BIN",
        "WINS_RELEASE_PYTHON_VENDOR",
        "WINS_RELEASE_CHILD_PYTHON",
    }
)
PYTHON_CUSTODY_BOOTSTRAP_TESTS = frozenset(
    {
        "tools/test_release_python_archive_custody.py",
        "tools/test_release_gate_determinism.py",
    }
)
BROWSER_RUNTIME_TESTS = frozenset({"extension/tools/core_tests.py"})

# Each rule is one directory level only.  Do not turn these into rglob calls:
# nested fixture/testdata directories can contain executable test-shaped
# helpers that are not independent release suites.
DISCOVERY_RULES: tuple[tuple[str, str, str], ...] = (
    ("tools", "test_*.py", "script"),
    ("tools", "*_test.py", "pytest"),
    ("tools/native_messaging", "test_*.py", "pytest"),
    ("router/tests", "test_*.py", "pytest"),
    ("dashboard", "test_*.py", "pytest"),
    ("extension/tools", "test_*.py", "pytest"),
    ("extension/tools", "core_tests.py", "script"),
    ("server", "test_*.py", "script"),
    ("test", "web_download_asset_decision_test.py", "script"),
    ("test", "web_download_artifact_gate.py", "script"),
    ("test", "web_download_artifact_gate_test.py", "script"),
)

# These files use pytest fixtures even though the rest of server/test_*.py is
# intentionally executed as direct scripts. Keep the exception separate from
# discovery so no path can match two rules with order-dependent semantics.
EXECUTION_MODE_OVERRIDES: dict[str, str] = {
    "server/test_site_ai_redirect_hardening.py": "pytest",
    "server/test_smart_router_hub_selection.py": "pytest",
}

# These roots are intentionally out of the application release suite.  Their
# tests need different operational inputs or are evidence/fixture helpers.  A
# new release-owned Python test belongs in DISCOVERY_RULES, never by broadening
# discovery to every test-shaped file in the checkout.
EXCLUDED_TEST_ROOTS: dict[str, str] = {
    "deploy/audit": "deployment audit requires separately governed target evidence",
    "docs/evidence": "documentation evidence helpers are not release suites",
    "staging-hub": "staging hub tests require separately governed staging inputs",
    "test": "Flutter tests are governed by G07 except the explicit Python website release suites",
}
EXCLUDED_TEST_COMPONENTS = frozenset({"fixtures", "fixture", "testdata", "__pycache__"})


class TestInvocationError(ValueError):
    """The runner cannot safely determine how to execute a test file."""


def _is_fixture_or_helper_path(path: Path, root: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return True
    return any(component in EXCLUDED_TEST_COMPONENTS for component in relative.parts)


def discovery_mode(path: Path, root: Path = ROOT) -> str:
    """Return the one approved execution mode for a discovered test path."""
    relative = path.relative_to(root).as_posix()
    if relative in EXECUTION_MODE_OVERRIDES:
        return EXECUTION_MODE_OVERRIDES[relative]
    for directory, pattern, mode in DISCOVERY_RULES:
        parent = (root / directory).resolve()
        if path.parent.resolve() == parent and path.match(pattern):
            return mode
    raise TestInvocationError(f"{relative}: not in an approved release-test root")


def discover_test_files(root: Path = ROOT) -> list[Path]:
    """Return sorted, unique, regular release-critical Python test files."""
    discovered: dict[str, Path] = {}
    for directory, pattern, _mode in DISCOVERY_RULES:
        base = root / directory
        if not base.is_dir() or base.is_symlink():
            continue
        for path in base.glob(pattern):
            if path.is_symlink() or not path.is_file() or _is_fixture_or_helper_path(path, root):
                continue
            relative = path.relative_to(root).as_posix()
            mode = discovery_mode(path, root)
            previous = discovered.setdefault(relative, path)
            if previous != path:
                raise TestInvocationError(f"duplicate release-test discovery: {relative}")
            if mode not in {"script", "pytest"}:
                raise TestInvocationError(f"{relative}: unknown execution mode {mode!r}")
    return [discovered[relative] for relative in sorted(discovered)]


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def needs_package_invocation(path: Path, tree: ast.Module | None = None) -> bool:
    tree = tree or _parse(path)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and (
            node.module == "tools" or node.module.startswith("tools.")
        ):
            return True
        if isinstance(node, ast.Import) and any(
            alias.name == "tools" or alias.name.startswith("tools.")
            for alias in node.names
        ):
            return True
    return False


def _has_required_subcommands(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if (
            not isinstance(node.func, ast.Attribute)
            or node.func.attr != "add_subparsers"
        ):
            continue
        if any(
            keyword.arg == "required"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        ):
            return True
    return False


def _is_sys_argv_index(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Attribute)
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == "sys"
        and node.value.attr == "argv"
    )


def _has_explicit_self_test_entrypoint(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1:
            continue
        if not isinstance(node.ops[0], ast.Eq) or len(node.comparators) != 1:
            continue
        left, right = node.left, node.comparators[0]
        if _is_sys_argv_index(left) and isinstance(right, ast.Constant):
            if right.value == "--self-test":
                return True
        if _is_sys_argv_index(right) and isinstance(left, ast.Constant):
            if left.value == "--self-test":
                return True
    return False


def test_arguments(path: Path, tree: ast.Module | None = None) -> list[str]:
    tree = tree or _parse(path)
    if not _has_required_subcommands(tree):
        return []
    if _has_explicit_self_test_entrypoint(tree):
        return ["--self-test"]
    raise TestInvocationError(
        f"{path.name}: required argparse subcommands but no explicit "
        "--self-test entry point"
    )


def command_for(path: Path, root: Path = ROOT) -> list[str]:
    child_python = os.environ.get("WINS_RELEASE_CHILD_PYTHON", "")
    if child_python:
        executable = Path(child_python)
        if (
            not executable.is_absolute()
            or executable.is_symlink()
            or not executable.is_file()
            or not os.access(executable, os.X_OK)
        ):
            raise TestInvocationError(
                "WINS_RELEASE_CHILD_PYTHON is not an absolute executable regular file"
            )
        python_executable = str(executable)
    else:
        python_executable = sys.executable
    if discovery_mode(path, root) == "pytest":
        return [
            python_executable,
            "-S",
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            path.relative_to(root).as_posix(),
        ]
    tree = _parse(path)
    module = "tools." + path.stem
    if needs_package_invocation(path, tree):
        command = [python_executable, "-S", "-m", module]
    else:
        command = [python_executable, "-S", str(path)]
    return command + test_arguments(path, tree)


def run_one(path: Path, root: Path = ROOT) -> tuple[bool, str, float]:
    start = time.monotonic()
    try:
        cmd = command_for(path, root)
        child_env = os.environ.copy()
        for variable in ACTIVE_CUSTODY_ENV:
            child_env.pop(variable, None)
        child_env["PYTHONEXECUTABLE"] = cmd[0]
        proc = subprocess.run(
            cmd,
            cwd=root,
            env=child_env,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
        )
        ok = proc.returncode == 0
        output = proc.stdout + proc.stderr
    except (SyntaxError, TestInvocationError) as exc:
        ok = False
        output = f"RUNNER CLASSIFICATION ERROR: {exc}"
    except subprocess.TimeoutExpired as exc:
        # subprocess.TimeoutExpired stores its captured stdout/stderr as raw
        # bytes EVEN when text=True, because decoding happens on the normal
        # return path, not on this exception. Concatenating those bytes with
        # the str above raised "TypeError: can only concatenate str (not
        # 'bytes') to str", which crashed the entire suite on the first test
        # that timed out instead of reporting it as a failure. Decode both,
        # tolerating a lone caller that ran text-less.
        def _dec(chunk: bytes | str | None) -> str:
            if chunk is None:
                return ""
            if isinstance(chunk, bytes):
                return chunk.decode("utf-8", errors="replace")
            return chunk

        ok = False
        output = (
            _dec(exc.stdout)
            + _dec(exc.stderr)
            + f"\nTIMED OUT after {TIMEOUT_SECONDS}s"
        )
    duration = time.monotonic() - start
    return ok, output, duration


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--list",
        action="store_true",
        help="print deterministic release-critical test paths without executing them",
    )
    parser.add_argument(
        "--release-critical",
        action="store_true",
        help="required when G19 invokes this authoritative runner",
    )
    parser.add_argument(
        "--exclude-python-custody-bootstrap",
        action="store_true",
        help="exclude the two exact suites that G19 runs through its dedicated unsandboxed bootstrap path",
    )
    browser_selection = parser.add_mutually_exclusive_group()
    browser_selection.add_argument(
        "--exclude-browser-runtime",
        action="store_true",
        help="exclude the exact browser runtime suite for separate custody execution",
    )
    browser_selection.add_argument(
        "--browser-runtime-only",
        action="store_true",
        help="run only the exact browser runtime suite through browser custody",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    files = discover_test_files()
    if args.exclude_python_custody_bootstrap:
        files = [
            path
            for path in files
            if path.relative_to(ROOT).as_posix() not in PYTHON_CUSTODY_BOOTSTRAP_TESTS
        ]
    if args.exclude_browser_runtime:
        files = [
            path
            for path in files
            if path.relative_to(ROOT).as_posix() not in BROWSER_RUNTIME_TESTS
        ]
    elif args.browser_runtime_only:
        files = [
            path
            for path in files
            if path.relative_to(ROOT).as_posix() in BROWSER_RUNTIME_TESTS
        ]
    if not files:
        print("No release-critical Python test files found", file=sys.stderr)
        return 1
    if args.list:
        for path in files:
            print(path.relative_to(ROOT).as_posix())
        return 0

    failures: list[str] = []
    for path in files:
        name = path.relative_to(ROOT).with_suffix("").as_posix()
        ok, output, duration = run_one(path)
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {name} ({duration:.1f}s)", flush=True)
        if not ok:
            failures.append(name)
            print(output.rstrip(), flush=True)
            print("-" * 70, flush=True)

    print()
    print(f"{len(files) - len(failures)}/{len(files)} release-critical Python test files passed")
    if failures:
        print("Failed: " + ", ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
