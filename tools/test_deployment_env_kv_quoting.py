#!/usr/bin/env python3
"""Regression contract for the control-plane secrets-file single-quote escaping.

``write_env_kv`` and ``append_runtime_env_kv`` in
``server/wins_control_plane_setup_ONETOUCH.sh`` both write
``KEY='value'`` lines into root-only secrets files that main() later
``source``s. Bash's escaping idiom for embedding a literal ``'`` inside a
single-quoted string is the 5-character sequence ``'"'"'``, but that
replacement text must be produced from an *unquoted* assignment
(``value=${value//...}``). Wrapping the assignment in double quotes
(``value="${value//...}"``) is a silent trap: bash's double-quote backslash
rules leave the escaping backslashes in the *result* instead of consuming
them, which corrupts any secret containing an apostrophe and, once the
backslash makes the quote count uneven, makes the env file fail to
``source`` at all the next time the hub restarts.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SOURCE_PATH = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"
SOURCE = SOURCE_PATH.read_text(encoding="utf-8")

# Values a real deployment could plausibly need to store, deliberately
# including several designed to defeat a naive escaper.
TRICKY_VALUES = [
    "plain-token-no-special-chars",
    "it's a test",
    "'leading quote",
    "trailing quote'",
    "multi'''quote",
    "back\\slash and 'quote",
    "$dollar and `backtick` and \"doublequote\"",
]


def function_definition(source: str, signature: str) -> str:
    """Return `name() { ... }` verbatim so it stays a deferred function
    definition (not an immediately-executed `{ ... }` block) once spliced
    into a standalone harness script; $1/$2 inside it must only bind when
    the function is actually called, never to the harness's own args."""
    start = source.index(signature)
    depth = 0
    brace_idx = source.index("{", start)
    for idx in range(brace_idx, len(source)):
        char = source[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start : idx + 1]
    raise AssertionError(f"unbalanced braces while extracting {signature}")


def run_bash(script: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", script],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        check=False,
    )


class ControlPlaneEnvKvQuotingTests(unittest.TestCase):
    def test_escaping_assignments_are_not_double_quoted(self) -> None:
        # This is the exact regression: re-wrapping either assignment in
        # double quotes reintroduces the backslash-leak bug even though the
        # function still "looks" correct at a glance. The LHS name differs
        # per function (escaped= vs value=), so match either.
        for signature in ("append_runtime_env_kv() {", "write_env_kv() {"):
            with self.subTest(function=signature):
                body = function_definition(SOURCE, signature)
                self.assertRegex(body, r"\b\w+=\$\{value//\\'/")
                self.assertNotRegex(body, r'\b\w+="\$\{value//')

    def test_append_runtime_env_kv_round_trips_through_source(self) -> None:
        body = function_definition(SOURCE, "append_runtime_env_kv() {")
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "primary.env"
            legacy_file = Path(tmp) / "legacy.env"
            for original in TRICKY_VALUES:
                with self.subTest(value=original):
                    env_file.write_text("", encoding="utf-8")
                    legacy_file.write_text("", encoding="utf-8")
                    script = f'''
set -Eeuo pipefail
ENV_FILE={str(env_file)!r}
LEGACY_ENV_FILE={str(legacy_file)!r}
{body}
append_runtime_env_kv TEST_KEY "$1"
# shellcheck disable=SC1090
source "${{ENV_FILE}}"
printf '%s' "${{TEST_KEY}}"
'''
                    combined = subprocess.run(
                        ["bash", "-c", script, "--", original],
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        timeout=30,
                        check=False,
                    )
                    self.assertEqual(
                        combined.returncode, 0, combined.stdout
                    )
                    self.assertEqual(combined.stdout, original)

    def test_write_env_kv_round_trips_through_source(self) -> None:
        body = function_definition(SOURCE, "write_env_kv() {")
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "buffered.env"
            for original in TRICKY_VALUES:
                with self.subTest(value=original):
                    script = f'''
set -Eeuo pipefail
env_kv_buffer=""
{body}
write_env_kv TEST_KEY "$1"
printf '%s' "${{env_kv_buffer}}" > {str(env_file)!r}
# shellcheck disable=SC1090
source {str(env_file)!r}
printf '%s' "${{TEST_KEY}}"
'''
                    result = subprocess.run(
                        ["bash", "-c", script, "--", original],
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        timeout=30,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout)
                    self.assertEqual(result.stdout, original)

    def test_write_env_kv_rejects_newlines_before_escaping(self) -> None:
        body = function_definition(SOURCE, "write_env_kv() {")
        script = f'''
set -Eeuo pipefail
env_kv_buffer=""
{body}
if write_env_kv TEST_KEY $'multi\\nline'; then
  echo DID_NOT_REJECT
  exit 1
fi
echo REJECTED_AS_EXPECTED
'''
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("REJECTED_AS_EXPECTED", result.stdout)


if __name__ == "__main__":
    unittest.main()
