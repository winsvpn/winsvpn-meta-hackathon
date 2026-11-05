"""Shared toolchain preflight for the server test battery (V-01, audits
2026-08-28).

Three independent auditors hit the same wall: `python3 server/test_*.py` is
not self-contained on macOS. The system interpreter is 3.9 and cannot PARSE
the PEP 604 unions embedded in the ONETOUCH hub source; Apple's LibreSSL
lacks the Ed25519 commands the descriptor suites use; /bin/bash 3.2 lacks
the associative arrays the core script sources. Each failure surfaced as a
deep syntax/runtime error -- or, worse, a suite that silently ran nothing --
instead of an actionable prerequisite message.

Importing this module from a test file enforces the interpreter floor
immediately, before any embedded source is parsed. Tests that need Bash 4+
or Ed25519-capable OpenSSL call the specific check, which resolves the right
binary (Homebrew paths first) or exits with exactly one actionable line.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

MIN_PYTHON = (3, 10, 0)


def _fail(message: str) -> "None":
    raise SystemExit(
        f"TOOLCHAIN PREREQUISITE NOT MET: {message}\n"
        "The server battery is not self-contained under the macOS system "
        "tools. Re-run with the pinned toolchain (see "
        "docs/blueprints/AI_HANDOFF_20260823.md section on the test "
        "battery), e.g. Homebrew python3.14 / openssl / bash."
    )


if sys.version_info < MIN_PYTHON:
    _fail(
        f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required (PEP 604 "
        f"unions in the embedded hub source); this interpreter is "
        f"{sys.version.split()[0]}."
    )


def bash4() -> str:
    """A bash >= 4 executable, or exit with one actionable message.

    The ONETOUCH core script sources associative arrays (Bash 4 feature);
    macOS /bin/bash is 3.2 and dies mid-source.
    """
    candidates = [
        os.environ.get("WINS_TEST_BASH", ""),
        "/opt/homebrew/bin/bash",
        "/usr/local/bin/bash",
        "/usr/bin/env bash" and shutil.which("bash") or "",
    ]
    for candidate in candidates:
        if not candidate or not os.path.exists(candidate):
            continue
        try:
            version = subprocess.run(
                [candidate, "-c", "echo ${BASH_VERSINFO[0]}"],
                capture_output=True, text=True, timeout=10,
            ).stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            continue
        if version.isdigit() and int(version) >= 4:
            return candidate
    _fail(
        "Bash 4+ is required (associative arrays in the ONETOUCH core "
        "script); no bash >= 4 was found. Install one (brew install bash) "
        "or point WINS_TEST_BASH at it."
    )
    raise AssertionError("unreachable")


def require_openssl_ed25519() -> str:
    """An OpenSSL 3.x binary with Ed25519 raw-signing, or exit."""
    binary = os.environ.get("WINS_TEST_OPENSSL", "") or shutil.which("openssl") or ""
    if binary:
        try:
            probe = subprocess.run(
                [binary, "list", "-public-key-algorithms"],
                capture_output=True, text=True, timeout=10,
            ).stdout
            if "ED25519" in probe.upper():
                return binary
        except (OSError, subprocess.TimeoutExpired):
            pass
    _fail(
        "An OpenSSL 3.x with Ed25519 support is required (the descriptor "
        "suites sign and verify with `openssl pkeyutl -rawin`); Apple's "
        "LibreSSL does not provide it. Install one (brew install openssl) "
        "or point WINS_TEST_OPENSSL at it."
    )
    raise AssertionError("unreachable")
