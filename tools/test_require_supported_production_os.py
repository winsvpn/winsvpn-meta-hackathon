#!/usr/bin/env python3
"""Behavioral + mutation tests for require_supported_production_os.

The three production installers (control ONETOUCH, data ONETOUCH, core
ONETOUCH) must share one OS gate (the winn3 gateway installer was the fourth
until slice S6 made it a tombstone with no gate, because it does nothing):
exact-string Ubuntu 24.04 is the only accepted production host;
Ubuntu 26.04 is refused by name citing the Python 3.12 pip-compile
C-extension wheel lock; anything else is refused generically.
ALLOW_UNSUPPORTED_OS=1 remains the only override.

Mutations run against in-memory copies of the extracted function. The
shared tree is never written. A green that cannot be made red is not
evidence: the suite includes a deliberate accept-26.04 mutant that MUST
be reported as caught.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import winn3_gateway_block as tombstone_block  # noqa: E402


ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTROL = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"
DATA = ROOT / "server" / "wins_data_plane_setup_ONETOUCH.sh"
CORE = ROOT / "server" / "wins_core_server_setup_ONETOUCH.sh"
LEGACY_HOME_SERVER = ROOT / "tools" / "home_server"
GATEWAY = ROOT / "server" / "wins_winn3_gateway_install.sh"

SCRIPTS = (
    ("control", CONTROL, "preflight_control"),
    ("data", DATA, "preflight_data_plane"),
    ("core", CORE, "preflight_core"),
)

NAMED_26_NEEDLE = (
    "Ubuntu 26.04 is not a supported production host. The control-plane "
    "pip-compile lock was generated with Python 3.12 and pins C-extension "
    "per-CPython wheels"
)
GENERIC_REFUSE_NEEDLE = "Supported production host is Ubuntu 24.04; detected"
ACCEPT_24 = 'os_id}" == "ubuntu" && "${os_version}" == "24.04"'
REFUSE_26 = 'os_id}" == "ubuntu" && "${os_version}" == "26.04"'
OLD_COMBINED = (
    'ALLOW_UNSUPPORTED_OS:-0}" != "1" && ( "${os_id}" != "ubuntu" '
    '|| "${os_version}" != "24.04" )'
)


def function_text(source: str, name: str) -> str:
    marker = f"{name}() {{"
    start = source.index(marker)
    cursor = source.find("\n}", start)
    while cursor >= 0:
        candidate = source[start : cursor + 2]
        if candidate.count("{") == candidate.count("}"):
            return candidate
        cursor = source.find("\n}", cursor + 2)
    raise AssertionError(f"unterminated function {name}")


def run_os_gate(
    function_src: str,
    os_release: str | None,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    rewritten = function_src.replace("/etc/os-release", "${WINS_OS_RELEASE_FILE}")
    script_text = f"""set -euo pipefail
err() {{ printf '%s\\n' "$*" >&2; }}
{rewritten}
require_supported_production_os
"""
    temp_parent = ROOT / ".artifacts" / "test-tmp"
    temp_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="wins-os-gate-", dir=temp_parent
    ) as temp:
        temp_path = pathlib.Path(temp)
        script = temp_path / "os_gate.sh"
        script.write_text(script_text, encoding="utf-8")
        env = os.environ.copy()
        if extra_env:
            env.update(extra_env)
        if os_release is None:
            env["WINS_OS_RELEASE_FILE"] = str(temp_path / "missing-os-release")
        else:
            release_path = temp_path / "os-release"
            release_path.write_text(os_release, encoding="utf-8")
            env["WINS_OS_RELEASE_FILE"] = str(release_path)
        return subprocess.run(
            ["bash", str(script)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
        )


def classify_run(proc: subprocess.CompletedProcess[str]) -> str:
    output = proc.stdout or ""
    if proc.returncode == 0:
        return "ACCEPT"
    if NAMED_26_NEEDLE in output:
        return "REFUSE_26_NAMED"
    if GENERIC_REFUSE_NEEDLE in output:
        return "REFUSE_GENERIC"
    return f"UNEXPECTED rc={proc.returncode!r} out={output!r}"


def expected_matrix(function_src: str) -> list[tuple[str, str | None, dict[str, str], str]]:
    """Return (label, os-release or None, extra env, expected classify)."""
    del function_src
    return [
        (
            "ubuntu-24.04-quoted",
            'ID="ubuntu"\nVERSION_ID="24.04"\n',
            {},
            "ACCEPT",
        ),
        (
            "ubuntu-24.04-unquoted",
            "ID=ubuntu\nVERSION_ID=24.04\n",
            {},
            "ACCEPT",
        ),
        (
            "ubuntu-26.04-quoted",
            'ID="ubuntu"\nVERSION_ID="26.04"\n',
            {},
            "REFUSE_26_NAMED",
        ),
        (
            "ubuntu-26.04-unquoted",
            "ID=ubuntu\nVERSION_ID=26.04\n",
            {},
            "REFUSE_26_NAMED",
        ),
        (
            "ubuntu-26.04-override",
            'ID="ubuntu"\nVERSION_ID="26.04"\n',
            {"ALLOW_UNSUPPORTED_OS": "1"},
            "ACCEPT",
        ),
        (
            "ubuntu-22.04",
            'ID="ubuntu"\nVERSION_ID="22.04"\n',
            {},
            "REFUSE_GENERIC",
        ),
        (
            "ubuntu-25.04",
            'ID="ubuntu"\nVERSION_ID="25.04"\n',
            {},
            "REFUSE_GENERIC",
        ),
        (
            "ubuntu-24.04.1-not-prefix",
            'ID="ubuntu"\nVERSION_ID="24.04.1"\n',
            {},
            "REFUSE_GENERIC",
        ),
        (
            "debian-12",
            'ID="debian"\nVERSION_ID="12"\n',
            {},
            "REFUSE_GENERIC",
        ),
        (
            "missing-os-release",
            None,
            {},
            "REFUSE_GENERIC",
        ),
    ]


def matrix_failures(function_src: str) -> list[str]:
    failures: list[str] = []
    for label, release, extra, expected in expected_matrix(function_src):
        proc = run_os_gate(function_src, release, extra)
        got = classify_run(proc)
        if got != expected:
            failures.append(
                f"{label}: expected {expected}, got {got} "
                f"(rc={proc.returncode}, out={proc.stdout!r})"
            )
    return failures


class RequireSupportedProductionOsTests(unittest.TestCase):
    def test_retired_home_server_prototype_tree_stays_absent(self) -> None:
        self.assertFalse(
            LEGACY_HOME_SERVER.exists(),
            "tools/home_server is a retired duplicate/prototype tree; use the "
            "authoritative server/, router/, and tools/recovery helpers",
        )

    def test_all_four_function_bodies_are_identical(self) -> None:
        bodies = []
        for label, path, _caller in SCRIPTS:
            source = path.read_text(encoding="utf-8")
            bodies.append((label, function_text(source, "require_supported_production_os")))
        reference = bodies[0][1]
        for label, body in bodies[1:]:
            self.assertEqual(
                body,
                reference,
                f"{label} require_supported_production_os differs from control",
            )

    def test_static_contract_on_every_script(self) -> None:
        for label, path, caller in SCRIPTS:
            source = path.read_text(encoding="utf-8")
            gate = function_text(source, "require_supported_production_os")
            self.assertIn(NAMED_26_NEEDLE, gate, label)
            self.assertIn(GENERIC_REFUSE_NEEDLE, gate, label)
            self.assertIn(ACCEPT_24, gate, label)
            self.assertIn(REFUSE_26, gate, label)
            self.assertIn('ALLOW_UNSUPPORTED_OS:-0}" == "1"', gate, label)
            self.assertNotIn(OLD_COMBINED, gate, label)
            self.assertEqual(
                gate.count("return 0"),
                2,
                f"{label} must return 0 only for ALLOW_UNSUPPORTED_OS and Ubuntu 24.04",
            )
            self.assertNotRegex(
                gate,
                r'os_version" == "26\.04"[\s\S]{0,200}return 0',
                f"{label} silently accepts Ubuntu 26.04",
            )
            self.assertNotIn(
                '|| "${os_version}" == "26.04"',
                gate,
                f"{label} widened the 24.04 accept to include 26.04",
            )
            caller_body = function_text(source, caller)
            self.assertIn(
                "require_supported_production_os",
                caller_body,
                f"{label} {caller} does not invoke the OS gate",
            )

    def test_retired_gateway_installer_has_no_os_gate_and_installs_nothing(self) -> None:
        # Slice S6 (design v17 2.8): the standalone installer is a tombstone.
        # It used to carry an OS gate that --teardown-forwarding skipped; the
        # tombstone has no gate because it does nothing on any host, and the
        # data-plane installer's own gate (the "data" row above) covers the
        # gateway it now installs.
        source = GATEWAY.read_text(encoding="utf-8")
        self.assertNotIn("require_supported_production_os", source)
        self.assertEqual(tombstone_block.tombstone_problems(source), [])

    def test_live_gate_matrix_no_mutation(self) -> None:
        source = CONTROL.read_text(encoding="utf-8")
        gate = function_text(source, "require_supported_production_os")
        failures = matrix_failures(gate)
        self.assertEqual(failures, [], "\n".join(failures))

    def test_comment_only_mutation_still_passes(self) -> None:
        source = CONTROL.read_text(encoding="utf-8")
        gate = function_text(source, "require_supported_production_os")
        mutated = gate.replace(
            "local os_id=\"\" os_version=\"\"",
            "local os_id=\"\" os_version=\"\"\n  # comment-only mutation probe",
            1,
        )
        self.assertNotEqual(mutated, gate)
        failures = matrix_failures(mutated)
        self.assertEqual(failures, [], "\n".join(failures))

    def test_accept_2604_mutation_is_caught(self) -> None:
        source = CONTROL.read_text(encoding="utf-8")
        gate = function_text(source, "require_supported_production_os")
        mutated = gate.replace(
            'os_version}" == "24.04"',
            'os_version}" == "24.04" || "${os_version}" == "26.04"',
            1,
        )
        self.assertNotEqual(mutated, gate)
        failures = matrix_failures(mutated)
        named_26_cases = [
            item for item in failures if item.startswith("ubuntu-26.04-quoted")
            or item.startswith("ubuntu-26.04-unquoted")
        ]
        self.assertTrue(
            named_26_cases,
            "accept-26.04 mutant was not caught; failures=" + repr(failures),
        )

    def test_drop_named_26_message_mutation_is_caught(self) -> None:
        source = CONTROL.read_text(encoding="utf-8")
        gate = function_text(source, "require_supported_production_os")
        mutated = gate.replace(NAMED_26_NEEDLE, "unsupported os", 1)
        self.assertNotEqual(mutated, gate)
        failures = matrix_failures(mutated)
        named_26_cases = [
            item
            for item in failures
            if item.startswith("ubuntu-26.04-quoted")
            or item.startswith("ubuntu-26.04-unquoted")
        ]
        self.assertTrue(
            named_26_cases,
            "generic-26.04 mutant was not caught; failures=" + repr(failures),
        )


if __name__ == "__main__":
    unittest.main()
