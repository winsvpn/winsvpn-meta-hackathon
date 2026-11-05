#!/usr/bin/env python3
"""Regression tests for the bounded fresh-install reboot/resume boundary."""

from __future__ import annotations

import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
ROLES = {
    "control": ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh",
    "data": ROOT / "server" / "wins_data_plane_setup_ONETOUCH.sh",
    "core": ROOT / "server" / "wins_core_server_setup_ONETOUCH.sh",
}


def function_body(source: str, name: str) -> str:
    marker = f"{name}() {{"
    start = source.find(marker)
    if start < 0:
        raise AssertionError(f"missing function {name}")
    cursor = source.find("\n}", start)
    while cursor >= 0:
        candidate = source[start : cursor + 2]
        if candidate.count("{") == candidate.count("}"):
            return candidate
        cursor = source.find("\n}", cursor + 2)
    raise AssertionError(f"unterminated function {name}")


class DeploymentRebootResumeTests(unittest.TestCase):
    def test_each_role_pauses_immediately_after_packages(self) -> None:
        for role, path in ROLES.items():
            with self.subTest(role=role):
                source = path.read_text(encoding="utf-8")
                main = source[source.rfind("\nmain() {") :]
                package = main.find("\n  apt_install\n")
                boundary = main.find(f"\n  pause_for_required_reboot {role}\n")
                self.assertGreaterEqual(package, 0)
                self.assertGreater(boundary, package)
                self.assertNotIn("install_awg", main[package:boundary])
                self.assertNotIn("write_env", main[package:boundary])

    def test_role_boundary_records_and_verifies_boot_change(self) -> None:
        temp_parent = ROOT / ".artifacts" / "test-tmp"
        temp_parent.mkdir(parents=True, exist_ok=True)
        for role, path in ROLES.items():
            with self.subTest(role=role):
                source = path.read_text(encoding="utf-8")
                body = function_body(source, "pause_for_required_reboot")
                with tempfile.TemporaryDirectory(
                    prefix=f"wins-reboot-{role}-", dir=temp_parent
                ) as temp:
                    root = pathlib.Path(temp)
                    script = root / "test.sh"
                    script_text = (
                        "set -euo pipefail\n"
                        'cd -- "$(dirname -- "$0")"\n'
                        "log() { :; }\n"
                        "err() { :; }\n"
                        # The deployed host is Ubuntu, where the root group is
                        # named ``root``.  macOS names GID 0 ``wheel``.  Keep
                        # this coordinator-side fixture isolated from that OS
                        # naming difference while still exercising marker
                        # creation, permissions, replacement, and cleanup.
                        'install() { local arg target=""; for arg in "$@"; do target="$arg"; done; mkdir -p -- "$target"; chmod 0700 "$target"; }\n'
                        "chown() { :; }\n"
                        + body
                        + "\n"
                        + f"role={role!r}\n"
                        + 'export WINSVPN_REBOOT_REQUIRED_FILE="$PWD/reboot-required"\n'
                        + 'export WINSVPN_BOOT_ID_FILE="$PWD/boot-id"\n'
                        + 'export WINSVPN_DEPLOY_STATE_DIR="$PWD/state"\n'
                        + "printf '%s\\n' '11111111-1111-4111-8111-111111111111' > \"$WINSVPN_BOOT_ID_FILE\"\n"
                        + 'pause_for_required_reboot "$role"\n'
                        + 'touch "$WINSVPN_REBOOT_REQUIRED_FILE"\n'
                        + 'set +e; pause_for_required_reboot "$role"; rc=$?; set -e; test "$rc" -eq 75\n'
                        + 'grep -Fx "boot_id=11111111-1111-4111-8111-111111111111" "$WINSVPN_DEPLOY_STATE_DIR/$role.reboot-required"\n'
                        + 'rm -f "$WINSVPN_REBOOT_REQUIRED_FILE"\n'
                        + 'set +e; pause_for_required_reboot "$role"; rc=$?; set -e; test "$rc" -eq 75\n'
                        + 'grep -Fx "boot_id=11111111-1111-4111-8111-111111111111" "$WINSVPN_DEPLOY_STATE_DIR/$role.reboot-required"\n'
                        + 'set +e; pause_for_required_reboot "$role"; rc=$?; set -e; test "$rc" -eq 75\n'
                        + "printf '%s\\n' '22222222-2222-4222-8222-222222222222' > \"$WINSVPN_BOOT_ID_FILE\"\n"
                        + 'pause_for_required_reboot "$role"\n'
                        + 'test ! -e "$WINSVPN_DEPLOY_STATE_DIR/$role.reboot-required"\n'
                        + 'printf "%s\\n" "role=$role" "boot_id=malformed" > "$WINSVPN_DEPLOY_STATE_DIR/$role.reboot-required"\n'
                        + 'set +e; pause_for_required_reboot "$role"; rc=$?; set -e; test "$rc" -eq 1\n'
                        + 'test -e "$WINSVPN_DEPLOY_STATE_DIR/$role.reboot-required"\n'
                    )
                    # ``Path.write_text(newline=...)`` is unavailable in the
                    # Apple-provided Python 3.9 used by a fresh macOS
                    # coordinator.  ``Path.open`` has supported explicit LF
                    # handling for every Python version accepted here.
                    with script.open("w", encoding="utf-8", newline="\n") as handle:
                        handle.write(script_text)
                    result = subprocess.run(
                        # Keep the executable path relative to ``cwd``.  A native
                        # Windows path (for example ``C:\\Users\\...``) is parsed
                        # by Bash as shell escapes and loses its separators before
                        # Git Bash/WSL can translate it.  Do not make the temporary
                        # directory Bash's cwd: the Windows WSL launcher may retain
                        # that directory briefly and make deterministic cleanup fail.
                        ["bash", script.relative_to(ROOT).as_posix()],
                        cwd=ROOT,
                        check=False,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                    )
                    self.assertEqual(0, result.returncode, result.stdout)

    def test_windows_wrapper_bounds_and_verifies_automatic_reboot(self) -> None:
        source = (ROOT / "tools" / "wins_deployment_preseed.ps1").read_text(
            encoding="utf-8"
        )
        required = (
            "[switch]$NoAutomaticReboot",
            "$deployExitCode -eq 75",
            "systemctl reboot",
            "$candidateBootId -ne $bootBefore",
            "AddMinutes(10)",
            "Automatic reboot is bounded to one",
        )
        for marker in required:
            self.assertIn(marker, source)

    def test_windows_wrapper_resume_is_stage_independent_and_hash_bound(self) -> None:
        source = (ROOT / "tools" / "wins_deployment_preseed.ps1").read_text(
            encoding="utf-8"
        )
        resume_start = source.index('$remoteResumeCommand = @"')
        resume_end = source.index('\n"@', resume_start)
        resume = source[resume_start:resume_end]

        # The first invocation securely removes its secret-bearing /tmp stage.
        # A post-reboot invocation must therefore use the installed root-only
        # inputs and prove that they still match the exact local deployment.
        self.assertNotIn("$remoteStage", resume)
        for marker in (
            "sha256sum -c -",
            "/root/winsvpn-secrets.env",
            "/root/winsvpn-defaults.env",
            "'/root/$roleScriptName' --preflight",
            "'/root/$roleScriptName' --deploy",
        ):
            self.assertIn(marker, resume)

        recovered = source.index(
            "Write-Host 'SSH recovered after the required reboot;"
        )
        second_invocation = source[recovered : recovered + 500]
        self.assertIn(
            "& ssh @sshBase $Target $remoteResumeWrapper", second_invocation
        )
        self.assertNotIn("& ssh @sshBase $Target $remoteWrapper\n", second_invocation)

if __name__ == "__main__":
    unittest.main(verbosity=2)
