#!/usr/bin/env python3
"""Regression tests for deployment preflight and required-service activation."""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import Optional


ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTROL = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"
DATA = ROOT / "server" / "wins_data_plane_setup_ONETOUCH.sh"
CORE = ROOT / "server" / "wins_core_server_setup_ONETOUCH.sh"
DEPLOYMENT_README = ROOT / "README_FINAL_DEPLOYMENT.md"
CHECKOUT_VERIFIER = ROOT / "tools" / "verify_deployment_checkout.py"
ROLE_SCRIPTS = (CONTROL, DATA, CORE)


def function_body(source: str, name: str) -> str:
    marker = f"{name}() {{"
    start = source.index(marker)
    cursor = source.find("\n}", start)
    while cursor >= 0:
        candidate = source[start : cursor + 2]
        if candidate.count("{") == candidate.count("}"):
            return candidate
        cursor = source.find("\n}", cursor + 2)
    raise AssertionError(f"unterminated function {name}")


def run_harness(script_text: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    temp_parent = ROOT / ".artifacts" / "test-tmp"
    temp_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="wins-service-semantics-", dir=temp_parent) as temp:
        script = pathlib.Path(temp) / "test.sh"
        with script.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(script_text)
        return subprocess.run(
            ["bash", script.relative_to(ROOT).as_posix(), *arguments],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )


class RequiredSshServiceTests(unittest.TestCase):
    def ssh_harness(self, source: str) -> str:
        helper = function_body(source, "enable_required_ssh_service")
        return f"""set -Eeuo pipefail
mode="$1"
systemctl() {{
  printf '%s\n' "$*"
  local command="$1" unit="${{3:-}}"
  if [[ "${{command}}" == "enable" ]]; then
    case "${{mode}}:${{unit}}" in
      first:ssh.service|fallback:sshd.service|inactive_then_fallback:ssh.service|inactive_then_fallback:sshd.service|inactive_all:ssh.service|inactive_all:sshd.service) return 0 ;;
      *) return 1 ;;
    esac
  fi
  if [[ "${{command}}" == "is-active" ]]; then
    case "${{mode}}:${{unit}}" in
      first:ssh.service|fallback:sshd.service|inactive_then_fallback:sshd.service) return 0 ;;
      *) return 1 ;;
    esac
  fi
  return 64
}}
log() {{ :; }}
err() {{ :; }}
{helper}
enable_required_ssh_service
"""

    def test_core_and_hub_use_the_same_fail_closed_helper(self) -> None:
        control_source = CONTROL.read_text(encoding="utf-8")
        core_source = CORE.read_text(encoding="utf-8")
        self.assertEqual(
            function_body(control_source, "enable_required_ssh_service"),
            function_body(core_source, "enable_required_ssh_service"),
        )
        for source in (control_source, core_source):
            apt_install = function_body(source, "apt_install")
            self.assertIn("enable_required_ssh_service", apt_install)
            self.assertNotIn("systemctl enable --now ssh 2>/dev/null || true", apt_install)
            self.assertNotIn("systemctl enable --now sshd 2>/dev/null || true", apt_install)

    def test_ssh_primary_and_fallback_units_must_prove_active(self) -> None:
        source = CORE.read_text(encoding="utf-8")
        cases = {
            "first": (
                0,
                ["enable --now ssh.service", "is-active --quiet ssh.service"],
            ),
            "fallback": (
                0,
                ["enable --now ssh.service", "enable --now sshd.service", "is-active --quiet sshd.service"],
            ),
            "inactive_then_fallback": (
                0,
                [
                    "enable --now ssh.service",
                    "is-active --quiet ssh.service",
                    "enable --now sshd.service",
                    "is-active --quiet sshd.service",
                ],
            ),
            "inactive_all": (
                1,
                [
                    "enable --now ssh.service",
                    "is-active --quiet ssh.service",
                    "enable --now sshd.service",
                    "is-active --quiet sshd.service",
                ],
            ),
        }
        for mode, (expected_returncode, expected_calls) in cases.items():
            with self.subTest(mode=mode):
                result = run_harness(self.ssh_harness(source), mode)
                self.assertEqual(expected_returncode, result.returncode, result.stdout)
                self.assertEqual(expected_calls, result.stdout.splitlines())


class PartialVaultUnlockTests(unittest.TestCase):
    def vault_service_block(self) -> str:
        source = CONTROL.read_text(encoding="utf-8")
        function = function_body(source, "write_partial_vault_unlock_tool")
        start = function.index("required_units=(")
        success = 'echo "Win\'s VPN partial vault is unlocked and hub services were started."'
        end = function.index(success, start) + len(success)
        return function[start:end].replace("\\${", "${")

    def vault_harness(self) -> str:
        block = self.vault_service_block()
        return f"""set -Eeuo pipefail
mode="$1"
systemctl() {{
  printf 'CALL %s\n' "$*"
  if [[ "$1" == "start" ]]; then
    [[ "${{mode}}" != "start_fail" ]]
    return
  fi
  if [[ "$1" == "is-active" ]]; then
    [[ "${{mode}}:$3" != "inactive:nginx.service" ]]
    return
  fi
  return 64
}}
{block}
"""

    def test_success_requires_start_and_every_unit_active(self) -> None:
        required = (
            "wins-hub.service",
            "nginx.service",
            "wins-hub-backup.timer",
            # F-8: retention pruning must come back up with the vault. If it
            # does not run, archives of the full account database and every hub
            # secret accumulate past the published 30-day window.
            "wins-hub-backup-prune.timer",
            "wins-weekly-maintenance.timer",
            "wins-gateway-canary.timer",
        )
        result = run_harness(self.vault_harness(), "success")
        self.assertEqual(0, result.returncode, result.stdout)
        lines = result.stdout.splitlines()
        self.assertEqual(f"CALL start {' '.join(required)}", lines[0])
        # Derived from `required` rather than hardcoded, so adding a unit to
        # the vault-unlock set does not require editing two places.
        self.assertEqual(
            [f"CALL is-active --quiet {unit}" for unit in required],
            lines[1:1 + len(required)],
        )
        self.assertEqual(
            "Win's VPN partial vault is unlocked and hub services were started.",
            lines[1 + len(required)],
        )

    def test_start_or_activity_failure_suppresses_success(self) -> None:
        for mode in ("start_fail", "inactive"):
            with self.subTest(mode=mode):
                result = run_harness(self.vault_harness(), mode)
                self.assertNotEqual(0, result.returncode, result.stdout)
                self.assertNotIn("vault is unlocked and hub services were started", result.stdout)


class ExplicitPreflightTests(unittest.TestCase):
    def test_active_role_scripts_define_preflight_and_label_validate_as_alias(self) -> None:
        for path in ROLE_SCRIPTS:
            with self.subTest(path=path.name):
                source = path.read_text(encoding="utf-8")
                early_guard = function_body(source, "wins_early_plaintext_swap_guard")
                self.assertIn("--preflight|--validate) validate_only=1", early_guard)
                self.assertIn("--preflight", source)
                self.assertIn("compatibility alias for --preflight", source)
                self.assertIn("does not validate an already deployed runtime", source)
                self.assertIn("no deployed runtime validation was performed", source)

    def test_primary_automation_uses_preflight_not_compatibility_alias(self) -> None:
        wrapper = (ROOT / "tools" / "wins_deployment_preseed.ps1").read_text(encoding="utf-8")
        self.assertEqual(2, wrapper.count("'/root/$roleScriptName' --preflight"))
        self.assertNotIn("'/root/$roleScriptName' --validate", wrapper)

        relay = (ROOT / "tools" / "relay_core_installer_transaction.py").read_text(encoding="utf-8")
        self.assertIn("wins_core_server_setup_ONETOUCH.sh --preflight", relay)
        self.assertIn("preflight_passed=", relay)
        self.assertNotIn("validate_passed=", relay)

        runbook = (ROOT / "README_FINAL_DEPLOYMENT.md").read_text(encoding="utf-8")
        self.assertIn("This mode checks only\ninstallation prerequisites", runbook)
        self.assertIn("does not validate an already deployed runtime", runbook)


class DeploymentCheckoutByteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="wins-deployment-checkout-")
        self.base = pathlib.Path(self.temporary.name)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Win's VPN Test")
        self.git("config", "user.email", "checkout-test@invalid.example")
        self.git("config", "core.filemode", "true")
        (self.repo / "tools").mkdir()
        shutil.copy2(CHECKOUT_VERIFIER, self.repo / "tools" / CHECKOUT_VERIFIER.name)
        (self.repo / ".gitignore").write_text(
            "*.ignored\n*.pth\n__pycache__/\nconftest.py\nsitecustomize.py\n"
            "usercustomize.py\nignored-dir/\n",
            encoding="utf-8",
        )
        (self.repo / "tracked.txt").write_text("first\n", encoding="utf-8")
        (self.repo / "ignored-dir").mkdir()
        (self.repo / "ignored-dir" / "tracked-source.txt").write_text(
            "tracked despite ignore rule\n", encoding="utf-8"
        )
        executable = self.repo / "deploy.sh"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        (self.repo / "tracked-link").symlink_to("tracked.txt")
        self.git("add", ".")
        self.git("add", "-f", "ignored-dir/tracked-source.txt")
        self.git("commit", "-qm", "initial")
        self.previous_sha = self.git("rev-parse", "HEAD").stdout.strip()
        (self.repo / "tracked.txt").write_text("approved\n", encoding="utf-8")
        self.git("add", "tracked.txt")
        self.git("commit", "-qm", "approved")
        self.approved_sha = self.git("rev-parse", "HEAD").stdout.strip()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(self.repo), *arguments],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def verify(
        self,
        approved_sha: Optional[str] = None,
        *,
        repo: Optional[pathlib.Path] = None,
        allow_ignored_paths: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        arguments = [
            sys.executable,
            "-I",
            "-B",
            "-S",
            str(CHECKOUT_VERIFIER),
            "--repo",
            str(repo or self.repo),
            "--approved-sha",
            approved_sha or self.approved_sha,
        ]
        if allow_ignored_paths:
            arguments.append("--allow-ignored-paths")
        return subprocess.run(
            arguments,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def assert_refused(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("verification refused", result.stderr)
        self.assertNotIn("deployment_checkout_verified=1", result.stdout)

    def test_clean_exact_checkout_and_pinned_object_invocation_pass(self) -> None:
        result = self.verify()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("deployment_checkout_verified=1", result.stdout)
        self.assertIn(f"approved_sha={self.approved_sha}", result.stdout)

        program = self.git(
            "--no-replace-objects",
            "show",
            f"{self.approved_sha}:tools/{CHECKOUT_VERIFIER.name}",
        ).stdout
        pinned = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                "-S",
                "-",
                "--repo",
                str(self.repo),
                "--approved-sha",
                self.approved_sha,
            ],
            input=program,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(0, pinned.returncode, pinned.stdout + pinned.stderr)
        self.assertIn("deployment_checkout_verified=1", pinned.stdout)

    def test_short_unknown_and_non_head_commit_ids_are_refused(self) -> None:
        for candidate in (
            self.approved_sha[:12],
            "0" * len(self.approved_sha),
            self.previous_sha,
            self.approved_sha.upper(),
        ):
            with self.subTest(candidate=candidate):
                self.assert_refused(self.verify(candidate))

    def test_staged_unstaged_and_untracked_state_are_refused_in_both_modes(self) -> None:
        cases = ("staged", "unstaged", "untracked")
        for case in cases:
            for allow_ignored_paths in (False, True):
                with self.subTest(case=case, allow_ignored_paths=allow_ignored_paths):
                    with tempfile.TemporaryDirectory(prefix="wins-checkout-case-") as isolated:
                        clone = pathlib.Path(isolated) / "repo"
                        subprocess.run(
                            ["git", "clone", "-q", "--no-local", str(self.repo), str(clone)],
                            check=True,
                        )
                        if case == "staged":
                            (clone / "tracked.txt").write_text("staged\n", encoding="utf-8")
                            subprocess.run(["git", "-C", str(clone), "add", "tracked.txt"], check=True)
                        elif case == "unstaged":
                            (clone / "tracked.txt").write_text("unstaged\n", encoding="utf-8")
                        else:
                            (clone / "untracked\nname").write_text("extra\n", encoding="utf-8")
                        self.assert_refused(
                            self.verify(
                                repo=clone,
                                allow_ignored_paths=allow_ignored_paths,
                            )
                        )

    def test_ignored_state_requires_explicit_operator_opt_in_and_is_receipted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-checkout-ignored-") as isolated:
            clone = pathlib.Path(isolated) / "repo"
            subprocess.run(
                ["git", "clone", "-q", "--no-local", str(self.repo), str(clone)],
                check=True,
            )
            (clone / "ordinary.ignored").write_text("operator artifact\n", encoding="utf-8")
            self.assert_refused(self.verify(repo=clone))

            allowed = self.verify(repo=clone, allow_ignored_paths=True)
            self.assertEqual(0, allowed.returncode, allowed.stdout + allowed.stderr)
            self.assertIn("deployment_checkout_verified=1", allowed.stdout)
            self.assertIn("ignored_paths_allowed=1", allowed.stdout)
            self.assertIn("ignored_entry_count=1", allowed.stdout)
            self.assertRegex(allowed.stdout, r"ignored_entries_sha256=[0-9a-f]{64}")

    def test_opt_in_refuses_ignored_vcs_and_interpreter_injection_paths(self) -> None:
        refused_paths = (
            "bootstrap.pth",
            "sitecustomize.py",
            "usercustomize.py",
            "conftest.py",
        )
        for refused_path in refused_paths:
            with self.subTest(refused_path=refused_path):
                with tempfile.TemporaryDirectory(prefix="wins-checkout-case-") as isolated:
                    clone = pathlib.Path(isolated) / "repo"
                    subprocess.run(
                        ["git", "clone", "-q", "--no-local", str(self.repo), str(clone)],
                        check=True,
                    )
                    (clone / refused_path).write_text("injection\n", encoding="utf-8")
                    result = self.verify(repo=clone, allow_ignored_paths=True)
                    self.assert_refused(result)
                    self.assertIn("injection path", result.stderr)

    def test_opt_in_counts_bytecode_without_reading_ignored_entries(self) -> None:
        cache = self.repo / "__pycache__"
        cache.mkdir()
        (cache / "module.cpython-314.pyc").write_bytes(b"not executable bytecode")
        dangling = self.repo / "dangling.ignored"
        dangling.symlink_to("absent-target")
        result = self.verify(allow_ignored_paths=True)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("ignored_entry_count=2", result.stdout)
        self.assertIn("ignored_bytecode_entry_count=1", result.stdout)

    def test_tracked_path_under_ignored_directory_is_not_exempted(self) -> None:
        tracked = self.repo / "ignored-dir" / "tracked-source.txt"
        tracked.write_text("substituted\n", encoding="utf-8")
        for allow_ignored_paths in (False, True):
            with self.subTest(allow_ignored_paths=allow_ignored_paths):
                result = self.verify(allow_ignored_paths=allow_ignored_paths)
                self.assert_refused(result)
                self.assertIn("staged, unstaged, or untracked", result.stderr)
                self.assertNotIn("ignored filesystem state", result.stderr)

    def test_assume_unchanged_and_skip_worktree_cannot_hide_substitution(self) -> None:
        for flag in ("--assume-unchanged", "--skip-worktree"):
            with self.subTest(flag=flag):
                with tempfile.TemporaryDirectory(prefix="wins-checkout-flag-") as isolated:
                    clone = pathlib.Path(isolated) / "repo"
                    subprocess.run(
                        ["git", "clone", "-q", "--no-local", str(self.repo), str(clone)],
                        check=True,
                    )
                    subprocess.run(
                        ["git", "-C", str(clone), "update-index", flag, "tracked.txt"],
                        check=True,
                    )
                    (clone / "tracked.txt").write_text("hidden substitution\n", encoding="utf-8")
                    status = subprocess.run(
                        ["git", "-C", str(clone), "status", "--porcelain=v1"],
                        check=True,
                        text=True,
                        stdout=subprocess.PIPE,
                    )
                    self.assertEqual("", status.stdout)
                    result = subprocess.run(
                        [
                            sys.executable,
                            "-I",
                            "-B",
                            "-S",
                            str(CHECKOUT_VERIFIER),
                            "--repo",
                            str(clone),
                            "--approved-sha",
                            self.approved_sha,
                        ],
                        check=False,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    self.assert_refused(result)
                    self.assertIn("index contains", result.stderr)

    def test_symlink_target_and_executable_mode_changes_are_refused(self) -> None:
        (self.repo / "tracked-link").unlink()
        (self.repo / "tracked-link").symlink_to("deploy.sh")
        self.assert_refused(self.verify())

        self.git("reset", "--hard", "-q", self.approved_sha)
        (self.repo / "deploy.sh").chmod(0o644)
        self.assert_refused(self.verify())

    def test_non_owner_permission_bits_do_not_misrepresent_git_mode(self) -> None:
        tracked = self.repo / "tracked.txt"
        tracked.chmod(0o605)
        result = self.verify()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_replace_refs_are_ignored_and_submodules_are_refused(self) -> None:
        self.git("replace", self.approved_sha, self.previous_sha)
        result = self.verify()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

        self.git("replace", "-d", self.approved_sha)
        child = self.base / "child"
        child.mkdir()
        subprocess.run(["git", "-C", str(child), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(child), "config", "user.name", "Test"], check=True)
        subprocess.run(
            ["git", "-C", str(child), "config", "user.email", "child@invalid.example"],
            check=True,
        )
        (child / "child.txt").write_text("child\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(child), "add", "."], check=True)
        subprocess.run(["git", "-C", str(child), "commit", "-qm", "child"], check=True)
        self.git("-c", "protocol.file.allow=always", "submodule", "add", "-q", str(child), "vendor/child")
        self.git("commit", "-qam", "add submodule")
        submodule_sha = self.git("rev-parse", "HEAD").stdout.strip()
        self.assert_refused(self.verify(submodule_sha))


class CoreDiskEncryptionOperatorContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = CORE.read_text(encoding="utf-8")
        match = re.search(
            r'^readonly CORE_DISK_ENCRYPTION_SUBSTITUTE_ACCEPT_REQUIRED="([A-Z_]+)"$',
            self.source,
            re.MULTILINE,
        )
        self.assertIsNotNone(match)
        self.acceptance = match.group(1)

    def harness(self) -> str:
        verifier = function_body(self.source, "verify_disk_encryption_posture")
        return f"""set -Eeuo pipefail
CORE_DISK_ENCRYPTION_MODE="$1"
CORE_DISK_ENCRYPTION_SUBSTITUTE_ACCEPT="${{2:-}}"
fixture_root="$3"
fixture_plain_swap="${{4:-0}}"
readonly CORE_DISK_ENCRYPTION_SUBSTITUTE_ACCEPT_REQUIRED="{self.acceptance}"
ENABLE_WINS_SWAPFILE=0
WINS_CRYPTSWAP_ENABLED=1
WINS_SWAPFILE_SIZE=12G
root_backed_by_luks() {{ [[ "${{fixture_root}}" == "luks" ]]; }}
unencrypted_swap_devices() {{
  if [[ "${{fixture_plain_swap}}" == "1" ]]; then
    printf '%s\n' /dev/plain-swap
  fi
}}
log() {{ printf 'LOG %s\n' "$*"; }}
warn() {{ printf 'WARN %s\n' "$*"; }}
err() {{ printf 'ERR %s\n' "$*"; }}
verify_core_secret_permissions() {{ return 0; }}
refuse_legacy_loop_swap() {{ return 0; }}
refuse_disk_swap_request() {{ return 0; }}
{verifier}
verify_disk_encryption_posture
printf 'effective=%s\n' "${{CORE_DISK_ENCRYPTION_EFFECTIVE}}"
"""

    def test_substitute_requires_exact_explicit_acceptance(self) -> None:
        refused = (
            ("auto", ""),
            ("substitute", ""),
            ("substitute", "wrong"),
            ("substitute", self.acceptance.lower()),
            ("substitute", self.acceptance + "\n"),
        )
        for mode, token in refused:
            with self.subTest(mode=mode, token=repr(token)):
                result = run_harness(self.harness(), mode, token, "plain", "0")
                self.assertNotEqual(0, result.returncode, result.stdout)
                self.assertIn("explicit operator acceptance", result.stdout)
                self.assertNotIn("effective=substitute", result.stdout)

        for mode in ("auto", "substitute"):
            with self.subTest(mode=mode, token="exact"):
                result = run_harness(self.harness(), mode, self.acceptance, "plain", "0")
                self.assertEqual(0, result.returncode, result.stdout)
                self.assertIn("effective=substitute", result.stdout)

    def test_luks_never_needs_or_downgrades_because_of_acceptance(self) -> None:
        for mode, token in (
            ("auto", ""),
            ("luks", ""),
            ("auto", self.acceptance),
            ("luks", self.acceptance),
        ):
            with self.subTest(mode=mode, token=bool(token)):
                result = run_harness(self.harness(), mode, token, "luks", "0")
                self.assertEqual(0, result.returncode, result.stdout)
                self.assertIn("effective=luks", result.stdout)

    def test_acceptance_never_waives_plaintext_swap_refusal(self) -> None:
        result = run_harness(
            self.harness(), "substitute", self.acceptance, "plain", "1"
        )
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertIn("Unencrypted swap detected", result.stdout)

    def test_readme_and_installer_publish_one_matching_contract(self) -> None:
        readme = DEPLOYMENT_README.read_text(encoding="utf-8")
        self.assertIn("CORE_DISK_ENCRYPTION_MODE=auto|luks|substitute", readme)
        self.assertIn(f"CORE_DISK_ENCRYPTION_SUBSTITUTE_ACCEPT={self.acceptance}", readme)
        self.assertIn("offline disk or provider snapshot", readme)
        self.assertNotIn(
            "Its root filesystem and active swap must be LUKS-backed; `--preflight`",
            readme,
        )
        self.assertIn(
            f'readonly CORE_DISK_ENCRYPTION_SUBSTITUTE_ACCEPT_REQUIRED="{self.acceptance}"',
            self.source,
        )

    def test_runbook_executes_the_verifier_from_the_approved_object(self) -> None:
        readme = DEPLOYMENT_README.read_text(encoding="utf-8")
        verifier = CHECKOUT_VERIFIER.read_text(encoding="utf-8")
        for guard in (
            "set -euo pipefail",
            "GIT_NO_REPLACE_OBJECTS=1",
            "git --no-replace-objects",
            f"${{AUDIT_APPROVED_SHA}}:tools/{CHECKOUT_VERIFIER.name}",
            "/usr/bin/python3 -I -B -S -",
            '--approved-sha "$AUDIT_APPROVED_SHA"',
        ):
            self.assertIn(guard, readme)
        self.assertIn('"--ignored=traditional"', verifier)
        self.assertIn("--allow-ignored-paths", verifier)
        self.assertIn('("ls-files", "-v", "-z")', verifier)
        self.assertIn("os.O_NOFOLLOW", verifier)


if __name__ == "__main__":
    unittest.main()
