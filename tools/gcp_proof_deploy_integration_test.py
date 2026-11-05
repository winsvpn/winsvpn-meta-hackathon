#!/usr/bin/env python3
"""No-cloud hostile tests for GCP proof deploy/helper integration."""

from __future__ import annotations

import base64
import json
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import gcp_proof_deploy_test as deploy_test

DEPLOY = deploy_test.DEPLOY
REMOTE = deploy_test.REMOTE
FakeRunner = deploy_test.FakeRunner
Fixture = deploy_test.Fixture


def ssh_commands(runner: FakeRunner) -> list[list[str]]:
    commands: list[list[str]] = []
    for call in runner.calls:
        if call[2:3] != ["ssh"]:
            continue
        command = next(token.removeprefix("--command=") for token in call if token.startswith("--command="))
        commands.append(shlex.split(command))
    return commands


def option_value(command: list[str], name: str) -> str | None:
    flag = f"--{name}"
    if flag in command:
        index = command.index(flag)
        if index + 1 < len(command):
            return command[index + 1]
    prefix = f"--{name}="
    for item in command:
        if item.startswith(prefix):
            return item[len(prefix):]
    return None


def scan_secret_tokens(*groups: Any) -> None:
    for group in groups:
        if group is None:
            continue
        if isinstance(group, (bytes, bytearray)):
            if DEPLOY.SECRET_RE.search(bytes(group)):
                raise AssertionError("credential-shaped bytes leaked")
            continue
        if isinstance(group, str):
            if group.startswith("--command="):
                remote = shlex.split(group.removeprefix("--command="))
                scan_secret_tokens(remote)
                continue
            if group.startswith("b64:"):
                decoded = base64.b64decode(group[4:].encode("ascii"), validate=True)
                if DEPLOY.SECRET_RE.search(decoded):
                    raise AssertionError("credential-shaped encoded stdin leaked")
                continue
            if DEPLOY.SECRET_RE.search(group.encode("ascii", "replace")):
                raise AssertionError("credential-shaped string leaked")
            continue
        if isinstance(group, dict):
            scan_secret_tokens(DEPLOY.canonical_bytes(group), json.dumps(group, sort_keys=True))
            continue
        if isinstance(group, (list, tuple)):
            for item in group:
                scan_secret_tokens(item)
            continue


class DeployHelperIntegrationTests(unittest.TestCase):
    def make(self) -> tuple[tempfile.TemporaryDirectory[str], Fixture]:
        temporary = tempfile.TemporaryDirectory()
        return temporary, Fixture(Path(temporary.name))

    def execute(self, fixture: Fixture, runner: FakeRunner) -> dict[str, Any]:
        runner.candidate_id = fixture.manifest["candidate_id"]
        runner.fixture = fixture
        with fixture.context_patch():
            return DEPLOY.execute(
                fixture.repo,
                fixture.plan_path,
                fixture.apply_path,
                fixture.manifest_path,
                fixture.output,
                confirm_live_deployment=True,
                runner=runner,
            )

    def test_pin_matches_current_helper_bytes_and_exchange_contract(self) -> None:
        helper = (TOOLS / "gcp_proof_remote_install.py").read_bytes()
        self.assertEqual(DEPLOY.REMOTE_HELPER_SHA256, DEPLOY.sha256_bytes(helper))
        self.assertEqual(DEPLOY.EXCHANGE_ACTIONS, REMOTE.EXCHANGE_ACTIONS)
        self.assertEqual(DEPLOY.EXCHANGE_CONTRACT, REMOTE.EXCHANGE_CONTRACT)
        self.assertEqual(DEPLOY.EXCHANGE_SOURCE_ROLE, "data-winn3")
        self.assertEqual(DEPLOY.EXCHANGE_TARGET_ROLE, "control")
        self.assertEqual(DEPLOY.PROOF_CLIENT_INNER_V4, REMOTE.PROOF_CLIENT_INNER_V4)
        self.assertEqual(
            DEPLOY.OWNER_CLOUD_EVIDENCE_BLOCKED,
            REMOTE.OWNER_CLOUD_EVIDENCE_BLOCKED,
        )
        self.assertEqual(DEPLOY.EXPECTED_STEPS, REMOTE.EXPECTED_STEPS)
        self.assertEqual(len(DEPLOY.EXPECTED_STEPS), 8)
        self.assertNotIn("\n", DEPLOY.REMOTE_EXCHANGE_BOOTSTRAP)
        self.assertNotIn("\n", DEPLOY.REMOTE_EXCHANGE_PUBLIC_BOOTSTRAP)
        self.assertEqual(
            DEPLOY.SSH_PIPE_RESPONSE_CONTRACT,
            DEPLOY.gcloud_custody.SSH_PIPE_RESPONSE_CONTRACT,
        )

    def test_success_path_binds_helper_sha_project_zone_and_two_secret_pipes(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        receipt = self.execute(fixture, runner)
        self.assertEqual(receipt["status"], "blocked")
        self.assertEqual(receipt["failure"], {})
        self.assertEqual(receipt["remote_helper_sha256"], DEPLOY.REMOTE_HELPER_SHA256)
        self.assertEqual(len(runner.pipe_calls), 2)
        self.assertEqual(len(runner.calls), 40)
        scan_secret_tokens(runner.calls, runner.pipe_calls, receipt)
        project = fixture.fleet["project"]
        for call in runner.calls:
            if call[:3] == ["gcloud", "compute", "ssh"]:
                self.assertTrue(any(token.startswith(f"--project={project}") for token in call))
                self.assertTrue(any(token.startswith("--zone=") for token in call))
                self.assertIn("--quiet", call)
        joined_calls = "\n".join(" ".join(call) for call in runner.calls)
        self.assertNotIn("exchange-data-emit", joined_calls)
        self.assertNotIn("exchange-control-import", joined_calls)
        self.assertNotIn("exchange-data-consume", joined_calls)
        first = runner.pipe_calls[0]
        second = runner.pipe_calls[1]
        first_producer = shlex.split(
            next(item.removeprefix("--command=") for item in first["producer"] if item.startswith("--command="))
        )
        first_consumer = shlex.split(
            next(item.removeprefix("--command=") for item in first["consumer"] if item.startswith("--command="))
        )
        second_producer = shlex.split(
            next(item.removeprefix("--command=") for item in second["producer"] if item.startswith("--command="))
        )
        second_consumer = shlex.split(
            next(item.removeprefix("--command=") for item in second["consumer"] if item.startswith("--command="))
        )
        self.assertEqual(option_value(first_producer, "action"), "exchange-data-emit")
        self.assertEqual(option_value(first_consumer, "action"), "exchange-control-import")
        self.assertEqual(first_producer[8], "none")
        self.assertEqual(first_producer[9], "helper")
        self.assertEqual(first_consumer[8], "pipe")
        self.assertEqual(first_consumer[9], "pipe-consumer")
        self.assertEqual(
            second_producer[:6],
            [
                "/usr/bin/sudo", "--non-interactive", "/usr/bin/python3", "-I", "-c",
                DEPLOY.REMOTE_EXCHANGE_PUBLIC_BOOTSTRAP,
            ],
        )
        self.assertEqual(option_value(second_consumer, "action"), "exchange-data-consume")
        self.assertEqual(second_consumer[8], "pipe")
        self.assertEqual(second_consumer[9], "pipe-consumer")
        for remote in (first_producer, first_consumer, second_consumer):
            self.assertEqual(remote[7], DEPLOY.REMOTE_HELPER_SHA256)
        actions = [item[1] for item in runner.exchange_helper_actions]
        self.assertEqual(
            actions,
            [
                "exchange-identity",
                "exchange-identity",
                "exchange-challenge",
                "exchange-challenge",
                "exchange-control-offer",
                "exchange-data-accept",
                "exchange-control-seal",
            ],
        )
        self.assertEqual(
            [item[0] for item in runner.exchange_helper_actions],
            [
                "control",
                "data-winn3",
                "control",
                "data-winn3",
                "control",
                "data-winn3",
                "control",
            ],
        )

    def test_owner_cloud_identity_absence_is_honest_blocked(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        runner.missing_gce_identity = True
        receipt = self.execute(fixture, runner)
        self.assertEqual(receipt["status"], "blocked")
        self.assertEqual(receipt["failure"]["reason"], DEPLOY.OWNER_CLOUD_EVIDENCE_BLOCKED)
        self.assertIn("BLOCKED:", receipt["failure"]["reason"])
        self.assertEqual(receipt["records"], [])
        self.assertEqual(runner.pipe_calls, [])
        scan_secret_tokens(runner.calls, runner.pipe_calls, receipt)

    def test_sealed_rerun_does_not_replace_exchange_events(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        runner.already_complete = True
        runner.already_sealed = True
        receipt = self.execute(fixture, runner)
        self.assertEqual(receipt["status"], "blocked")
        self.assertEqual(receipt["failure"], {})
        self.assertEqual(receipt["records"], [])
        self.assertEqual(runner.pipe_calls, [])
        self.assertEqual(runner.exchange_helper_actions, [])
        commands = ssh_commands(runner)
        exchange_actions = [
            option_value(command, "action")
            for command in commands
            if command[:6] == [
                "/usr/bin/sudo", "--non-interactive", "/usr/bin/python3", "-I", "-c",
                DEPLOY.REMOTE_EXCHANGE_BOOTSTRAP,
            ]
        ]
        self.assertEqual(exchange_actions, ["exchange-status", "exchange-status"])
        scan_secret_tokens(runner.calls, runner.pipe_calls, receipt)

    def test_partial_exchange_refuses_and_keeps_secrets_off_argv(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        runner.partial_exchange = True
        receipt = self.execute(fixture, runner)
        self.assertEqual(receipt["status"], "failed")
        self.assertIn("partial authenticated key exchange v1", receipt["failure"]["reason"])
        self.assertEqual(runner.pipe_calls, [])
        joined = "\n".join(" ".join(call) for call in runner.calls)
        self.assertNotIn("admission.key", joined)
        self.assertNotIn("client.key", joined)
        scan_secret_tokens(runner.calls, runner.pipe_calls, receipt)

    def test_missing_ssh_pipe_cannot_capture_emit_on_runner_stdout(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)

        class NoPipeRunner(FakeRunner):
            run_ssh_pipe = None

        runner = NoPipeRunner()
        receipt = self.execute(fixture, runner)
        self.assertEqual(receipt["status"], "failed")
        self.assertIn("authenticated SSH pipe", receipt["failure"]["reason"])
        joined = "\n".join(" ".join(call) for call in runner.calls)
        self.assertNotIn("exchange-data-emit", joined)
        self.assertEqual(runner.pipe_calls, [])
        scan_secret_tokens(runner.calls, receipt)

    def test_exchange_bootstrap_binds_reviewed_helper_digest(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            helper = Path(name) / "helper.py"
            helper.write_bytes(
                b"import sys\nprint('|'.join(sys.argv[1:]))\n"
            )
            digest = DEPLOY.sha256_bytes(helper.read_bytes())
            valid = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    DEPLOY.REMOTE_EXCHANGE_BOOTSTRAP,
                    str(helper),
                    digest,
                    "none",
                    "helper",
                    "--fixed-argument",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(valid.returncode, 0, valid.stderr.decode("ascii", "replace"))
            self.assertEqual(valid.stdout.decode("ascii").strip(), "--fixed-argument")
            mismatched = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    DEPLOY.REMOTE_EXCHANGE_BOOTSTRAP,
                    str(helper),
                    "0" * 64,
                    "none",
                    "helper",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(mismatched.returncode, 0)
            self.assertNotIn(b"--fixed-argument", mismatched.stdout)

    def test_pipe_consumer_stdout_mode_refuses_secret_helper_fields(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            helper = Path(name) / "helper.py"
            helper.write_bytes(
                b"import json,sys\n"
                b"sys.stdout.write(json.dumps({"
                b'"action":"exchange-control-import",'
                b'"contract":"winsvpn-gcp-proof-authenticated-key-exchange-v1",'
                b'"kind":"winsvpn.gcp_proof.authenticated_key_exchange_response.v1",'
                b'"public":None,'
                b'"receipt":None,'
                b'"schema_version":1,'
                b'"secret":{"client.key":"ab"}'
                b"},sort_keys=True,separators=(',',':')))\n"
            )
            digest = DEPLOY.sha256_bytes(helper.read_bytes())
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    DEPLOY.REMOTE_EXCHANGE_BOOTSTRAP,
                    str(helper),
                    digest,
                    "none",
                    "pipe-consumer",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b"client.key", result.stdout)
            self.assertNotIn(b"ab", result.stdout)


if __name__ == "__main__":
    unittest.main()
