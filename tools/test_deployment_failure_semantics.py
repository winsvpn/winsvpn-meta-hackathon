#!/usr/bin/env python3
"""Regression tests for deployment helpers called from shell conditionals."""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CORE = ROOT / "server" / "wins_core_server_setup_ONETOUCH.sh"
DATA = ROOT / "server" / "wins_data_plane_setup_ONETOUCH.sh"


def core_sync_agent(source: str) -> str:
    marker = 'cat > "${sync_tmp}" <<\'EOF\'\n'
    start = source.index(marker) + len(marker)
    end = source.index("\nEOF\n", start)
    return source[start:end]


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


class DeploymentFailureSemanticsTests(unittest.TestCase):
    def test_fresh_core_failure_hold_preserves_deployment_ssh_source(self) -> None:
        body = function_body(
            CORE.read_text(encoding="utf-8"), "install_core_failure_hold_firewall"
        )
        for marker in (
            'deployment_source="${SSH_CONNECTION:-${WINSVPN_DEPLOY_SOURCE:-}}"',
            'deployment_source="${deployment_source%% *}"',
            '${deployment_source}/32 -p tcp --dport 22 -j ACCEPT',
            "deployment_ssh_source_preserved=%s",
        ):
            self.assertIn(marker, body)

    def test_core_exit_reconfiguration_propagates_mutation_failures(self) -> None:
        agent = core_sync_agent(CORE.read_text(encoding="utf-8"))
        exit_xray = function_body(agent, "ensure_exit_xray")
        remove_container = function_body(agent, "remove_exit_container_if_present")
        exit_iface = function_body(agent, "ensure_exit_iface")
        for marker in (
            'xray -test -config "${tmp}" >/dev/null ||',
            'restart_marker="${config}.restart-required"',
            'install -o root -g root -m 0600 /dev/null "${restart_marker}"',
            'systemctl enable --now "${service}" >/dev/null || return 1',
            'systemctl restart "${service}" || return 1',
            'rm -f -- "${restart_marker}" || return 1',
            'systemctl is-active --quiet "${service}" || return 1',
        ):
            self.assertIn(marker, exit_xray)
        for marker in (
            'remove_exit_container_if_present "${container}"',
            'image="$(select_awg_image)" || { warn "Core exit setup failed class=exit_image_unavailable"; return 1; }',
            # H-8: the AWG interface name is passed to the container's `sh -c`
            # as a quoted positional argument ("-- ${iface}") rather than
            # being interpolated directly into the (attacker-shaped, from
            # hub-supplied assignment metadata) double-quoted command string,
            # so a crafted interface name can't break out of the command.
            'tail -f /dev/null\' -- "${iface}" >/dev/null || { warn "Core exit setup failed class=exit_container_start_failed"; return 1; }',
            'ip route replace default dev "${iface}" metric 100 table "${table_id}" 2>/dev/null || { warn "Core exit setup failed class=exit_route_update_failed"; return 1; }',
        ):
            self.assertIn(marker, exit_iface)
        self.assertNotIn(
            'docker rm -f "${container}" >/dev/null 2>&1 || true',
            remove_container,
        )
        self.assertIn(
            'docker rm -f "${container}" >/dev/null 2>&1 || return 1',
            remove_container,
        )
        self.assertLess(
            exit_iface.index('remove_exit_container_if_present "${container}"'),
            exit_iface.index('install -m 600 "${tmp}" "${conf}"'),
        )

    def test_core_stopped_exit_container_is_removed_before_recreate(self) -> None:
        agent = core_sync_agent(CORE.read_text(encoding="utf-8"))
        remove_container = function_body(agent, "remove_exit_container_if_present")
        exit_iface = function_body(agent, "ensure_exit_iface")
        not_running = exit_iface.index(
            "if ! docker ps --format '{{.Names}}' | grep -x \"${container}\""
        )
        remove_stopped = exit_iface.index(
            'remove_exit_container_if_present "${container}"', not_running
        )
        recreate = exit_iface.index('image="$(select_awg_image)"', not_running)
        self.assertLess(remove_stopped, recreate)

        temp_parent = ROOT / ".artifacts" / "test-tmp"
        temp_parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="wins-deployment-stopped-container-", dir=temp_parent
        ) as temp:
            harness = pathlib.Path(temp) / "test.sh"
            harness_text = (
                "set -Eeuo pipefail\n"
                + remove_container
                + "\n"
                + "inspect_result=1\n"
                + "remove_result=0\n"
                + "remove_calls=0\n"
                + "docker() {\n"
                + "  if [[ \"$*\" == 'container inspect wins-core-exit-corex3' ]]; then return \"${inspect_result}\"; fi\n"
                + "  if [[ \"$*\" == 'rm -f wins-core-exit-corex3' ]]; then remove_calls=$((remove_calls + 1)); return \"${remove_result}\"; fi\n"
                + "  return 64\n"
                + "}\n"
                + "remove_exit_container_if_present wins-core-exit-corex3\n"
                + "[[ \"${remove_calls}\" == 0 ]]\n"
                + "inspect_result=0\n"
                + "remove_result=29\n"
                + "if remove_exit_container_if_present wins-core-exit-corex3; then exit 91; fi\n"
                + "remove_result=0\n"
                + "remove_exit_container_if_present wins-core-exit-corex3\n"
                + "[[ \"${remove_calls}\" == 2 ]]\n"
            )
            with harness.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(harness_text)
            result = subprocess.run(
                ["bash", harness.relative_to(ROOT).as_posix()],
                cwd=ROOT,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            self.assertEqual(0, result.returncode, result.stdout)

    def test_core_stale_peer_revocation_fails_closed_and_is_revalidated(
        self,
    ) -> None:
        agent = core_sync_agent(CORE.read_text(encoding="utf-8"))
        collect_peers = function_body(agent, "collect_ingress_peer_sets")
        remove_stale = function_body(agent, "remove_stale_ingress_peers")
        validate_stale = function_body(agent, "validate_no_stale_ingress_peers")
        validate_runtime = function_body(agent, "validate_synced_runtime")
        main = function_body(agent, "main")
        self.assertIn("validate_no_stale_ingress_peers ||", validate_runtime)
        self.assertIn("remove_stale_ingress_peers ||", main)
        self.assertLess(
            main.index("validate_synced_runtime"), main.index("acknowledge_assignments")
        )
        self.assertNotIn('peer "${peer}" remove || true', remove_stale)

        temp_parent = ROOT / ".artifacts" / "test-tmp"
        temp_parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="wins-deployment-stale-peer-", dir=temp_parent
        ) as temp:
            harness = pathlib.Path(temp) / "test.sh"
            harness_text = (
                "set -Eeuo pipefail\n"
                + collect_peers
                + "\n"
                + remove_stale
                + "\n"
                + validate_stale
                + "\n"
                + "TMPDIR=\"$(dirname \"$0\")\"\n"
                + "export TMPDIR\n"
                + "ASSIGNMENTS_JSON='{}'\n"
                + "CORE_INGRESS_IFACE=core0\n"
                + "runtime_peers=$'active-peer\\nstale-peer'\n"
                + "remove_result=37\n"
                + "jq() { printf '%s\\n' active-peer; }\n"
                + "docker() {\n"
                + "  if [[ \"$*\" == 'exec wins-core-ingress awg show core0 peers' ]]; then printf '%s\\n' \"${runtime_peers}\"; return 0; fi\n"
                + "  if [[ \"$*\" == 'exec wins-core-ingress awg set core0 peer stale-peer remove' ]]; then\n"
                + "    if ((remove_result != 0)); then return \"${remove_result}\"; fi\n"
                + "    runtime_peers=active-peer\n"
                + "    return 0\n"
                + "  fi\n"
                + "  return 64\n"
                + "}\n"
                + "if remove_stale_ingress_peers; then exit 91; fi\n"
                + "if validate_no_stale_ingress_peers; then exit 92; fi\n"
                + "remove_result=0\n"
                + "remove_stale_ingress_peers\n"
                + "validate_no_stale_ingress_peers\n"
            )
            with harness.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(harness_text)
            result = subprocess.run(
                ["bash", harness.relative_to(ROOT).as_posix()],
                cwd=ROOT,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            self.assertEqual(0, result.returncode, result.stdout)

    def test_core_refresh_route_rolls_back_and_propagates_sync_failure(self) -> None:
        source = CORE.read_text(encoding="utf-8")
        rewrite = function_body(source, "rewrite_core_sync_env")
        refresh = function_body(source, "refresh_core_sync_route")
        self.assertIn('if write_core_sync_agent; then', refresh)
        self.assertIn('return "${refresh_rc}"', refresh)
        self.assertLess(
            refresh.index('mv -f -- "${rollback_tmp}" "${CORE_ENV_FILE}"'),
            refresh.index('err "Core sync route refresh failed; the previous route was restored."'),
        )

        temp_parent = ROOT / ".artifacts" / "test-tmp"
        temp_parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="wins-core-refresh-rollback-", dir=temp_parent
        ) as temp:
            root = pathlib.Path(temp)
            harness = root / "test.sh"
            env_file = root / "wins_core.env"
            preimage = root / "wins_core.env.expected"
            env_file.write_text(
                "ADMIN_TOKEN=preserve\n"
                "HUB_API_BASE=https://old.example\n"
                "ALLOW_RAW_HUB_ORIGIN=0\n"
                "CORE_ID=preserve-core\n",
                encoding="utf-8",
            )
            preimage.write_bytes(env_file.read_bytes())
            harness.write_text(
                "set -Eeuo pipefail\n"
                + rewrite
                + "\n"
                + refresh
                + "\n"
                + "CORE_ENV_FILE=\"$1\"\n"
                + "expected=\"$2\"\n"
                + "events=\"$3\"\n"
                + "CORE_SYNC_HUB_API_BASE=https://new.example\n"
                + "valid_dns_hostname() { return 0; }\n"
                + "wins_require_reviewed_xray_binary() { printf 'XRAY:%s\\n' \"$1\" >> \"${events}\"; return 0; }\n"
                + "write_core_sync_agent() { return 42; }\n"
                + "log() { printf 'LOG:%s\\n' \"$*\" >> \"${events}\"; }\n"
                + "warn() { printf 'WARN:%s\\n' \"$*\" >> \"${events}\"; }\n"
                + "err() { printf 'ERR:%s\\n' \"$*\" >> \"${events}\"; }\n"
                + "stat() { if [[ \"${1:-}\" == -c ]]; then case \"${2:-}\" in '%u') printf '0\\n' ;; '%u:%g') printf '0:0\\n' ;; *) return 64 ;; esac; else command stat \"$@\"; fi; }\n"
                + "find() { return 0; }\n"
                + "chown() { return 0; }\n"
                + "cp() { while (($# > 2)); do shift; done; command cp \"$1\" \"$2\"; }\n"
                + "systemctl() { printf 'SYSTEMCTL:%s\\n' \"$*\" >> \"${events}\"; return 0; }\n"
                + "if refresh_core_sync_route; then exit 91; else rc=$?; fi\n"
                + "[[ \"${rc}\" == 42 ]]\n"
                + "cmp -s \"${CORE_ENV_FILE}\" \"${expected}\"\n"
                + "[[ \"$(grep -c '^XRAY:/usr/local/bin/xray$' \"${events}\")\" == \"2\" ]]\n"
                + "! grep -Fq 'Core sync route refreshed through' \"${events}\"\n"
                + "grep -Fq 'Core sync route refresh failed; the previous route was restored.' \"${events}\"\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    "bash",
                    harness.relative_to(ROOT).as_posix(),
                    env_file.relative_to(ROOT).as_posix(),
                    preimage.relative_to(ROOT).as_posix(),
                    (root / "events.log").relative_to(ROOT).as_posix(),
                ],
                cwd=ROOT,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            self.assertEqual(0, result.returncode, result.stdout)

    def test_core_agent_install_serializes_required_sync_before_timer(self) -> None:
        source = CORE.read_text(encoding="utf-8")
        start = source.index("write_core_sync_agent() {")
        end = source.index("\nrewrite_core_sync_env()", start)
        writer = source[start:end]
        stop = writer.index("systemctl disable --now wins-core-sync.timer")
        required = writer.index(
            "CORE_SYNC_BUSY_EXIT_CODE=75 /usr/local/bin/wins-core-sync"
        )
        restart = writer.index("systemctl enable --now wins-core-sync.timer", required)
        self.assertLess(stop, required)
        self.assertLess(required, restart)
        self.assertNotIn("systemctl start wins-core-sync.service || true", writer)

    def test_core_assignment_mutations_fail_inside_conditional_context(self) -> None:
        sync_assignment = function_body(
            core_sync_agent(CORE.read_text(encoding="utf-8")), "sync_assignment"
        )
        # The free-tier policy helper is installed by the same installer and
        # called by absolute path; this test is about the mutations' failure
        # propagation, so the helper is a stub that succeeds.
        self.assertEqual(1, sync_assignment.count("/usr/local/sbin/wins-free-bandwidth"))
        sync_assignment = sync_assignment.replace(
            "/usr/local/sbin/wins-free-bandwidth", "free_policy_stub"
        )
        # sync_assignment validates the peer key, the preshared key and the
        # exit endpoint before any mutation (audit core F-1); the harness uses
        # the agent's own validators and well-formed keys, so every case below
        # still reaches the mutation whose failure it exercises.
        agent_text = core_sync_agent(CORE.read_text(encoding="utf-8"))
        validators = "\n".join(
            function_body(agent_text, name) for name in ("valid_awg_key", "valid_awg_endpoint")
        )
        peer_key = "A" * 43 + "="
        psk_key = "B" * 43 + "="
        temp_parent = ROOT / ".artifacts" / "test-tmp"
        temp_parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="wins-deployment-failure-", dir=temp_parent
        ) as temp:
            harness = pathlib.Path(temp) / "test.sh"
            harness_text = (
                "set -Eeuo pipefail\n"
                + validators
                + "\n"
                + sync_assignment
                + "\n"
                + "CORE_INGRESS_IFACE=core0\n"
                + "docker_result=0\n"
                + "ip_add_result=0\n"
                + "ensure_exit_iface() { :; }\n"
                + "free_policy_stub() { return 0; }\n"
                + "docker() { return \"${docker_result}\"; }\n"
                + "ip() {\n"
                + "  if [[ \"$*\" == 'rule del from 10.9.0.2/32' ]]; then return 1; fi\n"
                + "  if [[ \"$*\" == 'rule add from 10.9.0.2/32 table 52002 priority 11002' ]]; then return \"${ip_add_result}\"; fi\n"
                + "  return 64\n"
                + "}\n"
                + "item='{"
                + '\"client_public_key\":\"' + peer_key + '\",\"client_ip\":\"10.9.0.2\",'
                + '\"preshared_key\":\"\",\"table_id\":52002}'
                + "'\n"
                # Calling a Bash function as an ``if`` condition suppresses
                # errexit throughout its body.  These assertions prove that
                # each mutation propagates failure explicitly anyway.
                + "docker_result=23\n"
                + "if sync_assignment \"${item}\"; then exit 91; fi\n"
                + "item='{"
                + '\"client_public_key\":\"' + peer_key + '\",\"client_ip\":\"10.9.0.2\",'
                + '\"preshared_key\":\"' + psk_key + '\",\"table_id\":52002}'
                + "'\n"
                + "if sync_assignment \"${item}\"; then exit 93; fi\n"
                + "item='{"
                + '\"client_public_key\":\"' + peer_key + '\",\"client_ip\":\"10.9.0.2\",'
                + '\"preshared_key\":\"\",\"table_id\":52002}'
                + "'\n"
                + "docker_result=0\n"
                + "ip_add_result=24\n"
                + "if sync_assignment \"${item}\"; then exit 92; fi\n"
                + "ip_add_result=0\n"
                + "sync_assignment \"${item}\"\n"
            )
            with harness.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(harness_text)
            result = subprocess.run(
                ["bash", harness.relative_to(ROOT).as_posix()],
                cwd=ROOT,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            self.assertEqual(0, result.returncode, result.stdout)

    def test_data_management_preconditions_return_immediately(self) -> None:
        body = function_body(
            DATA.read_text(encoding="utf-8"), "verify_hub_node_management"
        )
        for message in (
            "NODE_TOKEN is required for hub management verification",
            "NODE_SLUG is required for hub management verification",
            "Hub peer resync URL is not configured",
        ):
            start = body.index(message)
            self.assertIn("return 1", body[start : start + 120])

    # Every base command preflight_data_plane checks before proceeding. Kept
    # here as the single source of truth so each per-command test below only
    # has to say which one it's testing the absence of.
    _DATA_PLANE_REQUIRED_COMMANDS = (
        "apt-get", "systemctl", "ip", "df", "awk", "sed", "grep", "pgrep",
        "hostname", "stat", "find", "base64", "mktemp", "curl", "python3",
        "ssh-keygen",
    )

    def _assert_data_plane_preflight_requires_command(
        self, missing_command: str
    ) -> None:
        self.assertIn(missing_command, self._DATA_PLANE_REQUIRED_COMMANDS)
        body = function_body(
            DATA.read_text(encoding="utf-8"), "preflight_data_plane"
        )
        bash_exe = shutil.which("bash") or "/bin/bash"
        stub_commands = [
            name
            for name in self._DATA_PLANE_REQUIRED_COMMANDS
            if name != missing_command
        ]

        temp_parent = ROOT / ".artifacts" / "test-tmp"
        temp_parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix=f"wins-data-plane-{missing_command}-dep-", dir=temp_parent
        ) as temp:
            stub_dir = pathlib.Path(temp) / "bin"
            stub_dir.mkdir()
            for name in stub_commands:
                stub = stub_dir / name
                stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                stub.chmod(0o755)

            harness = pathlib.Path(temp) / "test.sh"
            harness.write_text(
                "set -Eeuo pipefail\n"
                "err() { printf 'ERR:%s\\n' \"$*\" >&2; }\n"
                + body
                + "\n"
                + "preflight_data_plane\n",
                encoding="utf-8",
            )
            harness_arg = harness.relative_to(ROOT).as_posix()
            expected_message = f"Required base command is missing: {missing_command}"

            without_command = subprocess.run(
                [bash_exe, harness_arg],
                cwd=ROOT,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env={"PATH": str(stub_dir)},
            )
            self.assertEqual(1, without_command.returncode, without_command.stdout)
            self.assertIn(expected_message, without_command.stdout)

            restored_stub = stub_dir / missing_command
            restored_stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            restored_stub.chmod(0o755)
            with_command = subprocess.run(
                [bash_exe, harness_arg],
                cwd=ROOT,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env={"PATH": str(stub_dir)},
            )
            self.assertNotIn(expected_message, with_command.stdout)

    def test_data_plane_preflight_requires_curl(self) -> None:
        # check_not_hub() and roughly fifty other call sites in this script
        # shell out to curl, several via `|| true`, which previously let a
        # missing curl binary silently degrade a security check (the "don't
        # install a data-plane on top of a live hub" self-detection returned
        # an empty string and just skipped its comparison) instead of failing
        # the deployment outright. curl must be a hard preflight dependency
        # like every other base command this loop already checks.
        body = function_body(
            DATA.read_text(encoding="utf-8"), "preflight_data_plane"
        )
        self.assertIn(
            "for command_name in apt-get systemctl ip df awk sed grep pgrep "
            "hostname stat find base64 mktemp curl python3 ssh-keygen; do",
            body,
        )
        self._assert_data_plane_preflight_requires_command("curl")

    def test_data_plane_preflight_requires_python3(self) -> None:
        # python3 backs several embedded heredoc scripts in this file (UUID
        # generation, nginx capacity validation, tunnel gateway IP parsing,
        # CPU affinity bitmask calculation) with no command -v guard of its
        # own at any call site.
        self._assert_data_plane_preflight_requires_command("python3")

    def test_data_plane_preflight_requires_ssh_keygen(self) -> None:
        # ssh-keygen -A (host-key regeneration in harden_sshd, called twice)
        # has no command -v guard of its own at either call site.
        self._assert_data_plane_preflight_requires_command("ssh-keygen")


if __name__ == "__main__":
    unittest.main(verbosity=2)
