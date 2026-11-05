#!/usr/bin/env python3
"""Portable regressions for the three HIGH data-plane installer findings.

IA-DP-01  a rerun carried by the management tunnel must never restart the
          connector under itself; unavoidable restarts are refused in main()
          before the hub withdrawal and the serving latch.
IA-DP-02  NODE_TOKEN, XRAY_UUID and the bootstrap grant never appear in any
          child's argv; network-facing units hide other users' processes.
IA-DP-03  AdGuard Home runs unprivileged, only root may reach its admin API on
          127.0.0.1:3000, the firewall guards the port the UI really uses, and
          root never writes through a path the service user controls.

The production functions are extracted verbatim from the installer and run by
bash against stubs; no root, network, systemd or iptables is needed.
WINS_IA_DP_HIGH_DATA points the suite at another copy of the installer (the
snapshot for fail-before proof, or a mutant).
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tempfile
import unittest

# S4: the installer prepends these shared functions to the edge script with
# declare -f; a harness that cuts the heredoc text out supplies the same names.
S4_EDGE_SHARED_STUBS = (
    "wins_late_failure_hold() { return 1; }\n"
    "wins_latch_rules_dominate() { return 0; }\n"
    "winn3gw_render_chains() { return 0; }\n"
)

ROOT = pathlib.Path(__file__).resolve().parents[1]
DATA = pathlib.Path(
    os.environ.get(
        "WINS_IA_DP_HIGH_DATA",
        str(ROOT / "server" / "wins_data_plane_setup_ONETOUCH.sh"),
    )
)
BASH = shutil.which("bash") or "/bin/bash"
REAL_JQ = shutil.which("jq")

TOKEN_OLD = "A" * 96
TOKEN_NEW = "B" * 96
TUNNEL_ID = "22222222-2222-4222-8222-222222222222"
TUNNEL_ID_OLD = "11111111-1111-4111-8111-111111111111"
SSH_HOST = "ssh-node.example.net"
LOOPBACK = "127.0.0.1 40000 127.0.0.1 22"
DIRECT = "203.0.113.9 50000 198.51.100.1 22"
PINNED = "2026.8.2"
# 64 URL-safe characters: inside the hub's issued-token shape (32 to 256).
ISSUED_NODE_TOKEN = "nT_" + "k9-Q" * 15 + "Z"


def source() -> str:
    return DATA.read_text(encoding="utf-8")


def function_body(text: str, name: str) -> str:
    marker = f"\n{name}() {{\n"
    start = text.index(marker) + 1
    cursor = text.index("\n}\n", start)
    while True:
        candidate = text[start : cursor + 2]
        # Heredoc bodies inside these functions are brace-balanced.
        if candidate.count("{") == candidate.count("}"):
            return candidate + "\n"
        cursor = text.index("\n}\n", cursor + 2)


def optional_function(text: str, name: str) -> str:
    try:
        return function_body(text, name)
    except ValueError:
        return ""


def heredoc(text: str, opener: str, terminator: str = "EOF") -> str:
    at = text.index(opener)
    start = text.index("\n", at) + 1
    end = text.index(f"\n{terminator}\n", start)
    return text[start:end] + "\n"


def run_bash(script: str, env: dict[str, str], cwd: pathlib.Path) -> subprocess.CompletedProcess[str]:
    path = cwd / "harness.sh"
    path.write_text(script, encoding="utf-8")
    return subprocess.run(
        [BASH, str(path)],
        env=env,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=60,
        check=False,
    )


def base_env(extra: dict[str, str]) -> dict[str, str]:
    env = {
        "PATH": os.environ["PATH"],
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": "C",
    }
    env.update(extra)
    return env


def write_executable(path: pathlib.Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


# --------------------------------------------------------------------------
# IA-DP-01
# --------------------------------------------------------------------------

TUNNEL_FUNCTIONS = (
    "deployment_session_source_is_loopback",
    "data_resolve_management_tunnel_material",
    "data_management_tunnel_unit_text",
    "data_management_tunnel_carries_session",
    "data_management_tunnel_binary_stale",
    "data_management_tunnel_restart_reasons",
    "data_management_tunnel_rerun_gate",
    "data_tunnel_unit_drop_ssh_requires",
    "configure_node_management_tunnel",
)

TUNNEL_STUBS = r'''
set -Eeuo pipefail
trap 'printf "ERR-TRAP line %s rc %s\n" "$LINENO" "$?"' ERR
log() { [[ ! -e "${STATE}/log_fail" ]] || return 24; printf 'LOG %s\n' "$*"; }
wait_for_package_manager() { [[ ! -e "${STATE}/pm_busy" ]] || { printf 'ERR package manager busy\n'; return 1; }; }
warn() { printf 'WARN %s\n' "$*"; }
err() { printf 'ERR %s\n' "$*"; }
valid_dns_hostname() { [[ -n "$1" ]]; }
install_cloudflared_package() { printf 'install_cloudflared_package\n' >> "${EVENTS}"; }
id() { return 0; }
useradd() { :; }
install() { :; }
chown() { :; }
systemd-analyze() { :; }
dpkg-query() {
  case "$*" in
    *openssh-server*) cat "${STATE}/ssh_status" ;;
    *) cat "${STATE}/version" ;;
  esac
}
apt-mark() {
  printf 'apt-mark %s\n' "$*" >> "${EVENTS}"
  case "$1" in
    showhold)
      [[ ! -e "${STATE}/showhold_fail" ]] || return 26
      cat "${STATE}/holds" ;;
    hold)
      # dpkg takes its lock without waiting (FILE_LOCK_NOWAIT).
      [[ ! -e "${STATE}/dpkg_lock" ]] || { echo "E: Could not get lock /var/lib/dpkg/lock-frontend" >&2; return 100; }
      printf '%s\n' "$2" >> "${STATE}/holds"
      [[ ! -e "${STATE}/hold_commit_then_fail" ]] || return 23 ;;
    unhold)
      [[ ! -e "${STATE}/dpkg_lock" ]] || return 100
      grep -vx "$2" "${STATE}/holds" > "${STATE}/holds.new" || true; mv -f "${STATE}/holds.new" "${STATE}/holds" ;;
  esac
}
systemctl() {
  printf 'systemctl %s\n' "$*" >> "${EVENTS}"
  case "$1" in
    is-active)
      # Same state source as `show -p ActiveState`: a failed query is an
      # error (non-zero), exactly what `is-active` cannot tell from inactive.
      [[ ! -e "${STATE}/activestate_fail" ]] || return 4
      if [[ -e "${STATE}/activestate_value" ]]; then [[ "$(cat "${STATE}/activestate_value")" == active ]]
      else [[ "$(cat "${STATE}/active")" == 1 ]]; fi ;;
    show)
      case "$*" in
        *"-p Requires"*)
          [[ ! -e "${STATE}/show_deps_fail" ]] || return 1
          if [[ -e "${STATE}/loaded_deps" ]]; then cat "${STATE}/loaded_deps"; else printf '\n\n\n\n'; fi ;;
        *"-p ControlGroup"*) cat "${STATE}/control_group" ;;
        *"-p ActiveState"*)
          [[ ! -e "${STATE}/activestate_fail" ]] || return 1
          if [[ -e "${STATE}/activestate_value" ]]; then cat "${STATE}/activestate_value"
          elif [[ "$(cat "${STATE}/active")" == 1 ]]; then echo active
          else echo inactive; fi ;;
        *) [[ ! -e "${STATE}/mainpid_fail" ]] || return 1; cat "${STATE}/mainpid" ;;
      esac ;;
    daemon-reload) [[ ! -e "${STATE}/reload_fail" ]] ;;
    *) return 0 ;;
  esac
}
stat() {
  local last="${!#}"
  case "${last}" in
    *proc_exe) cat "${STATE}/running_id" ;;
    *) cat "${STATE}/installed_id" ;;
  esac
}
readlink() { if [[ -e "${STATE}/exe_link" ]]; then cat "${STATE}/exe_link"; else printf '/usr/bin/cloudflared\n'; fi; }
NODE_MANAGEMENT_TUNNEL_ENABLED_DEFAULT=1
CLOUDFLARED_VERSION=2026.8.2
DATA_MANAGEMENT_TUNNEL_UNIT="wins-node-management-tunnel.service"
DATA_MANAGEMENT_TUNNEL_BINARY="${STATE}/installed_binary"
WINS_SECRETS_FILE=/root/winsvpn-secrets.env
'''


class TunnelHarness:
    def __init__(self, case: unittest.TestCase) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="ia-dp-01-")
        case.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        self.state = self.root / "state"
        self.state.mkdir()
        self.events = self.root / "events.log"
        self.token_file = self.root / "node-management-token"
        self.unit_file = self.root / "wins-node-management-tunnel.service"
        self.node_env = self.root / "node.env"
        self.set_state(active="1", mainpid="4242", running="7:100", installed="7:100", version=PINNED)
        (self.state / "ssh_status").write_text("install ok installed\n", encoding="utf-8")
        (self.state / "installed_binary").write_bytes(b"cloudflared reviewed image\n")
        (self.state / "proc_exe").write_bytes(b"cloudflared reviewed image\n")
        (self.state / "control_group").write_text("/system.slice/wins-node-management-tunnel.service\n", encoding="utf-8")
        (self.state / "proc_cgroup").write_text("0::/system.slice/wins-node-management-tunnel.service\n", encoding="utf-8")
        (self.state / "holds").write_text("", encoding="utf-8")
        text = source()
        functions = []
        for name in TUNNEL_FUNCTIONS:
            body = optional_function(text, name)
            body = body.replace("/etc/cloudflared/node-management-token", str(self.token_file))
            body = body.replace('"/proc/${pid}/exe"', '"${STATE}/proc_exe"')
            body = body.replace('"/proc/${pid}/cgroup"', '"${STATE}/proc_cgroup"')
            body = body.replace(
                "/etc/systemd/system/wins-node-management-tunnel.service", str(self.unit_file)
            )
            functions.append(body)
        self.functions = "\n".join(functions)

    def set_state(self, **values: str) -> None:
        mapping = {
            "active": "active",
            "mainpid": "mainpid",
            "running": "running_id",
            "installed": "installed_id",
            "version": "version",
        }
        for key, value in values.items():
            (self.state / mapping[key]).write_text(value + "\n", encoding="utf-8")

    def events_text(self) -> str:
        return self.events.read_text(encoding="utf-8") if self.events.exists() else ""

    def run(self, call: str, ssh_connection: str | None, extra: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        if self.events.exists():
            self.events.unlink()
        env = base_env(
            {
                "EVENTS": str(self.events),
                "STATE": str(self.state),
                "NODE_ENV_FILE": str(self.node_env),
                "WINS_NODE_MANAGEMENT_TOKEN_FILE": str(self.token_file),
                "NODE_SLUG": "test-node",
                "NODE_SSH_HOST": SSH_HOST,
                "NODE_MANAGEMENT_TUNNEL_ID": TUNNEL_ID,
                "DATA_TUNNEL_UNIT_FILE": str(self.unit_file),
            }
        )
        if ssh_connection is not None:
            env["SSH_CONNECTION"] = ssh_connection
        env.update(extra or {})
        script = TUNNEL_STUBS + self.functions + "\n" + call + "\n"
        return run_bash(script, env, self.root)

    def install_first(self, token: str = TOKEN_OLD) -> None:
        """A detached first install lays down token, unit and node.env."""
        self.node_env.write_text('NODE_SLUG="test-node"\n', encoding="utf-8")
        result = self.run(
            "configure_node_management_tunnel",
            None,
            {
                "NODE_MGMT_TUNNEL_TOKEN": token,
                "NODE_MGMT_SSH_HOST": SSH_HOST,
                "NODE_MGMT_TUNNEL_ID": TUNNEL_ID_OLD,
            },
        )
        assert result.returncode == 0, result.stdout
        assert self.token_file.read_text(encoding="utf-8") == token + "\n"


class ManagementTunnelRerunTests(unittest.TestCase):
    def test_tunnel_rerun_with_nothing_changed_never_restarts(self) -> None:
        h = TunnelHarness(self)
        h.install_first()
        before_unit = h.unit_file.read_text(encoding="utf-8")
        result = h.run("configure_node_management_tunnel", LOOPBACK)
        self.assertEqual(0, result.returncode, result.stdout)
        events = h.events_text()
        self.assertNotIn("systemctl restart", events)
        self.assertNotIn("enable --now", events)
        self.assertIn("systemctl enable wins-node-management-tunnel.service", events)
        self.assertEqual(before_unit, h.unit_file.read_text(encoding="utf-8"))
        self.assertIn("not restarted", result.stdout)

    def test_tunnel_rerun_keeps_node_env_tunnel_id_single_and_current(self) -> None:
        # IA-DP-09 (lane FX-DP-MED) writes NODE_MANAGEMENT_TUNNEL_ID in
        # collect_inputs with write_env_kv's KEY="value" form; this function
        # must update that line in place, never duplicate it.
        h = TunnelHarness(self)
        h.install_first()
        h.node_env.write_text(
            'NODE_SLUG="test-node"\n'
            f'NODE_MANAGEMENT_TUNNEL_ID="{TUNNEL_ID_OLD}"\n'
            f'NODE_SSH_HOST="{SSH_HOST}"\n',
            encoding="utf-8",
        )
        result = h.run("configure_node_management_tunnel", LOOPBACK)
        self.assertEqual(0, result.returncode, result.stdout)
        lines = h.node_env.read_text(encoding="utf-8").splitlines()
        ids = [line for line in lines if line.startswith("NODE_MANAGEMENT_TUNNEL_ID=")]
        self.assertEqual([f"NODE_MANAGEMENT_TUNNEL_ID={TUNNEL_ID}"], ids)
        self.assertEqual(1, sum(line.startswith("NODE_SSH_HOST=") for line in lines))

    def test_tunnel_rerun_with_new_credential_refuses_and_changes_nothing(self) -> None:
        h = TunnelHarness(self)
        h.install_first()
        unit_before = h.unit_file.read_text(encoding="utf-8")
        env_before = h.node_env.read_text(encoding="utf-8")
        result = h.run(
            "configure_node_management_tunnel",
            LOOPBACK,
            {
                "NODE_MGMT_TUNNEL_TOKEN": TOKEN_NEW,
                "NODE_MGMT_SSH_HOST": SSH_HOST,
                "NODE_MGMT_TUNNEL_ID": TUNNEL_ID,
            },
        )
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertNotIn("systemctl restart", h.events_text())
        self.assertEqual(TOKEN_OLD + "\n", h.token_file.read_text(encoding="utf-8"))
        self.assertEqual(unit_before, h.unit_file.read_text(encoding="utf-8"))
        self.assertEqual(env_before, h.node_env.read_text(encoding="utf-8"))
        self.assertNotIn(TOKEN_NEW, result.stdout)

    def test_tunnel_rerun_defers_a_unit_change_without_restart(self) -> None:
        h = TunnelHarness(self)
        h.install_first()
        h.unit_file.write_text("[Unit]\nDescription=older reviewed unit\n", encoding="utf-8")
        result = h.run("configure_node_management_tunnel", LOOPBACK)
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertNotIn("systemctl restart", h.events_text())
        self.assertIn("ProtectProc=invisible", h.unit_file.read_text(encoding="utf-8"))
        self.assertRegex(result.stdout, r"WARN .*NOT restarted.*unit")

    def test_tunnel_rerun_defers_a_replaced_binary_without_restart(self) -> None:
        h = TunnelHarness(self)
        h.install_first()
        h.set_state(installed="7:999")
        result = h.run("configure_node_management_tunnel", LOOPBACK)
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertNotIn("systemctl restart", h.events_text())
        self.assertRegex(result.stdout, r"WARN .*NOT restarted.*binary")

    def test_direct_ip_session_still_restarts(self) -> None:
        h = TunnelHarness(self)
        h.install_first()
        result = h.run("configure_node_management_tunnel", DIRECT)
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("systemctl restart wins-node-management-tunnel.service", h.events_text())

    def test_detached_run_still_restarts(self) -> None:
        h = TunnelHarness(self)
        h.install_first()
        result = h.run("configure_node_management_tunnel", None)
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("systemctl restart wins-node-management-tunnel.service", h.events_text())

    def test_loopback_session_with_connector_down_starts_it(self) -> None:
        h = TunnelHarness(self)
        h.install_first()
        h.set_state(active="0")
        result = h.run("configure_node_management_tunnel", LOOPBACK)
        self.assertEqual(0, result.returncode, result.stdout)
        events = h.events_text()
        self.assertIn("enable --now wins-node-management-tunnel.service", events)
        self.assertIn("systemctl restart wins-node-management-tunnel.service", events)


class ManagementTunnelGateTests(unittest.TestCase):
    def gate(self, h: TunnelHarness, ssh: str | None, extra: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return h.run("data_management_tunnel_rerun_gate\necho GATE-PASSED", ssh, extra)

    def test_new_credential_over_tunnel_is_refused_before_mutation(self) -> None:
        h = TunnelHarness(self)
        h.install_first()
        result = self.gate(h, LOOPBACK, {"NODE_MGMT_TUNNEL_TOKEN": TOKEN_NEW})
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertNotIn("GATE-PASSED", result.stdout)
        self.assertIn("connector credential", result.stdout)
        self.assertNotIn(TOKEN_NEW, result.stdout)
        self.assertNotIn(TOKEN_OLD, result.stdout)

    def test_package_upgrade_over_tunnel_is_refused_before_mutation(self) -> None:
        h = TunnelHarness(self)
        h.install_first()
        h.set_state(version="2025.4.0")
        result = self.gate(h, LOOPBACK)
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertIn("cloudflared package", result.stdout)

    def test_unchanged_tunnel_rerun_passes(self) -> None:
        h = TunnelHarness(self)
        h.install_first()
        result = self.gate(h, LOOPBACK, {"NODE_MGMT_TUNNEL_TOKEN": TOKEN_OLD})
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("GATE-PASSED", result.stdout)

    def test_direct_detached_and_down_connector_pass(self) -> None:
        h = TunnelHarness(self)
        h.install_first()
        h.set_state(version="2025.4.0")
        for ssh in (DIRECT, None):
            result = self.gate(h, ssh, {"NODE_MGMT_TUNNEL_TOKEN": TOKEN_NEW})
            self.assertEqual(0, result.returncode, result.stdout)
        h.set_state(active="0")
        result = self.gate(h, LOOPBACK, {"NODE_MGMT_TUNNEL_TOKEN": TOKEN_NEW})
        self.assertEqual(0, result.returncode, result.stdout)
        result = self.gate(h, LOOPBACK, {"NODE_MANAGEMENT_TUNNEL_ENABLED": "0"})
        self.assertEqual(0, result.returncode, result.stdout)

    def test_main_runs_the_gate_before_any_withdrawal_or_preflight_exit(self) -> None:
        main = function_body(source(), "main")
        gate = re.search(r"^\s*data_management_tunnel_rerun_gate\s*$", main, re.MULTILINE)
        self.assertIsNotNone(gate, "main() must call data_management_tunnel_rerun_gate")
        assert gate is not None
        withdrawal = re.search(r"^\s*begin_data_deployment_withdrawal_before_mutation\s*$", main, re.MULTILINE)
        assert withdrawal is not None
        self.assertLess(gate.start(), withdrawal.start())
        self.assertLess(gate.start(), main.index('if [[ "${WINSVPN_VALIDATE_ONLY:-0}" == "1" ]]'))
        self.assertGreater(gate.start(), main.index("preflight_data_plane"))


class TunnelRefusalMessageTests(unittest.TestCase):
    """OI-DPHIGH-13 (N3a): refusals point new tunnel material at the secrets
    file and give no detached-unit recipe that would tempt --setenv."""

    def test_gate_refusal_names_the_secrets_file_and_no_unit_recipe(self) -> None:
        h = TunnelHarness(self)
        h.install_first()
        result = h.run("data_management_tunnel_rerun_gate", LOOPBACK, {"NODE_MGMT_TUNNEL_TOKEN": TOKEN_NEW})
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertIn("/root/winsvpn-secrets.env", result.stdout)
        self.assertNotIn("systemd-run", result.stdout)
        self.assertNotIn("--setenv=", result.stdout)

    def test_configure_refusal_and_deferral_give_no_unit_recipe(self) -> None:
        h = TunnelHarness(self)
        h.install_first()
        refused = h.run(
            "configure_node_management_tunnel",
            LOOPBACK,
            {"NODE_MGMT_TUNNEL_TOKEN": TOKEN_NEW, "NODE_MGMT_SSH_HOST": SSH_HOST, "NODE_MGMT_TUNNEL_ID": TUNNEL_ID},
        )
        self.assertNotEqual(0, refused.returncode, refused.stdout)
        self.assertIn("/root/winsvpn-secrets.env", refused.stdout)
        self.assertNotIn("systemd-run", refused.stdout)
        h.unit_file.write_text("[Unit]\nDescription=older\n", encoding="utf-8")
        deferred = h.run("configure_node_management_tunnel", LOOPBACK)
        self.assertEqual(0, deferred.returncode, deferred.stdout)
        self.assertIn("NOT restarted", deferred.stdout)
        self.assertNotIn("systemd-run", deferred.stdout)


class TunnelSshDependencyTests(unittest.TestCase):
    """OI-DPHIGH-4 (round 4): no ssh.service restart during apt reaches the
    connector carrying a tunnel rerun. The protection is the dependency itself:
    Wants=, not Requires=, rewritten into an older installed unit before apt.
    There is no openssh-server hold any more, so no hold lifecycle exists."""

    OLD_UNIT = "[Unit]\nAfter=network-online.target ssh.service\nRequires=ssh.service\n[Service]\nExecStart=/bin/true\n"

    def harness(self, unit: str | None = None) -> TunnelHarness:
        h = TunnelHarness(self)
        h.unit_file.write_text(self.OLD_UNIT if unit is None else unit, encoding="utf-8")
        return h

    def test_rendered_unit_has_no_dependency_that_propagates_an_ssh_restart(self) -> None:
        h = TunnelHarness(self)
        result = h.run("data_management_tunnel_unit_text /etc/cloudflared/node-management-token", None)
        self.assertEqual(0, result.returncode, result.stdout)
        lines = result.stdout.splitlines()
        self.assertIn("Wants=ssh.service", lines)
        self.assertIn("After=network-online.target ssh.service", lines)
        for key in ("Requires", "BindsTo", "PartOf", "Requisite", "Upholds"):
            self.assertFalse([l for l in lines if l.startswith(key + "=") and "ssh" in l], key)

    def test_carried_rerun_rewrites_requires_to_wants_before_apt(self) -> None:
        h = self.harness()
        result = h.run("data_tunnel_unit_drop_ssh_requires\necho RUN-CONTINUED", LOOPBACK)
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("RUN-CONTINUED", result.stdout)
        unit = h.unit_file.read_text(encoding="utf-8").splitlines()
        self.assertIn("Wants=ssh.service", unit)
        self.assertNotIn("Requires=ssh.service", unit)
        self.assertIn("After=network-online.target ssh.service", unit)
        events = h.events_text()
        self.assertIn("systemctl daemon-reload", events)
        self.assertNotIn("restart", events, "the rewrite must never restart the connector")
        self.assertNotIn("apt-mark", events, "no package hold exists any more")
        self.assertEqual([], [p.name for p in h.root.iterdir() if p.name.startswith(h.unit_file.name + ".")])

    def test_rewrite_logger_failure_does_not_end_the_run(self) -> None:
        h = self.harness()
        (h.state / "log_fail").write_text("", encoding="utf-8")
        result = h.run("data_tunnel_unit_drop_ssh_requires\necho RUN-CONTINUED", LOOPBACK)
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("RUN-CONTINUED", result.stdout)
        self.assertIn("Wants=ssh.service", h.unit_file.read_text(encoding="utf-8"))

    def test_failed_rewrite_refuses_and_leaves_no_temp_file(self) -> None:
        h = self.harness()
        locked = h.root / "locked-unit-dir"
        locked.mkdir()
        unit = locked / "wins-node-management-tunnel.service"
        unit.write_text(self.OLD_UNIT, encoding="utf-8")
        locked.chmod(0o555)
        self.addCleanup(locked.chmod, 0o755)
        result = h.run(
            "data_tunnel_unit_drop_ssh_requires\necho RUN-CONTINUED",
            LOOPBACK,
            {"DATA_TUNNEL_UNIT_FILE": str(unit)},
        )
        locked.chmod(0o755)
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertNotIn("RUN-CONTINUED", result.stdout)
        self.assertIn("provider console", result.stdout)
        self.assertEqual(self.OLD_UNIT, unit.read_text(encoding="utf-8"))
        self.assertEqual(["wins-node-management-tunnel.service"], [x.name for x in locked.iterdir()])
        self.assertNotIn("daemon-reload", h.events_text())

    def test_rewrite_failing_after_the_temp_file_removes_it(self) -> None:
        h = self.harness()
        result = h.run(
            "chmod() { return 1; }\ndata_tunnel_unit_drop_ssh_requires\necho RUN-CONTINUED",
            LOOPBACK,
        )
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertNotIn("RUN-CONTINUED", result.stdout)
        self.assertEqual(self.OLD_UNIT, h.unit_file.read_text(encoding="utf-8"))
        self.assertEqual([], [x.name for x in h.root.iterdir() if x.name.startswith(h.unit_file.name + ".")])
        self.assertNotIn("daemon-reload", h.events_text())

    def test_failed_daemon_reload_refuses(self) -> None:
        h = self.harness()
        result = h.run(
            "systemctl() { printf 'systemctl %s\\n' \"$*\" >> \"${EVENTS}\"; case \"$1\" in is-active) return 0 ;; daemon-reload) return 1 ;; esac; }\n"
            "data_tunnel_unit_drop_ssh_requires\necho RUN-CONTINUED",
            LOOPBACK,
        )
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertNotIn("RUN-CONTINUED", result.stdout)

    def test_uncarried_runs_and_current_units_change_nothing(self) -> None:
        for ssh in (DIRECT, None):
            h = self.harness()
            result = h.run("data_tunnel_unit_drop_ssh_requires", ssh)
            self.assertEqual(0, result.returncode, result.stdout)
            self.assertEqual(self.OLD_UNIT, h.unit_file.read_text(encoding="utf-8"))
            self.assertNotIn("daemon-reload", h.events_text())
        # A carried run with a current unit leaves the file alone, but still
        # reloads and verifies what systemd has loaded (round 5, N-4/N-6).
        h = self.harness("[Unit]\nWants=ssh.service\n")
        result = h.run("data_tunnel_unit_drop_ssh_requires", LOOPBACK)
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertEqual("[Unit]\nWants=ssh.service\n", h.unit_file.read_text(encoding="utf-8"))
        self.assertEqual(1, h.events_text().count("systemctl daemon-reload"))

    def test_main_rewrites_after_withdrawal_and_before_apt(self) -> None:
        main = function_body(source(), "main")

        def call(name: str) -> int:
            match = re.search(rf"^\s*{name}\s*$", main, re.MULTILINE)
            assert match is not None, name
            return match.start()

        self.assertLess(call("begin_data_deployment_withdrawal_before_mutation"), call("data_tunnel_unit_drop_ssh_requires"))
        self.assertLess(call("data_tunnel_unit_drop_ssh_requires"), call("apt_install"))

    def test_no_openssh_server_hold_remains_anywhere(self) -> None:
        text = source()
        self.assertNotIn("apt-mark hold openssh-server", text)
        self.assertNotIn("held-by-installer", text)
        self.assertNotIn("data_tunnel_ssh_restart_guard", text)
        # apt_install is back to the snapshot's own text: openssh-server is a
        # normal package again and no EXIT trap of this lane lives there.
        apt = function_body(text, "apt_install")
        self.assertIn(" openssh-server ", apt)
        self.assertIn("trap 'restore_unattended_upgrades || true' EXIT", apt)


class TunnelLoadedStateRound5Tests(unittest.TestCase):
    """Round 5 (Seat C N-4, Sol N-6): the decision is made on what systemd has
    loaded, after a reload that runs on every carried attempt."""

    OLD_UNIT = TunnelSshDependencyTests.OLD_UNIT

    def harness(self, unit: str) -> TunnelHarness:
        h = TunnelHarness(self)
        h.unit_file.write_text(unit, encoding="utf-8")
        return h

    def reloads(self, h: TunnelHarness) -> int:
        return h.events_text().count("systemctl daemon-reload")

    def test_loaded_dependency_from_a_drop_in_is_refused(self) -> None:
        for props in ("ssh.service\n\n\n\n", "\nssh.service\n\n\n", "\n\nssh.service\n\n",
                      "\n\n\nssh.service\n", "network-online.target sshd.service\n\n\n\n",
                      "ssh.socket\n\n\n\n"):
            h = self.harness("[Unit]\nWants=ssh.service\n")
            (h.state / "loaded_deps").write_text(props, encoding="utf-8")
            result = h.run("data_tunnel_unit_drop_ssh_requires\necho APT-REACHED", LOOPBACK)
            self.assertNotEqual(0, result.returncode, f"{props!r}: {result.stdout}")
            self.assertNotIn("APT-REACHED", result.stdout, repr(props))
            self.assertIn("drop-in", result.stdout)
            self.assertEqual(1, self.reloads(h), "the decision follows a fresh reload")

    def test_unrelated_loaded_dependencies_continue(self) -> None:
        h = self.harness("[Unit]\nWants=ssh.service\n")
        (h.state / "loaded_deps").write_text("network-online.target sshguard.service\n\n\nsystem.slice\n", encoding="utf-8")
        result = h.run("data_tunnel_unit_drop_ssh_requires\necho APT-REACHED", LOOPBACK)
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("APT-REACHED", result.stdout)

    def test_unreadable_loaded_dependencies_refuse(self) -> None:
        h = self.harness("[Unit]\nWants=ssh.service\n")
        (h.state / "show_deps_fail").write_text("", encoding="utf-8")
        result = h.run("data_tunnel_unit_drop_ssh_requires\necho APT-REACHED", LOOPBACK)
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertNotIn("APT-REACHED", result.stdout)

    def test_retry_after_a_failed_reload_reloads_and_verifies(self) -> None:
        h = self.harness(self.OLD_UNIT)
        (h.state / "reload_fail").write_text("", encoding="utf-8")
        first = h.run("data_tunnel_unit_drop_ssh_requires\necho APT-REACHED", LOOPBACK)
        self.assertNotEqual(0, first.returncode, first.stdout)
        self.assertIn("Wants=ssh.service", h.unit_file.read_text(encoding="utf-8"), "the rename landed before the reload failed")
        (h.state / "reload_fail").unlink()
        second = h.run("data_tunnel_unit_drop_ssh_requires\necho APT-REACHED", LOOPBACK)
        self.assertEqual(0, second.returncode, second.stdout)
        self.assertIn("APT-REACHED", second.stdout)
        self.assertEqual(1, self.reloads(h), "the retry must reload although the file already says Wants=")
        self.assertIn("-p Requires", h.events_text(), "the retry must verify the loaded dependencies")

    def test_retry_whose_reload_fails_again_still_refuses(self) -> None:
        h = self.harness("[Unit]\nWants=ssh.service\n")
        (h.state / "reload_fail").write_text("", encoding="utf-8")
        result = h.run("data_tunnel_unit_drop_ssh_requires\necho APT-REACHED", LOOPBACK)
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertNotIn("APT-REACHED", result.stdout)


class TunnelStaleImageGateRound5Tests(unittest.TestCase):
    """Round 5 (Seat C N-5, Sol N-7): a carried connector running a replaced
    image is refused before the withdrawal; needrestart would restart it."""

    def gate(self, h: TunnelHarness, ssh: str | None) -> subprocess.CompletedProcess[str]:
        return h.run("data_management_tunnel_rerun_gate\necho GATE-PASSED", ssh)

    def test_deleted_executable_is_refused(self) -> None:
        h = TunnelHarness(self)
        h.install_first()
        (h.state / "exe_link").write_text("/usr/bin/cloudflared (deleted)\n", encoding="utf-8")
        result = self.gate(h, LOOPBACK)
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertIn("cloudflared binary", result.stdout)

    def test_replaced_file_is_refused(self) -> None:
        h = TunnelHarness(self)
        h.install_first()
        h.set_state(installed="7:999")
        result = self.gate(h, LOOPBACK)
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertIn("cloudflared binary", result.stdout)

    def test_digest_mismatch_is_refused(self) -> None:
        h = TunnelHarness(self)
        h.install_first()
        (h.state / "installed_binary").write_bytes(b"a different image\n")
        result = self.gate(h, LOOPBACK)
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertIn("cloudflared binary", result.stdout)

    def test_unreadable_running_image_is_refused(self) -> None:
        h = TunnelHarness(self)
        h.install_first()
        (h.state / "proc_exe").unlink()
        result = self.gate(h, LOOPBACK)
        self.assertNotEqual(0, result.returncode, result.stdout)

    def test_unidentifiable_running_image_is_refused(self) -> None:
        """Sol N-8: with a deleted executable on disk, every MainPID or cgroup
        state that hides the running image must refuse, not pass."""
        cases = {
            "mainpid query fails": lambda h: (h.state / "mainpid_fail").write_text("", encoding="utf-8"),
            "mainpid empty": lambda h: (h.state / "mainpid").write_text("\n", encoding="utf-8"),
            "mainpid zero": lambda h: (h.state / "mainpid").write_text("0\n", encoding="utf-8"),
            "mainpid malformed": lambda h: (h.state / "mainpid").write_text("42x\n", encoding="utf-8"),
            "pid in another unit": lambda h: (h.state / "proc_cgroup").write_text("0::/system.slice/other.service\n", encoding="utf-8"),
            "pid cgroup unreadable": lambda h: (h.state / "proc_cgroup").unlink(),
            "unit cgroup empty": lambda h: (h.state / "control_group").write_text("\n", encoding="utf-8"),
        }
        for name, arrange in cases.items():
            h = TunnelHarness(self)
            h.install_first()
            (h.state / "exe_link").write_text("/usr/bin/cloudflared (deleted)\n", encoding="utf-8")
            arrange(h)
            result = self.gate(h, LOOPBACK)
            self.assertNotEqual(0, result.returncode, f"{name}: {result.stdout}")
            self.assertIn("cloudflared binary", result.stdout, name)
        # Without the deleted-executable fixture, the cgroup check alone must
        # refuse a PID that is not the unit's own process.
        for name, arrange in (
            ("fresh image, pid in another unit", lambda h: (h.state / "proc_cgroup").write_text("0::/system.slice/other.service\n", encoding="utf-8")),
            ("fresh image, pid cgroup unreadable", lambda h: (h.state / "proc_cgroup").unlink()),
        ):
            h = TunnelHarness(self)
            h.install_first()
            arrange(h)
            result = self.gate(h, LOOPBACK)
            self.assertNotEqual(0, result.returncode, f"{name}: {result.stdout}")
            self.assertIn("cloudflared binary", result.stdout, name)
        h = TunnelHarness(self)
        h.install_first()
        (h.state / "proc_cgroup").write_text("1:name=systemd:/system.slice/wins-node-management-tunnel.service\n", encoding="utf-8")
        self.assertEqual(0, self.gate(h, LOOPBACK).returncode, "a hybrid-hierarchy cgroup line also identifies the unit")

    def test_fresh_image_and_uncarried_runs_pass(self) -> None:
        h = TunnelHarness(self)
        h.install_first()
        self.assertEqual(0, self.gate(h, LOOPBACK).returncode)
        (h.state / "exe_link").write_text("/usr/bin/cloudflared (deleted)\n", encoding="utf-8")
        for ssh in (DIRECT, None):
            result = self.gate(h, ssh)
            self.assertEqual(0, result.returncode, result.stdout)
            self.assertIn("GATE-PASSED", result.stdout)


FALLBACK_STUBS = r'''
set -Eeuo pipefail
log() { printf 'LOG %s\n' "$*"; }; warn() { printf 'WARN %s\n' "$*"; }; err() { printf 'ERR %s\n' "$*"; }
data_plane_installer_path() { echo /root/installer.sh; }
ev() { printf '%s\n' "$*" >> "${ROOT}/events.log"; }
iptables-restore() { ev "iptables-restore $*"; cat > /dev/null; }
# A stateful iptables: one file per chain, one rule spec per line.
iptables() {
  ev "iptables $*"
  [[ "$1" == -w ]] && shift 2
  local op="$1" chain="$2"; shift 2
  [[ ! -e "${ROOT}/fw/fail${op}" ]] || return 1
  if [[ "${op}" == -n ]]; then [[ -e "${ROOT}/fw/$1" ]]; return; fi
  local f="${ROOT}/fw/${chain}"
  case "${op}" in
    -N) [[ ! -e "${f}" ]] || return 1; : > "${f}" ;;
    -F) [[ -e "${f}" ]] || return 1; : > "${f}" ;;
    -C) [[ -e "${f}" ]] && grep -Fxq -- "$*" "${f}" ;;
    -D) [[ -e "${f}" ]] || return 1
        awk -v r="$*" 'done || $0 != r { print; next } { done = 1 }' "${f}" > "${f}.t"
        if cmp -s "${f}" "${f}.t"; then rm -f "${f}.t"; return 1; fi
        mv -f "${f}.t" "${f}" ;;
    -I) shift
        [[ ! -e "${ROOT}/fw/ignoreI" ]] || return 0
        { printf '%s\n' "$*"; cat "${f}" 2>/dev/null; } > "${f}.t"; mv -f "${f}.t" "${f}" ;;
    -A) [[ ! -e "${ROOT}/fw/ignoreA" ]] || return 0
        printf '%s\n' "$*" >> "${f}" ;;
    -S) [[ "${chain}" != OUTPUT ]] || echo "-P OUTPUT ACCEPT"
        [[ ! -e "${f}" ]] || sed "s/^/-A ${chain} /" "${f}" ;;
  esac
}
ss() { ev "ss $*"; [[ ! -e "${ROOT}/ss_fail" ]] || return 1; cat "${ROOT}/ss.txt"; }
systemctl() {
  ev "systemctl $*"
  case "$1" in
    show) cat "${ROOT}/adguard_pid" ;;
    is-active) [[ -s "${ROOT}/ss.txt" ]] ;;
    stop) [[ ! -e "${ROOT}/stop_fails" ]] && : > "${ROOT}/ss.txt"; return 0 ;;
  esac
}
'''

OWNER_RULE = "-o lo -p tcp --dport {port} -m owner --socket-exists ! --uid-owner 0 -j REJECT --reject-with tcp-reset"


class AbortFallbackAdGuardGuardTests(unittest.TestCase):
    """OI-DPHIGH-14 (rounds 5 and 6): restoring the pre-deployment snapshot must
    not leave the unauthenticated admin API reachable by local users. The jump
    must be first in OUTPUT, every port AdGuard really listens on must be
    guarded, and anything not guaranteed stops AdGuard."""

    def run_fallback(self, output_rules: list[str], ss_lines: list[str], config: str | None = None,
                     faults: tuple[str, ...] = (), owner_chain: bool = False) -> tuple[subprocess.CompletedProcess[str], pathlib.Path]:
        text = source()
        functions = "".join(function_body(text, name) for name in (
            "data_adguard_ui_ports", "data_adguard_listening_admin_ports",
            "deploy_firewall_reassert_adguard_owner_guard", "deploy_firewall_rollback_on_exit")
            if f"\n{name}() {{\n" in text)
        temporary = tempfile.TemporaryDirectory(prefix="ia-dp-14-fallback-")
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        (root / "fw").mkdir()
        (root / "fw" / "OUTPUT").write_text("".join(r + "\n" for r in output_rules), encoding="utf-8")
        if owner_chain:
            (root / "fw" / "WINVPN-OUTPUT").write_text("", encoding="utf-8")
        for fault in faults:
            (root / fault).write_text("", encoding="utf-8")
        (root / "ss.txt").write_text("".join(line + "\n" for line in ss_lines), encoding="utf-8")
        (root / "adguard_pid").write_text("4321\n", encoding="utf-8")
        cfg = root / "AdGuardHome.yaml"
        if config is not None:
            cfg.write_text(config, encoding="utf-8")
        functions = functions.replace("/usr/local/sbin/wins-node-ssh-recovery-guard", str(root / "absent-guard"))
        functions = functions.replace('local config="${1:-/opt/AdGuardHome/AdGuardHome.yaml}"', f'local config="${{1:-{cfg}}}"')
        snapshot = root / "pre.rules"
        snapshot.write_text("*filter\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n", encoding="utf-8")
        script = (FALLBACK_STUBS + functions
                  + f"DEPLOY_FIREWALL_ROLLBACK_ARMED=1\nDEPLOY_FIREWALL_PRE_SNAPSHOT='{snapshot}'\n"
                  "deploy_firewall_rollback_on_exit 1\necho HANDLER-DONE\n")
        result = run_bash(script, base_env({"ROOT": str(root)}), root)
        return result, root

    @staticmethod
    def chain(root: pathlib.Path, name: str) -> list[str]:
        path = root / "fw" / name
        return path.read_text(encoding="utf-8").splitlines() if path.exists() else []

    @staticmethod
    def events(root: pathlib.Path) -> str:
        path = root / "events.log"
        return path.read_text(encoding="utf-8") if path.exists() else ""

    ADGUARD_3000 = 'LISTEN 0 4096 127.0.0.1:3000 0.0.0.0:* users:(("AdGuardHome",pid=4321,fd=9))'
    ADGUARD_53 = 'LISTEN 0 4096 127.0.0.1:53 0.0.0.0:* users:(("AdGuardHome",pid=4321,fd=8))'

    def test_restored_snapshot_gets_the_owner_guard_back_first_in_output(self) -> None:
        result, root = self.run_fallback([], [self.ADGUARD_3000, self.ADGUARD_53])
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("HANDLER-DONE", result.stdout)
        self.assertEqual("-j WINVPN-OUTPUT", self.chain(root, "OUTPUT")[0])
        self.assertEqual([OWNER_RULE.format(port=3000)], self.chain(root, "WINVPN-OUTPUT"))
        events = self.events(root)
        self.assertLess(events.index("iptables-restore"), events.index("-A WINVPN-OUTPUT"))
        self.assertNotIn("systemctl stop AdGuardHome.service", events)

    def test_earlier_accept_cannot_bypass_an_existing_jump(self) -> None:
        """Sol N-9: a restored OUTPUT with a loopback ACCEPT before the jump."""
        result, root = self.run_fallback(["-o lo -j ACCEPT", "-j WINVPN-OUTPUT"], [self.ADGUARD_3000], owner_chain=True)
        self.assertEqual(0, result.returncode, result.stdout)
        output = self.chain(root, "OUTPUT")
        self.assertEqual("-j WINVPN-OUTPUT", output[0])
        self.assertEqual(1, output.count("-j WINVPN-OUTPUT"))
        self.assertIn("-o lo -j ACCEPT", output)

    def test_unverifiable_jump_position_stops_adguard(self) -> None:
        result, root = self.run_fallback(["-o lo -j ACCEPT"], [self.ADGUARD_3000], faults=("fw/ignoreI",))
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("systemctl stop AdGuardHome.service", self.events(root))
        self.assertIn("AdGuard Home was stopped instead", result.stdout)

    def test_every_port_adguard_really_listens_on_is_guarded(self) -> None:
        """Sol N-10: the config already says 3000, the old listener is on 3100."""
        old = 'LISTEN 0 4096 127.0.0.1:3100 0.0.0.0:* users:(("AdGuardHome",pid=4321,fd=9))'
        stray = 'LISTEN 0 4096 [::1]:3200 [::]:* users:(("AdGuardHome",pid=999,fd=3))'
        by_pid = 'LISTEN 0 4096 127.0.0.1:3300 0.0.0.0:* users:(("adguard-worker",pid=4321,fd=11))'
        other = 'LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:* users:(("nginx",pid=77,fd=6))'
        result, root = self.run_fallback([], [old, self.ADGUARD_53, stray, by_pid, other], config="http:\n  address: 127.0.0.1:3000\n")
        self.assertEqual(0, result.returncode, result.stdout)
        rules = self.chain(root, "WINVPN-OUTPUT")
        self.assertNotIn(OWNER_RULE.format(port=8080), rules, "other services' ports are not AdGuard's")
        for port in (3000, 3100, 3200, 3300):
            self.assertIn(OWNER_RULE.format(port=port), rules, port)
        self.assertNotIn(OWNER_RULE.format(port=53), rules, "local DNS stays reachable")

    def test_unreadable_listeners_stop_adguard(self) -> None:
        result, root = self.run_fallback([], [self.ADGUARD_3000], faults=("ss_fail",))
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("systemctl stop AdGuardHome.service", self.events(root))

    def test_failed_rule_stops_adguard(self) -> None:
        result, root = self.run_fallback([], [self.ADGUARD_3000], faults=("fw/fail-A",))
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("systemctl stop AdGuardHome.service", self.events(root))
        self.assertIn("AdGuard Home was stopped instead", result.stdout)

    def test_rule_that_does_not_land_stops_adguard(self) -> None:
        result, root = self.run_fallback([], [self.ADGUARD_3000], faults=("fw/ignoreA",))
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("systemctl stop AdGuardHome.service", self.events(root))

    def test_a_stop_that_leaves_listeners_is_reported_unconfirmed(self) -> None:
        result, root = self.run_fallback([], [self.ADGUARD_3000], faults=("fw/fail-A", "stop_fails"))
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("not confirmed stopped", result.stdout)

    def test_installer_and_edge_derive_the_same_ports(self) -> None:
        text = source()
        edge = heredoc(text, "cat > /usr/local/bin/wins-edge-hardening <<'WINS_EDGE_EOF'", "WINS_EDGE_EOF")
        edge_fn = function_body(edge, "adguard_ui_port_from_config")
        installer_fn = function_body(text, "data_adguard_ui_ports")
        start = edge.index("ADGUARD_UI_PORT=\"$(adguard_ui_port_from_config)\"\n")
        end = edge.index('[[ "${ADGUARD_UI_PORT}" == "3000" ]] || ADGUARD_UI_PORTS="${ADGUARD_UI_PORT} 3000"\n', start)
        end = edge.index("\n", end) + 1
        edge_list = edge[start:end]
        fixtures = {
            "rendered": "http:\n  address: 127.0.0.1:3000\n",
            "moved": "http:\n  pprof:\n    port: 6060\n  address: '127.0.0.1:3100'\n",
            "v6": 'http:\n  address: "[::1]:3101"\n',
            "dns-only": "dns:\n  address: 127.0.0.1:4000\n",
            "bad": "http:\n  address: 127.0.0.1:70000\n",
            "missing": None,
        }
        with tempfile.TemporaryDirectory(prefix="ia-dp-14-parity-") as tmp:
            root = pathlib.Path(tmp)
            for name, content in fixtures.items():
                fake_root = root / name
                config = fake_root / "opt" / "AdGuardHome" / "AdGuardHome.yaml"
                config.parent.mkdir(parents=True)
                if content is not None:
                    config.write_text(content, encoding="utf-8")
                script = (
                    "set -Eeuo pipefail\n" + edge_fn + installer_fn
                    + edge_list
                    + f"printf 'EDGE=%s\\n' \"${{ADGUARD_UI_PORTS}}\"\nprintf 'INSTALLER=%s\\n' \"$(data_adguard_ui_ports '{config}')\"\n"
                )
                result = run_bash(script, base_env({"WINSVPN_TEST_ROOT": str(fake_root)}), root)
                self.assertEqual(0, result.returncode, result.stdout)
                values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
                self.assertEqual(values["EDGE"], values["INSTALLER"], name)


class TunnelSessionStateRound7Tests(unittest.TestCase):
    """Round 7 (Sol N-11, Fable ruling 2026-10-01, BLOCKING): only a reported
    `inactive` or `failed` ActiveState means "not carried"; a failed, empty
    or unrecognised query counts as carried, so both pre-apt safeguards and the
    configure-time deferral still apply. Plus Sol N-12 (follow-up): only the
    unified or name=systemd cgroup line identifies the unit."""

    def carried(self, h: TunnelHarness, ssh: str | None) -> str:
        result = h.run("if data_management_tunnel_carries_session; then echo CARRIED; else echo NOT-CARRIED; fi", ssh)
        self.assertEqual(0, result.returncode, result.stdout)
        return "CARRIED" if "\nCARRIED" in "\n" + result.stdout else "NOT-CARRIED"

    def test_only_a_reported_inactive_or_failed_state_is_not_carried(self) -> None:
        for value, expected in (("inactive", "NOT-CARRIED"), ("failed", "NOT-CARRIED"), ("active", "CARRIED"),
                                ("", "CARRIED"), ("activating", "CARRIED"), ("deactivating", "CARRIED"),
                                ("reloading", "CARRIED"), ("maintenance", "CARRIED"), ("bogus", "CARRIED")):
            h = TunnelHarness(self)
            (h.state / "activestate_value").write_text(value + "\n", encoding="utf-8")
            self.assertEqual(expected, self.carried(h, LOOPBACK), repr(value))
        h = TunnelHarness(self)
        (h.state / "activestate_fail").write_text("", encoding="utf-8")
        self.assertEqual("CARRIED", self.carried(h, LOOPBACK), "a failed query is carried")
        for ssh in (DIRECT, None):
            self.assertEqual("NOT-CARRIED", self.carried(h, ssh), "a non-loopback session is unchanged")

    def test_failed_state_query_still_reaches_the_stale_image_gate(self) -> None:
        h = TunnelHarness(self)
        h.install_first()
        (h.state / "activestate_fail").write_text("", encoding="utf-8")
        (h.state / "exe_link").write_text("/usr/bin/cloudflared (deleted)\n", encoding="utf-8")
        result = h.run("data_management_tunnel_rerun_gate\necho GATE-PASSED", LOOPBACK)
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertNotIn("GATE-PASSED", result.stdout)
        self.assertIn("cloudflared binary", result.stdout)

    def test_failed_state_query_still_reaches_the_dependency_helper(self) -> None:
        h = TunnelHarness(self)
        h.unit_file.write_text(TunnelSshDependencyTests.OLD_UNIT, encoding="utf-8")
        (h.state / "activestate_fail").write_text("", encoding="utf-8")
        (h.state / "loaded_deps").write_text("ssh.service\n\n\n\n", encoding="utf-8")
        result = h.run("data_tunnel_unit_drop_ssh_requires\necho APT-REACHED", LOOPBACK)
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertNotIn("APT-REACHED", result.stdout)
        self.assertIn("systemctl daemon-reload", h.events_text())
        self.assertIn("Wants=ssh.service", h.unit_file.read_text(encoding="utf-8"))

    def test_failed_state_query_defers_the_connector_restart(self) -> None:
        h = TunnelHarness(self)
        h.install_first()
        (h.state / "activestate_fail").write_text("", encoding="utf-8")
        result = h.run("configure_node_management_tunnel", LOOPBACK)
        self.assertEqual(0, result.returncode, result.stdout)
        events = h.events_text()
        self.assertNotIn("systemctl restart", events)
        self.assertNotIn("enable --now", events)

    def test_reported_inactive_connector_on_loopback_is_still_started(self) -> None:
        h = TunnelHarness(self)
        h.install_first()
        (h.state / "activestate_value").write_text("inactive\n", encoding="utf-8")
        result = h.run("configure_node_management_tunnel", LOOPBACK)
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("systemctl restart wins-node-management-tunnel.service", h.events_text())

    def test_unrelated_cgroup_hierarchy_does_not_identify_the_unit(self) -> None:
        """Sol N-12: a matching path under a v1 controller is not membership."""
        for lines, expect_refused in (
            ("2:memory:/system.slice/wins-node-management-tunnel.service\n1:name=systemd:/system.slice/other.service\n", True),
            ("3:cpu,cpuacct:/system.slice/wins-node-management-tunnel.service\n0::/system.slice/other.service\n", True),
            ("2:memory:/system.slice/other.service\n1:name=systemd:/system.slice/wins-node-management-tunnel.service\n", False),
            ("0::/system.slice/wins-node-management-tunnel.service\n", False),
        ):
            h = TunnelHarness(self)
            h.install_first()
            (h.state / "proc_cgroup").write_text(lines, encoding="utf-8")
            result = h.run("data_management_tunnel_rerun_gate\necho GATE-PASSED", LOOPBACK)
            if expect_refused:
                self.assertNotEqual(0, result.returncode, f"{lines!r}: {result.stdout}")
                self.assertIn("cloudflared binary", result.stdout)
            else:
                self.assertEqual(0, result.returncode, f"{lines!r}: {result.stdout}")
                self.assertIn("GATE-PASSED", result.stdout)


class EdgePreflightTunnelProofTests(unittest.TestCase):
    """OI-DPHIGH-1 (N1): wins_preflight_ssh_path_survives accepts a live
    loopback session on an active connector without any journal line, and keeps
    the journal proof for runs with no deployment session."""

    def run_preflight(self, ssh: str | None, active: bool, journal: bool) -> subprocess.CompletedProcess[str]:
        text = source()
        edge = heredoc(text, "cat > /usr/local/bin/wins-edge-hardening <<'WINS_EDGE_EOF'", "WINS_EDGE_EOF")
        cut = edge.index("\napply_rps\n")
        script = edge[:cut] + "\nwins_preflight_ssh_path_survives\necho PREFLIGHT-PASSED\n"
        temporary = tempfile.TemporaryDirectory(prefix="ia-dp-01-n1-")
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        (root / "node.env").write_text('NODE_MANAGEMENT_TUNNEL_ENABLED="1"\n', encoding="utf-8")
        write_executable(
            bin_dir / "systemctl",
            "#!/bin/bash\n"
            'case "$1" in\n'
            f"  is-active) exit {0 if active else 3} ;;\n"
            "  show) printf '%s\\n' 0123456789abcdef0123456789abcdef ;;\n"
            "esac\nexit 0\n",
        )
        journal_line = "echo 'cloudflared[1]: Registered tunnel connection'\n" if journal else ""
        write_executable(bin_dir / "journalctl", "#!/bin/bash\n" + journal_line + "exit 0\n")
        write_executable(bin_dir / "cloudflared", "#!/bin/bash\nexit 0\n")
        write_executable(bin_dir / "sleep", "#!/bin/bash\nexit 0\n")
        write_executable(bin_dir / "iptables", "#!/bin/bash\nexit 1\n")
        env = base_env(
            {
                "PATH": f"{bin_dir}:{os.environ['PATH']}",
                "NODE_ENV_FILE": str(root / "node.env"),
                "PUBLIC_VPN_INGRESS_ADMISSION_FILE": str(root / "absent-admission.env"),
                "WINN3_GATEWAY_ENV_FILE": str(root / "absent-winn3.env"),
                "WINSVPN_TEST_ROOT": str(root / "rootfs"),
                "WAN_IF": "eth0",
                "IPTABLES_BIN": str(bin_dir / "iptables"),
                "WINS_FIREWALL_LOCK_HELD": "1",
                "PUBLIC_VPN_INGRESS_ADMISSION": "0",
                "INSTALL_DATA_IDS_IPS": "0",
            }
        )
        if ssh is not None:
            env["SSH_CONNECTION"] = ssh
        return run_bash(script, env, root)

    def test_live_tunnel_session_needs_no_journal_line(self) -> None:
        result = self.run_preflight(LOOPBACK, active=True, journal=False)
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("PREFLIGHT-PASSED", result.stdout)

    def test_ipv6_loopback_session_is_accepted_too(self) -> None:
        result = self.run_preflight("::1 40000 ::1 22", active=True, journal=False)
        self.assertEqual(0, result.returncode, result.stdout)

    def test_inactive_connector_still_refuses_a_tunnel_session(self) -> None:
        result = self.run_preflight(LOOPBACK, active=False, journal=True)
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertNotIn("PREFLIGHT-PASSED", result.stdout)

    def test_sessionless_and_direct_runs_keep_the_journal_proof(self) -> None:
        for ssh in (None, DIRECT, "127.0.0.10 40000 127.0.0.1 22"):
            refused = self.run_preflight(ssh, active=True, journal=False)
            self.assertNotEqual(0, refused.returncode, f"{ssh}: {refused.stdout}")
            passed = self.run_preflight(ssh, active=True, journal=True)
            self.assertEqual(0, passed.returncode, f"{ssh}: {passed.stdout}")


# --------------------------------------------------------------------------
# IA-DP-02
# --------------------------------------------------------------------------

def jq_spy(bin_dir: pathlib.Path, argv_log: pathlib.Path) -> None:
    assert REAL_JQ, "jq is required"
    write_executable(
        bin_dir / "jq",
        "#!/bin/bash\n"
        f"printf '%s\\n' \"$*\" >> '{argv_log}'\n"
        f"exec '{REAL_JQ}' \"$@\"\n",
    )


class SecretArgvTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="ia-dp-02-")
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.argv_log = self.root / "argv.log"
        jq_spy(self.bin, self.argv_log)

    def test_bootstrap_grant_never_reaches_argv(self) -> None:
        grant = "grant-" + "Q" * 60
        body_copy = self.root / "body.json"
        write_executable(
            self.bin / "curl",
            "#!/bin/bash\n"
            f"printf '%s\\n' \"$*\" >> '{self.argv_log}'\n"
            "for arg in \"$@\"; do\n"
            "  case \"$arg\" in @*) cp \"${arg#@}\" '" + str(body_copy) + "' ;; esac\n"
            "done\n"
            "printf '%s' '{\"node_token\":\"" + ISSUED_NODE_TOKEN + "\"}'\n",
        )
        body = function_body(source(), "bootstrap_node_token")
        script = (
            "set -Eeuo pipefail\n"
            "log() { :; }; err() { printf 'ERR %s\\n' \"$*\"; }\n"
            "persist_node_token() { printf 'PERSISTED %s\\n' \"${#1}\"; }\n"
            + body
            + "\nbootstrap_node_token\n"
        )
        env = base_env(
            {
                "PATH": f"{self.bin}:{os.environ['PATH']}",
                "NODE_SLUG": "test-node",
                "NODE_BOOTSTRAP_TOKEN": grant,
                "HUB_API_BASE": "https://hub.example.net",
            }
        )
        result = run_bash(script, env, self.root)
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertNotIn(grant, self.argv_log.read_text(encoding="utf-8"))
        request = json.loads(body_copy.read_text(encoding="utf-8"))
        self.assertEqual({"slug": "test-node", "bootstrap_token": grant}, request)

    def test_register_payload_keeps_token_and_uuid_out_of_argv(self) -> None:
        text = source()
        register = heredoc(text, "cat > /usr/local/bin/wins-node-register <<'EOF'")
        start = register.index('\npayload="$(') + 1
        end = register.index('\n)"\n', start) + 4
        block = register[start:end]
        node_token = "node-token-" + "Z" * 48
        xray_uuid = "33333333-3333-4333-8333-333333333333"
        script = (
            "set -Eeuo pipefail\n"
            "NODE_SLUG=test-node; NODE_NAME='Test Node'; NODE_FLAG=XX\n"
            "data_plane_code_revision_value=unprovable\n"
            "NODE_HOST=198.51.100.1; WG_PORT=9110; tunnel_gateway_ipv4=10.8.1.1\n"
            "STEALTH_HOST=stealth.example.net; STEALTH_PUBLIC_PORT=80; pubkey=PUBKEY\n"
            f"NODE_TOKEN='{node_token}'; XRAY_UUID='{xray_uuid}'\n"
            "obfs='{}'; NODE_SSH_HOST=ssh.example.net; XRAY_PATH=/p; XRAY_SECURITY=none\n"
            "XRAY_SNI=''; XRAY_INBOUND_PORT=10085; NODE_MAX_PEERS=200\n"
            "load_cpu_pct=null; load_net_pct=null; load_sessions_pct=null\n"
            + block
            + "printf '%s' \"${payload}\"\n"
        )
        env = base_env({"PATH": f"{self.bin}:{os.environ['PATH']}"})
        result = run_bash(script, env, self.root)
        self.assertEqual(0, result.returncode, result.stdout)
        argv = self.argv_log.read_text(encoding="utf-8")
        self.assertNotIn(node_token, argv)
        self.assertNotIn(xray_uuid, argv)
        payload = json.loads(result.stdout)
        self.assertEqual(node_token, payload["secret_token"])
        self.assertEqual(xray_uuid, payload["xray_uuid"])
        self.assertEqual("test-node", payload["slug"])
        self.assertEqual(200, payload["max_peers"])
        self.assertEqual("198.51.100.1:9110", payload["endpoint"])

    def test_network_facing_units_hide_other_users_processes(self) -> None:
        text = source()
        xray = heredoc(text, "cat > /etc/systemd/system/xray.service.d/20-winsvpn-user.conf <<'EOF'")
        adguard = heredoc(text, "cat > /etc/systemd/system/AdGuardHome.service <<'EOF'")
        tunnel_function = optional_function(text, "data_management_tunnel_unit_text") or optional_function(
            text, "configure_node_management_tunnel"
        )
        for name, unit in (("xray", xray), ("AdGuard", adguard), ("cloudflared", tunnel_function)):
            self.assertRegex(unit, r"(?m)^ProtectProc=invisible$", f"{name} unit lacks ProtectProc=invisible")


# --------------------------------------------------------------------------
# IA-DP-03
# --------------------------------------------------------------------------

ADGUARD_STUBS = r'''
set -Eeuo pipefail
systemctl() { [[ "$1" == show ]] || return 0; [[ "${FAKE_ADGUARD_STATE-inactive}" != QUERY-FAILS ]] || return 1; printf '%s\n' "${FAKE_ADGUARD_STATE-inactive}"; }
log() { printf 'LOG %s\n' "$*"; }
warn() { printf 'WARN %s\n' "$*"; }
err() { printf 'ERR %s\n' "$*"; }
validate_adguard_dns_policy() { return 0; }
ADGUARD_DNS_BIND_DEFAULT=10.8.1.1
ADGUARD_PRIMARY_DOH_DEFAULT=https://dns.quad9.net/dns-query
ADGUARD_OPENDNS_FALLBACK_DOH_DEFAULT=https://dns.opendns.com/dns-query
DNS4EU_COMMERCIAL_DOH_URL_DEFAULT=
ADGUARD_RATE_LIMIT_QPS_DEFAULT=100
ADGUARD_SERVICE_USER=adguard
WINS_PARTIAL_VAULT_MOUNT_DEFAULT=/nonexistent-vault
id() { [[ "${FAKE_ADGUARD_USER:-1}" == 1 ]] || return 1; printf '%s\n' "${FAKE_ADGUARD_UID:-990}"; }
chown() { printf 'chown %s\n' "$*" >> "${EVENTS}"; }
chgrp() { printf 'chgrp %s\n' "$*" >> "${EVENTS}"; }
install() { printf 'install %s\n' "$*" >> "${EVENTS}"; command mkdir -p "${!#}"; }
# GNU mv -T emulation for macOS: rename(2) onto the exact path, never into it.
mv() {
  if [[ "$1" == -f && "$2" == -T && "$3" == -- ]]; then
    python3 -c 'import os, sys; os.replace(sys.argv[1], sys.argv[2])' "$4" "$5"
  else
    command mv "$@"
  fi
}
# GNU stat -c '%a' emulation for macOS.
stat() {
  if [[ "$1" == -c && "$2" == '%a' ]]; then
    python3 -c 'import os, sys; print(format(os.stat(sys.argv[1]).st_mode & 0o7777, "o"))' "$3"
  else
    command stat "$@"
  fi
}
'''


class AdGuardHarness:
    def __init__(self, case: unittest.TestCase) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="ia-dp-03-")
        case.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        self.events = self.root / "events.log"
        text = source()
        self.write_config = function_body(text, "write_adguard_config")
        self.secure = optional_function(text, "secure_adguard_workdir")
        self.verify = optional_function(text, "verify_adguard_unprivileged")

    def run(self, call: str, extra: dict[str, str] | None = None, prelude: str = "") -> subprocess.CompletedProcess[str]:
        env = base_env({"EVENTS": str(self.root / "events.log")})
        env.update(extra or {})
        script = ADGUARD_STUBS + prelude + self.write_config + self.secure + self.verify + "\n" + call + "\n"
        return run_bash(script, env, self.root)

    def events_text(self) -> str:
        return self.events.read_text(encoding="utf-8") if self.events.exists() else ""


class AdGuardPrivilegeTests(unittest.TestCase):
    def test_config_write_replaces_a_planted_symlink_instead_of_following_it(self) -> None:
        h = AdGuardHarness(self)
        workdir = h.root / "AdGuardHome"
        workdir.mkdir()
        victim = h.root / "victim-shadow"
        victim.write_text("root:x:0:0\n", encoding="utf-8")
        victim.chmod(0o644)
        config = workdir / "AdGuardHome.yaml"
        config.symlink_to(victim)
        result = h.run(f"write_adguard_config '{config}'")
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertEqual("root:x:0:0\n", victim.read_text(encoding="utf-8"))
        self.assertEqual(0o644, stat.S_IMODE(victim.stat().st_mode))
        self.assertFalse(config.is_symlink())
        self.assertIn("address: 127.0.0.1:3000", config.read_text(encoding="utf-8"))
        self.assertEqual(0o600, stat.S_IMODE(config.stat().st_mode))
        self.assertIn("adguard:adguard", h.events_text())
        self.assertEqual([], [p.name for p in workdir.iterdir() if p.name.startswith(".AdGuardHome.yaml.")])

    def test_config_write_refuses_to_land_inside_a_planted_directory(self) -> None:
        h = AdGuardHarness(self)
        workdir = h.root / "AdGuardHome"
        workdir.mkdir()
        elsewhere = h.root / "elsewhere"
        elsewhere.mkdir()
        (workdir / "AdGuardHome.yaml").symlink_to(elsewhere, target_is_directory=True)
        result = h.run(f"write_adguard_config '{workdir / 'AdGuardHome.yaml'}'")
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertEqual([], list(elsewhere.iterdir()))
        self.assertTrue((workdir / "AdGuardHome.yaml").is_file())

    def test_workdir_is_sticky_root_owned_and_binary_stays_root(self) -> None:
        h = AdGuardHarness(self)
        workdir = h.root / "opt" / "AdGuardHome"
        (workdir / "data" / "filters").mkdir(parents=True)
        (workdir / "AdGuardHome").write_text("#!/bin/sh\n", encoding="utf-8")
        (workdir / "AdGuardHome.yaml").write_text("schema_version: 34\n", encoding="utf-8")
        result = h.run(f"secure_adguard_workdir '{workdir}'")
        self.assertEqual(0, result.returncode, result.stdout)
        real = workdir.resolve()
        events = h.events_text()
        self.assertIn(f"chown root:adguard {real}\n", events)
        self.assertIn(f"chown root:root {real}/AdGuardHome\n", events)
        self.assertIn(f"chown -R -h adguard:adguard {real}/data\n", events)
        self.assertIn(f"chown -h adguard:adguard {real}/AdGuardHome.yaml\n", events)
        mode = stat.S_IMODE(real.stat().st_mode)
        self.assertEqual(0o1770, mode)
        # The restore preflight's secure_root_directory_path accepts a
        # group-writable directory only when it is sticky.
        preflight = function_body(source(), "secure_root_directory_path")
        self.assertIn("(8#${mode} & 0022) != 0 && (8#${mode} & 01000) == 0", preflight)
        self.assertFalse((mode & 0o022) != 0 and (mode & 0o1000) == 0)
        self.assertEqual(0o755, stat.S_IMODE((real / "AdGuardHome").stat().st_mode))

    def test_ownership_change_refused_while_adguard_still_runs(self) -> None:
        for state, allowed in (("active", False), ("deactivating", False), ("activating", False),
                               ("reloading", False), ("", False), ("QUERY-FAILS", False),
                               ("inactive", True), ("failed", True)):
            h = AdGuardHarness(self)
            workdir = h.root / "opt" / "AdGuardHome"
            (workdir / "data").mkdir(parents=True)
            (workdir / "AdGuardHome.yaml").write_text("x\n", encoding="utf-8")
            result = h.run(f"secure_adguard_workdir '{workdir}'", {"FAKE_ADGUARD_STATE": state})
            if allowed:
                self.assertEqual(0, result.returncode, f"{state}: {result.stdout}")
                self.assertIn("chown -h adguard:adguard", h.events_text(), state)
            else:
                self.assertNotEqual(0, result.returncode, f"{state}: {result.stdout}")
                self.assertNotIn("chown", h.events_text(), state)

    def test_partial_vault_mount_grants_group_search_only(self) -> None:
        h = AdGuardHarness(self)
        vault = h.root / "vault"
        target = vault / "data" / "adguard"
        target.mkdir(parents=True)
        (target / "AdGuardHome.yaml").write_text("x\n", encoding="utf-8")
        (vault / "data").chmod(0o755)
        vault.chmod(0o700)
        link = h.root / "opt-AdGuardHome"
        link.symlink_to(target, target_is_directory=True)
        self.addCleanup(vault.chmod, 0o755)
        result = h.run(f"secure_adguard_workdir '{link}'", {"WINS_PARTIAL_VAULT_MOUNT": str(vault)})
        self.assertEqual(0, result.returncode, result.stdout)
        events = h.events_text()
        self.assertIn(f"chgrp adguard {vault.resolve()}\n", events)
        self.assertNotIn(f"chgrp adguard {(vault / 'data').resolve()}\n", events)
        self.assertEqual(0o710, stat.S_IMODE(vault.stat().st_mode))

    def run_verify(self, uid: str, api_answers: bool, mode: str) -> subprocess.CompletedProcess[str]:
        h = AdGuardHarness(self)
        proc = h.root / "proc" / "4242"
        proc.mkdir(parents=True)
        (proc / "status").write_text(f"Name:\tAdGuardHome\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n", encoding="utf-8")
        h.verify = h.verify.replace('"/proc/${pid}/status"', f'"{h.root}/proc/${{pid}}/status"')
        prelude = (
            "systemctl() { [[ \"$1\" == show ]] && printf '4242\\n'; }\n"
            f"env() {{ printf 'env %s\\n' \"$*\" >> \"${{EVENTS}}\"; return {0 if api_answers else 7}; }}\n"
        )
        result = h.run("verify_adguard_unprivileged", {"WINS_DATA_PLANE_INSTALL_MODE": mode}, prelude)
        if uid != "0":
            probe = [line for line in h.events_text().splitlines() if line.startswith("env ")]
            self.assertEqual(1, len(probe), h.events_text())
            words = probe[0].split()[1:]
            self.assertEqual("-i", words[0], "the probe must start from an empty environment")
            runuser_at = words.index("runuser")
            self.assertEqual(
                ["PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"], words[1:runuser_at],
                "only the allowlisted variables may reach the uid-65534 probe",
            )
            self.assertEqual(["runuser", "-u", "nobody", "--", "curl"], words[runuser_at : runuser_at + 5])
        return result

    def test_verify_accepts_unprivileged_resolver_behind_the_owner_rule(self) -> None:
        self.assertEqual(0, self.run_verify("990", False, "main").returncode)

    def test_verify_refuses_a_root_resolver(self) -> None:
        self.assertNotEqual(0, self.run_verify("0", False, "main").returncode)

    def test_verify_refuses_an_api_that_answers_non_root_on_a_full_install(self) -> None:
        self.assertNotEqual(0, self.run_verify("990", True, "main").returncode)
        self.assertEqual(0, self.run_verify("990", True, "staged").returncode)

    def test_unit_runs_unprivileged_with_only_the_bind_capability(self) -> None:
        text = source()
        unit = heredoc(text, "cat > /etc/systemd/system/AdGuardHome.service <<'EOF'")
        service_user = re.search(r'^ADGUARD_SERVICE_USER="([a-z_][a-z0-9_-]*)"$', text, re.MULTILINE)
        self.assertIsNotNone(service_user, "ADGUARD_SERVICE_USER must be a fixed literal")
        assert service_user is not None
        for line in (
            f"User={service_user.group(1)}",
            f"Group={service_user.group(1)}",
            "AmbientCapabilities=CAP_NET_BIND_SERVICE",
            "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
            "NoNewPrivileges=true",
        ):
            self.assertRegex(unit, rf"(?m)^{re.escape(line)}$")

    def test_install_orders_account_config_ownership_then_restart_then_proof(self) -> None:
        install = function_body(source(), "install_adguard")
        order = [
            install.index("\n  ensure_adguard_service_user\n"),
            install.index("\n  write_adguard_config /opt/AdGuardHome/AdGuardHome.yaml\n"),
            install.index("\n  secure_adguard_workdir /opt/AdGuardHome\n"),
            install.index("\n  systemctl restart AdGuardHome\n"),
            install.index("verify_adguard_unprivileged || return 1"),
            install.index('echo "nameserver 127.0.0.1" > /etc/resolv.conf'),
        ]
        self.assertEqual(sorted(order), order)


class EdgeFirewallAdGuardTests(unittest.TestCase):
    """Runs the production wins-edge-hardening script up to its top-level call
    sequence against fake iptables backends and inspects the transaction."""

    def run_edge(self, node_env: str = 'NODE_MANAGEMENT_TUNNEL_ENABLED="1"\n',
                 extra: dict[str, str] | None = None, adguard_config: str | None = None) -> str:
        text = source()
        edge = heredoc(text, "cat > /usr/local/bin/wins-edge-hardening <<'WINS_EDGE_EOF'", "WINS_EDGE_EOF")
        cut = edge.index("\napply_rps\n")
        script = S4_EDGE_SHARED_STUBS + edge[:cut] + "\napply_firewall\n"
        temporary = tempfile.TemporaryDirectory(prefix="ia-dp-03-edge-")
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        (root / "node.env").write_text(node_env, encoding="utf-8")
        if adguard_config is not None:
            config = root / "rootfs" / "opt" / "AdGuardHome" / "AdGuardHome.yaml"
            config.parent.mkdir(parents=True)
            config.write_text(adguard_config, encoding="utf-8")
        capture = root / "restore-capture.txt"
        # -C (check) reports "absent" so ensure_jump stages every jump. -S
        # OUTPUT is empty until a restore ran, then shows the committed jump,
        # which apply_firewall reads back (F-DPHIGH-2).
        write_executable(
            bin_dir / "iptables",
            "#!/bin/bash\n"
            "while [[ \"${1:-}\" == -w ]]; do shift 2; done\n"
            "if [[ \"${1:-}\" == -t ]]; then shift 2; fi\n"
            "if [[ \"${1:-}\" == -S && \"${2:-}\" == OUTPUT && -s \"${FAKE_RESTORE_CAPTURE:?}\" ]]; then\n"
            "  echo '-P OUTPUT ACCEPT'; echo '-A OUTPUT -j WINVPN-OUTPUT'; exit 0\n"
            "fi\n"
            "case \"${1:-}\" in -n|-L|-m|-C) exit 1 ;; *) exit 0 ;; esac\n",
        )
        write_executable(
            bin_dir / "iptables-save",
            "#!/bin/bash\nprintf '%s\\n' '*filter' ':INPUT DROP [0:0]' ':FORWARD DROP [0:0]' ':OUTPUT ACCEPT [0:0]' 'COMMIT'\n",
        )
        write_executable(bin_dir / "iptables-restore", '#!/bin/bash\ncat >> "${FAKE_RESTORE_CAPTURE:?}"\nexit 0\n')
        write_executable(bin_dir / "systemctl", "#!/bin/bash\nexit 0\n")
        write_executable(bin_dir / "journalctl", "#!/bin/bash\nexit 0\n")
        env = base_env(
            {
                "PATH": f"{bin_dir}:{os.environ['PATH']}",
                "NODE_ENV_FILE": str(root / "node.env"),
                "PUBLIC_VPN_INGRESS_ADMISSION_FILE": str(root / "absent-admission.env"),
                "WINN3_GATEWAY_ENV_FILE": str(root / "absent-winn3.env"),
                "WINSVPN_TEST_ROOT": str(root / "rootfs"),
                "WAN_IF": "eth0",
                "IPTABLES_BIN": str(bin_dir / "iptables"),
                "IPTABLES_SAVE_BIN": str(bin_dir / "iptables-save"),
                "IPTABLES_RESTORE_BIN": str(bin_dir / "iptables-restore"),
                "FAKE_RESTORE_CAPTURE": str(capture),
                "WINS_FIREWALL_LOCK_HELD": "1",
                "PUBLIC_VPN_INGRESS_ADMISSION": "0",
                "INSTALL_DATA_IDS_IPS": "0",
            }
        )
        env.update(extra or {})
        result = run_bash(script, env, root)
        self.assertEqual(0, result.returncode, result.stdout)
        return capture.read_text(encoding="utf-8")

    def test_only_root_may_open_the_adguard_admin_port(self) -> None:
        transaction = self.run_edge()
        # --test and the real commit both carry the same transaction.
        self.assertIn(":WINVPN-OUTPUT - [0:0]", transaction)
        self.assertIn("-I OUTPUT 1 -j WINVPN-OUTPUT", transaction)
        rule = (
            "-A WINVPN-OUTPUT -o lo -p tcp --dport 3000 -m owner --socket-exists "
            "! --uid-owner 0 -j REJECT --reject-with tcp-reset"
        )
        self.assertIn(rule, transaction)
        filter_table = transaction.split("COMMIT")[0]
        self.assertLess(filter_table.index(":WINVPN-OUTPUT - [0:0]"), filter_table.index(rule))

    def test_ui_rules_guard_the_port_adguard_listens_on(self) -> None:
        transaction = self.run_edge()
        self.assertNotIn("--dport 8080", transaction)
        self.assertIn("-A WINVPN-INPUT -p tcp --dport 3000 -j DROP", transaction)
        config = function_body(source(), "write_adguard_config")
        listen = re.search(r"^  address: 127\.0\.0\.1:(\d+)$", config, re.MULTILINE)
        assert listen is not None
        edge = heredoc(source(), "cat > /usr/local/bin/wins-edge-hardening <<'WINS_EDGE_EOF'", "WINS_EDGE_EOF")
        edge = heredoc(source(), "cat > /usr/local/bin/wins-edge-hardening <<'WINS_EDGE_EOF'", "WINS_EDGE_EOF")
        fallback = function_body(edge, "adguard_ui_port_from_config") if "\nadguard_ui_port_from_config() {\n" in edge else ""
        default = re.search(r"printf '(\d+)\\n'\n  fi\n\}", fallback)
        assert default is not None, "the edge script must fall back to the rendered listen port"
        self.assertEqual(listen.group(1), default.group(1))

    def owner_rule(self, port: str) -> str:
        return (
            f"-A WINVPN-OUTPUT -o lo -p tcp --dport {port} -m owner --socket-exists "
            "! --uid-owner 0 -j REJECT --reject-with tcp-reset"
        )

    def test_bootstrap_guards_the_port_install_adguard_will_bind(self) -> None:
        """Sol N-3: main() runs the bootstrap transaction before install_adguard
        rewrites the config and restarts AdGuard. Whatever the old config says,
        the port write_adguard_config renders must already be guarded."""
        config = function_body(source(), "write_adguard_config")
        rendered = re.search(r"^  address: 127\.0\.0\.1:(\d+)$", config, re.MULTILINE)
        assert rendered is not None
        for old_port in ("3100", "3000", "8443"):
            transaction = self.run_edge(adguard_config=f"http:\n  address: 127.0.0.1:{old_port}\n")
            self.assertIn(self.owner_rule(rendered.group(1)), transaction, old_port)
            self.assertIn(self.owner_rule(old_port), transaction, old_port)
            self.assertIn(f"-A WINVPN-INPUT -p tcp --dport {old_port} -j DROP", transaction)
            self.assertIn(f"-A WINVPN-INPUT -p tcp --dport {rendered.group(1)} -j DROP", transaction)
        single = self.run_edge(adguard_config="http:\n  address: 127.0.0.1:3000\n")
        filter_table = single.split("COMMIT")[0]
        self.assertEqual(1, filter_table.count(self.owner_rule("3000")), "no duplicate rule once the config says 3000")

    def test_ui_port_override_cannot_move_the_owner_rule(self) -> None:
        rendered = "schema_version: 34\nhttp:\n  address: 127.0.0.1:3000\ndns:\n  port: 53\n"
        via_env = self.run_edge(extra={"ADGUARD_UI_PORT": "8080"}, adguard_config=rendered)
        via_node_env = self.run_edge(
            node_env='NODE_MANAGEMENT_TUNNEL_ENABLED="1"\nADGUARD_UI_PORT="8080"\n', adguard_config=rendered
        )
        for transaction in (via_env, via_node_env):
            self.assertIn(self.owner_rule("3000"), transaction)
            self.assertNotIn("--dport 8080", transaction)

    def test_owner_rule_follows_the_port_adguard_binds(self) -> None:
        moved = self.run_edge(
            extra={"ADGUARD_UI_PORT": "8080"},
            adguard_config='http:\n  session_ttl: 720h\n  address: "127.0.0.1:3100"\ndns:\n  address: 127.0.0.1:9999\n',
        )
        self.assertIn(self.owner_rule("3100"), moved)
        self.assertIn(self.owner_rule("3000"), moved, "the port install_adguard is about to bind stays guarded")
        self.assertNotIn("--dport 9999", moved)
        self.assertNotIn("--dport 8080", moved)
        for config in (None, "http:\n  address: not-a-port\n", "dns:\n  address: 127.0.0.1:4000\n"):
            fallback = self.run_edge(adguard_config=config)
            self.assertIn(self.owner_rule("3000"), fallback, config)
            owner_ports = re.findall(r"-A WINVPN-OUTPUT -o lo -p tcp --dport (\d+) ", fallback.split("COMMIT")[0])
            self.assertEqual(["3000"], owner_ports, f"only the fallback port is guarded for {config!r}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
