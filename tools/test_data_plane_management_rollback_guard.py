#!/usr/bin/env python3
"""Hostile portable regression for data-plane recovery and local withdrawal."""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import sys
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
DATA = ROOT / "server" / "wins_data_plane_setup_ONETOUCH.sh"


def heredoc(source: str, tag: str) -> str:
    marker = f"<<'{tag}'"
    marker_at = source.index(marker)
    start = source.index("\n", marker_at) + 1
    end = source.index(f"\n{tag}", start)
    return source[start:end] + "\n"


def function_body(source: str, name: str) -> str:
    marker = f"{name}() {{"
    start = source.index(marker)
    cursor = source.index("\n}", start)
    while True:
        candidate = source[start : cursor + 2]
        if candidate.count("{") == candidate.count("}"):
            return candidate
        cursor = source.index("\n}", cursor + 2)


def write_executable(path: pathlib.Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o700)


class FakeNode:
    def __init__(self, root: pathlib.Path, source: str) -> None:
        self.root = root
        self.bin = root / "bin"
        self.state = root / "state"
        self.etc_iptables = root / "etc-iptables"
        self.fw = root / "fw"
        self.logs = root / "logs"
        for directory in (self.bin, self.etc_iptables, self.fw, self.logs):
            directory.mkdir(parents=True)
        self.boot_id = root / "boot-id"
        self.boottime = root / "boottime"
        self.node_env = root / "node.env"
        self.installer = root / "installer.sh"
        self.guard = root / "wins-node-ssh-recovery-guard"
        self.local_guard = root / "wins-node-local-serving"
        self.rules = self.etc_iptables / "rules.v4"
        self.latch = root / "local-serving.disabled"
        self.ready = root / "node-deployment-ready"
        self.boot_id.write_text(
            "11111111-1111-4111-8111-111111111111\n", encoding="utf-8"
        )
        self.boottime.write_text("10\n", encoding="utf-8")
        self.node_env.write_text(
            "NODE_MANAGEMENT_TUNNEL_ID=22222222-2222-4222-8222-222222222222\n",
            encoding="utf-8",
        )
        self.installer.write_text("#!/bin/bash\ntrue\n", encoding="utf-8")
        self.installer.chmod(0o700)
        self.ready.write_text("ready\n", encoding="utf-8")
        self.source = source
        self._write_stubs()
        (self.fw / "INPUT").write_text(
            "-A INPUT -j WINVPN-INPUT\n", encoding="utf-8"
        )
        production = DATA.read_text(encoding="utf-8")
        write_executable(
            self.guard,
            self.portable_guard(heredoc(production, "WINS_NODE_SSH_RECOVERY_GUARD")),
        )
        write_executable(
            self.local_guard,
            heredoc(production, "WINS_NODE_LOCAL_SERVING_GUARD").replace(
                "  flock -x 9\n", "  : # portable test lock\n"
            ),
        )

    @staticmethod
    def portable_guard(guard: str) -> str:
        guard = guard.replace("  flock -x 9\n", "  : # portable test lock\n")
        return guard.replace(
            function_body(guard, "current_boottime_seconds"),
            'current_boottime_seconds() { cat "${TEST_BOOTTIME_FILE:?}"; }',
        )

    def _write_stubs(self) -> None:
        write_executable(
            self.bin / "id",
            "#!/bin/bash\n[[ \"${1:-}\" == -u ]] && { echo 0; exit 0; }\nexec /usr/bin/id \"$@\"\n",
        )
        write_executable(self.bin / "chown", "#!/bin/bash\nexit 0\n")
        write_executable(self.bin / "sync", "#!/bin/bash\nexit 0\n")
        if shutil.which("flock") is None:
            # S4: the guards now take fd 7 (wins_fw_lock) for the whole transition.
            # The single-process fixture needs no real exclusion, only success.
            write_executable(self.bin / "flock", "#!/bin/bash\nexit 0\n")
        write_executable(
            self.bin / "stat",
            r'''#!/bin/bash
case "$2" in
  '%u:%g:%a') echo '0:0:700' ;;
  '%u:%g:%a:%h') echo '0:0:600:1' ;;
  '%u:%g:%h') echo '0:0:1' ;;
  *) exec /usr/bin/stat "$@" ;;
esac
''',
        )
        write_executable(
            self.bin / "install",
            r'''#!/bin/bash
args=()
while (($#)); do
  case "$1" in
    -o|-g) shift 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
exec /usr/bin/install "${args[@]}"
''',
        )
        write_executable(
            self.bin / "systemctl",
            r'''#!/bin/bash
printf '%s\n' "$*" >> "${FAKE_SYSTEMCTL_LOG:?}"
exit 0
''',
        )
        write_executable(
            self.bin / "iptables",
            r'''#!/bin/bash
set -euo pipefail
if [[ "${1:-}" == -w ]]; then shift 2; fi
if [[ "${1:-}" == -n && "${2:-}" == -L ]]; then
  test -f "${FAKE_FW_DIR:?}/$3"
  exit
fi
operation="${1:-}"
chain="${2:-}"
file="${FAKE_FW_DIR:?}/${chain}"
case "$operation" in
  -N) : > "$file" ;;
  -F)
    if [[ "$chain" == WINVPN-LOCAL-SERVING && "${REQUIRE_LATCH_BEFORE_FIREWALL:-0}" == 1 ]]; then
      test -f "${WINS_NODE_LOCAL_SERVING_LATCH:?}"
    fi
    : > "$file"
    ;;
  -A)
    test -f "$file"
    shift 2
    rendered="$*"
    rendered="${rendered/-p tcp --dport/-p tcp -m tcp --dport}"
    printf -- '-A %s %s\n' "$chain" "$rendered" >> "$file"
    ;;
  -C)
    test -f "$file"
    shift 2
    grep -Fxq -- "-A $chain $*" "$file"
    ;;
  -D)
    test -f "$file"
    shift 2
    line="-A $chain $*"
    awk -v wanted="$line" 'BEGIN {removed=0} {if (!removed && $0 == wanted) {removed=1; next} print} END {exit(removed ? 0 : 1)}' "$file" > "$file.tmp"
    mv "$file.tmp" "$file"
    ;;
  -I)
    test -f "$file"
    position="${3:-}"
    test "$position" = 1
    shift 3
    { printf -- '-A %s %s\n' "$chain" "$*"; cat "$file"; } > "$file.tmp"
    mv "$file.tmp" "$file"
    ;;
  -S)
    test -f "$file"
    printf -- '-N %s\n' "$chain"
    cat "$file"
    ;;
  *) exit 2 ;;
esac
''',
        )
        write_executable(
            self.bin / "iptables-restore",
            r'''#!/usr/bin/env python3
import os
from pathlib import Path
import sys
assert sys.argv[1:] == ["--wait", "10", "--noflush"]
body = sys.stdin.read().splitlines()
chain = "WINVPN-LOCAL-SERVING"
assert body[0] == "*filter" and body[-1] == "COMMIT"
assert ":" + chain + " - [0:0]" in body
if os.environ.get("REQUIRE_LATCH_BEFORE_FIREWALL") == "1":
    assert Path(os.environ["WINS_NODE_LOCAL_SERVING_LATCH"]).is_file()
rules = [line for line in body if line.startswith("-A " + chain + " ")]
path = Path(os.environ["FAKE_FW_DIR"]) / chain
temporary = path.with_suffix(".tmp")
temporary.write_text("\n".join(rules) + "\n")
os.replace(temporary, path)
''',
        )
        write_executable(
            self.bin / "iptables-save",
            r'''#!/bin/bash
printf '%s\n' '*filter'
for file in "${FAKE_FW_DIR:?}"/*; do
  [[ -f "$file" ]] || continue
  printf -- ':%s - [0:0]\n' "$(basename "$file")"
  cat "$file"
done
printf '%s\n' COMMIT
''',
        )
        write_executable(
            self.bin / "ip6tables",
            r'''#!/bin/bash
printf '%s\n' "$*" >> "${FAKE_IP6TABLES_LOG:?}"
exit 0
''',
        )
        write_executable(
            self.bin / "wins-node-register",
            "#!/bin/bash\nexit \"${FAKE_REGISTER_RC:-0}\"\n",
        )
        write_executable(self.bin / "docker", "#!/bin/bash\nexit 0\n")

    def env(self) -> dict[str, str]:
        value = os.environ.copy()
        value.update(
            {
                "PATH": f"{self.bin}:{os.environ['PATH']}",
                "WINS_NODE_SSH_RECOVERY_STATE_DIR": str(self.state),
                "WINS_NODE_SSH_RECOVERY_RULES_FILE": str(self.rules),
                "WINS_NODE_SSH_RECOVERY_NODE_ENV_FILE": str(self.node_env),
                "WINS_NODE_SSH_RECOVERY_INSTALLER_PATH": str(self.installer),
                "WINS_NODE_SSH_RECOVERY_BOOT_ID_FILE": str(self.boot_id),
                "TEST_BOOTTIME_FILE": str(self.boottime),
                "NODE_SSH_RECOVERY_TIMEOUT_SECONDS": "120",
                "IPTABLES_BIN": str(self.bin / "iptables"),
                "IPTABLES_SAVE_BIN": str(self.bin / "iptables-save"),
                "IPTABLES_RESTORE_BIN": str(self.bin / "iptables-restore"),
                "SYSTEMCTL_BIN": str(self.bin / "systemctl"),
                "FAKE_FW_DIR": str(self.fw),
                "FAKE_SYSTEMCTL_LOG": str(self.logs / "systemctl"),
                "FAKE_IP6TABLES_LOG": str(self.logs / "ip6tables"),
                "SSH_CONNECTION": f"{self.source} 50000 203.0.113.9 22",
                "WINS_NODE_LOCAL_SERVING_LATCH": str(self.latch),
                "WINS_NODE_DEPLOYMENT_READY_FILE": str(self.ready),
                "WINS_NODE_LOCAL_SERVING_RULES_FILE": str(self.rules),
                "WINS_NODE_LOCAL_SERVING_LOCK_FILE": str(self.root / "local.lock"),
                "WINS_FIREWALL_LOCK": str(self.root / "wins-firewall.lock"),
                "IP6TABLES_BIN": str(self.bin / "ip6tables"),
                "WINS_NODE_REGISTER_BIN": str(self.bin / "wins-node-register"),
                "WINS_NODE_LOCAL_SERVING_INSTALLER_PATH": str(self.installer),
                # Portable stand-in for the shared firewall lock (Round SU),
                # like the guard's own "flock -x 9" replacement above: macOS
                # has no flock(1).
                "WINS_FIREWALL_LOCK_HELD": "1",
            }
        )
        return value

    def run_guard(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(self.guard), *args],
            env=self.env(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

    def run_local(
        self,
        *args: str,
        hub_down: bool = False,
        require_latch_before_firewall: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        environment = self.env()
        environment["REQUIRE_LATCH_BEFORE_FIREWALL"] = (
            "1" if require_latch_before_firewall else "0"
        )
        environment["FAKE_REGISTER_RC"] = "1" if hub_down else "0"
        return subprocess.run(
            ["bash", str(self.local_guard), *args],
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )


class RecoveryGuardRuntimeTests(unittest.TestCase):
    def make_node(self, source: str = "8.8.8.8") -> tuple[tempfile.TemporaryDirectory[str], FakeNode]:
        temporary = tempfile.TemporaryDirectory(prefix="wins-ssh-guard-")
        return temporary, FakeNode(pathlib.Path(temporary.name), source)

    def test_arm_is_immediate_exact_and_cannot_extend(self) -> None:
        temporary, node = self.make_node()
        with temporary:
            result = node.run_guard("arm")
            self.assertEqual(0, result.returncode, result.stdout)
            state_before = (node.state / "armed.env").read_bytes()
            chain = (node.fw / "WINVPN-SSH-RECOVERY").read_text(encoding="utf-8")
            self.assertEqual(
                "-A WINVPN-SSH-RECOVERY -s 8.8.8.8/32 -p tcp -m tcp --dport 22 "
                "-j ACCEPT\n",
                chain,
            )
            base = (node.fw / "INPUT").read_text(encoding="utf-8").splitlines()
            self.assertEqual("-A INPUT -j WINVPN-SSH-RECOVERY", base[0])
            self.assertEqual(1, base.count("-A INPUT -j WINVPN-SSH-RECOVERY"))
            second = node.run_guard("arm")
            self.assertNotEqual(0, second.returncode, second.stdout)
            self.assertIn("refusing to extend", second.stdout)
            self.assertEqual(state_before, (node.state / "armed.env").read_bytes())

    def test_timeout_client_loss_and_reboot_each_mark_fired_and_reassert(self) -> None:
        for mode in ("timeout", "reboot"):
            with self.subTest(mode=mode):
                temporary, node = self.make_node()
                with temporary:
                    self.assertEqual(0, node.run_guard("arm").returncode)
                    (node.fw / "WINVPN-SSH-RECOVERY").write_text("", encoding="utf-8")
                    if mode == "timeout":
                        node.boottime.write_text("131\n", encoding="utf-8")
                    else:
                        node.boot_id.write_text(
                            "33333333-3333-4333-8333-333333333333\n",
                            encoding="utf-8",
                        )
                        node.boottime.write_text("1\n", encoding="utf-8")
                    result = node.run_guard("check")
                    self.assertEqual(0, result.returncode, result.stdout)
                    state = (node.state / "armed.env").read_text(encoding="utf-8")
                    self.assertIn("FIRED=1\n", state)
                    self.assertIn("8.8.8.8/32", (node.fw / "WINVPN-SSH-RECOVERY").read_text())
                    self.assertIn("enable --now ssh.service", (node.logs / "systemctl").read_text())

    def test_foreign_position_one_drop_is_displaced_on_check(self) -> None:
        temporary, node = self.make_node()
        with temporary:
            self.assertEqual(0, node.run_guard("arm").returncode)
            base_file = node.fw / "INPUT"
            base_file.write_text(
                "-A INPUT -j DROP\n" + base_file.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            result = node.run_guard("check")
            self.assertEqual(0, result.returncode, result.stdout)
            base = base_file.read_text(encoding="utf-8").splitlines()
            self.assertEqual("-A INPUT -j WINVPN-SSH-RECOVERY", base[0])
            self.assertEqual("-A INPUT -j DROP", base[1])
            self.assertEqual(1, base.count("-A INPUT -j WINVPN-SSH-RECOVERY"))

    def test_confirm_after_firing_closes_before_state_removal_and_stays_closed(self) -> None:
        temporary, node = self.make_node()
        with temporary:
            self.assertEqual(0, node.run_guard("arm").returncode)
            node.boottime.write_text("131\n", encoding="utf-8")
            self.assertEqual(0, node.run_guard("check").returncode)
            installer_bytes = node.installer.read_bytes()
            node.installer.write_bytes(installer_bytes + b"# changed\n")
            rejected = node.run_guard("confirm")
            self.assertNotEqual(0, rejected.returncode, rejected.stdout)
            self.assertTrue((node.state / "armed.env").exists())
            self.assertIn("8.8.8.8/32", (node.fw / "WINVPN-SSH-RECOVERY").read_text())
            node.installer.write_bytes(installer_bytes)
            node.installer.chmod(0o700)
            result = node.run_guard("confirm")
            self.assertEqual(0, result.returncode, result.stdout)
            self.assertFalse((node.state / "armed.env").exists())
            self.assertTrue((node.state / "confirmed.env").exists())
            self.assertEqual("", (node.fw / "WINVPN-SSH-RECOVERY").read_text())
            self.assertNotIn(
                "-A INPUT -j WINVPN-SSH-RECOVERY",
                (node.fw / "INPUT").read_text(encoding="utf-8"),
            )
            persisted = node.rules.read_text(encoding="utf-8")
            self.assertNotIn("-A INPUT -j WINVPN-SSH-RECOVERY", persisted)
            self.assertNotIn("-A WINVPN-SSH-RECOVERY ", persisted)
            status = node.run_guard("status")
            self.assertEqual(0, status.returncode, status.stdout)
            self.assertEqual("confirmed", status.stdout.strip())
            self.assertEqual(0, node.run_guard("check").returncode)
            self.assertEqual("", (node.fw / "WINVPN-SSH-RECOVERY").read_text())

    def test_state_loss_fails_closed_for_each_recovery_surface_without_mutation(self) -> None:
        for orphan in ("live-chain", "live-base-jump", "persisted"):
            with self.subTest(orphan=orphan):
                temporary, node = self.make_node()
                with temporary:
                    self.assertEqual(0, node.run_guard("arm").returncode)
                    (node.state / "armed.env").unlink()
                    closed_rules = (
                        "*filter\n"
                        ":INPUT - [0:0]\n"
                        ":WINVPN-INPUT - [0:0]\n"
                        ":WINVPN-SSH-RECOVERY - [0:0]\n"
                        "-A INPUT -j WINVPN-INPUT\n"
                        "-A WINVPN-INPUT -j WINVPN-SSH-RECOVERY\n"
                        "COMMIT\n"
                    )
                    if orphan != "live-chain":
                        (node.fw / "WINVPN-SSH-RECOVERY").write_text(
                            "", encoding="utf-8"
                        )
                    if orphan != "live-base-jump":
                        (node.fw / "INPUT").write_text(
                            "-A INPUT -j WINVPN-INPUT\n", encoding="utf-8"
                        )
                    if orphan != "persisted":
                        node.rules.write_text(closed_rules, encoding="utf-8")

                    firewall_before = {
                        path.name: path.read_bytes()
                        for path in sorted(node.fw.iterdir())
                    }
                    persisted_before = node.rules.read_bytes()
                    for command in ("check", "status"):
                        result = node.run_guard(command)
                        self.assertNotEqual(0, result.returncode, result.stdout)
                        self.assertNotIn("externally confirmed", result.stdout)
                    self.assertEqual(
                        firewall_before,
                        {
                            path.name: path.read_bytes()
                            for path in sorted(node.fw.iterdir())
                        },
                    )
                    self.assertEqual(persisted_before, node.rules.read_bytes())

    def test_never_armed_check_accepts_only_fully_closed_recovery_state(self) -> None:
        temporary, node = self.make_node()
        with temporary:
            result = node.run_guard("check")
            self.assertEqual(0, result.returncode, result.stdout)
            (node.fw / "WINVPN-SSH-RECOVERY").write_text("", encoding="utf-8")
            node.rules.write_text(
                "*filter\n"
                ":INPUT - [0:0]\n"
                ":WINVPN-INPUT - [0:0]\n"
                ":WINVPN-SSH-RECOVERY - [0:0]\n"
                "-A INPUT -j WINVPN-INPUT\n"
                "-A WINVPN-INPUT -j WINVPN-SSH-RECOVERY\n"
                "COMMIT\n",
                encoding="utf-8",
            )
            result = node.run_guard("check")
            self.assertEqual(0, result.returncode, result.stdout)

    def test_malformed_or_non_global_sources_never_arm(self) -> None:
        for source in (
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.2",
            "100.64.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "240.0.0.1",
            "2001:4860:4860::8888",
            "203.0.113.9",
            "not-an-ip",
        ):
            with self.subTest(source=source):
                temporary, node = self.make_node(source)
                with temporary:
                    result = node.run_guard("arm")
                    self.assertNotEqual(0, result.returncode, result.stdout)
                    self.assertFalse((node.state / "armed.env").exists())


class LocalServingRuntimeTests(unittest.TestCase):
    def test_disable_commits_first_and_succeeds_during_hub_outage(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="wins-local-serving-")
        with temporary:
            node = FakeNode(pathlib.Path(temporary.name), "8.8.8.8")
            result = node.run_local(
                "disable", "--reason", "deployment-gate-failure", hub_down=True
            )
            self.assertEqual(0, result.returncode, result.stdout)
            self.assertTrue(node.latch.exists())
            self.assertFalse(node.ready.exists())
            rules = (node.fw / "WINVPN-LOCAL-SERVING").read_text(encoding="utf-8")
            self.assertEqual(
                "-A WINVPN-LOCAL-SERVING -i lo -j RETURN\n"
                "-A WINVPN-LOCAL-SERVING -m conntrack --ctstate RELATED,ESTABLISHED "
                "--ctdir REPLY -j RETURN\n"
                "-A WINVPN-LOCAL-SERVING -j DROP\n",
                rules,
            )
            ip6 = (node.logs / "ip6tables").read_text(encoding="utf-8")
            self.assertIn("-P INPUT DROP", ip6)
            self.assertIn("-P FORWARD DROP", ip6)
            status = node.run_local("status", hub_down=True)
            self.assertEqual(0, status.returncode, status.stdout)
            self.assertEqual("disabled", status.stdout.strip())

    def test_no_enable_or_clear_command_exists(self) -> None:
        source = DATA.read_text(encoding="utf-8")
        local = heredoc(source, "WINS_NODE_LOCAL_SERVING_GUARD")
        self.assertNotRegex(local, r"^\s*(enable|clear)\)", "unaudited recovery bypass")

    def test_only_exact_installer_rerun_can_release_after_postflight(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="wins-local-serving-release-")
        with temporary:
            node = FakeNode(pathlib.Path(temporary.name), "8.8.8.8")
            installer_sha = hashlib.sha256(node.installer.read_bytes()).hexdigest()
            disabled = node.run_local(
                "disable", "--reason", f"installer-rerun:{installer_sha}"
            )
            self.assertEqual(0, disabled.returncode, disabled.stdout)

            forged = node.run_local(
                "release-deployment", "--installer-sha256", "0" * 64
            )
            self.assertNotEqual(0, forged.returncode, forged.stdout)
            self.assertTrue(node.latch.exists())
            self.assertIn(
                "-A WINVPN-LOCAL-SERVING -j DROP",
                (node.fw / "WINVPN-LOCAL-SERVING").read_text(encoding="utf-8"),
            )

            released = node.run_local(
                "release-deployment",
                "--installer-sha256",
                installer_sha,
                require_latch_before_firewall=False,
            )
            self.assertEqual(0, released.returncode, released.stdout)
            self.assertFalse(node.latch.exists())
            self.assertEqual(
                "",
                (node.fw / "WINVPN-LOCAL-SERVING").read_text(encoding="utf-8"),
            )

    def test_manual_latch_cannot_be_released_by_installer_bytes(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="wins-local-serving-manual-")
        with temporary:
            node = FakeNode(pathlib.Path(temporary.name), "8.8.8.8")
            installer_sha = hashlib.sha256(node.installer.read_bytes()).hexdigest()
            self.assertEqual(
                0,
                node.run_local(
                    "disable", "--reason", "operator-emergency-withdrawal"
                ).returncode,
            )
            rejected = node.run_local(
                "release-deployment", "--installer-sha256", installer_sha
            )
            self.assertNotEqual(0, rejected.returncode, rejected.stdout)
            self.assertTrue(node.latch.exists())
            self.assertIn(
                "-A WINVPN-LOCAL-SERVING -j DROP",
                (node.fw / "WINVPN-LOCAL-SERVING").read_text(encoding="utf-8"),
            )


class StaticAndMutationTests(unittest.TestCase):
    def assert_contract(self, source: str) -> None:
        edge = heredoc(source, "WINS_EDGE_EOF")
        recovery = "ipt -A WINVPN-INPUT -j WINVPN-SSH-RECOVERY"
        local = "ipt -A WINVPN-INPUT -j WINVPN-LOCAL-SERVING"
        loopback = "ipt -A WINVPN-INPUT -i lo -j ACCEPT"
        self.assertIn(recovery, edge)
        self.assertIn(local, edge)
        self.assertIn(loopback, edge)
        self.assertLess(edge.index(recovery), edge.index(local))
        self.assertLess(edge.index(local), edge.index(loopback))
        self.assertNotIn("chain_reset filter WINVPN-SSH-RECOVERY", edge)
        self.assertNotIn("chain_reset filter WINVPN-LOCAL-SERVING", edge)
        self.assertIn("wins_require_ssh_recovery_guard_before_close || return 1", source)
        register = function_body(source, "write_register_script")
        self.assertIn('|| -e "${NODE_LOCAL_SERVING_LATCH}" || -L "${NODE_LOCAL_SERVING_LATCH}"', register)
        main = source[source.rfind("\nmain() {") :]
        # FIX-2 (2026-09-05 Germany RCA): arming must happen BEFORE the first
        # fail-closed bootstrap commit, and the FIX-3 abort-rollback window
        # spans exactly first-commit .. postflight.
        order = (
            "write_node_ssh_recovery_guard",
            "write_node_local_serving_guard",
            "arm_node_ssh_recovery_guard",
            "deploy_firewall_rollback_arm",
            "apply_bootstrap_firewall",
            "verify_hub_node_management",
            "write_firewall",
            "postflight_data_plane",
            "deploy_firewall_rollback_disarm",
        )
        positions = [main.index(item) for item in order]
        self.assertEqual(sorted(positions), positions)
        # FIX-2 extension (B0 acceptance): arm must precede not only the
        # apply_bootstrap_firewall CALL but the first '-P INPUT DROP' commit
        # reachable from main(). No firewall-committing verb may appear in
        # main() before the arm call, and the commit chain
        # apply_bootstrap_firewall -> wins-edge-hardening -> apply_firewall
        # must actually contain the policy DROP.
        arm_at = main.index("arm_node_ssh_recovery_guard")
        for commit_verb in (
            "apply_bootstrap_firewall",
            "write_firewall",
            "write_runtime_vpn_firewall_unit",
            "/usr/local/bin/wins-edge-hardening",
        ):
            self.assertNotIn(commit_verb, main[:arm_at])
        bootstrap_fn = function_body(source, "apply_bootstrap_firewall")
        self.assertIn("/usr/local/bin/wins-edge-hardening", bootstrap_fn)
        edge_firewall = function_body(edge, "apply_firewall")
        self.assertIn("ipt -P INPUT DROP", edge_firewall)
        self.assertNotIn("ssh-recovery-guard confirm", main)
        self.assertNotIn("ssh-recovery-guard confirm", register)
        arm_wrapper = function_body(source, "arm_node_ssh_recovery_guard")
        self.assertIn("armed|fired)", arm_wrapper)
        self.assertIn("continuing without changing its original deadline", arm_wrapper)

        # FIX-1: caller-inline bootstrap overrides must survive `source node.env`
        # inside the generated edge script, mirroring the pre-existing
        # PUBLIC_VPN_INGRESS_ADMISSION preservation pattern exactly.
        for preserved in (
            "NODE_MANAGEMENT_TUNNEL_ENABLED",
            "IONOS_HUB_IP",
            "INSTALL_DATA_IDS_IPS",
        ):
            self.assertIn(f'{preserved}_REQUESTED="${{{preserved}-}}"', edge)
            self.assertIn(f'{preserved}_REQUESTED_SET="${{{preserved}+x}}"', edge)
            self.assertIn(
                f'if [[ "${{{preserved}_REQUESTED_SET}}" == "x" ]]; then\n'
                f'  {preserved}="${{{preserved}_REQUESTED}}"\n'
                "fi",
                edge,
            )
        self.assertLess(
            edge.index('NODE_MANAGEMENT_TUNNEL_ENABLED_REQUESTED="${NODE_MANAGEMENT_TUNNEL_ENABLED-}"'),
            edge.index('source "${NODE_ENV_FILE}"'),
        )
        self.assertLess(
            edge.index('NODE_MANAGEMENT_TUNNEL_ENABLED="${NODE_MANAGEMENT_TUNNEL_ENABLED_REQUESTED}"'),
            edge.index('NODE_MANAGEMENT_TUNNEL_ENABLED="${NODE_MANAGEMENT_TUNNEL_ENABLED:-1}"'),
        )
        self.assertLess(
            edge.index('IONOS_HUB_IP="${IONOS_HUB_IP_REQUESTED}"'),
            edge.index('HUB_IP="${IONOS_HUB_IP:-}"'),
        )

        # FIX-3: the abort-rollback handler prefers the guard's own persisted
        # reassertion, falls back to the pre-deployment snapshot, and always
        # returns 0 so it cannot wedge the node or skip the chained Cloudflare
        # handler under set -e.
        for required in (
            "deploy_firewall_rollback_arm() {",
            "deploy_firewall_rollback_disarm() {",
            "deploy_firewall_rollback_on_exit() {",
            'trap \'winn3_installer_exit "$?" 0\' EXIT',
            'trap \'winn3_installer_exit "$?" 1\' EXIT',
            "winn3_installer_exit() {",
        ):
            self.assertIn(required, source)
        # S4 (design 2.7): the ordered exit wrapper keeps the rollback and the
        # chained Cloudflare handler, in that order, with the original status.
        wrapper = function_body(source, "winn3_installer_exit")
        self.assertLess(
            wrapper.index('deploy_firewall_rollback_on_exit "${rc}"'),
            wrapper.index('cloudflare_redirect_transaction_on_exit "${rc}"'),
        )
        rollback = function_body(source, "deploy_firewall_rollback_on_exit")
        self.assertTrue(rollback.rstrip().endswith("return 0\n}"))
        self.assertLess(
            rollback.index("wins-node-ssh-recovery-guard check"),
            rollback.index("iptables-restore --wait 10"),
        )

        # FIX-6 / FIX-6a: preflight loudly rejects an EXTERNAL IPv6
        # SSH_CONNECTION before any mutation, but a LOOPBACK source is
        # management-tunnel ingress (the local cloudflared proxy) and must
        # proceed: it is the fleet's steady-state rerun/resume path, not a
        # v6 direct session. The loopback branch must be evaluated first.
        preflight = function_body(source, "preflight_data_plane")
        self.assertIn('ssh_source="${SSH_CONNECTION%% *}"', preflight)
        self.assertIn("if deployment_session_source_is_loopback; then", preflight)
        self.assertIn('elif [[ "${ssh_source}" == *:* ]]; then', preflight)
        self.assertLess(
            preflight.index("if deployment_session_source_is_loopback; then"),
            preflight.index('elif [[ "${ssh_source}" == *:* ]]; then'),
        )
        self.assertIn("Reconnect over IPv4 (ssh -4)", preflight)
        helper = function_body(source, "deployment_session_source_is_loopback")
        for literal in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
            self.assertIn(literal, helper)

        # Candidate 4: on a rerun whose live firewall already routes through the
        # local-serving latch chain, the pinned recovery guard must be armed
        # BEFORE the latch engages, or the foreground rerun session is dropped
        # by the latch's own DROP.
        begin = function_body(source, "begin_data_deployment_withdrawal_before_mutation")
        self.assertIn("arm_node_ssh_recovery_guard", begin)
        self.assertLess(
            begin.index("arm_node_ssh_recovery_guard"),
            begin.index("wins-node-local-serving rotate-serving"),
        )
        self.assertLess(
            begin.index("arm_node_ssh_recovery_guard"),
            begin.index("wins-node-local-serving disable"),
        )
        # R25 R2-H1: the guard the previous release left on the node dies on a
        # receipt for other installer bytes, so this installer's own guard goes
        # on after the hub withdrawal and before the pin and the latch.
        upgrade = "( set -e; write_node_ssh_recovery_guard )"
        self.assertIn(upgrade, begin)
        self.assertLess(begin.index("/deployment/withdraw"), begin.index(upgrade))
        self.assertLess(begin.index(upgrade), begin.index("arm_node_ssh_recovery_guard ||"))

        # FIX-6a downstream coherence: every direct-source pinning consumer
        # must SKIP (never error, never pin a loopback address) when the
        # deployment session arrives through the management tunnel. The
        # latch-risk gate in begin_ stands down too: tunnel packets enter
        # via lo and are RETURNed by the disabled chain's first rule.
        self.assertIn("! deployment_session_source_is_loopback", begin)
        self.assertIn("if deployment_session_source_is_loopback; then", arm_wrapper)
        self.assertLess(
            arm_wrapper.index("deployment_session_source_is_loopback"),
            arm_wrapper.index("wins-node-ssh-recovery-guard status"),
        )
        close_gate = function_body(
            source, "wins_require_ssh_recovery_guard_before_close"
        )
        self.assertIn("if deployment_session_source_is_loopback; then", close_gate)
        self.assertLess(
            close_gate.index("deployment_session_source_is_loopback"),
            close_gate.index("wins-node-ssh-recovery-guard status"),
        )
        self.assertIn("! deployment_session_source_is_loopback", bootstrap_fn)
        postflight = function_body(source, "postflight_data_plane")
        self.assertEqual(2, postflight.count("deployment_session_source_is_loopback"))
        self.assertEqual(2, postflight.count("unconfirmed)"))
        self.assertIn(
            "if deployment_session_source_is_loopback; then recovery_synced=1; break; fi",
            main,
        )
        # A run with no SSH_CONNECTION (console, cloud-init, detached rerun)
        # arms no pin, so every consumer of the unconfirmed state stands down
        # for it exactly as for a loopback source.
        self.assertIn('if [[ -z "${SSH_CONNECTION:-}" ]]; then', arm_wrapper)
        self.assertLess(
            arm_wrapper.index('if [[ -z "${SSH_CONNECTION:-}" ]]; then'),
            arm_wrapper.index("wins-node-ssh-recovery-guard arm"),
        )
        self.assertIn('[[ -z "${SSH_CONNECTION:-}" && "${state}" == unconfirmed ]] && return 0', close_gate)
        self.assertEqual(2, postflight.count('|| [[ -z "${SSH_CONNECTION:-}" ]] || {'))
        self.assertIn(
            'if [[ -z "${SSH_CONNECTION:-}" ]]; then recovery_synced=1; break; fi',
            main,
        )

        timer = source[source.index("timer_file=/etc/systemd/system/wins-node-ssh-recovery-guard.timer") :]
        for required in (
            "OnBootSec=5s",
            "OnUnitActiveSec=30s",
            "AccuracySec=1s",
            "RandomizedDelaySec=0",
            "systemctl enable --now wins-node-ssh-recovery-guard.timer",
        ):
            self.assertIn(required, timer)
        guard = heredoc(source, "WINS_NODE_SSH_RECOVERY_GUARD")
        check = function_body(guard, "check_guard")
        self.assertIn("verify_recovery_fully_closed", check)
        self.assertLess(
            check.index("verify_recovery_fully_closed"),
            check.index('if [[ -e "${CONFIRMED_FILE}"'),
        )

    def test_current_contract(self) -> None:
        self.assert_contract(DATA.read_text(encoding="utf-8"))

    def test_mutation_controls_turn_red(self) -> None:
        source = DATA.read_text(encoding="utf-8")
        mutations = (
            source.replace("ipt -A WINVPN-INPUT -j WINVPN-SSH-RECOVERY", "", 1),
            source.replace(
                "ipt -A WINVPN-INPUT -j WINVPN-SSH-RECOVERY\n  ipt -A WINVPN-INPUT -j WINVPN-LOCAL-SERVING",
                "ipt -A WINVPN-INPUT -j WINVPN-LOCAL-SERVING\n  ipt -A WINVPN-INPUT -j WINVPN-SSH-RECOVERY",
                1,
            ),
            source.replace("wins_require_ssh_recovery_guard_before_close || return 1", "", 1),
            source.replace('|| -e "${NODE_LOCAL_SERVING_LATCH}" || -L "${NODE_LOCAL_SERVING_LATCH}"', "", 1),
            source.replace(
                "    verify_recovery_fully_closed\n"
                '    if [[ -e "${CONFIRMED_FILE}" || -L "${CONFIRMED_FILE}" ]]; then',
                '    if [[ -e "${CONFIRMED_FILE}" || -L "${CONFIRMED_FILE}" ]]; then',
                1,
            ),
            # FIX-1 mutation: dropping the tunnel-flag restore resurrects the
            # node.env clobber that stranded Germany.
            source.replace(
                'if [[ "${NODE_MANAGEMENT_TUNNEL_ENABLED_REQUESTED_SET}" == "x" ]]; then\n'
                '  NODE_MANAGEMENT_TUNNEL_ENABLED="${NODE_MANAGEMENT_TUNNEL_ENABLED_REQUESTED}"\n'
                "fi\n",
                "",
                1,
            ),
            # FIX-2 mutation: arming after the bootstrap commit again.
            source.replace(
                "  arm_node_ssh_recovery_guard\n"
                "  # FIX-3: open the abort-rollback window immediately before the first -P INPUT\n"
                "  # DROP commit; it closes again once postflight has passed.\n"
                "  deploy_firewall_rollback_arm\n"
                "  apply_bootstrap_firewall\n",
                "  apply_bootstrap_firewall\n"
                "  arm_node_ssh_recovery_guard\n"
                "  deploy_firewall_rollback_arm\n",
                1,
            ),
            # FIX-6a mutation: the preflight loopback exemption is removed
            # (unconditional ':' reject returns and re-locks the tunnel-based
            # rerun/resume path).
            source.replace(
                'elif [[ "${ssh_source}" == *:* ]]; then',
                'if [[ "${ssh_source}" == *:* ]]; then',
                1,
            ),
            # FIX-6a mutation: the arm wrapper no longer skips loopback
            # (management-tunnel) sessions, so the guard would die on a
            # non-globally-routable source mid-deploy.
            source.replace(
                "  if deployment_session_source_is_loopback; then\n"
                '    log "Deployment session arrives through the management tunnel (loopback SSH source); skipping the direct-source SSH recovery pin: the tunnel is the recovery path."\n'
                "    return 0\n"
                "  fi\n",
                "",
                1,
            ),
            # R25 mutations: a detached run (no SSH_CONNECTION) is no longer
            # skipped by the arm wrapper, the close gate, or the recovery wait.
            source.replace(
                '      if [[ -z "${SSH_CONNECTION:-}" ]]; then\n'
                '        log "No SSH_CONNECTION (console, cloud-init or detached run);',
                '      if false; then\n'
                '        log "No SSH_CONNECTION (console, cloud-init or detached run);',
                1,
            ),
            source.replace(
                '      [[ -z "${SSH_CONNECTION:-}" && "${state}" == unconfirmed ]] && return 0\n',
                "",
                1,
            ),
            source.replace(
                '        if [[ -z "${SSH_CONNECTION:-}" ]]; then recovery_synced=1; break; fi\n',
                "",
                1,
            ),
            # R25 R2-H1 mutation: the pre-latch pin asks the deployed guard again.
            source.replace("      ( set -e; write_node_ssh_recovery_guard )\n", "", 1),
            # B0 mutation: a firewall-committing call sneaks ahead of the arm,
            # opening a window where the first -P INPUT DROP commit could
            # strand the session with nothing pinned.
            source.replace(
                "  setup_sysctl\n",
                "  setup_sysctl\n  apply_bootstrap_firewall\n",
                1,
            ),
        )
        for index, mutated in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaises(AssertionError):
                    self.assert_contract(mutated)

    def test_confirm_close_order_and_single_lock_contract(self) -> None:
        source = DATA.read_text(encoding="utf-8")
        guard = heredoc(source, "WINS_NODE_SSH_RECOVERY_GUARD")
        confirm = function_body(guard, "confirm_guard")
        self.assertLess(confirm.index("close_recovery_rule"), confirm.index("atomic_write_file"))
        self.assertLess(confirm.index("atomic_write_file"), confirm.index('rm -f -- "${STATE_FILE}"'))
        # S4 (design 2.7): every command except status takes fd 7 straight
        # after the guard lock, before the dispatcher's case.
        self.assertEqual(
            1, guard.count('lock_guard\nif [[ "${1:-}" != status ]] && ! guard_hold_firewall_lock; then\n')
        )
        self.assertIn("flock -x 9", guard)
        self.assertIn('"${IPTABLES_BIN}" -w 10 -I INPUT 1 -j "${CHAIN}"', guard)
        self.assertIn("verify_recovery_base_jump", guard)


class EdgeBootstrapOverrideTests(unittest.TestCase):
    """Runtime proof (FIX-1) that caller-inline bootstrap overrides survive
    `source node.env` inside the generated wins-edge-hardening script.

    The generated script's variable-resolution preamble (everything before the
    first WG_PORT default) is extracted from the production installer and
    executed against a synthetic root-owned node.env. No firewall command,
    network call, or server is involved.
    """

    def run_preamble(
        self, source: str, node_env: str, inline: dict[str, str]
    ) -> dict[str, str]:
        edge = heredoc(source, "WINS_EDGE_EOF")
        marker = 'WG_PORT="${WG_PORT:-9110}"'
        preamble = edge[: edge.index(marker)]
        preamble += (
            "printf 'TUNNEL=%s\\nHUB=%s\\nIDS=%s\\nADMISSION=%s\\n' "
            '"${NODE_MANAGEMENT_TUNNEL_ENABLED}" "${HUB_IP}" '
            '"${INSTALL_DATA_IDS_IPS-unset}" "${PUBLIC_VPN_INGRESS_ADMISSION}"\n'
        )
        with tempfile.TemporaryDirectory(prefix="wins-edge-preamble-") as temp:
            root = pathlib.Path(temp)
            env_file = root / "node.env"
            env_file.write_text(node_env, encoding="utf-8")
            script = root / "preamble.sh"
            script.write_text(preamble, encoding="utf-8")
            environment = os.environ.copy()
            for name in (
                "NODE_ENV_FILE",
                "NODE_MANAGEMENT_TUNNEL_ENABLED",
                "IONOS_HUB_IP",
                "INSTALL_DATA_IDS_IPS",
                "PUBLIC_VPN_INGRESS_ADMISSION",
                "HUB_REGISTER_URL",
                "HUB_REGISTER_URL_FALLBACK",
            ):
                environment.pop(name, None)
            environment["NODE_ENV_FILE"] = str(env_file)
            environment["PUBLIC_VPN_INGRESS_ADMISSION_FILE"] = str(
                root / "absent-admission.env"
            )
            environment.update(inline)
            result = subprocess.run(
                ["bash", str(script)],
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stdout)
            return dict(
                line.split("=", 1) for line in result.stdout.strip().splitlines()
            )

    def test_bootstrap_inline_overrides_survive_node_env(self) -> None:
        # The demonstrated Germany clobber: node.env always persists
        # NODE_MANAGEMENT_TUNNEL_ENABLED="1"; the bootstrap caller passes
        # tunnel=0 + the deployment source inline. Without the _REQUESTED
        # preservation the flag reads back 1, HUB_IP stays empty and the
        # deploy-source tcp/22 accept is never emitted.
        resolved = self.run_preamble(
            DATA.read_text(encoding="utf-8"),
            'NODE_MANAGEMENT_TUNNEL_ENABLED="1"\n',
            {
                "PUBLIC_VPN_INGRESS_ADMISSION": "0",
                "INSTALL_DATA_IDS_IPS": "0",
                "NODE_MANAGEMENT_TUNNEL_ENABLED": "0",
                "IONOS_HUB_IP": "203.0.113.7",
            },
        )
        self.assertEqual("0", resolved["TUNNEL"])
        self.assertEqual("203.0.113.7", resolved["HUB"])
        self.assertEqual("0", resolved["IDS"])
        self.assertEqual("0", resolved["ADMISSION"])

    def test_unattended_timer_path_still_reads_persisted_values(self) -> None:
        # No caller-inline values: the systemd/timer path must keep resolving
        # everything from node.env exactly as before the fix.
        resolved = self.run_preamble(
            DATA.read_text(encoding="utf-8"),
            'NODE_MANAGEMENT_TUNNEL_ENABLED="1"\n',
            {},
        )
        self.assertEqual("1", resolved["TUNNEL"])
        self.assertEqual("", resolved["HUB"])
        self.assertEqual("unset", resolved["IDS"])
        self.assertEqual("0", resolved["ADMISSION"])

    def test_legacy_node_env_hub_ip_is_preserved_and_overridable(self) -> None:
        source = DATA.read_text(encoding="utf-8")
        legacy_env = (
            'NODE_MANAGEMENT_TUNNEL_ENABLED="0"\n'
            'IONOS_HUB_IP="198.51.100.7"\n'
        )
        persisted = self.run_preamble(source, legacy_env, {})
        self.assertEqual("0", persisted["TUNNEL"])
        self.assertEqual("198.51.100.7", persisted["HUB"])
        overridden = self.run_preamble(
            source,
            legacy_env,
            {
                "NODE_MANAGEMENT_TUNNEL_ENABLED": "0",
                "IONOS_HUB_IP": "203.0.113.9",
            },
        )
        self.assertEqual("0", overridden["TUNNEL"])
        self.assertEqual("203.0.113.9", overridden["HUB"])


class PreflightFix6aLoopbackTests(unittest.TestCase):
    """Runtime proof (FIX-6/FIX-6a) of the preflight SSH_CONNECTION triage.

    Executes the production helper plus the exact preflight block against
    synthetic SSH_CONNECTION values. Loopback sources are management-tunnel
    ingress (the local cloudflared proxy) and must proceed; genuine external
    IPv6 direct sessions must be rejected loudly BEFORE any mutation; bare
    IPv4 and detached runs proceed unchanged. No network, no firewall.
    """

    def run_block(self, ssh_connection: str | None) -> subprocess.CompletedProcess[str]:
        source = DATA.read_text(encoding="utf-8")
        helper = function_body(source, "deployment_session_source_is_loopback")
        preflight = function_body(source, "preflight_data_plane")
        start = preflight.index('if [[ -n "${SSH_CONNECTION:-}" ]]; then')
        end = preflight.index(
            'if [[ "${NODE_MANAGEMENT_TUNNEL_ENABLED:-$NODE_MANAGEMENT_TUNNEL_ENABLED_DEFAULT}" == "1" ]]; then'
        )
        script = (
            "set -Eeuo pipefail\n"
            "err() { printf 'ERR:%s\\n' \"$*\" >&2; }\n"
            "log() { printf 'LOG:%s\\n' \"$*\"; }\n"
            + helper
            + "\n"
            + preflight[start:end]
            + "\necho PROCEEDED\n"
        )
        environment = os.environ.copy()
        environment.pop("SSH_CONNECTION", None)
        if ssh_connection is not None:
            environment["SSH_CONNECTION"] = ssh_connection
        with tempfile.TemporaryDirectory(prefix="wins-fix6a-preflight-") as temp:
            path = pathlib.Path(temp) / "preflight-block.sh"
            path.write_text(script, encoding="utf-8")
            return subprocess.run(
                ["bash", str(path)],
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )

    def test_loopback_tunnel_ingress_proceeds_without_reject(self) -> None:
        for source_ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
            with self.subTest(source=source_ip):
                result = self.run_block(f"{source_ip} 51000 10.0.0.5 22")
                self.assertEqual(0, result.returncode, result.stdout)
                self.assertIn("PROCEEDED", result.stdout)
                self.assertIn("management-tunnel proxy", result.stdout)
                self.assertNotIn("Reconnect over IPv4", result.stdout)

    def test_external_ipv6_direct_session_is_rejected_before_mutation(self) -> None:
        for source_ip in ("2001:db8::5", "fe80::1", "2001:db8:0:1::abcd%eth0"):
            with self.subTest(source=source_ip):
                result = self.run_block(f"{source_ip} 51000 2001:db8::9 22")
                self.assertEqual(1, result.returncode, result.stdout)
                self.assertIn("Reconnect over IPv4 (ssh -4)", result.stdout)
                self.assertNotIn("PROCEEDED", result.stdout)

    def test_bare_ipv4_and_detached_sessions_proceed(self) -> None:
        for connection in ("203.0.113.7 51000 203.0.113.9 22", None):
            with self.subTest(connection=connection):
                result = self.run_block(connection)
                self.assertEqual(0, result.returncode, result.stdout)
                self.assertIn("PROCEEDED", result.stdout)
                self.assertNotIn("management-tunnel proxy", result.stdout)


class BootstrapSourceSelectionTests(unittest.TestCase):
    """Runtime proof (FIX-6a) that apply_bootstrap_firewall pins ONLY a bare
    external IPv4 deploy source and takes the tunnel-mode/no-direct-exception
    path for loopback (management-tunnel) and detached sessions.

    The production function is extracted verbatim; only the absolute
    wins-edge-hardening path is redirected to a recorder stub that captures
    the inline environment it would have received. No firewall, no network.
    """

    def run_bootstrap(
        self, ssh_connection: str | None
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
        source = DATA.read_text(encoding="utf-8")
        helper = function_body(source, "deployment_session_source_is_loopback")
        bootstrap = function_body(source, "apply_bootstrap_firewall")
        edge_path = "/usr/local/bin/wins-edge-hardening"
        self.assertIn(edge_path, bootstrap)
        with tempfile.TemporaryDirectory(prefix="wins-fix6a-bootstrap-") as temp:
            root = pathlib.Path(temp)
            recorder_out = root / "edge-env.txt"
            write_executable(
                root / "wins-edge-hardening",
                "#!/bin/bash\n"
                "env | grep -E '^(PUBLIC_VPN_INGRESS_ADMISSION|INSTALL_DATA_IDS_IPS"
                "|NODE_MANAGEMENT_TUNNEL_ENABLED|IONOS_HUB_IP)=' | sort"
                ' > "${RECORDER_OUT:?}"\n',
            )
            write_executable(root / "systemctl", "#!/bin/bash\nexit 0\n")
            bootstrap = bootstrap.replace(edge_path, str(root / "wins-edge-hardening"))
            script = (
                "set -Eeuo pipefail\n"
                "log() { printf 'LOG:%s\\n' \"$*\"; }\n"
                "write_edge_hardening_script() { :; }\n"
                "set_public_vpn_ingress_admission() { :; }\n"
                + helper
                + "\n"
                + bootstrap
                + "\napply_bootstrap_firewall\n"
            )
            path = root / "bootstrap.sh"
            path.write_text(script, encoding="utf-8")
            environment = os.environ.copy()
            environment.pop("SSH_CONNECTION", None)
            if ssh_connection is not None:
                environment["SSH_CONNECTION"] = ssh_connection
            environment["RECORDER_OUT"] = str(recorder_out)
            environment["PATH"] = f"{root}:{os.environ['PATH']}"
            result = subprocess.run(
                ["bash", str(path)],
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stdout)
            recorded = dict(
                line.split("=", 1)
                for line in recorder_out.read_text(encoding="utf-8").strip().splitlines()
            )
            return result, recorded

    def test_bare_ipv4_session_pins_the_deploy_source(self) -> None:
        _, recorded = self.run_bootstrap("203.0.113.7 51000 203.0.113.9 22")
        self.assertEqual("203.0.113.7", recorded["IONOS_HUB_IP"])
        self.assertEqual("0", recorded["NODE_MANAGEMENT_TUNNEL_ENABLED"])
        self.assertEqual("0", recorded["PUBLIC_VPN_INGRESS_ADMISSION"])
        self.assertEqual("0", recorded["INSTALL_DATA_IDS_IPS"])

    def test_loopback_session_never_pins_a_direct_exception(self) -> None:
        # 127.0.0.1 matches the bare-IPv4 regex, so without the FIX-6a skip
        # the bootstrap would pin a useless (guard-rejected) loopback accept;
        # ::1/::ffff:127.0.0.1 must behave identically.
        for source_ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
            with self.subTest(source=source_ip):
                _, recorded = self.run_bootstrap(f"{source_ip} 51000 10.0.0.5 22")
                self.assertNotIn("IONOS_HUB_IP", recorded)
                self.assertNotIn("NODE_MANAGEMENT_TUNNEL_ENABLED", recorded)
                self.assertEqual("0", recorded["PUBLIC_VPN_INGRESS_ADMISSION"])
                self.assertEqual("0", recorded["INSTALL_DATA_IDS_IPS"])

    def test_detached_session_takes_the_no_exception_path(self) -> None:
        _, recorded = self.run_bootstrap(None)
        self.assertNotIn("IONOS_HUB_IP", recorded)
        self.assertNotIn("NODE_MANAGEMENT_TUNNEL_ENABLED", recorded)


class ArmWrapperLoopbackTests(unittest.TestCase):
    """Runtime proof (FIX-6a) that the installer-side arm wrapper skips the
    direct-source pin for management-tunnel (loopback) sessions instead of
    letting the production guard binary die on a non-globally-routable source,
    while a bare external IPv4 session still arms the exact /32 pin."""

    def run_wrapper(
        self,
        node: FakeNode,
        function: str = "arm_node_ssh_recovery_guard",
        ssh_connection: str | None = None,
        detached: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        source = DATA.read_text(encoding="utf-8")
        helper = function_body(source, "deployment_session_source_is_loopback")
        wrapper = function_body(source, function)
        guard_path = "/usr/local/sbin/wins-node-ssh-recovery-guard"
        self.assertIn(guard_path, wrapper)
        wrapper = wrapper.replace(guard_path, str(node.guard))
        script = (
            "set -Eeuo pipefail\n"
            "log() { printf 'LOG:%s\\n' \"$*\"; }\n"
            "err() { printf 'ERR:%s\\n' \"$*\" >&2; }\n"
            "NODE_MANAGEMENT_TUNNEL_ENABLED_DEFAULT=1\n"
            "NODE_MANAGEMENT_TUNNEL_ENABLED=1\n"
            'HUB_IP=""\n'
            f'NODE_SSH_RECOVERY_STATE_DIR_DEFAULT="{node.state}"\n'
            "NODE_SSH_RECOVERY_TIMEOUT_SECONDS_DEFAULT=900\n"
            f'data_plane_installer_path() {{ printf \'%s\' "{node.installer}"; }}\n'
            + helper
            + "\n"
            + wrapper
            + f"\n{function}\n"
        )
        env = node.env()
        if detached:
            env.pop("SSH_CONNECTION")
        elif ssh_connection is not None:
            env["SSH_CONNECTION"] = ssh_connection
        with tempfile.TemporaryDirectory(prefix="wins-fix6a-arm-wrapper-") as temp:
            path = pathlib.Path(temp) / "wrapper.sh"
            path.write_text(script, encoding="utf-8")
            return subprocess.run(
                ["bash", str(path)],
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )

    def test_loopback_session_skips_the_pin_without_error(self) -> None:
        for source_ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
            with self.subTest(source=source_ip):
                temporary = tempfile.TemporaryDirectory(prefix="wins-fix6a-node-")
                with temporary:
                    node = FakeNode(pathlib.Path(temporary.name), source_ip)
                    result = self.run_wrapper(node)
                    self.assertEqual(0, result.returncode, result.stdout)
                    self.assertIn("management tunnel", result.stdout)
                    self.assertFalse((node.state / "armed.env").exists())
                    self.assertFalse((node.fw / "WINVPN-SSH-RECOVERY").exists())

    def test_external_ipv4_session_still_arms_the_exact_pin(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="wins-fix6a-node-v4-")
        with temporary:
            node = FakeNode(pathlib.Path(temporary.name), "8.8.8.8")
            result = self.run_wrapper(node)
            self.assertEqual(0, result.returncode, result.stdout)
            armed = (node.state / "armed.env").read_text(encoding="utf-8")
            self.assertIn("SOURCE_IPV4=8.8.8.8", armed)
            self.assertEqual(
                "-A WINVPN-SSH-RECOVERY -s 8.8.8.8/32 -p tcp -m tcp --dport 22 "
                "-j ACCEPT\n",
                (node.fw / "WINVPN-SSH-RECOVERY").read_text(encoding="utf-8"),
            )

    GATE = "wins_require_ssh_recovery_guard_before_close"
    REMOTE = "8.8.8.8 50000 203.0.113.9 22"

    def test_detached_session_without_ssh_connection_skips_the_pin_without_error(self) -> None:
        # Three nodes, 2026-10-19: a detached rerun after the package reboot
        # pause has no SSH_CONNECTION, the guard's arm died on it ('must contain
        # exactly four fields') and the deploy exited 1.
        with tempfile.TemporaryDirectory(prefix="wins-r25-detached-") as temporary:
            node = FakeNode(pathlib.Path(temporary), "8.8.8.8")
            result = self.run_wrapper(node, detached=True)
            self.assertEqual(0, result.returncode, result.stdout)
            self.assertIn("No SSH_CONNECTION", result.stdout)
            self.assertNotIn("exactly four fields", result.stdout)
            self.assertFalse((node.state / "armed.env").exists())
            self.assertFalse((node.fw / "WINVPN-SSH-RECOVERY").exists())

    def test_detached_rerun_keeps_a_pin_that_is_already_armed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-r25-detached-armed-") as temporary:
            node = FakeNode(pathlib.Path(temporary), "8.8.8.8")
            self.assertEqual(0, self.run_wrapper(node).returncode)
            armed = (node.state / "armed.env").read_bytes()
            rule = (node.fw / "WINVPN-SSH-RECOVERY").read_bytes()
            result = self.run_wrapper(node, detached=True)
            self.assertEqual(0, result.returncode, result.stdout)
            self.assertIn("remains armed", result.stdout)
            self.assertEqual(armed, (node.state / "armed.env").read_bytes())
            self.assertEqual(rule, (node.fw / "WINVPN-SSH-RECOVERY").read_bytes())

    def test_a_set_but_malformed_ssh_connection_is_never_skipped(self) -> None:
        for value in ("8.8.8.8", " ", "8.8.8.8 50000 203.0.113.9"):
            with self.subTest(value=value):
                with tempfile.TemporaryDirectory(prefix="wins-r25-malformed-") as temporary:
                    node = FakeNode(pathlib.Path(temporary), "8.8.8.8")
                    result = self.run_wrapper(node, ssh_connection=value)
                    self.assertNotEqual(0, result.returncode, result.stdout)
                    self.assertIn("exactly four fields", result.stdout)
                    self.assertNotIn("No SSH_CONNECTION", result.stdout)
                    self.assertFalse((node.state / "armed.env").exists())

    def test_close_gate_lets_a_detached_run_close_without_a_pin(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-r25-gate-detached-") as temporary:
            node = FakeNode(pathlib.Path(temporary), "8.8.8.8")
            result = self.run_wrapper(node, self.GATE, detached=True)
            self.assertEqual(0, result.returncode, result.stdout)
            self.assertNotIn("Refusing", result.stdout)

    def test_close_gate_still_refuses_a_real_source_without_a_pin(self) -> None:
        # Never weaken the pin for a real remote source.
        for value in (self.REMOTE, "8.8.8.8", "2001:db8::1 50000 2001:db8::2 22"):
            with self.subTest(value=value):
                with tempfile.TemporaryDirectory(prefix="wins-r25-gate-remote-") as temporary:
                    node = FakeNode(pathlib.Path(temporary), "8.8.8.8")
                    result = self.run_wrapper(node, self.GATE, ssh_connection=value)
                    self.assertNotEqual(0, result.returncode, result.stdout)
                    self.assertIn("Refusing to close the temporary deployment-source SSH exception", result.stdout)

    def test_close_gate_accepts_an_armed_pin_with_or_without_ssh_connection(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-r25-gate-armed-") as temporary:
            node = FakeNode(pathlib.Path(temporary), "8.8.8.8")
            self.assertEqual(0, self.run_wrapper(node).returncode)
            for kwargs in ({"detached": True}, {"ssh_connection": self.REMOTE}):
                with self.subTest(**kwargs):
                    result = self.run_wrapper(node, self.GATE, **kwargs)
                    self.assertEqual(0, result.returncode, result.stdout)

    def test_close_gate_refuses_an_unsafe_guard_state_even_when_detached(self) -> None:
        # Only 'unconfirmed' is relaxed. An armed pin whose installer bytes no
        # longer match makes status die, and that still refuses.
        with tempfile.TemporaryDirectory(prefix="wins-r25-gate-unsafe-") as temporary:
            node = FakeNode(pathlib.Path(temporary), "8.8.8.8")
            self.assertEqual(0, self.run_wrapper(node).returncode)
            node.installer.write_text("#!/bin/bash\necho changed\n", encoding="utf-8")
            result = self.run_wrapper(node, self.GATE, detached=True)
            self.assertNotEqual(0, result.returncode, result.stdout)
            self.assertIn("Refusing to close the temporary deployment-source SSH exception", result.stdout)

    # ---- R25 H: a rerun of newer installer bytes on a node with an external confirm ----

    def confirmed_node(self, directory: str) -> FakeNode:
        node = FakeNode(pathlib.Path(directory), "8.8.8.8")
        self.assertEqual(0, node.run_guard("arm").returncode)
        self.assertEqual(0, node.run_guard("confirm").returncode)
        self.assertEqual("confirmed", node.run_guard("status").stdout.strip())
        return node

    @staticmethod
    def upgrade(node: FakeNode) -> str:
        node.installer.write_text("#!/bin/bash\necho newer certified installer\n", encoding="utf-8")
        return hashlib.sha256(node.installer.read_bytes()).hexdigest()

    def test_a_rerun_of_newer_installer_bytes_re_arms_after_an_external_confirm(self) -> None:
        # The receipt names the installer that was confirmed. A newer certified
        # installer is not that installer, and the guard's own arm replaces the
        # receipt; the wrapper's status check used to die on the mismatch first.
        with tempfile.TemporaryDirectory(prefix="wins-r25-h-") as directory:
            node = self.confirmed_node(directory)
            digest = self.upgrade(node)
            result = self.run_wrapper(node)
            self.assertEqual(0, result.returncode, result.stdout)
            armed = (node.state / "armed.env").read_text(encoding="utf-8")
            self.assertIn("SOURCE_IPV4=8.8.8.8\n", armed)
            self.assertIn(f"INSTALLER_SHA256={digest}\n", armed)
            self.assertFalse((node.state / "confirmed.env").exists(), "the old receipt is replaced, not kept")
            self.assertIn("8.8.8.8/32", (node.fw / "WINVPN-SSH-RECOVERY").read_text(encoding="utf-8"))
            self.assertEqual("armed", node.run_guard("status").stdout.strip())

    def test_the_same_rerun_without_ssh_connection_stands_down_and_stays_unconfirmed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-r25-h-detached-") as directory:
            node = self.confirmed_node(directory)
            self.upgrade(node)
            result = self.run_wrapper(node, detached=True)
            self.assertEqual(0, result.returncode, result.stdout)
            self.assertIn("No SSH_CONNECTION", result.stdout)
            self.assertFalse((node.state / "armed.env").exists())
            status = node.run_guard("status")
            self.assertEqual(("unconfirmed", 3), (status.stdout.strip(), status.returncode))
            self.assertEqual(0, node.run_guard("check").returncode, "the 30 s timer must not die on the old receipt")
            self.assertEqual("", (node.fw / "WINVPN-SSH-RECOVERY").read_text(encoding="utf-8"))
            self.assertEqual(
                0, self.run_wrapper(node, self.GATE, detached=True).returncode,
                "and the close gate treats it as the unconfirmed state it is")

    def test_an_old_receipt_confirms_nothing_for_the_new_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-r25-h-nothing-") as directory:
            node = self.confirmed_node(directory)
            self.upgrade(node)
            self.assertNotEqual(0, node.run_guard("confirm").returncode, "there is no armed pin to confirm")
            gate = self.run_wrapper(node, self.GATE, ssh_connection=self.REMOTE)
            self.assertNotEqual(0, gate.returncode, "a real source still needs an armed or confirmed pin to close")

    def test_an_unsafe_guard_state_still_refuses_a_rerun_of_newer_bytes(self) -> None:
        receipt = "VERSION=1\nINSTALLER_SHA256={d}\nTUNNEL_ID={t}\nCONFIRMED_BOOT_ID={b}\nCONFIRMED_EPOCH=1\n"
        digest = "ab" * 32
        tunnel = "22222222-2222-4222-8222-222222222222"
        boot = "11111111-1111-4111-8111-111111111111"
        cases = {
            "receipt with an extra line": receipt.format(d=digest, t=tunnel, b=boot) + "EXTRA=1\n",
            "receipt with an unterminated extra line": receipt.format(d=digest, t=tunnel, b=boot) + "EXTRA=1",
            "receipt with a missing key": receipt.format(d=digest, t=tunnel, b=boot).replace("CONFIRMED_EPOCH=1\n", "OTHER=1\n"),
            "receipt of another version": receipt.format(d=digest, t=tunnel, b=boot).replace("VERSION=1", "VERSION=2"),
            "receipt with a malformed digest": receipt.format(d="xyz", t=tunnel, b=boot),
            "receipt with a malformed boot id": receipt.format(d=digest, t=tunnel, b="not-a-boot-id"),
            "receipt with a malformed epoch": receipt.format(d=digest, t=tunnel, b=boot).replace("EPOCH=1", "EPOCH=soon"),
        }
        for label, content in cases.items():
            with self.subTest(label), tempfile.TemporaryDirectory(prefix="wins-r25-h-corrupt-") as directory:
                node = self.confirmed_node(directory)
                (node.state / "confirmed.env").write_text(content, encoding="utf-8")
                self.upgrade(node)
                for kwargs in ({}, {"detached": True}):
                    result = self.run_wrapper(node, **kwargs)
                    self.assertNotEqual(0, result.returncode, result.stdout)
                    self.assertIn("unsafe", result.stdout)
                self.assertFalse((node.state / "armed.env").exists())
                self.assertEqual(content, (node.state / "confirmed.env").read_text(encoding="utf-8"))
        # An old receipt beside an open recovery chain is not the closed posture it stands for.
        with tempfile.TemporaryDirectory(prefix="wins-r25-h-open-") as directory:
            node = self.confirmed_node(directory)
            self.upgrade(node)
            (node.fw / "WINVPN-SSH-RECOVERY").write_text(
                "-A WINVPN-SSH-RECOVERY -s 8.8.8.8/32 -p tcp -m tcp --dport 22 -j ACCEPT\n", encoding="utf-8")
            result = self.run_wrapper(node)
            self.assertNotEqual(0, result.returncode, result.stdout)
            self.assertFalse((node.state / "armed.env").exists())
            self.assertNotEqual(0, node.run_guard("check").returncode)
        # A receipt that names the current bytes is judged exactly as before.
        with tempfile.TemporaryDirectory(prefix="wins-r25-h-same-") as directory:
            node = self.confirmed_node(directory)
            (node.fw / "WINVPN-SSH-RECOVERY").write_text(
                "-A WINVPN-SSH-RECOVERY -s 8.8.8.8/32 -p tcp -m tcp --dport 22 -j ACCEPT\n", encoding="utf-8")
            self.assertNotEqual(0, node.run_guard("status").returncode)
            self.assertNotEqual(0, self.run_wrapper(node).returncode)

    def test_an_unterminated_extra_line_makes_a_receipt_of_the_current_bytes_unconfirmed(self) -> None:
        # wc -l counts newline bytes, so a sixth, unterminated record used to
        # leave the count at five and every lookup still succeeded.
        with tempfile.TemporaryDirectory(prefix="wins-r25-h-unterminated-") as directory:
            node = self.confirmed_node(directory)
            receipt = node.state / "confirmed.env"
            good = receipt.read_text(encoding="utf-8")
            self.assertEqual(5, good.count("\n"))
            receipt.write_text(good + "EXTRA=1", encoding="utf-8")
            status = node.run_guard("status")
            self.assertNotEqual(0, status.returncode, status.stdout)
            self.assertNotEqual("confirmed", status.stdout.strip())
            self.assertNotEqual(0, node.run_guard("check").returncode)
            self.assertNotEqual(0, self.run_wrapper(node, self.GATE, ssh_connection=self.REMOTE).returncode)

    def test_armed_and_fired_pins_of_older_bytes_and_a_corrupt_state_still_refuse(self) -> None:
        for label in ("armed", "fired", "corrupt"):
            with self.subTest(label), tempfile.TemporaryDirectory(prefix="wins-r25-h-pin-") as directory:
                node = FakeNode(pathlib.Path(directory), "8.8.8.8")
                self.assertEqual(0, node.run_guard("arm").returncode)
                if label == "fired":
                    node.boottime.write_text("131\n", encoding="utf-8")
                    self.assertEqual(0, node.run_guard("check").returncode)
                    self.assertIn("FIRED=1\n", (node.state / "armed.env").read_text(encoding="utf-8"))
                if label == "corrupt":
                    text = (node.state / "armed.env").read_text(encoding="utf-8")
                    (node.state / "armed.env").write_text(text.replace("SOURCE_IPV4=8.8.8.8", "SOURCE_IPV4=10.0.0.9"), encoding="utf-8")
                else:
                    # Same bytes: the wrapper keeps the pin and its deadline, as before.
                    result = self.run_wrapper(node, detached=True)
                    self.assertEqual(0, result.returncode, result.stdout)
                    self.assertIn(f"remains {label}", result.stdout)
                before = (node.state / "armed.env").read_bytes()
                self.upgrade(node)
                for kwargs in ({}, {"detached": True}):
                    result = self.run_wrapper(node, **kwargs)
                    self.assertNotEqual(0, result.returncode, result.stdout)
                    self.assertIn("unsafe", result.stdout)
                self.assertEqual(before, (node.state / "armed.env").read_bytes())
                self.assertNotEqual(0, node.run_guard("arm").returncode)


SHA256_OF = (
    "import hashlib,sys; "
    "print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())"
)
OLD_GUARD_SNAPSHOT = ROOT / "server" / "testdata" / "wins_node_ssh_recovery_guard.deployed_1aa8ba0.snapshot"
OLD_GUARD_SNAPSHOT_SHA256 = "d09bf2a38d52fbc44af05ed7d748ca83e01829189985b5869a34ad6081b26667"


class RerunWithdrawalGuardUpgradeTests(unittest.TestCase):
    """R25 R2-H1: begin_data_deployment_withdrawal_before_mutation pins a direct
    SSH rerun session BEFORE the serving latch engages, and it does so by asking
    the SSH recovery guard that is installed on the node. On a deployed node that
    is the guard the previous release wrote (the frozen snapshot below), which
    dies on a confirmed receipt for other installer bytes. The installer must put
    its own guard on the node, after the hub withdrawal and before the latch."""

    REMOTE = "8.8.8.8 50000 203.0.113.9 22"
    WITHDRAWAL_ID = "0123456789abcdef0123456789abcdef"

    def deployed_node(self, directory: str) -> FakeNode:
        node = FakeNode(pathlib.Path(directory), "8.8.8.8")
        snapshot = OLD_GUARD_SNAPSHOT.read_bytes()
        self.assertEqual(OLD_GUARD_SNAPSHOT_SHA256, hashlib.sha256(snapshot).hexdigest())
        write_executable(node.guard, FakeNode.portable_guard(snapshot.decode("utf-8")))
        self.assertEqual(0, node.run_guard("arm").returncode)
        self.assertEqual(0, node.run_guard("confirm").returncode)
        self.assertEqual("confirmed", node.run_guard("status").stdout.strip())
        # The live firewall already routes through the local-serving latch chain.
        (node.fw / "WINVPN-INPUT").write_text("-A WINVPN-INPUT -j WINVPN-LOCAL-SERVING\n", encoding="utf-8")
        write_executable(node.bin / "systemd-analyze", "#!/bin/bash\nexit \"${FAKE_ANALYZE_RC:-0}\"\n")
        write_executable(
            node.bin / "curl",
            "#!/bin/bash\ncat > /dev/null\n"
            f'printf \'WITHDRAWN guard_sha256=%s\\n\' "$({sys.executable} -c "{SHA256_OF}" "${{GUARD_PATH:?}}")" >> "${{TRACE:?}}"\n'
            f"printf '{{\"ok\":true,\"operator_enabled\":false,\"withdrawal_id\":\"{self.WITHDRAWAL_ID}\"}}'\n",
        )
        write_executable(
            node.bin / "local-serving-shim",
            "#!/bin/bash\n"
            "{\n"
            '  printf \'LATCH %s\\n\' "$1"\n'
            f'  printf \'  guard_sha256=%s\\n\' "$({sys.executable} -c "{SHA256_OF}" "${{GUARD_PATH:?}}")"\n'
            '  printf \'  armed_installer=%s\\n\' "$(sed -n \'s/^INSTALLER_SHA256=//p\' "${WINS_NODE_SSH_RECOVERY_STATE_DIR:?}/armed.env" 2>/dev/null)"\n'
            '  printf \'  armed_source=%s\\n\' "$(sed -n \'s/^SOURCE_IPV4=//p\' "${WINS_NODE_SSH_RECOVERY_STATE_DIR:?}/armed.env" 2>/dev/null)"\n'
            '} >> "${TRACE:?}"\n'
            'exec bash "${REAL_LOCAL_GUARD:?}" "$@"\n',
        )
        return node

    @staticmethod
    def newer_installer(node: FakeNode) -> str:
        node.installer.write_text("#!/bin/bash\necho newer certified installer\n", encoding="utf-8")
        return hashlib.sha256(node.installer.read_bytes()).hexdigest()

    @staticmethod
    def current_guard_bytes() -> bytes:
        production = DATA.read_text(encoding="utf-8")
        return FakeNode.portable_guard(heredoc(production, "WINS_NODE_SSH_RECOVERY_GUARD")).encode("utf-8")

    def run_withdrawal(
        self, node: FakeNode, ssh_connection: str | None = REMOTE, extra_env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        source = DATA.read_text(encoding="utf-8")
        guard_text = heredoc(source, "WINS_NODE_SSH_RECOVERY_GUARD")
        writer = function_body(source, "write_node_ssh_recovery_guard")
        self.assertIn(guard_text[:-1], writer)
        writer = writer.replace(guard_text[:-1], "@@GUARD@@")
        functions = "\n".join(
            [
                function_body(source, "deployment_session_source_is_loopback"),
                function_body(source, "arm_node_ssh_recovery_guard"),
                writer,
                function_body(source, "begin_data_deployment_withdrawal_before_mutation"),
            ]
        )
        units = node.root / "units"
        units.mkdir(exist_ok=True)
        for production_path, test_path in (
            ("/usr/local/sbin/wins-node-ssh-recovery-guard", str(node.guard)),
            ("/usr/local/sbin/wins-node-local-serving", str(node.bin / "local-serving-shim")),
            ("/etc/systemd/system/", f"{units}/"),
            ("/etc/winsvpn/local-serving.disabled", str(node.latch)),
        ):
            functions = functions.replace(production_path, test_path)
        functions = functions.replace("@@GUARD@@", FakeNode.portable_guard(guard_text)[:-1])
        script = (
            "set -Eeuo pipefail\n"
            "log() { printf 'LOG:%s\\n' \"$*\"; }\n"
            "warn() { printf 'WARN:%s\\n' \"$*\" >&2; }\n"
            "err() { printf 'ERR:%s\\n' \"$*\" >&2; }\n"
            "NODE_MANAGEMENT_TUNNEL_ENABLED_DEFAULT=1\n"
            "NODE_MANAGEMENT_TUNNEL_ENABLED=1\n"
            'HUB_IP=""\n'
            f'NODE_ENV_FILE="{node.node_env}"\n'
            "NODE_SLUG=de-1\n"
            "NODE_TOKEN=node-token\n"
            "HUB_API_BASE=https://hub.invalid\n"
            f'NODE_SSH_RECOVERY_STATE_DIR_DEFAULT="{node.state}"\n'
            "NODE_SSH_RECOVERY_TIMEOUT_SECONDS_DEFAULT=900\n"
            f'data_plane_installer_path() {{ printf \'%s\' "{node.installer}"; }}\n'
            f'data_plane_installer_sha256() {{ "{sys.executable}" -c "{SHA256_OF}" "{node.installer}"; }}\n'
            "winn3_resume_repair_before_guard() { return 0; }\n"
            "winn3_prepend_shared_functions() { return 0; }\n"
            f"jq() {{ printf '%s\\n' {self.WITHDRAWAL_ID}; }}\n"
            + functions
            + "\nbegin_data_deployment_withdrawal_before_mutation\n"
            'echo "DONE rerun_active=${DATA_INSTALLER_RERUN_ACTIVE}"\n'
        )
        env = node.env()
        if ssh_connection is None:
            env.pop("SSH_CONNECTION")
        else:
            env["SSH_CONNECTION"] = ssh_connection
        env.update(
            {
                "TRACE": str(node.root / "trace.log"),
                "GUARD_PATH": str(node.guard),
                "REAL_LOCAL_GUARD": str(node.local_guard),
                "REQUIRE_LATCH_BEFORE_FIREWALL": "1",
                "FAKE_REGISTER_RC": "0",
            }
        )
        env.update(extra_env or {})
        with tempfile.TemporaryDirectory(prefix="wins-r25-h1-withdrawal-") as temp:
            path = pathlib.Path(temp) / "withdrawal.sh"
            path.write_text(script, encoding="utf-8")
            return subprocess.run(
                ["bash", str(path)], env=env, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
            )

    @staticmethod
    def trace(node: FakeNode) -> str:
        path = node.root / "trace.log"
        return path.read_text(encoding="utf-8") if path.exists() else ""

    @staticmethod
    def sha(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def test_the_deployed_guard_dies_on_the_new_bytes_so_the_pin_needs_the_new_guard(self) -> None:
        # The premise of R2-H1, shown on the real previous-release guard.
        with tempfile.TemporaryDirectory(prefix="wins-r25-h1-premise-") as directory:
            node = self.deployed_node(directory)
            self.newer_installer(node)
            status = node.run_guard("status")
            self.assertNotEqual(0, status.returncode, status.stdout)
            self.assertNotIn(status.stdout.strip(), ("confirmed", "unconfirmed"))
            self.assertNotEqual(0, node.run_guard("check").returncode, "the deployed timer tick dies too")

    def test_a_direct_ssh_rerun_installs_the_new_guard_after_the_withdrawal_pins_then_latches(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-r25-h1-migrate-") as directory:
            node = self.deployed_node(directory)
            old_sha = self.sha(node.guard.read_bytes())
            new_sha = self.sha(self.current_guard_bytes())
            self.assertNotEqual(old_sha, new_sha)
            digest = self.newer_installer(node)
            result = self.run_withdrawal(node)
            self.assertEqual(0, result.returncode, result.stdout)
            self.assertIn("DONE rerun_active=1", result.stdout)
            lines = self.trace(node).splitlines()
            # 1. The hub withdrawal comes first, and the host is untouched at that point.
            self.assertEqual(f"WITHDRAWN guard_sha256={old_sha}", lines[0])
            # 2. When the latch is asked for, the new guard is on disk and its exact /32 is armed for the new digest.
            self.assertEqual(
                ["LATCH disable", f"  guard_sha256={new_sha}", f"  armed_installer={digest}", "  armed_source=8.8.8.8"],
                lines[1:],
            )
            self.assertEqual(self.current_guard_bytes(), node.guard.read_bytes())
            self.assertFalse((node.state / "confirmed.env").exists(), "the old receipt is replaced, not kept")
            self.assertIn("8.8.8.8/32", (node.fw / "WINVPN-SSH-RECOVERY").read_text(encoding="utf-8"))
            self.assertTrue(node.latch.exists(), "and only then the serving latch engages")
            self.assertEqual("armed", node.run_guard("status").stdout.strip())
            units = sorted(path.name for path in (node.root / "units").iterdir())
            self.assertEqual(["wins-node-ssh-recovery-guard.service", "wins-node-ssh-recovery-guard.timer"], units)

    def test_a_failed_guard_install_refuses_before_the_latch_and_leaves_the_node_serving(self) -> None:
        for label in ("install", "units"):
            with self.subTest(label), tempfile.TemporaryDirectory(prefix="wins-r25-h1-refuse-") as directory:
                node = self.deployed_node(directory)
                old_bytes = node.guard.read_bytes()
                self.newer_installer(node)
                receipt = (node.state / "confirmed.env").read_bytes()
                extra_env: dict[str, str] = {}
                if label == "install":
                    write_executable(node.bin / "install", "#!/bin/bash\nexit 1\n")
                else:
                    extra_env["FAKE_ANALYZE_RC"] = "1"
                result = self.run_withdrawal(node, extra_env=extra_env)
                self.assertEqual(1, result.returncode, result.stdout)
                self.assertNotIn("DONE", result.stdout)
                self.assertIn("could not be installed before engaging the rerun serving latch", result.stdout)
                self.assertIn("the node keeps serving locally", result.stdout)
                trace = self.trace(node)
                self.assertTrue(trace.startswith("WITHDRAWN"), "the hub withdrawal already happened")
                self.assertNotIn("LATCH", trace)
                self.assertFalse(node.latch.exists())
                self.assertNotIn("DROP", (node.fw / "WINVPN-LOCAL-SERVING").read_text(encoding="utf-8")
                                 if (node.fw / "WINVPN-LOCAL-SERVING").exists() else "")
                self.assertFalse((node.state / "armed.env").exists(), "no recovery pin was touched")
                self.assertEqual(receipt, (node.state / "confirmed.env").read_bytes())
                if label == "install":
                    self.assertEqual(old_bytes, node.guard.read_bytes())

    def test_a_node_with_no_installed_guard_still_refuses_before_the_latch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-r25-h1-absent-") as directory:
            node = self.deployed_node(directory)
            node.guard.unlink()
            result = self.run_withdrawal(node)
            self.assertEqual(1, result.returncode, result.stdout)
            self.assertIn("no SSH recovery guard is installed to pin it", result.stdout)
            self.assertNotIn("LATCH", self.trace(node))
            self.assertFalse(node.latch.exists())

    def test_detached_and_tunnel_reruns_do_not_touch_the_guard_before_the_latch(self) -> None:
        # No direct session means no pre-latch pin; main() still installs the
        # guard before its own arm, so these paths are unchanged.
        for label, ssh_connection in (("detached", None), ("loopback", "127.0.0.1 50000 127.0.0.1 22")):
            with self.subTest(label), tempfile.TemporaryDirectory(prefix="wins-r25-h1-nopin-") as directory:
                node = self.deployed_node(directory)
                old_sha = self.sha(node.guard.read_bytes())
                self.newer_installer(node)
                result = self.run_withdrawal(node, ssh_connection=ssh_connection)
                self.assertEqual(0, result.returncode, result.stdout)
                self.assertEqual(
                    [f"WITHDRAWN guard_sha256={old_sha}", "LATCH disable", f"  guard_sha256={old_sha}",
                     "  armed_installer=", "  armed_source="],
                    self.trace(node).splitlines(),
                )
                self.assertFalse((node.root / "units").exists() and any((node.root / "units").iterdir()))
                self.assertFalse((node.state / "armed.env").exists())


class UnterminatedRecordShapeTests(unittest.TestCase):
    """R25: the shape checks of the node's security state files counted newline
    bytes with wc -l, so a valid file plus one unterminated extra record kept its
    count and every lookup still succeeded. Each site now also counts records."""

    UNTERMINATED = b"EXTRA=1"

    def test_an_armed_state_with_an_unterminated_extra_record_is_refused(self) -> None:
        cases = (("valid", b"", True), ("terminated extra record", b"EXTRA=1\n", False),
                 ("unterminated extra record", UnterminatedRecordShapeTests.UNTERMINATED, False))
        for label, suffix, accepted in cases:
            with self.subTest(label), tempfile.TemporaryDirectory(prefix="wins-r25-armed-shape-") as directory:
                node = FakeNode(pathlib.Path(directory), "8.8.8.8")
                self.assertEqual(0, node.run_guard("arm").returncode)
                state = node.state / "armed.env"
                original = state.read_bytes()
                self.assertEqual(8, original.count(b"\n"))
                state.write_bytes(original + suffix)
                status = node.run_guard("status")
                check = node.run_guard("check")
                if accepted:
                    self.assertEqual(("armed", 0), (status.stdout.strip(), status.returncode))
                    self.assertEqual(0, check.returncode, check.stdout)
                    continue
                self.assertNotEqual(0, status.returncode, status.stdout)
                self.assertIn("unexpected field count", status.stdout)
                self.assertNotEqual(0, check.returncode, check.stdout)
                confirm = node.run_guard("confirm")
                self.assertNotEqual(0, confirm.returncode, confirm.stdout)
                self.assertFalse((node.state / "confirmed.env").exists(), "a damaged pin is never turned into a receipt")
                self.assertEqual(original + suffix, state.read_bytes())

    def test_a_local_serving_latch_with_an_unterminated_extra_record_is_unsafe(self) -> None:
        cases = (("valid", b"", True), ("terminated extra record", b"EXTRA=1\n", False),
                 ("unterminated extra record", UnterminatedRecordShapeTests.UNTERMINATED, False))
        for label, suffix, safe in cases:
            with self.subTest(label), tempfile.TemporaryDirectory(prefix="wins-r25-latch-shape-") as directory:
                node = FakeNode(pathlib.Path(directory), "8.8.8.8")
                digest = hashlib.sha256(node.installer.read_bytes()).hexdigest()
                self.assertEqual(0, node.run_local("disable", "--reason", f"installer-rerun:{digest}").returncode)
                original = node.latch.read_bytes()
                self.assertEqual(3, original.count(b"\n"))
                node.latch.write_bytes(original + suffix)
                status = node.run_local("status")
                if safe:
                    self.assertEqual(("disabled", 0), (status.stdout.strip(), status.returncode), status.stdout)
                    continue
                self.assertNotEqual(0, status.returncode, status.stdout)
                self.assertIn("unsafe latch", status.stdout)
                enforce = node.run_local("enforce")
                self.assertNotEqual(0, enforce.returncode, enforce.stdout)
                self.assertIn("unsafe latch; customer services stopped", enforce.stdout)
                release = node.run_local(
                    "release-deployment", "--installer-sha256", digest, require_latch_before_firewall=False)
                self.assertNotEqual(0, release.returncode, release.stdout)
                self.assertIn("absent or unsafe", release.stdout)
                self.assertEqual(original + suffix, node.latch.read_bytes(), "an unsafe latch is never released")
                self.assertIn("-A WINVPN-LOCAL-SERVING -j DROP",
                              (node.fw / "WINVPN-LOCAL-SERVING").read_text(encoding="utf-8"))

    def test_the_installer_latch_file_check_refuses_an_unterminated_extra_record(self) -> None:
        source = DATA.read_text(encoding="utf-8")
        function = function_body(source, "winn3_latch_file_safe")
        valid = "VERSION=1\nREASON=installer-rerun:" + "ab" * 32 + "\nDISABLED_EPOCH=1\n"
        cases = (
            ("valid", valid, 0),
            ("terminated extra record", valid + "EXTRA=1\n", 1),
            ("unterminated extra record", valid + "EXTRA=1", 1),
            ("missing key", valid.replace("DISABLED_EPOCH=1", "OTHER=1"), 1),
            ("missing final newline", valid[:-1], 1),
        )
        for label, body, expected in cases:
            with self.subTest(label), tempfile.TemporaryDirectory(prefix="wins-r25-installer-latch-") as directory:
                node = FakeNode(pathlib.Path(directory), "8.8.8.8")
                latch = pathlib.Path(directory) / "installer-latch"
                latch.write_text(body, encoding="utf-8")
                self.assertIn("/etc/winsvpn/local-serving.disabled", function)
                script = "set -Eeuo pipefail\n" + function.replace(
                    "/etc/winsvpn/local-serving.disabled", str(latch)) + "\nwinn3_latch_file_safe\n"
                result = subprocess.run(["bash", "-c", script], env=node.env(), text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
                self.assertEqual(expected, result.returncode, result.stdout)


class AbortRollbackTrapTests(unittest.TestCase):
    """B0 fault-injection acceptance: the patch is validated by the ABORT
    test, not by the successful deploy.

    Simulates the failure window locally: the production guard binary arms
    the pinned /32 (FIX-2's arm-before-close), a firewall transaction then
    wipes the live pin and the persisted ruleset (the close), and the
    installer aborts BEFORE confirm with a non-zero exit. The production
    EXIT-trap functions (extracted verbatim, only the absolute guard path
    redirected) must re-insert AND persist the pin, so a stranded deploy
    still leaves a working recovery path. No real iptables, no network.
    """

    CLOSED_RULES = (
        "*filter\n"
        ":INPUT - [0:0]\n"
        ":WINVPN-INPUT - [0:0]\n"
        ":WINVPN-SSH-RECOVERY - [0:0]\n"
        "-A INPUT -j WINVPN-INPUT\n"
        "-A WINVPN-INPUT -j WINVPN-SSH-RECOVERY\n"
        "COMMIT\n"
    )
    PIN = (
        "-A WINVPN-SSH-RECOVERY -s 8.8.8.8/32 -p tcp -m tcp --dport 22 -j ACCEPT"
    )

    def build_harness(self, node: FakeNode, exit_rc: int, guard_exists: bool = True,
                      disarm_before_exit: bool = False) -> pathlib.Path:
        source = DATA.read_text(encoding="utf-8")
        start = source.index(
            'DEPLOY_FIREWALL_ROLLBACK_ARMED=0\nDEPLOY_FIREWALL_PRE_SNAPSHOT=""'
        )
        end = source.index("apply_bootstrap_firewall() {")
        rollback = source[start:end]
        guard_path = "/usr/local/sbin/wins-node-ssh-recovery-guard"
        self.assertIn(guard_path, rollback)
        replacement = (
            str(node.guard) if guard_exists else str(node.root / "absent-guard")
        )
        rollback = rollback.replace(guard_path, replacement)
        body = "deploy_firewall_rollback_arm\n"
        if disarm_before_exit:
            body += "deploy_firewall_rollback_disarm\n"
        body += f"exit {exit_rc}\n"
        script = (
            "set -Eeuo pipefail\n"
            "log() { printf 'LOG:%s\\n' \"$*\"; }\n"
            "warn() { printf 'WARN:%s\\n' \"$*\" >&2; }\n"
            "err() { printf 'ERR:%s\\n' \"$*\" >&2; }\n"
            f'data_plane_installer_path() {{ printf \'%s\' "{node.installer}"; }}\n'
            f'NODE_SSH_RECOVERY_STATE_DIR_DEFAULT="{node.state}"\n'
            + rollback
            + "\n"
            # S4: the EXIT trap is the ordered wrapper. The late-failure handler
            # and reassert step are unarmed in this harness (S4 suite covers
            # them), so they return at once exactly as the real ones do.
            + function_body(source, "winn3_installer_exit")
            + "\nwinn3_late_failure_on_exit() { return 0; }\n"
            + "winn3_late_failure_reassert() { return 0; }\n"
            + body
        )
        path = node.root / "abort-harness.sh"
        path.write_text(script, encoding="utf-8")
        return path

    def run_harness(self, node: FakeNode, path: pathlib.Path) -> subprocess.CompletedProcess[str]:
        environment = node.env()
        capture = node.root / "restore-capture.txt"
        write_executable(
            node.bin / "iptables-restore",
            '#!/bin/bash\ncat >> "${FAKE_RESTORE_CAPTURE:?}"\nexit 0\n',
        )
        environment["FAKE_RESTORE_CAPTURE"] = str(capture)
        return subprocess.run(
            ["bash", str(path)],
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

    def wipe_recovery_path(self, node: FakeNode) -> None:
        (node.fw / "WINVPN-SSH-RECOVERY").write_text("", encoding="utf-8")
        (node.fw / "INPUT").write_text("-A INPUT -j WINVPN-INPUT\n", encoding="utf-8")
        node.rules.write_text(self.CLOSED_RULES, encoding="utf-8")

    def test_abort_after_close_reinserts_and_persists_the_pin(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="wins-b0-abort-")
        with temporary:
            node = FakeNode(pathlib.Path(temporary.name), "8.8.8.8")
            self.assertEqual(0, node.run_guard("arm").returncode)
            self.wipe_recovery_path(node)
            result = self.run_harness(node, self.build_harness(node, 42))
            self.assertEqual(42, result.returncode, result.stdout)
            self.assertIn("reasserted and persisted", result.stdout)
            self.assertEqual(
                self.PIN + "\n",
                (node.fw / "WINVPN-SSH-RECOVERY").read_text(encoding="utf-8"),
            )
            base = (node.fw / "INPUT").read_text(encoding="utf-8").splitlines()
            self.assertEqual("-A INPUT -j WINVPN-SSH-RECOVERY", base[0])
            persisted = node.rules.read_text(encoding="utf-8")
            self.assertIn(self.PIN, persisted)
            self.assertIn("-A INPUT -j WINVPN-SSH-RECOVERY", persisted)

    def test_successful_exit_never_rolls_back(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="wins-b0-success-")
        with temporary:
            node = FakeNode(pathlib.Path(temporary.name), "8.8.8.8")
            self.assertEqual(0, node.run_guard("arm").returncode)
            self.wipe_recovery_path(node)
            result = self.run_harness(node, self.build_harness(node, 0))
            self.assertEqual(0, result.returncode, result.stdout)
            self.assertNotIn("Deployment aborted", result.stdout)
            self.assertEqual(
                "",
                (node.fw / "WINVPN-SSH-RECOVERY").read_text(encoding="utf-8"),
            )

    def test_disarmed_post_postflight_failure_does_not_roll_back(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="wins-b0-disarmed-")
        with temporary:
            node = FakeNode(pathlib.Path(temporary.name), "8.8.8.8")
            self.assertEqual(0, node.run_guard("arm").returncode)
            self.wipe_recovery_path(node)
            result = self.run_harness(
                node, self.build_harness(node, 9, disarm_before_exit=True)
            )
            self.assertEqual(9, result.returncode, result.stdout)
            self.assertEqual(
                "",
                (node.fw / "WINVPN-SSH-RECOVERY").read_text(encoding="utf-8"),
            )
            self.assertNotIn(self.PIN, node.rules.read_text(encoding="utf-8"))

    def test_unsafe_guard_falls_back_to_the_snapshot_restore(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="wins-b0-fallback-")
        with temporary:
            node = FakeNode(pathlib.Path(temporary.name), "8.8.8.8")
            result = self.run_harness(
                node, self.build_harness(node, 7, guard_exists=False)
            )
            self.assertEqual(7, result.returncode, result.stdout)
            self.assertIn("Restored the pre-deployment iptables snapshot", result.stdout)
            capture = (node.root / "restore-capture.txt").read_text(encoding="utf-8")
            self.assertIn("COMMIT", capture)

    def test_loopback_abort_verifies_fully_closed_without_inventing_a_pin(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="wins-b0-loopback-")
        with temporary:
            node = FakeNode(pathlib.Path(temporary.name), "::1")
            result = self.run_harness(node, self.build_harness(node, 5))
            self.assertEqual(5, result.returncode, result.stdout)
            self.assertFalse((node.state / "armed.env").exists())
            self.assertFalse((node.fw / "WINVPN-SSH-RECOVERY").exists())
            self.assertIn("Recovery guard reasserted", result.stdout)


class EdgeBootstrapRulesetTests(unittest.TestCase):
    """B0 acceptance, ruleset level: runs the production wins-edge-hardening
    script (everything up to the top-level call sequence, verbatim) against
    fake iptables backends and a synthetic node.env, then inspects the exact
    iptables-restore transaction the script produces.

    Scenario 1 is the demonstrated Germany clobber: the bootstrap caller
    passes NODE_MANAGEMENT_TUNNEL_ENABLED=0 + IONOS_HUB_IP=<deploy source>
    inline while node.env persists "1"; the produced ruleset MUST contain the
    deploy-source '--dport 22 ACCEPT' alongside the '-P INPUT DROP' policies
    (FIX-1 working). Scenario 2 is the tunnel/no-exception path taken for
    loopback and detached sessions: the ruleset must close direct SSH with NO
    tcp/22 source accept at all (FIX-6a coherent). No network, no real
    iptables, no servers.
    """

    def run_edge(
        self, node_env: str, inline: dict[str, str]
    ) -> tuple[subprocess.CompletedProcess[str], str, pathlib.Path]:
        source = DATA.read_text(encoding="utf-8")
        edge = heredoc(source, "WINS_EDGE_EOF")
        cut = edge.index("\napply_rps\n")
        script = S4_EDGE_SHARED_STUBS + edge[:cut] + "\nwins_preflight_ssh_path_survives\napply_firewall\n"
        temporary = tempfile.TemporaryDirectory(prefix="wins-b0-edge-")
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        (root / "node.env").write_text(node_env, encoding="utf-8")
        capture = root / "restore-capture.txt"
        write_executable(
            bin_dir / "iptables",
            r'''#!/bin/bash
set -u
if [[ "${1:-}" == -w ]]; then shift 2; fi
# F-DPHIGH-2: once a restore ran, -S OUTPUT shows the committed jump that
# apply_firewall reads back.
if [[ " $* " == *" -S OUTPUT "* && -s "${FAKE_RESTORE_CAPTURE:?}" ]]; then
  echo '-P OUTPUT ACCEPT'; echo '-A OUTPUT -j WINVPN-OUTPUT'; exit 0
fi
case "${1:-}" in
  -n|-L) exit 1 ;;
  -m) exit 1 ;;
  *) exit 0 ;;
esac
''',
        )
        write_executable(
            bin_dir / "iptables-save",
            "#!/bin/bash\n"
            "printf '%s\\n' '*filter' ':INPUT DROP [0:0]' ':FORWARD DROP [0:0]' "
            "':OUTPUT ACCEPT [0:0]' 'COMMIT'\n",
        )
        write_executable(
            bin_dir / "iptables-restore",
            '#!/bin/bash\ncat >> "${FAKE_RESTORE_CAPTURE:?}"\nexit 0\n',
        )
        write_executable(
            bin_dir / "systemctl",
            "#!/bin/bash\n"
            'case "$*" in\n'
            "  *InvocationID*) printf '%s\\n' '00000000000000000000000000000000' ;;\n"
            "esac\n"
            "exit 0\n",
        )
        write_executable(
            bin_dir / "journalctl",
            "#!/bin/bash\n"
            "echo 'cloudflared[1]: Registered tunnel connection'\n",
        )
        write_executable(bin_dir / "cloudflared", "#!/bin/bash\nexit 0\n")
        path = root / "edge.sh"
        path.write_text(script, encoding="utf-8")
        environment = os.environ.copy()
        for name in (
            "NODE_ENV_FILE",
            "NODE_MANAGEMENT_TUNNEL_ENABLED",
            "IONOS_HUB_IP",
            "INSTALL_DATA_IDS_IPS",
            "PUBLIC_VPN_INGRESS_ADMISSION",
            "HUB_REGISTER_URL",
            "HUB_REGISTER_URL_FALLBACK",
            "WAN_IF",
            "WINSVPN_TEST_ROOT",
        ):
            environment.pop(name, None)
        environment.update(
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
                # Portable stand-in for the shared firewall lock (Round SU).
                "WINS_FIREWALL_LOCK_HELD": "1",
            }
        )
        environment.update(inline)
        result = subprocess.run(
            ["bash", str(path)],
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout)
        return result, capture.read_text(encoding="utf-8"), root / "rootfs"

    def test_bootstrap_inline_override_emits_the_deploy_source_accept(self) -> None:
        _, transaction, rootfs = self.run_edge(
            'NODE_MANAGEMENT_TUNNEL_ENABLED="1"\n',
            {
                "PUBLIC_VPN_INGRESS_ADMISSION": "0",
                "INSTALL_DATA_IDS_IPS": "0",
                "NODE_MANAGEMENT_TUNNEL_ENABLED": "0",
                "IONOS_HUB_IP": "203.0.113.7",
            },
        )
        self.assertIn(
            "-A WINVPN-INPUT -p tcp -s 203.0.113.7 --dport 22 -j ACCEPT", transaction
        )
        self.assertIn(":INPUT DROP [0:0]", transaction)
        self.assertTrue((rootfs / "etc" / "iptables" / "rules.v4").exists())

    def test_tunnel_path_closes_direct_ssh_with_no_source_accept(self) -> None:
        # Exactly what apply_bootstrap_firewall invokes for loopback
        # (management-tunnel) and detached sessions: admission/IDS inline only,
        # everything else from node.env.
        result, transaction, rootfs = self.run_edge(
            'NODE_MANAGEMENT_TUNNEL_ENABLED="1"\n',
            {
                "PUBLIC_VPN_INGRESS_ADMISSION": "0",
                "INSTALL_DATA_IDS_IPS": "0",
            },
        )
        self.assertNotRegex(transaction, r"--dport 22 -j ACCEPT")
        self.assertNotRegex(transaction, r"-s \S+ --dport 22")
        self.assertIn(":INPUT DROP [0:0]", transaction)
        self.assertIn("Direct SSH ingress is intentionally blocked", result.stdout)
        self.assertTrue((rootfs / "etc" / "iptables" / "rules.v4").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
