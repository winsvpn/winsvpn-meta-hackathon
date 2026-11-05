#!/usr/bin/env python3
"""Offline hostile checks for the AICORE resource-isolation deployment contract."""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.stage_core_sync_agent import stage
from tools.validate_deployment_scripts import parse_heredocs


SOURCE = ROOT / "server" / "wins_core_server_setup_ONETOUCH.sh"


def _source() -> str:
    return SOURCE.read_text(encoding="utf-8")


def _function(text: str, name: str, next_name: str) -> str:
    start = text.index(f"{name}() {{")
    end = text.index(f"\n{next_name}() {{", start)
    return text[start:end]


def _heredoc_body(text: str, target: str) -> str:
    suffix = f" > {target} <<'EOF'"
    bodies = [
        block.body
        for block in parse_heredocs(SOURCE)
        if block.header.strip().endswith(suffix)
    ]
    if len(bodies) != 1:
        raise AssertionError(f"expected one heredoc for {target}, found {len(bodies)}")
    return bodies[0]


class CoreResourceIsolationTests(unittest.TestCase):
    def _topology(self, groups: list[tuple[int, ...]]) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            online = sorted({cpu for group in groups for cpu in group})
            (root / "online").write_text(
                f"{online[0]}-{online[-1]}\n", encoding="ascii"
            )
            for group in groups:
                siblings = ",".join(str(cpu) for cpu in group)
                for cpu in group:
                    topology = root / f"cpu{cpu}" / "topology"
                    topology.mkdir(parents=True)
                    (topology / "thread_siblings_list").write_text(
                        siblings + "\n", encoding="ascii"
                    )
            function = _function(
                _source(), "derive_core_cpu_sets", "resolve_core_isolation_nic"
            )
            return subprocess.run(
                ["bash", "-c", f"{function}\nderive_core_cpu_sets \"$1\"", "_", str(root)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

    def test_exact_eight_reciprocal_smt_pairs_are_split_by_whole_pair(self):
        groups = [(cpu, cpu + 8) for cpu in range(8)]
        result = self._topology(groups)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"(?m)^CORE_CPUSET=0-3,8-11$")
        self.assertRegex(result.stdout, r"(?m)^OTHER_CPUSET=4-7,12-15$")
        self.assertRegex(result.stdout, r"(?m)^TOPOLOGY_SHA256=[0-9a-f]{64}$")

    def test_non_pair_and_wrong_pair_count_topologies_fail_closed(self):
        malformed = [(0, 8), (1, 9), (2,), (3, 11), (4, 12), (5, 13), (6, 14), (7, 15)]
        self.assertNotEqual(self._topology(malformed).returncode, 0)
        self.assertNotEqual(
            self._topology([(cpu, cpu + 7) for cpu in range(7)]).returncode,
            0,
        )

    def test_all_three_core_tunnel_producers_set_explicit_parent(self):
        text = _source()
        self.assertEqual(text.count("--cgroup-parent=wins-core.slice"), 3)
        for block in (
            "--name wins-core-ingress \\\n    --cgroup-parent=wins-core.slice",
            "--name wins-core-exit \\\n    --cgroup-parent=wins-core.slice",
            '--name "${container}" \\\n      --cgroup-parent=wins-core.slice',
        ):
            self.assertIn(block, text)

    def test_slice_and_docker_defaults_are_explicit_and_fail_closed(self):
        text = _source()
        for unit in (
            "wins.slice",
            "wins-core.slice",
            "wins-ids.slice",
            "wins-ai.slice",
            "wins-build.slice",
        ):
            self.assertIn(f"/etc/systemd/system/{unit}", text)
        self.assertIn("systemctl set-property --runtime wins-core.slice", text)
        self.assertIn("systemctl set-property --runtime wins-ids.slice", text)
        self.assertIn("systemctl set-property --runtime wins-ai.slice", text)
        self.assertIn("systemctl set-property --runtime wins-build.slice", text)
        self.assertIn('data["cgroup-parent"] = "wins-build.slice"', text)
        self.assertIn("SocketMode=0600", text)
        self.assertNotIn("--cgroup-parent=user.slice", text)

    def test_build_interlock_uses_fresh_hub_state_lock_latch_and_monitor(self):
        text = _source()
        state = _heredoc_body(text, "/usr/local/sbin/wins-core-build-state")
        wrapper = _heredoc_body(text, "/usr/local/sbin/wins-core-maintenance-build")
        monitor = _heredoc_body(text, "/usr/local/sbin/wins-core-build-monitor")
        self.assertIn('state.get("promoted") is not False', state)
        self.assertIn('winsvpn-core-advertised-state-v2', state)
        self.assertIn('allow_pending_text != "1" and pending != ""', state)
        self.assertIn('now - observed > int(max_age_text)', state)
        self.assertIn('latch.get("boot_id") != boot_id', state)
        self.assertIn('stat.S_IMODE(info.st_mode) != 0o600', state)
        self.assertIn('flock -n 9', wrapper)
        self.assertIn('exec 7>"${CORE_BUILD_EXCLUSION_LOCK}"', wrapper)
        self.assertIn('flock -n 7', wrapper)
        self.assertEqual(wrapper.count("wins-core-build-state check"), 2)
        close_index = wrapper.index("exec 9>&-")
        check_indexes = [
            match.start()
            for match in re.finditer("wins-core-build-state check", wrapper)
        ]
        self.assertTrue(all(index < close_index for index in check_indexes))
        self.assertLess(close_index, wrapper.index('exec "$@"'))
        exclusion_index = wrapper.index('exec 7>"${CORE_BUILD_EXCLUSION_LOCK}"')
        state_lock_index = wrapper.index('exec 9>"${CORE_ADVERTISED_STATE_LOCK}"')
        command_index = wrapper.index('exec "$@"')
        self.assertLess(exclusion_index, state_lock_index)
        self.assertNotIn("exec 7>&-", wrapper[exclusion_index:command_index])
        self.assertIn("--slice=wins-build.slice", wrapper)
        self.assertIn('exec 8>"${CORE_BUILD_LAUNCH_LOCK}"', wrapper)
        self.assertIn("wins-core-build-state open", wrapper)
        self.assertIn("wins-core-build-state close", wrapper)
        self.assertIn("tasks=1", monitor)
        self.assertIn("wins-core-build-state check-running", monitor)
        self.assertIn("winsvpn-core-build-violation-v1", monitor)
        self.assertIn("--signal=SIGKILL wins-build.slice", monitor)
        self.assertIn("OnUnitActiveSec=10s", text)

    def test_effective_irq_affinity_is_reapplied_and_durably_proved(self):
        text = _source()
        helper = _heredoc_body(text, "/usr/local/sbin/wins-core-pin-nic-irqs")
        self.assertIn("effective_affinity_list", helper)
        self.assertIn("not effective.issubset(desired)", helper)
        self.assertIn("winsvpn-core-effective-irq-affinity-v1", helper)
        self.assertIn("os.fsync(stream.fileno())", helper)
        self.assertIn("os.fsync(descriptor)", helper)
        self.assertIn('chmod 0600 "${receipt_tmp}"', helper)
        self.assertIn("OnUnitActiveSec=30s", text)
        self.assertIn("IRQBALANCE_BANNED_CPULIST", text)
        self.assertIn('index($field, nic "-") == 1', text)

    def test_sync_stage_requires_hub_promotion_state_and_core_parent(self):
        with tempfile.TemporaryDirectory() as value:
            output = Path(value) / "stage"
            stage(SOURCE, output)
            agent = (output / "wins-core-sync").read_text(encoding="utf-8")
        self.assertIn("persist_core_advertised_state", agent)
        self.assertIn("winsvpn-core-advertised-state-v2", agent)
        self.assertIn('(.promoted | type == "boolean")', agent)
        self.assertIn("acknowledge_core_promotion", agent)
        self.assertIn('exec 7>"${CORE_BUILD_EXCLUSION_LOCK}"', agent)
        self.assertIn('/api/v1/core/promotion/ack', agent)
        self.assertIn("--cgroup-parent=wins-core.slice", agent)


if __name__ == "__main__":
    unittest.main()
