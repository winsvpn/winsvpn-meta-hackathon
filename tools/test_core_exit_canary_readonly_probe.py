import ast
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "core_exit_canary_readonly_probe.py"


def embedded_target() -> str:
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id == "target":
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return node.value.value
    raise AssertionError("Privileged embedded target was not found")


class CoreExitCanaryReadonlyProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = embedded_target()
        cls.tree = ast.parse(cls.target)

    def test_embedded_target_is_valid_python(self):
        compile(self.target, "<core-exit-canary-target>", "exec")

    def test_mux_contracts_are_exact_and_mutually_exclusive(self):
        for marker in (
            'mux.get("enabled") is False',
            'mux.get("concurrency")==0',
            'mux.get("xudpConcurrency")==0',
            'mux.get("xudpProxyUDP443")=="skip"',
            'mux.get("enabled") is True',
            'mux.get("concurrency")==-1',
            'mux.get("xudpConcurrency")==16',
            'mux.get("xudpProxyUDP443")=="allow"',
            'udp_tunnel and',
        ):
            self.assertIn(marker, self.target)
        self.assertIn('int(not native_mux and not legacy_mux)', self.target)

    def test_installed_agent_class_is_allow_listed_and_bounded(self):
        self.assertIn('handle.read(262145)', self.target)
        for value in ("native_udp", "legacy_xudp", "other", "unreadable"):
            self.assertIn(f'sync_agent_contract="{value}"', self.target)
        self.assertNotIn("sync_agent", self.output_keys())
        self.assertNotIn("sync_agent_text", self.output_keys())
        self.assertNotIn("sync_agent_hash", self.output_keys())

    def test_xray_observations_are_local_read_only_predicates(self):
        for marker in (
            '["systemctl","is-active","--quiet","wins-core-xray-exit@"+iface+".service"]',
            '["xray","-test","-config",xray_config_path]',
            '["ss","-H","-l","-u","-n"]',
            'item.get("listen")=="127.0.0.1"',
        ):
            self.assertIn(marker, self.target)
        self.assertNotIn("sudo", self.target)

    def recovery_metric_function(self):
        functions = [
            node for node in self.tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "recovery_timing_metrics"
        ]
        self.assertEqual(1, len(functions))
        module = ast.Module(body=functions, type_ignores=[])
        ast.fix_missing_locations(module)
        namespace = {"json": json, "re": __import__("re")}
        exec(compile(module, "<recovery-metric-test>", "exec"), namespace)
        return namespace["recovery_timing_metrics"]

    def test_recovery_metrics_pair_in_order_and_return_only_bounded_values(self):
        lines = [
            {"MESSAGE": "exit=corex1 recovering stale stealth handshake (Xray first, AWG second)", "__REALTIME_TIMESTAMP": "1000000"},
            {"MESSAGE": "exit=corex1 stale stealth handshake recovered", "__REALTIME_TIMESTAMP": "3100000"},
            {"MESSAGE": "exit=corex2 recovering stale stealth handshake (Xray first, AWG second)", "__REALTIME_TIMESTAMP": "10000000"},
            {"MESSAGE": "exit=corex2 stale stealth handshake recovered", "__REALTIME_TIMESTAMP": "14000000"},
            {"MESSAGE": "exit=corex3 recovering stale stealth handshake (Xray first, AWG second)", "__REALTIME_TIMESTAMP": "20000000"},
        ]
        result = self.recovery_metric_function()("\n".join(json.dumps(line) for line in lines))
        self.assertEqual({
            "recovery_sample_count": 2,
            "latest_recovery_seconds": 4,
            "max_recovery_seconds": 4,
            "latest_attempt_unrecovered": True,
        }, result)
        serialized = json.dumps(result, sort_keys=True)
        for sensitive in ("corex1", "corex2", "corex3", "MESSAGE", "TIMESTAMP"):
            self.assertNotIn(sensitive, serialized)

    def test_latest_attempt_flag_tracks_newest_attempt_and_clamps_duration(self):
        lines = [
            {"MESSAGE": "exit=corex1 recovering stale stealth handshake (Xray first, AWG second)", "__REALTIME_TIMESTAMP": "1000000"},
            {"MESSAGE": "exit=corex2 recovering stale stealth handshake (Xray first, AWG second)", "__REALTIME_TIMESTAMP": "2000000"},
            {"MESSAGE": "exit=corex2 stale stealth handshake recovered", "__REALTIME_TIMESTAMP": "5000000000"},
        ]
        result = self.recovery_metric_function()("\n".join(json.dumps(line) for line in lines))
        self.assertEqual(1, result["recovery_sample_count"])
        self.assertEqual(1800, result["latest_recovery_seconds"])
        self.assertEqual(1800, result["max_recovery_seconds"])
        self.assertFalse(result["latest_attempt_unrecovered"])

    def test_recovery_journal_window_and_output_are_strictly_bounded(self):
        for marker in (
            '["journalctl","-u","wins-core-sync.service","--since","-30 minutes","--no-pager","-o","json","-n","1000"]',
            "journal_text.splitlines()[:1000]",
            '"recovery_sample_count":min(500,len(samples))',
            "seconds=min(1800,max(0,",
        ):
            self.assertIn(marker, self.target)

    def output_keys(self) -> set[str]:
        dictionaries = [
            node for node in ast.walk(self.tree)
            if isinstance(node, ast.Dict)
            and any(
                isinstance(key, ast.Constant) and key.value == "role"
                for key in node.keys
            )
        ]
        self.assertEqual(1, len(dictionaries))
        return {
            key.value
            for key in dictionaries[0].keys
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        }

    def test_output_contains_only_aggregate_contract_additions(self):
        expected = {
            "native_udp_mux_disabled_configs_count",
            "legacy_xudp_enabled_configs_count",
            "other_mux_configs_count",
            "installed_sync_agent_contract",
            "exit_xray_unit_active",
            "xray_unit_active_count",
            "exit_xray_config_valid",
            "xray_config_valid_count",
            "exit_loopback_udp_listener",
            "loopback_udp_listener_count",
            "recovery_sample_count",
            "latest_recovery_seconds",
            "max_recovery_seconds",
            "latest_attempt_unrecovered",
        }
        keys = self.output_keys()
        self.assertTrue(expected.issubset(keys))
        for forbidden in (
            "xray_config_path",
            "xray_config_text",
            "xray_config_hash",
            "sync_agent_path",
            "sync_agent_text",
            "sync_agent_hash",
            "exit_identifier",
        ):
            self.assertNotIn(forbidden, keys)


if __name__ == "__main__":
    unittest.main()
