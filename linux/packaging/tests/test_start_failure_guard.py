"""Exercise the production shell start case with no host network mutations."""
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
SOURCE = ROOT / "linux/runner/linux_tunnel_backend.cc"


class StartFailureGuardTests(unittest.TestCase):
    def run_start(self, failure):
        source = SOURCE.read_text()
        start = source.index('case "${1:-}" in\n  start)')
        end = source.index('    ;;\n  stop)', start)
        case = source[start:end] + '    ;;\nesac\n'
        mocks = r'''
guard=0
kill_switch=1
tunnel=1
trap 'printf "FINAL guard=%s kill_switch=%s tunnel=%s\n" "$guard" "$kill_switch" "$tunnel"' EXIT
validate_config() { return 0; }
find_awg_quick() { printf mock_awg; }
install() { return 0; }
rm() { return 0; }
kill_switch_restore_preflight() { return 0; }
begin_reconnect_guard() { guard=1; }
cleanup_split_rules() { return 0; }
cleanup_xray_transport() { return 0; }
cleanup_winn_transport() { return 0; }
cleanup_winn3_kill_switch() { return 0; }
cleanup_kill_switch() { kill_switch=0; }
configure_xray_transport() { return 0; }
configure_kill_switch() { kill_switch=1; }
cleanup_reconnect_guard() { guard=0; }
mock_awg() { case "$1" in up) tunnel=1;; down) tunnel=0;; esac; }
activate_xray_transport() { [ "$failure" != xray ]; }
activate_winn_transport() { [ "$failure" != winn ]; }
configure_split_rules() { [ "$failure" != split ]; }
CONF_DIR=unused
CONF_DST=unused
APP_PID=123
'''
        return subprocess.run(
            ["/bin/sh", "-c", 'set -eu\nfailure="$4"\n' + mocks + case,
             "fixture", "start", str(SOURCE), "fixture-cgroup", failure],
            capture_output=True, text=True, timeout=10)

    def test_failed_transport_or_split_setup_keeps_block(self):
        for failure in ("xray", "winn", "split"):
            with self.subTest(failure=failure):
                result = self.run_start(failure)
                self.assertEqual(result.returncode, 65, result.stderr)
                self.assertIn("FINAL guard=1 kill_switch=0 tunnel=0",
                              result.stdout)

    def test_completed_setup_releases_transition_guard(self):
        result = self.run_start("none")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("FINAL guard=0 kill_switch=1 tunnel=1", result.stdout)


if __name__ == "__main__":
    unittest.main()
