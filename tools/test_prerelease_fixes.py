#!/usr/bin/env python3
"""Offline regressions for the PRERELEASE-FIX source and fixture contracts."""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CP = ROOT / "server/wins_control_plane_setup_ONETOUCH.sh"
DP = ROOT / "server/wins_data_plane_setup_ONETOUCH.sh"
SUITE = ROOT / "tools/test_deployment_runtime_configs.sh"
sys.path.insert(0, str(ROOT / "server"))
import fleet_reset_testlib as lib


def run_bash(script: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [lib.BASH, "--noprofile", "--norc", "-c", script],
        capture_output=True, text=True, timeout=20,
    )


class PrereleaseFixes(unittest.TestCase):
    def test_double_vpn_default_and_explicit_yes(self):
        admin = lib.heredoc(CP.read_text(), "cat > /usr/local/bin/wins-admin <<'PYEOF'", "PYEOF")
        node = next(n for n in ast.parse(admin).body
                    if isinstance(n, ast.FunctionDef) and n.name == "set_double_vpn_free_access")
        code = compile(ast.Module(body=[node], type_ignores=[]), "wins-admin", "exec")
        for answer in ("", " ", "n", "no", "0", "1", "true", "on", "maybe", "YES", " y ", "yes"):
            with self.subTest(answer=answer):
                calls, prompts = [], []
                def input_fixture(prompt):
                    prompts.append(prompt)
                    return answer
                ns = {"input": input_fixture, "post_form": lambda *args: calls.append(args)}
                exec(code, ns)
                ns["set_double_vpn_free_access"]()
                self.assertEqual(calls, [("/admin/double-vpn/free-access", {
                    "enabled": str(answer.strip().lower() in {"y", "yes"}).lower(),
                })])
                self.assertIn("[y/N]", prompts[0])

    def test_prepublication_dispatch_retries_and_rejects(self):
        fn = lib.function_text(CP.read_text(), "run_prepublication_gateway_canary")
        harness = r'''
set -Eeuo pipefail
log() { :; }; warn() { :; }; err() { :; }
calls=0
systemctl() {
  [[ "$*" == 'start wins-gateway-canary-prepublication.service' ]] || return 90
  calls=$((calls + 1))
  [[ "${calls}" -ge 2 ]]
}
PUBLIC_CANARY_ATTEMPTS=2
PUBLIC_CANARY_INTERVAL_SECONDS=0
run_prepublication_gateway_canary
[[ "${calls}" == 2 ]]
WINS_GATEWAY_CANARY_BIN=/unreviewed/fixture
if run_prepublication_gateway_canary; then exit 91; fi
[[ "${calls}" == 2 ]]
WINS_GATEWAY_CANARY_BIN=/usr/local/bin/wins-gateway-canary
systemctl() { calls=$((calls + 1)); return 1; }
if run_prepublication_gateway_canary; then exit 92; fi
[[ "${calls}" == 4 ]]
'''
        p = run_bash(fn + harness)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_canary_guards_reject_mutations(self):
        spec = importlib.util.spec_from_file_location("prf_validator", ROOT / "tools/validate_deployment_scripts.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        source = CP.read_text()
        module.validate_order_and_contract("control", source)
        mutations = (
            ("Environment=WINS_CANARY_SKIP_GATEWAY_RECORD=1", "Environment=WINS_CANARY_SKIP_GATEWAY_RECORD=0"),
            ("ExecStart=/usr/local/bin/wins-gateway-canary", "ExecStart=/unreviewed/canary"),
            ("Type=oneshot\nExecStart=/usr/local/bin/wins-gateway-canary", "Type=simple\nExecStart=/usr/local/bin/wins-gateway-canary"),
            ("ExecStart=/usr/local/bin/wins-gateway-canary\n", "ExecStart=/usr/local/bin/wins-gateway-canary\nExecStart=/unreviewed/canary\n"),
            ("ExecStart=/usr/local/bin/wins-gateway-canary\n", "ExecStart=/usr/local/bin/wins-gateway-canary\nRemainAfterExit=yes\n"),
            ("ExecStart=/usr/local/bin/wins-gateway-canary\n", "ExecStart=/usr/local/bin/wins-gateway-canary\nAmbientCapabilities=CAP_NET_ADMIN\n"),
            ('[[ "${canary_bin}" == "/usr/local/bin/wins-gateway-canary" ]] || {', '[[ -n "${canary_bin}" ]] || {'),
            ("if systemctl start wins-gateway-canary-prepublication.service; then", "if systemctl start --no-block wins-gateway-canary-prepublication.service; then"),
            ("  run_prepublication_gateway_canary\n  publish_active_gateway_record", "  publish_active_gateway_record\n  run_prepublication_gateway_canary"),
            ('err "Public gateway canary failed. The active-gateway pointer was not published."\n  return 1', 'err "Public gateway canary failed. The active-gateway pointer was not published."\n  return 0'),
        )
        for old, new in mutations:
            with self.subTest(guard=old):
                self.assertIn(old, source)
                with self.assertRaises(SystemExit):
                    module.validate_order_and_contract("control", source.replace(old, new, 1))

    def test_monotonic_timer_checks_then_queues_recovery(self):
        for installer in (CP, DP):
            fn = lib.function_text(installer.read_text(), "wins_enable_monotonic_timer")
            for state in ("elapsed", "waiting"):
                with self.subTest(installer=installer.name, state=state):
                    harness = r'''
set -Eeuo pipefail
log() { :; }
calls=''
systemctl() {
  case "$*" in
    'enable --now fixture.timer') calls+='enable;';;
    'show -p SubState --value fixture.timer') printf '%s\n' "$state";;
    'show -p Unit --value fixture.timer') printf '%s\n' fixture.service;;
    'start --no-block fixture.service') calls+='start;';;
    *) return 99;;
  esac
}
wins_enable_monotonic_timer fixture.timer
[[ "$calls" == "$expected" ]]
'''
                    prefix = f"state={state}\nexpected='{'enable;start;' if state == 'elapsed' else 'enable;'}'\n"
                    p = run_bash(fn + prefix + harness)
                    self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_runtime_python_fixture_closures(self):
        text = SUITE.read_text()
        main = lib.heredoc(CP.read_text(), 'cat > "${APP_DIR}/main.py" <<\'PYEOF\'', "PYEOF")
        with tempfile.TemporaryDirectory() as d:
            app = Path(d) / "main.py"
            app.write_text(main)
            for name, arg in (("test_control_transport_parser", app), ("test_core_management_provider_simulation", CP)):
                with self.subTest(fixture=name):
                    start = text.index(name + "() {")
                    start = text.index("<<'PYEOF'\n", start) + len("<<'PYEOF'\n")
                    end = text.index("\nPYEOF\n", start)
                    p = subprocess.run([sys.executable, "-B", "-", str(arg)],
                                       input=text[start:end], capture_output=True, text=True, timeout=20)
                    self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_edge_fixture_includes_the_shipped_helpers(self):
        source = DP.read_text()
        expected = "  winn3_prepend_shared_functions /usr/local/bin/wins-edge-hardening "
        names = ("wins_late_failure_hold", "wins_latch_rules_inspect", "wins_latch_rules_dominate", "winn3gw_render_chains")
        call = next(line for line in source.splitlines() if line.startswith(expected))
        self.assertEqual(call, expected + " ".join(names))
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "edge.sh"
            fixture = Path(d) / "installer.sh"
            # Use the shipped bodies in a private source-only fixture. The
            # Linux ownership calls are mocked; no installer globals are read.
            mini = "".join(lib.function_text(source, name) for name in names)
            mini += lib.function_text(source, "winn3_prepend_shared_functions")
            mini += "write_firewall() {\n" + call + "\n}\n"
            mini += "write_body() {\ncat > /usr/local/bin/wins-edge-hardening <<'WINS_EDGE_EOF'\n"
            mini += lib.heredoc(source, "cat > /usr/local/bin/wins-edge-hardening <<'WINS_EDGE_EOF'", "WINS_EDGE_EOF")
            mini += "WINS_EDGE_EOF\n}\n"
            fixture.write_text(mini)
            fn = lib.function_text(SUITE.read_text(), "extract_edge_hardening")
            extract = lib.function_text(SUITE.read_text(), "extract_heredoc")
            harness = "set -Eeuo pipefail\nstat() { printf '644\\n'; }\nchown() { :; }\n"
            harness += extract + fn + f"extract_edge_hardening '{fixture}' '{target}'\nbash -n '{target}'\n"
            p = run_bash(harness)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            for name in names:
                p = run_bash(lib.function_text(source, name) + f"declare -f {name}\n")
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertIn(p.stdout.strip(), target.read_text())
            marker = Path(d) / "hold"
            fn = lib.function_text(source, "wins_late_failure_hold").replace("/var/lib/winsvpn/winn3-late-failure.json", str(marker))
            p = run_bash(fn + f"if wins_late_failure_hold; then exit 90; fi\n: > '{marker}'\nwins_late_failure_hold\n")
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_current_hub_hardening_contract(self):
        text = SUITE.read_text()
        with tempfile.TemporaryDirectory() as d:
            harness = f"set -Eeuo pipefail\nwork_dir='{d}'\nCONTROL_SCRIPT='{CP}'\n"
            harness += 'err() { printf "%s\\n" "$*" >&2; return 1; }\n'
            harness += lib.function_text(text, "extract_heredoc")
            harness += lib.function_text(text, "test_control_host_hardening_contract")
            harness += "test_control_host_hardening_contract\n"
            p = run_bash(harness)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main()
