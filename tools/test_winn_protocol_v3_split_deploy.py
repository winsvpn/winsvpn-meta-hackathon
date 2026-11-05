#!/usr/bin/env python3
"""WINN_PROTOCOL_V3_ENABLE=1 must be a loud refuse, never a silent split.

Fleet-wide the flag used to install a legacy AmneziaWG PSK rotator on the
control plane (a role that cannot start it: no local AWG peer) while the
data-plane AWG-relay carrier was a tombstone unreachable from main().
Neither side warned. That is a silent half-deploy.

This file is the regression net:

* Runtime: extract the refuse functions into a private harness (never
  source the 30k-line ONETOUCH scripts — control-plane main is unguarded
  and data-plane top-level sources /root/*.env). Flag=0 must be silent
  success. Flag=1 must print SPLIT deploy and, on ONETOUCH, exit 1.
* set -e stubbed main(): flag=1 must not reach require_root; flag=0 must
  (positive control); deleting the refuse must reach it (inverted).
* Live --help only (never --deploy/--preflight/--install): the standalone
  gateway installer is a tombstone since slice S6 (design v17 2.8) and must
  exit 2 with its pointer whatever the flag; ONETOUCH --help must name the
  split and still exit 0.
* Call graph: main() must invoke the refuse before require_root.
* Static contract: validate_winn_protocol_v3_contract on live sources.
* Three controls, in memory, never against the shared tree: no-mutation
  (pass), comment-only (pass), deliberate break the suite MUST see
  (scored inverted). A green this file cannot make fail is not evidence.

Run (canonical, wired from validate_deployment_scripts.py):
  python3 tools/test_winn_protocol_v3_split_deploy.py -v
Shim: python3 server/test_winn_v3_split_deploy_loud.py
Never /tmp: harness files go under .spark_lanes/scratch/deploy_split_deploy_loud/.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTROL = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"
DATA = ROOT / "server" / "wins_data_plane_setup_ONETOUCH.sh"
GATEWAY = ROOT / "server" / "wins_winn3_gateway_install.sh"
TOOLS = ROOT / "tools"
SCRATCH = (
    Path(__file__).resolve().parents[3]
    / ".spark_lanes"
    / "scratch"
    / "deploy_split_deploy_loud"
    / "testrun"
)

sys.path.insert(0, str(TOOLS))
from validate_deployment_scripts import (  # noqa: E402
    function_body,
    validate_winn_protocol_v3_contract,
)

REFUSE_FN = "refuse_retired_winn_protocol_v3_enable"
SPLIT_NEEDLE = "SPLIT deploy"
GATEWAY_INSTALLER = "wins_winn3_gateway_install.sh"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def function_source(source: str, name: str) -> str:
    """Full `name() { ... }` using the validator's last-declaration rule."""
    body = function_body(source, name)
    return f"{name}() {{{body}"


def is_loud_onetouch_refuse(code: int, out: str) -> bool:
    return (
        code == 1
        and SPLIT_NEEDLE in out
        and GATEWAY_INSTALLER in out
        and "[ERR]" in out
    )


def _write_harness(name: str, body: str) -> Path:
    SCRATCH.mkdir(parents=True, exist_ok=True)
    path = SCRATCH / name
    path.write_text(body, encoding="utf-8")
    return path


def run_extracted(
    function_text: str,
    call: str,
    env_flag: str | None,
    harness_name: str,
) -> tuple[int, str]:
    """Run one extracted function with stub err/warn/log. No host mutation.

    The harness always exits 0 so the caller can read EXIT:<n> from stdout
    even when the function returned 1. That EXIT line is the measured status.
    """
    script = f"""#!/usr/bin/env bash
set -euo pipefail
err()  {{ printf '[ERR] %s\\n' "$*" >&2; }}
warn() {{ printf '[WARN] %s\\n' "$*" >&2; }}
log()  {{ printf '[INFO] %s\\n' "$*"; }}
WINN_PROTOCOL_V3_ENABLE_DEFAULT="${{WINN_PROTOCOL_V3_ENABLE:-0}}"
{function_text}
set +e
{call}
ec=$?
set -e
printf 'EXIT:%s\\n' "$ec"
"""
    path = _write_harness(harness_name, script)
    syntax = subprocess.run(
        ["bash", "-n", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if syntax.returncode != 0:
        return (
            99,
            f"BUILD_FAIL bash -n: {syntax.stderr or syntax.stdout}",
        )
    env = os.environ.copy()
    if env_flag is None:
        env.pop("WINN_PROTOCOL_V3_ENABLE", None)
    else:
        env["WINN_PROTOCOL_V3_ENABLE"] = env_flag
    proc = subprocess.run(
        ["bash", str(path)],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    combined = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        return proc.returncode, f"harness-crash rc={proc.returncode}\n{combined}"
    match = re.search(r"^EXIT:(\d+)\s*$", proc.stdout or "", re.MULTILINE)
    if not match:
        return 98, f"no EXIT line\n{combined}"
    return int(match.group(1)), combined


def run_set_e_entry(
    function_text: str,
    call: str,
    env_flag: str | None,
    harness_name: str,
) -> tuple[int, str]:
    """Run under set -e like the live installers.

    run_extracted uses `set +e` around the call so it can print EXIT:<n>
    after a function returns 1. That is correct for testing a function's
    return code, and wrong for proving main() aborts: bash set -e is
    suppressed in a `cmd || ...` / `set +e` context, including inside
    the called function. This helper keeps set -e on, stubs require_root
    (and siblings) to print CALLED:... and exit 99, and returns the
    process status. Flag=0 must reach the stub (exit 99). Flag=1 must
    not (exit 1 from the refuse, no CALLED: line).
    """
    script = (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        'err()  { printf \'[ERR] %s\\n\' "$*" >&2; }\n'
        'warn() { printf \'[WARN] %s\\n\' "$*" >&2; }\n'
        'log()  { printf \'[INFO] %s\\n\' "$*"; }\n'
        "require_root() { printf 'CALLED:require_root\\n'; exit 99; }\n"
        "repair_hub_recovery_contract() {"
        " printf 'CALLED:repair_hub_recovery_contract\\n'; exit 99; }\n"
        "preflight_control() {"
        " printf 'CALLED:preflight_control\\n'; exit 99; }\n"
        "preflight_data_plane() {"
        " printf 'CALLED:preflight_data_plane\\n'; exit 99; }\n"
        'WINN_PROTOCOL_V3_ENABLE_DEFAULT="${WINN_PROTOCOL_V3_ENABLE:-0}"\n'
        f"{function_text}\n"
        f"{call}\n"
    )
    path = _write_harness(harness_name, script)
    syntax = subprocess.run(
        ["bash", "-n", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if syntax.returncode != 0:
        return (
            99,
            f"BUILD_FAIL bash -n: {syntax.stderr or syntax.stdout}",
        )
    env = os.environ.copy()
    if env_flag is None:
        env.pop("WINN_PROTOCOL_V3_ENABLE", None)
    else:
        env["WINN_PROTOCOL_V3_ENABLE"] = env_flag
    proc = subprocess.run(
        ["bash", str(path)],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    combined = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, combined


def run_live_script(
    path: Path,
    args: list[str],
    env_flag: str | None,
) -> tuple[int, str]:
    """Execute a real installer with only --help (or empty args).

    Never pass --deploy/--preflight/--install/--start: those call
    require_root and mutate. --help is the path that was silent on the
    gateway installer before warn moved above the mode case. (The standalone
    gateway installer is a tombstone since slice S6; the all-modes sandbox
    run is tools/test_winn3_gateway_tombstone.py.)
    """
    env = os.environ.copy()
    if env_flag is None:
        env.pop("WINN_PROTOCOL_V3_ENABLE", None)
    else:
        env["WINN_PROTOCOL_V3_ENABLE"] = env_flag
    proc = subprocess.run(
        ["bash", str(path), *args],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def contract_error(control: str, data: str, gateway: str) -> str | None:
    try:
        validate_winn_protocol_v3_contract(
            control=control, data=data, gateway=gateway
        )
    except SystemExit as exc:
        return str(exc)
    return None


class SplitDeployLoudTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.control = _read(CONTROL)
        cls.data = _read(DATA)
        cls.gateway = _read(GATEWAY)
        cls.control_refuse = function_source(cls.control, REFUSE_FN)
        cls.data_refuse = function_source(cls.data, REFUSE_FN)
        cls.data_tombstone = function_source(cls.data, "install_winn_carrier_server")
        cls.control_main = function_body(cls.control, "main")
        cls.data_main = function_body(cls.data, "main")

    # ------------------------------------------------------------------
    # Runtime: extracted functions. Flag=0 silent; flag=1 loud.
    # ------------------------------------------------------------------

    def test_control_refuse_flag_unset_is_silent_success(self) -> None:
        code, out = run_extracted(
            self.control_refuse, REFUSE_FN, None, "cp_refuse_unset.sh"
        )
        self.assertNotEqual(code, 99, out)
        self.assertEqual(code, 0, out)
        self.assertNotIn(SPLIT_NEEDLE, out)
        self.assertNotIn("[ERR]", out)

    def test_control_refuse_flag_zero_is_silent_success(self) -> None:
        code, out = run_extracted(
            self.control_refuse, REFUSE_FN, "0", "cp_refuse_zero.sh"
        )
        self.assertNotEqual(code, 99, out)
        self.assertEqual(code, 0, out)
        self.assertNotIn(SPLIT_NEEDLE, out)
        self.assertNotIn("[ERR]", out)

    def test_control_refuse_flag_one_is_loud_failure(self) -> None:
        code, out = run_extracted(
            self.control_refuse, REFUSE_FN, "1", "cp_refuse_one.sh"
        )
        self.assertNotEqual(code, 99, out)
        self.assertTrue(is_loud_onetouch_refuse(code, out), out)
        self.assertIn("Refusing", out)
        self.assertIn("rotator", out)

    def test_control_refuse_flag_two_is_not_the_retired_enable(self) -> None:
        """Only the exact value 1 is the retired enable. 2 must not refuse
        a normal deploy — a guard that fires on any non-empty value is a
        different, worse bug."""
        code, out = run_extracted(
            self.control_refuse, REFUSE_FN, "2", "cp_refuse_two.sh"
        )
        self.assertNotEqual(code, 99, out)
        self.assertEqual(code, 0, out)
        self.assertNotIn(SPLIT_NEEDLE, out)

    def test_data_refuse_flag_zero_is_silent_success(self) -> None:
        code, out = run_extracted(
            self.data_refuse, REFUSE_FN, "0", "dp_refuse_zero.sh"
        )
        self.assertNotEqual(code, 99, out)
        self.assertEqual(code, 0, out)
        self.assertNotIn(SPLIT_NEEDLE, out)
        self.assertNotIn("[ERR]", out)

    def test_data_refuse_flag_one_is_loud_failure(self) -> None:
        code, out = run_extracted(
            self.data_refuse, REFUSE_FN, "1", "dp_refuse_one.sh"
        )
        self.assertNotEqual(code, 99, out)
        self.assertTrue(is_loud_onetouch_refuse(code, out), out)
        self.assertIn("Refusing", out)
        self.assertIn("RETIRED", out)

    def test_data_tombstone_flag_one_is_loud_failure(self) -> None:
        """Library-seam callers still hit install_winn_carrier_server."""
        combined = self.data_refuse + "\n" + self.data_tombstone
        code, out = run_extracted(
            combined, "install_winn_carrier_server", "1", "dp_tombstone_one.sh"
        )
        self.assertNotEqual(code, 99, out)
        self.assertEqual(code, 1, out)
        self.assertIn(SPLIT_NEEDLE, out)

    def test_data_tombstone_flag_zero_is_silent_success(self) -> None:
        combined = self.data_refuse + "\n" + self.data_tombstone
        code, out = run_extracted(
            combined, "install_winn_carrier_server", "0", "dp_tombstone_zero.sh"
        )
        self.assertNotEqual(code, 99, out)
        self.assertEqual(code, 0, out)
        self.assertNotIn(SPLIT_NEEDLE, out)

    # ------------------------------------------------------------------
    # Call graph: a defined-but-uncalled function is a false green.
    # ------------------------------------------------------------------

    def test_data_main_refuses_before_require_root(self) -> None:
        refuse_at = self.data_main.find(REFUSE_FN)
        root_at = self.data_main.find("require_root")
        self.assertGreaterEqual(refuse_at, 0, "data-plane main() never calls the refuse")
        self.assertGreaterEqual(root_at, 0, "data-plane main() lost require_root")
        self.assertLess(refuse_at, root_at, "data-plane refuse is after require_root")
        self.assertNotIn(
            "install_winn_carrier_server",
            self.data_main,
            "data-plane main() must not re-insert the retired carrier call site",
        )

    def test_control_main_refuses_on_deploy_preflight_and_repair(self) -> None:
        self.assertGreaterEqual(
            self.control_main.count(REFUSE_FN),
            3,
            "control-plane main() must refuse on --preflight, --repair, and --deploy",
        )
        deploy = (
            f"  {REFUSE_FN}\n"
            "  require_root\n"
            "  preflight_control"
        )
        self.assertIn(deploy, self.control_main)
        preflight = f"      {REFUSE_FN}\n      require_root"
        self.assertIn(preflight, self.control_main)
        repair = f"      {REFUSE_FN}\n      repair_hub_recovery_contract"
        self.assertIn(repair, self.control_main)

    def test_control_main_still_calls_install_after_refuse(self) -> None:
        """Defense in depth: even if the early refuse is deleted, the
        install function itself must still refuse rather than stage the
        rotator. This asserts the call site still exists; the flag=1
        path inside it is checked by the static contract."""
        self.assertIn("install_winn_protocol_server", self.control_main)
        install = function_body(self.control, "install_winn_protocol_server")
        self.assertIn(REFUSE_FN, install)
        enable_at = install.find("systemctl enable winn-server")
        refuse_at = install.find(REFUSE_FN)
        self.assertGreaterEqual(refuse_at, 0)
        if enable_at >= 0:
            self.assertLess(
                refuse_at,
                enable_at,
                "control-plane install enables winn-server before refusing",
            )

    # ------------------------------------------------------------------
    # Static contract on live sources (no-mutation control).
    # ------------------------------------------------------------------

    def test_live_static_contract_passes(self) -> None:
        err = contract_error(self.control, self.data, self.gateway)
        self.assertIsNone(err, err)

    def test_comment_only_edit_still_passes_static_contract(self) -> None:
        needle = f"{REFUSE_FN}() {{"
        self.assertEqual(self.control.count(needle), 1)
        self.assertEqual(self.data.count(needle), 1)
        comment = needle + "\n  # comment-only control: SPLIT deploy must not count\n"
        control = self.control.replace(needle, comment, 1)
        data = self.data.replace(needle, comment, 1)
        err = contract_error(control, data, self.gateway)
        self.assertIsNone(err, err)

    def test_comment_only_edit_still_refuses_at_runtime(self) -> None:
        mutated = self.control_refuse.replace(
            f"{REFUSE_FN}() {{",
            f"{REFUSE_FN}() {{\n  # comment-only control",
            1,
        )
        code, out = run_extracted(
            mutated, REFUSE_FN, "1", "cp_refuse_comment.sh"
        )
        self.assertEqual(code, 1, out)
        self.assertIn(SPLIT_NEEDLE, out)

    # ------------------------------------------------------------------
    # Deliberate breaks. Scored inverted: the suite MUST see red.
    # ------------------------------------------------------------------

    def test_removing_data_main_refuse_fails_static_contract(self) -> None:
        needle = (
            f"  {REFUSE_FN}\n"
            "  require_root\n"
            "  preflight_data_plane"
        )
        self.assertEqual(self.data.count(needle), 1, "data-plane refuse-before-root moved")
        mutated = self.data.replace(
            needle,
            "  require_root\n  preflight_data_plane",
            1,
        )
        err = contract_error(self.control, mutated, self.gateway)
        self.assertIsNotNone(err, "static contract stayed green after deleting data-plane refuse")
        self.assertIn("silent success", err or "")

    def test_removing_split_deploy_text_fails_static_contract(self) -> None:
        live = function_body(self.control, REFUSE_FN)
        self.assertIn(SPLIT_NEEDLE, live)
        mutated_fn = live.replace(SPLIT_NEEDLE, "inconsistent deploy", 1)
        mutated = self.control.replace(live, mutated_fn, 1)
        err = contract_error(mutated, self.data, self.gateway)
        self.assertIsNotNone(err, "static contract stayed green after deleting SPLIT deploy")
        self.assertIn("SPLIT deploy", err or "")

    def test_refuse_returning_zero_on_flag_one_fails_static_contract(self) -> None:
        """A refuse that logs then returns 0 is the original silent success."""
        live = function_body(self.control, REFUSE_FN)
        # Count the statement, not the comment "the return 1 is unreachable"
        # that function_body includes until the next function.
        self.assertEqual(live.count("\n  return 1\n"), 1)
        mutated_fn = live.replace("\n  return 1\n", "\n  return 0\n", 1)
        mutated = self.control.replace(live, mutated_fn, 1)
        err = contract_error(mutated, self.data, self.gateway)
        self.assertIsNotNone(err, "static contract stayed green when refuse returned 0")
        self.assertIn("return 0 only when the flag is not 1", err or "")

    def test_refuse_returning_zero_on_flag_one_fails_runtime_loudness(self) -> None:
        """Inverted: a refuse that logs then returns 0 is the original
        silent success. is_loud_onetouch_refuse must be false, or the
        live flag=1 test has nothing that would go red."""
        mutated = self.control_refuse.replace("\n  return 1\n", "\n  return 0\n", 1)
        code, out = run_extracted(
            mutated, REFUSE_FN, "1", "cp_refuse_return0.sh"
        )
        self.assertNotEqual(code, 99, out)
        self.assertEqual(code, 0, out)
        self.assertIn(SPLIT_NEEDLE, out)
        self.assertFalse(
            is_loud_onetouch_refuse(code, out),
            "return-0 mutant still counts as loud; the live assertion is too weak",
        )

    def test_control_enabling_rotator_before_refuse_fails_static_contract(self) -> None:
        install = function_body(self.control, "install_winn_protocol_server")
        needle = f"  {REFUSE_FN}\n  return 1"
        self.assertIn(needle, install)
        mutated_fn = install.replace(
            needle,
            "  systemctl enable winn-server.service\n" + needle,
            1,
        )
        mutated = self.control.replace(install, mutated_fn, 1)
        err = contract_error(mutated, self.data, self.gateway)
        self.assertIsNotNone(
            err,
            "static contract stayed green when winn-server enable moved before refuse",
        )
        self.assertTrue(
            "does not call" in (err or "") or "enables winn-server before" in (err or ""),
            err,
        )

    def test_silent_return1_without_split_text_fails_runtime_loudness(self) -> None:
        """A refuse that exits 1 with no explanation is not loud. The live
        flag=1 test requires SPLIT deploy in the output; this mutant is
        what that requirement exists to catch."""
        silent = f"""{REFUSE_FN}() {{
  if [[ "${{WINN_PROTOCOL_V3_ENABLE_DEFAULT}}" != "1" ]]; then
    return 0
  fi
  return 1
}}
"""
        code, out = run_extracted(
            silent, REFUSE_FN, "1", "cp_refuse_silent.sh"
        )
        self.assertNotEqual(code, 99, out)
        self.assertEqual(code, 1, out)
        self.assertFalse(
            is_loud_onetouch_refuse(code, out),
            "silent exit-1 mutant still counts as loud; SPLIT deploy is not required",
        )

    # ------------------------------------------------------------------
    # Slice S6: the standalone gateway installer is the tombstone. It used to
    # WARN on the retired flag; it now ignores its environment and exits 2.
    # ------------------------------------------------------------------

    def test_live_gateway_tombstone_exits_2_whatever_the_flag(self) -> None:
        for flag in (None, "0", "1"):
            for args in ([], ["--help"]):
                with self.subTest(flag=flag, args=args):
                    code, out = run_live_script(GATEWAY, args, flag)
                    self.assertEqual(code, 2, out)
                    self.assertIn("server/wins_data_plane_setup_ONETOUCH.sh", out)
                    self.assertIn("retired", out)
                    self.assertNotIn("[WARN]", out)

    def test_gateway_tombstone_exit_0_fails_static_contract(self) -> None:
        self.assertEqual(self.gateway.count("\nexit 2\n"), 1)
        mutated = self.gateway.replace("\nexit 2\n", "\nexit 0\n", 1)
        err = contract_error(self.control, self.data, mutated)
        self.assertIsNotNone(err, "static contract stayed green when the tombstone exited 0")
        self.assertIn("exit 2", err or "")

    def test_gateway_restored_warn_function_fails_static_contract(self) -> None:
        """The pre-S6 installer defined the warn and a main(); neither may return."""
        mutated = self.gateway.replace(
            "\nexit 2\n",
            "\nwarn_retired_winn_protocol_v3_enable_flag() {\n  warn 'SPLIT deploy ignored'\n}\nexit 2\n",
            1,
        )
        err = contract_error(self.control, self.data, mutated)
        self.assertIsNotNone(err, "static contract stayed green when the warn function came back")
        self.assertIn("not the tombstone", err or "")

    def test_gateway_tombstone_without_the_pointer_fails_static_contract(self) -> None:
        mutated = self.gateway.replace("server/wins_data_plane_setup_ONETOUCH.sh", "the data-plane installer")
        self.assertNotEqual(mutated, self.gateway)
        err = contract_error(self.control, self.data, mutated)
        self.assertIsNotNone(err, "static contract stayed green when the tombstone lost its pointer")
        self.assertIn("does not point at", err or "")

    def test_live_control_help_mentions_split_and_does_not_refuse(self) -> None:
        """--help is not a deploy. It must name the split and still exit 0."""
        code, out = run_live_script(CONTROL, ["--help"], "1")
        self.assertEqual(code, 0, out)
        self.assertIn(SPLIT_NEEDLE, out)
        self.assertIn(GATEWAY_INSTALLER, out)

    def test_live_data_help_mentions_split_and_does_not_refuse(self) -> None:
        code, out = run_live_script(DATA, ["--help"], "1")
        self.assertEqual(code, 0, out)
        self.assertIn(SPLIT_NEEDLE, out)
        self.assertIn(GATEWAY_INSTALLER, out)

    def test_stubbed_data_main_flag_one_never_reaches_require_root(self) -> None:
        needle = (
            f"  {REFUSE_FN}\n"
            "  require_root\n"
            "  preflight_data_plane"
        )
        self.assertIn(needle, self.data_main)
        main_fn = (
            "main() {\n"
            "  export WINS_DATA_PLANE_INSTALL_MODE=main\n"
            f"{needle}\n"
            "  printf 'REACHED_AFTER_ROOT\\n'\n"
            "}\n"
        )
        code, out = run_set_e_entry(
            self.data_refuse + "\n" + main_fn,
            "main",
            "1",
            "dp_set_e_main_one.sh",
        )
        self.assertNotEqual(code, 99, out)
        self.assertEqual(code, 1, out)
        self.assertIn(SPLIT_NEEDLE, out)
        self.assertNotIn("CALLED:require_root", out)
        self.assertNotIn("REACHED_AFTER_ROOT", out)

    def test_stubbed_data_main_flag_zero_reaches_require_root(self) -> None:
        """Positive control: the CALLED:require_root probe can fire."""
        needle = (
            f"  {REFUSE_FN}\n"
            "  require_root\n"
            "  preflight_data_plane"
        )
        self.assertIn(needle, self.data_main)
        main_fn = (
            "main() {\n"
            "  export WINS_DATA_PLANE_INSTALL_MODE=main\n"
            f"{needle}\n"
            "  printf 'REACHED_AFTER_ROOT\\n'\n"
            "}\n"
        )
        code, out = run_set_e_entry(
            self.data_refuse + "\n" + main_fn,
            "main",
            "0",
            "dp_set_e_main_zero.sh",
        )
        self.assertEqual(code, 99, out)
        self.assertIn("CALLED:require_root", out)
        self.assertNotIn(SPLIT_NEEDLE, out)

    def test_deleting_refuse_from_stubbed_data_main_reaches_require_root(self) -> None:
        """Inverted: a main that skipped the refuse must hit require_root
        even with flag=1. If this stays green when we delete the call,
        the set -e probe cannot see a miss."""
        main_fn = (
            "main() {\n"
            "  export WINS_DATA_PLANE_INSTALL_MODE=main\n"
            "  require_root\n"
            "  preflight_data_plane\n"
            "}\n"
        )
        code, out = run_set_e_entry(
            self.data_refuse + "\n" + main_fn,
            "main",
            "1",
            "dp_set_e_main_norefuse.sh",
        )
        self.assertEqual(code, 99, out)
        self.assertIn("CALLED:require_root", out)

    def test_stubbed_control_deploy_flag_one_never_reaches_require_root(self) -> None:
        needle = (
            f"  {REFUSE_FN}\n"
            "  require_root\n"
            "  preflight_control"
        )
        self.assertIn(needle, self.control_main)
        main_fn = (
            "main() {\n"
            f"{needle}\n"
            "  printf 'REACHED_AFTER_ROOT\\n'\n"
            "}\n"
        )
        code, out = run_set_e_entry(
            self.control_refuse + "\n" + main_fn,
            "main",
            "1",
            "cp_set_e_deploy_one.sh",
        )
        self.assertNotEqual(code, 99, out)
        self.assertEqual(code, 1, out)
        self.assertIn(SPLIT_NEEDLE, out)
        self.assertNotIn("CALLED:require_root", out)

    def test_stubbed_control_preflight_flag_one_never_reaches_require_root(self) -> None:
        needle = f"      {REFUSE_FN}\n      require_root"
        self.assertIn(needle, self.control_main)
        main_fn = (
            "main() {\n"
            "  case \"${1:-}\" in\n"
            "    --preflight|--validate)\n"
            f"{needle}\n"
            "      printf 'REACHED_AFTER_ROOT\\n'\n"
            "      return 0\n"
            "      ;;\n"
            "  esac\n"
            "}\n"
        )
        code, out = run_set_e_entry(
            self.control_refuse + "\n" + main_fn,
            "main --preflight",
            "1",
            "cp_set_e_preflight_one.sh",
        )
        self.assertNotEqual(code, 99, out)
        self.assertEqual(code, 1, out)
        self.assertIn(SPLIT_NEEDLE, out)
        self.assertNotIn("CALLED:require_root", out)

    def test_stubbed_control_repair_flag_one_never_reaches_repair(self) -> None:
        needle = f"      {REFUSE_FN}\n      repair_hub_recovery_contract"
        self.assertIn(needle, self.control_main)
        main_fn = (
            "main() {\n"
            "  case \"${1:-}\" in\n"
            "    --repair-recovery-contract)\n"
            f"{needle}\n"
            "      return 0\n"
            "      ;;\n"
            "  esac\n"
            "}\n"
        )
        code, out = run_set_e_entry(
            self.control_refuse + "\n" + main_fn,
            "main --repair-recovery-contract",
            "1",
            "cp_set_e_repair_one.sh",
        )
        self.assertNotEqual(code, 99, out)
        self.assertEqual(code, 1, out)
        self.assertIn(SPLIT_NEEDLE, out)
        self.assertNotIn("CALLED:repair_hub_recovery_contract", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
