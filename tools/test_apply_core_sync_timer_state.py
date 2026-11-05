from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
APPLY = ROOT / "tools" / "apply_core_sync_agent.sh"


def shell_function(source: str, name: str) -> str:
    start = source.index(f"{name}() {{")
    end = source.index("\n}\n", start) + 3
    return source[start:end]


class ApplyCoreSyncTimerStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = APPLY.read_text(encoding="utf-8")
        self.functions = "\n".join(
            shell_function(self.source, name)
            for name in ("restore_timer", "verify_timer_state")
        )

    def make_fixture(self, root: Path) -> tuple[Path, Path]:
        state = root / "state"
        fake_bin = root / "bin"
        state.mkdir()
        fake_bin.mkdir()
        systemctl = fake_bin / "systemctl"
        systemctl.write_text(
            r'''#!/usr/bin/env bash
set -Eeuo pipefail
state_dir="${STATE_DIR:?}"
operation="${1:-}"
case "${operation}" in
  is-enabled)
    value="$(<"${state_dir}/enabled")"
    printf '%s\n' "${value}"
    [[ "${value}" == "enabled" ]]
    ;;
  is-active)
    value="$(<"${state_dir}/active")"
    printf '%s\n' "${value}"
    [[ "${value}" == "active" ]]
    ;;
  enable)
    printf 'enabled\n' > "${state_dir}/enabled"
    ;;
  disable)
    if [[ "${IGNORE_DISABLE:-0}" != "1" ]]; then
      printf 'disabled\n' > "${state_dir}/enabled"
    fi
    ;;
  start)
    printf 'active\n' > "${state_dir}/active"
    ;;
  stop)
    if [[ "${IGNORE_STOP:-0}" != "1" ]]; then
      printf 'inactive\n' > "${state_dir}/active"
    fi
    ;;
  *)
    exit 64
    ;;
esac
''',
            encoding="utf-8",
        )
        systemctl.chmod(0o700)
        harness = root / "harness.sh"
        harness.write_text(
            "#!/usr/bin/env bash\n"
            "set -Eeuo pipefail\n"
            "TIMER=wins-core-sync.timer\n"
            'PRE_TIMER_ENABLED="$1"\n'
            'PRE_TIMER_ACTIVE="$2"\n'
            f"{self.functions}\n"
            "restore_timer\n"
            "verify_timer_state\n",
            encoding="utf-8",
        )
        harness.chmod(0o700)
        return state, harness

    def run_case(
        self,
        expected_enabled: str,
        expected_active: str,
        initial_enabled: str,
        initial_active: str,
        *,
        overrides: dict[str, str] | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], str, str]:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            state, harness = self.make_fixture(root)
            (state / "enabled").write_text(initial_enabled + "\n", encoding="utf-8")
            (state / "active").write_text(initial_active + "\n", encoding="utf-8")
            environment = os.environ.copy()
            environment["PATH"] = f"{root / 'bin'}:{environment['PATH']}"
            environment["STATE_DIR"] = str(state)
            environment.update(overrides or {})
            completed = subprocess.run(
                ["bash", str(harness), expected_enabled, expected_active],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                check=False,
                timeout=10,
            )
            return (
                completed,
                (state / "enabled").read_text(encoding="utf-8").strip(),
                (state / "active").read_text(encoding="utf-8").strip(),
            )

    def test_restore_and_verify_all_enabled_active_combinations(self) -> None:
        cases = (
            ("enabled", "active", "disabled", "inactive"),
            ("enabled", "inactive", "disabled", "active"),
            ("disabled", "active", "enabled", "inactive"),
            ("disabled", "inactive", "enabled", "active"),
        )
        for expected_enabled, expected_active, initial_enabled, initial_active in cases:
            with self.subTest(
                enabled=expected_enabled,
                active=expected_active,
            ):
                completed, final_enabled, final_active = self.run_case(
                    expected_enabled,
                    expected_active,
                    initial_enabled,
                    initial_active,
                )
                self.assertEqual(0, completed.returncode, completed.stderr)
                self.assertEqual(expected_enabled, final_enabled)
                self.assertEqual(expected_active, final_active)

    def test_intentionally_inactive_timer_is_accepted(self) -> None:
        completed, final_enabled, final_active = self.run_case(
            "enabled", "inactive", "disabled", "active"
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("enabled", final_enabled)
        self.assertEqual("inactive", final_active)

    def test_restore_failure_is_detected_before_commit(self) -> None:
        completed, final_enabled, final_active = self.run_case(
            "enabled",
            "inactive",
            "disabled",
            "active",
            overrides={"IGNORE_STOP": "1"},
        )
        self.assertNotEqual(0, completed.returncode)
        self.assertEqual("enabled", final_enabled)
        self.assertEqual("active", final_active)
        self.assertIn(
            "Core sync timer active state changed: expected=inactive actual=active",
            completed.stderr,
        )

        verification = self.source.index("\nverify_timer_state\n")
        self.assertLess(
            self.source.index("trap rollback ERR INT TERM EXIT"), verification
        )
        self.assertLess(verification, self.source.index("ROLLBACK_REQUIRED=0"))
        rollback = shell_function(self.source, "rollback")
        self.assertIn("restore_timer", rollback)

    def test_apply_helper_remains_valid_bash(self) -> None:
        completed = subprocess.run(
            ["bash", "-n", str(APPLY)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)


if __name__ == "__main__":
    unittest.main()
