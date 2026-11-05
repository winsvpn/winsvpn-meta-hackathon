from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from tools.relay_core_sync_transaction import classify_apply_failure
from tools.stage_core_sync_agent import REQUIRED_MARKERS, TRANSPORT_REQUIRED_MARKERS, stage


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "server" / "wins_core_server_setup_ONETOUCH.sh"
APPLY = ROOT / "tools" / "apply_core_sync_agent.sh"
RELAY = ROOT / "tools" / "relay_core_sync_transaction.py"


class CoreSyncTransactionTests(unittest.TestCase):
    def test_stale_policy_cleanup_targets_one_source_not_shared_priority(self):
        source = SOURCE.read_text(encoding="utf-8")
        start = source.index("remove_stale_assignment_state() (")
        end = source.index("\nverify_management_runtime()", start)
        cleanup = source[start:end]
        self.assertIn(
            'ip rule del from "${source_ip}/32" table "${table}" \\\n'
            '        priority "${priority}"',
            cleanup,
        )
        self.assertNotIn('ip rule del priority "${priority}"', cleanup)

    def test_client_policy_rule_is_kept_when_already_correct(self):
        # A matching rule must never be deleted and re-added on a tick: the
        # gap between the two netlink writes sent the client's packets to the
        # table 5299 blackhole (priority 32765) every 3 seconds.
        source = SOURCE.read_text(encoding="utf-8")
        start = source.index("\nsync_assignment() {")
        end = source.index("\nvalidate_assignment_runtime() {", start)
        body = source[start:end]
        self.assertNotIn('while ip rule del from "${client_ip}/32" 2>/dev/null; do :; done', body)
        self.assertIn('if ((rule_matched == 0)); then', body)
        self.assertIn(
            'ip rule add from "${client_ip}/32" table "${table_id}" priority "${priority}"',
            body,
        )
        self.assertIn(
            'ip rule del from "${client_ip}/32" table "${rule_table}" priority "${rule_priority}"',
            body,
        )
        self.assertIn("class=client_policy_rule_update_failed", body)

    def test_current_source_stages_without_transient_unready_race(self):
        with tempfile.TemporaryDirectory() as value:
            output = Path(value) / "stage"
            result = stage(SOURCE, output)
            self.assertEqual(result["contract"], "winsvpn-core-sync-staging-v1")
            self.assertEqual(result["readiness_transaction"], "preserve-until-failure")
            candidate = (output / "wins-core-sync").read_text(encoding="utf-8")
            self.assertNotRegex(candidate, r"(?m)^\s*register_core false\s*$")
            self.assertIn(
                'CORE_INGRESS_ADDR="${CORE_INGRESS_ADDR:-10.9.1.1/16}"',
                candidate,
            )
            self.assertIn("register_core false || true", candidate)
            self.assertIn('CORE_SYNC_FAILURE_STAGE="ready-registration"', candidate)
            for marker in REQUIRED_MARKERS:
                self.assertIn(marker, candidate)
            for marker in TRANSPORT_REQUIRED_MARKERS:
                self.assertIn(marker, candidate)
            self.assertNotIn(
                'CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS="${CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS:-45}"',
                candidate,
            )
            self.assertNotIn(
                'mux:{enabled:true,concurrency:-1,xudpConcurrency:16,xudpProxyUDP443:"allow"}',
                candidate,
            )
            for marker in (
                'CORE_SYNC_LOCK_FILE="${CORE_SYNC_LOCK_FILE:-/run/wins-core-sync.lock}"',
                'CORE_SYNC_LOCK_WAIT_SECONDS="${CORE_SYNC_LOCK_WAIT_SECONDS:-120}"',
                'CORE_SYNC_BUSY_EXIT_CODE="${CORE_SYNC_BUSY_EXIT_CODE:-0}"',
                "acquire_core_sync_lock() {",
                'flock -w "${CORE_SYNC_LOCK_WAIT_SECONDS}" 9',
                'return "${CORE_SYNC_BUSY_EXIT_CODE}"',
            ):
                self.assertIn(marker, candidate)
            self.assertLess(
                candidate.index("if acquire_core_sync_lock; then"),
                candidate.index("trap 'rc=$?; trap - EXIT"),
            )
            timer = (output / "wins-core-sync.timer").read_text(encoding="utf-8")
            self.assertIn("OnBootSec=3s", timer)
            self.assertIn("OnUnitActiveSec=1s", timer)
            self.assertIn("AccuracySec=100ms", timer)

    def test_busy_lock_never_publishes_unready_and_required_path_returns_75(self):
        bash_major = int(
            subprocess.run(
                ["bash", "-c", "printf %s \"${BASH_VERSINFO[0]}\""],
                text=True,
                stdout=subprocess.PIPE,
                check=True,
            ).stdout
        )
        if bash_major < 4:
            self.skipTest("The Core sync agent requires Bash 4 associative arrays.")
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            output = root / "stage"
            stage(SOURCE, output)
            agent = root / "wins-core-sync-no-main"
            agent.write_text(
                (output / "wins-core-sync")
                .read_text(encoding="utf-8")
                .replace('\nmain "$@"\n', "\n"),
                encoding="utf-8",
            )
            harness = root / "lock-test.sh"
            harness.write_text(
                r'''#!/usr/bin/env bash
set -Eeuo pipefail
agent="$1"
lock_file="$2"
CORE_ENV_FILE=/dev/null
# shellcheck disable=SC1090
source "${agent}"
CORE_SYNC_LOCK_FILE="${lock_file}"
CORE_SYNC_LOCK_WAIT_SECONDS=1
flock_result=1
flock() { return "${flock_result}"; }
if acquire_core_sync_lock; then
  echo "bounded lock contention unexpectedly acquired" >&2
  exit 91
else
  rc=$?
fi
[[ "${rc}" == 75 ]]

acquire_core_sync_lock() { return 75; }
register_calls=0
register_core() { register_calls=$((register_calls + 1)); }
CORE_SYNC_BUSY_EXIT_CODE=0
main
[[ "${register_calls}" == 0 ]]
CORE_SYNC_BUSY_EXIT_CODE=75
if main; then
  echo "required lock owner proof unexpectedly passed" >&2
  exit 92
else
  rc=$?
fi
[[ "${rc}" == 75 ]]
[[ "${register_calls}" == 0 ]]
''',
                encoding="utf-8",
            )
            completed = subprocess.run(
                ["bash", str(harness), str(agent), str(root / "sync.lock")],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=20,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)

    def test_staging_rejects_missing_process_wide_lock(self):
        source = SOURCE.read_text(encoding="utf-8")
        marker = "acquire_core_sync_lock() {"
        self.assertEqual(source.count(marker), 1)
        with tempfile.TemporaryDirectory() as value:
            modified = Path(value) / "core.sh"
            modified.write_text(
                source.replace(marker, "removed_core_sync_lock() {", 1),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "readiness contract is incomplete"):
                stage(modified, Path(value) / "stage")

    def test_staging_rejects_a_candidate_with_any_diagnostic_omitted(self):
        source = SOURCE.read_text(encoding="utf-8")
        for marker in REQUIRED_MARKERS:
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as value:
                modified = Path(value) / "core.sh"
                modified.write_text(source.replace(marker, "class=diagnostic_removed"), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "readiness contract is incomplete"):
                    stage(modified, Path(value) / "stage")

    def test_staging_rejects_enabled_xudp_mux(self):
        source = SOURCE.read_text(encoding="utf-8")
        disabled = TRANSPORT_REQUIRED_MARKERS[0]
        enabled = 'mux:{enabled:true,concurrency:-1,xudpConcurrency:16,xudpProxyUDP443:"allow"}'
        self.assertIn(disabled, source)
        with tempfile.TemporaryDirectory() as value:
            modified = Path(value) / "core.sh"
            modified.write_text(source.replace(disabled, enabled), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "XUDP aggregation"):
                stage(modified, Path(value) / "stage")

    def test_staging_rejects_undersized_legacy_handshake_timeout(self):
        source = SOURCE.read_text(encoding="utf-8")
        current = 'CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS="${CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS:-90}"'
        legacy = 'CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS="${CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS:-45}"'
        self.assertEqual(source.count(current), 2)
        self.assertNotIn(legacy, source)
        with tempfile.TemporaryDirectory() as value:
            modified = Path(value) / "core.sh"
            modified.write_text(source.replace(current, legacy), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "45-second handshake timeout"):
                stage(modified, Path(value) / "stage")

    def test_xray_preflight_fallback_preserves_healthy_stealth_or_persists_direct(self):
        bash_major = int(
            subprocess.run(
                ["bash", "-c", "printf %s \"${BASH_VERSINFO[0]}\""],
                text=True,
                stdout=subprocess.PIPE,
                check=True,
            ).stdout
        )
        if bash_major < 4:
            self.skipTest("The Core sync agent requires Bash 4 associative arrays.")
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            output = root / "stage"
            stage(SOURCE, output)
            agent = root / "wins-core-sync-no-main"
            agent.write_text(
                (output / "wins-core-sync")
                .read_text(encoding="utf-8")
                .replace('\nmain "$@"\n', "\n"),
                encoding="utf-8",
            )
            state = root / "state"
            state.mkdir()
            harness = root / "fallback-test.sh"
            harness.write_text(
                r'''#!/usr/bin/env bash
set -Eeuo pipefail
agent="$1"
state_dir="$2"
CORE_ENV_FILE=/dev/null
# shellcheck disable=SC1090
source "${agent}"
state_file="${state_dir}/corex3.transport"
health=1
existing_stealth_transport_is_healthy() { ((health == 1)); }

CORE_EXIT_TRANSPORT_MODE=stealth
preserved="$(fallback_exit_endpoint_after_xray_preflight_failure \
  wins-core-exit-corex3 corex3 43003 direct.example:9210 "${state_file}" \
  stealth 0 200 100)"
[[ "${preserved}" == "127.0.0.1:43003" ]]
grep -Fxq 'mode=stealth' "${state_file}"

health=0
CORE_EXIT_TRANSPORT_MODE=auto
direct="$(fallback_exit_endpoint_after_xray_preflight_failure \
  wins-core-exit-corex3 corex3 43003 direct.example:9210 "${state_file}" \
  stealth 1 300 100)"
[[ "${direct}" == "direct.example:9210" ]]
grep -Fxq 'mode=direct' "${state_file}"
grep -Fxq 'direct_started_epoch=300' "${state_file}"

CORE_EXIT_TRANSPORT_MODE=stealth
if fallback_exit_endpoint_after_xray_preflight_failure \
  wins-core-exit-corex3 corex3 43003 direct.example:9210 "${state_file}" \
  stealth 0 400 100 >/dev/null 2>&1; then
  echo 'forced stealth unexpectedly downgraded to direct' >&2
  exit 1
fi
''',
                encoding="utf-8",
            )
            completed = subprocess.run(
                ["bash", str(harness), str(agent), str(state)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=20,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)

    def test_existing_stealth_health_checks_config_unit_endpoint_and_handshake(self):
        source = SOURCE.read_text(encoding="utf-8")
        for guard in (
            'existing_stealth_transport_is_healthy() {',
            '[[ -s "${config}" ]] || return 1',
            'xray -test -config "${config}" >/dev/null || return 1',
            'systemctl is-active --quiet "${service}" || return 1',
            'awg show "${iface}" endpoints',
            '[[ "${endpoint_summary}" == "1:1" ]] || return 1',
            'exit_handshake_is_fresh "${container}" "${iface}"',
        ):
            self.assertIn(guard, source)

    def test_runtime_diagnostics_are_class_only_and_never_interpolate_values(self):
        source = SOURCE.read_text(encoding="utf-8")
        diagnostics = re.findall(
            r'warn "(Core (?:runtime validation|assignment synchronization|exit setup|handshake recovery) failed class=[a-z_]+)"',
            source,
        )
        self.assertGreaterEqual(len(diagnostics), len(REQUIRED_MARKERS))
        for diagnostic in diagnostics:
            self.assertNotIn("${", diagnostic)
            self.assertRegex(
                diagnostic,
                r'^Core (?:runtime validation|assignment synchronization|exit setup|handshake recovery) failed class=[a-z_]+$',
            )

    def test_assignment_key_and_endpoint_validators_refuse_config_injection(self):
        bash_major = int(
            subprocess.run(
                ["bash", "-c", "printf %s \"${BASH_VERSINFO[0]}\""],
                text=True,
                stdout=subprocess.PIPE,
                check=True,
            ).stdout
        )
        if bash_major < 4:
            self.skipTest("The Core sync agent requires Bash 4 associative arrays.")
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            output = root / "stage"
            stage(SOURCE, output)
            agent = root / "wins-core-sync-no-main"
            agent.write_text(
                (output / "wins-core-sync")
                .read_text(encoding="utf-8")
                .replace('\nmain "$@"\n', "\n"),
                encoding="utf-8",
            )
            harness = root / "validator-test.sh"
            harness.write_text(
                r"""#!/usr/bin/env bash
set -Eeuo pipefail
agent="$1"
CORE_ENV_FILE=/dev/null
# shellcheck disable=SC1090
source "${agent}"
good_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
valid_awg_key "${good_key}"
valid_awg_endpoint "198.51.100.7:9110"
valid_awg_endpoint "exit.example.net:51820"
valid_awg_endpoint "[2001:db8::1]:9110"
valid_awg_endpoint "127.0.0.1:41001"
if valid_awg_key "${good_key}
[Interface]
PostUp = id"; then echo "newline key accepted" >&2; exit 91; fi
if valid_awg_key "short"; then echo "short key accepted" >&2; exit 92; fi
if valid_awg_endpoint "198.51.100.7:9110
PostUp = id"; then echo "newline endpoint accepted" >&2; exit 93; fi
if valid_awg_endpoint "198.51.100.7:0"; then echo "port 0 accepted" >&2; exit 94; fi
if valid_awg_endpoint "198.51.100.7:70000"; then echo "port 70000 accepted" >&2; exit 95; fi
echo VALIDATORS-OK
""",
                encoding="utf-8",
            )
            result = subprocess.run(
                ["bash", str(harness), str(agent)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("VALIDATORS-OK", result.stdout)

    def test_apply_helper_is_rollback_and_hash_guarded(self):
        source = APPLY.read_text(encoding="utf-8")
        for marker in (
            "staged Core sync agent does not match manifest",
            "wins-core-sync.preimage",
            "wins-core-sync.timer.preimage",
            "trap rollback ERR INT TERM EXIT",
            "timeout --signal=TERM",
            "ExecMainStatus",
            "restore_timer",
        ):
            self.assertIn(marker, source)

    def test_relay_never_places_sudo_password_in_command_arguments(self):
        source = RELAY.read_text(encoding="utf-8")
        self.assertIn('input_bytes=(password + "\\n").encode("utf-8")', source)
        self.assertIn("sudo -S -p ''", source)
        self.assertNotIn("password}", source)
        self.assertIn("StrictHostKeyChecking=yes", source)
        self.assertIn("pinned_host_key_missing", source)

    def test_relay_failure_classification_does_not_return_raw_logs(self):
        self.assertEqual(
            classify_apply_failure(b"Transaction failed; restoring preimage", b"details"),
            "remote_transaction_rolled_back",
        )
        self.assertEqual(
            classify_apply_failure(b"", b"Sorry, try again."),
            "sudo_authentication_failed",
        )


if __name__ == "__main__":
    unittest.main()
