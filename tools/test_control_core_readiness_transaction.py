import json
from pathlib import Path
import ast
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools import apply_control_core_readiness as apply_readiness
from tools import stage_control_core_readiness as stage_readiness


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"
STAGER = ROOT / "tools" / "stage_control_core_readiness.py"
APPLIER = ROOT / "tools" / "apply_control_core_readiness.py"


def replace_function(source: str, name: str, replacement: str) -> str:
    start, end, _ = stage_readiness.span(source, name)
    lines = source.splitlines(keepends=True)
    return "".join(lines[:start]) + replacement.rstrip() + "\n\n" + "".join(lines[end:])


def stale_runtime_helper() -> str:
    return '''def apply_core_registration_runtime_state(
    conn,
    core_id,
    reported_revisions,
    now_iso,
    *,
    runtime_ready,
):
    expected_revisions = {
        item["device_id"]: item["assignment_revision"]
        for item in active_core_assignment_payloads(conn, core_id)
    }
    validated_assignment_count = len(reported_revisions)
    runtime_ready = runtime_ready and validated_assignment_count == len(expected_revisions)
    conn.execute(
        "UPDATE core_servers SET runtime_ready=? WHERE core_id=?",
        (1 if runtime_ready else 0, core_id),
    )
    return validated_assignment_count
'''


class ControlCoreReadinessTransactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.canonical = stage_readiness.embedded_main(
            SOURCE.read_text(encoding="utf-8", errors="strict")
        )

    def synthetic_live_with_stale_helper(self) -> str:
        live = replace_function(
            self.canonical,
            "apply_core_registration_runtime_state",
            stale_runtime_helper(),
        )
        return 'UNRELATED_LIVE_SENTINEL = "preserve-me"\n' + live

    def test_build_replaces_stale_runtime_helper_and_preserves_unrelated_live_text(self):
        candidate = stage_readiness.build(
            self.synthetic_live_with_stale_helper(), self.canonical
        )
        self.assertIn('UNRELATED_LIVE_SENTINEL = "preserve-me"', candidate)
        self.assertEqual(
            stage_readiness.function_text(
                candidate, "apply_core_registration_runtime_state"
            ),
            stage_readiness.function_text(
                self.canonical, "apply_core_registration_runtime_state"
            ),
        )
        stage_readiness.validate_candidate_contract(candidate)
        apply_readiness.validate_candidate_contract(candidate)

    def test_both_gates_reject_the_stale_snapshot_runtime_semantics(self):
        stale = self.synthetic_live_with_stale_helper()
        with self.assertRaisesRegex(RuntimeError, "runtime_snapshot_semantics"):
            stage_readiness.validate_candidate_contract(stale)
        with self.assertRaisesRegex(RuntimeError, "candidate_semantic_contract_failed"):
            apply_readiness.validate_candidate_contract(stale)

    def test_both_gates_reject_retry_headers_on_a_general_core_error(self):
        marker = (
            'raise HTTPException(status_code=503, detail="Selected Double VPN exit node '
            'is not ready. Please try again in a minute.")'
        )
        replacement = (
            'raise HTTPException(status_code=503, detail="Selected Double VPN exit node '
            'is not ready. Please try again in a minute.", headers={\n'
            '                    "X-Wins-Error-Code": "double_vpn_assignment_preparing",\n'
            '                    "Retry-After": "5",\n'
            '                })'
        )
        self.assertEqual(self.canonical.count(marker), 1)
        overbroad = self.canonical.replace(marker, replacement, 1)
        with self.assertRaisesRegex(RuntimeError, "headers_not_scoped"):
            stage_readiness.validate_candidate_contract(overbroad)
        with self.assertRaisesRegex(RuntimeError, "candidate_semantic_contract_failed"):
            apply_readiness.validate_candidate_contract(overbroad)

    def test_stage_gate_allows_distinct_fail_closed_retry_errors(self):
        verification_fn = (
            "_verify_account_sync"
            if stage_readiness.has_top_level(self.canonical, "_verify_account_sync")
            else "verify_account"
        )
        verification = stage_readiness.function_text(
            self.canonical, verification_fn
        )
        self.assertGreater(
            verification.count('"X-Wins-Error-Code"'), 1,
            "fixture must cover independent retry errors",
        )
        stage_readiness.validate_candidate_contract(self.canonical)
        apply_readiness.validate_candidate_contract(self.canonical)

    def test_both_gates_reject_reactivation_that_preserves_stale_ack(self):
        self.assertEqual(self.canonical.count("applied_revision=CASE"), 1)
        stale = self.canonical.replace(
            "applied_revision=CASE",
            "applied_revision=double_vpn_assignments.applied_revision, "
            "stale_ack_guard=CASE",
            1,
        )
        with self.assertRaisesRegex(
            RuntimeError, "assignment_reactivation_invalidation_incomplete"
        ):
            stage_readiness.validate_candidate_contract(stale)
        with self.assertRaisesRegex(RuntimeError, "candidate_semantic_contract_failed"):
            apply_readiness.validate_candidate_contract(stale)

    def test_single_to_double_reactivation_clears_stale_acknowledgement(self):
        verification_fn = (
            "_verify_account_sync"
            if stage_readiness.has_top_level(self.canonical, "_verify_account_sync")
            else "verify_account"
        )
        verification = stage_readiness.function_text(
            self.canonical, verification_fn
        )
        tree = ast.parse(verification)
        sql_values = [
            node.args[0].value
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "execute"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ]
        upsert = next(
            value
            for value in sql_values
            if "INSERT INTO double_vpn_assignments" in value
            and "ON CONFLICT(device_id) DO UPDATE SET" in value
        )
        deactivate = next(
            value
            for value in sql_values
            if "UPDATE double_vpn_assignments SET status='inactive'" in value
            and "WHERE device_id=?" in value
        )
        self.assertIn("applied_revision=CASE", upsert)
        self.assertIn("runtime_validated_at=CASE", upsert)
        self.assertIn("applied_revision=NULL", deactivate)
        self.assertIn("runtime_validated_at=NULL", deactivate)

        db = sqlite3.connect(":memory:")
        db.execute(
            """
            CREATE TABLE double_vpn_assignments (
                device_id TEXT PRIMARY KEY,
                account_number TEXT,
                core_id TEXT,
                exit_slug TEXT,
                client_public_key TEXT,
                client_ip TEXT,
                preshared_key TEXT,
                status TEXT,
                applied_revision TEXT,
                runtime_validated_at TEXT,
                assigned_at TEXT,
                updated_at TEXT
            )
            """
        )
        original = (
            "device", "account", "core", "exit", "public-key", "10.9.1.2",
            "psk", "active", "a" * 64, "2026-07-21T00:00:00+00:00",
            "2026-07-20T00:00:00+00:00", "2026-07-21T00:00:00+00:00",
        )
        db.execute(
            "INSERT INTO double_vpn_assignments VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            original,
        )

        # Single VPN deactivates the row and must invalidate the prior Core
        # acknowledgement before the same assignment is reactivated.
        db.execute(deactivate, ("2026-07-21T00:01:00+00:00", "device"))
        db.execute(
            upsert,
            (
                "device", "account", "core", "exit", "public-key", "10.9.1.2",
                "psk", "2026-07-20T00:00:00+00:00",
                "2026-07-21T00:02:00+00:00",
            ),
        )
        row = db.execute(
            "SELECT status, applied_revision, runtime_validated_at "
            "FROM double_vpn_assignments WHERE device_id='device'"
        ).fetchone()
        self.assertEqual(row, ("active", None, None))

        # An unchanged already-active retry may preserve genuinely current
        # evidence; changing assignment material must invalidate it again.
        db.execute(
            "UPDATE double_vpn_assignments SET applied_revision=?, runtime_validated_at=?",
            ("b" * 64, "2026-07-21T00:03:00+00:00"),
        )
        db.execute(
            upsert,
            (
                "device", "account", "core", "exit", "public-key", "10.9.1.2",
                "psk", "2026-07-20T00:00:00+00:00",
                "2026-07-21T00:04:00+00:00",
            ),
        )
        retained = db.execute(
            "SELECT applied_revision, runtime_validated_at "
            "FROM double_vpn_assignments WHERE device_id='device'"
        ).fetchone()
        self.assertEqual(
            retained, ("b" * 64, "2026-07-21T00:03:00+00:00")
        )
        db.execute(
            upsert,
            (
                "device", "account", "core", "exit", "new-public-key", "10.9.1.2",
                "psk", "2026-07-20T00:00:00+00:00",
                "2026-07-21T00:05:00+00:00",
            ),
        )
        changed = db.execute(
            "SELECT applied_revision, runtime_validated_at "
            "FROM double_vpn_assignments WHERE device_id='device'"
        ).fetchone()
        self.assertEqual(changed, (None, None))
        db.close()

    def test_cli_stage_emits_v5_semantic_manifest_for_synthetic_inputs(self):
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            source = root / "synthetic_setup.sh"
            live = root / "live_main.py"
            output = root / "stage"
            source.write_text(
                '#!/usr/bin/env bash\ncat > "${APP_DIR}/main.py" <<\'PYEOF\'\n'
                + self.canonical
                + "PYEOF\n",
                encoding="utf-8",
            )
            live.write_text(
                self.synthetic_live_with_stale_helper(), encoding="utf-8"
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(STAGER),
                    "--source",
                    str(source),
                    "--live",
                    str(live),
                    "--output",
                    str(output),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            result = json.loads(completed.stdout)
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(result["schema_version"], 2)
            self.assertEqual(
                manifest["semantic_contract"], "core-registration-snapshot-v5"
            )
            self.assertTrue(
                {
                    "core_runtime_snapshot_registration",
                    "assignment_preparation_retry_headers",
                    "assignment_reactivation_ack_invalidation",
                    "core_promotion_latch",
                }.issubset(manifest["changed_regions"])
            )
            apply_readiness.validate_candidate_contract(
                (output / "main.py").read_text(encoding="utf-8", errors="strict")
            )

    def test_build_inserts_runtime_helper_for_partially_deployed_live_source(self):
        partial = self.canonical
        start, end, _ = stage_readiness.span(
            partial, "apply_core_registration_runtime_state", decorators=False
        )
        lines = partial.splitlines(keepends=True)
        partial = "".join(lines[:start]) + "".join(lines[end:])
        self.assertNotIn("def apply_core_registration_runtime_state(", partial)

        candidate = stage_readiness.build(partial, self.canonical)

        self.assertEqual(
            candidate.count("def apply_core_registration_runtime_state("), 1
        )
        stage_readiness.validate_candidate_contract(candidate)

    def test_stage_and_apply_gates_reject_a_missing_core_promotion_contract(self):
        mutations = (
            ('"promoted": promoted,', '"promotion_state_removed": False,'),
            ("AND promoted = 1", "AND promoted IN (0, 1)"),
            (
                'require_admin_token(x_admin_token, request, "promote Double VPN Core")',
                'require_admin_token(None, request, "promote Double VPN Core")',
            ),
            (
                "SET promoted=1, active_promotion_id=?",
                "SET runtime_ready=1, active_promotion_id=?",
            ),
            (
                '"UPDATE core_servers SET promoted=0, runtime_ready=0, "',
                '"UPDATE core_servers SET runtime_ready=0, "',
            ),
        )
        for marker, replacement in mutations:
            with self.subTest(marker=marker):
                self.assertIn(marker, self.canonical)
                mutated = self.canonical.replace(marker, replacement, 1)
                with self.assertRaises(RuntimeError):
                    stage_readiness.validate_candidate_contract(mutated)
                with self.assertRaisesRegex(
                    RuntimeError, "candidate_semantic_contract_failed"
                ):
                    apply_readiness.validate_candidate_contract(mutated)

    def test_apply_path_requires_v2_manifest_and_revalidates_candidate(self):
        source = APPLIER.read_text(encoding="utf-8", errors="strict")
        for marker in (
            'manifest.get("schema_version") != 2',
            'manifest.get("semantic_contract") != SEMANTIC_CONTRACT',
            "validate_candidate_contract(candidate_text)",
            'validate_candidate_contract(MAIN.read_text(encoding="utf-8", errors="strict"))',
            '"semantic_contract": SEMANTIC_CONTRACT',
            '"watchdog_seconds": 180',
            '"database_changes": "additive_schema_only"',
            "if digest(MAIN) != manifest.get(\"preimage_sha256\")",
        ):
            self.assertIn(marker, source)

    def test_apply_rejects_stale_candidate_before_health_or_database_access(self):
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            stage = root / "stage"
            stage.mkdir()
            candidate = stage / "main.py"
            candidate.write_text(
                self.synthetic_live_with_stale_helper(), encoding="utf-8"
            )
            live = root / "live_main.py"
            live.write_text(self.canonical, encoding="utf-8")
            manifest = {
                "schema_version": 2,
                "contract": apply_readiness.STAGE_CONTRACT,
                "semantic_contract": apply_readiness.SEMANTIC_CONTRACT,
                "changed_regions": sorted(apply_readiness.REQUIRED_CHANGED_REGIONS),
                "preimage_sha256": apply_readiness.digest(live),
                "candidate_sha256": apply_readiness.digest(candidate),
                "secret_material_present": False,
                "publication_authorized": False,
            }
            (stage / "manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            with (
                mock.patch.object(apply_readiness, "MAIN", live),
                mock.patch.object(apply_readiness, "DB", root / "unused.db"),
                mock.patch.object(apply_readiness.os, "geteuid", return_value=0),
                mock.patch.object(apply_readiness, "secure_regular"),
                mock.patch.object(apply_readiness, "health_ok") as health,
                mock.patch.object(apply_readiness, "run") as command,
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "candidate_semantic_contract_failed"
                ):
                    apply_readiness.apply(stage)
            health.assert_not_called()
            command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
