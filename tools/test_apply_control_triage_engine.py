from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "apply_control_triage_engine.sh"


class ApplyControlTriageEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = SCRIPT.read_text(encoding="utf-8")

    def test_stage_contract_is_fail_closed(self):
        for marker in (
            'winsvpn-control-triage-staging-v1',
            'wins-triage-v3-local-health-context',
            'publication_authorized',
            'secret_material_present',
            'staging manifest file set is not exact',
            'staged hash mismatch',
        ):
            self.assertIn(marker, self.text)

    def test_database_is_backed_up_and_invariants_are_checked(self):
        for marker in (
            'source.backup(backup)',
            'PRAGMA integrity_check',
            'security_events',
            'security_feedback',
            'human_confirmed',
            'database invariant changed',
        ):
            self.assertIn(marker, self.text)

    def test_suricata_rule_tree_is_hash_locked(self):
        self.assertIn('/var/lib/suricata/rules/suricata.rules', self.text)
        self.assertIn('/var/lib/suricata/rules/wins-local.rules', self.text)
        self.assertGreaterEqual(self.text.count('sha256sum -c --strict "${RULE_HASHES}"'), 2)
        self.assertIn('systemctl is-active --quiet suricata.service', self.text)

    def test_failure_path_restores_files_database_and_unit_state(self):
        for marker in (
            'trap rollback ERR INT TERM EXIT',
            'restoring preimage',
            'rm -f -- "${DB_PATH}-wal" "${DB_PATH}-shm"',
            'restore_unit_state',
            'systemctl daemon-reload',
        ):
            self.assertIn(marker, self.text)

    def test_services_are_quiesced_before_database_backup(self):
        stop_at = self.text.index('systemctl stop "${QUIESCE_UNITS[@]}"')
        backup_at = self.text.index('source.backup(backup)')
        self.assertLess(stop_at, backup_at)


if __name__ == "__main__":
    unittest.main()
