#!/usr/bin/env python3
"""Replay behavioral regressions against saved pre-remediation installer bytes."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'server'))
import test_account_deletion_hub as harness
import test_control_plane_round12 as tests

baseline = json.loads((OUT / 'baseline.json').read_text())
harness.HUB = str(Path(baseline['backup']) / 'server/wins_control_plane_setup_ONETOUCH.sh')
names = {
    tests.AdmissionTests: ['test_missing_route_refuses_before_remote_install',
                          'test_invalid_obfuscation_refuses_before_remote_install',
                          'test_descriptor_eligibility_refusal_precedes_remote_install',
                          'test_capability_refusal_precedes_remote_install',
                          'test_concurrent_activation_has_one_preparer_and_one_assignment'],
    tests.PaymentTests: ['test_inflight_deliveries_retry_but_terminal_duplicates_acknowledge',
                         'test_early_settlement_retries_then_uses_bound_lifetime_price_once',
                         'test_lifetime_purchase_is_not_repriced_at_settlement'],
    tests.SecurityHelperTests: ['test_journal_errors_keep_existing_and_missing_checkpoints',
                               'test_journal_advances_only_after_all_returned_lines_are_processed',
                               'test_sqlite_helpers_close_connections_on_success_and_errors'],
}
suite = unittest.TestSuite(cls(name) for cls, methods in names.items() for name in methods)
result = unittest.TextTestRunner(verbosity=2).run(suite)
failed = sorted({case.id().split(' (', 1)[0] for case, trace in result.failures + result.errors})
summary = dict(tests_run=result.testsRun, failing_assertions=len(result.failures),
               errors=len(result.errors), failed_tests=failed,
               expected='All selected behavioral tests must reject old source')
(OUT / 'negative-control-results.json').write_text(json.dumps(summary, indent=2) + '\n')
raise SystemExit(0 if len(failed) == result.testsRun else 1)
