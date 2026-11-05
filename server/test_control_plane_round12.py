#!/usr/bin/env python3
"""Round 12 regressions on generated production code and isolated SQLite.

Remote nodes, payment providers, journalctl and alert delivery are controlled
boundaries. No live account, journal, host identity or service is accessed.
"""
import _toolchain  # noqa: F401
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

import test_account_deletion_hub as harness
import test_control_plane_round10 as round10
import test_control_plane_round11 as round11
import test_control_plane_round5 as round5
import test_winn3_descriptor_hub as descriptor


def set_up_hub(test):
    round10.Round10Tests.setUp(test)

    class HeaderHTTPException(harness.HTTPException):
        def __init__(self, status_code, detail=None, headers=None):
            super().__init__(status_code=status_code, detail=detail)
            self.headers = headers or {}

    test.mod.HTTPException = HeaderHTTPException


class AdmissionTests(unittest.TestCase):
    setUp = set_up_hub
    cleanup = round10.Round10Tests.cleanup
    device = round10.Round10Tests.device
    activate = round11.Round11Tests.activate
    seed_core = round11.Round11Tests.seed_core
    verify = round11.Round11Tests.verify
    used = round11.Round11Tests.used

    def refuse_before_install(self, sql, status=503):
        self.activate()
        with self.mod.get_db() as conn:
            conn.execute(sql)
        installed = []
        with self.assertRaises(harness.HTTPException) as caught:
            self.verify(double=False, sync=lambda *args: installed.append(args) or True)
        self.assertEqual(caught.exception.status_code, status)
        self.assertEqual(installed, [])
        self.assertIsNone(self.used())
        with self.mod.get_db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM peer_revocations").fetchone()[0], 0)

    def test_missing_route_refuses_before_remote_install(self):
        self.refuse_before_install("UPDATE nodes SET tunnel_gateway_ipv4=''")

    def test_invalid_obfuscation_refuses_before_remote_install(self):
        self.refuse_before_install("UPDATE nodes SET obfuscation_json='invalid-json'")

    def test_descriptor_eligibility_refusal_precedes_remote_install(self):
        with patch.object(self.mod, 'resolve_served_winn3_descriptor',
                          side_effect=self.mod.Winn3ContractError('client-dual-auth-downgrade')):
            self.refuse_before_install('SELECT 1')

    def test_capability_refusal_precedes_remote_install(self):
        with patch.object(self.mod, 'request_client_capabilities',
                          side_effect=self.mod.Winn3ContractError('invalid-capability')):
            self.refuse_before_install('SELECT 1', status=400)

    def test_actual_awg_subprocess_timeout_keeps_durable_compensation(self):
        self.activate()
        sync = self.mod.sync_peer_to_node
        attempted = []

        def timeout(host, cfg):
            attempted.append((host, cfg['client_public_key']))
            with patch.object(self.mod.subprocess, 'run', side_effect=subprocess.TimeoutExpired('ssh', 15)):
                return sync(host, cfg)

        with self.assertRaises(harness.HTTPException) as caught:
            self.verify(double=False, sync=timeout)
        self.assertEqual(caught.exception.status_code, 503)
        self.assertEqual(len(attempted), 1)
        self.assertIsNone(self.used())
        with self.mod.get_db() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM devices').fetchone()[0], 0)
            self.assertEqual([tuple(row) for row in conn.execute(
                'SELECT node_ip, client_public_key FROM peer_revocations')], attempted)

    def test_concurrent_activation_has_one_preparer_and_one_assignment(self):
        self.seed_core()
        waiting = threading.Event()
        release = threading.Event()
        waits = []

        def ready(core, device, revision):
            waits.append(device)
            if len(waits) > 1:
                return True
            waiting.set()
            if not release.wait(10):
                raise AssertionError('first enrollment was not released')
            return True

        def enroll(second=False):
            overrides = {}
            if second:
                overrides = dict(device_id='round12-second-device-12345678',
                                 device_fingerprint='round12-second-fingerprint-12345678',
                                 client_public_key='F' * 43 + '=')
            login = descriptor.build_login(self.mod, supports_winn3=True,
                                           supports_winn3_descriptor=True, double_vpn=True, **overrides)
            request = harness.FakeRequest(path='/verify', headers={'x-wins-activation': self.secret})
            return self.mod._verify_account_sync(request, login, harness.BackgroundTasks())

        with patch.object(self.mod, 'sync_peer_to_node', return_value=True), patch.object(
                self.mod, '_wait_for_core_assignment_ready_sync', side_effect=ready):
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(enroll)
                try:
                    self.assertTrue(waiting.wait(5), 'first enrollment never reached readiness')
                    with self.assertRaises(harness.HTTPException) as caught:
                        pool.submit(enroll, True).result(timeout=5)
                    self.assertEqual(caught.exception.status_code, 409)
                    self.assertEqual(caught.exception.headers['X-Wins-Error-Code'],
                                     'double_vpn_enrollment_in_flight')
                    with self.mod.get_db() as conn:
                        self.assertEqual(conn.execute('SELECT COUNT(*) FROM devices').fetchone()[0], 1)
                        self.assertEqual(conn.execute(
                            "SELECT COUNT(*) FROM double_vpn_assignments WHERE status='active'").fetchone()[0], 1)
                finally:
                    release.set()
                result = first.result(timeout=5)
        self.assertEqual(len(waits), 1)
        self.assertTrue(result['device_auth_token'])
        self.assertIsNotNone(self.used())
        with self.mod.get_db() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM double_vpn_enrollment_leases').fetchone()[0], 0)

    def test_failed_preparation_releases_lease_and_preserves_secret(self):
        self.seed_core()

        def fail(*args):
            raise RuntimeError('fixture failure')

        for ready in (lambda *args: False, fail):
            with self.assertRaises((harness.HTTPException, RuntimeError)):
                self.verify(ready=ready)
            self.assertIsNone(self.used())
            with self.mod.get_db() as conn:
                self.assertEqual(conn.execute('SELECT COUNT(*) FROM double_vpn_enrollment_leases').fetchone()[0], 0)
        self.assertTrue(self.verify(ready=lambda *args: True)['device_auth_token'])

    def test_lease_expiry_recovery_and_old_cleanup_cannot_remove_new_owner(self):
        self.seed_core()
        with self.mod.get_db() as conn:
            old = self.mod.acquire_double_vpn_enrollment_lease(conn, harness.ACCOUNT, 'old-device')
            conn.execute('UPDATE double_vpn_enrollment_leases SET expires_at=0')
        with self.mod.get_db() as conn:
            new = self.mod.acquire_double_vpn_enrollment_lease(conn, harness.ACCOUNT, 'new-device')
        self.mod.release_double_vpn_enrollment_lease(harness.ACCOUNT, old)
        with self.mod.get_db() as conn:
            self.assertEqual(conn.execute('SELECT lease_token FROM double_vpn_enrollment_leases').fetchone()[0], new)
        self.mod.release_double_vpn_enrollment_lease(harness.ACCOUNT, new)

    def test_expired_worker_cannot_finish_or_delete_replacement_lease(self):
        self.seed_core()
        replacement = []

        def replace(*args):
            with self.mod.get_db() as conn:
                conn.execute('UPDATE double_vpn_enrollment_leases SET expires_at=0')
                replacement.append(self.mod.acquire_double_vpn_enrollment_lease(
                    conn, harness.ACCOUNT, 'replacement-device'))
            return True

        with self.assertRaises(harness.HTTPException) as caught:
            self.verify(ready=replace)
        self.assertEqual(caught.exception.status_code, 409)
        self.assertIsNone(self.used())
        with self.mod.get_db() as conn:
            self.assertEqual(conn.execute('SELECT lease_token FROM double_vpn_enrollment_leases').fetchone()[0], replacement[0])


class PaymentTests(unittest.TestCase):
    setUp = set_up_hub
    cleanup = round10.Round10Tests.cleanup

    def invoice(self, invoice_id='round12-invoice'):
        return dict(id=invoice_id, status='Settled', amount='10.00', paidAmount='10.00', currency='USD',
                    metadata=dict(hub_order_id='round12-order', plan_key='lifetime_no_support',
                                  buyerEmail='round12@example.test'))

    def seed_order(self):
        self.mod.PAYPAL_LIFETIME_NO_SUPPORT_AMOUNT = '20.00'
        self.mod.PAYPAL_LIFETIME_CURRENCY = 'USD'
        with self.mod.get_db() as conn:
            conn.execute("INSERT INTO payment_orders(hub_order_id,provider,provider_order_id,plan_key,"
                         "expected_amount,expected_currency,buyer_email,status,created_at) "
                         "VALUES ('round12-order','btcpay','round12-invoice','lifetime_no_support',"
                         "'10.00','USD','round12@example.test','pending',?)", (self.mod.utcnow().isoformat(),))

    def btcpay(self, event='InvoiceSettled'):
        with patch.object(self.mod, 'btcpay_enabled', return_value=True), patch.object(
                self.mod, 'verify_btcpay_webhook_signature', return_value=True):
            return asyncio.run(self.mod.btcpay_webhook(round5.WebhookRequest(body={
                'type': event, 'invoiceId': 'round12-invoice'}), harness.BackgroundTasks()))

    def test_inflight_deliveries_retry_but_terminal_duplicates_acknowledge(self):
        self.mod.PAYPAL_WEBHOOK_ID = 'round12-webhook'
        for provider, event_id in (('paypal', 'round12-paypal'), ('btcpay', 'btcpay:round12-invoice')):
            with self.subTest(provider=provider):
                with self.mod.get_db() as conn:
                    self.assertTrue(self.mod.reserve_paypal_event(conn, event_id, 'fixture', ''))

                def invoke():
                    if provider == 'btcpay':
                        return self.btcpay()
                    with patch.object(self.mod, 'paypal_enabled', return_value=True), patch.object(
                            self.mod, 'verify_paypal_webhook_signature', return_value=True):
                        return asyncio.run(self.mod.paypal_webhook(round5.WebhookRequest(body={
                            'id': event_id, 'event_type': 'UNSUPPORTED', 'resource': {}}), harness.BackgroundTasks()))

                with patch.object(self.mod, 'btcpay_fetch_invoice', side_effect=AssertionError('duplicate fetched provider')):
                    with self.assertRaises(harness.HTTPException) as caught:
                        invoke()
                    self.assertEqual(caught.exception.status_code, 409)
                    self.assertEqual(caught.exception.headers['Retry-After'], '10')
                    with self.mod.get_db() as conn:
                        row = conn.execute('SELECT status,attempts FROM paypal_events WHERE event_id=?', (event_id,)).fetchone()
                        self.assertEqual(tuple(row), ('processing', 1))
                    for terminal in ('processed', 'ignored'):
                        with self.mod.get_db() as conn:
                            self.mod.finish_paypal_event(conn, event_id, terminal)
                        self.assertEqual(invoke()['status'], 'duplicate')

    def test_early_settlement_retries_then_uses_bound_lifetime_price_once(self):
        self.seed_order()
        invoice = self.invoice()
        early = dict(invoice, status='Processing')
        with patch.object(self.mod, 'btcpay_fetch_invoice', side_effect=[early, invoice]) as fetch:
            with self.assertRaises(harness.HTTPException) as caught:
                self.btcpay('InvoicePaymentSettled')
            self.assertEqual(caught.exception.status_code, 409)
            with self.mod.get_db() as conn:
                self.assertEqual(conn.execute("SELECT status FROM paypal_events WHERE event_id='btcpay:round12-invoice'").fetchone()[0], 'failed')
            result = self.btcpay()
            self.assertEqual(result['status'], 'ok')
            self.assertTrue(result['created'])
            self.assertEqual(self.btcpay()['status'], 'duplicate')
            self.assertEqual(fetch.call_count, 2)
        with self.mod.get_db() as conn:
            self.assertEqual(conn.execute("SELECT status FROM payment_orders WHERE hub_order_id='round12-order'").fetchone()[0], 'settled')
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM users WHERE email='round12@example.test'").fetchone()[0], 1)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM activation_delivery_outbox').fetchone()[0], 1)

    def test_expired_webhook_lease_can_resume_a_paid_invoice(self):
        self.seed_order()
        with self.mod.get_db() as conn:
            self.mod.reserve_paypal_event(conn, 'btcpay:round12-invoice', 'InvoiceSettled', '')
            conn.execute("UPDATE paypal_events SET lease_until='2000-01-01T00:00:00+00:00'")
        with patch.object(self.mod, 'btcpay_fetch_invoice', return_value=self.invoice()):
            self.assertTrue(self.btcpay()['created'])

    def test_lifetime_purchase_is_not_repriced_at_settlement(self):
        self.seed_order()
        with patch.object(self.mod, 'btcpay_fetch_invoice', return_value=self.invoice()):
            self.assertTrue(self.btcpay()['created'])
            self.assertEqual(self.btcpay()['status'], 'duplicate')
        with self.mod.get_db() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM activation_delivery_outbox').fetchone()[0], 1)

    def test_bound_invoice_still_rejects_underpayment_mismatch_and_nonfinite_amounts(self):
        self.seed_order()
        mutations = [dict(amount='9.99'), dict(paidAmount='9.99'), dict(currency='EUR'),
                     dict(amount='Infinity', paidAmount='Infinity'), dict(paidAmount='NaN'),
                     dict(paidAmount='Infinity'), dict(amount='NaN'),
                     dict(metadata=dict(self.invoice()['metadata'], hub_order_id='foreign-order')),
                     dict(metadata=dict(self.invoice()['metadata'], plan_key='one_month'))]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.mod.get_db() as conn:
                    conn.execute('DELETE FROM paypal_events')
                    conn.execute("UPDATE payment_orders SET status='pending'")
                with patch.object(self.mod, 'btcpay_fetch_invoice', return_value=dict(self.invoice(), **mutation)):
                    with self.assertRaises(RuntimeError):
                        self.btcpay()
                with self.mod.get_db() as conn:
                    self.assertEqual(conn.execute("SELECT status FROM payment_orders WHERE hub_order_id='round12-order'").fetchone()[0], 'manual_review')
                    self.assertEqual(conn.execute('SELECT COUNT(*) FROM activation_delivery_outbox').fetchone()[0], 0)


class SecurityHelperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='round12-security-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        source = Path(harness.HUB).read_text()
        self.source = source

        def load(path, name):
            marker = f"cat > {path} <<'PYEOF'\n"
            code = source.split(marker, 1)[1].split('\nPYEOF', 1)[0]
            code = code.replace('/root/vpn_auth.env', str(self.root / 'absent.env'))
            code = code.replace('/var/lib/wins-security-alerts', str(self.root))
            mod = types.ModuleType(name)
            exec(compile(code, name, 'exec'), mod.__dict__)
            return mod

        with patch.dict(os.environ, {'RATE_LIMIT_SECRET': 'fixture-secret-' * 4,
                                    'SECURITY_EVENTS_DB': str(self.root / 'events.sqlite'),
                                    'WINS_SECURITY_EVENTS_DB': str(self.root / 'events.sqlite')}, clear=True):
            self.triage = load('/usr/local/lib/wins_threat_triage.py', 'wins_threat_triage')
            old_path = sys.path[:]
            try:
                with patch.dict(sys.modules, {'wins_threat_triage': self.triage}):
                    self.monitor = load('/usr/local/bin/wins-security-alert-monitor', 'round12_monitor')
            finally:
                sys.path[:] = old_path

    def test_journal_errors_keep_existing_and_missing_checkpoints(self):
        checkpoint = self.root / 'journal-auth.last'
        failures = [subprocess.CalledProcessError(1, 'journalctl'),
                    subprocess.TimeoutExpired('journalctl', 25), OSError('fixture read failure')]
        for initial in (None, '100'):
            for failure in failures:
                with self.subTest(initial=initial, error=type(failure).__name__):
                    checkpoint.unlink(missing_ok=True)
                    if initial is not None:
                        checkpoint.write_text(initial)
                    with patch.object(self.monitor.time, 'time', return_value=200), patch.object(
                            self.monitor.subprocess, 'run', side_effect=failure) as read:
                        with self.assertRaises(type(failure)):
                            self.monitor.monitor_journal()
                    self.assertTrue(read.call_args.kwargs['check'])
                    self.assertEqual(checkpoint.read_text() if checkpoint.exists() else None, initial)

    def test_journal_advances_only_after_all_returned_lines_are_processed(self):
        checkpoint = self.root / 'journal-auth.last'
        checkpoint.write_text('100')

        def alert(*args):
            self.assertEqual(checkpoint.read_text(), '100')

        output = subprocess.CompletedProcess(['journalctl'], 0, stdout='150 failed password from 192.0.2.1\n')
        with patch.object(self.monitor.time, 'time', return_value=200), patch.object(
                self.monitor.subprocess, 'run', return_value=output), patch.object(
                self.monitor, 'send_alert', side_effect=alert) as sent:
            self.monitor.monitor_journal()
            self.assertEqual(sent.call_count, 1)
        self.assertEqual(checkpoint.read_text(), '200')
        self.assertEqual(list(self.root.glob('.journal-cursor-*')), [])
        checkpoint.write_text('100')
        with patch.object(self.monitor.time, 'time', return_value=200), patch.object(
                self.monitor.subprocess, 'run', return_value=output), patch.object(
                self.monitor, 'send_alert', side_effect=RuntimeError('fixture processing failure')):
            with self.assertRaises(RuntimeError):
                self.monitor.monitor_journal()
        self.assertEqual(checkpoint.read_text(), '100')

    def test_sqlite_helpers_close_connections_on_success_and_errors(self):
        connections = []
        real_connect = sqlite3.connect

        class TrackedConnection(sqlite3.Connection):
            closed = False

            def close(self):
                self.closed = True
                return super().close()

        def connect(*args, **kwargs):
            conn = real_connect(*args, factory=TrackedConnection, **kwargs)
            connections.append(conn)
            return conn

        def assert_closed():
            self.assertTrue(connections)
            for conn in connections:
                self.assertTrue(conn.closed, 'helper retained an open connection')
                with self.assertRaises(sqlite3.ProgrammingError):
                    conn.execute('SELECT 1')

        with patch.object(sqlite3, 'connect', side_effect=connect), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            event = self.monitor.record_event(3, 'failed ssh login', '192.0.2.1', {'fixture': True}, 'fixture')
            self.monitor.update_event_email_status(event, 'fixture-recorded')
            self.monitor.alert_body(3, 'failed ssh login', '192.0.2.1', {}, event)
            self.triage.classify_event('failed ssh login', 3, '192.0.2.1', {})
            self.triage.list_events(5)
            self.triage.report(24)
            with closing(real_connect(self.root / 'events.sqlite')) as conn, conn:
                self.assertEqual(conn.execute('SELECT email_status FROM security_events WHERE event_id=?', (event,)).fetchone()[0], 'fixture-recorded')
                conn.execute("UPDATE security_events SET triage_model_version='fixture-old'")
            self.assertEqual(self.triage.reclassify_events(5, include_stale=True)['processed'], 1)
            with patch.object(self.triage.os, 'geteuid', return_value=0):
                self.triage.submit_feedback(event, 'false_positive', 'Local fixture review only')
                with self.assertRaises(ValueError):
                    self.triage.submit_feedback('missing-event', 'false_positive', 'Local fixture review only')
            assert_closed()
            with patch.object(self.monitor, 'configure_security_events_connection', side_effect=sqlite3.OperationalError('fixture database failure')):
                self.monitor.record_event(3, 'failed ssh login', '192.0.2.1', {}, 'fixture')
                self.monitor.update_event_email_status(event, 'fixture-error')
                self.monitor.alert_body(3, 'failed ssh login', '192.0.2.1', {}, event)
            with patch.object(self.triage, 'configure_security_events_connection', side_effect=sqlite3.OperationalError('fixture database failure')):
                self.triage.classify_event('failed ssh login', 3, '192.0.2.1', {})
                for operation in (lambda: self.triage.list_events(5), lambda: self.triage.report(24),
                                  lambda: self.triage.reclassify_events(5)):
                    with self.assertRaises(sqlite3.OperationalError):
                        operation()
            assert_closed()


if __name__ == '__main__':
    unittest.main()
