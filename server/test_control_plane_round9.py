#!/usr/bin/env python3
"""Round 9 regressions using embedded production code and local SQLite.

Gateway/provider publication is mocked. Descriptor signing uses real OpenSSL;
no account, firewall, provider or remote-node action is performed.
"""
import _toolchain  # noqa: F401
import asyncio
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import shutil
import subprocess
import threading
import time
import types
import unittest
from unittest.mock import patch

import test_account_deletion_hub as harness
import test_winn3_descriptor_hub as descriptor
import test_winn3_serving_hub as serving

INSTALLER = Path(__file__).resolve().parent / 'wins_control_plane_setup_ONETOUCH.sh'
SPA_HELPER_HEAD = "cat > /usr/local/lib/wins_hub_spa_window.py <<'SPAWINDOWEOF'\n"


def load_spa_window_helper():
    """The SPA window helper (H0, D1) exactly as the installer writes it."""
    text = INSTALLER.read_text(encoding='utf-8')
    start = text.index(SPA_HELPER_HEAD) + len(SPA_HELPER_HEAD)
    source = text[start:text.index('\nSPAWINDOWEOF\n', start) + 1]
    namespace = {'__name__': 'wins_hub_spa_window_test'}
    exec(compile(source, 'wins_hub_spa_window.py', 'exec'), namespace)
    return types.SimpleNamespace(**namespace)


class Round9Tests(unittest.TestCase):
    def setUp(self):
        def close_handlers(**kwargs):
            for handler in kwargs.get('handlers', []):
                handler.close()

        with patch('logging.basicConfig', side_effect=close_handlers):
            self.mod = descriptor.load_hub_with_ring(
                DURABILITY_BARRIER_ENABLED=0, DURABILITY_BARRIER_REQUIRED=0,
                WINN3_INNER_POOL_CIDR='10.10.0.0/24', WINN3_CANARY_NODE_SLUG='',
                HIDE_CONTROL_ORIGIN=0,
            )
        self.mod.logger.propagate = False
        self.mod.logger.addHandler(logging.NullHandler())
        self.mod.security_alert = lambda *args, **kwargs: None
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for handler in list(self.mod.logger.handlers):
            handler.close()
            self.mod.logger.removeHandler(handler)
        shutil.rmtree(self.mod._TMPDIR)

    def test_expiry_selector_and_enforcer_agree(self):
        now = datetime(2026, 9, 13, tzinfo=timezone.utc)
        cases = [
            (None, True), ('', True), ('zz-invalid', True), ('Lifetime Access', True),
            (now.isoformat(), True), ('2026-09-13T01:00:00+02:00', True),
            ('2026-09-12T23:30:00-02:00', False), ('2026-09-14T00:00:00Z', False),
        ]
        for value, due in cases:
            with self.subTest(expiration=value):
                harness.seed_account(self.mod, devices=1)
                serving.seed_node(self.mod, slug='test-node')
                with self.mod.get_db() as conn:
                    conn.execute('DELETE FROM peer_revocations')
                    conn.execute('UPDATE users SET expiration_date=?', (value,))
                with patch.object(self.mod, 'utcnow', return_value=now):
                    self.assertEqual(self.mod.sweep_expired_account_runtime(), int(due))
                with self.mod.get_db() as conn:
                    self.assertEqual(conn.execute('SELECT status FROM users').fetchone()[0],
                                     'expired' if due else 'active')
                    self.assertEqual(conn.execute('SELECT COUNT(*) FROM devices').fetchone()[0],
                                     0 if due else 1)
                    self.assertEqual(conn.execute('SELECT COUNT(*) FROM peer_revocations').fetchone()[0],
                                     int(due))

    def test_failed_registry_publication_preserves_activation_for_retry(self):
        harness.seed_account(self.mod, devices=0)
        descriptor.arm_activation(self.mod)
        payload, signature = descriptor.envelope_for(descriptor.descriptor_payload())
        descriptor.seed_node(self.mod, protocol_version='winn/3', protocol_params_json='{}',
                             descriptor_json=json.dumps({'payload': payload, 'sig': signature}))
        request = harness.FakeRequest(path='/verify', headers={
            'x-wins-activation': descriptor.ACTIVATION_SECRET})
        login = descriptor.build_login(self.mod, supports_winn3=True,
                                       supports_winn3_descriptor=True)
        original_digest = self.mod.token_digest(descriptor.ACTIVATION_SECRET)
        publications = []

        def publish(conn, node_ip, slug, **_kwargs):
            self.assertTrue(conn.in_transaction)
            publications.append(self.mod.winn3_peer_registry_document(conn, slug))
            self.assertEqual(len(publications[-1]['peers']), 1)
            # The activation consumption and device are still invisible to readers.
            with self.mod.get_db() as reader:
                self.assertEqual(reader.execute('SELECT COUNT(*) FROM devices').fetchone()[0], 0)
                self.assertEqual(reader.execute('SELECT activation_secret_hash FROM users').fetchone()[0],
                                 original_digest)
            return False

        with patch.object(self.mod, 'sync_peer_to_node', return_value=True), patch.object(
                self.mod, 'sync_winn3_registry_to_node', side_effect=publish):
            with self.assertRaises(harness.HTTPException) as caught:
                asyncio.run(self.mod.verify_account(request, login, harness.BackgroundTasks()))
        self.assertEqual(caught.exception.status_code, 503)
        self.assertEqual(len(publications), 1)
        with self.mod.get_db() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM devices').fetchone()[0], 0)
            row = conn.execute('SELECT activation_secret_hash, activation_secret_used_at FROM users').fetchone()
            self.assertEqual(row[0], original_digest)
            self.assertIsNone(row[1])
            self.assertEqual(conn.execute('SELECT management_status FROM nodes').fetchone()[0], 'failed')
            conn.execute("UPDATE nodes SET management_status='ok'")
        with patch.object(self.mod, 'sync_peer_to_node', return_value=True), patch.object(
                self.mod, 'sync_winn3_registry_to_node', return_value=True):
            result = asyncio.run(self.mod.verify_account(request, login, harness.BackgroundTasks()))
        if hasattr(result, 'body'):
            result = json.loads(result.body)
        self.assertTrue(result['device_auth_token'])
        with self.mod.get_db() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM devices').fetchone()[0], 1)
            self.assertTrue(conn.execute('SELECT activation_secret_used_at FROM users').fetchone()[0])
            self.assertEqual(conn.execute('SELECT device_auth_token_hash FROM devices').fetchone()[0],
                             self.mod.token_digest(result['device_auth_token']))

    def test_ai_rate_limit_real_sqlite_contention_does_not_block_loop(self):
        harness.seed_account(self.mod, devices=0)
        request = harness.FakeRequest(path='/api/site/ai-chat')
        payload = types.SimpleNamespace(message='private credentials', locale='en', history=[])
        original_db = self.mod.get_db

        @contextmanager
        def bounded_wait_db():
            with original_db() as conn:
                conn.execute('PRAGMA busy_timeout=350')
                yield conn

        with self.mod.get_db() as blocker:
            blocker.execute('BEGIN IMMEDIATE')
            with patch.object(self.mod, 'get_db', bounded_wait_db), patch.object(
                    self.mod, 'site_sensitive_question', return_value=True):
                async def exercise():
                    task = asyncio.create_task(self.mod.site_ai_chat(payload, request))
                    start = time.monotonic()
                    await asyncio.sleep(0.05)
                    delay = time.monotonic() - start
                    blocker.rollback()
                    result = await task
                    self.assertEqual(result['mode'], 'guardrail')
                    self.assertLess(delay, 0.25, 'SQLite writer contention blocked the loop')
                asyncio.run(exercise())

    def test_webhooks_run_database_and_provider_work_in_worker(self):
        loop_thread = threading.get_ident()
        original_db = self.mod.get_db
        observed = []

        @contextmanager
        def checked_db():
            self.assertNotEqual(threading.get_ident(), loop_thread)
            observed.append('db')
            with original_db() as conn:
                yield conn

        class Request(harness.FakeRequest):
            async def body(self):
                self_thread = threading.get_ident()
                if self_thread != loop_thread:
                    raise AssertionError('ASGI body read moved off event loop')
                return json.dumps(self._body).encode()

        def fetch(invoice_id):
            self.assertNotEqual(threading.get_ident(), loop_thread)
            observed.append('provider')
            return {'status': 'processing'}

        self.mod.PAYPAL_WEBHOOK_ID = 'test-webhook'
        with patch.object(self.mod, 'get_db', checked_db), patch.object(
                self.mod, 'paypal_enabled', return_value=True), patch.object(
                self.mod, 'verify_paypal_webhook_signature', return_value=True):
            result = asyncio.run(self.mod.paypal_webhook(Request(body={
                'id': 'ROUND9-EVENT', 'event_type': 'UNSUPPORTED', 'resource': {}}),
                harness.BackgroundTasks()))
            self.assertEqual(result['status'], 'ignored')
        with patch.object(self.mod, 'get_db', checked_db), patch.object(
                self.mod, 'btcpay_enabled', return_value=True), patch.object(
                self.mod, 'verify_btcpay_webhook_signature', return_value=True), patch.object(
                self.mod, 'btcpay_fetch_invoice', side_effect=fetch):
            with self.assertRaises(harness.HTTPException) as caught:
                asyncio.run(self.mod.btcpay_webhook(Request(body={
                    'type': 'InvoiceSettled', 'invoiceId': 'ROUND9-INVOICE'}), harness.BackgroundTasks()))
            self.assertEqual(caught.exception.status_code, 409)
        with self.mod.get_db() as conn:
            self.assertEqual(conn.execute(
                "SELECT status FROM paypal_events WHERE event_id='btcpay:ROUND9-INVOICE'"
            ).fetchone()[0], 'failed')
        self.assertIn('db', observed)
        self.assertIn('provider', observed)

    def test_monero_claim_settlement_and_release_stay_off_loop(self):
        owner = threading.get_ident()
        original_db = self.mod.get_db
        calls = []

        @contextmanager
        def checked_db():
            self.assertNotEqual(threading.get_ident(), owner)
            with original_db() as conn:
                yield conn

        def checked(name, result):
            def call(*args):
                self.assertNotEqual(threading.get_ident(), owner)
                calls.append(name)
                return result
            return call

        with patch.object(self.mod, 'get_db', checked_db), patch.object(
                self.mod, 'monero_rpc_enabled', return_value=True), patch.object(
                self.mod, 'acquire_monero_poll_db_lease', side_effect=checked('claim', True)), patch.object(
                self.mod, 'claim_monero_poll_batch', return_value=[
                    {'hub_order_id': 'round9-order', 'subaddress_index': 1}]), patch.object(
                self.mod, 'monero_received_for_index', side_effect=checked('rpc', (1, 1, 'tx'))), patch.object(
                self.mod, 'settle_one_monero_order', side_effect=checked('settle', {'status': 'settled'})), patch.object(
                self.mod, 'release_monero_poll_db_lease', side_effect=checked('release', None)):
            result = asyncio.run(self.mod.run_monero_poll_sweep())
        self.assertEqual(result['settled'], 1)
        self.assertEqual(calls, ['claim', 'rpc', 'settle', 'release'])

    def test_admin_authentication_and_peer_resync_stay_off_loop(self):
        owner = threading.get_ident()
        request = harness.FakeRequest(body={'node_slug': 'round9-node'}, headers={
            'content-type': 'application/json'})
        calls = []
        def checked(name, result):
            def call(*args):
                self.assertNotEqual(threading.get_ident(), owner)
                calls.append((name, args))
                return result
            return call
        with patch.object(self.mod, 'require_admin_token', side_effect=checked('auth', None)), patch.object(
                self.mod, 'resync_active_peers_to_node', side_effect=checked('resync', {'ok': True})):
            result = asyncio.run(self.mod.admin_resync_node_peers(request, 'test-token'))
        self.assertEqual(result, {'ok': True})
        self.assertEqual([name for name, _ in calls], ['auth', 'resync'])
        self.assertEqual(calls[1][1], ('round9-node',))

    # H0 (D1, D4): the rule, its lease and its systemd cleanup timer moved from
    # the hub app into the root SPA helper, so these two tests drive the
    # helper's own open_window, extracted from the installer as shipped.
    def test_spa_arms_unique_systemd_cleanup_before_opening_owned_chain(self):
        helper = load_spa_window_helper()
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            self.assertEqual(kwargs['timeout'], 5)
            return subprocess.CompletedProcess(argv, 0)
        with patch.object(helper.shutil, 'which', side_effect=lambda name: '/usr/sbin/' + name), patch.object(
                helper.subprocess, 'run', side_effect=run):
            helper.open_window('192.0.2.4')
            helper.open_window('192.0.2.4')
        self.assertEqual(len(calls), 4)
        for timer, insert in (calls[:2], calls[2:]):
            self.assertIn('--on-active=20s', timer)
            self.assertIn('--timer-property=AccuracySec=1ms', timer)
            self.assertIn('-D', timer)
            self.assertIn('-I', insert)
            self.assertNotIn('INPUT', timer + insert)
            self.assertIn('WINVPN-HUB-INPUT', timer)
            self.assertIn('WINVPN-HUB-INPUT', insert)
            self.assertEqual(timer[timer.index('--comment') + 1], insert[insert.index('--comment') + 1])
        self.assertNotEqual(calls[0][calls[0].index('--comment') + 1],
                            calls[2][calls[2].index('--comment') + 1])

    def test_spa_schedule_failure_never_opens_and_insert_timeout_removes(self):
        helper = load_spa_window_helper()
        for failure_index in (0, 1):
            calls = []
            def run(argv, **kwargs):
                index = len(calls)
                calls.append(argv)
                if index == failure_index:
                    raise subprocess.TimeoutExpired(argv, 5)
                return subprocess.CompletedProcess(argv, 0)
            with self.subTest(failure_index=failure_index), patch.object(
                    helper.shutil, 'which', side_effect=lambda name: '/usr/sbin/' + name), patch.object(
                    helper.subprocess, 'run', side_effect=run):
                with self.assertRaises(subprocess.TimeoutExpired):
                    helper.open_window('192.0.2.4')
            if failure_index == 0:
                self.assertTrue(all('-I' not in argv for argv in calls))
            self.assertIn('-D', calls[-1])

    def test_spa_datagram_offloads_firewall_and_rejects_replay(self):
        key = b'round9-test-spa-secret'
        self.mod.SPA_HMAC = base64.b64encode(key).decode()
        self.mod.SPA_NONCES.clear()
        data = f'{self.mod.SPA_MARKER}:{int(time.time())}:{"a" * 24}'
        signature = base64.b64encode(self.mod.hmac.new(key, data.encode(), self.mod.hashlib.sha256).digest()).decode().rstrip('=')
        seen = []
        loop_thread = threading.get_ident()
        def opened(ip):
            self.assertNotEqual(threading.get_ident(), loop_thread)
            seen.append(ip)
            return True
        async def exercise():
            protocol = self.mod.SPAParamProtocol()
            packet = (data + signature).encode()
            protocol.datagram_received(packet, ('192.0.2.4', 41000))
            protocol.datagram_received(packet, ('192.0.2.4', 41000))
            await asyncio.gather(*protocol.window_tasks)
        with patch.object(self.mod, 'open_spa_window', side_effect=opened):
            asyncio.run(exercise())
        self.assertEqual(seen, ['192.0.2.4'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
