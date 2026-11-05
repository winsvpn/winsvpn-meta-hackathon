#!/usr/bin/env python3
"""Real FastAPI requests with isolated SQLite and controlled remote boundaries."""
import asyncio
import json
import shutil
import threading
from unittest.mock import patch

import httpx
import asgi_fixture as f


def cleanup(module):
    for handler in list(module.logger.handlers):
        handler.close()
        module.logger.removeHandler(handler)
    shutil.rmtree(module._TMPDIR)


def prevalidation():
    results = []
    for column, value in [('obfuscation_json', 'invalid-json'), ('tunnel_gateway_ipv4', '')]:
        module = f.load()
        try:
            activation = f.activate(module)
            with module.get_db() as conn:
                conn.execute(f'UPDATE nodes SET {column}=?', (value,))
            attempts = []
            module.sync_peer_to_node = lambda *args: attempts.append(True) or True
            status, body = f.request(module, f.login(module, 'validation'), activation=activation)
            with module.get_db() as conn:
                devices = conn.execute('SELECT COUNT(*) FROM devices').fetchone()[0]
                repairs = conn.execute('SELECT COUNT(*) FROM peer_revocations').fetchone()[0]
                used = conn.execute('SELECT activation_secret_used_at FROM users').fetchone()[0]
            assert status == 503 and not attempts and devices == 0 and repairs == 0 and used is None
            results.append(dict(field=column, status=status, remote_calls=len(attempts),
                                device_rows=devices, revocation_rows=repairs, activation_consumed=False))
        finally:
            cleanup(module)
    return results


async def concurrency():
    module = f.load()
    waiting = threading.Event()
    release = threading.Event()
    waits = []
    try:
        with module.get_db() as conn:
            conn.execute("UPDATE nodes SET protocol_version='winn/1', protocol_params_json='{}'")
            conn.execute("INSERT INTO core_servers (core_id, exit_public_key, ingress_public_key, "
                         "ingress_endpoint, tunnel_gateway_ipv4, status, runtime_ready) "
                         "VALUES ('fixture-core', ?, ?, '192.0.2.50:9210', '10.9.0.1', 'online', 1)",
                         ('D' * 43 + '=', 'E' * 43 + '='))
            core = dict(conn.execute('SELECT * FROM core_servers').fetchone())
        module.select_double_vpn_core = lambda conn: core
        activation = f.activate(module)

        def ready(core_id, device_id, revision):
            waits.append(device_id)
            waiting.set()
            assert release.wait(15), 'readiness barrier was not released'
            return True

        module._wait_for_core_assignment_ready_sync = ready
        first_login = f.login(module, 'first')
        second_login = f.login(module, 'second', key_byte=b'F')
        first_login.double_vpn = second_login.double_vpn = True
        headers = {'x-wins-activation': activation}
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=module.app), base_url='https://audit.invalid') as client:
            first = asyncio.create_task(client.post('/verify', headers=headers, json=first_login.model_dump()))
            try:
                assert await asyncio.to_thread(waiting.wait, 5), 'first request never reached readiness'
                second = await client.post('/verify', headers=headers, json=second_login.model_dump())
                assert second.status_code == 409, second.status_code
                assert second.headers['x-wins-error-code'] == 'double_vpn_enrollment_in_flight'
            finally:
                release.set()
            first_response = await first
        assert first_response.status_code == 200, first_response.status_code
        with module.get_db() as conn:
            devices = conn.execute('SELECT COUNT(*) FROM devices').fetchone()[0]
            assignments = conn.execute("SELECT COUNT(*) FROM double_vpn_assignments WHERE status='active'").fetchone()[0]
            leases = conn.execute('SELECT COUNT(*) FROM double_vpn_enrollment_leases').fetchone()[0]
        assert (devices, assignments, leases, len(waits)) == (1, 1, 0, 1)
        return dict(first_status=200, second_status=409, retry_after=second.headers['retry-after'],
                    devices=devices, active_assignments=assignments, remaining_leases=leases, preparers=len(waits))
    finally:
        release.set()
        cleanup(module)


async def payments():
    module = f.load()
    try:
        module.btcpay_enabled = module.paypal_enabled = lambda: True
        module.verify_btcpay_webhook_signature = module.verify_paypal_webhook_signature = lambda *args: True
        module.PAYPAL_WEBHOOK_ID = 'fixture-webhook'
        module.PAYPAL_LIFETIME_NO_SUPPORT_AMOUNT = '20.00'
        module.PAYPAL_LIFETIME_CURRENCY = 'USD'
        with module.get_db() as conn:
            conn.execute("INSERT INTO payment_orders(hub_order_id,provider,provider_order_id,plan_key,"
                         "expected_amount,expected_currency,buyer_email,status,created_at) "
                         "VALUES ('fixture-order','btcpay','fixture-invoice','lifetime_no_support',"
                         "'10.00','USD','fixture-payment@example.test','pending',?)", (module.utcnow().isoformat(),))
            module.reserve_paypal_event(conn, 'fixture-paypal', 'UNSUPPORTED', '')
        invoice = dict(id='fixture-invoice', status='Settled', amount='10.00', paidAmount='10.00', currency='USD',
                       metadata=dict(hub_order_id='fixture-order', plan_key='lifetime_no_support',
                                     buyerEmail='fixture-payment@example.test'))
        deliveries = [dict(invoice, status='Processing'), invoice]
        module.btcpay_fetch_invoice = lambda invoice_id: deliveries.pop(0)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=module.app), base_url='https://audit.invalid') as client:
            paypal_body = {'id': 'fixture-paypal', 'event_type': 'UNSUPPORTED', 'resource': {}}
            inflight = await client.post('/webhook/paypal', json=paypal_body)
            assert inflight.status_code == 409, inflight.status_code
            assert inflight.headers['retry-after'] == '10'
            with module.get_db() as conn:
                module.finish_paypal_event(conn, 'fixture-paypal', 'processed')
            duplicate = await client.post('/webhook/paypal', json=paypal_body)
            assert duplicate.status_code == 200 and duplicate.json()['status'] == 'duplicate'
            early = await client.post('/webhook/btcpay', json={'type': 'InvoicePaymentSettled', 'invoiceId': 'fixture-invoice'})
            assert early.status_code == 409, early.status_code
            assert early.headers['retry-after'] == '10'
            settled = await client.post('/webhook/btcpay', json={'type': 'InvoiceSettled', 'invoiceId': 'fixture-invoice'})
            assert settled.status_code == 200 and settled.json()['created'] is True, settled.status_code
            repeat = await client.post('/webhook/btcpay', json={'type': 'InvoiceSettled', 'invoiceId': 'fixture-invoice'})
            assert repeat.status_code == 200 and repeat.json()['status'] == 'duplicate'
        with module.get_db() as conn:
            jobs = conn.execute('SELECT COUNT(*) FROM activation_delivery_outbox').fetchone()[0]
            state = conn.execute("SELECT status FROM payment_orders WHERE hub_order_id='fixture-order'").fetchone()[0]
        assert jobs == 1 and state == 'settled' and not deliveries
        return dict(paypal_inflight=409, paypal_duplicate=200, early_btcpay=409,
                    settled_btcpay=200, duplicate_btcpay=200, provider_reads=2,
                    bound_price='10.00 USD', catalog_price='20.00 USD', outbox_rows=jobs, order_state=state)
    finally:
        cleanup(module)


async def parked_background_tasks(self):
    return None


if __name__ == '__main__':
    with patch('starlette.background.BackgroundTasks.__call__', new=parked_background_tasks):
        results = dict(prevalidation=prevalidation(), concurrency=asyncio.run(concurrency()),
                       payments=asyncio.run(payments()))
    (f.OUT / 'asgi-results.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(results, indent=2))
