from pathlib import Path
from datetime import timedelta
import asyncio
import importlib.metadata
import json
import logging
import os
import sqlite3
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'server'))
import test_account_deletion_hub as harness
import test_winn3_serving_hub as serving

harness._install_stubs = lambda: None
PATCHED = True


def guard(event, args):
    if event == 'socket.connect' or event == 'subprocess.Popen':
        raise PermissionError('ASGI audit prohibits all outbound connections and process launches')


sys.addaudithook(guard)


def load():
    module = harness.load_hub()
    for handler in list(module.logger.handlers):
        handler.close()
        module.logger.removeHandler(handler)
    module.logger.addHandler(logging.NullHandler())
    module.logger.propagate = False
    harness.seed_account(module, devices=0)
    serving.seed_node(module)
    module.sync_peer_to_node = lambda *args, **kwargs: True
    module.security_alert = lambda *args, **kwargs: None
    module.send_account_email = lambda *args, **kwargs: False
    return module


async def request(module, path, payload=None, headers=None):
    messages = []
    sent = False
    body = json.dumps(payload or {}).encode()
    request_headers = [(b'host', b'localhost'), (b'content-type', b'application/json')]
    request_headers += [(key.lower().encode(), value.encode()) for key, value in (headers or {}).items()]
    scope = {'type': 'http', 'asgi': {'version': '3.0', 'spec_version': '2.4'}, 'http_version': '1.1', 'method': 'GET' if payload is None else 'POST', 'scheme': 'http', 'path': path, 'raw_path': path.encode(), 'query_string': b'', 'root_path': '', 'headers': request_headers, 'client': ('127.0.0.1', 12345), 'server': ('localhost', 80)}

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {'type': 'http.request', 'body': body, 'more_body': False}
        await asyncio.Event().wait()

    async def send(message):
        messages.append(message)

    await module.app(scope, receive, send)
    status = next(message['status'] for message in messages if message['type'] == 'http.response.start')
    raw = b''.join(message.get('body', b'') for message in messages if message['type'] == 'http.response.body')
    try:
        data = json.loads(raw)
    except ValueError:
        data = {}
    return status, data


def login(module, number):
    model = serving.build_login(module, device_id=f'asgi-device-{number:016d}', device_fingerprint=f'asgi-fp-{number:016d}', device_model='audit-harness', selection_generation='a' * 32, ordinary_v3_failure_generation='a' * 32)
    return model.model_dump(mode='json')


async def run():
    module = load()
    with module.get_db() as connection:
        key = module.issue_activation_secret(connection, harness.ACCOUNT)
    statuses = []
    for number in [1, 2]:
        status, data = await request(module, '/verify', login(module, number), {'x-wins-activation': key})
        statuses.append({'status': status, 'bearerReturned': bool(data.get('device_auth_token'))})
    module = load()
    with module.get_db() as connection:
        concurrent_key = module.issue_activation_secret(connection, harness.ACCOUNT)
    concurrent_results = await asyncio.gather(*(
        request(module, '/verify', login(module, number), {'x-wins-activation': concurrent_key})
        for number in range(10, 14)
    ))
    concurrent_statuses = sorted(status for status, data in concurrent_results)
    assert concurrent_statuses == [200, 401, 401, 401], concurrent_statuses
    module = load()
    captured = []

    class Capture(logging.Handler):
        def emit(self, record):
            captured.append(record.getMessage())

    module.logger.addHandler(Capture())
    module.logger.setLevel(logging.INFO)
    injected = login(module, 99)
    injected['account_number'] = harness.ACCOUNT + '\nAUDIT_FORGED_LOG_RECORD'
    status, data = await request(module, '/verify', injected)
    log_probe = {
        'unauthenticatedStatus': status,
        'rawAccountLogged': any(harness.ACCOUNT in message for message in captured),
        'attackerNewlineLogged': any('\nAUDIT_FORGED_LOG_RECORD' in message for message in captured),
    }
    timing = []
    for route in ['/verify', '/free/status', '/account/status', '/legal/current']:
        module = load()
        with module.get_db() as connection:
            key = module.issue_activation_secret(connection, harness.ACCOUNT)
        blocker = sqlite3.connect(module._DB, check_same_thread=False)
        blocker.execute('BEGIN IMMEDIATE')

        def release():
            blocker.rollback()
            blocker.close()

        timer = threading.Timer(.35, release)
        timer.start()

        async def tick():
            start = time.monotonic()
            await asyncio.sleep(.01)
            return time.monotonic() - start

        ticker = asyncio.create_task(tick())
        await asyncio.sleep(0)
        try:
            payload = login(module, 3) if route == '/verify' else {'account_number': harness.ACCOUNT} if route == '/account/status' else None
            status, data = await request(module, route, payload, {'x-wins-activation': key})
            timing.append({'route': route, 'status': status, 'timerSeconds': round(await ticker, 4)})
        finally:
            timer.join()
    result = {'patched': PATCHED, 'frameworks': {name: importlib.metadata.version(name) for name in ['fastapi', 'starlette', 'pydantic']}, 'activation': statuses, 'concurrentActivation': concurrent_statuses, 'logProbe': log_probe, 'timing': timing, 'outboundConnectionsPermitted': False, 'lifespanStartupRun': False}
    if PATCHED:
        assert [item['status'] for item in statuses] == [200, 401], result
        assert log_probe == {'unauthenticatedStatus': 401, 'rawAccountLogged': False, 'attackerNewlineLogged': False}, result
        assert all(item['status'] == 200 and item['timerSeconds'] < .15 for item in timing), result
    (OUT / ('asgi_patched.json' if PATCHED else 'asgi_original.json')).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


asyncio.run(run())
