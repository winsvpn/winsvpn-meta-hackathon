"""Real ASGI validation with outbound sockets, processes and SMTP prohibited."""
import asyncio
import importlib.metadata
import json
import logging
from pathlib import Path
import shutil
import sqlite3
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "server"))
import test_account_deletion_hub as harness
import test_winn3_serving_hub as serving

harness._install_stubs = lambda: None


def guard(event, args):
    if event in {"socket.connect", "subprocess.Popen"}:
        raise PermissionError("Round 5 ASGI probe prohibits outbound I/O")


sys.addaudithook(guard)


async def post(module, path, payload, headers=None):
    messages = []
    body = json.dumps(payload).encode()
    sent = False
    request_headers = [(b"host", b"localhost"), (b"content-type", b"application/json")]
    request_headers += [(key.lower().encode(), value.encode()) for key, value in (headers or {}).items()]
    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"},
             "http_version": "1.1", "method": "POST", "scheme": "http", "path": path,
             "raw_path": path.encode(), "query_string": b"", "root_path": "", "headers": request_headers,
             "client": ("127.0.0.1", 12345), "server": ("localhost", 80)}

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        await asyncio.Event().wait()

    async def send(message):
        messages.append(message)

    await module.app(scope, receive, send)
    status = next(message["status"] for message in messages if message["type"] == "http.response.start")
    raw = b"".join(message.get("body", b"") for message in messages if message["type"] == "http.response.body")
    return status, json.loads(raw)


async def run():
    module = harness.load_hub()
    for handler in list(module.logger.handlers):
        handler.close()
        module.logger.removeHandler(handler)
    module.logger.addHandler(logging.NullHandler())
    module.logger.propagate = False
    module.security_alert = lambda *args, **kwargs: None
    module.paypal_enabled = lambda: True
    module.PAYPAL_WEBHOOK_ID = "test-webhook"
    module.PAYPAL_PLAN_1M = "test-plan"
    owner = threading.get_ident()
    provider_threads = []

    def signature(*args):
        provider_threads.append(threading.get_ident())
        time.sleep(0.15)
        return True

    def subscription(sub_id):
        provider_threads.append(threading.get_ident())
        time.sleep(0.15)
        return {"id": sub_id, "status": "ACTIVE", "plan_id": "test-plan",
                "subscriber": {"email_address": "buyer@example.test"}}

    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected external effect")

    module.verify_paypal_webhook_signature = signature
    module.fetch_paypal_subscription = subscription
    module.send_account_email = forbidden
    module.smart_router_trigger_for_existing_node = forbidden
    module.smart_router_recommend_node = forbidden
    try:
        harness.seed_account(module, devices=0)
        serving.seed_node(module)
        login = serving.build_login(module, location="auto").model_dump()
        denied, _ = await post(module, "/verify", login)
        assert denied == 401, denied
        payload = {"id": "evt-real-asgi", "event_type": "BILLING.SUBSCRIPTION.ACTIVATED",
                   "resource": {"id": "I-ASGI"}}
        async def ticker():
            started = time.monotonic()
            await asyncio.sleep(0.01)
            return time.monotonic() - started
        timer = asyncio.create_task(ticker())
        await asyncio.sleep(0)
        status, result = await post(module, "/webhook/paypal", payload)
        elapsed = await timer
        assert status == 200 and result["created"], (status, result)
        assert elapsed < 0.1, elapsed
        assert all(worker != owner for worker in provider_threads), provider_threads
        with module.get_db() as conn:
            row = conn.execute("SELECT status, sealed_secret FROM activation_delivery_outbox").fetchone()
            assert row["status"] == "pending" and row["sealed_secret"].startswith("wao1|")
        duplicate, result = await post(module, "/webhook/paypal", payload)
        assert duplicate == 200 and result["status"] == "duplicate"
        summary = {"frameworks": {name: importlib.metadata.version(name) for name in ("fastapi", "starlette", "pydantic")},
                   "unauthorizedVerify": denied, "paidWebhook": status, "duplicateWebhook": duplicate,
                   "timerSeconds": round(elapsed, 4), "providerCallsOffLoop": True,
                   "durableQueueBeforeResponse": True, "smtpCalled": False,
                   "lifespanStarted": False, "outboundConnectionsPermitted": False}
        (Path(__file__).parent / "asgi-result.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary, indent=2))
    finally:
        for handler in list(module.logger.handlers):
            handler.close()
            module.logger.removeHandler(handler)
        shutil.rmtree(module._TMPDIR)


if __name__ == "__main__":
    asyncio.run(run())
