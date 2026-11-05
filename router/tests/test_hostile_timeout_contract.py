"""Hostile and timeout proofs for initiation and distress routing."""
import asyncio
import json
import sys
import threading
import time
import types
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

if "httpx2" not in sys.modules:
    _httpx2 = types.ModuleType("httpx2")

    class _Timeout:
        def __init__(self, *args, **kwargs):
            pass

    class _Limits:
        def __init__(self, *args, **kwargs):
            pass

    class _AsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, *args, **kwargs):
            raise RuntimeError("offline test must not use the network")

        async def get(self, *args, **kwargs):
            raise RuntimeError("offline test must not use the network")

    _httpx2.Timeout = _Timeout
    _httpx2.Limits = _Limits
    _httpx2.AsyncClient = _AsyncClient
    sys.modules["httpx2"] = _httpx2

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import gemini_client
import local_gemma_client
import main
from provider_common import ProviderRouteDecision, load_provider_json
from schemas import RouteRequest
from security import reset_security_state
from test_protocol_selection import mixed_candidates
from test_router import (
    GOOGLE_MODEL,
    GOOGLE_SECRET,
    HMAC_SECRET,
    LOCAL_ARTIFACT_INVENTORY,
    LOCAL_ARTIFACT_ROOT,
    LOCAL_MODEL,
    LOCAL_MODEL_REVISION,
    make_request as _make_request,
    provider_decision,
    signed_request,
)


TERSE_DECISION_KEYS = {
    "selected_route_id",
    "decision",
    "confidence",
    "reason_codes",
    "source",
}


def make_request(*args, **kwargs):
    payload = _make_request(*args, **kwargs)
    for candidate in payload["candidates"]:
        if candidate.get("protocol_version") == "winn/1":
            candidate.setdefault("v1_engine_order", ["amneziawg", "xray"])
    return payload


async def provider_unavailable(request, timeout_s):
    raise RuntimeError("provider unavailable")


async def support_unavailable(question, context, timeout_s):
    raise RuntimeError("support provider unavailable")


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    journal_directory = tmp_path / "replay-journal"
    journal_directory.mkdir(mode=0o700)
    journal_directory.chmod(0o700)
    decision_directory = tmp_path / "decision-log"
    decision_directory.mkdir(mode=0o700)
    decision_directory.chmod(0o700)
    monkeypatch.setenv("SMART_ROUTER_HMAC_SECRET", HMAC_SECRET)
    monkeypatch.setenv(
        "SMART_ROUTER_NONCE_JOURNAL_PATH",
        str(journal_directory / "replay-nonces.sqlite3"),
    )
    monkeypatch.setenv("SMART_ROUTER_GEMMA_MODEL", LOCAL_MODEL)
    monkeypatch.setenv("SMART_ROUTER_GEMMA_MODEL_REVISION", LOCAL_MODEL_REVISION)
    monkeypatch.setenv("SMART_ROUTER_GEMMA_ARTIFACT_ROOT", LOCAL_ARTIFACT_ROOT)
    monkeypatch.setenv(
        "SMART_ROUTER_GEMMA_ARTIFACT_INVENTORY_SHA256",
        LOCAL_ARTIFACT_INVENTORY,
    )
    monkeypatch.setenv("SMART_ROUTER_GEMMA_URL", "http://127.0.0.1:8002")
    monkeypatch.setenv("GEMINI_API_KEY", GOOGLE_SECRET)
    monkeypatch.setenv("GEMINI_MODEL", GOOGLE_MODEL)
    monkeypatch.setenv("DECISIONS_FILE", str(decision_directory / "decisions.jsonl"))
    monkeypatch.delenv("SMART_ROUTER_RATE_LIMIT_REQUESTS", raising=False)
    monkeypatch.delenv("SMART_ROUTER_MAX_BODY_BYTES", raising=False)
    monkeypatch.delenv("SMART_ROUTER_TOTAL_BUDGET_MS", raising=False)
    monkeypatch.delenv("SMART_ROUTER_LOCAL_TIMEOUT_MS", raising=False)
    monkeypatch.delenv("SMART_ROUTER_GOOGLE_TIMEOUT_MS", raising=False)
    monkeypatch.delenv("SMART_ROUTER_NONCE_JOURNAL_MAX_ENTRIES", raising=False)
    monkeypatch.delenv("SMART_ROUTER_NONCE_JOURNAL_MAX_BYTES", raising=False)
    monkeypatch.delenv("SMART_ROUTER_NONCE_JOURNAL_LOCK_TIMEOUT_MS", raising=False)
    monkeypatch.delenv("SMART_ROUTER_DECISION_LOG_MAX_FILE_BYTES", raising=False)
    monkeypatch.delenv("SMART_ROUTER_DECISION_LOG_MAX_FILES", raising=False)
    monkeypatch.delenv("SMART_ROUTER_DECISION_LOG_MAX_TOTAL_BYTES", raising=False)
    monkeypatch.setattr(main, "decide_local_route", provider_unavailable)
    monkeypatch.setattr(main, "decide_google_route", provider_unavailable)
    monkeypatch.setattr(main, "answer_local_support", support_unavailable)
    monkeypatch.setattr(main, "answer_support", support_unavailable)

    async def ready_local_health(timeout_s=0.25):
        return {
            "configured": True,
            "runtime": "vllm",
            "model": LOCAL_MODEL,
            "engine_healthy": True,
            "model_served": True,
            "ready": True,
        }

    monkeypatch.setattr(main, "local_provider_health", ready_local_health)
    main.DECISIONS.clear()
    main.LAST_LOG_ERROR = None
    for state in main.PROVIDER_STATUS.values():
        state["last_error"] = None
        state["last_success"] = None
    main.PROVIDER_SEMAPHORE = asyncio.Semaphore(8)
    reset_security_state()
    yield
    main.DECISIONS.clear()
    reset_security_state()


@pytest.fixture
def client():
    return TestClient(main.app)


def assert_terse(body):
    assert set(body) == TERSE_DECISION_KEYS
    assert "private_key" not in body
    assert "endpoint" not in body
    assert "config" not in body


class _FakeGeminiResponse:
    status_code = 200
    has_redirect_location = False
    headers = {}

    def __init__(self, payload: bytes):
        self._payload = payload

    def raise_for_status(self):
        return None

    async def aiter_raw(self, chunk_size):
        del chunk_size
        yield self._payload


class _FakeGeminiStream:
    def __init__(self, payload: bytes):
        self._payload = payload

    async def __aenter__(self):
        return _FakeGeminiResponse(self._payload)

    async def __aexit__(self, exc_type, exc, tb):
        return False


def _install_gemini_inner(monkeypatch, inner, captured=None):
    payload = json.dumps(
        {"candidates": [{"content": {"parts": [{"text": inner}]}}]}
    ).encode("utf-8")

    class FakeClient:
        def __init__(self, **kwargs):
            if captured is not None:
                captured["constructed"] = True

        def stream(self, method, url, *, follow_redirects, headers, json, timeout=None):
            if captured is not None:
                captured.update(method=method, url=url, headers=headers, body=json)
            return _FakeGeminiStream(payload)

    monkeypatch.setattr(gemini_client.httpx2, "AsyncClient", FakeClient)


def test_unauthenticated_route_never_authorizes_or_logs(client):
    before = list(main.DECISIONS)
    response = client.post("/route", json=make_request(trigger="distress"))
    assert response.status_code == 401
    assert "selected_route_id" not in response.text
    assert list(main.DECISIONS) == before
    assert not Path(main.decisions_file_path()).exists()


def test_initiation_picks_authenticated_winn3_and_never_calls_ai(client, monkeypatch):
    async def forbidden(*args, **kwargs):
        raise AssertionError("AI must not run during connection initiation")

    monkeypatch.setattr(main, "decide_local_route", forbidden)
    monkeypatch.setattr(main, "decide_google_route", forbidden)
    payload = make_request(
        candidates=mixed_candidates(),
        current="v1-node",
        trigger="connection_initiation",
    )
    response = signed_request(client, "POST", "/route", payload)
    assert response.status_code == 200
    body = response.json()
    assert_terse(body)
    assert body["selected_route_id"] == "v3-node"
    assert body["source"] == "fallback"


def test_distress_skips_google_when_not_provisioned(client, monkeypatch):
    calls = []

    async def local(request, timeout_s):
        calls.append("local_gemma")
        raise RuntimeError("local Gemma outage")

    async def google(request, timeout_s):
        calls.append("google_gemini")
        raise AssertionError("Google must not run when unprovisioned")

    monkeypatch.delenv("GEMINI_API_KEY")
    monkeypatch.setattr(main, "decide_local_route", local)
    monkeypatch.setattr(main, "decide_google_route", google)
    response = signed_request(client, "POST", "/route", make_request(trigger="distress"))
    assert response.status_code == 200
    body = response.json()
    assert_terse(body)
    assert body["source"] == "fallback"
    assert calls == ["local_gemma"]
    assert "google_gemini" not in main.DECISIONS[-1]["provider_errors"]


def test_partial_google_config_is_treated_as_unprovisioned(client, monkeypatch):
    calls = []

    async def local(request, timeout_s):
        calls.append("local_gemma")
        raise RuntimeError("local Gemma outage")

    async def google(request, timeout_s):
        calls.append("google_gemini")
        return provider_decision()

    monkeypatch.delenv("GEMINI_MODEL")
    monkeypatch.setattr(main, "decide_local_route", local)
    monkeypatch.setattr(main, "decide_google_route", google)
    response = signed_request(client, "POST", "/route", make_request(trigger="distress"))
    assert response.status_code == 200
    assert response.json()["source"] == "fallback"
    assert calls == ["local_gemma"]


def test_malformed_keep_switch_mismatch_falls_back_immediately(client, monkeypatch):
    calls = []

    async def local(request, timeout_s):
        calls.append("local_gemma")
        return ProviderRouteDecision(
            selected_route_id="demo-route-b",
            decision="keep",
            confidence=0.91,
            reason_codes=["healthier_alternate"],
        )

    async def google(request, timeout_s):
        calls.append("google_gemini")
        raise RuntimeError("Google Gemini API outage")

    monkeypatch.setattr(main, "decide_local_route", local)
    monkeypatch.setattr(main, "decide_google_route", google)
    response = signed_request(client, "POST", "/route", make_request(trigger="distress"))
    assert response.status_code == 200
    body = response.json()
    assert_terse(body)
    assert body["source"] == "fallback"
    assert calls == ["local_gemma", "google_gemini"]


def test_hostile_extra_vpn_fields_and_source_injection_are_rejected(monkeypatch):
    captured = {}
    hostile = json.dumps(
        {
            "selected_route_id": "demo-route-b",
            "decision": "switch",
            "confidence": 0.9,
            "reason_codes": ["healthier_alternate"],
            "source": "explicit",
            "private_key": "forbidden-private-key",
            "endpoint": "203.0.113.9:8443",
        }
    )
    _install_gemini_inner(monkeypatch, hostile, captured)
    with pytest.raises(ValidationError):
        asyncio.run(
            gemini_client.decide_route(RouteRequest.model_validate(make_request()), 0.5)
        )
    assert captured["constructed"] is True


def test_markdown_fence_and_non_text_inner_payloads_fail_closed(monkeypatch):
    fenced = "```json\n" + provider_decision().model_dump_json() + "\n```"
    _install_gemini_inner(monkeypatch, fenced)
    with pytest.raises(RuntimeError, match="no structured content"):
        asyncio.run(
            gemini_client.decide_route(RouteRequest.model_validate(make_request()), 0.5)
        )

    payload = json.dumps(
        {"candidates": [{"content": {"parts": [{"text": {"selected_route_id": "demo-route-b"}}]}}]}
    ).encode("utf-8")

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        def stream(self, method, url, *, follow_redirects, headers, json, timeout=None):
            return _FakeGeminiStream(payload)

    monkeypatch.setattr(gemini_client.httpx2, "AsyncClient", FakeClient)
    with pytest.raises(RuntimeError, match="non-text structured content"):
        asyncio.run(
            gemini_client.decide_route(RouteRequest.model_validate(make_request()), 0.5)
        )


def test_unprovisioned_google_client_does_not_open_a_connection(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY")

    class Boom:
        def __init__(self, *args, **kwargs):
            raise AssertionError("unprovisioned Google must not open a client")

    monkeypatch.setattr(gemini_client.httpx2, "AsyncClient", Boom)
    with pytest.raises(RuntimeError, match="not provisioned"):
        asyncio.run(
            gemini_client.decide_route(RouteRequest.model_validate(make_request()), 0.5)
        )


def test_winn3_with_wrong_carrier_is_rejected(client, monkeypatch):
    async def forbidden(*args, **kwargs):
        raise AssertionError("malformed v3 candidate must not reach AI")

    monkeypatch.setattr(main, "decide_local_route", forbidden)
    monkeypatch.setattr(main, "decide_google_route", forbidden)
    payload = make_request(
        candidates=[
            {
                "route_id": "spoofed-v3",
                "reachable": True,
                "protocol_version": "winn/3",
                "carrier": "amneziawg",
                "dns_ok": True,
            },
            {
                "route_id": "v1-node",
                "reachable": True,
                "protocol_version": "winn/1",
                "carrier": "amneziawg",
                "dns_ok": True,
            },
        ],
        current="v1-node",
    )
    response = signed_request(client, "POST", "/route", payload)
    assert response.status_code == 422


def test_non_ascii_route_id_is_rejected_before_routing(client):
    payload = make_request()
    payload["candidates"][0]["route_id"] = "route-" + chr(0x0430)
    response = signed_request(client, "POST", "/route", payload)
    assert response.status_code == 422


def test_provider_timeout_then_unprovisioned_google_is_immediate_fallback(
    client,
    monkeypatch,
):
    monkeypatch.delenv("GEMINI_API_KEY")
    monkeypatch.setenv("SMART_ROUTER_TOTAL_BUDGET_MS", "250")
    monkeypatch.setenv("SMART_ROUTER_LOCAL_TIMEOUT_MS", "100")
    monkeypatch.setenv("SMART_ROUTER_GOOGLE_TIMEOUT_MS", "900")
    calls = []

    async def hang(request, timeout_s):
        calls.append("local_gemma")
        await asyncio.sleep(5)
        return provider_decision()

    async def google(request, timeout_s):
        calls.append("google_gemini")
        return provider_decision()

    monkeypatch.setattr(main, "decide_local_route", hang)
    monkeypatch.setattr(main, "decide_google_route", google)
    started = time.perf_counter()
    response = signed_request(client, "POST", "/route", make_request(trigger="distress"))
    elapsed = time.perf_counter() - started
    assert response.status_code == 200
    assert response.json()["source"] == "fallback"
    assert calls == ["local_gemma"]
    assert elapsed < 0.45


def test_google_timeout_after_local_outage_uses_deterministic_fallback(
    client,
    monkeypatch,
):
    monkeypatch.setenv("SMART_ROUTER_TOTAL_BUDGET_MS", "250")
    monkeypatch.setenv("SMART_ROUTER_LOCAL_TIMEOUT_MS", "100")
    monkeypatch.setenv("SMART_ROUTER_GOOGLE_TIMEOUT_MS", "100")
    calls = []

    async def local(request, timeout_s):
        calls.append("local_gemma")
        raise RuntimeError("local Gemma outage")

    async def hang(request, timeout_s):
        calls.append("google_gemini")
        await asyncio.sleep(5)
        return provider_decision()

    monkeypatch.setattr(main, "decide_local_route", local)
    monkeypatch.setattr(main, "decide_google_route", hang)
    started = time.perf_counter()
    response = signed_request(client, "POST", "/route", make_request(trigger="distress"))
    elapsed = time.perf_counter() - started
    assert response.status_code == 200
    body = response.json()
    assert_terse(body)
    assert body["source"] == "fallback"
    assert calls == ["local_gemma", "google_gemini"]
    assert elapsed < 0.45
    assert "google_gemini" in main.DECISIONS[-1]["provider_errors"]


def test_google_api_outage_falls_back_without_using_ai_route(client, monkeypatch):
    async def local(request, timeout_s):
        raise RuntimeError("local Gemma outage")

    async def google(request, timeout_s):
        raise RuntimeError("Google Gemini API outage 503")

    monkeypatch.setattr(main, "decide_local_route", local)
    monkeypatch.setattr(main, "decide_google_route", google)
    payload = make_request(
        candidates=mixed_candidates(),
        current="v1-node",
        trigger="distress",
    )
    response = signed_request(client, "POST", "/route", payload)
    assert response.status_code == 200
    body = response.json()
    assert_terse(body)
    assert body["source"] == "fallback"
    assert body["selected_route_id"] == "v3-node"


def test_out_of_set_and_vpn_config_shaped_selection_never_leave_the_closed_set(
    client,
    monkeypatch,
):
    async def local(request, timeout_s):
        return ProviderRouteDecision(
            selected_route_id="not-a-candidate",
            decision="switch",
            confidence=0.99,
            reason_codes=["invented_exit"],
        )

    async def google(request, timeout_s):
        return ProviderRouteDecision(
            selected_route_id="203.0.113.9",
            decision="switch",
            confidence=0.99,
            reason_codes=["raw_endpoint"],
        )

    monkeypatch.setattr(main, "decide_local_route", local)
    monkeypatch.setattr(main, "decide_google_route", google)
    response = signed_request(client, "POST", "/route", make_request(trigger="distress"))
    assert response.status_code == 200
    body = response.json()
    assert_terse(body)
    assert body["source"] == "fallback"
    assert body["selected_route_id"] in {"demo-route-a", "demo-route-b"}
    assert body["selected_route_id"] != "203.0.113.9"
    assert set(main.DECISIONS[-1]["provider_errors"]) == {"local_gemma", "google_gemini"}


def test_duplicate_json_keys_cannot_flip_initiation_into_distress(client, monkeypatch):
    async def forbidden(*args, **kwargs):
        raise AssertionError("duplicate JSON must not reach AI or routing")

    monkeypatch.setattr(main, "decide_local_route", forbidden)
    monkeypatch.setattr(main, "decide_google_route", forbidden)
    payload = make_request(trigger="connection_initiation")
    raw = json.dumps(payload, separators=(",", ":"))
    poisoned = raw[:-1] + ',"trigger":"distress"}'
    assert json.loads(poisoned)["trigger"] == "distress"
    response = signed_request(client, "POST", "/route", body=poisoned.encode("ascii"))
    assert response.status_code == 422
    assert response.json()["detail"] == "duplicate JSON key"
    assert "distress" not in response.text
    assert list(main.DECISIONS) == []


def test_malformed_json_does_not_reflect_body(client):
    secret = "forbidden-private-key-material"
    body = b'{"request_id":"' + secret.encode("ascii")
    response = signed_request(client, "POST", "/route", body=body)
    assert response.status_code == 422
    assert response.json()["detail"] == "malformed json"
    assert secret not in response.text


def test_load_provider_json_rejects_duplicates_nan_and_non_objects():
    with pytest.raises(RuntimeError, match="no structured content"):
        load_provider_json(
            b'{"choices":[{"message":{"content":"A"}}],'
            b'"choices":[{"message":{"content":"B"}}]}',
            "local Gemma",
        )
    with pytest.raises(RuntimeError, match="no structured content"):
        load_provider_json(b'{"foo":NaN}', "local Gemma")
    with pytest.raises(RuntimeError, match="no structured content"):
        load_provider_json(b"[1,2,3]", "local Gemma")


def test_local_duplicate_json_keys_fail_closed(monkeypatch):
    inner = (
        '{"selected_route_id":"not-a-candidate","decision":"switch",'
        '"confidence":0.99,"reason_codes":["invented_exit"],'
        '"selected_route_id":"demo-route-b"}'
    )
    payload = json.dumps(
        {
            "model": LOCAL_MODEL,
            "model_revision": LOCAL_MODEL_REVISION,
            "artifact_inventory_sha256": LOCAL_ARTIFACT_INVENTORY,
            "choices": [{"message": {"content": inner}}],
        }
    ).encode("utf-8")

    class FakeClient:
        def __init__(self, **kwargs):
            del kwargs

        def stream(self, method, path, *, follow_redirects, headers=None, json=None, timeout=None):
            del method, path, follow_redirects, headers, json, timeout
            return _FakeGeminiStream(payload)

    monkeypatch.setattr(local_gemma_client.httpx2, "AsyncClient", FakeClient)
    with pytest.raises(RuntimeError, match="no structured content"):
        asyncio.run(
            local_gemma_client.decide_route(RouteRequest.model_validate(make_request()), 0.5)
        )

    good = provider_decision().model_dump_json()
    envelope = (
        '{"model":"%s","choices":[{"message":{"content":"not-json"}}],'
        '"choices":[{"message":{"content":%s}}]}' % (LOCAL_MODEL, json.dumps(good))
    )

    class EnvelopeClient:
        def __init__(self, **kwargs):
            del kwargs

        def stream(self, method, path, *, follow_redirects, headers=None, json=None, timeout=None):
            del method, path, follow_redirects, headers, json, timeout
            return _FakeGeminiStream(envelope.encode("utf-8"))

    monkeypatch.setattr(local_gemma_client.httpx2, "AsyncClient", EnvelopeClient)
    with pytest.raises(RuntimeError, match="no structured content"):
        asyncio.run(
            local_gemma_client.decide_route(RouteRequest.model_validate(make_request()), 0.5)
        )


def test_gemini_duplicate_json_keys_fail_closed(monkeypatch):
    inner = (
        '{"selected_route_id":"not-a-candidate","decision":"switch",'
        '"confidence":0.99,"reason_codes":["invented_exit"],'
        '"selected_route_id":"demo-route-b"}'
    )
    _install_gemini_inner(monkeypatch, inner)
    with pytest.raises(RuntimeError, match="no structured content"):
        asyncio.run(
            gemini_client.decide_route(RouteRequest.model_validate(make_request()), 0.5)
        )

    good = provider_decision().model_dump_json()
    envelope = (
        '{"candidates":[{"content":{"parts":[{"text":"not-json"}]}}],'
        '"candidates":[{"content":{"parts":[{"text":%s}]}}]}' % json.dumps(good)
    )

    class FakeClient:
        def __init__(self, **kwargs):
            del kwargs

        def stream(self, method, url, *, follow_redirects, headers, json, timeout=None):
            del method, url, follow_redirects, headers, json, timeout
            return _FakeGeminiStream(envelope.encode("utf-8"))

    monkeypatch.setattr(gemini_client.httpx2, "AsyncClient", FakeClient)
    with pytest.raises(RuntimeError, match="no structured content"):
        asyncio.run(
            gemini_client.decide_route(RouteRequest.model_validate(make_request()), 0.5)
        )


def test_gemini_nan_confidence_and_trailing_prose_fail_closed(monkeypatch):
    _install_gemini_inner(
        monkeypatch,
        '{"selected_route_id":"demo-route-b","decision":"switch",'
        '"confidence":NaN,"reason_codes":["healthier_alternate"]}',
    )
    with pytest.raises(RuntimeError, match="no structured content"):
        asyncio.run(
            gemini_client.decide_route(RouteRequest.model_validate(make_request()), 0.5)
        )

    _install_gemini_inner(
        monkeypatch,
        provider_decision().model_dump_json() + "\nnote: also use 203.0.113.9",
    )
    with pytest.raises(RuntimeError, match="no structured content"):
        asyncio.run(
            gemini_client.decide_route(RouteRequest.model_validate(make_request()), 0.5)
        )


def test_route_capacity_exhaustion_uses_deterministic_fallback(client, monkeypatch):
    calls = []

    async def local(request, timeout_s):
        calls.append("local_gemma")
        return provider_decision()

    async def google(request, timeout_s):
        calls.append("google_gemini")
        return provider_decision()

    monkeypatch.setattr(main, "decide_local_route", local)
    monkeypatch.setattr(main, "decide_google_route", google)
    main.PROVIDER_SEMAPHORE = asyncio.Semaphore(0)
    response = signed_request(client, "POST", "/route", make_request(trigger="distress"))
    assert response.status_code == 200
    body = response.json()
    assert_terse(body)
    assert body["source"] == "fallback"
    assert calls == []
    assert "capacity" in main.DECISIONS[-1]["provider_errors"]


def test_storage_admission_wait_counts_against_the_deadline(monkeypatch):
    slots = threading.BoundedSemaphore(1)
    assert slots.acquire(blocking=False)
    monkeypatch.setattr(main, "_STORAGE_SLOTS", slots)
    release_worker = threading.Event()

    def stalled_storage():
        release_worker.wait(timeout=1)

    async def scenario():
        loop = asyncio.get_running_loop()
        loop.call_later(0.18, slots.release)
        started = loop.time()
        with pytest.raises(TimeoutError):
            await main._run_storage_with_deadline(stalled_storage, deadline=started + 0.2)
        return loop.time() - started

    try:
        elapsed = asyncio.run(scenario())
    finally:
        release_worker.set()
    assert elapsed < 0.29


def test_public_ready_burst_does_not_starve_signed_route(monkeypatch):
    monkeypatch.setenv("SMART_ROUTER_TOTAL_BUDGET_MS", "250")
    entered = threading.Event()
    release = threading.Event()
    calls = []
    calls_lock = threading.Lock()
    slots = threading.BoundedSemaphore(main._STORAGE_MAX_WORKERS)
    for _ in range(main._STORAGE_MAX_WORKERS - 1):
        assert slots.acquire(blocking=False)
    monkeypatch.setattr(main, "_STORAGE_SLOTS", slots)

    def slow_ready(*, deadline):
        assert isinstance(deadline, float)
        with calls_lock:
            calls.append(1)
            entered.set()
        release.wait(timeout=1)

    monkeypatch.setattr(main, "replay_journal_ready", slow_ready)
    with TestClient(main.app) as shared_client:
        statuses = []
        workers = [
            threading.Thread(target=lambda: statuses.append(shared_client.get("/ready").status_code))
            for _ in range(4)
        ]
        for worker in workers:
            worker.start()
        try:
            assert entered.wait(timeout=1)
            route = signed_request(shared_client, "POST", "/route", make_request())
            assert route.status_code == 200
        finally:
            release.set()
            for _ in range(main._STORAGE_MAX_WORKERS - 1):
                slots.release()
            for worker in workers:
                worker.join(timeout=2)
        assert all(not worker.is_alive() for worker in workers)
        assert len(calls) == 1
        assert len(statuses) == 4
        assert set(statuses) <= {200, 503}
        ready = shared_client.get("/ready")
        assert ready.status_code == 200
        assert len(calls) == 2


def test_sqlite_admission_stall_fails_closed_without_blocking_live(monkeypatch):
    monkeypatch.setenv("SMART_ROUTER_TOTAL_BUDGET_MS", "250")
    entered = threading.Event()
    release = threading.Event()
    result = {}

    def stalled_admission(nonce, now, ttl, timestamp, *, deadline):
        del nonce, now, ttl, timestamp
        assert isinstance(deadline, float)
        remaining = deadline - time.monotonic()
        assert remaining > 0
        entered.set()
        if not release.wait(timeout=remaining):
            raise TimeoutError("replay admission deadline exceeded")
        return main.router_security.ReplayDecision.ACCEPTED

    def request_route():
        started = time.perf_counter()
        result["response"] = signed_request(
            shared_client,
            "POST",
            "/route",
            make_request(),
        )
        result["elapsed"] = time.perf_counter() - started

    monkeypatch.setattr(main.router_security.REPLAY_GUARD, "accept", stalled_admission)
    with TestClient(main.app) as shared_client:
        worker = threading.Thread(target=request_route)
        worker.start()
        try:
            assert entered.wait(timeout=1)
            live_started = time.perf_counter()
            live = shared_client.get("/live")
            live_elapsed = time.perf_counter() - live_started
            worker.join(timeout=1)
            assert not worker.is_alive()
            assert live.status_code == 200
            assert live_elapsed < 0.2
            assert result["response"].status_code == 503
            assert result["response"].json()["detail"] == "routing deadline exceeded"
            assert result["elapsed"] < 0.5
            assert list(main.DECISIONS) == []
        finally:
            release.set()
            worker.join(timeout=1)


def test_decision_log_stall_is_bounded_without_rejecting_valid_route(monkeypatch):
    monkeypatch.setenv("SMART_ROUTER_TOTAL_BUDGET_MS", "250")
    entered = threading.Event()
    release = threading.Event()
    result = {}

    def stalled_append(record):
        del record
        entered.set()
        release.wait(timeout=2)

    def request_route():
        started = time.perf_counter()
        result["response"] = signed_request(
            shared_client,
            "POST",
            "/route",
            make_request(),
        )
        result["elapsed"] = time.perf_counter() - started

    monkeypatch.setattr(main.DECISION_LOG, "append", stalled_append)
    with TestClient(main.app) as shared_client:
        worker = threading.Thread(target=request_route)
        worker.start()
        try:
            assert entered.wait(timeout=1)
            live_started = time.perf_counter()
            live = shared_client.get("/live")
            live_elapsed = time.perf_counter() - live_started
            worker.join(timeout=1)
            assert not worker.is_alive()
            assert live.status_code == 200
            assert live_elapsed < 0.2
            assert result["response"].status_code == 200
            assert result["response"].json()["source"] == "fallback"
            assert result["elapsed"] < 0.5
            assert main.DECISIONS[-1]["decision"]["source"] == "fallback"
            assert main.LAST_LOG_ERROR["kind"] == "TimeoutError"
        finally:
            release.set()
            worker.join(timeout=1)
