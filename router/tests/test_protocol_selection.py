import asyncio
import json
import sys
import types
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

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

import main
from fallback import candidate_is_protocol_eligible
from provider_common import advisory_payload, routing_prompt
from schemas import RouteRequest
from security import reset_security_state
from test_router import make_request, provider_decision, signed_request


HMAC_SECRET = "router-test-hmac-secret-0123456789abcdef"
GOOGLE_SECRET = "google-test-secret-0123456789abcdef"
LOCAL_MODEL = "reviewed-gemma-runtime:release"
GOOGLE_MODEL = "reviewed-gemini-model"
TERSE_DECISION_KEYS = {
    "selected_route_id",
    "decision",
    "confidence",
    "reason_codes",
    "source",
}
GENERATION = "generation-01"
STALE_GENERATION = "generation-99"


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


def mixed_candidates(*, v3_reachable=True, v1_reachable=True):
    return [
        {
            "route_id": "v1-node",
            "reachable": v1_reachable,
            "protocol_version": "winn/1",
            "carrier": "amneziawg",
            "v1_engine_order": ["amneziawg", "xray"],
            "handshake_ms": 90,
            "packet_loss_pct": 0.0,
            "jitter_ms": 4,
            "dns_ok": True,
            "recent_failures": 0,
        },
        {
            "route_id": "v3-node",
            "reachable": v3_reachable,
            "protocol_version": "winn/3",
            "carrier": "winn3",
            "handshake_ms": 180,
            "packet_loss_pct": 1.0,
            "jitter_ms": 8,
            "dns_ok": True,
            "recent_failures": 0,
        },
    ]


def assert_terse(body):
    assert set(body) == TERSE_DECISION_KEYS


def test_initial_selection_requires_healthy_winn3(client):
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


def test_malicious_provider_v1_falls_back_to_healthy_winn3(client, monkeypatch):
    async def local(request, timeout_s):
        return provider_decision("v1-node")

    monkeypatch.setattr(main, "decide_local_route", local)
    payload = make_request(
        candidates=mixed_candidates(),
        current="v1-node",
        trigger="distress",
    )
    response = signed_request(client, "POST", "/route", payload)
    assert response.status_code == 200
    body = response.json()
    assert_terse(body)
    assert body["selected_route_id"] == "v3-node"
    assert body["source"] == "fallback"


def test_missing_carrier_is_rejected(client):
    payload = make_request(
        candidates=[
            {
                "route_id": "v3-node",
                "reachable": True,
                "protocol_version": "winn/3",
            }
        ],
        current="v3-node",
    )
    payload["candidates"][0].pop("carrier", None)
    response = signed_request(client, "POST", "/route", payload)
    assert response.status_code == 422


def test_malformed_candidate_json_is_rejected(client):
    payload = make_request()
    body = json.dumps(payload)[:-2].encode("utf-8")
    response = signed_request(client, "POST", "/route", body=body)
    assert response.status_code == 422
    assert response.json()["detail"] == "malformed json"


def test_no_healthy_v3_does_not_select_v1(client):
    payload = make_request(
        candidates=mixed_candidates(v3_reachable=False, v1_reachable=True),
        current="v1-node",
        trigger="connection_initiation",
    )
    response = signed_request(client, "POST", "/route", payload)
    assert response.status_code == 200
    body = response.json()
    assert_terse(body)
    assert body["selected_route_id"] == "v3-node"
    assert body["selected_route_id"] != "v1-node"


def test_stale_fallback_authorization_does_not_select_v1(client):
    payload = make_request(
        candidates=mixed_candidates(v3_reachable=False, v1_reachable=True),
        current="v1-node",
    )
    payload["selection_generation"] = GENERATION
    payload["ordinary_v3_failure_generation"] = STALE_GENERATION
    response = signed_request(client, "POST", "/route", payload)
    assert response.status_code == 200
    body = response.json()
    assert_terse(body)
    assert body["selected_route_id"] == "v3-node"


def test_matching_generation_allows_v1_when_v3_is_unhealthy(client):
    payload = make_request(
        candidates=mixed_candidates(v3_reachable=False, v1_reachable=True),
        current="v3-node",
    )
    payload["selection_generation"] = GENERATION
    payload["ordinary_v3_failure_generation"] = GENERATION
    response = signed_request(client, "POST", "/route", payload)
    assert response.status_code == 200
    body = response.json()
    assert_terse(body)
    assert body["selected_route_id"] == "v1-node"


def test_v1_engine_order_must_be_awg_then_xray(client):
    payload = make_request(
        candidates=[
            {
                "route_id": "v1-node",
                "reachable": True,
                "protocol_version": "winn/1",
                "carrier": "amneziawg",
                "v1_engine_order": ["xray", "amneziawg"],
                "dns_ok": True,
            }
        ],
        current="v1-node",
    )
    response = signed_request(client, "POST", "/route", payload)
    assert response.status_code == 422


def test_empty_v1_engine_order_is_rejected(client):
    payload = make_request(
        candidates=[
            {
                "route_id": "v1-node",
                "reachable": True,
                "protocol_version": "winn/1",
                "carrier": "amneziawg",
                "v1_engine_order": [],
                "dns_ok": True,
            }
        ],
        current="v1-node",
    )
    response = signed_request(client, "POST", "/route", payload)
    assert response.status_code == 422


def test_missing_v1_engine_order_is_rejected(client):
    candidate = mixed_candidates()[0]
    candidate.pop("v1_engine_order")
    payload = make_request(candidates=[candidate], current="v1-node")
    response = signed_request(client, "POST", "/route", payload)
    assert response.status_code == 422


def test_unknown_v1_engine_is_rejected_by_schema():
    candidate = mixed_candidates()[0]
    candidate["v1_engine_order"] = ["amneziawg", "wireguard"]
    payload = make_request(candidates=[candidate], current="v1-node")
    with pytest.raises(ValueError, match="v1_engine_order"):
        RouteRequest.model_validate(payload)


@pytest.mark.parametrize("carrier", ["xray", "wireguard", "winn3"])
def test_v1_candidate_cannot_replace_awg_as_primary_carrier(client, carrier):
    candidate = mixed_candidates()[0]
    candidate["carrier"] = carrier
    payload = make_request(candidates=[candidate], current="v1-node")
    response = signed_request(client, "POST", "/route", payload)
    assert response.status_code == 422


def test_explicit_v1_is_rejected_while_healthy_v3_exists(client, monkeypatch):
    async def forbidden(*args, **kwargs):
        raise AssertionError("AI must not run for explicit selection")

    monkeypatch.setattr(main, "decide_local_route", forbidden)
    payload = make_request(candidates=mixed_candidates(), current="v3-node")
    payload["explicit_route_id"] = "v1-node"
    response = signed_request(client, "POST", "/route", payload)
    assert response.status_code == 422


def test_advisory_prompt_allows_only_protocol_eligible_routes():
    request = RouteRequest.model_validate(
        make_request(
            candidates=mixed_candidates(),
            current="v1-node",
            trigger="distress",
        )
    )
    prompt = routing_prompt(request)
    assert 'Allowed route ids: ["v3-node"]' in prompt
    assert 'Allowed route ids: ["v1-node","v3-node"]' not in prompt
    payload = advisory_payload(request)
    assert [item["route_id"] for item in payload["candidates"]] == ["v3-node"]
    assert payload["current_route_id"] == "v1-node"
    assert '"route_id":"v1-node"' not in json.dumps(payload["candidates"], separators=(",", ":"))


def test_advisory_prompt_allows_v1_only_after_matching_generation():
    payload = make_request(
        candidates=mixed_candidates(v3_reachable=False, v1_reachable=True),
        current="v3-node",
        trigger="distress",
    )
    payload["selection_generation"] = GENERATION
    payload["ordinary_v3_failure_generation"] = GENERATION
    prompt = routing_prompt(RouteRequest.model_validate(payload))
    assert 'Allowed route ids: ["v1-node"]' in prompt
    assert 'Allowed route ids: ["v1-node","v3-node"]' not in prompt


def test_protocol_eligibility_matches_exact_route_id():
    request = RouteRequest.model_validate(
        make_request(candidates=mixed_candidates(), current="v1-node")
    )
    assert candidate_is_protocol_eligible(request, "v3-node") is True
    assert candidate_is_protocol_eligible(request, " v3-node") is False
    assert candidate_is_protocol_eligible(request, "v1-node") is False
