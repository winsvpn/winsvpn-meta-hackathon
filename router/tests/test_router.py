import asyncio
import json
import secrets
import sys
import time
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

import gemini_client
import local_gemma_client
import main
from fallback import deterministic_decision
from provider_common import ProviderRouteDecision, provider_payload
from schemas import RouteRequest
from security import PROTECTED_PATHS, reset_security_state, sign_request


HMAC_SECRET = "router-test-hmac-secret-0123456789abcdef"
GOOGLE_SECRET = "google-test-secret-0123456789abcdef"
LOCAL_MODEL = "reviewed-gemma-runtime:release"
LOCAL_MODEL_REVISION = "0123456789abcdef0123456789abcdef01234567"
LOCAL_ARTIFACT_ROOT = "/opt/gemma-artifact"
LOCAL_ARTIFACT_INVENTORY = "f" * 64
GOOGLE_MODEL = "reviewed-gemini-model"


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


NODE_SLUG_PATTERN = r"^[a-z0-9][a-z0-9-]{1,39}$"


@pytest.fixture
def client():
    return TestClient(main.app)


def make_request(candidates=None, current="demo-route-a", trigger="connection_initiation"):
    if candidates is None:
        candidates = [
            {
                "route_id": "demo-route-a",
                "protocol_version": "winn/1",
                "carrier": "amneziawg",
                "v1_engine_order": ["amneziawg", "xray"],
                "reachable": True,
                "handshake_ms": 220,
                "packet_loss_pct": 8.0,
                "jitter_ms": 30,
                "dns_ok": True,
                "recent_failures": 3,
            },
            {
                "route_id": "demo-route-b",
                "protocol_version": "winn/1",
                "carrier": "amneziawg",
                "v1_engine_order": ["amneziawg", "xray"],
                "reachable": True,
                "handshake_ms": 180,
                "packet_loss_pct": 0.5,
                "jitter_ms": 6,
                "dns_ok": True,
                "recent_failures": 0,
            },
        ]
    return {
        "request_id": "request-0001",
        "current_route_id": current,
        "candidates": [dict(item) for item in candidates],
        "signals": {
            "udp_ok": True,
            "tcp443_ok": True,
            "tls_ok": True,
            "control_plane_ok": True,
            "dns_ok": True,
        },
        "trigger": trigger,
    }


def provider_decision(route_id="demo-route-b", confidence=0.87, selected_route_id=None):
    return ProviderRouteDecision(
        selected_route_id=selected_route_id or route_id,
        decision="switch",
        confidence=confidence,
        reason_codes=["healthier_alternate"],
    )


def auth_headers(method, path, body=b"", *, nonce=None, timestamp=None, query=""):
    timestamp_value = str(timestamp if timestamp is not None else int(time.time()))
    nonce_value = nonce or secrets.token_urlsafe(18)
    signature = sign_request(
        HMAC_SECRET,
        method,
        path,
        timestamp_value,
        nonce_value,
        body,
        query=query,
    )
    return {
        "X-Smart-Router-Timestamp": timestamp_value,
        "X-Smart-Router-Nonce": nonce_value,
        "X-Smart-Router-Signature": signature,
    }


def signed_request(client, method, path, payload=None, *, body=None, nonce=None):
    if body is None:
        body = (
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
            if payload is not None
            else b""
        )
    parts = path.split("?", 1)
    base_path = parts[0]
    query = parts[1] if len(parts) > 1 else ""
    headers = auth_headers(method, base_path, body, nonce=nonce, query=query)
    if payload is not None or body:
        headers["Content-Type"] = "application/json"
    return client.request(method, path, content=body, headers=headers)


TERSE_DECISION_KEYS = {
    "selected_route_id",
    "decision",
    "confidence",
    "reason_codes",
    "source",
}


def assert_terse(body):
    assert set(body) == TERSE_DECISION_KEYS
    assert 1 <= len(body["reason_codes"]) <= 3


def test_make_request_fixture_binds_exact_protocol_carrier_policy():
    payload = make_request()
    for candidate in payload["candidates"]:
        assert candidate["protocol_version"] == "winn/1"
        assert candidate["carrier"] == "amneziawg"
        assert candidate["v1_engine_order"] == ["amneziawg", "xray"]

    hostile = {"route_id": "v1-route", "reachable": True}
    explicit = make_request(candidates=[hostile])
    assert explicit["candidates"] == [hostile]


def test_connection_initiation_is_deterministic_and_skips_ai(client, monkeypatch):
    async def forbidden(*args, **kwargs):
        raise AssertionError("AI must not run during normal connection initiation")

    monkeypatch.setattr(main, "decide_local_route", forbidden)
    monkeypatch.setattr(main, "decide_google_route", forbidden)
    response = signed_request(client, "POST", "/route", make_request())

    assert response.status_code == 200
    body = response.json()
    assert_terse(body)
    assert body["source"] == "fallback"
    assert body["selected_route_id"] in {"demo-route-a", "demo-route-b"}
    assert body["reason_codes"] == ["deterministic_fallback"]


def test_distress_uses_local_gemma_first_and_skips_google_after_success(client, monkeypatch):
    calls = []

    async def local(request, timeout_s):
        calls.append("local_gemma")
        return provider_decision()

    async def google(request, timeout_s):
        calls.append("google_gemini")
        raise AssertionError("Google must not run after a valid local decision")

    monkeypatch.setattr(main, "decide_local_route", local)
    monkeypatch.setattr(main, "decide_google_route", google)
    response = signed_request(client, "POST", "/route", make_request(trigger="distress"))

    assert response.status_code == 200
    body = response.json()
    assert_terse(body)
    assert body["source"] == "local_gemma"
    assert body["selected_route_id"] == "demo-route-b"
    assert body["decision"] == "switch"
    assert 0.0 <= body["confidence"] <= 1.0
    assert calls == ["local_gemma"]


def test_distress_local_failure_then_google_valid_uses_exact_order(client, monkeypatch):
    calls = []

    async def local(request, timeout_s):
        calls.append("local_gemma")
        raise TimeoutError("local deadline")

    async def google(request, timeout_s):
        calls.append("google_gemini")
        return provider_decision()

    monkeypatch.setattr(main, "decide_local_route", local)
    monkeypatch.setattr(main, "decide_google_route", google)
    response = signed_request(client, "POST", "/route", make_request(trigger="distress"))

    assert response.status_code == 200
    body = response.json()
    assert_terse(body)
    assert body["source"] == "google_gemini"
    assert body["selected_route_id"] == "demo-route-b"
    assert calls == ["local_gemma", "google_gemini"]


def test_distress_both_providers_fail_uses_deterministic_fallback(client, monkeypatch):
    calls = []

    async def local(request, timeout_s):
        calls.append("local_gemma")
        raise RuntimeError("local unavailable")

    async def google(request, timeout_s):
        calls.append("google_gemini")
        raise RuntimeError("google unavailable")

    monkeypatch.setattr(main, "decide_local_route", local)
    monkeypatch.setattr(main, "decide_google_route", google)
    response = signed_request(client, "POST", "/route", make_request(trigger="distress"))

    assert response.status_code == 200
    body = response.json()
    assert_terse(body)
    assert body["source"] == "fallback"
    assert body["reason_codes"] == ["deterministic_fallback"]
    assert calls == ["local_gemma", "google_gemini"]


def test_provider_outage_keeps_router_ready_and_deterministic(client, monkeypatch):
    calls = []

    async def local_unreachable(request, timeout_s):
        calls.append("local_gemma")
        raise ConnectionError("local provider connection refused")

    async def google_unreachable(request, timeout_s):
        calls.append("google_gemini")
        raise ConnectionError("secondary provider connection refused")

    monkeypatch.setattr(main, "decide_local_route", local_unreachable)
    monkeypatch.setattr(main, "decide_google_route", google_unreachable)

    before = client.get("/ready")
    response = signed_request(client, "POST", "/route", make_request(trigger="distress"))
    after = client.get("/ready")

    assert before.status_code == 200
    assert before.json()["ok"] is True
    assert response.status_code == 200
    body = response.json()
    assert_terse(body)
    assert body["source"] == "fallback"
    assert body["reason_codes"] == ["deterministic_fallback"]
    assert calls == ["local_gemma", "google_gemini"]
    assert after.status_code == 200
    assert after.json()["ok"] is True


def test_out_of_set_and_ineligible_provider_results_are_rejected(client, monkeypatch):
    async def local(request, timeout_s):
        return provider_decision("invented-route")

    async def google(request, timeout_s):
        return provider_decision("demo-route-dead")

    payload = make_request(
        candidates=[
            {
                "route_id": "demo-route-a",
                "reachable": True,
                "dns_ok": True,
                "protocol_version": "winn/1",
                "carrier": "amneziawg",
                "v1_engine_order": ["amneziawg", "xray"],
            },
            {
                "route_id": "demo-route-dead",
                "reachable": False,
                "dns_ok": True,
                "protocol_version": "winn/1",
                "carrier": "amneziawg",
                "v1_engine_order": ["amneziawg", "xray"],
            },
        ],
        trigger="distress",
    )
    monkeypatch.setattr(main, "decide_local_route", local)
    monkeypatch.setattr(main, "decide_google_route", google)
    response = signed_request(client, "POST", "/route", payload)

    assert response.status_code == 200
    assert response.json()["source"] == "fallback"
    assert response.json()["selected_route_id"] == "demo-route-a"
    assert set(main.DECISIONS[-1]["provider_errors"]) == {"local_gemma", "google_gemini"}


def test_hanging_providers_cannot_exceed_total_budget(client, monkeypatch):
    monkeypatch.setenv("SMART_ROUTER_TOTAL_BUDGET_MS", "250")
    monkeypatch.setenv("SMART_ROUTER_LOCAL_TIMEOUT_MS", "100")
    monkeypatch.setenv("SMART_ROUTER_GOOGLE_TIMEOUT_MS", "100")

    async def hang(request, timeout_s):
        await asyncio.sleep(5)
        return provider_decision()

    monkeypatch.setattr(main, "decide_local_route", hang)
    monkeypatch.setattr(main, "decide_google_route", hang)
    started = time.perf_counter()
    response = signed_request(client, "POST", "/route", make_request(trigger="distress"))
    elapsed = time.perf_counter() - started

    assert response.status_code == 200
    assert response.json()["source"] == "fallback"
    assert elapsed < 0.6


def test_authentication_is_required(client):
    response = client.post("/route", json=make_request())
    assert response.status_code == 401


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/"),
        ("POST", "/route"),
        ("POST", "/hoppy/escalate"),
        ("GET", "/decisions"),
        ("GET", "/decisions.csv"),
        ("GET", "/stats"),
        ("GET", "/health"),
    ],
)
def test_bearer_auth_is_inert_on_every_protected_path(client, method, path):
    response = client.request(
        method,
        path,
        json={} if method == "POST" else None,
        headers={"Authorization": f"Bearer {HMAC_SECRET}"},
    )
    assert path in PROTECTED_PATHS
    assert response.status_code == 401
    assert response.json()["detail"] == "authentication required"
    assert "WWW-Authenticate" not in response.headers


def test_bearer_header_does_not_override_valid_hmac_authentication(client):
    headers = auth_headers("GET", "/stats")
    headers["Authorization"] = f"Bearer {HMAC_SECRET}"
    response = client.get("/stats", headers=headers)
    assert response.status_code == 200


def test_live_edge_router_secret_alias_is_mandatory_and_supported(client, monkeypatch):
    monkeypatch.delenv("SMART_ROUTER_HMAC_SECRET")
    monkeypatch.setenv("EDGE_ROUTER_SECRET", HMAC_SECRET)
    assert signed_request(client, "GET", "/stats").status_code == 200

    monkeypatch.delenv("EDGE_ROUTER_SECRET")
    assert signed_request(client, "GET", "/stats").status_code == 503


def test_replayed_authenticated_request_is_rejected(client):
    nonce = secrets.token_urlsafe(18)
    first = signed_request(client, "POST", "/route", make_request(), nonce=nonce)
    second = signed_request(client, "POST", "/route", make_request(), nonce=nonce)
    assert first.status_code == 200
    assert second.status_code == 401
    assert second.json()["detail"] == "replayed request"


def test_oversized_request_is_rejected_before_parsing(client, monkeypatch):
    monkeypatch.setenv("SMART_ROUTER_MAX_BODY_BYTES", "4096")
    body = b"x" * 4097
    response = signed_request(client, "POST", "/route", body=body)
    assert response.status_code == 413


def test_rate_limit_rejects_excess_authenticated_requests(client, monkeypatch):
    monkeypatch.setenv("SMART_ROUTER_RATE_LIMIT_REQUESTS", "2")
    first = signed_request(client, "GET", "/stats")
    second = signed_request(client, "GET", "/stats")
    third = signed_request(client, "GET", "/stats")
    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 429


def test_rate_limited_route_does_not_write_decision_log(client, monkeypatch):
    monkeypatch.setenv("SMART_ROUTER_RATE_LIMIT_REQUESTS", "1")
    first = signed_request(client, "POST", "/route", make_request())
    assert first.status_code == 200
    path = Path(main.decisions_file_path())
    before = path.read_bytes()
    second = signed_request(client, "POST", "/route", make_request())
    assert second.status_code == 429
    assert path.read_bytes() == before
    assert len(main.DECISIONS) == 1


def test_decision_log_symlink_fails_closed_without_blocking_route(client):
    path = Path(main.decisions_file_path())
    victim = path.parent / "victim.txt"
    victim.write_bytes(b"untouched-secret")
    victim.chmod(0o600)
    first = signed_request(client, "POST", "/route", make_request())
    assert first.status_code == 200
    path.unlink()
    path.symlink_to(victim)
    second = signed_request(client, "POST", "/route", make_request())
    assert second.status_code == 200
    assert victim.read_bytes() == b"untouched-secret"
    health = signed_request(client, "GET", "/health")
    assert health.status_code == 200
    assert health.json()["logging_last_error"] is not None
    assert "untouched-secret" not in health.text


def test_invalid_rate_configuration_fails_closed(client, monkeypatch):
    monkeypatch.setenv("SMART_ROUTER_RATE_LIMIT_REQUESTS", "invalid")
    response = signed_request(client, "GET", "/stats")
    assert response.status_code == 503


def test_strict_schema_rejects_extra_secret_fields(client):
    payload = make_request(trigger="distress")
    payload["vpn_private_key"] = "forbidden-private-key"
    response = signed_request(client, "POST", "/route", payload)
    assert response.status_code == 422
    assert "forbidden-private-key" not in response.text
    assert not Path(main.decisions_file_path()).exists()


def test_provider_errors_and_decision_log_scrub_all_server_secrets(client, monkeypatch):
    raw_request_id = "request-secretish-0001"
    payload = make_request(trigger="distress")
    payload["request_id"] = raw_request_id

    async def leaking_error(request, timeout_s):
        raise RuntimeError(f"failure {HMAC_SECRET} {GOOGLE_SECRET}")

    monkeypatch.setattr(main, "decide_local_route", leaking_error)
    monkeypatch.setattr(main, "decide_google_route", leaking_error)
    response = signed_request(client, "POST", "/route", payload)

    assert response.status_code == 200
    raw_log = Path(main.decisions_file_path()).read_text()
    assert HMAC_SECRET not in raw_log
    assert GOOGLE_SECRET not in raw_log
    assert raw_request_id not in raw_log
    assert "[REDACTED]" in raw_log


def test_provider_payload_has_only_bounded_health_input():
    request = RouteRequest.model_validate(make_request())
    payload = provider_payload(request)
    text = json.dumps(payload)
    assert set(payload) == {
        "trigger",
        "current_route_id",
        "candidates",
        "signals",
        "selection_generation",
        "ordinary_v3_failure_generation",
    }
    assert request.request_id not in text
    assert HMAC_SECRET not in text
    assert GOOGLE_SECRET not in text


def test_health_stays_ready_for_deterministic_routing_if_local_model_is_absent(client, monkeypatch):
    monkeypatch.delenv("SMART_ROUTER_GEMMA_MODEL")

    async def not_ready(timeout_s=0.25):
        return {
            "configured": False,
            "runtime": "vllm",
            "model": None,
            "engine_healthy": False,
            "model_served": False,
            "ready": False,
        }

    monkeypatch.setattr(main, "local_provider_health", not_ready)
    response = signed_request(client, "GET", "/health")
    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert response.json()["ordering"] == [
        "deterministic_connection_initiation",
        "local_gemma_distress",
        "google_gemini_distress",
        "deterministic_distress_fallback",
    ]


def test_health_reports_vllm_model_and_google_config_separately(client):
    response = signed_request(client, "GET", "/health")
    assert response.status_code == 200
    body = response.json()
    assert body["providers"]["local_gemma"]["model_served"] is True
    assert body["providers"]["local_gemma"]["model"] == LOCAL_MODEL
    assert body["providers"]["google_gemini"]["configured"] is True
    assert body["providers"]["google_gemini"]["live_checked"] is False


def test_health_provider_probe_respects_shared_capacity(client, monkeypatch):
    calls = []

    async def local_health(timeout_s=0.25):
        calls.append(timeout_s)
        raise AssertionError("health must not bypass provider admission")

    monkeypatch.setattr(main, "local_provider_health", local_health)
    main.PROVIDER_SEMAPHORE = asyncio.Semaphore(0)
    response = signed_request(client, "GET", "/health")
    assert response.status_code == 200
    local = response.json()["providers"]["local_gemma"]
    assert local["ready"] is False
    assert local["error_kind"] == "ProviderCapacityUnavailable"
    assert calls == []


def test_operator_page_states_exact_provider_order(client):
    response = signed_request(client, "GET", "/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    text = response.text
    assert "deterministic Winn v3 first" in text
    assert "Winn v3 deterministic first" in text
    assert "local Gemma on distress" in text
    assert "bounded Google fallback" in text
    assert "aicore Gemma first" not in text
    assert "Gemini adaptive routing" not in text
    stats_fn = text[text.index("function renderStats") : text.index("function renderLast")]
    assert stats_fn.index("const local=") < stats_fn.index("local.model")


def test_public_liveness_exposes_no_provider_or_secret_state(client):
    response = client.get("/live")
    assert response.status_code == 200
    assert set(response.json()) == {"ok", "version"}
    assert response.json()["ok"] is True
    assert HMAC_SECRET not in response.text
    assert GOOGLE_SECRET not in response.text
    assert LOCAL_MODEL not in response.text


def test_public_readiness_matches_live_shape_and_hides_provider_state(client):
    response = client.get("/ready")
    assert response.status_code == 200
    assert set(response.json()) == {"ok", "version"}
    assert response.json()["ok"] is True
    assert HMAC_SECRET not in response.text
    assert GOOGLE_SECRET not in response.text
    assert LOCAL_MODEL not in response.text


def test_public_readiness_fails_closed_without_hmac_secret(client, monkeypatch):
    live = client.get("/live")
    monkeypatch.delenv("SMART_ROUTER_HMAC_SECRET")
    monkeypatch.delenv("EDGE_ROUTER_SECRET", raising=False)
    ready = client.get("/ready")
    assert live.status_code == 200
    assert live.json()["ok"] is True
    assert ready.status_code == 503
    assert set(ready.json()) == {"ok", "version"}
    assert ready.json()["ok"] is False


def test_public_readiness_fails_closed_if_journal_parent_is_world_readable(
    client,
    tmp_path,
    monkeypatch,
):
    journal_directory = tmp_path / "open-journal"
    journal_directory.mkdir(mode=0o755)
    journal_directory.chmod(0o755)
    monkeypatch.setenv(
        "SMART_ROUTER_NONCE_JOURNAL_PATH",
        str(journal_directory / "replay-nonces.sqlite3"),
    )
    response = client.get("/ready")
    assert response.status_code == 503
    assert set(response.json()) == {"ok", "version"}
    assert response.json()["ok"] is False


def test_current_route_must_bind_to_a_candidate_node(client):
    payload = make_request()
    payload["current_route_id"] = "missing-node"
    response = signed_request(client, "POST", "/route", payload)
    assert response.status_code == 422


def test_endpoint_shaped_route_id_is_rejected_before_routing(client):
    payload = make_request()
    payload["candidates"][0]["route_id"] = "203.0.113.9"
    response = signed_request(client, "POST", "/route", payload)
    assert response.status_code == 422


def test_uppercase_or_colon_route_id_is_rejected_before_routing(client):
    payload = make_request()
    payload["candidates"][0]["route_id"] = "Node:A"
    response = signed_request(client, "POST", "/route", payload)
    assert response.status_code == 422


def test_non_loopback_local_model_url_is_rejected(monkeypatch):
    monkeypatch.setenv("SMART_ROUTER_GEMMA_URL", "http://aicore.example:8002")
    with pytest.raises(RuntimeError, match="loopback"):
        local_gemma_client.get_local_url()


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1:8002",
        "http://localhost:8002",
        "http://127.0.0.1:8003",
        "http://127.0.0.1",
        "http://127.0.0.1:80",
        "http://127.0.0.1:8002/v1",
        "http://127.0.0.1:8002?x=1",
        "http://127.0.0.1:8002#frag",
        "http://user@127.0.0.1:8002",
        "http://127.0.0.1:8002/v1/chat/completions/extra",
        "http://0.0.0.0:8002",
        "http://[::ffff:127.0.0.1]:8002",
        "http://127.0.0.1:8002/v1/chat/completions;evil=1",
        "http://127.0.0.1:8002/;session=1",
        "http://127.0.0.1:8002;evil",
        "http://127.0.0.1:8002abc",
        "http://127.0.0.1:notaport",
        "http://127.0.0.1:65536",
    ],
)
def test_hostile_gemma_url_must_be_installer_loopback_http_8002(monkeypatch, url):
    monkeypatch.setenv("SMART_ROUTER_GEMMA_URL", url)
    with pytest.raises(RuntimeError, match="installer loopback HTTP on port 8002"):
        local_gemma_client.get_local_url()
    assert local_gemma_client.local_configured() is False


def test_ipv6_installer_loopback_url_is_canonicalized(monkeypatch):
    monkeypatch.setenv("SMART_ROUTER_GEMMA_URL", "http://[::1]:8002/v1/chat/completions")
    assert local_gemma_client.get_local_url() == "http://[::1]:8002"


def test_malformed_gemma_url_uses_deterministic_fallback_instead_of_500(
    client, monkeypatch
):
    async def forbidden_local(*args, **kwargs):
        raise AssertionError("malformed Gemma URL must not call local Gemma")

    async def forbidden_google(*args, **kwargs):
        raise AssertionError("malformed Gemma URL must fall back without Google")

    monkeypatch.setenv("SMART_ROUTER_GEMMA_URL", "http://127.0.0.1:8002abc")
    monkeypatch.delenv("GEMINI_API_KEY")
    monkeypatch.setattr(main, "decide_local_route", forbidden_local)
    monkeypatch.setattr(main, "decide_google_route", forbidden_google)
    response = signed_request(client, "POST", "/route", make_request(trigger="distress"))
    assert response.status_code == 200
    body = response.json()
    assert_terse(body)
    assert body["source"] == "fallback"
    assert body["reason_codes"] == ["deterministic_fallback"]


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8002/v1/chat/completions;evil=1",
        "http://127.0.0.1:8002;params=1",
        "http://127.0.0.1:65536",
    ],
)
def test_semicolon_or_malformed_port_gemma_url_uses_deterministic_fallback(
    client, monkeypatch, url
):
    monkeypatch.setenv("SMART_ROUTER_GEMMA_URL", url)
    monkeypatch.delenv("GEMINI_API_KEY")
    response = signed_request(client, "POST", "/route", make_request(trigger="distress"))
    assert response.status_code == 200
    assert response.json()["source"] == "fallback"


def test_live_vllm_url_and_gemma_model_aliases_are_normalized(monkeypatch):
    monkeypatch.delenv("SMART_ROUTER_GEMMA_URL")
    monkeypatch.delenv("SMART_ROUTER_GEMMA_MODEL")
    monkeypatch.setenv("VLLM_URL", "http://127.0.0.1:8002/v1/chat/completions")
    monkeypatch.setenv("GEMMA_MODEL", "gemma12b")
    assert local_gemma_client.get_local_url() == "http://127.0.0.1:8002"
    assert local_gemma_client.get_local_model() == "gemma12b"


def test_local_vllm_request_uses_openai_chat_schema_and_no_secrets(monkeypatch):
    captured = {}
    raw_decision = provider_decision().model_dump_json()

    class FakeResponse:
        status_code = 200
        has_redirect_location = False
        headers = {}

        def raise_for_status(self):
            return None

        async def aiter_raw(self, chunk_size):
            del chunk_size
            yield json.dumps({
                "model": LOCAL_MODEL,
                "model_revision": LOCAL_MODEL_REVISION,
                "artifact_inventory_sha256": LOCAL_ARTIFACT_INVENTORY,
                "choices": [{"message": {"content": raw_decision}}],
            }).encode("utf-8")

    class FakeStream:
        async def __aenter__(self):
            return FakeResponse()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class FakeClient:
        def __init__(self, **kwargs):
            captured["client_kwargs"] = kwargs

        def stream(self, method, path, *, follow_redirects, headers=None, json=None, timeout=None):
            captured.update(
                method=method,
                path=path,
                headers=headers,
                body=json,
                timeout=timeout,
                follow_redirects=follow_redirects,
            )
            return FakeStream()

    monkeypatch.setattr(local_gemma_client.httpx2, "AsyncClient", FakeClient)
    decision = asyncio.run(
        local_gemma_client.decide_route(RouteRequest.model_validate(make_request()), 0.5)
    )
    serialized = json.dumps(captured["body"])
    assert decision.selected_route_id == "demo-route-b"
    assert captured["client_kwargs"]["base_url"] == "http://127.0.0.1:8002"
    assert captured["path"] == "/v1/chat/completions"
    assert captured["body"]["model"] == LOCAL_MODEL
    assert captured["body"]["temperature"] == 0
    assert captured["body"]["max_tokens"] == 128
    assert captured["body"]["response_format"]["type"] == "json_schema"
    schema = captured["body"]["response_format"]["json_schema"]["schema"]
    assert schema["additionalProperties"] is False
    assert "title" not in schema
    assert schema["properties"]["selected_route_id"]["pattern"] == NODE_SLUG_PATTERN
    assert HMAC_SECRET not in serialized
    assert GOOGLE_SECRET not in serialized


@pytest.mark.parametrize("provider_path", ["route", "support"])
@pytest.mark.parametrize(
    ("include_model", "response_model"),
    [
        pytest.param(False, None, id="omitted"),
        pytest.param(True, None, id="null"),
        pytest.param(True, False, id="boolean"),
        pytest.param(True, 7, id="number"),
        pytest.param(True, [LOCAL_MODEL], id="array"),
        pytest.param(True, {"id": LOCAL_MODEL}, id="object"),
        pytest.param(True, "unreviewed-other-model", id="wrong-id"),
    ],
)
def test_local_gemma_rejects_response_without_exact_model(
    monkeypatch,
    provider_path,
    include_model,
    response_model,
):
    if provider_path == "route":
        content = provider_decision().model_dump_json()
    else:
        content = json.dumps({"answer": "Ignore me.", "escalated": False})
    envelope = {
        "model": LOCAL_MODEL,
        "model_revision": LOCAL_MODEL_REVISION,
        "artifact_inventory_sha256": LOCAL_ARTIFACT_INVENTORY,
        "choices": [{"message": {"content": content}}],
    }
    if include_model:
        envelope["model"] = response_model
    else:
        del envelope["model"]

    class FakeResponse:
        status_code = 200
        has_redirect_location = False
        headers = {}

        def raise_for_status(self):
            return None

        async def aiter_raw(self, chunk_size):
            del chunk_size
            yield json.dumps(envelope).encode("utf-8")

    class FakeStream:
        async def __aenter__(self):
            return FakeResponse()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class FakeClient:
        def __init__(self, **kwargs):
            del kwargs

        def stream(self, method, path, *, follow_redirects, headers=None, json=None, timeout=None):
            del method, path, follow_redirects, headers, json, timeout
            return FakeStream()

    monkeypatch.setattr(local_gemma_client.httpx2, "AsyncClient", FakeClient)
    with pytest.raises(RuntimeError, match="did not match configured artifact"):
        if provider_path == "route":
            asyncio.run(
                local_gemma_client.decide_route(
                    RouteRequest.model_validate(make_request()), 0.5
                )
            )
        else:
            asyncio.run(local_gemma_client.answer_support("What should I do?", "", 0.5))


@pytest.mark.parametrize(
    ("field", "drifted_value"),
    [
        ("model_revision", "fedcba9876543210fedcba9876543210fedcba98"),
        ("artifact_inventory_sha256", "e" * 64),
    ],
)
def test_local_gemma_rejects_drifted_reviewed_identity(
    monkeypatch,
    field,
    drifted_value,
):
    envelope = {
        "model": LOCAL_MODEL,
        "model_revision": LOCAL_MODEL_REVISION,
        "artifact_inventory_sha256": LOCAL_ARTIFACT_INVENTORY,
        "choices": [
            {"message": {"content": provider_decision().model_dump_json()}}
        ],
    }
    envelope[field] = drifted_value

    class FakeResponse:
        status_code = 200
        has_redirect_location = False
        headers = {}

        def raise_for_status(self):
            return None

        async def aiter_raw(self, chunk_size):
            del chunk_size
            yield json.dumps(envelope).encode("utf-8")

    class FakeStream:
        async def __aenter__(self):
            return FakeResponse()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class FakeClient:
        def __init__(self, **kwargs):
            del kwargs

        def stream(
            self,
            method,
            path,
            *,
            follow_redirects,
            headers=None,
            json=None,
            timeout=None,
        ):
            del method, path, follow_redirects, headers, json, timeout
            return FakeStream()

    monkeypatch.setattr(local_gemma_client.httpx2, "AsyncClient", FakeClient)
    with pytest.raises(RuntimeError, match="did not match configured artifact"):
        asyncio.run(
            local_gemma_client.decide_route(
                RouteRequest.model_validate(make_request()),
                0.5,
            )
        )


@pytest.mark.parametrize(
    "missing_name",
    [
        "SMART_ROUTER_GEMMA_MODEL_REVISION",
        "SMART_ROUTER_GEMMA_ARTIFACT_INVENTORY_SHA256",
    ],
)
def test_missing_local_model_custody_uses_deterministic_fallback(
    client,
    monkeypatch,
    missing_name,
):
    async def forbidden_local(*args, **kwargs):
        raise AssertionError("unbound local Gemma identity must not be called")

    async def forbidden_google(*args, **kwargs):
        raise AssertionError("unprovisioned Google fallback must not be called")

    monkeypatch.delenv(missing_name)
    monkeypatch.delenv("GEMINI_API_KEY")
    monkeypatch.setattr(main, "decide_local_route", forbidden_local)
    monkeypatch.setattr(main, "decide_google_route", forbidden_google)

    response = signed_request(client, "POST", "/route", make_request(trigger="distress"))
    assert response.status_code == 200
    assert response.json()["source"] == "fallback"
    assert response.json()["reason_codes"] == ["deterministic_fallback"]
    assert local_gemma_client.local_configured() is False


def test_local_health_uses_vllm_health_and_exact_models_endpoint(monkeypatch):
    paths = []

    class FakeResponse:
        def __init__(self, payload=None):
            self._payload = payload or {}
            self.status_code = 200
            self.has_redirect_location = False
            self.headers = {}

        def raise_for_status(self):
            return None

        async def aiter_raw(self, chunk_size):
            del chunk_size
            yield json.dumps(self._payload).encode("utf-8")

    class FakeStream:
        def __init__(self, response):
            self.response = response

        async def __aenter__(self):
            return self.response

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        def stream(self, method, path, *, follow_redirects, headers=None, timeout=None):
            assert method == "GET"
            assert follow_redirects is False
            paths.append(path)
            if path == "/v1/models":
                return FakeStream(FakeResponse({
                    "data": [{
                        "id": LOCAL_MODEL,
                        "model_revision": LOCAL_MODEL_REVISION,
                        "artifact_inventory_sha256": LOCAL_ARTIFACT_INVENTORY,
                    }]
                }))
            return FakeStream(FakeResponse())

    monkeypatch.setattr(local_gemma_client.httpx2, "AsyncClient", FakeClient)
    health = asyncio.run(local_gemma_client.provider_health(0.5))
    assert paths == ["/health", "/v1/models"]
    assert health["model"] == LOCAL_MODEL
    assert health["engine_healthy"] is True
    assert health["model_served"] is True
    assert health["ready"] is True


def test_google_api_key_is_header_only_never_payload_or_url(monkeypatch):
    captured = {}
    raw_decision = provider_decision().model_dump_json()

    class FakeResponse:
        status_code = 200
        has_redirect_location = False
        headers = {}

        def raise_for_status(self):
            return None

        async def aiter_raw(self, chunk_size):
            del chunk_size
            yield json.dumps(
                {"candidates": [{"content": {"parts": [{"text": raw_decision}]}}]}
            ).encode("utf-8")

    class FakeStream:
        async def __aenter__(self):
            return FakeResponse()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class FakeClient:
        def __init__(self, **kwargs):
            captured["client_kwargs"] = kwargs

        def stream(self, method, url, *, follow_redirects, headers, json, timeout=None):
            captured.update(
                method=method,
                url=url,
                headers=headers,
                body=json,
                timeout=timeout,
                follow_redirects=follow_redirects,
            )
            return FakeStream()

    monkeypatch.setattr(gemini_client.httpx2, "AsyncClient", FakeClient)
    decision = asyncio.run(
        gemini_client.decide_route(RouteRequest.model_validate(make_request()), 0.5)
    )
    serialized = json.dumps(captured["body"])
    assert decision.selected_route_id == "demo-route-b"
    assert GOOGLE_SECRET not in captured["url"]
    assert GOOGLE_SECRET not in serialized
    assert HMAC_SECRET not in serialized
    assert captured["headers"]["x-goog-api-key"] == GOOGLE_SECRET
    assert captured["body"]["generationConfig"]["temperature"] == 0
    assert captured["body"]["generationConfig"]["candidateCount"] == 1
    assert captured["body"]["generationConfig"]["maxOutputTokens"] == 128
    assert captured["body"]["generationConfig"]["responseMimeType"] == "application/json"
    schema = captured["body"]["generationConfig"]["responseSchema"]
    assert schema["additionalProperties"] is False
    assert "title" not in schema
    assert "description" not in schema
    assert schema["properties"]["selected_route_id"]["pattern"] == NODE_SLUG_PATTERN
    assert "responseFormat" not in captured["body"]["generationConfig"]


def test_terse_route_schema_rejects_verbose_or_non_snake_case_reasons():
    with pytest.raises(ValueError):
        ProviderRouteDecision(
            selected_route_id="demo-route-b",
            decision="switch",
            confidence=0.9,
            reason_codes=["one", "two", "three", "four"],
        )
    with pytest.raises(ValueError):
        ProviderRouteDecision(
            selected_route_id="demo-route-b",
            decision="switch",
            confidence=0.9,
            reason_codes=["NOT_SNAKE_CASE"],
        )
    with pytest.raises(ValueError):
        ProviderRouteDecision(
            selected_route_id="203.0.113.9",
            decision="switch",
            confidence=0.9,
            reason_codes=["raw_endpoint"],
        )


def test_hoppy_local_success_never_calls_google(client, monkeypatch):
    calls = []

    async def local(question, context, timeout_s):
        calls.append("local_gemma")
        return {"answer": "Local answer.", "escalated": False}

    async def google(question, context, timeout_s):
        calls.append("google_gemini")
        raise AssertionError("Google must not run after local Hoppy success")

    monkeypatch.setattr(main, "answer_local_support", local)
    monkeypatch.setattr(main, "answer_support", google)
    response = signed_request(
        client,
        "POST",
        "/hoppy/escalate",
        {"question": "What should I do?", "context": "hotel network"},
    )
    assert response.status_code == 200
    assert response.json()["answer"] == "Local answer."
    assert calls == ["local_gemma"]


def test_hoppy_local_failure_then_google_is_bounded(client, monkeypatch):
    calls = []

    async def local(question, context, timeout_s):
        calls.append("local_gemma")
        raise RuntimeError("local support down")

    async def support(question, context, timeout_s):
        calls.append("google_gemini")
        assert timeout_s <= main.google_timeout_s()
        return {"answer": "Use the healthier route.", "escalated": False}

    monkeypatch.setattr(main, "answer_local_support", local)
    monkeypatch.setattr(main, "answer_support", support)
    response = signed_request(
        client,
        "POST",
        "/hoppy/escalate",
        {"question": "What should I do?", "context": "hotel network"},
    )
    assert response.status_code == 200
    assert response.json()["answer"] == "Use the healthier route."
    assert calls == ["local_gemma", "google_gemini"]


def test_hoppy_both_providers_fail_uses_canned_fallback(client):
    response = signed_request(
        client,
        "POST",
        "/hoppy/escalate",
        {"question": "What should I do?", "context": "hotel network"},
    )
    assert response.status_code == 200
    assert response.json()["escalated"] is False
    assert "https://www.winsvpn.org/support/" in response.json()["answer"]


def test_hoppy_extra_keys_fail_closed_and_advance_to_google(client, monkeypatch):
    calls = []

    async def local(question, context, timeout_s):
        calls.append("local_gemma")
        return {"answer": "Local answer.", "escalated": False, "prose": "extra"}

    async def google(question, context, timeout_s):
        calls.append("google_gemini")
        return {"answer": "Google answer.", "escalated": False}

    monkeypatch.setattr(main, "answer_local_support", local)
    monkeypatch.setattr(main, "answer_support", google)
    response = signed_request(
        client,
        "POST",
        "/hoppy/escalate",
        {"question": "What should I do?", "context": "hotel network"},
    )
    assert response.status_code == 200
    assert response.json() == {"answer": "Google answer.", "escalated": False}
    assert calls == ["local_gemma", "google_gemini"]


def test_support_capacity_exhaustion_returns_static_fallback(client):
    main.PROVIDER_SEMAPHORE = asyncio.Semaphore(0)
    response = signed_request(
        client,
        "POST",
        "/hoppy/escalate",
        {"question": "What should I do?", "context": "hotel network"},
    )
    assert response.status_code == 200
    assert response.json()["escalated"] is False
    assert "https://www.winsvpn.org/support/" in response.json()["answer"]


def test_support_scrubs_reusable_secrets_before_google_payload(monkeypatch):
    captured = {}

    async def generate(prompt, schema, timeout_s):
        captured["prompt"] = prompt
        return json.dumps({"answer": "Safe answer.", "escalated": False})

    monkeypatch.setattr(gemini_client, "_generate", generate)
    answer = asyncio.run(
        gemini_client.answer_support(
            f"Question contains {HMAC_SECRET}",
            f"Context contains {GOOGLE_SECRET}",
            0.5,
        )
    )
    assert answer["answer"] == "Safe answer."
    assert HMAC_SECRET not in captured["prompt"]
    assert GOOGLE_SECRET not in captured["prompt"]
    assert captured["prompt"].count("[REDACTED]") == 2


def test_stats_distinguish_all_three_sources(client, monkeypatch):
    async def local(request, timeout_s):
        return provider_decision()

    monkeypatch.setattr(main, "decide_local_route", local)
    assert signed_request(client, "POST", "/route", make_request(trigger="distress")).status_code == 200

    async def local_fail(request, timeout_s):
        raise RuntimeError("local down")

    async def google(request, timeout_s):
        return provider_decision()

    monkeypatch.setattr(main, "decide_local_route", local_fail)
    monkeypatch.setattr(main, "decide_google_route", google)
    assert signed_request(client, "POST", "/route", make_request(trigger="distress")).status_code == 200

    monkeypatch.setattr(main, "decide_google_route", provider_unavailable)
    assert signed_request(client, "POST", "/route", make_request(trigger="distress")).status_code == 200

    stats = signed_request(client, "GET", "/stats").json()
    assert stats["by_source"] == {
        "explicit": 0,
        "local_gemma": 1,
        "google_gemini": 1,
        "fallback": 1,
    }


def test_candidate_count_and_duplicate_ids_are_rejected(client):
    too_many = make_request(
        candidates=[
            {"route_id": f"route-{index}", "reachable": True}
            for index in range(33)
        ]
    )
    duplicate = make_request(
        candidates=[
            {"route_id": "same-route", "reachable": True},
            {"route_id": "same-route", "reachable": True},
        ]
    )
    assert signed_request(client, "POST", "/route", too_many).status_code == 422
    assert signed_request(client, "POST", "/route", duplicate).status_code == 422


def test_non_finite_or_unbounded_metrics_are_rejected(client):
    non_finite = make_request()
    non_finite["candidates"][0]["handshake_ms"] = float("inf")
    unbounded = make_request()
    unbounded["candidates"][0]["jitter_ms"] = 120001
    assert signed_request(client, "POST", "/route", non_finite).status_code == 422
    assert signed_request(client, "POST", "/route", unbounded).status_code == 422


def test_string_coerced_metrics_and_flags_are_rejected(client):
    as_yes = make_request()
    as_yes["candidates"][0]["reachable"] = "yes"
    as_string_metric = make_request()
    as_string_metric["candidates"][0]["handshake_ms"] = "180"
    as_int_flag = make_request()
    as_int_flag["candidates"][0]["reachable"] = 1
    assert signed_request(client, "POST", "/route", as_yes).status_code == 422
    assert signed_request(client, "POST", "/route", as_string_metric).status_code == 422
    assert signed_request(client, "POST", "/route", as_int_flag).status_code == 422


def test_first_connection_allows_no_current_route(client, monkeypatch):
    async def local(request, timeout_s):
        assert request.current_route_id is None
        return provider_decision(selected_route_id="demo-route-b")

    monkeypatch.setattr(main, "decide_local_route", local)
    payload = make_request(trigger="distress")
    payload["current_route_id"] = None
    response = signed_request(client, "POST", "/route", payload)
    assert response.status_code == 200
    assert response.json()["selected_route_id"] == "demo-route-b"
    assert response.json()["decision"] == "switch"


def test_unknown_candidate_metrics_remain_null_in_provider_payload():
    request = RouteRequest.model_validate(
        make_request(
            candidates=[
                {
                    "route_id": "route-a",
                    "reachable": True,
                    "dns_ok": True,
                    "protocol_version": "winn/1",
                    "carrier": "amneziawg",
                    "v1_engine_order": ["amneziawg", "xray"],
                },
            ],
            current=None,
        )
    )
    candidate = provider_payload(request)["candidates"][0]
    assert candidate["handshake_ms"] is None
    assert candidate["packet_loss_pct"] is None
    assert candidate["jitter_ms"] is None
    assert candidate["recent_failures"] is None


def test_deterministic_fallback_excludes_dns_failed_candidate():
    request = RouteRequest.model_validate(
        make_request(
            candidates=[
                {
                    "route_id": "route-a",
                    "reachable": True,
                    "dns_ok": False,
                    "protocol_version": "winn/1",
                    "carrier": "amneziawg",
                    "v1_engine_order": ["amneziawg", "xray"],
                },
                {
                    "route_id": "route-b",
                    "reachable": True,
                    "dns_ok": True,
                    "protocol_version": "winn/1",
                    "carrier": "amneziawg",
                    "v1_engine_order": ["amneziawg", "xray"],
                },
            ],
            current="route-a",
        )
    )
    decision = deterministic_decision(request)
    assert decision.selected_route_id == "route-b"
    assert decision.decision == "switch"


def test_explicit_node_selection_bypasses_ai(client, monkeypatch):
    calls = []

    async def local(request, timeout_s):
        calls.append("local_gemma")
        raise AssertionError("local Gemma must not run for explicit selection")

    async def google(request, timeout_s):
        calls.append("google_gemini")
        raise AssertionError("Google must not run for explicit selection")

    monkeypatch.setattr(main, "decide_local_route", local)
    monkeypatch.setattr(main, "decide_google_route", google)
    payload = make_request()
    payload["explicit_route_id"] = "demo-route-b"
    response = signed_request(client, "POST", "/route", payload)
    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "explicit"
    assert body["selected_route_id"] == "demo-route-b"
    assert body["decision"] == "switch"
    assert body["reason_codes"] == ["explicit_selection"]
    assert calls == []


def test_explicit_node_must_be_in_the_candidate_set(client, monkeypatch):
    async def local(request, timeout_s):
        raise AssertionError("AI must not run for an invalid explicit selection")

    monkeypatch.setattr(main, "decide_local_route", local)
    payload = make_request()
    payload["explicit_route_id"] = "not-a-candidate"
    response = signed_request(client, "POST", "/route", payload)
    assert response.status_code == 422


@pytest.mark.parametrize(
    "candidate_patch",
    [
        {"reachable": False, "dns_ok": True},
        {"reachable": True, "dns_ok": False},
    ],
)
def test_explicit_node_rejects_unreachable_or_dns_failed_candidate(
    client,
    monkeypatch,
    candidate_patch,
):
    async def forbidden(*args, **kwargs):
        raise AssertionError("AI must not run for an ineligible explicit selection")

    monkeypatch.setattr(main, "decide_local_route", forbidden)
    monkeypatch.setattr(main, "decide_google_route", forbidden)
    payload = make_request()
    payload["explicit_route_id"] = "demo-route-b"
    payload["candidates"][1].update(candidate_patch)

    response = signed_request(client, "POST", "/route", payload)

    assert response.status_code == 422


def test_unknown_post_does_not_enter_strict_json_buffer(client, monkeypatch):
    monkeypatch.setenv("SMART_ROUTER_MAX_BODY_BYTES", "4096")
    response = client.post(
        "/not-a-route",
        content=b"x" * 4097,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 404


def test_signature_covers_query_string(client):
    response = signed_request(client, "GET", "/stats?window=1h")
    assert response.status_code == 200

    # Tampered query string with signature calculated without query must fail
    tampered_headers = auth_headers("GET", "/stats", b"", query="")
    tampered = client.get("/stats?window=1h", headers=tampered_headers)
    assert tampered.status_code == 401
