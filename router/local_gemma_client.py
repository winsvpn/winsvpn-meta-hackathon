"""Bounded local Gemma provider for aicore's vLLM service."""
import os
import re
from urllib.parse import urlsplit

import httpx2

from provider_common import (
    ProviderRouteDecision,
    ProviderSupportAnswer,
    SharedProviderClients,
    bounded_provider_request,
    load_provider_json,
    parse_provider_model,
    provider_response_schema,
    routing_prompt,
    support_prompt,
)
from schemas import RouteRequest


DEFAULT_LOCAL_URL = "http://127.0.0.1:8002"
INSTALLER_GEMMA_PORT = 8002
INSTALLER_LOOPBACK_HOSTS = {"127.0.0.1", "::1"}
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_IMMUTABLE_REVISION_RE = re.compile(r"^(?:[0-9a-f]{40}|sha256:[0-9a-f]{64})$")
_INVENTORY_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CLIENTS = SharedProviderClients(connect_cap=0.25)


def _first_env(*names: str) -> str:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return ""


def get_local_url() -> str:
    url = _first_env(
        "SMART_ROUTER_GEMMA_URL",
        "EDGE_ROUTER_GEMMA_URL",
        "LOCAL_LLM_URL",
        "VLLM_URL",
    ) or DEFAULT_LOCAL_URL
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
        username = parsed.username
        password = parsed.password
    except ValueError as err:
        raise RuntimeError(
            "local Gemma URL must be installer loopback HTTP on port 8002"
        ) from err
    path = parsed.path.rstrip("/")
    params = getattr(parsed, "params", "")
    if (
        parsed.scheme != "http"
        or hostname not in INSTALLER_LOOPBACK_HOSTS
        or port != INSTALLER_GEMMA_PORT
        or username is not None
        or password is not None
        or parsed.query
        or parsed.fragment
        or params
        or ";" in parsed.path
        or ";" in parsed.netloc
        or path not in {"", "/v1/chat/completions"}
    ):
        raise RuntimeError(
            "local Gemma URL must be installer loopback HTTP on port 8002"
        )
    if hostname == "::1":
        return "http://[::1]:8002"
    return "http://127.0.0.1:8002"


def get_local_model() -> str:
    model = _first_env(
        "SMART_ROUTER_GEMMA_MODEL",
        "EDGE_ROUTER_GEMMA_MODEL",
        "LOCAL_LLM_MODEL",
        "LOCAL_MODEL",
        "GEMMA_MODEL",
    )
    if not model:
        raise RuntimeError("reviewed local Gemma model is not configured")
    if not _MODEL_RE.fullmatch(model):
        raise RuntimeError("reviewed local Gemma model setting is invalid")
    return model


def get_local_identity() -> dict[str, str]:
    model = get_local_model()
    revision = _first_env("SMART_ROUTER_GEMMA_MODEL_REVISION")
    artifact_root = _first_env("SMART_ROUTER_GEMMA_ARTIFACT_ROOT")
    inventory = _first_env("SMART_ROUTER_GEMMA_ARTIFACT_INVENTORY_SHA256")
    if not _IMMUTABLE_REVISION_RE.fullmatch(revision):
        raise RuntimeError("reviewed local Gemma model revision is not configured")
    if (
        not re.fullmatch(r"/[A-Za-z0-9._/-]*", artifact_root)
        or os.path.normpath(artifact_root) != artifact_root
    ):
        raise RuntimeError("reviewed local Gemma artifact root is not configured")
    if not _INVENTORY_SHA256_RE.fullmatch(inventory):
        raise RuntimeError("reviewed local Gemma artifact inventory is not configured")
    return {
        "model": model,
        "model_revision": revision,
        "artifact_root": artifact_root,
        "artifact_inventory_sha256": inventory,
    }


def _require_response_identity(
    envelope: dict, label: str, expected: dict[str, str]
) -> None:
    # Stock vLLM OpenAI chat completions carry only "model"; the revision and
    # inventory fields are project extensions no stock server emits, and any
    # value a server did send would be self-asserted by that same server. The
    # authenticated identity anchor is the installer-validated on-disk
    # artifact (validate_gemma_artifact) behind the loopback-only listener.
    # So: the served model id must match exactly, and a revision or inventory
    # field that IS present must also match -- present-but-drifted fails
    # closed, absent (stock) does not.
    if envelope.get("model") != expected["model"]:
        raise RuntimeError(
            f"{label} response model identity did not match configured artifact"
        )
    for key in ("model_revision", "artifact_inventory_sha256"):
        if envelope.get(key) is not None and envelope.get(key) != expected[key]:
            raise RuntimeError(
                f"{label} response model identity did not match configured artifact"
            )


def local_configured() -> bool:
    try:
        get_local_url()
        get_local_identity()
        return True
    except (RuntimeError, ValueError):
        return False


def _request_headers() -> dict[str, str] | None:
    key = _first_env("SMART_ROUTER_VLLM_API_KEY", "VLLM_API_KEY")
    if not key:
        return None
    return {"Authorization": f"Bearer {key}"}


async def decide_route(request: RouteRequest, timeout_s: float) -> ProviderRouteDecision:
    """Ask the exact reviewed vLLM-served Gemma model for one decision."""
    identity = get_local_identity()
    model = identity["model"]
    body = {
        "model": model,
        "messages": [{"role": "user", "content": routing_prompt(request)}],
        "stream": False,
        "temperature": 0,
        "seed": 0,
        "max_tokens": 128,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "winsvpn_route_decision",
                "strict": True,
                "schema": provider_response_schema(ProviderRouteDecision),
            },
        },
    }
    client, timeout = await _CLIENTS.get(httpx2, timeout_s, base_url=get_local_url())
    _response, raw = await bounded_provider_request(
        client,
        "POST",
        "/v1/chat/completions",
        label="local Gemma",
        headers=_request_headers(),
        json=body,
        timeout=timeout,
    )
    envelope = load_provider_json(raw, "local Gemma")
    _require_response_identity(envelope, "local Gemma", identity)
    try:
        inner = envelope["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as err:
        raise RuntimeError("local Gemma returned no structured decision") from err
    if not isinstance(inner, str):
        raise RuntimeError("local Gemma returned non-text structured content")
    return parse_provider_model(inner, ProviderRouteDecision, "local Gemma")


async def answer_support(question: str, context: str, timeout_s: float) -> dict:
    """Ask local Gemma first for a bounded Hoppy answer."""
    identity = get_local_identity()
    model = identity["model"]
    body = {
        "model": model,
        "messages": [{"role": "user", "content": support_prompt(question, context)}],
        "stream": False,
        "temperature": 0,
        "seed": 0,
        "max_tokens": 256,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "winsvpn_support_answer",
                "strict": True,
                "schema": provider_response_schema(ProviderSupportAnswer),
            },
        },
    }
    client, timeout = await _CLIENTS.get(httpx2, timeout_s, base_url=get_local_url())
    _response, raw = await bounded_provider_request(
        client,
        "POST",
        "/v1/chat/completions",
        label="local Gemma support",
        headers=_request_headers(),
        json=body,
        timeout=timeout,
    )
    envelope = load_provider_json(raw, "local Gemma support")
    _require_response_identity(envelope, "local Gemma support", identity)
    try:
        inner = envelope["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as err:
        raise RuntimeError("local Gemma returned no structured support answer") from err
    if not isinstance(inner, str):
        raise RuntimeError("local Gemma returned non-text structured content")
    return parse_provider_model(inner, ProviderSupportAnswer, "local Gemma support").model_dump()


async def provider_health(timeout_s: float = 0.25) -> dict:
    """Require a healthy vLLM engine serving the exact reviewed model."""
    model = None
    revision = None
    artifact_root = None
    inventory = None
    try:
        identity = get_local_identity()
        model = identity["model"]
        revision = identity["model_revision"]
        artifact_root = identity["artifact_root"]
        inventory = identity["artifact_inventory_sha256"]
        client, timeout = await _CLIENTS.get(httpx2, timeout_s, base_url=get_local_url())
        headers = _request_headers()
        health_response, _health_body = await bounded_provider_request(
            client,
            "GET",
            "/health",
            label="local Gemma",
            headers=headers,
            timeout=timeout,
        )
        models_response, models_body = await bounded_provider_request(
            client,
            "GET",
            "/v1/models",
            label="local Gemma model-list",
            headers=headers,
            timeout=timeout,
        )
        health_response.raise_for_status()
        models_response.raise_for_status()
        model_entries = [
            item
            for item in load_provider_json(
                models_body, "local Gemma model-list"
            ).get("data", [])
            if isinstance(item, dict) and item.get("id") == model
        ]
        served = (
            len(model_entries) == 1
            and model_entries[0].get("root", artifact_root) == artifact_root
            and model_entries[0].get("model_revision", revision) == revision
            and model_entries[0].get("artifact_inventory_sha256", inventory) == inventory
        )
        return {
            "configured": True,
            "runtime": "vllm",
            "model": model,
            "model_revision": revision,
            "artifact_inventory_sha256": inventory,
            "engine_healthy": True,
            "model_served": served,
            "ready": served,
        }
    except Exception as err:
        return {
            "configured": local_configured(),
            "runtime": "vllm",
            "model": model,
            "model_revision": revision,
            "artifact_inventory_sha256": inventory,
            "engine_healthy": False,
            "model_served": False,
            "ready": False,
            "error_kind": type(err).__name__,
        }
