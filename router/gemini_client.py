"""Bounded server-side Google Gemini provider for the Smart Router."""
import os
import re
from urllib.parse import quote

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


GOOGLE_GENERATE_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_CLIENTS = SharedProviderClients(connect_cap=0.35)

# Compatibility name retained for existing imports and external tests.
GeminiRouteDecision = ProviderRouteDecision


GeminiSupportAnswer = ProviderSupportAnswer


def get_api_key() -> str:
    return os.environ.get("GEMINI_API_KEY", "").strip()


def get_model_name() -> str:
    model = os.environ.get("GEMINI_MODEL", "").strip()
    if not model:
        raise RuntimeError("GEMINI_MODEL is not configured")
    if not _MODEL_RE.fullmatch(model):
        raise RuntimeError("GEMINI_MODEL is invalid")
    return model


def gemini_configured() -> bool:
    try:
        return bool(get_api_key() and get_model_name())
    except RuntimeError:
        return False


def require_google_provisioned() -> None:
    if not gemini_configured():
        raise RuntimeError("Google Gemini is not provisioned")


def provider_health() -> dict:
    """Return configuration health without making a cloud request."""
    model = os.environ.get("GEMINI_MODEL", "").strip() or None
    configured = gemini_configured()
    return {
        "configured": configured,
        "model": model,
        "ready": configured,
        "live_checked": False,
    }


def _gemini_schema(model) -> dict:
    return provider_response_schema(model)


def _structured_text(envelope: object) -> str:
    try:
        text = envelope["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError, TypeError) as err:
        raise RuntimeError("Google Gemini returned no structured content") from err
    if not isinstance(text, str) or not text.strip():
        raise RuntimeError("Google Gemini returned non-text structured content")
    return text


def _load_gemini_envelope(raw: bytes) -> dict:
    return load_provider_json(raw, "Google Gemini")


def _parse_gemini_model(raw: str, model):
    return parse_provider_model(raw, model, "Google Gemini")


async def _generate(prompt: str, schema: dict, timeout_s: float) -> str:
    require_google_provisioned()
    key = get_api_key()
    model = get_model_name()
    url = f"{GOOGLE_GENERATE_BASE}/{quote(model, safe='')}:generateContent"
    body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0,
            "candidateCount": 1,
            "maxOutputTokens": 128,
            "responseMimeType": "application/json",
            "responseSchema": schema,
        },
    }
    client, timeout = await _CLIENTS.get(httpx2, timeout_s)
    _response, raw = await bounded_provider_request(
        client,
        "POST",
        url,
        label="Google Gemini",
        headers={"x-goog-api-key": key, "Content-Type": "application/json"},
        json=body,
        timeout=timeout,
    )
    envelope = _load_gemini_envelope(raw)
    return _structured_text(envelope)


async def decide_route(
    request: RouteRequest,
    timeout_s: float,
) -> ProviderRouteDecision:
    """Ask Google Gemini for a closed-set route decision."""
    require_google_provisioned()
    raw = await _generate(
        routing_prompt(request),
        _gemini_schema(ProviderRouteDecision),
        timeout_s,
    )
    return _parse_gemini_model(raw, ProviderRouteDecision)


async def answer_support(question: str, context: str, timeout_s: float) -> dict:
    """Ask Gemini a bounded support question; the caller owns fallback behavior."""
    require_google_provisioned()
    raw = await _generate(
        support_prompt(question, context),
        _gemini_schema(GeminiSupportAnswer),
        timeout_s,
    )
    return _parse_gemini_model(raw, GeminiSupportAnswer).model_dump()
