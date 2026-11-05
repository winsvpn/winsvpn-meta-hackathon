"""Provider-neutral Smart Router prompt, schema, and bounded transport."""
import asyncio
import json
import os
import re
import zlib
from typing import List, Literal

from pydantic import BaseModel, ConfigDict, Field

from fallback import protocol_eligible_candidates
from schemas import ReasonCode, RouteId, RouteRequest, strict_json_loads


MAX_PROVIDER_RESPONSE_BYTES = 64 * 1024
DEFAULT_PROVIDER_OPERATION_BOUND = 8
MAX_PROVIDER_OPERATION_BOUND = 64
_REDIRECT_STATUS = frozenset(range(300, 400))

_SECRET_TOKEN_RE = re.compile(
    r"(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"
    r"|(?i:bearer\s+)?(?i:AIza[0-9A-Za-z_-]{20,}|[A-Za-z0-9_-]{32,})"
)


class ProviderRouteDecision(BaseModel):
    """The only shape an AI route provider may return."""

    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)

    selected_route_id: RouteId
    decision: Literal["keep", "switch"]
    confidence: float = Field(ge=0.0, le=1.0)
    reason_codes: List[ReasonCode] = Field(min_length=1, max_length=3)


class ProviderSupportAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)

    answer: str = Field(min_length=1, max_length=800)
    escalated: bool


def scrub_provider_text(value: str) -> str:
    """Remove configured secrets and key-shaped material before AI payloads."""
    scrubbed = value
    for name in (
        "SMART_ROUTER_HMAC_SECRET",
        "EDGE_ROUTER_SECRET",
        "GEMINI_API_KEY",
        "SMART_ROUTER_VLLM_API_KEY",
        "VLLM_API_KEY",
    ):
        secret = os.environ.get(name, "").strip()
        if secret:
            scrubbed = scrubbed.replace(secret, "[REDACTED]")
    return _SECRET_TOKEN_RE.sub("[REDACTED]", scrubbed)


def provider_payload(request: RouteRequest) -> dict:
    """Return the bounded, credential-free subset retained for audit records."""
    return {
        "trigger": request.trigger,
        "current_route_id": request.current_route_id,
        "candidates": [candidate.model_dump() for candidate in request.candidates],
        "signals": request.signals.model_dump(),
        "selection_generation": request.selection_generation,
        "ordinary_v3_failure_generation": request.ordinary_v3_failure_generation,
    }


def advisory_payload(request: RouteRequest) -> dict:
    """Return the terse candidate subset actually offered to a provider."""
    payload = provider_payload(request)
    payload["candidates"] = [
        candidate.model_dump() for candidate in protocol_eligible_candidates(request)
    ]
    return payload


def provider_response_schema(model) -> dict:
    """Exact JSON schema: no titles, no extra keys, no invented fields."""
    schema = model.model_json_schema()

    def clean(node):
        if isinstance(node, dict):
            node.pop("title", None)
            node.pop("description", None)
            if node.get("type") == "object" or "properties" in node:
                node["additionalProperties"] = False
            for child in node.values():
                clean(child)
        elif isinstance(node, list):
            for child in node:
                clean(child)

    clean(schema)
    schema["type"] = "object"
    schema["additionalProperties"] = False
    return schema


def routing_prompt(request: RouteRequest) -> str:
    """Build one provider-neutral prompt from the strict wire model."""
    payload = advisory_payload(request)
    allowed_ids = [
        candidate.route_id for candidate in protocol_eligible_candidates(request)
    ]
    return (
        "Select exactly one VPN route from the closed allowed set. Never invent an "
        "endpoint, credential, configuration, or route. Disqualify unreachable or "
        "explicit DNS-failed candidates. Treat null metrics as unknown. Prefer a "
        "healthy reachable winn/3 carrier=winn3 route. Select winn/1 only when "
        "selection_generation matches ordinary_v3_failure_generation. Prefer "
        "interference recovery, then path health, then lower load and latency. "
        "Return only JSON matching the supplied schema with at most three short "
        "snake_case reason_codes and no prose.\n"
        f"Allowed route ids: {json.dumps(allowed_ids, separators=(',', ':'))}\n"
        f"Routing input: {json.dumps(payload, separators=(',', ':'), sort_keys=True)}"
    )


def support_prompt(question: str, context: str) -> str:
    return """You are Hoppy, the support assistant for Win's VPN. Answer in at most
three short sentences. Do not request, repeat, or reveal credentials. Set escalated=true only
when a human support engineer must follow up. Return only JSON matching the supplied schema.

User question: {question}
Context: {context}
""".format(
        question=scrub_provider_text(question),
        context=scrub_provider_text(context) if context else "(none)",
    )


class CappedDecoder:
    def __init__(self, content_encoding: str, limit: int, label: str) -> None:
        encoding = ",".join(part.strip().lower() for part in content_encoding.split(","))
        self._limit = limit
        self._label = label
        self._seen = 0
        self._raw_fallback = False
        if encoding in {"", "identity"}:
            self._obj = None
        elif encoding == "gzip":
            self._obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif encoding == "deflate":
            self._obj = zlib.decompressobj()
            self._raw_fallback = True
        else:
            raise RuntimeError(f"{label} response exceeded size limit")

    def _take(self, piece: bytes) -> bytes:
        if self._seen + len(piece) > self._limit:
            raise RuntimeError(f"{self._label} response exceeded size limit")
        self._seen += len(piece)
        return piece

    def feed(self, data: bytes) -> bytes:
        if not data:
            return b""
        if self._obj is None:
            return self._take(data)
        remaining = self._limit - self._seen
        if remaining <= 0:
            raise RuntimeError(f"{self._label} response exceeded size limit")
        try:
            piece = self._obj.decompress(data, remaining)
        except zlib.error as err:
            if self._raw_fallback and self._seen == 0:
                self._obj = zlib.decompressobj(-zlib.MAX_WBITS)
                self._raw_fallback = False
                return self.feed(data)
            raise RuntimeError(f"{self._label} returned no structured content") from err
        if self._obj.unconsumed_tail:
            raise RuntimeError(f"{self._label} response exceeded size limit")
        return self._take(piece)

    def finish(self) -> bytes:
        if self._obj is None:
            return b""
        try:
            piece = self._obj.flush()
        except zlib.error as err:
            raise RuntimeError(f"{self._label} returned no structured content") from err
        return self._take(piece)


def refuse_redirect(response, label: str) -> None:
    status = getattr(response, "status_code", None)
    if getattr(response, "has_redirect_location", False):
        raise RuntimeError(f"{label} redirect refused")
    if status is not None and int(status) in _REDIRECT_STATUS:
        raise RuntimeError(f"{label} redirect refused")


def declared_length(response, label: str) -> int | None:
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    raw = headers.get("content-length")
    if raw is None or raw == "":
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError) as err:
        raise RuntimeError(f"{label} response exceeded size limit") from err
    if value < 0 or value > MAX_PROVIDER_RESPONSE_BYTES:
        raise RuntimeError(f"{label} response exceeded size limit")
    return value


async def read_bounded_provider_body(response, label: str) -> bytes:
    refuse_redirect(response, label)
    declared_length(response, label)
    aiter_raw = getattr(response, "aiter_raw", None)
    if not callable(aiter_raw):
        raise RuntimeError(f"{label} client does not support streaming")
    headers = getattr(response, "headers", None)
    encoding = headers.get("content-encoding", "") if headers is not None else ""
    decoder = CappedDecoder(encoding, MAX_PROVIDER_RESPONSE_BYTES, label)
    wire = 0
    parts: list[bytes] = []
    async for chunk in aiter_raw(4096):
        wire += len(chunk)
        if wire > MAX_PROVIDER_RESPONSE_BYTES:
            raise RuntimeError(f"{label} response exceeded size limit")
        decoded = decoder.feed(chunk)
        if decoded:
            parts.append(decoded)
    tail = decoder.finish()
    if tail:
        parts.append(tail)
    return b"".join(parts)


def load_provider_json(body: bytes | bytearray | str, label: str):
    try:
        parsed = strict_json_loads(body)
    except json.JSONDecodeError:
        raise
    except (TypeError, UnicodeDecodeError, ValueError) as err:
        raise RuntimeError(f"{label} returned no structured content") from err
    if not isinstance(parsed, dict):
        raise RuntimeError(f"{label} returned no structured content")
    return parsed


def _unwrap_terse_json(parsed, label: str) -> dict:
    """Unwrap a single JSON-string-wrapped (double-encoded) decision safely.

    Some Gemma/Gemini serving stacks emit the decision object as a JSON-encoded
    string literal rather than a bare object. Accept that terse form, but only
    by unwrapping exactly one level and then running the exact same strict
    schema validation. A top-level non-string, a non-JSON string, or any
    malformed inner document still fails closed.
    """
    if isinstance(parsed, dict):
        return parsed
    if isinstance(parsed, str):
        try:
            inner = strict_json_loads(parsed)
        except (json.JSONDecodeError, TypeError, UnicodeDecodeError, ValueError) as err:
            raise RuntimeError(f"{label} returned no structured content") from err
        if isinstance(inner, dict):
            return inner
    raise RuntimeError(f"{label} returned no structured content")


def parse_provider_model(raw: str, model, label: str):
    try:
        parsed = strict_json_loads(raw)
    except (json.JSONDecodeError, TypeError, UnicodeDecodeError, ValueError) as err:
        raise RuntimeError(f"{label} returned no structured content") from err
    return model.model_validate(_unwrap_terse_json(parsed, label))


async def bounded_provider_request(
    client,
    method: str,
    url: str,
    *,
    label: str,
    headers=None,
    json=None,
    timeout=None,
):
    stream = getattr(client, "stream", None)
    if not callable(stream):
        raise RuntimeError(f"{label} client does not support streaming")
    kwargs = {}
    if headers is not None:
        kwargs["headers"] = headers
    if json is not None:
        kwargs["json"] = json
    if timeout is not None:
        kwargs["timeout"] = timeout
    async with stream(method, url, follow_redirects=False, **kwargs) as response:
        body = await read_bounded_provider_body(response, label)
        response.raise_for_status()
        return response, body


def provider_operation_bound() -> int:
    """Return the validated number of provider operations admitted by the router."""
    raw = os.environ.get("SMART_ROUTER_MAX_CONCURRENT_REQUESTS", "").strip()
    try:
        value = int(raw) if raw else DEFAULT_PROVIDER_OPERATION_BOUND
    except ValueError as err:
        raise RuntimeError(
            "SMART_ROUTER_MAX_CONCURRENT_REQUESTS must be an integer"
        ) from err
    if not 1 <= value <= MAX_PROVIDER_OPERATION_BOUND:
        raise RuntimeError(
            "SMART_ROUTER_MAX_CONCURRENT_REQUESTS must be between 1 and 64"
        )
    return value


class SharedProviderClients:
    """Reuse one httpx2 client per event loop and origin without mutating credentials."""

    def __init__(self, *, connect_cap: float, max_connections: int | None = None) -> None:
        operation_bound = provider_operation_bound()
        if max_connections is None:
            max_connections = operation_bound
        if type(max_connections) is not int:
            raise RuntimeError("provider max_connections must be an integer")
        if not 1 <= max_connections <= MAX_PROVIDER_OPERATION_BOUND:
            raise RuntimeError("provider max_connections must be between 1 and 64")
        if max_connections < operation_bound:
            raise RuntimeError(
                "provider max_connections cannot be smaller than admitted provider operations"
            )
        self._connect_cap = connect_cap
        self._max_connections = max_connections
        self._lock = asyncio.Lock()
        self._client = None
        self._key = None

    async def get(self, httpx_mod, timeout_s: float, *, base_url: str = ""):
        timeout = httpx_mod.Timeout(
            timeout_s,
            connect=min(timeout_s, self._connect_cap),
            pool=0.1,
        )
        client_cls = httpx_mod.AsyncClient
        loop = asyncio.get_running_loop()
        key = (base_url, id(client_cls), id(loop), self._max_connections)
        async with self._lock:
            client = self._client
            if (
                client is not None
                and self._key == key
                and not getattr(client, "is_closed", False)
            ):
                return client, timeout
            old = client
            old_loop_id = None if self._key is None else self._key[2]
            client = client_cls(
                timeout=timeout,
                limits=httpx_mod.Limits(
                    max_connections=self._max_connections,
                    max_keepalive_connections=max(0, self._max_connections // 2),
                ),
                trust_env=False,
                follow_redirects=False,
                max_redirects=0,
                headers={"Accept-Encoding": "identity"},
                **({"base_url": base_url} if base_url else {}),
            )
            self._client = client
            self._key = key
        if old is not None and old_loop_id == id(loop):
            aclose = getattr(old, "aclose", None)
            if callable(aclose):
                try:
                    await aclose()
                except Exception:
                    pass
        return client, timeout
