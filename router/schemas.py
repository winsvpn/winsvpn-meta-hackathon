"""Strict wire schemas for the Win's VPN Smart Router."""
import json
from typing import Annotated, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator


# Hub node slugs are the only valid route ids (`[a-z0-9][a-z0-9-]{1,39}`).
# That binds every selected route to a node and rejects endpoint-shaped values.
RouteId = Annotated[
    str,
    StringConstraints(
        min_length=2,
        max_length=40,
        pattern=r"^[a-z0-9][a-z0-9-]{1,39}$",
    ),
]
RequestId = Annotated[
    str,
    StringConstraints(
        min_length=8,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
]
ReasonCode = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_]*$",
    ),
]


def _reject_duplicate_json_keys(pairs):
    parsed = {}
    for key, value in pairs:
        if key in parsed:
            raise ValueError("duplicate JSON key")
        parsed[key] = value
    return parsed


def _reject_nonfinite_json_constant(_token: str):
    raise ValueError("non-finite JSON number")


def strict_json_loads(raw: bytes | bytearray | str):
    """Parse JSON with duplicate-key, non-finite, and trailing-data rejection."""
    if isinstance(raw, (bytes, bytearray)):
        text = raw.decode("utf-8")
    elif isinstance(raw, str):
        text = raw
    else:
        raise TypeError("JSON must be text or bytes")
    stripped = text.strip()
    if not stripped:
        raise ValueError("JSON is empty")
    decoder = json.JSONDecoder(
        object_pairs_hook=_reject_duplicate_json_keys,
        parse_constant=_reject_nonfinite_json_constant,
        strict=True,
    )
    obj, end = decoder.raw_decode(stripped)
    if end != len(stripped):
        raise ValueError("JSON has trailing data")
    return obj


class StrictModel(BaseModel):
    """Reject undeclared fields so credentials cannot enter provider payloads."""

    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


class Candidate(StrictModel):
    """One VPN exit route with its live health metrics."""

    route_id: RouteId
    reachable: bool
    protocol_version: Literal["winn/1", "winn/3"]
    carrier: Annotated[
        str,
        StringConstraints(
            min_length=1,
            max_length=64,
            pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
        ),
    ]
    load_ratio: Optional[float] = Field(default=None, ge=0, le=1)
    handshake_ms: Optional[float] = Field(default=None, ge=0, le=120000)
    packet_loss_pct: Optional[float] = Field(default=None, ge=0, le=100)
    jitter_ms: Optional[float] = Field(default=None, ge=0, le=120000)
    dns_ok: Optional[bool] = None
    recent_failures: Optional[int] = Field(default=None, ge=0, le=1000000)
    v1_engine_order: Optional[List[Literal["amneziawg", "xray"]]] = None

    @model_validator(mode="after")
    def exact_protocol_and_v1_order(self) -> "Candidate":
        if self.protocol_version == "winn/1":
            if self.carrier != "amneziawg":
                raise ValueError("winn/1 carrier must be amneziawg")
            if self.v1_engine_order is None:
                raise ValueError("v1_engine_order is required for winn/1")
            if list(self.v1_engine_order) != ["amneziawg", "xray"]:
                raise ValueError("v1_engine_order must be amneziawg then xray")
            return self
        if self.carrier != "winn3":
            raise ValueError("winn/3 carrier must be winn3")
        if self.v1_engine_order is not None:
            raise ValueError("v1_engine_order is only valid for winn/1")
        return self


class Signals(StrictModel):
    """Network-path capability signals observed from the device."""

    udp_ok: Optional[bool] = None
    tcp443_ok: Optional[bool] = None
    tls_ok: Optional[bool] = None
    control_plane_ok: Optional[bool] = None
    dns_ok: Optional[bool] = None


class RouteRequest(StrictModel):
    request_id: RequestId
    current_route_id: Optional[RouteId] = None
    explicit_route_id: Optional[RouteId] = None
    candidates: List[Candidate] = Field(min_length=1, max_length=32)
    signals: Signals = Field(default_factory=Signals)
    trigger: Literal["connection_initiation", "distress"] = "connection_initiation"
    selection_generation: Optional[RequestId] = None
    ordinary_v3_failure_generation: Optional[RequestId] = None

    @model_validator(mode="after")
    def unique_routes(self) -> "RouteRequest":
        route_ids = [candidate.route_id for candidate in self.candidates]
        if len(route_ids) != len(set(route_ids)):
            raise ValueError("candidate route_id values must be unique")
        bound = set(route_ids)
        if self.explicit_route_id is not None and self.explicit_route_id not in bound:
            raise ValueError("explicit_route_id must be one of the candidate route_id values")
        if self.current_route_id is not None and self.current_route_id not in bound:
            raise ValueError("current_route_id must be one of the candidate route_id values")
        return self


class RouteDecision(StrictModel):
    selected_route_id: RouteId
    decision: Literal["keep", "switch"]
    confidence: float = Field(ge=0.0, le=1.0)
    reason_codes: List[ReasonCode] = Field(min_length=1, max_length=3)
    source: Literal["explicit", "local_gemma", "google_gemini", "fallback"]
