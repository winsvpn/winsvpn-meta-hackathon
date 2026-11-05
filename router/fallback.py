"""Deterministic Winn v3-first router for Win's VPN.

Pure function of the request: no network, no LLM, no randomness.
Used for connection initiation and whenever distress AI is slow, invalid, or
unavailable. Never blocks connectivity.
"""
from typing import List, Tuple

from schemas import Candidate, RouteDecision, RouteRequest

REASON_FALLBACK = "deterministic_fallback"
CURRENT_TIE_TOLERANCE = 0.95  # prefer current route within 5% of best score
WINN_PROTOCOL_V1 = "winn/1"
WINN_PROTOCOL_V3 = "winn/3"
WINN3_STANDALONE_CARRIER = "winn3"
_HANDSHAKE_CAP_MS = 500.0
_JITTER_CAP_MS = 500.0
_UNKNOWN_LOAD_PENALTY = 100.0
_UNKNOWN_HANDSHAKE_PENALTY = _HANDSHAKE_CAP_MS / 10.0
_UNKNOWN_LOSS_PENALTY = 50.0
_UNKNOWN_JITTER_PENALTY = _JITTER_CAP_MS / 10.0
_UNKNOWN_FAILURES_PENALTY = 50.0


def _score(candidate: Candidate, request: RouteRequest) -> float:
    signals = request.signals
    load_penalty = (
        _UNKNOWN_LOAD_PENALTY
        if candidate.load_ratio is None
        else 100.0 * candidate.load_ratio
    )
    failures_penalty = (
        _UNKNOWN_FAILURES_PENALTY
        if candidate.recent_failures is None
        else 10.0 * candidate.recent_failures
    )
    handshake_penalty = (
        _UNKNOWN_HANDSHAKE_PENALTY
        if candidate.handshake_ms is None
        else min(candidate.handshake_ms, _HANDSHAKE_CAP_MS) / 10.0
    )
    loss_penalty = (
        _UNKNOWN_LOSS_PENALTY
        if candidate.packet_loss_pct is None
        else candidate.packet_loss_pct / 2.0
    )
    jitter_penalty = (
        _UNKNOWN_JITTER_PENALTY
        if candidate.jitter_ms is None
        else min(candidate.jitter_ms, _JITTER_CAP_MS) / 10.0
    )
    return (
        (100.0 if signals.udp_ok else 0.0)
        + (50.0 if signals.tcp443_ok else 0.0)
        + (30.0 if signals.tls_ok else 0.0)
        + (20.0 if signals.dns_ok else 0.0)
        - load_penalty
        - failures_penalty
        - handshake_penalty
        - loss_penalty
        - jitter_penalty
    )


def v1_ordinary_failure_authorized(request: RouteRequest) -> bool:
    """True only for a positively matching generation-bound ordinary v3 failure."""
    generation = str(request.selection_generation or "").strip()
    authorized = str(request.ordinary_v3_failure_generation or "").strip()
    return bool(generation) and generation == authorized


def _is_healthy(candidate: Candidate) -> bool:
    return bool(candidate.reachable) and candidate.dns_ok is not False


def _is_compatible_winn3(candidate: Candidate) -> bool:
    return (
        candidate.protocol_version == WINN_PROTOCOL_V3
        and candidate.carrier == WINN3_STANDALONE_CARRIER
    )


def protocol_eligible_candidates(request: RouteRequest) -> List[Candidate]:
    """Initial selection requires a healthy standalone winn/3 candidate when one exists.

    v1 may be selected only after a generation-bound positively ordinary v3
    failure authorization. A v1-only candidate set stays eligible.
    """
    candidates: List[Candidate] = list(request.candidates)
    standalone = [item for item in candidates if _is_compatible_winn3(item)]
    healthy_v3 = [item for item in standalone if _is_healthy(item)]
    if healthy_v3:
        return healthy_v3
    authorized = v1_ordinary_failure_authorized(request)
    if standalone and not authorized:
        return standalone
    if standalone and authorized:
        v1_rows = [
            item for item in candidates if item.protocol_version == WINN_PROTOCOL_V1
        ]
        return v1_rows or standalone
    return candidates


def candidate_is_protocol_eligible(request: RouteRequest, route_id: str) -> bool:
    return any(item.route_id == route_id for item in protocol_eligible_candidates(request))


def validate_fallback_decision(
    request: RouteRequest, decision: RouteDecision
) -> RouteDecision:
    """Enforce the deterministic fallback invariants before returning a decision.

    The selected route must be in the caller's closed candidate set, must not
    be a protocol-ineligible route while an eligible healthy route exists, and
    its decision field must match whether it equals the current route.
    """
    by_id = {candidate.route_id: candidate for candidate in request.candidates}
    if decision.selected_route_id not in by_id:
        raise ValueError("fallback selected a route outside the candidate set")
    if decision.source != "fallback":
        raise ValueError("fallback decision source must be fallback")
    selected = by_id[decision.selected_route_id]
    eligible = protocol_eligible_candidates(request)
    healthy_eligible = [item for item in eligible if _is_healthy(item)]
    if healthy_eligible and selected.route_id not in {
        item.route_id for item in healthy_eligible
    }:
        raise ValueError(
            "fallback selected a protocol-ineligible route while eligible healthy routes exist"
        )
    expected = (
        "keep"
        if (selected.route_id == request.current_route_id and healthy_eligible)
        else "switch"
    )
    if decision.decision != expected:
        raise ValueError("fallback decision field did not match selected route")
    return decision


def deterministic_decision(request: RouteRequest) -> RouteDecision:
    """Pick a route deterministically.

    Protocol-eligible reachable candidates only; if nothing is reachable in
    that pool, degrade to a best-effort pick across the protocol-eligible set
    with decision=switch so the client still attempts reconnection elsewhere.
    """
    candidates: List[Candidate] = protocol_eligible_candidates(request)
    if not candidates:
        standalone = [item for item in request.candidates if _is_compatible_winn3(item)]
        candidates = standalone or list(request.candidates)

    reachable = [c for c in candidates if _is_healthy(c)]
    best_effort = not reachable
    pool = reachable if reachable else candidates

    scored: List[Tuple[float, str, Candidate]] = sorted(
        ((_score(c, request), c.route_id, c) for c in pool),
        key=lambda t: (-t[0], t[1]),
    )
    best_score, _, best = scored[0]

    selected = best
    if not best_effort:
        current = next((c for c in pool if c.route_id == request.current_route_id), None)
        if current is not None and current.route_id != best.route_id:
            tolerance = max(1.0, abs(best_score) * (1.0 - CURRENT_TIE_TOLERANCE))
            if _score(current, request) >= best_score - tolerance:
                selected = current  # hysteresis: keep current on a near-tie

    second_score = scored[1][0] if len(scored) > 1 else best_score + 50.0
    gap = best_score - second_score
    confidence = (
        0.2
        if best_effort
        else min(0.95, max(0.05, 0.55 + gap / 100.0))
    )

    return validate_fallback_decision(
        request,
        RouteDecision(
            selected_route_id=selected.route_id,
            decision="keep" if (selected.route_id == request.current_route_id and not best_effort) else "switch",
            confidence=round(confidence, 3),
            reason_codes=[REASON_FALLBACK],
            source="fallback",
        ),
    )
