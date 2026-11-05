"""Fallback decision invariant validation for the deterministic router."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fallback import (
    deterministic_decision,
    protocol_eligible_candidates,
    validate_fallback_decision,
)
from schemas import RouteDecision, RouteRequest


def _winn3(route_id, *, reachable=True, dns_ok=True, **metrics):
    row = {
        "route_id": route_id,
        "reachable": reachable,
        "protocol_version": "winn/3",
        "carrier": "winn3",
        "dns_ok": dns_ok,
        "load_ratio": 0.0,
        "handshake_ms": 180.0,
        "packet_loss_pct": 1.0,
        "jitter_ms": 8.0,
        "recent_failures": 0,
    }
    row.update(metrics)
    return row


def _v1(route_id, *, reachable=True, dns_ok=True, **metrics):
    row = {
        "route_id": route_id,
        "reachable": reachable,
        "protocol_version": "winn/1",
        "carrier": "amneziawg",
        "v1_engine_order": ["amneziawg", "xray"],
        "dns_ok": dns_ok,
        "load_ratio": 0.0,
        "handshake_ms": 180.0,
        "packet_loss_pct": 1.0,
        "jitter_ms": 8.0,
        "recent_failures": 0,
    }
    row.update(metrics)
    return row


def _request(candidates, *, current=None, selection_generation=None, ordinary_v3_failure_generation=None):
    return RouteRequest.model_validate(
        {
            "request_id": "request-0001",
            "current_route_id": current,
            "candidates": candidates,
            "signals": {
                "udp_ok": True,
                "tcp443_ok": True,
                "tls_ok": True,
                "control_plane_ok": True,
                "dns_ok": True,
            },
            "trigger": "connection_initiation",
            "selection_generation": selection_generation,
            "ordinary_v3_failure_generation": ordinary_v3_failure_generation,
        }
    )


def _decision(route_id, decision, *, confidence=0.8, codes=("deterministic_fallback",)):
    return RouteDecision(
        selected_route_id=route_id,
        decision=decision,
        confidence=confidence,
        reason_codes=list(codes),
        source="fallback",
    )


def test_deterministic_output_always_passes_its_own_guard():
    scenarios = [
        _request([_winn3("route-a"), _winn3("route-b", handshake_ms=220.0, packet_loss_pct=8.0)], current="route-a"),
        _request([_winn3("route-a", reachable=False), _winn3("route-b", reachable=False)], current="route-a"),
        _request([_v1("v1-a")], current="v1-a"),
        _request(
            [_v1("v1-a"), _winn3("v3-b")],
            current="v1-a",
            selection_generation="generation-1",
            ordinary_v3_failure_generation="generation-1",
        ),
    ]
    for request in scenarios:
        decision = deterministic_decision(request)
        assert validate_fallback_decision(request, decision).selected_route_id == decision.selected_route_id


def test_rejects_route_outside_candidate_set():
    request = _request([_winn3("route-a")], current="route-a")
    with pytest.raises(ValueError, match="outside the candidate set"):
        validate_fallback_decision(request, _decision("route-b", "switch"))


def test_rejects_non_fallback_source():
    request = _request([_winn3("route-a")], current="route-a")
    bad = _decision("route-a", "keep")
    bad.source = "google_gemini"
    with pytest.raises(ValueError, match="source must be fallback"):
        validate_fallback_decision(request, bad)


def test_rejects_protocol_ineligible_route_while_healthy_winn3_exists():
    request = _request([_winn3("v3-a"), _v1("v1-b")], current="v1-b")
    assert "v3-a" in {c.route_id for c in protocol_eligible_candidates(request)}
    assert "v1-b" not in {c.route_id for c in protocol_eligible_candidates(request)}
    with pytest.raises(ValueError, match="protocol-ineligible"):
        validate_fallback_decision(request, _decision("v1-b", "switch"))


def test_rejects_decision_field_mismatch():
    request = _request([_winn3("route-a"), _winn3("route-b")], current="route-a")
    with pytest.raises(ValueError, match="decision field did not match"):
        validate_fallback_decision(request, _decision("route-b", "keep"))


def test_best_effort_switch_on_current_route_is_valid():
    request = _request(
        [_winn3("route-a", reachable=False), _winn3("route-b", reachable=False)],
        current="route-a",
    )
    decision = deterministic_decision(request)
    assert decision.selected_route_id == "route-a"
    assert decision.decision == "switch"
    assert validate_fallback_decision(request, decision).decision == "switch"