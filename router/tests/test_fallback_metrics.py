"""Offline matrix tests for unknown health metrics in deterministic fallback."""
import sys
from itertools import product
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fallback import deterministic_decision
from schemas import RouteRequest


METRIC_FIELDS = (
    "load_ratio",
    "handshake_ms",
    "packet_loss_pct",
    "jitter_ms",
    "recent_failures",
)
NULL_MASKS = tuple(range(1, 1 << len(METRIC_FIELDS)))
TERSE_DECISION_KEYS = {
    "selected_route_id",
    "decision",
    "confidence",
    "reason_codes",
    "source",
}
HEALTHY_WINN3_METRICS = {
    "load_ratio": 0.0,
    "handshake_ms": 180.0,
    "packet_loss_pct": 1.0,
    "jitter_ms": 8.0,
    "recent_failures": 0,
}
BEST_MEASURED_METRICS = {
    "load_ratio": 0.0,
    "handshake_ms": 0.0,
    "packet_loss_pct": 0.0,
    "jitter_ms": 0.0,
    "recent_failures": 0,
}


def _null_fields(mask: int) -> tuple[str, ...]:
    return tuple(
        field for index, field in enumerate(METRIC_FIELDS) if mask & (1 << index)
    )


def _winn3(route_id, *, dns_ok=True, reachable=True, **metrics):
    row = {
        "route_id": route_id,
        "reachable": reachable,
        "protocol_version": "winn/3",
        "carrier": "winn3",
        "dns_ok": dns_ok,
    }
    row.update(HEALTHY_WINN3_METRICS)
    row.update(metrics)
    return row


def _v1(route_id, **metrics):
    row = {
        "route_id": route_id,
        "reachable": True,
        "protocol_version": "winn/1",
        "carrier": "amneziawg",
        "v1_engine_order": ["amneziawg", "xray"],
        "dns_ok": True,
    }
    row.update(HEALTHY_WINN3_METRICS)
    row.update(metrics)
    return row


def _request(candidates, *, current=None, udp_ok=True, dns_ok=True):
    return RouteRequest.model_validate(
        {
            "request_id": "request-0001",
            "current_route_id": current,
            "candidates": candidates,
            "signals": {
                "udp_ok": udp_ok,
                "tcp443_ok": True,
                "tls_ok": True,
                "control_plane_ok": True,
                "dns_ok": dns_ok,
            },
            "trigger": "connection_initiation",
        }
    )


def _partial(base, null_fields, **overrides):
    row = dict(base)
    row.update(overrides)
    for field in null_fields:
        row[field] = None
    return row


def _assert_terse(decision):
    payload = decision.model_dump()
    assert set(payload) == TERSE_DECISION_KEYS
    assert payload["reason_codes"] == ["deterministic_fallback"]
    assert payload["source"] == "fallback"


@pytest.mark.parametrize("mask", NULL_MASKS)
def test_partial_null_metrics_cannot_outrank_healthy_measured_winn3(mask):
    null_fields = _null_fields(mask)
    request = _request(
        [
            _winn3("z-healthy-winn3"),
            _partial(_winn3("a-unknown-winn3"), null_fields),
        ],
        current="a-unknown-winn3",
    )
    decision = deterministic_decision(request)
    _assert_terse(decision)
    assert decision.selected_route_id == "z-healthy-winn3"
    assert decision.decision == "switch"


@pytest.mark.parametrize("mask", NULL_MASKS)
def test_best_measured_fields_with_nulls_cannot_outrank_healthy_winn3(mask):
    null_fields = _null_fields(mask)
    request = _request(
        [
            _winn3("z-healthy-winn3"),
            _partial(
                _winn3("a-unknown-winn3"),
                null_fields,
                **BEST_MEASURED_METRICS,
            ),
        ]
    )
    decision = deterministic_decision(request)
    _assert_terse(decision)
    assert decision.selected_route_id == "z-healthy-winn3"


@pytest.mark.parametrize(
    "present_fields",
    tuple(
        combo
        for combo in product((False, True), repeat=len(METRIC_FIELDS))
        if not all(combo)
    ),
)
def test_unknown_metric_matrix_preserves_healthy_winn3_winner(present_fields):
    metrics = {}
    for field, present in zip(METRIC_FIELDS, present_fields):
        metrics[field] = HEALTHY_WINN3_METRICS[field] if present else None
    request = _request(
        [
            _winn3("z-healthy-winn3"),
            _winn3("a-unknown-winn3", **metrics),
        ]
    )
    decision = deterministic_decision(request)
    _assert_terse(decision)
    assert decision.selected_route_id == "z-healthy-winn3"


def test_fully_measured_healthier_winn3_keeps_deterministic_order():
    request = _request(
        [
            _winn3(
                "route-a",
                handshake_ms=220.0,
                packet_loss_pct=8.0,
                jitter_ms=30.0,
                recent_failures=3,
            ),
            _winn3("route-b"),
        ],
        current="route-a",
    )
    decision = deterministic_decision(request)
    _assert_terse(decision)
    assert decision.selected_route_id == "route-b"
    assert decision.decision == "switch"


def test_equal_unknown_metrics_break_ties_by_route_id():
    request = _request(
        [
            _winn3(
                "route-b",
                load_ratio=None,
                handshake_ms=None,
                packet_loss_pct=None,
                jitter_ms=None,
                recent_failures=None,
            ),
            _winn3(
                "route-a",
                load_ratio=None,
                handshake_ms=None,
                packet_loss_pct=None,
                jitter_ms=None,
                recent_failures=None,
            ),
        ]
    )
    decision = deterministic_decision(request)
    _assert_terse(decision)
    assert decision.selected_route_id == "route-a"


def test_unknown_metrics_do_not_bypass_dns_failure():
    request = _request(
        [
            _partial(
                _winn3("a-unknown-winn3", dns_ok=False),
                METRIC_FIELDS,
                **BEST_MEASURED_METRICS,
            ),
            _winn3("z-healthy-winn3"),
        ],
        current="a-unknown-winn3",
    )
    decision = deterministic_decision(request)
    _assert_terse(decision)
    assert decision.selected_route_id == "z-healthy-winn3"


def test_udp_block_still_selects_healthy_measured_winn3():
    request = _request(
        [
            _partial(_winn3("a-unknown-winn3"), METRIC_FIELDS),
            _winn3("z-healthy-winn3"),
        ],
        udp_ok=False,
        dns_ok=False,
    )
    decision = deterministic_decision(request)
    _assert_terse(decision)
    assert decision.selected_route_id == "z-healthy-winn3"


def test_protocol_eligibility_prefers_unknown_winn3_over_measured_v1():
    request = _request(
        [
            _v1("v1-measured", **BEST_MEASURED_METRICS),
            _partial(_winn3("v3-unknown"), METRIC_FIELDS),
        ],
        current="v1-measured",
    )
    decision = deterministic_decision(request)
    _assert_terse(decision)
    assert decision.selected_route_id == "v3-unknown"


def test_unreachable_unknown_winn3_does_not_outrank_healthy_measured():
    request = _request(
        [
            _partial(_winn3("a-unknown-winn3", reachable=False), METRIC_FIELDS),
            _winn3("z-healthy-winn3"),
        ]
    )
    decision = deterministic_decision(request)
    _assert_terse(decision)
    assert decision.selected_route_id == "z-healthy-winn3"


def test_extreme_jitter_is_capped_to_the_unknown_jitter_penalty():
    request = _request(
        [
            _winn3("route-a", jitter_ms=120000.0),
            _winn3("route-b", jitter_ms=500.0),
        ]
    )
    decision = deterministic_decision(request)
    _assert_terse(decision)
    assert decision.selected_route_id == "route-a"
