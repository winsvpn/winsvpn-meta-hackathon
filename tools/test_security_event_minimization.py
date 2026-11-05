#!/usr/bin/env python3
"""Regression tests for security-event persistence and email minimization."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any


SOURCE = Path("server/wins_control_plane_setup_ONETOUCH.sh")
TEXT = SOURCE.read_text(encoding="utf-8")
SECRET = "test-security-event-secret"


def _namespace(start: str, end: str) -> dict[str, Any]:
    snippet = TEXT[TEXT.index(start) : TEXT.index(end, TEXT.index(start))]
    namespace: dict[str, Any] = {
        "Any": Any,
        "RATE_LIMIT_SECRET": SECRET,
        "hashlib": hashlib,
        "hmac": hmac,
        "json": json,
    }
    exec(compile(snippet, str(SOURCE), "exec"), namespace)
    return namespace


def _fixture() -> dict[str, Any]:
    return {
        "src_ip": "198.51.100.7",
        "transport_src_ip": "10.0.0.4",
        "dest_ip": "192.0.2.10",
        "dest_port": 443,
        "signature_id": 1001,
        "http_url": "/admin?token=raw",
        "http_user_agent": "private-agent",
        "account_hash": "already-hashed",
        "nested": [{"source_ip": "2001:db8::1"}, None, 7],
    }


def test_producers_share_pure_fixed_point_minimizer() -> None:
    hub = _namespace("def security_event_hash", "def security_now_utc")
    monitor = _namespace("def canonical_event_hash", "def source_ip_bucket_value")
    original = _fixture()
    before = copy.deepcopy(original)

    hub_result = hub["minimize_security_details"](original)
    monitor_result = monitor["minimize_security_details"](original)

    assert original == before
    assert hub_result == monitor_result
    assert hub["minimize_security_details"](hub_result) == hub_result
    assert monitor["minimize_security_details"](monitor_result) == monitor_result


def test_sensitive_values_leave_no_raw_persistence_or_email_shape() -> None:
    monitor = _namespace("def canonical_event_hash", "def source_ip_bucket_value")
    minimized = monitor["minimize_security_details"](_fixture())
    rendered = json.dumps(minimized, sort_keys=True)

    for raw in (
        "198.51.100.7",
        "10.0.0.4",
        "2001:db8::1",
        "/admin?token=raw",
        "private-agent",
    ):
        assert raw not in rendered
    for key in (
        "src_ip_hash",
        "transport_src_ip_hash",
        "http_url_hash",
        "http_user_agent_hash",
    ):
        assert key in minimized
    assert minimized["dest_ip"] == "192.0.2.10"
    assert minimized["dest_port"] == 443
    assert minimized["signature_id"] == 1001
    assert minimized["account_hash"] == "already-hashed"


def test_storage_email_and_legacy_migration_use_minimized_bytes() -> None:
    assert TEXT.count("json.dumps(minimize_security_details(details or {})") == 2
    assert '("Path bucket", security_event_hash(path) if path else "n/a")' in TEXT
    assert 'security_event_hash(path) if path else ""' in TEXT
    assert 'migration_id = "details-minimization-v1"' in TEXT
    assert "CREATE TABLE IF NOT EXISTS security_event_migrations" in TEXT
    assert "canonical_event_hash(minimized_text)" in TEXT
    assert 'decoded = {"legacy_payload_hash": canonical_event_hash(raw_details or "")}' in TEXT
