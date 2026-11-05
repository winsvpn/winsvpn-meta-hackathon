import asyncio
import logging
import multiprocessing
import os
import secrets
import sqlite3
import sys
import threading
import time
from pathlib import Path

import httpx
import types

if "httpx2" not in sys.modules:
    _httpx2 = types.ModuleType("httpx2")
    for k, v in httpx.__dict__.items():
        setattr(_httpx2, k, v)
    sys.modules["httpx2"] = _httpx2

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import security
from security import (
    DurableReplayGuard,
    ReplayDecision,
    replay_retention_end,
    sign_request,
)


HMAC_SECRET = "router-replay-test-secret-0123456789abcdef"


def _process_accept(path: str, ready, start, results) -> None:
    os.environ["SMART_ROUTER_NONCE_JOURNAL_PATH"] = path
    os.environ["SMART_ROUTER_NONCE_JOURNAL_LOCK_TIMEOUT_MS"] = "2000"
    ready.put(True)
    start.wait(10)
    decision = DurableReplayGuard().accept("shared-process-nonce", 1000.0, 30.0)
    results.put(decision.value)


@pytest.fixture
def journal_path(tmp_path, monkeypatch):
    directory = tmp_path / "nonce-journal"
    directory.mkdir(mode=0o700)
    path = directory / "replay-nonces.sqlite3"
    monkeypatch.setenv("SMART_ROUTER_NONCE_JOURNAL_PATH", str(path))
    monkeypatch.setenv("SMART_ROUTER_HMAC_SECRET", HMAC_SECRET)
    monkeypatch.delenv("EDGE_ROUTER_SECRET", raising=False)
    monkeypatch.delenv("SMART_ROUTER_NONCE_JOURNAL_MAX_ENTRIES", raising=False)
    monkeypatch.delenv("SMART_ROUTER_NONCE_JOURNAL_MAX_BYTES", raising=False)
    monkeypatch.delenv("SMART_ROUTER_NONCE_JOURNAL_LOCK_TIMEOUT_MS", raising=False)
    monkeypatch.delenv("SMART_ROUTER_RATE_LIMIT_REQUESTS", raising=False)
    security.reset_security_state()
    return path


def _security_client() -> TestClient:
    app = FastAPI()
    app.add_middleware(security.RouterSecurityMiddleware)

    @app.get("/health")
    async def health():
        return {"ok": True}

    return TestClient(app)


def _public_readiness():
    import main

    return TestClient(main.app).get("/ready")


def test_default_journal_path_matches_deployment_state_directory(monkeypatch):
    monkeypatch.delenv("SMART_ROUTER_NONCE_JOURNAL_PATH", raising=False)
    assert security.replay_journal_path() == Path(
        "/var/lib/winsvpn-router/replay-nonces.sqlite3"
    )


def test_ready_missing_journal_preinitializes_without_a_nonce(journal_path):
    assert not journal_path.exists()
    security.replay_journal_ready()
    assert journal_path.exists()
    assert _journal_count(journal_path) == 0
    assert _journal_high_water(journal_path) == 0.0


def test_ready_existing_journal_is_non_destructive(journal_path):
    assert (
        DurableReplayGuard().accept("readiness-seed-nonce-01", 1000.0, 30.0)
        is ReplayDecision.ACCEPTED
    )
    before = journal_path.read_bytes()
    security.replay_journal_ready()
    assert journal_path.read_bytes() == before
    assert _journal_count(journal_path) == 1
    assert not journal_path.with_name(f"{journal_path.name}-journal").exists()


def test_ready_rejects_correctly_permissioned_corrupt_journal(journal_path):
    payload = b"not a sqlite database"
    journal_path.write_bytes(payload)
    journal_path.chmod(0o600)

    with pytest.raises(RuntimeError, match="readiness validation failed"):
        security.replay_journal_ready()

    response = _public_readiness()
    assert response.status_code == 503
    assert response.json()["ok"] is False
    assert journal_path.read_bytes() == payload


def test_ready_rejects_near_match_wrong_schema(journal_path):
    connection = sqlite3.connect(journal_path)
    try:
        connection.execute(
            "CREATE TABLE replay_nonces ("
            "nonce_hash BLOB PRIMARY KEY NOT NULL, "
            "accepted_at REAL NOT NULL, "
            "expires_at REAL NOT NULL"
            ") WITHOUT ROWID"
        )
        connection.execute("PRAGMA user_version=1")
        connection.commit()
    finally:
        connection.close()
    journal_path.chmod(0o600)
    before = journal_path.read_bytes()

    with pytest.raises(RuntimeError, match="schema version mismatch"):
        security.replay_journal_ready()

    response = _public_readiness()
    assert response.status_code == 503
    assert response.json()["ok"] is False
    assert journal_path.read_bytes() == before


def test_ready_rejects_writer_lock_after_bounded_wait(journal_path, monkeypatch):
    assert (
        DurableReplayGuard().accept("readiness-lock-seed-01", 1000.0, 30.0)
        is ReplayDecision.ACCEPTED
    )
    monkeypatch.setenv("SMART_ROUTER_NONCE_JOURNAL_LOCK_TIMEOUT_MS", "50")
    blocker = sqlite3.connect(journal_path, isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        started = time.monotonic()
        response = _public_readiness()
        elapsed = time.monotonic() - started
    finally:
        blocker.rollback()
        blocker.close()
    assert response.status_code == 503
    assert response.json()["ok"] is False
    assert 0.04 <= elapsed < 1.0


def test_ready_rejects_read_only_journal(journal_path):
    assert (
        DurableReplayGuard().accept("readiness-read-only-seed", 1000.0, 30.0)
        is ReplayDecision.ACCEPTED
    )
    journal_path.chmod(0o400)
    with pytest.raises(RuntimeError, match="permissions must be 0600"):
        security.replay_journal_ready()
    response = _public_readiness()
    assert response.status_code == 503
    assert response.json()["ok"] is False


def test_ready_rejects_full_like_metadata_probe(journal_path, monkeypatch):
    assert (
        DurableReplayGuard().accept("readiness-full-seed", 1000.0, 30.0)
        is ReplayDecision.ACCEPTED
    )
    original_connect = sqlite3.connect

    class FullReadinessConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if sql.startswith("UPDATE replay_state"):
                raise sqlite3.OperationalError("database or disk is full")
            return super().execute(sql, parameters)

    def full_readiness_connect(database, **kwargs):
        return original_connect(database, factory=FullReadinessConnection, **kwargs)

    monkeypatch.setattr(security.sqlite3, "connect", full_readiness_connect)
    with pytest.raises(RuntimeError, match="readiness validation failed"):
        security.replay_journal_ready()
    assert _journal_count(journal_path) == 1
    assert _journal_high_water(journal_path) == 1000.0


def _signed_health(client: TestClient, nonce: str):
    return _signed_health_at(client, nonce, int(time.time()))


def _signed_health_at(client: TestClient, nonce: str, timestamp: int):
    timestamp_value = str(timestamp)
    signature = sign_request(HMAC_SECRET, "GET", "/health", timestamp_value, nonce, b"")
    return client.get(
        "/health",
        headers={
            "X-Smart-Router-Timestamp": timestamp_value,
            "X-Smart-Router-Nonce": nonce,
            "X-Smart-Router-Signature": signature,
        },
    )


def test_nonce_survives_guard_restart(journal_path):
    nonce = "restart-safe-nonce-0001"
    assert DurableReplayGuard().accept(nonce, 1000.0, 30.0) is ReplayDecision.ACCEPTED
    assert DurableReplayGuard().accept(nonce, 1001.0, 30.0) is ReplayDecision.REPLAY


def test_same_nonce_race_is_atomic_across_processes(journal_path):
    context = multiprocessing.get_context("spawn")
    ready = context.Queue()
    start = context.Event()
    results = context.Queue()
    workers = [
        context.Process(
            target=_process_accept,
            args=(str(journal_path), ready, start, results),
        )
        for _ in range(6)
    ]
    for worker in workers:
        worker.start()
    for _ in workers:
        assert ready.get(timeout=15) is True
    start.set()
    decisions = [results.get(timeout=15) for _ in workers]
    for worker in workers:
        worker.join(timeout=15)
        assert worker.exitcode == 0
    assert decisions.count(ReplayDecision.ACCEPTED.value) == 1
    assert decisions.count(ReplayDecision.REPLAY.value) == len(workers) - 1


def test_replay_retention_end_covers_both_hmac_boundaries():
    assert replay_retention_end(100.0, 30.0, 70.0) == 100.0
    assert replay_retention_end(100.0, 30.0, 100.0) == 130.0
    assert replay_retention_end(100.0, 30.0, 130.0) == 160.0
    assert replay_retention_end(100.0, 30.0) == 160.0
    with pytest.raises(ValueError):
        replay_retention_end(100.0, 30.0, 69.999)
    with pytest.raises(ValueError):
        replay_retention_end(100.0, 30.0, 130.0001)
    with pytest.raises(ValueError):
        replay_retention_end(100.0, 0.0)


def test_expiry_boundary_outlives_hmac_window_including_future_skew(journal_path):
    guard = DurableReplayGuard()
    nonce = "expiry-boundary-nonce-01"
    assert guard.accept(nonce, 100.0, 30.0) is ReplayDecision.ACCEPTED
    assert guard.accept(nonce, 159.999, 30.0) is ReplayDecision.REPLAY
    assert guard.accept(nonce, 160.0, 30.0) is ReplayDecision.REPLAY
    assert guard.accept(nonce, 160.0001, 30.0) is ReplayDecision.ACCEPTED


def test_same_nonce_blocked_at_past_hmac_timestamp_boundary(journal_path):
    guard = DurableReplayGuard()
    nonce = "past-boundary-nonce-0001"
    assert guard.accept(nonce, 100.0, 30.0, 70.0) is ReplayDecision.ACCEPTED
    assert guard.accept(nonce, 100.0, 30.0, 70.0) is ReplayDecision.REPLAY
    assert guard.accept(nonce, 100.0, 30.0, 100.0) is ReplayDecision.REPLAY
    assert guard.accept(nonce, 100.0001, 30.0, 100.0001) is ReplayDecision.ACCEPTED


def test_same_nonce_blocked_at_future_hmac_timestamp_boundary(journal_path):
    guard = DurableReplayGuard()
    nonce = "future-boundary-nonce-01"
    assert guard.accept(nonce, 100.0, 30.0, 130.0) is ReplayDecision.ACCEPTED
    assert guard.accept(nonce, 130.0, 30.0, 130.0) is ReplayDecision.REPLAY
    assert guard.accept(nonce, 160.0, 30.0, 130.0) is ReplayDecision.REPLAY
    assert DurableReplayGuard().accept(nonce, 160.0, 30.0, 130.0) is ReplayDecision.REPLAY
    assert guard.accept(nonce, 160.0001, 30.0, 160.0001) is ReplayDecision.ACCEPTED


def test_future_skewed_nonce_survives_restart_through_hmac_boundary(journal_path):
    nonce = "restart-future-skew-n01"
    assert DurableReplayGuard().accept(nonce, 100.0, 30.0, 130.0) is ReplayDecision.ACCEPTED
    assert DurableReplayGuard().accept(nonce, 160.0, 30.0, 130.0) is ReplayDecision.REPLAY


def test_forward_jump_persists_high_water_and_rollback_fails_closed(journal_path):
    guard = DurableReplayGuard()
    evicted = "forward-jump-evicted-n01"
    assert guard.accept(evicted, 1000.0, 30.0) is ReplayDecision.ACCEPTED
    assert guard.accept("forward-jump-new-nonce", 2000.0, 30.0) is ReplayDecision.ACCEPTED
    assert _journal_high_water(journal_path) == 2000.0
    assert _journal_count(journal_path) == 1

    assert guard.accept(evicted, 1001.0, 30.0) is ReplayDecision.UNAVAILABLE
    assert _journal_high_water(journal_path) == 2000.0


def test_invalid_ttl_or_timestamp_fails_closed(journal_path):
    guard = DurableReplayGuard()
    assert guard.accept("invalid-ttl-nonce-00001", 100.0, 0.0) is ReplayDecision.UNAVAILABLE
    assert guard.accept("outside-window-nonce-01", 100.0, 30.0, 69.0) is ReplayDecision.UNAVAILABLE
    assert guard.accept("outside-window-nonce-02", 100.0, 30.0, 131.0) is ReplayDecision.UNAVAILABLE


def test_unexpired_capacity_bound_fails_closed(journal_path, monkeypatch):
    monkeypatch.setenv("SMART_ROUTER_NONCE_JOURNAL_MAX_ENTRIES", "256")
    guard = DurableReplayGuard()
    for index in range(256):
        nonce = f"capacity-nonce-{index:04d}"
        assert guard.accept(nonce, 1000.0, 30.0) is ReplayDecision.ACCEPTED
    assert guard.accept("capacity-nonce-overflow", 1001.0, 30.0) is ReplayDecision.UNAVAILABLE
    assert guard.accept("capacity-nonce-0000", 1001.0, 30.0) is ReplayDecision.REPLAY
    assert guard.accept("capacity-after-expiry", 1060.0, 30.0) is ReplayDecision.UNAVAILABLE
    assert guard.accept("capacity-nonce-0000", 1060.0, 30.0) is ReplayDecision.REPLAY
    assert guard.accept("capacity-after-expiry", 1060.0001, 30.0) is ReplayDecision.ACCEPTED


def test_corrupt_database_fails_closed(journal_path):
    guard = DurableReplayGuard()
    assert guard.accept("corruption-seed-nonce", 1000.0, 30.0) is ReplayDecision.ACCEPTED
    journal_path.write_bytes(b"not a sqlite database")
    journal_path.chmod(0o600)
    assert guard.accept("corruption-new-nonce", 1001.0, 30.0) is ReplayDecision.UNAVAILABLE


def test_simulated_full_disk_write_rolls_back_and_fails_closed(journal_path, monkeypatch):
    original_connect = sqlite3.connect

    class DiskFullConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if sql.startswith("INSERT INTO replay_nonces"):
                raise sqlite3.OperationalError("database or disk is full")
            return super().execute(sql, parameters)

    def disk_full_connect(database, **kwargs):
        return original_connect(database, factory=DiskFullConnection, **kwargs)

    monkeypatch.setattr(security.sqlite3, "connect", disk_full_connect)
    guard = DurableReplayGuard()
    assert guard.accept("disk-full-nonce-0001", 1000.0, 30.0) is ReplayDecision.UNAVAILABLE

    monkeypatch.setattr(security.sqlite3, "connect", original_connect)
    assert guard.accept("disk-full-nonce-0001", 1001.0, 30.0) is ReplayDecision.ACCEPTED


def test_locked_database_fails_closed_after_bounded_wait(journal_path, monkeypatch):
    guard = DurableReplayGuard()
    assert guard.accept("lock-seed-nonce-0001", 1000.0, 30.0) is ReplayDecision.ACCEPTED
    monkeypatch.setenv("SMART_ROUTER_NONCE_JOURNAL_LOCK_TIMEOUT_MS", "50")
    blocker = sqlite3.connect(journal_path, isolation_level=None)
    blocker.execute("BEGIN EXCLUSIVE")
    try:
        started = time.monotonic()
        decision = guard.accept("lock-new-nonce-0001", 1001.0, 30.0)
        elapsed = time.monotonic() - started
    finally:
        blocker.rollback()
        blocker.close()
    assert decision is ReplayDecision.UNAVAILABLE
    assert elapsed < 1.0


def test_lock_stall_is_capped_by_absolute_worker_deadline(journal_path, monkeypatch):
    assert (
        DurableReplayGuard().accept("deadline-lock-seed-0001", 1000.0, 30.0)
        is ReplayDecision.ACCEPTED
    )
    monkeypatch.setenv("SMART_ROUTER_NONCE_JOURNAL_LOCK_TIMEOUT_MS", "2000")
    blocker = sqlite3.connect(journal_path, isolation_level=None)
    blocker.execute("BEGIN EXCLUSIVE")
    try:
        deadline = time.monotonic() + 0.15
        started = time.monotonic()
        decision = DurableReplayGuard().accept(
            "deadline-lock-new-01",
            1001.0,
            30.0,
            deadline=deadline,
        )
        elapsed = time.monotonic() - started
    finally:
        blocker.rollback()
        blocker.close()
    assert decision is ReplayDecision.UNAVAILABLE
    assert elapsed < 0.75
    assert _journal_count(journal_path) == 1


def test_expired_worker_does_not_create_a_missing_journal(journal_path):
    deadline = time.monotonic() - 1.0
    decision = DurableReplayGuard().accept(
        "expired-before-open-01",
        1000.0,
        30.0,
        deadline=deadline,
    )
    assert decision is ReplayDecision.UNAVAILABLE
    assert not journal_path.exists()


def test_worker_deadline_caps_sqlite_connection_and_busy_timeouts(
    journal_path,
    monkeypatch,
):
    clock = {"now": 100.0}
    monkeypatch.setattr(security.time, "monotonic", lambda: clock["now"])
    original_connect = sqlite3.connect
    captured = {}

    class CapturingConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if sql.startswith("PRAGMA busy_timeout="):
                captured["busy_timeout_ms"] = int(sql.rsplit("=", 1)[1])
            return super().execute(sql, parameters)

    def capturing_connect(database, **kwargs):
        captured["connect_timeout_s"] = kwargs["timeout"]
        return original_connect(database, factory=CapturingConnection, **kwargs)

    monkeypatch.setattr(security.sqlite3, "connect", capturing_connect)
    assert DurableReplayGuard().accept(
        "deadline-timeout-cap-01",
        1000.0,
        30.0,
        deadline=100.25,
    ) is ReplayDecision.ACCEPTED
    assert captured["connect_timeout_s"] <= 0.25
    assert captured["busy_timeout_ms"] <= 250


def test_deadline_before_commit_rolls_back_nonce_and_high_water(
    journal_path,
    monkeypatch,
):
    clock = {"now": 0.0}
    monkeypatch.setattr(security.time, "monotonic", lambda: clock["now"])
    original_connect = sqlite3.connect

    class DeadlineBeforeCommitConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            result = super().execute(sql, parameters)
            if sql == "SELECT COUNT(*) FROM replay_nonces":
                clock["now"] = 10.0
            return result

    def deadline_connect(database, **kwargs):
        return original_connect(
            database,
            factory=DeadlineBeforeCommitConnection,
            **kwargs,
        )

    monkeypatch.setattr(security.sqlite3, "connect", deadline_connect)
    decision = DurableReplayGuard().accept(
        "deadline-before-commit-01",
        1000.0,
        30.0,
        deadline=5.0,
    )
    assert decision is ReplayDecision.UNAVAILABLE
    connection = sqlite3.connect(journal_path)
    try:
        assert connection.execute(
            "SELECT name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"
        ).fetchall() == []
    finally:
        connection.close()

    monkeypatch.setattr(security.sqlite3, "connect", original_connect)
    assert DurableReplayGuard().accept(
        "deadline-after-rollback-01",
        10.0,
        30.0,
    ) is ReplayDecision.ACCEPTED
    assert _journal_high_water(journal_path) == 10.0


def test_symlink_and_hardlink_journals_fail_closed(journal_path, tmp_path, monkeypatch):
    target = tmp_path / "target.sqlite3"
    target.write_bytes(b"")
    target.chmod(0o600)
    journal_path.symlink_to(target)
    assert (
        DurableReplayGuard().accept("symlink-journal-nonce", 1000.0, 30.0)
        is ReplayDecision.UNAVAILABLE
    )

    journal_path.unlink()
    assert (
        DurableReplayGuard().accept("hardlink-seed-nonce", 1000.0, 30.0)
        is ReplayDecision.ACCEPTED
    )
    second_link = journal_path.with_name("second-link.sqlite3")
    os.link(journal_path, second_link)
    assert (
        DurableReplayGuard().accept("hardlink-new-nonce", 1001.0, 30.0)
        is ReplayDecision.UNAVAILABLE
    )


@pytest.mark.parametrize("mode", [0o644, 0o660, 0o777])
def test_insecure_file_permissions_fail_closed(journal_path, mode):
    guard = DurableReplayGuard()
    assert guard.accept("permission-seed-nonce", 1000.0, 30.0) is ReplayDecision.ACCEPTED
    journal_path.chmod(mode)
    assert guard.accept("permission-new-nonce", 1001.0, 30.0) is ReplayDecision.UNAVAILABLE


def test_insecure_or_symlinked_parent_fails_closed(journal_path, tmp_path, monkeypatch):
    journal_path.parent.chmod(0o755)
    assert (
        DurableReplayGuard().accept("parent-mode-nonce-01", 1000.0, 30.0)
        is ReplayDecision.UNAVAILABLE
    )

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir(mode=0o700)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    monkeypatch.setenv(
        "SMART_ROUTER_NONCE_JOURNAL_PATH",
        str(linked_parent / "journal.sqlite3"),
    )
    assert (
        DurableReplayGuard().accept("parent-link-nonce-01", 1000.0, 30.0)
        is ReplayDecision.UNAVAILABLE
    )


def test_raw_nonce_is_not_persisted(journal_path):
    nonce = "raw-nonce-must-not-be-stored"
    assert DurableReplayGuard().accept(nonce, 1000.0, 30.0) is ReplayDecision.ACCEPTED
    assert nonce.encode("ascii") not in journal_path.read_bytes()


def test_storage_failure_response_and_logs_contain_no_credentials(
    journal_path,
    monkeypatch,
    caplog,
):
    nonce = secrets.token_urlsafe(18)

    def failed_connect(*args, **kwargs):
        raise sqlite3.OperationalError(
            f"disk failure secret={HMAC_SECRET} nonce={nonce}"
        )

    monkeypatch.setattr(security.sqlite3, "connect", failed_connect)
    caplog.set_level(logging.DEBUG)
    response = _signed_health(_security_client(), nonce)
    rendered = response.text + caplog.text
    assert response.status_code == 503
    assert response.json() == {"detail": "replay protection unavailable"}
    assert HMAC_SECRET not in rendered
    assert nonce not in rendered


def test_invalid_journal_configuration_fails_closed(journal_path, monkeypatch):
    monkeypatch.setenv("SMART_ROUTER_NONCE_JOURNAL_PATH", "relative.sqlite3")
    response = _signed_health(_security_client(), "invalid-path-nonce-01")
    assert response.status_code == 503
    assert response.json() == {"detail": "replay protection unavailable"}


def _journal_count(path: Path) -> int:
    if not path.is_file():
        return 0
    connection = sqlite3.connect(path)
    try:
        row = connection.execute("SELECT COUNT(*) FROM replay_nonces").fetchone()
        return int(row[0]) if row else 0
    finally:
        connection.close()


def _journal_high_water(path: Path) -> float:
    connection = sqlite3.connect(path)
    try:
        row = connection.execute(
            "SELECT wall_clock_high_water FROM replay_state WHERE singleton = 1"
        ).fetchone()
        assert row is not None
        return float(row[0])
    finally:
        connection.close()


def test_same_nonce_race_is_atomic_across_threads(journal_path):
    barrier = threading.Barrier(8)
    results: list[str] = []
    lock = threading.Lock()

    def worker() -> None:
        barrier.wait(timeout=10)
        decision = DurableReplayGuard().accept("shared-thread-nonce", 1000.0, 30.0)
        with lock:
            results.append(decision.value)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)
        assert not thread.is_alive()
    assert results.count(ReplayDecision.ACCEPTED.value) == 1
    assert results.count(ReplayDecision.REPLAY.value) == 7
    assert _journal_count(journal_path) == 1


def test_rate_limited_authenticated_flood_does_not_exhaust_journal(
    journal_path,
    monkeypatch,
):
    monkeypatch.setenv("SMART_ROUTER_RATE_LIMIT_REQUESTS", "1")
    monkeypatch.setenv("SMART_ROUTER_NONCE_JOURNAL_MAX_ENTRIES", "256")
    security.reset_security_state()
    client = _security_client()
    first = _signed_health(client, "rate-limit-seed-nonce01")
    assert first.status_code == 200
    rejected: list[str] = []
    for index in range(255):
        nonce = f"rate-limit-flood-{index:04d}-xx"
        response = _signed_health(client, nonce)
        assert response.status_code == 429
        assert response.json() == {"detail": "rate limit exceeded"}
        rejected.append(nonce)
    assert len(rejected) == 255
    assert _journal_count(journal_path) == 1

    security.reset_security_state()
    reused = _signed_health(client, rejected[0])
    assert reused.status_code == 200
    assert _journal_count(journal_path) == 2
    security.reset_security_state()
    follow = _signed_health(client, "rate-limit-after-reset01")
    assert follow.status_code == 200
    assert _journal_count(journal_path) == 3
    security.reset_security_state()
    replay = _signed_health(client, "rate-limit-seed-nonce01")
    assert replay.status_code == 401
    assert replay.json() == {"detail": "replayed request"}
    assert _journal_count(journal_path) == 3


def _health_app():
    app = FastAPI()
    app.add_middleware(security.RouterSecurityMiddleware)

    @app.get("/health")
    async def health():
        return {"ok": True}

    return app


def test_http_same_nonce_race_admits_only_one(journal_path):
    app = _health_app()
    nonce = "http-race-nonce-00001"
    timestamp = str(int(time.time()))
    signature = sign_request(HMAC_SECRET, "GET", "/health", timestamp, nonce, b"")
    headers = {
        "X-Smart-Router-Timestamp": timestamp,
        "X-Smart-Router-Nonce": nonce,
        "X-Smart-Router-Signature": signature,
    }

    async def run() -> list[int]:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            responses = await asyncio.gather(
                *[client.get("/health", headers=headers) for _ in range(8)]
            )
            return [response.status_code for response in responses]

    codes = asyncio.run(run())
    assert codes.count(200) == 1
    assert codes.count(401) == 7
    assert _journal_count(journal_path) == 1


def test_concurrent_unique_nonces_honor_rate_limit_without_journal_fill(
    journal_path,
    monkeypatch,
):
    monkeypatch.setenv("SMART_ROUTER_RATE_LIMIT_REQUESTS", "1")
    security.reset_security_state()
    app = _health_app()

    async def run() -> list[int]:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            async def one(index: int):
                nonce = f"concurrent-unique-{index:04d}"
                timestamp = str(int(time.time()))
                signature = sign_request(
                    HMAC_SECRET,
                    "GET",
                    "/health",
                    timestamp,
                    nonce,
                    b"",
                )
                return await client.get(
                    "/health",
                    headers={
                        "X-Smart-Router-Timestamp": timestamp,
                        "X-Smart-Router-Nonce": nonce,
                        "X-Smart-Router-Signature": signature,
                    },
                )

            responses = await asyncio.gather(*[one(index) for index in range(8)])
            return [response.status_code for response in responses]

    codes = asyncio.run(run())
    assert codes.count(200) == 1
    assert codes.count(429) == 7
    assert _journal_count(journal_path) == 1


FROZEN_NOW = 1_700_000_100.0
AUTH_WINDOW = 30


def _freeze_router_clock(monkeypatch, current):
    monkeypatch.setattr(security.time, "time", lambda: current["now"])


@pytest.mark.parametrize("offset", [-AUTH_WINDOW, 0, AUTH_WINDOW])
def test_http_same_nonce_rejected_at_auth_window_boundary(
    journal_path,
    monkeypatch,
    offset,
):
    current = {"now": FROZEN_NOW}
    _freeze_router_clock(monkeypatch, current)
    nonce = (
        "http-boundary-past-n01"
        if offset < 0
        else "http-boundary-future-n1"
        if offset > 0
        else "http-boundary-center-n1"
    )
    timestamp = int(FROZEN_NOW) + offset
    client = _security_client()
    first = _signed_health_at(client, nonce, timestamp)
    second = _signed_health_at(client, nonce, timestamp)
    assert first.status_code == 200
    assert second.status_code == 401
    assert second.json() == {"detail": "replayed request"}


@pytest.mark.parametrize("offset", [-(AUTH_WINDOW + 1), AUTH_WINDOW + 1])
def test_http_hmac_outside_auth_window_is_rejected(
    journal_path,
    monkeypatch,
    offset,
):
    current = {"now": FROZEN_NOW}
    _freeze_router_clock(monkeypatch, current)
    nonce = "http-outside-past-n0001" if offset < 0 else "http-outside-future-n001"
    response = _signed_health_at(_security_client(), nonce, int(FROZEN_NOW) + offset)
    assert response.status_code == 401
    assert response.json() == {"detail": "authentication required"}
    assert _journal_count(journal_path) == 0


def test_http_future_skewed_nonce_blocked_until_timestamp_is_stale(
    journal_path,
    monkeypatch,
):
    current = {"now": FROZEN_NOW}
    _freeze_router_clock(monkeypatch, current)
    nonce = "http-future-skew-nonce01"
    timestamp = int(FROZEN_NOW) + AUTH_WINDOW
    client = _security_client()
    first = _signed_health_at(client, nonce, timestamp)
    assert first.status_code == 200

    for later in (FROZEN_NOW + AUTH_WINDOW, FROZEN_NOW + (2 * AUTH_WINDOW)):
        current["now"] = later
        replay = _signed_health_at(client, nonce, timestamp)
        assert replay.status_code == 401
        assert replay.json() == {"detail": "replayed request"}

    current["now"] = FROZEN_NOW + (2 * AUTH_WINDOW) + 1
    stale = _signed_health_at(client, nonce, timestamp)
    assert stale.status_code == 401
    assert stale.json() == {"detail": "authentication required"}
