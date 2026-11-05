#!/usr/bin/env python3
"""Real-hub regression tests for account expiry runtime revocation."""
from contextlib import closing
import _toolchain  # noqa: F401
import asyncio
import sqlite3
import traceback
from datetime import timedelta

from test_account_deletion_hub import (
    ACCOUNT,
    BackgroundTasks,
    FakeRequest,
    load_hub,
    seed_account,
)


def seed_expiring_runtime(mod, *, status="active"):
    expiry = (mod.utcnow() - timedelta(minutes=5)).isoformat()
    tokens = seed_account(mod, devices=1, expiration=expiry)
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        conn.execute(
            "INSERT OR REPLACE INTO nodes "
            "(slug, name, endpoint, ssh_host, status) VALUES (?, ?, ?, ?, ?)",
            ("test-node", "Test", "198.51.100.10:9110", "198.51.100.10", "online"),
        )
        conn.execute(
            "UPDATE users SET status=? WHERE account_number=?",
            (status, ACCOUNT),
        )
        conn.commit()
    return tokens


def counts(mod):
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        user = conn.execute(
            "SELECT status FROM users WHERE account_number=?", (ACCOUNT,)
        ).fetchone()
        devices = conn.execute(
            "SELECT COUNT(*) AS n FROM devices WHERE account_number=?", (ACCOUNT,)
        ).fetchone()["n"]
        queued = conn.execute(
            "SELECT COUNT(*) AS n FROM peer_revocations"
        ).fetchone()["n"]
        return user["status"], devices, queued


def test_status_transition_queues_revocation_before_expired_response():
    mod = load_hub()
    tokens = seed_expiring_runtime(mod)
    device, token = next(iter(tokens.items()))
    tasks = BackgroundTasks()
    payload = asyncio.run(
        mod.account_status(
            mod.AccountStatusRequest(account_number=ACCOUNT, device_id=device),
            FakeRequest(path="/account/status", headers={"authorization": f"Bearer {token}"}),
            tasks,
        )
    )
    assert payload["status"] == "expired"
    assert counts(mod) == ("expired", 0, 1)
    assert any(task[0] is mod.drain_peer_revocation_outbox for task in tasks.tasks)


def test_already_expired_runtime_is_backfilled_idempotently():
    mod = load_hub()
    seed_expiring_runtime(mod, status="expired")
    assert mod.sweep_expired_account_runtime() == 1
    assert counts(mod) == ("expired", 0, 1)
    assert mod.sweep_expired_account_runtime() == 0
    assert counts(mod) == ("expired", 0, 1)


def test_peer_removal_failure_stays_durable_until_success():
    mod = load_hub()
    seed_expiring_runtime(mod, status="expired")
    mod.sweep_expired_account_runtime()
    mod.remove_peer_from_node = lambda *_: False
    assert mod.drain_peer_revocation_outbox() == {"removed": 0, "retry": 1}
    assert counts(mod) == ("expired", 0, 1)
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute(
            "UPDATE peer_revocations SET next_attempt_at=0, lease_until=NULL"
        )
        conn.commit()
    mod.remove_peer_from_node = lambda *_: True
    assert mod.drain_peer_revocation_outbox() == {"removed": 1, "retry": 0}
    assert counts(mod) == ("expired", 0, 0)


def test_outbox_insert_failure_rolls_back_status_and_device_deletion():
    mod = load_hub()
    seed_expiring_runtime(mod)
    try:
        with mod.get_db() as conn:
            mod.ensure_schema(conn)
            conn.execute("""
                CREATE TRIGGER reject_peer_revocation
                BEFORE INSERT ON peer_revocations
                BEGIN
                    SELECT RAISE(ABORT, 'injected');
                END
            """)
            mod.expire_account_runtime_if_due(conn, ACCOUNT)
    except sqlite3.IntegrityError:
        pass
    else:
        raise AssertionError("injected outbox failure did not abort")
    assert counts(mod) == ("active", 1, 0)


TESTS = (
    test_status_transition_queues_revocation_before_expired_response,
    test_already_expired_runtime_is_backfilled_idempotently,
    test_peer_removal_failure_stays_durable_until_success,
    test_outbox_insert_failure_rolls_back_status_and_device_deletion,
)


if __name__ == "__main__":
    failures = 0
    for test in TESTS:
        try:
            test()
            print(f"PASS {test.__name__}")
        except Exception:
            failures += 1
            print(f"FAIL {test.__name__}")
            traceback.print_exc()
    print(f"\n{len(TESTS) - failures} passed, {failures} failed")
    raise SystemExit(1 if failures else 0)
