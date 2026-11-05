#!/usr/bin/env python3
"""Fail-closed regression tests for the embedded PayPal entitlement handler."""

from __future__ import annotations

import ast
import hashlib
import hmac
import os
import re
import sqlite3
import urllib.parse
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Optional


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"
PRESEED = ROOT / "tools" / "wins_deployment_preseed.ps1"
RUNTIME_TEST = ROOT / "tools" / "test_deployment_runtime_configs.sh"

REQUIRED_EVENTS = {
    "BILLING.SUBSCRIPTION.ACTIVATED",
    "BILLING.SUBSCRIPTION.UPDATED",
    "BILLING.SUBSCRIPTION.RE-ACTIVATED",
    "BILLING.SUBSCRIPTION.CANCELLED",
    "BILLING.SUBSCRIPTION.SUSPENDED",
    "BILLING.SUBSCRIPTION.EXPIRED",
    "BILLING.SUBSCRIPTION.PAYMENT.FAILED",
    "PAYMENT.SALE.COMPLETED",
    "PAYMENT.SALE.REFUNDED",
    "PAYMENT.SALE.REVERSED",
    "PAYMENT.CAPTURE.COMPLETED",
    "PAYMENT.CAPTURE.REFUNDED",
    "PAYMENT.CAPTURE.REVERSED",
}


def embedded_app_source(installer: str) -> str:
    marker = 'cat > "${APP_DIR}/main.py" <<\'PYEOF\''
    start = installer.index(marker)
    start = installer.index("\n", start) + 1
    end = installer.index("\nPYEOF", start)
    return installer[start:end]


def load_functions(source: str, names: set[str], namespace: dict[str, Any]) -> dict[str, Any]:
    tree = ast.parse(source)
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    found = {node.name for node in functions}
    if found != names:
        raise AssertionError(f"missing embedded functions: {sorted(names - found)}")
    exec(compile(ast.Module(body=functions, type_ignores=[]), "embedded-paypal-functions", "exec"), namespace)
    return namespace


def canonical_sources() -> tuple[str, str]:
    installer = INSTALLER.read_text(encoding="utf-8")
    app = embedded_app_source(installer)
    compile(app, "embedded-main.py", "exec")
    return installer, app


def test_event_contract() -> None:
    installer, app = canonical_sources()
    for path in (INSTALLER, PRESEED, RUNTIME_TEST):
        content = path.read_text(encoding="utf-8")
        missing = REQUIRED_EVENTS - {event for event in REQUIRED_EVENTS if event in content}
        assert not missing, f"{path.name} lacks required PayPal events: {sorted(missing)}"
        assert "CHECKOUT.ORDER.APPROVED" not in content, f"{path.name} still subscribes to pre-capture approval"
    assert 'PAYPAL_ACTIVE_STATUSES = {"ACTIVE"}' in app
    assert "paypal_purchase_reference TEXT" in installer
    assert "lifetime_amount_currency_mismatch" in app


def test_marker_and_reference_helpers() -> None:
    _, app = canonical_sources()
    namespace: dict[str, Any] = {
        "Any": Any,
        "Decimal": Decimal,
        "InvalidOperation": InvalidOperation,
        "os": os,
        "re": re,
        "urllib": __import__("urllib"),
        "PAYPAL_LIFETIME_SUPPORT_AMOUNT": "1000.00",
        "PAYPAL_LIFETIME_NO_SUPPORT_AMOUNT": "100.00",
        "PAYPAL_LIFETIME_CURRENCY": "USD",
    }
    load_functions(
        app,
        {
            "find_first_key",
            "paypal_link_markers",
            "normalize_paypal_reference",
            "paypal_parent_payment_reference",
            "paypal_payment_references",
            "paypal_refund_is_terminal",
            "validate_lifetime_payment_contract",
        },
        namespace,
    )
    assert namespace["paypal_link_markers"]("https://www.paypal.com/ncp/payment/Y2T86YRNDNQE6") == ("y2t86yrndnqe6",)
    assert namespace["paypal_link_markers"]("https://www.paypal.com/payment") == ()
    assert namespace["validate_lifetime_payment_contract"](
        {"amount": {"value": "1000.00", "currency_code": "USD"}}, "lifetime_support"
    )
    assert not namespace["validate_lifetime_payment_contract"](
        {"amount": {"value": "1.00", "currency_code": "USD"}}, "lifetime_support"
    )
    refund_resource = {
        "id": "REFUND123456",
        "status": "COMPLETED",
        "links": [{"rel": "up", "href": "https://api-m.paypal.com/v2/payments/captures/CAPTURE123456"}],
    }
    assert namespace["paypal_payment_references"]("PAYMENT.CAPTURE.REFUNDED", refund_resource) == ("CAPTURE123456",)
    namespace["paypal_json_request"] = lambda method, path: {"status": "PARTIALLY_REFUNDED"}
    terminal, references, subscription_id = namespace["paypal_refund_is_terminal"]("PAYMENT.CAPTURE.REFUNDED", refund_resource)
    assert terminal is False and references == ("CAPTURE123456",) and not subscription_id
    namespace["paypal_json_request"] = lambda method, path: {"status": "REFUNDED"}
    terminal, references, subscription_id = namespace["paypal_refund_is_terminal"]("PAYMENT.CAPTURE.REFUNDED", refund_resource)
    assert terminal is True and references == ("CAPTURE123456",) and not subscription_id
    sale_refund = {"id": "REFUND987654", "state": "completed", "sale_id": "SALE987654", "parent_payment": "PAYMENT987654"}
    assert namespace["paypal_parent_payment_reference"](sale_refund, "sale") == "SALE987654"
    namespace["paypal_json_request"] = lambda method, path: {"state": "refunded", "billing_agreement_id": "SUBSCRIPTION987654"}
    terminal, references, subscription_id = namespace["paypal_refund_is_terminal"]("PAYMENT.SALE.REFUNDED", sale_refund)
    assert terminal is True and references == ("SALE987654",) and subscription_id == "SUBSCRIPTION987654"


def test_upsert_sql() -> None:
    _, app = canonical_sources()
    import hashlib
    import hmac
    import secrets

    namespace: dict[str, Any] = {
        "Optional": Optional,
        "sqlite3": sqlite3,
        "datetime": datetime,
        "timezone": timezone,
        "timedelta": timedelta,
        "_ACTIVATION_SECRET_PEPPER": b"audit-test-only-pepper",
        "hashlib": hashlib,
        "hmac": hmac,
        "secrets": secrets,
        "DEVICE_LIMIT": 3,
        "PAYPAL_ACTIVE_STATUSES": {"ACTIVE"},
        "PAYPAL_INACTIVE_STATUSES": {"CANCELLED", "SUSPENDED", "EXPIRED", "PAYMENT_FAILED", "REFUNDED", "REVERSED"},
        "ensure_schema": lambda conn: None,
        "normalize_referral_code": lambda value: "",
        "paypal_duration_for_plan": lambda plan: timedelta(days=30),
        "parse_duration": lambda text: timedelta(days=30),
        "parse_paypal_datetime": lambda value: None,
        "parse_iso_datetime": lambda value: datetime.fromisoformat(value) if value else None,
        "apply_referral_bonus": lambda conn, **kwargs: (kwargs["base_expiry"], 0, ""),
        "new_account_number": lambda conn: "1111-2222-3333",
        "new_referral_code": lambda conn: "referral1234",
        "ensure_referral_code": lambda conn, account: "referral1234",
    }
    # H-1: upsert_paypal_account mints a fresh activation key set (via
    # issue_activation_secrets/issue_activation_secret/token_digest) on the
    # create branch only. Load the real embedded implementations rather than
    # mocking them, so this test exercises the exact hashing the live /verify
    # endpoint checks.
    load_functions(
        app,
        {"now_utc", "utcnow", "upsert_paypal_account", "issue_activation_secret", "issue_activation_secrets",
         "activation_key_count", "token_digest", "_hash_activation_secret", "create_paypal_events_table",
         "create_activation_extra_keys_table"},
        namespace,
    )
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE users (
          account_number TEXT PRIMARY KEY, email TEXT, subscriber_name TEXT, status TEXT,
          expiration_date TEXT, paypal_subscription_id TEXT, paypal_plan_id TEXT,
          paypal_payer_id TEXT, paypal_status TEXT, paypal_purchase_reference TEXT,
          last_paypal_sync TEXT, renewal_source TEXT, referral_code TEXT,
          referred_by_account_number TEXT, referral_bonus_days INTEGER DEFAULT 0,
          referral_bonus_applied_at TEXT, activation_secret_hash TEXT,
          activation_secret_expires_at TEXT, activation_secret_used_at TEXT
        )
        """
    )
    namespace["create_paypal_events_table"](conn)
    namespace["create_activation_extra_keys_table"](conn)
    upsert = namespace["upsert_paypal_account"]
    activation_digest = namespace["_hash_activation_secret"]
    account, created, _, activation_secrets = upsert(
        conn,
        email="buyer@example.com",
        subscriber_name="Buyer",
        subscription_id="",
        plan_id="lifetime_support",
        payer_id="PAYER123456",
        paypal_status="ACTIVE",
        next_billing_time=None,
        duration_text="10y",
        paypal_purchase_reference="CAPTURE123456",
    )
    assert account == "1111-2222-3333" and created is True
    row = conn.execute(
        "SELECT status, paypal_purchase_reference, activation_secret_hash FROM users"
    ).fetchone()
    assert row["status"] == "active" and row["paypal_purchase_reference"] == "CAPTURE123456"
    # A brand-new account must get one activation key per device slot (a list,
    # first key first), and only digests may end up stored in the DB, never the
    # plaintext.
    assert len(activation_secrets) == 3 and len(set(activation_secrets)) == 3
    assert activation_secrets[0] != row["activation_secret_hash"]
    assert row["activation_secret_hash"] == activation_digest(activation_secrets[0])
    extra_hashes = [r[0] for r in conn.execute("SELECT secret_hash FROM activation_extra_keys ORDER BY slot")]
    assert extra_hashes == [activation_digest(key) for key in activation_secrets[1:]]
    _, created, _, renewal_activation_secrets = upsert(
        conn,
        email="buyer@example.com",
        subscriber_name="Buyer",
        subscription_id="SUBSCRIPTION123",
        plan_id="PLAN123456",
        payer_id="PAYER123456",
        paypal_status="ACTIVE",
        next_billing_time=None,
        paypal_purchase_reference="SALE123456",
    )
    assert created is False
    # A renewal of an existing account must not mint or rotate any secret.
    assert renewal_activation_secrets == []
    assert conn.execute("SELECT paypal_purchase_reference FROM users").fetchone()[0] == "SALE123456"
    assert conn.execute("SELECT activation_secret_hash FROM users").fetchone()[0] == activation_digest(activation_secrets[0])
    assert [r[0] for r in conn.execute("SELECT secret_hash FROM activation_extra_keys ORDER BY slot")] == extra_hashes


def test_referral_bonus_clawback() -> None:
    _, app = canonical_sources()
    # A referred purchase used to grant the referrer time with nothing
    # reacting when that purchase was later cancelled/refunded/reversed --
    # the referrer kept the granted time for free. claw_back_referral_bonus
    # is called from both the stop_events and refund_events webhook branches
    # for the referred account; this loads the real embedded implementation
    # (not a stub) and proves it actually reverses both effects
    # apply_referral_bonus applied, and that it's idempotent against a
    # duplicate event (e.g. a cancellation followed by a later refund for
    # the same purchase).
    namespace: dict[str, Any] = {
        "sqlite3": sqlite3,
        "datetime": datetime,
        "timezone": timezone,
        "timedelta": timedelta,
        "parse_iso_datetime": lambda value: datetime.fromisoformat(value) if value else None,
        "hmac": hmac,
        "hashlib": hashlib,
        # The real embedded claw_back_referral_bonus resolves the tombstone for
        # a deleted referred account through the app's own helpers, so those
        # need to be loadable here too. RATE_LIMIT_SECRET is a runtime secret;
        # a fixed test double is sufficient because the tombstone path is only
        # an input to the clawback under test, never a guarantee under test.
        "RATE_LIMIT_SECRET": "test-double-00000000000000000000",
    }
    load_functions(
        app,
        {
            "now_utc",
            "utcnow",
            "claw_back_referral_bonus",
            "deleted_account_tombstone",
            "security_event_hash",
            "normalize_account_number",
        },
        namespace,
    )
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE users (
          account_number TEXT PRIMARY KEY, expiration_date TEXT,
          referral_bonus_days INTEGER DEFAULT 0
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE referral_rewards (
          id INTEGER PRIMARY KEY AUTOINCREMENT, referrer_account_number TEXT,
          referred_account_number TEXT UNIQUE, bonus_days INTEGER DEFAULT 0,
          clawed_back_at TEXT
        )
        """
    )
    utcnow = namespace["utcnow"]
    now = utcnow()
    referrer_expiry_before = now + timedelta(days=100)
    conn.execute(
        "INSERT INTO users (account_number, expiration_date, referral_bonus_days) VALUES (?, ?, ?)",
        ("REFERRER-0001", referrer_expiry_before.isoformat(), 30),
    )
    conn.execute(
        "INSERT INTO referral_rewards (referrer_account_number, referred_account_number, bonus_days) VALUES (?, ?, ?)",
        ("REFERRER-0001", "REFERRED-0001", 20),
    )
    conn.commit()

    claw_back = namespace["claw_back_referral_bonus"]
    claw_back(conn, "REFERRED-0001")

    row = conn.execute(
        "SELECT expiration_date, referral_bonus_days FROM users WHERE account_number = ?",
        ("REFERRER-0001",),
    ).fetchone()
    # The 20 granted days must be subtracted from the referrer's current
    # expiry and bonus-day tally, not just zeroed or left untouched.
    got_expiry = datetime.fromisoformat(row["expiration_date"])
    assert abs((got_expiry - (referrer_expiry_before - timedelta(days=20))).total_seconds()) < 2
    assert row["referral_bonus_days"] == 10
    reward_row = conn.execute(
        "SELECT clawed_back_at FROM referral_rewards WHERE referred_account_number = ?",
        ("REFERRED-0001",),
    ).fetchone()
    assert reward_row["clawed_back_at"], "reward row must be marked clawed back"

    # Idempotency: a second event for the same purchase (e.g. cancellation
    # arrives, then a later refund for the same subscription) must not claw
    # back the same grant twice.
    claw_back(conn, "REFERRED-0001")
    row_again = conn.execute(
        "SELECT expiration_date, referral_bonus_days FROM users WHERE account_number = ?",
        ("REFERRER-0001",),
    ).fetchone()
    assert row_again["expiration_date"] == row["expiration_date"]
    assert row_again["referral_bonus_days"] == 10

    # Floor: clawing back more days than the referrer has left must not
    # push their expiry into the past or their bonus tally negative.
    conn.execute(
        "UPDATE users SET expiration_date = ?, referral_bonus_days = ? WHERE account_number = ?",
        (now.isoformat(), 5, "REFERRER-0001"),
    )
    conn.execute(
        "INSERT INTO referral_rewards (referrer_account_number, referred_account_number, bonus_days) VALUES (?, ?, ?)",
        ("REFERRER-0001", "REFERRED-0002", 9999),
    )
    conn.commit()
    claw_back(conn, "REFERRED-0002")
    floored_row = conn.execute(
        "SELECT expiration_date, referral_bonus_days FROM users WHERE account_number = ?",
        ("REFERRER-0001",),
    ).fetchone()
    assert datetime.fromisoformat(floored_row["expiration_date"]) >= now
    assert floored_row["referral_bonus_days"] == 0

    # An account with no referral_rewards row at all (never referred anyone
    # in, or referred nobody) must be a safe no-op, not an error.
    claw_back(conn, "ACCOUNT-WITH-NO-REFERRAL")


def main() -> None:
    test_event_contract()
    test_marker_and_reference_helpers()
    test_upsert_sql()
    test_referral_bonus_clawback()
    print("PayPal entitlement contract tests passed")


if __name__ == "__main__":
    main()
