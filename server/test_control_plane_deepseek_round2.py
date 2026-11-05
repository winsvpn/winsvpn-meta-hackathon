#!/usr/bin/env python3
"""Tests for DeepSeek Round 2 consensus items: F-3.1, F-3.2, and F-3.3."""
import _toolchain  # noqa: F401
import hmac
import os
import shutil
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone

from test_account_deletion_hub import load_hub


class ControlPlaneDeepSeekRound2Tests(unittest.TestCase):
    def setUp(self):
        # Each scenario owns its database, including legacy migration state.
        self.mod = load_hub()
        self.conn = sqlite3.connect(self.mod._DB)
        self.conn.row_factory = sqlite3.Row
        self.mod.ensure_schema(self.conn)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.mod._TMPDIR)

    # =========================================================================
    # F-3.1: Timezone-aware UTC timestamping across control plane
    # =========================================================================
    def test_now_utc_returns_timezone_aware_utc_datetime(self):
        now = self.mod.now_utc()
        self.assertIsInstance(now, datetime)
        self.assertIsNotNone(now.tzinfo)
        self.assertEqual(now.tzinfo, timezone.utc)

    def test_utcnow_returns_timezone_aware_utc_datetime(self):
        now = self.mod.utcnow()
        self.assertIsInstance(now, datetime)
        self.assertIsNotNone(now.tzinfo)
        self.assertEqual(now.tzinfo, timezone.utc)

    def test_serialize_dt_formats_iso_with_utc_offset(self):
        dt = datetime(2026, 9, 13, 15, 30, 45, tzinfo=timezone.utc)
        serialized = self.mod.serialize_dt(dt)
        self.assertEqual(serialized, "2026-09-13T15:30:45+00:00")

    def test_parse_iso_datetime_converts_naive_and_offsets_to_aware_utc(self):
        # Naive ISO string becomes aware UTC
        naive_parsed = self.mod.parse_iso_datetime("2026-09-13T12:00:00")
        self.assertIsNotNone(naive_parsed)
        self.assertEqual(naive_parsed.tzinfo, timezone.utc)
        self.assertEqual(naive_parsed.hour, 12)

        # Aware ISO string with 'Z'
        z_parsed = self.mod.parse_iso_datetime("2026-09-13T12:00:00Z")
        self.assertIsNotNone(z_parsed)
        self.assertEqual(z_parsed.tzinfo, timezone.utc)
        self.assertEqual(z_parsed.hour, 12)

        # Aware ISO string with offset converts correctly to UTC
        offset_parsed = self.mod.parse_iso_datetime("2026-09-13T14:00:00+02:00")
        self.assertIsNotNone(offset_parsed)
        self.assertEqual(offset_parsed.tzinfo, timezone.utc)
        self.assertEqual(offset_parsed.hour, 12)

        # Comparison with now_utc() does not raise TypeError
        self.assertTrue(offset_parsed < self.mod.now_utc() + timedelta(days=365))

    def test_lifetime_expiry_ten_year_anchor_and_offset(self):
        anchor = datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        expiry_str = self.mod.lifetime_expiry(anchor)
        self.assertTrue(expiry_str.startswith("2035-06-01T12:00:00"))
        self.assertTrue(expiry_str.endswith("+00:00"))

        # Default anchor uses now_utc()
        default_expiry = self.mod.lifetime_expiry()
        parsed = self.mod.parse_iso_datetime(default_expiry)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.tzinfo, timezone.utc)
        self.assertGreater(parsed, self.mod.now_utc() + timedelta(days=365 * 9))

    # =========================================================================
    # F-3.2: Idempotent lifetime migration anchored to created_at
    # =========================================================================
    def test_migrate_legacy_lifetime_anchors_to_created_at(self):
        acc = "test-lifetime-acc-001"
        created = "2024-05-10T14:20:00+00:00"
        legacy_expiry = "LIFETIME ACCESS"

        self.conn.execute("DROP TABLE IF EXISTS users_pre_lifetime_migration_2025")
        self.conn.execute(
            """
            INSERT INTO users (account_number, email, status, expiration_date, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (acc, "lifetime@example.com", "active", legacy_expiry, created),
        )
        self.conn.commit()

        # Run migration
        migrated_count = self.mod.migrate_legacy_lifetime(self.conn)
        self.assertEqual(migrated_count, 1)

        # Verify backup table exists and contains old row
        backup_row = self.conn.execute(
            "SELECT * FROM users_pre_lifetime_migration_2025 WHERE account_number = ?",
            (acc,),
        ).fetchone()
        self.assertIsNotNone(backup_row)
        self.assertEqual(backup_row["expiration_date"], legacy_expiry)

        # Verify migrated expiration is created_at + 10 years
        user_row = self.conn.execute(
            "SELECT expiration_date FROM users WHERE account_number = ?",
            (acc,),
        ).fetchone()
        self.assertIsNotNone(user_row)
        migrated_exp = user_row["expiration_date"]
        self.assertTrue(migrated_exp.startswith("2034-05-10T14:20:00"))
        self.assertTrue(migrated_exp.endswith("+00:00"))

        # Idempotence test: running migration again produces no changes
        second_run_count = self.mod.migrate_legacy_lifetime(self.conn)
        self.assertEqual(second_run_count, 0)
        user_row_again = self.conn.execute(
            "SELECT expiration_date FROM users WHERE account_number = ?",
            (acc,),
        ).fetchone()
        self.assertEqual(user_row_again["expiration_date"], migrated_exp)

    def test_migrate_legacy_lifetime_ignores_standard_accounts(self):
        acc = "test-standard-acc-002"
        created = "2024-05-10T14:20:00+00:00"
        standard_expiry = "2024-06-10T14:20:00+00:00"

        self.conn.execute(
            """
            INSERT INTO users (account_number, email, status, expiration_date, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (acc, "standard@example.com", "active", standard_expiry, created),
        )
        self.conn.commit()

        migrated = self.mod.migrate_legacy_lifetime(self.conn)
        self.assertEqual(migrated, 0)

        user_row = self.conn.execute(
            "SELECT expiration_date FROM users WHERE account_number = ?",
            (acc,),
        ).fetchone()
        self.assertEqual(user_row["expiration_date"], standard_expiry)

    # =========================================================================
    # F-3.3: Hardened activation secret lifecycle
    # =========================================================================
    def test_issue_activation_secret_sets_peppered_hash_and_ttl(self):
        acc = "test-secret-acc-003"
        self.conn.execute(
            "INSERT INTO users (account_number, email, status) VALUES (?, ?, ?)",
            (acc, "secret@example.com", "active"),
        )
        self.conn.commit()

        secret = self.mod.issue_activation_secret(
            self.conn, acc, ttl=timedelta(minutes=30)
        )
        self.assertIsInstance(secret, str)
        self.assertEqual(len(secret), 43)

        row = self.conn.execute(
            "SELECT activation_secret_hash, activation_secret_expires_at, activation_secret_used_at "
            "FROM users WHERE account_number = ?",
            (acc,),
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertIsNotNone(row["activation_secret_hash"])
        self.assertIsNotNone(row["activation_secret_expires_at"])
        self.assertIsNone(row["activation_secret_used_at"])

        # Stored hash matches peppered HMAC
        expected_hash = self.mod._hash_activation_secret(secret)
        self.assertEqual(row["activation_secret_hash"], expected_hash)

        # Expiry is ~30 minutes in the future
        exp_dt = self.mod.parse_iso_datetime(row["activation_secret_expires_at"])
        self.assertIsNotNone(exp_dt)
        self.assertGreater(exp_dt, self.mod.now_utc() + timedelta(minutes=28))
        self.assertLess(exp_dt, self.mod.now_utc() + timedelta(minutes=32))

    def test_verify_and_consume_activation_secret_atomic_single_use(self):
        acc = "test-secret-acc-004"
        self.conn.execute(
            "INSERT INTO users (account_number, email, status) VALUES (?, ?, ?)",
            (acc, "singleuse@example.com", "active"),
        )
        self.conn.commit()

        secret = self.mod.issue_activation_secret(self.conn, acc)

        # Non-existent account fails constant-time
        self.assertFalse(
            self.mod.verify_and_consume_activation_secret(
                self.conn, "non-existent-acc", secret
            )
        )

        # Wrong secret fails
        self.assertFalse(
            self.mod.verify_and_consume_activation_secret(
                self.conn, acc, "wrong-secret-value"
            )
        )

        # First consumption succeeds
        self.assertTrue(
            self.mod.verify_and_consume_activation_secret(self.conn, acc, secret)
        )

        # activation_secret_used_at is recorded
        row = self.conn.execute(
            "SELECT activation_secret_used_at FROM users WHERE account_number = ?",
            (acc,),
        ).fetchone()
        self.assertIsNotNone(row["activation_secret_used_at"])

        # Second consumption fails (single-use constraint)
        self.assertFalse(
            self.mod.verify_and_consume_activation_secret(self.conn, acc, secret)
        )

    def test_verify_and_consume_activation_secret_rejects_expired(self):
        acc = "test-secret-acc-005"
        self.conn.execute(
            "INSERT INTO users (account_number, email, status) VALUES (?, ?, ?)",
            (acc, "expired@example.com", "active"),
        )
        self.conn.commit()

        # Issue secret expired 5 minutes ago
        secret = self.mod.issue_activation_secret(
            self.conn, acc, ttl=timedelta(minutes=-5)
        )

        self.assertFalse(
            self.mod.verify_and_consume_activation_secret(self.conn, acc, secret)
        )

    def test_activation_secret_matches_constant_time_and_backward_compatible(self):
        secret = "my-test-activation-setup-key"
        peppered_hash = self.mod._hash_activation_secret(secret)
        legacy_hash = self.mod.token_digest(secret)

        # Empty / None inputs return False
        self.assertFalse(self.mod.activation_secret_matches(None, secret))
        self.assertFalse(self.mod.activation_secret_matches(peppered_hash, ""))
        self.assertFalse(self.mod.activation_secret_matches(None, None))

        # Peppered hash matches
        self.assertTrue(self.mod.activation_secret_matches(peppered_hash, secret))

        # Legacy unsalted SHA-256 hash matches
        self.assertTrue(self.mod.activation_secret_matches(legacy_hash, secret))

        # Incorrect secret fails
        self.assertFalse(
            self.mod.activation_secret_matches(peppered_hash, "incorrect-key")
        )


if __name__ == "__main__":
    unittest.main()
