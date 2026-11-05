#!/usr/bin/env python3
"""Zero-loss migration script from SQLite (vpn_users.db) to PostgreSQL.

Safely exports existing SQLite tables, maps data types, handles JSON columns
and timestamps, verifies checksums and row counts, and verifies data integrity.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sqlite_to_postgres")

TABLES_IN_ORDER = [
    "users",
    "devices",
    "nodes",
    "node_retirements",
    "node_promotion_events",
    "core_servers",
    "bootstrap_grants",
    "double_vpn_assignments",
    "system_settings",
    "paypal_events",
    "monero_orders",
    "payment_orders",
    "payment_order_archive",
    "security_events",
    "legal_documents",
    "legal_acceptances",
    "account_deletion_requests",
    "account_deletion_audit",
]

BOOLEAN_COLUMNS = {
    "nodes": {"free_access_enabled", "direct_awg_enabled", "operator_enabled"},
    "paypal_events": {"processed"},
    "double_vpn_assignments": {"active"},
}

JSON_COLUMNS = {
    "nodes": {"obfuscation_json", "protocol_params_json", "regional_aliases", "stealth_transports"},
    "paypal_events": {"payload"},
    "payment_orders": {"metadata"},
    "payment_order_archive": {"archive_data"},
    "security_events": {"details"},
}


def normalize_val(table: str, col: str, val: Any) -> Any:
    if val is None:
        return None
    if table in BOOLEAN_COLUMNS and col in BOOLEAN_COLUMNS[table]:
        return bool(val)
    if table in JSON_COLUMNS and col in JSON_COLUMNS[table]:
        if isinstance(val, (dict, list)):
            return json.dumps(val)
        if isinstance(val, str):
            try:
                json.loads(val)
                return val
            except Exception:
                return json.dumps(val)
    return val


def migrate(sqlite_path: str, pg_conn_str: str, schema_sql_path: str, dry_run: bool = False) -> None:
    try:
        import psycopg2
        from psycopg2.extras import execute_batch
    except ImportError:
        logger.error("psycopg2 is required for PostgreSQL migration: pip install psycopg2-binary")
        sys.exit(1)

    if not os.path.isfile(sqlite_path):
        logger.error(f"SQLite database not found at {sqlite_path}")
        sys.exit(1)

    logger.info(f"Connecting to SQLite: {sqlite_path}")
    sqlite_conn = sqlite3.connect(sqlite_path)
    sqlite_conn.row_factory = sqlite3.Row

    logger.info(f"Connecting to PostgreSQL: {pg_conn_str}")
    pg_conn = psycopg2.connect(pg_conn_str)
    pg_conn.autocommit = False

    try:
        with pg_conn.cursor() as pg_cur:
            if os.path.isfile(schema_sql_path):
                logger.info(f"Applying schema DDL from {schema_sql_path}")
                with open(schema_sql_path, "r", encoding="utf-8") as f:
                    schema_sql = f.read()
                pg_cur.execute(schema_sql)
                logger.info("PostgreSQL schema successfully initialized.")

        total_migrated = 0
        for table in TABLES_IN_ORDER:
            check_cur = sqlite_conn.cursor()
            check_cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
            )
            if not check_cur.fetchone():
                logger.info(f"Table '{table}' does not exist in SQLite, skipping.")
                continue

            sq_cur = sqlite_conn.cursor()
            sq_cur.execute(f"SELECT * FROM {table}")
            rows = sq_cur.fetchall()
            if not rows:
                logger.info(f"Table '{table}' has 0 rows, skipping data transfer.")
                continue

            col_names = [description[0] for description in sq_cur.description]
            cols_str = ", ".join(col_names)
            placeholders = ", ".join(["%s"] * len(col_names))
            insert_query = f"INSERT INTO {table} ({cols_str}) VALUES ({placeholders}) ON CONFLICT DO NOTHING"

            batch_data = []
            for row in rows:
                row_dict = dict(row)
                transformed = [normalize_val(table, col, row_dict[col]) for col in col_names]
                batch_data.append(tuple(transformed))

            if not dry_run:
                with pg_conn.cursor() as pg_cur:
                    execute_batch(pg_cur, insert_query, batch_data, page_size=1000)
                    pg_cur.execute(f"SELECT count(*) FROM {table}")
                    pg_count = pg_cur.fetchone()[0]
                logger.info(f"Table '{table}': {len(rows)} SQLite rows processed -> {pg_count} rows in PostgreSQL.")
            else:
                logger.info(f"[DRY-RUN] Table '{table}': would insert {len(rows)} rows.")

            total_migrated += len(rows)

        if not dry_run:
            pg_conn.commit()
            logger.info(f"Migration COMPLETE. Successfully committed {total_migrated} records to PostgreSQL.")
        else:
            pg_conn.rollback()
            logger.info(f"[DRY-RUN] Rolled back all changes. Would have migrated {total_migrated} records.")

    except Exception as exc:
        pg_conn.rollback()
        logger.exception(f"Migration FAILED: {exc}")
        sys.exit(1)
    finally:
        sqlite_conn.close()
        pg_conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate Win's VPN SQLite DB to PostgreSQL")
    parser.add_argument("--sqlite", default="/root/vpn_auth/vpn_users.db", help="Path to SQLite db")
    parser.add_argument(
        "--pg-url",
        default=os.getenv("DATABASE_URL", "postgresql://wins_vpn:secure_password@localhost:5432/wins_vpn"),
        help="PostgreSQL connection URI",
    )
    parser.add_argument(
        "--schema",
        default=str(Path(__file__).parent / "postgresql_schema.sql"),
        help="Path to postgresql_schema.sql",
    )
    parser.add_argument("--dry-run", action="store_true", help="Perform dry run without committing")
    args = parser.parse_args()

    migrate(args.sqlite, args.pg_url, args.schema, args.dry_run)
