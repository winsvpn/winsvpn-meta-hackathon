#!/usr/bin/env python3
"""Regression coverage for fresh-node Double VPN peer restoration."""

from __future__ import annotations

import ast
import contextlib
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from validate_deployment_scripts import parse_heredocs


ROOT = Path(__file__).resolve().parents[1]
CONTROL = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"
MAIN_HEADER = 'cat > "${APP_DIR}/main.py" <<\'PYEOF\''


def load_resync_function(namespace: dict[str, Any]) -> None:
    blocks = [
        block.body
        for block in parse_heredocs(CONTROL)
        if block.header.strip() == MAIN_HEADER
    ]
    if len(blocks) != 1:
        raise AssertionError(f"expected one embedded hub main, found {len(blocks)}")
    tree = ast.parse(blocks[0])
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "resync_active_peers_to_node"
    )
    module = ast.Module(body=[function], type_ignores=[])
    ast.fix_missing_locations(module)
    exec(compile(module, str(CONTROL), "exec"), namespace)


class CorePeerResyncTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "hub.sqlite"
        connection = sqlite3.connect(self.database)
        connection.executescript(
            """
            CREATE TABLE users (
                account_number TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                expiration_date TEXT
            );
            CREATE TABLE devices (
                device_id TEXT PRIMARY KEY,
                account_number TEXT NOT NULL,
                client_public_key TEXT,
                vpn_internal_ip TEXT,
                preshared_key TEXT,
                location_slug TEXT
            );
            CREATE TABLE nodes (
                slug TEXT PRIMARY KEY,
                endpoint TEXT,
                ssh_host TEXT,
                status TEXT,
                max_peers INTEGER,
                retired_at TEXT
            );
            CREATE TABLE core_servers (
                core_id TEXT PRIMARY KEY,
                exit_public_key TEXT,
                status TEXT
            );
            CREATE TABLE core_exit_peers (
                core_id TEXT,
                exit_slug TEXT,
                core_exit_ip TEXT
            );
            CREATE TABLE double_vpn_assignments (
                device_id TEXT,
                account_number TEXT,
                core_id TEXT,
                exit_slug TEXT,
                status TEXT
            );
            """
        )
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        connection.execute("INSERT INTO users VALUES ('acct', 'active', ?)", (future,))
        connection.execute(
            "INSERT INTO devices VALUES "
            "('device', 'acct', 'customer-public', '10.8.1.2', 'customer-psk', 'spain')"
        )
        connection.execute(
            "INSERT INTO nodes VALUES "
            "('spain', 'spain.example:9110', 'spain.example', 'online', 100, NULL)"
        )
        connection.execute(
            "INSERT INTO core_servers VALUES ('core', 'core-exit-public', 'online')"
        )
        connection.execute(
            "INSERT INTO core_exit_peers VALUES ('core', 'spain', '10.8.255.2')"
        )
        connection.execute(
            "INSERT INTO double_vpn_assignments VALUES "
            "('device', 'acct', 'core', 'spain', 'active')"
        )
        connection.commit()
        connection.close()

        self.synced: list[tuple[str, dict[str, Any]]] = []

        @contextlib.contextmanager
        def get_db():
            conn = sqlite3.connect(self.database)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()

        def parse_iso_datetime(value: str | None):
            return datetime.fromisoformat(value) if value else None

        def sync_peer_to_node(host: str, config: dict[str, Any]) -> bool:
            self.synced.append((host, dict(config)))
            return True

        namespace: dict[str, Any] = {
            "Any": Any,
            "get_db": get_db,
            "ensure_schema": lambda _conn: None,
            "utcnow": lambda: datetime.now(timezone.utc),
            "parse_iso_datetime": parse_iso_datetime,
            "sync_peer_to_node": sync_peer_to_node,
            "sync_winn3_registry_to_node": lambda _conn, _host, _slug: True,
            "extract_node_host": lambda endpoint: endpoint.rsplit(":", 1)[0],
            "mark_node_management_status_by_slug": lambda *_args: None,
            "mark_node_management_status": lambda *_args: None,
            "verify_node_management_access": lambda _host: True,
        }
        load_resync_function(namespace)
        self.resync = namespace["resync_active_peers_to_node"]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_fresh_node_resync_restores_customer_and_core_system_peer(self) -> None:
        result = self.resync("spain")

        self.assertTrue(result["ok"])
        self.assertEqual(result["attempted"], 3)
        self.assertEqual(result["synced"], 3)
        self.assertEqual(result["core_attempted"], 1)
        self.assertEqual(result["core_synced"], 1)
        self.assertEqual(result["winn3_registry_attempted"], 1)
        self.assertEqual(result["winn3_registry_synced"], 1)
        core = [config for _host, config in self.synced if config["client_public_key"] == "core-exit-public"]
        self.assertEqual(len(core), 1)
        self.assertEqual(core[0]["vpn_internal_ip"], "10.8.255.2")
        self.assertEqual(core[0]["preshared_key"], "")

    def test_expired_assignment_does_not_restore_core_peer(self) -> None:
        expired = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        connection = sqlite3.connect(self.database)
        connection.execute("UPDATE users SET expiration_date=?", (expired,))
        connection.commit()
        connection.close()

        result = self.resync("spain")

        self.assertTrue(result["ok"])
        self.assertEqual(result["core_attempted"], 0)
        self.assertFalse(
            any(config["client_public_key"] == "core-exit-public" for _host, config in self.synced)
        )

    def test_retired_node_is_not_resynchronized(self) -> None:
        retired = datetime.now(timezone.utc).isoformat()
        connection = sqlite3.connect(self.database)
        connection.execute("UPDATE nodes SET retired_at=?", (retired,))
        connection.commit()
        connection.close()

        result = self.resync("spain")

        self.assertTrue(result["ok"])
        self.assertEqual(result["attempted"], 0)
        self.assertEqual(self.synced, [])


if __name__ == "__main__":
    unittest.main()
