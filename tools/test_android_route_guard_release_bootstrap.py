import base64
import datetime as dt
import importlib.util
import json
import os
import pathlib
import sqlite3
import struct
import subprocess
import tempfile
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("android_route_guard_release_bootstrap.py")
SPEC = importlib.util.spec_from_file_location("android_route_guard_release_bootstrap", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def public_key() -> str:
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + b"T" * 32
    return "ssh-ed25519 " + base64.b64encode(blob).decode() + " winsvpn-release"


def make_database(path: pathlib.Path) -> None:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE nodes (
          slug TEXT, endpoint TEXT, wg_port INTEGER, stealth_public_port INTEGER,
          xray_security TEXT, stealth_transports TEXT, status TEXT,
          management_status TEXT, free_access_enabled INTEGER,
          direct_awg_enabled INTEGER
        );
        CREATE TABLE core_servers (
          core_id TEXT, ingress_endpoint TEXT, stealth_endpoint TEXT,
          xray_security TEXT, stealth_transports TEXT, status TEXT,
          management_status TEXT, runtime_ready INTEGER
        );
        CREATE TABLE core_exit_peers (core_id TEXT, exit_slug TEXT);
        """
    )
    connection.execute(
        "INSERT INTO nodes VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            "spain-madrid", "203.0.113.10:9110", 9110, 80, "none",
            json.dumps([{"port": 80, "security": "none"}, {"port": 443, "security": "tls"}]),
            "online", "ok", 1, 1,
        ),
    )
    connection.execute(
        "INSERT INTO core_servers VALUES (?,?,?,?,?,?,?,?)",
        (
            "north-america-core", "core.example:9210", "core.example:80", "none",
            json.dumps([{"port": 80, "security": "none"}, {"port": 443, "security": "tls"}]),
            "online", "ok", 1,
        ),
    )
    connection.execute("INSERT INTO core_exit_peers VALUES (?,?)", ("north-america-core", "spain-madrid"))
    connection.commit()
    connection.close()


class BootstrapTests(unittest.TestCase):
    def test_serialized_target_paths_are_posix_on_windows(self):
        self.assertEqual(str(MODULE.GUARD_PATH), "/usr/local/sbin/winsvpn-android-route-guard")
        self.assertEqual(str(MODULE.DISPATCH_PATH), "/usr/local/sbin/winsvpn-android-route-dispatch")
        self.assertEqual(str(MODULE.SUDOERS_PATH), "/etc/sudoers.d/winsvpn-android-route-guard")
        self.assertEqual(str(MODULE.HOME_PATH), "/var/lib/winsvpn-route-release")

    def test_public_key_requires_unoptioned_ed25519(self):
        self.assertEqual(MODULE.validate_public_key(public_key()), public_key())
        with self.assertRaises(MODULE.BootstrapError):
            MODULE.validate_public_key('command="sh" ' + public_key())
        with self.assertRaises(MODULE.BootstrapError):
            MODULE.validate_public_key("ssh-rsa AAAA")

    def test_hub_inventory_is_redacted_and_controller_shaped(self):
        with tempfile.TemporaryDirectory() as directory:
            database = pathlib.Path(directory) / "hub.db"
            make_database(database)
            value = MODULE.inventory_from_database(database)
        MODULE.validate_inventory_shape(value)
        serialized = json.dumps(value, sort_keys=True)
        self.assertNotIn("spain-madrid", serialized)
        self.assertNotIn("north-america-core", serialized)
        self.assertNotIn("203.0.113.10", serialized)
        self.assertEqual(value["node"]["direct"]["port"], 9110)
        self.assertEqual(value["double_vpn"]["direct"]["port"], 9210)
        self.assertEqual(value["node"]["direct"]["ssh_alias"], "node-release")
        self.assertEqual(value["double_vpn"]["direct"]["ssh_alias"], "core-release")

    def test_hub_inventory_rejects_ambiguous_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            database = pathlib.Path(directory) / "hub.db"
            make_database(database)
            connection = sqlite3.connect(database)
            connection.execute(
                "INSERT INTO core_exit_peers VALUES (?,?)",
                ("north-america-core", "spain-madrid"),
            )
            connection.commit()
            connection.close()
            with self.assertRaises(MODULE.BootstrapError):
                MODULE.inventory_from_database(database)

    def test_inventory_rejects_stale_timestamp(self):
        with tempfile.TemporaryDirectory() as directory:
            database = pathlib.Path(directory) / "hub.db"
            make_database(database)
            value = MODULE.inventory_from_database(database)
        value["captured_at_utc"] = (
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)
        ).isoformat().replace("+00:00", "Z")
        with self.assertRaises(MODULE.BootstrapError):
            MODULE.validate_inventory_shape(value)

    def test_target_program_contains_only_public_material_and_compiles(self):
        program = MODULE.target_program(public_key(), "node", b"guard-source")
        compile(program, "<target-program>", "exec")
        self.assertIn("forced_command", program)
        self.assertNotIn("PRIVATE KEY", program)
        self.assertNotIn("PasswordAuthentication yes", program)

    def test_dispatcher_allows_only_guard_action_shape(self):
        self.assertIn("SSH_ORIGINAL_COMMAND", MODULE.DISPATCHER)
        self.assertIn("[0-9a-f]{32}", MODULE.DISPATCHER)
        self.assertIn("denied", MODULE.DISPATCHER)
        self.assertNotIn("eval", MODULE.DISPATCHER)
        denied = subprocess.run(
            ["bash"], input=MODULE.DISPATCHER.encode(),
            env={**os.environ, "SSH_ORIGINAL_COMMAND": "sudo -n /bin/sh"},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        # The Windows WSL launcher normalizes some stdin-script exit codes;
        # the security property is fail-closed plus the fixed denial marker.
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn(b"denied", denied.stderr)


if __name__ == "__main__":
    unittest.main()
