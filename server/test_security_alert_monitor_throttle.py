"""wins-security-alert-monitor throttle keys (2026-10-31 security audit).

The monitor's throttle key hashed the whole details dict, and SSH login
details carry a per-line line_hash, so no two logins ever shared a key and
every operator login mailed (435 mails 2026-10-22..31). These tests run the
monitor's own throttle functions, cut from the control-plane installer.
"""
import _toolchain  # noqa: F401  (V-01 preflight)
import ast
import hashlib
import json
import unittest
from pathlib import Path

HUB_INSTALLER = Path(__file__).with_name("wins_control_plane_setup_ONETOUCH.sh")
FUNCTIONS = ("alert_text", "throttle_identity", "throttle_window")


def monitor_source() -> str:
    text = HUB_INSTALLER.read_text(encoding="utf-8")
    body = text.split("cat > /usr/local/bin/wins-security-alert-monitor <<'PYEOF'\n", 1)[1]
    return body.split("\nPYEOF\n", 1)[0]


def load_throttle(throttle_seconds=300, trusted_seconds=21600) -> dict:
    tree = ast.parse(monitor_source())
    picked = [node for node in tree.body
              if isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS]
    assert sorted(node.name for node in picked) == sorted(FUNCTIONS), "monitor functions moved"
    namespace = {
        "THROTTLE_SECONDS": throttle_seconds,
        "TRUSTED_LOGIN_THROTTLE_SECONDS": trusted_seconds,
    }
    exec(compile(ast.Module(body=picked, type_ignores=[]), str(HUB_INSTALLER), "exec"), namespace)
    return namespace


def key(ns, priority, event_type, source, details) -> str:
    identity = ns["throttle_identity"](priority, event_type, source, details)
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()


def login(line_hash, *, trusted=True, method="publickey", user="root"):
    return {"method": method, "user": user, "trusted_admin_source": trusted, "line_hash": line_hash}


class ThrottleKeyTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_throttle()

    def test_two_logins_from_one_source_share_a_key(self):
        a = key(self.ns, 2, "successful ssh login", "198.51.100.7", login("aaa"))
        b = key(self.ns, 2, "successful ssh login", "198.51.100.7", login("bbb"))
        self.assertEqual(a, b)

    def test_source_user_and_method_still_separate_keys(self):
        base = key(self.ns, 2, "successful ssh login", "198.51.100.7", login("aaa"))
        self.assertNotEqual(base, key(self.ns, 2, "successful ssh login", "198.51.100.8", login("aaa")))
        self.assertNotEqual(base, key(self.ns, 2, "successful ssh login", "198.51.100.7", login("aaa", user="ubuntu")))
        self.assertNotEqual(base, key(self.ns, 2, "successful ssh login", "198.51.100.7", login("aaa", method="password")))

    def test_the_callers_details_are_not_mutated(self):
        details = login("aaa")
        self.ns["throttle_identity"](2, "successful ssh login", "198.51.100.7", details)
        self.assertEqual(details["line_hash"], "aaa")


class ThrottleWindowTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_throttle(throttle_seconds=300, trusted_seconds=21600)
        self.window = self.ns["throttle_window"]

    def test_trusted_key_login_uses_the_long_window(self):
        self.assertEqual(self.window("successful ssh login", login("x")), 21600)

    def test_untrusted_or_password_logins_keep_the_short_window(self):
        self.assertEqual(self.window("successful ssh login", login("x", trusted=False)), 300)
        self.assertEqual(self.window("successful ssh login", login("x", method="password")), 300)
        self.assertEqual(self.window("successful ssh login", {"trusted_admin_source": "true", "method": "publickey"}), 300)

    def test_other_events_keep_the_short_window(self):
        self.assertEqual(self.window("admin privilege escalation", {"mechanism": "sudo"}), 300)
        self.assertEqual(self.window("suricata alert", {"signature_id": 1}), 300)

    def test_a_short_trusted_setting_never_undercuts_the_base_window(self):
        ns = load_throttle(throttle_seconds=300, trusted_seconds=60)
        self.assertEqual(ns["throttle_window"]("successful ssh login", login("x")), 300)


if __name__ == "__main__":
    unittest.main()
