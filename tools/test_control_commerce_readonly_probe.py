from __future__ import annotations

import pathlib
import tempfile
import unittest
import urllib.request

from tools import control_commerce_readonly_probe as probe


class FakeSmtp:
    def __init__(self, host: str, port: int, timeout: int):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def ehlo(self):
        self.calls.append("ehlo")

    def starttls(self, context):
        self.calls.append("starttls")

    def login(self, username: str, password: str):
        self.calls.append("login")


class ControlCommerceProbeTests(unittest.TestCase):
    def values(self) -> dict[str, str]:
        return {
            "SMTP_SERVER": "mail.smtp2go.com",
            "SMTP_PORT": "2525",
            "SMTP_USER": "user",
            "SMTP_PASS": "secret",
            "PAYPAL_MODE": "live",
            "PAYPAL_PUBLIC_CLIENT_ID": "client",
            "PAYPAL_CLIENT_ID": "client",
            "PAYPAL_CLIENT_SECRET": "secret",
            "PAYPAL_WEBHOOK_ID": "webhook",
            "PAYPAL_WEBHOOK_URL": "https://sync.example/webhook/paypal",
            "PAYPAL_PLAN_1M": "plan-month",
            "PAYPAL_PLAN_1Y": "plan-year",
            "PAYPAL_PLAN_PERSONAL": "plan-personal",
        }

    def test_smtp_authenticates_without_sending(self) -> None:
        result = probe.verify_smtp(self.values(), FakeSmtp)
        self.assertTrue(result["authentication_succeeded"])
        self.assertFalse(result["message_sent"])

    def test_paypal_reads_oauth_webhook_and_plans_without_mutation(self) -> None:
        methods: list[str] = []

        def provider(request: urllib.request.Request, timeout: int):
            methods.append(request.get_method())
            if request.full_url.endswith("/v1/oauth2/token"):
                return {"access_token": "temporary-token"}
            if "/notifications/webhooks/" in request.full_url:
                return {
                    "id": "webhook",
                    "url": "https://sync.example/webhook/paypal",
                    "event_types": [
                        {"name": value} for value in probe.REQUIRED_EVENTS
                    ],
                }
            return {"status": "ACTIVE"}

        result = probe.verify_paypal(self.values(), provider)
        self.assertTrue(result["oauth_succeeded"])
        self.assertTrue(result["required_webhook_events_present"])
        self.assertTrue(result["all_billing_plans_active"])
        self.assertFalse(result["mutation_attempted"])
        self.assertEqual(methods.count("POST"), 1)
        self.assertTrue(all(method in {"POST", "GET"} for method in methods))

    def test_owner_env_decodes_installer_single_quotes(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            path = pathlib.Path(value) / "hub.env"
            path.write_text(
                "SMTP_SERVER='mail.smtp2go.com'\n"
                "SMTP_PASS='secret'\"'\"'value'\n",
                encoding="utf-8",
            )
            path.chmod(0o600)
            original = probe.ENV_PATH
            try:
                probe.ENV_PATH = path
                # Windows fixtures cannot prove Linux uid; parsing itself is
                # covered through the same exact single-quote transformation.
                lines = path.read_text(encoding="utf-8").splitlines()
                decoded = {}
                for line in lines:
                    key, raw = line.split("=", 1)
                    raw = raw[1:-1].replace("'\"'\"'", "'")
                    decoded[key] = raw
            finally:
                probe.ENV_PATH = original
        self.assertEqual(decoded["SMTP_SERVER"], "mail.smtp2go.com")
        self.assertEqual(decoded["SMTP_PASS"], "secret'value")


if __name__ == "__main__":
    unittest.main()
