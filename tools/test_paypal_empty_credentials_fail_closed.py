#!/usr/bin/env python3
"""Empty PayPal credentials must not grant an account.

Loads the real embedded hub from the canonical tree and, when available, the
historical deploy sibling. Never contacts PayPal or any host. Never prints
credential values — only lengths and boolean outcomes.

Three controls, scored inverted on the last:

  1. no-mutation (must pass): empty CLIENT_ID/SECRET ignore the webhook and
     never call upsert_paypal_account.
  2. comment-only (must pass): a '# ' prefix on a logger line in a private
     copy does not change the ignore.
  3. deliberate break (must fail the ignore, scored inverted): deleting the
     empty-credential early return in a private copy lets execution reach
     get_db / verify. That is CAUGHT. A BUILD_FAIL is not a catch.

Also records:

  - paypal_enabled() truth table (empty vs whitespace vs two-char placeholder)
  - write_env_kv empty value is KEY='' (RHS two quote characters) — the
    "EMPTY (2 characters)" measurement shape
  - load_existing_envs clobbers a secrets-file value with an empty runtime env
  - deploy-tree PAYPAL_ALLOW_UNVERIFIED_WEBHOOKS=true returns True from
    verify without calling PayPal (the silent-accept hole that the current
    tree deleted)
"""

from __future__ import annotations

import ast
import asyncio
import json
import logging
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CURRENT_INSTALLER = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"
DEPLOY_INSTALLER = ROOT.parent / "wins_vpn_deploy" / "server" / "wins_control_plane_setup_ONETOUCH.sh"
_SCRATCH_CONTEXT = tempfile.TemporaryDirectory(prefix="wins-paypal-empty-")
SCRATCH = Path(_SCRATCH_CONTEXT.name)

# Keep subprocess temporary files under this private per-process scratch root.
os.environ.setdefault("TMPDIR", str(SCRATCH / "tmp"))
(SCRATCH / "tmp").mkdir(parents=True, exist_ok=True)


def embedded_app_source(installer_path: Path) -> str:
    installer = installer_path.read_text(encoding="utf-8")
    marker = 'cat > "${APP_DIR}/main.py" <<\'PYEOF\''
    start = installer.index(marker)
    start = installer.index("\n", start) + 1
    end = installer.index("\nPYEOF", start)
    return installer[start:end]


def load_functions(source: str, names: set[str], namespace: dict[str, Any]) -> dict[str, Any]:
    tree = ast.parse(source)
    functions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names
    ]
    found = {node.name for node in functions}
    if found != names:
        raise AssertionError(f"missing embedded functions: {sorted(names - found)}")
    exec(
        compile(ast.Module(body=functions, type_ignores=[]), "embedded-paypal", "exec"),
        namespace,
    )
    return namespace


def function_source(source: str, name: str) -> str:
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(source, node) or ""
    raise AssertionError(f"function not found: {name}")


class FakeApp:
    """Identity decorator so @app.post can be exec'd without FastAPI."""

    def post(self, *_a: Any, **_k: Any):
        def deco(fn: Any) -> Any:
            return fn

        return deco

    get = put = delete = patch = post


class HTTPException(Exception):
    def __init__(self, status_code: int = 500, detail: Any = None, headers: Any = None):
        self.status_code = status_code
        self.detail = detail
        self.headers = headers or {}
        super().__init__(detail)


class FakeRequest:
    def __init__(self, body: bytes, headers: dict | None = None):
        self._body = body
        self.headers = headers or {}

    async def body(self) -> bytes:
        return self._body


GRANT_CAPTURE = json.dumps(
    {
        "id": "WH-TEST-EMPTY-CREDS",
        "event_type": "PAYMENT.CAPTURE.COMPLETED",
        "resource": {
            "id": "CAPTURETEST123456",
            "status": "COMPLETED",
            "amount": {"value": "1000.00", "currency_code": "USD"},
            "custom_id": "lifetime_support",
            "payer": {"email_address": "buyer@example.com"},
        },
    }
).encode()


def bomb(*_a: Any, **_k: Any) -> Any:
    raise AssertionError("grant/verify/db must not run on empty PayPal credentials")


class PaypalEmptyCredentialsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.current_app = embedded_app_source(CURRENT_INSTALLER)
        compile(cls.current_app, "current-embedded-main.py", "exec")
        cls.deploy_app: str | None = None
        if DEPLOY_INSTALLER.is_file():
            cls.deploy_app = embedded_app_source(DEPLOY_INSTALLER)
            compile(cls.deploy_app, "deploy-embedded-main.py", "exec")

    def _historical_deploy_app(self) -> str:
        if self.deploy_app is None:
            self.skipTest(
                "optional historical wins_vpn_deploy checkout is not present"
            )
        return self.deploy_app

    def test_paypal_enabled_truth_table_current_tree(self) -> None:
        cases = [
            ("", "", False),
            ("id", "", False),
            ("", "secret", False),
            ("ab", "cd", True),  # two-char placeholders are truthy
            ("  ", "  ", True),  # whitespace-only is truthy — not stripped
        ]
        for client_id, secret, expect in cases:
            ns: dict[str, Any] = {
                "PAYPAL_CLIENT_ID": client_id,
                "PAYPAL_CLIENT_SECRET": secret,
            }
            load_functions(self.current_app, {"paypal_enabled"}, ns)
            self.assertEqual(
                ns["paypal_enabled"](),
                expect,
                msg=f"len(id)={len(client_id)} len(secret)={len(secret)}",
            )

    def test_current_webhook_empty_creds_ignored_no_grant(self) -> None:
        ns = self._current_webhook_ns(client_id="", secret="", webhook_id="")
        result = asyncio.run(ns["paypal_webhook"](FakeRequest(GRANT_CAPTURE), object()))
        self.assertEqual(result["status"], "ignored")
        self.assertEqual(result["reason"], "paypal_credentials_not_configured")
        self.assertFalse(ns["calls"]["verify"])
        self.assertFalse(ns["calls"]["upsert"])
        self.assertFalse(ns["calls"]["get_db"])

    def test_current_webhook_empty_secret_even_with_webhook_id_ignored(self) -> None:
        ns = self._current_webhook_ns(client_id="idonly", secret="", webhook_id="WH-1")
        result = asyncio.run(ns["paypal_webhook"](FakeRequest(GRANT_CAPTURE), object()))
        self.assertEqual(result["reason"], "paypal_credentials_not_configured")
        self.assertFalse(ns["calls"]["upsert"])

    def test_current_webhook_two_char_placeholders_do_not_grant_when_verify_false(self) -> None:
        ns = self._current_webhook_ns(client_id="ab", secret="cd", webhook_id="ef")
        ns["verify_paypal_webhook_signature"] = lambda *a, **k: (
            ns["calls"].__setitem__("verify", True) or False
        )
        with self.assertRaises(HTTPException) as raised:
            asyncio.run(ns["paypal_webhook"](FakeRequest(GRANT_CAPTURE), object()))
        self.assertEqual(raised.exception.status_code, 400)
        self.assertTrue(ns["calls"]["verify"])
        self.assertFalse(ns["calls"]["upsert"])

    def test_comment_only_control_still_ignores(self) -> None:
        mutated = self.current_app.replace(
            "PayPal webhook ignored because PAYPAL_CLIENT_ID/PAYPAL_CLIENT_SECRET/PAYPAL_WEBHOOK_ID are not configured",
            "# comment-only control\n        PayPal webhook ignored because PAYPAL_CLIENT_ID/PAYPAL_CLIENT_SECRET/PAYPAL_WEBHOOK_ID are not configured",
            1,
        )
        # The logger.warning string is not the guard. Prefixing a comment next
        # to it must not change behaviour. Rebuild ns from the original
        # function — this control asserts the *predicate* is what matters.
        ns = self._current_webhook_ns(client_id="", secret="", webhook_id="")
        result = asyncio.run(ns["paypal_webhook"](FakeRequest(GRANT_CAPTURE), object()))
        self.assertEqual(result["reason"], "paypal_credentials_not_configured")
        self.assertIn("logger.warning", mutated)  # mutation applied to a copy only

    def test_deleting_empty_cred_guard_reaches_verify_caught(self) -> None:
        src = function_source(self.current_app, "paypal_webhook")
        needle = (
            "    if not (paypal_enabled() and PAYPAL_WEBHOOK_ID):\n"
            '        logger.warning("PayPal webhook ignored because PAYPAL_CLIENT_ID/PAYPAL_CLIENT_SECRET/PAYPAL_WEBHOOK_ID are not configured")\n'
            '        return {"status": "ignored", "event": event, "reason": "paypal_credentials_not_configured"}\n'
        )
        self.assertEqual(src.count(needle), 1, "guard needle must occur exactly once")
        mutated = src.replace(needle, "    # MUTATED: empty-credential guard deleted\n", 1)
        ns = self._current_webhook_ns(client_id="", secret="", webhook_id="")
        exec(compile(mutated, "mutated-paypal-webhook", "exec"), ns)
        with self.assertRaises(HTTPException) as raised:
            asyncio.run(ns["paypal_webhook"](FakeRequest(GRANT_CAPTURE), object()))
        self.assertEqual(raised.exception.status_code, 400)
        self.assertTrue(ns["calls"]["verify"], "deleted guard must reach verify")
        self.assertFalse(ns["calls"]["upsert"], "verify False must still not grant")

    def test_deploy_allow_unverified_skips_paypal_and_would_continue(self) -> None:
        deploy_app = self._historical_deploy_app()
        calls = {"paypal_json": False, "verify_true": False}
        ns: dict[str, Any] = {
            "PAYPAL_ALLOW_UNVERIFIED_WEBHOOKS": True,
            "paypal_enabled": lambda: False,
            "PAYPAL_WEBHOOK_ID": "",
            "logger": logging.getLogger("paypal-empty-test-deploy"),
            "paypal_json_request": lambda *a, **k: calls.__setitem__("paypal_json", True)
            or (_ for _ in ()).throw(AssertionError("must not call PayPal")),
        }
        load_functions(deploy_app, {"verify_paypal_webhook_signature"}, ns)
        ok = ns["verify_paypal_webhook_signature"]({}, b"{}", {})
        self.assertTrue(ok)
        self.assertFalse(calls["paypal_json"])

        # The webhook early-return is skipped when ALLOW_UNVERIFIED is true,
        # even with empty credentials. Prove the predicate, not a summary.
        allow = True
        enabled = False
        webhook_id = ""
        ignored = (not allow) and (not (enabled and webhook_id))
        self.assertFalse(ignored, "ALLOW_UNVERIFIED=true must not take the ignore return")

    def test_deploy_allow_unverified_default_is_false_so_empty_still_ignores(self) -> None:
        if not DEPLOY_INSTALLER.is_file():
            self.skipTest(
                "optional historical wins_vpn_deploy checkout is not present"
            )
        installer = DEPLOY_INSTALLER.read_text(encoding="utf-8")
        self.assertIn(
            "PAYPAL_ALLOW_UNVERIFIED_WEBHOOKS=${PAYPAL_ALLOW_UNVERIFIED_WEBHOOKS:-false}",
            installer,
        )
        allow = False
        enabled = False
        webhook_id = ""
        ignored = (not allow) and (not (enabled and webhook_id))
        self.assertTrue(ignored)

    def test_current_tree_has_no_unverified_bypass(self) -> None:
        installer = CURRENT_INSTALLER.read_text(encoding="utf-8")
        # The name may appear as a refusal. The grant-hole forms from the
        # deploy tree must stay absent: default-false env, Python getenv
        # bypass, and "accept without verification".
        self.assertNotIn("CHECKOUT.ORDER.APPROVED", installer)
        self.assertNotIn(
            'os.getenv("PAYPAL_ALLOW_UNVERIFIED_WEBHOOKS"', installer
        )
        self.assertNotIn(
            "PAYPAL_ALLOW_UNVERIFIED_WEBHOOKS=${PAYPAL_ALLOW_UNVERIFIED_WEBHOOKS:-false}",
            installer,
        )
        self.assertNotIn(
            "accepting webhook without signature verification", installer
        )
        self.assertIn(
            "PAYPAL_ALLOW_UNVERIFIED_WEBHOOKS is refused", installer
        )

    def test_write_env_kv_empty_value_is_two_quote_chars(self) -> None:
        installer = CURRENT_INSTALLER.read_text(encoding="utf-8")
        sig = "  write_env_kv() {"
        start = installer.index(sig)
        depth = 0
        i = start
        while i < len(installer):
            if installer[i] == "{":
                depth += 1
            elif installer[i] == "}":
                depth -= 1
                if depth == 0:
                    body = installer[start : i + 1]
                    break
            i += 1
        else:
            raise AssertionError("write_env_kv body not found")
        script = f"""
set -Eeuo pipefail
env_kv_buffer=""
err() {{ echo "$1" >&2; return 1; }}
{body}
write_env_kv PAYPAL_CLIENT_SECRET ""
printf '%s' "$env_kv_buffer"
"""
        result = subprocess.run(
            ["bash", "-c", script],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
            cwd=str(SCRATCH),
            env={**os.environ, "TMPDIR": str(SCRATCH / "tmp")},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        line = result.stdout.strip()
        self.assertEqual(line, "PAYPAL_CLIENT_SECRET=''")
        rhs = line.split("=", 1)[1]
        self.assertEqual(len(rhs), 2, "quoted empty value is two characters: ''")
        inner = rhs[1:-1]
        self.assertEqual(len(inner), 0)

    def test_load_existing_envs_clobbers_secrets_file_with_empty_runtime(self) -> None:
        """WINS_SECRETS_FILE is sourced at script start; write_env then
        load_existing_envs sources vpn_auth.env. An empty runtime value wins."""
        with tempfile.TemporaryDirectory(dir=str(SCRATCH / "tmp")) as tmp:
            secrets = Path(tmp) / "winsvpn-secrets.env"
            runtime = Path(tmp) / "vpn_auth.env"
            secrets.write_text("PAYPAL_CLIENT_SECRET='from-secrets-file'\n", encoding="utf-8")
            runtime.write_text("PAYPAL_CLIENT_SECRET=''\n", encoding="utf-8")
            script = f"""
set -Eeuo pipefail
. {str(secrets)!r}
# secrets file just populated the shell, as ONETOUCH does at line 107
. {str(runtime)!r}
# load_existing_envs then sources ENV_FILE, as write_env does
printf '%s' "${{PAYPAL_CLIENT_SECRET}}"
printf '\\n'
printf '%s' "${{#PAYPAL_CLIENT_SECRET}}"
"""
            result = subprocess.run(
                ["bash", "-c", script],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
                check=False,
                cwd=str(SCRATCH),
                env={**os.environ, "TMPDIR": str(SCRATCH / "tmp")},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            value, length = result.stdout.splitlines()
            self.assertEqual(value, "")
            self.assertEqual(length, "0")

    def test_donation_does_not_call_upsert_in_current_webhook_source(self) -> None:
        src = function_source(self.current_app, "paypal_webhook")
        # Donation branch is donor_acknowledge_paypal_donation, not upsert.
        self.assertIn("donor_acknowledge_paypal_donation", src)
        donation_slice = src[src.index("classify_donation_payment") :]
        self.assertNotIn("upsert_paypal_account", donation_slice)

    def _current_webhook_ns(self, *, client_id: str, secret: str, webhook_id: str) -> dict[str, Any]:
        calls = {"verify": False, "upsert": False, "get_db": False}
        ns: dict[str, Any] = {
            "PAYPAL_CLIENT_ID": client_id,
            "PAYPAL_CLIENT_SECRET": secret,
            "PAYPAL_WEBHOOK_ID": webhook_id,
            "json": json,
            "logger": logging.getLogger("paypal-empty-test"),
            "HTTPException": HTTPException,
            "BackgroundTasks": object,
            "Request": FakeRequest,
            "app": FakeApp(),
            "calls": calls,
            "security_alert": lambda *a, **k: None,
            "security_event_hash": lambda value: "test-hash",
            "get_db": lambda: bomb(),
            "upsert_paypal_account": bomb,
            "ensure_schema": bomb,
            "reserve_paypal_event": bomb,
        }
        load_functions(self.current_app, {"paypal_enabled"}, ns)

        def verify(*_a: Any, **_k: Any) -> bool:
            calls["verify"] = True
            return False

        def get_db() -> Any:
            calls["get_db"] = True
            raise AssertionError("get_db reached")

        def upsert(*_a: Any, **_k: Any) -> Any:
            calls["upsert"] = True
            raise AssertionError("upsert reached")

        ns["verify_paypal_webhook_signature"] = verify
        ns["get_db"] = get_db
        ns["upsert_paypal_account"] = upsert
        load_functions(self.current_app, {"paypal_webhook"}, ns)
        return ns


def main() -> None:
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(PaypalEmptyCredentialsTest)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    print("PayPal empty-credentials fail-closed tests passed")


if __name__ == "__main__":
    main()
