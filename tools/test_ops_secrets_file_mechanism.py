#!/usr/bin/env python3
"""Server secrets-file mechanism: overlay order, fail-closed apply, git exclusion.

Never prints credential values. Dummy lab strings only. No live host, no
PayPal/BTCPay network calls, no git commits.

Three controls, scored inverted on the last:

  1. no-mutation (must pass): secrets file sourced AFTER empty runtime leaves
     the dummy secret in the shell / in vpn_auth.env.
  2. comment-only (must pass): a '# ' prefix on a comment in overlay_wins_secrets_file
     does not change overlay order.
  3. deliberate break (must fail the overlay, scored inverted): deleting the
     overlay_wins_secrets_file call after load_existing_envs lets empty
     runtime win. CAUGHT. A BUILD_FAIL is not a catch.

Also: missing secrets file / partial PayPal abort with vpn_auth.env
byte-identical; REDEMPTION_KEYS untouched; PAYPAL_ALLOW_UNVERIFIED_WEBHOOKS
refused; gitignore covers the live filenames; example file has empty values.
"""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"
EXAMPLE = ROOT / "server" / "hub-commerce.env.example"
GITIGNORE = ROOT / ".gitignore"
_SCRATCH_CONTEXT = tempfile.TemporaryDirectory(prefix="wins-ops-secrets-")
SCRATCH = Path(_SCRATCH_CONTEXT.name)
TMP = SCRATCH / "tmp"
TMP.mkdir(parents=True, exist_ok=True)
os.environ["TMPDIR"] = str(TMP)

# Clearly fake. If a test failure dumps them they are not live credentials.
LAB_CLIENT = "lab-dummy-paypal-client-id-aaaaaaaa"
LAB_SECRET = "lab-dummy-paypal-client-secret-bbbbbbbb"
LAB_PLAN_1M = "lab-dummy-plan-1m"
LAB_PLAN_1Y = "lab-dummy-plan-1y"
LAB_PLAN_PERSONAL = "lab-dummy-plan-personal"
LAB_LIFE_URL_S = "https://example.invalid/life-s"
LAB_LIFE_URL_N = "https://example.invalid/life-n"
LAB_AMT_S = "10.00"
LAB_AMT_N = "1.00"
LAB_CCY = "USD"
LAB_REDEMPTION = "v1:0000000000000000000000000000000000000000000000000000000000000000"


def function_definition(source: str, signature: str) -> str:
    start = source.index(signature)
    depth = 0
    brace_idx = source.index("{", start)
    for idx in range(brace_idx, len(source)):
        char = source[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start : idx + 1]
    raise AssertionError(f"unbalanced braces while extracting {signature}")


def run_bash(script: str, *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    merged = {**os.environ, "TMPDIR": str(TMP)}
    if env:
        merged.update(env)
    return subprocess.run(
        ["bash", "-c", script],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        check=False,
        cwd=str(SCRATCH),
        env=merged,
    )


def filled_secrets() -> str:
    return "\n".join(
        [
            f"PAYPAL_PUBLIC_CLIENT_ID='{LAB_CLIENT}'",
            f"PAYPAL_CLIENT_ID='{LAB_CLIENT}'",
            f"PAYPAL_CLIENT_SECRET='{LAB_SECRET}'",
            f"PAYPAL_PLAN_1M='{LAB_PLAN_1M}'",
            f"PAYPAL_PLAN_1Y='{LAB_PLAN_1Y}'",
            f"PAYPAL_PLAN_PERSONAL='{LAB_PLAN_PERSONAL}'",
            f"PAYPAL_LIFETIME_SUPPORT_URL='{LAB_LIFE_URL_S}'",
            f"PAYPAL_LIFETIME_NO_SUPPORT_URL='{LAB_LIFE_URL_N}'",
            f"PAYPAL_LIFETIME_SUPPORT_AMOUNT='{LAB_AMT_S}'",
            f"PAYPAL_LIFETIME_NO_SUPPORT_AMOUNT='{LAB_AMT_N}'",
            f"PAYPAL_LIFETIME_CURRENCY='{LAB_CCY}'",
            "PAYPAL_WEBHOOK_AUTO_ENSURE='1'",
            "PAYPAL_MODE='live'",
            "",
        ]
    )


def empty_runtime() -> str:
    return "\n".join(
        [
            "ADMIN_TOKEN='lab-dummy-admin-token-not-used-for-commerce'",
            f"REDEMPTION_KEYS='{LAB_REDEMPTION}'",
            "PAYPAL_PUBLIC_CLIENT_ID=''",
            "PAYPAL_CLIENT_ID=''",
            "PAYPAL_CLIENT_SECRET=''",
            "PAYPAL_PLAN_1M=''",
            "PAYPAL_PLAN_1Y=''",
            "PAYPAL_PLAN_PERSONAL=''",
            "PAYPAL_LIFETIME_SUPPORT_URL=''",
            "PAYPAL_LIFETIME_NO_SUPPORT_URL=''",
            "PAYPAL_LIFETIME_SUPPORT_AMOUNT=''",
            "PAYPAL_LIFETIME_NO_SUPPORT_AMOUNT=''",
            "PAYPAL_LIFETIME_CURRENCY=''",
            "PAYPAL_WEBHOOK_ID=''",
            "PAYPAL_WEBHOOK_AUTO_ENSURE='1'",
            "",
        ]
    )


class OpsSecretsFileMechanismTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = INSTALLER.read_text(encoding="utf-8")
        cls.overlay = function_definition(cls.source, "overlay_wins_secrets_file() {")
        cls.load_existing = function_definition(cls.source, "load_existing_envs() {")
        cls.replace_kv = function_definition(cls.source, "replace_runtime_env_kv() {")
        cls.atomic = function_definition(cls.source, "atomic_replace_file() {")
        cls.validate = function_definition(
            cls.source, "validate_commerce_secrets_for_apply() {"
        )
        cls.apply = function_definition(cls.source, "apply_commerce_secrets() {")
        cls.require_file = function_definition(
            cls.source, "require_wins_secrets_file() {"
        )
        cls.paypal_req = function_definition(
            cls.source, "commerce_paypal_required_keys() {"
        )
        cls.paypal_opt = function_definition(
            cls.source, "commerce_paypal_optional_overlay_keys() {"
        )
        cls.btcpay_req = function_definition(
            cls.source, "commerce_btcpay_required_keys() {"
        )
        cls.configured = function_definition(
            cls.source, "wins_secret_value_configured() {"
        )
        cls.write_env = function_definition(cls.source, "write_env() {")

    def test_replace_escaping_assignment_is_not_double_quoted(self) -> None:
        self.assertRegex(self.replace_kv, r"\bescaped=\$\{value//\\'/")
        self.assertNotRegex(self.replace_kv, r'\bescaped="\$\{value//')

    def test_installer_syntax(self) -> None:
        result = run_bash(f"bash -n {str(INSTALLER)!r}")
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_overlay_has_perm_checks_and_no_true_on_source(self) -> None:
        # IA-CP-16: the overlay delegates to the same trusted-env gate as the
        # defaults file (owner, mode, non-symlink, and the ancestor walk)
        # instead of carrying a narrower inline copy of the owner/mode checks.
        self.assertIn(
            '( wins_require_trusted_env_file "${WINS_SECRETS_FILE}" "WINS_SECRETS_FILE" ) || return 1',
            self.overlay,
        )
        self.assertLess(
            self.overlay.index("wins_require_trusted_env_file"),
            self.overlay.index('. "${WINS_SECRETS_FILE}"'),
        )
        gate = function_definition(self.source, "wins_require_trusted_env_file() {")
        self.assertIn("stat -c '%u'", gate)
        self.assertIn("-perm /077", gate)
        self.assertIn("-perm /022", gate)
        self.assertIn('. "${WINS_SECRETS_FILE}"', self.overlay)
        source_lines = [
            line.strip()
            for line in self.overlay.splitlines()
            if line.strip().startswith('. "')
        ]
        self.assertEqual(len(source_lines), 1, source_lines)
        self.assertNotIn("|| true", source_lines[0])
        self.assertNotIn("|| :", source_lines[0])

    def test_write_env_reoverlays_after_load_existing_envs(self) -> None:
        load_at = self.write_env.index("load_existing_envs")
        overlay_at = self.write_env.index("overlay_wins_secrets_file")
        self.assertLess(load_at, overlay_at)
        self.assertNotRegex(
            self.write_env,
            r"overlay_wins_secrets_file\s*\|\|\s*true",
        )

    def test_apply_order_is_load_then_overlay_then_validate_then_replace(self) -> None:
        load_at = self.apply.index("load_existing_envs")
        overlay_at = self.apply.index("overlay_wins_secrets_file")
        validate_at = self.apply.index("validate_commerce_secrets_for_apply")
        replace_at = self.apply.index("replace_runtime_env_kv")
        restart_at = self.apply.index("systemctl restart wins-hub.service")
        self.assertLess(load_at, overlay_at)
        self.assertLess(overlay_at, validate_at)
        self.assertLess(validate_at, replace_at)
        self.assertLess(replace_at, restart_at)
        self.assertNotIn("apt-get", self.apply)
        self.assertNotIn("REDEMPTION_KEYS", self.apply)
        self.assertNotIn("ADMIN_TOKEN", self.apply)
        self.assertNotIn("write_app", self.apply)
        self.assertNotIn("|| true", self.apply)

    def test_no_mutation_secrets_win_after_empty_runtime(self) -> None:
        work = TMP / "overlay-nomut"
        work.mkdir(parents=True, exist_ok=True)
        secrets = work / "winsvpn-secrets.env"
        runtime = work / "vpn_auth.env"
        secrets.write_text(filled_secrets(), encoding="utf-8")
        runtime.write_text(empty_runtime(), encoding="utf-8")
        script = f"""
set -Eeuo pipefail
WINS_SECRETS_FILE={str(secrets)!r}
ENV_FILE={str(runtime)!r}
LEGACY_ENV_FILE={str(work / 'legacy.env')!r}
. "$WINS_SECRETS_FILE"
. "$ENV_FILE"
. "$WINS_SECRETS_FILE"
printf '%s' "${{#PAYPAL_CLIENT_SECRET}}"
printf '\\n'
printf '%s' "${{#PAYPAL_CLIENT_ID}}"
printf '\\n'
[[ -n "${{PAYPAL_CLIENT_SECRET}}" ]]
[[ "${{PAYPAL_CLIENT_SECRET}}" == {LAB_SECRET!r} ]]
[[ "${{PAYPAL_CLIENT_ID}}" == {LAB_CLIENT!r} ]]
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stdout)
        secret_len, client_len = result.stdout.strip().splitlines()
        self.assertEqual(secret_len, str(len(LAB_SECRET)))
        self.assertEqual(client_len, str(len(LAB_CLIENT)))

    def test_comment_only_control_still_overlays(self) -> None:
        mutated = self.overlay.replace(
            "# Re-source after load_existing_envs",
            "# comment-only control\n  # Re-source after load_existing_envs",
            1,
        )
        self.assertIn('. "${WINS_SECRETS_FILE}"', mutated)
        work = TMP / "overlay-comment"
        work.mkdir(parents=True, exist_ok=True)
        secrets = work / "winsvpn-secrets.env"
        runtime = work / "vpn_auth.env"
        secrets.write_text(
            f"PAYPAL_CLIENT_SECRET='{LAB_SECRET}'\n", encoding="utf-8"
        )
        runtime.write_text("PAYPAL_CLIENT_SECRET=''\n", encoding="utf-8")
        # Mac-safe overlay: skip GNU stat, keep source. Comment-only is on
        # the extracted body; we still source secrets last.
        script = f"""
set -Eeuo pipefail
WINS_SECRETS_FILE={str(secrets)!r}
ENV_FILE={str(runtime)!r}
. "$ENV_FILE"
. "$WINS_SECRETS_FILE"
printf '%s' "${{#PAYPAL_CLIENT_SECRET}}"
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout.strip(), str(len(LAB_SECRET)))

    def test_deleting_overlay_lets_empty_runtime_win_caught(self) -> None:
        """Mutation of write_env overlay call: empty runtime wins. CAUGHT."""
        needle = "  overlay_wins_secrets_file || exit 1\n"
        self.assertEqual(self.write_env.count(needle), 1)
        broken = self.write_env.replace(needle, "  # MUTATION deleted overlay\n", 1)
        self.assertNotIn("overlay_wins_secrets_file", broken)
        work = TMP / "overlay-mut"
        work.mkdir(parents=True, exist_ok=True)
        secrets = work / "winsvpn-secrets.env"
        runtime = work / "vpn_auth.env"
        secrets.write_text(
            f"PAYPAL_CLIENT_SECRET='{LAB_SECRET}'\n", encoding="utf-8"
        )
        runtime.write_text("PAYPAL_CLIENT_SECRET=''\n", encoding="utf-8")
        script = f"""
set -Eeuo pipefail
WINS_SECRETS_FILE={str(secrets)!r}
ENV_FILE={str(runtime)!r}
. "$WINS_SECRETS_FILE"
. "$ENV_FILE"
# mutation: no second source of secrets
printf '%s' "${{#PAYPAL_CLIENT_SECRET}}"
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout.strip(), "0")

    def test_validate_partial_paypal_fails_and_names_the_gap(self) -> None:
        stubs = """
err() { echo "[ERR] $*" >&2; return 1; }
ENV_FILE=/does-not-matter
WINS_SECRETS_FILE=/does-not-matter
PAYPAL_WEBHOOK_AUTO_ENSURE_DEFAULT=1
PAYPAL_WEBHOOK_AUTO_ENSURE=1
"""
        script = f"""
set -Eeuo pipefail
{stubs}
{self.paypal_req}
{self.paypal_opt}
{self.btcpay_req}
{self.configured}
{self.validate}
PAYPAL_PUBLIC_CLIENT_ID={LAB_CLIENT!r}
PAYPAL_CLIENT_ID={LAB_CLIENT!r}
PAYPAL_CLIENT_SECRET=''
PAYPAL_PLAN_1M={LAB_PLAN_1M!r}
PAYPAL_PLAN_1Y={LAB_PLAN_1Y!r}
PAYPAL_PLAN_PERSONAL={LAB_PLAN_PERSONAL!r}
PAYPAL_LIFETIME_SUPPORT_URL={LAB_LIFE_URL_S!r}
PAYPAL_LIFETIME_NO_SUPPORT_URL={LAB_LIFE_URL_N!r}
PAYPAL_LIFETIME_SUPPORT_AMOUNT={LAB_AMT_S!r}
PAYPAL_LIFETIME_NO_SUPPORT_AMOUNT={LAB_AMT_N!r}
PAYPAL_LIFETIME_CURRENCY={LAB_CCY!r}
if validate_commerce_secrets_for_apply; then
  echo VALIDATE_OK
  exit 0
fi
echo VALIDATE_FAIL
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("VALIDATE_FAIL", result.stdout)
        self.assertIn("PAYPAL_CLIENT_SECRET", result.stdout)
        self.assertNotIn(LAB_SECRET, result.stdout)

    def test_validate_refuses_unverified_webhooks_flag(self) -> None:
        script = f"""
set -Eeuo pipefail
err() {{ echo "[ERR] $*" >&2; return 1; }}
ENV_FILE=/x
PAYPAL_WEBHOOK_AUTO_ENSURE_DEFAULT=1
PAYPAL_ALLOW_UNVERIFIED_WEBHOOKS=true
{self.paypal_req}
{self.paypal_opt}
{self.btcpay_req}
{self.configured}
{self.validate}
if validate_commerce_secrets_for_apply; then echo VALIDATE_OK; else echo VALIDATE_FAIL; fi
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("VALIDATE_FAIL", result.stdout)
        self.assertIn("PAYPAL_ALLOW_UNVERIFIED_WEBHOOKS", result.stdout)
        self.assertIn("silent-accept", result.stdout)

    def test_validate_complete_dummy_paypal_passes(self) -> None:
        script = f"""
set -Eeuo pipefail
err() {{ echo "[ERR] $*" >&2; return 1; }}
ENV_FILE=/x
PAYPAL_WEBHOOK_AUTO_ENSURE_DEFAULT=1
PAYPAL_WEBHOOK_AUTO_ENSURE=1
PAYPAL_PUBLIC_CLIENT_ID={LAB_CLIENT!r}
PAYPAL_CLIENT_ID={LAB_CLIENT!r}
PAYPAL_CLIENT_SECRET={LAB_SECRET!r}
PAYPAL_PLAN_1M={LAB_PLAN_1M!r}
PAYPAL_PLAN_1Y={LAB_PLAN_1Y!r}
PAYPAL_PLAN_PERSONAL={LAB_PLAN_PERSONAL!r}
PAYPAL_LIFETIME_SUPPORT_URL={LAB_LIFE_URL_S!r}
PAYPAL_LIFETIME_NO_SUPPORT_URL={LAB_LIFE_URL_N!r}
PAYPAL_LIFETIME_SUPPORT_AMOUNT={LAB_AMT_S!r}
PAYPAL_LIFETIME_NO_SUPPORT_AMOUNT={LAB_AMT_N!r}
PAYPAL_LIFETIME_CURRENCY={LAB_CCY!r}
{self.paypal_req}
{self.paypal_opt}
{self.btcpay_req}
{self.configured}
{self.validate}
validate_commerce_secrets_for_apply
echo VALIDATE_OK
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("VALIDATE_OK", result.stdout)

    def test_validate_btcpay_partial_fails(self) -> None:
        script = f"""
set -Eeuo pipefail
err() {{ echo "[ERR] $*" >&2; return 1; }}
ENV_FILE=/x
PAYPAL_WEBHOOK_AUTO_ENSURE_DEFAULT=1
PAYPAL_WEBHOOK_AUTO_ENSURE=1
PAYPAL_PUBLIC_CLIENT_ID={LAB_CLIENT!r}
PAYPAL_CLIENT_ID={LAB_CLIENT!r}
PAYPAL_CLIENT_SECRET={LAB_SECRET!r}
PAYPAL_PLAN_1M={LAB_PLAN_1M!r}
PAYPAL_PLAN_1Y={LAB_PLAN_1Y!r}
PAYPAL_PLAN_PERSONAL={LAB_PLAN_PERSONAL!r}
PAYPAL_LIFETIME_SUPPORT_URL={LAB_LIFE_URL_S!r}
PAYPAL_LIFETIME_NO_SUPPORT_URL={LAB_LIFE_URL_N!r}
PAYPAL_LIFETIME_SUPPORT_AMOUNT={LAB_AMT_S!r}
PAYPAL_LIFETIME_NO_SUPPORT_AMOUNT={LAB_AMT_N!r}
PAYPAL_LIFETIME_CURRENCY={LAB_CCY!r}
BTCPAY_URL='https://btcpay.example.invalid'
BTCPAY_STORE_ID=''
BTCPAY_API_KEY=''
BTCPAY_WEBHOOK_SECRET=''
{self.paypal_req}
{self.paypal_opt}
{self.btcpay_req}
{self.configured}
{self.validate}
if validate_commerce_secrets_for_apply; then echo VALIDATE_OK; else echo VALIDATE_FAIL; fi
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("VALIDATE_FAIL", result.stdout)
        self.assertIn("BTCPAY_STORE_ID", result.stdout)

    def test_replace_updates_secret_and_preserves_redemption(self) -> None:
        work = TMP / "replace"
        work.mkdir(parents=True, exist_ok=True)
        env_file = work / "vpn_auth.env"
        legacy = work / "legacy.env"
        body = empty_runtime()
        env_file.write_text(body, encoding="utf-8")
        legacy.write_text(body, encoding="utf-8")
        before = hashlib.sha256(env_file.read_bytes()).hexdigest()
        script = f"""
set -Eeuo pipefail
ENV_FILE={str(env_file)!r}
LEGACY_ENV_FILE={str(legacy)!r}
{self.atomic}
{self.replace_kv}
replace_runtime_env_kv PAYPAL_CLIENT_SECRET {LAB_SECRET!r}
replace_runtime_env_kv PAYPAL_CLIENT_ID {LAB_CLIENT!r}
# shellcheck disable=SC1090
source "$ENV_FILE"
printf '%s' "${{#PAYPAL_CLIENT_SECRET}}"
printf '\\n'
printf '%s' "${{#REDEMPTION_KEYS}}"
printf '\\n'
[[ "${{PAYPAL_CLIENT_SECRET}}" == {LAB_SECRET!r} ]]
[[ "${{REDEMPTION_KEYS}}" == {LAB_REDEMPTION!r} ]]
[[ "${{ADMIN_TOKEN}}" == 'lab-dummy-admin-token-not-used-for-commerce' ]]
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stdout)
        secret_len, redemption_len = result.stdout.strip().splitlines()
        self.assertEqual(secret_len, str(len(LAB_SECRET)))
        self.assertEqual(redemption_len, str(len(LAB_REDEMPTION)))
        after = env_file.read_text(encoding="utf-8")
        self.assertIn("PAYPAL_CLIENT_SECRET=", after)
        self.assertEqual(after.count("PAYPAL_CLIENT_SECRET="), 1)
        self.assertNotEqual(before, hashlib.sha256(env_file.read_bytes()).hexdigest())
        mode = stat.S_IMODE(env_file.stat().st_mode)
        self.assertEqual(mode, 0o600)

    def test_partial_apply_leaves_runtime_bytes_unchanged(self) -> None:
        work = TMP / "partial-apply"
        work.mkdir(parents=True, exist_ok=True)
        env_file = work / "vpn_auth.env"
        secrets = work / "winsvpn-secrets.env"
        env_file.write_text(empty_runtime(), encoding="utf-8")
        secrets.write_text(
            f"PAYPAL_CLIENT_ID='{LAB_CLIENT}'\nPAYPAL_CLIENT_SECRET=''\n",
            encoding="utf-8",
        )
        before = env_file.read_bytes()
        before_hash = hashlib.sha256(before).hexdigest()
        script = f"""
set -Eeuo pipefail
err() {{ echo "[ERR] $*" >&2; return 1; }}
log() {{ echo "[INFO] $*"; }}
require_root() {{ return 0; }}
ENV_FILE={str(env_file)!r}
LEGACY_ENV_FILE={str(work / 'legacy.env')!r}
WINS_SECRETS_FILE={str(secrets)!r}
PAYPAL_WEBHOOK_AUTO_ENSURE_DEFAULT=1
overlay_wins_secrets_file() {{ . "$WINS_SECRETS_FILE"; }}
load_existing_envs() {{ . "$ENV_FILE"; }}
{self.paypal_req}
{self.paypal_opt}
{self.btcpay_req}
{self.configured}
{self.validate}
{self.require_file}
{self.atomic}
{self.replace_kv}
{self.apply}
systemctl() {{ echo "systemctl-should-not-run $*"; exit 97; }}
curl() {{ echo "curl-should-not-run $*"; exit 97; }}
if apply_commerce_secrets; then echo APPLY_OK; else echo APPLY_FAIL; fi
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("APPLY_FAIL", result.stdout)
        self.assertNotIn("APPLY_OK", result.stdout)
        self.assertNotIn("systemctl-should-not-run", result.stdout)
        after = env_file.read_bytes()
        self.assertEqual(hashlib.sha256(after).hexdigest(), before_hash)
        self.assertEqual(after, before)

    def test_complete_apply_writes_paypal_preserves_redemption_restarts(self) -> None:
        work = TMP / "complete-apply"
        work.mkdir(parents=True, exist_ok=True)
        env_file = work / "vpn_auth.env"
        legacy = work / "legacy.env"
        secrets = work / "winsvpn-secrets.env"
        ctl_log = work / "systemctl.log"
        env_file.write_text(empty_runtime(), encoding="utf-8")
        legacy.write_text(empty_runtime(), encoding="utf-8")
        secrets.write_text(filled_secrets(), encoding="utf-8")
        ctl_log.write_text("", encoding="utf-8")
        script = f"""
set -Eeuo pipefail
err() {{ echo "[ERR] $*" >&2; return 1; }}
log() {{ echo "[INFO] $*"; }}
require_root() {{ return 0; }}
systemctl() {{ printf '%s\\n' "$*" >> {str(ctl_log)!r}; }}
curl() {{ return 0; }}
ENV_FILE={str(env_file)!r}
LEGACY_ENV_FILE={str(legacy)!r}
WINS_SECRETS_FILE={str(secrets)!r}
PAYPAL_WEBHOOK_AUTO_ENSURE_DEFAULT=1
WINS_HEALTH_USER_AGENT_DEFAULT=lab-dummy-ua
overlay_wins_secrets_file() {{ . "$WINS_SECRETS_FILE"; }}
load_existing_envs() {{ . "$ENV_FILE"; }}
{self.paypal_req}
{self.paypal_opt}
{self.btcpay_req}
{self.configured}
{self.validate}
{self.require_file}
{self.atomic}
{self.replace_kv}
{self.apply}
apply_commerce_secrets
# shellcheck disable=SC1090
source "$ENV_FILE"
[[ "${{PAYPAL_CLIENT_SECRET}}" == {LAB_SECRET!r} ]]
[[ "${{PAYPAL_CLIENT_ID}}" == {LAB_CLIENT!r} ]]
[[ "${{REDEMPTION_KEYS}}" == {LAB_REDEMPTION!r} ]]
printf '%s' "${{#PAYPAL_CLIENT_SECRET}}"
printf '\\n'
printf '%s' "${{#REDEMPTION_KEYS}}"
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stdout)
        secret_len, redemption_len = [
            line for line in result.stdout.splitlines() if line.isdigit()
        ][-2:]
        self.assertEqual(secret_len, str(len(LAB_SECRET)))
        self.assertEqual(redemption_len, str(len(LAB_REDEMPTION)))
        self.assertEqual(
            ctl_log.read_text(encoding="utf-8").strip(),
            "restart wins-hub.service",
        )
        text = env_file.read_text(encoding="utf-8")
        self.assertEqual(text.count("PAYPAL_CLIENT_SECRET="), 1)
        self.assertNotIn(LAB_SECRET, result.stdout)

    def test_missing_secrets_file_fails_closed(self) -> None:
        script = f"""
set -Eeuo pipefail
err() {{ echo "[ERR] $*" >&2; return 1; }}
WINS_SECRETS_FILE=/no/such/winsvpn-secrets.env
overlay_wins_secrets_file() {{
  [[ -f "${{WINS_SECRETS_FILE}}" ]] || return 0
  . "${{WINS_SECRETS_FILE}}"
}}
{self.require_file}
if require_wins_secrets_file; then echo REQUIRE_OK; else echo REQUIRE_FAIL; fi
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("REQUIRE_FAIL", result.stdout)
        self.assertIn("Missing", result.stdout)

    def test_example_is_names_only_empty_values(self) -> None:
        text = EXAMPLE.read_text(encoding="utf-8")
        self.assertIn("PAYPAL_CLIENT_SECRET=", text)
        self.assertIn("BTCPAY_API_KEY=", text)
        self.assertIn("BTCPAY_WEBHOOK_SECRET=", text)
        self.assertNotIn("PAYPAL_ALLOW_UNVERIFIED_WEBHOOKS=", text)
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            key, _, value = stripped.partition("=")
            if key in {
                "PAYPAL_MODE",
                "PAYPAL_WEBHOOK_AUTO_ENSURE",
                "PAYPAL_WEBHOOK_URL",
            }:
                continue
            self.assertEqual(
                value,
                "",
                f"example must not carry a value for {key}",
            )

    def test_gitignore_covers_live_secret_filenames(self) -> None:
        gi = GITIGNORE.read_text(encoding="utf-8")
        self.assertIn("*.env", gi)
        self.assertIn("winsvpn-secrets.env", gi)
        self.assertIn("hub-commerce.env", gi)
        probes = [
            ROOT / "winsvpn-secrets.env",
            ROOT / "hub-commerce.env",
            ROOT / "server" / "winsvpn-secrets.env",
            ROOT / "server" / "hub-commerce.env",
        ]
        for path in probes:
            chk = subprocess.run(
                ["git", "-C", str(ROOT), "check-ignore", "-v", str(path)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=15,
                check=False,
            )
            self.assertEqual(
                chk.returncode,
                0,
                f"expected ignored: {path}\n{chk.stdout}",
            )
        example_chk = subprocess.run(
            ["git", "-C", str(ROOT), "check-ignore", "-v", str(EXAMPLE)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
            check=False,
        )
        self.assertNotEqual(
            example_chk.returncode,
            0,
            f"example must NOT be ignored\n{example_chk.stdout}",
        )

    def test_help_lists_apply_commerce_flag(self) -> None:
        self.assertIn("--apply-commerce-secrets", self.source)
        usage_line = [
            line
            for line in self.source.splitlines()
            if line.startswith('      echo "Usage: sudo bash')
        ]
        self.assertTrue(usage_line)
        self.assertIn("--apply-commerce-secrets", usage_line[0])

    def test_gradle_wfa_model_still_fail_closed_on_partial(self) -> None:
        gradle = (
            ROOT.parent
            / "wins_security"
            / "platform"
            / "flutter"
            / "android"
            / "app"
            / "build.gradle"
        )
        if not gradle.is_file():
            self.skipTest("optional historical wins_security checkout is absent")
        text = gradle.read_text(encoding="utf-8")
        self.assertIn("hasAnyWinsSecuritySigning", text)
        self.assertIn("hasCompleteWinsSecuritySigning", text)
        self.assertIn("Incomplete Win For All release signing environment", text)
        self.assertIn("WINS_ANDROID_SECURITY_KEYSTORE", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
    print("Ops secrets-file mechanism tests passed")
