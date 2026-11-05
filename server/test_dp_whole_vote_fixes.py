"""Whole-tree vote fixes in the data-plane installer.

1. Design v17 3.17 node side (S4): a plain fresh install completes through
   POST /api/v1/nodes/{slug}/deployment/complete-fresh, called by main() on the
   fresh branch after mark_data_deployment_ready and before the Cloudflare
   commit. Design 5.6 mutant: "the fresh path skips deployment/complete-fresh".
2. N-4/N-5: phase A does not resolve a first install's name, flag and host
   defaults before apt_install has installed jq; it needs only the address.
3. SYNC-14 N-3: phase B invalidates the gateway provenance stamp before the
   first gateway write."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

DP = Path(__file__).resolve().parent / "wins_data_plane_setup_ONETOUCH.sh"
BASH = os.environ.get("WINS_TEST_BASH") or shutil.which("bash")
DIGEST = "ab" * 32


def function_body(source: str, name: str) -> str:
    match = re.search(r"^" + name + r"\(\) \{\n.*?^\}\n", source, re.S | re.M)
    if match is None:
        raise AssertionError(f"{name} is not defined at column 0")
    return match.group(0)


class FreshBranchOrder(unittest.TestCase):
    def test_the_fresh_branch_completes_after_ready_and_before_the_cloudflare_commit(self):
        main = function_body(DP.read_text(), "main")
        start = main.index('if [[ "${DATA_INSTALLER_RERUN_ACTIVE}" == "1" ]]; then')
        commit = main.index("cloudflare_redirect_transaction_commit", start)
        branch = main[start:commit]
        fresh = branch[branch.index("\n  else\n"):]
        ready = fresh.index("mark_data_deployment_ready")
        complete = fresh.index("complete_fresh_deployment_after_postflight || return 1")
        self.assertLess(ready, complete)
        self.assertEqual(main.count("complete_fresh_deployment_after_postflight"), 1)


class CompleteFreshRequest(unittest.TestCase):
    def run_completion(self, response: str, digest: str = DIGEST):
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work, True)
        bindir = work / "bin"
        bindir.mkdir()
        record = work / "record"
        (bindir / "curl").write_text(
            "#!/bin/sh\n"
            "data=''\n"
            "for a in \"$@\"; do case \"$a\" in @*) data=\"${a#@}\";; esac; done\n"
            f"{{ cat; printf 'DATA '; cat \"$data\"; }} > '{record}'\n"
            "printf '%s' \"$CURL_RESPONSE\"\n")
        (bindir / "curl").chmod(0o755)
        function = function_body(DP.read_text(), "complete_fresh_deployment_after_postflight")
        script = (
            "set -Eeuo pipefail\n"
            "err() { printf 'ERR %s\\n' \"$*\" >&2; }\n"
            "log() { printf 'LOG %s\\n' \"$*\" >&2; }\n"
            "warn() { printf 'WARN %s\\n' \"$*\" >&2; }\n"
            f"data_plane_installer_sha256() {{ printf '%s\\n' '{digest}'; }}\n"
            "NODE_TOKEN=tok-123; NODE_SLUG=sg-1; HUB_API_BASE=https://hub.example/\n"
            + function +
            "if complete_fresh_deployment_after_postflight; then echo RC=0; else echo RC=1; fi\n")
        env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", CURL_RESPONSE=response,
                   TMPDIR=str(work))
        proc = subprocess.run([BASH, "-c", script], capture_output=True, text=True, env=env, timeout=60)
        sent = record.read_text() if record.exists() else None
        return proc.stdout.strip().splitlines()[-1], proc.stderr, sent

    def test_an_accepted_completion_posts_the_installer_digest_with_the_node_token(self):
        rc, err, sent = self.run_completion(json.dumps(
            {"ok": True, "slug": "sg-1", "operator_enabled": False, "auto_golive_pending": True, "reasons": []}))
        self.assertEqual(rc, "RC=0", err)
        self.assertIn('url = "https://hub.example/api/v1/nodes/sg-1/deployment/complete-fresh"', sent)
        self.assertIn('header = "x-node-token: tok-123"', sent)
        self.assertIn('request = "POST"', sent)
        body = json.loads(sent.split("DATA ", 1)[1])
        self.assertEqual(body, {"installer_sha256": DIGEST})

    def test_a_manual_completion_succeeds_and_names_the_hub_reasons(self):
        rc, err, _ = self.run_completion(json.dumps(
            {"ok": True, "slug": "sg-1", "operator_enabled": False, "auto_golive_pending": False,
             "reasons": ["ticket says go_live=manual"]}))
        self.assertEqual(rc, "RC=0", err)
        self.assertIn("WARN Hub: automatic go-live not recorded: ticket says go_live=manual", err)

    def test_every_refusal_fails_the_install(self):
        for response in ("", "not json", json.dumps({"ok": False, "operator_enabled": False}),
                         json.dumps({"ok": True, "operator_enabled": True}),
                         json.dumps({"ok": True}),
                         # Whole-tree reconciliation (stricter than either seat's draft): the
                         # answer must name this slug and be exactly one JSON object.
                         json.dumps({"ok": True, "slug": "other", "operator_enabled": False}),
                         json.dumps({"ok": True, "operator_enabled": False}),
                         json.dumps({"ok": True, "slug": "sg-1", "operator_enabled": False}) * 2):
            with self.subTest(response=response):
                rc, _err, _ = self.run_completion(response)
                self.assertEqual(rc, "RC=1")

    def test_an_unbound_installer_digest_sends_nothing(self):
        rc, _err, sent = self.run_completion(json.dumps({"ok": True, "operator_enabled": False}),
                                             digest="")
        self.assertEqual(rc, "RC=1")
        self.assertIsNone(sent)


class PhaseANodeDefaults(unittest.TestCase):
    def run_phase_a(self, env_file_exists: bool, resolved: str = "0"):
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work, True)
        node_env = work / "node.env"
        if env_file_exists:
            node_env.write_text("NODE_SLUG=sg-1\n")
        function = function_body(DP.read_text(), "winn3gw_phase_a")
        script = (
            "set -Eeuo pipefail\n"
            "err() { printf 'ERR %s\\n' \"$*\" >&2; }\n"
            "calls=()\n"
            "wins_late_failure_hold() { return 1; }\n"
            "deployment_session_is_direct_remote() { return 1; }\n"
            "data_resolve_node_defaults() { calls+=(resolve); DATA_DETECTED_PUBLIC_IPV4=198.51.100.9;"
            " DATA_AUTO_SLUG=auto; DATA_NODE_DEFAULTS_RESOLVED=1; }\n"
            f"detect_public_ipv4() {{ printf 'detect\\n' >> '{work / 'detect'}'; printf '%s\\n' 203.0.113.7; }}\n"
            "winn3_node_tool() { calls+=(\"tool:$*\"); return 1; }\n"
            f"NODE_ENV_FILE='{node_env}'; NODE_SLUG=sg-1; DATA_DETECTED_PUBLIC_IPV4=''\n"
            f"DATA_NODE_DEFAULTS_RESOLVED={resolved}\n"
            + function +
            "winn3gw_phase_a || true\n"
            f"cat '{work / 'detect'}' 2>/dev/null || true\n"
            "printf '%s\\n' \"${calls[@]}\" \"resolved=${DATA_NODE_DEFAULTS_RESOLVED}\"\n")
        proc = subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=60)
        return proc.stdout.strip().splitlines(), proc.stderr

    def test_a_first_install_detects_only_the_address(self):
        lines, err = self.run_phase_a(env_file_exists=False)
        self.assertEqual(lines[0], "detect", err)
        self.assertNotIn("resolve", lines)
        self.assertIn("tool:identity-context /etc/winn/public/gateway-identity.json sg-1 203.0.113.7:9111", lines)
        self.assertEqual(lines[-1], "resolved=0")

    def test_a_rerun_resolves_its_defaults_early(self):
        lines, err = self.run_phase_a(env_file_exists=True)
        self.assertEqual(lines[0], "resolve", err)
        self.assertNotIn("detect", lines)
        self.assertEqual(lines[-1], "resolved=1")

    def test_defaults_already_resolved_are_not_resolved_again(self):
        lines, err = self.run_phase_a(env_file_exists=False, resolved="1")
        self.assertNotIn("resolve", lines, err)
        self.assertNotIn("detect", lines)


class GatewayStampInvalidation(unittest.TestCase):
    def test_phase_b_invalidates_the_stamp_before_the_first_gateway_write(self):
        source = DP.read_text()
        body = function_body(source, "winn3gw_phase_b")
        at = body.index("\n  invalidate_gateway_code_stamp\n")
        for first_write in ("ensure_service_user", "install_binary", "winn3_node_tool credentials",
                            "write_unit", "record_gateway_code_stamp"):
            self.assertLess(at, body.index(first_write), first_write)
        self.assertGreater(at, body.index("check_gateway_egress_mtu || return 1"))


if __name__ == "__main__":
    unittest.main()
