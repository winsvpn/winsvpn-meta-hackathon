#!/usr/bin/env python3
"""Fleet reset plan 2026-10-08 (FLEET1): server/spain_crypto_payments_setup.sh.

The script must reproduce the configuration that works on Spain today (the
view-only wallet opened by --wallet-file, /json_rpc served to the hub), probe
the BTCPay upstream it proxies, and print hub instructions that work.

  TP-P3  the daemon opens the staged view-only wallet; no --wallet-dir, no
         restricted-rpc; the wallet files must be staged regular files.
  D7     nginx serves exactly one `location = /json_rpc` to the loopback
         wallet RPC and drops the Access headers before the daemon.
  FLEET1 Turn 2  the wallet has its own loopback listener (23001); no Host on
         the public BTCPay listener (23000) selects a server that reaches the
         wallet, and verify_services proves both at runtime.
  TP-P5  the summary goes to the secrets file and the apply path, never a
         hand edit of /root/vpn_auth.env, and says what --apply-commerce-secrets
         does not apply.
  TP-P6  verify_services refuses a BTCPay upstream that never answers.

Run: python3 -B -m pytest -q -p no:cacheprovider server/test_fleet_reset_spain_script.py
     WINS_FLEET_SPAIN=/path/to/script ... (mutant runs)
"""

from __future__ import annotations

import re
import subprocess
import textwrap
import unittest

import fleet_reset_testlib as lib

SPAIN = lib.installer("WINS_FLEET_SPAIN", "server/spain_crypto_payments_setup.sh")
SRC = SPAIN.read_text(encoding="utf-8")


def monero_service() -> str:
    return lib.function_text(SRC, "setup_monero_service")


class Case(unittest.TestCase):
    def setUp(self) -> None:
        self.sb = lib.Sandbox()

    def tearDown(self) -> None:
        self.sb.cleanup()


class WalletDaemonTests(Case):
    def test_the_unit_opens_the_staged_wallet_and_the_config_holds_the_secret(self) -> None:
        body = monero_service()
        unit = body[body.index("cat > /etc/systemd/system/monero-wallet-rpc.service <<EOF"):]
        unit = unit[:unit.index("\nEOF\n")]
        exec_start = unit[unit.index("ExecStart="):unit.index("Restart=")]
        self.assertNotIn("--wallet-dir", exec_start)
        self.assertIn("--config-file ${rpc_conf}", exec_start)
        self.assertIn("--wallet-file ${wallet_file}", exec_start)
        self.assertIn("--password-file ${MONERO_WALLET_PASSWORD_FILE}", exec_start)
        self.assertIn("--non-interactive", exec_start)
        self.assertNotIn("rpc-login", exec_start, "the RPC credential stays in the service-owned config")
        conf = body[body.index('cat > "${rpc_conf}" <<EOF'):]
        conf = conf[:conf.index("\nEOF\n")]
        self.assertIn("rpc-login=${rpc_user}:${rpc_pass}", conf)
        self.assertIn("rpc-bind-ip=127.0.0.1", conf)
        self.assertNotIn("restricted-rpc", conf)
        self.assertIn('MONERO_WALLET_PASSWORD_FILE="${MONERO_WALLET_DIR}/wallet.pass"', SRC)
        self.assertIn('MONERO_WALLET_NAME="${MONERO_WALLET_NAME:-winsvpn_view_wallet}"', SRC)

    def staging(self) -> str:
        body = monero_service()
        start = body.index('    [[ "${MONERO_WALLET_NAME}" =~')
        end = body.index("    (\n        umask 077", start)
        return body[start:end]

    def run_staging(self, files: dict[str, str | None], name: str = "winsvpn_view_wallet") -> subprocess.CompletedProcess:
        wallet = self.sb.path("wallet")
        wallet.mkdir()
        for fname, content in files.items():
            p = wallet / fname
            if content is None:
                p.symlink_to(self.sb.path("elsewhere"))
            else:
                p.write_text(content)
                p.chmod(0o644)
        script = lib.LOG_STUBS + textwrap.dedent(f'''
            set -Eeuo pipefail
            MONERO_WALLET_DIR={wallet}
            MONERO_WALLET_NAME='{name}'
            MONERO_WALLET_PASSWORD_FILE="${{MONERO_WALLET_DIR}}/wallet.pass"
            run() {{
        ''') + self.staging() + "\n  echo STAGED\n}\nrun\n"
        return self.sb.run(script)

    def test_a_staged_view_wallet_is_accepted_and_tightened(self) -> None:
        r = self.run_staging({"winsvpn_view_wallet": "cache", "winsvpn_view_wallet.keys": "keys", "wallet.pass": "pw"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("STAGED", r.stdout)
        for fname in ("winsvpn_view_wallet", "winsvpn_view_wallet.keys", "wallet.pass"):
            self.assertEqual(oct(self.sb.path("wallet", fname).stat().st_mode & 0o777), "0o600", fname)
        self.assertIn("chown -h monero-wallet:monero-wallet", "\n".join(self.sb.logged()))

    def test_the_wallet_cache_may_be_absent(self) -> None:
        r = self.run_staging({"winsvpn_view_wallet.keys": "keys", "wallet.pass": "pw"})
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_missing_or_symlinked_wallet_files_are_refused(self) -> None:
        cases = {
            "no keys": {"wallet.pass": "pw"},
            "no password": {"winsvpn_view_wallet.keys": "keys"},
            "empty password": {"winsvpn_view_wallet.keys": "keys", "wallet.pass": ""},
            "symlinked keys": {"winsvpn_view_wallet.keys": None, "wallet.pass": "pw"},
            "symlinked cache": {"winsvpn_view_wallet": None, "winsvpn_view_wallet.keys": "keys", "wallet.pass": "pw"},
        }
        for label, files in cases.items():
            with self.subTest(label=label):
                self.tearDown()
                self.setUp()
                r = self.run_staging(files)
                self.assertNotEqual(r.returncode, 0, label)
                self.assertNotIn("STAGED", r.stdout)

    def test_a_wallet_name_with_a_path_is_refused(self) -> None:
        r = self.run_staging({"winsvpn_view_wallet.keys": "keys", "wallet.pass": "pw"}, name="../etc/x")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("MONERO_WALLET_NAME must be a plain file name", r.stderr)


class NginxTests(unittest.TestCase):
    def test_exactly_one_json_rpc_location_to_the_loopback_wallet(self) -> None:
        conf = lib.heredoc(SRC, 'cat > "${NGINX_CONF_AVAILABLE}" <<\'EOF\'', "EOF")
        self.assertEqual(len(re.findall(r"^\s*location\s+= /json_rpc\s*\{", conf, re.M)), 1)
        self.assertEqual(len(re.findall(r"json_rpc", conf.split("location = /json_rpc", 1)[1].split("}", 1)[1])), 0)
        block = conf[conf.index("location = /json_rpc"):]
        block = block[:block.index("}")]
        self.assertIn("proxy_pass http://127.0.0.1:18083;", block)
        self.assertIn('proxy_set_header CF-Access-Client-Id "";', block)
        self.assertIn('proxy_set_header CF-Access-Client-Secret "";', block)
        self.assertNotIn("proxy_pass_header Authorization", block)
        self.assertIn("listen 127.0.0.1:23000 default_server;", conf)


def nginx_servers(conf: str) -> list[dict]:
    """Top-level server blocks: listen sockets, names and body text."""
    servers, depth, body = [], 0, []
    for line in conf.splitlines():
        stripped = line.strip()
        if depth == 0 and stripped == "server {":
            depth, body = 1, []
            continue
        if depth:
            depth += stripped.count("{") - stripped.count("}")
            if depth == 0:
                text = "\n".join(body)
                listens = re.findall(r"^\s*listen\s+([^;\s]+)([^;]*);", text, re.M)
                names = re.findall(r"^\s*server_name\s+([^;]+);", text, re.M)
                servers.append({"listen": [(a, "default_server" in rest) for a, rest in listens],
                                "names": " ".join(names).split(), "body": text})
            else:
                body.append(line)
    return servers


def nginx_select(servers: list[dict], socket: str, host: str) -> dict | None:
    """nginx's choice: an exact server_name on that socket, else its default_server, else the first."""
    candidates = [s for s in servers if any(a == socket for a, _ in s["listen"])]
    for server in candidates:
        if host in server["names"]:
            return server
    for server in candidates:
        if any(a == socket and d for a, d in server["listen"]):
            return server
    return candidates[0] if candidates else None


class WalletListenerTests(unittest.TestCase):
    HOSTS = ("btcpay.winsvpn.org", "monero-rpc.winsvpn.org", "localhost", "_", "", "evil.example")

    def setUp(self) -> None:
        self.servers = nginx_servers(lib.heredoc(SRC, 'cat > "${NGINX_CONF_AVAILABLE}" <<\'EOF\'', "EOF"))

    def test_no_host_on_the_public_btcpay_listener_reaches_the_wallet(self) -> None:
        # btcpay.winsvpn.org is public (no Access) and its ingress points at
        # 23000; a Host header must never select a wallet server there.
        for host in self.HOSTS:
            with self.subTest(host=host):
                server = nginx_select(self.servers, "127.0.0.1:23000", host)
                self.assertIsNotNone(server)
                self.assertNotIn("18083", server["body"], host)
                self.assertNotIn("json_rpc", server["body"], host)
        self.assertIn("proxy_pass http://127.0.0.1:49392;",
                      nginx_select(self.servers, "127.0.0.1:23000", "btcpay.winsvpn.org")["body"])

    def test_the_wallet_listener_serves_only_json_rpc(self) -> None:
        on_wallet = [s for s in self.servers if any(a == "127.0.0.1:23001" for a, _ in s["listen"])]
        self.assertEqual(len(on_wallet), 1)
        self.assertEqual([a for a, _ in on_wallet[0]["listen"]], ["127.0.0.1:23001"])
        for host in self.HOSTS:
            with self.subTest(host=host):
                server = nginx_select(self.servers, "127.0.0.1:23001", host)
                self.assertIs(server, on_wallet[0])
        body = on_wallet[0]["body"]
        self.assertIn("location = /json_rpc {", body)
        self.assertIn("proxy_pass http://127.0.0.1:18083;", body)
        self.assertNotIn("49392", body)
        self.assertRegex(body, r"location / \{\s*return 404;\s*\}")
        for server in self.servers:
            for address, _ in server["listen"]:
                self.assertTrue(address.startswith("127.0.0.1:"), address)


class WalletListenerProbeTests(Case):
    CURL = r'''#!/bin/sh
printf 'curl %s\n' "$*" >> "$FLEET_CALLS"
for a in "$@"; do last="$a"; done
case "$last" in
  *23001/json_rpc*) printf '%s' "${FLEET_WALLET_PROXY_CODE:-401}" ;;
  *23000/json_rpc*)
    case "$*" in *"Host: ${FLEET_LEAK_HOST:-none}"*)
      printf 'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest qop="auth"\r\n\r\n' ;;
    *) printf 'HTTP/1.1 404 Not Found\r\n\r\n' ;; esac ;;
esac
'''

    def probe(self, **env: str) -> subprocess.CompletedProcess:
        (self.sb.bin / "curl").write_text(self.CURL)
        (self.sb.bin / "curl").chmod(0o755)
        body = lib.function_text(SRC, "verify_services")
        start = body.index("    # FLEET1 Turn 2: the wallet RPC answers")
        end = body.rindex("\n}")
        script = lib.LOG_STUBS + "info() { printf '[INFO] %s\\n' \"$*\"; }\nset -Eeuo pipefail\nrun() {\n" + body[start:end] + "\n  echo PROVEN\n}\nrun\n"
        return self.sb.run(script, **env)

    def test_the_wallet_only_on_its_own_listener_passes(self) -> None:
        r = self.probe()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("PROVEN", r.stdout)
        hosts = [c for c in self.sb.logged() if "23000/json_rpc" in c]
        self.assertEqual(len(hosts), 3)

    def test_a_wallet_on_the_btcpay_listener_is_refused_for_any_host(self) -> None:
        for host in ("btcpay.winsvpn.org", "monero-rpc.winsvpn.org", "localhost"):
            with self.subTest(host=host):
                r = self.probe(FLEET_LEAK_HOST=host)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn(f"reaches the wallet RPC for Host {host}", r.stderr)

    def test_a_wallet_listener_without_the_digest_challenge_is_refused(self) -> None:
        r = self.probe(FLEET_WALLET_PROXY_CODE="404")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("127.0.0.1:23001/json_rpc answered 404", r.stderr)


class SummaryTests(unittest.TestCase):
    def test_the_summary_uses_the_secrets_file_and_names_what_apply_skips(self) -> None:
        body = lib.function_text(SRC, "print_summary")
        self.assertNotIn("Kansas Hub Environment Configuration (/root/vpn_auth.env)", body)
        self.assertIn("/root/winsvpn-secrets.env", body)
        self.assertIn("--apply-commerce-secrets", body)
        self.assertIn("does not apply the Monero keys", body)
        self.assertIn('MONERO_WALLET_RPC_URL="https://monero-rpc.winsvpn.org"', body)
        self.assertNotIn("WireGuard", body)
        self.assertIn("printf 'MONERO_WALLET_RPC_PASS is stored in %s and is not printed\\n'", body)


class BtcpayUpstreamProbeTests(Case):
    CURL = '#!/bin/sh\nprintf "curl %s\\n" "$*" >> "$FLEET_CALLS"\nprintf "%s" "${FLEET_HTTP:-000}"\n'

    def probe(self, http: str) -> subprocess.CompletedProcess:
        (self.sb.bin / "curl").write_text(self.CURL)
        (self.sb.bin / "curl").chmod(0o755)
        body = lib.function_text(SRC, "verify_services")
        start = body.index("    local btcpay_ready=")
        end = body.index("    # Check Nginx proxy port", start)
        script = lib.LOG_STUBS + "set -Eeuo pipefail\nsleep() { :; }\nrun() {\n" + body[start:end] + "\n  echo READY\n}\nrun\n"
        return self.sb.run(script, FLEET_HTTP=http)

    def test_a_redirect_to_login_is_ready(self) -> None:
        for http in ("302", "200"):
            with self.subTest(http=http):
                r = self.probe(http)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn("READY", r.stdout)

    def test_a_dead_upstream_fails_after_its_window(self) -> None:
        r = self.probe("502")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("BTCPay is not answering on 127.0.0.1:49392 (got 502)", r.stderr)
        self.assertEqual(sum(1 for c in self.sb.logged() if "127.0.0.1:49392" in c), 60)


if __name__ == "__main__":
    unittest.main()
