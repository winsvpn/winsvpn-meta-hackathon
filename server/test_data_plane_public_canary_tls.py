#!/usr/bin/env python3
"""Hostile TLS tests for the data-plane public WebSocket canary.

The public canary is deployment evidence for a DNS hostname routed through
Cloudflare.  It must reject an untrusted chain and a hostname mismatch even
when a default curl configuration tries to enable insecure mode.

Run: python3 server/test_data_plane_public_canary_tls.py
"""

from __future__ import annotations

import os
import pathlib
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import _toolchain  # noqa: F401  (V-01 preflight)


ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA_SCRIPT = ROOT / "server" / "wins_data_plane_setup_ONETOUCH.sh"
SOURCE = DATA_SCRIPT.read_text(encoding="utf-8")


def _extract_canary() -> str:
    opener = "cat > /usr/local/bin/wins-node-canary <<'EOF'\n"
    start = SOURCE.index(opener) + len(opener)
    end = SOURCE.index("\nEOF", start)
    return SOURCE[start:end]


def _function_body(source: str, name: str) -> str:
    start = source.index(f"{name}() {{")
    candidates = [
        position
        for marker in ("\n}\n\n", "\n}\r\n\r\n")
        if (position := source.find(marker, start)) >= 0
    ]
    if not candidates:
        raise AssertionError(f"could not find the end of {name}")
    return source[start : min(candidates) + 2]


CANARY = _extract_canary()
PUBLIC_PROBE = _function_body(CANARY, "check_public_websocket")


class _UpgradeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        self.send_response_only(101, "Switching Protocols")
        self.send_header("Connection", "Upgrade")
        self.send_header("Upgrade", "websocket")
        self.send_header("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
        self.end_headers()
        self.close_connection = True

    def log_message(self, _format: str, *_args: object) -> None:
        return None


class _QuietThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, _request: object, _client_address: object) -> None:
        return None


class PublicCanaryTlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.curl = shutil.which("curl")
        cls.openssl = shutil.which("openssl")
        cls.bash = shutil.which("bash")
        missing = [
            name
            for name, value in (
                ("bash", cls.bash),
                ("curl", cls.curl),
                ("openssl", cls.openssl),
            )
            if value is None
        ]
        if missing:
            raise RuntimeError(
                "data-plane canary TLS tests require: " + ", ".join(missing)
            )

        cls._temporary_directory = tempfile.TemporaryDirectory()
        cls.temp = pathlib.Path(cls._temporary_directory.name)
        cls.ca_cert = cls.temp / "ca.crt"
        cls.ca_key = cls.temp / "ca.key"
        cls.server_cert = cls.temp / "server.crt"
        cls.server_key = cls.temp / "server.key"
        cls.server_csr = cls.temp / "server.csr"
        cls._make_certificates()

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cls.server_cert, cls.server_key)
        cls.server = _QuietThreadingHTTPServer(("127.0.0.1", 0), _UpgradeHandler)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.server_thread = threading.Thread(
            target=cls.server.serve_forever,
            name="public-canary-hostile-tls",
            daemon=True,
        )
        cls.server_thread.start()

        functions_start = CANARY.index("failed=0")
        functions_end = CANARY.index('\nlog "Node canary started', functions_start)
        cls.canary_helpers = cls.temp / "wins-node-canary-helpers"
        cls.canary_helpers.write_text(
            "#!/usr/bin/env bash\n"
            "set -Eeuo pipefail\n"
            'LOG_FILE="${TEST_LOG_FILE:?}"\n'
            'CURL_UA="${TEST_CURL_UA:-curl/8.5.0}"\n'
            + CANARY[functions_start:functions_end]
            + "\n",
            encoding="utf-8",
        )
        cls.curl_home = cls.temp / "curl-home"
        cls.curl_home.mkdir()
        (cls.curl_home / ".curlrc").write_text("insecure\n", encoding="ascii")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=5)
        cls._temporary_directory.cleanup()

    @classmethod
    def _run_openssl(cls, *arguments: str) -> None:
        process = subprocess.run(
            [cls.openssl, *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if process.returncode != 0:
            raise RuntimeError(process.stderr.strip() or "openssl command failed")

    @classmethod
    def _make_certificates(cls) -> None:
        ca_config = cls.temp / "ca.cnf"
        ca_config.write_text(
            "[req]\n"
            "prompt = no\n"
            "distinguished_name = dn\n"
            "x509_extensions = v3_ca\n"
            "[dn]\n"
            "CN = Wins Canary Test Root\n"
            "[v3_ca]\n"
            "basicConstraints = critical,CA:true\n"
            "keyUsage = critical,keyCertSign,cRLSign\n"
            "subjectKeyIdentifier = hash\n",
            encoding="ascii",
        )
        cls._run_openssl(
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-days",
            "1",
            "-config",
            str(ca_config),
            "-keyout",
            str(cls.ca_key),
            "-out",
            str(cls.ca_cert),
        )

        server_config = cls.temp / "server.cnf"
        server_config.write_text(
            "[req]\n"
            "prompt = no\n"
            "distinguished_name = dn\n"
            "req_extensions = req_ext\n"
            "[dn]\n"
            "CN = localhost\n"
            "[req_ext]\n"
            "subjectAltName = DNS:localhost\n",
            encoding="ascii",
        )
        cls._run_openssl(
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-config",
            str(server_config),
            "-keyout",
            str(cls.server_key),
            "-out",
            str(cls.server_csr),
        )
        server_extensions = cls.temp / "server.ext"
        server_extensions.write_text(
            "subjectAltName = DNS:localhost\n"
            "basicConstraints = critical,CA:false\n"
            "keyUsage = critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage = serverAuth\n",
            encoding="ascii",
        )
        cls._run_openssl(
            "x509",
            "-req",
            "-in",
            str(cls.server_csr),
            "-CA",
            str(cls.ca_cert),
            "-CAkey",
            str(cls.ca_key),
            "-CAcreateserial",
            "-days",
            "1",
            "-sha256",
            "-extfile",
            str(server_extensions),
            "-out",
            str(cls.server_cert),
        )

    def _environment(self, *, trust_test_ca: bool, hostile_curlrc: bool) -> dict[str, str]:
        environment = os.environ.copy()
        for name in (
            "ALL_PROXY",
            "CURL_CA_BUNDLE",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "SSL_CERT_DIR",
            "SSL_CERT_FILE",
            "all_proxy",
            "http_proxy",
            "https_proxy",
        ):
            environment.pop(name, None)
        environment["NO_PROXY"] = "*"
        environment["no_proxy"] = "*"
        environment["NODE_CANARY_STRICT_PUBLIC"] = "1"
        environment["TEST_LOG_FILE"] = str(self.temp / "canary.log")
        if trust_test_ca:
            environment["CURL_CA_BUNDLE"] = str(self.ca_cert)
        if hostile_curlrc:
            environment["CURL_HOME"] = str(self.curl_home)
        else:
            environment["CURL_HOME"] = str(self.temp / "no-curl-config")
        return environment

    def _run_canary(
        self,
        url: str,
        *,
        trust_test_ca: bool,
        hostile_curlrc: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        harness = r'''
source "$1"
sleep() { :; }
check_public_websocket "hostile TLS fixture" "$2"
printf 'failed=%s\n' "$failed"
exit "$failed"
'''
        return subprocess.run(
            [self.bash, "-c", harness, "_", str(self.canary_helpers), url],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
            env=self._environment(
                trust_test_ca=trust_test_ca,
                hostile_curlrc=hostile_curlrc,
            ),
        )

    def test_public_probe_enforces_curl_verification_defaults(self) -> None:
        self.assertIn('status="$(curl -q -A "${CURL_UA}"', PUBLIC_PROBE)
        self.assertNotIn(" -k ", PUBLIC_PROBE)
        self.assertNotIn(" --insecure ", PUBLIC_PROBE)

    def test_matching_certificate_succeeds_when_test_ca_is_trusted(self) -> None:
        url = f"https://localhost:{self.server.server_port}/wins-stealth-tunnel"
        process = self._run_canary(url, trust_test_ca=True)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertIn("OK hostile TLS fixture", process.stdout)
        self.assertIn("failed=0", process.stdout)

    def test_untrusted_certificate_fails_with_verification_exit(self) -> None:
        url = f"https://localhost:{self.server.server_port}/wins-stealth-tunnel"
        process = self._run_canary(url, trust_test_ca=False)
        self.assertEqual(process.returncode, 1, process.stdout + process.stderr)
        self.assertIn("FAIL hostile TLS fixture", process.stdout)
        self.assertIn("actual=000", process.stdout)
        self.assertIn("curl-exit=60", process.stdout)
        self.assertIn("failed=1", process.stdout)

    def test_curlrc_cannot_reenable_insecure_mode(self) -> None:
        url = f"https://localhost:{self.server.server_port}/wins-stealth-tunnel"
        environment = self._environment(trust_test_ca=False, hostile_curlrc=True)
        insecure_control = subprocess.run(
            [
                self.curl,
                "-sS",
                "--http1.1",
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
                url,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=environment,
        )
        # curl may report 52 after the fixture closes the upgraded socket.  A
        # received 101 still proves the curlrc bypassed certificate rejection.
        self.assertNotEqual(insecure_control.returncode, 60)
        self.assertEqual(insecure_control.stdout, "101", insecure_control.stderr)

        process = self._run_canary(
            url,
            trust_test_ca=False,
            hostile_curlrc=True,
        )
        self.assertEqual(process.returncode, 1, process.stdout + process.stderr)
        self.assertIn("actual=000", process.stdout)
        self.assertIn("curl-exit=60", process.stdout)

    def test_trusted_certificate_for_wrong_hostname_fails(self) -> None:
        url = f"https://127.0.0.1:{self.server.server_port}/wins-stealth-tunnel"
        process = self._run_canary(url, trust_test_ca=True)
        self.assertEqual(process.returncode, 1, process.stdout + process.stderr)
        self.assertIn("actual=000", process.stdout)
        self.assertIn("curl-exit=60", process.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
