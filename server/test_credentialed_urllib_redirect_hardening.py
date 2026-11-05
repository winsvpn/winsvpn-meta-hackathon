#!/usr/bin/env python3
"""Credentialed urllib requests must never follow provider or admin redirects."""

from __future__ import annotations

import pathlib
import re
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable


ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = (ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh").read_text(
    encoding="utf-8"
)

REDIRECT_STATUSES = (301, 302, 303, 307, 308)
HANDLER_NAMES = (
    "_CredentialedNoRedirect",
    "_ProviderNoRedirect",
    "_CloudflareNoRedirect",
    "_LoopbackAdminNoRedirect",
    "_AdminNoRedirect",
)
SECRET_HEADERS = {
    "Authorization": "Bearer synthetic-test-token",
    "X-Admin-Token": "synthetic-admin-token",
    "X-Wins-Activation": "synthetic-activation",
}


def function_body(name: str, *, after: int = 0) -> str:
    start = SOURCE.index(f"def {name}(", after)
    candidates = [
        position
        for marker in ("\ndef ", "\nclass ", "\nPYEOF", "\nWINN3_SET_CARRIER_PY")
        if (position := SOURCE.find(marker, start + 1)) >= 0
    ]
    return SOURCE[start : min(candidates)]


def heredoc_body(opener: str, closer: str) -> str:
    start = SOURCE.index(opener) + len(opener)
    end = SOURCE.index(f"\n{closer}", start)
    return SOURCE[start:end]


def handler_class(name: str) -> type[urllib.request.HTTPRedirectHandler]:
    pattern = re.compile(
        rf"class {re.escape(name)}\(urllib[.]request[.]HTTPRedirectHandler\):\n"
        r"    def redirect_request\(self, req, fp, code, msg, headers, newurl\):\n"
        r"        return None\n"
    )
    match = pattern.search(SOURCE)
    if match is None:
        raise AssertionError(f"No exact fail-closed redirect handler found for {name}")
    namespace = {"urllib": __import__("urllib")}
    namespace["urllib"].request = urllib.request
    exec(compile(match.group(0), f"<{name}>", "exec"), namespace)
    return namespace[name]


def _quiet_log(self, *_args) -> None:
    return None


def _serve(handler: type[BaseHTTPRequestHandler]) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    server._wins_thread = thread  # type: ignore[attr-defined]
    return server


def _stop(server: ThreadingHTTPServer) -> None:
    server.shutdown()
    server.server_close()
    thread = getattr(server, "_wins_thread", None)
    if thread is not None:
        thread.join(timeout=5)


def _capture_handler(
    captured: list[tuple[str, dict[str, str]]],
) -> type[BaseHTTPRequestHandler]:
    class Target(BaseHTTPRequestHandler):
        def _capture(self) -> None:
            captured.append((self.path, {k: v for k, v in self.headers.items()}))
            self.send_response(200)
            self.end_headers()

        do_GET = _capture
        do_POST = _capture
        do_HEAD = _capture
        log_message = _quiet_log

    return Target


def _redirect_handler(
    status: int,
    location_for: Callable[[BaseHTTPRequestHandler], str | None],
) -> type[BaseHTTPRequestHandler]:
    class Redirect(BaseHTTPRequestHandler):
        def _redirect(self) -> None:
            self.send_response(status)
            location = location_for(self)
            if location is not None:
                self.send_header("Location", location)
            self.end_headers()

        do_GET = _redirect
        do_POST = _redirect
        do_HEAD = _redirect
        log_message = _quiet_log

    return Redirect


def _open_credentialed(opener: urllib.request.OpenerDirector, url: str) -> None:
    request = urllib.request.Request(
        url,
        data=b"{}",
        method="POST",
        headers=dict(SECRET_HEADERS),
    )
    opener.open(request, timeout=5)


class CredentialedUrllibRedirectHardeningTests(unittest.TestCase):
    def test_cloudflare_preflight_and_management_use_no_redirect_openers(self) -> None:
        preflight_start = SOURCE.index("verify_preflight_external_credentials()")
        preflight_end = SOURCE.index("\nPYEOF", preflight_start)
        preflight = SOURCE[preflight_start:preflight_end]
        json_request = function_body("json_request", after=preflight_start)
        self.assertIn("_CREDENTIALED_NO_REDIRECT_OPENER.open(request", json_request)
        self.assertNotIn("urllib.request.urlopen(request", json_request)
        tunnel_start = preflight.index("def verify_tunnel_api()")
        tunnel_end = preflight.index('check("Cloudflare Tunnel Edit"', tunnel_start)
        tunnel_probe = preflight[tunnel_start:tunnel_end]
        self.assertIn("_CREDENTIALED_NO_REDIRECT_OPENER.open(request", tunnel_probe)
        self.assertNotIn("urllib.request.urlopen(request", tunnel_probe)

        management = function_body("cloudflare_api_json")
        self.assertIn("_CLOUDFLARE_NO_REDIRECT_OPENER.open(request", management)
        self.assertNotIn("urllib.request.urlopen(request", management)

    def test_paypal_and_btcpay_use_shared_no_redirect_opener(self) -> None:
        for name in ("paypal_http_json", "btcpay_http_json"):
            with self.subTest(name=name):
                body = function_body(name, after=SOURCE.index("def paypal_base_url()"))
                self.assertIn("_PROVIDER_NO_REDIRECT_OPENER.open(req", body)
                self.assertNotIn("urllib.request.urlopen(req", body)
        monero = function_body("monero_opener", after=SOURCE.index("def paypal_base_url()"))
        self.assertIn("handlers = [_ProviderNoRedirect()]", monero)

    def test_every_production_opener_is_built_from_a_no_redirect_handler(self) -> None:
        """E2 (Claude audit, 2026-08-28): wiring, not just call sites.

        Rewriting every construction site to a bare build_opener() -- leaving
        the handler classes defined but unused and every .open() call site
        untouched -- kept this suite green, because the suite only asserted
        that _X_NO_REDIRECT_OPENER.open(...) appears. The opener must be
        BUILT from the hardened handler or the name is a lie.
        """
        import re
        sites = [m.start() for m in re.finditer(r"build_opener\(", SOURCE)]
        self.assertGreaterEqual(len(sites), 6,
                                "the expected no-redirect opener sites disappeared")
        for start in sites:
            window = SOURCE[start:start + 200]
            if "NoRedirect" in window:
                continue
            # The one sanctioned *handlers form: monero builds a per-call
            # opener whose FIRST handler is the redirect guard.
            context = SOURCE[max(0, start - 1500):start + 200]
            self.assertIn(
                "handlers = [_ProviderNoRedirect()]", context,
                "a production build_opener() is not built from a "
                "NoRedirect handler (E2): the redirect guard is defined "
                "but unused at this site")

    def test_both_loopback_admin_programs_use_no_redirect_openers(self) -> None:
        standalone = heredoc_body("<<'WINN3_SET_CARRIER_PY'", "WINN3_SET_CARRIER_PY")
        self.assertIn("_LOOPBACK_ADMIN_NO_REDIRECT_OPENER.open(req", standalone)
        self.assertNotIn("urllib.request.urlopen(req", standalone)

        admin = heredoc_body("cat > /usr/local/bin/wins-admin <<'PYEOF'", "PYEOF")
        self.assertEqual(admin.count("_ADMIN_NO_REDIRECT_OPENER.open(req"), 2)
        self.assertNotIn("urllib.request.urlopen(req", admin)

    def test_handlers_refuse_every_redirect_status_without_forwarding_secrets(self) -> None:
        for name in HANDLER_NAMES:
            for status in REDIRECT_STATUSES:
                with self.subTest(name=name, status=status):
                    captured: list[tuple[str, dict[str, str]]] = []
                    target = _serve(_capture_handler(captured))
                    source = _serve(
                        _redirect_handler(
                            status,
                            lambda _handler, port=target.server_port: (
                                f"http://127.0.0.1:{port}/capture"
                            ),
                        )
                    )
                    try:
                        opener = urllib.request.build_opener(handler_class(name))
                        with self.assertRaises(urllib.error.HTTPError) as raised:
                            _open_credentialed(
                                opener,
                                f"http://127.0.0.1:{source.server_port}/credentialed",
                            )
                        self.assertEqual(raised.exception.code, status)
                        raised.exception.close()
                        self.assertEqual(captured, [])
                    finally:
                        _stop(source)
                        _stop(target)

    def test_same_origin_redirects_and_loops_are_still_refused(self) -> None:
        for name in HANDLER_NAMES:
            for status, location in (
                (302, "/capture"),
                (307, "/credentialed"),
                (301, None),
            ):
                with self.subTest(name=name, status=status, location=location):
                    captured: list[tuple[str, dict[str, str]]] = []

                    class Combined(BaseHTTPRequestHandler):
                        def _handle(self) -> None:
                            if self.path == "/credentialed":
                                self.send_response(status)
                                if location is not None:
                                    self.send_header("Location", location)
                                self.end_headers()
                                return
                            captured.append(
                                (self.path, {k: v for k, v in self.headers.items()})
                            )
                            self.send_response(200)
                            self.end_headers()

                        do_GET = _handle
                        do_POST = _handle
                        log_message = _quiet_log

                    server = _serve(Combined)
                    try:
                        opener = urllib.request.build_opener(handler_class(name))
                        with self.assertRaises(urllib.error.HTTPError) as raised:
                            _open_credentialed(
                                opener,
                                f"http://127.0.0.1:{server.server_port}/credentialed",
                            )
                        self.assertEqual(raised.exception.code, status)
                        raised.exception.close()
                        self.assertEqual(captured, [])
                    finally:
                        _stop(server)

    def test_dns_rebinding_style_host_change_does_not_receive_secrets(self) -> None:
        captured: list[tuple[str, dict[str, str]]] = []
        target = _serve(_capture_handler(captured))
        source = _serve(
            _redirect_handler(
                302,
                lambda _handler, port=target.server_port: f"http://127.0.0.1:{port}/capture",
            )
        )
        try:
            for name in HANDLER_NAMES:
                with self.subTest(name=name):
                    opener = urllib.request.build_opener(handler_class(name))
                    with self.assertRaises(urllib.error.HTTPError) as raised:
                        _open_credentialed(
                            opener,
                            f"http://localhost:{source.server_port}/credentialed",
                        )
                    self.assertEqual(raised.exception.code, 302)
                    raised.exception.close()
            self.assertEqual(captured, [])
        finally:
            _stop(source)
            _stop(target)

    def test_malformed_and_http_downgrade_locations_never_reach_a_target(self) -> None:
        captured: list[tuple[str, dict[str, str]]] = []
        target = _serve(_capture_handler(captured))
        locations = (
            f"http://127.0.0.1:{target.server_port}/capture",
            "https://",
            "http://user:pass@127.0.0.1/capture",
        )
        try:
            for name in HANDLER_NAMES:
                for location in locations:
                    with self.subTest(name=name, location=location):
                        source = _serve(
                            _redirect_handler(302, lambda _handler, loc=location: loc)
                        )
                        try:
                            opener = urllib.request.build_opener(handler_class(name))
                            with self.assertRaises(urllib.error.HTTPError) as raised:
                                _open_credentialed(
                                    opener,
                                    f"http://127.0.0.1:{source.server_port}/credentialed",
                                )
                            self.assertEqual(raised.exception.code, 302)
                            raised.exception.close()
                        finally:
                            _stop(source)
            self.assertEqual(captured, [])
        finally:
            _stop(target)

    def test_header_names_stay_on_the_refused_source_response_only(self) -> None:
        captured: list[tuple[str, dict[str, str]]] = []
        target = _serve(_capture_handler(captured))
        source = _serve(
            _redirect_handler(
                308,
                lambda _handler, port=target.server_port: f"http://127.0.0.1:{port}/capture",
            )
        )
        try:
            opener = urllib.request.build_opener(handler_class("_CredentialedNoRedirect"))
            with self.assertRaises(urllib.error.HTTPError) as raised:
                _open_credentialed(
                    opener, f"http://127.0.0.1:{source.server_port}/credentialed"
                )
            self.assertEqual(raised.exception.code, 308)
            source_headers = {k.lower() for k in raised.exception.headers}
            raised.exception.close()
            self.assertNotIn("authorization", source_headers)
            self.assertEqual(captured, [])
        finally:
            _stop(source)
            _stop(target)


if __name__ == "__main__":
    unittest.main()
import _toolchain  # noqa: F401  (V-01 preflight)
