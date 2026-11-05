#!/usr/bin/env python3
"""Offline regressions for Site AI redirect and endpoint hardening.

The executable checks load the real hub ``main.py`` heredoc from the control-plane
installer.  Every transport is replaced with an in-memory fake, so this suite
cannot contact Gemini, Vertex, OAuth, or the local Site AI service.
"""

from __future__ import annotations

import _toolchain  # noqa: F401  (V-01 preflight)
import ast
import json
import sys
import types
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import test_account_deletion_hub as harness


class FakeResponse:
    def __init__(self, payload: dict[str, object]):
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return self._body


class RecordingOpener:
    def __init__(self, responses: list[dict[str, object]] | None = None):
        self.responses = list(responses or [])
        self.calls: list[tuple[object, float]] = []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        if not self.responses:
            raise AssertionError("unexpected Site AI transport call")
        return FakeResponse(self.responses.pop(0))


def load_site_hub(**env):
    defaults = {
        "SITE_AI_API_KEY": "site-ai-test-key",
        "SITE_AI_MODEL": "gemini-test-model",
        "SITE_AI_VERTEX_ENABLED": "1",
        "SITE_AI_VERTEX_PROJECT": "test-project",
        "SITE_AI_VERTEX_CREDENTIALS_PATH": "/nonexistent/site-ai-test-credentials.json",
        "SITE_AI_VERTEX_LOCATION": "us-central1",
        "SITE_AI_VERTEX_MODEL": "vertex-test-model",
        "SITE_AI_LOCAL_ENDPOINT": "http://127.0.0.1:11434",
        "SITE_AI_LOCAL_MODEL": "local-test-model",
    }
    defaults.update(env)
    return harness.load_hub(**defaults)


def function_source(name: str) -> str:
    source = harness._extract_main_block()
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == name:
            segment = ast.get_source_segment(source, node)
            assert segment is not None
            return segment
    raise AssertionError(f"missing {name} in extracted hub heredoc")


def called_names(source: str) -> set[str]:
    tree = ast.parse(source)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                names.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                names.add(node.func.attr)
    return names


def test_static_all_site_ai_http_paths_use_the_no_redirect_transport():
    for name in (
        "site_gemini_answer",
        "site_vertex_answer",
        "site_local_llm_answer",
        "_site_vertex_bearer_token",
    ):
        source = function_source(name)
        assert "_site_ai_open" in called_names(source), name
        assert "urlopen" not in called_names(source), name

    open_source = function_source("_site_ai_open")
    assert "_SITE_AI_NO_REDIRECT_OPENER.open" in open_source
    handler_source = function_source("_SiteAiNoRedirect")
    assert "return None" in handler_source



def test_static_every_build_opener_site_binds_a_no_redirect_handler():
    """E2 (Claude audit, 2026-08-28): construction wiring, not call sites.

    A bare build_opener() at any construction site -- handler classes left
    defined but unused, call sites untouched -- satisfied every other
    static assertion in this suite. Each production opener must be BUILT
    from a NoRedirect handler.
    """
    import re as _re
    source = harness._extract_main_block()
    sites = [m.start() for m in _re.finditer(r"build_opener\(", source)]
    assert len(sites) >= 1, "expected at least one build_opener site"
    for start in sites:
        window = source[start:start + 200]
        if "NoRedirect" in window:
            continue
        context = source[max(0, start - 1500):start + 200]
        assert "handlers = [_ProviderNoRedirect()]" in context, (
            "a production build_opener() is not built from a NoRedirect "
            "handler (E2): the redirect guard is defined but unused here")

def test_static_google_auth_refresh_and_manual_oauth_guards_are_present():
    source = function_source("_site_vertex_bearer_token")
    tree = ast.parse(source)
    assert "kwargs[\"allow_redirects\"] = False" in source
    assert "creds.refresh(_ga_request(session=session))" in source
    assert "oauth2.googleapis.com" in source
    assert "token_target.path != \"/token\"" in source
    assert "token_target.port not in {None, 443}" in source
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_site_ai_open"
        for node in ast.walk(tree)
    )


def test_no_redirect_handler_rejects_redirects_and_open_uses_only_bound_opener():
    mod = load_site_hub()
    handler = mod._SiteAiNoRedirect()
    for status in (301, 302, 303, 307, 308):
        assert handler.redirect_request(
            None, None, status, "moved", {}, "https://attacker.test/"
        ) is None

    opener = RecordingOpener([{"ok": True}])
    mod._SITE_AI_NO_REDIRECT_OPENER = opener
    request = mod.urllib.request.Request("https://example.invalid/")
    with mod._site_ai_open(request, timeout=3.5) as response:
        assert json.loads(response.read()) == {"ok": True}
    assert opener.calls == [(request, 3.5)]


def test_gemini_vertex_and_local_generation_use_no_redirect_opener():
    mod = load_site_hub()
    opener = RecordingOpener(
        [
            {"candidates": [{"content": {"parts": [{"text": "gemini"}]}}]},
            {"candidates": [{"content": {"parts": [{"text": "vertex"}]}}]},
            {"message": {"content": "local"}},
        ]
    )
    mod._SITE_AI_NO_REDIRECT_OPENER = opener
    mod._site_vertex_bearer_token = lambda: "vertex-test-token"

    assert mod.site_gemini_answer("hello", "en", []) == "gemini"
    assert mod.site_vertex_answer("hello", "en", []) == "vertex"
    assert mod.site_local_llm_answer("hello", "en", []) == "local"

    urls = [request.full_url for request, _timeout in opener.calls]
    assert urls[0].startswith("https://generativelanguage.googleapis.com/")
    assert urls[1].startswith("https://us-central1-aiplatform.googleapis.com/")
    assert urls[2] == "http://127.0.0.1:11434/api/chat"
    assert [timeout for _request, timeout in opener.calls] == [20, mod.SITE_AI_VERTEX_TIMEOUT, mod.SITE_AI_LOCAL_TIMEOUT]


def _install_google_auth_fakes(monkeypatch, observed: dict[str, object]):
    google = types.ModuleType("google")
    oauth2 = types.ModuleType("google.oauth2")
    service_account = types.ModuleType("google.oauth2.service_account")
    auth = types.ModuleType("google.auth")
    transport = types.ModuleType("google.auth.transport")
    transport_requests = types.ModuleType("google.auth.transport.requests")
    requests = types.ModuleType("requests")

    class Session:
        def request(self, method, url, **kwargs):
            observed["request"] = (method, url, kwargs)
            if kwargs.get("allow_redirects") is not False:
                raise AssertionError("Google auth refresh could follow a redirect")
            raise urllib.error.HTTPError(url, 302, "redirect refused", {}, None)

        def close(self):
            observed["closed"] = True

    class TransportRequest:
        def __init__(self, session):
            self.session = session

    class Credentials:
        token = None

        @classmethod
        def from_service_account_file(cls, path, scopes):
            observed["credentials"] = (path, scopes)
            return cls()

        def refresh(self, request):
            request.session.request("POST", "https://oauth2.googleapis.com/token")

    requests.Session = Session
    transport_requests.Request = TransportRequest
    service_account.Credentials = Credentials
    google.oauth2 = oauth2
    oauth2.service_account = service_account
    google.auth = auth
    auth.transport = transport
    transport.requests = transport_requests

    for name, module in {
        "google": google,
        "google.oauth2": oauth2,
        "google.oauth2.service_account": service_account,
        "google.auth": auth,
        "google.auth.transport": transport,
        "google.auth.transport.requests": transport_requests,
        "requests": requests,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)


def test_google_auth_refresh_session_cannot_follow_redirects(tmp_path, monkeypatch):
    creds_path = tmp_path / "vertex.json"
    creds_path.write_text("{}", encoding="utf-8")
    mod = load_site_hub(SITE_AI_VERTEX_CREDENTIALS_PATH=str(creds_path))
    mod._SITE_VERTEX_TOKEN_CACHE = {"token": None, "expiry": 0.0}
    observed: dict[str, object] = {}
    _install_google_auth_fakes(monkeypatch, observed)

    # The fake refresh emits a redirect response. The hardened session refuses it,
    # then the deliberately incomplete JSON makes the manual fallback return None.
    assert mod._site_vertex_bearer_token() is None
    method, url, kwargs = observed["request"]
    assert (method, url) == ("POST", "https://oauth2.googleapis.com/token")
    assert kwargs["allow_redirects"] is False
    assert observed["closed"] is True


def _force_manual_oauth(monkeypatch):
    google = types.ModuleType("google")
    oauth2 = types.ModuleType("google.oauth2")
    service_account = types.ModuleType("google.oauth2.service_account")

    class Credentials:
        @classmethod
        def from_service_account_file(cls, path, scopes):
            raise RuntimeError("force manual token exchange")

    service_account.Credentials = Credentials
    google.oauth2 = oauth2
    oauth2.service_account = service_account
    monkeypatch.setitem(sys.modules, "google", google)
    monkeypatch.setitem(sys.modules, "google.oauth2", oauth2)
    monkeypatch.setitem(sys.modules, "google.oauth2.service_account", service_account)

    jwt = types.ModuleType("jwt")
    jwt.encode = lambda *args, **kwargs: "signed-test-assertion"
    monkeypatch.setitem(sys.modules, "jwt", jwt)


@pytest.mark.parametrize(
    "token_uri",
    [
        "http://oauth2.googleapis.com/token",
        "https://example.com/token",
        "https://oauth2.googleapis.com/other",
        "https://user@oauth2.googleapis.com/token",
        "https://oauth2.googleapis.com:444/token",
        "https://oauth2.googleapis.com/token?next=1",
        "https://oauth2.googleapis.com/token#fragment",
    ],
)
def test_manual_oauth_rejects_every_unapproved_token_uri(tmp_path, monkeypatch, token_uri):
    creds_path = tmp_path / "vertex.json"
    creds_path.write_text(
        json.dumps({"client_email": "test@example.invalid", "private_key": "invalid-test-key", "token_uri": token_uri}),
        encoding="utf-8",
    )
    mod = load_site_hub(SITE_AI_VERTEX_CREDENTIALS_PATH=str(creds_path))
    mod._SITE_VERTEX_TOKEN_CACHE = {"token": None, "expiry": 0.0}
    _force_manual_oauth(monkeypatch)
    opener = RecordingOpener()
    mod._SITE_AI_NO_REDIRECT_OPENER = opener

    assert mod._site_vertex_bearer_token() is None
    assert opener.calls == []


@pytest.mark.parametrize(
    ("token_uri", "expected_url"),
    [
        ("https://oauth2.googleapis.com/token", "https://oauth2.googleapis.com/token"),
        ("https://oauth2.googleapis.com:443/token", "https://oauth2.googleapis.com:443/token"),
    ],
)
def test_manual_oauth_approved_endpoint_uses_no_redirect_opener(
    tmp_path, monkeypatch, token_uri, expected_url
):
    creds_path = tmp_path / "vertex.json"
    creds_path.write_text(
        json.dumps({"client_email": "test@example.invalid", "private_key": "invalid-test-key", "token_uri": token_uri}),
        encoding="utf-8",
    )
    mod = load_site_hub(SITE_AI_VERTEX_CREDENTIALS_PATH=str(creds_path))
    mod._SITE_VERTEX_TOKEN_CACHE = {"token": None, "expiry": 0.0}
    _force_manual_oauth(monkeypatch)
    opener = RecordingOpener([{"access_token": "manual-oauth-token"}])
    mod._SITE_AI_NO_REDIRECT_OPENER = opener

    assert mod._site_vertex_bearer_token() == "manual-oauth-token"
    assert len(opener.calls) == 1
    request, timeout = opener.calls[0]
    assert request.full_url == expected_url
    assert timeout == 10


@pytest.mark.parametrize(
    ("endpoint", "expected"),
    [
        ("http://127.0.0.1:11434", "http://127.0.0.1:11434/api/chat"),
        ("http://localhost:8002/", "http://localhost:8002/api/chat"),
        ("http://[::1]:65535", "http://[::1]:65535/api/chat"),
    ],
)
def test_local_endpoint_accepts_only_explicit_loopback_http_origin(endpoint, expected):
    mod = load_site_hub(SITE_AI_LOCAL_ENDPOINT=endpoint)
    assert mod._site_ai_local_url() == expected


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://127.0.0.1:11434",
        "http://192.168.1.10:11434",
        "http://example.com:11434",
        "http://user@127.0.0.1:11434",
        "http://user:pass@localhost:11434",
        "http://127.0.0.1:11434/?query=1",
        "http://127.0.0.1:11434/#fragment",
        "http://127.0.0.1:11434/v1/chat",
        "http://127.0.0.1",
        "http://127.0.0.1:0",
        "http://127.0.0.1:65536",
        "http://127.0.0.1:not-a-port",
    ],
)
def test_local_endpoint_rejects_non_loopback_credentials_query_fragment_port_and_path(endpoint):
    mod = load_site_hub(SITE_AI_LOCAL_ENDPOINT=endpoint)
    assert mod._site_ai_local_url() is None


def _quiet_log(self, *_args) -> None:
    return None


def _serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    server._wins_thread = thread
    return server


def _stop(server) -> None:
    server.shutdown()
    server.server_close()
    thread = getattr(server, "_wins_thread", None)
    if thread is not None:
        thread.join(timeout=5)


def _site_ai_opener(mod):
    return urllib.request.build_opener(mod._SiteAiNoRedirect)


def _credentialed_site_ai_request(url: str) -> urllib.request.Request:
    return urllib.request.Request(
        url,
        data=b'{"contents":[]}',
        method="POST",
        headers={
            "Authorization": "Bearer synthetic-site-ai-token",
            "X-Wins-Activation": "synthetic-activation",
            "Content-Type": "application/json",
        },
    )


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_site_ai_handler_refuses_cross_origin_redirects_without_forwarding_secrets(status):
    mod = load_site_hub()
    captured: list[tuple[str, dict[str, str]]] = []

    class Target(BaseHTTPRequestHandler):
        def _capture(self) -> None:
            captured.append((self.path, {k: v for k, v in self.headers.items()}))
            self.send_response(200)
            self.end_headers()

        do_GET = _capture
        do_POST = _capture
        log_message = _quiet_log

    class Redirect(BaseHTTPRequestHandler):
        def _redirect(self) -> None:
            self.send_response(status)
            self.send_header("Location", f"http://127.0.0.1:{target.server_port}/stolen")
            self.end_headers()

        do_GET = _redirect
        do_POST = _redirect
        log_message = _quiet_log

    target = _serve(Target)
    source = _serve(Redirect)
    try:
        opener = _site_ai_opener(mod)
        request = _credentialed_site_ai_request(
            f"http://127.0.0.1:{source.server_port}/v1/generate"
        )
        with pytest.raises(urllib.error.HTTPError) as raised:
            opener.open(request, timeout=5)
        assert raised.value.code == status
        raised.value.close()
        assert captured == []
    finally:
        _stop(source)
        _stop(target)


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("location", ["/stolen", "/v1/generate", None])
def test_site_ai_handler_refuses_same_origin_redirects_loops_and_missing_location(status, location):
    mod = load_site_hub()
    captured: list[tuple[str, dict[str, str]]] = []

    class Combined(BaseHTTPRequestHandler):
        def _handle(self) -> None:
            if self.path == "/v1/generate":
                self.send_response(status)
                if location is not None:
                    self.send_header("Location", location)
                self.end_headers()
                return
            captured.append((self.path, {k: v for k, v in self.headers.items()}))
            self.send_response(200)
            self.end_headers()

        do_GET = _handle
        do_POST = _handle
        log_message = _quiet_log

    server = _serve(Combined)
    try:
        opener = _site_ai_opener(mod)
        request = _credentialed_site_ai_request(
            f"http://127.0.0.1:{server.server_port}/v1/generate"
        )
        with pytest.raises(urllib.error.HTTPError) as raised:
            opener.open(request, timeout=5)
        assert raised.value.code == status
        raised.value.close()
        assert captured == []
    finally:
        _stop(server)


def test_site_ai_handler_refuses_dns_rebinding_host_change_and_malformed_location():
    mod = load_site_hub()
    captured: list[tuple[str, dict[str, str]]] = []

    class Target(BaseHTTPRequestHandler):
        def _capture(self) -> None:
            captured.append((self.path, {k: v for k, v in self.headers.items()}))
            self.send_response(200)
            self.end_headers()

        do_GET = _capture
        do_POST = _capture
        log_message = _quiet_log

    target = _serve(Target)
    locations = (
        f"http://127.0.0.1:{target.server_port}/stolen",
        "https://",
        "http://user:pass@127.0.0.1/stolen",
    )
    try:
        for location in locations:
            class Redirect(BaseHTTPRequestHandler):
                def _redirect(self) -> None:
                    self.send_response(302)
                    self.send_header("Location", location)
                    self.end_headers()

                do_GET = _redirect
                do_POST = _redirect
                log_message = _quiet_log

            source = _serve(Redirect)
            try:
                opener = _site_ai_opener(mod)
                request = _credentialed_site_ai_request(
                    f"http://localhost:{source.server_port}/v1/generate"
                )
                with pytest.raises(urllib.error.HTTPError) as raised:
                    opener.open(request, timeout=5)
                assert raised.value.code == 302
                raised.value.close()
            finally:
                _stop(source)
        assert captured == []
    finally:
        _stop(target)


def test_site_ai_open_uses_handler_that_never_forwards_secrets_across_redirects():
    mod = load_site_hub()
    captured: list[tuple[str, dict[str, str]]] = []

    class Target(BaseHTTPRequestHandler):
        def _capture(self) -> None:
            captured.append((self.path, {k: v for k, v in self.headers.items()}))
            self.send_response(200)
            self.end_headers()

        do_GET = _capture
        do_POST = _capture
        log_message = _quiet_log

    class Redirect(BaseHTTPRequestHandler):
        def _redirect(self) -> None:
            self.send_response(303)
            self.send_header("Location", f"http://127.0.0.1:{target.server_port}/stolen")
            self.end_headers()

        do_GET = _redirect
        do_POST = _redirect
        log_message = _quiet_log

    target = _serve(Target)
    source = _serve(Redirect)
    try:
        opener = urllib.request.build_opener(mod._SiteAiNoRedirect)
        mod._SITE_AI_NO_REDIRECT_OPENER = opener
        request = _credentialed_site_ai_request(
            f"http://127.0.0.1:{source.server_port}/v1/generate"
        )
        with pytest.raises(urllib.error.HTTPError) as raised:
            mod._site_ai_open(request, timeout=5)
        assert raised.value.code == 303
        raised.value.close()
        assert captured == []
    finally:
        _stop(source)
        _stop(target)
