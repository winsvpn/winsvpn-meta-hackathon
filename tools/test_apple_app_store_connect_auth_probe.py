#!/usr/bin/env python3
"""Hostile transport tests for the App Store Connect authentication probe."""

from __future__ import annotations

import io
import hashlib
import json
import os
import pathlib
import stat
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import apple_app_store_connect_auth_probe as auth_probe


TOKEN = "header.payload.signature"


def valid_body() -> bytes:
    return json.dumps(
        {
            "data": [
                {
                    "type": "apps",
                    "id": auth_probe.EXPECTED_APP_ID,
                    "attributes": {"bundleId": auth_probe.EXPECTED_BUNDLE_ID},
                }
            ]
        },
        separators=(",", ":"),
    ).encode("ascii")


class FakeResponse:
    def __init__(
        self,
        url: str,
        status: int,
        body: bytes,
        *,
        content_type: str | None = "application/json",
        content_length: str | None = None,
    ) -> None:
        self._url = url
        self.status = status
        self._stream = io.BytesIO(body)
        self.headers: dict[str, str] = {
            "Content-Length": (
                str(len(body)) if content_length is None else content_length
            )
        }
        if content_type is not None:
            self.headers["Content-Type"] = content_type

    def geturl(self) -> str:
        return self._url

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def read1(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class RecordingOpener:
    def __init__(self, response_factory) -> None:
        self.response_factory = response_factory
        self.requests: list[tuple[urllib.request.Request, int]] = []

    def open(
        self, request: urllib.request.Request, *, timeout: int
    ) -> FakeResponse:
        self.requests.append((request, timeout))
        return self.response_factory(request)


class RedirectFixture:
    def __init__(self, status: int | None = 302) -> None:
        self.source_authorizations: list[str | None] = []
        self.target_authorizations: list[str | None] = []
        target_authorizations = self.target_authorizations

        class TargetHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                target_authorizations.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(valid_body())

            def log_message(self, *_args: object) -> None:
                return None

        self.target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
        target_url = f"http://127.0.0.1:{self.target.server_port}/capture"
        source_authorizations = self.source_authorizations

        class SourceHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                source_authorizations.append(self.headers.get("Authorization"))
                response_status = (
                    status if status is not None else int(self.path.rsplit("/", 1)[-1])
                )
                self.send_response(response_status)
                self.send_header("Location", target_url)
                self.end_headers()

            def log_message(self, *_args: object) -> None:
                return None

        self.source = ThreadingHTTPServer(("127.0.0.1", 0), SourceHandler)
        self.source_url = f"http://127.0.0.1:{self.source.server_port}/start"
        self._threads = [
            threading.Thread(target=self.target.serve_forever, daemon=True),
            threading.Thread(target=self.source.serve_forever, daemon=True),
        ]

    def __enter__(self) -> RedirectFixture:
        for thread in self._threads:
            thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.source.shutdown()
        self.target.shutdown()
        self.source.server_close()
        self.target.server_close()
        for thread in self._threads:
            thread.join(timeout=2)

    def url_for_status(self, status: int) -> str:
        return f"{self.source_url}/{status}"


class AppleAppStoreConnectAuthProbeTests(unittest.TestCase):
    @staticmethod
    def _private_key(root: pathlib.Path) -> pathlib.Path:
        path = root / "AuthKey_ABCDEFGHIJ.p8"
        path.write_bytes(b"test-private-key-material\n")
        path.chmod(0o600)
        return path

    @staticmethod
    def _fake_signer(root: pathlib.Path, body: str) -> tuple[pathlib.Path, int]:
        path = root / "reviewed-openssl"
        path.write_text("#!/bin/sh\n" + body, encoding="ascii")
        path.chmod(0o500)
        return path, os.open(path, os.O_RDONLY)

    def test_local_redirect_never_replays_authorization(self) -> None:
        with RedirectFixture(302) as fixture:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}), auth_probe._NoRedirectHandler()
            )
            request = urllib.request.Request(
                fixture.source_url,
                headers={"Authorization": f"Bearer {TOKEN}"},
            )
            with self.assertRaisesRegex(urllib.error.HTTPError, "redirect refused") as raised:
                opener.open(request, timeout=2)
            raised.exception.close()
        self.assertEqual(fixture.source_authorizations, [f"Bearer {TOKEN}"])
        self.assertEqual(fixture.target_authorizations, [])

    def test_production_opener_is_no_proxy_and_no_redirect(self) -> None:
        handlers = auth_probe._AUTHENTICATED_OPENER.handlers
        redirect_handlers = [
            handler
            for handler in handlers
            if isinstance(handler, urllib.request.HTTPRedirectHandler)
        ]
        proxy_handlers = [
            handler
            for handler in handlers
            if isinstance(handler, urllib.request.ProxyHandler)
        ]
        self.assertEqual(len(redirect_handlers), 1)
        self.assertIsInstance(redirect_handlers[0], auth_probe._NoRedirectHandler)
        self.assertEqual(proxy_handlers, [])

    def test_probe_uses_only_exact_expected_request(self) -> None:
        opener = RecordingOpener(
            lambda request: FakeResponse(request.full_url, 200, valid_body())
        )
        with mock.patch.object(auth_probe, "_AUTHENTICATED_OPENER", opener):
            auth_probe._probe_token(TOKEN)
        self.assertEqual(len(opener.requests), 1)
        request, timeout = opener.requests[0]
        self.assertEqual(request.full_url, auth_probe.EXPECTED_API_URL)
        self.assertEqual(request.get_method(), "GET")
        self.assertIsNone(request.data)
        self.assertEqual(request.get_header("Authorization"), f"Bearer {TOKEN}")
        self.assertEqual(request.get_header("Accept"), "application/json")
        self.assertEqual(timeout, auth_probe.REQUEST_TIMEOUT_SECONDS)

    def test_every_300_status_is_refused_without_retry(self) -> None:
        with RedirectFixture(None) as fixture:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}), auth_probe._NoRedirectHandler()
            )
            for status in range(300, 400):
                with self.subTest(status=status):
                    request = urllib.request.Request(
                        fixture.url_for_status(status),
                        headers={"Authorization": f"Bearer {TOKEN}"},
                    )
                    with self.assertRaises(urllib.error.HTTPError) as raised:
                        opener.open(request, timeout=2)
                    raised.exception.close()
        self.assertEqual(
            fixture.source_authorizations, [f"Bearer {TOKEN}"] * 100
        )
        self.assertEqual(fixture.target_authorizations, [])

    def test_response_url_drift_is_rejected(self) -> None:
        expected = auth_probe.EXPECTED_API_URL
        drifted = [
            expected.replace("https://", "http://", 1),
            expected.replace("api.appstoreconnect.apple.com", "example.invalid", 1),
            expected.replace(".com/", ".com:443/", 1),
            expected.replace("/v1/apps", "/v1/users", 1),
            expected.replace("limit=1", "limit=2", 1),
        ]
        for response_url in drifted:
            with self.subTest(response_url=response_url):
                opener = RecordingOpener(
                    lambda _request, url=response_url: FakeResponse(
                        url, 200, valid_body()
                    )
                )
                with mock.patch.object(auth_probe, "_AUTHENTICATED_OPENER", opener):
                    with self.assertRaisesRegex(
                        auth_probe.ProbeError, "response URL differs"
                    ):
                        auth_probe._probe_token(TOKEN)

    def test_http_error_url_drift_is_rejected(self) -> None:
        def drifted_error(_request: urllib.request.Request) -> FakeResponse:
            raise urllib.error.HTTPError(
                auth_probe.EXPECTED_API_URL + "&drift=1",
                401,
                "Unauthorized",
                {},
                io.BytesIO(),
            )

        opener = RecordingOpener(drifted_error)
        with mock.patch.object(auth_probe, "_AUTHENTICATED_OPENER", opener):
            with self.assertRaisesRegex(auth_probe.ProbeError, "error URL differs"):
                auth_probe._probe_token(TOKEN)

    def test_status_and_content_type_are_strict(self) -> None:
        wrong_status = RecordingOpener(
            lambda request: FakeResponse(request.full_url, 201, valid_body())
        )
        with mock.patch.object(auth_probe, "_AUTHENTICATED_OPENER", wrong_status):
            with self.assertRaisesRegex(auth_probe.ProbeError, "HTTP 201"):
                auth_probe._probe_token(TOKEN)
        wrong_type = RecordingOpener(
            lambda request: FakeResponse(
                request.full_url, 200, valid_body(), content_type="text/html"
            )
        )
        with mock.patch.object(auth_probe, "_AUTHENTICATED_OPENER", wrong_type):
            with self.assertRaisesRegex(auth_probe.ProbeError, "non-JSON content type"):
                auth_probe._probe_token(TOKEN)

    def test_response_size_and_length_are_bounded(self) -> None:
        oversized_body = b"x" * (auth_probe.MAX_RESPONSE_BYTES + 1)
        oversized = RecordingOpener(
            lambda request: FakeResponse(request.full_url, 200, oversized_body)
        )
        with mock.patch.object(auth_probe, "_AUTHENTICATED_OPENER", oversized):
            with self.assertRaisesRegex(auth_probe.ProbeError, "safety limit"):
                auth_probe._probe_token(TOKEN)
        body = valid_body()
        mismatched = RecordingOpener(
            lambda request: FakeResponse(
                request.full_url,
                200,
                body,
                content_length=str(len(body) + 1),
            )
        )
        with mock.patch.object(auth_probe, "_AUTHENTICATED_OPENER", mismatched):
            with self.assertRaisesRegex(auth_probe.ProbeError, "does not match"):
                auth_probe._probe_token(TOKEN)

    def test_duplicate_nonfinite_and_malformed_json_are_rejected(self) -> None:
        hostile = [
            b'{"data":[],"data":[]}',
            b'{"data":[{"type":"apps","id":"6789417002","attributes":{"bundleId":"org.winsvpn.app","score":NaN}}]}',
            b'{"data":',
            b"\xff",
        ]
        for body in hostile:
            with self.subTest(body=body):
                opener = RecordingOpener(
                    lambda request, value=body: FakeResponse(
                        request.full_url, 200, value
                    )
                )
                with mock.patch.object(auth_probe, "_AUTHENTICATED_OPENER", opener):
                    with self.assertRaises(auth_probe.ProbeError):
                        auth_probe._probe_token(TOKEN)

    def test_exact_app_identity_is_required(self) -> None:
        hostile = [
            {"data": []},
            {
                "data": [
                    {
                        "type": "apps",
                        "id": auth_probe.EXPECTED_APP_ID,
                        "attributes": {"bundleId": auth_probe.EXPECTED_BUNDLE_ID},
                    },
                    {
                        "type": "apps",
                        "id": "other",
                        "attributes": {"bundleId": "other"},
                    },
                ]
            },
            {
                "data": [
                    {
                        "type": "users",
                        "id": auth_probe.EXPECTED_APP_ID,
                        "attributes": {"bundleId": auth_probe.EXPECTED_BUNDLE_ID},
                    }
                ]
            },
            {
                "data": [
                    {
                        "type": "apps",
                        "id": "other",
                        "attributes": {"bundleId": auth_probe.EXPECTED_BUNDLE_ID},
                    }
                ]
            },
            {
                "data": [
                    {
                        "type": "apps",
                        "id": auth_probe.EXPECTED_APP_ID,
                        "attributes": {"bundleId": "other"},
                    }
                ]
            },
        ]
        for payload in hostile:
            with self.subTest(payload=payload):
                body = json.dumps(payload, separators=(",", ":")).encode("ascii")
                opener = RecordingOpener(
                    lambda request, value=body: FakeResponse(
                        request.full_url, 200, value
                    )
                )
                with mock.patch.object(auth_probe, "_AUTHENTICATED_OPENER", opener):
                    with self.assertRaises(auth_probe.ProbeError):
                        auth_probe._probe_token(TOKEN)

    def test_token_and_expected_url_drift_fail_before_open(self) -> None:
        for token in ("", "token", "a.b.c\r\nX: stolen", "a b.c.d"):
            with self.subTest(token=token):
                with self.assertRaises(auth_probe.ProbeError):
                    auth_probe._probe_token(token)
        opener = RecordingOpener(
            lambda request: FakeResponse(request.full_url, 200, valid_body())
        )
        with mock.patch.object(auth_probe, "_AUTHENTICATED_OPENER", opener), mock.patch.object(
            auth_probe,
            "EXPECTED_API_URL",
            "https://example.invalid/v1/apps?filter%5BbundleId%5D=org.winsvpn.app&limit=1",
        ):
            with self.assertRaisesRegex(auth_probe.ProbeError, "noncanonical"):
                auth_probe._probe_token(TOKEN)
        self.assertEqual(opener.requests, [])

    def test_private_key_rejects_symlink_and_hardlink(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as name:
            root = pathlib.Path(name)
            key = self._private_key(root)
            link = root / "linked.p8"
            link.symlink_to(key.name)
            with self.assertRaisesRegex(auth_probe.ProbeError, "symlink"):
                auth_probe.require_private_external_key(str(link))
            hardlink = root / "hardlinked.p8"
            os.link(key, hardlink)
            with self.assertRaisesRegex(auth_probe.ProbeError, "regular file"):
                auth_probe.require_private_external_key(str(key))

    def test_private_key_is_anonymous_and_replacement_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as name:
            root = pathlib.Path(name)
            key = self._private_key(root)
            original = key.read_bytes()
            with self.assertRaisesRegex(auth_probe.ProbeError, "changed during signing"):
                with auth_probe._held_private_key(key) as custody:
                    held_descriptor = custody[0]
                    self.assertEqual(
                        os.pread(held_descriptor, len(original), 0), original
                    )
                    self.assertFalse(any(path.name == "key" for path in pathlib.Path(name).rglob("key")))
                    replacement = root / "replacement"
                    replacement.write_bytes(b"substitute\n")
                    replacement.chmod(0o600)
                    os.replace(replacement, key)

    def test_signer_uses_exact_path_fd_key_and_scrubbed_environment(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as name:
            root = pathlib.Path(name)
            key = self._private_key(root)
            key_descriptor = os.open(key, os.O_RDONLY)
            signer, signer_descriptor = self._fake_signer(
                root,
                "[ \"$OPENSSL_CONF\" = /dev/null ] || exit 31\n"
                "[ -z \"$DYLD_INSERT_LIBRARIES\" ] || exit 32\n"
                "[ -z \"$PYTHONPATH\" ] || exit 33\n"
                "case \"$4\" in /dev/fd/*) ;; *) exit 34 ;; esac\n"
                "IFS= read -r payload || [ -n \"$payload\" ] || exit 35\n"
                "printf '\\060\\006\\002\\001\\001\\002\\001\\002'\n",
            )
            try:
                with mock.patch.dict(
                    os.environ,
                    {
                        "PATH": str(root),
                        "OPENSSL_CONF": str(root / "hostile.cnf"),
                        "DYLD_INSERT_LIBRARIES": str(root / "hostile.dylib"),
                        "PYTHONPATH": str(root),
                    },
                    clear=False,
                ):
                    signature = auth_probe._sign_with_openssl(
                        signer, signer_descriptor, key_descriptor, b"message"
                    )
            finally:
                os.close(signer_descriptor)
                os.close(key_descriptor)
            self.assertEqual(signature, b"\x30\x06\x02\x01\x01\x02\x01\x02")

    def test_signer_bounds_output_and_timeout(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as name:
            root = pathlib.Path(name)
            key = self._private_key(root)
            key_descriptor = os.open(key, os.O_RDONLY)
            noisy, noisy_descriptor = self._fake_signer(
                root,
                "IFS= read -r payload || [ -n \"$payload\" ] || exit 35\n"
                "i=0; while [ \"$i\" -lt 9000 ]; do printf x; i=$((i+1)); done\n",
            )
            try:
                with self.assertRaisesRegex(auth_probe.ProbeError, "stdout exceeded"):
                    auth_probe._sign_with_openssl(
                        noisy, noisy_descriptor, key_descriptor, b"message"
                    )
            finally:
                os.close(noisy_descriptor)
                noisy.unlink()
            hung, hung_descriptor = self._fake_signer(
                root,
                "IFS= read -r payload || [ -n \"$payload\" ] || exit 35\n"
                "while :; do :; done\n",
            )
            try:
                with mock.patch.object(auth_probe, "SIGN_TIMEOUT_SECONDS", 1):
                    with self.assertRaisesRegex(auth_probe.ProbeError, "time bound"):
                        auth_probe._sign_with_openssl(
                            hung, hung_descriptor, key_descriptor, b"message"
                        )
            finally:
                os.close(hung_descriptor)
                os.close(key_descriptor)

    def test_signer_no_fork_boundary_blocks_setsid_descendant(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as name:
            root = pathlib.Path(name)
            marker = root / "escaped"
            key = self._private_key(root)
            key_descriptor = os.open(key, os.O_RDONLY)
            signer = root / "reviewed-openssl-python"
            signer.write_text(
                f"#!{sys.executable}\n"
                "import os, pathlib, sys, time\n"
                "try:\n"
                "    child = os.fork()\n"
                "except OSError:\n"
                "    child = -1\n"
                "if child == 0:\n"
                "    os.setsid(); time.sleep(1); "
                f"pathlib.Path({str(marker)!r}).write_text('escaped'); os._exit(0)\n"
                "sys.stdin.buffer.read()\n"
                "sys.stdout.buffer.write(b'\\x30\\x06\\x02\\x01\\x01\\x02\\x01\\x02')\n",
                encoding="ascii",
            )
            signer.chmod(0o500)
            signer_descriptor = os.open(signer, os.O_RDONLY)
            try:
                with self.assertRaises(auth_probe.ProbeError):
                    auth_probe._sign_with_openssl(
                        signer, signer_descriptor, key_descriptor, b"message"
                    )
            finally:
                os.close(signer_descriptor)
                os.close(key_descriptor)
            time.sleep(1.2)
            self.assertFalse(marker.exists())

    def test_signer_stdin_write_uses_the_absolute_deadline(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as name:
            root = pathlib.Path(name)
            key = self._private_key(root)
            key_descriptor = os.open(key, os.O_RDONLY)
            signer, signer_descriptor = self._fake_signer(
                root,
                "while :; do :; done\n",
            )
            started = time.monotonic()
            try:
                with (
                    mock.patch.object(auth_probe, "SIGN_TIMEOUT_SECONDS", 1),
                    mock.patch.object(auth_probe, "SIGN_INPUT_LIMIT_BYTES", 2_000_000),
                ):
                    with self.assertRaisesRegex(auth_probe.ProbeError, "time bound"):
                        auth_probe._sign_with_openssl(
                            signer,
                            signer_descriptor,
                            key_descriptor,
                            b"x" * 1_000_000,
                        )
            finally:
                os.close(signer_descriptor)
                os.close(key_descriptor)
            self.assertLess(time.monotonic() - started, 2.5)

    def test_response_body_uses_one_absolute_deadline(self) -> None:
        class SlowResponse(FakeResponse):
            def read1(self, size: int = -1) -> bytes:
                time.sleep(0.05)
                return super().read1(size)

        opener = RecordingOpener(
            lambda request: SlowResponse(request.full_url, 200, valid_body())
        )
        with (
            mock.patch.object(auth_probe, "_AUTHENTICATED_OPENER", opener),
            mock.patch.object(auth_probe, "REQUEST_TIMEOUT_SECONDS", 0.01),
        ):
            with self.assertRaisesRegex(auth_probe.ProbeError, "absolute deadline"):
                auth_probe._probe_token(TOKEN)

    def test_unreviewed_openssl_environment_is_owner_blocked(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "WINS_RELEASE_OPENSSL_RUNTIME": "/private/tmp/fake",
                "WINS_RELEASE_OPENSSL_RUNTIME_ID": "fake",
                "WINS_RELEASE_OPENSSL_ROOT": "/private/tmp/fake/openssl",
                "WINS_RELEASE_OPENSSL_TREE_SHA256": "0" * 64,
                "WINS_RELEASE_OPENSSL": "/private/tmp/fake/openssl/bin/openssl",
                "WINS_RELEASE_OPENSSL_SHA256": "0" * 64,
            },
            clear=False,
        ):
            with self.assertRaisesRegex(auth_probe.ProbeError, "authenticated OpenSSL"):
                with auth_probe._held_reviewed_openssl():
                    self.fail("unreviewed OpenSSL was accepted")

    def test_reviewed_openssl_is_privately_held_and_source_swap_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as name:
            runtime = pathlib.Path(name) / "runtime"
            openssl_root = runtime / "extracted/openssl"
            binary = openssl_root / "bin/openssl"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"authenticated-openssl")
            binary.chmod(0o500)
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            environment = {
                "WINS_RELEASE_OPENSSL_RUNTIME": str(runtime),
                "WINS_RELEASE_OPENSSL_RUNTIME_ID": "test-runtime-id",
                "WINS_RELEASE_OPENSSL_ROOT": str(openssl_root),
                "WINS_RELEASE_OPENSSL_TREE_SHA256": "a" * 64,
                "WINS_RELEASE_OPENSSL": str(binary),
                "WINS_RELEASE_OPENSSL_SHA256": digest,
            }
            with (
                mock.patch.dict(os.environ, environment, clear=False),
                mock.patch.object(auth_probe, "OPENSSL_TREE_SHA256", "a" * 64),
                mock.patch.object(auth_probe, "OPENSSL_EXECUTABLE_SHA256", digest),
                mock.patch.object(
                    auth_probe,
                    "_load_openssl_custody_controller",
                    return_value={"verify": lambda _arguments: None},
                ),
            ):
                with self.assertRaisesRegex(
                    auth_probe.ProbeError, "binary changed during signing"
                ):
                    with auth_probe._held_reviewed_openssl() as custody:
                        self.assertEqual(
                            custody[0].read_bytes(), b"authenticated-openssl"
                        )
                        replacement = binary.with_name("replacement")
                        replacement.write_bytes(b"substituted-openssl")
                        replacement.chmod(0o500)
                        os.replace(replacement, binary)


if __name__ == "__main__":
    unittest.main(verbosity=2)
