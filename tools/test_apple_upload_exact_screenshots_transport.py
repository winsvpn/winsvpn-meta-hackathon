#!/usr/bin/env python3
"""Hostile tests for exact Apple screenshot binary-upload transport."""

from __future__ import annotations

import io
import pathlib
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import apple_upload_exact_screenshots as uploader


PART = b"exact-screenshot-part"
UPLOAD_URL = (
    "https://dynamic-991.blobstore.apple.com/assets/upload.png"
    "?uploadId=test&partNumber=1"
)


class FakeResponse:
    def __init__(
        self,
        url: str,
        status: int = 200,
        body: bytes = b"",
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._url = url
        self.status = status
        self._stream = io.BytesIO(body)
        self.headers = (
            {"Content-Length": str(len(body))}
            if headers is None
            else headers
        )

    def geturl(self) -> str:
        return self._url

    def read(self, size: int = -1) -> bytes:
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


def operation(
    *,
    url: str = UPLOAD_URL,
    method: str = "PUT",
    headers: dict[str, str] | None = None,
    length: int = len(PART),
) -> dict[str, object]:
    return {
        "method": method,
        "url": url,
        "offset": 0,
        "length": length,
        "headers": {"Content-Type": "image/png"} if headers is None else headers,
    }


def reservation(
    *,
    url: str = UPLOAD_URL,
    request_headers: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    return {
        "attributes": {
            "uploadOperations": [
                {
                    "method": "PUT",
                    "url": url,
                    "offset": 0,
                    "length": len(PART),
                    "requestHeaders": (
                        [{"name": "Content-Type", "value": "image/png"}]
                        if request_headers is None
                        else request_headers
                    ),
                }
            ]
        }
    }


class RedirectFixture:
    def __init__(self) -> None:
        self.source_bodies: list[bytes] = []
        self.source_markers: list[str | None] = []
        self.source_authorizations: list[str | None] = []
        self.target_requests: list[tuple[str, bytes, str | None, str | None]] = []
        target_requests = self.target_requests

        class TargetHandler(BaseHTTPRequestHandler):
            def _capture(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                target_requests.append(
                    (
                        self.command,
                        body,
                        self.headers.get("X-Upload-Probe"),
                        self.headers.get("Authorization"),
                    )
                )
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_GET = _capture
            do_POST = _capture
            do_PUT = _capture

            def log_message(self, *_args: object) -> None:
                return None

        self.target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
        target_url = f"http://127.0.0.1:{self.target.server_port}/capture"
        source_bodies = self.source_bodies
        source_markers = self.source_markers
        source_authorizations = self.source_authorizations

        class SourceHandler(BaseHTTPRequestHandler):
            def do_PUT(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                source_bodies.append(self.rfile.read(length))
                source_markers.append(self.headers.get("X-Upload-Probe"))
                source_authorizations.append(self.headers.get("Authorization"))
                status = int(self.path.rsplit("/", 1)[-1])
                self.send_response(status)
                self.send_header("Location", target_url)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_args: object) -> None:
                return None

        self.source = ThreadingHTTPServer(("127.0.0.1", 0), SourceHandler)
        self.source_base = f"http://127.0.0.1:{self.source.server_port}/status"
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
        return f"{self.source_base}/{status}"


class AppleScreenshotUploadTransportTests(unittest.TestCase):
    def test_every_redirect_status_never_replays_authorization_or_body(self) -> None:
        with RedirectFixture() as fixture:
            for status in range(300, 400):
                with self.subTest(status=status):
                    request = urllib.request.Request(
                        fixture.url_for_status(status),
                        method="PUT",
                        data=PART,
                        headers={
                            "Authorization": "Bearer local-hostile-token",
                            "X-Upload-Probe": f"auth-marker-{status}",
                        },
                    )
                    with self.assertRaises(urllib.error.HTTPError):
                        uploader._UPLOAD_OPENER.open(request, timeout=2)
        self.assertEqual(fixture.source_bodies, [PART] * 100)
        self.assertEqual(
            fixture.source_authorizations,
            ["Bearer local-hostile-token"] * 100,
        )
        self.assertEqual(fixture.target_requests, [])

    def test_every_redirect_status_keeps_bytes_and_headers_off_target(self) -> None:
        with RedirectFixture() as fixture:
            with mock.patch.object(
                uploader, "_validate_upload_url", side_effect=lambda value: value
            ):
                for status in range(300, 400):
                    with self.subTest(status=status):
                        current = operation(
                            url=fixture.url_for_status(status),
                            headers={"X-Upload-Probe": f"marker-{status}"},
                        )
                        with self.assertRaisesRegex(
                            uploader.ScreenshotUploadError, "redirect refused"
                        ):
                            uploader._upload_part(current, PART)
        self.assertEqual(fixture.source_bodies, [PART] * 100)
        self.assertEqual(
            fixture.source_markers,
            [f"marker-{status}" for status in range(300, 400)],
        )
        self.assertEqual(fixture.source_authorizations, [None] * 100)
        self.assertEqual(fixture.target_requests, [])

    def test_production_opener_disables_proxies_and_redirects(self) -> None:
        handlers = uploader._UPLOAD_OPENER.handlers
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
        self.assertIsInstance(redirect_handlers[0], uploader._NoRedirectHandler)
        self.assertEqual(proxy_handlers, [])

    def test_exact_method_url_headers_body_status_and_timeout(self) -> None:
        opener = RecordingOpener(
            lambda request: FakeResponse(
                request.full_url,
                uploader.UPLOAD_SUCCESS_STATUS,
                headers={"Content-Length": "0", "ETag": '"part-1"'},
            )
        )
        uploader._upload_part(operation(), PART, opener=opener)
        self.assertEqual(len(opener.requests), 1)
        request, timeout = opener.requests[0]
        self.assertEqual(request.full_url, UPLOAD_URL)
        self.assertEqual(request.get_method(), "PUT")
        self.assertEqual(request.data, PART)
        request_headers = {
            name.lower(): value for name, value in request.header_items()
        }
        self.assertEqual(request_headers.get("content-type"), "image/png")
        self.assertIsNone(request.get_header("Authorization"))
        self.assertEqual(timeout, uploader.UPLOAD_TIMEOUT_SECONDS)

    def test_dynamic_public_upload_hosts_are_not_allowlisted(self) -> None:
        for hostname in (
            "store-001.blobstore.apple.com",
            "future-upload.example.com",
            "asset-cdn.example.net",
        ):
            with self.subTest(hostname=hostname):
                url = f"https://{hostname}/part?signature=test"
                self.assertEqual(uploader._validate_upload_url(url), url)

    def test_unsafe_url_components_are_rejected(self) -> None:
        unsafe_urls = (
            "http://store-001.blobstore.apple.com/part",
            "https://user@store-001.blobstore.apple.com/part",
            "https://user:pass@store-001.blobstore.apple.com/part",
            "https://store-001.blobstore.apple.com:444/part",
            "https://store-001.blobstore.apple.com/part#fragment",
            "https://store-001.blobstore.apple.com",
            "https://store-001.blobstore.apple.com\\part",
            "https://store-001.blobstore.apple.com/part?bad=%zz",
            "https://store-001.blobstore.apple.com/part token",
            "https://store-001.blobstore.apple.com./part",
            "https://localhost/part",
            "https://foo.localhost/part",
            "https://foo.local/part",
            "https://internal/part",
            "https://127.0.0.1/part",
            "https://10.0.0.1/part",
            "https://[::1]/part",
            "https://store-\u03b1.example.com/part",
            "https://store-001.blobstore.apple.com:bad/part",
        )
        for url in unsafe_urls:
            with self.subTest(url=url):
                with self.assertRaisesRegex(
                    uploader.ScreenshotUploadError, "unsafe|non-public"
                ):
                    uploader._validate_upload_url(url)

    def test_forbidden_and_ambiguous_operation_headers_are_rejected(self) -> None:
        for name in (
            "Authorization",
            "Proxy-Authorization",
            "Host",
            "Connection",
            "Content-Length",
            "Cookie",
            "Transfer-Encoding",
            "Proxy-Connection",
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    uploader.ScreenshotUploadError, "forbidden"
                ):
                    uploader.validated_upload_operations(
                        reservation(
                            request_headers=[{"name": name, "value": "unsafe"}]
                        ),
                        len(PART),
                    )
        with self.assertRaisesRegex(uploader.ScreenshotUploadError, "forbidden"):
            uploader.validated_upload_operations(
                reservation(
                    request_headers=[
                        {"name": "Content-Type", "value": "image/png"},
                        {"name": "content-type", "value": "image/jpeg"},
                    ]
                ),
                len(PART),
            )
        unopened = RecordingOpener(lambda request: FakeResponse(request.full_url))
        with self.assertRaisesRegex(uploader.ScreenshotUploadError, "forbidden"):
            uploader._upload_part(
                operation(headers={"Authorization": "Bearer must-not-send"}),
                PART,
                opener=unopened,
            )
        self.assertEqual(unopened.requests, [])

    def test_malformed_or_oversized_operation_headers_are_rejected(self) -> None:
        bad_headers = (
            [{"name": "Bad Header", "value": "x"}],
            [{"name": "X-Test", "value": "line\r\nbreak"}],
            [{"name": "X-Test", "value": "nul\x00byte"}],
            [
                {"name": f"X-Test-{index}", "value": "x"}
                for index in range(uploader.MAX_OPERATION_HEADERS + 1)
            ],
            [
                {
                    "name": "X-Test",
                    "value": "x" * (uploader.MAX_OPERATION_HEADER_BYTES + 1),
                }
            ],
        )
        for headers in bad_headers:
            with self.subTest(count=len(headers)):
                with self.assertRaises(uploader.ScreenshotUploadError):
                    uploader.validated_upload_operations(
                        reservation(request_headers=headers), len(PART)
                    )

    def test_request_and_response_url_or_method_drift_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            uploader.ScreenshotUploadError, "invalid validated"
        ):
            uploader._upload_part(operation(method="POST"), PART)
        with self.assertRaisesRegex(
            uploader.ScreenshotUploadError, "part length changed"
        ):
            uploader._upload_part(operation(length=len(PART) + 1), PART)
        drifted_urls = (
            UPLOAD_URL.replace("https://", "http://", 1),
            UPLOAD_URL.replace("dynamic-991", "dynamic-992", 1),
            UPLOAD_URL.replace(".com/", ".com:443/", 1),
            UPLOAD_URL.replace("upload.png", "upload-2.png", 1),
            UPLOAD_URL + "&drift=1",
            UPLOAD_URL + "#fragment",
        )
        for response_url in drifted_urls:
            with self.subTest(response_url=response_url):
                opener = RecordingOpener(
                    lambda _request, value=response_url: FakeResponse(value)
                )
                with self.assertRaisesRegex(
                    uploader.ScreenshotUploadError, "response URL changed"
                ):
                    uploader._upload_part(operation(), PART, opener=opener)

    def test_only_exact_upload_success_status_is_accepted(self) -> None:
        for status in (201, 202, 204, 299, 300, 399):
            with self.subTest(status=status):
                opener = RecordingOpener(
                    lambda request, current=status: FakeResponse(
                        request.full_url, current
                    )
                )
                with self.assertRaisesRegex(
                    uploader.ScreenshotUploadError, f"HTTP {status}"
                ):
                    uploader._upload_part(operation(), PART, opener=opener)

    def test_response_headers_body_and_content_length_are_bounded(self) -> None:
        cases = (
            FakeResponse(
                UPLOAD_URL,
                body=b"x" * (uploader.MAX_UPLOAD_RESPONSE_BYTES + 1),
            ),
            FakeResponse(
                UPLOAD_URL,
                body=b"x",
                headers={"Content-Length": "2"},
            ),
            FakeResponse(
                UPLOAD_URL,
                headers={
                    f"X-Test-{index}": "x"
                    for index in range(uploader.MAX_UPLOAD_RESPONSE_HEADERS + 1)
                },
            ),
            FakeResponse(
                UPLOAD_URL,
                headers={
                    "X-Test": "x" * (uploader.MAX_UPLOAD_RESPONSE_HEADER_BYTES + 1)
                },
            ),
        )
        for response in cases:
            with self.subTest(headers=len(response.headers)):
                opener = RecordingOpener(lambda _request, value=response: value)
                with self.assertRaises(uploader.ScreenshotUploadError):
                    uploader._upload_part(operation(), PART, opener=opener)

    def test_http_error_url_and_body_are_bounded(self) -> None:
        def raise_error(url: str, body: bytes):
            def factory(_request: urllib.request.Request) -> FakeResponse:
                raise urllib.error.HTTPError(
                    url,
                    403,
                    "Forbidden",
                    {"Content-Length": str(len(body))},
                    io.BytesIO(body),
                )

            return factory

        drifted = RecordingOpener(raise_error(UPLOAD_URL + "&drift=1", b""))
        with self.assertRaisesRegex(
            uploader.ScreenshotUploadError, "error URL changed"
        ):
            uploader._upload_part(operation(), PART, opener=drifted)
        oversized_body = b"x" * (uploader.MAX_UPLOAD_RESPONSE_BYTES + 1)
        oversized = RecordingOpener(raise_error(UPLOAD_URL, oversized_body))
        with self.assertRaisesRegex(uploader.ScreenshotUploadError, "safety limit"):
            uploader._upload_part(operation(), PART, opener=oversized)



class ScreenshotSubmissionGateModeTests(unittest.TestCase):
    def test_submission_gate_runs_release_ready_before_approved_signoff(self) -> None:
        # The plain validator demands the pre-release-ready records that
        # validate_owner_signoff(require_approved=True) refuses, so a plain
        # run here made screenshot preflight and upload impossible.
        calls: list[object] = []

        def fake_run(argv, **kwargs):
            calls.append(list(argv))
            return mock.Mock(returncode=0)

        def fake_signoff(root, *, require_approved):
            calls.append(("signoff", require_approved))

        with mock.patch.object(uploader.subprocess, "run", side_effect=fake_run), mock.patch.object(
            uploader, "validate_owner_signoff", side_effect=fake_signoff
        ):
            uploader.run_submission_gate()
        self.assertEqual(calls[0][1:], ["tools/validate_apple_submission_package.py", "--release-ready"])
        self.assertEqual(calls[1], ("signoff", True))

if __name__ == "__main__":
    unittest.main()
