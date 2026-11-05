#!/usr/bin/env python3
"""Hostile transport tests for App Store Connect release operations."""

from __future__ import annotations

import io
import json
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

import apple_app_store_connect_release_status as release_status


TOKEN = "header.payload.signature"


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
        self.headers: dict[str, str] = {}
        if content_type is not None:
            self.headers["Content-Type"] = content_type
        self.headers["Content-Length"] = (
            str(len(body)) if content_length is None else content_length
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


def json_response(
    request: urllib.request.Request,
    resource_type: str,
    resource_id: str,
    *,
    status: int,
) -> FakeResponse:
    body = json.dumps(
        {"data": {"type": resource_type, "id": resource_id}},
        separators=(",", ":"),
    ).encode("ascii")
    return FakeResponse(request.full_url, status, body)


def availability_payload(territory_id: str = "USA") -> dict[str, object]:
    local_id = f"winsvpn-availability-{territory_id}"
    return {
        "data": {
            "type": "appAvailabilities",
            "attributes": {"availableInNewTerritories": True},
            "relationships": {
                "app": {
                    "data": {"type": "apps", "id": release_status.APP_ID}
                },
                "territoryAvailabilities": {
                    "data": [
                        {"type": "territoryAvailabilities", "id": local_id}
                    ]
                },
            },
        },
        "included": [
            {
                "type": "territoryAvailabilities",
                "id": local_id,
                "attributes": {"available": True, "preOrderEnabled": False},
                "relationships": {
                    "territory": {
                        "data": {"type": "territories", "id": territory_id}
                    }
                },
            }
        ],
    }


class RedirectFixture:
    def __init__(self) -> None:
        self.source_requests: list[str | None] = []
        self.target_requests: list[str | None] = []
        target_requests = self.target_requests

        class TargetHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                target_requests.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"data":[]}')

            def log_message(self, *_args: object) -> None:
                return None

        self.target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
        target_url = f"http://127.0.0.1:{self.target.server_port}/sink"
        source_requests = self.source_requests

        class SourceHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                source_requests.append(self.headers.get("Authorization"))
                self.send_response(302)
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


class AppStoreConnectTransportTests(unittest.TestCase):
    def client(self) -> release_status.AppStoreConnectClient:
        return release_status.AppStoreConnectClient(TOKEN)

    def test_local_redirect_never_sends_a_second_authenticated_request(self) -> None:
        with RedirectFixture() as fixture:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                release_status._NoRedirectHandler(),
            )
            request = urllib.request.Request(
                fixture.source_url,
                headers={"Authorization": f"Bearer {TOKEN}"},
            )
            with self.assertRaisesRegex(urllib.error.HTTPError, "redirect refused"):
                opener.open(request, timeout=2)
        self.assertEqual(fixture.source_requests, [f"Bearer {TOKEN}"])
        self.assertEqual(fixture.target_requests, [])

    def test_production_opener_contains_the_no_redirect_handler(self) -> None:
        handlers = release_status._AUTHENTICATED_OPENER.handlers
        redirect_handlers = [
            handler
            for handler in handlers
            if isinstance(handler, urllib.request.HTTPRedirectHandler)
        ]
        self.assertEqual(len(redirect_handlers), 1)
        self.assertIsInstance(redirect_handlers[0], release_status._NoRedirectHandler)

    def test_get_uses_exact_https_url_headers_and_no_body(self) -> None:
        opener = RecordingOpener(
            lambda request: json_response(
                request, "apps", release_status.APP_ID, status=200
            )
        )
        with mock.patch.object(release_status, "_AUTHENTICATED_OPENER", opener):
            payload = self.client().get(
                f"/v1/apps/{release_status.APP_ID}",
                {"fields[apps]": "name,bundleId", "limit": "1"},
            )
        self.assertEqual(payload["data"]["type"], "apps")
        request, timeout = opener.requests[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertIsNone(request.data)
        self.assertEqual(timeout, release_status.REQUEST_TIMEOUT_SECONDS)
        self.assertEqual(
            request.full_url,
            "https://api.appstoreconnect.apple.com/v1/apps/"
            f"{release_status.APP_ID}?fields%5Bapps%5D=name%2CbundleId&limit=1",
        )
        self.assertEqual(request.get_header("Authorization"), f"Bearer {TOKEN}")

    def test_patch_attributes_method_body_and_response_identity(self) -> None:
        opener = RecordingOpener(
            lambda request: json_response(request, "appInfos", "info-1", status=200)
        )
        with mock.patch.object(release_status, "_AUTHENTICATED_OPENER", opener):
            self.client().patch_attributes(
                "/v1/appInfos/info-1",
                "appInfos",
                "info-1",
                {"primaryCategory": "UTILITIES"},
            )
        request, _ = opener.requests[0]
        self.assertEqual(request.get_method(), "PATCH")
        self.assertEqual(
            json.loads(request.data),
            {
                "data": {
                    "type": "appInfos",
                    "id": "info-1",
                    "attributes": {"primaryCategory": "UTILITIES"},
                }
            },
        )

    def test_post_resource_method_body_and_response_identity(self) -> None:
        opener = RecordingOpener(
            lambda request: json_response(
                request, "appScreenshotSets", "set-1", status=201
            )
        )
        relationships = {
            "appStoreVersionLocalization": {
                "data": {"type": "appStoreVersionLocalizations", "id": "loc-1"}
            }
        }
        with mock.patch.object(release_status, "_AUTHENTICATED_OPENER", opener):
            self.client().post_resource(
                "/v1/appScreenshotSets",
                "appScreenshotSets",
                {"screenshotDisplayType": "APP_IPHONE_67"},
                relationships,
            )
        request, _ = opener.requests[0]
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(
            json.loads(request.data)["data"]["relationships"], relationships
        )

    def test_delete_resource_method_has_no_body(self) -> None:
        opener = RecordingOpener(
            lambda request: FakeResponse(
                request.full_url, 204, b"", content_type=None
            )
        )
        with mock.patch.object(release_status, "_AUTHENTICATED_OPENER", opener):
            self.client().delete_resource(
                "/v1/appScreenshots/shot-1", "appScreenshots", "shot-1"
            )
        request, _ = opener.requests[0]
        self.assertEqual(request.get_method(), "DELETE")
        self.assertIsNone(request.data)

    def test_patch_relationship_method_and_body(self) -> None:
        opener = RecordingOpener(
            lambda request: FakeResponse(
                request.full_url, 204, b"", content_type=None
            )
        )
        with mock.patch.object(release_status, "_AUTHENTICATED_OPENER", opener):
            self.client().patch_relationship(
                "appStoreVersions", "version-1", "build", "builds", "build-1"
            )
        request, _ = opener.requests[0]
        self.assertEqual(request.get_method(), "PATCH")
        self.assertEqual(
            json.loads(request.data),
            {"data": {"type": "builds", "id": "build-1"}},
        )

    def test_availability_creation_method_body_and_identity(self) -> None:
        territory_id = "USA"
        payload = availability_payload(territory_id)
        opener = RecordingOpener(
            lambda request: json_response(
                request, "appAvailabilities", "availability-1", status=201
            )
        )
        with mock.patch.object(release_status, "_AUTHENTICATED_OPENER", opener):
            self.client().create_app_availability(payload, {territory_id})
        request, _ = opener.requests[0]
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(json.loads(request.data), payload)

    def test_every_operation_rejects_redirect_http_errors(self) -> None:
        def redirect(request: urllib.request.Request) -> FakeResponse:
            raise urllib.error.HTTPError(
                request.full_url,
                302,
                "Found",
                {"Location": "https://example.invalid/steal"},
                io.BytesIO(),
            )

        operations = [
            lambda client: client.get("/v1/apps/app-1"),
            lambda client: client.patch_attributes(
                "/v1/apps/app-1", "apps", "app-1", {"name": "Wins VPN"}
            ),
            lambda client: client.post_resource(
                "/v1/reviewSubmissions", "reviewSubmissions", {}, {}
            ),
            lambda client: client.delete_resource(
                "/v1/appScreenshots/shot-1", "appScreenshots", "shot-1"
            ),
            lambda client: client.patch_relationship(
                "appStoreVersions", "version-1", "build", "builds", "build-1"
            ),
            lambda client: client.create_app_availability(
                availability_payload(), {"USA"}
            ),
        ]
        for operation in operations:
            with self.subTest(operation=operation):
                opener = RecordingOpener(redirect)
                with mock.patch.object(
                    release_status, "_AUTHENTICATED_OPENER", opener
                ):
                    with self.assertRaisesRegex(
                        release_status.ReleaseStatusError, "refused HTTP redirect"
                    ):
                        operation(self.client())
                self.assertEqual(len(opener.requests), 1)

    def test_every_redirect_status_is_refused(self) -> None:
        for status in (300, 301, 302, 303, 304, 305, 306, 307, 308, 399):
            with self.subTest(status=status):
                def redirect(
                    request: urllib.request.Request,
                    code: int = status,
                ) -> FakeResponse:
                    raise urllib.error.HTTPError(
                        request.full_url,
                        code,
                        "Redirect",
                        {"Location": "https://example.invalid/steal"},
                        io.BytesIO(),
                    )

                opener = RecordingOpener(redirect)
                with mock.patch.object(
                    release_status, "_AUTHENTICATED_OPENER", opener
                ):
                    with self.assertRaisesRegex(
                        release_status.ReleaseStatusError, "refused HTTP redirect"
                    ):
                        self.client().get("/v1/apps/app-1")
                self.assertEqual(len(opener.requests), 1)

    def test_response_url_drift_is_rejected(self) -> None:
        intended = "https://api.appstoreconnect.apple.com/v1/apps/app-1"
        drifted = [
            "http://api.appstoreconnect.apple.com/v1/apps/app-1",
            "https://example.invalid/v1/apps/app-1",
            "https://api.appstoreconnect.apple.com:443/v1/apps/app-1",
            "https://api.appstoreconnect.apple.com/v1/apps/app-2",
            intended + "?drift=1",
        ]
        body = b'{"data":{"type":"apps","id":"app-1"}}'
        for response_url in drifted:
            with self.subTest(response_url=response_url):
                opener = RecordingOpener(
                    lambda _request, url=response_url: FakeResponse(url, 200, body)
                )
                with mock.patch.object(
                    release_status, "_AUTHENTICATED_OPENER", opener
                ):
                    with self.assertRaisesRegex(
                        release_status.ReleaseStatusError, "response URL differs"
                    ):
                        self.client().get("/v1/apps/app-1")

    def test_http_error_url_drift_and_exact_missing_relationship(self) -> None:
        intended = "https://api.appstoreconnect.apple.com/v1/apps/app-1/build"

        def drifted_error(request: urllib.request.Request) -> FakeResponse:
            raise urllib.error.HTTPError(
                intended + "?drift=1", 404, "Not Found", {}, io.BytesIO()
            )

        opener = RecordingOpener(drifted_error)
        with mock.patch.object(release_status, "_AUTHENTICATED_OPENER", opener):
            with self.assertRaisesRegex(
                release_status.ReleaseStatusError, "HTTP error URL differs"
            ):
                self.client().get(
                    "/v1/apps/app-1/build", allow_missing_relationship=True
                )

        def exact_error(request: urllib.request.Request) -> FakeResponse:
            raise urllib.error.HTTPError(
                request.full_url, 404, "Not Found", {}, io.BytesIO()
            )

        exact = RecordingOpener(exact_error)
        with mock.patch.object(release_status, "_AUTHENTICATED_OPENER", exact):
            self.assertEqual(
                self.client().get(
                    "/v1/apps/app-1/build", allow_missing_relationship=True
                ),
                {"data": None},
            )

    def test_malformed_and_ambiguous_jsonapi_bodies_are_rejected(self) -> None:
        hostile = [
            b'{"data":{"type":"apps","id":"one","id":"two"}}',
            b'{"data":[{"type":"apps","id":"one"},{"type":"apps","id":"one"}]}',
            b'{"data":{"type":"apps","id":"one","relationships":{"builds":{"data":[{"type":"builds","id":"build-1"},{"type":"builds","id":"build-1"}]}}}}',
            b'{"data":{"type":"apps","id":"one"},"included":[{"type":"builds","id":"build-1"},{"type":"builds","id":"build-1"}]}',
            b'{"data":{"type":"apps"}}',
            b'{"data":{"type":"apps","id":"one"},"errors":[]}',
            b'{"data":{"type":"apps","id":"one","attributes":{"score":NaN}}}',
        ]
        for body in hostile:
            with self.subTest(body=body):
                opener = RecordingOpener(
                    lambda request, value=body: FakeResponse(
                        request.full_url, 200, value
                    )
                )
                with mock.patch.object(
                    release_status, "_AUTHENTICATED_OPENER", opener
                ):
                    with self.assertRaises(release_status.ReleaseStatusError):
                        self.client().get("/v1/apps/app-1")

    def test_response_size_and_declared_length_are_fail_closed(self) -> None:
        body = b"x" * (release_status.MAX_RESPONSE_BYTES + 1)
        oversized = RecordingOpener(
            lambda request: FakeResponse(request.full_url, 200, body)
        )
        with mock.patch.object(release_status, "_AUTHENTICATED_OPENER", oversized):
            with self.assertRaisesRegex(
                release_status.ReleaseStatusError, "exceeded the size limit"
            ):
                self.client().get("/v1/apps/app-1")
        short = b'{"data":{"type":"apps","id":"app-1"}}'
        mismatched = RecordingOpener(
            lambda request: FakeResponse(
                request.full_url,
                200,
                short,
                content_length=str(len(short) + 1),
            )
        )
        with mock.patch.object(release_status, "_AUTHENTICATED_OPENER", mismatched):
            with self.assertRaisesRegex(
                release_status.ReleaseStatusError, "does not match Content-Length"
            ):
                self.client().get("/v1/apps/app-1")

    def test_content_type_and_no_content_body_are_fail_closed(self) -> None:
        body = b'{"data":{"type":"apps","id":"app-1"}}'
        wrong_type = RecordingOpener(
            lambda request: FakeResponse(
                request.full_url, 200, body, content_type="text/html"
            )
        )
        with mock.patch.object(release_status, "_AUTHENTICATED_OPENER", wrong_type):
            with self.assertRaisesRegex(
                release_status.ReleaseStatusError, "non-JSON content type"
            ):
                self.client().get("/v1/apps/app-1")
        delete_body = RecordingOpener(
            lambda request: FakeResponse(
                request.full_url, 204, b"unexpected", content_type=None
            )
        )
        with mock.patch.object(
            release_status, "_AUTHENTICATED_OPENER", delete_body
        ):
            with self.assertRaisesRegex(
                release_status.ReleaseStatusError, "unexpected response body"
            ):
                self.client().delete_resource(
                    "/v1/appScreenshots/shot-1", "appScreenshots", "shot-1"
                )
    def test_mutation_response_identity_must_match(self) -> None:
        opener = RecordingOpener(
            lambda request: json_response(request, "apps", "other", status=200)
        )
        with mock.patch.object(release_status, "_AUTHENTICATED_OPENER", opener):
            with self.assertRaisesRegex(
                release_status.ReleaseStatusError, "another JSON:API resource"
            ):
                self.client().patch_attributes(
                    "/v1/apps/app-1", "apps", "app-1", {"name": "Wins VPN"}
                )

    def test_malformed_mutation_json_and_relationships_are_refused_before_open(self) -> None:
        opener = RecordingOpener(
            lambda request: json_response(request, "apps", "app-1", status=200)
        )
        with mock.patch.object(release_status, "_AUTHENTICATED_OPENER", opener):
            with self.assertRaisesRegex(
                release_status.ReleaseStatusError, "malformed.*JSON"
            ):
                self.client().patch_attributes(
                    "/v1/apps/app-1", "apps", "app-1", {"score": float("nan")}
                )
            with self.assertRaisesRegex(
                release_status.ReleaseStatusError, "invalid JSON:API identity"
            ):
                self.client().post_resource(
                    "/v1/reviewSubmissions",
                    "reviewSubmissions",
                    {},
                    {"app": {"data": {"type": "apps", "id": "bad/id"}}},
                )
        self.assertEqual(opener.requests, [])

    def test_unsafe_request_paths_and_tokens_are_rejected_before_open(self) -> None:
        for path in (
            "http://api.appstoreconnect.apple.com/v1/apps",
            "/v1/apps?drift=1",
            "/v1/apps/../users",
            "/v1/apps/%2e%2e/users",
            "/v1//apps",
        ):
            with self.subTest(path=path):
                with self.assertRaises(release_status.ReleaseStatusError):
                    self.client().get(path)
        for token in ("", "token", "a.b.c\r\nX: stolen", "a b.c.d"):
            with self.subTest(token=token):
                with self.assertRaises(release_status.ReleaseStatusError):
                    release_status.AppStoreConnectClient(token)


if __name__ == "__main__":
    unittest.main(verbosity=2)
