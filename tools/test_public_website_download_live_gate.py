#!/usr/bin/env python3
"""Offline fixtures for the live public website download gate.

These tests never open a network connection. They reproduce the independently
verified v1.0.0 debug APK and unsigned Windows production drift, plus redirect,
debug signer, com.example identity, unsigned installer, mixed/mutable
candidates, stale receipts, source-only claims, credential/header replay,
oversize, malformed JSON, duplicate ID, stale release ID, and all-pending
controls.
"""

from __future__ import annotations

import io
import hashlib
import json
import os
import ssl
import sys
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from email.message import Message
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import public_website_download_live_gate as gate


LIVE_V100_MANIFEST = """{
  "schema": "winsvpn-download-manifest-v1",
  "release_id": "v1.0.0",
  "artifacts": [
    {
      "id": "windows",
      "label": "Windows",
      "status": "available",
      "delivery": { "kind": "github_release", "url": "https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.0/WinsVPN-Setup.exe" },
      "artifact": { "filename": "WinsVPN-Setup.exe", "sha256": "25cfc27fabf67a937c52704fc3a288f105aa74d99cdd7a23e850389ef83261d3", "bytes": 57358281 }
    },
    {
      "id": "android",
      "label": "Android",
      "status": "available",
      "delivery": { "kind": "github_release", "url": "https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.0/wins-vpn-android.apk" },
      "artifact": { "filename": "wins-vpn-android.apk", "sha256": "89e8ba316dd2a041bde8d019fd407aebf6250a1840a73c98f053e0b6b4621d0f", "bytes": 68984768 }
    },
    {
      "id": "linux",
      "label": "Linux",
      "status": "verification_pending",
      "delivery": { "kind": "direct", "url": null },
      "artifact": { "filename": null, "sha256": null, "bytes": null }
    },
    {
      "id": "macos",
      "label": "MacBook (macOS)",
      "status": "verification_pending",
      "delivery": { "kind": "store", "url": null },
      "artifact": { "filename": null, "sha256": null, "bytes": null }
    },
    {
      "id": "ios",
      "label": "iPhone (iOS)",
      "status": "verification_pending",
      "delivery": { "kind": "store", "url": null },
      "artifact": { "filename": null, "sha256": null, "bytes": null }
    }
  ]
}
"""

LIVE_V100_HTML = """<!doctype html>
<html lang="en">
<head><title>Win's VPN</title></head>
<body>
<a href="https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.0/WinsVPN-Setup.exe">Windows</a>
<a href="https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.0/wins-vpn-android.apk" download>Android</a>
</body>
</html>
"""

ALL_PENDING_HTML = """<!doctype html>
<html lang="en">
<head><title>Win's VPN</title></head>
<body>
<details class="download-menu"><summary>Download</summary>
<div class="download-list" id="topDownloadList">
<span class="download-option" data-download-platform="windows" aria-disabled="true">Windows</span>
<span class="download-option" data-download-platform="android" aria-disabled="true">Android</span>
<span class="download-option" data-download-platform="linux" aria-disabled="true">Linux</span>
<span class="download-option" data-download-platform="macos" aria-disabled="true">MacBook (macOS)</span>
<span class="download-option" data-download-platform="ios" aria-disabled="true">iPhone (iOS)</span>
</div></details>
<a class="button primary" href="#get">Get Win's VPN</a>
<a href="/privacy/">Privacy Policy</a>
</body></html>
"""


def pending_manifest(release_id: str = "v1.0.16+33") -> dict[str, object]:
    return {
        "schema": "winsvpn-download-manifest-v2",
        "release_id": release_id,
        "artifacts": [
            {
                "id": platform_id,
                "label": label,
                "status": "store_pending" if kind == "store" else "verification_pending",
                "delivery": {"kind": kind, "url": None},
                "artifact": {"filename": None, "sha256": None, "bytes": None},
            }
            for platform_id, label, kind in gate.PLATFORM_CONTRACT
        ],
    }


def pending_json(release_id: str = "v1.0.16+33") -> str:
    return json.dumps(pending_manifest(release_id), indent=2)


class FixtureTransport:
    def __init__(
        self,
        *,
        html: str = ALL_PENDING_HTML,
        manifest: str | bytes = "",
        redirects: dict[str, str] | None = None,
        headers: dict[str, dict[str, str]] | None = None,
        statuses: dict[str, int] | None = None,
    ) -> None:
        self.html = html
        self.manifest = manifest
        self.redirects = redirects or {}
        self.headers = headers or {}
        self.statuses = statuses or {}
        self.calls: list[tuple[str, int, int]] = []

    def __call__(self, url: str, *, timeout: int, max_bytes: int) -> gate.Hop:
        self.calls.append((url, timeout, max_bytes))
        if url in self.redirects:
            return gate.Hop(
                302,
                {"Location": self.redirects[url], **self.headers.get(url, {})},
                b"",
            )
        if url == gate.HOME_URL:
            body = self.html.encode("utf-8")
            default_type = "text/html; charset=utf-8"
        elif url == gate.MANIFEST_URL:
            body = (
                self.manifest
                if isinstance(self.manifest, bytes)
                else self.manifest.encode("utf-8")
            )
            default_type = "application/json"
        else:
            raise AssertionError(f"unexpected fetch {url}")
        extra = self.headers.get(url, {})
        status = self.statuses.get(url, 200)
        merged = {"Content-Type": default_type, **extra}
        if url == gate.HOME_URL and status == 200:
            merged = {**gate.LIVE_HTML_SECURITY_HEADERS, **merged}
        return gate.Hop(status, merged, body)

    @property
    def urls(self) -> list[str]:
        return [item[0] for item in self.calls]


class CountingReader:
    def __init__(self, size: int) -> None:
        self.size = size
        self.offset = 0
        self.read_calls = 0

    def read(self, n: int = -1) -> bytes:
        self.read_calls += 1
        if self.offset >= self.size:
            return b""
        take = self.size - self.offset if n < 0 else min(n, self.size - self.offset)
        self.offset += take
        return b"x" * take


class FakeResponse:
    def __init__(self, status: int, headers: Message, body: bytes) -> None:
        self.status = status
        self.headers = headers
        self._body = body
        self._offset = 0

    def getcode(self) -> int:
        return self.status

    def read(self, n: int = -1) -> bytes:
        if self._offset >= len(self._body):
            return b""
        if n < 0:
            chunk = self._body[self._offset :]
            self._offset = len(self._body)
            return chunk
        chunk = self._body[self._offset : self._offset + n]
        self._offset += len(chunk)
        return chunk

    def close(self) -> None:
        return None


class FakeOpener:
    def __init__(self, script: dict[str, object]) -> None:
        self.script = script
        self.requests: list[urllib.request.Request] = []

    def open(self, request: urllib.request.Request, timeout: int | None = None):
        del timeout
        self.requests.append(request)
        item = self.script[request.full_url]
        if isinstance(item, urllib.error.HTTPError):
            raise item
        return item


def signed_available_manifest() -> dict[str, object]:
    payload = pending_manifest()
    android_name = gate.CANONICAL_PUBLIC_FILENAMES["android"]
    windows_name = gate.CANONICAL_PUBLIC_FILENAMES["windows-x64"]
    digest = "a" * 64
    signer = gate.ANDROID_PUBLIC_SIGNER_SHA256
    windows_signer = "b" * 64
    payload["artifacts"][0] = {
        "id": "windows-x64",
        "label": "Windows x64",
        "status": "available",
        "delivery": {
            "kind": "direct",
            "url": gate.exact_public_artifact_url(windows_name),
        },
        "artifact": {
            "filename": windows_name,
            "sha256": digest,
            "bytes": 12,
            "canonical_release": gate.CANONICAL_RELEASE,
            "package_identity": gate.PUBLIC_PACKAGE_IDENTITY,
            "version": gate.CANONICAL_VERSION,
            "architecture": ["x64"],
            "signature": {
                "kind": gate.SIGNATURE_KINDS["windows-x64"],
                "sha256": windows_signer,
            },
            "privacy": {
                "kind": "release_artifact_privacy_receipt_v1",
                "receipt_filename": f"{windows_name}.privacy.json",
                "receipt_sha256": "c" * 64,
            },
            "release_receipt": {
                "kind": "release_publication_receipt_v1",
                "receipt_filename": f"{windows_name}.release.json",
                "receipt_sha256": "d" * 64,
            },
            "publication_receipt": {
                "kind": "website_download_publication_receipt_v1",
                "receipt_filename": f"{windows_name}.publication.json",
                "receipt_sha256": "e" * 64,
            },
            "winn_provenance": {
                "kind": "website_download_winn_provenance_receipt_v1",
                "receipt_filename": f"{windows_name}.winn.json",
                "receipt_sha256": "f" * 64,
                "primary": "winn/3",
                "fallback": "winn/1",
                "fallback_order": ["awg", "xray"],
            },
            "windows_verification": {
                "kind": "winverifytrust_receipt_v1",
                "receipt_filename": f"{windows_name}.authenticode.json",
                "receipt_sha256": "1" * 64,
                "approved_signer_subject": "CN=Win's VPN",
                "approved_signer_certificate_sha256": windows_signer,
            },
        },
    }
    payload["artifacts"][2] = {
        "id": "android",
        "label": "Android",
        "status": "available",
        "delivery": {
            "kind": "direct",
            "url": gate.exact_public_artifact_url(android_name),
        },
        "artifact": {
            "filename": android_name,
            "sha256": digest,
            "bytes": 12,
            "canonical_release": gate.CANONICAL_RELEASE,
            "package_identity": gate.PUBLIC_PACKAGE_IDENTITY,
            "version": gate.CANONICAL_VERSION,
            "architecture": ["arm64-v8a", "armeabi-v7a", "x86_64"],
            "signature": {
                "kind": gate.SIGNATURE_KINDS["android"],
                "sha256": signer,
            },
            "privacy": {
                "kind": "release_artifact_privacy_receipt_v1",
                "receipt_filename": f"{android_name}.privacy.json",
                "receipt_sha256": "2" * 64,
            },
            "release_receipt": {
                "kind": "release_publication_receipt_v1",
                "receipt_filename": f"{android_name}.release.json",
                "receipt_sha256": "3" * 64,
            },
            "publication_receipt": {
                "kind": "website_download_publication_receipt_v1",
                "receipt_filename": f"{android_name}.publication.json",
                "receipt_sha256": "4" * 64,
            },
            "winn_provenance": {
                "kind": "website_download_winn_provenance_receipt_v1",
                "receipt_filename": f"{android_name}.winn.json",
                "receipt_sha256": "5" * 64,
                "primary": "winn/3",
                "fallback": "winn/1",
                "fallback_order": ["awg", "xray"],
            },
        },
    }
    return payload


class PublicWebsiteDownloadLiveGateTests(unittest.TestCase):
    def setUp(self) -> None:
        for target, message in (
            ("socket.create_connection", "network create_connection"),
            ("urllib.request.urlopen", "network urlopen"),
        ):
            patcher = mock.patch(target, side_effect=AssertionError(message))
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_source_is_ascii_and_does_not_use_urlopen(self) -> None:
        source = (TOOLS / "public_website_download_live_gate.py").read_bytes()
        source.decode("ascii")
        self.assertNotIn(b"urllib.request.urlopen", source)
        self.assertIn(b"class _NoProxyHandler", source)
        self.assertIn(b"trust_env", source)
        self.assertIn(b"credential/header replay", source)
        self.assertIn(b"mixed candidates", source)
        self.assertIn(b"source-only claim", source)
        self.assertIn(b"debug signer", source)
        self.assertIn(b"com.example identity", source)
        self.assertIn(b"unsigned installer", source)

    def test_opener_disables_proxy_trust_env_and_keeps_strict_tls(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "HTTP_PROXY": "http://127.0.0.1:8080",
                "HTTPS_PROXY": "http://127.0.0.1:8080",
                "ALL_PROXY": "http://127.0.0.1:8080",
                "NO_PROXY": "*",
            },
            clear=False,
        ):
            with mock.patch(
                "urllib.request.getproxies",
                side_effect=AssertionError("trust_env proxy lookup"),
            ):
                opener = gate.build_live_opener()
        proxy = [handler for handler in opener.handlers if isinstance(handler, urllib.request.ProxyHandler)]
        self.assertEqual(len(proxy), 1)
        self.assertEqual(proxy[0].proxies, {})
        redirects = [
            handler
            for handler in opener.handlers
            if isinstance(handler, urllib.request.HTTPRedirectHandler)
        ]
        self.assertTrue(redirects)
        request = urllib.request.Request(gate.HOME_URL)
        for handler in redirects:
            self.assertIsNone(
                handler.redirect_request(
                    request,
                    None,
                    302,
                    "Found",
                    {},
                    gate.STALE_ANDROID_URL,
                )
            )
        https = [
            handler
            for handler in opener.handlers
            if isinstance(handler, urllib.request.HTTPSHandler)
        ]
        self.assertTrue(https)
        context = https[0]._context
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        http = [
            handler
            for handler in opener.handlers
            if isinstance(handler, urllib.request.HTTPHandler)
        ]
        self.assertTrue(http)
        with self.assertRaisesRegex(gate.LiveFetchError, "cleartext HTTP"):
            http[0].http_open(urllib.request.Request("http://winsvpn.org/"))
        cookies = [
            handler
            for handler in opener.handlers
            if isinstance(handler, urllib.request.HTTPCookieProcessor)
        ]
        self.assertEqual(cookies, [])

    @unittest.skipUnless(sys.platform == "darwin", "macOS release runtime only")
    def test_sealed_python_uses_root_owned_macos_ca_bundle(self) -> None:
        context = gate.strict_ssl_context()
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.get_ca_certs())

    def test_all_pending_positive(self) -> None:
        transport = FixtureTransport(html=ALL_PENDING_HTML, manifest=pending_json())
        report = gate.audit(transport)
        self.assertTrue(report.passed, report.findings)
        self.assertEqual(report.bindings, ())
        self.assertEqual(report.fetched, (gate.HOME_URL, gate.MANIFEST_URL))
        self.assertEqual(transport.urls, [gate.HOME_URL, gate.MANIFEST_URL])
        self.assertTrue(all(timeout == gate.TIMEOUT_SECONDS for _, timeout, _ in transport.calls))

    def test_placeholder_csp_fails_closed(self) -> None:
        transport = FixtureTransport(
            html=ALL_PENDING_HTML,
            manifest=pending_json(),
            headers={
                gate.HOME_URL: {
                    "Content-Security-Policy": "default-src 'self'; script-src 'sha256-<REDACTED_WG_KEY>'"
                }
            },
        )
        with self.assertRaisesRegex(gate.LiveFetchError, "placeholder hash"):
            gate.audit(transport)
        self.assertEqual(transport.urls, [gate.HOME_URL])

    def test_live_v1_debug_apk_and_unsigned_windows_is_stop_ship(self) -> None:
        transport = FixtureTransport(html=LIVE_V100_HTML, manifest=LIVE_V100_MANIFEST)
        report = gate.audit(transport)
        self.assertFalse(report.passed)
        rendered = "\n".join(report.findings)
        self.assertIn(gate.STALE_ANDROID_URL, rendered)
        self.assertIn(gate.STALE_WINDOWS_URL, rendered)
        self.assertIn(gate.STALE_ANDROID_SHA256, rendered)
        self.assertIn(gate.STALE_WINDOWS_SHA256, rendered)
        self.assertIn("68984768", rendered)
        self.assertIn("57358281", rendered)
        self.assertIn("stale Android debug APK identity", rendered)
        self.assertIn("stale unsigned Windows installer identity", rendered)
        self.assertIn("artifact bytes were not fetched", rendered)
        self.assertIn("active download anchor", rendered)
        self.assertIn("stale release_id v1.0.0", rendered)
        self.assertEqual(
            transport.urls,
            [gate.HOME_URL, gate.MANIFEST_URL],
        )
        self.assertNotIn(gate.STALE_ANDROID_URL, transport.urls)
        self.assertNotIn(gate.STALE_WINDOWS_URL, transport.urls)
        platforms = {binding.platform: binding for binding in report.bindings}
        self.assertEqual(platforms["android"].url, gate.STALE_ANDROID_URL)
        self.assertEqual(platforms["android"].filename, "wins-vpn-android.apk")
        self.assertEqual(platforms["android"].sha256, gate.STALE_ANDROID_SHA256)
        self.assertEqual(platforms["android"].byte_count, gate.STALE_ANDROID_BYTES)
        self.assertEqual(platforms["windows"].url, gate.STALE_WINDOWS_URL)
        self.assertEqual(platforms["windows"].filename, "WinsVPN-Setup.exe")
        self.assertEqual(platforms["windows"].sha256, gate.STALE_WINDOWS_SHA256)
        self.assertEqual(platforms["windows"].byte_count, gate.STALE_WINDOWS_BYTES)

    def test_live_html_aab_anchor_is_stop_ship(self) -> None:
        html = ALL_PENDING_HTML.replace(
            "</body>", '<a href="/downloads/app-release.aab">Android bundle</a></body>'
        )
        report = gate.audit(FixtureTransport(html=html, manifest=pending_json()))
        self.assertFalse(report.passed)
        self.assertTrue(
            any("app-release.aab" in finding for finding in report.findings),
            report.findings,
        )

    def test_redirect_off_origin_is_refused_without_following(self) -> None:
        cases = {
            "github": gate.STALE_ANDROID_URL,
            "www": "https://www.winsvpn.org/",
            "http": "http://winsvpn.org/",
            "downloads": "https://winsvpn.org/downloads/wins-vpn-android.apk",
            "query": "https://winsvpn.org/?next=/releases/downloads.json",
        }
        for name, location in cases.items():
            with self.subTest(name=name):
                transport = FixtureTransport(
                    html=ALL_PENDING_HTML,
                    manifest=pending_json(),
                    redirects={gate.HOME_URL: location},
                )
                with self.assertRaisesRegex(gate.LiveFetchError, "redirect is not allowed"):
                    gate.audit(transport)
                self.assertEqual(transport.urls, [gate.HOME_URL])
                self.assertNotIn(location, transport.urls)

    def test_same_origin_home_redirect_is_refused(self) -> None:
        calls: list[str] = []

        def transport(url: str, *, timeout: int, max_bytes: int) -> gate.Hop:
            del timeout, max_bytes
            calls.append(url)
            return gate.Hop(302, {"Location": "https://winsvpn.org/"}, b"")

        with self.assertRaisesRegex(gate.LiveFetchError, "redirect is not allowed"):
            gate.audit(transport)
        self.assertEqual(calls, [gate.HOME_URL])

    def test_oversized_html_and_json_fail_closed(self) -> None:
        html_transport = FixtureTransport(
            html=ALL_PENDING_HTML,
            manifest=pending_json(),
            headers={
                gate.HOME_URL: {"Content-Length": str(gate.MAX_HTML_BYTES + 1)}
            },
        )
        with self.assertRaisesRegex(gate.LiveFetchError, "oversized Content-Length"):
            gate.audit(html_transport)
        self.assertEqual(html_transport.urls, [gate.HOME_URL])

        json_transport = FixtureTransport(
            html=ALL_PENDING_HTML,
            manifest="{" + ("x" * (gate.MAX_JSON_BYTES + 1)),
            headers={
                gate.MANIFEST_URL: {"Content-Length": str(gate.MAX_JSON_BYTES + 1)}
            },
        )
        with self.assertRaisesRegex(gate.LiveFetchError, "oversized Content-Length"):
            gate.audit(json_transport)
        self.assertEqual(json_transport.urls, [gate.HOME_URL, gate.MANIFEST_URL])

        huge = b"{" + (b"x" * (gate.MAX_JSON_BYTES + 1))
        body_transport = FixtureTransport(html=ALL_PENDING_HTML, manifest=huge)
        with self.assertRaisesRegex(gate.LiveFetchError, "oversized body"):
            gate.audit(body_transport)

    def test_bounded_read_aborts_on_content_length_before_body(self) -> None:
        reader = CountingReader(gate.MAX_JSON_BYTES * 4)
        with self.assertRaisesRegex(gate.LiveFetchError, "oversized Content-Length"):
            gate.bounded_read(
                reader,
                gate.MAX_JSON_BYTES,
                {"Content-Length": str(gate.MAX_JSON_BYTES + 1)},
            )
        self.assertEqual(reader.read_calls, 0)

    def test_malformed_json_fails_closed(self) -> None:
        cases = (b"{", b"null", b"[1,2]", b'{"schema":', b"")
        for body in cases:
            with self.subTest(body=body):
                report = gate.evaluate_documents(
                    ALL_PENDING_HTML.encode("ascii"), body
                )
                self.assertFalse(report.passed)
                joined = "\n".join(report.findings)
                self.assertTrue(
                    "malformed" in joined
                    or "must be an object" in joined
                    or "not UTF-8" in joined
                    or "closed JSON schema" in joined
                    or "unsupported" in joined
                    or "release_id" in joined,
                    report.findings,
                )

    def test_duplicate_ids_fail_closed(self) -> None:
        payload = pending_manifest()
        payload["artifacts"][3] = json.loads(json.dumps(payload["artifacts"][2]))
        report = gate.evaluate_documents(
            ALL_PENDING_HTML.encode("ascii"),
            json.dumps(payload).encode("ascii"),
        )
        self.assertFalse(report.passed)
        self.assertTrue(any("duplicate artifact id: android" in item for item in report.findings))

    def test_stale_release_id_fails_when_all_pending(self) -> None:
        report = gate.evaluate_documents(
            ALL_PENDING_HTML.encode("ascii"),
            pending_json("v1.0.0").encode("ascii"),
        )
        self.assertFalse(report.passed)
        self.assertTrue(any("stale release_id v1.0.0" in item for item in report.findings))
        self.assertTrue(
            any(
                "release_id is not the current 1.0.16+33 website release" in item
                for item in report.findings
            )
        )
        self.assertEqual(report.bindings, ())

    def test_noncanonical_pending_release_id_fails(self) -> None:
        report = gate.evaluate_documents(
            ALL_PENDING_HTML.encode("ascii"),
            pending_json("v1.0.14+29").encode("ascii"),
        )
        self.assertFalse(report.passed)
        self.assertTrue(
            any(
                "release_id is not the current 1.0.16+33 website release" in item
                for item in report.findings
            )
        )
        self.assertEqual(report.bindings, ())

    def test_duplicate_json_object_keys_fail_closed(self) -> None:
        body = (
            b'{"schema":"winsvpn-download-manifest-v1","schema":"other",'
            b'"release_id":"v1.0.16+33","artifacts":[]}'
        )
        payload, errors = gate.parse_manifest(body)
        self.assertIsNone(payload)
        self.assertTrue(any("duplicate JSON key: schema" in item for item in errors))

    def test_nested_non_finite_json_numbers_fail_closed(self) -> None:
        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(constant=constant):
                body = (
                    '{"schema":"winsvpn-download-manifest-v1",'
                    '"release_id":"v1.0.16+33",'
                    '"artifacts":[{"artifact":{"bytes":'
                    + constant
                    + "}}]}"
                ).encode("ascii")
                payload, errors = gate.parse_manifest(body)
                self.assertIsNone(payload)
                self.assertEqual(
                    errors,
                    [f"non-finite JSON number is not allowed: {constant}"],
                )

    def test_live_hop_redirect_does_not_follow_or_read_apk_bytes(self) -> None:
        headers = Message()
        headers["Location"] = gate.STALE_ANDROID_URL
        error = urllib.error.HTTPError(
            gate.HOME_URL, 302, "Found", headers, io.BytesIO(b"apk-bytes")
        )
        opener = FakeOpener({gate.HOME_URL: error})
        hop = gate.live_hop(
            gate.HOME_URL,
            opener=opener,
            timeout=gate.TIMEOUT_SECONDS,
            max_bytes=gate.MAX_HTML_BYTES,
            accept_prefix="text/html",
        )
        self.assertEqual(hop.status, 302)
        self.assertEqual(hop.body, b"")
        self.assertEqual(
            [request.full_url for request in opener.requests],
            [gate.HOME_URL],
        )
        with self.assertRaisesRegex(gate.LiveFetchError, "redirect is not allowed"):
            gate.fetch_allowed(
                gate.HOME_URL,
                transport=lambda url, timeout, max_bytes: hop,
                max_bytes=gate.MAX_HTML_BYTES,
            )

    def test_main_rejects_arguments_without_live_fetch(self) -> None:
        with mock.patch.object(
            gate, "live_audit", side_effect=AssertionError("live fetch")
        ):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = gate.main(["--download-artifacts"])
        self.assertEqual(code, 1)
        self.assertIn("accepts no arguments", buffer.getvalue())

    def test_main_renders_stop_ship_without_authorizing_release(self) -> None:
        report = gate.evaluate_documents(
            LIVE_V100_HTML.encode("ascii"),
            LIVE_V100_MANIFEST.encode("ascii"),
        )
        with mock.patch.object(gate, "live_audit", return_value=report):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = gate.main([])
        self.assertEqual(code, 1)
        output = buffer.getvalue()
        self.assertTrue(output.startswith("FAIL"))
        self.assertIn("signed release is not authorized", output)
        self.assertIn("artifact bytes were not fetched", output)

    def test_refuses_to_fetch_artifact_urls_directly(self) -> None:
        with self.assertRaisesRegex(gate.LiveFetchError, "live audit pair"):
            gate.fetch_allowed(
                gate.STALE_ANDROID_URL,
                transport=lambda *args, **kwargs: (_ for _ in ()).throw(
                    AssertionError("artifact fetch")
                ),
                max_bytes=gate.MAX_HTML_BYTES,
            )

    def test_debug_signer_is_stop_ship(self) -> None:
        payload = signed_available_manifest()
        payload["artifacts"][2]["artifact"]["signature"] = {
            "kind": gate.SIGNATURE_KINDS["android"],
            "sha256": "d" * 64,
            "subject": "CN=Android Debug, O=Android, C=US",
        }
        report = gate.evaluate_documents(
            ALL_PENDING_HTML.encode("ascii"),
            json.dumps(payload).encode("ascii"),
        )
        self.assertFalse(report.passed)
        rendered = "\n".join(report.findings)
        self.assertIn("debug signer", rendered)
        self.assertIn("source-only claim", rendered)
        self.assertIn("artifact bytes were not fetched", rendered)
        output = gate.render_report(report)
        self.assertTrue(output.startswith("FAIL"))
        self.assertIn("signed release is not authorized", output)

    def test_com_example_identity_is_stop_ship(self) -> None:
        payload = signed_available_manifest()
        payload["artifacts"][2]["artifact"]["package_identity"] = (
            gate.STALE_ANDROID_DEBUG_PACKAGE
        )
        report = gate.evaluate_documents(
            ALL_PENDING_HTML.encode("ascii"),
            json.dumps(payload).encode("ascii"),
        )
        self.assertFalse(report.passed)
        rendered = "\n".join(report.findings)
        self.assertIn("com.example identity", rendered)
        platforms = {binding.platform: binding for binding in report.bindings}
        self.assertEqual(
            platforms["android"].package_identity,
            gate.STALE_ANDROID_DEBUG_PACKAGE,
        )

    def test_unsigned_windows_installer_is_stop_ship(self) -> None:
        payload = signed_available_manifest()
        payload["artifacts"][0]["artifact"].pop("windows_verification")
        payload["artifacts"][0]["artifact"]["signature"] = {
            "kind": "unsigned",
            "sha256": "0" * 64,
        }
        report = gate.evaluate_documents(
            ALL_PENDING_HTML.encode("ascii"),
            json.dumps(payload).encode("ascii"),
        )
        self.assertFalse(report.passed)
        self.assertTrue(
            any("unsigned installer" in item for item in report.findings),
            report.findings,
        )

    def test_mutable_latest_and_github_urls_are_stop_ship(self) -> None:
        payload = pending_manifest()
        payload["artifacts"][2]["status"] = "available"
        payload["artifacts"][2]["delivery"] = {
            "kind": "github_release",
            "url": (
                "https://github.com/winsvpn/winsvpn-downloads/releases/"
                "latest/download/wins-vpn-android.apk"
            ),
        }
        payload["artifacts"][2]["artifact"] = {
            "filename": "wins-vpn-android.apk",
            "sha256": "a" * 64,
            "bytes": 12,
        }
        report = gate.evaluate_documents(
            ALL_PENDING_HTML.encode("ascii"),
            json.dumps(payload).encode("ascii"),
        )
        self.assertFalse(report.passed)
        rendered = "\n".join(report.findings)
        self.assertIn("mutable candidate", rendered)
        self.assertIn("mixed Android/Windows candidates", rendered)
        self.assertIn("GitHub is backup-only", rendered)

    def test_mixed_android_available_windows_pending_is_stop_ship(self) -> None:
        payload = pending_manifest()
        android_name = gate.CANONICAL_PUBLIC_FILENAMES["android"]
        payload["artifacts"][2]["status"] = "available"
        payload["artifacts"][2]["delivery"]["url"] = gate.exact_public_artifact_url(
            android_name
        )
        payload["artifacts"][2]["artifact"] = {
            "filename": android_name,
            "sha256": "a" * 64,
            "bytes": 12,
            "package_identity": gate.PUBLIC_PACKAGE_IDENTITY,
            "signature": {
                "kind": gate.SIGNATURE_KINDS["android"],
                "sha256": gate.ANDROID_PUBLIC_SIGNER_SHA256,
            },
        }
        report = gate.evaluate_documents(
            ALL_PENDING_HTML.encode("ascii"),
            json.dumps(payload).encode("ascii"),
        )
        self.assertFalse(report.passed)
        rendered = "\n".join(report.findings)
        self.assertIn("mixed Android/Windows candidates", rendered)
        self.assertIn("mixed candidates", rendered)

    def test_html_anchor_with_pending_manifest_is_mixed_and_source_only(self) -> None:
        html = ALL_PENDING_HTML.replace(
            "</body>",
            '<a href="https://winsvpn.org/downloads/wins-vpn-android.apk">Android</a></body>',
        )
        report = gate.evaluate_documents(
            html.encode("ascii"),
            pending_json().encode("ascii"),
        )
        self.assertFalse(report.passed)
        rendered = "\n".join(report.findings)
        self.assertIn("mixed candidates", rendered)
        self.assertIn("active download anchor", rendered)

    def test_stale_receipt_is_stop_ship(self) -> None:
        payload = signed_available_manifest()
        payload["artifacts"][0]["artifact"]["windows_verification"][
            "receipt_sha256"
        ] = gate.STALE_WINDOWS_SHA256
        payload["artifacts"][2]["artifact"]["release_receipt"]["receipt_filename"] = (
            "wins-vpn-android.apk.v1.0.0.release.json"
        )
        report = gate.evaluate_documents(
            ALL_PENDING_HTML.encode("ascii"),
            json.dumps(payload).encode("ascii"),
        )
        self.assertFalse(report.passed)
        self.assertTrue(
            any("stale receipt" in item for item in report.findings),
            report.findings,
        )

    def test_source_only_flag_and_well_formed_signed_metadata_are_not_authorized(
        self,
    ) -> None:
        payload = signed_available_manifest()
        payload["artifacts"][2]["artifact"]["source_only"] = True
        report = gate.evaluate_documents(
            ALL_PENDING_HTML.encode("ascii"),
            json.dumps(payload).encode("ascii"),
        )
        self.assertFalse(report.passed)
        rendered = "\n".join(report.findings)
        self.assertIn("source-only claim", rendered)
        self.assertIn("artifact bytes were not fetched", rendered)
        self.assertTrue(
            any("signed release artifact" in item or "source-only" in item for item in report.findings)
        )
        clean = signed_available_manifest()
        clean_report = gate.evaluate_documents(
            ALL_PENDING_HTML.encode("ascii"),
            json.dumps(clean).encode("ascii"),
        )
        self.assertFalse(clean_report.passed)
        clean_rendered = "\n".join(clean_report.findings)
        self.assertIn("source-only claim", clean_rendered)
        self.assertIn(gate.exact_public_artifact_url("wins-vpn-android.apk"), clean_rendered)
        self.assertIn(gate.exact_public_artifact_url("WinsVPN-Setup.exe"), clean_rendered)

    def test_html_source_only_availability_claim_is_stop_ship(self) -> None:
        html = ALL_PENDING_HTML.replace(
            "</body>",
            "<p>Android downloads are now available</p></body>",
        )
        report = gate.evaluate_documents(
            html.encode("ascii"),
            pending_json().encode("ascii"),
        )
        self.assertFalse(report.passed)
        self.assertTrue(
            any("source-only claim" in item for item in report.findings),
            report.findings,
        )

    def test_set_cookie_response_is_header_replay_and_stops_before_manifest(
        self,
    ) -> None:
        transport = FixtureTransport(
            html=ALL_PENDING_HTML,
            manifest=pending_json(),
            headers={gate.HOME_URL: {"Set-Cookie": "session=1"}},
        )
        with self.assertRaisesRegex(gate.LiveFetchError, "credential/header replay"):
            gate.audit(transport)
        self.assertEqual(transport.urls, [gate.HOME_URL])

    def test_www_authenticate_is_header_replay(self) -> None:
        transport = FixtureTransport(
            html=ALL_PENDING_HTML,
            manifest=pending_json(),
            headers={gate.HOME_URL: {"WWW-Authenticate": "Basic realm=downloads"}},
        )
        with self.assertRaisesRegex(gate.LiveFetchError, "credential/header replay"):
            gate.audit(transport)
        self.assertEqual(transport.urls, [gate.HOME_URL])

    def test_authorization_request_header_is_refused(self) -> None:
        request = urllib.request.Request(
            gate.HOME_URL,
            headers={"Authorization": "Bearer replay", "User-Agent": gate.USER_AGENT},
        )
        self.assertEqual(
            gate.request_header_replay_error(request),
            "credential/header replay is not allowed",
        )

    def test_live_hop_does_not_send_or_replay_credentials(self) -> None:
        headers = Message()
        headers["Content-Type"] = "text/html"
        for name, value in gate.LIVE_HTML_SECURITY_HEADERS.items():
            headers[name] = value
        opener = FakeOpener(
            {
                gate.HOME_URL: FakeResponse(
                    200, headers, ALL_PENDING_HTML.encode("ascii")
                )
            }
        )
        hop = gate.live_hop(
            gate.HOME_URL,
            opener=opener,
            timeout=gate.TIMEOUT_SECONDS,
            max_bytes=gate.MAX_HTML_BYTES,
            accept_prefix="text/html",
        )
        self.assertEqual(hop.status, 200)
        sent = opener.requests[0]
        names = {key.lower() for key, _value in sent.header_items()}
        self.assertNotIn("authorization", names)
        self.assertNotIn("cookie", names)
        self.assertEqual(
            gate.request_header_replay_error(sent),
            None,
        )
        self.assertIn("no-store", sent.get_header("Cache-control") or "")

    def test_live_hop_set_cookie_is_refused_without_reading_as_success(self) -> None:
        headers = Message()
        headers["Content-Type"] = "text/html"
        headers["Set-Cookie"] = "sid=replay"
        opener = FakeOpener(
            {gate.HOME_URL: FakeResponse(200, headers, b"<html></html>")}
        )
        with self.assertRaisesRegex(gate.LiveFetchError, "credential/header replay"):
            gate.live_hop(
                gate.HOME_URL,
                opener=opener,
                timeout=gate.TIMEOUT_SECONDS,
                max_bytes=gate.MAX_HTML_BYTES,
                accept_prefix="text/html",
            )

    def test_canonical_url_rejects_userinfo_and_query(self) -> None:
        with self.assertRaisesRegex(gate.LiveFetchError, "userinfo"):
            gate.canonical_allowed_url(
                "https://user:pass@winsvpn.org/", expected_path="/"
            )
        with self.assertRaisesRegex(gate.LiveFetchError, "query or fragment"):
            gate.canonical_allowed_url(
                "https://winsvpn.org/?token=1", expected_path="/"
            )


    def _published_manifest_bytes(self) -> bytes:
        payload = pending_manifest()
        name = "wins-vpn-linux-x64.tar.gz"
        payload["artifacts"][3] = {
            "id": "linux-x64",
            "label": "Linux x64",
            "status": "available",
            "delivery": {"kind": "direct", "url": gate.exact_public_artifact_url(name)},
            "artifact": {"filename": name, "sha256": "a" * 64, "bytes": 12},
        }
        return json.dumps(payload, indent=2).encode("ascii")

    def test_published_mode_accepts_exact_gate_passed_manifest(self) -> None:
        body = self._published_manifest_bytes()
        transport = FixtureTransport(manifest=body)
        report = gate.published_audit(transport, body)
        self.assertTrue(report.passed, report.findings)
        self.assertEqual(transport.urls, [gate.HOME_URL, gate.MANIFEST_URL])

    def test_published_mode_refuses_any_other_live_manifest(self) -> None:
        body = self._published_manifest_bytes()
        live = body.replace(b'"a', b'"b', 1)
        report = gate.published_audit(FixtureTransport(manifest=live), body)
        self.assertFalse(report.passed)
        self.assertTrue(any("not the gate-passed manifest" in item for item in report.findings))

    def test_published_mode_still_refuses_static_download_anchors(self) -> None:
        body = self._published_manifest_bytes()
        report = gate.published_audit(FixtureTransport(html=LIVE_V100_HTML, manifest=body), body)
        self.assertFalse(report.passed)
        self.assertTrue(any("active download anchor" in item for item in report.findings))

    def test_store_pending_on_a_direct_entry_fails_closed(self) -> None:
        payload = pending_manifest()
        payload["artifacts"][3]["status"] = "store_pending"
        errors = gate.closed_manifest_errors(payload)
        self.assertTrue(any("store_pending is valid only" in item for item in errors), errors)



class PinnedGithubAssetLiveTests(unittest.TestCase):
    NAME = "wins-vpn-linux-x64.tar.gz"
    BODY = b"pinned-github-asset-bytes" * 100
    PINNED = gate.GITHUB_RELEASE_PREFIX + "wins-vpn-linux-x64.tar.gz"
    ASSET = "https://release-assets.githubusercontent.com/github-production-release-asset/1/abc?sp=r"

    def setUp(self) -> None:
        patcher = mock.patch("socket.create_connection", side_effect=AssertionError("network"))
        patcher.start()
        self.addCleanup(patcher.stop)
        reviewed = {self.NAME: (hashlib.sha256(self.BODY).hexdigest(), len(self.BODY))}
        for name, value in (
            ("REVIEWED_GITHUB_ASSETS", reviewed),
            ("GITHUB_RELEASE_ASSET_NAMES", frozenset({self.NAME, "SHA256SUMS"})),
        ):
            patch = mock.patch.object(gate, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def release_metadata(self, **changes: object) -> bytes:
        payload = {
            "tag_name": "v1.0.16-33",
            "draft": False,
            "immutable": True,
            "assets": [
                {"name": self.NAME, "size": len(self.BODY), "digest": "sha256:" + hashlib.sha256(self.BODY).hexdigest()},
                {"name": "SHA256SUMS", "size": 90, "digest": "sha256:" + "0" * 64},
            ],
        }
        payload.update(changes)
        return json.dumps(payload).encode("ascii")

    def manifest(self, url: str | None = None, body: bytes | None = None) -> bytes:
        payload = pending_manifest()
        data = self.BODY if body is None else body
        payload["artifacts"][3] = {
            "id": "linux-x64",
            "label": "Linux x64",
            "status": "available",
            "delivery": {"kind": "github_release", "url": url or self.PINNED},
            "artifact": {
                "filename": self.NAME,
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            },
        }
        return json.dumps(payload, indent=2).encode("ascii")

    def asset_transport(self, *, location: str | None = None, body: bytes | None = None, direct: bool = False):
        calls: list[str] = []
        served = self.BODY if body is None else body

        def transport(url: str, *, timeout: int, max_bytes: int) -> gate.Hop:
            if url == gate.GITHUB_RELEASE_API_URL:
                return gate.Hop(200, {"Content-Type": "application/json"}, getattr(self, "metadata", None) or self.release_metadata())
            calls.append(url)
            if url == self.PINNED and not direct:
                return gate.Hop(302, {"Location": location or self.ASSET}, b"")
            return gate.Hop(200, {"Content-Type": "application/octet-stream"}, served)

        return transport, calls

    def audit(self, manifest: bytes, transport) -> gate.AuditReport:
        return gate.published_audit(FixtureTransport(manifest=manifest), manifest, asset_transport=transport)

    def test_pinned_asset_is_fetched_through_one_redirect_and_verified(self) -> None:
        transport, calls = self.asset_transport()
        report = self.audit(self.manifest(), transport)
        self.assertTrue(report.passed, report.findings)
        self.assertEqual(calls, [self.PINNED, self.ASSET])
        self.assertIn(self.PINNED, report.fetched)
        self.assertIn(gate.GITHUB_RELEASE_API_URL, report.fetched)

    def test_release_must_be_immutable_with_exact_reviewed_assets(self) -> None:
        # Coordinator round 2 (GH-01/GH-02): the post-publish gate checks
        # GitHub's immutable flag, the asset inventory and GitHub's digests.
        for changes, needle in (
            ({"immutable": False}, "not an immutable release"),
            ({"draft": True}, "is a draft"),
            ({"assets": []}, "not exactly the seven reviewed files"),
            (
                {"assets": [
                    {"name": self.NAME, "size": len(self.BODY), "digest": "sha256:" + "f" * 64},
                    {"name": "SHA256SUMS", "size": 1, "digest": "sha256:" + "0" * 64},
                ]},
                "GitHub digest is not the reviewed SHA-256",
            ),
        ):
            with self.subTest(changes=changes):
                self.metadata = self.release_metadata(**changes)
                transport, _ = self.asset_transport()
                report = self.audit(self.manifest(), transport)
                self.assertFalse(report.passed)
                self.assertTrue(any(needle in item for item in report.findings), report.findings)
        self.metadata = None

    def test_manifest_hash_must_be_the_reviewed_constant(self) -> None:
        other = b"other-bytes-that-are-consistent-but-not-reviewed"
        transport, _ = self.asset_transport(body=other)
        report = self.audit(self.manifest(body=other), transport)
        self.assertFalse(report.passed)
        self.assertTrue(any("not the reviewed 1.0.16+33 binary" in item for item in report.findings), report.findings)

    def test_wrong_bytes_on_github_are_stop_ship_even_with_matching_metadata(self) -> None:
        transport, _ = self.asset_transport(body=self.BODY[:-1] + b"X")
        report = self.audit(self.manifest(), transport)
        self.assertFalse(report.passed)
        self.assertTrue(any("SHA-256 does not match" in item for item in report.findings), report.findings)

    def test_redirect_outside_github_asset_hosts_is_stop_ship(self) -> None:
        transport, calls = self.asset_transport(location="https://evil.example/asset")
        report = self.audit(self.manifest(), transport)
        self.assertFalse(report.passed)
        self.assertEqual(calls, [self.PINNED])

    def test_github_must_redirect_and_only_once(self) -> None:
        transport, _ = self.asset_transport(direct=True)
        self.assertFalse(self.audit(self.manifest(), transport).passed)

        def double(url: str, *, timeout: int, max_bytes: int) -> gate.Hop:
            return gate.Hop(302, {"Location": self.ASSET}, b"")

        self.assertFalse(self.audit(self.manifest(), double).passed)

    def test_unpinned_github_url_is_not_fetched(self) -> None:
        transport, calls = self.asset_transport()
        url = self.PINNED.replace("v1.0.16-33", "v1.0.0")
        report = self.audit(self.manifest(url), transport)
        self.assertFalse(report.passed)
        self.assertEqual(calls, [])

    def test_live_asset_transport_refuses_unpinned_urls(self) -> None:
        transport = gate.make_github_asset_transport(
            ((("linux-x64", self.PINNED, "a" * 64, 1),)), opener=object()  # type: ignore[arg-type]
        )
        with self.assertRaisesRegex(gate.LiveFetchError, "outside the pinned GitHub assets"):
            transport("https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.0/x", timeout=1, max_bytes=1)



class ReviewRoundOneLiveTests(unittest.TestCase):
    """Sol review round 1: release scope (DLP-05) and public waiver bytes (DLP-02)."""

    WAIVER = b'{"public_label":"Unsigned"}\n'

    def setUp(self) -> None:
        patcher = mock.patch("socket.create_connection", side_effect=AssertionError("network"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def windows_manifest(self, waiver_sha256: str) -> bytes:
        payload = pending_manifest()
        name = "WinsVPN-UNSIGNED-LOCAL-Setup.exe"
        payload["artifacts"][0] = {
            "id": "windows-x64",
            "label": "Windows x64",
            "status": "available",
            "delivery": {"kind": "github_release", "url": gate.GITHUB_RELEASE_PREFIX + name},
            "artifact": {
                "filename": name,
                "sha256": hashlib.sha256(b"exe").hexdigest(),
                "bytes": 3,
                "unsigned_waiver": {
                    "label": "Unsigned",
                    "waiver_filename": "download-unsigned-waiver.json",
                    "waiver_sha256": waiver_sha256,
                },
            },
        }
        return json.dumps(payload).encode("ascii")

    def site(self, manifest: bytes, waiver: bytes | None):
        fixture = FixtureTransport(manifest=manifest)

        def transport(url: str, *, timeout: int, max_bytes: int) -> gate.Hop:
            if url == gate.WAIVER_URL:
                if waiver is None:
                    return gate.Hop(404, {"Content-Type": "text/plain"}, b"")
                return gate.Hop(200, {"Content-Type": "application/json"}, waiver)
            return fixture(url, timeout=timeout, max_bytes=max_bytes)

        return transport

    def assets(self, url: str, *, timeout: int, max_bytes: int) -> gate.Hop:
        if url == gate.GITHUB_RELEASE_API_URL:
            digest = "sha256:" + hashlib.sha256(b"exe").hexdigest()
            return gate.Hop(200, {"Content-Type": "application/json"}, json.dumps({
                "tag_name": "v1.0.16-33", "draft": False, "immutable": True,
                "assets": [{"name": "WinsVPN-UNSIGNED-LOCAL-Setup.exe", "size": 3, "digest": digest}],
            }).encode("ascii"))
        if url.startswith(gate.GITHUB_RELEASE_PREFIX):
            return gate.Hop(302, {"Location": "https://release-assets.githubusercontent.com/x"}, b"")
        return gate.Hop(200, {"Content-Type": "application/octet-stream"}, b"exe")

    def test_unsigned_entry_requires_the_exact_live_waiver(self) -> None:
        reviewed = mock.patch.object(gate, "REVIEWED_GITHUB_ASSETS", {
            "WinsVPN-UNSIGNED-LOCAL-Setup.exe": (hashlib.sha256(b"exe").hexdigest(), 3),
        })
        names = mock.patch.object(gate, "GITHUB_RELEASE_ASSET_NAMES", frozenset({"WinsVPN-UNSIGNED-LOCAL-Setup.exe"}))
        reviewed.start()
        names.start()
        self.addCleanup(reviewed.stop)
        self.addCleanup(names.stop)
        good = hashlib.sha256(self.WAIVER).hexdigest()
        manifest = self.windows_manifest(good)
        report = gate.published_audit(self.site(manifest, self.WAIVER), manifest, asset_transport=self.assets)
        self.assertTrue(report.passed, report.findings)
        report = gate.published_audit(self.site(manifest, b"{}"), manifest, asset_transport=self.assets)
        self.assertTrue(any("waiver bytes do not match" in item for item in report.findings), report.findings)
        report = gate.published_audit(self.site(manifest, None), manifest, asset_transport=self.assets)
        self.assertTrue(any("waiver is unavailable" in item for item in report.findings), report.findings)

    def test_published_mode_needs_an_available_well_formed_entry(self) -> None:
        # Argon F-5: an all-pending or malformed manifest is not a publication.
        pending = json.dumps(pending_manifest()).encode("ascii")
        self.assertIn(
            "stop-ship: published manifest has no available downloads",
            gate.published_manifest_errors(pending, pending),
        )
        payload = json.loads(self.windows_manifest("a" * 64))
        payload["artifacts"][0]["artifact"]["sha256"] = "A" * 64
        payload["artifacts"][0]["artifact"]["bytes"] = 0
        body = json.dumps(payload).encode("ascii")
        errors = gate.published_manifest_errors(body, body)
        self.assertTrue(any("sha256 is invalid" in item for item in errors), errors)
        self.assertTrue(any("byte count is invalid" in item for item in errors), errors)

    def test_android_or_unlabelled_windows_is_outside_the_release(self) -> None:
        payload = pending_manifest()
        payload["artifacts"][2]["status"] = "available"
        payload["artifacts"][2]["delivery"]["url"] = gate.exact_public_artifact_url("wins-vpn-android.apk")
        payload["artifacts"][2]["artifact"]["filename"] = "wins-vpn-android.apk"
        body = json.dumps(payload).encode("ascii")
        errors = gate.published_manifest_errors(body, body)
        self.assertTrue(any("outside the owner-authorized" in item for item in errors), errors)
        windows = json.loads(self.windows_manifest("a" * 64))
        del windows["artifacts"][0]["artifact"]["unsigned_waiver"]
        body = json.dumps(windows).encode("ascii")
        errors = gate.published_manifest_errors(body, body)
        self.assertTrue(any("Unsigned owner waiver label" in item for item in errors), errors)


if __name__ == "__main__":
    unittest.main()
