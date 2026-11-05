#!/usr/bin/env python3
"""Read-only live audit of public website download posture.

This gate fetches only https://winsvpn.org/ and
https://winsvpn.org/releases/downloads.json. It is fail-closed, uses strict
TLS, disables trust_env/proxy lookup, refuses every redirect, and never
downloads Android or Windows artifact bytes. A signed release is not
authorized unless every platform is verification_pending with null
URL/filename/hash/bytes, the live release_id is v1.0.16+33, and the HTML
exposes no active download anchors.

Advertised Android and Windows public URLs are bound to the current signed
release identity and fail closed on debug signer, com.example identity,
unsigned installer, redirects, mutable or mixed candidates, stale receipts,
source-only claims, and credential/header replay. Independently verified
production drift still advertised as v1.0.0 is the debug Android APK digest
and the unsigned Windows installer digest below.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import stat
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Callable, Mapping
from urllib.parse import unquote, urljoin, urlparse


ORIGIN_HOST = "winsvpn.org"
HOME_PATH = "/"
MANIFEST_PATH = "/releases/downloads.json"
HOME_URL = "https://winsvpn.org/"
MANIFEST_URL = "https://winsvpn.org/releases/downloads.json"
# Published mode only: the public unsigned waiver whose digest the manifest binds.
WAIVER_PATH = "/releases/download-unsigned-waiver.json"
WAIVER_URL = "https://winsvpn.org/releases/download-unsigned-waiver.json"
PRODUCTION_ORIGIN = "https://winsvpn.org"
MAX_HTML_BYTES = 524288
MAX_JSON_BYTES = 65536
TIMEOUT_SECONDS = 15
MAX_REDIRECTS = 0
REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})
USER_AGENT = "WinsVPN-public-website-download-live-gate/1.0"
MANIFEST_SCHEMA = "winsvpn-download-manifest-v2"
CANONICAL_WEBSITE_RELEASE_ID = "v1.0.16+33"
CANONICAL_RELEASE = "1.0.16+33"
CANONICAL_VERSION = "1.0.16"
PUBLIC_PACKAGE_IDENTITY = "org.winsvpn.app"
STALE_ANDROID_DEBUG_PACKAGE = "com.example.wins_vpn"
DEBUG_SIGNER_MARKER = "android debug"
ROOT_KEYS = frozenset({"schema", "release_id", "artifacts"})
ENTRY_KEYS = frozenset({"id", "label", "status", "delivery", "artifact"})
DELIVERY_KEYS = frozenset({"kind", "url"})
ARTIFACT_KEYS = frozenset({"filename", "sha256", "bytes"})
ALLOWED_KINDS = frozenset({"direct", "store"})
PENDING_STATUS = "verification_pending"
STORE_PENDING_STATUS = "store_pending"
AVAILABLE_STATUS = "available"
PUBLIC_BINARY_PLATFORMS = frozenset({"android", "windows-x64", "windows-arm64"})
# Owner update 2026-10-25 (Workers Free plan): desktop binaries may be assets of
# this one pinned public GitHub release. The published-manifest audit fetches
# each such asset (one redirect hop, only to GitHub's release-asset hosts) and
# checks its byte count and SHA-256 against the gate-passed manifest.
GITHUB_RELEASE_PREFIX = (
    "https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.16-33/"
)
GITHUB_RELEASE_ENTRIES = frozenset({"windows-x64", "windows-arm64", "linux-x64", "linux-arm64"})
GITHUB_ASSET_HOSTS = frozenset(
    {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}
)
MAX_GITHUB_ASSET_BYTES = 512 * 1024 * 1024
GITHUB_RELEASE_TAG = "v1.0.16-33"
GITHUB_RELEASE_API_URL = (
    "https://api.github.com/repos/winsvpn/winsvpn-downloads/releases/tags/v1.0.16-33"
)
# The four reviewed 1.0.16+33 desktop binaries (P5 lane, landing cbb83b7). The
# published manifest and every downloaded GitHub asset must equal these.
REVIEWED_GITHUB_ASSETS = {
    "WinsVPN-UNSIGNED-LOCAL-Setup.exe": (
        "5331fbbfa293db2bab752baab6b8feeebddbbdaaf6f948b88e8b505f1c701b70",
        69474102,
    ),
    "WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe": (
        "a1c76d0384eec22aad9122164dfef39d1a8df63dbbca26ab241f8c4a3253fc32",
        53622614,
    ),
    "wins-vpn-linux-x64.tar.gz": (
        "fb99581f11a937ea4dfdb2bf0471016ed59ecb7dafa9bf0ea898f8ee2c1a5077",
        47232916,
    ),
    "wins-vpn-linux-arm64.tar.gz": (
        "5ee1bb936d9becef2024e1a1ac8e0fc7b878ecafeb224c035c47bfb4958e557a",
        44550864,
    ),
}
GITHUB_RELEASE_ASSET_NAMES = frozenset(
    {
        *REVIEWED_GITHUB_ASSETS,
        "SHA256SUMS",
        "wins-vpn-linux-x64.tar.gz.sigstore.json",
        "wins-vpn-linux-arm64.tar.gz.sigstore.json",
    }
)
GITHUB_ASSET_TIMEOUT_SECONDS = 300
# A stale live v1 manifest still names its Windows entry "windows"; it must keep
# producing a stop-ship binding, not slip past as an unknown id.
LEGACY_PUBLIC_BINARY_IDS = frozenset({"windows"})
RELEASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
BINARY_PATH_RE = re.compile(r"(?i)\.(?:apk|aab|exe|msi|msix|dmg|pkg|ipa)$")
FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+()-]{0,180}$")
# One manifest entry per architecture (owner ruling 2026-10-25).
PLATFORM_CONTRACT = (
    ("windows-x64", "Windows x64", "direct"),
    ("windows-arm64", "Windows ARM64", "direct"),
    ("android", "Android", "direct"),
    ("linux-x64", "Linux x64", "direct"),
    ("linux-arm64", "Linux ARM64", "direct"),
    ("macos", "MacBook (macOS)", "store"),
    ("ios", "iPhone (iOS)", "store"),
)
STORE_DOWNLOAD_HOSTS = frozenset(
    {
        "play.google.com",
        "apps.apple.com",
        "apps.microsoft.com",
        "flathub.org",
    }
)
CANONICAL_PUBLIC_FILENAMES = {
    "android": "wins-vpn-android.apk",
    "windows-x64": "WinsVPN-Setup.exe",
    "windows-arm64": "WinsVPN-Setup-arm64.exe",
    "windows": "WinsVPN-Setup.exe",
}
ANDROID_PUBLIC_SIGNER_SHA256 = (
    "4ebbff15a1274e7b072767fa37f00e8ffbeafab80cb61b51a5ab598af6dbe6ee"
)
SIGNATURE_KINDS = {
    "android": "apk_signer_certificate_sha256",
    "windows-x64": "authenticode_signer_certificate_sha256",
    "windows-arm64": "authenticode_signer_certificate_sha256",
    "windows": "authenticode_signer_certificate_sha256",
}
STALE_RELEASE_IDS = frozenset({"v1.0.0", "1.0.0", "v1.0.14+29", "1.0.14+29"})
STALE_ANDROID_SHA256 = (
    "89e8ba316dd2a041bde8d019fd407aebf6250a1840a73c98f053e0b6b4621d0f"
)
STALE_WINDOWS_SHA256 = (
    "25cfc27fabf67a937c52704fc3a288f105aa74d99cdd7a23e850389ef83261d3"
)
STALE_DIGESTS = frozenset({STALE_ANDROID_SHA256, STALE_WINDOWS_SHA256})
STALE_ANDROID_URL = (
    "https://github.com/winsvpn/winsvpn-downloads/releases/download/"
    "v1.0.0/wins-vpn-android.apk"
)
STALE_WINDOWS_URL = (
    "https://github.com/winsvpn/winsvpn-downloads/releases/download/"
    "v1.0.0/WinsVPN-Setup.exe"
)
STALE_ANDROID_BYTES = 68984768
STALE_WINDOWS_BYTES = 57358281
MUTABLE_URL_MARKERS = (
    "/releases/latest/",
    "/releases/download/latest/",
    "github.com/",
)
SOURCE_ONLY_HTML_CLAIMS = (
    "downloads are now available",
    "download is now available",
    "signed release is available",
    "source_only",
)
STALE_HTML_MARKERS = {
    STALE_ANDROID_URL: "obsolete Android immutable download URL",
    STALE_WINDOWS_URL: "obsolete Windows immutable download URL",
    STALE_ANDROID_SHA256: "stale Android debug APK digest",
    STALE_WINDOWS_SHA256: "stale unsigned Windows installer digest",
    STALE_ANDROID_DEBUG_PACKAGE: "com.example identity",
    "com.example": "com.example identity",
    "cn=android debug": "debug signer",
    "androiddebugkey": "debug signer",
    "winsvpn-downloads/releases/download/v1.0.0/wins-vpn-android.apk": (
        "obsolete Android immutable download URL"
    ),
    "winsvpn-downloads/releases/download/v1.0.0/WinsVPN-Setup.exe": (
        "obsolete Windows immutable download URL"
    ),
    "/releases/latest/": "mutable latest-release download URL",
    "/releases/download/latest/": "mutable latest-release download URL",
}
REQUIRED_HTML_SECURITY_HEADERS = (
    ("Strict-Transport-Security", "max-age=63072000"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Content-Security-Policy", "default-src 'self'"),
)
LIVE_HTML_SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'self'; object-src 'none'; frame-ancestors 'none'; "
        "base-uri 'self'"
    ),
}
ALLOWED_REQUEST_HEADERS = frozenset(
    {
        "accept",
        "accept-encoding",
        "cache-control",
        "connection",
        "host",
        "pragma",
        "user-agent",
    }
)
FORBIDDEN_REQUEST_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "cookie2",
        "authentication",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
    }
)
FORBIDDEN_RESPONSE_HEADERS = frozenset(
    {
        "set-cookie",
        "set-cookie2",
        "www-authenticate",
        "proxy-authenticate",
        "authorization",
        "proxy-authorization",
    }
)
RECEIPT_FIELD_NAMES = (
    "privacy",
    "release_receipt",
    "publication_receipt",
    "winn_provenance",
    "windows_verification",
)


class LiveFetchError(RuntimeError):
    """Fail-closed live fetch or document refusal."""


@dataclass(frozen=True)
class Hop:
    status: int
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class ArtifactBinding:
    platform: str
    url: object
    filename: object
    sha256: object
    byte_count: object
    package_identity: object = None
    signature: object = None
    source_only: object = None
    windows_verification: object = None
    receipts: object = None

    def reason(self) -> str:
        reasons = public_binary_reason_tags(self)
        return reasons[0] if reasons else "public binary is not verification_pending"

    def stop_ship_lines(self) -> list[str]:
        return [
            (
                "stop-ship: live public "
                f"{self.platform} artifact is available before a signed "
                "release is authorized"
            ),
            f"platform: {self.platform}",
            f"url: {self.url}",
            f"filename: {self.filename}",
            f"sha256: {self.sha256}",
            f"bytes: {self.byte_count}",
            f"package_identity: {self.package_identity}",
            f"reason: {self.reason()}",
            "source-only claim: live audit did not verify signed artifact bytes",
            "artifact bytes were not fetched",
        ]


@dataclass(frozen=True)
class AuditReport:
    passed: bool
    findings: tuple[str, ...]
    bindings: tuple[ArtifactBinding, ...]
    fetched: tuple[str, ...]


Transport = Callable[..., Hop]


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _NoProxyHandler(urllib.request.ProxyHandler):
    """Replace the default env-proxy handler without consulting trust_env.

    urllib skips a ProxyHandler with an empty map, which would otherwise leave
    the default getproxies() handler installed. Explicit no-op openers keep
    this handler registered and never select a proxy.
    """

    def __init__(self) -> None:
        super().__init__({})
        self.http_open = self._no_proxy
        self.https_open = self._no_proxy

    def _no_proxy(self, req: urllib.request.Request) -> None:
        return None


class _RefuseHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        raise LiveFetchError("cleartext HTTP is not allowed")


class _RefuseFileHandler(urllib.request.FileHandler):
    def file_open(self, req):
        raise LiveFetchError("file URLs are not allowed")


class _RefuseFTPHandler(urllib.request.FTPHandler):
    def ftp_open(self, req):
        raise LiveFetchError("FTP is not allowed")


class _RefuseDataHandler(urllib.request.DataHandler):
    def data_open(self, req):
        raise LiveFetchError("data URLs are not allowed")


class _EmptyPasswordMgr(urllib.request.HTTPPasswordMgr):
    def add_password(self, *args: object, **kwargs: object) -> None:
        raise LiveFetchError("credential/header replay is not allowed")

    def find_user_password(self, realm, authuri):
        return None, None


class _RefuseBasicAuthHandler(urllib.request.HTTPBasicAuthHandler):
    def http_error_401(self, req, fp, code, msg, headers):
        raise LiveFetchError("credential/header replay is not allowed")

    def retry_http_basic_auth(self, host, req, realm):
        raise LiveFetchError("credential/header replay is not allowed")


class _RefuseDigestAuthHandler(urllib.request.HTTPDigestAuthHandler):
    def http_error_401(self, req, fp, code, msg, headers):
        raise LiveFetchError("credential/header replay is not allowed")

    def retry_http_digest_auth(self, req, authreq):
        raise LiveFetchError("credential/header replay is not allowed")


class _DownloadAnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        mapping = {key.lower(): (value or "") for key, value in attrs}
        href = mapping.get("href", "").strip()
        if "download" in mapping or is_active_download_href(href):
            self.anchors.append(href or "(missing href)")


def strict_ssl_context() -> ssl.SSLContext:
    try:
        import certifi
    except ImportError:
        context = ssl.create_default_context()
        if not context.get_ca_certs() and sys.platform == "darwin":
            # The sealed release Python intentionally has no user-controlled
            # site packages or environment. Bind its trust store to the
            # root-owned macOS system bundle instead of silently falling back
            # to ambient Python or disabling certificate verification.
            system_bundle = Path("/private/etc/ssl/cert.pem")
            try:
                bundle_stat = os.lstat(system_bundle)
            except OSError as exc:
                raise LiveFetchError(
                    "root-owned macOS CA bundle is unavailable"
                ) from exc
            if (
                not stat.S_ISREG(bundle_stat.st_mode)
                or bundle_stat.st_uid != 0
                or bundle_stat.st_nlink != 1
                or stat.S_IMODE(bundle_stat.st_mode) & 0o022
            ):
                raise LiveFetchError(
                    "root-owned macOS CA bundle failed custody checks"
                )
            context = ssl.create_default_context(cafile=str(system_bundle))
    else:
        context = ssl.create_default_context(cafile=certifi.where())
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if (
        not context.check_hostname
        or context.verify_mode != ssl.CERT_REQUIRED
        or not context.get_ca_certs()
    ):
        raise LiveFetchError("strict TLS certificate verification is unavailable")
    return context


def build_live_opener(context: ssl.SSLContext | None = None) -> urllib.request.OpenerDirector:
    # _NoProxyHandler is the urllib equivalent of trust_env=False: environment
    # HTTP(S)_PROXY values are not consulted and no proxy is used.
    passwords = _EmptyPasswordMgr()
    opener = urllib.request.build_opener(
        _NoProxyHandler(),
        _NoRedirectHandler(),
        _RefuseHTTPHandler(),
        _RefuseFileHandler(),
        _RefuseFTPHandler(),
        _RefuseDataHandler(),
        _RefuseBasicAuthHandler(passwords),
        _RefuseDigestAuthHandler(passwords),
        urllib.request.HTTPSHandler(context=context or strict_ssl_context()),
    )
    for handler in opener.handlers:
        if isinstance(handler, urllib.request.HTTPCookieProcessor):
            raise LiveFetchError("credential/header replay is not allowed")
    return opener


def exact_public_artifact_url(filename: str) -> str:
    return f"{PRODUCTION_ORIGIN}/downloads/{filename}"


def canonical_public_filename(platform: str) -> str | None:
    return CANONICAL_PUBLIC_FILENAMES.get(platform)


def canonical_allowed_url(value: str, *, expected_path: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme.lower() != "https":
        raise LiveFetchError("URL is not HTTPS on the exact origin")
    if parsed.username or parsed.password:
        raise LiveFetchError("URL contains userinfo")
    if parsed.query or parsed.fragment:
        raise LiveFetchError("URL contains query or fragment")
    host = (parsed.hostname or "").lower()
    if host != ORIGIN_HOST or parsed.port not in (None, 443):
        raise LiveFetchError("redirect or URL left the exact origin")
    path = parsed.path if parsed.path else "/"
    if path != expected_path:
        raise LiveFetchError("URL is not an allowed live-audit resource")
    if expected_path == HOME_PATH:
        return HOME_URL
    return WAIVER_URL if expected_path == WAIVER_PATH else MANIFEST_URL


def expected_path_for(url: str) -> str:
    if url == HOME_URL:
        return HOME_PATH
    if url == MANIFEST_URL:
        return MANIFEST_PATH
    if url == WAIVER_URL:
        return WAIVER_PATH
    raise LiveFetchError("refusing to fetch a URL that is not the live audit pair")


def html_security_header_errors(headers: Mapping[str, str] | object) -> list[str]:
    errors: list[str] = []
    csp = header_value(headers, "Content-Security-Policy") or ""
    lowered = csp.lower()
    if "redacted" in lowered or "placeholder" in lowered or "sha256-<" in lowered:
        errors.append("stop-ship: live CSP contains a placeholder hash")
    for name, needle in REQUIRED_HTML_SECURITY_HEADERS:
        value = header_value(headers, name) or ""
        if needle.lower() not in value.lower():
            errors.append(f"stop-ship: live HTML is missing {name}")
    return errors


def header_value(headers: Mapping[str, str] | object, name: str) -> str | None:
    getter = getattr(headers, "get", None)
    if callable(getter):
        value = getter(name)
        if value is not None:
            return str(value)
    if isinstance(headers, Mapping):
        wanted = name.lower()
        for key, value in headers.items():
            if str(key).lower() == wanted:
                return str(value)
    return None


def header_names(headers: Mapping[str, str] | object) -> tuple[str, ...]:
    if isinstance(headers, Mapping):
        return tuple(str(key) for key in headers)
    keys = getattr(headers, "keys", None)
    if callable(keys):
        try:
            return tuple(str(key) for key in keys())
        except TypeError:
            return tuple(str(key) for key in keys)
    items = getattr(headers, "items", None)
    if callable(items):
        return tuple(str(key) for key, _value in items())
    return ()


def _header_name_is_credential(name: str) -> bool:
    lowered = name.lower().replace("_", "-")
    if lowered in FORBIDDEN_REQUEST_HEADERS or lowered in FORBIDDEN_RESPONSE_HEADERS:
        return True
    parts = lowered.split("-")
    return "api-key" in lowered or any(
        part in {"cookie", "cookie2", "authorization", "authenticate", "credential", "token"}
        for part in parts
    )


def request_header_replay_error(request: urllib.request.Request) -> str | None:
    for key, _value in request.header_items():
        lowered = str(key).lower()
        if lowered in FORBIDDEN_REQUEST_HEADERS or _header_name_is_credential(str(key)):
            if lowered in ALLOWED_REQUEST_HEADERS:
                continue
            return "credential/header replay is not allowed"
        if lowered not in ALLOWED_REQUEST_HEADERS:
            return "credential/header replay is not allowed"
    unredirected = getattr(request, "unredirected_hdrs", None)
    if isinstance(unredirected, Mapping):
        for key in unredirected:
            lowered = str(key).lower()
            if lowered in FORBIDDEN_REQUEST_HEADERS or _header_name_is_credential(str(key)):
                return "credential/header replay is not allowed"
    return None


def credential_header_replay_errors(headers: Mapping[str, str] | object) -> list[str]:
    errors: list[str] = []
    for name in header_names(headers):
        lowered = name.lower()
        if lowered in FORBIDDEN_RESPONSE_HEADERS or (
            _header_name_is_credential(name) and lowered not in ALLOWED_REQUEST_HEADERS
        ):
            errors.append("credential/header replay is not allowed")
            break
    return errors


def bounded_read(fp: object, max_bytes: int, headers: Mapping[str, str] | object) -> bytes:
    declared = header_value(headers, "Content-Length")
    if declared is not None:
        try:
            length = int(str(declared).strip())
        except ValueError as exc:
            raise LiveFetchError("invalid Content-Length") from exc
        if length < 0 or length > max_bytes:
            raise LiveFetchError(f"oversized Content-Length exceeds {max_bytes} bytes")
    read = getattr(fp, "read", None)
    if not callable(read):
        raise LiveFetchError("response body cannot be read")
    chunks: list[bytes] = []
    total = 0
    while True:
        remaining = max_bytes - total + 1
        block = read(min(65536, remaining))
        if not block:
            break
        if not isinstance(block, (bytes, bytearray)):
            raise LiveFetchError("response body is not bytes")
        total += len(block)
        if total > max_bytes:
            raise LiveFetchError(f"oversized body exceeds {max_bytes} bytes")
        chunks.append(bytes(block))
    return b"".join(chunks)


def accept_body(hop: Hop, max_bytes: int) -> bytes:
    declared = header_value(hop.headers, "Content-Length")
    if declared is not None:
        try:
            length = int(str(declared).strip())
        except ValueError as exc:
            raise LiveFetchError("invalid Content-Length") from exc
        if length < 0 or length > max_bytes:
            raise LiveFetchError(f"oversized Content-Length exceeds {max_bytes} bytes")
    if len(hop.body) > max_bytes:
        raise LiveFetchError(f"oversized body exceeds {max_bytes} bytes")
    return hop.body


def _content_type_ok(headers: Mapping[str, str] | object, prefix: str) -> bool:
    value = header_value(headers, "Content-Type")
    if value is None:
        return False
    return value.lower().split(";", 1)[0].strip().startswith(prefix)


def live_hop(
    url: str,
    *,
    opener: urllib.request.OpenerDirector,
    timeout: int,
    max_bytes: int,
    accept_prefix: str,
) -> Hop:
    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "User-Agent": USER_AGENT,
            "Accept": accept_prefix,
            "Cache-Control": "no-cache, no-store",
            "Pragma": "no-cache",
        },
    )
    replay = request_header_replay_error(request)
    if replay:
        raise LiveFetchError(replay)
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        try:
            headers = dict(exc.headers.items()) if exc.headers is not None else {}
            replay_errors = credential_header_replay_errors(headers)
            if replay_errors:
                raise LiveFetchError(replay_errors[0]) from exc
            if exc.code in REDIRECT_STATUS:
                return Hop(int(exc.code), headers, b"")
            raise LiveFetchError(f"HTTP {exc.code} for {url}") from exc
        finally:
            exc.close()
    except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
        raise LiveFetchError(f"live fetch failed closed: {type(exc).__name__}") from exc
    try:
        status = int(getattr(response, "status", None) or response.getcode())
        headers = dict(response.headers.items()) if response.headers is not None else {}
        replay_errors = credential_header_replay_errors(headers)
        if replay_errors:
            raise LiveFetchError(replay_errors[0])
        if status in REDIRECT_STATUS:
            return Hop(status, headers, b"")
        if status != 200:
            raise LiveFetchError(f"HTTP {status} for {url}")
        if not _content_type_ok(headers, accept_prefix.split(",", 1)[0].strip()):
            raise LiveFetchError(f"unexpected Content-Type for {url}")
        body = bounded_read(response, max_bytes, headers)
        return Hop(status, headers, body)
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()


def make_live_transport(
    opener: urllib.request.OpenerDirector | None = None,
) -> Transport:
    live_opener = opener or build_live_opener()

    def transport(url: str, *, timeout: int, max_bytes: int) -> Hop:
        if url == HOME_URL:
            accept = "text/html"
        elif url in (MANIFEST_URL, WAIVER_URL):
            accept = "application/json"
        else:
            raise LiveFetchError(
                "refusing to fetch a URL that is not the live audit pair"
            )
        return live_hop(
            url,
            opener=live_opener,
            timeout=timeout,
            max_bytes=max_bytes,
            accept_prefix=accept,
        )

    return transport


def fetch_allowed(
    url: str,
    *,
    transport: Transport,
    max_bytes: int,
    timeout: int = TIMEOUT_SECONDS,
    max_redirects: int = MAX_REDIRECTS,
) -> bytes:
    del max_redirects
    expected_path = expected_path_for(url)
    current = canonical_allowed_url(url, expected_path=expected_path)
    hop = transport(current, timeout=timeout, max_bytes=max_bytes)
    replay_errors = credential_header_replay_errors(hop.headers)
    if replay_errors:
        raise LiveFetchError(replay_errors[0])
    if hop.status in REDIRECT_STATUS:
        location = header_value(hop.headers, "Location") or ""
        nxt = urljoin(current, location) if location else location
        raise LiveFetchError(f"redirect is not allowed: {nxt or current}")
    if hop.status != 200:
        raise LiveFetchError(f"HTTP {hop.status} for {current}")
    accept_prefix = "text/html" if expected_path == HOME_PATH else "application/json"
    if not _content_type_ok(hop.headers, accept_prefix):
        raise LiveFetchError(f"unexpected Content-Type for {current}")
    if expected_path == HOME_PATH:
        header_errors = html_security_header_errors(hop.headers)
        if header_errors:
            raise LiveFetchError("; ".join(header_errors))
    return accept_body(hop, max_bytes)


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise LiveFetchError(f"duplicate JSON key: {key}")
        payload[key] = value
    return payload


def _reject_non_finite_constant(value: str) -> object:
    raise LiveFetchError(f"non-finite JSON number is not allowed: {value}")


def _normalized_sha256(value: object) -> str | None:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        return None
    return value.lower()


def _walk_strings(value: object) -> tuple[str, ...]:
    found: list[str] = []

    def visit(item: object) -> None:
        if isinstance(item, str):
            found.append(item)
            return
        if isinstance(item, dict):
            for key, nested in item.items():
                if isinstance(key, str):
                    found.append(key)
                visit(nested)
            return
        if isinstance(item, (list, tuple)):
            for nested in item:
                visit(nested)

    visit(value)
    return tuple(found)


def _truthy_source_only(value: object) -> bool:
    if value is True:
        return True
    if isinstance(value, dict) and value.get("source_only") is True:
        return True
    if isinstance(value, dict):
        return any(_truthy_source_only(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_truthy_source_only(item) for item in value)
    return False


def url_is_mutable(url: object) -> bool:
    if not isinstance(url, str) or not url:
        return False
    lowered = url.lower()
    if any(marker in lowered for marker in MUTABLE_URL_MARKERS):
        return True
    parsed = urlparse(url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        return True
    if parsed.scheme and parsed.scheme.lower() != "https":
        return True
    host = (parsed.hostname or "").lower()
    if host and host != ORIGIN_HOST:
        return True
    path = unquote(parsed.path or "")
    if "/releases/latest/" in path.lower() or "/releases/download/latest/" in path.lower():
        return True
    return False


def exact_signed_public_url(platform: str, filename: object, url: object) -> bool:
    expected_name = canonical_public_filename(platform)
    if expected_name is None or filename != expected_name:
        return False
    if not isinstance(url, str):
        return False
    return url == exact_public_artifact_url(expected_name) and not url_is_mutable(url)


def _receipt_snapshot(artifact: Mapping[str, object]) -> dict[str, object]:
    snapshot: dict[str, object] = {}
    for field in RECEIPT_FIELD_NAMES:
        if field in artifact:
            snapshot[field] = artifact.get(field)
    return snapshot


def _stale_receipt_reason(binding: ArtifactBinding) -> str | None:
    receipts = binding.receipts if isinstance(binding.receipts, dict) else {}
    material = [binding.windows_verification, receipts]
    for text in _walk_strings(material):
        lowered = text.lower()
        digest = _normalized_sha256(text)
        if digest in STALE_DIGESTS:
            return "stale receipt"
        if any(marker in lowered for marker in ("v1.0.0", "1.0.0", "v1.0.14+29", "1.0.14+29")):
            return "stale receipt"
    verification = binding.windows_verification if isinstance(binding.windows_verification, dict) else {}
    receipt_hash = _normalized_sha256(verification.get("receipt_sha256"))
    if receipt_hash in STALE_DIGESTS:
        return "stale receipt"
    return None


def _signature_map(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def public_binary_reason_tags(binding: ArtifactBinding) -> list[str]:
    reasons: list[str] = []
    digest = _normalized_sha256(binding.sha256)
    identity = binding.package_identity if isinstance(binding.package_identity, str) else ""
    identity_lower = identity.casefold()
    signature = _signature_map(binding.signature)
    signer = signature.get("sha256")
    signer_digest = _normalized_sha256(signer)
    subject = " ".join(
        str(signature.get(field) or "")
        for field in ("subject", "signer_subject", "common_name", "kind")
    )
    verification = (
        binding.windows_verification
        if isinstance(binding.windows_verification, dict)
        else {}
    )
    filename = binding.filename if isinstance(binding.filename, str) else ""
    if (
        identity_lower.startswith("com.example")
        or identity == STALE_ANDROID_DEBUG_PACKAGE
        or "com.example" in identity_lower
    ):
        reasons.append("com.example identity")
    debug_hit = (
        DEBUG_SIGNER_MARKER in subject.casefold()
        or DEBUG_SIGNER_MARKER in identity_lower
        or "androiddebugkey" in filename.casefold()
        or "debug" in filename.casefold()
        or signer_digest == STALE_ANDROID_SHA256
        or (
            binding.platform == "android"
            and signer_digest is not None
            and signer_digest != ANDROID_PUBLIC_SIGNER_SHA256
        )
    )
    if debug_hit:
        reasons.append("debug signer")
    if binding.platform == "android" and digest == STALE_ANDROID_SHA256:
        reasons.append("stale Android debug APK identity")
    unsigned = False
    if binding.platform.startswith("windows"):
        kind = signature.get("kind")
        if digest == STALE_WINDOWS_SHA256:
            reasons.append("stale unsigned Windows installer identity")
            unsigned = True
        if (
            not verification
            or kind in (None, "unsigned")
            or str(kind).casefold() == "unsigned"
            or verification.get("authenticode_status") in {"Unsigned", "unsigned"}
            or verification.get("signature_verified") is False
        ):
            unsigned = True
        approved = _normalized_sha256(verification.get("approved_signer_certificate_sha256"))
        if signer_digest and approved and signer_digest != approved:
            unsigned = True
        if signer_digest == STALE_WINDOWS_SHA256:
            unsigned = True
    if unsigned:
        reasons.append("unsigned installer")
    if url_is_mutable(binding.url):
        reasons.append("mutable candidate")
    elif not exact_signed_public_url(binding.platform, binding.filename, binding.url):
        if isinstance(binding.url, str) and binding.url:
            reasons.append("public URL is not bound to the current signed release artifact")
    stale_receipt = _stale_receipt_reason(binding)
    if stale_receipt:
        reasons.append(stale_receipt)
    # This live audit never fetches artifact bytes, so an advertised public
    # binary is always a source-only signed-release claim.
    reasons.append("source-only claim")
    unique: list[str] = []
    for item in reasons:
        if item not in unique:
            unique.append(item)
    return unique


def parse_manifest(body: bytes) -> tuple[object | None, list[str]]:
    if len(body) > MAX_JSON_BYTES:
        return None, [f"oversized body exceeds {MAX_JSON_BYTES} bytes"]
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None, ["manifest is not UTF-8"]
    try:
        payload = json.loads(
            text,
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_non_finite_constant,
        )
    except json.JSONDecodeError:
        return None, ["manifest JSON is malformed"]
    except LiveFetchError as exc:
        return None, [str(exc)]
    if not isinstance(payload, dict):
        return None, ["manifest root must be an object"]
    return payload, []


def _entry_is_advertised(entry: Mapping[str, object]) -> bool:
    if entry.get("status") == AVAILABLE_STATUS:
        return True
    delivery = entry.get("delivery") if isinstance(entry.get("delivery"), dict) else {}
    artifact = entry.get("artifact") if isinstance(entry.get("artifact"), dict) else {}
    if delivery.get("url") not in (None, ""):
        return True
    for field in ("filename", "sha256", "bytes", "package_identity", "signature", "source_only"):
        if artifact.get(field) not in (None, "", False):
            return True
    return any(field in artifact for field in RECEIPT_FIELD_NAMES)


def extract_public_binary_bindings(payload: object) -> tuple[ArtifactBinding, ...]:
    if not isinstance(payload, dict):
        return ()
    entries = payload.get("artifacts")
    if not isinstance(entries, list):
        return ()
    bindings: list[ArtifactBinding] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        platform = entry.get("id")
        if platform not in PUBLIC_BINARY_PLATFORMS | LEGACY_PUBLIC_BINARY_IDS:
            continue
        if not _entry_is_advertised(entry):
            continue
        delivery = entry.get("delivery") if isinstance(entry.get("delivery"), dict) else {}
        artifact = entry.get("artifact") if isinstance(entry.get("artifact"), dict) else {}
        bindings.append(
            ArtifactBinding(
                platform=str(platform),
                url=delivery.get("url"),
                filename=artifact.get("filename"),
                sha256=artifact.get("sha256"),
                byte_count=artifact.get("bytes"),
                package_identity=artifact.get("package_identity"),
                signature=artifact.get("signature"),
                source_only=artifact.get("source_only"),
                windows_verification=artifact.get("windows_verification"),
                receipts=_receipt_snapshot(artifact),
            )
        )
    return tuple(bindings)


def public_binary_binding_errors(
    platform_id: str, entry: Mapping[str, object], prefix: str
) -> list[str]:
    errors: list[str] = []
    delivery = entry.get("delivery") if isinstance(entry.get("delivery"), dict) else {}
    artifact = entry.get("artifact") if isinstance(entry.get("artifact"), dict) else {}
    binding = ArtifactBinding(
        platform=platform_id,
        url=delivery.get("url"),
        filename=artifact.get("filename"),
        sha256=artifact.get("sha256"),
        byte_count=artifact.get("bytes"),
        package_identity=artifact.get("package_identity"),
        signature=artifact.get("signature"),
        source_only=artifact.get("source_only"),
        windows_verification=artifact.get("windows_verification"),
        receipts=_receipt_snapshot(artifact),
    )
    for tag in public_binary_reason_tags(binding):
        errors.append(f"stop-ship: {prefix} {tag}")
    expected_name = canonical_public_filename(platform_id)
    filename = artifact.get("filename")
    url = delivery.get("url")
    if expected_name is not None and filename not in (None, expected_name):
        errors.append(
            f"stop-ship: {prefix} filename is not the exact canonical signed artifact"
        )
    if isinstance(filename, str) and FILENAME_RE.fullmatch(filename):
        expected_url = exact_public_artifact_url(filename)
        if url != expected_url:
            errors.append(
                f"stop-ship: {prefix} public URL is not bound to the current signed release artifact"
            )
    elif url not in (None, ""):
        errors.append(
            f"stop-ship: {prefix} public URL is not bound to the current signed release artifact"
        )
    identity = artifact.get("package_identity")
    if identity not in (None, PUBLIC_PACKAGE_IDENTITY):
        if isinstance(identity, str) and identity.casefold().startswith("com.example"):
            errors.append(f"stop-ship: {prefix} com.example identity")
        else:
            errors.append(
                f"stop-ship: {prefix} package identity is not the production org.winsvpn.app identity"
            )
    return errors


def closed_manifest_errors(payload: object) -> list[str]:
    if not isinstance(payload, dict):
        return ["manifest root must be an object"]
    if set(payload) != ROOT_KEYS:
        return ["manifest root is outside the closed JSON schema"]
    if payload.get("schema") != MANIFEST_SCHEMA:
        stale = payload.get("release_id")
        if isinstance(stale, str) and stale in STALE_RELEASE_IDS:
            return ["unsupported manifest schema", f"stop-ship: stale release_id {stale}"]
        return ["unsupported manifest schema"]
    release_id = payload.get("release_id")
    if not isinstance(release_id, str) or not RELEASE_ID_RE.fullmatch(release_id):
        return ["release_id is missing or invalid"]
    errors: list[str] = []
    if release_id != CANONICAL_WEBSITE_RELEASE_ID:
        errors.append(
            "stop-ship: release_id is not the current 1.0.16+33 website release"
        )
    if release_id in STALE_RELEASE_IDS:
        errors.append(f"stop-ship: stale release_id {release_id}")
    entries = payload.get("artifacts")
    if not isinstance(entries, list) or len(entries) != len(PLATFORM_CONTRACT):
        errors.append(
            f"manifest must contain exactly {len(PLATFORM_CONTRACT)} per-architecture artifacts"
        )
        return errors
    ids = [
        entry.get("id")
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("id"), str)
    ]
    for item in sorted({value for value in ids if ids.count(value) > 1}):
        errors.append(f"duplicate artifact id: {item}")
    available_ids: list[str] = []
    pending_ids: list[str] = []
    advertised_public: list[str] = []
    public_urls: list[str] = []
    for index, (platform_id, label, kind) in enumerate(PLATFORM_CONTRACT):
        entry = entries[index]
        prefix = f"artifact {platform_id}"
        if not isinstance(entry, dict):
            errors.append(f"{prefix} must be an object")
            continue
        if set(entry) != ENTRY_KEYS:
            errors.append(f"{prefix} is outside the closed JSON schema")
            if platform_id in PUBLIC_BINARY_PLATFORMS:
                errors.extend(public_binary_binding_errors(platform_id, entry, prefix))
            continue
        if entry.get("id") != platform_id or entry.get("label") != label:
            errors.append(f"{prefix} id/label/order mismatch")
        delivery = entry.get("delivery")
        artifact = entry.get("artifact")
        if not isinstance(delivery, dict) or set(delivery) != DELIVERY_KEYS:
            errors.append(f"{prefix} delivery is outside the closed JSON schema")
            continue
        if not isinstance(artifact, dict):
            errors.append(f"{prefix} artifact is outside the closed JSON schema")
            continue
        status = entry.get("status")
        if status == STORE_PENDING_STATUS and kind != "store":
            errors.append(f"{prefix} store_pending is valid only for an app-store entry")
        if status in {PENDING_STATUS, STORE_PENDING_STATUS}:
            pending_ids.append(platform_id)
            if set(artifact) != ARTIFACT_KEYS:
                errors.append(f"{prefix} pending artifact is outside the closed JSON schema")
            if delivery.get("kind") != kind:
                errors.append(f"{prefix} pending delivery kind is invalid")
            if delivery.get("url") is not None or any(
                artifact.get(field) is not None
                for field in ("filename", "sha256", "bytes")
            ):
                errors.append(
                    f"stop-ship: {prefix} pending entry contains release metadata"
                )
            if _truthy_source_only(artifact):
                errors.append(f"stop-ship: {prefix} source-only claim")
            url = delivery.get("url")
            if url_is_mutable(url):
                errors.append(f"stop-ship: {prefix} mutable candidate")
            if platform_id in PUBLIC_BINARY_PLATFORMS and _entry_is_advertised(entry):
                advertised_public.append(platform_id)
                errors.extend(public_binary_binding_errors(platform_id, entry, prefix))
            continue
        if status != AVAILABLE_STATUS:
            errors.append(f"{prefix} has an invalid status")
            continue
        available_ids.append(platform_id)
        if platform_id in PUBLIC_BINARY_PLATFORMS:
            advertised_public.append(platform_id)
            errors.extend(public_binary_binding_errors(platform_id, entry, prefix))
            url = delivery.get("url")
            if isinstance(url, str):
                public_urls.append(url)
        else:
            errors.append(
                f"stop-ship: {prefix} is available before a signed release is authorized"
            )
        if delivery.get("kind") == "direct":
            url = delivery.get("url")
            filename = artifact.get("filename")
            expected = (
                exact_public_artifact_url(filename)
                if isinstance(filename, str)
                else ""
            )
            if url != expected:
                errors.append(
                    f"stop-ship: {prefix} direct URL is not the exact production origin"
                )
            if url_is_mutable(url):
                errors.append(f"stop-ship: {prefix} mutable candidate")
        if delivery.get("kind") == "github_release":
            errors.append(
                f"stop-ship: {prefix} GitHub is backup-only and is not website publication authority"
            )
            url = delivery.get("url")
            if url_is_mutable(url):
                errors.append(f"stop-ship: {prefix} mutable candidate")
        if delivery.get("kind") not in ALLOWED_KINDS:
            errors.append(f"{prefix} delivery kind is outside the closed JSON schema")
    public_available = [item for item in advertised_public if item in PUBLIC_BINARY_PLATFORMS]
    if public_available and set(public_available) != PUBLIC_BINARY_PLATFORMS:
        errors.append("stop-ship: mixed Android/Windows candidates")
    if available_ids and pending_ids:
        errors.append("stop-ship: mixed candidates")
    if len(public_urls) != len(set(public_urls)) and public_urls:
        errors.append("stop-ship: mixed candidates")
    return errors


def is_active_download_href(href: str) -> bool:
    raw = href.strip()
    if not raw or raw.startswith("#") or raw.lower().startswith("mailto:"):
        return False
    lowered = raw.lower()
    if "/downloads/" in lowered:
        return True
    if "github.com/" in lowered and "/releases/" in lowered and "/download/" in lowered:
        return True
    if "/releases/latest/" in lowered or "/releases/download/latest/" in lowered:
        return True
    parsed = urlparse(raw)
    path = unquote(parsed.path or "")
    if BINARY_PATH_RE.search(path):
        return True
    host = (parsed.hostname or "").lower()
    return host in STORE_DOWNLOAD_HOSTS


def html_download_anchor_errors(website: str) -> list[str]:
    parser = _DownloadAnchorParser()
    try:
        parser.feed(website)
        parser.close()
    except Exception as exc:
        return [f"HTML could not be parsed fail-closed: {type(exc).__name__}"]
    errors = [
        f"stop-ship: HTML exposes active download anchor href={href}"
        for href in parser.anchors
    ]
    lowered = website.lower()
    for marker, description in STALE_HTML_MARKERS.items():
        if marker.lower() in lowered:
            line = f"stop-ship: HTML contains {description}"
            if line not in errors:
                errors.append(line)
    for claim in SOURCE_ONLY_HTML_CLAIMS:
        if claim in lowered:
            line = "stop-ship: HTML source-only claim"
            if line not in errors:
                errors.append(line)
    return errors


def mixed_candidate_errors(website: str, payload: object) -> list[str]:
    parser = _DownloadAnchorParser()
    try:
        parser.feed(website)
        parser.close()
    except Exception:
        return []
    hrefs = [href for href in parser.anchors if href and href != "(missing href)"]
    bindings = extract_public_binary_bindings(payload)
    bound_urls = [
        binding.url for binding in bindings if isinstance(binding.url, str) and binding.url
    ]
    errors: list[str] = []
    if hrefs and not bound_urls:
        errors.append(
            "stop-ship: mixed candidates: HTML download anchors with pending manifest"
        )
    elif hrefs and set(hrefs) != set(bound_urls):
        errors.append("stop-ship: mixed candidates")
    platforms = {binding.platform for binding in bindings}
    if platforms and platforms != PUBLIC_BINARY_PLATFORMS:
        errors.append("stop-ship: mixed Android/Windows candidates")
    return errors


def evaluate_documents(html_body: bytes, manifest_body: bytes) -> AuditReport:
    findings: list[str] = []
    try:
        html_text = html_body.decode("utf-8")
    except UnicodeDecodeError:
        html_text = ""
        findings.append("HTML is not UTF-8")
    payload, parse_errors = parse_manifest(manifest_body)
    findings.extend(parse_errors)
    bindings = extract_public_binary_bindings(payload) if payload is not None else ()
    for binding in bindings:
        findings.extend(binding.stop_ship_lines())
    if payload is not None:
        findings.extend(closed_manifest_errors(payload))
    if html_text:
        findings.extend(html_download_anchor_errors(html_text))
        if payload is not None:
            findings.extend(mixed_candidate_errors(html_text, payload))
    unique: list[str] = []
    for item in findings:
        if item not in unique:
            unique.append(item)
    return AuditReport(
        passed=not unique,
        findings=tuple(unique),
        bindings=bindings,
        fetched=(),
    )


def published_manifest_errors(manifest_body: bytes, expected_body: bytes) -> list[str]:
    """Post-deploy mode: the live manifest must be the exact gate-passed bytes.

    tools/verify_website_public_download_gate.py measured every available
    artifact and receipt locally against this manifest. Byte equality proves the
    live origin advertises exactly that decision and nothing else; the Worker
    serves /downloads/* only for entries in this deployed manifest.
    """
    if manifest_body != expected_body:
        return [
            "stop-ship: live manifest bytes are not the gate-passed manifest "
            f"(live sha256 {hashlib.sha256(manifest_body).hexdigest()}, "
            f"expected sha256 {hashlib.sha256(expected_body).hexdigest()})"
        ]
    payload, parse_errors = parse_manifest(manifest_body)
    if parse_errors or not isinstance(payload, dict):
        return parse_errors or ["manifest root must be an object"]
    errors: list[str] = []
    if set(payload) != ROOT_KEYS or payload.get("schema") != MANIFEST_SCHEMA:
        errors.append("manifest root is outside the closed v2 schema")
    if payload.get("release_id") != CANONICAL_WEBSITE_RELEASE_ID:
        errors.append("stop-ship: release_id is not the current 1.0.16+33 website release")
    entries = payload.get("artifacts")
    if not isinstance(entries, list) or len(entries) != len(PLATFORM_CONTRACT):
        errors.append(
            f"manifest must contain exactly {len(PLATFORM_CONTRACT)} per-architecture artifacts"
        )
        return errors
    available_count = 0
    for index, (platform_id, label, kind) in enumerate(PLATFORM_CONTRACT):
        entry = entries[index]
        if not isinstance(entry, dict) or entry.get("id") != platform_id or entry.get("label") != label:
            errors.append(f"artifact {platform_id} id/label/order mismatch")
            continue
        status = entry.get("status")
        delivery = entry.get("delivery") if isinstance(entry.get("delivery"), dict) else {}
        if status == AVAILABLE_STATUS:
            available_count += 1
            artifact = entry.get("artifact") if isinstance(entry.get("artifact"), dict) else {}
            filename = artifact.get("filename")
            # Argon F-5: a published entry must carry a lowercase SHA-256 and a
            # positive bounded byte count.
            digest = artifact.get("sha256")
            if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest) or digest != digest.lower():
                errors.append(f"stop-ship: artifact {platform_id} sha256 is invalid")
            size = artifact.get("bytes")
            if type(size) is not int or size <= 0 or size > MAX_GITHUB_ASSET_BYTES:
                errors.append(f"stop-ship: artifact {platform_id} byte count is invalid")
            # 1.0.16+33 release scope (review DLP-05): only the four desktop
            # entries, and Windows only under the Unsigned owner waiver.
            if platform_id not in GITHUB_RELEASE_ENTRIES:
                errors.append(
                    f"stop-ship: artifact {platform_id} is outside the owner-authorized 1.0.16+33 desktop launch"
                )
                continue
            if platform_id.startswith("windows-") and not (
                isinstance(artifact.get("unsigned_waiver"), dict)
                and artifact["unsigned_waiver"].get("label") == "Unsigned"
            ):
                errors.append(f"stop-ship: artifact {platform_id} must carry the Unsigned owner waiver label")
            if kind == "direct" and delivery.get("kind") == "github_release":
                if (
                    platform_id not in GITHUB_RELEASE_ENTRIES
                    or not isinstance(filename, str)
                    or delivery.get("url") != f"{GITHUB_RELEASE_PREFIX}{filename}"
                ):
                    errors.append(
                        f"stop-ship: artifact {platform_id} GitHub URL is not the pinned v1.0.16-33 asset"
                    )
                continue
            if kind != "direct" or delivery.get("kind") != "direct":
                errors.append(f"stop-ship: artifact {platform_id} is available outside a direct entry")
            if not isinstance(filename, str) or delivery.get("url") != exact_public_artifact_url(filename):
                errors.append(f"stop-ship: artifact {platform_id} direct URL is not the exact production origin")
        elif status not in {PENDING_STATUS, STORE_PENDING_STATUS}:
            errors.append(f"artifact {platform_id} has an invalid status")
        elif status == STORE_PENDING_STATUS and kind != "store":
            errors.append(f"artifact {platform_id} store_pending is valid only for an app-store entry")
    if available_count == 0:
        errors.append("stop-ship: published manifest has no available downloads")
    return errors


def unsigned_waiver_digest(payload: object) -> str | None:
    """The single waiver SHA-256 bound by available unsigned entries, if any."""
    if not isinstance(payload, dict) or not isinstance(payload.get("artifacts"), list):
        return None
    digests = set()
    for entry in payload["artifacts"]:
        if not isinstance(entry, dict) or entry.get("status") != AVAILABLE_STATUS:
            continue
        artifact = entry.get("artifact") if isinstance(entry.get("artifact"), dict) else {}
        waiver = artifact.get("unsigned_waiver")
        if isinstance(waiver, dict):
            digests.add(str(_normalized_sha256(waiver.get("waiver_sha256"))))
    if not digests:
        return None
    return digests.pop() if len(digests) == 1 else "mismatched-waiver-digests"


def pinned_github_assets(payload: object) -> tuple[tuple[str, str, str, int], ...]:
    """(entry id, URL, sha256, bytes) for every available pinned GitHub entry."""
    if not isinstance(payload, dict) or not isinstance(payload.get("artifacts"), list):
        return ()
    found: list[tuple[str, str, str, int]] = []
    for entry in payload["artifacts"]:
        if not isinstance(entry, dict) or entry.get("status") != AVAILABLE_STATUS:
            continue
        delivery = entry.get("delivery") if isinstance(entry.get("delivery"), dict) else {}
        artifact = entry.get("artifact") if isinstance(entry.get("artifact"), dict) else {}
        if delivery.get("kind") != "github_release":
            continue
        filename = artifact.get("filename")
        digest = _normalized_sha256(artifact.get("sha256"))
        size = artifact.get("bytes")
        url = delivery.get("url")
        if (
            entry.get("id") in GITHUB_RELEASE_ENTRIES
            and isinstance(filename, str)
            and FILENAME_RE.fullmatch(filename)
            and url == f"{GITHUB_RELEASE_PREFIX}{filename}"
            and digest is not None
            and type(size) is int
            and 0 < size <= MAX_GITHUB_ASSET_BYTES
        ):
            found.append((str(entry["id"]), url, digest, size))
    return tuple(found)


def github_release_errors(transport: Transport) -> list[str]:
    """The pinned release must be published, immutable and hold exactly the
    seven reviewed assets, with GitHub's own digests equal to the reviewed ones."""
    prefix = "stop-ship: GitHub release v1.0.16-33"
    try:
        hop = transport(GITHUB_RELEASE_API_URL, timeout=TIMEOUT_SECONDS, max_bytes=MAX_JSON_BYTES * 4)
        replay = credential_header_replay_errors(hop.headers)
        if replay:
            return [f"{prefix} {replay[0]}"]
        if hop.status != 200:
            return [f"{prefix} metadata answered HTTP {hop.status}"]
        body = accept_body(hop, MAX_JSON_BYTES * 4)
    except LiveFetchError as exc:
        return [f"{prefix} metadata fetch failed closed: {exc}"]
    try:
        payload = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_non_finite_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, LiveFetchError):
        return [f"{prefix} metadata is not JSON"]
    if not isinstance(payload, dict):
        return [f"{prefix} metadata is not an object"]
    findings: list[str] = []
    if payload.get("tag_name") != GITHUB_RELEASE_TAG:
        findings.append(f"{prefix} metadata names another tag")
    if payload.get("draft") is not False:
        findings.append(f"{prefix} is a draft")
    if payload.get("immutable") is not True:
        findings.append(f"{prefix} is not an immutable release")
    assets = payload.get("assets") if isinstance(payload.get("assets"), list) else []
    names = [item.get("name") for item in assets if isinstance(item, dict)]
    if sorted(names) != sorted(GITHUB_RELEASE_ASSET_NAMES):
        findings.append(f"{prefix} assets are not exactly the seven reviewed files: {sorted(map(str, names))}")
    for item in assets:
        if not isinstance(item, dict) or item.get("name") not in REVIEWED_GITHUB_ASSETS:
            continue
        digest, size = REVIEWED_GITHUB_ASSETS[item["name"]]
        if item.get("size") != size:
            findings.append(f"{prefix} {item['name']} size is not the reviewed {size}")
        if item.get("digest") != f"sha256:{digest}":
            findings.append(f"{prefix} {item['name']} GitHub digest is not the reviewed SHA-256")
    return findings


def github_asset_errors(
    entry_id: str, url: str, sha256: str, size: int, *, transport: Transport
) -> list[str]:
    """Fetch one pinned asset: github.com must answer with exactly one redirect
    to a GitHub release-asset host, which must return exactly the manifest bytes."""
    prefix = f"stop-ship: GitHub asset {entry_id}"
    reviewed = REVIEWED_GITHUB_ASSETS.get(url.rsplit("/", 1)[-1])
    if reviewed is None or reviewed != (sha256, size):
        return [f"{prefix} manifest SHA-256 and size are not the reviewed 1.0.16+33 binary"]
    try:
        first = transport(url, timeout=GITHUB_ASSET_TIMEOUT_SECONDS, max_bytes=size)
        replay = credential_header_replay_errors(first.headers)
        if replay:
            return [f"{prefix} {replay[0]}"]
        if first.status not in REDIRECT_STATUS:
            return [f"{prefix} did not redirect to a GitHub release-asset host (HTTP {first.status})"]
        location = header_value(first.headers, "Location") or ""
        target = urlparse(location)
        if (
            target.scheme != "https"
            or (target.hostname or "").lower() not in GITHUB_ASSET_HOSTS
            or target.port not in (None, 443)
            or target.username
            or target.password
        ):
            return [f"{prefix} redirected outside GitHub's release-asset hosts"]
        second = transport(location, timeout=GITHUB_ASSET_TIMEOUT_SECONDS, max_bytes=size)
        replay = credential_header_replay_errors(second.headers)
        if replay:
            return [f"{prefix} {replay[0]}"]
        if second.status != 200:
            return [f"{prefix} asset host answered HTTP {second.status}; no further redirect is followed"]
        body = accept_body(second, size)
    except LiveFetchError as exc:
        return [f"{prefix} fetch failed closed: {exc}"]
    if len(body) != size:
        return [f"{prefix} byte count {len(body)} is not the manifest {size}"]
    if hashlib.sha256(body).hexdigest() != sha256:
        return [f"{prefix} SHA-256 does not match the manifest"]
    return []


def make_github_asset_transport(
    assets: tuple[tuple[str, str, str, int], ...],
    opener: urllib.request.OpenerDirector | None = None,
) -> Transport:
    live_opener = opener or build_live_opener()
    pinned = {item[1] for item in assets}

    def transport(url: str, *, timeout: int, max_bytes: int) -> Hop:
        parsed = urlparse(url)
        if url == GITHUB_RELEASE_API_URL:
            return live_hop(
                url,
                opener=live_opener,
                timeout=timeout,
                max_bytes=max_bytes,
                accept_prefix="application/json",
            )
        if url not in pinned and (
            parsed.scheme != "https"
            or (parsed.hostname or "").lower() not in GITHUB_ASSET_HOSTS
        ):
            raise LiveFetchError("refusing to fetch a URL outside the pinned GitHub assets")
        return live_hop(
            url,
            opener=live_opener,
            timeout=timeout,
            max_bytes=max_bytes,
            accept_prefix="application/octet-stream",
        )

    return transport


def evaluate_published_documents(
    html_body: bytes, manifest_body: bytes, expected_body: bytes
) -> AuditReport:
    findings: list[str] = []
    try:
        html_text = html_body.decode("utf-8")
    except UnicodeDecodeError:
        html_text = ""
        findings.append("HTML is not UTF-8")
    findings.extend(published_manifest_errors(manifest_body, expected_body))
    if html_text:
        # The homepage renders download links from the manifest in the browser;
        # its static HTML must still carry no download or store anchor.
        findings.extend(html_download_anchor_errors(html_text))
    unique: list[str] = []
    for item in findings:
        if item not in unique:
            unique.append(item)
    return AuditReport(passed=not unique, findings=tuple(unique), bindings=(), fetched=())


def audit(transport: Transport) -> AuditReport:
    fetched: list[str] = []
    html_body = fetch_allowed(
        HOME_URL, transport=transport, max_bytes=MAX_HTML_BYTES
    )
    fetched.append(HOME_URL)
    manifest_body = fetch_allowed(
        MANIFEST_URL, transport=transport, max_bytes=MAX_JSON_BYTES
    )
    fetched.append(MANIFEST_URL)
    report = evaluate_documents(html_body, manifest_body)
    return AuditReport(
        passed=report.passed,
        findings=report.findings,
        bindings=report.bindings,
        fetched=tuple(fetched),
    )


def live_audit() -> AuditReport:
    return audit(make_live_transport())


def published_audit(
    transport: Transport,
    expected_body: bytes,
    *,
    asset_transport: Transport | None = None,
) -> AuditReport:
    html_body = fetch_allowed(HOME_URL, transport=transport, max_bytes=MAX_HTML_BYTES)
    manifest_body = fetch_allowed(MANIFEST_URL, transport=transport, max_bytes=MAX_JSON_BYTES)
    report = evaluate_published_documents(html_body, manifest_body, expected_body)
    findings = list(report.findings)
    fetched = [HOME_URL, MANIFEST_URL]
    if report.passed:
        payload, _ = parse_manifest(manifest_body)
        waiver_digest = unsigned_waiver_digest(payload)
        if waiver_digest is not None:
            # The Unsigned label is only honest if the public waiver it cites
            # is live with exactly the bound bytes (review DLP-02).
            try:
                waiver = fetch_allowed(WAIVER_URL, transport=transport, max_bytes=MAX_JSON_BYTES)
                if hashlib.sha256(waiver).hexdigest() != waiver_digest:
                    findings.append("stop-ship: live unsigned waiver bytes do not match the manifest")
            except LiveFetchError as exc:
                findings.append(f"stop-ship: live unsigned waiver is unavailable: {exc}")
        assets = pinned_github_assets(payload)
        if assets:
            fetch_asset = asset_transport or make_github_asset_transport(assets)
            findings.extend(github_release_errors(fetch_asset))
            fetched.append(GITHUB_RELEASE_API_URL)
            for entry_id, url, digest, size in assets:
                findings.extend(
                    github_asset_errors(entry_id, url, digest, size, transport=fetch_asset)
                )
                fetched.append(url)
    return AuditReport(
        passed=not findings,
        findings=tuple(findings),
        bindings=(),
        fetched=tuple(fetched),
    )


def render_report(report: AuditReport) -> str:
    if report.passed:
        return (
            "PASS\n"
            "live public website download posture is verification_pending\n"
            "artifact bytes were not fetched\n"
        )
    lines = ["FAIL", *report.findings, "signed release is not authorized"]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) == 2 and args[0] == "--published-manifest":
        try:
            expected_path = Path(args[1])
            if expected_path.is_symlink() or not expected_path.is_file():
                raise OSError("not a regular file")
            expected_body = expected_path.read_bytes()
            if len(expected_body) > MAX_JSON_BYTES:
                raise OSError("oversized manifest")
            report = published_audit(make_live_transport(), expected_body)
        except (OSError, LiveFetchError) as exc:
            sys.stdout.write(f"FAIL\npublished-manifest audit failed closed: {exc}\n")
            return 1
        if report.passed:
            sys.stdout.write(
                "PASS\nlive manifest equals the gate-passed manifest; static HTML "
                "carries no download anchors\n"
                + "".join(
                    f"verified GitHub {'release metadata (immutable, seven reviewed assets)' if url == GITHUB_RELEASE_API_URL else 'asset'} {url}\n"
                    for url in report.fetched[2:]
                )
                + ("artifact bytes were not fetched\n" if len(report.fetched) == 2 else "")
            )
            return 0
        sys.stdout.write("\n".join(["FAIL", *report.findings]) + "\n")
        return 1
    if args:
        sys.stdout.write(
            "FAIL\nthis gate accepts no arguments, or --published-manifest PATH "
            "after an owner-authorized deploy\n"
        )
        return 1
    try:
        report = live_audit()
    except LiveFetchError as exc:
        sys.stdout.write(f"FAIL\nlive fetch failed closed: {exc}\nsigned release is not authorized\n")
        return 1
    sys.stdout.write(render_report(report))
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
