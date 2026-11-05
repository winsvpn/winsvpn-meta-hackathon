#!/usr/bin/env python3
"""Local OWASP-style static audit for the Win's VPN public website.

This is not a replacement for a full dynamic scanner, but it catches the
high-value mistakes that have repeatedly caused production issues: missing
security headers, open CORS, unsafe redirects, dangerous DOM sinks, oversized
download artifacts missing from the site, and accidental secret-like literals.
"""

from __future__ import annotations

import base64
import hashlib
import html
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"
DEPLOYMENT_SCRIPTS = (
    ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh",
    ROOT / "server" / "wins_data_plane_setup_ONETOUCH.sh",
    ROOT / "server" / "wins_core_server_setup_ONETOUCH.sh",
)
CLIENT_SECRET_SOURCES = (
    ROOT / "drop_in" / "lib" / "spa_service.dart",
)
DOWNLOAD_MANIFEST = WEB / "releases" / "downloads.json"
WINDOWS_ARTIFACT_GATE = ROOT / "tools" / "windows_cross_store_artifact_gate.py"
ANDROID_RELEASE_ENGINE_ROOT = ROOT / "android" / "app" / "src" / "release" / "jniLibs"
DOWNLOAD_MANIFEST_SCHEMA = "winsvpn-download-manifest-v2"
# One manifest entry per architecture (owner ruling 2026-10-25).
DOWNLOAD_PLATFORM_CONTRACT = (
    ("windows-x64", "Windows x64"),
    ("windows-arm64", "Windows ARM64"),
    ("android", "Android"),
    ("linux-x64", "Linux x64"),
    ("linux-arm64", "Linux ARM64"),
    ("macos", "MacBook (macOS)"),
    ("ios", "iPhone (iOS)"),
)
DOWNLOAD_ENTRY_PLATFORMS = {
    "windows-x64": "windows",
    "windows-arm64": "windows",
    "android": "android",
    "linux-x64": "linux",
    "linux-arm64": "linux",
    "macos": "macos",
    "ios": "ios",
}
DOWNLOAD_ENTRY_ARCHITECTURES = {
    "windows-x64": "x64",
    "windows-arm64": "arm64",
    "linux-x64": "x64",
    "linux-arm64": "arm64",
}
DOWNLOAD_DELIVERY_KINDS = {
    "windows-x64": "direct",
    "windows-arm64": "direct",
    "android": "direct",
    "linux-x64": "direct",
    "linux-arm64": "direct",
    "macos": "store",
    "ios": "store",
}
DOWNLOAD_STORE_HOSTS = {
    "windows": {"apps.microsoft.com"},
    "android": {"play.google.com"},
    "linux": {"flathub.org"},
    "macos": {"apps.apple.com"},
    "ios": {"apps.apple.com"},
}
DOWNLOAD_PENDING_STATUSES = frozenset({"verification_pending", "store_pending"})
UNSIGNED_SIGNATURE_KIND = "unsigned_owner_waiver"
UNSIGNED_PUBLIC_LABEL = "Unsigned"
UNSIGNED_WAIVER_FILENAME = "download-unsigned-waiver.json"
UNSIGNED_WAIVER_KEYS = frozenset({"label", "waiver_filename", "waiver_sha256"})
UNSIGNED_CANONICAL_FILENAMES = {
    "windows-x64": "WinsVPN-UNSIGNED-LOCAL-Setup.exe",
    "windows-arm64": "WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe",
}
# Owner update 2026-10-25 (Workers Free plan): desktop binaries may be hosted as
# assets of exactly this public GitHub release. The tag uses "-33" because "+"
# in a URL path is ambiguous. Any other GitHub URL stays backup-only.
GITHUB_RELEASE_PREFIX = (
    "https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.16-33/"
)
GITHUB_RELEASE_ENTRIES = frozenset({"windows-x64", "windows-arm64", "linux-x64", "linux-arm64"})
PUBLISHED_DELIVERY_KINDS = frozenset({"direct", "github_release"})
RELEASE_LAUNCH_ENTRIES = frozenset({"windows-x64", "windows-arm64", "linux-x64", "linux-arm64"})


def github_release_url_is_pinned(url: str, filename: str) -> bool:
    parsed = urlparse(url)
    return (
        url == f"{GITHUB_RELEASE_PREFIX}{filename}"
        and parsed.scheme == "https"
        and parsed.hostname == "github.com"
        and parsed.port is None
        and not (parsed.username or parsed.password or parsed.query or parsed.fragment)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+()-]{0,180}", filename) is not None
    )


def without_pinned_github_release(text: str) -> str:
    """Remove the one pinned release prefix before scanning for stale GitHub URLs."""
    return re.sub(re.escape(GITHUB_RELEASE_PREFIX), "", text, flags=re.IGNORECASE)


def published_url_is_pinned(entry_id: str, kind: object, url: str, filename: str) -> bool:
    if kind == "direct":
        return direct_url_is_immutable(url, filename)
    if kind == "github_release":
        return entry_id in GITHUB_RELEASE_ENTRIES and github_release_url_is_pinned(url, filename)
    return False
CANONICAL_RELEASE = "1.0.16+33"
CANONICAL_WEBSITE_RELEASE_ID = "v1.0.16+33"
CANONICAL_VERSION_NAME = "1.0.16"
CANONICAL_VERSION_CODE = "33"
PUBLIC_PACKAGE_IDENTITY = "org.winsvpn.app"
STALE_ANDROID_DEBUG_PACKAGE = "com.example.wins_vpn"
ANDROID_PUBLIC_APPLICATION_ID = PUBLIC_PACKAGE_IDENTITY
ANDROID_PUBLIC_SIGNER_SHA256 = (
    "4ebbff15a1274e7b072767fa37f00e8ffbeafab80cb61b51a5ab598af6dbe6ee"
)
ANDROID_REQUIRED_ENGINE_BASENAMES = frozenset({"libam-go.so", "libwinnengine.so"})
# Android refuses Xray mode (VpnTunnelService.kt) and the Gradle packaging
# excludes libxray.so, so a public APK that carries it is refused.
ANDROID_FORBIDDEN_ENGINE_BASENAMES = frozenset(
    {"libam-quick.so", "libam.so", "libxray.so"}
)
MAX_PUBLIC_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_ANDROID_ARCHIVE_MEMBERS = 100_000
MAX_ANDROID_ENGINE_BYTES = 128 * 1024 * 1024
STALE_ANDROID_DEBUG_SHA256 = (
    "89e8ba316dd2a041bde8d019fd407aebf6250a1840a73c98f053e0b6b4621d0f"
)
STALE_WINDOWS_UNSIGNED_SHA256 = (
    "25cfc27fabf67a937c52704fc3a288f105aa74d99cdd7a23e850389ef83261d3"
)
PENDING_ARTIFACT_KEYS = frozenset({"filename", "sha256", "bytes"})
AVAILABLE_ARTIFACT_CUSTODY_KEYS = frozenset(
    {
        "filename",
        "sha256",
        "bytes",
        "canonical_release",
        "package_identity",
        "version",
        "architecture",
        "signature",
        "winn_provenance",
        "privacy",
        "release_receipt",
        "publication_receipt",
    }
)
WINDOWS_VERIFICATION_KEYS = frozenset(
    {
        "kind",
        "receipt_filename",
        "receipt_sha256",
        "approved_signer_subject",
        "approved_signer_certificate_sha256",
    }
)
RECEIPT_BINDING_KEYS = frozenset({"kind", "receipt_filename", "receipt_sha256"})
WINN_BINDING_KEYS = frozenset(
    {
        "kind",
        "receipt_filename",
        "receipt_sha256",
        "primary",
        "fallback",
        "fallback_order",
    }
)
WEB_DOWNLOAD_RECEIPT_KEYS = frozenset(
    {
        "schema",
        "kind",
        "canonical_release",
        "platform_id",
        "artifact_filename",
        "artifact_sha256",
        "artifact_bytes",
        "package_identity",
        "architecture",
        "version",
    }
)
# Each hosted receipt carries exactly one evidence object; its contents are
# validated by tools/website_download_custody.py (the publication authority).
PRIVACY_RECEIPT_KEYS = WEB_DOWNLOAD_RECEIPT_KEYS | frozenset({"scan"})
RELEASE_RECEIPT_KEYS = WEB_DOWNLOAD_RECEIPT_KEYS | frozenset({"build"})
WINN_RECEIPT_KEYS = WEB_DOWNLOAD_RECEIPT_KEYS | frozenset(
    {"primary", "fallback", "fallback_order", "engine_release"}
)
PRIVACY_RECEIPT_KIND = "release_artifact_privacy_receipt_v1"
RELEASE_RECEIPT_KIND = "release_publication_receipt_v1"
PRIVACY_RECEIPT_SCHEMA = "winsvpn-web-download-privacy-receipt-v1"
RELEASE_RECEIPT_SCHEMA = "winsvpn-web-download-release-receipt-v1"
PUBLICATION_RECEIPT_KIND = "website_download_publication_receipt_v1"
PUBLICATION_RECEIPT_SCHEMA = "winsvpn-website-download-publication-receipt-v1"
WINN_PRIMARY = "winn/3"
WINN_FALLBACK = "winn/1"
WINN_FALLBACK_ORDER = ["awg", "xray"]
WINN_PROVENANCE_KIND = "website_download_winn_provenance_receipt_v1"
WINN_PROVENANCE_SCHEMA = "winsvpn-website-download-winn-provenance-v1"
SIGNATURE_KINDS = {
    "windows": "authenticode_signer_certificate_sha256",
    "android": "apk_signer_certificate_sha256",
    "linux": "publication_signature_sha256",
    "macos": "publication_signature_sha256",
    "ios": "publication_signature_sha256",
}
PLATFORM_ARCHITECTURES = {
    "windows": frozenset({"x64", "arm64"}),
    "android": frozenset({"arm64-v8a", "armeabi-v7a", "x86_64"}),
    "linux": frozenset({"x64", "arm64"}),
    "macos": frozenset({"arm64", "x86_64"}),
    "ios": frozenset({"arm64"}),
}
STALE_ARCHITECTURE_LABELS = {
    "windows": frozenset(
        {"x86", "x86_64", "amd64", "i386", "i686", "aarch64", "arm", "win32", "ia32"}
    ),
    "android": frozenset(
        {"armeabi", "x86", "mips", "mips64", "arm64", "armv7", "armv8"}
    ),
    "linux": frozenset(
        {
            "x86_64",
            "amd64",
            "aarch64",
            "i386",
            "i686",
            "armhf",
            "armv7",
            "arm64-v8a",
        }
    ),
    "macos": frozenset({"x64", "amd64", "aarch64", "x86", "i386"}),
    "ios": frozenset({"x86_64", "x64", "armv7", "arm64e", "i386"}),
}
CANONICAL_FILENAMES = {
    "windows-x64": "WinsVPN-Setup.exe",
    "windows-arm64": "WinsVPN-Setup-arm64.exe",
    "android": "wins-vpn-android.apk",
    "linux-x64": "wins-vpn-linux-x64.tar.gz",
    "linux-arm64": "wins-vpn-linux-arm64.tar.gz",
}
STALE_PUBLIC_DOWNLOAD_MARKERS = {
    STALE_ANDROID_DEBUG_PACKAGE: "stale Android debug application ID",
    "winsvpn-downloads/releases/download/v1.0.0/wins-vpn-android.apk": (
        "obsolete Android immutable download URL"
    ),
    "winsvpn-downloads/releases/download/v1.0.0/WinsVPN-Setup.exe": (
        "obsolete Windows immutable download URL"
    ),
    "github.com/winsvpn/winsvpn-downloads/releases/download/": (
        "GitHub backup download URL is not website publication authority"
    ),
    STALE_ANDROID_DEBUG_SHA256: "stale Android debug APK digest",
    STALE_WINDOWS_UNSIGNED_SHA256: "stale unsigned Windows installer digest",
    "/releases/latest/download/": "mutable latest-release download URL",
    "/releases/download/latest/": "mutable latest-release download URL",
}
PUBLIC_BINARY_PATH_RE = re.compile(
    r"(?i)\.(?:apk|aab|exe|msi|msix|dmg|pkg|ipa)(?:$|[?#])"
)
MIN_APPLE_DEMO_MP4_BYTES = 700_000
MIN_APPLE_DEMO_POSTER_BYTES = 10_000

SECRET_PATTERNS = [
    re.compile(r"cfat_[A-Za-z0-9_-]{16,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"ECI[A-Za-z0-9_-]{20,}"),
    re.compile(r"awp_[A-Za-z0-9_-]{20,}"),
    re.compile(
        r"(?i)(?:secret|token|password|api[_-]?key)\s*=\s*[\"'][^\"']{16,}[\"']"
    ),
    re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
]

DEPLOYMENT_SECRET_PATTERNS = [
    re.compile(r"cf[a-z]{2}_[A-Za-z0-9_-]{16,}"),
    re.compile(r"awp_[A-Za-z0-9_-]{20,}"),
    re.compile(
        r"(?m)^(?:ADMIN_TOKEN_DEFAULT|SPA_KEY_DEFAULT|SPA_HMAC_DEFAULT|"
        r"XRAY_UUID_DEFAULT|SMTP_PASS_DEFAULT|PAYPAL_CLIENT_SECRET_DEFAULT|"
        r"CLOUDFLARE_[A-Z0-9_]*TOKEN_DEFAULT)=[\"'][^$\"'][^\"']*[\"']\s*$"
    ),
    re.compile(
        r"os\.getenv\([\"'](?:SPA_KEY|SPAKEY|SPA_HMAC|SPAHMAC)[\"']\)"
        r"[^\n]*\bor\s+[\"'][^\"']+[\"']"
    ),
]

CLIENT_SECRET_PATTERNS = [
    re.compile(
        r"String\.fromEnvironment\([\"'](?:WINS_SPA_KEY|WINS_SPA_HMAC)[\"'],"
        r"\s*defaultValue:\s*[\"'][^\"']+"
    ),
]

APPLE_DEMO_RELEASE_REQUIREMENTS = {
    "ios": {
        "label": "iOS",
        "aliases": ("ios",),
        "demo_assets": (
            WEB / "assets" / "demo" / "winsvpn-ios-demo.mp4",
            WEB / "assets" / "demo" / "winsvpn-ios-demo.webp",
        ),
        "release_patterns": (
            re.compile(r"\.ipa(?:[?#\"'\s<]|$)", re.IGNORECASE),
            re.compile(r"\btestflight\b", re.IGNORECASE),
            re.compile(r"\bios-app-store\b", re.IGNORECASE),
        ),
    },
    "macos": {
        "label": "macOS",
        "aliases": ("macos", "mac os", "mac app store"),
        "demo_assets": (
            WEB / "assets" / "demo" / "winsvpn-macos-demo.mp4",
            WEB / "assets" / "demo" / "winsvpn-macos-demo.webp",
        ),
        "release_patterns": (
            re.compile(r"\.(?:pkg|dmg)(?:[?#\"'\s<]|$)", re.IGNORECASE),
            re.compile(r"\bmacos-app-store\b", re.IGNORECASE),
            re.compile(r"\bmac-app-store\b", re.IGNORECASE),
            re.compile(r"\bmac app store\b", re.IGNORECASE),
        ),
    },
}

APPLE_RELEASE_SOURCE_PATHS = (
    WEB / "index.html",
    WEB / "support" / "index.html",
    WEB / "_worker.js",
)


def fail(message: str) -> tuple[str, str]:
    return ("FAIL", message)


def warn(message: str) -> tuple[str, str]:
    return ("WARN", message)


def ok(message: str) -> tuple[str, str]:
    return ("PASS", message)


def skip(message: str) -> tuple[str, str]:
    return ("SKIP", message)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def read_optional(path: Path) -> str | None:
    """Read a referenced source that may not exist in this checkout.

    The audit references a handful of sources that are not present at every
    commit (split-tree files absent from the public history). Callers MUST turn
    a None result into an explicit SKIP finding with a loud reason instead of
    either crashing or silently skipping the check.
    """
    if path.is_file():
        return path.read_text(encoding="utf-8", errors="replace")
    return None


def parse_headers_file(text: str, for_path: str) -> dict[str, str]:
    """Parses Cloudflare Pages' `_headers` file format: a path line followed
    by indented `Name: value` lines, blocks separated by blank lines."""
    values: dict[str, str] = {}
    in_block = False
    for line in text.splitlines():
        if not line.strip():
            in_block = False
            continue
        if not line[:1].isspace():
            in_block = line.strip() == for_path
            continue
        if in_block and ":" in line:
            name, _, value = line.strip().partition(":")
            values[name.strip()] = value.strip()
    return values


def audit_website_headers() -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    values = parse_headers_file(read(WEB / "_headers"), "/*")
    required = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
        "Origin-Agent-Cluster",
        "X-Permitted-Cross-Domain-Policies",
    ]
    for name in required:
        results.append(ok(f"header present: {name}") if values.get(name) else fail(f"missing header: {name}"))
    hsts = values.get("Strict-Transport-Security", "")
    results.append(
        ok("HSTS uses a two-year max-age and covers subdomains")
        if "max-age=63072000" in hsts and "includesubdomains" in hsts.lower()
        else fail("HSTS must use max-age=63072000 and includeSubDomains")
    )
    csp = values.get("Content-Security-Policy", "")
    for directive in ["default-src 'self'", "object-src 'none'", "frame-ancestors 'none'", "base-uri 'self'"]:
        results.append(ok(f"CSP contains {directive}") if directive in csp else fail(f"CSP missing {directive}"))
    website = read(WEB / "index.html")
    worker_csp_match = re.search(
        r'CONTENT_SECURITY_POLICY\s*=\s*"([^"]+)"', read(WEB / "_worker.js")
    )
    worker_csp = worker_csp_match.group(1) if worker_csp_match else ""
    csp_values = {
        "Cloudflare Pages": csp,
        "Cloudflare Pages Worker": worker_csp,
    }
    inline_scripts = re.findall(r"<script>(.*?)</script>", website, flags=re.DOTALL)
    if len(inline_scripts) != 1:
        results.append(fail("website must contain exactly one hash-bound inline script"))
    else:
        digest = base64.b64encode(
            hashlib.sha256(inline_scripts[0].encode("utf-8")).digest()
        ).decode("ascii")
        required_hash = f"'sha256-{digest}'"
        # _headers rules are skipped by Cloudflare Pages for any response that
        # passes through this advanced-mode Worker (redirects, /api/*, and the
        # ASSETS pass-through). Without a matching runtime CSP, those responses
        # would ship with every other security header except CSP.
        results.append(
            ok("Worker CSP constant matches the static Cloudflare Pages _headers CSP")
            if worker_csp and worker_csp == csp
            else fail("Worker CSP constant is missing or has drifted from web/_headers")
        )
        worker_source = read(WEB / "_worker.js")
        worker_applies_csp = bool(
            re.search(
                r'contentType\.includes\("text/html"\)[\s\S]{0,80}headers\.set\(\s*"Content-Security-Policy"',
                worker_source,
            )
        )
        results.append(
            ok("Worker applies CSP at runtime to HTML responses lacking one")
            if worker_applies_csp
            else fail("Worker does not apply CSP to responses it generates or proxies")
        )
        invalid = [
            host
            for host, policy in csp_values.items()
            if required_hash not in policy
            or "script-src 'self' 'unsafe-inline'" in policy
        ]
        results.append(
            fail(
                "inline script is not hash-bound without unsafe-inline on: "
                + ", ".join(invalid)
            )
            if invalid
            else ok("inline script is CSP hash-bound on both the static _headers and the Worker")
        )
    inline_styles = re.findall(r"<style>(.*?)</style>", website, flags=re.DOTALL)
    if len(inline_styles) != 1:
        results.append(fail("website must contain exactly one hash-bound inline style"))
    else:
        style_digest = base64.b64encode(
            hashlib.sha256(inline_styles[0].encode("utf-8")).digest()
        ).decode("ascii")
        required_style_hash = f"'sha256-{style_digest}'"
        invalid_style_hosts = [
            host
            for host, policy in csp_values.items()
            if required_style_hash not in policy
            or "style-src 'self' 'unsafe-inline'" in policy
        ]
        results.append(
            fail(
                "inline style is not hash-bound without unsafe-inline on: "
                + ", ".join(invalid_style_hosts)
            )
            if invalid_style_hosts
            else ok("inline style is CSP hash-bound on both the static _headers and the Worker")
        )
    worker_csp_text = worker_csp
    placeholder_hosts = [
        host
        for host, policy in (
            ("Cloudflare Pages", csp),
            ("Cloudflare Pages Worker", worker_csp_text),
        )
        if re.search(r"(?i)redacted|placeholder|sha256-<", policy or "")
    ]
    results.append(
        fail("CSP contains a placeholder hash on: " + ", ".join(placeholder_hosts))
        if placeholder_hosts
        else ok("CSP hash pins are not placeholders")
    )
    return results


def audit_redirects() -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    text = read(WEB / "_redirects")
    insecure = [line for line in text.splitlines() if " http://" in line]
    if insecure:
        results.append(fail("_redirects contains insecure redirect target"))
    else:
        results.append(ok("_redirects redirect targets are HTTPS or relative"))
    forced_statuses = re.findall(
        r"(?m)^\s*\S+\s+\S+\s+(?:200|301|302|303|307|308)!\s*$",
        read(WEB / "_redirects"),
    )
    results.append(
        fail("_redirects uses Netlify-only forced status syntax rejected by Cloudflare Pages")
        if forced_statuses
        else ok("_redirects uses Cloudflare Pages-compatible status syntax")
    )
    redirects = read(WEB / "_redirects")
    worker = read(WEB / "_worker.js")
    privacy_route_ready = (
        "/privacy /index.html 200" not in redirects
        and "/privacy/ /index.html 200" not in redirects
        and '["/privacy", "/privacy/"]' in worker
        and '["/privacy/", "/privacy/"]' in worker
        and "dedicatedDocumentRoutes.get(url.pathname)" in worker
    )
    results.append(
        ok("canonical /privacy/ route is mapped by the advanced-mode Pages Worker")
        if privacy_route_ready
        else fail("canonical /privacy/ route is not mapped consistently")
    )
    privacy_page = read(WEB / "privacy" / "index.html")
    dedicated_privacy_heading = re.search(
        r"<h1[^>]*>\s*Privacy Policy\s*</h1>",
        privacy_page,
        flags=re.IGNORECASE,
    )
    results.append(
        ok("dedicated /privacy/ document is headed Privacy Policy")
        if dedicated_privacy_heading
        else fail("dedicated /privacy/ document is not headed Privacy Policy")
    )
    download_redirect_lines = [
        line.strip()
        for line in redirects.splitlines()
        if line.strip() and not line.strip().startswith("#") and "/downloads" in line
    ]
    results.append(
        fail("_redirects publishes a download placeholder: " + "; ".join(download_redirect_lines))
        if download_redirect_lines
        else ok("_redirects does not publish download placeholders")
    )
    worker_empty_table = "const downloadRedirects = new Map();" in worker
    worker_routes_download_assets = (
        'if (target) return { action: "redirect", target };' not in worker
        and "Response.redirect(downloadDecision.target" not in worker
        and 'return { action: "asset" };' in worker
        and 'return { action: "not_found" };' in worker
        and "downloadManifestBoundPaths" in worker
        and 'deliveryUrl.origin !== "https://winsvpn.org"' in worker
        and 'downloadDecision.action === "asset"' in worker
        and 'contentType.toLowerCase().includes("text/html")' in worker
        and '"x-wins-download-route": "static-asset"' in worker
    )
    github_download_placeholder = (
        "winsvpn-downloads/releases/download/" in without_pinned_github_release(worker)
    )
    if not worker_empty_table or not worker_routes_download_assets or github_download_placeholder:
        results.append(
            fail("Worker download asset path is not fail-closed against placeholder redirects and HTML fallback")
        )
    else:
        results.append(ok("Worker serves only manifest-bound /downloads assets, rejects HTML fallback, and has zero placeholder redirects"))
    return results


def audit_dom() -> list[tuple[str, str]]:
    text = read(WEB / "index.html")
    results: list[tuple[str, str]] = []
    dangerous = ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("]
    for item in dangerous:
        if item in text:
            results.append(fail(f"index.html uses dangerous DOM sink: {item}"))
        else:
            results.append(ok(f"index.html avoids {item}"))
    inline_handlers = re.findall(r"\son[a-z0-9_-]+\s*=", text, flags=re.IGNORECASE)
    results.append(
        fail("index.html contains inline event handlers")
        if inline_handlers
        else ok("index.html avoids inline event handlers")
    )
    dynamic_inline_styles = re.findall(
        r"(?:\sstyle\s*=|\.style\.)", text, flags=re.IGNORECASE
    )
    results.append(
        fail("index.html contains CSP-bypassing inline style mutations")
        if dynamic_inline_styles
        else ok("index.html avoids inline style attributes and mutations")
    )
    http_refs = re.findall(r"(?<!https:)http://[^\s\"')<]+", text)
    if http_refs:
        results.append(fail(f"index.html contains plain HTTP references: {', '.join(sorted(set(http_refs))[:5])}"))
    else:
        results.append(ok("index.html has no plain HTTP references"))
    prominent_privacy_heading = re.search(
        r'<h[12][^>]*\bid=["\']privacy-policy["\'][^>]*>\s*'
        r'(?:Privacy Policy|Privacy and Legal Summary)\s*</h[12]>',
        text,
        flags=re.IGNORECASE,
    )
    if prominent_privacy_heading:
        results.append(ok("homepage privacy summary is explicitly labeled by a prominent anchored heading"))
    else:
        results.append(
            fail(
                "privacy policy must use an explicit Privacy Policy h1/h2 heading "
                "with id=privacy-policy"
            )
        )
    installed_app_disclosure_markers = (
        "Android installed-app visibility for split tunneling.",
        "first shows a separate installed-app access disclosure",
        "only after the user affirmatively chooses <em>Continue</em>",
        "choosing <em>Not now</em> leaves the inventory untouched",
        "The full inventory is not uploaded to Win's VPN, shared with third parties, sold, or used for advertising or analytics",
        "clearing Win's VPN app data or uninstalling the app",
    )
    missing_installed_app_disclosures = [
        marker for marker in installed_app_disclosure_markers if marker not in text
    ]
    if missing_installed_app_disclosures:
        results.append(
            fail(
                "privacy policy does not fully disclose Android installed-app "
                "visibility, local-only use, sharing limits, and deletion"
            )
        )
    else:
        results.append(
            ok(
                "privacy policy discloses Android installed-app visibility, "
                "local-only split-tunnel use, non-sharing, and deletion"
            )
        )
    # The app transmits a locally generated, per-install random identifier, not
    # Settings.Secure.ANDROID_ID. The policy previously named ANDROID_ID, which
    # over-stated collection; naming it again would re-introduce that error.
    device_id_markers = (
        "Device or other ID disclosure.",
        "random app-install identifier",
        "not derived from a device hardware identifier",
        "linked to the account",
        "not used for advertising or tracking",
        "deleted or overwritten when the device is deactivated",
    )
    results.append(
        ok("privacy policy accurately discloses Device or other ID handling")
        if all(marker in text for marker in device_id_markers)
        and "Settings.Secure.ANDROID_ID" not in text
        else fail("privacy policy is missing or over-states Device or other ID handling")
    )
    metadata_artifacts = [
        path.relative_to(WEB).as_posix()
        for path in WEB.rglob("*")
        if path.is_file() and path.name in {".DS_Store", "Thumbs.db", "desktop.ini"}
    ]
    if metadata_artifacts:
        results.append(
            fail(
                "public website contains OS metadata artifacts: "
                + ", ".join(metadata_artifacts)
            )
        )
    else:
        results.append(ok("public website contains no OS metadata artifacts"))
    return results


def audit_functions() -> list[tuple[str, str]]:
    # Netlify Functions (one file per public endpoint) were replaced by
    # /api/site/* routes inside this single Cloudflare Pages Worker; the
    # same properties -- no wildcard CORS, no risky server-side primitives,
    # some abuse throttling present -- are checked against the whole file
    # rather than per-route, since a wildcard header or eval() anywhere in
    # it is a real concern regardless of which route reaches that code.
    results: list[tuple[str, str]] = []
    path = WEB / "_worker.js"
    text = read(path)
    label = str(path.relative_to(ROOT))
    if 'Access-Control-Allow-Origin": "*"' in text or '"Access-Control-Allow-Origin": "*"' in text:
        results.append(fail(f"{label} allows wildcard CORS"))
    else:
        results.append(ok(f"{label} avoids wildcard CORS"))
    for item in ["eval(", "child_process", "Function("]:
        if item in text:
            results.append(fail(f"{label} uses risky server-side primitive: {item}"))
        else:
            results.append(ok(f"{label} avoids {item}"))
    if "requireQuota" in text or "isolateLocalRateLimited" in text:
        results.append(ok(f"{label} has abuse throttling on its public endpoints"))
    else:
        results.append(warn(f"{label} has no abuse throttling on its public endpoints"))
    return results


def audit_payment_provider() -> list[tuple[str, str]]:
    """Fail if an obsolete checkout provider returns to executable sources."""
    results: list[tuple[str, str]] = []
    obsolete_function = ROOT / "wins-backend" / "netlify" / "functions" / "lemon-squeezy.js"
    if obsolete_function.exists():
        results.append(fail("obsolete Lemon Squeezy webhook is present in the deployable tree"))
    else:
        results.append(ok("deployable billing code contains no legacy Lemon Squeezy webhook"))

    active_sources = {
        ROOT / ".env.example",
        WEB / "index.html",
        WEB / "_worker.js",
        ROOT / "cloudflare" / "sync-worker.js",
        ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh",
        ROOT / "server" / "wins_core_server_setup_ONETOUCH.sh",
        ROOT / "tools" / "wins_deployment_preseed.ps1",
    }
    deployable_roots = (
        WEB,
        ROOT / "cloudflare",
        ROOT / "server",
        ROOT / "lib",
        ROOT / "android" / "app",
        ROOT / "ios" / "Runner",
        ROOT / "macos" / "Runner",
        ROOT / "windows" / "runner",
        ROOT / "linux" / "runner",
        ROOT / "installer",
        ROOT / ".github" / "workflows",
    )
    text_suffixes = {
        ".c", ".cc", ".conf", ".cpp", ".css", ".dart", ".gradle", ".h",
        ".html", ".iss", ".java", ".js", ".json", ".kt", ".kts", ".m",
        ".mm", ".plist", ".ps1", ".py", ".service", ".sh", ".swift",
        ".timer", ".toml", ".ts", ".xml", ".yaml", ".yml",
    }
    ignored_parts = {"build", ".dart_tool", ".gradle", "node_modules", "Pods", "ephemeral"}
    for root in deployable_roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if (
                path.is_file()
                and path.suffix.lower() in text_suffixes
                and not ignored_parts.intersection(path.relative_to(ROOT).parts)
            ):
                active_sources.add(path)
    offending = [
        str(path.relative_to(ROOT))
        for path in sorted(active_sources)
        if path.is_file() and re.search(r"lemon[ _-]?squeezy|lemonsqueezy", read(path), re.IGNORECASE)
    ]
    if offending:
        results.append(fail(f"obsolete billing provider referenced by active source: {', '.join(offending)}"))
    else:
        results.append(ok("all deployable website, provisioning, and five-OS app sources are PayPal-only"))

    control_path = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"
    control = read_optional(control_path)
    if control is None:
        return [
            skip(
                "PayPal provisioning contract cannot be checked because the "
                f"referenced provisioning source is missing from this checkout: "
                f"{control_path.relative_to(ROOT)}"
            )
        ]
    paypal_markers = (
        '@app.post("/webhook/paypal")',
        "verify_paypal_webhook_signature",
        "Ensuring PayPal OAuth, webhook identity, and provisioning events",
        "PAYPAL_WEBHOOK_AUTO_ENSURE",
    )
    missing = [marker for marker in paypal_markers if marker not in control]
    if missing:
        results.append(fail(f"PayPal-only provisioning contract is incomplete: {missing}"))
    else:
        results.append(ok("PayPal webhook verification and automatic provisioning contract is present"))
    return results


def audit_legal_contract_parity() -> list[tuple[str, str]]:
    """Keep the public website, client clickwrap, and hub contract in lockstep."""
    results: list[tuple[str, str]] = []
    patterns = {
        "website": r"Version\s+(\d{4}-\d{2}-\d{2}\.v\d+)",
        "client": r"_legalDocumentVersion\s*=\s*['\"]([^'\"]+)['\"]",
        "control hub": r"LEGAL_DOCUMENT_VERSION_DEFAULT=['\"]([^'\"]+)['\"]",
    }
    source_paths = {
        "website": WEB / "index.html",
        "client": ROOT / "lib" / "main.dart",
        "control hub": ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh",
    }
    values: dict[str, str] = {}
    for label, pattern in patterns.items():
        path = source_paths[label]
        text = read_optional(path)
        if text is None:
            results.append(
                skip(
                    f"legal contract version for {label} cannot be read because "
                    f"the referenced source is missing from this checkout: "
                    f"{path.relative_to(ROOT)}"
                )
            )
            continue
        match = re.search(pattern, text)
        if match:
            values[label] = match.group(1)
        else:
            results.append(fail(f"could not determine {label} legal contract version"))
    if len(values) == len(patterns):
        if len(set(values.values())) == 1:
            results.append(ok(f"website, client, and control hub share legal contract {next(iter(values.values()))}"))
        else:
            results.append(fail(f"legal contract version mismatch: {values}"))
    elif values:
        results.append(fail(f"legal contract version parity cannot be proven: {values}"))
    return results


def audit_split_tunnel_claim_parity() -> list[tuple[str, str]]:
    """Keep public/support claims aligned with actual five-platform behavior."""
    sources = {
        "website": WEB / "index.html",
        "control Hoppy": ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh",
        "Core Hoppy": ROOT / "server" / "wins_core_server_setup_ONETOUCH.sh",
        "client UI": ROOT / "lib" / "main.dart",
    }
    required = ("android", "windows", "linux", "apple", "mdm", "destination", "per-app")
    results: list[tuple[str, str]] = []
    missing_sources: list[str] = []
    missing: dict[str, list[str]] = {}
    for label, path in sources.items():
        text = read_optional(path)
        if text is None:
            missing_sources.append(f"{label} ({path.relative_to(ROOT)})")
            continue
        absent = [marker for marker in required if marker not in text.lower()]
        if absent:
            missing[label] = absent
    for source in missing_sources:
        results.append(
            skip(
                "five-platform split-tunnel claim parity cannot scan a missing "
                f"referenced source from this checkout: {source}"
            )
        )
    if missing:
        results.append(fail(f"five-platform split-tunnel claim parity is incomplete: {missing}"))
    elif missing_sources:
        results.append(
            ok(
                "split-tunnel claims distinguish Android native per-app, Windows destination, "
                "Linux launcher-scoped per-app, and Apple destination/MDM limits "
                "across every referenced source present in this checkout"
            )
        )
    else:
        results.append(
            ok(
                "split-tunnel claims distinguish Android native per-app, Windows destination, "
                "Linux launcher-scoped per-app, and Apple destination/MDM limits"
            )
        )
    return results


def audit_secrets() -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    scan_paths = [
        WEB / "index.html",
        WEB / "_worker.js",
        # Published release records, receipts and waiver (Argon F-4).
        *sorted((WEB / "releases").glob("*.json")),
        *sorted((WEB / "downloads").glob("*.json")),
    ]
    findings = []
    for path in scan_paths:
        text = read(path)
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                findings.append(str(path.relative_to(ROOT)))
    for path in DEPLOYMENT_SCRIPTS:
        text = read_optional(path)
        if text is None:
            results.append(
                skip(
                    "deployment secret-literal scan skipped because the "
                    f"referenced source is missing from this checkout: "
                    f"{path.relative_to(ROOT)}"
                )
            )
            continue
        for pattern in DEPLOYMENT_SECRET_PATTERNS:
            if pattern.search(text):
                findings.append(str(path.relative_to(ROOT)))
    for path in CLIENT_SECRET_SOURCES:
        text = read_optional(path)
        if text is None:
            results.append(
                skip(
                    "client secret-literal scan skipped because the "
                    f"referenced source is missing from this checkout: "
                    f"{path.relative_to(ROOT)}"
                )
            )
            continue
        for pattern in CLIENT_SECRET_PATTERNS:
            if pattern.search(text):
                findings.append(str(path.relative_to(ROOT)))
    if findings:
        results.append(
            fail(
                "secret-like literal found in public website or deployment files: "
                + ", ".join(sorted(set(findings)))
            )
        )
    else:
        results.append(ok("no secret-like literals found in public website or deployment files"))
    return results


def public_download_marker_errors(web_root: Path = WEB) -> list[str]:
    """Reject known stale binaries and mutable release routes in public source."""
    errors: list[str] = []
    for path in sorted(candidate for candidate in web_root.rglob("*") if candidate.is_file()):
        if path.suffix.lower() not in {".html", ".js", ".json", ".txt"} and path.name not in {
            "_redirects",
            "_headers",
        }:
            continue
        if path.name == "download-custody.json" and path.parent.name == "releases":
            continue
        content = without_pinned_github_release(read(path))
        for marker, description in STALE_PUBLIC_DOWNLOAD_MARKERS.items():
            if marker.lower() in content.lower():
                errors.append(f"{path.relative_to(web_root)} contains {description}")
    return errors


def static_public_binary_link_errors(web_root: Path = WEB) -> list[str]:
    """Reject hard-coded binary anchors that bypass the manifest verifier."""
    errors: list[str] = []
    for path in sorted(web_root.rglob("*.html")):
        if not path.is_file():
            continue
        content = read(path)
        for match in re.finditer(
            r"<a\b[^>]*\bhref\s*=\s*([\"'])(?P<href>.*?)\1",
            content,
            flags=re.IGNORECASE | re.DOTALL,
        ):
            href = html.unescape(match.group("href")).strip()
            parsed = urlparse(href)
            if PUBLIC_BINARY_PATH_RE.search(unquote(parsed.path)):
                errors.append(
                    f"{path.relative_to(web_root)} hard-codes a public binary link "
                    f"outside the verified manifest renderer: {href}"
                )
    return errors


def find_android_sdk_tool(name: str) -> Path | None:
    executable_names = (name, f"{name}.bat", f"{name}.cmd")
    for executable_name in executable_names:
        found = shutil.which(executable_name)
        if found:
            return Path(found)

    roots = [
        os.environ.get("ANDROID_SDK_ROOT"),
        os.environ.get("ANDROID_HOME"),
        str(Path.home() / ".local" / "android-sdk"),
        str(Path.home() / "Library" / "Android" / "sdk"),
    ]
    candidates: list[Path] = []
    for raw_root in roots:
        if not raw_root:
            continue
        root = Path(raw_root)
        if name == "apksigner":
            candidates.extend(root.glob(f"build-tools/*/{name}*"))
        elif name == "apkanalyzer":
            candidates.extend(root.glob(f"cmdline-tools/*/bin/{name}*"))
    return sorted((path for path in candidates if path.is_file()), reverse=True)[0] if candidates else None


def read_public_artifact_bytes(path: Path) -> bytes:
    """Read one immutable regular-file view of a public artifact."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if os.name == "nt":
        flags |= getattr(os, "O_BINARY", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > MAX_PUBLIC_ARTIFACT_BYTES
        ):
            raise OSError("artifact must be one non-empty, single-link regular file")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise OSError("artifact changed or became truncated during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise OSError("artifact grew during read")
        after = os.fstat(descriptor)
        named = path.lstat()
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if identity(before) != identity(after) or identity(before) != identity(named):
            raise OSError("artifact was replaced or mutated during read")
        return b"".join(chunks)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _safe_android_archive_member(info: zipfile.ZipInfo) -> bool:
    path = info.filename
    pure = Path(path.replace("\\", "/"))
    mode = stat.S_IFMT(info.external_attr >> 16)
    return (
        path == path.replace("\\", "/")
        and not pure.is_absolute()
        and ".." not in pure.parts
        and not info.is_dir()
        and mode != stat.S_IFLNK
        and 0 < info.file_size <= MAX_ANDROID_ENGINE_BYTES
    )


def android_engine_provenance_errors(
    artifact_bytes: bytes,
    *,
    release_engine_root: Path = ANDROID_RELEASE_ENGINE_ROOT,
) -> list[str]:
    """Bind the public APK's Winn v3 payload to the current release engines."""
    expected = {
        f"lib/{abi}/{engine}"
        for abi in PLATFORM_ARCHITECTURES["android"]
        for engine in ANDROID_REQUIRED_ENGINE_BASENAMES
    }
    try:
        with zipfile.ZipFile(io.BytesIO(artifact_bytes)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ANDROID_ARCHIVE_MEMBERS:
                return ["Android APK contains too many archive members"]
            by_name: dict[str, list[zipfile.ZipInfo]] = {}
            unexpected: list[str] = []
            for info in infos:
                normalized = info.filename.replace("\\", "/")
                basename = normalized.rsplit("/", 1)[-1].lower()
                if basename in ANDROID_FORBIDDEN_ENGINE_BASENAMES:
                    unexpected.append(info.filename)
                    continue
                if basename not in ANDROID_REQUIRED_ENGINE_BASENAMES:
                    continue
                by_name.setdefault(normalized, []).append(info)
                if normalized not in expected:
                    unexpected.append(info.filename)
            errors: list[str] = []
            if unexpected:
                errors.append(
                    "Android APK carries release engines outside the exact current ABI inventory: "
                    + ", ".join(sorted(unexpected))
                )
            for member in sorted(expected):
                matches = by_name.get(member, [])
                if len(matches) != 1 or not _safe_android_archive_member(matches[0]):
                    errors.append(
                        f"Android APK requires one safe non-empty {member} release engine"
                    )
            if errors:
                return errors

            for abi in sorted(PLATFORM_ARCHITECTURES["android"]):
                member = f"lib/{abi}/libwinnengine.so"
                source = release_engine_root / abi / "libwinnengine.so"
                if source.is_symlink() or not source.is_file():
                    errors.append(
                        f"current Winn v3 release engine is unavailable for {abi}"
                    )
                    continue
                try:
                    current = read_public_artifact_bytes(source)
                    embedded = archive.read(by_name[member][0])
                except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                    errors.append(f"cannot bind the current Winn v3 {abi} engine: {exc}")
                    continue
                if hashlib.sha256(embedded).digest() != hashlib.sha256(current).digest():
                    errors.append(
                        f"Android APK Winn v3 engine for {abi} is not the exact current release payload"
                    )
            return errors
    except (OSError, zipfile.BadZipFile) as exc:
        return [f"Android public artifact is not a valid APK archive: {exc}"]


_WINDOWS_GATE_MODULE = None


def load_windows_artifact_gate():
    global _WINDOWS_GATE_MODULE
    if _WINDOWS_GATE_MODULE is not None:
        return _WINDOWS_GATE_MODULE
    if WINDOWS_ARTIFACT_GATE.is_symlink() or not WINDOWS_ARTIFACT_GATE.is_file():
        raise RuntimeError("reviewed Windows artifact gate is missing or symbolic")
    resolved = WINDOWS_ARTIFACT_GATE.resolve(strict=True)
    if resolved != WINDOWS_ARTIFACT_GATE:
        raise RuntimeError("reviewed Windows artifact gate resolved elsewhere")
    name = "winsvpn_website_windows_artifact_gate"
    spec = importlib.util.spec_from_file_location(name, resolved)
    if spec is None or spec.loader is None:
        raise RuntimeError("reviewed Windows artifact gate cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(name, None)
        raise
    if Path(module.__file__).resolve(strict=True) != resolved:
        raise RuntimeError("reviewed Windows artifact gate loaded from an unexpected path")
    _WINDOWS_GATE_MODULE = module
    return module


def windows_authenticode_cryptographic_errors(
    filename: str,
    data: bytes,
    artifact: dict[str, object],
    *,
    gate_module=None,
) -> list[str]:
    """Cryptographically verify the exact PE and bind its current version/signer."""
    try:
        gate = load_windows_artifact_gate() if gate_module is None else gate_module
        if gate.canonical_windows_release() != CANONICAL_RELEASE:
            raise RuntimeError("reviewed Windows release identity is not current")
        versions = gate.pe_version_info(filename, data)
        expected_file_version = f"{CANONICAL_VERSION_NAME}.{CANONICAL_VERSION_CODE}"
        if (
            versions.get("ProductVersion") != CANONICAL_VERSION_NAME
            or versions.get("FileVersion") != expected_file_version
        ):
            raise RuntimeError("installer VERSIONINFO is not 1.0.16.33")
        leaf = gate.authenticode_leaf_identity(filename, data)
        policy = gate.authenticode_custody_policy(filename, data, leaf)
        verified = gate._verify_outer_pe_authenticode(filename, data, policy)
        signature = artifact.get("signature")
        verification = artifact.get("windows_verification")
        expected_signer = (
            signature.get("sha256") if isinstance(signature, dict) else None
        )
        approved_signer = (
            verification.get("approved_signer_certificate_sha256")
            if isinstance(verification, dict)
            else None
        )
        if (
            not isinstance(verified, dict)
            or verified.get("sha256") != expected_signer
            or verified.get("sha256") != approved_signer
        ):
            raise RuntimeError("cryptographic signer is not the manifest-approved signer")
    except Exception as exc:
        return [f"Windows installer Authenticode cryptographic verification failed: {exc}"]
    return []


def android_public_artifact_errors(
    package_output: str,
    signature_output: str,
    *,
    package_returncode: int = 0,
    signature_returncode: int = 0,
    version_name_output: str | None = None,
    version_code_output: str | None = None,
    version_name_returncode: int = 0,
    version_code_returncode: int = 0,
) -> list[str]:
    """Validate the exact public APK identity and reviewed release signer."""
    errors: list[str] = []
    application_id = package_output.strip()
    if package_returncode or application_id != ANDROID_PUBLIC_APPLICATION_ID:
        errors.append(
            "Android APK application ID is not the production org.winsvpn.app identity"
        )
    if version_name_output is not None or version_code_output is not None:
        version_name = (version_name_output or "").strip()
        version_code = (version_code_output or "").strip()
        if (
            version_name_returncode
            or version_code_returncode
            or version_name != CANONICAL_VERSION_NAME
            or version_code != CANONICAL_VERSION_CODE
        ):
            errors.append(
                "Android APK version is not the current 1.0.16+33 release identity"
            )
    if signature_returncode:
        errors.append("Android APK signature verification failed")
        return errors
    if not re.search(r"Verified using v[23](?:\.\d+)? scheme .*:\s*true", signature_output):
        errors.append("Android APK has no verified v2/v3 release signature")
    signer_count = re.search(r"Number of signers:\s*(\d+)", signature_output)
    if signer_count is None or signer_count.group(1) != "1":
        errors.append("Android APK must have exactly one verified signer")
    signer_digests = {
        match.replace(":", "").lower()
        for match in re.findall(
            r"certificate SHA-256 digest:\s*([0-9a-fA-F:]{64,95})",
            signature_output,
        )
    }
    if signer_digests != {ANDROID_PUBLIC_SIGNER_SHA256}:
        errors.append("Android APK is not signed by the reviewed production upload certificate")
    return errors


def windows_pe_certificate_table_errors(data: bytes) -> list[str]:
    """Classify PE WIN_CERTIFICATE structure only; never claim signature validity."""
    try:
        if len(data) < 64 or data[:2] != b"MZ":
            raise ValueError("not a PE image")
        pe_offset = struct.unpack_from("<I", data, 60)[0]
        if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise ValueError("invalid PE header")
        optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
        optional = pe_offset + 24
        if optional + optional_size > len(data):
            raise ValueError("truncated optional header")
        magic = struct.unpack_from("<H", data, optional)[0]
        if magic == 0x20B:
            directory_count_offset = optional + 108
            directories_offset = optional + 112
        elif magic == 0x10B:
            directory_count_offset = optional + 92
            directories_offset = optional + 96
        else:
            raise ValueError("unsupported PE optional header")
        directory_count = struct.unpack_from("<I", data, directory_count_offset)[0]
        if directory_count <= 4 or directories_offset + 40 > optional + optional_size:
            raise ValueError("missing PE certificate directory")
        certificate_offset, certificate_size = struct.unpack_from(
            "<II", data, directories_offset + (4 * 8)
        )
        if (
            certificate_offset == 0
            or certificate_size < 8
            or certificate_offset % 8
            or certificate_offset + certificate_size > len(data)
        ):
            raise ValueError("missing embedded PE certificate table")
        length, revision, certificate_type = struct.unpack_from(
            "<IHH", data, certificate_offset
        )
        if (
            length < 8
            or length > certificate_size
            or certificate_offset + length > len(data)
            or revision != 0x0200
            or certificate_type != 0x0002
        ):
            raise ValueError("invalid embedded WIN_CERTIFICATE record")
    except (ValueError, struct.error) as exc:
        return [f"Windows installer has no structurally usable PE certificate table: {exc}"]
    return []


def windows_winverifytrust_receipt_errors(
    artifact_path: Path,
    artifact: dict[str, object],
    downloads_dir: Path,
) -> list[str]:
    """Require manifest-bound Windows trust evidence produced on Windows.

    PE certificate-table presence is not cryptographic verification. Publication
    requires a receipt that records WinVerifyTrust success, a trusted timestamp,
    and the exact manifest-approved signer and artifact identities.
    """
    verification = artifact.get("windows_verification")
    if not isinstance(verification, dict):
        return ["Windows publication requires a manifest-bound WinVerifyTrust receipt"]
    expected_keys = {
        "kind",
        "receipt_filename",
        "receipt_sha256",
        "approved_signer_subject",
        "approved_signer_certificate_sha256",
    }
    if set(verification) != expected_keys or verification.get("kind") != "winverifytrust_receipt_v1":
        return ["Windows WinVerifyTrust receipt binding has an invalid schema"]
    receipt_filename = verification.get("receipt_filename")
    receipt_sha256 = verification.get("receipt_sha256")
    approved_subject = verification.get("approved_signer_subject")
    approved_signer_sha256 = verification.get("approved_signer_certificate_sha256")
    if (
        not isinstance(receipt_filename, str)
        or receipt_filename != f"{artifact_path.name}.authenticode.json"
        or not isinstance(receipt_sha256, str)
        or not re.fullmatch(r"[a-f0-9]{64}", receipt_sha256)
        or not isinstance(approved_subject, str)
        or not approved_subject.strip()
        or len(approved_subject) > 512
        or not isinstance(approved_signer_sha256, str)
        or not re.fullmatch(r"[a-f0-9]{64}", approved_signer_sha256)
    ):
        return ["Windows WinVerifyTrust receipt binding is incomplete"]

    receipt_path = downloads_dir / receipt_filename
    if receipt_path.is_symlink() or not receipt_path.is_file():
        return ["Windows WinVerifyTrust receipt is missing or is a symlink"]
    try:
        receipt_bytes = receipt_path.read_bytes()
    except OSError as exc:
        return [f"Windows WinVerifyTrust receipt is unreadable: {exc}"]
    errors: list[str] = []
    if hashlib.sha256(receipt_bytes).hexdigest() != receipt_sha256:
        errors.append("Windows WinVerifyTrust receipt hash mismatch")
        return errors
    try:
        receipt = json.loads(receipt_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return [f"Windows WinVerifyTrust receipt is invalid JSON: {exc}"]
    required = {
        "schema",
        "artifact_filename",
        "artifact_sha256",
        "artifact_bytes",
        "winverifytrust_status",
        "authenticode_status",
        "signature_verified",
        "timestamp_verified",
        "signer_subject",
        "signer_certificate_sha256",
        "timestamp_certificate_sha256",
        "timestamp_utc",
    }
    if not isinstance(receipt, dict) or set(receipt) != required:
        return ["Windows WinVerifyTrust receipt does not have its exact schema"]
    expected_artifact_sha256 = artifact.get("sha256")
    expected_artifact_bytes = artifact.get("bytes")
    if (
        receipt.get("schema") != "winsvpn-windows-publication-winverifytrust-v1"
        or receipt.get("artifact_filename") != artifact_path.name
        or receipt.get("artifact_sha256") != expected_artifact_sha256
        or receipt.get("artifact_bytes") != expected_artifact_bytes
    ):
        errors.append("Windows WinVerifyTrust receipt does not bind the exact artifact")
    if (
        receipt.get("winverifytrust_status") != 0
        or receipt.get("authenticode_status") != "Valid"
        or receipt.get("signature_verified") is not True
    ):
        errors.append("Windows WinVerifyTrust receipt does not prove a valid signature")
    if (
        receipt.get("signer_subject") != approved_subject
        or receipt.get("signer_certificate_sha256") != approved_signer_sha256
    ):
        errors.append("Windows WinVerifyTrust receipt signer is not the manifest-approved signer")
    timestamp_certificate_sha256 = receipt.get("timestamp_certificate_sha256")
    timestamp_utc = receipt.get("timestamp_utc")
    if (
        receipt.get("timestamp_verified") is not True
        or not isinstance(timestamp_certificate_sha256, str)
        or not re.fullmatch(r"[a-f0-9]{64}", timestamp_certificate_sha256)
        or not isinstance(timestamp_utc, str)
    ):
        errors.append("Windows WinVerifyTrust receipt lacks a trusted timestamp")
    else:
        try:
            parsed_timestamp = datetime.fromisoformat(timestamp_utc.replace("Z", "+00:00"))
            if parsed_timestamp.tzinfo is None or parsed_timestamp.astimezone(timezone.utc) > datetime.now(timezone.utc):
                raise ValueError("invalid timestamp")
        except ValueError:
            errors.append("Windows WinVerifyTrust receipt timestamp is invalid")
    return errors


def _hex64(value: object) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[a-f0-9]{64}", value))


def _receipt_filename_ok(value: object, artifact_filename: object, suffix: str) -> bool:
    if not isinstance(value, str) or not isinstance(artifact_filename, str):
        return False
    return value == f"{artifact_filename}{suffix}" and bool(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+()-]{0,180}", value)
    )


def architecture_binding_errors(platform_id: str, architecture: object, prefix: str) -> list[str]:
    allowed = PLATFORM_ARCHITECTURES[platform_id]
    if not isinstance(architecture, list) or not architecture:
        return [f"{prefix} architecture is missing"]
    if any(not isinstance(item, str) for item in architecture):
        return [f"{prefix} architecture is invalid"]
    if len(architecture) != len(set(architecture)):
        return [f"{prefix} architecture contains duplicates"]
    stale = STALE_ARCHITECTURE_LABELS[platform_id]
    if any(item in stale for item in architecture):
        return [f"{prefix} pins a stale architecture artifact"]
    if any(item not in allowed for item in architecture):
        return [f"{prefix} architecture is not an allowed {platform_id} architecture"]
    if platform_id == "android" and set(architecture) != allowed:
        return [f"{prefix} architecture inventory is not the exact current Android ABI set"]
    if platform_id == "windows" and len(architecture) != 1:
        return [f"{prefix} architecture must bind exactly one current Windows installer architecture"]
    if platform_id == "linux" and len(architecture) != 1:
        return [f"{prefix} architecture must bind exactly one current Linux architecture"]
    if platform_id == "macos" and set(architecture) != allowed:
        return [f"{prefix} architecture inventory is not the exact current macOS set"]
    if platform_id == "ios" and architecture != ["arm64"]:
        return [f"{prefix} architecture inventory is not the exact current iOS set"]
    return []


def canonical_filename_for(
    entry_id: str, architecture: object, *, unsigned: bool = False
) -> str | None:
    if entry_id == "android":
        return None if unsigned else CANONICAL_FILENAMES["android"]
    if entry_id not in DOWNLOAD_ENTRY_ARCHITECTURES:
        return None
    if architecture != [DOWNLOAD_ENTRY_ARCHITECTURES[entry_id]]:
        return None
    if unsigned:
        return UNSIGNED_CANONICAL_FILENAMES.get(entry_id)
    return CANONICAL_FILENAMES.get(entry_id)


def artifact_is_unsigned_waiver(artifact: dict[str, object]) -> bool:
    signature = artifact.get("signature")
    return isinstance(signature, dict) and signature.get("kind") == UNSIGNED_SIGNATURE_KIND


def unsigned_waiver_binding_errors(artifact: dict[str, object], prefix: str) -> list[str]:
    binding = artifact.get("unsigned_waiver")
    signature = artifact.get("signature")
    if (
        not isinstance(binding, dict)
        or set(binding) != UNSIGNED_WAIVER_KEYS
        or binding.get("label") != UNSIGNED_PUBLIC_LABEL
        or binding.get("waiver_filename") != UNSIGNED_WAIVER_FILENAME
        or not _hex64(binding.get("waiver_sha256"))
        or not isinstance(signature, dict)
        or signature.get("sha256") != binding.get("waiver_sha256")
    ):
        return [f"{prefix} unsigned Windows download is not labelled Unsigned by the owner waiver"]
    return []


def receipt_binding_schema_errors(binding: object, artifact_filename: object, expected_kind: str, prefix: str, label: str) -> list[str]:
    if not isinstance(binding, dict) or set(binding) != RECEIPT_BINDING_KEYS:
        return [f"{prefix} requires a manifest-bound {label} receipt"]
    suffix = {
        PRIVACY_RECEIPT_KIND: ".privacy.json",
        RELEASE_RECEIPT_KIND: ".release.json",
        WINN_PROVENANCE_KIND: ".winn.json",
        PUBLICATION_RECEIPT_KIND: ".publication.json",
    }.get(expected_kind, ".json")
    if (
        binding.get("kind") != expected_kind
        or not _receipt_filename_ok(binding.get("receipt_filename"), artifact_filename, suffix)
        or not _hex64(binding.get("receipt_sha256"))
    ):
        return [f"{prefix} {label} receipt binding is incomplete"]
    return []


def winn_provenance_binding_errors(binding: object, artifact_filename: object, prefix: str) -> list[str]:
    if not isinstance(binding, dict) or set(binding) != WINN_BINDING_KEYS:
        return [f"{prefix} requires a manifest-bound Winn provenance receipt"]
    errors = receipt_binding_schema_errors(
        {
            "kind": binding.get("kind"),
            "receipt_filename": binding.get("receipt_filename"),
            "receipt_sha256": binding.get("receipt_sha256"),
        },
        artifact_filename,
        WINN_PROVENANCE_KIND,
        prefix,
        "Winn provenance",
    )
    if binding.get("primary") != WINN_PRIMARY:
        errors.append(f"{prefix} Winn primary is not winn/3")
    if binding.get("fallback") != WINN_FALLBACK:
        errors.append(f"{prefix} Winn fallback is not winn/1")
    if binding.get("fallback_order") != WINN_FALLBACK_ORDER:
        errors.append(f"{prefix} Winn v1 fallback order is not AWG then Xray")
    return errors


def available_artifact_custody_errors(entry_id: str, artifact: dict[str, object], prefix: str) -> list[str]:
    """Require exact 1.0.16+33 identity, architecture, signature, privacy, and receipts."""
    platform_id = DOWNLOAD_ENTRY_PLATFORMS.get(entry_id, entry_id)
    unsigned = artifact_is_unsigned_waiver(artifact)
    expected_keys = set(AVAILABLE_ARTIFACT_CUSTODY_KEYS)
    if platform_id == "windows":
        expected_keys.add("unsigned_waiver" if unsigned else "windows_verification")
    errors: list[str] = []
    digest = artifact.get("sha256")
    if isinstance(digest, str) and digest.lower() == STALE_ANDROID_DEBUG_SHA256:
        errors.append(f"{prefix} pins the stale Android debug APK digest")
    if isinstance(digest, str) and digest.lower() == STALE_WINDOWS_UNSIGNED_SHA256:
        errors.append(f"{prefix} pins the stale unsigned Windows installer digest")
    identity = artifact.get("package_identity")
    if identity == STALE_ANDROID_DEBUG_PACKAGE:
        errors.append(f"{prefix} uses the stale Android debug application ID")
    if unsigned and platform_id != "windows":
        errors.append(f"{prefix} only Windows may ship under the unsigned owner waiver")
        return errors
    if set(artifact) != expected_keys:
        errors.append(
            f"{prefix} available artifact is missing exact 1.0.16+33 custody metadata"
        )
        return errors
    if artifact.get("canonical_release") != CANONICAL_RELEASE:
        errors.append(f"{prefix} is not bound to the current 1.0.16+33 release")
    if identity != PUBLIC_PACKAGE_IDENTITY:
        errors.append(f"{prefix} package identity is not the production org.winsvpn.app identity")
    if artifact.get("version") != CANONICAL_VERSION_NAME:
        errors.append(f"{prefix} version is not the current 1.0.16 identity")
    errors.extend(architecture_binding_errors(platform_id, artifact.get("architecture"), prefix))
    expected_arch = DOWNLOAD_ENTRY_ARCHITECTURES.get(entry_id)
    if expected_arch is not None and artifact.get("architecture") != [expected_arch]:
        errors.append(f"{prefix} architecture does not match its {entry_id} manifest entry")
    expected_name = canonical_filename_for(
        entry_id, artifact.get("architecture"), unsigned=unsigned
    )
    filename = artifact.get("filename")
    if platform_id in {"windows", "android", "linux"}:
        if expected_name is None or filename != expected_name:
            errors.append(f"{prefix} filename is not the exact canonical target filename")
    signature = artifact.get("signature")
    expected_kind = UNSIGNED_SIGNATURE_KIND if unsigned else SIGNATURE_KINDS[platform_id]
    if (
        not isinstance(signature, dict)
        or set(signature) != {"kind", "sha256"}
        or signature.get("kind") != expected_kind
        or not _hex64(signature.get("sha256"))
    ):
        errors.append(f"{prefix} signature binding is incomplete")
    elif platform_id == "android" and signature.get("sha256") != ANDROID_PUBLIC_SIGNER_SHA256:
        errors.append(f"{prefix} is not signed by the reviewed production upload certificate")
    elif platform_id == "windows" and unsigned:
        errors.extend(unsigned_waiver_binding_errors(artifact, prefix))
    elif platform_id == "windows":
        verification = artifact.get("windows_verification")
        approved = (
            verification.get("approved_signer_certificate_sha256")
            if isinstance(verification, dict)
            else None
        )
        if signature.get("sha256") != approved:
            errors.append(f"{prefix} signature does not match the WinVerifyTrust signer")
    filename = artifact.get("filename")
    errors.extend(
        receipt_binding_schema_errors(
            artifact.get("privacy"), filename, PRIVACY_RECEIPT_KIND, prefix, "privacy"
        )
    )
    errors.extend(
        receipt_binding_schema_errors(
            artifact.get("release_receipt"),
            filename,
            RELEASE_RECEIPT_KIND,
            prefix,
            "release",
        )
    )
    errors.extend(winn_provenance_binding_errors(artifact.get("winn_provenance"), filename, prefix))
    errors.extend(
        receipt_binding_schema_errors(
            artifact.get("publication_receipt"),
            filename,
            PUBLICATION_RECEIPT_KIND,
            prefix,
            "publication",
        )
    )
    return errors


def web_download_receipt_file_errors(
    binding: dict[str, object],
    artifact: dict[str, object],
    platform_id: str,
    downloads_dir: Path,
    prefix: str,
    label: str,
    schema: str,
    kind: str,
    *,
    expected_keys: frozenset[str] = WEB_DOWNLOAD_RECEIPT_KEYS,
    extra_expected: dict[str, object] | None = None,
) -> list[str]:
    receipt_filename = binding.get("receipt_filename")
    receipt_sha256 = binding.get("receipt_sha256")
    if not isinstance(receipt_filename, str) or not isinstance(receipt_sha256, str):
        return [f"{prefix} {label} receipt binding is incomplete"]
    receipt_path = downloads_dir / receipt_filename
    if receipt_path.is_symlink() or not receipt_path.is_file():
        return [f"{prefix} {label} receipt is missing or is a symlink"]
    try:
        receipt_bytes = receipt_path.read_bytes()
    except OSError as exc:
        return [f"{prefix} {label} receipt is unreadable: {exc}"]
    if hashlib.sha256(receipt_bytes).hexdigest() != receipt_sha256:
        return [f"{prefix} {label} receipt hash mismatch"]
    try:
        receipt = json.loads(receipt_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return [f"{prefix} {label} receipt is invalid JSON: {exc}"]
    if not isinstance(receipt, dict) or set(receipt) != expected_keys:
        return [f"{prefix} {label} receipt does not have its exact schema"]
    if (
        receipt.get("schema") != schema
        or receipt.get("kind") != kind
        or receipt.get("canonical_release") != CANONICAL_RELEASE
        or receipt.get("platform_id") != platform_id
        or receipt.get("artifact_filename") != artifact.get("filename")
        or receipt.get("artifact_sha256") != artifact.get("sha256")
        or receipt.get("artifact_bytes") != artifact.get("bytes")
        or receipt.get("package_identity") != artifact.get("package_identity")
        or receipt.get("architecture") != artifact.get("architecture")
        or receipt.get("version") != CANONICAL_VERSION_NAME
    ):
        return [f"{prefix} {label} receipt does not bind the exact 1.0.16+33 artifact"]
    extra_expected = extra_expected or {}
    for key, expected in extra_expected.items():
        if receipt.get(key) != expected:
            return [f"{prefix} {label} receipt does not bind Winn v3 primary and Winn v1 fallback"]
    return []


def publication_receipt_file_errors(
    binding: dict[str, object],
    artifact: dict[str, object],
    downloads_dir: Path,
    prefix: str,
) -> list[str]:
    receipt_filename = binding.get("receipt_filename")
    receipt_sha256 = binding.get("receipt_sha256")
    if not isinstance(receipt_filename, str) or not isinstance(receipt_sha256, str):
        return [f"{prefix} publication receipt binding is incomplete"]
    receipt_path = downloads_dir / receipt_filename
    if receipt_path.is_symlink() or not receipt_path.is_file():
        return [f"{prefix} publication receipt is missing or is a symlink"]
    try:
        receipt_bytes = receipt_path.read_bytes()
    except OSError as exc:
        return [f"{prefix} publication receipt is unreadable: {exc}"]
    if hashlib.sha256(receipt_bytes).hexdigest() != receipt_sha256:
        return [f"{prefix} publication receipt hash mismatch"]
    try:
        receipt = json.loads(receipt_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return [f"{prefix} publication receipt is invalid JSON: {exc}"]
    if not isinstance(receipt, dict):
        return [f"{prefix} publication receipt is not a JSON object"]
    if (
        receipt.get("schema") != PUBLICATION_RECEIPT_SCHEMA
        or receipt.get("kind") != PUBLICATION_RECEIPT_KIND
        or receipt.get("canonical_release") != CANONICAL_RELEASE
        or receipt.get("artifact_filename") != artifact.get("filename")
        or receipt.get("artifact_sha256") != artifact.get("sha256")
        or receipt.get("artifact_bytes") != artifact.get("bytes")
    ):
        return [f"{prefix} publication receipt does not bind the exact artifact"]
    return []


def public_binary_identity_errors(
    platform_id: str,
    artifact_path: Path,
    *,
    artifact_bytes: bytes | None = None,
) -> list[str]:
    if platform_id == "android":
        if artifact_path.suffix.lower() != ".apk":
            return ["Android public direct artifact must be an APK"]
        analyzer = find_android_sdk_tool("apkanalyzer")
        signer = find_android_sdk_tool("apksigner")
        if analyzer is None or signer is None:
            return ["Android SDK apkanalyzer and apksigner are required for public APK verification"]
        try:
            exact_bytes = (
                read_public_artifact_bytes(artifact_path)
                if artifact_bytes is None
                else artifact_bytes
            )
        except OSError as exc:
            return [f"Android public artifact cannot be held for verification: {exc}"]
        with tempfile.TemporaryDirectory(prefix="winsvpn-public-apk-") as temporary:
            snapshot = Path(temporary) / "wins-vpn-android.apk"
            descriptor = os.open(
                snapshot,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                0o400,
            )
            try:
                view = memoryview(exact_bytes)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        return ["Android public artifact snapshot write failed"]
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            package_result = subprocess.run(
                [str(analyzer), "manifest", "application-id", str(snapshot)],
                capture_output=True,
                text=True,
                check=False,
            )
            version_name_result = subprocess.run(
                [str(analyzer), "manifest", "version-name", str(snapshot)],
                capture_output=True,
                text=True,
                check=False,
            )
            version_code_result = subprocess.run(
                [str(analyzer), "manifest", "version-code", str(snapshot)],
                capture_output=True,
                text=True,
                check=False,
            )
            signature_result = subprocess.run(
                [str(signer), "verify", "--verbose", "--print-certs", str(snapshot)],
                capture_output=True,
                text=True,
                check=False,
            )
        errors = android_public_artifact_errors(
            package_result.stdout + package_result.stderr,
            signature_result.stdout + signature_result.stderr,
            package_returncode=package_result.returncode,
            signature_returncode=signature_result.returncode,
            version_name_output=version_name_result.stdout + version_name_result.stderr,
            version_code_output=version_code_result.stdout + version_code_result.stderr,
            version_name_returncode=version_name_result.returncode,
            version_code_returncode=version_code_result.returncode,
        )
        errors.extend(android_engine_provenance_errors(exact_bytes))
        return errors
    if platform_id == "windows":
        try:
            data = (
                read_public_artifact_bytes(artifact_path)
                if artifact_bytes is None
                else artifact_bytes
            )
        except OSError as exc:
            return [f"Windows installer cannot be inspected: {exc}"]
        structural_errors = windows_pe_certificate_table_errors(data)
        if structural_errors:
            return structural_errors
        return [
            "Windows PE certificate-table structure is not Authenticode proof; "
            "a bound Windows-side WinVerifyTrust receipt is required"
        ]
    return []


def audit_public_download_regressions() -> list[tuple[str, str]]:
    errors = public_download_marker_errors() + static_public_binary_link_errors()
    if errors:
        return [fail("stale or mutable public download source rejected: " + "; ".join(errors))]
    return [ok("public source contains no stale debug package, stale artifact digest, or mutable download route")]


def audit_downloads() -> list[tuple[str, str]]:
    if not DOWNLOAD_MANIFEST.is_file():
        return [fail("download directory cannot be checked without its manifest")]
    try:
        payload = json.loads(read(DOWNLOAD_MANIFEST))
    except (json.JSONDecodeError, OSError) as exc:
        return [fail(f"download directory manifest is unreadable: {exc}")]

    bound_files: set[str] = set()
    for entry in payload.get("artifacts", []) if isinstance(payload, dict) else []:
        if not isinstance(entry, dict) or entry.get("status") != "available":
            continue
        delivery = entry.get("delivery")
        artifact = entry.get("artifact")
        if not isinstance(delivery, dict) or not isinstance(artifact, dict):
            continue
        if delivery.get("kind") not in PUBLISHED_DELIVERY_KINDS:
            continue
        filename = artifact.get("filename")
        if isinstance(filename, str) and filename:
            bound_files.add(filename)
            bound_files.add(f"{filename}.sha256")
            if DOWNLOAD_ENTRY_PLATFORMS.get(str(entry.get("id"))) == "linux":
                bound_files.add(f"{filename}.sigstore.json")
            for field in (
                "privacy",
                "release_receipt",
                "windows_verification",
                "winn_provenance",
                "publication_receipt",
            ):
                binding = artifact.get(field)
                if isinstance(binding, dict):
                    receipt_filename = binding.get("receipt_filename")
                    if isinstance(receipt_filename, str) and receipt_filename:
                        bound_files.add(receipt_filename)

    downloads = WEB / "downloads"
    present_files = {
        path.name for path in downloads.iterdir() if path.is_file()
    } if downloads.is_dir() else set()
    unbound = sorted(present_files - bound_files)
    missing = sorted(
        filename for filename in bound_files
        if not filename.endswith(".sha256") and filename not in present_files
    )
    results: list[tuple[str, str]] = []
    if unbound:
        preview = ", ".join(unbound[:8])
        suffix = f" (+{len(unbound) - 8} more)" if len(unbound) > 8 else ""
        results.append(
            fail(
                "public downloads directory contains manifest-unbound files: "
                f"{preview}{suffix}"
            )
        )
    elif present_files:
        results.append(ok("public downloads directory contains only manifest-bound artifacts"))
    else:
        results.append(ok("public downloads directory is empty while every release is pending"))
    if missing:
        results.append(fail("manifest-bound direct artifacts are missing: " + ", ".join(missing)))
    binding_errors = direct_download_binding_errors(payload, downloads)
    if binding_errors:
        results.append(
            fail(
                "manifest-bound direct artifact verification failed: "
                + "; ".join(binding_errors)
            )
        )
    elif bound_files:
        results.append(
            ok(
                "every direct artifact, byte count, SHA-256, and sidecar exactly "
                "matches the download release manifest"
            )
        )
    return results


def production_direct_url(filename: str) -> str:
    return f"https://winsvpn.org/downloads/{filename}"


def direct_url_is_immutable(url: str, filename: str) -> bool:
    parsed = urlparse(url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        return False
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 2 or parts[0] != "downloads" or unquote(parts[-1]) != filename:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname == "winsvpn.org"
        and parsed.port in (None, 443)
        and url == production_direct_url(filename)
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def direct_download_binding_errors(payload: object, downloads_dir: Path) -> list[str]:
    """Verify every available direct artifact against its release-manifest entry."""
    if not isinstance(payload, dict) or not isinstance(payload.get("artifacts"), list):
        return ["download release manifest cannot bind direct artifacts"]

    errors: list[str] = []
    for entry in payload["artifacts"]:
        if not isinstance(entry, dict) or entry.get("status") != "available":
            continue
        delivery = entry.get("delivery")
        artifact = entry.get("artifact")
        if not isinstance(delivery, dict) or delivery.get("kind") not in PUBLISHED_DELIVERY_KINDS:
            continue
        entry_id = entry.get("id") if isinstance(entry.get("id"), str) else "unknown"
        platform_id = DOWNLOAD_ENTRY_PLATFORMS.get(entry_id, entry_id)
        prefix = f"artifact {entry_id}"
        if not isinstance(artifact, dict):
            errors.append(f"{prefix} has no release-manifest artifact binding")
            continue

        filename = artifact.get("filename")
        expected_sha256 = artifact.get("sha256")
        expected_bytes = artifact.get("bytes")
        if (
            not isinstance(filename, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+()-]{0,180}", filename)
            or not isinstance(expected_sha256, str)
            or not re.fullmatch(r"[a-fA-F0-9]{64}", expected_sha256)
            or not isinstance(expected_bytes, int)
            or isinstance(expected_bytes, bool)
            or expected_bytes < 1
            or not isinstance(delivery.get("url"), str)
            or not published_url_is_pinned(
                entry_id, delivery.get("kind"), str(delivery.get("url")), filename
            )
        ):
            errors.append(f"{prefix} has an invalid release-manifest binding")
            continue

        artifact_path = downloads_dir / filename
        if artifact_path.is_symlink() or not artifact_path.is_file():
            errors.append(f"{prefix} file is missing or is a symlink: {filename}")
            continue
        try:
            exact_artifact = read_public_artifact_bytes(artifact_path)
        except OSError as exc:
            errors.append(f"{prefix} file is unreadable: {filename}: {exc}")
            continue
        actual_bytes = len(exact_artifact)
        actual_sha256 = hashlib.sha256(exact_artifact).hexdigest()
        if actual_bytes != expected_bytes:
            errors.append(
                f"{prefix} byte count mismatch for {filename}: "
                f"expected {expected_bytes}, got {actual_bytes}"
            )
        normalized_sha256 = expected_sha256.lower()
        if actual_sha256 != normalized_sha256:
            errors.append(f"{prefix} SHA-256 mismatch for {filename}")
        if platform_id == "windows" and artifact_is_unsigned_waiver(artifact):
            # Owner waiver (ruling 2026-10-21 "Ship unsigned"): the Unsigned
            # label must be true, so a certificate table here is refused.
            if not windows_pe_certificate_table_errors(exact_artifact):
                errors.append(
                    f"{prefix} carries a PE certificate table but is labelled Unsigned"
                )
            errors.extend(unsigned_waiver_binding_errors(artifact, prefix))
        elif platform_id == "windows":
            structural_errors = windows_pe_certificate_table_errors(exact_artifact)
            errors.extend(f"{prefix} {message}" for message in structural_errors)
            if not structural_errors:
                errors.extend(
                    f"{prefix} {message}"
                    for message in windows_authenticode_cryptographic_errors(
                        filename, exact_artifact, artifact
                    )
                )
                errors.extend(
                    f"{prefix} {message}"
                    for message in windows_winverifytrust_receipt_errors(
                        artifact_path, artifact, downloads_dir
                    )
                )
        else:
            errors.extend(
                f"{prefix} {message}"
                for message in public_binary_identity_errors(
                    platform_id,
                    artifact_path,
                    artifact_bytes=exact_artifact,
                )
            )

        sidecar_path = downloads_dir / f"{filename}.sha256"
        if sidecar_path.is_symlink() or not sidecar_path.is_file():
            errors.append(f"{prefix} SHA-256 sidecar is missing or is a symlink")
            continue
        try:
            sidecar = sidecar_path.read_bytes()
        except OSError as exc:
            errors.append(f"{prefix} SHA-256 sidecar is unreadable: {exc}")
            continue
        expected_line_lf = f"{normalized_sha256}  {filename}\n".encode("utf-8")
        expected_line_crlf = f"{normalized_sha256}  {filename}\r\n".encode("utf-8")
        if sidecar not in (expected_line_lf, expected_line_crlf):
            errors.append(
                f"{prefix} SHA-256 sidecar does not exactly bind {filename}"
            )
        privacy = artifact.get("privacy")
        release_receipt = artifact.get("release_receipt")
        winn_provenance = artifact.get("winn_provenance")
        if not isinstance(privacy, dict):
            errors.append(f"{prefix} requires a hosted privacy receipt")
        else:
            errors.extend(
                web_download_receipt_file_errors(
                    privacy,
                    artifact,
                    entry_id,
                    downloads_dir,
                    prefix,
                    "privacy",
                    PRIVACY_RECEIPT_SCHEMA,
                    PRIVACY_RECEIPT_KIND,
                    expected_keys=PRIVACY_RECEIPT_KEYS,
                )
            )
        if not isinstance(release_receipt, dict):
            errors.append(f"{prefix} requires a hosted release receipt")
        else:
            errors.extend(
                web_download_receipt_file_errors(
                    release_receipt,
                    artifact,
                    entry_id,
                    downloads_dir,
                    prefix,
                    "release",
                    RELEASE_RECEIPT_SCHEMA,
                    RELEASE_RECEIPT_KIND,
                    expected_keys=RELEASE_RECEIPT_KEYS,
                )
            )
        if not isinstance(winn_provenance, dict):
            errors.append(f"{prefix} requires a hosted Winn provenance receipt")
        else:
            errors.extend(
                web_download_receipt_file_errors(
                    winn_provenance,
                    artifact,
                    entry_id,
                    downloads_dir,
                    prefix,
                    "Winn provenance",
                    WINN_PROVENANCE_SCHEMA,
                    WINN_PROVENANCE_KIND,
                    expected_keys=WINN_RECEIPT_KEYS,
                    extra_expected={
                        "primary": WINN_PRIMARY,
                        "fallback": WINN_FALLBACK,
                        "fallback_order": WINN_FALLBACK_ORDER,
                    },
                )
            )
        publication_receipt = artifact.get("publication_receipt")
        if not isinstance(publication_receipt, dict):
            errors.append(f"{prefix} requires a hosted publication receipt")
        else:
            errors.extend(
                publication_receipt_file_errors(
                    publication_receipt,
                    artifact,
                    downloads_dir,
                    prefix,
                )
            )
    return errors


def download_manifest_errors(payload: object) -> list[str]:
    if not isinstance(payload, dict):
        return ["manifest root must be an object"]
    if payload.get("schema") != DOWNLOAD_MANIFEST_SCHEMA:
        return ["unsupported manifest schema"]
    entries = payload.get("artifacts")
    if not isinstance(entries, list) or len(entries) != len(DOWNLOAD_PLATFORM_CONTRACT):
        return [
            f"manifest must contain exactly {len(DOWNLOAD_PLATFORM_CONTRACT)} per-architecture artifacts"
        ]

    errors: list[str] = []
    available_count = 0
    direct_filenames: set[str] = set()
    for index, (platform_id, platform_label) in enumerate(DOWNLOAD_PLATFORM_CONTRACT):
        entry = entries[index]
        prefix = f"artifact {platform_id}"
        if not isinstance(entry, dict):
            errors.append(f"{prefix} must be an object")
            continue
        if entry.get("id") != platform_id or entry.get("label") != platform_label:
            errors.append(f"{prefix} id/label/order mismatch")
            continue
        delivery = entry.get("delivery")
        artifact = entry.get("artifact")
        if not isinstance(delivery, dict) or not isinstance(artifact, dict):
            errors.append(f"{prefix} delivery/artifact metadata missing")
            continue
        status = entry.get("status")
        if status in DOWNLOAD_PENDING_STATUSES:
            if status == "store_pending" and DOWNLOAD_DELIVERY_KINDS[platform_id] != "store":
                errors.append(f"{prefix} store_pending is valid only for an app-store entry")
            if set(artifact) != PENDING_ARTIFACT_KEYS:
                errors.append(f"{prefix} pending artifact is outside the closed JSON schema")
                continue
            expected_kind = DOWNLOAD_DELIVERY_KINDS[platform_id]
            if delivery.get("kind") == "github_release":
                errors.append(
                    f"{prefix} GitHub is backup-only and is not website publication authority"
                )
            elif delivery.get("kind") != expected_kind:
                errors.append(f"{prefix} pending delivery kind is invalid")
            if delivery.get("url") is not None or any(
                artifact.get(field) is not None
                for field in ("filename", "sha256", "bytes")
            ):
                errors.append(f"{prefix} pending entry contains release metadata")
            continue
        if status != "available":
            errors.append(f"{prefix} has an invalid status")
            continue
        available_count += 1
        # 1.0.16+33 release scope (owner rulings; review DLP-05): only the four
        # desktop entries, Windows only under the Unsigned owner waiver.
        if platform_id not in RELEASE_LAUNCH_ENTRIES:
            errors.append(f"{prefix} is outside the owner-authorized 1.0.16+33 desktop launch")
        elif DOWNLOAD_ENTRY_PLATFORMS[platform_id] == "windows" and not artifact_is_unsigned_waiver(artifact):
            errors.append(f"{prefix} must use the recorded Unsigned owner waiver")

        filename = artifact.get("filename")
        sha256 = artifact.get("sha256")
        byte_count = artifact.get("bytes")
        if not isinstance(filename, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._+()-]{0,180}", filename
        ):
            errors.append(f"{prefix} filename is invalid")
        if not isinstance(sha256, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", sha256):
            errors.append(f"{prefix} SHA-256 is invalid")
        if not isinstance(byte_count, int) or isinstance(byte_count, bool) or byte_count < 1:
            errors.append(f"{prefix} byte count is invalid")

        errors.extend(available_artifact_custody_errors(platform_id, artifact, prefix))

        if (
            DOWNLOAD_ENTRY_PLATFORMS[platform_id] == "windows"
            and entry.get("status") == "available"
            and not artifact_is_unsigned_waiver(artifact)
        ):
            verification = artifact.get("windows_verification")
            if not isinstance(verification, dict):
                errors.append(f"{prefix} requires a manifest-bound WinVerifyTrust receipt")
            else:
                expected_verification_keys = {
                    "kind",
                    "receipt_filename",
                    "receipt_sha256",
                    "approved_signer_subject",
                    "approved_signer_certificate_sha256",
                }
                if set(verification) != expected_verification_keys:
                    errors.append(f"{prefix} WinVerifyTrust receipt binding schema is invalid")

        url = delivery.get("url")
        if not isinstance(url, str) or not url:
            errors.append(f"{prefix} delivery URL is missing")
            continue
        parsed = urlparse(url)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            errors.append(f"{prefix} delivery URL contains forbidden components")
            continue
        kind = delivery.get("kind")
        if kind == "direct":
            if not isinstance(filename, str) or not direct_url_is_immutable(url, filename):
                errors.append(f"{prefix} direct URL is not the exact production origin")
            if isinstance(filename, str):
                if filename in direct_filenames:
                    errors.append(f"{prefix} duplicates a direct artifact filename")
                direct_filenames.add(filename)
        elif (
            kind == "github_release"
            and platform_id in GITHUB_RELEASE_ENTRIES
            and isinstance(filename, str)
            and github_release_url_is_pinned(url, filename)
        ):
            # Owner update 2026-10-25: the one pinned GitHub release may host
            # desktop binaries; every receipt above is still required.
            if filename in direct_filenames:
                errors.append(f"{prefix} duplicates a direct artifact filename")
            direct_filenames.add(filename)
        elif kind == "github_release":
            errors.append(
                f"{prefix} GitHub is backup-only and is not website publication authority"
            )
            parts = [part for part in parsed.path.split("/") if part]
            tag = parts[4] if len(parts) == 6 else ""
            if (
                "/releases/latest/" in url
                or "/releases/download/latest/" in url
                or tag.lower() == "latest"
            ):
                errors.append(f"{prefix} GitHub release URL is not a version-pinned immutable asset")
        elif kind == "store":
            if (
                parsed.scheme != "https"
                or parsed.hostname not in DOWNLOAD_STORE_HOSTS[DOWNLOAD_ENTRY_PLATFORMS[platform_id]]
            ):
                errors.append(f"{prefix} app-store host is not allowed")
        else:
            errors.append(f"{prefix} delivery kind is invalid")

    release_id = payload.get("release_id")
    if release_id != CANONICAL_WEBSITE_RELEASE_ID:
        errors.append("release_id is not the current 1.0.16+33 website release")
    if available_count and (
        not isinstance(release_id, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,79}", release_id)
    ):
        errors.append("available artifacts require a bounded release_id")
    return errors


def browser_download_contract_errors(website: str) -> list[str]:
    """Mutation-resistant static checks for the browser download boundary."""
    errors: list[str] = []
    github_branch = website.partition('} else if (delivery.kind === "github_release") {')[2].partition(
        '} else {\n            throw new Error("Unsupported download delivery kind")'
    )[0]
    if (
        not github_branch
        or "GitHub is backup-only and is not website publication authority" not in github_branch
        or "beginDownload" in github_branch
        or "pinnedParts" in github_branch
    ):
        errors.append("browser GitHub branch does not refuse GitHub as website publication authority")

    blocked_branch = website.partition('} else if (result.reason === "blocked") {')[2].partition(
        "} else {"
    )[0]
    if (
        not blocked_branch
        or "No unverified download was started" not in blocked_branch
        or "beginDownload(entry)" in blocked_branch
    ):
        errors.append("blocked byte verification must never start a download")
    if "winsVerifyDone" in website:
        errors.append("download verification must not expose a one-click bypass state")
    required_custody_markers = (
        'payload.schema !== "winsvpn-download-manifest-v2"',
        'payload.release_id !== "v1.0.16+33"',
        '"unsigned_owner_waiver"',
        'unsignedWaiver.label !== "Unsigned"',
        '(entry.status === "store_pending" && platform.kind === "store")',
        'artifact.canonical_release !== "1.0.16+33"',
        'package_identity !== "org.winsvpn.app"',
        'artifact.version !== "1.0.16"',
        "apk_signer_certificate_sha256",
        ANDROID_PUBLIC_SIGNER_SHA256,
        "Incomplete 1.0.16+33 download custody",
        "website_download_winn_provenance_receipt_v1",
        'winnProvenance.primary !== "winn/3"',
        'winnProvenance.fallback !== "winn/1"',
        "website_download_publication_receipt_v1",
        "winverifytrust_receipt_v1",
        "Direct artifact URL is not the exact production origin",
        'redirect: "error"',
        "https://winsvpn.org/downloads/",
        GITHUB_RELEASE_PREFIX,
        "pinnedGithubReleaseEntries.has(platform.id)",
    )
    missing_custody = [marker for marker in required_custody_markers if marker not in website]
    if missing_custody:
        errors.append(
            "browser download boundary does not fail closed on 1.0.16+33 custody: "
            + ", ".join(missing_custody)
        )
    return errors


def audit_download_manifest() -> list[tuple[str, str]]:
    if not DOWNLOAD_MANIFEST.is_file():
        return [fail("download release manifest is missing")]
    try:
        payload = json.loads(read(DOWNLOAD_MANIFEST))
    except (json.JSONDecodeError, OSError) as exc:
        return [fail(f"download release manifest is unreadable: {exc}")]

    errors = download_manifest_errors(payload)
    if errors:
        return [fail("download release manifest rejected: " + "; ".join(errors))]

    website = read(WEB / "index.html")
    top_menu = re.search(
        r'<div\s+class="download-list"\s+id="topDownloadList"[^>]*>(?P<body>.*?)</div>',
        website,
        flags=re.DOTALL,
    )
    if not top_menu:
        return [fail("top Download menu contract is missing")]
    options = re.findall(
        r'data-download-platform="([a-z0-9-]+)"[^>]*>([^<]+)</(?:span|a)>',
        top_menu.group("body"),
    )
    if tuple(options) != DOWNLOAD_PLATFORM_CONTRACT:
        return [fail(f"top Download menu order/labels are invalid: {options}")]
    if re.search(
        r"\.download-menu\s*\{[^}]*\bdisplay\s*:\s*none\b",
        website,
        flags=re.IGNORECASE | re.DOTALL,
    ):
        return [fail("top Download menu must remain available on narrow screens")]
    strip = re.search(
        r'<div\s+class="download-strip"\s+id="downloadStrip"[^>]*>(?P<body>.*?)</div>',
        website,
        flags=re.DOTALL,
    )
    strip_options = re.findall(
        r'data-download-platform="([a-z0-9-]+)"[^>]*>([^<]+)</(?:span|a)>',
        strip.group("body") if strip else "",
    )
    if tuple(strip_options) != DOWNLOAD_PLATFORM_CONTRACT:
        return [fail(f"download strip order/labels are invalid: {strip_options}")]

    required_renderer_markers = (
        'const downloadManifestUrl = "/releases/downloads.json";',
        "function normalizedDownloadEntries(payload)",
        "function renderDownloadSurface(container, entries)",
        "option.dataset.sha256 = entry.sha256;",
        "Pending download contains release metadata",
        "Incomplete 1.0.16+33 download custody",
        'payload.release_id !== "v1.0.16+33"',
        "GitHub is backup-only and is not website publication authority",
        "async function verifyPinnedSha256(entry)",
        "No unverified download was started",
        'id="downloadVerifyNote"',
        "Direct artifact URL is not the exact production origin",
        'redirect: "error"',
        "https://winsvpn.org/downloads/",
        "website_download_publication_receipt_v1",
        "winverifytrust_receipt_v1",
    )
    missing = [marker for marker in required_renderer_markers if marker not in website]
    if missing:
        return [fail(f"download manifest renderer contract is incomplete: {missing}")]
    browser_errors = browser_download_contract_errors(website)
    if browser_errors:
        return [fail("browser download boundary rejected: " + "; ".join(browser_errors))]
    cache_control = "no-cache, max-age=0, must-revalidate"
    if cache_control not in read(WEB / "_headers"):
        return [fail("download manifest must be revalidated on every request")]
    return [
        ok(
            "per-architecture Download menu is manifest-driven, fail-closed, "
            "and binds available links to exact SHA-256 metadata"
        )
    ]


def audit_map_tile_proxy() -> list[tuple[str, str]]:
    worker = read(WEB / "_worker.js")
    required = (
        '"User-Agent":\n          "WinsVPN-MapProxy/1.0 (+https://winsvpn.org; contact: support@winsvpn.org)"',
        'Referer: "https://www.winsvpn.org/"',
        "const mapTileCacheSeconds = 7 * 24 * 60 * 60;",
        'env.MAP_TILE_UPSTREAM_URL_TEMPLATE || env.MAP_TILE_URL_TEMPLATE',
        "/api/site/map-tile/{z}/{x}/{y}.png",
        "© OpenStreetMap contributors",
    )
    missing = [marker for marker in required if marker not in worker]
    if missing:
        return [
            fail(
                "first-party map tile proxy is missing identification, "
                "attribution, provider override, or seven-day caching controls"
            )
        ]
    return [
        ok(
            "map tile proxy has stable contact identity, valid site Referer, "
            "visible attribution, provider override, and seven-day caching"
        )
    ]


def strip_tags(value: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", " ", value)).strip()


def public_anchor_claims(text: str, platform_key: str) -> list[str]:
    config = APPLE_DEMO_RELEASE_REQUIREMENTS[platform_key]
    claims: list[str] = []
    for match in re.finditer(r"<a\b(?P<attrs>[^>]*)>(?P<body>.*?)</a>", text, flags=re.IGNORECASE | re.DOTALL):
        attrs = match.group("attrs")
        body = match.group("body")
        href_match = re.search(r"\bhref\s*=\s*([\"'])(?P<href>.*?)\1", attrs, flags=re.IGNORECASE | re.DOTALL)
        href = html.unescape(href_match.group("href")).strip() if href_match else ""
        visible = strip_tags(body)
        combined = f"{attrs} {href} {visible}".lower()
        mentions_platform = any(alias in combined for alias in config["aliases"])
        has_release_artifact = any(pattern.search(f"{href} {attrs}") for pattern in config["release_patterns"])
        if not mentions_platform and not has_release_artifact:
            continue
        is_placeholder = "coming soon" in combined and (not href or href.startswith("#")) and not has_release_artifact
        if is_placeholder:
            continue
        if has_release_artifact or "download" in combined or "app store" in combined or "testflight" in combined:
            label = visible or href or f"{config['label']} link"
            claims.append(f"public {config['label']} link: {label}")
    return claims


def public_demo_claims(text: str, platform_key: str) -> list[str]:
    config = APPLE_DEMO_RELEASE_REQUIREMENTS[platform_key]
    demo_stem = f"winsvpn-{platform_key}-demo"
    claims: list[str] = []
    if re.search(rf'data-demo-os\s*=\s*["\']{platform_key}["\']', text, flags=re.IGNORECASE):
        claims.append(f"public {config['label']} demo selector")
    if demo_stem in text:
        claims.append(f"public {config['label']} demo asset reference")
    return claims


def public_worker_claims(text: str, platform_key: str) -> list[str]:
    config = APPLE_DEMO_RELEASE_REQUIREMENTS[platform_key]
    claims: list[str] = []
    for pattern in config["release_patterns"]:
        if pattern.search(text):
            claims.append(f"public {config['label']} worker/function release route")
            break
    for line in text.splitlines():
        normalized = line.lower()
        if "apps.apple.com" in normalized and any(alias in normalized for alias in config["aliases"]):
            claims.append(f"public {config['label']} App Store worker/function route")
            break
    return claims


def audit_apple_public_release_gate() -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    source_texts = {path: read(path) for path in APPLE_RELEASE_SOURCE_PATHS if path.exists()}

    for platform_key, config in APPLE_DEMO_RELEASE_REQUIREMENTS.items():
        claims: list[str] = []
        for path, text in source_texts.items():
            if path.suffix == ".html":
                claims.extend(f"{path.relative_to(ROOT)}: {claim}" for claim in public_anchor_claims(text, platform_key))
                claims.extend(f"{path.relative_to(ROOT)}: {claim}" for claim in public_demo_claims(text, platform_key))
            else:
                claims.extend(f"{path.relative_to(ROOT)}: {claim}" for claim in public_worker_claims(text, platform_key))

        if not claims:
            results.append(ok(f"{config['label']} public download/demo links remain gated until matching demo videos exist"))
            continue

        missing_assets = [path.relative_to(ROOT) for path in config["demo_assets"] if not path.is_file()]
        too_small_assets = [
            path.relative_to(ROOT)
            for path in config["demo_assets"]
            if path.is_file()
            and path.stat().st_size < (MIN_APPLE_DEMO_MP4_BYTES if path.suffix == ".mp4" else MIN_APPLE_DEMO_POSTER_BYTES)
        ]
        if missing_assets:
            results.append(fail(f"{config['label']} public release claim requires demo assets: {', '.join(map(str, missing_assets))}"))
        if too_small_assets:
            results.append(fail(f"{config['label']} demo assets look too small: {', '.join(map(str, too_small_assets))}"))
        if not missing_assets and not too_small_assets:
            results.append(ok(f"{config['label']} public download/demo links have matching demo videos"))
        if missing_assets or too_small_assets:
            results.append(warn(f"{config['label']} claims found before release assets: {'; '.join(claims[:5])}"))
    return results


def audit_inline_csp_consistency() -> list[tuple[str, str]]:
    """Fail loudly when any inline <style>/<script> in index.html does not match
    the hash pinned in _headers and _worker.js.

    This is the gate against the defect class where an edit to a string inside
    an inline <script> (or <style>) block invalidates the CSP SHA-256 pin while
    the editor, having checked only the <style> block as byte-identical,
    concludes the CSP is unaffected. Deploying that state would make the browser
    refuse the script or style on a live site (unstyled page, or translation /
    payments / AI chat all dead).

    It shells out to web/verify_inline_csp.py -- the single source of truth
    shared with update_style_csp.py's extraction -- so the gate and the fixer
    cannot drift apart. The gate is read-only and never writes anything.
    """
    script = WEB / "verify_inline_csp.py"
    if not script.is_file():
        return [fail("inline CSP consistency gate web/verify_inline_csp.py is missing")]
    try:
        proc = subprocess.run(
            [sys.executable, str(script)],
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        return [fail(f"inline CSP consistency gate could not be executed: {exc}")]
    if proc.returncode == 0:
        return [ok(proc.stdout.strip() or "inline <style>/<script> CSP pins in sync")]
    details = (proc.stderr or proc.stdout or "").strip()
    summary = (
        "inline <style>/<script> CSP hash pins are stale "
        "(run `python3 web/update_style_csp.py` to resync)"
    )
    if details:
        summary += ": " + " ".join(details.splitlines())
    return [fail(summary)]


def _selftest_receipt(kind: str, schema: str, platform_id: str, filename: str, digest: str, byte_count: int, architecture: list[str], extra: dict[str, object] | None = None) -> tuple[dict[str, object], bytes]:
    payload: dict[str, object] = {
        "schema": schema,
        "kind": kind,
        "canonical_release": CANONICAL_RELEASE,
        "platform_id": platform_id,
        "artifact_filename": filename,
        "artifact_sha256": digest,
        "artifact_bytes": byte_count,
        "package_identity": PUBLIC_PACKAGE_IDENTITY,
        "architecture": architecture,
        "version": CANONICAL_VERSION_NAME,
    }
    evidence_key = {
        PRIVACY_RECEIPT_KIND: "scan",
        RELEASE_RECEIPT_KIND: "build",
        WINN_PROVENANCE_KIND: "engine_release",
    }.get(kind)
    if evidence_key:
        payload[evidence_key] = {"selftest": True}
    if extra:
        payload.update(extra)
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    return payload, body


def _selftest_available_artifact(
    platform_id: str,
    filename: str,
    digest: str,
    byte_count: int,
    architecture: list[str],
    *,
    signer_sha256: str,
    privacy_sha256: str,
    release_sha256: str,
    winn_sha256: str,
    publication_sha256: str = "a" * 64,
) -> dict[str, object]:
    artifact: dict[str, object] = {
        "filename": filename,
        "sha256": digest,
        "bytes": byte_count,
        "canonical_release": CANONICAL_RELEASE,
        "package_identity": PUBLIC_PACKAGE_IDENTITY,
        "version": CANONICAL_VERSION_NAME,
        "architecture": architecture,
        "signature": {
            "kind": SIGNATURE_KINDS[DOWNLOAD_ENTRY_PLATFORMS.get(platform_id, platform_id)],
            "sha256": signer_sha256,
        },
        "winn_provenance": {
            "kind": WINN_PROVENANCE_KIND,
            "receipt_filename": f"{filename}.winn.json",
            "receipt_sha256": winn_sha256,
            "primary": WINN_PRIMARY,
            "fallback": WINN_FALLBACK,
            "fallback_order": list(WINN_FALLBACK_ORDER),
        },
        "privacy": {
            "kind": PRIVACY_RECEIPT_KIND,
            "receipt_filename": f"{filename}.privacy.json",
            "receipt_sha256": privacy_sha256,
        },
        "release_receipt": {
            "kind": RELEASE_RECEIPT_KIND,
            "receipt_filename": f"{filename}.release.json",
            "receipt_sha256": release_sha256,
        },
        "publication_receipt": {
            "kind": PUBLICATION_RECEIPT_KIND,
            "receipt_filename": f"{filename}.publication.json",
            "receipt_sha256": publication_sha256,
        },
    }
    return artifact


def run_selftest() -> None:
    assert public_anchor_claims('<a href="/downloads/wins-vpn-ios.ipa" download>iOS</a>', "ios")
    assert public_anchor_claims('<a href="https://apps.apple.com/app/wins-vpn">Download on the iOS App Store</a>', "ios")
    assert public_anchor_claims('<a href="/downloads/WinVPN.pkg" download>macOS</a>', "macos")
    assert public_demo_claims('<a class="demo-link" data-demo-os="macos">Watch Demo</a>', "macos")
    assert public_worker_claims('["/downloads/wins-vpn-macos.pkg", "https://example.test/wins-vpn-macos.pkg"]', "macos")
    assert public_worker_claims('["/macos", "https://apps.apple.com/app/wins-vpn-macos"]', "macos")
    assert not public_anchor_claims('<a href="#get">iOS <span class="soon">(coming soon)</span></a>', "ios")
    assert not public_anchor_claims('<a href="#get">MacOS <span class="soon">(coming soon)</span></a>', "macos")
    assert not public_worker_claims(
        'const appStore = "https://apps.apple.com/app/wins-vpn";\nconst platform = "iOS coming soon";',
        "ios",
    )
    pending_payload = {
        "schema": DOWNLOAD_MANIFEST_SCHEMA,
        "release_id": CANONICAL_WEBSITE_RELEASE_ID,
        "artifacts": [
            {
                "id": platform_id,
                "label": label,
                "status": "store_pending" if DOWNLOAD_DELIVERY_KINDS[platform_id] == "store" else "verification_pending",
                "delivery": {"kind": DOWNLOAD_DELIVERY_KINDS[platform_id], "url": None},
                "artifact": {"filename": None, "sha256": None, "bytes": None},
            }
            for platform_id, label in DOWNLOAD_PLATFORM_CONTRACT
        ],
    }
    assert not download_manifest_errors(pending_payload)
    none_release = json.loads(json.dumps(pending_payload))
    none_release["release_id"] = None
    assert any(
        "release_id is not the current 1.0.16+33 website release" in error
        for error in download_manifest_errors(none_release)
    )
    pending_payload["artifacts"][0]["artifact"]["sha256"] = "0" * 64
    assert download_manifest_errors(pending_payload)
    pending_payload["artifacts"][0]["artifact"]["sha256"] = None
    assert not download_manifest_errors(pending_payload)
    linux_name = "wins-vpn-linux-x64.tar.gz"
    linux_arch = ["x64"]
    linux_digest = "a" * 64
    linux_bytes = 1_000_000
    winn_extra = {
        "primary": WINN_PRIMARY,
        "fallback": WINN_FALLBACK,
        "fallback_order": list(WINN_FALLBACK_ORDER),
    }
    _, linux_privacy_body = _selftest_receipt(
        PRIVACY_RECEIPT_KIND, PRIVACY_RECEIPT_SCHEMA, "linux-x64", linux_name, linux_digest, linux_bytes, linux_arch
    )
    _, linux_release_body = _selftest_receipt(
        RELEASE_RECEIPT_KIND, RELEASE_RECEIPT_SCHEMA, "linux-x64", linux_name, linux_digest, linux_bytes, linux_arch
    )
    _, linux_winn_body = _selftest_receipt(
        WINN_PROVENANCE_KIND,
        WINN_PROVENANCE_SCHEMA,
        "linux-x64",
        linux_name,
        linux_digest,
        linux_bytes,
        linux_arch,
        extra=winn_extra,
    )
    linux_artifact = _selftest_available_artifact(
        "linux-x64",
        linux_name,
        linux_digest,
        linux_bytes,
        linux_arch,
        signer_sha256="c" * 64,
        privacy_sha256=hashlib.sha256(linux_privacy_body).hexdigest(),
        release_sha256=hashlib.sha256(linux_release_body).hexdigest(),
        winn_sha256=hashlib.sha256(linux_winn_body).hexdigest(),
    )
    direct_payload = json.loads(json.dumps(pending_payload))
    direct_payload["artifacts"][3] = {
        "id": "linux-x64",
        "label": "Linux x64",
        "status": "available",
        "delivery": {"kind": "direct", "url": production_direct_url(linux_name)},
        "artifact": linux_artifact,
    }
    assert not download_manifest_errors(direct_payload)
    relative_payload = json.loads(json.dumps(direct_payload))
    relative_payload["artifacts"][3]["delivery"]["url"] = f"/downloads/{linux_name}"
    assert any(
        "exact production origin" in error
        for error in download_manifest_errors(relative_payload)
    )
    missing_custody = json.loads(json.dumps(direct_payload))
    missing_custody["artifacts"][3]["artifact"] = {
        "filename": linux_name,
        "sha256": linux_digest,
        "bytes": linux_bytes,
    }
    assert any(
        "missing exact 1.0.16+33 custody metadata" in error
        for error in download_manifest_errors(missing_custody)
    )
    stale_apk = json.loads(json.dumps(direct_payload))
    stale_apk["artifacts"][3]["artifact"]["sha256"] = STALE_ANDROID_DEBUG_SHA256
    stale_apk["artifacts"][3]["artifact"]["package_identity"] = STALE_ANDROID_DEBUG_PACKAGE
    assert any(
        "stale Android debug APK digest" in error
        for error in download_manifest_errors(stale_apk)
    )
    assert any(
        "stale Android debug application ID" in error
        for error in download_manifest_errors(stale_apk)
    )
    stale_arch = json.loads(json.dumps(direct_payload))
    stale_arch["artifacts"][3]["artifact"]["architecture"] = ["x86_64"]
    assert any(
        "stale architecture artifact" in error
        for error in download_manifest_errors(stale_arch)
    )
    android_name = linux_name
    android_arch = sorted(PLATFORM_ARCHITECTURES["android"])
    _, android_privacy_body = _selftest_receipt(
        PRIVACY_RECEIPT_KIND, PRIVACY_RECEIPT_SCHEMA, "android", android_name, linux_digest, linux_bytes, android_arch
    )
    _, android_release_body = _selftest_receipt(
        RELEASE_RECEIPT_KIND, RELEASE_RECEIPT_SCHEMA, "android", android_name, linux_digest, linux_bytes, android_arch
    )
    _, android_winn_body = _selftest_receipt(
        WINN_PROVENANCE_KIND,
        WINN_PROVENANCE_SCHEMA,
        "android",
        android_name,
        linux_digest,
        linux_bytes,
        android_arch,
        extra=winn_extra,
    )
    duplicate_payload = json.loads(json.dumps(direct_payload))
    duplicate_payload["artifacts"][2] = {
        "id": "android",
        "label": "Android",
        "status": "available",
        "delivery": {"kind": "direct", "url": production_direct_url(android_name)},
        "artifact": _selftest_available_artifact(
            "android",
            android_name,
            linux_digest,
            linux_bytes,
            android_arch,
            signer_sha256=ANDROID_PUBLIC_SIGNER_SHA256,
            privacy_sha256=hashlib.sha256(android_privacy_body).hexdigest(),
            release_sha256=hashlib.sha256(android_release_body).hexdigest(),
            winn_sha256=hashlib.sha256(android_winn_body).hexdigest(),
        ),
    }
    assert any(
        "duplicates a direct artifact filename" in error
        for error in download_manifest_errors(duplicate_payload)
    )
    with tempfile.TemporaryDirectory() as temporary_downloads:
        downloads_dir = Path(temporary_downloads)
        assert not direct_download_binding_errors(pending_payload, downloads_dir)

        artifact_bytes = b"wins-vpn-exact-candidate\x00\x01"
        artifact_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
        direct_entry = direct_payload["artifacts"][3]
        _, bound_privacy = _selftest_receipt(
            PRIVACY_RECEIPT_KIND,
            PRIVACY_RECEIPT_SCHEMA,
            "linux-x64",
            linux_name,
            artifact_sha256,
            len(artifact_bytes),
            linux_arch,
        )
        _, bound_release = _selftest_receipt(
            RELEASE_RECEIPT_KIND,
            RELEASE_RECEIPT_SCHEMA,
            "linux-x64",
            linux_name,
            artifact_sha256,
            len(artifact_bytes),
            linux_arch,
        )
        _, bound_winn = _selftest_receipt(
            WINN_PROVENANCE_KIND,
            WINN_PROVENANCE_SCHEMA,
            "linux-x64",
            linux_name,
            artifact_sha256,
            len(artifact_bytes),
            linux_arch,
            extra=winn_extra,
        )
        bound_publication = {
            "schema": PUBLICATION_RECEIPT_SCHEMA,
            "kind": PUBLICATION_RECEIPT_KIND,
            "canonical_release": CANONICAL_RELEASE,
            "artifact_filename": linux_name,
            "artifact_sha256": artifact_sha256,
            "artifact_bytes": len(artifact_bytes),
        }
        bound_publication_bytes = json.dumps(
            bound_publication, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        direct_entry["artifact"] = _selftest_available_artifact(
            "linux-x64",
            linux_name,
            artifact_sha256,
            len(artifact_bytes),
            linux_arch,
            signer_sha256="c" * 64,
            privacy_sha256=hashlib.sha256(bound_privacy).hexdigest(),
            release_sha256=hashlib.sha256(bound_release).hexdigest(),
            winn_sha256=hashlib.sha256(bound_winn).hexdigest(),
            publication_sha256=hashlib.sha256(bound_publication_bytes).hexdigest(),
        )
        direct_entry["delivery"]["url"] = production_direct_url(linux_name)
        artifact_path = downloads_dir / linux_name
        sidecar_path = downloads_dir / f"{linux_name}.sha256"
        artifact_path.write_bytes(artifact_bytes)
        sidecar_path.write_bytes(f"{artifact_sha256}  {linux_name}\n".encode("utf-8"))
        (downloads_dir / f"{linux_name}.privacy.json").write_bytes(bound_privacy)
        (downloads_dir / f"{linux_name}.release.json").write_bytes(bound_release)
        (downloads_dir / f"{linux_name}.winn.json").write_bytes(bound_winn)
        (downloads_dir / f"{linux_name}.publication.json").write_bytes(bound_publication_bytes)
        assert not direct_download_binding_errors(direct_payload, downloads_dir)
        assert not download_manifest_errors(direct_payload)

        artifact_path.write_bytes(b"wins-vpn-altered-candidate\x00\x01")
        altered_errors = direct_download_binding_errors(direct_payload, downloads_dir)
        assert any("byte count mismatch" in error for error in altered_errors)
        assert any("SHA-256 mismatch" in error for error in altered_errors)
        artifact_path.write_bytes(artifact_bytes)

        sidecar_path.write_bytes(
            f"{artifact_sha256}  wrong-filename.exe\n".encode("utf-8")
        )
        assert any(
            "sidecar does not exactly bind" in error
            for error in direct_download_binding_errors(direct_payload, downloads_dir)
        )
        sidecar_path.unlink()
        assert any(
            "sidecar is missing" in error
            for error in direct_download_binding_errors(direct_payload, downloads_dir)
        )

        sidecar_path.write_bytes(f"{artifact_sha256}  {linux_name}\n".encode("utf-8"))
        (downloads_dir / f"{linux_name}.privacy.json").write_bytes(bound_privacy + b" ")
        assert any(
            "privacy receipt hash mismatch" in error
            for error in direct_download_binding_errors(direct_payload, downloads_dir)
        )
        (downloads_dir / f"{linux_name}.privacy.json").write_bytes(bound_privacy)
        (downloads_dir / f"{linux_name}.winn.json").unlink()
        assert any(
            "Winn provenance receipt is missing" in error
            for error in direct_download_binding_errors(direct_payload, downloads_dir)
        )
        (downloads_dir / f"{linux_name}.winn.json").write_bytes(bound_winn)

        direct_entry["delivery"]["url"] = "/downloads/not-the-bound-file.exe"
        assert any(
            "invalid release-manifest binding" in error
            for error in direct_download_binding_errors(direct_payload, downloads_dir)
        )
        direct_entry["delivery"]["url"] = f"/downloads/{linux_name}"
        assert any(
            "invalid release-manifest binding" in error
            for error in direct_download_binding_errors(direct_payload, downloads_dir)
        )
        direct_entry["delivery"]["url"] = production_direct_url(linux_name)

        artifact_path.unlink()
        assert any(
            "file is missing" in error
            for error in direct_download_binding_errors(direct_payload, downloads_dir)
        )

    direct_payload["artifacts"][3]["delivery"]["url"] = f"https://evil.example/{linux_name}"
    assert download_manifest_errors(direct_payload)
    github_pinned_payload = json.loads(json.dumps(pending_payload))
    github_pinned_payload["artifacts"][0] = {
        "id": "windows-x64",
        "label": "Windows x64",
        "status": "available",
        "delivery": {
            "kind": "github_release",
            "url": "https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.0/WinsVPN-Setup.exe",
        },
        "artifact": {
            "filename": "WinsVPN-Setup.exe",
            "sha256": "a" * 64,
            "bytes": 1_000_000,
        },
    }
    assert any(
        "GitHub is backup-only and is not website publication authority" in error
        for error in download_manifest_errors(github_pinned_payload)
    )
    github_linux = json.loads(json.dumps(pending_payload))
    github_linux["artifacts"][3] = {
        "id": "linux-x64",
        "label": "Linux x64",
        "status": "available",
        "delivery": {
            "kind": "github_release",
            "url": f"https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.16+33/{linux_name}",
        },
        "artifact": linux_artifact,
    }
    assert any(
        "GitHub is backup-only and is not website publication authority" in error
        for error in download_manifest_errors(github_linux)
    )
    github_latest_payload = json.loads(json.dumps(github_pinned_payload))
    github_latest_payload["artifacts"][0]["delivery"]["url"] = (
        "https://github.com/winsvpn/winsvpn-downloads/releases/latest/download/WinsVPN-Setup.exe"
    )
    assert any(
        "not a version-pinned immutable asset" in error
        for error in download_manifest_errors(github_latest_payload)
    )
    github_wrong_tag_payload = json.loads(json.dumps(github_pinned_payload))
    github_wrong_tag_payload["artifacts"][0]["delivery"]["url"] = (
        "https://github.com/winsvpn/winsvpn-downloads/releases/download/latest/WinsVPN-Setup.exe"
    )
    assert any(
        "not a version-pinned immutable asset" in error
        for error in download_manifest_errors(github_wrong_tag_payload)
    )
    github_wrong_file_payload = json.loads(json.dumps(github_pinned_payload))
    github_wrong_file_payload["artifacts"][0]["delivery"]["url"] = (
        "https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.0/other.exe"
    )
    assert any(
        "GitHub is backup-only and is not website publication authority" in error
        for error in download_manifest_errors(github_wrong_file_payload)
    )
    github_wrong_host_payload = json.loads(json.dumps(github_pinned_payload))
    github_wrong_host_payload["artifacts"][0]["delivery"]["url"] = (
        "https://evil.example/winsvpn/winsvpn-downloads/releases/download/v1.0.0/WinsVPN-Setup.exe"
    )
    assert any(
        "GitHub is backup-only and is not website publication authority" in error
        for error in download_manifest_errors(github_wrong_host_payload)
    )
    ios_name = "wins-vpn-ios-20260824.ipa"
    ios_arch = ["arm64"]
    ios_digest = "b" * 64
    ios_bytes = 1_000_000
    _, ios_privacy_body = _selftest_receipt(
        PRIVACY_RECEIPT_KIND, PRIVACY_RECEIPT_SCHEMA, "ios", ios_name, ios_digest, ios_bytes, ios_arch
    )
    _, ios_release_body = _selftest_receipt(
        RELEASE_RECEIPT_KIND, RELEASE_RECEIPT_SCHEMA, "ios", ios_name, ios_digest, ios_bytes, ios_arch
    )
    _, ios_winn_body = _selftest_receipt(
        WINN_PROVENANCE_KIND,
        WINN_PROVENANCE_SCHEMA,
        "ios",
        ios_name,
        ios_digest,
        ios_bytes,
        ios_arch,
        extra=winn_extra,
    )
    store_payload = json.loads(json.dumps(pending_payload))
    store_payload["artifacts"][6] = {
        "id": "ios",
        "label": "iPhone (iOS)",
        "status": "available",
        "delivery": {
            "kind": "store",
            "url": "https://apps.apple.com/app/id1234567890",
        },
        "artifact": _selftest_available_artifact(
            "ios",
            ios_name,
            ios_digest,
            ios_bytes,
            ios_arch,
            signer_sha256="d" * 64,
            privacy_sha256=hashlib.sha256(ios_privacy_body).hexdigest(),
            release_sha256=hashlib.sha256(ios_release_body).hexdigest(),
            winn_sha256=hashlib.sha256(ios_winn_body).hexdigest(),
        ),
    }
    # Apple stays store_pending for 1.0.16+33, so a well-formed store entry is
    # refused only for release scope; a foreign store host adds its own error.
    assert download_manifest_errors(store_payload) == [
        "artifact ios is outside the owner-authorized 1.0.16+33 desktop launch"
    ]
    store_payload["artifacts"][6]["delivery"]["url"] = "https://evil.example/app/id1234567890"
    assert any(
        "app-store host is not allowed" in error
        for error in download_manifest_errors(store_payload)
    )
    print("Website security self-test passed")


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--selftest"]:
        run_selftest()
        return 0
    if args:
        print(f"usage: {Path(sys.argv[0]).name} [--selftest]", file=sys.stderr)
        return 2

    checks = (
        audit_website_headers()
        + audit_redirects()
        + audit_dom()
        + audit_functions()
        + audit_payment_provider()
        + audit_legal_contract_parity()
        + audit_split_tunnel_claim_parity()
        + audit_secrets()
        + audit_map_tile_proxy()
        + audit_public_download_regressions()
        + audit_downloads()
        + audit_download_manifest()
        + audit_apple_public_release_gate()
        + audit_inline_csp_consistency()
    )
    failures = 0
    skips = 0
    for status, message in checks:
        print(f"{status}: {message}")
        if status == "FAIL":
            failures += 1
        elif status == "SKIP":
            skips += 1
    verdict = "PASS" if not failures else "FAIL"
    print(
        f"SUMMARY: {len(checks) - failures - skips} pass, {skips} explicit "
        f"skip(s), {failures} fail of {len(checks)} checks, verdict {verdict}"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
