#!/usr/bin/env python3
"""Compare the LIVE winsvpn.org deployment against the repository build.

    python3 tools/verify_live_deployment.py
    python3 tools/verify_live_deployment.py --origin https://winsvpn.org

WHY THIS EXISTS. tools/website_security_audit.py audits the FILES IN THIS
REPOSITORY. It passes 56/57 while the live origin serves an older build whose
inline-script hash, Permissions-Policy and crypto-checkout markup all differ.
Every website gate in this tree has that same blind spot, which is how a
published site kept a dead "Pay with Crypto" coin button and a payment=()
Permissions-Policy that disables the Payment Request API for the wallet
buttons, with every local check green.

WHAT IT CHECKS. Read-only GETs only. No account is created, no order is placed,
no email is sent, and no server state is touched.

  1. The live document's inline <script> and <style> hashes are each present in
     the live Content-Security-Policy. A block that is not is a block the
     browser refuses to run.
  2. The live CSP equals the repository's Content-Security-Policy in
     web/_headers.
  3. The live Permissions-Policy equals the repository's.
  4. The live document contains every DOM marker the repository build ships.
     These are the cheap, stable, structural fingerprints of the fixes that
     must not silently regress on the origin.

EXIT STATUS. 0 when the origin matches the repository, 1 on any mismatch, 2 when
the origin could not be read at all. A non-zero status means "publish the
repository build", not "edit this file".
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import pathlib
import re
import ssl
import sys
import urllib.error
import urllib.request

DEFAULT_ORIGIN = "https://winsvpn.org"
REQUEST_TIMEOUT_SECONDS = 45
USER_AGENT = "winsvpn-live-deployment-verifier/1 (+read-only)"

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
HEADERS_FILE = REPO_ROOT / "web" / "_headers"
INDEX_FILE = REPO_ROOT / "web" / "index.html"

# Structural markers of the shipped crypto-checkout behaviour. Each one is a
# fix that a stale origin silently undoes, and each is a plain substring so this
# file never needs an HTML parser.
REQUIRED_LIVE_MARKERS = (
    # The retry control the inline error renders inside [data-crypto-row].
    "crypto-retry-button",
    # The reparent guard that keeps the donation modal out of the hidden drawer.
    "document.body.appendChild(backdrop)",
    # The coin selectors start disabled and are enabled only once
    # /api/site/crypto-config has loaded.
    "setCryptoCoinSelectors",
    # The fail-closed replacement for the old openModal() fallback.
    "renderCryptoUnavailable",
)

INLINE_SCRIPT_RE = re.compile(r"<script\b([^>]*)>(.*?)</script>", re.S | re.I)
INLINE_STYLE_RE = re.compile(r"<style\b([^>]*)>(.*?)</style>", re.S | re.I)
SRC_ATTR_RE = re.compile(r"\bsrc\s*=", re.I)


def sha256_b64(text: str) -> str:
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def tls_context() -> ssl.SSLContext:
    """A verifying TLS context that works on a Python without a wired trust store.

    A stock macOS Homebrew Python ships no CA bundle, so urlopen raises
    CERTIFICATE_VERIFY_FAILED against every HTTPS origin. Falling back to an
    unverified context would turn this checker into one that cannot tell a real
    origin from an interception proxy, so it never does: certifi when present,
    otherwise the platform default, and a hard failure if neither verifies.
    """
    try:
        import certifi
    except ImportError:
        return ssl.create_default_context()
    return ssl.create_default_context(cafile=certifi.where())


def fetch(url: str) -> tuple[str, dict[str, str]]:
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(
        request, timeout=REQUEST_TIMEOUT_SECONDS, context=tls_context()
    ) as response:
        body = response.read().decode("utf-8", "replace")
        headers = {key.lower(): value for key, value in response.headers.items()}
    return body, headers


def inline_blocks(html: str) -> tuple[list[str], list[str]]:
    scripts = [
        match.group(2)
        for match in INLINE_SCRIPT_RE.finditer(html)
        if not SRC_ATTR_RE.search(match.group(1))
    ]
    styles = [match.group(2) for match in INLINE_STYLE_RE.finditer(html)]
    return scripts, styles


def repo_header(name: str) -> str:
    """The value of `name` in the repository's global web/_headers block."""
    prefix = f"{name.lower()}:"
    for raw in HEADERS_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.lower().startswith(prefix):
            return line[len(prefix):].strip()
    raise SystemExit(f"{HEADERS_FILE} declares no {name} header")


def normalise_policy(value: str) -> str:
    """Collapse runs of whitespace so formatting alone never fails a check."""
    return " ".join(value.split())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--origin", default=DEFAULT_ORIGIN)
    arguments = parser.parse_args()
    origin = arguments.origin.rstrip("/")

    try:
        live_html, live_headers = fetch(origin + "/")
    except (urllib.error.URLError, OSError, TimeoutError) as error:
        print(f"FAIL: could not read {origin}/: {error}")
        return 2

    failures: list[str] = []
    checks = 0

    live_csp = normalise_policy(live_headers.get("content-security-policy", ""))
    live_permissions = normalise_policy(live_headers.get("permissions-policy", ""))
    repo_csp = normalise_policy(repo_header("Content-Security-Policy"))
    repo_permissions = normalise_policy(repo_header("Permissions-Policy"))

    # 1. Every inline block the live document ships is pinned by the live CSP.
    scripts, styles = inline_blocks(live_html)
    for index, block in enumerate(scripts):
        checks += 1
        digest = sha256_b64(block)
        if f"'sha256-{digest}'" in live_csp:
            print(f"PASS: live inline <script> #{index} ({len(block)} bytes) is pinned by the live CSP")
        else:
            failures.append(
                f"live inline <script> #{index} ({len(block)} bytes) hash sha256-{digest} "
                f"is absent from the live CSP, so the browser refuses to run it"
            )
    for index, block in enumerate(styles):
        checks += 1
        digest = sha256_b64(block)
        if f"'sha256-{digest}'" in live_csp:
            print(f"PASS: live inline <style> #{index} ({len(block)} bytes) is pinned by the live CSP")
        else:
            failures.append(
                f"live inline <style> #{index} ({len(block)} bytes) hash sha256-{digest} "
                f"is absent from the live CSP"
            )

    # 2 and 3. The live security headers are the repository's.
    checks += 1
    if live_csp == repo_csp:
        print("PASS: the live Content-Security-Policy equals web/_headers")
    else:
        failures.append(
            "the live Content-Security-Policy differs from web/_headers; the origin is "
            "serving an older header set"
        )

    checks += 1
    if live_permissions == repo_permissions:
        print("PASS: the live Permissions-Policy equals web/_headers")
    else:
        failures.append(
            f"the live Permissions-Policy differs from web/_headers. live={live_permissions!r} "
            f"repo={repo_permissions!r}"
        )

    # 4. The live document carries every marker the repository build ships.
    repo_html = INDEX_FILE.read_text(encoding="utf-8")
    for marker in REQUIRED_LIVE_MARKERS:
        checks += 1
        if marker not in repo_html:
            failures.append(
                f"web/index.html no longer contains the marker {marker!r}; update "
                f"REQUIRED_LIVE_MARKERS deliberately rather than deleting the check"
            )
            continue
        if marker in live_html:
            print(f"PASS: the live document ships {marker!r}")
        else:
            failures.append(
                f"the live document is missing {marker!r}, which web/index.html ships; "
                f"the origin is serving an older build"
            )

    print()
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        print(
            f"\nSUMMARY: {checks - len(failures)} pass, {len(failures)} fail of {checks} checks, "
            f"verdict FAIL against {origin}"
        )
        print("Publish the repository build to this origin, then re-run.")
        return 1

    print(f"SUMMARY: {checks} pass, 0 fail of {checks} checks, verdict PASS against {origin}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
