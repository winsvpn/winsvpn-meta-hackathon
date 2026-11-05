#!/usr/bin/env python3
"""Shared release secret-scan policy for packaged artifacts.

Customer binaries must not contain private keys, reusable tokens, Google
service-account JSON, or activation secrets. Runtime-required public pins,
public keys, and public certificates remain allowed. Obfuscation, R8, native
stripping, and minification are not secret protection. Durable secrets remain
server-side.
"""

from __future__ import annotations

import re
from collections.abc import Iterator


PUBLIC_PEM_MARKERS: tuple[bytes, ...] = (
    b"-----BEGIN CERTIFICATE-----",
    b"-----BEGIN PUBLIC KEY-----",
    b"-----BEGIN RSA PUBLIC KEY-----",
    b"-----BEGIN SSH2 PUBLIC KEY-----",
    b"-----BEGIN X509 CRL-----",
)
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
PRIVATE_KEY_MARKERS: tuple[bytes, ...] = (
    b"PRIVATE KEY-----",
    b"BEGIN OPENSSH PRIVATE KEY",
)

# Typed Google service-account JSON. The pattern matches the credential object
# marker, not a public email domain or a documentation word by itself.
SERVICE_ACCOUNT_JSON_RE = re.compile(
    rb"(?i)[\"']type[\"']\s*:\s*[\"']service_account[\"']"
)
SERVICE_ACCOUNT_MEMBER_RE = re.compile(
    r"(?i)(?:^|/)(?:[^/]*[_-])?(?:service[_-]?account|"
    r"application_default_credentials)(?:[_-][^/]*)?\.json$"
)

REUSABLE_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    (
        "private_key_material",
        re.compile(
            rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----"
        ),
    ),
    (
        "github_token",
        re.compile(
            rb"\b(?:gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{40,255})\b"
        ),
    ),
    (
        "google_oauth_client_secret",
        re.compile(rb"\bGOCSPX-[A-Za-z0-9_-]{20,120}\b"),
    ),
    ("google_api_key", re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("aws_access_key_id", re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("slack_token", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,255}\b")),
    (
        "stripe_live_secret",
        re.compile(rb"\b(?:sk|rk)_live_[A-Za-z0-9]{20,255}\b"),
    ),
    (
        "gitlab_personal_token",
        re.compile(rb"\bglpat-[A-Za-z0-9_-]{20,128}\b"),
    ),
    (
        "npm_access_token",
        re.compile(rb"\bnpm_[A-Za-z0-9]{36,128}\b"),
    ),
    (
        "pypi_api_token",
        re.compile(rb"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,400}\b"),
    ),
    (
        "google_service_account_json",
        SERVICE_ACCOUNT_JSON_RE,
    ),
)

# Extra artifact-walk needles used by the obfuscation contract. These stay
# out of the privacy scanner's core list because they can match compressed
# native tables that are not packaged credentials.
OBFUSCATION_EXTRA_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    (
        "base64_private_key_material",
        re.compile(rb"\bLS0tLS1CRUdJTi[A-Za-z0-9+/=]{24,}"),
    ),
    (
        "credentialed_uri",
        re.compile(
            rb"(?i)\bhttps?://[A-Za-z0-9._~-]{3,128}:"
            rb"[A-Za-z0-9._~!$&'()*+,;=%-]{12,128}@"
            rb"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?::[0-9]{1,5})?(?:[/?#]|\b)"
        ),
    ),
)
LONG_LIVED_CREDENTIAL_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    REUSABLE_SECRET_PATTERNS + OBFUSCATION_EXTRA_SECRET_PATTERNS
)

# Assignment names that mean a packaged secret. Public-key / pin field names
# are intentionally absent so runtime-required public material stays allowed.
CREDENTIAL_ASSIGNMENT_RE = re.compile(
    rb"(?i)(?:\"|'|\b)(?P<name>api[_-]?key|api[_-]?token|access[_-]?token|"
    rb"auth[_-]?token|client[_-]?secret|cloudflare[_-]?api[_-]?token|"
    rb"gemini[_-]?api[_-]?key|password|passwd|private[_-]?key|"
    rb"preshared[_-]?key|psk|activation[_-]?secret|"
    rb"x[-_]?wins[-_]?activation)(?:\"|'|\b)\s*[:=]\s*(?P<quote>\"|')?"
    rb"(?P<value>[A-Za-z0-9+/_.=-]{20,512})(?![A-Za-z0-9+/_.=-])"
)
CREDENTIAL_REFERENCE_RE = re.compile(
    rb"(?i)(?:process|import[.]meta|os|runtime|config)[.]env[.]"
    rb"[A-Z_][A-Z0-9_]{2,80}\Z"
)
SOURCE_MEMBER_REFERENCE_RE = re.compile(
    rb"[A-Za-z_][A-Za-z0-9_]*(?:[.][A-Za-z_][A-Za-z0-9_]*)+\Z"
)
# Exact sentinel values the app ships on purpose: each tells native code to use
# a key that already lives in the platform keystore. Exact bytes only, never a
# pattern (lib/winn_protocol_ios_raw_config.dart, ios/Runner/AppDelegate.swift).
REVIEWED_RUNTIME_KEY_SENTINELS: frozenset[bytes] = frozenset(
    {b"__WINS_EXISTING_KEYCHAIN_PRIVATE_KEY__"}
)
CREDENTIAL_PLACEHOLDER_RE = re.compile(
    rb"(?i)(?:YOUR_[A-Z0-9_]{3,}|REPLACE_WITH_[A-Z0-9_]{3,}|"
    rb"REDACTED(?:_[A-Z0-9_]+)?|PLACEHOLDER(?:_[A-Z0-9_]+)?)\Z"
)
# Runtime-required public pin / public-key assignment names. These must never
# be treated as credential names even if a later pattern grows a bare "key".
PUBLIC_MATERIAL_ASSIGNMENT_NAMES: frozenset[str] = frozenset(
    {
        "certificate",
        "client_public_key",
        "pinned_certificate",
        "public_key",
        "publickey",
        "pubkey",
        "server_public_key",
        "spki",
        "spki_pin",
    }
)
PUBLIC_PIN_VALUE_RE = re.compile(rb"(?:sha256/)?[A-Za-z0-9+/_-]{42,44}={0,2}\Z")


def _latin1_and_utf16_views(data: bytes) -> Iterator[bytes]:
    yield data
    if b"\x00" not in data:
        return
    for encoding in ("utf-16-le", "utf-16-be"):
        yield data.decode(encoding, errors="ignore").encode("utf-8", errors="ignore")


def contains_private_key_marker(data: bytes) -> bool:
    return any(marker in data for marker in PRIVATE_KEY_MARKERS)


def contains_only_public_crypto_material(data: bytes) -> bool:
    if contains_private_key_marker(data):
        return False
    if any(marker in data for marker in PUBLIC_PEM_MARKERS):
        return True
    if ED25519_SPKI_PREFIX in data:
        return True
    return False


def is_runtime_public_pin_or_key_value(value: bytes) -> bool:
    if contains_private_key_marker(value):
        return False
    if any(marker in value for marker in PUBLIC_PEM_MARKERS):
        return True
    return PUBLIC_PIN_VALUE_RE.fullmatch(value) is not None


def _folded_assignment_name(name: bytes) -> str:
    return name.decode("ascii", errors="ignore").lower().replace("-", "_")


def is_public_material_assignment_name(name: bytes) -> bool:
    folded = _folded_assignment_name(name)
    if folded in PUBLIC_MATERIAL_ASSIGNMENT_NAMES:
        return True
    return folded.endswith("_public_key") or folded.endswith("_spki_pin")


def service_account_member_name(label: str) -> bool:
    normalized = label.replace("\\", "/")
    return SERVICE_ACCOUNT_MEMBER_RE.search(normalized) is not None


def packaged_credential_assignment(data: bytes) -> bool:
    for view in _latin1_and_utf16_views(data):
        for match in CREDENTIAL_ASSIGNMENT_RE.finditer(view):
            name = match.group("name")
            value = match.group("value")
            trailing = view[match.end() :].lstrip()[:1]
            if is_public_material_assignment_name(name):
                continue
            if not match.group("quote") and SOURCE_MEMBER_REFERENCE_RE.fullmatch(value):
                continue
            if trailing in {b"(", b"[", b".", b"?"}:
                continue
            if CREDENTIAL_REFERENCE_RE.fullmatch(value):
                continue
            if CREDENTIAL_PLACEHOLDER_RE.fullmatch(value):
                continue
            if value in REVIEWED_RUNTIME_KEY_SENTINELS:
                continue
            return True
    return False


def secret_category(
    data: bytes,
    patterns: tuple[tuple[str, re.Pattern[bytes]], ...] = REUSABLE_SECRET_PATTERNS,
) -> str | None:
    for view in _latin1_and_utf16_views(data):
        for category, pattern in patterns:
            if pattern.search(view):
                return category
    return None


def reusable_secret_category(data: bytes) -> str | None:
    return secret_category(data, REUSABLE_SECRET_PATTERNS)


def long_lived_secret_category(data: bytes) -> str | None:
    return secret_category(data, LONG_LIVED_CREDENTIAL_PATTERNS)
