from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CONTROL = ROOT / "server/wins_control_plane_setup_ONETOUCH.sh"
DATA = ROOT / "server/wins_data_plane_setup_ONETOUCH.sh"
DISPOSITION = ROOT / "server/vendor/cloudflared-2026.8.2-deb-disposition.md"
REVIEW = ROOT / "server/vendor/cloudflared-2026.8.3-security-review.md"

EXPECTED_VERSION = "2026.10.0"
EXPECTED_AMD64 = "9721287c28f78cb623e77c7b95a63feea87e909054d75666a0ec9eff20e5d548"
EXPECTED_ARM64 = "7e0d76de3858b6396bd234ae26182bee222133398667d2647b90381d00c00e98"
EXPECTED_KEY = "1bd95f4082b320d541bee351560fc2765aa9f9cd8efa4c9e32135e63f252721d"
EXPECTED_FINGERPRINT = "CC94B39C77AE7342A68B89628A682D308D4E5E73"


def constant(text: str, name: str) -> str:
    match = re.search(rf'^{name}="\$\{{{name}:-([^}}]+)\}}"$', text, re.MULTILINE)
    assert match is not None, name
    return match.group(1)


def test_both_roles_pin_exact_deb_version_and_digests() -> None:
    for path in (CONTROL, DATA):
        text = path.read_text(encoding="utf-8")
        assert constant(text, "CLOUDFLARED_VERSION") == EXPECTED_VERSION
        assert constant(text, "CLOUDFLARED_AMD64_SHA256") == EXPECTED_AMD64
        assert constant(text, "CLOUDFLARED_ARM64_SHA256") == EXPECTED_ARM64
        assert re.fullmatch(r"[0-9a-f]{64}", EXPECTED_AMD64)
        assert re.fullmatch(r"[0-9a-f]{64}", EXPECTED_ARM64)


def test_both_roles_pin_committed_key_and_fingerprint() -> None:
    for path in (CONTROL, DATA):
        text = path.read_text(encoding="utf-8")
        assert constant(text, "CLOUDFLARE_KEY_SHA256") == EXPECTED_KEY
        assert constant(text, "CLOUDFLARE_KEY_FINGERPRINT") == EXPECTED_FINGERPRINT
    key_file = ROOT / "server/vendor/cloudflare-main.gpg"
    assert key_file.is_file() and key_file.stat().st_size > 0


def test_both_roles_enforce_exact_version_and_token_file() -> None:
    for path in (CONTROL, DATA):
        text = path.read_text(encoding="utf-8")
        assert "install_cloudflared_package() {" in text
        assert "cloudflared tunnel run --help" in text
        assert "--token-file" in text
        assert "apt-mark hold cloudflared" in text


def test_disposition_is_bound_to_the_pinned_version_and_states_the_premise_is_unattested() -> None:
    doc = DISPOSITION.read_text(encoding="utf-8")
    assert f"# cloudflared {EXPECTED_VERSION} deb disposition" in doc
    assert EXPECTED_AMD64 in doc and EXPECTED_ARM64 in doc
    assert "has NOT been re-attested for " + EXPECTED_VERSION in doc
    assert "UNVERIFIED" in doc
    # No stale pin from an earlier disposition may survive in the document.
    for stale in (
        "c805c7c8102190c04dfc16e3b4cc4acc9007d5b19b3afbcd608ea6fed7645a43",
        "096739c69f62cace40b144f0e6c81e61333f3d320ce07a265c7b17b5e925731c",
        "CLOUDFLARED_VERSION=2026.8.2",
    ):
        assert stale not in doc, stale


def test_disposition_documents_reachability_premise() -> None:
    doc = DISPOSITION.read_text(encoding="utf-8")
    assert "GO-2026-5932" in doc
    assert "does not call the affected OpenPGP symbols" in doc
    review = REVIEW.read_text(encoding="utf-8")
    assert "does not call the affected OpenPGP symbols" in review
