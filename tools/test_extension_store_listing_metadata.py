#!/usr/bin/env python3
"""Local-only consistency tests for the browser-extension store-listing drafts."""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import struct
import sys
import tempfile
import unicodedata
import zipfile
import zlib
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "extension" / "tools"))

import checks  # noqa: E402
import extension_store_listing_metadata as listing_gate  # noqa: E402
import jsonc  # noqa: E402


LISTING_ROOT = ROOT / "extension" / "store_listings"
ALLOWED_LISTING_FILES = listing_gate.ALLOWED_LISTING_FILES
ALLOWED_JSON_LISTING_FILES = frozenset(
    {
        listing_gate.STORE_IDENTITY_NAME,
        listing_gate.OWNER_SIGNOFF_NAME,
        listing_gate.PRIVACY_LABEL_NAME,
        listing_gate.RELEASE_CANDIDATE_NAME,
    }
)
NAME_LIMITS = {"chrome": 75, "edge": 45, "firefox": 50}
DESCRIPTION_LIMIT = 132
CHROME_NAME = checks.EXPECTED_TARGET_NAMES["chrome"]
EDGE_NAME = checks.EXPECTED_TARGET_NAMES["edge"]
FIREFOX_NAME = checks.EXPECTED_TARGET_NAMES["firefox"]
CHROME_TARGET = checks.EXTENSION_RELEASE_TARGETS["chrome"]
EDGE_TARGET = checks.EXTENSION_RELEASE_TARGETS["edge"]
FIREFOX_TARGET = checks.EXTENSION_RELEASE_TARGETS["firefox"]
GECKO_ID = "companion@winsvpn.org"
STORES = {
    "chrome": "Chrome Web Store",
    "edge": "Microsoft Edge Add-ons",
    "firefox": "Firefox Add-ons",
}
LISTINGS = {
    "chrome": {
        "name": CHROME_NAME,
        "file": "chrome.md",
        "target_id": CHROME_TARGET,
        "store": STORES["chrome"],
    },
    "edge": {
        "name": EDGE_NAME,
        "file": "edge.md",
        "target_id": EDGE_TARGET,
        "store": STORES["edge"],
    },
    "firefox": {
        "name": FIREFOX_NAME,
        "file": "firefox.md",
        "target_id": FIREFOX_TARGET,
        "store": STORES["firefox"],
    },
}
COMPLETED_CHECKBOX = re.compile(r"(?m)^- \[[xX]\]")
STORE_LISTING_URL = re.compile(
    r"https?://(?:chrome\.google\.com/webstore|chromewebstore\.google\.com|"
    r"microsoftedge\.microsoft\.com/addons|addons\.mozilla\.org)/",
    re.IGNORECASE,
)
CHROME_STORE_ID = re.compile(r"\b[a-p]{32}\b")
RECEIPT_HASH = re.compile(r"upload receipt[^.\n]*[a-fA-F0-9]{64}")
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp", ".gif"}
RECEIPT_SUFFIXES = {".json", ".sha256", ".zip", ".xpi"}
PRETTY_JS = "export function start() {\n  const ok = true;\n  return ok;\n}\n"
PENDING_SIGNER = {
    "status": "pending",
    "identity": "none",
    "store_signed": False,
}
NONFINITE_JSON_CONSTANTS = ("NaN", "Infinity", "-Infinity")


def _manifest(browser: str) -> dict[str, object]:
    base = jsonc.load_file(ROOT / "extension" / "manifest" / "base.jsonc")
    override = jsonc.load_file(ROOT / "extension" / "manifest" / f"{browser}.jsonc")
    merged = dict(base)
    merged.update(override)
    merged["permissions"] = list(
        dict.fromkeys(base["permissions"] + override.get("permissions", []))
    )
    merged["version"] = checks.reviewed_extension_version(browser)
    return merged


def _listing_text(browser: str) -> str:
    return (LISTING_ROOT / LISTINGS[browser]["file"]).read_text(encoding="utf-8")


def _listing_files() -> list[Path]:
    return sorted(path for path in LISTING_ROOT.rglob("*") if path.is_file() or path.is_symlink())


def test_listing_readme_keeps_application_release_and_extension_semver_distinct() -> None:
    readme = (LISTING_ROOT / "README.md").read_text(encoding="utf-8")
    identity = json.loads(
        (ROOT / "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json").read_text(
            encoding="utf-8"
        )
    )
    release = identity["canonical_release"]
    extension_version = identity["platform_mappings"]["browser_extensions"]["version"]
    assert f"`{release}`" in readme
    assert f"`{extension_version}`" in readme
    assert "`pubspec.yaml`" in readme
    assert extension_version == release.split("+", 1)[0]
    assert "BLOCKED until a real upload receipt binds the exact" in readme
    assert "Missing owner or store evidence" in readme
    assert listing_gate.LISTING_EVIDENCE_STATUS in readme
    assert "`chrome-extension-package`" in readme
    assert "`edge-extension-package`" in readme
    assert "`firefox-extension-package`" in readme
    assert GECKO_ID in readme
    assert "fails closed" in readme
    assert listing_gate.CHROME_STORE_ID in readme
    assert listing_gate.EDGE_STORE_ID in readme
    assert listing_gate.NATIVE_HOST_NAME in readme
    assert "Upload authorized: no." in readme
    assert "unsigned" in readme
    assert "whitespace-only" in readme
    assert "no_current_candidate" in readme
    assert listing_gate.HELD_HASH_STATUS in readme
    assert listing_gate.PRIVACY_LABEL_NAME in readme
    assert listing_gate.RELEASE_CANDIDATE_NAME in readme
    assert "Screenshot binaries" in readme or "screenshot binaries" in readme.lower()


def test_listing_directory_rejects_extra_files_and_nonregular_entries() -> None:
    names = {path.name for path in LISTING_ROOT.iterdir()}
    assert names == ALLOWED_LISTING_FILES
    discovered = _listing_files()
    assert {path.name for path in discovered} == ALLOWED_LISTING_FILES
    identities: set[tuple[int, int]] = set()
    for path in discovered:
        assert path.parent == LISTING_ROOT
        assert not path.is_symlink()
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode)
        assert info.st_nlink == 1
        identity = (info.st_dev, info.st_ino)
        assert identity not in identities
        identities.add(identity)
        assert path.suffix.lower() not in IMAGE_SUFFIXES
        payload = path.read_bytes()
        payload.decode("ascii")
        assert b"\x00" not in payload
        if path.name in ALLOWED_JSON_LISTING_FILES:
            json.loads(payload.decode("ascii"))
            continue
        if path.name != "README.md":
            assert path.suffix.lower() not in RECEIPT_SUFFIXES
    live = listing_gate.validate_live_listings(ROOT)
    assert live["ok"] is False
    assert live["status"] == listing_gate.LISTING_EVIDENCE_STATUS
    assert live["reason"] == listing_gate.LISTING_EVIDENCE_REASON
    assert live["publication_authorized"] is False
    assert live["upload_authorized"] is False
    assert live["upload_attempted"] is False
    assert live["native_host_name"] == listing_gate.NATIVE_HOST_NAME


def test_chrome_and_edge_listings_are_distinct_identities() -> None:
    chrome = _listing_text("chrome")
    edge = _listing_text("edge")
    firefox = _listing_text("firefox")
    assert CHROME_NAME != EDGE_NAME
    assert CHROME_TARGET != EDGE_TARGET
    assert CHROME_NAME not in edge
    assert EDGE_NAME not in chrome
    assert f"`{CHROME_TARGET}`" in chrome
    assert f"`{EDGE_TARGET}`" in edge
    assert f"`{CHROME_TARGET}`" not in edge
    assert f"`{EDGE_TARGET}`" not in chrome
    assert f"`{CHROME_TARGET}`" not in firefox
    assert f"`{EDGE_TARGET}`" not in firefox
    assert "Chrome Web Store" in chrome
    assert "Microsoft Edge Add-ons" in edge
    assert "is not Chrome evidence" in chrome
    assert "is not Edge evidence" in edge
    assert chrome != edge
    chrome_info = (LISTING_ROOT / "chrome.md").stat()
    edge_info = (LISTING_ROOT / "edge.md").stat()
    assert (chrome_info.st_dev, chrome_info.st_ino) != (
        edge_info.st_dev,
        edge_info.st_ino,
    )


@pytest.mark.parametrize("browser", sorted(LISTINGS))
def test_each_local_listing_matches_the_reviewed_manifest(browser: str) -> None:
    listing = LISTINGS[browser]
    text = _listing_text(browser)
    manifest = _manifest(browser)
    name = str(manifest["name"])
    version = str(manifest["version"])
    description = str(manifest["description"])

    assert name == listing["name"]
    assert len(name) <= NAME_LIMITS[browser]
    assert len(description) <= DESCRIPTION_LIMIT
    assert f"Name: `{name}`" in text
    assert f"Package version: `{version}`" in text
    assert f"Short description: `{description}`" in text
    assert f"Upload target: `{listing['target_id']}`" in text
    assert f"Store: `{listing['store']}`" in text
    if browser == "firefox":
        assert "Status: LOCAL LISTING TEXT ONLY." in text
        assert "No Firefox Add-ons draft or AMO item exists." in text
    else:
        assert "Status: BLOCKED." in text
        assert "Local draft only" in text
    assert "Listing evidence: BLOCKED." in text
    assert "Store evidence: BLOCKED." in text
    assert "BLOCKED until a real" in text
    assert "missing owner or store evidence" in text.lower()
    assert "upload receipt binds the exact" in text
    assert "Upload receipt: none." in text
    assert "Upload authorized: no." in text
    assert "Publication authorized: no." in text
    identity = listing_gate._load_release_identity(ROOT)
    assert f"Application companion release: `{identity['release']}`" in text
    assert f"Native-host name: `{listing_gate.NATIVE_HOST_NAME}`" in text
    assert "optional_host_permissions" in text
    assert "`<all_urls>`" in text
    assert "unsigned" in text
    assert "Archive signed: no." in text
    assert "Privacy practices: BLOCKED." in text
    assert "Category: owner-blocked." in text
    assert "whitespace-only" in text
    assert "Identifier mangling is forbidden." in text
    assert "Screenshots: none captured." in text
    assert "1280x800" in text
    assert "upload receipt" in text
    assert "approval" in text
    assert "screenshots" in text
    assert "It is not a standalone VPN" in text
    assert "does not make remote network requests" in text
    assert "https://www.winsvpn.org/support/" in text
    assert "https://www.winsvpn.org/browser-extension-privacy/" in text
    assert "counsel review pending" in text
    assert COMPLETED_CHECKBOX.search(text) is None
    assert STORE_LISTING_URL.search(text) is None
    assert RECEIPT_HASH.search(text) is None
    for permission in manifest["permissions"]:
        assert f"`{permission}`" in text

    if browser == "firefox":
        gecko = manifest["browser_specific_settings"]["gecko"]
        assert gecko["id"] == GECKO_ID
        assert f"Gecko ID: `{GECKO_ID}`" in text
        assert "data_collection_permissions` as `none`" in text
        assert gecko["data_collection_permissions"]["required"] == ["none"]
        assert "AMO listing URL: none." in text
        assert "allowed_extensions" in text
        assert "License: owner-blocked." in text
        assert "Reviewer source: authored `extension/src`." in text
        assert "Mozilla store review: none." in text
        assert CHROME_STORE_ID.search(text) is None
    else:
        store_id = (
            listing_gate.CHROME_STORE_ID
            if browser == "chrome"
            else listing_gate.EDGE_STORE_ID
        )
        assert f"Store ID: `{store_id}`" in text
        assert "owner-authenticated draft" in text.lower()
        assert "does not request host access at installation" in text
        assert "Store ID: none." not in text
        assert set(CHROME_STORE_ID.findall(text)) == {store_id}


def test_listings_stay_blocked_without_real_upload_receipt() -> None:
    readme = (LISTING_ROOT / "README.md").read_text(encoding="utf-8")
    assert COMPLETED_CHECKBOX.search(readme) is None
    assert STORE_LISTING_URL.search(readme) is None
    for browser, listing in LISTINGS.items():
        text = _listing_text(browser)
        assert f"`{listing['target_id']}`" in text
        assert "No " in text.split("Status:", 1)[1].split("##", 1)[0]
        status = text.split("##", 1)[0]
        assert "upload receipt" in status.lower()
        assert "none" in status.lower() or "no " in status.lower()
        assert listing_gate.LISTING_EVIDENCE_STATUS in status
        assert "- [ ] Store-required screenshots" in text
        assert "- [ ] Portal upload, review, approval, and public URL" in text
    states = listing_gate.listing_states(ROOT)
    assert states["ok"] is False
    assert states["status"] == listing_gate.LISTING_EVIDENCE_STATUS
    assert states["publication_authorized"] is False
    assert states["upload_authorized"] is False
    assert states["upload_attempted"] is False
    assert states["reason"] == listing_gate.LISTING_EVIDENCE_REASON
    assert states["trusted_signer"] == listing_gate.LISTING_EVIDENCE_STATUS
    assert states["owner_authorization"] == listing_gate.LISTING_EVIDENCE_STATUS
    assert states["native_host_name"] == listing_gate.NATIVE_HOST_NAME
    assert states["stores"] == {
        CHROME_TARGET: listing_gate.LISTING_EVIDENCE_STATUS,
        EDGE_TARGET: listing_gate.LISTING_EVIDENCE_STATUS,
        FIREFOX_TARGET: listing_gate.LISTING_EVIDENCE_STATUS,
    }
    for target_id, held in states["held_candidate_hashes"].items():
        assert target_id in listing_gate.LISTING_TARGETS
        assert held["sha256"] == listing_gate.HELD_CANDIDATE_SHA256
        assert held["hash_status"] == listing_gate.HELD_HASH_STATUS
        assert held["produced"] is False
        assert held["bytes"] == 0
    assert states["privacy_label"]["off_device_collection"] is False
    assert states["privacy_label"]["status"] == listing_gate.LISTING_EVIDENCE_STATUS
    blocked = listing_gate.bind_listing_upload_receipts({}, {})
    assert blocked["ok"] is False
    assert blocked["status"] == listing_gate.LISTING_EVIDENCE_STATUS
    assert blocked["publication_authorized"] is False
    assert blocked["upload_authorized"] is False
    assert blocked["stores"] == states["stores"]


_ISSUER = Ed25519PrivateKey.generate()
_ISSUER_PUBLIC = _ISSUER.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
_PRODUCER_PACKAGES: dict[str, bytes] | None = None
ESBUILD_CACHE = Path("/tmp/winsvpn-extension-esbuild-test-cache")
# The operator-supplied offline cache, captured before any fixture redirects
# the environment to the private test cache. Archive bytes are re-verified.
CONFIGURED_ESBUILD_CACHE = os.environ.get("WINS_EXTENSION_ESBUILD_CACHE", "").strip()


def _load_builder():
    spec = importlib.util.spec_from_file_location(
        "extension_build_listing_receipts", ROOT / "extension" / "build.py"
    )
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    return builder


def _seed_esbuild_cache(cache: Path) -> None:
    import store_js_minifier as minifier

    pin = minifier.pin_for_host()
    slot = cache / minifier.host_platform_key() / str(pin["archive_sha256"])
    slot.mkdir(parents=True, exist_ok=True)
    dest = slot / str(pin["archive_name"])
    discovered = Path("/tmp/winsvpn-esbuild-discovery/archives") / str(pin["archive_name"])
    if dest.is_file() and minifier.sha256_file(dest) == pin["archive_sha256"]:
        return
    sources = [discovered]
    if CONFIGURED_ESBUILD_CACHE:
        sources.insert(0, (
            Path(CONFIGURED_ESBUILD_CACHE) / minifier.host_platform_key()
            / str(pin["archive_sha256"]) / str(pin["archive_name"])
        ))
    for source in sources:
        if source.is_file():
            payload = source.read_bytes()
            minifier.verify_archive_bytes(payload, pin)
            dest.write_bytes(payload)
            dest.chmod(0o444)
            return
    raise RuntimeError("esbuild archive is missing from the local test cache")


@pytest.fixture(autouse=True)
def _listing_auth_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        listing_gate,
        "LISTING_RECEIPT_ISSUER_PUBLIC_KEY_HEX",
        _ISSUER_PUBLIC.hex(),
    )
    monkeypatch.setenv(listing_gate.LEDGER_ENV, str(tmp_path / "nonce-ledger"))
    _seed_esbuild_cache(ESBUILD_CACHE)
    monkeypatch.setenv("WINS_EXTENSION_ESBUILD_CACHE", str(ESBUILD_CACHE))
    monkeypatch.setenv("WINS_EXTENSION_ESBUILD_FETCH", "0")


def _artifact_name(browser: str) -> str:
    if browser == "firefox":
        return "wins-vpn-companion-firefox.xpi"
    return f"wins-vpn-companion-{browser}.zip"


def _producer_bytes(browser: str) -> bytes:
    global _PRODUCER_PACKAGES
    if _PRODUCER_PACKAGES is None:
        _seed_esbuild_cache(ESBUILD_CACHE)
        os.environ["WINS_EXTENSION_ESBUILD_CACHE"] = str(ESBUILD_CACHE)
        os.environ["WINS_EXTENSION_ESBUILD_FETCH"] = "0"
        builder = _load_builder()
        dist = Path(tempfile.mkdtemp(prefix="winsvpn-listing-producer-"))
        builder.DIST = dist
        packages: dict[str, bytes] = {}
        for name in ("chrome", "edge", "firefox"):
            artifact = builder.zip_package(builder.stage(name), name)
            packages[name] = artifact.read_bytes()
        _PRODUCER_PACKAGES = packages
    return _PRODUCER_PACKAGES[browser]


def _copy_zip(
    payload: bytes,
    *,
    comment: bytes | None = None,
    extra: dict[str, bytes] | None = None,
    replace: dict[str, bytes] | None = None,
) -> bytes:
    source = zipfile.ZipFile(io.BytesIO(payload))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dest:
        for info in source.infolist():
            body = source.read(info.filename)
            if replace and info.filename in replace:
                body = replace[info.filename]
            dest.writestr(info.filename, body)
        if extra:
            for name, body in extra.items():
                dest.writestr(name, body)
        if comment is not None:
            dest.comment = comment
    return out.getvalue()


def _synthetic_package_bytes(
    browser: str,
    *,
    pretty: bool = False,
    extra: dict[str, bytes] | None = None,
    version: str | None = None,
    name: str | None = None,
) -> bytes:
    js = PRETTY_JS if pretty else "export {};\n"
    listing = LISTINGS[browser]
    package_name = name or listing["name"]
    package_version = version or str(
        json.loads(
            (ROOT / "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json").read_text(
                encoding="utf-8"
            )
        )["platform_mappings"]["browser_extensions"]["version"]
    )
    description = (
        "Sends chosen sites through the Win's VPN desktop tunnel. Not a VPN on "
        "its own; it does nothing unless the desktop app is connected."
    )
    if browser == "firefox":
        manifest: dict[str, object] = {
            "manifest_version": 3,
            "name": package_name,
            "version": package_version,
            "description": description,
            "permissions": [
                "proxy",
                "nativeMessaging",
                "webRequest",
                "webRequestAuthProvider",
            ],
            "background": {"scripts": ["src/background/background.js"], "type": "module"},
            "browser_specific_settings": {
                "gecko": {
                    "id": GECKO_ID,
                    "strict_min_version": "140.0",
                    "data_collection_permissions": {"required": ["none"]},
                }
            },
            "content_security_policy": {
                "extension_pages": "script-src 'self'; connect-src 'none'"
            },
        }
        adapter = "firefox"
    else:
        manifest = {
            "manifest_version": 3,
            "name": package_name,
            "version": package_version,
            "description": description,
            "minimum_chrome_version": "116",
            "permissions": [
                "proxy",
                "nativeMessaging",
                "webRequest",
                "webRequestAuthProvider",
            ],
            "background": {
                "service_worker": "src/background/background.js",
                "type": "module",
            },
            "content_security_policy": {
                "extension_pages": "script-src 'self'; connect-src 'none'"
            },
        }
        adapter = "chromium"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr("src/background/background.js", js)
        archive.writestr("src/background/controller.js", js)
        archive.writestr(f"src/adapters/{adapter}.js", js)
        if extra:
            for member, body in extra.items():
                archive.writestr(member, body)
    return buf.getvalue()


def _write_receipt(path: Path, record: dict[str, object]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="ascii")
    os.chmod(path, 0o600)
    return path


def _prepare_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    repo = tmp_path / "repo"
    (repo / "docs" / "rulings").mkdir(parents=True)
    dest = repo / "docs" / "rulings" / "RELEASE_IDENTITY_MAP_20260824.json"
    dest.write_bytes((ROOT / "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json").read_bytes())
    os.chmod(dest, 0o644)
    (repo / "pubspec.yaml").write_bytes((ROOT / "pubspec.yaml").read_bytes())
    (repo / "extension" / "dist").mkdir(parents=True)
    monkeypatch.setattr(listing_gate, "ROOT", repo)
    return repo


def _write_artifact(repo: Path, browser: str, payload: bytes) -> Path:
    path = repo / "extension" / "dist" / _artifact_name(browser)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    os.chmod(path, 0o644)
    return path


def _signed_receipt(
    browser: str,
    payload: bytes,
    *,
    now: dt.datetime | None = None,
) -> dict[str, object]:
    listing = LISTINGS[browser]
    target_id = listing["target_id"]
    spec = listing_gate.LISTING_TARGETS[target_id]
    identity = json.loads(
        (ROOT / "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json").read_text(
            encoding="utf-8"
        )
    )
    digest = hashlib.sha256(payload).hexdigest()
    challenge = listing_gate.issue_listing_nonce(
        target_id,
        artifact_path=f"extension/dist/{_artifact_name(browser)}",
        artifact_sha256=digest,
        artifact_bytes=len(payload),
        now=now,
    )
    auth = dict(challenge)
    auth["signature"] = _ISSUER.sign(listing_gate._canonical_auth_bytes(auth)).hex()
    package: dict[str, object] = {
        "name": listing["name"],
        "version": identity["platform_mappings"]["browser_extensions"]["version"],
        "target_id": target_id,
    }
    if browser == "firefox":
        package["gecko_id"] = GECKO_ID
    return {
        "ok": True,
        "schema_version": listing_gate.LISTING_UPLOAD_RECEIPT_SCHEMA_VERSION,
        "contract": listing_gate.LISTING_UPLOAD_RECEIPT_CONTRACT,
        "release": identity["canonical_release"],
        "target_id": target_id,
        "platform": "extension",
        "issuance_id": auth["nonce"],
        "verified_utc": auth["issued_at"],
        "artifact": {
            "path": f"extension/dist/{_artifact_name(browser)}",
            "sha256": digest,
            "bytes": len(payload),
        },
        "package_identity": package,
        "store_evidence": {
            "surface": spec["store_surface"],
            "status": "not_uploaded",
            "store_id": "none",
        },
        "trusted_signer": dict(PENDING_SIGNER),
        "publication_authorized": False,
        "upload_attempted": False,
        "owner_authorization": {
            "status": "pending",
            "credentials_authorized": False,
            "upload_authorized": False,
        },
        "authentication": auth,
    }


def _bind_bytes(
    browser: str,
    payload: bytes,
    *,
    now: dt.datetime | None = None,
    record: dict[str, object] | None = None,
) -> dict[str, object]:
    receipt = record if record is not None else _signed_receipt(browser, payload, now=now)
    return listing_gate.bind_listing_upload_receipt(
        LISTINGS[browser]["target_id"],
        receipt,
        artifact_sha256=hashlib.sha256(payload).hexdigest(),
        artifact_bytes=len(payload),
        artifact_name=_artifact_name(browser),
        artifact_payload=payload,
        now=now,
    )


def _bind_file(browser: str, receipt: Path, artifact: Path) -> dict[str, object]:
    return listing_gate.bind_listing_upload_receipt_file(
        LISTINGS[browser]["target_id"], receipt, artifact
    )


@pytest.mark.parametrize("browser", ["chrome", "edge", "firefox"])
def test_listings_reject_copied_swapped_symlinked_and_hardlinked_drafts(
    browser: str, tmp_path: Path
) -> None:
    others = [name for name in LISTINGS if name != browser]
    source = LISTING_ROOT / LISTINGS[browser]["file"]
    listing_gate.validate_listing_file(browser, source)
    copied = tmp_path / f"{browser}-copy.md"
    copied.write_bytes(source.read_bytes())
    with pytest.raises(
        listing_gate.ListingReceiptError, match="copied or is not the exact listing identity"
    ):
        listing_gate.validate_listing_file(browser, copied)
    for other in others:
        swapped = tmp_path / LISTINGS[other]["file"]
        swapped.write_bytes(copied.read_bytes())
        swapped_text = swapped.read_text(encoding="utf-8")
        assert LISTINGS[browser]["name"] in swapped_text
        assert f"`{LISTINGS[browser]['target_id']}`" in swapped_text
        assert f"`{LISTINGS[other]['target_id']}`" not in swapped_text
        with pytest.raises(
            listing_gate.ListingReceiptError,
            match="swapped or is cross-store|does not bind the exact store identity|imports another 32-letter store ID",
        ):
            listing_gate.validate_listing_file(other, swapped)
        swapped.unlink()
    linked = tmp_path / LISTINGS[browser]["file"]
    linked.symlink_to(copied)
    with pytest.raises(listing_gate.ListingReceiptError, match="symbolic link|symlink"):
        listing_gate.validate_listing_file(browser, linked)
    linked.unlink()
    hard = tmp_path / LISTINGS[browser]["file"]
    try:
        os.link(copied, hard)
    except OSError as error:
        pytest.skip(f"hard links unavailable: {error}")
    with pytest.raises(listing_gate.ListingReceiptError, match="hardlink"):
        listing_gate.validate_listing_file(browser, hard)


@pytest.mark.parametrize("browser", ["chrome", "edge", "firefox"])
def test_listing_receipts_reject_copied_swapped_symlinked_and_hardlinked_files(
    browser: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    others = [name for name in LISTINGS if name != browser]
    repo = _prepare_repo(tmp_path, monkeypatch)
    payload = _producer_bytes(browser)
    artifact = _write_artifact(repo, browser, payload)
    record = _signed_receipt(browser, payload)
    receipt = _write_receipt(tmp_path / "receipts" / f"{browser}.json", record)
    bound = _bind_file(browser, receipt, artifact)
    assert bound["listing_status"] == listing_gate.LISTING_EVIDENCE_STATUS
    assert bound["publication_authorized"] is False
    assert bound["upload_authorized"] is False
    assert bound["unsigned_archive"] is True
    assert bound["native_host_name"] == listing_gate.NATIVE_HOST_NAME
    assert bound["artifact_sha256"] == hashlib.sha256(payload).hexdigest()
    assert bound["artifact_name"] == artifact.name
    assert bound["artifact_path"] == f"extension/dist/{_artifact_name(browser)}"
    assert bound["issuance_id"] == record["issuance_id"]
    assert bound["trusted_signer"] == PENDING_SIGNER
    copied = tmp_path / "receipts" / f"{browser}-copy.json"
    shutil.copy2(receipt, copied)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="cross-store|cross-package|invalid|already consumed|not verifier-issued",
    ):
        _bind_file(others[0], copied, artifact)
    swapped = tmp_path / "receipts" / f"{others[0]}.json"
    shutil.copy2(receipt, swapped)
    other_payload = _producer_bytes(others[0])
    other_artifact = _write_artifact(repo, others[0], other_payload)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="swapped|cross-store|cross-package|invalid|already consumed|not verifier-issued",
    ):
        _bind_file(others[0], swapped, other_artifact)
    linked = tmp_path / "receipts" / f"{browser}-link.json"
    linked.symlink_to(receipt)
    with pytest.raises(listing_gate.ListingReceiptError, match="symbolic link|symlink"):
        _bind_file(browser, linked, artifact)
    hard = tmp_path / "receipts" / f"{browser}-hard.json"
    try:
        os.link(receipt, hard)
    except OSError as error:
        pytest.skip(f"hard links unavailable: {error}")
    with pytest.raises(listing_gate.ListingReceiptError, match="hardlink"):
        _bind_file(browser, hard, artifact)
    live = listing_gate.listing_states(ROOT)
    assert live["stores"][LISTINGS[browser]["target_id"]] == listing_gate.LISTING_EVIDENCE_STATUS


def test_listing_receipts_reject_stale_reused_cross_and_unauthenticated() -> None:
    payloads = {browser: _producer_bytes(browser) for browser in LISTINGS}
    records = {
        FIREFOX_TARGET: _signed_receipt("firefox", payloads["firefox"]),
    }
    package_payloads = {
        FIREFOX_TARGET: payloads["firefox"],
    }
    artifact_ids = {
        FIREFOX_TARGET: (
            hashlib.sha256(payloads["firefox"]).hexdigest(),
            len(payloads["firefox"]),
            _artifact_name("firefox"),
        ),
    }
    bound = listing_gate.bind_listing_upload_receipts(
        records, artifact_ids, package_payloads
    )
    assert bound["ok"] is False
    assert bound["status"] == listing_gate.LISTING_EVIDENCE_STATUS
    assert bound["publication_authorized"] is False
    assert bound["upload_authorized"] is False
    assert bound["trusted_signer"] == listing_gate.LISTING_EVIDENCE_STATUS
    assert bound["reason"] == listing_gate.LISTING_EVIDENCE_REASON
    assert set(bound["stores"]) == {CHROME_TARGET, EDGE_TARGET, FIREFOX_TARGET}
    assert all(
        status == listing_gate.LISTING_EVIDENCE_STATUS
        for status in bound["stores"].values()
    )
    for target_id, receipt in bound["receipts"].items():
        assert receipt["artifact_sha256"] == artifact_ids[target_id][0]
        assert receipt["listing_status"] == listing_gate.LISTING_EVIDENCE_STATUS

    reused = {
        CHROME_TARGET: _signed_receipt("chrome", payloads["chrome"]),
        EDGE_TARGET: _signed_receipt("edge", payloads["chrome"]),
    }
    reused_artifacts = {
        CHROME_TARGET: (
            hashlib.sha256(payloads["chrome"]).hexdigest(),
            len(payloads["chrome"]),
            _artifact_name("chrome"),
        ),
        EDGE_TARGET: (
            hashlib.sha256(payloads["chrome"]).hexdigest(),
            len(payloads["chrome"]),
            _artifact_name("edge"),
        ),
    }
    with pytest.raises(listing_gate.ListingReceiptError, match="receipt reuse"):
        listing_gate.bind_listing_upload_receipts(
            reused, reused_artifacts, {CHROME_TARGET: payloads["chrome"], EDGE_TARGET: payloads["chrome"]}
        )

    now = dt.datetime.now(tz=dt.timezone.utc).replace(microsecond=0)
    stale_payload = payloads["chrome"]
    stale = _signed_receipt("chrome", stale_payload, now=now - dt.timedelta(minutes=6))
    with pytest.raises(listing_gate.ListingReceiptError, match="stale"):
        listing_gate.bind_listing_upload_receipt(
            CHROME_TARGET,
            stale,
            artifact_sha256=hashlib.sha256(stale_payload).hexdigest(),
            artifact_bytes=len(stale_payload),
            artifact_name=_artifact_name("chrome"),
            artifact_payload=stale_payload,
            now=now,
        )

    unauthenticated = _signed_receipt("edge", payloads["edge"])
    unauthenticated["authenticated"] = True
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="self-asserted authenticated:true is not issuer proof",
    ):
        listing_gate.bind_listing_upload_receipt(
            EDGE_TARGET,
            unauthenticated,
            artifact_sha256=hashlib.sha256(payloads["edge"]).hexdigest(),
            artifact_bytes=len(payloads["edge"]),
            artifact_name=_artifact_name("edge"),
            artifact_payload=payloads["edge"],
        )

    cross_store = _signed_receipt("firefox", payloads["firefox"])
    cross_store["store_evidence"]["surface"] = "chrome-web-store"
    with pytest.raises(listing_gate.ListingReceiptError, match="cross-store"):
        listing_gate.bind_listing_upload_receipt(
            FIREFOX_TARGET,
            cross_store,
            artifact_sha256=hashlib.sha256(payloads["firefox"]).hexdigest(),
            artifact_bytes=len(payloads["firefox"]),
            artifact_name=_artifact_name("firefox"),
            artifact_payload=payloads["firefox"],
        )

    cross_version = _signed_receipt("chrome", payloads["chrome"])
    cross_version["package_identity"]["version"] = "9.9.9"
    with pytest.raises(listing_gate.ListingReceiptError, match="cross-version"):
        listing_gate.bind_listing_upload_receipt(
            CHROME_TARGET,
            cross_version,
            artifact_sha256=hashlib.sha256(payloads["chrome"]).hexdigest(),
            artifact_bytes=len(payloads["chrome"]),
            artifact_name=_artifact_name("chrome"),
            artifact_payload=payloads["chrome"],
        )

    cross_package = _signed_receipt("edge", payloads["chrome"])
    with pytest.raises(listing_gate.ListingReceiptError, match="cross-package|swapped"):
        listing_gate.bind_listing_upload_receipt(
            EDGE_TARGET,
            cross_package,
            artifact_sha256=hashlib.sha256(payloads["edge"]).hexdigest(),
            artifact_bytes=len(payloads["edge"]),
            artifact_name=_artifact_name("edge"),
            artifact_payload=payloads["edge"],
        )

    boolean_schema = _signed_receipt("firefox", payloads["firefox"])
    boolean_schema["schema_version"] = True
    with pytest.raises(listing_gate.ListingReceiptError, match="invalid|swapped|cross-package"):
        listing_gate.bind_listing_upload_receipt(
            FIREFOX_TARGET,
            boolean_schema,
            artifact_sha256=hashlib.sha256(payloads["firefox"]).hexdigest(),
            artifact_bytes=len(payloads["firefox"]),
            artifact_name=_artifact_name("firefox"),
            artifact_payload=payloads["firefox"],
        )

    live = listing_gate.listing_states(ROOT)
    assert live["ok"] is False
    assert live["status"] == listing_gate.LISTING_EVIDENCE_STATUS
    assert live["publication_authorized"] is False
    assert live["upload_attempted"] is False


def test_listing_receipts_reject_symlinked_and_hardlinked_candidate_zips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _prepare_repo(tmp_path, monkeypatch)
    payload = _producer_bytes("chrome")
    digest = hashlib.sha256(payload).hexdigest()
    hidden = tmp_path / "hidden-chrome.zip"
    hidden.write_bytes(payload)
    os.chmod(hidden, 0o644)
    linked = repo / "extension" / "dist" / _artifact_name("chrome")
    linked.symlink_to(hidden)
    receipt = _write_receipt(
        tmp_path / "receipts" / "chrome.json",
        _signed_receipt("chrome", payload),
    )
    with pytest.raises(listing_gate.ListingReceiptError, match="symbolic link|symlink"):
        _bind_file("chrome", receipt, linked)
    linked.unlink()
    hard = repo / "extension" / "dist" / _artifact_name("chrome")
    try:
        os.link(hidden, hard)
    except OSError as error:
        pytest.skip(f"hard links unavailable: {error}")
    with pytest.raises(listing_gate.ListingReceiptError, match="hardlink"):
        _bind_file("chrome", receipt, hard)
    del digest


def test_listing_receipts_require_minified_chrome_and_firefox_package_bytes() -> None:
    for browser in ("chrome", "firefox"):
        pretty = _synthetic_package_bytes(browser, pretty=True)
        with pytest.raises(
            listing_gate.ListingReceiptError,
            match="not minified production code|not store-permitted minified|exact package bytes are invalid",
        ):
            _bind_bytes(browser, pretty)
        dummy = f"{browser}-not-a-zip\n".encode("ascii")
        with pytest.raises(
            listing_gate.ListingReceiptError,
            match="exact package bytes are invalid|not a zip",
        ):
            _bind_bytes(browser, dummy)


def test_listing_receipts_reject_replayed_issuance_and_claimed_signer() -> None:
    chrome = _producer_bytes("chrome")
    firefox = _producer_bytes("firefox")
    chrome_record = _signed_receipt("chrome", chrome)
    firefox_record = _signed_receipt("firefox", firefox)
    firefox_record["issuance_id"] = chrome_record["issuance_id"]
    firefox_record["authentication"]["nonce"] = chrome_record["authentication"]["nonce"]
    with pytest.raises(listing_gate.ListingReceiptError, match="receipt reuse"):
        listing_gate.bind_listing_upload_receipts(
            {
                CHROME_TARGET: chrome_record,
                FIREFOX_TARGET: firefox_record,
            },
            {
                CHROME_TARGET: (
                    hashlib.sha256(chrome).hexdigest(),
                    len(chrome),
                    _artifact_name("chrome"),
                ),
                FIREFOX_TARGET: (
                    hashlib.sha256(firefox).hexdigest(),
                    len(firefox),
                    _artifact_name("firefox"),
                ),
            },
            {CHROME_TARGET: chrome, FIREFOX_TARGET: firefox},
        )
    zero = _signed_receipt("chrome", chrome)
    zero["issuance_id"] = "0" * 32
    with pytest.raises(
        listing_gate.ListingReceiptError, match="issuance_id is invalid or replayable"
    ):
        _bind_bytes("chrome", chrome, record=zero)
    claimed = _signed_receipt("firefox", firefox)
    claimed["trusted_signer"] = {
        "status": "present",
        "identity": "Mozilla Add-ons",
        "store_signed": True,
    }
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="trusted signer must remain pending without owner evidence",
    ):
        _bind_bytes("firefox", firefox, record=claimed)


def test_listing_receipts_reject_already_signed_and_cross_version_package_bytes() -> None:
    signed = _copy_zip(
        _producer_bytes("firefox"), extra={"META-INF/mozilla.rsa": b"not-a-trusted-signer"}
    )
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="already packed or already signed|exact package bytes are invalid",
    ):
        _bind_bytes("firefox", signed)
    nested = _copy_zip(
        _producer_bytes("firefox"), extra={"src/META-INF/mozilla.rsa": b"nested-signer"}
    )
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="already packed or already signed|exact package bytes are invalid",
    ):
        _bind_bytes("firefox", nested)
    mismatched = _synthetic_package_bytes("chrome", version="9.9.9")
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="cross-version|exact package bytes are invalid|want reviewed",
    ):
        _bind_bytes("chrome", mismatched)


def test_listing_receipts_reject_self_asserted_auth_unissued_nonce_and_replay() -> None:
    payload = _producer_bytes("firefox")
    honest = _signed_receipt("firefox", payload)
    bound = _bind_bytes("firefox", payload, record=honest)
    assert bound["publication_authorized"] is False
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="already consumed|not verifier-issued|replay",
    ):
        _bind_bytes("firefox", payload, record=honest)

    forged = _signed_receipt("firefox", payload)
    forged["authentication"]["nonce"] = "ab" * 32
    forged["issuance_id"] = forged["authentication"]["nonce"]
    forged["authentication"]["signature"] = _ISSUER.sign(
        listing_gate._canonical_auth_bytes(forged["authentication"])
    ).hex()
    with pytest.raises(
        listing_gate.ListingReceiptError, match="not verifier-issued"
    ):
        _bind_bytes("firefox", payload, record=forged)

    missing = _signed_receipt("edge", _producer_bytes("edge"))
    del missing["authentication"]
    with pytest.raises(
        listing_gate.ListingReceiptError, match="schema fields are invalid"
    ):
        _bind_bytes("edge", _producer_bytes("edge"), record=missing)


def test_listing_receipts_accept_fresh_and_reject_future_skew() -> None:
    payload = _producer_bytes("firefox")
    now = dt.datetime.now(tz=dt.timezone.utc).replace(microsecond=0)
    fresh = _signed_receipt("firefox", payload, now=now - dt.timedelta(minutes=4))
    bound = listing_gate.bind_listing_upload_receipt(
        FIREFOX_TARGET,
        fresh,
        artifact_sha256=hashlib.sha256(payload).hexdigest(),
        artifact_bytes=len(payload),
        artifact_name=_artifact_name("firefox"),
        artifact_payload=payload,
        now=now,
    )
    assert bound["listing_status"] == listing_gate.LISTING_EVIDENCE_STATUS
    assert bound["publication_authorized"] is False
    future = _signed_receipt("chrome", _producer_bytes("chrome"), now=now + dt.timedelta(seconds=31))
    with pytest.raises(listing_gate.ListingReceiptError, match="stale or future-dated"):
        listing_gate.bind_listing_upload_receipt(
            CHROME_TARGET,
            future,
            artifact_sha256=hashlib.sha256(_producer_bytes("chrome")).hexdigest(),
            artifact_bytes=len(_producer_bytes("chrome")),
            artifact_name=_artifact_name("chrome"),
            artifact_payload=_producer_bytes("chrome"),
            now=now,
        )


def test_listing_file_bind_refuses_path_mismatch_and_ancestor_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _prepare_repo(tmp_path, monkeypatch)
    payload = _producer_bytes("chrome")
    outsider = tmp_path / "candidates" / _artifact_name("chrome")
    outsider.parent.mkdir(parents=True)
    outsider.write_bytes(payload)
    os.chmod(outsider, 0o644)
    receipt = _write_receipt(
        tmp_path / "receipts" / "chrome.json", _signed_receipt("chrome", payload)
    )
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="must stay inside the repository|exact candidate ZIP",
    ):
        _bind_file("chrome", receipt, outsider)

    wrong_dir = repo / "extension" / "other" / _artifact_name("chrome")
    wrong_dir.parent.mkdir(parents=True)
    wrong_dir.write_bytes(payload)
    os.chmod(wrong_dir, 0o644)
    with pytest.raises(
        listing_gate.ListingReceiptError, match="exact candidate ZIP|cross-package"
    ):
        _bind_file("chrome", receipt, wrong_dir)

    hidden = repo / "hidden"
    hidden.mkdir()
    real = hidden / _artifact_name("chrome")
    real.write_bytes(payload)
    os.chmod(real, 0o644)
    dist = repo / "extension" / "dist"
    if dist.exists():
        dist.rmdir()
    dist.symlink_to(hidden, target_is_directory=True)
    with pytest.raises(listing_gate.ListingReceiptError, match="symbolic link|symlink"):
        _bind_file("chrome", receipt, dist / _artifact_name("chrome"))


def test_listing_and_inspect_reject_zip_comment_extra_nfc_and_source_map() -> None:
    chrome = _producer_bytes("chrome")
    commented = _copy_zip(chrome, comment=b"sourceMappingURL=evil.map")
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="zip comments are forbidden|source-map|exact package bytes are invalid",
    ):
        _bind_bytes("chrome", commented)
    extra = _copy_zip(chrome, extra={"README.txt": b"extra"})
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="extra members|extra zip member|exact package bytes are invalid",
    ):
        _bind_bytes("chrome", extra)
    nfc_name = "src/cafe" + "\u0301" + ".js"
    assert unicodedata.normalize("NFC", nfc_name) != nfc_name
    non_nfc = _copy_zip(chrome, extra={nfc_name: b"export const x=1;\n"})
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="non-NFC|exact package bytes are invalid",
    ):
        _bind_bytes("chrome", non_nfc)
    mapped = _copy_zip(chrome, extra={"src/background/background.js.map": b"{}"})
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="source map|exact package bytes are invalid",
    ):
        _bind_bytes("chrome", mapped)


def test_listing_receipts_keep_publication_unauthorized_without_owner_evidence() -> None:
    payload = _producer_bytes("chrome")
    record = _signed_receipt("chrome", payload)
    record["publication_authorized"] = True
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="invalid, swapped, or cross-package",
    ):
        _bind_bytes("chrome", payload, record=record)
    honest = _bind_bytes("firefox", _producer_bytes("firefox"))
    assert honest["publication_authorized"] is False
    assert honest["upload_authorized"] is False
    assert honest["unsigned_archive"] is True
    assert honest["trusted_signer"]["store_signed"] is False
    assert honest["trusted_signer"]["identity"] == "none"


def test_listing_receipts_reject_unicode_path_extra_field() -> None:
    payload = _producer_bytes("chrome")
    source = zipfile.ZipFile(io.BytesIO(payload))
    out = io.BytesIO()
    name = b"manifest.json"
    extra = (
        struct.pack("<HHBL", 0x7075, 5 + len(name), 1, zlib.crc32(name) & 0xFFFFFFFF)
        + name
    )
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dest:
        for info in source.infolist():
            body = source.read(info.filename)
            if info.filename == "manifest.json":
                mutated = zipfile.ZipInfo(info.filename)
                mutated.extra = extra
                dest.writestr(mutated, body)
            else:
                dest.writestr(info.filename, body)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="unicode path extra|exact package bytes are invalid",
    ):
        _bind_bytes("chrome", out.getvalue())


def _copy_listings(repo: Path) -> Path:
    dest = repo / "extension" / "store_listings"
    dest.mkdir(parents=True)
    for path in LISTING_ROOT.iterdir():
        if path.is_file():
            shutil.copy2(path, dest / path.name)
            os.chmod(dest / path.name, 0o644)
    return dest


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="ascii"))


def _replace_once(payload: str, old: str, new: str) -> str:
    assert payload.count(old) == 1
    return payload.replace(old, new, 1)


@pytest.mark.parametrize("constant", NONFINITE_JSON_CONSTANTS)
def test_release_identity_rejects_nested_nonfinite_json_constant(
    constant: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _prepare_repo(tmp_path, monkeypatch)
    path = repo / listing_gate.RELEASE_IDENTITY_PATH
    payload = _replace_once(
        path.read_text(encoding="ascii"),
        '"policy": "pubspec"',
        f'"policy": {constant}',
    )
    path.write_text(payload, encoding="ascii")
    os.chmod(path, 0o644)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match=rf"release identity map contains non-finite JSON constant: {constant}",
    ):
        listing_gate._load_release_identity(repo)


@pytest.mark.parametrize("constant", NONFINITE_JSON_CONSTANTS)
def test_listing_signoff_rejects_nested_nonfinite_json_constant(
    constant: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _prepare_repo(tmp_path, monkeypatch)
    listings = _copy_listings(repo)
    path = listings / listing_gate.OWNER_SIGNOFF_NAME
    payload = _replace_once(
        path.read_text(encoding="ascii"),
        '"blockers": [',
        f'"blockers": [{constant},',
    )
    path.write_text(payload, encoding="ascii")
    os.chmod(path, 0o644)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match=rf"listing owner signoff contains non-finite JSON constant: {constant}",
    ):
        listing_gate.validate_live_listings(repo)


@pytest.mark.parametrize("constant", NONFINITE_JSON_CONSTANTS)
def test_upload_receipt_rejects_nested_nonfinite_json_constant(
    constant: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _prepare_repo(tmp_path, monkeypatch)
    payload = _producer_bytes("chrome")
    artifact = _write_artifact(repo, "chrome", payload)
    record = _signed_receipt("chrome", payload)
    receipt_payload = json.dumps(record, indent=2, sort_keys=True) + "\n"
    receipt_payload = _replace_once(
        receipt_payload,
        f'"bytes": {len(payload)}',
        f'"bytes": {constant}',
    )
    receipt = tmp_path / "receipts" / f"chrome-{constant}.json"
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_text(receipt_payload, encoding="ascii")
    os.chmod(receipt, 0o600)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match=rf"upload receipt contains non-finite JSON constant: {constant}",
    ):
        _bind_file("chrome", receipt, artifact)


def test_store_identity_draft_ids_and_native_host_linkage_are_exact() -> None:
    live = listing_gate.validate_live_listings(ROOT)
    identity = live["store_identity"]
    assert identity["status"] == listing_gate.LISTING_EVIDENCE_STATUS
    release_identity = listing_gate._load_release_identity(ROOT)
    assert identity["canonical_release"] == release_identity["release"]
    assert identity["package_version"] == release_identity["package_version"]
    assert identity["native_host_name"] == listing_gate.NATIVE_HOST_NAME
    assert identity["upload_authorized"] is False
    assert identity["publication_authorized"] is False
    chrome = identity["stores"][CHROME_TARGET]
    edge = identity["stores"][EDGE_TARGET]
    firefox = identity["stores"][FIREFOX_TARGET]
    assert chrome["store_id"] == listing_gate.CHROME_STORE_ID
    assert edge["store_id"] == listing_gate.EDGE_STORE_ID
    assert firefox["store_id"] == GECKO_ID
    assert chrome["store_id_status"] == "owner_authenticated_draft"
    assert edge["store_id_status"] == "owner_authenticated_draft"
    assert firefox["store_id_status"] == "declared_gecko_id"
    assert chrome["archive_signed"] is False
    assert edge["archive_signed"] is False
    assert firefox["archive_signed"] is False
    assert chrome["native_host_allowlist"] == [
        f"chrome-extension://{listing_gate.CHROME_STORE_ID}/"
    ]
    assert edge["native_host_allowlist"] == [
        f"chrome-extension://{listing_gate.EDGE_STORE_ID}/"
    ]
    assert firefox["native_host_allowlist"] == [GECKO_ID]
    assert listing_gate._native_host_allowlist("chrome") == tuple(
        chrome["native_host_allowlist"]
    )
    assert listing_gate._native_host_allowlist("edge") == tuple(
        edge["native_host_allowlist"]
    )
    assert listing_gate._native_host_allowlist("firefox") == tuple(
        firefox["native_host_allowlist"]
    )
    signoff = live["owner_signoff"]
    assert signoff["status"] == listing_gate.LISTING_EVIDENCE_STATUS
    assert signoff["upload_authorized"] is False
    assert signoff["credentials_authorized"] is False
    assert signoff["submission_approved"] is False
    assert signoff["native_host_chromium_identity"] == "owner_authenticated_draft"
    assert signoff["listing_screenshot_inventory"] == "owner-blocked"
    privacy = live["privacy_label"]
    assert privacy["status"] == listing_gate.LISTING_EVIDENCE_STATUS
    assert privacy["off_device_collection"] is False
    assert privacy["remote_code"] is False
    assert privacy["firefox_data_collection_permissions"] == ["none"]
    for target_id in (CHROME_TARGET, EDGE_TARGET, FIREFOX_TARGET):
        store = privacy["stores"][target_id]
        assert store["privacy_practices_status"] == listing_gate.LISTING_EVIDENCE_STATUS
        assert store["source_disclosure_status"] == listing_gate.LISTING_EVIDENCE_STATUS
        assert store["single_purpose"] == (
            "desktop-proxy-site-routing"
            if target_id == FIREFOX_TARGET
            else "desktop-companion-site-routing"
        )
    candidate = live["release_candidate"]
    assert candidate["status"] == listing_gate.LISTING_EVIDENCE_STATUS
    assert candidate["candidate_set_status"] == "no_current_candidate"
    assert candidate["upload_authorized"] is False
    assert candidate["archive_signed"] is False
    assert candidate["targets"][CHROME_TARGET]["produced"] is False
    assert candidate["targets"][CHROME_TARGET]["hash_status"] == listing_gate.HELD_HASH_STATUS
    assert candidate["targets"][CHROME_TARGET]["sha256"] == ""
    assert live["held_candidate_hashes"][CHROME_TARGET]["hash_status"] == listing_gate.HELD_HASH_STATUS
    assert candidate["targets"][FIREFOX_TARGET]["unsigned_archives"] == [
        "extension/dist/wins-vpn-companion-firefox.xpi",
        "extension/dist/wins-vpn-companion-firefox.zip",
    ]


def test_listings_and_identity_refuse_invented_chromium_store_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    invented = "abcdefghijklmnopabcdefghijklmnop"
    assert CHROME_STORE_ID.fullmatch(invented)
    repo = _prepare_repo(tmp_path, monkeypatch)
    listings = _copy_listings(repo)
    chrome = listings / "chrome.md"
    chrome.write_text(
        chrome.read_text(encoding="ascii").replace(
            listing_gate.CHROME_STORE_ID, invented
        ),
        encoding="ascii",
    )
    os.chmod(chrome, 0o644)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="invents a 32-letter store ID|imports another 32-letter store ID|exact store identity",
    ):
        listing_gate.validate_listing_file("chrome", chrome)
    shutil.copy2(LISTING_ROOT / "chrome.md", chrome)
    os.chmod(chrome, 0o644)
    identity_path = listings / listing_gate.STORE_IDENTITY_NAME
    record = _load_json(identity_path)
    record["stores"][CHROME_TARGET]["store_id"] = invented
    record["stores"][CHROME_TARGET]["native_host_allowlist"] = [
        f"chrome-extension://{invented}/"
    ]
    identity_path.write_text(json.dumps(record, indent=2) + "\n", encoding="ascii")
    os.chmod(identity_path, 0o644)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="draft store ID|unsigned companion archive|identity",
    ):
        listing_gate.validate_live_listings(repo)


def test_identity_and_signoff_refuse_upload_authorization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _prepare_repo(tmp_path, monkeypatch)
    listings = _copy_listings(repo)
    identity_path = listings / listing_gate.STORE_IDENTITY_NAME
    record = _load_json(identity_path)
    record["upload_authorized"] = True
    identity_path.write_text(json.dumps(record, indent=2) + "\n", encoding="ascii")
    os.chmod(identity_path, 0o644)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="upload_authorized must remain false",
    ):
        listing_gate.validate_live_listings(repo)
    record["upload_authorized"] = False
    identity_path.write_text(json.dumps(record, indent=2) + "\n", encoding="ascii")
    os.chmod(identity_path, 0o644)
    signoff_path = listings / listing_gate.OWNER_SIGNOFF_NAME
    signoff = _load_json(signoff_path)
    signoff["upload_authorized"] = True
    signoff_path.write_text(json.dumps(signoff, indent=2) + "\n", encoding="ascii")
    os.chmod(signoff_path, 0o644)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="upload_authorized must remain false",
    ):
        listing_gate.validate_live_listings(repo)


def test_identity_refuses_cross_store_id_and_signed_archive_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _prepare_repo(tmp_path, monkeypatch)
    listings = _copy_listings(repo)
    identity_path = listings / listing_gate.STORE_IDENTITY_NAME
    record = _load_json(identity_path)
    record["stores"][EDGE_TARGET]["store_id"] = listing_gate.CHROME_STORE_ID
    record["stores"][EDGE_TARGET]["native_host_allowlist"] = [
        f"chrome-extension://{listing_gate.CHROME_STORE_ID}/"
    ]
    identity_path.write_text(json.dumps(record, indent=2) + "\n", encoding="ascii")
    os.chmod(identity_path, 0o644)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="draft store ID|unsigned companion archive|native-host",
    ):
        listing_gate.validate_live_listings(repo)
    record = _load_json(LISTING_ROOT / listing_gate.STORE_IDENTITY_NAME)
    record["stores"][FIREFOX_TARGET]["archive_signed"] = True
    identity_path.write_text(json.dumps(record, indent=2) + "\n", encoding="ascii")
    os.chmod(identity_path, 0o644)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="unsigned companion archive",
    ):
        listing_gate.validate_live_listings(repo)


def test_listing_receipts_refuse_owner_upload_authorization() -> None:
    payload = _producer_bytes("chrome")
    record = _signed_receipt("chrome", payload)
    record["owner_authorization"]["upload_authorized"] = True
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="owner authorization must remain pending without owner evidence",
    ):
        _bind_bytes("chrome", payload, record=record)
    signed_claim = _signed_receipt("firefox", _producer_bytes("firefox"))
    signed_claim["upload_attempted"] = True
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="invalid, swapped, or cross-package",
    ):
        _bind_bytes("firefox", _producer_bytes("firefox"), record=signed_claim)


def test_privacy_label_refuses_off_device_collection_and_portal_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _prepare_repo(tmp_path, monkeypatch)
    listings = _copy_listings(repo)
    path = listings / listing_gate.PRIVACY_LABEL_NAME
    record = _load_json(path)
    record["off_device_collection"] = True
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="ascii")
    os.chmod(path, 0o644)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="privacy off_device_collection must remain false",
    ):
        listing_gate.validate_live_listings(repo)
    record["off_device_collection"] = False
    record["stores"][CHROME_TARGET]["privacy_practices_status"] = "submitted"
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="ascii")
    os.chmod(path, 0o644)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="privacy practices are not BLOCKED without owner portal evidence",
    ):
        listing_gate.validate_live_listings(repo)


def test_release_candidate_refuses_invented_hash_and_produced_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _prepare_repo(tmp_path, monkeypatch)
    listings = _copy_listings(repo)
    path = listings / listing_gate.RELEASE_CANDIDATE_NAME
    record = _load_json(path)
    record["targets"][EDGE_TARGET]["produced"] = True
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="ascii")
    os.chmod(path, 0o644)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="unbound unsigned archive",
    ):
        listing_gate.validate_live_listings(repo)
    record = _load_json(LISTING_ROOT / listing_gate.RELEASE_CANDIDATE_NAME)
    record["targets"][FIREFOX_TARGET]["sha256"] = "ab" * 32
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="ascii")
    os.chmod(path, 0o644)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="must stay held without a current candidate",
    ):
        listing_gate.validate_live_listings(repo)


def test_each_listing_names_exact_unsigned_archive_and_host_origin() -> None:
    for browser, listing in LISTINGS.items():
        text = _listing_text(browser)
        spec = listing_gate.LISTING_TARGETS[listing["target_id"]]
        for archive in spec["unsigned_archives"]:
            filename = Path(archive).name
            assert filename in text
        assert spec["native_host_allowlist"][0] in text
        assert spec["native_host_template"] in text
        listing_gate.validate_listing_file(browser, LISTING_ROOT / listing["file"])


def test_metadata_refuses_owner_free_ready_or_pending_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _prepare_repo(tmp_path, monkeypatch)
    listings = _copy_listings(repo)
    identity_path = listings / listing_gate.STORE_IDENTITY_NAME
    record = _load_json(identity_path)
    record["status"] = "pending"
    identity_path.write_text(json.dumps(record, indent=2) + "\n", encoding="ascii")
    os.chmod(identity_path, 0o644)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="must remain BLOCKED without owner evidence",
    ):
        listing_gate.validate_live_listings(repo)
    record["status"] = "LOCAL_READY"
    identity_path.write_text(json.dumps(record, indent=2) + "\n", encoding="ascii")
    os.chmod(identity_path, 0o644)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="must remain BLOCKED without owner evidence",
    ):
        listing_gate.validate_live_listings(repo)
    shutil.copy2(LISTING_ROOT / listing_gate.STORE_IDENTITY_NAME, identity_path)
    os.chmod(identity_path, 0o644)
    signoff_path = listings / listing_gate.OWNER_SIGNOFF_NAME
    signoff = _load_json(signoff_path)
    signoff["status"] = True
    signoff_path.write_text(json.dumps(signoff, indent=2) + "\n", encoding="ascii")
    os.chmod(signoff_path, 0o644)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="must remain BLOCKED without owner evidence",
    ):
        listing_gate.validate_live_listings(repo)


def test_listing_drafts_refuse_pending_ready_or_reviewed_false_greens(
    tmp_path: Path,
) -> None:
    chrome = tmp_path / "chrome.md"
    chrome.write_bytes((LISTING_ROOT / "chrome.md").read_bytes())
    os.chmod(chrome, 0o644)
    listing_gate.validate_listing_file("chrome", chrome)
    chrome.write_text(
        chrome.read_text(encoding="ascii").replace("Status: BLOCKED.", "Status: pending."),
        encoding="ascii",
    )
    os.chmod(chrome, 0o644)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="does not bind the exact store identity",
    ):
        listing_gate.validate_listing_file("chrome", chrome)
    firefox = tmp_path / "firefox.md"
    firefox.write_text(
        (LISTING_ROOT / "firefox.md")
        .read_text(encoding="ascii")
        .replace(
            "Status: LOCAL LISTING TEXT ONLY.",
            "Status: pending.",
        ),
        encoding="ascii",
    )
    os.chmod(firefox, 0o644)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="does not bind the exact store identity",
    ):
        listing_gate.validate_listing_file("firefox", firefox)
    firefox.write_text(
        (LISTING_ROOT / "firefox.md")
        .read_text(encoding="ascii")
        .replace("Mozilla store review: none.", "Mozilla store review: approved."),
        encoding="ascii",
    )
    os.chmod(firefox, 0o644)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="Mozilla review without store evidence|does not bind the exact store identity",
    ):
        listing_gate.validate_listing_file("firefox", firefox)


def test_release_candidate_refuses_current_hash_status_and_held_hex_contradiction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _prepare_repo(tmp_path, monkeypatch)
    listings = _copy_listings(repo)
    path = listings / listing_gate.RELEASE_CANDIDATE_NAME
    record = _load_json(path)
    record["targets"][CHROME_TARGET]["hash_status"] = "current"
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="ascii")
    os.chmod(path, 0o644)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="hash_status must stay held without a current candidate",
    ):
        listing_gate.validate_live_listings(repo)
    record = _load_json(LISTING_ROOT / listing_gate.RELEASE_CANDIDATE_NAME)
    record["status"] = "pending"
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="ascii")
    os.chmod(path, 0o644)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="must remain BLOCKED without owner evidence",
    ):
        listing_gate.validate_live_listings(repo)
    record = _load_json(LISTING_ROOT / listing_gate.RELEASE_CANDIDATE_NAME)
    record["targets"][EDGE_TARGET]["hash_status"] = listing_gate.HELD_HASH_STATUS
    record["targets"][EDGE_TARGET]["sha256"] = "cd" * 32
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="ascii")
    os.chmod(path, 0o644)
    with pytest.raises(
        listing_gate.ListingReceiptError,
        match="must stay held without a current candidate",
    ):
        listing_gate.validate_live_listings(repo)


def _set_pubspec_version(repo: Path, version: str) -> None:
    path = repo / "pubspec.yaml"
    text = path.read_text(encoding="utf-8")
    current = re.search(r"(?m)^version:[^\n]*$", text)
    assert current is not None
    path.write_text(
        text[: current.start()] + f"version: {version}" + text[current.end():],
        encoding="utf-8",
    )


def test_release_identity_binds_the_pubspec_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """EXT2 Turn 3: production validation follows the reviewed pubspec policy."""
    expected = checks.read_pubspec_manifest_version(ROOT / "pubspec.yaml")
    identity = listing_gate._load_release_identity(ROOT)
    assert identity["package_version"] == expected
    assert identity["release"].split("+", 1)[0] == expected
    repo = _prepare_repo(tmp_path, monkeypatch)
    assert listing_gate._load_release_identity(repo) == identity

    path = repo / listing_gate.RELEASE_IDENTITY_PATH
    original = path.read_text(encoding="ascii")
    path.write_text(
        _replace_once(original, '"policy": "pubspec"', '"policy": "independent_semver"'),
        encoding="ascii",
    )
    with pytest.raises(listing_gate.ListingReceiptError, match="version is not exact"):
        listing_gate._load_release_identity(repo)

    major, minor, patch = (int(part) for part in expected.split("."))
    bumped = f"{major}.{minor}.{patch + 1}"
    record = json.loads(original)
    browser = record["platform_mappings"]["browser_extensions"]
    browser["version"] = bumped
    browser["target_versions"] = {target: bumped for target in browser["target_versions"]}
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="ascii")
    with pytest.raises(listing_gate.ListingReceiptError, match="version is not exact"):
        listing_gate._load_release_identity(repo)
    path.write_text(original, encoding="ascii")

    _set_pubspec_version(repo, f"{major}.{minor}.{patch + 1}+1")
    with pytest.raises(listing_gate.ListingReceiptError, match="version is not exact"):
        listing_gate._load_release_identity(repo)

    _set_pubspec_version(repo, f"{expected}-beta.1+1")
    with pytest.raises(listing_gate.ListingReceiptError, match="pubspec version is invalid"):
        listing_gate._load_release_identity(repo)

    (repo / "pubspec.yaml").unlink()
    with pytest.raises(listing_gate.ListingReceiptError, match="pubspec version is invalid"):
        listing_gate._load_release_identity(repo)


def test_release_identity_refuses_a_release_that_disagrees_with_pubspec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _prepare_repo(tmp_path, monkeypatch)
    path = repo / listing_gate.RELEASE_IDENTITY_PATH
    record = json.loads(path.read_text(encoding="ascii"))
    expected = record["platform_mappings"]["browser_extensions"]["version"]
    assert listing_gate._load_release_identity(repo)["package_version"] == expected
    major, minor, patch = (int(part) for part in expected.split("."))
    record["canonical_release"] = f"{major}.{minor}.{patch + 1}+1"
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="ascii")
    os.chmod(path, 0o644)
    with pytest.raises(listing_gate.ListingReceiptError, match="version is not exact"):
        listing_gate._load_release_identity(repo)


def test_store_identity_record_requires_the_pubspec_policy() -> None:
    identity = listing_gate._load_release_identity(ROOT)
    record = _load_json(LISTING_ROOT / "store_identity.json")
    assert record["policy"] == "pubspec"
    listing_gate._validate_store_identity_record(record, identity)
    record["policy"] = "independent_semver"
    with pytest.raises(listing_gate.ListingReceiptError, match="store identity is not"):
        listing_gate._validate_store_identity_record(record, identity)


def test_owner_signoff_names_the_current_release_and_stays_unapproved() -> None:
    """Owner ruling: release references track the build; approval stays the owner's."""
    identity = listing_gate._load_release_identity(ROOT)
    live = listing_gate.validate_live_listings(ROOT)
    assert live["status"] == listing_gate.LISTING_EVIDENCE_STATUS
    assert live["upload_authorized"] is False
    signoff = _load_json(LISTING_ROOT / listing_gate.OWNER_SIGNOFF_NAME)
    assert signoff["canonical_release"] == identity["release"]
    assert signoff["package_version"] == identity["package_version"]
    assert signoff["submission_approved"] is False
    assert signoff["upload_authorized"] is False
    assert signoff["credentials_authorized"] is False
    assert signoff["status"] == "BLOCKED"
    assert any(identity["release"] in blocker for blocker in signoff["blockers"])
    assert not any("1.0.15+30" in blocker for blocker in signoff["blockers"])
    readme = (LISTING_ROOT / "README.md").read_text(encoding="utf-8")
    assert f"`owner_signoff.json`: blocked owner-signoff record for {identity['release']}." in readme


def test_listing_cli_reports_blocked_and_does_not_exit_zero() -> None:
    code = listing_gate.main()
    assert code == 2


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
