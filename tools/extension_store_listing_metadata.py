#!/usr/bin/env python3
"""Fail-closed Chrome/Edge/Firefox store-listing and upload-receipt custody.

Listing, review, and release-candidate metadata stay BLOCKED without owner or
store evidence. A receipt may bind exact unsigned ZIP bytes and still leave
every store BLOCKED. A receipt binds only when a repository-pinned Ed25519
issuer signature verifies over the strict canonical exact-key receipt, the
nonce was verifier-issued, freshness is short, replay consumption is durable,
and the exact artifact path plus target/store/version/bytes/hash match one
candidate ZIP of producer-closed minified production bytes. Copied, swapped,
ancestor-symlinked, leaf-symlinked, hardlinked, stale, reused, replayed,
cross-store, cross-version, cross-package, unsigned, and already-signed
receipts are refused. Missing owner proof is never ok or pending-ready.
Firefox is never claimed store-signed without Mozilla evidence. Candidate
hashes stay held while no current archive exists. This module never uploads,
signs, deploys, or invents portal evidence.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import secrets
import stat
import sys
from collections.abc import Mapping


ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKOUT_ROOT = ROOT
EXT_TOOLS = ROOT / "extension" / "tools"
if str(EXT_TOOLS) not in sys.path:
    sys.path.insert(0, str(EXT_TOOLS))

import assert_chrome_zip
import assert_firefox_zip
import jsonc
from store_version import read_pubspec_manifest_version

LISTING_ROOT = ROOT / "extension" / "store_listings"
RELEASE_IDENTITY_PATH = pathlib.Path("docs/rulings/RELEASE_IDENTITY_MAP_20260824.json")
STORE_IDENTITY_NAME = "store_identity.json"
OWNER_SIGNOFF_NAME = "owner_signoff.json"
PRIVACY_LABEL_NAME = "privacy_label_manifest.json"
RELEASE_CANDIDATE_NAME = "release_candidate.json"
STORE_IDENTITY_CONTRACT = "winsvpn-browser-extension-store-identity-v1"
OWNER_SIGNOFF_CONTRACT = "winsvpn-browser-extension-owner-signoff-v1"
PRIVACY_LABEL_CONTRACT = "winsvpn-browser-extension-privacy-label-v1"
RELEASE_CANDIDATE_CONTRACT = "winsvpn-browser-extension-release-candidate-v1"
LISTING_UPLOAD_RECEIPT_CONTRACT = "winsvpn-extension-listing-upload-receipt-v2"
LISTING_UPLOAD_RECEIPT_SCHEMA_VERSION = 2
LISTING_RECEIPT_ISSUER = "winsvpn-extension-listing-upload-receipt"
LISTING_RECEIPT_ISSUER_PUBLIC_KEY_HEX = (
    "e11e5119e11e5119e11e5119e11e5119e11e5119e11e5119e11e5119e11e5119"
)
MAX_RECEIPT_BYTES = 64 * 1024
MAX_LISTING_BYTES = 64 * 1024
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
MAX_RECEIPT_AGE = dt.timedelta(minutes=5)
MAX_CLOCK_SKEW = dt.timedelta(seconds=30)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
CHROMIUM_STORE_ID = re.compile(r"\b[a-p]{32}\b")
GECKO_ID = "companion@winsvpn.org"
NATIVE_HOST_NAME = "org.winsvpn.bridge"
CHROME_STORE_ID = "lnehjdblendkagjbmdclepjalahdhbbn"
EDGE_STORE_ID = "glgihadopbjoandhoihghddecoibcldf"
OWNER_IDENTITY_RECEIPT_CONTRACT = "winsvpn-browser-extension-store-identity-v1"
OWNER_IDENTITY_RECEIPT_ISSUANCE = "992aff113a8e8c3e6fb67f6e5146d4cb"
LISTING_EVIDENCE_STATUS = "BLOCKED"
LISTING_EVIDENCE_REASON = "BLOCKED without owner evidence"
HELD_HASH_STATUS = "held"
HELD_CANDIDATE_SHA256 = ""
ALLOWED_LISTING_FILES = frozenset(
    {
        "README.md",
        "chrome.md",
        "edge.md",
        "firefox.md",
        STORE_IDENTITY_NAME,
        OWNER_SIGNOFF_NAME,
        PRIVACY_LABEL_NAME,
        RELEASE_CANDIDATE_NAME,
    }
)
STORE_IDENTITY_KEYS = frozenset(
    {
        "schema_version",
        "contract",
        "status",
        "canonical_release",
        "package_version",
        "policy",
        "native_host_name",
        "upload_authorized",
        "publication_authorized",
        "credentials_authorized",
        "owner_identity_receipt",
        "stores",
    }
)
OWNER_IDENTITY_RECEIPT_KEYS = frozenset(
    {"contract", "authenticated", "issuance_id", "issuer", "created_utc"}
)
STORE_IDENTITY_TARGET_KEYS = frozenset(
    {
        "store",
        "listing_name",
        "store_id",
        "store_id_status",
        "native_host_template",
        "native_host_allowlist",
        "unsigned_archives",
        "archive_signed",
    }
)
OWNER_SIGNOFF_KEYS = frozenset(
    {
        "schema_version",
        "contract",
        "status",
        "canonical_release",
        "package_version",
        "submission_approved",
        "upload_authorized",
        "credentials_authorized",
        "listing_screenshot_inventory",
        "native_host_chromium_identity",
        "blockers",
    }
)
PRIVACY_LABEL_KEYS = frozenset(
    {
        "schema_version",
        "contract",
        "status",
        "canonical_release",
        "package_version",
        "privacy_policy_url",
        "remote_code",
        "off_device_collection",
        "tracking",
        "sale_of_data",
        "host_permissions_at_install",
        "optional_host_permissions",
        "native_messaging",
        "firefox_data_collection_permissions",
        "listing_screenshot_inventory",
        "stores",
    }
)
PRIVACY_STORE_KEYS = frozenset(
    {
        "surface",
        "privacy_practices_status",
        "single_purpose",
        "source_disclosure_status",
    }
)
RELEASE_CANDIDATE_KEYS = frozenset(
    {
        "schema_version",
        "contract",
        "status",
        "canonical_release",
        "package_version",
        "candidate_set_status",
        "upload_authorized",
        "publication_authorized",
        "credentials_authorized",
        "archive_signed",
        "targets",
    }
)
RELEASE_CANDIDATE_TARGET_KEYS = frozenset(
    {
        "unsigned_archives",
        "produced",
        "signed",
        "upload_performed",
        "hash_status",
        "sha256",
        "bytes",
    }
)
LISTING_AUTH_CANONICAL_KEYS = (
    "artifact_bytes",
    "artifact_path",
    "artifact_sha256",
    "issued_at",
    "issuer",
    "nonce",
    "store",
    "target_id",
    "version",
)
AUTHENTICATION_KEYS = frozenset(LISTING_AUTH_CANONICAL_KEYS) | {"signature"}
LISTING_RECEIPT_KEYS = frozenset(
    {
        "ok",
        "schema_version",
        "contract",
        "release",
        "target_id",
        "platform",
        "issuance_id",
        "verified_utc",
        "artifact",
        "package_identity",
        "store_evidence",
        "trusted_signer",
        "publication_authorized",
        "upload_attempted",
        "owner_authorization",
        "authentication",
    }
)
LEDGER_ENV = "WINS_EXTENSION_LISTING_NONCE_LEDGER"
DEFAULT_LEDGER_RELATIVE = ".artifacts/extension-listing-nonce-ledger"
STORE_EVIDENCE_KEYS = frozenset({"surface", "status", "store_id"})
OWNER_AUTHORIZATION_KEYS = frozenset(
    {
        "status",
        "credentials_authorized",
        "upload_authorized",
    }
)
TRUSTED_SIGNER_KEYS = frozenset({"status", "identity", "store_signed"})
ARTIFACT_KEYS = frozenset({"path", "sha256", "bytes"})
PACKAGE_IDENTITY_BASE_KEYS = frozenset({"name", "version", "target_id"})
LISTING_TARGETS: dict[str, dict[str, object]] = {
    "chrome-extension-package": {
        "browser": "chrome",
        "store": "Chrome Web Store",
        "store_surface": "chrome-web-store",
        "listing_file": "chrome.md",
        "name": "Win's VPN Proxy for Chrome",
        "artifact_names": ("wins-vpn-companion-chrome.zip",),
        "artifact_suffixes": (".zip",),
        "identity_keys": PACKAGE_IDENTITY_BASE_KEYS,
        "store_id": CHROME_STORE_ID,
        "store_id_status": "owner_authenticated_draft",
        "native_host_template": (
            "tools/native_messaging/manifests/org.winsvpn.bridge.chrome.json"
        ),
        "native_host_allowlist": (
            f"chrome-extension://{CHROME_STORE_ID}/",
        ),
        "unsigned_archives": ("extension/dist/wins-vpn-companion-chrome.zip",),
    },
    "edge-extension-package": {
        "browser": "edge",
        "store": "Microsoft Edge Add-ons",
        "store_surface": "edge-add-ons",
        "listing_file": "edge.md",
        "name": "Win's VPN Proxy for Microsoft Edge",
        "artifact_names": ("wins-vpn-companion-edge.zip",),
        "artifact_suffixes": (".zip",),
        "identity_keys": PACKAGE_IDENTITY_BASE_KEYS,
        "store_id": EDGE_STORE_ID,
        "store_id_status": "owner_authenticated_draft",
        "native_host_template": (
            "tools/native_messaging/manifests/org.winsvpn.bridge.edge.json"
        ),
        "native_host_allowlist": (f"chrome-extension://{EDGE_STORE_ID}/",),
        "unsigned_archives": ("extension/dist/wins-vpn-companion-edge.zip",),
    },
    "firefox-extension-package": {
        "browser": "firefox",
        "store": "Firefox Add-ons",
        "store_surface": "firefox-amo",
        "listing_file": "firefox.md",
        "name": "Win's VPN Proxy",
        "artifact_names": (
            "wins-vpn-companion-firefox.xpi",
            "wins-vpn-companion-firefox.zip",
        ),
        "artifact_suffixes": (".xpi", ".zip"),
        "identity_keys": PACKAGE_IDENTITY_BASE_KEYS | {"gecko_id"},
        "store_id": GECKO_ID,
        "store_id_status": "declared_gecko_id",
        "native_host_template": (
            "tools/native_messaging/manifests/org.winsvpn.bridge.firefox.json"
        ),
        "native_host_allowlist": (GECKO_ID,),
        "unsigned_archives": (
            "extension/dist/wins-vpn-companion-firefox.xpi",
            "extension/dist/wins-vpn-companion-firefox.zip",
        ),
    },
}
TARGET_BY_BROWSER = {
    str(spec["browser"]): target_id for target_id, spec in LISTING_TARGETS.items()
}


class ListingReceiptError(RuntimeError):
    """Fail-closed browser listing or upload-receipt refusal."""


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]], label: str
) -> dict[str, object]:
    record: dict[str, object] = {}
    for key, value in pairs:
        if key in record:
            raise ListingReceiptError(f"{label} contains duplicate JSON key: {key}")
        record[key] = value
    return record


def _reject_nonfinite_constant(value: str, label: str) -> object:
    raise ListingReceiptError(f"{label} contains non-finite JSON constant: {value}")


def _exact_mapping(value: object, keys: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise ListingReceiptError(f"{label} schema fields are invalid.")
    return value


def _exact_str(value: object, expected: str, label: str) -> str:
    if type(value) is not str or value != expected:
        raise ListingReceiptError(f"{label} is not exact.")
    return value


def _canonical_artifact_path(spec: Mapping[str, object], filename: str) -> str:
    allowed = spec["artifact_names"]
    if filename not in allowed:
        raise ListingReceiptError(
            "receipt is cross-package or does not bind the exact candidate ZIP."
        )
    return f"extension/dist/{filename}"


def _hex64(value: object, label: str) -> str:
    if type(value) is not str or HEX64.fullmatch(value) is None:
        raise ListingReceiptError(f"{label} digest is invalid.")
    return value


def _issuance_id(value: object, label: str) -> str:
    if type(value) is not str or HEX64.fullmatch(value) is None:
        raise ListingReceiptError(f"{label} issuance_id is invalid or replayable.")
    return value


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        stat.S_IFMT(info.st_mode),
    )


def _absolute_lexical(path: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(os.path.abspath(os.fspath(path)))


def _reject_symlink_or_special(info: os.stat_result, label: str) -> None:
    if stat.S_ISLNK(info.st_mode):
        raise ListingReceiptError(f"{label} traverses a symbolic link.")
    mode = info.st_mode
    if (
        stat.S_ISFIFO(mode)
        or stat.S_ISCHR(mode)
        or stat.S_ISBLK(mode)
        or stat.S_ISSOCK(mode)
    ):
        raise ListingReceiptError(f"{label} is a FIFO or special node.")


def _walk_from_stop(
    path: pathlib.Path,
    label: str,
    stop: pathlib.Path,
    *,
    leaf_directory: bool = False,
) -> None:
    absolute = _absolute_lexical(path)
    stop_abs = _absolute_lexical(stop)
    try:
        relative = absolute.relative_to(stop_abs)
    except ValueError as suc:
        raise ListingReceiptError(f"{label} must stay inside the repository.") from suc
    current = stop_abs
    try:
        info = current.lstat()
    except OSError as suc:
        raise ListingReceiptError(f"{label} custody root is missing.") from suc
    _reject_symlink_or_special(info, label)
    if not stat.S_ISDIR(info.st_mode):
        raise ListingReceiptError(f"{label} custody root must be a regular directory.")
    parts = relative.parts
    if not parts:
        if leaf_directory:
            return
        raise ListingReceiptError(f"{label} is not a file inside its custody root.")
    for index, part in enumerate(parts):
        if part in {"", ".", ".."}:
            raise ListingReceiptError(f"{label} path is not canonical.")
        current = current / part
        try:
            info = current.lstat()
        except OSError as suc:
            raise ListingReceiptError(f"{label} is missing.") from suc
        _reject_symlink_or_special(info, label)
        is_leaf = index == len(parts) - 1
        if is_leaf and leaf_directory:
            if not stat.S_ISDIR(info.st_mode):
                raise ListingReceiptError(f"{label} must be a regular directory.")
            continue
        if is_leaf:
            if not stat.S_ISREG(info.st_mode):
                raise ListingReceiptError(f"{label} is not a regular file.")
            if info.st_nlink != 1:
                raise ListingReceiptError(f"{label} has a hardlink alias.")
        elif not stat.S_ISDIR(info.st_mode):
            raise ListingReceiptError(f"{label} parent is not a directory.")


def _authenticated_regular_file(
    path: pathlib.Path,
    label: str,
    *,
    maximum: int = MAX_RECEIPT_BYTES,
    stop: pathlib.Path | None = None,
) -> tuple[bytes, str, tuple[int, ...]]:
    absolute = _absolute_lexical(path)
    _walk_from_stop(absolute, label, stop if stop is not None else absolute.parent)
    try:
        before = absolute.lstat()
    except OSError as suc:
        raise ListingReceiptError(f"{label} is missing.") from suc
    _reject_symlink_or_special(before, label)
    if not stat.S_ISREG(before.st_mode):
        raise ListingReceiptError(f"{label} is not a regular file.")
    if before.st_nlink != 1:
        raise ListingReceiptError(f"{label} has a hardlink alias.")
    if before.st_size <= 0 or before.st_size > maximum:
        raise ListingReceiptError(f"{label} size is not exact.")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as suc:
        raise ListingReceiptError(f"{label} cannot be opened without following.") from suc
    try:
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before) or not stat.S_ISREG(opened.st_mode):
            raise ListingReceiptError(
                f"{label} changed, is not regular, or has a hardlink alias."
            )
        chunks: list[bytes] = []
        digest = hashlib.sha256()
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise ListingReceiptError(f"{label} ended before its declared size.")
            chunks.append(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        extra = os.read(descriptor, 1)
        if extra:
            raise ListingReceiptError(f"{label} grew while it was read.")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        path_after = absolute.lstat()
    except OSError as suc:
        raise ListingReceiptError(f"{label} changed while it was read.") from suc
    payload = b"".join(chunks)
    if (
        _identity(before) != _identity(after)
        or _identity(after) != _identity(path_after)
        or len(payload) != before.st_size
        or stat.S_ISLNK(path_after.st_mode)
        or not stat.S_ISREG(path_after.st_mode)
        or path_after.st_nlink != 1
    ):
        raise ListingReceiptError(
            f"{label} was swapped or is not a regular single-inode file."
        )
    return payload, digest.hexdigest(), _identity(before)


def _repo_relative(root: pathlib.Path, path: pathlib.Path, label: str) -> str:
    root_abs = _absolute_lexical(root)
    path_abs = _absolute_lexical(path)
    try:
        relative = path_abs.relative_to(root_abs)
    except ValueError as suc:
        raise ListingReceiptError(f"{label} must stay inside the repository.") from suc
    posix = relative.as_posix()
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
        or "\\" in posix
    ):
        raise ListingReceiptError(f"{label} path is not canonical.")
    return posix


def _require_dir_nofollow(path: pathlib.Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as suc:
        raise ListingReceiptError(f"{label} is missing.") from suc
    _reject_symlink_or_special(info, label)
    if not stat.S_ISDIR(info.st_mode):
        raise ListingReceiptError(f"{label} must be a regular directory.")


def _ledger_dir(override: pathlib.Path | None = None) -> pathlib.Path:
    if override is not None:
        path = _absolute_lexical(override)
    else:
        env = os.environ.get(LEDGER_ENV, "").strip()
        path = _absolute_lexical(pathlib.Path(env) if env else ROOT / DEFAULT_LEDGER_RELATIVE)
    if path.exists() or path.is_symlink():
        _require_dir_nofollow(path, "listing nonce ledger")
        return path
    parent = path.parent
    if parent.exists() or parent.is_symlink():
        _require_dir_nofollow(parent, "listing nonce ledger parent")
    path.mkdir(parents=True, exist_ok=True)
    _require_dir_nofollow(path, "listing nonce ledger")
    return path


def _write_exclusive(path: pathlib.Path, payload: bytes, label: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as suc:
        raise ListingReceiptError(f"{label} already exists or cannot be created exclusively.") from suc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _canonical_auth_bytes(auth: Mapping[str, object]) -> bytes:
    payload = {key: auth.get(key) for key in LISTING_AUTH_CANONICAL_KEYS}
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _issuer_public_key_bytes() -> bytes:
    try:
        raw = bytes.fromhex(LISTING_RECEIPT_ISSUER_PUBLIC_KEY_HEX)
    except ValueError as suc:
        raise ListingReceiptError("listing receipt issuer public key is not pinned.") from suc
    if len(raw) != 32:
        raise ListingReceiptError("listing receipt issuer public key is not pinned.")
    return raw


def _verify_listing_signature(canonical: bytes, signature_hex: object) -> None:
    if type(signature_hex) is not str or re.fullmatch(r"[0-9a-f]{128}", signature_hex) is None:
        raise ListingReceiptError("listing receipt is not authenticated by the trusted issuer.")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as suc:
        raise ListingReceiptError(
            "listing receipt authentication requires the cryptography package."
        ) from suc
    try:
        public_key = Ed25519PublicKey.from_public_bytes(_issuer_public_key_bytes())
        public_key.verify(bytes.fromhex(signature_hex), canonical)
    except (InvalidSignature, ValueError, TypeError) as suc:
        raise ListingReceiptError(
            "listing receipt is not authenticated by the trusted issuer."
        ) from suc


def issue_listing_nonce(
    target_id: str,
    *,
    artifact_path: str,
    artifact_sha256: str,
    artifact_bytes: int,
    ledger_dir: pathlib.Path | None = None,
    now: dt.datetime | None = None,
) -> dict[str, object]:
    """Issue a one-use listing nonce bound to one exact artifact identity."""

    spec = _target_spec(target_id)
    identity = _load_release_identity(ROOT)
    filename = pathlib.PurePosixPath(artifact_path).name
    expected_path = _canonical_artifact_path(spec, filename)
    if artifact_path != expected_path:
        raise ListingReceiptError(
            f"{target_id} artifact path must be the exact repository path."
        )
    digest = _hex64(artifact_sha256, f"{target_id} candidate ZIP")
    if type(artifact_bytes) is not int or isinstance(artifact_bytes, bool) or artifact_bytes <= 0:
        raise ListingReceiptError(f"{target_id} artifact size is not exact.")
    stamp = (now or dt.datetime.now(tz=dt.timezone.utc)).replace(microsecond=0)
    issued_at = stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = secrets.token_hex(32)
    challenge: dict[str, object] = {
        "artifact_bytes": artifact_bytes,
        "artifact_path": expected_path,
        "artifact_sha256": digest,
        "issued_at": issued_at,
        "issuer": LISTING_RECEIPT_ISSUER,
        "nonce": nonce,
        "store": spec["store"],
        "target_id": target_id,
        "version": identity["package_version"],
    }
    payload = _canonical_auth_bytes(challenge)
    ledger = _ledger_dir(ledger_dir)
    issued = ledger / f"{nonce}.issued"
    consumed = ledger / f"{nonce}.consumed"
    if consumed.exists() or consumed.is_symlink() or issued.exists() or issued.is_symlink():
        raise ListingReceiptError(f"{target_id} listing nonce is invalid or replayable.")
    _write_exclusive(issued, payload, f"{target_id} issued listing nonce")
    return challenge


def _consume_listing_nonce(
    target_id: str,
    auth: Mapping[str, object],
    canonical: bytes,
    *,
    ledger_dir: pathlib.Path | None = None,
) -> None:
    nonce = _hex64(auth.get("nonce"), f"{target_id} listing nonce")
    ledger = _ledger_dir(ledger_dir)
    issued = ledger / f"{nonce}.issued"
    consumed = ledger / f"{nonce}.consumed"
    if consumed.exists() or consumed.is_symlink():
        raise ListingReceiptError(f"{target_id} listing nonce was already consumed.")
    try:
        issued_payload, _digest, _identity = _authenticated_regular_file(
            issued, f"{target_id} issued listing nonce", stop=ledger
        )
    except ListingReceiptError as suc:
        raise ListingReceiptError(
            f"{target_id} listing nonce was not verifier-issued."
        ) from suc
    if issued_payload != canonical:
        raise ListingReceiptError(
            f"{target_id} listing nonce does not bind the exact receipt."
        )
    try:
        _write_exclusive(consumed, canonical, f"{target_id} consumed listing nonce")
    except ListingReceiptError as suc:
        raise ListingReceiptError(f"{target_id} listing nonce was already consumed.") from suc
    try:
        issued.unlink()
    except OSError as suc:
        raise ListingReceiptError(
            f"{target_id} listing nonce could not be consumed fail-closed."
        ) from suc
    if issued.exists() or issued.is_symlink() or not consumed.is_file():
        raise ListingReceiptError(
            f"{target_id} listing nonce could not be consumed fail-closed."
        )


def _bind_listing_authentication(
    target_id: str,
    spec: Mapping[str, object],
    receipt: Mapping[str, object],
    *,
    artifact_path: str,
    artifact_sha256: str,
    artifact_bytes: int,
    package_version: str,
    now: dt.datetime | None,
    ledger_dir: pathlib.Path | None,
    consume: bool,
) -> str:
    if "authenticated" in receipt:
        raise ListingReceiptError(
            f"{target_id} self-asserted authenticated:true is not issuer proof."
        )
    auth = _exact_mapping(
        receipt.get("authentication"),
        set(AUTHENTICATION_KEYS),
        f"{target_id} listing authentication",
    )
    if auth.get("issuer") != LISTING_RECEIPT_ISSUER:
        raise ListingReceiptError(
            f"{target_id} listing receipt is not authenticated by the trusted issuer."
        )
    nonce = _hex64(auth.get("nonce"), f"{target_id} listing nonce")
    issued_at = _parse_utc(auth.get("issued_at"), f"{target_id} listing issued_at")
    clock = now or dt.datetime.now(tz=dt.timezone.utc)
    if issued_at > clock + MAX_CLOCK_SKEW or clock - issued_at > MAX_RECEIPT_AGE:
        raise ListingReceiptError(f"{target_id} receipt is stale or future-dated.")
    if (
        auth.get("target_id") != target_id
        or auth.get("store") != spec["store"]
        or auth.get("version") != package_version
        or auth.get("artifact_path") != artifact_path
        or auth.get("artifact_sha256") != artifact_sha256
        or type(auth.get("artifact_bytes")) is not int
        or isinstance(auth.get("artifact_bytes"), bool)
        or int(auth.get("artifact_bytes")) != artifact_bytes
    ):
        raise ListingReceiptError(
            f"{target_id} receipt was swapped or does not bind the exact candidate ZIP."
        )
    canonical = _canonical_auth_bytes(auth)
    _verify_listing_signature(canonical, auth.get("signature"))
    if consume:
        _consume_listing_nonce(target_id, auth, canonical, ledger_dir=ledger_dir)
    return nonce


def _trusted_signer(value: object, label: str) -> dict[str, object]:
    signer = _exact_mapping(value, set(TRUSTED_SIGNER_KEYS), f"{label} trusted signer")
    if (
        signer.get("status") != "pending"
        or signer.get("identity") != "none"
        or signer.get("store_signed") is not False
        or type(signer.get("store_signed")) is not bool
    ):
        raise ListingReceiptError(
            f"{label} trusted signer must remain pending without owner evidence."
        )
    return signer


def _inspect_package_bytes(
    target_id: str, spec: Mapping[str, object], payload: bytes
) -> dict[str, object]:
    browser = str(spec["browser"])
    if target_id == "firefox-extension-package":
        inspected = assert_firefox_zip.inspect_bytes(payload)
    else:
        inspected = assert_chrome_zip.inspect_bytes(payload, browser)
    if inspected.get("ok") is not True:
        failures = inspected.get("failures") or ["package identity is invalid"]
        detail = "; ".join(str(item) for item in failures)
        raise ListingReceiptError(
            f"{target_id} exact package bytes are invalid or not minified production code: {detail}"
        )
    return inspected


def _bind_inspected_identity(
    target_id: str,
    spec: Mapping[str, object],
    package: Mapping[str, object],
    inspected: Mapping[str, object],
    identity: Mapping[str, str],
) -> None:
    if (
        inspected.get("name") != spec["name"]
        or inspected.get("version") != identity["package_version"]
        or package.get("name") != inspected.get("name")
        or package.get("version") != inspected.get("version")
        or inspected.get("trusted_signer") != "none"
    ):
        raise ListingReceiptError(
            f"{target_id} receipt is cross-version or does not bind the store identity."
        )
    if target_id == "firefox-extension-package" and inspected.get("gecko_id") != GECKO_ID:
        raise ListingReceiptError(f"{target_id} Gecko ID is not exact.")
    if inspected.get("trusted_signer") != "none":
        raise ListingReceiptError(
            f"{target_id} upload archive is not the exact unsigned candidate ZIP."
        )


def _target_spec(target_id: str) -> dict[str, object]:
    spec = LISTING_TARGETS.get(target_id)
    if spec is None:
        raise ListingReceiptError(
            f"unsupported exact browser listing/upload target: {target_id}"
        )
    return spec


def _browser_spec(browser: str) -> tuple[str, dict[str, object]]:
    target_id = TARGET_BY_BROWSER.get(browser)
    if target_id is None:
        raise ListingReceiptError(f"unsupported exact browser listing: {browser}")
    return target_id, _target_spec(target_id)


def _load_release_identity(repo: pathlib.Path) -> dict[str, str]:
    path = repo / RELEASE_IDENTITY_PATH
    payload, _digest, _identity = _authenticated_regular_file(
        path, "release identity map", stop=repo
    )
    try:
        record = json.loads(
            payload.decode("ascii"),
            object_pairs_hook=lambda pairs: _reject_duplicate_keys(
                pairs, "release identity map"
            ),
            parse_constant=lambda value: _reject_nonfinite_constant(
                value, "release identity map"
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ListingReceiptError("release identity map is not ASCII JSON.") from exc
    if type(record) is not dict or record.get("schema_version") != 2:
        raise ListingReceiptError("release identity map schema is not exact.")
    release = record.get("canonical_release")
    platforms = record.get("platform_mappings")
    if type(release) is not str or type(platforms) is not dict:
        raise ListingReceiptError("release identity map fields are invalid.")
    browser_identity = platforms.get("browser_extensions")
    if type(browser_identity) is not dict:
        raise ListingReceiptError("browser extension release identity is invalid.")
    version = browser_identity.get("version")
    target_versions = browser_identity.get("target_versions")
    try:
        expected_version = read_pubspec_manifest_version(repo / "pubspec.yaml")
    except (OSError, ValueError) as exc:
        raise ListingReceiptError("pubspec version is invalid.") from exc
    if (
        type(version) is not str
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None
        or type(target_versions) is not dict
        or set(target_versions) != set(LISTING_TARGETS)
        or any(target_versions.get(target_id) != version for target_id in LISTING_TARGETS)
        or browser_identity.get("policy") != "pubspec"
        or version != expected_version
        or release.split("+", 1)[0] != expected_version
    ):
        raise ListingReceiptError("browser extension package version is not exact.")
    return {"release": release, "package_version": version}


def _load_json_object(path: pathlib.Path, label: str, *, stop: pathlib.Path) -> dict[str, object]:
    payload, _digest, _identity = _authenticated_regular_file(
        path, label, maximum=MAX_LISTING_BYTES, stop=stop
    )
    try:
        record = json.loads(
            _decode_ascii(payload, label),
            object_pairs_hook=lambda pairs: _reject_duplicate_keys(pairs, label),
            parse_constant=lambda value: _reject_nonfinite_constant(value, label),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ListingReceiptError(f"{label} is not ASCII JSON.") from exc
    if type(record) is not dict:
        raise ListingReceiptError(f"{label} must be one JSON object.")
    return record


def _require_false(value: object, label: str) -> None:
    if type(value) is not bool or value is not False:
        raise ListingReceiptError(f"{label} must remain false without owner evidence.")


def _require_blocked_status(value: object, label: str) -> None:
    if type(value) is not str or value != LISTING_EVIDENCE_STATUS:
        raise ListingReceiptError(
            f"{label} must remain BLOCKED without owner evidence."
        )


def _require_held_candidate_hash(digest: object, status: object, label: str) -> None:
    if type(status) is not str or status != HELD_HASH_STATUS:
        raise ListingReceiptError(
            f"{label} hash_status must stay held without a current candidate."
        )
    if type(digest) is not str or digest != HELD_CANDIDATE_SHA256:
        raise ListingReceiptError(
            f"{label} must stay held without a current candidate."
        )


def _blocked_store_map() -> dict[str, str]:
    return {target_id: LISTING_EVIDENCE_STATUS for target_id in LISTING_TARGETS}


def _held_candidate_hashes(candidate: Mapping[str, object]) -> dict[str, object]:
    targets = candidate.get("targets")
    if type(targets) is not dict:
        raise ListingReceiptError("listing release candidate targets are missing.")
    held: dict[str, object] = {}
    for target_id in LISTING_TARGETS:
        target = targets.get(target_id)
        if type(target) is not dict:
            raise ListingReceiptError(f"{target_id} held candidate hash is missing.")
        held[target_id] = {
            "sha256": target.get("sha256"),
            "hash_status": target.get("hash_status"),
            "bytes": target.get("bytes"),
            "produced": target.get("produced"),
        }
    return held


def _blocked_listing_payload(live: Mapping[str, object]) -> dict[str, object]:
    candidate = live["release_candidate"]
    if type(candidate) is not dict:
        raise ListingReceiptError("listing release candidate is missing.")
    return {
        "ok": False,
        "status": LISTING_EVIDENCE_STATUS,
        "release": live["release"],
        "package_version": live["package_version"],
        "publication_authorized": False,
        "upload_authorized": False,
        "upload_attempted": False,
        "owner_authorization": LISTING_EVIDENCE_STATUS,
        "trusted_signer": LISTING_EVIDENCE_STATUS,
        "native_host_name": NATIVE_HOST_NAME,
        "stores": _blocked_store_map(),
        "reason": LISTING_EVIDENCE_REASON,
        "held_candidate_hashes": _held_candidate_hashes(candidate),
        "store_identity": live["store_identity"],
        "owner_signoff": live["owner_signoff"],
        "privacy_label": live["privacy_label"],
        "release_candidate": candidate,
        "listings": live["listings"],
    }


def _native_host_allowlist(browser: str) -> tuple[str, ...]:
    spec = _target_spec(TARGET_BY_BROWSER[browser])
    relative = str(spec["native_host_template"])
    path = CHECKOUT_ROOT / relative
    payload, _digest, _identity = _authenticated_regular_file(
        path,
        f"{browser} native-host template",
        stop=CHECKOUT_ROOT,
        maximum=MAX_LISTING_BYTES,
    )
    try:
        record = jsonc.loads(_decode_ascii(payload, f"{browser} native-host template"))
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ListingReceiptError(
            f"{browser} native-host template is not ASCII JSONC."
        ) from exc
    if type(record) is not dict or record.get("name") != NATIVE_HOST_NAME:
        raise ListingReceiptError(
            f"{browser} native-host template does not bind {NATIVE_HOST_NAME}."
        )
    if browser == "firefox":
        allowed = record.get("allowed_extensions")
    else:
        allowed = record.get("allowed_origins")
    if type(allowed) is not list or not allowed or any(type(item) is not str for item in allowed):
        raise ListingReceiptError(f"{browser} native-host allowlist is invalid.")
    expected = spec["native_host_allowlist"]
    if tuple(allowed) != expected:
        raise ListingReceiptError(
            f"{browser} native-host allowlist does not match the listing identity."
        )
    return tuple(allowed)


def _validate_store_identity_record(
    record: Mapping[str, object], identity: Mapping[str, str]
) -> dict[str, object]:
    bound = _exact_mapping(dict(record), set(STORE_IDENTITY_KEYS), "store identity")
    schema = bound.get("schema_version")
    if (
        type(schema) is not int
        or isinstance(schema, bool)
        or schema != 1
        or bound.get("contract") != STORE_IDENTITY_CONTRACT
        or bound.get("canonical_release") != identity["release"]
        or bound.get("package_version") != identity["package_version"]
        or bound.get("policy") != "pubspec"
        or bound.get("native_host_name") != NATIVE_HOST_NAME
    ):
        raise ListingReceiptError("store identity is not the canonical 1.0.17+34 companion contract.")
    _require_blocked_status(bound.get("status"), "store identity status")
    _require_false(bound.get("upload_authorized"), "store identity upload_authorized")
    _require_false(bound.get("publication_authorized"), "store identity publication_authorized")
    _require_false(bound.get("credentials_authorized"), "store identity credentials_authorized")
    owner_receipt = _exact_mapping(
        bound.get("owner_identity_receipt"),
        set(OWNER_IDENTITY_RECEIPT_KEYS),
        "owner identity receipt",
    )
    if (
        owner_receipt.get("contract") != OWNER_IDENTITY_RECEIPT_CONTRACT
        or owner_receipt.get("authenticated") is not True
        or type(owner_receipt.get("authenticated")) is not bool
        or owner_receipt.get("issuance_id") != OWNER_IDENTITY_RECEIPT_ISSUANCE
        or owner_receipt.get("issuer") != "winsvpn-owner"
        or owner_receipt.get("created_utc") != "2026-08-31T05:23:32Z"
    ):
        raise ListingReceiptError("owner identity receipt is not the authenticated draft-ID record.")
    stores = bound.get("stores")
    if type(stores) is not dict or set(stores) != set(LISTING_TARGETS):
        raise ListingReceiptError("store identity stores are missing, extra, or swapped.")
    for target_id, spec in LISTING_TARGETS.items():
        store = _exact_mapping(
            stores.get(target_id),
            set(STORE_IDENTITY_TARGET_KEYS),
            f"{target_id} store identity",
        )
        store_id = store.get("store_id")
        if type(store_id) is not str or store_id != spec["store_id"]:
            raise ListingReceiptError(
                f"{target_id} does not bind the owner-authenticated draft store ID."
            )
        allowlist = store.get("native_host_allowlist")
        archives = store.get("unsigned_archives")
        if (
            store.get("store") != spec["store"]
            or store.get("listing_name") != spec["name"]
            or store.get("store_id") != spec["store_id"]
            or store.get("store_id_status") != spec["store_id_status"]
            or store.get("native_host_template") != spec["native_host_template"]
            or type(allowlist) is not list
            or tuple(allowlist) != spec["native_host_allowlist"]
            or type(archives) is not list
            or tuple(archives) != spec["unsigned_archives"]
            or store.get("archive_signed") is not False
            or type(store.get("archive_signed")) is not bool
        ):
            raise ListingReceiptError(
                f"{target_id} store identity does not bind the unsigned companion archive."
            )
        live_allowlist = _native_host_allowlist(str(spec["browser"]))
        if live_allowlist != spec["native_host_allowlist"]:
            raise ListingReceiptError(
                f"{target_id} native-host companion linkage does not match the live template."
            )
    return bound


def _validate_owner_signoff(
    record: Mapping[str, object], identity: Mapping[str, str]
) -> dict[str, object]:
    bound = _exact_mapping(dict(record), set(OWNER_SIGNOFF_KEYS), "listing owner signoff")
    schema = bound.get("schema_version")
    blockers = bound.get("blockers")
    if (
        type(schema) is not int
        or isinstance(schema, bool)
        or schema != 1
        or bound.get("contract") != OWNER_SIGNOFF_CONTRACT
        or bound.get("canonical_release") != identity["release"]
        or bound.get("package_version") != identity["package_version"]
        or bound.get("listing_screenshot_inventory") != "owner-blocked"
        or bound.get("native_host_chromium_identity") != "owner_authenticated_draft"
        or type(blockers) is not list
        or not blockers
        or any(type(item) is not str or not item for item in blockers)
    ):
        raise ListingReceiptError(
            "listing owner signoff is not the canonical 1.0.17+34 companion contract."
        )
    _require_blocked_status(bound.get("status"), "listing owner signoff status")
    _require_false(bound.get("submission_approved"), "listing submission_approved")
    _require_false(bound.get("upload_authorized"), "listing upload_authorized")
    _require_false(bound.get("credentials_authorized"), "listing credentials_authorized")
    required_blockers = (
        "draft IDs are not published",
        "upload remains unauthorized",
        "unsigned",
        "owner-blocked",
        "privacy-practices",
        "issuer public key",
        "whitespace-only",
        "BLOCKED",
    )
    joined = " ".join(str(item) for item in blockers)
    if any(token not in joined for token in required_blockers):
        raise ListingReceiptError("listing owner signoff omits current store blockers.")
    return bound


def _validate_privacy_label(
    record: Mapping[str, object], identity: Mapping[str, str]
) -> dict[str, object]:
    bound = _exact_mapping(dict(record), set(PRIVACY_LABEL_KEYS), "listing privacy label")
    schema = bound.get("schema_version")
    optional_hosts = bound.get("optional_host_permissions")
    firefox_collection = bound.get("firefox_data_collection_permissions")
    if (
        type(schema) is not int
        or isinstance(schema, bool)
        or schema != 1
        or bound.get("contract") != PRIVACY_LABEL_CONTRACT
        or bound.get("canonical_release") != identity["release"]
        or bound.get("package_version") != identity["package_version"]
        or bound.get("privacy_policy_url")
        != "https://www.winsvpn.org/browser-extension-privacy/"
        or bound.get("listing_screenshot_inventory") != "owner-blocked"
        or bound.get("native_messaging") != "on_device_only"
        or type(optional_hosts) is not list
        or optional_hosts != ["<all_urls>"]
        or type(firefox_collection) is not list
        or firefox_collection != ["none"]
    ):
        raise ListingReceiptError(
            "listing privacy label is not the canonical 1.0.17+34 companion contract."
        )
    _require_blocked_status(bound.get("status"), "listing privacy label status")
    for flag in (
        "remote_code",
        "off_device_collection",
        "tracking",
        "sale_of_data",
        "host_permissions_at_install",
    ):
        _require_false(bound.get(flag), f"listing privacy {flag}")
    stores = bound.get("stores")
    if type(stores) is not dict or set(stores) != set(LISTING_TARGETS):
        raise ListingReceiptError("listing privacy stores are missing, extra, or swapped.")
    for target_id, spec in LISTING_TARGETS.items():
        store = _exact_mapping(
            stores.get(target_id),
            set(PRIVACY_STORE_KEYS),
            f"{target_id} privacy practices",
        )
        single_purpose = (
            "desktop-proxy-site-routing"
            if target_id == "firefox-extension-package"
            else "desktop-companion-site-routing"
        )
        if (
            store.get("surface") != spec["store_surface"]
            or store.get("privacy_practices_status") != LISTING_EVIDENCE_STATUS
            or store.get("single_purpose") != single_purpose
            or store.get("source_disclosure_status") != LISTING_EVIDENCE_STATUS
        ):
            raise ListingReceiptError(
                f"{target_id} privacy practices are not BLOCKED without owner portal evidence."
            )
    return bound


def _validate_release_candidate(
    record: Mapping[str, object], identity: Mapping[str, str]
) -> dict[str, object]:
    bound = _exact_mapping(
        dict(record), set(RELEASE_CANDIDATE_KEYS), "listing release candidate"
    )
    schema = bound.get("schema_version")
    if (
        type(schema) is not int
        or isinstance(schema, bool)
        or schema != 1
        or bound.get("contract") != RELEASE_CANDIDATE_CONTRACT
        or bound.get("canonical_release") != identity["release"]
        or bound.get("package_version") != identity["package_version"]
        or bound.get("candidate_set_status") != "no_current_candidate"
        or bound.get("archive_signed") is not False
        or type(bound.get("archive_signed")) is not bool
    ):
        raise ListingReceiptError(
            "listing release candidate is not the canonical 1.0.17+34 companion contract."
        )
    _require_blocked_status(bound.get("status"), "listing release candidate status")
    _require_false(bound.get("upload_authorized"), "release candidate upload_authorized")
    _require_false(
        bound.get("publication_authorized"), "release candidate publication_authorized"
    )
    _require_false(
        bound.get("credentials_authorized"), "release candidate credentials_authorized"
    )
    targets = bound.get("targets")
    if type(targets) is not dict or set(targets) != set(LISTING_TARGETS):
        raise ListingReceiptError(
            "listing release candidate targets are missing, extra, or swapped."
        )
    for target_id, spec in LISTING_TARGETS.items():
        target = _exact_mapping(
            targets.get(target_id),
            set(RELEASE_CANDIDATE_TARGET_KEYS),
            f"{target_id} release candidate",
        )
        archives = target.get("unsigned_archives")
        size = target.get("bytes")
        if (
            type(archives) is not list
            or tuple(archives) != spec["unsigned_archives"]
            or target.get("produced") is not False
            or target.get("signed") is not False
            or target.get("upload_performed") is not False
            or type(target.get("produced")) is not bool
            or type(target.get("signed")) is not bool
            or type(target.get("upload_performed")) is not bool
            or type(size) is not int
            or isinstance(size, bool)
            or size != 0
        ):
            raise ListingReceiptError(
                f"{target_id} release candidate is not an unbound unsigned archive."
            )
        _require_held_candidate_hash(
            target.get("sha256"),
            target.get("hash_status"),
            f"{target_id} candidate SHA-256",
        )
    return bound


def _parse_utc(value: object, label: str) -> dt.datetime:
    if type(value) is not str or UTC_RE.fullmatch(value) is None:
        raise ListingReceiptError(f"{label} timestamp is invalid.")
    parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    return parsed.astimezone(dt.timezone.utc)


def _reject_digest_reuse(pairs: list[tuple[str, str]]) -> None:
    seen: dict[str, str] = {}
    for label, digest in pairs:
        previous = seen.get(digest)
        if previous is not None:
            raise ListingReceiptError(
                f"receipt reuse is refused: {label} reuses {previous}"
            )
        seen[digest] = label


def _decode_ascii(payload: bytes, label: str) -> str:
    if b"\x00" in payload:
        raise ListingReceiptError(f"{label} is not ASCII text.")
    try:
        return payload.decode("ascii")
    except UnicodeError as exc:
        raise ListingReceiptError(f"{label} is not ASCII text.") from exc


def validate_listing_file(browser: str, path: pathlib.Path) -> dict[str, object]:
    """Refuse swapped, copied-wrong-store, symlinked, or hardlinked listing drafts."""

    target_id, spec = _browser_spec(browser)
    payload, digest, identity = _authenticated_regular_file(
        path, f"{browser} listing draft", maximum=MAX_LISTING_BYTES
    )
    text = _decode_ascii(payload, f"{browser} listing draft")
    expected_name = str(spec["listing_file"])
    if path.name != expected_name:
        raise ListingReceiptError(
            f"{browser} listing draft was copied or is not the exact listing identity."
        )
    found_ids = set(CHROMIUM_STORE_ID.findall(text))
    allowed_ids = {str(spec["store_id"])} if browser in {"chrome", "edge"} else set()
    if found_ids - allowed_ids:
        raise ListingReceiptError(
            f"{browser} listing draft invents or imports another 32-letter store ID."
        )
    release_identity = _load_release_identity(ROOT)
    store = str(spec["store"])
    name = str(spec["name"])
    local_listing_status = (
        "Status: LOCAL LISTING TEXT ONLY."
        if browser == "firefox"
        else "Status: BLOCKED."
    )
    local_listing_kind = (
        "No Firefox Add-ons draft or AMO item exists."
        if browser == "firefox"
        else "Local draft only"
    )
    required = (
        f"Store: `{store}`",
        f"Upload target: `{target_id}`",
        f"Name: `{name}`",
        local_listing_status,
        "Listing evidence: BLOCKED.",
        "Store evidence: BLOCKED.",
        local_listing_kind,
        "BLOCKED until a real",
        "Missing owner or store evidence",
        "Upload receipt: none.",
        "Upload authorized: no.",
        "Publication authorized: no.",
        f"Application companion release: `{release_identity['release']}`",
        f"Package version: `{release_identity['package_version']}`",
        f"Native-host name: `{NATIVE_HOST_NAME}`",
        "optional_host_permissions",
        "`<all_urls>`",
        "unsigned",
        "Archive signed: no.",
        f"`{spec['native_host_template']}`",
        f"`{spec['store_id']}`",
        f"`{spec['native_host_allowlist'][0]}`",
        "Privacy practices: BLOCKED.",
        "Category: owner-blocked.",
        "whitespace-only",
        "Identifier mangling is forbidden.",
    )
    if any(phrase not in text for phrase in required):
        raise ListingReceiptError(
            f"{browser} listing draft does not bind the exact store identity."
        )
    for archive in spec["unsigned_archives"]:
        filename = pathlib.PurePosixPath(str(archive)).name
        if f"`{filename}`" not in text and f"`{archive}`" not in text:
            raise ListingReceiptError(
                f"{browser} listing draft does not name the exact unsigned archive."
            )
    for other_id, other in LISTING_TARGETS.items():
        if other_id == target_id:
            continue
        other_store = str(other["store"])
        other_name = str(other["name"])
        other_store_id = str(other["store_id"])
        if (
            f"`{other_id}`" in text
            or f"Store: `{other_store}`" in text
            or (other_name != name and f"Name: `{other_name}`" in text)
            or f"Store ID: `{other_store_id}`" in text
            or f"`{other['native_host_allowlist'][0]}`" in text
        ):
            raise ListingReceiptError(
                f"{browser} listing draft was swapped or is cross-store evidence."
            )
    if browser == "firefox":
        if f"Gecko ID: `{GECKO_ID}`" not in text:
            raise ListingReceiptError("firefox listing draft Gecko ID is not exact.")
        if "allowed_extensions" not in text:
            raise ListingReceiptError(
                "firefox listing draft omits native-host allowed_extensions."
            )
        if "License: owner-blocked." not in text:
            raise ListingReceiptError("firefox listing draft omits the owner-blocked license.")
        if "Reviewer source: authored `extension/src`." not in text:
            raise ListingReceiptError(
                "firefox listing draft omits authored reviewer source disclosure."
            )
        if "Mozilla store review: none." not in text:
            raise ListingReceiptError(
                "firefox listing draft claims Mozilla review without store evidence."
            )
    else:
        if "Store ID:" not in text or "owner-authenticated draft" not in text.lower():
            raise ListingReceiptError(
                f"{browser} listing draft omits the owner-authenticated draft identity status."
            )
    return {
        "browser": browser,
        "target_id": target_id,
        "store": store,
        "name": name,
        "store_id": spec["store_id"],
        "store_id_status": spec["store_id_status"],
        "native_host_name": NATIVE_HOST_NAME,
        "native_host_allowlist": list(spec["native_host_allowlist"]),
        "unsigned_archives": list(spec["unsigned_archives"]),
        "sha256": digest,
        "identity": identity,
        "status": LISTING_EVIDENCE_STATUS,
        "publication_authorized": False,
        "upload_authorized": False,
        "upload_attempted": False,
    }


def validate_live_listings(repo: pathlib.Path | None = None) -> dict[str, object]:
    """Keep live Chrome, Edge, and Firefox listing drafts BLOCKED and distinct."""

    root = ROOT if repo is None else repo
    listing_root = LISTING_ROOT if repo is None else root / "extension" / "store_listings"
    _require_dir_nofollow(_absolute_lexical(root), "repository root")
    _walk_from_stop(
        listing_root, "browser listing directory", root, leaf_directory=True
    )
    names = {path.name for path in listing_root.iterdir()}
    if names != ALLOWED_LISTING_FILES:
        raise ListingReceiptError("browser listing directory has extra or missing files.")
    identities: set[tuple[int, int]] = set()
    listings: dict[str, object] = {}
    for target_id, spec in LISTING_TARGETS.items():
        browser = str(spec["browser"])
        path = listing_root / str(spec["listing_file"])
        bound = validate_listing_file(browser, path)
        inode = (int(bound["identity"][0]), int(bound["identity"][1]))
        if inode in identities:
            raise ListingReceiptError("browser listing drafts share an inode.")
        identities.add(inode)
        listings[target_id] = bound
    identity = _load_release_identity(root)
    readme, _digest, _readme_identity = _authenticated_regular_file(
        listing_root / "README.md",
        "listing README",
        maximum=MAX_LISTING_BYTES,
        stop=listing_root,
    )
    readme_text = _decode_ascii(readme, "listing README")
    if (
        f"`{identity['release']}`" not in readme_text
        or f"`{identity['package_version']}`" not in readme_text
        or "BLOCKED until a real upload receipt binds the exact"
        not in readme_text
        or "Missing owner or store evidence" not in readme_text
        or LISTING_EVIDENCE_STATUS not in readme_text
        or CHROME_STORE_ID not in readme_text
        or EDGE_STORE_ID not in readme_text
        or NATIVE_HOST_NAME not in readme_text
        or "Upload authorized: no." not in readme_text
        or "unsigned" not in readme_text
        or PRIVACY_LABEL_NAME not in readme_text
        or RELEASE_CANDIDATE_NAME not in readme_text
        or "whitespace-only" not in readme_text
        or "no_current_candidate" not in readme_text
        or HELD_HASH_STATUS not in readme_text
    ):
        raise ListingReceiptError("listing README does not keep release identities distinct.")
    store_identity = _validate_store_identity_record(
        _load_json_object(
            listing_root / STORE_IDENTITY_NAME,
            "store identity",
            stop=listing_root,
        ),
        identity,
    )
    owner_signoff = _validate_owner_signoff(
        _load_json_object(
            listing_root / OWNER_SIGNOFF_NAME,
            "listing owner signoff",
            stop=listing_root,
        ),
        identity,
    )
    privacy_label = _validate_privacy_label(
        _load_json_object(
            listing_root / PRIVACY_LABEL_NAME,
            "listing privacy label",
            stop=listing_root,
        ),
        identity,
    )
    release_candidate = _validate_release_candidate(
        _load_json_object(
            listing_root / RELEASE_CANDIDATE_NAME,
            "listing release candidate",
            stop=listing_root,
        ),
        identity,
    )
    for json_name in (
        STORE_IDENTITY_NAME,
        OWNER_SIGNOFF_NAME,
        PRIVACY_LABEL_NAME,
        RELEASE_CANDIDATE_NAME,
    ):
        info = (listing_root / json_name).lstat()
        inode = (info.st_dev, info.st_ino)
        if inode in identities:
            raise ListingReceiptError("browser listing drafts share an inode.")
        identities.add(inode)
    live = {
        "ok": False,
        "status": LISTING_EVIDENCE_STATUS,
        "release": identity["release"],
        "package_version": identity["package_version"],
        "publication_authorized": False,
        "upload_authorized": False,
        "upload_attempted": False,
        "native_host_name": NATIVE_HOST_NAME,
        "store_identity": store_identity,
        "owner_signoff": owner_signoff,
        "privacy_label": privacy_label,
        "release_candidate": release_candidate,
        "held_candidate_hashes": _held_candidate_hashes(release_candidate),
        "listings": listings,
        "reason": LISTING_EVIDENCE_REASON,
    }
    return live


def _bound_receipt_digest_pairs(
    target_id: str, record: Mapping[str, object]
) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    artifact = record.get("artifact")
    if type(artifact) is dict:
        pairs.append(
            (
                f"{target_id}.artifact",
                _hex64(artifact.get("sha256"), f"{target_id} artifact"),
            )
        )
    return pairs


def bind_listing_upload_receipt(
    target_id: str,
    record: Mapping[str, object],
    *,
    artifact_sha256: str,
    artifact_bytes: int,
    artifact_name: str,
    artifact_payload: bytes | None = None,
    now: dt.datetime | None = None,
    ledger_dir: pathlib.Path | None = None,
    consume: bool = True,
) -> dict[str, object]:
    """Bind one listing upload receipt to exact candidate ZIP bytes and store identity."""

    spec = _target_spec(target_id)
    if "authenticated" in record:
        raise ListingReceiptError(
            f"{target_id} self-asserted authenticated:true is not issuer proof."
        )
    receipt = _exact_mapping(
        dict(record), set(LISTING_RECEIPT_KEYS), f"{target_id} upload receipt"
    )
    identity = _load_release_identity(ROOT)
    schema = receipt.get("schema_version")
    if (
        receipt.get("ok") is not True
        or type(schema) is not int
        or isinstance(schema, bool)
        or schema != LISTING_UPLOAD_RECEIPT_SCHEMA_VERSION
        or receipt.get("contract") != LISTING_UPLOAD_RECEIPT_CONTRACT
        or receipt.get("release") != identity["release"]
        or receipt.get("target_id") != target_id
        or receipt.get("platform") != "extension"
        or receipt.get("publication_authorized") is not False
        or receipt.get("upload_attempted") is not False
    ):
        raise ListingReceiptError(
            f"{target_id} receipt binding is invalid, swapped, or cross-package."
        )
    _trusted_signer(receipt.get("trusted_signer"), target_id)
    artifact = _exact_mapping(
        receipt.get("artifact"), set(ARTIFACT_KEYS), f"{target_id} artifact"
    )
    path = artifact.get("path")
    if type(path) is not str or not path or pathlib.PurePosixPath(path).is_absolute():
        raise ListingReceiptError(
            f"{target_id} artifact path must be the exact repository path."
        )
    filename = pathlib.PurePosixPath(path).name
    expected_path = _canonical_artifact_path(spec, filename)
    suffixes = spec["artifact_suffixes"]
    if (
        filename != artifact_name
        or path != expected_path
        or not any(filename.endswith(suffix) for suffix in suffixes)
    ):
        raise ListingReceiptError(
            f"{target_id} receipt is cross-package or does not bind the exact candidate ZIP."
        )
    bound_digest = _hex64(artifact_sha256, f"{target_id} candidate ZIP")
    if (
        artifact.get("sha256") != bound_digest
        or type(artifact.get("bytes")) is not int
        or isinstance(artifact.get("bytes"), bool)
        or int(artifact.get("bytes")) != artifact_bytes
        or int(artifact.get("bytes")) <= 0
    ):
        raise ListingReceiptError(
            f"{target_id} receipt was swapped or does not bind the exact candidate ZIP."
        )
    package = _exact_mapping(
        receipt.get("package_identity"),
        set(spec["identity_keys"]),
        f"{target_id} package identity",
    )
    if (
        package.get("name") != spec["name"]
        or package.get("version") != identity["package_version"]
        or package.get("target_id") != target_id
    ):
        raise ListingReceiptError(
            f"{target_id} receipt is cross-version or does not bind the store identity."
        )
    if target_id == "firefox-extension-package":
        _exact_str(package.get("gecko_id"), GECKO_ID, f"{target_id} Gecko ID")
    store = _exact_mapping(
        receipt.get("store_evidence"),
        set(STORE_EVIDENCE_KEYS),
        f"{target_id} store evidence",
    )
    store_id = store.get("store_id")
    if (
        store.get("surface") != spec["store_surface"]
        or store.get("status") != "not_uploaded"
        or type(store_id) is not str
        or store_id not in {"", "none"}
    ):
        raise ListingReceiptError(
            f"{target_id} store evidence is cross-store or is not pending portal evidence."
        )
    owner = _exact_mapping(
        receipt.get("owner_authorization"),
        set(OWNER_AUTHORIZATION_KEYS),
        f"{target_id} owner authorization",
    )
    if (
        owner.get("status") != "pending"
        or owner.get("credentials_authorized") is not False
        or owner.get("upload_authorized") is not False
    ):
        raise ListingReceiptError(
            f"{target_id} owner authorization must remain pending without owner evidence."
        )
    nonce = _bind_listing_authentication(
        target_id,
        spec,
        receipt,
        artifact_path=expected_path,
        artifact_sha256=bound_digest,
        artifact_bytes=artifact_bytes,
        package_version=identity["package_version"],
        now=now,
        ledger_dir=ledger_dir,
        consume=False,
    )
    issuance_id = _issuance_id(receipt.get("issuance_id"), target_id)
    if issuance_id != nonce:
        raise ListingReceiptError(
            f"{target_id} issuance_id is invalid or replayable."
        )
    verified_at = _parse_utc(receipt.get("verified_utc"), f"{target_id} receipt")
    issued_at = _parse_utc(
        receipt["authentication"]["issued_at"], f"{target_id} listing issued_at"
    )
    if verified_at != issued_at:
        raise ListingReceiptError(f"{target_id} receipt timestamp is not exact.")
    _reject_digest_reuse(_bound_receipt_digest_pairs(target_id, receipt))
    if artifact_payload is None:
        raise ListingReceiptError(f"{target_id} exact package bytes are missing.")
    if (
        hashlib.sha256(artifact_payload).hexdigest() != bound_digest
        or len(artifact_payload) != artifact_bytes
    ):
        raise ListingReceiptError(
            f"{target_id} receipt was swapped or does not bind the exact candidate ZIP."
        )
    inspected = _inspect_package_bytes(target_id, spec, artifact_payload)
    _bind_inspected_identity(target_id, spec, package, inspected, identity)
    if consume:
        canonical = _canonical_auth_bytes(receipt["authentication"])  # type: ignore[arg-type]
        _consume_listing_nonce(
            target_id,
            receipt["authentication"],  # type: ignore[arg-type]
            canonical,
            ledger_dir=ledger_dir,
        )
    return {
        "ok": True,
        "target_id": target_id,
        "browser": spec["browser"],
        "store": spec["store"],
        "release": identity["release"],
        "package_version": identity["package_version"],
        "artifact_sha256": bound_digest,
        "artifact_bytes": artifact_bytes,
        "artifact_name": filename,
        "artifact_path": expected_path,
        "issuance_id": issuance_id,
        "nonce": nonce,
        "trusted_signer": {
            "status": "pending",
            "identity": "none",
            "store_signed": False,
        },
        "listing_status": LISTING_EVIDENCE_STATUS,
        "publication_authorized": False,
        "upload_authorized": False,
        "upload_attempted": False,
        "unsigned_archive": True,
        "native_host_name": NATIVE_HOST_NAME,
        "store_evidence": {"surface": spec["store_surface"], "status": "not_uploaded"},
    }


def bind_listing_upload_receipt_file(
    target_id: str,
    receipt_path: pathlib.Path,
    artifact_path: pathlib.Path,
    *,
    now: dt.datetime | None = None,
    ledger_dir: pathlib.Path | None = None,
) -> dict[str, object]:
    """Authenticate one receipt file and bind it to one candidate ZIP path."""

    spec = _target_spec(target_id)
    relative = _repo_relative(ROOT, artifact_path, f"{target_id} candidate ZIP")
    expected_path = _canonical_artifact_path(spec, artifact_path.name)
    if relative != expected_path:
        raise ListingReceiptError(
            f"{target_id} receipt is cross-package or does not bind the exact candidate ZIP."
        )
    receipt_payload, receipt_digest, receipt_identity = _authenticated_regular_file(
        receipt_path, f"{target_id} upload receipt"
    )
    artifact_payload, artifact_digest, artifact_identity = _authenticated_regular_file(
        artifact_path,
        f"{target_id} candidate ZIP",
        maximum=MAX_ARTIFACT_BYTES,
        stop=ROOT,
    )
    if receipt_identity == artifact_identity:
        raise ListingReceiptError(
            f"{target_id} receipt reuse is refused: receipt reuses the candidate ZIP inode."
        )
    try:
        record = json.loads(
            _decode_ascii(receipt_payload, f"{target_id} upload receipt"),
            object_pairs_hook=lambda pairs: _reject_duplicate_keys(
                pairs, f"{target_id} upload receipt"
            ),
            parse_constant=lambda value: _reject_nonfinite_constant(
                value, f"{target_id} upload receipt"
            ),
        )
    except json.JSONDecodeError as suc:
        raise ListingReceiptError(f"{target_id} upload receipt is not JSON.") from suc
    if type(record) is not dict:
        raise ListingReceiptError(f"{target_id} upload receipt must be one JSON object.")
    artifact = record.get("artifact")
    if type(artifact) is not dict or artifact.get("path") != relative:
        raise ListingReceiptError(
            f"{target_id} receipt is cross-package or does not bind the exact candidate ZIP."
        )
    bound = bind_listing_upload_receipt(
        target_id,
        record,
        artifact_sha256=artifact_digest,
        artifact_bytes=len(artifact_payload),
        artifact_name=artifact_path.name,
        artifact_payload=artifact_payload,
        now=now,
        ledger_dir=ledger_dir,
    )
    after_receipt = receipt_path.lstat()
    after_artifact = artifact_path.lstat()
    if (
        _identity(after_receipt) != receipt_identity
        or _identity(after_artifact) != artifact_identity
        or stat.S_ISLNK(after_receipt.st_mode)
        or stat.S_ISLNK(after_artifact.st_mode)
    ):
        raise ListingReceiptError(
            f"{target_id} receipt or candidate ZIP was swapped after authentication."
        )
    bound["receipt_sha256"] = receipt_digest
    bound["receipt_identity"] = receipt_identity
    bound["artifact_identity"] = artifact_identity
    bound["store"] = spec["store"]
    return bound


def bind_listing_upload_receipts(
    records: Mapping[str, Mapping[str, object]],
    artifacts: Mapping[str, tuple[str, int, str]],
    payloads: Mapping[str, bytes] | None = None,
    *,
    ledger_dir: pathlib.Path | None = None,
    now: dt.datetime | None = None,
) -> dict[str, object]:
    """Bind listing receipts, refusing reuse, and keep missing stores pending."""

    if type(records) is not dict or type(artifacts) is not dict:
        raise ListingReceiptError("browser listing/upload receipt set is invalid.")
    unexpected = set(records) - set(LISTING_TARGETS)
    if unexpected:
        raise ListingReceiptError(
            "unexpected browser listing/upload receipt target: "
            + ", ".join(sorted(unexpected))
        )
    if not records:
        if artifacts:
            raise ListingReceiptError(
                "browser listing artifacts cannot bind without upload receipts."
            )
        live = validate_live_listings()
        payload = _blocked_listing_payload(live)
        return payload
    digest_pairs: list[tuple[str, str]] = []
    issuance_seen: dict[str, str] = {}
    nonce_seen: dict[str, str] = {}
    for target_id, record in records.items():
        if type(record) is not dict:
            raise ListingReceiptError(f"{target_id} upload receipt must be one JSON object.")
        issuance = _issuance_id(record.get("issuance_id"), target_id)
        previous = issuance_seen.get(issuance)
        if previous is not None:
            raise ListingReceiptError(
                f"receipt reuse is refused: {target_id} reuses {previous} issuance_id"
            )
        issuance_seen[issuance] = target_id
        auth = record.get("authentication")
        if type(auth) is dict:
            nonce = auth.get("nonce")
            if type(nonce) is str:
                reused = nonce_seen.get(nonce)
                if reused is not None:
                    raise ListingReceiptError(
                        f"receipt reuse is refused: {target_id} reuses {reused} nonce"
                    )
                nonce_seen[nonce] = target_id
        digest_pairs.extend(_bound_receipt_digest_pairs(target_id, dict(record)))
    _reject_digest_reuse(digest_pairs)
    if type(payloads) is not dict:
        raise ListingReceiptError("browser listing exact package bytes are missing.")
    bound: dict[str, object] = {}
    for target_id, record in records.items():
        artifact = artifacts.get(target_id)
        payload = payloads.get(target_id)
        if artifact is None or len(artifact) != 3:
            raise ListingReceiptError(f"{target_id} exact candidate ZIP identity is missing.")
        if type(payload) is not bytes:
            raise ListingReceiptError(f"{target_id} exact package bytes are missing.")
        digest, size, name = artifact
        bound[target_id] = bind_listing_upload_receipt(
            target_id,
            record,
            artifact_sha256=str(digest),
            artifact_bytes=int(size),
            artifact_name=str(name),
            artifact_payload=payload,
            now=now,
            ledger_dir=ledger_dir,
        )
    stores = _blocked_store_map()
    return {
        "ok": False,
        "status": LISTING_EVIDENCE_STATUS,
        "publication_authorized": False,
        "upload_authorized": False,
        "upload_attempted": False,
        "owner_authorization": LISTING_EVIDENCE_STATUS,
        "trusted_signer": LISTING_EVIDENCE_STATUS,
        "native_host_name": NATIVE_HOST_NAME,
        "stores": stores,
        "receipts": bound,
        "reason": LISTING_EVIDENCE_REASON,
    }


def listing_states(repo: pathlib.Path | None = None) -> dict[str, object]:
    """Return live Chrome, Edge, and Firefox listing states as BLOCKED without portal evidence."""

    live = validate_live_listings(repo)
    return _blocked_listing_payload(live)


def main() -> int:
    """Report BLOCKED listing evidence without treating it as a green pass."""

    try:
        live = listing_states()
    except ListingReceiptError as suc:
        print(f"FAIL: {suc}")
        return 1
    if live.get("ok") is not False or live.get("status") != LISTING_EVIDENCE_STATUS:
        print("FAIL: listing evidence is not BLOCKED without owner proof.")
        return 1
    print(
        "BLOCKED: Chrome Web Store, Edge Add-ons, and Firefox AMO listing, "
        "review, and release-candidate evidence is missing owner or store proof"
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
