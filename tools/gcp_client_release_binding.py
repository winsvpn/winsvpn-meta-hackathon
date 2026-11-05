#!/usr/bin/env python3
"""Bind the dedicated GCP proof executable to exact release provenance.

This module is intentionally independent of the fleet, deployer, collector, and
live-probe implementations.  It accepts no caller-authored build identity.  The
identity is derived from the custody-v3 proof source, release defines, reviewed
Go and Google Cloud CLI pins, fixed build contract, and exact build receipt.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import stat
import struct
import sys
from collections.abc import Mapping
from typing import Any


TOOLS = pathlib.Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import release_dependency_freeze as freeze
import build_gcp_proof_client as proof_builder


SCHEMA_VERSION = 3
CONTRACT = "winsvpn-gcp-client-release-binding-v3"
PLATFORM = "linux"
PROOF_CLIENT_TARGET = proof_builder.explicit_target("linux", "amd64")
OWNER_AUTHORITY_PATH = pathlib.Path(
    "/var/lib/winsvpn/gcloud-owner-authority-v1.json"
)
OWNER_ARTIFACT_AUTHORIZATION_PATH = pathlib.Path(
    "/var/lib/winsvpn/gcp-proof-client-artifact-authorization-v1.json"
)
OWNER_AUTHORITY_CONTRACT = "winsvpn-gcloud-owner-authority-v1"
OWNER_AUTHORIZATION_CONTRACT = (
    "winsvpn-gcp-proof-client-artifact-authorization-issuance-v1"
)
ARTIFACT_AUTHORIZATION_CONTRACT = (
    "winsvpn-gcp-proof-client-artifact-authorization-v1"
)
OWNER_ISSUER = "winsvpn-owner"
OWNER_ALGORITHM = "ed25519"
OWNER_SIGNATURE_DOMAIN = b"winsvpn-gcp-proof-client-artifact-authorization-v1\n"
OWNER_BLOCKED_AUTHORIZATION = (
    "OWNER-BLOCKED: exact GCP proof-client artifact authorization from the "
    "root-owned GCP owner authority is required"
)
MAX_OWNER_DOCUMENT = 64 * 1024
MAX_AUTHORIZATION_AGE = dt.timedelta(hours=6)
MAX_AUTHORIZATION_SKEW = dt.timedelta(minutes=5)
UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
ID_RE = re.compile(r"^[a-f0-9]{32}$")
ED25519_PUBLIC_KEY_RE = re.compile(r"^[a-f0-9]{64}$")
ED25519_SIGNATURE_RE = re.compile(r"^[a-f0-9]{128}$")
OWNER_AUTHORITY_KEYS = frozenset(
    {"algorithm", "contract", "key_id", "owner_uid", "public_key", "schema_version"}
)
OWNER_AUTHORIZATION_KEYS = frozenset(
    {"algorithm", "authorization", "contract", "issuer", "key_id", "schema_version", "signature"}
)
ARTIFACT_AUTHORIZATION_KEYS = frozenset(
    {
        "artifact_bytes",
        "artifact_name",
        "artifact_sha256",
        "authorization_id",
        "build_identity",
        "build_receipt_sha256",
        "contract",
        "expires_utc",
        "issued_utc",
        "purpose",
        "release",
        "release_input_index_sha256",
        "schema_version",
        "shared_revision",
        "source_sha256",
        "target",
    }
)
INDEX_KEYS = frozenset(
    {
        "schema_version",
        "contract",
        "release",
        "shared_revision",
        "created_utc",
        "shared_manifest",
        "platform_manifests",
        "sha256_anchor",
        "manifest_set_complete",
        "publication_authorized",
    }
)
RECEIPT_KEYS = frozenset(
    {
        "artifact",
        "build_contract",
        "build_identity",
        "builder",
        "contract",
        "defines",
        "publication_authorized",
        "release",
        "release_input_index",
        "schema_version",
        "shared_revision",
        "source",
        "target",
        "toolchain",
        "toolchain_pin_manifest",
    }
)
PROOF_BUILD_KEYS = frozenset(
    {
        "build_contract",
        "build_identity",
        "builder",
        "defines",
        "source",
        "target",
        "toolchain",
        "toolchain_pin_manifest",
    }
)


class ClientReleaseBindingError(RuntimeError):
    """A client release cannot be accepted as GCP proof input."""


def canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    """Return deterministic, compact, newline-terminated ASCII JSON."""

    try:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ClientReleaseBindingError(
            "Client release binding is not JSON-safe."
        ) from exc
    return (encoded + "\n").encode("ascii")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ClientReleaseBindingError(
                f"Duplicate JSON key {key!r} is forbidden."
            )
        result[key] = value
    return result


def _strict_json(label: str, data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            data.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs
        )
    except ClientReleaseBindingError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ClientReleaseBindingError(f"{label} is not valid UTF-8 JSON.") from exc
    if not isinstance(value, dict):
        raise ClientReleaseBindingError(f"{label} must be a JSON object.")
    return value


def _exact_keys(value: object, expected: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ClientReleaseBindingError(f"{label} has missing or unknown keys.")
    return value


def _canonical_repo_root(raw_repo: pathlib.Path) -> pathlib.Path:
    text = os.fspath(raw_repo)
    if not raw_repo.is_absolute() or os.path.normpath(text) != text:
        raise ClientReleaseBindingError(
            "Repository root must be an absolute canonical path."
        )
    try:
        info = raw_repo.lstat()
    except OSError as exc:
        raise ClientReleaseBindingError("Repository root is not readable.") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ClientReleaseBindingError(
            "Repository root must be a non-symlink directory."
        )
    if raw_repo.resolve() != raw_repo:
        raise ClientReleaseBindingError("Repository root path is not canonical.")
    return raw_repo


def _contained_absolute_path(
    repo: pathlib.Path, raw_path: pathlib.Path, label: str
) -> pathlib.Path:
    text = os.fspath(raw_path)
    if (
        not raw_path.is_absolute()
        or "\\" in text
        or "\x00" in text
        or os.path.normpath(text) != text
    ):
        raise ClientReleaseBindingError(
            f"{label} must be an absolute canonical path without traversal."
        )
    try:
        raw_path.relative_to(repo)
    except ValueError as exc:
        raise ClientReleaseBindingError(
            f"{label} must stay inside the repository."
        ) from exc
    try:
        secured = freeze.secure_repo_path(
            repo, raw_path, label, must_exist=True
        )
    except freeze.DependencyFreezeError as exc:
        raise ClientReleaseBindingError(str(exc)) from exc
    if secured != raw_path or secured.resolve() != raw_path:
        raise ClientReleaseBindingError(f"{label} path is not canonical.")
    return secured


def _identity(
    info: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_nlink,
        stat.S_IMODE(info.st_mode),
    )


def _read_stable_regular(
    path: pathlib.Path, label: str, *, executable: bool = False
) -> tuple[bytes, os.stat_result]:
    try:
        before = path.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
        ):
            raise ClientReleaseBindingError(
                f"{label} must be a single-link regular non-symlink file."
            )
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            finished = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = path.lstat()
    except ClientReleaseBindingError:
        raise
    except OSError as exc:
        raise ClientReleaseBindingError(f"{label} is not readable.") from exc
    if not (
        _identity(before)
        == _identity(opened)
        == _identity(finished)
        == _identity(after)
    ):
        raise ClientReleaseBindingError(f"{label} changed while being read.")
    data = b"".join(chunks)
    if not data:
        raise ClientReleaseBindingError(f"{label} must not be empty.")
    mode = stat.S_IMODE(opened.st_mode)
    if executable and (mode & 0o111 == 0 or mode & 0o022 != 0):
        raise ClientReleaseBindingError(
            f"{label} must be executable and not group/world writable."
        )
    return data, finished


def _snapshot_file(
    repo: pathlib.Path,
    raw_path: pathlib.Path,
    label: str,
    *,
    executable: bool = False,
) -> tuple[pathlib.Path, bytes, os.stat_result]:
    path = _contained_absolute_path(repo, raw_path, label)
    data, info = _read_stable_regular(path, label, executable=executable)
    return path, data, info


def _unchanged(
    path: pathlib.Path,
    label: str,
    expected_data: bytes,
    expected_info: os.stat_result,
    *,
    executable: bool = False,
) -> None:
    current_data, current_info = _read_stable_regular(
        path, label, executable=executable
    )
    if current_data != expected_data or _identity(current_info) != _identity(
        expected_info
    ):
        raise ClientReleaseBindingError(f"{label} changed during verification.")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _path_inside(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except ValueError:
        return False
    return True


def _read_root_owned_external(path: pathlib.Path, label: str) -> bytes:
    if not path.is_absolute() or os.geteuid() == 0:
        raise ClientReleaseBindingError(OWNER_BLOCKED_AUTHORIZATION)
    try:
        visible = path.lstat()
        if stat.S_ISLNK(visible.st_mode) or not stat.S_ISREG(visible.st_mode):
            raise ClientReleaseBindingError(OWNER_BLOCKED_AUTHORIZATION)
        resolved = path.resolve(strict=True)
        info = resolved.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) & 0o222
            or info.st_size <= 0
            or info.st_size > MAX_OWNER_DOCUMENT
            or _identity(visible) != _identity(info)
        ):
            raise ClientReleaseBindingError(OWNER_BLOCKED_AUTHORIZATION)
        for ancestor in (resolved.parent, *resolved.parents[1:]):
            ancestor_info = ancestor.lstat()
            if (
                stat.S_ISLNK(ancestor_info.st_mode)
                or not stat.S_ISDIR(ancestor_info.st_mode)
                or ancestor_info.st_uid != 0
                or stat.S_IMODE(ancestor_info.st_mode) & 0o022
            ):
                raise ClientReleaseBindingError(OWNER_BLOCKED_AUTHORIZATION)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        before = resolved.lstat()
        descriptor = os.open(resolved, flags)
        try:
            opened = os.fstat(descriptor)
            chunks: list[bytes] = []
            while block := os.read(descriptor, 1024 * 1024):
                chunks.append(block)
            finished = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = resolved.lstat()
    except ClientReleaseBindingError:
        raise
    except OSError as exc:
        raise ClientReleaseBindingError(OWNER_BLOCKED_AUTHORIZATION) from exc
    if not (
        _identity(info)
        == _identity(before)
        == _identity(opened)
        == _identity(finished)
        == _identity(after)
    ):
        raise ClientReleaseBindingError(f"{label} changed while it was read.")
    data = b"".join(chunks)
    if not data:
        raise ClientReleaseBindingError(OWNER_BLOCKED_AUTHORIZATION)
    return data


def _load_owner_authorization_documents(
    repo: pathlib.Path,
) -> tuple[bytes, bytes]:
    for path in (OWNER_AUTHORITY_PATH, OWNER_ARTIFACT_AUTHORIZATION_PATH):
        if _path_inside(path, repo):
            raise ClientReleaseBindingError(OWNER_BLOCKED_AUTHORIZATION)
    authority = _read_root_owned_external(
        OWNER_AUTHORITY_PATH, "GCP owner authority"
    )
    authorization = _read_root_owned_external(
        OWNER_ARTIFACT_AUTHORIZATION_PATH,
        "GCP proof-client artifact authorization",
    )
    return authority, authorization


def _exact_text(value: object, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or value.strip() != value
        or any(ord(character) < 32 for character in value)
    ):
        raise ClientReleaseBindingError(f"{label} is invalid.")
    return value


def _exact_int(value: object, label: str) -> int:
    if type(value) is not int:
        raise ClientReleaseBindingError(f"{label} is invalid.")
    return value


_ED25519_P = 2**255 - 19
_ED25519_L = 2**252 + 27742317777372353535851937790883648493
_ED25519_D = (-121665 * pow(121666, _ED25519_P - 2, _ED25519_P)) % _ED25519_P
_ED25519_I = pow(2, (_ED25519_P - 1) // 4, _ED25519_P)


def _ed25519_recover_x(y: int, sign: int) -> int | None:
    if y >= _ED25519_P:
        return None
    xx = (y * y - 1) * pow(
        _ED25519_D * y * y + 1, _ED25519_P - 2, _ED25519_P
    )
    x = pow(xx % _ED25519_P, (_ED25519_P + 3) // 8, _ED25519_P)
    if (x * x - xx) % _ED25519_P != 0:
        x = x * _ED25519_I % _ED25519_P
    if (x * x - xx) % _ED25519_P != 0 or (x == 0 and sign == 1):
        return None
    if x & 1 != sign:
        x = _ED25519_P - x
    return x


def _ed25519_decode_point(encoded: bytes) -> tuple[int, int, int, int] | None:
    if len(encoded) != 32:
        return None
    value = int.from_bytes(encoded, "little")
    y = value & ((1 << 255) - 1)
    x = _ed25519_recover_x(y, value >> 255)
    if x is None:
        return None
    return (x, y, 1, x * y % _ED25519_P)


def _ed25519_add(
    left: tuple[int, int, int, int], right: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % _ED25519_P
    b = (y1 + x1) * (y2 + x2) % _ED25519_P
    c = 2 * t1 * t2 * _ED25519_D % _ED25519_P
    d = 2 * z1 * z2 % _ED25519_P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (
        e * f % _ED25519_P,
        g * h % _ED25519_P,
        f * g % _ED25519_P,
        e * h % _ED25519_P,
    )


def _ed25519_mul(
    point: tuple[int, int, int, int], scalar: int
) -> tuple[int, int, int, int]:
    result = (0, 1, 1, 0)
    current = point
    while scalar:
        if scalar & 1:
            result = _ed25519_add(result, current)
        current = _ed25519_add(current, current)
        scalar >>= 1
    return result


_ED25519_BASE_Y = 4 * pow(5, _ED25519_P - 2, _ED25519_P) % _ED25519_P
_ED25519_BASE_X = _ed25519_recover_x(_ED25519_BASE_Y, 0)
if _ED25519_BASE_X is None:
    raise RuntimeError("Ed25519 base point construction failed")
_ED25519_BASE = (
    _ED25519_BASE_X,
    _ED25519_BASE_Y,
    1,
    _ED25519_BASE_X * _ED25519_BASE_Y % _ED25519_P,
)


def _ed25519_equal(
    left: tuple[int, int, int, int], right: tuple[int, int, int, int]
) -> bool:
    return (
        (left[0] * right[2] - right[0] * left[2]) % _ED25519_P == 0
        and (left[1] * right[2] - right[1] * left[2]) % _ED25519_P == 0
    )


def _verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    public_point = _ed25519_decode_point(public_key)
    signature_point = _ed25519_decode_point(signature[:32])
    scalar = int.from_bytes(signature[32:], "little")
    neutral = (0, 1, 1, 0)
    if public_point is None or signature_point is None or scalar >= _ED25519_L:
        return False
    if _ed25519_equal(public_point, neutral):
        return False
    challenge = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
    ) % _ED25519_L
    return _ed25519_equal(
        _ed25519_mul(_ED25519_BASE, scalar),
        _ed25519_add(signature_point, _ed25519_mul(public_point, challenge)),
    )


def _authorization_time(value: object, label: str) -> dt.datetime:
    text = _exact_text(value, label)
    if UTC_RE.fullmatch(text) is None:
        raise ClientReleaseBindingError(f"{label} is not exact UTC.")
    try:
        return dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.timezone.utc
        )
    except ValueError as exc:
        raise ClientReleaseBindingError(f"{label} is invalid.") from exc


def _parse_owner_authority(data: bytes) -> tuple[str, bytes]:
    authority = _exact_keys(
        _strict_json("GCP owner authority", data),
        OWNER_AUTHORITY_KEYS,
        "GCP owner authority",
    )
    if (
        _exact_int(authority.get("schema_version"), "Authority schema_version")
        != 1
        or _exact_text(authority.get("contract"), "Authority contract")
        != OWNER_AUTHORITY_CONTRACT
        or _exact_text(authority.get("algorithm"), "Authority algorithm")
        != OWNER_ALGORITHM
        or _exact_int(authority.get("owner_uid"), "Authority owner_uid") != 0
    ):
        raise ClientReleaseBindingError(OWNER_BLOCKED_AUTHORIZATION)
    public_key_text = _exact_text(authority.get("public_key"), "Authority key")
    key_id = _exact_text(authority.get("key_id"), "Authority key id")
    if ED25519_PUBLIC_KEY_RE.fullmatch(public_key_text) is None:
        raise ClientReleaseBindingError(OWNER_BLOCKED_AUTHORIZATION)
    public_key = bytes.fromhex(public_key_text)
    if key_id != _sha256(public_key):
        raise ClientReleaseBindingError(OWNER_BLOCKED_AUTHORIZATION)
    return key_id, public_key


def _verify_artifact_authorization_document(
    authority_data: bytes,
    authorization_data: bytes,
    expected: Mapping[str, Any],
) -> dict[str, Any]:
    key_id, public_key = _parse_owner_authority(authority_data)
    issuance = _exact_keys(
        _strict_json("Artifact authorization", authorization_data),
        OWNER_AUTHORIZATION_KEYS,
        "Artifact authorization",
    )
    if (
        _exact_int(issuance.get("schema_version"), "Authorization schema_version")
        != 1
        or _exact_text(issuance.get("contract"), "Authorization contract")
        != OWNER_AUTHORIZATION_CONTRACT
        or _exact_text(issuance.get("issuer"), "Authorization issuer")
        != OWNER_ISSUER
        or _exact_text(issuance.get("algorithm"), "Authorization algorithm")
        != OWNER_ALGORITHM
        or _exact_text(issuance.get("key_id"), "Authorization key id")
        != key_id
    ):
        raise ClientReleaseBindingError(OWNER_BLOCKED_AUTHORIZATION)
    authorization = _exact_keys(
        issuance.get("authorization"),
        ARTIFACT_AUTHORIZATION_KEYS,
        "Artifact authorization payload",
    )
    if (
        _exact_int(
            authorization.get("schema_version"),
            "Artifact authorization schema_version",
        )
        != 1
        or _exact_text(
            authorization.get("contract"), "Artifact authorization contract"
        )
        != ARTIFACT_AUTHORIZATION_CONTRACT
        or _exact_text(authorization.get("purpose"), "Authorization purpose")
        != "gcp-proof-client-execution"
    ):
        raise ClientReleaseBindingError(OWNER_BLOCKED_AUTHORIZATION)
    authorization_id = _exact_text(
        authorization.get("authorization_id"), "Authorization id"
    )
    if ID_RE.fullmatch(authorization_id) is None or authorization_id == "0" * 32:
        raise ClientReleaseBindingError(OWNER_BLOCKED_AUTHORIZATION)
    issued = _authorization_time(authorization.get("issued_utc"), "issued_utc")
    expires = _authorization_time(authorization.get("expires_utc"), "expires_utc")
    now = dt.datetime.now(dt.timezone.utc)
    if (
        issued > now + MAX_AUTHORIZATION_SKEW
        or now - issued > MAX_AUTHORIZATION_AGE
        or expires <= now
        or expires <= issued
        or expires - issued > MAX_AUTHORIZATION_AGE
    ):
        raise ClientReleaseBindingError(
            "OWNER-BLOCKED: GCP proof-client artifact authorization is stale or future-dated."
        )
    for key, value in expected.items():
        if authorization.get(key) != value:
            raise ClientReleaseBindingError(
                f"Artifact authorization does not bind exact {key.replace('_', ' ')}."
            )
    signature_text = _exact_text(issuance.get("signature"), "Authorization signature")
    if ED25519_SIGNATURE_RE.fullmatch(signature_text) is None or not _verify_ed25519(
        public_key,
        OWNER_SIGNATURE_DOMAIN + canonical_bytes(authorization),
        bytes.fromhex(signature_text),
    ):
        raise ClientReleaseBindingError(
            "GCP proof-client artifact authorization signature is invalid."
        )
    return authorization


def _authenticate_artifact_authorization(
    repo: pathlib.Path, expected: Mapping[str, Any]
) -> dict[str, Any]:
    first = _load_owner_authorization_documents(repo)
    authorization = _verify_artifact_authorization_document(
        first[0], first[1], expected
    )
    second = _load_owner_authorization_documents(repo)
    if second != first:
        raise ClientReleaseBindingError(
            "GCP owner authority or artifact authorization changed during verification."
        )
    if _verify_artifact_authorization_document(second[0], second[1], expected) != authorization:
        raise ClientReleaseBindingError(
            "GCP proof-client artifact authorization changed during verification."
        )
    return authorization


def _require_linux_amd64_elf(data: bytes) -> None:
    if (
        len(data) < 64
        or data[:4] != b"\x7fELF"
        or data[4:7] != b"\x02\x01\x01"
        or data[7] not in {0, 3}
    ):
        raise ClientReleaseBindingError(
            "Probe executable is not a Linux amd64 ELF64 artifact."
        )
    executable_type, machine, version = struct.unpack_from("<HHI", data, 16)
    header_size = struct.unpack_from("<H", data, 52)[0]
    if executable_type not in {2, 3} or machine != 62 or version != 1 or header_size != 64:
        raise ClientReleaseBindingError(
            "Probe executable is not a Linux amd64 ELF64 artifact."
        )


def verify_client_release(
    repo_root: pathlib.Path,
    release_input_index: pathlib.Path,
    build_receipt: pathlib.Path,
    artifact: pathlib.Path,
    *,
    platform: str = PLATFORM,
) -> dict[str, Any]:
    """Verify and bind one exact dedicated Linux proof executable."""

    if platform != PLATFORM:
        raise ClientReleaseBindingError("GCP proof client platform must be linux.")
    repo = _canonical_repo_root(repo_root)
    index_path, index_data, index_info = _snapshot_file(
        repo, release_input_index, "Release input index"
    )
    receipt_path, receipt_data, receipt_info = _snapshot_file(
        repo, build_receipt, "Build receipt"
    )
    artifact_path, artifact_data, artifact_info = _snapshot_file(
        repo, artifact, "Probe executable", executable=True
    )
    try:
        proof_builder.require_labeled_artifact_path(
            artifact_path, PROOF_CLIENT_TARGET, "Probe executable"
        )
    except proof_builder.ProofBuildError as exc:
        raise ClientReleaseBindingError(str(exc)) from exc
    _require_linux_amd64_elf(artifact_data)
    index_anchor_path, index_anchor_data, index_anchor_info = _snapshot_file(
        repo,
        index_path.with_name(index_path.name + ".sha256"),
        "Release input index anchor",
    )
    receipt_anchor_path, receipt_anchor_data, receipt_anchor_info = _snapshot_file(
        repo,
        receipt_path.with_name(receipt_path.name + ".sha256"),
        "Build receipt anchor",
    )

    index_record = _exact_keys(
        _strict_json("Release input index", index_data),
        INDEX_KEYS,
        "Release input index",
    )
    receipt_record = _exact_keys(
        _strict_json("Build receipt", receipt_data),
        RECEIPT_KEYS,
        "Build receipt",
    )
    if (
        index_record.get("schema_version") != freeze.SCHEMA_VERSION
        or index_record.get("contract") != freeze.INDEX_CONTRACT
    ):
        raise ClientReleaseBindingError("Release input index schema is unsupported.")
    if (
        receipt_record.get("schema_version") != proof_builder.SCHEMA_VERSION
        or receipt_record.get("contract") != proof_builder.RECEIPT_CONTRACT
        or receipt_record.get("publication_authorized") is not False
    ):
        raise ClientReleaseBindingError(
            "Dedicated proof build receipt schema is unsupported."
        )

    index_sha256 = _sha256(index_data)
    exact_recorded_index = {
        "path": index_path.relative_to(repo).as_posix(),
        "sha256": index_sha256,
    }
    if _exact_keys(
        receipt_record.get("release_input_index"),
        frozenset({"path", "sha256"}),
        "Recorded release input index",
    ) != exact_recorded_index:
        raise ClientReleaseBindingError(
            "Build receipt does not bind the exact supplied release input index."
        )
    receipt_artifact = _exact_keys(
        receipt_record.get("artifact"),
        frozenset({"bytes", "mode", "path", "sha256"}),
        "Build receipt artifact",
    )
    if (
        receipt_artifact.get("path") != artifact_path.relative_to(repo).as_posix()
        or receipt_artifact.get("bytes") != len(artifact_data)
        or receipt_artifact.get("sha256") != _sha256(artifact_data)
        or receipt_artifact.get("mode") != "0555"
        or stat.S_IMODE(artifact_info.st_mode) != 0o555
    ):
        raise ClientReleaseBindingError(
            "Probe executable bytes do not match the build receipt artifact."
        )

    try:
        index_result = freeze.verify_release_index(repo, index_path, PLATFORM)
        expected_provenance = proof_builder.expected_provenance(
            repo, index_path, PROOF_CLIENT_TARGET
        )
    except (freeze.DependencyFreezeError, proof_builder.ProofBuildError) as exc:
        raise ClientReleaseBindingError(str(exc)) from exc
    for key in (
        "build_contract",
        "build_identity",
        "builder",
        "defines",
        "release",
        "release_input_index",
        "shared_revision",
        "source",
        "target",
        "toolchain",
        "toolchain_pin_manifest",
    ):
        if receipt_record.get(key) != expected_provenance.get(key):
            raise ClientReleaseBindingError(
                f"Dedicated proof build receipt {key.replace('_', ' ')} changed."
            )

    receipt_sha256 = _sha256(receipt_data)
    _authenticate_artifact_authorization(
        repo,
        {
            "artifact_bytes": len(artifact_data),
            "artifact_name": artifact_path.name,
            "artifact_sha256": _sha256(artifact_data),
            "build_identity": receipt_record["build_identity"],
            "build_receipt_sha256": receipt_sha256,
            "release": receipt_record["release"],
            "release_input_index_sha256": index_sha256,
            "shared_revision": receipt_record["shared_revision"],
            "source_sha256": expected_provenance["source"]["sha256"],
            "target": proof_builder.target_value(PROOF_CLIENT_TARGET),
        },
    )

    expected_receipt_anchor = (
        f"{_sha256(receipt_data)}  {receipt_path.name}\n".encode("ascii")
    )
    if receipt_anchor_data != expected_receipt_anchor:
        raise ClientReleaseBindingError("Build receipt anchor is not exact.")
    expected_index_anchor = (
        f"{index_sha256}  {index_path.name}\n".encode("ascii")
    )
    if index_anchor_data != expected_index_anchor:
        raise ClientReleaseBindingError("Release input index anchor is not exact.")

    for path, label, data, info, executable in (
        (index_path, "Release input index", index_data, index_info, False),
        (receipt_path, "Build receipt", receipt_data, receipt_info, False),
        (artifact_path, "Probe executable", artifact_data, artifact_info, True),
        (
            index_anchor_path,
            "Release input index anchor",
            index_anchor_data,
            index_anchor_info,
            False,
        ),
        (
            receipt_anchor_path,
            "Build receipt anchor",
            receipt_anchor_data,
            receipt_anchor_info,
            False,
        ),
    ):
        _unchanged(path, label, data, info, executable=executable)

    if (
        index_result.get("release") != receipt_record.get("release")
        or index_result.get("shared_revision")
        != receipt_record.get("shared_revision")
        or not isinstance(receipt_record.get("build_identity"), str)
        or not re.fullmatch(r"[a-f0-9]{64}", receipt_record["build_identity"])
    ):
        raise ClientReleaseBindingError("Verified client release results disagree.")
    release = str(receipt_record["release"])
    proof_build = {
        key: receipt_record[key]
        for key in PROOF_BUILD_KEYS
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "contract": CONTRACT,
        "platform": PLATFORM,
        "release": release,
        "shared_revision": str(receipt_record["shared_revision"]),
        "release_input_index": {
            "path": str(index_path),
            "sha256": index_sha256,
            "bytes": len(index_data),
        },
        "build_receipt": {
            "path": str(receipt_path),
            "sha256": receipt_sha256,
            "bytes": len(receipt_data),
        },
        "artifact": {
            "path": str(artifact_path),
            "sha256": _sha256(artifact_data),
            "bytes": len(artifact_data),
        },
        "artifact_input_fingerprint_sha256": str(
            index_result["platforms"][PLATFORM]
        ),
        "proof_build": proof_build,
        "build_identity": (
            f"{PLATFORM}:{release}:{receipt_record['build_identity']}"
        ),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify and bind an exact Linux GCP proof client executable."
    )
    parser.add_argument("--repo-root", required=True, type=pathlib.Path)
    parser.add_argument("--client-platform", required=True)
    parser.add_argument("--release-input-index", required=True, type=pathlib.Path)
    parser.add_argument("--build-receipt", required=True, type=pathlib.Path)
    parser.add_argument("--artifact", required=True, type=pathlib.Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = verify_client_release(
            args.repo_root,
            args.release_input_index,
            args.build_receipt,
            args.artifact,
            platform=args.client_platform,
        )
    except ClientReleaseBindingError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
