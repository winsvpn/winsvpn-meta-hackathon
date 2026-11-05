#!/usr/bin/env python3
"""Publish the Android APK, AAB, and private symbols as one recoverable set.

The release producers prepare every replacement beside its final destination,
then use this helper while holding the repository release lock.  A journal is
written before the first rename.  Caught failures roll back immediately, and a
later producer invocation can recover a transaction interrupted by process or
machine termination.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import sys
import uuid
import zipfile
from dataclasses import dataclass
from typing import Any, Sequence


CONTRACT = "winsvpn-android-publication-transaction-v1"
STATE_FILENAME = "android-release-publication.state.json"
PHASE_COMMITTING = "committing"
PHASE_COMMITTED = "committed"
PHASE_FINALIZING = "finalizing"
PHASE_ROLLED_BACK = "rolled_back"
PHONE_TV_ROLES = {
    "apk-symbols",
    "aab-symbols",
    "tv-apk-symbols",
    "tv-aab-symbols",
    "apk",
    "aab",
    "tv-apk",
    "tv-aab",
}
PACKAGE_ROLES = {"apk", "aab", "tv-apk", "tv-aab"}
AAB_PREFLIGHT_ROLES = ("phone", "tv", "wear")
COMPLETE_PAIR_COUNT = 8
OWNER_BLOCKED_ABSENT_PACKAGES = (
    "OWNER-BLOCKED: produced Android AAB/APK bytes are absent"
)
OWNER_BLOCKED_STORE_AUTHORITY = (
    "OWNER-BLOCKED: Android Play Store publication authority is absent"
)
ZIP_LOCAL_FILE_MAGIC = b"PK\x03\x04"
JAR_SIGNATURE_SUFFIXES = (".RSA", ".DSA", ".EC")
APK_MANIFEST_MEMBER = "AndroidManifest.xml"
AAB_MANIFEST_MEMBER = "base/manifest/AndroidManifest.xml"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
AAB_PREFLIGHT_CONTRACT = "winsvpn-android-aab-publication-preflight-v1"
EXACT_PACKAGE = "org.winsvpn.app"
EXACT_VERSION_NAME = "1.0.16"
EXACT_PHONE_VERSION_CODE = 33
EXACT_TV_VERSION_CODE = 3302
EXACT_WEAR_VERSION_CODE = 3301
DEBUG_SIGNER_MARKER = "android debug"
ROLE_PACKAGE_IDENTITY = {
    "apk": {
        "kind": "apk",
        "package": EXACT_PACKAGE,
        "version_name": EXACT_VERSION_NAME,
        "version_code": EXACT_PHONE_VERSION_CODE,
        "is_tv": False,
        "is_wear": False,
    },
    "aab": {
        "kind": "aab",
        "package": EXACT_PACKAGE,
        "version_name": EXACT_VERSION_NAME,
        "version_code": EXACT_PHONE_VERSION_CODE,
        "is_tv": False,
        "is_wear": False,
    },
    "tv-apk": {
        "kind": "apk",
        "package": EXACT_PACKAGE,
        "version_name": EXACT_VERSION_NAME,
        "version_code": EXACT_TV_VERSION_CODE,
        "is_tv": True,
        "is_wear": False,
    },
    "tv-aab": {
        "kind": "aab",
        "package": EXACT_PACKAGE,
        "version_name": EXACT_VERSION_NAME,
        "version_code": EXACT_TV_VERSION_CODE,
        "is_tv": True,
        "is_wear": False,
    },
    "wear-aab": {
        "kind": "aab",
        "package": EXACT_PACKAGE,
        "version_name": EXACT_VERSION_NAME,
        "version_code": EXACT_WEAR_VERSION_CODE,
        "is_tv": False,
        "is_wear": True,
    },
}


class PublicationError(RuntimeError):
    """Fail-closed publication error."""


def _lexical_absolute(value: str | os.PathLike[str]) -> pathlib.Path:
    return pathlib.Path(os.path.abspath(os.fspath(value)))


def _exists(path: pathlib.Path) -> bool:
    return os.path.lexists(path)


def _assert_no_symlink_ancestors(path: pathlib.Path, *, leaf_may_be_missing: bool) -> None:
    path = _lexical_absolute(path)
    anchor = pathlib.Path(path.anchor)
    if not anchor.is_dir():
        raise PublicationError(f"Path anchor is unavailable: {path.anchor}")
    cursor = anchor
    parts = path.parts[1:]
    for index, part in enumerate(parts):
        cursor /= part
        is_leaf = index == len(parts) - 1
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            if is_leaf and leaf_may_be_missing:
                return
            raise PublicationError(f"Publication path ancestor is missing: {cursor}")
        if stat.S_ISLNK(info.st_mode):
            raise PublicationError(f"Publication path traverses a symbolic link: {cursor}")


def _sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _directory_identity(path: pathlib.Path) -> dict[str, int]:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise PublicationError(f"Publication parent is not a real directory: {path}")
    return {"device": int(info.st_dev), "inode": int(info.st_ino)}


def _assert_directory_identity(
    path: pathlib.Path, expected: dict[str, int]
) -> None:
    if (
        not isinstance(expected, dict)
        or set(expected) != {"device", "inode"}
        or type(expected["device"]) is not int
        or type(expected["inode"]) is not int
    ):
        raise PublicationError("Publication parent identity is malformed")
    try:
        current = _directory_identity(path)
    except OSError as exc:
        raise PublicationError(
            f"Publication parent directory changed after preflight: {path}"
        ) from exc
    if current != expected:
        raise PublicationError(
            f"Publication parent directory changed after preflight: {path}"
        )


def _assert_produced_package_bytes(path: pathlib.Path, role: str) -> None:
    if role not in PACKAGE_ROLES and role != "wear-aab":
        return
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise PublicationError(OWNER_BLOCKED_ABSENT_PACKAGES) from exc
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
        raise PublicationError(OWNER_BLOCKED_ABSENT_PACKAGES)


def _signers_module() -> Any:
    tools_dir = str(pathlib.Path(__file__).resolve().parent)
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    import verify_android_aab_signers as signers

    return signers


def _canonical_digest(payload: dict[str, Any], label: str) -> str:
    try:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PublicationError(f"{label} is not canonical") from exc
    return hashlib.sha256(encoded).hexdigest()


def _reject_foreign_form_destination(destination: pathlib.Path) -> None:
    if any("wear" in part.casefold() for part in destination.parts):
        raise PublicationError(
            "Wear candidate identity cannot enter phone/TV publication"
        )


def _embedded_certificate_identity(
    archive: zipfile.ZipFile, names: Sequence[str], role: str
) -> str:
    upper_names = [name.upper() for name in names]
    if len(upper_names) != len(set(upper_names)):
        raise PublicationError(f"Prepared {role} contains case-colliding ZIP member names")
    blocks = [
        name
        for name in upper_names
        if name.startswith("META-INF/") and name.endswith(JAR_SIGNATURE_SUFFIXES)
    ]
    signatures = [
        name for name in upper_names if name.startswith("META-INF/") and name.endswith(".SF")
    ]
    if len(blocks) != 1 or len(signatures) != 1:
        raise PublicationError(
            f"Prepared {role} is missing an embedded JAR certificate block"
        )
    if blocks[0].rsplit(".", 1)[0] != signatures[0].rsplit(".", 1)[0]:
        raise PublicationError(
            f"Prepared {role} signature block and .SF signer names do not match"
        )
    block_name = names[upper_names.index(blocks[0])]
    block = archive.read(block_name)
    if not block:
        raise PublicationError(
            f"Prepared {role} is missing an embedded JAR certificate block"
        )
    lowered = block.lower()
    if DEBUG_SIGNER_MARKER.encode("ascii") in lowered:
        raise PublicationError(f"Prepared {role} is signed by the Android debug signer")
    signers = _signers_module()
    try:
        certificate = signers._parse_pkcs7_certificate(block)
    except signers.SignerError as exc:
        raise PublicationError(
            f"Prepared {role} does not contain a parseable signer certificate"
        ) from exc
    common_names = signers._certificate_common_names(certificate)
    if any(DEBUG_SIGNER_MARKER in name.casefold() for name in common_names):
        raise PublicationError(f"Prepared {role} is signed by the Android debug signer")
    return hashlib.sha256(certificate).hexdigest()


def _extract_android_package_identity(
    path: pathlib.Path, role: str
) -> dict[str, Any]:
    expected = ROLE_PACKAGE_IDENTITY.get(role)
    if expected is None:
        raise PublicationError(f"Unsupported Android publication package role: {role}")
    _assert_produced_package_bytes(path, role)
    with path.open("rb") as stream:
        magic = stream.read(4)
    if magic != ZIP_LOCAL_FILE_MAGIC:
        raise PublicationError(f"Prepared {role} is not an Android ZIP package: {path}")
    try:
        with zipfile.ZipFile(path) as archive:
            names = [info.filename for info in archive.infolist()]
            embedded_certificate_sha256 = _embedded_certificate_identity(
                archive, names, role
            )
            has_apk_manifest = APK_MANIFEST_MEMBER in names
            has_aab_manifest = AAB_MANIFEST_MEMBER in names
            if expected["kind"] == "aab":
                if not has_aab_manifest or has_apk_manifest:
                    raise PublicationError(
                        f"Prepared {role} package/version/build identity belongs to another exact candidate"
                    )
                manifest = archive.read(AAB_MANIFEST_MEMBER)
            else:
                if not has_apk_manifest or has_aab_manifest:
                    raise PublicationError(
                        f"Prepared {role} package/version/build identity belongs to another exact candidate"
                    )
                manifest = archive.read(APK_MANIFEST_MEMBER)
    except zipfile.BadZipFile as exc:
        raise PublicationError(f"Prepared {role} is not a readable ZIP package: {path}") from exc
    signers = _signers_module()
    try:
        if expected["kind"] == "aab":
            root = signers._decode_proto_manifest(manifest)
        else:
            root = signers._decode_axml_manifest(manifest)
        parsed = signers._manifest_identity(root)
    except signers.SignerError as exc:
        raise PublicationError(
            f"Prepared {role} package/version/build identity is unreadable: {exc}"
        ) from exc
    identity = {
        "kind": expected["kind"],
        "package": parsed.get("package"),
        "version_name": parsed.get("version_name"),
        "version_code": parsed.get("version_code"),
        "is_tv": bool(parsed.get("is_tv")),
        "is_wear": bool(parsed.get("is_wear")),
        "embedded_certificate_sha256": embedded_certificate_sha256,
    }
    if identity["is_wear"] or identity["version_code"] == EXACT_WEAR_VERSION_CODE:
        if role != "wear-aab":
            raise PublicationError(
                "Wear candidate identity cannot enter phone/TV publication"
            )
    expected_fields = {
        "kind": expected["kind"],
        "package": expected["package"],
        "version_name": expected["version_name"],
        "version_code": expected["version_code"],
        "is_tv": expected["is_tv"],
        "is_wear": expected["is_wear"],
    }
    actual_fields = {
        "kind": identity["kind"],
        "package": identity["package"],
        "version_name": identity["version_name"],
        "version_code": identity["version_code"],
        "is_tv": identity["is_tv"],
        "is_wear": identity["is_wear"],
    }
    if actual_fields != expected_fields:
        raise PublicationError(
            f"Prepared {role} package/version/build/certificate identity belongs to another exact candidate"
        )
    return identity


def _assert_android_package_candidate(
    path: pathlib.Path, role: str
) -> dict[str, Any]:
    if role not in PACKAGE_ROLES:
        raise PublicationError(f"Unsupported Android publication package role: {role}")
    return _extract_android_package_identity(path, role)


def _assert_shared_embedded_certificate(
    identities: Sequence[dict[str, Any]],
) -> str:
    certificates = {
        record["embedded_certificate_sha256"] for record in identities
    }
    if len(certificates) != 1:
        raise PublicationError(
            "Android publication packages do not share one embedded certificate identity"
        )
    digest = next(iter(certificates))
    if SHA256_RE.fullmatch(digest) is None:
        raise PublicationError(
            "Android publication embedded certificate identity is invalid"
        )
    return digest


def _pair_preflight_payload(pairs: Sequence[Pair]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "contract": CONTRACT,
        "package": EXACT_PACKAGE,
        "version_name": EXACT_VERSION_NAME,
        "pairs": [
            {
                "role": pair.role,
                "destination": str(pair.destination),
                "new_fingerprint": pair.new_fingerprint,
                "identity": pair.identity,
            }
            for pair in pairs
        ],
    }


def _aab_preflight_payload(candidates: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "contract": AAB_PREFLIGHT_CONTRACT,
        "package": EXACT_PACKAGE,
        "version_name": EXACT_VERSION_NAME,
        "candidates": {
            form: {
                "role": f"{form}-aab" if form != "phone" else "aab",
                "path": candidates[form]["path"],
                "bytes": candidates[form]["bytes"],
                "sha256": candidates[form]["sha256"],
                "identity": candidates[form]["identity"],
            }
            for form in AAB_PREFLIGHT_ROLES
        },
    }


def _re_audit_committed_pairs(pairs: Sequence[Pair]) -> None:
    for pair in pairs:
        if not _same_fingerprint(pair.destination, pair.new_fingerprint):
            raise PublicationError(
                f"Committed Android output changed during publication: {pair.destination}"
            )
        if pair.role not in PACKAGE_ROLES:
            continue
        current = _extract_android_package_identity(pair.destination, pair.role)
        if current != pair.identity:
            raise PublicationError(
                f"Post-mutation identity re-audit failed for {pair.role}: {pair.destination}"
            )


def _assert_private_symbol_evidence(path: pathlib.Path, role: str) -> None:
    if not role.endswith("-symbols"):
        return
    mapping_names = {"mapping.txt", "proguard-mapping.txt"}
    mapping_found = False
    symbols_found = False

    def visit(directory: pathlib.Path) -> None:
        nonlocal mapping_found, symbols_found
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name)
        for entry in entries:
            entry_info = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(entry_info.st_mode):
                raise PublicationError(
                    f"Publication directory contains a symbolic link: {entry.path}"
                )
            if stat.S_ISDIR(entry_info.st_mode):
                visit(pathlib.Path(entry.path))
                continue
            if not stat.S_ISREG(entry_info.st_mode) or entry_info.st_size <= 0:
                continue
            if entry.name in mapping_names:
                mapping_found = True
            if entry.name.endswith(".symbols"):
                symbols_found = True

    visit(path)
    if not mapping_found or not symbols_found:
        raise PublicationError(
            f"Prepared {role} is missing private R8 mapping or Flutter .symbols evidence: {path}"
        )


def _fingerprint(path: pathlib.Path) -> dict[str, Any]:
    _assert_no_symlink_ancestors(path, leaf_may_be_missing=False)
    info = path.lstat()
    if stat.S_ISREG(info.st_mode):
        return {
            "kind": "file",
            "bytes": info.st_size,
            "sha256": _sha256_file(path),
        }
    if not stat.S_ISDIR(info.st_mode):
        raise PublicationError(f"Publication input is not a regular file or directory: {path}")

    records: list[dict[str, Any]] = []

    def visit(directory: pathlib.Path, prefix: pathlib.PurePosixPath) -> None:
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name)
        for entry in entries:
            relative = prefix / entry.name
            entry_info = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(entry_info.st_mode):
                raise PublicationError(
                    f"Publication directory contains a symbolic link: {entry.path}"
                )
            if stat.S_ISDIR(entry_info.st_mode):
                records.append({"path": relative.as_posix(), "kind": "directory"})
                visit(pathlib.Path(entry.path), relative)
            elif stat.S_ISREG(entry_info.st_mode):
                entry_path = pathlib.Path(entry.path)
                records.append(
                    {
                        "path": relative.as_posix(),
                        "kind": "file",
                        "bytes": entry_info.st_size,
                        "sha256": _sha256_file(entry_path),
                    }
                )
            else:
                raise PublicationError(
                    f"Publication directory contains a special file: {entry.path}"
                )

    visit(path, pathlib.PurePosixPath())
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "kind": "directory",
        "entries": len(records),
        "sha256": hashlib.sha256(canonical).hexdigest(),
    }


def _fsync_directory(path: pathlib.Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _replace_and_sync(
    source: pathlib.Path,
    destination: pathlib.Path,
    parent_identity: dict[str, int],
) -> None:
    """Rename beside the destination and durably record the directory entry."""
    if source.parent != destination.parent:
        raise PublicationError("Publication rename crossed parent directories")
    parent = destination.parent
    _assert_directory_identity(parent, parent_identity)
    if os.name != "nt" and os.rename in os.supports_dir_fd:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        directory = getattr(os, "O_DIRECTORY", 0)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if directory == 0 or nofollow == 0:
            raise PublicationError(
                "Descriptor-bound Android publication requires O_DIRECTORY and O_NOFOLLOW"
            )
        descriptor = os.open(parent, flags | directory | nofollow)
        try:
            opened = os.fstat(descriptor)
            opened_identity = {
                "device": int(opened.st_dev),
                "inode": int(opened.st_ino),
            }
            if opened_identity != parent_identity:
                raise PublicationError(
                    f"Publication parent directory changed after preflight: {parent}"
                )
            os.rename(
                source.name,
                destination.name,
                src_dir_fd=descriptor,
                dst_dir_fd=descriptor,
            )
            os.fsync(descriptor)
            _assert_directory_identity(parent, parent_identity)
        finally:
            os.close(descriptor)
        return
    os.replace(source, destination)
    _assert_directory_identity(parent, parent_identity)
    _fsync_directory(parent)


def _write_state(path: pathlib.Path, value: dict[str, Any]) -> None:
    _assert_no_symlink_ancestors(path.parent, leaf_may_be_missing=False)
    if not path.parent.is_dir():
        raise PublicationError(f"Publication-state parent is not a directory: {path.parent}")
    temporary = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex}")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if _exists(temporary):
            temporary.unlink()


def _remove_state(path: pathlib.Path) -> None:
    if _exists(path):
        _assert_no_symlink_ancestors(path, leaf_may_be_missing=False)
        if not path.is_file():
            raise PublicationError(f"Publication state is not a regular file: {path}")
        path.unlink()
        _fsync_directory(path.parent)


def _remove_regular_path(path: pathlib.Path) -> None:
    if not _exists(path):
        return
    _assert_no_symlink_ancestors(path, leaf_may_be_missing=False)
    info = path.lstat()
    if stat.S_ISREG(info.st_mode):
        path.unlink()
    elif stat.S_ISDIR(info.st_mode):
        shutil.rmtree(path)
    else:
        raise PublicationError(f"Refusing to remove a special publication path: {path}")
    _fsync_directory(path.parent)


def _is_ancestor(left: pathlib.Path, right: pathlib.Path) -> bool:
    try:
        right.relative_to(left)
        return left != right
    except ValueError:
        return False


def _publication_repo(state_path: pathlib.Path) -> pathlib.Path:
    state_path = _lexical_absolute(state_path)
    if state_path.name != STATE_FILENAME or state_path.parent.name != ".artifacts":
        raise PublicationError(
            f"Publication state must be <repo>/.artifacts/{STATE_FILENAME}."
        )
    repo = state_path.parent.parent
    _assert_no_symlink_ancestors(repo, leaf_may_be_missing=False)
    if not repo.is_dir():
        raise PublicationError(f"Publication repository is unavailable: {repo}")
    return repo


def _destination_role(repo: pathlib.Path, destination: pathlib.Path) -> str:
    _reject_foreign_form_destination(destination)
    exact = {
        repo / "build/app/outputs/flutter-apk/app-release.apk": "apk",
        repo / "build/app/outputs/flutter-apk/app-tv-release.apk": "tv-apk",
        repo / "build/app/outputs/bundle/release/app-release.aab": "aab",
        repo / "build/app/outputs/bundle/tvRelease/app-tv-release.aab": "tv-aab",
    }
    if destination in exact:
        return exact[destination]
    for directory, role in (
        (repo / ".artifacts/private-release-symbols/android-apk", "apk-symbols"),
        (repo / ".artifacts/private-release-symbols/android-aab", "aab-symbols"),
        (repo / ".artifacts/private-release-symbols/android-tv-apk", "tv-apk-symbols"),
        (repo / ".artifacts/private-release-symbols/android-tv-aab", "tv-aab-symbols"),
    ):
        try:
            relative = destination.relative_to(directory)
        except ValueError:
            continue
        if len(relative.parts) == 1 and re.fullmatch(
            r"[0-9A-Za-z][0-9A-Za-z.+_-]*", relative.parts[0]
        ):
            return role
    raise PublicationError(
        f"Publication destination is not a canonical Android output: {destination}"
    )


@dataclass(frozen=True)
class Pair:
    role: str
    prepared: pathlib.Path
    destination: pathlib.Path
    backup: pathlib.Path
    destination_existed: bool
    new_fingerprint: dict[str, Any]
    old_fingerprint: dict[str, Any] | None
    identity: dict[str, Any] | None
    parent_identity: dict[str, int]

    def as_record(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "prepared": str(self.prepared),
            "destination": str(self.destination),
            "backup": str(self.backup),
            "destination_existed": self.destination_existed,
            "new_fingerprint": self.new_fingerprint,
            "old_fingerprint": self.old_fingerprint,
            "identity": self.identity,
            "parent_identity": self.parent_identity,
        }


def _prepare_pairs(
    repo: pathlib.Path,
    raw_pairs: Sequence[Sequence[str]],
    transaction_id: str,
) -> list[Pair]:
    if len(raw_pairs) != COMPLETE_PAIR_COUNT:
        raise PublicationError(
            "Android publication requires eight complete phone-plus-TV pairs."
        )
    preliminary: list[
        tuple[pathlib.Path, pathlib.Path, str, dict[str, int]]
    ] = []
    all_paths: list[pathlib.Path] = []
    seen_destinations: set[str] = set()
    roles: set[str] = set()
    for raw_prepared, raw_destination in raw_pairs:
        prepared = _lexical_absolute(raw_prepared)
        destination = _lexical_absolute(raw_destination)
        if prepared.parent != destination.parent:
            raise PublicationError(
                "Each prepared Android output must be beside its final destination for an atomic rename: "
                f"{prepared} -> {destination}"
            )
        if prepared == destination:
            raise PublicationError("Prepared and destination paths must differ.")
        if not prepared.name.startswith(".winsvpn-android-publication-prepared-"):
            raise PublicationError(
                f"Prepared Android output has an unexpected name: {prepared}"
            )
        role = _destination_role(repo, destination)
        if role in roles:
            raise PublicationError(f"Android publication repeats the {role} role.")
        roles.add(role)
        destination_key = os.path.normcase(str(destination))
        if destination_key in seen_destinations:
            raise PublicationError(f"Android publication repeats a destination: {destination}")
        seen_destinations.add(destination_key)
        if role in PACKAGE_ROLES and not _exists(prepared):
            raise PublicationError(OWNER_BLOCKED_ABSENT_PACKAGES)
        _assert_no_symlink_ancestors(prepared, leaf_may_be_missing=False)
        _assert_no_symlink_ancestors(destination.parent, leaf_may_be_missing=False)
        if not destination.parent.is_dir():
            raise PublicationError(f"Publication destination parent is unavailable: {destination.parent}")
        if _exists(destination):
            _assert_no_symlink_ancestors(destination, leaf_may_be_missing=False)
        parent_identity = _directory_identity(destination.parent)
        preliminary.append((prepared, destination, role, parent_identity))
        all_paths.extend((prepared, destination))

    for index, left in enumerate(all_paths):
        for right in all_paths[index + 1 :]:
            if left == right or _is_ancestor(left, right) or _is_ancestor(right, left):
                raise PublicationError(
                    f"Android publication paths overlap and cannot be transacted safely: {left} and {right}"
                )

    result: list[Pair] = []
    if roles != PHONE_TV_ROLES:
        raise PublicationError(
            "Android publication does not cover the complete phone and TV output role set."
        )
    symbol_versions = {
        destination.name
        for _, destination, role, _parent_identity in preliminary
        if role.endswith("-symbols")
    }
    if len(symbol_versions) != 1:
        raise PublicationError(
            "Android private-symbol destinations must use the same release version identity."
        )

    for index, (prepared, destination, role, parent_identity) in enumerate(preliminary):
        _assert_directory_identity(destination.parent, parent_identity)
        backup = destination.parent / (
            f".winsvpn-android-publication-backup-{transaction_id}-{index}"
        )
        if _exists(backup):
            raise PublicationError(f"Publication backup path already exists: {backup}")
        destination_existed = _exists(destination)
        new_fingerprint = _fingerprint(prepared)
        old_fingerprint = _fingerprint(destination) if destination_existed else None
        expected_kind = "directory" if role.endswith("-symbols") else "file"
        if new_fingerprint["kind"] != expected_kind:
            raise PublicationError(
                f"Prepared {role} output must be a {expected_kind}: {prepared}"
            )
        if old_fingerprint is not None and old_fingerprint["kind"] != expected_kind:
            raise PublicationError(
                f"Existing {role} destination is not a {expected_kind}: {destination}"
            )
        identity = None
        if expected_kind == "file":
            identity = _assert_android_package_candidate(prepared, role)
        else:
            _assert_private_symbol_evidence(prepared, role)
        result.append(
            Pair(
                role=role,
                prepared=prepared,
                destination=destination,
                backup=backup,
                destination_existed=destination_existed,
                new_fingerprint=new_fingerprint,
                old_fingerprint=old_fingerprint,
                identity=identity,
                parent_identity=parent_identity,
            )
        )
    package_identities = [pair.identity for pair in result if pair.identity is not None]
    if len(package_identities) != len(PACKAGE_ROLES):
        raise PublicationError(
            "Android publication does not cover the complete phone and TV package set."
        )
    _assert_shared_embedded_certificate(package_identities)
    for pair in result:
        _assert_directory_identity(pair.destination.parent, pair.parent_identity)
    return result


def _load_state(path: pathlib.Path) -> dict[str, Any]:
    repo = _publication_repo(path)
    _assert_no_symlink_ancestors(path, leaf_may_be_missing=False)
    if not path.is_file():
        raise PublicationError(f"Publication state is not a regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PublicationError(f"Publication state is unreadable: {error}") from error
    if not isinstance(value, dict) or value.get("contract") != CONTRACT:
        raise PublicationError("Publication state has an unexpected contract.")
    if value.get("phase") not in {
        PHASE_COMMITTING,
        PHASE_COMMITTED,
        PHASE_FINALIZING,
        PHASE_ROLLED_BACK,
    }:
        raise PublicationError("Publication state has an invalid phase.")
    records = value.get("pairs")
    if not isinstance(records, list) or len(records) != COMPLETE_PAIR_COUNT:
        raise PublicationError("Publication state does not contain the complete phone and TV pair set.")
    required = {
        "role",
        "prepared",
        "destination",
        "backup",
        "destination_existed",
        "new_fingerprint",
        "old_fingerprint",
        "identity",
        "parent_identity",
    }
    transaction_id = value.get("transaction_id")
    if not isinstance(transaction_id, str) or not re.fullmatch(r"[0-9a-f]{32}", transaction_id):
        raise PublicationError("Publication state has an invalid transaction identifier.")
    roles: set[str] = set()
    symbol_versions: set[str] = set()
    all_paths: list[pathlib.Path] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict) or set(record) != required:
            raise PublicationError("Publication state contains a malformed pair.")
        for name in ("prepared", "destination", "backup"):
            candidate = pathlib.Path(record[name])
            if not candidate.is_absolute():
                raise PublicationError("Publication state contains a relative path.")
        prepared = pathlib.Path(record["prepared"])
        destination = pathlib.Path(record["destination"])
        backup = pathlib.Path(record["backup"])
        role = _destination_role(repo, destination)
        if record["role"] != role or role in roles:
            raise PublicationError("Publication state contains a repeated or mismatched output role.")
        roles.add(role)
        if role.endswith("-symbols"):
            symbol_versions.add(destination.name)
        if prepared.parent != destination.parent or not prepared.name.startswith(
            ".winsvpn-android-publication-prepared-"
        ):
            raise PublicationError("Publication state contains an unsafe prepared path.")
        expected_backup = destination.parent / (
            f".winsvpn-android-publication-backup-{transaction_id}-{index}"
        )
        if backup != expected_backup:
            raise PublicationError("Publication state contains an unsafe backup path.")
        if not isinstance(record["destination_existed"], bool):
            raise PublicationError("Publication state contains an invalid destination flag.")
        _assert_directory_identity(destination.parent, record["parent_identity"])
        stored_identity = record["identity"]
        if role in PACKAGE_ROLES:
            expected_identity = dict(ROLE_PACKAGE_IDENTITY[role])
            if not isinstance(stored_identity, dict):
                raise PublicationError("Publication state contains a malformed package identity.")
            certificate = stored_identity.get("embedded_certificate_sha256")
            if (
                SHA256_RE.fullmatch(
                    str(certificate) if certificate is not None else ""
                )
                is None
            ):
                raise PublicationError(
                    "Publication state contains an invalid embedded certificate identity."
                )
            comparable = {
                "kind": stored_identity.get("kind"),
                "package": stored_identity.get("package"),
                "version_name": stored_identity.get("version_name"),
                "version_code": stored_identity.get("version_code"),
                "is_tv": stored_identity.get("is_tv"),
                "is_wear": stored_identity.get("is_wear"),
            }
            if comparable != expected_identity:
                raise PublicationError(
                    "Publication state mixes package/version/build identity across exact candidates."
                )
        elif stored_identity is not None:
            raise PublicationError("Publication state contains an unexpected package identity.")
        for candidate in (prepared, destination, backup):
            _assert_no_symlink_ancestors(candidate.parent, leaf_may_be_missing=False)
            all_paths.append(candidate)
    if roles != PHONE_TV_ROLES:
        raise PublicationError(
            "Publication state does not cover the complete phone and TV output role set."
        )
    if len(symbol_versions) != 1:
        raise PublicationError(
            "Publication state mixes Android private-symbol version identities."
        )
    digest = value.get("preflight_digest")
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise PublicationError("Publication state has an invalid preflight digest.")
    package_identities = [
        record["identity"]
        for record in records
        if isinstance(record, dict) and record.get("role") in PACKAGE_ROLES
    ]
    if len(package_identities) != len(PACKAGE_ROLES):
        raise PublicationError("Publication state is missing a package identity.")
    _assert_shared_embedded_certificate(package_identities)
    for index, left in enumerate(all_paths):
        for right in all_paths[index + 1 :]:
            if left == right or _is_ancestor(left, right) or _is_ancestor(right, left):
                raise PublicationError("Publication state contains overlapping paths.")
    return value


def _same_fingerprint(path: pathlib.Path, expected: dict[str, Any] | None) -> bool:
    if expected is None or not _exists(path):
        return False
    return _fingerprint(path) == expected


def _rollback_data(value: dict[str, Any]) -> None:
    errors: list[str] = []
    for record in reversed(value["pairs"]):
        prepared = pathlib.Path(record["prepared"])
        destination = pathlib.Path(record["destination"])
        backup = pathlib.Path(record["backup"])
        destination_existed = bool(record["destination_existed"])
        new_fingerprint = record["new_fingerprint"]
        old_fingerprint = record["old_fingerprint"]
        try:
            parent_identity = record["parent_identity"]
            _assert_directory_identity(destination.parent, parent_identity)
            destination_present = _exists(destination)
            prepared_present = _exists(prepared)
            backup_present = _exists(backup)

            if destination_present and _same_fingerprint(destination, new_fingerprint):
                if prepared_present:
                    raise PublicationError(
                        f"Both committed and prepared copies exist during rollback: {destination}"
                    )
                _replace_and_sync(destination, prepared, parent_identity)
                destination_present = False
                prepared_present = True

            if backup_present:
                if destination_present:
                    raise PublicationError(
                        f"Destination changed while its rollback backup exists: {destination}"
                    )
                if not _same_fingerprint(backup, old_fingerprint):
                    raise PublicationError(f"Rollback backup changed: {backup}")
                _replace_and_sync(backup, destination, parent_identity)
                destination_present = True

            if destination_existed:
                if not destination_present or not _same_fingerprint(destination, old_fingerprint):
                    raise PublicationError(f"Prior Android output was not restored: {destination}")
            elif destination_present:
                raise PublicationError(f"Rollback left a new destination behind: {destination}")

            if not prepared_present or not _same_fingerprint(prepared, new_fingerprint):
                raise PublicationError(f"Prepared Android output was not recovered: {prepared}")
        except Exception as error:  # keep attempting all restorations
            errors.append(str(error))
    if errors:
        raise PublicationError("Android publication rollback failed: " + " | ".join(errors))


def _complete_rollback(state_path: pathlib.Path, value: dict[str, Any]) -> None:
    if value["phase"] != PHASE_ROLLED_BACK:
        _rollback_data(value)
        value["phase"] = PHASE_ROLLED_BACK
        _write_state(state_path, value)
    for record in value["pairs"]:
        prepared = pathlib.Path(record["prepared"])
        _assert_directory_identity(prepared.parent, record["parent_identity"])
        _remove_regular_path(prepared)
    _remove_state(state_path)


class _MutationInjector:
    def __init__(self, fail_after: int | None, abort_after: int | None) -> None:
        self.fail_after = fail_after
        self.abort_after = abort_after
        self.count = 0

    def completed(self) -> None:
        self.count += 1
        if self.abort_after is not None and self.count == self.abort_after:
            # Test-only process termination exercises journal recovery without
            # allowing the caught-error rollback path to run.
            os._exit(86)
        if self.fail_after is not None and self.count == self.fail_after:
            raise PublicationError(
                f"Injected Android publication failure after mutation {self.count}."
            )


def preflight_aab_publication(
    phone_aab: pathlib.Path,
    tv_aab: pathlib.Path,
    wear_aab: pathlib.Path,
    owner_authorization: str | None,
) -> dict[str, Any]:
    paths = {
        "phone": _lexical_absolute(phone_aab),
        "tv": _lexical_absolute(tv_aab),
        "wear": _lexical_absolute(wear_aab),
    }
    if len({os.path.normcase(str(path)) for path in paths.values()}) != 3:
        raise PublicationError("Phone, TV, and Wear AAB candidates must be distinct paths.")
    roles = {"phone": "aab", "tv": "tv-aab", "wear": "wear-aab"}
    candidates: dict[str, dict[str, Any]] = {}
    for form in AAB_PREFLIGHT_ROLES:
        path = paths[form]
        _assert_no_symlink_ancestors(path, leaf_may_be_missing=False)
        identity = _extract_android_package_identity(path, roles[form])
        fingerprint = _fingerprint(path)
        if fingerprint["kind"] != "file":
            raise PublicationError(f"Prepared {form} AAB output must be a file: {path}")
        candidates[form] = {
            "path": str(path),
            "bytes": fingerprint["bytes"],
            "sha256": fingerprint["sha256"],
            "identity": identity,
        }
    _assert_shared_embedded_certificate(
        [candidates[form]["identity"] for form in AAB_PREFLIGHT_ROLES]
    )
    digest = _canonical_digest(
        _aab_preflight_payload(candidates),
        "Android AAB publication preflight",
    )
    del digest, owner_authorization
    # Local candidate inspection cannot mint signature/store authority. The final
    # collector's authenticated form-factor receipts and external Play owner
    # authority remain mandatory and are deliberately outside this helper.
    raise PublicationError(OWNER_BLOCKED_STORE_AUTHORITY)


def commit(
    state_path: pathlib.Path,
    raw_pairs: Sequence[Sequence[str]],
    fail_after: int | None,
    abort_after: int | None,
) -> str:
    state_path = _lexical_absolute(state_path)
    repo = _publication_repo(state_path)
    _assert_no_symlink_ancestors(state_path.parent, leaf_may_be_missing=False)
    if _exists(state_path):
        raise PublicationError(
            f"An unfinished Android publication transaction already exists: {state_path}. Recover it first."
        )
    if fail_after is not None and fail_after < 1:
        raise PublicationError("Test failure injection must be a positive mutation number.")
    if abort_after is not None and abort_after < 1:
        raise PublicationError("Test abort injection must be a positive mutation number.")
    if fail_after is not None and abort_after is not None:
        raise PublicationError("Use only one publication test-injection mode at a time.")
    transaction_id = uuid.uuid4().hex
    pairs = _prepare_pairs(repo, raw_pairs, transaction_id)
    preflight_digest = _canonical_digest(
        _pair_preflight_payload(pairs),
        "Android publication transaction preflight",
    )
    value: dict[str, Any] = {
        "contract": CONTRACT,
        "phase": PHASE_COMMITTING,
        "transaction_id": transaction_id,
        "preflight_digest": preflight_digest,
        "pairs": [pair.as_record() for pair in pairs],
    }
    _write_state(state_path, value)
    injector = _MutationInjector(fail_after, abort_after)
    try:
        for pair in pairs:
            _assert_directory_identity(pair.destination.parent, pair.parent_identity)
            if pair.destination_existed:
                _replace_and_sync(
                    pair.destination, pair.backup, pair.parent_identity
                )
                injector.completed()
            _replace_and_sync(pair.prepared, pair.destination, pair.parent_identity)
            injector.completed()
        _re_audit_committed_pairs(pairs)
        value["phase"] = PHASE_COMMITTED
        _write_state(state_path, value)
    except BaseException as publication_error:
        try:
            _complete_rollback(state_path, value)
        except Exception as rollback_error:
            raise PublicationError(
                f"Android publication failed ({publication_error}) and automatic rollback also failed "
                f"({rollback_error}). Preserve {state_path} for recovery."
            ) from publication_error
        raise PublicationError(
            f"Android publication failed and the prior complete set was restored: {publication_error}"
        ) from publication_error
    return "committed"


def rollback(state_path: pathlib.Path) -> None:
    state_path = _lexical_absolute(state_path)
    value = _load_state(state_path)
    if value["phase"] == PHASE_FINALIZING:
        raise PublicationError(
            "The publication transaction is already finalizing; use recover to complete it."
        )
    _complete_rollback(state_path, value)


def finalize(state_path: pathlib.Path) -> None:
    state_path = _lexical_absolute(state_path)
    value = _load_state(state_path)
    if value["phase"] not in {PHASE_COMMITTED, PHASE_FINALIZING}:
        raise PublicationError("Only a fully committed Android publication can be finalized.")

    for record in value["pairs"]:
        prepared = pathlib.Path(record["prepared"])
        destination = pathlib.Path(record["destination"])
        backup = pathlib.Path(record["backup"])
        _assert_directory_identity(destination.parent, record["parent_identity"])
        if _exists(prepared):
            raise PublicationError(f"Committed publication still has a prepared path: {prepared}")
        if not _same_fingerprint(destination, record["new_fingerprint"]):
            raise PublicationError(f"Committed Android output changed before finalization: {destination}")
        if record["role"] in PACKAGE_ROLES:
            current = _extract_android_package_identity(
                destination, str(record["role"])
            )
            if current != record["identity"]:
                raise PublicationError(
                    f"Post-mutation identity re-audit failed for {record['role']}: {destination}"
                )
        if value["phase"] == PHASE_COMMITTED and bool(record["destination_existed"]):
            if not _same_fingerprint(backup, record["old_fingerprint"]):
                raise PublicationError(f"Publication rollback backup changed before finalization: {backup}")

    if value["phase"] != PHASE_FINALIZING:
        value["phase"] = PHASE_FINALIZING
        _write_state(state_path, value)
    for record in value["pairs"]:
        _remove_regular_path(pathlib.Path(record["backup"]))
    _remove_state(state_path)


def recover(state_path: pathlib.Path) -> str:
    state_path = _lexical_absolute(state_path)
    _publication_repo(state_path)
    if not _exists(state_path):
        return "none"
    value = _load_state(state_path)
    if value["phase"] == PHASE_FINALIZING:
        finalize(state_path)
        return "finalized"
    _complete_rollback(state_path, value)
    return "rolled_back"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    commit_parser = subparsers.add_parser("commit")
    commit_parser.add_argument("--state", required=True, type=pathlib.Path)
    commit_parser.add_argument(
        "--pair",
        nargs=2,
        metavar=("PREPARED", "DESTINATION"),
        action="append",
        required=True,
    )
    commit_parser.add_argument(
        "--test-fail-after",
        type=int,
        help=argparse.SUPPRESS,
    )
    commit_parser.add_argument(
        "--test-abort-after",
        type=int,
        help=argparse.SUPPRESS,
    )
    preflight_parser = subparsers.add_parser("preflight")
    preflight_parser.add_argument("--phone-aab", required=True, type=pathlib.Path)
    preflight_parser.add_argument("--tv-aab", required=True, type=pathlib.Path)
    preflight_parser.add_argument("--wear-aab", required=True, type=pathlib.Path)
    preflight_parser.add_argument("--confirm-owner-authorization")

    for name in ("rollback", "finalize", "recover"):
        command = subparsers.add_parser(name)
        command.add_argument("--state", required=True, type=pathlib.Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "preflight":
            payload = preflight_aab_publication(
                arguments.phone_aab,
                arguments.tv_aab,
                arguments.wear_aab,
                arguments.confirm_owner_authorization,
            )
            print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
            return 0
        if arguments.command == "commit":
            result = commit(
                arguments.state,
                arguments.pair,
                arguments.test_fail_after,
                arguments.test_abort_after,
            )
        elif arguments.command == "rollback":
            rollback(arguments.state)
            result = "rolled_back"
        elif arguments.command == "finalize":
            finalize(arguments.state)
            result = "finalized"
        else:
            result = recover(arguments.state)
    except PublicationError as error:
        print(f"ANDROID RELEASE PUBLICATION: FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"contract": CONTRACT, "ok": True, "result": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
