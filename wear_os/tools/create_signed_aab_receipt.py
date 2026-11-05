#!/usr/bin/env python3
"""Create the permission-frozen Wear signed-AAB receipt.

This writer binds current producer bytes, source freeze, dependency freeze,
AAB signer/package/version, R8 mapping, and schema-v2 private-symbol custody
into WEAR_OS_SIGNED_AAB_RECEIPT.json. It never downloads bundletool, never
builds or signs an AAB, and never uploads to Play. Self-authored freeze or
receipt material cannot authorize a production PASS.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any


CONTRACT = "winsvpn-wear-os-signed-aab-receipt-v2"
SCHEMA_VERSION = 2
RECEIPT_NAME = "WEAR_OS_SIGNED_AAB_RECEIPT.json"
SIDECAR_NAME = "WEAR_OS_SIGNED_AAB_RECEIPT.json.sha256"
SYMBOL_CONTRACT = "winsvpn-wear-os-private-symbol-custody-v2"
DEFAULT_REPO = Path(__file__).resolve().parents[2]
PRODUCER_PATHS = (
    "wear_os/tools/prepare_release.sh",
    "wear_os/tools/assert_release_aab.py",
    "wear_os/tools/signed_aab_receipt.py",
    "wear_os/tools/create_signed_aab_receipt.py",
    "wear_os/tools/external_tool_pins.json",
)
OWNER_BLOCKED_FREEZE = (
    "OWNER-BLOCKED: current reviewed source-freeze issuance identity is unavailable"
)
SELF_AUTH_RECEIPT = "self-authored Wear freeze or receipt cannot authorize production PASS"


class ReceiptError(RuntimeError):
    pass


def _load_py(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ReceiptError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _legacy():
    return _load_py(
        Path(__file__).resolve().with_name("signed_aab_receipt.py"),
        "wear_signed_aab_receipt_legacy",
    )


def _tools_dir(repo: Path) -> Path:
    return repo / "tools"


def _import_tools(repo: Path, name: str):
    path = _tools_dir(repo) / f"{name}.py"
    return _load_py(path, name)


def _producer_bytes(repo: Path, legacy: Any) -> dict[str, Any]:
    files: dict[str, Any] = {}
    for relative in PRODUCER_PATHS:
        evidence = legacy._stable_file_evidence(repo / relative, f"Wear producer {relative}")
        files[relative] = {
            "path": relative,
            "size_bytes": evidence["size_bytes"],
            "sha256": evidence["sha256"],
        }
    return files


def _bind_source_freeze(repo: Path) -> dict[str, Any]:
    freeze = _import_tools(repo, "release_source_freeze")
    try:
        issuance = freeze._bind_external_issuance(repo)
        state = freeze.verified_release_source_state(repo)
        record = freeze._json_record(state)
    except freeze.SourceFreezeError as error:
        raise ReceiptError(f"{OWNER_BLOCKED_FREEZE}: {error}") from error
    issuance_path = Path(str(issuance.path))
    try:
        issuance_path.relative_to(repo / ".artifacts")
        raise ReceiptError(SELF_AUTH_RECEIPT)
    except ValueError:
        pass
    if issuance_path.name == RECEIPT_NAME:
        raise ReceiptError(SELF_AUTH_RECEIPT)
    return {
        "lock_path": record["lock_path"],
        "source_fingerprint_sha256": record["source_fingerprint_sha256"],
        "app_source_fingerprint_sha256": record["app_source_fingerprint_sha256"],
        "source_file_count": record["source_file_count"],
        "issuance_id": issuance.issuance_id,
        "issuance_sha256": issuance.digest,
        "issuance_path": str(issuance.path),
        "authenticated": True,
    }


def _bind_dependency_freeze(repo: Path, release_input_index: Path) -> dict[str, Any]:
    freeze = _import_tools(repo, "release_dependency_freeze")
    try:
        verified = freeze.verify_release_index(repo, release_input_index, "wear_os")
        index_path = freeze.secure_repo_path(
            repo, release_input_index, "Release input index", must_exist=True
        )
        owners = freeze._allowed_owners(repo)
        _record, digest = freeze._read_json_file(
            index_path, owners, "Release input index", repo=repo
        )
    except freeze.DependencyFreezeError as error:
        raise ReceiptError(f"OWNER-BLOCKED: Wear dependency freeze is unavailable: {error}") from error
    relative = index_path.relative_to(repo).as_posix()
    if relative.endswith("/" + RECEIPT_NAME) or relative.endswith(RECEIPT_NAME):
        raise ReceiptError(SELF_AUTH_RECEIPT)
    platforms = verified.get("platforms")
    wear_fingerprint = platforms.get("wear_os") if isinstance(platforms, dict) else None
    if not isinstance(wear_fingerprint, str) or not wear_fingerprint:
        raise ReceiptError("OWNER-BLOCKED: Wear dependency freeze does not bind wear_os")
    return {
        "index_path": relative,
        "index_sha256": digest,
        "release": verified.get("release"),
        "platform": "wear_os",
        "wear_os_artifact_input_fingerprint_sha256": wear_fingerprint,
        "authenticated": True,
    }


def _reject_self_authorized(source_freeze: dict[str, Any], receipt_dir: Path) -> None:
    issuance_path = Path(str(source_freeze.get("issuance_path") or ""))
    if not issuance_path.is_absolute():
        raise ReceiptError(SELF_AUTH_RECEIPT)
    try:
        issuance_path.resolve(strict=True).relative_to(receipt_dir.resolve())
        raise ReceiptError(SELF_AUTH_RECEIPT)
    except ValueError:
        pass
    except OSError as error:
        raise ReceiptError(SELF_AUTH_RECEIPT) from error
    if source_freeze.get("authenticated") is not True:
        raise ReceiptError(OWNER_BLOCKED_FREEZE)
    if source_freeze.get("issuance_id") in {None, "", "0" * 32}:
        raise ReceiptError(SELF_AUTH_RECEIPT)


def _schema_v2_symbol_custody(
    mapping: Path,
    binding: dict[str, Any],
    external_gates: dict[str, Any],
    artifact_sha256: str,
) -> dict[str, Any]:
    if mapping.is_symlink() or not mapping.is_file():
        raise ReceiptError("missing Wear R8 mapping symbol")
    private = external_gates.get("private_symbol_custody")
    if not isinstance(private, dict) or private.get("passed") is not True:
        raise ReceiptError("schema-v2 private-symbol custody is missing")
    return {
        "schema_version": 2,
        "contract": SYMBOL_CONTRACT,
        "passed": True,
        "mapping_sha256": binding["external_sha256"],
        "embedded_sha256": binding["embedded_sha256"],
        "artifact_sha256": artifact_sha256,
        "manifest_sha256": private["manifest_sha256"],
        "sidecar_sha256": private["sidecar_sha256"],
    }


def record(
    repo: Path,
    aab: Path,
    mapping: Path,
    receipt_dir: Path,
    release_input_index: Path,
) -> dict[str, Any]:
    legacy = _legacy()
    repo = repo.resolve(strict=True)
    aab = aab.expanduser()
    mapping = mapping.expanduser()
    if aab.suffix.lower() != ".aab":
        raise ReceiptError(f"Wear release artifact must be a .aab: {aab}")
    if mapping.is_symlink() or not mapping.is_file():
        raise ReceiptError("missing Wear R8 mapping symbol")
    if receipt_dir.exists() or receipt_dir.is_symlink():
        raise ReceiptError(f"Wear receipt directory must be a new path: {receipt_dir}")
    pins = legacy._require_pin_alignment(repo)
    if pins.get("canonical_release") != legacy.CANONICAL_RELEASE:
        raise ReceiptError("Wear release stamp is not the canonical 1.0.16+33 identity.")
    expected_certificate = legacy._reviewed_upload_certificate_sha256(repo)
    source_freeze = _bind_source_freeze(repo)
    dependency_freeze = _bind_dependency_freeze(repo, release_input_index)
    producer = _producer_bytes(repo, legacy)
    store_metadata = legacy._reviewed_store_metadata(repo)
    _reject_self_authorized(source_freeze, receipt_dir)
    _held, held_identity, held_digest = legacy._hold_aab_bytes(aab)
    with legacy._private_input_snapshots(aab, mapping) as (staged_aab, staged_mapping):
        mapping_binding = legacy._bind_staged_r8_mapping(repo, staged_aab, staged_mapping)
        legacy._verify_aab_page_alignment(repo, staged_aab)
        inspected = legacy._assert_wear_signed_aab(repo, staged_aab)
        certificate_sha256, _subject = legacy._certificate(staged_aab)
        if certificate_sha256 != expected_certificate:
            raise ReceiptError("Wear AAB signer does not match the reviewed Android upload certificate")
        external_gates = legacy._verify_release_gates(repo, staged_aab, mapping.parent)
        artifact_evidence = {
            "name": aab.name,
            "size_bytes": staged_aab.stat().st_size,
            "sha256": legacy._sha256_file(staged_aab),
        }
        if artifact_evidence["sha256"] != held_digest:
            raise ReceiptError("Wear AAB current bytes changed during inspection")
        legacy._reject_receipt_reuse(repo, str(artifact_evidence["sha256"]))
        symbol_custody = _schema_v2_symbol_custody(
            mapping, mapping_binding, external_gates, str(artifact_evidence["sha256"])
        )
        decoder = inspected.get("manifest_decoder")
        manifest = inspected.get("manifest")
        if not isinstance(decoder, dict) or not isinstance(manifest, dict):
            raise ReceiptError("Wear inspector did not return structured gate evidence")
        payload = {
            "schema_version": SCHEMA_VERSION,
            "contract": CONTRACT,
            "canonical_release": legacy.CANONICAL_RELEASE,
            "platform": "wear-os",
            "play_track": "wear-os",
            "publication_authorized": False,
            "upload_performed": False,
            "application_id": pins["application_id"],
            "version_name": pins["version_name"],
            "version_code": pins["version_code"],
            "standalone": pins["standalone"],
            "artifact": artifact_evidence,
            "signing": legacy._signing_claims(pins, certificate_sha256, expected_certificate),
            "store_metadata": store_metadata,
            "custody": legacy._custody_claims(mapping, mapping_binding),
            "producer": producer,
            "source_freeze": source_freeze,
            "dependency_freeze": dependency_freeze,
            "private_symbol_custody": symbol_custody,
            "provenance": {
                "gradle": pins["gradle"],
                "agp": pins["agp"],
                "kotlin": pins["kotlin"],
                "files": legacy._provenance(repo),
                "producer": producer,
            },
            "gates": {
                **legacy._gate_claims(
                    inspected, expected_certificate, external_gates, mapping_binding
                ),
                "private_symbol_custody_v2": symbol_custody,
                "source_freeze": {"passed": True, "issuance_id": source_freeze["issuance_id"]},
                "dependency_freeze": {
                    "passed": True,
                    "index_sha256": dependency_freeze["index_sha256"],
                },
            },
            "receipt_storage": {
                "protection": "permission-frozen",
                "os_immutability_claimed": False,
                "external_append_only_store_claimed": False,
            },
        }
    legacy._revalidate_held_aab(aab, held_identity, held_digest)
    receipt_dir.mkdir(mode=0o700, parents=False)
    serialized = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    legacy._write_permission_frozen(receipt_dir / RECEIPT_NAME, serialized)
    sidecar = f"{hashlib.sha256(serialized).hexdigest()}  {RECEIPT_NAME}\n".encode("ascii")
    legacy._write_permission_frozen(receipt_dir / SIDECAR_NAME, sidecar)
    os.chmod(receipt_dir, 0o555)
    if legacy._writable(receipt_dir):
        raise ReceiptError("failed to permission-freeze Wear receipt directory")
    return {
        "ok": True,
        "contract": CONTRACT,
        "receipt": str(receipt_dir / RECEIPT_NAME),
        "artifact_sha256": payload["artifact"]["sha256"],
        "certificate_sha256": certificate_sha256,
        "receipt_protection": "permission-frozen",
        "publication_authorized": False,
        "upload_performed": False,
    }


def verify(
    repo: Path,
    aab: Path,
    mapping: Path,
    receipt_dir: Path,
    release_input_index: Path,
) -> dict[str, Any]:
    legacy = _legacy()
    repo = repo.resolve(strict=True)
    aab = aab.expanduser()
    mapping = mapping.expanduser()
    if mapping.is_symlink() or not mapping.is_file():
        raise ReceiptError("missing Wear R8 mapping symbol")
    payload = legacy._load_receipt(receipt_dir.expanduser())
    if payload.get("contract") != CONTRACT or payload.get("schema_version") != SCHEMA_VERSION:
        raise ReceiptError("Wear receipt contract is unsupported")
    if payload.get("canonical_release") != legacy.CANONICAL_RELEASE:
        raise ReceiptError("Wear receipt is not bound to the canonical 1.0.16+33 identity.")
    if payload.get("platform") != "wear-os" or payload.get("play_track") != "wear-os":
        raise ReceiptError("Wear receipt is not bound to the Wear OS Play track")
    if payload.get("publication_authorized") is not False:
        raise ReceiptError("Wear receipt must not authorize Play publication")
    if payload.get("upload_performed") is not False:
        raise ReceiptError("Wear receipt claims an upload; this gate never uploads")
    source_freeze = payload.get("source_freeze")
    dependency_freeze = payload.get("dependency_freeze")
    producer = payload.get("producer")
    if not isinstance(source_freeze, dict) or not isinstance(dependency_freeze, dict):
        raise ReceiptError(OWNER_BLOCKED_FREEZE)
    if not isinstance(producer, dict):
        raise ReceiptError("Wear receipt is missing current producer bytes")
    _reject_self_authorized(source_freeze, receipt_dir.expanduser())
    if source_freeze != _bind_source_freeze(repo):
        raise ReceiptError("Wear source freeze changed after receipt creation")
    if dependency_freeze != _bind_dependency_freeze(repo, release_input_index):
        raise ReceiptError("Wear dependency freeze changed after receipt creation")
    if producer != _producer_bytes(repo, legacy):
        raise ReceiptError("Wear producer bytes changed after receipt creation")
    pins = legacy._require_pin_alignment(repo)
    for key in ("application_id", "version_name", "version_code", "standalone"):
        if payload.get(key) != pins[key]:
            raise ReceiptError(f"Wear receipt {key} does not match current source")
    signing = payload.get("signing")
    if not isinstance(signing, dict):
        raise ReceiptError("Wear receipt signing block is missing")
    store_metadata = payload.get("store_metadata")
    if store_metadata != legacy._reviewed_store_metadata(repo):
        raise ReceiptError("Wear store metadata changed after receipt creation")
    expected_certificate = legacy._reviewed_upload_certificate_sha256(repo)
    _held, held_identity, held_digest = legacy._hold_aab_bytes(aab)
    with legacy._private_input_snapshots(aab, mapping) as (staged_aab, staged_mapping):
        artifact = payload.get("artifact")
        if not isinstance(artifact, dict):
            raise ReceiptError("Wear receipt artifact block is missing")
        if artifact != {
            "name": aab.name,
            "size_bytes": staged_aab.stat().st_size,
            "sha256": legacy._sha256_file(staged_aab),
        }:
            raise ReceiptError("Wear AAB no longer matches its permission-frozen receipt")
        if artifact["sha256"] != held_digest:
            raise ReceiptError("Wear AAB current bytes changed during inspection")
        mapping_binding = legacy._bind_staged_r8_mapping(repo, staged_aab, staged_mapping)
        if payload.get("custody") != legacy._custody_claims(mapping, mapping_binding):
            raise ReceiptError("Wear R8 mapping no longer matches its permission-frozen receipt")
        legacy._verify_aab_page_alignment(repo, staged_aab)
        inspected = legacy._assert_wear_signed_aab(repo, staged_aab)
        certificate_sha256, _subject = legacy._certificate(staged_aab)
        if certificate_sha256 != expected_certificate:
            raise ReceiptError("Wear AAB signer does not match the reviewed Android upload certificate")
        if signing != legacy._signing_claims(pins, certificate_sha256, expected_certificate):
            raise ReceiptError("Wear AAB signing evidence does not match the reviewed identity")
        external_gates = legacy._verify_release_gates(repo, staged_aab, mapping.parent)
        symbol_custody = _schema_v2_symbol_custody(
            mapping, mapping_binding, external_gates, str(artifact["sha256"])
        )
        if payload.get("private_symbol_custody") != symbol_custody:
            raise ReceiptError("Wear schema-v2 private-symbol custody changed after receipt creation")
        expected_gates = legacy._gate_claims(
            inspected, expected_certificate, external_gates, mapping_binding
        )
        expected_gates = {
            **expected_gates,
            "private_symbol_custody_v2": symbol_custody,
            "source_freeze": {"passed": True, "issuance_id": source_freeze["issuance_id"]},
            "dependency_freeze": {
                "passed": True,
                "index_sha256": dependency_freeze["index_sha256"],
            },
        }
        if payload.get("gates") != expected_gates:
            raise ReceiptError("Wear release gate evidence changed after receipt creation")
        legacy._reject_receipt_reuse(
            repo, str(artifact["sha256"]), ignore_dir=receipt_dir.expanduser()
        )
    legacy._revalidate_held_aab(aab, held_identity, held_digest)
    provenance = payload.get("provenance")
    if not isinstance(provenance, dict):
        raise ReceiptError("Wear receipt is missing provenance")
    for key in ("gradle", "agp", "kotlin"):
        if provenance.get(key) != pins[key]:
            raise ReceiptError(f"Wear receipt toolchain {key} drifted from current pins")
    if provenance.get("files") != legacy._provenance(repo):
        raise ReceiptError("Wear source or gate-tool provenance changed after receipt creation")
    if provenance.get("producer") != producer:
        raise ReceiptError("Wear producer provenance changed after receipt creation")
    return {
        "ok": True,
        "contract": CONTRACT,
        "receipt": str(receipt_dir / RECEIPT_NAME),
        "artifact_sha256": payload["artifact"]["sha256"],
        "certificate_sha256": expected_certificate,
        "receipt_protection": "permission-frozen",
        "publication_authorized": False,
        "upload_performed": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=DEFAULT_REPO)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("record", "verify"):
        command = subparsers.add_parser(name)
        command.add_argument("--aab", type=Path, required=True)
        command.add_argument("--mapping", type=Path, required=True)
        command.add_argument("--receipt-dir", type=Path, required=True)
        command.add_argument("--release-input-index", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "record":
            result = record(
                args.repo, args.aab, args.mapping, args.receipt_dir, args.release_input_index
            )
        else:
            result = verify(
                args.repo, args.aab, args.mapping, args.receipt_dir, args.release_input_index
            )
    except ReceiptError as error:
        print(f"WEAR OS SIGNED AAB RECEIPT: FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
