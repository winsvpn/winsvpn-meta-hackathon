#!/usr/bin/env python3
"""Focused regressions for website download custody publication rules."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import inspect
import io
import json
import os
import stat
import struct
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "website_download_custody.py"
SPEC = importlib.util.spec_from_file_location("website_download_custody", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CUSTODY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CUSTODY
SPEC.loader.exec_module(CUSTODY)

NOW = datetime(2026, 8, 24, 15, 0, 0, tzinfo=timezone.utc)
LINUX_BYTES = b"not-a-signed-release-just-plaintext\n"
LINUX_NAME = "wins-vpn-linux-x64.tar.gz"
ISSUANCE_ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
LINUX_NONCE = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
ANDROID_NONCE = "cccccccccccccccccccccccccccccccc"
CHALLENGE_NONCE = "dddddddddddddddddddddddddddddddd"
SIGNER = "c" * 64
LINUX_ENTRY = "linux-x64"
ENTRY_INDEX = {
    entry_id: index for index, (entry_id, _label, _kind) in enumerate(CUSTODY.PLATFORM_CONTRACT)
}
LINUX_INDEX = ENTRY_INDEX[LINUX_ENTRY]
OWNER_RULING = {
    "record": "owner_rulings_release_targets_20261021.md",
    "record_sha256": "1" * 64,
    "lines": [
        '- Website downloads: "Publish now": publish the verified desktop downloads.',
        '- Windows: "Ship unsigned". Windows x64 and ARM64 installers ship unsigned.',
    ],
}


def use_fresh_release_ledger(testcase: unittest.TestCase) -> Path:
    """Point the durable release ledger at a private per-test directory."""
    holder = tempfile.TemporaryDirectory()
    testcase.addCleanup(holder.cleanup)
    ledger = Path(holder.name) / "ledger" / "download-custody-consumed.jsonl"
    previous = os.environ.get(CUSTODY.RELEASE_LEDGER_ENV)
    os.environ[CUSTODY.RELEASE_LEDGER_ENV] = str(ledger)

    def restore() -> None:
        if previous is None:
            os.environ.pop(CUSTODY.RELEASE_LEDGER_ENV, None)
        else:
            os.environ[CUSTODY.RELEASE_LEDGER_ENV] = previous

    testcase.addCleanup(restore)
    return ledger


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pending_manifest() -> dict[str, Any]:
    return {
        "schema": CUSTODY.MANIFEST_SCHEMA,
        "release_id": CUSTODY.CANONICAL_WEBSITE_RELEASE_ID,
        "artifacts": [
            {
                "id": platform_id,
                "label": label,
                "status": (
                    CUSTODY.STORE_PENDING_STATUS if kind == "store" else CUSTODY.PENDING_STATUS
                ),
                "delivery": {"kind": kind, "url": None},
                "artifact": {"filename": None, "sha256": None, "bytes": None},
            }
            for platform_id, label, kind in CUSTODY.PLATFORM_CONTRACT
        ],
    }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(CUSTODY.canonical_json(payload) + b"\n")


def seed_pending(root: Path) -> Path:
    web = root / "web"
    write_json(web / "releases" / "downloads.json", pending_manifest())
    write_json(web / "releases" / "download-custody.json", CUSTODY.pending_custody_document())
    return web


def write_challenge(
    root: Path,
    *,
    nonce: str = CHALLENGE_NONCE,
    issued_utc: str = "2026-08-24T15:00:00Z",
) -> dict[str, Any]:
    challenge = {
        "schema": CUSTODY.CHALLENGE_SCHEMA,
        "nonce": nonce,
        "issued_utc": issued_utc,
        "canonical_release": CUSTODY.CANONICAL_RELEASE,
        "package_identity": CUSTODY.PUBLIC_PACKAGE_IDENTITY,
    }
    write_json(root / "web" / "releases" / CUSTODY.CHALLENGE_RELATIVE.name, challenge)
    return challenge


def linux_owner_platform(
    *,
    digest: str,
    byte_count: int,
    nonce: str = LINUX_NONCE,
    signer: str = SIGNER,
) -> dict[str, Any]:
    return {
        "id": LINUX_ENTRY,
        "target": "linux",
        "version": CUSTODY.CANONICAL_VERSION,
        "architecture": ["x64"],
        "artifact_filename": LINUX_NAME,
        "artifact_sha256": digest,
        "artifact_bytes": byte_count,
        "signature_kind": CUSTODY.SIGNATURE_KINDS["linux"],
        "signature_sha256": signer,
        "nonce": nonce,
        "receipt_filename": f"{LINUX_NAME}.publication.json",
    }


def owner_evidence_document(
    platforms: list[dict[str, Any]],
    *,
    issued_utc: str,
    issuance_id: str = ISSUANCE_ID,
    challenge_nonce: str = CHALLENGE_NONCE,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": CUSTODY.OWNER_EVIDENCE_SCHEMA,
        "issued_utc": issued_utc,
        "issuance_id": issuance_id,
        "canonical_release": CUSTODY.CANONICAL_RELEASE,
        "package_identity": CUSTODY.PUBLIC_PACKAGE_IDENTITY,
        "challenge_nonce": challenge_nonce,
        "owner_ruling": json.loads(json.dumps(OWNER_RULING)),
        "platforms": platforms,
    }
    if extra:
        payload.update(extra)
    return payload


def publication_receipt(
    *,
    digest: str,
    byte_count: int,
    owner_sha256: str,
    issued_utc: str,
    nonce: str = LINUX_NONCE,
    signer: str = SIGNER,
) -> dict[str, Any]:
    return {
        "schema": CUSTODY.PUBLICATION_RECEIPT_SCHEMA,
        "kind": CUSTODY.PUBLICATION_RECEIPT_KIND,
        "issuance_id": ISSUANCE_ID,
        "issued_utc": issued_utc,
        "nonce": nonce,
        "canonical_release": CUSTODY.CANONICAL_RELEASE,
        "package_identity": CUSTODY.PUBLIC_PACKAGE_IDENTITY,
        "platform_id": LINUX_ENTRY,
        "target": "linux",
        "version": CUSTODY.CANONICAL_VERSION,
        "architecture": ["x64"],
        "artifact_filename": LINUX_NAME,
        "artifact_sha256": digest,
        "artifact_bytes": byte_count,
        "signature_kind": CUSTODY.SIGNATURE_KINDS["linux"],
        "signature_sha256": signer,
        "challenge_nonce": CHALLENGE_NONCE,
        "owner_evidence_sha256": owner_sha256,
    }


def hosted_identity_receipt(
    *,
    kind: str,
    schema: str,
    digest: str,
    byte_count: int,
    filename: str = LINUX_NAME,
    platform_id: str = LINUX_ENTRY,
    architecture: list[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": schema,
        "kind": kind,
        "canonical_release": CUSTODY.CANONICAL_RELEASE,
        "platform_id": platform_id,
        "artifact_filename": filename,
        "artifact_sha256": digest,
        "artifact_bytes": byte_count,
        "package_identity": CUSTODY.PUBLIC_PACKAGE_IDENTITY,
        "architecture": architecture or ["x64"],
        "version": CUSTODY.CANONICAL_VERSION,
    }
    payload.update(receipt_evidence(kind, platform_id, filename))
    if extra:
        payload.update(extra)
    return payload


def receipt_evidence(kind: str, entry_id: str, filename: str) -> dict[str, Any]:
    """Valid evidence objects so each test reaches the rule it targets."""
    platform = CUSTODY.PLATFORM_TARGETS.get(entry_id, entry_id)
    arch = CUSTODY.ENTRY_ARCHITECTURES.get(entry_id, "x64")
    if kind == CUSTODY.PRIVACY_RECEIPT_KIND:
        return {
            CUSTODY.PRIVACY_EVIDENCE_KEY: {
                "contract": "winsvpn-release-artifact-privacy-scan-text-v1",
                "record_filename": "MAC_REAL_INVENTORY_SCAN.txt",
                "record_sha256": "2" * 64,
                "result": "pass",
                "matched_labels": [],
                "inventory_revision": "r3-1.0.16+33-local-20261015",
                "inventory_sha256": "3" * 64,
                "label_count": 56,
                "target_id": CUSTODY.expected_scan_target(entry_id) or f"{platform}-target",
            }
        }
    if kind == CUSTODY.RELEASE_RECEIPT_KIND:
        unsigned = filename in CUSTODY.UNSIGNED_CANONICAL_FILENAMES.values()
        target = (
            f"windows-{arch}-inno-unsigned"
            if unsigned
            else (f"{platform}-{arch}" if platform == "linux" else f"{platform}-release")
        )
        return {
            CUSTODY.RELEASE_EVIDENCE_KEY: {
                "receipt_contract": CUSTODY.BUILD_RECEIPT_CONTRACT,
                "receipt_filename": "BUILD_RECEIPT.json",
                "receipt_sha256": "4" * 64,
                "shared_revision": "5" * 40,
                "producer_path": "tools/build_linux_release.sh",
                "producer_sha256": "6" * 64,
                "toolchain_target": target,
                "signing": "unsigned" if unsigned else "orchestrator",
                "remote_machine": "x86_64",
                "source_artifact_name": filename,
                "finished_utc": "2026-08-24T14:00:00Z",
            }
        }
    if kind == CUSTODY.WINN_PROVENANCE_KIND:
        targets = CUSTODY.expected_winn_targets(entry_id) or [f"datapath-{platform}-arm64"]
        if platform == "windows":
            binding = {
                "kind": "producer_log",
                "log_filename": "build-windows.guest.log",
                "log_sha256": "7" * 64,
                "line": (
                    "Staged the release-verified, role-checked Winn Protocol v3 "
                    f"datapath and relay for {arch}."
                ),
            }
        else:
            binding = {
                "kind": "measured_member_sha256",
                "member": "./winn-datapath",
                "sha256": "8" * 64,
                "target": targets[0],
            }
        return {
            CUSTODY.WINN_EVIDENCE_KEY: {
                "manifest_sha256": "9" * 64,
                "signature_public_key": CUSTODY.pinned_winn_authority_key(),
                "verified_by": CUSTODY.WINN_RELEASE_VERIFIER,
                "source_commit": "a" * 40,
                "tree_sha256": "b" * 64,
                "targets": targets,
                "binding": binding,
            }
        }
    return {}


def winn_binding(filename: str, receipt_sha256: str) -> dict[str, Any]:
    return {
        "kind": CUSTODY.WINN_PROVENANCE_KIND,
        "receipt_filename": f"{filename}.winn.json",
        "receipt_sha256": receipt_sha256,
        "primary": CUSTODY.WINN_PRIMARY,
        "fallback": CUSTODY.WINN_FALLBACK,
        "fallback_order": list(CUSTODY.WINN_FALLBACK_ORDER),
    }


def linux_artifact(
    digest: str,
    byte_count: int,
    receipt_sha256: str,
    signer: str = SIGNER,
    *,
    filename: str = LINUX_NAME,
    privacy_sha256: str = "d" * 64,
    release_sha256: str = "e" * 64,
    winn_sha256: str = "f" * 64,
) -> dict[str, Any]:
    return {
        "filename": filename,
        "sha256": digest,
        "bytes": byte_count,
        "canonical_release": CUSTODY.CANONICAL_RELEASE,
        "package_identity": CUSTODY.PUBLIC_PACKAGE_IDENTITY,
        "version": CUSTODY.CANONICAL_VERSION,
        "architecture": ["x64"],
        "signature": {
            "kind": CUSTODY.SIGNATURE_KINDS["linux"],
            "sha256": signer,
        },
        "winn_provenance": winn_binding(filename, winn_sha256),
        "privacy": {
            "kind": CUSTODY.PRIVACY_RECEIPT_KIND,
            "receipt_filename": f"{filename}.privacy.json",
            "receipt_sha256": privacy_sha256,
        },
        "release_receipt": {
            "kind": CUSTODY.RELEASE_RECEIPT_KIND,
            "receipt_filename": f"{filename}.release.json",
            "receipt_sha256": release_sha256,
        },
        "publication_receipt": {
            "kind": CUSTODY.PUBLICATION_RECEIPT_KIND,
            "receipt_filename": f"{filename}.publication.json",
            "receipt_sha256": receipt_sha256,
        },
    }


def write_available_linux(
    root: Path,
    *,
    payload: bytes = LINUX_BYTES,
    issued_utc: str = "2026-08-24T15:00:00Z",
    mutate_receipt: dict[str, Any] | None = None,
    mutate_owner: dict[str, Any] | None = None,
    mutate_manifest_artifact: dict[str, Any] | None = None,
    mutate_delivery: dict[str, Any] | None = None,
    write_artifact: bool = True,
    write_owner: bool = True,
    write_receipt: bool = True,
    write_challenge_file: bool = True,
    sidecar: bytes | None = None,
    signer: str = SIGNER,
    filename: str | None = None,
) -> dict[str, Any]:
    artifact_name = LINUX_NAME if filename is None else filename
    digest = sha256_hex(payload)
    owner = owner_evidence_document(
        [linux_owner_platform(digest=digest, byte_count=len(payload), signer=signer)],
        issued_utc=issued_utc,
    )
    if mutate_owner:
        owner.update(mutate_owner)
    web = seed_pending(root)
    if write_challenge_file:
        write_challenge(root, issued_utc=issued_utc)
    owner_path = web / "releases" / "owner-publication-evidence.json"
    if write_owner:
        write_json(owner_path, owner)
        owner_sha256 = sha256_hex(owner_path.read_bytes())
    else:
        owner_sha256 = "0" * 64
    receipt = publication_receipt(
        digest=digest,
        byte_count=len(payload),
        owner_sha256=owner_sha256,
        issued_utc=issued_utc,
        signer=signer,
    )
    if mutate_receipt:
        receipt.update(mutate_receipt)
    receipt_bytes = CUSTODY.canonical_json(receipt) + b"\n"
    receipt_sha256 = sha256_hex(receipt_bytes)
    architecture = ["x64"]
    privacy = hosted_identity_receipt(
        kind=CUSTODY.PRIVACY_RECEIPT_KIND,
        schema=CUSTODY.PRIVACY_RECEIPT_SCHEMA,
        digest=digest,
        byte_count=len(payload),
        filename=artifact_name,
        architecture=architecture,
    )
    release_doc = hosted_identity_receipt(
        kind=CUSTODY.RELEASE_RECEIPT_KIND,
        schema=CUSTODY.RELEASE_RECEIPT_SCHEMA,
        digest=digest,
        byte_count=len(payload),
        filename=artifact_name,
        architecture=architecture,
    )
    winn_doc = hosted_identity_receipt(
        kind=CUSTODY.WINN_PROVENANCE_KIND,
        schema=CUSTODY.WINN_PROVENANCE_SCHEMA,
        digest=digest,
        byte_count=len(payload),
        filename=artifact_name,
        architecture=architecture,
        extra={
            "primary": CUSTODY.WINN_PRIMARY,
            "fallback": CUSTODY.WINN_FALLBACK,
            "fallback_order": list(CUSTODY.WINN_FALLBACK_ORDER),
        },
    )
    privacy_bytes = CUSTODY.canonical_json(privacy) + b"\n"
    release_bytes = CUSTODY.canonical_json(release_doc) + b"\n"
    winn_bytes = CUSTODY.canonical_json(winn_doc) + b"\n"
    manifest = pending_manifest()
    artifact = linux_artifact(
        digest,
        len(payload),
        receipt_sha256,
        signer=signer,
        filename=artifact_name,
        privacy_sha256=sha256_hex(privacy_bytes),
        release_sha256=sha256_hex(release_bytes),
        winn_sha256=sha256_hex(winn_bytes),
    )
    artifact["filename"] = artifact_name
    if mutate_manifest_artifact:
        artifact.update(mutate_manifest_artifact)
    delivery = {
        "kind": "direct",
        "url": CUSTODY.production_direct_url(artifact.get("filename") or artifact_name),
    }
    if mutate_delivery:
        delivery.update(mutate_delivery)
    manifest["artifacts"][LINUX_INDEX] = {
        "id": LINUX_ENTRY,
        "label": "Linux x64",
        "status": CUSTODY.AVAILABLE_STATUS,
        "delivery": delivery,
        "artifact": artifact,
    }
    write_json(web / "releases" / "downloads.json", manifest)
    custody = CUSTODY.pending_custody_document()
    custody["status"] = CUSTODY.AVAILABLE_STATUS
    custody["owner_evidence_filename"] = "owner-publication-evidence.json"
    write_json(web / "releases" / "download-custody.json", custody)
    downloads = web / "downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    if write_artifact:
        (downloads / artifact_name).write_bytes(payload)
        sidecar_path = downloads / f"{artifact_name}.sha256"
        sidecar_path.write_bytes(
            sidecar if sidecar is not None else f"{digest}  {artifact_name}\n".encode("ascii")
        )
    if write_receipt:
        (downloads / f"{artifact_name}.publication.json").write_bytes(receipt_bytes)
        (downloads / f"{artifact_name}.privacy.json").write_bytes(privacy_bytes)
        (downloads / f"{artifact_name}.release.json").write_bytes(release_bytes)
        (downloads / f"{artifact_name}.winn.json").write_bytes(winn_bytes)
    return {"digest": digest, "owner": owner, "receipt": receipt}


def write_hosted_identity_receipts(
    downloads: Path,
    *,
    platform_id: str,
    filename: str,
    digest: str,
    byte_count: int,
    architecture: list[str],
) -> tuple[str, str, str]:
    downloads.mkdir(parents=True, exist_ok=True)
    privacy = hosted_identity_receipt(
        kind=CUSTODY.PRIVACY_RECEIPT_KIND,
        schema=CUSTODY.PRIVACY_RECEIPT_SCHEMA,
        digest=digest,
        byte_count=byte_count,
        filename=filename,
        platform_id=platform_id,
        architecture=architecture,
    )
    release_doc = hosted_identity_receipt(
        kind=CUSTODY.RELEASE_RECEIPT_KIND,
        schema=CUSTODY.RELEASE_RECEIPT_SCHEMA,
        digest=digest,
        byte_count=byte_count,
        filename=filename,
        platform_id=platform_id,
        architecture=architecture,
    )
    winn_doc = hosted_identity_receipt(
        kind=CUSTODY.WINN_PROVENANCE_KIND,
        schema=CUSTODY.WINN_PROVENANCE_SCHEMA,
        digest=digest,
        byte_count=byte_count,
        filename=filename,
        platform_id=platform_id,
        architecture=architecture,
        extra={
            "primary": CUSTODY.WINN_PRIMARY,
            "fallback": CUSTODY.WINN_FALLBACK,
            "fallback_order": list(CUSTODY.WINN_FALLBACK_ORDER),
        },
    )
    privacy_bytes = CUSTODY.canonical_json(privacy) + b"\n"
    release_bytes = CUSTODY.canonical_json(release_doc) + b"\n"
    winn_bytes = CUSTODY.canonical_json(winn_doc) + b"\n"
    (downloads / f"{filename}.privacy.json").write_bytes(privacy_bytes)
    (downloads / f"{filename}.release.json").write_bytes(release_bytes)
    (downloads / f"{filename}.winn.json").write_bytes(winn_bytes)
    return sha256_hex(privacy_bytes), sha256_hex(release_bytes), sha256_hex(winn_bytes)


def hosted_bindings(filename: str, privacy_sha256: str, release_sha256: str, winn_sha256: str) -> dict[str, Any]:
    return {
        "winn_provenance": winn_binding(filename, winn_sha256),
        "privacy": {
            "kind": CUSTODY.PRIVACY_RECEIPT_KIND,
            "receipt_filename": f"{filename}.privacy.json",
            "receipt_sha256": privacy_sha256,
        },
        "release_receipt": {
            "kind": CUSTODY.RELEASE_RECEIPT_KIND,
            "receipt_filename": f"{filename}.release.json",
            "receipt_sha256": release_sha256,
        },
    }


def pe_bytes(machine: int, magic: int = 0x20B) -> bytes:
    data = bytearray(0x80)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 0x40)
    data[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<H", data, 0x44, machine)
    struct.pack_into("<H", data, 0x58, magic)
    return bytes(data)


class WebsiteDownloadCustodyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ledger = use_fresh_release_ledger(self)

    def evaluate(self, root: Path | None = None) -> CUSTODY.CustodyReport:
        return CUSTODY.evaluate_tree(root or self.root, now=NOW)

    def test_live_tree_stays_pending_without_artifacts_or_owner_evidence(self) -> None:
        report = CUSTODY.evaluate_repository(now=NOW)
        self.assertFalse(report.ok, report.summary)
        self.assertEqual(report.status, CUSTODY.PENDING_STATUS)
        self.assertTrue(report.summary.startswith("PENDING "))
        self.assertFalse(report.summary.startswith("PASS"), report.summary)
        self.assertIn("owner publication evidence are absent", report.summary)
        self.assertIn("https://winsvpn.org/downloads/WinsVPN-Setup.exe", report.summary)
        self.assertIn("https://winsvpn.org/downloads/wins-vpn-android.apk", report.summary)
        self.assertIn("com.example.wins_vpn", report.summary)
        self.assertIn(CUSTODY.STALE_ANDROID_DEBUG_SHA256, report.summary)
        self.assertIn("placeholder 302s", report.summary)
        self.assertEqual(report.findings, CUSTODY.PENDING_BLOCKERS)
        downloads = ROOT / "web" / "downloads"
        self.assertFalse(downloads.is_dir() and any(downloads.iterdir()))
        self.assertFalse((ROOT / CUSTODY.OWNER_EVIDENCE_RELATIVE).exists())
        live = json.loads(
            (ROOT / "web" / "releases" / "downloads.json").read_text(encoding="ascii")
        )
        for entry in live["artifacts"]:
            expected_status = (
                CUSTODY.STORE_PENDING_STATUS
                if entry["delivery"]["kind"] == "store"
                else CUSTODY.PENDING_STATUS
            )
            self.assertEqual(entry["status"], expected_status)
            self.assertIsNone(entry["delivery"]["url"])
            self.assertEqual(
                entry["artifact"],
                {"filename": None, "sha256": None, "bytes": None},
            )

    def test_live_custody_metadata_matches_pending_manifest(self) -> None:
        payload = json.loads(
            (ROOT / "web" / "releases" / "download-custody.json").read_text(
                encoding="ascii"
            )
        )
        self.assertEqual(payload["schema"], CUSTODY.CUSTODY_SCHEMA)
        self.assertEqual(payload["status"], CUSTODY.PENDING_STATUS)
        self.assertIsNone(payload["owner_evidence_filename"])
        self.assertEqual(payload["canonical_release"], "1.0.16+33")
        self.assertEqual(payload["production_origin"], "https://winsvpn.org")
        self.assertEqual(payload["canonical_filenames"]["linux-x64"], LINUX_NAME)
        self.assertEqual(payload["verifier_boundary"], list(CUSTODY.VERIFIER_FILES))
        self.assertEqual(
            payload["forbidden_android_debug_sha256"],
            CUSTODY.STALE_ANDROID_DEBUG_SHA256,
        )
        self.assertEqual(payload["winn_primary"], "winn/3")
        self.assertEqual(payload["winn_fallback"], "winn/1")
        self.assertEqual(payload["winn_fallback_order"], ["awg", "xray"])

    def test_cli_reports_pending_nonzero_for_the_live_tree(self) -> None:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = CUSTODY.main()
        self.assertEqual(code, 1, buffer.getvalue())
        self.assertTrue(buffer.getvalue().startswith("PENDING "))
        self.assertFalse(buffer.getvalue().startswith("PASS"), buffer.getvalue())

    def test_unsigned_authenticated_true_self_authored_json_cannot_pass(self) -> None:
        write_available_linux(self.root, mutate_owner={"authenticated": True})
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertFalse(report.summary.startswith("PASS"), report.summary)
        self.assertIn("authenticated", report.summary)

    def test_unkeyed_digest_is_not_authentication(self) -> None:
        digest = sha256_hex(LINUX_BYTES)
        write_available_linux(
            self.root,
            mutate_manifest_artifact={
                "signature": {
                    "kind": CUSTODY.SIGNATURE_KINDS["linux"],
                    "sha256": digest,
                }
            },
            signer=digest,
        )
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("unkeyed artifact digest is not cryptographic authentication", report.summary)
        self.assertFalse(report.summary.startswith("PASS"), report.summary)

    def test_plaintext_linux_bytes_are_not_a_signed_release(self) -> None:
        write_available_linux(self.root)
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("not a gzip tar", report.summary)
        self.assertFalse(report.summary.startswith("PASS"), report.summary)

    def test_missing_owner_evidence_cannot_make_a_download_available(self) -> None:
        write_available_linux(self.root, write_owner=False)
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("owner publication evidence", report.summary)

    def test_missing_verifier_challenge_cannot_make_a_download_available(self) -> None:
        write_available_linux(self.root, write_challenge_file=False)
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("verifier-issued one-use challenge", report.summary)

    def test_missing_artifact_bytes_fail_closed(self) -> None:
        write_available_linux(self.root, write_artifact=False)
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertTrue(
            "absent" in report.summary or "missing" in report.summary,
            report.summary,
        )

    def test_pending_is_required_when_artifacts_and_evidence_are_absent(self) -> None:
        seed_pending(self.root)
        report = self.evaluate()
        self.assertFalse(report.ok, report.summary)
        self.assertEqual(report.status, CUSTODY.PENDING_STATUS)
        self.assertTrue(report.summary.startswith("PENDING "))
        self.assertFalse(report.summary.startswith("PASS"), report.summary)

    def test_stale_android_debug_digest_is_never_substituted(self) -> None:
        write_available_linux(
            self.root,
            mutate_manifest_artifact={"sha256": CUSTODY.STALE_ANDROID_DEBUG_SHA256},
        )
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("stale Android debug APK digest", report.summary)

    def test_stale_unsigned_windows_digest_is_never_substituted(self) -> None:
        write_available_linux(
            self.root,
            mutate_manifest_artifact={"sha256": CUSTODY.STALE_WINDOWS_UNSIGNED_SHA256},
        )
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("stale unsigned Windows installer digest", report.summary)

    def test_debug_package_identity_is_refused(self) -> None:
        write_available_linux(
            self.root,
            mutate_manifest_artifact={
                "package_identity": CUSTODY.STALE_ANDROID_DEBUG_PACKAGE
            },
        )
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("stale Android debug application ID", report.summary)

    def test_historical_release_id_is_refused(self) -> None:
        seed_pending(self.root)
        manifest = pending_manifest()
        manifest["release_id"] = "v1.0.0"
        write_json(self.root / "web" / "releases" / "downloads.json", manifest)
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("historical release identity", report.summary)

    def test_unsigned_artifact_is_refused(self) -> None:
        write_available_linux(
            self.root,
            mutate_manifest_artifact={
                "signature": {"kind": "unsigned", "sha256": SIGNER}
            },
        )
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("signature kind", report.summary)

    def test_sha256_mismatch_is_refused(self) -> None:
        write_available_linux(self.root)
        artifact = self.root / "web" / "downloads" / LINUX_NAME
        artifact.write_bytes(LINUX_BYTES + b"tamper")
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertTrue(
            "SHA-256 mismatch" in report.summary or "byte count mismatch" in report.summary,
            report.summary,
        )

    def test_wrong_architecture_label_is_refused(self) -> None:
        write_available_linux(
            self.root,
            mutate_manifest_artifact={"architecture": ["mips"]},
        )
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("architecture", report.summary)

    def test_architecture_label_on_plaintext_is_not_measurement(self) -> None:
        write_available_linux(
            self.root,
            mutate_manifest_artifact={"architecture": ["arm64"]},
        )
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertTrue(
            "canonical filename" in report.summary
            or "not a gzip tar" in report.summary
            or "architecture" in report.summary,
            report.summary,
        )
        self.assertFalse(report.summary.startswith("PASS"), report.summary)

    def test_dual_linux_architecture_labels_are_refused(self) -> None:
        write_available_linux(
            self.root,
            mutate_manifest_artifact={"architecture": ["x64", "arm64"]},
        )
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("architecture", report.summary)
        self.assertFalse(report.summary.startswith("PASS"), report.summary)

    def test_wrong_version_is_refused(self) -> None:
        write_available_linux(
            self.root,
            mutate_manifest_artifact={"canonical_release": "1.0.14+29"},
        )
        report = self.evaluate()
        self.assertFalse(report.ok)
        combined = report.summary
        self.assertTrue(
            "historical release identity" in combined
            or "current 1.0.16+33 release" in combined,
            combined,
        )

    def test_replayed_nonce_is_refused(self) -> None:
        digest = sha256_hex(LINUX_BYTES)
        issued = "2026-08-24T15:00:00Z"
        android_platform = {
            "id": "android",
            "target": "android",
            "version": CUSTODY.CANONICAL_VERSION,
            "architecture": sorted(CUSTODY.PLATFORM_ARCHITECTURES["android"]),
            "artifact_filename": "wins-vpn-android.apk",
            "artifact_sha256": digest,
            "artifact_bytes": len(LINUX_BYTES),
            "signature_kind": CUSTODY.SIGNATURE_KINDS["android"],
            "signature_sha256": CUSTODY.ANDROID_PUBLIC_SIGNER_SHA256,
            "nonce": LINUX_NONCE,
            "receipt_filename": "wins-vpn-android.apk.publication.json",
        }
        owner = owner_evidence_document(
            [
                linux_owner_platform(digest=digest, byte_count=len(LINUX_BYTES)),
                android_platform,
            ],
            issued_utc=issued,
        )
        path = self.root / "owner.json"
        write_json(path, owner)
        seed_pending(self.root)
        (self.root / "web" / "releases" / "owner-publication-evidence.json").write_bytes(
            path.read_bytes()
        )
        with self.assertRaisesRegex(CUSTODY.WebsiteDownloadCustodyError, "nonce is a replay"):
            CUSTODY.load_owner_evidence(self.root, now=NOW)

    def test_consumed_replay_log_refuses_the_same_issuance(self) -> None:
        digest = sha256_hex(LINUX_BYTES)
        seed_pending(self.root)
        CUSTODY.consume_replay(
            self.root,
            issuance_id=ISSUANCE_ID,
            nonce=LINUX_NONCE,
            challenge_nonce=CHALLENGE_NONCE,
            owner_evidence_sha256="d" * 64,
            artifact_sha256=digest,
            now=NOW,
        )
        write_available_linux(self.root)
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("already consumed", report.summary)
        self.assertFalse(report.summary.startswith("PASS"), report.summary)

    def test_durable_replay_consumption_refuses_a_second_use(self) -> None:
        seed_pending(self.root)
        CUSTODY.consume_replay(
            self.root,
            issuance_id=ISSUANCE_ID,
            nonce=LINUX_NONCE,
            challenge_nonce=CHALLENGE_NONCE,
            owner_evidence_sha256="d" * 64,
            artifact_sha256="a" * 64,
            now=NOW,
        )
        with self.assertRaisesRegex(
            CUSTODY.WebsiteDownloadCustodyError, "already consumed"
        ):
            CUSTODY.consume_replay(
                self.root,
                issuance_id=ISSUANCE_ID,
                nonce=LINUX_NONCE,
                challenge_nonce=CHALLENGE_NONCE,
                owner_evidence_sha256="d" * 64,
                artifact_sha256="a" * 64,
                now=NOW,
            )

    def test_challenge_is_one_use_across_issuances_but_covers_one_batch(self) -> None:
        seed_pending(self.root)
        for nonce in (LINUX_NONCE, ANDROID_NONCE):
            CUSTODY.consume_replay(
                self.root,
                issuance_id=ISSUANCE_ID,
                nonce=nonce,
                challenge_nonce=CHALLENGE_NONCE,
                owner_evidence_sha256="d" * 64,
                artifact_sha256="a" * 64,
                now=NOW,
            )
        with self.assertRaisesRegex(CUSTODY.WebsiteDownloadCustodyError, "already consumed"):
            CUSTODY.consume_replay(
                self.root,
                issuance_id="e" * 32,
                nonce="f" * 32,
                challenge_nonce=CHALLENGE_NONCE,
                owner_evidence_sha256="e" * 64,
                artifact_sha256="a" * 64,
                now=NOW,
            )

    def test_retimestamped_receipt_without_new_binding_is_replayed(self) -> None:
        write_available_linux(
            self.root,
            mutate_receipt={"issued_utc": "2026-08-24T14:30:00Z"},
        )
        replayed = self.evaluate()
        self.assertFalse(replayed.ok)
        self.assertTrue(
            "does not match owner evidence" in replayed.summary
            or "stale or future-dated" in replayed.summary
            or "not a gzip tar" in replayed.summary,
            replayed.summary,
        )
        self.assertFalse(replayed.summary.startswith("PASS"), replayed.summary)

    def test_stale_publication_receipt_is_refused(self) -> None:
        write_available_linux(self.root, issued_utc="2026-08-20T15:00:00Z")
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("stale or future-dated", report.summary)

    def test_future_publication_receipt_is_refused(self) -> None:
        write_available_linux(self.root, issued_utc="2026-08-24T16:00:00Z")
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("stale or future-dated", report.summary)

    def test_authenticated_true_is_not_cryptographic_authentication(self) -> None:
        write_available_linux(self.root, mutate_owner={"authenticated": True})
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn(
            "self-asserted authenticated:true is not cryptographic authentication",
            report.summary,
        )

    def test_receipt_cannot_self_assert_authentication(self) -> None:
        write_available_linux(
            self.root, mutate_receipt={"authenticated": True}
        )
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertTrue(
            "authenticated" in report.summary or "exact schema" in report.summary,
            report.summary,
        )

    def test_duplicate_json_keys_are_refused(self) -> None:
        seed_pending(self.root)
        path = self.root / "web" / "releases" / "download-custody.json"
        original = path.read_bytes().rstrip()
        if original.endswith(b"}"):
            duplicated = original[:-1] + b',"status":"available"}'
        else:
            duplicated = original
        path.write_bytes(duplicated + b"\n")
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("duplicate JSON key", report.summary)

    def test_duplicate_authenticated_keys_cannot_hide_false(self) -> None:
        write_available_linux(self.root)
        owner_path = self.root / "web" / "releases" / "owner-publication-evidence.json"
        body = owner_path.read_bytes().rstrip()
        if body.endswith(b"}"):
            body = body[:-1] + b',"authenticated":false,"authenticated":true}'
        owner_path.write_bytes(body + b"\n")
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertTrue(
            "duplicate JSON key" in report.summary or "authenticated" in report.summary,
            report.summary,
        )
        self.assertFalse(report.summary.startswith("PASS"), report.summary)

    def test_unbound_file_cannot_fill_a_pending_surface(self) -> None:
        seed_pending(self.root)
        downloads = self.root / "web" / "downloads"
        downloads.mkdir(parents=True)
        (downloads / "orphan.bin").write_bytes(LINUX_BYTES)
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("substitute missing artifacts", report.summary)

    def test_pending_entry_cannot_carry_release_metadata(self) -> None:
        seed_pending(self.root)
        manifest = pending_manifest()
        manifest["artifacts"][LINUX_INDEX]["artifact"]["sha256"] = sha256_hex(LINUX_BYTES)
        write_json(self.root / "web" / "releases" / "downloads.json", manifest)
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("pending entry contains release metadata", report.summary)

    def test_android_requires_reviewed_production_signer(self) -> None:
        payload = b"not-an-apk-just-bytes\n"
        digest = sha256_hex(payload)
        issued = "2026-08-24T15:00:00Z"
        architecture = sorted(CUSTODY.PLATFORM_ARCHITECTURES["android"])
        owner = owner_evidence_document(
            [
                {
                    "id": "android",
                    "target": "android",
                    "version": CUSTODY.CANONICAL_VERSION,
                    "architecture": architecture,
                    "artifact_filename": "wins-vpn-android.apk",
                    "artifact_sha256": digest,
                    "artifact_bytes": len(payload),
                    "signature_kind": CUSTODY.SIGNATURE_KINDS["android"],
                    "signature_sha256": "d" * 64,
                    "nonce": ANDROID_NONCE,
                    "receipt_filename": "wins-vpn-android.apk.publication.json",
                }
            ],
            issued_utc=issued,
        )
        seed_pending(self.root)
        write_json(self.root / "web" / "releases" / "owner-publication-evidence.json", owner)
        with self.assertRaisesRegex(
            CUSTODY.WebsiteDownloadCustodyError, "reviewed production signer"
        ):
            CUSTODY.load_owner_evidence(self.root, now=NOW)

    def test_android_fake_bytes_with_pinned_cert_hex_cannot_pass(self) -> None:
        payload = b"not-an-apk-just-bytes\n"
        digest = sha256_hex(payload)
        issued = "2026-08-24T15:00:00Z"
        architecture = sorted(CUSTODY.PLATFORM_ARCHITECTURES["android"])
        write_available_linux(self.root)
        owner = owner_evidence_document(
            [
                {
                    "id": "android",
                    "target": "android",
                    "version": CUSTODY.CANONICAL_VERSION,
                    "architecture": architecture,
                    "artifact_filename": "wins-vpn-android.apk",
                    "artifact_sha256": digest,
                    "artifact_bytes": len(payload),
                    "signature_kind": CUSTODY.SIGNATURE_KINDS["android"],
                    "signature_sha256": CUSTODY.ANDROID_PUBLIC_SIGNER_SHA256,
                    "nonce": ANDROID_NONCE,
                    "receipt_filename": "wins-vpn-android.apk.publication.json",
                }
            ],
            issued_utc=issued,
        )
        write_json(self.root / "web" / "releases" / "owner-publication-evidence.json", owner)
        manifest = pending_manifest()
        receipt = {
            "schema": CUSTODY.PUBLICATION_RECEIPT_SCHEMA,
            "kind": CUSTODY.PUBLICATION_RECEIPT_KIND,
            "issuance_id": ISSUANCE_ID,
            "issued_utc": issued,
            "nonce": ANDROID_NONCE,
            "canonical_release": CUSTODY.CANONICAL_RELEASE,
            "package_identity": CUSTODY.PUBLIC_PACKAGE_IDENTITY,
            "platform_id": "android",
            "target": "android",
            "version": CUSTODY.CANONICAL_VERSION,
            "architecture": architecture,
            "artifact_filename": "wins-vpn-android.apk",
            "artifact_sha256": digest,
            "artifact_bytes": len(payload),
            "signature_kind": CUSTODY.SIGNATURE_KINDS["android"],
            "signature_sha256": CUSTODY.ANDROID_PUBLIC_SIGNER_SHA256,
            "challenge_nonce": CHALLENGE_NONCE,
            "owner_evidence_sha256": sha256_hex(
                (self.root / "web" / "releases" / "owner-publication-evidence.json").read_bytes()
            ),
        }
        receipt_bytes = CUSTODY.canonical_json(receipt) + b"\n"
        downloads = self.root / "web" / "downloads"
        privacy_sha, release_sha, winn_sha = write_hosted_identity_receipts(
            downloads,
            platform_id="android",
            filename="wins-vpn-android.apk",
            digest=digest,
            byte_count=len(payload),
            architecture=architecture,
        )
        manifest["artifacts"][ENTRY_INDEX["android"]] = {
            "id": "android",
            "label": "Android",
            "status": CUSTODY.AVAILABLE_STATUS,
            "delivery": {
                "kind": "direct",
                "url": CUSTODY.production_direct_url("wins-vpn-android.apk"),
            },
            "artifact": {
                "filename": "wins-vpn-android.apk",
                "sha256": digest,
                "bytes": len(payload),
                "canonical_release": CUSTODY.CANONICAL_RELEASE,
                "package_identity": CUSTODY.PUBLIC_PACKAGE_IDENTITY,
                "version": CUSTODY.CANONICAL_VERSION,
                "architecture": architecture,
                "signature": {
                    "kind": CUSTODY.SIGNATURE_KINDS["android"],
                    "sha256": CUSTODY.ANDROID_PUBLIC_SIGNER_SHA256,
                },
                **hosted_bindings(
                    "wins-vpn-android.apk", privacy_sha, release_sha, winn_sha
                ),
                "publication_receipt": {
                    "kind": CUSTODY.PUBLICATION_RECEIPT_KIND,
                    "receipt_filename": "wins-vpn-android.apk.publication.json",
                    "receipt_sha256": sha256_hex(receipt_bytes),
                },
            },
        }
        write_json(self.root / "web" / "releases" / "downloads.json", manifest)
        (downloads / "wins-vpn-android.apk").write_bytes(payload)
        (downloads / "wins-vpn-android.apk.sha256").write_bytes(
            f"{digest}  wins-vpn-android.apk\n".encode("ascii")
        )
        (downloads / "wins-vpn-android.apk.publication.json").write_bytes(receipt_bytes)
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("not an APK", report.summary)
        self.assertFalse(report.summary.startswith("PASS"), report.summary)

    def test_windows_plaintext_labeled_arm64_cannot_pass(self) -> None:
        payload = b"not-a-pe-not-authenticode\n"
        digest = sha256_hex(payload)
        write_available_linux(self.root)
        filename = "WinsVPN-Setup-arm64.exe"
        owner = owner_evidence_document(
            [
                {
                    "id": "windows-arm64",
                    "target": "windows",
                    "version": CUSTODY.CANONICAL_VERSION,
                    "architecture": ["arm64"],
                    "artifact_filename": filename,
                    "artifact_sha256": digest,
                    "artifact_bytes": len(payload),
                    "signature_kind": CUSTODY.SIGNATURE_KINDS["windows"],
                    "signature_sha256": SIGNER,
                    "nonce": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    "receipt_filename": f"{filename}.publication.json",
                }
            ],
            issued_utc="2026-08-24T15:00:00Z",
        )
        write_json(self.root / "web" / "releases" / "owner-publication-evidence.json", owner)
        receipt = {
            "schema": CUSTODY.PUBLICATION_RECEIPT_SCHEMA,
            "kind": CUSTODY.PUBLICATION_RECEIPT_KIND,
            "issuance_id": ISSUANCE_ID,
            "issued_utc": "2026-08-24T15:00:00Z",
            "nonce": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "canonical_release": CUSTODY.CANONICAL_RELEASE,
            "package_identity": CUSTODY.PUBLIC_PACKAGE_IDENTITY,
            "platform_id": "windows-arm64",
            "target": "windows",
            "version": CUSTODY.CANONICAL_VERSION,
            "architecture": ["arm64"],
            "artifact_filename": filename,
            "artifact_sha256": digest,
            "artifact_bytes": len(payload),
            "signature_kind": CUSTODY.SIGNATURE_KINDS["windows"],
            "signature_sha256": SIGNER,
            "challenge_nonce": CHALLENGE_NONCE,
            "owner_evidence_sha256": sha256_hex(
                (self.root / "web" / "releases" / "owner-publication-evidence.json").read_bytes()
            ),
        }
        receipt_bytes = CUSTODY.canonical_json(receipt) + b"\n"
        manifest = pending_manifest()
        manifest["artifacts"][ENTRY_INDEX["windows-arm64"]] = {
            "id": "windows-arm64",
            "label": "Windows ARM64",
            "status": CUSTODY.AVAILABLE_STATUS,
            "delivery": {"kind": "direct", "url": CUSTODY.production_direct_url(filename)},
            "artifact": {
                "filename": filename,
                "sha256": digest,
                "bytes": len(payload),
                "canonical_release": CUSTODY.CANONICAL_RELEASE,
                "package_identity": CUSTODY.PUBLIC_PACKAGE_IDENTITY,
                "version": CUSTODY.CANONICAL_VERSION,
                "architecture": ["arm64"],
                "signature": {
                    "kind": CUSTODY.SIGNATURE_KINDS["windows"],
                    "sha256": SIGNER,
                },
                **hosted_bindings(filename, "d" * 64, "e" * 64, "f" * 64),
                "publication_receipt": {
                    "kind": CUSTODY.PUBLICATION_RECEIPT_KIND,
                    "receipt_filename": f"{filename}.publication.json",
                    "receipt_sha256": sha256_hex(receipt_bytes),
                },
            },
        }
        write_json(self.root / "web" / "releases" / "downloads.json", manifest)
        downloads = self.root / "web" / "downloads"
        privacy_sha, release_sha, winn_sha = write_hosted_identity_receipts(
            downloads,
            platform_id="windows-arm64",
            filename=filename,
            digest=digest,
            byte_count=len(payload),
            architecture=["arm64"],
        )
        manifest["artifacts"][ENTRY_INDEX["windows-arm64"]]["artifact"].update(
            hosted_bindings(filename, privacy_sha, release_sha, winn_sha)
        )
        write_json(self.root / "web" / "releases" / "downloads.json", manifest)
        (downloads / filename).write_bytes(payload)
        (downloads / f"{filename}.sha256").write_bytes(
            f"{digest}  {filename}\n".encode("ascii")
        )
        (downloads / f"{filename}.publication.json").write_bytes(receipt_bytes)
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("not a PE image", report.summary)
        self.assertFalse(report.summary.startswith("PASS"), report.summary)

    def test_windows_mz_stub_is_not_authenticode(self) -> None:
        # The ARM64 website installer is the reviewed PE32+ x64 Inno loader.
        payload = pe_bytes(CUSTODY.PE_AMD64)
        digest = sha256_hex(payload)
        filename = "WinsVPN-Setup-arm64.exe"
        write_available_linux(self.root)
        owner = owner_evidence_document(
            [
                {
                    "id": "windows-arm64",
                    "target": "windows",
                    "version": CUSTODY.CANONICAL_VERSION,
                    "architecture": ["arm64"],
                    "artifact_filename": filename,
                    "artifact_sha256": digest,
                    "artifact_bytes": len(payload),
                    "signature_kind": CUSTODY.SIGNATURE_KINDS["windows"],
                    "signature_sha256": SIGNER,
                    "nonce": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    "receipt_filename": f"{filename}.publication.json",
                }
            ],
            issued_utc="2026-08-24T15:00:00Z",
        )
        write_json(self.root / "web" / "releases" / "owner-publication-evidence.json", owner)
        receipt = {
            "schema": CUSTODY.PUBLICATION_RECEIPT_SCHEMA,
            "kind": CUSTODY.PUBLICATION_RECEIPT_KIND,
            "issuance_id": ISSUANCE_ID,
            "issued_utc": "2026-08-24T15:00:00Z",
            "nonce": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "canonical_release": CUSTODY.CANONICAL_RELEASE,
            "package_identity": CUSTODY.PUBLIC_PACKAGE_IDENTITY,
            "platform_id": "windows-arm64",
            "target": "windows",
            "version": CUSTODY.CANONICAL_VERSION,
            "architecture": ["arm64"],
            "artifact_filename": filename,
            "artifact_sha256": digest,
            "artifact_bytes": len(payload),
            "signature_kind": CUSTODY.SIGNATURE_KINDS["windows"],
            "signature_sha256": SIGNER,
            "challenge_nonce": CHALLENGE_NONCE,
            "owner_evidence_sha256": sha256_hex(
                (self.root / "web" / "releases" / "owner-publication-evidence.json").read_bytes()
            ),
        }
        receipt_bytes = CUSTODY.canonical_json(receipt) + b"\n"
        manifest = pending_manifest()
        manifest["artifacts"][ENTRY_INDEX["windows-arm64"]] = {
            "id": "windows-arm64",
            "label": "Windows ARM64",
            "status": CUSTODY.AVAILABLE_STATUS,
            "delivery": {"kind": "direct", "url": CUSTODY.production_direct_url(filename)},
            "artifact": {
                "filename": filename,
                "sha256": digest,
                "bytes": len(payload),
                "canonical_release": CUSTODY.CANONICAL_RELEASE,
                "package_identity": CUSTODY.PUBLIC_PACKAGE_IDENTITY,
                "version": CUSTODY.CANONICAL_VERSION,
                "architecture": ["arm64"],
                "signature": {
                    "kind": CUSTODY.SIGNATURE_KINDS["windows"],
                    "sha256": SIGNER,
                },
                **hosted_bindings(filename, "d" * 64, "e" * 64, "f" * 64),
                "publication_receipt": {
                    "kind": CUSTODY.PUBLICATION_RECEIPT_KIND,
                    "receipt_filename": f"{filename}.publication.json",
                    "receipt_sha256": sha256_hex(receipt_bytes),
                },
            },
        }
        write_json(self.root / "web" / "releases" / "downloads.json", manifest)
        downloads = self.root / "web" / "downloads"
        privacy_sha, release_sha, winn_sha = write_hosted_identity_receipts(
            downloads,
            platform_id="windows-arm64",
            filename=filename,
            digest=digest,
            byte_count=len(payload),
            architecture=["arm64"],
        )
        manifest["artifacts"][ENTRY_INDEX["windows-arm64"]]["artifact"].update(
            hosted_bindings(filename, privacy_sha, release_sha, winn_sha)
        )
        write_json(self.root / "web" / "releases" / "downloads.json", manifest)
        (downloads / filename).write_bytes(payload)
        (downloads / f"{filename}.sha256").write_bytes(
            f"{digest}  {filename}\n".encode("ascii")
        )
        (downloads / f"{filename}.publication.json").write_bytes(receipt_bytes)
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("Authenticode", report.summary)
        self.assertFalse(report.summary.startswith("PASS"), report.summary)

    def test_owner_evidence_hash_mismatch_is_refused(self) -> None:
        write_available_linux(
            self.root,
            mutate_receipt={"owner_evidence_sha256": "e" * 64},
        )
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("current owner evidence", report.summary)

    def test_sidecar_mismatch_is_refused(self) -> None:
        write_available_linux(
            self.root, sidecar=b"deadbeef  wrong-name.bin\n"
        )
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("sidecar does not exactly bind", report.summary)

    def test_store_available_entry_is_not_a_local_signed_artifact(self) -> None:
        seed_pending(self.root)
        manifest = pending_manifest()
        manifest["artifacts"][ENTRY_INDEX["macos"]] = {
            "id": "macos",
            "label": "MacBook (macOS)",
            "status": CUSTODY.AVAILABLE_STATUS,
            "delivery": {"kind": "store", "url": "https://apps.apple.com/app/wins-vpn"},
            "artifact": {
                "filename": "wins-vpn-macos-20260824.pkg",
                "sha256": "a" * 64,
                "bytes": 2,
                "canonical_release": CUSTODY.CANONICAL_RELEASE,
                "package_identity": CUSTODY.PUBLIC_PACKAGE_IDENTITY,
                "architecture": ["arm64", "x86_64"],
                "signature": {
                    "kind": CUSTODY.SIGNATURE_KINDS["macos"],
                    "sha256": SIGNER,
                },
                "publication_receipt": {
                    "kind": CUSTODY.PUBLICATION_RECEIPT_KIND,
                    "receipt_filename": "wins-vpn-macos-20260824.pkg.publication.json",
                    "receipt_sha256": "f" * 64,
                },
            },
        }
        write_json(self.root / "web" / "releases" / "downloads.json", manifest)
        custody = CUSTODY.pending_custody_document()
        custody["status"] = CUSTODY.AVAILABLE_STATUS
        custody["owner_evidence_filename"] = "owner-publication-evidence.json"
        write_json(self.root / "web" / "releases" / "download-custody.json", custody)
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertTrue(
            "production store URL" in report.summary
            or "partial platform coverage" in report.summary,
            report.summary,
        )
        self.assertFalse(report.summary.startswith("PASS"), report.summary)

    def test_relative_download_url_is_not_the_production_origin(self) -> None:
        write_available_linux(
            self.root,
            mutate_delivery={"url": f"/downloads/{LINUX_NAME}"},
        )
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("exact production origin", report.summary)

    def test_wrong_origin_is_refused(self) -> None:
        write_available_linux(
            self.root,
            mutate_delivery={"url": f"https://winsvpn.example/downloads/{LINUX_NAME}"},
        )
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("exact production origin", report.summary)

    def test_noncanonical_linux_filename_is_refused(self) -> None:
        write_available_linux(
            self.root,
            mutate_manifest_artifact={"filename": "wins-vpn-linux-20260824.tar.gz"},
        )
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("exact canonical target filename", report.summary)

    def test_debug_filename_is_refused(self) -> None:
        write_available_linux(
            self.root,
            mutate_manifest_artifact={"filename": "wins-vpn-linux-debug-20260824.tar.gz"},
        )
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("debug artifact", report.summary)

    def test_debugging_filename_is_refused(self) -> None:
        write_available_linux(
            self.root,
            mutate_manifest_artifact={"filename": "wins-vpn-linux-debugging-20260824.tar.gz"},
        )
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("debug artifact", report.summary)

    def test_debug_substring_filenames_are_refused(self) -> None:
        for name in ("winsvpnDebugging.tar.gz", "undebug.tar.gz"):
            with self.subTest(name=name):
                write_available_linux(
                    self.root,
                    mutate_manifest_artifact={"filename": name},
                )
                report = self.evaluate()
                self.assertFalse(report.ok)
                self.assertIn("debug artifact", report.summary)

    def test_symlink_artifact_is_refused(self) -> None:
        write_available_linux(self.root)
        artifact = self.root / "web" / "downloads" / LINUX_NAME
        outside = self.root / "outside.bin"
        outside.write_bytes(LINUX_BYTES)
        artifact.unlink()
        artifact.symlink_to(outside)
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("symlink", report.summary)

    def test_ancestor_swap_outside_downloads_cannot_bind(self) -> None:
        write_available_linux(self.root, write_artifact=False)
        (self.root / "web" / "releases" / LINUX_NAME).write_bytes(LINUX_BYTES)
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertTrue(
            "missing" in report.summary or "absent" in report.summary,
            report.summary,
        )

    def test_path_traversal_filename_is_refused(self) -> None:
        write_available_linux(
            self.root,
            mutate_manifest_artifact={"filename": "../outside.bin"},
        )
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertTrue(
            "escapes" in report.summary or "invalid" in report.summary,
            report.summary,
        )

    def test_changed_artifact_cannot_reuse_the_same_issuance(self) -> None:
        other = b"wins-vpn-linux-other-bytes\n"
        other_digest = sha256_hex(other)
        write_available_linux(
            self.root,
            payload=LINUX_BYTES,
            mutate_manifest_artifact={"sha256": other_digest, "bytes": len(other)},
        )
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertTrue(
            "does not match owner publication evidence" in report.summary
            or "SHA-256 mismatch" in report.summary,
            report.summary,
        )

    def test_verifier_pin_mismatch_is_refused(self) -> None:
        seed_pending(self.root)
        custody = CUSTODY.pending_custody_document()
        custody["verifier_boundary"] = list(CUSTODY.VERIFIER_FILES[:-1]) + [
            "tools/not-a-pinned-verifier.py"
        ]
        write_json(self.root / "web" / "releases" / "download-custody.json", custody)
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("verifier boundary", report.summary)

    def test_partial_platform_launch_still_requires_measured_custody(self) -> None:
        # Owner ruling 2026-10-25 allows a per-platform launch, so partial
        # coverage is no longer a refusal by itself; the available entry must
        # still pass its measured custody (here: plaintext is not a tarball).
        write_available_linux(self.root)
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertNotIn("partial platform coverage", report.summary)
        self.assertIn("not a gzip tar", report.summary)
        self.assertFalse(report.summary.startswith("PASS"))

    def test_artifact_adjacent_cosign_key_is_not_a_trust_anchor(self) -> None:
        downloads = self.root / "web" / "downloads"
        downloads.mkdir(parents=True)
        (downloads / LINUX_NAME).write_bytes(b"dummy")
        (downloads / f"{LINUX_NAME}.sigstore.json").write_bytes(b"{}\n")
        adjacent = downloads / f"{LINUX_NAME}.cosign.pub"
        adjacent.write_text("ATTACKER-KEY\n", encoding="ascii")
        fd = os.open(downloads / LINUX_NAME, os.O_RDONLY | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        ran = {"n": 0}

        def fake_run(argv: object, **kwargs: object) -> object:
            ran["n"] += 1

            class Done:
                returncode = 0

            return Done()

        def missing_key(label: str) -> object:
            # The checkout now carries the canonical key; this case pins the
            # behaviour when it is absent and only an adjacent key is offered.
            raise CUSTODY.WebsiteDownloadCustodyError(f"{label} is missing")

        real_run = CUSTODY.subprocess.run
        real_key = CUSTODY.open_trusted_cosign_key
        CUSTODY.subprocess.run = fake_run  # type: ignore[method-assign]
        CUSTODY.open_trusted_cosign_key = missing_key  # type: ignore[method-assign]
        try:
            errors = CUSTODY.linux_signature_errors(
                self.root,
                LINUX_NAME,
                b"dummy",
                {CUSTODY.LINUX_SIGNING_RELATIVE: "0" * 64},
                "artifact linux",
                artifact_fd=fd,
            )
        finally:
            CUSTODY.subprocess.run = real_run  # type: ignore[method-assign]
            CUSTODY.open_trusted_cosign_key = real_key  # type: ignore[method-assign]
        combined = " ".join(errors)
        self.assertIn("canonical trusted key", combined)
        self.assertEqual(ran["n"], 0, combined)
        self.assertEqual(
            CUSTODY.TRUSTED_COSIGN_KEY_RELATIVE,
            "linux/packaging/release-signing/cosign.pub",
        )
        src = inspect.getsource(CUSTODY.linux_signature_errors)
        self.assertNotIn(".exists()", src)
        self.assertIn("open_trusted_cosign_key", src)
        self.assertNotIn("{filename}.cosign.pub", src)

    def test_linux_cosign_uses_canonical_descriptor_not_adjacent_or_pathname(self) -> None:
        downloads = self.root / "web" / "downloads"
        downloads.mkdir(parents=True)
        original = b"ORIGINAL-LINUX-BYTES"
        artifact = downloads / LINUX_NAME
        artifact.write_bytes(original)
        (downloads / f"{LINUX_NAME}.sigstore.json").write_bytes(b"{}\n")
        (downloads / f"{LINUX_NAME}.cosign.pub").write_text(
            "ATTACKER-KEY\n", encoding="ascii"
        )
        (self.root / "trusted.pub").write_text("TRUSTED-KEY\n", encoding="ascii")
        artifact_fd = os.open(artifact, os.O_RDONLY | os.O_CLOEXEC)
        self.addCleanup(os.close, artifact_fd)
        swapped = downloads / "swapped-linux.bin"
        swapped.write_bytes(b"SWAPPED-LINUX-BYTES")
        os.replace(swapped, artifact)
        captured: dict[str, Any] = {}

        def fake_key(label: str) -> CUSTODY.OpenedRelative:
            return CUSTODY.open_nofollow_file(
                self.root, "trusted.pub", label, max_bytes=4096
            )

        class FakeSigning:
            def validate_standard_bundle(self, path: str) -> None:
                captured["bundle"] = path

            @contextlib.contextmanager
            def open_authenticated_cosign(self, *_path: str) -> Any:
                yield 7

            def _proc_fd_path(self, fd: int, label: str) -> str:
                return f"/dev/fd/{fd}"

            def _cosign_executable(self, fd: int, label: str) -> str:
                return f"/dev/fd/{fd}"

        real_load = CUSTODY.load_pinned_module
        real_key = CUSTODY.open_trusted_cosign_key
        real_run = CUSTODY.subprocess.run

        def fake_load(relative: str, digest: str) -> Any:
            if relative == CUSTODY.LINUX_SIGNING_RELATIVE:
                return FakeSigning()
            return real_load(relative, digest)

        def fake_run(argv: Any, **kwargs: Any) -> Any:
            captured["argv"] = list(argv)
            captured["pass_fds"] = kwargs.get("pass_fds")
            arguments = list(argv)
            for name, flag in (("artifact_bytes", "verify-blob"), ("key_bytes", "--key")):
                ref = arguments[arguments.index(flag) + 1]
                if ref.startswith("/dev/fd/") or ref.startswith("/proc/self/fd/"):
                    fd = int(ref.rsplit("/", 1)[1])
                    captured[name] = os.pread(fd, 1 << 20, 0)
                else:
                    captured[name] = Path(ref).read_bytes()

            class Done:
                returncode = 0

            return Done()

        CUSTODY.load_pinned_module = fake_load  # type: ignore[method-assign]
        CUSTODY.open_trusted_cosign_key = fake_key  # type: ignore[method-assign]
        CUSTODY.subprocess.run = fake_run  # type: ignore[method-assign]
        try:
            errors = CUSTODY.linux_signature_errors(
                self.root,
                LINUX_NAME,
                original,
                {CUSTODY.LINUX_SIGNING_RELATIVE: "0" * 64},
                "artifact linux",
                artifact_fd=artifact_fd,
            )
        finally:
            CUSTODY.load_pinned_module = real_load  # type: ignore[method-assign]
            CUSTODY.open_trusted_cosign_key = real_key  # type: ignore[method-assign]
            CUSTODY.subprocess.run = real_run  # type: ignore[method-assign]
        self.assertEqual(errors, [])
        argv = captured["argv"]
        artifact_arg = argv[argv.index("verify-blob") + 1]
        key_arg = argv[argv.index("--key") + 1]
        # Cosign must verify the exact held bytes and the canonical trusted key,
        # never the swapped pathname or the artifact-adjacent key. Linux passes
        # descriptor paths; macOS (whose /dev/fd shares the file offset) passes
        # private snapshots of the held bytes.
        self.assertEqual(captured["artifact_bytes"], original)
        self.assertEqual(captured["key_bytes"], b"TRUSTED-KEY\n")
        if sys.platform != "darwin":
            self.assertTrue(
                artifact_arg.startswith("/dev/fd/")
                or artifact_arg.startswith("/proc/self/fd/"),
                artifact_arg,
            )
            self.assertTrue(
                key_arg.startswith("/dev/fd/") or key_arg.startswith("/proc/self/fd/"),
                key_arg,
            )
            self.assertIn(artifact_fd, captured["pass_fds"])
        self.assertNotIn(str(artifact.resolve()), argv)
        self.assertNotIn(str((downloads / f"{LINUX_NAME}.cosign.pub").resolve()), argv)
        self.assertEqual(os.pread(artifact_fd, len(original), 0), original)

    def test_windows_authenticode_leaf_sha256_must_match_policy(self) -> None:
        class FakeWindows:
            def authenticode_leaf_identity(self, filename: str, data: bytes) -> dict[str, str]:
                return {"sha256": "1" * 64, "common_name": "WINS VPN INC."}

            def authenticode_custody_policy(
                self, filename: str, data: bytes, leaf: dict[str, str]
            ) -> dict[str, str]:
                raise AssertionError("policy must not run on an unbound leaf")

        real = CUSTODY.load_pinned_module

        def fake_load(relative: str, digest: str) -> Any:
            if relative == CUSTODY.WINDOWS_GATE_RELATIVE:
                return FakeWindows()
            return real(relative, digest)

        CUSTODY.load_pinned_module = fake_load  # type: ignore[method-assign]
        try:
            errors = CUSTODY.windows_signature_errors(
                b"MZ",
                "WinsVPN-Setup.exe",
                {CUSTODY.WINDOWS_GATE_RELATIVE: "0" * 64},
                "artifact windows",
                policy_leaf_sha256="c" * 64,
            )
        finally:
            CUSTODY.load_pinned_module = real  # type: ignore[method-assign]
        self.assertIn("not bound to policy", " ".join(errors))

    def test_windows_matching_leaf_sha256_invokes_custody_policy(self) -> None:
        called = {"policy": 0}

        class FakeWindows:
            def authenticode_leaf_identity(self, filename: str, data: bytes) -> dict[str, str]:
                return {"sha256": "c" * 64}

            def authenticode_custody_policy(
                self, filename: str, data: bytes, leaf: dict[str, str]
            ) -> dict[str, str]:
                called["policy"] += 1
                return {"leaf_sha256": leaf["sha256"]}

        real = CUSTODY.load_pinned_module

        def fake_load(relative: str, digest: str) -> Any:
            if relative == CUSTODY.WINDOWS_GATE_RELATIVE:
                return FakeWindows()
            return real(relative, digest)

        CUSTODY.load_pinned_module = fake_load  # type: ignore[method-assign]
        try:
            errors = CUSTODY.windows_signature_errors(
                pe_bytes(CUSTODY.PE_AMD64),
                "WinsVPN-Setup.exe",
                {CUSTODY.WINDOWS_GATE_RELATIVE: "0" * 64},
                "artifact windows",
                policy_leaf_sha256="c" * 64,
            )
        finally:
            CUSTODY.load_pinned_module = real  # type: ignore[method-assign]
        self.assertEqual(errors, [])
        self.assertEqual(called["policy"], 1)

    def test_android_signature_uses_immutable_snapshot_of_open_descriptor(self) -> None:
        original = b"ORIGINAL-APK-BYTES"
        downloads = self.root / "web" / "downloads"
        downloads.mkdir(parents=True)
        path = downloads / "wins-vpn-android.apk"
        path.write_bytes(original)
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        swapped = downloads / "swapped-android.apk"
        swapped.write_bytes(b"SWAPPED-APK-BYTES")
        os.replace(swapped, path)
        captured: dict[str, Any] = {}

        class FakeAudit:
            def public_binary_identity_errors(
                self, platform: str, artifact_path: Path
            ) -> list[str]:
                captured["platform"] = platform
                captured["path"] = str(artifact_path)
                captured["bytes"] = Path(artifact_path).read_bytes()
                return ["forced-android-error"]

        real = CUSTODY.load_pinned_module

        def fake_load(relative: str, digest: str) -> Any:
            if relative == CUSTODY.WEBSITE_AUDIT_RELATIVE:
                return FakeAudit()
            return real(relative, digest)

        CUSTODY.load_pinned_module = fake_load  # type: ignore[method-assign]
        try:
            errors = CUSTODY.android_signature_errors(
                fd,
                {CUSTODY.WEBSITE_AUDIT_RELATIVE: "0" * 64},
                "artifact android",
            )
        finally:
            CUSTODY.load_pinned_module = real  # type: ignore[method-assign]
        self.assertEqual(captured["bytes"], original)
        self.assertNotEqual(Path(captured["path"]).resolve(), path.resolve())
        self.assertTrue(str(captured["path"]).endswith(".apk"), captured["path"])
        self.assertIn("forced-android-error", " ".join(errors))

    def test_consume_replay_is_descriptor_rooted_and_locked(self) -> None:
        src = inspect.getsource(CUSTODY.consume_replay) + inspect.getsource(
            CUSTODY._open_replay_journal
        )
        self.assertNotIn("path.parent", src)
        self.assertNotIn("O_APPEND", src)
        self.assertIn("LOCK_EX", src)
        self.assertIn("dir_fd", src)
        self.assertIn("_write_all", src)
        self.assertIn("_require_root_owned", src)
        self.assertNotIn("os.open(parent", src)

    def test_replay_web_symlink_into_artifacts_is_refused(self) -> None:
        seed_pending(self.root)
        evil = self.root / ".artifacts" / "attacker"
        (evil / "releases").mkdir(parents=True)
        web = self.root / "web"
        web.rename(self.root / "web.real")
        web.symlink_to(evil)
        with self.assertRaisesRegex(CUSTODY.WebsiteDownloadCustodyError, "symlink"):
            CUSTODY.consume_replay(
                self.root,
                issuance_id=ISSUANCE_ID,
                nonce=LINUX_NONCE,
                challenge_nonce=CHALLENGE_NONCE,
                owner_evidence_sha256="d" * 64,
                artifact_sha256="a" * 64,
                now=NOW,
            )
        self.assertFalse((evil / "releases" / CUSTODY.REPLAY_RELATIVE.name).exists())

    def test_replay_ancestor_swap_after_journal_open_cannot_double_consume(self) -> None:
        seed_pending(self.root)
        evil = self.root / ".artifacts" / "evil-web"
        (evil / "releases").mkdir(parents=True)
        real = CUSTODY._open_replay_journal

        def hook(root: Path) -> tuple[int, int, int, os.stat_result, os.stat_result]:
            result = real(root)
            web = root / "web"
            web.rename(root / "web.orig")
            evil.rename(web)
            return result

        CUSTODY._open_replay_journal = hook  # type: ignore[method-assign]
        try:
            CUSTODY.consume_replay(
                self.root,
                issuance_id=ISSUANCE_ID,
                nonce=LINUX_NONCE,
                challenge_nonce=CHALLENGE_NONCE,
                owner_evidence_sha256="d" * 64,
                artifact_sha256="a" * 64,
                now=NOW,
            )
        finally:
            CUSTODY._open_replay_journal = real  # type: ignore[method-assign]
        if (self.root / "web").exists() and (self.root / "web.orig").exists():
            (self.root / "web").rename(self.root / ".artifacts" / "used-evil-web")
            (self.root / "web.orig").rename(self.root / "web")
        with self.assertRaisesRegex(
            CUSTODY.WebsiteDownloadCustodyError, "already consumed"
        ):
            CUSTODY.consume_replay(
                self.root,
                issuance_id=ISSUANCE_ID,
                nonce=LINUX_NONCE,
                challenge_nonce=CHALLENGE_NONCE,
                owner_evidence_sha256="d" * 64,
                artifact_sha256="a" * 64,
                now=NOW,
            )

    def test_concurrent_replay_consume_is_one_use(self) -> None:
        seed_pending(self.root)
        real = CUSTODY._open_replay_journal
        gate = threading.Barrier(2)

        def hook(root: Path) -> tuple[int, int, int, os.stat_result, os.stat_result]:
            result = real(root)
            gate.wait(timeout=5)
            return result

        CUSTODY._open_replay_journal = hook  # type: ignore[method-assign]
        outcomes: list[str] = []

        def worker() -> None:
            try:
                CUSTODY.consume_replay(
                    self.root,
                    issuance_id=ISSUANCE_ID,
                    nonce=LINUX_NONCE,
                    challenge_nonce=CHALLENGE_NONCE,
                    owner_evidence_sha256="d" * 64,
                    artifact_sha256="a" * 64,
                    now=NOW,
                )
                outcomes.append("ok")
            except CUSTODY.WebsiteDownloadCustodyError as exc:
                outcomes.append(str(exc))

        try:
            threads = [threading.Thread(target=worker) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=8)
        finally:
            CUSTODY._open_replay_journal = real  # type: ignore[method-assign]
        self.assertEqual(outcomes.count("ok"), 1, outcomes)
        self.assertTrue(any("already consumed" in item for item in outcomes), outcomes)
        body = (self.root / CUSTODY.REPLAY_RELATIVE).read_bytes()
        lines = [line for line in body.split(b"\n") if line]
        self.assertEqual(len(lines), 1, body)

    def test_short_replay_write_still_persists_a_complete_record(self) -> None:
        seed_pending(self.root)
        real_write = os.write
        calls = {"n": 0}

        def torn(fd: int, data: bytes) -> int:
            raw = data.tobytes() if isinstance(data, memoryview) else bytes(data)
            if (
                b"winsvpn-website-download-custody-replay-v1" in raw
                and calls["n"] == 0
            ):
                calls["n"] += 1
                return real_write(fd, raw[: max(1, len(raw) // 3)])
            return real_write(fd, data)

        os.write = torn  # type: ignore[method-assign]
        try:
            CUSTODY.consume_replay(
                self.root,
                issuance_id=ISSUANCE_ID,
                nonce=LINUX_NONCE,
                challenge_nonce=CHALLENGE_NONCE,
                owner_evidence_sha256="d" * 64,
                artifact_sha256="a" * 64,
                now=NOW,
            )
        finally:
            os.write = real_write  # type: ignore[method-assign]
        body = (self.root / CUSTODY.REPLAY_RELATIVE).read_bytes()
        self.assertTrue(body.endswith(b"\n"), body)
        records = CUSTODY.load_replay_log(self.root)
        self.assertEqual(len(records), 1)

    def test_replay_write_failure_does_not_leave_a_truncated_journal(self) -> None:
        seed_pending(self.root)
        real_write = os.write

        def fail_write(fd: int, data: bytes) -> int:
            raw = data.tobytes() if isinstance(data, memoryview) else bytes(data)
            if CUSTODY.REPLAY_RECORD_SCHEMA.encode("ascii") in raw:
                real_write(fd, raw[:12])
                return 0
            return real_write(fd, data)

        os.write = fail_write  # type: ignore[method-assign]
        try:
            with self.assertRaisesRegex(
                CUSTODY.WebsiteDownloadCustodyError, "truncated"
            ):
                CUSTODY.consume_replay(
                    self.root,
                    issuance_id=ISSUANCE_ID,
                    nonce=LINUX_NONCE,
                    challenge_nonce=CHALLENGE_NONCE,
                    owner_evidence_sha256="d" * 64,
                    artifact_sha256="a" * 64,
                    now=NOW,
                )
        finally:
            os.write = real_write  # type: ignore[method-assign]
        log = self.root / CUSTODY.REPLAY_RELATIVE
        body = log.read_bytes() if log.is_file() else b""
        self.assertEqual(body, b"")
        self.assertEqual(CUSTODY.load_replay_log(self.root), {})

    def test_world_writable_replay_journal_is_refused(self) -> None:
        seed_pending(self.root)
        log = self.root / CUSTODY.REPLAY_RELATIVE
        log.write_bytes(b"")
        os.chmod(log, 0o666)
        with self.assertRaisesRegex(
            CUSTODY.WebsiteDownloadCustodyError, "group/other-writable|mode 0600"
        ):
            CUSTODY.consume_replay(
                self.root,
                issuance_id=ISSUANCE_ID,
                nonce=LINUX_NONCE,
                challenge_nonce=CHALLENGE_NONCE,
                owner_evidence_sha256="d" * 64,
                artifact_sha256="a" * 64,
                now=NOW,
            )

    def test_group_writable_replay_ancestor_is_refused(self) -> None:
        seed_pending(self.root)
        releases = self.root / "web" / "releases"
        os.chmod(releases, 0o777)
        with self.assertRaisesRegex(
            CUSTODY.WebsiteDownloadCustodyError, "group/other-writable"
        ):
            CUSTODY.consume_replay(
                self.root,
                issuance_id=ISSUANCE_ID,
                nonce=LINUX_NONCE,
                challenge_nonce=CHALLENGE_NONCE,
                owner_evidence_sha256="d" * 64,
                artifact_sha256="a" * 64,
                now=NOW,
            )

    def test_hardlinked_replay_journal_is_refused_on_consume(self) -> None:
        seed_pending(self.root)
        CUSTODY.consume_replay(
            self.root,
            issuance_id=ISSUANCE_ID,
            nonce=LINUX_NONCE,
            challenge_nonce=CHALLENGE_NONCE,
            owner_evidence_sha256="d" * 64,
            artifact_sha256="a" * 64,
            now=NOW,
        )
        log = self.root / CUSTODY.REPLAY_RELATIVE
        alias = self.root / "journal-alias"
        os.link(log, alias)
        with self.assertRaisesRegex(
            CUSTODY.WebsiteDownloadCustodyError, "regular file|filesystem link"
        ):
            CUSTODY.consume_replay(
                self.root,
                issuance_id=ISSUANCE_ID,
                nonce="e" * 32,
                challenge_nonce=CHALLENGE_NONCE,
                owner_evidence_sha256="d" * 64,
                artifact_sha256="a" * 64,
                now=NOW,
            )


    def test_stale_linux_x86_64_architecture_label_is_refused(self) -> None:
        write_available_linux(
            self.root,
            mutate_manifest_artifact={"architecture": ["x86_64"]},
        )
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("stale architecture artifact", report.summary)
        self.assertFalse(report.summary.startswith("PASS"), report.summary)

    def test_missing_winn_provenance_cannot_publish(self) -> None:
        write_available_linux(self.root)
        manifest = json.loads(
            (self.root / "web" / "releases" / "downloads.json").read_text(encoding="ascii")
        )
        del manifest["artifacts"][LINUX_INDEX]["artifact"]["winn_provenance"]
        write_json(self.root / "web" / "releases" / "downloads.json", manifest)
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("Winn provenance", report.summary)
        self.assertFalse(report.summary.startswith("PASS"), report.summary)

    def test_winn_v1_as_primary_cannot_publish(self) -> None:
        write_available_linux(self.root)
        manifest = json.loads(
            (self.root / "web" / "releases" / "downloads.json").read_text(encoding="ascii")
        )
        manifest["artifacts"][LINUX_INDEX]["artifact"]["winn_provenance"]["primary"] = "winn/1"
        write_json(self.root / "web" / "releases" / "downloads.json", manifest)
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("Winn primary is not winn/3", report.summary)

    def test_github_release_cannot_publish_linux(self) -> None:
        write_available_linux(
            self.root,
            mutate_delivery={
                "kind": "github_release",
                "url": (
                    "https://github.com/winsvpn/winsvpn-downloads/releases/download/"
                    f"v1.0.16+33/{LINUX_NAME}"
                ),
            },
        )
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn(
            "GitHub is backup-only and is not website publication authority",
            report.summary,
        )

    def test_mutable_latest_url_cannot_publish(self) -> None:
        write_available_linux(
            self.root,
            mutate_delivery={
                "url": "https://winsvpn.org/releases/latest/download/wins-vpn-linux-x64.tar.gz"
            },
        )
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertIn("mutable latest-release route", report.summary)

    def test_missing_hosted_privacy_receipt_cannot_publish(self) -> None:
        write_available_linux(self.root)
        (self.root / "web" / "downloads" / f"{LINUX_NAME}.privacy.json").unlink()
        report = self.evaluate()
        self.assertFalse(report.ok)
        self.assertTrue(
            "privacy receipt" in report.summary or "absent" in report.summary,
            report.summary,
        )



UNSIGNED_X64 = "WinsVPN-UNSIGNED-LOCAL-Setup.exe"


def unsigned_windows_artifact(
    *, filename: str = UNSIGNED_X64, architecture: list[str] | None = None, label: str = "Unsigned"
) -> dict[str, Any]:
    waiver = "9" * 64
    return {
        "filename": filename,
        "sha256": "1" * 64,
        "bytes": 10,
        "canonical_release": CUSTODY.CANONICAL_RELEASE,
        "package_identity": CUSTODY.PUBLIC_PACKAGE_IDENTITY,
        "version": CUSTODY.CANONICAL_VERSION,
        "architecture": architecture or ["x64"],
        "signature": {"kind": CUSTODY.UNSIGNED_SIGNATURE_KIND, "sha256": waiver},
        "unsigned_waiver": {
            "label": label,
            "waiver_filename": "download-unsigned-waiver.json",
            "waiver_sha256": waiver,
        },
        **hosted_bindings(filename, "d" * 64, "e" * 64, "f" * 64),
        "publication_receipt": {
            "kind": CUSTODY.PUBLICATION_RECEIPT_KIND,
            "receipt_filename": f"{filename}.publication.json",
            "receipt_sha256": "a" * 64,
        },
    }


def waiver_document(**changes: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": CUSTODY.UNSIGNED_WAIVER_SCHEMA,
        "release_id": CUSTODY.CANONICAL_WEBSITE_RELEASE_ID,
        "canonical_release": CUSTODY.CANONICAL_RELEASE,
        "platform": "windows",
        "entries": ["windows-x64", "windows-arm64"],
        "architectures": ["x64", "arm64"],
        "public_label": "Unsigned",
        "user_notice": "Unsigned installer: Windows SmartScreen reports an unknown publisher.",
        "owner_ruling": {"reference": CUSTODY.UNSIGNED_WAIVER_PUBLIC_REFERENCE},
    }
    payload.update(changes)
    return payload


class PerArchitectureReleaseRuleTests(unittest.TestCase):
    """Owner ruling 2026-10-25: per-architecture entries, unsigned waiver, R2."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ledger = use_fresh_release_ledger(self)

    def test_manifest_has_one_entry_per_architecture(self) -> None:
        self.assertEqual(CUSTODY.MANIFEST_SCHEMA, "winsvpn-download-manifest-v2")
        self.assertEqual(
            [item[0] for item in CUSTODY.PLATFORM_CONTRACT],
            ["windows-x64", "windows-arm64", "android", "linux-x64", "linux-arm64", "macos", "ios"],
        )
        live = json.loads((ROOT / "web" / "releases" / "downloads.json").read_text("ascii"))
        self.assertEqual(
            [entry["id"] for entry in live["artifacts"]],
            [item[0] for item in CUSTODY.PLATFORM_CONTRACT],
        )
        self.assertEqual(
            {entry["id"]: entry["status"] for entry in live["artifacts"]}["macos"],
            CUSTODY.STORE_PENDING_STATUS,
        )

    def test_v1_manifest_schema_is_refused(self) -> None:
        manifest = pending_manifest()
        manifest["schema"] = "winsvpn-download-manifest-v1"
        write_json(self.root / "web" / "releases" / "downloads.json", manifest)
        with self.assertRaisesRegex(CUSTODY.WebsiteDownloadCustodyError, "unsupported"):
            CUSTODY.load_manifest(self.root)

    def test_store_pending_is_only_valid_for_app_store_entries(self) -> None:
        entry = {
            "id": "linux-x64",
            "label": "Linux x64",
            "status": CUSTODY.STORE_PENDING_STATUS,
            "delivery": {"kind": "direct", "url": None},
            "artifact": {"filename": None, "sha256": None, "bytes": None},
        }
        errors = CUSTODY.pending_entry_errors(entry, "linux-x64", "artifact linux-x64", entry["status"])
        self.assertTrue(any("store_pending is valid only" in item for item in errors), errors)
        entry.update({"id": "ios", "delivery": {"kind": "store", "url": None}})
        self.assertEqual(
            CUSTODY.pending_entry_errors(entry, "ios", "artifact ios", entry["status"]), []
        )

    def test_unsigned_windows_entry_with_visible_label_is_schema_valid(self) -> None:
        self.assertEqual(
            CUSTODY.available_artifact_schema_errors(
                "windows-x64", unsigned_windows_artifact(), "artifact windows-x64"
            ),
            [],
        )

    def test_unsigned_windows_entry_without_unsigned_label_is_refused(self) -> None:
        errors = CUSTODY.available_artifact_schema_errors(
            "windows-x64", unsigned_windows_artifact(label="Signed"), "artifact windows-x64"
        )
        self.assertTrue(any("labelled Unsigned" in item for item in errors), errors)
        artifact = unsigned_windows_artifact()
        del artifact["unsigned_waiver"]
        errors = CUSTODY.available_artifact_schema_errors("windows-x64", artifact, "p")
        self.assertTrue(errors)

    def test_unsigned_artifact_cannot_hide_behind_signed_name(self) -> None:
        errors = CUSTODY.available_artifact_schema_errors(
            "windows-x64",
            unsigned_windows_artifact(filename="WinsVPN-Setup.exe"),
            "artifact windows-x64",
        )
        self.assertTrue(any("canonical target filename" in item for item in errors), errors)

    def test_unsigned_waiver_is_windows_only(self) -> None:
        artifact = unsigned_windows_artifact(filename=LINUX_NAME)
        errors = CUSTODY.available_artifact_schema_errors("linux-x64", artifact, "artifact linux-x64")
        self.assertTrue(any("only Windows" in item for item in errors), errors)

    def test_entry_architecture_must_match_entry(self) -> None:
        errors = CUSTODY.available_artifact_schema_errors(
            "windows-arm64",
            unsigned_windows_artifact(architecture=["x64"]),
            "artifact windows-arm64",
        )
        self.assertTrue(any("windows-arm64 manifest entry" in item for item in errors), errors)

    def test_unsigned_waiver_document_is_release_scoped_and_owner_recorded(self) -> None:
        path = self.root / CUSTODY.UNSIGNED_WAIVER_RELATIVE
        write_json(path, waiver_document())
        payload, digest = CUSTODY.load_unsigned_waiver(self.root)
        self.assertEqual(payload["public_label"], "Unsigned")
        self.assertEqual(digest, sha256_hex(path.read_bytes()))
        for change, pattern in (
            ({"release_id": "v1.0.14+29"}, "current 1.0.16\\+33"),
            ({"public_label": "Signed"}, "must be Unsigned"),
            ({"platform": "linux"}, "only Windows"),
            ({"architectures": ["arm64", "x64"]}, "architectures"),
            (
                {"owner_ruling": {"reference": "wrong"}},
                "public waiver reference",
            ),
        ):
            path.unlink()
            write_json(path, waiver_document(**change))
            with self.assertRaisesRegex(CUSTODY.WebsiteDownloadCustodyError, pattern):
                CUSTODY.load_unsigned_waiver(self.root)

    def test_windows_installers_are_the_reviewed_x64_inno_loader(self) -> None:
        self.assertEqual(CUSTODY.windows_type_errors(pe_bytes(CUSTODY.PE_AMD64), "x64", "p"), [])
        self.assertEqual(CUSTODY.windows_type_errors(pe_bytes(CUSTODY.PE_AMD64), "arm64", "p"), [])
        for payload in (
            pe_bytes(CUSTODY.PE_ARM64),
            pe_bytes(0x014C, magic=0x10B),
            pe_bytes(CUSTODY.PE_AMD64, magic=0x10B),
        ):
            errors = CUSTODY.windows_type_errors(payload, "arm64", "p")
            self.assertTrue(any("PE32+ x64 Inno loader" in item for item in errors), errors)

    def test_unsigned_label_must_be_true_and_version_current(self) -> None:
        class FakeWindows:
            def __init__(self, cert_size: int, version: str) -> None:
                self.cert_size = cert_size
                self.version = version

            def _parse_pe_image(self, *_args: Any, **kwargs: Any) -> dict[str, int]:
                assert kwargs["require_certificate"] is False
                return {"cert_size": self.cert_size}

            def pe_version_info(self, *_args: Any, **kwargs: Any) -> dict[str, str]:
                assert kwargs["require_certificate"] is False
                return {
                    "ProductVersion": self.version,
                    "FileVersion": f"{self.version}.33",
                    "ProductName": "Win's VPN",
                }

        real_load = CUSTODY.load_pinned_module
        pins = {CUSTODY.WINDOWS_GATE_RELATIVE: "0" * 64}
        try:
            for fake, expected in (
                (FakeWindows(0, "1.0.16"), None),
                (FakeWindows(4096, "1.0.16"), "labelled Unsigned"),
                (FakeWindows(0, "1.0.14"), "1.0.16.33"),
            ):
                CUSTODY.load_pinned_module = lambda *_args, fake=fake: fake  # type: ignore[method-assign]
                errors = CUSTODY.windows_unsigned_errors(b"MZ", UNSIGNED_X64, pins, "p")
                if expected is None:
                    self.assertEqual(errors, [])
                else:
                    self.assertTrue(any(expected in item for item in errors), errors)
        finally:
            CUSTODY.load_pinned_module = real_load  # type: ignore[method-assign]

    def test_privacy_scan_evidence_must_pass_for_the_same_target(self) -> None:
        good = receipt_evidence(CUSTODY.PRIVACY_RECEIPT_KIND, "linux-x64", LINUX_NAME)
        self.assertEqual(CUSTODY.privacy_scan_errors("linux-x64", good, "p"), [])
        for key, value in (
            ("matched_labels", ["SECRETS_KANSAS_SECRETS_SMTP_PASS"]),
            ("result", "fail"),
            ("target_id", "linux-arm64-package"),
            ("contract", "self-asserted"),
        ):
            receipt = json.loads(json.dumps(good))
            receipt["scan"][key] = value
            self.assertTrue(CUSTODY.privacy_scan_errors("linux-x64", receipt, "p"), key)

    def test_release_build_evidence_binds_target_signing_and_name(self) -> None:
        artifact = unsigned_windows_artifact(filename="WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe", architecture=["arm64"])
        good = receipt_evidence(
            CUSTODY.RELEASE_RECEIPT_KIND, "windows-arm64", "WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe"
        )
        self.assertEqual(CUSTODY.release_build_errors("windows-arm64", good, artifact, "p"), [])
        for key, value, pattern in (
            ("toolchain_target", "windows-x64-inno-unsigned", "windows-arm64-inno-unsigned"),
            ("signing", "authenticode", "unsigned label disagrees"),
            ("source_artifact_name", "WinsVPN-Setup-arm64.exe", "never renamed"),
            ("shared_revision", "short", "40-hex"),
        ):
            receipt = json.loads(json.dumps(good))
            receipt["build"][key] = value
            errors = CUSTODY.release_build_errors("windows-arm64", receipt, artifact, "p")
            self.assertTrue(any(pattern in item for item in errors), (key, errors))

    def test_winn_engine_evidence_binds_pinned_authority_and_entry_engines(self) -> None:
        good = receipt_evidence(CUSTODY.WINN_PROVENANCE_KIND, "windows-arm64", "x")
        self.assertEqual(CUSTODY.winn_engine_errors("windows-arm64", good, "p"), [])
        mutations = (
            ("signature_public_key", "0" * 64, "pinned Winn release authority"),
            ("targets", ["datapath-windows-amd64", "winn3-relay-windows-amd64"], "engines"),
            ("verified_by", "self", "verified by"),
        )
        for key, value, pattern in mutations:
            receipt = json.loads(json.dumps(good))
            receipt["engine_release"][key] = value
            errors = CUSTODY.winn_engine_errors("windows-arm64", receipt, "p")
            self.assertTrue(any(pattern in item for item in errors), (key, errors))
        receipt = json.loads(json.dumps(good))
        receipt["engine_release"]["binding"]["line"] = receipt["engine_release"]["binding"]["line"].replace("arm64", "x64")
        self.assertTrue(CUSTODY.winn_engine_errors("windows-arm64", receipt, "p"))
        linux = receipt_evidence(CUSTODY.WINN_PROVENANCE_KIND, "linux-x64", LINUX_NAME)
        linux["engine_release"]["binding"] = good["engine_release"]["binding"]
        errors = CUSTODY.winn_engine_errors("linux-x64", linux, "p")
        self.assertTrue(any("measured inside the tarball" in item for item in errors), errors)

    def test_linux_winn_engine_is_measured_inside_the_tarball(self) -> None:
        engine = b"\x7fELF-winn-datapath-bytes"
        buffer = io.BytesIO()
        import gzip
        import tarfile

        with tarfile.open(fileobj=buffer, mode="w") as archive:
            info = tarfile.TarInfo("./winn-datapath")
            info.size = len(engine)
            archive.addfile(info, io.BytesIO(engine))
        data = gzip.compress(buffer.getvalue())
        downloads = self.root / "web" / "downloads"
        downloads.mkdir(parents=True)
        for measured, expect_ok in ((sha256_hex(engine), True), ("0" * 64, False)):
            receipt = hosted_identity_receipt(
                kind=CUSTODY.WINN_PROVENANCE_KIND,
                schema=CUSTODY.WINN_PROVENANCE_SCHEMA,
                digest=sha256_hex(data),
                byte_count=len(data),
            )
            receipt["engine_release"]["binding"]["sha256"] = measured
            body = CUSTODY.canonical_json(receipt) + b"\n"
            (downloads / f"{LINUX_NAME}.winn.json").write_bytes(body)
            artifact = {"winn_provenance": winn_binding(LINUX_NAME, sha256_hex(body))}
            errors = CUSTODY.linux_winn_member_errors(self.root, artifact, data, "p")
            if expect_ok:
                self.assertEqual(errors, [])
            else:
                self.assertTrue(any("signed engine release digest" in item for item in errors), errors)

    def test_linux_decompression_bound_admits_the_real_release_size(self) -> None:
        # p5cbb83b7 linux-x64 inflates to 100945920 bytes, arm64 to 95744000.
        self.assertGreater(CUSTODY.MAX_LINUX_UNCOMPRESSED, 100945920)
        self.assertLessEqual(CUSTODY.MAX_LINUX_UNCOMPRESSED, 256 * 1024 * 1024)

    def test_owner_evidence_must_quote_the_publish_ruling(self) -> None:
        seed_pending(self.root)
        owner = owner_evidence_document(
            [linux_owner_platform(digest="1" * 64, byte_count=10)],
            issued_utc="2026-08-24T15:00:00Z",
        )
        owner["owner_ruling"]["lines"] = ['- Windows: "Ship unsigned".']
        write_json(self.root / "web" / "releases" / "owner-publication-evidence.json", owner)
        with self.assertRaisesRegex(CUSTODY.WebsiteDownloadCustodyError, "Publish now"):
            CUSTODY.load_owner_evidence(self.root, now=NOW)

    def test_owner_evidence_unsigned_kind_is_windows_only(self) -> None:
        seed_pending(self.root)
        platform = linux_owner_platform(digest="1" * 64, byte_count=10)
        platform["signature_kind"] = CUSTODY.UNSIGNED_SIGNATURE_KIND
        owner = owner_evidence_document([platform], issued_utc="2026-08-24T15:00:00Z")
        write_json(self.root / "web" / "releases" / "owner-publication-evidence.json", owner)
        with self.assertRaisesRegex(CUSTODY.WebsiteDownloadCustodyError, "unsigned waiver"):
            CUSTODY.load_owner_evidence(self.root, now=NOW)

    def test_custody_metadata_pins_r2_prefix_and_unsigned_names(self) -> None:
        seed_pending(self.root)
        self.assertEqual(CUSTODY.load_custody_metadata(self.root)["r2_object_prefix"], "downloads/sha256/")
        document = CUSTODY.pending_custody_document()
        document["r2_object_prefix"] = "public/"
        write_json(self.root / "web" / "releases" / "download-custody.json", document)
        with self.assertRaisesRegex(CUSTODY.WebsiteDownloadCustodyError, "R2 object prefix"):
            CUSTODY.load_custody_metadata(self.root)

    def test_per_platform_launch_passes_with_other_entries_pending(self) -> None:
        write_available_linux(self.root)
        (self.root / "web" / "downloads" / f"{LINUX_NAME}.sigstore.json").write_bytes(b"{}\n")
        real_measured = CUSTODY.measured_artifact_errors
        CUSTODY.measured_artifact_errors = lambda *_args, **_kwargs: []  # type: ignore[method-assign]
        try:
            report = CUSTODY.evaluate_tree(self.root, now=NOW)
        finally:
            CUSTODY.measured_artifact_errors = real_measured  # type: ignore[method-assign]
        self.assertTrue(report.ok, report.summary)
        self.assertTrue(report.summary.startswith("PASS 1 public download(s)"), report.summary)
        self.assertIn("not published: windows-x64, windows-arm64, android, linux-arm64, macos, ios", report.summary)



class PinnedGithubReleaseDeliveryTests(unittest.TestCase):
    """Owner update 2026-10-25: Workers Free plan, binaries on one pinned release."""

    PINNED = (
        "https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.16-33/"
        + LINUX_NAME
    )

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ledger = use_fresh_release_ledger(self)

    def evaluate(self, url: str, *, ruling_lines: list[str] | None = None) -> CUSTODY.CustodyReport:
        lines = ruling_lines if ruling_lines is not None else OWNER_RULING["lines"] + [
            "- Desktop downloads (2026-10-25): host the binaries on the public repo winsvpn/winsvpn-downloads."
        ]
        write_available_linux(
            self.root,
            mutate_delivery={"kind": "github_release", "url": url},
            mutate_owner={"owner_ruling": {**OWNER_RULING, "lines": lines}},
        )
        (self.root / "web" / "downloads" / f"{LINUX_NAME}.sigstore.json").write_bytes(b"{}\n")
        real_measured = CUSTODY.measured_artifact_errors
        CUSTODY.measured_artifact_errors = lambda *_args, **_kwargs: []  # type: ignore[method-assign]
        try:
            return CUSTODY.evaluate_tree(self.root, now=NOW)
        finally:
            CUSTODY.measured_artifact_errors = real_measured  # type: ignore[method-assign]

    def test_pinned_github_release_asset_can_publish_with_every_receipt(self) -> None:
        self.assertEqual(CUSTODY.github_release_url(LINUX_NAME), self.PINNED)
        report = self.evaluate(self.PINNED)
        self.assertTrue(report.ok, report.summary)

    def test_github_hosting_needs_the_recorded_owner_ruling(self) -> None:
        report = self.evaluate(self.PINNED, ruling_lines=list(OWNER_RULING["lines"]))
        self.assertFalse(report.ok)
        self.assertIn("names winsvpn/winsvpn-downloads", report.summary)

    def test_every_other_github_url_stays_backup_only(self) -> None:
        for url in (
            self.PINNED.replace("v1.0.16-33", "v1.0.16+33"),
            self.PINNED.replace("v1.0.16-33", "v1.0.0"),
            self.PINNED.replace("v1.0.16-33", "latest"),
            self.PINNED.replace("winsvpn/winsvpn-downloads", "winsvpn/winsvpn-download"),
            self.PINNED.replace("https://github.com", "https://github.com.evil.example"),
            self.PINNED.replace("https://", "http://"),
            self.PINNED + "?raw=1",
            self.PINNED.replace(LINUX_NAME, "wins-vpn-linux-arm64.tar.gz"),
        ):
            with self.subTest(url=url):
                if (self.root / "web").exists():
                    import shutil

                    shutil.rmtree(self.root / "web")
                report = self.evaluate(url)
                self.assertFalse(report.ok, url)
                self.assertIn("GitHub is backup-only", report.summary)

    def test_receipts_are_still_required_for_github_entries(self) -> None:
        write_available_linux(
            self.root,
            mutate_delivery={"kind": "github_release", "url": self.PINNED},
        )
        (self.root / "web" / "downloads" / f"{LINUX_NAME}.privacy.json").unlink()
        report = CUSTODY.evaluate_tree(self.root, now=NOW)
        self.assertFalse(report.ok)
        self.assertIn("privacy receipt", report.summary)

    def test_custody_metadata_pins_the_github_release_prefix(self) -> None:
        seed_pending(self.root)
        document = CUSTODY.pending_custody_document()
        document["github_release_prefix"] = "https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.0/"
        write_json(self.root / "web" / "releases" / "download-custody.json", document)
        with self.assertRaisesRegex(CUSTODY.WebsiteDownloadCustodyError, "GitHub release prefix"):
            CUSTODY.load_custody_metadata(self.root)



class ReviewRoundOneRegressionTests(unittest.TestCase):
    """Sol review round 1 (DLP-04, DLP-05, DLP-06) at the custody layer."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ledger = use_fresh_release_ledger(self)

    def test_dlp05_android_and_signed_windows_are_outside_this_release(self) -> None:
        write_available_linux(self.root)
        manifest_path = self.root / "web" / "releases" / "downloads.json"
        manifest = json.loads(manifest_path.read_text("ascii"))
        android = json.loads(json.dumps(manifest["artifacts"][LINUX_INDEX]))
        android.update({"id": "android", "label": "Android"})
        manifest["artifacts"][ENTRY_INDEX["android"]] = android
        signed = json.loads(json.dumps(manifest["artifacts"][LINUX_INDEX]))
        signed.update({"id": "windows-x64", "label": "Windows x64"})
        signed["artifact"]["signature"] = {
            "kind": CUSTODY.SIGNATURE_KINDS["windows"],
            "sha256": SIGNER,
        }
        manifest["artifacts"][ENTRY_INDEX["windows-x64"]] = signed
        write_json(manifest_path, manifest)
        report = CUSTODY.evaluate_tree(self.root, now=NOW)
        self.assertFalse(report.ok)
        self.assertIn("artifact android is outside the owner-authorized 1.0.16+33 desktop launch", report.summary)
        self.assertIn("artifact windows-x64 must use the recorded Unsigned owner waiver", report.summary)

    def test_dlp04_a_consumed_challenge_refuses_a_new_issuance_at_the_gate(self) -> None:
        write_available_linux(self.root)
        (self.root / "web" / "downloads" / f"{LINUX_NAME}.sigstore.json").write_bytes(b"{}\n")
        real_measured = CUSTODY.measured_artifact_errors
        CUSTODY.measured_artifact_errors = lambda *_args, **_kwargs: []  # type: ignore[method-assign]
        try:
            self.assertTrue(CUSTODY.evaluate_tree(self.root, now=NOW).ok)
            with self.assertRaisesRegex(CUSTODY.WebsiteDownloadCustodyError, "already consumed"):
                CUSTODY.consume_replay(
                    self.root,
                    issuance_id="e" * 32,
                    nonce="f" * 32,
                    challenge_nonce=CHALLENGE_NONCE,
                    owner_evidence_sha256="e" * 64,
                    artifact_sha256="a" * 64,
                    now=NOW,
                )
        finally:
            CUSTODY.measured_artifact_errors = real_measured  # type: ignore[method-assign]

    def test_argon_f2_nonce_and_issuance_never_reappear_under_another_key(self) -> None:
        seed_pending(self.root)
        CUSTODY.consume_replay(
            self.root,
            issuance_id=ISSUANCE_ID,
            nonce=LINUX_NONCE,
            challenge_nonce=CHALLENGE_NONCE,
            owner_evidence_sha256="d" * 64,
            artifact_sha256="a" * 64,
            now=NOW,
        )
        for issuance, nonce, challenge in (
            ("e" * 32, LINUX_NONCE, "f" * 32),
            (ISSUANCE_ID, "f" * 32, "e" * 32),
        ):
            with self.assertRaisesRegex(CUSTODY.WebsiteDownloadCustodyError, "already consumed"):
                CUSTODY.consume_replay(
                    self.root,
                    issuance_id=issuance,
                    nonce=nonce,
                    challenge_nonce=challenge,
                    owner_evidence_sha256="e" * 64,
                    artifact_sha256="a" * 64,
                    now=NOW,
                )

    def test_dlp06_public_waiver_cannot_carry_ruling_lines(self) -> None:
        path = self.root / CUSTODY.UNSIGNED_WAIVER_RELATIVE
        legacy = waiver_document()
        legacy["owner_ruling"] = dict(legacy["owner_ruling"], lines=['- Windows: "Ship unsigned". PRIVATE'])
        write_json(path, legacy)
        with self.assertRaisesRegex(CUSTODY.WebsiteDownloadCustodyError, "ruling reference is invalid"):
            CUSTODY.load_unsigned_waiver(self.root)



class DurableReleaseLedgerTests(unittest.TestCase):
    """DLP-04 / Argon F-2 cross-clone: the owner-controlled release ledger."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(os.path.realpath(self.temp.name))
        self.ledger = use_fresh_release_ledger(self)

    def passing_root(self, name: str, issuance_id: str) -> Path:
        root = self.base / name
        root.mkdir()
        write_available_linux(root, mutate_owner={"issuance_id": issuance_id})
        (root / "web" / "downloads" / f"{LINUX_NAME}.sigstore.json").write_bytes(b"{}\n")
        return root

    def evaluate(self, root: Path) -> CUSTODY.CustodyReport:
        real_measured = CUSTODY.measured_artifact_errors
        CUSTODY.measured_artifact_errors = lambda *_args, **_kwargs: []  # type: ignore[method-assign]
        try:
            return CUSTODY.evaluate_tree(root, now=NOW)
        finally:
            CUSTODY.measured_artifact_errors = real_measured  # type: ignore[method-assign]

    def test_same_challenge_cannot_publish_from_a_second_clone(self) -> None:
        first = self.passing_root("clone_a", ISSUANCE_ID)
        # The receipt helper binds ISSUANCE_ID; the second clone gets a fresh
        # issuance only in owner evidence, so its receipts also mismatch. Use a
        # matching second clone instead: same evidence copied, which is the
        # attack the ledger must stop.
        second = self.base / "clone_b"
        import shutil

        report = self.evaluate(first)
        self.assertTrue(report.ok, report.summary)
        shutil.copytree(first / "web", second / "web", ignore=shutil.ignore_patterns("download-custody-consumed.jsonl"))
        self.assertFalse((second / "web" / "releases" / "download-custody-consumed.jsonl").exists())
        replay = self.evaluate(second)
        self.assertFalse(replay.ok)
        self.assertIn("durable release ledger", replay.summary)
        lines = self.ledger.read_bytes().splitlines()
        self.assertEqual(len(lines), 1)
        record = json.loads(lines[0])
        self.assertEqual(record["challenge_nonce"], CHALLENGE_NONCE)
        self.assertEqual(stat.S_IMODE(os.stat(self.ledger.parent).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(self.ledger).st_mode), 0o600)

    def test_ledger_is_append_only_and_refuses_reuse_of_any_key(self) -> None:
        def consume(issuance: str, challenge: str, nonce: str) -> None:
            CUSTODY.consume_release_ledger(
                issuance_id=issuance,
                challenge_nonce=challenge,
                owner_evidence_sha256="d" * 64,
                nonces=[nonce],
                artifact_sha256s=["a" * 64],
                now=NOW,
            )

        consume("1" * 32, "2" * 32, "3" * 32)
        first = self.ledger.read_bytes()
        consume("4" * 32, "5" * 32, "6" * 32)
        self.assertTrue(self.ledger.read_bytes().startswith(first))
        for issuance, challenge, nonce in (
            ("7" * 32, "2" * 32, "8" * 32),
            ("1" * 32, "9" * 32, "a" * 32),
            ("b" * 32, "c" * 32, "3" * 32),
        ):
            with self.assertRaisesRegex(CUSTODY.WebsiteDownloadCustodyError, "durable release ledger"):
                consume(issuance, challenge, nonce)
        self.assertEqual(len(self.ledger.read_bytes().splitlines()), 2)

    def test_concurrent_consumers_of_one_challenge_get_exactly_one_success(self) -> None:
        results: list[str] = []

        def worker(index: int) -> None:
            try:
                CUSTODY.consume_release_ledger(
                    issuance_id=f"{index:032x}",
                    challenge_nonce="e" * 32,
                    owner_evidence_sha256="d" * 64,
                    nonces=[f"{index + 100:032x}"],
                    artifact_sha256s=["a" * 64],
                    now=NOW,
                )
                results.append("ok")
            except CUSTODY.WebsiteDownloadCustodyError:
                results.append("refused")

        threads = [threading.Thread(target=worker, args=(index,)) for index in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(results), 6, results)
        self.assertEqual(results.count("ok"), 1, results)

    def test_parse_error_symlink_mode_and_git_tree_are_refused(self) -> None:
        CUSTODY.consume_release_ledger(
            issuance_id="1" * 32, challenge_nonce="2" * 32, owner_evidence_sha256="d" * 64,
            nonces=["3" * 32], artifact_sha256s=["a" * 64], now=NOW,
        )
        with self.ledger.open("ab") as handle:
            handle.write(b"{not json}\n")
        with self.assertRaises(CUSTODY.WebsiteDownloadCustodyError):
            CUSTODY.release_ledger_records()
        self.ledger.unlink()
        target = self.base / "elsewhere.jsonl"
        target.write_bytes(b"")
        os.symlink(target, self.ledger)
        with self.assertRaisesRegex(CUSTODY.WebsiteDownloadCustodyError, "release ledger"):
            CUSTODY.release_ledger_records()
        self.ledger.unlink()
        os.chmod(self.ledger.parent, 0o755)
        with self.assertRaisesRegex(CUSTODY.WebsiteDownloadCustodyError, "0700"):
            CUSTODY.release_ledger_records()
        os.chmod(self.ledger.parent, 0o700)
        repo = self.base / "repo"
        (repo / ".git").mkdir(parents=True)
        os.environ[CUSTODY.RELEASE_LEDGER_ENV] = str(repo / "ledger" / "download-custody-consumed.jsonl")
        with self.assertRaisesRegex(CUSTODY.WebsiteDownloadCustodyError, "git work tree"):
            CUSTODY.consume_release_ledger(
                issuance_id="1" * 32, challenge_nonce="2" * 32, owner_evidence_sha256="d" * 64,
                nonces=["3" * 32], artifact_sha256s=["a" * 64], now=NOW,
            )

    def test_default_ledger_is_the_fixed_owner_path(self) -> None:
        self.assertEqual(
            str(CUSTODY.RELEASE_LEDGER_DEFAULT),
            "/Users/owner/.winsvpn-release-ledger/download-custody-consumed.jsonl",
        )


if __name__ == "__main__":
    unittest.main()
