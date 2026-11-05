#!/usr/bin/env python3
"""Focused Windows receipt-to-artifact binding tests for the cross-store gate."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import pathlib
import secrets
import shutil
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

TOOLS = pathlib.Path(__file__).resolve().parent
import sys

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import test_windows_cross_store_gate_adapters as adapters
import windows_cross_store_artifact_gate as gate
from test_windows_cross_store_gate_adapters import (
    build_receipt_payload,
    installer_pe,
    signed_pe,
    untrusted_signer,
    valid_offline_authenticode_proof,
)


ORIGIN = pathlib.Path(__file__).resolve().parents[1]


class WindowsReceiptArtifactBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name).resolve()
        self._install_repo()
        gate.ROOT = self.repo
        gate._SEEN_UPLOAD_RECEIPT_NONCES.clear()
        gate._SEEN_UPLOAD_RECEIPT_RUN_IDS.clear()

    def tearDown(self) -> None:
        gate.ROOT = ORIGIN
        self.temporary.cleanup()

    def _write(self, relative: str, contents: bytes) -> pathlib.Path:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        os.chmod(path, 0o644)
        return path

    def _copy(self, relative: str) -> pathlib.Path:
        source = ORIGIN / relative
        destination = self.repo / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        os.chmod(destination, 0o644)
        return destination

    def _file_sha256(self, relative: str) -> str:
        return hashlib.sha256((self.repo / relative).read_bytes()).hexdigest()

    def _install_repo(self) -> None:
        shutil.copytree(ORIGIN / "app_store/windows", self.repo / "app_store/windows")
        shutil.copytree(
            ORIGIN / "installer/windows/store", self.repo / "installer/windows/store"
        )
        for relative in (
            "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json",
            "installer/windows/build_installer.ps1",
            "tools/windows_cross_store_artifact_gate.py",
            "tools/release_obfuscation_contract.py",
        ):
            self._copy(relative)
        self._write("build/windows-installer/WinsVPN-Setup.exe", b"x64-website-exe")
        self._write(
            "build/windows-installer/WinsVPN-PartnerCenter.exe", b"x64-partner-exe"
        )
        self._write(
            "build/windows-installer/WinsVPN-Setup-arm64.exe", b"arm64-website-exe"
        )
        self._write(
            "build/windows-installer/WinsVPN-PartnerCenter-arm64.exe",
            b"arm64-partner-exe",
        )
        self._write(".artifacts/RELEASE_INPUT_INDEX.json", b'{"frozen":true}\n')
        for target_id in gate.REQUIRED_WINDOWS_UPLOAD_TARGETS:
            dummy = (json.dumps({"ok": True, "target_id": target_id}) + "\n").encode(
                "ascii"
            )
            self._write(self._build_receipt_relative(target_id), dummy)
            self._write_obfuscation_receipt(target_id)

    def _write_obfuscation_receipt(self, target_id: str) -> pathlib.Path:
        spec = gate.WINDOWS_PACKAGE_UPLOAD_TARGETS[target_id]
        artifact_path = f"build/windows-installer/{spec['artifact_name']}"
        relative = gate.obfuscation_receipt_relative(target_id)
        payload = {
            "schema_version": 2,
            "contract": "winsvpn-release-obfuscation-and-secret-free-v2",
            "platform": "windows",
            "app_version": "1.0.17",
            "build_number": "34",
            "target_id": target_id,
            "private_symbols_not_packaged": True,
            "artifacts": [
                {
                    "path": artifact_path,
                    "size": (self.repo / artifact_path).stat().st_size,
                    "sha256": self._file_sha256(artifact_path),
                }
            ],
        }
        return self._write(
            relative, (json.dumps(payload, sort_keys=True) + "\n").encode("ascii")
        )

    def _authentication(
        self, target_id: str, digest: str, size: int, *, signature: str = "ab" * 64
    ) -> dict[str, object]:
        issued = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        return {
            "authenticated": True,
            "issuer": gate.UPLOAD_RECEIPT_ISSUER,
            "run_id": secrets.token_hex(32),
            "nonce": secrets.token_hex(32),
            "issued_at": issued,
            "challenge": secrets.token_hex(64),
            "target_id": target_id,
            "architectures": list(
                gate.WINDOWS_PACKAGE_UPLOAD_TARGETS[target_id]["architectures"]
            ),
            "release": "1.0.17+34",
            "artifact_sha256": digest,
            "artifact_bytes": size,
            "signature": signature,
        }

    def _receipt(self, target_id: str) -> dict[str, object]:
        spec = gate.WINDOWS_PACKAGE_UPLOAD_TARGETS[target_id]
        architecture = gate.TARGET_ARCHITECTURES[target_id]
        artifact_name = spec["artifact_name"]
        artifact_path = gate.expected_upload_artifact_path(target_id)
        reviewed = gate._reviewed_store_metadata()
        build_relative = self._build_receipt_relative(target_id)
        return {
            "ok": True,
            "schema_version": gate.PACKAGE_UPLOAD_RECEIPT_SCHEMA_VERSION,
            "contract": gate.PACKAGE_UPLOAD_RECEIPT_CONTRACT,
            "release": "1.0.17+34",
            "target_id": target_id,
            "platform": "windows",
            "artifact": {
                "path": artifact_path,
                "sha256": self._file_sha256(artifact_path),
                "bytes": (self.repo / artifact_path).stat().st_size,
            },
            "build_receipt": {
                "path": build_relative,
                "sha256": self._file_sha256(build_relative),
                "target": spec["build_receipt_target"],
            },
            "producer": {
                "id": spec["producer_id"],
                "path": spec["producer"],
                "sha256": self._file_sha256(str(spec["producer"])),
            },
            "package_identity": {
                "product_version": "1.0.17",
                "four_part_version": "1.0.17.34",
                "architecture": architecture,
                "filename": artifact_name,
                "file_description": spec["file_description"],
                "surface": spec["store_surface"],
            },
            "architectures": list(spec["architectures"]),
            "signing": {
                "contract": spec["signing_contract"],
                "status": spec["signing_status"],
            },
            "store_evidence": {
                "surface": spec["store_surface"],
                "status": "not_uploaded",
                "metadata_sha256": reviewed["sha256"],
            },
            "descriptor": {
                "path": gate.DESCRIPTOR_RELATIVE,
                "sha256": self._file_sha256(gate.DESCRIPTOR_RELATIVE),
            },
            "source_freeze": {
                "path": ".artifacts/RELEASE_INPUT_INDEX.json",
                "sha256": self._file_sha256(".artifacts/RELEASE_INPUT_INDEX.json"),
            },
            "obfuscation_privacy": {
                "path": gate.OBFUSCATION_PRIVACY_RELATIVE,
                "sha256": self._file_sha256(gate.OBFUSCATION_PRIVACY_RELATIVE),
            },
            "evidence_collector": {
                "path": gate.EVIDENCE_COLLECTOR_RELATIVE,
                "sha256": hashlib.sha256(
                    (ORIGIN / gate.EVIDENCE_COLLECTOR_RELATIVE).read_bytes()
                ).hexdigest(),
            },
            "publication_authorized": False,
            "upload_attempted": False,
            "owner_authorization": {
                "contract": gate.OWNER_AUTHORIZATION_CONTRACT,
                "schema_version": gate.PACKAGE_UPLOAD_RECEIPT_SCHEMA_VERSION,
                "status": "pending",
                "credentials_authorized": False,
                "upload_authorized": False,
            },
            "authentication": self._authentication(
                target_id,
                self._file_sha256(artifact_path),
                (self.repo / artifact_path).stat().st_size,
            ),
        }

    def test_dummy_bytes_are_not_an_installer_identity(self) -> None:
        record = self._receipt("windows-x64-installer")
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"is not a PE image"
        ) as raised:
            gate.bind_package_upload_receipt(
                "windows-x64-installer",
                record,
                artifact_sha256=str(record["artifact"]["sha256"]),
                artifact_bytes=int(record["artifact"]["bytes"]),
            )
        self.assertNotIn("owner/environment blocker", str(raised.exception))
        self.assertNotIn('"ok": true', str(raised.exception).casefold())

    def test_partner_center_and_website_identities_stay_distinct(self) -> None:
        website = self._receipt("windows-x64-installer")
        partner = self._receipt("windows-x64-partner-center")
        self.assertNotEqual(
            website["package_identity"]["filename"],
            partner["package_identity"]["filename"],
        )
        self.assertNotEqual(
            website["package_identity"]["file_description"],
            partner["package_identity"]["file_description"],
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"is not a PE image"
        ):
            gate.bind_package_upload_receipt(
                "windows-x64-partner-center",
                partner,
                artifact_sha256=str(partner["artifact"]["sha256"]),
                artifact_bytes=int(partner["artifact"]["bytes"]),
            )

    def test_missing_artifact_is_an_owner_blocker(self) -> None:
        record = self._receipt("windows-x64-installer")
        (self.repo / "build/windows-installer/WinsVPN-Setup.exe").unlink()
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"owner/environment blocker:.*pending without owner evidence",
        ):
            gate.bind_package_upload_receipt(
                "windows-x64-installer",
                record,
                artifact_sha256=str(record["artifact"]["sha256"]),
                artifact_bytes=int(record["artifact"]["bytes"]),
            )

    def test_architecture_and_upload_authorization_drift_fail_closed(self) -> None:
        record = self._receipt("windows-x64-installer")
        record["package_identity"]["architecture"] = "arm64"
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, "package identity"
        ):
            gate.bind_package_upload_receipt(
                "windows-x64-installer",
                record,
                artifact_sha256=str(record["artifact"]["sha256"]),
                artifact_bytes=int(record["artifact"]["bytes"]),
            )
        record = self._receipt("windows-x64-installer")
        record["owner_authorization"]["upload_authorized"] = True
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, "owner authorization"
        ):
            gate.bind_package_upload_receipt(
                "windows-x64-installer",
                record,
                artifact_sha256=str(record["artifact"]["sha256"]),
                artifact_bytes=int(record["artifact"]["bytes"]),
            )
        record = self._receipt("windows-x64-installer")
        record["publication_authorized"] = True
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, "receipt binding is invalid"
        ):
            gate.bind_package_upload_receipt(
                "windows-x64-installer",
                record,
                artifact_sha256=str(record["artifact"]["sha256"]),
                artifact_bytes=int(record["artifact"]["bytes"]),
            )
        record = self._receipt("windows-x64-installer")
        live_digest = str(record["artifact"]["sha256"])
        live_bytes = int(record["artifact"]["bytes"])
        record["artifact"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, "swapped or does not bind"
        ):
            gate.bind_package_upload_receipt(
                "windows-x64-installer",
                record,
                artifact_sha256=live_digest,
                artifact_bytes=live_bytes,
            )

    def test_missing_or_swapped_obfuscation_receipt_fails_closed(self) -> None:
        record = self._receipt("windows-x64-installer")
        relative = gate.obfuscation_receipt_relative("windows-x64-installer")
        (self.repo / relative).unlink()
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"owner/environment blocker:.*pending without owner evidence",
        ):
            gate.bind_package_upload_receipt(
                "windows-x64-installer",
                record,
                artifact_sha256=str(record["artifact"]["sha256"]),
                artifact_bytes=int(record["artifact"]["bytes"]),
            )
        self._write_obfuscation_receipt("windows-x64-installer")
        payload = json.loads((self.repo / relative).read_text(encoding="ascii"))
        payload["artifacts"][0]["sha256"] = "0" * 64
        (self.repo / relative).write_text(json.dumps(payload) + "\n", encoding="ascii")
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, "obfuscation receipt"
        ):
            gate.bind_package_upload_receipt(
                "windows-x64-installer",
                record,
                artifact_sha256=str(record["artifact"]["sha256"]),
                artifact_bytes=int(record["artifact"]["bytes"]),
            )

    def test_required_set_stays_pending_without_arm64_owner_evidence(self) -> None:
        records = {
            "windows-x64-installer": self._receipt("windows-x64-installer"),
            "windows-x64-partner-center": self._receipt(
                "windows-x64-partner-center"
            ),
        }
        artifacts = {
            target_id: (
                str(record["artifact"]["sha256"]),
                int(record["artifact"]["bytes"]),
            )
            for target_id, record in records.items()
        }
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"owner/environment blocker:.*windows-arm64-installer",
        ):
            gate.bind_windows_package_upload_receipts(records, artifacts)

    def test_self_authored_receipt_without_authentication_fails_closed(self) -> None:
        record = self._receipt("windows-x64-installer")
        del record["authentication"]
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"schema fields are invalid"
        ) as raised:
            gate.bind_package_upload_receipt(
                "windows-x64-installer",
                record,
                artifact_sha256=str(record["artifact"]["sha256"]),
                artifact_bytes=int(record["artifact"]["bytes"]),
            )
        self.assertNotIn("owner/environment blocker", str(raised.exception))

    def test_held_pe_without_owner_signer_is_owner_blocked(self) -> None:
        pe = adapters.installer_pe("windows-x64-installer")
        self._write("build/windows-installer/WinsVPN-Setup.exe", pe)
        self._write_obfuscation_receipt("windows-x64-installer")
        record = self._receipt("windows-x64-installer")
        self.assertTrue(gate.owner_authenticode_pin_blocked())
        self.assertTrue(gate.owner_upload_receipt_key_blocked())
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"owner/environment blocker:.*OWNER-BLOCKED: ABSENT",
        ):
            gate.bind_package_upload_receipt(
                "windows-x64-installer",
                record,
                artifact_sha256=str(record["artifact"]["sha256"]),
                artifact_bytes=int(record["artifact"]["bytes"]),
            )

    def test_missing_windows_host_stays_owner_blocked(self) -> None:
        if os.name == "nt":
            self.skipTest("non-Windows-only assertion")
        pe = adapters.installer_pe("windows-x64-installer")
        self._write("build/windows-installer/WinsVPN-Setup.exe", pe)
        self._write_obfuscation_receipt("windows-x64-installer")
        leaf = gate.authenticode_leaf_identity("WinsVPN-Setup.exe", pe)
        record = self._receipt("windows-x64-installer")
        with mock.patch.object(gate, "OWNER_AUTHENTICODE_LEAF_SHA256", leaf["sha256"]):
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError,
                r"owner/environment blocker:.*disposable Windows verification host",
            ):
                gate.bind_package_upload_receipt(
                    "windows-x64-installer",
                    record,
                    artifact_sha256=str(record["artifact"]["sha256"]),
                    artifact_bytes=int(record["artifact"]["bytes"]),
                )

    def test_unsigned_upload_receipt_is_not_authenticated(self) -> None:
        pe = adapters.installer_pe("windows-x64-installer")
        self._install_pe("windows-x64-installer", pe)
        leaf = gate.authenticode_leaf_identity("WinsVPN-Setup.exe", pe)
        record = self._receipt("windows-x64-installer")
        private = ed25519.Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

        def fake_offline(_path, snapshot, *, target_id, leaf):
            return valid_offline_authenticode_proof(
                leaf,
                target_id=target_id,
                snapshot_sha256=snapshot.digest,
                snapshot_path=str(snapshot.path),
            )

        with mock.patch.object(gate, "OWNER_AUTHENTICODE_LEAF_SHA256", leaf["sha256"]):
            with mock.patch.object(
                gate, "OWNER_AUTHENTICODE_SIGNTOOL", "/abs/signtool.exe"
            ):
                with mock.patch.object(
                    gate, "OWNER_UPLOAD_RECEIPT_PUBLIC_KEY_HEX", public.hex()
                ):
                    with mock.patch.object(
                        gate,
                        "_verify_authenticode_offline",
                        side_effect=fake_offline,
                    ):
                        with self.assertRaisesRegex(
                            gate.WindowsArtifactGateError,
                            gate.UPLOAD_RECEIPT_UNAUTHENTICATED_ERROR,
                        ) as raised:
                            gate.bind_package_upload_receipt(
                                "windows-x64-installer",
                                record,
                                artifact_sha256=str(record["artifact"]["sha256"]),
                                artifact_bytes=int(record["artifact"]["bytes"]),
                            )
                        self.assertNotIn(
                            "owner/environment blocker", str(raised.exception)
                        )


    def _build_receipt_relative(self, target_id: str) -> str:
        spec = gate.WINDOWS_PACKAGE_UPLOAD_TARGETS[target_id]
        return f".artifacts/{spec['build_receipt_target']}/{target_id}/receipt.json"

    def _records(self, *target_ids: str) -> dict[str, dict[str, object]]:
        return {target_id: self._receipt(target_id) for target_id in target_ids}

    def _artifacts(
        self, records: dict[str, dict[str, object]]
    ) -> dict[str, tuple[str, int]]:
        return {
            target_id: (
                str(record["artifact"]["sha256"]),
                int(record["artifact"]["bytes"]),
            )
            for target_id, record in records.items()
        }

    def _bind(self, target_id: str, record: dict[str, object] | None = None) -> None:
        if record is None:
            record = self._receipt(target_id)
        gate.bind_package_upload_receipt(
            target_id,
            record,
            artifact_sha256=str(record["artifact"]["sha256"]),
            artifact_bytes=int(record["artifact"]["bytes"]),
        )

    def _write_build_receipt(self, target_id: str) -> str:
        spec = gate.WINDOWS_PACKAGE_UPLOAD_TARGETS[target_id]
        artifact_path = gate.expected_upload_artifact_path(target_id)
        relative = self._build_receipt_relative(target_id)
        payload = build_receipt_payload(
            name=spec["artifact_name"],
            digest=self._file_sha256(artifact_path),
            size_bytes=(self.repo / artifact_path).stat().st_size,
            target=spec["build_receipt_target"],
        )
        self._write(relative, payload)
        return relative

    def _install_pe(self, target_id: str, payload: bytes) -> None:
        self._write(gate.expected_upload_artifact_path(target_id), payload)
        self._write_obfuscation_receipt(target_id)
        self._write_build_receipt(target_id)

    def test_mixed_architecture_and_surface_receipts_fail_closed(self) -> None:
        mixed = self._receipt("windows-x64-installer")
        mixed["architectures"] = ["arm64"]
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"architecture inventory is not exact"
        ):
            self._bind("windows-x64-installer", mixed)
        identity = self._receipt("windows-x64-installer")
        identity["package_identity"]["architecture"] = "arm64"
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, "package identity"
        ):
            self._bind("windows-x64-installer", identity)
        swapped = self._receipt("windows-x64-partner-center")
        swapped["package_identity"]["filename"] = "WinsVPN-Setup.exe"
        swapped["package_identity"]["surface"] = "website"
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, "package identity"
        ):
            self._bind("windows-x64-partner-center", swapped)
        arm64 = self._receipt("windows-arm64-installer")
        arm64["package_identity"]["architecture"] = "x64"
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, "package identity"
        ):
            self._bind("windows-arm64-installer", arm64)

    def test_source_only_and_non_candidate_paths_fail_closed(self) -> None:
        source = (
            b"#!/usr/bin/env pwsh\nWrite-Host 'not an installer'\n"
        )
        self._write("build/windows-installer/WinsVPN-Setup.exe", source)
        self._write_obfuscation_receipt("windows-x64-installer")
        record = self._receipt("windows-x64-installer")
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.SOURCE_ONLY_INSTALLER_ERROR
        ) as raised:
            self._bind("windows-x64-installer", record)
        self.assertNotIn("owner/environment blocker", str(raised.exception))
        inno = self._receipt("windows-x64-installer")
        inno["artifact"]["path"] = "installer/windows/winsvpn.iss"
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, "artifact type is not allowed"
        ):
            self._bind("windows-x64-installer", inno)

    def test_stale_upload_receipt_and_selftest_fail_closed(self) -> None:
        record = self._receipt("windows-x64-installer")
        stale = (
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(hours=2)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        record["authentication"]["issued_at"] = stale
        pe = installer_pe("windows-x64-installer")
        self._install_pe("windows-x64-installer", pe)
        record = self._receipt("windows-x64-installer")
        record["authentication"]["issued_at"] = stale
        leaf = gate.authenticode_leaf_identity("WinsVPN-Setup.exe", pe)
        private = ed25519.Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        auth = record["authentication"]
        auth["signature"] = private.sign(
            gate._upload_receipt_canonical_bytes(auth)
        ).hex()

        def fake_offline(_path, snapshot, *, target_id, leaf):
            return valid_offline_authenticode_proof(
                leaf,
                target_id=target_id,
                snapshot_sha256=snapshot.digest,
                snapshot_path=str(snapshot.path),
            )

        with mock.patch.object(gate, "OWNER_AUTHENTICODE_LEAF_SHA256", leaf["sha256"]):
            with mock.patch.object(
                gate, "OWNER_AUTHENTICODE_SIGNTOOL", "/abs/signtool.exe"
            ):
                with mock.patch.object(
                    gate, "OWNER_UPLOAD_RECEIPT_PUBLIC_KEY_HEX", public.hex()
                ):
                    with mock.patch.object(
                        gate, "_verify_authenticode_offline", side_effect=fake_offline
                    ):
                        with self.assertRaisesRegex(
                            gate.WindowsArtifactGateError,
                            gate.UPLOAD_RECEIPT_STALE_ERROR,
                        ):
                            self._bind("windows-x64-installer", record)
        tagged = self._receipt("windows-x64-installer")
        tagged["authentication"]["challenge"] = "self_test" + ("ab" * 60)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.COLLECTOR_SELFTEST_ERROR
        ):
            self._bind("windows-x64-installer", tagged)
        with mock.patch.object(gate, "TEST_ONLY", True):
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError,
                "TEST_ONLY Windows gate cannot emit a production pass",
            ):
                self._bind("windows-x64-installer")

    def test_duplicate_partial_and_mixed_set_fail_closed(self) -> None:
        records = self._records(*gate.REQUIRED_WINDOWS_UPLOAD_TARGETS)
        records["windows-x64-partner-center"]["artifact"]["sha256"] = records[
            "windows-x64-installer"
        ]["artifact"]["sha256"]
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, "receipt reuse is refused"
        ) as raised:
            gate.bind_windows_package_upload_receipts(
                records, self._artifacts(records)
            )
        self.assertNotIn("owner/environment blocker", str(raised.exception))
        mixed = self._records(*gate.REQUIRED_WINDOWS_UPLOAD_TARGETS)
        mixed["windows-arm64-installer"]["architectures"] = ["x64"]
        mixed["windows-arm64-installer"]["package_identity"]["architecture"] = "x64"
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"architecture inventory is not exact"
        ):
            gate.bind_windows_package_upload_receipts(mixed, self._artifacts(mixed))
        partial = self._records(
            "windows-x64-installer", "windows-x64-partner-center"
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"owner/environment blocker:.*windows-arm64-installer",
        ):
            gate.bind_windows_package_upload_receipts(
                partial, self._artifacts(partial)
            )
        reused_producer = self._records(*gate.REQUIRED_WINDOWS_UPLOAD_TARGETS)
        reused_producer["windows-arm64-installer"]["producer"]["id"] = reused_producer[
            "windows-x64-installer"
        ]["producer"]["id"]
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, "receipt reuse is refused"
        ):
            gate.bind_windows_package_upload_receipts(
                reused_producer, self._artifacts(reused_producer)
            )

    def test_duplicate_json_and_swapped_collector_fail_closed(self) -> None:
        record = self._receipt("windows-x64-installer")
        encoded = json.dumps(record, sort_keys=True)
        poisoned = encoded[:-1] + ', "ok": false}'
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, "duplicate JSON key"
        ):
            gate.bind_package_upload_receipt(
                "windows-x64-installer",
                poisoned.encode("ascii"),
                artifact_sha256=str(record["artifact"]["sha256"]),
                artifact_bytes=int(record["artifact"]["bytes"]),
            )
        swapped = self._receipt("windows-x64-installer")
        swapped["evidence_collector"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, "evidence collector"
        ):
            self._bind("windows-x64-installer", swapped)
        aliased = self._receipt("windows-x64-installer")
        aliased["evidence_collector"]["path"] = gate.DESCRIPTOR_RELATIVE
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, "evidence collector path is not exact"
        ):
            self._bind("windows-x64-installer", aliased)

    def test_wrong_signer_missing_timestamp_and_wrong_pe_machine_fail_closed(
        self,
    ) -> None:
        untrusted = signed_pe(
            gate.PE_MACHINE_X86,
            version={
                "CompanyName": gate.AUTHENTICODE_LEAF_O,
                "FileDescription": gate.TARGET_FILE_DESCRIPTIONS[
                    "windows-x64-installer"
                ],
                "OriginalFilename": "WinsVPN-Setup.exe",
                "ProductName": "Win's VPN",
                "ProductVersion": "1.0.17",
            },
            signer=untrusted_signer(),
        )
        self._install_pe("windows-x64-installer", untrusted)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"Authenticode publisher leaf is not the reviewed",
        ) as raised:
            self._bind("windows-x64-installer")
        self.assertNotIn("owner/environment blocker", str(raised.exception))
        missing_ts = signed_pe(
            gate.PE_MACHINE_X86,
            version={
                "CompanyName": gate.AUTHENTICODE_LEAF_O,
                "FileDescription": gate.TARGET_FILE_DESCRIPTIONS[
                    "windows-x64-installer"
                ],
                "OriginalFilename": "WinsVPN-Setup.exe",
                "ProductName": "Win's VPN",
                "ProductVersion": "1.0.17",
            },
            timestamp=False,
        )
        self._install_pe("windows-x64-installer", missing_ts)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.TIMESTAMP_MISSING_ERROR
        ):
            self._bind("windows-x64-installer")
        native = signed_pe(
            gate.PE_MACHINE_X64,
            version={
                "CompanyName": gate.AUTHENTICODE_LEAF_O,
                "FileDescription": gate.TARGET_FILE_DESCRIPTIONS[
                    "windows-x64-installer"
                ],
                "OriginalFilename": "WinsVPN-Setup.exe",
                "ProductName": "Win's VPN",
                "ProductVersion": "1.0.17",
            },
        )
        self._install_pe("windows-x64-installer", native)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.INNO_BOOTSTRAP_ERROR
        ):
            self._bind("windows-x64-installer")

    def test_distinct_upload_targets_and_arm64_metadata_stay_pending(self) -> None:
        records = self._records(*gate.REQUIRED_WINDOWS_UPLOAD_TARGETS)
        identities = [
            (
                record["target_id"],
                record["package_identity"]["filename"],
                record["package_identity"]["architecture"],
                record["signing"]["contract"],
                record["producer"]["id"],
                record["artifact"]["path"],
            )
            for record in records.values()
        ]
        self.assertEqual(len(set(identities)), 4)
        self.assertEqual(
            {record["artifact"]["sha256"] for record in records.values()},
            {
                records[target]["artifact"]["sha256"]
                for target in gate.REQUIRED_WINDOWS_UPLOAD_TARGETS
            },
        )
        self.assertEqual(
            len({record["artifact"]["sha256"] for record in records.values()}),
            4,
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"is not a PE image"
        ):
            self._bind("windows-x64-installer", records["windows-x64-installer"])
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"owner/environment blocker:.*ARM64",
        ):
            self._bind("windows-arm64-installer", records["windows-arm64-installer"])
        extra = dict(records)
        extra["windows-x64-store-msix"] = self._receipt("windows-x64-installer")
        extra["windows-x64-store-msix"]["target_id"] = "windows-x64-store-msix"
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            "unexpected Windows package/upload receipt target",
        ):
            gate.bind_windows_package_upload_receipts(extra, self._artifacts(extra))

    def test_authenticated_receipt_binds_without_publication(self) -> None:
        pe = installer_pe("windows-x64-installer")
        self._install_pe("windows-x64-installer", pe)
        record = self._receipt("windows-x64-installer")
        leaf = gate.authenticode_leaf_identity("WinsVPN-Setup.exe", pe)
        private = ed25519.Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        auth = record["authentication"]
        auth["signature"] = private.sign(
            gate._upload_receipt_canonical_bytes(auth)
        ).hex()

        def fake_offline(_path, snapshot, *, target_id, leaf):
            return valid_offline_authenticode_proof(
                leaf,
                target_id=target_id,
                snapshot_sha256=snapshot.digest,
                snapshot_path=str(snapshot.path),
            )

        with mock.patch.object(gate, "OWNER_AUTHENTICODE_LEAF_SHA256", leaf["sha256"]):
            with mock.patch.object(
                gate, "OWNER_AUTHENTICODE_SIGNTOOL", "/abs/signtool.exe"
            ):
                with mock.patch.object(
                    gate, "OWNER_UPLOAD_RECEIPT_PUBLIC_KEY_HEX", public.hex()
                ):
                    with mock.patch.object(
                        gate, "_verify_authenticode_offline", side_effect=fake_offline
                    ):
                        bound = gate.bind_package_upload_receipt(
                            "windows-x64-installer",
                            record,
                            artifact_sha256=str(record["artifact"]["sha256"]),
                            artifact_bytes=int(record["artifact"]["bytes"]),
                        )
        self.assertTrue(bound["ok"])
        self.assertEqual(bound["architecture"], "x64")
        self.assertFalse(bound["publication_authorized"])
        self.assertFalse(bound["upload_attempted"])
        self.assertEqual(bound["owner_authorization"], "pending")
        replay = dict(record)
        replay["authentication"] = dict(record["authentication"])
        with mock.patch.object(gate, "OWNER_AUTHENTICODE_LEAF_SHA256", leaf["sha256"]):
            with mock.patch.object(
                gate, "OWNER_AUTHENTICODE_SIGNTOOL", "/abs/signtool.exe"
            ):
                with mock.patch.object(
                    gate, "OWNER_UPLOAD_RECEIPT_PUBLIC_KEY_HEX", public.hex()
                ):
                    with mock.patch.object(
                        gate, "_verify_authenticode_offline", side_effect=fake_offline
                    ):
                        with self.assertRaisesRegex(
                            gate.WindowsArtifactGateError,
                            gate.UPLOAD_RECEIPT_REPLAY_ERROR,
                        ):
                            self._bind("windows-x64-installer", replay)


if __name__ == "__main__":
    unittest.main()
