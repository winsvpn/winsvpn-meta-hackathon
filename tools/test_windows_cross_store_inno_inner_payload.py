#!/usr/bin/env python3
"""Fail-closed tests for packed Windows Inno inner-payload proof."""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

TOOLS = pathlib.Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import test_windows_cross_store_gate_adapters as adapters
import windows_cross_store_artifact_gate as gate


class WindowsInnoInnerPayloadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temp.name).resolve()
        self.root_patch = mock.patch.object(gate, "ROOT", self.repo)
        self.root_patch.start()
        self.owner_patch = adapters.patch_owner_issued_ids()
        self.owner_patch.start()
        self.receipt_patch = adapters.patch_receipt_issuer()
        self.receipt_patch.start()
        self.harness = adapters.WindowsCrossStoreGateAdapterTests()
        self.harness.repo = self.repo
        self.harness.temp = self.temp

    def tearDown(self) -> None:
        self.receipt_patch.stop()
        self.owner_patch.stop()
        self.root_patch.stop()
        self.temp.cleanup()

    def test_extractor_remains_owner_blocked_for_all_four_targets(self) -> None:
        for target in (
            "windows-x64-installer",
            "windows-x64-partner-center",
            "windows-arm64-installer",
            "windows-arm64-partner-center",
        ):
            with self.subTest(target=target):
                artifact, _hashes = self.harness.candidate(
                    target, write_install_proof=False
                )
                with self.assertRaisesRegex(
                    gate.WindowsArtifactGateError,
                    r"owner/environment blocker: no reviewed Inno inner-payload extractor",
                ):
                    gate.extract_packed_inner_payloads(self.repo / artifact)
                self.assertIn("data/app.so", gate.INNO_INNER_EXTRACTOR_ERROR)

    def test_self_authored_receipt_is_not_installer_proof(self) -> None:
        artifact, hashes = self.harness.candidate("windows-x64-installer")
        packed = self.harness.packed_from_stage(artifact)
        self.assertIn("data/app.so", packed)
        self.assertTrue((self.repo / (artifact + gate.INSTALL_PROOF_SUFFIX)).is_file())
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.MUTABLE_JSON_PROOF_ERROR
        ):
            self.harness.verify_fixture("windows-x64-installer", artifact, hashes)

    def test_inno_without_install_proof_receipt_fails_closed(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        packed = self.harness.packed_from_stage(artifact)
        self.assertIn("data/app.so", packed)
        self.assertTrue(packed["data/app.so"].startswith(b"\x7fELF"))
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"owner/environment blocker"
        ):
            self.harness.verify_fixture("windows-x64-installer", artifact, hashes)

    def test_sidecar_inventory_without_receipt_is_not_packed_proof(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"owner/environment blocker"
        ):
            self.harness.verify_fixture("windows-x64-installer", artifact, hashes)
        self.assertTrue((self.repo / "stage/wins_vpn.exe").is_file())
        self.assertTrue((self.repo / "stage/data/app.so").is_file())
        self.assertTrue(
            (self.repo / "stage/NativeMessagingHost/wins_bridge_host.exe").is_file()
        )

    def test_synthetic_extract_rejects_missing_packed_app_so(self) -> None:
        artifact, _hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        packed = self.harness.packed_from_stage(artifact)
        del packed["data/app.so"]
        inventory = gate._payload_inventory(self.harness.load_manifest(artifact))
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"packed Windows inner payloads do not match the producer inventory|data/app.so",
        ):
            gate.verify_packed_inner_payloads(
                packed,
                inventory,
                "x64",
                "1.0.17",
                "1.0.17.34",
                False,
                custody_policy=adapters.reviewed_custody_policy(),
            )

    def test_synthetic_extract_rejects_hash_mismatch_for_packed_app_so(self) -> None:
        artifact, _hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        packed = self.harness.packed_from_stage(artifact)
        packed["data/app.so"] = b"\x7fELF" + b"\x01" * 64
        inventory = gate._payload_inventory(self.harness.load_manifest(artifact))
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"packed data/app.so does not match the producer inventory",
        ):
            gate.verify_packed_inner_payloads(
                packed,
                inventory,
                "x64",
                "1.0.17",
                "1.0.17.34",
                False,
                custody_policy=adapters.reviewed_custody_policy(),
            )

    def test_synthetic_extract_rejects_cross_architecture_inner_pe(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        packed = self.harness.packed_from_stage(artifact)
        packed["wins_vpn.exe"] = adapters.app_pe(gate.PE_MACHINE_ARM64)
        digest = hashlib.sha256(packed["wins_vpn.exe"]).hexdigest()
        record = self.harness.load_manifest(artifact)
        for entry in record["payload"]:
            if entry["path"].endswith("wins_vpn.exe"):
                entry["sha256"] = digest
                entry["size"] = len(packed["wins_vpn.exe"])
        self.harness.save_manifest(artifact, record)
        inventory = gate._payload_inventory(record)
        with mock.patch.object(gate, "_verify_privacy_of_paths", return_value=None):
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError, r"PE32\+ x64"
            ):
                gate.verify_packed_inner_payloads(
                    packed,
                    inventory,
                    "x64",
                    "1.0.17",
                    "1.0.17.34",
                    False,
                    custody_policy=adapters.reviewed_custody_policy(),
                )

    def test_website_and_partner_center_remain_distinct_when_extractor_is_missing(
        self,
    ) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, "another exact target"
        ):
            self.harness.verify_fixture("windows-x64-partner-center", artifact, hashes)

    def test_x64_and_arm64_remain_distinct_when_extractor_is_missing(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, "another exact target"
        ):
            self.harness.verify_fixture("windows-arm64-installer", artifact, hashes)

    def _receipt(
        self,
        snapshot: gate.AuthenticatedSnapshot,
        leaf: dict[str, str],
        target_id: str,
        *,
        installer_sha256: str | None = None,
        architecture: str | None = None,
        source_closure: str | None = None,
        inner_payloads: dict[str, bytes] | None = None,
    ) -> dict[str, object]:
        overrides: dict[str, object] = {}
        if installer_sha256 is not None:
            overrides["installer_sha256"] = installer_sha256
        if architecture is not None:
            overrides["target_architecture"] = architecture
        if source_closure is not None:
            overrides["build_transaction"] = source_closure
        return adapters.signed_execution_receipt(
            snapshot,
            leaf,
            target_id,
            inner_payloads or {"wins_vpn.exe": b"MZ"},
            **overrides,
        )

    def test_authenticated_capture_must_bind_snapshot_digest_signer_and_transaction(
        self,
    ) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        path = self.repo / artifact
        snapshot = gate.snapshot_regular_file(
            path, "Windows installer artifact", maximum=gate.MAX_ARTIFACT_BYTES
        )
        try:
            leaf = gate.authenticode_leaf_identity(path.name, snapshot.bytes())
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError,
                r"not tied to the snapshot digest, size, and signer",
            ):
                gate._bind_execution_receipt(
                    snapshot,
                    leaf,
                    self._receipt(
                        snapshot,
                        leaf,
                        "windows-x64-installer",
                        installer_sha256="ab" * 32,
                    ),
                    "windows-x64-installer",
                    "x64",
                    gate.compute_windows_installer_source_closure(),
                )
        finally:
            snapshot.close()
        capture_snapshot = gate.snapshot_regular_file(
            path, "Windows installer artifact", maximum=gate.MAX_ARTIFACT_BYTES
        )
        try:
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError, gate.AUTHENTICATED_CAPTURE_ERROR
            ):
                gate.authenticated_windows_install_run_capture(capture_snapshot)
        finally:
            capture_snapshot.close()

    def test_execution_receipt_reuse_across_targets_is_not_pending(self) -> None:
        artifact, _hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        path = self.repo / artifact
        snapshot = gate.snapshot_regular_file(
            path, "Windows installer artifact", maximum=gate.MAX_ARTIFACT_BYTES
        )
        try:
            leaf = gate.authenticode_leaf_identity(path.name, snapshot.bytes())
            source_closure = gate.compute_windows_installer_source_closure()
            receipt = self._receipt(
                snapshot, leaf, "windows-x64-partner-center", source_closure=source_closure
            )
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError, gate.RECEIPT_REUSE_ERROR
            ) as raised:
                gate._bind_execution_receipt(
                    snapshot,
                    leaf,
                    receipt,
                    "windows-x64-installer",
                    "x64",
                    source_closure,
                )
            self.assertNotIn("owner/environment blocker", str(raised.exception))
            arm_receipt = self._receipt(
                snapshot,
                leaf,
                "windows-x64-installer",
                architecture="arm64",
                source_closure=source_closure,
            )
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError, gate.RECEIPT_REUSE_ERROR
            ) as arm_raised:
                gate._bind_execution_receipt(
                    snapshot,
                    leaf,
                    arm_receipt,
                    "windows-x64-installer",
                    "x64",
                    source_closure,
                )
            self.assertNotIn("owner/environment blocker", str(arm_raised.exception))
        finally:
            snapshot.close()

    def test_execution_receipt_source_closure_mismatch_fails_closed(self) -> None:
        artifact, _hashes = self.harness.candidate(
            "windows-arm64-partner-center", write_install_proof=False
        )
        path = self.repo / artifact
        snapshot = gate.snapshot_regular_file(
            path, "Windows installer artifact", maximum=gate.MAX_ARTIFACT_BYTES
        )
        try:
            leaf = gate.authenticode_leaf_identity(path.name, snapshot.bytes())
            source_closure = gate.compute_windows_installer_source_closure()
            receipt = self._receipt(
                snapshot,
                leaf,
                "windows-arm64-partner-center",
                source_closure="ab" * 32,
            )
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError,
                r"not bound to the current installer source closure",
            ) as raised:
                gate._bind_execution_receipt(
                    snapshot,
                    leaf,
                    receipt,
                    "windows-arm64-partner-center",
                    "arm64",
                    source_closure,
                )
            self.assertNotIn("owner/environment blocker", str(raised.exception))
        finally:
            snapshot.close()

    def test_capture_bytes_dict_is_not_an_authenticated_receipt(self) -> None:
        artifact, _hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        path = self.repo / artifact
        snapshot = gate.snapshot_regular_file(
            path, "Windows installer artifact", maximum=gate.MAX_ARTIFACT_BYTES
        )
        try:
            leaf = gate.authenticode_leaf_identity(path.name, snapshot.bytes())
            packed = self.harness.packed_from_stage(artifact)
            with (
                mock.patch.object(
                    gate,
                    "extract_packed_inner_payloads",
                    side_effect=gate.WindowsArtifactGateError(
                        gate.INNO_INNER_EXTRACTOR_ERROR
                    ),
                ),
                mock.patch.object(
                    gate,
                    "authenticated_windows_install_run_capture",
                    return_value=packed,
                ),
                self.assertRaisesRegex(
                    gate.WindowsArtifactGateError, r"exact schema"
                ) as raised,
            ):
                gate._prove_inner_payloads(
                    path,
                    snapshot,
                    leaf,
                    "windows-x64-installer",
                    "x64",
                    gate.compute_windows_installer_source_closure(),
                )
            self.assertNotIn("owner/environment blocker", str(raised.exception))
        finally:
            snapshot.close()

    def test_extractor_defect_is_not_converted_to_pending(self) -> None:
        artifact, _hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        path = self.repo / artifact
        snapshot = gate.snapshot_regular_file(
            path, "Windows installer artifact", maximum=gate.MAX_ARTIFACT_BYTES
        )
        try:
            leaf = gate.authenticode_leaf_identity(path.name, snapshot.bytes())
            with mock.patch.object(
                gate,
                "extract_packed_inner_payloads",
                side_effect=gate.WindowsArtifactGateError(
                    "packed Windows inner payloads include extra executables: extra.exe"
                ),
            ):
                with self.assertRaisesRegex(
                    gate.WindowsArtifactGateError, r"extra executables: extra.exe"
                ) as raised:
                    gate._prove_inner_payloads(
                        path,
                        snapshot,
                        leaf,
                        "windows-x64-installer",
                        "x64",
                        gate.compute_windows_installer_source_closure(),
                    )
            self.assertNotIn("owner/environment blocker", str(raised.exception))
        finally:
            snapshot.close()

    def test_reused_capture_receipt_is_not_pending(self) -> None:
        artifact, _hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        path = self.repo / artifact
        snapshot = gate.snapshot_regular_file(
            path, "Windows installer artifact", maximum=gate.MAX_ARTIFACT_BYTES
        )
        try:
            leaf = gate.authenticode_leaf_identity(path.name, snapshot.bytes())
            source_closure = gate.compute_windows_installer_source_closure()
            reused = self._receipt(
                snapshot, leaf, "windows-arm64-partner-center", source_closure=source_closure
            )
            with (
                mock.patch.object(
                    gate,
                    "extract_packed_inner_payloads",
                    side_effect=gate.WindowsArtifactGateError(
                        gate.INNO_INNER_EXTRACTOR_ERROR
                    ),
                ),
                mock.patch.object(
                    gate,
                    "authenticated_windows_install_run_capture",
                    return_value=reused,
                ),
                self.assertRaisesRegex(
                    gate.WindowsArtifactGateError, gate.RECEIPT_REUSE_ERROR
                ) as raised,
            ):
                gate._prove_inner_payloads(
                    path,
                    snapshot,
                    leaf,
                    "windows-x64-installer",
                    "x64",
                    source_closure,
                )
            self.assertNotIn("owner/environment blocker", str(raised.exception))
        finally:
            snapshot.close()


if __name__ == "__main__":
    unittest.main()
