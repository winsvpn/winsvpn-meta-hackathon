#!/usr/bin/env python3
"""Descriptor-bound snapshot, substitution, and expansion contracts."""

from __future__ import annotations

import datetime
import hashlib
import os
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock

TOOLS = pathlib.Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import release_dependency_freeze as freeze
import test_windows_cross_store_gate_adapters as adapters
import windows_cross_store_artifact_gate as gate


class WindowsCrossStoreSnapshotAndBoundsTests(unittest.TestCase):
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

    def test_artifact_and_proof_swap_restore_cannot_rebind_snapshot(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        origin = self.repo / artifact
        original = origin.read_bytes()
        original_digest = hashlib.sha256(original).hexdigest()
        evil = adapters.installer_pe("windows-x64-partner-center")
        self.assertNotEqual(original, evil)
        isolated = gate.snapshot_regular_file(
            origin, "Windows installer artifact", maximum=gate.MAX_ARTIFACT_BYTES
        )
        try:
            origin.write_bytes(evil)
            self.assertEqual(hashlib.sha256(isolated.bytes()).hexdigest(), original_digest)
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError, r"swapped or restored"
            ) as raised:
                isolated.assert_custody()
            self.assertNotIn("owner/environment blocker", str(raised.exception))
        finally:
            isolated.close()
            origin.write_bytes(original)

        manifest_path = self.repo / (artifact + ".payload-manifest.json")
        original_manifest = manifest_path.read_bytes()
        real_snapshot = gate.snapshot_regular_file

        def swap_after_snapshot(path: pathlib.Path, label: str, *, maximum: int):
            snapshot = real_snapshot(path, label, maximum=maximum)
            if label == "Windows installer artifact":
                path.write_bytes(evil)
            if label == "Windows payload manifest":
                path.write_bytes(b'{"schema_version":3}\n')
            return snapshot

        with mock.patch.object(gate, "snapshot_regular_file", side_effect=swap_after_snapshot):
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError, r"swapped or restored"
            ) as verify_raised:
                self.harness.verify_fixture(
                    "windows-x64-installer", artifact, hashes, extract=True
                )
        self.assertNotIn("owner/environment blocker", str(verify_raised.exception))
        origin.write_bytes(original)
        manifest_path.write_bytes(original_manifest)

    def test_snapshot_mutation_during_read_fails_closed(self) -> None:
        artifact, _hashes = self.harness.candidate(
            "windows-x64-partner-center", write_install_proof=False
        )
        origin = self.repo / artifact
        snapshot = gate.snapshot_regular_file(
            origin, "Windows installer artifact", maximum=gate.MAX_ARTIFACT_BYTES
        )
        try:
            os.chmod(snapshot.path, 0o600)
            with snapshot.path.open("ab") as handle:
                handle.write(b"X")
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError,
                r"mutated while it was read|digest changed|identity changed",
            ) as raised:
                snapshot.bytes()
            self.assertNotIn("owner/environment blocker", str(raised.exception))
        finally:
            snapshot.close()

    def test_source_closure_paths_must_be_unique_and_sorted(self) -> None:
        with mock.patch.object(
            gate, "WINDOWS_INSTALLER_SOURCE_PATHS", ("b-source", "a-source")
        ):
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError, r"unique and sorted"
            ):
                gate.compute_windows_installer_source_closure()
        digest = gate.compute_windows_installer_source_closure()
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(digest, gate.compute_windows_installer_source_closure())
        self.assertEqual(
            gate.WINDOWS_INSTALLER_SOURCE_PATHS,
            tuple(sorted(set(gate.WINDOWS_INSTALLER_SOURCE_PATHS))),
        )
        self.assertIn(gate.PRODUCER_RELATIVE_PATH, gate.WINDOWS_INSTALLER_SOURCE_PATHS)
        self.assertIn(gate.INNO_SCRIPT_RELATIVE_PATH, gate.WINDOWS_INSTALLER_SOURCE_PATHS)
        self.assertIn(
            gate.SIGNING_WRAPPER_RELATIVE_PATH, gate.WINDOWS_INSTALLER_SOURCE_PATHS
        )
        self.assertIn(
            gate.NATIVE_HOST_RENDERER_RELATIVE_PATH, gate.WINDOWS_INSTALLER_SOURCE_PATHS
        )

    def test_missing_authenticode_trust_stays_pending_and_swap_does_not(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-arm64-partner-center", write_install_proof=False
        )
        with mock.patch.object(
            gate,
            "extract_packed_inner_payloads",
            return_value=self.harness.packed_from_stage(artifact),
        ):
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError,
                r"owner/environment blocker: offline Authenticode|offline Authenticode trust verification failed",
            ) as pending:
                gate.verify_artifact(
                    "windows-arm64-partner-center", artifact, verify_signature=True
                )
        self.assertIn("Authenticode", str(pending.exception))
        origin = self.repo / artifact
        original = origin.read_bytes()
        real_snapshot = gate.snapshot_regular_file

        def swap_after_snapshot(path: pathlib.Path, label: str, *, maximum: int):
            snapshot = real_snapshot(path, label, maximum=maximum)
            if label == "Windows installer artifact":
                path.write_bytes(adapters.installer_pe("windows-arm64-installer"))
            return snapshot

        with mock.patch.object(gate, "snapshot_regular_file", side_effect=swap_after_snapshot):
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError, r"swapped or restored"
            ) as swapped:
                self.harness.verify_fixture(
                    "windows-arm64-partner-center", artifact, hashes, extract=True
                )
        self.assertNotIn("owner/environment blocker", str(swapped.exception))
        origin.write_bytes(original)

    def test_substituted_privacy_module_is_rejected(self) -> None:
        fake_path = self.repo / "evil_privacy.py"
        fake_path.write_text(
            "class PrivacyError(RuntimeError):\n    pass\n"
            "def validate_artifacts(paths, secrets):\n    return 1\n",
            encoding="utf-8",
        )
        fake = types.ModuleType("validate_release_artifact_privacy")
        fake.__file__ = str(fake_path)
        fake.PrivacyError = RuntimeError
        fake.validate_artifacts = lambda paths, secrets: 1
        with mock.patch.dict(sys.modules, {"validate_release_artifact_privacy": fake}):
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError,
                r"poisoned via PYTHONPATH, sitecustomize, or sys.modules substitution",
            ):
                gate._authenticated_privacy_module()

    def test_symlinked_release_identity_is_rejected(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        identity = self.repo / gate.RELEASE_IDENTITY_RELATIVE_PATH
        payload = identity.read_bytes()
        outside = pathlib.Path(self.temp.name).parent / "outside-release-identity.json"
        outside.write_bytes(payload)
        identity.unlink()
        try:
            identity.symlink_to(outside)
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError, r"symlink"
            ):
                self.harness.verify_fixture(
                    "windows-x64-installer", artifact, hashes, extract=True
                )
        finally:
            outside.unlink(missing_ok=True)

    def test_unbounded_json_and_inventory_expansion_is_refused(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        oversized = self.repo / (artifact + ".payload-manifest.json")
        oversized.write_bytes(b"{}" + (b" " * (gate.MAX_JSON_BYTES + 1)))
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"size ceiling"
        ):
            self.harness.verify_fixture("windows-x64-installer", artifact, hashes)

        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        record = self.harness.load_manifest(artifact)
        record["payload"] = [
            {
                "path": f"stage/pad-{index}.bin",
                "size": 1,
                "sha256": "ab" * 32,
            }
            for index in range(gate.MAX_INNER_ENTRIES + 1)
        ]
        self.harness.save_manifest(artifact, record)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"entry-count ceiling"
        ):
            self.harness.verify_fixture("windows-x64-installer", artifact, hashes)

        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        record = self.harness.load_manifest(artifact)
        record["payload"][0]["size"] = gate.MAX_INNER_FILE_BYTES + 1
        self.harness.save_manifest(artifact, record)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"per-file size ceiling"
        ):
            self.harness.verify_fixture("windows-x64-installer", artifact, hashes)

    def test_self_authored_json_cannot_stand_in_for_snapshot_capture(self) -> None:
        artifact, hashes = self.harness.candidate("windows-x64-installer")
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.MUTABLE_JSON_PROOF_ERROR
        ):
            self.harness.verify_fixture("windows-x64-installer", artifact, hashes)
        self.assertTrue((self.repo / (artifact + gate.INSTALL_PROOF_SUFFIX)).is_file())

    def test_ancestor_path_swap_to_symlink_fails_closed(self) -> None:
        artifact, _hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        origin = self.repo / artifact
        artifacts_dir = origin.parent
        outside = pathlib.Path(self.temp.name).parent / "outside-win-artifacts"
        outside.mkdir(exist_ok=True)
        evil = outside / origin.name
        evil.write_bytes(adapters.installer_pe("windows-x64-partner-center"))
        real_openat = gate._openat_child

        def swap_then_open(parent_fd: int, name: str, flags: int) -> int:
            if name == "artifacts" and artifacts_dir.is_dir() and not artifacts_dir.is_symlink():
                artifacts_dir.rename(self.repo / "artifacts.real")
                artifacts_dir.symlink_to(outside)
            return real_openat(parent_fd, name, flags)

        with mock.patch.object(gate, "_openat_child", side_effect=swap_then_open):
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError,
                r"symlink ancestor|could not bind path component",
            ) as raised:
                gate.snapshot_regular_file(
                    origin, "Windows installer artifact", maximum=gate.MAX_ARTIFACT_BYTES
                )
        self.assertNotIn("owner/environment blocker", str(raised.exception))
        self.assertTrue((self.repo / "artifacts.real" / origin.name).is_file())

    def test_execution_receipt_rejects_unauthenticated_stale_replay_and_unbound(
        self,
    ) -> None:
        artifact, _hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        path = self.repo / artifact
        snapshot = gate.snapshot_regular_file(
            path, "Windows installer artifact", maximum=gate.MAX_ARTIFACT_BYTES
        )
        try:
            leaf = gate.authenticode_leaf_identity(path.name, snapshot.bytes())
            inner = {"wins_vpn.exe": b"MZ-inner"}
            source_closure = gate.compute_windows_installer_source_closure()
            valid = adapters.signed_execution_receipt(
                snapshot, leaf, "windows-x64-installer", inner
            )
            extracted = gate._bind_execution_receipt(
                snapshot, leaf, valid, "windows-x64-installer", "x64", source_closure
            )
            self.assertEqual(extracted["wins_vpn.exe"], b"MZ-inner")
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError, gate.RECEIPT_REPLAY_ERROR
            ) as replayed:
                gate._bind_execution_receipt(
                    snapshot, leaf, valid, "windows-x64-installer", "x64", source_closure
                )
            self.assertNotIn("owner/environment blocker", str(replayed.exception))

            unsigned = adapters.signed_execution_receipt(
                snapshot,
                leaf,
                "windows-x64-installer",
                inner,
                signature="00" * 64,
            )
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError, gate.RECEIPT_UNAUTHENTICATED_ERROR
            ) as unauth:
                gate._bind_execution_receipt(
                    snapshot,
                    leaf,
                    unsigned,
                    "windows-x64-installer",
                    "x64",
                    source_closure,
                )
            self.assertNotIn("owner/environment blocker", str(unauth.exception))

            stale_time = (
                gate._execution_receipt_now() - datetime.timedelta(hours=1)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            stale = adapters.signed_execution_receipt(
                snapshot,
                leaf,
                "windows-x64-installer",
                inner,
                issued_at=stale_time,
            )
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError, gate.RECEIPT_STALE_ERROR
            ) as stale_raised:
                gate._bind_execution_receipt(
                    snapshot, leaf, stale, "windows-x64-installer", "x64", source_closure
                )
            self.assertNotIn("owner/environment blocker", str(stale_raised.exception))

            foreign = adapters.signed_execution_receipt(
                snapshot,
                leaf,
                "windows-x64-installer",
                inner,
                issuer="untrusted-issuer",
            )
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError, gate.RECEIPT_UNAUTHENTICATED_ERROR
            ) as issuer_raised:
                gate._bind_execution_receipt(
                    snapshot,
                    leaf,
                    foreign,
                    "windows-x64-installer",
                    "x64",
                    source_closure,
                )
            self.assertNotIn("owner/environment blocker", str(issuer_raised.exception))

            bound = adapters.signed_execution_receipt(
                snapshot, leaf, "windows-x64-installer", inner
            )
            bound["inner_payloads"] = {"wins_vpn.exe": b"TAMPERED-BYTES"}
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError,
                r"not tied to the exact inner payload bytes",
            ) as bytes_raised:
                gate._bind_execution_receipt(
                    snapshot, leaf, bound, "windows-x64-installer", "x64", source_closure
                )
            self.assertNotIn("owner/environment blocker", str(bytes_raised.exception))
        finally:
            snapshot.close()



class WindowsNativeHostInputParityTests(unittest.TestCase):
    def test_gate_source_closure_covers_every_frozen_native_host_input(self) -> None:
        # The committed store-id record decides the shipped Chrome/Edge
        # allowed_origins, so the freeze and the gate must both bind it.
        missing = sorted(
            set(freeze.WINDOWS_NATIVE_HOST_INPUT_PATHS)
            - set(gate.WINDOWS_INSTALLER_SOURCE_PATHS)
        )
        self.assertEqual(missing, [])
        for paths in (
            freeze.WINDOWS_NATIVE_HOST_INPUT_PATHS,
            gate.WINDOWS_INSTALLER_SOURCE_PATHS,
        ):
            self.assertIn("tools/native_messaging/manifests/store_ids.json", paths)


if __name__ == "__main__":
    unittest.main()
