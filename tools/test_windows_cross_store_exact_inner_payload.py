#!/usr/bin/env python3
"""Exact inner-payload contract for the Windows cross-store Inno gate."""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
from contextlib import ExitStack
from unittest import mock

TOOLS = pathlib.Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import test_windows_cross_store_gate_adapters as adapters
import windows_cross_store_artifact_gate as gate


class WindowsExactInnerPayloadTests(unittest.TestCase):
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

    def test_classical_positive_path_requires_native_host_and_manifests(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        result = self.harness.verify_fixture(
            "windows-x64-installer", artifact, hashes, extract=True
        )
        packed = self.harness.packed_from_stage(artifact)
        self.assertIn(gate.NATIVE_HOST_BASENAME, packed)
        self.assertIn("org.winsvpn.bridge.firefox.json", packed)
        self.assertIn("org.winsvpn.bridge.chrome.json", packed)
        self.assertIn("org.winsvpn.bridge.edge.json", packed)
        self.assertIn("xray.exe", packed)
        self.assertIn(adapters.PRODUCER_VC_REDIST_BASENAME["x64"], packed)
        self.assertIn(adapters.PRODUCER_AMNEZIAWG_MSI_BASENAME["x64"], packed)
        self.assertNotIn(adapters.PRODUCER_VC_REDIST_BASENAME["arm64"], packed)
        self.assertNotIn(adapters.PRODUCER_AMNEZIAWG_MSI_BASENAME["arm64"], packed)
        self.assertFalse(result["standalone_winn3"])
        self.assertTrue(result["inner_payloads_proven_from_snapshot"])

    def test_firefox_only_native_manifests_are_refused_when_chrome_and_edge_are_omitted(
        self,
    ) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer",
            include_chrome_edge=False,
            write_install_proof=False,
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"incomplete: org.winsvpn.bridge.chrome.json, org.winsvpn.bridge.edge.json",
        ):
            self.harness.verify_fixture(
                "windows-x64-installer", artifact, hashes, extract=True
            )

    def test_standalone_positive_path_does_not_require_legacy_engines(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer",
            standalone_winn3=True,
            write_install_proof=False,
        )
        result = self.harness.verify_fixture(
            "windows-x64-installer",
            artifact,
            hashes,
            extract=True,
            standalone_winn3=True,
        )
        packed = self.harness.packed_from_stage(artifact)
        self.assertIn(gate.NATIVE_HOST_BASENAME, packed)
        self.assertIn("org.winsvpn.bridge.firefox.json", packed)
        self.assertIn("winsvpn_winn3_engine.exe", packed)
        self.assertIn(adapters.PRODUCER_VC_REDIST_BASENAME["x64"], packed)
        self.assertNotIn("xray.exe", packed)
        self.assertNotIn("awg.exe", packed)
        self.assertNotIn("amneziawg.exe", packed)
        self.assertNotIn(adapters.PRODUCER_AMNEZIAWG_MSI_BASENAME["x64"], packed)
        self.assertNotIn(adapters.PRODUCER_AMNEZIAWG_MSI_BASENAME["arm64"], packed)
        self.assertTrue(result["standalone_winn3"])

    def test_hidden_payload_file_is_rejected(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        hidden = self.harness.write(
            "stage/.hidden.exe", adapters.signed_pe(gate.PE_MACHINE_X64)
        )
        record = self.harness.load_manifest(artifact)
        record["payload"].append(
            {
                "path": "stage/.hidden.exe",
                "size": hidden.stat().st_size,
                "sha256": "ab" * 32,
            }
        )
        self.harness.save_manifest(artifact, record)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"hidden file"
        ):
            self.harness.verify_fixture("windows-x64-installer", artifact, hashes)

    def test_extra_native_messaging_manifest_is_rejected(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        extra = self.harness.write(
            "stage/NativeMessagingHost/org.winsvpn.bridge.evil.json",
            adapters.native_manifest("firefox"),
        )
        record = self.harness.load_manifest(artifact)
        record["payload"].append(
            {
                "path": "stage/NativeMessagingHost/org.winsvpn.bridge.evil.json",
                "size": extra.stat().st_size,
                "sha256": hashlib.sha256(extra.read_bytes()).hexdigest(),
            }
        )
        self.harness.save_manifest(artifact, record)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"extra native-messaging manifests"
        ):
            self.harness.verify_fixture("windows-x64-installer", artifact, hashes)

    def test_extra_executable_is_rejected(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        extra = adapters.signed_pe(gate.PE_MACHINE_X64)
        record = self.harness.load_manifest(artifact)
        record["payload"].append(
            {
                "path": "stage/extra.exe",
                "size": len(extra),
                "sha256": hashlib.sha256(extra).hexdigest(),
            }
        )
        self.harness.save_manifest(artifact, record)
        self.harness.write("stage/extra.exe", extra)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"extra executables: extra.exe",
        ):
            self.harness.verify_fixture(
                "windows-x64-installer", artifact, hashes, extract=True
            )

    def test_extra_renamed_mullvad_payload_is_rejected(self) -> None:
        artifact, _hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        packed = self.harness.packed_from_stage(artifact)
        renamed = b"withdrawn-driver-bytes"
        digest = hashlib.sha256(renamed).hexdigest()
        packed["helper.exe"] = renamed
        inventory = gate._payload_inventory(self.harness.load_manifest(artifact))
        with (
            mock.patch.object(gate, "WITHDRAWN_MULLVAD_SHA256", frozenset({digest})),
            mock.patch.object(gate, "_verify_privacy_of_paths", return_value=None),
            self.assertRaisesRegex(
                gate.WindowsArtifactGateError, r"including when renamed"
            ),
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

    def test_x64_bytes_claimed_arm64_are_rejected_from_pe_bytes(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-arm64-installer", write_install_proof=False
        )
        packed = self.harness.packed_from_stage(artifact)
        packed["wins_vpn.exe"] = adapters.app_pe(gate.PE_MACHINE_X64)
        digest = hashlib.sha256(packed["wins_vpn.exe"]).hexdigest()
        record = self.harness.load_manifest(artifact)
        for entry in record["payload"]:
            if str(entry["path"]).endswith("wins_vpn.exe"):
                entry["sha256"] = digest
                entry["size"] = len(packed["wins_vpn.exe"])
        self.harness.save_manifest(artifact, record)
        inventory = gate._payload_inventory(record)
        with mock.patch.object(gate, "_verify_privacy_of_paths", return_value=None):
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError, r"PE32\+ arm64"
            ):
                gate.verify_packed_inner_payloads(
                    packed,
                    inventory,
                    "arm64",
                    "1.0.17",
                    "1.0.17.34",
                    False,
                    custody_policy=adapters.reviewed_custody_policy(),
                )

    def test_missing_native_host_fails_closed(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        record = self.harness.load_manifest(artifact)
        record["payload"] = [
            entry
            for entry in record["payload"]
            if not str(entry["path"]).endswith(gate.NATIVE_HOST_BASENAME)
        ]
        self.harness.save_manifest(artifact, record)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"incomplete.*wins_bridge_host\.exe"
        ):
            self.harness.verify_fixture("windows-x64-installer", artifact, hashes)

    def test_missing_firefox_native_manifest_fails_closed(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        record = self.harness.load_manifest(artifact)
        record["payload"] = [
            entry
            for entry in record["payload"]
            if not str(entry["path"]).endswith("org.winsvpn.bridge.firefox.json")
        ]
        self.harness.save_manifest(artifact, record)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"incomplete.*org\.winsvpn\.bridge\.firefox\.json",
        ):
            self.harness.verify_fixture("windows-x64-installer", artifact, hashes)

    def test_classical_package_missing_xray_is_incomplete(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        record = self.harness.load_manifest(artifact)
        record["payload"] = [
            entry
            for entry in record["payload"]
            if not str(entry["path"]).endswith("xray.exe")
        ]
        self.harness.save_manifest(artifact, record)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"incomplete.*xray\.exe"
        ):
            self.harness.verify_fixture("windows-x64-installer", artifact, hashes)

    def test_standalone_package_with_legacy_xray_is_rejected(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer",
            standalone_winn3=True,
            write_install_proof=False,
        )
        planted = self.harness.write(
            "stage/xray.exe", adapters.signed_pe(gate.PE_MACHINE_X64)
        )
        record = self.harness.load_manifest(artifact)
        record["payload"].append(
            {
                "path": "stage/xray.exe",
                "size": planted.stat().st_size,
                "sha256": hashlib.sha256(planted.read_bytes()).hexdigest(),
            }
        )
        self.harness.save_manifest(artifact, record)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"forbidden legacy engines.*xray\.exe"
        ):
            self.harness.verify_fixture(
                "windows-x64-installer", artifact, hashes, standalone_winn3=True
            )

    def test_variant_is_not_inferred_from_filenames(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        record = self.harness.load_manifest(artifact)
        record["standalone_winn3"] = True
        record["standalone_payload_verified"] = True
        record["signing"]["staged_xray_product_signed"] = False
        self.harness.save_manifest(artifact, record)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"forbidden legacy engines"
        ):
            self.harness.verify_fixture(
                "windows-x64-installer", artifact, hashes, standalone_winn3=True
            )

    def test_bool_string_coercion_of_standalone_fact_is_refused(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        path = self.repo / (artifact + ".payload-manifest.json")
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["standalone_winn3"] = "false"
        path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"JSON boolean; string/number coercion"
        ):
            self.harness.verify_fixture("windows-x64-installer", artifact, hashes)

    def test_integer_one_cannot_coerce_to_standalone_true(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer",
            standalone_winn3=True,
            write_install_proof=False,
        )
        path = self.repo / (artifact + ".payload-manifest.json")
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["standalone_winn3"] = 1
        path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"JSON boolean; string/number coercion"
        ):
            self.harness.verify_fixture(
                "windows-x64-installer", artifact, hashes, standalone_winn3=True
            )

    def test_duplicate_manifest_fields_fail_closed(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        path = self.repo / (artifact + ".payload-manifest.json")
        raw = json.loads(path.read_text(encoding="utf-8"))
        encoded = json.dumps(raw)
        encoded = encoded.replace(
            '"standalone_winn3": false',
            '"standalone_winn3": false, "standalone_winn3": true',
            1,
        )
        path.write_text(encoded, encoding="utf-8")
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"duplicate JSON key"
        ):
            self.harness.verify_fixture("windows-x64-installer", artifact, hashes)

    def test_manifest_installer_size_mismatch_fails_closed(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        record = self.harness.load_manifest(artifact)
        record["installer"]["size"] = int(record["installer"]["size"]) + 1
        self.harness.save_manifest(artifact, record)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            "payload manifest does not bind the exact installer",
        ):
            self.harness.verify_fixture("windows-x64-installer", artifact, hashes)

    def test_packed_extract_extra_file_is_rejected(self) -> None:
        artifact, _hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        packed = self.harness.packed_from_stage(artifact)
        packed["extra.exe"] = adapters.signed_pe(gate.PE_MACHINE_X64)
        inventory = gate._payload_inventory(self.harness.load_manifest(artifact))
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"extra executables: extra.exe"
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


    def test_missing_owner_identity_is_owner_blocked_for_packaged_chrome_and_edge(
        self,
    ) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        with mock.patch.object(
            gate,
            "_owner_issued_chromium_ids",
            side_effect=gate.WindowsArtifactGateError(
                "owner/environment blocker: Chrome and Edge store-listing ids require a "
                "current external owner-issued identity receipt; refusing to invent or "
                "accept a syntactically valid [a-p]{32} substitute"
            ),
        ):
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError, r"owner/environment blocker"
            ):
                self.harness.verify_fixture(
                    "windows-x64-installer", artifact, hashes, extract=True
                )

    def test_arbitrary_valid_shape_chrome_id_is_refused_when_not_owner_issued(
        self,
    ) -> None:
        blob = adapters.native_manifest("chrome", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"org.winsvpn.bridge.chrome.json native-messaging manifest is not exact",
        ):
            gate._verify_native_manifest_bytes(
                "org.winsvpn.bridge.chrome.json",
                blob,
                {
                    "chrome": adapters.FIXTURE_CHROME_ID,
                    "edge": adapters.FIXTURE_EDGE_ID,
                },
            )

    def test_placeholder_chrome_origin_is_refused(self) -> None:
        blob = adapters.native_manifest("chrome", "PLACEHOLDER_CHROME_EXTENSION_ID")
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"placeholder|not exact",
        ):
            gate._verify_native_manifest_bytes(
                "org.winsvpn.bridge.chrome.json",
                blob,
                {
                    "chrome": adapters.FIXTURE_CHROME_ID,
                    "edge": adapters.FIXTURE_EDGE_ID,
                },
            )

    def test_invented_zip_and_msix_targets_are_unsupported(self) -> None:
        for invented in (
            "windows-x64-website-zip",
            "windows-x64-store-msix",
            "windows-arm64-website-zip",
            "windows-arm64-store-msix",
            "windows-x64-zip",
            "windows-arm64-zip",
            "windows-x64-msix",
            "windows-arm64-msix",
        ):
            with self.subTest(target=invented):
                with self.assertRaisesRegex(
                    gate.WindowsArtifactGateError, "unsupported exact Windows target"
                ):
                    gate.verify_artifact(invented, "artifacts/unused")
                self.assertNotIn(invented, gate.TARGET_FILENAMES)
        for name in gate.TARGET_FILENAMES.values():
            self.assertTrue(name.endswith(".exe"))
            self.assertFalse(name.lower().endswith(".zip"))
            self.assertFalse(name.lower().endswith(".msix"))

    def test_successful_extract_binds_source_closure_and_exact_architecture(
        self,
    ) -> None:
        for target, architecture in (
            ("windows-x64-installer", "x64"),
            ("windows-x64-partner-center", "x64"),
            ("windows-arm64-installer", "arm64"),
            ("windows-arm64-partner-center", "arm64"),
        ):
            with self.subTest(target=target):
                artifact, hashes = self.harness.candidate(
                    target, write_install_proof=False
                )
                result = self.harness.verify_fixture(
                    target, artifact, hashes, extract=True
                )
                self.assertEqual(
                    result["source_closure_sha256"],
                    gate.compute_windows_installer_source_closure(),
                )
                self.assertEqual(result["target_architecture"], architecture)
                self.assertEqual(
                    result["file_description"], gate.TARGET_FILE_DESCRIPTIONS[target]
                )
                packed = self.harness.packed_from_stage(artifact)
                machine, _, _ = gate._parse_pe_bytes(
                    "wins_vpn.exe",
                    packed["wins_vpn.exe"],
                    expected_machine=gate._pe_machine_for_architecture(architecture),
                )
                self.assertEqual(machine, gate._pe_machine_for_architecture(architecture))

    def test_test_only_cannot_emit_a_production_pass(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        with mock.patch.object(gate, "TEST_ONLY", True):
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError, r"TEST_ONLY Windows gate cannot emit a production pass"
            ):
                self.harness.verify_fixture(
                    "windows-x64-installer", artifact, hashes, extract=True
                )

    def test_signing_json_does_not_satisfy_real_authenticode(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-partner-center", write_install_proof=False
        )
        record = self.harness.load_manifest(artifact)
        self.assertTrue(record["signing"]["production_signed"])
        with mock.patch.object(
            gate,
            "extract_packed_inner_payloads",
            return_value=self.harness.packed_from_stage(artifact),
        ):
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError,
                r"owner/environment blocker: offline Authenticode|offline Authenticode trust verification failed",
            ) as raised:
                gate.verify_artifact(
                    "windows-x64-partner-center", artifact, verify_signature=True
                )
        self.assertNotIn("ok", str(raised.exception).casefold())

    def test_mutated_inner_pe_hash_is_not_source_closure(self) -> None:
        artifact, _hashes = self.harness.candidate(
            "windows-arm64-installer", write_install_proof=False
        )
        packed = self.harness.packed_from_stage(artifact)
        packed["wins_vpn.exe"] = adapters.app_pe(gate.PE_MACHINE_ARM64)
        packed["wins_vpn.exe"] = packed["wins_vpn.exe"] + b"\x00"
        inventory = gate._payload_inventory(self.harness.load_manifest(artifact))
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"packed wins_vpn\.exe does not match the producer inventory",
        ):
            gate.verify_packed_inner_payloads(
                packed,
                inventory,
                "arm64",
                "1.0.17",
                "1.0.17.34",
                False,
                custody_policy=adapters.reviewed_custody_policy(),
            )


    def _pin_patches(self, hashes: dict[str, str], architecture: str):
        vc = dict(gate.VC_REDIST_SHA256)
        msi = dict(gate.AMNEZIAWG_MSI_SHA256)
        awg = dict(gate.AWG_TOOL_SHA256)
        wintun = dict(gate.WINTUN_SHA256)
        xray = dict(gate.XRAY_SHA256)
        vc_name = adapters.PRODUCER_VC_REDIST_BASENAME[architecture]
        msi_name = adapters.PRODUCER_AMNEZIAWG_MSI_BASENAME[architecture]
        if vc_name in hashes:
            vc[architecture] = hashes[vc_name]
        if msi_name in hashes:
            msi[architecture] = hashes[msi_name]
        if "awg.exe" in hashes:
            awg[architecture] = hashes["awg.exe"]
        if "wintun.dll" in hashes:
            wintun[architecture] = hashes["wintun.dll"]
        if "xray.exe" in hashes:
            xray[architecture] = hashes["xray.exe"]
        return (
            mock.patch.object(gate, "VC_REDIST_SHA256", vc),
            mock.patch.object(gate, "AMNEZIAWG_MSI_SHA256", msi),
            mock.patch.object(gate, "AWG_TOOL_SHA256", awg),
            mock.patch.object(gate, "WINTUN_SHA256", wintun),
            mock.patch.object(gate, "XRAY_SHA256", xray),
            mock.patch.object(gate, "_verify_privacy_of_paths", return_value=None),
        )

    def test_product_pe_allowlist_does_not_include_producer_support_payloads(self) -> None:
        for architecture in ("x64", "arm64"):
            with self.subTest(architecture=architecture):
                pe_names = gate._required_pe_basenames(False, architecture)
                self.assertNotIn(
                    adapters.PRODUCER_VC_REDIST_BASENAME[architecture], pe_names
                )
                self.assertNotIn(
                    adapters.PRODUCER_AMNEZIAWG_MSI_BASENAME[architecture], pe_names
                )
                required = gate._required_payload_basenames(False, architecture)
                self.assertIn(
                    adapters.PRODUCER_VC_REDIST_BASENAME[architecture], required
                )
                self.assertIn(
                    adapters.PRODUCER_AMNEZIAWG_MSI_BASENAME[architecture], required
                )
                standalone = gate._required_payload_basenames(True, architecture)
                self.assertIn(
                    adapters.PRODUCER_VC_REDIST_BASENAME[architecture], standalone
                )
                self.assertNotIn(
                    adapters.PRODUCER_AMNEZIAWG_MSI_BASENAME[architecture], standalone
                )

    def test_producer_shaped_support_payloads_are_target_specific(self) -> None:
        self.assertEqual(
            adapters.PRODUCER_VC_REDIST_BASENAME["x64"], "VC_redist.x64.exe"
        )
        self.assertEqual(
            adapters.PRODUCER_VC_REDIST_BASENAME["arm64"], "VC_redist.arm64.exe"
        )
        self.assertEqual(
            adapters.PRODUCER_AMNEZIAWG_MSI_BASENAME["x64"], "amneziawg-amd64.msi"
        )
        self.assertEqual(
            adapters.PRODUCER_AMNEZIAWG_MSI_BASENAME["arm64"], "amneziawg-arm64.msi"
        )
        for target, architecture in (
            ("windows-x64-installer", "x64"),
            ("windows-x64-partner-center", "x64"),
            ("windows-arm64-installer", "arm64"),
            ("windows-arm64-partner-center", "arm64"),
        ):
            with self.subTest(target=target):
                artifact, hashes = self.harness.candidate(
                    target, write_install_proof=False
                )
                result = self.harness.verify_fixture(
                    target, artifact, hashes, extract=True
                )
                packed = self.harness.packed_from_stage(artifact)
                self.assertTrue(result["ok"])
                self.assertIn(adapters.PRODUCER_VC_REDIST_BASENAME[architecture], packed)
                self.assertIn(
                    adapters.PRODUCER_AMNEZIAWG_MSI_BASENAME[architecture], packed
                )
                other = "arm64" if architecture == "x64" else "x64"
                self.assertNotIn(adapters.PRODUCER_VC_REDIST_BASENAME[other], packed)
                self.assertNotIn(
                    adapters.PRODUCER_AMNEZIAWG_MSI_BASENAME[other], packed
                )
                self.assertTrue(
                    packed[adapters.PRODUCER_AMNEZIAWG_MSI_BASENAME[architecture]].startswith(
                        gate.MSI_OLE_MAGIC
                    )
                )

    def test_allowlist_shaped_package_without_support_payloads_is_incomplete(
        self,
    ) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        record = self.harness.load_manifest(artifact)
        record["payload"] = [
            entry
            for entry in record["payload"]
            if not str(entry["path"]).endswith("VC_redist.x64.exe")
            and not str(entry["path"]).endswith("amneziawg-amd64.msi")
        ]
        self.harness.save_manifest(artifact, record)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"incomplete: amneziawg-amd64\.msi, vc_redist\.x64\.exe",
        ):
            self.harness.verify_fixture("windows-x64-installer", artifact, hashes)

    def test_missing_target_vc_redist_fails_closed(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-arm64-installer", write_install_proof=False
        )
        record = self.harness.load_manifest(artifact)
        record["payload"] = [
            entry
            for entry in record["payload"]
            if not str(entry["path"]).endswith("VC_redist.arm64.exe")
        ]
        self.harness.save_manifest(artifact, record)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"incomplete: vc_redist\.arm64\.exe"
        ):
            self.harness.verify_fixture("windows-arm64-installer", artifact, hashes)

    def test_missing_target_amneziawg_msi_fails_closed(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        record = self.harness.load_manifest(artifact)
        record["payload"] = [
            entry
            for entry in record["payload"]
            if not str(entry["path"]).endswith("amneziawg-amd64.msi")
        ]
        self.harness.save_manifest(artifact, record)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"incomplete: amneziawg-amd64\.msi"
        ):
            self.harness.verify_fixture("windows-x64-installer", artifact, hashes)

    def test_wrong_architecture_support_payloads_are_rejected(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        foreign_vc = adapters.producer_vc_redist_pe("arm64")
        foreign_msi = adapters.producer_amneziawg_msi("arm64")
        self.harness.write("stage/VC_redist.arm64.exe", foreign_vc)
        self.harness.write("stage/amneziawg-arm64.msi", foreign_msi)
        record = self.harness.load_manifest(artifact)
        record["payload"].extend(
            [
                {
                    "path": "stage/VC_redist.arm64.exe",
                    "size": len(foreign_vc),
                    "sha256": hashlib.sha256(foreign_vc).hexdigest(),
                },
                {
                    "path": "stage/amneziawg-arm64.msi",
                    "size": len(foreign_msi),
                    "sha256": hashlib.sha256(foreign_msi).hexdigest(),
                },
            ]
        )
        self.harness.save_manifest(artifact, record)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"wrong-architecture Windows support payload",
        ):
            self.harness.verify_fixture("windows-x64-installer", artifact, hashes)

    def test_standalone_amneziawg_msi_is_forbidden(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer",
            standalone_winn3=True,
            write_install_proof=False,
        )
        planted = adapters.producer_amneziawg_msi("x64")
        self.harness.write("stage/amneziawg-amd64.msi", planted)
        record = self.harness.load_manifest(artifact)
        record["payload"].append(
            {
                "path": "stage/amneziawg-amd64.msi",
                "size": len(planted),
                "sha256": hashlib.sha256(planted).hexdigest(),
            }
        )
        self.harness.save_manifest(artifact, record)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"forbidden AmneziaWG MSI support payload",
        ):
            self.harness.verify_fixture(
                "windows-x64-installer", artifact, hashes, standalone_winn3=True
            )

    def test_support_payload_hash_mismatch_fails_closed(self) -> None:
        artifact, _hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        packed = self.harness.packed_from_stage(artifact)
        packed["VC_redist.x64.exe"] = packed["VC_redist.x64.exe"] + b"\x00"
        inventory = gate._payload_inventory(self.harness.load_manifest(artifact))
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"packed VC_redist\.x64\.exe does not match the producer inventory",
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

    def test_hostile_product_pe_debug_metadata_is_rejected(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        hostile = adapters.app_pe(gate.PE_MACHINE_X64, codeview=True)
        packed = self.harness.packed_from_stage(artifact)
        packed["wins_vpn.exe"] = hostile
        digest = hashlib.sha256(hostile).hexdigest()
        hashes["wins_vpn.exe"] = digest
        record = self.harness.load_manifest(artifact)
        for entry in record["payload"]:
            if str(entry["path"]).endswith("wins_vpn.exe"):
                entry["sha256"] = digest
                entry["size"] = len(hostile)
        self.harness.save_manifest(artifact, record)
        inventory = gate._payload_inventory(record)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"packed wins_vpn\.exe retains native debug metadata",
        ):
            with ExitStack() as stack:
                for patcher in self._pin_patches(hashes, "x64"):
                    stack.enter_context(patcher)
                gate.verify_packed_inner_payloads(
                    packed,
                    inventory,
                    "x64",
                    "1.0.17",
                    "1.0.17.34",
                    False,
                    custody_policy=adapters.reviewed_custody_policy(),
                )

    def test_vendor_vc_redist_debug_metadata_is_accepted_when_hash_and_publisher_match(
        self,
    ) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        vendor = adapters.producer_vc_redist_pe("x64", codeview=True)
        packed = self.harness.packed_from_stage(artifact)
        original = bytes(vendor)
        packed["VC_redist.x64.exe"] = vendor
        digest = hashlib.sha256(vendor).hexdigest()
        hashes["VC_redist.x64.exe"] = digest
        record = self.harness.load_manifest(artifact)
        for entry in record["payload"]:
            if str(entry["path"]).endswith("VC_redist.x64.exe"):
                entry["sha256"] = digest
                entry["size"] = len(vendor)
        self.harness.save_manifest(artifact, record)
        inventory = gate._payload_inventory(record)
        self.assertTrue(gate._inner_pe_debug_sections(vendor))
        with ExitStack() as stack:
            for patcher in self._pin_patches(hashes, "x64"):
                stack.enter_context(patcher)
            gate.verify_packed_inner_payloads(
                packed,
                inventory,
                "x64",
                "1.0.17",
                "1.0.17.34",
                False,
                custody_policy=adapters.reviewed_custody_policy(),
            )
        self.assertEqual(packed["VC_redist.x64.exe"], original)
        self.assertTrue(gate._inner_pe_debug_sections(packed["VC_redist.x64.exe"]))

    def test_vendor_debug_metadata_without_reviewed_hash_is_rejected(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        vendor = adapters.producer_vc_redist_pe("x64", codeview=True)
        packed = self.harness.packed_from_stage(artifact)
        packed["VC_redist.x64.exe"] = vendor
        digest = hashlib.sha256(vendor).hexdigest()
        record = self.harness.load_manifest(artifact)
        for entry in record["payload"]:
            if str(entry["path"]).endswith("VC_redist.x64.exe"):
                entry["sha256"] = digest
                entry["size"] = len(vendor)
        self.harness.save_manifest(artifact, record)
        inventory = gate._payload_inventory(record)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"packed VC_redist\.x64\.exe retains native debug metadata",
        ):
            with ExitStack() as stack:
                for patcher in self._pin_patches(hashes, "x64"):
                    stack.enter_context(patcher)
                gate.verify_packed_inner_payloads(
                    packed,
                    inventory,
                    "x64",
                    "1.0.17",
                    "1.0.17.34",
                    False,
                    custody_policy=adapters.reviewed_custody_policy(),
                )

    def test_vendor_debug_metadata_with_wrong_publisher_is_rejected(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        lookalike = adapters.signed_pe(
            gate.PE_MACHINE_X86,
            version={
                "CompanyName": gate.VC_REDIST_PUBLISHER_CN,
                "FileDescription": "Win32 Cabinet Self-Extractor",
                "OriginalFilename": "VC_redist.x64.exe",
                "ProductName": adapters.PRODUCER_VC_REDIST_PRODUCT_NAME["x64"],
                "ProductVersion": gate.VC_REDIST_VERSION,
            },
            file_version=gate.VC_REDIST_VERSION,
            product_version=gate.VC_REDIST_VERSION,
            signer=adapters.lookalike_untrusted_signer(),
            codeview=True,
        )
        packed = self.harness.packed_from_stage(artifact)
        packed["VC_redist.x64.exe"] = lookalike
        digest = hashlib.sha256(lookalike).hexdigest()
        hashes["VC_redist.x64.exe"] = digest
        record = self.harness.load_manifest(artifact)
        for entry in record["payload"]:
            if str(entry["path"]).endswith("VC_redist.x64.exe"):
                entry["sha256"] = digest
                entry["size"] = len(lookalike)
        self.harness.save_manifest(artifact, record)
        inventory = gate._payload_inventory(record)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"Authenticode publisher is not the reviewed vendor identity",
        ):
            with ExitStack() as stack:
                for patcher in self._pin_patches(hashes, "x64"):
                    stack.enter_context(patcher)
                gate.verify_packed_inner_payloads(
                    packed,
                    inventory,
                    "x64",
                    "1.0.17",
                    "1.0.17.34",
                    False,
                    custody_policy=adapters.reviewed_custody_policy(),
                )

    def test_amneziawg_msi_without_publisher_binding_is_rejected(self) -> None:
        artifact, hashes = self.harness.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        hostile = gate.MSI_OLE_MAGIC + b"unsigned-msi-bytes"
        packed = self.harness.packed_from_stage(artifact)
        packed["amneziawg-amd64.msi"] = hostile
        digest = hashlib.sha256(hostile).hexdigest()
        hashes["amneziawg-amd64.msi"] = digest
        record = self.harness.load_manifest(artifact)
        for entry in record["payload"]:
            if str(entry["path"]).endswith("amneziawg-amd64.msi"):
                entry["sha256"] = digest
                entry["size"] = len(hostile)
        self.harness.save_manifest(artifact, record)
        inventory = gate._payload_inventory(record)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"not publisher-bound to Privacy Technologies OU",
        ):
            with ExitStack() as stack:
                for patcher in self._pin_patches(hashes, "x64"):
                    stack.enter_context(patcher)
                gate.verify_packed_inner_payloads(
                    packed,
                    inventory,
                    "x64",
                    "1.0.17",
                    "1.0.17.34",
                    False,
                    custody_policy=adapters.reviewed_custody_policy(),
                )


if __name__ == "__main__":
    unittest.main()
