#!/usr/bin/env python3
"""Focused fail-closed tests for the Windows cross-store artifact gate."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import pathlib
import sys
import unittest
from unittest import mock

TOOLS = pathlib.Path(__file__).resolve().parent
ROOT = TOOLS.parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import windows_cross_store_artifact_gate as gate
from test_windows_cross_store_gate_adapters import (
    WindowsCrossStoreGateFixtures,
    authenticode_signtool_stdout,
    build_receipt_payload,
    encode_pkcs7,
    installer_pe,
    origin_digest,
    reviewed_signer,
    signed_pe,
    valid_offline_authenticode_proof,
)


class WindowsCrossStoreArtifactGateTests(
    WindowsCrossStoreGateFixtures, unittest.TestCase
):
    def test_owner_signing_and_store_receipts_stay_blocked(self) -> None:
        self.assertEqual(
            gate.OWNER_AUTHENTICODE_LEAF_SHA256, gate.OWNER_AUTHENTICODE_BLOCKED
        )
        self.assertEqual(
            gate.OWNER_AUTHENTICODE_SIGNTOOL, gate.OWNER_AUTHENTICODE_BLOCKED
        )
        self.assertEqual(
            gate.OWNER_UPLOAD_RECEIPT_PUBLIC_KEY_HEX, gate.OWNER_AUTHENTICODE_BLOCKED
        )
        self.assertTrue(gate.owner_authenticode_pin_blocked())
        self.assertTrue(gate.owner_authenticode_signtool_blocked())
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"owner/environment blocker:.*OWNER-BLOCKED: ABSENT",
        ):
            gate.authenticode_verify_argv(
                gate.OWNER_AUTHENTICODE_SIGNTOOL, "/abs/snapshot.bin"
            )

    def test_exact_non_shell_signtool_argv_is_bound_to_snapshot(self) -> None:
        argv = gate.authenticode_verify_argv(
            "/abs/signtool.exe", "/abs/snapshot.bin"
        )
        self.assertEqual(
            argv,
            [
                "/abs/signtool.exe",
                "verify",
                "/pa",
                "/all",
                "/v",
                "/tw",
                "/abs/snapshot.bin",
            ],
        )
        self.assertEqual(tuple(argv[1:6]), gate.AUTHENTICODE_VERIFY_ARGV_PREFIX)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.AUTHENTICODE_ARGV_ERROR
        ):
            gate.authenticode_verify_argv("/abs/signtool", "/abs/snapshot.bin")
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.AUTHENTICODE_ARGV_ERROR
        ):
            gate._require_exact_authenticode_argv(
                [
                    "/abs/cmd.exe",
                    "/c",
                    "signtool.exe",
                    "verify",
                    "/pa",
                    "/abs/snapshot.bin",
                ],
                "/abs/snapshot.bin",
            )

    def test_caller_authored_authenticode_json_is_never_verification_evidence(
        self,
    ) -> None:
        leaf = gate.authenticode_leaf_identity(
            "WinsVPN-Setup.exe", installer_pe("windows-x64-installer")
        )
        forged = {
            "winverifytrust_status": 0,
            "timestamp_verified": True,
            "owner_authenticode_leaf_sha256": leaf["sha256"],
            "signer_subject": leaf["subject"],
        }
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            gate.CALLER_AUTHORED_AUTHENTICODE_JSON_ERROR,
        ):
            gate._require_offline_authenticode_proof(
                forged,
                leaf,
                target_id="windows-x64-installer",
                snapshot_sha256="a" * 64,
            )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            gate.CALLER_AUTHORED_AUTHENTICODE_JSON_ERROR,
        ):
            gate._parse_authenticode_verify_output(
                json.dumps(
                    {
                        "winverifytrust_status": 0,
                        "signature_verified": True,
                        "schema": gate.WEBSITE_WINVERIFYTRUST_SCHEMA,
                    }
                ),
                "",
                leaf,
            )

    def test_website_signing_evidence_cannot_prove_partner_center_upload(
        self,
    ) -> None:
        leaf = gate.authenticode_leaf_identity(
            "WinsVPN-PartnerCenter.exe",
            installer_pe("windows-x64-partner-center"),
        )
        proof = valid_offline_authenticode_proof(
            leaf,
            target_id="windows-x64-partner-center",
            surface="website",
        )
        with mock.patch.object(gate, "OWNER_AUTHENTICODE_SIGNTOOL", "/abs/signtool.exe"):
            with mock.patch.object(
                gate, "OWNER_AUTHENTICODE_LEAF_SHA256", leaf["sha256"]
            ):
                with self.assertRaisesRegex(
                    gate.WindowsArtifactGateError,
                    gate.WEBSITE_SIGNING_AS_PARTNER_CENTER_ERROR,
                ):
                    gate._require_offline_authenticode_proof(
                        proof,
                        leaf,
                        target_id="windows-x64-partner-center",
                        snapshot_sha256="a" * 64,
                    )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            gate.WEBSITE_SIGNING_AS_PARTNER_CENTER_ERROR,
        ):
            gate._reject_website_signing_evidence(
                "windows-x64-partner-center",
                {
                    "signing_contract": "windows-x64-authenticode",
                    "authenticode_json": "artifacts/WinsVPN-Setup.exe.authenticode.json",
                },
            )

    def test_stale_future_and_unbound_build_receipts_fail_closed(self) -> None:
        digest = "c" * 64
        gate._bind_windows_build_receipt(
            "windows-x64-installer",
            build_receipt_payload(
                name="WinsVPN-Setup.exe", digest=digest, size_bytes=8
            ),
            expected_sha256=digest,
            expected_bytes=8,
        )
        future = (
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(hours=1)
        ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.BUILD_RECEIPT_STALE_ERROR
        ):
            gate._bind_windows_build_receipt(
                "windows-x64-installer",
                build_receipt_payload(
                    name="WinsVPN-Setup.exe",
                    digest=digest,
                    size_bytes=8,
                    finished_utc=future,
                ),
                expected_sha256=digest,
                expected_bytes=8,
            )
        authorized = build_receipt_payload(
            name="WinsVPN-Setup.exe", digest=digest, size_bytes=8
        )
        record = json.loads(authorized.decode("ascii"))
        record["publication_authorized"] = True
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.BUILD_RECEIPT_IDENTITY_ERROR
        ):
            gate._bind_windows_build_receipt(
                "windows-x64-installer",
                json.dumps(record).encode("ascii"),
                expected_sha256=digest,
                expected_bytes=8,
            )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.BUILD_RECEIPT_IDENTITY_ERROR
        ):
            gate._bind_windows_build_receipt(
                "windows-x64-installer",
                build_receipt_payload(
                    name="WinsVPN-Setup.exe",
                    digest=digest,
                    size_bytes=8,
                    release="1.0.14+29",
                ),
                expected_sha256=digest,
                expected_bytes=8,
            )

    def test_snapshot_refuses_hardlink_and_symlink_path_replacement(self) -> None:
        artifact, hashes = self.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        origin = self.repo / artifact
        os.link(origin, self.repo / "artifacts" / "alias.exe")
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, "single-link|singly-linked"
        ):
            self.verify_fixture(
                "windows-x64-installer", artifact, hashes, extract=True
            )
        (self.repo / "artifacts" / "alias.exe").unlink()
        real = origin.with_name("real-WinsVPN-Setup.exe")
        origin.rename(real)
        origin.symlink_to(real)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, "symlink|reparse"
        ):
            gate.canonical_artifact("windows-x64-installer", artifact)

    def test_weak_digest_unsigned_and_wrong_publisher_fail_closed(self) -> None:
        leaf = gate.authenticode_leaf_identity(
            "WinsVPN-Setup.exe", installer_pe("windows-x64-installer")
        )
        missing_ts = "\n".join(
            line
            for line in authenticode_signtool_stdout(leaf).splitlines()
            if "timestamp" not in line.casefold() and "signing time" not in line.casefold()
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.TIMESTAMP_UNVERIFIED_ERROR
        ):
            gate._parse_authenticode_verify_output(missing_ts, "", leaf)
        ca, cert, _key = reviewed_signer()
        weak = installer_pe(
            "windows-x64-installer",
            pkcs7=encode_pkcs7(
                [ca, cert],
                cert,
                timestamp=True,
                digest_oid="1.3.14.3.2.26",
            ),
        )
        identity = gate.authenticode_leaf_identity("WinsVPN-Setup.exe", weak)
        policy = gate.authenticode_custody_policy(
            "WinsVPN-Setup.exe", weak, identity
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.OUTER_AUTHENTICODE_ERROR
        ):
            gate._verify_outer_pe_authenticode("WinsVPN-Setup.exe", weak, policy)
        artifact, hashes = self.candidate(
            "windows-x64-installer",
            write_install_proof=False,
            installer_bytes=installer_pe(
                "windows-x64-installer", authenticode=False
            ),
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"Authenticode PKCS#7|no embedded Authenticode|invalid WIN_CERTIFICATE",
        ):
            self.verify_fixture(
                "windows-x64-installer", artifact, hashes, extract=True
            )

    def test_verify_fixture_binds_descriptor_identity_and_exact_argv(self) -> None:
        artifact, hashes = self.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        result = self.verify_fixture(
            "windows-x64-installer", artifact, hashes, extract=True
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["target_id"], "windows-x64-installer")
        self.assertEqual(result["target_architecture"], "x64")
        self.assertEqual(result["product_version"], "1.0.17")
        self.assertEqual(result["file_version"], "1.0.17.34")
        self.assertEqual(result["descriptor"], gate.DESCRIPTOR_RELATIVE)
        self.assertEqual(
            result["descriptor_sha256"], origin_digest(gate.DESCRIPTOR_RELATIVE)
        )
        self.assertEqual(
            result["sha256"],
            hashlib.sha256((self.repo / artifact).read_bytes()).hexdigest(),
        )
        self.assertEqual(
            result["authenticode_argv"], list(gate.AUTHENTICODE_VERIFY_ARGV_PREFIX)
        )
        self.assertEqual(result["authenticode_digest_algorithm"], "sha256")
        self.assertEqual(result["authenticode_revocation"], "checked")
        self.assertRegex(result["authenticode_thumbprint"], r"^[0-9a-f]{40}$")
        call = self.authenticode_calls[0]
        argv = call["argv"]
        self.assertEqual(len(argv), 7)
        self.assertEqual(argv[1:6], list(gate.AUTHENTICODE_VERIFY_ARGV_PREFIX))
        self.assertTrue(pathlib.Path(str(argv[0])).is_absolute())
        self.assertTrue(str(argv[6]).endswith("snapshot.bin"))
        self.assertIs(call["kwargs"]["shell"], False)
        self.assertFalse(result["network_accessed"])

    def test_source_does_not_use_shell_or_caller_json_as_trust(self) -> None:
        source = pathlib.Path(gate.__file__).read_text(encoding="utf-8")
        self.assertIn("import subprocess", source)
        self.assertIn("shell=False", source)
        self.assertIn("AUTHENTICODE_VERIFY_ARGV_PREFIX", source)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("import ctypes", source)
        self.assertNotIn("WinVerifyTrust", source)
        self.assertNotIn("Get-AuthenticodeSignature", source)
        self.assertNotIn("shutil.which", source)

    def test_non_x86_bootstrap_and_test_only_cannot_false_green(self) -> None:
        native = signed_pe(
            gate.PE_MACHINE_ARM64,
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
        artifact, hashes = self.candidate(
            "windows-x64-installer",
            write_install_proof=False,
            installer_bytes=native,
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.INNO_BOOTSTRAP_ERROR
        ):
            self.verify_fixture(
                "windows-x64-installer", artifact, hashes, extract=True
            )
        artifact, hashes = self.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        with mock.patch.object(gate, "TEST_ONLY", True):
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError,
                "TEST_ONLY Windows gate cannot emit a production pass",
            ):
                self.verify_fixture(
                    "windows-x64-installer", artifact, hashes, extract=True
                )
        self.assertEqual(
            gate.EVIDENCE_COLLECTOR_RELATIVE,
            "tools/windows_release_matrix_evidence.py",
        )
        self.assertIn("evidence_collector", gate.PACKAGE_UPLOAD_RECEIPT_KEYS)
        self.assertIn("evidence_collector", gate.SHARED_UPLOAD_RECEIPT_PATH_FIELDS)


if __name__ == "__main__":
    unittest.main()
