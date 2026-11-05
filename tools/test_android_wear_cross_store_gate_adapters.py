#!/usr/bin/env python3
"""Focused contracts for Android, TV, and Wear cross-store gate adapters."""

from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))


def load(relative: str, name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


SIGNER = load("tools/verify_android_aab_signers.py", "cross_store_android_signer")
OBFUSCATION = load(
    "tools/release_obfuscation_contract.py", "cross_store_android_obfuscation"
)
WEAR = load("wear_os/tools/signed_aab_receipt.py", "cross_store_wear_receipt")
READINESS = load("tools/cross_store_upload_readiness.py", "cross_store_readiness_adapter_test")


class AndroidWearCrossStoreGateAdapterTest(unittest.TestCase):
    def test_cross_store_model_and_owner_gates_remain_unchanged(self) -> None:
        self.assertEqual(len(READINESS.REQUIRED_UPLOAD_TARGETS), 16)
        self.assertEqual(READINESS.PLANNED_UNSUPPORTED_TARGETS, {})
        self.assertEqual(
            READINESS.GATE_PRODUCER_IDS["android-upload-certificate"],
            ("tools/verify_android_aab_signers.py",),
        )
        self.assertEqual(
            READINESS.GATE_PRODUCER_IDS["android-obfuscation-privacy"],
            ("tools/release_obfuscation_contract.py",),
        )
        self.assertEqual(
            READINESS.GATE_PRODUCER_IDS["wear-r8-privacy"],
            ("wear_os/tools/signed_aab_receipt.py",),
        )
        source = (ROOT / "tools/cross_store_upload_readiness.py").read_text(
            encoding="utf-8"
        )
        for owner_gate in (
            "QUERY_ALL_PACKAGES",
            "submission_approved",
            "Purchase History",
        ):
            self.assertIn(owner_gate, source)

    def test_signing_adapter_runs_structure_crypto_and_identity_on_one_path(self) -> None:
        artifact = ROOT / "fixture.aab"
        bound = (7, (11, 22), 1234, "ab" * 32)
        retained = unittest.mock.MagicMock()
        retained.__enter__.return_value = bound
        retained.__exit__.return_value = False
        with (
            mock.patch.object(SIGNER, "_canonical_gate_artifact", return_value=artifact),
            mock.patch.object(
                SIGNER, "_retained_live_repo_file", return_value=retained
            ) as hold,
            mock.patch.object(SIGNER, "verify_held_aab_artifact") as held_verify,
            mock.patch.object(SIGNER, "_reviewed_store_metadata") as store,
        ):
            SIGNER.canonical_gate_verify("android-tv-aab", "artifacts/tv.aab")
        hold.assert_called_once_with("fixture.aab", "cross-store AAB")
        held_verify.assert_called_once_with(
            target_id="android-tv-aab",
            source_fd=7,
            expected_identity=(11, 22),
            expected_size=1234,
            expected_sha256="ab" * 32,
        )
        store.assert_called_once_with("android-tv-aab")
        # The held verifier runs structure, signature and identity on the one
        # retained copy of the candidate bytes.
        held = inspect.getsource(SIGNER.verify_held_aab_artifact)
        for required in (
            "verify_bytes(held.payload)",
            "analyze_held_aab(held.payload)",
            "_verify_cryptographic_signature(\n            held.tool_path,",
            "_enforce_target_identity(target_id, analysis)",
        ):
            self.assertIn(required, held)

    def test_signing_adapter_rejects_unknown_target_before_artifact_access(self) -> None:
        with self.assertRaisesRegex(SIGNER.SignerError, "unsupported exact"):
            SIGNER._canonical_gate_artifact("android-not-real", "missing.aab")

    def test_signing_adapter_rejects_tv_artifact_reused_as_phone(self) -> None:
        analysis = {
            "package": "org.winsvpn.app",
            "version_name": "1.0.16",
            "version_code": 33,
            "is_tv": True,
            "is_wear": False,
            "has_leanback_launcher": True,
            "modules": frozenset({"base"}),
            "abis": SIGNER.PHONE_TV_ABIS,
            "certificate_sha256": SIGNER._reviewed_upload_certificate(),
            "certificate_subject": "WinUpload",
            "metadata": {
                "libapp_debug": True,
                "libflutter_debug": True,
                "proguard_map": True,
            },
            "feature_required": {
                "android.software.leanback": "false",
                "android.hardware.touchscreen": "false",
            },
            "application_label": "Win's VPN",
            "application_banner": "@drawable/banner",
            "activities": ["org.winsvpn.app.MainActivity"],
            "permissions": {
                "android.permission.INTERNET",
                "android.permission.QUERY_ALL_PACKAGES",
            },
            "vpn_services": ["org.winsvpn.app.VpnTunnelService"],
            "native_engines": {
                abi: set(SIGNER.PHONE_TV_REQUIRED_NATIVE_ENGINES)
                for abi in SIGNER.PHONE_TV_ABIS
            },
            "forbidden_native": (),
            "private_symbols_leaked": False,
            "r8": {"ok": True, "class_mapping_count": 40},
        }
        with (
            mock.patch.object(SIGNER, "_assert_frozen_bundletool"),
            mock.patch.object(
                SIGNER, "_hold_aab_bytes", return_value=(b"held", (1, 2, 3, 4), "abc")
            ),
            mock.patch.object(SIGNER, "analyze_held_aab", return_value=analysis),
            mock.patch.object(SIGNER, "_cross_check_bundletool_identity"),
            mock.patch.object(SIGNER, "_revalidate_held_aab"),
        ):
            with self.assertRaisesRegex(SIGNER.SignerError, "another exact target"):
                SIGNER._verify_target_identity(
                    "android-phone-tablet-aab", ROOT / "fixture.aab"
                )

    def test_signing_adapter_rejects_stale_version_name_and_wrong_version_code(self) -> None:
        base = {
            "package": "org.winsvpn.app",
            "is_tv": False,
            "is_wear": False,
            "has_leanback_launcher": False,
            "modules": frozenset({"base"}),
            "abis": SIGNER.PHONE_TV_ABIS,
            "certificate_sha256": SIGNER._reviewed_upload_certificate(),
            "certificate_subject": "WinUpload",
            "metadata": {
                "libapp_debug": True,
                "libflutter_debug": True,
                "proguard_map": True,
            },
            "feature_required": {},
            "application_label": "Calculator",
            "application_banner": None,
            "activities": ["org.winsvpn.app.MainActivity"],
            "permissions": {
                "android.permission.INTERNET",
                "android.permission.QUERY_ALL_PACKAGES",
            },
            "vpn_services": ["org.winsvpn.app.VpnTunnelService"],
            "native_engines": {
                abi: set(SIGNER.PHONE_TV_REQUIRED_NATIVE_ENGINES)
                for abi in SIGNER.PHONE_TV_ABIS
            },
            "forbidden_native": (),
            "private_symbols_leaked": False,
            "r8": {"ok": True, "class_mapping_count": 40},
        }
        for version_code, version_name in ((33, "9.9.9"), (999, "1.0.16")):
            with self.subTest(version_code=version_code, version_name=version_name):
                analysis = dict(base)
                analysis["version_code"] = version_code
                analysis["version_name"] = version_name
                with (
                    mock.patch.object(SIGNER, "_assert_frozen_bundletool"),
                    mock.patch.object(
                        SIGNER,
                        "_hold_aab_bytes",
                        return_value=(b"held", (1, 2, 3, 4), "abc"),
                    ),
                    mock.patch.object(SIGNER, "analyze_held_aab", return_value=analysis),
                    mock.patch.object(SIGNER, "_cross_check_bundletool_identity"),
                    mock.patch.object(SIGNER, "_revalidate_held_aab"),
                    self.assertRaisesRegex(SIGNER.SignerError, "version identity"),
                ):
                    SIGNER._verify_target_identity(
                        "android-phone-tablet-aab", ROOT / "fixture.aab"
                    )

    def test_all_canonical_clis_require_exactly_three_arguments(self) -> None:
        cases = (
            (SIGNER, SIGNER.SignerError),
            (OBFUSCATION, OBFUSCATION.ObfuscationError),
        )
        for module, error in cases:
            with self.subTest(module=module.__name__):
                with self.assertRaisesRegex(error, "exactly --verify"):
                    module.main(["--verify", "android-phone-tablet-aab"])
        self.assertEqual(WEAR.main(["--verify", "wear-os-aab"]), 1)

    def test_obfuscation_adapter_dispatch_is_exact_and_non_building(self) -> None:
        source = (ROOT / "tools/release_obfuscation_contract.py").read_text(
            encoding="utf-8"
        )
        for required in (
            "verify_android_aab_signers.py",
            "verify_android_aab_page_alignment.py",
            "validate_release_artifact_privacy.py",
            'verify("android-aab", manifest, symbols_dir, [artifact])',
        ):
            self.assertIn(required, source)
        adapter = source[
            source.index("def canonical_android_gate_verify") : source.index(
                "def validate_static"
            )
        ]
        for forbidden in ("flutter build", "gradlew", "bundleRelease"):
            self.assertNotIn(forbidden, adapter)

    def test_wear_adapter_dispatches_only_the_exact_wear_target(self) -> None:
        expected = {"ok": True}
        with mock.patch.object(WEAR, "canonical_gate_verify", return_value=expected) as gate:
            self.assertEqual(
                WEAR.main(["--verify", "wear-os-aab", "artifacts/wear.aab"]), 0
            )
        gate.assert_called_once_with(
            WEAR.DEFAULT_REPO, "wear-os-aab", "artifacts/wear.aab"
        )
        with self.assertRaisesRegex(WEAR.ReceiptError, "unsupported exact Wear"):
            WEAR._canonical_gate_artifact(
                ROOT, "android-tv-aab", "artifacts/wear.aab"
            )

    def test_wear_adapter_reexecutes_identity_signing_privacy_and_r8_custody(self) -> None:
        source = (ROOT / "wear_os/tools/signed_aab_receipt.py").read_text(
            encoding="utf-8"
        )
        adapter = source[source.index("def canonical_gate_verify") : source.index("def _parser")]
        for required in (
            "_assert_wear_signed_aab",
            "_reviewed_upload_certificate_sha256",
            "_certificate",
            "_verify_release_gates",
            "_gate_claims",
            "_verify_aab_page_alignment",
            "_bind_unique_wear_receipt",
            "_reject_origin_swap",
            "_reviewed_store_metadata",
            "store_metadata",
            "CANONICAL_RELEASE",
            'symbols_dir / "mapping.txt"',
        ):
            self.assertIn(required, adapter)
        for forbidden in ("bundleRelease", "record("):
            self.assertNotIn(forbidden, adapter)

    def test_phone_tv_and_wear_identities_are_exact_1015_candidates(self) -> None:
        identity = json.loads(
            (ROOT / "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(identity["canonical_release"], "1.0.16+33")
        self.assertEqual(
            SIGNER._reviewed_target_identity("android-phone-tablet-aab"),
            ("org.winsvpn.app", "1.0.16", 33),
        )
        self.assertEqual(
            SIGNER._reviewed_target_identity("android-tv-aab"),
            ("org.winsvpn.app", "1.0.16", 3302),
        )
        self.assertEqual(
            SIGNER._reviewed_target_identity("wear-os-aab"),
            ("org.winsvpn.app", "1.0.16", 3301),
        )
        self.assertEqual(WEAR.CANONICAL_RELEASE, "1.0.16+33")
        self.assertEqual(WEAR.EXPECTED_APPLICATION_ID, "org.winsvpn.app")
        self.assertEqual(WEAR.WEAR_VERSION_CODE, 3301)
        obfuscation = (ROOT / "tools/release_obfuscation_contract.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("verify_android_aab_page_alignment.py", obfuscation)
        self.assertIn("android-phone-tablet-aab", obfuscation)
        self.assertIn("android-tv-aab", obfuscation)

    def test_wear_gate_stays_pending_and_refuses_receipt_reuse_or_swap(self) -> None:
        source = (ROOT / "wear_os/tools/signed_aab_receipt.py").read_text(encoding="utf-8")
        self.assertIn("Wear receipt reuse is refused", source)
        self.assertIn("swapped or restored", source)
        self.assertIn("owner/build-system blocker", source)
        self.assertIn('"publication_authorized": False', source)
        self.assertIn('"pending": True', source)
        adapter = source[
            source.index("def canonical_gate_verify") : source.index("def _parser")
        ]
        self.assertIn("_bind_unique_wear_receipt", adapter)
        self.assertIn("publication_authorized", adapter)
        self.assertIn("pending", adapter)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


# The signer live-hashes every path a receipt names (artifact, producer,
# descriptor, obfuscation contract, build receipt, source freeze), so the
# fixture digests must be the digests of the exact staged bytes below.
ARTIFACT_PAYLOADS = {
    "android-phone-tablet-aab": b"phone-bytes",
    "android-tv-aab": b"tv-bytes-1234",
    "wear-os-aab": b"wear-bytes-123456",
}
SOURCE_FREEZE_PAYLOAD = b'{"fixture":"source-freeze"}\n'


def _fixture_build_receipt_bytes(target_id: str) -> bytes:
    return f'{{"fixture":"{target_id}"}}\n'.encode("ascii")


def _staged_digest(relative: str) -> str:
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()


def _issue_android_receipt(record: dict[str, object]) -> dict[str, object]:
    spec = SIGNER.ANDROID_PACKAGE_UPLOAD_TARGETS[str(record["target_id"])]
    artifact = record["artifact"]
    record["authentication"] = SIGNER.issue_upload_receipt_challenge(
        str(record["target_id"]),
        artifact_sha256=str(artifact["sha256"]),
        artifact_bytes=int(artifact["bytes"]),
        architectures=tuple(str(item) for item in spec["architectures"]),
        release=str(record["release"]),
    )
    return record


def _store_evidence(target_id: str, spec: dict[str, object]) -> dict[str, object]:
    evidence: dict[str, object] = {
        "surface": spec["store_surface"],
        "status": "not_uploaded",
    }
    if target_id == "wear-os-aab":
        evidence["metadata_sha256"] = SIGNER._reviewed_wear_store_metadata()["sha256"]
    else:
        evidence["metadata_sha256"] = SIGNER._reviewed_store_metadata(target_id)["sha256"]
    return evidence


def _android_upload_receipt(
    target_id: str,
    *,
    digest: str,
    size: int,
    certificate: str,
) -> dict[str, object]:
    spec = SIGNER.ANDROID_PACKAGE_UPLOAD_TARGETS[target_id]
    return {
        "ok": True,
        "schema_version": SIGNER.PACKAGE_UPLOAD_RECEIPT_SCHEMA_VERSION,
        "contract": SIGNER.PACKAGE_UPLOAD_RECEIPT_CONTRACT,
        "release": SIGNER.CANONICAL_RELEASE,
        "target_id": target_id,
        "platform": spec["platform"],
        "artifact": {
            "path": f"artifacts/{target_id}.aab",
            "sha256": digest,
            "bytes": size,
        },
        "build_receipt": {
            "path": f".artifacts/release-build-receipts/android/{target_id}.json",
            "sha256": hashlib.sha256(_fixture_build_receipt_bytes(target_id)).hexdigest(),
            "target": spec["build_receipt_target"],
        },
        "producer": {
            "id": spec["producer"],
            "path": spec["producer"],
            "sha256": _staged_digest(str(spec["producer"])),
        },
        "package_identity": {
            "package": spec["package"],
            "version_name": spec["version_name"],
            "version_code": spec["version_code"],
            "form": spec["form"],
        },
        "architectures": list(spec["architectures"]),
        "signing": {
            "contract": spec["signing_contract"],
            "certificate_sha256": certificate,
        },
        "store_evidence": _store_evidence(target_id, spec),
        "descriptor": {
            "path": SIGNER.DESCRIPTOR_RELATIVE,
            "sha256": _staged_digest(SIGNER.DESCRIPTOR_RELATIVE),
        },
        "source_freeze": {
            "path": ".artifacts/release-freeze-1.0.16+33/SOURCE_FREEZE_RECEIPT.json",
            "sha256": hashlib.sha256(SOURCE_FREEZE_PAYLOAD).hexdigest(),
        },
        "obfuscation_privacy": {
            "path": SIGNER.OBFUSCATION_PRIVACY_RELATIVE,
            "sha256": _staged_digest(SIGNER.OBFUSCATION_PRIVACY_RELATIVE),
        },
        "publication_authorized": False,
        "upload_attempted": False,
        "owner_authorization": {
            "contract": SIGNER.OWNER_AUTHORIZATION_CONTRACT,
            "schema_version": SIGNER.PACKAGE_UPLOAD_RECEIPT_SCHEMA_VERSION,
            "status": "pending",
            "credentials_authorized": False,
            "upload_authorized": False,
        },
        "authentication": {
            "authenticated": True,
            "issuer": SIGNER.UPLOAD_RECEIPT_ISSUER,
            "run_id": "a" * 64,
            "nonce": "b" * 64,
            "issued_at": SIGNER._upload_receipt_now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "challenge": "c" * 128,
            "target_id": target_id,
            "architectures": list(spec["architectures"]),
            "release": SIGNER.CANONICAL_RELEASE,
            "artifact_sha256": digest,
            "artifact_bytes": size,
        },
    }


class AndroidPackageUploadReceiptBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name)
        identity = self.repo / "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json"
        identity.parent.mkdir(parents=True)
        identity.write_bytes(
            (ROOT / "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json").read_bytes()
        )
        # The signer now binds release identity from pinned source files
        # under ROOT (RELEASE_IDENTITY_SOURCE_SHA256), so the fixture repo
        # must carry them byte-identical.
        for relative in SIGNER.RELEASE_IDENTITY_SOURCE_SHA256:
            staged = self.repo / relative
            staged.parent.mkdir(parents=True, exist_ok=True)
            staged.write_bytes((ROOT / relative).read_bytes())
        for form in ("phone", "tv", "wear"):
            shutil.copytree(
                ROOT / f"app_store/android/{form}",
                self.repo / f"app_store/android/{form}",
            )
        self.certificate = "ab" * 32
        self.patches = [
            mock.patch.object(SIGNER, "ROOT", self.repo),
            mock.patch.object(
                SIGNER, "_reviewed_upload_certificate", return_value=self.certificate
            ),
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)
        staged_files = {
            SIGNER.DESCRIPTOR_RELATIVE,
            SIGNER.OBFUSCATION_PRIVACY_RELATIVE,
        } | {
            str(spec["producer"])
            for spec in SIGNER.ANDROID_PACKAGE_UPLOAD_TARGETS.values()
        }
        for relative in sorted(staged_files):
            staged = self.repo / relative
            staged.parent.mkdir(parents=True, exist_ok=True)
            staged.write_bytes((ROOT / relative).read_bytes())
        for target_id, payload in ARTIFACT_PAYLOADS.items():
            artifact = self.repo / "artifacts" / f"{target_id}.aab"
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_bytes(payload)
            build = (
                self.repo
                / ".artifacts/release-build-receipts/android"
                / f"{target_id}.json"
            )
            build.parent.mkdir(parents=True, exist_ok=True)
            build.write_bytes(_fixture_build_receipt_bytes(target_id))
        freeze = self.repo / ".artifacts/release-freeze-1.0.16+33/SOURCE_FREEZE_RECEIPT.json"
        freeze.parent.mkdir(parents=True, exist_ok=True)
        freeze.write_bytes(SOURCE_FREEZE_PAYLOAD)
        self.phone_digest = hashlib.sha256(
            ARTIFACT_PAYLOADS["android-phone-tablet-aab"]
        ).hexdigest()
        self.tv_digest = hashlib.sha256(ARTIFACT_PAYLOADS["android-tv-aab"]).hexdigest()
        self.wear_digest = hashlib.sha256(ARTIFACT_PAYLOADS["wear-os-aab"]).hexdigest()
        self.phone_size = len(ARTIFACT_PAYLOADS["android-phone-tablet-aab"])
        self.tv_size = len(ARTIFACT_PAYLOADS["android-tv-aab"])
        self.wear_size = len(ARTIFACT_PAYLOADS["wear-os-aab"])
        self.records = {
            "android-phone-tablet-aab": _issue_android_receipt(
                _android_upload_receipt(
                    "android-phone-tablet-aab",
                    digest=self.phone_digest,
                    size=self.phone_size,
                    certificate=self.certificate,
                )
            ),
            "android-tv-aab": _issue_android_receipt(
                _android_upload_receipt(
                    "android-tv-aab",
                    digest=self.tv_digest,
                    size=self.tv_size,
                    certificate=self.certificate,
                )
            ),
            "wear-os-aab": _issue_android_receipt(
                _android_upload_receipt(
                    "wear-os-aab",
                    digest=self.wear_digest,
                    size=self.wear_size,
                    certificate=self.certificate,
                )
            ),
        }
        self.artifacts = {
            "android-phone-tablet-aab": (self.phone_digest, self.phone_size),
            "android-tv-aab": (self.tv_digest, self.tv_size),
            "wear-os-aab": (self.wear_digest, self.wear_size),
        }

    def tearDown(self) -> None:
        # Patches stop through addCleanup (registered in setUp), which also
        # runs when setUp itself fails partway, so a failure here cannot leak
        # a patched SIGNER.ROOT into later tests.
        self.temporary.cleanup()

    def test_required_phone_tv_wear_receipts_stay_pending_without_owner_evidence(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            SIGNER.SignerError,
            "pending without owner evidence|no owner-issued",
        ):
            SIGNER.bind_android_package_upload_receipts(self.records, self.artifacts)
        self.assertEqual(SIGNER.canonical_android_release(), SIGNER.CANONICAL_RELEASE)
        phone = self.records["android-phone-tablet-aab"]
        self.assertEqual(phone["package_identity"]["package"], "org.winsvpn.app")
        self.assertEqual(phone["package_identity"]["version_name"], "1.0.16")
        self.assertEqual(phone["package_identity"]["version_code"], 33)
        self.assertEqual(
            self.records["android-tv-aab"]["package_identity"]["version_code"], 3302
        )
        self.assertEqual(
            self.records["wear-os-aab"]["package_identity"]["version_code"], 3301
        )
        self.assertEqual(
            phone["architectures"],
            ["arm64-v8a", "armeabi-v7a", "x86_64"],
        )
        self.assertEqual(
            self.records["wear-os-aab"]["architectures"],
            ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"],
        )

    def test_missing_receipts_remain_pending_without_owner_evidence(self) -> None:
        with self.assertRaisesRegex(
            SIGNER.SignerError, "pending without owner evidence"
        ):
            SIGNER.bind_android_package_upload_receipts({}, {})
        with self.assertRaisesRegex(
            SIGNER.SignerError, "pending without owner evidence"
        ):
            SIGNER.bind_android_package_upload_receipts(
                {"android-phone-tablet-aab": self.records["android-phone-tablet-aab"]},
                {"android-phone-tablet-aab": self.artifacts["android-phone-tablet-aab"]},
            )

    def test_architecture_version_and_form_fail_closed(self) -> None:
        self.records["android-phone-tablet-aab"]["architectures"] = ["arm64-v8a"]
        with self.assertRaisesRegex(SIGNER.SignerError, "architecture inventory"):
            SIGNER.bind_android_package_upload_receipts(self.records, self.artifacts)
        self.records["android-phone-tablet-aab"]["architectures"] = list(
            SIGNER.ANDROID_PACKAGE_UPLOAD_TARGETS["android-phone-tablet-aab"][
                "architectures"
            ]
        )
        self.records["android-tv-aab"]["package_identity"]["version_code"] = 33
        with self.assertRaisesRegex(SIGNER.SignerError, "package identity"):
            SIGNER.bind_package_upload_receipt(
                "android-tv-aab",
                self.records["android-tv-aab"],
                artifact_sha256=self.tv_digest,
                artifact_bytes=self.tv_size,
            )

    def test_receipt_reuse_byte_swap_and_owner_approval_fail_closed(self) -> None:
        self.records["android-tv-aab"]["artifact"]["sha256"] = self.phone_digest
        self.artifacts["android-tv-aab"] = (self.phone_digest, self.tv_size)
        with self.assertRaisesRegex(SIGNER.SignerError, "receipt reuse"):
            SIGNER.bind_android_package_upload_receipts(self.records, self.artifacts)
        self.records["android-tv-aab"]["artifact"]["sha256"] = self.tv_digest
        self.artifacts["android-tv-aab"] = (self.tv_digest, self.tv_size)
        with self.assertRaisesRegex(SIGNER.SignerError, "swapped or does not bind"):
            SIGNER.bind_package_upload_receipt(
                "android-phone-tablet-aab",
                self.records["android-phone-tablet-aab"],
                artifact_sha256=_digest("swapped-aab"),
                artifact_bytes=self.phone_size,
            )
        self.records["wear-os-aab"]["owner_authorization"]["status"] = "approved"
        self.records["wear-os-aab"]["owner_authorization"]["upload_authorized"] = True
        with self.assertRaisesRegex(
            SIGNER.SignerError, "pending without owner evidence"
        ):
            SIGNER.bind_package_upload_receipt(
                "wear-os-aab",
                self.records["wear-os-aab"],
                artifact_sha256=self.wear_digest,
                artifact_bytes=self.wear_size,
            )

    def test_live_bytes_changed_after_the_receipt_fail_closed(self) -> None:
        # The receipt and the caller agree on the digest; only the bytes on
        # disk changed. Only the live re-hash of every named path catches it.
        artifact = self.repo / "artifacts/android-phone-tablet-aab.aab"
        artifact.write_bytes(b"x" * self.phone_size)
        with self.assertRaisesRegex(SIGNER.SignerError, "swapped or does not bind"):
            SIGNER.bind_package_upload_receipt(
                "android-phone-tablet-aab",
                self.records["android-phone-tablet-aab"],
                artifact_sha256=self.phone_digest,
                artifact_bytes=self.phone_size,
            )
        artifact.write_bytes(ARTIFACT_PAYLOADS["android-phone-tablet-aab"])
        descriptor = self.repo / SIGNER.DESCRIPTOR_RELATIVE
        descriptor.write_bytes(descriptor.read_bytes() + b"\n")
        with self.assertRaisesRegex(SIGNER.SignerError, "swapped or does not bind"):
            SIGNER.bind_package_upload_receipt(
                "android-phone-tablet-aab",
                self.records["android-phone-tablet-aab"],
                artifact_sha256=self.phone_digest,
                artifact_bytes=self.phone_size,
            )

    def test_stale_replayed_and_unauthenticated_receipts_fail_closed(self) -> None:
        record = self.records["android-phone-tablet-aab"]
        auth = dict(record["authentication"])
        auth["issued_at"] = "2020-01-01T00:00:00Z"
        record["authentication"] = auth
        with self.assertRaisesRegex(SIGNER.SignerError, "is not fresh"):
            SIGNER.bind_package_upload_receipt(
                "android-phone-tablet-aab",
                record,
                artifact_sha256=self.phone_digest,
                artifact_bytes=self.phone_size,
            )
        signed = _issue_android_receipt(
            _android_upload_receipt(
                "android-phone-tablet-aab",
                digest=self.phone_digest,
                size=self.phone_size,
                certificate=self.certificate,
            )
        )
        signed["authentication"]["challenge"] = "d" * 128
        with self.assertRaisesRegex(
            SIGNER.SignerError, "not authenticated by the trusted issuer"
        ):
            SIGNER.bind_package_upload_receipt(
                "android-phone-tablet-aab",
                signed,
                artifact_sha256=self.phone_digest,
                artifact_bytes=self.phone_size,
            )
        replay = _issue_android_receipt(
            _android_upload_receipt(
                "android-phone-tablet-aab",
                digest=self.phone_digest,
                size=self.phone_size,
                certificate=self.certificate,
            )
        )
        with self.assertRaisesRegex(
            SIGNER.SignerError, "pending without owner evidence|no owner-issued"
        ):
            SIGNER.bind_android_package_upload_receipts(
                {
                    "android-phone-tablet-aab": replay,
                    "android-tv-aab": self.records["android-tv-aab"],
                    "wear-os-aab": self.records["wear-os-aab"],
                },
                self.artifacts,
            )
        # A pending attempt does not burn the challenge: consumption follows
        # a fully successful bind, so stub the owner-signature step (the
        # fixture bytes are not a real signed AAB) to reach it.
        with mock.patch.object(
            SIGNER, "_require_owner_issued_android_signature_held", return_value={}
        ):
            SIGNER.bind_android_package_upload_receipts(
                {
                    "android-phone-tablet-aab": replay,
                    "android-tv-aab": self.records["android-tv-aab"],
                    "wear-os-aab": self.records["wear-os-aab"],
                },
                self.artifacts,
            )
            with self.assertRaisesRegex(
                SIGNER.SignerError, "nonce or run_id was already consumed"
            ):
                SIGNER.bind_android_package_upload_receipts(
                    {
                        "android-phone-tablet-aab": replay,
                        "android-tv-aab": self.records["android-tv-aab"],
                        "wear-os-aab": self.records["wear-os-aab"],
                    },
                    self.artifacts,
                )

    def test_placeholder_ed25519_trust_key_is_refused(self) -> None:
        source = pathlib.Path(SIGNER.__file__).read_text(encoding="ascii")
        self.assertNotIn("UPLOAD_RECEIPT_ISSUER_PUBLIC_KEY_HEX", source)
        self.assertNotIn("Ed25519PublicKey", source)
        self.assertNotIn("Ed25519PrivateKey", source)
        record = _android_upload_receipt(
            "android-phone-tablet-aab",
            digest=self.phone_digest,
            size=self.phone_size,
            certificate=self.certificate,
        )
        record["authentication"]["public_key"] = "cafef00d" * 8
        with self.assertRaisesRegex(SIGNER.SignerError, "placeholder"):
            SIGNER.bind_package_upload_receipt(
                "android-phone-tablet-aab",
                record,
                artifact_sha256=self.phone_digest,
                artifact_bytes=self.phone_size,
            )

    def test_swapped_target_challenge_fails_closed(self) -> None:
        phone = _issue_android_receipt(
            _android_upload_receipt(
                "android-phone-tablet-aab",
                digest=self.phone_digest,
                size=self.phone_size,
                certificate=self.certificate,
            )
        )
        tv = _android_upload_receipt(
            "android-tv-aab",
            digest=self.tv_digest,
            size=self.tv_size,
            certificate=self.certificate,
        )
        tv["authentication"] = dict(phone["authentication"])
        with self.assertRaisesRegex(SIGNER.SignerError, "swapped or does not bind"):
            SIGNER.bind_package_upload_receipt(
                "android-tv-aab",
                tv,
                artifact_sha256=self.tv_digest,
                artifact_bytes=self.tv_size,
            )

    def test_hostile_restart_replay_fails_closed(self) -> None:
        record = _issue_android_receipt(
            _android_upload_receipt(
                "android-phone-tablet-aab",
                digest=self.phone_digest,
                size=self.phone_size,
                certificate=self.certificate,
            )
        )
        with mock.patch.object(
            SIGNER, "_require_owner_issued_android_signature_held", return_value={}
        ):
            SIGNER.bind_package_upload_receipt(
                "android-phone-tablet-aab",
                record,
                artifact_sha256=self.phone_digest,
                artifact_bytes=self.phone_size,
            )
        receipt_path = self.repo / "replay-receipt.json"
        receipt_path.write_text(
            json.dumps(record, ensure_ascii=True) + "\n", encoding="ascii"
        )
        script = (
            "import json, pathlib, sys\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "import verify_android_aab_signers as signer\n"
            "signer.ROOT = pathlib.Path(sys.argv[2])\n"
            "record = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding='ascii'))\n"
            "signer._require_owner_issued_android_signature_held = lambda target_id, candidate: {}\n"
            "signer._reviewed_upload_certificate = lambda: record['signing']['certificate_sha256']\n"
            "try:\n"
            "    signer.bind_package_upload_receipt(\n"
            "        record['target_id'], record,\n"
            "        artifact_sha256=record['artifact']['sha256'],\n"
            "        artifact_bytes=int(record['artifact']['bytes']),\n"
            "    )\n"
            "except signer.SignerError as exc:\n"
            "    sys.stderr.write(str(exc))\n"
            "    raise SystemExit(2)\n"
            "raise SystemExit(0)\n"
        )
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(ROOT / "tools"),
                str(self.repo),
                str(receipt_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertRegex(completed.stderr, "nonce or run_id was already consumed")

    def test_concurrent_challenge_reuse_fails_closed(self) -> None:
        record = _issue_android_receipt(
            _android_upload_receipt(
                "android-phone-tablet-aab",
                digest=self.phone_digest,
                size=self.phone_size,
                certificate=self.certificate,
            )
        )
        errors: list[str] = []
        successes: list[object] = []
        barrier = threading.Barrier(2)

        def worker() -> None:
            barrier.wait()
            try:
                successes.append(
                    SIGNER.bind_package_upload_receipt(
                        "android-phone-tablet-aab",
                        record,
                        artifact_sha256=self.phone_digest,
                        artifact_bytes=self.phone_size,
                    )
                )
            except SIGNER.SignerError as exc:
                errors.append(str(exc))

        with mock.patch.object(
            SIGNER, "_require_owner_issued_android_signature_held", return_value={}
        ):
            threads = [threading.Thread(target=worker), threading.Thread(target=worker)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(errors), 1)
        self.assertTrue(any("already consumed" in item for item in errors))

    def test_ancestor_swap_hardlink_and_special_file_fail_closed(self) -> None:
        artifacts = self.repo / "artifacts"
        artifacts.mkdir(exist_ok=True)
        payload = artifacts / "payload.aab"
        payload.write_bytes(b"good-bytes")
        real_openat = SIGNER._openat_child
        swapped = {"done": False}

        def hook(parent_fd: int, name: str, flags: int) -> int:
            child = real_openat(parent_fd, name, flags)
            if name == "artifacts" and not swapped["done"]:
                swapped["done"] = True
                artifacts.rename(self.repo / "artifacts.old")
                artifacts.mkdir()
                (artifacts / "payload.aab").write_bytes(b"evil-bytes")
            return child

        with mock.patch.object(SIGNER, "_openat_child", side_effect=hook):
            with self.assertRaisesRegex(SIGNER.SignerError, "ancestor was replaced"):
                SIGNER._hash_live_repo_file("artifacts/payload.aab", "artifact")
        restored = self.repo / "artifacts.old"
        if restored.exists():
            if artifacts.exists():
                for child in artifacts.iterdir():
                    child.unlink()
                artifacts.rmdir()
            restored.rename(artifacts)
        alias = self.repo / "alias.aab"
        os.link(payload, alias)
        with self.assertRaisesRegex(
            SIGNER.SignerError, "single-link|hardlink|duplicate"
        ):
            SIGNER._hash_live_repo_file("artifacts/payload.aab", "artifact")
        alias.unlink()
        payload.unlink()
        os.mkfifo(payload)
        try:
            with self.assertRaisesRegex(SIGNER.SignerError, "regular single-link"):
                SIGNER._hash_live_repo_file("artifacts/payload.aab", "artifact")
        finally:
            payload.unlink()


if __name__ == "__main__":
    unittest.main()
