#!/usr/bin/env python3
"""Focused fail-closed tests for Apple release-candidate state validation."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import plistlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "apple_upload_exact_release_candidates.py"
TOOLS_DIR = MODULE_PATH.parent

# The uploader uses sibling tool imports. Keep that import path stable when
# this test is collected from a directory other than the repository root.
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))


def load_uploader():
    spec = importlib.util.spec_from_file_location("wins_apple_candidate_uploader", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load Apple candidate uploader")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


UPLOADER = load_uploader()
import apple_cross_store_artifact_gate as apple_gate
import cross_store_upload_readiness as readiness
import validate_apple_submission_package as SUBMISSION


class AppleReleaseCandidateStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="wins-apple-candidate-state-")
        self.root = Path(self.temp.name)
        self.manifest_path = self.root / UPLOADER.MANIFEST_PATH
        self.manifest_path.parent.mkdir(parents=True)
        self.version = "1.0.17"
        self.build = "34"
        self.identity = UPLOADER.ArtifactIdentity(
            host_bundle_id=UPLOADER.EXPECTED_BUNDLE_ID,
            packet_tunnel_bundle_id=UPLOADER.EXPECTED_PACKET_TUNNEL_BUNDLE_ID,
            host_version=self.version,
            packet_tunnel_version=self.version,
            host_build=self.build,
            packet_tunnel_build=self.build,
            watch_bundle_id=UPLOADER.EXPECTED_WATCH_BUNDLE_ID,
            watch_version=self.version,
            watch_build=self.build,
        )
        self.manifest = self._valid_manifest()
        self._write_manifest()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _valid_manifest(self) -> dict[str, object]:
        artifacts: list[dict[str, object]] = []
        for platform, artifact_type, suffix in (
            ("ios", "ipa", ".ipa"),
            ("macos", "pkg", ".pkg"),
        ):
            relative_path = Path("artifacts") / f"WinsVPN-{platform}{suffix}"
            path = self.root / relative_path
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = f"exact-{platform}-candidate".encode("ascii")
            path.write_bytes(payload)
            artifacts.append(
                {
                    "platform": platform,
                    "lane": "app_store_local",
                    "type": artifact_type,
                    "path": relative_path.as_posix(),
                    "size_bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "bundle_id": UPLOADER.EXPECTED_BUNDLE_ID,
                    "packet_tunnel_bundle_id": (
                        UPLOADER.EXPECTED_PACKET_TUNNEL_BUNDLE_ID
                    ),
                    "expected_current_bundle_id": UPLOADER.EXPECTED_BUNDLE_ID,
                    "expected_current_packet_tunnel_bundle_id": (
                        UPLOADER.EXPECTED_PACKET_TUNNEL_BUNDLE_ID
                    ),
                    "artifact_status": "current_candidate",
                    "upload_status": "not_uploaded",
                    "signing": {
                        "status": "current_candidate",
                        "contract": "apple-distribution",
                        "authority": "Authority=Apple Distribution:",
                        "team_id": "5YT8H4U72M",
                    },
                    "shipped_architecture_inventory": (
                        {
                            "required_architectures": ["arm64", "x86_64"],
                            "shipped": [
                                {
                                    "path": "WinsVPN.app/Contents/MacOS/WinsVPN",
                                    "sha256": hashlib.sha256(
                                        b"exact-macos-candidate"
                                    ).hexdigest(),
                                    "size_bytes": len(payload),
                                    "architectures": ["arm64", "x86_64"],
                                }
                            ],
                        }
                        if platform == "macos"
                        else None
                    ),
                    "embedded_watchos_companion": (
                        {
                            "status": "current_candidate",
                            "bundle_id": UPLOADER.EXPECTED_WATCH_BUNDLE_ID,
                            "companion_bundle_id": UPLOADER.EXPECTED_BUNDLE_ID,
                            "version": self.version,
                            "build": self.build,
                            "executable": "WinsWatch",
                            "executable_sha256": hashlib.sha256(
                                b"watch-executable"
                            ).hexdigest(),
                            "privacy_info_sha256": hashlib.sha256(
                                b"watch-privacy"
                            ).hexdigest(),
                        }
                        if platform == "ios"
                        else None
                    ),
                }
            )
        artifacts = [
            {key: value for key, value in item.items() if value is not None}
            for item in artifacts
        ]
        return {
            "schema_version": 1,
            "app_version": self.version,
            "build_number": self.build,
            "candidate_set_status": "complete_local_candidates",
            "upload_status": "not_uploaded",
            "artifacts": artifacts,
        }

    def _write_manifest(self) -> None:
        self.manifest_path.write_text(
            json.dumps(self.manifest, indent=2) + "\n", encoding="utf-8"
        )

    def _identity_reader(self, platform: str, path: Path):
        self.assertIn(platform, {"ios", "macos"})
        self.assertTrue(path.is_file())
        return self.identity

    def _contamination_reader(self, path: Path, platform: str) -> None:
        self.assertTrue(path.is_file())
        self.assertIn(platform, {"ios", "macos"})

    @staticmethod
    def _watch_privacy() -> dict[str, object]:
        return {
            "NSPrivacyTracking": False,
            "NSPrivacyTrackingDomains": [],
            "NSPrivacyCollectedDataTypes": [],
            "NSPrivacyAccessedAPITypes": [],
        }

    def test_complete_candidates_require_current_bytes_and_identity(self) -> None:
        candidates = UPLOADER.candidate_map(
            self.root,
            identity_reader=self._identity_reader,
            contamination_reader=self._contamination_reader,
        )
        self.assertEqual(set(candidates), {"ios", "macos"})

    def test_missing_macos_candidate_is_rejected(self) -> None:
        self.manifest["artifacts"] = self.manifest["artifacts"][:1]
        self._write_manifest()
        with self.assertRaisesRegex(
            UPLOADER.UploadGateError,
            "exactly two Apple candidates",
        ):
            UPLOADER.candidate_map(
                self.root,
                identity_reader=self._identity_reader,
                contamination_reader=self._contamination_reader,
            )

    def test_submission_manifest_rejects_unexpected_platform_substitution(self) -> None:
        manifest = {
            "schema_version": 1,
            "app_version": self.version,
            "build_number": self.build,
            "candidate_set_status": (
                "preliminary_local_candidates_invalidated_by_shared_revision"
            ),
            "upload_status": "not_uploaded",
            "artifacts": [
                {
                    "platform": "future_apple_product",
                    "lane": "app_store_connect",
                    "type": "ipa",
                },
                {
                    "platform": "ios",
                    "lane": "app_store_local",
                    "type": "ipa",
                },
            ],
        }
        path = self.root / "release_candidate.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        with mock.patch.object(SUBMISSION, "ROOT", self.root), mock.patch.object(
            SUBMISSION, "ARTIFACT_MANIFEST", path
        ), mock.patch.object(
            SUBMISSION, "pubspec_version", return_value=(self.version, self.build)
        ):
            with self.assertRaisesRegex(AssertionError, "unexpected artifact tuple"):
                SUBMISSION.validate_artifact_manifest()

    def test_invalidated_candidate_is_rejected_before_missing_file(self) -> None:
        artifact = self.manifest["artifacts"][0]
        artifact["artifact_status"] = (
            "preliminary_snapshot_candidate_invalidated_by_shared_revision"
        )
        (self.root / artifact["path"]).unlink()
        self._write_manifest()
        with self.assertRaisesRegex(UPLOADER.UploadGateError, "invalidated"):
            UPLOADER.candidate_map(
                self.root,
                identity_reader=self._identity_reader,
                contamination_reader=self._contamination_reader,
            )

    def test_non_final_candidate_set_is_not_uploadable(self) -> None:
        self.manifest["candidate_set_status"] = (
            "preliminary_local_candidates_invalidated_by_shared_revision"
        )
        self._write_manifest()
        with self.assertRaisesRegex(UPLOADER.UploadGateError, "must be rebuilt"):
            UPLOADER.candidate_map(
                self.root,
                identity_reader=self._identity_reader,
                contamination_reader=self._contamination_reader,
            )

    def test_complete_candidate_requires_existing_artifact_bytes(self) -> None:
        artifact = self.manifest["artifacts"][0]
        (self.root / artifact["path"]).unlink()
        self._write_manifest()
        with self.assertRaisesRegex(UPLOADER.UploadGateError, "missing"):
            UPLOADER.candidate_map(
                self.root,
                identity_reader=self._identity_reader,
                contamination_reader=self._contamination_reader,
            )

    def test_complete_candidate_requires_matching_hash(self) -> None:
        artifact = self.manifest["artifacts"][0]
        artifact["sha256"] = "0" * 64
        self._write_manifest()
        with self.assertRaisesRegex(UPLOADER.UploadGateError, "SHA-256"):
            UPLOADER.candidate_map(
                self.root,
                identity_reader=self._identity_reader,
                contamination_reader=self._contamination_reader,
            )

    def test_embedded_version_and_build_must_match_manifest(self) -> None:
        for field, value, message in (
            ("host_version", "9.9.9", "embedded versions"),
            ("packet_tunnel_build", "999", "embedded build numbers"),
            ("watch_version", "9.9.9", "embedded Watch version"),
            ("watch_build", "999", "embedded Watch build"),
        ):
            mismatched = self.identity.__class__(
                **{
                    **self.identity.__dict__,
                    field: value,
                }
            )
            with self.subTest(field=field):
                with self.assertRaisesRegex(UPLOADER.UploadGateError, message):
                    UPLOADER.candidate_map(
                        self.root,
                        identity_reader=lambda _platform, _path, result=mismatched: result,
                        contamination_reader=self._contamination_reader,
                    )

    def test_embedded_bundle_ids_must_match_manifest(self) -> None:
        mismatched = self.identity.__class__(
            **{
                **self.identity.__dict__,
                "packet_tunnel_bundle_id": "org.example.stale.PacketTunnel",
            }
        )
        with self.assertRaisesRegex(UPLOADER.UploadGateError, "embedded bundle IDs"):
            UPLOADER.candidate_map(
                self.root,
                identity_reader=lambda _platform, _path: mismatched,
                contamination_reader=self._contamination_reader,
            )
        mismatched_watch = self.identity.__class__(
            **{
                **self.identity.__dict__,
                "watch_bundle_id": "org.example.stale.watchkitapp",
            }
        )
        with self.assertRaisesRegex(UPLOADER.UploadGateError, "Watch bundle ID"):
            UPLOADER.candidate_map(
                self.root,
                identity_reader=lambda _platform, _path: mismatched_watch,
                contamination_reader=self._contamination_reader,
            )

    def test_ios_identity_reader_uses_embedded_plists(self) -> None:
        ipa = self.root / "identity.ipa"
        host = {
            "CFBundleIdentifier": UPLOADER.EXPECTED_BUNDLE_ID,
            "CFBundleShortVersionString": self.version,
            "CFBundleVersion": self.build,
            "CFBundleSupportedPlatforms": ["iPhoneOS"],
        }
        packet = {
            "CFBundleIdentifier": UPLOADER.EXPECTED_PACKET_TUNNEL_BUNDLE_ID,
            "CFBundleShortVersionString": self.version,
            "CFBundleVersion": self.build,
        }
        watch = {
            "CFBundleIdentifier": UPLOADER.EXPECTED_WATCH_BUNDLE_ID,
            "CFBundleShortVersionString": self.version,
            "CFBundleVersion": self.build,
            "CFBundleExecutable": "WinsWatch",
        }
        with zipfile.ZipFile(ipa, "w") as archive:
            archive.writestr("Payload/Runner.app/Info.plist", plistlib.dumps(host))
            archive.writestr(
                "Payload/Runner.app/PrivacyInfo.xcprivacy",
                plistlib.dumps(self._watch_privacy()),
            )
            archive.writestr(
                "Payload/Runner.app/PlugIns/PacketTunnel.appex/Info.plist",
                plistlib.dumps(packet),
            )
            archive.writestr(
                "Payload/Runner.app/PlugIns/PacketTunnel.appex/PrivacyInfo.xcprivacy",
                plistlib.dumps(self._watch_privacy()),
            )
            archive.writestr(
                "Payload/Runner.app/Watch/WinsWatch.app/Info.plist",
                plistlib.dumps(watch),
            )
            archive.writestr(
                "Payload/Runner.app/Watch/WinsWatch.app/PrivacyInfo.xcprivacy",
                plistlib.dumps(self._watch_privacy()),
            )
            archive.writestr(
                "Payload/Runner.app/Watch/WinsWatch.app/WinsWatch",
                b"watch-executable",
            )
        self.assertEqual(UPLOADER.artifact_identity("ios", ipa), self.identity)

    def test_ios_identity_reader_rejects_invalid_zip_without_runtime_name_error(self) -> None:
        ipa = self.root / "invalid.ipa"
        ipa.write_bytes(b"not-a-zip")
        with self.assertRaisesRegex(
            UPLOADER.UploadGateError,
            "not a valid iOS IPA ZIP",
        ):
            UPLOADER.artifact_identity("ios", ipa)

    def test_ios_identity_reader_rejects_missing_or_legacy_watch_payload(self) -> None:
        host = {
            "CFBundleIdentifier": UPLOADER.EXPECTED_BUNDLE_ID,
            "CFBundleShortVersionString": self.version,
            "CFBundleVersion": self.build,
            "CFBundleSupportedPlatforms": ["iPhoneOS"],
        }
        packet = {
            "CFBundleIdentifier": UPLOADER.EXPECTED_PACKET_TUNNEL_BUNDLE_ID,
            "CFBundleShortVersionString": self.version,
            "CFBundleVersion": self.build,
        }
        for label, extra_path, message in (
            ("missing", None, "exactly one embedded Watch app"),
            (
                "legacy",
                "Payload/Runner.app/Watch/WinsWatch.app/PlugIns/"
                "WinsWatch Extension.appex/Info.plist",
                "legacy WinsWatch Extension.appex",
            ),
        ):
            ipa = self.root / f"{label}.ipa"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr(
                    "Payload/Runner.app/Info.plist", plistlib.dumps(host)
                )
                archive.writestr(
                    "Payload/Runner.app/PrivacyInfo.xcprivacy",
                    plistlib.dumps(self._watch_privacy()),
                )
                archive.writestr(
                    "Payload/Runner.app/PlugIns/PacketTunnel.appex/Info.plist",
                    plistlib.dumps(packet),
                )
                archive.writestr(
                    "Payload/Runner.app/PlugIns/PacketTunnel.appex/PrivacyInfo.xcprivacy",
                    plistlib.dumps(self._watch_privacy()),
                )
                if extra_path is not None:
                    archive.writestr(extra_path, plistlib.dumps({}))
            with self.subTest(label=label):
                with self.assertRaisesRegex(UPLOADER.UploadGateError, message):
                    UPLOADER.artifact_identity("ios", ipa)

    def test_ios_identity_reader_requires_watch_privacy_and_executable(self) -> None:
        host = {
            "CFBundleIdentifier": UPLOADER.EXPECTED_BUNDLE_ID,
            "CFBundleShortVersionString": self.version,
            "CFBundleVersion": self.build,
            "CFBundleSupportedPlatforms": ["iPhoneOS"],
        }
        packet = {
            "CFBundleIdentifier": UPLOADER.EXPECTED_PACKET_TUNNEL_BUNDLE_ID,
            "CFBundleShortVersionString": self.version,
            "CFBundleVersion": self.build,
        }
        watch = {
            "CFBundleIdentifier": UPLOADER.EXPECTED_WATCH_BUNDLE_ID,
            "CFBundleShortVersionString": self.version,
            "CFBundleVersion": self.build,
            "CFBundleExecutable": "WinsWatch",
        }
        for label, include_privacy, include_executable, message in (
            ("privacy", False, True, "Watch PrivacyInfo.xcprivacy is missing"),
            ("executable", True, False, "missing declared Watch executable"),
        ):
            ipa = self.root / f"missing-{label}.ipa"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr(
                    "Payload/Runner.app/Info.plist", plistlib.dumps(host)
                )
                archive.writestr(
                    "Payload/Runner.app/PrivacyInfo.xcprivacy",
                    plistlib.dumps(self._watch_privacy()),
                )
                archive.writestr(
                    "Payload/Runner.app/PlugIns/PacketTunnel.appex/Info.plist",
                    plistlib.dumps(packet),
                )
                archive.writestr(
                    "Payload/Runner.app/PlugIns/PacketTunnel.appex/PrivacyInfo.xcprivacy",
                    plistlib.dumps(self._watch_privacy()),
                )
                archive.writestr(
                    "Payload/Runner.app/Watch/WinsWatch.app/Info.plist",
                    plistlib.dumps(watch),
                )
                if include_privacy:
                    archive.writestr(
                        "Payload/Runner.app/Watch/WinsWatch.app/PrivacyInfo.xcprivacy",
                        plistlib.dumps(self._watch_privacy()),
                    )
                if include_executable:
                    archive.writestr(
                        "Payload/Runner.app/Watch/WinsWatch.app/WinsWatch", b"binary"
                    )
            with self.subTest(label=label):
                with self.assertRaisesRegex(UPLOADER.UploadGateError, message):
                    UPLOADER.artifact_identity("ios", ipa)

    def test_macos_identity_reader_uses_expanded_pkg_plists(self) -> None:
        package = self.root / "identity.pkg"
        package.write_bytes(b"fixture-package")

        def fake_expand(command, **_kwargs):
            expanded = Path(command[-1])
            host_plist = expanded / "WinsVPN.app/Contents/Info.plist"
            packet_plist = (
                expanded
                / "WinsVPN.app/Contents/PlugIns/PacketTunnel.appex/Contents/Info.plist"
            )
            packet_plist.parent.mkdir(parents=True)
            host_plist.write_bytes(
                plistlib.dumps(
                    {
                        "CFBundleIdentifier": UPLOADER.EXPECTED_BUNDLE_ID,
                        "CFBundleShortVersionString": self.version,
                        "CFBundleVersion": self.build,
                    }
                )
            )
            packet_plist.write_bytes(
                plistlib.dumps(
                    {
                        "CFBundleIdentifier": (
                            UPLOADER.EXPECTED_PACKET_TUNNEL_BUNDLE_ID
                        ),
                        "CFBundleShortVersionString": self.version,
                        "CFBundleVersion": self.build,
                    }
                )
            )
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with mock.patch.object(UPLOADER, "_bounded_process", side_effect=fake_expand):
            self.assertEqual(
                UPLOADER.artifact_identity("macos", package),
                UPLOADER.ArtifactIdentity(
                    host_bundle_id=UPLOADER.EXPECTED_BUNDLE_ID,
                    packet_tunnel_bundle_id=(
                        UPLOADER.EXPECTED_PACKET_TUNNEL_BUNDLE_ID
                    ),
                    host_version=self.version,
                    packet_tunnel_version=self.version,
                    host_build=self.build,
                    packet_tunnel_build=self.build,
                ),
            )

    def test_readiness_uses_validated_status_command(self) -> None:
        readiness = (ROOT / "tools/verify_apple_readiness.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("--print-validated-upload-status", readiness)
        self.assertNotIn(
            'status = manifest.get("upload_status")',
            readiness,
        )
        # Rehearsal r44: a rebuild has no current candidate yet, so the
        # validated status may be asked for only outside the rebuild branch.
        self.assertLess(
            readiness.index("Deferring exact release-candidate upload dry run"),
            readiness.index("--print-validated-upload-status"),
        )

    def test_submission_selftest_uses_hermetic_negative_guard_logs(self) -> None:
        rollout_manifest = json.loads(
            SUBMISSION.ROLLOUT_READINESS_MANIFEST.read_text(encoding="utf-8")
        )
        external_logs = set(rollout_manifest["negative_upload_guard_logs"].values())
        original_reader = SUBMISSION._read_tmp_evidence_log
        original_manifest_path = SUBMISSION.ROLLOUT_READINESS_MANIFEST

        def reject_external_logs(path_text: object, label: str) -> str:
            self.assertNotIn(str(path_text), external_logs)
            return original_reader(path_text, label)

        with mock.patch.object(
            SUBMISSION,
            "_read_tmp_evidence_log",
            side_effect=reject_external_logs,
        ):
            messages = SUBMISSION.run_selftest()

        self.assertEqual(SUBMISSION.ROLLOUT_READINESS_MANIFEST, original_manifest_path)
        self.assertIn(
            "PASS: authentication-guard self-test rejects missing-auth evidence "
            "without the exact fail-closed marker",
            messages,
        )

    def test_canonical_candidates_are_exact_1_0_17_34_bytes(self) -> None:
        self.assertEqual(self.version, "1.0.17")
        self.assertEqual(self.build, "34")
        self.assertEqual(apple_gate.canonical_apple_release(), "1.0.17+34")
        candidates = UPLOADER.candidate_map(
            self.root,
            identity_reader=self._identity_reader,
            contamination_reader=self._contamination_reader,
        )
        self.assertEqual(set(candidates), {"ios", "macos"})
        ios = self.manifest["artifacts"][0]
        macos = self.manifest["artifacts"][1]
        self.assertEqual(
            ios["sha256"],
            hashlib.sha256((self.root / ios["path"]).read_bytes()).hexdigest(),
        )
        self.assertEqual(
            macos["sha256"],
            hashlib.sha256((self.root / macos["path"]).read_bytes()).hexdigest(),
        )
        self.assertEqual(
            ios["embedded_watchos_companion"]["bundle_id"],
            UPLOADER.EXPECTED_WATCH_BUNDLE_ID,
        )
        self.assertEqual(
            macos["shipped_architecture_inventory"]["required_architectures"],
            ["arm64", "x86_64"],
        )

    def test_testflight_lane_cannot_replace_app_store_local_candidate(self) -> None:
        self.manifest["artifacts"][0]["lane"] = "testflight_internal"
        self._write_manifest()
        with self.assertRaisesRegex(
            UPLOADER.UploadGateError, "App Store-local artifact"
        ):
            UPLOADER.candidate_map(
                self.root,
                identity_reader=self._identity_reader,
                contamination_reader=self._contamination_reader,
            )

    def test_no_current_candidate_remains_unuploadable(self) -> None:
        self.manifest["candidate_set_status"] = "no_current_candidate"
        for artifact in self.manifest["artifacts"]:
            artifact["artifact_status"] = "no_current_candidate"
            artifact["path"] = ""
            artifact["sha256"] = ""
            artifact["size_bytes"] = 0
        self._write_manifest()
        with self.assertRaisesRegex(UPLOADER.UploadGateError, "must be rebuilt|match"):
            UPLOADER.candidate_map(
                self.root,
                identity_reader=self._identity_reader,
                contamination_reader=self._contamination_reader,
            )

    def test_owner_signoff_stays_pending_without_owner_evidence(self) -> None:
        self.assertFalse(readiness._owner_signoff_submission_approved(ROOT))
        evaluation = readiness.evaluate_source_gates(ROOT)
        self.assertFalse(evaluation["store_upload_authorized"])
        self.assertFalse(evaluation["publication_authorized"])
        blocker_ids = [item["id"] for item in evaluation["owner_blockers"]]
        self.assertIn("apple-owner-signoff", blocker_ids)

    def test_complete_candidates_without_owner_signing_fail_closed(self) -> None:
        for artifact in self.manifest["artifacts"]:
            artifact.pop("signing", None)
        self._write_manifest()
        with self.assertRaisesRegex(
            UPLOADER.UploadGateError, "omitted a real signed artifact identity"
        ):
            UPLOADER.candidate_map(
                self.root,
                identity_reader=self._identity_reader,
                contamination_reader=self._contamination_reader,
            )

    def test_adhoc_and_unbound_signing_fail_closed(self) -> None:
        self.manifest["artifacts"][0]["signing"] = {
            "status": "current_candidate",
            "contract": "apple-distribution",
            "authority": "ad-hoc",
            "team_id": "5YT8H4U72M",
        }
        self._write_manifest()
        with self.assertRaisesRegex(
            UPLOADER.UploadGateError, "Apple Distribution signing identity"
        ):
            UPLOADER.candidate_map(
                self.root,
                identity_reader=self._identity_reader,
                contamination_reader=self._contamination_reader,
            )

    def test_ios_zip_traversal_and_duplicate_members_fail_closed(self) -> None:
        traversal = self.root / "traversal.ipa"
        with zipfile.ZipFile(traversal, "w") as archive:
            archive.writestr("../Payload/Runner.app/Info.plist", plistlib.dumps({}))
        with self.assertRaisesRegex(UPLOADER.UploadGateError, "unsafe zip path"):
            UPLOADER.artifact_identity("ios", traversal)

        duplicate = self.root / "duplicate.ipa"
        with zipfile.ZipFile(duplicate, "w") as archive:
            archive.writestr("Payload/Runner.app/Info.plist", b"one")
            archive.writestr("payload/runner.app/info.plist", b"two")
        with self.assertRaisesRegex(
            UPLOADER.UploadGateError, "duplicate or empty zip paths"
        ):
            UPLOADER.artifact_identity("ios", duplicate)

    def test_hold_candidate_rejects_hardlinked_source(self) -> None:
        source = self.root / "source.ipa"
        source.write_bytes(b"exact-signed-ipa")
        alias = self.root / "alias.ipa"
        try:
            os.link(source, alias)
        except OSError as exc:
            self.skipTest(f"hardlink creation is unavailable: {exc}")
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        with self.assertRaisesRegex(UPLOADER.UploadGateError, "exact inode"):
            UPLOADER.hold_candidate(
                alias,
                self.root / "held.ipa",
                expected_sha256=digest,
                expected_size=source.stat().st_size,
            )

    def test_unsigned_packaging_preflight_fails_closed(self) -> None:
        ios = self.root / "unsigned.ipa"
        macos = self.root / "unsigned.pkg"
        ios.write_bytes(b"not-owner-signed")
        macos.write_bytes(b"not-owner-signed")
        with self.assertRaisesRegex(
            UPLOADER.UploadGateError, "owner-signed Apple Distribution artifact"
        ):
            UPLOADER.verify_exported_owner_signed_candidates(
                str(ios), str(macos), root=self.root
            )

    def test_owner_signed_packaging_hands_the_gate_repository_relative_paths(self) -> None:
        exports = self.root / "exports"
        exports.mkdir()
        ios = exports / "signed.ipa"
        macos = exports / "signed.pkg"
        ios.write_bytes(b"owner-signed-ipa")
        macos.write_bytes(b"owner-signed-pkg")
        calls: list[tuple[str, Path]] = []

        def record(target_id: str, path: Path) -> None:
            calls.append((target_id, path))

        UPLOADER.verify_exported_owner_signed_candidates(
            str(ios), "exports/signed.pkg", root=self.root, signature_verifier=record
        )
        self.assertEqual(
            calls,
            [
                ("ios-app-store-ipa", Path("exports/signed.ipa")),
                ("macos-app-store-pkg", Path("exports/signed.pkg")),
            ],
        )
        self.assertTrue(all(not path.is_absolute() for _target, path in calls))

    def test_owner_signed_packaging_keeps_exact_file_and_project_checks(self) -> None:
        exports = self.root / "exports"
        exports.mkdir()
        ios = exports / "signed.ipa"
        macos = exports / "signed.pkg"
        ios.write_bytes(b"owner-signed-ipa")
        macos.write_bytes(b"owner-signed-pkg")
        calls: list[tuple[str, Path]] = []
        record = lambda target_id, path: calls.append((target_id, path))
        with tempfile.TemporaryDirectory() as outside_dir:
            outside = Path(outside_dir) / "outside.ipa"
            outside.write_bytes(b"outside")
            with self.assertRaisesRegex(UPLOADER.UploadGateError, "outside the project"):
                UPLOADER.verify_exported_owner_signed_candidates(
                    str(outside), str(macos), root=self.root, signature_verifier=record
                )
        alias = exports / "alias.ipa"
        os.link(ios, alias)
        with self.assertRaisesRegex(UPLOADER.UploadGateError, "single-link regular file"):
            UPLOADER.verify_exported_owner_signed_candidates(
                str(ios), str(macos), root=self.root, signature_verifier=record
            )
        alias.unlink()
        with self.assertRaisesRegex(UPLOADER.UploadGateError, "must be repository-relative"):
            UPLOADER.require_owner_signed_packaging(
                ios, "ios", signature_verifier=record, gate_path=ios
            )
        self.assertEqual(calls, [])

    def _candidate_map_gate_calls(self, *, snapshot: bool, during_gate=None):
        """Run the default (real-artifact) candidate path up to the identity read."""

        calls: list[tuple[str, Path]] = []
        original = UPLOADER.require_owner_signed_packaging

        def record(target_id: str, path: Path) -> None:
            calls.append((target_id, path))
            if during_gate is not None:
                during_gate()

        def packaging(path, platform, *, gate_path=None):
            return original(
                path, platform, signature_verifier=record, gate_path=gate_path
            )

        class StopAfterGate(Exception):
            pass

        with tempfile.TemporaryDirectory() as held, mock.patch.object(
            UPLOADER, "require_owner_signed_packaging", side_effect=packaging
        ), mock.patch.object(UPLOADER, "artifact_identity", side_effect=StopAfterGate):
            try:
                UPLOADER.candidate_map(
                    self.root,
                    contamination_reader=self._contamination_reader,
                    snapshot_root=Path(held) if snapshot else None,
                )
            except StopAfterGate:
                pass
        return calls

    def test_candidate_map_hands_the_gate_repository_relative_paths(self) -> None:
        for snapshot in (False, True):
            with self.subTest(snapshot=snapshot):
                self.assertEqual(
                    self._candidate_map_gate_calls(snapshot=snapshot),
                    [("ios-app-store-ipa", Path("artifacts/WinsVPN-ios.ipa"))],
                )

    def test_candidate_map_rebinds_the_project_file_after_the_gate(self) -> None:
        project = self.root / "artifacts" / "WinsVPN-ios.ipa"

        def swap() -> None:
            project.write_bytes(b"swapped-after-hash")

        with self.assertRaisesRegex(
            UPLOADER.UploadGateError, "changed during the Apple artifact gate"
        ):
            self._candidate_map_gate_calls(snapshot=True, during_gate=swap)

    def test_real_gate_rejects_absolute_and_reaches_relative_candidates(self) -> None:
        # The cross-store gate refuses absolute paths outright; the relative form
        # the uploader now passes gets past that check to the artifact checks.
        with self.assertRaisesRegex(
            UPLOADER.AppleArtifactGateError, "must be repository-relative"
        ):
            UPLOADER.verify_signature(
                "ios-app-store-ipa", UPLOADER.ROOT / "missing-candidate.ipa"
            )
        with self.assertRaises(UPLOADER.AppleArtifactGateError) as context:
            UPLOADER.verify_signature("ios-app-store-ipa", Path("missing-candidate.ipa"))
        self.assertNotIn("repository-relative", str(context.exception))

    def test_missing_watch_hashes_and_macos_inventory_fail_closed(self) -> None:
        ios = self.manifest["artifacts"][0]
        ios["embedded_watchos_companion"]["executable_sha256"] = ""
        self._write_manifest()
        with self.assertRaisesRegex(
            UPLOADER.UploadGateError, "real signed artifact hashes"
        ):
            UPLOADER.candidate_map(
                self.root,
                identity_reader=self._identity_reader,
                contamination_reader=self._contamination_reader,
            )
        self.manifest = self._valid_manifest()
        macos = self.manifest["artifacts"][1]
        macos["shipped_architecture_inventory"]["shipped"] = []
        self._write_manifest()
        with self.assertRaisesRegex(
            UPLOADER.UploadGateError, "inventory arm64 and x86_64"
        ):
            UPLOADER.candidate_map(
                self.root,
                identity_reader=self._identity_reader,
                contamination_reader=self._contamination_reader,
            )

    def test_producer_fails_closed_without_owner_signed_exports(self) -> None:
        producer = (ROOT / "tools/build_apple_release_candidates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("--verify-owner-signed-packaging", producer)
        self.assertIn("require_exact_exported_candidate", producer)
        self.assertIn("owner-signed artifact is absent or symbolic", producer)
        self.assertIn('"${REALPATH_BIN}" -- "${candidate}"', producer)
        self.assertIn("resolve_real_executable \"${PYTHON_BIN}\"", producer)
        self.assertIn("PATH realpath is refused.", producer)
        helper = producer.split("resolve_real_executable() {", 1)[1].split("\n}\n", 1)[0]
        self.assertNotIn("$(realpath -e --", helper)
        self.assertNotIn("$(realpath --", helper)
        freeze = producer.index("freeze_apple_release_candidates.py")
        verify = producer.index("--verify-owner-signed-packaging")
        self.assertLess(verify, freeze)

    def test_producer_realpath_is_a_real_file_on_this_host(self) -> None:
        # R11a: macOS has no /usr/bin/realpath, so the producer stopped at its
        # first line on the release Mac. Run the selection block itself.
        producer = (ROOT / "tools/build_apple_release_candidates.sh").read_text(
            encoding="utf-8"
        )
        block = producer.split('PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"\n', 1)[1]
        block = block.split("resolve_real_executable() {", 1)[0]
        result = subprocess.run(
            ["/bin/bash", "-c", block + 'printf "%s\\n" "${REALPATH_BIN}"'],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        selected = result.stdout.strip()
        self.assertTrue(os.path.isfile(selected) and not os.path.islink(selected), selected)
        if sys.platform == "darwin":
            self.assertEqual(selected, "/bin/realpath")

    def test_debug_bundle_check_expects_the_debug_keychain_group(self) -> None:
        # R11a: the iOS Debug configuration signs with
        # org.winsvpn.shared.debug, so the producer's unsigned debug build
        # always failed the release-only keychain marker check.
        smoke = (ROOT / "tools/apple_runtime_smoke.sh").read_text(encoding="utf-8")
        project = (ROOT / "ios/Runner.xcodeproj/project.pbxproj").read_text(encoding="utf-8")
        self.assertIn(
            'WINS_KEYCHAIN_ACCESS_GROUP = "$(AppIdentifierPrefix)org.winsvpn.shared.debug";', project
        )
        self.assertIn(
            'WINS_KEYCHAIN_ACCESS_GROUP = "$(AppIdentifierPrefix)org.winsvpn.shared";', project
        )
        self.assertIn(
            '    "org.winsvpn.shared.debug"\n'
            '    if expected_app_bundle_id.endswith(".debug")\n'
            '    else "org.winsvpn.shared"\n',
            smoke,
        )
        self.assertEqual(smoke.count(".endswith(expected_keychain_group_suffix):"), 2)
        self.assertNotIn('.endswith("org.winsvpn.shared"):', smoke)

    def test_readiness_checks_the_ios_keychain_group_through_the_build_setting(self) -> None:
        # Since ee48a2f the iOS plists carry $(WINS_KEYCHAIN_ACCESS_GROUP), so the
        # readiness grep for the literal could never pass; it now checks the
        # reference and the exact value in every iOS configuration.
        readiness = (ROOT / "tools/verify_apple_readiness.sh").read_text(encoding="utf-8")
        reference = "<string>$(WINS_KEYCHAIN_ACCESS_GROUP)</string>"
        for plist in ("ios/Runner/Info.plist", "ios/PacketTunnel/Info.plist"):
            check = f"grep -Fq '{reference}' {plist}"
            self.assertTrue(check in readiness, f"readiness lacks: {check}")
            stale = f"org.winsvpn.shared' {plist}"
            self.assertFalse(stale in readiness, f"readiness still has: {stale}")
            self.assertIn(reference, (ROOT / plist).read_text(encoding="utf-8"))
        for plist in ("macos/Runner/Info.plist", "macos/PacketTunnel/Info.plist"):
            check = f"grep -q '\\$(AppIdentifierPrefix)org.winsvpn.shared' {plist}"
            self.assertTrue(check in readiness, f"readiness lacks: {check}")
        start = readiness.index('"${PYTHON_BIN}" - ios/Runner.xcodeproj/project.pbxproj <<')
        body = readiness[readiness.index("\n", start) + 1 : readiness.index("\nPY\n", start)]
        project = (ROOT / "ios/Runner.xcodeproj/project.pbxproj").read_text(encoding="utf-8")
        shared = 'WINS_KEYCHAIN_ACCESS_GROUP = "$(AppIdentifierPrefix)org.winsvpn.shared";'
        debug = 'WINS_KEYCHAIN_ACCESS_GROUP = "$(AppIdentifierPrefix)org.winsvpn.shared.debug";'
        self.assertEqual((project.count(shared), project.count(debug)), (4, 2))
        first_shared = project.index(shared)
        first_debug = project.index(debug)
        cases = (
            ("real project", project, 0),
            (
                "Debug and Release swapped",
                project.replace(debug, "@@").replace(shared, debug).replace("@@", shared),
                1,
            ),
            (
                "release group without team prefix",
                project[:first_shared]
                + 'WINS_KEYCHAIN_ACCESS_GROUP = "org.winsvpn.shared";'
                + project[first_shared + len(shared):],
                1,
            ),
            (
                "a configuration lost its group",
                project[:first_debug] + project[first_debug + len(debug):],
                1,
            ),
        )
        for label, text, expected_rc in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as raw:
                path = Path(raw) / "project.pbxproj"
                path.write_text(text, encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, "-I", "-c", body, str(path)],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                self.assertEqual(result.returncode, expected_rc, result.stdout + result.stderr)

    def test_macos_xcconfigs_build_from_a_clean_frozen_checkout(self) -> None:
        # R11a: the source freeze refuses the untracked Signing.xcconfig, but
        # Debug, Release and AppInfo hard-included it, so a frozen checkout
        # could not build macOS. Tracked safe defaults come first; the local
        # file is an optional override only.
        configs = ROOT / "macos/Runner/Configs"
        def settings(path: Path) -> dict[str, str]:
            values = {}
            for line in path.read_text(encoding="utf-8").splitlines():
                if "=" in line and not line.lstrip().startswith("//"):
                    key, value = line.split("=", 1)
                    values[key.strip()] = value.strip()
            return values
        self.assertEqual(
            settings(configs / "Signing.defaults.xcconfig"),
            settings(configs / "Signing.xcconfig.example"),
        )
        for name in ("Debug.xcconfig", "Release.xcconfig", "AppInfo.xcconfig"):
            lines = (configs / name).read_text(encoding="utf-8").splitlines()
            self.assertNotIn('#include "Signing.xcconfig"', lines, name)
            defaults = lines.index('#include "Signing.defaults.xcconfig"')
            self.assertEqual(lines[defaults + 1], '#include? "Signing.xcconfig"', name)

    def test_ios_automatic_signing_archives_with_the_development_identity(self) -> None:
        # R11a: Xcode 27 refuses to archive an automatically signed target whose
        # Release identity is pinned to Apple Distribution ("conflicting
        # provisioning settings"); the App Store export re-signs for distribution.
        project = (ROOT / "ios/Runner.xcodeproj/project.pbxproj").read_text(encoding="utf-8")
        self.assertNotIn('"CODE_SIGN_IDENTITY[sdk=iphoneos*]" = "Apple Distribution";', project)
        self.assertEqual(
            project.count('"CODE_SIGN_IDENTITY[sdk=iphoneos*]" = "Apple Development";'), 3
        )

    def test_archived_ios_app_is_resolved_from_the_archive(self) -> None:
        # Owner ruling 2026-10-16: PRODUCT_NAME stays "BasicCalc", so the
        # archive holds BasicCalc.app; the producer finds exactly one .app.
        smoke = (ROOT / "tools/apple_runtime_smoke.sh").read_text(encoding="utf-8")
        self.assertNotIn('Products/Applications/Runner.app"', smoke)
        self.assertNotIn('app_path="${extract_dir}/Payload/Runner.app"', smoke)
        helper = smoke.split("single_app_bundle_in() {", 1)[1].split("\n}\n", 1)[0]
        script = (
            "set -Eeuo pipefail\n"
            "die() { printf 'DIE: %s\\n' \"$*\" >&2; exit 65; }\n"
            "single_app_bundle_in() {" + helper + "\n}\n"
            'single_app_bundle_in "$1" probe\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def run() -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["/bin/bash", "-c", script, "probe", str(root)],
                    capture_output=True, text=True, check=False,
                )
            self.assertEqual(run().returncode, 65)
            (root / "BasicCalc.app").mkdir()
            result = run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), str(root / "BasicCalc.app"))
            (root / "Runner.app").mkdir()
            result = run()
            self.assertEqual(result.returncode, 65)
            self.assertIn("exactly one .app bundle; found 2", result.stderr)

    def test_ios_app_name_is_wins_vpn_everywhere_the_gate_binds_it(self) -> None:
        # Owner ruling 2026-10-25: the iPhone, iPad, and Apple Watch apps are named
        # "Win's VPN" and the extension "Win's VPN Helper". App Store Connect refused
        # the "Calculator" build with ITMS-90129 (Apple's own app name). The
        # calculator safety screen keeps its disguised VPN profile description.
        ios = plistlib.loads((ROOT / "ios/Runner/Info.plist").read_bytes())
        watch = plistlib.loads((ROOT / "ios/WinsWatch Watch App/Info.plist").read_bytes())
        packet = plistlib.loads((ROOT / "ios/PacketTunnel/Info.plist").read_bytes())
        delegate = (ROOT / "ios/Runner/AppDelegate.swift").read_text(encoding="utf-8")
        smoke = (ROOT / "tools/apple_runtime_smoke.sh").read_text(encoding="utf-8")
        readiness = (ROOT / "tools/verify_apple_readiness.sh").read_text(encoding="utf-8")
        watch_ui = (ROOT / "ios/WinsWatch Watch App/ContentView.swift").read_text(
            encoding="utf-8"
        )
        for plist in (ios, watch):
            self.assertEqual(plist["CFBundleDisplayName"], "Win's VPN")
            self.assertEqual(plist["CFBundleName"], "Win's VPN")
        self.assertEqual(packet["CFBundleDisplayName"], "Win's VPN Helper")
        self.assertEqual(packet["CFBundleName"], "Win's VPN Helper")
        self.assertIn('disguisedTunnelDescription = "Calculator"', delegate)
        self.assertIn('expected_host_name = "Win\'s VPN"\n', smoke)
        self.assertIn('IOS_APP_NAME = "Win\'s VPN"\n', readiness)
        self.assertNotIn("must not name a VPN", readiness)
        # The Watch screens send the user to the iPhone app by its home-screen name.
        self.assertIn('"Open Win\'s VPN on iPhone"', watch_ui)
        self.assertIn('.navigationTitle("Win\'s VPN")', watch_ui)
        self.assertIn('"Open Win\'s VPN on your iPhone to load servers."', watch_ui)
        self.assertNotIn("Calculator", watch_ui)
        project = (ROOT / "ios/Runner.xcodeproj/project.pbxproj").read_text(encoding="utf-8")
        self.assertIn('PRODUCT_NAME = "BasicCalc";', project)
        self.assertNotIn("INFOPLIST_KEY_CFBundleDisplayName", project)

    def test_apple_engine_builders_pin_their_umask(self) -> None:
        # R11a: engine bytes changed with the builder's umask (022 gave other
        # AWG bytes than 077); both builders now fix it themselves.
        for name in ("build_apple_engine_wrappers.sh", "build_apple_wg_go_bridge.sh"):
            lines = (ROOT / "tools" / name).read_text(encoding="utf-8").splitlines()
            self.assertEqual(lines[1], "set -Eeuo pipefail", name)
            self.assertIn("umask 077", lines[2:8], name)

    def test_release_contamination_contract_reaches_the_host_info_plists(self) -> None:
        # R11a: the archive passes INFOPLIST_KEY_WinsRelease* build settings,
        # but Xcode merges INFOPLIST_KEY_ settings only into generated plists;
        # the Runner targets use their own Info.plist, so the archived app had
        # no contract and the contamination gate refused it. Both host plists
        # now expand the settings explicitly.
        smoke = (ROOT / "tools/apple_runtime_smoke.sh").read_text(encoding="utf-8")
        for key, value in (
            ("WinsReleaseContaminationContract", "apple-release-no-live-smoke-v1"),
            ("WinsReleaseLiveSmokeCompiled", "NO"),
            ("WinsReleaseSmokePinEmbedded", "NO"),
        ):
            self.assertEqual(smoke.count(f"INFOPLIST_KEY_{key}={value}"), 3, key)
            for plist_path in ("ios/Runner/Info.plist", "macos/Runner/Info.plist"):
                plist = plistlib.loads((ROOT / plist_path).read_bytes())
                self.assertEqual(plist[key], f"$(INFOPLIST_KEY_{key})", plist_path)

    def test_live_smoke_markers_are_compiled_out_of_release_builds(self) -> None:
        # R11a: the archived App.framework/App still contained the live-smoke
        # result and PIN markers, so the contamination gate refused it. Both
        # bodies now sit behind a const-false branch in release.
        source = (ROOT / "lib/main.dart").read_text(encoding="utf-8")
        for wrapper, compiled in (
            ("Future<void> _writeAppleLiveTunnelSmokeResult(", "_writeAppleLiveTunnelSmokeResultCompiled("),
            ("String _appleLiveTunnelSmokePinValue() {", "_appleLiveTunnelSmokePinValueCompiled("),
        ):
            body = source.split(wrapper, 1)[1].split("\n  }\n", 1)[0]
            self.assertIn("if (!kReleaseMode || _appleLiveTunnelSmokeEnabled) {", body)
            self.assertIn(compiled, body)
            self.assertEqual(source.count(compiled), 2)  # definition and the one call
        self.assertIn("static const bool _appleLiveTunnelSmokeEnabled = !kReleaseMode &&", source)
        for marker in ("WINS_APPLE_LIVE_TUNNEL_SMOKE_RESULT ", "apple_live_tunnel_smoke_pin_missing_or_invalid"):
            before = source.partition(marker)[0]
            self.assertTrue(
                "_writeAppleLiveTunnelSmokeResultCompiled(" in before
                or "_appleLiveTunnelSmokePinValueCompiled(" in before,
                marker,
            )

    def test_producer_chmod_calls_work_with_macos_chmod(self) -> None:
        # R11a: macOS chmod parses "chmod 0600 -- FILE" as a file named "--"
        # and exits 1, which stopped the producer before the archive.
        producer = (ROOT / "tools/build_apple_release_candidates.sh").read_text(
            encoding="utf-8"
        )
        self.assertNotRegex(producer, r"chmod\s+[0-7]{3,4}\s+--")
        self.assertIn('chmod 0600 "${RUN_LOG}" "${VERIFICATION_LOG}"', producer)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "log"
            target.write_text("x", encoding="utf-8")
            result = subprocess.run(
                ["/bin/chmod", "0600", str(target)], capture_output=True, check=False
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_producer_verifies_the_scoped_index_per_apple_platform(self) -> None:
        # R11a: an ios,macos scoped index refuses a verify-index without
        # --platform, which stopped the producer before begin-build.
        producer = (ROOT / "tools/build_apple_release_candidates.sh").read_text(
            encoding="utf-8"
        )
        calls = producer.split("verify-index \\\n")[1:]
        self.assertEqual(len(calls), 4)
        for call in calls:
            line = call.split("\n", 1)[0]
            self.assertRegex(line, r'--index "\$\{RELEASE_INDEX\}" --platform (ios|macos)$')
        for platform in ("ios", "macos"):
            self.assertEqual(
                sum(call.split("\n", 1)[0].endswith(f"--platform {platform}") for call in calls), 2
            )

    def test_producer_removes_xcode_swiftpm_scaffolding_before_the_final_index_check(self) -> None:
        # Rehearsals r44 and r45: Xcode leaves empty mode-0777 xcshareddata/swiftpm
        # and Flutter/ephemeral/Packages/*/.swiftpm folders that the dependency
        # freeze refuses; the producer removes them (refusing any file inside)
        # before the post-build verify-index.
        producer = (ROOT / "tools/build_apple_release_candidates.sh").read_text(
            encoding="utf-8"
        )
        call = producer.rindex("\nremove_xcode_swiftpm_scaffolding\n")
        self.assertLess(call, producer.rindex("verify-index \\\n"))
        self.assertGreater(call, producer.index("--verify-owner-signed-packaging \\\n"))
        function = producer[producer.index("remove_xcode_swiftpm_scaffolding() {"):]
        function = function[: function.index("\n}\n") + 3]
        layout = []
        for platform in ("ios", "macos"):
            layout += [
                f"{platform}/Runner.xcworkspace/xcshareddata/swiftpm/configuration",
                f"{platform}/Runner.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/configuration",
                f"{platform}/Flutter/ephemeral/Packages/FlutterGeneratedPluginSwiftPackage/.swiftpm/xcode",
                f"{platform}/Flutter/ephemeral/Packages/.packages/FlutterFramework/.swiftpm/xcode",
            ]
        with tempfile.TemporaryDirectory(prefix="wins-swiftpm-scaffolding-") as temporary:
            repo = Path(temporary) / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            kept = repo / "ios/Runner.xcworkspace/xcshareddata/IDEWorkspaceChecks.plist"
            for relative in layout:
                (repo / relative).mkdir(parents=True)
                os.chmod(repo / relative, 0o777)
            kept.write_text("kept\n", encoding="utf-8")
            script = Path(temporary) / "run.sh"
            script.write_text(
                "set -Eeuo pipefail\n"
                'die() { echo "DIE: $*"; exit 3; }\n'
                f"ROOT={repo}\n" + function + "remove_xcode_swiftpm_scaffolding\n",
                encoding="utf-8",
            )
            result = subprocess.run(["/bin/bash", str(script)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for relative in layout:
                self.assertFalse((repo / relative).parent.exists(), relative)
            self.assertTrue(kept.is_file())
            held = repo / "macos/Flutter/ephemeral/Packages/FlutterGeneratedPluginSwiftPackage/.swiftpm/xcode"
            held.mkdir(parents=True)
            (held / "UserInterfaceState.xcuserstate").write_bytes(b"state")
            result = subprocess.run(["/bin/bash", str(script)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 3)
            self.assertIn("holds files; refusing to remove", result.stdout)
            self.assertTrue((held / "UserInterfaceState.xcuserstate").is_file())
            # R24 V1 F3: a git that cannot answer (here: not a repository) is a
            # refusal, not "untracked, delete". The folder stays in place.
            bare = Path(temporary) / "not-a-repo"
            scaffold = bare / "ios/Runner.xcworkspace/xcshareddata/swiftpm"
            scaffold.mkdir(parents=True)
            script.write_text(
                "set -Eeuo pipefail\n"
                'die() { echo "DIE: $*"; exit 3; }\n'
                f"ROOT={bare}\n" + function + "remove_xcode_swiftpm_scaffolding\n",
                encoding="utf-8",
            )
            result = subprocess.run(["/bin/bash", str(script)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
            self.assertIn("tracked state could not be read", result.stdout)
            self.assertTrue(scaffold.is_dir())


class AppleFreezeVerifiedReceiptHandoverTests(unittest.TestCase):
    """Rehearsal r51: the freeze's own manifest write made the worker refuse."""

    def test_freeze_hands_its_verified_receipts_to_the_manifest_validator(self) -> None:
        source = (ROOT / "tools/freeze_apple_release_candidates.py").read_text(encoding="utf-8")
        self.assertIn(
            'validate_artifact_manifest(\n            verified_receipts={"ios": ios_receipt_result, '
            '"macos": macos_receipt_result}\n        )',
            source,
        )
        self.assertLess(
            source.index("ios_receipt, ios_receipt_anchor, ios_receipt_result = require_build_receipt("),
            source.index("verified_receipts="),
        )

    def test_verified_result_skips_the_worker_but_keeps_every_binding(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            receipt = root / ".artifacts" / "r" / "IOS_BUILD_RECEIPT.json"
            receipt.parent.mkdir(parents=True)
            receipt.write_text("{}\n", encoding="utf-8")
            anchor = receipt.with_name(receipt.name + ".sha256")
            anchor.write_text("x\n", encoding="utf-8")
            artifact = {
                "build_receipt": ".artifacts/r/IOS_BUILD_RECEIPT.json",
                "build_receipt_sha256": "1" * 64,
                "build_receipt_anchor": ".artifacts/r/IOS_BUILD_RECEIPT.json.sha256",
                "build_receipt_anchor_sha256": "2" * 64,
                "sha256": "3" * 64,
                "size_bytes": 7,
                "artifact_input_fingerprint_sha256": "4" * 64,
                "platform_manifest_sha256": "5" * 64,
            }
            verified = {
                "receipt_sha256": "1" * 64,
                "artifact_sha256": "3" * 64,
                "artifact_size_bytes": 7,
                "artifact_input_fingerprint_sha256": "4" * 64,
                "platform_manifest_sha256": "5" * 64,
            }

            def hashed(path_value, sha_value, label):
                return root / str(path_value)

            def worker(*args, **kwargs):
                raise AssertionError("the worker must not run when a verified result is handed over")

            with mock.patch.object(SUBMISSION, "require_hashed_durable_file", side_effect=hashed), \
                    mock.patch.object(SUBMISSION, "verify_build_receipt", side_effect=worker):
                SUBMISSION.validate_formal_build_receipt_binding(
                    "ios", artifact, root / "a.ipa", root / "index.json", verified_result=verified
                )
                for field in verified:
                    changed = dict(verified)
                    changed[field] = "9" * 64 if field != "artifact_size_bytes" else 8
                    with self.subTest(field=field):
                        with self.assertRaisesRegex(AssertionError, f"{field} binding changed"):
                            SUBMISSION.validate_formal_build_receipt_binding(
                                "ios", artifact, root / "a.ipa", root / "index.json",
                                verified_result=changed,
                            )


class AppleFreezeRuntimeSourceStalenessTests(unittest.TestCase):
    """Rehearsal r49: the second pass rewrites tracked files with identical bytes."""

    def setUp(self) -> None:
        import freeze_apple_release_candidates as freeze

        self.freeze = freeze
        self.temp = tempfile.TemporaryDirectory(prefix="wins-apple-source-staleness-")
        self.repo = Path(self.temp.name)
        git = ["git", "-C", str(self.repo)]
        subprocess.run([*git, "init", "-q"], check=True)
        subprocess.run([*git, "config", "user.email", "t@example.invalid"], check=True)
        subprocess.run([*git, "config", "user.name", "t"], check=True)
        self.sources = {
            "lib/l10n/app_localizations.dart": "// generated\n",
            "ios/Runner.xcodeproj/project.pbxproj": "// project\n",
            "lib/main.dart": "void main() {}\n",
        }
        for relative, text in self.sources.items():
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        subprocess.run([*git, "add", "-A"], check=True)
        subprocess.run([*git, "commit", "-q", "-m", "fixture"], check=True)
        self.artifact_mtime = 1_000_000_000.0
        for relative in self.sources:
            os.utime(self.repo / relative, (self.artifact_mtime - 10, self.artifact_mtime - 10))
        self.extra: list[Path] = []

    def tearDown(self) -> None:
        self.temp.cleanup()

    def changed(self) -> list[str]:
        files = [self.repo / relative for relative in self.sources] + self.extra
        with mock.patch.object(self.freeze, "ROOT", self.repo), mock.patch.object(
            self.freeze, "_artifact_runtime_source_files", return_value=files
        ):
            return self.freeze.runtime_sources_changed_since("ios", self.artifact_mtime)

    def test_identical_rewrites_after_the_candidate_pass(self) -> None:
        for relative, text in self.sources.items():
            (self.repo / relative).write_text(text, encoding="utf-8")
        self.assertEqual(self.changed(), [])

    def test_an_edited_source_after_the_candidate_is_refused(self) -> None:
        (self.repo / "lib/main.dart").write_text("void main() { edit(); }\n", encoding="utf-8")
        self.assertEqual(self.changed(), ["lib/main.dart"])

    def test_an_untracked_newer_source_is_refused(self) -> None:
        extra = self.repo / "lib/new_source.dart"
        extra.write_text("// new\n", encoding="utf-8")
        self.extra.append(extra)
        self.assertEqual(self.changed(), ["lib/new_source.dart"])

class AppleFreezeArchitectureInventoryTests(unittest.TestCase):
    """R22 Y3-08: the PKG plist cannot steer the inventory; tools are bounded."""

    def setUp(self) -> None:
        import freeze_apple_release_candidates as freeze

        self.freeze = freeze

    def inventory(
        self,
        executable: str,
        *,
        symlinked: bool = False,
        linked_component: str = "",
        pkgutil_timeout: bool = False,
        lipo_timeout: bool = False,
    ) -> dict[str, object]:
        def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess:
            self.assertIn("timeout", kwargs)
            if argv[0] == "/usr/sbin/pkgutil":
                if pkgutil_timeout:
                    raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
                contents = Path(argv[3]) / "Payload" / "Win's VPN.app" / "Contents"
                # pkgutil --expand-full restores payload links; "outside" is a
                # sibling of the expansion, as any host path would be.
                outside = Path(argv[3]).parent / "outside"
                outside.mkdir()
                contents.mkdir(parents=True)
                if linked_component == "Contents/MacOS":
                    (outside / "WinsVPN").write_bytes(b"\xca\xfe\xba\xbe outside fat binary")
                    (contents / "MacOS").symlink_to(outside)
                else:
                    (contents / "MacOS").mkdir()
                plist = plistlib.dumps({"CFBundleExecutable": executable})
                if linked_component == "Contents/Info.plist":
                    (outside / "Info.plist").write_bytes(plist)
                    (contents / "Info.plist").symlink_to(outside / "Info.plist")
                else:
                    (contents / "Info.plist").write_bytes(plist)
                if linked_component == "Contents/MacOS":
                    return subprocess.CompletedProcess(argv, 0, b"", b"")
                binary = contents / "MacOS" / ("real" if symlinked else "WinsVPN")
                binary.write_bytes(b"\xcf\xfa\xed\xfe fixture executable")
                if symlinked:
                    (contents / "MacOS" / "WinsVPN").symlink_to("real")
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            if argv[0] == "/usr/bin/lipo":
                if lipo_timeout:
                    raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
                return subprocess.CompletedProcess(argv, 0, b"x86_64 arm64\n", b"")
            raise AssertionError(f"unexpected tool {argv[0]}")

        with mock.patch.object(self.freeze.subprocess, "run", side_effect=fake_run):
            return self.freeze._macos_shipped_architecture_inventory(
                Path("/fixture/Win's VPN.pkg")
            )

    def test_plain_executable_name_is_inventoried(self) -> None:
        shipped = self.inventory("WinsVPN")["shipped"]
        self.assertEqual(len(shipped), 1)
        self.assertEqual(shipped[0]["path"], "Win's VPN.app/Contents/MacOS/WinsVPN")
        self.assertEqual(shipped[0]["architectures"], ["x86_64", "arm64"])

    def test_plist_cannot_steer_the_inventory_outside_contents_macos(self) -> None:
        for name in ("/usr/bin/true", "../../../escape", "Helpers/WinsVPN", "..", "."):
            with self.subTest(executable=name):
                with self.assertRaisesRegex(
                    self.freeze.FreezeError, "CFBundleExecutable is not a plain file name"
                ):
                    self.inventory(name)
        with self.assertRaisesRegex(self.freeze.FreezeError, "missing macOS executable"):
            self.inventory("WinsVPN", symlinked=True)

    def test_linked_payload_directories_cannot_steer_the_inventory(self) -> None:
        # R23 W2-1: a plain final name is not enough; a linked Contents/MacOS made
        # the inventory measure and record a binary outside the expanded PKG.
        for component in ("Contents/MacOS", "Contents/Info.plist"):
            with self.subTest(linked=component):
                with self.assertRaisesRegex(self.freeze.FreezeError, "crosses a symlink"):
                    self.inventory("WinsVPN", linked_component=component)

    def test_pkgutil_and_lipo_are_bounded(self) -> None:
        with self.assertRaisesRegex(self.freeze.FreezeError, "pkgutil --expand-full timed out"):
            self.inventory("WinsVPN", pkgutil_timeout=True)
        with self.assertRaisesRegex(self.freeze.FreezeError, "lipo -archs timed out"):
            self.inventory("WinsVPN", lipo_timeout=True)


class AppleFreezeArchivePrivacyInventoryTests(unittest.TestCase):
    """R22 Y3 D2: the freeze binds the archive privacy report to the exact IPA and PKG."""

    APP = "Win's VPN.app"
    IOS_MANIFESTS = {
        f"{APP}/PrivacyInfo.xcprivacy": b"ios host privacy",
        f"{APP}/PlugIns/PacketTunnel.appex/PrivacyInfo.xcprivacy": b"ios tunnel privacy",
        f"{APP}/Watch/WinsWatch.app/PrivacyInfo.xcprivacy": b"watch privacy",
    }
    MACOS_MANIFESTS = {
        f"{APP}/Contents/Resources/PrivacyInfo.xcprivacy": b"macos host privacy",
        f"{APP}/Contents/Frameworks/Engine.framework/Versions/A/Resources/PrivacyInfo.xcprivacy": b"framework privacy",
    }

    def setUp(self) -> None:
        import freeze_apple_release_candidates as freeze

        self.freeze = freeze
        self.temp = tempfile.TemporaryDirectory(prefix="wins-apple-privacy-binding-")
        self.base = Path(self.temp.name)
        self.ipa = self.base / "Calculator.ipa"
        self.write_ipa(self.IOS_MANIFESTS)
        self.pkg = self.base / "Win's VPN.pkg"
        self.pkg.write_bytes(b"fixture package")
        self.pkg_manifests = dict(self.MACOS_MANIFESTS)
        self.pkg_linked = ""
        self.inventory = self.base / "APPLE_ARCHIVE_PRIVACY_INVENTORY.json"
        self.write_report(self.IOS_MANIFESTS, self.MACOS_MANIFESTS)
        self.validated: list[object] = []

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_ipa(self, manifests: dict[str, bytes], extra: tuple[str, ...] = ()) -> None:
        with zipfile.ZipFile(self.ipa, "w") as archive:
            archive.writestr(f"Payload/{self.APP}/Info.plist", b"plist")
            for relative, data in manifests.items():
                archive.writestr(f"Payload/{relative}", data)
            for name in extra:
                archive.writestr(name, b"extra privacy")

    def write_report(self, ios: dict[str, bytes], macos: dict[str, bytes]) -> None:
        def entries(manifests: dict[str, bytes]) -> list[dict[str, object]]:
            return [
                {
                    "path": f"Products/Applications/{relative}",
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
                for relative, data in manifests.items()
            ]

        report = {
            "report_type": "local_archive_privacy_manifest_inventory",
            "archives": [
                {"archive": "wins-vpn-ios.xcarchive", "privacy_manifests": entries(ios)},
                {"archive": "wins-vpn-macos.xcarchive", "privacy_manifests": entries(macos)},
            ],
        }
        self.inventory.write_text(json.dumps(report), encoding="utf-8")

    def fake_pkgutil(self, argv: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        self.assertEqual(argv[:2], ["/usr/sbin/pkgutil", "--expand-full"])
        self.assertIn("timeout", kwargs)
        payload = Path(argv[3]) / "Payload"
        contents = payload / self.APP / "Contents"
        contents.mkdir(parents=True)
        outside = Path(argv[3]).parent / "outside"
        outside.mkdir()
        if self.pkg_linked == "Contents/Info.plist":
            (outside / "Info.plist").write_bytes(b"plist")
            (contents / "Info.plist").symlink_to(outside / "Info.plist")
        else:
            (contents / "Info.plist").write_bytes(b"plist")
        for relative, data in self.pkg_manifests.items():
            path = payload / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        if self.pkg_linked == "Helpers/PrivacyInfo.xcprivacy":
            # A linked manifest the archive report does not list either.
            (outside / "PrivacyInfo.xcprivacy").write_bytes(b"unbound privacy")
            (contents / "Helpers").mkdir()
            (contents / "Helpers" / "PrivacyInfo.xcprivacy").symlink_to(
                outside / "PrivacyInfo.xcprivacy"
            )
        framework = contents / "Frameworks" / "Engine.framework"
        if framework.is_dir():
            # The real bundle layout: these links must not count the manifest twice.
            (framework / "Versions" / "Current").symlink_to("A")
            (framework / "Resources").symlink_to("Versions/Current/Resources")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    def bind(self) -> None:
        def record(report: object, expected: object) -> None:
            self.validated.append(expected)

        label = {"binary_evidence": {"expected_archives": ["expected-fixture"]}}
        with mock.patch.object(
            self.freeze.subprocess, "run", side_effect=self.fake_pkgutil
        ), mock.patch.object(
            self.freeze, "_validate_archive_privacy_report", side_effect=record
        ), mock.patch.object(self.freeze, "read_json", return_value=label):
            self.freeze.bind_archive_privacy_inventory(self.inventory, self.ipa, self.pkg)

    def test_report_matching_the_candidates_binds(self) -> None:
        self.bind()
        self.assertEqual(self.validated, [["expected-fixture"]])

    def test_changed_ios_manifest_bytes_are_refused(self) -> None:
        changed = dict(self.IOS_MANIFESTS)
        changed[f"{self.APP}/PrivacyInfo.xcprivacy"] = b"different host privacy"
        self.write_ipa(changed)
        with self.assertRaisesRegex(self.freeze.FreezeError, "ios candidate privacy manifests differ"):
            self.bind()

    def test_unreported_or_missing_manifests_are_refused(self) -> None:
        self.write_ipa(self.IOS_MANIFESTS, extra=(f"Payload/{self.APP}/Frameworks/New.framework/PrivacyInfo.xcprivacy",))
        with self.assertRaisesRegex(self.freeze.FreezeError, "New.framework"):
            self.bind()
        self.write_ipa(self.IOS_MANIFESTS)
        self.pkg_manifests.pop(f"{self.APP}/Contents/Resources/PrivacyInfo.xcprivacy")
        with self.assertRaisesRegex(self.freeze.FreezeError, "macos candidate privacy manifests differ"):
            self.bind()

    def test_malformed_reports_are_refused(self) -> None:
        report = json.loads(self.inventory.read_text(encoding="utf-8"))
        cases = {
            "missing archive": (lambda r: r["archives"].pop(1), "describe wins-vpn-macos.xcarchive exactly once"),
            "outside applications": (
                lambda r: r["archives"][0]["privacy_manifests"][0].update(path="Products/Other/PrivacyInfo.xcprivacy"),
                "outside Products/Applications",
            ),
            "duplicate path": (
                lambda r: r["archives"][0]["privacy_manifests"].append(dict(r["archives"][0]["privacy_manifests"][0])),
                "twice",
            ),
        }
        for label, (mutate, message) in cases.items():
            with self.subTest(case=label):
                changed = json.loads(json.dumps(report))
                mutate(changed)
                self.inventory.write_text(json.dumps(changed), encoding="utf-8")
                with self.assertRaisesRegex(self.freeze.FreezeError, message):
                    self.bind()
        self.inventory.write_text("not json", encoding="utf-8")
        with self.assertRaisesRegex(self.freeze.FreezeError, "not valid JSON"):
            self.bind()

    def test_pkg_links_cannot_hide_or_steer_a_privacy_manifest(self) -> None:
        # R23 W2-1, same file: the host app search and the walk do not cross a link,
        # and a linked manifest is refused instead of shipping unbound.
        for component in ("Contents/Info.plist", "Helpers/PrivacyInfo.xcprivacy"):
            with self.subTest(linked=component):
                self.pkg_linked = component
                with self.assertRaisesRegex(self.freeze.FreezeError, "crosses a symlink"):
                    self.bind()

    def test_link_check_covers_every_component_below_the_expansion(self) -> None:
        expanded = self.base / "expanded"
        (expanded / "Payload" / "A.app" / "Contents").mkdir(parents=True)
        (self.base / "elsewhere").mkdir()
        (expanded / "Payload" / "Linked.app").symlink_to(self.base / "elsewhere")
        real = expanded / "Payload" / "A.app" / "Contents"
        self.freeze._reject_symlinked_components(expanded, real, self.pkg, "fixture")
        for candidate in (
            expanded / "Payload" / "Linked.app" / "Contents",
            self.base / "elsewhere",
        ):
            with self.subTest(candidate=str(candidate)):
                with self.assertRaises(self.freeze.FreezeError):
                    self.freeze._reject_symlinked_components(
                        expanded, candidate, self.pkg, "fixture"
                    )

    def test_ipa_member_outside_payload_is_refused(self) -> None:
        self.write_ipa(self.IOS_MANIFESTS, extra=("Symbols/PrivacyInfo.xcprivacy",))
        with self.assertRaisesRegex(self.freeze.FreezeError, "outside Payload"):
            self.bind()

    def test_ipa_members_cannot_alias_or_link_a_privacy_manifest(self) -> None:
        # R24 F-R24-05: PurePosixPath folds "./" and "//" away, so a second raw
        # name measured over the reported manifest under the same key; a link
        # or case-colliding member gets the Watch identity read's refusal here too.
        host = f"Payload/{self.APP}/PrivacyInfo.xcprivacy"
        for label, alias in (
            ("dot segment", f"Payload/{self.APP}/./PrivacyInfo.xcprivacy"),
            ("empty segment", f"Payload/{self.APP}//PrivacyInfo.xcprivacy"),
        ):
            with self.subTest(case=label):
                # Written first, the alias is the one an extractor may keep while
                # the reported bytes, written last, are the ones measured.
                with zipfile.ZipFile(self.ipa, "w") as archive:
                    archive.writestr(alias, b"aliased privacy")
                    archive.writestr(f"Payload/{self.APP}/Info.plist", b"plist")
                    for relative, data in self.IOS_MANIFESTS.items():
                        archive.writestr(f"Payload/{relative}", data)
                with self.assertRaisesRegex(self.freeze.FreezeError, "unsafe zip"):
                    self.bind()
        with zipfile.ZipFile(self.ipa, "w") as archive:
            archive.writestr(f"Payload/{self.APP}/Info.plist", b"plist")
            for relative, data in self.IOS_MANIFESTS.items():
                if f"Payload/{relative}" == host:
                    link = zipfile.ZipInfo(host)
                    link.external_attr = (0o120777 << 16)
                    archive.writestr(link, data)
                else:
                    archive.writestr(f"Payload/{relative}", data)
        with self.assertRaisesRegex(self.freeze.FreezeError, "symbolic-link members"):
            self.bind()
        self.write_ipa(
            self.IOS_MANIFESTS, extra=(f"Payload/{self.APP}/privacyinfo.xcprivacy",)
        )
        with self.assertRaisesRegex(self.freeze.FreezeError, "duplicate or empty zip paths"):
            self.bind()

    def test_producer_writes_and_hands_over_the_report(self) -> None:
        producer = (ROOT / "tools/build_apple_release_candidates.sh").read_text(encoding="utf-8")
        first_pass = producer.split("WINS_APPLE_RELEASE_CANDIDATE_REBUILD=1", 1)[1].split("tee \"${RUN_LOG}\"", 1)[0]
        self.assertIn("WINS_APPLE_PRIVACY_ARCHIVE_REPORT=1", first_pass)
        stale = producer.index('/bin/rm -f "${ARCHIVE_PRIVACY_REPORT}"')
        self.assertLess(stale, producer.index("WINS_APPLE_RELEASE_CANDIDATE_REBUILD=1"))
        freeze = producer.split("tools/freeze_apple_release_candidates.py", 1)[1].split("\n\n", 1)[0]
        self.assertIn('--archive-privacy-inventory "${ARCHIVE_PRIVACY_INVENTORY}"', freeze)
        self.assertIn('ARCHIVE_PRIVACY_INVENTORY="${RECEIPT_DIR}/', producer)


if __name__ == "__main__":
    unittest.main()
