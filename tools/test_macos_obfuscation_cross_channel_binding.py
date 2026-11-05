#!/usr/bin/env python3
"""macOS App Store PKG and Developer ID obfuscation evidence must not cross-bind."""

from __future__ import annotations

import json
import pathlib
import shutil
import sys
import tempfile
import unittest
import zipfile
from unittest import mock


TOOLS = pathlib.Path(__file__).resolve().parent
ROOT = TOOLS.parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import apple_cross_store_artifact_gate as apple_gate
import release_obfuscation_contract as obfuscation


APP_STORE = "macos-app-store-pkg"
DEVELOPER_ID = "macos-developer-id-app"
IOS = "ios-app-store-ipa"


class MacosObfuscationCrossChannelBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name).resolve()
        self.private_root = self.repo / "private-release-symbols"
        self.private_root.mkdir(parents=True)
        (self.repo / "artifacts").mkdir()
        self.version_patch = mock.patch.object(
            obfuscation, "pubspec_version", return_value=("1.0.15", "30")
        )
        self.obfuscation_root_patch = mock.patch.object(obfuscation, "ROOT", self.repo)
        self.apple_root_patch = mock.patch.object(apple_gate, "ROOT", self.repo)
        self.apple_helper_patch = mock.patch.object(
            obfuscation,
            "_load_reviewed_helper",
            return_value=apple_gate,
        )
        self.private_patch = mock.patch.object(
            obfuscation, "PRIVATE_SYMBOL_ROOT", self.private_root
        )
        self.static_patch = mock.patch.object(obfuscation, "validate_static")
        self.hardening_patch = mock.patch.object(
            obfuscation, "verify_release_artifact_hardening"
        )
        self.privacy_patch = mock.patch.object(apple_gate, "verify_privacy_only")
        self.version_patch.start()
        self.obfuscation_root_patch.start()
        self.apple_root_patch.start()
        self.apple_helper_patch.start()
        self.private_patch.start()
        self.static_patch.start()
        self.hardening_patch.start()
        self.privacy_mock = self.privacy_patch.start()

    def tearDown(self) -> None:
        self.privacy_patch.stop()
        self.hardening_patch.stop()
        self.static_patch.stop()
        self.private_patch.stop()
        self.apple_helper_patch.stop()
        self.apple_root_patch.stop()
        self.obfuscation_root_patch.stop()
        self.version_patch.stop()
        self.temporary.cleanup()

    def _write_pkg(self, name: str = "WinsVPN.pkg", payload: bytes | None = None) -> pathlib.Path:
        path = self.repo / "artifacts" / name
        path.write_bytes(payload or (b"app-store-pkg-" + name.encode("ascii")))
        return path

    def _write_app_zip(
        self, name: str = "WinsVPN.app.zip", payload: bytes | None = None
    ) -> pathlib.Path:
        path = self.repo / "artifacts" / name
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("Win's VPN.app/Contents/Info.plist", payload or b"developer-id")
        return path

    def _write_ipa(self, name: str = "WinsVPN.ipa") -> pathlib.Path:
        path = self.repo / "artifacts" / name
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("Payload/Win's VPN.app/Info.plist", b"ios")
        return path

    def _prepare_target(self, target_id: str) -> tuple[dict[str, object], pathlib.Path]:
        layout = obfuscation.exact_obfuscation_layout(target_id)
        symbols_dir = pathlib.Path(str(layout["symbols_dir"]))
        symbols_dir.mkdir(parents=True, exist_ok=True)
        symbol_file = symbols_dir / "app.symbols"
        if not symbol_file.exists():
            symbol_file.write_bytes(b"s" * 128)
        if target_id == APP_STORE:
            artifact = self._write_pkg()
        else:
            artifact = self._write_app_zip()
        return layout, artifact

    def _record(self, target_id: str) -> tuple[dict[str, object], pathlib.Path]:
        layout, artifact = self._prepare_target(target_id)
        obfuscation.record(
            "macos",
            pathlib.Path(str(layout["symbols_dir"])),
            pathlib.Path(str(layout["manifest"])),
            [artifact],
            target_id,
        )
        return layout, artifact

    def test_macos_targets_have_distinct_target_bound_manifests(self) -> None:
        app_store = obfuscation.exact_obfuscation_layout(APP_STORE)
        developer_id = obfuscation.exact_obfuscation_layout(DEVELOPER_ID)
        self.assertEqual(app_store["platform"], "macos")
        self.assertEqual(developer_id["platform"], "macos")
        self.assertEqual(app_store["symbols_dir"], developer_id["symbols_dir"])
        self.assertNotEqual(app_store["manifest"], developer_id["manifest"])
        self.assertTrue(str(app_store["manifest"]).endswith("manifest-app-store.json"))
        self.assertTrue(
            str(developer_id["manifest"]).endswith("manifest-developer-id.json")
        )
        self.assertEqual(app_store["channel"], "mac-app-store")
        self.assertEqual(developer_id["channel"], "developer-id")
        self.assertEqual(app_store["signing_contract"], "apple-distribution")
        self.assertEqual(developer_id["signing_contract"], "developer-id-application")
        self.assertNotEqual(
            app_store["expected_authority"], developer_id["expected_authority"]
        )
        self.assertEqual(app_store["artifact_suffixes"], (".pkg",))
        self.assertEqual(developer_id["artifact_suffixes"], (".app.zip",))
        with self.assertRaisesRegex(obfuscation.ObfuscationError, "unsupported exact"):
            obfuscation.exact_obfuscation_layout(IOS)

    def test_macos_package_suffixes_are_channel_exclusive(self) -> None:
        app_store = apple_gate.macos_package_channel_contract(APP_STORE)
        developer_id = apple_gate.macos_package_channel_contract(DEVELOPER_ID)
        self.assertEqual(app_store["suffixes"], (".pkg",))
        self.assertEqual(developer_id["suffixes"], (".app.zip",))
        self.assertFalse(set(app_store["suffixes"]) & set(developer_id["suffixes"]))
        self.assertIs(app_store["signature_verified"], False)
        self.assertIs(developer_id["signature_verified"], False)
        self.assertEqual(app_store["signature_gate"], "verify_signature")
        with mock.patch.dict(
            apple_gate.TARGET_SUFFIXES,
            {
                IOS: (".ipa",),
                APP_STORE: (".pkg",),
                DEVELOPER_ID: (".app.zip", ".pkg"),
            },
            clear=True,
        ):
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "not exclusive"
            ):
                apple_gate._macos_exclusive_suffixes(APP_STORE)

    def test_bind_macos_package_channel_records_contract_without_signature_proof(
        self,
    ) -> None:
        pkg = self._write_pkg()
        app_zip = self._write_app_zip()
        with mock.patch.object(apple_gate.subprocess, "run") as run:
            bound_pkg = apple_gate.bind_macos_package_channel(
                APP_STORE, "artifacts/WinsVPN.pkg"
            )
            bound_zip = apple_gate.bind_macos_package_channel(
                DEVELOPER_ID, "artifacts/WinsVPN.app.zip"
            )
        run.assert_not_called()
        self.assertEqual(bound_pkg["artifact"], pkg)
        self.assertEqual(bound_zip["artifact"], app_zip)
        self.assertEqual(bound_pkg["channel"], "mac-app-store")
        self.assertEqual(bound_zip["channel"], "developer-id")
        self.assertEqual(bound_pkg["signing_contract"], "apple-distribution")
        self.assertEqual(bound_zip["signing_contract"], "developer-id-application")
        self.assertEqual(
            bound_pkg["expected_authority"], apple_gate.APP_STORE_DISTRIBUTION_AUTHORITY
        )
        self.assertEqual(
            bound_zip["expected_authority"],
            apple_gate.DEVELOPER_ID_APPLICATION_AUTHORITY,
        )
        self.assertIs(bound_pkg["signature_verified"], False)
        self.assertIs(bound_zip["signature_verified"], False)
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "unsupported macOS package channel"
        ):
            apple_gate.bind_macos_package_channel(IOS, "artifacts/WinsVPN.ipa")

    def test_cross_channel_substitution_fails(self) -> None:
        app_layout, app_artifact = self._record(APP_STORE)
        dev_layout, dev_artifact = self._record(DEVELOPER_ID)
        with self.assertRaisesRegex(
            obfuscation.ObfuscationError, "immutable obfuscation manifest"
        ):
            obfuscation.verify(
                "macos",
                pathlib.Path(str(dev_layout["manifest"])),
                pathlib.Path(str(dev_layout["symbols_dir"])),
                [dev_artifact],
                APP_STORE,
            )
        with self.assertRaisesRegex(
            obfuscation.ObfuscationError, "immutable obfuscation manifest"
        ):
            obfuscation.verify(
                "macos",
                pathlib.Path(str(app_layout["manifest"])),
                pathlib.Path(str(app_layout["symbols_dir"])),
                [app_artifact],
                DEVELOPER_ID,
            )
        shutil.copyfile(
            pathlib.Path(str(app_layout["manifest"])),
            pathlib.Path(str(dev_layout["manifest"])),
        )
        with self.assertRaisesRegex(
            obfuscation.ObfuscationError, "requested exact target"
        ):
            obfuscation.verify(
                "macos",
                pathlib.Path(str(dev_layout["manifest"])),
                pathlib.Path(str(dev_layout["symbols_dir"])),
                [dev_artifact],
                DEVELOPER_ID,
            )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "requires artifact suffix"
        ):
            apple_gate.bind_macos_package_channel(DEVELOPER_ID, "artifacts/WinsVPN.pkg")
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "requires artifact suffix"
        ):
            apple_gate.bind_macos_package_channel(APP_STORE, "artifacts/WinsVPN.app.zip")

    def test_missing_target_fails(self) -> None:
        layout, artifact = self._record(APP_STORE)
        manifest = pathlib.Path(str(layout["manifest"]))
        with self.assertRaisesRegex(
            obfuscation.ObfuscationError, "must select that target"
        ):
            obfuscation.verify(
                "macos",
                manifest,
                pathlib.Path(str(layout["symbols_dir"])),
                [artifact],
            )
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        payload.pop("target_id")
        manifest.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            obfuscation.ObfuscationError, "requested exact target"
        ):
            obfuscation.verify(
                "macos",
                manifest,
                pathlib.Path(str(layout["symbols_dir"])),
                [artifact],
                APP_STORE,
            )
        unbound_layout, unbound_artifact = self._prepare_target(DEVELOPER_ID)
        obfuscation.record(
            "macos",
            pathlib.Path(str(unbound_layout["symbols_dir"])),
            pathlib.Path(str(unbound_layout["manifest"])),
            [unbound_artifact],
        )
        unbound_payload = json.loads(
            pathlib.Path(str(unbound_layout["manifest"])).read_text(encoding="utf-8")
        )
        self.assertNotIn("target_id", unbound_payload)
        with self.assertRaisesRegex(
            obfuscation.ObfuscationError, "requested exact target"
        ):
            obfuscation.verify(
                "macos",
                pathlib.Path(str(unbound_layout["manifest"])),
                pathlib.Path(str(unbound_layout["symbols_dir"])),
                [unbound_artifact],
                DEVELOPER_ID,
            )

    def test_shared_manifest_fails(self) -> None:
        app_layout, app_artifact = self._prepare_target(APP_STORE)
        dev_layout, dev_artifact = self._prepare_target(DEVELOPER_ID)
        self.assertEqual(app_layout["symbols_dir"], dev_layout["symbols_dir"])
        self.assertNotEqual(app_layout["manifest"], dev_layout["manifest"])
        shared = pathlib.Path(str(app_layout["symbols_dir"])) / "manifest.json"
        with self.assertRaisesRegex(
            obfuscation.ObfuscationError, "immutable obfuscation manifest"
        ):
            obfuscation._bind_exact_target_paths(
                APP_STORE,
                "macos",
                pathlib.Path(str(app_layout["symbols_dir"])),
                shared,
                [app_artifact],
            )
        with self.assertRaisesRegex(
            obfuscation.ObfuscationError, "immutable obfuscation manifest"
        ):
            obfuscation._bind_exact_target_paths(
                DEVELOPER_ID,
                "macos",
                pathlib.Path(str(dev_layout["symbols_dir"])),
                pathlib.Path(str(app_layout["manifest"])),
                [dev_artifact],
            )
        with self.assertRaisesRegex(
            obfuscation.ObfuscationError, "immutable obfuscation manifest"
        ):
            obfuscation._bind_exact_target_paths(
                APP_STORE,
                "macos",
                pathlib.Path(str(app_layout["symbols_dir"])),
                pathlib.Path(str(dev_layout["manifest"])),
                [app_artifact],
            )

    def test_wrong_suffix_and_path_fail(self) -> None:
        self._write_pkg()
        self._write_app_zip()
        self._write_ipa()
        self._write_pkg("unsigned.pkg")
        stray_zip = self.repo / "artifacts" / "WinsVPN.zip"
        stray_zip.write_bytes(b"not-an-app-zip")
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "requires artifact suffix"
        ):
            apple_gate.canonical_artifact(APP_STORE, "artifacts/WinsVPN.app.zip")
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "requires artifact suffix"
        ):
            apple_gate.canonical_artifact(DEVELOPER_ID, "artifacts/WinsVPN.pkg")
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "requires artifact suffix"
        ):
            apple_gate.canonical_artifact(APP_STORE, "artifacts/WinsVPN.ipa")
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "requires artifact suffix"
        ):
            apple_gate.canonical_artifact(DEVELOPER_ID, "artifacts/WinsVPN.zip")
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "repository-relative"
        ):
            apple_gate.canonical_artifact(APP_STORE, "/tmp/WinsVPN.pkg")
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "unsafe components"
        ):
            apple_gate.canonical_artifact(APP_STORE, "../WinsVPN.pkg")
        layout, artifact = self._prepare_target(APP_STORE)
        with self.assertRaisesRegex(
            obfuscation.ObfuscationError, "does not match artifact"
        ):
            obfuscation._bind_exact_target_paths(
                APP_STORE,
                "macos",
                pathlib.Path(str(layout["symbols_dir"])),
                pathlib.Path(str(layout["manifest"])),
                [self.repo / "artifacts" / "WinsVPN.app.zip"],
            )
        other_symbols = self.private_root / "apple" / "macos" / "other"
        other_symbols.mkdir(parents=True)
        with self.assertRaisesRegex(
            obfuscation.ObfuscationError, "immutable symbol directory"
        ):
            obfuscation._bind_exact_target_paths(
                APP_STORE,
                "macos",
                other_symbols,
                pathlib.Path(str(layout["manifest"])),
                [artifact],
            )
        self.assertEqual(artifact.name, "WinsVPN.pkg")

    def test_valid_independent_fixtures(self) -> None:
        app_layout, app_artifact = self._record(APP_STORE)
        first_bytes = pathlib.Path(str(app_layout["manifest"])).read_bytes()
        dev_layout, dev_artifact = self._record(DEVELOPER_ID)
        self.assertEqual(
            pathlib.Path(str(app_layout["manifest"])).read_bytes(), first_bytes
        )
        obfuscation.verify(
            "macos",
            pathlib.Path(str(app_layout["manifest"])),
            pathlib.Path(str(app_layout["symbols_dir"])),
            [app_artifact],
            APP_STORE,
        )
        obfuscation.verify(
            "macos",
            pathlib.Path(str(dev_layout["manifest"])),
            pathlib.Path(str(dev_layout["symbols_dir"])),
            [dev_artifact],
            DEVELOPER_ID,
        )
        app_payload = json.loads(
            pathlib.Path(str(app_layout["manifest"])).read_text(encoding="utf-8")
        )
        dev_payload = json.loads(
            pathlib.Path(str(dev_layout["manifest"])).read_text(encoding="utf-8")
        )
        self.assertEqual(app_payload["target_id"], APP_STORE)
        self.assertEqual(dev_payload["target_id"], DEVELOPER_ID)
        obfuscation.canonical_apple_gate_verify(APP_STORE, "artifacts/WinsVPN.pkg")
        obfuscation.canonical_apple_gate_verify(
            DEVELOPER_ID, "artifacts/WinsVPN.app.zip"
        )
        self.assertEqual(self.privacy_mock.call_count, 2)

    def test_canonical_macos_gate_forwards_exact_target_id(self) -> None:
        self._write_pkg()
        self._write_app_zip()
        captured: list[tuple[str, pathlib.Path, pathlib.Path, str | None]] = []

        def fake_verify(
            platform: str,
            manifest: pathlib.Path,
            symbols: pathlib.Path,
            artifacts: list[pathlib.Path],
            target_id: str | None = None,
        ) -> None:
            del artifacts
            captured.append((platform, manifest, symbols, target_id))

        with mock.patch.object(obfuscation, "verify", side_effect=fake_verify):
            obfuscation.canonical_apple_gate_verify(APP_STORE, "artifacts/WinsVPN.pkg")
            obfuscation.canonical_apple_gate_verify(
                DEVELOPER_ID, "artifacts/WinsVPN.app.zip"
            )
        self.assertEqual(
            [item[3] for item in captured],
            [APP_STORE, DEVELOPER_ID],
        )
        self.assertEqual({item[0] for item in captured}, {"macos"})
        self.assertTrue(str(captured[0][1]).endswith("manifest-app-store.json"))
        self.assertTrue(str(captured[1][1]).endswith("manifest-developer-id.json"))
        self.assertEqual(captured[0][2], captured[1][2])
        self.assertNotEqual(captured[0][1], captured[1][1])

    def test_ios_canonical_path_stays_unbound_and_skips_macos_channel(self) -> None:
        self._write_ipa()
        captured: list[tuple[str, pathlib.Path, str | None]] = []
        bind_calls: list[str] = []

        def fake_verify(
            platform: str,
            manifest: pathlib.Path,
            symbols: pathlib.Path,
            artifacts: list[pathlib.Path],
            target_id: str | None = None,
        ) -> None:
            del symbols, artifacts
            captured.append((platform, manifest, target_id))

        def fake_bind(target_id: str, raw_path: str | pathlib.Path) -> dict[str, object]:
            del raw_path
            bind_calls.append(target_id)
            raise AssertionError("iOS must not use macOS package channel binding")

        with (
            mock.patch.object(obfuscation, "verify", side_effect=fake_verify),
            mock.patch.object(
                apple_gate, "bind_macos_package_channel", side_effect=fake_bind
            ),
        ):
            obfuscation.canonical_apple_gate_verify(IOS, "artifacts/WinsVPN.ipa")
        self.assertEqual(bind_calls, [])
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0][0], "ios")
        self.assertIsNone(captured[0][2])
        self.assertTrue(str(captured[0][1]).endswith("manifest.json"))
        self.assertIn("/apple/ios/", str(captured[0][1]).replace("\\", "/"))
        obfuscation.verify_embedded_watchos_companion("macos", [self._write_pkg()])
        with self.assertRaisesRegex(
            obfuscation.ObfuscationError, "missing the embedded watchOS"
        ):
            obfuscation.verify_embedded_watchos_companion("ios", [self._write_ipa()])


if __name__ == "__main__":
    unittest.main()
