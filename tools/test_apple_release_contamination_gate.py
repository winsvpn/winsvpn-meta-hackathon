#!/usr/bin/env python3

from __future__ import annotations

import io
import base64
import pathlib
import plistlib
import stat
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr
from unittest import mock

import apple_release_contamination_gate as gate


ROOT = pathlib.Path(__file__).resolve().parents[1]


class AppleReleaseContaminationGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="wins-contamination-test-")
        self.root = pathlib.Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_app(
        self,
        platform: str,
        *,
        contract: object = gate.CONTRACT_VALUE,
        smoke: object = False,
        pin: object = False,
        aot: bytes = b"release-aot-without-test-harness",
    ) -> pathlib.Path:
        app = self.root / ("Runner.app" if platform == "ios" else "Win's VPN.app")
        if platform == "ios":
            info = app / "Info.plist"
            binary = app / "Frameworks/App.framework/App"
        else:
            info = app / "Contents/Info.plist"
            binary = app / "Contents/Frameworks/App.framework/App"
        info.parent.mkdir(parents=True)
        binary.parent.mkdir(parents=True)
        info.write_bytes(
            plistlib.dumps(
                {
                    gate.CONTRACT_KEY: contract,
                    gate.LIVE_SMOKE_KEY: smoke,
                    gate.SMOKE_PIN_KEY: pin,
                }
            )
        )
        binary.write_bytes(aot)
        return app

    def zip_tree(self, source: pathlib.Path, destination: pathlib.Path, prefix: str = "") -> None:
        with zipfile.ZipFile(destination, "w") as archive:
            for path in sorted(source.rglob("*")):
                if path.is_file():
                    archive.write(path, prefix + path.relative_to(source).as_posix())

    def test_safe_ios_and_macos_apps_pass(self) -> None:
        gate.verify_app_bundle(self.make_app("ios"), "ios")
        self.root.joinpath("Runner.app").rename(self.root / "saved-ios.app")
        gate.verify_app_bundle(self.make_app("macos"), "macos")

    def test_missing_contract_fails_closed_for_old_archive(self) -> None:
        app = self.make_app("ios", contract="")
        with self.assertRaisesRegex(
            gate.AppleReleaseContaminationError, "contract is missing"
        ):
            gate.verify_app_bundle(app, "ios")

    def test_live_smoke_attestation_is_rejected(self) -> None:
        app = self.make_app("ios", smoke=True)
        with self.assertRaisesRegex(
            gate.AppleReleaseContaminationError, "compilation is disabled"
        ):
            gate.verify_app_bundle(app, "ios")

    def test_pin_attestation_is_rejected_without_echoing_pin(self) -> None:
        secret = "947261"
        app = self.make_app("ios", pin=True, aot=secret.encode("ascii"))
        ipa = self.root / "contaminated.ipa"
        self.zip_tree(app, ipa, "Payload/Runner.app/")
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(gate.main(["--platform", "ios", str(ipa)]), 1)
        self.assertNotIn(secret, stderr.getvalue())
        self.assertIn("PIN material is absent", stderr.getvalue())

    def test_compiled_aot_marker_is_rejected_even_when_metadata_claims_clean(self) -> None:
        app = self.make_app(
            "ios", aot=b"prefix" + gate.FORBIDDEN_AOT_MARKERS[0] + b"suffix"
        )
        with self.assertRaisesRegex(
            gate.AppleReleaseContaminationError, "compiled live-smoke behavior"
        ):
            gate.verify_app_bundle(app, "ios")

    def test_watch_companion_smoke_hook_is_rejected_in_the_embedded_watch(self) -> None:
        # R22 Y3 D2: the Watch smoke hook is DEBUG-only. A clean release Watch
        # executable passes; one carrying the hook marker, in the executable or
        # in a debug dylib beside it, fails, also from inside the exact IPA.
        app = self.make_app("ios")
        watch = app / "Watch/WinsWatch.app"
        watch.mkdir(parents=True)
        (watch / "WinsWatch").write_bytes(b"release watch executable")
        gate.verify_app_bundle(app, "ios")
        for name in ("WinsWatch", "WinsWatch.debug.dylib"):
            with self.subTest(member=name):
                (watch / name).write_bytes(
                    b"prefix" + gate.FORBIDDEN_WATCH_MARKERS[0] + b".json"
                )
                with self.assertRaisesRegex(
                    gate.AppleReleaseContaminationError, "companion smoke hook"
                ):
                    gate.verify_app_bundle(app, "ios")
                ipa = self.root / f"watch-hook-{name}.ipa"
                self.zip_tree(app, ipa, "Payload/Runner.app/")
                with self.assertRaisesRegex(
                    gate.AppleReleaseContaminationError, "companion smoke hook"
                ):
                    gate.verify_artifact(ipa, "ios")
                (watch / name).write_bytes(b"release watch executable")
        gate.verify_app_bundle(app, "ios")

    def test_watch_files_behind_a_symlink_are_refused_not_skipped(self) -> None:
        # R24 V1 F2: os.walk(followlinks=False) never descends a directory link and
        # the file loop skipped every non-regular entry, so a hook-carrying binary
        # behind a link passed. Any link under Watch/ is refused, also as an IPA
        # member (zipfile extracts a link member as a plain file of its target text).
        app = self.make_app("ios")
        watch = app / "Watch/WinsWatch.app"
        watch.mkdir(parents=True)
        (watch / "WinsWatch").write_bytes(b"release watch executable")
        hidden = self.root / "outside"
        hidden.mkdir()
        (hidden / "WinsWatch").write_bytes(b"x" + gate.FORBIDDEN_WATCH_MARKERS[0])
        (watch / "LinkedDir").symlink_to(hidden, target_is_directory=True)
        with self.assertRaisesRegex(gate.AppleReleaseContaminationError, "symlink"):
            gate.verify_app_bundle(app, "ios")
        (watch / "LinkedDir").unlink()
        (watch / "LinkedFile").symlink_to(hidden / "WinsWatch")
        with self.assertRaisesRegex(gate.AppleReleaseContaminationError, "symlink"):
            gate.verify_app_bundle(app, "ios")
        (watch / "LinkedFile").unlink()
        (watch / "Dangling").symlink_to(hidden / "missing")
        with self.assertRaisesRegex(gate.AppleReleaseContaminationError, "symlink"):
            gate.verify_app_bundle(app, "ios")
        (watch / "Dangling").unlink()
        gate.verify_app_bundle(app, "ios")
        ipa = self.root / "linked-watch.ipa"
        with zipfile.ZipFile(ipa, "w") as archive:
            for path in sorted(app.rglob("*")):
                if path.is_file():
                    archive.write(path, "Payload/Runner.app/" + path.relative_to(app).as_posix())
            link = zipfile.ZipInfo("Payload/Runner.app/Watch/WinsWatch.app/Hooked")
            link.external_attr = (stat.S_IFLNK | 0o755) << 16
            archive.writestr(link, "../../Frameworks/App.framework/App")
        with self.assertRaisesRegex(gate.AppleReleaseContaminationError, "symlink"):
            gate.verify_artifact(ipa, "ios")

    def test_marker_spanning_stream_chunk_boundary_is_rejected(self) -> None:
        marker = gate.FORBIDDEN_AOT_MARKERS[1]
        payload = b"x" * (1024 * 1024 - len(marker) // 2) + marker + b"end"
        app = self.make_app("macos", aot=payload)
        with self.assertRaises(gate.AppleReleaseContaminationError):
            gate.verify_app_bundle(app, "macos")

    def test_archive_reuse_is_checked_without_environment_state(self) -> None:
        app = self.make_app("ios", smoke=True)
        archive = self.root / "reused.xcarchive/Products/Applications"
        archive.mkdir(parents=True)
        app.rename(archive / app.name)
        with mock.patch.dict("os.environ", {}, clear=True):
            with self.assertRaisesRegex(
                gate.AppleReleaseContaminationError, "compilation is disabled"
            ):
                gate.verify_artifact(self.root / "reused.xcarchive", "ios")

    def test_exact_ipa_passes_and_platform_confusion_fails(self) -> None:
        app = self.make_app("ios")
        ipa = self.root / "safe.ipa"
        self.zip_tree(app, ipa, "Payload/Runner.app/")
        gate.verify_artifact(ipa, "ios")
        with self.assertRaisesRegex(
            gate.AppleReleaseContaminationError, "platform does not match"
        ):
            gate.verify_artifact(ipa, "macos")

    def test_current_process_environment_cannot_change_artifact_verdict(self) -> None:
        app = self.make_app("ios")
        ipa = self.root / "safe-with-dirty-environment.ipa"
        self.zip_tree(app, ipa, "Payload/Runner.app/")
        with mock.patch.dict(
            "os.environ",
            {
                "WINS_APPLE_LIVE_TUNNEL_SMOKE": "1",
                "WINS_IOS_LIVE_TUNNEL_SMOKE": "1",
                "WINS_APPLE_LIVE_TUNNEL_SMOKE_PIN": "947261",
            },
            clear=True,
        ):
            gate.verify_artifact(ipa, "ios")

    def test_exact_app_zip_passes(self) -> None:
        app = self.make_app("macos")
        archive = self.root / "safe.app.zip"
        self.zip_tree(app, archive, "Win's VPN.app/")
        gate.verify_artifact(archive, "macos")

    def test_pkg_path_uses_expanded_exact_payload(self) -> None:
        app = self.make_app("macos")
        package = self.root / "safe.pkg"
        package.write_bytes(b"synthetic-pkg")
        with mock.patch.object(gate, "_expand_pkg", return_value=app) as expand:
            gate.verify_artifact(package, "macos")
        expand.assert_called_once()

    def test_missing_or_duplicate_aot_payload_fails_closed(self) -> None:
        app = self.make_app("ios")
        (app / "Frameworks/App.framework/App").unlink()
        with self.assertRaisesRegex(
            gate.AppleReleaseContaminationError, "exactly one non-empty"
        ):
            gate.verify_app_bundle(app, "ios")

    def write_xcconfig(self, *defines: str) -> pathlib.Path:
        path = self.root / "Generated.xcconfig"
        encoded = [
            base64.b64encode(value.encode("utf-8")).decode("ascii")
            for value in defines
        ]
        path.write_text("DART_DEFINES=" + ",".join(encoded) + "\n", encoding="utf-8")
        return path

    def test_generated_build_metadata_allows_unrelated_defines(self) -> None:
        gate.verify_dart_defines_xcconfig(
            self.write_xcconfig("WINS_WINN3_ENABLED_PLATFORMS=ios")
        )

    def test_generated_build_metadata_allows_the_relay_release_define(self) -> None:
        # The ciphertext relay define is a release capability, not smoke contamination.
        for platform in ("ios", "macos"):
            with self.subTest(platform=platform):
                gate.verify_dart_defines_xcconfig(
                    self.write_xcconfig(
                        f"WINS_WINN3_ENABLED_PLATFORMS={platform}",
                        f"WINS_WINN3_RELAY_ENABLED_PLATFORMS={platform}",
                    )
                )

    def test_generated_build_metadata_rejects_external_payment_links(self) -> None:
        for value in ("true", "TRUE", "1"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    gate.AppleReleaseContaminationError,
                    "external payment links",
                ):
                    gate.verify_dart_defines_xcconfig(
                        self.write_xcconfig(f"WINS_ENABLE_EXTERNAL_PAYMENT_LINKS={value}")
                    )
        gate.verify_dart_defines_xcconfig(
            self.write_xcconfig("WINS_ENABLE_EXTERNAL_PAYMENT_LINKS=false")
        )

    def test_generated_build_metadata_without_dart_defines_is_clean(self) -> None:
        path = self.root / "Generated.xcconfig"
        path.write_text("FLUTTER_BUILD_MODE=release\n", encoding="utf-8")
        gate.verify_dart_defines_xcconfig(path)

    def test_generated_build_metadata_rejects_live_smoke_and_pin_without_echo(self) -> None:
        secret = "947261"
        for define in (
            "WINS_APPLE_LIVE_TUNNEL_SMOKE=true",
            f"WINS_APPLE_LIVE_TUNNEL_SMOKE_PIN={secret}",
            "WINS_IOS_LIVE_TUNNEL_SMOKE=1",
        ):
            with self.subTest(define=define):
                with self.assertRaises(gate.AppleReleaseContaminationError) as raised:
                    gate.verify_dart_defines_xcconfig(self.write_xcconfig(define))
                self.assertNotIn(secret, str(raised.exception))

    def test_generated_build_metadata_fails_closed_on_missing_or_invalid_values(self) -> None:
        with self.assertRaises(gate.AppleReleaseContaminationError):
            gate.verify_dart_defines_xcconfig(self.root / "missing.xcconfig")
        invalid = self.root / "invalid.xcconfig"
        invalid.write_text("DART_DEFINES=not-base64!\n", encoding="utf-8")
        with self.assertRaises(gate.AppleReleaseContaminationError):
            gate.verify_dart_defines_xcconfig(invalid)


class AppleReleaseContaminationIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runtime = (ROOT / "tools/apple_runtime_smoke.sh").read_text(encoding="utf-8")
        cls.uploader = (
            ROOT / "tools/apple_upload_exact_release_candidates.py"
        ).read_text(encoding="utf-8")
        cls.cross_store = (
            ROOT / "tools/apple_cross_store_artifact_gate.py"
        ).read_text(encoding="utf-8")

    def test_both_archive_producer_branches_stamp_release_metadata(self) -> None:
        # No archive generates its Info.plist: on iOS Xcode would replace the
        # "Win's VPN" CFBundleName with PRODUCT_NAME, and on macOS it drops
        # the version keys (MARKETING_VERSION is unset). Both host plists read
        # the markers and the Flutter build name and number themselves.
        self.assertEqual(self.runtime.count("GENERATE_INFOPLIST_FILE=YES"), 0)
        macos_plist = (ROOT / "macos/Runner/Info.plist").read_text(encoding="utf-8")
        for key, value in (
            ("CFBundleShortVersionString", "$(FLUTTER_BUILD_NAME)"),
            ("CFBundleVersion", "$(FLUTTER_BUILD_NUMBER)"),
            ("WinsReleaseContaminationContract", "$(INFOPLIST_KEY_WinsReleaseContaminationContract)"),
            ("WinsReleaseLiveSmokeCompiled", "$(INFOPLIST_KEY_WinsReleaseLiveSmokeCompiled)"),
            ("WinsReleaseSmokePinEmbedded", "$(INFOPLIST_KEY_WinsReleaseSmokePinEmbedded)"),
        ):
            self.assertIn(f"<key>{key}</key>\n\t<string>{value}</string>", macos_plist)
        ios_archive = self.runtime.split("create_signed_ios_archive() {", 1)[1]
        ios_archive = ios_archive.split("\n}\n", 1)[0]
        self.assertNotIn("GENERATE_INFOPLIST_FILE=YES", ios_archive)
        self.assertIn(
            "INFOPLIST_KEY_WinsReleaseContaminationContract=apple-release-no-live-smoke-v1",
            ios_archive,
        )
        ios_plist = (ROOT / "ios/Runner/Info.plist").read_text(encoding="utf-8")
        for key in (
            "WinsReleaseContaminationContract",
            "WinsReleaseLiveSmokeCompiled",
            "WinsReleaseSmokePinEmbedded",
        ):
            self.assertIn(
                f"<key>{key}</key>\n\t<string>$(INFOPLIST_KEY_{key})</string>",
                ios_plist,
            )
        self.assertGreaterEqual(
            self.runtime.count(
                "INFOPLIST_KEY_WinsReleaseContaminationContract=apple-release-no-live-smoke-v1"
            ),
            3,
        )
        self.assertGreaterEqual(
            self.runtime.count("INFOPLIST_KEY_WinsReleaseLiveSmokeCompiled=NO"), 3
        )
        self.assertGreaterEqual(
            self.runtime.count("INFOPLIST_KEY_WinsReleaseSmokePinEmbedded=NO"), 3
        )
        self.assertIn(
            "verify_apple_release_dart_defines ios/Flutter/Generated.xcconfig",
            self.runtime,
        )
        self.assertIn(
            "verify_apple_release_dart_defines macos/Flutter/ephemeral/Flutter-Generated.xcconfig",
            self.runtime,
        )

    def test_upload_only_lanes_reinspect_exact_archive(self) -> None:
        self.assertGreaterEqual(
            self.runtime.count(
                'verify_apple_release_contamination ios "${archive_path}"'
            ),
            3,
        )
        self.assertGreaterEqual(
            self.runtime.count(
                'verify_apple_release_contamination macos "${archive_path}"'
            ),
            2,
        )

    def test_exported_ipa_pkg_and_app_paths_are_bound(self) -> None:
        self.assertIn(
            'verify_apple_release_contamination ios "${ipa_path}"', self.runtime
        )
        self.assertIn(
            'verify_apple_release_contamination macos "${pkg_path}"', self.runtime
        )
        self.assertIn(
            'verify_apple_release_contamination macos "${app_path}"', self.runtime
        )

    def test_exact_uploader_and_cross_store_gate_call_artifact_validator(self) -> None:
        self.assertIn("contamination_reader(", self.uploader)
        self.assertIn("contamination_reader(artifact_path, platform)", self.uploader)
        self.assertIn("verify_release_contamination(app, platform)", self.cross_store)


if __name__ == "__main__":
    unittest.main()
