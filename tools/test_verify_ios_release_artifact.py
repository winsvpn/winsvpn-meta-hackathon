#!/usr/bin/env python3
"""Hostile tests for the produced iOS release-artifact verifier."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import pathlib
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import verify_ios_release_artifact as verifier  # noqa: E402


APP_UUID = "11111111-1111-1111-1111-111111111111"
EXTENSION_UUID = "22222222-2222-2222-2222-222222222222"
OTHER_UUID = "33333333-3333-3333-3333-333333333333"
WATCH_UUID = "44444444-4444-4444-4444-444444444444"


class FakeNativeTools:
    def __init__(self) -> None:
        self.get_task_allow = False
        self.development_profile = False
        self.application_identifier_suffix = ""
        self.archive_extension_uuid = EXTENSION_UUID
        self.missing_winn3_symbol = ""
        self.invalid_watch_signature = False
        self.invalid_watch_identity = False
        self.watch_application_identifier_suffix = ""
        self.watch_profile_identifier_suffix = ""
        self.watch_development_profile = False
        # The xcarchive is development-signed (Xcode 27 automatic signing); the
        # exported IPA is the distribution-signed artifact.
        self.archive_authority = "Apple Development: Win's VPN Test"
        self.archive_extra_entitlements: dict[str, object] = {}
        self.watch_profile_wildcard = False

    @staticmethod
    def _is_archive(path: str) -> bool:
        return ".xcarchive" in path

    @staticmethod
    def _is_extension(path: str) -> bool:
        return "PacketTunnel" in path

    @staticmethod
    def _is_watch(path: str) -> bool:
        return "WinsWatch" in path or "/Watch/" in path

    def _entitlements(self, path: str) -> dict[str, object]:
        if self._is_extension(path):
            bundle_id = verifier.EXPECTED_EXTENSION_BUNDLE_ID
        elif self._is_watch(path):
            bundle_id = verifier.EXPECTED_WATCH_BUNDLE_ID
        else:
            bundle_id = verifier.EXPECTED_APP_BUNDLE_ID
        suffix = (
            self.watch_application_identifier_suffix
            if self._is_watch(path)
            else self.application_identifier_suffix
        )
        get_task_allow = True if self._is_archive(path) else self.get_task_allow
        archive_extra = self.archive_extra_entitlements if self._is_archive(path) else {}
        if self._is_watch(path):
            return {
                "application-identifier": f"{verifier.EXPECTED_TEAM_ID}.{bundle_id}{suffix}",
                "com.apple.developer.team-identifier": verifier.EXPECTED_TEAM_ID,
                "get-task-allow": get_task_allow,
                **getattr(self, "watch_extra_entitlements", {}),
                **archive_extra,
            }
        return {
            "application-identifier": (
                f"{verifier.EXPECTED_TEAM_ID}.{bundle_id}"
                + suffix
            ),
            "com.apple.developer.team-identifier": verifier.EXPECTED_TEAM_ID,
            "com.apple.developer.networking.networkextension": [
                "packet-tunnel-provider"
            ],
            "com.apple.security.application-groups": [verifier.EXPECTED_APP_GROUP],
            "keychain-access-groups": [
                f"{verifier.EXPECTED_TEAM_ID}.{verifier.EXPECTED_KEYCHAIN_SUFFIX}"
            ],
            "get-task-allow": get_task_allow,
            **archive_extra,
        }

    def _profile(self, path: str) -> dict[str, object]:
        entitlements = self._entitlements(path)
        if self._is_watch(path) and (self._is_archive(path) or self.watch_profile_wildcard):
            # Xcode signs the development Watch app with the team wildcard profile.
            entitlements["application-identifier"] = f"{verifier.EXPECTED_TEAM_ID}.*"
        if self._is_watch(path) and self.watch_profile_identifier_suffix:
            entitlements["application-identifier"] = (
                str(entitlements["application-identifier"])
                + self.watch_profile_identifier_suffix
            )
        if not self._is_archive(path):
            entitlements["beta-reports-active"] = True
        profile: dict[str, object] = {
            "ApplicationIdentifierPrefix": [verifier.EXPECTED_TEAM_ID],
            "TeamIdentifier": [verifier.EXPECTED_TEAM_ID],
            "ExpirationDate": dt.datetime(2035, 1, 1),
            "Entitlements": entitlements,
        }
        if (
            self._is_archive(path)
            or self.development_profile
            or (self._is_watch(path) and self.watch_development_profile)
        ):
            profile["ProvisionedDevices"] = ["device-udid"]
        return profile

    def __call__(self, arguments: object) -> subprocess.CompletedProcess[bytes]:
        args = [str(value) for value in arguments]
        command = pathlib.Path(args[0]).name
        stdout = b""
        stderr = b""
        returncode = 0
        if command == "codesign":
            target = args[-1]
            if "--verify" in args and self.invalid_watch_signature and self._is_watch(target):
                returncode = 1
                stderr = b"invalid Watch signature"
            elif "--entitlements" in args:
                stdout = plistlib.dumps(self._entitlements(target))
            elif "--display" in args:
                if self._is_archive(target):
                    authority = self.archive_authority
                elif self.invalid_watch_identity and self._is_watch(target):
                    authority = "Apple Development: Invalid Watch Test"
                else:
                    authority = "Apple Distribution: Win's VPN Test"
                stderr = (
                    "Executable=/fixture\n"
                    f"Authority={authority}\n"
                    f"TeamIdentifier={verifier.EXPECTED_TEAM_ID}\n"
                ).encode("ascii")
        elif command == "security":
            stdout = plistlib.dumps(self._profile(args[-1]))
        elif command == "xcrun":
            tool = args[1]
            target = args[-1]
            if tool == "vtool":
                if self._is_watch(target):
                    # vtool prints one section per slice of a universal binary.
                    slices = getattr(
                        self, "watch_slices", dict(verifier.EXPECTED_MINIMUM_WATCHOS_BY_ARCH)
                    )
                    if slices is None:
                        stdout = (
                            "Load command 10\n      cmd LC_BUILD_VERSION\n"
                            f" platform WATCHOS\n    minos {verifier.EXPECTED_MINIMUM_WATCHOS}\n"
                        ).encode("ascii")
                    else:
                        # A None minimum models a slice without LC_BUILD_VERSION.
                        stdout = "".join(
                            f"{target} (architecture {arch}):\n"
                            + (
                                ""
                                if minimum is None
                                else "Load command 10\n      cmd LC_BUILD_VERSION\n"
                                f" platform WATCHOS\n    minos {minimum}\n      sdk 27.0\n"
                            )
                            for arch, minimum in slices.items()
                        ).encode("ascii")
                else:
                    stdout = (
                        "Load command 10\n"
                        "      cmd LC_BUILD_VERSION\n"
                        " platform IOS\n"
                        f"    minos {verifier.EXPECTED_MINIMUM_IOS}\n"
                        "      sdk 26.0\n"
                    ).encode("ascii")
            elif tool == "nm":
                symbols = sorted(verifier.REQUIRED_WINN3_SYMBOLS)
                if self.missing_winn3_symbol:
                    symbols.remove(self.missing_winn3_symbol)
                stdout = "".join(
                    f"0000000000000000 T _{symbol}\n" for symbol in symbols
                ).encode("ascii")
            elif tool == "dwarfdump":
                if self._is_extension(target):
                    uuid = (
                        self.archive_extension_uuid
                        if ".xcarchive" in target
                        else EXTENSION_UUID
                    )
                elif self._is_watch(target):
                    uuid = WATCH_UUID
                else:
                    uuid = APP_UUID
                stdout = f"UUID: {uuid} (arm64) {target}\n".encode("ascii")
            else:
                returncode = 1
                stderr = f"unexpected xcrun tool: {tool}".encode("ascii")
        elif command.startswith("python"):
            if not any(
                name in " ".join(args)
                for name in (
                    "release_obfuscation_contract.py",
                    "apple_release_symbol_custody.py",
                )
            ):
                returncode = 1
                stderr = b"unexpected Python verification command"
        else:
            returncode = 1
            stderr = f"unexpected command: {args!r}".encode("ascii")
        return subprocess.CompletedProcess(args, returncode, stdout, stderr)


class ReleaseFixture:
    def __init__(self, root: pathlib.Path) -> None:
        self.root = root
        self.payload_root = root / "ipa-root"
        self.app = self.payload_root / "Payload/Runner.app"
        self.archive = root / "Runner.xcarchive"
        self.ipa = root / "WinsVPN.ipa"
        self.obfuscation_receipt = pathlib.Path()
        self.symbol_receipt = pathlib.Path()
        self._make_app(self.app)
        archive_app = self.archive / "Products/Applications/Runner.app"
        shutil.copytree(self.app, archive_app)
        self._make_archive_metadata()
        self._make_dsyms()
        self.rebuild_ipa()
        self.rebuild_receipts()

    @staticmethod
    def _write_plist(path: pathlib.Path, value: dict[str, object]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as handle:
            plistlib.dump(value, handle)

    def _make_app(self, app: pathlib.Path) -> None:
        extension = app / "PlugIns/PacketTunnel.appex"
        extension.mkdir(parents=True)
        watch = app / "Watch/WinsWatch.app"
        watch.mkdir(parents=True)
        self._write_plist(
            app / "Info.plist",
            {
                "CFBundleIdentifier": verifier.EXPECTED_APP_BUNDLE_ID,
                "CFBundlePackageType": "APPL",
                "CFBundleExecutable": "Runner",
                "CFBundleDisplayName": "Win's VPN",
                "CFBundleName": "Win's VPN",
                "CFBundleShortVersionString": "1.0.15",
                "CFBundleVersion": "30",
                "MinimumOSVersion": verifier.EXPECTED_MINIMUM_IOS,
            },
        )
        self._write_plist(
            extension / "Info.plist",
            {
                "CFBundleIdentifier": verifier.EXPECTED_EXTENSION_BUNDLE_ID,
                "CFBundlePackageType": "XPC!",
                "CFBundleDisplayName": "Win's VPN Helper",
                "CFBundleName": "Win's VPN Helper",
                "CFBundleExecutable": "PacketTunnel",
                "CFBundleShortVersionString": "1.0.15",
                "CFBundleVersion": "30",
                "MinimumOSVersion": verifier.EXPECTED_MINIMUM_IOS,
                "WinsReleaseArtifactVerifierContract": verifier.ARTIFACT_CONTRACT,
                "NSExtension": {
                    "NSExtensionPointIdentifier": "com.apple.networkextension.packet-tunnel",
                    "NSExtensionPrincipalClass": "PacketTunnel.PacketTunnelProvider",
                },
            },
        )
        self._write_plist(
            watch / "Info.plist",
            {
                "CFBundleIdentifier": verifier.EXPECTED_WATCH_BUNDLE_ID,
                "CFBundlePackageType": "APPL",
                "CFBundleDisplayName": "Win's VPN",
                "CFBundleName": "Win's VPN",
                "CFBundleExecutable": verifier.EXPECTED_WATCH_EXECUTABLE,
                "CFBundleShortVersionString": "1.0.15",
                "CFBundleVersion": "30",
                "WKApplication": True,
                "WKCompanionAppBundleIdentifier": verifier.EXPECTED_APP_BUNDLE_ID,
                "WKRunsIndependentlyOfCompanionApp": False,
            },
        )
        shutil.copyfile(
            ROOT / "ios/Runner/PrivacyInfo.xcprivacy",
            app / "PrivacyInfo.xcprivacy",
        )
        shutil.copyfile(
            ROOT / "ios/PacketTunnel/PrivacyInfo.xcprivacy",
            extension / "PrivacyInfo.xcprivacy",
        )
        shutil.copyfile(
            ROOT / "ios/WinsWatch Watch App/PrivacyInfo.xcprivacy",
            watch / "PrivacyInfo.xcprivacy",
        )
        (app / "Runner").write_bytes(b"host-mach-o")
        extension_binary = b"extension-mach-o\x00" + b"\x00".join(
            verifier.REQUIRED_WINN3_BINARY_MARKERS
        )
        (extension / "PacketTunnel").write_bytes(extension_binary)
        (watch / verifier.EXPECTED_WATCH_EXECUTABLE).write_bytes(b"watch-mach-o")
        (app / "embedded.mobileprovision").write_bytes(b"host-profile")
        (extension / "embedded.mobileprovision").write_bytes(b"extension-profile")
        (watch / "embedded.mobileprovision").write_bytes(b"watch-profile")

    def _make_archive_metadata(self) -> None:
        self._write_plist(
            self.archive / "Info.plist",
            {
                "ArchiveVersion": 2,
                "Name": "Runner",
                "SchemeName": "Runner",
                "ApplicationProperties": {
                    "ApplicationPath": "Applications/Runner.app",
                    "CFBundleIdentifier": verifier.EXPECTED_APP_BUNDLE_ID,
                    "CFBundleShortVersionString": "1.0.15",
                    "CFBundleVersion": "30",
                    "SigningIdentity": "Apple Development: Win's VPN Test",
                    "Team": verifier.EXPECTED_TEAM_ID,
                },
            },
        )

    def _make_dsyms(self) -> None:
        records = {
            "Runner.app.dSYM/Contents/Resources/DWARF/Runner": b"host-dwarf" * 16,
            "PacketTunnel.appex.dSYM/Contents/Resources/DWARF/PacketTunnel": b"extension-dwarf"
            * 16,
            "WinsWatch.app.dSYM/Contents/Resources/DWARF/WinsWatch": b"watch-dwarf" * 16,
        }
        for relative, data in records.items():
            path = self.archive / "dSYMs" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)

    def rebuild_ipa(self) -> None:
        if self.ipa.exists():
            self.ipa.unlink()
        with zipfile.ZipFile(self.ipa, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(self.payload_root.rglob("*")):
                archive.write(path, path.relative_to(self.payload_root).as_posix())

    def rebuild_receipts(self) -> None:
        ipa_sha = verifier._sha256_file(self.ipa)
        ipa_size = self.ipa.stat().st_size
        obfuscation_dir = (
            self.root / "private-release-symbols/apple/ios/1.0.15+30"
        )
        obfuscation_dir.mkdir(parents=True, exist_ok=True)
        symbol = obfuscation_dir / "app.ios-arm64.symbols"
        symbol.write_bytes(b"flutter-symbols" * 16)
        self.obfuscation_receipt = obfuscation_dir / "manifest.json"
        obfuscation_payload = {
            "schema_version": 2,
            "contract": verifier.OBFUSCATION_CONTRACT,
            "contract_sha256": verifier._sha256_file(
                ROOT / "tools/release_obfuscation_contract.py"
            ),
            "platform": "ios",
            "app_version": "1.0.15",
            "build_number": "30",
            "created_at_utc": "2030-01-01T00:00:00+00:00",
            "private_symbols_not_packaged": True,
            "verification": verifier.EXPECTED_OBFUSCATION_VERIFICATION,
            "artifacts": [
                {
                    "path": verifier._artifact_record_path(self.ipa),
                    "size": ipa_size,
                    "sha256": ipa_sha,
                }
            ],
            "symbols": verifier._inventory(obfuscation_dir),
        }
        self.obfuscation_receipt.write_text(
            json.dumps(obfuscation_payload, indent=2, sort_keys=True) + "\n",
            encoding="ascii",
        )

        custody_dir = (
            self.root
            / "private-release-symbols/apple/artifact-custody/ios/1.0.15+30"
            / ipa_sha
        )
        flutter = custody_dir / "flutter"
        dsyms = custody_dir / "dSYMs"
        flutter.mkdir(parents=True, exist_ok=True)
        dsyms.mkdir(parents=True, exist_ok=True)
        (flutter / "app.ios-arm64.symbols").write_bytes(b"flutter-symbols" * 16)
        for source in sorted((self.archive / "dSYMs").rglob("*")):
            if source.is_file():
                destination = dsyms / source.relative_to(self.archive / "dSYMs")
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
        self.symbol_receipt = custody_dir / "manifest.json"
        custody_payload = {
            "schema_version": 1,
            "contract": verifier.SYMBOL_CUSTODY_CONTRACT,
            "platform": "ios",
            "app_version": "1.0.15",
            "build_number": "30",
            "created_at_utc": "2030-01-01T00:00:00+00:00",
            "private_symbols_not_packaged": True,
            "artifact": {
                "filename": self.ipa.name,
                "size": ipa_size,
                "sha256": ipa_sha,
            },
            "flutter_symbols": verifier._inventory(flutter),
            "xcarchive_dsyms": verifier._inventory(dsyms),
        }
        self.symbol_receipt.write_text(
            json.dumps(custody_payload, indent=2, sort_keys=True) + "\n",
            encoding="ascii",
        )

    def verify(self, tools: FakeNativeTools | None = None) -> None:
        verifier.verify_release_pair(
            self.ipa,
            self.archive,
            self.obfuscation_receipt,
            self.symbol_receipt,
            tools or FakeNativeTools(),
        )


class IOSReleaseArtifactVerifierTests(unittest.TestCase):
    def fixture(self, root: pathlib.Path) -> ReleaseFixture:
        return ReleaseFixture(root)

    def test_exact_archive_ipa_and_receipts_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            self.fixture(pathlib.Path(temporary)).verify()

    def test_source_release_configuration_is_fail_closed(self) -> None:
        project = (ROOT / "ios/Runner.xcodeproj/project.pbxproj").read_text(
            encoding="utf-8"
        )
        for identifier in (
            "97C147041CF9000F007C117D",
            "97C147071CF9000F007C117D",
            "A10000000000000000000011",
        ):
            match = re.search(
                rf"{identifier} /\* Release \*/ = \{{(.*?)\n\t\t\}};",
                project,
                re.DOTALL,
            )
            self.assertIsNotNone(match, identifier)
            block = match.group(1)
            # Xcode 27 refuses to archive with Apple Distribution under automatic
            # signing, so the archive is signed for development and the App Store
            # export re-signs it; the exported IPA must carry Apple Distribution.
            self.assertIn(
                '"CODE_SIGN_IDENTITY[sdk=iphoneos*]" = "Apple Development";',
                block,
            )
            self.assertNotIn("iPhone Developer", block)
            self.assertIn("IPHONEOS_DEPLOYMENT_TARGET = 15.0;", block)
            self.assertIn("STRIP_STYLE = all;", block)
            self.assertIn('DEBUG_INFORMATION_FORMAT = "dwarf-with-dsym";', block)
            self.assertIn("VALIDATE_PRODUCT = YES;", block)
            self.assertIn("ENABLE_CODE_COVERAGE = NO;", block)
            self.assertIn("ENABLE_DEBUG_DYLIB = NO;", block)
            self.assertIn("GCC_GENERATE_TEST_COVERAGE_FILES = NO;", block)
            self.assertIn("GCC_INSTRUMENT_PROGRAM_FLOW_ARCS = NO;", block)
            self.assertIn("GENERATE_PROFILING_CODE = NO;", block)
        packet_release = re.search(
            r"A10000000000000000000011 /\* Release \*/ = \{(.*?)\n\t\t\};",
            project,
            re.DOTALL,
        ).group(1)
        self.assertIn("-Wl,-force_load,$(WINN3_DATAPATH_ARCHIVE)", packet_release)
        self.assertIn("-Wl,-u,_WinnTunnelCreateWinn3", packet_release)
        runner_release = re.search(
            r"97C147071CF9000F007C117D /\* Release \*/ = \{(.*?)\n\t\t\};",
            project,
            re.DOTALL,
        ).group(1)
        self.assertIn("DART_OBFUSCATION = true;", runner_release)
        self.assertIn('EXTRA_GEN_SNAPSHOT_OPTIONS = "--strip";', runner_release)
        self.assertIn(
            'SPLIT_DEBUG_INFO = "$(PROJECT_DIR)/../.artifacts/private-release-symbols/'
            'apple/ios/$(FLUTTER_BUILD_NAME)+$(FLUTTER_BUILD_NUMBER)";',
            runner_release,
        )

        for path in (
            ROOT / "ios/Runner/Info.plist",
            ROOT / "ios/PacketTunnel/Info.plist",
        ):
            info = verifier._load_plist(path, str(path))
            self.assertEqual(info["MinimumOSVersion"], verifier.EXPECTED_MINIMUM_IOS)
        packet_info = verifier._load_plist(
            ROOT / "ios/PacketTunnel/Info.plist", "PacketTunnel source Info.plist"
        )
        self.assertEqual(
            packet_info["WinsReleaseArtifactVerifierContract"],
            verifier.ARTIFACT_CONTRACT,
        )
        for path in (
            ROOT / "ios/Runner/Runner.entitlements",
            ROOT / "ios/PacketTunnel/PacketTunnel.entitlements",
        ):
            entitlements = verifier._load_plist(path, str(path))
            verifier._reject_debug_entitlements(entitlements, str(path))
            self.assertEqual(
                entitlements["com.apple.developer.networking.networkextension"],
                ["packet-tunnel-provider"],
            )

    def test_debug_entitlement_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            tools = FakeNativeTools()
            tools.get_task_allow = True
            with self.assertRaisesRegex(verifier.VerificationError, "forbidden debug"):
                fixture.verify(tools)

    def test_development_profile_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            tools = FakeNativeTools()
            tools.development_profile = True
            with self.assertRaisesRegex(verifier.VerificationError, "development or ad hoc"):
                fixture.verify(tools)

    def test_application_identifier_suffix_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            tools = FakeNativeTools()
            tools.application_identifier_suffix = ".other"
            with self.assertRaisesRegex(verifier.VerificationError, "application-identifier"):
                fixture.verify(tools)

    def test_watch_slices_need_their_exact_reviewed_minimums(self) -> None:
        for slices, message in (
            ({"arm64_32": "9.0", "arm64": "9.0"}, r"for arm64\b"),
            ({"arm64_32": "26.0", "arm64": "26.0"}, "for arm64_32"),
            ({"arm64_32": "9.0", "armv7k": "9.0"}, "unreviewed architecture"),
            ({"arm64_32": "9.0"}, "expected exactly"),
            ({"arm64": "26.0"}, "expected exactly"),
            ({"arm64_32": "9.0", "arm64": None}, "slice 'arm64' has no LC_BUILD_VERSION"),
            (None, "unreviewed architecture"),
        ):
            with self.subTest(slices=slices):
                with tempfile.TemporaryDirectory() as temporary:
                    fixture = self.fixture(pathlib.Path(temporary))
                    tools = FakeNativeTools()
                    tools.watch_slices = slices
                    with self.assertRaisesRegex(verifier.VerificationError, message):
                        fixture.verify(tools)

    def test_watch_app_store_signing_flag_passes_and_other_extras_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            tools = FakeNativeTools()
            tools.watch_extra_entitlements = {"beta-reports-active": True}
            fixture.verify(tools)
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            tools = FakeNativeTools()
            tools.watch_extra_entitlements = {
                "beta-reports-active": True,
                "com.apple.security.application-groups": [verifier.EXPECTED_APP_GROUP],
            }
            with self.assertRaisesRegex(verifier.VerificationError, "unexpected entitlements"):
                fixture.verify(tools)

    def test_missing_watch_profile_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            (fixture.app / "Watch/WinsWatch.app/embedded.mobileprovision").unlink()
            fixture.rebuild_ipa()
            with self.assertRaisesRegex(verifier.VerificationError, "Watch embedded.mobileprovision"):
                fixture.verify()

    def test_watch_application_identifier_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            tools = FakeNativeTools()
            tools.watch_application_identifier_suffix = ".other"
            with self.assertRaisesRegex(verifier.VerificationError, "Watch application-identifier"):
                fixture.verify(tools)

    def test_watch_profile_application_identifier_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            tools = FakeNativeTools()
            tools.watch_profile_identifier_suffix = ".other"
            with self.assertRaisesRegex(
                verifier.VerificationError,
                "Watch profile does not authorize application-identifier",
            ):
                fixture.verify(tools)

    def test_watch_development_profile_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            tools = FakeNativeTools()
            tools.watch_development_profile = True
            with self.assertRaisesRegex(
                verifier.VerificationError, "Watch uses a development or ad hoc"
            ):
                fixture.verify(tools)

    def test_invalid_watch_signature_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            tools = FakeNativeTools()
            tools.invalid_watch_signature = True
            with self.assertRaisesRegex(verifier.VerificationError, "Watch signature verification"):
                fixture.verify(tools)

    def test_invalid_watch_distribution_identity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            tools = FakeNativeTools()
            tools.invalid_watch_identity = True
            with self.assertRaisesRegex(
                verifier.VerificationError, "Watch is not signed by Apple Distribution"
            ):
                fixture.verify(tools)

    def test_watch_version_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            path = fixture.app / "Watch/WinsWatch.app/Info.plist"
            info = verifier._load_plist(path, "fixture Watch Info.plist")
            info["CFBundleVersion"] = "31"
            fixture._write_plist(path, info)
            fixture.rebuild_ipa()
            with self.assertRaisesRegex(verifier.VerificationError, "Watch build"):
                fixture.verify()

    def test_built_bundle_names_must_be_wins_vpn(self) -> None:
        # Owner ruling 2026-10-25: "Calculator" was refused with ITMS-90129; the host and
        # Watch apps are "Win's VPN" and the extension "Win's VPN Helper" in the built IPA.
        for relative, subject in (
            ("Info.plist", "host"),
            ("Watch/WinsWatch.app/Info.plist", "Watch"),
            ("PlugIns/PacketTunnel.appex/Info.plist", "PacketTunnel"),
        ):
            for key in ("CFBundleDisplayName", "CFBundleName"):
                for wrong in ("Calculator", "WinsWatch"):
                    with self.subTest(bundle=subject, key=key, value=wrong):
                        with tempfile.TemporaryDirectory() as temporary:
                            fixture = self.fixture(pathlib.Path(temporary))
                            path = fixture.app / relative
                            info = verifier._load_plist(path, "fixture Info.plist")
                            info[key] = wrong
                            fixture._write_plist(path, info)
                            fixture.rebuild_ipa()
                            with self.assertRaisesRegex(
                                verifier.VerificationError, rf"{subject} {key}="
                            ):
                                fixture.verify()

    def test_ipa_member_other_users_cannot_read_is_rejected(self) -> None:
        # App Store Connect error 90255: the rejected 1.0.16 (33) uploads carried 600 files
        # and a 700 Payload/ directory. A 744 directory cannot be searched by others either.
        for relative, mode in (
            ("Payload/Runner.app/embedded.mobileprovision", 0o600),
            ("Payload/Runner.app/_CodeSignature/", 0o744),
            ("Payload/", 0o700),
        ):
            with self.subTest(member=relative, mode=oct(mode)):
                with tempfile.TemporaryDirectory() as temporary:
                    fixture = self.fixture(pathlib.Path(temporary))
                    rebuilt = fixture.ipa.with_suffix(".rebuilt.ipa")
                    with zipfile.ZipFile(fixture.ipa) as source, zipfile.ZipFile(
                        rebuilt, "w", compression=zipfile.ZIP_DEFLATED
                    ) as target:
                        names = {info.filename for info in source.infolist()}
                        for info in source.infolist():
                            data = b"" if info.is_dir() else source.read(info)
                            target.writestr(info, data)
                        if relative not in names:
                            info = zipfile.ZipInfo(relative)
                            info.create_system = 3
                            info.external_attr = 0o040755 << 16
                            target.writestr(info, b"")
                    with zipfile.ZipFile(rebuilt) as source, zipfile.ZipFile(
                        fixture.ipa, "w", compression=zipfile.ZIP_DEFLATED
                    ) as target:
                        for info in source.infolist():
                            data = b"" if info.is_dir() else source.read(info)
                            if info.filename == relative:
                                kind = 0o040000 if info.is_dir() else 0o100000
                                info.external_attr = (kind | mode) << 16
                            target.writestr(info, data)
                    with self.assertRaisesRegex(
                        verifier.VerificationError, "not readable by all users"
                    ):
                        fixture.verify()

    def test_watch_privacy_manifest_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            path = fixture.app / "Watch/WinsWatch.app/PrivacyInfo.xcprivacy"
            privacy = verifier._load_plist(path, "fixture Watch privacy")
            privacy["NSPrivacyTracking"] = True
            fixture._write_plist(path, privacy)
            fixture.rebuild_ipa()
            with self.assertRaisesRegex(verifier.VerificationError, "Watch privacy manifest"):
                fixture.verify()

    def test_missing_privacy_manifest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            (fixture.app / "PlugIns/PacketTunnel.appex/PrivacyInfo.xcprivacy").unlink()
            fixture.rebuild_ipa()
            with self.assertRaisesRegex(verifier.VerificationError, "PrivacyInfo"):
                fixture.verify()

    def test_wrong_deployment_target_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            info_path = fixture.app / "Info.plist"
            info = verifier._load_plist(info_path, "fixture")
            info["MinimumOSVersion"] = "14.0"
            fixture._write_plist(info_path, info)
            fixture.rebuild_ipa()
            with self.assertRaisesRegex(verifier.VerificationError, "MinimumOSVersion"):
                fixture.verify()

    def test_missing_v3_primary_symbol_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            tools = FakeNativeTools()
            tools.missing_winn3_symbol = "WinnTunnelCreateWinn3"
            with self.assertRaisesRegex(verifier.VerificationError, "v3-primary"):
                fixture.verify(tools)

    def test_missing_v3_primary_binary_marker_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            binary = fixture.app / "PlugIns/PacketTunnel.appex/PacketTunnel"
            binary.write_bytes(b"no-v3-markers")
            fixture.rebuild_ipa()
            with self.assertRaisesRegex(verifier.VerificationError, "v3-primary"):
                fixture.verify()

    def test_extra_or_miscontained_app_extension_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            other = fixture.app / "Other.appex"
            other.mkdir()
            fixture.rebuild_ipa()
            with self.assertRaisesRegex(verifier.VerificationError, "exactly PlugIns"):
                fixture.verify()

    def test_regular_file_disguised_as_app_extension_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            (fixture.app / "PlugIns/Other.appex").write_bytes(b"not-an-extension")
            fixture.rebuild_ipa()
            with self.assertRaisesRegex(verifier.VerificationError, "exactly PlugIns"):
                fixture.verify()

    def test_zip_path_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            with zipfile.ZipFile(fixture.ipa, "a") as archive:
                archive.writestr("../escape", b"escape")
            with self.assertRaisesRegex(verifier.VerificationError, "non-canonical"):
                fixture.verify()

    def test_case_colliding_zip_members_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            with zipfile.ZipFile(fixture.ipa, "a") as archive:
                archive.writestr("payload/runner.app/info.plist", b"collision")
            with self.assertRaisesRegex(verifier.VerificationError, "case-colliding"):
                fixture.verify()

    def test_archive_must_be_development_signed_and_ipa_distribution_signed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            tools = FakeNativeTools()
            tools.archive_authority = "Apple Distribution: Win's VPN Test"
            with self.assertRaisesRegex(
                verifier.VerificationError, "produced xcarchive host is not signed by Apple Development"
            ):
                fixture.verify(tools)
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            fixture._write_plist(
                fixture.archive / "Info.plist",
                {
                    **verifier._load_plist(fixture.archive / "Info.plist", "fixture"),
                    "ApplicationProperties": {
                        **verifier._load_plist(fixture.archive / "Info.plist", "fixture")[
                            "ApplicationProperties"
                        ],
                        "SigningIdentity": "Apple Distribution: Win's VPN Test",
                    },
                },
            )
            with self.assertRaisesRegex(
                verifier.VerificationError, "xcarchive SigningIdentity is not Apple Development"
            ):
                fixture.verify()

    def test_ipa_watch_profile_must_name_the_watch_app_id_exactly(self) -> None:
        # The development archive passes with the wildcard Watch profile; the IPA may not.
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            tools = FakeNativeTools()
            tools.watch_profile_wildcard = True
            with self.assertRaisesRegex(
                verifier.VerificationError,
                "exported IPA Watch profile does not authorize application-identifier",
            ):
                fixture.verify(tools)

    def test_archive_allows_only_get_task_allow_beyond_release_entitlements(self) -> None:
        for extra, message in (
            ({"task_for_pid-allow": True}, "forbidden debug"),
            ({"com.apple.security.cs.debugger": True}, "forbidden debug"),
            ({"aps-environment": "development"}, "development APNs"),
        ):
            with self.subTest(extra=extra):
                with tempfile.TemporaryDirectory() as temporary:
                    fixture = self.fixture(pathlib.Path(temporary))
                    tools = FakeNativeTools()
                    tools.archive_extra_entitlements = extra
                    with self.assertRaisesRegex(verifier.VerificationError, message):
                        fixture.verify(tools)

    def test_archive_and_ipa_uuid_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            tools = FakeNativeTools()
            tools.archive_extension_uuid = OTHER_UUID
            with self.assertRaisesRegex(verifier.VerificationError, "evidence differs"):
                fixture.verify(tools)

    def test_obfuscation_receipt_hash_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            payload = json.loads(fixture.obfuscation_receipt.read_text(encoding="ascii"))
            payload["artifacts"][0]["sha256"] = "0" * 64
            fixture.obfuscation_receipt.write_text(
                json.dumps(payload, sort_keys=True), encoding="ascii"
            )
            with self.assertRaisesRegex(verifier.VerificationError, "exact IPA"):
                fixture.verify()

    def test_symbol_custody_verification_checks_the_paired_archive(self) -> None:
        # R23 A-3: the custody closure binds the xcarchive inventory, so the
        # canonical custody verifier must be handed the archive this pair check
        # verified; without --archive it never compares it.
        custody_calls: list[list[str]] = []

        class RecordingTools(FakeNativeTools):
            def __call__(self, arguments: object) -> subprocess.CompletedProcess[bytes]:
                args = [str(value) for value in arguments]
                if any(arg.endswith("apple_release_symbol_custody.py") for arg in args):
                    custody_calls.append(args)
                return super().__call__(args)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            fixture.verify(RecordingTools())
            self.assertEqual(len(custody_calls), 1)
            command = custody_calls[0]
            self.assertEqual(command[2], "verify")
            self.assertEqual(command.count("--archive"), 1)
            self.assertEqual(
                command[command.index("--archive") + 1], str(fixture.archive)
            )

    def test_missing_symbol_receipt_remains_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            fixture.symbol_receipt.unlink()
            with self.assertRaisesRegex(verifier.BlockedError, "symbol-custody receipt"):
                fixture.verify()

    @unittest.skipUnless(hasattr(os, "link"), "hardlink test requires os.link")
    def test_hardlinked_ipa_is_rejected_before_inspection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            alias = pathlib.Path(temporary) / "alias.ipa"
            os.link(fixture.ipa, alias)
            with self.assertRaisesRegex(verifier.VerificationError, "hardlink"):
                with verifier.bind_ipa(alias):
                    pass


if __name__ == "__main__":
    unittest.main()
