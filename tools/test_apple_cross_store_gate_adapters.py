#!/usr/bin/env python3
"""Focused adversarial tests for canonical Apple cross-store gate adapters."""

from __future__ import annotations

import builtins
import hashlib
import json
import os
import pathlib
import plistlib
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import types
import unittest
import zipfile
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import apple_cross_store_artifact_gate as apple_gate
import apple_release_contamination_gate as contamination
import cross_store_upload_readiness as readiness
import release_obfuscation_contract as obfuscation
import validate_apple_submission_package as submission


PRIVACY = {
    "NSPrivacyTracking": False,
    "NSPrivacyTrackingDomains": [],
    "NSPrivacyCollectedDataTypes": [],
    "NSPrivacyAccessedAPITypes": [],
}


def _plist(
    bundle_id: str,
    *,
    release_host: bool = False,
    short_version: str = "1.0.17",
    bundle_version: str = "34",
) -> bytes:
    value: dict[str, object] = {
        "CFBundleIdentifier": bundle_id,
        "CFBundleShortVersionString": short_version,
        "CFBundleVersion": bundle_version,
    }
    if release_host:
        value.update(
            {
                contamination.CONTRACT_KEY: contamination.CONTRACT_VALUE,
                contamination.LIVE_SMOKE_KEY: False,
                contamination.SMOKE_PIN_KEY: False,
            }
        )
    return plistlib.dumps(value)


def _privacy(
    api_reasons: dict[str, frozenset[str]] | None = None,
    *,
    host_collection: bool = False,
) -> bytes:
    value = dict(PRIVACY)
    value["NSPrivacyAccessedAPITypes"] = [
        {
            "NSPrivacyAccessedAPIType": api_type,
            "NSPrivacyAccessedAPITypeReasons": sorted(reasons),
        }
        for api_type, reasons in sorted((api_reasons or {}).items())
    ]
    if host_collection:
        value["NSPrivacyCollectedDataTypes"] = [
            {
                "NSPrivacyCollectedDataType": data_type,
                "NSPrivacyCollectedDataTypeLinked": True,
                "NSPrivacyCollectedDataTypeTracking": False,
                "NSPrivacyCollectedDataTypePurposes": [
                    apple_gate.PRIVACY_APP_FUNCTIONALITY_PURPOSE
                ],
            }
            for data_type in sorted(apple_gate.HOST_PRIVACY_COLLECTED_TYPES)
        ]
    return plistlib.dumps(value)



# Real `xcrun --find` answers, taken once at import before any test patches
# subprocess, for the gate's lookup warm-up.
_XCRUN_LOOKUPS = (
    {
        name: subprocess.run(
            ["/usr/bin/xcrun", "--find", name], capture_output=True, check=False
        ).stdout
        for name in ("lipo", "nm", "otool-classic")
    }
    if sys.platform == "darwin"
    else {}
)

class AppleCrossStoreGateAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name)
        (self.repo / "artifacts").mkdir()
        identity = self.repo / apple_gate.RELEASE_IDENTITY_RELATIVE_PATH
        identity.parent.mkdir(parents=True)
        identity.write_bytes(
            (ROOT / apple_gate.RELEASE_IDENTITY_RELATIVE_PATH).read_bytes()
        )
        # The gate must never consult the owner-provisioned source-freeze trust
        # file; any call fails the test.
        self._freeze_patch = mock.patch.object(
            apple_gate.source_freeze,
            "verified_release_source_state",
            side_effect=AssertionError("gate consulted the source-freeze trust file"),
        )
        self._freeze_patch.start()
        self.codesign_authority = apple_gate.APP_STORE_DISTRIBUTION_AUTHORITY

    def tearDown(self) -> None:
        self._freeze_patch.stop()
        self.temporary.cleanup()

    def _reviewed_support_tree(self) -> tuple[pathlib.Path, pathlib.Path]:
        repo = self.repo / "reviewed-support"
        tools = repo / "tools"
        tools.mkdir(parents=True)
        for filename, _public_name in apple_gate.REQUIRED_MODULE_FILES:
            (tools / filename).write_bytes((ROOT / "tools" / filename).read_bytes())
        return repo.resolve(), tools.resolve()

    def test_reviewed_support_exec_rejects_swap_restore_without_executing_path(
        self,
    ) -> None:
        repo, tools = self._reviewed_support_tree()
        target = tools / "release_source_freeze.py"
        original = target.read_bytes()
        held = tools / ".release_source_freeze.held"
        malicious = b"raise RuntimeError('MALICIOUS_SNAPSHOT_CODE_EXECUTED')\n"
        real_compile = builtins.compile
        attacked = False

        def swap_during_compile(source, filename, mode, *args, **kwargs):
            nonlocal attacked
            if pathlib.Path(filename).name == target.name and not attacked:
                attacked = True
                os.rename(target, held)
                target.write_bytes(malicious)
                target.unlink()
                os.rename(held, target)
            return real_compile(source, filename, mode, *args, **kwargs)

        with (
            mock.patch.object(apple_gate, "ORIGIN_ROOT", repo),
            mock.patch.object(apple_gate, "TOOLS_DIR", tools),
            mock.patch("builtins.compile", side_effect=swap_during_compile),
            self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError,
                "source or ancestor changed|path was replaced",
            ),
        ):
            apple_gate._load_required_modules()
        self.assertTrue(attacked)
        self.assertEqual(target.read_bytes(), original)
        self.assertFalse(any(tools.glob(".*.winsvpn-apple-mod-*")))

    def test_reviewed_support_exec_ignores_preloaded_public_module_poison(self) -> None:
        repo, tools = self._reviewed_support_tree()
        poison = {
            public_name: types.ModuleType(public_name)
            for _filename, public_name in apple_gate.REQUIRED_MODULE_FILES
        }
        for module in poison.values():
            module.MALICIOUS_PRELOADED_MODULE = True
        with (
            mock.patch.object(apple_gate, "ORIGIN_ROOT", repo),
            mock.patch.object(apple_gate, "TOOLS_DIR", tools),
            mock.patch.dict(sys.modules, poison),
        ):
            loaded = apple_gate._load_required_modules()
            self.assertEqual(
                loaded["release_source_freeze"].LOCK_CONTRACT,
                "winsvpn-app-source-lock-v1",
            )
            self.assertFalse(
                hasattr(
                    loaded["release_source_freeze"],
                    "MALICIOUS_PRELOADED_MODULE",
                )
            )
            for public_name, module in poison.items():
                self.assertIs(sys.modules.get(public_name), module)
        self.assertFalse(any(tools.glob(".*.winsvpn-apple-mod-*")))

    def _ios_ipa(self, name: str = "WinsVPN.ipa") -> pathlib.Path:
        path = self.repo / "artifacts" / name
        with zipfile.ZipFile(path, "w") as archive:
            base = "Payload/Win's VPN.app"
            archive.writestr(
                f"{base}/Info.plist",
                _plist(apple_gate.HOST_BUNDLE_ID, release_host=True),
            )
            archive.writestr(f"{base}/Frameworks/App.framework/App", b"safe-aot")
            archive.writestr(
                f"{base}/PrivacyInfo.xcprivacy",
                _privacy(apple_gate.HOST_PRIVACY_API_REASONS, host_collection=True),
            )
            extension = f"{base}/PlugIns/PacketTunnel.appex"
            archive.writestr(f"{extension}/Info.plist", _plist(apple_gate.TUNNEL_BUNDLE_ID))
            archive.writestr(
                f"{extension}/PrivacyInfo.xcprivacy",
                _privacy(apple_gate.TUNNEL_PRIVACY_API_REASONS),
            )
            watch = f"{base}/Watch/WinsWatch.app"
            archive.writestr(f"{watch}/Info.plist", _plist(apple_gate.WATCH_BUNDLE_ID))
            archive.writestr(f"{watch}/PrivacyInfo.xcprivacy", _privacy())
            self._write_zip_engine_frameworks(archive, base, "ios")
        return path

    def _developer_id_zip(self) -> pathlib.Path:
        path = self.repo / "artifacts" / "WinsVPN.app.zip"
        with zipfile.ZipFile(path, "w") as archive:
            base = "Win's VPN.app/Contents"
            archive.writestr(
                f"{base}/Info.plist",
                _plist(apple_gate.HOST_BUNDLE_ID, release_host=True),
            )
            archive.writestr(f"{base}/Frameworks/App.framework/App", b"safe-aot")
            archive.writestr(
                f"{base}/Resources/PrivacyInfo.xcprivacy",
                _privacy(apple_gate.HOST_PRIVACY_API_REASONS, host_collection=True),
            )
            extension = f"{base}/PlugIns/PacketTunnel.appex/Contents"
            archive.writestr(f"{extension}/Info.plist", _plist(apple_gate.TUNNEL_BUNDLE_ID))
            archive.writestr(
                f"{extension}/Resources/PrivacyInfo.xcprivacy",
                _privacy(apple_gate.TUNNEL_PRIVACY_API_REASONS),
            )
            self._write_zip_engine_frameworks(archive, base, "macos")
        return path

    def _write_zip_engine_frameworks(
        self, archive: zipfile.ZipFile, base: str, platform: str
    ) -> None:
        contracts = {
            "WinsAmneziaWGPacketEngine": {
                apple_gate.PRIVACY_FILE_TIMESTAMP_API: frozenset({"C617.1"}),
            },
            "WinsXrayVlessWsTransport": {
                apple_gate.PRIVACY_FILE_TIMESTAMP_API: frozenset({"C617.1"}),
            },
            "WinsWinnPacketEngine": {
                apple_gate.PRIVACY_FILE_TIMESTAMP_API: frozenset({"C617.1"}),
                apple_gate.PRIVACY_SYSTEM_BOOT_TIME_API: frozenset({"35F9.1"}),
            },
        }
        for name, api_reasons in contracts.items():
            framework = f"{base}/Frameworks/{name}.framework"
            if platform == "ios":
                executable = f"{framework}/{name}"
                privacy = f"{framework}/PrivacyInfo.xcprivacy"
                image = self._thin_mh_dylib(apple_gate.CPU_TYPE_ARM64)
            else:
                executable = f"{framework}/Versions/A/{name}"
                privacy = f"{framework}/Versions/A/Resources/PrivacyInfo.xcprivacy"
                image = self._universal_mh_dylib()
            archive.writestr(executable, image)
            archive.writestr(privacy, _privacy(api_reasons))

    @staticmethod
    def _thin_mh_dylib(cputype: int, *, filetype: int = apple_gate.MH_DYLIB) -> bytes:
        data = bytearray(obfuscation._minimal_macho64(dwarf=False))
        struct.pack_into("<I", data, 4, cputype)
        struct.pack_into("<I", data, 12, filetype)
        return bytes(data)

    @classmethod
    def _universal_mh_dylib(cls, *, filetype: int = apple_gate.MH_DYLIB) -> bytes:
        arm = cls._thin_mh_dylib(apple_gate.CPU_TYPE_ARM64, filetype=filetype)
        x86 = cls._thin_mh_dylib(apple_gate.CPU_TYPE_X86_64, filetype=filetype)
        header_len = 8 + 20 * 2
        arm_off = header_len
        x86_off = arm_off + len(arm)
        blob = bytearray(x86_off + len(x86))
        struct.pack_into(">II", blob, 0, 0xCAFEBABE, 2)
        struct.pack_into(">IIIII", blob, 8, apple_gate.CPU_TYPE_ARM64, 0, arm_off, len(arm), 2)
        struct.pack_into(">IIIII", blob, 28, apple_gate.CPU_TYPE_X86_64, 3, x86_off, len(x86), 2)
        blob[arm_off : arm_off + len(arm)] = arm
        blob[x86_off : x86_off + len(x86)] = x86
        return bytes(blob)

    @classmethod
    def _write_macos_app(cls, app: pathlib.Path, *, aot: bytes | None = None) -> None:
        contents = app / "Contents"
        extension = contents / "PlugIns" / "PacketTunnel.appex" / "Contents"
        (contents / "Resources").mkdir(parents=True)
        (extension / "Resources").mkdir(parents=True)
        (contents / "Info.plist").write_bytes(
            _plist(apple_gate.HOST_BUNDLE_ID, release_host=True)
        )
        aot_path = contents / "Frameworks/App.framework/App"
        aot_path.parent.mkdir(parents=True)
        aot_path.write_bytes(aot if aot is not None else cls._universal_mh_dylib())
        (contents / "Resources" / "PrivacyInfo.xcprivacy").write_bytes(
            _privacy(apple_gate.HOST_PRIVACY_API_REASONS, host_collection=True)
        )
        (extension / "Info.plist").write_bytes(_plist(apple_gate.TUNNEL_BUNDLE_ID))
        (extension / "Resources" / "PrivacyInfo.xcprivacy").write_bytes(
            _privacy(apple_gate.TUNNEL_PRIVACY_API_REASONS)
        )
        contracts = {
            "WinsAmneziaWGPacketEngine": {
                apple_gate.PRIVACY_FILE_TIMESTAMP_API: frozenset({"C617.1"}),
            },
            "WinsXrayVlessWsTransport": {
                apple_gate.PRIVACY_FILE_TIMESTAMP_API: frozenset({"C617.1"}),
            },
            "WinsWinnPacketEngine": {
                apple_gate.PRIVACY_FILE_TIMESTAMP_API: frozenset({"C617.1"}),
                apple_gate.PRIVACY_SYSTEM_BOOT_TIME_API: frozenset({"35F9.1"}),
            },
        }
        for name, api_reasons in contracts.items():
            version = contents / "Frameworks" / f"{name}.framework" / "Versions" / "A"
            executable = version / name
            executable.parent.mkdir(parents=True, exist_ok=True)
            executable.write_bytes(cls._universal_mh_dylib())
            privacy = version / "Resources" / "PrivacyInfo.xcprivacy"
            privacy.parent.mkdir(parents=True, exist_ok=True)
            privacy.write_bytes(_privacy(api_reasons))
        engine_digest = hashlib.sha256(cls._universal_mh_dylib()).hexdigest()
        awg = {
            "generation": "3.1",
            "source": {
                "commit": "fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d",
                "tag": "v3.1.20260814",
            },
            "wrappers": {
                "macosx": {
                    "amneziawg_packet_engine": {"sha256": engine_digest},
                    "xray_vless_ws_transport": {"sha256": engine_digest},
                }
            },
        }
        winn = {"wrappers": {"macosx": {"sha256": engine_digest}}}
        awg_bytes = (json.dumps(awg, sort_keys=True) + "\n").encode("utf-8")
        winn_bytes = (json.dumps(winn, sort_keys=True) + "\n").encode("utf-8")
        (contents / "Resources" / "apple_awg_31_engine_provenance.json").write_bytes(
            awg_bytes
        )
        (contents / "Resources" / "apple_winn_v3_engine_provenance.json").write_bytes(
            winn_bytes
        )
        (contents / "Resources" / "apple_engine_artifacts_manifest.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "staged_components": [
                        "amneziawg_packet_engine",
                        "winn_packet_engine",
                        "xray_vless_ws_transport",
                    ],
                    "apple_awg_31_provenance_sha256": hashlib.sha256(
                        awg_bytes
                    ).hexdigest(),
                    "apple_winn_v3_provenance_sha256": hashlib.sha256(
                        winn_bytes
                    ).hexdigest(),
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    def _bounded_tool_fixture(self, run):
        """Adapt text tool fixtures to the bounded runner's byte result contract."""
        def bounded(argv, label, **kwargs):
            self.assertIsInstance(argv, list)
            self.assertNotIn("shell", kwargs)
            self.assertEqual(kwargs["cwd"], "/")
            if argv[:2] == [apple_gate.XCRUN, "--find"]:
                # The xcrun lookup warm-up: unconfined, no tool limits, real lookup.
                self.assertIs(kwargs.get("descendant_boundary"), False)
                self.assertNotIn("preexec_fn", kwargs)
                return subprocess.CompletedProcess(
                    argv, 0, _XCRUN_LOOKUPS.get(argv[2], b""), b""
                )
            expected_limits = (
                apple_gate._apply_child_rlimits
                if label.endswith((" signature normalization", " signature removal"))
                else apple_gate._apply_tool_rlimits
            )
            self.assertEqual(kwargs["preexec_fn"], expected_limits)
            self.assertGreater(kwargs["timeout"], 0)
            result = run(argv, **kwargs)
            return subprocess.CompletedProcess(
                result.args, result.returncode,
                result.stdout.encode("utf-8"), result.stderr.encode("utf-8"),
            )
        return bounded

    def _expanded_tool_argv(self, argv):
        command = list(argv)
        if sys.platform == "darwin":
            self.assertEqual(command[:3], [
                apple_gate.MACOS_DESCENDANT_BOUNDARY,
                "-p", apple_gate.MACOS_DESCENDANT_BOUNDARY_PROFILE,
            ])
            command = command[3:]
        return command

    def _process_result(self, argv, **kwargs):
        command = list(argv)
        stdout = ""
        stderr = ""
        if command[0] == "/usr/sbin/pkgutil" and "--check-signature" in command:
            stdout = (
                "Status: signed by a developer certificate issued by Apple (Development)\n"
                "Certificate Chain:\n"
                "    1. 3rd Party Mac Developer Installer: Win's VPN Inc "
                f"({apple_gate.TEAM_ID})\n"
                "    2. Apple Worldwide Developer Relations Certification Authority\n"
                "    3. Apple Root CA\n"
            )
        if command[0] == "/usr/bin/lipo":
            stdout = "arm64 x86_64\n"
        if command[:2] == [apple_gate.XCRUN, "otool-classic"]:
            if "-hv" in command:
                stdout = (
                    "Mach header\n"
                    "      magic cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags\n"
                    "MH_MAGIC_64    ARM64        ALL  0x00     DYLIB    15       1888 0x00100085\n"
                    "MH_MAGIC_64   X86_64        ALL  0x00     DYLIB    15       1888 0x00100085\n"
                )
            else:
                stdout = (
                    "      cmd LC_SEGMENT_64\n"
                    "  segname __TEXT\n"
                    "  sectname __text\n"
                    "  sectname __const\n"
                )
        if command[0] == "/usr/bin/nm":
            stdout = (
                "0000000000474000 S _kDartSnapshotData\n"
                "0000000000004000 T _kDartSnapshotText\n"
            )
        if command[0] == "/usr/bin/codesign" and "-d" in command:
            authority = self.codesign_authority
            stderr = (
                f"{apple_gate._exact_release_authority_line(authority)}\n"
                f"TeamIdentifier={apple_gate.TEAM_ID}\n"
                "Format=Mach-O thin (arm64)\n"
            )
        if command[0] == "/usr/sbin/spctl":
            stderr = "accepted\nsource=Notarized Developer ID\n"
        return subprocess.CompletedProcess(command, 0, stdout, stderr)

    def test_ios_signature_gate_is_artifact_only_and_exact(self) -> None:
        self._ios_ipa()
        calls: list[tuple[list[str], dict[str, object]]] = []

        def run(argv, **kwargs):
            calls.append((list(argv), kwargs))
            result = self._process_result(argv, **kwargs)
            if "/usr/bin/codesign" in argv and "-d" in argv:
                result.stderr = (
                    "Authority=Apple Distribution: Win's VPN Inc (5YT8H4U72M)\n"
                    "TeamIdentifier=5YT8H4U72M\n"
                )
            return result

        with mock.patch.object(apple_gate, "ROOT", self.repo), mock.patch.object(
            apple_gate, "_bounded_subprocess", side_effect=self._bounded_tool_fixture(run)
        ):
            apple_gate.verify_signature("ios-app-store-ipa", "artifacts/WinsVPN.ipa")
        codesign_calls = [
            argv for argv, _kwargs in calls if argv and argv[0] == "/usr/bin/codesign"
        ]
        self.assertGreaterEqual(len(codesign_calls), 4)
        verify_calls = [argv for argv in codesign_calls if "--verify" in argv]
        identity_calls = [argv for argv in codesign_calls if "-d" in argv]
        self.assertGreaterEqual(len(verify_calls), 2)
        self.assertGreaterEqual(len(identity_calls), 2)
        for argv, kwargs in calls:
            self.assertIsInstance(argv, list)
            self.assertFalse(
                {"xcodebuild", "flutter", "curl", "xcrun", "notarytool", "stapler"}
                & set(argv)
            )
        for argv in verify_calls:
            requirement = apple_gate._codesign_requirement_from_argv(argv)
            self.assertIn(f'subject.OU] = "{apple_gate.TEAM_ID}"', requirement)
            self.assertIn("anchor apple generic", requirement)
            self.assertNotIn("-R", argv)
            self.assertFalse(apple_gate._is_volfs_path(argv[-1]), msg=argv)

    def test_nested_appex_foreign_team_fails_closed(self) -> None:
        self._ios_ipa()

        def run(argv, **kwargs):
            result = self._process_result(argv, **kwargs)
            if argv and argv[0] == "/usr/bin/codesign" and "-d" in argv:
                target = pathlib.Path(argv[-1])
                info_path = target / "Info.plist"
                if not info_path.is_file():
                    info_path = target / "Contents" / "Info.plist"
                bundle_id = ""
                if info_path.is_file():
                    try:
                        parsed = plistlib.loads(info_path.read_bytes())
                    except Exception:
                        parsed = {}
                    bundle_id = str(parsed.get("CFBundleIdentifier") or "")
                if bundle_id == apple_gate.TUNNEL_BUNDLE_ID:
                    result.stderr = (
                        "Authority=Apple Distribution: Other Team (ABCD123456)\n"
                        "TeamIdentifier=ABCD123456\n"
                    )
                else:
                    result.stderr = (
                        "Authority=Apple Distribution: Win's VPN Inc "
                        f"({apple_gate.TEAM_ID})\n"
                        f"TeamIdentifier={apple_gate.TEAM_ID}\n"
                    )
            return result

        with mock.patch.object(apple_gate, "ROOT", self.repo), mock.patch.object(
            apple_gate, "_bounded_subprocess", side_effect=self._bounded_tool_fixture(run)
        ):
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "identity or team"
            ):
                apple_gate.verify_signature(
                    "ios-app-store-ipa", "artifacts/WinsVPN.ipa"
                )

    def test_inner_adhoc_signature_is_not_release_valid(self) -> None:
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "identity or team"
        ):
            apple_gate._require_release_codesign_identity(
                "Format=Mach-O thin (arm64)\nSignature=adhoc\n",
                apple_gate.APP_STORE_DISTRIBUTION_AUTHORITY,
            )

    def test_ios_host_tunnel_and_watch_versions_fail_closed(self) -> None:
        cases = (
            ("host", apple_gate.HOST_BUNDLE_ID),
            ("tunnel", apple_gate.TUNNEL_BUNDLE_ID),
            ("watch", apple_gate.WATCH_BUNDLE_ID),
        )
        for label, stale_bundle in cases:
            with self.subTest(bundle=label):
                path = self.repo / "artifacts" / f"stale-{label}.ipa"
                with zipfile.ZipFile(path, "w") as archive:
                    base = "Payload/Win's VPN.app"
                    archive.writestr(
                        f"{base}/Info.plist",
                        _plist(
                            apple_gate.HOST_BUNDLE_ID,
                            release_host=True,
                            short_version=(
                                "9.9.9"
                                if stale_bundle == apple_gate.HOST_BUNDLE_ID
                                else "1.0.17"
                            ),
                        ),
                    )
                    archive.writestr(f"{base}/Frameworks/App.framework/App", b"safe-aot")
                    archive.writestr(
                        f"{base}/PrivacyInfo.xcprivacy",
                        _privacy(
                            apple_gate.HOST_PRIVACY_API_REASONS,
                            host_collection=True,
                        ),
                    )
                    extension = f"{base}/PlugIns/PacketTunnel.appex"
                    archive.writestr(
                        f"{extension}/Info.plist",
                        _plist(
                            apple_gate.TUNNEL_BUNDLE_ID,
                            bundle_version=(
                                "999"
                                if stale_bundle == apple_gate.TUNNEL_BUNDLE_ID
                                else "34"
                            ),
                        ),
                    )
                    archive.writestr(
                        f"{extension}/PrivacyInfo.xcprivacy",
                        _privacy(apple_gate.TUNNEL_PRIVACY_API_REASONS),
                    )
                    watch = f"{base}/Watch/WinsWatch.app"
                    archive.writestr(
                        f"{watch}/Info.plist",
                        _plist(
                            apple_gate.WATCH_BUNDLE_ID,
                            short_version=(
                                "9.9.9"
                                if stale_bundle == apple_gate.WATCH_BUNDLE_ID
                                else "1.0.17"
                            ),
                        ),
                    )
                    archive.writestr(f"{watch}/PrivacyInfo.xcprivacy", _privacy())
                    self._write_zip_engine_frameworks(archive, base, "ios")
                with mock.patch.object(apple_gate, "ROOT", self.repo):
                    with self.assertRaisesRegex(
                        apple_gate.AppleArtifactGateError, "version"
                    ):
                        apple_gate.verify_privacy_only(
                            "ios-app-store-ipa", path.relative_to(self.repo)
                        )

    def test_release_candidate_adapter_rejects_stale_version_and_build(self) -> None:
        manifest = {"app_version": "9.9.9", "build_number": 999, "artifacts": []}
        with (
            mock.patch.object(
                submission,
                "sha256_file",
                side_effect=lambda path: (
                    submission.APPLE_CROSS_STORE_GATE_HELPER_SHA256
                    if path == submission.APPLE_CROSS_STORE_GATE_HELPER
                    else submission.APPLE_RELEASE_CONTAMINATION_GATE_HELPER_SHA256
                ),
            ),
            mock.patch.object(submission, "_load_reviewed_helper", return_value=apple_gate),
            mock.patch.object(submission, "read_json", return_value=manifest),
            self.assertRaisesRegex(AssertionError, r"canonical 1.0.17\+34"),
        ):
            submission.validate_cross_store_artifact(
                "ios-app-store-ipa", "artifacts/missing.ipa"
            )

    def test_developer_id_gate_requires_offline_notarized_assessment(self) -> None:
        self.codesign_authority = apple_gate.DEVELOPER_ID_APPLICATION_AUTHORITY
        self._developer_id_zip()
        calls: list[list[str]] = []

        def run(argv, **kwargs):
            calls.append(list(argv))
            if argv[0] == "/usr/bin/ditto":
                with zipfile.ZipFile(argv[-2]) as archive:
                    archive.extractall(argv[-1])
            return self._process_result(argv, **kwargs)

        with mock.patch.object(apple_gate, "ROOT", self.repo), mock.patch.object(
            apple_gate, "_bounded_subprocess", side_effect=self._bounded_tool_fixture(run)
        ):
            apple_gate.verify_signature(
                "macos-developer-id-app", "artifacts/WinsVPN.app.zip"
            )
        self.assertTrue(any(argv[0] == "/usr/sbin/spctl" for argv in calls))
        self.assertFalse(any("stapler" in argv or "notarytool" in argv for argv in calls))

    class _FakeExpand:
        def __init__(self) -> None:
            self.returncode = 0
            self.pid = os.getpid()

        def communicate(self, timeout=None):
            return "", ""

        def wait(self, timeout=None):
            return 0

        def kill(self) -> None:
            return None

    def test_macos_app_store_pkg_checks_installer_and_distribution_signature(self) -> None:
        package = self.repo / "artifacts" / "WinsVPN.pkg"
        package.write_bytes(b"synthetic-package" + (b"\x00" * (256 * 1024)))
        calls: list[tuple[list[str], dict[str, object]]] = []
        expand_calls: list[list[str]] = []

        def run(argv, **kwargs):
            command = list(argv)
            calls.append((command, kwargs))
            self.assertIsInstance(argv, list)
            self.assertEqual(kwargs["cwd"], "/")
            self.assertEqual(kwargs["env"]["PATH"], apple_gate.REVIEWED_SUBPROCESS_PATH)
            self.assertEqual(
                set(kwargs["env"]),
                {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"},
            )
            result = self._process_result(argv, **kwargs)
            if command[0] == "/usr/bin/codesign" and "-d" in command:
                result.stderr = (
                    "Authority=Apple Distribution: Win's VPN Inc (5YT8H4U72M)\n"
                    "TeamIdentifier=5YT8H4U72M\n"
                    "Format=Mach-O thin (arm64)\n"
                )
            return result

        def popen(argv, **kwargs):
            self.assertFalse(kwargs["shell"])
            command = self._expanded_tool_argv(argv)
            expand_calls.append(command)
            calls.append((command, kwargs))
            self.assertIsInstance(argv, list)
            self.assertEqual(kwargs["cwd"], "/")
            self.assertEqual(kwargs["preexec_fn"], apple_gate._apply_child_rlimits)
            self.assertTrue(kwargs["start_new_session"])
            self.assertEqual(
                set(kwargs["env"]),
                {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"},
            )
            if command[:2] == ["/usr/sbin/pkgutil", "--expand-full"]:
                self.assertNotEqual(command[2], str(package))
                self.assertTrue(command[2].startswith("/.vol/"))
                dest = command[-1]
                dest_parts = pathlib.PurePosixPath(dest).parts
                self.assertTrue(dest.startswith("/.vol/"))
                self.assertEqual(len(dest_parts), 4)
                dest_info = os.lstat(dest)
                self.assertTrue(stat.S_ISDIR(dest_info.st_mode))
                self.assertFalse(stat.S_ISLNK(dest_info.st_mode))
                self._write_macos_app(
                    pathlib.Path(dest)
                    / "WinsVPN.pkg"
                    / "Payload"
                    / "Applications"
                    / "Win's VPN.app"
                )
                return self._FakeExpand()
            raise AssertionError(command)

        with mock.patch.object(apple_gate, "ROOT", self.repo), mock.patch.object(
            apple_gate, "_bounded_subprocess", side_effect=self._bounded_tool_fixture(run)
        ), mock.patch.object(apple_gate.subprocess, "Popen", side_effect=popen):
            apple_gate.verify_signature(
                "macos-app-store-pkg", "artifacts/WinsVPN.pkg"
            )
        argv_only = [argv for argv, _kwargs in calls]
        self.assertTrue(
            any(argv[:2] == ["/usr/sbin/pkgutil", "--check-signature"] for argv in argv_only)
        )
        self.assertTrue(
            any(argv[:2] == ["/usr/sbin/pkgutil", "--expand-full"] for argv in expand_calls)
        )
        self.assertTrue(any(argv[0] == "/usr/bin/codesign" for argv in argv_only))
        self.assertTrue(any(argv[0] == "/usr/bin/lipo" for argv in argv_only))
        self.assertTrue(
            any(argv[:2] == [apple_gate.XCRUN, "otool-classic"] for argv in argv_only)
        )
        self.assertTrue(any(argv[0] == "/usr/bin/nm" for argv in argv_only))
        self.assertFalse(any(argv[0] == "/usr/sbin/spctl" for argv in argv_only))
        self.assertFalse(
            any(pathlib.Path(argv[0]).name in {"tar", "bsdtar", "xar", "cpio"} for argv in argv_only)
        )
        for argv in argv_only:
            self.assertIn(argv[0], apple_gate.REVIEWED_APPLE_TOOLS)
        for argv in argv_only:
            if argv[:2] == ["/usr/sbin/pkgutil", "--check-signature"]:
                self.assertNotEqual(argv[2], str(package))
                self.assertTrue(argv[2].startswith("/.vol/"))

    def test_macos_pkg_rejects_generic_mh_execute_aot_fixture(self) -> None:
        package = self.repo / "artifacts" / "WinsVPN.pkg"
        package.write_bytes(b"synthetic-package" + (b"\x00" * (256 * 1024)))

        def run(argv, **kwargs):
            result = self._process_result(argv, **kwargs)
            if argv[0] == "/usr/bin/codesign" and "-d" in argv:
                result.stderr = (
                    "Authority=Apple Distribution: Win's VPN Inc (5YT8H4U72M)\n"
                    "TeamIdentifier=5YT8H4U72M\n"
                    "Format=Mach-O thin (arm64)\n"
                )
            return result

        def popen(argv, **kwargs):
            self.assertFalse(kwargs["shell"])
            command = self._expanded_tool_argv(argv)
            if command[:2] == ["/usr/sbin/pkgutil", "--expand-full"]:
                self.assertTrue(command[2].startswith("/.vol/"))
                dest = command[-1]
                dest_parts = pathlib.PurePosixPath(dest).parts
                self.assertTrue(dest.startswith("/.vol/"))
                self.assertEqual(len(dest_parts), 4)
                dest_info = os.lstat(dest)
                self.assertTrue(stat.S_ISDIR(dest_info.st_mode))
                self.assertFalse(stat.S_ISLNK(dest_info.st_mode))
                self._write_macos_app(
                    pathlib.Path(dest)
                    / "WinsVPN.pkg"
                    / "Payload"
                    / "Applications"
                    / "Win's VPN.app",
                    aot=self._universal_mh_dylib(filetype=apple_gate.MH_EXECUTE),
                )
                return self._FakeExpand()
            raise AssertionError(command)

        with mock.patch.object(apple_gate, "ROOT", self.repo), mock.patch.object(
            apple_gate, "_bounded_subprocess", side_effect=self._bounded_tool_fixture(run)
        ), mock.patch.object(apple_gate.subprocess, "Popen", side_effect=popen):
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "MH_DYLIB|EXECUTE|Flutter AOT"
            ):
                apple_gate.verify_signature(
                    "macos-app-store-pkg", "artifacts/WinsVPN.pkg"
                )

    def test_wrong_target_suffix_absolute_escape_and_zip_symlink_fail(self) -> None:
        self._ios_ipa("wrong.pkg")
        real = self._ios_ipa("real.ipa")
        (self.repo / "artifacts" / "linked.ipa").symlink_to(real)
        with mock.patch.object(apple_gate, "ROOT", self.repo):
            with self.assertRaises(apple_gate.AppleArtifactGateError):
                apple_gate.canonical_artifact("unknown", "artifacts/wrong.pkg")
            with self.assertRaises(apple_gate.AppleArtifactGateError):
                apple_gate.canonical_artifact("ios-app-store-ipa", "artifacts/wrong.pkg")
            with self.assertRaises(apple_gate.AppleArtifactGateError):
                apple_gate.canonical_artifact("ios-app-store-ipa", "/tmp/wrong.ipa")
            with self.assertRaises(apple_gate.AppleArtifactGateError):
                apple_gate.canonical_artifact("ios-app-store-ipa", "../escape.ipa")
            with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "symlink"):
                apple_gate.canonical_artifact(
                    "ios-app-store-ipa", "artifacts/linked.ipa"
                )
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError,
                "tvOS is not a 1.0.17\\+34 shipping, upload, signing, or receipt surface",
            ):
                apple_gate.canonical_artifact(
                    "tvos-app-store-ipa", "artifacts/WinsVPN.ipa"
                )
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError,
                "watchOS is embedded in the iOS IPA",
            ):
                apple_gate.canonical_artifact(
                    "watchos-app-store-ipa", "artifacts/WinsVPN.ipa"
                )

        archive_path = self.repo / "artifacts" / "unsafe-symlink.app.zip"
        member = zipfile.ZipInfo("Win's VPN.app/Contents/Frameworks/escape")
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr(member, "../../../../outside")
        with zipfile.ZipFile(archive_path) as archive:
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "symlink|forbidden"
            ):
                apple_gate._safe_zip_members(archive)

    def test_submission_adapter_requires_exact_three_argument_contract(self) -> None:
        with mock.patch.object(
            submission, "validate_cross_store_artifact", return_value=["PASS: exact"]
        ) as verify:
            self.assertEqual(
                submission.main(["--verify", "ios-app-store-ipa", "artifacts/a.ipa"]),
                0,
            )
            verify.assert_called_once_with("ios-app-store-ipa", "artifacts/a.ipa")
        self.assertEqual(submission.main(["--verify", "ios-app-store-ipa"]), 1)

    def test_obfuscation_adapter_routes_all_three_apple_targets(self) -> None:
        for target in obfuscation.APPLE_CROSS_STORE_TARGETS:
            with self.subTest(target=target), mock.patch.object(
                obfuscation, "canonical_apple_gate_verify"
            ) as verify:
                self.assertEqual(obfuscation.main(["--verify", target, "artifact.pkg"]), 0)
                verify.assert_called_once_with(target, "artifact.pkg")

    def test_current_adapters_accept_the_current_gate(self) -> None:
        gate_digest = hashlib.sha256(
            (ROOT / "tools/apple_cross_store_artifact_gate.py").read_bytes()
        ).hexdigest()
        contamination_digest = hashlib.sha256(
            (ROOT / "tools/apple_release_contamination_gate.py").read_bytes()
        ).hexdigest()
        self.assertEqual(
            submission.APPLE_RELEASE_CONTAMINATION_GATE_HELPER_SHA256,
            contamination_digest,
        )
        self.assertEqual(
            obfuscation.APPLE_RELEASE_CONTAMINATION_GATE_HELPER_SHA256,
            contamination_digest,
        )
        self.assertEqual(
            submission.APPLE_CROSS_STORE_GATE_HELPER_SHA256,
            gate_digest,
        )
        self.assertEqual(
            obfuscation.APPLE_CROSS_STORE_GATE_HELPER_SHA256,
            gate_digest,
        )
        helper_source = (ROOT / "tools/validate_apple_submission_package.py").read_text(
            encoding="utf-8"
        )
        obfuscation_source = (ROOT / "tools/release_obfuscation_contract.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("apple_cross_store_artifact_gate.py", helper_source)
        self.assertIn("apple_cross_store_artifact_gate.py", obfuscation_source)

    def test_reviewed_helper_hash_is_checked_before_dynamic_load(self) -> None:
        with mock.patch.object(
            submission, "APPLE_CROSS_STORE_GATE_HELPER_SHA256", "0" * 64
        ):
            with self.assertRaisesRegex(AssertionError, "source hash"):
                submission.validate_cross_store_artifact(
                    "ios-app-store-ipa", "artifacts/WinsVPN.ipa"
                )
        with mock.patch.object(obfuscation, "sha256_file", return_value="bad"):
            with self.assertRaisesRegex(obfuscation.ObfuscationError, "source hash"):
                obfuscation.canonical_apple_gate_verify(
                    "ios-app-store-ipa", "artifacts/WinsVPN.ipa"
                )

    def test_contamination_helper_hash_is_checked_before_any_helper_runs(self) -> None:
        # R24 V2 F-05: loading the cross-store helper executes the contamination
        # helper, so a changed contamination helper must be refused before that
        # load, not after it.
        loaded = []

        def record_load(*args: object) -> None:
            loaded.append(args)
            raise AssertionError("a helper was loaded before the contamination hash")

        for module, loader, error, call in (
            (
                obfuscation,
                "_load_reviewed_helper",
                obfuscation.ObfuscationError,
                lambda: obfuscation.canonical_apple_gate_verify(
                    "ios-app-store-ipa", "artifacts/WinsVPN.ipa"
                ),
            ),
            (
                submission,
                "_load_reviewed_helper",
                AssertionError,
                lambda: submission.validate_cross_store_artifact(
                    "ios-app-store-ipa", "artifacts/WinsVPN.ipa"
                ),
            ),
        ):
            with self.subTest(module=module.__name__):
                with mock.patch.object(
                    module, "APPLE_RELEASE_CONTAMINATION_GATE_HELPER_SHA256", "0" * 64
                ), mock.patch.object(module, loader, side_effect=record_load):
                    with self.assertRaisesRegex(error, "contamination helper source hash"):
                        call()
                self.assertEqual(loaded, [])

    def test_cross_store_rejects_reused_artifact_bytes(self) -> None:
        first = self.repo / "artifacts" / "first.pkg"
        second = self.repo / "artifacts" / "second.pkg"
        first.write_bytes(b"same")
        second.write_bytes(b"same")
        receipts = {
            "macos-app-store-pkg": {
                "artifact": {"path": "artifacts/first.pkg", "sha256": "same"}
            },
            "macos-developer-id-app": {
                "artifact": {"path": "artifacts/second.pkg", "sha256": "same"}
            },
        }
        with self.assertRaisesRegex(readiness.UploadReadinessError, "distinct artifact"):
            readiness._assert_distinct_artifacts(self.repo, receipts)

    def test_runtime_shell_dispatch_precedes_toolchain_and_build_paths(self) -> None:
        text = (ROOT / "tools/apple_runtime_smoke.sh").read_text(encoding="utf-8")
        dispatch = text.index('if [[ "${1:-}" == "--verify" ]]')
        pins = text.index('REQUIRED_FLUTTER_VERSION="$(read_wins_toolchain_pin')
        build = text.index("build_apple_apps()")
        self.assertLess(dispatch, pins)
        self.assertLess(dispatch, build)
        self.assertIn('exec "${PYTHON_BIN}"', text[dispatch:pins])


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _dummy_authentication(
    target_id: str, *, digest: str, size: int, architectures: list[str]
) -> dict[str, object]:
    return {
        "authenticated": True,
        "issuer": apple_gate.UPLOAD_RECEIPT_ISSUER,
        "run_id": "a" * 64,
        "nonce": "b" * 64,
        "issued_at": apple_gate._upload_receipt_now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "challenge": "c" * 128,
        "target_id": target_id,
        "architectures": list(architectures),
        "release": apple_gate.CANONICAL_RELEASE,
        "artifact_sha256": digest,
        "artifact_bytes": size,
    }


def _issue_receipt(record: dict[str, object]) -> dict[str, object]:
    spec = apple_gate.APPLE_PACKAGE_UPLOAD_TARGETS[str(record["target_id"])]
    artifact = record["artifact"]
    record["authentication"] = apple_gate.issue_upload_receipt_challenge(
        str(record["target_id"]),
        artifact_sha256=str(artifact["sha256"]),
        artifact_bytes=int(artifact["bytes"]),
        architectures=tuple(str(item) for item in spec["architectures"]),
        release=str(record["release"]),
    )
    return record


def _pending_owner() -> dict[str, object]:
    return {
        "contract": apple_gate.OWNER_AUTHORIZATION_CONTRACT,
        "schema_version": apple_gate.PACKAGE_UPLOAD_RECEIPT_SCHEMA_VERSION,
        "status": "pending",
        "credentials_authorized": False,
        "upload_authorized": False,
    }


def _watch_artifact_verification(
    artifact_sha256: str, artifact_bytes: int
) -> dict[str, object]:
    result = {
        "schema_version": 1,
        "bundle_id": apple_gate.WATCH_BUNDLE_ID,
        "companion_bundle_id": apple_gate.HOST_BUNDLE_ID,
        "version": apple_gate.CANONICAL_MARKETING_VERSION,
        "build_number": apple_gate.CANONICAL_BUNDLE_VERSION,
        "parent_version": apple_gate.CANONICAL_MARKETING_VERSION,
        "parent_build_number": apple_gate.CANONICAL_BUNDLE_VERSION,
        "ipa_sha256": artifact_sha256,
        "ipa_bytes": artifact_bytes,
        "executable": apple_gate.WATCH_EXECUTABLE,
        "executable_sha256": _digest("watch-executable"),
        "architectures": ["arm64", "arm64_32"],
        "watch_connectivity_dependency": "/System/Library/Frameworks/WatchConnectivity.framework/WatchConnectivity",
        "wc_session_import": "_OBJC_CLASS_$_WCSession",
        "required_selectors": ["activationState", "isReachable", "receivedApplicationContext", "sendMessage:replyHandler:errorHandler:", "session:activationDidCompleteWithState:error:", "session:didReceiveApplicationContext:", "session:didReceiveMessage:", "sessionReachabilityDidChange:"],
        "privacy_manifest_sha256": _digest("watch-privacy"),
        "debug_sections": False,
    }
    return {
        "contract": "winsvpn-watch-artifact-verification-v1",
        "artifact_sha256": artifact_sha256,
        "verifier": {
            "path": apple_gate.WATCH_ARTIFACT_VERIFIER_RELATIVE,
            "sha256": _digest("watch-verifier"),
            "reviewed_verifier": True,
        },
        "result": result,
        "result_sha256": apple_gate._canonical_json_sha256(result),
    }


def _upload_receipt(
    target_id: str,
    *,
    digest: str,
    size: int,
) -> dict[str, object]:
    spec = apple_gate.APPLE_PACKAGE_UPLOAD_TARGETS[target_id]
    suffix = apple_gate.TARGET_SUFFIXES[target_id][0]
    record: dict[str, object] = {
        "ok": True,
        "schema_version": apple_gate.PACKAGE_UPLOAD_RECEIPT_SCHEMA_VERSION,
        "contract": apple_gate.PACKAGE_UPLOAD_RECEIPT_CONTRACT,
        "release": apple_gate.CANONICAL_RELEASE,
        "target_id": target_id,
        "platform": spec["platform"],
        "artifact": {
            "path": f"artifacts/WinsVPN-{target_id}{suffix}",
            "sha256": digest,
            "bytes": size,
        },
        "build_receipt": {
            "path": f".artifacts/build-receipts/{target_id}.json",
            "sha256": _digest(f"{target_id}-build"),
            "target": spec["build_receipt_target"],
        },
        "producer": {
            "id": apple_gate.PRODUCER_RELATIVE,
            "path": apple_gate.PRODUCER_RELATIVE,
            "sha256": _digest("apple-producer"),
        },
        "bundle_ids": dict(spec["bundle_ids"]),
        "architectures": list(spec["architectures"]),
        "signing": {
            "contract": spec["signing_contract"],
            "authority": spec["expected_authority"],
            "team_id": apple_gate.TEAM_ID,
        },
        "store_evidence": {
            "surface": spec["store_surface"],
            "testflight": spec["testflight"],
            "app_store": spec["app_store"],
            "notarization": spec["notarization"],
        },
        "descriptor": {
            "path": apple_gate.DESCRIPTOR_RELATIVE,
            "sha256": _digest("apple-descriptor"),
        },
        "source_freeze": {
            "path": ".artifacts/release-freeze-1.0.17+34/SOURCE_FREEZE_RECEIPT.json",
            "sha256": _digest("apple-source"),
        },
        "obfuscation_privacy": {
            "path": apple_gate.OBFUSCATION_PRIVACY_RELATIVE,
            "sha256": _digest("apple-privacy"),
        },
        "publication_authorized": False,
        "upload_attempted": False,
        "owner_authorization": _pending_owner(),
        "authentication": _dummy_authentication(
            target_id,
            digest=digest,
            size=size,
            architectures=list(spec["architectures"]),
        ),
    }
    if target_id == "ios-app-store-ipa":
        record["watchos"] = {
            "bundle_id": apple_gate.WATCH_BUNDLE_ID,
            "companion_bundle_id": apple_gate.HOST_BUNDLE_ID,
            "version": apple_gate.CANONICAL_MARKETING_VERSION,
            "build": apple_gate.CANONICAL_BUNDLE_VERSION,
            "executable": apple_gate.WATCH_EXECUTABLE,
            "executable_sha256": _digest("watch-executable"),
            "privacy_info_sha256": _digest("watch-privacy"),
            "artifact_verification": _watch_artifact_verification(digest, size),
        }
    return record


class ApplePackageUploadReceiptBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name)
        identity = self.repo / apple_gate.RELEASE_IDENTITY_RELATIVE_PATH
        identity.parent.mkdir(parents=True)
        identity.write_bytes(
            (ROOT / apple_gate.RELEASE_IDENTITY_RELATIVE_PATH).read_bytes()
        )
        self._root = mock.patch.object(apple_gate, "ROOT", self.repo)
        self._root.start()
        self.ios_digest = _digest("ios-1.0.17+34-ipa")
        self.macos_digest = _digest("macos-1.0.17+34-pkg")
        self.dev_digest = _digest("macos-1.0.17+34-developer-id")
        self.ios_size = 11
        self.macos_size = 13
        self.dev_size = 17
        self.records = {
            "ios-app-store-ipa": _issue_receipt(
                _upload_receipt(
                    "ios-app-store-ipa", digest=self.ios_digest, size=self.ios_size
                )
            ),
            "macos-app-store-pkg": _issue_receipt(
                _upload_receipt(
                    "macos-app-store-pkg", digest=self.macos_digest, size=self.macos_size
                )
            ),
        }
        self.artifacts = {
            "ios-app-store-ipa": (self.ios_digest, self.ios_size),
            "macos-app-store-pkg": (self.macos_digest, self.macos_size),
        }

    def tearDown(self) -> None:
        self._root.stop()
        self.temporary.cleanup()

    def test_required_ios_watchos_macos_receipts_bind_canonical_release(self) -> None:
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "pending without owner evidence|no owner-issued",
        ):
            apple_gate.bind_apple_package_upload_receipts(
                self.records, self.artifacts
            )
        self.assertEqual(
            apple_gate.canonical_apple_release(), apple_gate.CANONICAL_RELEASE
        )
        ios = self.records["ios-app-store-ipa"]
        self.assertEqual(ios["bundle_ids"]["host"], "org.winsvpn.app")
        self.assertEqual(ios["bundle_ids"]["tunnel"], "org.winsvpn.app.PacketTunnel")
        self.assertEqual(ios["bundle_ids"]["watch"], "org.winsvpn.app.watchkitapp")
        self.assertEqual(ios["architectures"], ["arm64"])
        self.assertEqual(ios["store_evidence"]["testflight"], "not_uploaded")
        self.assertEqual(ios["store_evidence"]["app_store"], "not_uploaded")
        self.assertEqual(
            self.records["macos-app-store-pkg"]["architectures"], ["arm64", "x86_64"]
        )
        self.assertEqual(ios["authentication"]["authenticated"], True)
        self.assertEqual(ios["authentication"]["issuer"], apple_gate.UPLOAD_RECEIPT_ISSUER)

    def test_missing_receipts_remain_pending_without_owner_evidence(self) -> None:
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "pending without owner evidence",
        ):
            apple_gate.bind_apple_package_upload_receipts({}, {})
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "pending without owner evidence",
        ):
            apple_gate.bind_apple_package_upload_receipts(
                {"ios-app-store-ipa": self.records["ios-app-store-ipa"]},
                {"ios-app-store-ipa": self.artifacts["ios-app-store-ipa"]},
            )

    def test_schema_v1_receipt_fails_closed(self) -> None:
        self.records["ios-app-store-ipa"]["schema_version"] = 1
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "receipt binding is invalid"
        ):
            apple_gate.bind_apple_package_upload_receipts(self.records, self.artifacts)

    def test_watch_verifier_receipt_missing_or_stale_fails_closed(self) -> None:
        watch = self.records["ios-app-store-ipa"]["watchos"]
        verification = watch.pop("artifact_verification")
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "watchOS companion schema"
        ):
            apple_gate.bind_package_upload_receipt(
                "ios-app-store-ipa",
                self.records["ios-app-store-ipa"],
                artifact_sha256=self.ios_digest,
                artifact_bytes=self.ios_size,
            )
        watch["artifact_verification"] = verification
        verification["result_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "stale or substituted"
        ):
            apple_gate.bind_package_upload_receipt(
                "ios-app-store-ipa",
                self.records["ios-app-store-ipa"],
                artifact_sha256=self.ios_digest,
                artifact_bytes=self.ios_size,
            )

    def test_schema_v2_identity_fails_closed_on_v1_and_stale_release(self) -> None:
        identity_path = self.repo / apple_gate.RELEASE_IDENTITY_RELATIVE_PATH
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
        identity["schema_version"] = 1
        identity_path.write_text(json.dumps(identity) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "inconsistent"
        ):
            apple_gate.canonical_apple_release()
        identity["schema_version"] = 2
        identity["canonical_release"] = "1.0.14+29"
        identity["marketing_version"] = "1.0.14"
        identity["build_number"] = 29
        identity["platform_mappings"]["apple"]["short_version"] = "1.0.14"
        identity["platform_mappings"]["apple"]["bundle_version"] = "29"
        identity_path.write_text(json.dumps(identity) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "inconsistent"
        ):
            apple_gate.reviewed_apple_release_identity()

    def test_receipt_reuse_and_byte_swap_fail_closed(self) -> None:
        self.records["macos-app-store-pkg"]["artifact"]["sha256"] = self.ios_digest
        self.artifacts["macos-app-store-pkg"] = (self.ios_digest, self.macos_size)
        with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "receipt reuse"):
            apple_gate.bind_apple_package_upload_receipts(self.records, self.artifacts)
        self.records["macos-app-store-pkg"]["artifact"]["sha256"] = self.macos_digest
        self.artifacts["macos-app-store-pkg"] = (self.macos_digest, self.macos_size)
        self.records["macos-app-store-pkg"]["build_receipt"]["sha256"] = self.records[
            "ios-app-store-ipa"
        ]["build_receipt"]["sha256"]
        with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "receipt reuse"):
            apple_gate.bind_apple_package_upload_receipts(self.records, self.artifacts)
        self.records["macos-app-store-pkg"]["build_receipt"]["sha256"] = _digest(
            "macos-app-store-pkg-build"
        )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "swapped or does not bind"
        ):
            apple_gate.bind_package_upload_receipt(
                "ios-app-store-ipa",
                self.records["ios-app-store-ipa"],
                artifact_sha256=_digest("swapped-ipa"),
                artifact_bytes=self.ios_size,
            )

    def test_watchos_bundle_version_and_macos_architectures_fail_closed(self) -> None:
        self.records["ios-app-store-ipa"]["watchos"]["bundle_id"] = (
            "org.winsvpn.app.watchkitapp.extension"
        )
        with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "watchOS companion"):
            apple_gate.bind_apple_package_upload_receipts(self.records, self.artifacts)
        self.records["ios-app-store-ipa"]["watchos"]["bundle_id"] = (
            apple_gate.WATCH_BUNDLE_ID
        )
        self.records["macos-app-store-pkg"]["architectures"] = ["arm64"]
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "architecture inventory"
        ):
            apple_gate.bind_package_upload_receipt(
                "macos-app-store-pkg",
                self.records["macos-app-store-pkg"],
                artifact_sha256=self.macos_digest,
                artifact_bytes=self.macos_size,
            )

    def test_signing_testflight_app_store_and_privacy_bindings_fail_closed(self) -> None:
        self.records["ios-app-store-ipa"]["signing"]["authority"] = (
            "Authority=Developer ID Application:"
        )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "signing evidence"
        ):
            apple_gate.bind_apple_package_upload_receipts(self.records, self.artifacts)
        self.records["ios-app-store-ipa"]["signing"]["authority"] = (
            "Authority=Apple Distribution:"
        )
        self.records["ios-app-store-ipa"]["store_evidence"]["testflight"] = "uploaded"
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "TestFlight/App Store"
        ):
            apple_gate.bind_apple_package_upload_receipts(self.records, self.artifacts)
        self.records["ios-app-store-ipa"]["store_evidence"]["testflight"] = "not_uploaded"
        self.records["macos-app-store-pkg"]["obfuscation_privacy"]["sha256"] = "0" * 63
        with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "digest is invalid"):
            apple_gate.bind_apple_package_upload_receipts(self.records, self.artifacts)

    def test_owner_approval_inside_receipt_is_refused(self) -> None:
        self.records["ios-app-store-ipa"]["owner_authorization"]["status"] = "approved"
        self.records["ios-app-store-ipa"]["owner_authorization"][
            "upload_authorized"
        ] = True
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "remain pending without owner evidence",
        ):
            apple_gate.bind_apple_package_upload_receipts(self.records, self.artifacts)

    def test_developer_id_is_optional_and_requires_notarization(self) -> None:
        optional = _issue_receipt(
            _upload_receipt(
                "macos-developer-id-app", digest=self.dev_digest, size=self.dev_size
            )
        )
        artifacts = dict(self.artifacts)
        artifacts["macos-developer-id-app"] = (self.dev_digest, self.dev_size)
        records = dict(self.records)
        records["macos-developer-id-app"] = optional
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "pending without owner evidence|no owner-issued",
        ):
            apple_gate.bind_apple_package_upload_receipts(records, artifacts)
        optional["store_evidence"]["notarization"] = None
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "notarization"
        ):
            apple_gate.bind_package_upload_receipt(
                "macos-developer-id-app",
                optional,
                artifact_sha256=self.dev_digest,
                artifact_bytes=self.dev_size,
            )

    def test_app_store_receipts_refuse_notarization_and_non_shipping_targets(self) -> None:
        self.records["ios-app-store-ipa"]["store_evidence"]["notarization"] = (
            "Notarized Developer ID"
        )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "notarization"
        ):
            apple_gate.bind_package_upload_receipt(
                "ios-app-store-ipa",
                self.records["ios-app-store-ipa"],
                artifact_sha256=self.ios_digest,
                artifact_bytes=self.ios_size,
            )
        self.records["ios-app-store-ipa"]["store_evidence"]["notarization"] = None
        self.records["macos-app-store-pkg"]["store_evidence"]["notarization"] = (
            "Notarized Developer ID"
        )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "notarization"
        ):
            apple_gate.bind_package_upload_receipt(
                "macos-app-store-pkg",
                self.records["macos-app-store-pkg"],
                artifact_sha256=self.macos_digest,
                artifact_bytes=self.macos_size,
            )
        self.records["macos-app-store-pkg"]["store_evidence"]["notarization"] = None
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "tvOS is not a 1.0.17\\+34 shipping, upload, signing, or receipt surface",
        ):
            apple_gate.bind_package_upload_receipt(
                "tvos-app-store-ipa",
                self.records["ios-app-store-ipa"],
                artifact_sha256=self.ios_digest,
                artifact_bytes=self.ios_size,
            )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "watchOS is embedded in the iOS IPA",
        ):
            apple_gate.bind_package_upload_receipt(
                "watchos-app-store-ipa",
                self.records["ios-app-store-ipa"],
                artifact_sha256=self.ios_digest,
                artifact_bytes=self.ios_size,
            )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "tvOS is not a 1.0.17\\+34 shipping, upload, signing, or receipt surface",
        ):
            apple_gate.bind_apple_package_upload_receipts(
                {
                    **self.records,
                    "tvos-app-store-ipa": self.records["ios-app-store-ipa"],
                },
                {
                    **self.artifacts,
                    "tvos-app-store-ipa": self.artifacts["ios-app-store-ipa"],
                },
            )

    def test_stale_replayed_and_unauthenticated_receipts_fail_closed(self) -> None:
        record = self.records["ios-app-store-ipa"]
        auth = dict(record["authentication"])
        auth["issued_at"] = "2020-01-01T00:00:00Z"
        record["authentication"] = auth
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "is not fresh"
        ):
            apple_gate.bind_package_upload_receipt(
                "ios-app-store-ipa",
                record,
                artifact_sha256=self.ios_digest,
                artifact_bytes=self.ios_size,
            )
        signed = _issue_receipt(
            _upload_receipt(
                "ios-app-store-ipa", digest=self.ios_digest, size=self.ios_size
            )
        )
        signed["authentication"]["challenge"] = "d" * 128
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "not authenticated by the trusted issuer",
        ):
            apple_gate.bind_package_upload_receipt(
                "ios-app-store-ipa",
                signed,
                artifact_sha256=self.ios_digest,
                artifact_bytes=self.ios_size,
            )
        replay = _issue_receipt(
            _upload_receipt(
                "ios-app-store-ipa", digest=self.ios_digest, size=self.ios_size
            )
        )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "pending without owner evidence|no owner-issued",
        ):
            apple_gate.bind_apple_package_upload_receipts(
                {
                    "ios-app-store-ipa": replay,
                    "macos-app-store-pkg": self.records["macos-app-store-pkg"],
                },
                self.artifacts,
            )
        # Failed owner evidence must leave the issued challenge retryable.
        apple_gate._consume_upload_receipt_challenge(replay["authentication"])
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "nonce or run_id was already consumed",
        ):
            apple_gate.bind_apple_package_upload_receipts(
                {
                    "ios-app-store-ipa": replay,
                    "macos-app-store-pkg": self.records["macos-app-store-pkg"],
                },
                self.artifacts,
            )

    def test_placeholder_ed25519_trust_key_is_refused(self) -> None:
        source = pathlib.Path(apple_gate.__file__).read_text(encoding="ascii")
        self.assertNotIn("UPLOAD_RECEIPT_ISSUER_PUBLIC_KEY_HEX", source)
        self.assertNotIn("Ed25519PublicKey", source)
        self.assertNotIn("Ed25519PrivateKey", source)
        record = _upload_receipt(
            "ios-app-store-ipa", digest=self.ios_digest, size=self.ios_size
        )
        record["authentication"]["public_key"] = "cafef00d" * 8
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "placeholder"
        ):
            apple_gate.bind_package_upload_receipt(
                "ios-app-store-ipa",
                record,
                artifact_sha256=self.ios_digest,
                artifact_bytes=self.ios_size,
            )
        record = _issue_receipt(
            _upload_receipt(
                "ios-app-store-ipa", digest=self.ios_digest, size=self.ios_size
            )
        )
        record["authentication"]["signature"] = "ab" * 64
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "placeholder"
        ):
            apple_gate.bind_package_upload_receipt(
                "ios-app-store-ipa",
                record,
                artifact_sha256=self.ios_digest,
                artifact_bytes=self.ios_size,
            )

    def test_swapped_target_challenge_fails_closed(self) -> None:
        ios = _issue_receipt(
            _upload_receipt(
                "ios-app-store-ipa", digest=self.ios_digest, size=self.ios_size
            )
        )
        macos = _upload_receipt(
            "macos-app-store-pkg", digest=self.macos_digest, size=self.macos_size
        )
        macos["authentication"] = dict(ios["authentication"])
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "swapped or does not bind",
        ):
            apple_gate.bind_package_upload_receipt(
                "macos-app-store-pkg",
                macos,
                artifact_sha256=self.macos_digest,
                artifact_bytes=self.macos_size,
            )

    def test_hostile_restart_replay_fails_closed(self) -> None:
        record = _issue_receipt(
            _upload_receipt(
                "ios-app-store-ipa", digest=self.ios_digest, size=self.ios_size
            )
        )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "pending without owner evidence|no owner-issued",
        ):
            apple_gate.bind_package_upload_receipt(
                "ios-app-store-ipa",
                record,
                artifact_sha256=self.ios_digest,
                artifact_bytes=self.ios_size,
            )
        # Model a committed receipt in the journal before testing restart replay.
        apple_gate._consume_upload_receipt_challenge(record["authentication"])
        receipt_path = self.repo / "replay-receipt.json"
        receipt_path.write_text(
            json.dumps(record, ensure_ascii=True) + "\n", encoding="ascii"
        )
        script = (
            "import json, pathlib, sys\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "import apple_cross_store_artifact_gate as gate\n"
            "gate.ROOT = pathlib.Path(sys.argv[2])\n"
            "record = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding='ascii'))\n"
            "try:\n"
            "    gate.bind_package_upload_receipt(\n"
            "        'ios-app-store-ipa', record,\n"
            "        artifact_sha256=record['artifact']['sha256'],\n"
            "        artifact_bytes=int(record['artifact']['bytes']),\n"
            "    )\n"
            "except gate.AppleArtifactGateError as exc:\n"
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
        record = _issue_receipt(
            _upload_receipt(
                "ios-app-store-ipa", digest=self.ios_digest, size=self.ios_size
            )
        )
        errors: list[str] = []
        committed: list[bool] = []
        barrier = threading.Barrier(2)

        def worker() -> None:
            barrier.wait()
            try:
                apple_gate._consume_upload_receipt_challenge(record["authentication"])
                committed.append(True)
            except apple_gate.AppleArtifactGateError as exc:
                errors.append(str(exc))

        threads = [threading.Thread(target=worker), threading.Thread(target=worker)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(committed, [True])
        self.assertEqual(len(errors), 1)
        self.assertIn("already consumed", errors[0])
        journal = self.repo / apple_gate.UPLOAD_RECEIPT_JOURNAL_RELATIVE
        records = apple_gate._parse_upload_receipt_journal(journal.read_bytes())
        self.assertEqual(sum(item["kind"] == "consumed-set" for item in records), 1)

    def test_ancestor_swap_hardlink_and_special_file_fail_closed(self) -> None:
        artifacts = self.repo / "artifacts"
        artifacts.mkdir(exist_ok=True)
        payload = artifacts / "payload.bin"
        payload.write_bytes(b"good-bytes")
        real_openat = apple_gate._openat_child
        swapped = {"done": False}

        def hook(parent_fd: int, name: str, flags: int) -> int:
            child = real_openat(parent_fd, name, flags)
            if name == "artifacts" and not swapped["done"]:
                swapped["done"] = True
                artifacts.rename(self.repo / "artifacts.old")
                artifacts.mkdir()
                (artifacts / "payload.bin").write_bytes(b"evil-bytes")
            return child

        with mock.patch.object(apple_gate, "_openat_child", side_effect=hook):
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "ancestor was replaced"
            ):
                apple_gate._hash_live_repo_file("artifacts/payload.bin", "artifact")
        restored = self.repo / "artifacts.old"
        if restored.exists():
            if artifacts.exists():
                for child in artifacts.iterdir():
                    child.unlink()
                artifacts.rmdir()
            restored.rename(artifacts)
        alias = self.repo / "alias.bin"
        os.link(payload, alias)
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "single-link|hardlink|duplicate"
        ):
            apple_gate._hash_live_repo_file("artifacts/payload.bin", "artifact")
        alias.unlink()
        payload.unlink()
        os.mkfifo(payload)
        try:
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "regular single-link"
            ):
                apple_gate._hash_live_repo_file("artifacts/payload.bin", "artifact")
        finally:
            payload.unlink()

    def test_current_tree_owner_signoff_stays_pending(self) -> None:
        self.assertFalse(readiness._owner_signoff_submission_approved(ROOT))
        signoff = json.loads(
            (ROOT / readiness.OWNER_SIGNOFF).read_text(encoding="utf-8")
        )
        self.assertIs(signoff["submission_approved"], False)
        self.assertEqual(signoff["owner_authorization"]["status"], "pending")
        self.assertIs(signoff["owner_authorization"]["upload_authorized"], False)
        self.assertEqual(signoff["owner_authorization"]["evidence"]["release"], "1.0.17+34")


if __name__ == "__main__":
    unittest.main()
