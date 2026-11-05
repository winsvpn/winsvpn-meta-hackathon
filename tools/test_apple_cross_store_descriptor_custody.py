#!/usr/bin/env python3
"""Exact reproductions of Apple cross-store descriptor, SSV, ZIP, and freeze findings."""

from __future__ import annotations

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
import unicodedata
import unittest
import zipfile
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import apple_cross_store_artifact_gate as apple_gate
import apple_release_contamination_gate as contamination
import release_obfuscation_contract as obfuscation


PRIVACY = {
    "NSPrivacyTracking": False,
    "NSPrivacyTrackingDomains": [],
    "NSPrivacyCollectedDataTypes": [],
    "NSPrivacyAccessedAPITypes": [],
}


def _plist(bundle_id: str) -> bytes:
    value: dict[str, object] = {
        "CFBundleIdentifier": bundle_id,
        "CFBundleShortVersionString": "1.0.17",
        "CFBundleVersion": "34",
    }
    if bundle_id == apple_gate.HOST_BUNDLE_ID:
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


def _thin_mh_dylib(cputype: int, *, filetype: int = apple_gate.MH_DYLIB) -> bytes:
    data = bytearray(obfuscation._minimal_macho64(dwarf=False))
    struct.pack_into("<I", data, 4, cputype)
    struct.pack_into("<I", data, 12, filetype)
    return bytes(data)


def _write_engine_frameworks(archive: zipfile.ZipFile, base: str) -> None:
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
        archive.writestr(f"{framework}/{name}", _thin_mh_dylib(apple_gate.CPU_TYPE_ARM64))
        archive.writestr(f"{framework}/PrivacyInfo.xcprivacy", _privacy(api_reasons))


def _write_ios_ipa(path: pathlib.Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        base = "Payload/Win's VPN.app"
        archive.writestr(f"{base}/Info.plist", _plist(apple_gate.HOST_BUNDLE_ID))
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
        _write_engine_frameworks(archive, base)


class AppleCrossStoreDescriptorCustodyTests(unittest.TestCase):
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

    def tearDown(self) -> None:
        self._freeze_patch.stop()
        self.temporary.cleanup()

    def test_imported_module_origin_bytes_match_freeze_bound_snapshots(self) -> None:
        # The gate compiles each support module from the descriptor-held bytes
        # it hashed (no snapshot file), into a private module that is never the
        # public sys.modules entry.
        for filename, public_name in apple_gate.REQUIRED_MODULE_FILES:
            module = apple_gate._MODULES[public_name]
            origin = ROOT / "tools" / filename
            self.assertTrue(
                module.__name__.startswith(f"_winsvpn_apple_gate_{public_name}_")
            )
            self.assertEqual(pathlib.Path(module.__file__).resolve(), origin.resolve())
            self.assertEqual(
                hashlib.sha256(origin.read_bytes()).hexdigest(),
                apple_gate._MODULE_DIGESTS[public_name],
            )
            self.assertEqual(
                module.__winsvpn_source_sha256__,
                apple_gate._MODULE_DIGESTS[public_name],
            )
            self.assertIsNot(sys.modules.get(public_name), module)
            self.assertNotIn(module.__name__, sys.modules)

    def test_pythonpath_cannot_substitute_imported_support_modules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evil = pathlib.Path(tmp)
            (evil / "release_source_freeze.py").write_text(
                "raise SystemExit('poisoned-freeze')\n", encoding="utf-8"
            )
            (evil / "release_obfuscation_contract.py").write_text(
                "raise SystemExit('poisoned-obfuscation')\n", encoding="utf-8"
            )
            (evil / "apple_release_contamination_gate.py").write_text(
                "raise SystemExit('poisoned-privacy')\n", encoding="utf-8"
            )
            env = os.environ.copy()
            env["PYTHONPATH"] = str(evil) + os.pathsep + str(ROOT / "tools")
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import sys; "
                    f"sys.path[:0] = [{str(evil)!r}, {str(ROOT / 'tools')!r}]; "
                    "import apple_cross_store_artifact_gate as g; "
                    "print(g.source_freeze.LOCK_CONTRACT); "
                    "print(g.contamination.CONTRACT_VALUE)",
                ],
                cwd=str(ROOT),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("winsvpn-app-source-lock-v1", completed.stdout)
        self.assertIn("apple-release-no-live-smoke-v1", completed.stdout)
        self.assertNotIn("poisoned", completed.stdout + completed.stderr)

    def test_sys_modules_poisoning_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evil = pathlib.Path(tmp) / "release_obfuscation_contract.py"
            evil.write_text("ObfuscationError = RuntimeError\n", encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import sys, types, pathlib;"
                    f"p = pathlib.Path({str(evil)!r});"
                    "fake = types.ModuleType('release_obfuscation_contract');"
                    "fake.__file__ = str(p);"
                    "fake.ObfuscationError = RuntimeError;"
                    "sys.modules['release_obfuscation_contract'] = fake;"
                    "import apple_cross_store_artifact_gate as g;"
                    "assert g.obfuscation is not fake;"
                    "assert g.ObfuscationError is not RuntimeError;"
                    "assert g.obfuscation.__winsvpn_source_sha256__"
                    " == g._MODULE_DIGESTS['release_obfuscation_contract'];"
                    "assert sys.modules['release_obfuscation_contract'] is fake;"
                    "print('reviewed-closure-bound')",
                ],
                cwd=str(ROOT / "tools"),
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        # The gate rejects the poisoned public module as its dependency: it
        # binds the descriptor-held reviewed bytes instead, and hands the
        # caller's sys.modules entry back untouched (the same ignore-and-isolate
        # contract as the submission validator and obfuscation loaders).
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("reviewed-closure-bound", completed.stdout)

    def _absent_source_freeze_trust_file(self):
        return mock.patch.object(
            apple_gate.source_freeze,
            "verified_release_source_state",
            side_effect=apple_gate.source_freeze.SourceFreezeError(
                "No immutable APP_SOURCE_LOCK"
            ),
        )

    def test_support_custody_does_not_require_source_freeze_trust_file(self) -> None:
        probe = apple_gate._support_custody_operation(lambda value: ("ran", value))
        self._freeze_patch.stop()
        try:
            with self._absent_source_freeze_trust_file() as freeze:
                self.assertEqual(probe(7), ("ran", 7))
                freeze.assert_not_called()
        finally:
            self._freeze_patch.start()

    def test_support_custody_still_rejects_changed_support_bytes(self) -> None:
        ran: list[bool] = []
        probe = apple_gate._support_custody_operation(lambda: ran.append(True))
        for filename, public_name in apple_gate.REQUIRED_MODULE_FILES:
            with self.subTest(module=public_name), mock.patch.dict(
                apple_gate._MODULE_DIGESTS, {public_name: "0" * 64}
            ):
                with self.assertRaisesRegex(
                    apple_gate.AppleArtifactGateError,
                    "imported support module origin bytes changed: " + filename,
                ):
                    probe()
        self.assertEqual(ran, [])

    def test_support_custody_rehashes_support_bytes_per_operation(self) -> None:
        held: list[object] = []
        original = apple_gate._HeldSupportSources

        def holding(*args, **kwargs):
            custody = original(*args, **kwargs)
            held.append(custody)
            return custody

        probe = apple_gate._support_custody_operation(lambda: len(held))
        with mock.patch.object(apple_gate, "_HeldSupportSources", side_effect=holding):
            self.assertEqual(probe(), 1)
            self.assertEqual(probe(), 2)
        self.assertEqual(
            [custody.digests for custody in held],
            [
                {
                    filename: apple_gate._MODULE_DIGESTS[public_name]
                    for filename, public_name in apple_gate.REQUIRED_MODULE_FILES
                }
            ]
            * 2,
        )

    def test_native_host_source_closure_does_not_require_source_freeze(self) -> None:
        self._freeze_patch.stop()
        try:
            with self._absent_source_freeze_trust_file() as freeze:
                digest = apple_gate.bind_macos_native_host_source_freeze()
                freeze.assert_not_called()
        finally:
            self._freeze_patch.start()
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(digest, apple_gate.compute_macos_native_host_source_closure()[0])

    def test_native_host_source_closure_binds_exact_single_link_sources(self) -> None:
        source = self.repo / "tools" / "native.sh"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"#!/bin/sh\necho one\n")
        with mock.patch.object(apple_gate, "ORIGIN_ROOT", self.repo), mock.patch.object(
            apple_gate, "macos_native_host_source_paths", return_value=("tools/native.sh",)
        ):
            first = apple_gate.compute_macos_native_host_source_closure()[0]
            with mock.patch.object(
                apple_gate, "MACOS_NATIVE_HOST_SOURCE_CLOSURE_SHA256", first
            ):
                self.assertEqual(apple_gate.bind_macos_native_host_source_freeze(), first)
            source.write_bytes(b"#!/bin/sh\necho two\n")
            self.assertNotEqual(
                apple_gate.compute_macos_native_host_source_closure()[0], first
            )
            alias = self.repo / "tools" / "alias.sh"
            os.link(source, alias)
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "single-link file"
            ):
                apple_gate.bind_macos_native_host_source_freeze()
            alias.unlink()
            source.unlink()
            with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "is missing"):
                apple_gate.bind_macos_native_host_source_freeze()

    def test_native_host_source_closure_pin_equals_the_committed_inputs(self) -> None:
        # Recomputed from the repository files here, not through the gate's
        # closure function: path, SHA-256 and size of every present input.
        records = []
        for relative in apple_gate.macos_native_host_source_paths():
            path = ROOT / relative
            if relative == apple_gate.OPTIONAL_NATIVE_HOST_SOURCE and not path.is_file():
                continue
            payload = path.read_bytes()
            records.append(
                {
                    "path": relative,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "bytes": len(payload),
                }
            )
        encoded = (
            json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n"
        ).encode("ascii")
        self.assertEqual(len(records), 17)
        self.assertIn(
            apple_gate.OPTIONAL_NATIVE_HOST_SOURCE, [record["path"] for record in records]
        )
        self.assertEqual(
            hashlib.sha256(encoded).hexdigest(),
            apple_gate.MACOS_NATIVE_HOST_SOURCE_CLOSURE_SHA256,
        )
        self.assertEqual(
            apple_gate.bind_macos_native_host_source_freeze(),
            apple_gate.MACOS_NATIVE_HOST_SOURCE_CLOSURE_SHA256,
        )

    def test_native_host_source_closure_edit_is_refused_against_the_pin(self) -> None:
        relatives = apple_gate.macos_native_host_source_paths()
        for relative in relatives:
            source = ROOT / relative
            if not source.is_file():
                continue
            copy = self.repo / relative
            copy.parent.mkdir(parents=True, exist_ok=True)
            copy.write_bytes(source.read_bytes())
        pinned = apple_gate.MACOS_NATIVE_HOST_SOURCE_CLOSURE_SHA256
        with mock.patch.object(apple_gate, "ORIGIN_ROOT", self.repo):
            self.assertEqual(apple_gate.bind_macos_native_host_source_freeze(), pinned)
            edited = self.repo / "tools/native_messaging/host/pubspec.yaml"
            original = edited.read_bytes()
            edited.write_bytes(original + b"\n")
            current = apple_gate.compute_macos_native_host_source_closure()[0]
            self.assertNotEqual(current, pinned)
            with self.assertRaises(apple_gate.AppleArtifactGateError) as raised:
                apple_gate.bind_macos_native_host_source_freeze()
            self.assertEqual(
                str(raised.exception),
                f"native-host source closure changed: reviewed={pinned} current={current}; "
                "review the changed inputs and update "
                "MACOS_NATIVE_HOST_SOURCE_CLOSURE_SHA256 in the same change",
            )
            edited.write_bytes(original)
            self.assertEqual(apple_gate.bind_macos_native_host_source_freeze(), pinned)
            (self.repo / apple_gate.OPTIONAL_NATIVE_HOST_SOURCE).unlink()
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "native-host source closure changed"
            ):
                apple_gate.bind_macos_native_host_source_freeze()

    def test_pathname_only_system_tool_is_owner_environment_blocked(self) -> None:
        self.assertEqual(
            apple_gate._reviewed_tool("/usr/bin/codesign"), "/usr/bin/codesign"
        )
        with tempfile.TemporaryDirectory() as temporary:
            fake = pathlib.Path(temporary) / "codesign"
            fake.write_bytes(pathlib.Path("/usr/bin/codesign").read_bytes()[:64] + b"\n")
            os.chmod(fake, 0o755)
            with mock.patch.object(
                apple_gate,
                "REVIEWED_APPLE_TOOLS",
                frozenset({str(fake)}),
            ):
                with self.assertRaisesRegex(
                    apple_gate.AppleArtifactGateError,
                    "owner/environment blocker",
                ):
                    apple_gate._reviewed_tool(str(fake))

    def test_canonical_parent_symlink_cannot_rebind_artifact(self) -> None:
        real = self.repo / "real-artifacts"
        real.mkdir()
        ipa = real / "WinsVPN.ipa"
        ipa.write_bytes(b"payload" + (b"\x00" * 64))
        (self.repo / "artifacts").rmdir()
        (self.repo / "artifacts").symlink_to(real)
        with mock.patch.object(apple_gate, "ROOT", self.repo):
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "symlink"
            ):
                apple_gate.canonical_artifact(
                    "ios-app-store-ipa", "artifacts/WinsVPN.ipa"
                )

    def test_intermediate_parent_symlink_cannot_rebind_execution_target(self) -> None:
        root = self.repo / "private-root"
        root.mkdir()
        private = apple_gate._prepare_private_root(root)
        token = apple_gate._PRIVATE_ROOT.set(private)
        try:
            nested = private.tree_dir / "nested"
            nested.mkdir()
            payload = nested / "file.bin"
            payload.write_bytes(b"data")
            outside = self.repo / "outside"
            outside.mkdir()
            (outside / "file.bin").write_bytes(b"evil")
            payload.unlink()
            nested.rmdir()
            nested.symlink_to(outside)
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "symlink"
            ):
                apple_gate._bind_execution_target(
                    private.tree_dir / "nested" / "file.bin"
                )
        finally:
            apple_gate._PRIVATE_ROOT.reset(token)
            apple_gate._cleanup_private_root(private)

    def test_codesign_uses_sealed_inspect_and_volfs_tools_keep_kernel_paths(
        self,
    ) -> None:
        ipa = self.repo / "artifacts" / "WinsVPN.ipa"
        _write_ios_ipa(ipa)
        original = str(ipa)
        recorded: list[list[str]] = []

        def bounded(argv, label, **kwargs):
            command = list(argv)
            if command[:2] == [apple_gate.XCRUN, "--find"]:
                return subprocess.run(
                    command, capture_output=True, check=False, env=kwargs["env"]
                )
            recorded.append(command)
            self.assertNotIn(original, command)
            targets = [
                argument
                for argument in command[1:]
                if argument.startswith("/") and not argument.startswith("/usr/")
            ]
            self.assertTrue(targets, msg=command)
            for target in targets:
                self.assertNotEqual(target, original)
                if command[0] in apple_gate.NON_VOLFS_ARGV_TOOLS:
                    self.assertFalse(target.startswith("/.vol/"), msg=command)
                else:
                    self.assertTrue(target.startswith("/.vol/"), msg=command)
            if command[0] == "/usr/bin/codesign" and "-d" in command:
                return subprocess.CompletedProcess(
                    command,
                    0,
                    b"",
                    b"Authority=Apple Distribution: Win's VPN Inc "
                    b"(5YT8H4U72M)\nTeamIdentifier=5YT8H4U72M\n",
                )
            return subprocess.CompletedProcess(command, 0, b"", b"")

        # Every gate tool runs through _bounded_subprocess (the no-fork
        # boundary); patching subprocess.run no longer intercepts them.
        with mock.patch.object(apple_gate, "ROOT", self.repo), mock.patch.object(
            apple_gate, "_bounded_subprocess", side_effect=bounded
        ):
            apple_gate.verify_signature("ios-app-store-ipa", "artifacts/WinsVPN.ipa")
        self.assertTrue(any(argv[0] == "/usr/bin/codesign" for argv in recorded))
        for argv in recorded:
            self.assertNotIn(original, argv)

    def test_ios_ipa_fixture_binds_the_four_type_host_privacy_contract(self) -> None:
        ipa = self.repo / "artifacts" / "WinsVPN.ipa"
        _write_ios_ipa(ipa)
        with zipfile.ZipFile(ipa) as archive:
            host = plistlib.loads(archive.read("Payload/Win's VPN.app/PrivacyInfo.xcprivacy"))
            tunnel = plistlib.loads(
                archive.read(
                    "Payload/Win's VPN.app/PlugIns/PacketTunnel.appex/PrivacyInfo.xcprivacy"
                )
            )
            collected = {
                item["NSPrivacyCollectedDataType"]
                for item in host["NSPrivacyCollectedDataTypes"]
            }
        self.assertEqual(collected, set(apple_gate.HOST_PRIVACY_COLLECTED_TYPES))
        self.assertIn(
            "NSPrivacyCollectedDataTypeProductInteraction",
            collected,
        )
        self.assertEqual(tunnel["NSPrivacyCollectedDataTypes"], [])
        self.assertFalse(host["NSPrivacyTracking"])
        self.assertFalse(tunnel["NSPrivacyTracking"])

    def test_lipo_nm_otool_consume_volfs_of_bound_private_file(self) -> None:
        root = self.repo / "tool-root"
        root.mkdir()
        private = apple_gate._prepare_private_root(root)
        token = apple_gate._PRIVATE_ROOT.set(private)
        payload = private.tree_dir / "bin"
        payload.write_bytes(b"\x00" * 64)
        lexical = str(payload)
        recorded: list[list[str]] = []

        def bounded(argv, label, **kwargs):
            if argv[:2] == [apple_gate.XCRUN, "--find"]:
                return subprocess.run(argv, capture_output=True, check=False, env=kwargs["env"])
            recorded.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, b"arm64\n", b"")

        try:
            with mock.patch.object(apple_gate, "_bounded_subprocess", side_effect=bounded):
                apple_gate._run_on_path(
                    ["/usr/bin/lipo", "-archs"], payload, "Mach-O architecture inspection"
                )
                apple_gate._run_on_path(
                    [apple_gate.XCRUN, "otool-classic", "-l"], payload,
                    "Mach-O load-command inspection",
                )
                apple_gate._run_on_path(
                    ["/usr/bin/nm", "-a"], payload, "Mach-O symbol-table inspection"
                )
        finally:
            apple_gate._PRIVATE_ROOT.reset(token)
            apple_gate._cleanup_private_root(private)
        self.assertEqual(len(recorded), 3)
        for argv in recorded:
            self.assertTrue(argv[-1].startswith("/.vol/"), msg=argv)
            self.assertNotEqual(argv[-1], lexical)

    def test_zip_ratio_bomb_is_rejected_before_extract(self) -> None:
        archive_path = self.repo / "artifacts" / "bomb.ipa"
        with zipfile.ZipFile(
            archive_path, "w", compression=zipfile.ZIP_DEFLATED
        ) as archive:
            archive.writestr("Payload/zeros.bin", b"\x00" * (1024 * 64))
        with zipfile.ZipFile(archive_path) as archive:
            member = archive.getinfo("Payload/zeros.bin")
            self.assertGreater(member.file_size / max(member.compress_size, 1), 8)
            with mock.patch.object(apple_gate, "MAX_COMPRESSION_RATIO", 2):
                with self.assertRaisesRegex(
                    apple_gate.AppleArtifactGateError, "compression ratio"
                ):
                    apple_gate._safe_zip_members(archive)

    def test_unicode_normalization_alias_is_rejected(self) -> None:
        nfc = "cafe\u00e9.bin"
        nfd = unicodedata.normalize("NFD", nfc)
        self.assertNotEqual(nfc, nfd)
        archive_path = self.repo / "artifacts" / "alias.ipa"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr(f"Payload/{nfd}", b"alias")
        with zipfile.ZipFile(archive_path) as archive:
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "Unicode-normalization alias"
            ):
                apple_gate._safe_zip_members(archive)

    def test_zip_extract_refuses_declared_size_overrun(self) -> None:
        archive_path = self.repo / "artifacts" / "overrun.ipa"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("Payload/a.bin", b"abcdef")
        root = self.repo / "zip-root"
        root.mkdir()
        private = apple_gate._prepare_private_root(root)
        token = apple_gate._PRIVATE_ROOT.set(private)
        try:
            snapshot = apple_gate._snapshot_pkg(
                archive_path, private.snapshot_file
            )
            archive = apple_gate._zipfile_from_snapshot(snapshot)
            try:
                members = apple_gate._safe_zip_members(archive)
                real_open = archive.open

                def open_overrun(member, mode="r"):
                    handle = real_open(member, mode)

                    class Extra:
                        def read(self, n=-1):
                            data = handle.read(n)
                            if not data:
                                return b""
                            return data + b"EXTRA"

                        def close(self) -> None:
                            handle.close()

                        def __enter__(self):
                            return self

                        def __exit__(self, *args) -> None:
                            handle.close()

                    return Extra()

                archive.open = open_overrun  # type: ignore[method-assign]
                apple_gate._mkdir_private_relative(private.root / "ipa")
                with self.assertRaisesRegex(
                    apple_gate.AppleArtifactGateError, "bounded preallocation"
                ):
                    apple_gate._extract_zip_members(
                        archive, private.root / "ipa", members
                    )
            finally:
                archive.close()
                snapshot.close()
        finally:
            apple_gate._PRIVATE_ROOT.reset(token)
            apple_gate._cleanup_private_root(private)

    def test_cleanup_refuses_substituted_symlink_without_following_chmod(self) -> None:
        root = self.repo / "cleanup-root"
        root.mkdir()
        private = apple_gate._prepare_private_root(root)
        victim = self.repo / "victim"
        victim.write_bytes(b"secret")
        os.chmod(victim, 0o644)
        target = private.tree_dir / "payload.bin"
        target.write_bytes(b"inner")
        os.chmod(target, 0o400)
        os.unlink(target)
        target.symlink_to(victim)
        apple_gate._cleanup_private_root(private)
        self.assertEqual(stat.S_IMODE(victim.stat().st_mode), 0o644)
        self.assertTrue(victim.exists())
        self.assertFalse(target.exists())
        self.assertFalse(target.is_symlink())

    def test_descriptor_source_and_privacy_receipt_binding_refuses_reuse(self) -> None:
        identity = self.repo / apple_gate.RELEASE_IDENTITY_RELATIVE_PATH
        with mock.patch.object(apple_gate, "ROOT", self.repo):
            digest = hashlib.sha256(b"ios-descriptor-bytes").hexdigest()
            record = {
                "ok": True,
                "schema_version": 2,
                "contract": apple_gate.PACKAGE_UPLOAD_RECEIPT_CONTRACT,
                "release": "1.0.17+34",
                "target_id": "ios-app-store-ipa",
                "platform": "ios",
                "artifact": {
                    "path": "artifacts/WinsVPN.ipa",
                    "sha256": digest,
                    "bytes": 64,
                },
                "build_receipt": {
                    "path": ".artifacts/IOS_BUILD_RECEIPT.json",
                    "sha256": hashlib.sha256(b"ios-build").hexdigest(),
                    "target": "app-store-connect",
                },
                "producer": {
                    "id": "tools/apple_runtime_smoke.sh",
                    "path": "tools/apple_runtime_smoke.sh",
                    "sha256": hashlib.sha256(b"ios-producer").hexdigest(),
                },
                "bundle_ids": {
                    "host": apple_gate.HOST_BUNDLE_ID,
                    "tunnel": apple_gate.TUNNEL_BUNDLE_ID,
                    "watch": apple_gate.WATCH_BUNDLE_ID,
                },
                "architectures": ["arm64"],
                "signing": {
                    "contract": "apple-distribution",
                    "authority": "Authority=Apple Distribution:",
                    "team_id": apple_gate.TEAM_ID,
                },
                "store_evidence": {
                    "surface": "apple-app-store-iphone-watch",
                    "testflight": "not_uploaded",
                    "app_store": "not_uploaded",
                    "notarization": None,
                },
                "descriptor": {
                    "path": "tools/apple_cross_store_artifact_gate.py",
                    "sha256": hashlib.sha256(
                        (ROOT / "tools/apple_cross_store_artifact_gate.py").read_bytes()
                    ).hexdigest(),
                },
                "source_freeze": {
                    "path": ".artifacts/SOURCE_FREEZE_RECEIPT.json",
                    "sha256": hashlib.sha256(b"ios-source").hexdigest(),
                },
                "obfuscation_privacy": {
                    "path": apple_gate.OBFUSCATION_PRIVACY_RELATIVE,
                    "sha256": hashlib.sha256(
                        (ROOT / apple_gate.OBFUSCATION_PRIVACY_RELATIVE).read_bytes()
                    ).hexdigest(),
                },
                "publication_authorized": False,
                "upload_attempted": False,
                "owner_authorization": {
                    "contract": apple_gate.OWNER_AUTHORIZATION_CONTRACT,
                    "schema_version": 2,
                    "status": "pending",
                    "credentials_authorized": False,
                    "upload_authorized": False,
                },
                "authentication": {
                    "authenticated": True,
                    "issuer": apple_gate.UPLOAD_RECEIPT_ISSUER,
                    "run_id": "a" * 64,
                    "nonce": "b" * 64,
                    "issued_at": apple_gate._upload_receipt_now().strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                    "challenge": "c" * 128,
                    "target_id": "ios-app-store-ipa",
                    "architectures": ["arm64"],
                    "release": "1.0.17+34",
                    "artifact_sha256": digest,
                    "artifact_bytes": 64,
                },
                "watchos": {
                    "bundle_id": apple_gate.WATCH_BUNDLE_ID,
                    "companion_bundle_id": apple_gate.HOST_BUNDLE_ID,
                    "version": "1.0.17",
                    "build": "34",
                    "executable": "WinsWatch",
                    "executable_sha256": hashlib.sha256(b"watch-exec").hexdigest(),
                    "privacy_info_sha256": hashlib.sha256(b"watch-privacy").hexdigest(),
                    "artifact_verification": {
                        "contract": "winsvpn-watch-artifact-verification-v1",
                        "artifact_sha256": digest,
                        "verifier": {
                            "path": apple_gate.WATCH_ARTIFACT_VERIFIER_RELATIVE,
                            "sha256": hashlib.sha256(b"watch-verifier").hexdigest(),
                            "reviewed_verifier": True,
                        },
                        "result": {
                            "schema_version": 1,
                            "bundle_id": apple_gate.WATCH_BUNDLE_ID,
                            "companion_bundle_id": apple_gate.HOST_BUNDLE_ID,
                            "version": apple_gate.CANONICAL_MARKETING_VERSION,
                            "build_number": apple_gate.CANONICAL_BUNDLE_VERSION,
                            "parent_version": apple_gate.CANONICAL_MARKETING_VERSION,
                            "parent_build_number": apple_gate.CANONICAL_BUNDLE_VERSION,
                            "ipa_sha256": digest,
                            "ipa_bytes": 64,
                            "executable": apple_gate.WATCH_EXECUTABLE,
                            "executable_sha256": hashlib.sha256(b"watch-exec").hexdigest(),
                            "architectures": ["arm64", "arm64_32"],
                            "watch_connectivity_dependency": "/System/Library/Frameworks/WatchConnectivity.framework/WatchConnectivity",
                            "wc_session_import": "_OBJC_CLASS_$_WCSession",
                            "required_selectors": ["activationState", "isReachable", "receivedApplicationContext", "sendMessage:replyHandler:errorHandler:", "session:activationDidCompleteWithState:error:", "session:didReceiveApplicationContext:", "session:didReceiveMessage:", "sessionReachabilityDidChange:"],
                            "privacy_manifest_sha256": hashlib.sha256(b"watch-privacy").hexdigest(),
                            "debug_sections": False,
                        },
                        "result_sha256": "",
                    },
                },
            }
            record["watchos"]["artifact_verification"]["result_sha256"] = (
                apple_gate._canonical_json_sha256(
                    record["watchos"]["artifact_verification"]["result"]
                )
            )
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError,
                "not authenticated by the trusted issuer",
            ):
                apple_gate.bind_package_upload_receipt(
                    "ios-app-store-ipa",
                    record,
                    artifact_sha256=digest,
                    artifact_bytes=64,
                )
            record["source_freeze"]["sha256"] = record["descriptor"]["sha256"]
            with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "receipt reuse"):
                apple_gate.bind_package_upload_receipt(
                    "ios-app-store-ipa",
                    record,
                    artifact_sha256=digest,
                    artifact_bytes=64,
                )
            record["source_freeze"]["sha256"] = hashlib.sha256(b"ios-source").hexdigest()
            record["authentication"]["public_key"] = "cafef00d" * 8
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "placeholder"
            ):
                apple_gate.bind_package_upload_receipt(
                    "ios-app-store-ipa",
                    record,
                    artifact_sha256=digest,
                    artifact_bytes=64,
                )
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
                    apple_gate._hash_live_repo_file(
                        "artifacts/payload.bin", "artifact"
                    )
        self.assertTrue(identity.is_file())


if __name__ == "__main__":
    unittest.main()
