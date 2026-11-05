#!/usr/bin/env python3
"""Regressions for exact Linux/Windows obfuscation-manifest identity."""

from __future__ import annotations

import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
import zipfile
from unittest import mock

TOOLS = pathlib.Path(__file__).resolve().parent
ROOT = TOOLS.parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import release_obfuscation_contract as obfuscation
import validate_release_artifact_privacy as privacy
import windows_cross_store_artifact_gate as windows_gate


LINUX_SCRIPT = ROOT / "tools/build_linux_release.sh"
WINDOWS_SCRIPT = ROOT / "installer/windows/build_installer.ps1"
SIX_TARGETS = (
    "linux-x64-package",
    "linux-arm64-package",
    "windows-x64-installer",
    "windows-x64-partner-center",
    "windows-arm64-installer",
    "windows-arm64-partner-center",
)


class ExactObfuscationManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.private_root = pathlib.Path(self.temporary.name).resolve() / "private-release-symbols"
        self.private_root.mkdir(parents=True)
        self.version_patch = mock.patch.object(
            obfuscation, "pubspec_version", return_value=("1.0.15", "30")
        )
        self.root_patch = mock.patch.object(obfuscation, "PRIVATE_SYMBOL_ROOT", self.private_root)
        self.static_patch = mock.patch.object(obfuscation, "validate_static")
        self.hardening_patch = mock.patch.object(
            obfuscation, "verify_release_artifact_hardening"
        )
        self.version_patch.start()
        self.root_patch.start()
        self.static_patch.start()
        self.hardening_patch.start()

    def tearDown(self) -> None:
        self.hardening_patch.stop()
        self.static_patch.stop()
        self.root_patch.stop()
        self.version_patch.stop()
        self.temporary.cleanup()

    def _prepare_target(self, target_id: str) -> tuple[dict[str, object], pathlib.Path]:
        layout = obfuscation.exact_obfuscation_layout(target_id)
        symbols_dir = pathlib.Path(str(layout["symbols_dir"]))
        symbols_dir.mkdir(parents=True, exist_ok=True)
        symbol_file = symbols_dir / "app.symbols"
        if not symbol_file.exists():
            symbol_file.write_bytes(b"s" * 128)
        artifact_dir = self.private_root.parent / "artifacts"
        artifact_dir.mkdir(exist_ok=True)
        artifact = artifact_dir / str(layout["artifact_name"])
        artifact.write_bytes(b"artifact-" + target_id.encode("ascii"))
        return layout, artifact

    def test_six_targets_have_distinct_immutable_manifests(self) -> None:
        manifests = []
        for target_id in SIX_TARGETS:
            layout = obfuscation.exact_obfuscation_layout(target_id)
            manifests.append(pathlib.Path(str(layout["manifest"])))
        self.assertEqual(len(manifests), len(set(manifests)))
        linux = [
            obfuscation.exact_obfuscation_layout(target_id)
            for target_id in ("linux-x64-package", "linux-arm64-package")
        ]
        self.assertNotEqual(linux[0]["symbols_dir"], linux[1]["symbols_dir"])
        for architecture in ("x64", "arm64"):
            website = obfuscation.exact_obfuscation_layout(f"windows-{architecture}-installer")
            partner = obfuscation.exact_obfuscation_layout(
                f"windows-{architecture}-partner-center"
            )
            self.assertEqual(website["symbols_dir"], partner["symbols_dir"])
            self.assertNotEqual(website["manifest"], partner["manifest"])
            self.assertTrue(str(website["manifest"]).endswith("manifest-website.json"))
            self.assertTrue(str(partner["manifest"]).endswith("manifest-partner-center.json"))

    def test_shared_architecture_windows_records_remain_independently_verifiable(self) -> None:
        for architecture in ("x64", "arm64"):
            with self.subTest(architecture=architecture):
                first_id = f"windows-{architecture}-installer"
                second_id = f"windows-{architecture}-partner-center"
                first_layout, first_artifact = self._prepare_target(first_id)
                second_layout, second_artifact = self._prepare_target(second_id)
                obfuscation.record(
                    "windows",
                    pathlib.Path(str(first_layout["symbols_dir"])),
                    pathlib.Path(str(first_layout["manifest"])),
                    [first_artifact],
                    first_id,
                )
                first_bytes = pathlib.Path(str(first_layout["manifest"])).read_bytes()
                obfuscation.record(
                    "windows",
                    pathlib.Path(str(second_layout["symbols_dir"])),
                    pathlib.Path(str(second_layout["manifest"])),
                    [second_artifact],
                    second_id,
                )
                self.assertEqual(
                    pathlib.Path(str(first_layout["manifest"])).read_bytes(),
                    first_bytes,
                )
                obfuscation.verify(
                    "windows",
                    pathlib.Path(str(first_layout["manifest"])),
                    pathlib.Path(str(first_layout["symbols_dir"])),
                    [first_artifact],
                    first_id,
                )
                obfuscation.verify(
                    "windows",
                    pathlib.Path(str(second_layout["manifest"])),
                    pathlib.Path(str(second_layout["symbols_dir"])),
                    [second_artifact],
                    second_id,
                )
                with self.assertRaisesRegex(obfuscation.ObfuscationError, "immutable"):
                    obfuscation.verify(
                        "windows",
                        pathlib.Path(str(second_layout["manifest"])),
                        pathlib.Path(str(second_layout["symbols_dir"])),
                        [second_artifact],
                        first_id,
                    )

    def test_windows_unsigned_local_installer_names_bind_the_same_exact_targets(self) -> None:
        # build_installer.ps1 -AllowUnsigned writes WinsVPN-UNSIGNED-LOCAL-*; the exact-target
        # record then failed with "does not match artifact WinsVPN-UNSIGNED-LOCAL-Setup.exe"
        # although the privacy validator accepts that name for the same target.
        for target_id, unsigned in obfuscation.WINDOWS_UNSIGNED_LOCAL_ARTIFACT_NAMES.items():
            with self.subTest(target=target_id):
                layout = obfuscation.exact_obfuscation_layout(target_id)
                canonical = obfuscation.EXACT_PACKAGE_TARGET_ARTIFACT_NAMES[target_id]
                self.assertEqual(layout["artifact_names"], (canonical, unsigned))
                self.assertEqual(
                    {name.lower() for name in layout["artifact_names"]},
                    set(privacy.TARGET_CANONICAL_FILENAMES[target_id]),
                )
                self.assertEqual(
                    obfuscation._privacy_target_for_release_artifact(
                        "windows", pathlib.Path(unsigned)
                    ),
                    target_id,
                )
                symbols_dir = pathlib.Path(str(layout["symbols_dir"]))
                symbols_dir.mkdir(parents=True, exist_ok=True)
                (symbols_dir / "app.symbols").write_bytes(b"s" * 128)
                artifact_dir = self.private_root.parent / "unsigned-artifacts"
                artifact_dir.mkdir(exist_ok=True)
                artifact = artifact_dir / unsigned
                artifact.write_bytes(b"unsigned-" + target_id.encode("ascii"))
                manifest = pathlib.Path(str(layout["manifest"]))
                obfuscation.record("windows", symbols_dir, manifest, [artifact], target_id)
                obfuscation.verify("windows", manifest, symbols_dir, [artifact], target_id)
        other = obfuscation.exact_obfuscation_layout("windows-arm64-installer")
        self.assertFalse(
            obfuscation._artifact_matches_exact_layout("WinsVPN-UNSIGNED-LOCAL-Setup.exe", other)
        )

    def test_artifact_hardlink_is_never_accepted(self) -> None:
        _layout, artifact = self._prepare_target("windows-x64-installer")
        hardlink = artifact.with_name("hardlink.exe")
        os.link(artifact, hardlink)
        with self.assertRaisesRegex(obfuscation.ObfuscationError, "unsafe or empty"):
            obfuscation.inspect_artifacts([artifact])

    def test_verify_refuses_artifact_changed_during_hardening(self) -> None:
        target_id = "windows-x64-installer"
        layout, artifact = self._prepare_target(target_id)
        symbols_dir = pathlib.Path(str(layout["symbols_dir"]))
        manifest = pathlib.Path(str(layout["manifest"]))
        obfuscation.record(
            "windows", symbols_dir, manifest, [artifact], target_id
        )

        def replace_during_hardening(
            _platform, _artifacts, privacy_target_id=None, defer_secret_scan=None
        ):
            self.assertEqual(privacy_target_id, target_id)
            artifact.write_bytes(b"changed-during-hardening")

        obfuscation.verify_release_artifact_hardening.side_effect = (
            replace_during_hardening
        )
        with self.assertRaisesRegex(obfuscation.ObfuscationError, "changed while"):
            obfuscation.verify(
                "windows", manifest, symbols_dir, [artifact], target_id
            )

    def test_linux_architectures_record_without_overwriting(self) -> None:
        first_layout, first_artifact = self._prepare_target("linux-x64-package")
        second_layout, second_artifact = self._prepare_target("linux-arm64-package")
        obfuscation.record(
            "linux",
            pathlib.Path(str(first_layout["symbols_dir"])),
            pathlib.Path(str(first_layout["manifest"])),
            [first_artifact],
            "linux-x64-package",
        )
        first_bytes = pathlib.Path(str(first_layout["manifest"])).read_bytes()
        obfuscation.record(
            "linux",
            pathlib.Path(str(second_layout["symbols_dir"])),
            pathlib.Path(str(second_layout["manifest"])),
            [second_artifact],
            "linux-arm64-package",
        )
        self.assertEqual(
            pathlib.Path(str(first_layout["manifest"])).read_bytes(),
            first_bytes,
        )
        obfuscation.verify(
            "linux",
            pathlib.Path(str(first_layout["manifest"])),
            pathlib.Path(str(first_layout["symbols_dir"])),
            [first_artifact],
            "linux-x64-package",
        )
        obfuscation.verify(
            "linux",
            pathlib.Path(str(second_layout["manifest"])),
            pathlib.Path(str(second_layout["symbols_dir"])),
            [second_artifact],
            "linux-arm64-package",
        )

    def test_unbound_schema_cannot_green_exact_target_verification(self) -> None:
        layout, artifact = self._prepare_target("windows-x64-installer")
        obfuscation.record(
            "windows",
            pathlib.Path(str(layout["symbols_dir"])),
            pathlib.Path(str(layout["manifest"])),
            [artifact],
            "windows-x64-installer",
        )
        payload = json.loads(pathlib.Path(str(layout["manifest"])).read_text(encoding="utf-8"))
        payload.pop("target_id")
        pathlib.Path(str(layout["manifest"])).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(obfuscation.ObfuscationError, "requested exact target"):
            obfuscation.verify(
                "windows",
                pathlib.Path(str(layout["manifest"])),
                pathlib.Path(str(layout["symbols_dir"])),
                [artifact],
                "windows-x64-installer",
            )
        with self.assertRaisesRegex(obfuscation.ObfuscationError, "must bind an exact target"):
            obfuscation.record(
                "linux",
                pathlib.Path(str(layout["symbols_dir"])),
                pathlib.Path(str(layout["manifest"])),
                [artifact],
            )

    def test_canonical_windows_verify_selects_surface_manifest(self) -> None:
        verified: list[tuple[str, pathlib.Path, pathlib.Path, list[pathlib.Path], str | None]] = []
        signature_flags: list[bool] = []

        def fake_verify_artifact(target_id: str, raw_path: str, *, verify_signature: bool = True):
            signature_flags.append(verify_signature)
            layout = obfuscation.exact_obfuscation_layout(target_id)
            architecture, surface = obfuscation.WINDOWS_CROSS_STORE_TARGET_LAYOUT[target_id]
            return {
                "ok": True,
                "artifact": raw_path,
                "target_architecture": architecture,
                "distribution_surface": surface,
                "layout": layout,
            }

        with (
            mock.patch.object(windows_gate, "verify_artifact", side_effect=fake_verify_artifact),
            mock.patch.object(
                obfuscation,
                "verify",
                side_effect=lambda platform, manifest, symbols, artifacts, target_id=None: verified.append(
                    (platform, manifest, symbols, artifacts, target_id)
                ),
            ),
            mock.patch.object(obfuscation, "_run_cross_store_tool"),
        ):
            obfuscation.canonical_windows_gate_verify(
                "windows-x64-installer", "build/windows-installer/WinsVPN-Setup.exe"
            )
            obfuscation.canonical_windows_gate_verify(
                "windows-x64-partner-center",
                "build/windows-installer/WinsVPN-PartnerCenter.exe",
            )
        self.assertEqual(signature_flags, [True, True])
        source = (ROOT / "tools/release_obfuscation_contract.py").read_text(
            encoding="utf-8"
        )
        start = source.index("def canonical_windows_gate_verify(")
        end = source.find("\ndef ", start + 1)
        body = source[start : len(source) if end < 0 else end]
        self.assertIn("verify_signature=True", body)
        self.assertNotIn("verify_signature=False", body)
        self.assertEqual(
            [item[4] for item in verified],
            ["windows-x64-installer", "windows-x64-partner-center"],
        )
        self.assertTrue(str(verified[0][1]).endswith("manifest-website.json"))
        self.assertTrue(str(verified[1][1]).endswith("manifest-partner-center.json"))
        self.assertEqual(verified[0][2], verified[1][2])
        self.assertNotEqual(verified[0][1], verified[1][1])

    def test_all_six_targets_remain_verifiable_after_all_are_recorded(self) -> None:
        recorded: list[tuple[str, str, dict[str, object], pathlib.Path, bytes]] = []
        for target_id in SIX_TARGETS:
            layout, artifact = self._prepare_target(target_id)
            platform = str(layout["platform"])
            obfuscation.record(
                platform,
                pathlib.Path(str(layout["symbols_dir"])),
                pathlib.Path(str(layout["manifest"])),
                [artifact],
                target_id,
            )
            recorded.append(
                (
                    target_id,
                    platform,
                    layout,
                    artifact,
                    pathlib.Path(str(layout["manifest"])).read_bytes(),
                )
            )
        for target_id, platform, layout, artifact, original in recorded:
            self.assertEqual(
                pathlib.Path(str(layout["manifest"])).read_bytes(),
                original,
            )
            obfuscation.verify(
                platform,
                pathlib.Path(str(layout["manifest"])),
                pathlib.Path(str(layout["symbols_dir"])),
                [artifact],
                target_id,
            )

    def test_static_contract_accepts_architecture_and_surface_producers(self) -> None:
        self.static_patch.stop()
        try:
            obfuscation.validate_static()
        finally:
            self.static_patch.start()
        linux = LINUX_SCRIPT.read_text(encoding="utf-8")
        windows = WINDOWS_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("bind_linux_obfuscation_paths", linux)
        self.assertIn(
            'LINUX_SYMBOL_DIR="${ROOT}/.artifacts/private-release-symbols/linux/${arch_label}/${APP_VERSION}+${BUILD_NUMBER}"',
            linux,
        )
        self.assertNotIn(
            'LINUX_SYMBOL_DIR="${ROOT}/.artifacts/private-release-symbols/linux/${APP_VERSION}+${BUILD_NUMBER}"',
            linux,
        )
        self.assertIn('--target-id "linux-${LINUX_RELEASE_ARCH_LABEL}-package"', linux)
        self.assertIn("private-release-symbols/linux/${arch_label}/", linux)
        self.assertIn(
            "private-release-symbols/linux/${LINUX_RELEASE_ARCH_LABEL}/", linux
        )
        self.assertIn('manifest-$DistributionSurface.json', windows)
        self.assertNotIn(
            'Join-Path $WindowsSymbolDir "manifest.json"',
            windows,
        )
        self.assertIn("--target-id $WindowsObfuscationTargetId", windows)
        self.assertIn("windows-x64-partner-center", windows)
        self.assertIn("windows-arm64-partner-center", windows)

    def test_linux_and_windows_producers_parse(self) -> None:
        bash = shutil.which("bash")
        self.assertIsNotNone(bash)
        completed = subprocess.run(
            [bash, "-n", str(LINUX_SCRIPT)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        pwsh = shutil.which("pwsh") or shutil.which("powershell")
        if pwsh is None:
            self.skipTest("pwsh is unavailable for parser validation")
        command = (
            "$tokens=$null; $errors=$null; "
            "[System.Management.Automation.Language.Parser]::ParseFile("
            f"'{WINDOWS_SCRIPT}', [ref]$tokens, [ref]$errors) > $null; "
            "if ($errors.Count) { $errors | ForEach-Object { "
            "Write-Error $_.Message }; exit 1 }"
        )
        parsed = subprocess.run(
            [pwsh, "-NoLogo", "-NoProfile", "-Command", command],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(parsed.returncode, 0, parsed.stderr)

    def test_final_app_targets_are_complete_and_distinct(self) -> None:
        self.assertEqual(
            obfuscation.FINAL_APP_TARGET_IDS,
            (
                "android-phone-tablet-aab",
                "android-tv-aab",
                "wear-os-aab",
                "ios-app-store-ipa",
                "macos-app-store-pkg",
                "macos-developer-id-app",
                "windows-x64-installer",
                "windows-x64-partner-center",
                "windows-arm64-installer",
                "windows-arm64-partner-center",
                "linux-x64-package",
                "linux-arm64-package",
                "chrome-extension-package",
                "edge-extension-package",
                "firefox-extension-package",
            ),
        )
        self.assertEqual(
            len(obfuscation.FINAL_APP_TARGET_IDS),
            len(set(obfuscation.FINAL_APP_TARGET_IDS)),
        )
        for target_id in (
            "linux-x64-package",
            "windows-x64-installer",
            "wear-os-aab",
            "chrome-extension-package",
            "edge-extension-package",
            "firefox-extension-package",
        ):
            layout = obfuscation.exact_obfuscation_layout(target_id)
            self.assertTrue(layout["symbols_dir"])
            self.assertTrue(layout["manifest"])

    def test_wear_and_extension_layouts_do_not_share_receipts(self) -> None:
        wear = obfuscation.exact_obfuscation_layout("wear-os-aab")
        chrome = obfuscation.exact_obfuscation_layout("chrome-extension-package")
        edge = obfuscation.exact_obfuscation_layout("edge-extension-package")
        firefox = obfuscation.exact_obfuscation_layout("firefox-extension-package")
        manifests = [
            pathlib.Path(str(item["manifest"]))
            for item in (wear, chrome, edge, firefox)
        ]
        self.assertEqual(len(manifests), len(set(manifests)))
        self.assertEqual(wear["platform"], "wear-os")
        self.assertEqual(wear["evidence"], "r8")
        self.assertEqual(chrome["platform"], "chrome")
        self.assertEqual(edge["platform"], "edge")
        self.assertEqual(firefox["platform"], "firefox")
        self.assertIn("wins-vpn-companion-firefox.xpi", firefox["artifact_names"])

    def test_wear_and_extension_record_without_overwriting(self) -> None:
        wear_layout, wear_artifact = self._prepare_target("wear-os-aab")
        mapping = pathlib.Path(str(wear_layout["symbols_dir"])) / "mapping.txt"
        mapping.write_bytes(b"# compiler: R8\n" + (b"class X\n" * 300))
        chrome_layout, chrome_artifact = self._prepare_target("chrome-extension-package")
        obfuscation.record(
            "wear-os",
            pathlib.Path(str(wear_layout["symbols_dir"])),
            pathlib.Path(str(wear_layout["manifest"])),
            [wear_artifact],
            "wear-os-aab",
        )
        wear_bytes = pathlib.Path(str(wear_layout["manifest"])).read_bytes()
        obfuscation.record(
            "chrome",
            pathlib.Path(str(chrome_layout["symbols_dir"])),
            pathlib.Path(str(chrome_layout["manifest"])),
            [chrome_artifact],
            "chrome-extension-package",
        )
        self.assertEqual(
            pathlib.Path(str(wear_layout["manifest"])).read_bytes(),
            wear_bytes,
        )
        obfuscation.verify(
            "wear-os",
            pathlib.Path(str(wear_layout["manifest"])),
            pathlib.Path(str(wear_layout["symbols_dir"])),
            [wear_artifact],
            "wear-os-aab",
        )
        obfuscation.verify(
            "chrome",
            pathlib.Path(str(chrome_layout["manifest"])),
            pathlib.Path(str(chrome_layout["symbols_dir"])),
            [chrome_artifact],
            "chrome-extension-package",
        )

    def test_canonical_dispatch_covers_wear_and_extensions(self) -> None:
        routed: list[str] = []
        with (
            mock.patch.object(
                obfuscation,
                "canonical_wear_gate_verify",
                side_effect=lambda target, path: routed.append(target),
            ),
            mock.patch.object(
                obfuscation,
                "canonical_extension_gate_verify",
                side_effect=lambda target, path: routed.append(target),
            ),
            mock.patch.object(obfuscation, "canonical_apple_gate_verify"),
        ):
            self.assertEqual(
                obfuscation.main(["--verify", "wear-os-aab", "wear.aab"]), 0
            )
            self.assertEqual(
                obfuscation.main(
                    ["--verify", "chrome-extension-package", "chrome.zip"]
                ),
                0,
            )
            self.assertEqual(
                obfuscation.main(["--verify", "edge-extension-package", "edge.zip"]),
                0,
            )
            self.assertEqual(
                obfuscation.main(
                    ["--verify", "firefox-extension-package", "firefox.xpi"]
                ),
                0,
            )
        self.assertEqual(
            routed,
            [
                "wear-os-aab",
                "chrome-extension-package",
                "edge-extension-package",
                "firefox-extension-package",
            ],
        )
        with self.assertRaisesRegex(obfuscation.ObfuscationError, "unsupported exact"):
            obfuscation.main(["--verify", "not-a-target", "artifact.bin"])


class ApprovedVendorDebugMetadataTests(unittest.TestCase):
    """The obfuscation contract's stripped-payload check honours the same reviewed
    vendor table as the privacy scan, so the pinned awg CLI (which keeps its ELF
    .symtab) is not refused by one tool after the other accepted it."""

    def test_pinned_awg_symbol_table_passes_only_with_its_exact_bytes(self) -> None:
        payload = obfuscation._minimal_elf64(".text", ".symtab")
        with self.assertRaisesRegex(obfuscation.ObfuscationError, "unstripped native debug"):
            obfuscation.reject_unstripped_native_blob("awg", payload)
        approved = {"awg": frozenset({hashlib.sha256(payload).hexdigest()})}
        with mock.patch.object(obfuscation, "APPROVED_VENDOR_DEBUG_METADATA_SHA256", approved):
            obfuscation.reject_unstripped_native_blob("awg", payload)
            obfuscation.reject_unstripped_native_blob("wins-vpn-linux-x64.tar.gz!/awg", payload)
            with self.assertRaisesRegex(obfuscation.ObfuscationError, "unstripped native debug"):
                obfuscation.reject_unstripped_native_blob("xray", payload)
            with self.assertRaisesRegex(obfuscation.ObfuscationError, "unstripped native debug"):
                obfuscation.reject_unstripped_native_blob("awg", payload + b"\0")

    def test_vendor_table_equals_the_privacy_table(self) -> None:
        self.assertEqual(
            obfuscation.APPROVED_VENDOR_DEBUG_METADATA_SHA256,
            privacy.APPROVED_VENDOR_DEBUG_METADATA_SHA256,
        )
        for name, digests in obfuscation.APPROVED_VENDOR_DEBUG_METADATA_SHA256.items():
            self.assertIsInstance(digests, frozenset, name)
            self.assertTrue(all(re.fullmatch(r"[0-9a-f]{64}", item) for item in digests), name)

    def test_vendor_check_needs_no_repository_import(self) -> None:
        # The Apple gate loads this file by descriptor with __package__ = "" and a
        # closed module set. Every payload, Apple binaries included, reaches the
        # vendor check first, so it must not import the privacy scan.
        tools_dir = pathlib.Path(obfuscation.__file__).resolve().parent
        with tempfile.TemporaryDirectory() as raw:
            loader = pathlib.Path(raw) / "load.py"
            loader.write_text(
                "import importlib.abc, sys, types\n"
                "class Block(importlib.abc.MetaPathFinder):\n"
                "    def find_spec(self, name, path, target=None):\n"
                "        if name in {'validate_release_artifact_privacy', 'tools.validate_release_artifact_privacy'}:\n"
                "            raise ModuleNotFoundError(f\"No module named '{name}'\")\n"
                "sys.meta_path.insert(0, Block())\n"
                "sys.path.insert(0, sys.argv[1])\n"
                "raw = open(sys.argv[1] + '/release_obfuscation_contract.py', 'rb').read()\n"
                "module = types.ModuleType('release_obfuscation_contract')\n"
                "module.__file__ = 'tools/release_obfuscation_contract.py'\n"
                "module.__package__ = ''\n"
                "module.__spec__ = None\n"
                "sys.modules['release_obfuscation_contract'] = module\n"
                "exec(compile(raw, module.__file__, 'exec'), module.__dict__)\n"
                "assert not module._is_approved_vendor_debug_metadata('Contents/MacOS/wins_vpn', b'ordinary payload')\n"
                "print('ISOLATED LOAD OK')\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [sys.executable, "-I", str(loader), str(tools_dir)],
                cwd=raw, capture_output=True, text=True, check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("ISOLATED LOAD OK", completed.stdout)


class WindowsReviewedSourceCustodyTests(unittest.TestCase):
    """The Windows host has no O_NOFOLLOW, O_DIRECTORY or dir_fd, so the reviewed
    helper custody holds one descriptor on the file after a link check of every
    path component. The branch is driven directly here because it is the only
    one a Windows release host runs."""

    def _custody(self, path: pathlib.Path):
        custody = object.__new__(obfuscation._ReviewedSourceCustody)
        custody.path = path
        custody.label = "fixture"
        custody._records = []
        custody._queue = None
        custody._closed = False
        custody._file_fd = -1
        return custody

    def test_windows_branch_holds_the_file_and_detects_a_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            source = pathlib.Path(raw).resolve() / "helper.py"
            source.write_bytes(b"VALUE = 1\n")
            custody = self._custody(source)
            custody._open_windows_source()
            try:
                self.assertEqual(custody.payload(), b"VALUE = 1\n")
                custody.verify()
                replacement = source.with_name("helper.new")
                replacement.write_bytes(b"VALUE = 22\n")
                try:
                    os.replace(replacement, source)
                except PermissionError:
                    # Windows refuses to replace a file that is held open.
                    custody.verify()
                else:
                    with self.assertRaises(obfuscation.ObfuscationError):
                        custody.verify()
            finally:
                custody.close(verify=False)

    def test_windows_branch_refuses_a_link_in_the_source_path(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = pathlib.Path(raw).resolve()
            (base / "real").mkdir()
            (base / "real" / "helper.py").write_bytes(b"VALUE = 1\n")
            os.symlink(base / "real", base / "linked")
            os.symlink(base / "real" / "helper.py", base / "alias.py")
            for candidate in (base / "linked" / "helper.py", base / "alias.py"):
                custody = self._custody(candidate)
                with self.assertRaises(obfuscation.ObfuscationError, msg=str(candidate)):
                    custody._open_windows_source()
                custody.close(verify=False)

    def test_windows_file_identity_ignores_the_creation_versus_change_time_split(self) -> None:
        # A Windows path stat reports the creation time as st_ctime_ns and a
        # handle stat reports the change time, so the same file never agrees.
        def info(ctime_ns: int) -> types.SimpleNamespace:
            return types.SimpleNamespace(
                st_dev=1, st_ino=2, st_uid=0, st_mode=0o100644, st_nlink=1,
                st_size=7, st_mtime_ns=3, st_ctime_ns=ctime_ns,
            )

        by_path, by_handle = info(100), info(200)
        with mock.patch.object(obfuscation.os, "name", "posix"):
            self.assertNotEqual(
                obfuscation._regular_file_identity(by_path),
                obfuscation._regular_file_identity(by_handle),
            )
        with mock.patch.object(obfuscation.os, "name", "nt"):
            self.assertEqual(
                obfuscation._regular_file_identity(by_path),
                obfuscation._regular_file_identity(by_handle),
            )

    def test_windows_file_identity_ignores_the_execute_bits_a_path_stat_infers(self) -> None:
        # lstat of a .exe reports 0o100777 and fstat of the same file 0o100666, which
        # made the exact-target record of WinsVPN-UNSIGNED-LOCAL-Setup.exe fail with
        # "Exact artifact path replacement is not allowed".
        def info(mode: int) -> types.SimpleNamespace:
            return types.SimpleNamespace(
                st_dev=1, st_ino=2, st_uid=0, st_mode=mode, st_nlink=1,
                st_size=7, st_mtime_ns=3, st_ctime_ns=4,
            )

        by_path, by_handle = info(0o100777), info(0o100666)
        with mock.patch.object(obfuscation.os, "name", "posix"):
            self.assertNotEqual(
                obfuscation._regular_file_identity(by_path),
                obfuscation._regular_file_identity(by_handle),
            )
        with mock.patch.object(obfuscation.os, "name", "nt"):
            self.assertEqual(
                obfuscation._regular_file_identity(by_path),
                obfuscation._regular_file_identity(by_handle),
            )
            self.assertNotEqual(
                obfuscation._regular_file_identity(info(0o100666)),
                obfuscation._regular_file_identity(info(0o120666)),
            )


class SecretScanDeferralTests(unittest.TestCase):
    """The Windows build host hands the exact secret scan to the release host."""

    @staticmethod
    def full_remote_input(platform: str = "windows", **overrides: object) -> dict[str, object]:
        """A REMOTE_INPUT.json with every field release_remote_build.py prepare writes."""

        reference = lambda name: {  # noqa: E731
            "path": f".artifacts/release-inputs-1.0.16+33/{name}",
            "sha256": "b" * 64,
        }
        document: dict[str, object] = {
            "contract": obfuscation.SECRET_SCAN_DEFERRAL_INPUT_CONTRACT,
            "release": "1.0.16+33",
            "platform": platform,
            "remote_host": platform,
            "build_begin_sha256": "a" * 64,
            "release_input_index": reference("RELEASE_INPUT_INDEX.json"),
            "shared_manifest": reference("SHARED_INPUTS.json"),
            "platform_manifest": reference(f"{platform.upper()}_INPUTS.json"),
            "source_archive": {
                "contract": "winsvpn-remote-source-archive-v1",
                "path": ".artifacts/remote-builds/run/SOURCE.tar",
                "sha256": "c" * 64,
                "size_bytes": 1024,
                "revision": "d" * 40,
                "object_format": "sha1",
                "file_count": 3,
                "listing_sha256": "e" * 64,
                "mtime": 1790000000,
            },
            "producer": {
                "path": {
                    "windows": "installer/windows/build_installer.ps1",
                    "linux": "tools/build_linux_release.sh",
                }[platform],
                "sha256": "f" * 64,
            },
        }
        document.update(overrides)
        return document

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.temporary.name)
        self.remote_input = self.base / "REMOTE_INPUT.json"
        self.remote_input.write_text(json.dumps(self.full_remote_input()), encoding="utf-8")
        self.artifact = self.base / "WinsVPN-UNSIGNED-LOCAL-Setup.exe"
        self.artifact.write_bytes(b"MZ-installer-fixture")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_deferral_is_available_to_a_windows_remote_attested_build_only(self) -> None:
        with mock.patch.object(obfuscation.os, "name", "posix"):
            with self.assertRaisesRegex(obfuscation.ObfuscationError, "only by a Windows build host"):
                obfuscation.require_secret_scan_deferral(self.remote_input)
        with mock.patch.object(obfuscation.os, "name", "nt"):
            obfuscation.require_secret_scan_deferral(self.remote_input)
            valid = self.full_remote_input()
            shortened = {key: value for key, value in valid.items() if key != "source_archive"}
            for label, document in {
                # The three fields the first version looked at were enough to pass.
                "three fields only": {
                    "contract": obfuscation.SECRET_SCAN_DEFERRAL_INPUT_CONTRACT,
                    "platform": "windows",
                    "remote_host": "windows",
                },
                "linux input": self.full_remote_input("linux"),
                "other contract": dict(valid, contract="x"),
                "windows platform on a linux host": dict(valid, remote_host="linux"),
                "linux platform on a windows host": dict(valid, platform="linux"),
                "unreviewed producer": dict(valid, producer={"path": "installer/windows/other.ps1", "sha256": "f" * 64}),
                "missing source archive": shortened,
                "extra field": dict(valid, extra="x"),
                "short digest": dict(valid, build_begin_sha256="a" * 63),
                "index outside .artifacts": dict(
                    valid, release_input_index={"path": "RELEASE_INPUT_INDEX.json", "sha256": "b" * 64}
                ),
                "not an object": [],
            }.items():
                with self.subTest(label=label):
                    bad = self.base / "bad.json"
                    bad.write_text(json.dumps(document), encoding="utf-8")
                    with self.assertRaisesRegex(obfuscation.ObfuscationError, "remote-attestation input"):
                        obfuscation.require_secret_scan_deferral(bad)
            with self.assertRaisesRegex(obfuscation.ObfuscationError, "readable REMOTE_INPUT.json"):
                obfuscation.require_secret_scan_deferral(self.base / "missing.json")
            huge = self.base / "huge.json"
            huge.write_bytes(b" " * (obfuscation.SECRET_SCAN_DEFERRAL_INPUT_LIMIT + 8))
            with self.assertRaises(obfuscation.ObfuscationError):
                obfuscation.require_secret_scan_deferral(huge)

    def test_hardening_defers_without_loading_the_inventory_and_only_on_windows(self) -> None:
        import contextlib
        import io as _io

        import release_secret_inventory as inventory_module

        def forbidden(*_args, **_kwargs):
            raise AssertionError("a deferred scan must not load the inventory")

        with mock.patch.object(obfuscation.os, "name", "nt"), mock.patch.object(
            inventory_module, "load_authenticated_secret_inventory", side_effect=forbidden
        ):
            output = _io.StringIO()
            with contextlib.redirect_stdout(output):
                obfuscation.verify_release_artifact_hardening(
                    "windows",
                    [self.artifact],
                    privacy_target_id="windows-x64-installer",
                    defer_secret_scan=self.remote_input,
                )
            self.assertIn("DEFERRED TO THE RELEASE HOST", output.getvalue())
            with self.assertRaisesRegex(obfuscation.ObfuscationError, "Only a Windows build"):
                obfuscation.verify_release_artifact_hardening(
                    "linux", [self.artifact], defer_secret_scan=self.remote_input
                )
            for target in ("android-aab", "linux-x64-package", "chrome-extension-package", "macos-app-store-pkg"):
                with self.subTest(target=target):
                    with self.assertRaisesRegex(obfuscation.ObfuscationError, "Windows installer scan"):
                        obfuscation.verify_release_artifact_hardening(
                            "windows", [self.artifact], privacy_target_id=target,
                            defer_secret_scan=self.remote_input,
                        )
            for target in (
                "windows-x64-installer", "windows-x64-partner-center",
                "windows-arm64-installer", "windows-arm64-partner-center",
            ):
                with self.subTest(target=target), contextlib.redirect_stdout(_io.StringIO()):
                    obfuscation.verify_release_artifact_hardening(
                        "windows", [self.artifact], privacy_target_id=target,
                        defer_secret_scan=self.remote_input,
                    )
        # Without the deferral the scan still needs the inventory, so a host that
        # cannot load it fails instead of passing quietly.
        with mock.patch.object(
            inventory_module,
            "load_authenticated_secret_inventory",
            side_effect=inventory_module.InventoryError("no inventory"),
        ):
            with self.assertRaisesRegex(obfuscation.ObfuscationError, "no inventory"):
                obfuscation.verify_release_artifact_hardening(
                    "windows", [self.artifact], privacy_target_id="windows-x64-installer"
                )

    def test_record_and_verify_forward_the_deferral(self) -> None:
        for function in (obfuscation.record, obfuscation.verify):
            with self.subTest(function=function.__name__):
                self.assertIn("defer_secret_scan", function.__code__.co_varnames)
        source = pathlib.Path(obfuscation.__file__).read_text(encoding="utf-8")
        self.assertEqual(source.count("defer_secret_scan=defer_secret_scan"), 4)
        self.assertIn('"--defer-secret-scan-to-release-host"', source)


class FinalAppHardeningGateTests(unittest.TestCase):
    def setUp(self) -> None:
        _seed_esbuild_cache()

    def test_missing_artifact_and_receipt_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name).resolve()
            private = root / "private-release-symbols"
            private.mkdir()
            with self.assertRaisesRegex(obfuscation.ObfuscationError, "required"):
                obfuscation.inspect_artifacts([])
            missing = root / "missing.apk"
            with self.assertRaisesRegex(obfuscation.ObfuscationError, "absent|unsafe"):
                obfuscation.inspect_artifacts([missing])
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "absent or escaped"
            ):
                obfuscation.contained(root / "absent-receipt.json", private)

    def test_unminified_and_obfuscated_extension_js_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            pretty = root / "pretty.zip"
            with zipfile.ZipFile(pretty, "w") as archive:
                archive.writestr(
                    "background.js",
                    b"function start() {\n  const ok = true;\n  return ok;\n}\n",
                )
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "not store-permitted minified"
            ):
                obfuscation.verify_extension_javascript_hardening("chrome", [pretty])
            obfuscated = root / "obfuscated.zip"
            with zipfile.ZipFile(obfuscated, "w") as archive:
                archive.writestr(
                    "background.js", b"var _0xabcd=function(){return 1;}"
                )
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "Chrome forbids"
            ):
                obfuscation.verify_extension_javascript_hardening("chrome", [obfuscated])
            empty = root / "empty.zip"
            with zipfile.ZipFile(empty, "w") as archive:
                archive.writestr("manifest.json", b'{"manifest_version":3}')
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "contains no JavaScript"
            ):
                obfuscation.verify_extension_javascript_hardening("firefox", [empty])
            foreign = root / "foreign.zip"
            with zipfile.ZipFile(foreign, "w") as archive:
                archive.writestr(
                    "background.js", b"const ok=true;function start(){return 1;}"
                )
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError,
                "not the reproducible esbuild producer output",
            ):
                obfuscation.verify_extension_javascript_hardening("edge", [foreign])

    def test_ios_ipa_without_watchos_fails_and_stripped_companion_passes(self) -> None:
        stripped = obfuscation._minimal_macho64(dwarf=False)
        dwarf = obfuscation._minimal_macho64(dwarf=True)
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            missing = root / "nowatch.ipa"
            with zipfile.ZipFile(missing, "w") as archive:
                archive.writestr(
                    "Payload/Runner.app/Frameworks/App.framework/App", stripped
                )
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "missing the embedded watchOS"
            ):
                obfuscation.verify_embedded_watchos_companion("ios", [missing])
            dirty = root / "dirty-watch.ipa"
            with zipfile.ZipFile(dirty, "w") as archive:
                archive.writestr(
                    "Payload/Runner.app/Watch/WinsWatch.app/WinsWatch", dwarf
                )
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "unstripped native"
            ):
                obfuscation.verify_embedded_watchos_companion("ios", [dirty])
            clean = root / "watch.ipa"
            with zipfile.ZipFile(clean, "w") as archive:
                archive.writestr(
                    "Payload/Runner.app/Watch/WinsWatch.app/WinsWatch", stripped
                )
                # Real Watch apps carry non-code resources beside the executable.
                for resource in ("Assets.car", "Info.plist", "PkgInfo", "PrivacyInfo.xcprivacy"):
                    archive.writestr(
                        f"Payload/Runner.app/Watch/WinsWatch.app/{resource}", b"not code"
                    )
            obfuscation.verify_embedded_watchos_companion("ios", [clean])
            garbled = root / "garbled-watch.ipa"
            with zipfile.ZipFile(garbled, "w") as archive:
                archive.writestr(
                    "Payload/Runner.app/Watch/WinsWatch.app/WinsWatch", b"not a Mach-O"
                )
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "not a parseable Mach-O"
            ):
                obfuscation.verify_embedded_watchos_companion("ios", [garbled])
            resources_only = root / "resources-only-watch.ipa"
            with zipfile.ZipFile(resources_only, "w") as archive:
                archive.writestr(
                    "Payload/Runner.app/Watch/WinsWatch.app/Assets.car", b"not code"
                )
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "missing the embedded watchOS"
            ):
                obfuscation.verify_embedded_watchos_companion("ios", [resources_only])

    def test_wear_mapping_negative_mutations_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name).resolve()
            symbols = root / "wear-os" / "1.0.15+3001"
            symbols.mkdir(parents=True)
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "R8 mapping receipt is absent"
            ):
                obfuscation.inspect_r8_mapping(symbols, root)
            mapping = symbols / "mapping.txt"
            mapping.write_bytes(b"# compiler: R8\nshort\n")
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "empty or truncated"
            ):
                obfuscation.inspect_r8_mapping(symbols, root)
            mapping.write_bytes(b"# compiler: D8\n" + (b"x" * 2048))
            with self.assertRaisesRegex(obfuscation.ObfuscationError, "not an R8 map"):
                obfuscation.inspect_r8_mapping(symbols, root)
            mapping.write_bytes(b"# compiler: R8\n" + (b"class X\n" * 300))
            inspected = obfuscation.inspect_r8_mapping(symbols, root)
            self.assertEqual(inspected[0]["path"], "mapping.txt")

    def test_receipt_does_not_claim_obfuscation_protects_secrets(self) -> None:
        claims = obfuscation._receipt_verification()
        self.assertTrue(claims["obfuscation_is_not_secret_protection"])
        self.assertTrue(claims["durable_secrets_remain_server_side"])
        self.assertTrue(claims["authenticated_receipt_required"])
        extension_claims = obfuscation._receipt_verification("chrome")
        self.assertTrue(extension_claims["extension_store_minification_required"])
        self.assertTrue(extension_claims["extension_obfuscation_forbidden"])
        self.assertNotIn("flutter_obfuscation_flag_required", extension_claims)
        wear_claims = obfuscation._receipt_verification("wear-os")
        self.assertTrue(wear_claims["android_r8_minify_required"])
        self.assertTrue(wear_claims["android_resource_shrinking_required"])
        self.assertNotIn("flutter_obfuscation_flag_required", wear_claims)
        android_claims = obfuscation._receipt_verification("android-apk")
        self.assertTrue(android_claims["flutter_obfuscation_flag_required"])
        self.assertTrue(android_claims["split_debug_info_flag_required"])
        self.assertTrue(android_claims["android_r8_minify_required"])
        self.assertTrue(android_claims["private_r8_mapping_verified"])
        ios_claims = obfuscation._receipt_verification("ios")
        self.assertTrue(ios_claims["apple_dsym_separated"])
        self.assertTrue(ios_claims["apple_strip_style_all_required"])
        macos_claims = obfuscation._receipt_verification("macos")
        self.assertTrue(macos_claims["apple_dsym_separated"])
        linux_claims = obfuscation._receipt_verification("linux")
        self.assertTrue(linux_claims["split_debug_info_flag_required"])
        self.assertTrue(linux_claims["linux_split_dwarf_required"])
        self.assertNotIn("android_r8_minify_required", linux_claims)
        windows_claims = obfuscation._receipt_verification("windows")
        self.assertTrue(windows_claims["inspected_native_debug_sections_absent"])
        self.assertTrue(windows_claims["windows_pdb_separated"])

    def test_static_contract_covers_r8_strip_and_watchos(self) -> None:
        contract = (ROOT / "tools/release_obfuscation_contract.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("isMinifyEnabled = true", contract)
        self.assertIn("isShrinkResources = true", contract)
        self.assertIn("SDKROOT = watchos", contract)
        self.assertIn("dwarf-with-dsym", contract)
        self.assertIn("apple_dsym_separated", contract)
        self.assertIn("windows_pdb_separated", contract)
        self.assertIn("linux_split_dwarf_required", contract)
        self.assertIn("objcopy --only-keep-debug", contract)
        self.assertIn("Assert-WindowsPayloadContainsNoDebugSymbols", contract)
        self.assertIn("proguard-mapping.txt", contract)
        self.assertIn("Chrome forbids", contract)
        self.assertIn("--minify", contract)
        self.assertIn("javascript-obfuscator", contract)
        self.assertIn("require_zip_javascript_matches_producer", contract)
        self.assertIn("--minify-identifiers", contract)
        self.assertIn("--minify-syntax", contract)
        self.assertNotIn("comment_lines" + " >= 2", contract)
        self.assertNotIn("lstrip(" + '" \\t")', contract)
        obfuscation.validate_static()

    def test_canonical_gates_fail_closed_when_artifact_absent(self) -> None:
        with self.assertRaisesRegex(obfuscation.ObfuscationError, "absent"):
            obfuscation.canonical_wear_gate_verify(
                "wear-os-aab", "missing/app-release.aab"
            )
        with self.assertRaisesRegex(obfuscation.ObfuscationError, "absent"):
            obfuscation.canonical_extension_gate_verify(
                "chrome-extension-package",
                "missing/wins-vpn-companion-chrome.zip",
            )

    def test_cross_store_privacy_calls_require_fixed_root_inventory(self) -> None:
        source = (ROOT / "tools/release_obfuscation_contract.py").read_text(
            encoding="utf-8"
        )
        functions = (
            "canonical_android_gate_verify",
            "canonical_linux_gate_verify",
            "canonical_windows_gate_verify",
            "canonical_wear_gate_verify",
            "canonical_extension_gate_verify",
        )
        for name in functions:
            with self.subTest(name=name):
                start = source.index(f"def {name}(")
                end = source.find("\ndef ", start + 1)
                body = source[start : len(source) if end < 0 else end]
                self.assertIn("--authenticated-inventory", body)
                self.assertIn('"--target"', body)
                self.assertNotIn('["--artifacts", "--artifact"', body)

    def test_android_flutter_evidence_requires_r8_mapping(self) -> None:
        stripped = obfuscation._minimal_elf64(".text", ".dynsym")
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name).resolve()
            private = root / "private-release-symbols"
            symbols = private / "android-apk" / "1.0.15+30"
            symbols.mkdir(parents=True)
            (symbols / "app.android-arm64.symbols").write_bytes(b"s" * 128)
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "R8 mapping receipt is absent"
            ):
                obfuscation.inspect_private_evidence("android-apk", symbols, private)
            mapping = symbols / "proguard-mapping.txt"
            mapping.write_bytes(b"# compiler: R8\n" + (b"com.example.Keep -> a:\n" * 160))
            records = obfuscation.inspect_private_evidence(
                "android-apk", symbols, private
            )
            paths = [str(item["path"]) for item in records]
            self.assertIn("app.android-arm64.symbols", paths)
            self.assertIn("proguard-mapping.txt", paths)
            artifact = root / "app-release.apk"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("lib/arm64-v8a/libapp.so", stripped)
            manifest = symbols / "manifest.json"
            with mock.patch.object(obfuscation, "PRIVATE_SYMBOL_ROOT", private):
                with mock.patch.object(obfuscation, "validate_static"):
                    with mock.patch.object(
                        obfuscation, "verify_release_artifact_hardening"
                    ):
                        with mock.patch.object(
                            obfuscation, "pubspec_version", return_value=("1.0.15", "30")
                        ):
                            obfuscation.record(
                                "android-apk", symbols, manifest, [artifact]
                            )
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertTrue(payload["verification"]["private_r8_mapping_verified"])
            self.assertEqual(
                [item["path"] for item in payload["symbols"] if item["path"].endswith(".txt")],
                ["proguard-mapping.txt"],
            )

    def test_packaged_service_account_and_activation_secrets_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            sa = root / "sa.zip"
            with zipfile.ZipFile(sa, "w") as archive:
                archive.writestr(
                    "assets/adc.json",
                    b'{"type":"service_account","project_id":"wins-proof",'
                    b'"client_email":"proof@wins-proof.iam.gserviceaccount.com"}',
                )
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "google_service_account_json"
            ):
                obfuscation.verify_release_artifact_hardening("windows", [sa])
            named = root / "named-sa.zip"
            with zipfile.ZipFile(named, "w") as archive:
                archive.writestr("google-service-account.json", b'{"project_id":"x"}')
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "google_service_account_json"
            ):
                obfuscation.verify_release_artifact_hardening("windows", [named])
            activation = root / "activation.zip"
            with zipfile.ZipFile(activation, "w") as archive:
                archive.writestr(
                    "assets/config.bin",
                    b'activation_secret="one-time-enrollment-secret-value-001"',
                )
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "activation_secret"
            ):
                obfuscation.verify_release_artifact_hardening("windows", [activation])

    def test_runtime_public_pins_and_public_keys_remain_allowed(self) -> None:
        pins = (
            b"const String kSpkiWinsvpnOrgWildcard = "
            b"'H6Mj7DsLr6FAGUz4jLll4sc9AXDe3XcOsv4qWwUzY98=';\n"
            b"const String kReviewedAnnouncementPubkeyA1 = "
            b"'d9hwDSlQpYvnph33NJFHAbOm3hKR1wWEhC/kFiNoeoo=';\n"
            b"const String server_public_key = "
            b"'d9hwDSlQpYvnph33NJFHAbOm3hKR1wWEhC/kFiNoeoo=';\n"
            b"-----BEGIN PUBLIC KEY-----\n"
            b"MIIBfixturepublickeynotasecretXX\n"
            b"-----END PUBLIC KEY-----\n"
            b"-----BEGIN CERTIFICATE-----\n"
            b"MIIBfixturepubliccertnotasecretXX\n"
            b"-----END CERTIFICATE-----\n"
        )
        obfuscation.reject_embedded_long_lived_credentials("pins.dart", pins)
        with tempfile.TemporaryDirectory() as temp_name:
            artifact = pathlib.Path(temp_name) / "public.zip"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("assets/pins.dart", pins)
            self.assertGreaterEqual(privacy.validate_artifacts((artifact,), {}), 1)


ESBUILD_CACHE = pathlib.Path("/tmp/winsvpn-extension-esbuild-test-cache")
# The operator-supplied offline cache, captured before _seed_esbuild_cache
# redirects the environment to the private test cache. Archive bytes are
# re-verified.
CONFIGURED_ESBUILD_CACHE = os.environ.get("WINS_EXTENSION_ESBUILD_CACHE", "").strip()
_PRODUCER_ZIPS: dict[str, bytes] | None = None


def _seed_esbuild_cache() -> None:
    minifier = obfuscation._store_js_minifier()
    os.environ[minifier.CACHE_ENV] = str(ESBUILD_CACHE)
    os.environ[minifier.FETCH_ENV] = "0"
    pin = minifier.pin_for_host()
    slot = ESBUILD_CACHE / minifier.host_platform_key() / str(pin["archive_sha256"])
    slot.mkdir(parents=True, exist_ok=True)
    dest = slot / str(pin["archive_name"])
    discovered = (
        pathlib.Path("/tmp/winsvpn-esbuild-discovery/archives") / str(pin["archive_name"])
    )
    if dest.is_file() and minifier.sha256_file(dest) == pin["archive_sha256"]:
        return
    sources = [discovered]
    if CONFIGURED_ESBUILD_CACHE:
        sources.insert(0, (
            pathlib.Path(CONFIGURED_ESBUILD_CACHE) / minifier.host_platform_key()
            / str(pin["archive_sha256"]) / str(pin["archive_name"])
        ))
    for source in sources:
        if source.is_file():
            payload = source.read_bytes()
            minifier.verify_archive_bytes(payload, pin)
            dest.write_bytes(payload)
            dest.chmod(0o444)
            return


def _load_extension_builder():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "extension_build_obfuscation_gate", ROOT / "extension" / "build.py"
    )
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    return builder


def _producer_zip(browser: str) -> bytes:
    global _PRODUCER_ZIPS
    if _PRODUCER_ZIPS is None:
        _seed_esbuild_cache()
        builder = _load_extension_builder()
        dist = pathlib.Path(tempfile.mkdtemp(prefix="winsvpn-obf-producer-"))
        builder.DIST = dist
        packages: dict[str, bytes] = {}
        for name in ("chrome", "edge", "firefox"):
            artifact = builder.zip_package(builder.stage(name), name)
            packages[name] = artifact.read_bytes()
        _PRODUCER_ZIPS = packages
    return _PRODUCER_ZIPS[browser]


def _rewrite_zip(
    payload: bytes,
    *,
    comment: bytes | None = None,
    replace: dict[str, bytes] | None = None,
    extra: dict[str, bytes] | None = None,
) -> bytes:
    source = zipfile.ZipFile(io.BytesIO(payload))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dest:
        for info in source.infolist():
            data = source.read(info.filename)
            if replace and info.filename in replace:
                data = replace[info.filename]
            dest.writestr(info.filename, data)
        if extra:
            for name, body in extra.items():
                dest.writestr(name, body)
        if comment is not None:
            dest.comment = comment
    return out.getvalue()


class ExtensionProducerJavascriptGateTests(unittest.TestCase):
    def setUp(self) -> None:
        _seed_esbuild_cache()

    def _write(self, root: pathlib.Path, name: str, payload: bytes) -> pathlib.Path:
        path = root / name
        path.write_bytes(payload)
        os.chmod(path, 0o644)
        return path

    def test_producer_packages_are_distinct_and_have_no_source_maps(self) -> None:
        chrome = _producer_zip("chrome")
        edge = _producer_zip("edge")
        firefox = _producer_zip("firefox")
        self.assertNotEqual(chrome, edge)
        self.assertNotEqual(chrome, firefox)
        self.assertNotEqual(edge, firefox)
        for payload in (chrome, edge, firefox):
            self.assertNotIn(b"sourceMappingURL", payload)
            self.assertNotIn(b"sourceURL", payload)
            self.assertNotIn(b"javascript-obfuscator", payload)

    def test_honest_producer_packages_pass_javascript_hardening(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            for browser, filename in (
                ("chrome", "wins-vpn-companion-chrome.zip"),
                ("edge", "wins-vpn-companion-edge.zip"),
                ("firefox", "wins-vpn-companion-firefox.xpi"),
            ):
                artifact = self._write(root, filename, _producer_zip(browser))
                obfuscation.verify_extension_javascript_hardening(browser, [artifact])

    def test_hostile_javascript_and_zip_evasions_fail_closed(self) -> None:
        chrome = _producer_zip("chrome")
        member = "src/core/constants.js"
        with zipfile.ZipFile(io.BytesIO(chrome)) as archive:
            original = archive.read(member)
        one_space = b" " + original
        zero_indent = (
            b"export function start() {\nconst ok = true;\nreturn ok;\n}\n"
        )
        nbsp = original.replace(b"\n", b"\n\xc2\xa0", 1)
        colon_map = original + b"\n//# sourceMappingURL:hidden.js.map\n"
        spaced_map = original + b"\n//# source Mapping URL = hidden.js.map\n"
        zwsp_map = original + "//# sourceMappingURL\u200b=hidden.js.map\n".encode(
            "utf-8"
        )
        plus_one = original + b"\n"
        cases = (
            ("one-space", _rewrite_zip(chrome, replace={member: one_space})),
            ("zero-indent", _rewrite_zip(chrome, replace={member: zero_indent})),
            ("nbsp", _rewrite_zip(chrome, replace={member: nbsp})),
            ("colon-map", _rewrite_zip(chrome, replace={member: colon_map})),
            ("spaced-map", _rewrite_zip(chrome, replace={member: spaced_map})),
            ("zwsp-map", _rewrite_zip(chrome, replace={member: zwsp_map})),
            (
                "zip-comment",
                _rewrite_zip(chrome, comment=b"sourceMappingURL=hidden.js.map"),
            ),
            (
                "colon-comment",
                _rewrite_zip(chrome, comment=b"sourceMappingURL:hidden.js.map"),
            ),
            ("producer-plus-one", _rewrite_zip(chrome, replace={member: plus_one})),
            (
                "foreign-compact",
                _rewrite_zip(
                    chrome,
                    replace={
                        member: b"const ok=true;function start(){return 1;}\n"
                    },
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            for name, payload in cases:
                with self.subTest(name=name):
                    artifact = self._write(root, f"{name}.zip", payload)
                    with self.assertRaises(obfuscation.ObfuscationError):
                        obfuscation.verify_extension_javascript_hardening(
                            "chrome", [artifact]
                        )


if __name__ == "__main__":
    unittest.main()
