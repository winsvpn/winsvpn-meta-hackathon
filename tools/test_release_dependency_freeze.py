#!/usr/bin/env python3
"""Regression tests for dependency-scoped release freezing."""

from __future__ import annotations

import base64
import contextlib
import datetime as dt
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


SCRIPT = pathlib.Path(__file__).with_name("release_dependency_freeze.py")
TOOLS_DIR = SCRIPT.parent
if str(SCRIPT.parent) not in sys.path:
    sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("release_dependency_freeze", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
import release_source_freeze as freeze
REAL_SCANNER_CLOSURE = dict(MODULE.RELEASE_HOST_SECRET_SCANNER_CLOSURE)


EXPECTED_PLATFORM_ROOTS = {
    "android": ("android", "winn_protocol_experimental"),
    "wear_os": ("wear_os",),
    "extension": ("extension",),
    "windows": ("windows", "installer/windows", "winn_protocol_experimental"),
    "linux": ("linux", "winn_protocol_experimental"),
    "macos": (
        "macos",
        "apple/WinsTunnelCore",
        "apple/EngineWrappers",
        "apple/EngineArtifacts/macos",
        "winn_protocol_experimental",
    ),
    "ios": (
        "ios",
        "apple/WinsTunnelCore",
        "apple/EngineWrappers",
        "apple/EngineArtifacts/ios/iphoneos",
        "winn_protocol_experimental",
    ),
}
EXPECTED_BUILD_PRODUCERS = {
    "android": "tools/build_android_release.ps1",
    "wear_os": "wear_os/tools/signed_aab_receipt.py",
    "extension": "extension/build.py",
    "windows": "installer/windows/build_installer.ps1",
    "linux": "tools/build_linux_release.sh",
    "macos": "tools/apple_runtime_smoke.sh",
    "ios": "tools/apple_runtime_smoke.sh",
}
EXPECTED_NATIVE_EXTRA_OWNERS = {
    "app_store/android/wear/README.md": ("wear_os",),
    "app_store/android/wear/artifacts/release_candidate.json": ("wear_os",),
    "app_store/android/wear/metadata/en-US/full_description.txt": ("wear_os",),
    "app_store/android/wear/metadata/en-US/short_description.txt": ("wear_os",),
    "app_store/android/wear/metadata/en-US/title.txt": ("wear_os",),
    "app_store/android/wear/metadata/en-US/whats_new.txt": ("wear_os",),
    "app_store/android/wear/review/data_safety.md": ("wear_os",),
    "app_store/android/wear/review/owner_signoff.json": ("wear_os",),
    "app_store/android/wear/review/play_console_notes.txt": ("wear_os",),
    "app_store/android/wear/review/privacy_label_manifest.json": ("wear_os",),
    "apple/EngineArtifacts/apple_winn_v3_engine_provenance.json": ("macos", "ios"),
    "apple/ExportOptions/ios-app-store-connect.plist": ("ios",),
    "apple/ExportOptions/ios-app-store-local.plist": ("ios",),
    "apple/ExportOptions/ios-release-testing.plist": ("ios",),
    "apple/ExportOptions/ios-testflight-internal.plist": ("ios",),
    "apple/ExportOptions/macos-app-store-connect.plist": ("macos",),
    "apple/ExportOptions/macos-app-store-local.plist": ("macos",),
    "apple/ExportOptions/macos-developer-id.plist": ("macos",),
    "assets/icon/Win Empire.png": ("macos", "ios"),
    "assets/icon/app_icon.png": ("windows",),
    "docs/THIRD_PARTY_NOTICES_AND_COMPONENT_INVENTORY.md": ("linux",),
    "tools/native_messaging/host/bin/wins_bridge_host.dart": ("windows",),
    "tools/native_messaging/host/pubspec.lock": ("windows",),
    "tools/native_messaging/host/pubspec.yaml": ("windows",),
    "tools/native_messaging/install_native_host.sh": ("windows",),
    "tools/native_messaging/manifests/store_ids.json": ("windows",),
    "tools/native_messaging/native_host_layout.py": ("windows",),
    "tools/native_messaging/render_host_manifest.py": ("windows",),
    "web/icons/Icon-512.png": ("linux",),
}
EXPECTED_HOST_LIB_ALIASES = (
    (
        "tools/native_messaging/host/lib/browser_bridge_app_ipc.dart",
        "../../../../lib/browser_bridge_app_ipc.dart",
    ),
    (
        "tools/native_messaging/host/lib/browser_bridge_framing.dart",
        "../../../../lib/browser_bridge_framing.dart",
    ),
    (
        "tools/native_messaging/host/lib/browser_bridge_protocol.dart",
        "../../../../lib/browser_bridge_protocol.dart",
    ),
    (
        "tools/native_messaging/host/lib/browser_bridge_proxy.dart",
        "../../../../lib/browser_bridge_proxy.dart",
    ),
    (
        "tools/native_messaging/host/lib/vpn_config_validation.dart",
        "../../../../lib/vpn_config_validation.dart",
    ),
    (
        "tools/native_messaging/host/lib/windows_system_executable.dart",
        "../../../../lib/windows_system_executable.dart",
    ),
    (
        "tools/native_messaging/host/lib/winn_carrier_profile_keys.dart",
        "../../../../lib/winn_carrier_profile_keys.dart",
    ),
    (
        "tools/native_messaging/host/lib/winn_protocol_dispatch.dart",
        "../../../../lib/winn_protocol_dispatch.dart",
    ),
)
EXPECTED_PRODUCER_OWNERS = {
    "android/tools/prepare_android_winn_assets.sh": ("android",),
    "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json": tuple(EXPECTED_PLATFORM_ROOTS),
    "extension/build.py": ("extension",),
    "extension/tools/assert_chrome_zip.py": ("extension",),
    "extension/tools/assert_firefox_zip.py": ("extension",),
    "extension/tools/checks.py": ("extension",),
    "installer/windows/build_installer.ps1": ("windows",),
    "linux/packaging/flathub/manifest_artifact.py": ("linux",),
    "linux/packaging/snap/manifest_artifact.py": ("linux",),
    "tools/android_play_redemption_gate.py": ("android",),
    "tools/android_release_publication.py": ("android",),
    "tools/android_signing_preseed.ps1": ("android",),
    "tools/apple_cross_store_artifact_gate.py": ("macos", "ios"),
    "tools/apple_profile_manager.py": ("macos", "ios"),
    "tools/apple_release_symbol_custody.py": ("macos", "ios"),
    "tools/apple_runtime_smoke.sh": ("macos", "ios"),
    "tools/apple_upload_exact_release_candidates.py": ("macos", "ios"),
    "tools/build_android_release.ps1": ("android",),
    "tools/build_android_release_macos.sh": ("android", "wear_os"),
    "tools/build_apple_engine_wrappers.sh": ("macos", "ios"),
    "tools/build_apple_release_candidates.sh": ("macos", "ios"),
    "tools/build_apple_wg_go_bridge.sh": ("macos", "ios"),
    "tools/build_linux_arm64_awg.sh": ("linux",),
    "tools/build_linux_release.sh": ("linux",),
    "tools/build_windows_amneziawg_client.ps1": ("windows",),
    "tools/build_windows_awg_engine.ps1": ("windows",),
    "tools/build_winn_protocol_engine.sh": ("android", "windows", "linux", "macos", "ios"),
    "tools/build_xray_engine.sh": ("android", "linux"),
    "tools/create_cross_machine_source_archive.ps1": ("linux",),
    "tools/cross_store_gate_runner.py": tuple(EXPECTED_PLATFORM_ROOTS),
    "tools/cross_store_target_receipt.py": tuple(EXPECTED_PLATFORM_ROOTS),
    "tools/cross_store_upload_readiness.py": tuple(EXPECTED_PLATFORM_ROOTS),
    "tools/ensure_macos_app_icon.sh": ("macos", "ios"),
    "tools/extract_cross_machine_source_archive.sh": ("linux",),
    "tools/fin_release_gate.sh": tuple(EXPECTED_PLATFORM_ROOTS),
    "tools/freeze_apple_release_candidates.py": ("macos", "ios"),
    "tools/github_backup_only_policy.py": tuple(EXPECTED_PLATFORM_ROOTS),
    "tools/linux_apt_pins.json": ("linux",),
    "tools/linux_cross_store_artifact_gate.py": ("linux",),
    "tools/linux_release_signing.py": ("linux",),
    "tools/native_messaging/build_native_host.ps1": ("extension", "windows"),
    "tools/native_messaging/build_native_host.sh": ("extension", "macos", "ios"),
    "tools/native_messaging/native_host_layout.py": ("extension", "macos", "ios"),
    "tools/native_messaging/render_host_manifest.py": ("extension", "macos", "ios"),
    "tools/private_release_symbol_custody.py": ("android", "wear_os", "windows", "linux"),
    "tools/private_symbol_custody.ps1": ("android", "windows"),
    "tools/release-python-requirements.txt": ("windows",),
    "tools/release_android_toolchain_archive_custody.sh": ("android",),
    "tools/release_browser_archive_custody.py": tuple(EXPECTED_PLATFORM_ROOTS),
    "tools/release_browser_archive_custody.sh": tuple(EXPECTED_PLATFORM_ROOTS),
    "tools/release_dependency_freeze.py": tuple(EXPECTED_PLATFORM_ROOTS),
    "tools/release_freeze_client.py": ("extension", "windows", "linux", "macos", "ios"),
    "tools/release_remote_attestation_check.py": ("windows", "linux"),
    "tools/release_remote_build.py": ("windows", "linux"),
    "tools/release_remote_run_record_signature.py": ("windows", "linux"),
    "tools/release_go_archive_custody.py": tuple(EXPECTED_PLATFORM_ROOTS),
    "tools/release_go_archive_custody.sh": tuple(EXPECTED_PLATFORM_ROOTS),
    "tools/release_obfuscation_contract.py": ("android", "extension", "windows", "linux", "macos", "ios"),
    "tools/release_python_archive_custody.sh": tuple(EXPECTED_PLATFORM_ROOTS),
    "tools/release_source_freeze.py": tuple(EXPECTED_PLATFORM_ROOTS),
    "tools/run_test_suite.py": tuple(EXPECTED_PLATFORM_ROOTS),
    "tools/stage_apple_engine_artifacts.sh": ("macos", "ios"),
    "tools/strip_image_metadata.py": ("windows",),
    "tools/test_linux_arm64_fallback_elf.py": ("linux",),
    "tools/test_release_dependency_freeze.py": tuple(EXPECTED_PLATFORM_ROOTS),
    "tools/test_release_source_freeze.py": tuple(EXPECTED_PLATFORM_ROOTS),
    "tools/toolchain-pins.json": tuple(EXPECTED_PLATFORM_ROOTS),
    "tools/validate_apple_submission_package.py": ("macos", "ios"),
    "tools/validate_flutter_package_config.py": ("android",),
    "tools/validate_release_artifact_privacy.py": tuple(EXPECTED_PLATFORM_ROOTS),
    "tools/verify_android_aab_page_alignment.py": ("android", "wear_os"),
    "tools/verify_android_aab_signers.py": ("android", "wear_os"),
    "tools/verify_embedded_engine_runtime_versions.py": ("android", "windows", "linux", "macos", "ios"),
    "tools/verify_linux_apt_pins.py": ("linux",),
    "tools/verify_standalone_v3_artifact.py": ("android", "macos"),
    "tools/verify_winn3_ring_artifact.py": ("android", "windows", "linux", "macos", "ios"),
    "tools/wear_os_pairing_contract_check.py": ("android", "wear_os"),
    "tools/windows_cross_store_artifact_gate.py": ("windows",),
    "tools/windows_inno_sign.ps1": ("windows",),
    "tools/windows_winn3_artifact_provenance.py": ("windows",),
    "tools/winn3_descriptor_ring_defines.py": ("android", "windows", "linux", "macos", "ios"),
    "tools/winn3_descriptor_ring_identity.py": ("android", "windows", "linux", "macos", "ios"),
    "tools/winn_release.py": ("android", "windows", "linux", "macos", "ios"),
    "tools/winn_release_authority.json": ("android", "windows", "linux", "macos", "ios"),
    "wear_os/tools/assert_release_aab.py": ("wear_os",),
    "wear_os/tools/create_signed_aab_receipt.py": ("wear_os",),
    "wear_os/tools/prepare_release.sh": ("wear_os",),
    "wear_os/tools/signed_aab_receipt.py": ("wear_os",),
}


def _owners_by_path(platform_paths: dict[str, tuple[str, ...]]) -> dict[str, tuple[str, ...]]:
    owners: dict[str, list[str]] = {}
    for platform, paths in platform_paths.items():
        for path in paths:
            if platform in owners.setdefault(path, []):
                raise AssertionError(f"duplicate inventory entry: {platform}: {path}")
            owners[path].append(platform)
    return {path: tuple(platforms) for path, platforms in owners.items()}


def _assert_independent_release_inventory() -> None:
    if MODULE.PLATFORM_ROOTS != EXPECTED_PLATFORM_ROOTS:
        raise AssertionError("platform root inventory drifted")
    if MODULE.PLATFORM_BUILD_PRODUCERS != EXPECTED_BUILD_PRODUCERS:
        raise AssertionError("build producer inventory drifted")
    if MODULE.WINDOWS_NATIVE_HOST_LIB_SYMLINK_ALIASES != EXPECTED_HOST_LIB_ALIASES:
        raise AssertionError("native-host alias inventory drifted")
    if _owners_by_path(MODULE.PLATFORM_NATIVE_EXTRA_PATHS) != EXPECTED_NATIVE_EXTRA_OWNERS:
        raise AssertionError("native extra inventory drifted")
    if _owners_by_path(MODULE.PLATFORM_PRODUCER_PATHS) != EXPECTED_PRODUCER_OWNERS:
        raise AssertionError("release producer inventory drifted")


class DependencyFreezeTests(unittest.TestCase):
    def setUp(self) -> None:
        _assert_independent_release_inventory()
        MODULE._FIXTURE_MODE = True
        MODULE._PRODUCTION_REQUIRED = False
        self.temporary = tempfile.TemporaryDirectory()
        self.trust_temp = tempfile.TemporaryDirectory(prefix="wins-dep-freeze-trust-")
        self.repo = pathlib.Path(self.temporary.name)
        self.trust_path = pathlib.Path(self.trust_temp.name) / freeze.EXTERNAL_TRUST_NAME
        MODULE._SOURCE_FREEZE_TRUST_PATH = str(self.trust_path)
        MODULE._SOURCE_FREEZE_SELF_AUTHORED_OVERRIDE = False
        self.issuance_id = "a" * 32
        self.created_utc = freeze._utc_now_text()
        self._write("pubspec.yaml", "name: wins_vpn\nversion: 1.0.14+29\n")
        self._write("pubspec.lock", "packages: {}\n")
        self._write("lib/main.dart", "void main() {}\n")
        self._write("assets/icon.txt", "shared\n")
        for platform, roots in EXPECTED_PLATFORM_ROOTS.items():
            for root in roots:
                self._write(f"{root}/{platform}-input.txt", f"{platform}\n")
        for path in EXPECTED_NATIVE_EXTRA_OWNERS:
            self._write(path, f"native extra input: {path}\n")
        for path in EXPECTED_PRODUCER_OWNERS:
            self._write(path, f"producer: {path}\n")
        # The worker executes the secret scanner closure for a remote Windows
        # receipt, so its fixture members are valid Python and the scanner is the
        # test stub (before the manifests are made, which freeze their bytes).
        for relative in MODULE.RELEASE_HOST_SECRET_SCANNER_CLOSURE:
            self._write(
                relative,
                self._SCANNER_STUB
                if relative == MODULE.RELEASE_HOST_SECRET_SCANNER
                else f"# stub {relative}\n",
            )
        # Every Windows receipt, in every mode, is made and verified with the worker's
        # own scan, so every test runs against the stub closure and a default inventory.
        self._install_scanner_stub()
        self._default_scan_inventory = self._scan_inventory("pass")
        for path in EXPECTED_BUILD_PRODUCERS.values():
            self._write(path, f"build producer: {path}\n")
        self._write(
            EXPECTED_BUILD_PRODUCERS["windows"],
            """#!/usr/bin/env python3
# WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_V2
import os
import stat
import struct
import sys

def fail(code, reason):
    sys.stderr.write("fixture producer: " + reason + "\\n")
    raise SystemExit(code)

if sys.argv[1:] != [\"--wins-release-dependency-build-attempt-v2\"]:
    fail(2, "argument contract mismatch")
contract = os.environ.get(\"WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT\")
if contract != \"winsvpn-witnessed-build-attempt-v2\":
    fail(3, "environment contract mismatch: " + repr(contract))
output = os.environ.get(\"WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT\", \"\")
if not output or os.path.basename(output) != output:
    fail(4, "output name contract mismatch")
try:
    output_fd = int(os.environ[\"WINS_RELEASE_DEPENDENCY_OUTPUT_FD\"], 10)
except (KeyError, ValueError):
    fail(5, "output capability contract mismatch")
if not stat.S_ISFIFO(os.fstat(output_fd).st_mode):
    fail(6, "output capability is not a stream")
image = bytearray(0x1400)
image[:2] = b\"MZ\"
struct.pack_into(\"<I\", image, 0x3C, 0x80)
image[0x80:0x84] = b\"PE\\x00\\x00\"
struct.pack_into(\"<HHIIIHH\", image, 0x84, 0x8664, 1, 0, 0, 0, 240, 0x0022)
optional = 0x98
struct.pack_into(\"<H\", image, optional, 0x20B)
struct.pack_into(\"<I\", image, optional + 16, 0x1000)
struct.pack_into(\"<I\", image, optional + 20, 0x1000)
struct.pack_into(\"<Q\", image, optional + 24, 0x140000000)
struct.pack_into(\"<I\", image, optional + 32, 0x1000)
struct.pack_into(\"<I\", image, optional + 36, 0x200)
struct.pack_into(\"<I\", image, optional + 56, 0x2000)
struct.pack_into(\"<I\", image, optional + 60, 0x200)
struct.pack_into(\"<H\", image, optional + 68, 2)
struct.pack_into(\"<I\", image, optional + 108, 16)
section = optional + 240
image[section:section + 8] = b\".text\\x00\\x00\\x00\"
struct.pack_into(\"<IIII\", image, section + 8, 0x1000, 0x1000, 0x1000, 0x200)
struct.pack_into(\"<I\", image, section + 36, 0x60000020)
image[0x200:0x204] = b\"\\x48\\x31\\xc0\\xc3\"
image[0x240:0x255] = b\"Inno Setup Setup Data\"
os.write(output_fd, image)
""",
        )
        self._install_host_lib_aliases()
        self._write(
            "tools/toolchain-pins.json",
            json.dumps(
                {
                    "tools": {
                        "flutter": {
                            "version": "3.47.6",
                            "revision": "5fc346839b5d0eef006ed8404392afb4dfae428d",
                        },
                        "xcode": {"version": "27.0", "build": "27A266a"},
                        "gradle": {
                            "distribution_version": "9.8.0",
                            "distribution_sha256_by_flavour": {
                                "all": "46ac66d47f30f3dacfdf306e0b714a91a34fb94a22ba0a744b280933f47bc0cf",
                                "bin": "bafd5ce9cfaea0fbccfdc8439a1ac42fbd4cd9c89dc9a988228d8a2639a58e6c",
                            },
                        },
                    }
                },
                sort_keys=True,
            )
            + "\n",
        )
        self._copy_source_freeze_control_bytes()
        self.output = self.repo / ".artifacts" / "freeze"
        self.shared_path = self.output / "SHARED_INPUTS.json"
        MODULE.create_shared_manifest(self.repo, self.shared_path, "sr1")
        self.platform_paths: dict[str, pathlib.Path] = {}
        for platform in EXPECTED_PLATFORM_ROOTS:
            path = self.output / f"{platform.upper()}_INPUTS.json"
            MODULE.create_platform_manifest(self.repo, platform, self.shared_path, path)
            self.platform_paths[platform] = path
        self._install_current_custody()

    def tearDown(self) -> None:
        MODULE._POST_SELECT_HOOK = None
        MODULE._POST_INPUT_CAPTURE_HOOK = None
        MODULE._POST_DIRECTORY_BIND_HOOK = None
        MODULE._POST_FINAL_CAPTURE_HOOK = None
        MODULE._FIXTURE_MODE = False
        MODULE._PRODUCTION_REQUIRED = False
        MODULE._SOURCE_FREEZE_TRUST_PATH = None
        MODULE._SOURCE_FREEZE_SELF_AUTHORED_OVERRIDE = None
        freeze._POST_TREE_CAPTURE_HOOK = None
        freeze._POST_DIRECTORY_BIND_HOOK = None
        freeze._POST_FINAL_CAPTURE_HOOK = None
        freeze._EXTERNAL_TRUST_PATH = None
        self.trust_temp.cleanup()
        self.temporary.cleanup()

    def _write(self, relative: str, contents: str) -> None:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")

    def _replace_read_only_manifest(self, path: pathlib.Path, contents: str) -> None:
        os.chmod(path, 0o600)
        try:
            path.write_text(contents, encoding="utf-8")
        finally:
            os.chmod(path, 0o400)

    def _install_host_lib_aliases(self) -> None:
        for alias, target in EXPECTED_HOST_LIB_ALIASES:
            name = pathlib.PurePosixPath(alias).name
            lib_rel = f"lib/{name}"
            if not (self.repo / lib_rel).exists():
                self._write(lib_rel, f"shared {name}\n")
            path = self.repo / alias
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists() or path.is_symlink():
                path.unlink()
            try:
                path.symlink_to(target)
            except (OSError, NotImplementedError) as exc:
                raise unittest.SkipTest(
                    "Symlink creation is unavailable on this host"
                ) from exc

    def _restore_host_lib_alias(self, alias: str, target: str) -> None:
        path = self.repo / alias
        if path.exists() or path.is_symlink():
            path.unlink()
        path.symlink_to(target)

    def _write_json(self, relative: str, record: dict) -> None:
        self._write(
            relative, json.dumps(record, indent=2, sort_keys=True) + "\n"
        )

    def _file_sha256(self, relative: str) -> str:
        return hashlib.sha256((self.repo / relative).read_bytes()).hexdigest()

    def _copy_source_freeze_control_bytes(self) -> None:
        tools_src = pathlib.Path(freeze.__file__).resolve().parent
        tools_dst = self.repo / "tools"
        tools_dst.mkdir(parents=True, exist_ok=True)
        for name in (
            freeze.CONTROLLER_NAME,
            freeze.TEST_NAME,
            freeze.TOOLCHAIN_PIN_NAME,
        ):
            shutil.copy2(tools_src / name, tools_dst / name)

    def _copied_control_trust_fields(self) -> dict[str, str]:
        return {
            "controller_sha256": self._file_sha256(
                f"tools/{freeze.CONTROLLER_NAME}"
            ),
            "test_sha256": self._file_sha256(f"tools/{freeze.TEST_NAME}"),
            "manifest_sha256": self._file_sha256(
                f"tools/{freeze.TOOLCHAIN_PIN_NAME}"
            ),
        }

    def _rewrite_trust(self, record: dict) -> None:
        if self.trust_path.exists() or self.trust_path.is_symlink():
            os.chmod(self.trust_path, 0o644)
            self.trust_path.unlink()
        self.trust_path.write_text(json.dumps(record), encoding="utf-8")
        os.chmod(self.trust_path, 0o444)
        freeze._EXTERNAL_TRUST_PATH = str(self.trust_path)
        MODULE._SOURCE_FREEZE_TRUST_PATH = str(self.trust_path)

    def _rewrite_anchored(self, path: pathlib.Path, record: dict) -> None:
        anchor = path.with_name(path.name + ".sha256")
        os.chmod(path, 0o600)
        path.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.chmod(path, 0o400)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        os.chmod(anchor, 0o600)
        anchor.write_text(f"{digest}  {path.name}\n", encoding="ascii")
        os.chmod(anchor, 0o400)

    def _install_current_custody(self) -> None:
        release = "1.0.14+29"
        freeze_dir = f".artifacts/release-freeze-{release}"
        lock_relative = f"{freeze_dir}/{MODULE.APP_SOURCE_LOCK_NAME}"
        scope_relative = f"{freeze_dir}/{MODULE.SCOPE_FREEZE_NAME}"
        digest = "0" * 64
        scope = {
            "schema_version": 1,
            "contract": freeze.SCOPE_CONTRACT,
            "release": release,
            "scope_frozen": True,
            "source_fingerprint_sha256": digest,
            "publication_locked": True,
            "issuance_id": self.issuance_id,
            "created_utc": self.created_utc,
        }
        self._write_json(scope_relative, scope)
        lock = {
            "schema_version": 1,
            "contract": MODULE.APP_SOURCE_LOCK_CONTRACT,
            "release": release,
            "scope_frozen": True,
            "publication_locked": True,
            "scope_freeze_sha256": self._file_sha256(scope_relative),
            "frozen_combined_source_fingerprint_sha256": digest,
            "frozen_combined_source_file_count": 1,
            "app_source_contract": MODULE.APP_SOURCE_CONTRACT,
            "app_source_fingerprint_sha256": digest,
            "app_source_file_count": 1,
            "website_source_contract": MODULE.WEBSITE_SOURCE_CONTRACT,
            "website_source_fingerprint_sha256_at_freeze": digest,
            "website_source_file_count_at_freeze": 0,
            "website_index_sha256_at_freeze": digest,
            "immutable_website_source_fingerprint_sha256_at_freeze": digest,
            "immutable_website_source_file_count_at_freeze": 0,
            "website_mutable_paths_after_scope_freeze": ["web/index.html"],
            "website_staging_allowed_after_scope_freeze": True,
            "issuance_id": self.issuance_id,
            "created_utc": self.created_utc,
        }
        self._write_json(lock_relative, lock)
        self.lock_path = self.repo / lock_relative
        self.scope_path = self.repo / scope_relative
        self._issue_current_trust()

    def _issue_current_trust(self) -> None:
        record = {
            "schema_version": 1,
            "contract": freeze.EXTERNAL_TRUST_CONTRACT,
            "release": "1.0.14+29",
            "created_utc": self.created_utc,
            "issuance_id": self.issuance_id,
            "authenticated": True,
            "issuer": freeze.EXTERNAL_TRUST_ISSUER,
            "app_source_lock_sha256": hashlib.sha256(
                self.lock_path.read_bytes()
            ).hexdigest(),
            "scope_freeze_sha256": hashlib.sha256(
                self.scope_path.read_bytes()
            ).hexdigest(),
            "website_stage_sha256": None,
        }
        record.update(self._copied_control_trust_fields())
        self._rewrite_trust(record)

    @contextlib.contextmanager
    def _hook(self, name: str, hook):
        previous = getattr(MODULE, name)
        setattr(MODULE, name, hook)
        try:
            yield
        finally:
            setattr(MODULE, name, previous)

    def _other_platforms(self, *excluded: str) -> tuple[str, ...]:
        return tuple(
            platform for platform in EXPECTED_PLATFORM_ROOTS if platform not in excluded
        )

    def test_all_initial_manifests_verify(self) -> None:
        for platform, path in self.platform_paths.items():
            result = MODULE.verify_manifest(self.repo, path)
            self.assertTrue(result["ok"])
            self.assertEqual(result["platform"], platform)

    def test_release_inventory_matches_independent_reviewed_controls(self) -> None:
        _assert_independent_release_inventory()

    def test_hostile_inventory_omission_and_owner_drift_are_detected(self) -> None:
        omitted = dict(MODULE.PLATFORM_PRODUCER_PATHS)
        omitted["windows"] = tuple(
            path
            for path in omitted["windows"]
            if path != "tools/windows_inno_sign.ps1"
        )
        with mock.patch.object(MODULE, "PLATFORM_PRODUCER_PATHS", omitted):
            with self.assertRaisesRegex(AssertionError, "producer inventory drifted"):
                _assert_independent_release_inventory()

        drifted = dict(MODULE.PLATFORM_PRODUCER_PATHS)
        drifted["linux"] = drifted["linux"] + ("tools/windows_inno_sign.ps1",)
        with mock.patch.object(MODULE, "PLATFORM_PRODUCER_PATHS", drifted):
            with self.assertRaisesRegex(AssertionError, "producer inventory drifted"):
                _assert_independent_release_inventory()

    def test_executing_controller_is_exact_reviewed_source_code(self) -> None:
        actual_repo = SCRIPT.parents[1]
        payload = SCRIPT.read_bytes()
        self.assertEqual(
            MODULE._require_executing_controller(actual_repo, payload),
            payload,
        )
        stale = compile(
            "stale_controller = True\n",
            MODULE._EXECUTING_MODULE_CODE.co_filename,
            "exec",
            dont_inherit=True,
        )
        with mock.patch.object(MODULE, "_EXECUTING_MODULE_CODE", stale):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError,
                "code differs from reviewed source bytes",
            ):
                MODULE._require_executing_controller(actual_repo, payload)

    def test_source_freeze_loader_rejects_module_and_bytecode_poisoning(self) -> None:
        poisoned = type(sys)("release_source_freeze")
        poisoned.SCOPE_CONTRACT = "poisoned"
        with mock.patch.dict(sys.modules, {"release_source_freeze": poisoned}):
            with mock.patch.object(MODULE, "_SOURCE_FREEZE_MODULE", poisoned):
                isolated = MODULE._source_freeze_module()
        self.assertIsNot(isolated, poisoned)
        self.assertEqual(isolated.SCOPE_CONTRACT, freeze.SCOPE_CONTRACT)
        self.assertIsNone(isolated.__loader__)
        self.assertIsNone(isolated.__cached__)
        self.assertNotIn(isolated.__name__, sys.modules)

    def test_isolated_fixture_mode_cannot_authorize_release(self) -> None:
        record = json.loads(self.shared_path.read_text(encoding="utf-8"))
        self.assertFalse(record["publication_authorized"])
        self.assertTrue(MODULE.isolated_fixture_mode_active())
        with mock.patch.object(
            sys,
            "argv",
            [
                "release_dependency_freeze.py",
                "freeze-shared",
                "--repo",
                str(self.repo),
                "--revision",
                "sr-cli",
                "--output",
                str(self.output / "CLI_SHARED.json"),
            ],
        ):
            self.assertEqual(MODULE.main(), 1)
        self.assertFalse((self.output / "CLI_SHARED.json").exists())

    def test_production_cli_refuses_a_tree_without_git(self) -> None:
        MODULE._FIXTURE_MODE = False
        try:
            with mock.patch.object(
                sys,
                "argv",
                [
                    "release_dependency_freeze.py",
                    "freeze-shared",
                    "--repo",
                    str(self.repo),
                    "--revision",
                    "sr-cli",
                    "--output",
                    str(self.output / "CLI_SHARED.json"),
                ],
            ):
                self.assertEqual(MODULE.main(), 1)
        finally:
            MODULE._FIXTURE_MODE = True
        self.assertFalse((self.output / "CLI_SHARED.json").exists())

    def test_native_change_invalidates_only_owner(self) -> None:
        self._write("windows/windows-input.txt", "windows changed\n")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Native"):
            MODULE.verify_manifest(self.repo, self.platform_paths["windows"])
        for platform in self._other_platforms("windows"):
            self.assertTrue(
                MODULE.verify_manifest(self.repo, self.platform_paths[platform])["ok"]
            )

    def test_shared_change_invalidates_every_platform(self) -> None:
        self._write("lib/main.dart", "void main() { print('changed'); }\n")
        for path in self.platform_paths.values():
            with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Shared"):
                MODULE.verify_manifest(self.repo, path)

    def test_release_controls_and_toolchain_pin_invalidate_every_platform(self) -> None:
        for control in MODULE.COMMON_RELEASE_CONTROL_PATHS:
            with self.subTest(control=control):
                original = (self.repo / control).read_text(encoding="utf-8")
                self._write(control, original + "changed release control\n")
                for path in self.platform_paths.values():
                    with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Producer"):
                        MODULE.verify_manifest(self.repo, path)
                self._write(control, original)

    def test_browser_and_go_custody_controls_are_common_release_inputs(self) -> None:
        for control in (
            "tools/release_browser_archive_custody.py",
            "tools/release_browser_archive_custody.sh",
            "tools/release_go_archive_custody.py",
            "tools/release_go_archive_custody.sh",
        ):
            self.assertIn(control, MODULE.COMMON_RELEASE_CONTROL_PATHS)

    def test_generated_build_outputs_do_not_invalidate(self) -> None:
        self._write("windows/build/output.exe", "output\n")
        self._write("windows/flutter/generated_plugins.cmake", "generated\n")
        self._write("android/.gradle/cache.bin", "generated\n")
        self._write(
            "android/app/src/main/java/io/flutter/plugins/GeneratedPluginRegistrant.java",
            "generated\n",
        )
        self._write("macos/Flutter/GeneratedPluginRegistrant.swift", "generated\n")
        self._write("ios/Runner/GeneratedPluginRegistrant.h", "generated\n")
        self._write("ios/Runner/GeneratedPluginRegistrant.m", "generated\n")
        # Rehearsal r46: the post-build check refused this generated podspec.
        self._write("ios/Flutter/Flutter.podspec", "# This is a generated file\n")
        for path in self.platform_paths.values():
            self.assertTrue(MODULE.verify_manifest(self.repo, path)["ok"])

    def test_generated_plugin_symlink_is_rejected_inside_excluded_tree(self) -> None:
        target = self.repo / "generated-plugin-target"
        target.mkdir()
        self._write("generated-plugin-target/plugin.txt", "generated\n")
        link = (
            self.repo
            / "windows/flutter/ephemeral/.plugin_symlinks/generated_plugin"
        )
        link.parent.mkdir(parents=True, exist_ok=True)
        try:
            link.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation is unavailable on this host")
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, r"Symlink|reparse point"
        ):
            MODULE.verify_manifest(self.repo, self.platform_paths["windows"])

    def test_undeclared_asset_does_not_invalidate_artifacts(self) -> None:
        self._write("assets/unused-design-source.png", "not packaged\n")
        for path in self.platform_paths.values():
            self.assertTrue(MODULE.verify_manifest(self.repo, path)["ok"])

    def test_platform_extra_input_invalidates_only_owner(self) -> None:
        self._write(
            "docs/THIRD_PARTY_NOTICES_AND_COMPONENT_INVENTORY.md",
            "linux notices changed\n",
        )
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Native"):
            MODULE.verify_manifest(self.repo, self.platform_paths["linux"])
        for platform in ("android", "windows", "macos", "ios"):
            self.assertTrue(
                MODULE.verify_manifest(self.repo, self.platform_paths[platform])["ok"]
            )

    def test_apple_common_and_target_engine_invalidation(self) -> None:
        common_path = self.repo / "apple/WinsTunnelCore/macos-input.txt"
        original_common = common_path.read_text(encoding="utf-8")
        self._write(
            "apple/WinsTunnelCore/macos-input.txt", "shared Apple changed\n"
        )
        for platform in ("macos", "ios"):
            with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Native"):
                MODULE.verify_manifest(self.repo, self.platform_paths[platform])
        for platform in ("android", "windows", "linux"):
            self.assertTrue(
                MODULE.verify_manifest(self.repo, self.platform_paths[platform])["ok"]
            )

        self._write("apple/WinsTunnelCore/macos-input.txt", original_common)
        self._write(
            "apple/EngineArtifacts/macos/macos-input.txt", "macOS engine changed\n"
        )
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Native"):
            MODULE.verify_manifest(self.repo, self.platform_paths["macos"])
        self.assertTrue(
            MODULE.verify_manifest(self.repo, self.platform_paths["ios"])["ok"]
        )

    def test_apple_icon_invalidates_only_both_apple_artifacts(self) -> None:
        self._write("assets/icon/Win Empire.png", "Apple icon changed\n")
        for platform in ("macos", "ios"):
            with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Native"):
                MODULE.verify_manifest(self.repo, self.platform_paths[platform])
        for platform in ("android", "windows", "linux"):
            self.assertTrue(
                MODULE.verify_manifest(self.repo, self.platform_paths[platform])["ok"]
            )

    def test_platform_export_option_invalidates_only_owner(self) -> None:
        self._write(
            "apple/ExportOptions/ios-app-store-local.plist",
            "iOS export changed\n",
        )
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Native"):
            MODULE.verify_manifest(self.repo, self.platform_paths["ios"])
        for platform in ("android", "windows", "linux", "macos"):
            self.assertTrue(
                MODULE.verify_manifest(self.repo, self.platform_paths[platform])["ok"]
            )

    def test_windows_builder_transients_do_not_invalidate(self) -> None:
        self._write(
            "installer/windows/dependencies/xray-extract/xray.exe", "temporary\n"
        )
        self._write(
            "installer/windows/dependencies/xray-windows-64.zip", "temporary\n"
        )
        self.assertTrue(
            MODULE.verify_manifest(self.repo, self.platform_paths["windows"])["ok"]
        )

    def test_windows_native_host_inputs_are_exact_shipping_files(self) -> None:
        expected = (
            "tools/native_messaging/host/bin/wins_bridge_host.dart",
            "tools/native_messaging/host/pubspec.lock",
            "tools/native_messaging/host/pubspec.yaml",
            "tools/native_messaging/install_native_host.sh",
            "tools/native_messaging/manifests/store_ids.json",
            "tools/native_messaging/native_host_layout.py",
            "tools/native_messaging/render_host_manifest.py",
        )
        extras = MODULE.PLATFORM_NATIVE_EXTRA_PATHS["windows"]
        windows_roots = MODULE.PLATFORM_ROOTS["windows"]
        windows_producers = MODULE.PLATFORM_PRODUCER_PATHS["windows"]
        self.assertEqual(MODULE.WINDOWS_NATIVE_HOST_INPUT_PATHS, expected)
        self.assertEqual(
            extras, ("assets/icon/app_icon.png",) + expected
        )
        self.assertEqual(
            MODULE.WINDOWS_NATIVE_HOST_LIB_SYMLINK_ALIASES,
            freeze.SOURCE_SYMLINK_ALIASES,
        )
        self.assertEqual(len(MODULE.WINDOWS_NATIVE_HOST_LIB_SYMLINK_ALIASES), 8)
        self.assertEqual(
            MODULE.WINDOWS_NATIVE_HOST_LIB_SYMLINK_DIR,
            "tools/native_messaging/host/lib",
        )
        for alias, target in MODULE.WINDOWS_NATIVE_HOST_LIB_SYMLINK_ALIASES:
            with self.subTest(alias=alias):
                self.assertNotIn(alias, extras)
                self.assertNotIn(alias, windows_roots)
                self.assertNotIn(alias, windows_producers)
                self.assertEqual(
                    target,
                    f"../../../../lib/{pathlib.PurePosixPath(alias).name}",
                )
        record = json.loads(self.platform_paths["windows"].read_text(encoding="utf-8"))
        native_files = [item["path"] for item in record["native_inputs"]["files"]]
        for alias, _target in MODULE.WINDOWS_NATIVE_HOST_LIB_SYMLINK_ALIASES:
            self.assertNotIn(alias, native_files)
        self.assertNotIn("tools", windows_roots)
        self.assertNotIn("tools/native_messaging", windows_roots)
        self.assertNotIn("tools/native_messaging/host", windows_roots)
        self.assertIn(
            "tools/native_messaging/build_native_host.ps1", windows_producers
        )
        rejected = (
            "tools/native_messaging/host/bin/wins_bridge_host_harness.dart",
            "tools/native_messaging/host/lib/browser_bridge_app_ipc.dart",
            "tools/native_messaging/host/.dart_tool/package_config.json",
            "tools/native_messaging/host/build/host.dill",
            "tools/native_messaging/manifests/org.winsvpn.bridge.chrome.json",
            "tools/native_messaging/manifests/org.winsvpn.bridge.edge.json",
            "tools/native_messaging/manifests/org.winsvpn.bridge.firefox.json",
            "tools/native_messaging/install_macos_native_host.sh",
            "tools/native_messaging/README-macos-companion-pkg.md",
            "tools/native_messaging/live_boundary_probe.py",
            "tools/native_messaging/test_native_host_registration.py",
        )
        for relative in rejected:
            with self.subTest(rejected=relative):
                self.assertNotIn(relative, extras)
                self.assertNotIn(relative, windows_roots)
                self.assertNotIn(relative, windows_producers)

        previous_bytecode = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        try:
            import windows_cross_store_artifact_gate as gate
        finally:
            sys.dont_write_bytecode = previous_bytecode

        gate_hosts = tuple(
            path
            for path in gate.WINDOWS_INSTALLER_SOURCE_PATHS
            if path.startswith("tools/native_messaging/")
        )
        self.assertEqual(MODULE.WINDOWS_NATIVE_HOST_INPUT_PATHS, gate_hosts)
        installer = (
            SCRIPT.parents[1] / "installer/windows/build_installer.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("build_native_host.ps1", installer)
        self.assertIn("render_host_manifest.py", installer)
        self.assertIn("native_host_layout.py", installer)

    def test_windows_native_host_source_edit_invalidates_inputs_and_index(
        self,
    ) -> None:
        index = self._create_index()
        self.assertTrue(MODULE.verify_release_index(self.repo, index)["ok"])
        host = "tools/native_messaging/host/bin/wins_bridge_host.dart"
        original = (self.repo / host).read_text(encoding="utf-8")
        self._write(host, original + "host-only source edit\n")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Native"):
            MODULE.verify_manifest(self.repo, self.platform_paths["windows"])
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Native"):
            MODULE.verify_release_index(self.repo, index)
        for platform in self._other_platforms("windows"):
            self.assertTrue(
                MODULE.verify_manifest(self.repo, self.platform_paths[platform])[
                    "ok"
                ]
            )

    def test_windows_store_id_record_edit_invalidates_inputs_and_index(
        self,
    ) -> None:
        index = self._create_index()
        self.assertTrue(MODULE.verify_release_index(self.repo, index)["ok"])
        record = "tools/native_messaging/manifests/store_ids.json"
        original = (self.repo / record).read_text(encoding="utf-8")
        self._write(record, original + "\n")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Native"):
            MODULE.verify_manifest(self.repo, self.platform_paths["windows"])
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Native"):
            MODULE.verify_release_index(self.repo, index)

    def test_windows_native_host_unrelated_generated_and_private_do_not_invalidate(
        self,
    ) -> None:
        index = self._create_index()
        for relative in (
            "tools/native_messaging/host/bin/wins_bridge_host_harness.dart",
            "tools/native_messaging/host/.dart_tool/package_config.json",
            "tools/native_messaging/host/build/host.dill",
            "tools/native_messaging/manifests/org.winsvpn.bridge.chrome.json",
            "tools/native_messaging/install_macos_native_host.sh",
            "tools/native_messaging/README-macos-companion-pkg.md",
            "tools/native_messaging/live_boundary_probe.py",
        ):
            self._write(relative, "unrelated or generated native-host artifact\n")
        self.assertTrue(
            MODULE.verify_manifest(self.repo, self.platform_paths["windows"])["ok"]
        )
        self.assertTrue(MODULE.verify_release_index(self.repo, index)["ok"])
        for platform in self._other_platforms("windows"):
            self.assertTrue(
                MODULE.verify_manifest(self.repo, self.platform_paths[platform])[
                    "ok"
                ]
            )

    def test_windows_host_lib_alias_retarget_fails_windows_and_index_only(self) -> None:
        index = self._create_index()
        self.assertTrue(MODULE.verify_release_index(self.repo, index)["ok"])
        evil = self.repo / "tools" / "native_messaging" / "host" / "evil.dart"
        evil.write_text("hostile host lib payload\n", encoding="utf-8")
        for alias, expected in MODULE.WINDOWS_NATIVE_HOST_LIB_SYMLINK_ALIASES:
            with self.subTest(alias=alias, kind="relative-evil"):
                path = self.repo / alias
                path.unlink()
                path.symlink_to("../evil.dart")
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError, r"symlink alias"
                ):
                    MODULE.verify_manifest(self.repo, self.platform_paths["windows"])
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError, r"symlink alias"
                ):
                    MODULE.verify_release_index(self.repo, index)
                for platform in self._other_platforms("windows"):
                    self.assertTrue(
                        MODULE.verify_manifest(
                            self.repo, self.platform_paths[platform]
                        )["ok"]
                    )
                self._restore_host_lib_alias(alias, expected)
            with self.subTest(alias=alias, kind="wrong-lib-file"):
                path = self.repo / alias
                path.unlink()
                path.symlink_to("../../../../lib/main.dart")
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError, r"symlink alias"
                ):
                    MODULE.verify_manifest(self.repo, self.platform_paths["windows"])
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError, r"symlink alias"
                ):
                    MODULE.verify_release_index(self.repo, index)
                for platform in self._other_platforms("windows"):
                    self.assertTrue(
                        MODULE.verify_manifest(
                            self.repo, self.platform_paths[platform]
                        )["ok"]
                    )
                self._restore_host_lib_alias(alias, expected)
        evil.unlink()
        self.assertTrue(
            MODULE.verify_manifest(self.repo, self.platform_paths["windows"])["ok"]
        )
        self.assertTrue(MODULE.verify_release_index(self.repo, index)["ok"])

    def test_windows_host_lib_alias_replace_fails_windows_and_index_only(self) -> None:
        index = self._create_index()
        for alias, expected in MODULE.WINDOWS_NATIVE_HOST_LIB_SYMLINK_ALIASES:
            with self.subTest(alias=alias):
                path = self.repo / alias
                name = pathlib.PurePosixPath(alias).name
                payload = (self.repo / "lib" / name).read_bytes() + b"replaced-alias\n"
                path.unlink()
                path.write_bytes(payload)
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError, r"symlink alias"
                ):
                    MODULE.verify_manifest(self.repo, self.platform_paths["windows"])
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError, r"symlink alias"
                ):
                    MODULE.verify_release_index(self.repo, index)
                for platform in self._other_platforms("windows"):
                    self.assertTrue(
                        MODULE.verify_manifest(
                            self.repo, self.platform_paths[platform]
                        )["ok"]
                    )
                self._restore_host_lib_alias(alias, expected)
        self.assertTrue(
            MODULE.verify_manifest(self.repo, self.platform_paths["windows"])["ok"]
        )
        self.assertTrue(MODULE.verify_release_index(self.repo, index)["ok"])

    def test_deleted_mullvad_paths_remain_excluded_from_windows_freeze(self) -> None:
        deleted = (
            "installer/windows/dependencies/mullvad-split-tunnel.sys",
            "installer/windows/dependencies/mullvad-split-tunnel.cat",
            "installer/windows/dependencies/mullvad-split-tunnel.inf",
            "installer/windows/dependencies/mullvad-split-tunnel-arm64.sys",
            "installer/windows/dependencies/mullvad-split-tunnel-arm64.cat",
            "installer/windows/dependencies/mullvad-split-tunnel-arm64.inf",
            "installer/windows/licenses/mullvad-split-tunnel-MPL-2.0.txt",
        )
        windows_declared = (
            MODULE.PLATFORM_ROOTS["windows"]
            + MODULE.PLATFORM_NATIVE_EXTRA_PATHS["windows"]
            + MODULE.PLATFORM_PRODUCER_PATHS["windows"]
            + MODULE.WINDOWS_NATIVE_HOST_INPUT_PATHS
            + tuple(
                alias for alias, _target in MODULE.WINDOWS_NATIVE_HOST_LIB_SYMLINK_ALIASES
            )
            + tuple(
                target
                for _alias, target in MODULE.WINDOWS_NATIVE_HOST_LIB_SYMLINK_ALIASES
            )
        )
        for relative in deleted:
            with self.subTest(deleted=relative):
                self.assertNotIn(relative, windows_declared)
        for relative in windows_declared:
            with self.subTest(declared=relative):
                self.assertNotIn("mullvad", relative.casefold())

    def test_unknown_file_inside_source_scope_invalidates(self) -> None:
        self._write("windows/test-results/current-run.log", "unexpected\n")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Native"):
            MODULE.verify_manifest(self.repo, self.platform_paths["windows"])

    def test_manifest_is_immutable(self) -> None:
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "overwrite"):
            MODULE.create_shared_manifest(self.repo, self.shared_path, "sr1")

    def test_manifest_publication_is_read_only_and_return_bound(self) -> None:
        output = self.output / "DURABLE_SHARED_INPUTS.json"
        MODULE.create_shared_manifest(self.repo, output, "durable-shared")
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o400)

        original = MODULE._write_new

        def transient_output_rename(repo, path, record, label):
            result = original(repo, path, record, label)
            backup = path.with_name(path.name + ".held")
            path.rename(backup)
            backup.rename(path)
            return result

        with mock.patch.object(
            MODULE, "_write_new", side_effect=transient_output_rename
        ):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError,
                "path or ancestor was replaced after final capture",
            ):
                MODULE.create_shared_manifest(
                    self.repo,
                    self.output / "RENAMED_SHARED_INPUTS.json",
                    "renamed-shared",
                )

    def test_manifest_retains_selected_source_leaf_through_return(self) -> None:
        original = MODULE._write_new
        source = self.repo / "lib/main.dart"

        def write_then_touch_source(repo, path, record, label):
            result = original(repo, path, record, label)
            with source.open("r+b") as handle:
                payload = handle.read()
                handle.seek(0)
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            return result

        with mock.patch.object(
            MODULE, "_write_new", side_effect=write_then_touch_source
        ):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError,
                "path or ancestor was replaced after final capture",
            ):
                MODULE.create_shared_manifest(
                    self.repo,
                    self.output / "SOURCE_TOUCHED_SHARED_INPUTS.json",
                    "source-touched",
                )

    def test_secret_in_selected_scope_fails_closed(self) -> None:
        self._write("android/release-key.p12", "not-a-real-key\n")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "forbidden"):
            MODULE.input_state(self.repo, MODULE.platform_native_paths("android"))

    def test_credential_variants_and_symlinks_fail_closed(self) -> None:
        for relative in (
            "android/.env.production",
            "android/signing.ppk",
            "android/key.properties",
        ):
            with self.subTest(relative=relative):
                path = self.repo / relative
                self._write(relative, "secret\n")
                with self.assertRaisesRegex(MODULE.DependencyFreezeError, "forbidden"):
                    MODULE.input_state(
                        self.repo, MODULE.platform_native_paths("android")
                    )
                path.unlink()
        target = self.repo / "outside.txt"
        target.write_text("outside\n", encoding="utf-8")
        link = self.repo / "android" / "linked-input"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation is unavailable on this host")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Symlink"):
            MODULE.input_state(self.repo, MODULE.platform_native_paths("android"))

    def test_external_pubspec_asset_is_shared(self) -> None:
        for path in self.platform_paths.values():
            path.unlink()
        self.shared_path.unlink()
        self._write(
            "pubspec.yaml",
            "name: wins_vpn\nversion: 1.0.14+29\ndependencies:\n"
            "  flutter:\n    sdk: flutter\nflutter:\n  assets:\n"
            "    - assets/\n    - branding/logo.txt\n",
        )
        self._write("branding/logo.txt", "brand one\n")
        MODULE.create_shared_manifest(self.repo, self.shared_path, "sr2")
        windows = self.output / "WINDOWS_INPUTS_V2.json"
        MODULE.create_platform_manifest(
            self.repo, "windows", self.shared_path, windows
        )
        self._write("branding/logo.txt", "brand two\n")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Shared"):
            MODULE.verify_manifest(self.repo, windows)

    def test_adjacent_assets_shaders_and_fonts_are_shared(self) -> None:
        for path in self.platform_paths.values():
            path.unlink()
        self.shared_path.unlink()
        self._write(
            "pubspec.yaml",
            "name: wins_vpn\nversion: 1.0.14+29\nflutter:\n"
            "  assets:\n    - assets/\n"
            "  shaders:\n    - effects/privacy.frag\n"
            "  fonts:\n    - family: WinsVPN\n      fonts:\n"
            "        - asset: typography/winsvpn.ttf\n",
        )
        self._write("effects/privacy.frag", "shader one\n")
        self._write("typography/winsvpn.ttf", "font one\n")
        MODULE.create_shared_manifest(self.repo, self.shared_path, "sr3")
        windows = self.output / "WINDOWS_INPUTS_V3.json"
        MODULE.create_platform_manifest(
            self.repo, "windows", self.shared_path, windows
        )
        self._write("effects/privacy.frag", "shader two\n")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Shared"):
            MODULE.verify_manifest(self.repo, windows)

    def test_valid_yaml_flow_assets_shaders_and_fonts_are_shared(self) -> None:
        self._write(
            "pubspec.yaml",
            "name: wins_vpn\nversion: 1.0.14+29\nflutter:\n"
            "  assets: [branding/logo.txt, \"branding/flow #1.txt\"]\n"
            "  shaders: [\n    'effects/flow,privacy.frag',\n  ]\n"
            "  fonts: [{family: WinsVPN, fonts: [{asset: typography/flow.ttf}]}]\n",
        )
        expected = (
            "branding/logo.txt",
            "branding/flow #1.txt",
            "effects/flow,privacy.frag",
            "typography/flow.ttf",
        )
        for relative in expected:
            self._write(relative, f"flow asset: {relative}\n")
        self.assertEqual(MODULE._declared_pubspec_assets(self.repo), expected)
        roots = MODULE.shared_roots(self.repo)
        for relative in expected:
            self.assertIn(relative, roots)
        selected = {item.path for item in MODULE.input_state(self.repo, roots).files}
        for relative in expected:
            self.assertIn(relative, selected)

    def test_pubspec_overrides_and_unsupported_asset_mappings_are_rejected(self) -> None:
        self._write("pubspec_overrides.yaml", "dependency_overrides: {}\n")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "forbidden"):
            MODULE.shared_roots(self.repo)
        (self.repo / "pubspec_overrides.yaml").unlink()

        hostile = {
            "top-level-flow": "flutter: {assets: [branding/logo.txt]}\n",
            "block-map": "flutter:\n  assets:\n    - path: branding/logo.txt\n",
            "flow-map": "flutter:\n  assets: [{path: branding/logo.txt}]\n",
        }
        for label, declaration in hostile.items():
            with self.subTest(label=label):
                self._write(
                    "pubspec.yaml",
                    "name: wins_vpn\nversion: 1.0.14+29\n" + declaration,
                )
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError, "flow mapping|map-form"
                ):
                    MODULE.shared_roots(self.repo)

    def test_duplicate_top_level_flutter_mappings_are_rejected(self) -> None:
        self._write(
            "pubspec.yaml",
            "name: wins_vpn\nversion: 1.0.14+29\n"
            "flutter:\n  assets: [assets/icon.txt]\n"
            "flutter:\n  shaders: [effects/privacy.frag]\n",
        )
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "duplicate top-level flutter"
        ):
            MODULE.shared_roots(self.repo)

    def test_one_retained_pubspec_drives_every_operation_interpretation(self) -> None:
        observed: list[tuple[int, bytes]] = []
        original = MODULE._operation_pubspec

        def observe(repo: pathlib.Path):
            held = original(repo)
            if held is not None:
                observed.append((id(held), held.payload))
            return held

        output = self.output / "PUBSPEC_CUSTODY.json"
        with mock.patch.object(MODULE, "_operation_pubspec", side_effect=observe):
            MODULE.create_shared_manifest(self.repo, output, "pubspec-custody")
        self.assertGreaterEqual(len(observed), 3)
        self.assertEqual(len({identity for identity, _payload in observed}), 1)
        self.assertEqual(
            {payload for _identity, payload in observed},
            {(self.repo / "pubspec.yaml").read_bytes()},
        )

    def test_transient_compiler_input_creation_is_rejected_operation_wide(self) -> None:
        transient = self.repo / "lib" / "transient_release_input.dart"

        def mutate_after_capture() -> None:
            transient.write_text("void transient() {}\n", encoding="utf-8")
            transient.unlink()
            MODULE._POST_INPUT_CAPTURE_HOOK = None

        MODULE._POST_INPUT_CAPTURE_HOOK = mutate_after_capture
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError,
            "compiler-input|path or ancestor|changed during freeze capture",
        ):
            MODULE.create_shared_manifest(
                self.repo,
                self.output / "TRANSIENT_SOURCE.json",
                "transient-source",
            )

    def test_transient_pubspec_override_is_rejected_operation_wide(self) -> None:
        transient = self.repo / "pubspec_overrides.yaml"

        def mutate_after_capture() -> None:
            transient.write_text("dependency_overrides: {}\n", encoding="utf-8")
            transient.unlink()
            MODULE._POST_INPUT_CAPTURE_HOOK = None

        MODULE._POST_INPUT_CAPTURE_HOOK = mutate_after_capture
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError,
            "Release-input repository root|repository ancestor|path or ancestor|"
            "changed during freeze capture",
        ):
            MODULE.create_shared_manifest(
                self.repo,
                self.output / "TRANSIENT_OVERRIDE.json",
                "transient-override",
            )

    def test_late_transient_source_creation_is_rejected_before_api_return(self) -> None:
        transient = self.repo / "lib" / "late_transient_release_input.dart"
        original = MODULE._write_new

        def mutate_after_publication(*args, **kwargs):
            result = original(*args, **kwargs)
            transient.write_text("void lateTransient() {}\n", encoding="utf-8")
            transient.unlink()
            return result

        with mock.patch.object(
            MODULE, "_write_new", side_effect=mutate_after_publication
        ):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError,
                "compiler-input|path or ancestor|changed",
            ):
                MODULE.create_shared_manifest(
                    self.repo,
                    self.output / "LATE_TRANSIENT_SOURCE.json",
                    "late-transient-source",
                )

    def test_pubspec_asset_paths_preserve_dots_and_reject_traversal(self) -> None:
        self.assertEqual(
            MODULE._normalize_declared_asset_path("./branding/.release/logo.txt"),
            "branding/.release/logo.txt",
        )
        for unsafe in ("../secret.txt", "./../secret.txt", "..\\secret.txt", "/tmp/x"):
            with self.subTest(unsafe=unsafe):
                with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Unsafe"):
                    MODULE._normalize_declared_asset_path(unsafe)

    def test_platform_manifest_tampering_fails(self) -> None:
        path = self.platform_paths["windows"]
        record = json.loads(path.read_text(encoding="utf-8"))
        record["publication_authorized"] = True
        record["native_roots"] = ["tampered"]
        record["native_inputs"]["files"] = []
        self._replace_read_only_manifest(path, json.dumps(record))
        with self.assertRaises(MODULE.DependencyFreezeError):
            MODULE.verify_manifest(self.repo, path)

    def test_shared_manifest_tampering_fails(self) -> None:
        record = json.loads(self.shared_path.read_text(encoding="utf-8"))
        record["publication_authorized"] = True
        record["roots"] = ["tampered"]
        record["inputs"]["files"] = []
        self._replace_read_only_manifest(self.shared_path, json.dumps(record))
        with self.assertRaises(MODULE.DependencyFreezeError):
            MODULE.verify_manifest(self.repo, self.shared_path)

    def test_producer_change_invalidates_only_owner(self) -> None:
        self._write("tools/windows_inno_sign.ps1", "changed producer\n")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Producer"):
            MODULE.verify_manifest(self.repo, self.platform_paths["windows"])
        for platform in ("android", "linux", "macos", "ios"):
            self.assertTrue(
                MODULE.verify_manifest(self.repo, self.platform_paths[platform])["ok"]
            )

    def test_windows_awg_builder_change_invalidates_only_windows(self) -> None:
        self._write("tools/build_windows_awg_engine.ps1", "changed AWG producer\n")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Producer"):
            MODULE.verify_manifest(self.repo, self.platform_paths["windows"])
        for platform in ("android", "linux", "macos", "ios"):
            self.assertTrue(
                MODULE.verify_manifest(self.repo, self.platform_paths[platform])["ok"]
            )

    def test_windows_amneziawg_client_builder_change_invalidates_only_windows(
        self,
    ) -> None:
        self._write(
            "tools/build_windows_amneziawg_client.ps1",
            "changed AmneziaWG maintenance-helper producer\n",
        )
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Producer"):
            MODULE.verify_manifest(self.repo, self.platform_paths["windows"])
        for platform in ("android", "linux", "macos", "ios"):
            self.assertTrue(
                MODULE.verify_manifest(self.repo, self.platform_paths[platform])["ok"]
            )

    def test_every_installer_helper_is_bound_as_a_windows_producer(self) -> None:
        helpers = (
            "tools/release_dependency_freeze.py",
            "tools/build_windows_amneziawg_client.ps1",
            "tools/verify_embedded_engine_runtime_versions.py",
            "tools/release_obfuscation_contract.py",
            "tools/private_release_symbol_custody.py",
            "tools/private_symbol_custody.ps1",
            "tools/validate_release_artifact_privacy.py",
        )
        windows_producers = set(MODULE.PLATFORM_PRODUCER_PATHS["windows"])
        installer = (
            SCRIPT.parents[1] / "installer/windows/build_installer.ps1"
        ).read_text(encoding="utf-8")
        for helper in helpers:
            with self.subTest(helper=helper):
                self.assertIn(helper, windows_producers)
                self.assertIn(pathlib.PurePosixPath(helper).name, installer)
                original = (self.repo / helper).read_text(encoding="utf-8")
                self._write(helper, original + "changed installer helper\n")
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError, "Producer"
                ):
                    MODULE.verify_manifest(
                        self.repo, self.platform_paths["windows"]
                    )
                self._write(helper, original)

    def test_generated_intellij_module_file_is_excluded(self) -> None:
        self._write("android/wins_vpn_android.iml", "generated IDE state\n")
        result = MODULE.verify_manifest(
            self.repo, self.platform_paths["android"]
        )
        self.assertTrue(result["ok"])

    def test_release_freeze_verifier_is_bound_to_every_platform(self) -> None:
        verifier = "tools/release_dependency_freeze.py"
        for producers in MODULE.PLATFORM_PRODUCER_PATHS.values():
            self.assertIn(verifier, producers)
        original = (self.repo / verifier).read_text(encoding="utf-8")
        self._write(verifier, original + "changed release verifier\n")
        for platform, manifest in self.platform_paths.items():
            with self.subTest(platform=platform):
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError, "Producer"
                ):
                    MODULE.verify_manifest(self.repo, manifest)

    def test_macos_android_helper_change_invalidates_only_android(self) -> None:
        self._write(
            "tools/build_android_release_macos.sh",
            "changed macOS Android producer\n",
        )
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Producer"):
            MODULE.verify_manifest(self.repo, self.platform_paths["android"])
        for platform in ("windows", "linux", "macos", "ios"):
            self.assertTrue(
                MODULE.verify_manifest(self.repo, self.platform_paths[platform])["ok"]
            )

    def test_every_android_byte_producer_is_bound_to_android(self) -> None:
        helpers = (
            "tools/release_dependency_freeze.py",
            "tools/android_signing_preseed.ps1",
            "tools/build_android_release.ps1",
            "tools/build_android_release_macos.sh",
            "tools/android_release_publication.py",
            "tools/release_obfuscation_contract.py",
            "tools/private_release_symbol_custody.py",
            "tools/private_symbol_custody.ps1",
            "tools/validate_release_artifact_privacy.py",
        )
        android_producers = set(MODULE.PLATFORM_PRODUCER_PATHS["android"])
        for helper in helpers:
            with self.subTest(helper=helper):
                self.assertIn(helper, android_producers)
                original = (self.repo / helper).read_text(encoding="utf-8")
                self._write(helper, original + "changed Android producer helper\n")
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError, "Producer"
                ):
                    MODULE.verify_manifest(
                        self.repo, self.platform_paths["android"]
                    )
                for platform, producers in MODULE.PLATFORM_PRODUCER_PATHS.items():
                    if platform == "android":
                        continue
                    if helper in producers:
                        with self.assertRaisesRegex(
                            MODULE.DependencyFreezeError, "Producer"
                        ):
                            MODULE.verify_manifest(
                                self.repo, self.platform_paths[platform]
                            )
                    else:
                        self.assertTrue(
                            MODULE.verify_manifest(
                                self.repo, self.platform_paths[platform]
                            )["ok"]
                        )
                self._write(helper, original)

    def test_linux_neutral_stage_producers_invalidate_only_linux(self) -> None:
        for producer in (
            "tools/create_cross_machine_source_archive.ps1",
            "tools/extract_cross_machine_source_archive.sh",
        ):
            original = (self.repo / producer).read_text(encoding="utf-8")
            self._write(producer, original + "changed neutral staging producer\n")
            with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Producer"):
                MODULE.verify_manifest(self.repo, self.platform_paths["linux"])
            for platform in ("android", "windows", "macos", "ios"):
                self.assertTrue(
                    MODULE.verify_manifest(self.repo, self.platform_paths[platform])[
                        "ok"
                    ]
                )
            self._write(producer, original)

    def test_every_linux_artifact_validator_is_bound_to_linux(self) -> None:
        helpers = (
            "tools/release_obfuscation_contract.py",
            "tools/private_release_symbol_custody.py",
            "tools/validate_release_artifact_privacy.py",
        )
        linux_producers = set(MODULE.PLATFORM_PRODUCER_PATHS["linux"])
        for helper in helpers:
            with self.subTest(helper=helper):
                self.assertIn(helper, linux_producers)
                original = (self.repo / helper).read_text(encoding="utf-8")
                self._write(helper, original + "changed Linux validator\n")
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError, "Producer"
                ):
                    MODULE.verify_manifest(self.repo, self.platform_paths["linux"])
                self._write(helper, original)

    def test_linux_engine_producers_are_bound_and_isolated(self) -> None:
        helpers = MODULE.LINUX_ENGINE_PRODUCER_PATHS
        self.assertEqual(
            helpers,
            (
                "tools/verify_embedded_engine_runtime_versions.py",
                "tools/build_xray_engine.sh",
                "tools/build_winn_protocol_engine.sh",
                "tools/winn_release.py",
                "tools/build_linux_arm64_awg.sh",
            ),
        )
        linux_producers = set(MODULE.PLATFORM_PRODUCER_PATHS["linux"])
        producer = (
            SCRIPT.parents[1] / "tools/build_linux_release.sh"
        ).read_text(encoding="utf-8")
        for helper in helpers:
            with self.subTest(helper=helper):
                self.assertIn(helper, linux_producers)
                self.assertIn(pathlib.PurePosixPath(helper).name, producer)
                original = (self.repo / helper).read_text(encoding="utf-8")
                self._write(helper, original + "changed Linux engine producer\n")
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError, "Producer"
                ):
                    MODULE.verify_manifest(self.repo, self.platform_paths["linux"])
                for platform, producers in MODULE.PLATFORM_PRODUCER_PATHS.items():
                    if platform == "linux":
                        continue
                    if helper in producers:
                        with self.assertRaisesRegex(
                            MODULE.DependencyFreezeError, "Producer"
                        ):
                            MODULE.verify_manifest(
                                self.repo, self.platform_paths[platform]
                            )
                    else:
                        self.assertTrue(
                            MODULE.verify_manifest(
                                self.repo, self.platform_paths[platform]
                            )["ok"]
                        )
                self._write(helper, original)

    def test_transitive_byte_producers_are_platform_scoped(self) -> None:
        self._write("tools/strip_image_metadata.py", "changed normalizer\n")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Producer"):
            MODULE.verify_manifest(self.repo, self.platform_paths["windows"])
        for platform in ("android", "linux", "macos", "ios"):
            self.assertTrue(
                MODULE.verify_manifest(self.repo, self.platform_paths[platform])["ok"]
            )

        self._write("tools/strip_image_metadata.py", "producer: tools/strip_image_metadata.py\n")
        self._write("tools/build_apple_wg_go_bridge.sh", "changed engine builder\n")
        for platform in ("macos", "ios"):
            with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Producer"):
                MODULE.verify_manifest(self.repo, self.platform_paths[platform])
        for platform in ("android", "windows", "linux"):
            self.assertTrue(
                MODULE.verify_manifest(self.repo, self.platform_paths[platform])["ok"]
            )

    def test_apple_producer_change_invalidates_both_apple_artifacts(self) -> None:
        self._write("tools/apple_runtime_smoke.sh", "changed Apple producer\n")
        for platform in ("macos", "ios"):
            with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Producer"):
                MODULE.verify_manifest(self.repo, self.platform_paths[platform])
        for platform in ("android", "windows", "linux"):
            self.assertTrue(
                MODULE.verify_manifest(self.repo, self.platform_paths[platform])["ok"]
            )

    def test_platform_manifest_binds_shared_file_hash(self) -> None:
        record = json.loads(self.shared_path.read_text(encoding="utf-8"))
        record["created_utc"] = "2000-01-01T00:00:00Z"
        self._replace_read_only_manifest(self.shared_path, json.dumps(record))
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "file identity"):
            MODULE.verify_manifest(self.repo, self.platform_paths["windows"])

    def test_release_index_binds_all_manifest_hashes(self) -> None:
        index = self.output / "RELEASE_INPUT_INDEX.json"
        MODULE.create_release_index(self.repo, self.output, index)
        self.assertTrue(MODULE.verify_release_index(self.repo, index)["ok"])
        windows = self.platform_paths["windows"]
        record = json.loads(windows.read_text(encoding="utf-8"))
        record["created_utc"] = "2000-01-01T00:00:00Z"
        self._replace_read_only_manifest(windows, json.dumps(record))
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "identity changed"):
            MODULE.verify_release_index(self.repo, index)

    def test_platform_scoped_index_verification_ignores_other_native_trees(self) -> None:
        index = self.output / "RELEASE_INPUT_INDEX.json"
        MODULE.create_release_index(self.repo, self.output, index)
        self._write("macos/macos-input.txt", "macos unavailable on Windows\n")
        scoped = MODULE.verify_release_index(self.repo, index, "windows")
        self.assertTrue(scoped["ok"])
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Native"):
            MODULE.verify_release_index(self.repo, index)

    def test_platform_scoped_index_still_binds_every_manifest_file(self) -> None:
        index = self.output / "RELEASE_INPUT_INDEX.json"
        MODULE.create_release_index(self.repo, self.output, index)
        macos = self.platform_paths["macos"]
        self._replace_read_only_manifest(
            macos, macos.read_text(encoding="utf-8") + " "
        )
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "identity changed"):
            MODULE.verify_release_index(self.repo, index, "windows")

    def test_platform_scoped_index_retains_nonselected_manifest_through_return(self) -> None:
        index = self.output / "RELEASE_INPUT_INDEX.json"
        MODULE.create_release_index(self.repo, self.output, index)
        macos = self.platform_paths["macos"]
        displaced = macos.with_name("MACOS_INPUTS.displaced")
        replacement = macos.with_name("MACOS_INPUTS.replacement")
        replacement.write_bytes(macos.read_bytes())
        replacement.chmod(0o400)
        original = MODULE._verify_manifest_authenticated
        swapped = False

        def swap_nonselected(repo, path):
            nonlocal swapped
            if pathlib.Path(path).name == "WINDOWS_INPUTS.json" and not swapped:
                macos.rename(displaced)
                replacement.rename(macos)
                swapped = True
            return original(repo, path)

        try:
            with mock.patch.object(
                MODULE,
                "_verify_manifest_authenticated",
                side_effect=swap_nonselected,
            ):
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError,
                    "return custody|changed|identity|replaced",
                ):
                    MODULE.verify_release_index(self.repo, index, "windows")
        finally:
            if swapped:
                macos.unlink()
                displaced.rename(macos)
            elif replacement.exists():
                replacement.unlink()

    def test_release_index_timestamp_tamper_fails_anchor(self) -> None:
        index = self.output / "RELEASE_INPUT_INDEX.json"
        MODULE.create_release_index(self.repo, self.output, index)
        record = json.loads(index.read_text(encoding="utf-8"))
        record["created_utc"] = "2000-01-01T00:00:00Z"
        os.chmod(index, 0o600)
        index.write_text(json.dumps(record), encoding="utf-8")
        os.chmod(index, 0o400)
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "anchor changed"):
            MODULE.verify_release_index(self.repo, index)

    def test_anchor_first_publication_rolls_back_and_retries_cleanly(self) -> None:
        index = self.output / "RELEASE_INPUT_INDEX.json"
        original = MODULE._publish_stage_entry

        def fail_at_record(stage_fd, stage_name, parent_fd, final_name):
            if final_name == index.name:
                raise MODULE.DependencyFreezeError("simulated publication crash")
            return original(stage_fd, stage_name, parent_fd, final_name)

        with mock.patch.object(
            MODULE, "_publish_stage_entry", side_effect=fail_at_record
        ):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, "simulated publication crash"
            ):
                MODULE.create_release_index(self.repo, self.output, index)
        self.assertFalse(index.exists())
        self.assertFalse(index.with_name(index.name + ".sha256").exists())
        self.assertFalse(
            any(
                path.name.startswith(".freeze-staging-")
                for path in (self.repo / ".artifacts").iterdir()
            )
        )

        MODULE.create_release_index(self.repo, self.output, index)
        anchor = index.with_name(index.name + ".sha256")
        self.assertEqual(stat.S_IMODE(index.stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(anchor.stat().st_mode), 0o400)
        self.assertTrue(MODULE.verify_release_index(self.repo, index)["ok"])

    def test_hard_crash_after_record_publish_rolls_back_only_and_retries(self) -> None:
        if not hasattr(os, "fork"):
            self.skipTest("fork is unavailable on this host")
        output = self.repo / ".artifacts" / "HARD_CRASH_RECORD.json"
        record = {"contract": "hard-crash-record-test", "value": 1}
        original = MODULE._publish_stage_entry
        pid = os.fork()
        if pid == 0:
            def crash_after_record(stage_fd, stage_name, parent_fd, final_name):
                original(stage_fd, stage_name, parent_fd, final_name)
                if final_name == output.name:
                    os._exit(73)

            MODULE._publish_stage_entry = crash_after_record
            try:
                MODULE._write_anchored_record(
                    self.repo, output, record, "Hard crash record"
                )
            except BaseException:
                os._exit(99)
            os._exit(0)
        waited, status = os.waitpid(pid, 0)
        self.assertEqual(waited, pid)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 73)
        self.assertTrue(output.exists())
        self.assertFalse(output.with_name(output.name + ".sha256").exists())
        stages = [
            path
            for path in (self.repo / ".artifacts").iterdir()
            if path.name.startswith(".freeze-staging-")
        ]
        self.assertEqual(len(stages), 1)
        backdated = (
            dt.datetime.now(tz=dt.timezone.utc).timestamp()
            - MODULE.MAX_RECEIPT_AGE.total_seconds()
            - 60
        )
        os.utime(stages[0], (backdated, backdated))

        MODULE._write_anchored_record(
            self.repo, output, record, "Hard crash record"
        )
        loaded, _digest = MODULE._read_anchored_json(
            self.repo, output, "Hard crash record"
        )
        self.assertEqual(loaded, record)
        self.assertFalse(
            any(
                path.name.startswith(".freeze-staging-")
                for path in (self.repo / ".artifacts").iterdir()
            )
        )

    def test_hard_crash_after_anchor_link_preserves_committed_pair(self) -> None:
        if not hasattr(os, "fork"):
            self.skipTest("fork is unavailable on this host")
        output = self.repo / ".artifacts" / "HARD_CRASH_COMMIT.json"
        anchor_name = output.name + ".sha256"
        record = {"contract": "hard-crash-commit-test", "value": 1}
        original = MODULE._publish_stage_entry
        pid = os.fork()
        if pid == 0:
            def crash_after_anchor_link(stage_fd, stage_name, parent_fd, final_name):
                if final_name != anchor_name:
                    return original(stage_fd, stage_name, parent_fd, final_name)
                os.link(
                    stage_name,
                    final_name,
                    src_dir_fd=stage_fd,
                    dst_dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                MODULE._fsync_directory(parent_fd, "publication output directory")
                os._exit(74)

            MODULE._publish_stage_entry = crash_after_anchor_link
            try:
                MODULE._write_anchored_record(
                    self.repo, output, record, "Hard crash commit"
                )
            except BaseException:
                os._exit(99)
            os._exit(0)
        waited, status = os.waitpid(pid, 0)
        self.assertEqual(waited, pid)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 74)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "Refusing to overwrite immutable"
        ):
            MODULE._write_anchored_record(
                self.repo, output, record, "Hard crash commit"
            )
        loaded, _digest = MODULE._read_anchored_json(
            self.repo, output, "Hard crash commit"
        )
        self.assertEqual(loaded, record)
        self.assertFalse(
            any(
                path.name.startswith(".freeze-staging-")
                for path in (self.repo / ".artifacts").iterdir()
            )
        )

    def test_post_commit_failure_cannot_roll_back_anchored_pair(self) -> None:
        output = self.repo / ".artifacts" / "POST_COMMIT_FAILURE.json"
        record = {"contract": "post-commit-failure-test", "value": 1}
        original = MODULE._hold_repo_regular_file
        failed = False

        def fail_first_record_hold(repo, path, owners, *, label):
            nonlocal failed
            if pathlib.Path(path) == output and not failed:
                failed = True
                raise MODULE.DependencyFreezeError("simulated post-commit failure")
            return original(repo, path, owners, label=label)

        with mock.patch.object(
            MODULE, "_hold_repo_regular_file", side_effect=fail_first_record_hold
        ):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, "simulated post-commit failure"
            ):
                MODULE._write_anchored_record(
                    self.repo, output, record, "Post-commit failure"
                )
        self.assertTrue(output.exists())
        self.assertTrue(output.with_name(output.name + ".sha256").exists())
        loaded, _digest = MODULE._read_anchored_json(
            self.repo, output, "Post-commit failure"
        )
        self.assertEqual(loaded, record)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "Refusing to overwrite immutable"
        ):
            MODULE._write_anchored_record(
                self.repo, output, record, "Post-commit failure"
            )

    def test_unparseable_publication_journal_is_preserved_and_cannot_wedge_retry(self) -> None:
        output = self.repo / ".artifacts" / "PARTIAL_JOURNAL.json"
        relative = output.relative_to(self.repo)
        transaction_id = hashlib.sha256(
            relative.as_posix().encode("utf-8")
        ).hexdigest()
        nonce = "a" * 64
        stage = self.repo / ".artifacts" / (
            f".freeze-staging-{transaction_id}-{nonce}"
        )
        stage.mkdir(mode=0o700)
        for name, payload in ((".lock", b""), ("journal", b"{")):
            path = stage / name
            path.write_bytes(payload)
            path.chmod(0o400)

        record = {"contract": "partial-journal-test", "value": 1}
        MODULE._write_anchored_record(
            self.repo, output, record, "Partial journal"
        )
        loaded, _digest = MODULE._read_anchored_json(
            self.repo, output, "Partial journal"
        )
        self.assertEqual(loaded, record)
        self.assertTrue(stage.exists())
        self.assertEqual((stage / "journal").read_bytes(), b"{")

    def test_concurrent_publication_has_exactly_one_commit_point(self) -> None:
        output = self.repo / ".artifacts" / "CONCURRENT_RECORD.json"
        record = {"contract": "concurrent-publication-test", "value": 1}
        barrier = threading.Barrier(2)
        results: list[tuple[str, object]] = []

        def publish() -> None:
            barrier.wait()
            try:
                results.append(
                    ("ok", MODULE._write_anchored_record(
                        self.repo, output, record, "Concurrent record"
                    ))
                )
            except MODULE.DependencyFreezeError as exc:
                results.append(("error", str(exc)))

        threads = [threading.Thread(target=publish) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual([kind for kind, _ in results].count("ok"), 1)
        self.assertEqual([kind for kind, _ in results].count("error"), 1)
        loaded, digest = MODULE._read_anchored_json(
            self.repo, output, "Concurrent record"
        )
        self.assertEqual(loaded, record)
        self.assertEqual(digest, hashlib.sha256(MODULE._canonical_json(record)).hexdigest())
        self.assertFalse(
            any(
                path.name.startswith(".freeze-staging-")
                for path in (self.repo / ".artifacts").iterdir()
            )
        )

    def test_unbound_backdated_publication_state_cannot_wedge_or_be_deleted(self) -> None:
        artifacts = self.repo / ".artifacts"
        output = artifacts / "BOUNDED_PUBLICATION.json"
        record = {"contract": "bounded-publication-test", "value": 1}
        attacker_state = []
        for index in range(MODULE.PUBLICATION_STAGE_LIMIT):
            stage = artifacts / f".freeze-staging-count-{index:03d}"
            stage.mkdir(mode=0o700)
            attacker_state.append(stage)

        for index in range(MODULE.PUBLICATION_STAGE_LIMIT):
            stage = artifacts / f".FREEZE-STAGING-casefold-{index:03d}"
            stage.mkdir(mode=0o700)
            attacker_state.append(stage)

        stale = artifacts / ".freeze-staging-stale"
        stale.mkdir(mode=0o700)
        attacker_state.append(stale)
        stale_time = (
            dt.datetime.now(tz=dt.timezone.utc).timestamp()
            - MODULE.MAX_RECEIPT_AGE.total_seconds()
            - 60
        )
        os.utime(stale, (stale_time, stale_time))

        oversized = artifacts / ".freeze-staging-oversized"
        oversized.mkdir(mode=0o700)
        attacker_state.append(oversized)
        payload = oversized / "payload"
        with payload.open("wb") as handle:
            handle.truncate(MODULE.PUBLICATION_STAGE_BYTES_LIMIT + 1)
        os.chmod(payload, 0o400)
        MODULE._write_anchored_record(
            self.repo, output, record, "Bounded publication"
        )
        self.assertTrue(output.exists())
        self.assertTrue(output.with_name(output.name + ".sha256").exists())
        self.assertTrue(all(path.exists() for path in attacker_state))
        self.assertEqual(payload.stat().st_size, MODULE.PUBLICATION_STAGE_BYTES_LIMIT + 1)

    def test_matching_publication_stage_count_is_bounded_before_reads(self) -> None:
        artifacts = self.repo / ".artifacts"
        output = artifacts / "MATCHING_STAGE_COUNT.json"
        relative = output.relative_to(self.repo).as_posix()
        transaction_id = hashlib.sha256(relative.encode("utf-8")).hexdigest()
        prefix = f".freeze-staging-{transaction_id}-"
        stages = []
        for index in range(MODULE.PUBLICATION_STAGE_LIMIT + 1):
            stage = artifacts / f"{prefix}malformed-{index:03d}"
            stage.mkdir(mode=0o700)
            stages.append(stage)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "transaction-count bound"
        ):
            MODULE._write_anchored_record(
                self.repo,
                output,
                {"contract": "matching-stage-count", "value": 1},
                "Matching stage count",
            )
        self.assertTrue(all(stage.exists() for stage in stages))

    def test_matching_publication_stage_bytes_are_bounded_before_json_read(self) -> None:
        artifacts = self.repo / ".artifacts"
        output = artifacts / "MATCHING_STAGE_BYTES.json"
        relative = output.relative_to(self.repo).as_posix()
        transaction_id = hashlib.sha256(relative.encode("utf-8")).hexdigest()
        prefix = f".freeze-staging-{transaction_id}-"
        stage = artifacts / f"{prefix}{'0' * 64}"
        stage.mkdir(mode=0o700)
        for name, payload in ((".lock", b""), ("journal", b"{}")):
            path = stage / name
            path.write_bytes(payload)
            path.chmod(0o400)
        oversized = stage / "record"
        with oversized.open("wb") as handle:
            handle.truncate(MODULE.PUBLICATION_STAGE_BYTES_LIMIT + 1)
        oversized.chmod(0o400)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "aggregate byte bound"
        ):
            MODULE._write_anchored_record(
                self.repo,
                output,
                {"contract": "matching-stage-bytes", "value": 1},
                "Matching stage bytes",
            )
        self.assertEqual(
            oversized.stat().st_size, MODULE.PUBLICATION_STAGE_BYTES_LIMIT + 1
        )

    def test_one_malformed_matching_publication_stage_is_counted_and_rejected(self) -> None:
        artifacts = self.repo / ".artifacts"
        output = artifacts / "MALFORMED_MATCHING_STAGE.json"
        relative = output.relative_to(self.repo).as_posix()
        transaction_id = hashlib.sha256(relative.encode("utf-8")).hexdigest()
        stage = artifacts / f".freeze-staging-{transaction_id}-bad"
        stage.mkdir(mode=0o700)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "malformed prefix-shaped"
        ):
            MODULE._write_anchored_record(
                self.repo,
                output,
                {"contract": "malformed-matching-stage", "value": 1},
                "Malformed matching stage",
            )
        self.assertTrue(stage.exists())

    def test_unknown_build_attempt_state_is_counted_never_deleted_and_fails_closed(self) -> None:
        artifacts = self.repo / ".artifacts"
        owners = MODULE._allowed_owners(self.repo)
        attacker_state = []
        for index in range(MODULE.BUILD_ATTEMPT_LIMIT):
            attempt = artifacts / f".build-attempt-count-{index:03d}"
            attempt.mkdir(mode=0o700)
            attacker_state.append(attempt)

        for index in range(MODULE.BUILD_ATTEMPT_LIMIT):
            attempt = artifacts / f".BUILD-ATTEMPT-casefold-{index:03d}"
            attempt.mkdir(mode=0o700)
            attacker_state.append(attempt)

        stale = artifacts / ".build-attempt-stale"
        stale.mkdir(mode=0o700)
        attacker_state.append(stale)
        stale_time = (
            dt.datetime.now(tz=dt.timezone.utc).timestamp()
            - MODULE.MAX_RECEIPT_AGE.total_seconds()
            - 60
        )
        os.utime(stale, (stale_time, stale_time))

        oversized = artifacts / ".build-attempt-oversized"
        oversized.mkdir(mode=0o700)
        attacker_state.append(oversized)
        payload = oversized / "payload"
        with payload.open("wb") as handle:
            handle.truncate(MODULE.BUILD_ATTEMPT_BYTES_LIMIT + 1)
        os.chmod(payload, 0o400)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError,
            "Unknown build attempt namespace|aggregate bytes",
        ):
            MODULE._create_build_attempt_directory(
                self.repo, "3" * 64, owners
            )
        self.assertTrue(all(path.exists() for path in attacker_state))
        self.assertEqual(payload.stat().st_size, MODULE.BUILD_ATTEMPT_BYTES_LIMIT + 1)

    def test_retired_attempts_do_not_exhaust_future_build_slots(self) -> None:
        artifacts = self.repo / ".artifacts"
        owners = MODULE._allowed_owners(self.repo)
        for index in range(MODULE.BUILD_ATTEMPT_LIMIT + 2):
            held = MODULE._create_build_attempt_directory(
                self.repo, f"{index + 1:064x}", owners
            )
            lock_fd = MODULE._acquire_build_attempt_lock(held, owners)
            try:
                MODULE._retire_completed_build_attempt(
                    held, frozenset()
                )
            finally:
                MODULE._release_build_attempt_lock(lock_fd)
                MODULE._close_held_directory(held)
        self.assertFalse(
            any(path.name.startswith(".build-attempt-") for path in artifacts.iterdir())
        )

    def test_build_attempt_count_boundaries_64_65_66(self) -> None:
        artifacts = self.repo / ".artifacts"
        owners = MODULE._allowed_owners(self.repo)
        for existing_count in (63, 64, 65, 66):
            with self.subTest(existing_count=existing_count):
                created = []
                for index in range(existing_count):
                    path = artifacts / f".build-attempt-{index + 1:064x}"
                    path.mkdir(mode=0o700)
                    created.append(path)
                minted = None
                try:
                    if existing_count == 63:
                        minted = MODULE._create_build_attempt_directory(
                            self.repo, "f" * 64, owners
                        )
                        self.assertEqual(
                            sum(
                                path.name.startswith(".build-attempt-")
                                for path in artifacts.iterdir()
                            ),
                            64,
                        )
                    else:
                        with self.assertRaisesRegex(
                            MODULE.DependencyFreezeError,
                            "count exceeds the admission bound",
                        ):
                            MODULE._create_build_attempt_directory(
                                self.repo, "f" * 64, owners
                            )
                finally:
                    if minted is not None:
                        MODULE._remove_empty_build_attempt(minted)
                        MODULE._close_held_directory(minted)
                    for path in reversed(created):
                        path.rmdir()

    def test_build_attempt_aggregate_byte_cap_fails_without_deletion(self) -> None:
        artifacts = self.repo / ".artifacts"
        attempt = artifacts / (".build-attempt-" + "a" * 64)
        attempt.mkdir(mode=0o700)
        payload = attempt / "payload"
        with payload.open("wb") as handle:
            handle.truncate(MODULE.BUILD_ATTEMPT_BYTES_LIMIT + 1)
        payload.chmod(0o400)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError,
            "unknown or unsafe retained state|aggregate bytes",
        ):
            MODULE._create_build_attempt_directory(
                self.repo, "b" * 64, MODULE._allowed_owners(self.repo)
            )
        self.assertTrue(attempt.exists())
        self.assertEqual(payload.stat().st_size, MODULE.BUILD_ATTEMPT_BYTES_LIMIT + 1)

    def test_unknown_expired_attempt_fails_closed_without_deletion(self) -> None:
        attempt = self.repo / ".artifacts" / (".build-attempt-" + "c" * 64)
        attempt.mkdir(mode=0o700)
        old = (
            dt.datetime.now(tz=dt.timezone.utc).timestamp()
            - MODULE.BUILD_ATTEMPT_MAX_AGE_SECONDS
            - 60
        )
        os.utime(attempt, (old, old))
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError,
            "Unknown expired build attempt requires owner review",
        ):
            MODULE._create_build_attempt_directory(
                self.repo, "d" * 64, MODULE._allowed_owners(self.repo)
            )
        self.assertTrue(attempt.exists())

    def _backdate_attempt_for_gc(
        self, begin: pathlib.Path, record: dict[str, object]
    ) -> pathlib.Path:
        attempt = self.repo / str(record["build_attempt"]["directory"])
        old = dt.datetime.now(tz=dt.timezone.utc) - dt.timedelta(
            seconds=MODULE.BUILD_ATTEMPT_MAX_AGE_SECONDS + 60
        )
        old_text = old.isoformat().replace("+00:00", "Z")
        record["begun_utc"] = old_text
        self._rewrite_anchored(begin, record)
        journal_path = attempt / MODULE.BUILD_ATTEMPT_JOURNAL_NAME
        journal = json.loads(journal_path.read_text(encoding="ascii"))
        journal["created_utc"] = old_text
        journal["begin_receipt_sha256"] = hashlib.sha256(
            MODULE._canonical_json(record)
        ).hexdigest()
        os.chmod(journal_path, 0o600)
        journal_path.write_bytes(MODULE._canonical_json(journal))
        os.chmod(journal_path, 0o400)
        return attempt

    def test_authenticated_expired_interrupted_attempt_is_collected(self) -> None:
        index = self._create_index()
        begin = self.output / "INTERRUPTED_BEGIN.json"
        record = MODULE.begin_build_receipt(self.repo, index, "windows", begin)
        attempt = self._backdate_attempt_for_gc(begin, record)
        next_begin = self.output / "AFTER_GC_BEGIN.json"
        MODULE.begin_build_receipt(self.repo, index, "windows", next_begin)
        self.assertFalse(attempt.exists())
        self.assertTrue(begin.exists())
        self.assertTrue(begin.with_name(begin.name + ".sha256").exists())
        retired = list(
            (self.repo / ".artifacts").glob(".retired-build-attempt-*")
        )
        self.assertEqual(len(retired), 1)
        self.assertTrue((retired[0] / MODULE.BUILD_ATTEMPT_JOURNAL_NAME).exists())
        self.assertTrue(next_begin.exists())

    def test_retired_attempt_cap_blocks_gc_before_a_65th_retired_rename(self) -> None:
        index = self._create_index()
        begin = self.output / "RETIRED_CAP_BEGIN.json"
        record = MODULE.begin_build_receipt(self.repo, index, "windows", begin)
        attempt = self._backdate_attempt_for_gc(begin, record)
        artifacts = self.repo / ".artifacts"
        for number in range(MODULE.BUILD_ATTEMPT_RETIRED_LIMIT):
            retired = artifacts / (
                f".retired-build-attempt-{number + 1:064x}-{number + 101:064x}"
            )
            retired.mkdir(mode=0o700)
            marker = retired / "retained"
            marker.write_bytes(b"retained\n")
            marker.chmod(0o400)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError,
            "requires owner review before GC",
        ):
            MODULE.begin_build_receipt(
                self.repo,
                index,
                "windows",
                self.output / "RETIRED_CAP_NEXT.json",
            )
        self.assertTrue(attempt.exists())
        self.assertEqual(
            len(list(artifacts.glob(".retired-build-attempt-*"))),
            MODULE.BUILD_ATTEMPT_RETIRED_LIMIT,
        )

    def test_abandoned_attempt_replacement_race_is_not_deleted(self) -> None:
        index = self._create_index()
        begin = self.output / "GC_RACE_BEGIN.json"
        record = MODULE.begin_build_receipt(self.repo, index, "windows", begin)
        attempt = self._backdate_attempt_for_gc(begin, record)
        original_attempt = self.repo / ".artifacts" / "gc-attempt-original"
        replacement = self.repo / ".artifacts" / "gc-attempt-replacement"
        replacement.mkdir(mode=0o700)
        (replacement / "owner-state").write_bytes(b"replacement must survive\n")
        (replacement / "owner-state").chmod(0o400)
        original = MODULE._exclusive_rename_at
        swapped = False

        def replace_before_quarantine(parent_fd, source, destination, label):
            nonlocal swapped
            if source == attempt.name and not swapped:
                attempt.rename(original_attempt)
                replacement.rename(attempt)
                swapped = True
            return original(parent_fd, source, destination, label)

        with mock.patch.object(
            MODULE, "_exclusive_rename_at", side_effect=replace_before_quarantine
        ):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError,
                "Refusing to collect a replaced abandoned attempt directory",
            ):
                MODULE._create_build_attempt_directory(
                    self.repo, "e" * 64, MODULE._allowed_owners(self.repo)
                )
        retired = list(
            (self.repo / ".artifacts").glob(".retired-build-attempt-*")
        )
        self.assertEqual(len(retired), 1)
        self.assertEqual(
            (retired[0] / "owner-state").read_bytes(),
            b"replacement must survive\n",
        )
        self.assertTrue(original_attempt.exists())
        self.assertTrue(begin.exists())

    def test_abandoned_attempt_post_check_replacement_is_quarantined_not_deleted(self) -> None:
        index = self._create_index()
        begin = self.output / "GC_POST_CHECK_RACE_BEGIN.json"
        record = MODULE.begin_build_receipt(self.repo, index, "windows", begin)
        attempt = self._backdate_attempt_for_gc(begin, record)
        journal = attempt / MODULE.BUILD_ATTEMPT_JOURNAL_NAME
        original_journal = self.repo / ".artifacts" / "gc-post-check-original"
        replacement_payload = journal.read_bytes()
        replacement = self.repo / ".artifacts" / "gc-post-check-replacement"
        replacement.write_bytes(replacement_payload)
        replacement.chmod(0o400)
        original = MODULE._exclusive_rename_at
        swapped = False

        def replace_after_check(parent_fd, source, destination, label):
            nonlocal swapped
            if source == attempt.name and not swapped:
                journal.rename(original_journal)
                replacement.rename(journal)
                swapped = True
            return original(parent_fd, source, destination, label)

        with mock.patch.object(
            MODULE, "_exclusive_rename_at", side_effect=replace_after_check
        ):
            minted = MODULE._create_build_attempt_directory(
                self.repo, "9" * 64, MODULE._allowed_owners(self.repo)
            )
        MODULE._remove_empty_build_attempt(minted)
        MODULE._close_held_directory(minted)
        retired = list(
            (self.repo / ".artifacts").glob(".retired-build-attempt-*")
        )
        self.assertEqual(len(retired), 1)
        self.assertEqual(
            (retired[0] / MODULE.BUILD_ATTEMPT_JOURNAL_NAME).read_bytes(),
            replacement_payload,
        )
        self.assertTrue(original_journal.exists())
        self.assertTrue(begin.exists())

    def test_build_attempt_lock_rejects_concurrent_owner(self) -> None:
        if not hasattr(os, "fork"):
            self.skipTest("fork is unavailable on this host")
        owners = MODULE._allowed_owners(self.repo)
        held = MODULE._create_build_attempt_directory(
            self.repo, "4" * 64, owners
        )
        lock_fd = MODULE._acquire_build_attempt_lock(held, owners)
        self.assertFalse(
            (
                self.repo
                / ".artifacts"
                / (".build-attempt-" + "4" * 64)
                / ".lock"
            ).exists()
        )
        pid = os.fork()
        if pid == 0:
            os.close(lock_fd)
            child_held = None
            try:
                child_held = MODULE._hold_repo_directory(
                    self.repo,
                    self.repo / ".artifacts" / (".build-attempt-" + "4" * 64),
                    owners,
                    label="Concurrent build attempt",
                )
                MODULE._acquire_build_attempt_lock(child_held, owners)
            except MODULE.DependencyFreezeError as exc:
                os._exit(0 if "active in another process" in str(exc) else 3)
            finally:
                if child_held is not None:
                    MODULE._close_held_directory(child_held)
            os._exit(2)
        waited, status = os.waitpid(pid, 0)
        self.assertEqual(waited, pid)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 0)
        try:
            MODULE._retire_completed_build_attempt(held, frozenset())
        finally:
            MODULE._release_build_attempt_lock(lock_fd)
            MODULE._close_held_directory(held)

    def test_release_index_missing_manifest_fails_cleanly(self) -> None:
        index = self.output / "RELEASE_INPUT_INDEX.json"
        MODULE.create_release_index(self.repo, self.output, index)
        self.platform_paths["linux"].unlink()
        with self.assertRaises(MODULE.DependencyFreezeError):
            MODULE.verify_release_index(self.repo, index)

    def test_input_read_error_fails_with_controlled_message(self) -> None:
        with mock.patch.object(os, "open", side_effect=OSError("denied")):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, "Unable to read dependency input"
            ):
                MODULE.input_state(self.repo, ("lib",))

    def test_case_colliding_inputs_fail_closed(self) -> None:
        upper = self.repo / "lib" / "Foo.dart"
        lower = self.repo / "lib" / "foo.dart"
        upper.write_text("upper\n", encoding="utf-8")
        lower.write_text("lower\n", encoding="utf-8")
        if not upper.exists() or not lower.exists() or upper.read_text() == lower.read_text():
            self.skipTest("Case-distinct files are unavailable on this filesystem")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Case-colliding"):
            MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))

    def _create_index(self) -> pathlib.Path:
        index = self.output / "RELEASE_INPUT_INDEX.json"
        MODULE.create_release_index(self.repo, self.output, index)
        return index

    @staticmethod
    def _zip_payload(entries: dict[str, bytes]) -> bytes:
        output = MODULE.io.BytesIO()
        with MODULE.zipfile.ZipFile(
            output, "w", compression=MODULE.zipfile.ZIP_DEFLATED
        ) as archive:
            for name, payload in entries.items():
                archive.writestr(name, payload)
        return output.getvalue()

    @staticmethod
    def _valid_pe_payload() -> bytes:
        image = bytearray(0x1400)
        image[:2] = b"MZ"
        MODULE.struct.pack_into("<I", image, 0x3C, 0x80)
        image[0x80:0x84] = b"PE\x00\x00"
        MODULE.struct.pack_into(
            "<HHIIIHH", image, 0x84, 0x8664, 1, 0, 0, 0, 240, 0x0022
        )
        optional = 0x98
        MODULE.struct.pack_into("<H", image, optional, 0x20B)
        MODULE.struct.pack_into("<I", image, optional + 16, 0x1000)
        MODULE.struct.pack_into("<I", image, optional + 20, 0x1000)
        MODULE.struct.pack_into("<Q", image, optional + 24, 0x140000000)
        MODULE.struct.pack_into("<I", image, optional + 32, 0x1000)
        MODULE.struct.pack_into("<I", image, optional + 36, 0x200)
        MODULE.struct.pack_into("<I", image, optional + 56, 0x2000)
        MODULE.struct.pack_into("<I", image, optional + 60, 0x200)
        MODULE.struct.pack_into("<H", image, optional + 68, 2)
        MODULE.struct.pack_into("<I", image, optional + 108, 16)
        section = optional + 240
        image[section:section + 8] = b".text\x00\x00\x00"
        MODULE.struct.pack_into(
            "<IIII", image, section + 8, 0x1000, 0x1000, 0x1000, 0x200
        )
        MODULE.struct.pack_into("<I", image, section + 36, 0x60000020)
        image[0x200:0x204] = b"\x48\x31\xc0\xc3"
        image[0x240:0x255] = b"Inno Setup Setup Data"
        return bytes(image)

    @staticmethod
    def _valid_tar_payload() -> bytes:
        output = MODULE.io.BytesIO()
        with MODULE.tarfile.open(fileobj=output, mode="w:gz") as archive:
            for name, payload, mode in (
                ("winsvpn/bin/winsvpn", b"\x7fELF" + b"A" * 4092, 0o755),
                ("winsvpn/manifest.json", b'{"contract":"winsvpn-linux-package-v1"}\n', 0o644),
                ("winsvpn/README.txt", b"Win's VPN\n", 0o644),
            ):
                info = MODULE.tarfile.TarInfo(name)
                info.size = len(payload)
                info.mode = mode
                archive.addfile(info, MODULE.io.BytesIO(payload))
        return output.getvalue()

    @staticmethod
    def _valid_xar_payload() -> bytes:
        toc = (
            b"<xar><toc><file><name>Payload</name></file>"
            b"<signature><X509Certificate>YQ==</X509Certificate></signature>"
            b"</toc></xar>"
        )
        compressed = MODULE.zlib.compress(toc)
        header = MODULE.struct.pack(
            ">4sHHQQI", b"xar!", 28, 1, len(compressed), len(toc), 1
        )
        return header + compressed + b"signed-package-heap"

    def test_witness_documents_never_occupy_release_artifact_role(self) -> None:
        extension_witness = MODULE._canonical_json(
            {
                "contract": MODULE.BUILD_ATTEMPT_CONTRACT,
                "kind": "witness",
                "padding": "x" * 186,
            }
        )
        self.assertEqual(len(extension_witness), 279)
        apple_witness = b"WINS_RELEASE_DEPENDENCY_NATIVE_BUILD_WITNESS_V1\n"
        hostile = (
            ("extension", "chrome-zip", "chrome.zip", extension_witness),
            ("ios", "app-store-connect", "WinsVPN.ipa", apple_witness),
            ("macos", "app-store-connect", "WinsVPN.pkg", apple_witness),
        )
        for platform, target, name, payload in hostile:
            with self.subTest(platform=platform, target=target):
                with self.assertRaises(MODULE.DependencyFreezeError):
                    MODULE._validate_release_artifact_bytes(
                        platform, target, name, payload
                    )

    def test_windows_installer_loader_must_be_the_64_bit_inno_loader(self) -> None:
        # ISCC 7.1.0 embeds a 32-bit loader (machine 0x14c, PE32) unless SetupArchitecture=x64
        # is set, and has no ARM64 loader; both architectures therefore carry the x64 loader.
        valid = self._valid_pe_payload()
        pe_machine = 0x84
        for machine, label in ((0x14C, "x86 loader"), (0xAA64, "ARM64 loader")):
            hostile = bytearray(valid)
            MODULE.struct.pack_into("<H", hostile, pe_machine, machine)
            for target in ("windows-x64-inno-unsigned", "windows-arm64-inno-unsigned"):
                with self.subTest(loader=label, target=target):
                    with self.assertRaisesRegex(MODULE.DependencyFreezeError, "PE32\\+ structure"):
                        MODULE._validate_release_artifact_bytes(
                            "windows", target, "setup.exe", bytes(hostile)
                        )

    def test_windows_installer_accepts_virtual_only_sections_and_still_checks_raw_ones(self) -> None:
        # Real Inno loaders carry .bss and .tls: sections with SizeOfRawData 0 that exist
        # only in the mapped image. They failed the old "raw_size < 1" check.
        def with_second_section(raw_size: int, raw_offset: int) -> bytes:
            image = bytearray(self._valid_pe_payload())
            MODULE.struct.pack_into("<H", image, 0x86, 2)
            second = 0x98 + 240 + 40
            image[second:second + 8] = b".bss\x00\x00\x00\x00"
            MODULE.struct.pack_into(
                "<IIII", image, second + 8, 0x1000, 0x2000, raw_size, raw_offset
            )
            MODULE.struct.pack_into("<I", image, second + 36, 0xC0000080)
            return bytes(image)

        for target in ("windows-x64-inno-unsigned", "windows-arm64-inno-unsigned"):
            with self.subTest(target=target):
                MODULE._validate_release_artifact_bytes(
                    "windows", target, "setup.exe", with_second_section(0, 0)
                )
                with self.assertRaisesRegex(MODULE.DependencyFreezeError, "PE32\\+ structure"):
                    MODULE._validate_release_artifact_bytes(
                        "windows", target, "setup.exe", with_second_section(0x200, 0x1400)
                    )

    def test_windows_installer_entry_requires_file_backed_executable_code(self) -> None:
        # An executable section with no stored bytes, or an entry point in the zero-filled
        # tail of a section's virtual extent, is not a stored loader: a fabricated image
        # could otherwise carry no code at all and still pass with the "Inno Setup" marker.
        section = 0x98 + 240
        for label, raw_size, raw_offset, entry in (
            ("code section with no stored bytes", 0, 0, 0x1000),
            ("entry beyond the stored bytes", 0x200, 0x200, 0x1300),
        ):
            image = bytearray(self._valid_pe_payload())
            MODULE.struct.pack_into("<II", image, section + 16, raw_size, raw_offset)
            MODULE.struct.pack_into("<I", image, 0x98 + 16, entry)
            for target in ("windows-x64-inno-unsigned", "windows-arm64-inno-unsigned"):
                with self.subTest(label=label, target=target):
                    with self.assertRaisesRegex(MODULE.DependencyFreezeError, "PE32\\+ structure"):
                        MODULE._validate_release_artifact_bytes(
                            "windows", target, "setup.exe", bytes(image)
                        )

    def test_windows_installer_virtual_only_sections_cannot_claim_code_or_file_bytes(self) -> None:
        def with_second_section(flags: int, raw_offset: int) -> bytes:
            image = bytearray(self._valid_pe_payload())
            MODULE.struct.pack_into("<H", image, 0x86, 2)
            second = 0x98 + 240 + 40
            image[second:second + 8] = b".bss\x00\x00\x00\x00"
            MODULE.struct.pack_into("<IIII", image, second + 8, 0x1000, 0x2000, 0, raw_offset)
            MODULE.struct.pack_into("<I", image, second + 36, flags)
            return bytes(image)

        MODULE._validate_release_artifact_bytes(
            "windows", "windows-x64-inno-unsigned", "setup.exe", with_second_section(0xC0000000, 0)
        )
        for label, flags, raw_offset in (
            ("executable flag", 0xE0000080, 0),
            ("code flag", 0xC0000020, 0),
            ("file pointer", 0xC0000080, 0x200),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(MODULE.DependencyFreezeError, "PE32\\+ structure"):
                    MODULE._validate_release_artifact_bytes(
                        "windows", "windows-x64-inno-unsigned", "setup.exe",
                        with_second_section(flags, raw_offset),
                    )

    def test_format_validators_reject_header_only_fakes(self) -> None:
        hostile = (
            ("extension", "chrome-zip", "chrome.zip", b"PK\x03\x04" + b"\x00" * 64),
            ("android", "android-release-apk", "app.apk", b"PK\x03\x04" + b"\x00" * 64),
            ("windows", "windows-x64-inno-unsigned", "setup.exe", b"MZ" + b"\x00" * 4094),
            ("linux", "linux-x64", "winsvpn.tar.gz", b"\x1f\x8b" + b"\x00" * 510),
            ("ios", "app-store-connect", "WinsVPN.ipa", b"PK\x03\x04" + b"\x00" * 64),
            ("macos", "developer-id", "WinsVPN.pkg", b"xar!" + b"\x00" * 60),
        )
        for platform, target, name, payload in hostile:
            with self.subTest(platform=platform, target=target):
                with self.assertRaises(MODULE.DependencyFreezeError):
                    MODULE._validate_release_artifact_bytes(
                        platform, target, name, payload
                    )

    def test_format_dispatch_accepts_only_reviewed_complete_structural_fixtures(self) -> None:
        apk = self._zip_payload(
            {
                "AndroidManifest.xml": b"manifest",
                "classes.dex": b"dex\n035\x00" + b"A" * 64,
                "resources.arsc": b"resources",
                "META-INF/WINS.SF": b"signature-file",
                "META-INF/WINS.RSA": b"signer",
            }
        )
        aab = self._zip_payload(
            {
                "BundleConfig.pb": b"bundle-config",
                "base/manifest/AndroidManifest.xml": b"manifest",
                "base/dex/classes.dex": b"dex\n035\x00" + b"A" * 64,
                "META-INF/WINS.SF": b"signature-file",
                "META-INF/WINS.RSA": b"signer",
            }
        )
        msix = self._zip_payload(
            {
                "[Content_Types].xml": b"<Types/>",
                "AppxManifest.xml": b"<Package/>",
                "AppxBlockMap.xml": b"<BlockMap/>",
                "AppxSignature.p7x": b"signature",
            }
        )
        plist = MODULE.plistlib.dumps(
            {"CFBundleExecutable": "WinsVPN"}, fmt=MODULE.plistlib.FMT_BINARY
        )
        ipa = self._zip_payload(
            {
                "Payload/WinsVPN.app/Info.plist": plist,
                "Payload/WinsVPN.app/WinsVPN": b"\xcf\xfa\xed\xfe" + b"A" * 4092,
                "Payload/WinsVPN.app/_CodeSignature/CodeResources": b"signature",
                "Payload/WinsVPN.app/embedded.mobileprovision": b"profile",
            }
        )
        honest = (
            (
                "extension",
                "chrome-zip",
                "wins-vpn-companion-chrome.zip",
                self._extension_store_zip("chrome"),
            ),
            (
                "extension",
                "firefox-zip",
                "wins-vpn-companion-firefox.xpi",
                self._extension_store_zip("firefox"),
            ),
            ("windows", "windows-x64-inno-unsigned", "setup.exe", self._valid_pe_payload()),
            ("windows", "windows-arm64-inno-unsigned", "setup.exe", self._valid_pe_payload()),
        )
        for platform, target, name, payload in honest:
            with self.subTest(platform=platform, target=target):
                MODULE._validate_release_artifact_bytes(platform, target, name, payload)
        # Android packages now pass only as complete signed APK/AAB structures;
        # these fixtures lack a binary manifest or the JAR signature manifest.
        for target, name, payload, reason in (
            ("android-release-apk", "app.apk", apk, "binary AndroidManifest"),
            ("android-release-aab", "app.aab", aab, "JAR signature"),
        ):
            with self.subTest(android_incomplete=target):
                with self.assertRaisesRegex(MODULE.DependencyFreezeError, reason):
                    MODULE._validate_release_artifact_bytes(
                        "android", target, name, payload
                    )
        # Wear OS now passes only as a complete signed bundle whose base
        # manifest requires a watch; this fixture has no JAR signature manifest.
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "JAR signature"):
            MODULE._validate_release_artifact_bytes(
                "wear_os", "wear-os-release-aab", "wear.aab", aab
            )
        owner_blocked = (
            ("windows", "windows-x64-msix", "setup.msix", msix),
        )
        for platform, target, name, payload in owner_blocked:
            with self.subTest(owner_blocked=(platform, target)):
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError, "no reviewed"
                ):
                    MODULE._validate_release_artifact_bytes(
                        platform, target, name, payload
                    )
        # Linux now has the reviewed tarball validator (round R11a); the old
        # structural fixture is not the published tarball and stays refused.
        with self.subTest(linux_structural_fixture=True):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, "not the reviewed Linux release tarball"
            ):
                MODULE._validate_release_artifact_bytes(
                    "linux", "linux-x64", "winsvpn.tar.gz", self._valid_tar_payload()
                )
        # R11a: Apple formats now have real validators; these structural
        # placeholders (Astra CE-04) must still be refused by them.
        for platform, name, payload, reason in (
            ("ios", "Win's VPN.ipa", ipa, "provisioning profile"),
            ("macos", "Win's VPN.pkg", self._valid_xar_payload(), "TOC checksum is missing"),
        ):
            with self.subTest(placeholder=platform):
                with self.assertRaisesRegex(MODULE.DependencyFreezeError, reason):
                    MODULE._validate_release_artifact_bytes(
                        platform, "app-store-local", name, payload
                    )

    def _prepare_hostile_windows_producer(
        self, source: str, tag: str
    ) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path]:
        self._write(MODULE.PLATFORM_BUILD_PRODUCERS["windows"], source)
        revision = self.repo / ".artifacts" / f"freeze-producer-{tag}"
        shared = revision / "SHARED_INPUTS.json"
        MODULE.create_shared_manifest(self.repo, shared, f"producer-{tag}")
        for platform in MODULE.PLATFORM_ROOTS:
            MODULE.create_platform_manifest(
                self.repo,
                platform,
                shared,
                revision / f"{platform.upper()}_INPUTS.json",
            )
        index = revision / "RELEASE_INPUT_INDEX.json"
        MODULE.create_release_index(self.repo, revision, index)
        begin = revision / "WINDOWS_BUILD_BEGIN.json"
        MODULE.begin_build_receipt(self.repo, index, "windows", begin)
        artifact = self.repo / "build" / "windows-installer" / tag / "WinsVPN-Setup.exe"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        receipt = revision / "WINDOWS_BUILD_RECEIPT.json"
        return index, begin, artifact, receipt

    def _finish_prepared_windows_producer(
        self,
        index: pathlib.Path,
        begin: pathlib.Path,
        artifact: pathlib.Path,
        receipt: pathlib.Path,
    ) -> dict[str, object]:
        return MODULE.finish_build_receipt(
            self.repo,
            index,
            "windows",
            begin,
            artifact,
            MODULE.PLATFORM_BUILD_PRODUCERS["windows"],
            "flutter",
            "3.47.6",
            "5fc346839b5d0eef006ed8404392afb4dfae428d",
            "windows-x64-inno-unsigned",
            receipt,
            secret_inventory_path=self._default_scan_inventory,
        )

    def _new_valid_receipt(self) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        index = self._create_index()
        begin = self.output / "WINDOWS_BUILD_BEGIN.json"
        receipt = self.output / "WINDOWS_BUILD_RECEIPT.json"
        artifact = self.repo / "build" / "windows-installer" / "WinsVPN-Setup.exe"
        MODULE.begin_build_receipt(self.repo, index, "windows", begin)
        artifact.parent.mkdir(parents=True, exist_ok=True)
        MODULE.finish_build_receipt(
            self.repo,
            index,
            "windows",
            begin,
            artifact,
            MODULE.PLATFORM_BUILD_PRODUCERS["windows"],
            "flutter",
            "3.47.6",
            "5fc346839b5d0eef006ed8404392afb4dfae428d",
            "windows-x64-inno-unsigned",
            receipt,
            secret_inventory_path=self._default_scan_inventory,
        )
        return index, artifact, receipt

    def _create_native_only_revision_index(self, platform: str) -> pathlib.Path:
        revision = self.repo / ".artifacts" / f"freeze-{platform}-revision"
        revision.mkdir(parents=True)
        for source in [self.shared_path, *self.platform_paths.values()]:
            (revision / source.name).write_bytes(source.read_bytes())
        changed_manifest = revision / f"{platform.upper()}_INPUTS.json"
        changed_manifest.unlink()
        MODULE.create_platform_manifest(
            self.repo,
            platform,
            revision / "SHARED_INPUTS.json",
            changed_manifest,
        )
        index = revision / "RELEASE_INPUT_INDEX.json"
        MODULE.create_release_index(self.repo, revision, index)
        return index

    def _create_regenerated_equivalent_index(self) -> pathlib.Path:
        revision = self.repo / ".artifacts" / "freeze-regenerated-equivalent"
        shared = revision / "SHARED_INPUTS.json"
        MODULE.create_shared_manifest(self.repo, shared, "sr1")
        for platform in MODULE.PLATFORM_ROOTS:
            MODULE.create_platform_manifest(
                self.repo,
                platform,
                shared,
                revision / f"{platform.upper()}_INPUTS.json",
            )
        index = revision / "RELEASE_INPUT_INDEX.json"
        MODULE.create_release_index(self.repo, revision, index)
        return index

    _MACOS_ANDROID_PRODUCER = "tools/build_android_release_macos.sh"

    def _valid_aab_payload(self, marker: bytes = b"release") -> bytes:
        payload = self._zip_payload(
            {
                "base/manifest/AndroidManifest.xml": b"\x0a\x04" + marker,
                "base/dex/classes.dex": b"dex\n035\x00" + marker,
                "BundleConfig.pb": b"\x0a\x02\x08\x01",
                "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\r\n\r\n",
                "META-INF/UPLOAD.SF": b"Signature-Version: 1.0\r\n\r\n",
                "META-INF/UPLOAD.RSA": b"\x30\x82\x01\x00" + marker,
            }
        )
        # A trailing ZIP comment lets a test change one byte without making
        # the archive structurally invalid.
        comment = b"wins-release"
        return (
            payload[:-2]
            + len(comment).to_bytes(2, "little")
            + comment
        )

    def _attested_android_receipt(
        self,
        name: str = "AAB",
        artifact_relative: str = "build/app/outputs/bundle/release/app-release.aab",
        producer: str | None = None,
        index: pathlib.Path | None = None,
        write_artifact: bool = True,
    ) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path]:
        index = index or self._create_index()
        begin = self.output / f"ANDROID_{name}_BUILD_BEGIN.json"
        receipt = self.output / f"ANDROID_{name}_BUILD_RECEIPT.json"
        artifact = self.repo / artifact_relative
        with mock.patch.object(MODULE, "_native_process_host", return_value="darwin"):
            MODULE.begin_build_receipt(self.repo, index, "android", begin)
            artifact.parent.mkdir(parents=True, exist_ok=True)
            if write_artifact:
                artifact.write_bytes(self._valid_aab_payload())
            MODULE.finish_build_receipt(
                self.repo,
                index,
                "android",
                begin,
                artifact,
                producer or self._MACOS_ANDROID_PRODUCER,
                "flutter",
                "3.47.6",
                "5fc346839b5d0eef006ed8404392afb4dfae428d",
                "android-release-aab",
                receipt,
            )
        return index, begin, artifact, receipt

    _ATTESTED_DARWIN_PLATFORMS = ("android", "ios", "macos", "extension", "wear_os")
    _APPLE_PRODUCER = "tools/apple_runtime_smoke.sh"
    _EXTENSION_PRODUCER = "extension/build.py"
    _WEAR_PRODUCER = "wear_os/tools/prepare_release.sh"
    _WEAR_AAB = "wear_os/app/build/outputs/bundle/release/app-release.aab"
    _ESBUILD_TOOLCHAIN = (
        "esbuild",
        "0.28.2",
        "10b6243df618d374bb2d5c9cfbe7052e1405f6aa4e53a6164f11a91b9f2e1384",
    )
    _GRADLE_TOOLCHAIN = (
        "Gradle",
        "9.8.0",
        "46ac66d47f30f3dacfdf306e0b714a91a34fb94a22ba0a744b280933f47bc0cf",
    )

    @classmethod
    def _extension_store_zip(
        cls, browser: str, *, extra: dict[str, bytes] | None = None, **changes: object
    ) -> bytes:
        manifest: dict[str, object] = {
            "manifest_version": 3,
            "name": {
                "chrome": "Win's VPN Proxy for Chrome",
                "edge": "Win's VPN Proxy for Microsoft Edge",
                "firefox": "Win's VPN Proxy",
            }[browser],
            "version": "1.0.16",
            "background": {"type": "module"},
        }
        if browser == "firefox":
            manifest["background"]["scripts"] = ["src/background/background.js"]
            manifest["browser_specific_settings"] = {
                "gecko": {"id": "companion@winsvpn.org"}
            }
        else:
            manifest["background"]["service_worker"] = "src/background/background.js"
        manifest.update(changes)
        entries = {
            "manifest.json": json.dumps(manifest).encode("utf-8"),
            "src/background/background.js": b"self.addEventListener('install',()=>{});\n",
        }
        entries.update(extra or {})
        return cls._zip_payload(entries)

    @staticmethod
    def _proto_bytes(number: int, payload: bytes) -> bytes:
        def varint(value: int) -> bytes:
            out = bytearray()
            while True:
                low = value & 0x7F
                value >>= 7
                if value:
                    out.append(low | 0x80)
                else:
                    out.append(low)
                    return bytes(out)

        return varint(number << 3 | 2) + varint(len(payload)) + payload

    @classmethod
    def _proto_manifest(
        cls,
        features: tuple[tuple[str, str | None], ...],
        package: str = "org.winsvpn.app",
    ) -> bytes:
        """aapt2 protobuf XmlNode: <manifest package=...> with <uses-feature> children."""

        android = b"http://schemas.android.com/apk/res/android"

        def attribute(name: bytes, value: bytes, namespace: bytes = b"") -> bytes:
            body = cls._proto_bytes(2, name) + cls._proto_bytes(3, value)
            if namespace:
                body = cls._proto_bytes(1, namespace) + body
            return cls._proto_bytes(4, body)

        children = b""
        for feature, required in features:
            element = cls._proto_bytes(3, b"uses-feature") + attribute(
                b"name", feature.encode("ascii"), android
            )
            if required is not None:
                element += attribute(b"required", required.encode("ascii"), android)
            children += cls._proto_bytes(5, cls._proto_bytes(1, element))
        root = (
            cls._proto_bytes(3, b"manifest")
            + attribute(b"package", package.encode("ascii"))
            + children
        )
        return cls._proto_bytes(1, root)

    def _signed_bundle(self, manifest: bytes, *, signed: bool = True) -> bytes:
        entries = {
            "base/manifest/AndroidManifest.xml": manifest,
            "base/dex/classes.dex": b"dex\n035\x00release",
            "BundleConfig.pb": b"\x0a\x02\x08\x01",
            "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\r\n\r\n",
            "META-INF/UPLOAD.SF": b"Signature-Version: 1.0\r\n\r\n",
        }
        if signed:
            entries["META-INF/UPLOAD.RSA"] = b"\x30\x82\x01\x00signer"
        return self._zip_payload(entries)

    def _wear_bundle(self) -> bytes:
        return self._signed_bundle(
            self._proto_manifest((("android.hardware.type.watch", None),))
        )

    def _attested_darwin_receipt(
        self,
        platform: str,
        artifact_relative: str,
        payload: bytes,
        producer: str,
        toolchain: tuple[str, str, str],
        target: str,
        index: pathlib.Path | None = None,
        tag: str = "",
    ) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path]:
        index = index or self._create_index()
        begin = self.output / f"{platform.upper()}{tag}_BUILD_BEGIN.json"
        receipt = self.output / f"{platform.upper()}{tag}_BUILD_RECEIPT.json"
        artifact = self.repo / artifact_relative
        with mock.patch.object(MODULE, "_native_process_host", return_value="darwin"):
            MODULE.begin_build_receipt(self.repo, index, platform, begin)
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_bytes(payload)
            MODULE.finish_build_receipt(
                self.repo,
                index,
                platform,
                begin,
                artifact,
                producer,
                *toolchain,
                target,
                receipt,
            )
        return index, begin, artifact, receipt

    def test_darwin_extension_and_wear_producers_are_attested_and_named(self) -> None:
        self.assertEqual(
            MODULE._platform_build_producer("extension", "darwin"),
            self._EXTENSION_PRODUCER,
        )
        self.assertEqual(
            MODULE._platform_build_producer("wear_os", "darwin"), self._WEAR_PRODUCER
        )
        for platform in ("extension", "wear_os"):
            with self.subTest(platform=platform):
                self.assertEqual(
                    MODULE._platform_build_execution(platform, "darwin"),
                    MODULE.PRODUCER_EXECUTION_ATTESTED,
                )
                self.assertIn(
                    MODULE._platform_build_producer(platform, "darwin"),
                    MODULE.PLATFORM_PRODUCER_PATHS[platform],
                )
                for host in ("linux", "windows"):
                    self.assertEqual(
                        MODULE._platform_build_execution(platform, host),
                        MODULE.PRODUCER_EXECUTION_WITNESSED,
                    )
                    self.assertEqual(
                        MODULE._platform_build_producer(platform, host),
                        MODULE.PLATFORM_BUILD_PRODUCERS[platform],
                    )
        MODULE._assert_canonical_platforms()

    def test_darwin_extension_receipts_bind_each_store_zip(self) -> None:
        index = self._create_index()
        for browser in ("chrome", "edge", "firefox"):
            with self.subTest(browser=browser):
                payload = self._extension_store_zip(browser)
                _index, _begin, artifact, receipt = self._attested_darwin_receipt(
                    "extension",
                    f"build/extension/dist/wins-vpn-companion-{browser}.zip",
                    payload,
                    self._EXTENSION_PRODUCER,
                    self._ESBUILD_TOOLCHAIN,
                    f"{browser}-zip",
                    index=index,
                    tag=f"_{browser.upper()}",
                )
                record = json.loads(receipt.read_text(encoding="utf-8"))
                self.assertEqual(
                    record["producer"],
                    {
                        "path": self._EXTENSION_PRODUCER,
                        "sha256": self._file_sha256(self._EXTENSION_PRODUCER),
                        "host": "darwin",
                        "execution": "producer-attested",
                    },
                )
                self.assertEqual(record["toolchain"]["target"], f"{browser}-zip")
                self.assertEqual(
                    record["artifact"]["sha256"], hashlib.sha256(payload).hexdigest()
                )
                result = MODULE.verify_build_receipt(
                    self.repo, index, "extension", receipt, artifact
                )
                self.assertTrue(result["ok"])
                witnessed = json.loads(json.dumps(record))
                witnessed["producer"]["execution"] = "witnessed"
                self._rewrite_anchored(receipt, witnessed)
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError,
                    "producer execution is not accepted on darwin",
                ):
                    MODULE.verify_build_receipt(
                        self.repo, index, "extension", receipt, artifact
                    )

    def test_darwin_extension_receipt_refuses_the_wrong_store_zip(self) -> None:
        index = self._create_index()
        cases = (
            ("chrome-zip", "wins-vpn-companion-edge.zip", "chrome", "canonical"),
            ("firefox-zip", "wins-vpn-companion-firefox.zip", "chrome", "Firefox"),
            ("edge-zip", "wins-vpn-companion-edge.zip", "firefox", "Chromium"),
        )
        for number, (target, name, browser, reason) in enumerate(cases):
            with self.subTest(target=target, name=name, content=browser):
                with self.assertRaisesRegex(MODULE.DependencyFreezeError, reason):
                    self._attested_darwin_receipt(
                        "extension",
                        f"build/extension/dist/wrong-{number}/{name}",
                        self._extension_store_zip(browser),
                        self._EXTENSION_PRODUCER,
                        self._ESBUILD_TOOLCHAIN,
                        target,
                        index=index,
                        tag=f"_WRONG{number}",
                    )

    def test_extension_release_validator_binds_name_and_browser_family(self) -> None:
        validate = MODULE._validate_release_artifact_bytes
        for browser in ("chrome", "edge", "firefox"):
            with self.subTest(accepted=browser):
                validate(
                    "extension",
                    f"{browser}-zip",
                    f"wins-vpn-companion-{browser}.zip",
                    self._extension_store_zip(browser),
                )
        validate(
            "extension",
            "firefox-zip",
            "wins-vpn-companion-firefox.xpi",
            self._extension_store_zip("firefox"),
        )
        chrome = self._extension_store_zip("chrome")
        refused = (
            ("chrome-zip", "chrome.zip", chrome, "canonical"),
            ("chrome-zip", "wins-vpn-companion-chrome.xpi", chrome, "canonical"),
            ("chrome-zip", "wins-vpn-companion-chrome.crx", chrome, "ZIP or XPI"),
            ("edge-zip", "wins-vpn-companion-chrome.zip", chrome, "canonical"),
            ("edge-zip", "wins-vpn-companion-edge.zip",
             self._extension_store_zip("chrome"), "store name"),
            ("chrome-zip", "wins-vpn-companion-chrome.zip",
             self._extension_store_zip("edge"), "store name"),
            ("firefox-zip", "wins-vpn-companion-firefox.zip",
             self._extension_store_zip("firefox", name="Win's VPN Proxy for Chrome"),
             "store name"),
            ("chrome-zip", "wins-vpn-companion-chrome.zip",
             self._extension_store_zip("firefox"), "Chromium"),
            ("firefox-zip", "wins-vpn-companion-firefox.zip", chrome, "Firefox"),
            ("chrome-zip", "wins-vpn-companion-chrome.zip",
             self._extension_store_zip("chrome", manifest_version=2), "Manifest V3"),
            ("chrome-zip", "wins-vpn-companion-chrome.zip",
             self._extension_store_zip(
                 "chrome", background={"service_worker": "src/missing.js"}
             ), "packaged service worker"),
            ("chrome-zip", "wins-vpn-companion-chrome.zip",
             self._extension_store_zip(
                 "chrome", extra={"META-INF/mozilla.rsa": b"signature"}
             ), "already signed"),
            ("edge-zip", "wins-vpn-companion-edge.zip",
             self._extension_store_zip(
                 "edge", extra={"_metadata/verified_contents.json": b"{}"}
             ), "already signed"),
            ("firefox-zip", "wins-vpn-companion-firefox.zip",
             self._extension_store_zip(
                 "firefox",
                 browser_specific_settings={"gecko": {"id": "other@example.org"}},
             ), "Firefox"),
            ("chrome-zip", "wins-vpn-companion-chrome.zip",
             self._extension_store_zip(
                 "chrome",
                 browser_specific_settings={"gecko": {"id": "companion@winsvpn.org"}},
             ), "Chromium"),
        )
        for number, (target, name, payload, reason) in enumerate(refused):
            with self.subTest(refused=number, target=target, name=name):
                with self.assertRaisesRegex(MODULE.DependencyFreezeError, reason):
                    validate("extension", target, name, payload)

    def test_wear_os_validator_requires_a_signed_watch_bundle(self) -> None:
        validate = MODULE._validate_release_artifact_bytes
        validate("wear_os", "wear-os-release-aab", "app-release.aab", self._wear_bundle())
        phone = self._signed_bundle(self._proto_manifest(()))
        tv = self._signed_bundle(
            self._proto_manifest(
                (
                    ("android.software.leanback", "false"),
                    ("android.hardware.touchscreen", "false"),
                )
            )
        )
        optional_watch = self._signed_bundle(
            self._proto_manifest((("android.hardware.type.watch", "false"),))
        )
        for name, payload in (("phone", phone), ("tv", tv), ("optional", optional_watch)):
            with self.subTest(refused=name):
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError, "is not a Wear OS bundle"
                ):
                    validate("wear_os", "wear-os-release-aab", "app-release.aab", payload)
        other_package = self._signed_bundle(
            self._proto_manifest(
                (("android.hardware.type.watch", None),), package="org.example.other"
            )
        )
        refused = (
            ("wear-os-release-aab", "app-release.aab", other_package, "org.winsvpn.app manifest"),
            (
                "wear-os-release-aab",
                "app-release.aab",
                self._signed_bundle(
                    self._proto_manifest((("android.hardware.type.watch", None),)),
                    signed=False,
                ),
                "JAR signature",
            ),
            ("wear-os-release-aab", "app-release.apk", self._wear_bundle(), r"\.aab file"),
            ("android-release-aab", "app-release.aab", self._wear_bundle(), "Wear OS release AAB"),
            (
                "wear-os-release-aab",
                "app-release.aab",
                self._signed_bundle(self._proto_manifest(())[:-3]),
                "protobuf",
            ),
            (
                "wear-os-release-aab",
                "app-release.aab",
                self._signed_bundle(b"\x03\x00\x08\x00binary-xml-manifest"),
                "protobuf",
            ),
        )
        for number, (target, name, payload, reason) in enumerate(refused):
            with self.subTest(refused=number, target=target):
                with self.assertRaisesRegex(MODULE.DependencyFreezeError, reason):
                    validate("wear_os", target, name, payload)

    def test_android_validator_refuses_a_wear_bundle_as_phone_or_tv(self) -> None:
        validate = MODULE._validate_release_artifact_bytes
        phone = self._signed_bundle(self._proto_manifest(()))
        for target in ("android-release-aab", "android-tv-release-aab"):
            with self.subTest(target=target):
                validate("android", target, "app-release.aab", phone)
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError, "is a Wear OS bundle"
                ):
                    validate("android", target, "app-release.aab", self._wear_bundle())

    def test_watch_required_value_follows_aapt2_boolean_spellings(self) -> None:
        # R22 X1 F-04: aapt2's ParseBool trims whitespace and accepts true,
        # TRUE, True, false, FALSE and False; anything else is refused.
        validate = MODULE._validate_release_artifact_bytes
        watch = "android.hardware.type.watch"
        for spelling in ("FALSE", "False", " false "):
            optional = self._signed_bundle(self._proto_manifest(((watch, spelling),)))
            with self.subTest(optional=spelling):
                validate("android", "android-release-aab", "app-release.aab", optional)
                with self.assertRaisesRegex(MODULE.DependencyFreezeError, "is not a Wear OS bundle"):
                    validate("wear_os", "wear-os-release-aab", "app-release.aab", optional)
        for spelling in ("TRUE", "True", "true"):
            required = self._signed_bundle(self._proto_manifest(((watch, spelling),)))
            with self.subTest(required=spelling):
                validate("wear_os", "wear-os-release-aab", "app-release.aab", required)
                with self.assertRaisesRegex(MODULE.DependencyFreezeError, "is a Wear OS bundle"):
                    validate("android", "android-release-aab", "app-release.aab", required)
        for spelling in ("0", "@bool/watch_required", ""):
            unknown = self._signed_bundle(self._proto_manifest(((watch, spelling),)))
            for platform, target in (
                ("wear_os", "wear-os-release-aab"),
                ("android", "android-release-aab"),
            ):
                with self.subTest(unknown=spelling, platform=platform):
                    with self.assertRaisesRegex(MODULE.DependencyFreezeError, "not a literal boolean"):
                        validate(platform, target, "app-release.aab", unknown)

    def test_android_validator_refuses_an_unreadable_manifest_naming_the_watch(self) -> None:
        # R22 X1 F-04: a manifest that names the watch feature but does not
        # parse is no longer accepted as a phone or TV bundle; one that does
        # not name it keeps the phone path's old tolerance.
        validate = MODULE._validate_release_artifact_bytes
        unreadable_watch = self._signed_bundle(
            self._proto_manifest(
                (
                    ("android.hardware.type.watch", None),
                    ("android.software.leanback", "false"),
                )
            )[:-3]
        )
        unreadable_phone = self._signed_bundle(self._proto_manifest(())[:-3])
        for target in ("android-release-aab", "android-tv-release-aab"):
            with self.subTest(target=target):
                validate("android", target, "app-release.aab", unreadable_phone)
                with self.assertRaisesRegex(MODULE.DependencyFreezeError, "protobuf"):
                    validate("android", target, "app-release.aab", unreadable_watch)

    def test_darwin_wear_receipt_binds_the_prepare_release_aab(self) -> None:
        payload = self._wear_bundle()
        index, _begin, artifact, receipt = self._attested_darwin_receipt(
            "wear_os",
            self._WEAR_AAB,
            payload,
            self._WEAR_PRODUCER,
            self._GRADLE_TOOLCHAIN,
            "wear-os-release-aab",
        )
        record = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(
            record["producer"],
            {
                "path": self._WEAR_PRODUCER,
                "sha256": self._file_sha256(self._WEAR_PRODUCER),
                "host": "darwin",
                "execution": "producer-attested",
            },
        )
        self.assertEqual(record["artifact"]["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertTrue(
            MODULE.verify_build_receipt(self.repo, index, "wear_os", receipt, artifact)["ok"]
        )

    def test_darwin_wear_receipt_refuses_phone_bundle_and_substituted_producer(self) -> None:
        index = self._create_index()
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "is not a Wear OS bundle"):
            self._attested_darwin_receipt(
                "wear_os",
                "wear_os/app/build/outputs/bundle/release/phone/app-release.aab",
                self._signed_bundle(self._proto_manifest(())),
                self._WEAR_PRODUCER,
                self._GRADLE_TOOLCHAIN,
                "wear-os-release-aab",
                index=index,
                tag="_PHONE",
            )
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError,
            "wear_os build receipt on darwin must use wear_os/tools/prepare_release.sh",
        ):
            self._attested_darwin_receipt(
                "wear_os",
                "wear_os/app/build/outputs/bundle/release/legacy/app-release.aab",
                self._wear_bundle(),
                MODULE.PLATFORM_BUILD_PRODUCERS["wear_os"],
                self._GRADLE_TOOLCHAIN,
                "wear-os-release-aab",
                index=index,
                tag="_LEGACY",
            )

    def test_host_producer_map_is_explicit_and_attested_only_for_darwin_android_and_apple(self) -> None:
        self.assertEqual(
            MODULE._platform_build_producer("android", "darwin"),
            self._MACOS_ANDROID_PRODUCER,
        )
        for platform in ("ios", "macos"):
            self.assertEqual(
                MODULE._platform_build_producer(platform, "darwin"),
                self._APPLE_PRODUCER,
            )
        self.assertEqual(
            MODULE._platform_build_producer("android", "windows"),
            "tools/build_android_release.ps1",
        )
        for platform in MODULE.PLATFORM_BUILD_PRODUCERS:
            for host in ("darwin", "linux", "windows"):
                with self.subTest(platform=platform, host=host):
                    attested = (
                        host == "darwin" and platform in self._ATTESTED_DARWIN_PLATFORMS
                    )
                    expected = (
                        MODULE.PRODUCER_EXECUTION_ATTESTED
                        if attested
                        else MODULE.PRODUCER_EXECUTION_WITNESSED
                    )
                    self.assertEqual(
                        MODULE._platform_build_execution(platform, host), expected
                    )
                    if not attested:
                        self.assertEqual(
                            MODULE._platform_build_producer(platform, host),
                            MODULE.PLATFORM_BUILD_PRODUCERS[platform],
                        )
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Unsupported"):
            MODULE._platform_build_producer("android", "unsupported")

    def test_darwin_android_attested_receipt_binds_artifact_and_producer(self) -> None:
        index, _begin, artifact, receipt = self._attested_android_receipt()
        record = json.loads(receipt.read_text(encoding="utf-8"))
        producer_bytes = (self.repo / self._MACOS_ANDROID_PRODUCER).read_bytes()
        artifact_bytes = artifact.read_bytes()
        self.assertEqual(
            record["producer"],
            {
                "path": self._MACOS_ANDROID_PRODUCER,
                "sha256": hashlib.sha256(producer_bytes).hexdigest(),
                "host": "darwin",
                "execution": "producer-attested",
            },
        )
        self.assertEqual(
            record["artifact"]["sha256"], hashlib.sha256(artifact_bytes).hexdigest()
        )
        self.assertEqual(record["artifact"]["size_bytes"], len(artifact_bytes))
        claim = record["build_attempt"]["claim_record"]
        commit = record["build_attempt"]["commit_record"]
        self.assertEqual(claim["producer"], record["producer"])
        self.assertEqual(
            commit["artifact"]["sha256"], hashlib.sha256(artifact_bytes).hexdigest()
        )
        self.assertEqual(commit["artifact"]["inode"], artifact.stat().st_ino)
        self.assertEqual(artifact.stat().st_nlink, 1)
        self.assertFalse(
            any(
                path.name.startswith(".build-attempt-")
                for path in (self.repo / ".artifacts").iterdir()
            )
        )
        result = MODULE.verify_build_receipt(
            self.repo, index, "android", receipt, artifact
        )
        self.assertTrue(result["ok"])
        self.assertEqual(
            result["artifact_sha256"], hashlib.sha256(artifact_bytes).hexdigest()
        )

    @classmethod
    def _valid_ipa_payload(cls, marker: bytes = b"release", with_profile: bool = True) -> bytes:
        entries = {
            "Payload/Runner.app/Info.plist": MODULE.plistlib.dumps(
                {"CFBundleExecutable": "Runner", "CFBundleIdentifier": "org.winsvpn.app"}
            ),
            "Payload/Runner.app/_CodeSignature/CodeResources": b"<plist/>" + marker,
            "Payload/Runner.app/Runner": b"\xcf\xfa\xed\xfe" + bytes(8192),
            "Payload/Runner.app/Watch/Watch.app/Info.plist": MODULE.plistlib.dumps(
                {"CFBundleExecutable": "Watch"}
            ),
        }
        if with_profile:
            entries["Payload/Runner.app/embedded.mobileprovision"] = b"profile" + marker
        return cls._zip_payload(entries)

    @staticmethod
    def _xar_payload(signed: bool = True, namespaced: bool = True) -> bytes:
        signature = ""
        if signed:
            namespace = ' xmlns="http://www.w3.org/2000/09/xmldsig#"' if namespaced else ""
            signature = (
                '<signature style="RSA"><offset>20</offset><size>256</size>'
                f"<KeyInfo{namespace}><X509Data><X509Certificate>MIIB</X509Certificate>"
                "</X509Data></KeyInfo></signature>"
            )
        toc = (
            '<?xml version="1.0" encoding="UTF-8"?><xar><toc>'
            '<checksum style="sha1"><offset>0</offset><size>20</size></checksum>'
            + signature
            + '<file id="1"><name>Distribution</name></file></toc></xar>'
        ).encode("utf-8")
        compressed = MODULE.zlib.compress(toc)
        header = b"xar!" + MODULE.struct.pack(">HHQQI", 28, 1, len(compressed), len(toc), 1)
        return header + compressed + bytes(128)

    def _attested_apple_receipt(
        self,
        platform: str,
        artifact_relative: str,
        payload: bytes,
        producer: str | None = None,
        index: pathlib.Path | None = None,
        tag: str = "",
    ) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path]:
        index = index or self._create_index()
        begin = self.output / f"{platform.upper()}{tag}_BUILD_BEGIN.json"
        receipt = self.output / f"{platform.upper()}{tag}_BUILD_RECEIPT.json"
        artifact = self.repo / artifact_relative
        with mock.patch.object(MODULE, "_native_process_host", return_value="darwin"):
            MODULE.begin_build_receipt(self.repo, index, platform, begin)
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_bytes(payload)
            MODULE.finish_build_receipt(
                self.repo,
                index,
                platform,
                begin,
                artifact,
                producer or self._APPLE_PRODUCER,
                "Xcode",
                "27.0",
                "27A266a",
                "app-store-local",
                receipt,
            )
        return index, begin, artifact, receipt

    def test_darwin_ios_receipt_refuses_unsigned_structure_with_apostrophe_name(self) -> None:
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "lacks the release provisioning profile"):
            self._attested_apple_receipt(
                "ios", "build/apple/exports/ios-app-store-local/Win's VPN.ipa",
                self._valid_ipa_payload(),
            )

    def test_darwin_macos_receipt_refuses_fake_xar_signature(self) -> None:
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "XAR TOC checksum does not match"):
            self._attested_apple_receipt(
                "macos", "build/apple/exports/macos-app-store-local/Win's VPN.pkg",
                self._xar_payload(),
            )

    def test_apple_artifact_validators_refuse_incomplete_or_unsigned_packages(self) -> None:
        validate = MODULE._validate_release_artifact_bytes
        bad = {
            ("ios", "Win's VPN.ipa"): (
                self._valid_ipa_payload(),
                self._valid_ipa_payload(with_profile=False),
                self._zip_payload({"Payload/Runner.app/Info.plist": b"x"}),
                b"not a zip archive",
            ),
            ("ios", "Win's VPN.pkg"): (self._valid_ipa_payload(),),
            ("macos", "Win's VPN.pkg"): (
                self._xar_payload(),
                self._xar_payload(namespaced=False),
                self._xar_payload(signed=False),
                b"xar!" + bytes(10),
                self._valid_ipa_payload(),
            ),
            ("macos", "Win's VPN.ipa"): (self._xar_payload(),),
        }
        for (platform, name), payloads in bad.items():
            for index, payload in enumerate(payloads):
                with self.subTest(platform=platform, name=name, case=index):
                    with self.assertRaises(MODULE.DependencyFreezeError):
                        validate(platform, "app-store-local", name, payload)

    def test_finish_build_accepts_only_the_apostrophe_beyond_the_old_filename_set(self) -> None:
        index = self._create_index()
        names = ('bad"name.ipa', "bad;name.ipa", "bad$name.ipa", "bad`name.ipa", "bad&name.ipa")
        for number, name in enumerate(names):
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError, "Built artifact filename is unsafe"
                ):
                    self._attested_apple_receipt(
                        "ios",
                        f"build/apple/exports/unsafe/{name}",
                        self._valid_ipa_payload(),
                        index=index,
                        tag=f"_UNSAFE{number}",
                    )

    def test_the_apostrophe_is_reviewed_only_for_the_apple_platforms(self) -> None:
        for platform in MODULE.PLATFORM_BUILD_PRODUCERS:
            pattern = MODULE._artifact_name_pattern(platform)
            apple = platform in ("ios", "macos")
            with self.subTest(platform=platform):
                self.assertEqual(
                    bool(re.fullmatch(pattern, "Win's VPN.ipa")), apple
                )
                self.assertIsNotNone(re.fullmatch(pattern, "WinsVPN.ipa"))
                self.assertIsNotNone(re.fullmatch(pattern, "a" * 192))
                self.assertIsNone(re.fullmatch(pattern, "a" * 193))
                for unsafe in ('bad"name.ipa', "bad;name.ipa", "bad$name.ipa",
                               "bad`name.ipa", "bad&name.ipa", "-lead.ipa",
                               "'lead.ipa", " lead.ipa"):
                    self.assertIsNone(re.fullmatch(pattern, unsafe))

    def test_xcode_and_gradle_toolchain_labels_are_pinned(self) -> None:
        # R22 X1 X1-3: Apple and Wear receipts name Xcode and Gradle; their
        # labels must equal the reviewed pins like Flutter's do.
        check = MODULE._assert_toolchain_matches_reviewed_pin
        check(self.repo, "Xcode", "27.0", "27A266a")
        check(self.repo, *self._GRADLE_TOOLCHAIN[:2], self._GRADLE_TOOLCHAIN[2])
        check(self.repo, *self._ESBUILD_TOOLCHAIN)
        for name, version, revision in (
            ("Xcode", "26.0", "27A266a"),
            ("Xcode", "27.0", "26A100a"),
            ("Gradle", "9.7.0", self._GRADLE_TOOLCHAIN[2]),
            ("Gradle", "9.8.0", "0" * 64),
        ):
            with self.subTest(name=name, version=version, revision=revision):
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError, f"{name} build receipt does not match"
                ):
                    check(self.repo, name, version, revision)

    def test_apple_receipt_refuses_a_substituted_producer_on_darwin(self) -> None:
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError,
            "ios build receipt on darwin must use tools/apple_runtime_smoke.sh",
        ):
            self._attested_apple_receipt(
                "ios",
                "build/apple/exports/ios-app-store-local/Win's VPN.ipa",
                self._valid_ipa_payload(),
                producer="tools/build_apple_release_candidates.sh",
            )

    def test_attested_receipt_refuses_one_changed_artifact_byte(self) -> None:
        index, _begin, artifact, receipt = self._attested_android_receipt()
        original = artifact.stat()
        payload = bytearray(artifact.read_bytes())
        payload[-1] ^= 0x01
        MODULE._validate_release_artifact_bytes(
            "android", "android-release-aab", artifact.name, bytes(payload)
        )
        with open(artifact, "r+b") as handle:
            handle.write(bytes(payload))
        os.utime(artifact, ns=(original.st_atime_ns, original.st_mtime_ns))
        self.assertEqual(artifact.stat().st_ino, original.st_ino)
        self.assertEqual(artifact.stat().st_size, original.st_size)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "Exact built artifact does not match"
        ):
            MODULE.verify_build_receipt(self.repo, index, "android", receipt, artifact)

    def test_attested_receipt_claiming_another_host_is_refused(self) -> None:
        index, _begin, artifact, receipt = self._attested_android_receipt()
        original = json.loads(receipt.read_text(encoding="utf-8"))
        for host in ("windows", "linux"):
            with self.subTest(host=host):
                claimed = json.loads(json.dumps(original))
                claimed["producer"]["host"] = host
                claimed["producer"]["path"] = MODULE.PLATFORM_BUILD_PRODUCERS["android"]
                self._rewrite_anchored(receipt, claimed)
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError,
                    f"producer execution is not accepted on {host}",
                ):
                    MODULE.verify_build_receipt(
                        self.repo, index, "android", receipt, artifact
                    )
        witnessed = json.loads(json.dumps(original))
        witnessed["producer"]["execution"] = "witnessed"
        self._rewrite_anchored(receipt, witnessed)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "producer execution is not accepted on darwin"
        ):
            MODULE.verify_build_receipt(self.repo, index, "android", receipt, artifact)
        self._rewrite_anchored(receipt, original)
        self.assertTrue(
            MODULE.verify_build_receipt(self.repo, index, "android", receipt, artifact)["ok"]
        )

    def test_attested_receipt_refuses_a_changed_producer_digest(self) -> None:
        index, _begin, artifact, receipt = self._attested_android_receipt()
        record = json.loads(receipt.read_text(encoding="utf-8"))
        record["producer"]["sha256"] = hashlib.sha256(b"other producer").hexdigest()
        self._rewrite_anchored(receipt, record)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "Build receipt binding is invalid or changed"
        ):
            MODULE.verify_build_receipt(self.repo, index, "android", receipt, artifact)

    def test_attested_execution_is_refused_for_every_other_platform(self) -> None:
        for platform in MODULE.PLATFORM_BUILD_PRODUCERS:
            for host in ("darwin", "linux", "windows"):
                if host == "darwin" and platform in self._ATTESTED_DARWIN_PLATFORMS:
                    continue
                with self.subTest(platform=platform, host=host):
                    self.assertNotEqual(
                        MODULE._platform_build_execution(platform, host),
                        MODULE.PRODUCER_EXECUTION_ATTESTED,
                    )
                    with self.assertRaisesRegex(
                        MODULE.DependencyFreezeError, "cannot be producer-attested"
                    ):
                        MODULE._finish_producer_attested_build(
                            repo=self.repo,
                            index_path=self.repo,
                            platform=platform,
                            begin={},
                            begun=dt.datetime.now(tz=dt.timezone.utc),
                            begin_path=self.repo,
                            begin_sha="0" * 64,
                            attempt={},
                            held_attempt=None,
                            held_artifact_parent=None,
                            artifact_path=self.repo / "artifact",
                            output=self.repo / "receipt",
                            owners=frozenset(),
                            verified={},
                            source_freeze={},
                            toolchain_custody={},
                            custody=None,
                            held_producer=None,
                            producer_record={"host": host},
                            toolchain={},
                        )

    def test_windows_producer_is_refused_for_darwin_android(self) -> None:
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError,
            "android build receipt on darwin must use tools/build_android_release_macos.sh",
        ):
            self._attested_android_receipt(
                producer=MODULE.PLATFORM_BUILD_PRODUCERS["android"]
            )

    def test_attested_begin_nonce_is_single_use(self) -> None:
        index, begin, artifact, _receipt = self._attested_android_receipt()
        second = self.output / "ANDROID_AAB_SECOND_RECEIPT.json"
        self.assertFalse(
            any(
                path.name.startswith(".build-attempt-")
                for path in (self.repo / ".artifacts").iterdir()
            )
        )
        with mock.patch.object(MODULE, "_native_process_host", return_value="darwin"):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, "Build attempt does not exist"
            ):
                MODULE.finish_build_receipt(
                    self.repo,
                    index,
                    "android",
                    begin,
                    artifact,
                    self._MACOS_ANDROID_PRODUCER,
                    "flutter",
                    "3.47.6",
                    "5fc346839b5d0eef006ed8404392afb4dfae428d",
                    "android-release-aab",
                    second,
                )
        self.assertFalse(second.exists())

    def test_attested_artifact_older_than_its_begin_receipt_is_refused(self) -> None:
        index = self._create_index()
        artifact = self.repo / "build/app/outputs/bundle/release/app-release.aab"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_bytes(self._valid_aab_payload())
        stale = os.stat(artifact).st_mtime - 3600
        os.utime(artifact, (stale, stale))
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "outside its build attempt"
        ):
            self._attested_android_receipt(
                name="STALE", index=index, write_artifact=False
            )

    def test_attested_finish_requires_existing_single_link_regular_artifact(self) -> None:
        index = self._create_index()
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "must already exist"
        ):
            self._attested_android_receipt(
                name="MISSING", index=index, write_artifact=False
            )
        artifact = self.repo / "build/app/outputs/bundle/release/linked.aab"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        other = artifact.with_name("other.aab")
        with mock.patch.object(MODULE, "_native_process_host", return_value="darwin"):
            begin = self.output / "ANDROID_LINKED_BUILD_BEGIN.json"
            MODULE.begin_build_receipt(self.repo, index, "android", begin)
            other.write_bytes(self._valid_aab_payload())
            os.link(other, artifact)
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, "link count|single-link"
            ):
                MODULE.finish_build_receipt(
                    self.repo, index, "android", begin, artifact,
                    self._MACOS_ANDROID_PRODUCER, "flutter", "3.47.6",
                    "5fc346839b5d0eef006ed8404392afb4dfae428d",
                    "android-release-aab",
                    self.output / "ANDROID_LINKED_BUILD_RECEIPT.json",
                )
        self.assertTrue(other.exists())
        self.assertTrue(artifact.exists())

    def test_android_package_validator_requires_signed_apk_or_aab(self) -> None:
        aab = self._valid_aab_payload()
        MODULE._validate_release_artifact_bytes(
            "android", "android-release-aab", "app-release.aab", aab
        )
        unsigned = self._zip_payload(
            {
                "base/manifest/AndroidManifest.xml": b"\x0a\x04",
                "BundleConfig.pb": b"\x0a\x02",
                "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\r\n",
            }
        )
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "JAR signature"):
            MODULE._validate_release_artifact_bytes(
                "android", "android-release-aab", "app-release.aab", unsigned
            )
        no_signer_block = self._zip_payload(
            {
                "base/manifest/AndroidManifest.xml": b"\x0a\x04",
                "BundleConfig.pb": b"\x0a\x02",
                "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\r\n",
                "META-INF/UPLOAD.SF": b"Signature-Version: 1.0\r\n",
            }
        )
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "JAR signature"):
            MODULE._validate_release_artifact_bytes(
                "android", "android-release-aab", "app-release.aab", no_signer_block
            )
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, r"\.apk file"):
            MODULE._validate_release_artifact_bytes(
                "android", "android-release-apk", "app-release.aab", aab
            )
        apk_plain = self._zip_payload(
            {
                "AndroidManifest.xml": b"\x03\x00\x08\x00manifest",
                "classes.dex": b"dex\n035\x00",
            }
        )
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "signing block"):
            MODULE._validate_release_artifact_bytes(
                "android", "android-release-apk", "app-release.apk", apk_plain
            )
        eocd = apk_plain.rfind(b"PK\x05\x06")
        central = MODULE.struct.unpack_from("<L", apk_plain, eocd + 16)[0]
        block = b"\x00" * 8 + b"\x00" * 8 + b"APK Sig Block 42"
        signed = bytearray(apk_plain[:central] + block + apk_plain[central:])
        MODULE.struct.pack_into("<L", signed, eocd + len(block) + 16, central + len(block))
        MODULE._validate_release_artifact_bytes(
            "android", "android-release-apk", "app-release.apk", bytes(signed)
        )
        # This signed fixture's base manifest is not a protobuf Wear manifest.
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "protobuf"):
            MODULE._validate_release_artifact_bytes(
                "wear_os", "wear-os-release-aab", "wear.aab", aab
            )

    def test_two_phase_build_receipt_binds_exact_new_artifact(self) -> None:
        index, artifact, receipt = self._new_valid_receipt()
        result = MODULE.verify_build_receipt(
            self.repo, index, "windows", receipt, artifact,
            self._default_scan_inventory,
        )
        self.assertTrue(result["ok"])
        self.assertTrue(result["fixture_only"])
        self.assertFalse(result["production_pass_allowed"])
        self.assertEqual(result["artifact_sha256"], hashlib.sha256(artifact.read_bytes()).hexdigest())
        self.assertTrue(
            MODULE.verify_build_receipt(
                self.repo, index, "windows", receipt, artifact,
                self._default_scan_inventory,
            )["ok"]
        )
        self.assertFalse(
            any(
                path.name.startswith(".build-attempt-")
                for path in (self.repo / ".artifacts").iterdir()
            )
        )
        artifact.write_bytes(b"replaced artifact")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Exact built artifact"):
            MODULE.verify_build_receipt(self.repo, index, "windows", receipt, artifact, self._default_scan_inventory)

    def test_consumed_receipt_rejects_replaced_artifacts_directory(self) -> None:
        index, artifact, receipt = self._new_valid_receipt()
        original = self.repo / ".artifacts"
        saved = self.repo / "saved-artifacts"
        replacement = self.repo / "replacement-artifacts"
        shutil.copytree(original, replacement, symlinks=True)
        original.rename(saved)
        replacement.rename(original)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError,
            "parent directory identity changed",
        ):
            MODULE.verify_build_receipt(
                self.repo, index, "windows", receipt, artifact,
                self._default_scan_inventory,
            )

    def test_build_receipt_boundary_keeps_real_checks_without_token_scan(self) -> None:
        # Every darwin and linux producer lacks at least one adoption token, so
        # the static scan refused every receipt on those hosts. The boundary
        # keeps the production-authority and producer-file custody checks.
        producer_relative = MODULE._platform_build_producer(
            "android", MODULE._native_process_host()
        )
        producer = self.repo / producer_relative
        producer.parent.mkdir(parents=True, exist_ok=True)
        producer.write_bytes(b"# producer without native witness tokens\n")
        self.assertTrue(
            MODULE._native_build_witness_adoption_gaps("android", producer.read_bytes())
        )
        MODULE._FIXTURE_MODE = False
        MODULE._PRODUCTION_REQUIRED = False
        MODULE._AUTHORITATIVE_WORKER_READY = False
        try:
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError,
                re.escape(MODULE.FIXTURE_CANNOT_AUTHORIZE),
            ):
                MODULE._require_build_witness_boundary(self.repo, "android")
            MODULE._PRODUCTION_REQUIRED = True
            MODULE._AUTHORITATIVE_WORKER_READY = True
            MODULE._require_build_witness_boundary(self.repo, "android")
            producer.chmod(0o664)
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, "group/world-writable"
            ):
                MODULE._require_build_witness_boundary(self.repo, "android")
            producer.chmod(0o644)
            target = producer.with_name("real-producer" + producer.suffix)
            producer.rename(target)
            producer.symlink_to(target.name)
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, "Symlink|symlink|reparse"
            ):
                MODULE._require_build_witness_boundary(self.repo, "android")
        finally:
            MODULE._AUTHORITATIVE_WORKER_READY = False
            MODULE._PRODUCTION_REQUIRED = False
            MODULE._FIXTURE_MODE = True

    def test_six_real_producers_have_exact_native_fail_closed_interfaces(self) -> None:
        self.assertEqual(len(MODULE.NATIVE_BUILD_WITNESS_ADAPTERS), 6)
        self.assertEqual(
            set(MODULE.NATIVE_BUILD_WITNESS_ADAPTERS),
            set(MODULE.PLATFORM_BUILD_PRODUCERS.values()),
        )
        production_repo = SCRIPT.parents[1]
        adopted: set[str] = set()
        owner_blocked: set[str] = set()
        for producer, adapter in MODULE.NATIVE_BUILD_WITNESS_ADAPTERS.items():
            payload = (production_repo / producer).read_bytes()
            for platform in adapter["platforms"]:
                with self.subTest(platform=platform, producer=producer):
                    gaps = MODULE._native_build_witness_adoption_gaps(
                        platform, payload
                    )
                    if gaps:
                        owner_blocked.add(producer)
                        self.assertTrue(
                            {
                                "contract marker",
                                "private attempt marker",
                                "streaming output capability",
                            }
                            & set(gaps)
                        )
                    else:
                        adopted.add(producer)
            self.assertTrue(tuple(adapter["systems"]))
        self.assertGreaterEqual(len(adopted), 1)
        self.assertGreaterEqual(len(owner_blocked), 1)
        self.assertEqual(
            set(MODULE.NATIVE_BUILD_WITNESS_ADAPTERS),
            adopted | owner_blocked,
        )
        self.assertEqual(
            MODULE.NATIVE_BUILD_WITNESS_ADAPTERS[
                "installer/windows/build_installer.ps1"
            ]["runtime"],
            "powershell-file",
        )
        self.assertEqual(
            MODULE.NATIVE_BUILD_WITNESS_ADAPTERS[
                "tools/build_linux_release.sh"
            ]["host"],
            "linux",
        )

    def test_native_runtime_matrix_has_no_pseudo_host_bypass(self) -> None:
        producer = pathlib.Path("/private/tmp/.build-attempt-test/.producer")
        with mock.patch.dict(os.environ, {"SystemRoot": r"C:\Windows"}):
            executable, command = MODULE._native_witness_command(
                "windows", producer, "windows", fixture=False
            )
        self.assertEqual(executable.name.lower(), "powershell.exe")
        self.assertEqual(
            command[-3:], ["-File", str(producer), MODULE.BUILD_ATTEMPT_SWITCH]
        )
        executable, command = MODULE._native_witness_command(
            "linux", producer, "linux", fixture=False
        )
        self.assertEqual(executable, pathlib.Path("/bin/bash"))
        self.assertEqual(command[1], "-p")
        executable, command = MODULE._native_witness_command(
            "macos", producer, "darwin", fixture=False
        )
        self.assertEqual(executable, pathlib.Path("/bin/bash"))
        self.assertEqual(command[1], "-p")
        for platform in ("wear_os", "extension"):
            executable, command = MODULE._native_witness_command(
                platform, producer, "darwin", fixture=False
            )
            self.assertEqual(executable, pathlib.Path(sys.executable))
            self.assertEqual(command[1:3], ["-I", "-S"])
            pinned = pathlib.Path("/pinned/release/python/bin/python3.14")
            token = MODULE._ACTIVE_AUTHORITATIVE_WORKER_CUSTODY.set(
                mock.Mock(executable_path=pinned)
            )
            try:
                executable, command = MODULE._native_witness_command(
                    platform, producer, "darwin", fixture=False
                )
            finally:
                MODULE._ACTIVE_AUTHORITATIVE_WORKER_CUSTODY.reset(token)
            self.assertEqual(executable, pinned)
            self.assertEqual(command[0], str(pinned))
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, "refusing linux substitution"
            ):
                MODULE._native_witness_command(
                    platform, producer, "linux", fixture=False
                )

    def test_darwin_sandbox_constructs_exact_environment_inside_boundary(self) -> None:
        if sys.platform != "darwin":
            self.skipTest("macOS fixed-function sandbox boundary is required")
        command, launch_environment = MODULE._darwin_sandboxed_command(
            pathlib.Path("/usr/bin/sandbox-exec"),
            "(version 1)(allow default)",
            ["/bin/sh", "-c", "exit 0"],
            {"ZED": "last", "ALPHA": "first"},
        )
        self.assertEqual(
            command[:5],
            [
                "/usr/bin/sandbox-exec",
                "-p",
                "(version 1)(allow default)",
                "/usr/bin/env",
                "-i",
            ],
        )
        self.assertEqual(command[5:7], ["ALPHA=first", "ZED=last"])
        self.assertEqual(command[7:], ["/bin/sh", "-c", "exit 0"])
        self.assertNotIn("ALPHA", launch_environment)
        self.assertNotIn("ZED", launch_environment)
        self.assertEqual(launch_environment["PATH"], "/usr/bin:/bin")

    def test_producer_diagnostic_is_bounded_and_redacts_secret_shapes(self) -> None:
        secret = "A" * 80
        diagnostic = (
            f"failure token={secret} credential: {secret} safe-category\n"
            + ("x" * 9000)
        ).encode("ascii")
        summary = MODULE._bounded_producer_diagnostic(diagnostic)
        self.assertNotIn(secret, summary)
        self.assertIn("token=[REDACTED]", summary)
        self.assertIn("credential=[REDACTED]", summary)
        self.assertIn("safe-category", summary)
        self.assertIn("truncated", summary)
        self.assertLessEqual(
            len(summary), MODULE.BUILD_ATTEMPT_DIAGNOSTIC_TEXT_LIMIT + 120
        )

    def test_authenticated_releasepython_uses_production_sandbox_dispatch(self) -> None:
        if sys.platform != "darwin":
            self.skipTest("macOS production sandbox dispatch is required")
        if tuple(sys.version_info[:3]) != MODULE._RELEASE_PYTHON_VERSION:
            self.skipTest("pinned release Python 3.14.7 is required")
        if pathlib.Path(sys._base_executable) != _pinned_release_python_or_skip(self):
            self.skipTest("pinned release Python base executable is required")

        owners = MODULE._allowed_owners(self.repo)
        old_fixture = MODULE._FIXTURE_MODE
        old_production = MODULE._PRODUCTION_REQUIRED
        old_worker = MODULE._AUTHORITATIVE_WORKER_READY
        try:
            MODULE._FIXTURE_MODE = False
            MODULE._PRODUCTION_REQUIRED = True
            MODULE._AUTHORITATIVE_WORKER_READY = True
            for platform in ("wear_os", "extension"):
                producer_relative = MODULE.PLATFORM_BUILD_PRODUCERS[platform]
                canonical = SCRIPT.parents[1] / producer_relative
                gaps = MODULE._native_build_witness_adoption_gaps(
                    platform, canonical.read_bytes()
                )
                if gaps:
                    self.assertTrue(
                        {"private attempt marker", "streaming output capability"}
                        & set(gaps)
                    )
                    continue
                producer_path = self.repo / producer_relative
                producer_path.write_bytes(canonical.read_bytes())
                nonce = hashlib.sha256(
                    f"production-sandbox-dispatch:{platform}".encode("ascii")
                ).hexdigest()
                output_name = f"{platform}-production-dispatch.json"
                held_attempt = None
                held_source = None
                held_private = None
                output_descriptor = None
                with self.subTest(platform=platform):
                    try:
                        held_source = MODULE._hold_repo_regular_file(
                            self.repo,
                            producer_path,
                            owners,
                            label="Production dispatch producer",
                        )
                        held_attempt = MODULE._create_build_attempt_directory(
                            self.repo, nonce, owners
                        )
                        held_private = MODULE._install_private_attempt_producer(
                            self.repo, held_attempt, held_source, owners
                        )
                        output_descriptor, _identity = (
                            MODULE._create_attempt_output_descriptor(
                                held_attempt, output_name
                            )
                        )
                        returned = MODULE._run_witnessed_producer(
                            held_attempt,
                            held_private,
                            platform,
                            nonce,
                            output_name,
                            output_descriptor,
                            ".py",
                        )
                        self.assertEqual(returned, output_descriptor)
                        output_info = os.fstat(output_descriptor)
                        payload = os.pread(
                            output_descriptor, output_info.st_size, 0
                        )
                        witness = json.loads(payload)
                        self.assertEqual(
                            witness["contract"], MODULE.BUILD_ATTEMPT_CONTRACT
                        )
                        self.assertEqual(witness["nonce"], nonce)
                        self.assertEqual(witness["platform"], platform)
                        self.assertEqual(
                            witness["marker"],
                            MODULE.NATIVE_BUILD_WITNESS_MARKER.decode("ascii"),
                        )
                    finally:
                        if output_descriptor is not None:
                            os.close(output_descriptor)
                        if held_private is not None:
                            MODULE._close_held_regular_file(held_private)
                        if held_source is not None:
                            MODULE._close_held_regular_file(held_source)
                        if held_attempt is not None:
                            attempt_fd = held_attempt.components[-1].descriptor
                            for name in (".producer", output_name):
                                try:
                                    os.unlink(name, dir_fd=attempt_fd)
                                except FileNotFoundError:
                                    pass
                            MODULE._remove_empty_build_attempt(held_attempt)
                            MODULE._close_held_directory(held_attempt)
        finally:
            MODULE._AUTHORITATIVE_WORKER_READY = old_worker
            MODULE._PRODUCTION_REQUIRED = old_production
            MODULE._FIXTURE_MODE = old_fixture

    def test_mutable_worker_flags_cannot_fabricate_descendant_supervision(self) -> None:
        owners = MODULE._allowed_owners(self.repo)
        producer_path = self.repo / MODULE.PLATFORM_BUILD_PRODUCERS["windows"]
        nonce = hashlib.sha256(b"no-fabricated-supervision").hexdigest()
        output_name = "no-fabricated-supervision.exe"
        held_source = MODULE._hold_repo_regular_file(
            self.repo, producer_path, owners, label="Unsupervised producer"
        )
        held_attempt = MODULE._create_build_attempt_directory(
            self.repo, nonce, owners
        )
        held_private = MODULE._install_private_attempt_producer(
            self.repo, held_attempt, held_source, owners
        )
        output_descriptor, _identity = MODULE._create_attempt_output_descriptor(
            held_attempt, output_name
        )
        old_fixture = MODULE._FIXTURE_MODE
        old_production = MODULE._PRODUCTION_REQUIRED
        old_worker = MODULE._AUTHORITATIVE_WORKER_READY
        try:
            MODULE._FIXTURE_MODE = False
            MODULE._PRODUCTION_REQUIRED = True
            MODULE._AUTHORITATIVE_WORKER_READY = True
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError,
                "OWNER-BLOCKED.*whole-job descendant supervisor",
            ):
                MODULE._run_witnessed_producer(
                    held_attempt,
                    held_private,
                    "windows",
                    nonce,
                    output_name,
                    output_descriptor,
                    ".ps1",
                )
        finally:
            MODULE._AUTHORITATIVE_WORKER_READY = old_worker
            MODULE._PRODUCTION_REQUIRED = old_production
            MODULE._FIXTURE_MODE = old_fixture
            os.close(output_descriptor)
            MODULE._close_held_regular_file(held_private)
            MODULE._close_held_regular_file(held_source)
            attempt_fd = held_attempt.components[-1].descriptor
            for name in (".producer", output_name):
                try:
                    os.unlink(name, dir_fd=attempt_fd)
                except FileNotFoundError:
                    pass
            MODULE._remove_empty_build_attempt(held_attempt)
            MODULE._close_held_directory(held_attempt)

    def test_adopted_real_producer_interfaces_execute_or_owner_block(self) -> None:
        if tuple(sys.version_info[:3]) != MODULE._RELEASE_PYTHON_VERSION:
            self.skipTest("reviewed local Python 3.14.7 is required")
        production_repo = SCRIPT.parents[1]
        actual_host = MODULE._native_process_host()
        for platform in MODULE.PLATFORM_BUILD_PRODUCERS:
            producer = MODULE.PLATFORM_BUILD_PRODUCERS[platform]
            adapter = MODULE.NATIVE_BUILD_WITNESS_ADAPTERS[producer]
            with self.subTest(platform=platform, producer=producer):
                payload = (production_repo / producer).read_bytes()
                gaps = MODULE._native_build_witness_adoption_gaps(
                    platform, payload
                )
                if gaps:
                    self.assertTrue(
                        {
                            "contract marker",
                            "private attempt marker",
                            "streaming output capability",
                        }
                        & set(gaps)
                    )
                    continue
                with tempfile.TemporaryDirectory(
                    prefix="wins-real-native-witness-", dir="/private/tmp"
                ) as temporary:
                    attempt = pathlib.Path(temporary)
                    snapshot = attempt / ".producer"
                    snapshot.write_bytes(payload)
                    snapshot.chmod(0o500)
                    output = attempt / f"{platform}-witness.bin"
                    output.touch(mode=0o600)
                    nonce = hashlib.sha256(
                        f"real-interface:{platform}".encode("ascii")
                    ).hexdigest()
                    env = {
                        key: value
                        for key, value in os.environ.items()
                        if not key.startswith(
                            "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_"
                        )
                    }
                    env.update(
                        {
                            "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT": MODULE.BUILD_ATTEMPT_CONTRACT,
                            "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE": nonce,
                            "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT": output.name,
                            "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_PLATFORM": platform,
                        }
                    )
                    if actual_host not in tuple(adapter["systems"]):
                        powershell = shutil.which("pwsh")
                        if adapter["runtime"] == "powershell-file" and powershell:
                            command = [
                                powershell,
                                "-NoLogo",
                                "-NoProfile",
                                "-NonInteractive",
                                "-File",
                                str(snapshot),
                                MODULE.BUILD_ATTEMPT_SWITCH,
                            ]
                            completed = subprocess.run(
                                command,
                                cwd=attempt,
                                env=env,
                                check=False,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                            )
                            self.assertEqual(completed.returncode, 86)
                            self.assertEqual(output.read_bytes(), b"")
                        else:
                            self.assertNotIn(
                                actual_host, tuple(adapter["systems"])
                            )
                        continue
                    if adapter["runtime"] == "isolated-python":
                        executable, command = MODULE._native_witness_command(
                            platform, snapshot, actual_host, fixture=False
                        )
                        self.assertEqual(
                            executable, MODULE._reviewed_release_python_executable()
                        )
                        self.assertEqual(command[1:3], ["-I", "-S"])
                        self.assertEqual(command[-1], MODULE.BUILD_ATTEMPT_SWITCH)
                        self.assertEqual(output.read_bytes(), b"")
                        continue
                    else:
                        command = [
                            "/bin/bash",
                            "-p",
                            str(snapshot),
                            MODULE.BUILD_ATTEMPT_SWITCH,
                        ]
                    completed = subprocess.run(
                        command,
                        cwd=attempt,
                        env=env,
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    self.assertEqual(
                        completed.returncode,
                        0,
                        completed.stderr.decode("utf-8", errors="replace"),
                    )
                    self.assertIn(
                        MODULE.NATIVE_BUILD_WITNESS_MARKER,
                        output.read_bytes(),
                    )

    def test_imported_library_cannot_mint_or_accept_build_receipts(self) -> None:
        MODULE._FIXTURE_MODE = False
        calls = (
            lambda: MODULE.begin_build_receipt(
                self.repo,
                self.output / "MISSING_INDEX.json",
                "windows",
                self.output / "BLOCKED_BEGIN.json",
            ),
            lambda: MODULE.finish_build_receipt(
                self.repo,
                self.output / "MISSING_INDEX.json",
                "windows",
                self.output / "MISSING_BEGIN.json",
                self.repo / "build/windows-installer/MISSING.exe",
                MODULE.PLATFORM_BUILD_PRODUCERS["windows"],
                "flutter",
                "3.47.6",
                "5fc346839b5d0eef006ed8404392afb4dfae428d",
                "windows-x64-inno-unsigned",
                self.output / "BLOCKED_RECEIPT.json",
                secret_inventory_path=self._default_scan_inventory,
            ),
            lambda: MODULE.verify_build_receipt(
                self.repo,
                self.output / "MISSING_INDEX.json",
                "windows",
                self.output / "MISSING_RECEIPT.json",
                self.repo / "build/windows-installer/MISSING.exe",
            ),
        )
        try:
            for call in calls:
                with self.subTest(call=call):
                    with self.assertRaisesRegex(
                        MODULE.DependencyFreezeError,
                        re.escape(MODULE.FIXTURE_CANNOT_AUTHORIZE),
                    ):
                        call()
        finally:
            MODULE._FIXTURE_MODE = True

    def test_persistent_artifacts_directory_identity_survives_no_replacement(self) -> None:
        index = self._create_index()
        begin = self.output / "ARTIFACTS_REPLACEMENT_BEGIN.json"
        receipt = self.output / "ARTIFACTS_REPLACEMENT_RECEIPT.json"
        artifact = self.repo / "build/windows-installer/artifacts-replacement.exe"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        begin_record = MODULE.begin_build_receipt(
            self.repo, index, "windows", begin
        )
        original_artifacts = self.repo / ".artifacts"
        replacement = self.repo / "replacement-artifacts"
        saved = self.repo / "original-artifacts"
        shutil.copytree(original_artifacts, replacement, symlinks=True)
        original_artifacts.rename(saved)
        replacement.rename(original_artifacts)

        replacement_attempt = (
            self.repo / str(begin_record["build_attempt"]["directory"])
        )
        begin_record["build_attempt"]["directory_identity"] = (
            MODULE._build_attempt_directory_identity(replacement_attempt.stat())
        )
        payload = MODULE._canonical_json(begin_record)
        anchor = begin.with_name(begin.name + ".sha256")
        os.chmod(begin, 0o600)
        begin.write_bytes(payload)
        os.chmod(begin, 0o400)
        os.chmod(anchor, 0o600)
        anchor.write_text(
            f"{hashlib.sha256(payload).hexdigest()}  {begin.name}\n",
            encoding="ascii",
        )
        os.chmod(anchor, 0o400)

        with mock.patch.object(MODULE, "_run_witnessed_producer") as producer:
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError,
                "persistent \\.artifacts identity changed",
            ):
                self._finish_prepared_windows_producer(
                    index, begin, artifact, receipt
                )
        producer.assert_not_called()

    def test_begin_post_commit_failure_preserves_attempt_and_receipt_pair(self) -> None:
        index = self._create_index()
        begin = self.output / "POST_COMMIT_BEGIN.json"
        original = MODULE._hold_repo_regular_file
        failed = False

        def fail_after_commit(repo, path, owners, *, label):
            nonlocal failed
            if pathlib.Path(path) == begin and not failed:
                failed = True
                raise MODULE.DependencyFreezeError("simulated begin post-commit failure")
            return original(repo, path, owners, label=label)

        with mock.patch.object(
            MODULE, "_hold_repo_regular_file", side_effect=fail_after_commit
        ):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, "simulated begin post-commit failure"
            ):
                MODULE.begin_build_receipt(
                    self.repo, index, "windows", begin
                )
        self.assertTrue(begin.exists())
        self.assertTrue(begin.with_name(begin.name + ".sha256").exists())
        record = json.loads(begin.read_text(encoding="utf-8"))
        attempt = MODULE._parse_build_attempt(record["build_attempt"])
        self.assertTrue((self.repo / str(attempt["directory"])).is_dir())

    def test_finish_post_commit_failure_preserves_artifact_and_receipt_pair(self) -> None:
        index = self._create_index()
        begin = self.output / "POST_COMMIT_FINISH_BEGIN.json"
        receipt = self.output / "POST_COMMIT_FINISH.json"
        artifact = self.repo / "build/post-commit-finish/WinsVPN-Setup.exe"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        MODULE.begin_build_receipt(self.repo, index, "windows", begin)
        original = MODULE._hold_repo_regular_file
        failed = False

        def fail_after_commit(repo, path, owners, *, label):
            nonlocal failed
            if pathlib.Path(path) == receipt and not failed:
                failed = True
                raise MODULE.DependencyFreezeError("simulated finish post-commit failure")
            return original(repo, path, owners, label=label)

        with mock.patch.object(
            MODULE, "_hold_repo_regular_file", side_effect=fail_after_commit
        ):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, "simulated finish post-commit failure"
            ):
                self._finish_prepared_windows_producer(
                    index, begin, artifact, receipt
                )
        self.assertTrue(artifact.exists())
        self.assertEqual(artifact.stat().st_nlink, 2)
        self.assertTrue(receipt.exists())
        self.assertTrue(receipt.with_name(receipt.name + ".sha256").exists())
        with mock.patch.object(MODULE, "_run_witnessed_producer") as producer:
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError,
                "requires owner review and cannot be reused",
            ):
                self._finish_prepared_windows_producer(
                    index, begin, artifact, receipt
                )
        producer.assert_not_called()

    def test_partial_build_attempt_journals_are_rollback_only(self) -> None:
        index = self._create_index()
        for index_number, partial_name in enumerate((".claim", ".receipt"), start=1):
            with self.subTest(partial_name=partial_name):
                begin = self.output / f"PARTIAL_{index_number}_BEGIN.json"
                receipt = self.output / f"PARTIAL_{index_number}_RECEIPT.json"
                artifact = self.repo / (
                    f"build/partial-{index_number}/WinsVPN-Setup.exe"
                )
                artifact.parent.mkdir(parents=True, exist_ok=True)
                record = MODULE.begin_build_receipt(
                    self.repo, index, "windows", begin
                )
                attempt = MODULE._parse_build_attempt(record["build_attempt"])
                attempt_path = self.repo / str(attempt["directory"])
                partial = attempt_path / partial_name
                partial.write_bytes(b"{")
                partial.chmod(0o400)

                result = self._finish_prepared_windows_producer(
                    index, begin, artifact, receipt
                )
                self.assertEqual(result["contract"], MODULE.BUILD_RECEIPT_CONTRACT)
                self.assertFalse(attempt_path.exists())
                self.assertTrue(
                    MODULE.verify_build_receipt(
                        self.repo, index, "windows", receipt, artifact,
                        self._default_scan_inventory,
                    )["ok"]
                )

    def test_same_uid_forged_postmortem_receipt_never_runs_producer(self) -> None:
        index = self._create_index()
        begin = self.output / "FORGED_POSTMORTEM_BEGIN.json"
        receipt = self.output / "FORGED_POSTMORTEM_RECEIPT.json"
        artifact = self.repo / "build/windows-installer/forged-postmortem.exe"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        record = MODULE.begin_build_receipt(self.repo, index, "windows", begin)
        attempt = MODULE._parse_build_attempt(record["build_attempt"])
        attempt_path = self.repo / str(attempt["directory"])
        for name in (".claim", ".receipt"):
            path = attempt_path / name
            path.write_text("{}\n", encoding="ascii")
            path.chmod(0o400)
        forged_payload = b"{}\n"
        receipt.write_bytes(forged_payload)
        receipt.chmod(0o400)
        receipt_anchor = receipt.with_name(receipt.name + ".sha256")
        receipt_anchor.write_text(
            f"{hashlib.sha256(forged_payload).hexdigest()}  {receipt.name}\n",
            encoding="ascii",
        )
        receipt_anchor.chmod(0o400)

        with mock.patch.object(MODULE, "_run_witnessed_producer") as producer:
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError,
                "requires owner review and cannot be reused",
            ):
                self._finish_prepared_windows_producer(
                    index, begin, artifact, receipt
                )
        producer.assert_not_called()

    def test_hard_crash_before_receipt_rolls_back_artifact_and_reruns_producer(self) -> None:
        if not hasattr(os, "fork"):
            self.skipTest("fork is unavailable on this host")
        index = self._create_index()
        begin = self.output / "CRASH_BEFORE_RECEIPT_BEGIN.json"
        receipt = self.output / "CRASH_BEFORE_RECEIPT.json"
        artifact = self.repo / "build/crash-before-receipt/WinsVPN-Setup.exe"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        MODULE.begin_build_receipt(self.repo, index, "windows", begin)
        original = MODULE._write_anchored_record
        pid = os.fork()
        if pid == 0:
            def crash_before_receipt(repo, output, record, label):
                if label == "Build receipt":
                    os._exit(75)
                return original(repo, output, record, label)

            MODULE._write_anchored_record = crash_before_receipt
            try:
                self._finish_prepared_windows_producer(
                    index, begin, artifact, receipt
                )
            except BaseException:
                os._exit(99)
            os._exit(0)
        waited, status = os.waitpid(pid, 0)
        self.assertEqual(waited, pid)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 75)
        self.assertTrue(artifact.exists())
        self.assertFalse(receipt.exists())

        record = self._finish_prepared_windows_producer(
            index, begin, artifact, receipt
        )
        self.assertEqual(record["contract"], MODULE.BUILD_RECEIPT_CONTRACT)
        self.assertTrue(
            MODULE.verify_build_receipt(
                self.repo, index, "windows", receipt, artifact,
                self._default_scan_inventory,
            )["ok"]
        )
        self.assertEqual(artifact.stat().st_nlink, 1)

    def test_hard_crash_after_receipt_commit_verifies_without_producer_rerun(self) -> None:
        if not hasattr(os, "fork"):
            self.skipTest("fork is unavailable on this host")
        index = self._create_index()
        begin = self.output / "CRASH_AFTER_RECEIPT_BEGIN.json"
        receipt = self.output / "CRASH_AFTER_RECEIPT.json"
        artifact = self.repo / "build/crash-after-receipt/WinsVPN-Setup.exe"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        MODULE.begin_build_receipt(self.repo, index, "windows", begin)
        original = MODULE._write_anchored_record
        pid = os.fork()
        if pid == 0:
            def crash_after_receipt(repo, output, record, label):
                result = original(repo, output, record, label)
                if label == "Build receipt":
                    os._exit(76)
                return result

            MODULE._write_anchored_record = crash_after_receipt
            try:
                self._finish_prepared_windows_producer(
                    index, begin, artifact, receipt
                )
            except BaseException:
                os._exit(99)
            os._exit(0)
        waited, status = os.waitpid(pid, 0)
        self.assertEqual(waited, pid)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 76)
        self.assertTrue(artifact.exists())
        self.assertTrue(receipt.exists())
        self.assertEqual(artifact.stat().st_nlink, 2)

        with mock.patch.object(MODULE, "_run_witnessed_producer") as producer:
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError,
                "requires owner review and cannot be reused",
            ):
                self._finish_prepared_windows_producer(
                    index, begin, artifact, receipt
                )
        producer.assert_not_called()
        self.assertTrue(artifact.exists())
        self.assertTrue(receipt.exists())
        self.assertEqual(artifact.stat().st_nlink, 2)
        result = MODULE.verify_build_receipt(
            self.repo, index, "windows", receipt, artifact,
            self._default_scan_inventory,
        )
        self.assertTrue(result["ok"])
        self.assertTrue(result["fixture_only"])
        self.assertFalse(result["production_pass_allowed"])
        self.assertEqual(artifact.stat().st_nlink, 1)
        record = json.loads(receipt.read_text(encoding="utf-8"))
        attempt = MODULE._parse_build_attempt(
            {
                key: value
                for key, value in record["build_attempt"].items()
                if key not in {
                    "claim_sha256",
                    "commit_journal_sha256",
                    "claim_record",
                    "commit_record",
                }
            }
        )
        self.assertFalse((self.repo / str(attempt["directory"])).exists())

    def test_build_begin_mints_private_journaled_unique_attempts(self) -> None:
        index = self._create_index()
        first = self.output / "FIRST_BUILD_BEGIN.json"
        second = self.output / "SECOND_BUILD_BEGIN.json"
        first_record = MODULE.begin_build_receipt(self.repo, index, "windows", first)
        second_record = MODULE.begin_build_receipt(self.repo, index, "windows", second)
        first_attempt = MODULE._parse_build_attempt(first_record["build_attempt"])
        second_attempt = MODULE._parse_build_attempt(second_record["build_attempt"])
        self.assertNotEqual(first_attempt["nonce"], second_attempt["nonce"])
        for record, begin in ((first_attempt, first), (second_attempt, second)):
            attempt = self.repo / str(record["directory"])
            self.assertEqual(stat.S_IMODE(attempt.stat().st_mode), 0o700)
            self.assertEqual(
                [path.name for path in attempt.iterdir()],
                [MODULE.BUILD_ATTEMPT_JOURNAL_NAME],
            )
            journal = MODULE._parse_build_attempt_admission_journal(
                json.loads(
                    (attempt / MODULE.BUILD_ATTEMPT_JOURNAL_NAME).read_text(
                        encoding="ascii"
                    )
                )
            )
            self.assertEqual(journal["nonce"], record["nonce"])
            self.assertEqual(
                journal["begin_receipt"], begin.relative_to(self.repo).as_posix()
            )
            self.assertEqual(
                record["begin_receipt"], begin.relative_to(self.repo).as_posix()
            )

    def test_unintegrated_producer_is_refused_before_execution(self) -> None:
        index, begin, artifact, receipt = self._prepare_hostile_windows_producer(
            "raise SystemExit('must not execute')\n", "unintegrated"
        )
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "producer is not integrated"
        ):
            self._finish_prepared_windows_producer(index, begin, artifact, receipt)
        self.assertFalse(artifact.exists())

    def test_witnessed_producer_zero_and_multiple_outputs_are_rejected(self) -> None:
        marker = "# WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_V2\n"
        zero = marker + "raise SystemExit(0)\n"
        index, begin, artifact, receipt = self._prepare_hostile_windows_producer(
            zero, "zero-output"
        )
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "did not populate its retained output inode"
        ):
            self._finish_prepared_windows_producer(index, begin, artifact, receipt)
        self.assertFalse(artifact.exists())

        multiple = marker + """import os
os.write(int(os.environ[\"WINS_RELEASE_DEPENDENCY_OUTPUT_FD\"]), b\"one\")
with open(\"extra.bin\", \"wb\") as extra_handle:
    extra_handle.write(b\"two\")
"""
        index, begin, artifact, receipt = self._prepare_hostile_windows_producer(
            multiple, "multiple-output"
        )
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError,
            "exactly one declared output|failed with exit status",
        ):
            self._finish_prepared_windows_producer(index, begin, artifact, receipt)
        self.assertFalse(artifact.exists())

    def test_witnessed_producer_cannot_write_outside_private_attempt(self) -> None:
        source = """# WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_V2
import os
import pathlib
repo = pathlib.Path.cwd().parents[1]
(repo / \"hostile-outside.bin\").write_bytes(b\"outside\")
"""
        index, begin, artifact, receipt = self._prepare_hostile_windows_producer(
            source, "outside-output"
        )
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "failed with exit status"
        ):
            self._finish_prepared_windows_producer(index, begin, artifact, receipt)
        self.assertFalse((self.repo / "hostile-outside.bin").exists())
        self.assertFalse(artifact.exists())

    def test_witnessed_producer_rejects_detached_inherited_output_descriptor(self) -> None:
        source = """# WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_V2
import os
import time
output_fd = int(os.environ["WINS_RELEASE_DEPENDENCY_OUTPUT_FD"])
os.write(output_fd, b"witnessed bytes")
pid = os.fork()
if pid == 0:
    os.setsid()
    os.close(2)
    time.sleep(0.25)
    try:
        os.write(output_fd, b"post-parent-return mutation")
    except OSError:
        pass
    os._exit(0)
raise SystemExit(0)
"""
        index, begin, artifact, receipt = self._prepare_hostile_windows_producer(
            source, "detached-output-fd"
        )
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError,
            "detached output descriptor",
        ):
            self._finish_prepared_windows_producer(
                index, begin, artifact, receipt
            )
        self.assertFalse(artifact.exists())

    def _surviving_producer_processes(self) -> list[str]:
        listing = subprocess.run(
            ["/bin/ps", "-axww", "-o", "pid=,command="],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
        ).stdout.decode("utf-8", "replace")
        markers = {str(self.repo), str(self.repo.resolve())}
        return [
            line for line in listing.splitlines()
            if any(marker in line for marker in markers)
        ]

    def test_witnessed_producer_deadline_holds_against_a_writer_that_never_drains(self) -> None:
        # R23 W1-01: a descendant that outlives the leader and never lets the
        # private stderr channel run dry kept the drain loop alive with no
        # deadline check, and the refusal never killed the group it is in.
        source = """# WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_V2
import os
import time
output_fd = int(os.environ["WINS_RELEASE_DEPENDENCY_OUTPUT_FD"])
os.write(output_fd, b"witnessed bytes")
if os.fork() == 0:
    stop = time.monotonic() + 30
    while time.monotonic() < stop:
        try:
            os.write(2, b"x" * 4096)
        except OSError:
            break
    os._exit(0)
raise SystemExit(0)
"""
        index, begin, artifact, receipt = self._prepare_hostile_windows_producer(
            source, "endless-writer"
        )
        started = time.monotonic()
        with mock.patch.object(MODULE, "BUILD_ATTEMPT_TIMEOUT_SECONDS", 2):
            # Normally the writer keeps the channel readable and the deadline
            # refuses. On a host so loaded that the writer misses a 50 ms poll
            # window, the detached-descriptor refusal fires first instead;
            # either way the time bound and the group kill below must hold.
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError,
                "exceeded its deadline|detached output descriptor",
            ):
                self._finish_prepared_windows_producer(
                    index, begin, artifact, receipt
                )
        self.assertLess(time.monotonic() - started, 20)
        time.sleep(0.5)
        self.assertEqual(self._surviving_producer_processes(), [])
        self.assertFalse(artifact.exists())

    def test_witnessed_producer_retention_error_kills_the_producer_group(self) -> None:
        # R23 W1-01: an OSError while retaining artifact bytes escaped the
        # kill-and-wait handler and left the producer running unsupervised.
        source = """# WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_V2
import os
import time
output_fd = int(os.environ["WINS_RELEASE_DEPENDENCY_OUTPUT_FD"])
os.write(output_fd, b"witnessed bytes")
time.sleep(30)
"""
        index, begin, artifact, receipt = self._prepare_hostile_windows_producer(
            source, "retention-error"
        )
        original = MODULE._create_attempt_output_descriptor

        def read_only_output(held_attempt, output_name):
            descriptor, identity = original(held_attempt, output_name)
            read_only = os.open(
                output_name,
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=held_attempt.components[-1].descriptor,
            )
            os.close(descriptor)
            return read_only, identity

        started = time.monotonic()
        with mock.patch.object(
            MODULE, "_create_attempt_output_descriptor", read_only_output
        ):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, "could not be retained"
            ):
                self._finish_prepared_windows_producer(
                    index, begin, artifact, receipt
                )
        self.assertLess(time.monotonic() - started, 20)
        time.sleep(0.5)
        self.assertEqual(self._surviving_producer_processes(), [])
        self.assertFalse(artifact.exists())

    def test_witnessed_producer_cannot_copy_repository_or_old_artifact_bytes(self) -> None:
        old = self.repo / ".artifacts" / "old-release-bytes.bin"
        old.write_bytes(b"old release bytes")
        source = """# WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_V2
import os
import pathlib
repo = pathlib.Path.cwd().parents[1]
payload = (repo / ".artifacts" / "old-release-bytes.bin").read_bytes()
os.write(int(os.environ["WINS_RELEASE_DEPENDENCY_OUTPUT_FD"]), payload)
"""
        index, begin, artifact, receipt = self._prepare_hostile_windows_producer(
            source, "old-byte-copy"
        )
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "failed with exit status"
        ):
            self._finish_prepared_windows_producer(index, begin, artifact, receipt)
        self.assertFalse(artifact.exists())

        source = """# WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_V2
import os
import pathlib
repo = pathlib.Path.cwd().parents[1]
payload = (repo / "windows" / "windows-input.txt").read_bytes()
os.write(int(os.environ["WINS_RELEASE_DEPENDENCY_OUTPUT_FD"]), payload)
"""
        index, begin, artifact, receipt = self._prepare_hostile_windows_producer(
            source, "compiler-source-copy"
        )
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "failed with exit status"
        ):
            self._finish_prepared_windows_producer(index, begin, artifact, receipt)
        self.assertFalse(artifact.exists())

    def test_witnessed_producer_cannot_relabel_external_readable_bytes(self) -> None:
        source = """# WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_V2
import os
import pathlib
payload = pathlib.Path("/etc/hosts").read_bytes()
os.write(int(os.environ["WINS_RELEASE_DEPENDENCY_OUTPUT_FD"]), payload)
"""
        index, begin, artifact, receipt = self._prepare_hostile_windows_producer(
            source, "external-byte-copy"
        )
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "failed with exit status"
        ):
            self._finish_prepared_windows_producer(index, begin, artifact, receipt)
        self.assertFalse(artifact.exists())

    def test_consumed_build_attempt_cannot_be_replayed(self) -> None:
        index, artifact, _receipt = self._new_valid_receipt()
        begin = self.output / "WINDOWS_BUILD_BEGIN.json"
        replay_artifact = artifact.with_name("WinsVPN-Replay-Setup.exe")
        replay_receipt = self.output / "WINDOWS_REPLAY_RECEIPT.json"
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError,
            "not pristine and empty|already been claimed|"
            "claim belongs to another transaction|Build attempt does not exist",
        ):
            MODULE.finish_build_receipt(
                self.repo,
                index,
                "windows",
                begin,
                replay_artifact,
                MODULE.PLATFORM_BUILD_PRODUCERS["windows"],
                "flutter",
                "3.47.6",
                "5fc346839b5d0eef006ed8404392afb4dfae428d",
                "windows-x64-inno-unsigned",
                replay_receipt,
                secret_inventory_path=self._default_scan_inventory,
            )
        self.assertFalse(replay_artifact.exists())
        self.assertFalse(replay_receipt.exists())

    def test_cross_attempt_and_cross_platform_substitution_are_rejected(self) -> None:
        index = self._create_index()
        first = self.output / "CROSS_FIRST_BEGIN.json"
        second = self.output / "CROSS_SECOND_BEGIN.json"
        MODULE.begin_build_receipt(self.repo, index, "windows", first)
        MODULE.begin_build_receipt(self.repo, index, "windows", second)
        first_record = json.loads(first.read_text(encoding="utf-8"))
        second_record = json.loads(second.read_text(encoding="utf-8"))
        first_record["build_attempt"] = second_record["build_attempt"]
        self._rewrite_anchored(first, first_record)
        artifact = self.repo / "build" / "windows-installer" / "cross.exe"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError,
            "Build attempt is not pristine and empty|binding changed|identity changed",
        ):
            self._finish_prepared_windows_producer(
                index, first, artifact, self.output / "CROSS_RECEIPT.json"
            )
        linux_artifact = self.repo / "build" / "linux" / "cross.tar.zst"
        linux_artifact.parent.mkdir(parents=True, exist_ok=True)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "Build begin receipt binding changed"
        ):
            MODULE.finish_build_receipt(
                self.repo,
                index,
                "linux",
                second,
                linux_artifact,
                MODULE.PLATFORM_BUILD_PRODUCERS["linux"],
                "flutter",
                "3.47.6",
                "5fc346839b5d0eef006ed8404392afb4dfae428d",
                "linux-x64-appimage",
                self.output / "LINUX_CROSS_RECEIPT.json",
            )

    def test_post_producer_path_substitution_cannot_replace_retained_inode(self) -> None:
        index = self._create_index()
        begin = self.output / "SUBSTITUTION_BEGIN.json"
        MODULE.begin_build_receipt(self.repo, index, "windows", begin)
        artifact = self.repo / "build" / "windows-installer" / "substitution.exe"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        original = MODULE._run_witnessed_producer

        def substitute(*args, **kwargs) -> int:
            descriptor = original(*args, **kwargs)
            held_attempt = args[0]
            output_name = args[4]
            attempt_fd = held_attempt.components[-1].descriptor
            os.rename(output_name, ".displaced", src_dir_fd=attempt_fd, dst_dir_fd=attempt_fd)
            attacker = os.open(
                output_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=attempt_fd,
            )
            try:
                os.write(attacker, b"attacker bytes")
            finally:
                os.close(attacker)
            os.unlink(".displaced", dir_fd=attempt_fd)
            return descriptor

        with mock.patch.object(MODULE, "_run_witnessed_producer", substitute):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError,
                "retained output inode|output custody",
            ):
                self._finish_prepared_windows_producer(
                    index,
                    begin,
                    artifact,
                    self.output / "SUBSTITUTION_RECEIPT.json",
                )
        self.assertFalse(artifact.exists())

    def test_held_lock_rename_recreate_cannot_replace_retained_inode(self) -> None:
        source = """# WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_V2
import os
output = os.environ["WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT"]
os.rename(output, ".held-lock-displaced")
with open(output, "xb") as replacement:
    replacement.write(b"replacement under held controller lock")
os.unlink(".held-lock-displaced")
"""
        index, begin, artifact, receipt = self._prepare_hostile_windows_producer(
            source, "held-lock-rename-recreate"
        )
        original_profile = MODULE._producer_sandbox_profile

        def hostile_profile(*args, **kwargs) -> str:
            profile = original_profile(*args, **kwargs)
            attempt = MODULE._sandbox_build_attempt_path(args[0])
            return profile + f'(allow file-write* (subpath "{attempt}"))'

        with mock.patch.object(
            MODULE, "_producer_sandbox_profile", side_effect=hostile_profile
        ):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError,
                "failed with exit status|output changed after execution|"
                "retained output inode|output custody",
            ):
                self._finish_prepared_windows_producer(
                    index, begin, artifact, receipt
                )
        self.assertFalse(artifact.exists())
        self.assertFalse(receipt.exists())

    def test_unaffected_platform_receipt_survives_other_native_revision(self) -> None:
        _, artifact, receipt = self._new_valid_receipt()
        self._write("linux/linux-input.txt", "linux native revision\n")
        revised_index = self._create_native_only_revision_index("linux")
        result = MODULE.verify_build_receipt(
            self.repo, revised_index, "windows", receipt, artifact,
            self._default_scan_inventory,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["platform"], "windows")

    def test_receipt_survives_regenerated_equivalent_manifests(self) -> None:
        _, artifact, receipt = self._new_valid_receipt()
        revised_index = self._create_regenerated_equivalent_index()
        result = MODULE.verify_build_receipt(
            self.repo, revised_index, "windows", receipt, artifact,
            self._default_scan_inventory,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["platform"], "windows")

    def test_changed_platform_receipt_does_not_survive_its_native_revision(self) -> None:
        _, artifact, receipt = self._new_valid_receipt()
        self._write("windows/windows-input.txt", "windows native revision\n")
        revised_index = self._create_native_only_revision_index("windows")
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError,
            "does not match the current shared/platform inputs",
        ):
            MODULE.verify_build_receipt(
                self.repo, revised_index, "windows", receipt, artifact,
                self._default_scan_inventory,
            )

    def test_flutter_receipt_must_match_reviewed_toolchain_pin(self) -> None:
        index = self._create_index()
        begin = self.output / "WINDOWS_TOOLCHAIN_BEGIN.json"
        artifact = self.repo / "build" / "windows-installer" / "WinsVPN-Setup.exe"
        MODULE.begin_build_receipt(self.repo, index, "windows", begin)
        artifact.parent.mkdir(parents=True, exist_ok=True)
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "reviewed Flutter"):
            MODULE.finish_build_receipt(
                self.repo,
                index,
                "windows",
                begin,
                artifact,
                MODULE.PLATFORM_BUILD_PRODUCERS["windows"],
                "Flutter",
                "3.44.6",
                "ee80f08bbf000000000000000000000000000000",
                "windows-x64-inno-unsigned",
                self.output / "WINDOWS_TOOLCHAIN_RECEIPT.json",
                secret_inventory_path=self._default_scan_inventory,
            )

    def test_old_artifact_relabeling_fails_finish(self) -> None:
        artifact = self.repo / "build" / "windows-installer" / "WinsVPN-Setup.exe"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_bytes(b"old artifact")
        index = self._create_index()
        begin = self.output / "WINDOWS_BUILD_BEGIN.json"
        MODULE.begin_build_receipt(self.repo, index, "windows", begin)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError,
            "must not preexist|lacks its retained attempt hardlink",
        ):
            MODULE.finish_build_receipt(
                self.repo,
                index,
                "windows",
                begin,
                artifact,
                MODULE.PLATFORM_BUILD_PRODUCERS["windows"],
                "flutter",
                "3.47.6",
                "5fc346839b5d0eef006ed8404392afb4dfae428d",
                "windows-x64-inno-unsigned",
                self.output / "WINDOWS_BUILD_RECEIPT.json",
                secret_inventory_path=self._default_scan_inventory,
            )

    def test_finish_reverifies_unchanged_platform_inputs(self) -> None:
        index = self._create_index()
        begin = self.output / "WINDOWS_BUILD_BEGIN.json"
        artifact = self.repo / "build" / "windows-installer" / "WinsVPN-Setup.exe"
        MODULE.begin_build_receipt(self.repo, index, "windows", begin)
        artifact.parent.mkdir(parents=True, exist_ok=True)
        self._write("windows/windows-input.txt", "changed during build\n")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Native"):
            MODULE.finish_build_receipt(
                self.repo,
                index,
                "windows",
                begin,
                artifact,
                MODULE.PLATFORM_BUILD_PRODUCERS["windows"],
                "flutter",
                "3.47.6",
                "5fc346839b5d0eef006ed8404392afb4dfae428d",
                "windows-x64-inno-unsigned",
                self.output / "WINDOWS_BUILD_RECEIPT.json",
                secret_inventory_path=self._default_scan_inventory,
            )

    def test_build_receipt_finish_before_begin_fails(self) -> None:
        index, artifact, receipt = self._new_valid_receipt()
        record = json.loads(receipt.read_text(encoding="utf-8"))
        record["finished_utc"] = "2000-01-01T00:00:00Z"
        self._rewrite_anchored(receipt, record)
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "finish precedes"):
            MODULE.verify_build_receipt(
                self.repo, index, "windows", receipt, artifact,
                self._default_scan_inventory,
            )

    def test_build_receipts_reject_reuse_and_secret_metadata(
        self,
    ) -> None:
        index, artifact, receipt = self._new_valid_receipt()
        begin = self.output / "WINDOWS_BUILD_BEGIN.json"
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "overwrite"):
            MODULE.begin_build_receipt(self.repo, index, "windows", begin)
        secret_begin = self.output / "WINDOWS_SECRET_BEGIN.json"
        secret_artifact = artifact.with_name("WinsVPN-Secret-Setup.exe")
        MODULE.begin_build_receipt(self.repo, index, "windows", secret_begin)
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "secret material"):
            MODULE.finish_build_receipt(
                self.repo,
                index,
                "windows",
                secret_begin,
                secret_artifact,
                MODULE.PLATFORM_BUILD_PRODUCERS["windows"],
                "api-token",
                "3.47.6",
                "5fc346839b5d0eef006ed8404392afb4dfae428d",
                "windows-x64-inno-unsigned",
                self.output / "SECRET_METADATA_RECEIPT.json",
                secret_inventory_path=self._default_scan_inventory,
            )
        existing = receipt.read_bytes()
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError,
            "requires owner review and cannot be reused|Build attempt does not exist",
        ):
            MODULE.finish_build_receipt(
                self.repo,
                index,
                "windows",
                begin,
                artifact,
                MODULE.PLATFORM_BUILD_PRODUCERS["windows"],
                "flutter",
                "3.47.6",
                "5fc346839b5d0eef006ed8404392afb4dfae428d",
                "windows-x64-inno-unsigned",
                receipt,
                secret_inventory_path=self._default_scan_inventory,
            )
        self.assertEqual(receipt.read_bytes(), existing)
        overwrite_begin = self.output / "WINDOWS_OVERWRITE_BEGIN.json"
        overwrite_artifact = artifact.with_name("WinsVPN-Other-Setup.exe")
        MODULE.begin_build_receipt(self.repo, index, "windows", overwrite_begin)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError,
            "overwrite|requires owner review and cannot be reused",
        ):
            MODULE.finish_build_receipt(
                self.repo,
                index,
                "windows",
                overwrite_begin,
                overwrite_artifact,
                MODULE.PLATFORM_BUILD_PRODUCERS["windows"],
                "flutter",
                "3.47.6",
                "5fc346839b5d0eef006ed8404392afb4dfae428d",
                "windows-x64-inno-unsigned",
                receipt,
                secret_inventory_path=self._default_scan_inventory,
            )

    def test_reparse_index_and_output_ancestor_fail_closed(self) -> None:
        index = self._create_index()
        alias = self.repo / "INDEX_ALIAS.json"
        outside = self.repo / "outside-output"
        linked_dir = self.repo / ".artifacts" / "linked-output"
        outside.mkdir()
        try:
            alias.symlink_to(index)
            linked_dir.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink/reparse creation is unavailable on this host")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "reparse point"):
            MODULE.verify_release_index(self.repo, alias)
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "reparse point"):
            MODULE.begin_build_receipt(
                self.repo,
                index,
                "windows",
                linked_dir / "WINDOWS_BUILD_BEGIN.json",
            )

    def test_wear_os_and_extension_are_isolated_release_platforms(self) -> None:
        self.assertIn("wear_os", MODULE.PLATFORM_ROOTS)
        self.assertIn("extension", MODULE.PLATFORM_ROOTS)
        self.assertEqual(
            MODULE.PLATFORM_ROOTS["android"],
            ("android", MODULE.WINN_SOURCE_ROOT),
        )
        self.assertEqual(MODULE.PLATFORM_ROOTS["wear_os"], ("wear_os",))
        self.assertEqual(MODULE.PLATFORM_ROOTS["extension"], ("extension",))
        self.assertEqual(
            MODULE.PLATFORM_ROOTS["windows"],
            ("windows", "installer/windows", MODULE.WINN_SOURCE_ROOT),
        )
        self.assertEqual(
            MODULE.PLATFORM_ROOTS["linux"], ("linux", MODULE.WINN_SOURCE_ROOT)
        )
        self.assertEqual(
            MODULE.PLATFORM_BUILD_PRODUCERS["wear_os"],
            "wear_os/tools/signed_aab_receipt.py",
        )
        self.assertEqual(
            MODULE.PLATFORM_BUILD_PRODUCERS["extension"],
            "extension/build.py",
        )
        self.assertIn(
            "tools/wear_os_pairing_contract_check.py",
            MODULE.PLATFORM_PRODUCER_PATHS["android"],
        )
        self.assertIn(
            "tools/wear_os_pairing_contract_check.py",
            MODULE.PLATFORM_PRODUCER_PATHS["wear_os"],
        )

        self._write("wear_os/wear_os-input.txt", "wear native revision\n")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Native"):
            MODULE.verify_manifest(self.repo, self.platform_paths["wear_os"])
        for platform in self._other_platforms("wear_os"):
            self.assertTrue(
                MODULE.verify_manifest(self.repo, self.platform_paths[platform])["ok"]
            )

        self._write("wear_os/wear_os-input.txt", "wear_os\n")
        self._write("extension/extension-input.txt", "extension native revision\n")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Native"):
            MODULE.verify_manifest(self.repo, self.platform_paths["extension"])
        for platform in self._other_platforms("extension"):
            self.assertTrue(
                MODULE.verify_manifest(self.repo, self.platform_paths[platform])["ok"]
            )

    def test_shared_wear_pairing_producer_invalidates_android_and_wear_only(
        self,
    ) -> None:
        helper = "tools/wear_os_pairing_contract_check.py"
        original = (self.repo / helper).read_text(encoding="utf-8")
        self._write(helper, original + "changed pairing producer\n")
        for platform in ("android", "wear_os"):
            with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Producer"):
                MODULE.verify_manifest(self.repo, self.platform_paths[platform])
        for platform in self._other_platforms("android", "wear_os"):
            self.assertTrue(
                MODULE.verify_manifest(self.repo, self.platform_paths[platform])["ok"]
            )

    def test_winn_source_closure_invalidates_each_consuming_platform(self) -> None:
        self.assertEqual(
            {
                "android",
                "windows",
                "linux",
                "macos",
                "ios",
            },
            {
                platform
                for platform, roots in MODULE.PLATFORM_ROOTS.items()
                if MODULE.WINN_SOURCE_ROOT in roots
            },
        )
        source = self.repo / MODULE.WINN_SOURCE_ROOT / "android-input.txt"
        original = source.read_text(encoding="utf-8")
        source.write_text(original + "changed Winn source\n", encoding="utf-8")
        for platform in (
            "android",
            "windows",
            "linux",
            "macos",
            "ios",
        ):
            with self.subTest(platform=platform):
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError, "Native"
                ):
                    MODULE.verify_manifest(self.repo, self.platform_paths[platform])
        for platform in ("wear_os", "extension"):
            self.assertTrue(
                MODULE.verify_manifest(self.repo, self.platform_paths[platform])["ok"]
            )
        source.write_text(original, encoding="utf-8")

    def test_cross_store_target_and_gate_producers_are_bound(self) -> None:
        import cross_store_upload_readiness as readiness

        for target in readiness.ALL_UPLOAD_TARGETS:
            bound = set(target.producer_ids)
            bound.update(readiness.GATE_PRODUCER_IDS[target.signing_gate_id])
            bound.update(readiness.GATE_PRODUCER_IDS[target.hardening_gate_id])
            if target.manifest_verifier_path is not None:
                bound.add(target.manifest_verifier_path)
            with self.subTest(target=target.target_id):
                freeze_producers = set(
                    MODULE.PLATFORM_PRODUCER_PATHS[target.platform]
                )
                self.assertTrue(
                    bound.issubset(freeze_producers),
                    sorted(bound - freeze_producers),
                )
                self.assertIn(
                    MODULE.PLATFORM_BUILD_PRODUCERS[target.platform],
                    freeze_producers,
                )

    def test_canonical_freeze_platforms_cover_every_store_surface(self) -> None:
        self.assertEqual(
            set(MODULE.PLATFORM_ROOTS), set(MODULE.CANONICAL_FREEZE_PLATFORMS)
        )
        self.assertEqual(
            set(MODULE.PLATFORM_STORE_SURFACES), set(MODULE.CANONICAL_FREEZE_PLATFORMS)
        )
        self.assertEqual(
            MODULE.PLATFORM_STORE_SURFACES["android"],
            ("google-play-phone", "google-play-tv"),
        )
        self.assertEqual(
            MODULE.PLATFORM_STORE_SURFACES["wear_os"], ("google-play-wear-os",)
        )
        self.assertEqual(
            MODULE.PLATFORM_STORE_SURFACES["extension"],
            ("chrome-web-store", "edge-add-ons", "firefox-amo"),
        )
        self.assertEqual(MODULE.PRIVACY_POLICY_URL, "https://www.winsvpn.org/privacy/")
        for platform in MODULE.CANONICAL_FREEZE_PLATFORMS:
            with self.subTest(platform=platform):
                MODULE._assert_required_gate_producers(platform)
                self.assertTrue(MODULE.store_surfaces(platform))
                self.assertTrue(MODULE.allowed_targets(platform))

    def test_historical_five_platform_index_is_incomplete(self) -> None:
        index = self._create_index()
        record = json.loads(index.read_text(encoding="utf-8"))
        for extra in ("wear_os", "extension"):
            record["platform_manifests"].pop(extra)
        self._rewrite_anchored(index, record)
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "incomplete"):
            MODULE.verify_release_index(self.repo, index)

    def _create_scoped_index(
        self, platforms: tuple[str, ...] = ("android",)
    ) -> pathlib.Path:
        index = self.output / "RELEASE_INPUT_INDEX.json"
        MODULE.create_release_index(self.repo, self.output, index, platforms)
        return index

    def test_scoped_index_records_only_real_manifests_and_says_it_is_incomplete(
        self,
    ) -> None:
        index = self._create_scoped_index()
        record = json.loads(index.read_text(encoding="utf-8"))
        self.assertEqual(record["contract"], MODULE.SCOPED_INDEX_CONTRACT)
        self.assertNotEqual(record["contract"], MODULE.INDEX_CONTRACT)
        self.assertIs(record["manifest_set_complete"], False)
        self.assertIs(record["publication_authorized"], False)
        self.assertEqual(sorted(record["platform_manifests"]), ["android"])
        self.assertEqual(record["platform_scope"], ["android"])
        self.assertEqual(
            record["unfrozen_platforms"],
            sorted(set(MODULE.CANONICAL_FREEZE_PLATFORMS) - {"android"}),
        )
        self.assertEqual(
            set(record),
            set(MODULE.INDEX_RECORD_KEYS) | set(MODULE.SCOPED_INDEX_EXTRA_KEYS),
        )
        reference = record["platform_manifests"]["android"]
        self.assertEqual(reference["path"], "ANDROID_INPUTS.json")
        self.assertEqual(
            reference["sha256"], self._file_sha256(".artifacts/freeze/ANDROID_INPUTS.json")
        )
        verified = MODULE.verify_release_index(self.repo, index, "android")
        self.assertTrue(verified["ok"])
        self.assertIs(verified["scoped"], True)
        self.assertEqual(verified["platform_scope"], ["android"])
        self.assertEqual(sorted(verified["platforms"]), ["android"])
        self.assertEqual(
            stat.S_IMODE(index.stat().st_mode), 0o400
        )
        # The complete index keeps its exact legacy contract and key set.
        complete = self.output / "RELEASE_INPUT_INDEX_COMPLETE.json"
        MODULE.create_release_index(self.repo, self.output, complete)
        legacy = json.loads(complete.read_text(encoding="utf-8"))
        self.assertEqual(legacy["contract"], MODULE.INDEX_CONTRACT)
        self.assertIs(legacy["manifest_set_complete"], True)
        self.assertEqual(set(legacy), set(MODULE.INDEX_RECORD_KEYS))
        self.assertEqual(sorted(legacy["platform_manifests"]), sorted(EXPECTED_PLATFORM_ROOTS))
        legacy_result = MODULE.verify_release_index(self.repo, complete)
        self.assertTrue(legacy_result["ok"])
        self.assertNotIn("scoped", legacy_result)

    def test_scoped_index_refuses_full_set_and_out_of_scope_verification(self) -> None:
        index = self._create_scoped_index(("wear_os", "android"))
        self.assertEqual(
            json.loads(index.read_text(encoding="utf-8"))["platform_scope"],
            ["android", "wear_os"],
        )
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "full-set verification"
        ):
            MODULE.verify_release_index(self.repo, index)
        for platform in ("ios", "macos", "windows", "linux", "extension"):
            with self.subTest(platform=platform):
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError, "outside the scope"
                ):
                    MODULE.verify_release_index(self.repo, index, platform)
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Unsupported platform"):
            MODULE.verify_release_index(self.repo, index, "tvos")
        for platform in ("android", "wear_os"):
            with self.subTest(platform=platform):
                self.assertTrue(
                    MODULE.verify_release_index(self.repo, index, platform)["ok"]
                )

    def test_scoped_index_does_not_need_other_platform_manifests_or_inputs(self) -> None:
        # The Apple engine roots are ignored build outputs that exist in no
        # checkout, so neither Apple manifest can be produced.
        shutil.rmtree(self.repo / "apple" / "EngineArtifacts")
        for platform in ("ios", "macos"):
            with self.subTest(platform=platform):
                with self.assertRaises(MODULE.DependencyFreezeError):
                    MODULE.create_platform_manifest(
                        self.repo,
                        platform,
                        self.shared_path,
                        self.output / f"{platform.upper()}_RETRY.json",
                    )
            self.platform_paths[platform].unlink()
        with self.assertRaises(MODULE.DependencyFreezeError):
            MODULE.create_release_index(
                self.repo, self.output, self.output / "RELEASE_INPUT_INDEX_COMPLETE.json"
            )
        index = self._create_scoped_index(("android",))
        self.assertTrue(MODULE.verify_release_index(self.repo, index, "android")["ok"])
        self.assertTrue(MODULE.verify_manifest(self.repo, self.platform_paths["android"])["ok"])

    def test_scoped_index_envelope_tampering_fails_closed(self) -> None:
        index = self._create_scoped_index(("android",))
        original = json.loads(index.read_text(encoding="utf-8"))

        def expect_refused(label: str, change) -> None:
            record = json.loads(json.dumps(original))
            change(record)
            self._rewrite_anchored(index, record)
            with self.subTest(case=label):
                with self.assertRaises(MODULE.DependencyFreezeError):
                    MODULE.verify_release_index(self.repo, index, "android")

        expect_refused(
            "claims to be complete",
            lambda r: r.__setitem__("manifest_set_complete", True),
        )
        expect_refused("scope field dropped", lambda r: r.pop("platform_scope"))
        expect_refused("unfrozen field dropped", lambda r: r.pop("unfrozen_platforms"))
        expect_refused(
            "unfrozen list understated",
            lambda r: r.__setitem__("unfrozen_platforms", r["unfrozen_platforms"][:-1]),
        )
        expect_refused(
            "scope names a platform without a reference",
            lambda r: r.__setitem__("platform_scope", ["windows"]),
        )
        expect_refused(
            "scope covers every platform",
            lambda r: (
                r.__setitem__("platform_scope", sorted(MODULE.CANONICAL_FREEZE_PLATFORMS)),
                r.__setitem__("unfrozen_platforms", []),
            ),
        )
        expect_refused(
            "scope repeats a platform",
            lambda r: r.__setitem__("platform_scope", ["android", "android"]),
        )
        expect_refused(
            "scoped record relabelled as the complete contract",
            lambda r: r.__setitem__("contract", MODULE.INDEX_CONTRACT),
        )
        expect_refused(
            "unknown contract",
            lambda r: r.__setitem__("contract", "winsvpn-release-input-index-v2"),
        )
        expect_refused(
            "reference outside the scope",
            lambda r: r["platform_manifests"].__setitem__(
                "ios", dict(r["platform_manifests"]["android"])
            ),
        )
        complete = self.output / "RELEASE_INPUT_INDEX_COMPLETE.json"
        MODULE.create_release_index(self.repo, self.output, complete)
        legacy = json.loads(complete.read_text(encoding="utf-8"))
        legacy["manifest_set_complete"] = False
        self._rewrite_anchored(complete, legacy)
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "contract is invalid"):
            MODULE.verify_release_index(self.repo, complete, "android")

    def test_scoped_index_creation_rejects_bad_scopes(self) -> None:
        output = self.output / "RELEASE_INPUT_INDEX.json"
        for label, scope in (
            ("empty", ()),
            ("unknown platform", ("android", "tvos")),
            ("duplicate platform", ("android", "android")),
            ("every platform", tuple(MODULE.CANONICAL_FREEZE_PLATFORMS)),
            ("bare string", "android"),
            ("blank entry", ("",)),
            ("non-text entry", (1,)),
        ):
            with self.subTest(scope=label):
                with self.assertRaises(MODULE.DependencyFreezeError):
                    MODULE.create_release_index(self.repo, self.output, output, scope)
        self.assertFalse(output.exists())
        self.assertFalse(output.with_name(output.name + ".sha256").exists())
        self.platform_paths["ios"].unlink()
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "does not exist"):
            MODULE.create_release_index(
                self.repo, self.output, output, ("android", "ios")
            )
        self.assertFalse(output.exists())
        self.assertFalse(
            any(
                path.name.startswith(".freeze-staging-")
                for path in (self.repo / ".artifacts").iterdir()
            )
        )

    def test_scoped_index_still_binds_in_scope_manifest_and_live_inputs(self) -> None:
        index = self._create_scoped_index(("android",))
        self._write("android/android-input.txt", "changed android input\n")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Native"):
            MODULE.verify_release_index(self.repo, index, "android")
        self._write("android/android-input.txt", "android\n")
        self.assertTrue(MODULE.verify_release_index(self.repo, index, "android")["ok"])
        android = self.platform_paths["android"]
        self._replace_read_only_manifest(
            android, android.read_text(encoding="utf-8") + " "
        )
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "identity changed"):
            MODULE.verify_release_index(self.repo, index, "android")

    def test_android_build_lifecycle_runs_on_a_scoped_index(self) -> None:
        index, _begin, artifact, receipt = self._attested_android_receipt(
            index=self._create_scoped_index(("android",))
        )
        record = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(
            record["release_input_index"]["path"],
            ".artifacts/freeze/RELEASE_INPUT_INDEX.json",
        )
        result = MODULE.verify_build_receipt(
            self.repo, index, "android", receipt, artifact
        )
        self.assertTrue(result["ok"])
        self.assertEqual(
            result["artifact_input_fingerprint_sha256"],
            json.loads(index.read_text(encoding="utf-8"))["platform_manifests"][
                "android"
            ]["artifact_input_fingerprint_sha256"],
        )
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "outside the scope"):
            MODULE.begin_build_receipt(
                self.repo, index, "windows", self.output / "WINDOWS_SCOPED_BEGIN.json"
            )
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "outside the scope"):
            MODULE.verify_build_receipt(self.repo, index, "windows", receipt, artifact, self._default_scan_inventory)

    def test_receipts_carry_forward_between_scoped_and_complete_indexes(self) -> None:
        scoped = self._create_scoped_index(("android",))
        _scoped, _begin, scoped_artifact, scoped_receipt = self._attested_android_receipt(
            name="SCOPED_AAB", index=scoped
        )
        complete_alt = self.output / "RELEASE_INPUT_INDEX_COMPLETE.json"
        MODULE.create_release_index(self.repo, self.output, complete_alt)
        _complete, _begin2, complete_artifact, complete_receipt = (
            self._attested_android_receipt(
                name="COMPLETE_AAB",
                artifact_relative="build/app/outputs/bundle/tvRelease/app-tv-release.aab",
                index=complete_alt,
            )
        )
        regenerated = self.repo / ".artifacts" / "freeze-scoped-regenerated"
        shared = regenerated / "SHARED_INPUTS.json"
        MODULE.create_shared_manifest(self.repo, shared, "sr1")
        MODULE.create_platform_manifest(
            self.repo, "android", shared, regenerated / "ANDROID_INPUTS.json"
        )
        regenerated_scoped = regenerated / "RELEASE_INPUT_INDEX.json"
        MODULE.create_release_index(
            self.repo, regenerated, regenerated_scoped, ("android",)
        )
        self.assertNotEqual(regenerated_scoped.read_bytes(), scoped.read_bytes())
        for label, receipt, artifact in (
            ("scoped receipt under a regenerated scoped index", scoped_receipt, scoped_artifact),
            ("complete receipt under a regenerated scoped index", complete_receipt, complete_artifact),
        ):
            with self.subTest(case=label):
                self.assertTrue(
                    MODULE.verify_build_receipt(
                        self.repo, regenerated_scoped, "android", receipt, artifact
                    )["ok"]
                )
        regenerated_complete = self._create_regenerated_equivalent_index()
        with self.subTest(case="scoped receipt under a regenerated complete index"):
            self.assertTrue(
                MODULE.verify_build_receipt(
                    self.repo,
                    regenerated_complete,
                    "android",
                    scoped_receipt,
                    scoped_artifact,
                )["ok"]
            )

    def test_create_index_cli_scope_is_optional_and_comma_separated(self) -> None:
        parser = MODULE._parser()
        base = ["create-index", "--repo", "/x", "--manifest-dir", "/x/m", "--output", "/x/i"]
        with mock.patch.object(MODULE, "create_release_index", return_value={}) as create:
            MODULE._dispatch_command(
                parser.parse_args([*base, "--platforms", "android,wear_os"])
            )
            self.assertEqual(create.call_args.args[3], ("android", "wear_os"))
            MODULE._dispatch_command(parser.parse_args(base))
            self.assertIsNone(create.call_args.args[3])
            MODULE._dispatch_command(parser.parse_args([*base, "--platforms", ""]))
            self.assertEqual(create.call_args.args[3], ("",))
        with self.assertRaises(MODULE.DependencyFreezeError):
            MODULE._normalize_index_scope(("",))
        verify = parser.parse_args(["verify-index", "--repo", "/x", "--index", "/x/i"])
        self.assertIsNone(verify.platform)

    def test_full_set_consumers_refuse_a_scoped_index(self) -> None:
        index = self._create_scoped_index(("android",))
        import cross_store_upload_readiness as readiness
        import public_release_live_smoke_common as smoke

        with mock.patch.object(
            readiness,
            "evaluate_source_gates",
            return_value={
                "local_gate_bindings_complete": True,
                "unsupported_build_receipt_targets": [],
            },
        ):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, "full-set verification"
            ):
                readiness.record_evidence(
                    self.repo, self.output / "READINESS.json", index
                )
        with self.assertRaisesRegex(smoke.EvidenceError, "full-set verification"):
            smoke.release_input_binding(self.repo, "android", str(index))
        # The consumers that parse the index JSON themselves are exercised, not
        # only grepped: the exact key set and the contract are what refuse it.
        import gcp_client_release_binding as gcp

        scoped_record = json.loads(index.read_text(encoding="utf-8"))
        self.assertNotEqual(set(scoped_record), set(gcp.INDEX_KEYS))
        self.assertNotEqual(scoped_record["contract"], MODULE.INDEX_CONTRACT)
        self.assertIs(scoped_record["manifest_set_complete"], False)
        for relative, marker in (
            ("tools/build_linux_release.sh", "release index fields are not exact"),
            ("tools/build_linux_arm64_awg.sh", "release input index fields are not exact"),
        ):
            with self.subTest(consumer=relative, check="embedded index parser"):
                source = (SCRIPT.parent.parent / relative).read_text(encoding="utf-8")
                at = source.index(marker)
                begins = [
                    match.end()
                    for match in re.finditer(r"<<'PY'[ \t]*\n", source[:at])
                ]
                end = source.index("\nPY\n", at)
                done = subprocess.run(
                    [sys.executable, "-I", "-", str(index)],
                    input=source[begins[-1]:end] + "\n",
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(done.returncode, 0, done.stdout)
                self.assertIn("not exact", done.stderr)
        root = SCRIPT.parent
        for relative, marker in (
            ("tools/gcp_client_release_binding.py", "!= freeze.INDEX_CONTRACT"),
            ("tools/android_final_evidence_collector.py", '"winsvpn-release-input-index-v1"'),
            ("tools/build_linux_release.sh", '"winsvpn-release-input-index-v1"'),
            ("tools/build_linux_arm64_awg.sh", '"winsvpn-release-input-index-v1"'),
        ):
            with self.subTest(consumer=relative):
                source = (root.parent / relative).read_text(encoding="utf-8")
                self.assertIn(marker, source)
                self.assertNotIn("index-scoped", source)
                self.assertNotIn("SCOPED_INDEX_CONTRACT", source)

    def test_production_aggregate_cap_admits_the_android_set_and_stops_at_one_gib(
        self,
    ) -> None:
        mebibyte = 1024 * 1024
        self.assertEqual(MODULE.MAX_DEPENDENCY_AGGREGATE_BYTES, 1024 * mebibyte)
        # The Android native set measured 594.84 MiB at 1.0.16+33.
        self.assertGreater(MODULE.MAX_DEPENDENCY_AGGREGATE_BYTES, 595 * mebibyte)
        root = self.repo / "sparse-root"
        root.mkdir()

        def sparse(name: str, size: int) -> None:
            path = root / name
            with open(path, "wb") as handle:
                handle.truncate(size)
            if path.stat().st_blocks * 512 > 16 * mebibyte:
                self.skipTest("sparse files are unavailable on this filesystem")

        owners = MODULE._allowed_owners(self.repo)

        def select() -> int:
            repo_fd, _info = MODULE._open_repo_dir(self.repo, owners)
            try:
                selected, _directories = MODULE._selected_paths(
                    repo_fd, ("sparse-root",), owners
                )
            finally:
                os.close(repo_fd)
            return len(selected)

        for name in ("a.bin", "b.bin", "c.bin"):
            sparse(name, 300 * mebibyte)
        self.assertEqual(select(), 3)
        sparse("d.bin", 124 * mebibyte)
        self.assertEqual(select(), 4)
        sparse("e.bin", 1)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "aggregate size is outside the accepted bound"
        ):
            select()
        (root / "e.bin").unlink()
        sparse("f.bin", 301 * mebibyte)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "aggregate size is outside the accepted bound"
        ):
            select()

    def test_freeze_outputs_must_stay_under_artifacts(self) -> None:
        outside = self.repo / "not-artifacts" / "SHARED_INPUTS.json"
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, r"\.artifacts"):
            MODULE.create_shared_manifest(self.repo, outside, "sr-out")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, r"\.artifacts"):
            MODULE.create_platform_manifest(
                self.repo,
                "windows",
                self.shared_path,
                self.repo / "not-artifacts" / "WINDOWS_INPUTS.json",
            )
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, r"\.artifacts"):
            MODULE.create_release_index(
                self.repo,
                self.output,
                self.repo / "not-artifacts" / "RELEASE_INPUT_INDEX.json",
            )

    def test_receipt_rejects_unreviewed_and_cross_platform_targets(self) -> None:
        index = self._create_index()
        begin = self.output / "WINDOWS_TARGET_BEGIN.json"
        MODULE.begin_build_receipt(self.repo, index, "windows", begin)
        artifact = self.repo / "build" / "windows-installer" / "WinsVPN-Setup.exe"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "reviewed store target"):
            MODULE.finish_build_receipt(
                self.repo,
                index,
                "windows",
                begin,
                artifact,
                MODULE.PLATFORM_BUILD_PRODUCERS["windows"],
                "flutter",
                "3.47.6",
                "5fc346839b5d0eef006ed8404392afb4dfae428d",
                "android-release-apk",
                self.output / "WINDOWS_WRONG_TARGET_RECEIPT.json",
                secret_inventory_path=self._default_scan_inventory,
            )
        MODULE.finish_build_receipt(
            self.repo,
            index,
            "windows",
            begin,
            artifact,
            MODULE.PLATFORM_BUILD_PRODUCERS["windows"],
            "flutter",
            "3.47.6",
            "5fc346839b5d0eef006ed8404392afb4dfae428d",
            "windows-x64-inno-unsigned",
            self.output / "WINDOWS_REVIEWED_TARGET_RECEIPT.json",
            secret_inventory_path=self._default_scan_inventory,
        )

    def test_android_tv_target_is_reviewed_and_isolated_from_wear(self) -> None:
        self.assertIn(
            "android-tv-release-apk", MODULE.allowed_targets("android")
        )
        self.assertIn(
            "android-tv-release-aab", MODULE.allowed_targets("android")
        )
        self.assertNotIn(
            "android-tv-release-apk", MODULE.allowed_targets("wear_os")
        )
        self.assertNotIn(
            "android-tv-release-aab", MODULE.allowed_targets("wear_os")
        )
        self.assertEqual(
            MODULE.allowed_targets("wear_os"), ("wear-os-release-aab",)
        )
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "reviewed store target"):
            MODULE._assert_allowed_target("wear_os", "android-release-aab")

    def test_apple_obfuscation_and_privacy_gates_are_bound(self) -> None:
        helpers = (
            "tools/release_obfuscation_contract.py",
            "tools/validate_release_artifact_privacy.py",
            "tools/apple_release_symbol_custody.py",
            "tools/cross_store_upload_readiness.py",
            # The Apple receipt verifiers import this client; it must be a
            # frozen producer input like the verifiers themselves.
            "tools/release_freeze_client.py",
        )
        for helper in helpers:
            with self.subTest(helper=helper):
                for platform in ("macos", "ios"):
                    self.assertIn(helper, MODULE.PLATFORM_PRODUCER_PATHS[platform])
                original = (self.repo / helper).read_text(encoding="utf-8")
                self._write(helper, original + "changed Apple hardening gate\n")
                for platform in ("macos", "ios"):
                    with self.assertRaisesRegex(
                        MODULE.DependencyFreezeError, "Producer"
                    ):
                        MODULE.verify_manifest(
                            self.repo, self.platform_paths[platform]
                        )
                self._write(helper, original)

    def test_wear_and_extension_bind_privacy_not_flutter_obfuscation(self) -> None:
        wear_producers = set(MODULE.PLATFORM_PRODUCER_PATHS["wear_os"])
        extension_producers = set(MODULE.PLATFORM_PRODUCER_PATHS["extension"])
        self.assertIn("tools/validate_release_artifact_privacy.py", wear_producers)
        self.assertIn("tools/cross_store_upload_readiness.py", wear_producers)
        self.assertNotIn("tools/release_obfuscation_contract.py", wear_producers)
        self.assertIn(
            "tools/validate_release_artifact_privacy.py", extension_producers
        )
        self.assertIn("tools/cross_store_upload_readiness.py", extension_producers)
        self.assertIn("tools/release_obfuscation_contract.py", extension_producers)
        helper = "tools/validate_release_artifact_privacy.py"
        original = (self.repo / helper).read_text(encoding="utf-8")
        self._write(helper, original + "changed privacy gate\n")
        for platform in (
            "wear_os",
            "extension",
            "android",
            "windows",
            "linux",
            "macos",
            "ios",
        ):
            with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Producer"):
                MODULE.verify_manifest(self.repo, self.platform_paths[platform])
        self._write(helper, original)

    def test_upload_readiness_producer_is_bound_to_every_platform(self) -> None:
        helper = "tools/cross_store_upload_readiness.py"
        for producers in MODULE.PLATFORM_PRODUCER_PATHS.values():
            self.assertIn(helper, producers)
        original = (self.repo / helper).read_text(encoding="utf-8")
        self._write(helper, original + "changed upload-readiness evidence\n")
        for platform, manifest in self.platform_paths.items():
            with self.subTest(platform=platform):
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError, "Producer"
                ):
                    MODULE.verify_manifest(self.repo, manifest)
        self._write(helper, original)


    def test_selection_read_race_cannot_pass(self) -> None:
        victim = self.repo / "lib" / "main.dart"

        def hook() -> None:
            victim.write_text("selection-race replacement\n", encoding="utf-8")

        with self._hook("_POST_SELECT_HOOK", hook):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, "selection and read"
            ):
                MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))

    def test_post_hash_replacement_cannot_pass(self) -> None:
        victim = self.repo / "lib" / "main.dart"

        def hook() -> None:
            victim.write_text("post-hash replacement\n", encoding="utf-8")

        with self._hook("_POST_INPUT_CAPTURE_HOOK", hook):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, "during freeze capture"
            ):
                MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))

    def test_hardlink_input_is_rejected(self) -> None:
        source = self.repo / "lib" / "main.dart"
        alias = self.repo / "hardlink-outside.dart"
        try:
            os.link(source, alias)
        except OSError:
            self.skipTest("Hardlink creation is unavailable on this host")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "link count 1"):
            MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))
        alias.unlink()
        MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))

    def test_symlink_swap_between_selection_and_read_is_rejected(self) -> None:
        victim = self.repo / "lib" / "main.dart"
        target = self.repo / "outside.txt"
        target.write_text("outside\n", encoding="utf-8")

        def hook() -> None:
            victim.unlink()
            victim.symlink_to(target)

        try:
            target.write_text("outside\n", encoding="utf-8")
        except OSError:
            self.skipTest("Symlink creation is unavailable on this host")
        with self._hook("_POST_SELECT_HOOK", hook):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError,
                r"selection and read|regular non-symlink|Unable to read dependency input|Symlink",
            ):
                MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))

    def test_source_set_insertion_during_capture_fails(self) -> None:
        inserted = self.repo / "lib" / "inserted.dart"

        def hook() -> None:
            inserted.write_text("inserted\n", encoding="utf-8")

        with self._hook("_POST_INPUT_CAPTURE_HOOK", hook):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, "during freeze capture"
            ):
                MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))
        inserted.unlink()
        MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))

    def test_source_set_removal_during_capture_fails(self) -> None:
        victim = self.repo / "lib" / "main.dart"

        def hook() -> None:
            victim.unlink()

        with self._hook("_POST_INPUT_CAPTURE_HOOK", hook):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, "during freeze capture"
            ):
                MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))
        victim.write_text("void main() {}\n", encoding="utf-8")
        MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))

    def test_path_swap_during_capture_cannot_pass(self) -> None:
        first = self.repo / "lib" / "main.dart"
        second = self.repo / "lib" / "other.dart"
        second.write_text("other-lib-input\n", encoding="utf-8")

        def hook() -> None:
            tmp = self.repo / "lib" / "swap.tmp"
            first.rename(tmp)
            second.rename(first)
            tmp.rename(second)

        with self._hook("_POST_INPUT_CAPTURE_HOOK", hook):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, "during freeze capture"
            ):
                MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))

    def test_duplicate_json_keys_are_rejected_recursively(self) -> None:
        original = self.shared_path.read_text(encoding="utf-8")
        top_duplicate = original.replace(
            '  "schema_version": 1,\n',
            '  "schema_version": 1,\n  "schema_version": 1,\n',
            1,
        )
        nested_duplicate = original.replace(
            '    "file_count":',
            '    "file_count": 1,\n    "file_count":',
            1,
        )
        for candidate in (top_duplicate, nested_duplicate):
            with self.subTest(candidate=candidate[:80]):
                self._replace_read_only_manifest(self.shared_path, candidate)
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError, "duplicate JSON key"
                ):
                    MODULE.verify_manifest(self.repo, self.shared_path)
        self._replace_read_only_manifest(self.shared_path, original)

    def test_non_finite_json_is_rejected_recursively(self) -> None:
        original = self.shared_path.read_text(encoding="utf-8")
        candidates = (
            original.replace('"schema_version": 1', '"schema_version": NaN', 1),
            re.sub(r'"size": \d+', '"size": Infinity', original, count=1),
            re.sub(r'"size": \d+', '"size": -Infinity', original, count=1),
            re.sub(r'"size": \d+', '"size": 1e9999', original, count=1),
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate[:120]):
                self._replace_read_only_manifest(self.shared_path, candidate)
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError,
                    r"non-finite|Unable to read",
                ):
                    MODULE.verify_manifest(self.repo, self.shared_path)
        self._replace_read_only_manifest(self.shared_path, original)
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "non-finite"):
            MODULE._canonical_json({"outer": [{"value": float("nan")}]})

    def test_bool_as_int_and_wrong_scalar_types_are_rejected(self) -> None:
        original = self.shared_path.read_text(encoding="utf-8")
        cases = (
            original.replace('"schema_version": 1', '"schema_version": true', 1),
            original.replace('"shared_revision": "sr1"', '"shared_revision": 1', 1),
            original.replace(
                '"generated_outputs_excluded": true',
                '"generated_outputs_excluded": 1',
                1,
            ),
            re.sub(r'"file_count": \d+', '"file_count": true', original, count=1),
            re.sub(r'"size": \d+', '"size": true', original, count=1),
        )
        for candidate in cases:
            with self.subTest(candidate=candidate[:120]):
                self._replace_read_only_manifest(self.shared_path, candidate)
                with self.assertRaises(MODULE.DependencyFreezeError):
                    MODULE.verify_manifest(self.repo, self.shared_path)
        self._replace_read_only_manifest(self.shared_path, original)

    def test_extra_and_missing_fields_are_rejected(self) -> None:
        original = self.shared_path.read_text(encoding="utf-8")
        extra = original.replace(
            "{\n",
            '{\n  "extra": true,\n',
            1,
        )
        self._replace_read_only_manifest(self.shared_path, extra)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "schema fields are invalid"
        ):
            MODULE.verify_manifest(self.repo, self.shared_path)
        missing = original.replace(
            '  "publication_authorized": false,\n',
            "",
            1,
        )
        self._replace_read_only_manifest(self.shared_path, missing)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "schema fields are invalid"
        ):
            MODULE.verify_manifest(self.repo, self.shared_path)
        self._replace_read_only_manifest(self.shared_path, original)

    def test_parent_directory_swap_cannot_redirect_capture(self) -> None:
        attacker = self.repo / "attacker-lib"
        attacker.mkdir()
        (attacker / "main.dart").write_text("attacker payload\n", encoding="utf-8")
        original = self.repo / "lib"
        backup = self.repo / "lib-original"

        def hook(relative: str) -> None:
            if relative != "lib" or backup.exists():
                return
            original.rename(backup)
            attacker.rename(original)

        try:
            with self._hook("_POST_DIRECTORY_BIND_HOOK", hook):
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError,
                    r"identity changed while traversing|Symlink|reparse point",
                ):
                    MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))
        finally:
            lib = self.repo / "lib"
            if backup.exists():
                if lib.exists() or lib.is_symlink():
                    if lib.is_symlink():
                        lib.unlink()
                    elif not attacker.exists():
                        lib.rename(attacker)
                    else:
                        if lib.is_dir() and not lib.is_symlink():
                            for child in lib.iterdir():
                                child.unlink()
                            lib.rmdir()
                        else:
                            lib.unlink()
                backup.rename(lib)
        MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))

    def test_artifact_swap_during_verify_is_rejected(self) -> None:
        index, artifact, receipt = self._new_valid_receipt()
        other = artifact.parent / "other-artifact.exe"
        other.write_bytes(b"swapped artifact bytes!!")

        def hook(relative: str) -> None:
            if relative != "build/windows-installer":
                return
            if artifact.is_symlink() or not artifact.exists():
                return
            artifact.unlink()
            artifact.symlink_to(other)

        with self._hook("_POST_DIRECTORY_BIND_HOOK", hook):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError,
                r"identity changed while traversing|Symlink|reparse point|Exact built artifact|Unable to read|regular non-symlink",
            ):
                MODULE.verify_build_receipt(
                    self.repo, index, "windows", receipt, artifact,
                    self._default_scan_inventory,
                )

    def test_receipt_verification_requires_exact_artifact_bytes(self) -> None:
        index, _artifact, receipt = self._new_valid_receipt()
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError,
            "Exact built artifact bytes are required",
        ):
            MODULE.verify_build_receipt(self.repo, index, "windows", receipt)

    def test_group_world_writable_file_and_directory_are_rejected(self) -> None:
        source = self.repo / "lib" / "main.dart"
        original_file_mode = source.stat().st_mode
        os.chmod(source, 0o666)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "group/world-writable dependency file"
        ):
            MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))
        os.chmod(source, original_file_mode)
        lib = self.repo / "lib"
        original_dir_mode = lib.stat().st_mode
        os.chmod(lib, 0o777)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "group/world-writable dependency directory"
        ):
            MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))
        os.chmod(lib, original_dir_mode)
        MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))

    def test_directory_component_case_fold_collision_is_rejected(self) -> None:
        upper = self.repo / "lib" / "Foo"
        lower = self.repo / "lib" / "foo"
        upper.mkdir()
        (upper / "a.dart").write_text("a\n", encoding="utf-8")
        try:
            lower.mkdir()
        except FileExistsError:
            self.skipTest(
                "Case-distinct directories are unavailable on this filesystem"
            )
        (lower / "b.dart").write_text("b\n", encoding="utf-8")
        if (
            not upper.exists()
            or not lower.exists()
            or upper.resolve() == lower.resolve()
        ):
            self.skipTest(
                "Case-distinct directories are unavailable on this filesystem"
            )
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, r"Case-colliding|case-fold"
        ):
            MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))

    def test_selected_file_count_and_aggregate_byte_bombs_fail(self) -> None:
        previous_count = MODULE.MAX_DEPENDENCY_FILE_COUNT
        previous_bytes = MODULE.MAX_DEPENDENCY_AGGREGATE_BYTES
        try:
            MODULE.MAX_DEPENDENCY_FILE_COUNT = 1
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError,
                "dependency file count is outside the accepted bound",
            ):
                MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))
            MODULE.MAX_DEPENDENCY_FILE_COUNT = previous_count
            MODULE.MAX_DEPENDENCY_AGGREGATE_BYTES = 8
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError,
                "dependency aggregate size is outside the accepted bound",
            ):
                MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))
        finally:
            MODULE.MAX_DEPENDENCY_FILE_COUNT = previous_count
            MODULE.MAX_DEPENDENCY_AGGREGATE_BYTES = previous_bytes
        MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))

    def test_excluded_name_directory_symlink_is_rejected_before_omission(self) -> None:
        target = self.repo / "outside-build"
        target.mkdir()
        (target / "hidden.txt").write_text("hidden\n", encoding="utf-8")
        link = self.repo / "windows" / "build"
        try:
            link.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation is unavailable on this host")
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, r"Symlink|reparse point"
        ):
            MODULE.input_state(self.repo, MODULE.platform_native_paths("windows"))
        link.unlink()
        MODULE.input_state(self.repo, MODULE.platform_native_paths("windows"))

    def test_repository_root_pathname_replacement_is_rejected(self) -> None:
        original = self.repo
        scratch = pathlib.Path(
            tempfile.mkdtemp(prefix="dep-freeze-root-swap-", dir=str(original.parent))
        )
        backup = scratch / "repo-original"
        attacker = scratch / "attacker-repo"
        attacker.mkdir()
        (attacker / "lib").mkdir()
        (attacker / "lib" / "main.dart").write_text(
            "attacker payload\n", encoding="utf-8"
        )

        def hook(relative: str) -> None:
            if relative != "." or backup.exists():
                return
            original.rename(backup)
            attacker.rename(original)

        try:
            with self._hook("_POST_DIRECTORY_BIND_HOOK", hook):
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError,
                    r"replaced while a bound descriptor remained readable|identity changed",
                ):
                    MODULE.input_state(self.repo, ("lib",))
        finally:
            current = self.repo
            if backup.exists():
                if current.exists() or current.is_symlink():
                    current.rename(attacker)
                backup.rename(current)
            shutil.rmtree(scratch, ignore_errors=True)
        MODULE.input_state(self.repo, ("lib",))

    def test_external_parent_pathname_replacement_is_rejected(self) -> None:
        nested = self.repo / "outer" / "inner"
        nested.mkdir(parents=True)
        target = nested / "leaf.txt"
        target.write_text("leaf\n", encoding="utf-8")
        backup = self.repo / "inner-original"
        attacker = self.repo / "attacker-inner"
        attacker.mkdir()
        (attacker / "leaf.txt").write_text("attacker\n", encoding="utf-8")

        def hook(relative: str) -> None:
            if relative != "." or backup.exists():
                return
            nested.rename(backup)
            attacker.rename(nested)

        try:
            with self._hook("_POST_DIRECTORY_BIND_HOOK", hook):
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError,
                    r"replaced while a bound descriptor remained readable|identity changed",
                ):
                    MODULE._stable_read_regular_file(
                        target,
                        MODULE._allowed_owners(self.repo),
                        label="dependency input",
                    )
        finally:
            if backup.exists():
                if nested.exists() or nested.is_symlink():
                    nested.rename(attacker)
                backup.rename(nested)

    def test_retained_regular_file_detects_in_place_leaf_write(self) -> None:
        target = self.repo / "lib" / "main.dart"
        owners = MODULE._allowed_owners(self.repo)
        held = MODULE._hold_repo_regular_file(
            self.repo, target, owners, label="Retained input leaf"
        )
        try:
            with target.open("r+b") as handle:
                original = handle.read()
                handle.seek(0)
                handle.write(original)
                handle.flush()
                os.fsync(handle.fileno())
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError,
                "path or ancestor was replaced after final capture",
            ):
                MODULE._rebind_held_regular_file(held)
        finally:
            MODULE._close_held_regular_file(held)

    def test_release_outputs_reject_reserved_transaction_namespaces(self) -> None:
        for relative in (
            ".artifacts/.build-attempt-" + "a" * 64 + "/receipt.json",
            ".artifacts/.freeze-staging-" + "b" * 64 + "/receipt.json",
            ".artifacts/.BUILD-ATTEMPT-" + "c" * 64 + "/receipt.json",
            ".artifacts/.FREEZE-STAGING-" + "d" * 64 + "/receipt.json",
            ".artifacts/\uff0ebuild-attempt-" + "e" * 64 + "/receipt.json",
            ".artifacts/\uff0efreeze-staging-" + "f" * 64 + "/receipt.json",
        ):
            with self.subTest(relative=relative):
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError,
                    "reserved release transaction namespace",
                ):
                    MODULE._require_artifacts_output(
                        self.repo,
                        self.repo / relative,
                        "Reserved output",
                        allow_missing_leaf=True,
                    )

    def test_configured_directory_root_case_fold_collision_is_rejected(self) -> None:
        upper = self.repo / "LIB"
        try:
            upper.mkdir()
        except FileExistsError:
            self.skipTest(
                "Case-distinct directories are unavailable on this filesystem"
            )
        (upper / "other.dart").write_text("other\n", encoding="utf-8")
        if (
            not upper.exists()
            or (self.repo / "lib").resolve() == upper.resolve()
        ):
            self.skipTest(
                "Case-distinct directories are unavailable on this filesystem"
            )
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, r"Case-colliding|case-fold"
        ):
            MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))

    def test_configured_file_root_case_fold_collision_is_rejected(self) -> None:
        original_path = self.repo / "pubspec.yaml"
        original = original_path.read_text(encoding="utf-8")
        upper = self.repo / "PUBSPEC.YAML"
        try:
            upper.write_text("name: collision\n", encoding="utf-8")
        except FileExistsError:
            self.skipTest("Case-distinct files are unavailable on this filesystem")
        try:
            distinct = (
                upper.exists()
                and original_path.exists()
                and not os.path.samefile(upper, original_path)
                and upper.read_text(encoding="utf-8") != original
            )
        except OSError:
            distinct = False
        if not distinct:
            original_path.write_text(original, encoding="utf-8")
            self.skipTest("Case-distinct files are unavailable on this filesystem")
        try:
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, r"Case-colliding|case-fold"
            ):
                MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))
        finally:
            if upper.exists() and not os.path.samefile(upper, original_path):
                upper.unlink()
            original_path.write_text(original, encoding="utf-8")

    def test_nested_fifo_is_rejected_not_omitted(self) -> None:
        fifo = self.repo / "lib" / "nested" / "pipe"
        fifo.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.mkfifo(fifo)
        except (OSError, AttributeError, NotImplementedError):
            self.skipTest("FIFO creation is unavailable on this host")
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, r"regular file or directory"
        ):
            MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))
        fifo.unlink()
        fifo.parent.rmdir()
        MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))

    def test_year_2000_build_receipt_is_stale(self) -> None:
        index, artifact, receipt = self._new_valid_receipt()
        record = json.loads(receipt.read_text(encoding="utf-8"))
        record["begun_utc"] = "2000-01-01T00:00:00Z"
        record["finished_utc"] = "2000-01-01T00:00:01Z"
        self._rewrite_anchored(receipt, record)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, r"stale or future-dated"
        ):
            MODULE.verify_build_receipt(
                self.repo, index, "windows", receipt, artifact,
                self._default_scan_inventory,
            )

    def test_missing_app_source_lock_fails_receipt(self) -> None:
        lock = (
            self.repo
            / ".artifacts"
            / "release-freeze-1.0.14+29"
            / MODULE.APP_SOURCE_LOCK_NAME
        )
        lock.unlink()
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "No immutable APP_SOURCE_LOCK"
        ):
            self._new_valid_receipt()

    def test_substituted_toolchain_custody_receipt_fails(self) -> None:
        index, artifact, receipt = self._new_valid_receipt()
        record = json.loads(receipt.read_text(encoding="utf-8"))
        swapped = dict(record["toolchain_custody"])
        swapped["issuance_id"] = "c" * 32
        record["toolchain_custody"] = swapped
        self._rewrite_anchored(receipt, record)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError,
            "toolchain-custody receipt identity is not bound to the build transaction",
        ):
            MODULE.verify_build_receipt(
                self.repo, index, "windows", receipt, artifact,
                self._default_scan_inventory,
            )

    def test_receipt_extra_bool_and_wrong_type_fields_are_rejected(self) -> None:
        index, artifact, receipt = self._new_valid_receipt()
        original = json.loads(receipt.read_text(encoding="utf-8"))
        extra = dict(original)
        extra["extra"] = True
        self._rewrite_anchored(receipt, extra)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "schema fields are invalid"
        ):
            MODULE.verify_build_receipt(
                self.repo, index, "windows", receipt, artifact,
                self._default_scan_inventory,
            )
        bool_version = dict(original)
        bool_version["schema_version"] = True
        self._rewrite_anchored(receipt, bool_version)
        with self.assertRaises(MODULE.DependencyFreezeError):
            MODULE.verify_build_receipt(
                self.repo, index, "windows", receipt, artifact,
                self._default_scan_inventory,
            )
        wrong_type = dict(original)
        wrong_type["shared_revision"] = 1
        self._rewrite_anchored(receipt, wrong_type)
        with self.assertRaises(MODULE.DependencyFreezeError):
            MODULE.verify_build_receipt(
                self.repo, index, "windows", receipt, artifact,
                self._default_scan_inventory,
            )
        self._rewrite_anchored(receipt, original)
        trust = json.loads(self.trust_path.read_text(encoding="utf-8"))
        extra_trust = dict(trust)
        extra_trust["extra"] = True
        os.chmod(self.trust_path, 0o644)
        self.trust_path.write_text(json.dumps(extra_trust), encoding="utf-8")
        os.chmod(self.trust_path, 0o444)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "schema fields are invalid"
        ):
            MODULE.verify_build_receipt(
                self.repo, index, "windows", receipt, artifact,
                self._default_scan_inventory,
            )
        bool_trust = dict(trust)
        bool_trust["schema_version"] = True
        os.chmod(self.trust_path, 0o644)
        self.trust_path.write_text(json.dumps(bool_trust), encoding="utf-8")
        os.chmod(self.trust_path, 0o444)
        with self.assertRaises(MODULE.DependencyFreezeError):
            MODULE.verify_build_receipt(
                self.repo, index, "windows", receipt, artifact,
                self._default_scan_inventory,
            )
        wrong_trust = dict(trust)
        wrong_trust["authenticated"] = 1
        os.chmod(self.trust_path, 0o644)
        self.trust_path.write_text(json.dumps(wrong_trust), encoding="utf-8")
        os.chmod(self.trust_path, 0o444)
        with self.assertRaises(MODULE.DependencyFreezeError):
            MODULE.verify_build_receipt(
                self.repo, index, "windows", receipt, artifact,
                self._default_scan_inventory,
            )


    def test_app_source_lock_schema_matches_source_freeze_producer(self) -> None:
        self.assertEqual(MODULE.APP_SOURCE_LOCK_KEYS, freeze.LOCK_KEYS)
        self.assertEqual(MODULE.APP_SOURCE_LOCK_CONTRACT, freeze.LOCK_CONTRACT)
        self.assertEqual(
            freeze.EXTERNAL_TRUST_KEYS,
            {
                "schema_version",
                "contract",
                "release",
                "created_utc",
                "issuance_id",
                "authenticated",
                "issuer",
                "app_source_lock_sha256",
                "scope_freeze_sha256",
                "website_stage_sha256",
                "controller_sha256",
                "test_sha256",
                "manifest_sha256",
            },
        )

    def test_issuance_binds_copied_controller_test_and_manifest(self) -> None:
        fields = self._copied_control_trust_fields()
        record = json.loads(self.trust_path.read_text(encoding="utf-8"))
        self.assertEqual(record["controller_sha256"], fields["controller_sha256"])
        self.assertEqual(record["test_sha256"], fields["test_sha256"])
        self.assertEqual(record["manifest_sha256"], fields["manifest_sha256"])
        MODULE._load_current_authenticated_custody(self.repo)
        if sys.version_info[:2] != (3, 14):
            self.skipTest(
                "copied source-freeze toolchain closure requires the reviewed Python 3.14 runtime"
            )
        freeze._require_executing_toolchain_closure(
            freeze._bind_external_issuance(self.repo)
        )

    def test_scope_freeze_content_is_validated_against_lock_and_issuance(self) -> None:
        original_scope = json.loads(self.scope_path.read_text(encoding="utf-8"))
        original_lock = json.loads(self.lock_path.read_text(encoding="utf-8"))
        try:
            changed_scope = dict(original_scope)
            changed_scope["release"] = "1.0.14+30"
            self._write_json(
                f"{self.scope_path.parent.relative_to(self.repo)}/{self.scope_path.name}",
                changed_scope,
            )
            changed_lock = dict(original_lock)
            changed_lock["scope_freeze_sha256"] = self._file_sha256(
                f"{self.scope_path.parent.relative_to(self.repo)}/{self.scope_path.name}"
            )
            self._write_json(
                f"{self.lock_path.parent.relative_to(self.repo)}/{self.lock_path.name}",
                changed_lock,
            )
            self._issue_current_trust()
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, "release"
            ):
                MODULE._load_current_authenticated_custody(self.repo)
        finally:
            self._write_json(
                f"{self.scope_path.parent.relative_to(self.repo)}/{self.scope_path.name}",
                original_scope,
            )
            self._write_json(
                f"{self.lock_path.parent.relative_to(self.repo)}/{self.lock_path.name}",
                original_lock,
            )
            self._issue_current_trust()

    def test_omitted_source_freeze_control_digests_fail(self) -> None:
        original = json.loads(self.trust_path.read_text(encoding="utf-8"))
        for key in ("controller_sha256", "test_sha256", "manifest_sha256"):
            with self.subTest(key=key):
                record = dict(original)
                del record[key]
                self._rewrite_trust(record)
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError,
                    f"missing pin: source-freeze pin record lacks {key};",
                ):
                    MODULE._load_current_authenticated_custody(self.repo)
        self._rewrite_trust(original)
        MODULE._load_current_authenticated_custody(self.repo)

    def test_substituted_source_freeze_control_digests_fail(self) -> None:
        original = json.loads(self.trust_path.read_text(encoding="utf-8"))
        expected = self._copied_control_trust_fields()
        messages = {
            "controller_sha256": "producer identity",
            "test_sha256": "test identity",
            "manifest_sha256": "toolchain manifest/controller/test closure",
        }
        for key, message in messages.items():
            with self.subTest(key=key):
                self.assertEqual(original[key], expected[key])
                record = dict(original)
                record[key] = "0" * 64
                self._rewrite_trust(record)
                with self.assertRaisesRegex(freeze.SourceFreezeError, message):
                    freeze._require_executing_toolchain_closure(
                        freeze._bind_external_issuance(self.repo)
                    )
        self._rewrite_trust(original)
        MODULE._load_current_authenticated_custody(self.repo)

    def test_same_uid_committed_pin_record_is_accepted(self) -> None:
        MODULE._SOURCE_FREEZE_SELF_AUTHORED_OVERRIDE = None
        record = json.loads(self.trust_path.read_text(encoding="utf-8"))
        self.assertTrue(record["authenticated"] is True)
        self.assertEqual(self.trust_path.stat().st_uid, os.getuid())
        for mode in (0o444, 0o644):
            os.chmod(self.trust_path, mode)
            MODULE._load_current_authenticated_custody(self.repo)
        os.chmod(self.trust_path, 0o664)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "group/world-writable source-freeze pin record"
        ):
            MODULE._load_current_authenticated_custody(self.repo)
        os.chmod(self.trust_path, 0o444)
        MODULE._SOURCE_FREEZE_SELF_AUTHORED_OVERRIDE = False
        MODULE._load_current_authenticated_custody(self.repo)

    def test_excluded_directory_fifo_symlink_socket_hardlink_and_sparse_fail(self) -> None:
        gradle = self.repo / "android" / ".gradle"
        gradle.mkdir(parents=True, exist_ok=True)
        fifo = gradle / "pipe"
        try:
            os.mkfifo(fifo)
        except (OSError, AttributeError, NotImplementedError):
            self.skipTest("FIFO creation is unavailable on this host")
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "regular file or directory"
        ):
            MODULE.input_state(self.repo, MODULE.platform_native_paths("android"))
        fifo.unlink()
        sneaky = self.repo / "ios" / "Pods" / "sneaky"
        sneaky.parent.mkdir(parents=True, exist_ok=True)
        sneaky.symlink_to("cache.bin")
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, r"Symlink|reparse point"
        ):
            MODULE.input_state(self.repo, MODULE.platform_native_paths("ios"))
        sneaky.unlink()
        cache = gradle / "cache.bin"
        cache.write_bytes(b"gradle-cache")
        outside = self.repo / "hardlink-cache.bin"
        os.link(cache, outside)
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "link count 1"):
            MODULE.input_state(self.repo, MODULE.platform_native_paths("android"))
        outside.unlink()
        sock_path = gradle / "sock"
        bound = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            bound.bind(str(sock_path))
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, "regular file or directory"
            ):
                MODULE.input_state(self.repo, MODULE.platform_native_paths("android"))
        except OSError:
            self.skipTest("UNIX socket bind is unavailable on this host")
        finally:
            bound.close()
            if sock_path.exists():
                sock_path.unlink()
        sparse = gradle / "sparse.bin"
        fd = os.open(sparse, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o644)
        try:
            os.ftruncate(fd, MODULE.MAX_DEPENDENCY_FILE_BYTES + 1)
        finally:
            os.close(fd)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "outside the accepted bound"
        ):
            MODULE.input_state(self.repo, MODULE.platform_native_paths("android"))
        sparse.unlink()
        MODULE.input_state(self.repo, MODULE.platform_native_paths("android"))

    def test_nfkc_collision_is_rejected(self) -> None:
        info = os.lstat(self.repo / "lib" / "main.dart")
        identity = MODULE._file_identity(info)
        selected: dict[str, tuple[str, tuple[int, ...]]] = {}
        MODULE._add_selected(
            selected, "lib/caf\u00e9.dart", identity, size=4, aggregate_bytes=0
        )
        self.assertEqual(
            MODULE._fold_key("lib/caf\u00e9.dart"),
            MODULE._fold_key("lib/cafe\u0301.dart"),
        )
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, r"Case-colliding|case-fold"
        ):
            MODULE._add_selected(
                selected, "lib/cafe\u0301.dart", identity, size=4, aggregate_bytes=4
            )
        MODULE.input_state(self.repo, MODULE.shared_roots(self.repo))

    @contextlib.contextmanager
    def case_sensitive_repo_copy(self):
        staging = pathlib.Path(tempfile.mkdtemp(prefix="wins-dep-freeze-cs-"))
        image = staging / "cs.sparseimage"
        mount = staging / "mnt"
        mount.mkdir()
        attached = False
        try:
            try:
                subprocess.run(
                    [
                        "hdiutil",
                        "create",
                        "-size",
                        "64m",
                        "-fs",
                        "Case-sensitive APFS",
                        "-volname",
                        "WINSDFCS",
                        "-type",
                        "SPARSE",
                        "-ov",
                        str(image),
                    ],
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    ["hdiutil", "attach", str(image), "-mountpoint", str(mount)],
                    check=True,
                    capture_output=True,
                )
            except (FileNotFoundError, subprocess.CalledProcessError) as exc:
                self.skipTest(
                    "case-sensitive APFS fixture is unavailable on this host"
                )
            attached = True
            dest = mount / "repo"
            shutil.copytree(self.repo, dest, symlinks=True)
            yield dest
        finally:
            if attached:
                subprocess.run(
                    ["hdiutil", "detach", str(mount), "-force"],
                    check=False,
                    capture_output=True,
                )
            shutil.rmtree(staging, ignore_errors=True)

    def test_nfkc_collision_on_case_sensitive_fixture(self) -> None:
        with self.case_sensitive_repo_copy() as repo:
            ligature = repo / "lib" / "\ufb01.dart"
            plain = repo / "lib" / "fi.dart"
            ligature.write_text("ligature\n", encoding="utf-8")
            plain.write_text("plain\n", encoding="utf-8")
            self.assertTrue(ligature.exists())
            self.assertTrue(plain.exists())
            self.assertNotEqual(ligature.stat().st_ino, plain.stat().st_ino)
            self.assertEqual(
                MODULE._fold_key(ligature.name), MODULE._fold_key(plain.name)
            )
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, r"Case-colliding|case-fold"
            ):
                MODULE.input_state(repo, MODULE.shared_roots(repo))

    def test_lib_LIB_collision_on_case_sensitive_fixture(self) -> None:
        with self.case_sensitive_repo_copy() as repo:
            lib = repo / "lib"
            colliding = repo / "LIB"
            self.assertTrue(lib.is_dir())
            colliding.mkdir()
            (colliding / "evil.dart").write_text("evil\n", encoding="utf-8")
            self.assertNotEqual(lib.stat().st_ino, colliding.stat().st_ino)
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, r"Case-colliding|case-fold"
            ):
                MODULE.input_state(repo, MODULE.shared_roots(repo))

    def test_case_sensitive_apfs_suite_preserves_descriptor_safe_parent_handling(self) -> None:
        with self.case_sensitive_repo_copy() as repo:
            MODULE.input_state(repo, MODULE.shared_roots(repo))
            fifo = repo / "android" / ".gradle" / "pipe"
            fifo.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.mkfifo(fifo)
            except (OSError, AttributeError, NotImplementedError):
                self.skipTest("FIFO creation is unavailable on this host")
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, "regular file or directory"
            ):
                MODULE.input_state(repo, MODULE.platform_native_paths("android"))
            fifo.unlink()
            MODULE.input_state(repo, MODULE.platform_native_paths("android"))

    def test_receipt_directory_rebind_after_final_capture_fails(self) -> None:
        index, artifact, receipt = self._new_valid_receipt()
        freeze_dir = self.repo / ".artifacts" / "release-freeze-1.0.14+29"
        backup = freeze_dir.with_name(freeze_dir.name + "-original")
        attacker = freeze_dir.with_name(freeze_dir.name + "-attacker")

        def hook() -> None:
            if backup.exists():
                return
            shutil.copytree(freeze_dir, attacker, symlinks=True)
            freeze_dir.rename(backup)
            attacker.rename(freeze_dir)

        try:
            with self._hook("_POST_FINAL_CAPTURE_HOOK", hook):
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError,
                    r"replaced while a bound descriptor remained readable|identity changed",
                ):
                    MODULE.verify_build_receipt(
                        self.repo, index, "windows", receipt, artifact,
                        self._default_scan_inventory,
                    )
        finally:
            current = self.repo / ".artifacts" / "release-freeze-1.0.14+29"
            if backup.exists():
                if current.exists() or current.is_symlink():
                    shutil.rmtree(current)
                backup.rename(freeze_dir)
            if attacker.exists():
                shutil.rmtree(attacker)
        MODULE.verify_build_receipt(self.repo, index, "windows", receipt, artifact, self._default_scan_inventory)

    def test_transient_receipt_parent_swap_and_restore_is_detected(self) -> None:
        index, artifact, receipt = self._new_valid_receipt()
        freeze_dir = self.repo / ".artifacts" / "release-freeze-1.0.14+29"
        backup = freeze_dir.with_name(freeze_dir.name + "-held-original")
        attacker = freeze_dir.with_name(freeze_dir.name + "-transient-attacker")

        def hook() -> None:
            shutil.copytree(freeze_dir, attacker, symlinks=True)
            freeze_dir.rename(backup)
            attacker.rename(freeze_dir)
            freeze_dir.rename(attacker)
            backup.rename(freeze_dir)

        try:
            with self._hook("_POST_FINAL_CAPTURE_HOOK", hook):
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError,
                    r"path or ancestor was replaced after final capture|"
                    r"replaced while a bound descriptor remained readable",
                ):
                    MODULE.verify_build_receipt(
                        self.repo, index, "windows", receipt, artifact,
                        self._default_scan_inventory,
                    )
        finally:
            if backup.exists():
                if freeze_dir.exists() or freeze_dir.is_symlink():
                    shutil.rmtree(freeze_dir)
                backup.rename(freeze_dir)
            if attacker.exists():
                shutil.rmtree(attacker)
        MODULE.verify_build_receipt(self.repo, index, "windows", receipt, artifact, self._default_scan_inventory)

    def test_artifact_leaf_rebind_after_final_capture_fails(self) -> None:
        index, artifact, receipt = self._new_valid_receipt()
        backup = artifact.with_name(artifact.name + ".original")
        attacker = artifact.with_name(artifact.name + ".attacker")
        shutil.copy2(artifact, attacker)

        def hook() -> None:
            if backup.exists():
                return
            artifact.rename(backup)
            attacker.rename(artifact)

        try:
            with self._hook("_POST_FINAL_CAPTURE_HOOK", hook):
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError,
                    "path or ancestor was replaced after final capture",
                ):
                    MODULE.verify_build_receipt(
                        self.repo, index, "windows", receipt, artifact,
                        self._default_scan_inventory,
                    )
        finally:
            if backup.exists():
                if artifact.exists() or artifact.is_symlink():
                    artifact.unlink()
                backup.rename(artifact)
            if attacker.exists() or attacker.is_symlink():
                attacker.unlink()
        MODULE.verify_build_receipt(self.repo, index, "windows", receipt, artifact, self._default_scan_inventory)

    def test_artifact_ancestor_rebind_after_final_capture_fails(self) -> None:
        index, artifact, receipt = self._new_valid_receipt()
        parent = artifact.parent
        backup = parent.with_name(parent.name + "-original")
        attacker = parent.with_name(parent.name + "-attacker")

        def hook() -> None:
            if backup.exists():
                return
            shutil.copytree(parent, attacker, copy_function=shutil.copy2)
            parent.rename(backup)
            attacker.rename(parent)

        try:
            with self._hook("_POST_FINAL_CAPTURE_HOOK", hook):
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError,
                    "path or ancestor was replaced after final capture",
                ):
                    MODULE.verify_build_receipt(
                        self.repo, index, "windows", receipt, artifact,
                        self._default_scan_inventory,
                    )
        finally:
            if backup.exists():
                if parent.exists() or parent.is_symlink():
                    shutil.rmtree(parent)
                backup.rename(parent)
            if attacker.exists():
                shutil.rmtree(attacker)
        MODULE.verify_build_receipt(self.repo, index, "windows", receipt, artifact, self._default_scan_inventory)

    def test_finish_build_retains_artifact_through_final_hook(self) -> None:
        artifact = self.repo / "build/windows-installer/WinsVPN-Setup.exe"
        backup = artifact.with_name(artifact.name + ".original")
        attacker = artifact.with_name(artifact.name + ".attacker")
        receipt = self.output / "WINDOWS_BUILD_RECEIPT.json"

        def hook() -> None:
            if backup.exists():
                return
            shutil.copy2(artifact, attacker)
            artifact.rename(backup)
            attacker.rename(artifact)

        try:
            with self._hook("_POST_FINAL_CAPTURE_HOOK", hook):
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError,
                    "path or ancestor was replaced after final capture|"
                    "hardlink custody changed|Refusing to roll back changed",
                ):
                    self._new_valid_receipt()
        finally:
            if backup.exists():
                if artifact.exists() or artifact.is_symlink():
                    artifact.unlink()
                backup.rename(artifact)
            if attacker.exists() or attacker.is_symlink():
                attacker.unlink()
        self.assertFalse(receipt.exists())

    def test_finish_build_retains_platform_manifest_leaf_through_return(self) -> None:
        manifest = self.platform_paths["windows"]
        backup = manifest.with_name(manifest.name + ".original")
        attacker = manifest.with_name(manifest.name + ".attacker")
        shutil.copy2(manifest, attacker)

        def hook() -> None:
            if backup.exists():
                return
            manifest.rename(backup)
            attacker.rename(manifest)
            manifest.rename(attacker)
            backup.rename(manifest)

        try:
            with self._hook("_POST_FINAL_CAPTURE_HOOK", hook):
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError,
                    "path or ancestor was replaced after final capture",
                ):
                    self._new_valid_receipt()
        finally:
            if backup.exists():
                if manifest.exists() or manifest.is_symlink():
                    manifest.unlink()
                backup.rename(manifest)
            if attacker.exists() or attacker.is_symlink():
                attacker.unlink()

    def test_direct_verify_retains_platform_manifest_leaf_through_return(self) -> None:
        manifest = self.platform_paths["windows"]
        backup = manifest.with_name(manifest.name + ".direct-original")
        attacker = manifest.with_name(manifest.name + ".direct-attacker")
        shutil.copy2(manifest, attacker)

        def hook() -> None:
            if backup.exists():
                return
            manifest.rename(backup)
            attacker.rename(manifest)
            manifest.rename(attacker)
            backup.rename(manifest)

        try:
            with self._hook("_POST_INPUT_CAPTURE_HOOK", hook):
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError,
                    "path or ancestor was replaced after final capture",
                ):
                    MODULE.verify_manifest(self.repo, manifest)
        finally:
            if backup.exists():
                if manifest.exists() or manifest.is_symlink():
                    manifest.unlink()
                backup.rename(manifest)
            if attacker.exists() or attacker.is_symlink():
                attacker.unlink()

    # Remote-attested Windows and Linux receipts (round R11a).
    _LINUX_REMOTE_PRODUCER = "tools/build_linux_release.sh"
    _FLUTTER_REVISION = "5fc346839b5d0eef006ed8404392afb4dfae428d"

    def _fixture_source_listing(
        self, skip: tuple[str, ...] = (), corrupt: tuple[str, ...] = ()
    ) -> tuple[str, int, list[tuple[str, str, str]]]:
        entries = []
        for path in self.repo.rglob("*"):
            relative = path.relative_to(self.repo).as_posix()
            if relative.split("/")[0] == ".artifacts" or relative in skip:
                continue
            if path.is_symlink():
                payload = os.fsencode(os.readlink(path))
                mode = "120000"
            elif path.is_file():
                payload = path.read_bytes()
                mode = "100755" if os.access(path, os.X_OK) else "100644"
            else:
                continue
            if relative in corrupt:
                payload += b"drift"
            entries.append((relative, mode, MODULE._git_blob_oid(payload, "sha1")))
        entries.sort(key=lambda item: item[0].encode("utf-8"))
        return "sha1", 1760000000, entries

    @staticmethod
    def _linux_tarball(
        target: str = "linux-x64",
        machine: int = 62,
        *,
        drop_from_manifest: str | None = None,
        symlink: bool = False,
        owner: int = 0,
        unsorted: bool = False,
        manifest_mode: int = 0o644,
        executable_mode: int = 0o755,
        gzip_mtime: int = 0,
    ) -> bytes:
        import gzip
        import io
        import struct
        import tarfile

        def elf(value: int) -> bytes:
            head = bytearray(64)
            head[:4] = b"\x7fELF"
            head[4] = 2
            head[5] = 1
            struct.pack_into("<H", head, 18, value)
            return bytes(head) + bytes(4096)

        files = {
            "amneziawg-go": (elf(machine), executable_mode),
            "awg": (b"#!/bin/sh\nexit 0\n", 0o755),
            "awg-quick": (b"#!/bin/sh\nexit 0\n", 0o755),
            "install.sh": (b"#!/bin/sh\nexit 0\n", 0o755),
            "lib/libapp.so": (elf(machine), 0o644),
            "lib/libflutter_linux_gtk.so": (elf(machine), 0o644),
            "winn-datapath": (elf(machine), 0o755),
            "winn3-descriptor-ring-attestation.json": (b"{}\n", 0o644),
            "winn3-dual-auth-release-attestation.json": (b"{}\n", 0o644),
            "wins_vpn": (elf(machine), 0o755),
            "xray": (elf(machine), 0o755),
        }
        manifest = "".join(
            f"{hashlib.sha256(data).hexdigest()}  {name}\n"
            for name, (data, _mode) in sorted(files.items())
            if name != drop_from_manifest
        )
        files["release-manifest.sha256"] = (manifest.encode("ascii"), manifest_mode)
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as archive:
            names = ["./", "./lib/"] + [f"./{name}" for name in files]
            if symlink:
                names.append("./link")
            ordered = sorted(names)
            if unsorted:
                ordered = list(reversed(ordered))
            for name in ordered:
                info = tarfile.TarInfo(name)
                info.uid = info.gid = owner if name == "./wins_vpn" else 0
                info.mtime = 1760000000
                if name.endswith("/"):
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    archive.addfile(info)
                elif name == "./link":
                    info.type = tarfile.SYMTYPE
                    info.linkname = "wins_vpn"
                    archive.addfile(info)
                else:
                    data, mode = files[name[2:]]
                    info.size = len(data)
                    info.mode = mode
                    archive.addfile(info, io.BytesIO(data))
        return gzip.compress(raw.getvalue(), mtime=gzip_mtime)

    def test_linux_release_tarball_validator_accepts_only_the_reviewed_layout(self) -> None:
        name = "wins-vpn-linux-x64.tar.gz"
        MODULE._validate_release_artifact_bytes(
            "linux", "linux-x64", name, self._linux_tarball()
        )
        MODULE._validate_release_artifact_bytes(
            "linux", "linux-arm64", "wins-vpn-linux-arm64.tar.gz",
            self._linux_tarball("linux-arm64", 183),
        )
        refusals = {
            "wrong name": ("linux-x64", "wins-vpn-linux-arm64.tar.gz", self._linux_tarball()),
            "wrong machine": ("linux-arm64", "wins-vpn-linux-arm64.tar.gz", self._linux_tarball()),
            "manifest not exhaustive": ("linux-x64", name, self._linux_tarball(drop_from_manifest="xray")),
            "symbolic link": ("linux-x64", name, self._linux_tarball(symlink=True)),
            "not root owned": ("linux-x64", name, self._linux_tarball(owner=1000)),
            "unsorted": ("linux-x64", name, self._linux_tarball(unsorted=True)),
            "executable mode": ("linux-x64", name, self._linux_tarball(executable_mode=0o644)),
            "gzip time": ("linux-x64", name, self._linux_tarball(gzip_mtime=1760000000)),
            "not gzip": ("linux-x64", name, b"PK\x03\x04" + bytes(64)),
        }
        for label, (target, artifact_name, payload) in refusals.items():
            with self.subTest(label=label):
                with self.assertRaises(MODULE.DependencyFreezeError):
                    MODULE._validate_release_artifact_bytes(
                        "linux", target, artifact_name, payload
                    )

    _WINDOWS_REMOTE_PRODUCER = "installer/windows/build_installer.ps1"
    _WINDOWS_REMOTE_OVERRIDES = {
        "platform": "windows",
        "remote_host": "windows",
        "toolchain": {
            "name": "Flutter",
            "version": "3.47.6",
            "revision": "5fc346839b5d0eef006ed8404392afb4dfae428d",
            "target": "windows-x64-inno-unsigned",
        },
        "remote_system": {"system": "Windows", "machine": "AMD64"},
        "secret_scan": "deferred-to-release-host",
    }

    def _remote_windows_begin(
        self, index: pathlib.Path, run: str = "w1"
    ) -> tuple[pathlib.Path, pathlib.Path, dict[str, object]]:
        directory = self.repo / ".artifacts" / "remote-builds" / run
        directory.mkdir(parents=True)
        begin = directory / "BUILD_BEGIN.json"
        archive = directory / "SOURCE.tar"
        with mock.patch.object(MODULE, "_native_process_host", return_value="darwin"), mock.patch.object(
            MODULE, "_remote_source_listing", return_value=self._fixture_source_listing()
        ):
            remote = MODULE.prepare_remote_attested_begin(
                self.repo, index, "windows", "windows", archive
            )
            record = MODULE.begin_build_receipt(self.repo, index, "windows", begin, remote)
        return begin, archive, record

    def _remote_windows_run(
        self,
        begin: pathlib.Path,
        artifact: pathlib.Path,
        overrides: dict[str, object] | None = None,
    ) -> pathlib.Path:
        merged = dict(self._WINDOWS_REMOTE_OVERRIDES)
        merged.update(overrides or {})
        for key in [key for key, value in merged.items() if value is None]:
            del merged[key]
        path = self._remote_run_record(begin, artifact, merged)
        document = json.loads(path.read_text(encoding="utf-8"))
        for key, value in (overrides or {}).items():
            if value is None:
                document.pop(key, None)
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    _SCANNER_STUB = """\
import hashlib, json, os, sys
inventory = os.environ["WINS_RELEASE_SECRET_INVENTORY"]
raw = open(inventory, "rb").read()
control = json.loads(raw)
argv = sys.argv[1:]
target = argv[argv.index("--target") + 1]
artifact = argv[argv.index("--artifact") + 1]
mode = control["mode"]
if control.get("probe"):
    json.dump(
        {"argv": sys.argv, "cwd": os.getcwd(), "env": sorted(os.environ), "file": __file__,
         "name": __name__, "stdin_tty": sys.stdin.isatty(),
         "modules": sorted(name for name in sys.modules if name.startswith("release_"))},
        open(control["probe"], "w"),
    )
if mode == "mutate":
    open(artifact, "ab").write(b"x")
if mode == "crash":
    sys.stderr.write("inventory is unreadable: " + inventory + "\\n")
    sys.exit(2)
digest = hashlib.sha256(open(artifact, "rb").read()).hexdigest()
labels, values, matched, verdict = 5, 5, "", "PASS"
shown_target, shown_digest, shown_inventory = target, digest, hashlib.sha256(raw).hexdigest()
if mode == "hit" or (mode == "content" and b"SYNTHETIC_ALPHA_SECRET" in open(artifact, "rb").read()):
    verdict, matched = "FAIL", "SYNTHETIC_ALPHA"
if mode == "wrong_target":
    shown_target = "windows-arm64-installer"
if mode == "wrong_artifact":
    shown_digest = "0" * 64
if mode == "empty":
    labels = values = 0
if mode == "no_inventory_digest":
    shown_inventory = ""
if mode == "garbage":
    print("ok")
    sys.exit(0)
print(f"RELEASE ARTIFACT PRIVACY: {verdict}")
print("revision=fixture-revision")
print("labels=A,B,C,D,E")
print(f"label_count={labels}")
print(f"unique_value_count={values}")
print(f"inventory_sha256={shown_inventory}")
print(f"target={shown_target}")
print(f"artifact={shown_digest}")
print(f"matched_labels={matched}")
if mode == "extra_line":
    print("RELEASE SUPPLEMENTAL EPHEMERAL SECRET SCAN: PASS (0 embedded files, 0 fields)")
sys.exit(1 if verdict == "FAIL" else 0)
"""

    def _install_scanner_stub(self) -> None:
        """Pin the fixture closure (written by setUp) in place of the real one."""

        closure = {
            relative: hashlib.sha256((self.repo / relative).read_bytes()).hexdigest()
            for relative in MODULE.RELEASE_HOST_SECRET_SCANNER_CLOSURE
        }
        patcher = mock.patch.object(MODULE, "RELEASE_HOST_SECRET_SCANNER_CLOSURE", closure)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _scan_inventory(self, mode: str = "pass", probe: bool = False) -> str:
        """A control file standing in for the inventory, outside the repository."""

        directory = pathlib.Path(tempfile.mkdtemp(prefix="wins-scan-inventory-")).resolve()
        self.addCleanup(shutil.rmtree, directory, True)
        self.scan_probe = directory / "probe.json"
        path = directory / "inventory.json"
        document: dict[str, object] = {"mode": mode}
        if probe:
            document["probe"] = str(self.scan_probe)
        path.write_text(json.dumps(document), encoding="utf-8")
        return str(path)

    def _remote_windows_finish(
        self,
        index: pathlib.Path,
        begin: pathlib.Path,
        artifact: pathlib.Path,
        run_record: pathlib.Path,
        inventory: str | None | bool = True,
        target: str = "windows-x64-inno-unsigned",
    ) -> pathlib.Path:
        receipt = begin.parent / "BUILD_RECEIPT.json"
        if inventory is True:
            inventory = self._scan_inventory()
        elif inventory is False:
            inventory = None
        with mock.patch.object(MODULE, "_native_process_host", return_value="darwin"):
            MODULE.finish_build_receipt(
                self.repo,
                index,
                "windows",
                begin,
                artifact,
                self._WINDOWS_REMOTE_PRODUCER,
                "Flutter",
                "3.47.6",
                self._FLUTTER_REVISION,
                target,
                receipt,
                "windows",
                run_record,
                inventory,
            )
        return receipt

    def _verify_remote_windows(
        self,
        index: pathlib.Path,
        receipt: pathlib.Path,
        artifact: pathlib.Path,
        inventory: str | None = None,
    ) -> dict[str, object]:
        """verify-receipt for a remote Windows receipt, which runs the scan itself."""

        return MODULE.verify_build_receipt(
            self.repo, index, "windows", receipt, artifact,
            self._scan_inventory() if inventory is None else inventory,
        )

    def test_remote_windows_run_record_must_defer_its_secret_scan_to_the_release_host(self) -> None:
        index = self._create_index()
        for number, (label, overrides, message) in enumerate(
            (
                ("missing", {"secret_scan": None}, "Remote run record schema fields"),
                ("other value", {"secret_scan": "skipped"}, "defer its secret scan"),
                ("empty", {"secret_scan": ""}, "defer its secret scan"),
            )
        ):
            with self.subTest(label=label):
                begin, _archive, _record = self._remote_windows_begin(index, f"ws{number}")
                artifact = begin.parent / "WinsVPN-UNSIGNED-LOCAL-Setup.exe"
                artifact.write_bytes(self._valid_pe_payload())
                run_record = self._remote_windows_run(begin, artifact, overrides)
                with self.assertRaisesRegex(MODULE.DependencyFreezeError, message):
                    self._remote_windows_finish(index, begin, artifact, run_record)
                self.assertFalse((begin.parent / "BUILD_RECEIPT.json").exists())

    def test_remote_windows_receipt_embeds_the_deferred_secret_scan_run_record(self) -> None:
        self._install_scanner_stub()
        index = self._create_index()
        begin, _archive, _record = self._remote_windows_begin(index, "wok")
        artifact = begin.parent / "WinsVPN-UNSIGNED-LOCAL-Setup.exe"
        artifact.write_bytes(self._valid_pe_payload())
        receipt = self._remote_windows_finish(
            index, begin, artifact, self._remote_windows_run(begin, artifact)
        )
        built = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(
            built["remote_attestation"]["run_record"]["record"]["secret_scan"],
            "deferred-to-release-host",
        )
        self.assertTrue(
            self._verify_remote_windows(index, receipt, artifact)["ok"]
        )
        # verify-receipt applies the same run-record checks to the embedded copy.
        built["remote_attestation"]["run_record"]["record"]["secret_scan"] = "skipped"
        self._rewrite_anchored(receipt, built)
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "defer its secret scan"):
            self._verify_remote_windows(index, receipt, artifact)

    def _windows_installer(
        self, run: str, index: pathlib.Path | None = None, name: str = "WinsVPN-UNSIGNED-LOCAL-Setup.exe"
    ) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        index = index or self._create_index()
        begin, _archive, _record = self._remote_windows_begin(index, run)
        artifact = begin.parent / name
        artifact.write_bytes(self._valid_pe_payload())
        return index, begin, artifact

    def test_the_worker_runs_the_scan_and_binds_it_into_the_receipt_and_the_claim(self) -> None:
        self._install_scanner_stub()
        index, begin, artifact = self._windows_installer("wscan")
        inventory = self._scan_inventory(probe=True)
        run_record = self._remote_windows_run(begin, artifact)
        receipt = self._remote_windows_finish(index, begin, artifact, run_record, inventory)
        built = json.loads(receipt.read_text(encoding="utf-8"))
        binding = built["remote_attestation"]["release_host_secret_scan"]
        self.assertEqual(set(binding), {"record", "sha256"})
        scan = binding["record"]
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        self.assertEqual(scan["contract"], MODULE.RELEASE_HOST_SECRET_SCAN_CONTRACT)
        self.assertEqual(scan["target_id"], "windows-x64-installer")
        self.assertEqual(scan["result"], "pass")
        self.assertEqual(scan["matched_labels"], [])
        self.assertEqual(scan["artifact"]["sha256"], digest)
        self.assertEqual(scan["scanner"]["closure"], MODULE.RELEASE_HOST_SECRET_SCANNER_CLOSURE)
        self.assertEqual(
            scan["scanner"]["sha256"],
            MODULE.RELEASE_HOST_SECRET_SCANNER_CLOSURE[MODULE.RELEASE_HOST_SECRET_SCANNER],
        )
        self.assertEqual(
            scan["inventory"]["sha256"], hashlib.sha256(pathlib.Path(inventory).read_bytes()).hexdigest()
        )
        self.assertEqual(binding["sha256"], hashlib.sha256(MODULE._canonical_json(scan)).hexdigest())
        # The authenticated claim carries the same scan, so its digest covers it.
        self.assertEqual(built["build_attempt"]["claim_record"]["release_host_secret_scan"], binding)
        self.assertTrue(
            self._verify_remote_windows(index, receipt, artifact, inventory)["ok"]
        )
        # The exact command, with the inventory by path in the environment only.
        probe = json.loads(self.scan_probe.read_text(encoding="utf-8"))
        self.assertEqual(
            probe["argv"][1:],
            ["--artifacts", "--target", "windows-x64-installer", "--artifact", str(artifact)],
        )
        self.assertNotIn(inventory, " ".join(probe["argv"]))
        self.assertEqual(probe["name"], "__main__")
        self.assertEqual(probe["file"], str(self.repo / MODULE.RELEASE_HOST_SECRET_SCANNER))
        self.assertEqual(probe["cwd"], str(self.repo))
        self.assertEqual(
            set(probe["env"]) - {"LC_CTYPE", "__CF_USER_TEXT_ENCODING"},
            {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "PYTHONDONTWRITEBYTECODE", "WINS_RELEASE_SECRET_INVENTORY"},
        )
        # The scanner's siblings are the pinned closure's modules, nothing else.
        self.assertEqual(
            probe["modules"],
            ["release_obfuscation_contract", "release_secret_inventory", "release_secret_scan_policy"],
        )

    def test_a_remote_windows_finish_without_the_inventory_path_refuses_and_spends_nothing(self) -> None:
        self._install_scanner_stub()
        index, begin, artifact = self._windows_installer("wnone")
        run_record = self._remote_windows_run(begin, artifact)
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "requires the authenticated secret inventory"):
            self._remote_windows_finish(index, begin, artifact, run_record, inventory=False)
        self.assertFalse((begin.parent / "BUILD_RECEIPT.json").exists())
        # The single-use attempt is still unspent: the same begin receipt finishes.
        receipt = self._remote_windows_finish(index, begin, artifact, run_record)
        self.assertTrue(receipt.exists())

    def test_no_caller_written_scan_record_is_accepted_anywhere(self) -> None:
        # D33-01: finish-build used to take --release-host-secret-scan <file> and
        # accept a record naming the artifact digest, the scanner digest and "pass".
        import inspect

        self.assertNotIn("release_host_secret_scan", inspect.signature(MODULE.finish_build_receipt).parameters)
        self.assertNotIn(
            "release_host_secret_scan",
            inspect.signature(MODULE._finish_producer_attested_build).parameters,
        )
        self.assertFalse(hasattr(MODULE, "_require_release_host_secret_scan_file"))
        parser = MODULE._parser()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "finish-build", "--repo", ".", "--index", "i", "--platform", "windows",
                    "--begin", "b", "--artifact", "a", "--producer", "p", "--toolchain-name", "n",
                    "--toolchain-version", "v", "--toolchain-revision", "r", "--target", "t",
                    "--output", "o", "--release-host-secret-scan", "forged.json",
                ]
            )
        # The reproduction: a record in the previous format, naming the artifact digest,
        # the scanner digest, an inventory summary and "pass", written by the caller. It
        # was accepted without any scanner running. Where the record's path used to go
        # now goes the inventory path, so the file is run as an inventory by the
        # scanner and never read as a result.
        self._install_scanner_stub()
        index, begin, artifact = self._windows_installer("wforge")
        run_record = self._remote_windows_run(begin, artifact)
        forged = pathlib.Path(self._scan_inventory()).with_name("forged.json")
        forged.write_text(
            json.dumps(
                {
                    "contract": "winsvpn-release-host-secret-scan-v1",
                    "platform": "windows",
                    "target_id": "windows-x64-installer",
                    "artifact": {
                        "name": artifact.name,
                        "size_bytes": artifact.stat().st_size,
                        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    },
                    "scanner": {
                        "path": MODULE.RELEASE_HOST_SECRET_SCANNER,
                        "sha256": hashlib.sha256(
                            (self.repo / MODULE.RELEASE_HOST_SECRET_SCANNER).read_bytes()
                        ).hexdigest(),
                    },
                    "inventory": {"revision": "forged", "label_count": 1, "unique_value_count": 1},
                    "result": "pass",
                    "matched_labels": [],
                    "scanned_utc": MODULE._utc_now(),
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaises(MODULE.DependencyFreezeError):
            self._remote_windows_finish(index, begin, artifact, run_record, str(forged))
        self.assertFalse((begin.parent / "BUILD_RECEIPT.json").exists())

    def test_every_scan_failure_refuses_before_the_attempt_is_spent(self) -> None:
        self._install_scanner_stub()
        index = self._create_index()
        for number, (mode, message) in enumerate(
            (
                ("hit", "refused the installer"),
                ("crash", "refused the installer"),
                ("garbage", "refused the installer"),
                ("extra_line", "refused the installer"),
                ("no_inventory_digest", "refused the installer"),
                ("wrong_target", "did not cover this installer and target"),
                ("wrong_artifact", "did not cover this installer and target"),
                ("empty", "did not cover this installer and target"),
                ("mutate", "did not cover this installer and target"),
            )
        ):
            with self.subTest(mode=mode):
                index, begin, artifact = self._windows_installer(f"wfail{number}", index)
                run_record = self._remote_windows_run(begin, artifact)
                inventory = self._scan_inventory(mode)
                with self.assertRaisesRegex(MODULE.DependencyFreezeError, message) as raised:
                    self._remote_windows_finish(index, begin, artifact, run_record, inventory)
                self.assertNotIn(inventory, str(raised.exception))
                self.assertFalse((begin.parent / "BUILD_RECEIPT.json").exists())

    def test_a_partner_center_installer_is_scanned_under_its_own_target(self) -> None:
        # D33-03: the target followed the architecture only, so a Partner Center
        # installer was scanned (and its correct record refused) as a website installer.
        self._install_scanner_stub()
        index = self._create_index()
        for number, (name, target, scanned) in enumerate(
            (
                ("WinsVPN-UNSIGNED-LOCAL-PartnerCenter.exe", "windows-x64-inno-unsigned", "windows-x64-partner-center"),
                ("WinsVPN-UNSIGNED-LOCAL-Setup.exe", "windows-x64-inno-unsigned", "windows-x64-installer"),
            )
        ):
            with self.subTest(name=name):
                index, begin, artifact = self._windows_installer(f"wpc{number}", index, name)
                inventory = self._scan_inventory(probe=True)
                receipt = self._remote_windows_finish(
                    index, begin, artifact, self._remote_windows_run(begin, artifact), inventory, target
                )
                built = json.loads(receipt.read_text(encoding="utf-8"))
                self.assertEqual(built["remote_attestation"]["release_host_secret_scan"]["record"]["target_id"], scanned)
                probe = json.loads(self.scan_probe.read_text(encoding="utf-8"))
                self.assertEqual(probe["argv"][probe["argv"].index("--target") + 1], scanned)
                self.assertTrue(
                    self._verify_remote_windows(index, receipt, artifact, inventory)["ok"]
                )

    def test_an_installer_named_for_the_other_architecture_is_never_scanned(self) -> None:
        self._install_scanner_stub()
        index = self._create_index()
        for number, name in enumerate(
            ("WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe", "WinsVPN-UNSIGNED-LOCAL-PartnerCenter-arm64.exe", "WinsVPN.exe")
        ):
            with self.subTest(name=name):
                index, begin, artifact = self._windows_installer(f"warch{number}", index, name)
                inventory = self._scan_inventory(probe=True)
                with self.assertRaises(MODULE.DependencyFreezeError):
                    self._remote_windows_finish(
                        index, begin, artifact, self._remote_windows_run(begin, artifact), inventory
                    )
                self.assertFalse(self.scan_probe.exists(), "the scanner must not run for a mismatched name")
                self.assertFalse((begin.parent / "BUILD_RECEIPT.json").exists())

    def test_a_scanner_closure_that_is_not_the_pinned_one_is_never_run(self) -> None:
        self._install_scanner_stub()
        index, begin, artifact = self._windows_installer("wdrift")
        run_record = self._remote_windows_run(begin, artifact)
        # Any member of the closure, not only the scanner itself.
        self._write("tools/release_secret_inventory.py", "# a different inventory loader\n")
        inventory = self._scan_inventory(probe=True)
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "not the frozen one"):
            self._remote_windows_finish(index, begin, artifact, run_record, inventory)
        self.assertFalse(self.scan_probe.exists(), "no scanner byte may run when the closure drifted")
        self.assertFalse((begin.parent / "BUILD_RECEIPT.json").exists())

    def test_the_inventory_path_must_be_absolute_and_normalized(self) -> None:
        self._install_scanner_stub()
        index = self._create_index()
        for number, bad in enumerate(
            ("inventory.json", "/tmp/../inventory.json", "/tmp//inventory.json", "/tmp/inv\0.json", "")
        ):
            with self.subTest(path=bad):
                index, begin, artifact = self._windows_installer(f"wpath{number}", index)
                run_record = self._remote_windows_run(begin, artifact)
                with self.assertRaises(MODULE.DependencyFreezeError):
                    self._remote_windows_finish(index, begin, artifact, run_record, bad or None)
                self.assertFalse((begin.parent / "BUILD_RECEIPT.json").exists())

    def test_the_scan_target_follows_the_canonical_installer_name_and_architecture(self) -> None:
        x64 = {"target": "windows-x64-inno-unsigned"}
        arm64 = {"target": "windows-arm64-inno-unsigned"}
        expected = {
            "WinsVPN-Setup.exe": ("windows-x64-installer", x64),
            "WinsVPN-UNSIGNED-LOCAL-Setup.exe": ("windows-x64-installer", x64),
            "WinsVPN-PartnerCenter.exe": ("windows-x64-partner-center", x64),
            "WinsVPN-UNSIGNED-LOCAL-PartnerCenter.exe": ("windows-x64-partner-center", x64),
            "WinsVPN-Setup-arm64.exe": ("windows-arm64-installer", arm64),
            "WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe": ("windows-arm64-installer", arm64),
            "WinsVPN-PartnerCenter-arm64.exe": ("windows-arm64-partner-center", arm64),
            "WinsVPN-UNSIGNED-LOCAL-PartnerCenter-arm64.exe": ("windows-arm64-partner-center", arm64),
        }
        self.assertEqual(len(expected), len(MODULE.RELEASE_HOST_SECRET_SCAN_TARGETS))
        for name, (target_id, toolchain) in expected.items():
            with self.subTest(name=name):
                self.assertEqual(MODULE._release_host_secret_scan_target(name, toolchain), target_id)
                opposite = arm64 if toolchain is x64 else x64
                with self.assertRaises(MODULE.DependencyFreezeError):
                    MODULE._release_host_secret_scan_target(name, opposite)
        for name in ("WinsVPN.exe", "setup.exe", "WinsVPN-Setup.exe.bak", "wins-vpn-linux-x64.tar.gz", ""):
            with self.subTest(name=name), self.assertRaises(MODULE.DependencyFreezeError):
                MODULE._release_host_secret_scan_target(name, x64)
        with self.assertRaises(MODULE.DependencyFreezeError):
            MODULE._release_host_secret_scan_target("WinsVPN-Setup.exe", {"target": "linux-x64"})

    def test_the_scan_target_table_equals_the_scanners_own_canonical_filenames(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "scanner_for_target_table", TOOLS_DIR / "validate_release_artifact_privacy.py"
        )
        with mock.patch.object(sys, "path", [str(TOOLS_DIR), *sys.path]), mock.patch.dict(sys.modules):
            scanner = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = scanner
            spec.loader.exec_module(scanner)
        windows = {
            target: names
            for target, names in scanner.TARGET_CANONICAL_FILENAMES.items()
            if target.startswith("windows-")
        }
        derived: dict[str, set[str]] = {}
        for name, target in MODULE.RELEASE_HOST_SECRET_SCAN_TARGETS.items():
            derived.setdefault(target, set()).add(name)
        self.assertEqual(derived, {target: set(names) for target, names in windows.items()})

    def test_the_pinned_scanner_closure_is_the_files_it_names(self) -> None:
        # The class patches the pinned table with its stub closure, so compare the real one.
        self.assertEqual(list(REAL_SCANNER_CLOSURE)[-1], MODULE.RELEASE_HOST_SECRET_SCANNER)
        for relative, expected in REAL_SCANNER_CLOSURE.items():
            with self.subTest(relative=relative):
                self.assertEqual(
                    hashlib.sha256((TOOLS_DIR.parent / relative).read_bytes()).hexdigest(), expected
                )

    def test_verify_receipt_rederives_every_field_of_the_embedded_scan(self) -> None:
        self._install_scanner_stub()
        index = self._create_index()
        other = "0" * 64
        mutations = {
            "contract": lambda s: s["record"].update({"contract": "winsvpn-something-else"}),
            "platform": lambda s: s["record"].update({"platform": "linux"}),
            "target": lambda s: s["record"].update({"target_id": "windows-x64-partner-center"}),
            "artifact digest": lambda s: s["record"]["artifact"].update({"sha256": other}),
            "artifact name": lambda s: s["record"]["artifact"].update({"name": "WinsVPN-Setup.exe"}),
            "scanner digest": lambda s: s["record"]["scanner"].update({"sha256": other}),
            "scanner path": lambda s: s["record"]["scanner"].update({"path": "tools/other.py"}),
            "closure member": lambda s: s["record"]["scanner"]["closure"].update(
                {next(iter(s["record"]["scanner"]["closure"])): other}
            ),
            "closure removed": lambda s: s["record"]["scanner"]["closure"].pop(
                next(iter(s["record"]["scanner"]["closure"]))
            ),
            "inventory digest zeroed": lambda s: s["record"]["inventory"].update({"sha256": other}),
            "inventory digest malformed": lambda s: s["record"]["inventory"].update({"sha256": "x"}),
            "inventory counts": lambda s: s["record"]["inventory"].update({"label_count": 0}),
            "inventory revision": lambda s: s["record"]["inventory"].update({"revision": "other"}),
            "verdict": lambda s: s["record"].update({"result": "fail"}),
            "labels": lambda s: s["record"].update({"matched_labels": ["X"]}),
            "future": lambda s: s["record"].update({"scanned_utc": "2999-01-01T00:00:00Z"}),
            "extra field": lambda s: s["record"].update({"path": "/nowhere"}),
            "binding digest": lambda s: s.update({"sha256": other}),
            "binding extra": lambda s: s.update({"path": "x"}),
        }
        for number, (label, change) in enumerate(mutations.items()):
            with self.subTest(label=label):
                index, begin, artifact = self._windows_installer(f"wver{number}", index)
                receipt = self._remote_windows_finish(
                    index, begin, artifact, self._remote_windows_run(begin, artifact)
                )
                built = json.loads(receipt.read_text(encoding="utf-8"))
                change(built["remote_attestation"]["release_host_secret_scan"])
                self._rewrite_anchored(receipt, built)
                with self.assertRaises(MODULE.DependencyFreezeError):
                    self._verify_remote_windows(index, receipt, artifact)

    def _swap_installer_and_rewrite_receipt(
        self, receipt: pathlib.Path, artifact: pathlib.Path, payload: bytes
    ) -> None:
        """Replace the installer bytes and rewrite every receipt field that mentions them.

        The attempt directory is gone once finish-build returns, so nothing outside the
        receipt holds the old bytes: the scan record, the run record, the claim, the
        commit record, their digests and the anchor are all rewritten to agree."""

        artifact.write_bytes(payload)
        info = artifact.stat()
        digest = hashlib.sha256(payload).hexdigest()
        identity = {"name": artifact.name, "size_bytes": len(payload), "sha256": digest}
        built = json.loads(receipt.read_text(encoding="utf-8"))
        built["artifact"].update(
            size_bytes=len(payload), sha256=digest, modified_time_ns=info.st_mtime_ns
        )
        binding = built["remote_attestation"]
        binding["run_record"]["record"]["artifact"] = dict(identity)
        scan = binding["release_host_secret_scan"]
        scan["record"]["artifact"] = dict(identity)
        scan["sha256"] = hashlib.sha256(MODULE._canonical_json(scan["record"])).hexdigest()
        attempt = built["build_attempt"]
        claim, commit = attempt["claim_record"], attempt["commit_record"]
        claim["release_host_secret_scan"] = scan
        attempt["claim_sha256"] = commit["claim_sha256"] = hashlib.sha256(
            MODULE._canonical_json(claim)
        ).hexdigest()
        commit["artifact"].update(
            size_bytes=len(payload), sha256=digest, modified_time_ns=info.st_mtime_ns,
            device=info.st_dev, inode=info.st_ino,
        )
        attempt["commit_journal_sha256"] = hashlib.sha256(
            MODULE._canonical_json(commit)
        ).hexdigest()
        self._rewrite_anchored(receipt, built)

    def test_a_consistently_rewritten_receipt_with_changed_installer_bytes_is_refused(self) -> None:
        # D33-04. Every field of the receipt can be rewritten to agree with changed
        # installer bytes once the attempt directory is gone, so verification must scan the
        # bytes itself instead of believing the receipt's record of a scan.
        self._install_scanner_stub()
        index, begin, artifact = self._windows_installer("wrewrite")
        inventory = self._scan_inventory("content")
        receipt = self._remote_windows_finish(
            index, begin, artifact, self._remote_windows_run(begin, artifact), inventory
        )
        self.assertTrue(self._verify_remote_windows(index, receipt, artifact, inventory)["ok"])
        original = artifact.read_bytes()
        tampered = bytearray(original)
        tampered[0x300:0x300 + 22] = b"SYNTHETIC_ALPHA_SECRET"
        self._swap_installer_and_rewrite_receipt(receipt, artifact, bytes(tampered))
        # Everything the receipt says is now mutually consistent and structurally valid.
        self.assertTrue(
            json.loads(receipt.read_text(encoding="utf-8"))["artifact"]["sha256"]
            == hashlib.sha256(bytes(tampered)).hexdigest()
        )
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "refused the installer"):
            self._verify_remote_windows(index, receipt, artifact, inventory)

    def _rewrite_remote_windows_receipt_as_witnessed(
        self,
        receipt: pathlib.Path,
        begin: pathlib.Path,
        artifact: pathlib.Path,
        payload: bytes,
        *,
        keep_scan_binding: bool = False,
    ) -> None:
        """Rewrite a remote-attested Windows receipt to claim it was witnessed.

        Producer execution becomes witnessed, every remote binding is removed from the
        receipt, its claim and the begin record on disk, the installer bytes are
        replaced, and every digest and the anchor are rewritten to agree. With
        keep_scan_binding the worker's scan record is kept at the top level (pointed at
        the new bytes), the way a careful forger would present a witnessed receipt."""

        artifact.write_bytes(payload)
        info = artifact.stat()
        digest = hashlib.sha256(payload).hexdigest()
        identity = {"name": artifact.name, "size_bytes": len(payload), "sha256": digest}
        begin_record = json.loads(begin.read_text(encoding="utf-8"))
        del begin_record["remote_attestation"]
        self._rewrite_anchored(begin, begin_record)
        begin_sha = hashlib.sha256(begin.read_bytes()).hexdigest()
        built = json.loads(receipt.read_text(encoding="utf-8"))
        scan = built["remote_attestation"]["release_host_secret_scan"]
        del built["remote_attestation"]
        built["producer"]["execution"] = MODULE.PRODUCER_EXECUTION_WITNESSED
        built["build_begin_receipt"]["sha256"] = begin_sha
        built["artifact"].update(
            size_bytes=len(payload), sha256=digest, modified_time_ns=info.st_mtime_ns
        )
        if keep_scan_binding:
            scan["record"]["artifact"] = dict(identity)
            scan["sha256"] = hashlib.sha256(MODULE._canonical_json(scan["record"])).hexdigest()
            built["release_host_secret_scan"] = scan
        attempt = built["build_attempt"]
        claim, commit = attempt["claim_record"], attempt["commit_record"]
        claim.pop("release_host_secret_scan", None)
        claim["producer"] = built["producer"]
        claim["build_begin_sha256"] = begin_sha
        attempt["claim_sha256"] = commit["claim_sha256"] = hashlib.sha256(
            MODULE._canonical_json(claim)
        ).hexdigest()
        commit["build_begin_sha256"] = begin_sha
        commit["artifact"].update(
            size_bytes=len(payload), sha256=digest, modified_time_ns=info.st_mtime_ns,
            device=info.st_dev, inode=info.st_ino,
        )
        attempt["commit_journal_sha256"] = hashlib.sha256(
            MODULE._canonical_json(commit)
        ).hexdigest()
        self._rewrite_anchored(receipt, built)

    def test_a_receipt_rewritten_as_witnessed_cannot_skip_the_scan(self) -> None:
        # D33-05. Verification used to choose the rescan from the receipt's own
        # producer.execution. Rewritten to witnessed, with the remote bindings removed,
        # a receipt for changed installer bytes was accepted without any scan.
        self._install_scanner_stub()
        index = self._create_index()
        inventory = self._scan_inventory("content")
        tampered_prefix = bytearray(self._valid_pe_payload())
        tampered_prefix[0x300:0x300 + 22] = b"SYNTHETIC_ALPHA_SECRET"
        for number, (label, keep_binding) in enumerate(
            (("bindings removed", False), ("scan binding forged at the top level", True))
        ):
            with self.subTest(label=label):
                index, begin, artifact = self._windows_installer(f"wwit{number}", index)
                receipt = self._remote_windows_finish(
                    index, begin, artifact, self._remote_windows_run(begin, artifact), inventory
                )
                self.assertTrue(self._verify_remote_windows(index, receipt, artifact, inventory)["ok"])
                self._rewrite_remote_windows_receipt_as_witnessed(
                    receipt, begin, artifact, bytes(tampered_prefix), keep_scan_binding=keep_binding
                )
                rewritten = json.loads(receipt.read_text(encoding="utf-8"))
                self.assertEqual(rewritten["producer"]["execution"], "witnessed")
                self.assertNotIn("remote_attestation", rewritten)
                # A downstream consumer verifies a receipt that looks witnessed the way it
                # verifies any witnessed receipt, with no inventory. That used to accept it
                # with no scan at all; now every Windows receipt needs one.
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError,
                    "requires the authenticated secret inventory" if keep_binding else "scan binding",
                ):
                    MODULE.verify_build_receipt(self.repo, index, "windows", receipt, artifact)
                # Whatever the receipt says about how it was made, the scan runs and the
                # receipt that does not carry a worker scan is refused.
                with self.assertRaises(MODULE.DependencyFreezeError) as refused:
                    self._verify_remote_windows(index, receipt, artifact, inventory)
                if keep_binding:
                    self.assertIn("refused the installer", str(refused.exception))
                else:
                    self.assertIn("secret scan", str(refused.exception))

    def test_the_scan_decision_comes_from_the_platform_and_the_held_installer(self) -> None:
        required = MODULE._release_host_secret_scan_required
        for name in ("WinsVPN-Setup.exe", "winsvpn-unsigned-local-setup-arm64.EXE", "anything.exe"):
            self.assertTrue(required("windows", name, b"MZ"), name)
        for platform, name, payload in (
            ("linux", "wins-vpn-linux-x64.tar.gz", b"\x1f\x8b"),
            ("android", "app-release.aab", b"PK"),
            ("macos", "WinsVPN.pkg", b"xar!"),
        ):
            self.assertFalse(required(platform, name, payload), (platform, name))
        # A Windows installer presented as another platform's artifact is refused, by name
        # or by its PE header, instead of being treated as a receipt that needs no scan.
        for platform in ("linux", "android", "wear_os", "extension", "macos", "ios"):
            for name, payload in (("WinsVPN-Setup.exe", b"PK"), ("custom.exe", b"MZ" + bytes(10))):
                with self.subTest(platform=platform, name=name), self.assertRaisesRegex(
                    MODULE.DependencyFreezeError, "Windows installer is accepted only as a Windows receipt"
                ):
                    required(platform, name, payload)

    def test_every_windows_finish_needs_the_inventory_and_scans_in_every_mode(self) -> None:
        # D33-05. finish-build decided the scan from --remote-host and the begin record, so a
        # Windows finish without them was a witnessed receipt with no worker scan at all.
        index = self._create_index()
        begin = self.output / "WITNESSED_SCAN_BEGIN.json"
        receipt = self.output / "WITNESSED_SCAN_RECEIPT.json"
        artifact = self.repo / "build/witnessed-scan/WinsVPN-Setup.exe"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        MODULE.begin_build_receipt(self.repo, index, "windows", begin)
        def finish(inventory):
            return MODULE.finish_build_receipt(
                self.repo, index, "windows", begin, artifact,
                MODULE.PLATFORM_BUILD_PRODUCERS["windows"], "flutter", "3.47.6",
                "5fc346839b5d0eef006ed8404392afb4dfae428d", "windows-x64-inno-unsigned",
                receipt, secret_inventory_path=inventory,
            )
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "requires the authenticated secret inventory path"):
            finish(None)
        self.assertFalse(artifact.exists())
        # A scan hit refuses the witnessed Windows finish and publishes nothing.
        marker_inventory = self._scan_inventory("hit")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "refused the installer"):
            finish(marker_inventory)
        self.assertFalse(artifact.exists())
        self.assertFalse(receipt.exists())

    def test_a_witnessed_windows_receipt_carries_and_is_verified_with_the_worker_scan(self) -> None:
        index = self._create_index()
        begin = self.output / "WITNESSED_BOUND_BEGIN.json"
        receipt = self.output / "WITNESSED_BOUND_RECEIPT.json"
        artifact = self.repo / "build/witnessed-bound/WinsVPN-Setup.exe"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        MODULE.begin_build_receipt(self.repo, index, "windows", begin)
        inventory = self._scan_inventory("pass")
        MODULE.finish_build_receipt(
            self.repo, index, "windows", begin, artifact,
            MODULE.PLATFORM_BUILD_PRODUCERS["windows"], "flutter", "3.47.6",
            "5fc346839b5d0eef006ed8404392afb4dfae428d", "windows-x64-inno-unsigned",
            receipt, secret_inventory_path=inventory,
        )
        built = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(built["producer"]["execution"], "witnessed")
        binding = built["release_host_secret_scan"]
        self.assertEqual(set(binding), {"record", "sha256"})
        self.assertEqual(binding["record"]["artifact"]["sha256"], built["artifact"]["sha256"])
        self.assertEqual(binding["record"]["target_id"], "windows-x64-installer")
        self.assertNotIn("remote_attestation", built)
        self.assertTrue(MODULE.verify_build_receipt(self.repo, index, "windows", receipt, artifact, inventory)["ok"])
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "requires the authenticated secret inventory"):
            MODULE.verify_build_receipt(self.repo, index, "windows", receipt, artifact)
        # The binding cannot be dropped or added where it does not belong.
        stripped = dict(built)
        del stripped["release_host_secret_scan"]
        self._rewrite_anchored(receipt, stripped)
        with self.assertRaises(MODULE.DependencyFreezeError):
            MODULE.verify_build_receipt(self.repo, index, "windows", receipt, artifact, inventory)

    def test_the_declared_target_suffix_can_only_add_a_requirement(self) -> None:
        # toolchain.target is declared by the receipt (and by the finish caller), and its
        # -signed suffix does select a check: the certificate table must exist. That choice
        # is one-way. Declaring -unsigned only drops a requirement the receipt then does not
        # claim to meet, and a store gate still demands the -signed target for a signed
        # store, so a rewrite can neither upgrade bytes nor skip the scan. The architecture
        # is not read from the PE (every Inno loader here is x64, even for ARM64); it is
        # re-derived from the installer's file name, which must agree with the target.
        image = self._valid_pe_payload()
        for arch in ("x64", "arm64"):
            for kind, accepted in (("unsigned", True), ("unsigned-prebuilt", True), ("signed", False)):
                with self.subTest(arch=arch, kind=kind):
                    if accepted:
                        MODULE._validate_release_artifact_bytes(
                            "windows", f"windows-{arch}-inno-{kind}", "setup.exe", image
                        )
                    else:
                        with self.assertRaises(MODULE.DependencyFreezeError):
                            MODULE._validate_release_artifact_bytes(
                                "windows", f"windows-{arch}-inno-{kind}", "setup.exe", image
                            )
        for name, declared in (
            ("WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe", "windows-x64-inno-unsigned"),
            ("WinsVPN-UNSIGNED-LOCAL-Setup.exe", "windows-arm64-inno-unsigned"),
        ):
            with self.subTest(name=name), self.assertRaises(MODULE.DependencyFreezeError):
                MODULE._release_host_secret_scan_target(name, {"target": declared})

    def test_verifying_a_remote_windows_receipt_needs_the_inventory_it_was_scanned_with(self) -> None:
        self._install_scanner_stub()
        index, begin, artifact = self._windows_installer("winv")
        inventory = self._scan_inventory("pass")
        receipt = self._remote_windows_finish(
            index, begin, artifact, self._remote_windows_run(begin, artifact), inventory
        )
        # No inventory path: refused, nothing is taken on the receipt's word.
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "requires the authenticated secret inventory"):
            MODULE.verify_build_receipt(self.repo, index, "windows", receipt, artifact)
        # A different inventory (another digest) is not the one the scan was made with.
        other = pathlib.Path(self._scan_inventory("pass")).with_name("other.json")
        other.write_text(json.dumps({"mode": "pass", "note": "a different file"}), encoding="utf-8")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "not the inventory the receipt's scan was made with"):
            self._verify_remote_windows(index, receipt, artifact, str(other))
        # The same inventory passes.
        self.assertTrue(self._verify_remote_windows(index, receipt, artifact, inventory)["ok"])

    def test_the_verification_scan_must_match_everything_the_receipt_binds(self) -> None:
        self._install_scanner_stub()
        index = self._create_index()
        base = {
            "contract": MODULE.RELEASE_HOST_SECRET_SCAN_CONTRACT,
            "platform": "windows",
            "target_id": "windows-x64-installer",
            "artifact": {"name": "WinsVPN-UNSIGNED-LOCAL-Setup.exe", "size_bytes": 5, "sha256": "a" * 64},
            "scanner": {"path": MODULE.RELEASE_HOST_SECRET_SCANNER, "sha256": "b" * 64, "closure": {"x": "c" * 64}},
            "inventory": {"revision": "r", "label_count": 3, "unique_value_count": 3, "sha256": "d" * 64},
            "result": "pass",
            "matched_labels": [],
            "scanned_utc": "2026-10-22T00:00:00Z",
        }
        def bound(record):
            return {"record": record, "sha256": hashlib.sha256(MODULE._canonical_json(record)).hexdigest()}
        # Only the time may differ.
        MODULE._require_release_host_secret_scan_rerun(dict(base, scanned_utc="2026-10-23T00:00:00Z"), bound(base))
        mutations = {
            "target": {"target_id": "windows-x64-partner-center"},
            "artifact": {"artifact": dict(base["artifact"], sha256="0" * 64)},
            "scanner": {"scanner": dict(base["scanner"], sha256="0" * 64)},
            "closure": {"scanner": dict(base["scanner"], closure={"x": "0" * 64})},
            "revision": {"inventory": dict(base["inventory"], revision="other")},
            "counts": {"inventory": dict(base["inventory"], label_count=4)},
            "result": {"result": "fail"},
            "labels": {"matched_labels": ["X"]},
        }
        for label, change in mutations.items():
            with self.subTest(label=label), self.assertRaises(MODULE.DependencyFreezeError):
                MODULE._require_release_host_secret_scan_rerun(dict(base, **change), bound(base))
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "not the inventory"):
            MODULE._require_release_host_secret_scan_rerun(
                dict(base, inventory=dict(base["inventory"], sha256="0" * 64)), bound(base)
            )

    def test_no_other_receipt_is_verified_with_a_secret_inventory_path(self) -> None:
        index = self._create_index()
        begin, _archive, _record = self._remote_linux_begin(index, "lverify")
        artifact = begin.parent / "wins-vpn-linux-x64.tar.gz"
        artifact.write_bytes(self._linux_tarball())
        receipt = self._remote_linux_finish(
            index, begin, artifact, self._remote_run_record(begin, artifact)
        )
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Only a Windows receipt is verified"):
            MODULE.verify_build_receipt(
                self.repo, index, "linux", receipt, artifact, "/tmp/inventory.json"
            )
        self.assertTrue(MODULE.verify_build_receipt(self.repo, index, "linux", receipt, artifact)["ok"])

    def test_the_verify_command_takes_only_an_inventory_path(self) -> None:
        parser = MODULE._parser()
        parsed = parser.parse_args(
            [
                "verify-receipt", "--repo", ".", "--index", "i", "--platform", "windows",
                "--receipt", "r", "--artifact", "a", "--secret-inventory-path", "/x/inventory.json",
            ]
        )
        self.assertEqual(parsed.secret_inventory_path, "/x/inventory.json")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "verify-receipt", "--repo", ".", "--index", "i", "--platform", "windows",
                    "--receipt", "r", "--artifact", "a", "--release-host-secret-scan", "forged.json",
                ]
            )

    def test_verify_receipt_refuses_a_missing_or_diverging_scan(self) -> None:
        self._install_scanner_stub()
        index = self._create_index()
        for number, label in enumerate(("removed from the binding", "claim copy altered", "claim copy removed")):
            with self.subTest(label=label):
                index, begin, artifact = self._windows_installer(f"wdiv{number}", index)
                receipt = self._remote_windows_finish(
                    index, begin, artifact, self._remote_windows_run(begin, artifact)
                )
                built = json.loads(receipt.read_text(encoding="utf-8"))
                if label == "removed from the binding":
                    del built["remote_attestation"]["release_host_secret_scan"]
                elif label == "claim copy altered":
                    built["build_attempt"]["claim_record"]["release_host_secret_scan"]["record"]["inventory"]["revision"] = "x"
                else:
                    del built["build_attempt"]["claim_record"]["release_host_secret_scan"]
                self._rewrite_anchored(receipt, built)
                with self.assertRaises(MODULE.DependencyFreezeError):
                    self._verify_remote_windows(index, receipt, artifact)

    def test_only_a_windows_receipt_takes_a_secret_inventory_path(self) -> None:
        index = self._create_index()
        begin, _archive, _record = self._remote_linux_begin(index, "lscan")
        artifact = begin.parent / "wins-vpn-linux-x64.tar.gz"
        artifact.write_bytes(self._linux_tarball())
        run_record = self._remote_run_record(begin, artifact)
        receipt = begin.parent / "BUILD_RECEIPT.json"
        with mock.patch.object(MODULE, "_native_process_host", return_value="darwin"):
            with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Only a Windows build receipt takes a secret inventory path"):
                MODULE.finish_build_receipt(
                    self.repo, index, "linux", begin, artifact, self._LINUX_REMOTE_PRODUCER,
                    "flutter", "3.47.6", self._FLUTTER_REVISION, "linux-x64", receipt,
                    "linux", run_record, "/tmp/inventory.json",
                )
        self.assertFalse(receipt.exists())

    def test_remote_linux_run_record_carries_no_secret_scan_field(self) -> None:
        index = self._create_index()
        begin, _archive, _record = self._remote_linux_begin(index, "lnx")
        artifact = begin.parent / "wins-vpn-linux-x64.tar.gz"
        artifact.write_bytes(self._linux_tarball())
        run_record = self._remote_run_record(
            begin, artifact, {"secret_scan": "deferred-to-release-host"}
        )
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "Remote run record schema fields"):
            self._remote_linux_finish(index, begin, artifact, run_record)

    def test_remote_attested_producers_are_an_explicit_separate_class(self) -> None:
        self.assertEqual(
            MODULE.REMOTE_ATTESTED_PLATFORM_HOSTS,
            {
                ("linux", "linux"): "tools/build_linux_release.sh",
                ("windows", "windows"): "installer/windows/build_installer.ps1",
            },
        )
        self.assertEqual(MODULE.PRODUCER_EXECUTION_REMOTE_ATTESTED, "remote-attested")
        self.assertTrue(
            set(MODULE.REMOTE_ATTESTED_PLATFORM_HOSTS).isdisjoint(
                MODULE.PRODUCER_ATTESTED_PLATFORM_HOSTS
            )
        )
        for platform, host in MODULE.REMOTE_ATTESTED_PLATFORM_HOSTS:
            # A native Linux or Windows finish-build stays witnessed: only the
            # Mac orchestrator path can produce a remote-attested receipt.
            self.assertEqual(
                MODULE._platform_build_execution(platform, host),
                MODULE.PRODUCER_EXECUTION_WITNESSED,
            )
        for platform, host in (("android", "linux"), ("linux", "windows"), ("ios", "darwin")):
            with self.subTest(platform=platform, host=host):
                with self.assertRaisesRegex(MODULE.DependencyFreezeError, "no remote-attested"):
                    MODULE._remote_attested_build_producer(platform, host)
        for platform in ("linux", "windows"):
            for path in (
                "tools/release_remote_build.py",
                "tools/release_remote_attestation_check.py",
                "tools/release_remote_run_record_signature.py",
            ):
                self.assertIn(path, MODULE.PLATFORM_PRODUCER_PATHS[platform])

    def _remote_linux_begin(
        self,
        index: pathlib.Path,
        run: str = "r1",
        listing: tuple[str, int, list[tuple[str, str, str]]] | None = None,
    ) -> tuple[pathlib.Path, pathlib.Path, dict[str, object]]:
        directory = self.repo / ".artifacts" / "remote-builds" / run
        directory.mkdir(parents=True)
        begin = directory / "BUILD_BEGIN.json"
        archive = directory / "SOURCE.tar"
        with mock.patch.object(MODULE, "_native_process_host", return_value="darwin"), mock.patch.object(
            MODULE, "_remote_source_listing", return_value=listing or self._fixture_source_listing()
        ):
            remote = MODULE.prepare_remote_attested_begin(
                self.repo, index, "linux", "linux", archive
            )
            record = MODULE.begin_build_receipt(self.repo, index, "linux", begin, remote)
        return begin, archive, record

    def _remote_run_record(
        self,
        begin: pathlib.Path,
        artifact: pathlib.Path,
        overrides: dict[str, object] | None = None,
    ) -> pathlib.Path:
        record = json.loads(begin.read_text(encoding="utf-8"))
        payload = artifact.read_bytes()
        run = {
            "contract": MODULE.REMOTE_RUN_RECORD_CONTRACT,
            "release": record["release"],
            "platform": "linux",
            "remote_host": "linux",
            "build_begin_sha256": hashlib.sha256(begin.read_bytes()).hexdigest(),
            "source_archive_sha256": record["remote_attestation"]["source_archive"]["sha256"],
            "release_input_index_sha256": record["release_input_index"]["sha256"],
            "platform_manifest_sha256": record["platform_manifest"]["sha256"],
            "producer": record["remote_attestation"]["producer"],
            "toolchain": {
                "name": "flutter",
                "version": "3.47.6",
                "revision": self._FLUTTER_REVISION,
                "target": "linux-x64",
            },
            "artifact": {
                "name": artifact.name,
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            },
            "signing": "unsigned",
            "remote_system": {"system": "Linux", "machine": "x86_64"},
            "finished_utc": MODULE._utc_now(),
        }
        run.update(overrides or {})
        path = begin.parent / "REMOTE_RUN.json"
        path.write_text(json.dumps(run), encoding="utf-8")
        return path

    def _remote_linux_finish(
        self,
        index: pathlib.Path,
        begin: pathlib.Path,
        artifact: pathlib.Path,
        run_record: pathlib.Path | None,
        remote_host: str | None = "linux",
    ) -> pathlib.Path:
        receipt = begin.parent / "BUILD_RECEIPT.json"
        with mock.patch.object(MODULE, "_native_process_host", return_value="darwin"):
            MODULE.finish_build_receipt(
                self.repo,
                index,
                "linux",
                begin,
                artifact,
                self._LINUX_REMOTE_PRODUCER,
                "flutter",
                "3.47.6",
                self._FLUTTER_REVISION,
                "linux-x64",
                receipt,
                remote_host,
                run_record,
            )
        return receipt

    def test_remote_linux_receipt_binds_begin_source_digest_and_validated_artifact(self) -> None:
        index = self._create_index()
        begin, archive, record = self._remote_linux_begin(index)
        remote = record["remote_attestation"]
        self.assertEqual(remote["remote_host"], "linux")
        self.assertEqual(remote["orchestrator_host"], "darwin")
        self.assertEqual(
            remote["source_archive"]["sha256"],
            hashlib.sha256(archive.read_bytes()).hexdigest(),
        )
        self.assertGreater(remote["manifest_files_checked"], 0)
        with MODULE.tarfile.open(archive) as source:
            names = source.getnames()
        self.assertEqual(names, sorted(names, key=lambda item: item.encode("utf-8")))
        self.assertIn(self._LINUX_REMOTE_PRODUCER, names)
        artifact = begin.parent / "wins-vpn-linux-x64.tar.gz"
        artifact.write_bytes(self._linux_tarball())
        receipt = self._remote_linux_finish(
            index, begin, artifact, self._remote_run_record(begin, artifact)
        )
        built = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(
            built["producer"],
            {
                "path": self._LINUX_REMOTE_PRODUCER,
                "sha256": hashlib.sha256(
                    (self.repo / self._LINUX_REMOTE_PRODUCER).read_bytes()
                ).hexdigest(),
                "host": "linux",
                "execution": "remote-attested",
            },
        )
        self.assertEqual(built["remote_attestation"]["begin"], remote)
        self.assertEqual(
            built["remote_attestation"]["run_record"]["record"]["artifact"]["sha256"],
            built["artifact"]["sha256"],
        )
        result = MODULE.verify_build_receipt(self.repo, index, "linux", receipt, artifact)
        self.assertTrue(result["ok"])

    def test_remote_linux_receipt_accepts_signing_deferred_to_the_mac(self) -> None:
        index = self._create_index()
        begin, _archive, _record = self._remote_linux_begin(index, "deferred")
        artifact = begin.parent / "wins-vpn-linux-x64.tar.gz"
        artifact.write_bytes(self._linux_tarball())
        receipt = self._remote_linux_finish(
            index, begin, artifact,
            self._remote_run_record(begin, artifact, {"signing": "orchestrator"}),
        )
        built = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(
            built["remote_attestation"]["run_record"]["record"]["signing"], "orchestrator"
        )
        self.assertTrue(
            MODULE.verify_build_receipt(self.repo, index, "linux", receipt, artifact)["ok"]
        )

    def test_remote_receipt_requires_the_mac_remote_begin_record(self) -> None:
        index = self._create_index()
        directory = self.repo / ".artifacts" / "remote-builds" / "plain"
        directory.mkdir(parents=True)
        begin = directory / "BUILD_BEGIN.json"
        with mock.patch.object(MODULE, "_native_process_host", return_value="darwin"):
            MODULE.begin_build_receipt(self.repo, index, "linux", begin)
        artifact = directory / "wins-vpn-linux-x64.tar.gz"
        artifact.write_bytes(self._linux_tarball())
        run_record = directory / "REMOTE_RUN.json"
        run_record.write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "remote begin record"):
            self._remote_linux_finish(index, begin, artifact, run_record)
        # And a remote begin cannot be finished as a local (non-remote) build.
        remote_begin, _archive, _record = self._remote_linux_begin(index, "r2")
        remote_artifact = remote_begin.parent / "wins-vpn-linux-x64.tar.gz"
        remote_artifact.write_bytes(self._linux_tarball())
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "remote begin record|remote host"):
            self._remote_linux_finish(index, remote_begin, remote_artifact, None, None)

    def test_remote_begin_is_orchestrated_only_from_darwin(self) -> None:
        index = self._create_index()
        archive = self.repo / ".artifacts" / "SOURCE.tar"
        with mock.patch.object(MODULE, "_native_process_host", return_value="linux"):
            with self.assertRaisesRegex(MODULE.DependencyFreezeError, "macOS release host"):
                MODULE.prepare_remote_attested_begin(self.repo, index, "linux", "linux", archive)
        self.assertFalse(archive.exists())

    def test_remote_begin_refuses_a_source_tree_that_is_not_the_frozen_revision(self) -> None:
        index = self._create_index()
        producer = self._LINUX_REMOTE_PRODUCER
        cases = {
            "differs from the frozen revision": self._fixture_source_listing(corrupt=(producer,)),
            "does not carry the frozen bytes": self._fixture_source_listing(skip=(producer,)),
        }
        for number, (message, listing) in enumerate(cases.items()):
            with self.subTest(message=message):
                with self.assertRaisesRegex(MODULE.DependencyFreezeError, message):
                    self._remote_linux_begin(index, f"bad{number}", listing)
                self.assertFalse(
                    (self.repo / ".artifacts" / "remote-builds" / f"bad{number}" / "SOURCE.tar").exists()
                )

    def test_remote_receipt_refuses_a_changed_source_archive(self) -> None:
        index = self._create_index()
        begin, archive, _record = self._remote_linux_begin(index)
        artifact = begin.parent / "wins-vpn-linux-x64.tar.gz"
        artifact.write_bytes(self._linux_tarball())
        run_record = self._remote_run_record(begin, artifact)
        with archive.open("ab") as handle:
            handle.write(b"\0")
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "no longer matches its begin record"):
            self._remote_linux_finish(index, begin, artifact, run_record)

    def test_remote_receipt_refuses_an_invalid_artifact(self) -> None:
        index = self._create_index()
        begin, _archive, _record = self._remote_linux_begin(index)
        artifact = begin.parent / "wins-vpn-linux-x64.tar.gz"
        artifact.write_bytes(self._linux_tarball(drop_from_manifest="wins_vpn"))
        run_record = self._remote_run_record(begin, artifact)
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "not exhaustive"):
            self._remote_linux_finish(index, begin, artifact, run_record)

    def test_remote_run_record_must_match_begin_record_and_copied_artifact(self) -> None:
        index = self._create_index()
        cases = {
            "build_begin_sha256": {"build_begin_sha256": "0" * 64},
            "source_archive_sha256": {"source_archive_sha256": "1" * 64},
            "platform_manifest_sha256": {"platform_manifest_sha256": "2" * 64},
            "producer": {"producer": {"path": self._LINUX_REMOTE_PRODUCER, "sha256": "3" * 64}},
            "artifact": {"artifact": {"name": "wins-vpn-linux-x64.tar.gz", "size_bytes": 1, "sha256": "4" * 64}},
            "remote_host": {"remote_host": "windows"},
            "signing": {"signing": "producer"},
        }
        for number, (key, override) in enumerate(cases.items()):
            with self.subTest(key=key):
                begin, _archive, _record = self._remote_linux_begin(index, f"rr{number}")
                artifact = begin.parent / "wins-vpn-linux-x64.tar.gz"
                artifact.write_bytes(self._linux_tarball())
                run_record = self._remote_run_record(begin, artifact, override)
                message = (
                    "signing mode is not reviewed" if key == "signing" else f"Remote run record {key}"
                )
                with self.assertRaisesRegex(MODULE.DependencyFreezeError, message):
                    self._remote_linux_finish(index, begin, artifact, run_record)
                self.assertFalse((begin.parent / "BUILD_RECEIPT.json").exists())

    def test_verify_receipt_rechecks_the_embedded_remote_run_record(self) -> None:
        # R22 X1 F-02: verify-receipt applies finish-build's run-record checks
        # to the copy the receipt embeds, so it accepts no run record that
        # finish-build would have refused.
        index = self._create_index()
        cases = {
            "signing": ({"signing": "producer"}, "signing mode is not reviewed"),
            "release": ({"release": "9.9.9+1"}, "Remote run record release"),
            "release_input_index_sha256": (
                {"release_input_index_sha256": "5" * 64},
                "Remote run record release_input_index_sha256",
            ),
            "platform_manifest_sha256": (
                {"platform_manifest_sha256": "6" * 64},
                "Remote run record platform_manifest_sha256",
            ),
            "schema": ({"unreviewed": True}, "Remote run record schema fields"),
        }
        for number, (key, (change, message)) in enumerate(cases.items()):
            with self.subTest(key=key):
                begin, _archive, _record = self._remote_linux_begin(index, f"ve{number}")
                artifact = begin.parent / "wins-vpn-linux-x64.tar.gz"
                artifact.write_bytes(self._linux_tarball())
                receipt = self._remote_linux_finish(
                    index, begin, artifact, self._remote_run_record(begin, artifact)
                )
                built = json.loads(receipt.read_text(encoding="utf-8"))
                built["remote_attestation"]["run_record"]["record"].update(change)
                self._rewrite_anchored(receipt, built)
                with self.assertRaisesRegex(MODULE.DependencyFreezeError, message):
                    MODULE.verify_build_receipt(self.repo, index, "linux", receipt, artifact)


_PINNED_PYTHON_HOST_KEYS = {"arm64": "darwin_arm64", "x86_64": "darwin_amd64"}


def _pinned_release_python_or_skip(test: unittest.TestCase) -> pathlib.Path:
    """Return the host's pinned release Python, or skip when it is absent."""

    if sys.platform != "darwin":
        test.skipTest("pinned release Python worker is macOS-only")
    host_key = _PINNED_PYTHON_HOST_KEYS.get(os.uname().machine)
    python = json.loads(
        SCRIPT.with_name("toolchain-pins.json").read_text(encoding="utf-8")
    )["tools"]["python"]
    if (
        host_key is None
        or host_key not in python.get("reviewed_executable_path", {})
        or host_key not in python.get("executable_sha256", {})
    ):
        test.skipTest("release Python is not pinned for this host")
    path = pathlib.Path(python["reviewed_executable_path"][host_key])
    digest = python["executable_sha256"][host_key]
    if not path.is_file() or path.is_symlink():
        test.skipTest(f"pinned release Python is not installed: {path}")
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        test.skipTest("installed release Python does not match its pin")
    return path


class ReleaseHostSecretScanRealScannerTests(unittest.TestCase):
    """The worker's scan with the real scanner closure and a synthetic inventory."""

    SECRET = "SyntheticWorkerScanSecret0123456789abcdef"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="wins-real-scan-")
        base = pathlib.Path(self.temporary.name).resolve()
        os.chmod(base, 0o700)
        self.repo = base / "repo"
        for relative in MODULE.RELEASE_HOST_SECRET_SCANNER_CLOSURE:
            target = self.repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(TOOLS_DIR.parent / relative, target)
        for directory in (self.repo, self.repo / "tools"):
            os.chmod(directory, 0o700)
        self.inventory = base / "inventory" / "release-secret-inventory.json"
        self.inventory.parent.mkdir()
        os.chmod(self.inventory.parent, 0o700)
        self.inventory.write_text(
            json.dumps({"schema_version": 1, "revision": "rev-worker-scan", "secrets": {"SYNTHETIC_WORKER": self.SECRET}}),
            encoding="utf-8",
        )
        os.chmod(self.inventory, 0o600)
        self.owners = MODULE._allowed_owners(self.repo)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _installer(self, payload: bytes) -> tuple[pathlib.Path, dict[str, object]]:
        path = self.repo / "WinsVPN-UNSIGNED-LOCAL-Setup.exe"
        path.write_bytes(payload)
        os.chmod(path, 0o600)
        return path, {
            "name": path.name,
            "size_bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    def _scan(self, payload: bytes, inventory: object = None) -> dict[str, object]:
        path, artifact = self._installer(payload)
        return MODULE._run_release_host_secret_scan(
            self.repo, path, artifact, {"target": "windows-x64-inno-unsigned"},
            str(self.inventory) if inventory is None else inventory, self.owners,
        )

    def test_a_clean_installer_passes_and_binds_the_inventory_digest(self) -> None:
        payload = DependencyFreezeTests._valid_pe_payload()
        scan = self._scan(payload)
        self.assertEqual(scan["result"], "pass")
        self.assertEqual(scan["matched_labels"], [])
        self.assertEqual(scan["target_id"], "windows-x64-installer")
        self.assertEqual(scan["artifact"]["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(
            scan["inventory"],
            {
                "revision": "rev-worker-scan",
                "label_count": 1,
                "unique_value_count": 1,
                "sha256": hashlib.sha256(self.inventory.read_bytes()).hexdigest(),
            },
        )
        self.assertEqual(scan["scanner"]["closure"], MODULE.RELEASE_HOST_SECRET_SCANNER_CLOSURE)
        self.assertNotIn(self.SECRET, json.dumps(scan))
        self.assertNotIn(str(self.inventory), json.dumps(scan))

    def test_an_installer_carrying_an_inventory_secret_is_refused_without_disclosing_it(self) -> None:
        payload = DependencyFreezeTests._valid_pe_payload() + self.SECRET.encode("ascii")
        with self.assertRaises(MODULE.DependencyFreezeError) as raised:
            self._scan(payload)
        message = str(raised.exception)
        self.assertIn("refused the installer", message)
        self.assertNotIn(self.SECRET, message)
        self.assertNotIn(str(self.inventory), message)

    def test_an_inventory_the_scanner_does_not_accept_is_never_a_pass(self) -> None:
        os.chmod(self.inventory, 0o644)
        with self.assertRaises(MODULE.DependencyFreezeError):
            self._scan(DependencyFreezeTests._valid_pe_payload())
        os.chmod(self.inventory, 0o600)
        inside = self.repo / "inventory.json"
        shutil.copyfile(self.inventory, inside)
        os.chmod(inside, 0o600)
        with self.assertRaises(MODULE.DependencyFreezeError):
            self._scan(DependencyFreezeTests._valid_pe_payload(), str(inside))
        with self.assertRaises(MODULE.DependencyFreezeError):
            self._scan(DependencyFreezeTests._valid_pe_payload(), str(self.inventory) + ".missing")


class AuthoritativeWorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.python = _pinned_release_python_or_skip(self)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="wins-release-dependency-worker-", dir="/private/tmp"
        )
        self.repo = pathlib.Path(self.temporary.name)
        tools = self.repo / "tools"
        tools.mkdir(mode=0o700)
        source_tools = SCRIPT.parent
        for name in (
            "release_dependency_freeze.py",
            "toolchain-pins.json",
        ):
            shutil.copy2(source_tools / name, tools / name)
        env = {
            "GIT_AUTHOR_EMAIL": "worker-test@winsvpn.example",
            "GIT_AUTHOR_NAME": "Worker Test",
            "GIT_COMMITTER_EMAIL": "worker-test@winsvpn.example",
            "GIT_COMMITTER_NAME": "Worker Test",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": str(self.repo),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        }
        for command in (
            ["/usr/bin/git", "init", "-q"],
            ["/usr/bin/git", "add", "tools"],
            ["/usr/bin/git", "commit", "-q", "-m", "worker-test"],
        ):
            subprocess.run(
                command,
                check=True,
                cwd=self.repo,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        MODULE._FIXTURE_MODE = False
        MODULE._PRODUCTION_REQUIRED = False
        MODULE._POST_SELECT_HOOK = None
        MODULE._POST_INPUT_CAPTURE_HOOK = None
        MODULE._POST_DIRECTORY_BIND_HOOK = None
        MODULE._POST_FINAL_CAPTURE_HOOK = None
        MODULE._SOURCE_FREEZE_MODULE = None
        MODULE._SOURCE_FREEZE_TRUST_PATH = None
        MODULE._SOURCE_FREEZE_SELF_AUTHORED_OVERRIDE = None

    def tearDown(self) -> None:
        MODULE._FIXTURE_MODE = False
        MODULE._PRODUCTION_REQUIRED = False
        MODULE._POST_SELECT_HOOK = None
        MODULE._POST_INPUT_CAPTURE_HOOK = None
        MODULE._POST_DIRECTORY_BIND_HOOK = None
        MODULE._POST_FINAL_CAPTURE_HOOK = None
        MODULE._SOURCE_FREEZE_MODULE = None
        MODULE._SOURCE_FREEZE_TRUST_PATH = None
        MODULE._SOURCE_FREEZE_SELF_AUTHORED_OVERRIDE = None
        if hasattr(self, "temporary"):
            self.temporary.cleanup()

    def _verify_missing_argv(self) -> list[str]:
        return [
            "release_dependency_freeze.py",
            "verify",
            "--repo",
            str(self.repo),
            "--manifest",
            str(self.repo / "MISSING.json"),
        ]

    def test_pristine_worker_reexec_discards_imported_rebinding(self) -> None:
        hostile = mock.Mock(side_effect=AssertionError("imported mutation executed"))
        spawn = mock.Mock(side_effect=AssertionError("imported parent spawned worker"))
        with mock.patch.object(MODULE, "_dispatch_command", hostile):
            with mock.patch.object(MODULE.subprocess, "run", spawn):
                with mock.patch.object(sys, "argv", self._verify_missing_argv()):
                    self.assertEqual(MODULE.main(), 1)
        hostile.assert_not_called()
        spawn.assert_not_called()

    def test_imported_parent_cannot_substitute_release_python_binary(self) -> None:
        spawn = mock.Mock(side_effect=AssertionError("substituted binary executed"))
        with mock.patch.object(
            MODULE,
            "_reviewed_release_python_executable",
            lambda: pathlib.Path("/usr/bin/true"),
        ):
            with mock.patch.object(MODULE.subprocess, "run", spawn):
                with mock.patch.object(sys, "argv", self._verify_missing_argv()):
                    self.assertEqual(MODULE.main(), 1)
        spawn.assert_not_called()

    def test_imported_parent_name_mutation_cannot_dispatch_worker(self) -> None:
        original_name = MODULE.__name__
        for name in (
            "_initial_script_entry",
            "_exec_authoritative_worker",
            "_run_authoritative_worker",
            "_fresh_posix_namespace",
            "_spawn_authoritative_worker",
        ):
            self.assertFalse(hasattr(MODULE, name), name)
        try:
            MODULE.__name__ = "__main__"
            with mock.patch.object(
                MODULE,
                "_reviewed_release_python_executable",
                lambda: pathlib.Path("/usr/bin/true"),
            ):
                with mock.patch.object(MODULE.subprocess, "run") as run:
                    with mock.patch.object(sys, "argv", self._verify_missing_argv()):
                        self.assertEqual(MODULE.main(), 1)
            run.assert_not_called()
        finally:
            MODULE.__name__ = original_name

    def test_preloaded_subprocess_run_cannot_grant_worker_success(self) -> None:
        controller = self.repo / "tools/release_dependency_freeze.py"
        wrapper = "\n".join(
            (
                "import runpy",
                "import subprocess",
                "import sys",
                "class Accepted:",
                "    returncode = 0",
                "    stdout = '{}'",
                "    stderr = ''",
                "subprocess.run = lambda *args, **kwargs: Accepted()",
                f"sys.argv = [{str(controller)!r}, 'verify', '--repo', {str(self.repo)!r}, '--manifest', {str(self.repo / 'MISSING.json')!r}]",
                f"runpy.run_path({str(controller)!r}, run_name='__main__')",
            )
        )
        completed = subprocess.run(
            [str(self.python), "-I", "-S", "-c", wrapper],
            check=False,
            cwd="/private/tmp",
            env=MODULE._worker_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotEqual(completed.stdout.strip(), "{}")
        self.assertIn(
            MODULE.AUTHENTICATED_WORKER_LAUNCH_REQUIRED,
            completed.stderr,
        )

    def test_preloaded_json_and_functools_cannot_reconstruct_private_worker(self) -> None:
        controller = self.repo / "tools/release_dependency_freeze.py"
        source_descriptor = os.open(controller, os.O_RDONLY)
        try:
            descriptor = fcntl.fcntl(source_descriptor, fcntl.F_DUPFD, 64)
        finally:
            os.close(source_descriptor)
        wrapper = "\n".join(
            (
                "import functools",
                "import json",
                "import os",
                "import sys",
                "functools.wraps = lambda original: (lambda wrapped: (lambda *args, **kwargs: {'ok': True}))",
                "json.dumps = lambda *args, **kwargs: '{\"production_authority_authenticated\":true,\"publication_authorized\":true}'",
                f"sys.argv = [{str(controller)!r}, {MODULE._AUTHORITATIVE_WORKER_SWITCH!r}, {str(descriptor)!r}, 'verify', '--repo', {str(self.repo)!r}, '--manifest', {str(self.repo / 'MISSING.json')!r}]",
                f"source = os.pread({descriptor}, os.fstat({descriptor}).st_size, 0)",
                f"path = '/dev/fd/{descriptor}'",
                "namespace = {'__name__': '__main__', '__file__': path, '__package__': None, '__builtins__': __builtins__}",
                "exec(compile(source, path, 'exec'), namespace)",
            )
        )
        try:
            completed = subprocess.run(
                [str(self.python), "-I", "-S", "-c", wrapper],
                check=False,
                cwd="/private/tmp",
                env=MODULE._worker_environment(),
                pass_fds=(descriptor,),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        finally:
            os.close(descriptor)
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn('"production_authority_authenticated":true', completed.stdout)
        self.assertRegex(
            completed.stderr,
            r"worker (?:is not pristine|kernel process identity changed)",
        )

    def test_rewritten_nsgetargv_cannot_reconstruct_private_worker(self) -> None:
        controller = self.repo / "tools/release_dependency_freeze.py"
        source_descriptor = os.open(controller, os.O_RDONLY)
        try:
            descriptor = fcntl.fcntl(source_descriptor, fcntl.F_DUPFD, 64)
        finally:
            os.close(source_descriptor)
        path = f"/dev/fd/{descriptor}"
        worker_tail = [
            MODULE._AUTHORITATIVE_WORKER_SWITCH,
            str(descriptor),
            "verify",
            "--repo",
            str(self.repo),
            "--manifest",
            str(self.repo / "MISSING.json"),
        ]
        fake_process_argv = [
            str(self.python),
            "-I",
            "-S",
            path,
            *worker_tail,
        ]
        wrapper = "\n".join(
            (
                "import ctypes",
                "import os",
                "import sys",
                f"fake_argv = {fake_process_argv!r}",
                "buffers = [ctypes.create_string_buffer(value.encode('utf-8')) for value in fake_argv]",
                "array = (ctypes.c_char_p * len(buffers))(*[ctypes.cast(value, ctypes.c_char_p) for value in buffers])",
                "process = ctypes.CDLL(None)",
                "process._NSGetArgc.restype = ctypes.POINTER(ctypes.c_int)",
                "process._NSGetArgv.restype = ctypes.POINTER(ctypes.POINTER(ctypes.c_char_p))",
                "process._NSGetArgc().contents.value = len(fake_argv)",
                "process._NSGetArgv()[0] = ctypes.cast(array, ctypes.POINTER(ctypes.c_char_p))",
                f"sys.argv = [{path!r}, *{worker_tail!r}]",
                f"source = os.pread({descriptor}, os.fstat({descriptor}).st_size, 0)",
                f"allowed = set({sorted(MODULE._PRISTINE_RELEASE_PYTHON_BOOTSTRAP_MODULES)!r})",
                "for module_name in tuple(sys.modules):",
                "    if module_name not in allowed:",
                "        del sys.modules[module_name]",
                f"namespace = {{'__name__': '__main__', '__file__': {path!r}, '__package__': None, '__builtins__': __builtins__}}",
                f"exec(compile(source, {path!r}, 'exec'), namespace)",
            )
        )
        try:
            completed = subprocess.run(
                [str(self.python), "-I", "-S", "-c", wrapper],
                check=False,
                cwd="/private/tmp",
                env=MODULE._worker_environment(),
                pass_fds=(descriptor,),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        finally:
            os.close(descriptor)
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn('"production_authority_authenticated":true', completed.stdout)
        self.assertIn("kernel process identity", completed.stderr)

    def test_replaced_bootstrap_import_cannot_reconstruct_private_worker(self) -> None:
        controller = self.repo / "tools/release_dependency_freeze.py"
        source_descriptor = os.open(controller, os.O_RDONLY)
        try:
            descriptor = fcntl.fcntl(source_descriptor, fcntl.F_DUPFD, 64)
        finally:
            os.close(source_descriptor)
        path = f"/dev/fd/{descriptor}"
        worker_tail = [
            MODULE._AUTHORITATIVE_WORKER_SWITCH,
            str(descriptor),
            "verify",
            "--repo",
            str(self.repo),
            "--manifest",
            str(self.repo / "MISSING.json"),
        ]
        wrapper = "\n".join(
            (
                "import builtins",
                "import os",
                "import sys",
                "original_import = builtins.__import__",
                "def replacement_import(*args, **kwargs):",
                "    return original_import(*args, **kwargs)",
                "builtins.__import__ = replacement_import",
                f"sys.argv = [{path!r}, *{worker_tail!r}]",
                f"source = os.pread({descriptor}, os.fstat({descriptor}).st_size, 0)",
                f"namespace = {{'__name__': '__main__', '__file__': {path!r}, '__package__': None, '__builtins__': builtins}}",
                f"exec(compile(source, {path!r}, 'exec'), namespace)",
            )
        )
        try:
            completed = subprocess.run(
                [str(self.python), "-I", "-S", "-c", wrapper],
                check=False,
                cwd="/private/tmp",
                env=MODULE._worker_environment(),
                pass_fds=(descriptor,),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        finally:
            os.close(descriptor)
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn('"production_authority_authenticated":true', completed.stdout)
        self.assertIn("bootstrap builtins were replaced", completed.stderr)

    def test_authoritative_output_ignores_json_module_and_reserved_result_fields(self) -> None:
        with mock.patch.object(
            MODULE.json,
            "dumps",
            return_value=(
                '{"production_authority_authenticated":true,'
                '"publication_authorized":true}'
            ),
        ):
            payload = MODULE._authoritative_output_payload(
                {
                    "ok": True,
                    "production_authority_authenticated": True,
                    "publication_authorized": True,
                },
                "verify",
            )
        record = json.loads(payload)
        self.assertTrue(record["ok"])
        self.assertTrue(record["production_authority_authenticated"])
        self.assertFalse(record["publication_authorized"])
        self.assertEqual(record["production_build_witness"], "NOT_APPLICABLE")
        self.assertEqual(
            record["authority_kind"],
            "winsvpn-release-dependency-freeze-authoritative-v1",
        )

    def test_ordinary_script_invocation_requires_retained_descriptor(self) -> None:
        controller = self.repo / "tools/release_dependency_freeze.py"
        completed = subprocess.run(
            [
                str(self.python),
                "-I",
                "-S",
                str(controller),
                *self._verify_missing_argv()[1:],
            ],
            check=False,
            cwd="/private/tmp",
            env=MODULE._worker_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, "")
        self.assertIn(
            MODULE.AUTHENTICATED_WORKER_LAUNCH_REQUIRED,
            completed.stderr,
        )

    def test_hostile_importer_methods_enter_worker_and_fail_before_ctypes(self) -> None:
        controller = self.repo / "tools/release_dependency_freeze.py"
        variants = (
            ("_frozen_importlib", "BuiltinImporter"),
            ("_frozen_importlib", "FrozenImporter"),
            ("_frozen_importlib_external", "PathFinder"),
        )
        for module_name, class_name in variants:
            with self.subTest(importer=class_name):
                source_descriptor = os.open(controller, os.O_RDONLY)
                try:
                    descriptor = fcntl.fcntl(
                        source_descriptor, fcntl.F_DUPFD, 64
                    )
                finally:
                    os.close(source_descriptor)
                path = f"/dev/fd/{descriptor}"
                worker_tail = [
                    MODULE._AUTHORITATIVE_WORKER_SWITCH,
                    str(descriptor),
                    "verify",
                    "--repo",
                    str(self.repo),
                    "--manifest",
                    str(self.repo / "MISSING.json"),
                ]
                wrapper = "\n".join(
                    (
                        f"import {module_name} as hostile_importlib",
                        "import os",
                        "import sys",
                        f"importer = hostile_importlib.{class_name}",
                        "original = importer.find_spec",
                        "def hostile(cls, fullname, path=None, target=None):",
                        "    return original(fullname, path, target)",
                        "importer.find_spec = classmethod(hostile)",
                        f"sys.argv = [{path!r}, *{worker_tail!r}]",
                        f"source = os.pread({descriptor}, os.fstat({descriptor}).st_size, 0)",
                        f"namespace = {{'__name__': '__main__', '__file__': {path!r}, '__package__': None, '__builtins__': __builtins__}}",
                        f"exec(compile(source, {path!r}, 'exec'), namespace)",
                    )
                )
                try:
                    completed = subprocess.run(
                        [
                            str(self.python),
                            "-I",
                            "-S",
                            "-c",
                            wrapper,
                        ],
                        check=False,
                        cwd="/private/tmp",
                        env=MODULE._worker_environment(),
                        pass_fds=(descriptor,),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                finally:
                    os.close(descriptor)
                self.assertEqual(completed.returncode, 1)
                self.assertEqual(completed.stdout, "")
                self.assertIn(
                    "bootstrap importer methods were replaced",
                    completed.stderr,
                )
                self.assertNotIn("kernel process identity", completed.stderr)

    def test_worker_authenticates_posix_write_and_late_ctypes_import(self) -> None:
        source = SCRIPT.read_text(encoding="ascii")
        self.assertNotIn("\nimport ctypes\n", source)
        self.assertGreater(
            source.index("import ctypes as authenticated_ctypes"),
            source.index("def _darwin_kernel_process_identity"),
        )
        self.assertIn("and os.write is _BOOTSTRAP_POSIX_WRITE", source)
        self.assertIn("_BOOTSTRAP_POSIX_WRITE(1, view[offset:])", source)

    def test_runpy_sitecustomize_and_posix_seams_enter_worker_and_fail(self) -> None:
        controller = self.repo / "tools/release_dependency_freeze.py"
        variants = (
            ("import runpy", "bootstrap OS or startup seams were replaced"),
            (
                "import sys\nsys.modules['sitecustomize'] = type(sys)('sitecustomize')",
                "bootstrap OS or startup seams were replaced",
            ),
            (
                "import posix\nposix.write = lambda *args: 1",
                "bootstrap OS or startup seams were replaced",
            ),
        )
        for hostile_setup, expected in variants:
            with self.subTest(hostile_setup=hostile_setup.splitlines()[0]):
                source_descriptor = os.open(controller, os.O_RDONLY)
                try:
                    descriptor = fcntl.fcntl(
                        source_descriptor, fcntl.F_DUPFD, 64
                    )
                finally:
                    os.close(source_descriptor)
                path = f"/dev/fd/{descriptor}"
                worker_tail = [
                    MODULE._AUTHORITATIVE_WORKER_SWITCH,
                    str(descriptor),
                    "verify",
                    "--repo",
                    str(self.repo),
                    "--manifest",
                    str(self.repo / "MISSING.json"),
                ]
                wrapper = "\n".join(
                    (
                        hostile_setup,
                        "import os",
                        "import sys",
                        f"sys.argv = [{path!r}, *{worker_tail!r}]",
                        f"source = os.pread({descriptor}, os.fstat({descriptor}).st_size, 0)",
                        f"namespace = {{'__name__': '__main__', '__file__': {path!r}, '__package__': None, '__builtins__': __builtins__}}",
                        f"exec(compile(source, {path!r}, 'exec'), namespace)",
                    )
                )
                try:
                    completed = subprocess.run(
                        [str(self.python), "-I", "-S", "-c", wrapper],
                        check=False,
                        cwd="/private/tmp",
                        env=MODULE._worker_environment(),
                        pass_fds=(descriptor,),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                finally:
                    os.close(descriptor)
                self.assertEqual(completed.returncode, 1)
                self.assertIn(expected, completed.stderr)
                self.assertNotIn("kernel process identity", completed.stderr)

    def test_worker_help_cannot_exit_before_source_authentication(self) -> None:
        controller = self.repo / "tools/release_dependency_freeze.py"
        descriptor = os.open(controller, os.O_RDONLY)
        try:
            completed = subprocess.run(
                [
                    str(self.python),
                    "-I",
                    "-S",
                    f"/dev/fd/{descriptor}",
                    MODULE._AUTHORITATIVE_WORKER_SWITCH,
                    str(descriptor),
                    "--repo",
                    str(self.repo),
                    "--help",
                ],
                check=False,
                cwd="/private/tmp",
                env=MODULE._worker_environment(),
                pass_fds=(descriptor,),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        finally:
            os.close(descriptor)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, "")
        self.assertNotIn("usage:", completed.stderr.lower())
        self.assertRegex(
            completed.stderr,
            r"arguments are invalid",
        )

    def test_pristine_worker_refuses_parent_hook_state_before_spawn(self) -> None:
        MODULE._POST_SELECT_HOOK = object()
        with mock.patch.object(MODULE.subprocess, "run") as run:
            with mock.patch.object(sys, "argv", self._verify_missing_argv()):
                self.assertEqual(MODULE.main(), 1)
        run.assert_not_called()

    def test_authoritative_worker_rejects_interpreter_identity_drift(self) -> None:
        controller = self.repo / "tools/release_dependency_freeze.py"
        pins_path = self.repo / "tools/toolchain-pins.json"
        pins = json.loads(pins_path.read_text(encoding="utf-8"))
        host_key = _PINNED_PYTHON_HOST_KEYS[os.uname().machine]
        pins["tools"]["python"]["reviewed_executable_path"][host_key] = (
            "/usr/bin/python3"
        )
        pins_path.write_text(json.dumps(pins, indent=2) + "\n", encoding="utf-8")
        descriptor = os.open(controller, os.O_RDONLY)
        try:
            command = [
                str(self.python),
                "-I",
                "-S",
                f"/dev/fd/{descriptor}",
                MODULE._AUTHORITATIVE_WORKER_SWITCH,
                str(descriptor),
                *self._verify_missing_argv()[1:],
            ]
            completed = subprocess.run(
                command,
                check=False,
                cwd="/private/tmp",
                env=MODULE._worker_environment(),
                pass_fds=(descriptor,),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        finally:
            os.close(descriptor)
        self.assertEqual(completed.returncode, 1)
        self.assertIn(MODULE.PINNED_RELEASE_PYTHON_REQUIRED, completed.stderr)

    def test_worker_refuses_pins_file_that_differs_from_tracked_tree(self) -> None:
        pins_path = self.repo / "tools/toolchain-pins.json"
        pins = json.loads(pins_path.read_text(encoding="utf-8"))
        pins["tools"]["python"]["note"] = "edited after the reviewed commit"
        pins_path.write_text(json.dumps(pins, indent=2) + "\n", encoding="utf-8")
        controller = self.repo / "tools/release_dependency_freeze.py"
        descriptor = os.open(controller, os.O_RDONLY)
        try:
            completed = subprocess.run(
                [
                    str(self.python),
                    "-I",
                    "-S",
                    f"/dev/fd/{descriptor}",
                    MODULE._AUTHORITATIVE_WORKER_SWITCH,
                    str(descriptor),
                    *self._verify_missing_argv()[1:],
                ],
                check=False,
                cwd="/private/tmp",
                env=MODULE._worker_environment(),
                pass_fds=(descriptor,),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        finally:
            os.close(descriptor)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, "")
        self.assertIn("tools/toolchain-pins.json", completed.stderr)
        self.assertRegex(
            completed.stderr,
            r"does not match the exact tracked Git tree|not immutable/clean",
        )

    def test_authoritative_worker_rejects_environment_injection(self) -> None:
        controller = self.repo / "tools/release_dependency_freeze.py"
        descriptor = os.open(controller, os.O_RDONLY)
        try:
            env = MODULE._worker_environment()
            env["PYTHONPATH"] = str(self.repo)
            command = [
                str(self.python),
                "-I",
                "-S",
                f"/dev/fd/{descriptor}",
                MODULE._AUTHORITATIVE_WORKER_SWITCH,
                str(descriptor),
                *self._verify_missing_argv()[1:],
            ]
            completed = subprocess.run(
                command,
                check=False,
                cwd="/private/tmp",
                env=env,
                pass_fds=(descriptor,),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        finally:
            os.close(descriptor)
        self.assertEqual(completed.returncode, 1)
        self.assertIn("environment is not scrubbed", completed.stderr)


class AuthoritativeWorkerLocalFallbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.python = _pinned_release_python_or_skip(self)
        completed = subprocess.run(
            [str(self.python), "-I", "-S", "-c", "import sys; print('.'.join(map(str, sys.version_info[:3])))"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if (
            completed.returncode != 0
            or completed.stdout.strip()
            != ".".join(str(value) for value in MODULE._RELEASE_PYTHON_VERSION)
        ):
            self.skipTest("local Python does not match reviewed 3.14.7")
        self.environment = {
            "HOME": "/private/tmp",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "TMPDIR": "/private/tmp",
        }

    def test_local_314_fallback_runs_direct_launch_refusal(self) -> None:
        completed = subprocess.run(
            [str(self.python), "-I", "-S", str(SCRIPT), "--help"],
            check=False,
            cwd="/private/tmp",
            env=self.environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, "")
        self.assertIn(
            MODULE.AUTHENTICATED_WORKER_LAUNCH_REQUIRED, completed.stderr
        )

    def test_pinned_314_worker_authenticates_before_git(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="wins-pinned-worker-")
        self.addCleanup(temporary.cleanup)
        repo = pathlib.Path(temporary.name)
        (repo / "tools").mkdir(mode=0o700)
        for name in ("release_dependency_freeze.py", "toolchain-pins.json"):
            shutil.copy2(SCRIPT.with_name(name), repo / "tools" / name)
        controller = repo / "tools/release_dependency_freeze.py"
        descriptor = os.open(controller, os.O_RDONLY)
        try:
            completed = subprocess.run(
                [
                    str(self.python),
                    "-I",
                    "-S",
                    f"/dev/fd/{descriptor}",
                    MODULE._AUTHORITATIVE_WORKER_SWITCH,
                    str(descriptor),
                    "verify",
                    "--repo",
                    str(repo),
                    "--manifest",
                    str(repo / "MISSING.json"),
                ],
                check=False,
                cwd="/private/tmp",
                env=self.environment,
                pass_fds=(descriptor,),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        finally:
            os.close(descriptor)
        self.assertEqual(completed.returncode, 1)
        self.assertNotIn(
            '"production_authority_authenticated":true', completed.stdout
        )
        # Every interpreter, process, environment, source-descriptor and pin
        # check passed; the worker then refuses because the copy has no Git.
        self.assertEqual(
            completed.stderr,
            f"RELEASE DEPENDENCY FREEZE: FAIL: {MODULE.GIT_REQUIRED}\n",
        )
        source = SCRIPT.read_text(encoding="ascii")
        self.assertNotIn("/Library/WinsVPN/ReleasePython", source)


class WorkerImportPathTests(unittest.TestCase):
    def test_runtime_import_path_admits_only_the_runtime_stdlib(self) -> None:
        prefix = pathlib.Path("/opt/pinned-python")
        MODULE._require_runtime_import_path(
            prefix,
            [
                "/opt/pinned-python/lib/python314.zip",
                "/opt/pinned-python/lib/python3.14",
                "/opt/pinned-python/lib/python3.14/lib-dynload",
            ],
        )
        for entries in (
            [],
            ["/opt/pinned-python/lib/../../evil"],
            ["/opt/pinned-python/lib/python3.14", "/opt/other/lib"],
            ["lib/python3.14"],
            [""],
            ["/opt/pinned-python/libx"],
            ["/opt/pinned-python"],
        ):
            with self.subTest(entries=entries):
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError, "import path escaped its runtime"
                ):
                    MODULE._require_runtime_import_path(prefix, entries)


class PinnedReleasePythonWorkerTests(unittest.TestCase):
    """Launch the worker on the pinned interpreter in a Git-free copy.

    Each launch must either stop at GIT_REQUIRED, which proves every
    interpreter, process, environment, descriptor and pin check passed, or
    refuse at the specific pin or environment check under test.
    """

    def setUp(self) -> None:
        self.python = _pinned_release_python_or_skip(self)
        temporary = tempfile.TemporaryDirectory(prefix="wins-pinned-freeze-")
        self.addCleanup(temporary.cleanup)
        self.repo = pathlib.Path(temporary.name).resolve()
        tools = self.repo / "tools"
        tools.mkdir(mode=0o700)
        for name in (
            "release_dependency_freeze.py",
            "run_release_dependency_freeze.sh",
            "toolchain-pins.json",
        ):
            shutil.copy2(SCRIPT.with_name(name), tools / name)
        self.pins = tools / "toolchain-pins.json"
        self.environment = MODULE._worker_environment()

    def _rewrite_pins(self, transform) -> None:
        text = self.pins.read_text(encoding="utf-8")
        rewritten = transform(text)
        self.assertNotEqual(rewritten, text)
        self.pins.write_text(rewritten, encoding="utf-8")

    def _set_host_digest(self, digest: str) -> None:
        pins = json.loads(self.pins.read_text(encoding="utf-8"))
        host_key = _PINNED_PYTHON_HOST_KEYS[os.uname().machine]
        pins["tools"]["python"]["executable_sha256"][host_key] = digest
        self.pins.write_text(json.dumps(pins, indent=2) + "\n", encoding="utf-8")

    def _worker_argv(self) -> list[str]:
        return [
            "verify-index",
            "--repo",
            str(self.repo),
            "--index",
            str(self.repo / ".artifacts/MISSING-INDEX.json"),
        ]

    def _direct(self, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        controller = self.repo / "tools/release_dependency_freeze.py"
        descriptor = os.open(controller, os.O_RDONLY)
        try:
            return subprocess.run(
                [
                    str(self.python),
                    "-I",
                    "-S",
                    f"/dev/fd/{descriptor}",
                    MODULE._AUTHORITATIVE_WORKER_SWITCH,
                    str(descriptor),
                    *self._worker_argv(),
                ],
                check=False,
                cwd="/private/tmp",
                env=self.environment if environment is None else environment,
                pass_fds=(descriptor,),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        finally:
            os.close(descriptor)

    def _parent(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "/bin/bash",
                str(self.repo / "tools/run_release_dependency_freeze.sh"),
                *self._worker_argv(),
            ],
            check=False,
            cwd="/private/tmp",
            env={"HOME": "/private/tmp", "PATH": "/usr/bin:/bin", "LANG": "C"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_parent_launches_pinned_python_and_reaches_git_requirement(self) -> None:
        completed = self._parent()
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(
            completed.stderr,
            f"RELEASE DEPENDENCY FREEZE: FAIL: {MODULE.GIT_REQUIRED}\n",
        )

    def test_direct_pinned_worker_reaches_git_requirement(self) -> None:
        completed = self._direct()
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(
            completed.stderr,
            f"RELEASE DEPENDENCY FREEZE: FAIL: {MODULE.GIT_REQUIRED}\n",
        )

    def test_worker_refuses_interpreter_bytes_that_differ_from_pin(self) -> None:
        self._set_host_digest("0" * 64)
        completed = self._direct()
        self.assertEqual(completed.returncode, 1)
        self.assertIn(MODULE.PINNED_RELEASE_PYTHON_REQUIRED, completed.stderr)
        self.assertIn("do not match the pinned SHA-256", completed.stderr)
        self.assertNotIn(MODULE.GIT_REQUIRED, completed.stderr)

    def test_parent_refuses_interpreter_bytes_that_differ_from_pin(self) -> None:
        self._set_host_digest("0" * 64)
        completed = self._parent()
        self.assertEqual(completed.returncode, 1)
        self.assertIn(
            "pinned release Python bytes do not match tools/toolchain-pins.json",
            completed.stderr,
        )
        self.assertNotIn("RELEASE DEPENDENCY FREEZE: FAIL", completed.stderr)

    def test_worker_refuses_interpreter_outside_pinned_path(self) -> None:
        pins = json.loads(self.pins.read_text(encoding="utf-8"))
        host_key = _PINNED_PYTHON_HOST_KEYS[os.uname().machine]
        pins["tools"]["python"]["reviewed_executable_path"][host_key] = (
            "/usr/bin/python3"
        )
        self.pins.write_text(json.dumps(pins, indent=2) + "\n", encoding="utf-8")
        completed = self._direct()
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(
            completed.stderr,
            "RELEASE DEPENDENCY FREEZE: FAIL: "
            f"{MODULE.PINNED_RELEASE_PYTHON_REQUIRED}\n",
        )

    def test_worker_and_parent_refuse_duplicate_pin_keys(self) -> None:
        self._rewrite_pins(
            lambda text: text.replace(
                '"implementation": "cpython"',
                '"implementation": "cpython", "implementation": "cpython"',
                1,
            )
        )
        completed = self._direct()
        self.assertEqual(completed.returncode, 1)
        self.assertIn("duplicate JSON key: implementation", completed.stderr)
        parent = self._parent()
        self.assertEqual(parent.returncode, 1)
        self.assertIn("does not pin a release Python", parent.stderr)

    def test_worker_refuses_version_pin_drift(self) -> None:
        self._rewrite_pins(
            lambda text: text.replace('"version": "3.14.7"', '"version": "3.14.6"', 1)
        )
        completed = self._direct()
        self.assertEqual(completed.returncode, 1)
        self.assertIn("release Python version pin drifted", completed.stderr)

    def test_worker_refuses_dynamic_loader_environment(self) -> None:
        environment = dict(self.environment)
        environment["DYLD_LIBRARY_PATH"] = "/private/tmp"
        completed = self._direct(environment)
        self.assertEqual(completed.returncode, 1)
        self.assertIn("environment is not scrubbed", completed.stderr)
        self.assertNotIn(MODULE.GIT_REQUIRED, completed.stderr)

    def test_worker_refuses_controller_differing_from_retained_descriptor(self) -> None:
        controller = self.repo / "tools/release_dependency_freeze.py"
        # Identical reviewed bytes, but not the repository controller inode.
        substitute = controller.with_name("substitute_controller.py")
        shutil.copy2(controller, substitute)
        descriptor = os.open(substitute, os.O_RDONLY)
        try:
            completed = subprocess.run(
                [
                    str(self.python),
                    "-I",
                    "-S",
                    f"/dev/fd/{descriptor}",
                    MODULE._AUTHORITATIVE_WORKER_SWITCH,
                    str(descriptor),
                    *self._worker_argv(),
                ],
                check=False,
                cwd="/private/tmp",
                env=self.environment,
                pass_fds=(descriptor,),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        finally:
            os.close(descriptor)
        self.assertEqual(completed.returncode, 1)
        self.assertIn("not the retained repository controller", completed.stderr)


def _der(tag: int, content: bytes) -> bytes:
    if len(content) < 0x80:
        return bytes([tag, len(content)]) + content
    size = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + content


def _der_oid(dotted: str) -> bytes:
    numbers = [int(part) for part in dotted.split(".")]
    body = bytearray([numbers[0] * 40 + numbers[1]])
    for number in numbers[2:]:
        chunk = [number & 0x7F]
        number >>= 7
        while number:
            chunk.append(0x80 | (number & 0x7F))
            number >>= 7
        body.extend(reversed(chunk))
    return _der(0x06, bytes(body))


def _der_int(value: int) -> bytes:
    return _der(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def _der_seq(*parts: bytes) -> bytes:
    return _der(0x30, b"".join(parts))


def _der_name(common_name: str, unit: str) -> bytes:
    return _der_seq(
        _der(0x31, _der_seq(_der_oid("2.5.4.11"), _der(0x0C, unit.encode()))),
        _der(0x31, _der_seq(_der_oid("2.5.4.3"), _der(0x0C, common_name.encode()))),
    )


class _TestRsaKey:
    """Deterministic test-only RSA key; generated per run, never stored."""

    def __init__(self, seed: int) -> None:
        import random

        generator = random.Random(seed)
        self.e = 65537
        while True:
            p = self._prime(generator)
            q = self._prime(generator)
            phi = (p - 1) * (q - 1)
            if p != q and MODULE.math.gcd(self.e, phi) == 1:
                break
        self.n = p * q
        self.d = pow(self.e, -1, phi)

    @staticmethod
    def _prime(generator) -> int:
        small = (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47)
        while True:
            candidate = generator.getrandbits(1024) | (1 << 1023) | (1 << 1022) | 1
            if any(candidate % prime == 0 for prime in small):
                continue
            d, r = candidate - 1, 0
            while d % 2 == 0:
                d //= 2
                r += 1
            for _ in range(24):
                x = pow(generator.randrange(2, candidate - 2), d, candidate)
                if x in (1, candidate - 1):
                    continue
                for _ in range(r - 1):
                    x = pow(x, 2, candidate)
                    if x == candidate - 1:
                        break
                else:
                    break
            else:
                return candidate

    def sign_digest(self, algorithm: str, digest: bytes) -> bytes:
        size = (self.n.bit_length() + 7) // 8
        info = MODULE._apple_digest_info(algorithm, digest, True)
        encoded = b"\x00\x01" + b"\xff" * (size - 3 - len(info)) + b"\x00" + info
        return pow(int.from_bytes(encoded, "big"), self.d, self.n).to_bytes(size, "big")

    def spki(self) -> bytes:
        key = _der_seq(_der_int(self.n), _der_int(self.e))
        return _der_seq(
            _der_seq(_der_oid("1.2.840.113549.1.1.1"), b"\x05\x00"),
            _der(0x03, b"\x00" + key),
        )


def _test_certificate(
    subject: bytes,
    issuer: bytes,
    key: _TestRsaKey,
    issuer_key: _TestRsaKey,
    serial: int,
    *,
    ca: bool = False,
    path_length: int | None = None,
    key_usage: int | None = None,
    extensions: bytes | None = None,
) -> bytes:
    """Test certificate; ``ca`` adds critical basicConstraints cA like Apple's CAs.

    ``key_usage`` is the first keyUsage byte (0x06 is keyCertSign and cRLSign,
    as the Apple Root CA and WWDR G3 carry). ``extensions`` replaces the whole
    [3] extensions field for malformed-input cases.
    """

    algorithm = _der_seq(_der_oid("1.2.840.113549.1.1.11"), b"\x05\x00")
    validity = _der_seq(_der(0x17, b"260101000000Z"), _der(0x17, b"360101000000Z"))
    if extensions is None:
        entries = b""
        if ca:
            constraints = _der(0x01, b"\xff") + (
                _der_int(path_length) if path_length is not None else b""
            )
            entries += _der_seq(
                _der_oid("2.5.29.19"), _der(0x01, b"\xff"), _der(0x04, _der_seq(constraints))
            )
        if key_usage is not None:
            entries += _der_seq(
                _der_oid("2.5.29.15"),
                _der(0x01, b"\xff"),
                _der(0x04, _der(0x03, bytes([1, key_usage]))),
            )
        extensions = _der(0xA3, _der_seq(entries)) if entries else b""
    tbs = _der_seq(
        _der(0xA0, _der_int(2)),
        _der_int(serial),
        algorithm,
        issuer,
        validity,
        subject,
        key.spki(),
        extensions,
    )
    signature = issuer_key.sign_digest("sha256", hashlib.sha256(tbs).digest())
    return _der_seq(tbs, algorithm, _der(0x03, b"\x00" + signature))


class AppleReleaseArtifactValidatorTests(unittest.TestCase):
    """Real IPA and PKG validators (round R11a, Astra CE-04 follow-up).

    The fixtures are built here: a synthetic arm64 Mach-O whose CodeDirectory
    hashes are computed over its real pages, a CMS SignedData and XAR RSA
    signature made with test-only RSA keys, and a test root that replaces the
    pinned Apple Root CA digest only inside these tests.
    """

    TEAM = "5YT8H4U72M"
    _keys: dict[str, _TestRsaKey] = {}

    @classmethod
    def setUpClass(cls) -> None:
        if not cls._keys:
            cls._keys = {name: _TestRsaKey(seed) for name, seed in (("root", 11), ("ca", 12), ("leaf", 13), ("rogue", 14))}
        keys = cls._keys
        cls.root_name = _der_name("Test Apple Root CA", "Test Root")
        cls.ca_name = _der_name("Test Apple Worldwide Developer Relations", "G3")
        cls.root = _test_certificate(
            cls.root_name, cls.root_name, keys["root"], keys["root"], 1, ca=True, key_usage=0x06
        )
        cls.ca = _test_certificate(
            cls.ca_name, cls.root_name, keys["ca"], keys["root"], 2,
            ca=True, path_length=0, key_usage=0x06,
        )

    def setUp(self) -> None:
        patcher = mock.patch.object(
            MODULE, "APPLE_ROOT_CA_SHA256", hashlib.sha256(self.root).hexdigest()
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _leaf(self, common_name: str, team: str | None = None, key: str = "leaf", serial: int = 3) -> bytes:
        return _test_certificate(
            _der_name(common_name, team or self.TEAM), self.ca_name, self._keys[key], self._keys["ca"], serial
        )

    def _cms(self, content: bytes, leaf: bytes, key: str = "leaf", serial: int = 3) -> bytes:
        sha256 = _der_seq(_der_oid("2.16.840.1.101.3.4.2.1"), b"\x05\x00")
        attributes = _der_seq(
            _der_oid("1.2.840.113549.1.9.3"), _der(0x31, _der_oid("1.2.840.113549.1.7.1"))
        ) + _der_seq(
            _der_oid("1.2.840.113549.1.9.4"), _der(0x31, _der(0x04, hashlib.sha256(content).digest()))
        )
        signature = self._keys[key].sign_digest("sha256", hashlib.sha256(_der(0x31, attributes)).digest())
        signer = _der_seq(
            _der_int(1),
            _der_seq(self.ca_name, _der_int(serial)),
            sha256,
            _der(0xA0, attributes),
            _der_seq(_der_oid("1.2.840.113549.1.1.1"), b"\x05\x00"),
            _der(0x04, signature),
        )
        signed_data = _der_seq(
            _der_int(1),
            _der(0x31, sha256),
            _der_seq(_der_oid("1.2.840.113549.1.7.1")),
            _der(0xA0, leaf + self.ca + self.root),
            _der(0x31, signer),
        )
        return _der_seq(_der_oid("1.2.840.113549.1.7.2"), _der(0xA0, signed_data))

    def _macho(
        self,
        info: bytes | None,
        resources: bytes | None,
        identifier: str = "org.winsvpn.app",
        team: str | None = None,
        common_name: str = "Apple Distribution: Win's VPN Inc (5YT8H4U72M)",
        signed: bool = True,
        code_size: int = 3 * 4096 + 1000,
        bits: int = 64,
        universal: bool = False,
    ) -> bytes:
        if universal:
            # watchOS style: an arm64 slice and an arm64_32 (32-bit) slice,
            # each signed on its own, behind a big-endian fat header.
            slices = [
                self._macho(info, resources, identifier, team, common_name, signed, code_size, bits=width)
                for width in (64, 32)
            ]
            header = MODULE.struct.pack(">II", 0xCAFEBABE, len(slices))
            body = b""
            offset = 4096
            for width, image in zip((64, 32), slices):
                cpu = 0x0100000C if width == 64 else 0x0200000C
                header += MODULE.struct.pack(">IIIII", cpu, 0, offset, len(image), 12)
                padded = image + bytes(-len(image) % 4096)
                body += padded
                offset += len(padded)
            return header + bytes(4096 - len(header)) + body
        data_size = 16384
        data_offset = (code_size + 15) & ~15
        if bits == 64:
            header = MODULE.struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 16, 0, 0)
        else:
            header = MODULE.struct.pack("<7I", 0xFEEDFACE, 0x0200000C, 0, 2, 1, 16, 0)
        command = MODULE.struct.pack("<4I", 0x1D, 16, data_offset, data_size)
        code = header + command
        code += bytes((index * 7 + 3) % 251 for index in range(data_offset - len(code)))
        requirements = MODULE.struct.pack(">III", 0xFADE0C01, 12, 0)
        specials = [info, requirements, resources]
        ident = identifier.encode() + b"\x00"
        team_bytes = (team or self.TEAM).encode() + b"\x00"
        ident_offset = 88
        team_offset = ident_offset + len(ident)
        hash_offset = team_offset + len(team_bytes) + 32 * len(specials)
        code_count = (data_offset + 4095) // 4096
        length = hash_offset + 32 * code_count
        directory = MODULE.struct.pack(
            ">9I4BI", 0xFADE0C02, length, 0x20400, 0, hash_offset, ident_offset,
            len(specials), code_count, data_offset, 32, 2, 0, 12, 0,
        )
        directory += MODULE.struct.pack(">II", 0, team_offset) + MODULE.struct.pack(">IQ", 0, 0)
        directory += MODULE.struct.pack(">QQQ", 0, 0, 0) + ident + team_bytes
        for data in reversed(specials):
            directory += hashlib.sha256(data).digest() if data is not None else bytes(32)
        for index in range(code_count):
            directory += hashlib.sha256(code[index * 4096 : (index + 1) * 4096]).digest()
        cms = self._cms(directory, self._leaf(common_name)) if signed else b""
        blobs = [(0, directory), (2, requirements), (0x10000, MODULE.struct.pack(">II", 0xFADE0B01, 8 + len(cms)) + cms)]
        offset = 12 + 8 * len(blobs)
        index_bytes = b""
        body = b""
        for slot, blob in blobs:
            index_bytes += MODULE.struct.pack(">II", slot, offset + len(body))
            body += blob
        superblob = MODULE.struct.pack(">III", 0xFADE0CC0, offset + len(body), len(blobs)) + index_bytes + body
        self.assertLessEqual(len(superblob), data_size)
        return code + superblob + bytes(data_size - len(superblob))

    @staticmethod
    def _cdhash(binary: bytes) -> bytes:
        if binary[:4] == b"\xca\xfe\xba\xbe":
            offset, size = MODULE.struct.unpack_from(">II", binary, 16)
            binary = binary[offset : offset + size]
        header_size = 32 if binary[:4] == b"\xcf\xfa\xed\xfe" else 28
        data_offset = MODULE.struct.unpack_from("<I", binary, header_size + 8)[0]
        superblob = binary[data_offset:]
        cd_offset = MODULE.struct.unpack_from(">I", superblob, 16)[0]
        cd_length = MODULE.struct.unpack_from(">I", superblob, cd_offset + 4)[0]
        return hashlib.sha256(superblob[cd_offset : cd_offset + cd_length]).digest()[:20]

    def _profile(self) -> bytes:
        return b"\x30\x80" + b"<plist><key>TeamIdentifier</key><string>" + self.TEAM.encode() + b"</string></plist>" + bytes(32)

    def _bundle(self, root: str, executable: str, identifier: str, files: dict[str, bytes], nested: dict[str, bytes] | None = None, **macho) -> dict[str, bytes]:
        info = MODULE.plistlib.dumps({"CFBundleExecutable": executable, "CFBundleIdentifier": identifier})
        seal: dict[str, object] = {name: {"hash2": hashlib.sha256(payload).digest()} for name, payload in files.items()}
        for relative, binary in (nested or {}).items():
            seal[relative] = {"cdhash": self._cdhash(binary), "requirement": "anchor apple generic"}
        resources = MODULE.plistlib.dumps({"files": {}, "files2": seal, "rules": {}, "rules2": {}})
        entries = {f"{root}/{name}": payload for name, payload in files.items()}
        entries[f"{root}/Info.plist"] = info
        entries[f"{root}/_CodeSignature/CodeResources"] = resources
        entries[f"{root}/{executable}"] = self._macho(info, resources, identifier, **macho)
        return entries

    def _ipa_entries(self, **macho) -> dict[str, bytes]:
        app = "Payload/Runner.app"
        watch = self._bundle(
            f"{app}/Watch/WinsWatch.app", "WinsWatch", "org.winsvpn.app.watchkitapp",
            {"embedded.mobileprovision": self._profile(), "Assets.car": b"watch-assets"},
            universal=True,
        )
        watch_binary = watch[f"{app}/Watch/WinsWatch.app/WinsWatch"]
        # A framework with no resources has an empty files2 seal (real Xcode output).
        framework = self._bundle(f"{app}/Frameworks/App.framework", "App", "io.flutter.flutter.app", {})
        entries = self._bundle(
            app, "Runner", "org.winsvpn.app",
            {"embedded.mobileprovision": self._profile(), "Assets.car": b"assets"},
            nested={
                "Watch/WinsWatch.app": watch_binary,
                "Frameworks/App.framework": framework[f"{app}/Frameworks/App.framework/App"],
            },
            **macho,
        )
        entries.update(watch)
        entries.update(framework)
        entries["Symbols/0000.symbols"] = b"symbols"
        return entries

    @staticmethod
    def _zip(entries: dict[str, bytes]) -> bytes:
        output = MODULE.io.BytesIO()
        with MODULE.zipfile.ZipFile(output, "w", compression=MODULE.zipfile.ZIP_DEFLATED) as archive:
            for name, payload in entries.items():
                archive.writestr(name, payload)
        return output.getvalue()

    def _validate_ipa(self, payload: bytes) -> None:
        MODULE._validate_release_artifact_bytes("ios", "app-store-local", "Win's VPN.ipa", payload)

    def _validate_pkg(self, payload: bytes) -> None:
        MODULE._validate_release_artifact_bytes("macos", "app-store-local", "Win's VPN.pkg", payload)

    def _pkg(
        self,
        common_name: str = "3rd Party Mac Developer Installer: Win's VPN Inc (5YT8H4U72M)",
        algorithm: str = "sha1",
        corrupt_checksum: bool = False,
        signed: bool = True,
        corrupt_data: bool = False,
    ) -> bytes:
        distribution = b'<?xml version="1.0"?><installer-gui-script minSpecVersion="2"/>'
        payload = b"component-payload" * 64
        digest_size = hashlib.new(algorithm).digest_size
        leaf = self._leaf(common_name)
        signature_xml = ""
        if signed:
            certificates = "".join(
                f"<X509Certificate>{base64.b64encode(item).decode()}</X509Certificate>"
                for item in (leaf, self.ca, self.root)
            )
            signature_xml = (
                f'<signature style="RSA"><offset>{digest_size}</offset><size>256</size>'
                f'<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data>{certificates}</X509Data></KeyInfo></signature>'
            )
        data_offset = digest_size + (256 if signed else 0)
        files = ""
        heap_files = b""
        for index, (name, content) in enumerate((("Distribution", distribution), ("Payload", payload)), start=1):
            offset = data_offset + len(heap_files)
            files += (
                f'<file id="{index}"><name>{name}</name><type>file</type><data><offset>{offset}</offset>'
                f"<length>{len(content)}</length><size>{len(content)}</size>"
                f'<encoding style="application/octet-stream"/>'
                f'<archived-checksum style="sha1">{hashlib.sha1(content).hexdigest()}</archived-checksum>'
                f'<extracted-checksum style="sha1">{hashlib.sha1(content).hexdigest()}</extracted-checksum></data></file>'
            )
            heap_files += content
        toc = (
            '<?xml version="1.0" encoding="UTF-8"?><xar><toc>'
            f'<checksum style="{algorithm}"><offset>0</offset><size>{digest_size}</size></checksum>'
            + signature_xml + files + "</toc></xar>"
        ).encode()
        compressed = MODULE.zlib.compress(toc)
        if algorithm == "sha1":
            header = b"xar!" + MODULE.struct.pack(">HHQQI", 28, 1, len(compressed), len(toc), 1)
        else:
            name = algorithm.encode().ljust(36, b"\x00")
            header = b"xar!" + MODULE.struct.pack(">HHQQI", 64, 1, len(compressed), len(toc), 3) + name
        checksum = hashlib.new(algorithm, compressed).digest()
        if corrupt_checksum:
            checksum = bytes([checksum[0] ^ 1]) + checksum[1:]
        heap = checksum
        if signed:
            heap += self._keys["leaf"].sign_digest(algorithm, checksum)
        if corrupt_data:
            heap_files = heap_files[:-1] + bytes([heap_files[-1] ^ 1])
        return header + compressed + heap + heap_files

    def test_signed_ipa_with_watch_app_is_accepted(self) -> None:
        self._validate_ipa(self._zip(self._ipa_entries()))

    def test_flipped_code_byte_is_refused(self) -> None:
        entries = self._ipa_entries()
        binary = bytearray(entries["Payload/Runner.app/Runner"])
        binary[5000] ^= 0x01
        entries["Payload/Runner.app/Runner"] = bytes(binary)
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "code page 1 does not match"):
            self._validate_ipa(self._zip(entries))

    def test_flipped_watch_code_byte_is_refused(self) -> None:
        entries = self._ipa_entries()
        name = "Payload/Runner.app/Watch/WinsWatch.app/WinsWatch"
        binary = bytearray(entries[name])
        binary[4096 + 100] ^= 0x01
        entries[name] = bytes(binary)
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "WinsWatch.app executable slice 0 code page 0"):
            self._validate_ipa(self._zip(entries))
        # The arm64_32 slice is verified too.
        binary = bytearray(self._ipa_entries()[name])
        second = MODULE.struct.unpack_from(">I", binary, 8 + 20 + 8)[0]
        binary[second + 100] ^= 0x01
        entries = self._ipa_entries()
        entries[name] = bytes(binary)
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "WinsWatch.app executable slice 1 code page 0"):
            self._validate_ipa(self._zip(entries))

    def test_ad_hoc_or_unsigned_ipa_is_refused(self) -> None:
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "no CMS signature"):
            self._validate_ipa(self._zip(self._ipa_entries(signed=False)))

    def test_ipa_from_another_team_or_development_identity_is_refused(self) -> None:
        for kwargs, reason in (
            ({"team": "ABCDE12345"}, "not the release team"),
            ({"common_name": "Apple Development: Someone (5YT8H4U72M)"}, "release team's Apple Distribution identity"),
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaisesRegex(MODULE.DependencyFreezeError, reason):
                    self._validate_ipa(self._zip(self._ipa_entries(**kwargs)))

    def test_ipa_chain_to_an_unpinned_root_is_refused(self) -> None:
        with mock.patch.object(MODULE, "APPLE_ROOT_CA_SHA256", "0" * 64):
            with self.assertRaisesRegex(MODULE.DependencyFreezeError, "pinned Apple Root CA"):
                self._validate_ipa(self._zip(self._ipa_entries()))

    def test_chain_issuer_must_be_a_certification_authority(self) -> None:
        # R22 X1 F-01 / X1-1: every developer holds an end-entity certificate
        # under the Apple root. Its key must not be able to issue a leaf that
        # names the release team, even though every RSA signature verifies.
        parse = lambda der: MODULE._parse_apple_certificate(der, "probe")  # noqa: E731
        keys = self._keys
        team_name = _der_name(f"Apple Distribution: Win's VPN Inc ({self.TEAM})", self.TEAM)
        attacker_name = _der_name("Apple Distribution: Other Team (ABCDE12345)", "ABCDE12345")
        sub_name = _der_name("Test Sub CA", "Sub")
        honest = _test_certificate(team_name, self.ca_name, keys["leaf"], keys["ca"], 3)
        MODULE._require_apple_certificate_chain(
            parse(honest),
            [parse(honest), parse(self.ca), parse(self.root)],
            MODULE.APPLE_IPA_SIGNER_PREFIXES,
            "probe",
        )
        issuers = {
            "end-entity issuer": _test_certificate(
                attacker_name, self.ca_name, keys["leaf"], keys["ca"], 7
            ),
            "CA issuer without keyCertSign": _test_certificate(
                attacker_name, self.ca_name, keys["leaf"], keys["ca"], 8,
                ca=True, key_usage=0x80,
            ),
            # The WWDR-style CA carries pathLenConstraint 0, so no CA may sit
            # between it and a leaf.
            "sub-CA below a pathLen 0 CA": _test_certificate(
                sub_name, self.ca_name, keys["leaf"], keys["ca"], 9,
                ca=True, key_usage=0x06,
            ),
        }
        for case, issuer in issuers.items():
            with self.subTest(case=case):
                issuer_name = attacker_name if case != "sub-CA below a pathLen 0 CA" else sub_name
                forged = _test_certificate(team_name, issuer_name, keys["rogue"], keys["leaf"], 10)
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError, "not a certification authority"
                ):
                    MODULE._require_apple_certificate_chain(
                        parse(forged),
                        [parse(forged), parse(issuer), parse(self.ca), parse(self.root)],
                        MODULE.APPLE_IPA_SIGNER_PREFIXES,
                        "probe",
                    )

    def test_certificate_extensions_must_not_repeat(self) -> None:
        constraints = _der_seq(
            _der_oid("2.5.29.19"), _der(0x01, b"\xff"), _der(0x04, _der_seq(_der(0x01, b"\xff")))
        )
        for case, extensions in (
            ("repeated basicConstraints", _der(0xA3, _der_seq(constraints + constraints))),
            (
                "repeated extensions field",
                _der(0xA3, _der_seq(constraints)) + _der(0xA3, _der_seq(constraints)),
            ),
        ):
            with self.subTest(case=case):
                certificate = _test_certificate(
                    self.ca_name, self.root_name, self._keys["ca"], self._keys["root"], 2,
                    extensions=extensions,
                )
                with self.assertRaisesRegex(MODULE.DependencyFreezeError, "certificate is malformed"):
                    MODULE._parse_apple_certificate(certificate, "probe")

    def test_rsa_verification_refuses_oversized_keys(self) -> None:
        # R22 X1 X1-2: the key comes from artifact DER, so its size bounds the
        # cost of the modular exponentiation.
        certificate = MODULE._parse_apple_certificate(
            self._leaf(f"Apple Distribution: Win's VPN Inc ({self.TEAM})"), "probe"
        )
        key = self._keys["leaf"]
        digest = hashlib.sha256(b"probe").digest()
        signature = key.sign_digest("sha256", digest)
        verify = MODULE._apple_rsa_signature_verifies
        self.assertTrue(verify(certificate, "sha256", digest, signature))
        # e + (e*d - 1) is congruent to e modulo lambda(n): the same signature
        # verifies under this 2000-plus-bit exponent unless its size is refused.
        wide_exponent = MODULE.dataclasses.replace(
            certificate, exponent=key.e + (key.e * key.d - 1)
        )
        self.assertFalse(verify(wide_exponent, "sha256", digest, signature))
        # An 8800-bit modulus n = s**3 - EM makes s a valid e = 3 signature.
        size = 1100
        info = MODULE._apple_digest_info("sha256", digest, True)
        encoded = int.from_bytes(
            b"\x00\x01" + b"\xff" * (size - 3 - len(info)) + b"\x00" + info, "big"
        )
        target = (1 << (8 * size - 1)) + encoded
        low, high = 0, 1 << (target.bit_length() // 3 + 2)
        while low < high:
            middle = (low + high) // 2
            if middle**3 < target:
                low = middle + 1
            else:
                high = middle
        wide_modulus = MODULE.dataclasses.replace(
            certificate, modulus=low**3 - encoded, exponent=3
        )
        self.assertEqual(wide_modulus.modulus.bit_length(), 8 * size)
        self.assertFalse(verify(wide_modulus, "sha256", digest, low.to_bytes(size, "big")))

    def test_ipa_seal_detects_modified_missing_and_unsealed_files(self) -> None:
        cases = []
        modified = self._ipa_entries()
        modified["Payload/Runner.app/Assets.car"] = b"assetz"
        cases.append((modified, "sealed file Assets.car was modified"))
        missing = self._ipa_entries()
        del missing["Payload/Runner.app/embedded.mobileprovision"]
        cases.append((missing, "lacks the release provisioning profile"))
        extra = self._ipa_entries()
        extra["Payload/Runner.app/unsealed.bin"] = b"x"
        cases.append((extra, "file unsealed.bin is not sealed"))
        plugin = self._ipa_entries()
        plugin["Payload/Runner.app/PlugIns/Tunnel.appex/Info.plist"] = b"x"
        cases.append((plugin, "not sealed"))
        resources = self._ipa_entries()
        resources["Payload/Runner.app/_CodeSignature/CodeResources"] += b"\n"
        cases.append((resources, "special slot 3 does not bind"))
        info = self._ipa_entries()
        info["Payload/Runner.app/Info.plist"] = info["Payload/Runner.app/Info.plist"].replace(b"org.winsvpn.app", b"org.winsvpn.apq")
        cases.append((info, "special slot 1 does not bind"))
        for index, (entries, reason) in enumerate(cases):
            with self.subTest(case=index):
                with self.assertRaisesRegex(MODULE.DependencyFreezeError, reason):
                    self._validate_ipa(self._zip(entries))

    def test_ipa_with_two_apps_or_wrong_target_or_suffix_is_refused(self) -> None:
        entries = self._ipa_entries()
        entries["Payload/Other.app/Info.plist"] = b"x"
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "exactly one Payload"):
            self._validate_ipa(self._zip(entries))
        payload = self._zip(self._ipa_entries())
        for target, name in (("developer-id", "Win's VPN.ipa"), ("app-store-local", "Win's VPN.pkg")):
            with self.subTest(target=target, name=name):
                with self.assertRaisesRegex(MODULE.DependencyFreezeError, "no reviewed cryptographic IPA validator"):
                    MODULE._validate_release_artifact_bytes("ios", target, name, payload)

    def test_signed_pkg_is_accepted_with_sha1_and_sha256_toc(self) -> None:
        for algorithm in ("sha1", "sha256"):
            with self.subTest(algorithm=algorithm):
                self._validate_pkg(self._pkg(algorithm=algorithm))

    def test_pkg_corruption_canaries_are_refused(self) -> None:
        good = self._pkg()
        cases = (
            (self._pkg(corrupt_checksum=True), "TOC checksum does not match"),
            (good[:-40], "lies outside the heap"),
            (self._pkg(signed=False), "signature is missing"),
            (self._pkg(corrupt_data=True), "does not match its archived checksum"),
            (self._pkg(common_name="Developer ID Installer: Win's VPN Inc (5YT8H4U72M)"), "3rd Party Mac Developer Installer identity"),
            (good[:200] + bytes([good[200] ^ 1]) + good[201:], "XAR"),
        )
        for index, (payload, reason) in enumerate(cases):
            with self.subTest(case=index):
                with self.assertRaisesRegex(MODULE.DependencyFreezeError, reason):
                    self._validate_pkg(payload)
        signature_start = len(good) - len(b"component-payload" * 64) - len(b'<?xml version="1.0"?><installer-gui-script minSpecVersion="2"/>') - 256
        flipped = bytearray(good)
        flipped[signature_start + 10] ^= 0x01
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "XAR signature does not verify"):
            self._validate_pkg(bytes(flipped))
        with mock.patch.object(MODULE, "APPLE_ROOT_CA_SHA256", "0" * 64):
            with self.assertRaisesRegex(MODULE.DependencyFreezeError, "pinned Apple Root CA"):
                self._validate_pkg(good)

    def test_pkg_signed_by_an_untrusted_leaf_key_is_refused(self) -> None:
        with mock.patch.object(self._keys["leaf"], "d", self._keys["rogue"].d):
            forged = self._pkg()
        with self.assertRaisesRegex(MODULE.DependencyFreezeError, "XAR signature does not verify"):
            self._validate_pkg(forged)

    def test_ce04_placeholders_stay_refused(self) -> None:
        legacy = DependencyFreezeTests
        placeholders = (
            ("ios", "Win's VPN.ipa", legacy._valid_ipa_payload()),
            ("ios", "Win's VPN.ipa", legacy._valid_ipa_payload(with_profile=False)),
            ("macos", "Win's VPN.pkg", legacy._xar_payload()),
            ("macos", "Win's VPN.pkg", legacy._xar_payload(namespaced=False)),
            ("macos", "Win's VPN.pkg", legacy._xar_payload(signed=False)),
            ("macos", "Win's VPN.pkg", legacy._valid_xar_payload()),
        )
        for index, (platform, name, payload) in enumerate(placeholders):
            with self.subTest(case=index):
                with self.assertRaises(MODULE.DependencyFreezeError):
                    MODULE._validate_release_artifact_bytes(platform, "app-store-local", name, payload)


class GitTrackedFreezeTests(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("git is required for tracked-tree freeze tests")
        MODULE._FIXTURE_MODE = False
        MODULE._PRODUCTION_REQUIRED = False
        MODULE._POST_SELECT_HOOK = None
        MODULE._POST_INPUT_CAPTURE_HOOK = None
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name)

    def tearDown(self) -> None:
        MODULE._POST_SELECT_HOOK = None
        MODULE._POST_INPUT_CAPTURE_HOOK = None
        MODULE._FIXTURE_MODE = False
        MODULE._PRODUCTION_REQUIRED = False
        self.temporary.cleanup()

    def _git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        for key in (
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_COMMON_DIR",
        ):
            env.pop(key, None)
        env["GIT_CONFIG_GLOBAL"] = os.devnull
        env["GIT_CONFIG_SYSTEM"] = os.devnull
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["GIT_AUTHOR_NAME"] = "Freeze Test"
        env["GIT_AUTHOR_EMAIL"] = "freeze-test@winsvpn.example"
        env["GIT_COMMITTER_NAME"] = "Freeze Test"
        env["GIT_COMMITTER_EMAIL"] = "freeze-test@winsvpn.example"
        env["GIT_TERMINAL_PROMPT"] = "0"
        return subprocess.run(
            ["git", "-C", str(self.repo), *args],
            check=check,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _write(self, relative: str, contents: str) -> pathlib.Path:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        return path

    def _commit_tree(self, files: dict[str, str], *, message: str = "tracked") -> None:
        self._git("init", "-q", "-b", "main")
        for relative, contents in files.items():
            self._write(relative, contents)
            self._git("add", "--", relative.replace("\\", "/"))
        self._git(
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "--no-gpg-sign",
            "-m",
            message,
        )

    def test_hostile_untracked_xray_arm64_is_rejected(self) -> None:
        self._commit_tree(
            {
                ".gitignore": ".artifacts/\n",
                "installer/windows/dependencies/xray.exe": "tracked-xray\n",
            }
        )
        self._write(
            "installer/windows/dependencies/xray-arm64.exe",
            "untracked-xray-arm64\n",
        )
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, MODULE.GIT_UNTRACKED_INPUT
        ):
            MODULE.input_state(self.repo, ("installer/windows",))

    def test_git_literal_backslash_path_cannot_alias_untracked_shipping_path(self) -> None:
        self._git("init", "-q", "-b", "main")
        literal = self._write("lib/alias\\payload.dart", "same bytes\n")
        self._git("add", "--", "lib/alias\\payload.dart")
        self._git(
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "--no-gpg-sign",
            "-m",
            "literal-backslash",
        )
        literal.unlink()
        self._write("lib/alias/payload.dart", "same bytes\n")
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "Git .* path is not canonical"
        ):
            MODULE.input_state(self.repo, ("lib",))

    def test_hostile_staged_only_input_is_rejected(self) -> None:
        self._commit_tree({"lib/main.dart": "void main() {}\n"})
        self._write("lib/extra.dart", "staged only\n")
        self._git("add", "--", "lib/extra.dart")
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, MODULE.GIT_STAGED_ONLY_INPUT
        ):
            MODULE.input_state(self.repo, ("lib",))

    def test_dirty_source_outside_the_inputs_names_the_path(self) -> None:
        # Rehearsal r51: the refusal printed the status code ("M") because the
        # (xy, path) pairs were unpacked in the wrong order.
        self._commit_tree(
            {
                "lib/main.dart": "void main() {}\n",
                "app_store/apple/artifacts/release_candidate.json": "{}\n",
            }
        )
        self._write("app_store/apple/artifacts/release_candidate.json", '{"changed": true}\n')
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError,
            r"source state is not immutable/clean according to the local release policy: "
            r"app_store/apple/artifacts/release_candidate\.json$",
        ):
            MODULE.input_state(self.repo, ("lib",))

    def test_hostile_dirty_after_freeze_is_rejected(self) -> None:
        self._commit_tree({"lib/main.dart": "void main() {}\n"})

        def hook() -> None:
            self._write("lib/dirty-after-freeze.dart", "inserted after capture\n")

        previous = MODULE._POST_INPUT_CAPTURE_HOOK
        MODULE._POST_INPUT_CAPTURE_HOOK = hook
        try:
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError,
                r"untracked filesystem file is not a tracked Git tree input|"
                r"source state is not immutable/clean|"
                r"dependency inputs changed during freeze capture",
            ):
                MODULE.input_state(self.repo, ("lib",))
        finally:
            MODULE._POST_INPUT_CAPTURE_HOOK = previous

    def test_hostile_symlink_input_is_rejected(self) -> None:
        self._commit_tree({"lib/main.dart": "void main() {}\n"})
        link = self.repo / "lib" / "alias.dart"
        try:
            link.symlink_to("main.dart")
        except (OSError, NotImplementedError) as suc:
            raise unittest.SkipTest(
                "Symlink creation is unavailable on this host"
            ) from suc
        self._git("add", "--", "lib/alias.dart")
        self._git(
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "--no-gpg-sign",
            "-m",
            "tracked symlink",
        )
        link.unlink()
        self._write("lib/alias.dart", "regular replacement of git symlink\n")
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, MODULE.GIT_SYMLINK_INPUT
        ):
            MODULE.input_state(self.repo, ("lib",))

    def test_tracked_input_omission_is_rejected_against_git_denominator(self) -> None:
        self._commit_tree(
            {
                "lib/main.dart": "void main() {}\n",
                "lib/omitted.dart": "const omitted = true;\n",
            }
        )
        original = MODULE._selected_paths

        def omit_one(*args, **kwargs):
            selected, directories = original(*args, **kwargs)
            return (
                [
                    item
                    for item in selected
                    if item[0] != "lib/omitted.dart"
                ],
                directories,
            )

        with mock.patch.object(MODULE, "_selected_paths", side_effect=omit_one):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, MODULE.GIT_OMITTED_INPUT
            ):
                MODULE.input_state(self.repo, ("lib",))

    def test_assume_unchanged_cannot_hide_dirty_tracked_input(self) -> None:
        self._commit_tree({"lib/main.dart": "void main() {}\n"})
        self._git("update-index", "--assume-unchanged", "lib/main.dart")
        self._write("lib/main.dart", "void hiddenChange() {}\n")
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, MODULE.GIT_INDEX_WORKTREE_SPLIT
        ):
            MODULE.input_state(self.repo, ("lib",))

    def test_fingerprint_is_local_and_audit_retains_git_identity(self) -> None:
        self._commit_tree({"lib/main.dart": "void main() {}\n"})
        initial = MODULE.input_state(self.repo, ("lib",))
        self._git(
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "--allow-empty",
            "--no-gpg-sign",
            "-m",
            "same tree new head",
        )
        new_head = MODULE.input_state(self.repo, ("lib",))
        self.assertEqual(initial.fingerprint_sha256, new_head.fingerprint_sha256)
        self.assertEqual(initial.files, new_head.files)
        self.assertIsNotNone(initial.git_audit)
        self.assertIsNotNone(new_head.git_audit)
        self.assertNotEqual(initial.git_audit.head, new_head.git_audit.head)
        self.assertEqual(initial.git_audit.tree, new_head.git_audit.tree)
        self.assertEqual(
            initial.git_audit.selected_blobs, new_head.git_audit.selected_blobs
        )

        self._write("docs/unrelated.txt", "new root tree\n")
        self._git("add", "--", "docs/unrelated.txt")
        self._git(
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "--no-gpg-sign",
            "-m",
            "new root tree",
        )
        new_tree = MODULE.input_state(self.repo, ("lib",))
        self.assertEqual(new_head.fingerprint_sha256, new_tree.fingerprint_sha256)
        self.assertEqual(new_head.files, new_tree.files)
        self.assertNotEqual(new_head.git_audit.tree, new_tree.git_audit.tree)
        self.assertEqual(
            new_head.git_audit.selected_blobs, new_tree.git_audit.selected_blobs
        )

        source = self.repo / "lib/main.dart"
        os.chmod(source, 0o755)
        self._git("add", "--", "lib/main.dart")
        self._git(
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "--no-gpg-sign",
            "-m",
            "executable mode",
        )
        executable = MODULE.input_state(self.repo, ("lib",))
        self.assertNotEqual(new_tree.fingerprint_sha256, executable.fingerprint_sha256)
        self.assertEqual(new_tree.files, executable.files)

    def test_manifest_git_audit_binds_selected_blob_identity(self) -> None:
        self._commit_tree({"lib/main.dart": "void main() {}\n"})
        state = MODULE.input_state(self.repo, ("lib",))
        record = MODULE._state_record(state)
        audit = record["git_audit"]
        self.assertIsInstance(audit, dict)
        selected = audit["selected_blobs"]
        self.assertTrue(selected)
        original = selected[0]["oid"]
        selected[0]["oid"] = ("0" if original[0] != "0" else "1") * len(original)
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "dependency Git audit changed"
        ):
            MODULE._assert_state_matches(
                "Git audit", record, state, require_files=True
            )

    def test_manifest_git_state_contains_only_semantically_bound_fields(self) -> None:
        self._commit_tree({"lib/main.dart": "void main() {}\n"})
        state = MODULE.input_state(self.repo, ("lib",))
        record = MODULE._state_record(state)
        audit = record["git_audit"]
        self.assertNotIn("head", audit)
        self.assertNotIn("tree", audit)
        self.assertEqual(
            audit["binding_scope"], "selected-blobs-semantic-v1"
        )
        audit["binding_scope"] = "audit-only"
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError, "semantic binding scope is invalid"
        ):
            MODULE._validate_state_record(record, require_files=True)

    def test_unbound_git_head_tree_fields_and_selected_blob_drift_are_rejected(self) -> None:
        self._commit_tree({"lib/main.dart": "void main() {}\n"})
        state = MODULE.input_state(self.repo, ("lib",))
        record = MODULE._state_record(state)
        for field in ("head", "tree"):
            hostile = json.loads(json.dumps(record))
            hostile["git_audit"][field] = "0" * 40
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError,
                    "Dependency input Git audit schema fields are invalid",
                ):
                    MODULE._validate_state_record(hostile, require_files=True)

        original = json.loads(json.dumps(record))
        self._git(
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "--allow-empty",
            "--no-gpg-sign",
            "-m",
            "unrelated head drift",
        )
        MODULE._assert_state_matches(
            "Semantic Git binding",
            original,
            MODULE.input_state(self.repo, ("lib",)),
            require_files=True,
        )
        self._write("lib/main.dart", "void changed() {}\n")
        self._git("add", "--", "lib/main.dart")
        self._git(
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "--no-gpg-sign",
            "-m",
            "selected blob drift",
        )
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError,
            "dependency inputs changed|dependency file details changed|Git audit changed",
        ):
            MODULE._assert_state_matches(
                "Semantic Git binding",
                original,
                MODULE.input_state(self.repo, ("lib",)),
                require_files=True,
            )

    def test_imported_controller_from_another_tree_cannot_execute(self) -> None:
        self._commit_tree(
            {"tools/release_dependency_freeze.py": SCRIPT.read_text(encoding="utf-8")}
        )
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError,
            "not the reviewed repository controller",
        ):
            MODULE.input_state(self.repo, ("tools/release_dependency_freeze.py",))

    def test_git_uses_fixed_absolute_executable_and_constructed_environment(self) -> None:
        self._commit_tree({"lib/main.dart": "void main() {}\n"})
        fake = self._write("fake-bin/git", "#!/bin/sh\nprintf poisoned\\n\n")
        os.chmod(fake, 0o755)
        poisoned_env = {
            "PATH": str(fake.parent),
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_VALUE_0": "poisoned",
            "DYLD_INSERT_LIBRARIES": "/tmp/poisoned.dylib",
        }
        with mock.patch.dict(os.environ, poisoned_env, clear=False):
            output = MODULE._run_git(self.repo, "--version").decode("ascii")
            env = MODULE._git_env()
        self.assertTrue(output.startswith("git version "))
        self.assertEqual(
            env,
            {
                "GIT_ATTR_NOSYSTEM": "1",
                "GIT_CONFIG_COUNT": "2",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_KEY_0": "core.fsmonitor",
                "GIT_CONFIG_KEY_1": "core.hooksPath",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_CONFIG_VALUE_0": "false",
                "GIT_CONFIG_VALUE_1": os.devnull,
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_PAGER": "cat",
                "GIT_TERMINAL_PROMPT": "0",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            },
        )
        with mock.patch.object(MODULE, "_REVIEWED_GIT_EXECUTABLE", fake):
            with self.assertRaisesRegex(
                MODULE.DependencyFreezeError, "reviewed Git executable identity changed"
            ):
                MODULE._open_reviewed_git_executable()

    def test_replacement_ref_cannot_substitute_reviewed_head_tree(self) -> None:
        authentic = "authentic retained bytes\n"
        attacker = "attacker replacement bytes\n"
        self._commit_tree({"lib/main.dart": authentic})
        original_head = self._git("rev-parse", "HEAD").stdout.strip()
        self._write("lib/main.dart", attacker)
        self._git("add", "--", "lib/main.dart")
        self._git(
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "--no-gpg-sign",
            "-m",
            "attacker replacement",
        )
        attacker_head = self._git("rev-parse", "HEAD").stdout.strip()
        self._git("read-tree", original_head)
        self._write("lib/main.dart", authentic)
        self._git("update-ref", "HEAD", original_head)
        self._git("replace", original_head, attacker_head)
        self.assertIn(
            "attacker",
            self._git("show", "HEAD:lib/main.dart").stdout,
        )
        with self.assertRaisesRegex(
            MODULE.DependencyFreezeError,
            "external or replacement-object indirection",
        ):
            MODULE.input_state(self.repo, ("lib",))

    def test_external_git_metadata_indirections_are_rejected(self) -> None:
        self._commit_tree({"lib/main.dart": "void main() {}\n"})
        variants = {
            "objects/info/alternates": "/private/tmp/external-objects\n",
            "info/grafts": "0" * 40 + " " + "1" * 40 + "\n",
        }
        for relative, contents in variants.items():
            with self.subTest(relative=relative):
                path = self.repo / ".git" / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents, encoding="utf-8")
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError,
                    "external or replacement-object indirection",
                ):
                    MODULE.input_state(self.repo, ("lib",))
                path.unlink()

        config = self.repo / ".git/config"
        original = config.read_bytes()
        variants = (
            original + b"\n[include]\n\tpath = /private/tmp/hostile.gitconfig\n",
            original + b"\r[include]\n\tpath = /private/tmp/hostile.gitconfig\n",
            original + b"\n[core]\n\rworktree = /private/tmp/hostile-worktree\n",
            b"\xef\xbb\xbf" + original,
        )
        for payload in variants:
            with self.subTest(payload=payload[-64:]):
                config.write_bytes(payload)
                with self.assertRaisesRegex(
                    MODULE.DependencyFreezeError,
                    r"external path indirection|unsupported control syntax",
                ):
                    MODULE.input_state(self.repo, ("lib",))
        config.write_bytes(original)

    def test_repo_local_fsmonitor_is_disabled(self) -> None:
        self._commit_tree({"lib/main.dart": "void main() {}\n"})
        marker = self.repo / ".git" / "fsmonitor-invoked"
        hook = self.repo / ".git" / "hostile-fsmonitor.sh"
        hook.write_text(
            "#!/bin/sh\nprintf called > " + str(marker) + "\nprintf '2\\n'\n",
            encoding="utf-8",
        )
        hook.chmod(0o700)
        self._git("config", "core.fsmonitor", str(hook))
        state = MODULE.input_state(self.repo, ("lib",))
        self.assertEqual(state.file_count, 1)
        self.assertFalse(marker.exists())

    def test_git_cwd_cannot_be_redirected_by_higher_ancestor_swap(self) -> None:
        current_parent = self.repo / "current-parent"
        attacker_parent = self.repo / "attacker-parent"
        authentic = current_parent / "repo"
        attacker = attacker_parent / "repo"

        def initialize(path: pathlib.Path, contents: str) -> None:
            path.mkdir(parents=True)
            env = os.environ.copy()
            env.update(
                {
                    "GIT_CONFIG_GLOBAL": os.devnull,
                    "GIT_CONFIG_SYSTEM": os.devnull,
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_AUTHOR_NAME": "Freeze Test",
                    "GIT_AUTHOR_EMAIL": "freeze-test@winsvpn.example",
                    "GIT_COMMITTER_NAME": "Freeze Test",
                    "GIT_COMMITTER_EMAIL": "freeze-test@winsvpn.example",
                }
            )
            subprocess.run(
                ["git", "-C", str(path), "init", "-q", "-b", "main"],
                check=True,
                env=env,
            )
            source = path / "lib/main.dart"
            source.parent.mkdir()
            source.write_text(contents, encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(path), "add", "--", "lib/main.dart"],
                check=True,
                env=env,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(path),
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-q",
                    "--no-gpg-sign",
                    "-m",
                    "tracked",
                ],
                check=True,
                env=env,
            )

        initialize(authentic, "authentic retained bytes\n")
        initialize(attacker, "attacker pathname bytes\n")
        backup_parent = self.repo / "retained-parent"
        original_run = MODULE.subprocess.run
        in_swap = False

        def swap_around_git(*args, **kwargs):
            nonlocal in_swap
            command = args[0] if args else kwargs.get("args")
            if in_swap or not command or command[0] != "/usr/bin/git":
                return original_run(*args, **kwargs)
            in_swap = True
            current_parent.rename(backup_parent)
            attacker_parent.rename(current_parent)
            try:
                return original_run(*args, **kwargs)
            finally:
                current_parent.rename(attacker_parent)
                backup_parent.rename(current_parent)
                in_swap = False

        with mock.patch.object(MODULE.subprocess, "run", side_effect=swap_around_git):
            state = MODULE.input_state(authentic, ("lib",))
        self.assertEqual(state.file_count, 1)
        self.assertEqual(
            state.files[0].sha256,
            hashlib.sha256(b"authentic retained bytes\n").hexdigest(),
        )
        self.assertNotIn(b"attacker", (authentic / "lib/main.dart").read_bytes())

    def test_clean_tracked_tree_freeze_succeeds(self) -> None:
        self._commit_tree(
            {
                ".gitignore": ".artifacts/\n",
                "lib/main.dart": "void main() {}\n",
            }
        )
        state = MODULE.input_state(self.repo, ("lib",))
        self.assertEqual(state.file_count, 1)
        self.assertEqual(state.files[0].path, "lib/main.dart")
        self.assertFalse(MODULE.isolated_fixture_mode_active())



class ReadableDescriptorsTests(unittest.TestCase):
    def test_output_wait_handles_descriptors_above_fd_setsize(self) -> None:
        # The freeze raises its open-file limit, so a producer pipe can land above
        # FD_SETSIZE (1024), where select.select raises ValueError on macOS.
        import resource

        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        wanted = 1200
        if hard != resource.RLIM_INFINITY and hard < wanted:
            self.skipTest("hard open-file limit is below 1200")
        resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, wanted), hard))
        self.addCleanup(resource.setrlimit, resource.RLIMIT_NOFILE, (soft, hard))
        held: list[int] = []

        def close_held() -> None:
            for descriptor in held:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

        self.addCleanup(close_held)
        while not held or held[-1] < 1030:
            held.append(os.open(os.devnull, os.O_RDONLY))
        read_fd, write_fd = os.pipe()
        held.extend((read_fd, write_fd))
        self.assertGreaterEqual(read_fd, 1024)
        self.assertEqual(MODULE._readable_descriptors((read_fd,), 0), [])
        os.write(write_fd, b"x")
        self.assertEqual(MODULE._readable_descriptors((read_fd,), 0), [read_fd])
        os.read(read_fd, 1)
        os.close(write_fd)
        held.remove(write_fd)
        self.assertEqual(MODULE._readable_descriptors((read_fd,), 0), [read_fd])

if __name__ == "__main__":
    unittest.main()
