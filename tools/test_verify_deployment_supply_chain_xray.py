#!/usr/bin/env python3
"""Focused regressions for the central Xray supply-chain verifier."""

from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
VERIFY_PATH = ROOT / "tools/verify_deployment_supply_chain.py"
INSTALLER_PATH = ROOT / "installer/windows/build_installer.ps1"
ENGINE_PATH = ROOT / "tools/build_xray_engine.sh"
X64_HASH = "fffbe5dd92fe13cfc6ab72dead66ddd92c09b2bb27a85592e8e6f4ec27ee1224"
ARM64_HASH = "c6edaa0e535b81d8c4c4a25378e6717b4406a8a0d72b751f4d0a1f171817e7af"
ANDROID_ARM64_HASH = (
    "30772382fcee4fe18b6c31a3daf9a53878b5bfa775e05ea3f3c8cb0b0ec73b2b"
)
ANDROID_ARMV7_HASH = (
    "35e5256bce15bc30bd3dbf7ba82c7ac6b138782eae811e0ae4ab535fbedec1b9"
)
ANDROID_X86_64_HASH = (
    "82885af5bc2c89eb10201af08049d865c398025fe89f2b8cd02178fc275876b4"
)
UNRELATED_HASH = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def load_verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_deployment_supply_chain", VERIFY_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load verify_deployment_supply_chain")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def render_xray_table(
    entries: list[tuple[str, str]],
    *,
    suffix: str = "[$TargetArchitecture]",
) -> str:
    lines = ["$XrayExeSha256 = @{"]
    for key, digest in entries:
        lines.append(f"    '{key}' = '{digest}'")
    lines.append("}" + suffix)
    return "\n".join(lines)


class VerifyDeploymentSupplyChainXrayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_verifier()
        cls.installer = INSTALLER_PATH.read_text(encoding="utf-8")
        cls.engine = ENGINE_PATH.read_text(encoding="utf-8")

    def test_live_powershell_table_parses_exact_x64_and_arm64_hashes(self) -> None:
        parsed = self.module.parse_powershell_xray_sha256_table(self.installer)
        self.assertEqual(
            parsed,
            {"x64": X64_HASH, "arm64": ARM64_HASH},
        )
        self.assertEqual(parsed, self.module.WINDOWS_XRAY_EXE_SHA256)
        self.assertEqual(
            tuple(self.module.WINDOWS_XRAY_REQUIRED_ARCHITECTURES),
            ("x64", "arm64"),
        )

    def test_live_windows_binaries_are_directly_hashed_for_both_architectures(
        self,
    ) -> None:
        self.module.verify_windows_xray_binaries(
            ROOT, dict(self.module.WINDOWS_XRAY_EXE_SHA256)
        )
        self.module.require_file_sha256(
            ROOT / "installer/windows/dependencies/xray.exe",
            X64_HASH,
            "Windows Xray x64",
        )
        self.module.require_file_sha256(
            ROOT / "installer/windows/dependencies/xray-arm64.exe",
            ARM64_HASH,
            "Windows Xray arm64",
        )

    def test_live_android_binaries_require_arm64_armv7_x86_64_exact_hashes(
        self,
    ) -> None:
        expected = dict(self.module.ANDROID_XRAY_BINARY_SHA256)
        self.assertEqual(
            set(expected),
            {"arm64-v8a", "armeabi-v7a", "x86_64"},
        )
        self.assertEqual(expected["arm64-v8a"], ANDROID_ARM64_HASH)
        self.assertEqual(expected["armeabi-v7a"], ANDROID_ARMV7_HASH)
        self.assertEqual(expected["x86_64"], ANDROID_X86_64_HASH)
        self.module.verify_android_xray_binaries(ROOT, expected)

    def test_xray_pinned_commit_verification_is_preserved(self) -> None:
        self.assertEqual(
            self.module.XRAY_ENGINE_COMMIT,
            "b26a91de4f3294e26a0ad0a970b81a386a41f789",
        )
        self.assertEqual(self.module.XRAY_ENGINE_TAG, "v26.9.30")
        self.assertEqual(
            self.module.LATEST_GITHUB_RELEASES["XTLS/Xray-core"],
            "v26.9.30",
        )
        self.module.verify_xray_engine_recipe_pins(self.engine)
        mutated = self.engine.replace(
            self.module.XRAY_ENGINE_COMMIT, "0" * 40
        )
        with self.assertRaisesRegex(RuntimeError, "XRAY_COMMIT"):
            self.module.verify_xray_engine_recipe_pins(mutated)
        mutated_tag = self.engine.replace('XRAY_TAG="v26.9.30"', 'XRAY_TAG="v26.3.28"')
        with self.assertRaisesRegex(RuntimeError, "XRAY_TAG"):
            self.module.verify_xray_engine_recipe_pins(mutated_tag)

    def test_scalar_legacy_xray_sha256_form_is_rejected(self) -> None:
        scalar = f'$XrayExeSha256 = "{X64_HASH}"\n'
        with self.assertRaisesRegex(RuntimeError, "scalar legacy"):
            self.module.parse_powershell_xray_sha256_table(scalar)
        mixed = (
            scalar
            + render_xray_table([("x64", X64_HASH), ("arm64", ARM64_HASH)])
            + "\n"
        )
        with self.assertRaisesRegex(RuntimeError, "scalar legacy"):
            self.module.parse_powershell_xray_sha256_table(mixed)

    def test_missing_extra_malformed_and_duplicate_architecture_keys_are_rejected(
        self,
    ) -> None:
        valid = [("x64", X64_HASH), ("arm64", ARM64_HASH)]
        cases = (
            ("missing", valid[:1], r"missing arm64"),
            (
                "extra",
                valid + [("x86", UNRELATED_HASH)],
                r"extra x86",
            ),
            (
                "wrong-arch-keys",
                [("amd64", X64_HASH), ("aarch64", ARM64_HASH)],
                r"missing arm64|missing x64|extra",
            ),
            (
                "malformed-digest",
                [("x64", X64_HASH), ("arm64", "not-a-sha256-digest")],
                r"malformed architecture key",
            ),
            (
                "malformed-uppercase",
                [("x64", X64_HASH.upper()), ("arm64", ARM64_HASH)],
                r"malformed architecture key",
            ),
            (
                "malformed-quotes",
                [("x64", X64_HASH), ("arm64", ARM64_HASH)],
                r"malformed architecture key",
            ),
            (
                "duplicate",
                valid + [("x64", UNRELATED_HASH)],
                r"duplicate architecture key",
            ),
        )
        for name, entries, pattern in cases:
            source = render_xray_table(entries)
            if name == "malformed-quotes":
                source = source.replace("'x64'", '"x64"')
            with self.subTest(name=name):
                with self.assertRaisesRegex(RuntimeError, pattern):
                    self.module.parse_powershell_xray_sha256_table(source)

        without_index = render_xray_table(valid, suffix="")
        with self.assertRaisesRegex(RuntimeError, "exactly one"):
            self.module.parse_powershell_xray_sha256_table(without_index)

    def test_swapped_windows_hashes_fail(self) -> None:
        swapped_table = render_xray_table(
            [("x64", ARM64_HASH), ("arm64", X64_HASH)]
        )
        parsed = self.module.parse_powershell_xray_sha256_table(swapped_table)
        self.assertNotEqual(parsed, self.module.WINDOWS_XRAY_EXE_SHA256)
        with self.assertRaisesRegex(RuntimeError, r"Windows Xray x64 drift"):
            self.module.verify_windows_xray_binaries(ROOT, parsed)

    def test_wrong_arch_windows_hashes_fail(self) -> None:
        x64_path = ROOT / "installer/windows/dependencies/xray.exe"
        arm64_path = ROOT / "installer/windows/dependencies/xray-arm64.exe"
        with self.assertRaisesRegex(RuntimeError, r"Windows Xray x64 drift"):
            self.module.require_file_sha256(
                x64_path, ARM64_HASH, "Windows Xray x64"
            )
        with self.assertRaisesRegex(RuntimeError, r"Windows Xray arm64 drift"):
            self.module.require_file_sha256(
                arm64_path, X64_HASH, "Windows Xray arm64"
            )
        wrong_arch = render_xray_table(
            [("amd64", X64_HASH), ("arm64", ARM64_HASH)]
        )
        with self.assertRaisesRegex(RuntimeError, r"missing x64|extra amd64"):
            self.module.parse_powershell_xray_sha256_table(wrong_arch)

    def test_swapped_android_hashes_fail(self) -> None:
        swapped = dict(self.module.ANDROID_XRAY_BINARY_SHA256)
        swapped["arm64-v8a"], swapped["x86_64"] = (
            swapped["x86_64"],
            swapped["arm64-v8a"],
        )
        with self.assertRaisesRegex(
            RuntimeError, r"Android Xray main/arm64-v8a drift"
        ):
            self.module.verify_android_xray_binaries(ROOT, swapped)

    def test_wrong_arch_android_hashes_fail(self) -> None:
        arm64_path = (
            ROOT
            / "android/app/src/main/jniLibs/arm64-v8a/libxray.so"
        )
        with self.assertRaisesRegex(
            RuntimeError, r"Android Xray main/arm64-v8a drift"
        ):
            self.module.require_file_sha256(
                arm64_path, ANDROID_ARMV7_HASH, "Android Xray main/arm64-v8a"
            )
        wrong_keys = {
            "arm64": ANDROID_ARM64_HASH,
            "armeabi-v7a": ANDROID_ARMV7_HASH,
            "x86_64": ANDROID_X86_64_HASH,
        }
        with self.assertRaisesRegex(
            RuntimeError, r"missing arm64-v8a|extra arm64"
        ):
            self.module.verify_android_xray_binaries(ROOT, wrong_keys)

    def test_live_local_xray_rebuild_verifier_passes(self) -> None:
        self.module.verify_xray_engine_rebuild_pins()

    def _newest_release_listing(self, *tags: tuple[str, str, bool]) -> mock.Mock:
        listing = [
            {
                "tag_name": tag,
                "published_at": published,
                "prerelease": prerelease,
                "draft": False,
            }
            for tag, published, prerelease in tags
        ]
        return mock.Mock(
            return_value=io.BytesIO(json.dumps(listing).encode("utf-8"))
        )

    def test_owner_approved_prerelease_tracking_accepts_newest_prerelease(
        self,
    ) -> None:
        # Owner decision 2026-10-06: Xray follows the newest tag even though
        # upstream flags it prerelease; /releases/latest would say v26.3.27.
        self.assertIn(
            "XTLS/Xray-core", self.module.OWNER_APPROVED_PRERELEASE_TRACKING
        )
        fake = self._newest_release_listing(
            ("v26.3.27", "2026-03-27T17:51:11Z", False),
            ("v26.9.30", "2026-09-30T07:41:08Z", True),
            ("v26.9.9", "2026-09-08T22:28:10Z", True),
        )
        with mock.patch.object(self.module, "request", fake):
            self.module.verify_newest_release_pin(
                "XTLS/Xray-core", "v26.9.30"
            )

    def test_owner_approved_prerelease_tracking_rejects_a_newer_tag(self) -> None:
        fake = self._newest_release_listing(
            ("v26.9.30", "2026-09-30T07:41:08Z", True),
            ("v26.10.5", "2026-10-05T07:41:08Z", True),
        )
        with mock.patch.object(self.module, "request", fake):
            with self.assertRaisesRegex(RuntimeError, "newest release drift"):
                self.module.verify_newest_release_pin(
                    "XTLS/Xray-core", "v26.9.30"
                )


if __name__ == "__main__":
    unittest.main()
