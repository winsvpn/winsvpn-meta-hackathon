#!/usr/bin/env python3
"""Source contracts for exact Windows PE and Inno version resources."""

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PUBSPEC = (ROOT / "pubspec.yaml").read_text(encoding="utf-8")
RUNNER_RC = (ROOT / "windows/runner/Runner.rc").read_text(encoding="utf-8")
INNO = (ROOT / "installer/windows/winsvpn.iss").read_text(encoding="utf-8")
PRODUCER = (ROOT / "installer/windows/build_installer.ps1").read_text(
    encoding="utf-8"
)


def canonical_versions() -> tuple[str, str]:
    match = re.search(r"(?m)^version:\s*(\d+\.\d+\.\d+)\+(\d+)\s*$", PUBSPEC)
    if match is None:
        raise AssertionError("pubspec.yaml lacks major.minor.patch+build version")
    product = match.group(1)
    build = int(match.group(2))
    parts = [int(value) for value in product.split(".")] + [build]
    if any(value > 65535 for value in parts):
        raise AssertionError("Windows PE version component exceeds 65535")
    return product, f"{product}.{build}"


class WindowsVersionResourceContractTests(unittest.TestCase):
    def test_runner_fixed_and_textual_versions_are_canonical(self) -> None:
        product, file_version = canonical_versions()
        self.assertIn(
            f'#define WINS_PRODUCT_VERSION_NUMBER {product.replace(".", ",")},0',
            RUNNER_RC,
        )
        self.assertIn(
            f'#define WINS_FILE_VERSION_NUMBER {file_version.replace(".", ",")}',
            RUNNER_RC,
        )
        self.assertIn(f'#define WINS_PRODUCT_VERSION_STRING "{product}"', RUNNER_RC)
        self.assertIn(f'#define WINS_FILE_VERSION_STRING "{file_version}"', RUNNER_RC)
        self.assertIn("FILEVERSION WINS_FILE_VERSION_NUMBER", RUNNER_RC)
        self.assertIn("PRODUCTVERSION WINS_PRODUCT_VERSION_NUMBER", RUNNER_RC)
        self.assertIn('VALUE "FileVersion", WINS_FILE_VERSION_STRING "\\0"', RUNNER_RC)
        self.assertIn(
            'VALUE "ProductVersion", WINS_PRODUCT_VERSION_STRING "\\0"', RUNNER_RC
        )
        self.assertNotIn("FLUTTER_VERSION_BUILD", RUNNER_RC)

    def test_inno_requires_and_applies_exact_resource_defines(self) -> None:
        required = (
            '#error "ReleaseProductVersion is required. Use build_installer.ps1 so it is derived from pubspec.yaml."',
            '#error "ReleaseFileVersion is required. Use build_installer.ps1 so it is derived from pubspec.yaml."',
            "VersionInfoProductVersion={#ReleaseProductVersion}",
            "VersionInfoVersion={#ReleaseFileVersion}",
            "VersionInfoProductTextVersion={#ReleaseProductVersion}",
            "VersionInfoTextVersion={#ReleaseFileVersion}",
        )
        for marker in required:
            self.assertIn(marker, INNO)

    def test_producer_derives_passes_and_rechecks_resource_versions(self) -> None:
        product, file_version = canonical_versions()
        self.assertIn('$WindowsProductVersion = $AppVersion', PRODUCER)
        self.assertIn('$WindowsFileVersion = "$AppVersion.$BuildNumber"', PRODUCER)
        self.assertIn(
            '"/DReleaseProductVersion=$WindowsProductVersion"', PRODUCER
        )
        self.assertIn('"/DReleaseFileVersion=$WindowsFileVersion"', PRODUCER)
        self.assertIn("function Assert-WindowsReleaseVersionResources", PRODUCER)
        self.assertIn(
            "Assert-WindowsReleaseVersionResources -Path (Join-Path $ReleaseDir 'wins_vpn.exe')",
            PRODUCER,
        )
        self.assertIn(
            "Assert-WindowsReleaseVersionResources -Path $installer -Label 'Windows installer'",
            PRODUCER,
        )
        self.assertEqual(product, "1.0.17")
        self.assertEqual(file_version, "1.0.17.34")

    def test_resource_contract_is_architecture_neutral(self) -> None:
        product, file_version = canonical_versions()
        for architecture in ("x64", "arm64"):
            self.assertIn(f"'{architecture}'", PRODUCER)
        self.assertNotIn("TargetArchitecture -ceq 'x64'", INNO.split("VersionInfoVersion")[0])
        self.assertEqual(product, "1.0.17")
        self.assertEqual(file_version, "1.0.17.34")


if __name__ == "__main__":
    unittest.main()
