#!/usr/bin/env python3
"""Pin every Windows installer third-party license check to tracked bytes."""

from __future__ import annotations

import hashlib
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
ISS = ROOT / "installer/windows/winsvpn.iss"
LICENSE_INDEX = ROOT / "installer/windows/licenses/README.txt"
LICENSE_DIR = LICENSE_INDEX.parent
LICENSE_PINS = {
    "LicensesIndexSha256": ("README.txt", "README.txt"),
    "StandaloneLicensesIndexSha256": (
        "README-STANDALONE-WINN3.txt",
        "README.txt",
    ),
    "WintunLicenceSha256": (
        "Wintun-Prebuilt-Binaries-License.txt",
        "Wintun-Prebuilt-Binaries-License.txt",
    ),
    "AwgToolsGpl2LicenceSha256": (
        "amneziawg-tools-GPL-2.0.txt",
        "amneziawg-tools-GPL-2.0.txt",
    ),
    "AmneziaWgMitLicenceSha256": (
        "amneziawg-MIT.txt",
        "amneziawg-MIT.txt",
    ),
    "XrayMpl2LicenceSha256": (
        "Xray-core-MPL-2.0.txt",
        "Xray-core-MPL-2.0.txt",
    ),
}
LICENSE_DEFINE = re.compile(
    r'^#define ([A-Za-z0-9_]*(?:Licence|LicensesIndex)Sha256) "([0-9a-f]{64})"$',
    re.MULTILINE,
)


class WindowsInstallerLicenseIndexTests(unittest.TestCase):
    def test_every_license_sha256_pin_matches_committed_bytes(self) -> None:
        iss = ISS.read_text(encoding="utf-8")
        pins = dict(LICENSE_DEFINE.findall(iss))
        self.assertEqual(set(pins), set(LICENSE_PINS), iss)
        for define, (source_name, _installed_name) in LICENSE_PINS.items():
            with self.subTest(define=define, filename=source_name):
                path = LICENSE_DIR / source_name
                self.assertTrue(path.is_file(), path)
                self.assertEqual(
                    pins[define],
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                )

    def test_every_license_pin_is_bound_to_source_and_post_install_check(self) -> None:
        iss = ISS.read_text(encoding="utf-8")
        for define, (source_name, installed_name) in LICENSE_PINS.items():
            with self.subTest(define=define, filename=source_name):
                self.assertIn(
                    f'Source: "{{#LicensesDir}}\\{source_name}"; '
                    'DestDir: "{app}\\licenses";',
                    iss,
                )
                if source_name != installed_name:
                    source_line = next(
                        line
                        for line in iss.splitlines()
                        if f'{{#LicensesDir}}\\{source_name}' in line
                    )
                    self.assertIn(f'DestName: "{installed_name}"', source_line)
                self.assertIn(
                    f"'{installed_name}', '{{#{define}}}'",
                    iss,
                )
                self.assertEqual(iss.count(f"{{#{define}}}"), 1)

    def test_standalone_index_is_honest_about_variant_scope(self) -> None:
        index = (LICENSE_DIR / "README-STANDALONE-WINN3.txt").read_text(
            encoding="utf-8"
        )
        lowered = index.casefold()
        self.assertIn("wintun-prebuilt-binaries-license.txt", lowered)
        self.assertIn("statically linked", lowered)
        self.assertIn("third-party go modules", lowered)
        self.assertIn("do not distribute", lowered)
        self.assertIn("does not install", lowered)
        for absent_runtime in ("amneziawg.exe", "awg.exe", "xray.exe"):
            self.assertIn(absent_runtime, lowered)
        self.assertNotIn("gpl-2.0", lowered)
        self.assertNotIn("mozilla public license", lowered)

    def test_license_index_omits_withdrawn_mullvad_entries(self) -> None:
        index = LICENSE_INDEX.read_text(encoding="utf-8")
        self.assertNotIn("mullvad", index.casefold())
        self.assertNotIn("mullvad-split-tunnel-MPL-2.0.txt", index)
        iss = ISS.read_text(encoding="utf-8")
        self.assertNotIn("SplitTunnelMpl2LicenceSha256", iss)
        self.assertNotIn("mullvad-split-tunnel-MPL-2.0.txt", iss)


if __name__ == "__main__":
    unittest.main()
