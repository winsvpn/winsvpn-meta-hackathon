import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
L10N = ROOT / "lib" / "l10n"
DEPENDENCIES = ROOT / "installer" / "windows" / "dependencies"
LICENSES = ROOT / "installer" / "windows" / "licenses"
LICENSE_INDEXES = tuple(sorted(LICENSES.glob("README*.txt")))
WITHDRAWN_DRIVER_BLOBS = (
    "mullvad-split-tunnel.sys",
    "mullvad-split-tunnel.cat",
    "mullvad-split-tunnel.inf",
    "mullvad-split-tunnel-arm64.sys",
    "mullvad-split-tunnel-arm64.cat",
    "mullvad-split-tunnel-arm64.inf",
)

ARB_FILES = (
    L10N / "app_en.arb",
    L10N / "app_my.arb",
)
GENERATED_LOCALIZATIONS = (
    L10N / "app_localizations.dart",
    L10N / "app_localizations_en.dart",
    L10N / "app_localizations_my.dart",
)


class WithdrawnMullvadShippingSurfaceTests(unittest.TestCase):
    def test_shipping_arb_has_no_mullvad_feature_key_or_claim(self) -> None:
        for path in ARB_FILES:
            with self.subTest(path=path.name):
                content = path.read_text(encoding="utf-8")
                document = json.loads(content)
                self.assertNotIn("mullvadDriver", document)
                self.assertNotIn("mullvad", content.casefold())

    def test_generated_localizations_have_no_mullvad_feature_claim(self) -> None:
        for path in GENERATED_LOCALIZATIONS:
            with self.subTest(path=path.name):
                self.assertNotIn(
                    "mullvad",
                    path.read_text(encoding="utf-8").casefold(),
                )

    def test_shipping_windows_license_index_has_no_mullvad_entry(self) -> None:
        self.assertGreaterEqual(len(LICENSE_INDEXES), 2)
        for path in LICENSE_INDEXES:
            with self.subTest(path=path.name):
                index = path.read_text(encoding="utf-8")
                self.assertNotIn("mullvad", index.casefold())
                self.assertNotIn("mullvad-split-tunnel-MPL-2.0.txt", index)

    def test_withdrawn_mullvad_driver_blobs_are_absent_from_dependencies(self) -> None:
        for name in WITHDRAWN_DRIVER_BLOBS:
            with self.subTest(name=name):
                self.assertFalse(
                    (DEPENDENCIES / name).exists(),
                    f"{name} must not remain as a parked installer dependency",
                )

    def test_parked_mullvad_license_file_is_absent(self) -> None:
        self.assertFalse((LICENSES / "mullvad-split-tunnel-MPL-2.0.txt").exists())


if __name__ == "__main__":
    unittest.main()
