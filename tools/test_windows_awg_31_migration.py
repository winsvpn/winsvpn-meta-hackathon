#!/usr/bin/env python3
"""Focused static contract for the official Windows AmneziaWG 3.1 migration."""

from __future__ import annotations

import hashlib
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CLIENT = (ROOT / "tools/build_windows_amneziawg_client.ps1").read_text(
    encoding="utf-8"
)
ENGINE = (ROOT / "tools/build_windows_awg_engine.ps1").read_text(
    encoding="utf-8"
)
MODULE = (ROOT / "windows/awg_engine/go.mod").read_text(encoding="utf-8")
MODULE_SUM = (ROOT / "windows/awg_engine/go.sum").read_text(encoding="utf-8")
INSTALLER = (ROOT / "installer/windows/build_installer.ps1").read_text(
    encoding="utf-8"
)
STORE = (ROOT / "installer/windows/build_store_msix.ps1").read_text(
    encoding="utf-8"
)
DEPENDENCIES = ROOT / "installer/windows/dependencies"
WINDOWS_NOTICE = (ROOT / "installer/windows/licenses/amneziawg-MIT.txt").read_text(
    encoding="utf-8"
)
IN_APP_NOTICE = (ROOT / "lib/main.dart").read_text(encoding="utf-8")
REFRESH_DOC = (ROOT / "docs/RELEASE_ENGINE_BINARY_REFRESH.md").read_text(
    encoding="utf-8"
)
PROVENANCE_DOC = (ROOT / "docs/AMNEZIAWG_ENGINE_PROVENANCE.md").read_text(
    encoding="utf-8"
)

OFFICIAL_MSI_SHA256 = (
    "a1b48ea8699cd347832a3691d832004574ef8ad65bcf887611ac8acb99b7de8b"
)
OFFICIAL_AWG_EXE_SHA256 = (
    "272badace73caeb26dc42656f318b3eb7f10028c2f76faad1f52d6fe1e0ced12"
)
OFFICIAL_PRODUCT_HELPER_SHA256 = (
    "12525f397d957659354df03ac1e9568170d8842aa8fa0d16942d8a59d7307d41"
)
STALE_MSI_SHA256 = (
    "a0fa81022a6e0204b67c92f0046aaebac923bf6ffc786f503c5acff483807b4a"
)
STALE_AWG_EXE_SHA256 = (
    "cd17f8641bb78ea6476c7341fb7339731ecd8f682e46ab1b43618cea75185552"
)
STALE_PRODUCT_HELPER_SHA256 = (
    "c1a9500254948ac4a1562d8ddf0808b45441ed36bf6746499b67efee6eef1ae9"
)


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class WindowsAwg31MigrationTests(unittest.TestCase):
    def test_packaged_notices_match_official_awg31_sources(self) -> None:
        combined = "\n".join((WINDOWS_NOTICE, IN_APP_NOTICE, REFRESH_DOC))
        for marker in (
            "v3.1.20260814",
            "v3.1.20260828",
            "5c16489e2cd9ed3a0a7a27c7445bba5238132f86",
            "b5928efb6ca19f0153958460c3d141f04abc5c2e",
            "ca5dd3b983bd19c335ab095ccd21fc2f804ec968",
        ):
            self.assertIn(marker, combined)
        for stale in ("v0.2.16", "v0.2.18", "v0.2.19", "client 2.0.1"):
            self.assertNotIn(stale, combined)

    def test_official_source_identities_are_exact(self) -> None:
        for marker in (
            "$sourceVersion = '3.1.0'",
            "$sourceCommit = 'ca5dd3b983bd19c335ab095ccd21fc2f804ec968'",
            "$windowsLibraryVersion = 'v3.1.20260814'",
            "$windowsLibraryCommit = 'e90531d15802cb976773f3b63443bc281f738ca3'",
            "$engineVersion = 'v3.1.20260828'",
            "$engineCommit = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'",
            "$engineSourceArchiveSha256",
            "10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4",
            "The official Windows client release tag is not the Go engine tag.",
            "The Windows library tag and the Go engine tag are independent pins and must not be conflated.",
            "$upstreamEngineVersion = 'v3.1.20260814'",
            "'h1:l2AhBD+sFycU8Im81n/bZORMxW7fWtlZJEuJ4Hh0+z0='",
            "'h1:D8d8gGvwXcTxUIsE4z6F6vjy4/VZddu95vMNtOygh1c='",
            "'bdc3d347ffebb8fea5eab4e8baf3e1c99d7488f119b1aafc38922973d643afa2'",
            "'84243a4e2616cf698afee71c8a8f2193f6012987428a956dba8249cd143b5e36'",
            "function Set-EngineRequirementOverride",
        ):
            self.assertIn(marker, CLIENT)
        for marker in (
            "$engineVersion = 'v3.1.20260828'",
            "$engineCommit = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'",
            "$engineModule = 'github.com/amnezia-vpn/amneziawg-go/v3'",
            "$engineSourceArchiveSha256",
            "10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4",
            "The Go engine tag must not be confused with the Windows client 3.1.0 release.",
        ):
            self.assertIn(marker, ENGINE)

    def test_client_source_and_toolchain_bytes_are_frozen(self) -> None:
        for digest in (
            "ad578b6a2107ae4c1bab214c8057e89608ac516d6e381675c3d9441ccc4da70a",
            "268286d6183ec93c39e5295e73e660d9920481c66ecff8331ab64fa082230723",
            "c501fd947d08a4bfdb29f65a9f06ced004779be7a90a125f703c1c5a5130350b",
            "79bd946166bc6e87d4ff1602889557590703fc8a64737fbfe7f0b64ebda431d7",
            "a5ad25797aadc29f0e7aa0bf91e6197ce57c48cb845194a18ae7c2dbbebadcbd",
            "a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d",
        ):
            self.assertIn(digest, CLIENT)
        self.assertIn("$goVersion = '1.27.1'", CLIENT)
        self.assertIn("Assert-Sha256 -Path $buildScript", CLIENT)
        self.assertIn("$buildPatchSha256 -cne $expectedBuildPatchSha256", CLIENT)
        self.assertIn("GOFLAGS = '-mod=readonly -buildvcs=false'", CLIENT)

    def test_engine_source_and_v3_import_rewrite_are_frozen(self) -> None:
        for digest in (
            "e447b49513d1fc452fa7cb2f87b15c40b88ab6f0656e22b4eccdfe238fa623e4",
            "fbec66bcbe1cf3603eb5b0f6c7c2041aea6749dc8c1d36b91726a7a479df4719",
            "a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d",
        ):
            self.assertIn(digest, ENGINE)
        for marker in (
            "Get-PreparedEngineEntrypoint",
            "$legacyCount -ne 4",
            "schema_version = 3",
            "build_entrypoint_sha256",
            "github.com/amnezia-vpn/amneziawg-go=>github.com/amnezia-vpn/amneziawg-go/v3",
            "GOFLAGS = '-mod=readonly'",
        ):
            self.assertIn(marker, ENGINE)

    def test_local_module_records_exact_v3_contract(self) -> None:
        for marker in (
            "go 1.27.1",
            "toolchain go1.27.1",
            "github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828",
            "b5928efb6ca19f0153958460c3d141f04abc5c2e",
            "10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4",
            "not the Windows client release 3.1.0",
            "amneziawg-tools v3.1.20260812",
        ):
            self.assertIn(marker, MODULE)
        self.assertIn("direct in-place build is not an acceptance", MODULE)
        self.assertIn(
            "github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828 h1:D8d8gGvwXcTxUIsE4z6F6vjy4/VZddu95vMNtOygh1c=",
            MODULE_SUM,
        )
        self.assertNotIn("github.com/amnezia-vpn/amneziawg-go v0.2.19", MODULE_SUM)

    def test_installer_freezes_release_and_embedded_payload_bytes(self) -> None:
        for marker in (
            '$AmneziaWgVersion = "3.1.0"',
            "a1b48ea8699cd347832a3691d832004574ef8ad65bcf887611ac8acb99b7de8b",
            "ba446f6e1a4093e43a65d6ff45f4b8c7b6485dc419327eedaa1a218549740e3a",
            "272badace73caeb26dc42656f318b3eb7f10028c2f76faad1f52d6fe1e0ced12",
            "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
            '$AmneziaWgSourceCommit = "ca5dd3b983bd19c335ab095ccd21fc2f804ec968"',
            '$AmneziaWgWindowsLibraryCommit = "e90531d15802cb976773f3b63443bc281f738ca3"',
            '$AmneziaWgEngineCommit = "b5928efb6ca19f0153958460c3d141f04abc5c2e"',
        ):
            self.assertIn(marker, INSTALLER)

    def test_rebuilt_helper_is_bound_to_provenance_not_an_unproven_hash(self) -> None:
        self.assertNotIn("$AmneziaWgExeSha256 =", INSTALLER)
        self.assertIn(
            "Assert-WindowsAwgSchema2OwnerPublicationContract",
            INSTALLER,
        )
        self.assertIn("unsigned_artifact_sha256", INSTALLER)
        self.assertIn("expected_unsigned_artifact_sha256", INSTALLER)
        self.assertIn(
            "unsigned digest does not agree with the helper bytes and reviewed pin",
            INSTALLER,
        )
        # The expected digest is the producer's pin, not the file's own hash.
        self.assertIn(f"ProductHelperSha256 = '{OFFICIAL_PRODUCT_HELPER_SHA256}'", CLIENT)
        self.assertIn(f"'x64' = '{OFFICIAL_PRODUCT_HELPER_SHA256}'", INSTALLER)
        helper = INSTALLER[
            INSTALLER.index("function Assert-RebuiltAmneziaWgHelper") :
            INSTALLER.index("function Assert-AmneziaWgPayloadSignatures")
        ]
        self.assertIn("$expectedUnsigned = $AmneziaWgHelperUnsignedSha256", helper)
        self.assertNotIn("Get-FileHash -LiteralPath $AmneziaWgExe", helper)
        for marker in (
            "$AmneziaWgSourceBuildBatSha256",
            "$AmneziaWgPatchedBuildBatSha256",
            "$AmneziaWgBuildPatchSha256",
            "$AmneziaWgGoVersion",
            "module_build_info",
        ):
            self.assertIn(marker, INSTALLER)
        self.assertNotIn("'pending_release_signing' -Name 'authenticode_status'", INSTALLER)

    def test_old_shipping_identities_are_not_accepted_pins(self) -> None:
        production = "\n".join((CLIENT, ENGINE, MODULE, INSTALLER))
        for stale in (
            "1cc94272ca8e9e223a5fe76382f5880f09d3c12d",
            "8e0e3784143cc06de5422d09d9b6cd1d352dfeb4",
        ):
            self.assertNotIn(stale, production)
        self.assertNotIn(STALE_MSI_SHA256, ENGINE)
        self.assertNotIn(STALE_MSI_SHA256, MODULE)
        self.assertNotIn(STALE_MSI_SHA256, INSTALLER)
        for source in (CLIENT, STORE):
            self.assertIn("$rejectedLegacyMsiSha256 =", source)
            self.assertIn(STALE_MSI_SHA256, source)
            self.assertIn("$rejectedLegacyAwgExeSha256 =", source)
            self.assertIn(STALE_AWG_EXE_SHA256, source)
            self.assertIn("$rejectedLegacyProductHelperSha256 =", source)
            self.assertIn(STALE_PRODUCT_HELPER_SHA256, source)
            self.assertNotRegex(
                source,
                rf"\$upstreamMsiSha256\s*=\s*'{STALE_MSI_SHA256}'",
            )
            self.assertNotRegex(
                source,
                rf"\$expectedProductHelperSha256\s*=\s*'{STALE_PRODUCT_HELPER_SHA256}'",
            )
        self.assertNotRegex(
            STORE,
            rf"(?i)'amneziawg-amd64\.msi'\s*=\s*'{STALE_MSI_SHA256}'",
        )
        self.assertNotRegex(
            STORE,
            rf"(?i)'awg\.exe'\s*=\s*'{STALE_AWG_EXE_SHA256}'",
        )
        self.assertNotRegex(
            STORE,
            rf"(?i)'amneziawg\.exe'\s*=\s*'{STALE_PRODUCT_HELPER_SHA256}'",
        )

    def test_store_packager_aligns_with_awg_31_and_rejects_legacy_in_every_mode(
        self,
    ) -> None:
        for marker in (
            "$AmneziaWgVersion = '3.1.0'",
            "$AmneziaWgEngineVersion = 'v3.1.20260828'",
            "$AmneziaWgEngineCommit = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'",
            "$AmneziaWgSourceCommit = 'ca5dd3b983bd19c335ab095ccd21fc2f804ec968'",
            "$AmneziaWgWindowsLibraryVersion = 'v3.1.20260814'",
            "$AmneziaWgWindowsLibraryCommit = 'e90531d15802cb976773f3b63443bc281f738ca3'",
            OFFICIAL_MSI_SHA256,
            OFFICIAL_AWG_EXE_SHA256,
            OFFICIAL_PRODUCT_HELPER_SHA256,
            "function Assert-OfficialAwg31Dependencies",
            "function Assert-NotRejectedSha256",
            "rejected legacy 2.0.1 identity",
            "Official AWG 3.1.0 is required.",
            "Refusing to package stale or mixed Windows dependencies.",
            "never rewrites the pin from the bytes on disk",
            "does not download",
        ):
            self.assertIn(marker, STORE)
        self.assertRegex(
            STORE,
            rf"(?i)'amneziawg-amd64\.msi'\s*=\s*'{OFFICIAL_MSI_SHA256}'",
        )
        self.assertRegex(
            STORE,
            rf"(?i)'awg\.exe'\s*=\s*'{OFFICIAL_AWG_EXE_SHA256}'",
        )
        self.assertRegex(
            STORE,
            rf"(?i)'amneziawg\.exe'\s*=\s*'{OFFICIAL_PRODUCT_HELPER_SHA256}'",
        )
        self.assertIn("\n    Assert-OfficialAwg31Dependencies\n", STORE)
        self.assertIn("\nAssert-OfficialAwg31Dependencies\n", STORE)
        self_test = STORE[
            STORE.index("function Invoke-SelfTest") : STORE.index("if ($SelfTest)")
        ]
        self.assertIn("Assert-OfficialAwg31Dependencies", self_test)
        self.assertIn(
            "Store packager still accepts a rejected AmneziaWG 2.0.1",
            self_test,
        )
        top_level = STORE.index("\nAssert-OfficialAwg31Dependencies\n")
        self.assertLess(STORE.index("if ($SelfTest)"), top_level)
        self.assertLess(top_level, STORE.index("if ($DevelopmentIdentity)"))
        self.assertNotIn("Invoke-PinnedHttpsDownload", STORE)
        self.assertNotIn(
            "amneziawg-windows-client/releases/download",
            STORE,
        )

    def test_current_payloads_match_official_pins_and_reject_legacy(self) -> None:
        msi = sha256(DEPENDENCIES / "amneziawg-amd64.msi")
        awg = sha256(DEPENDENCIES / "awg.exe")
        helper = sha256(DEPENDENCIES / "amneziawg.exe")
        self.assertEqual(msi, OFFICIAL_MSI_SHA256)
        self.assertEqual(awg, OFFICIAL_AWG_EXE_SHA256)
        self.assertEqual(helper, OFFICIAL_PRODUCT_HELPER_SHA256)
        self.assertNotEqual(msi, STALE_MSI_SHA256)
        self.assertNotEqual(awg, STALE_AWG_EXE_SHA256)
        self.assertNotEqual(helper, STALE_PRODUCT_HELPER_SHA256)
        self.assertIn(msi, STORE)
        self.assertIn(awg, STORE)
        self.assertIn("$rejectedLegacyMsiSha256 =", STORE)
        self.assertIn("$rejectedLegacyAwgExeSha256 =", STORE)
        self.assertNotRegex(
            STORE,
            rf"(?i)'amneziawg-amd64\.msi'\s*=\s*'{STALE_MSI_SHA256}'",
        )
        self.assertNotRegex(
            STORE,
            rf"(?i)'awg\.exe'\s*=\s*'{STALE_AWG_EXE_SHA256}'",
        )
        # The provenance doc must describe the committed cache as it is.
        self.assertNotIn("may still hold rejected", PROVENANCE_DOC)
        self.assertIn(
            "The committed x64 cache holds the official 3.1.0 MSI",
            PROVENANCE_DOC,
        )


class PreparedEngineEntrypointBehaviourTests(unittest.TestCase):
    """Runs the reviewed Get-PreparedEngineEntrypoint with PowerShell on fixtures."""

    @classmethod
    def setUpClass(cls) -> None:
        import shutil

        cls.pwsh = shutil.which("pwsh") or shutil.which("powershell")
        if cls.pwsh is None:
            raise unittest.SkipTest("PowerShell is not installed")
        start = ENGINE.index("function Get-PreparedEngineEntrypoint {")
        cls.function = ENGINE[start : ENGINE.index("\n}\n", start) + 3]
        prefixes = [
            line for line in ENGINE.splitlines()
            if line.startswith(("$legacyEntrypointModulePrefix = ", "$v3EntrypointModulePrefix = "))
        ]
        assert len(prefixes) == 2, prefixes
        cls.prefixes = "\n".join(prefixes)

    def _prepare(self, imports: list[str]) -> tuple[int, str]:
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as name:
            base = pathlib.Path(name)
            source = base / "main.go"
            source.write_text(
                "package main\n\nimport (\n"
                + "".join(f'\t"{path}"\n' for path in imports)
                + ")\n",
                encoding="utf-8",
            )
            script = base / "probe.ps1"
            script.write_text(
                "$ErrorActionPreference = 'Stop'\n"
                + self.prefixes + "\n"
                + f"$sourceMain = '{source}'\n"
                + self.function
                + "try { $out = Get-PreparedEngineEntrypoint; Write-Output $out } "
                + "catch { Write-Output ('REFUSED: ' + $_.Exception.Message); exit 3 }\n",
                encoding="utf-8",
            )
            done = subprocess.run(
                [self.pwsh, "-NoProfile", "-NonInteractive", "-File", str(script)],
                capture_output=True, text=True, check=False,
            )
            return done.returncode, done.stdout

    V3 = [f"github.com/amnezia-vpn/amneziawg-go/v3/{p}" for p in ("conn", "device", "ipc", "tun")]
    LEGACY = [f"github.com/amnezia-vpn/amneziawg-go/{p}" for p in ("conn", "device", "ipc", "tun")]

    def test_source_already_on_the_v3_module_path_is_accepted_unchanged(self) -> None:
        code, out = self._prepare(self.V3)
        self.assertEqual(code, 0, out)
        self.assertEqual(out.count("amneziawg-go/v3/"), 4)

    def test_reviewed_entry_point_in_the_tree_is_accepted(self) -> None:
        imports = [
            line.strip().strip('"')
            for line in (ROOT / "windows/awg_engine/main.go").read_text(encoding="utf-8").splitlines()
            if "amneziawg-go" in line
        ]
        self.assertEqual(imports, self.V3)
        code, out = self._prepare(imports)
        self.assertEqual(code, 0, out)

    def test_legacy_imports_are_migrated_to_v3(self) -> None:
        code, out = self._prepare(self.LEGACY)
        self.assertEqual(code, 0, out)
        self.assertEqual(out.count("amneziawg-go/v3/"), 4)

    def test_mixed_or_unexpected_import_sets_are_refused(self) -> None:
        for label, imports in (
            ("mixed", self.V3[:2] + self.LEGACY[2:]),
            ("three legacy", self.LEGACY[:3]),
            ("five v3", self.V3 + ["github.com/amnezia-vpn/amneziawg-go/v3/ratelimiter"]),
            ("v3 plus one legacy", self.V3 + ["github.com/amnezia-vpn/amneziawg-go/ratelimiter"]),
        ):
            with self.subTest(label=label):
                code, out = self._prepare(imports)
                self.assertEqual(code, 3, out)
                self.assertIn("REFUSED", out)

if __name__ == "__main__":
    unittest.main(verbosity=2)
