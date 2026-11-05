#!/usr/bin/env python3
"""Hostile symlink tests for Apple private release-symbol custody."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import apple_release_symbol_custody as custody


DWARF_UUID = "4B1D0000-1111-2222-3333-444444444444"
PACKET_TUNNEL_UUID = "5B1D0000-1111-2222-3333-444444444444"
WATCH_UUID = "6B1D0000-1111-2222-3333-444444444444"
DWARF_BYTES = ("dwarf-uuid:" + DWARF_UUID + "\n").encode("ascii") + b"\x00" * 96
SYMBOL_BYTES = b"s" * 128
ARTIFACT_BYTES = b"exact-apple-artifact"


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@unittest.skipUnless(
    hasattr(os, "O_NOFOLLOW") and hasattr(os, "symlink"),
    "Apple symbol custody no-follow tests require POSIX O_NOFOLLOW",
)
class AppleReleaseSymbolCustodyTests(unittest.TestCase):
    def fixture(
        self, root: pathlib.Path, *, artifact_bytes: bytes = ARTIFACT_BYTES
    ) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path]:
        artifact = root / "WinsVPN.ipa"
        artifact.write_bytes(artifact_bytes)
        flutter = root / "flutter"
        flutter.mkdir()
        (flutter / "app.ios-arm64.symbols").write_bytes(SYMBOL_BYTES)
        archive = root / "Runner.xcarchive"
        dwarf = archive / "dSYMs" / "Runner.app.dSYM" / "Contents" / "Resources" / "DWARF"
        dwarf.mkdir(parents=True)
        (dwarf / "Runner").write_bytes(DWARF_BYTES)
        info = archive / "dSYMs" / "Runner.app.dSYM" / "Contents" / "Info.plist"
        info.write_bytes(b"<?xml version='1.0'?><plist />\n")
        private_root = root / "private-release-symbols" / "apple"
        return artifact, flutter, archive, private_root

    def collect(
        self,
        artifact: pathlib.Path,
        flutter: pathlib.Path,
        archive: pathlib.Path,
        private_root: pathlib.Path,
        platform: str = "ios",
    ) -> pathlib.Path:
        evidence = {
            "app_version": custody.release_identity()[0],
            "build_number": custody.release_identity()[1],
            "host_uuids": [DWARF_UUID.lower()],
            "packet_tunnel_uuids": [PACKET_TUNNEL_UUID.lower()],
            "watch_uuids": [WATCH_UUID.lower()],
            "dsym_uuids": sorted(
                [
                    DWARF_UUID.lower(),
                    PACKET_TUNNEL_UUID.lower(),
                    WATCH_UUID.lower(),
                ]
            ),
        }
        with mock.patch.object(
            custody, "_authoritative_ios_evidence", return_value=evidence
        ), mock.patch.object(
            custody, "_copied_dsym_uuids", return_value=evidence["dsym_uuids"]
        ):
            return custody.collect(
                platform,
                artifact,
                flutter,
                archive,
                private_root,
                allow_test_root=True,
            )

    def validate(
        self,
        destination: pathlib.Path,
        artifact: pathlib.Path,
        archive: pathlib.Path,
    ) -> None:
        values = sorted(
            [DWARF_UUID.lower(), PACKET_TUNNEL_UUID.lower(), WATCH_UUID.lower()]
        )
        with mock.patch.object(custody, "_copied_dsym_uuids", return_value=values):
            custody.validate_manifest(destination, artifact, "ios", archive)

    def assert_no_manifest(self, private_root: pathlib.Path) -> None:
        self.assertEqual(list(private_root.rglob("manifest.json")), [])

    def rewrite_manifest_inventory(self, destination: pathlib.Path) -> None:
        manifest = destination / "manifest.json"
        payload = json.loads(manifest.read_text(encoding="ascii"))
        payload["xcarchive_dsyms"] = custody.inventory(destination / "dSYMs")
        manifest.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="ascii"
        )

    def test_source_binds_original_paths_with_lstat_and_nofollow(self) -> None:
        text = (ROOT / "tools/apple_release_symbol_custody.py").read_text(encoding="ascii")
        self.assertIn("O_NOFOLLOW", text)
        self.assertIn(".lstat(", text)
        self.assertNotIn("expanduser().resolve(strict=True)", text)

    def test_collect_preserves_exact_uuid_and_hash_custody(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            artifact, flutter, archive, private_root = self.fixture(root)
            destination = self.collect(artifact, flutter, archive, private_root)
            artifact_digest = _sha256_bytes(ARTIFACT_BYTES)
            self.assertEqual(destination.name, artifact_digest)
            dwarf_dest = (
                destination
                / "dSYMs"
                / "Runner.app.dSYM"
                / "Contents"
                / "Resources"
                / "DWARF"
                / "Runner"
            )
            symbol_dest = destination / "flutter" / "app.ios-arm64.symbols"
            self.assertEqual(dwarf_dest.read_bytes(), DWARF_BYTES)
            self.assertIn(DWARF_UUID.encode("ascii"), dwarf_dest.read_bytes())
            self.assertEqual(symbol_dest.read_bytes(), SYMBOL_BYTES)
            self.assertEqual(custody.sha256_file(dwarf_dest), _sha256_bytes(DWARF_BYTES))
            self.assertEqual(custody.sha256_file(symbol_dest), _sha256_bytes(SYMBOL_BYTES))
            payload = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["contract"], custody.CONTRACT)
            self.assertEqual(payload["artifact"]["sha256"], artifact_digest)
            self.assertEqual(payload["artifact"]["size"], len(ARTIFACT_BYTES))
            dwarf_records = [
                item
                for item in payload["xcarchive_dsyms"]
                if str(item["path"]).endswith("DWARF/Runner")
            ]
            self.assertEqual(len(dwarf_records), 1)
            self.assertEqual(dwarf_records[0]["sha256"], _sha256_bytes(DWARF_BYTES))
            self.assertEqual(dwarf_records[0]["size"], len(DWARF_BYTES))
            symbol_records = [
                item
                for item in payload["flutter_symbols"]
                if item["path"] == "app.ios-arm64.symbols"
            ]
            self.assertEqual(len(symbol_records), 1)
            self.assertEqual(symbol_records[0]["sha256"], _sha256_bytes(SYMBOL_BYTES))
            again = self.collect(artifact, flutter, archive, private_root)
            self.assertEqual(again, destination)
            self.validate(destination, artifact, archive)

            closure = json.loads(
                (destination / "dSYMs" / custody.CLOSURE_FILENAME).read_text(
                    encoding="ascii"
                )
            )
            self.assertEqual(closure["contract"], custody.CLOSURE_CONTRACT)
            self.assertEqual(closure["artifact"]["sha256"], artifact_digest)
            self.assertEqual(closure["xcarchive"]["filename"], archive.name)
            self.assertEqual(closure["host_uuids"], [DWARF_UUID.lower()])
            self.assertEqual(
                closure["packet_tunnel_uuids"], [PACKET_TUNNEL_UUID.lower()]
            )
            self.assertEqual(closure["watch_uuids"], [WATCH_UUID.lower()])
            self.assertEqual(
                closure["producer_source_sha256"],
                custody.sha256_file(ROOT / "tools/apple_release_symbol_custody.py"),
            )
            self.assertEqual(
                closure["ios_verifier_source_sha256"],
                custody.sha256_file(ROOT / "tools/verify_ios_release_artifact.py"),
            )
            serialized = json.dumps(closure, sort_keys=True)
            self.assertNotIn(str(root), serialized)

    def test_existing_receipt_rejects_cross_candidate_xcarchive(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            artifact, flutter, archive, private_root = self.fixture(root)
            self.collect(artifact, flutter, archive, private_root)
            alternate_root = root / "alternate"
            alternate_archive = alternate_root / archive.name
            shutil.copytree(archive, alternate_archive)
            (alternate_archive / "cross-candidate.txt").write_bytes(b"different archive")
            with self.assertRaisesRegex(custody.CustodyError, "xcarchive inventory is stale"):
                self.collect(artifact, flutter, alternate_archive, private_root)

    def test_archive_drift_after_collection_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            artifact, flutter, archive, private_root = self.fixture(root)
            destination = self.collect(artifact, flutter, archive, private_root)
            (archive / "late-debug-map").write_bytes(b"drift")
            with self.assertRaisesRegex(custody.CustodyError, "xcarchive inventory is stale"):
                self.validate(destination, artifact, archive)

    def test_cli_verify_checks_the_named_archive(self) -> None:
        # R23 A-3: `verify --archive` parsed the archive and then ignored it.
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            artifact, flutter, archive, private_root = self.fixture(root)
            self.collect(artifact, flutter, archive, private_root)
            values = sorted(
                [DWARF_UUID.lower(), PACKET_TUNNEL_UUID.lower(), WATCH_UUID.lower()]
            )

            def run_verify(*extra: str) -> int:
                argv = [
                    "apple_release_symbol_custody.py",
                    "verify",
                    "--platform",
                    "ios",
                    "--artifact",
                    str(artifact),
                    "--private-root",
                    str(private_root),
                    *extra,
                ]
                with mock.patch.object(sys, "argv", argv), mock.patch.object(
                    custody, "_copied_dsym_uuids", return_value=values
                ), mock.patch("sys.stdout"):
                    return custody.main()

            self.assertEqual(run_verify("--archive", str(archive)), 0)
            (archive / "late-debug-map").write_bytes(b"drift")
            with self.assertRaisesRegex(custody.CustodyError, "xcarchive inventory is stale"):
                run_verify("--archive", str(archive))
            renamed = root / "Other.xcarchive"
            archive.rename(renamed)
            with self.assertRaisesRegex(custody.CustodyError, "belongs to another xcarchive"):
                run_verify("--archive", str(renamed))

    def test_missing_watch_dsym_coverage_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            artifact, flutter, archive, private_root = self.fixture(root)
            evidence = {
                "app_version": custody.release_identity()[0],
                "build_number": custody.release_identity()[1],
                "host_uuids": [DWARF_UUID.lower()],
                "packet_tunnel_uuids": [PACKET_TUNNEL_UUID.lower()],
                "watch_uuids": [WATCH_UUID.lower()],
                "dsym_uuids": [DWARF_UUID.lower(), PACKET_TUNNEL_UUID.lower()],
            }
            with mock.patch.object(
                custody, "_authoritative_ios_evidence", return_value=evidence
            ):
                with self.assertRaisesRegex(custody.CustodyError, "Watch UUIDs"):
                    custody.collect(
                        "ios",
                        artifact,
                        flutter,
                        archive,
                        private_root,
                        allow_test_root=True,
                    )
            self.assert_no_manifest(private_root)

    def test_bcsymbolmaps_are_copied_and_uuid_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            artifact, flutter, archive, private_root = self.fixture(root)
            maps = archive / "BCSymbolMaps"
            maps.mkdir()
            source = maps / f"{DWARF_UUID}.bcsymbolmap"
            source.write_bytes(b"bcsymbolmap" + b"b" * 96)
            destination = self.collect(artifact, flutter, archive, private_root)
            copied = destination / "dSYMs" / "BCSymbolMaps" / source.name
            self.assertEqual(copied.read_bytes(), source.read_bytes())
            closure = json.loads(
                (destination / "dSYMs" / custody.CLOSURE_FILENAME).read_text(
                    encoding="ascii"
                )
            )
            self.assertEqual(closure["bcsymbolmap_uuids"], [DWARF_UUID.lower()])

    def test_unmatched_bcsymbolmap_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            artifact, flutter, archive, private_root = self.fixture(root)
            maps = archive / "BCSymbolMaps"
            maps.mkdir()
            maps.joinpath("7B1D0000-1111-2222-3333-444444444444.bcsymbolmap").write_bytes(
                b"unmatched-map" + b"m" * 96
            )
            with self.assertRaisesRegex(custody.CustodyError, "BCSymbolMap UUIDs"):
                self.collect(artifact, flutter, archive, private_root)
            self.assert_no_manifest(private_root)

    def test_hardlinked_artifact_and_symbol_inputs_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            artifact, flutter, archive, private_root = self.fixture(root)
            artifact_alias = root / "artifact-hardlink.ipa"
            os.link(artifact, artifact_alias)
            with self.assertRaisesRegex(custody.CustodyError, "unsafe|empty"):
                self.collect(artifact, flutter, archive, private_root)
            artifact_alias.unlink()
            symbol = flutter / "app.ios-arm64.symbols"
            os.link(symbol, flutter / "hardlink.ios-arm64.symbols")
            with self.assertRaisesRegex(custody.CustodyError, "hard-linked"):
                self.collect(artifact, flutter, archive, private_root)
            self.assert_no_manifest(private_root)

    def test_same_path_artifact_replacement_during_hash_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            artifact, flutter, archive, private_root = self.fixture(root)
            original_sha256_fd = custody._sha256_fd
            replaced = False

            def replace_after_hash(fd: int, size: int, label: str) -> str:
                nonlocal replaced
                digest = original_sha256_fd(fd, size, label)
                if label == "Apple release artifact" and not replaced:
                    replaced = True
                    artifact.rename(root / "held-original.ipa")
                    artifact.write_bytes(b"cross-candidate replacement")
                return digest

            with mock.patch.object(custody, "_sha256_fd", side_effect=replace_after_hash):
                with self.assertRaisesRegex(custody.CustodyError, "replaced"):
                    self.collect(artifact, flutter, archive, private_root)
            self.assert_no_manifest(private_root)

    def test_forged_source_closure_is_rejected_even_if_manifest_is_rehashed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            artifact, flutter, archive, private_root = self.fixture(root)
            destination = self.collect(artifact, flutter, archive, private_root)
            closure_path = destination / "dSYMs" / custody.CLOSURE_FILENAME
            closure = json.loads(closure_path.read_text(encoding="ascii"))
            closure["producer_source_sha256"] = "0" * 64
            closure_path.write_text(
                json.dumps(closure, indent=2, sort_keys=True) + "\n", encoding="ascii"
            )
            self.rewrite_manifest_inventory(destination)
            with self.assertRaisesRegex(custody.CustodyError, "producer source closure"):
                self.validate(destination, artifact, archive)

    def test_copied_dsym_uuid_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            artifact, flutter, archive, private_root = self.fixture(root)
            destination = self.collect(artifact, flutter, archive, private_root)
            drifted = sorted([DWARF_UUID.lower(), PACKET_TUNNEL_UUID.lower()])
            with mock.patch.object(custody, "_copied_dsym_uuids", return_value=drifted):
                with self.assertRaisesRegex(custody.CustodyError, "dSYM UUIDs differ"):
                    custody.validate_manifest(destination, artifact, "ios", archive)

    def test_verifier_loader_ignores_preloaded_module_injection(self) -> None:
        module_name = "_winsvpn_symbol_custody_ios_verifier"
        poisoned = object()
        with mock.patch.dict(sys.modules, {module_name: poisoned}):
            loaded = custody._load_ios_verifier()
        self.assertEqual(
            pathlib.Path(loaded.__file__).resolve(),
            (ROOT / "tools/verify_ios_release_artifact.py").resolve(),
        )
        self.assertIsNot(loaded, poisoned)

    def test_require_safe_file_binds_original_inode_not_a_followed_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            artifact = root / "WinsVPN.ipa"
            artifact.write_bytes(ARTIFACT_BYTES)
            before = artifact.lstat()
            bound = custody.require_safe_file(artifact, "Apple release artifact")
            after = bound.lstat()
            self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))
            self.assertEqual(bound, pathlib.Path(os.path.abspath(artifact)))
            self.assertFalse(stat.S_ISLNK(after.st_mode))

    def test_top_level_artifact_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            artifact, flutter, archive, private_root = self.fixture(root)
            outside = root / "outside.ipa"
            outside.write_bytes(b"hostile-artifact-bytes")
            alias = root / "alias.ipa"
            alias.symlink_to(outside)
            with self.assertRaisesRegex(custody.CustodyError, "unsafe|symlink"):
                custody.require_safe_file(alias, "Apple release artifact")
            with self.assertRaisesRegex(custody.CustodyError, "unsafe|symlink"):
                custody.sha256_file(alias)
            with self.assertRaisesRegex(custody.CustodyError, "unsafe|symlink"):
                self.collect(alias, flutter, archive, private_root)
            self.assert_no_manifest(private_root)
            self.assertEqual(outside.read_bytes(), b"hostile-artifact-bytes")

    def test_top_level_archive_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            artifact, flutter, archive, private_root = self.fixture(root)
            alias = root / "alias.xcarchive"
            alias.symlink_to(archive, target_is_directory=True)
            self.assertTrue(alias.is_symlink())
            self.assertTrue(alias.resolve().is_dir())
            with self.assertRaisesRegex(custody.CustodyError, "unsafe|symlink|xcarchive"):
                self.collect(artifact, flutter, alias, private_root)
            self.assert_no_manifest(private_root)

    def test_top_level_flutter_root_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            artifact, flutter, archive, private_root = self.fixture(root)
            alias = root / "flutter-alias"
            alias.symlink_to(flutter, target_is_directory=True)
            with self.assertRaisesRegex(custody.CustodyError, "unsafe|symlink"):
                self.collect(artifact, alias, archive, private_root)
            self.assert_no_manifest(private_root)

    def test_nested_flutter_directory_symlink_substitution_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            artifact, flutter, archive, private_root = self.fixture(root)
            outside = root / "outside-symbols"
            outside.mkdir()
            (outside / "pwned.symbols").write_bytes(b"pwned-flutter-symbols" + b"p" * 64)
            nested = flutter / "nested"
            nested.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(custody.CustodyError, "symlink"):
                self.collect(artifact, flutter, archive, private_root)
            self.assert_no_manifest(private_root)

    def test_nested_flutter_file_symlink_substitution_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            artifact, flutter, archive, private_root = self.fixture(root)
            outside = root / "pwned.ios-arm64.symbols"
            outside.write_bytes(b"pwned-file-symbols" + b"p" * 64)
            linked = flutter / "extra.ios-arm64.symbols"
            linked.symlink_to(outside)
            with self.assertRaisesRegex(custody.CustodyError, "symlink"):
                self.collect(artifact, flutter, archive, private_root)
            self.assert_no_manifest(private_root)

    def test_nested_dsym_bundle_symlink_substitution_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            artifact, flutter, archive, private_root = self.fixture(root)
            outside = root / "evil.dSYM"
            dwarf = outside / "Contents" / "Resources" / "DWARF"
            dwarf.mkdir(parents=True)
            (dwarf / "Runner").write_bytes(b"hostile-dwarf-uuid-payload" + b"h" * 64)
            linked = archive / "dSYMs" / "PacketTunnel.appex.dSYM"
            linked.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(custody.CustodyError, "symlink"):
                self.collect(artifact, flutter, archive, private_root)
            self.assert_no_manifest(private_root)

    def test_nested_dwarf_file_symlink_substitution_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            artifact, flutter, archive, private_root = self.fixture(root)
            dwarf = archive / "dSYMs" / "Runner.app.dSYM" / "Contents" / "Resources" / "DWARF" / "Runner"
            outside = root / "hostile-dwarf"
            outside.write_bytes(b"substituted-uuid-bytes" + b"x" * 64)
            dwarf.unlink()
            dwarf.symlink_to(outside)
            with self.assertRaisesRegex(custody.CustodyError, "symlink"):
                self.collect(artifact, flutter, archive, private_root)
            self.assert_no_manifest(private_root)

    def test_dsyms_directory_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            artifact, flutter, archive, private_root = self.fixture(root)
            real = archive / "dSYMs"
            parked = root / "parked-dSYMs"
            real.rename(parked)
            real.symlink_to(parked, target_is_directory=True)
            with self.assertRaisesRegex(custody.CustodyError, "symlink|dSYMs"):
                self.collect(artifact, flutter, archive, private_root)
            self.assert_no_manifest(private_root)

    def test_macos_pkg_hash_key_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            _artifact, flutter, archive, private_root = self.fixture(root)
            pkg = root / "WinsVPN.pkg"
            pkg.write_bytes(b"exact-apple-pkg-artifact")
            destination = self.collect(pkg, flutter, archive, private_root, platform="macos")
            self.assertEqual(destination.name, _sha256_bytes(b"exact-apple-pkg-artifact"))
            payload = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["platform"], "macos")
            self.assertEqual(payload["artifact"]["filename"], "WinsVPN.pkg")


class FrameworkSymlinkInventoryTests(unittest.TestCase):
    """A macOS xcarchive holds versioned frameworks built from two symlink shapes."""

    def _tree(self, root: pathlib.Path, links: dict[str, str]) -> int:
        framework = root / "Products/Applications/Win's VPN.app/Contents/Frameworks/App.framework"
        (framework / "Versions/A/Resources").mkdir(parents=True)
        (framework / "Versions/A/App").write_bytes(b"framework-binary")
        (framework / "Versions/A/Resources/Info.plist").write_bytes(b"plist")
        for link, target in links.items():
            os.symlink(target, framework / link)
        return os.open(root, os.O_RDONLY | os.O_DIRECTORY)

    def test_versioned_framework_symlinks_are_recorded_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fd = self._tree(
                pathlib.Path(temporary),
                {
                    "Versions/Current": "A",
                    "App": "Versions/Current/App",
                    "Resources": "Versions/Current/Resources",
                },
            )
            try:
                records = custody._directory_inventory(
                    fd, "xcarchive", allow_framework_symlinks=True
                )
                with self.assertRaisesRegex(custody.CustodyError, "contains a symlink"):
                    custody._directory_inventory(fd, "xcarchive")
            finally:
                os.close(fd)
        links = {str(r["path"]).split("App.framework/", 1)[1]: r["symlink"] for r in records if "symlink" in r}
        self.assertEqual(
            links,
            {
                "App": "Versions/Current/App",
                "Resources": "Versions/Current/Resources",
                "Versions/Current": "A",
            },
        )
        self.assertEqual(sum(1 for r in records if "sha256" in r), 2)

    def test_any_other_symlink_is_refused(self) -> None:
        for link, target in (
            ("Versions/Current", "../../outside"),
            ("Versions/Current", "A/../B"),
            ("App", "/etc/passwd"),
            ("App", "Versions/Current/Other"),
            ("Versions/A/Link", "Resources"),
        ):
            with self.subTest(link=link, target=target):
                with tempfile.TemporaryDirectory() as temporary:
                    fd = self._tree(pathlib.Path(temporary), {link: target})
                    try:
                        with self.assertRaisesRegex(custody.CustodyError, "contains a symlink"):
                            custody._directory_inventory(
                                fd, "xcarchive", allow_framework_symlinks=True
                            )
                    finally:
                        os.close(fd)
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "Contents").mkdir()
            (root / "Contents/real").write_bytes(b"x")
            os.symlink("real", root / "Contents/Link")
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaisesRegex(custody.CustodyError, "contains a symlink"):
                    custody._directory_inventory(fd, "xcarchive", allow_framework_symlinks=True)
            finally:
                os.close(fd)


if __name__ == "__main__":
    unittest.main(verbosity=2)
