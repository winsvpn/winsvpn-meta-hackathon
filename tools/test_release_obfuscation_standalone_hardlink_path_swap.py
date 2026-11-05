#!/usr/bin/env python3
"""Standalone record/verify must not PASS a hardlink or live path-swap."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

TOOLS = pathlib.Path(__file__).resolve().parent
ROOT = TOOLS.parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import release_obfuscation_contract as obfuscation
import release_secret_inventory as inventory
import validate_release_artifact_privacy as privacy


class StandaloneHardlinkPathSwapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.private_root = (self.root / "private-release-symbols").resolve()
        self.symbols = self.private_root / "android-apk" / "1.0.15+30"
        self.symbols.mkdir(parents=True)
        (self.symbols / "app.android-arm64.symbols").write_bytes(b"s" * 128)
        (self.symbols / "proguard-mapping.txt").write_bytes(
            b"# compiler: R8\n" + (b"com.example.Keep -> a:\n" * 160)
        )
        self.manifest = self.symbols / "manifest.json"
        self.artifact = self.root / "app-release.apk"
        self.clean_path = self.root / "app-release.clean.apk"
        self.stash_path = self.root / "app-release.stash.apk"
        self.created_dirs: list[pathlib.Path] = []
        self.real_mkdtemp = tempfile.mkdtemp
        self.version_patch = mock.patch.object(
            obfuscation, "pubspec_version", return_value=("1.0.15", "30")
        )
        self.private_patch = mock.patch.object(
            obfuscation, "PRIVATE_SYMBOL_ROOT", self.private_root
        )
        self.static_patch = mock.patch.object(obfuscation, "validate_static")
        self.synthetic_inventory = inventory.SecretInventory(
            "synthetic-obfuscation-test-1",
            {"SYNTHETIC_RELEASE_SECRET": "synthetic-release-secret-0001"},
        )
        self.inventory_loader_patch = mock.patch.object(
            inventory,
            "load_authenticated_secret_inventory",
            return_value=self.synthetic_inventory,
        )
        self.release_values_patch = mock.patch.object(
            privacy,
            "release_secret_values",
            side_effect=lambda loaded: loaded._stream_secret_values(),
        )
        self.version_patch.start()
        self.private_patch.start()
        self.static_patch.start()
        self.inventory_loader_patch.start()
        self.release_values_patch.start()
        self.mkdtemp_patch = mock.patch.object(
            tempfile, "mkdtemp", side_effect=self._tracking_mkdtemp
        )
        self.mkdtemp_patch.start()

    def tearDown(self) -> None:
        self.mkdtemp_patch.stop()
        self.release_values_patch.stop()
        self.inventory_loader_patch.stop()
        self.static_patch.stop()
        self.private_patch.stop()
        self.version_patch.stop()
        for path in self.created_dirs:
            shutil.rmtree(path, ignore_errors=True)
        self.temporary.cleanup()

    def _tracking_mkdtemp(self, *args, **kwargs):
        created = self.real_mkdtemp(*args, **kwargs)
        prefix = kwargs.get("prefix") or (args[0] if args else "")
        if str(prefix).startswith(obfuscation.STANDALONE_HARDENING_SNAPSHOT_PREFIX):
            self.created_dirs.append(pathlib.Path(created))
        return created

    def _apk_bytes(self, *, dirty: bool) -> bytes:
        stripped = obfuscation._minimal_elf64(".text", ".dynsym")
        debug = obfuscation._minimal_elf64(".text", ".debug_info")
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("lib/arm64-v8a/libapp.so", stripped)
            archive.writestr(
                "lib/arm64-v8a/libxray.so",
                debug if dirty else stripped,
            )
        return buffer.getvalue()

    def _write_apk(self, path: pathlib.Path, *, dirty: bool) -> bytes:
        payload = self._apk_bytes(dirty=dirty)
        path.write_bytes(payload)
        return payload

    def _assert_no_snapshot_leftovers(self) -> None:
        leftovers = [
            path
            for path in self.created_dirs
            if path.exists()
        ]
        self.assertEqual(leftovers, [])

    def _assert_not_production_pass(self, output: str) -> None:
        self.assertNotIn("RELEASE OBFUSCATION EVIDENCE: PASS", output)

    def _capture_record(self) -> str:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            obfuscation.record(
                "android-apk",
                self.symbols,
                self.manifest,
                [self.artifact],
            )
        return stdout.getvalue()

    def _capture_verify(self) -> str:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            obfuscation.verify(
                "android-apk",
                self.manifest,
                self.symbols,
                [self.artifact],
            )
        return stdout.getvalue()

    def test_unauthenticated_inventory_cannot_pass_production_hardening(self) -> None:
        self._write_apk(self.artifact, dirty=False)
        with mock.patch.object(
            privacy,
            "release_secret_values",
            inventory.release_secret_values,
        ):
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "not release coverage"
            ):
                obfuscation.verify_release_artifact_hardening(
                    "android-apk", [self.artifact]
                )

    def _swap_live_to_clean(self) -> None:
        os.replace(self.artifact, self.stash_path)
        os.replace(self.clean_path, self.artifact)

    def _restore_live_from_clean(self) -> None:
        os.replace(self.artifact, self.clean_path)
        os.replace(self.stash_path, self.artifact)

    def test_valid_apk_record_and_verify_use_private_snapshot(self) -> None:
        self._write_apk(self.artifact, dirty=False)
        seen: list[pathlib.Path] = []
        real = obfuscation.verify_release_artifact_hardening

        def capture(platform: str, paths: list[pathlib.Path]) -> None:
            seen.extend(pathlib.Path(item) for item in paths)
            return real(platform, paths)

        with mock.patch.object(
            obfuscation, "verify_release_artifact_hardening", side_effect=capture
        ):
            output = self._capture_record()
        self.assertIn("RELEASE OBFUSCATION EVIDENCE: PASS", output)
        self.assertEqual(len(seen), 1)
        self.assertNotEqual(seen[0].resolve(), self.artifact.resolve())
        self.assertIn(obfuscation.STANDALONE_HARDENING_SNAPSHOT_PREFIX, str(seen[0]))
        self.assertEqual(seen[0].name, self.artifact.name)
        payload = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertEqual(
            payload["artifacts"][0]["sha256"],
            hashlib.sha256(self.artifact.read_bytes()).hexdigest(),
        )
        output = self._capture_verify()
        self.assertIn("RELEASE OBFUSCATION EVIDENCE: PASS", output)
        self._assert_no_snapshot_leftovers()

    def test_hardlink_source_is_rejected_by_inspect_record_and_verify(self) -> None:
        self._write_apk(self.artifact, dirty=False)
        alias = self.root / "app-release.hardlink.apk"
        os.link(self.artifact, alias)
        self.assertGreater(self.artifact.lstat().st_nlink, 1)
        stdout = io.StringIO()
        with self.assertRaisesRegex(
            obfuscation.ObfuscationError,
            "hardlink|unsafe or empty|not regular",
        ):
            with contextlib.redirect_stdout(stdout):
                obfuscation.inspect_artifacts([self.artifact])
        self._assert_not_production_pass(stdout.getvalue())
        stdout = io.StringIO()
        with self.assertRaisesRegex(
            obfuscation.ObfuscationError,
            "hardlink|unsafe or empty|not regular",
        ):
            with contextlib.redirect_stdout(stdout):
                obfuscation.record(
                    "android-apk",
                    self.symbols,
                    self.manifest,
                    [self.artifact],
                )
        self._assert_not_production_pass(stdout.getvalue())
        self.assertFalse(self.manifest.exists())
        self._write_apk(self.artifact.with_name("unique-clean.apk"), dirty=False)
        unique = self.artifact.with_name("unique-clean.apk")
        obfuscation.record("android-apk", self.symbols, self.manifest, [unique])
        os.link(unique, unique.with_name("unique-clean.alias.apk"))
        stdout = io.StringIO()
        with self.assertRaisesRegex(
            obfuscation.ObfuscationError,
            "hardlink|unsafe or empty|not regular",
        ):
            with contextlib.redirect_stdout(stdout):
                obfuscation.verify(
                    "android-apk",
                    self.manifest,
                    self.symbols,
                    [unique],
                )
        self._assert_not_production_pass(stdout.getvalue())
        self._assert_no_snapshot_leftovers()

    def test_clean_bytes_path_swap_during_record_hardening_cannot_pass(self) -> None:
        dirty = self._write_apk(self.artifact, dirty=True)
        self._write_apk(self.clean_path, dirty=False)
        real = obfuscation.verify_release_artifact_hardening

        def swap_clean_bytes(_platform: str, paths: list[pathlib.Path]) -> None:
            self.assertTrue(
                any(
                    obfuscation.STANDALONE_HARDENING_SNAPSHOT_PREFIX in str(path)
                    for path in paths
                )
            )
            self._swap_live_to_clean()
            try:
                return real(_platform, paths)
            finally:
                self._restore_live_from_clean()

        stdout = io.StringIO()
        with mock.patch.object(
            obfuscation,
            "verify_release_artifact_hardening",
            side_effect=swap_clean_bytes,
        ):
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError,
                "debug|unstripped|native",
            ):
                with contextlib.redirect_stdout(stdout):
                    obfuscation.record(
                        "android-apk",
                        self.symbols,
                        self.manifest,
                        [self.artifact],
                    )
        self._assert_not_production_pass(stdout.getvalue())
        self.assertEqual(self.artifact.read_bytes(), dirty)
        self.assertFalse(self.manifest.exists())
        self._assert_no_snapshot_leftovers()

    def test_clean_bytes_path_swap_during_verify_hardening_cannot_pass(self) -> None:
        self._write_apk(self.artifact, dirty=False)
        self._capture_record()
        dirty = self._write_apk(self.artifact, dirty=True)
        self._write_apk(self.clean_path, dirty=False)
        payload = json.loads(self.manifest.read_text(encoding="utf-8"))
        payload["artifacts"][0]["sha256"] = hashlib.sha256(dirty).hexdigest()
        payload["artifacts"][0]["size"] = len(dirty)
        self.manifest.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        real = obfuscation.verify_release_artifact_hardening

        def swap_clean_bytes(_platform: str, paths: list[pathlib.Path]) -> None:
            self._swap_live_to_clean()
            try:
                return real(_platform, paths)
            finally:
                self._restore_live_from_clean()

        stdout = io.StringIO()
        with mock.patch.object(
            obfuscation,
            "verify_release_artifact_hardening",
            side_effect=swap_clean_bytes,
        ):
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError,
                "debug|unstripped|native|does not match",
            ):
                with contextlib.redirect_stdout(stdout):
                    obfuscation.verify(
                        "android-apk",
                        self.manifest,
                        self.symbols,
                        [self.artifact],
                    )
        self._assert_not_production_pass(stdout.getvalue())
        self.assertEqual(self.artifact.read_bytes(), dirty)
        self._assert_no_snapshot_leftovers()

    def test_path_replacement_and_post_check_mutation_are_rejected(self) -> None:
        self._write_apk(self.artifact, dirty=False)
        real = obfuscation.verify_release_artifact_hardening

        def replace_with_copy(_platform: str, paths: list[pathlib.Path]) -> None:
            real(_platform, paths)
            payload = self.artifact.read_bytes()
            replacement = self.root / "app-release.replaced.apk"
            replacement.write_bytes(payload)
            os.replace(replacement, self.artifact)

        stdout = io.StringIO()
        with mock.patch.object(
            obfuscation,
            "verify_release_artifact_hardening",
            side_effect=replace_with_copy,
        ):
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError,
                "replaced|swapped|restored|aliased|changed while",
            ):
                with contextlib.redirect_stdout(stdout):
                    obfuscation.record(
                        "android-apk",
                        self.symbols,
                        self.manifest,
                        [self.artifact],
                    )
        self._assert_not_production_pass(stdout.getvalue())

        self._write_apk(self.artifact, dirty=False)

        def mutate_after(_platform: str, paths: list[pathlib.Path]) -> None:
            real(_platform, paths)
            current = self.artifact.read_bytes()
            self.artifact.write_bytes(current + b"\x00")

        stdout = io.StringIO()
        with mock.patch.object(
            obfuscation,
            "verify_release_artifact_hardening",
            side_effect=mutate_after,
        ):
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError,
                "replaced|swapped|restored|aliased|changed while",
            ):
                with contextlib.redirect_stdout(stdout):
                    obfuscation.record(
                        "android-apk",
                        self.symbols,
                        self.manifest,
                        [self.artifact],
                    )
        self._assert_not_production_pass(stdout.getvalue())
        self._assert_no_snapshot_leftovers()

    def test_aliasing_during_hardening_and_cleanup_failure_cannot_pass(self) -> None:
        self._write_apk(self.artifact, dirty=False)
        alias = self.root / "app-release.alias.apk"
        real = obfuscation.verify_release_artifact_hardening

        def alias_source(_platform: str, paths: list[pathlib.Path]) -> None:
            real(_platform, paths)
            os.link(self.artifact, alias)

        stdout = io.StringIO()
        with mock.patch.object(
            obfuscation,
            "verify_release_artifact_hardening",
            side_effect=alias_source,
        ):
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError,
                "hardlink|unsafe or empty|not regular|aliased|changed while",
            ):
                with contextlib.redirect_stdout(stdout):
                    obfuscation.record(
                        "android-apk",
                        self.symbols,
                        self.manifest,
                        [self.artifact],
                    )
        self._assert_not_production_pass(stdout.getvalue())
        if alias.exists():
            alias.unlink()

        self._write_apk(self.artifact, dirty=False)
        real_unlink = os.unlink

        def busy_snapshot_unlink(path, *args, **kwargs):
            if obfuscation.STANDALONE_HARDENING_SNAPSHOT_PREFIX in os.fspath(path):
                raise OSError("snapshot busy")
            return real_unlink(path, *args, **kwargs)

        stdout = io.StringIO()
        with mock.patch.object(os, "unlink", side_effect=busy_snapshot_unlink):
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError,
                "cleanup failed",
            ):
                with contextlib.redirect_stdout(stdout):
                    obfuscation.record(
                        "android-apk",
                        self.symbols,
                        self.manifest,
                        [self.artifact],
                    )
        self._assert_not_production_pass(stdout.getvalue())
        self.assertFalse(self.manifest.exists())

    def test_symlink_source_is_rejected(self) -> None:
        self._write_apk(self.artifact, dirty=False)
        linked = self.root / "app-release.link.apk"
        os.symlink(self.artifact.name, linked)
        stdout = io.StringIO()
        with self.assertRaisesRegex(obfuscation.ObfuscationError, "symlink"):
            with contextlib.redirect_stdout(stdout):
                obfuscation.record(
                    "android-apk",
                    self.symbols,
                    self.manifest,
                    [linked],
                )
        self._assert_not_production_pass(stdout.getvalue())
        self._assert_no_snapshot_leftovers()


if __name__ == "__main__":
    unittest.main()
