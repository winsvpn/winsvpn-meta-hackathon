#!/usr/bin/env python3
"""Garble mode for the website-only Winn client engines (owner ruling 2026-10-27).

Covers the two refusals that keep obfuscation from weakening a gate: the
release driver garbles only website client engines, and a garbled Windows
engine takes its role only from a signed manifest row naming its exact bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import windows_winn3_artifact_provenance as prov  # noqa: E402
import winn_release as wr  # noqa: E402

OBFUSCATION = {
    "executable_sha256": "a" * 64,
    "flags": ["-literals", "-tiny"],
    "seed_sha256": "b" * 64,
    "tool": "mvdan.cc/garble",
    "version": "v0.18.0",
}


def signed_entry(data: bytes, *, target: str, package: str, role: str, goarch: str = "amd64") -> dict:
    return {
        "artifact": {
            "target": target,
            "package": package,
            "role": role,
            "goos": "windows",
            "goarch": goarch,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "obfuscation": dict(OBFUSCATION),
        },
        "manifest_obfuscation": dict(OBFUSCATION),
    }


class ObfuscatedRoleTests(unittest.TestCase):
    core = b"garbled core bytes " * 64
    relay = b"garbled relay bytes " * 64

    def core_entry(self, data: bytes | None = None) -> dict:
        return signed_entry(data or self.core, target="datapath-windows-amd64",
                            package="./cmd/winn-datapath", role="datapath")

    def relay_entry(self, data: bytes | None = None) -> dict:
        return signed_entry(data or self.relay, target="winn3-relay-windows-amd64",
                            package=".", role="winn3-relay")

    def test_signed_rows_name_each_role(self) -> None:
        core = prov._obfuscated_role_facts(self.core, role="core", architecture="x64",
                                           signed_entry=self.core_entry())
        relay = prov._obfuscated_role_facts(self.relay, role="relay", architecture="x64",
                                            signed_entry=self.relay_entry())
        self.assertEqual(core["go_path"], "datapath-windows-amd64:./cmd/winn-datapath")
        self.assertEqual(relay["go_path"], "winn3-relay-windows-amd64:.")
        self.assertEqual(core["go_version"], "unknown")

    def test_a_garbled_engine_without_a_signed_row_is_refused(self) -> None:
        with self.assertRaisesRegex(prov.ProvenanceError, "needs --signed-entry"):
            prov._obfuscated_role_facts(self.core, role="core", architecture="x64", signed_entry=None)

    def test_relay_bytes_cannot_pass_as_the_core(self) -> None:
        # The relay carries no Winn cryptography; staging it as the core would
        # put cleartext on the wire. Its own signed row must not admit it.
        with self.assertRaisesRegex(prov.ProvenanceError, "does not name these garbled bytes"):
            prov._obfuscated_role_facts(self.relay, role="core", architecture="x64",
                                        signed_entry=self.relay_entry())

    def test_a_row_for_other_bytes_is_refused(self) -> None:
        with self.assertRaisesRegex(prov.ProvenanceError, "does not name these garbled bytes"):
            prov._obfuscated_role_facts(self.core + b"!", role="core", architecture="x64",
                                        signed_entry=self.core_entry())

    def test_the_wrong_architecture_is_refused(self) -> None:
        entry = signed_entry(self.core, target="datapath-windows-arm64",
                             package="./cmd/winn-datapath", role="datapath", goarch="arm64")
        with self.assertRaisesRegex(prov.ProvenanceError, "does not name these garbled bytes"):
            prov._obfuscated_role_facts(self.core, role="core", architecture="x64", signed_entry=entry)

    def test_a_row_without_garble_is_refused(self) -> None:
        entry = self.core_entry()
        entry["artifact"]["obfuscation"] = {**OBFUSCATION, "tool": "other"}
        entry["manifest_obfuscation"] = dict(entry["artifact"]["obfuscation"])
        with self.assertRaisesRegex(prov.ProvenanceError, "does not name these garbled bytes"):
            prov._obfuscated_role_facts(self.core, role="core", architecture="x64", signed_entry=entry)

    def test_bytes_that_still_name_a_module_are_refused(self) -> None:
        data = self.core + b"winsvpn.local/winnprotocol"
        with self.assertRaisesRegex(prov.ProvenanceError, "still name"):
            prov._obfuscated_role_facts(data, role="core", architecture="x64",
                                        signed_entry=self.core_entry(data))


class ReleaseDriverGarbleScopeTests(unittest.TestCase):
    def build_args(self, out: Path, targets: str, **extra: object) -> argparse.Namespace:
        values = dict(out=str(out), set=None, targets=targets, source_commit="0" * 40,
                      source_export=None, go_archive=None, ndk=None, developer_dir=None,
                      module_proxy="off", jobs=1, skip_unavailable=False, keep_work=False,
                      obfuscate="none", garble_seed_file=None)
        values.update(extra)
        return argparse.Namespace(**values)

    def test_a_garble_release_needs_a_website_engine(self) -> None:
        for target in ("datapath-ios-arm64", "datapath-archive-darwin-arm64",
                       "winn3-gateway-linux-amd64", "server-linux-amd64", "linux-amd64"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                args = self.build_args(Path(tmp) / "out", target, obfuscate="garble",
                                       garble_seed_file="/nonexistent/seed")
                with self.assertRaisesRegex(wr.ReleaseError, "at least one website client engine"):
                    wr.build_release(args)

    def test_a_seed_without_garble_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = self.build_args(Path(tmp) / "out", "datapath-linux-amd64",
                                   garble_seed_file="/nonexistent/seed")
            with self.assertRaisesRegex(wr.ReleaseError, "only valid with --obfuscate garble"):
                wr.build_release(args)

    def test_website_targets_are_obfuscatable(self) -> None:
        for target in wr.SETS["android"] + wr.SETS["windows"] + ("datapath-linux-amd64", "datapath-linux-arm64"):
            self.assertTrue(target.startswith(wr.OBFUSCATABLE_PREFIXES), target)
        for target in wr.SETS["apple"] + ("winn3-gateway-linux-amd64",):
            self.assertFalse(target.startswith(wr.OBFUSCATABLE_PREFIXES), target)

    def test_garble_pin_is_exact(self) -> None:
        pins = wr.garble_pins(wr.load_garble_pin())
        self.assertRegex(pins["version"], r"^v\d+\.\d+\.\d+$")
        self.assertRegex(pins["executable_sha256"], r"^[0-9a-f]{64}$")
        with self.assertRaisesRegex(wr.ReleaseError, "no garble entry"):
            wr.garble_pins({})


class PlayBundleRefusesGarbledEngineTests(unittest.TestCase):
    def scan(self, engine: bytes, suffix: str) -> list[str]:
        import zipfile
        import android_play_redemption_gate as gate
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / f"bundle{suffix}"
            with zipfile.ZipFile(bundle, "w") as archive:
                archive.writestr("base/lib/arm64-v8a/libapp.so", b"x")
                archive.writestr("base/lib/arm64-v8a/libwinnengine.so", engine)
            return gate.scan_aab(bundle, [])[1]

    def test_a_garbled_engine_in_an_aab_fails(self) -> None:
        self.assertEqual(len(self.scan(b"garbled", ".aab")), 1)

    def test_a_plain_engine_in_an_aab_passes(self) -> None:
        self.assertEqual(self.scan(b"..winsvpn.local/winnprotocol/winn3/core..", ".aab"), [])

    def test_the_website_apk_may_carry_a_garbled_engine(self) -> None:
        self.assertEqual(self.scan(b"garbled", ".apk"), [])


class SignedManifestObfuscationScopeTests(unittest.TestCase):
    def test_an_obfuscation_record_on_a_store_target_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            release = Path(tmp)
            artifact = release / "artifacts" / "datapath-ios-arm64" / "libwinn-datapath.a"
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"archive")
            artifact.with_suffix(".h").write_bytes(b"header")
            digest = hashlib.sha256(b"archive").hexdigest()
            manifest = {"obfuscation": dict(OBFUSCATION), "artifacts": [{
                "target": "datapath-ios-arm64", "path": "artifacts/datapath-ios-arm64/libwinn-datapath.a",
                "sha256": digest, "build_a_sha256": digest, "build_b_sha256": digest, "size": 7,
                "header_path": "artifacts/datapath-ios-arm64/libwinn-datapath.h",
                "header_sha256": hashlib.sha256(b"header").hexdigest(),
                "obfuscation": dict(OBFUSCATION)}]}
            with self.assertRaisesRegex(wr.ReleaseError, "obfuscation record is not allowed"):
                wr.verify_artifacts(release, manifest)


if __name__ == "__main__":
    unittest.main()
