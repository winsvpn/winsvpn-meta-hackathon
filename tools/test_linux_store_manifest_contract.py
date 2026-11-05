#!/usr/bin/env python3
"""Focused tests for the Linux store manifest contract helpers."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import shutil
import sys
import tarfile
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "linux/packaging/store_manifest_contract.py"
IDENTITY = pathlib.Path("docs/rulings/RELEASE_IDENTITY_MAP_20260824.json")
FLUTTER_REVISION = "5fc346839b5d0eef006ed8404392afb4dfae428d"
FLUTTER_URL_PREFIX = (
    "https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/"
)


def _load_contract():
    spec = importlib.util.spec_from_file_location(
        "_winsvpn_test_store_manifest_contract", CONTRACT
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load store manifest contract")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CONTRACT_MODULE = _load_contract()


class StoreManifestContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name)
        identity = self.repo / IDENTITY
        identity.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / IDENTITY, identity)
        (self.repo / ".artifacts").mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _gzip_tar(self, path: pathlib.Path, payload: bytes) -> None:
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
            info = tarfile.TarInfo("./payload")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        with path.open("wb") as handle:
            with gzip.GzipFile(filename="", mode="wb", fileobj=handle, mtime=0) as compressed:
                compressed.write(tar_buffer.getvalue())

    def test_surrogate_gzip_tar_flatpak_and_snap_extensions_fail_closed(self) -> None:
        flatpak = self.repo / ".artifacts/org.winsvpn.app.flatpak"
        self._gzip_tar(flatpak, b"not a flatpak\n")
        digest = hashlib.sha256(flatpak.read_bytes()).hexdigest()
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "gzip-tar|surrogate"
        ):
            CONTRACT_MODULE.bind_native_package_receipt(
                repo=self.repo,
                target_id="linux-flathub-manifest",
                package=flatpak,
                sha256=digest,
            )
        snap = self.repo / ".artifacts/wins-vpn.snap"
        self._gzip_tar(snap, b"not a snap\n")
        snap_digest = hashlib.sha256(snap.read_bytes()).hexdigest()
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "gzip-tar|surrogate"
        ):
            CONTRACT_MODULE.bind_native_package_receipt(
                repo=self.repo,
                target_id="linux-snap-manifest",
                package=snap,
                sha256=snap_digest,
            )

    def test_package_receipts_require_exact_digest_and_target_binding(self) -> None:
        package = self.repo / ".artifacts/org.winsvpn.app.flatpak"
        package.write_bytes(b"hsqs" + b"\x00" * 64)
        digest = hashlib.sha256(package.read_bytes()).hexdigest()
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "package artifact digest"
        ):
            CONTRACT_MODULE.bind_native_package_receipt(
                repo=self.repo,
                target_id="linux-flathub-manifest",
                package=package,
                sha256="0" * 64,
            )
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "target binding"
        ):
            CONTRACT_MODULE.bind_native_package_receipt(
                repo=self.repo,
                target_id="linux-snap-manifest",
                package=package,
                sha256=digest,
            )
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "owner-blocked|native-format"
        ):
            CONTRACT_MODULE.bind_native_package_receipt(
                repo=self.repo,
                target_id="linux-flathub-manifest",
                package=package,
                sha256=digest,
            )

    def test_invalid_shell_and_architecture_mapping(self) -> None:
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "shell syntax"
        ):
            CONTRACT_MODULE.validate_shell("for do done\n", require_pinned_flutter=False)
        self.assertEqual(
            CONTRACT_MODULE.run_architecture_mapping("flatpak", "x86_64"), "x64"
        )
        self.assertEqual(
            CONTRACT_MODULE.run_architecture_mapping("flatpak", "aarch64"), "arm64"
        )
        self.assertEqual(
            CONTRACT_MODULE.run_architecture_mapping("snap", "amd64"), "x64"
        )
        self.assertEqual(
            CONTRACT_MODULE.run_architecture_mapping("snap", "arm64"), "arm64"
        )

    def test_duplicate_and_bool_coercion_json_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "duplicate JSON key"
        ):
            CONTRACT_MODULE._strict_json_object(
                b'{"a": 1, "a": 2}\n', "fixture"
            )
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "duplicate JSON key"
        ):
            CONTRACT_MODULE._strict_json_object(
                b'{"outer": {"inner": 1, "inner": 2}}\n', "fixture"
            )
        document = CONTRACT_MODULE._strict_json_object(
            b'{"flag": true, "count": 2}\n', "fixture"
        )
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "exact int JSON type"
        ):
            CONTRACT_MODULE._require_int(document["flag"], "flag")
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "non-exact JSON type"
        ):
            CONTRACT_MODULE._strict_json_object(b'{"n": 1.5}\n', "fixture")

    def test_missing_flutter_archive_bytes_fail_closed(self) -> None:
        receipt = self.repo / ".artifacts/FLUTTER_SDK_RECEIPT.json"
        record = {
            "schema_version": 1,
            "contract": "winsvpn-linux-flutter-sdk-receipt-v1",
            "version": "3.47.6",
            "revision": FLUTTER_REVISION,
            "channel": "stable",
            "dart_version": "3.13.5",
            "archives": {
                "x64": {
                    "archive_path": ".artifacts/flutter/flutter_linux_x64_3.47.6-stable.tar.xz",
                    "bytes": 12,
                    "name": "flutter_linux_x64_3.47.6-stable.tar.xz",
                    "sha256": "a" * 64,
                    "url": FLUTTER_URL_PREFIX
                    + "flutter_linux_x64_3.47.6-stable.tar.xz",
                },
                "arm64": {
                    "archive_path": ".artifacts/flutter/flutter_linux_arm64_3.47.6-stable.tar.xz",
                    "bytes": 13,
                    "name": "flutter_linux_arm64_3.47.6-stable.tar.xz",
                    "sha256": "b" * 64,
                    "url": FLUTTER_URL_PREFIX
                    + "flutter_linux_arm64_3.47.6-stable.tar.xz",
                },
            },
        }
        receipt.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "Flutter x64 SDK archive|externally bound|unauthenticated"
        ):
            CONTRACT_MODULE.load_flutter_sdk_receipt(self.repo, receipt)

    def test_invented_per_arch_store_ids_are_not_canonical(self) -> None:
        invented = (
            "linux-x64-deb",
            "linux-arm64-deb",
            "linux-x64-snap",
            "linux-arm64-snap",
            "linux-x64-flathub",
            "linux-arm64-flathub",
        )
        for target_id in invented:
            with self.subTest(target_id=target_id):
                self.assertNotIn(target_id, CONTRACT_MODULE.NATIVE_PACKAGE_TARGETS)
                package = self.repo / ".artifacts" / f"{target_id}.bin"
                package.write_bytes(b"hsqs" + b"\x00" * 64)
                digest = hashlib.sha256(package.read_bytes()).hexdigest()
                with self.assertRaisesRegex(
                    CONTRACT_MODULE.ManifestContractError, "target binding"
                ):
                    CONTRACT_MODULE.bind_native_package_receipt(
                        repo=self.repo,
                        target_id=target_id,
                        package=package,
                        sha256=digest,
                    )
        self.assertEqual(
            set(CONTRACT_MODULE.NATIVE_PACKAGE_TARGETS),
            {"linux-flathub-manifest", "linux-snap-manifest"},
        )

    def test_mixed_architecture_mapping_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "unsupported"
        ):
            CONTRACT_MODULE.run_architecture_mapping("flatpak", "ppc64")
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "unsupported"
        ):
            CONTRACT_MODULE.run_architecture_mapping("snap", "x86_64")

    def test_canonical_release_matches_identity_ruling(self) -> None:
        identity = CONTRACT_MODULE._strict_json_object(
            (ROOT / IDENTITY).read_bytes(), "release identity"
        )
        canonical = identity["canonical_release"]
        marketing_expected = canonical.split("+")[0]
        debian_expected = canonical.replace("+", "-")
        marketing, debian, release = CONTRACT_MODULE._canonical_linux_versions(self.repo)
        self.assertEqual(marketing, marketing_expected)
        self.assertEqual(debian, debian_expected)
        self.assertEqual(release, canonical)

    def test_owner_blocked_native_package_stays_pending(self) -> None:
        package = self.repo / ".artifacts/org.winsvpn.app.flatpak"
        package.write_bytes(b"hsqs" + b"\x00" * 64)
        digest = hashlib.sha256(package.read_bytes()).hexdigest()
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "owner-blocked"
        ):
            CONTRACT_MODULE.bind_native_package_receipt(
                repo=self.repo,
                target_id="linux-flathub-manifest",
                package=package,
                sha256=digest,
            )

    def test_linux_gate_upload_receipts_cover_deb_snap_and_flathub(self) -> None:
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        import tools.linux_cross_store_artifact_gate as linux_gate

        self.assertEqual(
            set(linux_gate.REQUIRED_LINUX_UPLOAD_TARGETS),
            {
                "linux-x64-package",
                "linux-arm64-package",
                "linux-flathub-manifest",
                "linux-snap-manifest",
            },
        )
        self.assertEqual(
            linux_gate.LINUX_PACKAGE_UPLOAD_TARGETS["linux-x64-package"]["kind"], "DEB"
        )
        self.assertEqual(
            linux_gate.LINUX_PACKAGE_UPLOAD_TARGETS["linux-snap-manifest"]["kind"], "Snap"
        )
        self.assertEqual(
            linux_gate.LINUX_PACKAGE_UPLOAD_TARGETS["linux-flathub-manifest"]["kind"],
            "Flatpak",
        )
        self.assertFalse(linux_gate.LINUX_APPIMAGE_UPLOAD_TARGET)
        self.assertNotIn("linux-x64-appimage", linux_gate.LINUX_PACKAGE_UPLOAD_TARGETS)
        with self.assertRaisesRegex(
            linux_gate.LinuxArtifactGateError, "pending without owner evidence"
        ):
            linux_gate.bind_linux_package_upload_receipts({}, {})

    def test_ambient_flutter_command_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "ambient flutter"
        ):
            CONTRACT_MODULE.validate_shell("set -eu\nflutter pub get --offline\n")

    def test_flutter_bundle_engine_copy_is_rejected(self) -> None:
        dest = CONTRACT_MODULE.engine_install_dest("flatpak")
        complete = (
            "set -eu\n"
            + CONTRACT_MODULE.architecture_case_script("flatpak")
            + CONTRACT_MODULE.host_target_arch_bind_script()
            + 'flutter_sdk="$PWD/flutter-sdk/flutter/bin/flutter"\n'
            + 'test -x "$flutter_sdk"\n'
            + '"$flutter_sdk" pub get --offline\n'
            + 'bundle="build/linux/${flutter_arch}/release/bundle"\n'
            + f'install -Dm0755 "$bundle/wins_vpn" {dest}/wins_vpn\n'
            + f'install -Dm0755 "$bundle/winsvpn-bypass-bpf" {dest}/winsvpn-bypass-bpf\n'
            + CONTRACT_MODULE.engine_stage_script("flatpak")
            + 'install -Dm0644 "$bundle/data/icudtl.dat" dest/icudtl.dat\n'
            + "mkdir -p dest/flutter_assets\n"
            + "install -Dm0755 host/wins_bridge_host dest/wins_bridge_host\n"
            + "install -Dm0644 attestation.json dest/winn3-descriptor-ring-attestation.json\n"
            + "printf store-recipe.sha256 > dest/store-recipe.sha256\n"
            + "printf release-manifest.sha256 > dest/release-manifest.sha256\n"
        )
        CONTRACT_MODULE.validate_recipe_payload(complete)
        poisoned = complete + 'install -Dm0755 "$bundle/winn-datapath" /app/bin/winn-datapath\n'
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError,
            "must not copy engine payloads from the Flutter bundle",
        ):
            CONTRACT_MODULE.validate_recipe_payload(poisoned)


if __name__ == "__main__":
    unittest.main()
