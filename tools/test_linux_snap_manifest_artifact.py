#!/usr/bin/env python3
"""Focused tests for the exact, offline Snapcraft manifest artifact."""

from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import importlib.util
import io
import json
import lzma
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import types
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
PRODUCER = pathlib.Path("linux/packaging/snap/manifest_artifact.py")
CONTRACT = pathlib.Path("linux/packaging/store_manifest_contract.py")
IDENTITY = pathlib.Path("docs/rulings/RELEASE_IDENTITY_MAP_20260824.json")
METADATA = pathlib.Path("linux/packaging/org.winsvpn.app.metainfo.xml")
FLUTTER_REVISION = "5fc346839b5d0eef006ed8404392afb4dfae428d"
FLUTTER_URL_PREFIX = (
    "https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/"
)
FLUTTER_ISSUER = "winsvpn-linux-flutter-toolchain-custody"
PAYLOAD_MARKERS = (
    "wins_vpn",
    "winn-datapath",
    "awg",
    "xray",
    "winsvpn-bypass-bpf",
    "icudtl.dat",
    "flutter_assets",
    "wins_bridge_host",
    "winn3-descriptor-ring-attestation.json",
    "store-recipe.sha256",
    "release-manifest.sha256",
)


def _load_module(path: pathlib.Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CONTRACT_HELPER = _load_module(ROOT / CONTRACT, "_winsvpn_tools_snap_contract_helper")


def _ustar(members: list[tuple[str, str, bytes | None]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, kind, payload in members:
            info = tarfile.TarInfo(name)
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                info.size = 0
                archive.addfile(info)
            else:
                data = payload or b""
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _write_tar_gz(path: pathlib.Path, members: list[tuple[str, str, bytes | None]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(gzip.compress(_ustar(members), mtime=0))


def _write_engine_source_archives(repo: pathlib.Path, contract) -> None:
    archives = repo / "linux/packaging" / contract.ENGINE_ARCHIVE_DIR
    archives.mkdir(parents=True, exist_ok=True)
    license_bytes = (
        ROOT / "installer/windows/licenses/Xray-core-MPL-2.0.txt"
    ).read_bytes()
    prefix = contract.XRAY_SOURCE_STRIP_PREFIX
    _write_tar_gz(
        archives / contract.XRAY_SOURCE_ARCHIVE_NAME,
        [
            (prefix, "dir", None),
            (f"{prefix}/LICENSE", "file", license_bytes),
            (f"{prefix}/go.mod", "file", b"module github.com/xtls/xray-core\n"),
        ],
    )
    gomod_prefix = contract.STORE_GOMODCACHE_STRIP_PREFIX
    _write_tar_gz(
        archives / contract.STORE_GOMODCACHE_ARCHIVE_NAME,
        [
            (gomod_prefix, "dir", None),
            (f"{gomod_prefix}/README", "file", b"winsvpn-store-gomodcache\n"),
        ],
    )


def _write_tar_xz(path: pathlib.Path, members: list[tuple[str, str, bytes | None]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(lzma.compress(_ustar(members), format=lzma.FORMAT_XZ))


class SnapManifestArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name)
        for relative in (PRODUCER, CONTRACT, IDENTITY, METADATA):
            destination = self.repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        self.release = json.loads((self.repo / IDENTITY).read_text(encoding="utf-8"))["canonical_release"]
        self.version = self.release.split("+")[0]
        self.source_url = (
            f"https://downloads.winsvpn.org/source/wins-vpn-{self.version}.tar.gz"
        )
        self.metainfo_bytes = (ROOT / METADATA).read_bytes()
        self.assertEqual((self.repo / METADATA).read_bytes(), self.metainfo_bytes)
        self.assertGreater(len(self.metainfo_bytes), 0)
        _write_engine_source_archives(self.repo, CONTRACT_HELPER)
        self.output = self.repo / ".artifacts/snap/snapcraft.yaml"
        self.receipt = self.repo / ".artifacts/snap/receipt.json"
        self.output.parent.mkdir(parents=True)
        self.source_archive = (
            self.repo / f".artifacts/source/wins-vpn-{self.version}.tar.gz"
        )
        _write_tar_gz(
            self.source_archive,
            [
                (f"wins-vpn-{self.version}", "dir", None),
                (
                    f"wins-vpn-{self.version}/README",
                    "file",
                    b"winsvpn-source-snapshot-snap\n",
                ),
            ],
        )
        self.x64 = self.repo / ".artifacts/flutter/flutter_linux_x64_3.47.6-stable.tar.xz"
        self.arm64 = (
            self.repo / ".artifacts/flutter/flutter_linux_arm64_3.47.6-stable.tar.xz"
        )
        _write_tar_xz(
            self.x64,
            [
                ("flutter", "dir", None),
                ("flutter/bin", "dir", None),
                ("flutter/bin/flutter", "file", b"flutter-linux-x64-sdk-snap\n"),
            ],
        )
        _write_tar_xz(
            self.arm64,
            [
                ("flutter", "dir", None),
                ("flutter/bin", "dir", None),
                ("flutter/bin/flutter", "file", b"flutter-linux-arm64-sdk-snap\n"),
            ],
        )
        self.source_identity = CONTRACT_HELPER.stream_archive_identity(
            self.repo,
            self.source_archive,
            "fixture source",
            kind="tar.gz",
            expected_root=None,
            allow_symlinks=False,
            max_bytes=CONTRACT_HELPER.MAX_SOURCE_ARCHIVE_BYTES,
        )
        self.x64_identity = CONTRACT_HELPER.stream_archive_identity(
            self.repo,
            self.x64,
            "fixture flutter x64",
            kind="tar.xz",
            expected_root="flutter",
            allow_symlinks=True,
            max_bytes=CONTRACT_HELPER.MAX_FLUTTER_ARCHIVE_BYTES,
        )
        self.arm64_identity = CONTRACT_HELPER.stream_archive_identity(
            self.repo,
            self.arm64,
            "fixture flutter arm64",
            kind="tar.xz",
            expected_root="flutter",
            allow_symlinks=True,
            max_bytes=CONTRACT_HELPER.MAX_FLUTTER_ARCHIVE_BYTES,
        )
        self.source_sha256 = self.source_identity[0]
        self.toolchain_receipt = self._write_flutter_receipt()
        self._write_freeze()
        self.module = _load_module(self.repo / PRODUCER, "tools_snap_fixture")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_freeze(self, *, sync_trust: bool = True, **overrides: object) -> pathlib.Path:
        module_path = self.repo / CONTRACT
        record = {
            "schema_version": 1,
            "contract": "winsvpn-linux-store-source-freeze-receipt-v1",
            "created_utc": CONTRACT_HELPER._utc_now(),
            "issuance_id": "c" * 32,
            "release": self.release,
            "authenticated": True,
            "issuer": "winsvpn-release-source-freeze",
            "module": {
                "path": CONTRACT.as_posix(),
                "sha256": hashlib.sha256(module_path.read_bytes()).hexdigest(),
                "bytes": module_path.stat().st_size,
            },
            "source": {
                "url": self.source_url,
                "sha256": self.source_sha256,
                "archive_path": self.source_archive.relative_to(self.repo).as_posix(),
                "bytes": self.source_identity[1],
                "tree_sha256": self.source_identity[2],
            },
        }
        record.update(overrides)
        path = (
            self.repo
            / f".artifacts/release-freeze-{self.release}"
            / "STORE_SOURCE_RECEIPT.json"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() or path.is_symlink():
            path.unlink()
        path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if sync_trust:
            self._write_trust(record)
        return path

    def _write_trust(self, freeze: dict[str, object] | None = None) -> pathlib.Path:
        if freeze is None:
            freeze_path = (
                self.repo
                / f".artifacts/release-freeze-{self.release}"
                / "STORE_SOURCE_RECEIPT.json"
            )
            freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
        record = {
            "schema_version": 1,
            "contract": "winsvpn-linux-store-source-toolchain-trust-v1",
            "created_utc": freeze["created_utc"],
            "issuance_id": freeze["issuance_id"],
            "release": freeze["release"],
            "issuer": "winsvpn-release-source-freeze",
            "module": freeze["module"],
            "source": freeze["source"],
            "flutter": {
                "channel": "stable",
                "dart_version": "3.13.5",
                "issuance_id": "d" * 32,
                "issuer": FLUTTER_ISSUER,
                "revision": FLUTTER_REVISION,
                "version": "3.47.6",
            },
        }
        path = self.repo / "linux/packaging/STORE_SOURCE_TRUST.json"
        if path.exists() or path.is_symlink():
            path.unlink()
        path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def _write_flutter_receipt(self, **overrides: object) -> pathlib.Path:
        record = {
            "schema_version": 2,
            "contract": "winsvpn-linux-flutter-sdk-receipt-v1",
            "version": "3.47.6",
            "revision": FLUTTER_REVISION,
            "channel": "stable",
            "dart_version": "3.13.5",
            "created_utc": CONTRACT_HELPER._utc_now(),
            "issuance_id": "d" * 32,
            "authenticated": True,
            "issuer": FLUTTER_ISSUER,
            "archives": {
                "x64": {
                    "archive_path": self.x64.relative_to(self.repo).as_posix(),
                    "bytes": self.x64_identity[1],
                    "name": self.x64.name,
                    "sha256": self.x64_identity[0],
                    "tree_sha256": self.x64_identity[2],
                    "url": FLUTTER_URL_PREFIX + self.x64.name,
                },
                "arm64": {
                    "archive_path": self.arm64.relative_to(self.repo).as_posix(),
                    "bytes": self.arm64_identity[1],
                    "name": self.arm64.name,
                    "sha256": self.arm64_identity[0],
                    "tree_sha256": self.arm64_identity[2],
                    "url": FLUTTER_URL_PREFIX + self.arm64.name,
                },
            },
        }
        record.update(overrides)
        path = self.repo / ".artifacts/flutter/FLUTTER_SDK_RECEIPT.json"
        if path.exists() or path.is_symlink():
            path.unlink()
        path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def _produce(self) -> None:
        self.module.produce_manifest(
            self.repo,
            self.source_url,
            self.source_sha256,
            self.version,
            self.output,
            self.receipt,
            self.source_archive,
            self.toolchain_receipt,
        )

    def _rewrite_receipt(self, mutate) -> None:
        record = json.loads(self.receipt.read_text(encoding="utf-8"))
        mutate(record)
        self.receipt.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        digest = hashlib.sha256(self.receipt.read_bytes()).hexdigest()
        self.receipt.with_name(self.receipt.name + ".sha256").write_text(
            f"{digest}  {self.receipt.name}\n", encoding="ascii"
        )

    def _write_raw_receipt(self, payload: str) -> None:
        self.receipt.write_text(payload, encoding="utf-8")
        digest = hashlib.sha256(self.receipt.read_bytes()).hexdigest()
        self.receipt.with_name(self.receipt.name + ".sha256").write_text(
            f"{digest}  {self.receipt.name}\n", encoding="ascii"
        )

    def test_produce_and_verify_are_exact_offline_and_manifest_only(self) -> None:
        self._produce()
        with mock.patch.object(socket, "socket", side_effect=AssertionError("network")):
            result = self.module.verify_receipt(self.repo, self.receipt, self.output)
        manifest = self.output.read_text(encoding="utf-8")
        self.assertTrue(result["ok"])
        self.assertTrue(result["manifest_only"])
        self.assertFalse(result["package_verified"])
        self.assertNotIn("bound_packages", result)
        self.assertFalse(result["verification_network_accessed"])
        self.assertIn("base: core26\n", manifest)
        self.assertIn("confinement: classic\n", manifest)
        self.assertIn("does not claim Snap Store approval", manifest)
        self.assertIn(f"source-checksum: sha256/{self.source_sha256}\n", manifest)
        self.assertIn('"$flutter_sdk" pub get --offline', manifest)
        self.assertNotRegex(manifest, r"(?m)^[ \t]*flutter(?:\s|$)")
        for marker in PAYLOAD_MARKERS:
            self.assertIn(marker, manifest)
        self.assertEqual(
            self.module.contract.ENGINE_INSTALL_LINE.findall(manifest),
            list(self.module.contract.ENGINE_INSTALL_ORDER),
        )
        self.assertIn("not an implicit fallback", manifest)
        self.assertIn("trusted served configuration", manifest)
        self.assertIn("linux/packaging/stage_store_engines.sh", manifest)
        self.assertIn(self.module.contract.ENGINE_CHECKSUM_COMMAND, manifest)
        self.assertIn("refusing Flutter-bundle engine leftover", manifest)
        self.assertIn(self.module.contract.CLASSIC_SNAP_UNBOUNDED, manifest)
        self.assertIn(self.module.contract.CLASSIC_SNAP_REVIEW, manifest)
        self.assertNotIn("plugs are not granted", manifest)
        self.assertNotIn("sha256sum --strict --check", manifest)
        self.assertNotRegex(
            manifest, r"\$bundle/(?:winn-datapath|awg-quick|amneziawg-go|awg|xray)\b"
        )
        self.assertNotIn("\n    plugs:", manifest)
        self.assertNotIn("--device=all", manifest)
        self.assertNotIn("      - curl\n", manifest)
        self.assertNotIn("      - git\n", manifest)
        self.assertIn(self.module.contract.REVIEWED_GO_ARCHIVE_URL["x64"], manifest)
        self.assertIn(self.module.contract.XRAY_COMMIT, manifest)
        self.assertNotIn(self.module.contract.XRAY_GIT_URL, manifest)
        self.assertIn(self.module.contract.XRAY_SOURCE_URL, manifest)
        self.assertIn(self.module.contract.STORE_GOMODCACHE_URL, manifest)
        self.assertIn(self.module.contract.WINN_DATAPATH_BIND, manifest)
        self.assertIn(self.module.contract.REVIEWED_CLANG_VERSION, manifest)
        self.assertIn("source-type: file", manifest)
        self.assertIn("WINS_ENGINE_SOURCE_ROOT", manifest)
        self.assertIn(self.module.contract.HOST_TARGET_CROSS_BUILD_REFUSAL, manifest)
        contract = self.module.contract
        xray_archive = contract.xray_source_archive_sha256()
        xray_tree = contract.xray_source_tree_sha256()
        gomod_archive = contract.store_gomodcache_archive_sha256()
        license_digest = hashlib.sha256(
            (ROOT / "installer/windows/licenses/Xray-core-MPL-2.0.txt").read_bytes()
        ).hexdigest()
        self.assertIn(xray_archive, manifest)
        self.assertIn(xray_tree, manifest)
        self.assertIn(gomod_archive, manifest)
        self.assertIn(contract.XRAY_IDENTITY_SHA256, manifest)
        self.assertNotEqual(xray_archive, license_digest)
        self.assertNotEqual(xray_tree, xray_archive)
        self.assertNotIn('install -Dm0755 "$engine_stage/', manifest)
        for arch in ("x64", "arm64"):
            for digest in self.module.contract.REVIEWED_ENGINE_PAYLOAD_SHA256[arch].values():
                self.assertIn(digest, manifest)

    def test_fixture_metainfo_is_exact_canonical_bytes(self) -> None:
        fixture = self.repo / METADATA
        canonical = ROOT / METADATA
        self.assertEqual(fixture.read_bytes(), self.metainfo_bytes)
        self.assertEqual(self.metainfo_bytes, canonical.read_bytes())
        self.assertIn(b'id>org.winsvpn.app</id>', self.metainfo_bytes)
        self.assertIn(f'version="{self.version}"'.encode("ascii"), self.metainfo_bytes)
        self.assertEqual(
            fixture.relative_to(self.repo).as_posix(),
            METADATA.as_posix(),
        )

    def test_missing_and_drifted_metainfo_fail_closed(self) -> None:
        metainfo = self.repo / METADATA
        metainfo.unlink()
        with self.assertRaisesRegex(
            self.module.contract.ManifestContractError,
            r"AppStream metainfo does not exist",
        ):
            self._produce()
        self.assertFalse(self.output.exists())
        drifted = self.metainfo_bytes.replace(
            f'version="{self.version}"'.encode("ascii"), b'version="9.9.9"', 1
        )
        self.assertNotEqual(drifted, self.metainfo_bytes)
        metainfo.write_bytes(drifted)
        with self.assertRaisesRegex(
            self.module.contract.ManifestContractError,
            "must declare the current version",
        ):
            self._produce()
        self.assertFalse(self.output.exists())
        metainfo.write_bytes(self.metainfo_bytes)
        self._produce()
        self.assertTrue(self.output.exists())

    def test_generated_shell_passes_bash_n_and_maps_x64_and_arm64(self) -> None:
        self._produce()
        script = self.module.extract_shell(self.output.read_bytes())
        self.module.contract.validate_shell(script)
        self.assertEqual(
            self.module.contract.run_architecture_mapping("snap", "amd64"), "x64"
        )
        self.assertEqual(
            self.module.contract.run_architecture_mapping("snap", "arm64"), "arm64"
        )
        with self.assertRaisesRegex(
            self.module.contract.ManifestContractError, "unsupported"
        ):
            self.module.contract.run_architecture_mapping("snap", "i386")

    def test_invalid_shell_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            self.module.contract.ManifestContractError, "shell syntax"
        ):
            self.module.contract.validate_shell(
                "echo 'unterminated\n", require_pinned_flutter=False
            )

    def test_missing_stale_and_wrong_target_receipts_fail_closed(self) -> None:
        with self.assertRaises(self.module.contract.ManifestContractError):
            self.module.verify_receipt(self.repo, self.receipt, self.output)
        self._produce()
        stale = (
            (dt.datetime.now(tz=dt.timezone.utc) - dt.timedelta(hours=73))
            .isoformat()
            .replace("+00:00", "Z")
        )
        self._rewrite_receipt(lambda record: record.__setitem__("created_utc", stale))
        with self.assertRaisesRegex(
            self.module.contract.ManifestContractError, "stale"
        ):
            self.module.verify_receipt(self.repo, self.receipt, self.output)
        self._rewrite_receipt(
            lambda record: (
                record.__setitem__(
                    "created_utc",
                    dt.datetime.now(tz=dt.timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z"),
                ),
                record.__setitem__("target_id", "linux-flathub-manifest"),
            )
        )
        with self.assertRaisesRegex(
            self.module.contract.ManifestContractError, "binding"
        ):
            self.module.verify_receipt(self.repo, self.receipt, self.output)

    def test_stale_release_version_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            self.module.contract.ManifestContractError, f"canonical {self.version}"
        ):
            self.module.produce_manifest(
                self.repo,
                "https://downloads.winsvpn.org/source/wins-vpn-9.9.9.tar.gz",
                self.source_sha256,
                "9.9.9",
                self.output,
                self.receipt,
                self.source_archive,
                self.toolchain_receipt,
            )
        self.assertFalse(self.output.exists())
        self._produce()
        self._rewrite_receipt(lambda record: record.__setitem__("version", "9.9.9"))
        with self.assertRaisesRegex(
            self.module.contract.ManifestContractError, f"canonical {self.version}"
        ):
            self.module.verify_receipt(self.repo, self.receipt, self.output)

    def test_duplicate_top_level_json_keys_fail_closed(self) -> None:
        self._produce()
        text = self.receipt.read_text(encoding="utf-8")
        text = text.replace(
            f'"version": "{self.version}"',
            f'"version": "9.9.9",\n  "version": "{self.version}"',
            1,
        )
        self._write_raw_receipt(text)
        with self.assertRaisesRegex(
            self.module.contract.ManifestContractError, "duplicate JSON key"
        ):
            self.module.verify_receipt(self.repo, self.receipt, self.output)

    def test_bool_coercion_fails_closed(self) -> None:
        self._produce()
        self._rewrite_receipt(
            lambda record: record["artifact"].__setitem__("bytes", True)
        )
        with self.assertRaisesRegex(
            self.module.contract.ManifestContractError, "exact int JSON type"
        ):
            self.module.verify_receipt(self.repo, self.receipt, self.output)

    def test_attacker_url_and_hash_cannot_emit_ok(self) -> None:
        with self.assertRaisesRegex(
            self.module.contract.ManifestContractError, "reviewed HTTPS origin|Source URL"
        ):
            self.module.produce_manifest(
                self.repo,
                f"https://attacker.test/wins-vpn-{self.version}.tar.gz",
                self.source_sha256,
                self.version,
                self.output,
                self.receipt,
                self.source_archive,
                self.toolchain_receipt,
            )
        with self.assertRaisesRegex(
            self.module.contract.ManifestContractError,
            "self-authentication|source-freeze receipt",
        ):
            self.module.produce_manifest(
                self.repo,
                self.source_url,
                "b" * 64,
                self.version,
                self.output,
                self.receipt,
                self.source_archive,
                self.toolchain_receipt,
            )

    def test_missing_source_bytes_fail_closed(self) -> None:
        missing = self.repo / ".artifacts/source/missing.tar.gz"
        with self.assertRaisesRegex(
            self.module.contract.ManifestContractError, "source archive snapshot"
        ):
            self.module.produce_manifest(
                self.repo,
                self.source_url,
                self.source_sha256,
                self.version,
                self.output,
                self.receipt,
                missing,
                self.toolchain_receipt,
            )

    def test_self_asserted_authenticated_receipt_fails_without_external_trust(self) -> None:
        (self.repo / "linux/packaging/STORE_SOURCE_TRUST.json").unlink()
        with self.assertRaisesRegex(
            self.module.contract.ManifestContractError,
            "externally bound source/toolchain identity is unavailable|self-asserted",
        ):
            self._produce()

    def test_missing_source_freeze_receipt_fails_closed(self) -> None:
        freeze = (
            self.repo
            / f".artifacts/release-freeze-{self.release}"
            / "STORE_SOURCE_RECEIPT.json"
        )
        freeze.unlink()
        with self.assertRaisesRegex(RuntimeError, "source-freeze receipt is required"):
            _load_module(self.repo / PRODUCER, "tools_snap_missing_freeze")

    def test_ambient_flutter_is_not_invoked(self) -> None:
        fake_bin = self.repo / "fake-bin"
        fake_bin.mkdir()
        marker = self.repo / "ambient-flutter-ran"
        flutter = fake_bin / "flutter"
        flutter.write_text(f"#!/bin/sh\nprintf ran > {marker}\n", encoding="utf-8")
        flutter.chmod(0o755)
        with mock.patch.dict(
            os.environ, {"PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", "")}
        ):
            self._produce()
            result = self.module.verify_receipt(self.repo, self.receipt, self.output)
        self.assertFalse(marker.exists())
        self.assertEqual(result["flutter_sdk"]["version"], "3.47.6")
        self.assertIs(result["manifest_only"], True)

    def test_manifest_only_truth_cannot_claim_packages(self) -> None:
        self._produce()
        self._rewrite_receipt(
            lambda record: record.__setitem__("package_verified", True)
        )
        with self.assertRaisesRegex(
            self.module.contract.ManifestContractError, "binding|package"
        ):
            self.module.verify_receipt(self.repo, self.receipt, self.output)
        for leftover in self.output.parent.iterdir():
            leftover.unlink()
        canonical_receipt = self.output.with_name(self.output.name + ".receipt.json")
        self.module.produce_manifest(
            self.repo,
            self.source_url,
            self.source_sha256,
            self.version,
            self.output,
            canonical_receipt,
            self.source_archive,
            self.toolchain_receipt,
        )
        verified = self.module.canonical_gate_verify(
            "linux-snap-manifest",
            self.output.relative_to(self.repo).as_posix(),
        )
        self.assertIs(verified["manifest_only"], True)
        self.assertIs(verified["package_verified"], False)
        self.assertNotIn("bound_packages", verified)

    def test_pythonpath_and_sys_modules_cannot_substitute_contract(self) -> None:
        fake = types.ModuleType("store_manifest_contract")
        fake.CONTRACT_MODULE_IDENTITY = "attacker"

        def boom(**_kwargs):
            return {"ok": True, "manifest_only": False, "package_verified": True}

        fake.produce = boom
        fake.verify = boom
        sys.modules["store_manifest_contract"] = fake
        try:
            module = _load_module(self.repo / PRODUCER, "tools_snap_poisoned")
            self.assertEqual(
                module.contract.CONTRACT_MODULE_IDENTITY,
                "winsvpn-linux-store-manifest-contract-module-v1",
            )
            self.assertIsNot(module.contract, fake)
        finally:
            if sys.modules.get("store_manifest_contract") is fake:
                del sys.modules["store_manifest_contract"]

    def test_attacker_private_module_is_rejected(self) -> None:
        fake = types.ModuleType("_winsvpn_store_manifest_contract_attacker")
        fake.CONTRACT_MODULE_IDENTITY = "winsvpn-linux-store-manifest-contract-module-v1"
        fake.produce = lambda **_kwargs: {
            "ok": True,
            "manifest_only": False,
            "package_verified": True,
        }
        digest = hashlib.sha256((self.repo / CONTRACT).read_bytes()).hexdigest()
        origin = os.path.abspath(self.repo / CONTRACT)
        origin_key = hashlib.sha256(origin.encode("utf-8")).hexdigest()
        predicted = f"_winsvpn_store_manifest_contract_{digest}_{origin_key}"
        sys.modules[predicted] = fake
        sys.modules["_winsvpn_store_manifest_contract_attacker"] = fake
        try:
            with self.assertRaisesRegex(
                RuntimeError, "private contract identity|malicious or substituted"
            ):
                _load_module(self.repo / PRODUCER, "tools_snap_private_attacker")
        finally:
            if sys.modules.get(predicted) is fake:
                del sys.modules[predicted]
            if sys.modules.get("_winsvpn_store_manifest_contract_attacker") is fake:
                del sys.modules["_winsvpn_store_manifest_contract_attacker"]

    def test_sitecustomize_pythonpath_does_not_run(self) -> None:
        injection = self.repo / "injection-isolated"
        injection.mkdir()
        marker = self.repo / "sitecustomize-isolated-ran"
        (injection / "sitecustomize.py").write_text(
            f"open({str(marker)!r}, 'w', encoding='utf-8').write('ran')\n",
            encoding="utf-8",
        )
        (injection / "store_manifest_contract.py").write_text(
            "raise SystemExit('pwned')\n", encoding="utf-8"
        )
        env = {
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "LANG": "C",
            "PYTHONPATH": str(injection),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                str(self.repo / PRODUCER),
                "produce",
                "--repo",
                str(self.repo),
                "--source-url",
                self.source_url,
                "--source-sha256",
                self.source_sha256,
                "--source-archive",
                str(self.source_archive),
                "--toolchain-receipt",
                str(self.toolchain_receipt),
                "--version",
                self.version,
                "--output",
                str(self.output),
                "--receipt",
                str(self.receipt),
            ],
            cwd=str(self.repo),
            env=env,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertNotIn(b"pwned", completed.stderr)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace"))
        self.assertFalse(marker.exists())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO creation is unavailable")
    def test_fifo_is_rejected_before_open(self) -> None:
        freeze = (
            self.repo
            / f".artifacts/release-freeze-{self.release}"
            / "STORE_SOURCE_RECEIPT.json"
        )
        freeze.unlink()
        os.mkfifo(freeze)
        box: list[object] = []

        def attempt() -> None:
            try:
                _load_module(self.repo / PRODUCER, "tools_snap_fifo")
                box.append("ok")
            except Exception as suc:
                box.append(suc)

        worker = threading.Thread(target=attempt, daemon=True)
        worker.start()
        worker.join(2.0)
        self.assertFalse(worker.is_alive(), "FIFO open hung")
        self.assertEqual(len(box), 1)
        self.assertIsInstance(box[0], RuntimeError)
        self.assertRegex(str(box[0]), r"FIFO|special node|regular file|unavailable")

    def test_33mib_archive_is_rejected_before_allocation(self) -> None:
        zeros = b"\0" * (33 * 1024 * 1024)
        _write_tar_gz(
            self.source_archive,
            [("bomb", "dir", None), ("bomb/zero", "file", zeros)],
        )
        digest = hashlib.sha256(self.source_archive.read_bytes()).hexdigest()
        self._write_freeze(
            source={
                "url": self.source_url,
                "sha256": digest,
                "archive_path": self.source_archive.relative_to(self.repo).as_posix(),
                "bytes": self.source_archive.stat().st_size,
                "tree_sha256": "f" * 64,
            }
        )
        with self.assertRaisesRegex(
            self.module.contract.ManifestContractError,
            r"compressed bomb|32 MiB",
        ):
            self.module.produce_manifest(
                self.repo,
                self.source_url,
                digest,
                self.version,
                self.output,
                self.receipt,
                self.source_archive,
                self.toolchain_receipt,
            )

    def test_incomplete_and_comment_only_payload_are_rejected(self) -> None:
        incomplete = (
            "set -eu\n"
            + self.module.contract.architecture_case_script("snap")
            + 'flutter_sdk="$CRAFT_STAGE/flutter/bin/flutter"\n'
            + 'test -x "$flutter_sdk"\n'
            + '"$flutter_sdk" pub get --offline\n'
            + "install -Dm0755 bundle/wins_vpn $CRAFT_PART_INSTALL/bin/wins_vpn\n"
        )
        with self.assertRaisesRegex(
            self.module.contract.ManifestContractError, "incomplete"
        ):
            self.module.contract.validate_recipe_payload(incomplete)
        comment_only = (
            "set -eu\n"
            "# wins_vpn winn-datapath awg xray winsvpn-bypass-bpf\n"
            "# icudtl.dat flutter_assets wins_bridge_host\n"
            "# winn3-descriptor-ring-attestation.json\n"
            "# store-recipe.sha256 release-manifest.sha256\n"
            'flutter_sdk="$CRAFT_STAGE/flutter/bin/flutter"\n'
            'test -x "$flutter_sdk"\n'
        )
        with self.assertRaisesRegex(
            self.module.contract.ManifestContractError, "incomplete"
        ):
            self.module.contract.validate_recipe_payload(comment_only)

    def test_flutter_bundle_engine_copy_is_rejected_even_when_otherwise_complete(self) -> None:
        complete = self.module._build_script()
        self.module.contract.validate_recipe_payload(complete)
        poisoned = complete + 'install -Dm0755 "$bundle/awg" "$CRAFT_PART_INSTALL/bin/awg"\n'
        with self.assertRaisesRegex(
            self.module.contract.ManifestContractError,
            "must not copy engine payloads from the Flutter bundle",
        ):
            self.module.contract.validate_recipe_payload(poisoned)

    def test_missing_reviewed_engine_archives_fail_closed_owner_input(self) -> None:
        shutil.rmtree(self.repo / "linux/packaging" / CONTRACT_HELPER.ENGINE_ARCHIVE_DIR)
        with self.assertRaisesRegex(
            self.module.contract.ManifestContractError,
            "owner input required: reviewed Xray source archive is absent",
        ):
            self._produce()

    @unittest.skipUnless(hasattr(os, "link"), "hard links unavailable")
    def test_hard_linked_and_external_artifacts_fail_closed(self) -> None:
        self._produce()
        linked = self.output.with_suffix(".linked.yaml")
        os.link(self.output, linked)
        with self.assertRaisesRegex(
            self.module.contract.ManifestContractError, "hard link"
        ):
            self.module.verify_receipt(self.repo, self.receipt, self.output)
        outside = self.repo.parent / "outside-snap.yaml"
        outside.write_text("name: outside\n", encoding="utf-8")
        try:
            with self.assertRaisesRegex(
                self.module.contract.ManifestContractError, "inside"
            ):
                self.module.verify_receipt(self.repo, self.receipt, outside)
        finally:
            outside.unlink(missing_ok=True)

    def test_linux_upload_receipt_for_snap_stays_pending_without_owner_evidence(self) -> None:
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        import tools.linux_cross_store_artifact_gate as linux_gate

        self.assertEqual(
            linux_gate.LINUX_PACKAGE_UPLOAD_TARGETS["linux-snap-manifest"]["kind"], "Snap"
        )
        self.assertEqual(
            linux_gate.LINUX_PACKAGE_UPLOAD_TARGETS["linux-snap-manifest"]["architectures"],
            ("x64", "arm64"),
        )
        with self.assertRaisesRegex(
            linux_gate.LinuxArtifactGateError, "pending without owner evidence"
        ):
            linux_gate.bind_linux_package_upload_receipts({}, {})
        with self.assertRaisesRegex(
            linux_gate.LinuxArtifactGateError, "unsupported exact Linux package/upload target"
        ):
            linux_gate.bind_package_upload_receipt(
                "linux-x64-snap",
                {},
                artifact_sha256="a" * 64,
                artifact_bytes=8,
            )


if __name__ == "__main__":
    unittest.main()
