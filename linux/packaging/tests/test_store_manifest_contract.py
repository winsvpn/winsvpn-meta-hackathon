#!/usr/bin/env python3
"""Focused fail-closed tests for Linux store manifest custody."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import lzma
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[3]
CONTRACT = ROOT / "linux/packaging/store_manifest_contract.py"
IDENTITY = pathlib.Path("docs/rulings/RELEASE_IDENTITY_MAP_20260824.json")
METADATA = pathlib.Path("linux/packaging/org.winsvpn.app.metainfo.xml")
SOURCE_URL = "https://downloads.winsvpn.org/source/wins-vpn-1.0.15.tar.gz"
FLUTTER_REVISION = "5fc346839b5d0eef006ed8404392afb4dfae428d"
FLUTTER_URL_PREFIX = (
    "https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/"
)
FLUTTER_ISSUER = "winsvpn-linux-flutter-toolchain-custody"


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


def _load_contract_from(path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(
        "_winsvpn_test_store_manifest_contract_bound", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load bound store manifest contract")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _ustar(members: list[tuple[str, str, bytes | None]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, kind, payload in members:
            info = tarfile.TarInfo(name)
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                info.size = 0
                archive.addfile(info)
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = payload.decode("utf-8") if payload else ""
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


def _write_tar_xz(path: pathlib.Path, members: list[tuple[str, str, bytes | None]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(lzma.compress(_ustar(members), format=lzma.FORMAT_XZ))


class StoreManifestContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name)
        identity = self.repo / IDENTITY
        identity.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / IDENTITY, identity)
        contract_copy = self.repo / "linux/packaging/store_manifest_contract.py"
        contract_copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(CONTRACT, contract_copy)
        metainfo_copy = self.repo / METADATA
        metainfo_copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / METADATA, metainfo_copy)
        producer = self.repo / "linux/packaging/flathub/manifest_artifact.py"
        producer.parent.mkdir(parents=True, exist_ok=True)
        producer.write_text("# producer fixture\n", encoding="utf-8")
        (self.repo / ".artifacts/source").mkdir(parents=True)
        (self.repo / ".artifacts/flutter").mkdir(parents=True)
        (self.repo / ".artifacts/flathub").mkdir(parents=True)
        self.release = json.loads((self.repo / IDENTITY).read_text(encoding="utf-8"))["canonical_release"]
        self.version = self.release.split("+")[0]
        self.source_url = f"https://downloads.winsvpn.org/source/wins-vpn-{self.version}.tar.gz"
        self.source_archive = self.repo / f".artifacts/source/wins-vpn-{self.version}.tar.gz"
        _write_tar_gz(
            self.source_archive,
            [
                (f"wins-vpn-{self.version}", "dir", None),
                (f"wins-vpn-{self.version}/README", "file", b"winsvpn-source\n"),
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
                ("flutter/bin/flutter", "file", b"flutter-linux-x64\n"),
            ],
        )
        _write_tar_xz(
            self.arm64,
            [
                ("flutter", "dir", None),
                ("flutter/bin", "dir", None),
                ("flutter/bin/flutter", "file", b"flutter-linux-arm64\n"),
            ],
        )
        self.source_identity = CONTRACT_MODULE.stream_archive_identity(
            self.repo,
            self.source_archive,
            "fixture source",
            kind="tar.gz",
            expected_root=None,
            allow_symlinks=False,
            max_bytes=CONTRACT_MODULE.MAX_SOURCE_ARCHIVE_BYTES,
        )
        self.x64_identity = CONTRACT_MODULE.stream_archive_identity(
            self.repo,
            self.x64,
            "fixture flutter x64",
            kind="tar.xz",
            expected_root="flutter",
            allow_symlinks=True,
            max_bytes=CONTRACT_MODULE.MAX_FLUTTER_ARCHIVE_BYTES,
        )
        self.arm64_identity = CONTRACT_MODULE.stream_archive_identity(
            self.repo,
            self.arm64,
            "fixture flutter arm64",
            kind="tar.xz",
            expected_root="flutter",
            allow_symlinks=True,
            max_bytes=CONTRACT_MODULE.MAX_FLUTTER_ARCHIVE_BYTES,
        )
        self.module_payload = contract_copy.read_bytes()
        self.freeze_issuance = "a" * 32
        self.flutter_issuance = "b" * 32
        self.toolchain_receipt = self._write_flutter_receipt()
        self._write_freeze()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _now(self) -> str:
        return CONTRACT_MODULE._utc_now()

    def _write_freeze(self, *, sync_trust: bool = True, **overrides: object) -> pathlib.Path:
        module_path = self.repo / "linux/packaging/store_manifest_contract.py"
        record = {
            "schema_version": 1,
            "contract": "winsvpn-linux-store-source-freeze-receipt-v1",
            "created_utc": self._now(),
            "issuance_id": self.freeze_issuance,
            "release": self.release,
            "authenticated": True,
            "issuer": "winsvpn-release-source-freeze",
            "module": {
                "path": "linux/packaging/store_manifest_contract.py",
                "sha256": hashlib.sha256(module_path.read_bytes()).hexdigest(),
                "bytes": module_path.stat().st_size,
            },
            "source": {
                "url": self.source_url,
                "sha256": self.source_identity[0],
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
                "issuance_id": self.flutter_issuance,
                "issuer": FLUTTER_ISSUER,
                "revision": FLUTTER_REVISION,
                "version": "3.47.6",
            },
        }
        trust_path = self.repo / "linux/packaging/STORE_SOURCE_TRUST.json"
        trust_path.parent.mkdir(parents=True, exist_ok=True)
        if trust_path.exists() or trust_path.is_symlink():
            trust_path.unlink()
        trust_path.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return trust_path

    def _archive_record(
        self, path: pathlib.Path, identity: tuple[str, int, str]
    ) -> dict[str, object]:
        return {
            "archive_path": path.relative_to(self.repo).as_posix(),
            "bytes": identity[1],
            "name": path.name,
            "sha256": identity[0],
            "tree_sha256": identity[2],
            "url": FLUTTER_URL_PREFIX + path.name,
        }

    def _write_flutter_receipt(self, **overrides: object) -> pathlib.Path:
        record = {
            "schema_version": 2,
            "contract": "winsvpn-linux-flutter-sdk-receipt-v1",
            "version": "3.47.6",
            "revision": FLUTTER_REVISION,
            "channel": "stable",
            "dart_version": "3.13.5",
            "created_utc": self._now(),
            "issuance_id": self.flutter_issuance,
            "authenticated": True,
            "issuer": FLUTTER_ISSUER,
            "archives": {
                "x64": self._archive_record(self.x64, self.x64_identity),
                "arm64": self._archive_record(self.arm64, self.arm64_identity),
            },
        }
        record.update(overrides)
        path = self.repo / ".artifacts/flutter/FLUTTER_SDK_RECEIPT.json"
        if path.exists() or path.is_symlink():
            path.unlink()
        path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def _produce(self) -> dict[str, object]:
        return CONTRACT_MODULE.produce(
            repo=self.repo,
            target_id="linux-flathub-manifest",
            artifact_format="flathub-json",
            producer_path="linux/packaging/flathub/manifest_artifact.py",
            source_url=self.source_url,
            source_sha256=self.source_identity[0],
            source_archive=self.source_archive,
            toolchain_receipt=self.toolchain_receipt,
            version=self.version,
            output=self.repo / ".artifacts/flathub/org.winsvpn.app.json",
            receipt=self.repo / ".artifacts/flathub/receipt.json",
            render=self._render,
            extract_shell=self._extract,
        )

    def _render(self, source_url: str, source_sha256: str, version: str, flutter) -> bytes:
        script = (
            "set -eu\n"
            + CONTRACT_MODULE.architecture_case_script("flatpak")
            + 'flutter_sdk="$PWD/flutter-sdk/flutter/bin/flutter"\n'
            + 'test -x "$flutter_sdk"\n'
            + '"$flutter_sdk" pub get --offline\n'
        )
        return (
            json.dumps(
                {
                    "id": "org.winsvpn.app",
                    "x-winsvpn-version": version,
                    "source": {"url": source_url, "sha256": source_sha256},
                    "flutter": flutter.version,
                    "commands": [script.rstrip("\n")],
                },
                indent=2,
            )
            + "\n"
        ).encode("utf-8")

    def _extract(self, payload: bytes) -> str:
        document = CONTRACT_MODULE._strict_json_object(payload, "fixture manifest")
        commands = document["commands"]
        return "\n".join(command if command.endswith("\n") else command + "\n" for command in commands)


    def test_produce_and_verify_bind_freeze_and_stay_manifest_only(self) -> None:
        produced = self._produce()
        self.assertIs(produced["manifest_only"], True)
        self.assertIs(produced["package_verified"], False)
        result = CONTRACT_MODULE.verify(
            repo=self.repo,
            target_id="linux-flathub-manifest",
            artifact_format="flathub-json",
            producer_path="linux/packaging/flathub/manifest_artifact.py",
            receipt=self.repo / ".artifacts/flathub/receipt.json",
            artifact=self.repo / ".artifacts/flathub/org.winsvpn.app.json",
            render=self._render,
            extract_shell=self._extract,
        )
        self.assertTrue(result["ok"])
        self.assertIs(result["manifest_only"], True)
        self.assertIs(result["package_verified"], False)
        self.assertNotIn("bound_packages", result)
        self.assertEqual(result["flutter_sdk"]["issuer"], FLUTTER_ISSUER)
        self.assertEqual(result["source"]["tree_sha256"], self.source_identity[2])

    def test_corrupted_metainfo_blocks_produce_and_verify(self) -> None:
        metainfo = self.repo / METADATA
        original = metainfo.read_bytes()
        metainfo.write_text(
            "<component type='desktop-application'></component>", encoding="utf-8"
        )
        try:
            with self.assertRaisesRegex(
                CONTRACT_MODULE.ManifestContractError, "well-formed XML|exactly one|empty"
            ):
                self._produce()
        finally:
            metainfo.write_bytes(original)
        self._produce()
        metainfo.write_text(
            "<component type='desktop-application'></component>", encoding="utf-8"
        )
        try:
            with self.assertRaisesRegex(
                CONTRACT_MODULE.ManifestContractError, "well-formed XML|exactly one|empty"
            ):
                CONTRACT_MODULE.verify(
                    repo=self.repo,
                    target_id="linux-flathub-manifest",
                    artifact_format="flathub-json",
                    producer_path="linux/packaging/flathub/manifest_artifact.py",
                    receipt=self.repo / ".artifacts/flathub/receipt.json",
                    artifact=self.repo / ".artifacts/flathub/org.winsvpn.app.json",
                    render=self._render,
                    extract_shell=self._extract,
                )
        finally:
            metainfo.write_bytes(original)

    def test_malicious_support_module_is_rejected(self) -> None:
        freeze = CONTRACT_MODULE.load_source_freeze_receipt(self.repo)
        evil = self.repo / "linux/packaging/store_manifest_contract.py"
        evil.write_text(
            "CONTRACT_MODULE_IDENTITY = 'winsvpn-linux-store-manifest-contract-module-v1'\n"
            "REVIEWED_FLUTTER_VERSION = '3.47.6'\n"
            "REVIEWED_FLUTTER_REVISION = '5fc346839b5d0eef006ed8404392afb4dfae428d'\n"
            "def produce(**_kwargs):\n"
            "    return {'ok': True, 'manifest_only': False, 'package_verified': True}\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError,
            "support module is not bound|source-freeze receipt",
        ):
            CONTRACT_MODULE.load_source_freeze_receipt(self.repo)
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError,
            "support module is not bound|source-freeze receipt",
        ):
            CONTRACT_MODULE.assert_support_module_bound(
                self.repo, freeze.module_sha256
            )

    def test_attacker_source_self_authentication_cannot_emit_ok(self) -> None:
        attacker = self.repo / ".artifacts/source/attacker.tar.gz"
        _write_tar_gz(
            attacker,
            [
                (f"wins-vpn-{self.version}", "dir", None),
                (f"wins-vpn-{self.version}/README", "file", b"attacker-source\n"),
            ],
        )
        attacker_digest = hashlib.sha256(attacker.read_bytes()).hexdigest()
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError,
            "self-authentication|source-freeze receipt",
        ):
            CONTRACT_MODULE.bind_source_archive(
                self.repo, self.source_url, attacker_digest, attacker
            )
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError,
            "self-authentication|source-freeze receipt",
        ):
            CONTRACT_MODULE.bind_source_archive(
                self.repo, self.source_url, attacker_digest, self.source_archive
            )

    def test_attacker_flutter_self_authentication_cannot_emit_ok(self) -> None:
        caller = self.repo / ".artifacts/flutter/CALLER.json"
        caller.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "contract": "winsvpn-linux-flutter-sdk-receipt-v1",
                    "version": "3.47.6",
                    "revision": FLUTTER_REVISION,
                    "channel": "stable",
                    "dart_version": "3.13.5",
                    "archives": {
                        "x64": {
                            "archive_path": self.x64.relative_to(self.repo).as_posix(),
                            "bytes": self.x64_identity[1],
                            "name": self.x64.name,
                            "sha256": self.x64_identity[0],
                            "url": FLUTTER_URL_PREFIX + self.x64.name,
                        },
                        "arm64": {
                            "archive_path": self.arm64.relative_to(self.repo).as_posix(),
                            "bytes": self.arm64_identity[1],
                            "name": self.arm64.name,
                            "sha256": self.arm64_identity[0],
                            "url": FLUTTER_URL_PREFIX + self.arm64.name,
                        },
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError,
            "unauthenticated|schema fields",
        ):
            CONTRACT_MODULE.load_flutter_sdk_receipt(self.repo, caller)
        fake_issuer = self._write_flutter_receipt(
            issuer="caller-created", authenticated=True
        )
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError,
            "unauthenticated|toolchain custody",
        ):
            CONTRACT_MODULE.load_flutter_sdk_receipt(self.repo, fake_issuer)

    def test_traversal_member_is_rejected(self) -> None:
        traversal = self.repo / ".artifacts/source/traversal.tar.gz"
        _write_tar_gz(traversal, [("../../etc/passwd", "file", b"pwned\n")])
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "traversal"
        ):
            CONTRACT_MODULE.stream_archive_identity(
                self.repo,
                traversal,
                "traversal source",
                kind="tar.gz",
                expected_root=None,
                allow_symlinks=False,
                max_bytes=CONTRACT_MODULE.MAX_SOURCE_ARCHIVE_BYTES,
            )
        doubled = self.repo / ".artifacts/flutter/doubled.tar.xz"
        _write_tar_xz(
            doubled,
            [
                ("flutter", "dir", None),
                ("flutter//bin/flutter", "file", b"bad\n"),
            ],
        )
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError,
            "doubled separators|traversal",
        ):
            CONTRACT_MODULE.stream_archive_identity(
                self.repo,
                doubled,
                "doubled flutter",
                kind="tar.xz",
                expected_root="flutter",
                allow_symlinks=True,
                max_bytes=CONTRACT_MODULE.MAX_FLUTTER_ARCHIVE_BYTES,
            )

    def test_32mib_compressed_bomb_is_rejected(self) -> None:
        bomb = self.repo / ".artifacts/source/bomb.tar.gz"
        zeros = b"\0" * (33 * 1024 * 1024)
        _write_tar_gz(
            bomb,
            [
                ("bomb", "dir", None),
                ("bomb/zero", "file", zeros),
            ],
        )
        self.assertLess(bomb.stat().st_size, 1024 * 1024)
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError,
            r"compressed bomb|32 MiB",
        ):
            CONTRACT_MODULE.stream_archive_identity(
                self.repo,
                bomb,
                "compressed bomb",
                kind="tar.gz",
                expected_root=None,
                allow_symlinks=False,
                max_bytes=CONTRACT_MODULE.MAX_SOURCE_ARCHIVE_BYTES,
            )

    def test_year_2000_receipt_is_rejected(self) -> None:
        self._write_freeze(created_utc="2000-01-01T00:00:00Z")
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "stale"
        ):
            CONTRACT_MODULE.load_source_freeze_receipt(self.repo)
        self._write_freeze()
        self._write_flutter_receipt(created_utc="2000-01-01T00:00:00Z")
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "stale"
        ):
            CONTRACT_MODULE.load_flutter_sdk_receipt(self.repo, self.toolchain_receipt)

    def test_pre_read_size_ceilings_are_enforced(self) -> None:
        oversized = self.repo / f".artifacts/source/wins-vpn-{self.version}.tar.gz"
        with mock.patch.object(CONTRACT_MODULE, "MAX_SOURCE_ARCHIVE_BYTES", 32):
            with self.assertRaisesRegex(
                CONTRACT_MODULE.ManifestContractError,
                "outer size ceiling before reading",
            ):
                CONTRACT_MODULE.stream_archive_identity(
                    self.repo,
                    oversized,
                    "oversized source",
                    kind="tar.gz",
                    expected_root=None,
                    allow_symlinks=False,
                    max_bytes=32,
                )
        huge_json = self.repo / ".artifacts/flutter/huge.json"
        huge_json.write_bytes(b"{" + (b" " * 64) + b"}\n")
        with mock.patch.object(CONTRACT_MODULE, "MAX_JSON_BYTES", 16):
            with self.assertRaisesRegex(
                CONTRACT_MODULE.ManifestContractError,
                "outer size ceiling before reading",
            ):
                CONTRACT_MODULE.bind_repo_file(
                    self.repo,
                    huge_json.relative_to(self.repo).as_posix(),
                    "oversized JSON",
                    max_bytes=16,
                )

    def test_stale_unauthenticated_duplicate_extra_bool_and_wrong_type_flutter_receipts(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "unauthenticated|toolchain custody"
        ):
            CONTRACT_MODULE.load_flutter_sdk_receipt(
                self.repo, self._write_flutter_receipt(authenticated=False)
            )
        extra = json.loads(self._write_flutter_receipt().read_text(encoding="utf-8"))
        extra["extra"] = "field"
        path = self.repo / ".artifacts/flutter/FLUTTER_SDK_RECEIPT.json"
        path.unlink()
        path.write_text(json.dumps(extra) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "schema fields"
        ):
            CONTRACT_MODULE.load_flutter_sdk_receipt(self.repo, path)
        path.unlink()
        path.write_text(
            '{"schema_version": 2, "schema_version": 2, "contract": '
            '"winsvpn-linux-flutter-sdk-receipt-v1"}\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "duplicate JSON key"
        ):
            CONTRACT_MODULE.load_flutter_sdk_receipt(self.repo, path)
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "exact int JSON type|schema fields"
        ):
            CONTRACT_MODULE.load_flutter_sdk_receipt(
                self.repo, self._write_flutter_receipt(schema_version=True)
            )
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "x64 and arm64|schema fields"
        ):
            CONTRACT_MODULE.load_flutter_sdk_receipt(
                self.repo, self._write_flutter_receipt(archives=["x64", "arm64"])
            )

    def test_unicode_and_case_collisions_are_rejected(self) -> None:
        case_collision = self.repo / ".artifacts/flutter/case.tar.xz"
        _write_tar_xz(
            case_collision,
            [
                ("flutter", "dir", None),
                ("flutter/Readme", "file", b"a\n"),
                ("flutter/README", "file", b"b\n"),
            ],
        )
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "case-fold collision"
        ):
            CONTRACT_MODULE.stream_archive_identity(
                self.repo,
                case_collision,
                "case collision",
                kind="tar.xz",
                expected_root="flutter",
                allow_symlinks=True,
                max_bytes=CONTRACT_MODULE.MAX_FLUTTER_ARCHIVE_BYTES,
            )
        unicode_collision = self.repo / ".artifacts/source/unicode.tar.gz"
        nfc = f"wins-vpn-{self.version}/caf\u00e9"
        nfd = f"wins-vpn-{self.version}/cafe\u0301"
        _write_tar_gz(
            unicode_collision,
            [
                (f"wins-vpn-{self.version}", "dir", None),
                (nfc, "file", b"a\n"),
                (nfd, "file", b"b\n"),
            ],
        )
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError,
            "Unicode|canonical|collision|traversal",
        ):
            CONTRACT_MODULE.stream_archive_identity(
                self.repo,
                unicode_collision,
                "unicode collision",
                kind="tar.gz",
                expected_root=None,
                allow_symlinks=False,
                max_bytes=CONTRACT_MODULE.MAX_SOURCE_ARCHIVE_BYTES,
            )

    def test_digest_of_current_bytes_is_not_a_trust_anchor(self) -> None:
        (self.repo / f".artifacts/release-freeze-{self.release}/STORE_SOURCE_RECEIPT.json").unlink()
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError,
            "source-freeze receipt",
        ):
            CONTRACT_MODULE.bind_source_archive(
                self.repo, self.source_url, self.source_identity[0], self.source_archive
            )

    def test_surrogate_gzip_tar_flatpak_and_snap_extensions_fail_closed(self) -> None:
        flatpak = self.repo / ".artifacts/org.winsvpn.app.flatpak"
        _write_tar_gz(flatpak, [("payload", "file", b"not a flatpak\n")])
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

    def test_ambient_flutter_command_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "ambient flutter"
        ):
            CONTRACT_MODULE.validate_shell("set -eu\nflutter pub get --offline\n")

    def test_self_asserted_authenticated_receipt_fails_without_external_trust(self) -> None:
        trust = self.repo / "linux/packaging/STORE_SOURCE_TRUST.json"
        trust.unlink()
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError,
            "externally bound source/toolchain identity is unavailable|self-asserted",
        ):
            CONTRACT_MODULE.load_source_freeze_receipt(self.repo)
        self._write_freeze(sync_trust=False)
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError,
            "externally bound source/toolchain identity is unavailable|self-asserted",
        ):
            CONTRACT_MODULE.produce(
                repo=self.repo,
                target_id="linux-flathub-manifest",
                artifact_format="flathub-json",
                producer_path="linux/packaging/flathub/manifest_artifact.py",
                source_url=self.source_url,
                source_sha256=self.source_identity[0],
                source_archive=self.source_archive,
                toolchain_receipt=self.toolchain_receipt,
                version=self.version,
                output=self.repo / ".artifacts/flathub/org.winsvpn.app.json",
                receipt=self.repo / ".artifacts/flathub/receipt.json",
                render=self._render,
                extract_shell=self._extract,
            )

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
                CONTRACT_MODULE.load_source_freeze_receipt(self.repo)
                box.append("ok")
            except Exception as suc:
                box.append(suc)

        worker = threading.Thread(target=attempt, daemon=True)
        worker.start()
        worker.join(2.0)
        self.assertFalse(worker.is_alive(), "FIFO open hung")
        self.assertEqual(len(box), 1)
        self.assertIsInstance(box[0], CONTRACT_MODULE.ManifestContractError)
        self.assertRegex(
            str(box[0]),
            r"FIFO|special node|regular file|unavailable",
        )

    def test_incomplete_and_comment_only_recipes_are_rejected(self) -> None:
        incomplete = (
            "set -eu\n"
            + CONTRACT_MODULE.architecture_case_script("flatpak")
            + 'flutter_sdk="$PWD/flutter-sdk/flutter/bin/flutter"\n'
            + 'test -x "$flutter_sdk"\n'
            + '"$flutter_sdk" pub get --offline\n'
            + "install -Dm0755 bundle/wins_vpn /app/bin/wins_vpn\n"
        )
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "incomplete"
        ):
            CONTRACT_MODULE.validate_recipe_payload(incomplete)
        comment_only = (
            "set -eu\n"
            "# install wins_vpn winn-datapath awg awg-quick amneziawg-go xray\n"
            "# winsvpn-bypass-bpf icudtl.dat flutter_assets wins_bridge_host\n"
            "# winn3-descriptor-ring-attestation.json store-recipe.sha256 release-manifest.sha256\n"
            + 'flutter_sdk="$PWD/flutter-sdk/flutter/bin/flutter"\n'
            + 'test -x "$flutter_sdk"\n'
            + '"$flutter_sdk" pub get --offline\n'
        )
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "incomplete|comment"
        ):
            CONTRACT_MODULE.validate_recipe_payload(comment_only)

    def _complete_store_recipe(self, kind: str) -> str:
        dest = CONTRACT_MODULE.engine_install_dest(kind)
        return (
            "set -eu\n"
            + CONTRACT_MODULE.architecture_case_script(kind)
            + CONTRACT_MODULE.host_target_arch_bind_script()
            + 'flutter_sdk="$PWD/flutter-sdk/flutter/bin/flutter"\n'
            + 'test -x "$flutter_sdk"\n'
            + '"$flutter_sdk" pub get --offline\n'
            + 'bundle="build/linux/${flutter_arch}/release/bundle"\n'
            + f'install -Dm0755 "$bundle/wins_vpn" {dest}/wins_vpn\n'
            + f'install -Dm0755 "$bundle/winsvpn-bypass-bpf" {dest}/winsvpn-bypass-bpf\n'
            + CONTRACT_MODULE.engine_stage_script(kind)
            + 'install -Dm0644 "$bundle/data/icudtl.dat" dest/icudtl.dat\n'
            + "mkdir -p dest/flutter_assets\n"
            + "install -Dm0755 host/wins_bridge_host dest/wins_bridge_host\n"
            + "install -Dm0644 attestation.json dest/winn3-descriptor-ring-attestation.json\n"
            + "printf store-recipe.sha256 > dest/store-recipe.sha256\n"
            + "printf release-manifest.sha256 > dest/release-manifest.sha256\n"
        )

    def test_explicit_engine_staging_is_architecture_bound_and_sha256_verified(self) -> None:
        for kind in ("flatpak", "snap"):
            script = self._complete_store_recipe(kind)
            CONTRACT_MODULE.validate_shell(script)
            CONTRACT_MODULE.validate_recipe_payload(script)
            live = CONTRACT_MODULE.live_shell_text(script)
            self.assertIn(CONTRACT_MODULE.STAGE_STORE_ENGINES, live)
            self.assertIn(CONTRACT_MODULE.ENGINE_CHECKSUM_COMMAND, live)
            self.assertIn(CONTRACT_MODULE.WINN_DATAPATH_BIND, live)
            self.assertIn(CONTRACT_MODULE.FLUTTER_BUNDLE_ENGINE_REFUSAL, live)
            self.assertIn(CONTRACT_MODULE.HOST_TARGET_CROSS_BUILD_REFUSAL, live)
            self.assertIn(CONTRACT_MODULE.SYMLINK_ENGINE_DEST_REFUSAL, live)
            self.assertIn("WINS_ENGINE_SOURCE_ROOT", live)
            self.assertIn('find "$bundle"', live)
            self.assertIsNone(CONTRACT_MODULE.BUNDLE_ENGINE_COPY.search(live))
            for arch in ("x64", "arm64"):
                for digest in CONTRACT_MODULE.REVIEWED_ENGINE_PAYLOAD_SHA256[arch].values():
                    self.assertIn(digest, live)
            self.assertEqual(
                CONTRACT_MODULE.ENGINE_INSTALL_LINE.findall(live),
                list(CONTRACT_MODULE.ENGINE_INSTALL_ORDER),
            )
            self.assertNotIn('install -Dm0755 "$engine_stage/', live)
            self.assertIsNone(re.search(r"(?m)^[ \t]*curl\b", live))
            self.assertNotIn("git clone", live)

    def test_engine_source_declarations_require_archive_identity_and_reject_git(self) -> None:
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError,
            "owner input required: reviewed (Xray source|Go module cache) archive is absent",
        ):
            CONTRACT_MODULE.engine_source_snap_parts()
        archives = self.repo / "linux/packaging" / CONTRACT_MODULE.ENGINE_ARCHIVE_DIR
        license_bytes = (
            ROOT / "installer/windows/licenses/Xray-core-MPL-2.0.txt"
        ).read_bytes()
        prefix = CONTRACT_MODULE.XRAY_SOURCE_STRIP_PREFIX
        _write_tar_gz(
            archives / CONTRACT_MODULE.XRAY_SOURCE_ARCHIVE_NAME,
            [
                (prefix, "dir", None),
                (f"{prefix}/LICENSE", "file", license_bytes),
                (f"{prefix}/go.mod", "file", b"module github.com/xtls/xray-core\n"),
            ],
        )
        gomod_prefix = CONTRACT_MODULE.STORE_GOMODCACHE_STRIP_PREFIX
        _write_tar_gz(
            archives / CONTRACT_MODULE.STORE_GOMODCACHE_ARCHIVE_NAME,
            [
                (gomod_prefix, "dir", None),
                (f"{gomod_prefix}/README", "file", b"winsvpn-store-gomodcache\n"),
            ],
        )
        bound = _load_contract_from(self.repo / "linux/packaging/store_manifest_contract.py")
        snap = "\n".join(bound.engine_source_snap_parts()) + "\n"
        bound.validate_engine_source_declarations(snap)
        archive_digest = bound.xray_source_archive_sha256()
        tree_digest = bound.xray_source_tree_sha256()
        gomod_digest = bound.store_gomodcache_archive_sha256()
        license_digest = hashlib.sha256(license_bytes).hexdigest()
        gosum_digest = hashlib.sha256(
            (ROOT / "winn_protocol_experimental/go.sum").read_bytes()
        ).hexdigest()
        self.assertIn(archive_digest, snap)
        self.assertIn(tree_digest, snap)
        self.assertIn(gomod_digest, snap)
        self.assertIn(bound.XRAY_IDENTITY_SHA256, snap)
        self.assertNotEqual(archive_digest, license_digest)
        self.assertNotEqual(tree_digest, archive_digest)
        self.assertNotEqual(gomod_digest, gosum_digest)
        self.assertIn(CONTRACT_MODULE.XRAY_SOURCE_URL, snap)
        self.assertNotIn(CONTRACT_MODULE.XRAY_GIT_URL, snap)
        self.assertIn(CONTRACT_MODULE.STORE_GOMODCACHE_URL, snap)
        self.assertIn(CONTRACT_MODULE.REVIEWED_CLANG_VERSION, snap)
        with self.assertRaisesRegex(
            bound.ManifestContractError,
            "SHA-256-authenticated archive, not git",
        ):
            bound.validate_engine_source_declarations(snap + "source-type: git\n")
        with self.assertRaisesRegex(
            bound.ManifestContractError,
            "must not clone Xray at build time",
        ):
            bound.validate_engine_source_declarations(
                snap + bound.XRAY_GIT_URL + "\n"
            )
        identity_tar = archives / CONTRACT_MODULE.XRAY_SOURCE_ARCHIVE_NAME
        _write_tar_gz(
            identity_tar,
            [
                (prefix, "dir", None),
                (f"{prefix}/LICENSE", "file", license_bytes),
                (f"{prefix}/go.mod", "file", b"module github.com/xtls/xray-core\n"),
                (
                    f"{prefix}/{CONTRACT_MODULE.XRAY_IDENTITY_RELATIVE}",
                    "file",
                    CONTRACT_MODULE.XRAY_IDENTITY_TEXT.encode("ascii"),
                ),
            ],
        )
        with self.assertRaisesRegex(
            bound.ManifestContractError,
            r"must not include \.winsvpn-xray-identity",
        ):
            bound.xray_source_tree_sha256()
        _write_tar_gz(
            archives / CONTRACT_MODULE.XRAY_SOURCE_ARCHIVE_NAME,
            [
                (prefix, "dir", None),
                (f"{prefix}/LICENSE", "file", license_bytes),
                (f"{prefix}/go.mod", "file", b"module github.com/xtls/xray-core\n"),
            ],
        )
        flatpak = json.dumps(bound.engine_source_flatpak_sources())
        bound.validate_engine_source_declarations(flatpak)
        self.assertNotIn('"type": "git"', flatpak)
        self.assertIn(archive_digest, flatpak)
        self.assertIn(tree_digest, flatpak)
        self.assertIn(gomod_digest, flatpak)

    def test_swapped_engine_install_order_is_rejected(self) -> None:
        complete = self._complete_store_recipe("flatpak")
        CONTRACT_MODULE.validate_recipe_payload(complete)
        swapped = complete.replace(
            "'winsvpn-engine-publish:winn-datapath'",
            "WINN_PUBLISH_PLACEHOLDER",
        ).replace(
            "'winsvpn-engine-publish:xray'",
            "'winsvpn-engine-publish:winn-datapath'",
        ).replace(
            "WINN_PUBLISH_PLACEHOLDER",
            "'winsvpn-engine-publish:xray'",
        )
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError,
            "must install Winn v3 then AWG then Xray",
        ):
            CONTRACT_MODULE.validate_recipe_payload(swapped)

    def test_engine_stage_install_d_final_hop_is_rejected(self) -> None:
        complete = self._complete_store_recipe("flatpak")
        CONTRACT_MODULE.validate_recipe_payload(complete)
        poisoned = complete + 'install -Dm0755 "$engine_stage/xray" /app/bin/xray-copy\n'
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError,
            "must not publish engines with install -D",
        ):
            CONTRACT_MODULE.validate_recipe_payload(poisoned)

    def test_flutter_bundle_engine_copy_is_rejected_even_when_otherwise_complete(self) -> None:
        complete = self._complete_store_recipe("flatpak")
        CONTRACT_MODULE.validate_recipe_payload(complete)
        poisoned = complete + 'install -Dm0755 "$bundle/awg" /app/bin/awg-leftover\n'
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError,
            "must not copy engine payloads from the Flutter bundle",
        ):
            CONTRACT_MODULE.validate_recipe_payload(poisoned)
        comment_poisoned = complete + '# install -Dm0755 "$bundle/xray" /app/bin/xray\n'
        CONTRACT_MODULE.validate_recipe_payload(comment_poisoned)

    def test_engine_payload_pins_match_producer_and_installer(self) -> None:
        producer = (ROOT / "tools/build_linux_release.sh").read_text(encoding="utf-8")
        installer = (ROOT / "linux/packaging/install.sh").read_text(encoding="utf-8")
        pins = CONTRACT_MODULE.REVIEWED_ENGINE_PAYLOAD_SHA256
        self.assertIn(f'AWG_BINARY_SHA256="{pins["x64"]["awg"]}"', producer)
        self.assertIn(f'AWG_BINARY_SHA256_ARM64="{pins["arm64"]["awg"]}"', producer)
        self.assertIn(f'AWG_QUICK_SHA256="{pins["x64"]["awg-quick"]}"', producer)
        self.assertIn(
            f'AWG_QUICK_SOURCE_SHA256="{CONTRACT_MODULE.AWG_QUICK_SOURCE_SHA256}"',
            producer,
        )
        self.assertEqual(pins["x64"]["awg-quick"], pins["arm64"]["awg-quick"])
        self.assertIn(f'AWG_GO_BINARY_SHA256="{pins["x64"]["amneziawg-go"]}"', producer)
        self.assertIn(
            f'AWG_GO_BINARY_SHA256_ARM64="{pins["arm64"]["amneziawg-go"]}"', producer
        )
        self.assertIn(f'XRAY_SHA256_AMD64="{pins["x64"]["xray"]}"', producer)
        self.assertIn(f'XRAY_SHA256_ARM64="{pins["arm64"]["xray"]}"', producer)
        self.assertIn(f"AWG_SHA256={pins['x64']['awg']}", installer)
        self.assertIn(f"AWG_SHA256={pins['arm64']['awg']}", installer)
        self.assertIn(f"AWG_QUICK_SHA256={pins['x64']['awg-quick']}", installer)
        self.assertIn(f"AWG_GO_SHA256={pins['x64']['amneziawg-go']}", installer)
        self.assertIn(f"AWG_GO_SHA256={pins['arm64']['amneziawg-go']}", installer)
        self.assertIn(f"XRAY_SHA256={pins['x64']['xray']}", installer)
        self.assertIn(f"XRAY_SHA256={pins['arm64']['xray']}", installer)

    def test_stage_store_engines_wrapper_refuses_flutter_bundle_destination(self) -> None:
        wrapper = ROOT / "linux/packaging/stage_store_engines.sh"
        self.assertTrue(wrapper.is_file())
        with tempfile.TemporaryDirectory() as temporary:
            dest = (
                pathlib.Path(temporary)
                / "build"
                / "linux"
                / "x64"
                / "release"
                / "bundle"
            )
            dest.mkdir(parents=True)
            completed = subprocess.run(
                ["bash", str(wrapper), str(dest), "x64"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertEqual(completed.returncode, 65, completed.stderr)
        self.assertIn(
            "refusing to stage store engines into a Flutter linux bundle",
            completed.stderr,
        )
        usage = subprocess.run(
            ["bash", str(wrapper)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(usage.returncode, 64, usage.stderr)

    def test_stage_store_engines_wrapper_refuses_symlink_and_nested_bundle_dest(self) -> None:
        wrapper = ROOT / "linux/packaging/stage_store_engines.sh"
        with tempfile.TemporaryDirectory() as temporary:
            real = pathlib.Path(temporary) / "real-stage"
            real.mkdir()
            link = pathlib.Path(temporary) / "link-stage"
            link.symlink_to(real)
            linked = subprocess.run(
                ["bash", str(wrapper), str(link), "x64"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(linked.returncode, 65, linked.stderr)
            self.assertIn("refusing symlink engine destination", linked.stderr)
            nested = (
                pathlib.Path(temporary)
                / "build"
                / "linux"
                / "x64"
                / "release"
                / "bundle"
                / "nested"
            )
            nested.mkdir(parents=True)
            nested_run = subprocess.run(
                ["bash", str(wrapper), str(nested), "x64"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(nested_run.returncode, 65, nested_run.stderr)
            self.assertIn(
                "refusing to stage store engines into a Flutter linux bundle",
                nested_run.stderr,
            )

    def test_real_metainfo_artifact_passes_validation_with_produced_byte_evidence(
        self,
    ) -> None:
        metainfo_path = ROOT / "linux/packaging/org.winsvpn.app.metainfo.xml"
        payload = metainfo_path.read_bytes()
        result = CONTRACT_MODULE.validate_metainfo(ROOT, self.version)
        self.assertEqual(result["app_id"], "org.winsvpn.app")
        self.assertEqual(result["release_version"], self.version)
        self.assertEqual(result["binary"], "wins_vpn")
        self.assertEqual(result["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(result["bytes"], len(payload))
        self.assertIn("Network", result["categories"])
        self.assertIn("Security", result["categories"])
        self.assertEqual(len(result["oars_attributes"]), 28)

    def test_metainfo_validation_fails_closed_on_mutations(self) -> None:
        path = ROOT / "linux/packaging/org.winsvpn.app.metainfo.xml"
        original = path.read_bytes()
        cases = (
            (
                b"<component type='desktop-application'></component>",
                "exactly one|empty|well-formed XML",
            ),
            (
                original.replace(b"<metadata_license>CC0-1.0</metadata_license>", b""),
                "metadata_license",
            ),
            (
                original.replace(f'version="{self.version}"'.encode("utf-8"), b'version="9.9.9"'),
                "must declare the current version",
            ),
            (
                original.replace(
                    b'<content_attribute id="social-location">none</content_attribute>\n',
                    b"",
                ),
                "missing OARS attributes",
            ),
        )
        for mutation, expected in cases:
            with self.subTest(mutation=expected):
                corrupted = self.repo / METADATA
                corrupted.parent.mkdir(parents=True, exist_ok=True)
                corrupted.write_bytes(mutation)
                with self.assertRaisesRegex(
                    CONTRACT_MODULE.ManifestContractError, expected
                ):
                    CONTRACT_MODULE.validate_metainfo(self.repo, self.version)
                corrupted.unlink()

    def test_exact_count_ratio_and_depth_bounds(self) -> None:
        deep = "/".join(["d"] * 33)
        deep_archive = self.repo / ".artifacts/source/deep.tar.gz"
        _write_tar_gz(deep_archive, [(deep, "file", b"too-deep\n")])
        with self.assertRaisesRegex(
            CONTRACT_MODULE.ManifestContractError, "depth"
        ):
            CONTRACT_MODULE.stream_archive_identity(
                self.repo,
                deep_archive,
                "deep source",
                kind="tar.gz",
                expected_root=None,
                allow_symlinks=False,
                max_bytes=CONTRACT_MODULE.MAX_SOURCE_ARCHIVE_BYTES,
            )
        crowded = self.repo / ".artifacts/source/crowded.tar.gz"
        members = [("crowd", "dir", None)]
        members.extend((f"crowd/f{index}", "file", b"x\n") for index in range(3))
        _write_tar_gz(crowded, members)
        with mock.patch.object(CONTRACT_MODULE, "MAX_MEMBERS", 2):
            with self.assertRaisesRegex(
                CONTRACT_MODULE.ManifestContractError, "member-count"
            ):
                CONTRACT_MODULE.stream_archive_identity(
                    self.repo,
                    crowded,
                    "crowded source",
                    kind="tar.gz",
                    expected_root=None,
                    allow_symlinks=False,
                    max_bytes=CONTRACT_MODULE.MAX_SOURCE_ARCHIVE_BYTES,
                )


if __name__ == "__main__":
    unittest.main()
