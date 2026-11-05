#!/usr/bin/env python3
"""Focused OpenSSL source-to-binary custody tests for official 4.0.2."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "release_openssl_archive_custody.py"
SHELL = ROOT / "tools" / "release_openssl_archive_custody.sh"
PIN_MANIFEST = ROOT / "tools" / "toolchain-pins.json"
OFFICIAL_SOURCE_SHA256 = "736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8"
PRESERVED_OPENSSL_401_SHA256 = (
    "2db3f3a0d6ea4b59e1f094ace2c8cd536dffb87cdc39084c5afa1e6f7f37dd09"
)
OTHER_SHA256 = "1" * 64

SPEC = importlib.util.spec_from_file_location("release_openssl_archive_custody", TOOL)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load OpenSSL custody module")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def write_bytes(path: Path, data: bytes, mode: int = 0o444) -> Path:
    path.write_bytes(data)
    path.chmod(mode)
    return path


def official_pin(**hash_overrides: str) -> dict[str, object]:
    archive_sha = hash_overrides.get(
        "archive_sha", MODULE.OFFICIAL_ARCHIVE_SHA256 or ("aa" * 32)
    )
    tree_sha = hash_overrides.get(
        "tree_sha", MODULE.OFFICIAL_TREE_SHA256 or ("bb" * 32)
    )
    executable_sha = hash_overrides.get(
        "executable_sha", MODULE.OFFICIAL_EXECUTABLE_SHA256 or ("cc" * 32)
    )
    pin: dict[str, object] = {
        "version": MODULE.OFFICIAL_VERSION,
        "platform": MODULE.OFFICIAL_PLATFORM,
        "source_archive": "/Users/owner/Downloads/openssl-4.0.2.tar.gz",
        "source_name": MODULE.OFFICIAL_SOURCE_NAME,
        "source_sha": MODULE.OFFICIAL_SOURCE_SHA256,
        "archive": "/Users/owner/Downloads/wins-openssl-4.0.2-darwin-arm64.zip",
        "archive_sha": archive_sha,
        "tree_sha": tree_sha,
        "executable_sha": executable_sha,
        "root": MODULE.OFFICIAL_ROOT,
        "executable": MODULE.OFFICIAL_EXECUTABLE,
        "build_configuration": MODULE.OFFICIAL_CONFIGURATION,
        "compiler_identity": dict(MODULE.FROZEN_COMPILER_IDENTITY),
        "build_receipt_env": MODULE.RECEIPT_ENV,
    }
    pin["build_transaction"] = MODULE.canonical_build_transaction(pin)
    return pin


class ReleaseOpensslArchiveCustodyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pin = official_pin()
        cls.controller_data, cls.controller_sha = MODULE.snapshot_controller()
        cls.base = Path(tempfile.mkdtemp(prefix="wins-openssl-custody-test.", dir="/private/tmp"))
        cls.base.chmod(0o700)
        cls.live_manifest = json.loads(PIN_MANIFEST.read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls) -> None:
        for path in cls.base.rglob("*"):
            if not path.is_symlink():
                try:
                    path.chmod(path.stat().st_mode | stat.S_IWUSR | stat.S_IXUSR)
                except FileNotFoundError:
                    pass
        shutil.rmtree(cls.base, ignore_errors=True)

    def setUp(self) -> None:
        self.case = Path(tempfile.mkdtemp(prefix="case.", dir=str(self.base)))
        self.case.chmod(0o700)
        os.environ.pop(MODULE.RECEIPT_ENV, None)

    def tearDown(self) -> None:
        os.environ.pop(MODULE.RECEIPT_ENV, None)

    def matching_receipt_document(self, **overrides: object) -> dict[str, object]:
        compiler = dict(MODULE.FROZEN_COMPILER_IDENTITY)
        document: dict[str, object] = {
            "contract": MODULE.RECEIPT_CONTRACT,
            "schema_version": 1,
            "authenticated": True,
            "issuer": MODULE.RECEIPT_ISSUER,
            "version": MODULE.OFFICIAL_VERSION,
            "source_archive_name": MODULE.OFFICIAL_SOURCE_NAME,
            "source_archive_sha256": MODULE.OFFICIAL_SOURCE_SHA256,
            "build_configuration": MODULE.OFFICIAL_CONFIGURATION,
            "compiler_identity": compiler,
            "build_transaction": self.pin["build_transaction"],
            "archive_sha256": self.pin["archive_sha"],
            "install_tree_sha256": self.pin["tree_sha"],
            "executable_sha256": self.pin["executable_sha"],
            "controller": MODULE.CONTROLLER_RELATIVE,
            "controller_sha256": self.controller_sha,
        }
        document.update(overrides)
        return document

    def receipt_bytes(self, **overrides: object) -> bytes:
        return json.dumps(self.matching_receipt_document(**overrides)).encode("ascii")

    def parse_receipt(self, **overrides: object) -> dict[str, object]:
        return MODULE.parse_build_receipt(self.receipt_bytes(**overrides))

    def test_official_402_identity_and_adopted_live_pins(self) -> None:
        self.assertEqual(MODULE.OFFICIAL_VERSION, "4.0.2")
        self.assertEqual(MODULE.OFFICIAL_SOURCE_NAME, "openssl-4.0.2.tar.gz")
        self.assertEqual(MODULE.OFFICIAL_SOURCE_SHA256, OFFICIAL_SOURCE_SHA256)
        self.assertEqual(MODULE.OFFICIAL_ARCHIVE_NAME, "wins-openssl-4.0.2-darwin-arm64.zip")
        self.assertEqual(MODULE.OFFICIAL_RELEASE_DATE, "25 Aug 2026")
        self.assertEqual(MODULE.OFFICIAL_CONFIGURATION, "darwin64-arm64-cc no-shared no-tests no-docs")
        self.assertEqual(self.pin["compiler_identity"], MODULE.FROZEN_COMPILER_IDENTITY)
        self.assertEqual(self.pin["build_transaction"], MODULE.canonical_build_transaction(self.pin))
        if MODULE.OFFICIAL_BUILD_TRANSACTION:
            self.assertEqual(self.pin["build_transaction"], MODULE.OFFICIAL_BUILD_TRANSACTION)
        live = self.live_manifest["tools"]["openssl"]
        self.assertEqual(live["version"], "4.0.2")
        self.assertEqual(live["source_archive_name"], MODULE.OFFICIAL_SOURCE_NAME)
        self.assertEqual(live["source_archive_sha256"], OFFICIAL_SOURCE_SHA256)
        self.assertEqual(MODULE.load_pin(PIN_MANIFEST), self.pin)
        discovered = live["discovered_latest_stable"]
        self.assertEqual(discovered["version"], "4.0.2")
        self.assertIs(discovered["adopted"], True)
        self.assertEqual(discovered["source_archive_sha256"], OFFICIAL_SOURCE_SHA256)
        self.assertEqual(discovered["retrieved_utc"], "2026-08-25T16:09:55Z")
        self.assertIn("owner-blocked", str(discovered["blocker"]).lower())
        source = TOOL.read_text(encoding="ascii")
        wrapper = SHELL.read_text(encoding="ascii")
        self.assertNotRegex(source, r"urllib|urlopen|requests|http\.client|socket\.create_connection")
        self.assertNotRegex(wrapper, r"curl|wget|http://|https://")
        self.assertIn("never performs", source)
        self.assertIn("network execution", source)
        self.assertIn("never self-authorizes a build receipt", source)
        self.assertIn("OpenSSL 4.0.2", source)
        self.assertIn("owner-blocked", source)

    def test_stale_or_substituted_live_pin_is_rejected(self) -> None:
        stale = json.loads(json.dumps(self.live_manifest))
        stale_pin = stale["tools"]["openssl"]
        stale_pin["version"] = "4.0.1"
        stale_pin["source_archive_name"] = "openssl-4.0.1.tar.gz"
        stale_pin["source_archive_sha256"] = PRESERVED_OPENSSL_401_SHA256
        stale_path = write_bytes(
            self.case / "stale-toolchain-pins.json",
            json.dumps(stale, sort_keys=True).encode("ascii"),
        )
        with self.assertRaisesRegex(MODULE.Refused, r"release identity pin mismatch"):
            MODULE.load_pin(stale_path)

        substituted = json.loads(json.dumps(self.live_manifest))
        substituted["tools"]["openssl"]["source_archive_sha256"] = OTHER_SHA256
        substituted_path = write_bytes(
            self.case / "substituted-toolchain-pins.json",
            json.dumps(substituted, sort_keys=True).encode("ascii"),
        )
        with self.assertRaisesRegex(
            MODULE.Refused,
            r"source digest pin is not the official OpenSSL 4.0.2 digest",
        ):
            MODULE.load_pin(substituted_path)

    def test_matching_receipt_binds_source_to_binary_and_controller(self) -> None:
        receipt = self.parse_receipt()
        MODULE.bind_source_to_binary(receipt, self.pin, self.controller_sha)
        self.assertEqual(receipt["source_sha"], OFFICIAL_SOURCE_SHA256)
        self.assertEqual(receipt["archive_sha"], self.pin["archive_sha"])
        self.assertEqual(receipt["controller_sha256"], self.controller_sha)

    def test_forged_source_digest_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            MODULE.Refused,
            r"source digest is not the official OpenSSL 4.0.2 digest",
        ):
            self.parse_receipt(source_archive_sha256=OTHER_SHA256)
        with self.assertRaisesRegex(
            MODULE.Refused,
            r"source archive identity mismatch",
        ):
            self.parse_receipt(source_archive_name="openssl-9.9.9.tar.gz")
        with self.assertRaisesRegex(
            MODULE.Refused,
            r"source digest is not the official OpenSSL 4.0.2 digest",
        ):
            self.parse_receipt(source_archive_sha256=PRESERVED_OPENSSL_401_SHA256)

    def test_changed_configuration_flags_are_rejected(self) -> None:
        with self.assertRaisesRegex(
            MODULE.Refused,
            r"configuration flags mismatch",
        ):
            self.parse_receipt(build_configuration="darwin64-arm64-cc enable-weak-ssl-ciphers")

    def test_wrong_compiler_toolchain_identity_is_rejected(self) -> None:
        compiler = dict(MODULE.FROZEN_COMPILER_IDENTITY)
        compiler["sha256"] = OTHER_SHA256
        compiler["version_line"] = "Apple clang version 1.0.0 (clang-1000.0.0.0)"
        with self.assertRaisesRegex(
            MODULE.Refused,
            r"compiler/toolchain identity mismatch",
        ):
            self.parse_receipt(compiler_identity=compiler)

    def test_source_to_binary_mismatch_is_rejected(self) -> None:
        receipt = self.parse_receipt(archive_sha256=OTHER_SHA256)
        self.assertEqual(receipt["source_sha"], OFFICIAL_SOURCE_SHA256)
        with self.assertRaisesRegex(
            MODULE.Refused,
            r"source-to-binary provenance mismatch",
        ):
            MODULE.bind_source_to_binary(receipt, self.pin, self.controller_sha)
        tree_mismatch = self.parse_receipt(install_tree_sha256=OTHER_SHA256)
        with self.assertRaisesRegex(
            MODULE.Refused,
            r"source-to-binary provenance mismatch",
        ):
            MODULE.bind_source_to_binary(tree_mismatch, self.pin, self.controller_sha)
        exec_mismatch = self.parse_receipt(executable_sha256=OTHER_SHA256)
        with self.assertRaisesRegex(
            MODULE.Refused,
            r"source-to-binary provenance mismatch",
        ):
            MODULE.bind_source_to_binary(exec_mismatch, self.pin, self.controller_sha)

    def test_self_authored_receipt_is_owner_blocked(self) -> None:
        receipt = write_bytes(self.case / "self-auth.json", self.receipt_bytes())
        os.environ[MODULE.RECEIPT_ENV] = str(receipt)
        with self.assertRaisesRegex(MODULE.Refused, r"owner-blocked"):
            MODULE.require_external_build_receipt(ROOT)
        with self.assertRaisesRegex(MODULE.Refused, r"cannot self-authorize"):
            MODULE.require_external_build_receipt(ROOT)
        fake_repo = self.case / "candidate-repo"
        (fake_repo / "tools").mkdir(parents=True)
        adjacent = fake_repo / "tools" / "openssl-self-auth-receipt.json"
        write_bytes(adjacent, self.receipt_bytes())
        os.environ[MODULE.RECEIPT_ENV] = str(adjacent)
        with self.assertRaisesRegex(MODULE.Refused, r"owner-blocked"):
            MODULE.require_external_build_receipt(fake_repo)
        writable = write_bytes(self.case / "writable.json", self.receipt_bytes(), 0o644)
        os.environ[MODULE.RECEIPT_ENV] = str(writable)
        with self.assertRaisesRegex(MODULE.Refused, r"owner-blocked"):
            MODULE.require_external_build_receipt(ROOT)
        os.environ.pop(MODULE.RECEIPT_ENV, None)
        with self.assertRaisesRegex(MODULE.Refused, r"owner-blocked"):
            MODULE.require_external_build_receipt(ROOT)

    def test_prepare_refuses_self_auth_and_missing_receipt_before_extract(self) -> None:
        with mock.patch.object(
            MODULE.tempfile,
            "mkdtemp",
            side_effect=AssertionError("OpenSSL archive must not be extracted"),
        ):
            with self.assertRaisesRegex(MODULE.Refused, r"owner-blocked"):
                MODULE.prepare(str(PIN_MANIFEST))
            synthetic = write_bytes(
                self.case / "toolchain-pins.json",
                json.dumps(
                    {
                        "tools": {
                            "openssl": {
                                "version": MODULE.OFFICIAL_VERSION,
                                "platform": MODULE.OFFICIAL_PLATFORM,
                                "source_archive_path": self.pin["source_archive"],
                                "source_archive_name": MODULE.OFFICIAL_SOURCE_NAME,
                                "source_archive_sha256": MODULE.OFFICIAL_SOURCE_SHA256,
                                "archive_path": {"darwin_arm64": self.pin["archive"]},
                                "archive_sha256": {"darwin_arm64": self.pin["archive_sha"]},
                                "install_tree_sha256": {"darwin_arm64": self.pin["tree_sha"]},
                                "top_level_root": MODULE.OFFICIAL_ROOT,
                                "executable": MODULE.OFFICIAL_EXECUTABLE,
                                "executable_sha256": self.pin["executable_sha"],
                                "build_configuration": MODULE.OFFICIAL_CONFIGURATION,
                                "compiler_identity": dict(MODULE.FROZEN_COMPILER_IDENTITY),
                                "build_transaction": self.pin["build_transaction"],
                                "build_receipt_env": MODULE.RECEIPT_ENV,
                            }
                        }
                    }
                ).encode("ascii"),
                0o644,
            )
            with self.assertRaisesRegex(MODULE.Refused, r"owner-blocked"):
                MODULE.prepare(str(synthetic))
            receipt = write_bytes(self.case / "prepare-self-auth.json", self.receipt_bytes())
            os.environ[MODULE.RECEIPT_ENV] = str(receipt)
            with self.assertRaisesRegex(MODULE.Refused, r"cannot self-authorize"):
                MODULE.prepare(str(synthetic))

    def test_controller_digest_mismatch_is_rejected(self) -> None:
        receipt = self.parse_receipt(controller_sha256=OTHER_SHA256)
        with self.assertRaisesRegex(
            MODULE.Refused,
            r"controller digest mismatch",
        ):
            MODULE.bind_source_to_binary(receipt, self.pin, self.controller_sha)

    def test_shell_replacement_manifest_and_controller_cannot_self_authorize(self) -> None:
        replacement = write_bytes(
            self.case / "toolchain-pins.json",
            PIN_MANIFEST.read_bytes(),
            0o644,
        )
        copied = write_bytes(
            self.case / "release_openssl_archive_custody.py",
            TOOL.read_bytes(),
            0o644,
        )
        script = (
            f"source {shlex.quote(str(SHELL))}\n"
            "wins_release_python_run() { :; }\n"
            f"wins_release_openssl_prepare {shlex.quote(str(TOOL))} "
            f"{shlex.quote(str(replacement))}\n"
        )
        replaced_manifest = subprocess.run(
            ["/bin/bash", "-c", script],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
        self.assertNotEqual(replaced_manifest.returncode, 0, replaced_manifest.stderr)
        self.assertRegex(replaced_manifest.stderr, r"cannot self-authorize")
        self.assertNotIn("RUNTIME|", replaced_manifest.stdout)
        script = (
            f"source {shlex.quote(str(SHELL))}\n"
            "wins_release_python_run() { :; }\n"
            f"wins_release_openssl_prepare {shlex.quote(str(copied))} "
            f"{shlex.quote(str(PIN_MANIFEST))}\n"
        )
        replaced_controller = subprocess.run(
            ["/bin/bash", "-c", script],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
        self.assertNotEqual(replaced_controller.returncode, 0, replaced_controller.stderr)
        self.assertRegex(
            replaced_controller.stderr,
            r"malicious or substituted OpenSSL custody controller rejected",
        )
        self.assertNotIn("RUNTIME|", replaced_controller.stdout)

    def test_json_authenticated_flag_does_not_self_authorize(self) -> None:
        forged = self.parse_receipt()
        MODULE.bind_source_to_binary(forged, self.pin, self.controller_sha)
        receipt = write_bytes(self.case / "json-true.json", self.receipt_bytes())
        os.environ[MODULE.RECEIPT_ENV] = str(receipt)
        with self.assertRaisesRegex(MODULE.Refused, r"owner-blocked"):
            MODULE.verify_build_receipt(ROOT, self.pin, self.controller_sha)
        with self.assertRaisesRegex(
            MODULE.Refused,
            r"authenticated must be JSON true",
        ):
            self.parse_receipt(authenticated=False)

    def test_descriptor_reads_are_mutation_resistant(self) -> None:
        source = TOOL.read_text(encoding="ascii")
        self.assertIn("O_NOFOLLOW", source)
        self.assertIn("fstat", source)
        self.assertIn("file changed while it was hashed", source)
        self.assertIn("was replaced after it was opened", source)


if __name__ == "__main__":
    unittest.main()
