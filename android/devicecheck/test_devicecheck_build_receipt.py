#!/usr/bin/env python3
"""Hostile, producer-only tests for DeviceCheck build receipt custody.

No test invokes Gradle, Android SDK tooling, signing, ADB, or a device. The
reviewed-tool outputs are represented by a fixture runner after exact staged
bytes have been held by devicecheck_build_receipt.py.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import time
import types
import unittest
import sys
from unittest import mock
from typing import Callable


_RECEIPT_TOOL = pathlib.Path(__file__).resolve().with_name("devicecheck_build_receipt.py")
_RECEIPT_SPEC = importlib.util.spec_from_file_location(
    "winsvpn_devicecheck_build_receipt_test_dependency",
    _RECEIPT_TOOL,
)
if _RECEIPT_SPEC is None or _RECEIPT_SPEC.loader is None:
    raise RuntimeError("cannot load exact DeviceCheck build-receipt dependency")
receipt = importlib.util.module_from_spec(_RECEIPT_SPEC)
sys.modules[_RECEIPT_SPEC.name] = receipt
_RECEIPT_SPEC.loader.exec_module(receipt)


ROOT = pathlib.Path(__file__).resolve().parents[2]
BUILD_SCRIPT = ROOT / "android/devicecheck/build_devicecheck.sh"
RECEIPT_TOOL = ROOT / "android/devicecheck/devicecheck_build_receipt.py"
THIS_TEST = pathlib.Path(__file__).resolve()


def write_file(path: pathlib.Path, data: str | bytes, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = data.encode("utf-8") if isinstance(data, str) else data
    path.write_bytes(raw)
    if executable:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class FakeReviewedTools:
    def __init__(self) -> None:
        self.packages: dict[bytes, tuple[str, str, int]] = {
            b"T": ("org.winsvpn.devicecheck", "devicecheck", 1),
            b"X": ("org.winsvpn.devicecheck.test", "devicecheck", 1),
        }
        self.signers: dict[bytes, str] = {
            b"T": "1" * 64,
            b"X": "1" * 64,
        }
        self.multi_signer = False
        self.on_call: Callable[[tuple[str, ...]], None] | None = None

    def __call__(self, command: tuple[str, ...] | list[str]) -> str:
        command = tuple(command)
        if self.on_call is not None:
            self.on_call(command)
        artifact = pathlib.Path(command[-1])
        marker = artifact.read_bytes()[:1]
        if marker not in self.packages or marker not in self.signers:
            raise AssertionError(f"unknown staged fixture artifact marker: {marker!r}")
        if len(command) >= 3 and command[1] == "-jar":
            signer = self.signers[marker]
            lines = [
                "Verified using v2 scheme (APK Signature Scheme v2): true",
                f"Signer #1 certificate SHA-256 digest: {signer}",
            ]
            if self.multi_signer:
                lines.append(f"Signer #2 certificate SHA-256 digest: {signer}")
            return "\n".join(lines) + "\n"
        if len(command) >= 2 and command[1] == "dump":
            package_id, version_name, version_code = self.packages[marker]
            return (
                "package: "
                f"name='{package_id}' versionCode='{version_code}' "
                f"versionName='{version_name}'\n"
            )
        raise AssertionError(f"unexpected reviewed-tool command: {command!r}")


class DeviceCheckBuildReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="wins-devicecheck-receipt-")
        self.root = pathlib.Path(self.temporary.name)
        self.authorization_id = "9" * 64
        self.repo = self.root / self.authorization_id
        self.sdk = self.root / "sdk"
        self.java_root = self.root / "sealed-java"
        self.original_constants = {
            name: getattr(receipt, name)
            for name in (
                "SEALED_JAVA_ROOT",
                "EXPECTED_OWNER_SIGNER_SHA256",
                "EXPECTED_SOURCE_AUTHORITY_SHA256",
                "SOURCE_AUTHORITY_ROOT",
                "SOURCE_SNAPSHOT_BASE",
                "SOURCE_MANIFEST_BASE",
                "OWNER_AUTHORITY_PATH",
                "LOADER_PATH",
                "CONTROLLER_PATH",
                "OWNER_SIGNER_CERTIFICATE_PATH",
                "BUILD_WORKSPACE_ROOT",
                "BUILD_CACHE_ROOT",
            )
        }
        receipt.SEALED_JAVA_ROOT = self.java_root
        receipt.EXPECTED_OWNER_SIGNER_SHA256 = "1" * 64
        receipt.EXPECTED_SOURCE_AUTHORITY_SHA256 = "6" * 64
        receipt.SOURCE_AUTHORITY_ROOT = self.root / "devicecheck-v3"
        receipt.SOURCE_SNAPSHOT_BASE = receipt.SOURCE_AUTHORITY_ROOT / "snapshots/sha256"
        receipt.SOURCE_MANIFEST_BASE = receipt.SOURCE_AUTHORITY_ROOT / "manifests/sha256"
        receipt.OWNER_AUTHORITY_PATH = self.root / "devicecheck-v3.authority.json"
        receipt.LOADER_PATH = receipt.SOURCE_AUTHORITY_ROOT / "loader.py"
        receipt.CONTROLLER_PATH = receipt.SOURCE_AUTHORITY_ROOT / "controller.py"
        receipt.OWNER_SIGNER_CERTIFICATE_PATH = self.root / "owner.x509.pem"
        receipt.BUILD_WORKSPACE_ROOT = self.root
        receipt.BUILD_CACHE_ROOT = self.root / "private-cache"
        self.cache = receipt.BUILD_CACHE_ROOT / self.authorization_id
        self.cache.mkdir(parents=True)
        self.cache.chmod(0o700)
        self.tools = FakeReviewedTools()
        self._write_fixture()
        self.repo.chmod(0o700)
        self._write_source_transaction()

    def tearDown(self) -> None:
        for name, value in self.original_constants.items():
            setattr(receipt, name, value)
        self.temporary.cleanup()

    @property
    def target_apk(self) -> pathlib.Path:
        return self.repo / receipt.VARIANT_POLICIES["debug"].target_apk

    @property
    def test_apk(self) -> pathlib.Path:
        return self.repo / receipt.VARIANT_POLICIES["debug"].android_test_apk

    @property
    def receipt_dir(self) -> pathlib.Path:
        return self.repo / receipt.receipt_directory_relative("debug")

    def _write_fixture(self) -> None:
        devicecheck = self.repo / "android/devicecheck"
        devicecheck.mkdir(parents=True, exist_ok=True)
        write_file(self.repo / "android/app/build.gradle.kts", 'android {\n    ndkVersion = "30.0.16248370"\n}\n')
        write_file(self.repo / "android/gradlew", "#!/bin/sh\nexit 0\n", executable=True)
        write_file(self.repo / "android/gradle/wrapper/gradle-wrapper.jar", b"root-wrapper")
        write_file(
            self.repo / "android/gradle/wrapper/gradle-wrapper.properties",
            "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.8.0-all.zip\n",
        )
        shutil.copy2(BUILD_SCRIPT, devicecheck / "build_devicecheck.sh")
        shutil.copy2(RECEIPT_TOOL, devicecheck / "devicecheck_build_receipt.py")
        shutil.copy2(THIS_TEST, devicecheck / "test_devicecheck_build_receipt.py")
        write_file(devicecheck / "test_live_hardware_attestation_proof.py", "# companion source contract\n")
        write_file(devicecheck / "test_shipping_source_closure.py", "# companion closure contract\n")
        write_file(devicecheck / "test_gradle_custody.py", "# companion Gradle custody test\n")
        write_file(devicecheck / "test_ndk_selection.py", "# companion NDK custody test\n")
        write_file(
            devicecheck / "app/build.gradle.kts",
            "android {\n"
            "    compileSdk = 37\n"
            "    minSdk = 24\n"
            "    ndkVersion = \"30.0.16248370\"\n"
            "    targetSdk = 35\n"
            "}\n",
        )
        write_file(devicecheck / "build.gradle.kts", "plugins { }\n")
        write_file(devicecheck / "gradle.properties", "android.useAndroidX=true\n")
        write_file(devicecheck / "settings.gradle.kts", 'plugins {\n    id("com.android.application") version "9.4.1" apply false\n}\n')
        write_file(devicecheck / "gradlew", "#!/bin/sh\nexit 0\n", executable=True)
        write_file(devicecheck / "gradlew.bat", "@echo off\n")
        write_file(devicecheck / "local.properties", f"sdk.dir={self.sdk}\n")
        write_file(
            devicecheck / "gradle/wrapper/gradle-wrapper.properties",
            "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.8.0-all.zip\n",
        )
        write_file(devicecheck / "gradle/wrapper/gradle-wrapper.jar", b"devicecheck-wrapper")
        write_file(devicecheck / "gradle/dependency-locking/app.lockfile", "fixture-lock\n")
        write_file(devicecheck / "gradle/verification-metadata.xml", "<verify-metadata>true</verify-metadata>\n")
        write_file(devicecheck / "app/src/main/AndroidManifest.xml", "<manifest/>\n")
        write_file(
            devicecheck / "app/src/main/kotlin/org/winsvpn/devicecheck/CheckActivity.kt",
            "package org.winsvpn.devicecheck\n",
        )
        write_file(
            devicecheck / "app/src/androidTest/kotlin/org/winsvpn/devicecheck/HardwareAttestationTest.kt",
            "package org.winsvpn.devicecheck\nclass HardwareAttestationTest\n",
        )
        write_file(
            devicecheck / "app/src/androidTest/kotlin/org/winsvpn/devicecheck/LiveHardwareAttestationProofTest.kt",
            "package org.winsvpn.devicecheck\nclass LiveHardwareAttestationProofTest\n",
        )
        write_file(devicecheck / "awgresponder/go.mod", "module fixture/awgresponder\n")
        write_file(devicecheck / "awgresponder/main.go", "package main\n")
        write_file(devicecheck / "engine/go.mod", "module fixture/engine\n")
        write_file(devicecheck / "engine/main.go", "package main\n")
        write_file(self.target_apk, b"T target DeviceCheck APK bytes")
        write_file(self.test_apk, b"X androidTest DeviceCheck APK bytes")
        tools = self.sdk / "build-tools" / receipt.BUILD_TOOLS_VERSION
        write_file(tools / "apksigner", "#!/bin/sh\nexit 0\n", executable=True)
        write_file(tools / "aapt", "#!/bin/sh\nexit 0\n", executable=True)
        write_file(tools / "lib/apksigner.jar", b"reviewed-apksigner-jar")
        write_file(
            self.java_root / receipt.SEALED_JAVA_RELATIVE,
            "#!/bin/sh\nexit 0\n",
            executable=True,
        )

    def _write_source_transaction(self) -> None:
        closure = receipt.hold_source_closure(self.repo)
        now = time.time_ns()
        nonce = "a" * 64
        value = {
            "schema_version": 4,
            "contract": receipt.SOURCE_TRANSACTION_CONTRACT,
            "authority_sha256": receipt.EXPECTED_SOURCE_AUTHORITY_SHA256,
            "authorization_id": self.authorization_id,
            "source_closure_sha256": "7" * 64,
            "producer_source_sha256": receipt._inventory_sha256(closure.inventory()),
            "source_index_path": str(receipt.SOURCE_MANIFEST_BASE / ("8" * 64 + ".json")),
            "source_index_sha256": "8" * 64,
            "build_script_sha256": closure.held[
                "android/devicecheck/build_devicecheck.sh"
            ].sha256,
            "receipt_tool_sha256": closure.held[
                "android/devicecheck/devicecheck_build_receipt.py"
            ].sha256,
            "release_python_sha256": "2" * 64,
            "loader_sha256": "3" * 64,
            "controller_sha256": "4" * 64,
            "owner_signer_sha256": receipt.EXPECTED_OWNER_SIGNER_SHA256,
            "owner_signer_certificate_sha256": "5" * 64,
            "workspace": receipt._workspace_identity(self.repo),
            "cache": receipt._directory_identity(self.cache, "fixture private cache"),
            "source_snapshot": str(receipt.SOURCE_SNAPSHOT_BASE / ("7" * 64)),
            "handoff_contract": receipt.BUILD_HANDOFF_CONTRACT,
            "atomic_publication_contract": receipt.ATOMIC_PUBLICATION_CONTRACT,
            "consumer_status": receipt.CONSUMER_STATUS,
            "nonce": nonce,
            "issued_unix_ns": now - 1_000_000,
            "expires_unix_ns": now + 60 * 1_000_000_000,
            "monotonic_sequence": 17,
            "controller_state_path": str(
                receipt.CONTROLLER_STATE_ROOT / f"17-{nonce}.json"
            ),
            "sealed": True,
        }
        write_file(
            self.repo / receipt.SOURCE_TRANSACTION_RELATIVE,
            receipt._canonical_json(value),
        )

    def _owner_authority(self) -> dict[str, object]:
        source_index_sha256 = "8" * 64
        records = {
            "release_python": receipt.RELEASE_PYTHON_PATH,
            "loader": receipt.LOADER_PATH,
            "controller": receipt.CONTROLLER_PATH,
            "owner_signer_certificate": receipt.OWNER_SIGNER_CERTIFICATE_PATH,
        }
        return {
            "schema_version": 4,
            "contract": receipt.OWNER_AUTHORITY_CONTRACT,
            **{
                name: {
                    "path": str(path),
                    "sha256": str(index + 2) * 64,
                    "size_bytes": index + 1,
                }
                for index, (name, path) in enumerate(records.items())
            },
            "source_manifest": {
                "path": str(receipt.SOURCE_MANIFEST_BASE / f"{source_index_sha256}.json"),
                "sha256": source_index_sha256,
                "size_bytes": 101,
            },
            "source_snapshot": {
                "path": str(receipt.SOURCE_SNAPSHOT_BASE / ("7" * 64)),
                "closure_sha256": "7" * 64,
            },
            "build": {
                "atomic_publication_contract": receipt.ATOMIC_PUBLICATION_CONTRACT,
                "build_gid": max(os.getgid(), 1),
                "build_uid": max(os.getuid(), 1),
                "cache_mode": "0700",
                "cache_root": str(receipt.BUILD_CACHE_ROOT),
                "fresh_workspace_required": True,
                "handoff_contract": receipt.BUILD_HANDOFF_CONTRACT,
                "workspace_mode": "0700",
                "workspace_root": str(receipt.BUILD_WORKSPACE_ROOT),
            },
            "authorization": {
                "authorization_id": self.authorization_id,
                "nonce": "a" * 64,
                "sequence": 17,
            },
            "consumer": {
                "contract": receipt.BUILD_HANDOFF_CONTRACT,
                "status": receipt.CONSUMER_STATUS,
            },
            "owner_signer_sha256": receipt.EXPECTED_OWNER_SIGNER_SHA256,
            "secret_material_redacted": True,
        }

    def _record(self) -> dict[str, object]:
        return receipt.record(self.repo, self.sdk, "debug", runner=self.tools)

    def _make_receipt_writable(self) -> tuple[pathlib.Path, pathlib.Path]:
        receipt_path = self.repo / receipt.receipt_relative("debug")
        sidecar_path = self.repo / receipt.sidecar_relative("debug")
        self.receipt_dir.chmod(0o700)
        receipt_path.chmod(0o600)
        sidecar_path.chmod(0o600)
        return receipt_path, sidecar_path

    def _write_forged_payload(self, payload: dict[str, object]) -> None:
        receipt_path, sidecar_path = self._make_receipt_writable()
        raw = receipt._canonical_json(payload)
        receipt_path.write_bytes(raw)
        sidecar_path.write_bytes(
            f"{hashlib.sha256(raw).hexdigest()}  {receipt.RECEIPT_NAME}\n".encode("ascii")
        )

    def test_record_and_verify_bind_complete_target_and_android_test_closure(self) -> None:
        result = self._record()
        self.assertTrue(result["ok"])
        self.assertEqual(result["receipt"], receipt.receipt_relative("debug"))
        self.assertTrue((self.repo / receipt.receipt_relative("debug")).is_file())
        payload, digest = receipt.load_receipt(self.repo, "debug")
        self.assertEqual(digest, result["receipt_sha256"])
        self.assertEqual(payload["contract"], receipt.CONTRACT)
        self.assertEqual(payload["build"], {
            "android_test_output": receipt.VARIANT_POLICIES["debug"].android_test_apk,
            "android_test_task": ":app:assembleDebugAndroidTest",
            "compile_sdk": 37,
            "min_sdk": 24,
            "target_sdk": 35,
            "target_output": receipt.VARIANT_POLICIES["debug"].target_apk,
            "target_task": ":app:assembleDebug",
            "variant": "debug",
        })
        self.assertEqual(
            payload["artifacts"]["target"]["package_id"],
            "org.winsvpn.devicecheck",
        )
        self.assertEqual(
            payload["artifacts"]["target"]["bytes"],
            len(b"T target DeviceCheck APK bytes"),
        )
        self.assertEqual(
            payload["artifacts"]["android_test"]["bytes"],
            len(b"X androidTest DeviceCheck APK bytes"),
        )
        self.assertEqual(
            payload["artifacts"]["android_test"]["package_id"],
            "org.winsvpn.devicecheck.test",
        )
        self.assertEqual(
            payload["artifacts"]["target"]["signer_sha256"],
            payload["artifacts"]["android_test"]["signer_sha256"],
        )
        self.assertEqual(payload["gradle_custody"]["agp_version"], "9.4.1")
        self.assertEqual(payload["gradle_custody"]["gradle_version"], "9.8.0")
        self.assertEqual(payload["gradle_custody"]["ndk_version"], "30.0.16248370")
        self.assertEqual(payload["toolchain"]["sdk_root"], str(self.sdk))
        self.assertEqual(
            payload["source_transaction"]["authorization_id"],
            self.authorization_id,
        )
        self.assertEqual(
            payload["source_transaction"]["source_index_sha256"],
            "8" * 64,
        )
        self.assertEqual(
            payload["source_transaction"]["source_closure_sha256"],
            "7" * 64,
        )
        self.assertEqual(
            payload["receipt_storage"]["atomic_publication_contract"],
            receipt.ATOMIC_PUBLICATION_CONTRACT,
        )
        inventory = {item["path"] for item in payload["source_closure"]["inventory"]}
        self.assertTrue(set(receipt.REQUIRED_CLOSURE_PATHS).issubset(inventory))
        self.assertIn("android/devicecheck/test_devicecheck_build_receipt.py", inventory)
        verified = receipt.verify(self.repo, self.sdk, "debug", runner=self.tools)
        self.assertEqual(verified["receipt_sha256"], result["receipt_sha256"])

    def test_v4_authority_requires_content_addresses_and_integrated_consumer(self) -> None:
        authority = self._owner_authority()
        raw = receipt._canonical_json(authority)
        self.assertEqual(
            receipt._validate_owner_authority_bytes(
                raw,
                receipt.EXPECTED_SOURCE_AUTHORITY_SHA256,
            ),
            authority,
        )
        hostile = json.loads(raw)
        hostile["consumer"]["status"] = "unintegrated"
        with self.assertRaisesRegex(receipt.ReceiptError, "consumer is not integrated"):
            receipt._validate_owner_authority_bytes(
                receipt._canonical_json(hostile),
                receipt.EXPECTED_SOURCE_AUTHORITY_SHA256,
            )
        hostile = json.loads(raw)
        hostile["source_manifest"]["path"] = str(self.root / "caller-manifest.json")
        with self.assertRaisesRegex(receipt.ReceiptError, "content-addressed path"):
            receipt._validate_owner_authority_bytes(
                receipt._canonical_json(hostile),
                receipt.EXPECTED_SOURCE_AUTHORITY_SHA256,
            )
        hostile = json.loads(raw)
        hostile["source_snapshot"]["path"] = str(self.root / "devicecheck-v2/source")
        with self.assertRaisesRegex(receipt.ReceiptError, "content-addressed closure"):
            receipt._validate_owner_authority_bytes(
                receipt._canonical_json(hostile),
                receipt.EXPECTED_SOURCE_AUTHORITY_SHA256,
            )

    def test_transaction_rejects_caller_source_index_and_private_cache_swap(self) -> None:
        transaction_path = self.repo / receipt.SOURCE_TRANSACTION_RELATIVE
        value = json.loads(transaction_path.read_text(encoding="ascii"))
        closure = receipt.hold_source_closure(self.repo)
        hostile = dict(value)
        hostile["source_index_path"] = str(self.root / "caller-selected.json")
        with self.assertRaisesRegex(receipt.ReceiptError, "authenticated snapshot"):
            receipt._validate_transaction_value(hostile, self.repo, closure)

        old_cache = self.cache.with_name("retired-cache")
        self.cache.rename(old_cache)
        self.cache.mkdir()
        self.cache.chmod(0o700)
        with self.assertRaisesRegex(receipt.ReceiptError, "private cache"):
            receipt._validate_transaction_value(value, self.repo, closure)

    def test_stale_candidate_and_source_hash_as_apk_custody_are_rejected(self) -> None:
        self._record()
        payload, _digest = receipt.load_receipt(self.repo, "debug")
        original_payload = json.loads(receipt._canonical_json(payload))
        payload["artifacts"]["target"]["sha256"] = payload["source_transaction"][
            "source_closure_sha256"
        ]
        self._write_forged_payload(payload)
        with self.assertRaisesRegex(receipt.ReceiptError, "forged, stale, or caller-authored"):
            receipt.verify(self.repo, self.sdk, "debug", runner=self.tools)
        self._write_forged_payload(original_payload)

        transaction_path = self.repo / receipt.SOURCE_TRANSACTION_RELATIVE
        transaction = json.loads(transaction_path.read_text(encoding="ascii"))
        transaction["nonce"] = "b" * 64
        transaction["controller_state_path"] = str(
            receipt.CONTROLLER_STATE_ROOT
            / f"{transaction['monotonic_sequence']}-{transaction['nonce']}.json"
        )
        transaction_path.write_bytes(receipt._canonical_json(transaction))
        with self.assertRaisesRegex(receipt.ReceiptError, "forged, stale, or caller-authored"):
            receipt.verify(self.repo, self.sdk, "debug", runner=self.tools)

    def test_atomic_handoff_never_exposes_a_partial_final_directory(self) -> None:
        derived = receipt.derive_receipt(self.repo, self.sdk, "debug", runner=self.tools)
        original_rename = receipt._rename_exclusive
        observations: list[tuple[str, ...]] = []

        def observe(directory_fd: int, source: str, target: str) -> None:
            with self.assertRaises(FileNotFoundError):
                os.stat(target, dir_fd=directory_fd, follow_symlinks=False)
            staging_fd = os.open(source, receipt._directory_open_flags(), dir_fd=directory_fd)
            try:
                observations.append(tuple(sorted(os.listdir(staging_fd))))
            finally:
                os.close(staging_fd)
            original_rename(directory_fd, source, target)

        with mock.patch.object(receipt, "_rename_exclusive", side_effect=observe):
            publication = receipt.publish_receipt(self.repo, "debug", derived.payload)
        publication.close()
        self.assertEqual(observations, [(receipt.RECEIPT_NAME, receipt.SIDECAR_NAME)])
        self.assertEqual(
            tuple(sorted(path.name for path in self.receipt_dir.iterdir())),
            (receipt.RECEIPT_NAME, receipt.SIDECAR_NAME),
        )

    def test_receipt_parent_swap_during_atomic_handoff_is_rejected(self) -> None:
        derived = receipt.derive_receipt(self.repo, self.sdk, "debug", runner=self.tools)
        publication_root = self.repo / receipt.RECEIPT_BASE
        retired = publication_root.with_name("devicecheck-receipts-retired")
        original_rename = receipt._rename_exclusive

        def swap_parent(directory_fd: int, source: str, target: str) -> None:
            publication_root.rename(retired)
            publication_root.mkdir()
            original_rename(directory_fd, source, target)

        with mock.patch.object(receipt, "_rename_exclusive", side_effect=swap_parent):
            with self.assertRaisesRegex(receipt.ReceiptError, "ancestor changed"):
                receipt.publish_receipt(self.repo, "debug", derived.payload)
        self.assertFalse((publication_root / "debug").exists())
        self.assertFalse((retired / "debug").exists())

    def test_missing_android_test_output_is_rejected_before_publication(self) -> None:
        self.test_apk.unlink()
        with self.assertRaisesRegex(receipt.ReceiptError, "androidTest APK is missing"):
            self._record()
        self.assertFalse(self.receipt_dir.exists())

    def test_wrong_package_version_or_signer_is_rejected(self) -> None:
        cases = (
            ("package", ("org.other.test", "devicecheck", 1), "package id"),
            ("version", ("org.winsvpn.devicecheck.test", "wrong", 1), "version_name"),
        )
        for _label, evidence, expected in cases:
            with self.subTest(expected=expected):
                self.tools.packages[b"X"] = evidence
                with self.assertRaisesRegex(receipt.ReceiptError, expected):
                    receipt.derive_receipt(self.repo, self.sdk, "debug", runner=self.tools)
                self.tools.packages[b"X"] = ("org.winsvpn.devicecheck.test", "devicecheck", 1)
        self.tools.signers[b"X"] = "2" * 64
        with self.assertRaisesRegex(receipt.ReceiptError, "signer_sha256"):
            receipt.derive_receipt(self.repo, self.sdk, "debug", runner=self.tools)

    def test_missing_owner_signer_identity_is_owner_blocked(self) -> None:
        receipt.EXPECTED_OWNER_SIGNER_SHA256 = "0" * 64
        with self.assertRaisesRegex(receipt.ReceiptError, "OWNER-BLOCKED"):
            receipt.derive_receipt(self.repo, self.sdk, "debug", runner=self.tools)

    def test_source_swap_after_prebuild_transaction_is_rejected(self) -> None:
        source = self.repo / "android/devicecheck/app/src/main/AndroidManifest.xml"
        source.write_text("<manifest package='hostile'/>\n", encoding="ascii")
        with self.assertRaisesRegex(receipt.ReceiptError, "pre-build authenticated snapshot"):
            receipt.derive_receipt(self.repo, self.sdk, "debug", runner=self.tools)

    def test_forged_all_environment_and_arbitrary_fd9_cannot_authorize_build(self) -> None:
        hostile = self.root / "hostile-transaction.json"
        hostile.write_bytes(b'{"hostile":true}\n')
        hostile.chmod(0o400)
        saved_fd = None
        try:
            try:
                saved_fd = os.dup(9)
            except OSError:
                saved_fd = None
            hostile_fd = os.open(hostile, os.O_RDONLY)
            try:
                os.dup2(hostile_fd, 9)
            finally:
                os.close(hostile_fd)
            forged_environment = {
                "WINS_DEVICECHECK_AUTHENTICATED_TRANSACTION": "v3",
                "WINS_DEVICECHECK_AUTHENTICATED_WORKSPACE": str(self.repo),
                "WINS_DEVICECHECK_OWNER_AUTHORITY_SHA256": "6" * 64,
                "WINS_DEVICECHECK_SOURCE_CLOSURE_SHA256": "7" * 64,
                "WINS_DEVICECHECK_SOURCE_TRANSACTION_FD": "9",
                "WINN_DEVICECHECK_RECEIPT_SELFTEST": "1",
            }
            with mock.patch.dict(os.environ, forged_environment, clear=False):
                closure = receipt.hold_source_closure(self.repo)
                with self.assertRaisesRegex(receipt.ReceiptError, "OWNER-BLOCKED"):
                    receipt._source_transaction(
                        self.repo,
                        closure,
                        require_inherited_descriptor=True,
                    )
        finally:
            if saved_fd is None:
                with contextlib.suppress(OSError):
                    os.close(9)
            else:
                os.dup2(saved_fd, 9)
                os.close(saved_fd)

    def test_fake_meta_inf_is_not_signer_evidence(self) -> None:
        fake = (
            "META-INF/CERT.RSA\n"
            "Signer #1 certificate SHA-256 digest: " + "1" * 64 + "\n"
        )
        with self.assertRaisesRegex(receipt.ReceiptError, "not verified"):
            receipt._parse_signer_digest(fake, "fake META-INF APK")

    def test_expired_or_replayed_transaction_fields_are_rejected(self) -> None:
        transaction_path = self.repo / receipt.SOURCE_TRANSACTION_RELATIVE
        base = json.loads(transaction_path.read_text(encoding="ascii"))
        closure = receipt.hold_source_closure(self.repo)
        now = 10_000_000_000
        cases = (
            ("future-issued", now + 1, now + 2, False),
            ("exact-issued", now, now + 1, True),
            ("exact-expiry", now - 1, now, False),
            ("just-before-expiry", now - 1, now + 1, True),
            (
                "exact-max-lifetime",
                now - 1,
                now - 1 + receipt.MAX_TRANSACTION_LIFETIME_NS,
                True,
            ),
            (
                "over-max-lifetime",
                now - 1,
                now + receipt.MAX_TRANSACTION_LIFETIME_NS,
                False,
            ),
        )
        for label, issued, expires, accepted in cases:
            with self.subTest(boundary=label):
                value = dict(base)
                value["issued_unix_ns"] = issued
                value["expires_unix_ns"] = expires
                with mock.patch.object(receipt.time, "time_ns", return_value=now):
                    if accepted:
                        receipt._validate_transaction_value(value, self.repo, closure)
                    else:
                        with self.assertRaisesRegex(receipt.ReceiptError, "expiry"):
                            receipt._validate_transaction_value(value, self.repo, closure)

        transaction_sha256 = hashlib.sha256(
            receipt._canonical_json(base)
        ).hexdigest()
        consumed = {
            "schema_version": 1,
            "contract": receipt.CONTROLLER_STATE_CONTRACT,
            "authority_sha256": base["authority_sha256"],
            "nonce": base["nonce"],
            "monotonic_sequence": base["monotonic_sequence"],
            "phase": "consumed",
            "transaction_sha256": transaction_sha256,
            "receipt_sha256": "b" * 64,
        }
        receipt._validate_controller_state_value(
            consumed,
            base,
            transaction_sha256,
            frozenset({"consumed"}),
        )
        with self.assertRaisesRegex(receipt.ReceiptError, "replayed|consumed"):
            receipt._validate_controller_state_value(
                consumed,
                base,
                transaction_sha256,
                frozenset({"building"}),
            )

    def test_same_version_same_signer_substitution_changes_apk_custody(self) -> None:
        self._record()
        payload, _digest = receipt.load_receipt(self.repo, "debug")
        original_sha = payload["artifacts"]["target"]["sha256"]
        self.target_apk.write_bytes(b"T substituted same-version same-signer APK bytes")
        self.assertNotEqual(original_sha, hashlib.sha256(self.target_apk.read_bytes()).hexdigest())
        with self.assertRaisesRegex(receipt.ReceiptError, "forged, stale, or caller-authored"):
            receipt.verify(self.repo, self.sdk, "debug", runner=self.tools)

    def test_multi_signer_artifact_is_rejected(self) -> None:
        self.tools.multi_signer = True
        with self.assertRaisesRegex(receipt.ReceiptError, "exactly one APK signer"):
            receipt.derive_receipt(self.repo, self.sdk, "debug", runner=self.tools)

    def test_same_apk_hash_and_hardlink_reuse_are_rejected(self) -> None:
        self.test_apk.write_bytes(self.target_apk.read_bytes())
        with self.assertRaisesRegex(receipt.ReceiptError, "reuse one SHA-256"):
            receipt.derive_receipt(self.repo, self.sdk, "debug", runner=self.tools)

    def test_special_mode_artifact_is_rejected(self) -> None:
        with self.assertRaisesRegex(receipt.ReceiptError, "setuid or setgid"):
            receipt._require_regular_one_link(
                types.SimpleNamespace(st_mode=stat.S_IFREG | 0o6755, st_nlink=1),
                "hostile APK",
            )
        self.test_apk.unlink()
        os.link(self.target_apk, self.test_apk)
        with self.assertRaisesRegex(receipt.ReceiptError, "one-link"):
            receipt.derive_receipt(self.repo, self.sdk, "debug", runner=self.tools)

    def test_same_path_and_symlink_or_ancestor_substitution_are_rejected(self) -> None:
        held = receipt.hold_relative_file(
            self.repo,
            receipt.VARIANT_POLICIES["debug"].target_apk,
            "fixture target APK",
            max_bytes=receipt.MAX_APK_BYTES,
            capture=False,
        )
        record = {
            "package_id": "org.winsvpn.devicecheck",
            "signer_sha256": "1" * 64,
            "version_code": 1,
            "version_name": "devicecheck",
            "version_name_utf8_hex": "646576696365636865636b",
        }
        with self.assertRaisesRegex(receipt.ReceiptError, "paths are reused"):
            receipt._require_distinct_artifacts(held, held, record, record)

        replacement = self.root / "symlink-replacement.apk"
        write_file(replacement, b"T replacement")
        self.target_apk.unlink()
        os.symlink(replacement, self.target_apk)
        with self.assertRaisesRegex(receipt.ReceiptError, "unsafe file entry|not a regular file"):
            receipt.derive_receipt(self.repo, self.sdk, "debug", runner=self.tools)

    def test_ancestor_substitution_is_rejected(self) -> None:
        target_parent = self.target_apk.parent
        original_parent = target_parent.with_name("debug-original")
        replacement_parent = self.root / "replacement-debug-output"
        replacement_parent.mkdir()
        write_file(replacement_parent / self.target_apk.name, b"T replacement")
        target_parent.rename(original_parent)
        os.symlink(replacement_parent, target_parent)
        with self.assertRaisesRegex(receipt.ReceiptError, "not a real directory"):
            receipt.derive_receipt(self.repo, self.sdk, "debug", runner=self.tools)

    def test_extra_or_split_apk_output_is_rejected(self) -> None:
        write_file(self.target_apk.parent / "split_config.arm64_v8a.apk", b"split")
        with self.assertRaisesRegex(receipt.ReceiptError, "split, extra, or ambiguous"):
            receipt.derive_receipt(self.repo, self.sdk, "debug", runner=self.tools)

    def test_source_omission_is_rejected(self) -> None:
        required = self.repo / receipt.REQUIRED_CLOSURE_PATHS[0]
        required.unlink()
        with self.assertRaisesRegex(receipt.ReceiptError, "omits required inputs"):
            receipt.derive_receipt(self.repo, self.sdk, "debug", runner=self.tools)

    def test_output_drift_during_inspection_is_rejected_without_receipt(self) -> None:
        calls = 0

        def drift(_command: tuple[str, ...]) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                self.target_apk.write_bytes(b"T changed after descriptor hold")

        self.tools.on_call = drift
        with self.assertRaisesRegex(receipt.ReceiptError, "changed during SDK descriptor custody"):
            self._record()
        self.assertFalse(self.receipt_dir.exists())

    def test_path_swap_during_inspection_is_rejected_without_receipt(self) -> None:
        replacement = self.root / "replacement.apk"
        write_file(replacement, b"T replacement bytes")
        calls = 0

        def swap(_command: tuple[str, ...]) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                os.replace(replacement, self.target_apk)

        self.tools.on_call = swap
        with self.assertRaisesRegex(receipt.ReceiptError, "changed during SDK descriptor custody"):
            self._record()
        self.assertFalse(self.receipt_dir.exists())

    def test_producer_drift_invalidates_a_previously_published_receipt(self) -> None:
        receipt_tool = self.repo / "android/devicecheck/devicecheck_build_receipt.py"
        held_leaf = receipt.hold_relative_file(
            self.repo,
            "android/devicecheck/devicecheck_build_receipt.py",
            "held receipt tool leaf",
            max_bytes=receipt.MAX_SOURCE_BYTES,
            capture=True,
        )
        leaf_stash = receipt_tool.with_name("devicecheck_build_receipt.py.held")
        receipt_tool.rename(leaf_stash)
        shutil.copy2(leaf_stash, receipt_tool)
        receipt_tool.unlink()
        leaf_stash.rename(receipt_tool)
        with self.assertRaisesRegex(receipt.ReceiptError, "drifted"):
            held_leaf.revalidate()

        held_parent = receipt.hold_relative_file(
            self.repo,
            "android/devicecheck/devicecheck_build_receipt.py",
            "held receipt tool parent",
            max_bytes=receipt.MAX_SOURCE_BYTES,
            capture=True,
        )
        parent = receipt_tool.parent
        parent_stash = parent.with_name("devicecheck-held")
        parent.rename(parent_stash)
        parent_stash.rename(parent)
        with self.assertRaisesRegex(receipt.ReceiptError, "drifted"):
            held_parent.revalidate()

        self._record()
        script = self.repo / "android/devicecheck/build_devicecheck.sh"
        script.write_bytes(script.read_bytes() + b"\n# producer drift\n")
        with self.assertRaisesRegex(receipt.ReceiptError, "pre-build authenticated snapshot"):
            receipt.verify(self.repo, self.sdk, "debug", runner=self.tools)

    def test_forged_receipt_fields_are_not_accepted_even_with_matching_sidecar(self) -> None:
        self._record()
        payload, _digest = receipt.load_receipt(self.repo, "debug")
        payload["build"]["target_task"] = ":app:assembleForged"  # type: ignore[index]
        self._write_forged_payload(payload)
        with self.assertRaisesRegex(receipt.ReceiptError, "forged, stale, or caller-authored"):
            receipt.verify(self.repo, self.sdk, "debug", runner=self.tools)

    def test_duplicate_json_keys_are_rejected_even_with_matching_sidecar(self) -> None:
        self._record()
        receipt_path, sidecar_path = self._make_receipt_writable()
        duplicate = b'{"schema_version":1,"schema_version":1}\n'
        receipt_path.write_bytes(duplicate)
        sidecar_path.write_bytes(
            f"{hashlib.sha256(duplicate).hexdigest()}  {receipt.RECEIPT_NAME}\n".encode("ascii")
        )
        with self.assertRaisesRegex(receipt.ReceiptError, "duplicate JSON key"):
            receipt.verify(self.repo, self.sdk, "debug", runner=self.tools)

    def test_sidecar_mismatch_is_rejected(self) -> None:
        self._record()
        receipt_path, sidecar_path = self._make_receipt_writable()
        sidecar_path.write_bytes(b"0" * 64 + b"  wrong-name.json\n")
        with self.assertRaisesRegex(receipt.ReceiptError, "sidecar"):
            receipt.verify(self.repo, self.sdk, "debug", runner=self.tools)
        self.assertTrue(receipt_path.exists())

    def test_partial_publication_rolls_back_both_receipt_files(self) -> None:
        derived = receipt.derive_receipt(self.repo, self.sdk, "debug", runner=self.tools)
        original_open = receipt.os.open

        def fail_sidecar(path: object, flags: int, *args: object, **kwargs: object) -> int:
            if os.fspath(path) == receipt.SIDECAR_NAME and flags & os.O_CREAT:
                raise OSError("forced sidecar publication failure")
            return original_open(path, flags, *args, **kwargs)

        with mock.patch.object(receipt.os, "open", side_effect=fail_sidecar):
            with self.assertRaisesRegex(OSError, "forced sidecar"):
                receipt.publish_receipt(self.repo, "debug", derived.payload)
        self.assertFalse((self.receipt_dir / receipt.RECEIPT_NAME).exists())
        self.assertFalse((self.receipt_dir / receipt.SIDECAR_NAME).exists())

    def test_crash_partial_publication_is_rejected_without_overwrite(self) -> None:
        self.receipt_dir.mkdir(parents=True)
        partial = self.receipt_dir / receipt.RECEIPT_NAME
        partial.write_bytes(b'{"partial":true}\n')
        with self.assertRaisesRegex(receipt.ReceiptError, "no-replace publication refused"):
            self._record()
        self.assertEqual(partial.read_bytes(), b'{"partial":true}\n')
        self.assertFalse((self.receipt_dir / receipt.SIDECAR_NAME).exists())

    def test_selftest_is_producer_only(self) -> None:
        self.assertEqual(
            receipt.selftest(),
            {"contract": receipt.CONTRACT, "device_actions": False, "ok": True},
        )

    def test_build_script_selftest_returns_before_sdk_or_device_work(self) -> None:
        source = BUILD_SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn('"/dev/fd/10" -I -S', source)
        self.assertIn('"${RELEASE_PYTHON}" -I -S /dev/fd/11 gate', source)
        self.assertIn(
            'exec "${RELEASE_PYTHON}" -I -S /dev/fd/16 selftest',
            source,
        )
        self.assertIn('require_held_path_fd 10 "ReleasePython"', source)
        environment = {
            "PATH": os.environ["PATH"],
            "WINN_DEVICECHECK_RECEIPT_SELFTEST": "1",
        }
        completed = subprocess.run(
            ["bash", str(BUILD_SCRIPT)],
            cwd=BUILD_SCRIPT.parent,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("OWNER-BLOCKED", completed.stderr)
        self.assertNotIn("Android SDK pinned", completed.stdout)
        self.assertNotIn("adb", completed.stdout.lower())

    def test_build_script_rejects_all_env_forgery_with_readable_fd9(self) -> None:
        forged = self.root / "forged-ticket.json"
        write_file(forged, b'{"forged":true}\n')
        saved_fd = None
        try:
            with contextlib.suppress(OSError):
                saved_fd = os.dup(9)
            source_fd = os.open(forged, os.O_RDONLY)
            try:
                os.dup2(source_fd, 9)
            finally:
                os.close(source_fd)
            environment = {
                "PATH": os.environ["PATH"],
                "WINS_DEVICECHECK_AUTHENTICATED_TRANSACTION": "v3",
                "WINS_DEVICECHECK_AUTHENTICATED_WORKSPACE": str(ROOT),
                "WINS_DEVICECHECK_OWNER_AUTHORITY_SHA256": "6" * 64,
                "WINS_DEVICECHECK_SOURCE_CLOSURE_SHA256": "7" * 64,
                "WINS_DEVICECHECK_SOURCE_TRANSACTION_FD": "9",
                "WINN_DEVICECHECK_RECEIPT_SELFTEST": "1",
            }
            completed = subprocess.run(
                ["bash", str(BUILD_SCRIPT)],
                cwd=BUILD_SCRIPT.parent,
                env=environment,
                pass_fds=(9,),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=20,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("OWNER-BLOCKED", completed.stderr)
            self.assertNotIn("Android SDK pinned", completed.stdout)
            self.assertNotIn("copying the host sources", completed.stdout)
            self.assertNotIn("assembling", completed.stdout)
        finally:
            if saved_fd is None:
                with contextlib.suppress(OSError):
                    os.close(9)
            else:
                os.dup2(saved_fd, 9)
                os.close(saved_fd)

    def test_build_script_is_a_fail_closed_authority_gate_without_build_body(self) -> None:
        source = BUILD_SCRIPT.read_text(encoding="utf-8")
        for token in (
            "WINN_DEVICECHECK_RECEIPT_SELFTEST",
            'RELEASE_PYTHON="/Library/WinsVPN/ReleasePython/3.14.7/launcher/python3"',
            '"${RELEASE_PYTHON}" -I -S /dev/fd/11 gate',
            'exec "${RELEASE_PYTHON}" -I -S /dev/fd/16 selftest',
            'require_held_path_fd 9 "transaction ticket"',
            'require_held_path_fd 10 "ReleasePython"',
            'require_held_path_fd 11 "release loader"',
            'require_held_path_fd 12 "release controller"',
            'require_held_path_fd 14 "owner authority"',
            'require_held_path_fd 15 "owner signer certificate"',
            'require_held_path_fd 16 "authority-bound receipt tool"',
            "monotonic controller state descriptor is absent or invalid",
        ):
            with self.subTest(token=token):
                self.assertIn(token, source)
        self.assertNotIn('"/dev/fd/10" -I -S', source)
        gate_offset = source.index('"${RELEASE_PYTHON}" -I -S /dev/fd/11 gate')
        blocker_offset = source.index(
            'OWNER-BLOCKED: immutable compiler-input handoff is not implemented'
        )
        self.assertLess(gate_offset, blocker_offset)
        production_prefix = source[source.index("# Production builds"):gate_offset]
        self.assertNotIn('python3.14 "${RECEIPT_TOOL}"', production_prefix)
        self.assertNotIn('-S "${RECEIPT_TOOL}"', production_prefix)
        executable_lines = "\n".join(
            line for line in source.splitlines() if line.strip() and not line.startswith("#")
        )
        for forbidden in (
            '"${ANDROID_DIR}/gradlew"',
            "ndk-build",
            'APKSIGNER="',
            'ADB="',
            "/dev/fd/16 record",
            "WINN_DEVICECHECK_PRODUCER_ONLY",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, executable_lines)

    def test_disabled_producer_cannot_mint_receipt_without_fixture_runner(self) -> None:
        closure = receipt.hold_source_closure(self.repo)
        with self.assertRaisesRegex(
            receipt.ReceiptError,
            "OWNER-BLOCKED: DeviceCheck build producer is intentionally disabled",
        ):
            receipt._validate_build_script_policy(
                closure,
                receipt.VARIANT_POLICIES["debug"],
                schema_fixture=False,
            )

    def test_instrumentation_build_type_tracks_exact_signing_mode(self) -> None:
        source = (
            ROOT / "android/devicecheck/app/build.gradle.kts"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'testBuildType = if (hasCompleteEnvironmentSigning) "release" else "debug"',
            source,
        )

    def test_release_android_test_classpaths_have_strict_lock_state(self) -> None:
        lock = (
            ROOT / "android/devicecheck/gradle/dependency-locking/app.lockfile"
        ).read_text(encoding="utf-8")
        for configuration in (
            "releaseAndroidTestAnnotationProcessorClasspath",
            "releaseAndroidTestCompileClasspath",
            "releaseAndroidTestRuntimeClasspath",
        ):
            with self.subTest(configuration=configuration):
                self.assertIn(configuration, lock)

    def test_reviewed_sdk_tools_receive_the_held_descriptor_not_a_staged_path(self) -> None:
        source = RECEIPT_TOOL.read_text(encoding="utf-8")
        self.assertIn("pass_fds=descriptors", source)
        self.assertIn('descriptor_path = f"/dev/fd/{descriptor}"', source)
        self.assertIn('f"/dev/fd/{jar_descriptor}"', source)
        self.assertIn('f"/dev/fd/{java_descriptor}"', source)
        self.assertIn('f"/dev/fd/{aapt_descriptor}"', source)
        self.assertNotIn("str(toolchain.java.path)", source)
        self.assertIn("def held_descriptor", source)
        self.assertNotIn("TemporaryDirectory", source)
        completed = mock.Mock(returncode=0, stdout="verified\n")
        with mock.patch.object(receipt.subprocess, "run", return_value=completed) as run:
            self.assertEqual(
                receipt._run_checked(("reviewed-apksigner", "/dev/fd/71"), pass_fds=(71,)),
                "verified\n",
            )
        self.assertEqual(run.call_args.kwargs["pass_fds"], (71,))
        self.assertEqual(run.call_args.kwargs["env"], receipt._tool_environment())
        self.assertEqual(run.call_args.kwargs["cwd"], "/private/tmp")
        self.assertTrue(run.call_args.kwargs["close_fds"])

    def test_reviewed_sdk_tool_ancestor_swap_restore_is_rejected(self) -> None:
        original = self.sdk / "build-tools" / receipt.BUILD_TOOLS_VERSION
        held = original.with_name(original.name + "-held")
        hostile = self.root / "hostile-build-tools"
        shutil.copytree(original, hostile)
        calls = 0

        def swap_restore(command: tuple[str, ...]) -> None:
            nonlocal calls
            calls += 1
            if calls != 1:
                return
            original.rename(held)
            hostile.rename(original)
            original.rename(hostile)
            held.rename(original)

        self.tools.on_call = swap_restore
        with self.assertRaisesRegex(receipt.ReceiptError, "ancestor changed"):
            self._record()

    def test_production_toolchain_requires_system_immutable_execution_paths(self) -> None:
        with self.assertRaisesRegex(
            receipt.ReceiptError,
            "root-owned|SF_IMMUTABLE|not a real directory",
        ):
            receipt.hold_toolchain(self.sdk, require_sealed_execution=True)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
