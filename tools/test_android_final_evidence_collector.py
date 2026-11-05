#!/usr/bin/env python3
"""Offline fail-closed tests for the Android physical evidence lane."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import inspect
import io
import json
import os
import pathlib
import py_compile
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from unittest import mock

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
DEVICECHECK_DIR = TOOLS_DIR.parent / "android/devicecheck"
if str(DEVICECHECK_DIR) not in sys.path:
    sys.path.insert(0, str(DEVICECHECK_DIR))

import android_remote_route_control as route_control
import android_final_evidence_collector as collector
import android_release_matrix_evidence as matrix_compiler
from android_release_ui_driver import AndroidDriver, Runtime, sha256_text


NOW = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
EMPTY = hashlib.sha256(b"").hexdigest()
PWSH = shutil.which("pwsh")
if PWSH is None:
    bundled_pwsh = pathlib.Path.home() / ".homebrew/Homebrew/bin/pwsh"
    if bundled_pwsh.is_file():
        PWSH = str(bundled_pwsh)


def _encode_ed25519_point(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _t = point
    inverse = pow(z, collector._ED25519_P - 2, collector._ED25519_P)
    affine_x = x * inverse % collector._ED25519_P
    affine_y = y * inverse % collector._ED25519_P
    return (affine_y | ((affine_x & 1) << 255)).to_bytes(32, "little")


def _ed25519_fixture_key(seed: bytes) -> tuple[bytes, bytes, int]:
    expanded = hashlib.sha512(seed).digest()
    scalar_bytes = bytearray(expanded[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")
    public = _encode_ed25519_point(
        collector._ed25519_mul(collector._ED25519_BASE, scalar)
    )
    return public, expanded[32:], scalar


def _ed25519_sign(public: bytes, prefix: bytes, scalar: int, message: bytes) -> bytes:
    nonce = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little")
    nonce %= collector._ED25519_L
    encoded_nonce = _encode_ed25519_point(
        collector._ed25519_mul(collector._ED25519_BASE, nonce)
    )
    challenge = int.from_bytes(
        hashlib.sha512(encoded_nonce + public + message).digest(), "little"
    ) % collector._ED25519_L
    response = (nonce + challenge * scalar) % collector._ED25519_L
    return encoded_nonce + response.to_bytes(32, "little")


RSA_FIXTURE_N = int(
    "d07fe1b74a8e631bea23efe2369e882016f2d96dc03f05bf6769e04ab71f45a4"
    "b5db965ba57a78d61209fc565e9824561d3503c3c57a450ec50902e5bd7e831f"
    "bcb46caaa9c39ce194ac9358f850d962b61a12539782ec7fbae4551ffec860591"
    "b3e814a96025d563600ea0150862b0a0cfb151f3e7ab2c2f2e009dd2c75ba6de"
    "b0f0c5c57778193fe376659e52d00ba6a3532707f659510b3d59beb4886d4568"
    "705e261d66f881b8d65a07d2ecf2e7daddd67bf24cdd6675c3d3432683ba6fbb"
    "98a5198518876705e2f27a1abce2e134a42ec77703adeffa3436f887c71d43226"
    "faa3006c41b7c1ea522d0a2a9c390f91d38d9767997aa774796bb601f50ad3",
    16,
)
RSA_FIXTURE_D = int(
    "07d7ffc456fc33534e042b169e0a69c1974b6c8d99f1650475de004f9f43006a"
    "396338ed5ab4d84de960d1cae8051e3cd51d74f64cfc141401aa9c9ecaf9b2f2"
    "2335c06ecd332c383a5121bbf39f8b061126baf0c51eea49c5dca82d2b771b54"
    "ced713a31c309b954e33cb99e00f24185d33a6f04577f538ab4d6d6192361d9c"
    "ca9843da889811c8abbb911802ca2f0216c78a32a7dad8909e7787a29f1b5db2"
    "d745ba8a42013fce7f8592db8f1748e04904ebac5b6a70194447bbf995deda3e6"
    "3ef8cf2e95bc2aceb8808088af6bd32fbacad309be3329ebfd63e9ed99d0d4c33"
    "7afeda2a0389c4c9ba40162353df4bc0bcd396e9c501e8a51460feab51853d",
    16,
)


def _rsa_fixture_sign(message: bytes) -> str:
    width = (RSA_FIXTURE_N.bit_length() + 7) // 8
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420")
    tail = digest_info + hashlib.sha256(message).digest()
    encoded = b"\x00\x01" + b"\xff" * (width - len(tail) - 3) + b"\x00" + tail
    signature = pow(int.from_bytes(encoded, "big"), RSA_FIXTURE_D, RSA_FIXTURE_N)
    return signature.to_bytes(width, "big").hex()


def _fixture_device_semantic_report(
    nonce: bytes,
    attestation_value: dict,
    *,
    context_sha256: str = "5" * 64,
    overrides: dict[str, str] | None = None,
) -> bytes:
    report = {name: "1" for name in collector.DEVICE_ATTESTATION_REPORT_FIELDS}
    report.update(
        {
            "schema": collector.DEVICE_ATTESTATION_REPORT_SCHEMA,
            "host_session_nonce": nonce.hex(),
            "transcript_context_sha256": context_sha256,
            "persistent_key_id": attestation_value["attested_key_id"],
            "target_package_id": collector.DEVICE_ATTESTATION_PACKAGE,
            "target_version_name_utf8_hex": collector.DEVICE_ATTESTATION_VERSION_NAME.encode().hex(),
            "target_version_code": str(collector.DEVICE_ATTESTATION_VERSION_CODE),
            "target_signer_sha256": attestation_value["attestation_app_signer_sha256"],
            "target_base_apk_sha256": "1" * 64,
            "target_base_apk_bytes": "1048576",
            "target_installing_package": "com.android.shell",
            "target_initiating_package": "com.android.shell",
            "target_originating_package": "none",
            "test_apk_package_id": collector.DEVICE_ATTESTATION_TEST_PACKAGE,
            "test_apk_version_name_utf8_hex": collector.DEVICE_ATTESTATION_VERSION_NAME.encode().hex(),
            "test_apk_version_code": str(collector.DEVICE_ATTESTATION_VERSION_CODE),
            "test_apk_signer_sha256": attestation_value["attestation_app_signer_sha256"],
            "test_apk_sha256": "2" * 64,
            "test_apk_bytes": "524288",
            "test_apk_installing_package": "com.android.shell",
            "test_apk_initiating_package": "com.android.shell",
            "test_apk_originating_package": "none",
            "key_origin": "generated",
            "key_purposes": "sign",
            "key_digests": "sha256",
            "key_signature_paddings": "rsa-pkcs1-v1_5-sign",
            "key_security_level": attestation_value["attestation_security_level"],
            "key_rsa_modulus_bits": str(
                int(attestation_value["attested_rsa_modulus_hex"], 16).bit_length()
            ),
            "key_rsa_public_exponent": str(
                attestation_value["attested_rsa_public_exponent"]
            ),
            "attestation_leaf_certificate_sha256": attestation_value[
                "attestation_leaf_certificate_sha256"
            ],
            "attestation_extension_sha256": "c" * 64,
            "attestation_version": "3",
            "attestation_security_level": attestation_value[
                "attestation_security_level"
            ],
            "keymint_version": "3",
            "keymint_security_level": attestation_value[
                "attestation_security_level"
            ],
            "attestation_challenge_sha256": attestation_value[
                "attestation_challenge_sha256"
            ],
            "attested_verified_boot_key_sha256": "d" * 64,
            "attested_verified_boot_hash_sha256": "e" * 64,
            "attested_device_locked": "true",
            "attested_verified_boot_state": "green",
            "current_verified_boot_state": "green",
            "current_flash_locked": "1",
            "current_vbmeta_device_state": "locked",
            "user_device_secure": "true",
            "user_unlocked": "true",
            "device_provisioned": "true",
            "boot_count": "7",
            "android_sdk": "36",
            "android_security_patch": "2025-01-01",
            "display_count": "1",
            "display_id": "0",
            "display_name_nonce_sha256": "f" * 64,
            "display_flags": "0",
            "display_state": "2",
            "display_rotation": "0",
            "display_mode_id": "1",
            "display_physical_width_pixels": "1080",
            "display_physical_height_pixels": "2400",
            "display_refresh_millihertz": "60000",
            "display_current_width_pixels": "1080",
            "display_current_height_pixels": "2400",
            "display_maximum_width_pixels": "1080",
            "display_maximum_height_pixels": "2400",
            "display_density_dpi": "420",
            "runtime_process_name_utf8_hex": collector.DEVICE_ATTESTATION_PACKAGE.encode().hex(),
            "runtime_process_id": "1234",
            "runtime_process_uid": "10000",
            "runtime_elapsed_realtime_millis": "100000",
            "runtime_uptime_millis": "90000",
            "runtime_wall_clock_millis": str(int(dt.datetime.now(dt.timezone.utc).timestamp() * 1000)),
            "network_count": "1",
            "active_network_handle": "42",
            "active_network_transports": "wifi",
            "active_network_validated": "true",
            "active_network_internet": "true",
            "active_interface_name_utf8_hex": b"wlan0".hex(),
            "active_link_address_count": "1",
            "active_route_count": "1",
            "active_dns_server_count": "1",
            "active_network_mtu": "1500",
            "active_endpoint_nonce_sha256": "9" * 64,
            "vpn_present": "false",
            "vpn_network_handle": "0",
            "vpn_interface_name_utf8_hex": b"none".hex(),
            "vpn_link_address_count": "0",
            "vpn_route_count": "0",
            "vpn_dns_server_count": "0",
            "vpn_network_mtu": "0",
            "vpn_endpoint_nonce_sha256": collector._nonce_salted_device_report_hash(
                nonce, "vpn_network_endpoint", "none"
            ),
        }
    )
    for label in collector.DEVICE_ATTESTATION_BUILD_HASH_LABELS:
        report[f"build_{label}_nonce_sha256"] = "8" * 64
    if overrides:
        report.update(overrides)
    return "".join(
        f"{name}={report[name]}\n" for name in collector.DEVICE_ATTESTATION_REPORT_FIELDS
    ).encode("ascii")


def _fixture_device_proof_output(
    nonce: bytes,
    attestation_value: dict,
    *,
    context_sha256: str = "5" * 64,
    code: int = -1,
    report_overrides: dict[str, str] | None = None,
    signature_hex: str | None = None,
) -> subprocess.CompletedProcess:
    report = _fixture_device_semantic_report(
        nonce,
        attestation_value,
        context_sha256=context_sha256,
        overrides=report_overrides,
    )
    signature = signature_hex or _rsa_fixture_sign(
        collector.DEVICE_ATTESTATION_PROOF_DOMAIN + nonce + report
    )
    return subprocess.CompletedProcess(
        [],
        0,
        stdout=(
            "INSTRUMENTATION_STATUS: id=AndroidJUnitRunner\n"
            "INSTRUMENTATION_STATUS: numtests=1\n"
            "INSTRUMENTATION_STATUS: stream=\n"
            f"INSTRUMENTATION_STATUS: test={collector.DEVICE_ATTESTATION_TEST_METHOD}\n"
            f"INSTRUMENTATION_STATUS: class={collector.DEVICE_ATTESTATION_PROOF_CLASS}\n"
            "INSTRUMENTATION_STATUS: current=1\n"
            "INSTRUMENTATION_STATUS_CODE: 1\n"
            "INSTRUMENTATION_STATUS: winsvpn_attestation_report_b64="
            f"{base64.b64encode(report).decode('ascii')}\n"
            "INSTRUMENTATION_STATUS: winsvpn_attestation_signature_hex="
            f"{signature}\n"
            "INSTRUMENTATION_STATUS: winsvpn_attestation_key_id="
            f"{attestation_value['attested_key_id']}\n"
            "INSTRUMENTATION_STATUS: winsvpn_attestation_schema="
            f"{collector.DEVICE_ATTESTATION_REPORT_SCHEMA}\n"
            "INSTRUMENTATION_STATUS_CODE: 0\n"
            "INSTRUMENTATION_STATUS: id=AndroidJUnitRunner\n"
            "INSTRUMENTATION_STATUS: numtests=1\n"
            "INSTRUMENTATION_STATUS: stream=\n"
            f"INSTRUMENTATION_STATUS: test={collector.DEVICE_ATTESTATION_TEST_METHOD}\n"
            f"INSTRUMENTATION_STATUS: class={collector.DEVICE_ATTESTATION_PROOF_CLASS}\n"
            "INSTRUMENTATION_STATUS: current=1\n"
            "INSTRUMENTATION_STATUS_CODE: 0\n"
            "INSTRUMENTATION_RESULT: stream=\n"
            f"INSTRUMENTATION_CODE: {code}\n"
        ),
        stderr="",
    )


class FormFactorManifestFixture:
    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temp.name)
        self.manifest_dir = self.repo / ".artifacts" / "form-factor-input"
        self.manifest_dir.mkdir(parents=True)
        self.output = self.repo / ".artifacts" / "output"
        self.output.mkdir()
        self.app_version = "1.0.15"
        self.phone_build = "30"
        self.codes = {"phone": 30, "tv": 3002, "wear": 3001}
        self.build_hash = "b" * 64
        self.native_tool_paths: dict[str, pathlib.Path] = {}
        native_root = self.repo / ".native-tools"
        native_root.mkdir()
        self.adb_support_root = native_root / "platform-tools"
        self.adb_support_root.mkdir()
        self.tesseract_support_root = native_root / "tesseract"
        self.tesseract_support_root.mkdir()
        for index, role in enumerate(collector.NATIVE_TOOL_ROLES):
            path = (
                self.adb_support_root / "adb.exe"
                if role == "adb"
                else self.tesseract_support_root / "tesseract.exe"
                if role == "tesseract"
                else native_root / f"{role}.exe"
            )
            path.write_bytes((f"native-tool:{role}:" + "x" * (index + 1)).encode("ascii"))
            path.chmod(0o700)
            self.native_tool_paths[role] = path
        (self.adb_support_root / "AdbWinApi.dll").write_bytes(b"fixture-adb-win-api")
        (self.adb_support_root / "AdbWinUsbApi.dll").write_bytes(b"fixture-adb-win-usb-api")
        (self.tesseract_support_root / "tessdata").mkdir()
        (self.tesseract_support_root / "tessdata/eng.traineddata").write_bytes(
            b"fixture-English-tessdata"
        )
        self.expected_map_city_labels = ["Alpha City", "Beta City"]
        self.serial = "USBPHYSICAL1234"
        self.hardware_identity_sha256 = "d" * 64
        self.route_inventory = self.repo / ".route-authority" / "inventory.json"
        self.ssh_config = self.repo / ".route-authority" / "ssh-config"
        self.ssh_identity = self.repo / ".route-authority" / "release-key"
        self.ssh_known_hosts = self.repo / ".route-authority" / "known-hosts"
        self.write_json(self.route_inventory, inventory())
        self.ssh_config.write_text(
            "Host core-release\n"
            "  HostName core.example.test\n"
            "  User release\n"
            "  Port 22\n"
            "Host node-release\n"
            "  HostName node.example.test\n"
            "  User release\n"
            "  Port 22\n",
            encoding="ascii",
        )
        self.ssh_identity.write_text("fixture-private-key\n", encoding="ascii")
        self.ssh_known_hosts.write_text(
            "core.example.test ssh-ed25519 AAAAFIXTURECORE\n"
            "node.example.test ssh-ed25519 AAAAFIXTURENODE\n",
            encoding="ascii",
        )
        self.route_authority_paths = {
            "route_inventory": self.route_inventory,
            "ssh_config": self.ssh_config,
            "ssh_identity": self.ssh_identity,
            "ssh_known_hosts": self.ssh_known_hosts,
        }
        self.captured = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
        self.public_key, self.signing_prefix, self.signing_scalar = _ed25519_fixture_key(
            hashlib.sha256(b"android-form-factor-owner-fixture").digest()
        )
        self.authority_key_id = hashlib.sha256(self.public_key).hexdigest()
        self.original_authority_pin = (
            collector.EXPECTED_FORM_FACTOR_OWNER_AUTHORITY_SHA256
        )
        self.attested_modulus_hex = format(RSA_FIXTURE_N, "x")
        self.attested_key_id = collector._attested_key_id(
            self.attested_modulus_hex, 65537
        )
        self._create_release_input_authority()
        self._create_devicecheck_build_receipt()
        self.packages = {}
        for index, (key, relative) in enumerate(collector.CANONICAL_PRODUCED_PACKAGES):
            raw = (f"package:{key}:" + "x" * (index + 1)).encode("ascii")
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            self.packages[key] = {
                "path": relative,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size_bytes": len(raw),
                "signer_certificate_sha256": collector.EXPECTED_SIGNER,
                "cryptographic_signature_verified": True,
            }
        for key, relative in collector.PHONE_CANDIDATE_ALIASES.items():
            alias = self.repo / relative
            alias.parent.mkdir(parents=True, exist_ok=True)
            alias.write_bytes((self.repo / self.packages[key]["path"]).read_bytes())
        self.descriptors: list[dict] = []
        self.producer_paths: dict[str, str] = {}
        for descriptor_id in collector.FORM_FACTOR_DESCRIPTOR_IDS:
            self._create_descriptor(descriptor_id)
        self.manifest = self.manifest_dir / "manifest.json"
        self.authorization = self.manifest_dir / "owner-authorization.json"
        self.device_attestation = self.manifest_dir / "device-attestation.json"
        self.write_manifest()

    def close(self) -> None:
        collector.EXPECTED_FORM_FACTOR_OWNER_AUTHORITY_SHA256 = (
            self.original_authority_pin
        )
        collector._close_evidence_holds(self.output)
        self.temp.cleanup()

    @staticmethod
    def sha(path: pathlib.Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def write_json(path: pathlib.Path, value: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n",
            encoding="utf-8",
        )

    def producer_closure(self, relative: str) -> str:
        raw = (self.repo / relative).read_bytes()
        digest = hashlib.sha256()
        digest.update(relative.encode("ascii") + b"\0")
        digest.update(raw)
        digest.update(b"\0")
        return digest.hexdigest()

    def _create_release_input_authority(self) -> None:
        authority = self.repo / collector.FORM_FACTOR_OWNER_AUTHORITY_RELATIVE
        self.write_json(authority, {
            "schema_version": 1,
            "contract": collector.FORM_FACTOR_OWNER_AUTHORITY_CONTRACT,
            "algorithm": "ed25519",
            "key_id": self.authority_key_id,
            "public_key_hex": self.public_key.hex(),
            "secret_material_redacted": True,
        })
        collector.EXPECTED_FORM_FACTOR_OWNER_AUTHORITY_SHA256 = self.sha(authority)
        release_root = self.repo / ".artifacts/release-inputs/fixture"
        android_manifest = release_root / "ANDROID_INPUTS.json"
        self.write_json(android_manifest, {
            "schema_version": 1,
            "contract": "winsvpn-platform-inputs-v1",
            "native_inputs": {
                "files": [{
                    "path": collector.FORM_FACTOR_OWNER_AUTHORITY_RELATIVE,
                    "sha256": self.sha(authority),
                    "size": authority.stat().st_size,
                }],
            },
        })
        self.release_index = release_root / "RELEASE_INPUT_INDEX.json"
        self.write_json(self.release_index, {
            "schema_version": 1,
            "contract": "winsvpn-release-input-index-v1",
            "platform_manifests": {
                "android": {
                    "artifact_input_fingerprint_sha256": "c" * 64,
                    "path": android_manifest.name,
                    "sha256": self.sha(android_manifest),
                },
            },
        })
        self.release_hash = self.sha(self.release_index)

    def _create_devicecheck_build_receipt(self) -> None:
        required_sources = (
            "android/devicecheck/app/src/androidTest/kotlin/org/winsvpn/devicecheck/HardwareAttestationTest.kt",
            "android/devicecheck/app/src/androidTest/kotlin/org/winsvpn/devicecheck/LiveHardwareAttestationProofTest.kt",
            "android/devicecheck/build_devicecheck.sh",
            "android/devicecheck/devicecheck_build_receipt.py",
            "android/devicecheck/devicecheck_source_custody.py",
            "android/devicecheck/test_devicecheck_build_receipt.py",
            "android/devicecheck/test_devicecheck_source_custody.py",
            "android/devicecheck/test_live_hardware_attestation_proof.py",
            "android/devicecheck/test_shipping_source_closure.py",
            "android/devicecheck/gradle/dependency-locking/app.lockfile",
            "android/devicecheck/gradle/verification-metadata.xml",
        )
        source_inventory = []
        for index, relative in enumerate(required_sources):
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if relative == "android/devicecheck/devicecheck_source_custody.py":
                raw = (
                    f'CONTRACT = "{collector.DEVICECHECK_SOURCE_CUSTODY_CONTRACT}"\n'
                    f'OWNER_AUTHORITY_CONTRACT = "{collector.DEVICECHECK_SOURCE_AUTHORITY_CONTRACT}"\n'
                    'SOURCE_AUTHORITY_RELATIVE = "ReleaseAndroidSource/devicecheck-v3"\n'
                    f'CONSUMER_STATUS = "{collector.DEVICECHECK_SOURCE_CONSUMER_STATUS}"\n'
                ).encode("ascii")
            else:
                raw = f"devicecheck-source:{index}:{relative}\n".encode("ascii")
            path.write_bytes(raw)
            source_inventory.append(
                {
                    "bytes": len(raw),
                    "path": relative,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
        source_inventory.sort(key=lambda item: item["path"])
        source_records = {item["path"]: item for item in source_inventory}
        target_path = (
            "android/devicecheck/app/build/outputs/apk/release/app-release.apk"
        )
        test_path = (
            "android/devicecheck/app/build/outputs/apk/androidTest/release/"
            "app-release-androidTest.apk"
        )

        def artifact(
            path: str, package_id: str, raw: bytes, inode: int
        ) -> dict:
            return {
                "bytes": len(raw),
                "identity": {
                    "ctime_ns": 100 + inode,
                    "device": 1,
                    "flags": 0,
                    "gid": os.getgid(),
                    "inode": inode,
                    "mode": 0o444,
                    "mtime_ns": 200 + inode,
                    "nlink": 1,
                    "size": len(raw),
                    "uid": os.getuid(),
                },
                "package_id": package_id,
                "path": path,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "signer_sha256": collector.EXPECTED_SIGNER,
                "version_code": collector.DEVICE_ATTESTATION_VERSION_CODE,
                "version_name": collector.DEVICE_ATTESTATION_VERSION_NAME,
                "version_name_utf8_hex": collector.DEVICE_ATTESTATION_VERSION_NAME.encode(
                    "utf-8"
                ).hex(),
            }

        self.devicecheck_target_bytes = b"fixture DeviceCheck target APK"
        self.devicecheck_test_bytes = b"fixture DeviceCheck androidTest APK"
        target_file = self.repo / target_path
        test_file = self.repo / test_path
        target_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_bytes(self.devicecheck_target_bytes)
        test_file.write_bytes(self.devicecheck_test_bytes)
        target = artifact(
            target_path,
            collector.DEVICE_ATTESTATION_PACKAGE,
            self.devicecheck_target_bytes,
            101,
        )
        android_test = artifact(
            test_path,
            collector.DEVICE_ATTESTATION_TEST_PACKAGE,
            self.devicecheck_test_bytes,
            102,
        )
        producer_paths = {
            "build_script": "android/devicecheck/build_devicecheck.sh",
            "companion_source_contract_test": "android/devicecheck/test_live_hardware_attestation_proof.py",
            "hardware_attestation_test": "android/devicecheck/app/src/androidTest/kotlin/org/winsvpn/devicecheck/HardwareAttestationTest.kt",
            "live_hardware_attestation_proof_test": "android/devicecheck/app/src/androidTest/kotlin/org/winsvpn/devicecheck/LiveHardwareAttestationProofTest.kt",
            "receipt_tool": "android/devicecheck/devicecheck_build_receipt.py",
            "source_custody": "android/devicecheck/devicecheck_source_custody.py",
            "source_custody_contract_test": "android/devicecheck/test_devicecheck_source_custody.py",
            "shipping_source_closure_test": "android/devicecheck/test_shipping_source_closure.py",
        }
        inventory_sha256 = hashlib.sha256(
            collector._canonical_json_bytes(
                source_inventory, "fixture DeviceCheck inventory"
            )
            + b"\n"
        ).hexdigest()
        self.devicecheck_source_inventory_sha256 = inventory_sha256
        self.devicecheck_target_sha256 = hashlib.sha256(
            self.devicecheck_target_bytes
        ).hexdigest()
        self.devicecheck_test_sha256 = hashlib.sha256(
            self.devicecheck_test_bytes
        ).hexdigest()
        tool = lambda relative, marker: {
            "bytes": len(marker),
            "path": relative,
            "sha256": hashlib.sha256(marker).hexdigest(),
        }
        payload = {
            "artifacts": {"android_test": android_test, "target": target},
            "build": {
                "android_test_output": test_path,
                "android_test_task": ":app:assembleReleaseAndroidTest",
                "min_sdk": 24,
                "target_output": target_path,
                "target_task": ":app:assembleRelease",
                "variant": "release",
            },
            "consumer_status": collector.DEVICECHECK_SOURCE_CONSUMER_STATUS,
            "contract": collector.DEVICECHECK_BUILD_RECEIPT_CONTRACT,
            "gradle_custody": {
                "agp_version": "9.4.1",
                "dependency_lock": source_records[
                    "android/devicecheck/gradle/dependency-locking/app.lockfile"
                ],
                "gradle_version": "9.8.0",
                "ndk_version": "30.0.16248370",
                "verification_metadata": source_records[
                    "android/devicecheck/gradle/verification-metadata.xml"
                ],
            },
            "owner_signer": {
                "certificate_sha256": collector.EXPECTED_SIGNER,
                "identity_source": "reviewed-source-pin",
            },
            "parity": {
                "android_test_package_id": collector.DEVICE_ATTESTATION_TEST_PACKAGE,
                "package_relation": "target_package_id + .test",
                "passed": True,
                "signer_sha256": collector.EXPECTED_SIGNER,
                "version_code": collector.DEVICE_ATTESTATION_VERSION_CODE,
                "version_name_utf8_hex": collector.DEVICE_ATTESTATION_VERSION_NAME.encode(
                    "utf-8"
                ).hex(),
            },
            "producer": {
                role: source_records[relative]
                for role, relative in producer_paths.items()
            },
            "receipt_storage": {
                "publication": "descriptor-relative-no-replace",
                "receipt_name": "DEVICECHECK_BUILD_RECEIPT.json",
                "sidecar_name": "DEVICECHECK_BUILD_RECEIPT.json.sha256",
            },
            "schema_version": 2,
            "source_closure": {
                "inventory": source_inventory,
                "inventory_sha256": inventory_sha256,
            },
            "source_transaction": {
                "authority_sha256": "6" * 64,
                "expires_unix_ns": time.time_ns() + 60_000_000_000,
                "monotonic_sequence": 17,
                "nonce": "a" * 64,
                "prebuild_source_inventory_sha256": inventory_sha256,
                "source_snapshot": (
                    collector.DEVICECHECK_SOURCE_SNAPSHOT_PREFIX + inventory_sha256
                ),
                "transaction_sha256": "7" * 64,
                "workspace": {
                    "device": 1,
                    "inode": 2,
                    "mode": 0o700,
                    "path": str(self.repo),
                    "uid": os.getuid(),
                },
            },
            "toolchain": {
                "aapt": tool(
                    "build-tools/36.0.0/aapt", b"fixture reviewed aapt"
                ),
                "android_build_tools_version": "36.0.0",
                "apksigner": tool(
                    "build-tools/36.0.0/apksigner", b"fixture reviewed apksigner"
                ),
                "apksigner_jar": tool(
                    "build-tools/36.0.0/lib/apksigner.jar",
                    b"fixture reviewed apksigner jar",
                ),
                "execution": {
                    "aapt": "held-path-with-ancestor-custody",
                    "apksigner": "sealed-java-held-jar-descriptor",
                    "environment": "explicit-allowlist",
                },
                "java": tool(
                    collector.DEVICECHECK_SEALED_JAVA_RELATIVE,
                    b"fixture owner-sealed Java",
                ),
                "java_root": collector.DEVICECHECK_SEALED_JAVA_ROOT,
            },
        }
        self.devicecheck_build_receipt = (
            self.repo / collector.DEVICECHECK_BUILD_RECEIPT_RELATIVE
        )
        self.write_json(self.devicecheck_build_receipt, payload)
        self.devicecheck_build_receipt_sha256 = self.sha(
            self.devicecheck_build_receipt
        )
        self.devicecheck_build_receipt.with_name(
            self.devicecheck_build_receipt.name + ".sha256"
        ).write_text(
            f"{self.devicecheck_build_receipt_sha256}  "
            "DEVICECHECK_BUILD_RECEIPT.json\n",
            encoding="ascii",
        )

    def receipt_value(self, descriptor_id: str) -> dict:
        if descriptor_id in collector.DESCRIPTOR_PACKAGE_KEYS:
            form, role, package_key = collector.DESCRIPTOR_PACKAGE_KEYS[descriptor_id]
            record = self.packages[package_key]
            return {
                "schema_version": 1,
                "contract": collector.PRODUCED_ARTIFACT_CONTRACT,
                "form_factor": form,
                "role": role,
                "candidate_id": collector.FORM_FACTOR_CANDIDATES[form],
                "path": record["path"],
                "sha256": record["sha256"],
                "size_bytes": record["size_bytes"],
                "version_name": self.app_version,
                "version_code": self.codes[form],
                "captured_at_utc": self.captured,
                "secret_material_redacted": True,
            }
        form = descriptor_id.removesuffix("-runtime")
        if form == "wear":
            return {
                "schema_version": 1,
                "contract": collector.WEAR_RUNTIME_CONTRACT,
                "form_factor": "wear",
                "kind": "pairing_runtime",
                "candidate_id": "wear-os",
                "artifact_sha256": self.packages["wear_aab"]["sha256"],
                "version_name": self.app_version,
                "version_code": self.codes["wear"],
                "companion_phone_artifact_sha256": self.packages["phone_apk"]["sha256"],
                "pairing_observed": True,
                "source_only": False,
                "passed": True,
                "captured_at_utc": self.captured,
                "secret_material_redacted": True,
            }
        return {
            "schema_version": 1,
            "contract": collector.RUNTIME_CONTRACT,
            "form_factor": form,
            "kind": "live_vpn",
            "candidate_id": collector.FORM_FACTOR_CANDIDATES[form],
            "artifact_sha256": self.packages[f"{form}_apk"]["sha256"],
            "version_name": self.app_version,
            "version_code": self.codes[form],
            "primary_transport": collector.WINN_PRIMARY_TRANSPORT,
            "fallback_transports": list(collector.WINN_FALLBACK_TRANSPORTS),
            "winn_v3_session_observed": True,
            "source_only": False,
            "passed": True,
            "captured_at_utc": self.captured,
            "secret_material_redacted": True,
        }

    def _create_descriptor(self, descriptor_id: str) -> None:
        source = self.manifest_dir / "sources" / descriptor_id
        source.mkdir(parents=True)
        producer_relative = f"tools/{descriptor_id}-producer.py"
        producer = self.repo / producer_relative
        producer.parent.mkdir(parents=True, exist_ok=True)
        producer.write_text(f"PRODUCER = {descriptor_id!r}\n", encoding="ascii")
        self.producer_paths[descriptor_id] = producer_relative
        producer_sha = self.sha(producer)
        closure = self.producer_closure(producer_relative)
        receipt = source / "receipt.json"
        self.write_json(receipt, self.receipt_value(descriptor_id))
        value = json.loads(receipt.read_text(encoding="utf-8"))
        index = source / "index.json"
        self.write_json(index, {
            "schema_version": 1,
            "contract": collector.FORM_FACTOR_SOURCE_INDEX_CONTRACT,
            "created_at_utc": self.captured,
            "producer": {
                "path": producer_relative,
                "closure_sha256": closure,
                "files": [{"path": producer_relative, "sha256": producer_sha}],
            },
            "files": [{
                "path": "receipt.json",
                "sha256": self.sha(receipt),
                "size_bytes": receipt.stat().st_size,
                "contract": value["contract"],
            }],
            "sealed": True,
            "secret_material_redacted": True,
        })
        self.descriptors.append({
            "id": descriptor_id,
            "receipt_path": receipt.relative_to(self.manifest_dir).as_posix(),
            "receipt_sha256": self.sha(receipt),
            "source_index_path": index.relative_to(self.manifest_dir).as_posix(),
            "source_index_sha256": self.sha(index),
            "producer_closure_sha256": closure,
        })

    def write_manifest(self) -> None:
        self.write_json(self.manifest, {
            "schema_version": 1,
            "contract": collector.FORM_FACTOR_MANIFEST_CONTRACT,
            "application_id": collector.EXPECTED_APPLICATION_ID,
            "app_version": self.app_version,
            "phone_build_number": self.phone_build,
            "release_input_index_sha256": self.release_hash,
            "build_receipt_sha256": self.build_hash,
            "captured_at_utc": self.captured,
            "descriptors": self.descriptors,
            "secret_material_redacted": True,
        })
        self.manifest_sha = self.sha(self.manifest)
        self.write_json(self.device_attestation, {
            "schema_version": 1,
            "contract": collector.DEVICE_ATTESTATION_CONTRACT,
            "application_id": collector.EXPECTED_APPLICATION_ID,
            "app_version": self.app_version,
            "phone_build_number": self.phone_build,
            "serial_sha256": sha256_text(self.serial),
            "transport": "usb",
            "hardware_identity_sha256": self.hardware_identity_sha256,
            "attestation_challenge_sha256": collector._device_attestation_challenge(
                manifest_sha256=self.manifest_sha,
                app_version=self.app_version,
                phone_build_number=self.phone_build,
                serial_sha256=sha256_text(self.serial),
            ),
            "key_attestation_verified": True,
            "attestation_chain_verified": True,
            "attestation_security_level": "strongbox",
            "attestation_certificate_chain_sha256": "1" * 64,
            "attestation_leaf_certificate_sha256": "2" * 64,
            "attestation_application_id": collector.DEVICE_ATTESTATION_PACKAGE,
            "attestation_app_signer_sha256": collector.EXPECTED_SIGNER,
            "hardware_enforced_key_authorization": {
                "keymint_security_level": "strongbox",
                "origin": "generated",
                "purposes": ["sign"],
                "digests": ["sha256"],
                "signature_paddings": ["rsa-pkcs1-v1_5-sign"],
            },
            "attested_public_key_algorithm": "rsa",
            "attested_rsa_modulus_hex": self.attested_modulus_hex,
            "attested_rsa_public_exponent": 65537,
            "attested_key_id": self.attested_key_id,
            "live_proof_signature_algorithm": "rsa-pkcs1-v1_5-sha256",
            "verified_boot_state": "green",
            "device_locked": True,
            "captured_at_utc": self.captured,
            "passed": True,
            "secret_material_redacted": True,
        })
        self.write_authorization()

    def authorization_payload(self) -> dict:
        issued = dt.datetime.now(dt.timezone.utc)
        return {
            "schema_version": 2,
            "contract": collector.FORM_FACTOR_OWNER_AUTHORIZATION_CONTRACT,
            "algorithm": "ed25519",
            "key_id": self.authority_key_id,
            "application_id": collector.EXPECTED_APPLICATION_ID,
            "app_version": self.app_version,
            "phone_build_number": self.phone_build,
            "release_input_index_sha256": self.release_hash,
            "build_receipt_sha256": self.build_hash,
            "form_factor_manifest_sha256": self.manifest_sha,
            "candidate_ids": collector.FORM_FACTOR_CANDIDATES,
            "package_sha256s": {
                role: self.packages[role]["sha256"]
                for role, _relative in collector.CANONICAL_PRODUCED_PACKAGES
            },
            "package_signer_sha256s": {
                role: collector.EXPECTED_SIGNER
                for role, _relative in collector.CANONICAL_PRODUCED_PACKAGES
            },
            "cryptographic_package_signatures_verified": {
                role: True
                for role, _relative in collector.CANONICAL_PRODUCED_PACKAGES
            },
            "native_tool_sha256s": {
                role: self.sha(self.native_tool_paths[role])
                for role in collector.NATIVE_TOOL_ROLES
            },
            "adb_support_tree_sha256": collector._adb_support_tree_snapshot(
                self.adb_support_root
            )["tree_sha256"],
            "tesseract_support_tree_sha256": collector._tesseract_support_tree_snapshot(
                self.tesseract_support_root
            )["tree_sha256"],
            "route_authority_sha256s": {
                role: self.sha(self.route_authority_paths[role])
                for role in collector.ROUTE_AUTHORITY_ROLES
            },
            "expected_map_city_labels": self.expected_map_city_labels,
            "physical_device": {
                "serial_sha256": sha256_text(self.serial),
                "transport": "usb",
                "hardware_identity_sha256": self.hardware_identity_sha256,
                "attestation_receipt_sha256": self.sha(self.device_attestation),
                "attested_key_id": self.attested_key_id,
                "hardware_enforced_key_authorization": {
                    "keymint_security_level": "strongbox",
                    "origin": "generated",
                    "purposes": ["sign"],
                    "digests": ["sha256"],
                    "signature_paddings": ["rsa-pkcs1-v1_5-sign"],
                },
                "attestation_certificate_chain_sha256": "1" * 64,
            },
            "devicecheck_build_receipt": {
                "receipt_sha256": self.devicecheck_build_receipt_sha256,
                "contract": collector.DEVICECHECK_BUILD_RECEIPT_CONTRACT,
                "consumer_status": json.loads(
                    self.devicecheck_build_receipt.read_text(encoding="utf-8")
                )["consumer_status"],
                "variant": "release",
                "target_apk_sha256": hashlib.sha256(
                    self.devicecheck_target_bytes
                ).hexdigest(),
                "target_apk_bytes": len(self.devicecheck_target_bytes),
                "android_test_apk_sha256": hashlib.sha256(
                    self.devicecheck_test_bytes
                ).hexdigest(),
                "android_test_apk_bytes": len(self.devicecheck_test_bytes),
                "signer_sha256": collector.EXPECTED_SIGNER,
                "source_inventory_sha256": json.loads(
                    self.devicecheck_build_receipt.read_text(encoding="utf-8")
                )["source_closure"]["inventory_sha256"],
            },
            "approved_producers": [
                {
                    "descriptor_id": descriptor["id"],
                    "path": self.producer_paths[descriptor["id"]],
                    "closure_sha256": descriptor["producer_closure_sha256"],
                }
                for descriptor in self.descriptors
            ],
            "issued_at_utc": issued.isoformat().replace("+00:00", "Z"),
            "expires_at_utc": (issued + dt.timedelta(hours=1)).isoformat().replace(
                "+00:00", "Z"
            ),
            "secret_material_redacted": True,
        }

    def write_authorization(self, payload: dict | None = None) -> None:
        if not hasattr(self, "authorization"):
            return
        if payload is None:
            payload = self.authorization_payload()
        message = (
            collector.FORM_FACTOR_OWNER_SIGNATURE_DOMAIN
            + collector._canonical_json_bytes(payload, "fixture authorization")
        )
        value = {
            **payload,
            "signature_hex": _ed25519_sign(
                self.public_key,
                self.signing_prefix,
                self.signing_scalar,
                message,
            ).hex(),
        }
        self.write_json(self.authorization, value)
        self.authorization_sha = self.sha(self.authorization)

    def rewrite_receipt(self, descriptor_id: str, mutate) -> None:
        descriptor = next(item for item in self.descriptors if item["id"] == descriptor_id)
        receipt = self.manifest_dir / descriptor["receipt_path"]
        value = json.loads(receipt.read_text(encoding="utf-8"))
        mutate(value)
        self.write_json(receipt, value)
        index = self.manifest_dir / descriptor["source_index_path"]
        index_value = json.loads(index.read_text(encoding="utf-8"))
        index_value["files"][0].update({
            "sha256": self.sha(receipt),
            "size_bytes": receipt.stat().st_size,
            "contract": value.get("contract"),
        })
        self.write_json(index, index_value)
        descriptor["receipt_sha256"] = self.sha(receipt)
        descriptor["source_index_sha256"] = self.sha(index)
        self.write_manifest()

    def preflight(self) -> dict:
        return collector.preflight_form_factor_evidence(
            self.repo,
            self.manifest,
            self.manifest_sha,
            self.authorization,
            self.authorization_sha,
            self.release_index,
            self.packages,
            self.app_version,
            self.phone_build,
            self.release_hash,
            self.build_hash,
            self.native_tool_paths,
            self.adb_support_root,
            self.tesseract_support_root,
            self.route_authority_paths,
            inventory(),
            self.sha(self.route_inventory),
            self.expected_map_city_labels,
            self.device_attestation,
            self.devicecheck_build_receipt,
            self.devicecheck_build_receipt_sha256,
            self.devicecheck_target_sha256,
            len(self.devicecheck_target_bytes),
            self.devicecheck_test_sha256,
            len(self.devicecheck_test_bytes),
            self.devicecheck_source_inventory_sha256,
            self.serial,
        )

    def devicecheck_owner_pins(self) -> dict[str, str | int]:
        return {
            "expected_target_apk_sha256": self.devicecheck_target_sha256,
            "expected_target_apk_bytes": len(self.devicecheck_target_bytes),
            "expected_android_test_apk_sha256": self.devicecheck_test_sha256,
            "expected_android_test_apk_bytes": len(self.devicecheck_test_bytes),
            "expected_source_inventory_sha256": self.devicecheck_source_inventory_sha256,
        }

    def symbols(self) -> dict[str, str]:
        result: dict[str, str] = {}
        for role in collector.CANONICAL_SYMBOL_ROLES:
            code = self.codes["wear"] if role == "wear-os" else self.codes["phone"]
            root = (
                self.repo
                / ".artifacts/private-release-symbols"
                / role
                / f"{self.app_version}+{code}"
            )
            root.mkdir(parents=True, exist_ok=True)
            mapping = root / "mapping.txt"
            mapping.write_text(f"mapping:{role}\n", encoding="ascii")
            (root / "libapp.so.symbols").write_text(f"symbols:{role}\n", encoding="ascii")
            result[role] = self.sha(mapping)
        return result


def inventory(double_port: int = 9210) -> dict:
    return {
        "schema_version": 1,
        "contract": "winsvpn-android-route-inventory-v1",
        "captured_at_utc": NOW,
        "node": {
            "direct": {"protocol": "udp", "port": 9110, "ssh_alias": "node-release"},
            "advertised_xray_routes": [
                {"protocol": "tcp", "port": 80, "security": "none", "ssh_alias": "node-release"},
                {"protocol": "tcp", "port": 443, "security": "tls", "ssh_alias": "node-release"},
            ],
            "core_id_sha256": EMPTY,
            "exit_slug_sha256": EMPTY,
        },
        "double_vpn": {
            "direct": {"protocol": "udp", "port": double_port, "ssh_alias": "core-release"},
            "advertised_xray_routes": [
                {"protocol": "tcp", "port": 80, "security": "none", "ssh_alias": "core-release"},
                {"protocol": "tcp", "port": 8443, "security": "tls", "ssh_alias": "core-release"},
            ],
            "core_id_sha256": "4" * 64,
            "exit_slug_sha256": "5" * 64,
        },
        "secret_material_redacted": True,
    }


class RouteControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.temp.name) / "routes.json"
        self.path.write_text(json.dumps(inventory()) + "\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_accepts_dynamic_core_port_and_separate_route_sets(self) -> None:
        self.path.write_text(json.dumps(inventory(18437)) + "\n", encoding="utf-8")
        value, digest = route_control.load_inventory(self.path)
        self.assertEqual(value["double_vpn"]["direct"]["port"], 18437)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_rejects_unisolatable_duplicate_tcp_port(self) -> None:
        value = inventory()
        value["node"]["advertised_xray_routes"][1]["port"] = 80
        self.path.write_text(json.dumps(value) + "\n", encoding="utf-8")
        with self.assertRaises(route_control.RouteControlError):
            route_control.load_inventory(self.path)

    def test_xray_plan_blocks_mode_specific_direct_and_other_routes(self) -> None:
        selected, plan = route_control.mode_plan(inventory(18437), "double_vpn", "xray", 8443, "tls")
        self.assertEqual(selected["port"], 8443)
        self.assertIn({"protocol": "udp", "port": 18437}, plan["core-release"]["blocks"])
        self.assertIn({"protocol": "tcp", "port": 80}, plan["core-release"]["blocks"])
        self.assertNotIn({"protocol": "udp", "port": 9110}, plan["core-release"]["blocks"])

    def test_apply_refuses_same_public_nat_identity(self) -> None:
        with mock.patch.object(route_control, "host_public_ipv4", return_value="198.51.100.10"):
            with self.assertRaises(route_control.RouteControlError):
                route_control.apply(inventory(), "node", "xray", 80, "none", "f" * 32, "198.51.100.10")

    def test_apply_is_key_only_redacted_and_watchdog_bound(self) -> None:
        calls: list[tuple[str, str, dict | None]] = []
        def fake(alias, action, remote_id=None, payload=None):
            calls.append((alias, action, payload))
            return {
                "contract": route_control.REMOTE_CONTRACT,
                "passed": True,
                "secret_material_redacted": True,
                "before_state_sha256": "1" * 64,
                "applied_state_sha256": "2" * 64,
                "source_ipv4_sha256": "3" * 64,
                "watchdog_armed": True,
                "shared_nat_ambiguity_absent": True,
            }
        with mock.patch.object(route_control, "host_public_ipv4", return_value="1.1.1.1"), mock.patch.object(route_control, "ssh_call", side_effect=fake):
            result = route_control.apply(inventory(), "node", "xray", 80, "none", "e" * 32, "8.8.8.8")
        self.assertNotIn("8.8.8.8", json.dumps(result))
        self.assertTrue(result["watchdog_armed"])
        self.assertEqual(calls[0][2]["watchdog_seconds"], 180)
        self.assertIn({"protocol": "udp", "port": 9110}, calls[0][2]["blocks"])

    def test_pinned_route_subprocess_uses_exact_ssh_path(self) -> None:
        proxy = collector._PinnedRouteSubprocess(
            pathlib.Path("/reviewed/ssh"),
            pathlib.Path("/reviewed/config"),
            pathlib.Path("/reviewed/identity"),
            pathlib.Path("/reviewed/known-hosts"),
            {"node-release"},
        )
        completed = subprocess.CompletedProcess([], 0, stdout="{}", stderr="")
        with mock.patch.object(
            collector, "_bounded_subprocess_run", return_value=completed
        ) as run:
            actual = proxy.run(
                [
                    "ssh", "-o", "BatchMode=yes", "-F", "/reviewed/config",
                    "node-release", "sudo", "-n", "/reviewed/helper", "observe",
                ],
                text=True,
            )
        self.assertIs(actual, completed)
        command = run.call_args.args[0]
        self.assertEqual(command[0], "/reviewed/ssh")
        self.assertIn("IdentityAgent=none", command)
        self.assertIn("IdentityFile=/reviewed/identity", command)
        self.assertIn("UserKnownHostsFile=/reviewed/known-hosts", command)
        self.assertIn("ProxyCommand=none", command)
        self.assertEqual(command[-5:], ["node-release", "sudo", "-n", "/reviewed/helper", "observe"])
        with self.assertRaisesRegex(route_control.RouteControlError, "unpinned executable"):
            proxy.run(["powershell.exe", "-V"])
        with self.assertRaisesRegex(route_control.RouteControlError, "wrong SSH config"):
            proxy.run(
                ["ssh", "-F", "/attacker/config", "node-release", "sudo", "-n", "helper"]
            )


class DriverPureTests(unittest.TestCase):
    def test_fresh_regression_markers_reject_fail_then_pass_duplicates(self) -> None:
        with self.assertRaisesRegex(
            collector.CollectorError,
            "duplicate marker: CLEAN_UNINSTALL",
        ):
            collector.parse_markers(
                "CLEAN_UNINSTALL=FAIL\nCLEAN_UNINSTALL=PASS\n",
                collector.FRESH_REGRESSION_MARKERS,
            )

    def test_fresh_regression_markers_reject_unexpected_security_marker(self) -> None:
        with self.assertRaisesRegex(
            collector.CollectorError,
            "unexpected marker: OWNER_AUTHORIZED",
        ):
            collector.parse_markers(
                "OWNER_AUTHORIZED=PASS\n",
                collector.FRESH_REGRESSION_MARKERS,
            )

    def test_fresh_regression_marker_schema_has_no_live_vpn_outputs(self) -> None:
        self.assertTrue(
            collector.FRESH_REGRESSION_REQUIRED_MARKERS.isdisjoint(
                {
                    "ANDROID_DOUBLE_VPN_LIVE",
                    "DOUBLE_VPN_TRANSPORT",
                    "PUBLIC_EGRESS_SHA256",
                }
            )
        )
        self.assertEqual(
            collector.parse_markers(
                "diagnostic line\nCLEAN_UNINSTALL=PASS\n",
                collector.FRESH_REGRESSION_MARKERS,
            ),
            {"CLEAN_UNINSTALL": "PASS"},
        )

    def driver(self) -> AndroidDriver:
        value = object.__new__(AndroidDriver)
        value.adb = "adb"
        value.serial = "USB123"
        value.pin = "1357"
        value.package = "org.winsvpn.app"
        value.width = 1080
        value.height = 2400
        return value

    def test_rejects_unmeasured_map_assertions(self) -> None:
        with self.assertRaisesRegex(
            collector.CollectorError, "authenticated Android map geometry measurement"
        ):
            collector._validated_map_visual(
                {
                    "screenshot_path": "map.png",
                    "screenshot_sha256": "1" * 64,
                    "radius_miles": 50,
                    "city_labels_visible": True,
                    "target_marker_visible": True,
                    "viewport_not_world_zoom": True,
                },
                ["Alpha City", "Beta City"],
            )

    def test_accepts_authenticated_map_geometry(self) -> None:
        observed = collector._validated_map_visual(
            {
                "measurement_contract": "winsvpn-android-map-geometry-observation-v1",
                "screenshot_path": "map.png",
                "screenshot_sha256": "1" * 64,
                "observed_city_labels": ["Beta City", "Alpha City"],
                "viewport_bounds_px": [0, 0, 1000, 800],
                "radius_circle_bounds_px": [100, 0, 900, 800],
                "target_marker_bounds_px": [487, 387, 513, 413],
                "target_marker_semantic_observed": True,
            },
            ["Alpha City", "Beta City"],
        )
        self.assertEqual(observed["radius_miles"], 50)
        self.assertTrue(observed["viewport_not_world_zoom"])

    def test_adb_server_environment_rejects_remote_overrides(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "ADB_SERVER_SOCKET": "tcp:127.0.0.1:5038",
                "ADB_LIBUSB": "1",
                "ANDROID_ADB_SERVER_ADDRESS": "attacker.example",
            },
            clear=False,
        ):
            with self.assertRaisesRegex(collector.CollectorError, "ADDRESS overrides"):
                collector._validate_adb_server_environment("tcp:127.0.0.1:5038")
        with mock.patch.dict(
            os.environ,
            {
                "ADB_SERVER_SOCKET": "tcp:127.0.0.1:5038",
                "ADB_LIBUSB": "1",
            },
            clear=False,
        ):
            os.environ.pop("ANDROID_ADB_SERVER_ADDRESS", None)
            os.environ.pop("ANDROID_ADB_SERVER_PORT", None)
            collector._validate_adb_server_environment("tcp:127.0.0.1:5038")
        with mock.patch.dict(
            os.environ,
            {"ADB_SERVER_SOCKET": "tcp:127.0.0.1:5038"},
            clear=True,
        ):
            with self.assertRaisesRegex(collector.CollectorError, "libusb"):
                collector._validate_adb_server_environment("tcp:127.0.0.1:5038")

    def test_physical_device_rejects_emulator_or_non_usb_transport(self) -> None:
        with self.assertRaisesRegex(collector.CollectorError, "emulator transports"):
            collector._verify_physical_usb_device(
                pathlib.Path("/reviewed/adb.exe"),
                "emulator-5554",
                {"value": {}},
                {},
            )
        devices = subprocess.CompletedProcess(
            [], 0, stdout="List of devices attached\nUSBPHYSICAL1234 device product:x\n", stderr=""
        )
        with mock.patch.object(
            collector, "_bounded_subprocess_run", return_value=devices
        ):
            with self.assertRaisesRegex(collector.CollectorError, "ADB transport"):
                collector._verify_physical_usb_device(
                    pathlib.Path("/reviewed/adb.exe"),
                    "USBPHYSICAL1234",
                    {"value": {}},
                    {},
                )

    def test_physical_device_binds_hardware_and_verified_boot(self) -> None:
        serial = "USBPHYSICAL1234"
        properties = {
            "serial": serial,
            "usb": "usb:1-2",
            "product": "wins_phone",
            "model": "Wins Phone",
            "device": "wins_device",
            "boot_serial": serial,
        }
        hardware_sha256 = hashlib.sha256(
            collector._canonical_json_bytes(properties, "fixture hardware")
        ).hexdigest()
        outputs = [
            "List of devices attached\n"
            f"{serial} device usb:1-2 product:wins_phone model:Wins_Phone "
            "device:wins_device transport_id:7\n",
            "libusb,shell_v2",
            "usb:1-2",
            serial,
            properties["product"],
            properties["model"],
            properties["device"],
            properties["boot_serial"],
            "green",
            "1",
        ]
        completed = [
            subprocess.CompletedProcess([], 0, stdout=value, stderr="")
            for value in outputs
        ]
        attestation = {
            "snapshot": {"sha256": "3" * 64},
            "value": {
                "hardware_identity_sha256": hardware_sha256,
                "attested_key_id": collector._attested_key_id(
                    format(RSA_FIXTURE_N, "x"), 65537
                ),
                "attested_rsa_modulus_hex": format(RSA_FIXTURE_N, "x"),
                "attested_rsa_public_exponent": 65537,
                "attestation_app_signer_sha256": collector.EXPECTED_SIGNER,
                "attestation_security_level": "tee",
                "attestation_leaf_certificate_sha256": "a" * 64,
                "attestation_challenge_sha256": "b" * 64,
            },
        }
        nonce = b"n" * 32
        devicecheck_build_receipt = {
            "snapshot": {"sha256": "c" * 64},
            "value": {
                "consumer_status": collector.DEVICECHECK_SOURCE_CONSUMER_STATUS,
                "source_closure": {"inventory_sha256": "d" * 64},
            },
            "target": {"sha256": "1" * 64, "bytes": 1048576},
            "android_test": {"sha256": "2" * 64, "bytes": 524288},
        }
        initial_context = hashlib.sha256(
            collector._canonical_json_bytes(
                {
                    "hardware_identity_sha256": hardware_sha256,
                    "serial_sha256": collector.sha256_text(serial),
                    "transport_id": "7",
                    "devicecheck_custody": collector._devicecheck_custody_context(
                        devicecheck_build_receipt
                    ),
                },
                "fixture initial attestation context",
            )
        ).hexdigest()
        proof = _fixture_device_proof_output(
            nonce,
            attestation["value"],
            context_sha256=initial_context,
        )
        completed.append(proof)
        completed.append(
            subprocess.CompletedProcess([], 0, stdout=outputs[0], stderr="")
        )
        with mock.patch.object(
            collector, "_bounded_subprocess_run", side_effect=completed
        ), mock.patch.object(collector.secrets, "token_bytes", return_value=nonce):
            observed = collector._verify_physical_usb_device(
                pathlib.Path("/reviewed/adb.exe"),
                serial,
                attestation,
                devicecheck_build_receipt,
            )
        self.assertEqual(observed["hardware_identity_sha256"], hardware_sha256)
        self.assertEqual(observed["transport"], "usb")
        self.assertEqual(observed["transport_id"], "7")

    def test_transport_binding_rejects_reconnect_or_second_device(self) -> None:
        changed = subprocess.CompletedProcess(
            [],
            0,
            stdout=(
                "List of devices attached\n"
                "USBPHYSICAL1234 device usb:1-2 transport_id:8\n"
            ),
            stderr="",
        )
        with mock.patch.object(
            collector, "_bounded_subprocess_run", return_value=changed
        ):
            with self.assertRaisesRegex(collector.CollectorError, "stable physical"):
                collector._adb_transport_binding(
                    pathlib.Path("/reviewed/adb.exe"),
                    "USBPHYSICAL1234",
                    "7",
                )
        duplicate = subprocess.CompletedProcess(
            [],
            0,
            stdout=(
                "List of devices attached\n"
                "USBPHYSICAL1234 device usb:1-2 transport_id:7\n"
                "ATTACKER device usb:1-3 transport_id:9\n"
            ),
            stderr="",
        )
        with mock.patch.object(
            collector, "_bounded_subprocess_run", return_value=duplicate
        ):
            with self.assertRaisesRegex(collector.CollectorError, "exactly one"):
                collector._adb_transport_binding(
                    pathlib.Path("/reviewed/adb.exe"), "USBPHYSICAL1234"
                )

    def test_attestation_parser_rejects_runner_failure_and_lifecycle_drift(self) -> None:
        attestation_value = {
            "attested_key_id": collector._attested_key_id(
                format(RSA_FIXTURE_N, "x"), 65537
            ),
            "attested_rsa_modulus_hex": format(RSA_FIXTURE_N, "x"),
            "attested_rsa_public_exponent": 65537,
            "attestation_app_signer_sha256": collector.EXPECTED_SIGNER,
            "attestation_security_level": "tee",
            "attestation_leaf_certificate_sha256": "a" * 64,
            "attestation_challenge_sha256": "b" * 64,
        }
        output = _fixture_device_proof_output(
            b"n" * 32, attestation_value
        ).stdout
        lines = output.splitlines(keepends=True)
        start_end = lines.index("INSTRUMENTATION_STATUS_CODE: 1\n") + 1
        custom_end = lines.index("INSTRUMENTATION_STATUS_CODE: 0\n", start_end) + 1
        finish_end = lines.index("INSTRUMENTATION_STATUS_CODE: 0\n", custom_end) + 1
        start = "".join(lines[:start_end])
        custom = "".join(lines[start_end:custom_end])
        finish = "".join(lines[custom_end:finish_end])
        tail = "".join(lines[finish_end:])
        mutants = {
            "reordered custom block": custom + start + finish + tail,
            "post-proof test failure": output.replace(
                "INSTRUMENTATION_RESULT: stream=\n",
                "INSTRUMENTATION_STATUS: stack=java.lang.AssertionError\n"
                "INSTRUMENTATION_STATUS_CODE: -2\n"
                "INSTRUMENTATION_RESULT: stream=\n",
                1,
            ),
            "mixed custom and runner fields": output.replace(
                "INSTRUMENTATION_STATUS: winsvpn_attestation_report_b64=",
                f"INSTRUMENTATION_STATUS: class={collector.DEVICE_ATTESTATION_PROOF_CLASS}\n"
                "INSTRUMENTATION_STATUS: winsvpn_attestation_report_b64=",
                1,
            ),
            "missing runner stream": output.replace(
                "INSTRUMENTATION_STATUS: stream=\n", "", 1
            ),
            "unknown result": output.replace(
                "INSTRUMENTATION_RESULT: stream=\n",
                "INSTRUMENTATION_RESULT: unknown=unsafe\n",
                1,
            ),
            "duplicate result": output.replace(
                "INSTRUMENTATION_RESULT: stream=\n",
                "INSTRUMENTATION_RESULT: stream=\n"
                "INSTRUMENTATION_RESULT: stream=duplicate\n",
                1,
            ),
            "malformed result": output.replace(
                "INSTRUMENTATION_RESULT: stream=\n",
                "INSTRUMENTATION_RESULT stream=unsafe\n",
                1,
            ),
            "failure marker": output.replace(
                "INSTRUMENTATION_RESULT: stream=\n",
                "INSTRUMENTATION_FAILED: process crashed\n"
                "INSTRUMENTATION_RESULT: stream=\n",
                1,
            ),
        }
        for label, mutant in mutants.items():
            with self.subTest(label=label), self.assertRaisesRegex(
                collector.CollectorError,
                "ambiguous|schema|lifecycle|reported failure",
            ):
                collector._instrumentation_attestation_status(mutant)

    def test_attestation_parser_rejects_ordinary_failure_and_unbounded_custom_bundle(
        self,
    ) -> None:
        ordinary_failure = (
            f"INSTRUMENTATION_STATUS: class={collector.DEVICE_ATTESTATION_PROOF_CLASS}\n"
            "INSTRUMENTATION_STATUS: current=1\n"
            "INSTRUMENTATION_STATUS: id=AndroidJUnitRunner\n"
            "INSTRUMENTATION_STATUS: numtests=1\n"
            "INSTRUMENTATION_STATUS: stream=\n"
            f"INSTRUMENTATION_STATUS: test={collector.DEVICE_ATTESTATION_TEST_METHOD}\n"
            "INSTRUMENTATION_STATUS_CODE: 1\n"
            f"INSTRUMENTATION_STATUS: class={collector.DEVICE_ATTESTATION_PROOF_CLASS}\n"
            "INSTRUMENTATION_STATUS: current=1\n"
            "INSTRUMENTATION_STATUS: id=AndroidJUnitRunner\n"
            "INSTRUMENTATION_STATUS: numtests=1\n"
            "INSTRUMENTATION_STATUS: stack=java.lang.AssertionError: fixture failure\n"
            "INSTRUMENTATION_STATUS: stream=fixture failure\n"
            f"INSTRUMENTATION_STATUS: test={collector.DEVICE_ATTESTATION_TEST_METHOD}\n"
            "INSTRUMENTATION_STATUS_CODE: -2\n"
            "INSTRUMENTATION_RESULT: stream=\n"
            "INSTRUMENTATION_CODE: -1\n"
        )
        with self.assertRaisesRegex(
            collector.CollectorError, "ambiguous|lifecycle|reported failure"
        ):
            collector._instrumentation_attestation_status(ordinary_failure)

        attestation_value = {
            "attested_key_id": collector._attested_key_id(
                format(RSA_FIXTURE_N, "x"), 65537
            ),
            "attested_rsa_modulus_hex": format(RSA_FIXTURE_N, "x"),
            "attested_rsa_public_exponent": 65537,
            "attestation_app_signer_sha256": collector.EXPECTED_SIGNER,
            "attestation_security_level": "tee",
            "attestation_leaf_certificate_sha256": "a" * 64,
            "attestation_challenge_sha256": "b" * 64,
        }
        oversized = _fixture_device_proof_output(
            b"n" * 32, attestation_value
        ).stdout
        oversized = re.sub(
            r"(?m)^(INSTRUMENTATION_STATUS: winsvpn_attestation_report_b64=).*$",
            lambda match: match.group(1)
            + "A" * (collector.MAX_DEVICE_ATTESTATION_STATUS_BUNDLE_BYTES + 1),
            oversized,
        )
        with self.assertRaisesRegex(collector.CollectorError, "bounded|schema"):
            collector._instrumentation_attestation_status(oversized)

    def test_live_attestation_rejects_replayed_or_forged_signature(self) -> None:
        modulus_hex = format(RSA_FIXTURE_N, "x")
        key_id = collector._attested_key_id(modulus_hex, 65537)
        attestation = {
            "snapshot": {"sha256": "3" * 64},
            "value": {
                "hardware_identity_sha256": "4" * 64,
                "attested_key_id": key_id,
                "attested_rsa_modulus_hex": modulus_hex,
                "attested_rsa_public_exponent": 65537,
                "attestation_app_signer_sha256": collector.EXPECTED_SIGNER,
                "attestation_security_level": "tee",
                "attestation_leaf_certificate_sha256": "a" * 64,
                "attestation_challenge_sha256": "b" * 64,
            },
        }
        result = _fixture_device_proof_output(
            b"n" * 32,
            attestation["value"],
            signature_hex="0" * 512,
        )
        with mock.patch.object(
            collector, "_bounded_subprocess_run", return_value=result
        ), mock.patch.object(collector.secrets, "token_bytes", return_value=b"n" * 32):
            with self.assertRaisesRegex(collector.CollectorError, "prove possession"):
                collector._live_device_attestation_proof(
                    pathlib.Path("/reviewed/adb.exe"),
                    "7",
                    attestation,
                    phase="initial",
                    context_sha256="5" * 64,
                )

        uppercase = _fixture_device_proof_output(b"n" * 32, attestation["value"])
        uppercase.stdout = re.sub(
            r"(?m)^(INSTRUMENTATION_STATUS: winsvpn_attestation_signature_hex=)([0-9a-f]+)$",
            lambda match: match.group(1) + match.group(2).upper(),
            uppercase.stdout,
        )
        with mock.patch.object(
            collector, "_bounded_subprocess_run", return_value=uppercase
        ), mock.patch.object(collector.secrets, "token_bytes", return_value=b"n" * 32):
            with self.assertRaisesRegex(collector.CollectorError, "prove possession"):
                collector._live_device_attestation_proof(
                    pathlib.Path("/reviewed/adb.exe"),
                    "7",
                    attestation,
                    phase="initial",
                    context_sha256="5" * 64,
                )

        replay = _fixture_device_proof_output(b"n" * 32, attestation["value"])
        with mock.patch.object(
            collector, "_bounded_subprocess_run", return_value=replay
        ), mock.patch.object(collector.secrets, "token_bytes", return_value=b"r" * 32):
            with self.assertRaisesRegex(collector.CollectorError, "contradicts"):
                collector._live_device_attestation_proof(
                    pathlib.Path("/reviewed/adb.exe"),
                    "7",
                    attestation,
                    phase="initial",
                    context_sha256="5" * 64,
                )

    def test_live_attestation_rejects_status_zero_as_final_session_code(self) -> None:
        modulus_hex = format(RSA_FIXTURE_N, "x")
        key_id = collector._attested_key_id(modulus_hex, 65537)
        nonce = b"n" * 32
        attestation = {
            "snapshot": {"sha256": "3" * 64},
            "value": {
                "hardware_identity_sha256": "4" * 64,
                "attested_key_id": key_id,
                "attested_rsa_modulus_hex": modulus_hex,
                "attested_rsa_public_exponent": 65537,
                "attestation_app_signer_sha256": collector.EXPECTED_SIGNER,
                "attestation_security_level": "tee",
                "attestation_leaf_certificate_sha256": "a" * 64,
                "attestation_challenge_sha256": "b" * 64,
            },
        }
        result = _fixture_device_proof_output(
            nonce, attestation["value"], code=0
        )
        with mock.patch.object(
            collector, "_bounded_subprocess_run", return_value=result
        ), mock.patch.object(collector.secrets, "token_bytes", return_value=nonce):
            with self.assertRaisesRegex(collector.CollectorError, "prove possession"):
                collector._live_device_attestation_proof(
                    pathlib.Path("/reviewed/adb.exe"),
                    "7",
                    attestation,
                    phase="initial",
                    context_sha256="5" * 64,
                )

    def test_live_attestation_accepts_only_nonce_key_and_local_report(self) -> None:
        nonce = b"n" * 32
        modulus_hex = format(RSA_FIXTURE_N, "x")
        value = {
            "hardware_identity_sha256": "4" * 64,
            "attested_key_id": collector._attested_key_id(modulus_hex, 65537),
            "attested_rsa_modulus_hex": modulus_hex,
            "attested_rsa_public_exponent": 65537,
            "attestation_app_signer_sha256": collector.EXPECTED_SIGNER,
            "attestation_security_level": "tee",
            "attestation_leaf_certificate_sha256": "a" * 64,
            "attestation_challenge_sha256": "b" * 64,
        }
        result = _fixture_device_proof_output(nonce, value)
        with mock.patch.object(
            collector, "_bounded_subprocess_run", return_value=result
        ) as runner, mock.patch.object(
            collector.secrets, "token_bytes", return_value=nonce
        ):
            proof = collector._live_device_attestation_proof(
                pathlib.Path("/reviewed/adb.exe"),
                "7",
                {"snapshot": {"sha256": "3" * 64}, "value": value},
                phase="final",
                context_sha256="5" * 64,
            )
        argv = runner.call_args.args[0]
        self.assertIn("winsvpn_attestation_session_nonce", argv)
        self.assertIn(nonce.hex(), argv)
        self.assertIn("winsvpn_attestation_transcript_context_sha256", argv)
        self.assertIn("5" * 64, argv)
        self.assertNotIn("winsvpn_attestation_challenge_sha256", argv)
        self.assertEqual(proof["report_schema"], collector.DEVICE_ATTESTATION_REPORT_SCHEMA)
        self.assertRegex(proof["report_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(proof["target_base_apk_sha256"], "1" * 64)
        self.assertEqual(proof["target_base_apk_bytes"], "1048576")
        self.assertEqual(proof["test_apk_sha256"], "2" * 64)
        self.assertEqual(proof["test_apk_bytes"], "524288")

    def test_live_attestation_uses_exact_v4_context_signature_contract(self) -> None:
        self.assertEqual(
            collector.DEVICE_ATTESTATION_REPORT_SCHEMA,
            "winsvpn-android-live-hardware-attestation-evidence-v4",
        )
        self.assertEqual(
            collector.DEVICE_ATTESTATION_PROOF_DOMAIN,
            b"WINSVPN-ANDROID-LIVE-HARDWARE-ATTESTATION-EVIDENCE-V4\0",
        )
        self.assertEqual(
            collector.DEVICE_ATTESTATION_REPORT_FIELDS[:4],
            (
                "schema",
                "host_session_nonce",
                "transcript_context_sha256",
                "persistent_key_id",
            ),
        )
        source = (TOOLS_DIR / "android_final_evidence_collector.py").read_text(
            encoding="ascii"
        )
        self.assertIn("winsvpn_attestation_transcript_context_sha256", source)
        self.assertNotIn("winsvpn_attestation_transcript_sha256", source)

    def test_device_semantic_report_rejects_vpn_transport_contradictions(self) -> None:
        nonce = b"n" * 32
        modulus_hex = format(RSA_FIXTURE_N, "x")
        value = {
            "attested_key_id": collector._attested_key_id(modulus_hex, 65537),
            "attested_rsa_modulus_hex": modulus_hex,
            "attested_rsa_public_exponent": 65537,
            "attestation_app_signer_sha256": collector.EXPECTED_SIGNER,
            "attestation_security_level": "tee",
            "attestation_leaf_certificate_sha256": "a" * 64,
            "attestation_challenge_sha256": "b" * 64,
        }
        valid_vpn = {
            "network_count": "2",
            "active_network_transports": "wifi,vpn",
            "vpn_present": "true",
            "vpn_network_handle": "42",
            "vpn_interface_name_utf8_hex": b"wlan0".hex(),
            "vpn_link_address_count": "1",
            "vpn_route_count": "1",
            "vpn_dns_server_count": "1",
            "vpn_network_mtu": "1500",
            "vpn_endpoint_nonce_sha256": "8" * 64,
        }
        report = _fixture_device_semantic_report(
            nonce, value, overrides=valid_vpn
        )
        parsed = collector._parse_device_semantic_report(report)
        collector._validate_device_semantic_report(parsed, nonce, {"value": value}, "5" * 64)
        for field, replacement in (
            ("vpn_interface_name_utf8_hex", b"tun0".hex()),
            ("vpn_link_address_count", "2"),
            ("vpn_endpoint_nonce_sha256", "9" * 64),
        ):
            with self.subTest(field=field):
                contradicted = dict(valid_vpn)
                contradicted[field] = replacement
                parsed = collector._parse_device_semantic_report(
                    _fixture_device_semantic_report(
                        nonce, value, overrides=contradicted
                    )
                )
                with self.assertRaisesRegex(collector.CollectorError, "VPN endpoint"):
                    collector._validate_device_semantic_report(
                        parsed, nonce, {"value": value}, "5" * 64
                    )

    def test_live_attestation_rejects_transcript_or_apk_identity_drift(self) -> None:
        nonce = b"n" * 32
        modulus_hex = format(RSA_FIXTURE_N, "x")
        value = {
            "hardware_identity_sha256": "4" * 64,
            "attested_key_id": collector._attested_key_id(modulus_hex, 65537),
            "attested_rsa_modulus_hex": modulus_hex,
            "attested_rsa_public_exponent": 65537,
            "attestation_app_signer_sha256": collector.EXPECTED_SIGNER,
            "attestation_security_level": "tee",
            "attestation_leaf_certificate_sha256": "a" * 64,
            "attestation_challenge_sha256": "b" * 64,
        }
        for label, overrides in (
            ("transcript", {"transcript_context_sha256": "6" * 64}),
            ("same APK", {"test_apk_sha256": "1" * 64}),
            ("empty APK", {"target_base_apk_bytes": "0"}),
            ("oversized APK", {"test_apk_bytes": str(512 * 1024 * 1024 + 1)}),
        ):
            with self.subTest(label=label):
                result = _fixture_device_proof_output(
                    nonce,
                    value,
                    report_overrides=overrides,
                )
                with mock.patch.object(
                    collector, "_bounded_subprocess_run", return_value=result
                ), mock.patch.object(
                    collector.secrets, "token_bytes", return_value=nonce
                ):
                    with self.assertRaisesRegex(
                        collector.CollectorError, "contradicts|APK identity|out of range"
                    ):
                        collector._live_device_attestation_proof(
                            pathlib.Path("/reviewed/adb.exe"),
                            "7",
                            {"snapshot": {"sha256": "3" * 64}, "value": value},
                            phase="final",
                            context_sha256="5" * 64,
                        )

    def test_live_attestation_rejects_validly_signed_semantic_drift(self) -> None:
        nonce = b"n" * 32
        modulus_hex = format(RSA_FIXTURE_N, "x")
        value = {
            "hardware_identity_sha256": "4" * 64,
            "attested_key_id": collector._attested_key_id(modulus_hex, 65537),
            "attested_rsa_modulus_hex": modulus_hex,
            "attested_rsa_public_exponent": 65537,
            "attestation_app_signer_sha256": collector.EXPECTED_SIGNER,
            "attestation_security_level": "tee",
            "attestation_leaf_certificate_sha256": "a" * 64,
            "attestation_challenge_sha256": "b" * 64,
        }
        result = _fixture_device_proof_output(
            nonce,
            value,
            report_overrides={"target_signer_sha256": "0" * 64},
        )
        with mock.patch.object(
            collector, "_bounded_subprocess_run", return_value=result
        ), mock.patch.object(collector.secrets, "token_bytes", return_value=nonce):
            with self.assertRaisesRegex(collector.CollectorError, "contradicts"):
                collector._live_device_attestation_proof(
                    pathlib.Path("/reviewed/adb.exe"),
                    "7",
                    {"snapshot": {"sha256": "3" * 64}, "value": value},
                    phase="initial",
                    context_sha256="5" * 64,
                )

    def test_live_attestation_rejects_old_or_extra_status_fields(self) -> None:
        nonce = b"n" * 32
        modulus_hex = format(RSA_FIXTURE_N, "x")
        value = {
            "attested_key_id": collector._attested_key_id(modulus_hex, 65537),
            "attested_rsa_modulus_hex": modulus_hex,
            "attested_rsa_public_exponent": 65537,
            "attestation_app_signer_sha256": collector.EXPECTED_SIGNER,
            "attestation_security_level": "tee",
            "attestation_leaf_certificate_sha256": "a" * 64,
            "attestation_challenge_sha256": "b" * 64,
        }
        result = _fixture_device_proof_output(nonce, value)
        result.stdout = result.stdout.replace(
            "INSTRUMENTATION_CODE: -1\n",
            f"INSTRUMENTATION_STATUS: winsvpn_attestation_challenge_sha256={'c' * 64}\n"
            "INSTRUMENTATION_CODE: -1\n",
        )
        with mock.patch.object(
            collector, "_bounded_subprocess_run", return_value=result
        ), mock.patch.object(collector.secrets, "token_bytes", return_value=nonce):
            with self.assertRaisesRegex(
                collector.CollectorError, "status (?:schema|is ambiguous)"
            ):
                collector._live_device_attestation_proof(
                    pathlib.Path("/reviewed/adb.exe"),
                    "7",
                    {"snapshot": {"sha256": "3" * 64}, "value": value},
                    phase="initial",
                    context_sha256="5" * 64,
                )

    def test_live_attestation_requires_one_custom_status_code_zero(self) -> None:
        nonce = b"n" * 32
        modulus_hex = format(RSA_FIXTURE_N, "x")
        value = {
            "attested_key_id": collector._attested_key_id(modulus_hex, 65537),
            "attested_rsa_modulus_hex": modulus_hex,
            "attested_rsa_public_exponent": 65537,
            "attestation_app_signer_sha256": collector.EXPECTED_SIGNER,
            "attestation_security_level": "tee",
            "attestation_leaf_certificate_sha256": "a" * 64,
            "attestation_challenge_sha256": "b" * 64,
        }
        for status_mutation in (
            lambda output: output.replace("INSTRUMENTATION_STATUS_CODE: 0\n", ""),
            lambda output: output.replace(
                "INSTRUMENTATION_STATUS_CODE: 0\n",
                "INSTRUMENTATION_STATUS_CODE: 1\n",
            ),
            lambda output: output.replace(
                "INSTRUMENTATION_CODE: -1\n",
                "INSTRUMENTATION_STATUS: winsvpn_attestation_schema="
                f"{collector.DEVICE_ATTESTATION_REPORT_SCHEMA}\n"
                "INSTRUMENTATION_STATUS_CODE: 0\n"
                "INSTRUMENTATION_CODE: -1\n",
            ),
        ):
            result = _fixture_device_proof_output(nonce, value)
            result.stdout = status_mutation(result.stdout)
            with mock.patch.object(
                collector, "_bounded_subprocess_run", return_value=result
            ), mock.patch.object(
                collector.secrets, "token_bytes", return_value=nonce
            ):
                with self.assertRaisesRegex(
                    collector.CollectorError,
                    "(?:status (?:schema|is ambiguous)|runner lifecycle)",
                ):
                    collector._live_device_attestation_proof(
                        pathlib.Path("/reviewed/adb.exe"),
                        "7",
                        {"snapshot": {"sha256": "3" * 64}, "value": value},
                        phase="initial",
                        context_sha256="5" * 64,
                    )

    def test_device_semantic_report_rejects_order_and_duplicate_drift(self) -> None:
        nonce = b"n" * 32
        modulus_hex = format(RSA_FIXTURE_N, "x")
        value = {
            "attested_key_id": collector._attested_key_id(modulus_hex, 65537),
            "attested_rsa_modulus_hex": modulus_hex,
            "attested_rsa_public_exponent": 65537,
            "attestation_app_signer_sha256": collector.EXPECTED_SIGNER,
            "attestation_security_level": "tee",
            "attestation_leaf_certificate_sha256": "a" * 64,
            "attestation_challenge_sha256": "b" * 64,
        }
        lines = _fixture_device_semantic_report(nonce, value).splitlines(keepends=True)
        lines[0], lines[1] = lines[1], lines[0]
        with self.assertRaisesRegex(collector.CollectorError, "order"):
            collector._parse_device_semantic_report(b"".join(lines))
        lines = _fixture_device_semantic_report(nonce, value).splitlines(keepends=True)
        lines[1] = lines[0]
        with self.assertRaisesRegex(collector.CollectorError, "order|duplicate"):
            collector._parse_device_semantic_report(b"".join(lines))

    def test_final_attestation_proof_binds_complete_held_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            evidence = root / "machine-evidence.json"
            collector._write_exact_bytes(evidence, b'{"passed":true}\n')
            physical = {
                "serial_sha256": "1" * 64,
                "hardware_identity_sha256": "2" * 64,
                "transport": "usb",
                "usb": "usb:1-2",
                "transport_id": "7",
            }
            attestation = {
                "snapshot": {"sha256": "3" * 64},
                "value": {"attested_key_id": "4" * 64},
            }
            devicecheck_build_receipt = {
                "snapshot": {"sha256": "a" * 64},
                "value": {
                    "consumer_status": collector.DEVICECHECK_SOURCE_CONSUMER_STATUS,
                    "source_closure": {"inventory_sha256": "b" * 64},
                },
                "target": {"sha256": "8" * 64, "bytes": 1048576},
                "android_test": {"sha256": "9" * 64, "bytes": 524288},
            }
            observed_contexts: list[str] = []

            def fake_proof(*_args, **kwargs):
                observed_contexts.append(kwargs["context_sha256"])
                return {
                    "nonce_sha256": "5" * 64,
                    "report_schema": collector.DEVICE_ATTESTATION_REPORT_SCHEMA,
                    "report_sha256": "6" * 64,
                    "report_b64": "Zml4dHVyZS1yZXBvcnQK",
                    "target_base_apk_sha256": "8" * 64,
                    "target_base_apk_bytes": "1048576",
                    "test_apk_sha256": "9" * 64,
                    "test_apk_bytes": "524288",
                    "attested_key_id": "4" * 64,
                    "signature_hex": "7" * 512,
                }

            with mock.patch.object(
                collector,
                "_adb_transport_binding",
                return_value={"listed_usb": "1-2", "transport_id": "7"},
            ), mock.patch.object(
                collector, "_live_device_attestation_proof", side_effect=fake_proof
            ):
                name, digest = collector._finalize_device_transcript_proof(
                    root,
                    pathlib.Path("/reviewed/adb.exe"),
                    "USBPHYSICAL1234",
                    physical,
                    attestation,
                    devicecheck_build_receipt,
                )
            self.assertEqual(name, "physical-device-final-proof.json")
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertEqual(len(observed_contexts), 1)
            expected_transcript = {
                "contract": "winsvpn-android-device-evidence-transcript-v1",
                "serial_sha256": physical["serial_sha256"],
                "hardware_identity_sha256": physical["hardware_identity_sha256"],
                "transport": physical["transport"],
                "usb": physical["usb"],
                "transport_id": physical["transport_id"],
                "devicecheck_custody": collector._devicecheck_custody_context(
                    devicecheck_build_receipt
                ),
                "files": [
                    {
                        "path": evidence.name,
                        "sha256": hashlib.sha256(b'{"passed":true}\n').hexdigest(),
                        "size_bytes": len(b'{"passed":true}\n'),
                    }
                ],
            }
            self.assertEqual(
                observed_contexts[0],
                hashlib.sha256(
                    collector._canonical_json_bytes(
                        expected_transcript, "fixture final transcript"
                    )
                ).hexdigest(),
            )
            proof = json.loads((root / name).read_text(encoding="utf-8"))
            self.assertEqual(proof["transcript_sha256"], observed_contexts[0])
            self.assertEqual(proof["transcript_file_count"], 1)
            self.assertEqual(
                proof["semantic_report_schema"],
                collector.DEVICE_ATTESTATION_REPORT_SCHEMA,
            )
            evidence.write_bytes(b'{"passed":false}\n')
            with self.assertRaisesRegex(collector.CollectorError, "identity changed|bytes changed"):
                collector._reaudit_evidence_holds(root)
            collector._close_evidence_holds(root)

    def test_final_attestation_proof_rejects_devicecheck_producer_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            collector._write_exact_bytes(root / "machine-evidence.json", b"{}\n")
            physical = {
                "serial_sha256": "1" * 64,
                "hardware_identity_sha256": "2" * 64,
                "transport": "usb",
                "usb": "usb:1-2",
                "transport_id": "7",
            }
            attestation = {
                "snapshot": {"sha256": "3" * 64},
                "value": {"attested_key_id": "4" * 64},
            }
            producer = {
                "snapshot": {"sha256": "a" * 64},
                "value": {
                    "consumer_status": collector.DEVICECHECK_SOURCE_CONSUMER_STATUS,
                    "source_closure": {"inventory_sha256": "b" * 64},
                },
                "target": {"sha256": "8" * 64, "bytes": 64},
                "android_test": {"sha256": "9" * 64, "bytes": 32},
            }
            proof = {
                "nonce_sha256": "5" * 64,
                "report_schema": collector.DEVICE_ATTESTATION_REPORT_SCHEMA,
                "report_sha256": "6" * 64,
                "report_b64": "Zml4dHVyZQo=",
                "target_base_apk_sha256": "8" * 64,
                "target_base_apk_bytes": "65",
                "test_apk_sha256": "9" * 64,
                "test_apk_bytes": "32",
                "attested_key_id": "4" * 64,
                "signature_hex": "7" * 512,
            }
            try:
                with mock.patch.object(
                    collector,
                    "_adb_transport_binding",
                    return_value={"listed_usb": "1-2", "transport_id": "7"},
                ), mock.patch.object(
                    collector,
                    "_live_device_attestation_proof",
                    return_value=proof,
                ):
                    with self.assertRaisesRegex(
                        collector.CollectorError, "contradict producer custody"
                    ):
                        collector._finalize_device_transcript_proof(
                            root,
                            pathlib.Path("/reviewed/adb.exe"),
                            "USBPHYSICAL1234",
                            physical,
                            attestation,
                            producer,
                        )
            finally:
                collector._close_evidence_holds(root)

    def test_bounded_subprocess_kills_before_post_output_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            marker = pathlib.Path(temp_name) / "post-output-marker"
            code = (
                "import os,pathlib;"
                "os.write(1,b'x'*(2*1024*1024));"
                f"pathlib.Path({str(marker)!r}).write_text('unsafe')"
            )
            with self.assertRaisesRegex(collector.CollectorError, "output limit"):
                collector._bounded_subprocess_run(
                    [sys.executable, "-c", code],
                    text=True,
                    timeout=30,
                    stdout_limit=1024,
                    stderr_limit=1024,
                )
            self.assertFalse(marker.exists())

    @unittest.skipIf(os.name == "nt", "POSIX process groups are required")
    def test_bounded_subprocess_kills_surviving_descendant_after_leader_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            marker = root / "surviving-descendant-marker"
            ready = root / "surviving-descendant-ready"
            descendant = (
                "import pathlib,sys,time;"
                "pathlib.Path(sys.argv[1]).write_text('ready');"
                "time.sleep(1);"
                "pathlib.Path(sys.argv[2]).write_text('unsafe');"
                "time.sleep(30)"
            )
            leader = (
                "import pathlib,subprocess,sys,time;"
                "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2],sys.argv[3]]);"
                "p=pathlib.Path(sys.argv[2]);"
                "deadline=time.monotonic()+5;"
                "exec(\"while not p.exists():\\n"
                " if time.monotonic()>=deadline: raise SystemExit(8)\\n"
                " time.sleep(0.01)\")"
            )
            result = collector._bounded_subprocess_run(
                [sys.executable, "-c", leader, descendant, str(ready), str(marker)],
                text=True,
                timeout=10,
                stdout_limit=1024,
                stderr_limit=1024,
            )
            self.assertEqual(result.returncode, 0)
            self.assertTrue(ready.is_file())
            time.sleep(1.2)
            self.assertFalse(marker.exists())

    def test_evidence_hold_rejects_pathname_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            path = root / "receipt.json"
            collector._write_exact_bytes(path, b'{"passed":true}\n')
            replacement = root / "replacement.json"
            replacement.write_bytes(path.read_bytes())
            os.replace(replacement, path)
            try:
                with self.assertRaisesRegex(collector.CollectorError, "identity changed"):
                    collector._reaudit_evidence_holds(root)
            finally:
                collector._close_evidence_holds(root)

    def test_ui_semantic_lookup_and_tap_use_control_bounds(self) -> None:
        driver = self.driver()
        xml = '<hierarchy><node class="android.widget.Switch" content-desc="Double VPN\nDetails" checked="true" checkable="true" bounds="[100,200][300,400]" /></hierarchy>'
        driver.xml_text = lambda: xml  # type: ignore[method-assign]
        calls: list[list[str]] = []
        driver.adb_run = lambda args, **kwargs: calls.append(args) or ""  # type: ignore[method-assign]
        node = driver.find("Double VPN", class_name="android.widget.Switch")
        self.assertIsNotNone(node)
        driver.tap(node)
        self.assertEqual(calls[-1][-2:], ["200", "300"])

    def test_runtime_requires_real_tun_service_xray_and_dns_sources(self) -> None:
        driver = self.driver()
        def fake(args, **kwargs):
            joined = " ".join(args)
            if "/proc/net/dev" in joined:
                return " tun0: 4096 1 1 1 1 1 1 1 2048 1 1 1 1 1 1 1\n"
            if "activity services" in joined:
                return "org.winsvpn.app/.VpnTunnelService"
            if "ps -A" in joined:
                return "u0_a1 2 1 libxray.so"
            if "connectivity" in joined:
                return (
                    "  NetworkAgentInfo{network{130} ni{VPN CONNECTED extra: "
                    "VPN:org.winsvpn.app} lp{{InterfaceName: tun0 "
                    "DnsAddresses: [ /10.8.1.1 ]}} nc{[ Transports: WIFI|VPN "
                    "Capabilities: INTERNET&VALIDATED]}}\n"
                )
            return ""
        driver.adb_run = fake  # type: ignore[method-assign]
        runtime = driver.runtime()
        self.assertEqual(runtime, Runtime(True, 4096, 2048, True, True, True, True, ("10.8.1.1",)))

    def test_runtime_does_not_treat_not_vpn_as_a_vpn_transport(self) -> None:
        driver = self.driver()
        def fake(args, **kwargs):
            joined = " ".join(args)
            if "connectivity" in joined:
                return (
                    "  NetworkAgentInfo{network{104} ni{WIFI CONNECTED} "
                    "lp{{InterfaceName: wlan0 DnsAddresses: [ /192.168.50.1 ]}} "
                    "nc{[ Transports: WIFI Capabilities: INTERNET&NOT_VPN&VALIDATED]}}\n"
                    "  NetworkRequest [ LISTEN id=11, [ Transports: VPN "
                    "Capabilities: TRUSTED RequestorPkg: android] ]\n"
                )
            return ""
        driver.adb_run = fake  # type: ignore[method-assign]
        runtime = driver.runtime()
        self.assertFalse(runtime.vpn_network_present)
        self.assertFalse(runtime.vpn_validated)
        self.assertEqual(runtime.dns_servers, ())


class FormFactorClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = FormFactorManifestFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def build(self, preflight: dict | None = None, symbols: dict[str, str] | None = None) -> dict:
        return collector.build_form_factor_closure(
            self.fixture.repo,
            self.fixture.output,
            self.fixture.packages,
            symbols if symbols is not None else self.fixture.symbols(),
            self.fixture.app_version,
            preflight if preflight is not None else self.fixture.preflight(),
            self.fixture.captured,
        )

    def test_devicecheck_build_receipt_is_owner_bound_and_source_current(self) -> None:
        preflight = self.fixture.preflight()
        devicecheck = preflight["devicecheck_build_receipt"]
        self.assertEqual(
            devicecheck["value"]["consumer_status"],
            collector.DEVICECHECK_SOURCE_CONSUMER_STATUS,
        )
        self.assertEqual(
            devicecheck["snapshot"]["sha256"],
            self.fixture.devicecheck_build_receipt_sha256,
        )
        self.assertEqual(
            devicecheck["target"]["sha256"],
            hashlib.sha256(self.fixture.devicecheck_target_bytes).hexdigest(),
        )
        self.assertEqual(
            preflight["owner_authorization"]["value"]
            ["devicecheck_build_receipt"]["receipt_sha256"],
            self.fixture.devicecheck_build_receipt_sha256,
        )
        self.assertEqual(
            preflight["owner_authorization"]["value"]
            ["devicecheck_build_receipt"]["consumer_status"],
            collector.DEVICECHECK_SOURCE_CONSUMER_STATUS,
        )
        self.assertEqual(
            collector._devicecheck_custody_context(devicecheck)["consumer_status"],
            collector.DEVICECHECK_SOURCE_CONSUMER_STATUS,
        )

    def test_collector_rejects_stale_unintegrated_production_receipt(self) -> None:
        receipt_path = self.fixture.devicecheck_build_receipt
        pristine_value = json.loads(receipt_path.read_text(encoding="utf-8"))
        pristine_authorization = self.fixture.authorization_payload()
        build_script_path = "android/devicecheck/build_devicecheck.sh"
        build_script = self.fixture.repo / build_script_path
        source_custody_path = "android/devicecheck/devicecheck_source_custody.py"
        source_custody = self.fixture.repo / source_custody_path
        integrated_source_custody = source_custody.read_bytes()
        unintegrated_source_custody = integrated_source_custody.replace(
            b'CONSUMER_STATUS = "integrated"',
            b'CONSUMER_STATUS = "unintegrated"',
        )
        markers = (
            b"# DEVICECHECK_PRODUCER_DISABLED=immutable-compiler-input-v1\n",
            b'SOURCE_CONSUMER_STATUS="unintegrated"\n',
            b"echo 'OWNER-BLOCKED: immutable compiler-input handoff is not implemented'\n",
        )

        def reissue(
            value: dict,
            *,
            build_script_raw: bytes,
            source_custody_raw: bytes,
            owner_status: object = "integrated",
            owner_status_present: bool = True,
            duplicate_status: bool = False,
        ) -> None:
            build_script.write_bytes(build_script_raw)
            source_custody.write_bytes(source_custody_raw)
            inventory = value["source_closure"]["inventory"]
            for relative, path in (
                (build_script_path, build_script),
                (source_custody_path, source_custody),
            ):
                record = next(item for item in inventory if item["path"] == relative)
                record.update(
                    {"bytes": path.stat().st_size, "sha256": self.fixture.sha(path)}
                )
                for role, producer_record in value["producer"].items():
                    if producer_record["path"] == relative:
                        value["producer"][role] = dict(record)
            inventory_sha256 = hashlib.sha256(
                collector._canonical_json_bytes(
                    inventory, "hostile DeviceCheck source inventory"
                )
                + b"\n"
            ).hexdigest()
            value["source_closure"]["inventory_sha256"] = inventory_sha256
            value["source_transaction"]["prebuild_source_inventory_sha256"] = (
                inventory_sha256
            )
            value["source_transaction"]["source_snapshot"] = (
                collector.DEVICECHECK_SOURCE_SNAPSHOT_PREFIX + inventory_sha256
            )
            self.fixture.write_json(receipt_path, value)
            if duplicate_status:
                raw = receipt_path.read_text(encoding="utf-8")
                receipt_path.write_text(
                    raw.replace(
                        '  "consumer_status": "integrated",\n',
                        '  "consumer_status": "integrated",\n'
                        '  "consumer_status": "integrated",\n',
                        1,
                    ),
                    encoding="utf-8",
                )
            self.fixture.devicecheck_build_receipt_sha256 = self.fixture.sha(receipt_path)
            self.fixture.devicecheck_source_inventory_sha256 = inventory_sha256
            receipt_path.with_name(receipt_path.name + ".sha256").write_text(
                f"{self.fixture.devicecheck_build_receipt_sha256}  "
                "DEVICECHECK_BUILD_RECEIPT.json\n",
                encoding="ascii",
            )
            authorization = json.loads(json.dumps(pristine_authorization))
            authorization["devicecheck_build_receipt"]["receipt_sha256"] = (
                self.fixture.devicecheck_build_receipt_sha256
            )
            authorization["devicecheck_build_receipt"]["source_inventory_sha256"] = (
                inventory_sha256
            )
            if owner_status_present:
                authorization["devicecheck_build_receipt"][
                    "consumer_status"
                ] = owner_status
            else:
                authorization["devicecheck_build_receipt"].pop("consumer_status")
            self.fixture.write_authorization(authorization)

        for marker_count in range(4):
            with self.subTest(unintegrated_marker_count=marker_count):
                value = json.loads(json.dumps(pristine_value))
                value["consumer_status"] = "unintegrated"
                reissue(
                    value,
                    build_script_raw=(
                        b"active-build-script\n" + b"".join(markers[:marker_count])
                    ),
                    source_custody_raw=unintegrated_source_custody,
                    owner_status="unintegrated",
                )
                with self.assertRaisesRegex(
                    collector.CollectorError,
                    "OWNER-BLOCKED: DeviceCheck source-custody consumer is not integrated",
                ):
                    self.fixture.preflight()

        hostile_statuses = (
            ("missing", None, False, False),
            ("malformed", 7, True, False),
            ("unknown", "future-integrated", True, False),
            ("duplicate", "integrated", True, True),
        )
        for label, status, present, duplicate in hostile_statuses:
            with self.subTest(status=label):
                value = json.loads(json.dumps(pristine_value))
                if present:
                    value["consumer_status"] = status
                else:
                    value.pop("consumer_status")
                reissue(
                    value,
                    build_script_raw=b"active-build-script\n",
                    source_custody_raw=integrated_source_custody,
                    owner_status=status,
                    owner_status_present=present,
                    duplicate_status=duplicate,
                )
                with self.assertRaises(collector.CollectorError):
                    self.fixture.preflight()

    def test_rejects_wrong_or_reauthorized_forged_devicecheck_receipt(self) -> None:
        with self.assertRaisesRegex(collector.CollectorError, "receipt changed"):
            collector._devicecheck_build_receipt(
                self.fixture.repo,
                self.fixture.devicecheck_build_receipt,
                "0" * 64,
                {},
                **self.fixture.devicecheck_owner_pins(),
            )
        payload = json.loads(
            self.fixture.devicecheck_build_receipt.read_text(encoding="utf-8")
        )
        payload["artifacts"]["target"]["sha256"] = "e" * 64
        self.fixture.write_json(self.fixture.devicecheck_build_receipt, payload)
        self.fixture.devicecheck_build_receipt_sha256 = self.fixture.sha(
            self.fixture.devicecheck_build_receipt
        )
        self.fixture.devicecheck_build_receipt.with_name(
            self.fixture.devicecheck_build_receipt.name + ".sha256"
        ).write_text(
            f"{self.fixture.devicecheck_build_receipt_sha256}  "
            "DEVICECHECK_BUILD_RECEIPT.json\n",
            encoding="ascii",
        )
        with self.assertRaisesRegex(
            collector.CollectorError,
            "APK producer receipt contradicts owner custody",
        ):
            self.fixture.preflight()

    def test_rejects_devicecheck_v2_top_level_transaction_and_identity_drift(self) -> None:
        original = json.loads(
            self.fixture.devicecheck_build_receipt.read_text(encoding="utf-8")
        )
        cases = (
            (
                "owner signer",
                lambda value: value["owner_signer"].__setitem__(
                    "certificate_sha256", "8" * 64
                ),
            ),
            (
                "source transaction",
                lambda value: value["source_transaction"].__setitem__(
                    "prebuild_source_inventory_sha256", "8" * 64
                ),
            ),
            (
                "artifact (?:fields|identity)",
                lambda value: value["artifacts"]["target"]["identity"].pop("flags"),
            ),
        )
        for expected, mutate in cases:
            with self.subTest(expected=expected):
                payload = json.loads(json.dumps(original))
                mutate(payload)
                self.fixture.write_json(self.fixture.devicecheck_build_receipt, payload)
                digest = self.fixture.sha(self.fixture.devicecheck_build_receipt)
                self.fixture.devicecheck_build_receipt.with_name(
                    self.fixture.devicecheck_build_receipt.name + ".sha256"
                ).write_text(
                    f"{digest}  DEVICECHECK_BUILD_RECEIPT.json\n", encoding="ascii"
                )
                with self.assertRaisesRegex(collector.CollectorError, expected):
                    collector._devicecheck_build_receipt(
                        self.fixture.repo,
                        self.fixture.devicecheck_build_receipt,
                        digest,
                        {},
                        **self.fixture.devicecheck_owner_pins(),
                    )

    def test_rejects_legacy_source_snapshot_and_stale_producer_closure(self) -> None:
        original = json.loads(
            self.fixture.devicecheck_build_receipt.read_text(encoding="utf-8")
        )
        cases = (
            (
                "current content-addressed source custody",
                lambda value: value["source_transaction"].__setitem__(
                    "source_snapshot",
                    "/Library/WinsVPN/ReleaseAndroidSource/devicecheck-v2/source",
                ),
            ),
            (
                "producer closure",
                lambda value: value["producer"].pop("source_custody"),
            ),
            (
                "producer closure",
                lambda value: value["producer"].pop(
                    "source_custody_contract_test"
                ),
            ),
        )
        for expected, mutate in cases:
            with self.subTest(expected=expected):
                payload = json.loads(json.dumps(original))
                mutate(payload)
                self.fixture.write_json(self.fixture.devicecheck_build_receipt, payload)
                digest = self.fixture.sha(self.fixture.devicecheck_build_receipt)
                self.fixture.devicecheck_build_receipt.with_name(
                    self.fixture.devicecheck_build_receipt.name + ".sha256"
                ).write_text(
                    f"{digest}  DEVICECHECK_BUILD_RECEIPT.json\n",
                    encoding="ascii",
                )
                with self.assertRaisesRegex(collector.CollectorError, expected):
                    collector._devicecheck_build_receipt(
                        self.fixture.repo,
                        self.fixture.devicecheck_build_receipt,
                        digest,
                        {},
                        **self.fixture.devicecheck_owner_pins(),
                    )

    def test_rejects_duplicate_or_nonfinite_devicecheck_v2_json(self) -> None:
        original = self.fixture.devicecheck_build_receipt.read_text(encoding="ascii")
        hostile_values = (
            original.replace(
                '  "schema_version": 2,',
                '  "schema_version": 2,\n  "schema_version": 2,',
                1,
            ),
            re.sub(r'("expires_unix_ns": )\d+', r'\1NaN', original, count=1),
        )
        for hostile in hostile_values:
            with self.subTest(kind="duplicate" if "schema_version\n" in hostile else "nonfinite"):
                self.fixture.devicecheck_build_receipt.write_text(
                    hostile, encoding="ascii"
                )
                digest = self.fixture.sha(self.fixture.devicecheck_build_receipt)
                self.fixture.devicecheck_build_receipt.with_name(
                    self.fixture.devicecheck_build_receipt.name + ".sha256"
                ).write_text(
                    f"{digest}  DEVICECHECK_BUILD_RECEIPT.json\n", encoding="ascii"
                )
                with self.assertRaisesRegex(
                    collector.CollectorError, "strict UTF-8 JSON"
                ):
                    collector._devicecheck_build_receipt(
                        self.fixture.repo,
                        self.fixture.devicecheck_build_receipt,
                        digest,
                        {},
                        **self.fixture.devicecheck_owner_pins(),
                    )

    def test_rejects_local_devicecheck_apk_or_owner_pin_substitution(self) -> None:
        with self.assertRaisesRegex(
            collector.CollectorError, "APK producer receipt contradicts owner custody"
        ):
            collector._devicecheck_build_receipt(
                self.fixture.repo,
                self.fixture.devicecheck_build_receipt,
                self.fixture.devicecheck_build_receipt_sha256,
                {},
                **{
                    **self.fixture.devicecheck_owner_pins(),
                    "expected_target_apk_sha256": "9" * 64,
                },
            )

        target = self.fixture.repo / (
            "android/devicecheck/app/build/outputs/apk/release/app-release.apk"
        )
        original = target.read_bytes()
        try:
            target.write_bytes(original + b"substituted")
            with self.assertRaisesRegex(
                collector.CollectorError,
                "locally held DeviceCheck APK contradicts producer custody",
            ):
                collector._devicecheck_build_receipt(
                    self.fixture.repo,
                    self.fixture.devicecheck_build_receipt,
                    self.fixture.devicecheck_build_receipt_sha256,
                    {},
                    **self.fixture.devicecheck_owner_pins(),
                )
        finally:
            target.write_bytes(original)

    def test_rejects_legacy_owner_authorization_without_devicecheck_v2_binding(
        self,
    ) -> None:
        payload = self.fixture.authorization_payload()
        payload["schema_version"] = 1
        self.fixture.write_authorization(payload)
        with self.assertRaisesRegex(
            collector.CollectorError, "owner authorization contradicts"
        ):
            self.fixture.preflight()

    def test_rejects_devicecheck_source_omission_and_post_preflight_drift(self) -> None:
        preflight = self.fixture.preflight()
        source = (
            self.fixture.repo
            / "android/devicecheck/test_live_hardware_attestation_proof.py"
        )
        source_bytes = source.read_bytes()
        source.write_bytes(source_bytes + b"# drift\n")
        with self.assertRaisesRegex(
            collector.CollectorError, "form-factor evidence changed"
        ):
            collector._reaudit_form_factor_snapshots(
                self.fixture.repo, preflight
            )
        source.write_bytes(source_bytes)

        payload = json.loads(
            self.fixture.devicecheck_build_receipt.read_text(encoding="utf-8")
        )
        payload["source_closure"]["inventory"] = [
            item
            for item in payload["source_closure"]["inventory"]
            if item["path"]
            != "android/devicecheck/test_devicecheck_build_receipt.py"
        ]
        payload["source_closure"]["inventory_sha256"] = hashlib.sha256(
            collector._canonical_json_bytes(
                payload["source_closure"]["inventory"],
                "hostile DeviceCheck inventory",
            )
            + b"\n"
        ).hexdigest()
        self.fixture.write_json(self.fixture.devicecheck_build_receipt, payload)
        digest = self.fixture.sha(self.fixture.devicecheck_build_receipt)
        self.fixture.devicecheck_build_receipt.with_name(
            self.fixture.devicecheck_build_receipt.name + ".sha256"
        ).write_text(
            f"{digest}  DEVICECHECK_BUILD_RECEIPT.json\n", encoding="ascii"
        )
        with self.assertRaisesRegex(
            collector.CollectorError, "source inventory contradicts owner custody"
        ):
            collector._devicecheck_build_receipt(
                self.fixture.repo,
                self.fixture.devicecheck_build_receipt,
                digest,
                {},
                **self.fixture.devicecheck_owner_pins(),
            )

    def test_rejects_devicecheck_unsealed_toolchain_contract(self) -> None:
        original = self.fixture.devicecheck_build_receipt.read_bytes()
        for mutation in ("missing-java", "ambient-environment", "wrong-java-root"):
            with self.subTest(mutation=mutation):
                payload = json.loads(original.decode("utf-8"))
                if mutation == "missing-java":
                    del payload["toolchain"]["java"]
                elif mutation == "ambient-environment":
                    payload["toolchain"]["execution"]["environment"] = "ambient"
                else:
                    payload["toolchain"]["java_root"] = "/tmp/attacker-jdk"
                self.fixture.write_json(self.fixture.devicecheck_build_receipt, payload)
                digest = self.fixture.sha(self.fixture.devicecheck_build_receipt)
                self.fixture.devicecheck_build_receipt.with_name(
                    self.fixture.devicecheck_build_receipt.name + ".sha256"
                ).write_text(
                    f"{digest}  DEVICECHECK_BUILD_RECEIPT.json\n",
                    encoding="ascii",
                )
                with self.assertRaisesRegex(
                    collector.CollectorError, "Build Tools custody"
                ):
                    collector._devicecheck_build_receipt(
                        self.fixture.repo,
                        self.fixture.devicecheck_build_receipt,
                        digest,
                        {},
                        **self.fixture.devicecheck_owner_pins(),
                    )
        self.fixture.devicecheck_build_receipt.write_bytes(original)

    def test_imports_exact_indexed_eight_descriptor_matrix(self) -> None:
        preflight = self.fixture.preflight()
        closure = self.build(preflight)
        self.assertEqual(set(closure["form_factor_matrix"]), {"phone", "tv", "wear"})
        self.assertEqual(closure["form_factor_matrix"]["phone"]["version_code"], 30)
        self.assertEqual(closure["form_factor_matrix"]["tv"]["version_code"], 3002)
        self.assertEqual(closure["form_factor_matrix"]["wear"]["version_code"], 3001)
        self.assertEqual(
            closure["form_factor_matrix"]["phone"]["runtime"]["kind"], "live_vpn"
        )
        self.assertEqual(
            closure["form_factor_matrix"]["wear"]["runtime"]["kind"], "pairing_runtime"
        )
        self.assertTrue(closure["mapping_owner_blocked"])
        self.assertEqual(
            set(closure["private_symbol_mapping_sha256"]),
            {"android-apk", "android-aab", "android-tv-apk", "android-tv-aab", "wear-os"},
        )
        phone_source = self.fixture.manifest_dir / "sources/phone-runtime/receipt.json"
        self.assertEqual((self.fixture.output / "phone-runtime.json").read_bytes(), phone_source.read_bytes())
        relocation = json.loads(
            (self.fixture.output / "phone-runtime-source-relocation.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(relocation["source_index_path"], "phone-runtime-source-index.json")
        self.assertEqual(relocation["files"][0]["source_path"], "receipt.json")
        self.assertEqual(relocation["files"][0]["imported_path"], "phone-runtime.json")
        self.assertEqual(
            relocation["files"][0]["source_sha256"],
            hashlib.sha256(phone_source.read_bytes()).hexdigest(),
        )

    def test_collector_closure_is_accepted_by_matrix_validator(self) -> None:
        closure = self.build()
        machine = {
            "app_version": self.fixture.app_version,
            "build_number": self.fixture.phone_build,
            "artifact_sha256": self.fixture.packages["phone_apk"]["sha256"],
            **closure,
        }
        artifact = self.fixture.repo / self.fixture.packages["phone_apk"]["path"]
        matrix_compiler.validate_form_factor_matrix(
            machine,
            self.fixture.output,
            self.fixture.repo,
            artifact,
            self.fixture.packages["phone_apk"]["sha256"],
            dt.datetime.fromisoformat(self.fixture.captured.replace("Z", "+00:00")),
        )

    def test_rejects_manifest_omission(self) -> None:
        self.fixture.descriptors.pop()
        self.fixture.write_manifest()
        with self.assertRaisesRegex(collector.CollectorError, "exactly eight descriptors"):
            self.fixture.preflight()

    def test_rejects_manifest_hash_drift(self) -> None:
        expected = self.fixture.manifest_sha
        self.fixture.manifest.write_bytes(self.fixture.manifest.read_bytes() + b" ")
        with self.assertRaisesRegex(collector.CollectorError, "manifest hash changed"):
            collector.preflight_form_factor_evidence(
                self.fixture.repo,
                self.fixture.manifest,
                expected,
                self.fixture.authorization,
                self.fixture.authorization_sha,
                self.fixture.release_index,
                self.fixture.packages,
                self.fixture.app_version,
                self.fixture.phone_build,
                self.fixture.release_hash,
                self.fixture.build_hash,
                self.fixture.native_tool_paths,
                self.fixture.adb_support_root,
                self.fixture.tesseract_support_root,
                self.fixture.route_authority_paths,
                inventory(),
                self.fixture.sha(self.fixture.route_inventory),
                self.fixture.expected_map_city_labels,
                self.fixture.device_attestation,
                self.fixture.devicecheck_build_receipt,
                self.fixture.devicecheck_build_receipt_sha256,
                self.fixture.devicecheck_target_sha256,
                len(self.fixture.devicecheck_target_bytes),
                self.fixture.devicecheck_test_sha256,
                len(self.fixture.devicecheck_test_bytes),
                self.fixture.devicecheck_source_inventory_sha256,
                self.fixture.serial,
            )

    def test_rejects_invalid_owner_authorization_signature(self) -> None:
        value = json.loads(self.fixture.authorization.read_text(encoding="utf-8"))
        value["signature_hex"] = "0" * 128
        self.fixture.write_json(self.fixture.authorization, value)
        self.fixture.authorization_sha = self.fixture.sha(self.fixture.authorization)
        with self.assertRaisesRegex(collector.CollectorError, "signature is invalid"):
            self.fixture.preflight()

    def test_rejects_self_selected_owner_authority(self) -> None:
        collector.EXPECTED_FORM_FACTOR_OWNER_AUTHORITY_SHA256 = "3" * 64
        with self.assertRaisesRegex(collector.CollectorError, "owner authority changed"):
            self.fixture.preflight()

    def test_rejects_owner_signed_missing_package_signature_proof(self) -> None:
        payload = self.fixture.authorization_payload()
        payload["cryptographic_package_signatures_verified"]["wear_aab"] = False
        self.fixture.write_authorization(payload)
        with self.assertRaisesRegex(collector.CollectorError, "contradicts the exact candidate"):
            self.fixture.preflight()

    def test_rejects_owner_signed_native_tool_hash_drift(self) -> None:
        payload = self.fixture.authorization_payload()
        payload["native_tool_sha256s"]["adb"] = "0" * 64
        self.fixture.write_authorization(payload)
        with self.assertRaisesRegex(collector.CollectorError, "contradicts the exact candidate"):
            self.fixture.preflight()

    def test_rejects_owner_signed_adb_support_tree_hash_drift(self) -> None:
        payload = self.fixture.authorization_payload()
        payload["adb_support_tree_sha256"] = "0" * 64
        self.fixture.write_authorization(payload)
        with self.assertRaisesRegex(collector.CollectorError, "contradicts the exact candidate"):
            self.fixture.preflight()

    def test_rejects_owner_signed_tesseract_support_tree_hash_drift(self) -> None:
        payload = self.fixture.authorization_payload()
        payload["tesseract_support_tree_sha256"] = "0" * 64
        self.fixture.write_authorization(payload)
        with self.assertRaisesRegex(collector.CollectorError, "contradicts the exact candidate"):
            self.fixture.preflight()

    def test_rejects_imported_attested_signing_key(self) -> None:
        value = json.loads(self.fixture.device_attestation.read_text(encoding="utf-8"))
        value["hardware_enforced_key_authorization"]["origin"] = "imported"
        self.fixture.write_json(self.fixture.device_attestation, value)
        self.fixture.write_authorization()
        with self.assertRaisesRegex(collector.CollectorError, "attestation receipt is invalid"):
            self.fixture.preflight()

    def test_rejects_noncanonical_leading_zero_attested_modulus(self) -> None:
        value = json.loads(self.fixture.device_attestation.read_text(encoding="utf-8"))
        value["attested_rsa_modulus_hex"] = "0" + value["attested_rsa_modulus_hex"]
        value["attested_key_id"] = collector._attested_key_id(
            value["attested_rsa_modulus_hex"],
            value["attested_rsa_public_exponent"],
        )
        self.fixture.write_json(self.fixture.device_attestation, value)
        self.fixture.write_authorization()
        with self.assertRaisesRegex(collector.CollectorError, "attestation receipt is invalid"):
            self.fixture.preflight()

    def test_rejects_owner_signed_route_authority_hash_drift(self) -> None:
        payload = self.fixture.authorization_payload()
        payload["route_authority_sha256s"]["ssh_identity"] = "0" * 64
        self.fixture.write_authorization(payload)
        with self.assertRaisesRegex(collector.CollectorError, "contradicts the exact candidate"):
            self.fixture.preflight()

    def test_rejects_owner_signed_map_city_drift(self) -> None:
        payload = self.fixture.authorization_payload()
        payload["expected_map_city_labels"] = ["Attacker City", "Beta City"]
        self.fixture.write_authorization(payload)
        with self.assertRaisesRegex(collector.CollectorError, "contradicts the exact candidate"):
            self.fixture.preflight()

    def test_rejects_owner_signed_emulator_device(self) -> None:
        self.fixture.serial = "emulator-5554"
        self.fixture.write_manifest()
        with self.assertRaisesRegex(collector.CollectorError, "exact hardware serial"):
            self.fixture.preflight()

    def test_rejects_owner_signed_device_attestation_hash_drift(self) -> None:
        payload = self.fixture.authorization_payload()
        payload["physical_device"]["attestation_receipt_sha256"] = "0" * 64
        self.fixture.write_authorization(payload)
        with self.assertRaisesRegex(collector.CollectorError, "contradicts the exact candidate"):
            self.fixture.preflight()

    def test_rejects_owner_signed_ssh_proxy_or_include(self) -> None:
        self.fixture.ssh_config.write_text(
            "Host core-release\n"
            "  HostName core.example.test\n"
            "  User release\n"
            "  Port 22\n"
            "  ProxyCommand attacker.exe %h %p\n"
            "Host node-release\n"
            "  HostName node.example.test\n"
            "  User release\n"
            "  Port 22\n",
            encoding="ascii",
        )
        self.fixture.write_authorization()
        with self.assertRaisesRegex(collector.CollectorError, "permits only"):
            self.fixture.preflight()

    def test_rejects_arbitrary_producer_not_approved_by_owner(self) -> None:
        old_authorization = self.fixture.authorization.read_bytes()
        old_authorization_sha = self.fixture.authorization_sha
        descriptor = next(
            item for item in self.fixture.descriptors if item["id"] == "tv-runtime"
        )
        index = self.fixture.manifest_dir / descriptor["source_index_path"]
        index_value = json.loads(index.read_text(encoding="utf-8"))
        producer_relative = "tools/attacker-tv-runtime-producer.py"
        producer = self.fixture.repo / producer_relative
        producer.write_text("PASSED = True\n", encoding="ascii")
        closure = self.fixture.producer_closure(producer_relative)
        index_value["producer"] = {
            "path": producer_relative,
            "closure_sha256": closure,
            "files": [{
                "path": producer_relative,
                "sha256": self.fixture.sha(producer),
            }],
        }
        self.fixture.write_json(index, index_value)
        descriptor["source_index_sha256"] = self.fixture.sha(index)
        descriptor["producer_closure_sha256"] = closure
        self.fixture.producer_paths["tv-runtime"] = producer_relative
        self.fixture.write_manifest()
        self.fixture.authorization.write_bytes(old_authorization)
        self.fixture.authorization_sha = old_authorization_sha
        with self.assertRaisesRegex(
            collector.CollectorError,
            "owner authorization contradicts|owner authorization changed",
        ):
            self.fixture.preflight()

    def test_rejects_candidate_authored_authority_replacement(self) -> None:
        authority = self.fixture.repo / collector.FORM_FACTOR_OWNER_AUTHORITY_RELATIVE
        value = json.loads(authority.read_text(encoding="utf-8"))
        value["public_key_hex"] = "1" * 64
        value["key_id"] = hashlib.sha256(bytes.fromhex("1" * 64)).hexdigest()
        self.fixture.write_json(authority, value)
        with self.assertRaisesRegex(collector.CollectorError, "authority changed"):
            self.fixture.preflight()

    def test_rejects_stale_runtime_receipt(self) -> None:
        stale = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=2)).isoformat()
        self.fixture.rewrite_receipt(
            "tv-runtime", lambda value: value.__setitem__("captured_at_utc", stale)
        )
        with self.assertRaisesRegex(collector.CollectorError, "stale or from another run"):
            self.fixture.preflight()

    def test_rejects_cross_candidate_runtime_receipt(self) -> None:
        self.fixture.rewrite_receipt(
            "tv-runtime", lambda value: value.__setitem__("candidate_id", "android-phone-tablet")
        )
        with self.assertRaisesRegex(collector.CollectorError, "contradicts the exact candidate"):
            self.fixture.preflight()

    def test_rejects_cross_candidate_produced_receipt(self) -> None:
        self.fixture.rewrite_receipt(
            "wear-aab-produced",
            lambda value: value.__setitem__("candidate_id", "android-tv"),
        )
        with self.assertRaisesRegex(collector.CollectorError, "contradicts the exact package"):
            self.fixture.preflight()

    def test_rejects_duplicate_receipt_or_source_index(self) -> None:
        phone = next(item for item in self.fixture.descriptors if item["id"] == "phone-runtime")
        tv = next(item for item in self.fixture.descriptors if item["id"] == "tv-runtime")
        tv.update({
            "receipt_path": phone["receipt_path"],
            "receipt_sha256": phone["receipt_sha256"],
            "source_index_path": phone["source_index_path"],
            "source_index_sha256": phone["source_index_sha256"],
            "producer_closure_sha256": phone["producer_closure_sha256"],
        })
        self.fixture.write_manifest()
        with self.assertRaisesRegex(collector.CollectorError, "duplicated"):
            self.fixture.preflight()

    def test_rejects_source_only_runtime_substitution(self) -> None:
        self.fixture.rewrite_receipt(
            "phone-runtime", lambda value: value.__setitem__("source_only", True)
        )
        with self.assertRaisesRegex(collector.CollectorError, "contradicts the exact candidate"):
            self.fixture.preflight()

    def test_rejects_phone_runtime_reused_as_tv(self) -> None:
        phone = next(item for item in self.fixture.descriptors if item["id"] == "phone-runtime")
        tv = next(item for item in self.fixture.descriptors if item["id"] == "tv-runtime")
        tv["receipt_path"] = phone["receipt_path"]
        tv["receipt_sha256"] = phone["receipt_sha256"]
        self.fixture.write_manifest()
        with self.assertRaisesRegex(collector.CollectorError, "duplicated"):
            self.fixture.preflight()

    def test_rejects_wear_vpn_misuse(self) -> None:
        def mutate(value: dict) -> None:
            value.clear()
            value.update(self.fixture.receipt_value("phone-runtime"))
            value["form_factor"] = "wear"
            value["candidate_id"] = "wear-os"
            value["artifact_sha256"] = self.fixture.packages["wear_aab"]["sha256"]
            value["version_code"] = self.fixture.codes["wear"]

        self.fixture.rewrite_receipt("wear-runtime", mutate)
        with self.assertRaisesRegex(collector.CollectorError, "wear runtime receipt fields are invalid"):
            self.fixture.preflight()

    def test_rejects_wrong_transport_order(self) -> None:
        self.fixture.rewrite_receipt(
            "phone-runtime",
            lambda value: value.__setitem__(
                "fallback_transports", ["winn_v1_xray", "winn_v1_awg"]
            ),
        )
        with self.assertRaisesRegex(collector.CollectorError, "Winn v3 then Winn v1 AWG then Xray"):
            self.fixture.preflight()

    def test_rejects_wrong_wear_companion(self) -> None:
        self.fixture.rewrite_receipt(
            "wear-runtime",
            lambda value: value.__setitem__("companion_phone_artifact_sha256", "f" * 64),
        )
        with self.assertRaisesRegex(collector.CollectorError, "exact pairing evidence"):
            self.fixture.preflight()

    def test_rejects_duplicate_tv_and_wear_issued_codes(self) -> None:
        for descriptor_id in ("wear-aab-produced", "wear-runtime"):
            self.fixture.rewrite_receipt(
                descriptor_id,
                lambda value: value.__setitem__(
                    "version_code", self.fixture.codes["tv"]
                ),
            )
        with self.assertRaisesRegex(collector.CollectorError, "not distinct issued identities"):
            self.fixture.preflight()

    def test_rejects_missing_wear_package(self) -> None:
        del self.fixture.packages["wear_aab"]
        with self.assertRaisesRegex(collector.CollectorError, "package closure is incomplete"):
            self.fixture.preflight()

    def test_rejects_missing_wear_mapping(self) -> None:
        preflight = self.fixture.preflight()
        symbols = self.fixture.symbols()
        del symbols["wear-os"]
        with self.assertRaisesRegex(collector.CollectorError, "mapping closure is incomplete"):
            self.build(preflight, symbols)

    def test_rejects_public_mapping_in_bundle(self) -> None:
        preflight = self.fixture.preflight()
        (self.fixture.output / "mapping.txt").write_text("must stay private\n", encoding="ascii")
        with self.assertRaisesRegex(collector.CollectorError, "private owner custody"):
            self.build(preflight)

    def test_rejects_source_index_membership_drift(self) -> None:
        descriptor = next(item for item in self.fixture.descriptors if item["id"] == "tv-runtime")
        index = self.fixture.manifest_dir / descriptor["source_index_path"]
        value = json.loads(index.read_text(encoding="utf-8"))
        value["files"][0]["sha256"] = "0" * 64
        self.fixture.write_json(index, value)
        descriptor["source_index_sha256"] = self.fixture.sha(index)
        self.fixture.write_manifest()
        with self.assertRaisesRegex(collector.CollectorError, "source-index inventory"):
            self.fixture.preflight()

    def test_rejects_owner_signed_relocated_private_mapping(self) -> None:
        descriptor = next(
            item for item in self.fixture.descriptors if item["id"] == "tv-runtime"
        )
        index = self.fixture.manifest_dir / descriptor["source_index_path"]
        receipt = self.fixture.manifest_dir / descriptor["receipt_path"]
        mapping = index.parent / "mapping.txt"
        os.replace(receipt, mapping)
        index_value = json.loads(index.read_text(encoding="utf-8"))
        index_value["files"] = [{
            "path": mapping.name,
            "sha256": self.fixture.sha(mapping),
            "size_bytes": mapping.stat().st_size,
            "contract": collector.RUNTIME_CONTRACT,
        }]
        self.fixture.write_json(index, index_value)
        descriptor["receipt_path"] = mapping.relative_to(self.fixture.manifest_dir).as_posix()
        descriptor["receipt_sha256"] = self.fixture.sha(mapping)
        descriptor["source_index_sha256"] = self.fixture.sha(index)
        self.fixture.write_manifest()
        with self.assertRaisesRegex(collector.CollectorError, "private mapping/symbol"):
            self.fixture.preflight()

    def test_rejects_pathname_replacement_after_preflight(self) -> None:
        preflight = self.fixture.preflight()
        descriptor = next(item for item in self.fixture.descriptors if item["id"] == "wear-runtime")
        receipt = self.fixture.manifest_dir / descriptor["receipt_path"]
        replacement = receipt.with_name("replacement.json")
        replacement.write_bytes(receipt.read_bytes())
        os.replace(replacement, receipt)
        with self.assertRaisesRegex(collector.CollectorError, "changed after preflight"):
            self.build(preflight)

    def test_rejects_benign_named_source_carrying_mapping_grammar(self) -> None:
        descriptor = next(item for item in self.fixture.descriptors if item["id"] == "tv-runtime")
        index = self.fixture.manifest_dir / descriptor["source_index_path"]
        observation = index.with_name("observation.txt")
        observation.write_text(
            "com.winsvpn.SecretClass -> a:\n",
            encoding="ascii",
        )
        value = json.loads(index.read_text(encoding="utf-8"))
        value["files"].append({
            "path": observation.name,
            "sha256": self.fixture.sha(observation),
            "size_bytes": observation.stat().st_size,
            "contract": "winsvpn-android-tv-observation-v1",
        })
        value["files"].sort(key=lambda item: item["path"])
        self.fixture.write_json(index, value)
        descriptor["source_index_sha256"] = self.fixture.sha(index)
        self.fixture.write_manifest()
        with self.assertRaisesRegex(collector.CollectorError, "only its exact receipt"):
            self.fixture.preflight()

    def test_rejects_package_mutation_during_physical_run(self) -> None:
        preflight = self.fixture.preflight()
        package = self.fixture.repo / self.fixture.packages["tv_aab"]["path"]
        package.write_bytes(package.read_bytes() + b"mutated")
        with self.assertRaisesRegex(collector.CollectorError, "changed after preflight"):
            self.build(preflight)

    def test_rejects_native_tool_mutation_during_physical_run(self) -> None:
        preflight = self.fixture.preflight()
        self.fixture.native_tool_paths["tesseract"].write_bytes(b"mutated tool")
        with self.assertRaisesRegex(collector.CollectorError, "executable changed after preflight"):
            self.build(preflight)

    def test_rejects_adb_support_dll_mutation_during_physical_run(self) -> None:
        preflight = self.fixture.preflight()
        (self.fixture.adb_support_root / "AdbWinApi.dll").write_bytes(
            b"mutated-adb-support"
        )
        with self.assertRaisesRegex(collector.CollectorError, "ADB support tree changed"):
            self.build(preflight)

    def test_rejects_tesseract_tessdata_mutation_during_physical_run(self) -> None:
        preflight = self.fixture.preflight()
        (self.fixture.tesseract_support_root / "tessdata/eng.traineddata").write_bytes(
            b"mutated-tessdata"
        )
        with self.assertRaisesRegex(
            collector.CollectorError, "Tesseract support tree changed"
        ):
            self.build(preflight)

    def test_rejects_route_authority_mutation_during_physical_run(self) -> None:
        preflight = self.fixture.preflight()
        self.fixture.ssh_identity.write_text("replacement-key\n", encoding="ascii")
        with self.assertRaisesRegex(collector.CollectorError, "changed after preflight"):
            self.build(preflight)

    def test_rejects_private_mapping_mutation_during_physical_run(self) -> None:
        preflight = self.fixture.preflight()
        self.fixture.symbols()
        symbols = collector.assert_obfuscation_symbol_evidence(
            self.fixture.repo,
            self.fixture.app_version,
            self.fixture.codes["phone"],
            self.fixture.codes["wear"],
            preflight["bound_files"],
        )
        mapping = (
            self.fixture.repo
            / ".artifacts/private-release-symbols/android-tv-aab"
            / f"{self.fixture.app_version}+{self.fixture.codes['phone']}"
            / "mapping.txt"
        )
        mapping.write_text("mutated mapping\n", encoding="ascii")
        with self.assertRaisesRegex(collector.CollectorError, "changed after preflight"):
            self.build(preflight, symbols)

    def test_rejects_ancestor_directory_substitution_after_preflight(self) -> None:
        preflight = self.fixture.preflight()
        descriptor = next(
            item for item in self.fixture.descriptors if item["id"] == "phone-runtime"
        )
        receipt = self.fixture.manifest_dir / descriptor["receipt_path"]
        source_root = receipt.parent
        original = source_root.with_name(source_root.name + "-original")
        os.replace(source_root, original)
        source_root.mkdir()
        for path in original.iterdir():
            (source_root / path.name).write_bytes(path.read_bytes())
        with self.assertRaisesRegex(collector.CollectorError, "changed after preflight"):
            self.build(preflight)

    def test_rejects_mode_or_ctime_drift_after_preflight(self) -> None:
        preflight = self.fixture.preflight()
        descriptor = next(
            item for item in self.fixture.descriptors if item["id"] == "wear-runtime"
        )
        receipt = self.fixture.manifest_dir / descriptor["receipt_path"]
        receipt.chmod(0o400)
        with self.assertRaisesRegex(collector.CollectorError, "changed after preflight"):
            self.build(preflight)

    def test_rejects_symlinked_or_hardlinked_receipt(self) -> None:
        descriptor = next(item for item in self.fixture.descriptors if item["id"] == "wear-runtime")
        receipt = self.fixture.manifest_dir / descriptor["receipt_path"]
        original = receipt.with_name("original.json")
        os.replace(receipt, original)
        os.symlink(original.name, receipt)
        with self.assertRaisesRegex(collector.CollectorError, "symbolic link|single-link"):
            self.fixture.preflight()
        receipt.unlink()
        os.link(original, receipt)
        with self.assertRaisesRegex(collector.CollectorError, "single-link regular file"):
            self.fixture.preflight()

    def test_rejects_duplicate_json_keys(self) -> None:
        descriptor = next(item for item in self.fixture.descriptors if item["id"] == "phone-runtime")
        receipt = self.fixture.manifest_dir / descriptor["receipt_path"]
        raw = receipt.read_text(encoding="utf-8").replace(
            '  "passed": true,', '  "passed": true,\n  "passed": true,', 1
        )
        receipt.write_text(raw, encoding="utf-8")
        index = self.fixture.manifest_dir / descriptor["source_index_path"]
        index_value = json.loads(index.read_text(encoding="utf-8"))
        index_value["files"][0]["sha256"] = self.fixture.sha(receipt)
        index_value["files"][0]["size_bytes"] = receipt.stat().st_size
        self.fixture.write_json(index, index_value)
        descriptor["receipt_sha256"] = self.fixture.sha(receipt)
        descriptor["source_index_sha256"] = self.fixture.sha(index)
        self.fixture.write_manifest()
        with self.assertRaisesRegex(collector.CollectorError, "strict UTF-8 JSON"):
            self.fixture.preflight()


def _write_synthetic_package_verifier_inputs(
    repo: pathlib.Path,
) -> tuple[pathlib.Path, dict[str, dict[str, str | int]]]:
    for ordinal, (role, relative) in enumerate(collector.CANONICAL_PRODUCED_PACKAGES):
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("AndroidManifest.xml", f"version=1.2.3;role={role};n={ordinal}")
        path.write_bytes(buffer.getvalue())
    for role, relative in collector.PHONE_CANDIDATE_ALIASES.items():
        alias = repo / relative
        alias.parent.mkdir(parents=True, exist_ok=True)
        canonical = repo / dict(collector.CANONICAL_PRODUCED_PACKAGES)[role]
        alias.write_bytes(canonical.read_bytes())
    custody: dict[str, dict[str, str | int]] = {}
    tool_root = repo / "held-package-verifier"
    tool_root.mkdir()
    for ordinal, role in enumerate(("java", "apksigner_jar", "aab_verifier_jar")):
        path = (tool_root / role).resolve()
        raw = f"reviewed fixture tool {ordinal} {role}\n".encode("ascii")
        path.write_bytes(raw)
        if role == "java":
            path.chmod(0o755)
        custody[role] = {
            "expected_path": str(path),
            "path": str(path),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
        }
    apk = repo / dict(collector.CANONICAL_PRODUCED_PACKAGES)["phone_apk"]
    return apk, custody


def _synthetic_verifier_completed_process(**kwargs):
    if kwargs["expected_format"] == "apk-signing-block":
        stdout = (
            "Verifies\n"
            "Verified using v1 scheme (JAR signing): false\n"
            "Verified using v2 scheme (APK Signature Scheme v2): true\n"
            "Verified using v3 scheme (APK Signature Scheme v3): true\n"
            f"Signer #1 certificate SHA-256 digest: {collector.EXPECTED_SIGNER}\n"
        ).encode("ascii")
    else:
        stdout = json.dumps(
            {
                "schema_version": 1,
                "contract": collector.PACKAGE_VERIFIER_OUTPUT_CONTRACT,
                "artifact_sha256": kwargs["artifact_sha256"],
                "artifact_size_bytes": kwargs["artifact_size_bytes"],
                "cryptographic_verified": True,
                "format": "aab-jar",
                "signer_certificate_sha256": collector.EXPECTED_SIGNER,
                "signed_payload_entries": 3,
                "unsigned_payload_entries": [],
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    return subprocess.CompletedProcess([], 0, stdout=stdout, stderr=b"")


def _synthetic_tool_bindings() -> dict[str, dict[str, str | int]]:
    return {
        role: {
            "sha256": hashlib.sha256(role.encode("ascii")).hexdigest(),
            "size_bytes": len(role),
        }
        for role in ("java", "apksigner_jar", "aab_verifier_jar")
    }


def _child_digest_from_descriptor(descriptor: int) -> str:
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            (
                "import hashlib,os,sys;fd=int(sys.argv[1]);os.lseek(fd,0,0);"
                "print(hashlib.sha256(os.read(fd,1048576)).hexdigest())"
            ),
            str(descriptor),
        ],
        pass_fds=(descriptor,),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stdout)
    return completed.stdout.strip()


class ClosureStaticTests(unittest.TestCase):
    def test_wrapper_embedded_csharp_targets_windows_powershell_51_process_apis(self) -> None:
        source = (TOOLS_DIR / "android_public_release_live_smoke.ps1").read_text(
            encoding="ascii"
        )
        csharp = re.search(
            r"Add-Type -TypeDefinition @'\n(.*?)\n'@", source, re.DOTALL
        )
        self.assertIsNotNone(csharp)
        bounded = csharp.group(1).split(
            "public static class ReleaseBoundedProcess", 1
        )[1]
        self.assertNotIn(".Kill(true)", bounded)
        self.assertNotIn(".ArgumentList", bounded)
        for required in (
            "CREATE_SUSPENDED",
            "CreateJobObject",
            "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
            "AssignProcessToJobObject",
            "PROC_THREAD_ATTRIBUTE_HANDLE_LIST",
            "CreateProcessW",
            "ResumeThread",
            "TerminateJobObject",
            "SafeFileHandle",
            "DisposeLocalCopyOfClientHandle",
        ):
            self.assertIn(required, bounded)

    @unittest.skipUnless(PWSH, "PowerShell is unavailable")
    def test_wrapper_embedded_csharp_compiles_with_add_type_contract(self) -> None:
        source = (TOOLS_DIR / "android_public_release_live_smoke.ps1").read_text(
            encoding="ascii"
        )
        csharp = re.search(
            r"Add-Type -TypeDefinition @'\n(.*?)\n'@", source, re.DOTALL
        )
        self.assertIsNotNone(csharp)
        completed = subprocess.run(
            [
                str(PWSH),
                "-NoLogo",
                "-NoProfile",
                "-Command",
                "$code=[Console]::In.ReadToEnd();"
                "Add-Type -TypeDefinition $code -Language CSharp;"
                "if ('WinsVpn.ReleaseBoundedProcess' -as [type]) {"
                " 'EMBEDDED_CSHARP_COMPILE_PASS'; exit 0 }; exit 9",
            ],
            input=csharp.group(1),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout)
        self.assertIn("EMBEDDED_CSHARP_COMPILE_PASS", completed.stdout)

    @unittest.skipUnless(PWSH, "PowerShell is unavailable")
    def test_wrapper_bounded_process_kills_output_flood_tree(self) -> None:
        source = (TOOLS_DIR / "android_public_release_live_smoke.ps1").read_text(
            encoding="utf-8"
        )
        csharp = re.search(
            r"Add-Type -TypeDefinition @'\n(.*?)\n'@", source, re.DOTALL
        )
        self.assertIsNotNone(csharp)
        with tempfile.TemporaryDirectory() as temp_name:
            temp = pathlib.Path(temp_name)
            csharp_path = temp / "bounded.cs"
            csharp_path.write_text(csharp.group(1), encoding="ascii")
            marker = temp / "post-output-marker"
            child = temp / "flood.py"
            child.write_text(
                "import os,pathlib,sys\n"
                "os.write(1,b'x'*(2*1024*1024))\n"
                "pathlib.Path(sys.argv[1]).write_text('unsafe')\n",
                encoding="ascii",
            )
            script = (
                "$code=[IO.File]::ReadAllText($args[0]);"
                "Add-Type -TypeDefinition $code;"
                "try {"
                " [WinsVpn.ReleaseBoundedProcess]::Run("
                "  $args[1],[string[]]@($args[2],$args[3]),$null,1024,1024,30000"
                " ) | Out-Null; exit 9"
                "} catch {"
                " if (Test-Path -LiteralPath $args[3]) { exit 8 };"
                " 'POWERSHELL_BOUNDED_PROCESS_PASS'"
                "}"
            )
            completed = subprocess.run(
                [
                    str(PWSH),
                    "-NoLogo",
                    "-NoProfile",
                    "-Command",
                    script,
                    str(csharp_path),
                    sys.executable,
                    str(child),
                    str(marker),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=60,
            )
            marker_existed = marker.exists()
        self.assertEqual(completed.returncode, 0, completed.stdout)
        self.assertIn("POWERSHELL_BOUNDED_PROCESS_PASS", completed.stdout)
        self.assertFalse(marker_existed)

    @unittest.skipUnless(PWSH, "PowerShell is unavailable")
    def test_wrapper_bounded_process_delivers_held_bytes_over_stdin(self) -> None:
        source = (TOOLS_DIR / "android_public_release_live_smoke.ps1").read_text(
            encoding="utf-8"
        )
        csharp = re.search(
            r"Add-Type -TypeDefinition @'\n(.*?)\n'@", source, re.DOTALL
        )
        self.assertIsNotNone(csharp)
        held = b"held authenticated Python source closure\n"
        with tempfile.TemporaryDirectory() as temp_name:
            temp = pathlib.Path(temp_name)
            csharp_path = temp / "bounded.cs"
            csharp_path.write_text(csharp.group(1), encoding="ascii")
            child = temp / "stdin_probe.py"
            child.write_text(
                "import hashlib,sys\n"
                "print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())\n",
                encoding="ascii",
            )
            script = (
                "$code=[IO.File]::ReadAllText($args[0]);"
                "Add-Type -TypeDefinition $code;"
                "$bytes=[Convert]::FromBase64String($args[3]);"
                "$result=[WinsVpn.ReleaseBoundedProcess]::Run("
                " $args[1],[string[]]@($args[2]),$bytes,1024,1024,30000"
                ");"
                "$result.Stdout; exit 0"
            )
            completed = subprocess.run(
                [
                    str(PWSH),
                    "-NoLogo",
                    "-NoProfile",
                    "-CommandWithArgs",
                    script,
                    str(csharp_path),
                    sys.executable,
                    str(child),
                    base64.b64encode(held).decode("ascii"),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=60,
            )
        self.assertEqual(completed.returncode, 0, completed.stdout)
        self.assertEqual(completed.stdout.strip(), hashlib.sha256(held).hexdigest())

    @unittest.skipUnless(PWSH, "PowerShell is unavailable")
    def test_wrapper_selftest_rejects_marker_spoofing_python_shim(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            temp = pathlib.Path(temp_name)
            shim = temp / "python3"
            invoked = temp / "shim-invoked"
            shim.write_text(
                "#!/bin/sh\n"
                f"touch {invoked!s}\n"
                "printf '%s\\n' \\\n"
                "  'ANDROID RELEASE MATRIX EVIDENCE COMPILER SELF-TEST: PASS' \\\n"
                "  'ANDROID RELEASE UI DRIVER SELF-TEST: PASS' \\\n"
                "  'ANDROID REMOTE ROUTE CONTROL SELF-TEST: PASS' \\\n"
                "  'ANDROID FINAL EVIDENCE COLLECTOR SELF-TEST: PASS' \\\n"
                "  'PUBLIC RELEASE LIVE-SMOKE PRODUCER SELF-TEST: PASS'\n"
                "exit 0\n",
                encoding="ascii",
            )
            shim.chmod(0o755)
            environment = {
                **os.environ,
                "PATH": str(temp),
                "LOCALAPPDATA": str(temp),
                "WINS_RELEASE_PYTHON": str(shim),
            }
            completed = subprocess.run(
                [
                    str(PWSH),
                    "-NoLogo",
                    "-NoProfile",
                    "-File",
                    str(TOOLS_DIR / "android_public_release_live_smoke.ps1"),
                    "-SelfTest",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=30,
                env=environment,
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(invoked.exists(), completed.stdout)
        self.assertRegex(completed.stdout, r"OWNER-BLOCKED|custody")

    def test_wrapper_isolated_bootstrap_rejects_stdlib_shadowing(self) -> None:
        source = (TOOLS_DIR / "android_public_release_live_smoke.ps1").read_text(encoding="utf-8")
        match = re.search(r"\$script:IsolatedPythonBootstrap = '([^']+)'", source)
        self.assertIsNotNone(match)
        bootstrap = match.group(1)
        self.assertNotIn("sys.path", bootstrap)
        self.assertIn("sys.dont_write_bytecode=True", bootstrap)
        self.assertIn("base64.b64decode", bootstrap)
        self.assertNotIn("open(", bootstrap)
        module_paths = dict(
            re.findall(r'\(\"([a-z_]+)\",\"(tools/[a-z0-9_]+\.py)\"\)', bootstrap)
        )
        with tempfile.TemporaryDirectory() as temp_name:
            temp = pathlib.Path(temp_name)
            (temp / "hashlib.py").write_text(
                "raise SystemExit('FORGED HASHLIB IMPORTED')\n", encoding="ascii"
            )
            entrypoint = "tools/android_final_evidence_collector.py"
            held_sources = {
                path: b"SAFE_SOURCE = True\n" for path in module_paths.values()
            }
            held_sources[entrypoint] = (
                b"import hashlib\nassert hasattr(hashlib, 'sha256')\n"
                b"print('ISOLATED STDLIB RESOLUTION: PASS')\n"
            )
            payload = {
                "schema_version": 1,
                "entrypoint": entrypoint,
                "arguments": [],
                "files": {
                    path: base64.b64encode(raw).decode("ascii")
                    for path, raw in held_sources.items()
                },
                "digests": {
                    path: hashlib.sha256(raw).hexdigest()
                    for path, raw in held_sources.items()
                },
            }
            encoded = json.dumps(
                payload, separators=(",", ":"), sort_keys=True
            ).encode("ascii")
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-c",
                    bootstrap,
                ],
                input=encoded,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=30,
            )
        self.assertEqual(completed.returncode, 0, completed.stdout)
        self.assertEqual(
            completed.stdout.decode("utf-8").strip(),
            "ISOLATED STDLIB RESOLUTION: PASS",
        )

    def test_wrapper_isolated_bootstrap_rejects_unchecked_hash_pyc(self) -> None:
        source = (TOOLS_DIR / "android_public_release_live_smoke.ps1").read_text(encoding="utf-8")
        bootstrap = re.search(
            r"\$script:IsolatedPythonBootstrap = '([^']+)'", source
        ).group(1)
        module_paths = dict(
            re.findall(r'\(\"([a-z_]+)\",\"(tools/[a-z0-9_]+\.py)\"\)', bootstrap)
        )
        self.assertIn("release_secret_scan_policy", module_paths)
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            tools = root / "tools"
            tools.mkdir()
            for module_path in module_paths.values():
                (root / module_path).write_text("SAFE_SOURCE = True\n", encoding="ascii")
            poisoned = tools / "release_secret_scan_policy.py"
            poisoned.write_text("raise SystemExit('FORGED PYC EXECUTED')\n", encoding="ascii")
            py_compile.compile(
                str(poisoned),
                invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
                doraise=True,
            )
            poisoned.write_text("SAFE_SOURCE = True\n", encoding="ascii")
            entrypoint = "tools/android_final_evidence_collector.py"
            held_sources = {
                path: b"SAFE_SOURCE = True\n" for path in module_paths.values()
            }
            held_sources[entrypoint] = (
                b"import release_secret_scan_policy as policy\n"
                b"assert policy.SAFE_SOURCE is True\n"
                b"print('SOURCE ONLY LOADER: PASS')\n"
            )
            payload = {
                "schema_version": 1,
                "entrypoint": entrypoint,
                "arguments": [],
                "files": {
                    path: base64.b64encode(raw).decode("ascii")
                    for path, raw in held_sources.items()
                },
                "digests": {
                    path: hashlib.sha256(raw).hexdigest()
                    for path, raw in held_sources.items()
                },
            }
            encoded = json.dumps(
                payload, separators=(",", ":"), sort_keys=True
            ).encode("ascii")
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-c",
                    bootstrap,
                ],
                input=encoded,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=30,
            )
        self.assertEqual(completed.returncode, 0, completed.stdout)
        self.assertEqual(
            completed.stdout.decode("utf-8").strip(),
            "SOURCE ONLY LOADER: PASS",
        )

    def test_wrapper_root_authenticates_python_code_closure(self) -> None:
        source = (TOOLS_DIR / "android_public_release_live_smoke.ps1").read_text(encoding="utf-8")
        entries = dict(
            re.findall(r"'((?:tools)/[^']+)' = '([0-9a-f]{64})'", source)
        )
        expected = {
            "tools/android_final_evidence_collector.py",
            "tools/android_release_matrix_evidence.py",
            "tools/android_release_ui_driver.py",
            "tools/android_remote_route_control.py",
            "tools/android_remote_route_guard.sh",
            "tools/android_fresh_release_regression.ps1",
            "tools/android_exact_installed_live_cycle.ps1",
            "tools/public_release_live_smoke_common.py",
            "tools/validate_release_artifact_privacy.py",
            "tools/release_obfuscation_contract.py",
            "tools/release_dependency_freeze.py",
            "tools/release_secret_scan_policy.py",
            "tools/release_secret_inventory.py",
        }
        self.assertEqual(set(entries), expected)
        for relative, digest in entries.items():
            self.assertEqual(hashlib.sha256((TOOLS_DIR.parent / relative).read_bytes()).hexdigest(), digest)
        self.assertIn("$script:EvidenceCodeStreams", source)
        self.assertIn("[IO.FileShare]::Read", source)

    def test_wrapper_rejects_release_dependency_freeze_source_drift(self) -> None:
        wrapper = (TOOLS_DIR / "android_public_release_live_smoke.ps1").read_text(
            encoding="ascii"
        )
        entries = dict(
            re.findall(r"'((?:tools)/[^']+)' = '([0-9a-f]{64})'", wrapper)
        )
        relative = "tools/release_dependency_freeze.py"
        accepted = (TOOLS_DIR.parent / relative).read_bytes()
        pinned = entries[relative]
        self.assertEqual(hashlib.sha256(accepted).hexdigest(), pinned)
        for hostile in (
            accepted + b"\n# hostile post-review drift\n",
            bytes([accepted[0] ^ 1]) + accepted[1:],
        ):
            with self.subTest(hostile_sha256=hashlib.sha256(hostile).hexdigest()):
                self.assertNotEqual(hashlib.sha256(hostile).hexdigest(), pinned)
        self.assertIn(
            "$digest -cne [string]$ExpectedEvidenceCodeSha256[$relative]",
            wrapper,
        )
        self.assertIn(
            "OWNER-BLOCKED: Android evidence code does not match its wrapper trust anchor",
            wrapper,
        )

    def test_remote_guard_has_transaction_and_watchdog_controls(self) -> None:
        source = (TOOLS_DIR / "android_remote_route_guard.sh").read_text(encoding="utf-8")
        for required in (
            "iptables-restore --noflush", "systemd-run --collect --quiet", "watchdog_seconds",
            "conntrack -L -f ipv4", "flock -x", "umask 077", "source_ipv4_sha256",
            "MAX_PAYLOAD_BYTES=32768", "assert_secure_file", "assert_globally_clean",
            'iptables -t mangle -L "${mangle_chain}" -nvx --line-numbers',
        ):
            self.assertIn(required, source)
        self.assertNotIn("iptables-save", source)
        self.assertNotIn('cat >"${payload_file}"', source)
        self.assertNotRegex(source, r"PasswordAuthentication=yes|StrictHostKeyChecking=no")

    def test_controller_enforces_key_only_ssh(self) -> None:
        source = (TOOLS_DIR / "android_remote_route_control.py").read_text(encoding="utf-8")
        for required in (
            '"BatchMode=yes"', '"PasswordAuthentication=no"',
            '"KbdInteractiveAuthentication=no"', '"StrictHostKeyChecking=yes"',
        ):
            self.assertIn(required, source)

    def test_public_producer_closure_contains_every_android_helper(self) -> None:
        source = (TOOLS_DIR / "public_release_live_smoke_common.py").read_text(encoding="utf-8")
        for helper in (
            "android_final_evidence_collector.py", "android_release_matrix_evidence.py",
            "android_release_ui_driver.py", "android_remote_route_control.py",
            "android_remote_route_guard.sh", "android_fresh_release_regression.ps1",
        ):
            self.assertIn(helper, source)

    def test_public_wrapper_has_only_fresh_physical_evidence_path(self) -> None:
        source = (TOOLS_DIR / "android_public_release_live_smoke.ps1").read_text(encoding="utf-8")
        parameter_block = source.split(")\n\nSet-StrictMode", 1)[0]
        for forbidden in ("$MachineEvidence", "$MapScreenshot", "$NativeTranscript", "$CollectPhysical"):
            self.assertNotIn(forbidden, parameter_block)
        self.assertIn("Every qualifying Android run requires", source)
        self.assertIn("android_final_evidence_collector.py", source)
        self.assertIn("--output-root", source)
        self.assertIn("--evidence-index", source)
        self.assertIn("--expected-evidence-index-sha256", source)
        self.assertIn("--form-factor-evidence-manifest", source)
        self.assertIn("--expected-form-factor-evidence-manifest-sha256", source)
        self.assertIn("--form-factor-owner-authorization", source)
        self.assertIn("--expected-form-factor-owner-authorization-sha256", source)
        self.assertIn("--device-attestation-receipt", source)
        self.assertIn("--devicecheck-build-receipt", source)
        self.assertIn("--expected-devicecheck-build-receipt-sha256", source)
        self.assertIn("--expected-devicecheck-target-apk-sha256", source)
        self.assertIn("--expected-devicecheck-target-apk-bytes", source)
        self.assertIn("--expected-devicecheck-android-test-apk-sha256", source)
        self.assertIn("--expected-devicecheck-android-test-apk-bytes", source)
        self.assertIn("--expected-devicecheck-source-inventory-sha256", source)
        self.assertIn("deviceCheckBuildReceiptSidecarPath", source)
        self.assertIn("deviceCheckTargetApkPath", source)
        self.assertIn("deviceCheckAndroidTestApkPath", source)
        self.assertIn("Refusing to reuse an Android native transcript", source)
        self.assertNotIn("--machine-evidence", source)
        for native_argument in (
            "--powershell",
            "--ssh",
            "--ssh-config",
            "--ssh-identity",
            "--ssh-known-hosts",
            "--whoami",
            "--icacls",
            "--taskkill",
            "--expected-adb-server-socket",
            "--adb-support-root",
            "$script:NativeToolStreams",
            "$script:RouteAuthorityStreams",
            "Start-DedicatedAdbServer",
            "Assert-DedicatedAdbServerStillBound",
            "ReleaseTcpListener",
            "ANDROID_ADB_SERVER_ADDRESS",
            "ADB_LIBUSB",
            "ReleaseBoundedProcess",
            "Invoke-BoundedAndroidChild",
            "ExpectedFormFactorOwnerAuthoritySha256",
            "Assert-OwnerIndependentReadOnlyAdbTree",
            "Assert-OwnerIndependentReadOnlyTesseractTree",
            "AdbWinApi.dll",
            "AdbWinUsbApi.dll",
            "--tesseract-support-root",
            "tessdata\\eng.traineddata",
            "$script:EvidenceBundleStreams",
            "Add-HeldAndroidEvidenceFile",
            "native-transcript",
            "evidence-member:",
        ):
            self.assertIn(native_argument, source)
        self.assertNotIn("Android\\Sdk\\platform-tools\\adb.exe", parameter_block)

    def test_public_wrapper_passes_every_required_devicecheck_argument_pair(self) -> None:
        source = (TOOLS_DIR / "android_public_release_live_smoke.ps1").read_text(
            encoding="ascii"
        )
        collector_args = source.split("$collectorArgs = @(", 1)[1].split(")\n", 1)[0]
        expected_pairs = {
            "--device-attestation-receipt": "$deviceAttestationPath",
            "--devicecheck-build-receipt": "$deviceCheckBuildReceiptPath",
            "--expected-devicecheck-build-receipt-sha256": "$ExpectedDeviceCheckBuildReceiptSha256",
            "--expected-devicecheck-target-apk-sha256": "$ExpectedDeviceCheckTargetApkSha256",
            "--expected-devicecheck-target-apk-bytes": "$ExpectedDeviceCheckTargetApkBytes",
            "--expected-devicecheck-android-test-apk-sha256": "$ExpectedDeviceCheckAndroidTestApkSha256",
            "--expected-devicecheck-android-test-apk-bytes": "$ExpectedDeviceCheckAndroidTestApkBytes",
            "--expected-devicecheck-source-inventory-sha256": "$ExpectedDeviceCheckSourceInventorySha256",
        }
        for option, value in expected_pairs.items():
            with self.subTest(option=option):
                self.assertEqual(
                    collector_args.count(f"'{option}', {value}"),
                    1,
                )

    def test_tesseract_uses_strict_non_extensible_environment(self) -> None:
        source = (TOOLS_DIR / "android_final_evidence_collector.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("tesseract_env = dict(os.environ)", source)
        for required in (
            'tesseract_env["OMP_TOOL"] = "disabled"',
            'tesseract_env["OMP_NUM_THREADS"] = "1"',
            'tesseract_env["OMP_DYNAMIC"] = "FALSE"',
            'tesseract_env["NoDefaultCurrentDirectoryInExePath"] = "1"',
            "cwd=self.tesseract_support_root",
            '"--tessdata-dir"',
        ):
            self.assertIn(required, source)

    def test_public_wrapper_requires_held_authenticated_python(self) -> None:
        source = (TOOLS_DIR / "android_public_release_live_smoke.ps1").read_text(encoding="utf-8")
        for required in (
            "WINS_RELEASE_PYTHON",
            "Assert-WinsAndroidToolchainCustodyManifestPreflight",
            "Assert-WinsAndroidToolchainCustody",
            "New-HeldPythonArguments",
            "Windows process creation cannot prove execution from the held",
            "[IO.FileShare]::Read",
            "Assert-AuthenticatedReleasePythonStillBound",
            "Assert-OwnerIndependentReadOnlyPythonTree",
            "ProgramW6432",
            "GetAccessRules",
            "CurrentTokenPrivileges",
            "SeTakeOwnershipPrivilege",
            "SeRestorePrivilege",
            "SeDebugPrivilege",
            "-I', '-S', '-c'",
        ):
            self.assertIn(required, source)
        self.assertNotRegex(source, r"Get-Command\s+python(?:\.exe|3)?")

    def test_public_wrapper_uses_bounded_stdin_not_source_argv(self) -> None:
        source = (TOOLS_DIR / "android_public_release_live_smoke.ps1").read_text(
            encoding="utf-8"
        )
        bootstrap = re.search(
            r"\$script:IsolatedPythonBootstrap = '([^']+)'", source
        ).group(1)
        self.assertIn("sys.stdin.buffer.read(16777217)", bootstrap)
        self.assertIn("len(raw)<=16777216", bootstrap)
        self.assertNotIn("sys.argv[1]", bootstrap)
        self.assertIn(
            "StartPortable(fileName, arguments, standardInput != null)", source
        )
        self.assertIn("PipeDirection.Out, HandleInheritability.Inheritable", source)
        self.assertIn("child.StandardInput.Write(", source)
        self.assertIn("standardInput.Length > 16777216", source)
        self.assertIn("-StandardInput $isolatedCollectorInvocation.StandardInput", source)
        self.assertNotRegex(source, r"\$encoded\s*=|,\s*\$encoded\)")

    def test_public_wrapper_root_authenticates_custody_manifest(self) -> None:
        source = (TOOLS_DIR / "android_public_release_live_smoke.ps1").read_text(encoding="utf-8")
        match = re.search(
            r"\$ExpectedToolchainCustodyManifestSha256 = '([0-9a-f]{64})'", source
        )
        self.assertIsNotNone(match)
        manifest = (TOOLS_DIR / "android-toolchain-custody.json").read_bytes()
        self.assertEqual(hashlib.sha256(manifest).hexdigest(), match.group(1))
        substituted = manifest.replace(b'"issuance_id": "', b'"issuance_id": "0', 1)
        self.assertNotEqual(hashlib.sha256(substituted).hexdigest(), match.group(1))
        open_manifest = source.index("$script:CustodyManifestStream = [IO.FileStream]::new(")
        hash_check = source.index("$manifestDigest -cne $ExpectedToolchainCustodyManifestSha256")
        parse_manifest = source.index("$custodyText = Read-HeldUtf8Text -Stream $script:CustodyManifestStream")
        source_helper = source.index("New-Module -ScriptBlock")
        self.assertLess(open_manifest, hash_check)
        self.assertLess(hash_check, parse_manifest)
        self.assertLess(parse_manifest, source_helper)
        self.assertNotIn(". $ToolchainCustodyHelper", source)
        self.assertNotIn("Get-Content -Raw -LiteralPath $ToolchainCustodyManifest", source)
        self.assertIn("[IO.FileShare]::Read", source)
        self.assertIn("Assert-AuthenticatedSupportFilesStillBound", source)

    def test_collector_seals_exclusive_indexed_bundle(self) -> None:
        source = (TOOLS_DIR / "android_final_evidence_collector.py").read_text(encoding="utf-8")
        for required in (
            "winsvpn-android-evidence-bundle-index-v1",
            'root.mkdir(mode=0o700, parents=False, exist_ok=False)',
            'index_path = root / "EVIDENCE_INDEX.json"',
            '"machine_evidence_path"',
            '"map_screenshot_path"',
            '"producer_contract_sha256"',
            '"remote_guard"',
            "seal_evidence_bundle(root)",
            "OWNER-BLOCKED: produced Android AAB/APK bytes are absent",
            "assert_held_produced_packages",
            "assert_obfuscation_symbol_evidence",
        ):
            self.assertIn(required, source)

    def test_collector_owner_blocks_missing_canonical_packages(self) -> None:
        import android_final_evidence_collector as collector

        with tempfile.TemporaryDirectory() as name:
            repo = pathlib.Path(name)
            (repo / "build/app/outputs/flutter-apk").mkdir(parents=True)
            apk = repo / "build/app/outputs/flutter-apk/app-release.apk"
            with self.assertRaisesRegex(
                collector.CollectorError,
                "OWNER-BLOCKED: produced Android AAB/APK bytes are absent",
            ):
                collector.assert_held_produced_packages(repo, apk)

    def test_collector_identity_reads_pubspec_version(self) -> None:
        import android_final_evidence_collector as collector

        name, code = collector.expected_android_identity(TOOLS_DIR.parent)
        self.assertRegex(name, r"^\d+\.\d+\.\d+$")
        self.assertRegex(code, r"^\d+$")
        self.assertEqual(collector.EXPECTED_APPLICATION_ID, "org.winsvpn.app")

    def test_collector_production_package_api_has_no_fixture_reachability(self) -> None:
        signature = inspect.signature(collector.assert_held_produced_packages)
        self.assertEqual(tuple(signature.parameters), ("repo", "apk"))
        collector_source = (TOOLS_DIR / "android_final_evidence_collector.py").read_text(
            encoding="ascii"
        )
        wrapper_source = (TOOLS_DIR / "android_public_release_live_smoke.ps1").read_text(
            encoding="ascii"
        )
        self.assertNotIn("fixture_mode", collector_source)
        self.assertNotIn("fixture_process_runner", collector_source)
        self.assertNotIn("fixture_mode", wrapper_source)
        self.assertIn("packages = assert_held_produced_packages(repo, apk)", collector_source)
        runner_source = inspect.getsource(collector._run_held_package_verifier)
        self.assertIn('f"/proc/self/fd/{descriptor}"', runner_source)
        self.assertIn("pass_fds=(java_fd, verifier_fd, artifact_fd)", runner_source)
        self.assertNotIn('["path"]', runner_source)
        cli = subprocess.run(
            [
                sys.executable,
                str(TOOLS_DIR / "android_final_evidence_collector.py"),
                "--package-verifier-fixture",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=30,
        )
        self.assertEqual(cli.returncode, 2, cli.stdout)
        self.assertIn("unrecognized arguments", cli.stdout)
        with self.assertRaisesRegex(
            collector.CollectorError,
            "accepts only process output",
        ):
            collector._package_verifier_output(
                {"cryptographic_verified": True},
                role="phone_apk",
                package_sha256="1" * 64,
                package_size=1,
                expected_format="apk-signing-block",
                tool_snapshots=_synthetic_tool_bindings(),
            )

    def test_synthetic_process_output_parses_without_production_records(self) -> None:
        tools = _synthetic_tool_bindings()
        for ordinal, (role, _relative) in enumerate(
            collector.CANONICAL_PRODUCED_PACKAGES
        ):
            raw = f"synthetic parser bytes {ordinal} {role}".encode("ascii")
            expected_format = "apk-signing-block" if role.endswith("_apk") else "aab-jar"
            completed = _synthetic_verifier_completed_process(
                role=role,
                artifact_sha256=hashlib.sha256(raw).hexdigest(),
                artifact_size_bytes=len(raw),
                expected_format=expected_format,
            )
            parsed = collector._package_verifier_output(
                completed,
                role=role,
                package_sha256=hashlib.sha256(raw).hexdigest(),
                package_size=len(raw),
                expected_format=expected_format,
                tool_snapshots=tools,
            )
            self.assertEqual(parsed["artifact_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertRegex(parsed["output_sha256"], r"^[0-9a-f]{64}$")

    def test_collector_rejects_fake_meta_inf_signatures_for_all_five_packages(self) -> None:
        tools = _synthetic_tool_bindings()
        for role, _relative in collector.CANONICAL_PRODUCED_PACKAGES:
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr("AndroidManifest.xml", f"fake={role}")
                archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n\r\n")
                archive.writestr("META-INF/CERT.SF", "Signature-Version: 1.0\r\n\r\n")
                archive.writestr("META-INF/CERT.RSA", b"not-a-cryptographic-signature")
            raw = buffer.getvalue()
            expected_format = "apk-signing-block" if role.endswith("_apk") else "aab-jar"
            completed = subprocess.CompletedProcess(
                [], 1, stdout=b"", stderr=b"synthetic rejection"
            )
            with self.subTest(role=role), self.assertRaisesRegex(
                collector.CollectorError,
                f"{role} cryptographic package verification failed",
            ):
                collector._package_verifier_output(
                    completed,
                    role=role,
                    package_sha256=hashlib.sha256(raw).hexdigest(),
                    package_size=len(raw),
                    expected_format=expected_format,
                    tool_snapshots=tools,
                )

    def test_verifier_parser_rejects_signer_drift(self) -> None:
        raw = b"synthetic signer drift parser input"
        completed = _synthetic_verifier_completed_process(
            role="phone_apk",
            artifact_sha256=hashlib.sha256(raw).hexdigest(),
            artifact_size_bytes=len(raw),
            expected_format="apk-signing-block",
        )
        completed.stdout = completed.stdout.replace(
            collector.EXPECTED_SIGNER.encode("ascii"), b"9" * 64
        )
        with self.assertRaisesRegex(
            collector.CollectorError,
            "signing-block verification failed",
        ):
            collector._package_verifier_output(
                completed,
                role="phone_apk",
                package_sha256=hashlib.sha256(raw).hexdigest(),
                package_size=len(raw),
                expected_format="apk-signing-block",
                tool_snapshots=_synthetic_tool_bindings(),
            )

    def test_collector_rejects_held_verifier_path_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            repo = pathlib.Path(name)
            _apk, custody = _write_synthetic_package_verifier_inputs(repo)
            alternate = repo / "held-package-verifier/alternate-java"
            alternate.write_bytes((repo / "held-package-verifier/java").read_bytes())
            alternate.chmod(0o755)
            custody["java"]["path"] = str(alternate.resolve())
            with self.assertRaisesRegex(collector.CollectorError, "OWNER-BLOCKED"):
                collector._package_verifier_custody_hold(custody)

    def test_collector_rejects_artifact_mutation_and_same_version_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            repo = pathlib.Path(name)
            apk, _custody = _write_synthetic_package_verifier_inputs(repo)
            hold = collector._open_held_external_file(
                apk, "synthetic held artifact", max_bytes=1024 * 1024
            )
            try:
                raw = bytearray(apk.read_bytes())
                raw[-1] ^= 1
                apk.write_bytes(raw)
                with self.assertRaisesRegex(collector.CollectorError, "identity changed"):
                    collector._revalidate_held_external_file(
                        hold, "synthetic held artifact"
                    )
            finally:
                collector._close_held_external_files({"artifact": hold})
        with tempfile.TemporaryDirectory() as name:
            repo = pathlib.Path(name)
            apk, _custody = _write_synthetic_package_verifier_inputs(repo)
            tv_apk = repo / dict(collector.CANONICAL_PRODUCED_PACKAGES)["tv_apk"]
            hold = collector._open_held_external_file(
                tv_apk, "synthetic held TV artifact", max_bytes=1024 * 1024
            )
            try:
                os.replace(apk, tv_apk)
                with self.assertRaisesRegex(collector.CollectorError, "identity changed"):
                    collector._revalidate_held_external_file(
                        hold, "synthetic held TV artifact"
                    )
            finally:
                collector._close_held_external_files({"artifact": hold})

    def test_collector_rejects_verifier_tool_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            repo = pathlib.Path(name)
            _apk, custody = _write_synthetic_package_verifier_inputs(repo)
            holds = collector._package_verifier_custody_hold(custody)
            try:
                pathlib.Path(str(custody["apksigner_jar"]["path"])).write_bytes(
                    b"substituted verifier bytes\n"
                )
                with self.assertRaisesRegex(collector.CollectorError, "identity changed"):
                    collector._revalidate_held_external_file(
                        holds["apksigner_jar"],
                        "synthetic held apksigner jar",
                    )
            finally:
                collector._close_held_external_files(holds)

    @unittest.skipIf(os.name == "nt", "pass_fds is POSIX-only")
    def test_transient_tool_leaf_substitute_restore_uses_held_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            repo = pathlib.Path(name)
            _apk, custody = _write_synthetic_package_verifier_inputs(repo)
            java = pathlib.Path(str(custody["java"]["path"]))
            held = collector._open_held_external_file(
                java, "synthetic held Java", max_bytes=1024 * 1024, executable=True
            )
            backup = java.with_name("java.held")
            expected = held["sha256"]
            try:
                os.replace(java, backup)
                java.write_bytes(b"attacker transient Java bytes\n")
                java.chmod(0o755)
                observed = _child_digest_from_descriptor(held["descriptor"])
                java.unlink()
                os.replace(backup, java)
                with self.assertRaisesRegex(
                    collector.CollectorError, "ancestor identity changed"
                ):
                    collector._revalidate_held_external_file(
                        held, "synthetic held Java"
                    )
            finally:
                if backup.exists() and not java.exists():
                    os.replace(backup, java)
                collector._close_held_external_files({"java": held})
            self.assertEqual(observed, expected)
            self.assertNotEqual(observed, hashlib.sha256(b"attacker transient Java bytes\n").hexdigest())

    @unittest.skipIf(os.name == "nt", "pass_fds is POSIX-only")
    def test_transient_tool_parent_substitute_restore_uses_held_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            repo = pathlib.Path(name)
            _apk, custody = _write_synthetic_package_verifier_inputs(repo)
            java = pathlib.Path(str(custody["java"]["path"]))
            parent = java.parent
            ancestor_identity = collector._directory_identity(parent.lstat())
            ordinary_sibling = parent / "ordinary-unrelated-sibling"
            ordinary_sibling.mkdir()
            try:
                self.assertEqual(
                    collector._directory_identity(parent.lstat()),
                    ancestor_identity,
                )
            finally:
                ordinary_sibling.rmdir()
            held_parent = parent.with_name("held-package-verifier.original")
            held = collector._open_held_external_file(
                java, "synthetic held Java", max_bytes=1024 * 1024, executable=True
            )
            expected = held["sha256"]
            try:
                higher_sibling = parent.parent / "ordinary-unrelated-sibling"
                higher_sibling.mkdir()
                try:
                    collector._revalidate_held_external_file(
                        held, "synthetic held Java"
                    )
                finally:
                    higher_sibling.rmdir()
                os.replace(parent, held_parent)
                parent.mkdir()
                attacker = parent / "java"
                attacker.write_bytes(b"attacker transient parent bytes\n")
                attacker.chmod(0o755)
                observed = _child_digest_from_descriptor(held["descriptor"])
                attacker.unlink()
                parent.rmdir()
                os.replace(held_parent, parent)
                with self.assertRaisesRegex(
                    collector.CollectorError, "ancestor identity changed"
                ):
                    collector._revalidate_held_external_file(
                        held, "synthetic held Java"
                    )
            finally:
                if held_parent.exists() and not parent.exists():
                    os.replace(held_parent, parent)
                collector._close_held_external_files({"java": held})
            self.assertEqual(observed, expected)
            self.assertNotEqual(observed, hashlib.sha256(b"attacker transient parent bytes\n").hexdigest())

    def test_collector_owner_blocks_missing_authenticated_package_verifier(self) -> None:
        import io
        import zipfile
        import android_final_evidence_collector as collector

        with tempfile.TemporaryDirectory() as name:
            repo = pathlib.Path(name)
            paths = []
            for role, relative in collector.CANONICAL_PRODUCED_PACKAGES:
                path = repo / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, "w") as archive:
                    archive.writestr("AndroidManifest.xml", role)
                path.write_bytes(buffer.getvalue())
                paths.append(path)
            with self.assertRaisesRegex(collector.CollectorError, "OWNER-BLOCKED"):
                collector.assert_held_produced_packages(repo, paths[0])

    def test_collector_self_test_is_not_production_pass(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(TOOLS_DIR / "android_final_evidence_collector.py"), "--self-test"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("ANDROID FINAL EVIDENCE COLLECTOR SELF-TEST: PASS", completed.stdout)
        self.assertNotIn("ANDROID FINAL EVIDENCE COLLECTOR: PASS", completed.stdout.replace(
            "ANDROID FINAL EVIDENCE COLLECTOR SELF-TEST: PASS", ""
        ))


if __name__ == "__main__":
    unittest.main()
