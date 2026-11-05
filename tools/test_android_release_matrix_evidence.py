#!/usr/bin/env python3
"""Fail-closed tests for Android machine-evidence compilation."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import uuid

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from android_release_matrix_evidence import (
    CANONICAL_PACKAGE_PATHS,
    EXPECTED_SIGNER_SHA256,
    FORM_FACTOR_CANDIDATES,
    HELPER_PATHS,
    INDEX_CONTRACT,
    MAPPING_ROLES,
    OWNER_BLOCKED_ABSENT_PACKAGES,
    OWNER_BLOCKED_LISTING,
    OWNER_BLOCKED_MAPPING,
    PHONE_CANDIDATE_ALIASES,
    EvidenceError,
    compile_evidence,
    load_evidence_bundle,
)


NOW = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
REPO = pathlib.Path(__file__).resolve().parent.parent


class Fixture:
    def __init__(self, root: pathlib.Path) -> None:
        self.workspace = root
        self.run_id = uuid.uuid4()
        self.root = root / str(self.run_id)
        self.root.mkdir()
        self.artifact = root / "release.apk"
        self.artifact.write_bytes(b"exact-release-apk")
        self.artifact_hash = self.sha(self.artifact)
        self.direct_egress = "1" * 64
        self.baseline_egress = "2" * 64
        self.app_version = "1.0.14"
        self.version_codes = {"phone": 14, "tv": 1402, "wear": 1401}
        self.package_payloads = {
            ("phone", "apk"): b"exact-release-apk",
            ("phone", "aab"): b"exact-release-aab",
            ("tv", "apk"): b"exact-tv-apk-bytes",
            ("tv", "aab"): b"exact-tv-aab-bytes",
            ("wear", "aab"): b"exact-wear-aab-bytes",
        }
        self.package_records: dict[tuple[str, str], dict[str, str | int]] = {}

    @staticmethod
    def sha(path: pathlib.Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def json_receipt(self, name: str, value: dict) -> tuple[str, str]:
        path = self.root / name
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        return name, self.sha(path)

    def base_receipt(self, contract: str) -> dict:
        return {
            "schema_version": 1,
            "contract": contract,
            "captured_at_utc": NOW,
            "secret_material_redacted": True,
        }

    def stage_produced_packages(self) -> None:
        for key, relative in CANONICAL_PACKAGE_PATHS.items():
            path = self.workspace / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(self.package_payloads[key])
            self.package_records[key] = {
                "path": relative,
                "sha256": self.sha(path),
                "size_bytes": path.stat().st_size,
            }
        for role, relative in PHONE_CANDIDATE_ALIASES.items():
            path = self.workspace / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(self.package_payloads[("phone", role)])

    def stage_mapping(self) -> dict[str, str]:
        evidence: dict[str, str] = {}
        for role in MAPPING_ROLES:
            code = self.version_codes["wear"] if role == "wear-os" else self.version_codes["phone"]
            stamp = f"{self.app_version}+{code}"
            role_root = self.workspace / ".artifacts" / "private-release-symbols" / role / stamp
            role_root.mkdir(parents=True, exist_ok=True)
            mapping = role_root / "mapping.txt"
            mapping.write_text(f"mapping:{role}:{stamp}\n", encoding="utf-8")
            (role_root / "libapp.so.symbols").write_text(f"symbols:{role}\n", encoding="utf-8")
            evidence[role] = self.sha(mapping)
        return evidence

    def produced_receipt(
        self,
        form: str,
        role: str,
        record: dict[str, str | int],
        version_code: int,
    ) -> tuple[str, str]:
        receipt = {
            **self.base_receipt("winsvpn-android-produced-artifact-receipt-v1"),
            "form_factor": form,
            "role": role,
            "candidate_id": FORM_FACTOR_CANDIDATES[form],
            "path": record["path"],
            "sha256": record["sha256"],
            "size_bytes": record["size_bytes"],
            "version_name": self.app_version,
            "version_code": version_code,
        }
        return self.json_receipt(f"{form}-{role}-produced.json", receipt)

    def vpn_runtime_receipt(self, form: str, artifact_sha256: str, version_code: int) -> tuple[str, str]:
        receipt = {
            **self.base_receipt("winsvpn-android-form-factor-runtime-receipt-v1"),
            "form_factor": form,
            "kind": "live_vpn",
            "candidate_id": FORM_FACTOR_CANDIDATES[form],
            "artifact_sha256": artifact_sha256,
            "version_name": self.app_version,
            "version_code": version_code,
            "primary_transport": "winn_v3",
            "fallback_transports": ["winn_v1_awg", "winn_v1_xray"],
            "winn_v3_session_observed": True,
            "source_only": False,
            "passed": True,
        }
        return self.json_receipt(f"{form}-runtime.json", receipt)

    def wear_runtime_receipt(self, wear_sha256: str, phone_sha256: str) -> tuple[str, str]:
        receipt = {
            **self.base_receipt("winsvpn-android-wear-runtime-receipt-v1"),
            "form_factor": "wear",
            "kind": "pairing_runtime",
            "candidate_id": FORM_FACTOR_CANDIDATES["wear"],
            "artifact_sha256": wear_sha256,
            "version_name": self.app_version,
            "version_code": self.version_codes["wear"],
            "companion_phone_artifact_sha256": phone_sha256,
            "pairing_observed": True,
            "source_only": False,
            "passed": True,
        }
        return self.json_receipt("wear-runtime.json", receipt)

    def form_factor_closure(self) -> dict:
        self.stage_produced_packages()
        mapping = self.stage_mapping()
        matrix = {}
        for form, roles in (
            ("phone", ("apk", "aab")),
            ("tv", ("apk", "aab")),
            ("wear", ("aab",)),
        ):
            packages = {}
            for role in roles:
                record = self.package_records[(form, role)]
                receipt_path, receipt_hash = self.produced_receipt(
                    form, role, record, self.version_codes[form]
                )
                packages[role] = {
                    "role": role,
                    "path": record["path"],
                    "sha256": record["sha256"],
                    "size_bytes": record["size_bytes"],
                    "receipt_path": receipt_path,
                    "receipt_sha256": receipt_hash,
                }
            if form == "wear":
                runtime_artifact = self.package_records[("wear", "aab")]["sha256"]
                runtime_path, runtime_hash = self.wear_runtime_receipt(
                    str(runtime_artifact),
                    str(self.package_records[("phone", "apk")]["sha256"]),
                )
                kind = "pairing_runtime"
            else:
                runtime_artifact = self.package_records[(form, "apk")]["sha256"]
                runtime_path, runtime_hash = self.vpn_runtime_receipt(
                    form,
                    str(runtime_artifact),
                    self.version_codes[form],
                )
                kind = "live_vpn"
            matrix[form] = {
                "form_factor": form,
                "candidate_id": FORM_FACTOR_CANDIDATES[form],
                "version_name": self.app_version,
                "version_code": self.version_codes[form],
                "packages": packages,
                "runtime": {
                    "kind": kind,
                    "artifact_sha256": runtime_artifact,
                    "source_only": False,
                    "receipt_path": runtime_path,
                    "receipt_sha256": runtime_hash,
                    "passed": True,
                },
            }
        phone_aab = self.package_records[("phone", "aab")]
        tv_apk = self.package_records[("tv", "apk")]
        tv_aab = self.package_records[("tv", "aab")]
        wear_aab = self.package_records[("wear", "aab")]
        return {
            "application_id": "org.winsvpn.app",
            "phone_aab_sha256": phone_aab["sha256"],
            "phone_aab_size_bytes": phone_aab["size_bytes"],
            "tv_apk_sha256": tv_apk["sha256"],
            "tv_apk_size_bytes": tv_apk["size_bytes"],
            "tv_aab_sha256": tv_aab["sha256"],
            "tv_aab_size_bytes": tv_aab["size_bytes"],
            "wear_aab_sha256": wear_aab["sha256"],
            "wear_aab_size_bytes": wear_aab["size_bytes"],
            "private_symbol_mapping_sha256": mapping,
            "mapping_owner_blocked": True,
            "listing_inventory": {
                "phone": OWNER_BLOCKED_LISTING,
                "tv": OWNER_BLOCKED_LISTING,
                "wear": OWNER_BLOCKED_LISTING,
            },
            "form_factor_matrix": matrix,
        }

    def forcing(self, lane_id: str, required: bool, direct_first_hop_port: int) -> dict:
        before = hashlib.sha256(f"before:{lane_id}".encode()).hexdigest()
        operation = str(uuid.uuid4())
        restore = {
            **self.base_receipt("winsvpn-android-forcing-receipt-v1"),
            "phase": "restore",
            "operation_id": operation,
            "lane_id": lane_id,
            "blocked_udp_port": direct_first_hop_port,
            "before_state_sha256": before,
            "after_state_sha256": before,
            "passed": True,
        }
        restore_path, restore_hash = self.json_receipt(f"{lane_id}-restore.json", restore)
        if required:
            apply = {
                **self.base_receipt("winsvpn-android-forcing-receipt-v1"),
                "phase": "apply",
                "operation_id": operation,
                "lane_id": lane_id,
                "blocked_udp_port": direct_first_hop_port,
                "before_state_sha256": before,
                "applied_state_sha256": hashlib.sha256(f"applied:{lane_id}".encode()).hexdigest(),
                "passed": True,
            }
            apply_path, apply_hash = self.json_receipt(f"{lane_id}-apply.json", apply)
        else:
            apply_path, apply_hash = "", ""
        return {
            "required": required,
            "blocked_udp_port": direct_first_hop_port,
            "apply_passed": required,
            "restore_passed": True,
            "before_state_sha256": before,
            "after_state_sha256": before,
            "apply_receipt_path": apply_path,
            "apply_receipt_sha256": apply_hash,
            "restore_receipt_path": restore_path,
            "restore_receipt_sha256": restore_hash,
        }

    def lane(
        self,
        lane_id: str,
        kind: str,
        port: int,
        security: str,
        *,
        direct_first_hop_port: int | None = None,
    ) -> dict:
        is_xray = kind in {"xray", "double_vpn_xray"}
        is_double = kind in {"double_vpn_direct", "double_vpn_xray"}
        protocol = "tcp" if is_xray else "udp"
        if direct_first_hop_port is None:
            direct_first_hop_port = 9210 if is_double else 9110
        advertised = (
            [{"protocol": "tcp", "port": 80, "security": "none"},
             {"protocol": "tcp", "port": 8443, "security": "tls"}]
            if is_double else
            [{"protocol": "tcp", "port": 80, "security": "none"},
             {"protocol": "tcp", "port": 443, "security": "tls"}]
        )
        canonical = "".join(
            f"tcp|{item['port']}|{item['security']}\n"
            for item in sorted(advertised, key=lambda item: (item["port"], item["security"]))
        )
        mode_manifest = hashlib.sha256(canonical.encode()).hexdigest()
        inventory_digest = "6" * 64
        remote = {
            **self.base_receipt("winsvpn-android-remote-route-observation-v1"),
            "mode": "double_vpn" if is_double else "node",
            "lane_kind": "xray" if is_xray else "direct",
            "selected_protocol": protocol,
            "selected_port": port,
            "selected_security": security,
            "direct_first_hop_port": direct_first_hop_port,
            "selected_packets": 5,
            "selected_bytes": 4096,
            "direct_packets": 5 if not is_xray else 0,
            "direct_bytes": 4096 if not is_xray else 0,
            "direct_block_packets": 3 if is_xray else 0,
            "route_inventory_sha256": inventory_digest,
            "mode_xray_manifest_sha256": mode_manifest,
            "passed": True,
        }
        remote_path, remote_hash = self.json_receipt(f"{lane_id}-remote.json", remote)
        receipt = {
            **self.base_receipt("winsvpn-android-route-receipt-v1"),
            "lane_id": lane_id,
            "protocol": protocol,
            "port": port,
            "direct_first_hop_port": direct_first_hop_port,
            "security": security,
            "double_vpn": is_double,
            "double_vpn_core_id_sha256": "4" * 64 if is_double else hashlib.sha256(b"").hexdigest(),
            "double_vpn_exit_slug_sha256": "5" * 64 if is_double else hashlib.sha256(b"").hexdigest(),
            "route_inventory_sha256": inventory_digest,
            "mode_xray_manifest_sha256": mode_manifest,
            "remote_observation_sha256": remote_hash,
            "connected_observed": True,
        }
        receipt_path, receipt_hash = self.json_receipt(f"{lane_id}-route.json", receipt)
        return {
            "lane_id": lane_id,
            "kind": kind,
            "protocol": protocol,
            "port": port,
            "direct_first_hop_port": direct_first_hop_port,
            "security": security,
            "double_vpn": is_double,
            "double_vpn_core_id_sha256": "4" * 64 if is_double else hashlib.sha256(b"").hexdigest(),
            "double_vpn_exit_slug_sha256": "5" * 64 if is_double else hashlib.sha256(b"").hexdigest(),
            "route_inventory_sha256": inventory_digest,
            "mode_xray_manifest_sha256": mode_manifest,
            "remote_observation_path": remote_path,
            "remote_observation_sha256": remote_hash,
            "connected_passed": True,
            "tunnel_validated": True,
            "tun_rx_delta": 4096,
            "tun_tx_delta": 2048,
            "protected_egress_sha256": self.direct_egress,
            "xray_process_observed": is_xray,
            "route_receipt_path": receipt_path,
            "route_receipt_sha256": receipt_hash,
            "forcing": self.forcing(lane_id, is_xray, direct_first_hop_port),
            "residue": {
                "tun_absent": True,
                "vpn_service_absent": True,
                "xray_absent": True,
                "passed": True,
            },
        }

    def machine(self) -> dict:
        signature = {
            **self.base_receipt("winsvpn-android-apk-signature-receipt-v1"),
            "artifact_sha256": self.artifact_hash,
            "artifact_size_bytes": self.artifact.stat().st_size,
            "installed_base_apk_sha256": self.artifact_hash,
            "installed_base_apk_size_bytes": self.artifact.stat().st_size,
            "artifact_signer_sha256": EXPECTED_SIGNER_SHA256,
            "installed_signer_sha256": EXPECTED_SIGNER_SHA256,
            "apksigner_verified": True,
        }
        signature_path, signature_hash = self.json_receipt("signature.json", signature)
        logcat = self.root / "startup.log"
        logcat.write_text("07-18 I/Flutter: started\n", encoding="utf-8")
        screenshot = self.root / "map.png"
        screenshot.write_bytes(b"PNG" + b"x" * 2048)
        split = {
            **self.base_receipt("winsvpn-android-split-browser-receipt-v1"),
            "excluded_package": "com.android.chrome",
            "protected_package": "com.sec.android.app.sbrowser",
            "baseline_egress_sha256": self.baseline_egress,
            "excluded_egress_sha256": self.baseline_egress,
            "protected_egress_sha256": self.direct_egress,
            "selection_ui_sha256": "3" * 64,
            "passed": True,
        }
        split_path, split_hash = self.json_receipt("split.json", split)
        leak = {
            **self.base_receipt("winsvpn-android-leak-receipt-v1"),
            "dns_servers": ["10.8.1.1"],
            "protected_canary_count": 2,
            "dns_leak_passed": True,
            "ipv4_leak_passed": True,
            "ipv6_leak_passed": True,
        }
        leak_path, leak_hash = self.json_receipt("leak.json", leak)
        network = {
            **self.base_receipt("winsvpn-android-network-change-receipt-v1"),
            "before_underlying_transport": "wifi",
            "after_underlying_transport": "cellular",
            "vpn_continuously_present": True,
            "tun_rx_delta": 8192,
            "tun_tx_delta": 4096,
            "protected_egress_sha256": self.direct_egress,
            "dns_servers": ["10.8.1.1"],
            "dns_leak_passed": True,
            "ipv4_leak_passed": True,
            "ipv6_leak_passed": True,
            "wifi_state_restored": True,
            "mobile_data_state_restored": True,
            "passed": True,
        }
        network_path, network_hash = self.json_receipt("network.json", network)
        teardown = {
            **self.base_receipt("winsvpn-android-global-teardown-receipt-v1"),
            "tun_absent": True,
            "vpn_service_absent": True,
            "xray_absent": True,
            "wifi_state_restored": True,
            "mobile_data_state_restored": True,
            "passed": True,
        }
        teardown_path, teardown_hash = self.json_receipt("teardown.json", teardown)
        rollback = {
            **self.base_receipt("winsvpn-android-global-rollback-receipt-v1"),
            "before_state_sha256": "6" * 64,
            "after_state_sha256": "6" * 64,
            "remote_forcing_absent": True,
            "network_state_restored": True,
            "split_state_restored": True,
            "double_vpn_state_restored": True,
            "passed": True,
        }
        rollback_path, rollback_hash = self.json_receipt("rollback.json", rollback)
        return {
            "schema_version": 2,
            "contract": "winsvpn-android-release-machine-evidence-v2",
            "platform": "android",
            "app_version": "1.0.14",
            "build_number": "14",
            "artifact_sha256": self.artifact_hash,
            "artifact_size_bytes": self.artifact.stat().st_size,
            "release_input_index_sha256": "7" * 64,
            "platform_manifest_sha256": "8" * 64,
            "artifact_input_fingerprint_sha256": "9" * 64,
            "build_receipt_sha256": "a" * 64,
            "producer_contract_sha256": "b" * 64,
            **self.form_factor_closure(),
            "artifact_signer_sha256": EXPECTED_SIGNER_SHA256,
            "installed_base_apk_sha256": self.artifact_hash,
            "installed_base_apk_size_bytes": self.artifact.stat().st_size,
            "installed_signer_sha256": EXPECTED_SIGNER_SHA256,
            "artifact_signature_receipt_path": signature_path,
            "artifact_signature_receipt_sha256": signature_hash,
            "clean_uninstall_passed": True,
            "install_passed": True,
            "run_id": str(self.run_id),
            "captured_at_utc": NOW,
            "secret_material_redacted": True,
            "startup": {
                "pid": 1234,
                "logcat_path": logcat.name,
                "logcat_sha256": self.sha(logcat),
                "fatal_scan_passed": True,
            },
            "direct_awg_port": 9110,
            "double_vpn_direct_port": 9210,
            "advertised_xray_routes": [
                {"protocol": "tcp", "port": 80, "security": "none"},
                {"protocol": "tcp", "port": 443, "security": "tls"},
            ],
            "double_vpn_advertised_xray_routes": [
                {"protocol": "tcp", "port": 80, "security": "none"},
                {"protocol": "tcp", "port": 8443, "security": "tls"},
            ],
            "lanes": [
                self.lane("direct", "direct_awg", 9110, "none"),
                self.lane("xray-80", "xray", 80, "none"),
                self.lane("xray-443", "xray", 443, "tls"),
                self.lane("double-direct", "double_vpn_direct", 9210, "none"),
                self.lane("double-xray", "double_vpn_xray", 80, "none"),
                self.lane("double-xray-8443", "double_vpn_xray", 8443, "tls"),
            ],
            "split_browser": {
                "excluded_package": "com.android.chrome",
                "protected_package": "com.sec.android.app.sbrowser",
                "baseline_egress_sha256": self.baseline_egress,
                "excluded_egress_sha256": self.baseline_egress,
                "protected_egress_sha256": self.direct_egress,
                "selection_receipt_path": split_path,
                "selection_receipt_sha256": split_hash,
                "passed": True,
            },
            "leak": {
                "dns_servers": ["10.8.1.1"],
                "protected_canary_count": 2,
                "dns_leak_passed": True,
                "ipv4_leak_passed": True,
                "ipv6_leak_passed": True,
                "receipt_path": leak_path,
                "receipt_sha256": leak_hash,
            },
            "map_visual": {
                "screenshot_path": screenshot.name,
                "screenshot_sha256": self.sha(screenshot),
                "radius_miles": 50,
                "city_labels_visible": True,
                "target_marker_visible": True,
                "viewport_not_world_zoom": True,
            },
            "network_change": {
                **{key: value for key, value in network.items() if key not in {
                    "schema_version", "contract", "captured_at_utc", "secret_material_redacted"
                }},
                "receipt_path": network_path,
                "receipt_sha256": network_hash,
            },
            "teardown": {
                **{key: value for key, value in teardown.items() if key not in {
                    "schema_version", "contract", "captured_at_utc", "secret_material_redacted"
                }},
                "receipt_path": teardown_path,
                "receipt_sha256": teardown_hash,
            },
            "rollback": {
                **{key: value for key, value in rollback.items() if key not in {
                    "schema_version", "contract", "captured_at_utc", "secret_material_redacted"
                }},
                "receipt_path": rollback_path,
                "receipt_sha256": rollback_hash,
            },
        }

    def binding(self, machine: dict) -> dict[str, str]:
        return {
            field: machine[field]
            for field in (
                "release_input_index_sha256",
                "platform_manifest_sha256",
                "artifact_input_fingerprint_sha256",
                "build_receipt_sha256",
                "producer_contract_sha256",
            )
        } | {
            "shared_revision": "sr1",
            "release_input_index_path": ".artifacts/test/RELEASE_INPUT_INDEX.json",
            "build_receipt_path": ".artifacts/test/android-build-receipt.json",
        }

    def evidence_index(self, machine: dict, *, created_at: str = NOW) -> tuple[pathlib.Path, str]:
        machine_path = self.root / "machine-evidence.json"
        machine_path.write_text(json.dumps(machine, sort_keys=True) + "\n", encoding="utf-8")
        entries = []
        for path in sorted(self.root.iterdir(), key=lambda item: item.name):
            if path.suffix.lower() == ".json":
                value = json.loads(path.read_text(encoding="utf-8"))
                contract = value["contract"]
            elif path.name == "map.png":
                contract = "winsvpn-android-map-screenshot-v1"
            elif path.name == "startup.log":
                contract = "winsvpn-android-startup-logcat-v1"
            else:
                raise AssertionError(f"unexpected fixture evidence: {path}")
            entries.append({
                "path": path.name,
                "sha256": self.sha(path),
                "size_bytes": path.stat().st_size,
                "contract": contract,
            })
        helpers = {
            name: {"path": relative, "sha256": self.sha(REPO / relative)}
            for name, relative in HELPER_PATHS.items()
        }
        binding = self.binding(machine)
        index = {
            "schema_version": 1,
            "contract": INDEX_CONTRACT,
            "run_id": machine["run_id"],
            "created_at_utc": created_at,
            "machine_evidence_path": machine_path.name,
            "map_screenshot_path": "map.png",
            "files": entries,
            "binding": {
                "artifact": {
                    "path": self.artifact.resolve().relative_to(REPO.resolve()).as_posix(),
                    "sha256": self.artifact_hash,
                    "size_bytes": self.artifact.stat().st_size,
                },
                "release_inputs": {
                    "path": binding["release_input_index_path"],
                    "sha256": binding["release_input_index_sha256"],
                    "platform_manifest_sha256": binding["platform_manifest_sha256"],
                    "artifact_input_fingerprint_sha256": binding["artifact_input_fingerprint_sha256"],
                    "shared_revision": binding["shared_revision"],
                },
                "build_receipt": {
                    "path": binding["build_receipt_path"],
                    "sha256": binding["build_receipt_sha256"],
                },
                "producer": {
                    "path": "tools/android_public_release_live_smoke.ps1",
                    "closure_sha256": binding["producer_contract_sha256"],
                },
            },
            "helpers": helpers,
            "secret_material_redacted": True,
        }
        index_path = self.root / "EVIDENCE_INDEX.json"
        index_path.write_text(json.dumps(index, sort_keys=True) + "\n", encoding="utf-8")
        return index_path, self.sha(index_path)


class AndroidReleaseMatrixEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        (REPO / ".artifacts").mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=REPO / ".artifacts")
        self.fixture = Fixture(pathlib.Path(self.temp.name))
        self.machine = self.fixture.machine()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def compile(self, machine: dict | None = None) -> dict:
        candidate = machine or self.machine
        binding = {
            field: candidate[field]
            for field in (
                "release_input_index_sha256",
                "platform_manifest_sha256",
                "artifact_input_fingerprint_sha256",
                "build_receipt_sha256",
                "producer_contract_sha256",
            )
        }
        return compile_evidence(
            candidate, self.fixture.root, self.fixture.artifact, binding, "d" * 64,
            self.fixture.workspace,
        )

    def load_bundle(self, index_path: pathlib.Path, digest: str) -> tuple:
        return load_evidence_bundle(
            REPO,
            index_path,
            self.fixture.artifact,
            self.fixture.binding(self.machine),
            expected_index_sha256=digest,
            expected_run_id=self.machine["run_id"],
        )

    def test_complete_machine_evidence_compiles_native_v2(self) -> None:
        result = self.compile()
        self.assertEqual(result["contract"], "winsvpn-native-live-smoke-v2")
        self.assertEqual(result["evidence_bundle_index_sha256"], "d" * 64)
        self.assertEqual(result["direct_awg"], {"protocol": "udp", "port": 9110, "passed": True})
        self.assertEqual(len(result["tested_xray_routes"]), 2)
        self.assertNotIn("private_symbol_mapping_sha256", result)
        self.assertNotIn("form_factor_matrix", result)
        self.assertNotIn("listing_inventory", result)

    def assert_rejected(self, mutate) -> None:
        candidate = copy.deepcopy(self.machine)
        mutate(candidate)
        with self.assertRaises(EvidenceError):
            self.compile(candidate)

    def test_rejects_installed_apk_mismatch(self) -> None:
        self.assert_rejected(lambda value: value.__setitem__("installed_base_apk_sha256", "a" * 64))

    def test_rejects_missing_advertised_route_lane(self) -> None:
        self.assert_rejected(lambda value: value["lanes"].pop(2))

    def test_accepts_arbitrary_observed_core_first_hop_port(self) -> None:
        machine = copy.deepcopy(self.machine)
        machine["double_vpn_direct_port"] = 18437
        for lane in machine["lanes"]:
            if lane["kind"] not in {"double_vpn_direct", "double_vpn_xray"}:
                continue
            lane["direct_first_hop_port"] = 18437
            lane["forcing"]["blocked_udp_port"] = 18437
            remote = self.fixture.root / lane["remote_observation_path"]
            remote_value = json.loads(remote.read_text(encoding="utf-8"))
            remote_value["direct_first_hop_port"] = 18437
            if lane["kind"] == "double_vpn_direct":
                remote_value["selected_port"] = 18437
            remote.write_text(json.dumps(remote_value, sort_keys=True) + "\n", encoding="utf-8")
            lane["remote_observation_sha256"] = self.fixture.sha(remote)
            receipt = self.fixture.root / lane["route_receipt_path"]
            route_value = json.loads(receipt.read_text(encoding="utf-8"))
            route_value["direct_first_hop_port"] = 18437
            route_value["remote_observation_sha256"] = lane["remote_observation_sha256"]
            receipt.write_text(json.dumps(route_value, sort_keys=True) + "\n", encoding="utf-8")
            lane["route_receipt_sha256"] = self.fixture.sha(receipt)
            restore = self.fixture.root / lane["forcing"]["restore_receipt_path"]
            restore_value = json.loads(restore.read_text(encoding="utf-8"))
            restore_value["blocked_udp_port"] = 18437
            restore.write_text(json.dumps(restore_value, sort_keys=True) + "\n", encoding="utf-8")
            lane["forcing"]["restore_receipt_sha256"] = self.fixture.sha(restore)
            if lane["forcing"]["required"]:
                apply = self.fixture.root / lane["forcing"]["apply_receipt_path"]
                apply_value = json.loads(apply.read_text(encoding="utf-8"))
                apply_value["blocked_udp_port"] = 18437
                apply.write_text(json.dumps(apply_value, sort_keys=True) + "\n", encoding="utf-8")
                lane["forcing"]["apply_receipt_sha256"] = self.fixture.sha(apply)
            if lane["kind"] == "double_vpn_direct":
                lane["port"] = 18437
                route_value["port"] = 18437
                receipt.write_text(json.dumps(route_value, sort_keys=True) + "\n", encoding="utf-8")
                lane["route_receipt_sha256"] = self.fixture.sha(receipt)
        self.compile(machine)

    def test_rejects_double_lane_using_data_plane_port(self) -> None:
        self.assert_rejected(
            lambda value: value["lanes"][3].__setitem__("direct_first_hop_port", 9110)
        )

    def test_rejects_missing_double_advertised_route_lane(self) -> None:
        self.assert_rejected(lambda value: value["lanes"].pop(5))

    def test_rejects_double_xray_forcing_wrong_first_hop(self) -> None:
        self.assert_rejected(
            lambda value: value["lanes"][4]["forcing"].__setitem__("blocked_udp_port", 9110)
        )

    def test_rejects_double_lane_without_real_core_identity(self) -> None:
        self.assert_rejected(
            lambda value: value["lanes"][3].__setitem__(
                "double_vpn_core_id_sha256", hashlib.sha256(b"").hexdigest()
            )
        )

    def test_rejects_non_double_lane_with_double_identity(self) -> None:
        self.assert_rejected(
            lambda value: value["lanes"][0].__setitem__("double_vpn_core_id_sha256", "4" * 64)
        )

    def test_rejects_empty_egress_sentinel(self) -> None:
        self.assert_rejected(
            lambda value: value["lanes"][0].__setitem__(
                "protected_egress_sha256", hashlib.sha256(b"").hexdigest()
            )
        )

    def test_rejects_route_security_receipt_contradiction(self) -> None:
        self.assert_rejected(lambda value: value["lanes"][1].__setitem__("security", "tls"))

    def test_rejects_unrestored_forcing_state(self) -> None:
        self.assert_rejected(lambda value: value["lanes"][1]["forcing"].__setitem__("after_state_sha256", "f" * 64))

    def test_rejects_unforced_xray_lane(self) -> None:
        self.assert_rejected(lambda value: value["lanes"][1]["forcing"].__setitem__("required", False))

    def test_rejects_split_same_egress(self) -> None:
        self.assert_rejected(lambda value: value["split_browser"].__setitem__("protected_egress_sha256", self.fixture.baseline_egress))

    def test_rejects_residue(self) -> None:
        self.assert_rejected(lambda value: value["lanes"][0]["residue"].__setitem__("xray_absent", False))

    def test_rejects_wrong_signer(self) -> None:
        self.assert_rejected(lambda value: value.__setitem__("artifact_signer_sha256", "b" * 64))

    def test_rejects_startup_log_hash_mismatch(self) -> None:
        self.assert_rejected(lambda value: value["startup"].__setitem__("logcat_sha256", "c" * 64))

    def test_rejects_network_change_without_vpn_continuity(self) -> None:
        self.assert_rejected(
            lambda value: value["network_change"].__setitem__("vpn_continuously_present", False)
        )

    def test_rejects_global_teardown_residue(self) -> None:
        self.assert_rejected(lambda value: value["teardown"].__setitem__("tun_absent", False))

    def test_rejects_global_rollback_state_mismatch(self) -> None:
        self.assert_rejected(
            lambda value: value["rollback"].__setitem__("after_state_sha256", "c" * 64)
        )

    def test_rejects_stale_producer_binding(self) -> None:
        candidate = copy.deepcopy(self.machine)
        binding = {
            field: candidate[field]
            for field in (
                "release_input_index_sha256",
                "platform_manifest_sha256",
                "artifact_input_fingerprint_sha256",
                "build_receipt_sha256",
                "producer_contract_sha256",
            )
        }
        binding["producer_contract_sha256"] = "c" * 64
        with self.assertRaises(EvidenceError):
            compile_evidence(
                candidate, self.fixture.root, self.fixture.artifact, binding, "d" * 64,
                self.fixture.workspace,
            )

    def test_indexed_bundle_loads_and_binds_machine_once(self) -> None:
        path, digest = self.fixture.evidence_index(self.machine)
        machine, root, actual, map_path = self.load_bundle(path, digest)
        self.assertEqual(machine["run_id"], self.machine["run_id"])
        self.assertEqual(root, self.fixture.root.resolve())
        self.assertEqual(actual, digest)
        self.assertEqual(map_path.name, "map.png")

    def test_indexed_bundle_compiles_native_v2(self) -> None:
        path, digest = self.fixture.evidence_index(self.machine)
        machine, root, actual, _map_path = self.load_bundle(path, digest)
        binding = {
            field: machine[field]
            for field in (
                "release_input_index_sha256",
                "platform_manifest_sha256",
                "artifact_input_fingerprint_sha256",
                "build_receipt_sha256",
                "producer_contract_sha256",
            )
        }
        result = compile_evidence(
            machine, root, self.fixture.artifact, binding, actual, self.fixture.workspace
        )
        self.assertEqual(result["contract"], "winsvpn-native-live-smoke-v2")
        self.assertEqual(result["evidence_bundle_index_sha256"], digest)
        self.assertEqual(result["artifact_sha256"], self.fixture.artifact_hash)

    def test_rejects_stale_runtime_receipt_from_older_run(self) -> None:
        receipt = self.fixture.root / self.machine["form_factor_matrix"]["tv"]["runtime"]["receipt_path"]
        value = json.loads(receipt.read_text(encoding="utf-8"))
        stale = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=13)).isoformat().replace("+00:00", "Z")
        value["captured_at_utc"] = stale
        receipt.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        self.machine["form_factor_matrix"]["tv"]["runtime"]["receipt_sha256"] = self.fixture.sha(receipt)
        with self.assertRaises(EvidenceError):
            self.compile()

    def test_rejects_unindexed_extra_file(self) -> None:
        path, digest = self.fixture.evidence_index(self.machine)
        (self.fixture.root / "fabricated.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaises(EvidenceError):
            self.load_bundle(path, digest)

    def test_rejects_indexed_file_changed_after_seal(self) -> None:
        path, digest = self.fixture.evidence_index(self.machine)
        (self.fixture.root / "startup.log").write_text("fabricated\n", encoding="utf-8")
        with self.assertRaises(EvidenceError):
            self.load_bundle(path, digest)

    def test_rejects_index_digest_mismatch(self) -> None:
        path, _ = self.fixture.evidence_index(self.machine)
        with self.assertRaises(EvidenceError):
            self.load_bundle(path, "e" * 64)

    def test_rejects_fabricated_helper_binding(self) -> None:
        path, _ = self.fixture.evidence_index(self.machine)
        index = json.loads(path.read_text(encoding="utf-8"))
        index["helpers"]["remote_guard"]["sha256"] = "e" * 64
        path.write_text(json.dumps(index, sort_keys=True) + "\n", encoding="utf-8")
        with self.assertRaises(EvidenceError):
            self.load_bundle(path, self.fixture.sha(path))

    def test_rejects_stale_evidence_index(self) -> None:
        stale = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=4)).isoformat().replace("+00:00", "Z")
        path, digest = self.fixture.evidence_index(self.machine, created_at=stale)
        with self.assertRaises(EvidenceError):
            self.load_bundle(path, digest)

    def test_rejects_source_only_runtime(self) -> None:
        self.assert_rejected(
            lambda value: value["form_factor_matrix"]["phone"]["runtime"].__setitem__(
                "source_only", True
            )
        )

    def test_rejects_mixed_tv_artifact_using_phone_hash(self) -> None:
        phone_apk = self.fixture.package_records[("phone", "apk")]["sha256"]

        def mutate(value) -> None:
            value["form_factor_matrix"]["tv"]["packages"]["apk"]["sha256"] = phone_apk
            value["tv_apk_sha256"] = phone_apk
            value["form_factor_matrix"]["tv"]["runtime"]["artifact_sha256"] = phone_apk

        self.assert_rejected(mutate)

    def test_rejects_duplicate_produced_hashes(self) -> None:
        phone_aab = self.fixture.package_records[("phone", "aab")]["sha256"]

        def mutate(value) -> None:
            value["form_factor_matrix"]["tv"]["packages"]["aab"]["sha256"] = phone_aab
            value["tv_aab_sha256"] = phone_aab

        self.assert_rejected(mutate)

    def test_rejects_stale_machine_captured_at(self) -> None:
        stale = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=9)).isoformat().replace("+00:00", "Z")
        self.assert_rejected(lambda value: value.__setitem__("captured_at_utc", stale))

    def test_rejects_wear_vpn_runtime(self) -> None:
        self.assert_rejected(
            lambda value: value["form_factor_matrix"]["wear"]["runtime"].__setitem__(
                "kind", "live_vpn"
            )
        )

    def test_rejects_phone_runtime_standing_in_for_tv(self) -> None:
        def mutate(value) -> None:
            phone_runtime = value["form_factor_matrix"]["phone"]["runtime"]
            value["form_factor_matrix"]["tv"]["runtime"]["receipt_path"] = phone_runtime["receipt_path"]
            value["form_factor_matrix"]["tv"]["runtime"]["receipt_sha256"] = phone_runtime["receipt_sha256"]

        self.assert_rejected(mutate)

    def test_rejects_missing_wear_produced_aab(self) -> None:
        wear = self.fixture.workspace / CANONICAL_PACKAGE_PATHS[("wear", "aab")]
        wear.unlink()
        with self.assertRaisesRegex(EvidenceError, OWNER_BLOCKED_ABSENT_PACKAGES):
            self.compile()

    def test_rejects_mapping_file_in_public_bundle(self) -> None:
        (self.fixture.root / "mapping.txt").write_text("leaked-mapping\n", encoding="utf-8")
        with self.assertRaises(EvidenceError):
            self.compile()

    def test_rejects_missing_mapping_as_owner_blocked(self) -> None:
        role_root = (
            self.fixture.workspace / ".artifacts" / "private-release-symbols"
            / "wear-os" / f"{self.fixture.app_version}+{self.fixture.version_codes['wear']}"
        )
        (role_root / "mapping.txt").unlink()
        with self.assertRaisesRegex(EvidenceError, OWNER_BLOCKED_MAPPING):
            self.compile()

    def test_rejects_listing_inventory_claimed_present(self) -> None:
        self.assert_rejected(
            lambda value: value["listing_inventory"].__setitem__("tv", "present")
        )

    def test_rejects_source_only_produced_hashes_without_bytes(self) -> None:
        path = self.fixture.workspace / CANONICAL_PACKAGE_PATHS[("tv", "aab")]
        path.unlink()
        with self.assertRaisesRegex(EvidenceError, OWNER_BLOCKED_ABSENT_PACKAGES):
            self.compile()

    def test_rejects_wrong_winn_transport_order(self) -> None:
        receipt = self.fixture.root / self.machine["form_factor_matrix"]["phone"]["runtime"]["receipt_path"]
        value = json.loads(receipt.read_text(encoding="utf-8"))
        value["fallback_transports"] = ["winn_v1_xray", "winn_v1_awg"]
        receipt.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        self.machine["form_factor_matrix"]["phone"]["runtime"]["receipt_sha256"] = self.fixture.sha(receipt)
        with self.assertRaises(EvidenceError):
            self.compile()

    def test_rejects_mixed_form_factor_version_codes(self) -> None:
        self.assert_rejected(
            lambda value: value["form_factor_matrix"]["tv"].__setitem__(
                "version_code", self.fixture.version_codes["phone"]
            )
        )

    def test_rejects_flavored_phone_apk_mismatch(self) -> None:
        flavored = self.fixture.workspace / PHONE_CANDIDATE_ALIASES["apk"]
        flavored.write_bytes(b"other-phone-candidate")
        with self.assertRaises(EvidenceError):
            self.compile()

    def test_machine_evidence_cli_bypass_is_removed(self) -> None:
        result = subprocess.run(
            [sys.executable, str(REPO / "tools" / "android_release_matrix_evidence.py"),
             "--machine-evidence", "fabricated.json"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=30,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrecognized arguments: --machine-evidence", result.stderr)


if __name__ == "__main__":
    unittest.main()
