#!/usr/bin/env python3
"""Fail-closed tests for Windows physical machine-evidence compilation."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
import uuid

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from windows_release_matrix_evidence import (
    BINDING_FIELDS,
    EvidenceError,
    IDENTITY_CONTRACT,
    PAYLOAD_CONTRACT,
    PE_MACHINE_ARM64,
    PE_MACHINE_X64,
    PE_MACHINE_X86,
    RUNTIME_CONTRACT,
    WINN_V1_AWG_CONTRACT,
    WINN_V1_XRAY_CONTRACT,
    WINN_V3_CONTRACT,
    _clear_secure_cache,
    _reject_reparse_walk,
    compile_bundle,
    compile_evidence,
    pe_architecture,
    require_architecture_binding,
    architecture_binding_for,
    secure_read_once,
)
from public_release_live_smoke_common import validate_native_transcript


NOW = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
_OMIT = object()


def minimal_pe32_plus(
    machine: int = PE_MACHINE_X64,
    payload: bytes = b"winsvpn",
    minimum: int = 2048,
) -> bytes:
    dos = bytearray(128)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = (128).to_bytes(4, "little")
    coff = machine.to_bytes(2, "little") + (0).to_bytes(2, "little")
    coff += (0).to_bytes(4, "little") * 3
    coff += (240).to_bytes(2, "little") + (0x0022).to_bytes(2, "little")
    optional = bytearray(240)
    optional[0:2] = (0x20B).to_bytes(2, "little")
    optional[36:40] = (512).to_bytes(4, "little")
    optional[108:112] = (16).to_bytes(4, "little")
    cert = bytearray(8 + len(payload))
    cert[0:4] = (8 + len(payload)).to_bytes(4, "little")
    cert[4:6] = (0x0200).to_bytes(2, "little")
    cert[6:8] = (0x0002).to_bytes(2, "little")
    cert[8:] = payload
    while len(cert) % 8:
        cert.append(0)
    cert[0:4] = len(cert).to_bytes(4, "little")
    optional[144:148] = (512).to_bytes(4, "little")
    optional[148:152] = len(cert).to_bytes(4, "little")
    headers = bytes(dos) + b"PE\0\0" + coff + bytes(optional)
    blob = headers.ljust(512, b"\x00") + bytes(cert)
    if len(blob) < minimum:
        blob += b"\x00" * (minimum - len(blob))
    return blob


class Fixture:
    def __init__(self, root: pathlib.Path, architecture: str = "x64") -> None:
        self.run_id = str(uuid.uuid4())
        self.root = root / self.run_id
        self.root.mkdir()
        self.architecture = architecture
        self.pe_machine = PE_MACHINE_X64 if architecture == "x64" else PE_MACHINE_ARM64
        self.artifact = self.root / "WinsVPN-Setup.exe"
        self.artifact.write_bytes(
            minimal_pe32_plus(self.pe_machine, b"installer", 2048)
        )
        self.map = self.root / "map.png"
        self.map.write_bytes(b"\x89PNG\r\n\x1a\n" + b"map" * 1024)
        self.rollback = self.root / "rollback.exe"
        self.rollback.write_bytes(
            minimal_pe32_plus(self.pe_machine, b"rollback", 2048)
        )
        self.gui = b"exact-gui"
        self.service = b"exact-service"
        self.awg_engine = b"exact-awg-engine"
        self.bindings = {
            field: hashlib.sha256(field.encode()).hexdigest()
            for field in BINDING_FIELDS
        }
        self.collector_closure = self.digest("collector-closure")
        self.sequence = 0

    @staticmethod
    def digest(data: bytes | str) -> str:
        if isinstance(data, str):
            data = data.encode()
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def sha(path: pathlib.Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def write_json(self, name: str, value: dict) -> dict[str, str]:
        path = self.root / name
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        return {"path": name, "sha256": self.sha(path)}

    def base(self, contract: str) -> dict:
        self.sequence += 1
        return {
            "schema_version": 1,
            "contract": contract,
            "run_id": self.run_id,
            "captured_at_utc": NOW,
            "secret_material_redacted": True,
            **self.bindings,
            "collector_closure_sha256": self.collector_closure,
            "artifact_sha256": self.sha(self.artifact),
            "step_nonce": str(uuid.uuid4()),
            "sequence": self.sequence,
            "started_at_utc": NOW,
            "finished_at_utc": NOW,
        }

    def receipt(self, name: str, contract: str, values: dict) -> dict[str, str]:
        return self.write_json(name, {**self.base(contract), **values})

    def architecture_fields(self) -> dict:
        return {
            "architecture": self.architecture,
            "pe_machine": self.pe_machine,
            "native_architecture": self.architecture,
            "os_architecture": "X64" if self.architecture == "x64" else "Arm64",
            "process_wow64": False,
            "source_only": False,
            "release_identity": "1.0.14+29",
        }

    def lane(self, lane_id: str, kind: str, port: int, security: str) -> dict:
        core = kind.startswith("core_")
        xray = kind.endswith("_xray")
        direct_port = 9210 if core else 9110
        protocol = "tcp" if xray else "udp"
        lane = {
            "lane_id": lane_id,
            "kind": kind,
            "protocol": protocol,
            "port": port,
            "direct_first_hop_port": direct_port,
            "security": security,
        }
        client = self.receipt(
            f"{lane_id}-client.json",
            "winsvpn-windows-client-route-receipt-v1",
            {
                **lane,
                "connect_label": "Connect VPN",
                "connect_role": 43,
                "disconnect_label": "Disconnect VPN",
                "disconnect_role": 43,
                "native_active_observed": True,
                "manager_running": True,
                "awg_engine_running": True,
                "legacy_tunnel_service_absent": True,
                "adapter_up": True,
                "protected_route_present": True,
                "xray_process_observed": xray,
                "rx_bytes_delta": 4096,
                "tx_bytes_delta": 2048,
                "protected_egress_sha256": self.digest("protected-egress"),
                "normal_teardown_proven": True,
                "residual_awg_engine_absent": True,
                "residual_legacy_service_absent": True,
                "residual_adapter_absent": True,
                "residual_xray_absent": True,
                "residual_routes_absent": True,
                "passed": True,
            },
        )
        server = self.receipt(
            f"{lane_id}-server.json",
            "winsvpn-windows-server-route-receipt-v1",
            {
                "lane_id": lane_id,
                "scope": "core" if core else "node",
                "protocol": protocol,
                "port": port,
                "direct_first_hop_port": direct_port,
                "security": security,
                "entry_ingress_packets": 5,
                "exit_egress_packets": 4,
                "handshake_advanced": True,
                "rx_bytes_delta": 4096,
                "tx_bytes_delta": 2048,
                "xray_upgrade_observed": xray,
                "suricata_drop_count": 0,
                "observer_identity_sha256": self.digest(f"observer:{'core' if core else 'node'}"),
                "observer_host_key_sha256": self.digest(f"host-key:{'core' if core else 'node'}"),
                "peer_public_key_sha256": self.digest(f"peer:{'core' if core else 'node'}"),
                "allowed_ip_set_sha256": self.digest(f"allowed-ip:{'core' if core else 'node'}"),
                "observation_window_nonce": str(uuid.uuid4()),
                "entry_counter_before_sha256": self.digest(f"entry-before:{lane_id}"),
                "entry_counter_after_sha256": self.digest(f"entry-after:{lane_id}"),
                "exit_counter_before_sha256": self.digest(f"exit-before:{lane_id}"),
                "exit_counter_after_sha256": self.digest(f"exit-after:{lane_id}"),
                "suricata_ruleset_sha256": self.digest(f"suricata:{'core' if core else 'node'}"),
                "expected_exit_identity_sha256": self.digest(f"exit:{'core' if core else 'node'}"),
                "observer_authenticated": True,
                "peer_bound": True,
                "expected_exit_observed": True,
                "passed": True,
            },
        )
        before = self.digest(f"before:{lane_id}")
        forcing = self.receipt(
            f"{lane_id}-forcing.json",
            "winsvpn-windows-forcing-receipt-v1",
            {
                "lane_id": lane_id,
                "required": xray,
                "blocked_udp_port": direct_port,
                "operation_id": str(uuid.uuid4()),
                "before_state_sha256": before,
                "applied_state_sha256": self.digest(f"applied:{lane_id}") if xray else before,
                "after_state_sha256": before,
                "apply_passed": xray,
                "restore_passed": True,
                "passed": True,
            },
        )
        return {
            **lane,
            "client_receipt": client,
            "server_receipt": server,
            "forcing_receipt": forcing,
        }

    def machine(self) -> dict:
        artifact_hash = self.sha(self.artifact)
        gui_hash = self.digest(self.gui)
        service_hash = self.digest(self.service)
        awg_engine_hash = self.digest(self.awg_engine)
        payload_hash = self.digest("payload-manifest")
        manifest = {
            "schema_version": 1,
            "created_utc": NOW,
            "release_identity": "1.0.14+29",
            "internal_candidate": "1.0.14-test",
            "publication_authorized": False,
            "stage": "owner-only-test-stage",
            "shared_revision": "test",
            "shared_fingerprint_sha256": self.digest("shared"),
            "native_fingerprint_sha256": self.digest("native"),
            "producer_fingerprint_sha256": self.digest("producer"),
            "artifact_input_fingerprint_sha256": self.digest("inputs"),
            "source_archive_sha256": self.digest("source"),
            "artifacts": [
                {"name": "WinsVPN-Setup.exe", "sha256": artifact_hash, "size": self.artifact.stat().st_size},
                {"name": "WinsVPN-Setup.exe.payload-manifest.json", "sha256": payload_hash, "size": 1234},
                {"name": "wins_vpn.exe", "sha256": gui_hash, "size": len(self.gui)},
                {"name": "wins_vpn_tunnel_service.exe", "sha256": service_hash, "size": len(self.service)},
                {"name": "winsvpn_awg_engine.exe", "sha256": awg_engine_hash, "size": len(self.awg_engine)},
            ],
            "payload_entry_count": 43,
            "payload_all_present_and_matching": True,
            "authenticode_status": "Valid",
            "unsigned_local_candidate": False,
        }
        candidate_ref = self.write_json("candidate-manifest.json", manifest)
        signature = self.receipt(
            "signature.json",
            "winsvpn-windows-signature-receipt-v1",
            {
                **self.architecture_fields(),
                "artifact_sha256": artifact_hash,
                "artifact_size_bytes": self.artifact.stat().st_size,
                "authenticode_status": "Valid",
                "signer_certificate_sha256": self.digest("signer"),
                "timestamp_certificate_sha256": self.digest("timestamp"),
                "signature_verified": True,
                "timestamp_verified": True,
            },
        )
        install = self.receipt(
            "install.json",
            "winsvpn-windows-install-receipt-v1",
            {
                **self.architecture_fields(),
                "artifact_sha256": artifact_hash,
                "candidate_manifest_sha256": candidate_ref["sha256"],
                "previous_version_uninstalled": True,
                "install_exit_code": 0,
                "installed_gui_sha256": gui_hash,
                "installed_gui_size_bytes": len(self.gui),
                "installed_service_sha256": service_hash,
                "installed_service_size_bytes": len(self.service),
                "installed_awg_engine_sha256": awg_engine_hash,
                "installed_awg_engine_size_bytes": len(self.awg_engine),
                "manager_service_running": True,
                "gui_launched": True,
                "passed": True,
            },
        )
        payload = self.receipt(
            "payload.json",
            PAYLOAD_CONTRACT,
            {
                **self.architecture_fields(),
                "candidate_payload_manifest_sha256": payload_hash,
                "payload_snapshot_index_sha256": self.digest("payload-snapshot"),
                "payload_entry_count": 43,
                "payload_pe_count": 4,
                "payload_pe_verified": True,
                "mixed_architecture": False,
                "passed": True,
            },
        )
        runtime = self.receipt(
            "runtime.json",
            RUNTIME_CONTRACT,
            {
                **self.architecture_fields(),
                "runtime_observed": True,
                "passed": True,
            },
        )
        node_routes = [
            {"protocol": "tcp", "port": 80, "security": "none"},
            {"protocol": "tcp", "port": 443, "security": "tls"},
        ]
        core_routes = [
            {"protocol": "tcp", "port": 80, "security": "none"},
            {"protocol": "tcp", "port": 443, "security": "tls"},
        ]
        advertisement = self.receipt(
            "advertisement.json",
            "winsvpn-windows-route-advertisement-receipt-v1",
            {
                "node_direct_awg_port": 9110,
                "core_direct_awg_port": 9210,
                "node_advertised_xray_routes": node_routes,
                "core_advertised_xray_routes": core_routes,
                "node_registration_sha256": self.digest("node"),
                "core_assignment_sha256": self.digest("core"),
                "api_response_sha256": self.digest("api"),
                "passed": True,
            },
        )
        rapid = self.receipt(
            "rapid.json",
            "winsvpn-windows-rapid-cancel-receipt-v1",
            {
                "connect_label": "Connect VPN",
                "connect_role": 43,
                "cancel_label": "Cancel VPN connection",
                "cancel_role": 43,
                "cancel_before_native_active": True,
                "late_restart_absent": True,
                "reconnect_passed": True,
                "disconnect_label": "Disconnect VPN",
                "disconnect_role": 43,
                "clean_state_proven": True,
                "passed": True,
            },
        )
        baseline = self.digest("baseline")
        protected = self.digest("protected")
        split = self.receipt(
            "split.json",
            "winsvpn-windows-split-tunnel-receipt-v1",
            {
                "excluded_executable_sha256": self.digest("excluded.exe"),
                "protected_executable_sha256": self.digest("protected.exe"),
                "baseline_egress_sha256": baseline,
                "excluded_egress_sha256": baseline,
                "protected_egress_sha256": protected,
                "selection_ui_sha256": self.digest("selection-ui"),
                "wfp_service_running": True,
                "process_rule_observed": True,
                "rollback_clean": True,
                "passed": True,
            },
        )
        profiles = [
            {
                "name": name,
                "transition_observed": True,
                "protected_egress_sha256": protected,
                "dns_protected": True,
                "passed": True,
            }
            for name in ("wifi_to_ethernet", "ethernet_to_wifi", "dhcp_renew", "ipv6_recovery")
        ]
        network = self.receipt(
            "network.json",
            "winsvpn-windows-network-change-receipt-v1",
            {"profiles": profiles, "final_route_restored": True, "final_dns_restored": True, "passed": True},
        )
        leak = self.receipt(
            "leak.json",
            "winsvpn-windows-leak-receipt-v1",
            {
                "tunnel_dns_sha256": self.digest("live-dynamic-tunnel-dns"),
                "protected_canary_count": 2,
                "dns_leak_passed": True,
                "ipv4_leak_passed": True,
                "ipv6_leak_passed": True,
                "kill_switch_passed": True,
                "passed": True,
            },
        )
        watchdog_state = self.digest("watchdog-state")
        watchdog = self.receipt(
            "watchdog.json",
            "winsvpn-windows-release-watchdog-receipt-v1",
            {
                "normal_teardown_proven": True,
                "fail_safe_triggered": False,
                "baseline_state_sha256": watchdog_state,
                "final_state_sha256": watchdog_state,
                "dns_restored": True,
                "lan_management_restored": True,
                "egress_restored": True,
                "pass": True,
            },
        )
        route_state = self.digest("route-state")
        egress = self.digest("egress")
        previous_signer = self.digest("previous-signer")
        previous_payload_value = {
            "schema_version": 2,
            "installer": {
                "name": "rollback.exe",
                "sha256": self.sha(self.rollback),
                "size": self.rollback.stat().st_size,
            },
            "producer": {},
            "signing": {
                "production_signed": True,
                "every_loose_pe_verified": True,
                "staged_xray_product_signed": True,
                "inno_setup_and_uninstaller_signed": True,
                "self_signed_certificate_forbidden": True,
            },
            "payload": [
                {"path": "wins_vpn.exe", "size": 10, "sha256": self.digest("old-gui")}
            ],
        }
        previous_payload = self.write_json(
            "previous-installer.payload-manifest.json", previous_payload_value
        )
        previous_record = self.write_json(
            "previous-release-record.json",
            {
                "schema_version": 1,
                "contract": "winsvpn-windows-previous-release-record-v1",
                "release_identity": "1.0.13+28",
                "artifact_sha256": self.sha(self.rollback),
                "artifact_size_bytes": self.rollback.stat().st_size,
                "payload_manifest_sha256": previous_payload["sha256"],
                "signer_certificate_sha256": previous_signer,
                "owner_authorization_content_sha256": self.digest("owner-content"),
                "owner_authorization_cms_sha256": self.digest("owner-cms"),
            },
        )
        teardown = self.receipt(
            "teardown.json",
            "winsvpn-windows-teardown-rollback-receipt-v1",
            {
                **self.architecture_fields(),
                "baseline_route_sha256": route_state,
                "final_route_sha256": route_state,
                "baseline_egress_sha256": egress,
                "final_egress_sha256": egress,
                "manager_running": True,
                "legacy_tunnel_service_absent": True,
                "awg_engine_absent": True,
                "split_service_absent": True,
                "adapter_absent_or_down": True,
                "xray_absent": True,
                "protected_routes_absent": True,
                "rollback_artifact_path": self.rollback.name,
                "rollback_artifact_sha256": self.sha(self.rollback),
                "previous_release_record_path": previous_record["path"],
                "previous_release_record_sha256": previous_record["sha256"],
                "previous_payload_manifest_path": previous_payload["path"],
                "previous_payload_manifest_sha256": previous_payload["sha256"],
                "previous_signer_certificate_sha256": previous_signer,
                "rollback_signature_verified": True,
                "rollback_payload_verified": True,
                "rollback_owner_authorization_verified": True,
                "rollback_install_passed": True,
                "candidate_reinstall_passed": True,
                "final_installed_gui_sha256": gui_hash,
                "final_installed_service_sha256": service_hash,
                "final_installed_awg_engine_sha256": awg_engine_hash,
                "passed": True,
            },
        )
        map_receipt = self.receipt(
            "map.json",
            "winsvpn-windows-map-receipt-v1",
            {
                "screenshot_path": self.map.name,
                "screenshot_sha256": self.sha(self.map),
                "radius_miles": 50,
                "city_labels_visible": True,
                "target_marker_visible": True,
                "viewport_not_world_zoom": True,
                "passed": True,
            },
        )
        lanes = [
            self.lane("node-direct", "node_direct_awg", 9110, "none"),
            self.lane("node-xray-80", "node_xray", 80, "none"),
            self.lane("node-xray-443", "node_xray", 443, "tls"),
            self.lane("core-direct", "core_direct_awg", 9210, "none"),
            self.lane("core-xray-80", "core_xray", 80, "none"),
            self.lane("core-xray-443", "core_xray", 443, "tls"),
        ]
        self.receipt(
            "winn-v3.json",
            WINN_V3_CONTRACT,
            {
                **self.architecture_fields(),
                "primary_transport": "winn_v3",
                "winn_v3_session_observed": True,
                "fallback_transports": ["winn_v1_awg", "winn_v1_xray"],
                "passed": True,
            },
        )
        self.receipt(
            "winn-v1-awg.json",
            WINN_V1_AWG_CONTRACT,
            {
                **self.architecture_fields(),
                "transport": "winn_v1_awg",
                "observed": True,
                "passed": True,
            },
        )
        self.receipt(
            "winn-v1-xray.json",
            WINN_V1_XRAY_CONTRACT,
            {
                **self.architecture_fields(),
                "transport": "winn_v1_xray",
                "observed": True,
                "passed": True,
            },
        )
        self.receipt(
            "machine-identity.json",
            IDENTITY_CONTRACT,
            {
                **self.architecture_fields(),
                "artifact_sha256": artifact_hash,
                "machine_guid_sha256": self.digest("machine-guid"),
            },
        )
        return {
            "schema_version": 1,
            "contract": "winsvpn-windows-release-machine-evidence-v1",
            "platform": "windows",
            "app_version": "1.0.14",
            "build_number": "29",
            "run_id": self.run_id,
            "captured_at_utc": NOW,
            "secret_material_redacted": True,
            "step_nonce": str(uuid.uuid4()),
            "sequence": self.sequence + 1,
            "started_at_utc": NOW,
            "finished_at_utc": NOW,
            **self.bindings,
            "collector_closure_sha256": self.collector_closure,
            "artifact_sha256": artifact_hash,
            "artifact_size_bytes": self.artifact.stat().st_size,
            "installed_gui_sha256": gui_hash,
            "installed_gui_size_bytes": len(self.gui),
            "installed_service_sha256": service_hash,
            "installed_service_size_bytes": len(self.service),
            "installed_awg_engine_sha256": awg_engine_hash,
            "installed_awg_engine_size_bytes": len(self.awg_engine),
            "architecture": self.architecture,
            "pe_machine": self.pe_machine,
            "native_architecture": self.architecture,
            "os_architecture": "X64" if self.architecture == "x64" else "Arm64",
            "process_wow64": False,
            "candidate_manifest": candidate_ref,
            "signature_receipt": signature,
            "install_receipt": install,
            "payload_receipt": payload,
            "runtime_receipt": runtime,
            "route_advertisement_receipt": advertisement,
            "node_direct_awg_port": 9110,
            "core_direct_awg_port": 9210,
            "node_advertised_xray_routes": node_routes,
            "core_advertised_xray_routes": core_routes,
            "lanes": lanes,
            "rapid_cancel_receipt": rapid,
            "split_tunnel_receipt": split,
            "network_change_receipt": network,
            "leak_receipt": leak,
            "watchdog_receipt": watchdog,
            "teardown_rollback_receipt": teardown,
            "map_receipt": map_receipt,
        }

    def bundle(self, machine: dict) -> pathlib.Path:
        machine_ref = self.write_json("machine-evidence.json", machine)
        entries: list[dict] = []
        used: set[str] = set()
        for path in sorted(self.root.iterdir(), key=lambda item: item.name):
            if path.name == "bundle-index.json" or not path.is_file():
                continue
            contract = ""
            sequence = 0
            nonce = str(uuid.uuid4())
            if path.suffix == ".json" and path.name != "candidate-manifest.json":
                raw = json.loads(path.read_text(encoding="utf-8"))
                contract = str(raw.get("contract") or "")
                if contract and all(
                    key in raw
                    for key in ("run_id", "sequence", "step_nonce", "collector_closure_sha256")
                ):
                    sequence = int(raw["sequence"])
                    nonce = str(raw["step_nonce"])
                else:
                    contract = ""
            entries.append(
                {
                    "path": path.name,
                    "sha256": self.sha(path),
                    "size_bytes": path.stat().st_size,
                    "contract": contract,
                    "sequence": sequence,
                    "step_nonce": nonce,
                }
            )
            used.add(path.name)
        next_sequence = max(entry["sequence"] for entry in entries) + 1
        for entry in entries:
            if entry["sequence"] == 0:
                entry["sequence"] = next_sequence
                next_sequence += 1
        entries.sort(key=lambda item: item["sequence"])
        index = {
            "schema_version": 1,
            "contract": "winsvpn-windows-release-bundle-index-v1",
            "run_id": self.run_id,
            "created_at_utc": NOW,
            "secret_material_redacted": True,
            "collector_closure_sha256": self.collector_closure,
            **self.bindings,
            "artifact_sha256": self.sha(self.artifact),
            "machine_evidence_path": machine_ref["path"],
            "machine_evidence_sha256": machine_ref["sha256"],
            "entries": entries,
            "publication_authorized": False,
            "sealed": True,
        }
        path = self.root / "bundle-index.json"
        path.write_text(json.dumps(index, sort_keys=True) + "\n", encoding="utf-8")
        return path


class WindowsReleaseMatrixEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.fixture = Fixture(pathlib.Path(self.temp.name))
        self.machine = self.fixture.machine()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def compile(self, machine: dict | None = None, bindings: dict[str, str] | None = None) -> dict:
        return compile_evidence(
            machine or self.machine,
            self.fixture.root,
            self.fixture.artifact,
            self.fixture.map,
            bindings or self.fixture.bindings,
        )

    def mutate_json_file(self, name: str, **changes: object) -> dict[str, str]:
        path = self.fixture.root / name
        value = json.loads(path.read_text(encoding="utf-8"))
        for key, item in changes.items():
            if item is _OMIT:
                value.pop(key, None)
            else:
                value[key] = item
        return self.fixture.write_json(name, value)

    def mutate_receipt(self, machine: dict, key: str, **changes: object) -> None:
        ref = machine[key]
        machine[key] = self.mutate_json_file(str(ref["path"]), **changes)

    def reindex(self, index: pathlib.Path, name: str) -> None:
        path = self.fixture.root / name
        value = json.loads(index.read_text(encoding="utf-8"))
        for entry in value["entries"]:
            if entry["path"] != name:
                continue
            entry["sha256"] = self.fixture.sha(path)
            entry["size_bytes"] = path.stat().st_size
            if path.suffix == ".json":
                raw = json.loads(path.read_text(encoding="utf-8"))
                if "step_nonce" in raw:
                    entry["step_nonce"] = raw["step_nonce"]
                if "sequence" in raw:
                    entry["sequence"] = raw["sequence"]
                if "contract" in raw:
                    entry["contract"] = raw["contract"]
        index.write_text(json.dumps(value) + "\n", encoding="utf-8")

    def test_complete_machine_matrix_compiles(self) -> None:
        native = self.compile()
        self.assertEqual(native["direct_awg"]["port"], 9110)
        self.assertEqual(len(native["tested_xray_routes"]), 2)
        self.assertTrue(all(native["windows_matrix"].values()))
        native["evidence_bundle_index_sha256"] = self.fixture.digest("logical-test-index")
        sanitized, _, _, routes, _ = validate_native_transcript(
            native,
            platform="windows",
            version="1.0.14",
            build="29",
            artifact_sha256=self.fixture.sha(self.fixture.artifact),
            evidence_not_before_utc=dt.datetime.fromisoformat(
                NOW.replace("Z", "+00:00")
            )
            - dt.timedelta(seconds=1),
        )
        self.assertEqual(sanitized["platform"], "windows")
        self.assertEqual(len(routes), 2)

    def test_complete_indexed_bundle_compiles(self) -> None:
        index = self.fixture.bundle(self.machine)
        native = compile_bundle(
            index,
            self.fixture.artifact,
            self.fixture.map,
            expected_bindings=self.fixture.bindings,
            expected_collector_closure=self.fixture.collector_closure,
        )
        self.assertTrue(native["windows_matrix"]["rollback"])
        self.assertEqual(
            native["evidence_bundle_index_sha256"],
            self.fixture.sha(index),
        )

    def test_secure_read_rejects_nested_caller_symlink(self) -> None:
        target = pathlib.Path(self.temp.name) / "target"
        target.mkdir()
        link = pathlib.Path(self.temp.name) / "caller-link"
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        with self.assertRaisesRegex(EvidenceError, "reparse point"):
            _reject_reparse_walk(link / "evidence.json")

    def test_tampered_bundle_index_machine_hash_is_rejected(self) -> None:
        index = self.fixture.bundle(self.machine)
        value = json.loads(index.read_text(encoding="utf-8"))
        value["machine_evidence_sha256"] = self.fixture.digest("tampered-machine")
        index.write_text(json.dumps(value) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "machine-evidence index hash is stale"):
            compile_bundle(
                index,
                self.fixture.artifact,
                self.fixture.map,
                expected_bindings=self.fixture.bindings,
                expected_collector_closure=self.fixture.collector_closure,
            )

    def test_bundle_rejects_wrong_collector_closure(self) -> None:
        index = self.fixture.bundle(self.machine)
        with self.assertRaisesRegex(EvidenceError, "fixed collector closure"):
            compile_bundle(
                index,
                self.fixture.artifact,
                self.fixture.map,
                expected_bindings=self.fixture.bindings,
                expected_collector_closure=self.fixture.digest("wrong-collector"),
            )

    def test_bundle_directory_must_equal_index_run_uuid(self) -> None:
        index = self.fixture.bundle(self.machine)
        value = json.loads(index.read_text(encoding="utf-8"))
        value["run_id"] = str(uuid.uuid4())
        index.write_text(json.dumps(value) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "directory must equal"):
            compile_bundle(
                index,
                self.fixture.artifact,
                self.fixture.map,
                expected_bindings=self.fixture.bindings,
                expected_collector_closure=self.fixture.collector_closure,
            )

    def test_bundle_run_uuid_must_be_canonical_lowercase(self) -> None:
        index = self.fixture.bundle(self.machine)
        value = json.loads(index.read_text(encoding="utf-8"))
        value["run_id"] = value["run_id"].upper()
        index.write_text(json.dumps(value) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "canonical lowercase"):
            compile_bundle(
                index,
                self.fixture.artifact,
                self.fixture.map,
                expected_bindings=self.fixture.bindings,
                expected_collector_closure=self.fixture.collector_closure,
            )

    def test_bundle_rejects_nonconsecutive_sequences(self) -> None:
        index = self.fixture.bundle(self.machine)
        value = json.loads(index.read_text())
        value["entries"][-1]["sequence"] += 5
        index.write_text(json.dumps(value) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "consecutive from one"):
            compile_bundle(
                index,
                self.fixture.artifact,
                self.fixture.map,
                expected_bindings=self.fixture.bindings,
                expected_collector_closure=self.fixture.collector_closure,
            )

    def test_stale_release_binding_fails(self) -> None:
        bindings = dict(self.fixture.bindings)
        bindings["producer_contract_sha256"] = "0" * 64
        with self.assertRaisesRegex(EvidenceError, "stale or mismatched producer_contract"):
            self.compile(bindings=bindings)

    def test_missing_core_advertised_route_lane_fails(self) -> None:
        machine = copy.deepcopy(self.machine)
        machine["lanes"] = [lane for lane in machine["lanes"] if lane["lane_id"] != "core-xray-443"]
        with self.assertRaisesRegex(EvidenceError, "Every Core-advertised Xray route"):
            self.compile(machine)

    def test_dynamic_core_first_hop_mismatch_fails(self) -> None:
        machine = copy.deepcopy(self.machine)
        machine["core_direct_awg_port"] = 9310
        with self.assertRaisesRegex(EvidenceError, "advertisement receipt contradicts"):
            self.compile(machine)

    def test_core_first_hop_cannot_collapse_to_node_9110(self) -> None:
        machine = copy.deepcopy(self.machine)
        machine["core_direct_awg_port"] = 9110
        with self.assertRaisesRegex(EvidenceError, "Core first hop must remain distinct"):
            self.compile(machine)

    def test_xray_forcing_restore_mismatch_fails(self) -> None:
        machine = copy.deepcopy(self.machine)
        lane = next(item for item in machine["lanes"] if item["lane_id"] == "node-xray-80")
        ref = lane["forcing_receipt"]
        path = self.fixture.root / ref["path"]
        forcing = json.loads(path.read_text())
        forcing["after_state_sha256"] = self.fixture.digest("wrong-after")
        lane["forcing_receipt"] = self.fixture.write_json(ref["path"], forcing)
        with self.assertRaisesRegex(EvidenceError, "did not restore exact pre-test state"):
            self.compile(machine)

    def test_server_observer_authentication_false_fails(self) -> None:
        machine = copy.deepcopy(self.machine)
        lane = next(item for item in machine["lanes"] if item["lane_id"] == "node-direct")
        ref = lane["server_receipt"]
        path = self.fixture.root / ref["path"]
        receipt = json.loads(path.read_text(encoding="utf-8"))
        receipt["observer_authenticated"] = False
        lane["server_receipt"] = self.fixture.write_json(ref["path"], receipt)
        with self.assertRaisesRegex(EvidenceError, "observer_authenticated must be true"):
            self.compile(machine)

    def test_node_observer_host_key_mismatch_fails(self) -> None:
        machine = copy.deepcopy(self.machine)
        lane = next(item for item in machine["lanes"] if item["lane_id"] == "node-xray-80")
        ref = lane["server_receipt"]
        path = self.fixture.root / ref["path"]
        receipt = json.loads(path.read_text(encoding="utf-8"))
        receipt["observer_host_key_sha256"] = self.fixture.digest("wrong-host-key")
        lane["server_receipt"] = self.fixture.write_json(ref["path"], receipt)
        with self.assertRaisesRegex(EvidenceError, "do not share one pinned observer"):
            self.compile(machine)

    def test_installed_gui_hash_mismatch_fails(self) -> None:
        machine = copy.deepcopy(self.machine)
        machine["installed_gui_sha256"] = self.fixture.digest("other-gui")
        with self.assertRaisesRegex(EvidenceError, "wins_vpn.exe does not match"):
            self.compile(machine)

    def test_installed_awg_engine_hash_mismatch_fails(self) -> None:
        machine = copy.deepcopy(self.machine)
        machine["installed_awg_engine_sha256"] = self.fixture.digest("other-engine")
        with self.assertRaisesRegex(EvidenceError, "winsvpn_awg_engine.exe does not match"):
            self.compile(machine)

    def test_required_tls_443_route_cannot_be_omitted(self) -> None:
        machine = copy.deepcopy(self.machine)
        machine["node_advertised_xray_routes"] = [
            route for route in machine["node_advertised_xray_routes"]
            if route["port"] != 443
        ]
        advertisement_path = self.fixture.root / machine["route_advertisement_receipt"]["path"]
        advertisement = json.loads(advertisement_path.read_text(encoding="utf-8"))
        advertisement["node_advertised_xray_routes"] = machine["node_advertised_xray_routes"]
        machine["route_advertisement_receipt"] = self.fixture.write_json(
            machine["route_advertisement_receipt"]["path"], advertisement
        )
        machine["lanes"] = [
            lane for lane in machine["lanes"] if lane["lane_id"] != "node-xray-443"
        ]
        with self.assertRaisesRegex(EvidenceError, "TCP 80/none and TCP 443/tls"):
            self.compile(machine)

    def test_formal_worker_uses_the_installed_awg_engine(self) -> None:
        worker = (TOOLS_DIR / "windows_release_interactive_worker.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("$InstalledAwgEngine", worker)
        self.assertIn("Get-Process winsvpn_awg_engine", worker)
        self.assertIn("installed_awg_engine_sha256", worker)
        self.assertIn("awg_engine_running = $true", worker)
        self.assertIn("residual_awg_engine_absent = $true", worker)
        forcing = worker[worker.index("function Add-XrayForcingRules"):]
        self.assertIn("$InstalledAwgEngine", forcing[:2500])

    def test_release_watchdog_tracks_and_stops_the_awg_engine(self) -> None:
        watchdog = (TOOLS_DIR / "windows_release_safe_watchdog.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("awg_engine_pids", watchdog)
        self.assertIn("Get-Process winsvpn_awg_engine", watchdog)
        self.assertIn("runtime.installed_awg_engine_path", watchdog)
        self.assertIn("runtime.installed_awg_engine_sha256", watchdog)

    def test_wrapper_rejects_manual_native_transcript_interface(self) -> None:
        wrapper = (pathlib.Path(__file__).parent / "windows_public_release_live_smoke.ps1").read_text(encoding="utf-8")
        self.assertNotIn("[string]$NativeTranscript", wrapper)
        self.assertNotIn("[string]$MachineEvidence", wrapper)
        self.assertIn("[string]$EvidenceBundleIndex", wrapper)
        self.assertIn("windows_release_matrix_driver.ps1", wrapper)

    def refresh_refs(self, value: object) -> None:
        if isinstance(value, dict):
            if set(value.keys()) == {"path", "sha256"}:
                path = self.fixture.root / str(value["path"])
                value["sha256"] = self.fixture.sha(path)
                return
            for child in value.values():
                self.refresh_refs(child)
        elif isinstance(value, list):
            for child in value:
                self.refresh_refs(child)

    def rewrite_json_timestamps(self, when: str) -> None:
        for path in self.fixture.root.glob("*.json"):
            raw = json.loads(path.read_text(encoding="utf-8"))
            changed = False
            for key in (
                "captured_at_utc",
                "started_at_utc",
                "finished_at_utc",
                "created_utc",
                "created_at_utc",
            ):
                if key in raw:
                    raw[key] = when
                    changed = True
            if changed:
                path.write_text(json.dumps(raw, sort_keys=True) + "\n", encoding="utf-8")

    def test_stub_mz_installer_is_not_windows_evidence(self) -> None:
        with self.assertRaisesRegex(EvidenceError, "not a PE"):
            pe_architecture(b"MZ" + b"installer" * 512, "stub installer")
        temp = tempfile.TemporaryDirectory()
        try:
            fixture = Fixture(pathlib.Path(temp.name))
            fixture.artifact.write_bytes(b"MZ" + b"installer" * 512)
            machine = fixture.machine()
            with self.assertRaisesRegex(EvidenceError, "not a PE"):
                compile_evidence(
                    machine,
                    fixture.root,
                    fixture.artifact,
                    fixture.map,
                    fixture.bindings,
                )
        finally:
            temp.cleanup()

    def test_arm64_installer_compiles_when_identity_matches(self) -> None:
        temp = tempfile.TemporaryDirectory()
        try:
            fixture = Fixture(pathlib.Path(temp.name), architecture="arm64")
            machine = fixture.machine()
            native = compile_evidence(
                machine,
                fixture.root,
                fixture.artifact,
                fixture.map,
                fixture.bindings,
            )
            self.assertEqual(native["direct_awg"]["port"], 9110)
            self.assertEqual(
                pe_architecture(fixture.artifact.read_bytes(), "arm64 installer"),
                "arm64",
            )
            native_bundle = compile_bundle(
                fixture.bundle(machine),
                fixture.artifact,
                fixture.map,
                expected_bindings=fixture.bindings,
                expected_collector_closure=fixture.collector_closure,
            )
            self.assertTrue(native_bundle["windows_matrix"]["rollback"])
        finally:
            temp.cleanup()

    def test_mixed_x64_arm64_rollback_fails(self) -> None:
        self.fixture.rollback.write_bytes(
            minimal_pe32_plus(PE_MACHINE_ARM64, b"rollback-arm64", 2048)
        )
        rollback_hash = self.fixture.sha(self.fixture.rollback)
        rollback_size = self.fixture.rollback.stat().st_size
        payload_path = self.fixture.root / "previous-installer.payload-manifest.json"
        payload = json.loads(payload_path.read_text(encoding="utf-8"))
        payload["installer"]["sha256"] = rollback_hash
        payload["installer"]["size"] = rollback_size
        payload_ref = self.fixture.write_json(payload_path.name, payload)
        record_path = self.fixture.root / "previous-release-record.json"
        record = json.loads(record_path.read_text(encoding="utf-8"))
        record["artifact_sha256"] = rollback_hash
        record["artifact_size_bytes"] = rollback_size
        record["payload_manifest_sha256"] = payload_ref["sha256"]
        record_ref = self.fixture.write_json(record_path.name, record)
        teardown_path = self.fixture.root / self.machine["teardown_rollback_receipt"]["path"]
        teardown = json.loads(teardown_path.read_text(encoding="utf-8"))
        teardown["rollback_artifact_sha256"] = rollback_hash
        teardown["previous_release_record_sha256"] = record_ref["sha256"]
        teardown["previous_payload_manifest_sha256"] = payload_ref["sha256"]
        self.machine["teardown_rollback_receipt"] = self.fixture.write_json(
            teardown_path.name, teardown
        )
        self.refresh_refs(self.machine)
        with self.assertRaisesRegex(EvidenceError, "architecture does not match"):
            self.compile()

    def test_stale_machine_evidence_fails(self) -> None:
        when = (
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=73)
        ).isoformat().replace("+00:00", "Z")
        self.rewrite_json_timestamps(when)
        self.machine["captured_at_utc"] = when
        self.machine["started_at_utc"] = when
        self.machine["finished_at_utc"] = when
        self.refresh_refs(self.machine)
        with self.assertRaisesRegex(EvidenceError, "72-hour live-evidence window"):
            self.compile()

    def test_future_machine_evidence_fails(self) -> None:
        when = (
            dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)
        ).isoformat().replace("+00:00", "Z")
        self.rewrite_json_timestamps(when)
        self.machine["captured_at_utc"] = when
        self.machine["started_at_utc"] = when
        self.machine["finished_at_utc"] = when
        self.refresh_refs(self.machine)
        with self.assertRaisesRegex(EvidenceError, "is in the future"):
            self.compile()

    def test_bundle_requires_machine_identity(self) -> None:
        index = self.fixture.bundle(self.machine)
        value = json.loads(index.read_text(encoding="utf-8"))
        for entry in value["entries"]:
            if entry["path"] == "machine-identity.json":
                entry["contract"] = ""
        index.write_text(json.dumps(value) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "machine-identity"):
            compile_bundle(
                index,
                self.fixture.artifact,
                self.fixture.map,
                expected_bindings=self.fixture.bindings,
                expected_collector_closure=self.fixture.collector_closure,
            )

    def test_bundle_rejects_duplicate_signature_contract(self) -> None:
        index = self.fixture.bundle(self.machine)
        signature = self.fixture.root / "signature.json"
        duplicate = json.loads(signature.read_text(encoding="utf-8"))
        value = json.loads(index.read_text(encoding="utf-8"))
        next_sequence = max(int(entry["sequence"]) for entry in value["entries"]) + 1
        duplicate["sequence"] = next_sequence
        duplicate["step_nonce"] = str(uuid.uuid4())
        duplicate_ref = self.fixture.write_json("signature-duplicate.json", duplicate)
        value["entries"].append(
            {
                "path": duplicate_ref["path"],
                "sha256": duplicate_ref["sha256"],
                "size_bytes": (self.fixture.root / duplicate_ref["path"]).stat().st_size,
                "contract": "winsvpn-windows-signature-receipt-v1",
                "sequence": next_sequence,
                "step_nonce": duplicate["step_nonce"],
            }
        )
        index.write_text(json.dumps(value) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(
            EvidenceError,
            "duplicate winsvpn-windows-signature-receipt-v1",
        ):
            compile_bundle(
                index,
                self.fixture.artifact,
                self.fixture.map,
                expected_bindings=self.fixture.bindings,
                expected_collector_closure=self.fixture.collector_closure,
            )

    def test_bundle_rejects_mixed_pe_entry(self) -> None:
        index = self.fixture.bundle(self.machine)
        mixed = self.fixture.root / "mixed-arm64.exe"
        mixed.write_bytes(minimal_pe32_plus(PE_MACHINE_ARM64, b"mixed-arm", 2048))
        value = json.loads(index.read_text(encoding="utf-8"))
        next_sequence = max(int(entry["sequence"]) for entry in value["entries"]) + 1
        value["entries"].append(
            {
                "path": mixed.name,
                "sha256": self.fixture.sha(mixed),
                "size_bytes": mixed.stat().st_size,
                "contract": "",
                "sequence": next_sequence,
                "step_nonce": str(uuid.uuid4()),
            }
        )
        index.write_text(json.dumps(value) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "mixes x64 and arm64"):
            compile_bundle(
                index,
                self.fixture.artifact,
                self.fixture.map,
                expected_bindings=self.fixture.bindings,
                expected_collector_closure=self.fixture.collector_closure,
            )

    def test_secure_read_fails_closed_when_cached_path_changes(self) -> None:
        _clear_secure_cache()
        first = secure_read_once(
            self.fixture.artifact, maximum=8 * 1024 * 1024, label="cached installer"
        )
        self.assertEqual(pe_architecture(first, "cached installer"), "x64")
        self.fixture.artifact.write_bytes(
            minimal_pe32_plus(PE_MACHINE_X64, b"changed-installer", 2048)
        )
        with self.assertRaisesRegex(EvidenceError, "changed after the first secure read"):
            secure_read_once(
                self.fixture.artifact, maximum=8 * 1024 * 1024, label="cached installer"
            )

    def test_identity_architecture_mismatch_fails(self) -> None:
        index = self.fixture.bundle(self.machine)
        path = self.fixture.root / "machine-identity.json"
        identity = json.loads(path.read_text(encoding="utf-8"))
        identity["architecture"] = "arm64"
        identity["native_architecture"] = "arm64"
        identity["os_architecture"] = "Arm64"
        identity["pe_machine"] = PE_MACHINE_ARM64
        rewritten = self.fixture.write_json(path.name, identity)
        value = json.loads(index.read_text(encoding="utf-8"))
        for entry in value["entries"]:
            if entry["path"] == path.name:
                entry["sha256"] = rewritten["sha256"]
                entry["size_bytes"] = path.stat().st_size
                entry["step_nonce"] = identity["step_nonce"]
                entry["sequence"] = identity["sequence"]
        index.write_text(json.dumps(value) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "cross-candidate or inconsistent"):
            compile_bundle(
                index,
                self.fixture.artifact,
                self.fixture.map,
                expected_bindings=self.fixture.bindings,
                expected_collector_closure=self.fixture.collector_closure,
            )

    def test_schema_requires_architecture_cross_bind(self) -> None:
        schema = json.loads(
            (TOOLS_DIR / "windows_release_machine_evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        for field in (
            "architecture",
            "pe_machine",
            "native_architecture",
            "os_architecture",
            "process_wow64",
            "payload_receipt",
            "runtime_receipt",
        ):
            self.assertIn(field, schema["required"])
            self.assertIn(field, schema["properties"])
        binding = schema["$defs"]["architectureBinding"]
        self.assertEqual(
            binding["required"],
            [
                "architecture",
                "pe_machine",
                "native_architecture",
                "os_architecture",
                "process_wow64",
            ],
        )
        self.assertEqual(schema["properties"]["process_wow64"], {"const": False})
        self.assertEqual(schema["properties"]["pe_machine"]["enum"], [34404, 43620])

    def test_missing_signature_architecture_fails(self) -> None:
        self.mutate_receipt(self.machine, "signature_receipt", pe_machine=_OMIT)
        with self.assertRaisesRegex(EvidenceError, "fields are invalid"):
            self.compile()

    def test_wow64_runtime_receipt_fails(self) -> None:
        self.mutate_receipt(self.machine, "runtime_receipt", process_wow64=True)
        with self.assertRaisesRegex(EvidenceError, "WOW64"):
            self.compile()

    def test_x86_payload_receipt_fails(self) -> None:
        self.mutate_receipt(
            self.machine,
            "payload_receipt",
            architecture="x86",
            pe_machine=PE_MACHINE_X86,
            native_architecture="x86",
            os_architecture="X86",
        )
        with self.assertRaisesRegex(EvidenceError, "x86/stub"):
            self.compile()

    def test_mixed_install_native_architecture_fails(self) -> None:
        self.mutate_receipt(
            self.machine,
            "install_receipt",
            native_architecture="arm64",
            os_architecture="Arm64",
        )
        with self.assertRaisesRegex(EvidenceError, "mixed, WOW64, omitted, or unsupported"):
            self.compile()

    def test_cross_candidate_teardown_architecture_fails(self) -> None:
        self.mutate_receipt(
            self.machine,
            "teardown_rollback_receipt",
            architecture="arm64",
            pe_machine=PE_MACHINE_ARM64,
            native_architecture="arm64",
            os_architecture="Arm64",
        )
        with self.assertRaisesRegex(EvidenceError, "cross-candidate or inconsistent"):
            self.compile()

    def test_source_only_payload_receipt_fails(self) -> None:
        self.mutate_receipt(self.machine, "payload_receipt", source_only=True)
        with self.assertRaisesRegex(EvidenceError, "source-only"):
            self.compile()

    def test_stale_runtime_release_identity_fails(self) -> None:
        self.mutate_receipt(
            self.machine, "runtime_receipt", release_identity="1.0.13+28"
        )
        with self.assertRaisesRegex(EvidenceError, "release identity is stale or mixed"):
            self.compile()

    def test_inconsistent_signature_and_install_architecture_fails(self) -> None:
        self.mutate_receipt(
            self.machine,
            "signature_receipt",
            architecture="arm64",
            pe_machine=PE_MACHINE_ARM64,
            native_architecture="arm64",
            os_architecture="Arm64",
        )
        with self.assertRaisesRegex(EvidenceError, "cross-candidate or inconsistent"):
            self.compile()

    def test_payload_mixed_architecture_flag_fails(self) -> None:
        self.mutate_receipt(self.machine, "payload_receipt", mixed_architecture=True)
        with self.assertRaisesRegex(EvidenceError, "payload receipt architecture is mixed"):
            self.compile()

    def test_source_only_identity_fails(self) -> None:
        index = self.fixture.bundle(self.machine)
        self.mutate_json_file("machine-identity.json", source_only=True)
        self.reindex(index, "machine-identity.json")
        with self.assertRaisesRegex(EvidenceError, "source-only"):
            compile_bundle(
                index,
                self.fixture.artifact,
                self.fixture.map,
                expected_bindings=self.fixture.bindings,
                expected_collector_closure=self.fixture.collector_closure,
            )

    def test_bundle_rejects_duplicate_payload_contract(self) -> None:
        index = self.fixture.bundle(self.machine)
        payload = self.fixture.root / "payload.json"
        duplicate = json.loads(payload.read_text(encoding="utf-8"))
        value = json.loads(index.read_text(encoding="utf-8"))
        next_sequence = max(int(entry["sequence"]) for entry in value["entries"]) + 1
        duplicate["sequence"] = next_sequence
        duplicate["step_nonce"] = str(uuid.uuid4())
        duplicate_ref = self.fixture.write_json("payload-duplicate.json", duplicate)
        value["entries"].append(
            {
                "path": duplicate_ref["path"],
                "sha256": duplicate_ref["sha256"],
                "size_bytes": (self.fixture.root / duplicate_ref["path"]).stat().st_size,
                "contract": PAYLOAD_CONTRACT,
                "sequence": next_sequence,
                "step_nonce": duplicate["step_nonce"],
            }
        )
        index.write_text(json.dumps(value) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, f"duplicate {PAYLOAD_CONTRACT}"):
            compile_bundle(
                index,
                self.fixture.artifact,
                self.fixture.map,
                expected_bindings=self.fixture.bindings,
                expected_collector_closure=self.fixture.collector_closure,
            )

    def test_bundle_rejects_missing_winn_v3_receipt(self) -> None:
        index = self.fixture.bundle(self.machine)
        value = json.loads(index.read_text(encoding="utf-8"))
        for entry in value["entries"]:
            if entry["contract"] == WINN_V3_CONTRACT:
                entry["contract"] = ""
        index.write_text(json.dumps(value) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "winn-v3-receipt"):
            compile_bundle(
                index,
                self.fixture.artifact,
                self.fixture.map,
                expected_bindings=self.fixture.bindings,
                expected_collector_closure=self.fixture.collector_closure,
            )

    def test_bundle_rejects_winn_xray_before_awg(self) -> None:
        index = self.fixture.bundle(self.machine)
        awg_path = self.fixture.root / "winn-v1-awg.json"
        xray_path = self.fixture.root / "winn-v1-xray.json"
        awg = json.loads(awg_path.read_text(encoding="utf-8"))
        xray = json.loads(xray_path.read_text(encoding="utf-8"))
        awg["sequence"], xray["sequence"] = xray["sequence"], awg["sequence"]
        self.fixture.write_json(awg_path.name, awg)
        self.fixture.write_json(xray_path.name, xray)
        self.reindex(index, awg_path.name)
        self.reindex(index, xray_path.name)
        with self.assertRaisesRegex(EvidenceError, "Xray fallback is not after AWG"):
            compile_bundle(
                index,
                self.fixture.artifact,
                self.fixture.map,
                expected_bindings=self.fixture.bindings,
                expected_collector_closure=self.fixture.collector_closure,
            )

    def test_bundle_rejects_mixed_winn_fallback_order(self) -> None:
        index = self.fixture.bundle(self.machine)
        self.mutate_json_file(
            "winn-v3.json",
            fallback_transports=["winn_v1_xray", "winn_v1_awg"],
        )
        self.reindex(index, "winn-v3.json")
        with self.assertRaisesRegex(EvidenceError, "mixed fallback order"):
            compile_bundle(
                index,
                self.fixture.artifact,
                self.fixture.map,
                expected_bindings=self.fixture.bindings,
                expected_collector_closure=self.fixture.collector_closure,
            )

    def test_x86_pe_installer_is_not_windows_evidence(self) -> None:
        temp = tempfile.TemporaryDirectory()
        try:
            fixture = Fixture(pathlib.Path(temp.name))
            fixture.artifact.write_bytes(
                minimal_pe32_plus(PE_MACHINE_X86, b"installer-x86", 2048)
            )
            machine = fixture.machine()
            with self.assertRaisesRegex(EvidenceError, "not PE32\\+ x64 or arm64"):
                compile_evidence(
                    machine,
                    fixture.root,
                    fixture.artifact,
                    fixture.map,
                    fixture.bindings,
                )
        finally:
            temp.cleanup()

    def test_require_architecture_binding_rejects_omitted_fields(self) -> None:
        expected = architecture_binding_for("x64")
        with self.assertRaisesRegex(EvidenceError, "omitted architecture binding"):
            require_architecture_binding({"architecture": "x64"}, "unit", expected)

    def test_self_test_is_not_a_live_evidence_pass(self) -> None:
        import subprocess

        completed = subprocess.run(
            [sys.executable, str(TOOLS_DIR / "windows_release_matrix_evidence.py"), "--self-test"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("WINDOWS RELEASE MATRIX COMPILER SELF-TEST: PASS", completed.stdout)
        self.assertNotIn(
            "WINDOWS RELEASE MATRIX EVIDENCE: PASS",
            completed.stdout.replace(
                "WINDOWS RELEASE MATRIX COMPILER SELF-TEST: PASS", ""
            ),
        )


if __name__ == "__main__":
    unittest.main()
