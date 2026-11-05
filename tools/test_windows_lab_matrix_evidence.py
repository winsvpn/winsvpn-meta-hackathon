#!/usr/bin/env python3
"""Fail-closed tests for nonpublishable Windows lab evidence compilation."""

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

from windows_lab_matrix_evidence import (
    BINDING_FIELDS,
    EvidenceError,
    _reject_reparse_walk,
    compile_bundle,
    compile_evidence,
)

LAB_MARKERS = {
    "evidence_class": "nonpublishable_lab",
    "lab_only": True,
    "publication_authorized": False,
    "public_release_gate_eligible": False,
    "unsigned_local_candidate": True,
}


NOW = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


class Fixture:
    def __init__(self, root: pathlib.Path) -> None:
        self.run_id = str(uuid.uuid4())
        self.root = root / self.run_id
        self.root.mkdir()
        self.artifact = self.root / "WinsVPN-Setup.exe"
        self.artifact.write_bytes(b"MZ" + b"installer" * 512)
        self.map = self.root / "map.png"
        self.map.write_bytes(b"\x89PNG\r\n\x1a\n" + b"map" * 1024)
        self.rollback = self.root / "rollback.exe"
        self.rollback.write_bytes(b"MZ" + b"rollback" * 512)
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
            **LAB_MARKERS,
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
            "winsvpn-windows-lab-client-route-receipt-v1",
            {
                **lane,
                "connect_label": "Connect VPN",
                "connect_role": 43,
                "disconnect_label": "Disconnect VPN",
                "disconnect_role": 43,
                "native_active_observed": True,
                "manager_running": True,
                "awg_engine_running": True,
                "legacy_tunnel_services_absent": True,
                "adapter_up": True,
                "protected_route_present": True,
                "xray_process_observed": xray,
                "rx_bytes_delta": 4096,
                "tx_bytes_delta": 2048,
                "protected_egress_sha256": self.digest("protected-egress"),
                "normal_teardown_proven": True,
                "residual_awg_engine_absent": True,
                "residual_legacy_tunnel_services_absent": True,
                "residual_adapter_absent": True,
                "residual_xray_absent": True,
                "residual_routes_absent": True,
                "passed": True,
            },
        )
        server = self.receipt(
            f"{lane_id}-server.json",
            "winsvpn-windows-lab-server-route-receipt-v1",
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
                "core_exit_xray_carrier_proven": core and xray,
                "core_exit_peer_rx_bytes_delta": 4096 if core else 0,
                "core_exit_peer_tx_bytes_delta": 2048 if core else 0,
                "observer_authenticated": True,
                "peer_bound": True,
                "expected_exit_observed": True,
                "passed": True,
            },
        )
        before = self.digest(f"before:{lane_id}")
        forcing = self.receipt(
            f"{lane_id}-forcing.json",
            "winsvpn-windows-lab-forcing-receipt-v1",
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
            **LAB_MARKERS,
            "created_utc": NOW,
            "release_identity": "1.0.14+29",
            "internal_candidate": True,
            "stage": "nonpublishable_lab",
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
            "authenticode_status": "NotSigned",
        }
        candidate_ref = self.write_json("candidate-manifest.json", manifest)
        signature = self.receipt(
            "signature.json",
            "winsvpn-windows-lab-signature-receipt-v1",
            {
                "artifact_sha256": artifact_hash,
                "artifact_size_bytes": self.artifact.stat().st_size,
                "authenticode_status": "NotSigned",
                "signer_certificate_sha256": "",
                "timestamp_certificate_sha256": "",
                "signature_verified": False,
                "timestamp_verified": False,
                "nonpublishable_lab_acceptance": True,
            },
        )
        install = self.receipt(
            "install.json",
            "winsvpn-windows-lab-install-receipt-v1",
            {
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
            "winsvpn-windows-lab-route-advertisement-receipt-v1",
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
            "winsvpn-windows-lab-rapid-cancel-receipt-v1",
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
            "winsvpn-windows-lab-split-tunnel-receipt-v1",
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
            "winsvpn-windows-lab-network-change-receipt-v1",
            {"profiles": profiles, "final_route_restored": True, "final_dns_restored": True, "passed": True},
        )
        leak = self.receipt(
            "leak.json",
            "winsvpn-windows-lab-leak-receipt-v1",
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
            "winsvpn-windows-lab-watchdog-receipt-v1",
            {
                "normal_teardown_proven": True,
                "fail_safe_triggered": False,
                "baseline_state_sha256": watchdog_state,
                "final_state_sha256": watchdog_state,
                "dns_restored": True,
                "lan_management_restored": True,
                "egress_restored": True,
                "awg_engine_absent": True,
                "pass": True,
            },
        )
        route_state = self.digest("route-state")
        egress = self.digest("egress")
        previous_payload_value = {
            "schema_version": 2,
            "installer": {
                "name": "rollback.exe",
                "sha256": self.sha(self.rollback),
                "size": self.rollback.stat().st_size,
            },
            "producer": {},
            "signing": {
                "production_signed": False,
                "every_loose_pe_verified": False,
                "staged_xray_product_signed": False,
                "inno_setup_and_uninstaller_signed": False,
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
                "contract": "winsvpn-windows-lab-previous-release-record-v1",
                **LAB_MARKERS,
                "release_identity": "1.0.13+28",
                "artifact_sha256": self.sha(self.rollback),
                "artifact_size_bytes": self.rollback.stat().st_size,
                "payload_manifest_sha256": previous_payload["sha256"],
            },
        )
        teardown = self.receipt(
            "teardown.json",
            "winsvpn-windows-lab-teardown-rollback-receipt-v1",
            {
                "baseline_route_sha256": route_state,
                "final_route_sha256": route_state,
                "baseline_egress_sha256": egress,
                "final_egress_sha256": egress,
                "manager_running": True,
                "awg_engine_absent": True,
                "legacy_tunnel_services_absent": True,
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
                "previous_signer_certificate_sha256": "",
                "rollback_signature_verified": False,
                "rollback_payload_verified": True,
                "rollback_owner_authorization_verified": False,
                "rollback_lab_hash_authorization_verified": True,
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
            "winsvpn-windows-lab-map-receipt-v1",
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
        return {
            "schema_version": 1,
            "contract": "winsvpn-windows-lab-machine-evidence-v1",
            "platform": "windows",
            "app_version": "1.0.14",
            "build_number": "29",
            "run_id": self.run_id,
            "captured_at_utc": NOW,
            "secret_material_redacted": True,
            **LAB_MARKERS,
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
            "candidate_manifest": candidate_ref,
            "signature_receipt": signature,
            "install_receipt": install,
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
            "contract": "winsvpn-windows-lab-bundle-index-v1",
            "run_id": self.run_id,
            "created_at_utc": NOW,
            "secret_material_redacted": True,
            **LAB_MARKERS,
            "collector_closure_sha256": self.collector_closure,
            **self.bindings,
            "artifact_sha256": self.sha(self.artifact),
            "machine_evidence_path": machine_ref["path"],
            "machine_evidence_sha256": machine_ref["sha256"],
            "entries": entries,
            "sealed": True,
        }
        path = self.root / "bundle-index.json"
        path.write_text(json.dumps(index, sort_keys=True) + "\n", encoding="utf-8")
        return path


class WindowsLabMatrixEvidenceTests(unittest.TestCase):
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

    def test_complete_machine_matrix_compiles(self) -> None:
        native = self.compile()
        self.assertEqual(native["contract"], "winsvpn-windows-lab-native-evidence-v1")
        self.assertEqual({key: native[key] for key in LAB_MARKERS}, LAB_MARKERS)
        self.assertFalse(native["checks"]["artifact_signature"])
        self.assertTrue(native["checks"]["exact_unsigned_candidate"])
        self.assertEqual(native["direct_awg"]["port"], 9110)
        self.assertEqual(len(native["tested_xray_routes"]), 2)
        self.assertTrue(all(native["windows_matrix"].values()))

    def test_machine_schema_requires_engine_and_both_standard_xray_routes(self) -> None:
        schema = json.loads(
            (pathlib.Path(__file__).parent / "windows_lab_machine_evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIn("installed_awg_engine_sha256", schema["required"])
        self.assertIn("installed_awg_engine_size_bytes", schema["required"])
        required_routes = schema["$defs"]["routes"]["allOf"]
        self.assertEqual(
            {
                (entry["contains"]["properties"]["port"]["const"],
                 entry["contains"]["properties"]["security"]["const"])
                for entry in required_routes
            },
            {(80, "none"), (443, "tls")},
        )

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

    def test_machine_publication_marker_cannot_be_enabled(self) -> None:
        machine = copy.deepcopy(self.machine)
        machine["publication_authorized"] = True
        with self.assertRaisesRegex(EvidenceError, "immutable nonpublishable lab marker"):
            self.compile(machine)

    def test_public_machine_contract_is_rejected(self) -> None:
        machine = copy.deepcopy(self.machine)
        machine["contract"] = "winsvpn-windows-release-machine-evidence-v1"
        with self.assertRaisesRegex(EvidenceError, "contract/version/platform is invalid"):
            self.compile(machine)

    def test_signed_candidate_receipt_is_rejected(self) -> None:
        machine = copy.deepcopy(self.machine)
        ref = machine["signature_receipt"]
        path = self.fixture.root / ref["path"]
        receipt = json.loads(path.read_text(encoding="utf-8"))
        receipt.update(
            authenticode_status="Valid",
            signer_certificate_sha256=self.fixture.digest("signer"),
            timestamp_certificate_sha256=self.fixture.digest("timestamp"),
            signature_verified=True,
            timestamp_verified=True,
        )
        machine["signature_receipt"] = self.fixture.write_json(ref["path"], receipt)
        with self.assertRaisesRegex(EvidenceError, "not explicitly unsigned"):
            self.compile(machine)

    def test_candidate_manifest_rejects_unbound_extra_artifact(self) -> None:
        machine = copy.deepcopy(self.machine)
        ref = machine["candidate_manifest"]
        path = self.fixture.root / ref["path"]
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["artifacts"].append(
            {"name": "rogue.dll", "sha256": self.fixture.digest("rogue"), "size": 1}
        )
        machine["candidate_manifest"] = self.fixture.write_json(ref["path"], manifest)
        with self.assertRaisesRegex(EvidenceError, "unexpected artifact"):
            self.compile(machine)

    def test_previous_payload_cannot_claim_production_signing(self) -> None:
        machine = copy.deepcopy(self.machine)
        teardown_ref = machine["teardown_rollback_receipt"]
        teardown_path = self.fixture.root / teardown_ref["path"]
        teardown = json.loads(teardown_path.read_text(encoding="utf-8"))

        payload_path = self.fixture.root / teardown["previous_payload_manifest_path"]
        payload = json.loads(payload_path.read_text(encoding="utf-8"))
        payload["signing"]["production_signed"] = True
        payload_ref = self.fixture.write_json(payload_path.name, payload)

        record_path = self.fixture.root / teardown["previous_release_record_path"]
        record = json.loads(record_path.read_text(encoding="utf-8"))
        record["payload_manifest_sha256"] = payload_ref["sha256"]
        record_ref = self.fixture.write_json(record_path.name, record)

        teardown["previous_payload_manifest_sha256"] = payload_ref["sha256"]
        teardown["previous_release_record_sha256"] = record_ref["sha256"]
        machine["teardown_rollback_receipt"] = self.fixture.write_json(
            teardown_path.name, teardown
        )
        with self.assertRaisesRegex(EvidenceError, "Previous payload manifest"):
            self.compile(machine)

    def test_bundle_publication_marker_cannot_be_enabled(self) -> None:
        index = self.fixture.bundle(self.machine)
        value = json.loads(index.read_text(encoding="utf-8"))
        value["publication_authorized"] = True
        index.write_text(json.dumps(value) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "immutable nonpublishable lab marker"):
            compile_bundle(
                index,
                self.fixture.artifact,
                self.fixture.map,
                expected_bindings=self.fixture.bindings,
                expected_collector_closure=self.fixture.collector_closure,
            )

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

    def test_installed_awg_engine_hash_mismatch_fails(self) -> None:
        machine = copy.deepcopy(self.machine)
        machine["installed_awg_engine_sha256"] = self.fixture.digest("other-engine")
        with self.assertRaisesRegex(EvidenceError, "winsvpn_awg_engine.exe does not match"):
            self.compile(machine)

    def test_required_tls_443_route_cannot_be_omitted(self) -> None:
        machine = copy.deepcopy(self.machine)
        machine["node_advertised_xray_routes"] = [
            route
            for route in machine["node_advertised_xray_routes"]
            if route["port"] != 443
        ]
        advertisement_path = self.fixture.root / machine["route_advertisement_receipt"]["path"]
        advertisement = json.loads(advertisement_path.read_text(encoding="utf-8"))
        advertisement["node_advertised_xray_routes"] = machine[
            "node_advertised_xray_routes"
        ]
        machine["route_advertisement_receipt"] = self.fixture.write_json(
            machine["route_advertisement_receipt"]["path"], advertisement
        )
        machine["lanes"] = [
            lane for lane in machine["lanes"] if lane["lane_id"] != "node-xray-443"
        ]
        with self.assertRaisesRegex(EvidenceError, "TCP 80/none and TCP 443/tls"):
            self.compile(machine)

    def test_lab_worker_uses_the_installed_awg_engine(self) -> None:
        worker = (pathlib.Path(__file__).parent / "windows_lab_interactive_worker.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("$InstalledAwgEngine", worker)
        self.assertIn("Get-Process winsvpn_awg_engine", worker)
        self.assertIn("installed_awg_engine_sha256", worker)
        self.assertIn("awg_engine_running = $true", worker)
        self.assertIn("residual_awg_engine_absent = $true", worker)
        forcing = worker[worker.index("function Add-XrayForcingRules") :]
        self.assertIn("$InstalledAwgEngine", forcing[:2500])

    def test_core_xray_lane_requires_exact_core_to_exit_carrier_proof(self) -> None:
        worker = (pathlib.Path(__file__).parent / "windows_lab_interactive_worker.ps1").read_text(
            encoding="utf-8"
        )
        assertion = worker[
            worker.index("function Assert-CoreServerObservation") :
            worker.index("function Wait-TunnelActive")
        ]
        for marker in (
            "xray_exit_unit_matches_config_path",
            "exit_peer_match_count_before",
            "exit_peer_match_count_after",
            "exit_peer_endpoint_loopback_matches_xray",
            "exit_peer_handshake_fresh_after",
            "exit_peer_rx_delta",
            "exit_peer_tx_delta",
        ):
            self.assertIn(marker, assertion)
        self.assertIn("Pinned Core-to-exit Xray carrier", assertion)
        self.assertIn("core_exit_xray_carrier_proven", worker)

        machine = copy.deepcopy(self.machine)
        lane = next(item for item in machine["lanes"] if item["kind"] == "core_xray")
        reference = lane["server_receipt"]
        path = self.fixture.root / reference["path"]
        server = json.loads(path.read_text(encoding="utf-8"))
        server["core_exit_xray_carrier_proven"] = False
        lane["server_receipt"] = self.fixture.write_json(reference["path"], server)
        with self.assertRaisesRegex(EvidenceError, "Core-to-exit Xray carrier proof"):
            self.compile(machine)

    def test_lab_watchdog_tracks_and_stops_the_awg_engine(self) -> None:
        watchdog = (pathlib.Path(__file__).parent / "windows_lab_safe_watchdog.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("awg_engine_pids", watchdog)
        self.assertIn("Get-Process winsvpn_awg_engine", watchdog)
        self.assertIn("Runtime.installed_awg_engine_path", watchdog)
        self.assertIn("runtime.installed_awg_engine_sha256", watchdog)

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

    def test_wrapper_rejects_manual_native_transcript_interface(self) -> None:
        wrapper = (pathlib.Path(__file__).parent / "windows_public_release_live_smoke.ps1").read_text(encoding="utf-8")
        self.assertNotIn("[string]$NativeTranscript", wrapper)
        self.assertNotIn("[string]$MachineEvidence", wrapper)
        self.assertIn("[string]$EvidenceBundleIndex", wrapper)
        self.assertIn("windows_release_matrix_driver.ps1", wrapper)


if __name__ == "__main__":
    unittest.main()
