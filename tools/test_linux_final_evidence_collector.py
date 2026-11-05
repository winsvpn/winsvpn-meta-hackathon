#!/usr/bin/env python3
"""Tests for the final Linux machine-evidence collector."""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import tempfile
import types
import unittest

from linux_apple_release_matrix_evidence import MatrixError, compile_evidence
from linux_final_evidence_collector import (
    CONTRACT,
    LINUX_PUBLIC_PRODUCER,
    Collector,
    CollectorError,
    LaneObservation,
    is_reparse_point,
    reject_reparse_components,
    require_linux_root,
    sha256_file,
    validate_owner_only_linux_bundle,
    validate_installed_tool_binding,
)
from public_release_live_smoke_common import producer_contract_hash


class FakeDriver:
    def __init__(self, artifact: pathlib.Path) -> None:
        self.artifact = artifact
        self.version = "1.0.14"
        self.build = "29"
        self.empty_double_identity = False
        self.network_change_passed = True
        self.rollback_really_fails = True
        self.map_cities = ["Alpha", "Beta", "Gamma"]
        self.direct_port = 9110
        self.double_direct_port = 9210
        self.routes = [
            {"protocol": "tcp", "port": 80, "security": "none"},
            {"protocol": "tcp", "port": 443, "security": "tls"},
        ]
        self.double_routes = [
            {"protocol": "tcp", "port": 8080, "security": "none"},
            {"protocol": "tcp", "port": 8443, "security": "tls"},
        ]
        self.wrong_forcing_port = False
        self.on_network_begin = lambda: None
        self.on_network_restore = lambda: None
        self.on_rollback_inject = lambda: None
        self.on_rollback_restore = lambda: None

    @staticmethod
    def base(action: str, **fields):
        return {
            "schema_version": 1,
            "contract": CONTRACT,
            "action": action,
            "passed": True,
            "secret_material_redacted": True,
            **fields,
        }

    def call(self, action: str, **values: str):
        if action == "clean_install":
            return self.base(
                action,
                source_artifact_sha256=sha256_file(self.artifact),
                app_version=self.version,
                build_number=self.build,
                clean_remove_passed=True,
                install_passed=True,
            )
        if action == "connect":
            kind = values["kind"]
            double = kind in {"double_vpn_direct", "double_vpn_xray"}
            is_xray = kind in {"xray", "double_vpn_xray"}
            direct_port = self.double_direct_port if double else self.direct_port
            routes = self.double_routes if double else self.routes
            port = int(values["port"]) if is_xray else direct_port
            security = values["security"] if is_xray else "none"
            if is_xray and int(values["direct_port"]) != direct_port:
                raise AssertionError("collector supplied the wrong mode direct port")
            return self.base(
                action,
                kind=kind,
                port=port,
                security=security,
                actual_direct_port=direct_port,
                advertised_xray_routes=list(routes),
                forcing_blocked_udp_port=(
                    (self.direct_port if self.wrong_forcing_port else direct_port)
                    if is_xray else None
                ),
                forced_route=is_xray,
                double_vpn_active=double,
                double_vpn_core_id_sha256=(
                    __import__("hashlib").sha256(
                        (b"" if self.empty_double_identity else b"north-america-core")
                    ).hexdigest()
                    if double else __import__("hashlib").sha256(b"").hexdigest()
                ),
                double_vpn_exit_slug_sha256=(
                    __import__("hashlib").sha256(
                        (b"" if self.empty_double_identity else b"spain")
                    ).hexdigest()
                    if double else __import__("hashlib").sha256(b"").hexdigest()
                ),
            )
        if action == "disconnect":
            return self.base(action)
        if action == "select_split":
            return self.base(action, selection_applied=True)
        if action == "launch_split":
            return self.base(action, launched=True)
        if action == "network_change_begin":
            self.on_network_begin()
            return self.base(
                action, change_triggered_by_harness=self.network_change_passed
            )
        if action == "network_change_restore":
            self.on_network_restore()
            return self.base(action, restored=True)
        if action == "rollback_inject":
            self.on_rollback_inject()
            return self.base(action, failure_injected_by_harness=True)
        if action == "rollback_restore":
            self.on_rollback_restore()
            return self.base(action, restored=True)
        if action == "capture_map":
            screenshot = pathlib.Path(values["output"])
            screenshot.write_bytes(b"\x89PNG\r\n\x1a\n" + b"map" * 2048)
            return self.base(
                action,
                capture_method="linux-window-capture",
                screenshot_sha256=sha256_file(screenshot),
                radius_label_50_miles_detected=True,
                surrounding_city_labels=list(self.map_cities),
                target_marker_detected=True,
                viewport_not_world_zoom=True,
            )
        if action == "finalize":
            return self.base(action, restored=True)
        raise AssertionError(f"unexpected action: {action}")

    def expect_failure(self, action: str, **values: str) -> int:
        if not self.rollback_really_fails:
            raise CollectorError("Injected failure did not make driver action connect fail")
        return 73


class FakeProbe:
    def __init__(self) -> None:
        self.state = "a" * 64
        self.interface_state = "8" * 64

    def state_hash(self) -> str:
        return self.state

    def interface_state_hash(self, unused: str) -> str:
        return self.interface_state

    def installed_payload_report(self, artifact: pathlib.Path, output: pathlib.Path):
        report = {
            "schema_version": 1,
            "contract": "winsvpn-linux-installed-payload-v1",
            "platform": "linux",
            "artifact_sha256": sha256_file(artifact),
            "installed_payload_manifest_sha256": "c" * 64,
            "member_count": 12,
            "exact_archive_payload_installed": True,
            "secret_material_redacted": True,
        }
        output.write_text(json.dumps(report) + "\n", encoding="utf-8")
        return report

    def observe_lane(self, **unused) -> LaneObservation:
        return LaneObservation(
            rx_delta_bytes=2048,
            tx_delta_bytes=1024,
            protected_egress_sha256="d" * 64,
            provider_executable_sha256="e" * 64,
            dns_protected=True,
            ipv4_protected=True,
            ipv6_escape_blocked=True,
            public_canaries_agree=True,
        )

    def wait_for_lane(self, **unused) -> LaneObservation:
        return self.observe_lane()

    def split_assertions(self) -> None:
        pass

    def teardown_assertions(self) -> None:
        pass


class LinuxCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.artifact = self.root / "linux.tar.gz"
        self.artifact.write_bytes(b"exact-linux-release")
        self.binding = {
            "release_input_index_sha256": "1" * 64,
            "platform_manifest_sha256": "2" * 64,
            "artifact_input_fingerprint_sha256": "3" * 64,
            "build_receipt_sha256": "4" * 64,
            "producer_contract_sha256": "5" * 64,
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_collector(self, name: str = "run"):
        output = self.root / name
        output.mkdir()
        driver = FakeDriver(self.artifact)
        probe = FakeProbe()
        driver.on_network_begin = lambda: setattr(probe, "interface_state", "9" * 64)
        driver.on_network_restore = lambda: setattr(probe, "interface_state", "8" * 64)
        driver.on_rollback_inject = lambda: setattr(probe, "state", "f" * 64)
        driver.on_rollback_restore = lambda: setattr(probe, "state", "a" * 64)
        collector = Collector(
            driver=driver,
            probe=probe,  # type: ignore[arg-type]
            artifact=self.artifact,
            output_dir=output,
            app_version="1.0.14",
            build_number="29",
            binding=dict(self.binding),
            network_interface="eth0",
        )
        return collector, driver, probe, output

    def make_owner_only_bundle(self, name: str):
        if os.name == "nt":
            self.skipTest("Owner-only Linux bundle tests require POSIX ownership/modes")
        collector, _, _, output = self.make_collector(name)
        machine_path, screenshot = collector.collect()
        repo = pathlib.Path(__file__).resolve().parent.parent
        producer = producer_contract_hash(repo, LINUX_PUBLIC_PRODUCER)
        machine = json.loads(machine_path.read_text(encoding="utf-8"))
        machine["producer_contract_sha256"] = producer
        machine_path.write_text(
            json.dumps(machine, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        frozen = output / "exact-input-linux-artifact.tar.gz"
        shutil.copyfile(self.artifact, frozen)
        index_path = output / "EVIDENCE_INDEX.json"
        index = json.loads(index_path.read_text(encoding="utf-8"))
        index["producer_contract_sha256"] = producer
        index["machine_evidence"].update(
            sha256=sha256_file(machine_path), size_bytes=machine_path.stat().st_size
        )
        index["frozen_artifact"] = {
            "path": frozen.name,
            "sha256": sha256_file(frozen),
            "size_bytes": frozen.stat().st_size,
            "contract": "winsvpn-linux-frozen-artifact-v1",
        }
        index_path.write_text(
            json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        for path in output.iterdir():
            os.chmod(path, 0o600)
        os.chmod(output, 0o700)
        return output, machine_path, screenshot, index_path

    def test_owner_only_index_rejects_fabricated_user_bundle(self) -> None:
        output, _, _, _ = self.make_owner_only_bundle("fabricated-owner")
        with self.assertRaises(CollectorError):
            validate_owner_only_linux_bundle(
                output,
                repo=pathlib.Path(__file__).resolve().parent.parent,
                expected_uid=os.geteuid() + 1,
            )

    def test_owner_only_index_rejects_wrong_mode(self) -> None:
        output, _, _, _ = self.make_owner_only_bundle("wrong-mode")
        os.chmod(output / "linux-map.png", 0o644)
        with self.assertRaises(CollectorError):
            validate_owner_only_linux_bundle(
                output,
                repo=pathlib.Path(__file__).resolve().parent.parent,
                expected_uid=os.geteuid(),
            )

    def test_owner_only_index_rejects_symlinked_receipt(self) -> None:
        output, _, _, index_path = self.make_owner_only_bundle("symlink-receipt")
        index = json.loads(index_path.read_text(encoding="utf-8"))
        receipt = output / next(iter(index["receipt_files"]))
        saved = receipt.with_suffix(".saved")
        receipt.replace(saved)
        receipt.symlink_to(saved.name)
        with self.assertRaises(CollectorError):
            validate_owner_only_linux_bundle(
                output,
                repo=pathlib.Path(__file__).resolve().parent.parent,
                expected_uid=os.geteuid(),
            )

    def test_owner_only_index_rejects_unindexed_extra(self) -> None:
        output, _, _, _ = self.make_owner_only_bundle("extra")
        extra = output / "fabricated.json"
        extra.write_text("{}\n", encoding="utf-8")
        os.chmod(extra, 0o600)
        with self.assertRaises(CollectorError):
            validate_owner_only_linux_bundle(
                output,
                repo=pathlib.Path(__file__).resolve().parent.parent,
                expected_uid=os.geteuid(),
            )

    def test_owner_only_index_rejects_machine_index_mismatch(self) -> None:
        output, _, _, index_path = self.make_owner_only_bundle("index-mismatch")
        index = json.loads(index_path.read_text(encoding="utf-8"))
        index["machine_evidence"]["sha256"] = "f" * 64
        index_path.write_text(
            json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.chmod(index_path, 0o600)
        with self.assertRaises(CollectorError):
            validate_owner_only_linux_bundle(
                output,
                repo=pathlib.Path(__file__).resolve().parent.parent,
                expected_uid=os.geteuid(),
            )

    def test_owner_only_index_rejects_missing_private_index(self) -> None:
        output, _, _, index_path = self.make_owner_only_bundle("missing-index")
        index_path.unlink()
        with self.assertRaises(CollectorError):
            validate_owner_only_linux_bundle(
                output,
                repo=pathlib.Path(__file__).resolve().parent.parent,
                expected_uid=os.geteuid(),
            )

    def test_linux_wrapper_requires_exact_bundle_and_private_index_hash(self) -> None:
        wrapper = (
            pathlib.Path(__file__).resolve().parent / "linux_public_release_live_smoke.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("validate_owner_only_linux_bundle", wrapper)
        self.assertIn("expected_uid=0", wrapper)
        self.assertIn("--evidence-bundle-index-sha256", wrapper)

    def test_full_collection_compiles_with_exact_route_matrix(self) -> None:
        collector, _, _, output = self.make_collector()
        machine_path, screenshot = collector.collect()
        machine = json.loads(machine_path.read_text(encoding="utf-8"))
        native = compile_evidence(
            machine, output, self.artifact, screenshot, dict(self.binding)
        )
        self.assertEqual(native["direct_awg"]["port"], 9110)
        self.assertEqual(
            {(item["port"], item["security"]) for item in native["tested_xray_routes"]},
            {(80, "none"), (443, "tls")},
        )
        self.assertEqual(machine["double_vpn_direct_port"], 9210)
        self.assertEqual(
            {
                (item["port"], item["security"])
                for item in machine["lanes"]
                if item["kind"] == "double_vpn_xray"
            },
            {(8080, "none"), (8443, "tls")},
        )
        self.assertTrue((output / "EVIDENCE_INDEX.json").is_file())

    def test_compiler_emits_private_evidence_bundle_index_binding(self) -> None:
        collector, _, _, output = self.make_collector("private-index-transcript")
        machine_path, screenshot = collector.collect()
        machine = json.loads(machine_path.read_text(encoding="utf-8"))
        native = compile_evidence(
            machine,
            output,
            self.artifact,
            screenshot,
            dict(self.binding),
            "a" * 64,
        )
        self.assertEqual(native["evidence_bundle_index_sha256"], "a" * 64)

    def test_compiler_rejects_missing_double_vpn_xray_backup_route(self) -> None:
        collector, _, _, output = self.make_collector()
        machine_path, screenshot = collector.collect()
        machine = json.loads(machine_path.read_text(encoding="utf-8"))
        machine["lanes"] = [
            item
            for item in machine["lanes"]
            if not (
                item["kind"] == "double_vpn_xray"
                and item["port"] == 8443
                and item["security"] == "tls"
            )
        ]
        with self.assertRaises(MatrixError):
            compile_evidence(
                machine, output, self.artifact, screenshot, dict(self.binding)
            )

    def test_compiler_rejects_machine_bundle_from_stale_producer_contract(self) -> None:
        collector, _, _, output = self.make_collector()
        machine_path, screenshot = collector.collect()
        machine = json.loads(machine_path.read_text(encoding="utf-8"))
        current = dict(self.binding)
        current["producer_contract_sha256"] = "6" * 64
        with self.assertRaises(MatrixError):
            compile_evidence(machine, output, self.artifact, screenshot, current)

    def test_compiler_rejects_double_lane_that_does_not_reach_selected_exit(self) -> None:
        collector, _, _, output = self.make_collector()
        machine_path, screenshot = collector.collect()
        machine = json.loads(machine_path.read_text(encoding="utf-8"))
        double = next(
            item for item in machine["lanes"] if item["kind"] == "double_vpn_direct"
        )
        double["protected_egress_sha256"] = "7" * 64
        receipt_path = output / double["receipt_path"]
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["protected_egress_sha256"] = "7" * 64
        receipt_path.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        double["receipt_sha256"] = sha256_file(receipt_path)
        with self.assertRaises(MatrixError):
            compile_evidence(
                machine, output, self.artifact, screenshot, dict(self.binding)
            )

    def test_rejects_empty_double_vpn_identity(self) -> None:
        collector, driver, _, _ = self.make_collector()
        driver.empty_double_identity = True
        with self.assertRaises(CollectorError):
            collector.collect()

    def test_rejects_xray_forcing_that_blocks_wrong_mode_direct_port(self) -> None:
        collector, driver, _, _ = self.make_collector()
        driver.wrong_forcing_port = True
        with self.assertRaises(CollectorError):
            collector.collect()

    def test_arbitrary_dynamic_core_port_and_distinct_routes_are_bound(self) -> None:
        collector, driver, _, output = self.make_collector()
        driver.double_direct_port = 55210
        machine_path, screenshot = collector.collect()
        machine = json.loads(machine_path.read_text(encoding="utf-8"))
        compile_evidence(machine, output, self.artifact, screenshot, dict(self.binding))
        self.assertEqual(machine["double_vpn_direct_port"], 55210)
        double_xray = [
            lane for lane in machine["lanes"] if lane["kind"] == "double_vpn_xray"
        ]
        self.assertTrue(double_xray)
        self.assertTrue(
            all(lane["forcing_blocked_udp_port"] == 55210 for lane in double_xray)
        )

    def test_rejects_untriggered_network_change(self) -> None:
        collector, driver, _, _ = self.make_collector()
        driver.network_change_passed = False
        with self.assertRaises(CollectorError):
            collector.collect()

    def test_rejects_claimed_network_change_without_kernel_state_change(self) -> None:
        collector, driver, probe, _ = self.make_collector()
        driver.on_network_begin = lambda: None
        with self.assertRaises(CollectorError):
            collector.collect()

    def test_rejects_rollback_that_does_not_force_failure(self) -> None:
        collector, driver, _, _ = self.make_collector()
        driver.rollback_really_fails = False
        with self.assertRaises(CollectorError):
            collector.collect()

    def test_rejects_claimed_rollback_injection_without_state_change(self) -> None:
        collector, driver, probe, _ = self.make_collector()
        driver.on_rollback_inject = lambda: None
        with self.assertRaises(CollectorError):
            collector.collect()

    def test_rejects_insufficient_semantic_city_labels(self) -> None:
        collector, driver, _, _ = self.make_collector()
        driver.map_cities = ["Alpha", "alpha"]
        with self.assertRaises(CollectorError):
            collector.collect()

    def test_compiler_rejects_tampered_hash_bound_lane_receipt(self) -> None:
        collector, _, _, output = self.make_collector()
        machine_path, screenshot = collector.collect()
        machine = json.loads(machine_path.read_text(encoding="utf-8"))
        machine["lanes"][0]["rx_delta_bytes"] += 1
        with self.assertRaises(MatrixError):
            compile_evidence(
                machine, output, self.artifact, screenshot, dict(self.binding)
            )

    def test_compiler_rejects_wrong_forcing_port_even_with_receipt_tampering(self) -> None:
        collector, _, _, output = self.make_collector()
        machine_path, screenshot = collector.collect()
        machine = json.loads(machine_path.read_text(encoding="utf-8"))
        lane = next(item for item in machine["lanes"] if item["kind"] == "double_vpn_xray")
        lane["forcing_blocked_udp_port"] = machine["direct_awg_port"]
        receipt_path = output / lane["receipt_path"]
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["forcing_blocked_udp_port"] = machine["direct_awg_port"]
        receipt_path.write_text(json.dumps(receipt) + "\n", encoding="utf-8")
        lane["receipt_sha256"] = sha256_file(receipt_path)
        with self.assertRaises(MatrixError):
            compile_evidence(machine, output, self.artifact, screenshot, dict(self.binding))

    def test_compiler_rejects_wrong_mode_route_manifest_hash(self) -> None:
        collector, _, _, output = self.make_collector()
        machine_path, screenshot = collector.collect()
        machine = json.loads(machine_path.read_text(encoding="utf-8"))
        lane = next(item for item in machine["lanes"] if item["kind"] == "double_vpn_xray")
        lane["advertised_xray_routes_sha256"] = "f" * 64
        with self.assertRaises(MatrixError):
            compile_evidence(machine, output, self.artifact, screenshot, dict(self.binding))

    def test_compiler_rejects_double_lane_without_real_identity_hash(self) -> None:
        collector, _, _, output = self.make_collector()
        machine_path, screenshot = collector.collect()
        machine = json.loads(machine_path.read_text(encoding="utf-8"))
        double = next(item for item in machine["lanes"] if item["double_vpn_active"])
        double["double_vpn_core_id_sha256"] = __import__("hashlib").sha256(b"").hexdigest()
        with self.assertRaises(MatrixError):
            compile_evidence(
                machine, output, self.artifact, screenshot, dict(self.binding)
            )

    def test_production_root_gate_rejects_non_root_and_non_linux(self) -> None:
        proc_net_dev = self.root / "proc-net-dev"
        proc_net_dev.write_text("Inter-| Receive | Transmit\n", encoding="utf-8")
        with self.assertRaises(CollectorError):
            require_linux_root("posix", 1000, proc_net_dev)
        with self.assertRaises(CollectorError):
            require_linux_root("nt", 0, proc_net_dev)
        require_linux_root("posix", 0, proc_net_dev)

    def test_rejects_symlinked_input_and_output_parent(self) -> None:
        target = self.root / "target.bin"
        target.write_bytes(b"immutable")
        link = self.root / "linked.bin"
        real_parent = self.root / "real-output"
        linked_parent = self.root / "linked-output"
        real_parent.mkdir()
        try:
            link.symlink_to(target)
            linked_parent.symlink_to(real_parent, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")
        with self.assertRaises(CollectorError):
            reject_reparse_components(link, "test input", must_exist=True)
        with self.assertRaises(CollectorError):
            reject_reparse_components(
                linked_parent / "new-run", "test output", must_exist=False
            )

    def test_windows_reparse_attribute_is_rejected_without_symlink_privilege(self) -> None:
        self.assertTrue(
            is_reparse_point(types.SimpleNamespace(st_file_attributes=0x400))  # type: ignore[arg-type]
        )
        self.assertFalse(
            is_reparse_point(types.SimpleNamespace(st_file_attributes=0))  # type: ignore[arg-type]
        )

    def test_installed_tool_must_match_source_bytes_and_mode(self) -> None:
        exact = "1" * 64
        validate_installed_tool_binding(
            uid=0,
            mode=0o755,
            executable=True,
            installed_sha256=exact,
            source_sha256=exact,
            label="test driver",
        )
        with self.assertRaises(CollectorError):
            validate_installed_tool_binding(
                uid=0,
                mode=0o755,
                executable=True,
                installed_sha256="2" * 64,
                source_sha256=exact,
                label="test driver",
            )
        with self.assertRaises(CollectorError):
            validate_installed_tool_binding(
                uid=0,
                mode=0o777,
                executable=True,
                installed_sha256=exact,
                source_sha256=exact,
                label="test driver",
            )


if __name__ == "__main__":
    unittest.main()
