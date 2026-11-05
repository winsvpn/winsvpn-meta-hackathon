#!/usr/bin/env python3
"""Fail-closed tests for Apple final machine-evidence collection."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import plistlib
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from unittest import mock

import apple_final_evidence_collector as subject

from apple_final_evidence_collector import (
    APPLE_PUBLIC_PRODUCER,
    CONTRACT,
    Collector,
    CollectorError,
    embedded_watch_identity_from_ipa,
    hold_exact_artifact,
    owner_evidence_set_sha256,
    pending_owner_evidence_set,
    reject_mutable_tmp_authority,
    sha256_file,
    validate_macos_architecture_inventory,
    validate_owner_only_bundle,
)
from linux_apple_release_matrix_evidence import MatrixError, compile_evidence
from public_release_live_smoke_common import producer_contract_hash


EMPTY = hashlib.sha256(b"").hexdigest()


class FakeAppleDriver:
    def __init__(self, artifact: pathlib.Path) -> None:
        self.artifact = artifact
        self.routes = [
            {"protocol": "tcp", "port": 80, "security": "none"},
            {"protocol": "tcp", "port": 443, "security": "tls"},
        ]
        self.double_routes = [
            {"protocol": "tcp", "port": 8080, "security": "none"},
            {"protocol": "tcp", "port": 8443, "security": "tls"},
        ]
        self.direct_port = 9110
        self.double_direct_port = 9210
        self.ui_connect = True
        self.rollback_hash = "9" * 64
        self.cities = ["Alpha", "Beta", "Gamma"]
        self.wrong_forcing_port = False

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
        if action == "routes":
            return self.base(action, advertised_xray_routes=list(self.routes))
        if action == "clean_install":
            return self.base(
                action,
                source_artifact_sha256=sha256_file(self.artifact),
                clean_remove_passed=True,
                install_passed=True,
                installed_identity_sha256="5" * 64,
                exact_install_source_verified=True,
                app_version="1.0.17",
                build_number="34",
                install_method=(
                    "macos-signed-package"
                    if values["platform"] == "macos"
                    else "xcode-devicectl-exact-ipa"
                ),
                installed_bundle_id="org.winsvpn.app",
                installed_team_id="5YT8H4U72M",
                installed_designated_requirement_sha256="d" * 64,
                install_session_sha256="e" * 64,
            )
        if action == "lane":
            kind = values["kind"]
            double = kind.startswith("double_vpn")
            xray = kind in {"xray", "double_vpn_xray"}
            actual_direct = self.double_direct_port if double else self.direct_port
            mode_routes = self.double_routes if double else self.routes
            return self.base(
                action,
                lane_id=values["lane_id"],
                kind=kind,
                protocol="tcp" if xray else "udp",
                port=int(values["port"]) if xray else actual_direct,
                security=values["security"] if xray else "none",
                actual_direct_port=actual_direct,
                advertised_xray_routes=list(mode_routes),
                forcing_blocked_udp_port=(
                    (self.direct_port if self.wrong_forcing_port else actual_direct)
                    if xray else None
                ),
                ui_connect_invoked=self.ui_connect,
                ui_disconnect_invoked=True,
                connected_observed=True,
                double_vpn_active=double,
                rx_delta_bytes=2048,
                tx_delta_bytes=1024,
                protected_egress_sha256="7" * 64,
                provider_executable_sha256="6" * 64,
                control_state_before_sha256="8" * 64,
                control_state_after_sha256="8" * 64,
                forcing_applied=xray,
                forcing_restored=True,
                double_vpn_core_id_sha256=hashlib.sha256(b"core" if double else b"").hexdigest(),
                double_vpn_exit_slug_sha256=hashlib.sha256(b"exit" if double else b"").hexdigest(),
            )
        if action == "split":
            return self.base(
                action,
                scope="destination-consumer-mdm-per-app-only",
                consumer_per_app_available=False,
                mdm_per_app_only=True,
                selection_applied_by_harness=True,
                selected_scope_bypassed=True,
                ordinary_scope_protected=True,
            )
        if action == "leak":
            return self.base(action, dns_protected=True, ipv4_protected=True, ipv6_escape_blocked=True, public_canaries_agree=True)
        if action == "network_change":
            return self.base(action, change_triggered_by_harness=True, pre_change_protected=True, post_change_recovered=True, post_change_protected=True)
        if action == "teardown":
            return self.base(action, disconnect_requested_by_harness=True, provider_absent=True, protected_routes_absent=True, transient_state_absent=True)
        if action == "rollback":
            return self.base(action, failure_injected_by_harness=True, prior_state_sha256="9" * 64, restored_state_sha256=self.rollback_hash, recovery_connect_passed=True)
        if action == "capture_map":
            path = pathlib.Path(values["output"])
            path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"map" * 2048)
            return self.base(
                action,
                capture_method=(
                    "macos-window-capture"
                    if values["platform"] == "macos"
                    else "xcode-device-ui-capture"
                ),
                screenshot_sha256=sha256_file(path),
                radius_label_50_miles_detected=True,
                surrounding_city_labels=list(self.cities),
                target_marker_detected=True,
                viewport_not_world_zoom=True,
            )
        if action == "finalize":
            return self.base(
                action,
                restored=True,
                baseline_state_removed=True,
            )
        raise AssertionError(action)


class AppleCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        if sys.platform.startswith("linux"):
            self.temp_parent = pathlib.Path(tempfile.gettempdir()) / (
                f"winsvpn-apple-collector-unit-tests-{os.getuid()}"
            )
        else:
            self.temp_parent = (
                pathlib.Path(__file__).resolve().parent.parent
                / ".artifacts"
                / "apple-collector-unit-tests"
            )
        self.temp_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=self.temp_parent)
        self.root = pathlib.Path(self.temp.name)
        self.artifact = self.root / "winsvpn.pkg"
        self.artifact.write_bytes(b"exact-apple-artifact")
        self.ipa = self.root / "WinsVPN.ipa"
        self._write_ipa(self.ipa)
        self.xcarchive = self.root / "Runner.xcarchive"
        (self.xcarchive / "Products/Applications/Runner.app").mkdir(parents=True)
        (self.xcarchive / "Info.plist").write_bytes(
            plistlib.dumps({"ArchiveVersion": 2})
        )
        self.obfuscation_receipt = self.root / "obfuscation.json"
        self.obfuscation_receipt.write_text('{"receipt":"obfuscation"}\n', encoding="ascii")
        self.symbol_custody_receipt = self.root / "symbol-custody.json"
        self.symbol_custody_receipt.write_text(
            '{"receipt":"symbol-custody"}\n', encoding="ascii"
        )
        self.route_inventory = self.root / "ios-route-inventory.json"
        self.route_inventory.write_text("{}\n", encoding="utf-8")
        self.ssh_config = self.root / "ios-ssh-config"
        self.ssh_config.write_text("Host spain\n  HostName 192.0.2.1\n", encoding="utf-8")
        repo = pathlib.Path(__file__).resolve().parent.parent
        self.binding = {
            "release_input_index_sha256": "1" * 64,
            "platform_manifest_sha256": "2" * 64,
            "artifact_input_fingerprint_sha256": "3" * 64,
            "build_receipt_sha256": "4" * 64,
            "producer_contract_sha256": producer_contract_hash(
                repo, APPLE_PUBLIC_PRODUCER
            ),
        }

    @staticmethod
    def _write_ipa(path: pathlib.Path, *, include_watch: bool = True) -> None:
        host = {
            "CFBundleIdentifier": subject.HOST_BUNDLE_ID,
            "CFBundleShortVersionString": subject.CANONICAL_APP_VERSION,
            "CFBundleVersion": subject.CANONICAL_BUILD_NUMBER,
        }
        watch = {
            "CFBundleIdentifier": subject.WATCH_BUNDLE_ID,
            "CFBundleExecutable": subject.WATCH_EXECUTABLE,
            "CFBundleShortVersionString": subject.CANONICAL_APP_VERSION,
            "CFBundleVersion": subject.CANONICAL_BUILD_NUMBER,
            "WKCompanionAppBundleIdentifier": subject.HOST_BUNDLE_ID,
            "WKRunsIndependentlyOfCompanionApp": False,
        }
        privacy = plistlib.dumps(
            {
                "NSPrivacyTracking": False,
                "NSPrivacyTrackingDomains": [],
                "NSPrivacyCollectedDataTypes": [],
                "NSPrivacyAccessedAPITypes": [],
            }
        )
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("Payload/Runner.app/Info.plist", plistlib.dumps(host))
            if include_watch:
                prefix = "Payload/Runner.app/Watch/WinsWatch.app"
                archive.writestr(f"{prefix}/Info.plist", plistlib.dumps(watch))
                archive.writestr(f"{prefix}/WinsWatch", b"exact-watch-executable")
                archive.writestr(f"{prefix}/PrivacyInfo.xcprivacy", privacy)

    def _ios_verification(
        self,
        ipa: pathlib.Path,
        archive: pathlib.Path,
        obfuscation_receipt: pathlib.Path,
        symbol_custody_receipt: pathlib.Path,
    ) -> dict[str, object]:
        bindings = subject._ios_release_input_bindings(
            ipa, archive, obfuscation_receipt, symbol_custody_receipt
        )
        watch = embedded_watch_identity_from_ipa(ipa)
        result = {
            "schema_version": 1,
            "bundle_id": watch["bundle_id"],
            "companion_bundle_id": watch["companion_bundle_id"],
            "version": watch["version"],
            "build_number": watch["build"],
            "parent_version": subject.CANONICAL_APP_VERSION,
            "parent_build_number": subject.CANONICAL_BUILD_NUMBER,
            "ipa_sha256": bindings["ipa_sha256"],
            "ipa_bytes": bindings["ipa_bytes"],
            "executable": watch["executable"],
            "executable_sha256": watch["executable_sha256"],
            "architectures": ["arm64"],
            "watch_connectivity_dependency": (
                subject.watch_artifact_schema.WATCHCONNECTIVITY_DYLIB
            ),
            "wc_session_import": "_OBJC_CLASS_$_WCSession",
            "required_selectors": sorted(
                subject.watch_artifact_schema.REQUIRED_SELECTORS
            ),
            "privacy_manifest_sha256": watch["privacy_info_sha256"],
            "debug_sections": False,
        }
        result_sha256 = hashlib.sha256(
            json.dumps(
                result, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("ascii")
        ).hexdigest()
        return {
            "schema_version": subject.IOS_RELEASE_VERIFICATION_SCHEMA_VERSION,
            "contract": subject.IOS_RELEASE_VERIFICATION_CONTRACT,
            "artifact_contract": subject.ios_release_verifier.ARTIFACT_CONTRACT,
            "verifier_source_sha256": sha256_file(
                subject.IOS_RELEASE_VERIFIER_PATH
            ),
            **bindings,
            "host_version": subject.CANONICAL_APP_VERSION,
            "host_build_number": subject.CANONICAL_BUILD_NUMBER,
            "watch_artifact_verification": {
                "contract": "winsvpn-watch-artifact-verification-v1",
                "artifact_sha256": bindings["ipa_sha256"],
                "verifier": {
                    "path": "tools/apple_watch_artifact_verifier.py",
                    "sha256": sha256_file(subject.WATCH_ARTIFACT_VERIFIER_PATH),
                },
                "result": result,
                "result_sha256": result_sha256,
            },
            "watch_profile_verified": True,
            "watch_signature_verified": True,
            "watch_distribution_identity_verified": True,
            "watch_platform": "WATCHOS",
            "watch_minimum_os": subject.ios_release_verifier.EXPECTED_MINIMUM_WATCHOS,
            "watch_uuids": ["44444444-4444-4444-4444-444444444444"],
            "watch_uuid_parity_verified": True,
            "watch_dsym_coverage_verified": True,
        }

    def make_ios(self, name: str, *, verifier=None, artifact: pathlib.Path | None = None):
        selected = artifact or self.ipa
        driver = FakeAppleDriver(selected)
        collector = Collector(
            driver=driver,
            platform="ios",
            artifact=selected,
            output_dir=self.root / name,
            binding=dict(self.binding),
            ios_route_inventory=self.route_inventory,
            ios_ssh_config=self.ssh_config,
            ios_archive=self.xcarchive,
            ios_obfuscation_receipt=self.obfuscation_receipt,
            ios_symbol_custody_receipt=self.symbol_custody_receipt,
            ios_release_evidence_verifier=verifier or self._ios_verification,
            require_owner_signed=False,
        )
        return collector, driver

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make(self, name: str):
        driver = FakeAppleDriver(self.artifact)
        collector = Collector(
            driver=driver,
            platform="macos",
            artifact=self.artifact,
            output_dir=self.root / name,
            binding=dict(self.binding),
            require_owner_signed=False,
        )
        return collector, driver

    def test_finalization_failure_never_publishes_evidence_index(self) -> None:
        collector, driver = self.make("finalization-failure")
        original = driver.call

        def incomplete(action: str, **values: str):
            if action == "finalize":
                return driver.base(
                    action, restored=False, baseline_state_removed=False
                )
            return original(action, **values)

        driver.call = incomplete
        with self.assertRaisesRegex(CollectorError, "finalization"):
            collector.collect()
        self.assertFalse(collector.final_output_dir.exists())
        self.assertFalse((collector.output_dir / "EVIDENCE_INDEX.json").exists())
        collector.close()
        self.assertFalse(collector.output_dir.exists())

    def test_collector_bounded_command_caps_output_timeout_and_descendants(self) -> None:
        with self.assertRaisesRegex(CollectorError, "output bound"):
            subject._bounded_command(
                ["/bin/sh", "-c", "yes x"],
                label="noisy collector child",
                timeout=3,
            )
        with self.assertRaisesRegex(CollectorError, "time bound"):
            subject._bounded_command(
                ["/bin/sh", "-c", "sleep 30"],
                label="hung collector child",
                timeout=1,
            )
        completed = subject._bounded_command(
            [
                "/bin/sh",
                "-c",
                'sleep 30 >/dev/null 2>&1 & printf "%s" "$!"',
            ],
            label="zero-exit collector leader",
            timeout=3,
        )
        child_pid = int(completed.stdout.decode("ascii"))
        for _attempt in range(50):
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.01)
        else:
            self.fail("collector left a descendant process alive")

    @unittest.skipUnless(sys.platform == "darwin", "Xcode custody is macOS-only")
    def test_ios_runner_uses_retained_xcode_fd_and_scrubbed_environment(self) -> None:
        completed = subprocess.CompletedProcess(["/usr/bin/xcrun"], 0, b"", b"")
        with subject._AuthenticatedXcodeSelection() as xcode, mock.patch.object(
            subject, "_bounded_command", return_value=completed
        ) as bounded:
            subject._authoritative_ios_command_runner(
                ["/usr/bin/xcrun", "vtool", "-show-build", "/dev/null"],
                xcode,
            )
        kwargs = bounded.call_args.kwargs
        self.assertEqual(kwargs["env"]["DEVELOPER_DIR"], xcode.descriptor_path)
        self.assertEqual(kwargs["pass_fds"], (xcode.descriptor,))
        self.assertNotIn("TOOLCHAINS", kwargs["env"])
        self.assertNotIn("DYLD_LIBRARY_PATH", kwargs["env"])

    def test_complete_matrix_compiles(self) -> None:
        collector, _ = self.make("complete")
        machine_path, screenshot = collector.collect()
        machine = json.loads(machine_path.read_text(encoding="utf-8"))
        native = compile_evidence(machine, machine_path.parent, self.artifact, screenshot, dict(self.binding))
        self.assertEqual(len(native["tested_xray_routes"]), 2)
        self.assertEqual(
            len([lane for lane in machine["lanes"] if lane["kind"] == "double_vpn_xray"]),
            2,
        )
        self.assertEqual(machine["direct_awg_port"], 9110)
        self.assertEqual(machine["double_vpn_direct_port"], 9210)
        self.assertEqual(
            {(route["port"], route["security"]) for route in machine["double_vpn_advertised_xray_routes"]},
            {(8080, "none"), (8443, "tls")},
        )

    def test_owner_only_bundle_rejects_fabricated_user_owner(self) -> None:
        collector, _ = self.make("fabricated-user-owner")
        machine_path, _ = collector.collect()
        with self.assertRaises(CollectorError):
            validate_owner_only_bundle(
                machine_path.parent,
                platform="macos",
                repo=pathlib.Path(__file__).resolve().parent.parent,
                expected_uid=collector.owner_uid + 1,
            )

    def test_owner_only_bundle_returns_exact_private_index_hash(self) -> None:
        collector, _ = self.make("private-index-hash")
        machine_path, _ = collector.collect()
        expected_machine, expected_map, index_sha256 = validate_owner_only_bundle(
            machine_path.parent,
            platform="macos",
            repo=pathlib.Path(__file__).resolve().parent.parent,
            expected_uid=collector.owner_uid,
        )
        self.assertEqual(expected_machine, machine_path)
        self.assertEqual(expected_map, machine_path.parent / "map.png")
        self.assertEqual(
            index_sha256,
            sha256_file(machine_path.parent / "EVIDENCE_INDEX.json"),
        )

    def test_owner_only_bundle_rejects_missing_private_index(self) -> None:
        collector, _ = self.make("missing-private-index")
        machine_path, _ = collector.collect()
        (machine_path.parent / "EVIDENCE_INDEX.json").unlink()
        with self.assertRaises(CollectorError):
            validate_owner_only_bundle(
                machine_path.parent,
                platform="macos",
                repo=pathlib.Path(__file__).resolve().parent.parent,
                expected_uid=collector.owner_uid,
            )

    def test_owner_only_bundle_rejects_wrong_directory_mode(self) -> None:
        if os.name == "nt":
            self.skipTest("Windows compatibility stat does not expose POSIX directory modes")
        collector, _ = self.make("wrong-bundle-mode")
        machine_path, _ = collector.collect()
        os.chmod(machine_path.parent, 0o755)
        self.assertEqual(stat.S_IMODE(machine_path.parent.stat().st_mode), 0o755)
        with self.assertRaises(CollectorError):
            validate_owner_only_bundle(
                machine_path.parent,
                platform="macos",
                repo=pathlib.Path(__file__).resolve().parent.parent,
                expected_uid=collector.owner_uid,
            )

    def test_owner_only_bundle_rejects_symlinked_component(self) -> None:
        collector, _ = self.make("owner-symlink")
        machine_path, _ = collector.collect()
        receipt = next(
            machine_path.parent / name
            for name in json.loads(
                (machine_path.parent / "EVIDENCE_INDEX.json").read_text(encoding="utf-8")
            )["receipt_sha256"]
        )
        saved = receipt.with_suffix(".saved")
        receipt.replace(saved)
        try:
            receipt.symlink_to(saved.name)
        except OSError as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")
        with self.assertRaises(CollectorError):
            validate_owner_only_bundle(
                machine_path.parent,
                platform="macos",
                repo=pathlib.Path(__file__).resolve().parent.parent,
                expected_uid=collector.owner_uid,
            )

    def test_collector_refuses_to_reuse_or_overwrite_bundle(self) -> None:
        collector, _ = self.make("no-overwrite")
        collector.collect()
        with self.assertRaises(CollectorError):
            Collector(
                driver=FakeAppleDriver(self.artifact),
                platform="macos",
                artifact=self.artifact,
                output_dir=collector.output_dir,
                binding=dict(self.binding),
            )

    def test_public_wrapper_requires_root_owned_exact_collector_bundle(self) -> None:
        wrapper = (
            pathlib.Path(__file__).resolve().parent / "apple_public_release_live_smoke.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("validate_owner_only_bundle", wrapper)
        self.assertIn("expected_uid=0", wrapper)
        self.assertIn("machine_input != expected_machine", wrapper)
        self.assertIn("map_input != expected_map", wrapper)
        self.assertIn("--evidence-bundle-index-sha256", wrapper)

    def test_compiler_emits_private_evidence_bundle_index_binding(self) -> None:
        collector, _ = self.make("private-index-transcript")
        machine_path, screenshot = collector.collect()
        machine = json.loads(machine_path.read_text(encoding="utf-8"))
        native = compile_evidence(
            machine,
            machine_path.parent,
            self.artifact,
            screenshot,
            dict(self.binding),
            "b" * 64,
        )
        self.assertEqual(native["evidence_bundle_index_sha256"], "b" * 64)

    def test_arbitrary_dynamic_core_port_is_bound_without_9110_substitution(self) -> None:
        collector, driver = self.make("dynamic-core")
        driver.double_direct_port = 55210
        machine_path, screenshot = collector.collect()
        machine = json.loads(machine_path.read_text(encoding="utf-8"))
        self.assertEqual(machine["direct_awg_port"], 9110)
        self.assertEqual(machine["double_vpn_direct_port"], 55210)
        double = next(lane for lane in machine["lanes"] if lane["kind"] == "double_vpn_direct")
        self.assertEqual(double["port"], 55210)
        compile_evidence(machine, machine_path.parent, self.artifact, screenshot, dict(self.binding))

    def test_ios_uses_exact_ipa_install_session_without_claiming_container_export(self) -> None:
        collector, _ = self.make_ios("ios")
        machine_path, screenshot = collector.collect()
        machine = json.loads(machine_path.read_text(encoding="utf-8"))
        install_receipt = json.loads(
            (machine_path.parent / machine["install"]["receipt_path"]).read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(install_receipt["install_method"], "xcode-devicectl-exact-ipa")
        watch_receipt = json.loads(
            (machine_path.parent / "watch-companion.json").read_text(encoding="utf-8")
        )
        release = watch_receipt["release_artifact_verification"]
        self.assertTrue(release["watch_profile_verified"])
        self.assertTrue(release["watch_signature_verified"])
        self.assertTrue(release["watch_distribution_identity_verified"])
        self.assertTrue(release["watch_uuid_parity_verified"])
        self.assertTrue(release["watch_dsym_coverage_verified"])
        self.assertEqual(release["watch_platform"], "WATCHOS")
        self.assertEqual(release["watch_minimum_os"], "9.0")
        compile_evidence(
            machine,
            machine_path.parent,
            self.ipa,
            screenshot,
            dict(self.binding),
        )

    def test_ios_release_verifier_omitted_watch_evidence_is_rejected(self) -> None:
        def omitted(*args):
            record = self._ios_verification(*args)
            del record["watch_dsym_coverage_verified"]
            return record

        collector, _ = self.make_ios("ios-omitted-verifier-watch", verifier=omitted)
        with self.assertRaisesRegex(CollectorError, "fields are invalid"):
            collector.collect()

    def test_watch_snapshot_helper_passes_exact_held_reviewed_source(self) -> None:
        digest = sha256_file(self.ipa)
        expected = subject.WATCH_ARTIFACT_VERIFIER_SHA256
        result = {"result": {"executable_sha256": "a" * 64}}
        with mock.patch.object(
            subject, "verify_watch_artifact_snapshot", return_value=result
        ) as verify:
            self.assertIs(
                subject._verify_watch_release_snapshot(
                    self.ipa,
                    artifact_sha256=digest,
                    artifact_size=self.ipa.stat().st_size,
                ),
                result,
            )
        verify.assert_called_once()
        args, kwargs = verify.call_args
        self.assertEqual(args, (self.ipa,))
        self.assertEqual(kwargs["artifact_sha256"], digest)
        self.assertEqual(kwargs["artifact_size"], self.ipa.stat().st_size)
        self.assertEqual(kwargs["expected_verifier_sha256"], expected)
        self.assertEqual(
            hashlib.sha256(kwargs["verifier_source"]).hexdigest(), expected
        )

    def test_ios_release_verifier_watch_field_drift_is_rejected(self) -> None:
        def drifted(*args):
            record = self._ios_verification(*args)
            snapshot = record["watch_artifact_verification"]
            snapshot["result"]["parent_build_number"] = "31"
            snapshot["result_sha256"] = hashlib.sha256(
                json.dumps(
                    snapshot["result"],
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("ascii")
            ).hexdigest()
            return record

        collector, _ = self.make_ios("ios-watch-field-drift", verifier=drifted)
        with self.assertRaisesRegex(CollectorError, "incomplete or stale"):
            collector.collect()

    def test_ios_cross_candidate_symbol_receipt_substitution_is_rejected(self) -> None:
        def substituted(*args):
            record = self._ios_verification(*args)
            record["symbol_custody_receipt_sha256"] = "f" * 64
            return record

        collector, _ = self.make_ios("ios-cross-candidate-receipt", verifier=substituted)
        with self.assertRaisesRegex(CollectorError, "different candidate"):
            collector.collect()

    def test_ios_stale_release_verifier_schema_is_rejected(self) -> None:
        def stale(*args):
            record = self._ios_verification(*args)
            record["schema_version"] = 0
            return record

        collector, _ = self.make_ios("ios-stale-verifier", verifier=stale)
        with self.assertRaisesRegex(CollectorError, "schema or source is stale"):
            collector.collect()

    def test_authoritative_ios_verifier_maps_watch_profile_uuid_and_dsym_proof(self) -> None:
        expected = self._ios_verification(
            self.ipa,
            self.xcarchive,
            self.obfuscation_receipt,
            self.symbol_custody_receipt,
        )
        bundle = mock.Mock(
            app_version=subject.CANONICAL_APP_VERSION,
            build_number=subject.CANONICAL_BUILD_NUMBER,
            watch_uuids=frozenset(expected["watch_uuids"]),
        )
        with (
            mock.patch.object(subject.ios_release_verifier, "verify_release_pair") as pair,
            mock.patch.object(
                subject.ios_release_verifier,
                "_archive_app",
                return_value=self.xcarchive / "Products/Applications/Runner.app",
            ),
            mock.patch.object(
                subject.ios_release_verifier,
                "verify_app_bundle",
                return_value=bundle,
            ) as bundle_verifier,
            mock.patch.object(
                subject.ios_release_verifier,
                "_archive_dsym_uuids",
                return_value=frozenset(expected["watch_uuids"]),
            ),
            mock.patch.object(
                subject,
                "verify_watch_artifact_snapshot",
                return_value=expected["watch_artifact_verification"],
            ),
        ):
            actual = subject.authoritative_ios_release_verification(
                self.ipa,
                self.xcarchive,
                self.obfuscation_receipt,
                self.symbol_custody_receipt,
            )
        pair.assert_called_once()
        bundle_verifier.assert_called_once()
        self.assertEqual(
            bundle_verifier.call_args.kwargs,
            {"distribution": False},
            "the xcarchive is development-signed; only the IPA proves distribution",
        )
        self.assertTrue(actual["watch_profile_verified"])
        self.assertTrue(actual["watch_signature_verified"])
        self.assertTrue(actual["watch_distribution_identity_verified"])
        self.assertTrue(actual["watch_uuid_parity_verified"])
        self.assertTrue(actual["watch_dsym_coverage_verified"])
        self.assertEqual(actual["watch_uuids"], expected["watch_uuids"])

    def test_authoritative_stale_symbol_receipt_remains_owner_blocked(self) -> None:
        with mock.patch.object(
            subject.ios_release_verifier,
            "verify_release_pair",
            side_effect=subject.ios_release_verifier.VerificationError(
                "symbol-custody receipt is stale"
            ),
        ):
            with self.assertRaisesRegex(
                CollectorError, "OWNER-BLOCKED.*symbol-custody receipt is stale"
            ):
                subject.authoritative_ios_release_verification(
                    self.ipa,
                    self.xcarchive,
                    self.obfuscation_receipt,
                    self.symbol_custody_receipt,
                )

    def test_ios_missing_xcarchive_is_owner_blocked(self) -> None:
        missing = self.root / "missing.xcarchive"
        with self.assertRaisesRegex(CollectorError, "OWNER-BLOCKED.*xcarchive"):
            Collector(
                driver=FakeAppleDriver(self.ipa),
                platform="ios",
                artifact=self.ipa,
                output_dir=self.root / "ios-missing-xcarchive",
                binding=dict(self.binding),
                ios_route_inventory=self.route_inventory,
                ios_ssh_config=self.ssh_config,
                ios_archive=missing,
                ios_obfuscation_receipt=self.obfuscation_receipt,
                ios_symbol_custody_receipt=self.symbol_custody_receipt,
                ios_release_evidence_verifier=self._ios_verification,
                require_owner_signed=False,
            )

    def test_ios_missing_symbol_custody_receipt_is_owner_blocked(self) -> None:
        missing = self.root / "missing-symbol-custody.json"
        with self.assertRaisesRegex(
            CollectorError, "OWNER-BLOCKED.*symbol-custody receipt"
        ):
            Collector(
                driver=FakeAppleDriver(self.ipa),
                platform="ios",
                artifact=self.ipa,
                output_dir=self.root / "ios-missing-symbol-custody",
                binding=dict(self.binding),
                ios_route_inventory=self.route_inventory,
                ios_ssh_config=self.ssh_config,
                ios_archive=self.xcarchive,
                ios_obfuscation_receipt=self.obfuscation_receipt,
                ios_symbol_custody_receipt=missing,
                ios_release_evidence_verifier=self._ios_verification,
                require_owner_signed=False,
            )

    def test_owner_signed_ios_cannot_substitute_release_verifier(self) -> None:
        with self.assertRaisesRegex(CollectorError, "cannot substitute"):
            Collector(
                driver=FakeAppleDriver(self.ipa),
                platform="ios",
                artifact=self.ipa,
                output_dir=self.root / "ios-substituted-production-verifier",
                binding=dict(self.binding),
                ios_route_inventory=self.route_inventory,
                ios_ssh_config=self.ssh_config,
                ios_archive=self.xcarchive,
                ios_obfuscation_receipt=self.obfuscation_receipt,
                ios_symbol_custody_receipt=self.symbol_custody_receipt,
                ios_release_evidence_verifier=self._ios_verification,
                require_owner_signed=True,
            )

    def test_rejects_non_ui_connect(self) -> None:
        collector, driver = self.make("no-ui")
        driver.ui_connect = False
        with self.assertRaises(CollectorError):
            collector.collect()

    def test_rejects_xray_forcing_that_blocks_wrong_mode_direct_port(self) -> None:
        collector, driver = self.make("wrong-forcing-port")
        driver.wrong_forcing_port = True
        with self.assertRaises(CollectorError):
            collector.collect()

    def test_rejects_unrestored_rollback(self) -> None:
        collector, driver = self.make("rollback")
        driver.rollback_hash = "0" * 64
        with self.assertRaises(CollectorError):
            collector.collect()

    def test_rejects_insufficient_map_city_semantics(self) -> None:
        collector, driver = self.make("map")
        driver.cities = ["Alpha", "alpha"]
        with self.assertRaises(CollectorError):
            collector.collect()

    def test_compiler_rejects_tampered_apple_lane_receipt(self) -> None:
        collector, _ = self.make("tamper")
        machine_path, screenshot = collector.collect()
        machine = json.loads(machine_path.read_text(encoding="utf-8"))
        machine["lanes"][0]["tx_delta_bytes"] += 1
        with self.assertRaises(MatrixError):
            compile_evidence(machine, machine_path.parent, self.artifact, screenshot, dict(self.binding))

    def test_compiler_rejects_wrong_mode_route_manifest_hash(self) -> None:
        collector, _ = self.make("wrong-mode-route-hash")
        machine_path, screenshot = collector.collect()
        machine = json.loads(machine_path.read_text(encoding="utf-8"))
        lane = next(item for item in machine["lanes"] if item["kind"] == "double_vpn_xray")
        lane["advertised_xray_routes_sha256"] = "f" * 64
        with self.assertRaises(MatrixError):
            compile_evidence(
                machine, machine_path.parent, self.artifact, screenshot, dict(self.binding)
            )

    def test_compiler_rejects_stale_apple_producer_contract(self) -> None:
        collector, _ = self.make("producer")
        machine_path, screenshot = collector.collect()
        machine = json.loads(machine_path.read_text(encoding="utf-8"))
        stale = dict(self.binding)
        stale["producer_contract_sha256"] = "b" * 64
        with self.assertRaises(MatrixError):
            compile_evidence(machine, machine_path.parent, self.artifact, screenshot, stale)

    def test_omitted_watch_ipa_is_rejected(self) -> None:
        ipa = self.root / "no-watch.ipa"
        host = {
            "CFBundleIdentifier": "org.winsvpn.app",
            "CFBundleShortVersionString": "1.0.17",
            "CFBundleVersion": "34",
            "CFBundleSupportedPlatforms": ["iPhoneOS"],
        }
        packet = {
            "CFBundleIdentifier": "org.winsvpn.app.PacketTunnel",
            "CFBundleShortVersionString": "1.0.17",
            "CFBundleVersion": "34",
        }
        privacy = {
            "NSPrivacyTracking": False,
            "NSPrivacyTrackingDomains": [],
            "NSPrivacyCollectedDataTypes": [],
            "NSPrivacyAccessedAPITypes": [],
        }
        with zipfile.ZipFile(ipa, "w") as archive:
            archive.writestr("Payload/Runner.app/Info.plist", plistlib.dumps(host))
            archive.writestr(
                "Payload/Runner.app/PrivacyInfo.xcprivacy", plistlib.dumps(privacy)
            )
            archive.writestr(
                "Payload/Runner.app/PlugIns/PacketTunnel.appex/Info.plist",
                plistlib.dumps(packet),
            )
            archive.writestr(
                "Payload/Runner.app/PlugIns/PacketTunnel.appex/PrivacyInfo.xcprivacy",
                plistlib.dumps(privacy),
            )
        with self.assertRaises(CollectorError) as raised:
            embedded_watch_identity_from_ipa(ipa)
        self.assertIn("omitted the embedded watchOS companion", str(raised.exception))

        collector, _ = self.make_ios("ios-omitted-watch", artifact=ipa)
        with self.assertRaises(CollectorError) as collect_raised:
            collector.collect()
        self.assertIn("omitted the embedded watchOS companion", str(collect_raised.exception))

    def test_missing_architecture_and_tmp_authority_and_changed_evidence(self) -> None:
        with self.assertRaises(CollectorError) as raised:
            validate_macos_architecture_inventory(
                {
                    "required_architectures": ["arm64", "x86_64"],
                    "shipped": [
                        {
                            "path": "Contents/MacOS/WinsVPN",
                            "sha256": "a" * 64,
                            "size_bytes": 4,
                            "architectures": ["arm64"],
                        }
                    ],
                },
                require_complete=True,
            )
        self.assertIn("missing shipped macOS architecture", str(raised.exception))
        with self.assertRaises(CollectorError) as tmp_raised:
            reject_mutable_tmp_authority(
                "/tmp/wins_apple_current_both_live_runtime_019f58ea.log",
                "runtime log",
            )
        self.assertIn("mutable /tmp logs", str(tmp_raised.exception))

        snapshot = "b" * 64
        pending = pending_owner_evidence_set(app_store_privacy_snapshot_sha256=snapshot)
        with self.assertRaises(CollectorError) as pending_raised:
            owner_evidence_set_sha256(pending)
        self.assertIn("incomplete post-build evidence set", str(pending_raised.exception))

        complete = dict(pending)
        complete.update(
            {
                "release_input_index_sha256": "1" * 64,
                "ios_artifact_sha256": "2" * 64,
                "ios_artifact_size_bytes": 12,
                "watch_executable_sha256": "3" * 64,
                "watch_privacy_info_sha256": "4" * 64,
                "macos_artifact_sha256": "5" * 64,
                "macos_artifact_size_bytes": 14,
                "macos_architecture_inventory": {
                    "required_architectures": ["arm64", "x86_64"],
                    "shipped": [
                        {
                            "path": "Contents/MacOS/WinsVPN",
                            "sha256": "6" * 64,
                            "size_bytes": 7,
                            "architectures": ["arm64", "x86_64"],
                        }
                    ],
                },
                "runtime_evidence_sha256": "7" * 64,
                "watch_companion_smoke_sha256": "8" * 64,
                "archive_privacy_inventory_sha256": "9" * 64,
                "final_receipt_sha256": {"FINAL.json": "a" * 64},
            }
        )
        digest = owner_evidence_set_sha256(complete)
        mutated = dict(complete)
        mutated["runtime_evidence_sha256"] = "c" * 64
        self.assertNotEqual(digest, owner_evidence_set_sha256(mutated))

    def test_compiler_rejects_symlinked_receipt_even_when_bytes_match(self) -> None:
        collector, _ = self.make("symlink")
        machine_path, screenshot = collector.collect()
        machine = json.loads(machine_path.read_text(encoding="utf-8"))
        receipt = machine_path.parent / machine["lanes"][0]["receipt_path"]
        copy_path = receipt.with_suffix(".copy.json")
        receipt.replace(copy_path)
        try:
            receipt.symlink_to(copy_path.name)
        except OSError as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")
        with self.assertRaises(MatrixError):
            compile_evidence(
                machine,
                machine_path.parent,
                self.artifact,
                screenshot,
                dict(self.binding),
            )

    def test_unsigned_artifact_fails_closed_by_default(self) -> None:
        with self.assertRaisesRegex(
            CollectorError, "owner-signed Apple Distribution"
        ):
            Collector(
                driver=FakeAppleDriver(self.artifact),
                platform="macos",
                artifact=self.artifact,
                output_dir=self.root / "unsigned-default",
                binding=dict(self.binding),
            )

    def test_hold_exact_artifact_rejects_hardlinks_and_keeps_single_link_copy(self) -> None:
        source = self.root / "single.pkg"
        source.write_bytes(b"held-owner-bytes")
        held = self.root / "held.pkg"
        digest, size = hold_exact_artifact(source, held)
        self.assertEqual(size, len(b"held-owner-bytes"))
        self.assertEqual(digest, hashlib.sha256(b"held-owner-bytes").hexdigest())
        self.assertEqual(os.stat(held).st_nlink, 1)
        alias = self.root / "alias.pkg"
        try:
            os.link(source, alias)
        except OSError as exc:
            self.skipTest(f"hardlink creation is unavailable: {exc}")
        with self.assertRaisesRegex(CollectorError, "single-link"):
            hold_exact_artifact(alias, self.root / "held-hardlink.pkg")

    def test_held_artifact_rehash_never_returns_an_unverified_cached_digest(self) -> None:
        source = self.root / "rehash-source.pkg"
        source.write_bytes(b"descriptor-rehash-source")
        custody = hold_exact_artifact(source, self.root / "rehash-held.pkg")
        custody.digest = "0" * 64
        try:
            with self.assertRaisesRegex(CollectorError, "digest changed"):
                custody.rehash()
        finally:
            custody.close(verify=False)

    def test_substitute_after_signature_verification_is_rejected(self) -> None:
        collector, _driver = self.make("substitute-after-signature")
        held = collector.artifact
        authentic = held.with_name("authentic.pkg")
        held.rename(authentic)
        held.write_bytes(b"same-uid-unsigned-substitute")
        try:
            with self.assertRaisesRegex(
                CollectorError, "changed while retained|substituted"
            ):
                collector.collect()
        finally:
            custody = collector._held_artifact
            custody.close(verify=False)
            collector._held_artifact = None
            collector._held_directory.cleanup()
            collector._held_directory = None

    def test_collection_passes_retained_descriptor_to_install_driver(self) -> None:
        collector, driver = self.make("descriptor-install-source")
        observed: list[pathlib.Path] = []
        original = driver.call

        def recording(action: str, **values: str):
            if action == "clean_install":
                artifact = pathlib.Path(values["artifact"])
                observed.append(artifact)
                self.assertIn(artifact.parent.as_posix(), {"/dev/fd", "/proc/self/fd"})
                self.assertEqual(artifact.read_bytes(), b"exact-apple-artifact")
            return original(action, **values)

        driver.call = recording
        collector.collect()
        collector.close()
        self.assertEqual(len(observed), 1)

    def test_xcarchive_change_after_custody_is_rejected(self) -> None:
        collector, _driver = self.make_ios("xcarchive-after-custody")
        self.assertGreater(len(collector._held_ios_archive._files), 0)
        (self.xcarchive / "Info.plist").write_bytes(
            plistlib.dumps({"ArchiveVersion": 3})
        )
        try:
            with self.assertRaisesRegex(CollectorError, "xcarchive .*changed"):
                collector.collect()
        finally:
            collector._held_ios_archive.close(verify=False)
            collector._held_ios_archive = None
            for receipt in collector._held_ios_receipts:
                receipt.close(verify=False)
            collector._held_ios_receipts = []
            collector._held_artifact.close(verify=False)
            collector._held_artifact = None
            collector._held_directory.cleanup()
            collector._held_directory = None

    def test_xcarchive_write_and_restore_is_rejected_by_retained_file_custody(self) -> None:
        collector, _driver = self.make_ios("xcarchive-write-restore")
        target = self.xcarchive / "Info.plist"
        original = target.read_bytes()
        target.write_bytes(b"x" * len(original))
        target.write_bytes(original)
        try:
            with self.assertRaisesRegex(
                CollectorError, "xcarchive .*changed|file .*changed|substituted"
            ):
                collector._held_ios_archive.verify()
        finally:
            collector._held_ios_archive.close(verify=False)
            collector._held_ios_archive = None
            for receipt in collector._held_ios_receipts:
                receipt.close(verify=False)
            collector._held_ios_receipts = []
            collector._held_artifact.close(verify=False)
            collector._held_artifact = None
            collector._held_directory.cleanup()
            collector._held_directory = None

    def test_ipa_zip_traversal_and_duplicate_members_fail_closed(self) -> None:
        import plistlib
        import zipfile as zipfile_mod

        traversal = self.root / "traversal.ipa"
        with zipfile_mod.ZipFile(traversal, "w") as archive:
            archive.writestr("../Info.plist", plistlib.dumps({"CFBundleIdentifier": "x"}))
        with self.assertRaisesRegex(CollectorError, "unsafe zip path"):
            embedded_watch_identity_from_ipa(traversal)

        duplicate = self.root / "duplicate.ipa"
        with zipfile_mod.ZipFile(duplicate, "w") as archive:
            archive.writestr("Payload/Runner.app/Info.plist", b"one")
            archive.writestr("payload/runner.app/info.plist", b"two")
        with self.assertRaisesRegex(CollectorError, "duplicate or empty zip paths"):
            embedded_watch_identity_from_ipa(duplicate)


if __name__ == "__main__":
    unittest.main()
