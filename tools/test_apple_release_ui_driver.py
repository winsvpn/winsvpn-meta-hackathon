#!/usr/bin/env python3
"""Non-mutating tests for the physical Apple release UI driver."""

from __future__ import annotations

import pathlib
import datetime as dt
import hashlib
import inspect
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import apple_release_ui_driver as driver

from apple_release_ui_driver import (
    AX_SCRIPT,
    DriverError,
    IOS_XCTEST_CONTRACT,
    PF_ANCHOR,
    advertised_routes,
    bundle_manifest,
    forcing_pf_rules,
    matching_macos_apps,
    macos_relocation_roots,
    app_bundle_identifier,
    safe_regular,
    sha256_text,
    runtime_direct_port,
    validate_ios_route_inventory,
)


class AppleReleaseUIDriverTests(unittest.TestCase):
    def test_routes_preserve_exact_advertised_order(self) -> None:
        self.assertEqual(
            advertised_routes({"xray": {"transports": [
                {"port": 80, "security": "none"},
                {"port": 443, "security": "tls"},
            ]}}),
            [
                {"protocol": "tcp", "port": 80, "security": "none"},
                {"protocol": "tcp", "port": 443, "security": "tls"},
            ],
        )

    def test_routes_reject_duplicate_or_unapproved_security(self) -> None:
        for routes in (
            [{"port": 80, "security": "none"}] * 2,
            [{"port": 443, "security": "reality"}],
        ):
            with self.assertRaises(DriverError):
                advertised_routes({"xray": {"transports": routes}})

    def test_ax_driver_uses_semantic_labels_and_axpress(self) -> None:
        self.assertIn("description of e", AX_SCRIPT)
        self.assertIn('perform action "AXPress"', AX_SCRIPT)
        self.assertNotIn("mouse location", AX_SCRIPT.lower())

    @staticmethod
    def ios_inventory() -> dict:
        empty = sha256_text("")
        return {
            "schema_version": 1,
            "contract": "winsvpn-android-route-inventory-v1",
            "captured_at_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "node": {
                "direct": {"protocol": "udp", "port": 9110, "ssh_alias": "spain"},
                "advertised_xray_routes": [
                    {"protocol": "tcp", "port": 80, "security": "none", "ssh_alias": "spain"},
                    {"protocol": "tcp", "port": 443, "security": "tls", "ssh_alias": "spain"},
                ],
                "core_id_sha256": empty,
                "exit_slug_sha256": empty,
            },
            "double_vpn": {
                "direct": {"protocol": "udp", "port": 55210, "ssh_alias": "core"},
                "advertised_xray_routes": [
                    {"protocol": "tcp", "port": 8080, "security": "none", "ssh_alias": "core"},
                    {"protocol": "tcp", "port": 8443, "security": "tls", "ssh_alias": "core"},
                ],
                "core_id_sha256": sha256_text("core"),
                "exit_slug_sha256": sha256_text("exit"),
            },
            "secret_material_redacted": True,
        }

    def test_ios_inventory_accepts_dynamic_xray_routes_and_mode_direct_ports(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = pathlib.Path(name) / "inventory.json"
            path.write_text(json.dumps(self.ios_inventory()), encoding="utf-8")
            value, digest = validate_ios_route_inventory(path)
            self.assertEqual(value["node"]["direct"]["port"], 9110)
            self.assertEqual(value["double_vpn"]["direct"]["port"], 55210)
            self.assertEqual(len(digest), 64)

    def test_ios_inventory_rejects_unsafe_alias_duplicate_port_and_stale_time(self) -> None:
        variants = []
        unsafe = self.ios_inventory(); unsafe["node"]["direct"]["ssh_alias"] = "bad alias"; variants.append(unsafe)
        duplicate = self.ios_inventory(); duplicate["node"]["advertised_xray_routes"][1]["port"] = 80; variants.append(duplicate)
        stale = self.ios_inventory(); stale["captured_at_utc"] = "2020-01-01T00:00:00Z"; variants.append(stale)
        with tempfile.TemporaryDirectory() as name:
            for index, value in enumerate(variants):
                path = pathlib.Path(name) / f"inventory-{index}.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaises(DriverError):
                    validate_ios_route_inventory(path)

    def test_xctestrun_rewrite_and_nested_environment_target_only_ui_bundle(self) -> None:
        raw = {"TestConfigurations": [{"TestTargets": [
            {"IsUITestBundle": True, "UITargetAppPath": "/old/Runner.app", "TestHostPath": "/old/UITests.xctest"},
            {"IsUITestBundle": False, "TestHostPath": "/old/UnitTests.xctest"},
        ]}]}
        rewritten = driver._rewrite_xctestrun(raw, "/old", "/new", "/exact/Runner.app")
        self.assertEqual(rewritten["TestConfigurations"][0]["TestTargets"][0]["UITargetAppPath"], "/exact/Runner.app")
        self.assertEqual(rewritten["TestConfigurations"][0]["TestTargets"][1]["TestHostPath"], "/new/UnitTests.xctest")
        self.assertEqual(driver._inject_xctest_environment(rewritten, {"WINS_IOS_RELEASE_ACTION": "lane"}), 1)
        self.assertNotIn("EnvironmentVariables", rewritten["TestConfigurations"][0]["TestTargets"][1])

    def test_ios_lane_binds_xray_forcing_provider_and_dynamic_route(self) -> None:
        inventory = self.ios_inventory()
        binding = {"artifact_sha256": "a" * 64, "installed_record_sha256": "b" * 64, "provider_executable_sha256": "c" * 64}
        base = {"schema_version": 1, "contract": IOS_XCTEST_CONTRACT, "secret_material_redacted": True}
        lane_observation = {
            **base, "action": "lane", "double_vpn_active": False,
            "transport_mode": "xray_vless_ws_amneziawg", "rx_delta_bytes": 2048,
            "tx_delta_bytes": 1024, "protected_egress_sha256": "d" * 64,
            "provider_healthy": True, "dns_count": 2,
            "dns_full_tunnel_match_enabled": True, "ipv6_leak_protection_enabled": True,
        }
        route_results = [
            {"passed": True, "secret_material_redacted": True, "before_state_sha256": "e" * 64, "watchdog_armed": True},
            {"passed": True, "secret_material_redacted": True, "selected_port": 80, "selected_security": "none", "selected_bytes": 4096, "direct_block_packets": 1},
            {"passed": True, "secret_material_redacted": True, "before_state_sha256": "e" * 64, "after_state_sha256": "e" * 64},
        ]
        with (
            mock.patch.object(driver, "ios_runtime_binding", return_value=(binding, inventory)),
            mock.patch.object(driver, "run_ios_xctest", side_effect=[({**base, "action": "physical_egress", "source_public_ipv4": "8.8.8.8"}, None), (lane_observation, None)]),
            mock.patch.object(driver, "ios_route_call", side_effect=route_results) as route_call,
        ):
            result = driver.ios_lane("node-xray-80", "xray", 80, "none", 9110)
        self.assertEqual(result["port"], 80)
        self.assertEqual(result["forcing_blocked_udp_port"], 9110)
        self.assertEqual(result["provider_executable_sha256"], "c" * 64)
        self.assertEqual(route_call.call_count, 3)

    def test_ios_lane_restores_remote_guard_when_xctest_fails(self) -> None:
        inventory = self.ios_inventory()
        binding = {"artifact_sha256": "a" * 64, "installed_record_sha256": "b" * 64, "provider_executable_sha256": "c" * 64}
        physical = {"schema_version": 1, "contract": IOS_XCTEST_CONTRACT, "secret_material_redacted": True, "action": "physical_egress", "source_public_ipv4": "8.8.8.8"}
        with (
            mock.patch.object(driver, "ios_runtime_binding", return_value=(binding, inventory)),
            mock.patch.object(driver, "run_ios_xctest", side_effect=[(physical, None), DriverError("test failure")]),
            mock.patch.object(driver, "ios_route_call", side_effect=[
                {"passed": True, "secret_material_redacted": True, "before_state_sha256": "e" * 64, "watchdog_armed": True},
                {"passed": True, "secret_material_redacted": True, "before_state_sha256": "e" * 64, "after_state_sha256": "e" * 64},
            ]) as route_call,
        ):
            with self.assertRaises(DriverError):
                driver.ios_lane("node-xray-443", "xray", 443, "tls", 9110)
        self.assertEqual(route_call.call_args_list[-1].args[0], "restore")

    def test_ios_source_has_no_blanket_limitation_and_all_release_actions(self) -> None:
        source = pathlib.Path(driver.__file__).read_text(encoding="utf-8")
        swift = (pathlib.Path(driver.__file__).resolve().parent.parent / "ios/RunnerUITests/VpnPermissionUITests.swift").read_text(encoding="utf-8")
        self.assertNotIn("IOS_UI_LIMITATION", source)
        self.assertIn("winsvpn-apple-route-controller.py", source)
        for action in ("physical_egress", "lane", "split", "leak", "network_change", "teardown", "rollback", "capture_map"):
            self.assertIn(f'case "{action}"', swift)

    def test_pf_forcing_uses_an_anchor_invoked_by_stock_macos_root_rules(self) -> None:
        self.assertTrue(PF_ANCHOR.startswith("com.apple/"))

    def test_runtime_direct_port_is_live_and_must_match_xray_remote_port(self) -> None:
        self.assertEqual(
            runtime_direct_port(
                {"server_endpoint": "198.51.100.1:55210", "xray": {"remote_awg_port": 55210}}
            ),
            55210,
        )
        with self.assertRaises(DriverError):
            runtime_direct_port(
                {"server_endpoint": "198.51.100.1:55210", "xray": {"remote_awg_port": 9110}}
            )

    def test_forcing_rules_are_scoped_to_transport_destinations(self) -> None:
        config = {
            "server_endpoint": "198.51.100.10:55210",
            "xray": {"host": "203.0.113.20", "server_name": "203.0.113.20"},
        }
        rules = forcing_pf_rules(
            config,
            [
                {"protocol": "tcp", "port": 80, "security": "none"},
                {"protocol": "tcp", "port": 443, "security": "tls"},
            ],
            80,
            55210,
        )
        self.assertTrue(all(" to any " not in rule for rule in rules))
        self.assertTrue(any("to 198.51.100.10 port = 55210" in rule for rule in rules))
        self.assertTrue(any("to 203.0.113.20 port = 443" in rule for rule in rules))
        self.assertFalse(any("to 203.0.113.20 port = 80" in rule for rule in rules))

    def test_bundle_manifest_changes_with_payload_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            payload = root / "Contents/MacOS/WinsVPN"
            payload.parent.mkdir(parents=True)
            payload.write_bytes(b"one")
            before = bundle_manifest(root)
            payload.write_bytes(b"two")
            self.assertNotEqual(before, bundle_manifest(root))

    def test_safe_regular_rejects_symlink_when_available(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            target = root / "target"
            target.write_bytes(b"x")
            link = root / "link"
            try:
                link.symlink_to(target.name)
            except OSError as exc:
                self.skipTest(f"symlink unavailable: {exc}")
            with self.assertRaises(DriverError):
                safe_regular(link, "test")

    def test_safe_regular_rejects_nested_caller_controlled_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            real = root / "real"
            real.mkdir()
            target = real / "target"
            target.write_bytes(b"x")
            link = root / "linked-directory"
            try:
                link.symlink_to(real.name, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlink unavailable: {exc}")
            with self.assertRaises(DriverError):
                safe_regular(link / target.name, "test")

    def test_clean_install_requires_inherited_artifact_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            artifact = pathlib.Path(name) / "candidate.pkg"
            artifact.write_bytes(b"not-a-package")
            with self.assertRaisesRegex(DriverError, "inherited retained"):
                driver.clean_install("macos", artifact)

    def test_descriptor_command_reads_held_inode_after_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            container = pathlib.Path(name)
            root = container / "candidate-parent"
            root.mkdir()
            artifact = root / "candidate.pkg"
            artifact.write_bytes(b"authentic")
            descriptor = os.open(artifact, os.O_RDONLY)
            try:
                retained_parent = container / "retained-parent"
                os.replace(root, retained_parent)
                root.mkdir()
                artifact.write_bytes(b"substitute")
                result = driver.run(
                    ["/bin/cat", f"/dev/fd/{descriptor}"]
                )
            finally:
                os.close(descriptor)
            self.assertEqual(result.stdout, "authentic")
            self.assertEqual(artifact.read_bytes(), b"substitute")

    def test_descriptor_command_rejects_hardlinked_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            artifact = root / "candidate.pkg"
            artifact.write_bytes(b"authentic")
            os.link(artifact, root / "second-link")
            descriptor = os.open(artifact, os.O_RDONLY)
            try:
                with self.assertRaisesRegex(DriverError, "descriptor is unsafe"):
                    driver.run(["/bin/cat", f"/dev/fd/{descriptor}"])
            finally:
                os.close(descriptor)

    def test_machine_command_scrubs_ambient_environment(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"DYLD_INSERT_LIBRARIES": "/tmp/hostile", "PYTHONPATH": "/tmp/hostile"},
            clear=False,
        ):
            result = driver.run(["/usr/bin/env"])
        self.assertNotIn("DYLD_INSERT_LIBRARIES", result.stdout)
        self.assertNotIn("PYTHONPATH", result.stdout)
        self.assertIn("HOME=/var/empty", result.stdout)

    def test_machine_command_bounds_output_and_timeout(self) -> None:
        with mock.patch.object(driver, "PROCESS_OUTPUT_LIMIT_BYTES", 1024):
            with self.assertRaisesRegex(DriverError, "stdout exceeded"):
                driver.run(
                    [sys.executable, "-I", "-S", "-c", "import sys;sys.stdout.write('x'*2048)"],
                    timeout=5,
                )
        with self.assertRaisesRegex(DriverError, "time bound"):
            driver.run(
                [sys.executable, "-I", "-S", "-c", "import time;time.sleep(10)"],
                timeout=1,
            )

    def test_machine_command_no_fork_boundary_blocks_setsid_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            marker = pathlib.Path(name) / "escaped"
            script = (
                "import os,sys,time\n"
                "try: pid=os.fork()\n"
                "except OSError:\n"
                " print('fork-blocked');sys.exit(0)\n"
                "if pid==0:\n"
                " os.setsid();os.close(1);os.close(2);time.sleep(1);open(sys.argv[1],'w').write('escaped');os._exit(0)\n"
                "print('leader-ok')\n"
            )
            result = driver.run(
                [sys.executable, "-I", "-S", "-c", script, str(marker)],
                timeout=5,
            )
            self.assertEqual(result.stdout.strip(), "fork-blocked")
            time.sleep(1.2)
            self.assertFalse(marker.exists())

    def test_machine_command_stdin_uses_the_absolute_deadline(self) -> None:
        started = time.monotonic()
        with self.assertRaisesRegex(DriverError, "time bound"):
            driver.run(
                [sys.executable, "-I", "-S", "-c", "import time;time.sleep(10)"],
                input_text="x" * driver.PROCESS_OUTPUT_LIMIT_BYTES,
                timeout=1,
            )
        self.assertLess(time.monotonic() - started, 2.5)

    def test_console_execution_is_owner_blocked_without_whole_job_supervisor(self) -> None:
        with self.assertRaisesRegex(DriverError, "OWNER-BLOCKED.*whole-job supervisor"):
            driver.as_console(["/usr/bin/true"])

    def test_console_build_root_has_private_parent_and_exact_owner_mode(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as name:
            outer = pathlib.Path(name)
            private_parent = outer / "private-parent"
            private_parent.mkdir(mode=0o700)
            build_root = driver._create_console_build_root(
                private_parent,
                os.geteuid(),
            )
            self.assertEqual(stat.S_IMODE(private_parent.lstat().st_mode), 0o711)
            self.assertEqual(private_parent.lstat().st_uid, os.geteuid())
            self.assertEqual(stat.S_IMODE(build_root.lstat().st_mode), 0o700)
            self.assertEqual(build_root.lstat().st_uid, os.geteuid())

    def test_console_build_root_rejects_broad_or_wrong_parent_authority(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as name:
            private_parent = pathlib.Path(name) / "private-parent"
            private_parent.mkdir(mode=0o755)
            with self.assertRaisesRegex(DriverError, "parent identity is unsafe"):
                driver._create_console_build_root(private_parent, os.geteuid())

    def test_xctest_tree_copy_rejects_symlink_hardlink_and_source_mutation(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as name:
            root = pathlib.Path(name)
            source = root / "source"
            source.mkdir()
            destinations = root / "destinations"
            destinations.mkdir()
            secret = root / "root-readable-secret"
            secret.write_bytes(b"must-not-copy")
            link = source / "leak"
            link.symlink_to(secret)
            with self.assertRaisesRegex(DriverError, "symlinks"):
                driver._copy_tree_no_follow(
                    source,
                    destinations / "symlink-copy",
                    expected_uid=os.geteuid(),
                    label="hostile Xcode Products",
                )
            copied = destinations / "symlink-copy"
            self.assertFalse(
                any(
                    path.is_file() and path.read_bytes() == b"must-not-copy"
                    for path in copied.rglob("*")
                )
            )

            link.unlink()
            payload = source / "payload"
            payload.write_bytes(b"authentic")
            os.link(payload, source / "payload-second-link")
            with self.assertRaisesRegex(DriverError, "identity is unsafe"):
                driver._copy_tree_no_follow(
                    source,
                    destinations / "hardlink-copy",
                    expected_uid=os.geteuid(),
                    label="hostile Xcode Products",
                )

            (source / "payload-second-link").unlink()
            original_pread = os.pread
            changed = False

            def mutate_after_read(descriptor: int, size: int, offset: int) -> bytes:
                nonlocal changed
                block = original_pread(descriptor, size, offset)
                if block and not changed:
                    changed = True
                    payload.write_bytes(b"substitute")
                return block

            with mock.patch.object(driver.os, "pread", side_effect=mutate_after_read):
                with self.assertRaisesRegex(
                    DriverError, "grew during retained copy|changed during retained copy|ancestry changed"
                ):
                    driver._copy_tree_no_follow(
                        source,
                        destinations / "mutation-copy",
                        expected_uid=os.geteuid(),
                        label="hostile Xcode Products",
                    )
            self.assertFalse((destinations / "mutation-copy").exists())

            special_source = root / "special-source"
            special_source.mkdir()
            os.mkfifo(special_source / "fifo")
            with self.assertRaisesRegex(DriverError, "special file"):
                driver._copy_tree_no_follow(
                    special_source,
                    destinations / "special-copy",
                    expected_uid=os.geteuid(),
                    label="hostile Xcode Products",
                )

    def test_xctest_tree_copy_binds_exact_regular_bytes(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as name:
            root = pathlib.Path(name)
            source = root / "source"
            destination_parent = root / "destination"
            source.mkdir()
            destination_parent.mkdir()
            nested = source / "RunnerUITests.xctest"
            nested.mkdir()
            executable = nested / "RunnerUITests"
            executable.write_bytes(b"compiled-ui-test")
            executable.chmod(0o500)
            copied = destination_parent / "Products"
            driver._copy_tree_no_follow(
                source,
                copied,
                expected_uid=os.geteuid(),
                label="honest Xcode Products",
            )
            driver._harden_tree(copied)
            digest, entries, byte_count = driver._tree_binding(
                copied,
                expected_uid=os.geteuid(),
                label="bound Xcode Products",
            )
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertEqual(entries, 3)
            self.assertEqual(byte_count, len(b"compiled-ui-test"))
            self.assertEqual(driver._exact_ui_test_executable(copied).read_bytes(), b"compiled-ui-test")
            driver._relax_sealed_tree_for_cleanup(copied)

    def test_xctest_tree_copy_rejects_transient_parent_swap(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as name:
            root = pathlib.Path(name)
            source = root / "source"
            source.mkdir()
            destinations = root / "destinations"
            destinations.mkdir()
            (source / "payload").write_bytes(b"authentic")
            retained = root / "retained"
            original_pread = os.pread
            swapped = False

            def swap_parent(descriptor: int, size: int, offset: int) -> bytes:
                nonlocal swapped
                block = original_pread(descriptor, size, offset)
                if block and not swapped:
                    swapped = True
                    os.replace(source, retained)
                    source.mkdir()
                    (source / "payload").write_bytes(b"substitute")
                return block

            with mock.patch.object(driver.os, "pread", side_effect=swap_parent):
                with self.assertRaisesRegex(
                    DriverError, "ancestry changed|directory changed during retained copy"
                ):
                    driver._copy_tree_no_follow(
                        source,
                        destinations / "parent-swap-copy",
                        expected_uid=os.geteuid(),
                        label="hostile Xcode Products",
                    )
            self.assertFalse((destinations / "parent-swap-copy").exists())

    def test_runtime_schema_binds_products_executable_and_source_snapshot(self) -> None:
        required = {
            "products_tree_sha256",
            "products_tree_entries",
            "products_tree_bytes",
            "ui_test_executable_relative_path",
            "ui_test_executable_sha256",
            "ui_test_executable_bytes",
            "source_snapshot_sha256",
            "source_snapshot_entries",
            "source_snapshot_bytes",
        }
        self.assertTrue(required.issubset(driver.IOS_BINDING_FIELDS))
        source = inspect.getsource(driver.prepare_ios_xctest_runtime)
        self.assertNotIn("shutil.copytree", source)
        self.assertIn("_copy_source_inputs", source)
        self.assertGreaterEqual(source.count("_copy_tree_no_follow"), 2)
        self.assertGreaterEqual(source.count("_tree_binding"), 3)
        self.assertIn('"winsvpn-ios-xctest-runtime-v2"', source)

    def test_clean_install_forwards_exact_pkg_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            artifact = root / "candidate.pkg"
            artifact.write_bytes(b"authenticated-pkg")
            descriptor = os.open(artifact, os.O_RDONLY)
            descriptor_path = pathlib.Path(f"/dev/fd/{descriptor}")
            session = subprocess.CompletedProcess([], 0, "installed", "")
            try:
                with (
                    mock.patch.object(driver, "run", return_value=session) as machine_run,
                    mock.patch.object(driver, "find_one_app", return_value=root / "Payload.app"),
                    mock.patch.object(driver, "install_macos_package_exact", return_value=(session, "manifest")) as installer,
                    mock.patch.object(driver, "plist_identity", return_value=("1.0.15", "30")),
                    mock.patch.object(driver, "codesign_identity", return_value=("ABCDEFGHIJ", "r" * 64)),
                ):
                    result = driver.clean_install("macos", descriptor_path)
            finally:
                os.close(descriptor)
            self.assertEqual(
                result["source_artifact_sha256"],
                hashlib.sha256(b"authenticated-pkg").hexdigest(),
            )
            self.assertEqual(machine_run.call_args.args[0][2], str(descriptor_path))
            self.assertEqual(installer.call_args.args[0], descriptor_path)

    def test_installer_receives_same_retained_pkg_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            artifact = root / "candidate.pkg"
            artifact.write_bytes(b"authenticated-pkg")
            descriptor = os.open(artifact, os.O_RDONLY)
            descriptor_path = pathlib.Path(f"/dev/fd/{descriptor}")
            installed = root / "Installed.app"
            installed.mkdir()
            work = root / "work"
            work.mkdir()
            session = subprocess.CompletedProcess([], 0, "installed", "")
            try:
                with (
                    mock.patch.object(driver, "MACOS_INSTALL_PATH", installed),
                    mock.patch.object(driver, "macos_relocation_candidates", return_value=[]),
                    mock.patch.object(driver, "receipt_files", return_value=[]),
                    mock.patch.object(driver, "bundle_manifest", return_value="manifest"),
                    mock.patch.object(driver, "persist_macos_install_rollback"),
                    mock.patch.object(driver, "register_app"),
                    mock.patch.object(driver, "run", return_value=session) as machine_run,
                ):
                    result, manifest = driver.install_macos_package_exact(
                        descriptor_path, installed, work
                    )
            finally:
                os.close(descriptor)
            self.assertIs(result, session)
            self.assertEqual(manifest, "manifest")
            installer_calls = [
                call.args[0]
                for call in machine_run.call_args_list
                if call.args and call.args[0][0] == "/usr/sbin/installer"
            ]
            self.assertEqual(
                installer_calls,
                [["/usr/sbin/installer", "-pkg", str(descriptor_path), "-target", "/"]],
            )

    def test_matching_macos_apps_only_returns_exact_host_identifier(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            expected = root / "DerivedData/Runner/Build/Products/Debug/Win's VPN.app"
            wrong = root / "Other.app"
            for app, identifier in (
                (expected, "org.winsvpn.app"),
                (wrong, "org.example.other"),
            ):
                contents = app / "Contents"
                contents.mkdir(parents=True)
                import plistlib
                with (contents / "Info.plist").open("wb") as handle:
                    plistlib.dump({"CFBundleIdentifier": identifier}, handle)
            self.assertEqual(app_bundle_identifier(expected), "org.winsvpn.app")
            self.assertEqual(matching_macos_apps([root]), [expected.resolve()])

    def test_matching_macos_apps_ignores_symlinked_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            app = root / "Real.app"
            contents = app / "Contents"
            contents.mkdir(parents=True)
            import plistlib
            with (contents / "Info.plist").open("wb") as handle:
                plistlib.dump({"CFBundleIdentifier": "org.winsvpn.app"}, handle)
            link = root / "Linked.app"
            try:
                link.symlink_to(app, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlink unavailable: {exc}")
            self.assertEqual(matching_macos_apps([root]), [app.resolve()])

    def test_relocation_roots_include_real_user_hidden_candidate_tree(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            users = pathlib.Path(name)
            home = users / "release-user"
            home.mkdir()
            # CI may run this test as root (notably through WSL), so inject the
            # test fixture's UID threshold without weakening the production
            # default that excludes macOS system accounts below UID 500.
            roots = macos_relocation_roots(users, minimum_user_uid=0)
            self.assertIn(home.resolve() / ".winsvpn-release-candidates", roots)
            self.assertNotIn(home.resolve(), roots)

    def test_successful_install_rollback_snapshot_outlives_temporary_quarantine(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            state = root / "state"
            state.mkdir()
            quarantine = root / "temporary-quarantine"
            app_backup = quarantine / "prior-app"
            (app_backup / "Contents").mkdir(parents=True)
            (app_backup / "Contents/payload").write_bytes(b"prior")
            receipt_backup = quarantine / "prior-receipt"
            receipt_backup.write_bytes(b"receipt")
            rollback = state / "macos-install-rollback"
            with (
                mock.patch.object(driver, "STATE_ROOT", state),
                mock.patch.object(driver, "MACOS_INSTALL_ROLLBACK_ROOT", rollback),
                mock.patch.object(driver.os, "chown", create=True),
            ):
                driver.persist_macos_install_rollback(
                    [(driver.MACOS_INSTALL_PATH, app_backup, True)],
                    [(pathlib.Path("/var/db/receipts/org.winsvpn.app.bom"), receipt_backup)],
                )
            import shutil
            shutil.rmtree(quarantine)
            self.assertEqual((rollback / "prior-app/Contents/payload").read_bytes(), b"prior")
            self.assertEqual((rollback / "receipts/org.winsvpn.app.bom").read_bytes(), b"receipt")


if __name__ == "__main__":
    unittest.main()
