#!/usr/bin/env python3
"""Fail-closed unit tests for the root-installed Linux release UI driver."""

from __future__ import annotations

import io
import pathlib
import sys
import tarfile
import tempfile
import types
import unittest

TOOLS = pathlib.Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from linux_release_ui_driver import (
    CANARY_EXECUTABLE,
    DriverError,
    advertised_routes,
    double_identity_fields,
    forcing_rule_records,
    installed_version,
    is_reparse_point,
    minimal_desktop_environment,
    minimal_installer_environment,
    parse_tesseract_tsv,
    reject_symlink_components,
    rollback_install_root,
    runtime_direct_port,
    response,
    safe_extract,
    ui_worker,
    validate_live_xray_route,
    validate_split_canary_metadata,
    validate_route_forcing_capability,
)


class LinuxReleaseUiDriverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_routes_are_sanitized_and_secret_free(self) -> None:
        routes = advertised_routes(
            {
                "xray": {
                    "transports": [
                        {
                            "port": 443,
                            "security": "tls",
                            "uuid": "must-not-escape",
                            "host": "private-origin.example",
                        },
                        {
                            "port": 80,
                            "security": "none",
                            "endpoint": "198.51.100.10",
                        },
                    ]
                }
            }
        )
        self.assertEqual(
            routes,
            [
                {"protocol": "tcp", "port": 80, "security": "none"},
                {"protocol": "tcp", "port": 443, "security": "tls"},
            ],
        )
        self.assertNotIn("must-not-escape", repr(routes))
        self.assertNotIn("198.51.100.10", repr(routes))

    def test_routes_reject_duplicate_or_invalid_transport(self) -> None:
        with self.assertRaises(DriverError):
            advertised_routes(
                {"xray": {"transports": [{"port": 80, "security": "none"}] * 2}}
            )
        with self.assertRaises(DriverError):
            advertised_routes(
                {"xray": {"transports": [{"port": 80, "security": "reality"}]}}
            )

    def test_forcing_rejects_same_port_security_ambiguity(self) -> None:
        routes = [
            {"protocol": "tcp", "port": 443, "security": "none"},
            {"protocol": "tcp", "port": 443, "security": "tls"},
        ]
        with self.assertRaises(DriverError):
            validate_route_forcing_capability(routes, 443, "tls")
        validate_route_forcing_capability(
            [{"protocol": "tcp", "port": 443, "security": "tls"}],
            443,
            "tls",
        )

    def test_runtime_direct_port_accepts_arbitrary_live_port_and_rejects_mismatch(self) -> None:
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

    @staticmethod
    def _xray_edge(tag: str, port: int = 80, security: str = "none") -> dict:
        return {
            "tag": tag,
            "protocol": "vless",
            "settings": {"vnext": [{"port": port}]},
            "streamSettings": {
                "security": security,
                "wsSettings": {
                    "host": "edge.example",
                    "headers": {"Host": "edge.example"},
                },
            },
        }

    def test_live_xray_route_accepts_redundant_same_route_edges(self) -> None:
        config = {
            "outbounds": [
                self._xray_edge("vless-ws-edge-0"),
                self._xray_edge("vless-ws-edge-1"),
            ]
        }
        self.assertEqual(validate_live_xray_route(config, 80, "none"), 2)

    def test_live_xray_route_rejects_mixed_or_duplicated_edges(self) -> None:
        with self.assertRaises(DriverError):
            validate_live_xray_route(
                {
                    "outbounds": [
                        self._xray_edge("edge-0"),
                        self._xray_edge("edge-1", port=443, security="tls"),
                    ]
                },
                80,
                "none",
            )
        with self.assertRaises(DriverError):
            validate_live_xray_route(
                {"outbounds": [self._xray_edge("edge-0"), self._xray_edge("edge-0")]},
                80,
                "none",
            )

    def test_forcing_rules_are_scoped_to_transport_destinations(self) -> None:
        records = forcing_rule_records(
            {
                "server_endpoint": "198.51.100.10:55210",
                "xray": {"host": "203.0.113.20", "server_name": "203.0.113.20"},
            },
            [
                {"protocol": "tcp", "port": 80, "security": "none"},
                {"protocol": "tcp", "port": 443, "security": "tls"},
            ],
            80,
            55210,
        )
        rules = [rule for _, rule in records]
        self.assertTrue(all("-d" in rule for rule in rules))
        self.assertTrue(any("198.51.100.10" in rule and "55210" in rule for rule in rules))
        self.assertTrue(any("203.0.113.20" in rule and "443" in rule for rule in rules))
        self.assertFalse(any("203.0.113.20" in rule and "80" in rule for rule in rules))

    def test_double_identity_contract_never_returns_raw_identifiers(self) -> None:
        fields = double_identity_fields(True, "north-america-core", "spain-madrid")
        self.assertEqual(
            set(fields),
            {"double_vpn_core_id_sha256", "double_vpn_exit_slug_sha256"},
        )
        self.assertNotIn("north-america-core", repr(fields))
        self.assertNotIn("spain-madrid", repr(fields))
        with self.assertRaises(DriverError):
            double_identity_fields(True, "", "spain-madrid")
        with self.assertRaises(DriverError):
            double_identity_fields(False, "unexpected", "")

    def test_response_has_machine_envelope_without_caller_pass_fields(self) -> None:
        result = response("routes", advertised_xray_routes=[])
        self.assertEqual(result["passed"], True)
        self.assertEqual(result["secret_material_redacted"], True)
        self.assertNotIn("caller_passed", result)
        self.assertNotIn("receipt", result)

    def test_desktop_and_installer_environments_do_not_forward_secrets(self) -> None:
        source = {
            "LANG": "en_US.UTF-8",
            "DISPLAY": ":99",
            "CLOUDFLARE_API_TOKEN": "must-not-escape",
            "PAYPAL_CLIENT_SECRET": "must-not-escape",
            "SSH_AUTH_SOCK": "/root/private-agent",
        }
        desktop = minimal_desktop_environment(
            source,
            user="release-user",
            uid=1001,
            home=pathlib.Path("/home/release-user"),
            display=":1",
            wayland_display="",
            xauthority="/home/release-user/.Xauthority",
        )
        installer = minimal_installer_environment(source)
        for value in (desktop, installer):
            self.assertNotIn("CLOUDFLARE_API_TOKEN", value)
            self.assertNotIn("PAYPAL_CLIENT_SECRET", value)
            self.assertNotIn("SSH_AUTH_SOCK", value)
        self.assertEqual(desktop["DISPLAY"], ":1")
        self.assertEqual(desktop["USER"], "release-user")
        self.assertEqual(installer["DEBIAN_FRONTEND"], "noninteractive")

    def test_split_canary_pid_must_be_owned_and_match_installed_canary(self) -> None:
        value = {
            "schema_version": 1,
            "socket_mark": 51820,
            "cgroup": "/winsvpn-bypass.slice/canary.scope",
            "pid": 4242,
        }
        expected_cmdline = b"bash\0" + str(CANARY_EXECUTABLE).encode() + b"\0"
        self.assertEqual(
            validate_split_canary_metadata(
                value,
                desktop_uid=1001,
                file_uid=1001,
                file_mode=0o600,
                process_uid=1001,
                process_cmdline=expected_cmdline,
                process_cgroup=value["cgroup"],
            ),
            4242,
        )
        for mutation in ("owner", "command", "cgroup"):
            with self.subTest(mutation=mutation), self.assertRaises(DriverError):
                validate_split_canary_metadata(
                    value,
                    desktop_uid=1001,
                    file_uid=1001,
                    file_mode=0o600,
                    process_uid=0 if mutation == "owner" else 1001,
                    process_cmdline=(b"sleep\0" + b"120\0" if mutation == "command" else expected_cmdline),
                    process_cgroup=("/user.slice" if mutation == "cgroup" else value["cgroup"]),
                )

    def test_split_assertion_discovers_the_actual_desktop_uid(self) -> None:
        script = pathlib.Path(__file__).with_name(
            "linux_live_split_assertions.sh"
        ).read_text(encoding="utf-8")
        self.assertNotIn("id -u winsvpn", script)
        self.assertIn("/run/user/([1-9][0-9]*)/", script)

    @staticmethod
    def _add_tar_member(
        bundle: tarfile.TarFile,
        name: str,
        content: bytes | None,
        mode: int,
    ) -> None:
        info = tarfile.TarInfo(name)
        info.uid = 0
        info.gid = 0
        info.mode = mode
        if content is None:
            info.type = tarfile.DIRTYPE
            info.size = 0
            bundle.addfile(info)
        else:
            info.size = len(content)
            bundle.addfile(info, io.BytesIO(content))

    def test_safe_extract_accepts_regular_root_owned_release_shape(self) -> None:
        archive = self.root / "safe.tar.gz"
        destination = self.root / "extract"
        destination.mkdir()
        with tarfile.open(archive, "w:gz") as bundle:
            self._add_tar_member(bundle, "share/", None, 0o755)
            self._add_tar_member(bundle, "share/data.txt", b"safe", 0o644)
            self._add_tar_member(bundle, "wins_vpn", b"binary", 0o755)
            self._add_tar_member(bundle, "install.sh", b"#!/bin/sh\n", 0o755)
        safe_extract(archive, destination)
        self.assertEqual((destination / "share/data.txt").read_bytes(), b"safe")

    def test_safe_extract_rejects_links_traversal_and_metadata(self) -> None:
        for case in ("link", "traversal", "owner", "mode"):
            with self.subTest(case=case):
                archive = self.root / f"unsafe-{case}.tar.gz"
                destination = self.root / f"extract-{case}"
                destination.mkdir()
                with tarfile.open(archive, "w:gz") as bundle:
                    info = tarfile.TarInfo(
                        {
                            "link": "link",
                            "traversal": "../escape",
                            "owner": "file.txt",
                            "mode": "file.txt",
                        }[case]
                    )
                    info.uid = 1 if case == "owner" else 0
                    info.gid = 0
                    info.mode = 0o666 if case == "mode" else 0o644
                    if case == "link":
                        info.type = tarfile.SYMTYPE
                        info.linkname = "/etc/passwd"
                        bundle.addfile(info)
                    else:
                        info.size = 1
                        bundle.addfile(info, io.BytesIO(b"x"))
                with self.assertRaises(DriverError):
                    safe_extract(archive, destination)

    def test_failed_install_restores_previous_root_or_removes_new_root(self) -> None:
        app_root = self.root / "app"
        previous = self.root / "previous"
        app_root.mkdir()
        (app_root / "identity").write_text("failed-new", encoding="utf-8")
        previous.mkdir()
        (previous / "identity").write_text("prior", encoding="utf-8")
        rollback_install_root(app_root, previous, had_previous=True)
        self.assertEqual(
            (app_root / "identity").read_text(encoding="utf-8"), "prior"
        )
        self.assertFalse(previous.exists())

        failed_only = self.root / "failed-only"
        failed_only.mkdir()
        rollback_install_root(
            failed_only, self.root / "unused", had_previous=False
        )
        self.assertFalse(failed_only.exists())

    def test_installed_version_reads_only_valid_appstream_release(self) -> None:
        root = self.root / "app"
        metadata = root / "share/metainfo/org.winsvpn.app.metainfo.xml"
        metadata.parent.mkdir(parents=True)
        metadata.write_text(
            '<component><releases><release version="1.0.14"/></releases></component>',
            encoding="utf-8",
        )
        self.assertEqual(installed_version(root), "1.0.14")
        metadata.write_text(
            '<component><releases><release version="latest"/></releases></component>',
            encoding="utf-8",
        )
        with self.assertRaises(DriverError):
            installed_version(root)

    def test_map_tsv_requires_central_machine_observed_labels(self) -> None:
        header = (
            "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\t"
            "left\ttop\twidth\theight\tconf\ttext"
        )
        rows = [
            "5\t1\t1\t1\t1\t1\t100\t120\t80\t20\t90\tAlpha",
            "5\t1\t2\t1\t1\t1\t300\t260\t70\t20\t88\tBeta",
            "5\t1\t3\t1\t1\t1\t20\t10\t100\t20\t99\tExplore map",
            "5\t1\t4\t1\t1\t1\t20\t900\t100\t20\t99\tCredits",
        ]
        self.assertEqual(
            parse_tesseract_tsv("\n".join([header, *rows]), 1000, 1000),
            ["Alpha", "Beta"],
        )
        with self.assertRaises(DriverError):
            parse_tesseract_tsv("", 1000, 1000)

    def test_root_path_validation_rejects_symlink_components(self) -> None:
        target = self.root / "target"
        target.write_bytes(b"x")
        link = self.root / "link"
        try:
            link.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")
        with self.assertRaises(DriverError):
            reject_symlink_components(link, "test path", must_exist=True)

    def test_windows_reparse_attribute_is_rejected_without_symlink_privilege(self) -> None:
        self.assertTrue(
            is_reparse_point(types.SimpleNamespace(st_file_attributes=0x400))  # type: ignore[arg-type]
        )
        self.assertFalse(
            is_reparse_point(types.SimpleNamespace(st_file_attributes=0))  # type: ignore[arg-type]
        )

    def test_accessibility_worker_rejects_invalid_identity_or_pid(self) -> None:
        with self.assertRaises(DriverError):
            ui_worker("names", 0, "", False, "", "")


if __name__ == "__main__":
    unittest.main()
