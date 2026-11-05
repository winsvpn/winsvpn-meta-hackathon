#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


subject = load_module("gcp_proof_live_probe_absence_subject", TOOLS / "gcp_proof_live_probe.py")
fleet = subject.fleet


def probe_function() -> Any:
    namespace: dict[str, Any] = {}
    source = (
        "import os, stat, subprocess\n"
        "FORBIDDEN_COMPONENT_PROFILES = "
        + json.dumps(
            subject.FORBIDDEN_COMPONENT_PROFILES,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
        + subject._forbidden_component_library_source()
    )
    exec(compile(source, "<forbidden-component-library>", "exec"), namespace)
    return namespace["probe_forbidden_component_absence"]


class FakeSyscallRunner:
    def __init__(self) -> None:
        self.path_states: dict[str, Any] = {}
        self.interface_states: dict[str, Any] = {}
        self.unit_states: dict[str, Any] = {}
        self.ports: dict[str, Any] = {"tcp": [], "udp": []}
        self.docker_states: dict[tuple[str, str], Any] = {}
        self.calls: list[tuple[Any, ...]] = []

    def path_state(self, path: str) -> Any:
        self.calls.append(("path", path))
        return self.path_states.get(path, "not-found")

    def interface_state(self, name: str) -> Any:
        self.calls.append(("interface", name))
        return self.interface_states.get(name, "not-found")

    def unit_load_state(self, unit: str) -> Any:
        self.calls.append(("unit", unit))
        return self.unit_states.get(unit, "not-found")

    def listening_ports(self, protocol: str) -> Any:
        self.calls.append(("listeners", protocol))
        return copy.deepcopy(self.ports[protocol])

    def docker_object_state(self, kind: str, name: str) -> Any:
        self.calls.append(("docker", kind, name))
        return self.docker_states.get((kind, name), ("not-found", "engine-not-found"))


class ForbiddenComponentAbsenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.probe = probe_function()

    def test_every_role_emits_closed_validated_absence_evidence(self) -> None:
        for role in ("control", "data-winn3", "data-cover"):
            with self.subTest(role=role):
                runner = FakeSyscallRunner()
                evidence = self.probe(role, runner)
                validated = subject.validate_forbidden_component_absence(role, evidence)
                self.assertEqual(validated, evidence)
                self.assertEqual(
                    set(evidence),
                    {"checks", "contract", "role", "schema_version"},
                )
                self.assertEqual(
                    len(evidence["checks"]),
                    len(subject.FORBIDDEN_COMPONENT_PROFILES[role]),
                )
                encoded = json.dumps(evidence, sort_keys=True)
                self.assertNotIn(": true", encoded)
                self.assertNotIn(": false", encoded)
        control_subjects = {
            item.get("subject")
            for item in subject.FORBIDDEN_COMPONENT_PROFILES["control"]
        }
        cover_subjects = {
            item.get("subject")
            for item in subject.FORBIDDEN_COMPONENT_PROFILES["data-cover"]
        }
        self.assertNotIn("/etc/winn/winn3-gateway.env", control_subjects)
        self.assertIn("/etc/winn/winn3-gateway.env", cover_subjects)

    def test_data_winn3_rejects_xray_path_and_loaded_inactive_unit(self) -> None:
        for path in (
            "/usr/local/bin/xray",
            "/usr/local/etc/xray/config.json",
            "/etc/systemd/system/xray.service.d/20-winsvpn-user.conf",
        ):
            with self.subTest(path=path):
                runner = FakeSyscallRunner()
                runner.path_states[path] = "present"
                with self.assertRaisesRegex(SystemExit, "forbidden path"):
                    self.probe("data-winn3", runner)

        runner = FakeSyscallRunner()
        # An inactive service with a loaded unit is still installed and forbidden.
        runner.unit_states["xray.service"] = "loaded"
        with self.assertRaisesRegex(SystemExit, "LoadState"):
            self.probe("data-winn3", runner)

    def test_data_winn3_rejects_awg_residue_interface_and_docker_objects(self) -> None:
        for path in (
            "/var/lib/winsvpn/awg-server-image/provenance.json",
            "/etc/amnezia/amneziawg/awg0.conf",
        ):
            with self.subTest(path=path):
                runner = FakeSyscallRunner()
                runner.path_states[path] = "present"
                with self.assertRaisesRegex(SystemExit, "forbidden path"):
                    self.probe("data-winn3", runner)

        runner = FakeSyscallRunner()
        runner.interface_states["awg0"] = "present"
        with self.assertRaisesRegex(SystemExit, "network interface"):
            self.probe("data-winn3", runner)

        runner = FakeSyscallRunner()
        runner.docker_states[("image", "amneziavpn/amneziawg-go:v3.1.20260828")] = (
            "present",
            "inspect-present",
        )
        with self.assertRaisesRegex(SystemExit, "Docker object"):
            self.probe("data-winn3", runner)

        runner = FakeSyscallRunner()
        runner.docker_states[("container", "amnezia-awg2")] = (
            "present",
            "inspect-present",
        )
        with self.assertRaisesRegex(SystemExit, "Docker object"):
            self.probe("data-winn3", runner)

    def test_data_winn3_rejects_exact_and_dynamic_v1_listener_ports(self) -> None:
        for protocol, port in (
            ("tcp", 80),
            ("tcp", 443),
            ("tcp", 10085),
            ("udp", 9110),
            ("udp", 20000),
            ("udp", 27191),
            ("udp", 32767),
        ):
            with self.subTest(protocol=protocol, port=port):
                runner = FakeSyscallRunner()
                runner.ports[protocol] = [port]
                with self.assertRaisesRegex(SystemExit, "listener"):
                    self.probe("data-winn3", runner)

    def test_data_cover_rejects_every_winn3_stack_category(self) -> None:
        cases = (
            ("path", "/usr/local/libexec/winn/winn3-gateway"),
            ("path", "/etc/winn/winn3-gateway.env"),
            ("unit", "winn3-gateway.service"),
            ("unit", "winn3-gateway-firewall.service"),
            ("interface", "winn3gw0"),
            ("tcp", 9111),
            ("udp", 9111),
        )
        for kind, value in cases:
            with self.subTest(kind=kind, value=value):
                runner = FakeSyscallRunner()
                if kind == "path":
                    runner.path_states[str(value)] = "present"
                elif kind == "unit":
                    runner.unit_states[str(value)] = "inactive"
                elif kind == "interface":
                    runner.interface_states[str(value)] = "present-or-unsafe"
                else:
                    runner.ports[kind] = [value]
                with self.assertRaises(SystemExit):
                    self.probe("data-cover", runner)

    def test_control_combines_both_data_plane_forbidden_profiles(self) -> None:
        runner = FakeSyscallRunner()
        runner.path_states["/usr/local/bin/xray"] = "present"
        with self.assertRaisesRegex(SystemExit, "forbidden path"):
            self.probe("control", runner)

        runner = FakeSyscallRunner()
        runner.path_states["/usr/local/libexec/winn/winn3-gateway"] = "present"
        with self.assertRaisesRegex(SystemExit, "forbidden path"):
            self.probe("control", runner)

        runner = FakeSyscallRunner()
        runner.ports["udp"] = [9111]
        with self.assertRaisesRegex(SystemExit, "listener"):
            self.probe("control", runner)

    def test_malformed_runner_results_cannot_be_treated_as_absence(self) -> None:
        runner = FakeSyscallRunner()
        runner.path_states["/usr/local/bin/xray"] = True
        with self.assertRaisesRegex(SystemExit, "absence is unproven"):
            self.probe("data-winn3", runner)

        runner = FakeSyscallRunner()
        runner.docker_states[("image", "amneziavpn/amneziawg-go:v3.1.20260828")] = (
            "not-found",
            "inspect-not-found",
        )
        with self.assertRaisesRegex(SystemExit, "absence is unproven"):
            self.probe("data-winn3", runner)

        runner = FakeSyscallRunner()
        runner.ports["udp"] = [9110, 9110]
        with self.assertRaisesRegex(SystemExit, "inventory is malformed"):
            self.probe("data-winn3", runner)

        runner = FakeSyscallRunner()
        runner.docker_states[("image", "amneziavpn/amneziawg-go:v3.1.20260828")] = (
            "not-found",
            True,
        )
        with self.assertRaisesRegex(SystemExit, "absence is unproven"):
            self.probe("data-winn3", runner)

    def test_validator_rejects_missing_extra_mixed_and_boolean_fields(self) -> None:
        evidence = self.probe("data-cover", FakeSyscallRunner())
        mutations = []

        missing = copy.deepcopy(evidence)
        missing.pop("checks")
        mutations.append(missing)

        extra = copy.deepcopy(evidence)
        extra["ok"] = True
        mutations.append(extra)

        mixed = copy.deepcopy(evidence)
        mixed["role"] = "data-winn3"
        mutations.append(mixed)

        boolean_schema = copy.deepcopy(evidence)
        boolean_schema["schema_version"] = True
        mutations.append(boolean_schema)

        boolean_state = copy.deepcopy(evidence)
        boolean_state["checks"][0]["entry_state"] = True
        mutations.append(boolean_state)

        inactive_unit = copy.deepcopy(evidence)
        unit = next(
            item
            for item in inactive_unit["checks"]
            if item["kind"] == "systemd-unit"
        )
        unit["load_state"] = "inactive"
        mutations.append(inactive_unit)

        swapped = copy.deepcopy(evidence)
        swapped["checks"][0], swapped["checks"][1] = (
            swapped["checks"][1],
            swapped["checks"][0],
        )
        mutations.append(swapped)

        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaises(fleet.FleetRefused):
                    subject.validate_forbidden_component_absence(
                        "data-cover", mutation
                    )

    def test_host_requires_remote_absence_evidence_then_restores_frozen_row(self) -> None:
        legacy_row = {"role": "data-cover", "instance": "proof-cover-a1"}
        evidence = self.probe("data-cover", FakeSyscallRunner())
        remote_row = {
            **legacy_row,
            "forbidden_component_absence": evidence,
        }
        self.assertEqual(
            subject.strip_validated_forbidden_component_absence(
                "data-cover", remote_row
            ),
            legacy_row,
        )
        with self.assertRaisesRegex(fleet.FleetRefused, "extra or missing"):
            subject.strip_validated_forbidden_component_absence(
                "data-cover", legacy_row
            )
        poisoned = copy.deepcopy(remote_row)
        poisoned["forbidden_component_absence"]["checks"][0][
            "entry_state"
        ] = True
        with self.assertRaises(fleet.FleetRefused):
            subject.strip_validated_forbidden_component_absence(
                "data-cover", poisoned
            )

    def test_validator_rejects_a_positive_observation_for_every_profile_entry(self) -> None:
        for role in ("control", "data-winn3", "data-cover"):
            evidence = self.probe(role, FakeSyscallRunner())
            for index, check in enumerate(evidence["checks"]):
                with self.subTest(role=role, index=index, kind=check["kind"]):
                    mutation = copy.deepcopy(evidence)
                    item = mutation["checks"][index]
                    if item["kind"] in {"path", "interface"}:
                        item["entry_state"] = "present"
                    elif item["kind"] == "systemd-unit":
                        item["load_state"] = "loaded"
                    elif item["kind"] == "listener-set":
                        item["matching_ports"] = [
                            item["ports"][0]
                            if item["ports"]
                            else item["port_ranges"][0][0]
                        ]
                    else:
                        item["object_state"] = "present"
                    with self.assertRaises(fleet.FleetRefused):
                        subject.validate_forbidden_component_absence(role, mutation)

    def test_embedded_runner_is_bounded_descriptor_based_and_allowlisted(self) -> None:
        source = subject._forbidden_component_library_source()
        for required in (
            "O_NOFOLLOW",
            "dir_fd=fd",
            "follow_symlinks=False",
            "timeout=FORBIDDEN_PROBE_TIMEOUT_SECONDS",
            "shell=False",
            "--property=LoadState",
            '"/usr/bin/ss"',
        ):
            self.assertIn(required, source)

        namespace: dict[str, Any] = {}
        executable_source = (
            "import os, stat, subprocess\n"
            "FORBIDDEN_COMPONENT_PROFILES = "
            + json.dumps(subject.FORBIDDEN_COMPONENT_PROFILES, sort_keys=True)
            + "\n"
            + source
        )
        exec(compile(executable_source, "<runner-library>", "exec"), namespace)
        runner = namespace["DescriptorSyscallRunner"]()
        with self.assertRaisesRegex(SystemExit, "not allowlisted"):
            runner._run_exact(("/bin/sh", "-c", "exit 0"))

    def test_descriptor_probe_distinguishes_missing_present_and_symlink_parent(self) -> None:
        namespace: dict[str, Any] = {}
        executable_source = (
            "import os, stat, subprocess\n"
            "FORBIDDEN_COMPONENT_PROFILES = "
            + json.dumps(subject.FORBIDDEN_COMPONENT_PROFILES, sort_keys=True)
            + "\n"
            + subject._forbidden_component_library_source()
        )
        exec(compile(executable_source, "<descriptor-library>", "exec"), namespace)
        runner = namespace["DescriptorSyscallRunner"]()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            missing = root / "missing"
            runner._allowed_paths.add(str(missing))
            self.assertEqual(runner.path_state(str(missing)), "not-found")
            missing.write_bytes(b"present\n")
            self.assertEqual(runner.path_state(str(missing)), "present")

            real = root / "real"
            real.mkdir()
            (real / "child").write_bytes(b"present\n")
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            through_symlink = alias / "child"
            runner._allowed_paths.add(str(through_symlink))
            self.assertEqual(
                runner.path_state(str(through_symlink)), "present-or-unsafe"
            )

    def test_systemd_probe_requires_exact_not_found_machine_output(self) -> None:
        namespace: dict[str, Any] = {}
        executable_source = (
            "import os, stat, subprocess\n"
            "FORBIDDEN_COMPONENT_PROFILES = "
            + json.dumps(subject.FORBIDDEN_COMPONENT_PROFILES, sort_keys=True)
            + "\n"
            + subject._forbidden_component_library_source()
        )
        exec(compile(executable_source, "<systemd-library>", "exec"), namespace)
        runner = namespace["DescriptorSyscallRunner"]()

        valid = SimpleNamespace(returncode=0, stdout=b"not-found\n", stderr=b"")
        with mock.patch.object(namespace["subprocess"], "run", return_value=valid) as run:
            self.assertEqual(runner.unit_load_state("xray.service"), "not-found")
        argv = run.call_args.args[0]
        self.assertEqual(
            argv,
            [
                "/usr/bin/systemctl",
                "show",
                "--property=LoadState",
                "--value",
                "xray.service",
            ],
        )
        self.assertIs(run.call_args.kwargs["shell"], False)
        self.assertEqual(run.call_args.kwargs["timeout"], 5)

        for result in (
            SimpleNamespace(returncode=0, stdout=b"inactive\n", stderr=b""),
            SimpleNamespace(returncode=0, stdout=b" not-found\n", stderr=b""),
            SimpleNamespace(returncode=0, stdout=b"not-found\n\n", stderr=b""),
            SimpleNamespace(returncode=0, stdout=b"not-found\n", stderr=b"warning"),
            SimpleNamespace(returncode=1, stdout=b"not-found\n", stderr=b""),
        ):
            with self.subTest(result=result):
                with mock.patch.object(namespace["subprocess"], "run", return_value=result):
                    with self.assertRaises(SystemExit):
                        runner.unit_load_state("xray.service")

    def test_socket_probe_parses_numeric_ipv4_and_ipv6_only(self) -> None:
        namespace: dict[str, Any] = {}
        executable_source = (
            "import os, stat, subprocess\n"
            "FORBIDDEN_COMPONENT_PROFILES = "
            + json.dumps(subject.FORBIDDEN_COMPONENT_PROFILES, sort_keys=True)
            + "\n"
            + subject._forbidden_component_library_source()
        )
        exec(compile(executable_source, "<socket-library>", "exec"), namespace)
        runner = namespace["DescriptorSyscallRunner"]()
        tcp = SimpleNamespace(
            returncode=0,
            stdout=(
                b"LISTEN 0 4096 0.0.0.0:9111 0.0.0.0:*\n"
                b"LISTEN 0 4096 [::]:443 [::]:*\n"
            ),
            stderr=b"",
        )
        with mock.patch.object(namespace["subprocess"], "run", return_value=tcp):
            self.assertEqual(runner.listening_ports("tcp"), [443, 9111])

        udp = SimpleNamespace(
            returncode=0,
            stdout=(
                b"UNCONN 0 0 0.0.0.0:9110 0.0.0.0:*\n"
                b"UNCONN 0 0 [::]:32767 [::]:*\n"
            ),
            stderr=b"",
        )
        with mock.patch.object(namespace["subprocess"], "run", return_value=udp):
            self.assertEqual(runner.listening_ports("udp"), [9110, 32767])

        malformed = SimpleNamespace(
            returncode=0,
            stdout=b"LISTEN 0 4096 0.0.0.0:http 0.0.0.0:*\n",
            stderr=b"",
        )
        with mock.patch.object(namespace["subprocess"], "run", return_value=malformed):
            with self.assertRaisesRegex(SystemExit, "port is malformed"):
                runner.listening_ports("tcp")

    def test_docker_object_absence_requires_the_entire_engine_to_be_absent(self) -> None:
        namespace: dict[str, Any] = {}
        executable_source = (
            "import os, stat, subprocess\n"
            "FORBIDDEN_COMPONENT_PROFILES = "
            + json.dumps(subject.FORBIDDEN_COMPONENT_PROFILES, sort_keys=True)
            + "\n"
            + subject._forbidden_component_library_source()
        )
        exec(compile(executable_source, "<docker-library>", "exec"), namespace)
        runner = namespace["DescriptorSyscallRunner"]()
        image = "amneziavpn/amneziawg-go:v3.1.20260828"
        with mock.patch.object(runner, "path_state", return_value="not-found") as paths:
            self.assertEqual(
                runner.docker_object_state("image", image),
                ("not-found", "engine-not-found"),
            )
        self.assertEqual(paths.call_count, 3)

        def present_binary(path: str) -> str:
            return "present" if path == "/usr/bin/docker" else "not-found"

        with mock.patch.object(runner, "path_state", side_effect=present_binary):
            with self.assertRaisesRegex(SystemExit, "engine state is present"):
                runner.docker_object_state("image", image)

    def test_deployment_script_binds_profiles_and_emits_required_evidence(self) -> None:
        script = subject._deployment_script()
        compile(script, "<gcp-proof-deployment-script>", "exec")
        self.assertNotIn("__WINS_FORBIDDEN_COMPONENT_PROBE_LIBRARY__", script)
        self.assertIn("FORBIDDEN_COMPONENT_PROFILES = ", script)
        self.assertIn("probe_forbidden_component_absence", script)
        self.assertIn('"forbidden_component_absence": forbidden_component_absence', script)
        self.assertIn('awg_role = expected["role"] == "data-cover"', script)


if __name__ == "__main__":
    unittest.main()
