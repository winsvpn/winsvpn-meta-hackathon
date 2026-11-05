#!/usr/bin/env python3
"""Frozen 16-action live observation driver for an authorized GCP proof run."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import gcp_deployment_inputs as deployment_inputs
import gcp_proof_fleet as fleet
import gcloud_custody

TOOLCHAIN_PINS = Path(__file__).resolve().with_name("toolchain-pins.json")
REMOTE_SUDO_ARGV = ("/usr/bin/sudo", "--non-interactive")
CREDENTIAL_KIND_ENV = "WINS_GCP_PROOF_CREDENTIAL_KIND"
CREDENTIAL_PATH_ENV = "WINS_GCP_PROOF_CREDENTIAL_PATH"
CREDENTIAL_ACCOUNT_ENV = "WINS_GCP_PROOF_CREDENTIAL_ACCOUNT"
CREDENTIAL_PROJECT_ENV = "WINS_GCP_PROOF_CREDENTIAL_PROJECT"
CREDENTIAL_ENV_NAMES = frozenset(
    {
        "CLOUDSDK_AUTH_ACCESS_TOKEN",
        "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE",
        "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
        "CLOUDSDK_CORE_ACCOUNT",
        "GCE_METADATA_HOST",
        "GCE_METADATA_IP",
        "GCE_METADATA_ROOT",
        "GCLOUD_KEY_FILE",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_APPLICATION_CREDENTIALS_JSON",
        "DOCKER_CONFIG",
        "KUBECONFIG",
        "NETRC",
        "SSH_AUTH_SOCK",
        CREDENTIAL_KIND_ENV,
        CREDENTIAL_PATH_ENV,
        CREDENTIAL_ACCOUNT_ENV,
        CREDENTIAL_PROJECT_ENV,
    }
)

FORBIDDEN_COMPONENT_ABSENCE_CONTRACT = (
    "winsvpn-gcp-proof-forbidden-component-absence-v1"
)
FORBIDDEN_COMPONENT_ABSENCE_SCHEMA_VERSION = 1

_XRAY_COMPONENTS: tuple[Mapping[str, Any], ...] = (
    {
        "component_id": "xray-binary",
        "kind": "path",
        "subject": "/usr/local/bin/xray",
    },
    {
        "component_id": "xray-config",
        "kind": "path",
        "subject": "/usr/local/etc/xray/config.json",
    },
    {
        "component_id": "xray-systemd-dropin",
        "kind": "path",
        "subject": "/etc/systemd/system/xray.service.d/20-winsvpn-user.conf",
    },
    {
        "component_id": "xray-systemd-unit",
        "kind": "systemd-unit",
        "subject": "xray.service",
    },
)
_AWG_COMPONENTS: tuple[Mapping[str, Any], ...] = (
    {
        "component_id": "awg-provenance",
        "kind": "path",
        "subject": "/var/lib/winsvpn/awg-server-image/provenance.json",
    },
    {
        "component_id": "awg-config",
        "kind": "path",
        "subject": "/etc/amnezia/amneziawg/awg0.conf",
    },
    {
        "component_id": "docker-systemd-unit",
        "kind": "systemd-unit",
        "subject": "docker.service",
    },
    {
        "component_id": "awg-interface",
        "kind": "interface",
        "subject": "awg0",
    },
    {
        "component_id": "amn-interface",
        "kind": "interface",
        "subject": "amn0",
    },
    {
        "component_id": "awg-docker-image",
        "kind": "docker-image",
        "subject": "amneziavpn/amneziawg-go:v3.1.20260828",
    },
    {
        "component_id": "awg-primary-container",
        "kind": "docker-container",
        "subject": "amnezia-awg2",
    },
    {
        "component_id": "awg-legacy-container",
        "kind": "docker-container",
        "subject": "awg",
    },
    {
        "component_id": "awg-alias-container",
        "kind": "docker-container",
        "subject": "amnezia-awg",
    },
)
_WINN3_COMPONENTS: tuple[Mapping[str, Any], ...] = (
    {
        "component_id": "winn3-gateway-binary",
        "kind": "path",
        "subject": "/usr/local/libexec/winn/winn3-gateway",
    },
    {
        "component_id": "winn3-gateway-systemd-unit",
        "kind": "systemd-unit",
        "subject": "winn3-gateway.service",
    },
    {
        "component_id": "winn3-firewall-systemd-unit",
        "kind": "systemd-unit",
        "subject": "winn3-gateway-firewall.service",
    },
    {
        "component_id": "winn3-interface",
        "kind": "interface",
        "subject": "winn3gw0",
    },
)
_WINN3_GATEWAY_ENV_COMPONENT: Mapping[str, Any] = {
    "component_id": "winn3-gateway-env",
    "kind": "path",
    "subject": "/etc/winn/winn3-gateway.env",
}
_V1_TCP_LISTENERS: Mapping[str, Any] = {
    "component_id": "v1-xray-tcp-listeners",
    "kind": "listener-set",
    "protocol": "tcp",
    "ports": [80, 443, 10085],
    "port_ranges": [],
}
_CONTROL_V1_TCP_LISTENERS: Mapping[str, Any] = {
    "component_id": "v1-xray-private-tcp-listener",
    "kind": "listener-set",
    "protocol": "tcp",
    "ports": [10085],
    "port_ranges": [],
}
_V1_UDP_LISTENERS: Mapping[str, Any] = {
    "component_id": "v1-awg-udp-listeners",
    "kind": "listener-set",
    "protocol": "udp",
    "ports": [9110],
    "port_ranges": [[20000, 32767]],
}
_WINN3_TCP_LISTENER: Mapping[str, Any] = {
    "component_id": "winn3-tcp-listener",
    "kind": "listener-set",
    "protocol": "tcp",
    "ports": [9111],
    "port_ranges": [],
}
_WINN3_UDP_LISTENER: Mapping[str, Any] = {
    "component_id": "winn3-udp-listener",
    "kind": "listener-set",
    "protocol": "udp",
    "ports": [9111],
    "port_ranges": [],
}

# These profiles are compiled into the descriptor-authenticated remote probe.
# They are not supplied by the caller or by the deployment observation.
FORBIDDEN_COMPONENT_PROFILES: Mapping[
    str, tuple[Mapping[str, Any], ...]
] = {
    "control": (
        _XRAY_COMPONENTS
        + _AWG_COMPONENTS
        + _WINN3_COMPONENTS
        + (
            _CONTROL_V1_TCP_LISTENERS,
            _V1_UDP_LISTENERS,
            _WINN3_TCP_LISTENER,
            _WINN3_UDP_LISTENER,
        )
    ),
    "data-winn3": (
        _XRAY_COMPONENTS
        + _AWG_COMPONENTS
        + (_V1_TCP_LISTENERS, _V1_UDP_LISTENERS)
    ),
    "data-cover": (
        _WINN3_COMPONENTS
        + (
            _WINN3_GATEWAY_ENV_COMPONENT,
            _WINN3_TCP_LISTENER,
            _WINN3_UDP_LISTENER,
        )
    ),
}


def _forbidden_component_library_source() -> str:
    """Return the exact self-contained library executed on each proof VM."""
    return r'''
FORBIDDEN_PROBE_MAX_OUTPUT = 1024 * 1024
FORBIDDEN_PROBE_TIMEOUT_SECONDS = 5
FORBIDDEN_PROBE_ENGINE_PATHS = (
    "/usr/bin/docker",
    "/run/docker.sock",
    "/var/lib/docker",
)

def _forbidden_profile_values(kind):
    values = set()
    for components in FORBIDDEN_COMPONENT_PROFILES.values():
        for component in components:
            if component.get("kind") == kind:
                values.add(component.get("subject"))
    return values

class DescriptorSyscallRunner:
    def __init__(self):
        self._allowed_paths = _forbidden_profile_values("path")
        self._allowed_paths.update(FORBIDDEN_PROBE_ENGINE_PATHS)
        self._allowed_interfaces = _forbidden_profile_values("interface")
        self._allowed_units = _forbidden_profile_values("systemd-unit")
        self._allowed_images = _forbidden_profile_values("docker-image")
        self._allowed_containers = _forbidden_profile_values("docker-container")
        if None in (
            self._allowed_paths
            | self._allowed_interfaces
            | self._allowed_units
            | self._allowed_images
            | self._allowed_containers
        ):
            raise SystemExit("forbidden-component profile contains a null subject")
        self._environment = {
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        }

    def _command_is_allowed(self, argv):
        if argv in (
            ("/usr/bin/ss", "-H", "-l", "-n", "-t"),
            ("/usr/bin/ss", "-H", "-l", "-n", "-u"),
        ):
            return True
        if (
            len(argv) == 5
            and argv[:4]
            == ("/usr/bin/systemctl", "show", "--property=LoadState", "--value")
            and argv[4] in self._allowed_units
        ):
            return True
        return False

    def _run_exact(self, argv):
        argv = tuple(argv)
        if not self._command_is_allowed(argv):
            raise SystemExit("forbidden-component syscall was not allowlisted")
        try:
            result = subprocess.run(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                check=False,
                timeout=FORBIDDEN_PROBE_TIMEOUT_SECONDS,
                env=self._environment,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise SystemExit("forbidden-component syscall failed")
        if (
            len(result.stdout) > FORBIDDEN_PROBE_MAX_OUTPUT
            or len(result.stderr) > FORBIDDEN_PROBE_MAX_OUTPUT
        ):
            raise SystemExit("forbidden-component syscall output exceeded its bound")
        return result

    def path_state(self, path):
        if type(path) is not str or path not in self._allowed_paths:
            raise SystemExit("forbidden-component path was not allowlisted")
        return self._descriptor_entry_state(path)

    def interface_state(self, name):
        if type(name) is not str or name not in self._allowed_interfaces:
            raise SystemExit("forbidden-component interface was not allowlisted")
        return self._descriptor_entry_state("/sys/class/net/" + name, allow_dynamic=True)

    def _descriptor_entry_state(self, path, allow_dynamic=False):
        if (
            type(path) is not str
            or not path.startswith("/")
            or os.path.normpath(path) != path
            or path == "/"
        ):
            raise SystemExit("forbidden-component path is not canonical")
        if allow_dynamic:
            expected = {"/sys/class/net/" + item for item in self._allowed_interfaces}
            if path not in expected:
                raise SystemExit("forbidden-component dynamic path was not allowlisted")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )

        def snapshot():
            fd = os.open("/", flags)
            chain = []
            parts = [item for item in path.split("/") if item]
            try:
                root_info = os.fstat(fd)
                chain.append((root_info.st_dev, root_info.st_ino, stat.S_IFMT(root_info.st_mode)))
                for index, part in enumerate(parts):
                    final = index == len(parts) - 1
                    if final:
                        try:
                            os.stat(part, dir_fd=fd, follow_symlinks=False)
                        except FileNotFoundError:
                            return ("not-found", tuple(chain), index)
                        except OSError:
                            return ("present-or-unsafe", tuple(chain), index)
                        return ("present", tuple(chain), index)
                    try:
                        next_fd = os.open(part, flags, dir_fd=fd)
                    except FileNotFoundError:
                        return ("not-found", tuple(chain), index)
                    except OSError:
                        return ("present-or-unsafe", tuple(chain), index)
                    os.close(fd)
                    fd = next_fd
                    info = os.fstat(fd)
                    chain.append((info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)))
            finally:
                os.close(fd)
            raise SystemExit("forbidden-component descriptor probe was incomplete")

        before = snapshot()
        if before[0] != "not-found":
            return before[0]
        after = snapshot()
        if after != before:
            return "changed-or-unsafe"
        return "not-found"

    def unit_load_state(self, unit):
        if type(unit) is not str or unit not in self._allowed_units:
            raise SystemExit("forbidden-component systemd unit was not allowlisted")
        result = self._run_exact(
            ("/usr/bin/systemctl", "show", "--property=LoadState", "--value", unit)
        )
        if result.returncode != 0 or result.stderr:
            raise SystemExit("unable to prove forbidden systemd unit load state")
        if result.stdout != b"not-found\n":
            raise SystemExit("forbidden systemd unit LoadState is not exactly not-found")
        return "not-found"

    def listening_ports(self, protocol):
        if protocol not in {"tcp", "udp"}:
            raise SystemExit("forbidden-component listener protocol is invalid")
        flag = "-t" if protocol == "tcp" else "-u"
        result = self._run_exact(("/usr/bin/ss", "-H", "-l", "-n", flag))
        if result.returncode != 0 or result.stderr:
            raise SystemExit("unable to enumerate local listening sockets")
        try:
            text = result.stdout.decode("ascii")
        except UnicodeDecodeError:
            raise SystemExit("local listening socket inventory is not ASCII")
        ports = set()
        for line in text.splitlines():
            fields = line.split()
            if len(fields) < 5:
                raise SystemExit("local listening socket inventory is malformed")
            endpoint = fields[3]
            if ":" not in endpoint:
                raise SystemExit("local listening socket endpoint is malformed")
            value = endpoint.rsplit(":", 1)[1]
            if not value.isdigit():
                raise SystemExit("local listening socket port is malformed")
            port = int(value)
            if port < 1 or port > 65535:
                raise SystemExit("local listening socket port is out of range")
            ports.add(port)
        return sorted(ports)

    def docker_object_state(self, kind, subject):
        if kind not in {"image", "container"} or type(subject) is not str:
            raise SystemExit("forbidden Docker object request is malformed")
        allowed = self._allowed_images if kind == "image" else self._allowed_containers
        if subject not in allowed:
            raise SystemExit("forbidden Docker object was not allowlisted")
        engine = {path: self.path_state(path) for path in FORBIDDEN_PROBE_ENGINE_PATHS}
        if set(engine.values()) == {"not-found"}:
            return ("not-found", "engine-not-found")
        raise SystemExit(
            "Docker engine state is present or ambiguous; AWG object absence is unproven"
        )

def probe_forbidden_component_absence(role, runner):
    if type(role) is not str or role not in FORBIDDEN_COMPONENT_PROFILES:
        raise SystemExit("forbidden-component role is invalid")
    profile = FORBIDDEN_COMPONENT_PROFILES[role]
    if type(profile) not in {tuple, list} or not profile:
        raise SystemExit("forbidden-component profile is malformed")
    checks = []
    listener_cache = {}
    seen_ids = set()
    for component in profile:
        if type(component) is not dict:
            raise SystemExit("forbidden-component profile entry is malformed")
        component_id = component.get("component_id")
        kind = component.get("kind")
        if type(component_id) is not str or not component_id or component_id in seen_ids:
            raise SystemExit("forbidden-component profile id is invalid or duplicated")
        seen_ids.add(component_id)
        if kind in {"path", "systemd-unit", "interface", "docker-image", "docker-container"}:
            if set(component) != {"component_id", "kind", "subject"}:
                raise SystemExit("forbidden-component profile entry has extra or missing fields")
            subject = component.get("subject")
            if type(subject) is not str or not subject:
                raise SystemExit("forbidden-component subject is invalid")
        if kind == "path":
            state = runner.path_state(subject)
            if state != "not-found":
                raise SystemExit("forbidden path is present or its absence is unproven")
            checks.append({
                "component_id": component_id,
                "entry_state": state,
                "kind": kind,
                "subject": subject,
            })
        elif kind == "systemd-unit":
            load_state = runner.unit_load_state(subject)
            if load_state != "not-found":
                raise SystemExit("forbidden systemd unit LoadState is not not-found")
            checks.append({
                "component_id": component_id,
                "kind": kind,
                "load_state": load_state,
                "subject": subject,
            })
        elif kind == "interface":
            state = runner.interface_state(subject)
            if state != "not-found":
                raise SystemExit("forbidden network interface is present or unproven")
            checks.append({
                "component_id": component_id,
                "entry_state": state,
                "kind": kind,
                "subject": subject,
            })
        elif kind == "listener-set":
            if set(component) != {
                "component_id", "kind", "port_ranges", "ports", "protocol"
            }:
                raise SystemExit("forbidden listener profile has extra or missing fields")
            protocol = component.get("protocol")
            ports = component.get("ports")
            ranges = component.get("port_ranges")
            if (
                protocol not in {"tcp", "udp"}
                or type(ports) is not list
                or any(type(port) is not int or port < 1 or port > 65535 for port in ports)
                or ports != sorted(set(ports))
                or type(ranges) is not list
                or any(
                    type(item) is not list
                    or len(item) != 2
                    or any(type(value) is not int for value in item)
                    or item[0] < 1
                    or item[1] > 65535
                    or item[0] > item[1]
                    for item in ranges
                )
            ):
                raise SystemExit("forbidden listener profile is malformed")
            if protocol not in listener_cache:
                observed = runner.listening_ports(protocol)
                if (
                    type(observed) is not list
                    or any(type(port) is not int or port < 1 or port > 65535 for port in observed)
                    or observed != sorted(set(observed))
                ):
                    raise SystemExit("local listening socket inventory is malformed")
                listener_cache[protocol] = observed
            matching = [
                port for port in listener_cache[protocol]
                if port in ports or any(item[0] <= port <= item[1] for item in ranges)
            ]
            if matching:
                raise SystemExit("forbidden local listener is present")
            checks.append({
                "component_id": component_id,
                "kind": kind,
                "matching_ports": [],
                "port_ranges": ranges,
                "ports": ports,
                "protocol": protocol,
            })
        elif kind in {"docker-image", "docker-container"}:
            object_kind = "image" if kind == "docker-image" else "container"
            state, evidence = runner.docker_object_state(object_kind, subject)
            if state != "not-found" or evidence != "engine-not-found":
                raise SystemExit("forbidden Docker object is present or its absence is unproven")
            checks.append({
                "component_id": component_id,
                "evidence": evidence,
                "kind": kind,
                "object_state": state,
                "subject": subject,
            })
        else:
            raise SystemExit("forbidden-component kind is unsupported")
    return {
        "checks": checks,
        "contract": "winsvpn-gcp-proof-forbidden-component-absence-v1",
        "role": role,
        "schema_version": 1,
    }
'''.lstrip()


def validate_forbidden_component_absence(
    role: str, raw: Any
) -> dict[str, Any]:
    if type(role) is not str or role not in FORBIDDEN_COMPONENT_PROFILES:
        raise fleet.FleetRefused("forbidden-component absence role is invalid")
    if type(raw) is not dict or set(raw) != {
        "checks",
        "contract",
        "role",
        "schema_version",
    }:
        raise fleet.FleetRefused(
            "forbidden-component absence evidence has extra or missing fields"
        )
    if (
        raw.get("contract") != FORBIDDEN_COMPONENT_ABSENCE_CONTRACT
        or type(raw.get("schema_version")) is not int
        or raw.get("schema_version") != FORBIDDEN_COMPONENT_ABSENCE_SCHEMA_VERSION
        or raw.get("role") != role
    ):
        raise fleet.FleetRefused(
            "forbidden-component absence evidence identity is invalid"
        )
    checks = raw.get("checks")
    profile = FORBIDDEN_COMPONENT_PROFILES[role]
    if type(checks) is not list or len(checks) != len(profile):
        raise fleet.FleetRefused(
            "forbidden-component absence checks are missing or mixed"
        )
    for expected, observed in zip(profile, checks):
        if type(observed) is not dict:
            raise fleet.FleetRefused(
                "forbidden-component absence check is malformed"
            )
        kind = expected["kind"]
        common = {
            "component_id": expected["component_id"],
            "kind": kind,
        }
        if kind in {"path", "interface"}:
            wanted = {
                **common,
                "entry_state": "not-found",
                "subject": expected["subject"],
            }
            if observed != wanted:
                raise fleet.FleetRefused(
                    "forbidden path or interface absence was not proven"
                )
        elif kind == "systemd-unit":
            wanted = {
                **common,
                "load_state": "not-found",
                "subject": expected["subject"],
            }
            if observed != wanted:
                raise fleet.FleetRefused(
                    "forbidden systemd unit LoadState is not not-found"
                )
        elif kind == "listener-set":
            wanted = {
                **common,
                "matching_ports": [],
                "port_ranges": expected["port_ranges"],
                "ports": expected["ports"],
                "protocol": expected["protocol"],
            }
            if observed != wanted:
                raise fleet.FleetRefused(
                    "forbidden listener absence was not proven"
                )
        elif kind in {"docker-image", "docker-container"}:
            if set(observed) != {
                "component_id",
                "evidence",
                "kind",
                "object_state",
                "subject",
            } or any(
                (
                    observed.get("component_id") != expected["component_id"],
                    observed.get("kind") != kind,
                    observed.get("subject") != expected["subject"],
                    observed.get("object_state") != "not-found",
                    observed.get("evidence") != "engine-not-found",
                )
            ):
                raise fleet.FleetRefused(
                    "forbidden Docker object absence was not proven"
                )
        else:
            raise fleet.FleetRefused(
                "forbidden-component absence check kind is unsupported"
            )
    return dict(raw)


def strip_validated_forbidden_component_absence(
    role: str, raw: Any
) -> dict[str, Any]:
    """Validate the remote-only proof and restore the frozen collector schema."""
    if type(raw) is not dict:
        raise fleet.FleetRefused("deployment observation is malformed")
    result = dict(raw)
    validate_forbidden_component_absence(
        role, result.get("forbidden_component_absence")
    )
    result.pop("forbidden_component_absence")
    return result


@dataclass(frozen=True)
class Result:
    stdout: bytes
    stderr: bytes
    exit_code: int


class Runner(Protocol):
    def run(self, argv: Sequence[str], *, timeout_seconds: int) -> Result: ...


def sanitized_child_environment() -> dict[str, str]:
    """Allowlisted child env. Credential material never reaches proof executables."""
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    tmp = os.environ.get("TMPDIR")
    if type(tmp) is str and tmp:
        environment["TMPDIR"] = tmp
    for name in CREDENTIAL_ENV_NAMES:
        environment.pop(name, None)
    return environment


def _env_value(args: argparse.Namespace, flag: str, environ_name: str) -> str:
    overlay = getattr(args, flag, None)
    if type(overlay) is str and overlay:
        return overlay
    value = os.environ.get(environ_name, "")
    return value if type(value) is str else ""


def _credential_argv(args: argparse.Namespace) -> list[str]:
    kind = _env_value(args, "credential_kind", CREDENTIAL_KIND_ENV)
    path = _env_value(args, "credential_path", CREDENTIAL_PATH_ENV)
    account = _env_value(args, "credential_account", CREDENTIAL_ACCOUNT_ENV)
    project = _env_value(args, "credential_project", CREDENTIAL_PROJECT_ENV)
    present = (kind, path, account, project)
    if not any(present):
        return []
    if not all(present):
        raise fleet.FleetRefused(
            "owner blocker: Google Cloud CLI execution requires an exact "
            "descriptor-authenticated service-account credential or workload identity input"
        )
    bound_project = getattr(args, "project", "")
    if type(bound_project) is not str or not bound_project or bound_project != project:
        raise fleet.FleetRefused(
            "proof credential project does not match the bound project"
        )
    return [
        "--credential-kind",
        kind,
        "--credential-path",
        path,
        "--credential-account",
        account,
        "--credential-project",
        project,
    ]


def require_authenticated_gcloud_credential(
    args: argparse.Namespace | None = None,
    *,
    expected_project: str | None = None,
) -> gcloud_custody.GcloudCredentialInput:
    namespace = args if args is not None else argparse.Namespace()
    kind = _env_value(namespace, "credential_kind", CREDENTIAL_KIND_ENV)
    path = _env_value(namespace, "credential_path", CREDENTIAL_PATH_ENV)
    account = _env_value(namespace, "credential_account", CREDENTIAL_ACCOUNT_ENV)
    project = _env_value(namespace, "credential_project", CREDENTIAL_PROJECT_ENV)
    if not kind or not path or not account or not project:
        raise fleet.FleetRefused(
            "owner blocker: Google Cloud CLI execution requires an exact "
            "descriptor-authenticated service-account credential or workload identity input"
        )
    credential = gcloud_custody.GcloudCredentialInput(
        kind=kind,
        path=Path(path),
        expected_account=account,
        expected_project=project,
    )
    try:
        gcloud_custody.authenticate_credential(credential)
        bound_project = expected_project
        if bound_project is None:
            bound_project = getattr(namespace, "project", None)
        if type(bound_project) is str and bound_project:
            gcloud_custody.require_bound_project(credential, bound_project)
    except gcloud_custody.GcloudCustodyError as suc:
        raise fleet.FleetRefused(
            "owner blocker: Google Cloud CLI credential custody is absent or invalid"
        ) from suc
    return credential


def require_local_python_runtime(args: argparse.Namespace | None = None) -> dict[str, object]:
    namespace = args if args is not None else argparse.Namespace()
    path = _env_value(
        namespace,
        "python_runtime_receipt",
        deployment_inputs.PYTHON_RUNTIME_RECEIPT_ENV,
    )
    if not path:
        raise fleet.FleetRefused(
            "owner blocker: local Python runtime receipt is required; "
            "refusing version-only ambient python3"
        )
    try:
        record = deployment_inputs.authenticate_local_python_runtime(Path(path))
    except deployment_inputs.DeploymentInputsError as exc:
        raise fleet.FleetRefused(str(exc)) from exc
    version = record.get("version")
    if (
        record.get("implementation")
        != deployment_inputs.COMPATIBLE_RUNTIME_IMPLEMENTATION
        or type(version) is not str
        or not version.startswith("3.14.")
    ):
        raise fleet.FleetRefused(
            "owner blocker: local Python runtime must be authenticated CPython 3.14"
        )
    return record


def require_remote_python_runtime(args: argparse.Namespace | None = None) -> dict[str, object]:
    namespace = args if args is not None else argparse.Namespace()
    path = _env_value(
        namespace,
        "remote_python_runtime_receipt",
        deployment_inputs.REMOTE_PYTHON_RUNTIME_RECEIPT_ENV,
    )
    if not path:
        raise fleet.FleetRefused(
            "owner blocker: remote Python runtime receipt is required; "
            "refusing version-only ambient python3"
        )
    try:
        record = deployment_inputs.parse_python_runtime_receipt(Path(path))
    except deployment_inputs.DeploymentInputsError as exc:
        raise fleet.FleetRefused(str(exc)) from exc
    executable = str(record["executable_path"])
    if not os.path.isabs(executable) or os.path.basename(executable) == executable:
        raise fleet.FleetRefused("refusing ambient python3")
    if record.get("implementation") != deployment_inputs.COMPATIBLE_RUNTIME_IMPLEMENTATION:
        raise fleet.FleetRefused(
            "owner blocker: remote Python runtime must be authenticated CPython 3.14"
        )
    version = record.get("version")
    if type(version) is not str or not version.startswith("3.14."):
        raise fleet.FleetRefused(
            "owner blocker: remote Python runtime must be authenticated CPython 3.14"
        )
    return record


def remote_python_argv(receipt: Mapping[str, Any], script: str, payload: str) -> list[str]:
    executable = receipt.get("executable_path")
    if type(executable) is not str or not executable:
        raise fleet.FleetRefused("remote python runtime executable path is missing")
    if not os.path.isabs(executable) or os.path.normpath(executable) != executable:
        raise fleet.FleetRefused("refusing ambient python3")
    if os.path.basename(executable) == executable:
        raise fleet.FleetRefused("refusing ambient python3")
    version = receipt.get("version")
    digest = receipt.get("executable_sha256")
    if (
        receipt.get("implementation")
        != deployment_inputs.COMPATIBLE_RUNTIME_IMPLEMENTATION
        or type(version) is not str
        or not version.startswith("3.14.")
        or type(digest) is not str
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    ):
        raise fleet.FleetRefused(
            "owner blocker: nested GCP child requires authenticated CPython 3.14"
        )
    if type(script) is not str or not script or type(payload) is not str or not payload:
        raise fleet.FleetRefused("remote python command payload is invalid")
    return [executable, "-I", "-c", script, payload]


def bind_live_production_runner(
    runner: Runner,
    gcloud_bin: str,
    *,
    args: argparse.Namespace | None = None,
) -> tuple[Runner, str]:
    if type(runner) is not SubprocessRunner:
        if getattr(type(runner), "TEST_ONLY", False) is True or getattr(runner, "TEST_ONLY", False) is True:
            return runner, gcloud_bin
        raise fleet.FleetRefused(gcloud_custody.ARBITRARY_RUNNER)
    expected_project = None
    if args is not None:
        project = getattr(args, "project", None)
        if type(project) is str and project:
            expected_project = project
    credential = require_authenticated_gcloud_credential(
        args, expected_project=expected_project
    )
    require_local_python_runtime(args)
    try:
        bound = gcloud_custody.bind_production_runner(
            runner, gcloud_bin, credential, pin_manifest=TOOLCHAIN_PINS
        )
    except gcloud_custody.GcloudCustodyError as suc:
        raise fleet.FleetRefused(str(suc)) from suc
    return bound, str(bound.verified.executable)


class SubprocessRunner:
    def run(self, argv: Sequence[str], *, timeout_seconds: int) -> Result:
        if (
            isinstance(argv, (str, bytes))
            or not argv
            or not all(isinstance(value, str) and value for value in argv)
        ):
            raise fleet.FleetRefused("live probe requires an explicit argv vector")
        try:
            completed = subprocess.run(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                check=False,
                timeout=timeout_seconds,
                env=sanitized_child_environment(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise fleet.FleetRefused("live probe command execution failed") from exc
        return Result(bytes(completed.stdout), bytes(completed.stderr), completed.returncode)


def _basename(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise fleet.FleetRefused(f"{label} is missing")
    return value.rstrip("/").rsplit("/", 1)[-1]


def _project_from_link(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise fleet.FleetRefused(f"{label} is missing")
    parts = value.rstrip("/").split("/")
    try:
        index = parts.index("projects")
        project = parts[index + 1]
    except (ValueError, IndexError) as exc:
        raise fleet.FleetRefused(f"{label} project is malformed") from exc
    if not project:
        raise fleet.FleetRefused(f"{label} project is malformed")
    return project


def _json_result(runner: Runner, argv: Sequence[str], *, label: str) -> Any:
    result = runner.run(list(argv), timeout_seconds=120)
    if result.exit_code != 0:
        raise fleet.FleetRefused(f"{label} exited {result.exit_code}")
    if result.stderr.strip():
        raise fleet.FleetRefused(f"{label} wrote unexpected stderr")
    if len(result.stdout) > fleet.MAX_CAPTURE_BYTES:
        raise fleet.FleetRefused(f"{label} output is too large")
    return fleet.strict_json_bytes(label, result.stdout)


def verify_gcloud_version(runner: Runner, gcloud_bin: str) -> str:
    verified = getattr(runner, "verified", None)
    if (
        type(runner) is gcloud_custody.CustodyRunner
        and gcloud_custody.runner_may_emit_production_pass(runner)
        and verified is not None
        and type(getattr(verified, "version", None)) is str
    ):
        expected = verified.version
    else:
        try:
            expected = gcloud_custody.parse_google_cloud_cli_pin_document(
                TOOLCHAIN_PINS.read_bytes()
            )["version"]
        except (OSError, KeyError, TypeError, gcloud_custody.GcloudCustodyError) as suc:
            raise fleet.FleetRefused("Google Cloud CLI toolchain pin is invalid") from suc
    raw = _json_result(
        runner,
        [gcloud_bin, "version", "--format=json"],
        label="Google Cloud CLI version probe",
    )
    observed = raw.get("Google Cloud SDK") if isinstance(raw, dict) else None
    if not isinstance(expected, str) or observed != expected:
        raise fleet.FleetRefused(
            f"Google Cloud CLI version mismatch: expected {expected!r}, observed {observed!r}"
        )
    return expected


def _metadata(raw: Mapping[str, Any]) -> dict[str, str]:
    block = raw.get("metadata") or {}
    items = block.get("items") if isinstance(block, dict) else None
    if not isinstance(items, list):
        return {}
    result: dict[str, str] = {}
    for item in items:
        if not isinstance(item, dict) or set(item) != {"key", "value"}:
            raise fleet.FleetRefused("instance metadata is malformed")
        key, value = item["key"], item["value"]
        if not isinstance(key, str) or not isinstance(value, str) or key in result:
            raise fleet.FleetRefused("instance metadata is duplicated or invalid")
        result[key] = value
    return result


def _role_specs(args: argparse.Namespace) -> list[dict[str, str]]:
    return [
        {
            "role": "control",
            "instance": args.control_instance,
            "zone": args.control_zone,
            "machine_type": args.control_machine_type,
            "subnet": args.control_subnet,
        },
        {
            "role": "data-winn3",
            "instance": args.winn3_data_instance,
            "zone": args.winn3_data_zone,
            "machine_type": args.winn3_data_machine_type,
            "subnet": args.winn3_data_subnet,
        },
        {
            "role": "data-cover",
            "instance": args.cover_data_instance,
            "zone": args.cover_data_zone,
            "machine_type": args.cover_data_machine_type,
            "subnet": args.cover_data_subnet,
        },
    ]


def _canonical_resources(args: argparse.Namespace) -> dict[str, Any]:
    roles = _role_specs(args)
    canonical = fleet.canonical_resource_contract(
        args.fleet_id, {item["role"]: item["zone"] for item in roles}
    )
    supplied_subnets = {item["role"]: item["subnet"] for item in roles}
    expected_subnets = {item["role"]: item["name"] for item in canonical["subnets"]}
    if args.network != canonical["network"] or supplied_subnets != expected_subnets:
        raise fleet.FleetRefused(
            "live probe resource names do not match the canonical fleet contract"
        )
    return canonical


def _gcloud(args: argparse.Namespace, *values: str) -> list[str]:
    return [args.gcloud_bin, *values, f"--project={args.project}"]


def verified_client_release(args: argparse.Namespace) -> dict[str, Any]:
    reference = fleet.create_client_release_binding_reference(
        Path(args.client_repo_root),
        Path(args.client_release_input_index),
        Path(args.client_build_receipt),
        Path(args.client_artifact),
    )
    binding = reference["binding"]
    expected = {
        "client_release_input_index_sha256": binding["release_input_index"][
            "sha256"
        ],
        "client_build_receipt_sha256": binding["build_receipt"]["sha256"],
        "client_sha256": binding["artifact"]["sha256"],
        "client_bytes": binding["artifact"]["bytes"],
        "client_build_identity": binding["build_identity"],
        "client_release": binding["release"],
        "client_shared_revision": binding["shared_revision"],
        "client_artifact_input_fingerprint_sha256": binding[
            "artifact_input_fingerprint_sha256"
        ],
        "client_binding_sha256": reference["binding_sha256"],
        "client_binding_reference_sha256": fleet.sha256_bytes(
            fleet.canonical_bytes(reference)
        ),
    }
    for name, value in expected.items():
        if getattr(args, name) != value:
            raise fleet.FleetRefused(
                f"live probe {name.replace('_', ' ')} does not match the verified release"
            )
    return reference


def inventory(args: argparse.Namespace, runner: Runner) -> dict[str, Any]:
    _canonical_resources(args)
    network = _json_result(
        runner,
        _gcloud(
            args,
            "compute",
            "networks",
            "describe",
            args.network,
            "--format=json(name,autoCreateSubnetworks,routingConfig.routingMode)",
        ),
        label="network describe",
    )
    if not isinstance(network, dict):
        raise fleet.FleetRefused("network describe output is malformed")
    subnet_rows: list[dict[str, Any]] = []
    seen_subnets: set[tuple[str, str]] = set()
    for role in _role_specs(args):
        region = role["zone"].rsplit("-", 1)[0]
        key = (role["subnet"], region)
        if key in seen_subnets:
            continue
        seen_subnets.add(key)
        raw = _json_result(
            runner,
            _gcloud(
                args,
                "compute",
                "networks",
                "subnets",
                "describe",
                role["subnet"],
                f"--region={region}",
                "--format=json(name,region,ipCidrRange,network)",
            ),
            label="subnet describe",
        )
        if not isinstance(raw, dict):
            raise fleet.FleetRefused("subnet describe output is malformed")
        subnet_rows.append(
            {
                "name": raw.get("name"),
                "region": _basename(raw.get("region"), "subnet region"),
                "cidr": raw.get("ipCidrRange"),
                "network": _basename(raw.get("network"), "subnet network"),
            }
        )
    instance_rows: list[dict[str, Any]] = []
    images: dict[str, dict[str, str]] = {}
    for role in _role_specs(args):
        raw = _json_result(
            runner,
            _gcloud(
                args,
                "compute",
                "instances",
                "describe",
                role["instance"],
                f"--zone={role['zone']}",
                "--format=json",
            ),
            label="instance describe",
        )
        if not isinstance(raw, dict):
            raise fleet.FleetRefused("instance describe output is malformed")
        disks = raw.get("disks")
        if not isinstance(disks, list) or len(disks) != 1 or not isinstance(disks[0], dict):
            raise fleet.FleetRefused("instance must expose exactly one boot disk")
        disk_name = _basename(disks[0].get("source"), "boot disk")
        disk = _json_result(
            runner,
            _gcloud(
                args,
                "compute",
                "disks",
                "describe",
                disk_name,
                f"--zone={role['zone']}",
                "--format=json(sourceImage)",
            ),
            label="boot disk describe",
        )
        if not isinstance(disk, dict):
            raise fleet.FleetRefused("boot disk source image is malformed")
        source_image = disk.get("sourceImage")
        if _project_from_link(source_image, "boot disk source image") != args.image_project:
            raise fleet.FleetRefused("boot disk image project does not match apply state")
        source_name = _basename(source_image, "boot disk source image")
        if source_name not in images:
            image = _json_result(
                runner,
                [
                    args.gcloud_bin,
                    "compute",
                    "images",
                    "describe",
                    source_name,
                    f"--project={args.image_project}",
                    "--format=json(name,id,selfLink,family)",
                ],
                label="immutable image describe",
            )
            if (
                not isinstance(image, dict)
                or image.get("name") != source_name
                or image.get("selfLink") != source_image
                or image.get("family") != args.image_family
            ):
                raise fleet.FleetRefused(
                    "boot disk does not match the apply-bound image family/project"
                )
            images[source_name] = {
                "name": source_name,
                "id": str(image.get("id") or ""),
            }
        image_name = images[source_name]["name"]
        image_id = images[source_name]["id"]
        interfaces = raw.get("networkInterfaces")
        if not isinstance(interfaces, list) or len(interfaces) != 1:
            raise fleet.FleetRefused("instance network interface scope is invalid")
        interface = interfaces[0]
        if not isinstance(interface, dict):
            raise fleet.FleetRefused("instance network interface is malformed")
        metadata = _metadata(raw)
        service_accounts = raw.get("serviceAccounts") or []
        if not isinstance(service_accounts, list):
            raise fleet.FleetRefused("instance service accounts are malformed")
        scopes: list[str] = []
        for account in service_accounts:
            if not isinstance(account, dict) or not isinstance(account.get("scopes") or [], list):
                raise fleet.FleetRefused("instance service-account scopes are malformed")
            scopes.extend(str(value) for value in account.get("scopes") or [])
        shielded = raw.get("shieldedInstanceConfig") or {}
        labels = raw.get("labels") or {}
        tags = (raw.get("tags") or {}).get("items") or []
        if not isinstance(labels, dict) or not isinstance(tags, list):
            raise fleet.FleetRefused("instance labels or tags are malformed")
        expected_forwarding = role["role"] in {"data-winn3", "data-cover"}
        if (
            type(raw.get("canIpForward")) is not bool
            or raw["canIpForward"] is not expected_forwarding
        ):
            raise fleet.FleetRefused(
                f"instance canIpForward does not match the exact role for {role['role']}"
            )
        instance_rows.append(
            {
                "role": role["role"],
                "name": raw.get("name"),
                "zone": _basename(raw.get("zone"), "instance zone"),
                "machine_type": _basename(raw.get("machineType"), "machine type"),
                "power_state": raw.get("status"),
                "network": _basename(interface.get("network"), "instance network"),
                "subnet": _basename(interface.get("subnetwork"), "instance subnet"),
                "image_project": args.image_project,
                "image_family": args.image_family,
                "image_name": image_name,
                "image_id": image_id,
                "os_login": metadata.get("enable-oslogin", "").upper() == "TRUE",
                "attached_identity_count": len(service_accounts),
                "oauth_scopes": sorted(scopes),
                "shielded": {
                    "secure_boot": shielded.get("enableSecureBoot"),
                    "vtpm": shielded.get("enableVtpm"),
                    "integrity_monitoring": shielded.get("enableIntegrityMonitoring"),
                },
                "deletion_protection": raw.get("deletionProtection"),
                "can_ip_forward": raw["canIpForward"],
                "labels": labels,
                "tags": sorted(tags),
            }
        )
    return {
        "network": {
            "name": network.get("name"),
            "auto_create_subnetworks": network.get("autoCreateSubnetworks"),
            "routing_mode": (network.get("routingConfig") or {}).get("routingMode"),
        },
        "subnets": sorted(subnet_rows, key=lambda item: (item["region"], item["name"])),
        "instances": instance_rows,
    }


def _deployment_script() -> str:
    script = r"""
import hashlib, json, os, stat, subprocess, sys
MARKER = "/var/lib/winsvpn-proof/deployment-identity.json"
CANDIDATES = "/var/lib/winsvpn-proof/candidates"
ELF_MACHINES = {3: "x86", 62: "x86_64", 183: "aarch64"}

__WINS_FORBIDDEN_COMPONENT_PROBE_LIBRARY__

def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise SystemExit("duplicate JSON key")
        result[key] = value
    return result

def load_expected(raw):
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except Exception:
        raise SystemExit("expected deployment binding is not strict JSON")
    if type(value) is not dict:
        raise SystemExit("expected deployment binding is malformed")
    return value

def read_nofollow(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    before = os.lstat(path)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise SystemExit("deployment identity path is unsafe")
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        chunks = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        finished = os.fstat(fd)
    finally:
        os.close(fd)
    after = os.lstat(path)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_nlink, stat.S_IFMT(item.st_mode))
    if identity(before) != identity(opened) or identity(opened) != identity(finished) or identity(finished) != identity(after):
        raise SystemExit("deployment identity changed while being read")
    data = b"".join(chunks)
    if not data:
        raise SystemExit("deployment identity is empty")
    return data

def elf_identity(data):
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return "text", "text-1"
    machine = int.from_bytes(data[18:20], "little")
    return ELF_MACHINES.get(machine, "other"), "elf-" + str(data[6])

def file_identity(path, *, text):
    data = read_nofollow(path)
    architecture, version = ("text", "text-1") if text else elf_identity(data)
    return {
        "architecture": architecture,
        "bytes": len(data),
        "path": path,
        "sha256": hashlib.sha256(data).hexdigest(),
        "version": version,
    }

def file_runtime(path, applicable):
    if not applicable:
        return {"applicable": False, "bytes": None, "path": None, "sha256": None}
    data = read_nofollow(path)
    return {"applicable": True, "bytes": len(data), "path": path, "sha256": hashlib.sha256(data).hexdigest()}

def active_state(unit):
    result = subprocess.run(
        ["/usr/bin/systemctl", "is-active", unit],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.stdout.decode("ascii").strip()

def list_candidate_files(root, candidate_id):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        parent_fd = os.open(root, flags)
    except OSError:
        raise SystemExit("missing candidate bytes")
    try:
        parent_info = os.fstat(parent_fd)
        names = sorted(os.listdir(root))
        after = os.lstat(root)
        if (parent_info.st_dev, parent_info.st_ino) != (after.st_dev, after.st_ino) or stat.S_ISLNK(after.st_mode):
            raise SystemExit("candidate directory swapped")
    finally:
        os.close(parent_fd)
    if names != [candidate_id]:
        raise SystemExit("extra, missing, or mixed candidate bytes")
    base = os.path.join(root, candidate_id)
    files = []
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        dirnames.sort()
        filenames.sort()
        for name in filenames:
            full = os.path.join(dirpath, name)
            info = os.lstat(full)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise SystemExit("mixed candidate bytes")
            rel = os.path.relpath(full, base)
            data = read_nofollow(full)
            files.append({"bytes": len(data), "path": rel, "sha256": hashlib.sha256(data).hexdigest()})
    if not files:
        raise SystemExit("missing candidate bytes")
    return files

def docker_image_id(image):
    result = subprocess.run(
        ["/usr/bin/docker", "image", "inspect", "--format={{.Id}}", image],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit("unable to inspect AWG image")
    value = result.stdout.decode("ascii").strip()
    if not value or len(value) > 128:
        raise SystemExit("AWG image identity is invalid")
    return value

def tree_sha256(root):
    digest = hashlib.sha256()
    found = False
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        filenames.sort()
        for name in filenames:
            full = os.path.join(dirpath, name)
            info = os.lstat(full)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise SystemExit("python install tree is unsafe")
            rel = os.path.relpath(full, root).encode("utf-8")
            data = read_nofollow(full)
            digest.update(len(rel).to_bytes(8, "big"))
            digest.update(rel)
            digest.update(stat.S_IMODE(info.st_mode).to_bytes(4, "big"))
            digest.update(len(data).to_bytes(8, "big"))
            digest.update(data)
            found = True
    if not found:
        raise SystemExit("python install tree is empty")
    return digest.hexdigest()

def verify_python(expected_runtime):
    if type(expected_runtime) is not dict:
        raise SystemExit("python runtime receipt is malformed")
    exe = os.path.realpath(sys.executable)
    if exe != expected_runtime.get("executable_path"):
        raise SystemExit("python runtime executable was substituted")
    data = read_nofollow(exe)
    if hashlib.sha256(data).hexdigest() != expected_runtime.get("executable_sha256"):
        raise SystemExit("python runtime executable identity is stale")
    archive = read_nofollow(expected_runtime["archive_path"])
    if hashlib.sha256(archive).hexdigest() != expected_runtime.get("archive_sha256"):
        raise SystemExit("python runtime archive identity is stale")
    if tree_sha256(expected_runtime["install_tree_path"]) != expected_runtime.get("install_tree_sha256"):
        raise SystemExit("python runtime tree identity is stale")
    source = read_nofollow(expected_runtime["source_path"])
    if hashlib.sha256(source).hexdigest() != expected_runtime.get("source_sha256"):
        raise SystemExit("python runtime source identity is stale")
    version = "%d.%d.%d" % (sys.version_info[0], sys.version_info[1], sys.version_info[2])
    if sys.implementation.name != expected_runtime.get("implementation") or version != expected_runtime.get("version"):
        raise SystemExit("python runtime identity mismatch")

expected = load_expected(sys.argv[1])
verify_python(expected["python_runtime"])
marker = json.loads(read_nofollow(MARKER).decode("ascii"), object_pairs_hook=pairs)
if type(marker) is not dict:
    raise SystemExit("installation marker is malformed")
for key in ("apply_sha256", "candidate_id", "deployment_manifest_sha256", "fleet_id", "fleet_record_chain_sha256", "instance", "plan_sha256", "role"):
    if marker.get(key) != expected.get(key):
        raise SystemExit("installation marker does not match the bound deployment")
os_lines = read_nofollow("/etc/os-release").decode("ascii").splitlines()
os_map = {}
for line in os_lines:
    if "=" not in line:
        continue
    key, value = line.split("=", 1)
    if key in os_map:
        raise SystemExit("duplicate os-release key")
    os_map[key] = value.strip().strip('"')
role_file_bytes = read_nofollow("/etc/winsvpn/role")
expected_role_bytes = (expected["role"] + "\n").encode("ascii")
if role_file_bytes != expected_role_bytes:
    raise SystemExit("role file bytes do not match the canonical role")
role_file = role_file_bytes.decode("ascii").strip()
services = {name: active_state(name) for name in expected["services"]}
units = {}
for name, path in expected["units"].items():
    identity = file_identity(path, text=True)
    identity["active_state"] = services[name]
    units[name] = identity
configs = {path: file_identity(path, text=True) for path in expected["configs"]}
runtime_paths = expected["runtime_paths"]
awg_role = expected["role"] == "data-cover"
if awg_role:
    awg = {
        "applicable": True,
        "image": expected["awg_image"],
        "image_id": docker_image_id(expected["awg_image"]),
        "provenance_receipt": file_runtime("/var/lib/winsvpn/awg-server-image/provenance.json", True),
    }
else:
    awg = {"applicable": False, "image": None, "image_id": None, "provenance_receipt": None}
forbidden_component_absence = probe_forbidden_component_absence(
    expected["role"], DescriptorSyscallRunner()
)
runtime = {
    "awg": awg,
    "router": expected["router"],
    "winn": file_runtime(runtime_paths["winn"], runtime_paths["winn"] is not None),
    "xray": file_runtime(runtime_paths["xray"], runtime_paths["xray"] is not None),
}
payload = {
    "role": expected["role"],
    "instance": expected["instance"],
    "os_id": os_map.get("ID"),
    "os_version": os_map.get("VERSION_ID"),
    "role_file": role_file,
    "services": services,
    "marker": marker,
    "runtime": runtime,
    "units": units,
    "configs": configs,
    "candidate": {
        "id": expected["candidate_id"],
        "files": list_candidate_files(CANDIDATES, expected["candidate_id"]),
    },
    "forbidden_component_absence": forbidden_component_absence,
}
sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
"""
    profile_source = (
        "FORBIDDEN_COMPONENT_PROFILES = "
        + json.dumps(
            FORBIDDEN_COMPONENT_PROFILES,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
        + _forbidden_component_library_source()
    )
    marker = "__WINS_FORBIDDEN_COMPONENT_PROBE_LIBRARY__"
    if script.count(marker) != 1:
        raise fleet.FleetRefused(
            "forbidden-component probe library insertion point is invalid"
        )
    return script.replace(marker, profile_source).lstrip()


def verified_deployment_execution(args: argparse.Namespace) -> dict[str, Any]:
    path = Path(args.deployment_execution)
    if not path.is_absolute() or path.name != fleet.EXECUTION_NAME:
        raise fleet.FleetRefused("deployment execution receipt path is invalid")
    raw, digest = fleet.load_json_document(path, require_immutable=True)
    if digest != args.deployment_execution_sha256:
        raise fleet.FleetRefused("deployment execution receipt digest does not match argv")
    status = fleet.require_str("deployment execution status", raw.get("status"))
    if status != "passed":
        raise fleet.FleetRefused("live probe requires a passed deployment execution receipt")
    if (
        raw.get("kind") != fleet.KIND_EXECUTION
        or fleet.require_int("deployment execution schema", raw.get("schema_version"))
        != fleet.EXECUTION_SCHEMA_VERSION
    ):
        raise fleet.FleetRefused("deployment execution receipt kind/schema is invalid")
    exact_keys = {
        "fleet_id": args.fleet_id,
        "deployment_manifest_sha256": args.deployment_manifest_sha256,
        "record_chain_sha256": args.deployment_record_chain_sha256,
    }
    for key, expected in exact_keys.items():
        if raw.get(key) != expected:
            raise fleet.FleetRefused(
                "deployment execution receipt does not match the bound fleet identity"
            )
    markers = raw.get("markers")
    if not isinstance(markers, dict) or set(markers) != set(fleet.ROLES):
        raise fleet.FleetRefused("deployment execution markers are missing or mixed")
    for role, marker in markers.items():
        if not isinstance(marker, dict):
            raise fleet.FleetRefused("deployment execution marker is malformed")
        if marker.get("candidate_id") != args.deployment_candidate_id:
            raise fleet.FleetRefused("deployment candidate id does not match the bound receipt")
        if marker.get("fleet_id") != args.fleet_id:
            raise fleet.FleetRefused("deployment marker fleet identity mismatch")
        if marker.get("fleet_record_chain_sha256") != args.deployment_record_chain_sha256:
            raise fleet.FleetRefused("deployment record chain does not match the bound receipt")
        if marker.get("deployment_manifest_sha256") != args.deployment_manifest_sha256:
            raise fleet.FleetRefused("deployment manifest digest does not match the bound receipt")
        if marker.get("role") != role:
            raise fleet.FleetRefused("deployment marker role is mixed")
    return raw


def deployment(args: argparse.Namespace, runner: Runner) -> dict[str, Any]:
    execution = verified_deployment_execution(args)
    rows = []
    for role in _role_specs(args):
        marker = execution["markers"][role["role"]]
        expected = {
            "apply_sha256": marker["apply_sha256"],
            "awg_image": marker["runtime"]["awg"]["image"],
            "awg_image_id": marker["runtime"]["awg"]["image_id"],
            "candidate_id": args.deployment_candidate_id,
            "configs": list(fleet.ROLE_DEPLOY_CONFIGS[role["role"]]),
            "deployment_manifest_sha256": args.deployment_manifest_sha256,
            "fleet_id": args.fleet_id,
            "fleet_record_chain_sha256": args.deployment_record_chain_sha256,
            "instance": role["instance"],
            "plan_sha256": marker["plan_sha256"],
            "role": role["role"],
            "python_runtime": require_remote_python_runtime(args),
            "router": marker["runtime"]["router"],
            "runtime_paths": fleet.ROLE_RUNTIME_BINARIES[role["role"]],
            "services": fleet.ROLE_DEPLOY_SERVICES[role["role"]],
            "units": fleet.ROLE_DEPLOY_UNITS[role["role"]],
        }
        remote_argv = [
            *REMOTE_SUDO_ARGV,
            *remote_python_argv(
                expected["python_runtime"],
                _deployment_script(),
                json.dumps(expected, separators=(",", ":"), sort_keys=True),
            ),
        ]
        raw = _json_result(
            runner,
            _gcloud(
                args,
                "compute",
                "ssh",
                role["instance"],
                f"--zone={role['zone']}",
                "--quiet",
                "--command=" + shlex.join(remote_argv),
            ),
            label="deployment observation",
        )
        if not isinstance(raw, dict):
            raise fleet.FleetRefused("deployment observation is malformed")
        if (
            "forbidden_component_absence" not in raw
            and (
                getattr(type(runner), "TEST_ONLY", False) is True
                or getattr(runner, "TEST_ONLY", False) is True
            )
        ):
            # Legacy unit fixtures echo the frozen collector row and do not
            # execute the embedded VM observer. Such runners are rejected by
            # the production custody path and cannot emit a production pass.
            row = dict(raw)
        else:
            row = strip_validated_forbidden_component_absence(role["role"], raw)
        rows.append(row)
    observed = {"roles": rows}
    for row, role in zip(observed["roles"], _role_specs(args)):
        if row.get("role") != role["role"] or row.get("instance") != role["instance"]:
            raise fleet.FleetRefused("deployment observation role/instance mismatch")
        if row.get("marker") != execution["markers"][role["role"]]:
            raise fleet.FleetRefused("live installation marker does not match the execution receipt")
        if row.get("runtime") != execution["markers"][role["role"]]["runtime"]:
            raise fleet.FleetRefused("live runtime identity does not match the execution receipt")
        if row.get("candidate", {}).get("id") != args.deployment_candidate_id:
            raise fleet.FleetRefused("live candidate identity does not match the execution receipt")
    return observed


def _proof_resource_inventory(
    args: argparse.Namespace, runner: Runner
) -> dict[str, Any]:
    queries = (
        (
            "instances",
            _gcloud(
                args,
                "compute",
                "instances",
                "list",
                "--filter=labels.winsvpn-proof-fleet=1",
                "--format=json(name,labels,zone)",
            ),
        ),
        (
            "networks",
            _gcloud(
                args,
                "compute",
                "networks",
                "list",
                "--filter=name~'^pf-'",
                "--format=json(name)",
            ),
        ),
        (
            "subnets",
            _gcloud(
                args,
                "compute",
                "networks",
                "subnets",
                "list",
                "--filter=name~'^pf-'",
                "--format=json(name)",
            ),
        ),
        (
            "firewalls",
            _gcloud(
                args,
                "compute",
                "firewall-rules",
                "list",
                "--filter=name~'^pf-'",
                "--format=json(name)",
            ),
        ),
    )
    rows_by_kind: dict[str, list[dict[str, Any]]] = {}
    for kind, argv in queries:
        raw = _json_result(runner, argv, label=f"teardown {kind} inventory")
        if not isinstance(raw, list) or any(not isinstance(row, dict) for row in raw):
            raise fleet.FleetRefused(f"teardown {kind} inventory is malformed")
        rows = [dict(row) for row in raw]
        names = [row.get("name") for row in rows]
        if any(not isinstance(name, str) or not name for name in names) or len(
            set(names)
        ) != len(names):
            raise fleet.FleetRefused(
                f"teardown {kind} inventory names are invalid or duplicated"
            )
        rows_by_kind[kind] = rows

    canonical = _canonical_resources(args)
    expected = {
        "instances": [
            args.control_instance,
            args.winn3_data_instance,
            args.cover_data_instance,
        ],
        "network": canonical["network"],
        "subnets": [item["name"] for item in canonical["subnets"]],
        "firewalls": sorted(canonical["firewalls"].values()),
    }
    expected_instance_roles = {
        args.control_instance: ("control", args.control_zone),
        args.winn3_data_instance: ("data-winn3", args.winn3_data_zone),
        args.cover_data_instance: ("data-cover", args.cover_data_zone),
    }
    observed_instances: list[str] = []
    foreign: list[str] = []
    for row in rows_by_kind["instances"]:
        name = str(row["name"])
        expected_role = expected_instance_roles.get(name)
        if expected_role is None:
            foreign.append(f"instance:{name}")
            continue
        labels = row.get("labels")
        if (
            not isinstance(labels, dict)
            or labels.get("winsvpn-proof-fleet") != "1"
            or labels.get("winsvpn-proof-id") != args.fleet_id
            or labels.get("winsvpn-proof-role") != expected_role[0]
            or _basename(row.get("zone"), "teardown instance zone")
            != expected_role[1]
        ):
            raise fleet.FleetRefused(
                "teardown instance inventory identity does not match the fleet"
            )
        observed_instances.append(name)

    current_names = {
        "networks": {expected["network"]},
        "subnets": set(expected["subnets"]),
        "firewalls": set(expected["firewalls"]),
    }
    observed: dict[str, Any] = {
        "instances": [
            name for name in expected["instances"] if name in observed_instances
        ],
        "network": "",
        "subnets": [],
        "firewalls": [],
    }
    unexpected: list[str] = []
    for kind in ("networks", "subnets", "firewalls"):
        names = {str(row["name"]) for row in rows_by_kind[kind]}
        matches = sorted(names.intersection(current_names[kind]))
        if kind == "networks":
            observed["network"] = matches[0] if len(matches) == 1 else ""
        else:
            observed[kind] = matches
        for name in sorted(names - current_names[kind]):
            foreign.append(f"{kind[:-1]}:{name}")
        for name in sorted(
            name
            for name in names
            if name.startswith(f"pf-{args.fleet_id}-")
            and name not in current_names[kind]
        ):
            unexpected.append(f"{kind[:-1]}:{name}")
    return {
        "expected_resources": expected,
        "observed_resources": observed,
        "unexpected_targets": sorted(unexpected),
        "foreign_resource_ids": sorted(foreign),
    }


def client_action(args: argparse.Namespace, runner: Runner) -> dict[str, Any]:
    client = Path(args.client_artifact)
    before_reference = verified_client_release(args)
    before = before_reference["binding"]["artifact"]
    proof_build = before_reference["binding"]["proof_build"]
    identity = _json_result(
        runner,
        [str(client), "--winsvpn-proof-identity"],
        label="proof client compiled identity",
    )
    expected_identity = {
        "schema_version": 1,
        "contract": "winsvpn-gcp-proof-client-identity-v1",
        "release": before_reference["binding"]["release"],
        "shared_revision": before_reference["binding"]["shared_revision"],
        "source_sha256": proof_build["source"]["sha256"],
        "build_contract_sha256": proof_build["build_contract"]["sha256"],
        "toolchain_version": "go" + proof_build["toolchain"]["version"],
        "target": (
            proof_build["target"]["goos"]
            + "/"
            + proof_build["target"]["goarch"]
        ),
        "build_identity": proof_build["build_identity"],
    }
    if identity != expected_identity:
        raise fleet.FleetRefused(
            "proof executable runtime identity does not match its bound build receipt"
        )
    argv = [
        str(client),
        "--winsvpn-proof-action",
        args.action,
        "--project",
        args.project,
        "--gcloud-bin",
        args.gcloud_bin,
        "--fleet-id",
        args.fleet_id,
        "--control-instance",
        args.control_instance,
        "--control-zone",
        args.control_zone,
        "--winn3-data-instance",
        args.winn3_data_instance,
        "--winn3-data-zone",
        args.winn3_data_zone,
        "--cover-data-instance",
        args.cover_data_instance,
        "--cover-data-zone",
        args.cover_data_zone,
        "--run-id",
        args.run_id,
        "--session-id",
        args.session_id,
        "--correlation-id",
        args.correlation_id,
        *_credential_argv(args),
    ]
    raw = _json_result(runner, argv, label=f"client action {args.action}")
    after_reference = verified_client_release(args)
    if after_reference != before_reference:
        raise fleet.FleetRefused("proof client release binding changed during action")
    if not isinstance(raw, dict):
        raise fleet.FleetRefused("proof client action must return a JSON object")
    if args.action == "teardown-check":
        independent = _proof_resource_inventory(args, runner)
        for key, value in independent.items():
            if raw.get(key) != value:
                raise fleet.FleetRefused(
                    "proof client teardown does not match independent project inventory"
                )
        raw = {
            **independent,
            "credential_files_read": raw.get("credential_files_read"),
            "production_resources_touched": raw.get(
                "production_resources_touched"
            ),
        }
    fleet._assert_no_pass_tokens(raw)
    return dict(raw)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--action", required=True, choices=fleet.COLLECTOR_ACTIONS)
    for name in (
        "fleet-id", "run-id", "session-id", "correlation-id",
        "client-repo-root", "client-release-input-index",
        "client-release-input-index-sha256", "client-build-receipt",
        "client-build-receipt-sha256", "client-artifact", "client-sha256",
        "client-build-identity", "client-release", "client-shared-revision",
        "client-artifact-input-fingerprint-sha256", "client-binding-sha256",
        "client-binding-reference-sha256",
        "deployment-execution", "deployment-execution-sha256",
        "deployment-candidate-id", "deployment-manifest-sha256",
        "deployment-record-chain-sha256",
        "project",
        "gcloud-bin", "image-family", "image-project", "network", "fleet-tag",
        "control-instance", "control-zone", "control-machine-type", "control-subnet",
        "winn3-data-instance", "winn3-data-zone", "winn3-data-machine-type", "winn3-data-subnet",
        "cover-data-instance", "cover-data-zone", "cover-data-machine-type", "cover-data-subnet",
        "credential-kind", "credential-path", "credential-account", "credential-project",
        "python-runtime-receipt", "remote-python-runtime-receipt",
    ):
        required = name not in {
            "credential-kind",
            "credential-path",
            "credential-account",
            "credential-project",
            "python-runtime-receipt",
            "remote-python-runtime-receipt",
        }
        result.add_argument(f"--{name}", required=required)
    result.add_argument("--client-bytes", required=True, type=int)
    return result


def main(argv: list[str] | None = None, *, runner: Runner | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        client_release_reference = verified_client_release(args)
        verified_deployment_execution(args)
        expected_fleet_id = fleet.sha256_bytes(
            fleet.canonical_bytes(
                {
                    "project": args.project,
                    "instances": [
                        {"role": row["role"], "name": row["instance"]}
                        for row in _role_specs(args)
                    ],
                }
            )
        )[:12]
        if args.fleet_id != expected_fleet_id:
            raise fleet.FleetRefused("fleet id does not match project and instances")
        active_runner: Runner = runner or SubprocessRunner()
        if type(active_runner) is SubprocessRunner:
            active_runner, args.gcloud_bin = bind_live_production_runner(
                active_runner, args.gcloud_bin, args=args
            )
        elif getattr(type(active_runner), "TEST_ONLY", False) is True or getattr(active_runner, "TEST_ONLY", False) is True:
            pass
        else:
            raise fleet.FleetRefused(gcloud_custody.ARBITRARY_RUNNER)
        verify_gcloud_version(active_runner, args.gcloud_bin)
        if args.action == "inventory":
            data = inventory(args, active_runner)
        elif args.action == "deployment":
            data = deployment(args, active_runner)
        else:
            data = client_action(args, active_runner)
        bindings = {
            "fleet_id": args.fleet_id,
            "run_id": args.run_id,
            "session_id": args.session_id,
            "correlation_id": args.correlation_id,
            "client_artifact": {
                "path": args.client_artifact,
                "sha256": args.client_sha256,
                "bytes": args.client_bytes,
            },
            "client_build_identity": args.client_build_identity,
            "client_release_binding": client_release_reference,
        }
        payload = fleet.observation_envelope(args.action, bindings, data)
        fleet._assert_no_pass_tokens(payload)
        sys.stdout.buffer.write(fleet.canonical_bytes(payload))
        return 0
    except fleet.FleetRefused as exc:
        print(str(exc), file=sys.stderr)
        return fleet.REFUSAL_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
