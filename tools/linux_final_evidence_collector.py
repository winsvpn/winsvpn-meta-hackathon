#!/usr/bin/env python3
"""Collect the final Linux release matrix from a real installed application.

The collector owns observation and receipt production.  A small root-owned
desktop driver performs UI actions through a fixed argv protocol; it cannot
submit pass booleans or receipt files.  Network, process, route, payload,
traffic, leak, teardown, rollback, and screenshot hashes are observed here.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Any, Protocol

from public_release_live_smoke_common import (
    build_receipt_binding,
    producer_contract_hash,
    release_input_binding,
)


CONTRACT = "winsvpn-linux-final-evidence-collector-v1"
MACHINE_CONTRACT = "winsvpn-linux-apple-release-machine-evidence-v1"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
INVALID_OBSERVATION_DIGESTS = {EMPTY_SHA256, "0" * 64}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
LANE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,79}$")
CANARIES = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
)
INSTALLED_DRIVER = pathlib.Path("/usr/local/libexec/winsvpn-release-ui-driver.py")
INSTALLED_SPLIT_CANARY = pathlib.Path(
    "/usr/local/libexec/winsvpn-release-split-canary.sh"
)
LINUX_PUBLIC_PRODUCER = "tools/linux_public_release_live_smoke.sh"


class CollectorError(RuntimeError):
    pass


def is_reparse_point(info: os.stat_result) -> bool:
    """Return true for a Windows reparse point without weakening POSIX checks."""
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def reject_reparse_components(path: pathlib.Path, label: str, *, must_exist: bool) -> pathlib.Path:
    """Reject symlink/reparse traversal before resolving an immutable input."""
    expanded = path.expanduser()
    absolute = expanded if expanded.is_absolute() else pathlib.Path.cwd() / expanded
    current = pathlib.Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if not current.exists() and not current.is_symlink():
            if must_exist:
                raise CollectorError(f"{label} does not exist")
            continue
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or is_reparse_point(info):
            raise CollectorError(f"{label} must not traverse a symlink/reparse point")
    if must_exist:
        if not absolute.is_file() or absolute.is_symlink():
            raise CollectorError(f"{label} must be a regular file")
    return absolute.resolve(strict=must_exist)


def require_linux_root(os_name: str, euid: int | None, proc_net_dev: pathlib.Path) -> None:
    """Fail before any production collection unless the caller is Linux root."""
    if os_name != "posix" or not proc_net_dev.is_file():
        raise CollectorError("Linux final evidence collection must run on Linux")
    if euid != 0:
        raise CollectorError("Linux final evidence collection must run as root")


def require_installed_tool(
    installed: pathlib.Path, source: pathlib.Path, label: str
) -> pathlib.Path:
    """Bind a root-installed executable to its exact repository source bytes."""
    target = reject_reparse_components(installed, label, must_exist=True)
    expected = reject_reparse_components(source, f"{label} source", must_exist=True)
    info = target.stat()
    validate_installed_tool_binding(
        uid=info.st_uid,
        mode=stat.S_IMODE(info.st_mode),
        executable=os.access(target, os.X_OK),
        installed_sha256=sha256_file(target),
        source_sha256=sha256_file(expected),
        label=label,
    )
    return target


def validate_installed_tool_binding(
    *,
    uid: int,
    mode: int,
    executable: bool,
    installed_sha256: str,
    source_sha256: str,
    label: str,
) -> None:
    """Pure metadata/hash gate used by the production installed-tool check."""
    if uid != 0 or mode != 0o755:
        raise CollectorError(f"{label} must be root-owned with mode 0755")
    if not executable:
        raise CollectorError(f"{label} must be executable")
    if installed_sha256 != source_sha256:
        raise CollectorError(f"{label} does not match the repository release-tool bytes")


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_owner_file(
    path: pathlib.Path,
    *,
    expected_uid: int,
    expected_mode: int = 0o600,
    label: str,
) -> bytes:
    try:
        link_info = path.lstat()
    except FileNotFoundError as exc:
        raise CollectorError(f"{label} does not exist") from exc
    if stat.S_ISLNK(link_info.st_mode) or is_reparse_point(link_info):
        raise CollectorError(f"{label} must not be a symlink/reparse point")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CollectorError(f"{label} could not be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or stat.S_IMODE(before.st_mode) != expected_mode
        ):
            raise CollectorError(f"{label} ownership/type/mode is invalid")
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size):
            raise CollectorError(f"{label} changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _indexed_file(path: pathlib.Path, contract: str) -> dict[str, Any]:
    return {
        "path": path.name,
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
        "contract": contract,
    }


def validate_owner_only_linux_bundle(
    bundle: pathlib.Path,
    *,
    repo: pathlib.Path,
    expected_uid: int = 0,
) -> tuple[pathlib.Path, pathlib.Path, str]:
    bundle = reject_reparse_components(bundle, "Linux collector bundle", must_exist=False)
    try:
        info = bundle.lstat()
    except FileNotFoundError as exc:
        raise CollectorError("Linux collector bundle does not exist") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or is_reparse_point(info)
        or info.st_uid != expected_uid
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise CollectorError("Linux collector bundle must be a root-owned 0700 directory")

    index_path = bundle / "EVIDENCE_INDEX.json"
    index_bytes = _read_owner_file(
        index_path, expected_uid=expected_uid, label="Linux collector index"
    )
    try:
        index = json.loads(index_bytes.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CollectorError("Linux collector index must be UTF-8 JSON") from exc
    fields = {
        "schema_version", "contract", "run_id", "machine_evidence",
        "map_screenshot", "receipt_files", "installed_payload",
        "frozen_artifact", "release_input_index_sha256",
        "platform_manifest_sha256", "artifact_input_fingerprint_sha256",
        "build_receipt_sha256", "producer_contract_sha256",
        "secret_material_redacted",
    }
    if not isinstance(index, dict) or set(index) != fields:
        raise CollectorError("Linux collector index fields are invalid")
    if (
        index["schema_version"] != 2
        or index["contract"] != "winsvpn-linux-final-evidence-index-v2"
        or index["secret_material_redacted"] is not True
    ):
        raise CollectorError("Linux collector index contract/version is invalid")
    try:
        parsed_run_id = uuid.UUID(str(index["run_id"]))
    except ValueError as exc:
        raise CollectorError("Linux collector index run_id is invalid") from exc
    if parsed_run_id.int == 0:
        raise CollectorError("Linux collector index run_id is empty")
    for field in (
        "release_input_index_sha256", "platform_manifest_sha256",
        "artifact_input_fingerprint_sha256", "build_receipt_sha256",
        "producer_contract_sha256",
    ):
        require_sha256(index[field], field)
    if index["producer_contract_sha256"] != producer_contract_hash(repo, LINUX_PUBLIC_PRODUCER):
        raise CollectorError("Linux collector index was produced under a stale producer closure")

    expected_names = {"EVIDENCE_INDEX.json"}

    def verify_entry(raw: Any, expected_contract: str, label: str) -> tuple[pathlib.Path, bytes]:
        entry = require_exact(raw, {"path", "sha256", "size_bytes", "contract"}, label)
        name = str(entry["path"])
        relative = pathlib.Path(name)
        if relative.is_absolute() or ".." in relative.parts or relative.name != name:
            raise CollectorError(f"{label} path is invalid")
        if entry["contract"] != expected_contract:
            raise CollectorError(f"{label} contract is invalid")
        path = bundle / name
        data = _read_owner_file(path, expected_uid=expected_uid, label=label)
        if require_sha256(entry["sha256"], f"{label} sha256") != sha256_bytes(data):
            raise CollectorError(f"{label} hash does not match")
        if isinstance(entry["size_bytes"], bool) or entry["size_bytes"] != len(data):
            raise CollectorError(f"{label} size does not match")
        expected_names.add(name)
        return path, data

    machine_path, machine_bytes = verify_entry(
        index["machine_evidence"], MACHINE_CONTRACT, "Linux machine evidence"
    )
    map_path, _ = verify_entry(
        index["map_screenshot"], "winsvpn-linux-map-screenshot-v1", "Linux map screenshot"
    )
    _, payload_bytes = verify_entry(
        index["installed_payload"], "winsvpn-linux-installed-payload-v1", "Linux installed payload"
    )
    frozen_path, frozen_bytes = verify_entry(
        index["frozen_artifact"], "winsvpn-linux-frozen-artifact-v1", "Linux frozen artifact"
    )
    receipts = index["receipt_files"]
    if not isinstance(receipts, dict) or not receipts:
        raise CollectorError("Linux collector index does not bind receipts")
    for name, entry in receipts.items():
        if not isinstance(entry, dict) or entry.get("path") != name:
            raise CollectorError("Linux receipt index path is inconsistent")
        contract = str(entry.get("contract", ""))
        if not contract.startswith("winsvpn-"):
            raise CollectorError("Linux receipt contract is invalid")
        _, receipt_bytes = verify_entry(entry, contract, f"Linux receipt {name}")
        try:
            receipt_value = json.loads(receipt_bytes.decode("utf-8-sig"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise CollectorError(f"Linux receipt {name} must be UTF-8 JSON") from exc
        if not isinstance(receipt_value, dict) or receipt_value.get("contract") != contract:
            raise CollectorError(f"Linux receipt {name} embedded contract is inconsistent")
    if {item.name for item in bundle.iterdir()} != expected_names:
        raise CollectorError("Linux collector bundle contains unindexed files")
    try:
        machine = json.loads(machine_bytes.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CollectorError("Linux machine evidence must be UTF-8 JSON") from exc
    if machine.get("run_id") != index["run_id"]:
        raise CollectorError("Linux collector run_id does not match machine evidence")
    if (
        machine.get("contract") != MACHINE_CONTRACT
        or machine.get("platform") != "linux"
        or machine.get("secret_material_redacted") is not True
    ):
        raise CollectorError("Linux machine evidence contract/platform/redaction is invalid")
    try:
        payload_value = json.loads(payload_bytes.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CollectorError("Linux installed payload must be UTF-8 JSON") from exc
    if (
        not isinstance(payload_value, dict)
        or payload_value.get("contract") != "winsvpn-linux-installed-payload-v1"
        or payload_value.get("secret_material_redacted") is not True
    ):
        raise CollectorError("Linux installed payload contract/redaction is invalid")
    if machine.get("artifact_sha256") != sha256_bytes(frozen_bytes):
        raise CollectorError("Linux collector artifact binding is inconsistent")
    for field in (
        "release_input_index_sha256", "platform_manifest_sha256",
        "artifact_input_fingerprint_sha256", "build_receipt_sha256",
        "producer_contract_sha256",
    ):
        if machine.get(field) != index[field]:
            raise CollectorError(f"Linux collector binding is inconsistent: {field}")
    return machine_path, map_path, sha256_bytes(index_bytes)


def require_exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        actual = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise CollectorError(f"{label} fields are invalid: {actual}")
    return value


def require_true(value: Any, label: str) -> None:
    if value is not True:
        raise CollectorError(f"{label} must be true")


def require_sha256(value: Any, label: str) -> str:
    text = str(value)
    if not SHA256_RE.fullmatch(text):
        raise CollectorError(f"{label} must be a lowercase SHA-256 digest")
    return text


def parse_json_stdout(output: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(output)
    except json.JSONDecodeError as exc:
        raise CollectorError(f"{label} did not return one JSON object") from exc
    if not isinstance(value, dict):
        raise CollectorError(f"{label} did not return one JSON object")
    return value


def atomic_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    # pathlib.Path.write_text() did not accept ``newline`` until Python 3.10.
    # The collector is also exercised by the Python 3.9 bundled with Xcode, so
    # use the long-supported open() spelling while retaining deterministic LF.
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


class DriverProtocol(Protocol):
    def call(self, action: str, **values: str) -> dict[str, Any]: ...

    def expect_failure(self, action: str, **values: str) -> int: ...


class DesktopDriver:
    """Fixed argv interface to the platform-specific Linux UI driver."""

    def __init__(self, executable: pathlib.Path, timeout_seconds: int) -> None:
        if executable.is_symlink():
            raise CollectorError("Linux release driver must not be a symlink")
        path = executable.resolve(strict=True)
        info = path.stat()
        if not path.is_file() or path.is_symlink():
            raise CollectorError("Linux release driver must be a regular file")
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise CollectorError("Linux release driver must be root-owned and not group/world writable")
        if not os.access(path, os.X_OK):
            raise CollectorError("Linux release driver is not executable")
        self.path = path
        self.timeout_seconds = timeout_seconds

    def _argv(self, action: str, values: dict[str, str]) -> list[str]:
        if not re.fullmatch(r"[a-z][a-z0-9_-]{2,40}", action):
            raise CollectorError("Linux driver action is invalid")
        argv = [str(self.path), "--action", action]
        for key in sorted(values):
            if not re.fullmatch(r"[a-z][a-z0-9_-]{1,40}", key):
                raise CollectorError("Linux driver argument name is invalid")
            argv.extend((f"--{key.replace('_', '-')}", str(values[key])))
        return argv

    def _run(self, action: str, values: dict[str, str], *, check: bool) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            self._argv(action, values),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=self.timeout_seconds,
            check=False,
        )
        if check and result.returncode != 0:
            raise CollectorError(f"Linux driver action {action} failed with exit {result.returncode}")
        return result

    def call(self, action: str, **values: str) -> dict[str, Any]:
        result = self._run(action, values, check=True)
        return parse_json_stdout(result.stdout, f"Linux driver {action}")

    def expect_failure(self, action: str, **values: str) -> int:
        result = self._run(action, values, check=False)
        if result.returncode == 0:
            raise CollectorError(f"Injected failure did not make driver action {action} fail")
        return result.returncode


@dataclass(frozen=True)
class LaneObservation:
    rx_delta_bytes: int
    tx_delta_bytes: int
    protected_egress_sha256: str
    provider_executable_sha256: str
    dns_protected: bool
    ipv4_protected: bool
    ipv6_escape_blocked: bool
    public_canaries_agree: bool


class LinuxProbe:
    def __init__(self, tools_dir: pathlib.Path, timeout_seconds: int) -> None:
        self.tools_dir = tools_dir
        self.timeout_seconds = timeout_seconds

    def run(
        self,
        argv: list[str],
        *,
        env: dict[str, str] | None = None,
        check: bool = True,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            argv,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=timeout or self.timeout_seconds,
            check=False,
        )
        if check and result.returncode != 0:
            raise CollectorError(f"Machine probe failed ({argv[0]} exit {result.returncode})")
        return result

    def state_hash(self) -> str:
        observations: list[tuple[str, str]] = []
        commands = (
            ("link", ["ip", "-details", "-json", "link", "show"]),
            ("rule4", ["ip", "-4", "-json", "rule", "show"]),
            ("route4", ["ip", "-4", "-json", "route", "show", "table", "all"]),
            ("iptables", ["iptables-save"]),
            ("ip6tables", ["ip6tables-save"]),
        )
        for name, argv in commands:
            result = self.run(argv)
            observations.append((name, result.stdout))
        runtime: list[dict[str, Any]] = []
        for root in (pathlib.Path("/run/wins-vpn"), pathlib.Path("/run/wins-vpn-xray")):
            if not root.exists():
                continue
            for path in sorted(root.rglob("*")):
                info = path.lstat()
                relative = path.as_posix()
                if path.is_symlink():
                    raise CollectorError(f"Runtime state unexpectedly contains a symlink: {relative}")
                item: dict[str, Any] = {
                    "path": relative,
                    "mode": f"{stat.S_IMODE(info.st_mode):04o}",
                    "kind": "directory" if path.is_dir() else "file",
                }
                if path.is_file():
                    item["sha256"] = sha256_file(path)
                runtime.append(item)
        installed_controls: list[dict[str, Any]] = []
        for path in (
            pathlib.Path("/opt/wins-vpn/wins_vpn"),
            pathlib.Path("/opt/wins-vpn/awg"),
            pathlib.Path("/opt/wins-vpn/awg-quick"),
            pathlib.Path("/opt/wins-vpn/amneziawg-go"),
            pathlib.Path("/opt/wins-vpn/xray"),
        ):
            if not path.is_file() or path.is_symlink():
                raise CollectorError(f"Installed control executable is missing or unsafe: {path.name}")
            info = path.stat()
            installed_controls.append(
                {
                    "path": path.as_posix(),
                    "mode": f"{stat.S_IMODE(info.st_mode):04o}",
                    "uid": info.st_uid,
                    "gid": info.st_gid,
                    "sha256": sha256_file(path),
                }
            )
        canonical = json.dumps(
            {
                "commands": observations,
                "runtime": runtime,
                "installed_controls": installed_controls,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        return sha256_text(canonical)

    def interface_state_hash(self, interface: str) -> str:
        link = self.run(
            ["ip", "-details", "-json", "link", "show", "dev", interface]
        ).stdout
        address = self.run(
            ["ip", "-json", "address", "show", "dev", interface]
        ).stdout
        return sha256_text(
            json.dumps(
                {"link": json.loads(link), "address": json.loads(address)},
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )

    def installed_payload_report(
        self, artifact: pathlib.Path, output: pathlib.Path
    ) -> dict[str, Any]:
        self.run(
            [
                sys.executable,
                str(self.tools_dir / "linux_installed_artifact_manifest.py"),
                "--artifact",
                str(artifact),
                "--installed-root",
                "/opt/wins-vpn",
                "--output",
                str(output),
            ]
        )
        return parse_json_stdout(output.read_text(encoding="utf-8"), "installed payload report")

    @staticmethod
    def _tun_counters() -> tuple[int, int]:
        for line in pathlib.Path("/proc/net/dev").read_text(encoding="utf-8").splitlines():
            if re.match(r"^\s*winsvpn:", line):
                values = line.split(":", 1)[1].split()
                return int(values[0]), int(values[8])
        raise CollectorError("winsvpn interface counters are unavailable")

    def _provider_hash(self, is_xray: bool) -> str:
        if is_xray:
            pid_text = pathlib.Path("/run/wins-vpn-xray/xray.pid").read_text().strip()
            if not pid_text.isdigit() or int(pid_text) <= 1:
                raise CollectorError("Xray PID is invalid")
            executable = pathlib.Path(f"/proc/{pid_text}/exe").resolve(strict=True)
            if executable != pathlib.Path("/opt/wins-vpn/xray"):
                raise CollectorError("Xray provider executable identity is wrong")
            return sha256_file(executable)
        matches: list[pathlib.Path] = []
        for proc in pathlib.Path("/proc").iterdir():
            if not proc.name.isdigit():
                continue
            try:
                executable = (proc / "exe").resolve(strict=True)
            except (FileNotFoundError, PermissionError):
                continue
            if executable == pathlib.Path("/opt/wins-vpn/amneziawg-go"):
                matches.append(executable)
        if len(matches) != 1:
            raise CollectorError("Expected exactly one pinned AmneziaWG provider process")
        return sha256_file(matches[0])

    def _verify_route(
        self, is_xray: bool, port: int, security: str, direct_port: int
    ) -> None:
        route = self.run(["ip", "-4", "route", "get", "1.1.1.1"]).stdout
        if not re.search(r"\bdev winsvpn(?:\s|$)", route):
            raise CollectorError("Ordinary IPv4 route is not protected")
        if is_xray:
            env = dict(os.environ)
            env["WINS_EXPECT_XRAY_PORT"] = str(port)
            env["WINS_EXPECT_XRAY_SECURITY"] = security
            env["WINS_EXPECT_AWG_DESTINATION_PORT"] = str(direct_port)
            self.run(["bash", str(self.tools_dir / "linux_live_tunnel_assertions.sh")], env=env)
        else:
            endpoint_output = self.run(
                ["/opt/wins-vpn/awg", "show", "winsvpn", "endpoints"]
            ).stdout.strip()
            endpoint = endpoint_output.split()[-1] if endpoint_output else ""
            match = re.search(r":([0-9]{1,5})$", endpoint)
            if not match or int(match.group(1)) != port:
                raise CollectorError("Direct AmneziaWG peer does not match the live runtime port")
            if pathlib.Path("/run/wins-vpn-xray/xray.pid").exists():
                raise CollectorError("Direct lane unexpectedly has an Xray provider")

    def observe_lane(
        self, *, is_xray: bool, port: int, security: str, direct_port: int
    ) -> LaneObservation:
        before_rx, before_tx = self._tun_counters()
        self._verify_route(is_xray, port, security, direct_port)
        values: list[str] = []
        for url in CANARIES:
            value = self.run(
                [
                    "curl", "--proto", "=https", "--tlsv1.2", "-4fsS",
                    "--interface", "winsvpn", "--max-time", "12", url,
                ],
                timeout=20,
            ).stdout.strip()
            try:
                address = ipaddress.ip_address(value)
            except ValueError as exc:
                raise CollectorError("Protected egress canary returned an invalid IP") from exc
            if address.version != 4:
                raise CollectorError("Protected egress canary did not return IPv4")
            values.append(value)
        if len(set(values)) != 1:
            raise CollectorError("Protected egress canaries disagree")
        after_rx, after_tx = self._tun_counters()
        rx_delta = after_rx - before_rx
        tx_delta = after_tx - before_tx
        if rx_delta < 96 or tx_delta < 96:
            raise CollectorError("Lane lacks bidirectional protected traffic")
        dns = self.run(["resolvectl", "status", "winsvpn"]).stdout
        if "DNS Servers: 10.8.1.1" not in dns:
            raise CollectorError("Tunnel DNS is not pinned to 10.8.1.1")
        ipv6 = self.run(
            [
                "curl", "--proto", "=https", "--tlsv1.2", "-6fsS",
                "--max-time", "5", "https://api64.ipify.org",
            ],
            check=False,
            timeout=10,
        )
        if ipv6.returncode == 0:
            raise CollectorError("Public IPv6 escaped the IPv4-only tunnel")
        return LaneObservation(
            rx_delta_bytes=rx_delta,
            tx_delta_bytes=tx_delta,
            protected_egress_sha256=sha256_text(values[0]),
            provider_executable_sha256=self._provider_hash(is_xray),
            dns_protected=True,
            ipv4_protected=True,
            ipv6_escape_blocked=True,
            public_canaries_agree=True,
        )

    def split_assertions(self) -> None:
        self.run(["bash", str(self.tools_dir / "linux_live_split_assertions.sh")])

    def teardown_assertions(self) -> None:
        self.run(["bash", str(self.tools_dir / "linux_live_tunnel_teardown_assertions.sh")])

    def wait_for_lane(
        self,
        *,
        is_xray: bool,
        port: int,
        security: str,
        direct_port: int,
        timeout_seconds: int = 120,
    ) -> LaneObservation:
        deadline = time.monotonic() + timeout_seconds
        last_error = ""
        while time.monotonic() < deadline:
            try:
                return self.observe_lane(
                    is_xray=is_xray,
                    port=port,
                    security=security,
                    direct_port=direct_port,
                )
            except (CollectorError, FileNotFoundError) as exc:
                last_error = str(exc)
                time.sleep(3)
        raise CollectorError(f"Tunnel did not recover after harness network change: {last_error}")


class Collector:
    def __init__(
        self,
        *,
        driver: DriverProtocol,
        probe: LinuxProbe,
        artifact: pathlib.Path,
        output_dir: pathlib.Path,
        app_version: str,
        build_number: str,
        binding: dict[str, str],
        network_interface: str,
    ) -> None:
        self.driver = driver
        self.probe = probe
        self.artifact = artifact
        self.output_dir = output_dir
        self.app_version = app_version
        self.build_number = build_number
        self.binding = binding
        self.network_interface = network_interface
        self.receipt_index = 0

    def receipt(self, stem: str, contract: str, fields: dict[str, Any]) -> dict[str, str]:
        self.receipt_index += 1
        name = f"{self.receipt_index:02d}-{stem}.json"
        path = self.output_dir / name
        payload = {
            "schema_version": 1,
            "contract": contract,
            **fields,
            "captured_at_utc": now_utc(),
            "secret_material_redacted": True,
        }
        atomic_json(path, payload)
        return {"receipt_path": name, "receipt_sha256": sha256_file(path)}

    @staticmethod
    def driver_base(value: dict[str, Any], action: str, fields: set[str]) -> dict[str, Any]:
        result = require_exact(
            value,
            {"schema_version", "contract", "action", "passed", "secret_material_redacted", *fields},
            f"Linux driver {action}",
        )
        if result["schema_version"] != 1 or result["contract"] != CONTRACT or result["action"] != action:
            raise CollectorError(f"Linux driver {action} contract/version/action is invalid")
        require_true(result["passed"], f"Linux driver {action}")
        require_true(result["secret_material_redacted"], f"Linux driver {action} redaction")
        return result

    @staticmethod
    def normalize_routes(value: Any, label: str) -> list[dict[str, Any]]:
        if not isinstance(value, list) or not value:
            raise CollectorError(f"{label} is empty or invalid")
        keys: set[tuple[int, str]] = set()
        routes: list[dict[str, Any]] = []
        for raw in value:
            route = require_exact(raw, {"protocol", "port", "security"}, label)
            port = route["port"]
            security = route["security"]
            if (
                route["protocol"] != "tcp"
                or isinstance(port, bool)
                or not isinstance(port, int)
                or not 1 <= port <= 65535
                or security not in {"none", "tls"}
            ):
                raise CollectorError(f"{label} contains an invalid route")
            key = (port, security)
            if key in keys:
                raise CollectorError(f"{label} contains a duplicate route")
            keys.add(key)
            routes.append(dict(route))
        return sorted(routes, key=lambda item: (item["port"], item["security"]))

    def connect_response(
        self,
        kind: str,
        port: int | None = None,
        security: str | None = None,
        expected_direct_port: int | None = None,
    ) -> dict[str, Any]:
        is_xray = kind in {"xray", "double_vpn_xray"}
        arguments = {"kind": kind}
        if is_xray:
            if port is None or security is None or expected_direct_port is None:
                raise CollectorError("Linux Xray request lacks its mode baseline binding")
            arguments.update(
                port=str(port), security=security, direct_port=str(expected_direct_port)
            )
        elif any(value is not None for value in (port, security, expected_direct_port)):
            raise CollectorError("Linux direct baseline must be discovered by the installed app")
        raw = self.driver.call("connect", **arguments)
        value = self.driver_base(
            raw,
            "connect",
            {
                "kind", "port", "security", "actual_direct_port",
                "advertised_xray_routes", "forcing_blocked_udp_port",
                "forced_route", "double_vpn_active",
                "double_vpn_core_id_sha256", "double_vpn_exit_slug_sha256",
            },
        )
        actual_direct_port = value["actual_direct_port"]
        if (
            isinstance(actual_direct_port, bool)
            or not isinstance(actual_direct_port, int)
            or not 1 <= actual_direct_port <= 65535
        ):
            raise CollectorError("Linux driver returned an invalid live direct port")
        routes = self.normalize_routes(
            value["advertised_xray_routes"], f"{kind} live advertised routes"
        )
        value["advertised_xray_routes"] = routes
        if value["kind"] != kind or value["security"] != (security if is_xray else "none"):
            raise CollectorError("Linux driver connected a route other than the requested route")
        if is_xray:
            if value["port"] != port or actual_direct_port != expected_direct_port:
                raise CollectorError("Linux Xray connection contradicts its mode baseline")
            if value["forcing_blocked_udp_port"] != actual_direct_port:
                raise CollectorError("Linux Xray forcing did not block the mode direct port")
        elif value["port"] != actual_direct_port:
            raise CollectorError("Linux direct connection contradicts its live runtime port")
        elif value["forcing_blocked_udp_port"] is not None:
            raise CollectorError("Linux direct baseline unexpectedly reports UDP forcing")
        is_double = kind in {"double_vpn_direct", "double_vpn_xray"}
        if value["forced_route"] is not is_xray or value["double_vpn_active"] is not is_double:
            raise CollectorError("Linux driver route forcing/Double VPN result contradicts the lane")
        for field in ("double_vpn_core_id_sha256", "double_vpn_exit_slug_sha256"):
            digest = require_sha256(value[field], f"Linux driver {field}")
            if is_double and digest in INVALID_OBSERVATION_DIGESTS:
                raise CollectorError(f"Linux driver {field} lacks a real Double VPN identity")
            if not is_double and digest != EMPTY_SHA256:
                raise CollectorError(f"Linux driver {field} is inconsistent")
        return value

    def disconnect(self) -> None:
        self.driver_base(self.driver.call("disconnect"), "disconnect", set())
        self.probe.teardown_assertions()

    def collect_lane(
        self,
        lane_id: str,
        kind: str,
        protocol: str,
        port: int | None = None,
        security: str | None = None,
        expected_direct_port: int | None = None,
    ) -> tuple[dict[str, Any], int, list[dict[str, Any]]]:
        if not LANE_ID_RE.fullmatch(lane_id):
            raise CollectorError("Generated Linux lane ID is invalid")
        self.probe.teardown_assertions()
        before = self.probe.state_hash()
        response = self.connect_response(kind, port, security, expected_direct_port)
        is_xray = kind in {"xray", "double_vpn_xray"}
        lane_port = response["port"]
        lane_security = response["security"]
        actual_direct_port = response["actual_direct_port"]
        mode_routes = response["advertised_xray_routes"]
        observation = self.probe.observe_lane(
            is_xray=is_xray,
            port=lane_port,
            security=lane_security,
            direct_port=actual_direct_port,
        )
        for field, digest in (
            ("protected egress", observation.protected_egress_sha256),
            ("provider executable", observation.provider_executable_sha256),
        ):
            if require_sha256(digest, f"Linux {lane_id} {field}") in INVALID_OBSERVATION_DIGESTS:
                raise CollectorError(f"Linux {lane_id} {field} is an empty/sentinel observation")
        self.disconnect()
        after = self.probe.state_hash()
        if after != before:
            raise CollectorError(f"{lane_id} did not restore the exact pre-lane control state")
        is_double = kind in {"double_vpn_direct", "double_vpn_xray"}
        core_hash = response["double_vpn_core_id_sha256"]
        exit_hash = response["double_vpn_exit_slug_sha256"]
        fields = {
            "platform": "linux",
            "lane_id": lane_id,
            "kind": kind,
            "protocol": protocol,
            "port": lane_port,
            "security": lane_security,
            "runtime_direct_port": actual_direct_port,
            "advertised_xray_routes_sha256": sha256_text(
                json.dumps(mode_routes, separators=(",", ":"), sort_keys=True)
            ),
            "forcing_blocked_udp_port": response["forcing_blocked_udp_port"],
            "double_vpn_active": is_double,
            "provider_executable_sha256": observation.provider_executable_sha256,
            "connected_observed": True,
            "rx_delta_bytes": observation.rx_delta_bytes,
            "tx_delta_bytes": observation.tx_delta_bytes,
            "protected_egress_sha256": observation.protected_egress_sha256,
            "control_state_before_sha256": before,
            "control_state_after_sha256": after,
            "forcing_applied": is_xray,
            "forcing_restored": True,
            "double_vpn_core_id_sha256": core_hash,
            "double_vpn_exit_slug_sha256": exit_hash,
        }
        lane = {
            "lane_id": lane_id,
            "kind": kind,
            "protocol": protocol,
            "port": lane_port,
            "security": lane_security,
            "runtime_direct_port": actual_direct_port,
            "advertised_xray_routes_sha256": fields["advertised_xray_routes_sha256"],
            "forcing_blocked_udp_port": response["forcing_blocked_udp_port"],
            "connected_passed": True,
            "double_vpn_active": is_double,
            "rx_delta_bytes": observation.rx_delta_bytes,
            "tx_delta_bytes": observation.tx_delta_bytes,
            "protected_egress_sha256": observation.protected_egress_sha256,
            "provider_executable_sha256": observation.provider_executable_sha256,
            "control_state_before_sha256": before,
            "control_state_after_sha256": after,
            "forcing_applied": is_xray,
            "forcing_restored": True,
            "double_vpn_core_id_sha256": core_hash,
            "double_vpn_exit_slug_sha256": exit_hash,
            **self.receipt(lane_id, "winsvpn-route-observation-v1", fields),
        }
        return lane, actual_direct_port, mode_routes

    def collect(self) -> tuple[pathlib.Path, pathlib.Path]:
        artifact_hash = sha256_file(self.artifact)
        install_result = self.driver_base(
            self.driver.call(
                "clean_install",
                artifact=str(self.artifact),
                app_version=self.app_version,
                build_number=self.build_number,
            ),
            "clean_install",
            {"source_artifact_sha256", "app_version", "build_number", "clean_remove_passed", "install_passed"},
        )
        if (
            install_result["source_artifact_sha256"] != artifact_hash
            or install_result["app_version"] != self.app_version
            or install_result["build_number"] != self.build_number
        ):
            raise CollectorError("Linux clean install is not bound to the exact release artifact/version")
        require_true(install_result["clean_remove_passed"], "Linux clean removal")
        require_true(install_result["install_passed"], "Linux install")

        payload_path = self.output_dir / "installed-payload.json"
        payload = self.probe.installed_payload_report(self.artifact, payload_path)
        payload_hash = sha256_file(payload_path)
        installed_identity = require_sha256(
            payload["installed_payload_manifest_sha256"], "installed payload identity"
        )
        install_fields = {
            "platform": "linux",
            "source_artifact_sha256": artifact_hash,
            "installed_identity_sha256": installed_identity,
            "app_version": self.app_version,
            "build_number": self.build_number,
            "exact_install_source_verified": True,
        }
        install = {
            "source_artifact_sha256": artifact_hash,
            "clean_remove_passed": True,
            "install_passed": True,
            "installed_identity_sha256": installed_identity,
            "exact_install_source_verified": True,
            **self.receipt("install", "winsvpn-install-receipt-v1", install_fields),
        }

        direct_lane, direct_awg_port, advertised = self.collect_lane(
            "direct-awg", "direct_awg", "udp"
        )
        lanes = [direct_lane]
        for route in advertised:
            port, security = route["port"], route["security"]
            lane, _, _ = self.collect_lane(
                f"xray-{port}-{security}", "xray", "tcp", port, security,
                direct_awg_port,
            )
            lanes.append(lane)
        double_lane, double_vpn_direct_port, double_advertised = self.collect_lane(
            "double-direct", "double_vpn_direct", "udp"
        )
        lanes.append(double_lane)
        for route in double_advertised:
            port, security = route["port"], route["security"]
            lane, _, _ = self.collect_lane(
                    f"double-xray-{port}-{security}",
                    "double_vpn_xray",
                    "tcp",
                    port,
                    security,
                    double_vpn_direct_port,
                )
            lanes.append(lane)
        split_result = self.driver_base(
            self.driver.call("select_split"), "select_split", {"selection_applied"}
        )
        require_true(split_result["selection_applied"], "Linux split selection")
        split_connect = self.connect_response("direct_awg")
        if split_connect["actual_direct_port"] != direct_awg_port or split_connect["advertised_xray_routes"] != advertised:
            raise CollectorError("Linux node baseline changed before split testing")
        launch_split = self.driver_base(
            self.driver.call("launch_split"), "launch_split", {"launched"}
        )
        require_true(launch_split["launched"], "Linux split canary launch")
        self.probe.split_assertions()
        self.disconnect()
        split_fields = {
            "scope": "launcher-cgroup-v2",
            "consumer_per_app_available": True,
            "mdm_per_app_only": False,
            "selection_applied_by_harness": True,
            "selected_scope_bypassed": True,
            "ordinary_scope_protected": True,
        }
        split = {
            **split_fields,
            **self.receipt("split", "winsvpn-split-observation-v1", split_fields),
        }

        leak_fields = {
            "dns_protected": True,
            "ipv4_protected": True,
            "ipv6_escape_blocked": True,
            "public_canaries_agree": True,
        }
        leak = {
            **leak_fields,
            **self.receipt("leak", "winsvpn-leak-observation-v1", leak_fields),
        }

        network_connect = self.connect_response("direct_awg")
        if network_connect["actual_direct_port"] != direct_awg_port or network_connect["advertised_xray_routes"] != advertised:
            raise CollectorError("Linux node baseline changed before network testing")
        self.probe.observe_lane(
            is_xray=False,
            port=direct_awg_port,
            security="none",
            direct_port=direct_awg_port,
        )
        pre_interface_state = self.probe.interface_state_hash(self.network_interface)
        change_result = self.driver_base(
            self.driver.call("network_change_begin", interface=self.network_interface),
            "network_change_begin",
            {"change_triggered_by_harness"},
        )
        require_true(change_result["change_triggered_by_harness"], "Linux network change")
        changed_interface_state = self.probe.interface_state_hash(self.network_interface)
        if changed_interface_state == pre_interface_state:
            raise CollectorError("Harness network-change action did not change the named interface state")
        restored_change = self.driver_base(
            self.driver.call("network_change_restore", interface=self.network_interface),
            "network_change_restore",
            {"restored"},
        )
        require_true(restored_change["restored"], "Linux network-change restoration")
        self.probe.wait_for_lane(
            is_xray=False,
            port=direct_awg_port,
            security="none",
            direct_port=direct_awg_port,
        )
        self.disconnect()
        change_fields = {
            "change_triggered_by_harness": True,
            "pre_change_protected": True,
            "post_change_recovered": True,
            "post_change_protected": True,
        }
        network_change = {
            **change_fields,
            **self.receipt(
                "network-change", "winsvpn-network-change-observation-v1", change_fields
            ),
        }

        teardown_fields = {
            "disconnect_requested_by_harness": True,
            "provider_absent": True,
            "protected_routes_absent": True,
            "transient_state_absent": True,
        }
        teardown = {
            **teardown_fields,
            **self.receipt("teardown", "winsvpn-teardown-observation-v1", teardown_fields),
        }

        self.probe.teardown_assertions()
        prior = self.probe.state_hash()
        inject = self.driver_base(
            self.driver.call("rollback_inject"),
            "rollback_inject",
            {"failure_injected_by_harness"},
        )
        require_true(inject["failure_injected_by_harness"], "Linux rollback injection")
        injected_state = self.probe.state_hash()
        if injected_state == prior:
            raise CollectorError("Rollback injection did not change the observed control state")
        failed_code = self.driver.expect_failure("connect", kind="direct_awg")
        if failed_code == 0:
            raise CollectorError("Rollback injection did not cause a real connection failure")
        restore_result = self.driver_base(
            self.driver.call("rollback_restore"), "rollback_restore", {"restored"}
        )
        require_true(restore_result["restored"], "Linux rollback restoration")
        restored = self.probe.state_hash()
        if restored != prior:
            raise CollectorError("Rollback restoration did not reproduce the exact prior state")
        rollback_connect = self.connect_response("direct_awg")
        if rollback_connect["actual_direct_port"] != direct_awg_port or rollback_connect["advertised_xray_routes"] != advertised:
            raise CollectorError("Linux node baseline changed after rollback recovery")
        self.probe.observe_lane(
            is_xray=False,
            port=direct_awg_port,
            security="none",
            direct_port=direct_awg_port,
        )
        self.disconnect()
        rollback_fields = {
            "failure_injected_by_harness": True,
            "prior_state_sha256": prior,
            "restored_state_sha256": restored,
            "recovery_connect_passed": True,
        }
        rollback = {
            **rollback_fields,
            **self.receipt("rollback", "winsvpn-rollback-observation-v1", rollback_fields),
        }

        screenshot = self.output_dir / "linux-map.png"
        map_result = self.driver_base(
            self.driver.call("capture_map", output=str(screenshot)),
            "capture_map",
            {
                "capture_method", "screenshot_sha256", "radius_label_50_miles_detected",
                "surrounding_city_labels", "target_marker_detected", "viewport_not_world_zoom",
            },
        )
        if not screenshot.is_file() or screenshot.is_symlink() or screenshot.stat().st_size < 4096:
            raise CollectorError("Linux map driver did not create a plausible regular screenshot")
        if not screenshot.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"):
            raise CollectorError("Linux map screenshot must be PNG")
        screenshot_hash = sha256_file(screenshot)
        if map_result["capture_method"] != "linux-window-capture" or map_result["screenshot_sha256"] != screenshot_hash:
            raise CollectorError("Linux map capture method/hash is invalid")
        for field in (
            "radius_label_50_miles_detected", "target_marker_detected", "viewport_not_world_zoom"
        ):
            require_true(map_result[field], f"Linux map {field}")
        city_labels = map_result["surrounding_city_labels"]
        if (
            not isinstance(city_labels, list)
            or len({str(label).strip().casefold() for label in city_labels if str(label).strip()}) < 2
        ):
            raise CollectorError("Linux semantic map capture found fewer than two city labels")
        map_fields = {
            "platform": "linux",
            "screenshot_sha256": screenshot_hash,
            "capture_method": "linux-window-capture",
            "radius_label_50_miles_detected": True,
            "surrounding_city_label_count": len(
                {str(label).strip().casefold() for label in city_labels if str(label).strip()}
            ),
            "target_marker_detected": True,
            "viewport_not_world_zoom": True,
        }
        map_visual = {
            **{key: value for key, value in map_fields.items() if key != "platform"},
            **self.receipt(
                "map", "winsvpn-map-capture-observation-v1", map_fields
            ),
        }

        run_id = str(uuid.uuid4())
        machine = {
            "schema_version": 1,
            "contract": MACHINE_CONTRACT,
            "platform": "linux",
            "app_version": self.app_version,
            "build_number": self.build_number,
            "artifact_sha256": artifact_hash,
            "artifact_size_bytes": self.artifact.stat().st_size,
            **self.binding,
            "run_id": run_id,
            "captured_at_utc": now_utc(),
            "secret_material_redacted": True,
            "install": install,
            "installed_payload": {
                "path": payload_path.name,
                "sha256": payload_hash,
                "installed_payload_manifest_sha256": installed_identity,
            },
            "advertised_xray_routes": sorted(
                advertised, key=lambda item: (item["port"], item["security"])
            ),
            "double_vpn_advertised_xray_routes": sorted(
                double_advertised, key=lambda item: (item["port"], item["security"])
            ),
            "direct_awg_port": direct_awg_port,
            "double_vpn_direct_port": double_vpn_direct_port,
            "lanes": lanes,
            "split_scope": split,
            "leak": leak,
            "network_change": network_change,
            "teardown": teardown,
            "rollback": rollback,
            "map_visual": map_visual,
        }
        output = self.output_dir / "linux-machine-evidence.json"
        atomic_json(output, machine)
        receipt_files: dict[str, dict[str, Any]] = {}
        for path in sorted(self.output_dir.glob("[0-9][0-9]-*.json")):
            receipt = json.loads(path.read_text(encoding="utf-8"))
            receipt_files[path.name] = _indexed_file(path, str(receipt["contract"]))
        payload_contract = json.loads(payload_path.read_text(encoding="utf-8"))["contract"]
        index = {
            "schema_version": 2,
            "contract": "winsvpn-linux-final-evidence-index-v2",
            "run_id": run_id,
            "machine_evidence": _indexed_file(output, MACHINE_CONTRACT),
            "map_screenshot": _indexed_file(
                screenshot, "winsvpn-linux-map-screenshot-v1"
            ),
            "receipt_files": receipt_files,
            "installed_payload": _indexed_file(payload_path, str(payload_contract)),
            "frozen_artifact": _indexed_file(
                self.artifact, "winsvpn-linux-frozen-artifact-v1"
            ),
            **self.binding,
            "secret_material_redacted": True,
        }
        atomic_json(self.output_dir / "EVIDENCE_INDEX.json", index)
        return output, screenshot


def prepare_output(repo: pathlib.Path, value: pathlib.Path) -> pathlib.Path:
    output = reject_reparse_components(value, "Linux evidence output", must_exist=False)
    artifacts = (repo / ".artifacts").resolve()
    try:
        output.relative_to(artifacts)
    except ValueError as exc:
        raise CollectorError("Linux evidence output must stay under repository .artifacts") from exc
    if output.exists():
        raise CollectorError("Linux evidence output directory must be new and immutable")
    output.mkdir(parents=True, mode=0o700)
    os.chmod(output, 0o700)
    info = output.lstat()
    if (
        output.is_symlink() or not output.is_dir() or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise CollectorError("Linux evidence output directory is unsafe")
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--driver")
    parser.add_argument("--artifact")
    parser.add_argument("--app-version")
    parser.add_argument("--build-number")
    parser.add_argument("--release-input-index")
    parser.add_argument("--build-receipt")
    parser.add_argument("--output-dir")
    parser.add_argument("--network-interface")
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        require_sha256("0" * 64, "self-test")
        try:
            require_sha256("A" * 64, "self-test")
        except CollectorError:
            pass
        else:
            raise CollectorError("Collector self-test accepted a non-lowercase digest")
        print("LINUX FINAL EVIDENCE COLLECTOR SELF-TEST: PASS")
        return 0
    euid = os.geteuid() if hasattr(os, "geteuid") else None
    require_linux_root(os.name, euid, pathlib.Path("/proc/net/dev"))
    os.umask(0o077)
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", str(args.app_version)):
        raise CollectorError("app version is invalid")
    if not str(args.build_number).isdigit():
        raise CollectorError("build number is invalid")
    if not 30 <= args.timeout_seconds <= 600:
        raise CollectorError("timeout must be between 30 and 600 seconds")
    required = (
        args.driver, args.artifact, args.release_input_index,
        args.build_receipt, args.output_dir, args.network_interface,
    )
    if any(not value for value in required):
        parser.error("driver, artifact, release input index, build receipt, output dir, and network interface are required")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", args.network_interface):
        raise CollectorError("network interface name is invalid")
    repo = pathlib.Path(__file__).resolve().parent.parent
    artifact = reject_reparse_components(
        pathlib.Path(args.artifact), "Linux release artifact", must_exist=True
    )
    release_index = reject_reparse_components(
        pathlib.Path(args.release_input_index), "Release input index", must_exist=True
    )
    build_receipt = reject_reparse_components(
        pathlib.Path(args.build_receipt), "Build receipt", must_exist=True
    )
    driver_path = reject_reparse_components(
        pathlib.Path(args.driver), "Linux release driver", must_exist=True
    )
    expected_driver = repo / "tools/linux_release_ui_driver.py"
    expected_canary = repo / "tools/linux_split_tunnel_live_canary.sh"
    driver_path = require_installed_tool(
        driver_path, expected_driver, "Linux release UI driver"
    )
    require_installed_tool(
        INSTALLED_SPLIT_CANARY,
        expected_canary,
        "Linux release split canary",
    )
    input_binding = release_input_binding(repo, "linux", str(release_index))
    receipt_binding = build_receipt_binding(
        repo, "linux", str(release_index), str(build_receipt), artifact
    )
    binding = {
        "release_input_index_sha256": input_binding.index_sha256,
        "platform_manifest_sha256": input_binding.platform_manifest_sha256,
        "artifact_input_fingerprint_sha256": input_binding.artifact_input_fingerprint_sha256,
        "build_receipt_sha256": receipt_binding.sha256,
        "producer_contract_sha256": producer_contract_hash(
            repo, LINUX_PUBLIC_PRODUCER
        ),
    }
    output = prepare_output(repo, pathlib.Path(args.output_dir))
    frozen_artifact = output / "exact-input-linux-artifact.tar.gz"
    with artifact.open("rb") as source, frozen_artifact.open("xb") as target:
        shutil.copyfileobj(source, target, 1024 * 1024)
    os.chmod(frozen_artifact, 0o600)
    if (
        sha256_file(frozen_artifact) != sha256_file(artifact)
        or frozen_artifact.stat().st_size != artifact.stat().st_size
    ):
        raise CollectorError("Frozen Linux artifact copy changed during capture")
    artifact = frozen_artifact
    driver = DesktopDriver(driver_path, args.timeout_seconds)
    collector = Collector(
        driver=driver,
        probe=LinuxProbe(repo / "tools", args.timeout_seconds),
        artifact=artifact,
        output_dir=output,
        app_version=args.app_version,
        build_number=args.build_number,
        binding=binding,
        network_interface=args.network_interface,
    )
    try:
        machine, screenshot = collector.collect()
    finally:
        final = Collector.driver_base(
            driver.call("finalize"), "finalize", {"restored"}
        )
        require_true(final["restored"], "Linux release driver final restoration")
    print("LINUX FINAL EVIDENCE COLLECTOR: PASS")
    print(f"Machine evidence: {machine}")
    print(f"Map screenshot: {screenshot}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CollectorError, OSError, subprocess.SubprocessError) as error:
        print(f"LINUX FINAL EVIDENCE COLLECTOR: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
