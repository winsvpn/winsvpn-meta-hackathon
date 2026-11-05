#!/usr/bin/python3
"""Root-owned protocol-attempt broker for winsvpn-gcp-proof-protocol-attempt-request-v1.

Binds /run/winsvpn-proof/protocol-attempt.sock and atomically maintains
/run/winsvpn-proof/protocol-attempts.json using the exact journal and
acknowledgement contracts consumed by gcp_proof_remote_action.py. Clients may
supply only that helper's fixed request fields. Role comes from the root-owned
role file. Peer credentials must be root. Commands are a closed argv table
executed with shell=False. Protocol attempts run the release-custodied Winn3
probe, AWG userspace client, and Xray client runtime against provisioned
root-owned config. Missing credentials fail closed. This process is not
installer-integrated.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = 1
ATTEMPT_JOURNAL_CONTRACT = "winsvpn-gcp-proof-protocol-attempts-v1"
ATTEMPT_REQUEST_CONTRACT = "winsvpn-gcp-proof-protocol-attempt-request-v1"
ATTEMPT_ACK_CONTRACT = "winsvpn-gcp-proof-protocol-attempt-ack-v1"
FLEET_BINDING_CONTRACT = "winsvpn-gcp-proof-fleet-binding-v1"
ROLE_FILE = "/etc/winsvpn/role"
FLEET_BINDING_PATH = "/var/lib/winsvpn-proof/fleet-binding.json"
ATTEMPT_JOURNAL_PATH = "/run/winsvpn-proof/protocol-attempts.json"
ATTEMPT_SOCKET_PATH = "/run/winsvpn-proof/protocol-attempt.sock"
BIN_IP = "/usr/sbin/ip"
BIN_SYSTEMCTL = "/usr/bin/systemctl"
BIN_AWG = "/usr/local/bin/awg"
WINN3_PROBE_BIN = "/usr/local/bin/winn3-probe"
AMNEZIAWG_GO_BIN = "/usr/local/bin/amneziawg-go"
XRAY_BIN = "/usr/local/bin/xray"
AWG_IFACE = "awg0"
XRAY_IFACE = "xray0"
PROOF_CLIENT_DIR = "/etc/winn/proof-client"
AWG_CLIENT_CONF = "/etc/winn/proof-client/awg0.conf"
XRAY_CLIENT_CONF = "/etc/winn/proof-client/xray-client.json"
WINN3_PROBE_ENV = "/etc/winn/proof-client/winn3-probe.env"
XRAY_PROBE_ENV = "/etc/winn/proof-client/xray-probe.env"
WINN3_PROBE_OUT = "/run/winsvpn-proof/winn3-probe.out"
XRAY_PROBE_OUT = "/run/winsvpn-proof/xray-probe.out"
PROOF_CLIENT_INNER_V4 = "10.10.0.2"
PROOF_GATEWAY_INNER_V4 = "10.10.0.1"
UNIT_WINN3_PROBE = "winsvpn-proof-winn3-probe.service"
UNIT_AWG_CLIENT = "winsvpn-proof-awg-client.service"
UNIT_XRAY_CLIENT = "winsvpn-proof-xray-client.service"
UNIT_XRAY_PROBE = "winsvpn-proof-xray-probe.service"
UNIT_XRAY_SERVER = "xray.service"
SHOW_PROPERTIES = "--property=Id,FragmentPath,MainPID,ActiveState,Result,ExecMainStatus,Type"
COMMAND_TIMEOUT_SECONDS = 90
IFACE_WAIT_ATTEMPTS = 8
IFACE_WAIT_SECONDS = 0.25
MAX_REQUEST = 65536
REFUSAL_EXIT = 2
JOURNAL_MODE = 0o400
PROOF_CLIENT_MODE = 0o400
ROLE_MODE = 0o400
FLEET_BINDING_MODE = 0o400
SOCKET_MODE = 0o700
DIR_MODE = 0o700
PROBE_OUT_MODES = frozenset({0o400, 0o600})
CHILD_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}

INSTANCE_RE = re.compile(r"[a-z]([-a-z0-9]{0,61}[a-z0-9])?\Z")
ZONE_RE = re.compile(r"[a-z]+-[a-z]+[0-9]+-[a-z]\Z")
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}\Z")
FLEET_RE = re.compile(r"[a-f0-9]{12}\Z")
UTC_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z\Z")
VALUE_FORBIDDEN_RE = re.compile(r"[\\;&|$`(){}[\]*?!\s]")
HEX64_RE = re.compile(r"[0-9a-f]{64}\Z")
HEX3904_RE = re.compile(r"[0-9a-f]{3904}\Z")
AWG_PEER_RE = re.compile(r"[A-Za-z0-9+/]{42,44}={0,2}\Z")
DOCUMENTATION_NETWORKS = (
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
)
UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
WINN3_DIALED_RE = re.compile(
    r"v3probe: dialed ([0-9.]+):([0-9]+), inner ([0-9.]+), target ([0-9.]+), inner MTU ([0-9]+)\Z"
)
WINN3_SENT_RE = re.compile(r"v3probe: SENT  (.+)\Z")
WINN3_RECV_RE = re.compile(r"v3probe: RECV  (.+)\Z")
WINN3_COUNTS_RE = re.compile(r"v3probe: sent=([0-9]+) received=([0-9]+) unmatched=([0-9]+)\Z")
WINN3_STATS_RE = re.compile(
    r"v3probe: tunnel stats tx=([0-9]+) rx=([0-9]+) rx_dropped_invalid=([0-9]+) tx_dropped_invalid=([0-9]+)\Z"
)
WINN3_HANDSHAKE_RE = re.compile(
    r"v3probe: HANDSHAKE ok state=carrying epoch=([0-9]+) session=([A-Za-z0-9._:-]+)\Z"
)
WINN3_HANDSHAKE_ABSENT_RE = re.compile(
    r"v3probe: HANDSHAKE absent state=([a-z]+) wait=([0-9]+(?:\.[0-9]+)?(?:ms|s|m))\Z"
)
WINN3_REPLY_RE = re.compile(r"v3probe: VERDICT a matching reply came back through the winn/3 session\Z")
PING_SUMMARY_RE = re.compile(
    r"([0-9]+) packets transmitted, ([0-9]+) received,"
)
ENV_LINE_RE = re.compile(r"([A-Z][A-Z0-9_]*)=(.*)\Z")
PROOF_CLIENT_FILES = (
    ("client.key", 64, HEX64_RE),
    ("static.pub", 64, HEX64_RE),
    ("admission.key", 64, HEX64_RE),
    ("auth_ed25519.pub", 64, HEX64_RE),
    ("auth_mldsa65.pub", 3904, HEX3904_RE),
)
WINN3_PROBE_ENV_KEYS = (
    "WINN3_PROOF_GW",
    "WINN3_PROOF_GATEWAY_ID",
    "WINN3_PROOF_ED_PUB",
    "WINN3_PROOF_ML_PUB",
)
XRAY_PROBE_ENV_KEYS = ("XRAY_PROOF_PEER",)
FORBIDDEN_OUTPUT_KEYS = frozenset(
    {"pass", "passed", "ok", "success", "verdict", "acceptance"}
)
CREDENTIAL_PATHS = frozenset(
    {
        "/root/vpn_auth.env",
        "/root/vpn_auth/.env",
        "/root/winsvpn-secrets.env",
        "/root/vpn_auth/vpn_users.db",
        "/etc/winn/credentials",
    }
)
PRODUCTION_PATH_PREFIXES = (
    "/etc/nginx/sites-enabled/",
    "/var/lib/postgresql/",
    "/home/",
)

ATTEMPT_JOURNAL_KEYS = {"contract", "events", "schema_version"}
ATTEMPT_EVENT_KEYS = {
    "action",
    "correlation_id",
    "monotonic_ns",
    "node",
    "phase",
    "protocol",
    "result",
    "session_id",
    "utc",
}
ATTEMPT_REQUEST_KEYS = {
    "action",
    "contract",
    "correlation_id",
    "node",
    "protocol",
    "schema_version",
    "session_id",
}
ATTEMPT_ACK_KEYS = {
    "action",
    "contract",
    "correlation_id",
    "node",
    "protocol",
    "session_id",
    "state",
}
FLEET_BINDING_KEYS = {
    "schema_version",
    "contract",
    "project",
    "fleet_id",
    "control",
    "data-winn3",
    "data-cover",
}
MEMBER_KEYS = {"instance", "zone"}
ALLOWED_ROLES = frozenset({"control", "data-winn3", "data-cover"})
ALLOWED_PROTOCOLS = frozenset({"awg", "winn3", "xray"})
FINISHED_RESULTS = frozenset({"connected", "failed"})

ARGV_SYSTEMCTL_START_WINN3_PROBE = (BIN_SYSTEMCTL, "start", UNIT_WINN3_PROBE)
ARGV_SYSTEMCTL_SHOW_WINN3_PROBE = (
    BIN_SYSTEMCTL,
    "show",
    UNIT_WINN3_PROBE,
    "--no-pager",
    SHOW_PROPERTIES,
)
ARGV_SYSTEMCTL_STOP_WINN3_PROBE = (BIN_SYSTEMCTL, "stop", UNIT_WINN3_PROBE)
ARGV_SYSTEMCTL_START_AWG_CLIENT = (BIN_SYSTEMCTL, "start", UNIT_AWG_CLIENT)
ARGV_SYSTEMCTL_SHOW_AWG_CLIENT = (
    BIN_SYSTEMCTL,
    "show",
    UNIT_AWG_CLIENT,
    "--no-pager",
    SHOW_PROPERTIES,
)
ARGV_SYSTEMCTL_STOP_AWG_CLIENT = (BIN_SYSTEMCTL, "stop", UNIT_AWG_CLIENT)
ARGV_SYSTEMCTL_ACTIVE_AWG_CLIENT = (BIN_SYSTEMCTL, "is-active", UNIT_AWG_CLIENT)
ARGV_SYSTEMCTL_START_XRAY_CLIENT = (BIN_SYSTEMCTL, "start", UNIT_XRAY_CLIENT)
ARGV_SYSTEMCTL_SHOW_XRAY_CLIENT = (
    BIN_SYSTEMCTL,
    "show",
    UNIT_XRAY_CLIENT,
    "--no-pager",
    SHOW_PROPERTIES,
)
ARGV_SYSTEMCTL_STOP_XRAY_CLIENT = (BIN_SYSTEMCTL, "stop", UNIT_XRAY_CLIENT)
ARGV_SYSTEMCTL_ACTIVE_XRAY_CLIENT = (BIN_SYSTEMCTL, "is-active", UNIT_XRAY_CLIENT)
ARGV_SYSTEMCTL_ACTIVE_XRAY_SERVER = (BIN_SYSTEMCTL, "is-active", UNIT_XRAY_SERVER)
ARGV_SYSTEMCTL_START_XRAY_PROBE = (BIN_SYSTEMCTL, "start", UNIT_XRAY_PROBE)
ARGV_SYSTEMCTL_SHOW_XRAY_PROBE = (
    BIN_SYSTEMCTL,
    "show",
    UNIT_XRAY_PROBE,
    "--no-pager",
    SHOW_PROPERTIES,
)
ARGV_SYSTEMCTL_STOP_XRAY_PROBE = (BIN_SYSTEMCTL, "stop", UNIT_XRAY_PROBE)
ARGV_IP_LINK_AWG = (BIN_IP, "link", "show", AWG_IFACE)
ARGV_IP_LINK_UP_AWG = (BIN_IP, "link", "set", AWG_IFACE, "up")
ARGV_IP_LINK_XRAY = (BIN_IP, "link", "show", XRAY_IFACE)
ARGV_IP_STATS_XRAY = (BIN_IP, "-s", "link", "show", XRAY_IFACE)
ARGV_AWG_SETCONF = (BIN_AWG, "setconf", AWG_IFACE, AWG_CLIENT_CONF)
ARGV_AWG_HANDSHAKES = (BIN_AWG, "show", AWG_IFACE, "latest-handshakes")
ARGV_AWG_TRANSFER = (BIN_AWG, "show", AWG_IFACE, "transfer")
ARGV_AWG_ENDPOINTS = (BIN_AWG, "show", AWG_IFACE, "endpoints")

ALLOWED_COMMANDS = frozenset(
    {
        ARGV_SYSTEMCTL_START_WINN3_PROBE,
        ARGV_SYSTEMCTL_SHOW_WINN3_PROBE,
        ARGV_SYSTEMCTL_STOP_WINN3_PROBE,
        ARGV_SYSTEMCTL_START_AWG_CLIENT,
        ARGV_SYSTEMCTL_SHOW_AWG_CLIENT,
        ARGV_SYSTEMCTL_STOP_AWG_CLIENT,
        ARGV_SYSTEMCTL_ACTIVE_AWG_CLIENT,
        ARGV_SYSTEMCTL_START_XRAY_CLIENT,
        ARGV_SYSTEMCTL_SHOW_XRAY_CLIENT,
        ARGV_SYSTEMCTL_STOP_XRAY_CLIENT,
        ARGV_SYSTEMCTL_ACTIVE_XRAY_CLIENT,
        ARGV_SYSTEMCTL_ACTIVE_XRAY_SERVER,
        ARGV_SYSTEMCTL_START_XRAY_PROBE,
        ARGV_SYSTEMCTL_SHOW_XRAY_PROBE,
        ARGV_SYSTEMCTL_STOP_XRAY_PROBE,
        ARGV_IP_LINK_AWG,
        ARGV_IP_LINK_UP_AWG,
        ARGV_IP_LINK_XRAY,
        ARGV_IP_STATS_XRAY,
        ARGV_AWG_SETCONF,
        ARGV_AWG_HANDSHAKES,
        ARGV_AWG_TRANSFER,
        ARGV_AWG_ENDPOINTS,
    }
)
ALLOWED_FRAGMENTS = {
    UNIT_WINN3_PROBE: frozenset(
        {
            "/lib/systemd/system/winsvpn-proof-winn3-probe.service",
            "/etc/systemd/system/winsvpn-proof-winn3-probe.service",
        }
    ),
    UNIT_AWG_CLIENT: frozenset(
        {
            "/lib/systemd/system/winsvpn-proof-awg-client.service",
            "/etc/systemd/system/winsvpn-proof-awg-client.service",
        }
    ),
    UNIT_XRAY_CLIENT: frozenset(
        {
            "/lib/systemd/system/winsvpn-proof-xray-client.service",
            "/etc/systemd/system/winsvpn-proof-xray-client.service",
        }
    ),
    UNIT_XRAY_PROBE: frozenset(
        {
            "/lib/systemd/system/winsvpn-proof-xray-probe.service",
            "/etc/systemd/system/winsvpn-proof-xray-probe.service",
        }
    ),
}
UNIT_EXECUTABLES = {
    UNIT_WINN3_PROBE: WINN3_PROBE_BIN,
    UNIT_AWG_CLIENT: AMNEZIAWG_GO_BIN,
    UNIT_XRAY_CLIENT: XRAY_BIN,
    UNIT_XRAY_PROBE: "/usr/bin/ping",
}

# Closed internal action table. Keys are the exact helper-emitted
# (action, protocol) pairs. Argv tuples are fixed; request fields never enter
# a command. Role and node-role gates are enforced before invocation.
ACTION_TABLE = {
    ("connect-primary", "winn3"): {
        "node_role": "data-winn3",
        "allowed_roles": frozenset({"control", "data-winn3"}),
        "unit": UNIT_WINN3_PROBE,
        "executable": WINN3_PROBE_BIN,
        "finished_result": "connected",
        "kind": "oneshot",
    },
    ("probe-awg-block", "awg"): {
        "node_role": "data-cover",
        "allowed_roles": frozenset({"control", "data-cover"}),
        "unit": UNIT_AWG_CLIENT,
        "executable": AMNEZIAWG_GO_BIN,
        "finished_result": "failed",
        "kind": "simple",
    },
    ("connect-cover-awg", "awg"): {
        "node_role": "data-cover",
        "allowed_roles": frozenset({"control", "data-cover"}),
        "unit": UNIT_AWG_CLIENT,
        "executable": AMNEZIAWG_GO_BIN,
        "finished_result": "connected",
        "kind": "simple",
    },
    ("connect-cover-xray", "xray"): {
        "node_role": "data-cover",
        "allowed_roles": frozenset({"control", "data-cover"}),
        "unit": UNIT_XRAY_CLIENT,
        "executable": XRAY_BIN,
        "finished_result": "connected",
        "kind": "simple",
    },
    ("probe-awg-block", "xray"): {
        "node_role": "data-cover",
        "allowed_roles": frozenset({"control", "data-cover"}),
        "unit": UNIT_XRAY_CLIENT,
        "executable": XRAY_BIN,
        "finished_result": "connected",
        "kind": "simple",
    },
    ("probe-winn3-block", "winn3"): {
        "node_role": "data-winn3",
        "allowed_roles": frozenset({"control", "data-winn3"}),
        "unit": UNIT_WINN3_PROBE,
        "executable": WINN3_PROBE_BIN,
        "finished_result": "failed",
        "kind": "oneshot",
    },
    ("probe-winn3-block", "awg"): {
        "node_role": "data-cover",
        "allowed_roles": frozenset({"control", "data-cover"}),
        "unit": UNIT_AWG_CLIENT,
        "executable": AMNEZIAWG_GO_BIN,
        "finished_result": "connected",
        "kind": "simple",
    },
    ("probe-cover-withdrawn", "winn3"): {
        "node_role": "data-winn3",
        "allowed_roles": frozenset({"control", "data-winn3"}),
        "unit": UNIT_WINN3_PROBE,
        "executable": WINN3_PROBE_BIN,
        "finished_result": "failed",
        "kind": "oneshot",
    },
}

_JOURNAL_LOCK = threading.Lock()


class AttemptBrokerError(RuntimeError):
    """The protocol attempt is unauthenticated, stale, or unsafe."""


class CommandResult:
    def __init__(self, stdout: bytes = b"", stderr: bytes = b"", exit_code: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code


class Paths:
    def __init__(
        self,
        *,
        socket_path: str,
        journal: str,
        role: str,
        fleet_binding: str,
        run_dir: str,
        proof_client_dir: str,
        awg_client_conf: str,
        xray_client_conf: str,
        winn3_probe_env: str,
        xray_probe_env: str,
        winn3_probe_out: str,
        xray_probe_out: str,
    ) -> None:
        self.socket = socket_path
        self.journal = journal
        self.role = role
        self.fleet_binding = fleet_binding
        self.run_dir = run_dir
        self.proof_client_dir = proof_client_dir
        self.awg_client_conf = awg_client_conf
        self.xray_client_conf = xray_client_conf
        self.winn3_probe_env = winn3_probe_env
        self.xray_probe_env = xray_probe_env
        self.winn3_probe_out = winn3_probe_out
        self.xray_probe_out = xray_probe_out

    @staticmethod
    def production() -> "Paths":
        return Paths(
            socket_path=ATTEMPT_SOCKET_PATH,
            journal=ATTEMPT_JOURNAL_PATH,
            role=ROLE_FILE,
            fleet_binding=FLEET_BINDING_PATH,
            run_dir=os.path.dirname(ATTEMPT_SOCKET_PATH),
            proof_client_dir=PROOF_CLIENT_DIR,
            awg_client_conf=AWG_CLIENT_CONF,
            xray_client_conf=XRAY_CLIENT_CONF,
            winn3_probe_env=WINN3_PROBE_ENV,
            xray_probe_env=XRAY_PROBE_ENV,
            winn3_probe_out=WINN3_PROBE_OUT,
            xray_probe_out=XRAY_PROBE_OUT,
        )

    @staticmethod
    def overlay(root: str) -> "Paths":
        if type(root) is not str or not root:
            raise AttemptBrokerError("test root is invalid")
        absolute = os.path.abspath(root)
        if absolute == "/" or not absolute.startswith("/"):
            raise AttemptBrokerError("test root is invalid")
        def join(production: str) -> str:
            return os.path.join(absolute, production.lstrip("/"))

        return Paths(
            socket_path=join(ATTEMPT_SOCKET_PATH),
            journal=join(ATTEMPT_JOURNAL_PATH),
            role=join(ROLE_FILE),
            fleet_binding=join(FLEET_BINDING_PATH),
            run_dir=join(os.path.dirname(ATTEMPT_SOCKET_PATH)),
            proof_client_dir=join(PROOF_CLIENT_DIR),
            awg_client_conf=join(AWG_CLIENT_CONF),
            xray_client_conf=join(XRAY_CLIENT_CONF),
            winn3_probe_env=join(WINN3_PROBE_ENV),
            xray_probe_env=join(XRAY_PROBE_ENV),
            winn3_probe_out=join(WINN3_PROBE_OUT),
            xray_probe_out=join(XRAY_PROBE_OUT),
        )


class ProductionHost:
    TEST_ONLY = False
    root_uid = 0
    root_gid = 0

    def monotonic_ns(self) -> int:
        return time.monotonic_ns()

    def utc_now(self) -> str:
        now = datetime.now(timezone.utc)
        return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond:06d}000Z"

    def run(self, argv: Sequence[str]) -> CommandResult:
        if not argv or not all(isinstance(item, str) and item for item in argv):
            raise AttemptBrokerError("command argv is invalid")
        try:
            completed = subprocess.run(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                check=False,
                timeout=COMMAND_TIMEOUT_SECONDS,
                env=CHILD_ENV,
            )
        except FileNotFoundError as exc:
            raise AttemptBrokerError(f"absent tool {argv[0]}") from exc
        except (OSError, subprocess.TimeoutExpired) as suc:
            raise AttemptBrokerError("bounded protocol attempt failed") from suc
        return CommandResult(
            bytes(completed.stdout), bytes(completed.stderr), int(completed.returncode)
        )

    def hash_executable(self, path: str) -> str:
        return sha256_bytes(
            _read_regular(
                path,
                self,
                f"process executable {path}",
                executable=True,
            )
        )

    def peer_credentials(self, conn: socket.socket) -> tuple[int, int, int]:
        if not hasattr(socket, "SO_PEERCRED"):
            raise AttemptBrokerError("peer credential interface is unavailable")
        try:
            credentials = conn.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
        except OSError as suc:
            raise AttemptBrokerError("protocol attempt peer credentials are unavailable") from suc
        pid, uid, gid = struct.unpack("3i", credentials)
        return int(pid), int(uid), int(gid)

    def fchown(self, fd: int) -> None:
        os.fchown(fd, self.root_uid, self.root_gid)

    def chown(self, path: str) -> None:
        os.chown(path, self.root_uid, self.root_gid)


def canonical_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_bytes(value: Any) -> bytes:
    return (canonical_dumps(value) + "\n").encode("ascii")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AttemptBrokerError(f"duplicate JSON key {key!r} is forbidden")
        result[key] = value
    return result


def strict_json(data: bytes, label: str) -> Any:
    if not data:
        raise AttemptBrokerError(f"{label} is empty")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as suc:
        raise AttemptBrokerError(f"{label} is not ASCII JSON") from suc
    decoder = json.JSONDecoder(object_pairs_hook=_strict_pairs)
    try:
        value, index = decoder.raw_decode(text)
    except json.JSONDecodeError as suc:
        raise AttemptBrokerError(f"{label} is not strict ASCII JSON") from suc
    if text[index:].strip():
        raise AttemptBrokerError(f"{label} contains multiple JSON values")
    return value


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise AttemptBrokerError(f"{label} schema fields are invalid")
    for key in value:
        if str(key).lower() in FORBIDDEN_OUTPUT_KEYS:
            raise AttemptBrokerError(f"{label} contains a forbidden pass token")
    return value


def exact_int(value: object, label: str, *, minimum: int | None = None) -> int:
    if type(value) is not int:
        raise AttemptBrokerError(f"{label} must be an exact integer")
    if minimum is not None and value < minimum:
        raise AttemptBrokerError(f"{label} is out of range")
    return value


def parse_utc(value: str) -> datetime:
    if type(value) is not str or not UTC_RE.fullmatch(value):
        raise AttemptBrokerError("timestamp is not canonical UTC")
    stamp = value[:-1]
    fraction = 0
    if "." in stamp:
        stamp, raw_fraction = stamp.split(".", 1)
        fraction = int(raw_fraction.ljust(6, "0")[:6])
    return datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S").replace(
        tzinfo=timezone.utc, microsecond=fraction
    )


def _forbid_credential_path(path: str) -> None:
    if path in CREDENTIAL_PATHS:
        raise AttemptBrokerError("credential file access is forbidden")
    for prefix in CREDENTIAL_PATHS:
        if path.startswith(prefix.rstrip("/") + "/"):
            raise AttemptBrokerError("credential file access is forbidden")
    for prefix in PRODUCTION_PATH_PREFIXES:
        if path.startswith(prefix):
            raise AttemptBrokerError("production resource access is forbidden")


def _identity(
    item: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int, int]:
    return (
        item.st_dev,
        item.st_ino,
        item.st_uid,
        item.st_gid,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
        stat.S_IFMT(item.st_mode),
        stat.S_IMODE(item.st_mode),
    )


def _nofollow_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    if not nofollow:
        raise AttemptBrokerError("O_NOFOLLOW is required")
    return nofollow | cloexec


def _require_owner_mode(
    info: os.stat_result,
    host: Any,
    label: str,
    *,
    write_ok: bool = False,
    required_mode: int | None = None,
    allowed_modes: frozenset[int] | None = None,
    executable: bool = False,
) -> None:
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid != host.root_uid or info.st_gid != host.root_gid:
        raise AttemptBrokerError(f"{label} ownership or mode is unsafe")
    if required_mode is not None:
        if mode != required_mode:
            raise AttemptBrokerError(f"{label} ownership or mode is unsafe")
        return
    if allowed_modes is not None:
        if mode not in allowed_modes:
            raise AttemptBrokerError(f"{label} ownership or mode is unsafe")
        return
    if mode & 0o022:
        raise AttemptBrokerError(f"{label} ownership or mode is unsafe")
    if executable:
        if mode & 0o111 == 0:
            raise AttemptBrokerError(f"{label} ownership or mode is unsafe")
        return
    if not write_ok and mode & 0o222:
        raise AttemptBrokerError(f"{label} ownership or mode is unsafe")


def _open_directory(path: str, host: Any, label: str) -> int:
    _forbid_credential_path(path)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not directory:
        raise AttemptBrokerError("O_DIRECTORY is required")
    try:
        before = os.lstat(path)
    except OSError as suc:
        raise AttemptBrokerError(f"{label} is unreadable") from suc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise AttemptBrokerError(f"{label} is unsafe")
    _require_owner_mode(before, host, label, required_mode=DIR_MODE)
    try:
        fd = os.open(path, os.O_RDONLY | directory | _nofollow_flags())
    except OSError as suc:
        raise AttemptBrokerError(f"{label} is unreadable") from suc
    try:
        opened = os.fstat(fd)
        after = os.lstat(path)
        _require_owner_mode(opened, host, label, required_mode=DIR_MODE)
    except AttemptBrokerError:
        os.close(fd)
        raise
    except OSError as suc:
        os.close(fd)
        raise AttemptBrokerError(f"{label} is unreadable") from suc
    if (
        not stat.S_ISDIR(opened.st_mode)
        or _identity(before) != _identity(opened)
        or _identity(opened) != _identity(after)
    ):
        os.close(fd)
        raise AttemptBrokerError(f"{label} changed while being opened")
    return fd


def _stat_nofollow(path: str, *, dir_fd: int | None = None) -> os.stat_result:
    if dir_fd is None:
        return os.lstat(path)
    return os.stat(path, dir_fd=dir_fd, follow_symlinks=False)


def _leaf_name(path: str, directory: str, label: str) -> str:
    if os.path.dirname(path) != directory:
        raise AttemptBrokerError(f"{label} is unsafe")
    name = os.path.basename(path)
    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise AttemptBrokerError(f"{label} is unsafe")
    return name


def _open_proof_client_dir(host: Any, paths: Paths) -> int:
    path = paths.proof_client_dir
    _forbid_credential_path(path)
    parent = os.path.dirname(path)
    leaf = os.path.basename(path)
    if not leaf or leaf in {".", ".."} or "/" in leaf or "\x00" in leaf:
        raise AttemptBrokerError("proof client directory is unsafe")
    directory = getattr(os, "O_DIRECTORY", 0)
    if not directory:
        raise AttemptBrokerError("O_DIRECTORY is required")
    try:
        parent_before = os.lstat(parent)
        named = os.lstat(path)
    except OSError as suc:
        raise AttemptBrokerError("proof client directory is unreadable") from suc
    if stat.S_ISLNK(parent_before.st_mode) or not stat.S_ISDIR(parent_before.st_mode):
        raise AttemptBrokerError("proof client directory is unsafe")
    if stat.S_ISLNK(named.st_mode) or not stat.S_ISDIR(named.st_mode):
        raise AttemptBrokerError("proof client directory is unsafe")
    _require_owner_mode(parent_before, host, "proof client parent directory", write_ok=True)
    _require_owner_mode(named, host, "proof client directory", required_mode=DIR_MODE)
    parent_fd = -1
    child = -1
    try:
        parent_fd = os.open(parent, os.O_RDONLY | directory | _nofollow_flags())
        parent_opened = os.fstat(parent_fd)
        parent_after = os.lstat(parent)
        if (
            not stat.S_ISDIR(parent_opened.st_mode)
            or _identity(parent_before) != _identity(parent_opened)
            or _identity(parent_opened) != _identity(parent_after)
        ):
            raise AttemptBrokerError("proof client directory changed while being opened")
        _require_owner_mode(
            parent_opened, host, "proof client parent directory", write_ok=True
        )
        child = os.open(leaf, os.O_RDONLY | directory | _nofollow_flags(), dir_fd=parent_fd)
        opened = os.fstat(child)
        named_after = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if (
            stat.S_ISLNK(named_after.st_mode)
            or not stat.S_ISDIR(opened.st_mode)
            or _identity(named) != _identity(opened)
            or _identity(opened) != _identity(named_after)
        ):
            raise AttemptBrokerError("proof client directory changed while being opened")
        _require_owner_mode(opened, host, "proof client directory", required_mode=DIR_MODE)
    except AttemptBrokerError:
        if child >= 0:
            os.close(child)
        if parent_fd >= 0:
            os.close(parent_fd)
        raise
    except OSError as suc:
        if child >= 0:
            os.close(child)
        if parent_fd >= 0:
            os.close(parent_fd)
        raise AttemptBrokerError("proof client directory is unreadable") from suc
    os.close(parent_fd)
    return child


def _read_regular_bound(
    path: str,
    host: Any,
    label: str,
    *,
    required_mode: int | None = None,
    allowed_modes: frozenset[int] | None = None,
    executable: bool = False,
    dir_fd: int | None = None,
) -> tuple[bytes, tuple[int, int, int, int, int, int, int, int, int]]:
    if dir_fd is None:
        _forbid_credential_path(path)
    fd = -1
    try:
        before = _stat_nofollow(path, dir_fd=dir_fd)
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
        ):
            raise AttemptBrokerError(f"{label} is not a regular single-link file")
        _require_owner_mode(
            before,
            host,
            label,
            required_mode=required_mode,
            allowed_modes=allowed_modes,
            executable=executable,
        )
        if dir_fd is None:
            fd = os.open(path, os.O_RDONLY | _nofollow_flags())
        else:
            fd = os.open(path, os.O_RDONLY | _nofollow_flags(), dir_fd=dir_fd)
        opened = os.fstat(fd)
        _require_owner_mode(
            opened,
            host,
            label,
            required_mode=required_mode,
            allowed_modes=allowed_modes,
            executable=executable,
        )
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        finished = os.fstat(fd)
        _require_owner_mode(
            finished,
            host,
            label,
            required_mode=required_mode,
            allowed_modes=allowed_modes,
            executable=executable,
        )
        after = _stat_nofollow(path, dir_fd=dir_fd)
    except AttemptBrokerError:
        raise
    except OSError as suc:
        raise AttemptBrokerError(f"{label} is unreadable") from suc
    finally:
        if fd >= 0:
            os.close(fd)
    if not all(_identity(before) == _identity(item) for item in (opened, finished, after)):
        raise AttemptBrokerError(f"{label} changed while being read")
    if opened.st_nlink != 1 or not stat.S_ISREG(opened.st_mode):
        raise AttemptBrokerError(f"{label} is not a regular single-link file")
    data = b"".join(chunks)
    if not data:
        raise AttemptBrokerError(f"{label} is empty")
    return data, _identity(finished)


def _read_regular(
    path: str,
    host: Any,
    label: str,
    *,
    required_mode: int | None = None,
    allowed_modes: frozenset[int] | None = None,
    executable: bool = False,
    dir_fd: int | None = None,
) -> bytes:
    data, _ident = _read_regular_bound(
        path,
        host,
        label,
        required_mode=required_mode,
        allowed_modes=allowed_modes,
        executable=executable,
        dir_fd=dir_fd,
    )
    return data


def _bind_proof_leaf(
    bindings: dict[str, tuple[tuple[int, int, int, int, int, int, int, int, int], str]],
    name: str,
    data: bytes,
    ident: tuple[int, int, int, int, int, int, int, int, int],
) -> None:
    bindings[name] = (ident, sha256_bytes(data))


def _revalidate_proof_bindings(
    host: Any,
    dir_fd: int,
    bindings: dict[str, tuple[tuple[int, int, int, int, int, int, int, int, int], str]],
) -> None:
    for name, (ident, digest) in bindings.items():
        data, again = _read_regular_bound(
            name,
            host,
            f"proof client {name}",
            required_mode=PROOF_CLIENT_MODE,
            dir_fd=dir_fd,
        )
        if again != ident or sha256_bytes(data) != digest:
            raise AttemptBrokerError(f"proof client {name} changed while being used")


def run_allowlisted(host: Any, argv: Sequence[str]) -> CommandResult:
    key = tuple(argv)
    if key not in ALLOWED_COMMANDS:
        raise AttemptBrokerError("command is not allowlisted")
    result = host.run(list(argv))
    if result.exit_code == 127:
        raise AttemptBrokerError(f"absent tool {argv[0]}")
    return result


def parse_systemctl_show(data: bytes) -> dict[str, str]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as suc:
        raise AttemptBrokerError("systemctl show is not ASCII") from suc
    result: dict[str, str] = {}
    for line in text.splitlines():
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in result:
            raise AttemptBrokerError("duplicate systemctl show key")
        result[key] = value
    return result


def _unit_identity(
    host: Any,
    unit: str,
    shown: CommandResult,
    *,
    kind: str,
    expected_result: str = "success",
) -> dict[str, str]:
    if shown.exit_code != 0:
        raise AttemptBrokerError(f"unable to inspect {unit}")
    fields = parse_systemctl_show(shown.stdout)
    fragment = fields.get("FragmentPath", "")
    pid = fields.get("MainPID", "0")
    active = fields.get("ActiveState", "")
    result = fields.get("Result", "")
    exec_status = fields.get("ExecMainStatus", "")
    unit_type = fields.get("Type", "")
    if fields.get("Id") != unit or fragment not in ALLOWED_FRAGMENTS[unit]:
        raise AttemptBrokerError(f"service identity is invalid: {unit}")
    if unit_type != kind:
        raise AttemptBrokerError(f"service identity is invalid: {unit}")
    if kind == "oneshot":
        if expected_result == "success":
            if active not in {"inactive", "dead"}:
                raise AttemptBrokerError(f"service identity is invalid: {unit}")
            if result != "success" or exec_status != "0" or not pid.isdigit():
                raise AttemptBrokerError(f"service identity is invalid: {unit}")
        elif expected_result == "failed":
            if active != "failed" or result != "exit-code" or exec_status != "1":
                raise AttemptBrokerError(f"service identity is invalid: {unit}")
            if not pid.isdigit():
                raise AttemptBrokerError(f"service identity is invalid: {unit}")
        else:
            raise AttemptBrokerError(f"service identity is invalid: {unit}")
    elif kind == "simple":
        if active != "active" or not pid.isdigit() or int(pid) <= 0:
            raise AttemptBrokerError(f"service identity is invalid: {unit}")
    else:
        raise AttemptBrokerError(f"service identity is invalid: {unit}")
    executable = UNIT_EXECUTABLES[unit]
    digest = host.hash_executable(executable)
    if type(digest) is not str or not digest:
        raise AttemptBrokerError(f"executable identity is invalid: {executable}")
    return {
        "unit": unit,
        "fragment": fragment,
        "executable": executable,
        "executable_sha256": digest,
        "main_pid": pid,
    }


def load_role(host: Any, paths: Paths) -> str:
    text = (
        _read_regular(paths.role, host, "role file", required_mode=ROLE_MODE)
        .decode("ascii")
        .strip()
    )
    if text not in ALLOWED_ROLES:
        raise AttemptBrokerError("role file is invalid")
    return text


def load_fleet_binding(host: Any, paths: Paths) -> dict[str, Any]:
    record = exact_keys(
        strict_json(
            _read_regular(
                paths.fleet_binding, host, "fleet binding", required_mode=FLEET_BINDING_MODE
            ),
            "fleet binding",
        ),
        FLEET_BINDING_KEYS,
        "fleet binding",
    )
    if (
        exact_int(record["schema_version"], "fleet binding schema_version") != SCHEMA_VERSION
        or record["contract"] != FLEET_BINDING_CONTRACT
        or type(record["project"]) is not str
        or type(record["fleet_id"]) is not str
        or not FLEET_RE.fullmatch(str(record["fleet_id"]))
    ):
        raise AttemptBrokerError("fleet binding is stale")
    names: list[str] = []
    for role in ("control", "data-winn3", "data-cover"):
        member = exact_keys(record[role], MEMBER_KEYS, f"fleet binding {role}")
        instance = str(member["instance"])
        zone = str(member["zone"])
        if not INSTANCE_RE.fullmatch(instance) or not ZONE_RE.fullmatch(zone):
            raise AttemptBrokerError(f"fleet binding {role} identity is invalid")
        names.append(instance)
    if len(set(names)) != 3:
        raise AttemptBrokerError("same-node fallback is forbidden")
    return record


def _consumer_event(
    *,
    action: str,
    correlation_id: str,
    monotonic_ns: int,
    node: str,
    phase: str,
    protocol: str,
    result: str,
    session_id: str,
    utc: str,
) -> dict[str, Any]:
    event = {
        "action": action,
        "correlation_id": correlation_id,
        "monotonic_ns": monotonic_ns,
        "node": node,
        "phase": phase,
        "protocol": protocol,
        "result": result,
        "session_id": session_id,
        "utc": utc,
    }
    return exact_keys(event, ATTEMPT_EVENT_KEYS, "protocol attempt event")


def _validate_event(raw: Any, index: int) -> dict[str, Any]:
    event = exact_keys(raw, ATTEMPT_EVENT_KEYS, f"protocol attempt event {index}")
    for key in (
        "action",
        "correlation_id",
        "node",
        "phase",
        "protocol",
        "result",
        "session_id",
        "utc",
    ):
        if type(event[key]) is not str or not event[key]:
            raise AttemptBrokerError(f"protocol attempt event {index} is invalid")
        if VALUE_FORBIDDEN_RE.search(event[key]):
            raise AttemptBrokerError(f"protocol attempt event {index} is invalid")
    exact_int(event["monotonic_ns"], "attempt monotonic", minimum=0)
    parse_utc(event["utc"])
    if event["protocol"] not in ALLOWED_PROTOCOLS:
        raise AttemptBrokerError(f"protocol attempt event {index} is invalid")
    if event["phase"] not in {"started", "finished"}:
        raise AttemptBrokerError(f"protocol attempt event {index} is invalid")
    if event["phase"] == "started" and event["result"] != "pending":
        raise AttemptBrokerError(f"protocol attempt event {index} is invalid")
    if event["phase"] == "finished" and event["result"] not in FINISHED_RESULTS:
        raise AttemptBrokerError(f"protocol attempt event {index} is invalid")
    return dict(event)


def load_attempt_journal(host: Any, paths: Paths) -> dict[str, Any]:
    try:
        os.lstat(paths.journal)
    except FileNotFoundError:
        return {
            "schema_version": SCHEMA_VERSION,
            "contract": ATTEMPT_JOURNAL_CONTRACT,
            "events": [],
        }
    except OSError as suc:
        raise AttemptBrokerError("protocol attempt journal is unreadable") from suc
    record = exact_keys(
        strict_json(
            _read_regular(
                paths.journal, host, "protocol attempt journal", required_mode=JOURNAL_MODE
            ),
            "protocol attempt journal",
        ),
        ATTEMPT_JOURNAL_KEYS,
        "protocol attempt journal",
    )
    if (
        exact_int(record["schema_version"], "attempt journal schema_version")
        != SCHEMA_VERSION
        or record["contract"] != ATTEMPT_JOURNAL_CONTRACT
        or not isinstance(record["events"], list)
    ):
        raise AttemptBrokerError("protocol attempt journal contract is invalid")
    events = [_validate_event(raw, index) for index, raw in enumerate(record["events"])]
    if len(events) % 2 != 0:
        raise AttemptBrokerError("protocol attempt journal is stale")
    last_mono = -1
    last_utc: datetime | None = None
    for index in range(0, len(events), 2):
        started = events[index]
        finished = events[index + 1]
        if (
            started["phase"] != "started"
            or finished["phase"] != "finished"
            or started["protocol"] != finished["protocol"]
            or started["action"] != finished["action"]
            or started["node"] != finished["node"]
            or started["session_id"] != finished["session_id"]
            or started["correlation_id"] != finished["correlation_id"]
        ):
            raise AttemptBrokerError("protocol attempt journal is stale")
        for event in (started, finished):
            mono = exact_int(event["monotonic_ns"], "attempt monotonic", minimum=0)
            stamp = parse_utc(event["utc"])
            if mono <= last_mono:
                raise AttemptBrokerError("protocol attempt timestamps are not strictly ordered")
            if last_utc is not None and stamp <= last_utc:
                raise AttemptBrokerError("protocol attempt UTC timestamps are not strictly ordered")
            last_mono = mono
            last_utc = stamp
    return {
        "schema_version": SCHEMA_VERSION,
        "contract": ATTEMPT_JOURNAL_CONTRACT,
        "events": events,
    }


def _atomic_write_journal(host: Any, paths: Paths, payload: Mapping[str, Any]) -> None:
    encoded = canonical_bytes(payload)
    decoded = exact_keys(
        strict_json(encoded, "protocol attempt journal"),
        ATTEMPT_JOURNAL_KEYS,
        "protocol attempt journal",
    )
    if decoded != payload:
        raise AttemptBrokerError("protocol attempt journal is not canonical")
    parent_fd = _open_directory(paths.run_dir, host, "protocol attempt directory")
    name = os.path.basename(paths.journal)
    temporary = f".protocol-attempts.{os.getpid()}.{time.time_ns()}"
    fd = -1
    renamed = False
    pending: BaseException | None = None
    cleanup_error: BaseException | None = None
    try:
        try:
            existing = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if (
                stat.S_ISLNK(existing.st_mode)
                or not stat.S_ISREG(existing.st_mode)
                or existing.st_nlink != 1
            ):
                raise AttemptBrokerError(
                    "protocol attempt journal is not a regular single-link file"
                )
            _require_owner_mode(
                existing, host, "protocol attempt journal", required_mode=JOURNAL_MODE
            )
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _nofollow_flags(),
            0o600,
            dir_fd=parent_fd,
        )
        created = os.fstat(fd)
        if (
            not stat.S_ISREG(created.st_mode)
            or created.st_nlink != 1
            or stat.S_ISLNK(created.st_mode)
        ):
            raise AttemptBrokerError("protocol attempt journal is not a regular single-link file")
        view = memoryview(encoded)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(fd)
        os.fchmod(fd, JOURNAL_MODE)
        host.fchown(fd)
        os.fsync(fd)
        finished = os.fstat(fd)
        if (
            finished.st_nlink != 1
            or finished.st_uid != host.root_uid
            or finished.st_gid != host.root_gid
            or stat.S_IMODE(finished.st_mode) != JOURNAL_MODE
            or stat.S_IMODE(finished.st_mode) & 0o222
        ):
            raise AttemptBrokerError("protocol attempt journal ownership or mode is unsafe")
        os.close(fd)
        fd = -1
        os.rename(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        renamed = True
        directory_sync_error: OSError | None = None
        try:
            os.fsync(parent_fd)
        except OSError as suc:
            directory_sync_error = suc
        verify = os.open(name, os.O_RDONLY | _nofollow_flags(), dir_fd=parent_fd)
        try:
            verified = os.fstat(verify)
            named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            chunks: list[bytes] = []
            while True:
                chunk = os.read(verify, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            after = os.fstat(verify)
            named_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        finally:
            os.close(verify)
        if (
            not stat.S_ISREG(verified.st_mode)
            or stat.S_ISLNK(named.st_mode)
            or verified.st_nlink != 1
            or verified.st_uid != host.root_uid
            or verified.st_gid != host.root_gid
            or stat.S_IMODE(verified.st_mode) != JOURNAL_MODE
            or (verified.st_dev, verified.st_ino) != (finished.st_dev, finished.st_ino)
            or (named.st_dev, named.st_ino) != (finished.st_dev, finished.st_ino)
            or (named_after.st_dev, named_after.st_ino) != (finished.st_dev, finished.st_ino)
            or _identity(verified) != _identity(after)
            or b"".join(chunks) != encoded
        ):
            raise AttemptBrokerError("protocol attempt journal changed while being written")
        if directory_sync_error is not None:
            pending = AttemptBrokerError(
                "protocol attempt journal committed but directory fsync is uncertain"
            )
            pending.__cause__ = directory_sync_error
            raise pending
    except AttemptBrokerError as suc:
        pending = suc
    except OSError as suc:
        if renamed:
            pending = AttemptBrokerError(
                "protocol attempt journal committed but directory fsync is uncertain"
            )
        else:
            pending = AttemptBrokerError("protocol attempt journal write failed")
        pending.__cause__ = suc
    finally:
        if fd >= 0:
            os.close(fd)
        if not renamed:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            except OSError as suc:
                cleanup_error = AttemptBrokerError(
                    "protocol attempt journal cleanup failed"
                )
                cleanup_error.__cause__ = suc
        os.close(parent_fd)
    if cleanup_error is not None:
        raise cleanup_error
    if pending is not None:
        raise pending


def parse_request(raw: Any) -> dict[str, Any]:
    record = exact_keys(raw, ATTEMPT_REQUEST_KEYS, "protocol attempt request")
    if record["contract"] != ATTEMPT_REQUEST_CONTRACT:
        raise AttemptBrokerError("protocol attempt request contract is invalid")
    if exact_int(record["schema_version"], "request schema_version") != SCHEMA_VERSION:
        raise AttemptBrokerError("unsupported request schema version")
    for key, value in record.items():
        if key == "schema_version":
            continue
        if type(value) is not str or not value or VALUE_FORBIDDEN_RE.search(value):
            raise AttemptBrokerError(f"request {key} is invalid")
    if record["action"] not in {action for action, _protocol in ACTION_TABLE}:
        raise AttemptBrokerError("unsupported action")
    if record["protocol"] not in ALLOWED_PROTOCOLS:
        raise AttemptBrokerError("protocol attempt is not allowlisted")
    if not INSTANCE_RE.fullmatch(record["node"]):
        raise AttemptBrokerError("request node is invalid")
    if not ID_RE.fullmatch(record["session_id"]) or not ID_RE.fullmatch(
        record["correlation_id"]
    ):
        raise AttemptBrokerError("request identity is invalid")
    return record


def _require_peer_root(conn: socket.socket, host: Any) -> None:
    _pid, uid, _gid = host.peer_credentials(conn)
    if uid != 0:
        raise AttemptBrokerError("protocol attempt peer is not root")


def _require_attempt_gate(
    request: Mapping[str, Any], role: str, binding: Mapping[str, Any]
) -> dict[str, Any]:
    key = (request["action"], request["protocol"])
    if key not in ACTION_TABLE:
        raise AttemptBrokerError("protocol attempt is not allowlisted")
    spec = ACTION_TABLE[key]
    if role not in spec["allowed_roles"]:
        raise AttemptBrokerError("unexpected role")
    if role == "data-winn3" and request["protocol"] in {"awg", "xray"}:
        raise AttemptBrokerError("unexpected role")
    if role == "data-cover" and request["protocol"] == "winn3":
        raise AttemptBrokerError("unexpected role")
    expected_node = str(binding[spec["node_role"]]["instance"])
    winn3 = str(binding["data-winn3"]["instance"])
    cover = str(binding["data-cover"]["instance"])
    if winn3 == cover:
        raise AttemptBrokerError("same-node fallback is forbidden")
    if request["node"] != expected_node:
        raise AttemptBrokerError("wrong-role fallback is forbidden")
    if request["protocol"] in {"awg", "xray"} and request["node"] == winn3:
        raise AttemptBrokerError("same-node fallback is forbidden")
    if request["protocol"] == "winn3" and request["node"] == cover:
        raise AttemptBrokerError("wrong-role fallback is forbidden")
    return spec


def _replay_forbidden(events: Sequence[Mapping[str, Any]], request: Mapping[str, Any]) -> None:
    for event in events:
        if (
            event["session_id"] == request["session_id"]
            and event["correlation_id"] == request["correlation_id"]
            and event["protocol"] == request["protocol"]
            and event["action"] == request["action"]
        ):
            raise AttemptBrokerError("duplicate protocol attempt is forbidden")


def _require_fresh_awg_failure(
    events: Sequence[Mapping[str, Any]], request: Mapping[str, Any]
) -> None:
    if len(events) < 2:
        raise AttemptBrokerError("exact AWG-first fallback attempt sequence is absent")
    started = events[-2]
    finished = events[-1]
    if (
        started["protocol"] != "awg"
        or finished["protocol"] != "awg"
        or started["phase"] != "started"
        or finished["phase"] != "finished"
        or started["result"] != "pending"
        or finished["result"] != "failed"
        or started["action"] != request["action"]
        or finished["action"] != request["action"]
        or started["session_id"] != request["session_id"]
        or finished["session_id"] != request["session_id"]
        or started["correlation_id"] != request["correlation_id"]
        or finished["correlation_id"] != request["correlation_id"]
        or started["node"] != request["node"]
        or finished["node"] != request["node"]
    ):
        raise AttemptBrokerError("exact AWG-first fallback attempt sequence is absent")


def _require_fresh_protocol_failure(
    events: Sequence[Mapping[str, Any]],
    request: Mapping[str, Any],
    protocol: str,
    node: str,
) -> None:
    if len(events) < 2:
        raise AttemptBrokerError("required failed protocol attempt is absent")
    started = events[-2]
    finished = events[-1]
    if (
        started["protocol"] != protocol
        or finished["protocol"] != protocol
        or started["phase"] != "started"
        or finished["phase"] != "finished"
        or started["result"] != "pending"
        or finished["result"] != "failed"
        or started["action"] != request["action"]
        or finished["action"] != request["action"]
        or started["session_id"] != request["session_id"]
        or finished["session_id"] != request["session_id"]
        or started["correlation_id"] != request["correlation_id"]
        or finished["correlation_id"] != request["correlation_id"]
        or started["node"] != node
        or finished["node"] != node
    ):
        raise AttemptBrokerError("required failed protocol attempt is absent")
def _is_active(result: CommandResult) -> bool:
    if result.stderr.strip():
        raise AttemptBrokerError("unit active-state probe failed")
    try:
        state = result.stdout.decode("ascii").strip()
    except UnicodeDecodeError as suc:
        raise AttemptBrokerError("unit active-state probe is not ASCII") from suc
    if result.exit_code not in {0, 3}:
        raise AttemptBrokerError("unit active-state probe failed")
    if state == "active":
        if result.exit_code != 0:
            raise AttemptBrokerError("unit active-state probe failed")
        return True
    if state == "inactive" and result.exit_code == 3:
        return False
    raise AttemptBrokerError("unit active-state probe failed")


def _awg_handshake_completed(data: bytes) -> bool:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as suc:
        raise AttemptBrokerError("AWG handshake output is not ASCII") from suc
    if not text.strip():
        raise AttemptBrokerError("AWG handshake evidence is absent")
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 2 or not fields[1].isdigit():
            raise AttemptBrokerError("AWG handshake output is malformed")
        stamp = int(fields[1])
        if stamp > 0:
            return True
    return False


def _placeholder_token(value: str) -> bool:
    if type(value) is not str or len(value) < 8:
        return True
    body = value.rstrip("=")
    return not body or len(set(body.lower())) < 2


def _require_ipv4(value: str, label: str) -> str:
    if type(value) is not str or not value or VALUE_FORBIDDEN_RE.search(value):
        raise AttemptBrokerError(f"{label} is unprovisioned")
    try:
        address = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, ValueError) as suc:
        raise AttemptBrokerError(f"{label} is unprovisioned") from suc
    if address.is_multicast or address.is_unspecified:
        raise AttemptBrokerError(f"{label} is unprovisioned")
    return value


def _require_outer_ipv4(value: str, label: str) -> str:
    address_text = _require_ipv4(value, label)
    address = ipaddress.IPv4Address(address_text)
    if address.is_loopback or address.is_link_local or address.is_reserved:
        raise AttemptBrokerError(f"{label} is unprovisioned")
    for network in DOCUMENTATION_NETWORKS:
        if address in network:
            raise AttemptBrokerError(f"{label} is unprovisioned")
    return address_text


def _require_ipv4_port(value: str, label: str) -> None:
    if type(value) is not str or ":" not in value or VALUE_FORBIDDEN_RE.search(value):
        raise AttemptBrokerError(f"{label} is unprovisioned")
    host, port_text = value.rsplit(":", 1)
    _require_outer_ipv4(host, label)
    if not port_text.isdigit():
        raise AttemptBrokerError(f"{label} is unprovisioned")
    port = int(port_text)
    if port < 1 or port > 65535:
        raise AttemptBrokerError(f"{label} is unprovisioned")


def _parse_env_file(data: bytes, keys: Sequence[str], label: str) -> dict[str, str]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as suc:
        raise AttemptBrokerError(f"{label} is not ASCII") from suc
    if not text.strip():
        raise AttemptBrokerError(f"{label} is unprovisioned")
    parsed: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = ENV_LINE_RE.fullmatch(line)
        if match is None:
            raise AttemptBrokerError(f"{label} is unprovisioned")
        key, value = match.group(1), match.group(2)
        if key in parsed or VALUE_FORBIDDEN_RE.search(value):
            raise AttemptBrokerError(f"{label} is unprovisioned")
        parsed[key] = value
    expected = set(keys)
    if set(parsed) != expected:
        raise AttemptBrokerError(f"{label} is unprovisioned")
    for key in keys:
        if not parsed[key]:
            raise AttemptBrokerError(f"{label} is unprovisioned")
    return parsed


def _require_hex_file(
    host: Any,
    path: str,
    size: int,
    pattern: re.Pattern[str],
    label: str,
    *,
    dir_fd: int,
    bindings: dict[str, tuple[tuple[int, int, int, int, int, int, int, int, int], str]],
) -> str:
    data, ident = _read_regular_bound(
        path, host, label, required_mode=PROOF_CLIENT_MODE, dir_fd=dir_fd
    )
    _bind_proof_leaf(bindings, path, data, ident)
    if len(data) != size:
        raise AttemptBrokerError(f"{label} is unprovisioned")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as suc:
        raise AttemptBrokerError(f"{label} is unprovisioned") from suc
    if pattern.fullmatch(text) is None:
        raise AttemptBrokerError(f"{label} is unprovisioned")
    return text


def _require_config_file(
    host: Any,
    path: str,
    label: str,
    *,
    dir_fd: int,
    bindings: dict[str, tuple[tuple[int, int, int, int, int, int, int, int, int], str]],
) -> bytes:
    name = path
    data, ident = _read_regular_bound(
        name, host, label, required_mode=PROOF_CLIENT_MODE, dir_fd=dir_fd
    )
    _bind_proof_leaf(bindings, name, data, ident)
    if len(data) < 16:
        raise AttemptBrokerError(f"{label} is unprovisioned")
    return data


def _require_awg_key(value: str, label: str) -> str:
    if type(value) is not str or AWG_PEER_RE.fullmatch(value) is None or _placeholder_token(value):
        raise AttemptBrokerError(f"{label} is unprovisioned")
    return value


def _parse_awg_client_conf(data: bytes) -> dict[str, str]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as suc:
        raise AttemptBrokerError("AWG client config is not ASCII") from suc
    section = ""
    parsed: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line in {"[Interface]", "[Peer]"}:
            section = line[1:-1]
            continue
        if " = " not in line or not section:
            raise AttemptBrokerError("AWG client config is unprovisioned")
        key, value = line.split(" = ", 1)
        field = f"{section}.{key}"
        if field in parsed or not value or VALUE_FORBIDDEN_RE.search(value):
            raise AttemptBrokerError("AWG client config is unprovisioned")
        parsed[field] = value
    required = {
        "Interface.Address",
        "Interface.PrivateKey",
        "Peer.PublicKey",
        "Peer.Endpoint",
        "Peer.AllowedIPs",
    }
    if required - set(parsed):
        raise AttemptBrokerError("AWG client config is unprovisioned")
    if parsed["Interface.Address"] != PROOF_CLIENT_INNER_V4 + "/32":
        raise AttemptBrokerError("AWG client config is unprovisioned")
    if parsed["Peer.AllowedIPs"] != "0.0.0.0/0":
        raise AttemptBrokerError("AWG client config is unprovisioned")
    private_key = _require_awg_key(parsed["Interface.PrivateKey"], "AWG private key")
    public_key = _require_awg_key(parsed["Peer.PublicKey"], "AWG peer public key")
    if private_key == public_key:
        raise AttemptBrokerError("AWG client config is unprovisioned")
    _require_ipv4_port(parsed["Peer.Endpoint"], "AWG endpoint")
    return parsed


def _require_provisioned_xray_client(data: bytes) -> None:
    raw = strict_json(data, "Xray client config")
    if not isinstance(raw, dict):
        raise AttemptBrokerError("Xray client config is unprovisioned")
    inbounds = raw.get("inbounds")
    outbounds = raw.get("outbounds")
    if not isinstance(inbounds, list) or not isinstance(outbounds, list):
        raise AttemptBrokerError("Xray client config is unprovisioned")
    has_tun = False
    for item in inbounds:
        if not isinstance(item, dict):
            raise AttemptBrokerError("Xray client config is unprovisioned")
        settings = item.get("settings")
        if item.get("protocol") == "tun" and isinstance(settings, dict) and settings.get("name") == "xray0":
            has_tun = True
    has_proxy = False
    for item in outbounds:
        if not isinstance(item, dict):
            raise AttemptBrokerError("Xray client config is unprovisioned")
        if item.get("protocol") in {"vless", "vmess", "trojan"}:
            settings = item.get("settings")
            if not isinstance(settings, dict):
                raise AttemptBrokerError("Xray client config is unprovisioned")
            vnext = settings.get("vnext")
            if not isinstance(vnext, list) or len(vnext) != 1 or not isinstance(vnext[0], dict):
                raise AttemptBrokerError("Xray client config is unprovisioned")
            address = vnext[0].get("address")
            port = vnext[0].get("port")
            users = vnext[0].get("users")
            if type(port) is not int or port < 1 or port > 65535:
                raise AttemptBrokerError("Xray client config is unprovisioned")
            _require_outer_ipv4(str(address), "Xray outbound address")
            if not isinstance(users, list) or len(users) != 1 or not isinstance(users[0], dict):
                raise AttemptBrokerError("Xray client config is unprovisioned")
            user_id = users[0].get("id")
            if type(user_id) is not str or UUID_RE.fullmatch(user_id) is None:
                raise AttemptBrokerError("Xray client config is unprovisioned")
            has_proxy = True
    if not has_tun or not has_proxy:
        raise AttemptBrokerError("Xray client config is unprovisioned")


def _require_winn3_material(
    host: Any,
    paths: Paths,
    binding: Mapping[str, Any],
    dir_fd: int,
    bindings: dict[str, tuple[tuple[int, int, int, int, int, int, int, int, int], str]],
) -> dict[str, str]:
    pubs: dict[str, str] = {}
    for name, size, pattern in PROOF_CLIENT_FILES:
        pubs[name] = _require_hex_file(
            host,
            name,
            size,
            pattern,
            f"proof client {name}",
            dir_fd=dir_fd,
            bindings=bindings,
        )
    env_name = _leaf_name(paths.winn3_probe_env, paths.proof_client_dir, "Winn3 probe env")
    env_data, env_ident = _read_regular_bound(
        env_name,
        host,
        "Winn3 probe env",
        required_mode=PROOF_CLIENT_MODE,
        dir_fd=dir_fd,
    )
    _bind_proof_leaf(bindings, env_name, env_data, env_ident)
    env = _parse_env_file(env_data, WINN3_PROBE_ENV_KEYS, "Winn3 probe env")
    _require_ipv4_port(env["WINN3_PROOF_GW"], "Winn3 probe gateway")
    expected_id = str(binding["data-winn3"]["instance"])
    if env["WINN3_PROOF_GATEWAY_ID"] != expected_id or not ID_RE.fullmatch(env["WINN3_PROOF_GATEWAY_ID"]):
        raise AttemptBrokerError("Winn3 probe env is unprovisioned")
    if HEX64_RE.fullmatch(env["WINN3_PROOF_ED_PUB"]) is None:
        raise AttemptBrokerError("Winn3 probe env is unprovisioned")
    if HEX3904_RE.fullmatch(env["WINN3_PROOF_ML_PUB"]) is None:
        raise AttemptBrokerError("Winn3 probe env is unprovisioned")
    if not hmac.compare_digest(env["WINN3_PROOF_ED_PUB"], pubs["auth_ed25519.pub"]):
        raise AttemptBrokerError("Winn3 probe env is unprovisioned")
    if not hmac.compare_digest(env["WINN3_PROOF_ML_PUB"], pubs["auth_mldsa65.pub"]):
        raise AttemptBrokerError("Winn3 probe env is unprovisioned")
    return env


def _require_awg_material(
    host: Any,
    paths: Paths,
    dir_fd: int,
    bindings: dict[str, tuple[tuple[int, int, int, int, int, int, int, int, int], str]],
) -> None:
    name = _leaf_name(paths.awg_client_conf, paths.proof_client_dir, "AWG client config")
    _parse_awg_client_conf(
        _require_config_file(
            host, name, "AWG client config", dir_fd=dir_fd, bindings=bindings
        )
    )


def _require_xray_material(
    host: Any,
    paths: Paths,
    dir_fd: int,
    bindings: dict[str, tuple[tuple[int, int, int, int, int, int, int, int, int], str]],
) -> dict[str, str]:
    conf_name = _leaf_name(
        paths.xray_client_conf, paths.proof_client_dir, "Xray client config"
    )
    _require_provisioned_xray_client(
        _require_config_file(
            host, conf_name, "Xray client config", dir_fd=dir_fd, bindings=bindings
        )
    )
    env_name = _leaf_name(paths.xray_probe_env, paths.proof_client_dir, "Xray probe env")
    env_data, env_ident = _read_regular_bound(
        env_name,
        host,
        "Xray probe env",
        required_mode=PROOF_CLIENT_MODE,
        dir_fd=dir_fd,
    )
    _bind_proof_leaf(bindings, env_name, env_data, env_ident)
    env = _parse_env_file(env_data, XRAY_PROBE_ENV_KEYS, "Xray probe env")
    _require_ipv4(env["XRAY_PROOF_PEER"], "Xray probe peer")
    if env["XRAY_PROOF_PEER"] != PROOF_GATEWAY_INNER_V4:
        raise AttemptBrokerError("Xray probe env is unprovisioned")
    return env


_STOP_ACTIVE = {
    ARGV_SYSTEMCTL_STOP_AWG_CLIENT: ARGV_SYSTEMCTL_ACTIVE_AWG_CLIENT,
    ARGV_SYSTEMCTL_STOP_XRAY_CLIENT: ARGV_SYSTEMCTL_ACTIVE_XRAY_CLIENT,
}


def _stop_unit(host: Any, argv: Sequence[str]) -> None:
    result = run_allowlisted(host, argv)
    if result.exit_code != 0:
        raise AttemptBrokerError(f"unable to stop {argv[-1]}")
    active = _STOP_ACTIVE.get(tuple(argv))
    if active is None:
        return
    if _is_active(run_allowlisted(host, active)):
        raise AttemptBrokerError(f"{argv[-1]} remained active")


def _stop_runtime_units(host: Any, protocol: str) -> None:
    if protocol == "awg":
        _stop_unit(host, ARGV_SYSTEMCTL_STOP_AWG_CLIENT)
        return
    if protocol == "xray":
        errors: list[BaseException] = []
        for argv in (ARGV_SYSTEMCTL_STOP_XRAY_PROBE, ARGV_SYSTEMCTL_STOP_XRAY_CLIENT):
            try:
                _stop_unit(host, argv)
            except AttemptBrokerError as suc:
                errors.append(suc)
        if errors:
            raise AttemptBrokerError("runtime cleanup failed") from errors[0]
        return
    if protocol == "winn3":
        _stop_unit(host, ARGV_SYSTEMCTL_STOP_WINN3_PROBE)


def _cleanup_runtime(host: Any, protocol: str) -> None:
    try:
        _stop_runtime_units(host, protocol)
    except AttemptBrokerError as suc:
        raise AttemptBrokerError("runtime cleanup failed") from suc


def _wait_link(host: Any, argv: Sequence[str], label: str) -> CommandResult:
    attempts = 1 if getattr(host, "TEST_ONLY", False) is True else IFACE_WAIT_ATTEMPTS
    last: CommandResult | None = None
    for _unused in range(attempts):
        last = run_allowlisted(host, argv)
        if last.exit_code == 0:
            return last
        time.sleep(IFACE_WAIT_SECONDS)
    if last is None or last.exit_code != 0:
        raise AttemptBrokerError(f"absent {label}")
    return last


def _parse_winn3_witness(data: bytes) -> dict[str, str]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as suc:
        raise AttemptBrokerError("Winn3 probe evidence is not ASCII") from suc
    if not text.strip():
        raise AttemptBrokerError("Winn3 probe evidence is absent")
    dialed = None
    sent = None
    recv = None
    counts = None
    stats = None
    handshake = None
    reply = False
    for line in text.splitlines():
        match = WINN3_DIALED_RE.fullmatch(line)
        if match is not None:
            dialed = match
            continue
        match = WINN3_SENT_RE.fullmatch(line)
        if match is not None:
            sent = match.group(1)
            continue
        match = WINN3_RECV_RE.fullmatch(line)
        if match is not None:
            recv = match.group(1)
            continue
        match = WINN3_COUNTS_RE.fullmatch(line)
        if match is not None:
            counts = match
            continue
        match = WINN3_STATS_RE.fullmatch(line)
        if match is not None:
            stats = match
            continue
        match = WINN3_HANDSHAKE_RE.fullmatch(line)
        if match is not None:
            handshake = match
            continue
        if WINN3_REPLY_RE.fullmatch(line):
            reply = True
    if dialed is None or sent is None or recv is None or counts is None or stats is None:
        raise AttemptBrokerError("Winn3 request and response witnesses are absent")
    if handshake is None or not reply:
        raise AttemptBrokerError("Winn3 handshake evidence is absent")
    inner = dialed.group(3)
    if inner != PROOF_CLIENT_INNER_V4:
        raise AttemptBrokerError("Winn3 inner identity is invalid")
    sent_count = int(counts.group(1))
    recv_count = int(counts.group(2))
    tx = int(stats.group(1))
    rx = int(stats.group(2))
    if sent_count <= 0 or recv_count <= 0 or tx <= 0 or rx <= 0:
        raise AttemptBrokerError("Winn3 carried-byte evidence is absent")
    if not sent.strip() or not recv.strip():
        raise AttemptBrokerError("Winn3 probe evidence is invalid")
    if PROOF_CLIENT_INNER_V4 not in sent or PROOF_CLIENT_INNER_V4 not in recv:
        raise AttemptBrokerError("Winn3 inner identity is invalid")
    peer = f"{dialed.group(1)}:{dialed.group(2)}"
    _require_ipv4_port(peer, "Winn3 remote peer")
    epoch = handshake.group(1)
    session_state = handshake.group(2)
    if not session_state or VALUE_FORBIDDEN_RE.search(session_state):
        raise AttemptBrokerError("Winn3 handshake evidence is absent")
    return {
        "bytes_rx": str(rx),
        "bytes_tx": str(tx),
        "peer_identity": peer,
        "request_witness": sent,
        "response_witness": recv,
        "session_evidence": f"carrying-epoch-{epoch}-{session_state}",
    }


def _parse_winn3_failed_witness(data: bytes) -> dict[str, str]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as suc:
        raise AttemptBrokerError("Winn3 failed probe evidence is not ASCII") from suc
    dialed = None
    absent = None
    for line in text.splitlines():
        matched_dialed = WINN3_DIALED_RE.fullmatch(line)
        if matched_dialed is not None:
            if dialed is not None:
                raise AttemptBrokerError("Winn3 failed probe evidence is malformed")
            dialed = matched_dialed
            continue
        matched_absent = WINN3_HANDSHAKE_ABSENT_RE.fullmatch(line)
        if matched_absent is not None:
            if absent is not None:
                raise AttemptBrokerError("Winn3 failed probe evidence is malformed")
            absent = matched_absent
            continue
        if (
            WINN3_HANDSHAKE_RE.fullmatch(line)
            or WINN3_REPLY_RE.fullmatch(line)
            or WINN3_SENT_RE.fullmatch(line)
            or WINN3_RECV_RE.fullmatch(line)
            or WINN3_COUNTS_RE.fullmatch(line)
            or WINN3_STATS_RE.fullmatch(line)
        ):
            raise AttemptBrokerError("Winn3 failed probe evidence contradicts failure")
        if line:
            raise AttemptBrokerError("Winn3 failed probe evidence is malformed")
    if dialed is None or absent is None:
        raise AttemptBrokerError("Winn3 failed handshake witness is absent")
    inner = dialed.group(3)
    if inner != PROOF_CLIENT_INNER_V4:
        raise AttemptBrokerError("Winn3 inner identity is invalid")
    peer = f"{dialed.group(1)}:{dialed.group(2)}"
    _require_ipv4_port(peer, "Winn3 remote peer")
    state = absent.group(1)
    wait = absent.group(2)
    if state == "carrying":
        raise AttemptBrokerError("Winn3 failed probe evidence contradicts failure")
    return {
        "bytes_rx": "0",
        "bytes_tx": "0",
        "peer_identity": peer,
        "request_witness": f"handshake-attempt:{peer}",
        "response_witness": f"handshake-absent:{wait}",
        "session_evidence": f"handshake-absent-{state}",
    }


def _parse_awg_peer_bytes(data: bytes, label: str) -> tuple[str, int, int]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as suc:
        raise AttemptBrokerError(f"{label} is not ASCII") from suc
    if not text.strip():
        raise AttemptBrokerError(f"{label} is absent")
    peer = ""
    rx = -1
    tx = -1
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 3 or not AWG_PEER_RE.fullmatch(fields[0]):
            raise AttemptBrokerError(f"{label} is malformed")
        if not fields[1].isdigit() or not fields[2].isdigit():
            raise AttemptBrokerError(f"{label} is malformed")
        if peer:
            raise AttemptBrokerError(f"{label} is malformed")
        peer = fields[0]
        rx = int(fields[1])
        tx = int(fields[2])
    if not peer or rx < 0 or tx < 0:
        raise AttemptBrokerError(f"{label} is absent")
    return peer, rx, tx


def _parse_awg_endpoints(data: bytes) -> tuple[str, str]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as suc:
        raise AttemptBrokerError("AWG endpoint output is not ASCII") from suc
    if not text.strip():
        raise AttemptBrokerError("AWG endpoint evidence is absent")
    peer = ""
    endpoint = ""
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 2 or not AWG_PEER_RE.fullmatch(fields[0]):
            raise AttemptBrokerError("AWG endpoint output is malformed")
        if peer:
            raise AttemptBrokerError("AWG endpoint output is malformed")
        peer = fields[0]
        endpoint = fields[1]
        if endpoint != "(none)":
            _require_ipv4_port(endpoint, "AWG remote peer")
    if not peer or not endpoint:
        raise AttemptBrokerError("AWG endpoint evidence is absent")
    return peer, endpoint


def _parse_ip_link_stats(data: bytes, iface: str) -> tuple[int, int]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as suc:
        raise AttemptBrokerError("interface stats are not ASCII") from suc
    if iface not in text:
        raise AttemptBrokerError("Xray tun xray0 is absent")
    rx_bytes: int | None = None
    tx_bytes: int | None = None
    expecting = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("RX:"):
            expecting = "rx"
            continue
        if stripped.startswith("TX:"):
            expecting = "tx"
            continue
        if expecting and stripped:
            fields = stripped.split()
            if not fields or not fields[0].isdigit():
                raise AttemptBrokerError("interface stats are malformed")
            value = int(fields[0])
            if expecting == "rx":
                rx_bytes = value
            else:
                tx_bytes = value
            expecting = ""
    if rx_bytes is None or tx_bytes is None:
        raise AttemptBrokerError("interface stats are absent")
    return rx_bytes, tx_bytes


def _parse_ping_witness(data: bytes) -> tuple[int, int, str]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as suc:
        raise AttemptBrokerError("Xray probe evidence is not ASCII") from suc
    if not text.strip():
        raise AttemptBrokerError("Xray probe evidence is absent")
    summary = None
    peer = ""
    for line in text.splitlines():
        if line.startswith("PING "):
            fields = line.split()
            if len(fields) < 2:
                raise AttemptBrokerError("Xray probe evidence is malformed")
            peer = fields[1]
        match = PING_SUMMARY_RE.search(line)
        if match is not None:
            summary = match
    if summary is None:
        raise AttemptBrokerError("Xray request and response witnesses are absent")
    transmitted = int(summary.group(1))
    received = int(summary.group(2))
    if transmitted <= 0 or received <= 0:
        raise AttemptBrokerError("Xray carried-byte evidence is absent")
    _require_ipv4(peer, "Xray remote peer")
    return transmitted, received, peer


def _exercise_winn3(
    host: Any, spec: Mapping[str, Any], paths: Paths, binding: Mapping[str, Any]
) -> dict[str, str]:
    started = False
    proof_fd = -1
    bindings: dict[str, tuple[tuple[int, int, int, int, int, int, int, int, int], str]] = {}
    try:
        proof_fd = _open_proof_client_dir(host, paths)
        env = _require_winn3_material(host, paths, binding, proof_fd, bindings)
        # systemd EnvironmentFile reopens the production path. A root-owned
        # 0700 proof-client directory whose parent is not group/world-writable
        # cannot be replaced by a non-root process; leaves are re-read via
        # openat/O_NOFOLLOW from the held directory fd immediately before start.
        _revalidate_proof_bindings(host, proof_fd, bindings)
        started_unit = run_allowlisted(host, ARGV_SYSTEMCTL_START_WINN3_PROBE)
        started = True
        expected_result = str(spec["finished_result"])
        if expected_result == "connected" and started_unit.exit_code != 0:
            raise AttemptBrokerError("Winn v3 action path failed")
        if expected_result == "failed" and started_unit.exit_code == 0:
            raise AttemptBrokerError("Winn v3 failure contradicted by a successful probe")
        identity = _unit_identity(
            host,
            spec["unit"],
            run_allowlisted(host, ARGV_SYSTEMCTL_SHOW_WINN3_PROBE),
            kind="oneshot",
            expected_result="failed" if expected_result == "failed" else "success",
        )
        if identity["executable"] != spec["executable"]:
            raise AttemptBrokerError("Winn v3 executable identity is invalid")
        probe_evidence = _read_regular(
            paths.winn3_probe_out,
            host,
            "Winn3 probe evidence",
            allowed_modes=PROBE_OUT_MODES,
        )
        witness = (
            _parse_winn3_failed_witness(probe_evidence)
            if expected_result == "failed"
            else _parse_winn3_witness(probe_evidence)
        )
        if witness["peer_identity"] != env["WINN3_PROOF_GW"]:
            raise AttemptBrokerError("Winn3 remote peer is inconsistent")
        identity.update(witness)
        return identity
    except Exception:
        if started:
            _cleanup_runtime(host, "winn3")
        raise
    finally:
        if proof_fd >= 0:
            os.close(proof_fd)


def _exercise_awg(host: Any, spec: Mapping[str, Any], paths: Paths) -> dict[str, str]:
    started = False
    proof_fd = -1
    bindings: dict[str, tuple[tuple[int, int, int, int, int, int, int, int, int], str]] = {}
    try:
        proof_fd = _open_proof_client_dir(host, paths)
        _require_awg_material(host, paths, proof_fd, bindings)
        if _is_active(run_allowlisted(host, ARGV_SYSTEMCTL_ACTIVE_AWG_CLIENT)):
            raise AttemptBrokerError("leftover AWG client is forbidden")
        _revalidate_proof_bindings(host, proof_fd, bindings)
        started_unit = run_allowlisted(host, ARGV_SYSTEMCTL_START_AWG_CLIENT)
        started = True
        if started_unit.exit_code != 0:
            raise AttemptBrokerError("absent AWG service")
        identity = _unit_identity(
            host,
            spec["unit"],
            run_allowlisted(host, ARGV_SYSTEMCTL_SHOW_AWG_CLIENT),
            kind="simple",
        )
        if identity["executable"] != spec["executable"]:
            raise AttemptBrokerError("AWG executable identity is invalid")
        # awg setconf reopens the production path. The held directory fd plus a
        # root-owned 0700 proof-client directory whose parent is not
        # group/world-writable prevent non-root replacement of that inode.
        _revalidate_proof_bindings(host, proof_fd, bindings)
        configured = run_allowlisted(host, ARGV_AWG_SETCONF)
        if configured.exit_code != 0:
            raise AttemptBrokerError("absent AWG client config")
        link_up = run_allowlisted(host, ARGV_IP_LINK_UP_AWG)
        if link_up.exit_code != 0:
            raise AttemptBrokerError("absent AWG interface")
        link = _wait_link(host, ARGV_IP_LINK_AWG, "AWG interface")
        if AWG_IFACE.encode("ascii") not in link.stdout:
            raise AttemptBrokerError("absent AWG interface")
        handshake = run_allowlisted(host, ARGV_AWG_HANDSHAKES)
        if handshake.exit_code != 0:
            raise AttemptBrokerError("absent AWG interface")
        handshake_completed = _awg_handshake_completed(handshake.stdout)
        if spec["finished_result"] == "connected" and not handshake_completed:
            raise AttemptBrokerError("AWG connected attempt lacks a handshake")
        if spec["finished_result"] == "failed" and handshake_completed:
            raise AttemptBrokerError("AWG failure contradicted by an in-window handshake")
        transfer = run_allowlisted(host, ARGV_AWG_TRANSFER)
        if transfer.exit_code != 0:
            raise AttemptBrokerError("AWG transfer evidence is absent")
        peer, rx, tx = _parse_awg_peer_bytes(transfer.stdout, "AWG transfer")
        endpoints = run_allowlisted(host, ARGV_AWG_ENDPOINTS)
        if endpoints.exit_code != 0:
            raise AttemptBrokerError("AWG endpoint evidence is absent")
        endpoint_peer, endpoint = _parse_awg_endpoints(endpoints.stdout)
        if endpoint_peer != peer:
            raise AttemptBrokerError("AWG peer identity is inconsistent")
        if spec["finished_result"] == "connected" and (rx <= 0 or tx <= 0):
            raise AttemptBrokerError("AWG carried-byte evidence is absent")
        identity.update(
            {
                "bytes_rx": str(rx),
                "bytes_tx": str(tx),
                "peer_identity": peer,
                "request_witness": "awg-latest-handshakes",
                "response_witness": handshake.stdout.decode("ascii").strip(),
                "session_evidence": (
                    f"awg-handshake-connected:{endpoint}"
                    if handshake_completed
                    else f"awg-handshake-absent:{endpoint}"
                ),
            }
        )
        _stop_runtime_units(host, "awg")
        return identity
    except Exception:
        if started:
            _cleanup_runtime(host, "awg")
        raise
    finally:
        if proof_fd >= 0:
            os.close(proof_fd)


def _exercise_xray(host: Any, spec: Mapping[str, Any], paths: Paths) -> dict[str, str]:
    started = False
    proof_fd = -1
    bindings: dict[str, tuple[tuple[int, int, int, int, int, int, int, int, int], str]] = {}
    try:
        proof_fd = _open_proof_client_dir(host, paths)
        env = _require_xray_material(host, paths, proof_fd, bindings)
        if _is_active(run_allowlisted(host, ARGV_SYSTEMCTL_ACTIVE_XRAY_SERVER)):
            raise AttemptBrokerError("background Xray is forbidden")
        if _is_active(run_allowlisted(host, ARGV_SYSTEMCTL_ACTIVE_XRAY_CLIENT)):
            raise AttemptBrokerError("background Xray is forbidden")
        _revalidate_proof_bindings(host, proof_fd, bindings)
        started_unit = run_allowlisted(host, ARGV_SYSTEMCTL_START_XRAY_CLIENT)
        started = True
        if started_unit.exit_code != 0:
            raise AttemptBrokerError("Xray action path failed")
        identity = _unit_identity(
            host,
            spec["unit"],
            run_allowlisted(host, ARGV_SYSTEMCTL_SHOW_XRAY_CLIENT),
            kind="simple",
        )
        if identity["executable"] != spec["executable"]:
            raise AttemptBrokerError("Xray executable identity is invalid")
        link = _wait_link(host, ARGV_IP_LINK_XRAY, "Xray tun xray0")
        if XRAY_IFACE.encode("ascii") not in link.stdout:
            raise AttemptBrokerError("Xray tun xray0 is absent")
        _revalidate_proof_bindings(host, proof_fd, bindings)
        probe = run_allowlisted(host, ARGV_SYSTEMCTL_START_XRAY_PROBE)
        if probe.exit_code != 0:
            raise AttemptBrokerError("Xray action path failed")
        _unit_identity(
            host,
            UNIT_XRAY_PROBE,
            run_allowlisted(host, ARGV_SYSTEMCTL_SHOW_XRAY_PROBE),
            kind="oneshot",
        )
        transmitted, received, peer = _parse_ping_witness(
            _read_regular(
                paths.xray_probe_out,
                host,
                "Xray probe evidence",
                allowed_modes=PROBE_OUT_MODES,
            )
        )
        if peer != env["XRAY_PROOF_PEER"]:
            raise AttemptBrokerError("Xray remote peer is inconsistent")
        stats = run_allowlisted(host, ARGV_IP_STATS_XRAY)
        if stats.exit_code != 0:
            raise AttemptBrokerError("Xray tun xray0 is absent")
        rx, tx = _parse_ip_link_stats(stats.stdout, XRAY_IFACE)
        if rx <= 0 or tx <= 0:
            raise AttemptBrokerError("Xray carried-byte evidence is absent")
        identity.update(
            {
                "bytes_rx": str(rx),
                "bytes_tx": str(tx),
                "peer_identity": peer,
                "request_witness": f"ping-transmitted-{transmitted}",
                "response_witness": f"ping-received-{received}",
                "session_evidence": "xray0-bidirectional",
            }
        )
        _stop_runtime_units(host, "xray")
        return identity
    except Exception:
        if started:
            _cleanup_runtime(host, "xray")
        raise
    finally:
        if proof_fd >= 0:
            os.close(proof_fd)


def _exercise(
    host: Any,
    protocol: str,
    spec: Mapping[str, Any],
    paths: Paths,
    binding: Mapping[str, Any],
) -> dict[str, str]:
    if protocol == "winn3":
        return _exercise_winn3(host, spec, paths, binding)
    if protocol == "awg":
        return _exercise_awg(host, spec, paths)
    if protocol == "xray":
        return _exercise_xray(host, spec, paths)
    raise AttemptBrokerError("protocol attempt is not allowlisted")


def execute_attempt(payload: bytes, host: Any, paths: Paths) -> dict[str, Any]:
    if len(payload) == 0 or len(payload) > MAX_REQUEST:
        raise AttemptBrokerError("protocol attempt request is too large")
    request = parse_request(strict_json(payload, "protocol attempt request"))
    role = load_role(host, paths)
    binding = load_fleet_binding(host, paths)
    spec = _require_attempt_gate(request, role, binding)
    with _JOURNAL_LOCK:
        journal = load_attempt_journal(host, paths)
        events = list(journal["events"])
        _replay_forbidden(events, request)
        if request["action"] == "probe-awg-block" and request["protocol"] == "xray":
            _require_fresh_awg_failure(events, request)
        if request["action"] == "probe-winn3-block" and request["protocol"] == "awg":
            _require_fresh_protocol_failure(
                events,
                request,
                "winn3",
                str(binding["data-winn3"]["instance"]),
            )
        directory_fd = _open_directory(paths.run_dir, host, "protocol attempt directory")
        os.close(directory_fd)
        started_mono = host.monotonic_ns()
        started_utc = host.utc_now()
        identity = _exercise(host, request["protocol"], spec, paths, binding)
        try:
            finished_mono = host.monotonic_ns()
            finished_utc = host.utc_now()
            if not (started_mono < finished_mono):
                raise AttemptBrokerError("protocol attempt timestamps are not strictly ordered")
            if parse_utc(finished_utc) <= parse_utc(started_utc):
                raise AttemptBrokerError("protocol attempt UTC timestamps are not strictly ordered")
            if events:
                last = events[-1]
                if started_mono <= exact_int(last["monotonic_ns"], "attempt monotonic", minimum=0):
                    raise AttemptBrokerError("protocol attempt timestamps are not strictly ordered")
                if parse_utc(started_utc) <= parse_utc(last["utc"]):
                    raise AttemptBrokerError(
                        "protocol attempt UTC timestamps are not strictly ordered"
                    )
            if identity["unit"] != spec["unit"] or identity["executable"] != spec["executable"]:
                raise AttemptBrokerError("executable/unit identity is invalid")
            for key in (
                "bytes_rx",
                "bytes_tx",
                "peer_identity",
                "request_witness",
                "response_witness",
                "session_evidence",
            ):
                value = identity.get(key)
                if type(value) is not str or not value:
                    raise AttemptBrokerError("protocol attempt witnesses are absent")
            started_event = _consumer_event(
                action=request["action"],
                correlation_id=request["correlation_id"],
                monotonic_ns=started_mono,
                node=request["node"],
                phase="started",
                protocol=request["protocol"],
                result="pending",
                session_id=request["session_id"],
                utc=started_utc,
            )
            finished_event = _consumer_event(
                action=request["action"],
                correlation_id=request["correlation_id"],
                monotonic_ns=finished_mono,
                node=request["node"],
                phase="finished",
                protocol=request["protocol"],
                result=spec["finished_result"],
                session_id=request["session_id"],
                utc=finished_utc,
            )
            # Role, executable/unit identity, and outcome are bound at event time
            # from the role file and closed action table. They are not journal
            # fields: the helper consumer uses exact ATTEMPT_EVENT_KEYS. The
            # helper request has no nonce field; correlation_id is the replay key.
            if role not in spec["allowed_roles"]:
                raise AttemptBrokerError("unexpected role")
            appended = events + [started_event, finished_event]
            record = {
                "schema_version": SCHEMA_VERSION,
                "contract": ATTEMPT_JOURNAL_CONTRACT,
                "events": appended,
            }
            _atomic_write_journal(host, paths, record)
        except Exception:
            if request["protocol"] in {"awg", "xray"}:
                _cleanup_runtime(host, request["protocol"])
            raise
    ack = {
        "action": request["action"],
        "contract": ATTEMPT_ACK_CONTRACT,
        "correlation_id": request["correlation_id"],
        "node": request["node"],
        "protocol": request["protocol"],
        "session_id": request["session_id"],
        "state": "completed",
    }
    return exact_keys(ack, ATTEMPT_ACK_KEYS, "protocol attempt acknowledgement")


def _unlink_stale_socket(path: str, host: Any) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISSOCK(info.st_mode):
        raise AttemptBrokerError("protocol attempt controller ownership or mode is unsafe")
    if info.st_uid != host.root_uid:
        raise AttemptBrokerError("protocol attempt controller ownership or mode is unsafe")
    os.unlink(path)


def bind_controller(host: Any, paths: Paths) -> socket.socket:
    parent_fd = _open_directory(paths.run_dir, host, "protocol attempt directory")
    os.close(parent_fd)
    _unlink_stale_socket(paths.socket, host)
    previous = os.umask(0o077)
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.bind(paths.socket)
            os.chmod(paths.socket, SOCKET_MODE)
            host.chown(paths.socket)
            info = os.lstat(paths.socket)
            if (
                not stat.S_ISSOCK(info.st_mode)
                or info.st_uid != host.root_uid
                or stat.S_IMODE(info.st_mode) & 0o077
            ):
                raise AttemptBrokerError(
                    "protocol attempt controller ownership or mode is unsafe"
                )
            sock.listen(8)
        except OSError as suc:
            sock.close()
            raise AttemptBrokerError("protocol attempt controller bind failed") from suc
    finally:
        os.umask(previous)
    return sock


def adopt_systemd_controller(host: Any, paths: Paths) -> socket.socket | None:
    """Adopt the single socket passed by systemd, if this is socket activation."""
    listen_pid = os.environ.get("LISTEN_PID")
    listen_fds = os.environ.get("LISTEN_FDS")
    if listen_pid is None and listen_fds is None:
        return None
    if listen_pid != str(os.getpid()) or listen_fds != "1":
        raise AttemptBrokerError("systemd socket activation identity is invalid")
    try:
        sock = socket.socket(fileno=3)
        if (
            sock.family != socket.AF_UNIX
            or sock.type & socket.SOCK_STREAM != socket.SOCK_STREAM
            or sock.getsockname() != paths.socket
            or sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
        ):
            raise AttemptBrokerError("systemd socket activation identity is invalid")
        info = os.lstat(paths.socket)
        if (
            not stat.S_ISSOCK(info.st_mode)
            or info.st_uid != host.root_uid
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise AttemptBrokerError("systemd socket activation custody is unsafe")
        return sock
    except AttemptBrokerError:
        raise
    except OSError as exc:
        raise AttemptBrokerError("systemd socket activation is unavailable") from exc


def _recv_all(conn: socket.socket) -> bytes:
    conn.settimeout(COMMAND_TIMEOUT_SECONDS)
    chunks: list[bytes] = []
    size = 0
    try:
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_REQUEST:
                raise AttemptBrokerError("protocol attempt request is too large")
            chunks.append(chunk)
    except (OSError, TimeoutError) as suc:
        raise AttemptBrokerError("bounded protocol attempt failed") from suc
    return b"".join(chunks)


def handle_connection(conn: socket.socket, host: Any, paths: Paths) -> None:
    _require_peer_root(conn, host)
    payload = _recv_all(conn)
    ack = execute_attempt(payload, host, paths)
    encoded = canonical_bytes(ack)
    if len(encoded) == 0 or len(encoded) > MAX_REQUEST:
        raise AttemptBrokerError("protocol attempt acknowledgement is too large")
    conn.sendall(encoded)


def serve_forever(host: Any, paths: Paths) -> None:
    sock = adopt_systemd_controller(host, paths) or bind_controller(host, paths)
    try:
        while True:
            conn, _unused = sock.accept()
            try:
                handle_connection(conn, host, paths)
            except AttemptBrokerError:
                pass
            finally:
                conn.close()
    finally:
        sock.close()


def run_argv(argv: Sequence[str], host: Any | None = None) -> tuple[int, bytes, bytes]:
    active = host if host is not None else ProductionHost()
    if getattr(active, "TEST_ONLY", False) is True:
        return REFUSAL_EXIT, b"", b"test host cannot emit production output\n"
    try:
        if list(argv):
            raise AttemptBrokerError("broker argv must be empty")
        serve_forever(active, Paths.production())
        return 0, b"", b""
    except AttemptBrokerError as suc:
        return REFUSAL_EXIT, b"", (str(suc) + "\n").encode("ascii")


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    code, stdout, stderr = run_argv(args, ProductionHost())
    if stdout:
        sys.stdout.buffer.write(stdout)
    if stderr:
        sys.stderr.buffer.write(stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
