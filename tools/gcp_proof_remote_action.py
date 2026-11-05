#!/usr/bin/python3
"""VM-side helper for winsvpn-gcp-proof-remote-action-v1.

Installed as /usr/local/libexec/winsvpn-gcp-proof-remote. The reviewed local
Go proof client is the sole orchestrator and invokes this program over SSH
with a closed flag vector. Observation envelopes are schema v4. The helper
collects role-specific local evidence and never accepts caller-supplied
success booleans, byte counts, commands, paths, hosts, ports, shell
fragments, or synthetic interface counters as traffic proof.
"""

from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import json
import os
import re
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence


REQUEST_CONTRACT = "winsvpn-gcp-proof-remote-action-request-v4"
RESPONSE_CONTRACT = "winsvpn-gcp-proof-remote-action-v1"
OBSERVATION_CONTRACT = "winsvpn-gcp-proof-remote-action-v4"
TEST_RESPONSE_CONTRACT = "winsvpn-gcp-proof-remote-action-test-v4"
TRANSACTION_CONTRACT = "winsvpn-gcp-proof-transaction-v4"
STATE_CONTRACT = "winsvpn-gcp-proof-remote-action-state-v1"
FLEET_BINDING_CONTRACT = "winsvpn-gcp-proof-fleet-binding-v1"
WINN3_STATUS_CONTRACT = "winsvpn-gcp-proof-winn3-status-v2"
ATTEMPT_JOURNAL_CONTRACT = "winsvpn-gcp-proof-protocol-attempts-v1"
SCHEMA_VERSION = 1
REQUEST_SCHEMA_VERSION = 4
OBSERVATION_SCHEMA_VERSION = 4
WINN3_STATUS_SCHEMA_VERSION = 2
INSTALL_PATH = "/usr/local/libexec/winsvpn-gcp-proof-remote"
ATTEMPT_BROKER_PATH = "/usr/local/libexec/winsvpn-gcp-proof-attempt-broker"
ATTEMPT_BROKER_INSTALL_MODE = 0o555
STATE_ROOT = "/var/lib/winsvpn-proof"
ROLE_FILE = "/etc/winsvpn/role"
MARKER_PATH = "/var/lib/winsvpn-proof/deployment-identity.json"
FLEET_BINDING_PATH = "/var/lib/winsvpn-proof/fleet-binding.json"
SESSION_STATE_PATH = "/var/lib/winsvpn-proof/remote-action-state.json"
DESCRIPTOR_PATH = "/var/lib/winsvpn-proof/winn3-descriptor.json"
DESCRIPTOR_PUBKEY_PATH = "/var/lib/winsvpn-proof/winn3-g1.pub"
DESCRIPTOR_PAYLOAD_PATH = "/var/lib/winsvpn-proof/winn3-descriptor.payload"
DESCRIPTOR_SIG_PATH = "/var/lib/winsvpn-proof/winn3-descriptor.sig"
HELPER_IDENTITY_PATH = "/var/lib/winsvpn-proof/remote-action-helper.json"
HELPER_IDENTITY_CONTRACT = "winsvpn-gcp-proof-remote-action-helper-install-v1"
HELPER_IDENTITY_KIND = "winsvpn.gcp_proof.remote_action_helper_install.v1"
HELPER_SOURCE_PATH = "tools/gcp_proof_remote_action.py"
HELPER_INSTALL_MODE = 0o555
HELPER_REQUIRED_ROLES = ("control", "data-cover", "data-winn3")
REPLAY_PATH = "/var/lib/winsvpn-proof/remote-action-replay.json"
REPLAY_CONTRACT = "winsvpn-gcp-proof-remote-action-replay-v1"
LOCK_PATH = "/var/lib/winsvpn-proof/remote-action.lock"
NFT_DIR = "/var/lib/winsvpn-proof/nft"
INSTANCE_ID_PATH = "/var/lib/winsvpn-proof/instance-id"
BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"
DMI_PRODUCT_SERIAL_PATH = "/sys/class/dmi/id/product_serial"
WINN3_STATUS_PATHS = {
    "control": "/run/winsvpn-proof/winn3-status.json",
    "data-winn3": "/run/winn3-gateway/status.json",
    "data-cover": "/run/winsvpn-proof/winn3-status.json",
}
ATTEMPT_JOURNAL_PATH = "/run/winsvpn-proof/protocol-attempts.json"
ATTEMPT_SOCKET_PATH = "/run/winsvpn-proof/protocol-attempt.sock"
ATTEMPT_REQUEST_CONTRACT = "winsvpn-gcp-proof-protocol-attempt-request-v1"
ATTEMPT_ACK_CONTRACT = "winsvpn-gcp-proof-protocol-attempt-ack-v1"
NFT_AWG_TABLE = "winsvpn-proof-awg"
NFT_WINN3_TABLE = "winsvpn-proof-winn3"
NFT_COVER_TABLE = "winsvpn-proof-cover"
NFT_AWG_FILE = "/var/lib/winsvpn-proof/nft/awg-block.nft"
NFT_WINN3_FILE = "/var/lib/winsvpn-proof/nft/winn3-block.nft"
NFT_COVER_FILE = "/var/lib/winsvpn-proof/nft/cover-withdraw.nft"
PROC_NET_DEV = "/proc/net/dev"
HUB_HOST = "127.0.0.1"
HUB_PORT = 8000
ALLOWED_HTTP_PATHS = frozenset({"/healthz", "/nodes"})
BIN_IP = "/usr/sbin/ip"
BIN_SYSTEMCTL = "/usr/bin/systemctl"
BIN_SS = "/usr/bin/ss"
BIN_NFT = "/usr/sbin/nft"
BIN_AWG = "/usr/bin/awg"
BIN_OPENSSL = "/usr/bin/openssl"
BIN_DOCKER = "/usr/bin/docker"
BIN_XRAY = "/usr/local/bin/xray"
AWG_CONTAINER = "amnezia-awg2"
AWG_IFACE = "awg0"
XRAY_API_SERVER = "127.0.0.1:8080"
XRAY_STATSQUERY_ARGV = (
    BIN_XRAY,
    "api",
    "statsquery",
    "--server=" + XRAY_API_SERVER,
    "-pattern=user>>>",
    "-json",
)
COMMAND_TIMEOUT_SECONDS = 30
ACTION_TIMEOUT_SECONDS = 120
MAX_OUTPUT = 4 * 1024 * 1024
MAX_EXECUTABLE = 64 * 1024 * 1024
MAX_DESCRIPTOR_PART = 64 * 1024
MAX_REPLAY_DIGESTS = 64
REFUSAL_EXIT = 2
CHILD_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}

HEX64_RE = re.compile(r"[0-9a-f]{64}\Z")
PROJECT_RE = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]\Z")
INSTANCE_RE = re.compile(r"[a-z]([-a-z0-9]{0,61}[a-z0-9])?\Z")
ZONE_RE = re.compile(r"[a-z]+-[a-z]+[0-9]+-[a-z]\Z")
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}\Z")
FLEET_RE = re.compile(r"[a-f0-9]{12}\Z")
UTC_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z\Z")
PROCESS_NONCE_RE = re.compile(r"[0-9a-f]{32}\Z")
BOOT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
GCE_INSTANCE_ID_RE = re.compile(r"[1-9][0-9]{0,31}\Z")
DMI_INSTANCE_RE = re.compile(r"GoogleCloud-([1-9][0-9]{0,31})\Z")
COMM_RE = re.compile(r"[A-Za-z0-9_.:-]{1,16}\Z")
INTERFACE_RE = re.compile(r"[A-Za-z0-9_.:@-]{1,64}\Z")
AWG_PEER_RE = re.compile(r"[A-Za-z0-9+/]{43}=\Z")
XRAY_USER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@:-]{0,127}\Z")
XRAY_STAT_NAME_RE = re.compile(
    r"user>>>([A-Za-z0-9][A-Za-z0-9._@:-]{0,127})>>>traffic>>>(uplink|downlink)\Z"
)
PROC_EXE_RE = re.compile(r"/proc/[1-9][0-9]{0,9}/exe\Z")
VALUE_FORBIDDEN_RE = re.compile(r"[\\;&|$`(){}[\]*?!\s]")
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

PHASE_OBSERVE_BEFORE = "observe-before"
PHASE_EXERCISE = "exercise"
PHASE_OBSERVE_AFTER = "observe-after"
PHASE_MUTATE = "mutate"
OBSERVE_PHASES = frozenset({PHASE_OBSERVE_BEFORE, PHASE_OBSERVE_AFTER})
REQUEST_PHASES = frozenset(
    {PHASE_OBSERVE_BEFORE, PHASE_EXERCISE, PHASE_OBSERVE_AFTER, PHASE_MUTATE}
)
SYNTHETIC_INTERFACES = frozenset({"winn3", "xray0"})
REAL_WINN3_INTERFACE = "winn3gw0"
REAL_AWG_INTERFACE = "awg0"
ACTION_OPERATIONS = {
    "route-decision": "query-signed-route-decision",
    "connect-primary": "exercise-winn3-client",
    "connect-cover-awg": "exercise-awg-client",
    "connect-cover-xray": "exercise-xray-client",
    "inject-awg-block": "block-cover-awg",
    "probe-awg-block": "exercise-cover-fallback",
    "restore-awg": "restore-cover-awg",
    "inject-winn3-block": "block-winn3",
    "probe-winn3-block": "exercise-winn3-fallback",
    "withdraw-cover": "withdraw-cover-route",
    "probe-cover-withdrawn": "exercise-downgrade-refusal",
    "restore-cover": "restore-cover-route",
    "restore-winn3": "restore-winn3",
    "teardown-check": "inspect-proof-scope",
}
MUTATING_ACTIONS = frozenset(
    {
        "inject-awg-block",
        "restore-awg",
        "inject-winn3-block",
        "withdraw-cover",
        "restore-cover",
        "restore-winn3",
    }
)
ACTION_ROLES = {
    "route-decision": "control",
    "connect-primary": "control",
    "connect-cover-awg": "control",
    "connect-cover-xray": "control",
    "inject-awg-block": "data-cover",
    "probe-awg-block": "control",
    "restore-awg": "data-cover",
    "inject-winn3-block": "data-winn3",
    "probe-winn3-block": "control",
    "withdraw-cover": "control",
    "probe-cover-withdrawn": "control",
    "restore-cover": "control",
    "restore-winn3": "data-winn3",
    "teardown-check": "control",
}
ACTION_PHASE_ROLES = {
    ("route-decision", PHASE_EXERCISE): frozenset({"control"}),
    ("teardown-check", PHASE_EXERCISE): frozenset({"control"}),
    ("connect-primary", PHASE_OBSERVE_BEFORE): frozenset({"data-winn3"}),
    ("connect-primary", PHASE_EXERCISE): frozenset({"control"}),
    ("connect-primary", PHASE_OBSERVE_AFTER): frozenset({"data-winn3"}),
    ("connect-cover-awg", PHASE_OBSERVE_BEFORE): frozenset({"data-cover"}),
    ("connect-cover-awg", PHASE_EXERCISE): frozenset({"control"}),
    ("connect-cover-awg", PHASE_OBSERVE_AFTER): frozenset({"data-cover"}),
    ("connect-cover-xray", PHASE_OBSERVE_BEFORE): frozenset({"data-cover"}),
    ("connect-cover-xray", PHASE_EXERCISE): frozenset({"control"}),
    ("connect-cover-xray", PHASE_OBSERVE_AFTER): frozenset({"data-cover"}),
    ("probe-awg-block", PHASE_OBSERVE_BEFORE): frozenset({"data-cover"}),
    ("probe-awg-block", PHASE_EXERCISE): frozenset({"control"}),
    ("probe-awg-block", PHASE_OBSERVE_AFTER): frozenset({"data-cover"}),
    ("inject-awg-block", PHASE_MUTATE): frozenset({"data-cover"}),
    ("restore-awg", PHASE_MUTATE): frozenset({"data-cover"}),
    ("inject-winn3-block", PHASE_MUTATE): frozenset({"data-winn3"}),
    ("restore-winn3", PHASE_MUTATE): frozenset({"data-winn3"}),
    ("withdraw-cover", PHASE_MUTATE): frozenset({"control"}),
    ("restore-cover", PHASE_MUTATE): frozenset({"control"}),
    ("probe-winn3-block", PHASE_OBSERVE_BEFORE): frozenset({"data-winn3", "data-cover"}),
    ("probe-winn3-block", PHASE_EXERCISE): frozenset({"control"}),
    ("probe-winn3-block", PHASE_OBSERVE_AFTER): frozenset({"data-winn3", "data-cover"}),
    ("probe-cover-withdrawn", PHASE_OBSERVE_BEFORE): frozenset(
        {"data-winn3", "data-cover"}
    ),
    ("probe-cover-withdrawn", PHASE_EXERCISE): frozenset({"control"}),
    ("probe-cover-withdrawn", PHASE_OBSERVE_AFTER): frozenset(
        {"data-winn3", "data-cover"}
    ),
}
ATTEMPT_ACK_ACTIONS = frozenset(
    {
        "connect-primary",
        "connect-cover-awg",
        "connect-cover-xray",
        "probe-awg-block",
        "probe-winn3-block",
        "probe-cover-withdrawn",
    }
)
REMOTE_HELPER_DATA_KEYS = {
    "connect-primary": frozenset({"attempts"}),
    "connect-cover-awg": frozenset({"protocol", "node", "result"}),
    "connect-cover-xray": frozenset({"protocol", "node", "result"}),
    "probe-awg-block": frozenset({"control_id", "attempts", "attempt_events"}),
    "probe-winn3-block": frozenset({"control_id", "attempts", "attempt_events"}),
    "probe-cover-withdrawn": frozenset(
        {
            "control_id",
            "attempts",
            "attempt_events",
            "refusal_code",
            "same_node_downgrade_attempts",
        }
    ),
}
ROLE_PRIMARY_UNIT = {
    "control": "wins-hub.service",
    "data-winn3": "winn3-gateway.service",
    "data-cover": "xray.service",
}
ROLE_COMM = {
    "control": "wins-hub",
    "data-winn3": "winn3-gateway",
    "data-cover": "xray",
}
ROLE_UNITS = {
    "control": ("wins-hub.service",),
    "data-winn3": ("winn3-gateway.service",),
    "data-cover": ("xray.service", "docker.service"),
}
ROLE_BINARIES = {
    "control": (),
    "data-winn3": ("/usr/local/libexec/winn/winn3-gateway",),
    "data-cover": ("/usr/local/bin/xray",),
}
DATA_WINN3_FORBIDDEN_UNITS = (
    "xray.service",
    "docker.service",
    "docker.socket",
)
DATA_WINN3_FORBIDDEN_BINARIES = (
    "/usr/local/bin/xray",
    "/usr/bin/xray",
    BIN_DOCKER,
    "/usr/local/bin/docker",
    "/snap/bin/docker",
    "/usr/bin/dockerd",
    "/usr/local/bin/dockerd",
)
PROTOCOL_IFACES = {
    "winn3": (REAL_WINN3_INTERFACE,),
    "awg": (REAL_AWG_INTERFACE,),
    "xray": (),
}
REQUEST_FLAG_ORDER = (
    "schema-version",
    "action",
    "phase",
    "project",
    "instance",
    "role",
    "fleet-id",
    "run-id",
    "session-id",
    "correlation-id",
    "client-build-identity",
    "challenge",
    "request-hash",
)
REQUEST_KEYS = {
    "schema_version",
    "contract",
    "action",
    "phase",
    "project",
    "instance",
    "role",
    "fleet_id",
    "run_id",
    "session_id",
    "correlation_id",
    "client_build_identity",
    "challenge",
    "request_sha256",
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
STATE_KEYS = {
    "schema_version",
    "contract",
    "run_id",
    "session_id",
    "correlation_id",
    "fleet_id",
    "control_id",
    "protocol",
    "node",
    "state",
    "monotonic_ns",
    "updated_utc",
}
WINN3_STATUS_KEYS = {
    "boot_id",
    "contract",
    "event",
    "forward",
    "inner_packets_delivered",
    "observed_utc",
    "observed_monotonic_ns",
    "process_id",
    "process_nonce",
    "process_start_ticks",
    "process_started_utc",
    "ready",
    "reflected",
    "rx_device_writes",
    "schema_version",
    "sequence",
}
WINN3_STATUS_IDENTITY_KEYS = (
    "boot_id",
    "process_id",
    "process_nonce",
    "process_start_ticks",
    "process_started_utc",
)
AWG_PEER_KEYS = {"peer", "rx", "tx", "handshake_unix"}
AWG_PEER_EVIDENCE_KEYS = {"latest_handshake_unix", "public_key", "rx", "tx"}
XRAY_STATS_KEYS = {"downlink", "uplink", "user"}
PROCESS_IDENTITY_KEYS = {"comm", "exe_sha256", "pid", "starttime_ticks"}
TRANSACTION_KEYS = {
    "contract",
    "kind",
    "nonce",
    "protocol",
    "response",
    "response_sha256",
}
EVIDENCE_KEYS = {
    "attempt_acknowledgements",
    "attempt_journal_after",
    "attempt_journal_after_awg",
    "attempt_journal_before",
    "awg_peers",
    "boot_id",
    "challenge",
    "client_build_identity",
    "ended_monotonic_ns",
    "instance",
    "instance_id",
    "interface_counters",
    "process_identity",
    "request_sha256",
    "role",
    "services",
    "started_monotonic_ns",
    "winn3_status",
    "xray_stats",
}
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
DESCRIPTOR_KEYS = {"payload", "sig"}
DESCRIPTOR_IDENTITY_KEYS = frozenset({"node", "descriptor_node", "selected_node"})
MARKER_KEYS = {"fleet_id", "instance", "role"}
HELPER_IDENTITY_KEYS = {
    "bytes",
    "candidate_id",
    "contract",
    "fleet_id",
    "instance",
    "kind",
    "mode",
    "path",
    "required_roles",
    "role",
    "schema_version",
    "sha256",
    "source_path",
    "st_dev",
    "st_ino",
}
REPLAY_KEYS = {"contract", "digests", "run_id", "schema_version", "session_id"}
ALLOWED_WRITE_PATHS = frozenset(
    {
        SESSION_STATE_PATH,
        DESCRIPTOR_PAYLOAD_PATH,
        DESCRIPTOR_SIG_PATH,
        NFT_AWG_FILE,
        NFT_WINN3_FILE,
        NFT_COVER_FILE,
        REPLAY_PATH,
    }
)
ALLOWED_STATE_PARENTS = frozenset({STATE_ROOT, NFT_DIR})
UNIT_FRAGMENT_PREFIXES = (
    "/lib/systemd/system/",
    "/usr/lib/systemd/system/",
    "/etc/systemd/system/",
)
NFT_AWG_RULESET = (
    "table inet winsvpn-proof-awg {\n"
    "  chain input {\n"
    "    type filter hook input priority 0; policy accept;\n"
    "    udp dport { 9110, 20000-32767 } drop\n"
    "  }\n"
    "}\n"
)
NFT_WINN3_RULESET = (
    "table inet winsvpn-proof-winn3 {\n"
    "  chain input {\n"
    "    type filter hook input priority 0; policy accept;\n"
    "    udp dport 9111 drop\n"
    "  }\n"
    "}\n"
)
NFT_COVER_RULESET = (
    "table inet winsvpn-proof-cover {\n"
    "  chain output {\n"
    "    type filter hook output priority 0; policy accept;\n"
    "    meta l4proto udp udp dport { 9110, 20000-32767 } drop\n"
    "  }\n"
    "}\n"
)


class RemoteActionError(RuntimeError):
    """The remote proof action is unauthenticated, stale, or unsafe."""


class CommandResult:
    def __init__(self, stdout: bytes = b"", stderr: bytes = b"", exit_code: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code


class ProductionHost:
    TEST_ONLY = False

    def __init__(self) -> None:
        self._lock_fd = -1

    def monotonic_ns(self) -> int:
        return time.monotonic_ns()

    def utc_now(self) -> str:
        return format_rfc3339_nano(time.time_ns())

    def acquire_action_lock(self) -> None:
        if self._lock_fd >= 0:
            raise RemoteActionError("concurrent remote action is forbidden")
        directory = getattr(os, "O_DIRECTORY", 0)
        if not directory:
            raise RemoteActionError("O_DIRECTORY is required")
        root_fd = -1
        lock_fd = -1
        try:
            before = os.lstat(STATE_ROOT)
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
                raise RemoteActionError("state directory is unsafe")
            if stat.S_IMODE(before.st_mode) & 0o022 and not (before.st_mode & stat.S_ISVTX):
                raise RemoteActionError("state directory is writable")
            root_fd = os.open(
                STATE_ROOT, os.O_RDONLY | directory | _nofollow_flags()
            )
            opened = os.fstat(root_fd)
            if _identity(before) != _identity(opened) or not stat.S_ISDIR(opened.st_mode):
                raise RemoteActionError("state directory changed while being opened")
            lock_fd = os.open(
                os.path.basename(LOCK_PATH),
                os.O_RDWR | os.O_CREAT | _nofollow_flags(),
                0o600,
                dir_fd=root_fd,
            )
            lock_info = os.fstat(lock_fd)
            if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_nlink != 1:
                raise RemoteActionError("action lock is unsafe")
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RemoteActionError("concurrent remote action is forbidden") from exc
        except RemoteActionError:
            if lock_fd >= 0:
                os.close(lock_fd)
            raise
        except OSError as exc:
            if lock_fd >= 0:
                os.close(lock_fd)
            raise RemoteActionError("action lock is unreadable") from exc
        finally:
            if root_fd >= 0:
                os.close(root_fd)
        self._lock_fd = lock_fd

    def release_action_lock(self) -> None:
        if self._lock_fd < 0:
            return
        fd = self._lock_fd
        self._lock_fd = -1
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def require_helper_identity_binding(self, record: Mapping[str, Any]) -> None:
        try:
            before = os.lstat(INSTALL_PATH)
            fd = os.open(INSTALL_PATH, os.O_RDONLY | _nofollow_flags())
        except OSError as exc:
            raise RemoteActionError("installed remote proof-action helper is unreadable") from exc
        try:
            opened = os.fstat(fd)
            after = os.lstat(INSTALL_PATH)
        finally:
            os.close(fd)
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or _identity(before) != _identity(opened)
            or _identity(opened) != _identity(after)
        ):
            raise RemoteActionError(
                "installed remote proof-action helper is not a regular single-link file"
            )
        mode = exact_int(record["mode"], "helper identity mode")
        size = exact_int(record["bytes"], "helper identity bytes", minimum=1)
        dev = exact_int(record["st_dev"], "helper identity st_dev", minimum=0)
        ino = exact_int(record["st_ino"], "helper identity st_ino", minimum=1)
        if opened.st_dev != dev or opened.st_ino != ino or opened.st_size != size:
            raise RemoteActionError("remote proof-action helper identity is stale")
        if os.geteuid() == 0 and (
            opened.st_uid != 0
            or opened.st_gid != 0
            or stat.S_IMODE(opened.st_mode) != mode
            or mode != HELPER_INSTALL_MODE
        ):
            raise RemoteActionError(
                "installed remote proof-action helper ownership or mode is unsafe"
            )

    def exists(self, path: str) -> bool:
        _forbid_credential_path(path)
        try:
            os.lstat(path)
        except OSError:
            return False
        return True

    def read_file(self, path: str) -> bytes:
        _forbid_credential_path(path)
        return _read_regular(path, f"local file {path}")

    def write_file(self, path: str, data: bytes, mode: int) -> None:
        _forbid_credential_path(path)
        _forbid_uncontained_write(path)
        _atomic_write(path, data, mode)

    def run(self, argv: Sequence[str]) -> CommandResult:
        if not argv or not all(isinstance(item, str) and item for item in argv):
            raise RemoteActionError("command argv is invalid")
        process: subprocess.Popen[bytes] | None = None
        selector = selectors.DefaultSelector()
        streams: dict[str, Any] = {}
        succeeded = False
        try:
            process = subprocess.Popen(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                env=CHILD_ENV,
                bufsize=0,
                close_fds=True,
                start_new_session=True,
            )
            if process.stdout is None or process.stderr is None:
                raise RemoteActionError("local probe execution failed")
            streams = {"stdout": process.stdout, "stderr": process.stderr}
            chunks: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
            totals = {"stdout": 0, "stderr": 0}
            for label, stream in streams.items():
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)

            deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
            open_streams = len(streams)
            while open_streams:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(list(argv), COMMAND_TIMEOUT_SECONDS)
                events = selector.select(min(remaining, 0.25))
                for key, _mask in events:
                    label = str(key.data)
                    try:
                        chunk = os.read(
                            key.fd,
                            min(65536, MAX_OUTPUT + 1 - totals[label]),
                        )
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        open_streams -= 1
                        continue
                    chunks[label].append(chunk)
                    totals[label] += len(chunk)
                    if totals[label] > MAX_OUTPUT:
                        raise RemoteActionError("local probe output is too large")

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(list(argv), COMMAND_TIMEOUT_SECONDS)
            exit_code = process.wait(timeout=remaining)
            stdout = b"".join(chunks["stdout"])
            stderr = b"".join(chunks["stderr"])
            succeeded = True
            return CommandResult(stdout, stderr, int(exit_code))
        except FileNotFoundError as exc:
            raise RemoteActionError(f"absent tool {argv[0]}") from exc
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RemoteActionError("local probe execution failed") from exc
        finally:
            selector.close()
            for stream in streams.values():
                try:
                    stream.close()
                except OSError:
                    pass
            if process is not None and not succeeded:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    try:
                        process.kill()
                    except (OSError, ProcessLookupError):
                        pass
                try:
                    process.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    pass

    def http_get(self, path: str) -> bytes:
        if path not in ALLOWED_HTTP_PATHS or ".." in path or "\x00" in path:
            raise RemoteActionError("http path is not allowlisted")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {HUB_HOST}:{HUB_PORT}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii")
        try:
            sock = socket.create_connection((HUB_HOST, HUB_PORT), timeout=5)
        except OSError as exc:
            raise RemoteActionError("local hub probe failed") from exc
        try:
            peer = sock.getpeername()
            if peer[0] != HUB_HOST or int(peer[1]) != HUB_PORT:
                raise RemoteActionError("local hub redirected off loopback")
            sock.settimeout(5)
            sock.sendall(request)
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = sock.recv(min(65536, MAX_OUTPUT + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_OUTPUT:
                    raise RemoteActionError("local hub response is too large")
            raw = b"".join(chunks)
        except RemoteActionError:
            raise
        except OSError as exc:
            raise RemoteActionError("local hub probe failed") from exc
        finally:
            sock.close()
        header, separator, body = raw.partition(b"\r\n\r\n")
        if not separator:
            raise RemoteActionError("local hub probe failed")
        status = header.split(b"\r\n", 1)[0]
        if status not in {b"HTTP/1.1 200 OK", b"HTTP/1.0 200 OK"}:
            raise RemoteActionError("local hub probe failed")
        try:
            header_text = header.decode("ascii")
        except UnicodeDecodeError as exc:
            raise RemoteActionError("local hub probe failed") from exc
        lowered = header_text.lower()
        if "transfer-encoding:" in lowered:
            raise RemoteActionError("local hub response encoding is not bound")
        content_length = None
        for line in header_text.split("\r\n")[1:]:
            if line.lower().startswith("content-length:"):
                if content_length is not None:
                    raise RemoteActionError("local hub response encoding is not bound")
                try:
                    content_length = int(line.split(":", 1)[1].strip())
                except ValueError as exc:
                    raise RemoteActionError("local hub response encoding is not bound") from exc
        if content_length is None or content_length < 1 or content_length > MAX_OUTPUT:
            raise RemoteActionError("local hub response is too large")
        if len(body) != content_length:
            raise RemoteActionError("local hub response is too large")
        return body

    def hash_executable(self, path: str) -> str:
        _forbid_credential_path(path)
        proc_exe = PROC_EXE_RE.fullmatch(path) is not None
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if not proc_exe:
            flags |= _nofollow_flags()
        elif not getattr(os, "O_NOFOLLOW", 0):
            raise RemoteActionError("O_NOFOLLOW is required")
        fd = -1
        try:
            if not proc_exe:
                before = os.lstat(path)
                if (
                    stat.S_ISLNK(before.st_mode)
                    or not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                ):
                    raise RemoteActionError(
                        f"process executable {path} is not a regular single-link file"
                    )
            fd = os.open(path, flags)
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode):
                raise RemoteActionError(f"process executable {path} is unreadable")
            if not proc_exe:
                after = os.lstat(path)
                if _identity(before) != _identity(opened) or _identity(opened) != _identity(
                    after
                ):
                    raise RemoteActionError(
                        f"process executable {path} changed while being read"
                    )
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_EXECUTABLE:
                    raise RemoteActionError(f"process executable {path} is too large")
                digest.update(chunk)
            finished = os.fstat(fd)
            if _identity(opened) != _identity(finished):
                raise RemoteActionError(f"process executable {path} changed while being read")
            if total == 0:
                raise RemoteActionError(f"process executable {path} is empty")
            return digest.hexdigest()
        except RemoteActionError:
            raise
        except OSError as exc:
            raise RemoteActionError(f"process executable {path} is unreadable") from exc
        finally:
            if fd >= 0:
                os.close(fd)

    def hold_attempt_broker_identity(self) -> Any:
        return _hold_attempt_broker_at_root("/", ATTEMPT_BROKER_PATH)

    def require_root_owned_evidence(self, path: str) -> None:
        _forbid_credential_path(path)
        try:
            info = os.lstat(path)
        except OSError as exc:
            raise RemoteActionError(f"evidence file {path} is unreadable") from exc
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise RemoteActionError(f"evidence file {path} ownership or mode is unsafe")

    def read_root_owned_evidence(self, path: str) -> bytes:
        self.require_root_owned_evidence(path)
        before = os.lstat(path)
        data = _read_regular(path, f"evidence file {path}")
        after = os.lstat(path)
        if _identity(before) != _identity(after):
            raise RemoteActionError(f"evidence file {path} changed while being read")
        return data

    def read_gateway_status_evidence(self, path: str) -> bytes:
        if path != WINN3_STATUS_PATHS["data-winn3"]:
            raise RemoteActionError("gateway status path is not the exact proof path")
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _nofollow_flags()
        file_flags = (
            os.O_RDONLY | _nofollow_flags() | getattr(os, "O_NONBLOCK", 0)
        )
        run_fd = parent_fd = evidence_fd = -1
        try:
            run_fd = os.open("/run", directory_flags)
            run_before = os.fstat(run_fd)
            if (
                not stat.S_ISDIR(run_before.st_mode)
                or run_before.st_uid != 0
                or stat.S_IMODE(run_before.st_mode) & 0o022
            ):
                raise RemoteActionError("gateway status runtime root is unsafe")
            parent_fd = os.open("winn3-gateway", directory_flags, dir_fd=run_fd)
            parent_before = os.fstat(parent_fd)
            if (
                not stat.S_ISDIR(parent_before.st_mode)
                or parent_before.st_uid == 0
                or stat.S_IMODE(parent_before.st_mode) != 0o700
            ):
                raise RemoteActionError("gateway status runtime directory is unsafe")
            evidence_fd = os.open("status.json", file_flags, dir_fd=parent_fd)
            before = os.fstat(evidence_fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_uid != parent_before.st_uid
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_size <= 0
                or before.st_size > MAX_OUTPUT
            ):
                raise RemoteActionError("gateway status evidence ownership or mode is unsafe")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(evidence_fd, min(65536, MAX_OUTPUT + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_OUTPUT:
                    raise RemoteActionError("gateway status evidence is too large")
            after = os.fstat(evidence_fd)
            named = os.stat("status.json", dir_fd=parent_fd, follow_symlinks=False)
            parent_after = os.fstat(parent_fd)
            run_after = os.fstat(run_fd)
            if (
                _identity(before) != _identity(after)
                or _identity(after) != _identity(named)
                or _identity(parent_before) != _identity(parent_after)
                or _identity(run_before) != _identity(run_after)
            ):
                raise RemoteActionError("gateway status evidence changed while being read")
            data = b"".join(chunks)
            if not data:
                raise RemoteActionError("gateway status evidence is empty")
            return data
        except RemoteActionError:
            raise
        except OSError as exc:
            raise RemoteActionError("gateway status evidence is unreadable") from exc
        finally:
            for descriptor in (evidence_fd, parent_fd, run_fd):
                if descriptor >= 0:
                    os.close(descriptor)

    def trigger_protocol_attempt(
        self, request: Mapping[str, Any], protocol: str, node: str
    ) -> dict[str, Any]:
        if protocol not in {"awg", "winn3", "xray"}:
            raise RemoteActionError("protocol attempt is not allowlisted")
        try:
            before = os.lstat(ATTEMPT_SOCKET_PATH)
        except OSError as exc:
            raise RemoteActionError("protocol attempt controller is absent") from exc
        if (
            not stat.S_ISSOCK(before.st_mode)
            or before.st_uid != 0
            or stat.S_IMODE(before.st_mode) & 0o077
        ):
            raise RemoteActionError("protocol attempt controller ownership or mode is unsafe")
        payload = canonical_bytes(
            {
                "schema_version": SCHEMA_VERSION,
                "contract": ATTEMPT_REQUEST_CONTRACT,
                "action": request["action"],
                "correlation_id": request["correlation_id"],
                "node": node,
                "protocol": protocol,
                "session_id": request["session_id"],
            }
        )
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.settimeout(COMMAND_TIMEOUT_SECONDS)
            client.connect(ATTEMPT_SOCKET_PATH)
            if hasattr(socket, "SO_PEERCRED"):
                credentials = client.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
                )
                _pid, uid, _gid = struct.unpack("3i", credentials)
                if uid != 0:
                    raise RemoteActionError("protocol attempt controller peer is not root")
            else:
                raise RemoteActionError("protocol attempt controller peer is not root")
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = client.recv(65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > 65536:
                    raise RemoteActionError("protocol attempt acknowledgement is too large")
                chunks.append(chunk)
        except RemoteActionError:
            raise
        except (OSError, TimeoutError) as exc:
            raise RemoteActionError("bounded protocol attempt failed") from exc
        finally:
            client.close()
        try:
            after = os.lstat(ATTEMPT_SOCKET_PATH)
        except OSError as exc:
            raise RemoteActionError("protocol attempt controller changed") from exc
        if _identity(before) != _identity(after):
            raise RemoteActionError("protocol attempt controller changed")
        ack = exact_keys(
            strict_json(b"".join(chunks), "protocol attempt acknowledgement"),
            {
                "action",
                "contract",
                "correlation_id",
                "node",
                "protocol",
                "session_id",
                "state",
            },
            "protocol attempt acknowledgement",
        )
        if (
            ack["contract"] != ATTEMPT_ACK_CONTRACT
            or ack["action"] != request["action"]
            or ack["correlation_id"] != request["correlation_id"]
            or ack["node"] != node
            or ack["protocol"] != protocol
            or ack["session_id"] != request["session_id"]
            or ack["state"] != "completed"
        ):
            raise RemoteActionError("protocol attempt acknowledgement is invalid")
        return dict(ack)


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
            raise RemoteActionError(f"duplicate JSON key {key!r} is forbidden")
        result[key] = value
    return result


def strict_json(data: bytes, label: str) -> Any:
    if not data:
        raise RemoteActionError(f"{label} is empty")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RemoteActionError(f"{label} is not ASCII JSON") from exc
    decoder = json.JSONDecoder(object_pairs_hook=_strict_pairs)
    try:
        value, index = decoder.raw_decode(text)
    except json.JSONDecodeError as exc:
        raise RemoteActionError(f"{label} is not strict ASCII JSON") from exc
    if text[index:].strip():
        raise RemoteActionError(f"{label} contains multiple JSON values")
    return value


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise RemoteActionError(f"{label} schema fields are invalid")
    for key in value:
        if str(key).lower() in FORBIDDEN_OUTPUT_KEYS:
            raise RemoteActionError(f"{label} contains a forbidden pass token")
    return value


def exact_int(value: object, label: str, *, minimum: int | None = None) -> int:
    if type(value) is not int:
        raise RemoteActionError(f"{label} must be an exact integer")
    if minimum is not None and value < minimum:
        raise RemoteActionError(f"{label} is out of range")
    return value


def exact_bool(value: object, expected: bool, label: str) -> bool:
    if type(value) is not bool or value is not expected:
        raise RemoteActionError(f"{label} must be exactly {expected}")
    return value


def _forbid_credential_path(path: str) -> None:
    if path in CREDENTIAL_PATHS:
        raise RemoteActionError("credential file access is forbidden")
    for prefix in CREDENTIAL_PATHS:
        if path.startswith(prefix.rstrip("/") + "/"):
            raise RemoteActionError("credential file access is forbidden")
    for prefix in PRODUCTION_PATH_PREFIXES:
        if path.startswith(prefix):
            raise RemoteActionError("production resource access is forbidden")


def _nofollow_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise RemoteActionError("O_NOFOLLOW is required")
    return nofollow | getattr(os, "O_CLOEXEC", 0)


def _forbid_uncontained_write(path: str) -> None:
    if path not in ALLOWED_WRITE_PATHS:
        raise RemoteActionError("write path is not contained")
    if not path.startswith(STATE_ROOT + "/") or ".." in path.split("/"):
        raise RemoteActionError("write path is not contained")
    parent = os.path.dirname(path)
    leaf = os.path.basename(path)
    if parent not in ALLOWED_STATE_PARENTS or not leaf or leaf in {".", ".."} or "/" in leaf:
        raise RemoteActionError("write path is not contained")


def _identity(item: os.stat_result) -> tuple[int, int, int, int, int, int, int, int, int]:
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


def _attempt_broker_directory_identity(
    item: os.stat_result,
) -> tuple[int, int, int, int, int, int]:
    return (
        item.st_dev,
        item.st_ino,
        item.st_uid,
        item.st_gid,
        stat.S_IFMT(item.st_mode),
        stat.S_IMODE(item.st_mode),
    )


def _attempt_broker_file_identity(
    item: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int, int, int]:
    return (*_identity(item), item.st_nlink)


def _require_attempt_broker_directory(
    item: os.stat_result,
    *,
    owner_uid: int,
    owner_gid: int,
) -> None:
    if (
        not stat.S_ISDIR(item.st_mode)
        or item.st_uid != owner_uid
        or item.st_gid != owner_gid
        or stat.S_IMODE(item.st_mode) & 0o022
    ):
        raise RemoteActionError("attempt-broker executable ancestry is unsafe")


def _require_attempt_broker_file(
    item: os.stat_result,
    *,
    owner_uid: int,
    owner_gid: int,
) -> None:
    if (
        not stat.S_ISREG(item.st_mode)
        or item.st_nlink != 1
        or item.st_uid != owner_uid
        or item.st_gid != owner_gid
        or stat.S_IMODE(item.st_mode) != ATTEMPT_BROKER_INSTALL_MODE
        or item.st_size < 1
        or item.st_size > MAX_EXECUTABLE
    ):
        raise RemoteActionError(
            "attempt-broker executable is not a protected regular single-link file"
        )


def _hash_attempt_broker_descriptor(fd: int) -> tuple[str, int, os.stat_result]:
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        before = os.fstat(fd)
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, MAX_EXECUTABLE + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_EXECUTABLE:
                raise RemoteActionError("attempt-broker executable is too large")
            digest.update(chunk)
        finished = os.fstat(fd)
    except RemoteActionError:
        raise
    except OSError as exc:
        raise RemoteActionError("attempt-broker executable is unreadable") from exc
    if (
        _attempt_broker_file_identity(before)
        != _attempt_broker_file_identity(finished)
        or total != before.st_size
        or total == 0
    ):
        raise RemoteActionError("attempt-broker executable changed while being read")
    return digest.hexdigest(), total, finished


class _HeldAttemptBrokerIdentity:
    def __init__(
        self,
        *,
        directory_fds: list[int],
        directory_identities: list[tuple[int, int, int, int, int, int]],
        directory_links: list[
            tuple[int, str, int, tuple[int, int, int, int, int, int]]
        ],
        file_fd: int,
        file_parent_fd: int,
        file_name: str,
        file_identity: tuple[int, int, int, int, int, int, int, int, int, int],
        digest: str,
        byte_count: int,
        owner_uid: int,
        owner_gid: int,
    ) -> None:
        self._directory_fds = directory_fds
        self._directory_identities = directory_identities
        self._directory_links = directory_links
        self._file_fd = file_fd
        self._file_parent_fd = file_parent_fd
        self._file_name = file_name
        self._file_identity = file_identity
        self._digest = digest
        self._byte_count = byte_count
        self._owner_uid = owner_uid
        self._owner_gid = owner_gid
        self._finished = False
        self._closed = False

    def _verify_path_binding(self) -> None:
        try:
            for fd, expected in zip(
                self._directory_fds, self._directory_identities, strict=True
            ):
                current = os.fstat(fd)
                _require_attempt_broker_directory(
                    current,
                    owner_uid=self._owner_uid,
                    owner_gid=self._owner_gid,
                )
                if _attempt_broker_directory_identity(current) != expected:
                    raise RemoteActionError("attempt-broker executable ancestry changed")
            for parent_fd, name, child_fd, expected in self._directory_links:
                named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                opened = os.fstat(child_fd)
                if (
                    stat.S_ISLNK(named.st_mode)
                    or _attempt_broker_directory_identity(named) != expected
                    or _attempt_broker_directory_identity(opened) != expected
                ):
                    raise RemoteActionError("attempt-broker executable ancestry changed")
            named_file = os.stat(
                self._file_name,
                dir_fd=self._file_parent_fd,
                follow_symlinks=False,
            )
            opened_file = os.fstat(self._file_fd)
        except RemoteActionError:
            raise
        except OSError as exc:
            raise RemoteActionError("attempt-broker executable path changed") from exc
        _require_attempt_broker_file(
            named_file,
            owner_uid=self._owner_uid,
            owner_gid=self._owner_gid,
        )
        _require_attempt_broker_file(
            opened_file,
            owner_uid=self._owner_uid,
            owner_gid=self._owner_gid,
        )
        if (
            _attempt_broker_file_identity(named_file) != self._file_identity
            or _attempt_broker_file_identity(opened_file) != self._file_identity
        ):
            raise RemoteActionError("attempt-broker executable path changed")

    def finish(self) -> str:
        if self._closed or self._finished:
            raise RemoteActionError("attempt-broker identity use is invalid")
        self._verify_path_binding()
        digest, byte_count, finished = _hash_attempt_broker_descriptor(self._file_fd)
        if (
            _attempt_broker_file_identity(finished) != self._file_identity
            or byte_count != self._byte_count
            or digest != self._digest
        ):
            raise RemoteActionError("attempt-broker executable changed during use")
        self._verify_path_binding()
        self._finished = True
        return digest

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        descriptors = [self._file_fd, *reversed(self._directory_fds)]
        self._file_fd = -1
        self._directory_fds = []
        first_error: OSError | None = None
        for descriptor in descriptors:
            if descriptor < 0:
                continue
            try:
                os.close(descriptor)
            except OSError as exc:
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise RemoteActionError(
                "attempt-broker identity descriptor close failed"
            ) from first_error


def _hold_attempt_broker_at_root(
    root_path: str,
    logical_path: str,
) -> _HeldAttemptBrokerIdentity:
    if logical_path != ATTEMPT_BROKER_PATH:
        raise RemoteActionError("attempt-broker executable path is not fixed")
    if type(root_path) is not str or not os.path.isabs(root_path) or "\x00" in root_path:
        raise RemoteActionError("attempt-broker executable root is invalid")
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    if not directory_flag:
        raise RemoteActionError("O_DIRECTORY is required")
    directory_flags = os.O_RDONLY | directory_flag | _nofollow_flags()
    file_flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | _nofollow_flags()
    components = logical_path.split("/")
    if components[:1] != [""] or any(
        not component or component in {".", ".."} for component in components[1:]
    ):
        raise RemoteActionError("attempt-broker executable path is not fixed")
    directory_fds: list[int] = []
    directory_identities: list[tuple[int, int, int, int, int, int]] = []
    directory_links: list[
        tuple[int, str, int, tuple[int, int, int, int, int, int]]
    ] = []
    file_fd = -1
    try:
        root_fd = os.open(root_path, directory_flags)
        directory_fds.append(root_fd)
        root_info = os.fstat(root_fd)
        owner_uid = root_info.st_uid
        owner_gid = root_info.st_gid
        if root_path == "/" and (owner_uid != 0 or owner_gid != 0):
            raise RemoteActionError("attempt-broker executable ancestry is unsafe")
        _require_attempt_broker_directory(
            root_info,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        directory_identities.append(_attempt_broker_directory_identity(root_info))
        parent_fd = root_fd
        for component in components[1:-1]:
            named_before = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            _require_attempt_broker_directory(
                named_before,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
            )
            child_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            directory_fds.append(child_fd)
            opened = os.fstat(child_fd)
            named_after = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            expected = _attempt_broker_directory_identity(opened)
            if (
                stat.S_ISLNK(named_before.st_mode)
                or stat.S_ISLNK(named_after.st_mode)
                or _attempt_broker_directory_identity(named_before) != expected
                or _attempt_broker_directory_identity(named_after) != expected
            ):
                raise RemoteActionError("attempt-broker executable ancestry changed")
            _require_attempt_broker_directory(
                opened,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
            )
            directory_identities.append(expected)
            directory_links.append((parent_fd, component, child_fd, expected))
            parent_fd = child_fd

        file_name = components[-1]
        named_before = os.stat(file_name, dir_fd=parent_fd, follow_symlinks=False)
        _require_attempt_broker_file(
            named_before,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        file_fd = os.open(file_name, file_flags, dir_fd=parent_fd)
        opened_file = os.fstat(file_fd)
        named_after = os.stat(file_name, dir_fd=parent_fd, follow_symlinks=False)
        expected_file = _attempt_broker_file_identity(opened_file)
        if (
            stat.S_ISLNK(named_before.st_mode)
            or stat.S_ISLNK(named_after.st_mode)
            or _attempt_broker_file_identity(named_before) != expected_file
            or _attempt_broker_file_identity(named_after) != expected_file
        ):
            raise RemoteActionError("attempt-broker executable changed while being opened")
        _require_attempt_broker_file(
            opened_file,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        digest, byte_count, finished = _hash_attempt_broker_descriptor(file_fd)
        if _attempt_broker_file_identity(finished) != expected_file:
            raise RemoteActionError("attempt-broker executable changed while being read")
        held = _HeldAttemptBrokerIdentity(
            directory_fds=directory_fds,
            directory_identities=directory_identities,
            directory_links=directory_links,
            file_fd=file_fd,
            file_parent_fd=parent_fd,
            file_name=file_name,
            file_identity=expected_file,
            digest=digest,
            byte_count=byte_count,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        directory_fds = []
        file_fd = -1
        return held
    except RemoteActionError:
        raise
    except OSError as exc:
        raise RemoteActionError("attempt-broker executable is absent or unsafe") from exc
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        for descriptor in reversed(directory_fds):
            os.close(descriptor)


def _open_state_parent(parent: str) -> int:
    directory = getattr(os, "O_DIRECTORY", 0)
    if not directory:
        raise RemoteActionError("O_DIRECTORY is required")
    flags = os.O_RDONLY | directory | _nofollow_flags()
    if parent == STATE_ROOT:
        try:
            before = os.lstat(STATE_ROOT)
        except OSError as exc:
            raise RemoteActionError("state directory is unsafe") from exc
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
            raise RemoteActionError("state directory is unsafe")
        if stat.S_IMODE(before.st_mode) & 0o022 and not (before.st_mode & stat.S_ISVTX):
            raise RemoteActionError("state directory is writable")
        fd = os.open(STATE_ROOT, flags)
        try:
            opened = os.fstat(fd)
        except OSError:
            os.close(fd)
            raise
        if _identity(before) != _identity(opened) or not stat.S_ISDIR(opened.st_mode):
            os.close(fd)
            raise RemoteActionError("state directory changed while being opened")
        return fd
    if parent != NFT_DIR:
        raise RemoteActionError("write path is not contained")
    root_fd = _open_state_parent(STATE_ROOT)
    child = -1
    try:
        try:
            os.mkdir("nft", 0o700, dir_fd=root_fd)
        except FileExistsError:
            pass
        child = os.open("nft", flags, dir_fd=root_fd)
        opened = os.fstat(child)
        named = os.stat("nft", dir_fd=root_fd, follow_symlinks=False)
        if (
            stat.S_ISLNK(named.st_mode)
            or not stat.S_ISDIR(opened.st_mode)
            or _identity(opened) != _identity(named)
        ):
            raise RemoteActionError("state directory is unsafe")
        if stat.S_IMODE(opened.st_mode) & 0o022:
            raise RemoteActionError("state directory is writable")
        return child
    except RemoteActionError:
        if child >= 0:
            os.close(child)
        raise
    except OSError as exc:
        if child >= 0:
            os.close(child)
        raise RemoteActionError("state directory is unsafe") from exc
    finally:
        os.close(root_fd)


def _read_regular(path: str, label: str, *, limit: int = MAX_OUTPUT) -> bytes:
    fd = -1
    try:
        before = os.lstat(path)
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
        ):
            raise RemoteActionError(f"{label} is not a regular single-link file")
        if before.st_size > limit:
            raise RemoteActionError(f"{label} is too large")
        fd = os.open(path, os.O_RDONLY | _nofollow_flags())
        opened = os.fstat(fd)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise RemoteActionError(f"{label} is too large")
        finished = os.fstat(fd)
        after = os.lstat(path)
    except RemoteActionError:
        raise
    except OSError as exc:
        raise RemoteActionError(f"{label} is unreadable") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    if not all(_identity(before) == _identity(item) for item in (opened, finished, after)):
        raise RemoteActionError(f"{label} changed while being read")
    data = b"".join(chunks)
    if not data:
        raise RemoteActionError(f"{label} is empty")
    return data


def _atomic_write(path: str, data: bytes, mode: int) -> None:
    _forbid_uncontained_write(path)
    if len(data) == 0 or len(data) > MAX_OUTPUT:
        raise RemoteActionError("write payload is too large")
    parent = os.path.dirname(path)
    leaf = os.path.basename(path)
    parent_fd = _open_state_parent(parent)
    tmp_name = f".remote-action.{os.getpid()}.{time.time_ns()}"
    tmp_fd = -1
    try:
        tmp_fd = os.open(
            tmp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _nofollow_flags(),
            0o600,
            dir_fd=parent_fd,
        )
        view = memoryview(data)
        while view:
            written = os.write(tmp_fd, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(tmp_fd)
        os.fchmod(tmp_fd, mode)
        os.close(tmp_fd)
        tmp_fd = -1
        os.replace(tmp_name, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        named = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if (
            named.st_size != len(data)
            or named.st_nlink != 1
            or not stat.S_ISREG(named.st_mode)
            or stat.S_IMODE(named.st_mode) != mode
        ):
            raise RemoteActionError("state file changed while being written")
    except RemoteActionError:
        raise
    except OSError as exc:
        raise RemoteActionError("state file write failed") from exc
    finally:
        if tmp_fd >= 0:
            os.close(tmp_fd)
        try:
            os.unlink(tmp_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def request_digest(request: Mapping[str, Any]) -> str:
    return sha256_bytes(
        canonical_bytes(
            {
                "action": request["action"],
                "challenge": request["challenge"],
                "client_build_identity": request["client_build_identity"],
                "contract": REQUEST_CONTRACT,
                "correlation_id": request["correlation_id"],
                "fleet_id": request["fleet_id"],
                "instance": request["instance"],
                "phase": request["phase"],
                "project": request["project"],
                "role": request["role"],
                "run_id": request["run_id"],
                "schema_version": REQUEST_SCHEMA_VERSION,
                "session_id": request["session_id"],
            }
        )
    )


def allowed_roles(action: str, phase: str) -> frozenset[str]:
    key = (action, phase)
    if key not in ACTION_PHASE_ROLES:
        raise RemoteActionError("unexpected phase")
    return ACTION_PHASE_ROLES[key]


def parse_argv(argv: Sequence[str]) -> dict[str, Any]:
    joined = " ".join(argv)
    for token in (
        "--command",
        "--cmd",
        "--shell",
        "--host",
        "--port",
        "--path",
        "--bytes-rx",
        "--bytes-tx",
        "--success",
        "--ok",
        "--pass",
        "--result",
        "--script",
    ):
        if token in joined:
            raise RemoteActionError("caller-supplied command, path, host, or success field is forbidden")
    if len(argv) != len(REQUEST_FLAG_ORDER):
        raise RemoteActionError("request argv has missing or extra tokens")
    values: dict[str, str] = {}
    for index, name in enumerate(REQUEST_FLAG_ORDER):
        token = argv[index]
        prefix = f"--{name}="
        if not token.startswith(prefix) or token.count("=") != 1:
            raise RemoteActionError(f"request argv must use the fixed --{name}=value form")
        value = token[len(prefix) :]
        if not value or VALUE_FORBIDDEN_RE.search(value) or "\x00" in value:
            raise RemoteActionError(f"request {name} is unsafe")
        values[name] = value
    if values["schema-version"] != str(REQUEST_SCHEMA_VERSION):
        raise RemoteActionError("unsupported request schema version")
    action = values["action"]
    if action not in ACTION_OPERATIONS:
        raise RemoteActionError("unsupported action")
    phase = values["phase"]
    if phase not in REQUEST_PHASES:
        raise RemoteActionError("unexpected phase")
    role = values["role"]
    if role not in {"control", "data-winn3", "data-cover"}:
        raise RemoteActionError("unexpected role")
    if role not in allowed_roles(action, phase):
        raise RemoteActionError("unexpected role")
    if not PROJECT_RE.fullmatch(values["project"]):
        raise RemoteActionError("project is invalid")
    if not INSTANCE_RE.fullmatch(values["instance"]):
        raise RemoteActionError("instance is invalid")
    if not FLEET_RE.fullmatch(values["fleet-id"]):
        raise RemoteActionError("fleet id is invalid")
    if not HEX64_RE.fullmatch(values["client-build-identity"]):
        raise RemoteActionError("client build identity is invalid")
    if not HEX64_RE.fullmatch(values["challenge"]):
        raise RemoteActionError("challenge is invalid")
    if not HEX64_RE.fullmatch(values["request-hash"]):
        raise RemoteActionError("request hash is invalid")
    for name in ("run-id", "session-id", "correlation-id"):
        if not ID_RE.fullmatch(values[name]):
            raise RemoteActionError(f"{name.replace('-', ' ')} is invalid")
    record = {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "contract": REQUEST_CONTRACT,
        "action": action,
        "phase": phase,
        "project": values["project"],
        "instance": values["instance"],
        "role": role,
        "fleet_id": values["fleet-id"],
        "run_id": values["run-id"],
        "session_id": values["session-id"],
        "correlation_id": values["correlation-id"],
        "client_build_identity": values["client-build-identity"],
        "challenge": values["challenge"],
        "request_sha256": values["request-hash"],
    }
    return validate_request(record)


def validate_request(raw: Any) -> dict[str, Any]:
    record = exact_keys(raw, REQUEST_KEYS, "request")
    if record["contract"] != REQUEST_CONTRACT:
        raise RemoteActionError("request contract is invalid")
    if exact_int(record["schema_version"], "request schema_version") != REQUEST_SCHEMA_VERSION:
        raise RemoteActionError("unsupported request schema version")
    for key, value in record.items():
        if key == "schema_version":
            continue
        if type(value) is not str or not value:
            raise RemoteActionError(f"request {key} is invalid")
        if VALUE_FORBIDDEN_RE.search(value) or "\x00" in value:
            raise RemoteActionError(f"request {key} is unsafe")
    action = record["action"]
    if action not in ACTION_OPERATIONS:
        raise RemoteActionError("unsupported action")
    phase = record["phase"]
    if phase not in REQUEST_PHASES:
        raise RemoteActionError("unexpected phase")
    role = record["role"]
    if role not in {"control", "data-winn3", "data-cover"}:
        raise RemoteActionError("unexpected role")
    if role not in allowed_roles(action, phase):
        raise RemoteActionError("unexpected role")
    if not PROJECT_RE.fullmatch(record["project"]):
        raise RemoteActionError("project is invalid")
    if not INSTANCE_RE.fullmatch(record["instance"]):
        raise RemoteActionError("instance is invalid")
    if not FLEET_RE.fullmatch(record["fleet_id"]):
        raise RemoteActionError("fleet id is invalid")
    if not HEX64_RE.fullmatch(record["client_build_identity"]):
        raise RemoteActionError("client build identity is invalid")
    if not HEX64_RE.fullmatch(record["challenge"]):
        raise RemoteActionError("challenge is invalid")
    if not HEX64_RE.fullmatch(record["request_sha256"]):
        raise RemoteActionError("request hash is invalid")
    for name in ("run_id", "session_id", "correlation_id"):
        if not ID_RE.fullmatch(record[name]):
            raise RemoteActionError(f"{name.replace('_', ' ')} is invalid")
    if request_digest(record) != record["request_sha256"]:
        raise RemoteActionError("request hash mismatch")
    return record


def run_allowlisted(host: Any, argv: Sequence[str]) -> CommandResult:
    allowed = allowlisted_commands()
    key = tuple(argv)
    if key not in allowed:
        raise RemoteActionError("command is not allowlisted")
    result = host.run(list(argv))
    if result.exit_code == 127:
        raise RemoteActionError(f"absent tool {argv[0]}")
    return result


def allowlisted_commands() -> set[tuple[str, ...]]:
    commands: set[tuple[str, ...]] = {
        (BIN_IP, "-json", "addr"),
        (BIN_IP, "-json", "route"),
        (BIN_IP, "-json", "-s", "link"),
        (BIN_SS, "-H", "-lnt"),
        (BIN_SS, "-H", "-lnu"),
        (BIN_AWG, "show", AWG_IFACE, "latest-handshakes"),
        (BIN_AWG, "show", AWG_IFACE, "transfer"),
        XRAY_STATSQUERY_ARGV,
        (BIN_NFT, "-f", NFT_AWG_FILE),
        (BIN_NFT, "-f", NFT_WINN3_FILE),
        (BIN_NFT, "-f", NFT_COVER_FILE),
        (BIN_NFT, "delete", "table", "inet", NFT_AWG_TABLE),
        (BIN_NFT, "delete", "table", "inet", NFT_WINN3_TABLE),
        (BIN_NFT, "delete", "table", "inet", NFT_COVER_TABLE),
        (BIN_NFT, "list", "table", "inet", NFT_AWG_TABLE),
        (BIN_NFT, "list", "table", "inet", NFT_WINN3_TABLE),
        (BIN_NFT, "list", "table", "inet", NFT_COVER_TABLE),
        (
            BIN_OPENSSL,
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            DESCRIPTOR_PUBKEY_PATH,
            "-rawin",
            "-in",
            DESCRIPTOR_PAYLOAD_PATH,
            "-sigfile",
            DESCRIPTOR_SIG_PATH,
        ),
    }
    units = {
        "wins-hub.service",
        "winn3-gateway.service",
        "xray.service",
        "docker.service",
    } | set(DATA_WINN3_FORBIDDEN_UNITS)
    for unit in units:
        commands.add((BIN_SYSTEMCTL, "is-active", unit))
        commands.add(
            (
                BIN_SYSTEMCTL,
                "show",
                unit,
                "--no-pager",
                "--property=Id,FragmentPath,MainPID,ActiveState",
            )
        )
        commands.add(
            (
                BIN_SYSTEMCTL,
                "show",
                unit,
                "--no-pager",
                "--property=Id,LoadState",
            )
        )
    return commands


def load_json_file(host: Any, path: str, keys: set[str], label: str) -> dict[str, Any]:
    return exact_keys(strict_json(host.read_file(path), label), keys, label)


def load_role(host: Any) -> str:
    text = host.read_file(ROLE_FILE).decode("ascii").strip()
    if text not in {"control", "data-winn3", "data-cover"}:
        raise RemoteActionError("role file is invalid")
    return text


def load_fleet_binding(host: Any, request: Mapping[str, Any]) -> dict[str, Any]:
    record = load_json_file(host, FLEET_BINDING_PATH, FLEET_BINDING_KEYS, "fleet binding")
    if (
        exact_int(record["schema_version"], "fleet binding schema_version") != SCHEMA_VERSION
        or record["contract"] != FLEET_BINDING_CONTRACT
        or record["project"] != request["project"]
        or record["fleet_id"] != request["fleet_id"]
    ):
        raise RemoteActionError("fleet binding is stale")
    names: list[str] = []
    for role in ("control", "data-winn3", "data-cover"):
        member = exact_keys(record[role], MEMBER_KEYS, f"fleet binding {role}")
        if not INSTANCE_RE.fullmatch(str(member["instance"])) or not ZONE_RE.fullmatch(
            str(member["zone"])
        ):
            raise RemoteActionError(f"fleet binding {role} identity is invalid")
        names.append(str(member["instance"]))
    if len(set(names)) != 3:
        raise RemoteActionError("fleet binding instance identities must be distinct")
    expected_instance = record[request["role"]]["instance"]
    if expected_instance != request["instance"]:
        raise RemoteActionError("fleet binding instance does not match the request")
    return record


def load_marker(host: Any, request: Mapping[str, Any]) -> dict[str, Any]:
    raw = load_json_file(host, MARKER_PATH, MARKER_KEYS, "deployment marker")
    if (
        raw["fleet_id"] != request["fleet_id"]
        or raw["instance"] != request["instance"]
        or raw["role"] != request["role"]
    ):
        raise RemoteActionError("deployment marker is stale")
    return raw


_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class _UTCDelta:
    """Duration with nanosecond precision, exposing timedelta-like total_seconds()."""

    __slots__ = ("_ns",)

    def __init__(self, ns: int) -> None:
        self._ns = ns

    def total_seconds(self) -> float:
        return self._ns / 1_000_000_000


class UTCInstant:
    """UTC instant with exact nanosecond precision, matching Go time.Time."""

    __slots__ = ("unix_ns",)

    def __init__(self, unix_ns: int) -> None:
        self.unix_ns = unix_ns

    def __eq__(self, other: object) -> bool:
        ns = _unix_ns(other)
        if ns is None:
            return NotImplemented
        return self.unix_ns == ns

    def __lt__(self, other: object) -> bool:
        ns = _unix_ns(other)
        if ns is None:
            return NotImplemented
        return self.unix_ns < ns

    def __le__(self, other: object) -> bool:
        ns = _unix_ns(other)
        if ns is None:
            return NotImplemented
        return self.unix_ns <= ns

    def __gt__(self, other: object) -> bool:
        ns = _unix_ns(other)
        if ns is None:
            return NotImplemented
        return self.unix_ns > ns

    def __ge__(self, other: object) -> bool:
        ns = _unix_ns(other)
        if ns is None:
            return NotImplemented
        return self.unix_ns >= ns

    def __sub__(self, other: object) -> _UTCDelta:
        ns = _unix_ns(other)
        if ns is None:
            return NotImplemented
        return _UTCDelta(self.unix_ns - ns)

    def __repr__(self) -> str:
        return f"UTCInstant({self.unix_ns})"


def _unix_ns(value: object) -> int | None:
    if isinstance(value, UTCInstant):
        return value.unix_ns
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return None
        utc = value.astimezone(timezone.utc)
        delta = utc.replace(microsecond=0) - _UNIX_EPOCH
        return (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + utc.microsecond * 1000
    return None


def format_rfc3339_nano(unix_ns: int) -> str:
    seconds, nano = divmod(unix_ns, 1_000_000_000)
    stamp = datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    if nano == 0:
        return stamp + "Z"
    return stamp + "." + f"{nano:09d}".rstrip("0") + "Z"


def parse_utc(value: str) -> UTCInstant:
    if type(value) is not str or not UTC_RE.fullmatch(value):
        raise RemoteActionError("timestamp is not canonical UTC")
    if not value.endswith("Z"):
        raise RemoteActionError("timestamp must use UTC Z form")
    stamp = value[:-1]
    fraction_digits = ""
    if "." in stamp:
        stamp, fraction_digits = stamp.split(".", 1)
    try:
        parsed = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError as suc:
        raise RemoteActionError("timestamp is not canonical UTC") from suc
    nano = int(fraction_digits.ljust(9, "0")) if fraction_digits else 0
    if nano < 0 or nano >= 1_000_000_000:
        raise RemoteActionError("timestamp is not canonical UTC")
    delta = parsed - _UNIX_EPOCH
    return UTCInstant((delta.days * 86_400 + delta.seconds) * 1_000_000_000 + nano)


def region_of(zone: str) -> str:
    return zone[: zone.rfind("-")]


def resource_identity(binding: Mapping[str, Any]) -> dict[str, Any]:
    fleet_id = str(binding["fleet_id"])
    subnets = [
        f"pf-{fleet_id}-sn-{role}"
        for role in ("control", "data-winn3", "data-cover")
    ]
    firewalls = sorted(
        [
            f"pf-{fleet_id}-admin-ssh",
            f"pf-{fleet_id}-control-http",
            f"pf-{fleet_id}-cover-in",
            f"pf-{fleet_id}-winn3-in",
        ]
    )
    return {
        "instances": [
            binding["control"]["instance"],
            binding["data-winn3"]["instance"],
            binding["data-cover"]["instance"],
        ],
        "network": f"pf-{fleet_id}-net",
        "subnets": subnets,
        "firewalls": firewalls,
    }


def parse_proc_net_dev(data: bytes) -> dict[str, tuple[int, int]]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RemoteActionError("interface counters are not ASCII") from exc
    result: dict[str, tuple[int, int]] = {}
    for line in text.splitlines():
        if ":" not in line or line.strip().startswith("Inter") or line.strip().startswith("face"):
            continue
        name, rest = line.split(":", 1)
        iface = name.strip()
        parts = rest.split()
        if len(parts) < 16:
            raise RemoteActionError("interface counter line is malformed")
        rx = exact_int(int(parts[0]), f"{iface} rx", minimum=0)
        tx = exact_int(int(parts[8]), f"{iface} tx", minimum=0)
        if iface in result:
            raise RemoteActionError("duplicate interface counter")
        result[iface] = (rx, tx)
    return result


def parse_ip_link_stats(data: bytes) -> dict[str, tuple[int, int]]:
    raw = strict_json(data, "ip link")
    if not isinstance(raw, list):
        raise RemoteActionError("ip link output is malformed")
    result: dict[str, tuple[int, int]] = {}
    for item in raw:
        if not isinstance(item, dict) or "ifname" not in item:
            raise RemoteActionError("ip link row is malformed")
        name = item["ifname"]
        if type(name) is not str or not name:
            raise RemoteActionError("ip link name is invalid")
        stats = item.get("stats64") or item.get("stats") or {}
        if not isinstance(stats, dict):
            raise RemoteActionError("ip link stats are malformed")
        rx_block = stats.get("rx") if isinstance(stats.get("rx"), dict) else {}
        tx_block = stats.get("tx") if isinstance(stats.get("tx"), dict) else {}
        rx = exact_int(rx_block.get("bytes", 0), f"{name} rx", minimum=0)
        tx = exact_int(tx_block.get("bytes", 0), f"{name} tx", minimum=0)
        if name in result:
            raise RemoteActionError("duplicate ip link name")
        result[name] = (rx, tx)
    return result


def require_matching_counters(
    proc_map: Mapping[str, tuple[int, int]],
    ip_map: Mapping[str, tuple[int, int]],
    names: Sequence[str],
) -> dict[str, tuple[int, int]]:
    result: dict[str, tuple[int, int]] = {}
    for name in names:
        if name not in proc_map or name not in ip_map:
            continue
        if proc_map[name] != ip_map[name]:
            raise RemoteActionError("interface counter sources disagree")
        result[name] = proc_map[name]
    return result


def parse_systemctl_show(data: bytes) -> dict[str, str]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RemoteActionError("systemctl show is not ASCII") from exc
    result: dict[str, str] = {}
    for line in text.splitlines():
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in result:
            raise RemoteActionError("duplicate systemctl show key")
        result[key] = value
    return result


def collect_service_evidence(host: Any, role: str) -> dict[str, Any]:
    units: dict[str, Any] = {}
    for unit in ROLE_UNITS[role]:
        active = run_allowlisted(host, (BIN_SYSTEMCTL, "is-active", unit))
        if active.exit_code not in {0, 3} or active.stderr.strip():
            raise RemoteActionError(f"absent tool or unit {unit}")
        state = active.stdout.decode("ascii").strip()
        shown = run_allowlisted(
            host,
            (
                BIN_SYSTEMCTL,
                "show",
                unit,
                "--no-pager",
                "--property=Id,FragmentPath,MainPID,ActiveState",
            ),
        )
        if shown.exit_code != 0:
            raise RemoteActionError(f"unable to inspect {unit}")
        fields = parse_systemctl_show(shown.stdout)
        if fields.get("Id") != unit or fields.get("ActiveState") != state:
            raise RemoteActionError(f"service identity is invalid: {unit}")
        fragment = fields.get("FragmentPath", "")
        pid = fields.get("MainPID", "0")
        exe_hash = None
        if pid.isdigit() and int(pid) > 0:
            exe_hash = host.hash_executable(f"/proc/{pid}/exe")
        unit_hash = None
        if fragment:
            if (
                ".." in fragment.split("/")
                or not fragment.startswith(UNIT_FRAGMENT_PREFIXES)
            ):
                raise RemoteActionError(f"unit fragment path is not contained: {unit}")
            unit_hash = sha256_bytes(host.read_file(fragment))
        units[unit] = {
            "active_state": state,
            "fragment_path": fragment,
            "fragment_sha256": unit_hash,
            "main_pid": int(pid) if pid.isdigit() else 0,
            "executable_sha256": exe_hash,
        }
    binaries: dict[str, str] = {}
    for path in ROLE_BINARIES[role]:
        binaries[path] = host.hash_executable(path)
    forbidden = {"units": {}, "binaries": {}}
    if role == "data-winn3":
        for unit in DATA_WINN3_FORBIDDEN_UNITS:
            shown = run_allowlisted(
                host,
                (
                    BIN_SYSTEMCTL,
                    "show",
                    unit,
                    "--no-pager",
                    "--property=Id,LoadState",
                ),
            )
            if shown.exit_code not in {0, 4}:
                raise RemoteActionError(f"unable to prove forbidden unit absence: {unit}")
            fields = parse_systemctl_show(shown.stdout) if shown.stdout.strip() else {}
            if fields.get("Id") not in {unit, None}:
                raise RemoteActionError(f"forbidden unit identity is invalid: {unit}")
            load_state = fields.get("LoadState", "not-found" if shown.exit_code == 4 else "")
            if shown.exit_code == 0 and load_state != "not-found":
                raise RemoteActionError(f"forbidden component is present on data-winn3: {unit}")
            if load_state not in {"not-found"}:
                raise RemoteActionError(f"forbidden unit absence is not proven: {unit}")
            forbidden["units"][unit] = {"load_state": load_state}
        for path in DATA_WINN3_FORBIDDEN_BINARIES:
            absent = not host.exists(path)
            if not absent:
                raise RemoteActionError(
                    f"forbidden component is present on data-winn3: {path}"
                )
            forbidden["binaries"][path] = {"absent": True}
    return {"units": units, "binaries": binaries, "forbidden": forbidden}


def collect_network_snapshot(host: Any) -> dict[str, Any]:
    addr = run_allowlisted(host, (BIN_IP, "-json", "addr"))
    route = run_allowlisted(host, (BIN_IP, "-json", "route"))
    link = run_allowlisted(host, (BIN_IP, "-json", "-s", "link"))
    sockets_tcp = run_allowlisted(host, (BIN_SS, "-H", "-lnt"))
    sockets_udp = run_allowlisted(host, (BIN_SS, "-H", "-lnu"))
    for item in (addr, route, link, sockets_tcp, sockets_udp):
        if item.exit_code != 0:
            raise RemoteActionError("absent tool or network probe failed")
    proc_map = parse_proc_net_dev(host.read_file(PROC_NET_DEV))
    ip_map = parse_ip_link_stats(link.stdout)
    counters = require_matching_counters(
        proc_map, ip_map, sorted(set(proc_map) | set(ip_map))
    )
    return {
        "addr": strict_json(addr.stdout, "ip addr") if addr.stdout.strip() else [],
        "route": strict_json(route.stdout, "ip route") if route.stdout.strip() else [],
        "sockets_tcp": sockets_tcp.stdout.decode("ascii"),
        "sockets_udp": sockets_udp.stdout.decode("ascii"),
        "counters": {name: {"rx": rx, "tx": tx} for name, (rx, tx) in sorted(counters.items())},
        "proc_counters": proc_map,
        "ip_counters": ip_map,
    }


def iface_delta(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    protocol: str,
) -> tuple[str, int, int]:
    raise RemoteActionError("synthetic interface evidence is not accepted")


def real_winn3_interface_counters(snapshot: Mapping[str, Any]) -> dict[str, dict[str, int]]:
    counters = snapshot.get("counters")
    if not isinstance(counters, dict):
        raise RemoteActionError("Winn3 interface counter evidence is missing")
    for name in counters:
        if type(name) is not str or not INTERFACE_RE.fullmatch(name):
            raise RemoteActionError("interface name is invalid")
        if name in SYNTHETIC_INTERFACES:
            continue
    if REAL_WINN3_INTERFACE not in counters:
        if any(name in SYNTHETIC_INTERFACES for name in counters):
            raise RemoteActionError("synthetic interface evidence is not accepted")
        raise RemoteActionError("Winn3 interface counter evidence is missing")
    selected = counters[REAL_WINN3_INTERFACE]
    return {
        REAL_WINN3_INTERFACE: {
            "rx": exact_int(selected["rx"], "winn3gw0 rx", minimum=0),
            "tx": exact_int(selected["tx"], "winn3gw0 tx", minimum=0),
        }
    }


def parse_proc_stat_starttime(data: bytes) -> int:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as suc:
        raise RemoteActionError("process stat is not ASCII") from suc
    close = text.rfind(")")
    if close < 0:
        raise RemoteActionError("process stat is malformed")
    fields = text[close + 1 :].split()
    if len(fields) < 20:
        raise RemoteActionError("process stat is malformed")
    try:
        starttime = int(fields[19])
    except ValueError as suc:
        raise RemoteActionError("process starttime is invalid") from suc
    return exact_int(starttime, "process starttime", minimum=1)


def collect_process_identity(
    host: Any, services: Mapping[str, Any], role: str
) -> dict[str, Any]:
    unit_name = ROLE_PRIMARY_UNIT[role]
    units = services.get("units")
    if not isinstance(units, dict) or unit_name not in units:
        raise RemoteActionError("process identity evidence is absent")
    record = units[unit_name]
    if not isinstance(record, dict):
        raise RemoteActionError("process identity is missing or malformed")
    pid = exact_int(record.get("main_pid"), f"{unit_name} main_pid", minimum=1)
    digest = record.get("executable_sha256")
    if type(digest) is not str or not HEX64_RE.fullmatch(digest):
        raise RemoteActionError("process identity is missing or malformed")
    starttime = parse_proc_stat_starttime(host.read_file(f"/proc/{pid}/stat"))
    try:
        comm = host.read_file(f"/proc/{pid}/comm").decode("ascii").strip()
    except UnicodeDecodeError as suc:
        raise RemoteActionError("process identity is missing or malformed") from suc
    if not COMM_RE.fullmatch(comm) or comm != ROLE_COMM[role]:
        raise RemoteActionError("process identity is not bound to the role service")
    return exact_keys(
        {
            "comm": comm,
            "exe_sha256": digest,
            "pid": pid,
            "starttime_ticks": starttime,
        },
        PROCESS_IDENTITY_KEYS,
        "process identity",
    )


def load_instance_id(host: Any) -> str:
    if host.exists(INSTANCE_ID_PATH):
        text = host.read_file(INSTANCE_ID_PATH).decode("ascii").strip()
        if GCE_INSTANCE_ID_RE.fullmatch(text):
            return text
        raise RemoteActionError("instance id is invalid")
    if host.exists(DMI_PRODUCT_SERIAL_PATH):
        text = host.read_file(DMI_PRODUCT_SERIAL_PATH).decode("ascii").strip()
        matched = DMI_INSTANCE_RE.fullmatch(text)
        if matched is not None:
            return matched.group(1)
        raise RemoteActionError("instance id is invalid")
    raise RemoteActionError("instance id is absent")


def load_boot_id(host: Any) -> str:
    text = host.read_file(BOOT_ID_PATH).decode("ascii").strip()
    if not BOOT_ID_RE.fullmatch(text):
        raise RemoteActionError("boot id is invalid")
    return text


def requires_attempt_broker_identity(request: Mapping[str, Any]) -> bool:
    return (
        request["role"] == "control"
        and request["phase"] == PHASE_EXERCISE
        and request["action"] in ATTEMPT_ACK_ACTIONS
    )


def collect_helper_hashes(host: Any, request: Mapping[str, Any]) -> dict[str, str]:
    remote = host.hash_executable(INSTALL_PATH)
    if type(remote) is not str or not HEX64_RE.fullmatch(remote) or remote == "0" * 64:
        raise RemoteActionError("helper hash evidence is missing or malformed")
    raw = host.read_file(HELPER_IDENTITY_PATH)
    identity = exact_keys(
        strict_json(raw, "helper identity"),
        HELPER_IDENTITY_KEYS,
        "helper identity",
    )
    if canonical_bytes(identity) != raw:
        raise RemoteActionError("remote proof-action helper identity is not canonical")
    if identity["required_roles"] != list(HELPER_REQUIRED_ROLES):
        raise RemoteActionError("remote proof-action helper identity is stale")
    candidate = identity["candidate_id"]
    if type(candidate) is not str or not HEX64_RE.fullmatch(candidate):
        raise RemoteActionError("remote proof-action helper identity is stale")
    if (
        identity["kind"] != HELPER_IDENTITY_KIND
        or exact_int(identity["schema_version"], "helper identity schema_version")
        != SCHEMA_VERSION
        or identity["contract"] != HELPER_IDENTITY_CONTRACT
        or identity["path"] != INSTALL_PATH
        or identity["source_path"] != HELPER_SOURCE_PATH
        or identity["sha256"] != remote
        or exact_int(identity["mode"], "helper identity mode") != HELPER_INSTALL_MODE
        or exact_int(identity["bytes"], "helper identity bytes", minimum=1) < 1
        or identity["role"] != request["role"]
        or identity["fleet_id"] != request["fleet_id"]
        or identity["instance"] != request["instance"]
        or type(identity["sha256"]) is not str
        or not HEX64_RE.fullmatch(identity["sha256"])
    ):
        raise RemoteActionError("remote proof-action helper identity is stale")
    binder = getattr(host, "require_helper_identity_binding", None)
    if binder is None:
        raise RemoteActionError("helper identity binding is absent")
    binder(identity)
    return {"remote": remote}


def transaction_protocol(request: Mapping[str, Any]) -> str:
    role = request["role"]
    action = request["action"]
    phase = request["phase"]
    if role == "data-winn3":
        return "winn3"
    if role == "data-cover" and action == "connect-cover-awg":
        return "awg"
    if role == "data-cover" and action == "connect-cover-xray":
        return "xray"
    if role == "data-cover" and action in {
        "probe-awg-block",
        "inject-awg-block",
        "restore-awg",
    }:
        return "awg-xray-fallback"
    if role == "data-cover":
        return "cover"
    if action == "probe-awg-block" and phase == PHASE_EXERCISE:
        return "awg-xray-fallback"
    if action == "connect-cover-awg":
        return "awg"
    if action == "connect-cover-xray":
        return "xray"
    if action == "teardown-check":
        return "scope"
    if action in {"withdraw-cover", "restore-cover", "probe-cover-withdrawn"}:
        return "cover"
    return "winn3"


def transaction_record(
    challenge: str, kind: str, protocol: str, response: Mapping[str, Any]
) -> dict[str, Any]:
    if not HEX64_RE.fullmatch(challenge):
        raise RemoteActionError("challenge is invalid")
    if not isinstance(response, dict) or not response:
        raise RemoteActionError("exact transaction response is invalid")
    digest = sha256_bytes(canonical_bytes(response))
    return exact_keys(
        {
            "contract": TRANSACTION_CONTRACT,
            "kind": kind,
            "nonce": challenge,
            "protocol": protocol,
            "response": dict(response),
            "response_sha256": digest,
        },
        TRANSACTION_KEYS,
        "nonce-bound transaction",
    )


def load_winn3_status(
    host: Any, role: str, *, require_activity: bool = False
) -> dict[str, Any]:
    path = WINN3_STATUS_PATHS[role]
    if role == "data-winn3":
        evidence = host.read_gateway_status_evidence(path)
    else:
        raise RemoteActionError("Winn3 status v2 is not the role-specific gateway evidence")
    record = exact_keys(
        strict_json(evidence, "winn3 status"),
        WINN3_STATUS_KEYS,
        "winn3 status",
    )
    if (
        exact_int(record["schema_version"], "winn3 status schema_version")
        != WINN3_STATUS_SCHEMA_VERSION
        or record["contract"] != WINN3_STATUS_CONTRACT
    ):
        raise RemoteActionError("winn3 status contract is invalid")
    exact_bool(record["forward"], True, "winn3 forward")
    exact_bool(record["ready"], True, "winn3 ready")
    if type(record["event"]) is not str or record["event"] != "posture":
        raise RemoteActionError("winn3 status event is invalid")
    process_id = exact_int(record["process_id"], "winn3 process_id", minimum=1)
    nonce = record["process_nonce"]
    if type(nonce) is not str or not PROCESS_NONCE_RE.fullmatch(nonce):
        raise RemoteActionError("winn3 process nonce is invalid")
    boot_id = record["boot_id"]
    if type(boot_id) is not str or not BOOT_ID_RE.fullmatch(boot_id):
        raise RemoteActionError("winn3 status boot id is invalid")
    if boot_id != load_boot_id(host):
        raise RemoteActionError("winn3 status boot id does not match the host")
    exact_int(record["process_start_ticks"], "winn3 process_start_ticks", minimum=1)
    exact_int(record["observed_monotonic_ns"], "winn3 observed_monotonic_ns", minimum=1)
    parse_utc(str(record["process_started_utc"]))
    observed = parse_utc(str(record["observed_utc"]))
    if observed <= parse_utc(str(record["process_started_utc"])):
        raise RemoteActionError("Winn3 status v2 observation time is invalid")
    exact_int(record["sequence"], "winn3 sequence", minimum=1)
    reflected = exact_int(record["reflected"], "winn3 reflected", minimum=0)
    delivered = exact_int(
        record["inner_packets_delivered"], "winn3 inner_packets_delivered", minimum=0
    )
    writes = exact_int(record["rx_device_writes"], "winn3 rx_device_writes", minimum=0)
    if reflected > 0 and delivered == 0:
        raise RemoteActionError("reflection mode")
    if not record["forward"]:
        raise RemoteActionError("reflection mode")
    if require_activity and (delivered == 0 or writes == 0 or process_id <= 0):
        raise RemoteActionError("zero or unchanged counters")
    return record


def winn3_status_delta(
    before: Mapping[str, Any], after: Mapping[str, Any]
) -> dict[str, int]:
    for key in WINN3_STATUS_IDENTITY_KEYS:
        if before.get(key) != after.get(key):
            raise RemoteActionError("Winn3 status process identity changed")
    if parse_utc(str(after["observed_utc"])) <= parse_utc(str(before["observed_utc"])):
        raise RemoteActionError("Winn3 status observation is not strictly ordered")
    if exact_int(
        after["observed_monotonic_ns"], "winn3 observed_monotonic_ns", minimum=1
    ) <= exact_int(
        before["observed_monotonic_ns"], "winn3 observed_monotonic_ns", minimum=1
    ):
        raise RemoteActionError("Winn3 status monotonic observation is not strictly ordered")
    sequence = exact_int(after["sequence"], "winn3 sequence", minimum=0) - exact_int(
        before["sequence"], "winn3 sequence", minimum=0
    )
    if sequence <= 0:
        raise RemoteActionError("Winn3 status sequence did not increase")
    delivered = exact_int(
        after["inner_packets_delivered"], "winn3 inner_packets_delivered", minimum=0
    ) - exact_int(
        before["inner_packets_delivered"], "winn3 inner_packets_delivered", minimum=0
    )
    writes = exact_int(
        after["rx_device_writes"], "winn3 rx_device_writes", minimum=0
    ) - exact_int(before["rx_device_writes"], "winn3 rx_device_writes", minimum=0)
    if delivered <= 0 or writes <= 0:
        raise RemoteActionError("Winn3 status counters did not increase during the action")
    if delivered > writes:
        raise RemoteActionError("Winn3 status counter relationship is invalid")
    return {
        "inner_packets_delivered": delivered,
        "rx_device_writes": writes,
        "sequence": sequence,
    }


def require_winn3_process_binding(
    status: Mapping[str, Any],
    services: Mapping[str, Any],
    process_identity: Mapping[str, Any],
) -> None:
    unit = services.get("units", {}).get("winn3-gateway.service")
    if not isinstance(unit, dict):
        raise RemoteActionError("Winn3 gateway process identity is absent")
    pid = exact_int(status["process_id"], "winn3 process_id", minimum=1)
    if exact_int(unit.get("main_pid"), "winn3-gateway main_pid", minimum=1) != pid:
        raise RemoteActionError("Winn3 status process identity does not match the service")
    if exact_int(process_identity["pid"], "process identity pid", minimum=1) != pid:
        raise RemoteActionError("Winn3 status process identity does not match the service")
    if exact_int(
        status["process_start_ticks"], "winn3 process_start_ticks", minimum=1
    ) != exact_int(
        process_identity["starttime_ticks"], "process identity starttime_ticks", minimum=1
    ):
        raise RemoteActionError("Winn3 status process start does not match the service")


def parse_awg_peer_sample(handshakes: bytes, transfer: bytes) -> dict[str, Any]:
    try:
        handshake_text = handshakes.decode("ascii")
        transfer_text = transfer.decode("ascii")
    except UnicodeDecodeError as suc:
        raise RemoteActionError("AWG peer evidence is not ASCII") from suc
    handshake_peer = ""
    handshake_unix = -1
    for line in handshake_text.splitlines():
        fields = line.split()
        if len(fields) != 2 or not AWG_PEER_RE.fullmatch(fields[0]) or not fields[1].isdigit():
            raise RemoteActionError("AWG handshake output is malformed")
        if handshake_peer:
            raise RemoteActionError("AWG peer identity is not exact")
        handshake_peer = fields[0]
        handshake_unix = int(fields[1])
    transfer_peer = ""
    rx = -1
    tx = -1
    for line in transfer_text.splitlines():
        fields = line.split()
        if (
            len(fields) != 3
            or not AWG_PEER_RE.fullmatch(fields[0])
            or not fields[1].isdigit()
            or not fields[2].isdigit()
        ):
            raise RemoteActionError("AWG transfer output is malformed")
        if transfer_peer:
            raise RemoteActionError("AWG peer identity is not exact")
        transfer_peer = fields[0]
        rx = int(fields[1])
        tx = int(fields[2])
    if not handshake_peer or not transfer_peer or handshake_peer != transfer_peer:
        raise RemoteActionError("AWG peer identity is absent or inconsistent")
    return exact_keys(
        {
            "peer": handshake_peer,
            "rx": exact_int(rx, "AWG peer rx", minimum=0),
            "tx": exact_int(tx, "AWG peer tx", minimum=0),
            "handshake_unix": exact_int(handshake_unix, "AWG handshake", minimum=0),
        },
        AWG_PEER_KEYS,
        "AWG peer sample",
    )


def collect_awg_peer(host: Any) -> dict[str, Any]:
    handshake = run_allowlisted(host, (BIN_AWG, "show", AWG_IFACE, "latest-handshakes"))
    transfer = run_allowlisted(host, (BIN_AWG, "show", AWG_IFACE, "transfer"))
    if handshake.exit_code != 0 or transfer.exit_code != 0:
        raise RemoteActionError("absent tool or AWG peer probe failed")
    return parse_awg_peer_sample(handshake.stdout, transfer.stdout)


def awg_peer_evidence(sample: Mapping[str, Any]) -> dict[str, Any]:
    return exact_keys(
        {
            "latest_handshake_unix": exact_int(
                sample["handshake_unix"], "AWG handshake", minimum=0
            ),
            "public_key": sample["peer"],
            "rx": exact_int(sample["rx"], "AWG peer rx", minimum=0),
            "tx": exact_int(sample["tx"], "AWG peer tx", minimum=0),
        },
        AWG_PEER_EVIDENCE_KEYS,
        "AWG peer evidence",
    )


def collect_awg_peers(host: Any) -> list[dict[str, Any]]:
    return [awg_peer_evidence(collect_awg_peer(host))]


def awg_peer_delta(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    *,
    started: datetime,
    ended: datetime,
    require_increase: bool,
) -> dict[str, Any]:
    if before.get("peer") != after.get("peer") or not AWG_PEER_RE.fullmatch(str(after.get("peer", ""))):
        raise RemoteActionError("AWG peer identity changed")
    rx = exact_int(after["rx"], "AWG peer rx", minimum=0) - exact_int(
        before["rx"], "AWG peer rx", minimum=0
    )
    tx = exact_int(after["tx"], "AWG peer tx", minimum=0) - exact_int(
        before["tx"], "AWG peer tx", minimum=0
    )
    handshake_unix = exact_int(after["handshake_unix"], "AWG handshake", minimum=0)
    handshake = UTCInstant(handshake_unix * 1_000_000_000) if handshake_unix > 0 else None
    in_window = handshake is not None and started <= handshake <= ended
    if require_increase:
        if rx <= 0 or tx <= 0:
            raise RemoteActionError("AWG peer transfer counters did not increase")
        if handshake is None or handshake_unix <= 0:
            raise RemoteActionError("AWG handshake has never completed")
        if not in_window:
            raise RemoteActionError("AWG handshake is outside the action window")
    else:
        if rx != 0 or tx != 0:
            raise RemoteActionError("AWG peer transfer contradicted the blocked attempt")
        if in_window:
            raise RemoteActionError("AWG failure contradicted by an in-window handshake")
    latest = format_rfc3339_nano(handshake.unix_ns) if handshake is not None else ""
    return {
        "peer": after["peer"],
        "rx": rx,
        "tx": tx,
        "latest_handshake_utc": latest,
        "handshake_unix": handshake_unix,
    }


def parse_xray_stats(data: bytes) -> dict[str, Any]:
    raw = strict_json(data, "xray StatsService")
    if not isinstance(raw, dict):
        raise RemoteActionError("xray StatsService response is malformed")
    if any(key in raw for key in ("reset", "Reset")):
        raise RemoteActionError("xray StatsService reset is forbidden")
    stats = raw.get("stat")
    if stats is None:
        stats = raw.get("stats")
    if isinstance(stats, dict):
        stats = [stats]
    if not isinstance(stats, list) or not stats:
        raise RemoteActionError("xray StatsService exact-user counters are absent")
    user = ""
    uplink = None
    downlink = None
    for item in stats:
        if not isinstance(item, dict) or "name" not in item:
            raise RemoteActionError("xray StatsService row is malformed")
        name = item["name"]
        if type(name) is not str or name.startswith("inbound>>>") or name.startswith("outbound>>>"):
            raise RemoteActionError("xray StatsService aggregate counters are forbidden")
        matched = XRAY_STAT_NAME_RE.fullmatch(name)
        if matched is None:
            raise RemoteActionError("xray StatsService name is not an exact user counter")
        item_user = matched.group(1)
        direction = matched.group(2)
        if user and item_user != user:
            raise RemoteActionError("xray StatsService user identity is not exact")
        user = item_user
        value = item.get("value")
        if type(value) is str and value.isdigit():
            value = int(value)
        count = exact_int(value, f"xray {direction}", minimum=0)
        if direction == "uplink":
            if uplink is not None:
                raise RemoteActionError("xray StatsService uplink is duplicated")
            uplink = count
        else:
            if downlink is not None:
                raise RemoteActionError("xray StatsService downlink is duplicated")
            downlink = count
    if not user or not XRAY_USER_RE.fullmatch(user) or uplink is None or downlink is None:
        raise RemoteActionError("xray StatsService exact-user counters are incomplete")
    return exact_keys(
        {"user": user, "uplink": uplink, "downlink": downlink},
        XRAY_STATS_KEYS,
        "xray StatsService sample",
    )


def collect_xray_stats(host: Any) -> dict[str, Any]:
    result = run_allowlisted(host, XRAY_STATSQUERY_ARGV)
    if result.exit_code != 0:
        raise RemoteActionError("absent tool or Xray StatsService probe failed")
    return parse_xray_stats(result.stdout)


def xray_stats_delta(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    *,
    require_increase: bool,
) -> dict[str, Any]:
    if before.get("user") != after.get("user") or not XRAY_USER_RE.fullmatch(str(after.get("user", ""))):
        raise RemoteActionError("xray StatsService user identity changed")
    uplink = exact_int(after["uplink"], "xray uplink", minimum=0) - exact_int(
        before["uplink"], "xray uplink", minimum=0
    )
    downlink = exact_int(after["downlink"], "xray downlink", minimum=0) - exact_int(
        before["downlink"], "xray downlink", minimum=0
    )
    if require_increase:
        if uplink <= 0 or downlink <= 0:
            raise RemoteActionError("xray StatsService exact-user counters did not increase")
    elif uplink != 0 or downlink != 0:
        raise RemoteActionError("xray StatsService exact-user counters contradicted the blocked attempt")
    return {"user": after["user"], "uplink": uplink, "downlink": downlink}


def load_attempt_journal(host: Any, *, required: bool) -> dict[str, Any]:
    if not host.exists(ATTEMPT_JOURNAL_PATH):
        if required:
            raise RemoteActionError("timestamped protocol attempt journal is absent")
        return {
            "schema_version": SCHEMA_VERSION,
            "contract": ATTEMPT_JOURNAL_CONTRACT,
            "events": [],
        }
    record = exact_keys(
        strict_json(
            host.read_root_owned_evidence(ATTEMPT_JOURNAL_PATH),
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
        raise RemoteActionError("protocol attempt journal contract is invalid")
    events: list[dict[str, Any]] = []
    for index, raw in enumerate(record["events"]):
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
                raise RemoteActionError(f"protocol attempt event {index} is invalid")
            if VALUE_FORBIDDEN_RE.search(event[key]):
                raise RemoteActionError(f"protocol attempt event {index} is invalid")
        exact_int(event["monotonic_ns"], "attempt monotonic", minimum=0)
        parse_utc(event["utc"])
        if (
            event["action"] not in ATTEMPT_ACK_ACTIONS
            or event["protocol"] not in {"awg", "winn3", "xray"}
            or event["phase"] not in {"started", "finished"}
            or (event["phase"] == "started" and event["result"] != "pending")
            or (
                event["phase"] == "finished"
                and event["result"] not in {"connected", "failed"}
            )
        ):
            raise RemoteActionError(f"protocol attempt event {index} is invalid")
        events.append(dict(event))
    if len(events) % 2 != 0:
        raise RemoteActionError("protocol attempt journal is stale")
    last_mono = -1
    last_utc: UTCInstant | None = None
    for index in range(0, len(events), 2):
        started_event = events[index]
        finished_event = events[index + 1]
        if (
            started_event["phase"] != "started"
            or finished_event["phase"] != "finished"
            or any(
                started_event[key] != finished_event[key]
                for key in (
                    "action",
                    "correlation_id",
                    "node",
                    "protocol",
                    "session_id",
                )
            )
        ):
            raise RemoteActionError("protocol attempt journal is stale")
        for event in (started_event, finished_event):
            monotonic = exact_int(event["monotonic_ns"], "attempt monotonic", minimum=0)
            stamp = parse_utc(event["utc"])
            if monotonic <= last_mono or (last_utc is not None and stamp <= last_utc):
                raise RemoteActionError(
                    "protocol attempt timestamps are not strictly ordered"
                )
            last_mono = monotonic
            last_utc = stamp
    return {
        "schema_version": SCHEMA_VERSION,
        "contract": ATTEMPT_JOURNAL_CONTRACT,
        "events": events,
    }


def require_awg_then_xray_attempts(
    before: Mapping[str, Any],
    after_awg: Mapping[str, Any],
    after: Mapping[str, Any],
    request: Mapping[str, Any],
    *,
    node: str,
    started_mono: int,
    ended_mono: int,
    started: datetime,
    ended: datetime,
) -> list[dict[str, Any]]:
    previous = before["events"]
    awg_current = after_awg["events"]
    current = after["events"]
    if len(awg_current) <= len(previous) or awg_current[: len(previous)] != previous:
        raise RemoteActionError("protocol attempt journal did not append atomically")
    if len(current) <= len(awg_current) or current[: len(awg_current)] != awg_current:
        raise RemoteActionError("protocol attempt journal did not append atomically")
    awg_observed = awg_current[len(previous) :]
    xray_observed = current[len(awg_current) :]
    observed = awg_observed + xray_observed
    expected = (
        ("awg", "started", "pending"),
        ("awg", "finished", "failed"),
        ("xray", "started", "pending"),
        ("xray", "finished", "connected"),
    )
    if len(awg_observed) != 2 or len(xray_observed) != 2:
        raise RemoteActionError("exact AWG-first fallback attempt sequence is absent")
    last_mono = started_mono
    last_utc = started
    for event, (protocol, phase, result) in zip(observed, expected):
        if (
            event["action"] != request["action"]
            or event["correlation_id"] != request["correlation_id"]
            or event["session_id"] != request["session_id"]
            or event["node"] != node
            or event["protocol"] != protocol
            or event["phase"] != phase
            or event["result"] != result
        ):
            raise RemoteActionError("AWG-first fallback attempt sequence is invalid")
        event_mono = exact_int(event["monotonic_ns"], "attempt monotonic", minimum=0)
        if not (last_mono < event_mono < ended_mono):
            raise RemoteActionError("protocol attempt timestamps are not strictly ordered")
        event_utc = parse_utc(event["utc"])
        if not (last_utc < event_utc < ended):
            raise RemoteActionError("protocol attempt UTC timestamps are not strictly ordered")
        last_mono = event_mono
        last_utc = event_utc
    return [dict(event) for event in observed]


def require_single_protocol_attempt(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    request: Mapping[str, Any],
    *,
    node: str,
    protocol: str,
    result: str,
    started_mono: int,
    ended_mono: int,
    started: datetime,
    ended: datetime,
) -> list[dict[str, Any]]:
    previous = before["events"]
    current = after["events"]
    if len(current) <= len(previous) or current[: len(previous)] != previous:
        raise RemoteActionError("protocol attempt journal did not append atomically")
    observed = current[len(previous) :]
    expected = (("started", "pending"), ("finished", result))
    if len(observed) != len(expected):
        raise RemoteActionError("exact protocol attempt sequence is absent")
    last_mono = started_mono
    last_utc = started
    for event, (phase, expected_result) in zip(observed, expected):
        if (
            event["action"] != request["action"]
            or event["correlation_id"] != request["correlation_id"]
            or event["session_id"] != request["session_id"]
            or event["node"] != node
            or event["protocol"] != protocol
            or event["phase"] != phase
            or event["result"] != expected_result
        ):
            raise RemoteActionError("protocol attempt sequence is invalid")
        event_mono = exact_int(event["monotonic_ns"], "attempt monotonic", minimum=0)
        if not (last_mono < event_mono < ended_mono):
            raise RemoteActionError("protocol attempt timestamps are not strictly ordered")
        event_utc = parse_utc(event["utc"])
        if not (last_utc < event_utc < ended):
            raise RemoteActionError("protocol attempt UTC timestamps are not strictly ordered")
        last_mono = event_mono
        last_utc = event_utc
    return [dict(event) for event in observed]


def require_no_awg_handshake_during_attempt(
    data: bytes, started: datetime, ended: datetime
) -> None:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RemoteActionError("AWG handshake output is not ASCII") from exc
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 2 or not fields[1].isdigit():
            raise RemoteActionError("AWG handshake output is malformed")
        stamp = int(fields[1])
        if stamp <= 0:
            continue
        handshake = UTCInstant(stamp * 1_000_000_000)
        if started <= handshake <= ended:
            raise RemoteActionError("AWG failure contradicted by an in-window handshake")


def hub_nodes(host: Any) -> list[dict[str, Any]]:
    health = strict_json(host.http_get("/healthz"), "hub healthz")
    if not isinstance(health, dict) or health.get("service") != "wins-hub":
        raise RemoteActionError("local hub healthz is invalid")
    payload = strict_json(host.http_get("/nodes"), "hub nodes")
    if not isinstance(payload, dict) or not isinstance(payload.get("nodes"), list):
        raise RemoteActionError("hub nodes listing is malformed")
    nodes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in payload["nodes"]:
        if not isinstance(item, dict):
            raise RemoteActionError("hub node row is malformed")
        slug = item.get("slug")
        if type(slug) is not str or not INSTANCE_RE.fullmatch(slug):
            raise RemoteActionError("hub node slug is invalid")
        if slug in seen:
            raise RemoteActionError("duplicate hub node slug")
        seen.add(slug)
        nodes.append(
            {
                "slug": slug,
                "carrier": item.get("carrier"),
                "protocol_version": item.get("protocol_version"),
                "reachable": item.get("reachable"),
            }
        )
    return nodes


def require_winn3_node(nodes: Sequence[Mapping[str, Any]], binding: Mapping[str, Any]) -> str:
    winn3 = str(binding["data-winn3"]["instance"])
    cover = str(binding["data-cover"]["instance"])
    matches = [
        item
        for item in nodes
        if item.get("carrier") == "winn3" and item.get("protocol_version") in {"winn/3", "winn3"}
    ]
    if len(matches) != 1 or matches[0]["slug"] != winn3:
        raise RemoteActionError("signed Winn3 node binding is absent")
    if matches[0]["reachable"] is not True:
        raise RemoteActionError("Winn3 canary is not reachable")
    if matches[0]["slug"] == cover:
        raise RemoteActionError("same-node fallback is forbidden")
    return winn3


def require_cover_node(nodes: Sequence[Mapping[str, Any]], binding: Mapping[str, Any]) -> str:
    cover = str(binding["data-cover"]["instance"])
    winn3 = str(binding["data-winn3"]["instance"])
    matches = [
        item
        for item in nodes
        if item.get("slug") == cover
        and item.get("carrier") in {"amneziawg", "xray"}
        and item.get("protocol_version") in {"winn/1", "winn1"}
    ]
    if not matches:
        raise RemoteActionError("cover node binding is absent")
    if cover == winn3:
        raise RemoteActionError("same-node fallback is forbidden")
    return cover


def descriptor_node_from_payload(payload: bytes) -> str:
    record = strict_json(payload, "winn3 descriptor payload")
    if not isinstance(record, dict):
        raise RemoteActionError("winn3 descriptor payload must be an object")
    identity_keys = [
        key for key in record if key.casefold() in DESCRIPTOR_IDENTITY_KEYS
    ]
    if identity_keys != ["node"]:
        raise RemoteActionError("winn3 descriptor payload node identity is ambiguous")
    node = record["node"]
    if type(node) is not str or not INSTANCE_RE.fullmatch(node):
        raise RemoteActionError("winn3 descriptor payload node identity is invalid")
    return node


def verify_descriptor(host: Any) -> tuple[str, str]:
    envelope_bytes = host.read_file(DESCRIPTOR_PATH)
    envelope = exact_keys(
        strict_json(envelope_bytes, "winn3 descriptor"), DESCRIPTOR_KEYS, "winn3 descriptor"
    )
    payload_b64 = envelope["payload"]
    sig_b64 = envelope["sig"]
    if type(payload_b64) is not str or type(sig_b64) is not str or not payload_b64 or not sig_b64:
        raise RemoteActionError("winn3 descriptor envelope is incomplete")
    try:
        payload = base64.b64decode(payload_b64, validate=True)
        signature = base64.b64decode(sig_b64, validate=True)
    except (ValueError, binascii.Error) as suc:
        raise RemoteActionError("winn3 descriptor envelope is not valid base64") from suc
    if not payload or not signature:
        raise RemoteActionError("winn3 descriptor envelope is incomplete")
    if len(payload) > MAX_DESCRIPTOR_PART or len(signature) > MAX_DESCRIPTOR_PART:
        raise RemoteActionError("winn3 descriptor envelope is too large")
    pubkey = host.read_file(DESCRIPTOR_PUBKEY_PATH)
    if not pubkey:
        raise RemoteActionError("winn3 descriptor public key is empty")
    host.write_file(DESCRIPTOR_PAYLOAD_PATH, payload, 0o600)
    host.write_file(DESCRIPTOR_SIG_PATH, signature, 0o600)
    if (
        host.read_file(DESCRIPTOR_PAYLOAD_PATH) != payload
        or host.read_file(DESCRIPTOR_SIG_PATH) != signature
        or host.read_file(DESCRIPTOR_PUBKEY_PATH) != pubkey
    ):
        raise RemoteActionError("winn3 descriptor path changed while being verified")
    verified = run_allowlisted(
        host,
        (
            BIN_OPENSSL,
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            DESCRIPTOR_PUBKEY_PATH,
            "-rawin",
            "-in",
            DESCRIPTOR_PAYLOAD_PATH,
            "-sigfile",
            DESCRIPTOR_SIG_PATH,
        ),
    )
    if verified.exit_code != 0:
        raise RemoteActionError("winn3 descriptor signature is not verified")
    if (
        host.read_file(DESCRIPTOR_PAYLOAD_PATH) != payload
        or host.read_file(DESCRIPTOR_SIG_PATH) != signature
        or host.read_file(DESCRIPTOR_PUBKEY_PATH) != pubkey
    ):
        raise RemoteActionError("winn3 descriptor path changed while being verified")
    return sha256_bytes(envelope_bytes), descriptor_node_from_payload(payload)


def parse_awg_handshake(data: bytes, started: datetime, ended: datetime) -> str:
    try:
        text = data.decode("ascii").strip()
    except UnicodeDecodeError as suc:
        raise RemoteActionError("AWG handshake output is not ASCII") from suc
    if not text:
        raise RemoteActionError("AWG handshake evidence is absent")
    latest = 0
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            raise RemoteActionError("AWG handshake line is malformed")
        try:
            stamp = int(parts[-1])
        except ValueError as suc:
            raise RemoteActionError("AWG handshake timestamp is invalid") from suc
        if stamp > latest:
            latest = stamp
    if latest <= 0:
        raise RemoteActionError("AWG handshake has never completed")
    handshake = UTCInstant(latest * 1_000_000_000)
    if handshake < started or handshake > ended:
        raise RemoteActionError("AWG handshake is outside the action window")
    return format_rfc3339_nano(handshake.unix_ns)


def consume_replay(host: Any, request: Mapping[str, Any]) -> None:
    digest = request["request_sha256"]
    if type(digest) is not str or not HEX64_RE.fullmatch(digest):
        raise RemoteActionError("request hash is invalid")
    if host.exists(REPLAY_PATH):
        record = load_json_file(host, REPLAY_PATH, REPLAY_KEYS, "remote action replay")
        if (
            exact_int(record["schema_version"], "replay schema_version") != SCHEMA_VERSION
            or record["contract"] != REPLAY_CONTRACT
        ):
            raise RemoteActionError("remote action replay log is stale")
        if record["session_id"] != request["session_id"] or record["run_id"] != request["run_id"]:
            digests: list[str] = []
        else:
            raw_digests = record["digests"]
            if not isinstance(raw_digests, list) or not raw_digests:
                raise RemoteActionError("remote action replay log is stale")
            digests = []
            seen: set[str] = set()
            for item in raw_digests:
                if type(item) is not str or not HEX64_RE.fullmatch(item) or item in seen:
                    raise RemoteActionError("remote action replay log is stale")
                seen.add(item)
                digests.append(item)
            if digest in seen:
                raise RemoteActionError("replayed request is forbidden")
            if len(digests) >= MAX_REPLAY_DIGESTS:
                raise RemoteActionError("remote action replay log is full")
    else:
        digests = []
    payload = {
        "schema_version": SCHEMA_VERSION,
        "contract": REPLAY_CONTRACT,
        "session_id": request["session_id"],
        "run_id": request["run_id"],
        "digests": [*digests, digest],
    }
    host.write_file(REPLAY_PATH, canonical_bytes(payload), 0o600)


def load_session_state(host: Any) -> dict[str, Any] | None:
    if not host.exists(SESSION_STATE_PATH):
        return None
    return load_json_file(host, SESSION_STATE_PATH, STATE_KEYS, "session state")


def write_session_state(
    host: Any,
    request: Mapping[str, Any],
    *,
    control_id: str,
    protocol: str,
    node: str,
    state: str,
    monotonic_ns: int,
    updated_utc: str,
) -> None:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "contract": STATE_CONTRACT,
        "run_id": request["run_id"],
        "session_id": request["session_id"],
        "correlation_id": request["correlation_id"],
        "fleet_id": request["fleet_id"],
        "control_id": control_id,
        "protocol": protocol,
        "node": node,
        "state": state,
        "monotonic_ns": monotonic_ns,
        "updated_utc": updated_utc,
    }
    host.write_file(SESSION_STATE_PATH, canonical_bytes(payload), 0o600)


def require_session_state(
    host: Any,
    request: Mapping[str, Any],
    *,
    control_id: str,
    protocol: str,
    node: str,
    state: str,
    monotonic_ns: int,
) -> dict[str, Any]:
    record = load_session_state(host)
    if record is None:
        raise RemoteActionError("session state is absent")
    if (
        exact_int(record["schema_version"], "session schema_version") != SCHEMA_VERSION
        or record["contract"] != STATE_CONTRACT
        or record["run_id"] != request["run_id"]
        or record["session_id"] != request["session_id"]
        or record["correlation_id"] != request["correlation_id"]
        or record["fleet_id"] != request["fleet_id"]
        or record["control_id"] != control_id
        or record["protocol"] != protocol
        or record["node"] != node
        or record["state"] != state
    ):
        raise RemoteActionError("session state is stale")
    previous = exact_int(record["monotonic_ns"], "session monotonic", minimum=0)
    parse_utc(record["updated_utc"])
    if monotonic_ns <= previous:
        raise RemoteActionError("session state is stale")
    return record


def apply_nft(host: Any, path: str, ruleset: str, table: str) -> None:
    host.write_file(path, ruleset.encode("ascii"), 0o600)
    loaded = run_allowlisted(host, (BIN_NFT, "-f", path))
    if loaded.exit_code != 0:
        raise RemoteActionError("nft mutation failed")
    listed = run_allowlisted(host, (BIN_NFT, "list", "table", "inet", table))
    if listed.exit_code != 0 or table.encode("ascii") not in listed.stdout:
        raise RemoteActionError("nft table evidence is absent")


def delete_nft(host: Any, table: str) -> None:
    deleted = run_allowlisted(host, (BIN_NFT, "delete", "table", "inet", table))
    if deleted.exit_code != 0:
        raise RemoteActionError("nft restore failed")
    listed = run_allowlisted(host, (BIN_NFT, "list", "table", "inet", table))
    if listed.exit_code == 0:
        raise RemoteActionError("nft table remained after restore")


def attempt(protocol: str, node: str, result: str) -> dict[str, str]:
    return {"protocol": protocol, "node": node, "result": result}


def handle_route_decision(host: Any, request: Mapping[str, Any], binding: Mapping[str, Any]) -> dict[str, Any]:
    nodes = hub_nodes(host)
    selected_node = require_winn3_node(nodes, binding)
    digest, descriptor_node = verify_descriptor(host)
    if descriptor_node != selected_node:
        raise RemoteActionError(
            "signed descriptor node does not match the selected Winn3 node"
        )
    return {
        "served_carrier": "winn3",
        "descriptor_node": descriptor_node,
        "selected_node": selected_node,
        "descriptor_sha256": digest,
        "signature_state": "verified",
        "canary_state": "reachable",
    }


def handle_connect_primary(
    host: Any,
    request: Mapping[str, Any],
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    winn3 = str(binding["data-winn3"]["instance"])
    cover = str(binding["data-cover"]["instance"])
    if winn3 == cover:
        raise RemoteActionError("same-node fallback is forbidden")
    return {"attempts": [attempt("winn3", winn3, "connected")]}


def handle_connect_cover_awg(
    host: Any,
    request: Mapping[str, Any],
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    cover = str(binding["data-cover"]["instance"])
    if cover == str(binding["data-winn3"]["instance"]):
        raise RemoteActionError("same-node fallback is forbidden")
    return {
        "protocol": "awg",
        "node": cover,
        "result": "connected",
    }


def handle_connect_cover_xray(
    host: Any,
    request: Mapping[str, Any],
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    cover = str(binding["data-cover"]["instance"])
    if cover == str(binding["data-winn3"]["instance"]):
        raise RemoteActionError("same-node fallback is forbidden")
    return {"protocol": "xray", "node": cover, "result": "connected"}


def protocol_failed(before: Mapping[str, Any], after: Mapping[str, Any], protocol: str) -> bool:
    raise RemoteActionError("synthetic interface evidence is not accepted")


def require_attempt_interface(
    before: Mapping[str, Any], after: Mapping[str, Any], protocol: str
) -> str:
    raise RemoteActionError("synthetic interface evidence is not accepted")


def handle_probe_awg_block(
    host: Any,
    request: Mapping[str, Any],
    binding: Mapping[str, Any],
    attempts_before: Mapping[str, Any],
    attempts_after_awg: Mapping[str, Any],
    attempts_after: Mapping[str, Any],
    started_mono: int,
    ended_mono: int,
    started: datetime,
    ended: datetime,
) -> dict[str, Any]:
    cover = str(binding["data-cover"]["instance"])
    winn3 = str(binding["data-winn3"]["instance"])
    if cover == winn3:
        raise RemoteActionError("same-node fallback is forbidden")
    observed = require_awg_then_xray_attempts(
        attempts_before,
        attempts_after_awg,
        attempts_after,
        request,
        node=cover,
        started_mono=started_mono,
        ended_mono=ended_mono,
        started=started,
        ended=ended,
    )
    return {
        "control_id": "negative-awg-block",
        "attempts": [
            attempt("awg", cover, "blocked"),
            attempt("xray", cover, "connected"),
        ],
        "attempt_events": observed,
    }


def handle_probe_winn3_block(
    host: Any,
    request: Mapping[str, Any],
    binding: Mapping[str, Any],
    attempts_before: Mapping[str, Any],
    attempts_after_winn3: Mapping[str, Any],
    attempts_after: Mapping[str, Any],
    started_mono: int,
    ended_mono: int,
    started: datetime,
    ended: datetime,
) -> dict[str, Any]:
    cover = str(binding["data-cover"]["instance"])
    winn3 = str(binding["data-winn3"]["instance"])
    if cover == winn3:
        raise RemoteActionError("same-node fallback is forbidden")
    winn3_events = require_single_protocol_attempt(
        attempts_before,
        attempts_after_winn3,
        request,
        node=winn3,
        protocol="winn3",
        result="failed",
        started_mono=started_mono,
        ended_mono=ended_mono,
        started=started,
        ended=ended,
    )
    awg_events = require_single_protocol_attempt(
        attempts_after_winn3,
        attempts_after,
        request,
        node=cover,
        protocol="awg",
        result="connected",
        started_mono=started_mono,
        ended_mono=ended_mono,
        started=started,
        ended=ended,
    )
    if (
        exact_int(winn3_events[-1]["monotonic_ns"], "attempt monotonic", minimum=0)
        >= exact_int(awg_events[0]["monotonic_ns"], "attempt monotonic", minimum=0)
        or parse_utc(winn3_events[-1]["utc"]) >= parse_utc(awg_events[0]["utc"])
    ):
        raise RemoteActionError("Winn3-first fallback attempt order is invalid")
    return {
        "control_id": "negative-winn3-block",
        "attempts": [
            attempt("winn3", winn3, "blocked"),
            attempt("awg", cover, "connected"),
        ],
        "attempt_events": winn3_events + awg_events,
    }


def handle_probe_cover_withdrawn(
    host: Any,
    request: Mapping[str, Any],
    binding: Mapping[str, Any],
    monotonic_ns: int,
    attempts_before: Mapping[str, Any],
    attempts_after: Mapping[str, Any],
    started_mono: int,
    ended_mono: int,
    started: datetime,
    ended: datetime,
) -> dict[str, Any]:
    require_session_state(
        host,
        request,
        control_id="negative-cover-withdrawn",
        protocol="",
        node=str(binding["data-cover"]["instance"]),
        state="withdrawn",
        monotonic_ns=monotonic_ns,
    )
    winn3 = str(binding["data-winn3"]["instance"])
    cover = str(binding["data-cover"]["instance"])
    if cover == winn3:
        raise RemoteActionError("same-node fallback is forbidden")
    attempt_events = require_single_protocol_attempt(
        attempts_before,
        attempts_after,
        request,
        node=winn3,
        protocol="winn3",
        result="failed",
        started_mono=started_mono,
        ended_mono=ended_mono,
        started=started,
        ended=ended,
    )
    return {
        "control_id": "negative-cover-withdrawn",
        "attempts": [attempt("winn3", winn3, "blocked")],
        "attempt_events": attempt_events,
        "refusal_code": "same_node_downgrade_refused",
        "same_node_downgrade_attempts": 0,
    }


def handle_teardown(binding: Mapping[str, Any]) -> dict[str, Any]:
    identity = resource_identity(binding)
    return {
        "expected_resources": identity,
        "observed_resources": identity,
        "unexpected_targets": [],
        "foreign_resource_ids": [],
        "credential_files_read": [],
        "production_resources_touched": [],
    }


def mid_probe(host: Any, request: Mapping[str, Any]) -> None:
    if request["role"] != "control":
        return
    health = host.http_get("/healthz")
    nodes = host.http_get("/nodes")
    if not health or not nodes:
        raise RemoteActionError("local hub probe failed")


def dispatch_action(
    host: Any,
    request: Mapping[str, Any],
    binding: Mapping[str, Any],
    *,
    started: datetime,
    ended: datetime,
    started_mono: int,
    ended_mono: int,
    attempts_before: Mapping[str, Any] | None,
    attempts_after_awg: Mapping[str, Any] | None,
    attempts_after: Mapping[str, Any] | None,
) -> dict[str, Any]:
    action = request["action"]
    if not (started_mono < ended_mono):
        raise RemoteActionError("monotonic action interval is not strictly increasing")
    if ended_mono - started_mono > ACTION_TIMEOUT_SECONDS * 1_000_000_000:
        raise RemoteActionError("monotonic action interval exceeds the bound")
    if action == "route-decision":
        return handle_route_decision(host, request, binding)
    if action == "connect-primary":
        if attempts_before is None or attempts_after is None:
            raise RemoteActionError("timestamped protocol attempts are absent")
        require_single_protocol_attempt(
            attempts_before,
            attempts_after,
            request,
            node=str(binding["data-winn3"]["instance"]),
            protocol="winn3",
            result="connected",
            started_mono=started_mono,
            ended_mono=ended_mono,
            started=started,
            ended=ended,
        )
        return handle_connect_primary(host, request, binding)
    if action == "connect-cover-awg":
        if attempts_before is None or attempts_after is None:
            raise RemoteActionError("timestamped protocol attempts are absent")
        require_single_protocol_attempt(
            attempts_before,
            attempts_after,
            request,
            node=str(binding["data-cover"]["instance"]),
            protocol="awg",
            result="connected",
            started_mono=started_mono,
            ended_mono=ended_mono,
            started=started,
            ended=ended,
        )
        return handle_connect_cover_awg(host, request, binding)
    if action == "connect-cover-xray":
        if attempts_before is None or attempts_after is None:
            raise RemoteActionError("timestamped protocol attempts are absent")
        require_single_protocol_attempt(
            attempts_before,
            attempts_after,
            request,
            node=str(binding["data-cover"]["instance"]),
            protocol="xray",
            result="connected",
            started_mono=started_mono,
            ended_mono=ended_mono,
            started=started,
            ended=ended,
        )
        return handle_connect_cover_xray(host, request, binding)
    if action == "inject-awg-block":
        existing = load_session_state(host)
        if existing is not None and existing.get("state") == "blocked":
            raise RemoteActionError("duplicate JSON or duplicate mutation is forbidden")
        apply_nft(host, NFT_AWG_FILE, NFT_AWG_RULESET, NFT_AWG_TABLE)
        write_session_state(
            host,
            request,
            control_id="negative-awg-block",
            protocol="awg",
            node=str(binding["data-cover"]["instance"]),
            state="blocked",
            monotonic_ns=ended_mono,
            updated_utc=host.utc_now(),
        )
        return {"control_id": "negative-awg-block", "protocol": "awg", "state": "blocked"}
    if action == "probe-awg-block":
        if attempts_before is None or attempts_after_awg is None or attempts_after is None:
            raise RemoteActionError("timestamped protocol attempts are absent")
        return handle_probe_awg_block(
            host,
            request,
            binding,
            attempts_before,
            attempts_after_awg,
            attempts_after,
            started_mono,
            ended_mono,
            started,
            ended,
        )
    if action == "restore-awg":
        require_session_state(
            host,
            request,
            control_id="negative-awg-block",
            protocol="awg",
            node=str(binding["data-cover"]["instance"]),
            state="blocked",
            monotonic_ns=ended_mono,
        )
        delete_nft(host, NFT_AWG_TABLE)
        write_session_state(
            host,
            request,
            control_id="negative-awg-block",
            protocol="awg",
            node=str(binding["data-cover"]["instance"]),
            state="restored",
            monotonic_ns=ended_mono,
            updated_utc=host.utc_now(),
        )
        return {"control_id": "negative-awg-block", "protocol": "awg", "state": "restored"}
    if action == "inject-winn3-block":
        existing = load_session_state(host)
        if existing is not None and existing.get("state") == "blocked":
            raise RemoteActionError("duplicate JSON or duplicate mutation is forbidden")
        apply_nft(host, NFT_WINN3_FILE, NFT_WINN3_RULESET, NFT_WINN3_TABLE)
        write_session_state(
            host,
            request,
            control_id="negative-winn3-block",
            protocol="winn3",
            node=str(binding["data-winn3"]["instance"]),
            state="blocked",
            monotonic_ns=ended_mono,
            updated_utc=host.utc_now(),
        )
        return {"control_id": "negative-winn3-block", "protocol": "winn3", "state": "blocked"}
    if action == "probe-winn3-block":
        if attempts_before is None or attempts_after_awg is None or attempts_after is None:
            raise RemoteActionError("timestamped protocol attempts are absent")
        return handle_probe_winn3_block(
            host,
            request,
            binding,
            attempts_before,
            attempts_after_awg,
            attempts_after,
            started_mono,
            ended_mono,
            started,
            ended,
        )
    if action == "withdraw-cover":
        existing = load_session_state(host)
        if existing is not None and existing.get("state") == "withdrawn":
            raise RemoteActionError("duplicate JSON or duplicate mutation is forbidden")
        apply_nft(host, NFT_COVER_FILE, NFT_COVER_RULESET, NFT_COVER_TABLE)
        write_session_state(
            host,
            request,
            control_id="negative-cover-withdrawn",
            protocol="",
            node=str(binding["data-cover"]["instance"]),
            state="withdrawn",
            monotonic_ns=ended_mono,
            updated_utc=host.utc_now(),
        )
        return {
            "control_id": "negative-cover-withdrawn",
            "node": str(binding["data-cover"]["instance"]),
            "state": "withdrawn",
        }
    if action == "probe-cover-withdrawn":
        if attempts_before is None or attempts_after is None:
            raise RemoteActionError("timestamped protocol attempts are absent")
        return handle_probe_cover_withdrawn(
            host,
            request,
            binding,
            ended_mono,
            attempts_before,
            attempts_after,
            started_mono,
            ended_mono,
            started,
            ended,
        )
    if action == "restore-cover":
        require_session_state(
            host,
            request,
            control_id="negative-cover-withdrawn",
            protocol="",
            node=str(binding["data-cover"]["instance"]),
            state="withdrawn",
            monotonic_ns=ended_mono,
        )
        delete_nft(host, NFT_COVER_TABLE)
        write_session_state(
            host,
            request,
            control_id="negative-cover-withdrawn",
            protocol="",
            node=str(binding["data-cover"]["instance"]),
            state="restored",
            monotonic_ns=ended_mono,
            updated_utc=host.utc_now(),
        )
        return {
            "control_id": "negative-cover-withdrawn",
            "node": str(binding["data-cover"]["instance"]),
            "state": "restored",
        }
    if action == "restore-winn3":
        require_session_state(
            host,
            request,
            control_id="negative-winn3-block",
            protocol="winn3",
            node=str(binding["data-winn3"]["instance"]),
            state="blocked",
            monotonic_ns=ended_mono,
        )
        delete_nft(host, NFT_WINN3_TABLE)
        write_session_state(
            host,
            request,
            control_id="negative-winn3-block",
            protocol="winn3",
            node=str(binding["data-winn3"]["instance"]),
            state="restored",
            monotonic_ns=ended_mono,
            updated_utc=host.utc_now(),
        )
        return {"control_id": "negative-winn3-block", "protocol": "winn3", "state": "restored"}
    if action == "teardown-check":
        return handle_teardown(binding)
    raise RemoteActionError("unsupported action")


def needs_winn3_status(request: Mapping[str, Any]) -> bool:
    return request["role"] == "data-winn3" and request["phase"] in OBSERVE_PHASES


def needs_cover_protocol(request: Mapping[str, Any]) -> bool:
    return request["role"] == "data-cover" and request["phase"] in OBSERVE_PHASES


def needs_fallback_journals(request: Mapping[str, Any]) -> bool:
    return (
        request["action"] == "probe-awg-block"
        and request["role"] == "control"
        and request["phase"] == PHASE_EXERCISE
    )


def effect_digest(envelope: Mapping[str, Any]) -> str:
    core = {
        "action": envelope["action"],
        "boot_id": envelope["boot_id"],
        "challenge": envelope["challenge"],
        "contract": envelope["contract"],
        "correlation_id": envelope["correlation_id"],
        "data": envelope["data"],
        "effect_kind": envelope["effect_kind"],
        "ended_utc": envelope["ended_utc"],
        "evidence": envelope["evidence"],
        "helper_hashes": envelope["helper_hashes"],
        "instance": envelope["instance"],
        "instance_id": envelope["instance_id"],
        "operation": envelope["operation"],
        "phase": envelope["phase"],
        "project": envelope["project"],
        "request_sha256": envelope["request_sha256"],
        "role": envelope["role"],
        "run_id": envelope["run_id"],
        "schema_version": envelope["schema_version"],
        "session_id": envelope["session_id"],
        "started_utc": envelope["started_utc"],
        "state_sha256": envelope["state_sha256"],
        "transaction": envelope["transaction"],
    }
    if "fixture_only" in envelope:
        core["fixture_only"] = envelope["fixture_only"]
    return sha256_bytes(canonical_dumps(core).encode("ascii"))


def forbid_pass_tokens(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).lower() in FORBIDDEN_OUTPUT_KEYS:
                raise RemoteActionError("output contains a forbidden pass token")
            forbid_pass_tokens(item)
    elif isinstance(value, list):
        for item in value:
            forbid_pass_tokens(item)


def execute(request: Mapping[str, Any], host: Any) -> dict[str, Any]:
    test_only = getattr(host, "TEST_ONLY", False) is True
    request = validate_request(request)
    role = load_role(host)
    if role != request["role"]:
        raise RemoteActionError("unexpected role")
    marker = load_marker(host, request)
    binding = load_fleet_binding(host, request)
    if marker["role"] != role:
        raise RemoteActionError("unexpected role")
    acquire = getattr(host, "acquire_action_lock", None)
    release = getattr(host, "release_action_lock", None)
    if acquire is None or release is None:
        raise RemoteActionError("action lock is absent")
    locked = False
    try:
        acquire()
        locked = True
        consume_replay(host, request)
        return _execute_bound(request, host, role, binding, test_only)
    finally:
        if locked:
            release()


def _execute_bound(
    request: Mapping[str, Any],
    host: Any,
    role: str,
    binding: Mapping[str, Any],
    test_only: bool,
) -> dict[str, Any]:
    services = collect_service_evidence(host, role)
    process_identity = collect_process_identity(host, services, role)
    instance_id = load_instance_id(host)
    boot_id = load_boot_id(host)
    helper_hashes = collect_helper_hashes(host, request)
    request_sha256 = request["request_sha256"]
    if request_sha256 != request_digest(request):
        raise RemoteActionError("request hash mismatch")
    started_mono = host.monotonic_ns()
    started_utc = host.utc_now()
    started = parse_utc(started_utc)
    snapshot = collect_network_snapshot(host)
    winn3_status = None
    interface_counters = None
    awg_peers = None
    xray_stats = None
    if needs_winn3_status(request):
        winn3_status = load_winn3_status(host, role)
        require_winn3_process_binding(winn3_status, services, process_identity)
        interface_counters = real_winn3_interface_counters(snapshot)
    elif needs_cover_protocol(request):
        awg_peers = collect_awg_peers(host)
        xray_stats = collect_xray_stats(host)
    attempts_before = None
    attempts_after_awg = None
    attempts_after = None
    attempt_acknowledgements: list[dict[str, Any]] = []
    broker_identity = None
    require_broker = requires_attempt_broker_identity(request)
    if require_broker:
        holder = getattr(host, "hold_attempt_broker_identity", None)
        if holder is None:
            raise RemoteActionError("attempt-broker identity binding is absent")
        broker_identity = holder()
        if broker_identity is None or (
            not test_only and type(broker_identity) is not _HeldAttemptBrokerIdentity
        ):
            raise RemoteActionError("attempt-broker identity binding is invalid")
    try:
        if request["phase"] == PHASE_EXERCISE and request["role"] == "control":
            mid_probe(host, request)
            if request["action"] == "connect-primary":
                attempts_before = load_attempt_journal(host, required=False)
                attempt_acknowledgements.append(
                    host.trigger_protocol_attempt(
                        request, "winn3", str(binding["data-winn3"]["instance"])
                    )
                )
                attempts_after = load_attempt_journal(host, required=True)
            if request["action"] in {"connect-cover-awg", "connect-cover-xray"}:
                protocol = "awg" if request["action"] == "connect-cover-awg" else "xray"
                cover = str(binding["data-cover"]["instance"])
                attempts_before = load_attempt_journal(host, required=False)
                attempt_acknowledgements.append(
                    host.trigger_protocol_attempt(request, protocol, cover)
                )
                attempts_after = load_attempt_journal(host, required=True)
            if request["action"] == "probe-awg-block":
                cover = str(binding["data-cover"]["instance"])
                attempts_before = load_attempt_journal(host, required=False)
                attempt_acknowledgements.append(
                    host.trigger_protocol_attempt(request, "awg", cover)
                )
                attempts_after_awg = load_attempt_journal(host, required=True)
                collect_network_snapshot(host)
                attempt_acknowledgements.append(
                    host.trigger_protocol_attempt(request, "xray", cover)
                )
                attempts_after = load_attempt_journal(host, required=True)
            if request["action"] == "probe-winn3-block":
                attempts_before = load_attempt_journal(host, required=False)
                attempt_acknowledgements.append(
                    host.trigger_protocol_attempt(
                        request, "winn3", str(binding["data-winn3"]["instance"])
                    )
                )
                attempts_after_awg = load_attempt_journal(host, required=True)
                attempt_acknowledgements.append(
                    host.trigger_protocol_attempt(
                        request, "awg", str(binding["data-cover"]["instance"])
                    )
                )
                attempts_after = load_attempt_journal(host, required=True)
            if request["action"] == "probe-cover-withdrawn":
                attempts_before = load_attempt_journal(host, required=False)
                attempt_acknowledgements.append(
                    host.trigger_protocol_attempt(
                        request, "winn3", str(binding["data-winn3"]["instance"])
                    )
                )
                attempts_after = load_attempt_journal(host, required=True)
        if require_broker:
            if not attempt_acknowledgements:
                raise RemoteActionError("protocol attempt acknowledgement is absent")
            finisher = getattr(broker_identity, "finish", None)
            if finisher is None:
                raise RemoteActionError("attempt-broker identity binding is invalid")
            broker_digest = finisher()
            if (
                type(broker_digest) is not str
                or not HEX64_RE.fullmatch(broker_digest)
                or broker_digest == "0" * 64
            ):
                raise RemoteActionError("helper hash evidence is missing or malformed")
            helper_hashes["attempt_broker"] = broker_digest
        elif attempt_acknowledgements:
            raise RemoteActionError("unexpected protocol attempt acknowledgement")
    finally:
        if broker_identity is not None:
            closer = getattr(broker_identity, "close", None)
            if closer is None:
                raise RemoteActionError("attempt-broker identity binding is invalid")
            closer()
    expected_helper_hashes = (
        {"attempt_broker", "remote"} if require_broker else {"remote"}
    )
    if set(helper_hashes) != expected_helper_hashes:
        raise RemoteActionError("helper hash evidence is missing or malformed")
    ended_utc = host.utc_now()
    ended_mono = host.monotonic_ns()
    ended = parse_utc(ended_utc)
    if ended <= started or (ended - started).total_seconds() > ACTION_TIMEOUT_SECONDS:
        raise RemoteActionError("action time window is invalid")
    if not (started_mono < ended_mono):
        raise RemoteActionError("monotonic action interval is not strictly increasing")
    if ended_mono - started_mono > ACTION_TIMEOUT_SECONDS * 1_000_000_000:
        raise RemoteActionError("monotonic action interval exceeds the bound")
    data = None
    if request["phase"] in {PHASE_EXERCISE, PHASE_MUTATE}:
        data = dispatch_action(
            host,
            request,
            binding,
            started=started,
            ended=ended,
            started_mono=started_mono,
            ended_mono=ended_mono,
            attempts_before=attempts_before,
            attempts_after_awg=attempts_after_awg,
            attempts_after=attempts_after,
        )
        expected_data_keys = REMOTE_HELPER_DATA_KEYS.get(request["action"])
        if expected_data_keys is not None:
            data = exact_keys(
                data,
                expected_data_keys,
                f"{request['action']} remote helper data",
            )
        forbid_pass_tokens(data)
    if request["phase"] in OBSERVE_PHASES and data is not None:
        raise RemoteActionError("observe phase must not carry action data")
    if (
        request["phase"] not in OBSERVE_PHASES
        and request["action"] in ATTEMPT_ACK_ACTIONS
        and request["role"] != "control"
        and attempt_acknowledgements
    ):
        raise RemoteActionError("unexpected protocol attempt acknowledgement")
    evidence = exact_keys(
        {
            "attempt_acknowledgements": attempt_acknowledgements,
            "attempt_journal_after": attempts_after,
            "attempt_journal_after_awg": attempts_after_awg,
            "attempt_journal_before": attempts_before,
            "awg_peers": awg_peers,
            "boot_id": boot_id,
            "challenge": request["challenge"],
            "client_build_identity": request["client_build_identity"],
            "ended_monotonic_ns": ended_mono,
            "instance": request["instance"],
            "instance_id": instance_id,
            "interface_counters": interface_counters,
            "process_identity": process_identity,
            "request_sha256": request_sha256,
            "role": role,
            "services": services,
            "started_monotonic_ns": started_mono,
            "winn3_status": winn3_status,
            "xray_stats": xray_stats,
        },
        EVIDENCE_KEYS,
        "remote action evidence",
    )
    forbid_pass_tokens(evidence)
    state_sha256 = sha256_bytes(canonical_bytes(evidence))
    effect_kind = "remote_mutation" if request["phase"] == PHASE_MUTATE else "observation"
    if request["phase"] in OBSERVE_PHASES:
        transaction_payload = {
            "boot_id": boot_id,
            "ended_monotonic_ns": ended_mono,
            "instance_id": instance_id,
            "phase": request["phase"],
            "role": role,
        }
    else:
        if not isinstance(data, dict):
            raise RemoteActionError("exact transaction response is invalid")
        transaction_payload = dict(data)
    envelope = {
        "schema_version": OBSERVATION_SCHEMA_VERSION,
        "contract": TEST_RESPONSE_CONTRACT if test_only else OBSERVATION_CONTRACT,
        "action": request["action"],
        "phase": request["phase"],
        "project": request["project"],
        "instance": request["instance"],
        "instance_id": instance_id,
        "boot_id": boot_id,
        "role": request["role"],
        "run_id": request["run_id"],
        "session_id": request["session_id"],
        "correlation_id": request["correlation_id"],
        "operation": ACTION_OPERATIONS[request["action"]],
        "effect_kind": effect_kind,
        "challenge": request["challenge"],
        "request_sha256": request_sha256,
        "helper_hashes": helper_hashes,
        "started_utc": started_utc,
        "ended_utc": ended_utc,
        "state_sha256": state_sha256,
        "evidence": evidence,
        "transaction": transaction_record(
            request["challenge"], effect_kind, transaction_protocol(request), transaction_payload
        ),
        "data": data,
    }
    if test_only:
        envelope["fixture_only"] = True
    envelope["effect_sha256"] = effect_digest(envelope)
    forbid_pass_tokens(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) == 0 or len(encoded) > MAX_OUTPUT:
        raise RemoteActionError("response size is invalid")
    return envelope


def run_argv(argv: Sequence[str], host: Any | None = None) -> tuple[int, bytes, bytes]:
    active = host if host is not None else ProductionHost()
    if getattr(active, "TEST_ONLY", False) is True:
        return REFUSAL_EXIT, b"", b"test host cannot emit production output\n"
    try:
        request = parse_argv(argv)
        envelope = execute(request, active)
        return 0, canonical_bytes(envelope), b""
    except RemoteActionError as suc:
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
