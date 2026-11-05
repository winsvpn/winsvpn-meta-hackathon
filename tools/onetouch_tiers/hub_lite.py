#!/usr/bin/env python3
"""hub-lite: the real hub app and the real descriptor signer, run locally for tests.

Design v17 5.1 "Setup" and the Singapore runbook prerequisite 2: "the real hub
app from the CP installer run locally against a scratch database, enough for
complete-fresh, the signer request path and the go-live sweep in tests".

What runs as the installer ships it:
  * main.py, extracted from the control-plane installer heredoc, digest pinned,
    loaded with the REAL fastapi, pydantic and dateutil. Every HTTP operation
    goes through starlette's in-process TestClient (real request parsing, real
    routes, no socket). FastAPI startup and lifespan events are never run.
  * wins_descriptor_signer.py, extracted from its heredoc, digest pinned, run
    as its own process. Its own serve() takes the listening socket as fd 3
    under LISTEN_PID/LISTEN_FDS (systemd socket activation, emulated by
    hub-lite), and its own operator CLIs (ledger-bootstrap, reconcile,
    confirm) build and install the ledger.
  * The hub's request builder (winn3_build_signer_request) and client
    (winn3_signer_client) send real bytes over that AF_UNIX socket.
  * wins_node_dataplane_probe.py (its DB writers only: apply_verdicts and
    apply_carry_verdict) records recorded probe verdicts, and main.py's own
    ingest_winn3_canary_result records recorded canary results.

What is replaced, and only at named boundaries: BOUNDARIES below. What could
not be made real on this Mac: NOT_REAL below. The three literal-path source
replacements load_hub uses are the only edits to main.py's text:
MAIN_SOURCE_REPLACEMENTS (each applied exactly once, asserted).

State lives in --state DIR (0700): keys, the scratch SQLite database, the
signer's config and ledger, per-node test material. Separate CLI invocations
continue the same hub; the module is reloaded per invocation. No output ever
carries the admin token, a node token, an admission secret or key material.

Nothing here contacts a host: a process-wide guard refuses every connect that
is not AF_UNIX or loopback and every name lookup that is not a literal or
localhost, and the node transport (ssh) is answered by NodeEmulator from
recorded state.

FINDINGS lists shipped-code behaviour hub-lite measured on 705bedd (HL-F1
blocked every pre-sign canary on the shipped default). HL-F1 to HL-F3 are fixed
in this tree by fix_hl (FINAL4 step 3_HL); DEVIATIONS lists the opt-in setting
(init --endpoint-pin-workaround, HL-D1) that routed around HL-F1 and is no
longer needed.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import importlib
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SERVER = REPO / "server"
CP_INSTALLER = SERVER / "wins_control_plane_setup_ONETOUCH.sh"
DP_INSTALLER = SERVER / "wins_data_plane_setup_ONETOUCH.sh"

MAIN_HEADER = "  cat > \"${APP_DIR}/main.py\" <<'PYEOF'"
SIGNER_HEADER = "cat > /usr/local/lib/wins_descriptor_signer.py <<'DESCSIGNEREOF'"
PROBE_HEADER = "cat > /usr/local/lib/wins_node_dataplane_probe.py <<'DPPROBEEOF'"
# The digests of the shipped heredocs at FLEET1 Turn 2 (FINAL4 Turn 4, f64d2df,
# plus the fleet reset fixes of 2026-10-09: D7 wallet-RPC Access headers with a
# dedicated token, the TP-P9 BTCPay checkout chains in main.py and in GET
# /nodes, and the GRUB guard alert; the signer is unchanged), plus the
# tunnel-speed round's "wan_qdisc_parameters" drift reason (2026-10-09),
# combined by INTEG6, plus the Double VPN ciphertext relay hub changes of
# 0def2313 (main.py only; the signer is unchanged), plus the 2026-10-31
# descriptor-expiry alert fix (6-day warning, closed nodes skipped; main.py
# only). A different installer is
# refused unless the caller passes the digests it expects (pinned=False).
PINNED_MAIN_SHA256 = "076adc8d1a00be7d088dc1cde67d43876f57d524cb02762bf0fa3170e1baeadf"
PINNED_SIGNER_SHA256 = "fd2c6aa234b032742452da960430b0e0c5b6b84bf9cc83e4dbb33129344b6afa"

# Harness-only redirection of root-owned literal paths main.py writes at
# import (the same three replacements load_hub in
# server/test_account_deletion_hub.py makes). (old, placeholder, count).
MAIN_SOURCE_REPLACEMENTS = (
    ('"/var/log/winsvpn"', "LOG_DIR", 1),
    ('"/var/log/winsvpn/master.log"', "LOG_FILE", 1),
    ('"/var/lib/wins-security-alerts"', "STATE_DIR", 1),
)

# Module constants rebound after exec to paths under the state directory. A
# rebinding changes where a file lives, never what the code does with it.
MAIN_PATH_REBINDS = (
    ("WINN3_SIGNER_SOCKET", "the H2 signer client's socket path (/run/wins-descriptor-signer/sock)"),
    ("WINN3_SIGNER_SOCKET_PATH", "the H4 status helper's socket path (same socket)"),
    ("WINN3_CANARY_KEY_ROOT", "the pre-sign canary key root (/root/vpn_auth/winn3-canary)"),
    ("WINN3_CANARY_REQUEST_DIR", "H3's request spool (/var/lib/wins-canary-requests)"),
    ("WINN3_CANARY_RESULT_DIR", "H3's result spool (/var/lib/wins-canary-results)"),
    ("HUB_MANAGEMENT_SSH_CONTROL_DIR", "ssh ControlMaster directory (/var/lib/wins-hub-ssh/cm)"),
)

BOUNDARIES = (
    {"name": "node transport (ssh)", "replaced": "main.subprocess.run for argv[0] == 'ssh' (node_ssh_command output)",
     "main_functions": ["winn3_pull_identity", "sync_winn3_registry_to_node", "observe_winn3_node",
                        "verify_node_management_access", "sync_peer_to_node", "remove_peer_from_node",
                        "hub_offnode_check_run"],
     "why": "no host is contacted. NodeEmulator answers each fixed remote command class from recorded "
            "state: the pulled identity (a JSON file or the test builder; in Tier B captured from the node), "
            "the registry the hub last published (sequence-checked like the node's own script), the AWG peers "
            "the hub pushed, and the off-node check report (healthy, failing or a recorded file). Every "
            "command is still built by main.py's node_ssh_command; an unknown command class exits 255."},
    {"name": "v3 canary probe binary", "replaced": "main.winn3_run_canary_probe",
     "main_functions": ["winn3_pre_sign_canary", "winn3_served_profile_canary"],
     "why": "winn3-probe would handshake to the node over the network. The recorded verdict per stage "
            "(pre_sign, served) becomes its exit status and stdout; binding, profile render and proof checks "
            "stay real."},
    {"name": "post-flip v3 canary and H3 consumer", "replaced": "nothing: recorded results enter through "
     "main.ingest_winn3_canary_result", "main_functions": ["ingest_winn3_canary_result"],
     "why": "the canary unit runs on the hub against the node; its result is supplied by the caller and "
            "bound to the row by main.winn3_result_binding."},
    {"name": "data-plane prober and AWG carrying canary (H5)", "replaced": "nothing: recorded verdicts enter "
     "through the real probe script's apply_verdicts and apply_carry_verdict",
     "main_functions": ["(wins_node_dataplane_probe.py) apply_verdicts", "apply_carry_verdict"],
     "why": "the probes send datagrams to the node; the verdicts are supplied by the caller."},
    {"name": "Cloudflare edge", "replaced": "main.ensure_ssh_management_tunnel",
     "main_functions": ["ensure_ssh_management_tunnel"],
     "why": "creates a Cloudflare tunnel, DNS record and Access app over the API. hub-lite returns the "
            "hostname main.management_tunnel_hostname derives, so POST /admin/nodes/bootstrap-management-tunnel "
            "pins the node host key exactly as shipped. Every other Cloudflare call is refused by the network guard."},
    {"name": "observers (not replacements)", "replaced": "main.winn3_signer_client, main.winn3_store_descriptor, "
     "main.winn3_pre_sign_canary, main.winn3_served_profile_canary are wrapped",
     "main_functions": ["winn3_signer_client", "winn3_store_descriptor", "winn3_pre_sign_canary",
                        "winn3_served_profile_canary"],
     "why": "each wrapper calls the shipped function unchanged and records what crossed it (verb, "
            "expected_prior_seq, issued seq and kid; the carrier in the database at store and at the "
            "served-profile canary) as test evidence."},
    {"name": "SMTP and alerts", "replaced": "main.security_alert",
     "main_functions": ["security_alert"],
     "why": "alerts are emailed; hub-lite records (priority, event, details) in alerts.jsonl instead."},
    {"name": "in-process provisioning scheduler", "replaced": "main._winn3_provision_start_thread",
     "main_functions": ["trigger_winn3_auto_provision", "winn3_schedule_auto_provision",
                        "trigger_winn3_golive_after_release"],
     "why": "a trigger would start winn3_auto_provision on a background thread at once; hub-lite records "
            "the trigger and the caller runs the real job explicitly (provision), so tests are deterministic."},
    {"name": "clock", "replaced": "main.now_utc, main.security_now_utc, main.time (time() only); the probe's "
     "utcnow_iso and datetime; the signer's CLOCK",
     "main_functions": ["now_utc", "utcnow"],
     "why": "identical to the real clock while the offset is 0. `advance` moves all three together (hub, "
            "probe writers, signer), which the renewal window (7 days) needs."},
    {"name": "signer peer credential check", "replaced": "signer.peer_is_hub",
     "main_functions": [],
     "why": "SO_PEERPIDFD, SO_PEERCRED and the wins-hub.service cgroup do not exist on macOS. hub-lite admits "
            "only a peer with this user's uid whose pid is the hub-lite process that started the signer "
            "(LOCAL_PEERPID / LOCAL_PEERCRED on macOS, SO_PEERCRED on Linux)."},
    {"name": "signer operator root and service user",
     "replaced": "signer.cli_is_root, signer.signer_user_ids, signer.cli_chown",
     "main_functions": [],
     "why": "the operator CLIs refuse a non-root user and chown to wins-desc-signer; hub-lite runs them as "
            "the invoking user, which also owns the signer's files (cli_chown hands each file to the invoking "
            "user instead of root or wins-desc-signer)."},
)

NOT_REAL = (
    "The signer does not run under its own OS user, root or systemd: it is a child process of hub-lite with "
    "this user's uid. Socket activation is emulated (hub-lite binds, listens and passes fd 3 with "
    "LISTEN_PID/LISTEN_FDS), so the socket unit's 0660 wins-desc-signer:root ownership, PrivateNetwork, "
    "InaccessiblePaths and the hub unit sandbox are not exercised (Tier A, H0 and H1 own them).",
    "The peer credential check (uid 0, wins-hub.service cgroup, pidfd) is replaced by a same-uid, hub-pid check.",
    "The signer's config (signer.json, ticket-epoch, the active slot key) is written by hub-lite in the "
    "installer's format; the installer's bash key-injection and active-slot pin functions are not run "
    "(H1's suite runs them).",
    "No probe touches a node: identity pull, registry publication, AWG peer pushes, the off-node check, the "
    "pre-sign and served-profile canaries, the post-flip canary, the data-plane prober and the AWG carrying "
    "canary all take recorded results (BOUNDARIES).",
    "Cloudflare tunnel creation, DNS and Access are not run; the management hostname is main.py's own.",
    "FastAPI startup events (background loops: sweeps, canary ingest, authority reconcile) never run; the "
    "operations call the same functions once, explicitly.",
    "serve uses uvicorn with lifespan off, in front of the same app; nginx and Cloudflare are not in front. "
    "On SIGTERM uvicorn exits without hub-lite's cleanup; the signer child notices its parent is gone and "
    "exits within 0.5 s.",
    "A test node's identity (gateway static, Ed25519 and ML-DSA-65 keys, credential record digest) is random "
    "bytes of the right sizes, signed by a real ssh-keygen host key; the hub checks sizes and the host-key "
    "signature, never the keys' algebra. Tier B passes the node's real files with node --pulled-identity.",
    "The signer's digest and digest-mail units (daily digest, emailed) are not run; reconcile reads "
    "--digest at an absent file, the operator's known case.",
)

# Measured on 705bedd, not assumed. FINDINGS are shipped-code behaviour
# hub-lite surfaced; DEVIATIONS are the opt-in harness settings that route
# around one, each named with the finding it answers. All three findings are
# fixed in this tree by fix_hl (DELTA.diff 83666391..., FINAL4 step 3_HL): each
# entry's `status` names the fix and the tests, and `reproduced_by` names the
# hub-lite test that now shows the fixed behaviour.
FINDINGS = (
    {"id": "HL-F1", "where": "main.py winn3_prepare_canary (CP main.py line 15908)",
     "what": "the pre-sign canary publishes the registry with sync_winn3_registry_to_node(conn, "
             "extract_node_host(node['endpoint']), ...), i.e. to the node's public endpoint IP, not its "
             "management ssh_host. node_ssh_command refuses that host: no management pin exists for an IP "
             "(install_management_known_hosts accepts only names under the management zone) and, with the "
             "shipped default HIDE_CONTROL_ORIGIN=1, any IP literal. The publication fails and "
             "winn3_auto_provision holds every node with canary-registry-publication-failed before it signs. "
             "Every other registry publication uses ssh_host or the endpoint (resync, admission).",
     "status": "fixed in this tree by fix_hl: winn3_prepare_canary publishes over the pinned management host and "
               "falls back like the identity pull (server/test_hub_h3_canary.py test_hl_f1_*)",
     "reproduced_by": "server/test_winn3_onetouch_hublite.py::test_shipped_default_reaches_signing_and_go_live"},
    {"id": "HL-F2", "where": "main.py winn3_recovery_state with winn3_recovery_node_set and winn3_node_hosts",
     "what": "a recovery node that is not winn/3 (a fresh node before its flip, or one rolled back, whose v3 "
             "registry the hub has published) is in the recovery set through its ledger publications, but "
             "winn3_node_hosts maps winn/3 rows only. Its needed journal read is (slug, '') while the read-back "
             "records the real gateway, so it never counts: budget trust, and with it node_auto_reopen_arm and "
             "every automatic go-live or reopen, waits the full WINN3_DEPARTURE_LEDGER_SECONDS (3600 s) after "
             "each hub start whenever such a node exists.",
     "status": "fixed in this tree by fix_hl: a released node that is not yet winn/3 is read back at its "
               "registered host and the budget is trusted (server/test_hub_h7_fresh_install_golive.py test_hl_f2_*)",
     "reproduced_by": "server/test_winn3_onetouch_hublite.py::test_a_recovery_node_that_is_not_winn3_no_longer_delays_the_arm_hl_f2"},
    {"id": "HL-F3", "where": "main.py node_auto_reopen_failures ('no healthy-proof streak that began after the "
                             "closure') with the prober's apply_verdicts",
     "what": "the prober probes every node row, and only a non-green run resets data_plane_green_since; neither "
             "complete-fresh nor a re-bootstrap does. A node whose healthy streak began before its fresh_install "
             "closure (a green prober run between the final registration and complete-fresh, or a same-slug "
             "reset the prober never saw down) stays held with that reason for as long as it stays healthy, "
             "until the 6 h window expires to an operator closure. One unreachable run releases it.",
     "status": "fixed in this tree by fix_hl: complete-fresh, a re-bootstrap and the installer_rerun closure end a "
               "streak that began before the closure (server/test_hub_h7_fresh_install_golive.py test_hl_f3_*, "
               "server/test_hub_offnode_gate_h6.py test_hl_f3_*); FINAL4 step 7 (F4-HL) does the same for the "
               "stale sweep's closures and a prober run that closes (server/test_hub_offnode_gate_h6.py "
               "ClosureStreakTests)",
     "reproduced_by": "server/test_winn3_onetouch_hublite.py::test_a_streak_that_began_before_the_closure_no_longer_holds_the_go_live_hl_f3"},
)
DEVIATIONS = (
    {"id": "HL-D1", "answers": "HL-F1", "flag": "init --endpoint-pin-workaround",
     "what": "HIDE_CONTROL_ORIGIN=0 for this hub, and the node host key is also pinned under the endpoint IP "
             "in managed_known_hosts (written directly: no route accepts an IP). With it the pre-sign "
             "canary's publication reaches the node transport and the rest of the 3.1 order runs as shipped. "
             "Off by default. No longer needed in this tree: with HL-F1 fixed by fix_hl the shipped default "
             "reaches signing and go-live (the hub-lite suite runs on the default; S7's hub-backed Tier B step "
             "tests still pass the flag)."},
)

NETWORK_TOOLS = frozenset(("scp", "sftp", "curl", "wget", "cloudflared", "nc", "ncat", "socat", "dig",
                           "nslookup", "host", "ping", "winn3-probe", "awg", "wg", "ssh-keyscan"))
GOOD_OBFUSCATION = {"Jc": 2, "Jmin": 10, "Jmax": 30, "S1": 16, "S2": 80, "S3": 16, "S4": 0,
                    "H1": 11, "H2": 22, "H3": 33, "H4": 44}
DEFAULT_ENDPOINT_IP = "203.0.113.10"
SLOTS = ("g1", "g2", "g3")
DAY = 86400


class HubLiteError(RuntimeError):
    pass


# ----------------------------------------------------------- shared helpers --

_H1 = None


def _h1():
    """server/test_hub_h1_descriptor_signer.py: its heredoc extractor and its
    openssl helpers (genkey, openssl_sign, run) are reused, not copied."""
    global _H1
    if _H1 is None:
        if str(SERVER) not in sys.path:
            sys.path.insert(0, str(SERVER))
        _H1 = importlib.import_module("test_hub_h1_descriptor_signer")
    return _H1


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def extract(installer_text: str) -> dict:
    """The three heredocs hub-lite runs, extracted by H1's own extractor."""
    heredoc = _h1().heredoc
    return {"main": heredoc(installer_text, MAIN_HEADER),
            "signer": heredoc(installer_text, SIGNER_HEADER),
            "probe": heredoc(installer_text, PROBE_HEADER)}


def digests(installer_text: str) -> dict:
    parts = extract(installer_text)
    return {"main_sha256": sha256_text(parts["main"]), "signer_sha256": sha256_text(parts["signer"]),
            "main_lines": len(parts["main"].splitlines()), "signer_lines": len(parts["signer"].splitlines())}


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def write_private(path: Path, data, mode: int = 0o600) -> None:
    path = Path(path)
    blob = data if isinstance(data, bytes) else str(data).encode("utf-8")
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(blob)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def private_dir(path: Path) -> Path:
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def refuse_state_path(state: Path) -> Path:
    resolved = Path(os.path.realpath(os.path.expanduser(str(state))))
    home = Path(os.path.realpath(os.path.expanduser("~")))
    for forbidden in (home / ".xprize", home / ".ssh"):
        if resolved == forbidden or forbidden in resolved.parents:
            raise HubLiteError(f"refusing a state directory under {forbidden}")
    if resolved == home or resolved == Path("/"):
        raise HubLiteError("refusing the home or root directory as a state directory")
    return resolved


# ------------------------------------------------------------ network guard --

_GUARD_INSTALLED = [False]


def _loopback_address(family, address) -> bool:
    if family == socket.AF_UNIX:
        return True
    try:
        import ipaddress
        return ipaddress.ip_address(str(address[0]).split("%", 1)[0]).is_loopback
    except (ValueError, TypeError, IndexError):
        return False


def install_network_guard() -> None:
    """Refuse every connect that is not AF_UNIX or loopback, and every name
    lookup that is not a literal or localhost, process-wide. Idempotent.
    Loopback stays open so other suites sharing a pytest process keep their
    local fixtures; hub-lite itself never opens a TCP connection."""
    if _GUARD_INSTALLED[0]:
        return
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_getaddrinfo = socket.getaddrinfo

    def connect(self, address):
        if not _loopback_address(self.family, address):
            raise ConnectionRefusedError("hub-lite network guard: no host is contacted")
        return original_connect(self, address)

    def connect_ex(self, address):
        if not _loopback_address(self.family, address):
            raise ConnectionRefusedError("hub-lite network guard: no host is contacted")
        return original_connect_ex(self, address)

    def getaddrinfo(host, *args, **kwargs):
        name = host.decode() if isinstance(host, bytes) else str(host or "")
        try:
            import ipaddress
            ipaddress.ip_address(name.strip("[]"))
        except ValueError:
            if name not in ("localhost", ""):
                raise socket.gaierror(socket.EAI_NONAME, "hub-lite network guard: no name lookup")
        return original_getaddrinfo(host, *args, **kwargs)

    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex
    socket.getaddrinfo = getaddrinfo
    _GUARD_INSTALLED[0] = True


@contextlib.contextmanager
def _real_third_party():
    """main.py must load against the real fastapi, pydantic and dateutil. The
    stub-based suites install module stubs in sys.modules; drop them here (the
    next load_hub installs them again)."""
    for name in ("fastapi", "fastapi.responses", "pydantic", "dateutil", "dateutil.relativedelta"):
        module = sys.modules.get(name)
        if module is not None and getattr(module, "__file__", None) is None:
            del sys.modules[name]
    for name in ("fastapi", "fastapi.responses", "pydantic", "dateutil.relativedelta"):
        importlib.import_module(name)
    yield


# --------------------------------------------------------------- the clock --

class _Clock:
    """One offset shared by main.py, the probe writers and the signer."""

    def __init__(self, path: Path):
        self.path = path

    def offset(self) -> float:
        try:
            return float(self.path.read_text().strip() or 0)
        except (OSError, ValueError):
            return 0.0

    def time(self) -> float:
        return time.time() + self.offset()

    def now_utc(self) -> datetime:
        return datetime.now(timezone.utc) + timedelta(seconds=self.offset())


class _TimeShim(types.ModuleType):
    def __init__(self, clock: _Clock):
        super().__init__("time")
        self._clock = clock

    def __getattr__(self, name):
        return getattr(time, name)

    def time(self):
        return self._clock.time()


def _shifted_datetime(clock: _Clock):
    class ShiftedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.now(tz) + timedelta(seconds=clock.offset())
    return ShiftedDatetime


# ------------------------------------------------------ the node transport --

class NodeEmulator:
    """Answers main.py's ssh commands for the nodes hub-lite registered."""

    def __init__(self, hub: "HubLite"):
        self.hub = hub
        self.trace: list = []

    def _node_for_host(self, host: str):
        for slug in self.hub.node_slugs():
            meta = self.hub.node_meta(slug)
            if meta.get("ssh_host") == host or meta.get("endpoint_ip") == host:
                return slug
        return None

    def _state(self, slug):
        path = self.hub.node_dir(slug) / "emulated_node.json"
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError):
            return {"registry_b64": "", "seq": 0, "awg_peers": {}}

    def _save(self, slug, state):
        write_private(self.hub.node_dir(slug) / "emulated_node.json", canonical(state))

    def run(self, argv, **kwargs):
        argv = list(argv)
        host = argv[-2].split("@", 1)[-1] if len(argv) >= 2 else ""
        command = argv[-1] if argv else ""
        slug = self._node_for_host(host)
        kind, rc, out, err = "unhandled", 255, "", "hub-lite node emulator: unhandled command"
        if slug is None:
            kind, err = "unknown-host", "hub-lite node emulator: no node with this management host"
        else:
            kind, rc, out, err = self._answer(slug, command, kwargs.get("input"))
        self.trace.append({"slug": slug, "kind": kind, "rc": rc})
        self.hub.record("node-transport", slug=slug, kind=kind, rc=rc)
        text = kwargs.get("text") or kwargs.get("universal_newlines") or kwargs.get("errors")
        if not text:
            out, err = out.encode(), err.encode()
        return subprocess.CompletedProcess(argv, rc, out, err)

    def _answer(self, slug, command, stdin=None):
        plan = self.hub.node_plan(slug)
        state = self._state(slug)
        if "/etc/winn/public/gateway-identity.json" in command:
            if plan.get("pull") == "fail":
                return "identity-pull", 1, "", "identity unreadable"
            pulled = self.hub.pulled_identity(slug)
            return "identity-pull", 0, json.dumps(pulled, separators=(",", ":")) + "\n", ""
        if "WINN3-OBSERVE-V1" in command:
            seq = int(re.search(r"seq=([0-9]+);", command).group(1))
            if seq <= state["seq"]:
                return "registry-observe", 3, "", f"winn3-registry-stale-sequence {state['seq']}"
            state["seq"] = seq
            self._save(slug, state)
            body = "WINN3-OBSERVE-V1\n"
            body += ("REG " + state["registry_b64"] + "\n") if state["registry_b64"] else "REG-ABSENT\n"
            return "registry-observe", 0, body + "END\n", ""
        if "/etc/winn/winn3-peers.json" in command and ".winn3-stage." in command:
            # The registry and the journal lines arrive on stdin (registry
            # first); the command carries the sequence, the lengths and the
            # digest of the whole stream. The node's own order: group, then
            # the stream check (exact length to end of file, whole-stream
            # digest), then the sequence guard.
            if plan.get("publish") == "fail":
                return "registry-publish", 4, "", "winn3-gateway-group-absent"
            seq = int(re.search(r"\bseq=([0-9]+);", command).group(1))
            total = int(re.search(r"\btotal=([0-9]+);", command).group(1))
            reg_len = int(re.search(r"\breg_len=([0-9]+);", command).group(1))
            stream_sha = re.search(r"\bstream_sha=([0-9a-f]{64});", command).group(1)
            stream = (stdin or "").encode("ascii")
            if len(stream) != total or reg_len > total or hashlib.sha256(stream).hexdigest() != stream_sha:
                return "registry-publish", 5, "", "winn3-registry-bad-payload"
            if seq <= state["seq"]:
                return "registry-publish", 3, "", f"winn3-registry-stale-sequence {state['seq']}"
            state["registry_b64"] = base64.b64encode(stream[:reg_len]).decode("ascii")
            state["seq"] = seq
            self._save(slug, state)
            return "registry-publish", 0, "", ""
        if self.hub.mod.HUB_OFFNODE_CHECK_PATH in command:
            return self._offnode(slug, plan, state)
        if "docker exec" in command:
            inner = command
            # D5: the v1 free-tier policy runs on the node before the peer is
            # installed. The emulator models the helper as succeeding, so the
            # policy segment (helper call plus its refusal branch, which spells
            # a peer removal) is dropped before the command is classified.
            inner = re.sub(r"(?:if \[ -x \S+ \]; then )?\S*wins-free-bandwidth awg0 \S+ \S+ \|\| \{ .*?"
                           r"echo 'bandwidth-policy-failed' >&2; exit 1; \}; (?:fi; )?", "", inner, count=1)
            if "awg set awg0 peer" in inner and " remove" in inner:
                match = re.search(r"awg set awg0 peer (\S+) remove", inner)
                if match:
                    state["awg_peers"].pop(shlex.split(match.group(1))[0], None)
                    self._save(slug, state)
                return "awg-peer-remove", 0, "", ""
            if "peer_pub=" in inner and "allowed_ip=" in inner:
                peer = re.search(r"peer_pub=('[^']*'|\S+?);", inner)
                allowed = re.search(r"allowed_ip=('[^']*'|\S+?);", inner)
                if peer and allowed:
                    state["awg_peers"][shlex.split(peer.group(1))[0]] = shlex.split(allowed.group(1))[0]
                    self._save(slug, state)
                return "awg-peer-sync", 0, "", ""
            if "awg show awg0 public-key" in inner:
                if plan.get("management") == "fail":
                    return "management-probe", 1, "", "awg unreachable"
                return "management-probe", 0, "", ""
            return "awg-other", 0, "", ""
        return "unhandled", 255, "", "hub-lite node emulator: unhandled command"

    def _offnode(self, slug, plan, state):
        mode = plan.get("offnode", "healthy")
        if mode == "missing":
            return "offnode-check", self.hub.mod.HUB_OFFNODE_CHECK_EXIT_MISSING, "", ""
        if isinstance(mode, str) and mode.startswith("file:"):
            return "offnode-check", 0, Path(mode[5:]).read_text(), ""
        registry = base64.b64decode(state["registry_b64"]) if state["registry_b64"] else b""
        canary_key = self.hub.mod.AWG_CANARY_PUBLIC_KEY
        lines = ["AWG_READ ok iface=awg0 peers=%d" % len(state["awg_peers"])]
        for key, allowed in sorted(state["awg_peers"].items()):
            if canary_key and key == canary_key and allowed == self.hub.mod.AWG_CANARY_ALLOWED_IPS:
                lines.append("AWGSYSPEER %s canary %s never" % (
                    hashlib.sha256(key.encode()).hexdigest()[:16],
                    hashlib.sha256(allowed.encode()).hexdigest()[:16]))
            else:
                lines.append("AWGPEER %s" % hashlib.sha256(key.encode()).hexdigest()[:16])
        if mode == "fail":
            lines.append("AWGPEER %s" % ("f" * 16))
        if registry:
            lines.append("V3_FILE present regular=1 sha256=%s" % hashlib.sha256(registry).hexdigest())
            lines.append("V3_VALID gateway_rules=ok")
            lines.append("GW unit=active pid_known=1 forward=1 registry_flag_matches=1 gateway_can_read=1 "
                         "started_after_file=1 reload_failed_since_file=0")
        else:
            lines.append("V3_FILE absent")
            lines.append("GW unit=inactive pid_known=0 forward=0 registry_flag_matches=0 "
                         "gateway_can_read=unknown started_after_file=unknown reload_failed_since_file=unknown")
        return "offnode-check", 0, "\n".join(lines) + "\n", ""


class _SubprocessShim(types.ModuleType):
    """main.py's `subprocess` name: ssh goes to NodeEmulator, a network tool
    is refused, everything else (openssl, ssh-keygen) runs for real."""

    def __init__(self, emulator: NodeEmulator):
        super().__init__("subprocess")
        self._emulator = emulator

    def __getattr__(self, name):
        return getattr(subprocess, name)

    @staticmethod
    def _tool(argv):
        if isinstance(argv, (list, tuple)) and argv:
            return os.path.basename(str(argv[0]))
        return ""

    def run(self, argv, *args, **kwargs):
        tool = self._tool(argv)
        if tool == "ssh":
            return self._emulator.run(argv, **kwargs)
        if tool in NETWORK_TOOLS:
            raise PermissionError(f"hub-lite: {tool} is a network tool and is not run")
        return subprocess.run(argv, *args, **kwargs)

    def Popen(self, argv, *args, **kwargs):  # noqa: N802 - mirrors subprocess
        tool = self._tool(argv)
        if tool == "ssh" or tool in NETWORK_TOOLS:
            raise PermissionError(f"hub-lite: {tool} is not started")
        return subprocess.Popen(argv, *args, **kwargs)

    def check_output(self, argv, *args, **kwargs):
        if self._tool(argv) in NETWORK_TOOLS | {"ssh"}:
            raise PermissionError("hub-lite: network tool refused")
        return subprocess.check_output(argv, *args, **kwargs)

    def call(self, argv, *args, **kwargs):
        if self._tool(argv) in NETWORK_TOOLS | {"ssh"}:
            raise PermissionError("hub-lite: network tool refused")
        return subprocess.call(argv, *args, **kwargs)

    def check_call(self, argv, *args, **kwargs):
        if self._tool(argv) in NETWORK_TOOLS | {"ssh"}:
            raise PermissionError("hub-lite: network tool refused")
        return subprocess.check_call(argv, *args, **kwargs)


# --------------------------------------------------------------- hub-lite --

class HubLite:
    """One hub: the extracted main.py, a signer process, keys and a database
    in `state`. Construct with init=True once; later constructions continue it."""

    def __init__(self, state, cp_installer=CP_INSTALLER, *, init=False, main_source=None,
                 signer_source=None, pinned=True, env_overrides=None, start_signer=True,
                 endpoint_pin_workaround=False):
        self.state = private_dir(refuse_state_path(Path(state)))
        self.cp_installer = Path(cp_installer)
        self.events: list = []
        self.alerts: list = []
        self.triggers: list = []
        self.canary_plan = {"pre_sign": "ok", "served": "ok"}
        self._stage = None
        self._signer_proc = None
        self._socket_dir = None
        self._client = None
        installer_text = self.cp_installer.read_text(encoding="utf-8")
        parts = extract(installer_text)
        self.extracted = {"main_sha256": sha256_text(parts["main"]),
                          "signer_sha256": sha256_text(parts["signer"]),
                          "probe_sha256": sha256_text(parts["probe"])}
        if pinned and (self.extracted["main_sha256"] != PINNED_MAIN_SHA256
                       or self.extracted["signer_sha256"] != PINNED_SIGNER_SHA256):
            raise HubLiteError("the control-plane installer's main.py or signer digest is not the pinned one")
        self.main_text = parts["main"] if main_source is None else main_source
        self.signer_text = parts["signer"] if signer_source is None else signer_source
        self.probe_text = parts["probe"]
        self.mutated = {"main": main_source is not None, "signer": signer_source is not None}
        self.clock = _Clock(self.state / "clock_offset")
        self.dirs = {name: private_dir(self.state / name) for name in
                     ("keys", "nodes", "log", "work", "signer", "canary-keys", "canary-requests",
                      "canary-results", "ssh-cm")}
        for name in ("config", "state", "work", "digest"):
            self.dirs["signer-" + name] = private_dir(self.dirs["signer"] / name)
        if init:
            self._init_material(endpoint_pin_workaround)
        elif not (self.state / "manifest.json").exists():
            raise HubLiteError("no hub-lite state here; run init first")
        self.manifest = json.loads((self.state / "manifest.json").read_text())
        self.env = self._hub_env(env_overrides or {})
        install_network_guard()
        self._write_signer_program()
        if init:
            rc = self.signer_cli("ledger-bootstrap")
            if rc["rc"] != 0:
                raise HubLiteError("ledger-bootstrap failed: " + rc["stderr"][-300:])
        if start_signer:
            self.start_signer()
        self.mod = self._load_main()
        self.probe = self._load_probe()
        with self.activated(), self.mod.get_db() as conn:
            self.mod.ensure_schema(conn)

    # ---------------------------------------------------------- material --
    def _init_material(self, endpoint_pin_workaround=False):
        h1 = _h1()
        if (self.state / "manifest.json").exists():
            raise HubLiteError("state already initialized")
        pubs = {}
        for slot in SLOTS + ("t1",):
            key = self.dirs["keys"] / f"{slot}.ed25519.pem"
            pubs[slot] = base64.b64encode(h1.genkey(key)).decode()
            os.chmod(key, 0o600)
        secrets_doc = {"admin_token": secrets.token_urlsafe(32), "rate_limit_secret": secrets.token_hex(32),
                       "spa_hmac": secrets.token_hex(32), "management_name_hmac_key": secrets.token_hex(32),
                       "tunnel_service_token_secret": secrets.token_hex(32)}
        write_private(self.state / "secrets.json", canonical(secrets_doc))
        write_private(self.state / "admin_token", secrets_doc["admin_token"] + "\n")
        canary_pub = base64.b64encode(os.urandom(32)).decode()
        manifest = {"version": 1, "created_at": int(time.time()), "pubkeys": pubs,
                    "active_slot": os.environ.get("WINN3_DESCRIPTOR_SIGNER_ACTIVE_SLOT", "g2"),
                    "awg_canary_public_key": canary_pub, "extracted": self.extracted,
                    "mutated": self.mutated, "deviations": ["HL-D1"] if endpoint_pin_workaround else []}
        if manifest["active_slot"] not in SLOTS:
            raise HubLiteError("WINN3_DESCRIPTOR_SIGNER_ACTIVE_SLOT must be g1, g2 or g3")
        write_private(self.state / "manifest.json", json.dumps(manifest, indent=1, sort_keys=True))
        self._write_signer_config(manifest)
        write_private(self.state / "clock_offset", "0\n")

    def _write_signer_config(self, manifest):
        slot = manifest["active_slot"]
        config = self.dirs["signer-config"]
        shutil.copyfile(self.dirs["keys"] / f"{slot}.ed25519.pem", config / f"{slot}.ed25519.pem")
        os.chmod(config / f"{slot}.ed25519.pem", 0o600)
        write_private(config / "signer.json", canonical({
            "active_slot": slot, "active_slot_pubkey": manifest["pubkeys"][slot],
            "ticket_pubkey_t1": manifest["pubkeys"]["t1"]}), 0o440)
        write_private(config / "ticket-epoch", "1\n", 0o440)

    def _secrets(self):
        return json.loads((self.state / "secrets.json").read_text())

    def _hub_env(self, overrides):
        s = self._secrets()
        env = {
            "DATABASE_PATH": str(self.state / "vpn_users.db"),
            "SECURITY_EVENTS_DB": str(self.state / "security_events.db"),
            "ADMIN_TOKEN": s["admin_token"], "RATE_LIMIT_SECRET": s["rate_limit_secret"],
            "SPA_HMAC": s["spa_hmac"], "MANAGEMENT_NAME_HMAC_KEY": s["management_name_hmac_key"],
            "SMTP_PASS": "", "IONOS_HUB_IP": "",
            "NODE_MANAGEMENT_TUNNEL_ZONE_NAME": "hublite.test",
            "TUNNEL_SERVICE_TOKEN_ID": "hublite-test.access",
            "TUNNEL_SERVICE_TOKEN_SECRET": s["tunnel_service_token_secret"],
            "AWG_CANARY_PUBLIC_KEY": self.manifest_value("awg_canary_public_key"),
            "WINN3_SIGNER_TICKET_PUBKEY_T1": self.manifest_value("pubkeys")["t1"],
            "WINN3_DESCRIPTOR_SIGNER_ACTIVE_SLOT": self.manifest_value("active_slot"),
            "WINN3_AUTO_SIGN": "1", "WINN3_AUTO_CARRIER": "1", "WINN3_FRESH_INSTALL_AUTO_GOLIVE": "1",
            "NODE_INSTALLER_RERUN_AUTO_REOPEN_ENABLED": "1", "WINN3_INNER_POOL_CIDR": "10.10.0.0/24",
            "WINN3_RECOVERY_MODE": "0", "WINN3_CANARY_BIN": str(self.state / "bin" / "winn3-probe"),
        }
        for slot in SLOTS:
            env[f"WINN3_DESCRIPTOR_PUBKEY_{slot.upper()}"] = self.manifest_value("pubkeys")[slot]
        if "HL-D1" in self.manifest_value("deviations"):
            env["HIDE_CONTROL_ORIGIN"] = "0"
        env.update({k: str(v) for k, v in overrides.items()})
        return env

    def manifest_value(self, key):
        return json.loads((self.state / "manifest.json").read_text())[key]

    @contextlib.contextmanager
    def activated(self):
        """This hub's environment for the duration of an operation (main.py
        reads several switches at call time)."""
        saved = {k: os.environ.get(k) for k in self.env}
        os.environ.update(self.env)
        try:
            yield
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def record(self, event, **fields):
        entry = dict(event=event, **fields)
        self.events.append(entry)

    # ------------------------------------------------------------- main --
    def _load_main(self):
        src = self.main_text
        targets = {"LOG_DIR": str(self.dirs["log"]), "LOG_FILE": str(self.dirs["log"] / "master.log"),
                   "STATE_DIR": str(self.state)}
        self.replacements_applied = []
        for old, placeholder, count in MAIN_SOURCE_REPLACEMENTS:
            found = src.count(old)
            if found != count:
                raise HubLiteError(f"main.py replacement {old} found {found} times, expected {count}")
            src = src.replace(old, repr(targets[placeholder]))
            self.replacements_applied.append((old, found))
        module = types.ModuleType("wins_hub_lite_main")
        module.__file__ = str(self.state / "main.py")
        sys.modules[module.__name__] = module
        import logging
        root = logging.getLogger()
        self._root_handlers = (list(root.handlers), root.level)
        with self.activated(), _real_third_party():
            exec(compile(src, "wins_hub_main.py", "exec"), module.__dict__)
        # main.py's basicConfig(force=True) installed a file and a stderr
        # handler on the root logger; close() closes them and restores these.
        self._hub_handlers = [h for h in root.handlers if h not in self._root_handlers[0]]
        self._bind(module)
        return module

    def _bind(self, mod):
        rebinds = {"WINN3_SIGNER_SOCKET": str(self.socket_path), "WINN3_SIGNER_SOCKET_PATH": str(self.socket_path),
                   "WINN3_CANARY_KEY_ROOT": self.dirs["canary-keys"],
                   "WINN3_CANARY_REQUEST_DIR": self.dirs["canary-requests"],
                   "WINN3_CANARY_RESULT_DIR": self.dirs["canary-results"],
                   "HUB_MANAGEMENT_SSH_CONTROL_DIR": str(self.dirs["ssh-cm"])}
        for name, _why in MAIN_PATH_REBINDS:
            if not hasattr(mod, name):
                raise HubLiteError(f"main.py has no {name}")
            value = rebinds[name]
            setattr(mod, name, type(getattr(mod, name))(value) if isinstance(getattr(mod, name), Path) else value)
        self.emulator = NodeEmulator(self)
        mod.subprocess = _SubprocessShim(self.emulator)
        clock = self.clock
        mod.now_utc = clock.now_utc
        mod.security_now_utc = clock.now_utc
        mod.time = _TimeShim(clock)
        original_probe = mod.winn3_run_canary_probe
        hub = self

        def winn3_run_canary_probe(argv, timeout):
            verdict = hub.canary_plan.get(hub._stage or "", "fail")
            hub.record("canary-probe", stage=hub._stage, verdict=verdict)
            if verdict == "ok":
                return subprocess.CompletedProcess(argv, 0, b"HANDSHAKE ok state=carrying\n", b"")
            return subprocess.CompletedProcess(argv, 1, b"HANDSHAKE failed\n", b"")
        winn3_run_canary_probe.original = original_probe
        mod.winn3_run_canary_probe = winn3_run_canary_probe
        for name, stage in (("winn3_pre_sign_canary", "pre_sign"), ("winn3_served_profile_canary", "served")):
            original = getattr(mod, name)

            def staged(*args, _original=original, _stage=stage, **kwargs):
                hub._stage = _stage
                current = hub.row(args[0]["slug"]) if args else None
                hub.record("canary-stage", stage=_stage,
                           carrier_in_database=current["protocol_version"] if current else None,
                           carrier_on_probed_row=args[0]["protocol_version"] if args else None)
                try:
                    return _original(*args, **kwargs)
                finally:
                    hub._stage = None
            setattr(mod, name, staged)

        def security_alert(priority, event_type, request=None, source_ip="", details=None):
            entry = {"priority": priority, "event": event_type,
                     "details": {k: v for k, v in (details or {}).items() if isinstance(v, (str, int, bool, list))}}
            hub.alerts.append(entry)
            with open(hub.state / "alerts.jsonl", "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")
        mod.security_alert = security_alert

        # Observers: they call the original and record what crossed it.
        original_client = mod.winn3_signer_client

        def winn3_signer_client(request):
            entry = {"verb": request.get("verb"), "expected_prior_seq": request.get("expected_prior_seq"),
                     "generation": request.get("generation"), "slug": request.get("slug")}
            try:
                reply = original_client(request)
            except ValueError as exc:
                hub.record("signer-request", ok=False, error=str(exc), **entry)
                raise
            hub.record("signer-request", ok=True, seq=reply.get("seq"), kid=reply.get("kid"),
                       orphan=reply.get("orphan"), **entry)
            return reply
        mod.winn3_signer_client = winn3_signer_client
        original_store = mod.winn3_store_descriptor

        def winn3_store_descriptor(conn, row, payload_b64, signature_b64):
            result = original_store(conn, row, payload_b64, signature_b64)
            hub.record("descriptor-stored", slug=row["slug"], carrier_at_store=row["protocol_version"],
                       seq=result[0].get("seq"), kid=result[0].get("kid"), slot=result[1])
            return result
        mod.winn3_store_descriptor = winn3_store_descriptor

        def ensure_ssh_management_tunnel(kind, identifier):
            kind = str(kind or "").strip().lower()
            slug = str(identifier or "").strip().lower()
            return {"tunnel_id": "hub-lite-no-tunnel", "ssh_host": mod.management_tunnel_hostname(kind, slug),
                    "tunnel_token": "hub-lite-no-tunnel-token", "access_required": False,
                    "access_application_id": ""}
        mod.ensure_ssh_management_tunnel = ensure_ssh_management_tunnel

        def start_thread(target, slug):
            hub.triggers.append(slug)
            with mod._WINN3_PROVISION_LOCK:
                mod._WINN3_PROVISION_STATE.pop(slug, None)
        mod._winn3_provision_start_thread = start_thread

    def _load_probe(self):
        module = types.ModuleType("wins_hub_lite_probe")
        with self.activated():
            exec(compile(self.probe_text, "wins_node_dataplane_probe.py", "exec"), module.__dict__)
        module.DB_PATH = self.env["DATABASE_PATH"]
        clock = self.clock
        module.datetime = _shifted_datetime(clock)
        module.utcnow_iso = lambda: clock.now_utc().replace(tzinfo=None).isoformat()
        module.log = lambda message: self.record("probe-log", message=str(message)[:200])
        return module

    # ----------------------------------------------------------- signer --
    @property
    def socket_path(self) -> Path:
        candidate = self.dirs["signer"] / "sock"
        if len(str(candidate)) < 100:
            return candidate
        if self._socket_dir is None:
            self._socket_dir = Path(tempfile.mkdtemp(prefix="hls-"))
            os.chmod(self._socket_dir, 0o700)
        return self._socket_dir / "sock"

    def _write_signer_program(self):
        path = self.dirs["signer"] / "wins_descriptor_signer.py"
        write_private(path, self.signer_text, 0o600)
        write_private(self.dirs["signer"] / "program.sha256", sha256_text(self.signer_text) + "\n")

    def _signer_argv(self, *args):
        return [sys.executable, "-B", "-I", str(Path(__file__).resolve()), "_signer", "--state", str(self.state),
                *args]

    def _signer_env(self):
        return {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "HUBLITE_HUB_PID": str(os.getpid()),
                "LC_ALL": "C", "HOME": str(self.state), "HUBLITE_OPENSSL": _h1().OPENSSL,
                "HUBLITE_SSH_KEYGEN": _h1().SSH_KEYGEN or "/usr/bin/ssh-keygen"}

    def signer_cli(self, mode, *args):
        """One of the signer's own operator CLIs (3.12), run as its own process."""
        done = subprocess.run(self._signer_argv("cli", mode, *args), capture_output=True, text=True,
                              env=self._signer_env(), timeout=120, check=False)
        self.record("signer-cli", mode=mode, rc=done.returncode)
        return {"rc": done.returncode, "stdout": done.stdout, "stderr": done.stderr}

    def start_signer(self):
        if self._signer_proc is not None:
            return
        path = self.socket_path
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        os.chmod(path, 0o600)
        listener.listen(16)
        log = open(self.dirs["signer"] / "signer.log", "ab")
        try:
            self._signer_proc = subprocess.Popen(
                self._signer_argv("serve", "--fd", str(listener.fileno())), pass_fds=(listener.fileno(),),
                stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=self._signer_env())
        finally:
            listener.close()
            log.close()
        self.record("signer-started", pid=self._signer_proc.pid)

    def stop_signer(self):
        proc, self._signer_proc = self._signer_proc, None
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
        with contextlib.suppress(OSError):
            self.socket_path.unlink()

    def restart_signer(self):
        self.stop_signer()
        self.start_signer()

    def close(self):
        self.stop_signer()
        if getattr(self, "_hub_handlers", None) is not None:
            import logging
            root = logging.getLogger()
            for handler in self._hub_handlers:
                root.removeHandler(handler)
                handler.close()
            for handler in self._root_handlers[0]:
                if handler not in root.handlers:
                    root.addHandler(handler)
            root.setLevel(self._root_handlers[1])
            self._hub_handlers = None
        if self._socket_dir is not None:
            shutil.rmtree(self._socket_dir, ignore_errors=True)
            self._socket_dir = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def ledger(self) -> dict:
        return json.loads((self.dirs["signer-state"] / "ledger.json").read_text())

    def signer_epoch(self) -> int:
        return int((self.dirs["signer-config"] / "ticket-epoch").read_text().strip())

    # ------------------------------------------------------------- http --
    @property
    def client(self):
        if self._client is None:
            import logging
            import warnings
            logging.getLogger("httpx").setLevel(logging.WARNING)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                from starlette.testclient import TestClient
            # Never entered as a context manager: that would run the lifespan.
            self._client = TestClient(self.mod.app, raise_server_exceptions=True)
        return self._client

    def http(self, method, path, *, admin=False, node_token=None, json_body=None, form=None):
        headers = {}
        if admin:
            headers["x-admin-token"] = self._secrets()["admin_token"]
        if node_token is not None:
            headers["x-node-token"] = node_token
        with self.activated():
            response = self.client.request(method, path, headers=headers, json=json_body, data=form)
        try:
            body = response.json()
        except ValueError:
            body = {"text": response.text[:500]}
        self.record("http", method=method, path=path, status=response.status_code)
        return response.status_code, body

    @contextlib.contextmanager
    def db(self):
        conn = sqlite3.connect(self.env["DATABASE_PATH"], timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def row(self, slug):
        with self.db() as conn:
            row = conn.execute("SELECT * FROM nodes WHERE slug=?", (slug,)).fetchone()
        return dict(row) if row is not None else None

    # ------------------------------------------------------------- nodes --
    def node_dir(self, slug) -> Path:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,39}", slug or ""):
            raise HubLiteError("slug is invalid")
        return private_dir(self.dirs["nodes"] / slug)

    def node_slugs(self):
        return sorted(p.name for p in self.dirs["nodes"].iterdir() if (p / "node.json").exists())

    def node_meta(self, slug):
        try:
            return json.loads((self.node_dir(slug) / "node.json").read_text())
        except (OSError, ValueError):
            return {}

    def node_plan(self, slug):
        return self.node_meta(slug).get("plan", {})

    def set_node_plan(self, slug, **plan):
        meta = self.node_meta(slug)
        meta.setdefault("plan", {}).update(plan)
        write_private(self.node_dir(slug) / "node.json", json.dumps(meta, indent=1, sort_keys=True))

    def node_token(self, slug):
        return (self.node_dir(slug) / "node_token").read_text().strip()

    def pulled_identity(self, slug):
        return json.loads((self.node_dir(slug) / "pulled.json").read_text())

    def _host_key(self, slug, fresh=False):
        directory = self.node_dir(slug)
        key = directory / "host_ed25519"
        if fresh or not key.exists():
            for path in (key, directory / "host_ed25519.pub"):
                with contextlib.suppress(FileNotFoundError):
                    path.unlink()
            _h1().run([_h1().SSH_KEYGEN or "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "hublite",
                       "-f", str(key)])
        line = (directory / "host_ed25519.pub").read_text().split()
        blob = base64.b64decode(line[1])
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        return key, f"{line[0]} {line[1]}", fingerprint

    def build_identity(self, slug, *, endpoint_ip=DEFAULT_ENDPOINT_IP, gateway_id=None, fresh=False):
        """The node side of 3.5 for a test node: gateway keys, the admission
        secret and the identity file signed by the node's SSH host key with
        ssh-keygen -Y sign (namespace winsvpn-winn3-identity/v1)."""
        key, hostline, _fp = self._host_key(slug, fresh=fresh)
        secret = secrets.token_hex(32)
        fingerprint = hashlib.sha256(b"winn3-admission-fingerprint-v1" + secret.encode()).hexdigest()[:16]
        body = {"slug": slug, "gateway_id": gateway_id or f"{slug}-gw1", "endpoint": f"{endpoint_ip}:9111",
                "inner_router_v4": "10.10.0.1", "inner_resolver_v4": "10.10.0.1", "path_mtu": 1450,
                "plan": "udp", "static_pub_hex": os.urandom(32).hex(), "auth_ed25519_hex": os.urandom(32).hex(),
                "auth_mldsa65_hex": os.urandom(1952).hex(), "admission_fingerprint": fingerprint,
                "credential_record_sha256": os.urandom(32).hex(), "ssh_host_ed25519_key": hostline}
        raw = canonical(body)
        work = Path(tempfile.mkdtemp(dir=self.dirs["work"]))
        try:
            doc = work / "gateway-identity.json"
            doc.write_bytes(raw)
            _h1().run([_h1().SSH_KEYGEN or "ssh-keygen", "-q", "-Y", "sign", "-f", str(key),
                       "-n", "winsvpn-winn3-identity/v1", str(doc)])
            sig = (work / "gateway-identity.json.sig").read_bytes()
        finally:
            shutil.rmtree(work, ignore_errors=True)
        pulled = {"identity": base64.b64encode(raw).decode(), "identity_sig": base64.b64encode(sig).decode(),
                  "admission_secret": secret, "detected_public_ip": endpoint_ip}
        write_private(self.node_dir(slug) / "pulled.json", canonical(pulled))
        return pulled

    def identity(self, slug):
        return json.loads(base64.b64decode(self.pulled_identity(slug)["identity"]))

    def allocate_endpoint_ip(self, slug):
        known = self.node_meta(slug).get("endpoint_ip")
        if known:
            return known
        used = {self.node_meta(other).get("endpoint_ip") for other in self.node_slugs()}
        for host in range(10, 250):
            candidate = f"203.0.113.{host}"
            if candidate not in used:
                return candidate
        raise HubLiteError("no documentation-range endpoint address left")

    def _pin_endpoint_ip(self, slug, endpoint_ip, hostline):
        """HL-D1 only: the IP pin no route can write (FINDINGS HL-F1)."""
        path = Path(self.mod.MANAGEMENT_KNOWN_HOSTS_PATH)
        lines = [line for line in path.read_text().splitlines() if line.split(None, 1)[0] != endpoint_ip]
        lines.append(f"{endpoint_ip} {hostline}")
        write_private(path, "\n".join(lines) + "\n")

    def node(self, slug, *, installer_sha256=None, pulled_file=None, fresh_machine=False,
             endpoint_ip=None, status="online", stealth=None):
        """Bootstrap (or re-bootstrap) a node through the real routes: a grant
        from POST /admin/bootstrap-grant, POST /api/v1/nodes/bootstrap, the
        management pin through POST /admin/nodes/bootstrap-management-tunnel,
        POST /api/v1/nodes/register, then one real resync (the node's
        management probe and closure cleanup, through the node transport)."""
        directory = self.node_dir(slug)
        existing = (directory / "node.json").exists()
        endpoint_ip = endpoint_ip or self.allocate_endpoint_ip(slug)
        digest = installer_sha256 or self.node_meta(slug).get("installer_sha256") or hashlib.sha256(
            DP_INSTALLER.read_bytes()).hexdigest()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise HubLiteError("installer_sha256 must be 64 lowercase hex characters")
        if pulled_file:
            pulled = json.loads(Path(pulled_file).read_text())
            if set(pulled) != {"identity", "identity_sig", "admission_secret", "detected_public_ip"}:
                raise HubLiteError("the pulled identity file must hold exactly identity, identity_sig, "
                                   "admission_secret and detected_public_ip")
            write_private(directory / "pulled.json", canonical(pulled))
            endpoint_ip = pulled["detected_public_ip"]
        elif fresh_machine or not (directory / "pulled.json").exists():
            pulled = self.build_identity(slug, endpoint_ip=endpoint_ip, fresh=fresh_machine)
        else:
            pulled = self.pulled_identity(slug)
        identity = json.loads(base64.b64decode(pulled["identity"]))
        status_code, grant = self.http("POST", "/admin/bootstrap-grant", admin=True,
                                       json_body={"role": "node", "subject_id": slug, "ttl_seconds": 600})
        if status_code != 200:
            raise HubLiteError(f"bootstrap grant refused ({status_code})")
        status_code, boot = self.http("POST", "/api/v1/nodes/bootstrap",
                                      json_body={"slug": slug, "bootstrap_token": grant["bootstrap_token"]})
        if status_code != 200:
            raise HubLiteError(f"bootstrap refused ({status_code})")
        write_private(directory / "node_token", boot["node_token"] + "\n")
        status_code, tunnel = self.http("POST", "/admin/nodes/bootstrap-management-tunnel", admin=True,
                                        json_body={"node_slug": slug,
                                                   "ssh_host_keys": [identity["ssh_host_ed25519_key"]]})
        if status_code != 200:
            raise HubLiteError(f"management pin refused ({status_code}): {tunnel}")
        meta = self.node_meta(slug)
        if stealth is None:
            stealth = meta.get("stealth") or ""
        if stealth not in ("", "tls", "plain"):
            raise HubLiteError("stealth must be tls or plain")
        meta.update({"slug": slug, "ssh_host": tunnel["ssh_host"], "endpoint_ip": endpoint_ip,
                     "installer_sha256": digest, "gateway_id": identity["gateway_id"], "stealth": stealth})
        if stealth and not meta.get("xray_uuid"):
            import uuid
            meta["xray_uuid"] = str(uuid.uuid4())
        if fresh_machine or not meta.get("awg_public_key"):
            meta["awg_public_key"] = base64.b64encode(os.urandom(32)).decode()
        meta.setdefault("plan", {})
        write_private(directory / "node.json", json.dumps(meta, indent=1, sort_keys=True))
        if "HL-D1" in self.manifest["deviations"]:
            self._pin_endpoint_ip(slug, endpoint_ip, identity["ssh_host_ed25519_key"])
        if fresh_machine:
            with contextlib.suppress(FileNotFoundError):
                (directory / "emulated_node.json").unlink()
        self._register(slug, boot["node_token"], status=status)
        with self.activated():
            resync = self.mod.resync_active_peers_to_node(slug)
        row = self.row(slug)
        return {"ok": True, "slug": slug, "rebootstrap": existing, "ssh_host": tunnel["ssh_host"],
                "node_token_file": str(directory / "node_token"), "installer_sha256": digest,
                "management_status": row["management_status"], "resync_ok": bool(resync.get("ok")),
                "deployment_generation": row["deployment_generation"],
                "node_bootstrapped_at": row["node_bootstrapped_at"]}

    def _register(self, slug, node_token, *, status="online"):
        """POST /api/v1/nodes/register as wins-node-register sends it."""
        meta = self.node_meta(slug)
        identity = self.identity(slug)
        endpoint_ip, digest, stealth = meta["endpoint_ip"], meta["installer_sha256"], meta.get("stealth") or ""
        registration = {
            "slug": slug, "name": f"hub-lite {slug}", "flag": "X",
            "data_plane_code_revision": "sha256:" + digest, "endpoint": f"{endpoint_ip}:9110",
            "tunnel_gateway_ipv4": "10.8.1.1", "public_key": meta["awg_public_key"],
            "secret_token": node_token, "status": status,
            "obfuscation_json": json.dumps(GOOD_OBFUSCATION), "ssh_host": meta["ssh_host"], "wg_port": 9110,
            "max_peers": 100,
            "winn3_gateway": {"state": "active", "forward": True, "resolver": True, "listen": "0.0.0.0:9111",
                              "gateway_id": identity["gateway_id"], "inner_v4": identity["inner_router_v4"],
                              "forward_cidr": "10.10.0.0/24", "path_mtu": identity["path_mtu"],
                              "plan": identity["plan"]},
        }
        if stealth:
            # "tls" registers the installer default 80:none,443:tls, which the hub
            # serves (and so proves) as stealth_tls only; "plain" registers 80:none,
            # served and proved as stealth (main.parse_xray_transports).
            transports = [{"port": 80, "security": "none"}]
            if stealth == "tls":
                transports.append({"port": 443, "security": "tls"})
            registration.update(stealth_endpoint=f"stealth-{slug}.hublite.test:80", xray_uuid=meta["xray_uuid"],
                                stealth_public_port=80, xray_path="/wins-stealth-tunnel", xray_security="none",
                                stealth_transports=transports)
        status_code, registered = self.http("POST", "/api/v1/nodes/register", json_body=registration)
        if status_code != 200:
            raise HubLiteError(f"registration refused ({status_code}): {registered}")

    def rerun(self, slug, *, new_gateway_keys=False, installer_sha256=None):
        """An installer rerun as the node performs it: POST .../deployment/
        withdraw, the final registration, POST .../deployment/complete. With
        new_gateway_keys the rerun regenerated the gateway keys and the
        admission secret on the same machine (same SSH host key)."""
        token = self.node_token(slug)
        status_code, withdrawn = self.http("POST", f"/api/v1/nodes/{slug}/deployment/withdraw", node_token=token)
        if status_code != 200:
            return {"ok": False, "stage": "withdraw", "status_code": status_code, "detail": withdrawn.get("detail")}
        if new_gateway_keys:
            self.build_identity(slug, endpoint_ip=self.node_meta(slug)["endpoint_ip"])
        if installer_sha256:
            meta = self.node_meta(slug)
            meta["installer_sha256"] = installer_sha256
            write_private(self.node_dir(slug) / "node.json", json.dumps(meta, indent=1, sort_keys=True))
        self._register(slug, token)
        status_code, done = self.http("POST", f"/api/v1/nodes/{slug}/deployment/complete", node_token=token,
                                      json_body={"withdrawal_id": withdrawn["withdrawal_id"]})
        row = self.row(slug)
        return {"ok": status_code == 200, "status_code": status_code, "body": done,
                "deployment_generation": row["deployment_generation"],
                "health_closed_reason": row["health_closed_reason"]}

    # ----------------------------------------------------------- tickets --
    def ticket(self, slug, action="new", *, go_live="auto", tier="free", epoch=None, not_after=None,
               post=True, nonce=None, endpoint_ip=None, gateway_id=None, host_key_sha256=None):
        """A t1 ticket (3.8) signed by real openssl with the test t1 key, and
        posted through the REAL POST /admin/nodes/winn3/signer-ticket."""
        meta = self.node_meta(slug)
        identity = self.identity(slug)
        if epoch is None:
            status_code, body = self.http("GET", "/admin/nodes/winn3/signer-ticket", admin=True)
            if status_code != 200 or not isinstance(body.get("epoch"), int):
                raise HubLiteError(f"the signer epoch is unavailable ({status_code})")
            epoch = body["epoch"]
        fields = {"slug": slug, "action": action, "epoch": epoch,
                  "endpoint_ip": endpoint_ip or meta.get("endpoint_ip") or DEFAULT_ENDPOINT_IP,
                  "gateway_id": gateway_id or identity["gateway_id"],
                  "host_key_sha256": host_key_sha256 or self._host_key(slug)[2],
                  "go_live": go_live, "tier": tier, "nonce": nonce or secrets.token_hex(16),
                  "not_after": int(not_after if not_after is not None else self.clock.time() + 3 * DAY)}
        raw = canonical(fields)
        work = Path(tempfile.mkdtemp(dir=self.dirs["work"]))
        try:
            sig = _h1().openssl_sign(self.dirs["keys"] / "t1.ed25519.pem",
                                     b"winsvpn-winn3-signer-ticket/v1\x00" + raw, work)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        envelope = {"payload": base64.b64encode(raw).decode(), "sig": base64.b64encode(sig).decode()}
        result = {"ticket": envelope, "fields": fields}
        if post:
            status_code, body = self.http("POST", "/admin/nodes/winn3/signer-ticket", admin=True,
                                          json_body={"slug": slug, "ticket": envelope})
            result.update(posted_status=status_code, posted=body)
            time.sleep(0.002)
        return result

    # ------------------------------------------------------ operations --
    def complete_fresh(self, slug, installer_sha256=None, token=None):
        digest = installer_sha256 or self.node_meta(slug).get("installer_sha256")
        status_code, body = self.http("POST", f"/api/v1/nodes/{slug}/deployment/complete-fresh",
                                      node_token=token if token is not None else self.node_token(slug),
                                      json_body={"installer_sha256": digest})
        return {"status_code": status_code, "body": body}

    def provision(self, slug, *, pre_sign="ok", served="ok"):
        self.canary_plan = {"pre_sign": pre_sign, "served": served}
        before = len(self.emulator.trace)
        with self.activated():
            result = self.mod.winn3_auto_provision(slug)
        return {"result": result, "node_transport": [t["kind"] for t in self.emulator.trace[before:]]}

    def signer_request(self, slug, verb, *, store=True):
        """One request built by the hub's REAL request builder and sent by its
        REAL client, then stored by the real store path, as the job does."""
        mod = self.mod
        with self.activated():
            with mod.get_db() as conn:
                row = conn.execute(mod.WINN3_JOB_ROW_SQL, (slug,)).fetchone()
            pulled = self.pulled_identity(slug) if verb != "renew" else None
            try:
                request = mod.winn3_build_signer_request(row, verb, row["deployment_generation"], pulled)
            except ValueError as exc:
                return {"ok": False, "request": None, "error": str(exc), "refused_by": "hub-request-builder"}
            summary = {"verb": request["verb"], "expected_prior_seq": request["expected_prior_seq"],
                       "generation": request["generation"]}
            try:
                reply = mod.winn3_signer_client(request)
            except ValueError as exc:
                return {"ok": False, "request": summary, "error": str(exc), "refused_by": "signer"}
            out = {"ok": True, "request": summary, "seq": reply["seq"], "kid": reply["kid"],
                   "orphan": reply["orphan"]}
            if store:
                with mod.get_db() as conn:
                    conn.commit()
                    conn.execute("BEGIN IMMEDIATE")
                    current = conn.execute(mod.WINN3_JOB_ROW_SQL, (slug,)).fetchone()
                    descriptor, _slot, _rotated, _row = mod.winn3_store_descriptor(
                        conn, current, reply["payload"], reply["sig"])
                    conn.execute("UPDATE nodes SET winn3_identity_sha256=? WHERE slug=?",
                                 (mod.winn3_identity_digest(descriptor), slug))
                out["stored_seq"] = descriptor["seq"]
        return out

    def signer_state_verb(self, slug, verb, *, require_bumped=True):
        """STEP-14: suspend or unsuspend with a t1 ticket through the hub's
        real signer client. The generation is bumped first: a suspend needs
        the sticky hold or a withheld descriptor already in place."""
        if verb not in ("suspend", "unsuspend"):
            raise HubLiteError("verb must be suspend or unsuspend")
        row = self.row(slug)
        if verb == "suspend" and require_bumped and not (row["winn3_operator_hold"] or not row["winn3_descriptor_json"]):
            return {"ok": False, "error": "generation-not-bumped-first",
                    "detail": "hold (POST /admin/nodes/winn3 enabled=false) or withhold first (STEP-14)"}
        minted = self.ticket(slug, verb)
        with self.activated():
            try:
                reply = self.mod.winn3_signer_client({"verb": verb, "slug": slug, "ticket": minted["ticket"]})
            except ValueError as exc:
                return {"ok": False, "error": str(exc), "ticket_nonce": minted["fields"]["nonce"]}
        return {"ok": True, "state": reply.get("state"), "ticket_nonce": minted["fields"]["nonce"],
                "deployment_generation": row["deployment_generation"]}

    def hold(self, slug, enabled_hold=True):
        before = self.row(slug)["deployment_generation"]
        if enabled_hold:
            form = {"slug": slug, "enabled": "false"}
        else:
            identity = self.identity(slug)
            form = {"slug": slug, "enabled": "true", "protocol_params_json": json.dumps({"carrier": "winn3"}),
                    "path_mtu": str(identity["path_mtu"]), "carrier_classes": identity["plan"]}
        status_code, body = self.http("POST", "/admin/nodes/winn3", admin=True, form=form)
        row = self.row(slug)
        return {"status_code": status_code, "ok": status_code == 200, "detail": body.get("detail"),
                "generation_before": before, "deployment_generation": row["deployment_generation"],
                "winn3_operator_hold": row["winn3_operator_hold"], "protocol_version": row["protocol_version"]}

    def withhold(self, slug):
        before = self.row(slug)["deployment_generation"]
        status_code, body = self.http("POST", "/admin/nodes/winn3/descriptor", admin=True,
                                      form={"slug": slug, "enabled": "false"})
        row = self.row(slug)
        return {"status_code": status_code, "ok": status_code == 200, "generation_before": before,
                "deployment_generation": row["deployment_generation"],
                "descriptor_stored": bool(row["winn3_descriptor_json"]),
                "admission_floor": self.retained_floor(slug)}

    def retained_floor(self, slug):
        mod = self.mod
        row = self.row(slug)
        with self.activated():
            descriptor = mod.winn3_stored_descriptor(row, clock_tolerant=True)
            return mod.winn3_admission_sequence_floor(
                descriptor, mod.parse_winn3_admission_ledger(row["winn3_admission_json"]))

    def g1_descriptor(self, slug, seq, *, admission_gen=1):
        """A descriptor in the signer's format 3, signed by the test g1 key,
        as the standalone installer's emergency path stored them (3.12)."""
        identity = self.identity(slug)
        pulled = self.pulled_identity(slug)
        now = int(self.clock.time())
        payload = {"v": 3, "alg": "ed25519", "kid": "g1", "node": slug, "endpoint": identity["endpoint"],
                   "inner_router_v4": identity["inner_router_v4"],
                   "inner_resolver_v4": identity["inner_resolver_v4"],
                   "static_pub": base64.b64encode(bytes.fromhex(identity["static_pub_hex"])).decode(),
                   "gateway_id": base64.b64encode(identity["gateway_id"].encode()).decode(),
                   "admission_secret": base64.b64encode(pulled["admission_secret"].encode()).decode(),
                   "tag_size": 32, "padding": "bucket", "bucket_window_s": 10, "max_skew_s": 60,
                   "auth_ed25519": base64.b64encode(bytes.fromhex(identity["auth_ed25519_hex"])).decode(),
                   "auth_mldsa65": base64.b64encode(bytes.fromhex(identity["auth_mldsa65_hex"])).decode(),
                   "seq": seq, "iat": now, "not_after": now + 14 * DAY, "admission_gen": admission_gen}
        raw = canonical(payload)
        work = Path(tempfile.mkdtemp(dir=self.dirs["work"]))
        try:
            sig = _h1().openssl_sign(self.dirs["keys"] / "g1.ed25519.pem",
                                     b"winsvpn-winn3-descriptor/v1\x00" + raw, work)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        return base64.b64encode(raw).decode(), base64.b64encode(sig).decode()

    def adopt_g1(self, slug, seq, *, confirm=True, allowance=None):
        """STEP-13 hub half: store the slug's g1 descriptor through the REAL
        POST /admin/nodes/winn3/descriptor, then the signer's own reconcile
        CLI rebuilds the ledger from it (3.12), and confirm lowers the gate."""
        payload, sig = self.g1_descriptor(slug, seq)
        status_code, body = self.http("POST", "/admin/nodes/winn3/descriptor", admin=True,
                                      form={"slug": slug, "enabled": "true", "descriptor_payload_b64": payload,
                                            "descriptor_sig_b64": sig})
        if status_code != 200:
            return {"ok": False, "stored_status": status_code, "detail": body.get("detail")}
        env_file = self.state / "hub.env"
        write_private(env_file, "".join(f"WINN3_DESCRIPTOR_PUBKEY_{s.upper()}={self.env['WINN3_DESCRIPTOR_PUBKEY_' + s.upper()]}\n"
                                        for s in SLOTS))
        reconcile = self.signer_cli("reconcile", "--db", self.env["DATABASE_PATH"], "--env-file", str(env_file),
                                    "--digest", str(self.dirs["signer-digest"] / "latest.json"))
        out = {"ok": reconcile["rc"] == 0, "stored_status": status_code, "reconcile_rc": reconcile["rc"],
               "reconcile_error": reconcile["stderr"].strip()[-300:] if reconcile["rc"] else ""}
        if reconcile["rc"] == 0 and confirm:
            args = ["--allowance", str(allowance)] if allowance is not None else []
            confirmed = self.signer_cli("confirm", *args)
            out.update(confirm_rc=confirmed["rc"], ok=confirmed["rc"] == 0)
        record = self.ledger()["slugs"].get(slug) or {}
        live = [item for item in record.get("issuances", []) if not item["superseded"]]
        out.update(ledger_state=record.get("state"), ledger_floor=record.get("floor"),
                   ledger_live_seq=max((item["seq"] for item in live), default=None),
                   ledger_live_kid=(max(live, key=lambda i: i["seq"])["kid"] if live else None),
                   ticket_epoch=self.signer_epoch(), hub_floor=self.retained_floor(slug))
        return out

    # ----------------------------------------------------- proofs, sweep --
    def heartbeat(self, slug, status="online"):
        return self.http("POST", "/api/v1/nodes/heartbeat",
                         json_body={"slug": slug, "secret_token": self.node_token(slug), "status": status})[0]

    def arm(self, wait_budget=False):
        """Authority recovery through the real reconcile pass (enter, read
        back, then complete), node read-backs answered by the node transport.
        A read-back counts once the gateway refresh allowance has passed
        (WINN3_GATEWAY_REFRESH_SECONDS, 2 s), so real time is waited out."""
        with self.activated():
            for attempt in range(4):
                self.mod.reconcile_winn3_authority_ledger()
                with self.mod.get_db() as conn:
                    view = self.mod.winn3_recovery_state(conn)
                if view.get("paired") and view.get("complete") and view.get("budget_trusted"):
                    break
                if attempt < 3:
                    time.sleep(float(self.mod.WINN3_GATEWAY_REFRESH_SECONDS) + 0.25)
            advanced = 0.0
            if wait_budget and view.get("paired") and view.get("complete") and not view.get("budget_trusted"):
                # Time passing, not a shortcut: the shared clock (hub, probe
                # writers, signer) moves to the hub's own budget_trusted_after.
                advanced = max(0.0, float(view["budget_trusted_after"]) - self.clock.time()) + 1.0
                self.advance(advanced)
                self.mod.reconcile_winn3_authority_ledger()
                with self.mod.get_db() as conn:
                    view = self.mod.winn3_recovery_state(conn)
        return {"paired": bool(view.get("paired")), "complete": bool(view.get("complete")),
                "budget_trusted": bool(view.get("budget_trusted")), "clock_advanced_s": advanced}

    def probe_run(self, slug, verdicts):
        with self.activated(), self.db() as conn:
            return self.probe.apply_verdicts(conn, slug, *[(verdicts.get(name, "unconfigured"), "hub-lite recorded")
                                                           for name in ("udp", "stealth", "stealth_tls")])

    def carry(self, slug, transport, verdict):
        row = self.row(slug)
        observed = self.clock.now_utc().replace(tzinfo=None).isoformat()
        if verdict == "stale":
            completed = self.mod.parse_iso_datetime(row["deployment_completed_at"])
            observed = (completed - timedelta(seconds=1)).replace(tzinfo=None).isoformat()
            verdict = "reachable"
        mapped = {"ok": "reachable", "fail": "unreachable"}.get(verdict, verdict)
        with self.activated(), self.db() as conn:
            snapshot = self.probe.carry_snapshot(conn.execute("SELECT * FROM nodes WHERE slug=?", (slug,)).fetchone())
            return self.probe.apply_carry_verdict(conn, slug, transport, mapped, observed, snapshot)

    def canary_result(self, slug, verdict="ok"):
        mod = self.mod
        row = self.row(slug)
        checked = self.clock.now_utc()
        if verdict == "stale":
            checked = mod.parse_iso_datetime(row["deployment_completed_at"]).replace(tzinfo=timezone.utc) - timedelta(seconds=1)
        with self.activated():
            binding = mod.winn3_result_binding(row)
            result = {"slug": slug, "status": "ok" if verdict in ("ok", "stale") else "fail",
                      "detail": "" if verdict != "fail" else "hub-lite recorded failure",
                      "checked_at": checked.isoformat(), **binding}
            with mod.get_db() as conn:
                return mod.ingest_winn3_canary_result(conn, result, slug)

    def sweep(self, slug=None, *, probe_runs=None, reachability=None, carry=None, canary="ok",
              offnode="healthy", heartbeat=True, wait_budget=False):
        """One real go-live sweep with the proofs the prober, the carrying
        canary, the v3 canary and the node-side check would have produced.
        Order: heartbeat, authority recovery, a first sweep (the arm's
        baseline look), N recorded prober runs, carry and canary results,
        then the real auto_reopen_health_closed_nodes."""
        slugs = [slug] if slug else [s for s in self.node_slugs() if self.row(s)]
        for name in slugs:
            self.set_node_plan(name, offnode=offnode)
            if heartbeat:
                self.heartbeat(name)
        armed = self.arm(wait_budget=wait_budget)
        if armed["clock_advanced_s"] and heartbeat:
            for name in slugs:
                self.heartbeat(name)
        with self.activated():
            first = self.mod.auto_reopen_health_closed_nodes()
        runs = self.mod.NODE_AUTO_REOPEN_PROOFS if probe_runs is None else probe_runs
        for name in slugs:
            plan = self.mod.node_promotion_transport_plan(self.row(name))
            reach = {transport: ("reachable" if plan.get(transport) is not None else "unconfigured")
                     for transport in ("udp", "stealth", "stealth_tls")}
            reach.update(reachability or {})
            for _ in range(runs):
                if heartbeat:
                    self.heartbeat(name)
                self.probe_run(name, reach)
            wanted = {"udp": "ok"}
            for transport in ("stealth", "stealth_tls"):
                if plan.get(transport) is not None:
                    wanted[transport] = "ok"
            wanted.update(carry or {})
            for transport, verdict in wanted.items():
                if verdict != "none":
                    self.carry(name, transport, verdict)
            if canary != "none":
                self.canary_result(name, canary)
        with self.activated():
            result = self.mod.auto_reopen_health_closed_nodes()
        return {"armed": armed, "first_pass_held": sorted(first.get("held", {})),
                "reopened": result.get("reopened", []), "held": result.get("held", {}),
                "probe_runs": runs}

    # ------------------------------------------------------------ status --
    def status(self, slug):
        row = self.row(slug)
        if row is None:
            return {"ok": False, "error": "node-not-found"}
        descriptor = None
        with self.activated():
            descriptor = self.mod.winn3_stored_descriptor(row, clock_tolerant=True) if row["winn3_descriptor_json"] else None
        with self.db() as conn:
            promotion = conn.execute("SELECT * FROM node_promotion_events WHERE slug=? ORDER BY promoted_at DESC "
                                     "LIMIT 1", (slug,)).fetchone()
            promotions = conn.execute("SELECT COUNT(*) FROM node_promotion_events WHERE slug=?", (slug,)).fetchone()[0]
        return {"ok": True, "slug": slug,
                "operator_enabled": row["operator_enabled"], "protocol_version": row["protocol_version"],
                "carrier_classes": row["carrier_classes"], "deployment_generation": row["deployment_generation"],
                "deployment_released_at": row["deployment_released_at"],
                "deployment_completed_at": row["deployment_completed_at"],
                "health_closed_reason": row["health_closed_reason"], "latch_cause": row["latch_cause"],
                "winn3_operator_hold": row["winn3_operator_hold"], "management_status": row["management_status"],
                "free_access_enabled": row["free_access_enabled"],
                "descriptor_seq": descriptor.get("seq") if descriptor else None,
                "descriptor_kid": descriptor.get("kid") if descriptor else None,
                "retained_floor": self.retained_floor(slug),
                "promotion_count": promotions,
                "latest_promotion_source": promotion["operator_source_hash"] if promotion else None,
                "latest_promotion_tier": promotion["tier"] if promotion else None}

    def advance(self, seconds):
        offset = self.clock.offset() + float(seconds)
        write_private(self.state / "clock_offset", f"{offset}\n")
        return {"ok": True, "clock_offset_s": offset}


# ------------------------------------------------------- signer process --

def signer_process(argv) -> int:
    """`hub_lite.py _signer --state DIR serve --fd N` or `... cli MODE ARGS`.
    Standard library only; loads the extracted signer and checks its digest."""
    import importlib.util
    if len(argv) < 3 or argv[0] != "--state" or argv[2] not in ("serve", "cli"):
        sys.stderr.write("usage: hub_lite.py _signer --state DIR serve --fd N | cli MODE [ARGS]\n")
        return 2
    args = types.SimpleNamespace(state=argv[1], what=argv[2], fd=None, rest=argv[3:])
    if args.what == "serve":
        if len(argv) != 5 or argv[3] != "--fd" or not argv[4].isdigit():
            sys.stderr.write("usage: hub_lite.py _signer --state DIR serve --fd N\n")
            return 2
        args.fd = int(argv[4])
    state = Path(args.state)
    signer_dir = state / "signer"
    program = signer_dir / "wins_descriptor_signer.py"
    text = program.read_text(encoding="utf-8")
    if sha256_text(text) != (signer_dir / "program.sha256").read_text().strip():
        sys.stderr.write("hub-lite signer: program digest mismatch\n")
        return 2
    spec = importlib.util.spec_from_file_location("wins_descriptor_signer", program)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.CONFIG_DIR, mod.STATE_DIR = str(signer_dir / "config"), str(signer_dir / "state")
    mod.WORK_DIR, mod.DIGEST_DIR = str(signer_dir / "work"), str(signer_dir / "digest")
    mod.HUB_KEY_HISTORY = str(signer_dir / "hub-key-history")
    mod.OPERATOR_SSH_KEYS = str(signer_dir / "operator-ssh-keys")
    mod.DEFAULT_HUB_DB = str(state / "vpn_users.db")
    mod.DEFAULT_DIGEST_FILE = str(signer_dir / "digest" / "latest.json")
    # The Ed25519-capable openssl and the ssh-keygen the parent resolved
    # (H1's toolchain check): the signer's own run_tool calls them by path.
    mod.OPENSSL = os.environ["HUBLITE_OPENSSL"]
    mod.SSH_KEYGEN = os.environ["HUBLITE_SSH_KEYGEN"]
    offset_file = state / "clock_offset"

    def clock():
        try:
            return time.time() + float(offset_file.read_text().strip() or 0)
        except (OSError, ValueError):
            return time.time()
    mod.CLOCK = clock
    mod.cli_is_root = lambda: True
    mod.signer_user_ids = lambda: (os.getuid(), os.getgid())
    # root:<signer group> and wins-desc-signer ownership: the invoking user owns everything here.
    mod.cli_chown = lambda fd, owner: os.fchown(fd, os.getuid(), os.getgid())
    hub_pid = int(os.environ.get("HUBLITE_HUB_PID", "0") or 0)

    def peer_is_hub(conn):
        try:
            if sys.platform == "darwin":
                pid = struct.unpack("i", conn.getsockopt(0, 2, 4))[0]          # SOL_LOCAL, LOCAL_PEERPID
                uid = struct.unpack_from("I", conn.getsockopt(0, 1, 76), 4)[0]  # LOCAL_PEERCRED xucred.cr_uid
            else:
                pid, uid, _gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        except OSError:
            return False
        return uid == os.geteuid() and pid > 0 and pid == hub_pid
    mod.peer_is_hub = peer_is_hub
    if args.what == "cli":
        return int(mod.main(["wins_descriptor_signer.py", *args.rest]) or 0)
    parent = os.getppid()

    def watchdog():
        while os.getppid() == parent:
            time.sleep(0.5)
        os._exit(0)
    threading.Thread(target=watchdog, daemon=True).start()
    if args.fd != 3:
        os.dup2(args.fd, 3)
        os.close(args.fd)
    os.environ["LISTEN_PID"] = str(os.getpid())
    os.environ["LISTEN_FDS"] = "1"
    return int(mod.main(["wins_descriptor_signer.py", "serve"]) or 0)


# ------------------------------------------------------------------- CLI --

def _emit(obj) -> int:
    print(json.dumps(obj, sort_keys=True, default=str))
    return 0 if obj.get("ok", True) is not False else 1


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "_signer":
        return signer_process(argv[1:])
    try:
        return _main(argv)
    except HubLiteError as exc:
        return _emit({"ok": False, "error": str(exc)})


def _main(argv) -> int:
    parser = argparse.ArgumentParser(prog="hub_lite.py", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add(name, **kw):
        p = sub.add_parser(name, **kw)
        p.add_argument("--state", required=True)
        return p
    p = add("init")
    p.add_argument("--cp-installer", default=str(CP_INSTALLER))
    p.add_argument("--endpoint-pin-workaround", action="store_true", help="DEVIATIONS HL-D1 (answers FINDINGS HL-F1)")
    p = add("node")
    p.add_argument("--slug", required=True)
    p.add_argument("--installer-sha256")
    p.add_argument("--pulled-identity", help="JSON file: identity, identity_sig, admission_secret, detected_public_ip")
    p.add_argument("--fresh-machine", action="store_true", help="new host key and gateway identity (provider reset)")
    p.add_argument("--endpoint-ip", help="default: the next free 203.0.113.x for a new slug")
    p.add_argument("--stealth", choices=("tls", "plain"),
                   help="also advertise stealth: tls (80:none,443:tls, served as stealth_tls) or plain (80:none)")
    p = add("ticket")
    p.add_argument("--slug", required=True)
    p.add_argument("--action", required=True, choices=("new", "reset", "endpoint", "rekey", "suspend", "unsuspend"))
    p.add_argument("--go-live", default="auto", choices=("auto", "manual"))
    p.add_argument("--tier", default="free", choices=("free", "premium"))
    p = add("complete-fresh")
    p.add_argument("--slug", required=True)
    p.add_argument("--installer-sha256")
    p = add("provision")
    p.add_argument("--slug", required=True)
    p.add_argument("--pre-sign", default="ok", choices=("ok", "fail"))
    p.add_argument("--served", default="ok", choices=("ok", "fail"))
    p = add("sweep")
    p.add_argument("--slug")
    p.add_argument("--probe-runs", type=int)
    p.add_argument("--carry", default="{}", help='JSON, e.g. {"udp":"ok"}; values ok, fail, stale, none')
    p.add_argument("--canary", default="ok", choices=("ok", "fail", "stale", "none"))
    p.add_argument("--offnode", default="healthy", help="healthy, fail, missing or file:PATH")
    p.add_argument("--wait-budget", action="store_true",
                   help="advance the shared clock to the hub's budget_trusted_after (FINDINGS HL-F2)")
    p = add("probe")
    p.add_argument("--slug", required=True)
    for transport in ("udp", "stealth", "stealth_tls"):
        p.add_argument("--" + transport.replace("_", "-"),
                       choices=("reachable", "unreachable", "probe_error", "unconfigured"),
                       help="default: reachable when the transport is offered, else unconfigured")
    p = add("rerun")
    p.add_argument("--slug", required=True)
    p.add_argument("--new-gateway-keys", action="store_true")
    p.add_argument("--installer-sha256")
    for name in ("hold", "unhold", "withhold", "status"):
        add(name).add_argument("--slug", required=True)
    for name in ("suspend", "unsuspend"):
        add(name).add_argument("--slug", required=True)
    p = add("request")
    p.add_argument("--slug", required=True)
    p.add_argument("--verb", required=True, choices=("sign", "rekey", "renew"))
    p = add("adopt-g1")
    p.add_argument("--slug", required=True)
    p.add_argument("--seq", type=int, required=True)
    p.add_argument("--no-confirm", action="store_true")
    p.add_argument("--allowance", type=int)
    p = add("advance")
    p.add_argument("--seconds", type=float, required=True)
    p = add("serve")
    p.add_argument("--listen", default="127.0.0.1:8000")
    p.add_argument("--tls-cert")
    p.add_argument("--tls-key")
    p.add_argument("--allow-nonloopback", action="store_true")
    args = parser.parse_args(argv)

    if args.cmd == "serve":
        host, _, port = args.listen.rpartition(":")
        import ipaddress
        try:
            loopback = ipaddress.ip_address(host.strip("[]")).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if not loopback and not args.allow_nonloopback:
            return _emit({"ok": False, "error": "refusing a non-loopback listen without --allow-nonloopback"})
    if args.cmd == "init":
        hub = HubLite(args.state, args.cp_installer, init=True,
                      endpoint_pin_workaround=args.endpoint_pin_workaround)
        try:
            return _emit({"ok": True, "state": str(hub.state), "extracted": hub.extracted,
                          "replacements": [[old, n] for old, n in hub.replacements_applied],
                          "active_slot": hub.manifest["active_slot"], "ticket_epoch": hub.signer_epoch(),
                          "admin_token_file": str(hub.state / "admin_token"),
                          "deviations": hub.manifest["deviations"],
                          "ledger_slugs": len(hub.ledger()["slugs"])})
        finally:
            hub.close()
    hub = HubLite(args.state, start_signer=args.cmd not in ("status", "advance"))
    try:
        if args.cmd == "node":
            return _emit(hub.node(args.slug, installer_sha256=args.installer_sha256,
                                  pulled_file=args.pulled_identity, fresh_machine=args.fresh_machine,
                                  endpoint_ip=args.endpoint_ip, stealth=args.stealth))
        if args.cmd == "ticket":
            minted = hub.ticket(args.slug, args.action, go_live=args.go_live, tier=args.tier)
            return _emit({"ok": minted.get("posted_status") == 200, "slug": args.slug,
                          "action": args.action, "nonce": minted["fields"]["nonce"],
                          "epoch": minted["fields"]["epoch"], "go_live": args.go_live, "tier": args.tier,
                          "not_after": minted["fields"]["not_after"], "posted_status": minted.get("posted_status"),
                          "detail": (minted.get("posted") or {}).get("detail")})
        if args.cmd == "complete-fresh":
            out = hub.complete_fresh(args.slug, args.installer_sha256)
            return _emit(dict(out, ok=out["status_code"] == 200 and out["body"].get("ok") is True))
        if args.cmd == "provision":
            out = hub.provision(args.slug, pre_sign=args.pre_sign, served=args.served)
            return _emit(dict(out, ok=bool(out["result"].get("ok")), status=hub.status(args.slug)))
        if args.cmd == "sweep":
            out = hub.sweep(args.slug, probe_runs=args.probe_runs, carry=json.loads(args.carry),
                            canary=args.canary, offnode=args.offnode, wait_budget=args.wait_budget)
            if args.slug:
                out["status"] = hub.status(args.slug)
            return _emit(dict(out, ok=True))
        if args.cmd == "probe":
            plan = hub.mod.node_promotion_transport_plan(hub.row(args.slug))
            verdicts = {t: (getattr(args, t) or ("reachable" if plan.get(t) is not None else "unconfigured"))
                        for t in ("udp", "stealth", "stealth_tls")}
            return _emit(dict(hub.probe_run(args.slug, verdicts), ok=True, verdicts=verdicts))
        if args.cmd == "rerun":
            return _emit(hub.rerun(args.slug, new_gateway_keys=args.new_gateway_keys,
                                   installer_sha256=args.installer_sha256))
        if args.cmd in ("hold", "unhold"):
            return _emit(hub.hold(args.slug, enabled_hold=args.cmd == "hold"))
        if args.cmd == "withhold":
            return _emit(hub.withhold(args.slug))
        if args.cmd in ("suspend", "unsuspend"):
            return _emit(hub.signer_state_verb(args.slug, args.cmd))
        if args.cmd == "request":
            return _emit(hub.signer_request(args.slug, args.verb))
        if args.cmd == "adopt-g1":
            return _emit(hub.adopt_g1(args.slug, args.seq, confirm=not args.no_confirm, allowance=args.allowance))
        if args.cmd == "status":
            return _emit(hub.status(args.slug))
        if args.cmd == "advance":
            return _emit(hub.advance(args.seconds))
        if args.cmd == "serve":
            import uvicorn
            host, _, port = args.listen.rpartition(":")
            kwargs = {"host": host.strip("[]"), "port": int(port), "lifespan": "off", "log_level": "warning"}
            if args.tls_cert or args.tls_key:
                kwargs.update(ssl_certfile=args.tls_cert, ssl_keyfile=args.tls_key)
            print(json.dumps({"ok": True, "serving": args.listen, "tls": bool(args.tls_cert)}), flush=True)
            with hub.activated():
                uvicorn.run(hub.mod.app, **kwargs)
            return 0
    finally:
        hub.close()
    return 2


if __name__ == "__main__":
    sys.exit(main())
