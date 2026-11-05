#!/usr/bin/env python3
"""A stand-in native-messaging host, for verification only.

THIS IS NOT THE SHIPPING HOST. The real one is `bin/wins_bridge_host.dart` on
the desktop side and `lib/browser_bridge_protocol.dart` is the normative
contract. This file exists so the extension's native-messaging path can be
exercised for real in a browser, with the tunnel state driven from a JSON file
rather than from an app that would have to be connected.

It implements the same shapes, so a divergence between the two shows up here as
a failing verification run rather than in the field:

  * length-prefixed JSON framing on stdin/stdout
  * `{v, id, type, ok, ...}` replies, `{v, id, type:"error", error:"<code>"}`
  * the status snapshot at the top level of the reply
  * `issue_proxy_credential` returning a token and one or two ports and NO HOST
  * proxy is plaintext only (webRequest), no TLS. See ruling 2026-08-07.

That last one is the property the whole design rests on. There is no host field
in this file because there is no host field in the contract: the extension
supplies loopback itself, so no message from any host -- this one, the real one,
or a hostile replacement -- can point a browser at a routable address.

-------------------------------------------------------------------------------
AND THE STAND-IN CARRIES THE TEST THAT KEEPS IT FROM DRIFTING
-------------------------------------------------------------------------------

    python3 dev_bridge.py --contract-check [--host <compiled wins_bridge_host>]

On 2026-08-07 the real compiled host was found to have nested the status
snapshot where the extension reads it flat, so the real host and the real
extension could not interoperate on any browser. It had been true for as long as
the bridge had existed and nobody could see it, because every verification run
in this tree used THIS FILE and this file was correct.

The lesson is not "the stand-in was wrong". It is that a stand-in faithful
enough to test against is faithful enough to hide a divergence in the thing it
stands in for, and that nothing was ever comparing the two. So:

  * CONTRACT_SCRIPT below is a shared fixture -- every request type, every
    field, and the malformed cases -- written once and asserted against BOTH
    implementations, so a change to either one has to be made twice on purpose.
  * with `--host`, the two are driven side by side over the same stdio protocol
    with the same state file and their replies compared field by field. Only
    the fields in VARIABLE_FIELDS may differ, each with a reason.

It runs as a gate in `build.py`, which requires the real host (`require=True`):
a build that could not produce one is refused, never noted-and-passed. Standalone
runs of this file without `--host` still run the fixture half alone, which is
what keeps this file honest in a checkout that has no Dart toolchain.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import shutil
import struct
import subprocess
import sys
import threading
import time

PROTOCOL_VERSION = 1
# `ProxyCredential.generate`'s default ttl, in seconds. The real host reports
# the remaining time, which is this minus the moment of asking; the contract
# check treats the field as variable for that reason.
CREDENTIAL_TTL_SECONDS = 8 * 60 * 60
STATE_PATH = os.environ.get("WV_BRIDGE_STATE", "")
LOG_PATH = os.environ.get("WV_BRIDGE_LOG", "")
TOKEN_PATH = os.environ.get("WV_BRIDGE_TOKEN", "")

# Verification only. When set, the credential reply carries an extra `host`
# field naming a routable address, to prove the extension ignores it. The real
# contract has no host field at all; this is a hostile host, simulated.
INJECT_HOST = os.environ.get("WV_BRIDGE_INJECT_HOST", "")

_write_lock = threading.Lock()

# End of stream, as distinct from a frame whose JSON value happens to be null.
# Conflating the two is how a single four-byte `null` frame used to terminate
# this bridge. (Contract diff 2026-08-07, case I.)
EOF = object()

# `Platform.operatingSystem` on the desktop side. Named here so the two halves
# emit the same token for the same machine rather than each inventing one.
OPERATING_SYSTEM = {
    "darwin": "macos", "linux": "linux", "win32": "windows",
}.get(sys.platform, sys.platform)

_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")

# The desktop side's guard, in the same shape. `lib/browser_bridge_protocol.dart`
# refuses to serialise an outbound message carrying anything address-shaped, at
# the single choke point every byte passes through. This file had no equivalent,
# so a state file with an address in a node name produced a message the real host
# would have suppressed. (Contract diff 2026-08-07, cases K and L.)
_IPV4 = re.compile(
    r"(?<![\w.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?![\w.])")
_IPV6 = re.compile(r"(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F]{0,4}|::[0-9a-fA-F]{1,4}")
_HOSTNAME = re.compile(
    r"(?<![\w.])[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61})*"
    r"\.(?:com|net|org|io|dev|xyz|co|us|uk|ru|cn|sg|jp|de|fr|nl|info|top|site)(?![\w])")
_SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
MAX_OUTBOUND_INTEGER = 1 << 24


def contains_address_literal(value: str) -> bool:
    return bool(_IPV4.search(value) or _IPV6.search(value) or _HOSTNAME.search(value))


def assert_outbound_is_address_free(message, path="$") -> None:
    """Refuse to emit an address. Structural, over the decoded tree."""
    if message is None or isinstance(message, bool):
        return
    if isinstance(message, int):
        if abs(message) > MAX_OUTBOUND_INTEGER:
            raise ValueError(f"{path}: integer {message} is wide enough to carry an address")
        return
    if isinstance(message, str):
        if contains_address_literal(message):
            raise ValueError(f"{path}: string value is address-shaped")
        return
    if isinstance(message, list):
        for i, item in enumerate(message):
            assert_outbound_is_address_free(item, f"{path}[{i}]")
        return
    if isinstance(message, dict):
        for key, value in message.items():
            if not isinstance(key, str):
                raise ValueError(f"{path}: non-string key {key!r}")
            if contains_address_literal(key):
                raise ValueError(f"{path}.{key}: key is address-shaped")
            assert_outbound_is_address_free(value, f"{path}.{key}")
        return
    raise ValueError(f"{path}: value of type {type(message).__name__} is outside the schema")


def sanitize_correlation_id(raw) -> str:
    """`sanitizeCorrelationId` from the normative contract, to the letter.

    Anything outside [A-Za-z0-9_-], or longer than 64 characters, is replaced
    WHOLESALE rather than trimmed -- a partially scrubbed identifier is still an
    identifier. This file used to echo whatever it was sent.
    (Contract diff 2026-08-07, case F.)
    """
    if not isinstance(raw, str) or not raw or len(raw) > 64:
        return ""
    return raw if _ID_RE.match(raw) else ""


def log(kind: str, payload) -> None:
    if not LOG_PATH:
        return
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"t": time.time(), "kind": kind, "payload": payload}) + "\n")
    except OSError:
        pass


class FramingError(Exception):
    """The length prefix and the bytes stopped agreeing. Stop reading."""


def read_message():
    """One frame, or None at end of stream.

    A frame whose bytes are not JSON raises rather than returning a value, and
    that is the contract's answer rather than a preference: a length-prefixed
    stream whose payload will not parse is a stream whose framing may already
    have desynchronised, and continuing to read one is how a bad length leads a
    parser off the end of everything after it. The real host closes the
    connection on exactly this and says so on stderr.

    This used to return `{}` for unparseable bytes, which produced a spurious
    `unsupported_version` reply on a connection that was no longer trustworthy,
    and -- worse -- `json.loads(b"null")` returned None, which `main` read as
    end of stream. A single frame containing the four bytes `null` terminated
    the bridge. (Contract diff 2026-08-07, cases H and I.)
    """
    header = sys.stdin.buffer.read(4)
    if len(header) < 4:
        return EOF
    (length,) = struct.unpack("@I", header)
    if length == 0 or length > 1 << 20:
        raise FramingError(f"implausible frame length {length}")
    body = sys.stdin.buffer.read(length)
    if len(body) < length:
        return EOF
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FramingError(f"inbound frame is not UTF-8 JSON: {error}") from error


def send(message: dict) -> None:
    if not INJECT_HOST:
        # THE CHOKE POINT, matching `encodeOutboundBridgeMessage`. Refusing to
        # emit is the right failure: losing a status update is survivable,
        # leaking a hub address is not. `WV_BRIDGE_INJECT_HOST` is the one
        # deliberate exception -- a hostile host, simulated, to prove the
        # extension ignores what it is sent -- so the guard stands down only
        # under the flag whose whole purpose is to violate it.
        try:
            assert_outbound_is_address_free(message)
        except ValueError as error:
            sys.stderr.write(f"outbound message suppressed: {error}\n")
            return
    body = json.dumps(message, separators=(",", ":")).encode("utf-8")
    with _write_lock:
        sys.stdout.buffer.write(struct.pack("@I", len(body)))
        sys.stdout.buffer.write(body)
        sys.stdout.buffer.flush()
    # The token is never logged. Its length is, so a run can be checked without
    # putting the secret into a file that outlives the session.
    redacted = dict(message)
    if "token" in redacted:
        redacted["token"] = f"<redacted:{len(redacted['token'])} chars>"
    log("out", redacted)


_PAIRING_CREDENTIAL = re.compile(r"^[0-9a-f]{64}\Z")


def read_state() -> dict:
    """Read the tunnel state.

    The real host asks the desktop app. This one reads a file, and defaults to
    `app_not_running`: when the state cannot be determined, the honest answer is
    "not connected", which makes the extension fail closed. Defaulting the other
    way would make an unreadable file look like a working tunnel.
    """
    default = {
        "status": "app_not_running",
        "detail": "app_not_running",
        "winn": "unavailable_on_this_platform",
        "selectedSlug": "",
        "nodes": [],
        "canRequestConnect": False,
        "proxyPort": 0,
        "proxyReady": False,
        # Stand-in parity with the desktop host snapshot: the host reports the
        # bridged-TLS handoff fields; the extension reads them tolerantly.
        "proxyTls": False,
        "proxyTlsPort": 0,
        "rxKib": 0,
        "txKib": 0,
        # The desktop app's answer for this browser's pairing (R20 A1). The
        # stand-in, like the real host's file-backed harness, has no app to
        # approve a pairing, so it is always unpaired and a state file cannot
        # claim otherwise (the override below).
        "pairing": "unpaired",
    }
    if not STATE_PATH:
        return default
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return default
    if not isinstance(data, dict):
        return default
    out = dict(default)
    out.update({k: v for k, v in data.items() if k in default})
    out["pairing"] = "unpaired"  # never read from the file
    # NODE VALIDATION, which this file did not have.
    #
    # `BridgeNode`'s constructor on the desktop side refuses a slug outside
    # `kSlugPattern` and refuses an address-shaped display name at construction,
    # so a hostile node list cannot even build the object. This file passed the
    # state file through untouched, so the same input produced two different
    # messages -- which is the class of divergence this whole exercise is about.
    # Rejected whole, never trimmed: a partially scrubbed address is an address.
    # (Contract diff 2026-08-07, case L.)
    nodes = []
    for node in out.get("nodes") or []:
        if not isinstance(node, dict):
            continue
        slug = node.get("slug")
        name = str(node.get("name", "")).strip()
        flag = str(node.get("flag", ""))
        if not isinstance(slug, str) or not _SLUG.match(slug):
            continue
        if contains_address_literal(name) or len(flag) > 8:
            continue
        nodes.append({"slug": slug, "name": name, "flag": flag})
    out["nodes"] = nodes
    return out


class Host:
    def __init__(self) -> None:
        # 32 bytes, base64url, no padding: 43 characters, matching the desktop
        # side. Generated once per process, so it dies when the browser closes
        # the port -- which is what lets both sides refuse to persist it.
        self.token = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
        self.issued = False
        self.subscribed = False
        if TOKEN_PATH:
            # The harness pre-writes a token so the stand-in proxy and this host
            # agree on one; otherwise a fresh one is generated per process, as
            # the real host does. Either way it exists only in memory here and
            # dies when the browser closes the port.
            try:
                with open(TOKEN_PATH, "r", encoding="utf-8") as fh:
                    existing = fh.read().strip()
                if existing:
                    self.token = existing
                else:
                    raise OSError
            except OSError:
                with open(TOKEN_PATH, "w", encoding="utf-8") as fh:
                    fh.write(self.token)

    def reply(self, mid: str, kind: str, body: dict) -> None:
        send({"v": PROTOCOL_VERSION, "id": mid, "type": kind, "ok": True, **body})

    def error(self, mid: str, code: str) -> None:
        send({"v": PROTOCOL_VERSION, "id": mid, "type": "error", "ok": False, "error": code})

    def event(self, kind: str, body: dict) -> None:
        send({"v": PROTOCOL_VERSION, "id": "", "type": kind, "ok": True, **body})

    def handle(self, msg) -> None:
        if not isinstance(msg, dict):
            self.error("", "malformed")
            return
        mid = sanitize_correlation_id(msg.get("id"))
        if msg.get("v") != PROTOCOL_VERSION:
            self.error(mid, "unsupported_version")
            return

        kind = msg.get("type")
        state = read_state()

        if kind == "hello":
            # `protocolVersion` and `platform` are what make a hello a
            # handshake rather than a second get_status. The real host has
            # always sent them and this file never did.
            # (Contract diff 2026-08-07, case A.)
            self.reply(mid, "hello", {
                "protocolVersion": PROTOCOL_VERSION,
                "platform": OPERATING_SYSTEM,
                **state,
            })
        elif kind == "get_status":
            self.reply(mid, "status", state)
        elif kind == "subscribe":
            self.subscribed = True
            self.reply(mid, "status", state)
        elif kind == "unsubscribe":
            self.subscribed = False
            self.reply(mid, "status", state)
        elif kind == "issue_proxy_credential":
            if not state.get("proxyReady"):
                # No credential and no listening socket until the desktop side
                # says its gate would admit traffic. The real host used to issue
                # regardless; it no longer does.
                self.error(mid, "app_not_running")
                return
            self.issued = True
            body = {
                "token": self.token,
                "proxyPort": state.get("proxyPort", 0),
                # The second listener's port. Zero when this bridge has no TLS
                # door, which is the desktop side as it ships today.

                # The credential's own lifetime, and the state it was issued
                # against. Both are dropped by the extension, which reads only
                # the ports and the token -- they are here because the real host
                # sends them and the two messages have to be the same message.
                # (Contract diff 2026-08-07, case D.)
                "expiresInSeconds": CREDENTIAL_TTL_SECONDS,
                **state,
            }
            if INJECT_HOST:
                body["host"] = INJECT_HOST
            self.reply(mid, "proxy_credential", body)
        elif kind == "revoke_proxy_credential":
            self.issued = False
            self.reply(mid, "status", state)
        elif kind == "pair_begin":
            # No app to show the in-app confirmation: the closed vocabulary's
            # refusal, exactly as the real host answers when its state source
            # cannot pair.
            self.error(mid, "app_not_running")
        elif kind == "set_pairing":
            credential = msg.get("credential")
            if not isinstance(credential, str) or (
                credential and not _PAIRING_CREDENTIAL.match(credential)
            ):
                self.error(mid, "malformed")
                return
            self.reply(mid, "status", state)
        elif kind == "pair_forget":
            self.reply(mid, "status", state)
        elif kind in ("request_connect", "request_disconnect"):
            # A request, not a command: the desktop app owns the tunnel. The
            # answer is the resulting status, never an assumption that it took
            # -- unless there is no app to forward to, in which case there is no
            # status to render and the closed vocabulary's own refusal code is
            # the answer. (Contract diff 2026-08-07, case E.)
            if state.get("status") == "app_not_running":
                self.error(mid, "app_not_running")
            else:
                self.reply(mid, "status", state)
        else:
            self.error(mid, "unknown_request")


def main() -> int:
    host = Host()

    def pusher():
        last = None
        while True:
            time.sleep(0.4)
            if not host.subscribed:
                continue
            state = read_state()
            key = json.dumps(state, sort_keys=True)
            if key != last:
                last = key
                host.event("status", state)

    threading.Thread(target=pusher, daemon=True).start()

    while True:
        try:
            msg = read_message()
        except FramingError as error:
            sys.stderr.write(f"framing error, closing: {error}\n")
            return 0
        if msg is EOF:
            return 0
        log("in", msg)
        host.handle(msg)


# ---------------------------------------------------------------------------
# THE CONTRACT, WRITTEN DOWN ONCE
# ---------------------------------------------------------------------------

# Two tunnel states, because most of the disagreements found on 2026-08-07 were
# state-dependent and a fixture pinned to one state would have missed four of
# them. The keys are exactly the ones `read_state` knows and exactly the ones
# `FileStateSource` on the desktop side knows.
CONTRACT_STATES = {
    "app_absent": {
        "status": "app_not_running", "detail": "app_not_running",
        "winn": "unavailable_on_this_platform", "selectedSlug": "", "nodes": [],
        "canRequestConnect": False, "proxyReady": False, "proxyTls": False, "proxyTlsPort": 0,
        "rxKib": 0, "txKib": 0,
    },
    "connected_ready": {
        "status": "connected", "detail": "none",
        "winn": "unavailable_on_this_platform", "selectedSlug": "yangon",
        "nodes": [{"slug": "yangon", "name": "Yangon", "flag": "MM"},
                  # Refused by both sides, for two different reasons that must
                  # produce the same message: the slug is not a slug, and the
                  # name is address-shaped.
                  {"slug": "Not A Slug", "name": "fine", "flag": ""},
                  {"slug": "hostile", "name": "hub 198.51.100.7", "flag": ""}],
        "canRequestConnect": True, "proxyReady": True, "proxyTls": False, "proxyTlsPort": 0,
        "rxKib": 12, "txKib": 34,
    },
}

# Fields that may legitimately differ between two running implementations. Each
# needs a reason, and "the extension ignores it" is NOT one -- that is how the
# nesting defect survived. These are per-process facts, not shape.
VARIABLE_FIELDS = {
    "proxyTls": "TLS-listener handoff flag set by the desktop host; the extension "
                "reads it tolerantly and never branches on it (protocol-version note "
                "in lib/browser_bridge_protocol.dart)",
    "proxyTlsPort": "kernel-assigned bridged-TLS port reported by the host; 0 while "
                    "no TLS listener is up (absent in older hosts by design)",
    "token": "generated per process; both must produce 43 base64url characters",
    "proxyPort": "kernel-assigned ephemeral port; the real host binds, the "
                 "stand-in reports what the state file says",

    "expiresInSeconds": "the ttl minus the moment of asking",
}

# request, state, and what the reply must be. `...` marks a field whose value is
# in VARIABLE_FIELDS; `None` marks a field that must be ABSENT.
CONTRACT_SCRIPT = [
    ("hello carries the handshake and the snapshot, flat",
     "app_absent", {"v": 1, "id": "h1", "type": "hello"},
     {"type": "hello", "ok": True, "id": "h1", "protocolVersion": 1,
      "platform": OPERATING_SYSTEM, "status": "app_not_running",
      "proxyTls": ..., "proxyTlsPort": ...}),
    ("get_status is the snapshot at the top level of the reply",
     "app_absent", {"v": 1, "id": "s1", "type": "get_status"},
     {"type": "status", "ok": True, "id": "s1", "status": "app_not_running",
      "detail": "app_not_running", "proxyReady": False, "nodes": [],
      "proxyTls": ..., "proxyTlsPort": ...}),
    ("get_status carries the connected snapshot, and drops the bad nodes",
     "connected_ready", {"v": 1, "id": "s2", "type": "get_status"},
     {"type": "status", "ok": True, "id": "s2", "status": "connected",
      "detail": "none", "selectedSlug": "yangon", "canRequestConnect": True,
      "proxyReady": True, "rxKib": 12, "txKib": 34,
      "nodes": [{"slug": "yangon", "name": "Yangon", "flag": "MM"}],
      "proxyTls": ..., "proxyTlsPort": ...}),
    ("subscribe is acknowledged with a status, not a word of its own",
     "connected_ready", {"v": 1, "id": "sub", "type": "subscribe"},
     {"type": "status", "ok": True, "id": "sub", "status": "connected",
      "proxyTls": ..., "proxyTlsPort": ...}),
    ("unsubscribe likewise",
     "connected_ready", {"v": 1, "id": "uns", "type": "unsubscribe"},
     {"type": "status", "ok": True, "id": "uns", "status": "connected",
      "proxyTls": ..., "proxyTlsPort": ...}),
    ("a credential is refused while the desktop gate is shut",
     "app_absent", {"v": 1, "id": "c0", "type": "issue_proxy_credential"},
     {"type": "error", "ok": False, "id": "c0", "error": "app_not_running"}),
    ("a credential carries the token, both ports, the ttl and the snapshot",
     "connected_ready", {"v": 1, "id": "c1", "type": "issue_proxy_credential"},
     {"type": "proxy_credential", "ok": True, "id": "c1", "token": ...,
      "proxyPort": ..., "expiresInSeconds": ...,
      "status": "connected", "proxyReady": True, "host": None,
      "proxyTls": ..., "proxyTlsPort": ...}),
    ("revoke is acknowledged with a status",
     "connected_ready", {"v": 1, "id": "rv", "type": "revoke_proxy_credential"},
     {"type": "status", "ok": True, "id": "rv", "status": "connected",
      "proxyTls": ..., "proxyTlsPort": ...}),
    ("request_connect with no app to forward to is refused by code",
     "app_absent", {"v": 1, "id": "rc", "type": "request_connect"},
     {"type": "error", "ok": False, "id": "rc", "error": "app_not_running"}),
    ("request_connect with an app there answers with the resulting status",
     "connected_ready", {"v": 1, "id": "rc2", "type": "request_connect"},
     {"type": "status", "ok": True, "id": "rc2", "status": "connected",
      "proxyTls": ..., "proxyTlsPort": ...}),
    ("request_disconnect follows the same rule",
     "connected_ready", {"v": 1, "id": "rd", "type": "request_disconnect"},
     {"type": "status", "ok": True, "id": "rd", "status": "connected",
      "proxyTls": ..., "proxyTlsPort": ...}),
    ("pair_begin with no app able to confirm is refused by code",
     "connected_ready", {"v": 1, "id": "pb", "type": "pair_begin"},
     {"type": "error", "ok": False, "id": "pb", "error": "app_not_running"}),
    ("set_pairing is acknowledged with the app's unpaired status",
     "connected_ready",
     {"v": 1, "id": "sp", "type": "set_pairing", "credential": "a" * 64},
     {"type": "status", "ok": True, "id": "sp", "status": "connected",
      "pairing": "unpaired", "credential": None,
      "proxyTls": ..., "proxyTlsPort": ...}),
    ("set_pairing with a malformed credential is malformed",
     "connected_ready",
     {"v": 1, "id": "sp2", "type": "set_pairing", "credential": "NOT-HEX"},
     {"type": "error", "ok": False, "id": "sp2", "error": "malformed"}),
    ("pair_forget is acknowledged with a status",
     "connected_ready", {"v": 1, "id": "pf", "type": "pair_forget"},
     {"type": "status", "ok": True, "id": "pf", "pairing": "unpaired",
      "proxyTls": ..., "proxyTlsPort": ...}),
    ("an unknown request type is refused by code",
     "app_absent", {"v": 1, "id": "u1", "type": "nonsense"},
     {"type": "error", "ok": False, "id": "u1", "error": "unknown_request"}),
    ("a non-integer type is not a request either",
     "app_absent", {"v": 1, "id": "u2", "type": 7},
     {"type": "error", "ok": False, "id": "u2", "error": "unknown_request"}),
    ("a version this peer does not know is refused before anything else",
     "app_absent", {"v": 2, "id": "v1", "type": "hello"},
     {"type": "error", "ok": False, "id": "v1", "error": "unsupported_version"}),
    ("a version that is a string is not version 1",
     "app_absent", {"v": "1", "id": "v2", "type": "get_status"},
     {"type": "error", "ok": False, "id": "v2", "error": "unsupported_version"}),
    ("an absent version is refused",
     "app_absent", {"id": "v3", "type": "get_status"},
     {"type": "error", "ok": False, "id": "v3", "error": "unsupported_version"}),
    ("a correlation id longer than 64 characters is replaced, not trimmed",
     "app_absent", {"v": 1, "id": "a" * 80, "type": "get_status"},
     {"type": "status", "ok": True, "id": "",
      "proxyTls": ..., "proxyTlsPort": ...}),
    ("a correlation id outside [A-Za-z0-9_-] is replaced wholesale",
     "app_absent", {"v": 1, "id": "bad id!", "type": "get_status"},
     {"type": "status", "ok": True, "id": "",
      "proxyTls": ..., "proxyTlsPort": ...}),
    ("a non-string correlation id becomes empty",
     "app_absent", {"v": 1, "id": 7, "type": "get_status"},
     {"type": "status", "ok": True, "id": "",
      "proxyTls": ..., "proxyTlsPort": ...}),
    ("an absent correlation id becomes empty",
     "app_absent", {"v": 1, "type": "get_status"},
     {"type": "status", "ok": True, "id": "",
      "proxyTls": ..., "proxyTlsPort": ...}),
    ("a field neither side knows is ignored rather than echoed",
     "app_absent", {"v": 1, "id": "x1", "type": "get_status", "junk": {"a": [1, 2]}},
     {"type": "status", "ok": True, "id": "x1", "junk": None}),
]

# Frames that are not objects at all. Kept apart from the script above because
# the answer is about framing rather than about a request.
CONTRACT_FRAMES = [
    ("an array frame is malformed, and is answered", b"[1,2,3]",
     {"type": "error", "ok": False, "id": "", "error": "malformed"}),
    ("a string frame is malformed", b'"hello"',
     {"type": "error", "ok": False, "id": "", "error": "malformed"}),
    ("a number frame is malformed", b"7",
     {"type": "error", "ok": False, "id": "", "error": "malformed"}),
    # `null` is a valid JSON document and an invalid request. It must be
    # answered like any other non-object -- NOT read as end of stream, which is
    # what this file used to do and which killed the bridge outright.
    ("a null frame is malformed, and does not end the session", b"null",
     {"type": "error", "ok": False, "id": "", "error": "malformed"}),
]


def _frame(body: bytes) -> bytes:
    return struct.pack("@I", len(body)) + body


def _drive(command, state_path, frames, want_ids=None, seconds=1.2):
    """Send frames to a bridge over stdio and collect the replies."""
    import select

    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            env={**os.environ, "WV_BRIDGE_STATE": str(state_path),
                                 "WV_BRIDGE_LOG": "", "WV_BRIDGE_TOKEN": "",
                                 "WV_BRIDGE_INJECT_HOST": ""})
    replies = []
    try:
        for body in frames:
            try:
                proc.stdin.write(_frame(body))
                proc.stdin.flush()
            except (BrokenPipeError, OSError):
                replies.append({"__error": "the bridge closed its input"})
                break
            got, buf, deadline = [], b"", time.time() + seconds
            while time.time() < deadline:
                ready, _, _ = select.select([proc.stdout], [], [], 0.1)
                if not ready:
                    continue
                chunk = os.read(proc.stdout.fileno(), 65536)
                if not chunk:
                    break
                buf += chunk
                while len(buf) >= 4:
                    (n,) = struct.unpack("@I", buf[:4])
                    if len(buf) < 4 + n:
                        break
                    got.append(json.loads(buf[4:4 + n].decode("utf-8")))
                    buf = buf[4 + n:]
                if got:
                    break
            # Pick the reply to THIS request rather than the first thing that
            # arrived. A subscribed host pushes unsolicited `status` events with
            # an empty id, and one landing in the window would otherwise be read
            # as the answer to whatever was asked next.
            want = None if want_ids is None else want_ids[len(replies)]
            match = None
            if want is not None:
                match = next((g for g in got if g.get("id") == want), None)
            replies.append(match or (got[0] if got else {"__error": "no reply"}))
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=6)
        except subprocess.TimeoutExpired:
            proc.kill()
    return replies


def _compare(label, expected, got, failures, who):
    if not isinstance(got, dict):
        failures.append(f"{who}: {label}: reply was not an object: {got!r}")
        return
    if got.get("v") != PROTOCOL_VERSION:
        failures.append(f"{who}: {label}: reply carried v={got.get('v')!r}")
    for key, want in expected.items():
        if want is None:
            if key in got:
                failures.append(f"{who}: {label}: {key} must be absent, got {got[key]!r}")
            continue
        if want is ...:
            if key not in got:
                failures.append(f"{who}: {label}: {key} is required and absent")
            continue
        if got.get(key) != want:
            failures.append(
                f"{who}: {label}: {key} = {got.get(key)!r}, contract says {want!r}")


def contract_check(host_command=None, verbose=True) -> int:
    """Both implementations against the same fixture, then against each other."""
    import tempfile

    failures: list[str] = []
    work = tempfile.mkdtemp(prefix="wv-contract-")
    state_path = os.path.join(work, "state.json")
    stand_in = [sys.executable, os.path.abspath(__file__)]

    implementations = [("stand-in", stand_in)]
    if host_command:
        implementations.append(("real host", list(host_command) + ["--state-file", state_path]))

    # Grouped by state so each implementation is started once per state, which
    # is also what makes the credential cases meaningful: the real host binds
    # its listeners on the first issue and reports them from then on.
    for state_key, state in CONTRACT_STATES.items():
        cases = [c for c in CONTRACT_SCRIPT if c[1] == state_key]
        if not cases:
            continue
        with open(state_path, "w", encoding="utf-8") as fh:
            json.dump(state, fh)
        frames = [json.dumps(c[2], separators=(",", ":")).encode("utf-8") for c in cases]
        want_ids = [c[3].get("id") for c in cases]
        per_impl = {}
        for who, command in implementations:
            per_impl[who] = _drive(command, state_path, frames, want_ids)
            for (label, _, _, expected), got in zip(cases, per_impl[who]):
                _compare(label, expected, got, failures, who)
        if len(per_impl) == 2:
            a, b = per_impl["stand-in"], per_impl["real host"]
            for (label, _, _, _), left, right in zip(cases, a, b):
                for key in set(left) | set(right):
                    if key in VARIABLE_FIELDS:
                        continue
                    if left.get(key) != right.get(key):
                        failures.append(
                            f"DIVERGENCE: {label}: {key} = {left.get(key)!r} in the "
                            f"stand-in and {right.get(key)!r} in the real host. Either "
                            "one of them is wrong, or the field belongs in "
                            "VARIABLE_FIELDS with a reason.")

    with open(state_path, "w", encoding="utf-8") as fh:
        json.dump(CONTRACT_STATES["app_absent"], fh)
    frames = [f[1] for f in CONTRACT_FRAMES]
    for who, command in implementations:
        for (label, _, expected), got in zip(CONTRACT_FRAMES,
                                             _drive(command, state_path, frames)):
            _compare(label, expected, got, failures, who)

    if verbose:
        cross = " and against each other" if host_command else ""
        print(f"bridge contract: {len(CONTRACT_SCRIPT) + len(CONTRACT_FRAMES)} cases "
              f"against {len(implementations)} implementation(s){cross}")
        if not host_command:
            print("  NOTE: no compiled host given, so only the fixture half ran. "
                  "The cross-check is what catches a divergence the fixture does "
                  "not already name.")
    for line in failures:
        print(f"  FAIL {line}")
    if not failures and verbose:
        print("  ok")
    return 1 if failures else 0


class RealHostUnavailable(RuntimeError):
    """The real compiled host could not be produced, with the reason."""


def _host_build_inputs(host_pkg: str) -> list[str]:
    """Return every local input whose change invalidates the host executable."""
    inputs = [
        os.path.join(host_pkg, "pubspec.yaml"),
        os.path.join(host_pkg, "pubspec.lock"),
        os.path.join(host_pkg, ".dart_tool", "package_config.json"),
    ]
    overrides = os.path.join(host_pkg, "pubspec_overrides.yaml")
    if os.path.exists(overrides):
        inputs.append(overrides)
    for source_dir in ("bin", "lib"):
        source_root = os.path.join(host_pkg, source_dir)
        if not os.path.isdir(source_root):
            continue
        for root, _dirs, names in os.walk(source_root):
            inputs.extend(
                os.path.join(root, name)
                for name in names
                if name.endswith(".dart")
            )
    return inputs


def find_real_host(quiet: bool = False, require: bool = False) -> list | None:
    """The real host, compiled, if this checkout can produce one.

    WHICH BINARY, AND WHY IT IS NOT THE SHIPPING ONE. The shipping entry point
    uses `AppIpcStateSource`: authenticated IPv4-loopback IPC with the desktop
    app, fail-closed to `app_not_running`. A contract fixture cannot drive that
    source through connected/proxy-ready states without a running app, so every
    state-dependent case would be untestable against the shipping binary.

    The cross-check compiles `bin/wins_bridge_host_harness.dart`, which is the
    shipping host with a file-backed state source substituted for that one
    field and NOTHING else changed: the same `BridgeHost`, the same dispatch,
    the same `BridgeStatus.toWire`, the same outbound guard, the same framing.
    Everything this fixture asserts lives in that shared code. The shipping
    binary is still what `build_native_host.sh` compiles.

    Cached on every host compile input: Dart sources, pubspec/lock, resolver
    overrides, and package metadata. This prevents a stale executable from
    crossing the release gate after a source or dependency-resolution change.

    A fresh clone has no `.dart_tool/package_config.json`, so the package is
    resolved first: `dart pub get --offline --enforce-lockfile` (the lockfile is tracked, and an
    offline resolve can only draw on the cache the machine already holds),
    falling back to an online resolve only if the offline one fails.

    `require=True` is the build gate's mode: every "could not produce a host"
    outcome raises `RealHostUnavailable` instead of printing a NOTE and
    returning None. A package produced without the real-host cross-check is not
    a package this project ships, so the gate must fail, not note and pass.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    host_pkg = os.path.normpath(os.path.join(
        here, "..", "..", "tools", "native_messaging", "host"))
    source = os.path.join(host_pkg, "bin", "wins_bridge_host_harness.dart")
    shared = os.path.join(host_pkg, "bin", "wins_bridge_host.dart")
    if not (os.path.exists(source) and os.path.exists(shared)):
        if require:
            raise RealHostUnavailable(
                f"host source is missing: {source} or {shared}")
        return None
    out = os.path.join(host_pkg, "build", "wins_bridge_host_contract")
    if not shutil.which("dart"):
        if not quiet and not require:
            print("  NOTE: no `dart` on PATH, so the real host could not be built "
                  "for the cross-check")
        if require:
            raise RealHostUnavailable("no `dart` on PATH")
        return None
    package_config = os.path.join(host_pkg, ".dart_tool", "package_config.json")
    manifest = os.path.join(host_pkg, "pubspec.yaml")
    lockfile = os.path.join(host_pkg, "pubspec.lock")
    needs_resolve = not os.path.exists(package_config)
    if not needs_resolve:
        newest_manifest = max(os.path.getmtime(manifest), os.path.getmtime(lockfile))
        needs_resolve = os.path.getmtime(package_config) < newest_manifest
    if needs_resolve:
        offline = subprocess.run(
            ["dart", "pub", "get", "--offline", "--enforce-lockfile"],
            cwd=host_pkg, capture_output=True, text=True)
        if offline.returncode != 0:
            online = subprocess.run(
                ["dart", "pub", "get", "--enforce-lockfile"],
                cwd=host_pkg, capture_output=True, text=True)
            if online.returncode != 0:
                detail = (online.stdout + online.stderr)[:600]
                if require:
                    raise RealHostUnavailable(
                        "`dart pub get` failed offline and online:\n" + detail)
                print("  NOTE: the host package could not be resolved, so the "
                      f"cross-check could not run:\n{detail}")
                return None
    build_inputs = _host_build_inputs(host_pkg)
    missing_inputs = [path for path in build_inputs if not os.path.isfile(path)]
    if missing_inputs:
        detail = ", ".join(missing_inputs)
        if require:
            raise RealHostUnavailable(f"host build input is missing: {detail}")
        if not quiet:
            print(f"  NOTE: host build input is missing: {detail}")
        return None
    newest = max(os.path.getmtime(path) for path in build_inputs)
    if os.path.exists(out) and os.path.getmtime(out) >= newest:
        return [out]
    os.makedirs(os.path.dirname(out), exist_ok=True)
    built = subprocess.run(
        ["dart", "compile", "exe", "bin/wins_bridge_host_harness.dart", "-o", out],
        cwd=host_pkg, capture_output=True, text=True)
    if built.returncode != 0:
        detail = (built.stdout + built.stderr)[:600]
        if require:
            raise RealHostUnavailable(
                "the real host would not compile:\n" + detail)
        print("  NOTE: the real host would not compile, so the cross-check could "
              f"not run:\n{detail}")
        return None
    return [out]


if __name__ == "__main__":
    if "--contract-check" in sys.argv:
        ap = argparse.ArgumentParser()
        ap.add_argument("--contract-check", action="store_true")
        ap.add_argument("--host", default=None)
        parsed = ap.parse_args()
        host = [parsed.host] if parsed.host else find_real_host()
        sys.exit(contract_check(host))
    try:
        sys.exit(main())
    except (BrokenPipeError, KeyboardInterrupt):
        sys.exit(0)
