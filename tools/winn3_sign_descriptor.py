#!/usr/bin/env python3
"""Offline signing primitive for a winn/3 standalone gateway descriptor.

WHY THIS FILE EXISTS. The hub app holds NO descriptor signing key and cannot
read one: the active slot's private key lives in the separate signer service
(wins-descriptor-signer), which signs only within policy.
New or changed identities require the matching unused t1 ticket and the
node's signed identity. Renewal uses the retained identity within its renewal
window and per-slug limit. Normal fleet quotas apply except for ticketed
issuances spending an operator-granted recovery allowance.

`/admin/*` is one fleet-wide shared token, and a forged descriptor is not
defacement -- it is an attacker's
static key, admission secret and endpoint delivered to a client as authentic.
So a leaked admin token must be able to WITHHOLD gateway material and never
to MINT it outside that policy.

This file is the OFFLINE path, kept for the ceremonies that are deliberately
offline: the g1 emergency re-signs (tools/mint_and_register_winn3_descriptors.py
drives this file for them) and any operator ceremony. It is not the hub's
normal signing path; the signer service is. Until this file existed nothing in
the tree performed offline signing: `docs/WINN3_GATEWAY_DEPLOYMENT_RUNBOOK_
20260812.md` section 8 carried an explicit "UNVERIFIED: the exact signing
procedure ... was not established from this tree".

WHAT IT SIGNS, and every byte of it is derived from the two verifiers rather
than from a specification:

  message  = WINN3_DESCRIPTOR_DOMAIN || 0x00 || payload
  domain   = b"winsvpn-winn3-descriptor/v1"
  payload  = the UTF-8 JSON bytes, verbatim

  hub    -- server/wins_control_plane_setup_ONETOUCH.sh,
            `winn3_verify_descriptor_signature`:
                message = WINN3_DESCRIPTOR_DOMAIN + b"\\x00" + payload
  client -- lib/winn_protocol_dispatch.dart, `verifyWinn3Descriptor`:
                message = utf8(kWinn3DescriptorDomain) + 0x00 + payloadBytes

THE SIGNED BYTES ARE THE PAYLOAD BYTES VERBATIM. The hub stores
`{"payload": <b64 as uploaded>, "sig": <b64>}` and never re-serialises the JSON,
and the client verifies the bytes it decodes from that same envelope. Neither
side imposes a canonical JSON form, so the SIGNER's serialisation is the only
one that exists. This file uses `sort_keys=True, separators=(",", ":"),
ensure_ascii=False` -- the form tools/winn3_sign_announcement.py uses and
`envelope_for` uses in server/test_winn3_descriptor_hub.py -- so that re-signing
the same inputs reproduces the same bytes.

THE PRIVATE KEY. It is passed BY PATH and is never read, printed, logged,
copied, or written anywhere by this script. openssl(1) opens it directly. There
is deliberately NO key-generation mode here: the project rule for the
announcement key (now also signed offline, tools/winn3_sign_announcement.py) is
that "the private key must never be created by, or pass through, a script that
is committed to a repository", and the descriptor key
sits at a strictly larger blast radius than that one. Generate it by hand; the
runbook gives the line.

WHAT DOES GET WRITTEN. The MESSAGE handed to openssl contains the payload, and
the payload contains `admission_secret`. It is therefore written only inside a
0700 `tempfile.TemporaryDirectory()` that is removed before this process exits,
never to the working directory and never to a path that outlives the run.

Ed25519 is one-shot, so openssl needs a seekable `-in` and refuses a pipe
("unable to determine file size for oneshot operation"). Same reason the hub
writes a temp file to verify.

Usage:
  tools/winn3_sign_descriptor.py pubkey  --key <PRIVATE.pem>
  tools/winn3_sign_descriptor.py sign    --key <PRIVATE.pem> ... --prev-seq N
  tools/winn3_sign_descriptor.py sign    --help

Exit codes: 0 signed, 2 refused (bad input / seq did not increase), 3 openssl or
environment failure.
"""
import argparse
import base64
import binascii
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time

# --------------------------------------------------------------------------
# Constants. Every one is a copy of a hub constant and is checked against the
# LIVE hub module by server/test_winn3_sign_descriptor_tool.py::
# test_constants_do_not_drift_from_the_hub, in the same spirit as the hub's own
# test_core_constants_do_not_drift: a hand-maintained second copy that silently
# disagrees with the implementation is a failure this project has already had.
# --------------------------------------------------------------------------
DOMAIN = b"winsvpn-winn3-descriptor/v1"
FORMAT_VERSION = 3
KEY_SLOTS = ("g1", "g2", "g3")
ALG_ED25519 = "ed25519"
SUPPORTED_ALGS = (ALG_ED25519,)
ED25519_PUBLIC_KEY_BYTES = 32
ED25519_SIGNATURE_BYTES = 64
# RFC 8410 SubjectPublicKeyInfo prefix for Ed25519.
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
# Dual-signature attestation public-key sizes, mirroring the hub constants
# WINN3_DUAL_AUTH_ED25519_PUBLIC_KEY_BYTES / WINN3_DUAL_AUTH_MLDSA65_PUBLIC_KEY_BYTES.
DUAL_AUTH_ED25519_PUBLIC_KEY_BYTES = 32
DUAL_AUTH_MLDSA65_PUBLIC_KEY_BYTES = 1952

MIN_TAG_SIZE = 16
MAX_TAG_SIZE = 32
DEFAULT_TAG_SIZE = 32
MIN_ADMISSION_SECRET_BYTES = 32
STATIC_PUBLIC_KEY_BYTES = 32
MIN_GATEWAY_ID_BYTES = 1
MAX_GATEWAY_ID_BYTES = 255
DEFAULT_BUCKET_WINDOW_SECONDS = 10
DEFAULT_MAX_SKEW_SECONDS = 60
MIN_BUCKET_WINDOW_SECONDS_CORE = 1
MAX_BUCKET_CANDIDATES = 4096
PADDING_POLICIES = ("none", "bucket", "mimic")
DEFAULT_PADDING_POLICY = "bucket"
MAX_LIVE_ADMISSION_KEYS = 2
MAX_ADMISSION_HMAC_BUDGET = 64
MIN_DESCRIPTOR_TTL_SECONDS = 3600
MAX_DESCRIPTOR_TTL_SECONDS = 30 * 24 * 3600
MAX_DESCRIPTOR_BYTES = 4096

REQUIRED_FIELDS = (
    "admission_gen", "admission_secret", "alg", "bucket_window_s", "endpoint",
    "gateway_id", "iat", "inner_resolver_v4", "inner_router_v4", "kid",
    "max_skew_s", "node", "not_after", "padding", "seq", "static_pub",
    "tag_size", "v",
)
# Optional dual-signature attestation fields, mirroring the hub's
# WINN3_DESCRIPTOR_OPTIONAL_FIELDS: absent on legacy descriptors, present as a
# PAIR (both base64 of raw key bytes, exactly sized) on dual-provisioned nodes.
OPTIONAL_FIELDS = ("auth_ed25519", "auth_mldsa65")
PLAIN_IPV4_FIELDS = ("inner_resolver_v4", "inner_router_v4")
SECRET_FIELDS = ("admission_secret",)

# The hub reads this name. The Dart client reads the same value under a
# DIFFERENT name (`WINS_` prefix) via --dart-define. Staging one under the
# other's name is a silent no-op at both ends, so both are printed by `pubkey`.
HUB_PUBKEY_ENV = "WINN3_DESCRIPTOR_PUBKEY_{SLOT}"
CLIENT_PUBKEY_DEFINE = "WINS_WINN3_DESCRIPTOR_PUBKEY_{SLOT}"


class Refused(Exception):
    """An input this hub would refuse. Carries a reason, never a value."""

    def __init__(self, reason, fields=()):
        super().__init__(reason)
        self.reason = reason
        self.fields = list(fields)

    def __str__(self):
        if self.fields:
            return f"{self.reason} (fields: {', '.join(self.fields)})"
        return self.reason


def die(message, code=2):
    sys.stderr.write(f"REFUSED: {message}\n")
    raise SystemExit(code)


# --------------------------------------------------------------------------
# Validators, mirrored from the hub so a bad value costs the operator a local
# error instead of a 400 in the middle of a ceremony.
# --------------------------------------------------------------------------
def is_ip_literal_endpoint(value):
    """Mirror of the hub's winn3_is_ip_literal_endpoint / isWinnIpLiteralEndpoint.

    A hostname is refused because resolving one would leave the device outside
    the tunnel. Loopback is accepted (the stacked stealth arrangement points at
    a local inbound); unspecified and multicast are not.
    """
    text = str(value or "").strip()
    if not text:
        return False
    if text.startswith("[") and "]:" in text:
        host, _, port = text.partition("]:")
        host = host[1:]
    elif text.count(":") == 1:
        host, _, port = text.partition(":")
    else:
        return False
    if not host or not port.isdigit():
        return False
    try:
        port_num = int(port)
    except ValueError:
        return False
    if not (1 <= port_num <= 65535):
        return False
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not (addr.is_unspecified or addr.is_multicast)


def is_inner_ipv4(value):
    """A bare dotted-quad IPv4 address -- no port, no hostname, no IPv6.

    Unspecified, multicast and loopback are refused: none can be a tunnel
    assignment or an inner next hop, and accepting one produces a session that
    starts and carries nothing.
    """
    text = str(value or "").strip()
    if not text or text.count(".") != 3:
        return False
    try:
        addr = ipaddress.IPv4Address(text)
    except ValueError:
        return False
    return not (addr.is_unspecified or addr.is_multicast or addr.is_loopback)


def operator_text_has_edge_whitespace(raw):
    """True when decoded operator bytes carry leading or trailing whitespace.

    Trap 3. `gateway_id` is an authenticated input to the admission tag and is
    NEVER TRANSMITTED, so the two ends never discover they disagree. One
    trailing space keys 9 bytes on the gateway and on Apple and 8 on Android,
    and the gateway answers a failed tag with silence. Caught here, where it
    costs one operator one line of output.

    BYTES, not str, and that is the whole point. `bytes.isspace()` is ASCII-only
    (space, \\t, \\n, \\r, \\v, \\f); `str.strip()` additionally eats \\x1c-\\x1f
    and a pile of Unicode separators. A tool that used the str form would refuse
    values the hub accepts -- stricter than the thing it is a front end for,
    which is its own kind of wrong on a deadline. Pinned against the hub's own
    function by test_edge_whitespace_matches_the_hub_byte_for_byte.
    """
    if not raw:
        return False
    return raw[:1].isspace() or raw[-1:].isspace()


def looks_like_ascii_hex(raw):
    """True when every byte is an ASCII hex digit -- the shape keygen writes.

    Used ONLY to tell the two encodings apart for the warning below, never to
    accept or refuse. The admission secret is opaque bytes by contract and
    nothing here may decode it.
    """
    if not raw:
        return False
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return False
    return bool(re.fullmatch(r"[0-9a-fA-F]+", text))


def freshness_geometry(bucket_window_s, max_skew_s):
    """(spread, candidates, acceptance_span_s), mirroring core exactly.

    spread = ceil(skew / window); candidates = 2*spread + 1. The handshake
    replay-cache lifetime is the same number by construction; if the two ever
    drift apart the gap is a span in which a recorded packet is a working
    gateway detector again.
    """
    window = int(bucket_window_s)
    skew = int(max_skew_s)
    if window < MIN_BUCKET_WINDOW_SECONDS_CORE:
        raise Refused("bucket-window-below-one-second", ["bucket_window_s"])
    if skew < window:
        raise Refused("max-skew-below-bucket-window", ["max_skew_s"])
    spread = -(-skew // window)
    candidates = 2 * spread + 1
    if candidates > MAX_BUCKET_CANDIDATES:
        raise Refused("bucket-candidates-over-core-ceiling", ["max_skew_s"])
    return spread, candidates, candidates * window


def b64decode_strict(value, field):
    try:
        return base64.b64decode(str(value).strip(), validate=True)
    except (binascii.Error, ValueError):
        raise Refused("descriptor-field-not-base64", [field]) from None


# --------------------------------------------------------------------------
# openssl. The key is referenced by PATH and never read by this process.
# --------------------------------------------------------------------------
def _openssl_command():
    configured = os.environ.get("WINS_RELEASE_OPENSSL")
    if not configured:
        return "openssl"
    if not os.path.isabs(configured):
        die("WINS_RELEASE_OPENSSL must be an absolute path.", 3)
    try:
        info = os.lstat(configured)
    except OSError as exc:
        die(f"WINS_RELEASE_OPENSSL is unavailable: {exc}", 3)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        die("WINS_RELEASE_OPENSSL must name one regular, non-symlink file.", 3)
    if not os.access(configured, os.X_OK):
        die("WINS_RELEASE_OPENSSL is not executable.", 3)
    return configured


def _run_openssl(argv, *, stdin_ok=False):
    try:
        completed = subprocess.run(
            [_openssl_command(), *argv],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )
    except FileNotFoundError:
        die("openssl(1) is not on PATH. The hub verifies with openssl; signing "
            "with anything else would be signing with different arithmetic.", 3)
    except subprocess.TimeoutExpired:
        die("openssl timed out.", 3)
    if completed.returncode != 0:
        # stderr from openssl never contains key material, but it can contain
        # the key PATH, which is not a secret. It never contains key bytes.
        detail = completed.stderr.decode("utf-8", "replace").strip()
        die(f"openssl {argv[0]} failed: {detail or 'no diagnostic'}", 3)
    return completed.stdout


def public_key_raw(key_path):
    """The raw 32-byte Ed25519 public half of the key at `key_path`.

    `openssl pkey -pubout -outform DER` emits a 44-byte SPKI whose last 32 bytes
    are the raw key. The prefix is asserted rather than assumed so that an
    RSA or P-256 key -- which would produce a signature nothing can verify --
    is caught here instead of at the hub.
    """
    if not os.path.exists(key_path):
        die(f"private key not found at {key_path}", 2)
    der = _run_openssl(
        ["pkey", "-in", key_path, "-pubout", "-outform", "DER"])
    if not der.startswith(ED25519_SPKI_PREFIX) or len(der) != 44:
        die("that key is not Ed25519 (its SubjectPublicKeyInfo does not carry "
            "the RFC 8410 Ed25519 prefix). `alg` is inside the signed bytes and "
            "ed25519 is the only algorithm the shipped client can verify.", 2)
    return der[-ED25519_PUBLIC_KEY_BYTES:]


def sign_message(key_path, message):
    """Detached Ed25519 signature over `message`, by real openssl.

    The message contains the admission secret, so it is written only inside a
    0700 temporary directory that is removed before return.
    """
    with tempfile.TemporaryDirectory(prefix="winn3-sign-") as work:
        message_path = os.path.join(work, "descriptor.bin")
        fd = os.open(message_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(message)
        signature = _run_openssl(
            ["pkeyutl", "-sign", "-rawin", "-inkey", key_path,
             "-in", message_path])
    if len(signature) != ED25519_SIGNATURE_BYTES:
        die(f"openssl returned a {len(signature)}-byte signature; Ed25519 is "
            f"{ED25519_SIGNATURE_BYTES}.", 3)
    return signature


def verify_message(public_raw, message, signature):
    """Verify with the PUBLIC half, exactly as the hub does.

    Run unconditionally after signing. It costs one openssl call and it is the
    difference between "this tool emitted bytes" and "this tool emitted bytes
    the hub's own verification construction accepts".
    """
    with tempfile.TemporaryDirectory(prefix="winn3-verify-") as work:
        key_path = os.path.join(work, "descriptor.der")
        msg_path = os.path.join(work, "descriptor.bin")
        sig_path = os.path.join(work, "descriptor.sig")
        for path, blob in (
            (key_path, ED25519_SPKI_PREFIX + public_raw),
            (msg_path, message),
            (sig_path, signature),
        ):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(blob)
        completed = subprocess.run(
            [_openssl_command(), "pkeyutl", "-verify", "-rawin", "-pubin",
             "-inkey", key_path, "-keyform", "DER",
             "-sigfile", sig_path, "-in", msg_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )
    return completed.returncode == 0


# --------------------------------------------------------------------------
# Payload construction
# --------------------------------------------------------------------------
def canonical_payload_bytes(payload):
    """The exact bytes that are signed, uploaded, stored and verified.

    Neither verifier imposes a canonical form -- both verify the bytes they are
    handed -- so this is the signer's choice, and it is the same choice the
    announcement tool makes for its payload and the hub test suite makes for its
    descriptor fixtures. Deterministic, so re-signing identical inputs
    reproduces identical bytes.
    """
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def build_payload(args):
    """Assemble and fully validate the descriptor payload.

    Mirrors validate_winn3_descriptor_payload. Every refusal here is one the hub
    would also make, and it is made BEFORE any signature exists.
    """
    warnings = []

    # --- gateway_id: operator TEXT or pre-encoded base64, never both -------
    # The double-encode is the exact defect this tree already shipped once.
    # Requiring the operator to say WHICH they have is the only way a tool can
    # tell `winsgw-fresh-01` from base64 of something else.
    if (args.gateway_id_text is None) == (args.gateway_id_b64 is None):
        raise Refused(
            "give exactly one of --gateway-id-text (an operator string like "
            "winsgw-fresh-01, base64'd for you) or --gateway-id-b64 (already "
            "base64). Guessing between them is how the gateway_id defect "
            "happened", ["gateway_id"])
    if args.gateway_id_text is not None:
        gateway_id_raw = args.gateway_id_text.encode("utf-8")
        gateway_id_b64 = base64.b64encode(gateway_id_raw).decode()
    else:
        gateway_id_b64 = args.gateway_id_b64.strip()
        gateway_id_raw = b64decode_strict(gateway_id_b64, "gateway_id")
    if not (MIN_GATEWAY_ID_BYTES <= len(gateway_id_raw) <= MAX_GATEWAY_ID_BYTES):
        raise Refused("descriptor-field-length", ["gateway_id"])
    if operator_text_has_edge_whitespace(gateway_id_raw):
        raise Refused("descriptor-gateway-id-has-edge-whitespace", ["gateway_id"])

    # --- admission_secret: from the key FILE's bytes, or pre-encoded -------
    # The secret is OPAQUE BYTES. keygen writes 64 ASCII hex characters and
    # every consumer keys with the file's bytes after stripping ONE trailing
    # CR/LF and nothing else. Anything that hex-decodes it in transit produces a
    # wrong admission tag on one end only, and the gateway answers with silence.
    if (args.admission_secret_file is None) == (args.admission_secret_b64 is None):
        raise Refused(
            "give exactly one of --admission-secret-file (the keygen file; its "
            "bytes are used verbatim after stripping one trailing CR/LF) or "
            "--admission-secret-b64", ["admission_secret"])
    if args.admission_secret_file is not None:
        if not os.path.exists(args.admission_secret_file):
            raise Refused("admission secret file not found", ["admission_secret"])
        with open(args.admission_secret_file, "rb") as handle:
            admission_raw = handle.read()
        # Exactly the trim every consumer does: one trailing CR/LF, nothing else.
        if admission_raw.endswith(b"\r\n"):
            admission_raw = admission_raw[:-2]
        elif admission_raw.endswith(b"\n") or admission_raw.endswith(b"\r"):
            admission_raw = admission_raw[:-1]
        admission_b64 = base64.b64encode(admission_raw).decode()
    else:
        admission_b64 = args.admission_secret_b64.strip()
        admission_raw = b64decode_strict(admission_b64, "admission_secret")
    if len(admission_raw) < MIN_ADMISSION_SECRET_BYTES:
        raise Refused("descriptor-field-length", ["admission_secret"])
    if operator_text_has_edge_whitespace(admission_raw):
        raise Refused("descriptor-admission-secret-has-edge-whitespace",
                      ["admission_secret"])
    if not re.fullmatch(rb"[0-9a-f]{64}", admission_raw):
        raise Refused(
            "descriptor-admission-secret-noncanonical", ["admission_secret"]
        )

    # --- static_pub --------------------------------------------------------
    static_b64 = args.static_pub.strip()
    static_raw = b64decode_strict(static_b64, "static_pub")
    if len(static_raw) != STATIC_PUBLIC_KEY_BYTES:
        raise Refused("descriptor-field-length", ["static_pub"])

    # --- dual-auth attestation keys (OPTIONAL, and only as a pair) ---------
    # Mirrors the hub validator: both present and exactly sized, or neither.
    # A half-provisioned descriptor is refused by the hub, so it is refused
    # here before a signature over it exists.
    if (args.auth_ed25519 is None) != (args.auth_mldsa65 is None):
        raise Refused(
            "auth_ed25519 and auth_mldsa65 are optional as a PAIR: give both "
            "or neither", ["auth_ed25519", "auth_mldsa65"])
    auth_fields = {}
    if args.auth_ed25519 is not None:
        ed_raw = b64decode_strict(args.auth_ed25519, "auth_ed25519")
        if len(ed_raw) != DUAL_AUTH_ED25519_PUBLIC_KEY_BYTES:
            raise Refused("descriptor-field-length", ["auth_ed25519"])
        ml_raw = b64decode_strict(args.auth_mldsa65, "auth_mldsa65")
        if len(ml_raw) != DUAL_AUTH_MLDSA65_PUBLIC_KEY_BYTES:
            raise Refused("descriptor-field-length", ["auth_mldsa65"])
        auth_fields = {
            "auth_ed25519": args.auth_ed25519.strip(),
            "auth_mldsa65": args.auth_mldsa65.strip(),
        }

    # --- scalars -----------------------------------------------------------
    kid = args.kid.strip().lower()
    if kid not in KEY_SLOTS:
        raise Refused("descriptor-unknown-key-slot", ["kid"])
    alg = args.alg.strip().lower()
    if alg not in SUPPORTED_ALGS:
        raise Refused("descriptor-unsupported-algorithm", ["alg"])
    node = args.node.strip().lower()
    if not node:
        raise Refused("descriptor-missing-node", ["node"])
    endpoint = args.endpoint.strip()
    if not is_ip_literal_endpoint(endpoint):
        raise Refused("descriptor-endpoint-not-ip-literal", ["endpoint"])
    for field, value in (("inner_router_v4", args.inner_router_v4),
                         ("inner_resolver_v4", args.inner_resolver_v4)):
        if not is_inner_ipv4(value):
            raise Refused("descriptor-inner-address-not-ipv4", [field])
    if args.inner_resolver_v4.strip() != args.inner_router_v4.strip():
        raise Refused(
            "descriptor-resolver-does-not-match-gateway-bind",
            ["inner_resolver_v4", "inner_router_v4"],
        )
    if not (MIN_TAG_SIZE <= args.tag_size <= MAX_TAG_SIZE):
        raise Refused("descriptor-tag-size-out-of-range", ["tag_size"])
    if args.padding not in PADDING_POLICIES:
        raise Refused("descriptor-unknown-padding-policy", ["padding"])

    spread, candidates, span = freshness_geometry(
        args.bucket_window_s, args.max_skew_s)
    # Checked at the WORST case rather than the current one: accepted only if it
    # would still be affordable mid-rotation, because otherwise the refusal
    # lands on the operator at the worst possible moment.
    cost = candidates * MAX_LIVE_ADMISSION_KEYS
    if cost > MAX_ADMISSION_HMAC_BUDGET:
        raise Refused("descriptor-freshness-exceeds-rotation-budget",
                      ["bucket_window_s", "max_skew_s"])

    if args.admission_gen < 0:
        raise Refused("descriptor-negative-admission-generation", ["admission_gen"])
    if args.seq < 0:
        raise Refused("descriptor-negative-sequence", ["seq"])

    iat = int(args.iat) if args.iat is not None else int(time.time())
    not_after = iat + int(args.ttl)
    ttl = not_after - iat
    if ttl < MIN_DESCRIPTOR_TTL_SECONDS:
        raise Refused("descriptor-ttl-too-short", ["not_after"])
    if ttl > MAX_DESCRIPTOR_TTL_SECONDS:
        raise Refused("descriptor-ttl-too-long", ["not_after"])

    payload = {
        "v": int(args.format_version),
        "alg": alg,
        "kid": kid,
        "node": node,
        "endpoint": endpoint,
        # Plain dotted-quad TEXT, not base64. Every other byte-valued field is
        # base64; these two are addresses and reach `[winn]` as text, with no
        # decode anywhere to disagree about.
        "inner_router_v4": args.inner_router_v4.strip(),
        "inner_resolver_v4": args.inner_resolver_v4.strip(),
        "static_pub": static_b64,
        "gateway_id": gateway_id_b64,
        "admission_secret": admission_b64,
        "admission_gen": int(args.admission_gen),
        "tag_size": int(args.tag_size),
        "padding": args.padding,
        "bucket_window_s": int(args.bucket_window_s),
        "max_skew_s": int(args.max_skew_s),
        "seq": int(args.seq),
        "iat": iat,
        "not_after": not_after,
    }
    payload.update(auth_fields)
    # The key set is CLOSED at the hub -- an unknown field is refused, not
    # ignored, and a missing one is refused too. Assert both directions here so
    # a future edit to this dict cannot silently produce an unpublishable
    # descriptor.
    missing = sorted(set(REQUIRED_FIELDS) - set(payload))
    unknown = sorted(
        set(payload) - set(REQUIRED_FIELDS) - set(OPTIONAL_FIELDS))
    if missing or unknown:
        raise Refused("descriptor-field-set-mismatch", missing + unknown)

    if int(args.format_version) != FORMAT_VERSION:
        warnings.append(
            f"--format-version {args.format_version} is not the hub's "
            f"WINN3_DESCRIPTOR_FORMAT_VERSION ({FORMAT_VERSION}). The hub will "
            f"refuse this with descriptor-unsupported-format-version.")

    geometry = {
        "spread": spread,
        "bucket_candidates": candidates,
        "acceptance_span_s": span,
        "worst_case_hmacs_per_dropped_datagram": cost,
        "hmac_budget": MAX_ADMISSION_HMAC_BUDGET,
        "ttl_s": ttl,
    }
    return payload, geometry, warnings


def check_seq_increases(args):
    """Refuse unless `seq` strictly increases over the stored value.

    THE ROLLBACK DEFENCE, and it is the only one there is. A leaked admin token
    cannot mint a descriptor, but it CAN replay a captured earlier envelope --
    and reinstating a retired descriptor resurrects a burnt admission secret,
    which is the one move that turns a dead secret back into a live one. The hub
    enforces this too (409, "no node record was changed"); it is enforced HERE
    as well so the ceremony fails before a signature over a rollback-shaped
    payload exists at all. A rollback is a NEW ceremony with a HIGHER seq, never
    a re-upload of an old envelope.

    `--prev-seq none` is the FIRST publication for a node and must be typed
    explicitly. There is no default, because a defaulted 0 would silently accept
    a re-upload against a node that already has a descriptor.
    """
    raw = str(args.prev_seq).strip().lower()
    if raw in ("none", "first", "new"):
        if args.seq < 0:
            raise Refused("descriptor-negative-sequence", ["seq"])
        return None
    try:
        previous = int(raw)
    except ValueError:
        raise Refused(
            "--prev-seq must be the stored seq (an integer) or the literal "
            "'none' for a node that has never had a descriptor. Read the "
            "stored value from GET /admin/nodes/winn3/descriptor", ["seq"]
        ) from None
    if args.seq <= previous:
        raise Refused(
            f"seq must STRICTLY INCREASE: --seq {args.seq} is not greater than "
            f"the stored seq {previous}. A rollback is a new ceremony with a "
            f"higher seq, never a re-upload of an older envelope -- re-uploading "
            f"one would resurrect an admission secret that may already have been "
            f"retired and burnt. Nothing was signed",
            ["seq"])
    return previous


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------
def cmd_pubkey(args):
    raw = public_key_raw(args.key)
    encoded = base64.b64encode(raw).decode()
    slot = args.kid.strip().lower()
    if slot not in KEY_SLOTS:
        die(f"--kid must be one of {', '.join(KEY_SLOTS)}", 2)
    upper = slot.upper()
    if args.bare:
        print(encoded)
        return 0
    print("# Base64 of the RAW 32-byte Ed25519 public half. The private key was")
    print("# read only by openssl and is not printed, copied or logged.")
    print()
    print(f"# 1. HUB  -- /root/vpn_auth.env (wins-hub.service EnvironmentFile).")
    print(f"#    NOTE: no `WINS_` prefix. wins_control_plane_setup_ONETOUCH.sh")
    print(f"#    write_env persists this when WINN3_DESCRIPTOR_PUBKEY_{upper}")
    print(f"#    or WINN3_DESCRIPTOR_PUBKEY_{upper}_FILE is set, and keeps a")
    print(f"#    value already in that file across re-runs. It never generates")
    print(f"#    a key. Without a public key the hub cannot verify at all.")
    print(f"{HUB_PUBKEY_ENV.format(SLOT=upper)}={encoded}")
    print()
    print(f"# 2. CLIENT -- a --dart-define on every build. WITH the `WINS_` prefix.")
    print(f"#    A build with no compiled key reports")
    print(f"#    descriptor-no-verification-keys-compiled and standalone is")
    print(f"#    unavailable; it never accepts a descriptor unverified.")
    print(f"--dart-define={CLIENT_PUBKEY_DEFINE.format(SLOT=upper)}={encoded}")
    return 0


def cmd_sign(args):
    try:
        previous = check_seq_increases(args)
        payload, geometry, warnings = build_payload(args)
    except Refused as exc:
        die(str(exc), 2)

    payload_bytes = canonical_payload_bytes(payload)
    if len(payload_bytes) > MAX_DESCRIPTOR_BYTES:
        die(f"payload is {len(payload_bytes)} bytes, over the "
            f"{MAX_DESCRIPTOR_BYTES}-byte ceiling", 2)

    public_raw = public_key_raw(args.key)
    message = DOMAIN + b"\x00" + payload_bytes
    signature = sign_message(args.key, message)

    # Never emit a signature this tool has not itself verified against the
    # hub's construction. A tool that produces a signature the hub rejects is
    # worse than no tool.
    if not verify_message(public_raw, message, signature):
        die("self-verification FAILED: the signature this run produced does "
            "not verify under its own public key. Nothing was emitted.", 3)

    payload_b64 = base64.b64encode(payload_bytes).decode()
    sig_b64 = base64.b64encode(signature).decode()
    pub_b64 = base64.b64encode(public_raw).decode()
    upper = payload["kid"].upper()

    if args.json:
        print(json.dumps({
            "descriptor_payload_b64": payload_b64,
            "descriptor_sig_b64": sig_b64,
            "public_key_b64": pub_b64,
            "kid": payload["kid"],
            "node": payload["node"],
            "seq": payload["seq"],
            "previous_seq": previous,
            "admission_gen": payload["admission_gen"],
            "iat": payload["iat"],
            "not_after": payload["not_after"],
            "payload_bytes": len(payload_bytes),
            "geometry": geometry,
            "warnings": warnings,
        }, indent=2, sort_keys=True))
        return 0

    if args.out_dir:
        os.makedirs(args.out_dir, mode=0o700, exist_ok=True)
        for name, text in (("descriptor_payload_b64.txt", payload_b64),
                           ("descriptor_sig_b64.txt", sig_b64),
                           ("descriptor_pubkey_b64.txt", pub_b64)):
            path = os.path.join(args.out_dir, name)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as handle:
                handle.write(text + "\n")

    for warning in warnings:
        sys.stderr.write(f"WARNING: {warning}\n")

    print("# ---------------------------------------------------------------")
    print("# winn/3 descriptor SIGNED and self-verified with openssl.")
    print(f"#   node={payload['node']}  kid={payload['kid']}  "
          f"seq={payload['seq']}  admission_gen={payload['admission_gen']}")
    print(f"#   previous stored seq: "
          f"{'none (first publication)' if previous is None else previous}")
    print(f"#   v={payload['v']}  payload={len(payload_bytes)} bytes "
          f"(ceiling {MAX_DESCRIPTOR_BYTES})")
    print(f"#   iat={payload['iat']}  not_after={payload['not_after']}  "
          f"ttl={geometry['ttl_s']}s")
    print(f"#   freshness: {geometry['bucket_candidates']} candidates, "
          f"{geometry['worst_case_hmacs_per_dropped_datagram']} HMACs per "
          f"dropped datagram mid-rotation (budget "
          f"{geometry['hmac_budget']})")
    print("#")
    print("# THE PAYLOAD CARRIES admission_secret. It is not a log line. Do not")
    print("# paste it into a ticket, a chat, or a shared terminal recording.")
    print("# ---------------------------------------------------------------")
    print()
    print(f"{HUB_PUBKEY_ENV.format(SLOT=upper)}={pub_b64}")
    print()
    print("DESCRIPTOR_PAYLOAD_B64='" + payload_b64 + "'")
    print()
    print("DESCRIPTOR_SIG_B64='" + sig_b64 + "'")
    print()
    print("# Publish (the admin token is referenced, never printed):")
    print("#   curl -sS -X POST \"$HUB_BASE/admin/nodes/winn3/descriptor\" \\")
    print("#     -H \"x-admin-token: $WINS_ADMIN_TOKEN\" \\")
    print(f"#     -F 'slug={payload['node']}' -F 'enabled=true' \\")
    print("#     -F \"descriptor_payload_b64=$DESCRIPTOR_PAYLOAD_B64\" \\")
    print("#     -F \"descriptor_sig_b64=$DESCRIPTOR_SIG_B64\"")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="winn3_sign_descriptor.py",
        description=(
            "Sign a winn/3 standalone gateway descriptor offline. The hub app "
            "cannot read the descriptor key held by the separate signer "
            "service. This tool provides the offline ceremony path. "
            "The private key is passed BY PATH and is never read, printed or "
            "copied by this script."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "There is no key-generation mode on purpose. Generate the key "
            "yourself:\n"
            "    umask 077 && openssl genpkey -algorithm ED25519 -out g1.pem\n"
            "A private key must never be created by, or pass through, a script "
            "committed to this repository."))
    sub = parser.add_subparsers(dest="command", required=True)

    pub = sub.add_parser(
        "pubkey", help="print the base64 raw-32-byte public half of a key")
    pub.add_argument("--key", required=True, metavar="PATH",
                     help="Ed25519 private key (PEM). Read by openssl only.")
    pub.add_argument("--kid", default="g1", metavar="SLOT",
                     help="slot this key fills: g1, g2 or g3 (default g1)")
    pub.add_argument("--bare", action="store_true",
                     help="print only the base64 value, no commentary")
    pub.set_defaults(func=cmd_pubkey)

    sign = sub.add_parser("sign", help="sign a descriptor payload")
    sign.add_argument("--key", required=True, metavar="PATH",
                      help="Ed25519 private key (PEM). Read by openssl only.")
    sign.add_argument("--node", required=True,
                      help="node slug. INSIDE the signed bytes; a descriptor "
                           "installed on the wrong node is refused by the hub")
    sign.add_argument("--endpoint", required=True, metavar="HOST:PORT",
                      help="gateway endpoint, IP LITERAL with a nonzero port")
    sign.add_argument("--inner-router-v4", required=True, metavar="A.B.C.D",
                      help="inner next hop, plain dotted quad, inside the hub "
                           "pool. Must equal the gateway's WINN3_GATEWAY_INNER_V4")
    sign.add_argument("--inner-resolver-v4", required=True, metavar="A.B.C.D",
                      help="inner DNS responder, plain dotted quad, inside the "
                           "pool. Must equal --inner-router-v4 and the gateway's "
                           "WINN3_GATEWAY_INNER_V4")
    sign.add_argument("--static-pub", required=True, metavar="B64",
                      help="gateway X25519 static public key, base64 of 32 bytes")
    sign.add_argument("--auth-ed25519", metavar="B64",
                      help="optional dual-auth Ed25519 public key, base64 of 32 "
                           "raw bytes; must be given together with "
                           "--auth-mldsa65")
    sign.add_argument("--auth-mldsa65", metavar="B64",
                      help="optional dual-auth ML-DSA-65 public key, base64 of "
                           "1952 raw bytes; must be given together with "
                           "--auth-ed25519")
    sign.add_argument("--gateway-id-text", metavar="TEXT",
                      help="operator string, e.g. winsgw-fresh-01. Base64'd for "
                           "you. Mutually exclusive with --gateway-id-b64")
    sign.add_argument("--gateway-id-b64", metavar="B64",
                      help="gateway id already base64. Mutually exclusive with "
                           "--gateway-id-text")
    sign.add_argument("--admission-secret-file", metavar="PATH",
                      help="the keygen file. Its BYTES are used verbatim after "
                           "stripping one trailing CR/LF, then base64'd. This is "
                           "the encoding every consumer uses")
    sign.add_argument("--admission-secret-b64", metavar="B64",
                      help="admission secret already base64. Mutually exclusive "
                           "with --admission-secret-file")
    sign.add_argument("--admission-gen", type=int, required=True,
                      help="admission key generation. A CHANGE here is a "
                           "rotation and the hub records the previous one")
    sign.add_argument("--seq", type=int, required=True,
                      help="descriptor sequence. Must strictly increase")
    sign.add_argument("--prev-seq", required=True, metavar="N|none",
                      help="the seq currently stored for this node, from GET "
                           "/admin/nodes/winn3/descriptor, or the literal "
                           "'none' for a first publication. No default: a "
                           "defaulted value would silently permit a re-upload")
    sign.add_argument("--kid", default="g1", help="signing slot (default g1)")
    sign.add_argument("--alg", default=ALG_ED25519, help="default ed25519")
    sign.add_argument("--iat", type=int, default=None,
                      help="issued-at unix seconds (default: now)")
    sign.add_argument("--ttl", type=int, default=86400, metavar="SECONDS",
                      help=f"lifetime, {MIN_DESCRIPTOR_TTL_SECONDS}.."
                           f"{MAX_DESCRIPTOR_TTL_SECONDS} (default 86400)")
    sign.add_argument("--tag-size", type=int, default=DEFAULT_TAG_SIZE)
    sign.add_argument("--padding", default=DEFAULT_PADDING_POLICY,
                      choices=list(PADDING_POLICIES))
    sign.add_argument("--bucket-window-s", type=int,
                      default=DEFAULT_BUCKET_WINDOW_SECONDS)
    sign.add_argument("--max-skew-s", type=int,
                      default=DEFAULT_MAX_SKEW_SECONDS)
    sign.add_argument("--format-version", type=int, default=FORMAT_VERSION,
                      help=f"`v`, inside the signed bytes. Default "
                           f"{FORMAT_VERSION}, required by both the hub and "
                           f"shipping Dart client. Override only deliberately")
    sign.add_argument("--out-dir", metavar="DIR",
                      help="also write payload/sig/pubkey as 0600 files here")
    sign.add_argument("--json", action="store_true",
                      help="machine-readable output")
    sign.set_defaults(func=cmd_sign)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
