#!/usr/bin/env python3
"""Emergency g1 re-signing for one winn/3 gateway, generic.

WHY THIS FILE EXISTS. The hub's normal signing path is the signer service,
which signs only within policy: renewals of pinned identities, the rate
limits, and no new or changed identity without an unused t1 ticket for that
slug, action, endpoint IP, gateway ID and pinned host key. When the hub
verify ring must return to g1, every stored descriptor of the removed slot
has to be re-signed with g1, withdrawn with its gateway stopped, or its node
retired. The re-signing with g1 is this tool's job: it is the emergency g1
tool, run on the operator Mac with the offline g1 ceremony key.

It reads the node's published identity from /etc/winn/public/gateway-identity.json
over the management SSH channel and hard-codes nothing: no node list, no
router, no endpoint, no gateway ID, no slug. The operator names the node on
the command line and supplies the sequence numbers from the hub. Run it once
per node; the sequence numbers are per node.

The admission secret is read from the node's root-only credential file over
the same SSH channel, checked against the identity's admission fingerprint,
and handed to tools/winn3_sign_descriptor.py through a 0600 file in a 0700
temporary directory that is removed after signing, never through a command
line. The signed payload carries it, so the result file is created fresh at
0600 (O_EXCL and O_NOFOLLOW); an existing --out path is refused.

Announcements stay offline. This tool signs descriptors only; announcements
are signed by tools/winn3_sign_announcement.py, off the hub, and verified
against ANNOUNCE_PUBKEY_A1..A3.

The identity file is the canonical JSON (sorted keys, compact) the
data-plane installer publishes at /etc/winn/public/gateway-identity.json
(0644). The fields this tool requires:

  slug                  the node slug
  gateway_id            the gateway ID text
  endpoint              the detected public IPv4 plus ":9111"
  inner_router_v4       the inner next hop, plain dotted quad
  inner_resolver_v4     the inner DNS responder, plain dotted quad
  static_pub_hex        the X25519 static public key, 64 hex characters
  auth_ed25519_hex      the dual-auth Ed25519 public key, 64 hex characters
  auth_mldsa65_hex       the dual-auth ML-DSA-65 public key, 3904 hex characters
  admission_fingerprint the winn3-admission-fingerprint-v1 digest, 16 hex
                        characters

The admission secret is read from /etc/winn/credentials/winn3-gateway-admission.key
(the gateway installer's WINN3_ADMISSION_KEY_PATH default). It must be
exactly 64 lowercase hex characters and its fingerprint must equal
admission_fingerprint; anything else is refused before any signing happens.

Usage:
  tools/mint_and_register_winn3_descriptors.py --key G1_KEY --host SSH_TARGET \
      --seq N --prev-seq N|none --admission-gen N [--ttl SECONDS] [--out FILE]

  --key           the offline g1 private key: a PEM, or the escrowed 32-byte
                  raw Ed25519 seed (g1.key), which is wrapped as PKCS#8 into a
                  0600 PEM inside the 0700 temporary directory for openssl and
                  removed after signing
  --host          the node's management SSH target (BatchMode; the operator's
                  own key, never a hub-held credential)
  --seq           the new descriptor sequence, strictly above the stored one
  --prev-seq      the seq currently stored for this node, from
                  GET /admin/nodes/winn3/descriptor, or "none" for a first
                  publication. No default: a defaulted value would silently
                  permit a re-upload
  --admission-gen the admission key generation, unchanged for a re-sign of
                  the same identity
  --ttl           descriptor lifetime in seconds (default 2592000, 30 days)
  --out           where to write the result JSON, mode 0600
                  (default /tmp/winn3_signed_descriptors.json). Every
                  invocation requires a fresh output path: an existing file
                  or symlink there is refused, never overwritten

The result is one JSON object keyed by the slug, holding the fields the
admin form needs plus the signing metadata. Extract the two the form posts:

  jq -r '.["<slug>"].descriptor_payload_b64' /tmp/winn3_signed_descriptors.json
  jq -r '.["<slug>"].descriptor_sig_b64' /tmp/winn3_signed_descriptors.json

and register the envelope:

  curl -sS -X POST "$HUB_BASE/admin/nodes/winn3/descriptor" \
    -H "x-admin-token: $WINS_ADMIN_TOKEN" \
    -F "slug=<slug>" -F "enabled=true" \
    -F "descriptor_payload_b64=$DESCRIPTOR_PAYLOAD_B64" \
    -F "descriptor_sig_b64=$DESCRIPTOR_SIG_B64"

Exit codes: 0 signed, 2 refused (bad input or fingerprint mismatch), 3 SSH,
openssl or environment failure.
"""

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

IDENTITY_PATH = "/etc/winn/public/gateway-identity.json"
ADMISSION_KEY_PATH = "/etc/winn/credentials/winn3-gateway-admission.key"
SIGN_TOOL = os.path.join(REPO_ROOT, "tools", "winn3_sign_descriptor.py")
FP_DOMAIN = "winn3-admission-fingerprint-v1"
DEFAULT_OUT = "/tmp/winn3_signed_descriptors.json"
DEFAULT_TTL = 2592000
# PKCS#8 prefix for a raw Ed25519 seed: the escrowed g1.key is the 32-byte
# seed, and openssl reads only an encoded key.
ED25519_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
ED25519_SEED_BYTES = 32

HEX_DIGITS = set("0123456789abcdef")


def die(message, code=2):
    sys.stderr.write(f"REFUSED: {message}\n")
    raise SystemExit(code)


def ssh_cat(host, path):
    """One file's bytes over the operator's own BatchMode SSH channel."""
    cmd = ["ssh", "-o", "BatchMode=yes", host, f"cat {path}"]
    res = subprocess.run(cmd, capture_output=True)
    if res.returncode != 0:
        detail = res.stderr.decode("utf-8", "replace").strip()
        die(f"could not read {path} from {host} over SSH: {detail}", 3)
    return res.stdout


def require_hex_field(identity, name, length):
    value = identity.get(name)
    if not isinstance(value, str) or len(value) != length \
            or any(c not in HEX_DIGITS for c in value):
        die(f"{IDENTITY_PATH} field {name} must be {length} lowercase hex "
            f"characters; got {value!r}")
    return value


def require_text_field(identity, name):
    value = identity.get(name)
    if not isinstance(value, str) or not value:
        die(f"{IDENTITY_PATH} field {name} must be non-empty text")
    if value != value.strip():
        die(f"{IDENTITY_PATH} field {name} has edge whitespace")
    return value


def admission_fingerprint(secret_bytes):
    """Byte-identical to the shell: sha256(domain + CR/LF-free secret)[:16]."""
    digest = hashlib.sha256()
    digest.update(FP_DOMAIN.encode("ascii"))
    digest.update(secret_bytes)
    return digest.hexdigest()[:16]


def main():
    parser = argparse.ArgumentParser(
        prog="mint_and_register_winn3_descriptors.py",
        description=(
            "Emergency g1 re-signing for one winn/3 gateway. Reads the node's "
            "published identity from /etc/winn/public/gateway-identity.json "
            "over the management SSH channel and hard-codes nothing. Signs "
            "through tools/winn3_sign_descriptor.py; a PEM g1 key is passed "
            "BY PATH and never read by this script, and a raw 32-byte seed "
            "is wrapped into a 0600 PEM in a 0700 temporary directory that "
            "is removed after signing. Nothing prints the key."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Run once per node; --seq, --prev-seq and --admission-gen are per "
            "node. Announcements stay offline: this tool signs descriptors "
            "only."))
    parser.add_argument("--key", required=True, metavar="PATH",
                        help="offline g1 private key: a PEM, or the escrowed "
                             "32-byte raw Ed25519 seed (g1.key)")
    parser.add_argument("--host", required=True, metavar="SSH_TARGET",
                        help="the node's management SSH target (BatchMode)")
    parser.add_argument("--seq", required=True, type=int, metavar="N",
                        help="the new descriptor sequence, strictly above the "
                             "stored one")
    parser.add_argument("--prev-seq", required=True, metavar="N|none",
                        help="the seq currently stored for this node, from "
                             "GET /admin/nodes/winn3/descriptor, or 'none' "
                             "for a first publication")
    parser.add_argument("--admission-gen", required=True, type=int, metavar="N",
                        help="the admission key generation, unchanged for a "
                             "re-sign of the same identity")
    parser.add_argument("--ttl", type=int, default=DEFAULT_TTL, metavar="SECONDS",
                        help=f"descriptor lifetime (default {DEFAULT_TTL})")
    parser.add_argument("--out", default=DEFAULT_OUT, metavar="FILE",
                        help=f"result JSON, mode 0600, a fresh path that "
                             f"must not exist yet (default {DEFAULT_OUT})")
    args = parser.parse_args()

    if os.path.lexists(args.out):
        die("--out already exists; choose a new output path")
    if args.seq < 0:
        die("--seq must not be negative")
    if args.admission_gen < 0:
        die("--admission-gen must not be negative")
    if not os.path.isfile(args.key):
        die(f"g1 private key not found at {args.key}")

    raw_identity = ssh_cat(args.host, IDENTITY_PATH)
    try:
        identity = json.loads(raw_identity.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        die(f"{IDENTITY_PATH} on {args.host} is not valid JSON: {exc}")
    if not isinstance(identity, dict):
        die(f"{IDENTITY_PATH} on {args.host} must be a JSON object")

    slug = require_text_field(identity, "slug").lower()
    gateway_id = require_text_field(identity, "gateway_id")
    endpoint = require_text_field(identity, "endpoint")
    inner_router = require_text_field(identity, "inner_router_v4")
    inner_resolver = require_text_field(identity, "inner_resolver_v4")
    static_hex = require_hex_field(identity, "static_pub_hex", 64)
    auth_ed_hex = require_hex_field(identity, "auth_ed25519_hex", 64)
    auth_ml_hex = require_hex_field(identity, "auth_mldsa65_hex", 3904)
    fingerprint = require_hex_field(identity, "admission_fingerprint", 16)

    host_part, sep, port_part = endpoint.rpartition(":")
    if not sep or port_part != "9111":
        die(f"the identity endpoint must be <IPv4>:9111; got {endpoint!r}")
    try:
        ipaddress.IPv4Address(host_part)
    except ValueError:
        die(f"the identity endpoint must be an IPv4 literal plus :9111; "
            f"got {endpoint!r}")
    for name, value in (("inner_router_v4", inner_router),
                        ("inner_resolver_v4", inner_resolver)):
        try:
            ipaddress.IPv4Address(value)
        except ValueError:
            die(f"{IDENTITY_PATH} field {name} must be a plain dotted quad; "
                f"got {value!r}")

    secret_bytes = ssh_cat(args.host, ADMISSION_KEY_PATH)
    secret_stripped = secret_bytes
    if secret_stripped.endswith(b"\r\n"):
        secret_stripped = secret_stripped[:-2]
    elif secret_stripped.endswith(b"\n") or secret_stripped.endswith(b"\r"):
        secret_stripped = secret_stripped[:-1]
    try:
        secret_text = secret_stripped.decode("ascii")
    except UnicodeDecodeError:
        die(f"{ADMISSION_KEY_PATH} on {args.host} is not ASCII")
    if len(secret_text) != 64 or any(c not in HEX_DIGITS for c in secret_text):
        die(f"{ADMISSION_KEY_PATH} on {args.host} must be exactly 64 "
            f"lowercase hex characters; got {len(secret_text)} bytes")
    if admission_fingerprint(secret_stripped) != fingerprint:
        die(f"the admission secret on {args.host} does not match the "
            f"identity's admission_fingerprint; refusing to sign a "
            f"descriptor the gateway would refuse")

    work = tempfile.mkdtemp(prefix="winn3-emergency-")
    secret_path = os.path.join(work, "admission.key")
    pem_path = os.path.join(work, "g1.pem")
    try:
        fd = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(secret_bytes)

        key_path = args.key
        if os.path.getsize(args.key) == ED25519_SEED_BYTES:
            with open(args.key, "rb") as handle:
                seed = handle.read()
            der = ED25519_PKCS8_PREFIX + seed
            fd = os.open(pem_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as handle:
                handle.write("-----BEGIN PRIVATE KEY-----\n"
                             + base64.encodebytes(der).decode("ascii")
                             + "-----END PRIVATE KEY-----\n")
            key_path = pem_path

        cmd = [
            sys.executable, SIGN_TOOL, "sign",
            "--key", key_path,
            "--node", slug,
            "--endpoint", endpoint,
            "--inner-router-v4", inner_router,
            "--inner-resolver-v4", inner_resolver,
            "--static-pub", base64.b64encode(bytes.fromhex(static_hex)).decode(),
            "--auth-ed25519", base64.b64encode(bytes.fromhex(auth_ed_hex)).decode(),
            "--auth-mldsa65", base64.b64encode(bytes.fromhex(auth_ml_hex)).decode(),
            "--gateway-id-text", gateway_id,
            "--admission-secret-file", secret_path,
            "--admission-gen", str(args.admission_gen),
            "--seq", str(args.seq),
            "--prev-seq", args.prev_seq,
            "--kid", "g1",
            "--ttl", str(args.ttl),
            "--json",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            sys.stderr.write(res.stderr)
            die(f"winn3_sign_descriptor.py refused to sign {slug} "
                f"(exit {res.returncode})", res.returncode or 2)
        try:
            signed = json.loads(res.stdout)
        except json.JSONDecodeError as exc:
            die(f"winn3_sign_descriptor.py printed unreadable JSON: {exc}", 3)
    finally:
        for path in (secret_path, pem_path):
            try:
                os.unlink(path)
            except OSError:
                pass
        try:
            os.rmdir(work)
        except OSError:
            pass

    result = {slug: signed}
    try:
        fd = os.open(
            args.out,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
    except FileExistsError:
        die("--out already exists; choose a new output path")
    except OSError:
        die("could not create the owner-only output file", 3)
    with os.fdopen(fd, "w") as handle:
        os.fchmod(handle.fileno(), 0o600)
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")

    print(f"Emergency g1 descriptor signed for {slug}: "
          f"kid=g1 seq={signed.get('seq')} "
          f"previous_seq={signed.get('previous_seq')} "
          f"admission_gen={signed.get('admission_gen')}")
    print(f"Result written to {args.out} (mode 0600)")
    print("Register it with POST /admin/nodes/winn3/descriptor "
          "(see the module docstring for the exact curl).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
