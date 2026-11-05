#!/usr/bin/env python3
"""Offline check of a signed winn/3 descriptor envelope before it is published.

A rotation signs a descriptor on the operator's machine and uploads it later.
This runs the REPO hub's own validate_winn3_descriptor_payload and
winn3_verify_descriptor_signature over the envelope (the hub module is
extracted from server/wins_control_plane_setup_ONETOUCH.sh by the same harness
the hub test battery uses, and openssl verifies), against the compiled ring in
tools/winn3_descriptor_ring_defines.py, and then checks that the payload
carries exactly what the rotation staged: the node, seq, admission_gen, the
successor public keys, and the admission secret file's bytes.

It prints public fields only. admission_secret is compared, never printed.
The deployed hub runs its own copy of these checks at upload; this is the
check that fails on the operator's machine instead of in the cut window.

Usage:
  tools/winn3_verify_descriptor_envelope.py --envelope-dir DIR --node SLUG \\
      --expect-seq N --expect-admission-gen G \\
      [--staged-dir OUT] [--ring-pub g1=B64 ...]

  DIR holds descriptor_payload_b64.txt and descriptor_sig_b64.txt as written
  by `winn3_sign_descriptor.py sign --out-dir`. OUT is the local directory of
  `winn3_gateway_provision_keys.sh --generate-successor` (static_pub.b64,
  auth_ed25519.b64, auth_mldsa65.b64, admission.key). --ring-pub replaces the
  compiled ring and exists for fixture tests only.

Exit codes: 0 every check passed, 1 a check failed, 2 bad input.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBLIC_FIELDS = (
    "v", "alg", "kid", "node", "seq", "admission_gen", "iat", "not_after",
    "tag_size", "padding", "bucket_window_s", "max_skew_s",
    "inner_router_v4", "inner_resolver_v4", "gateway_id",
)


def read_text(path: str) -> str:
    with open(path, encoding="ascii") as handle:
        return handle.read().strip()


def admission_b64_from_file(path: str) -> str:
    """The encoding the signer uses: file bytes, one trailing CR/LF removed."""
    with open(path, "rb") as handle:
        raw = handle.read()
    if raw.endswith(b"\r\n"):
        raw = raw[:-2]
    elif raw.endswith(b"\n") or raw.endswith(b"\r"):
        raw = raw[:-1]
    return base64.b64encode(raw).decode()


def load_repo_hub(ring: dict[str, str]):
    sys.path.insert(0, os.path.join(ROOT, "server"))
    for slot in ("g1", "g2", "g3"):
        os.environ.pop(f"WINN3_DESCRIPTOR_PUBKEY_{slot.upper()}", None)
    import test_account_deletion_hub as harness  # noqa: E402  (hub loader)
    settings = {f"WINN3_DESCRIPTOR_PUBKEY_{slot.upper()}": key for slot, key in ring.items()}
    # The hub logs at import; keep this tool's stdout to its own lines.
    with contextlib.redirect_stdout(io.StringIO()):
        return harness.load_hub(**settings)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--envelope-dir", required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--expect-seq", type=int, required=True)
    parser.add_argument("--expect-admission-gen", type=int, required=True)
    parser.add_argument("--staged-dir")
    parser.add_argument("--ring-pub", action="append", default=[], metavar="SLOT=B64")
    args = parser.parse_args(argv)

    if args.ring_pub:
        ring = {}
        for item in args.ring_pub:
            slot, _, key = item.partition("=")
            if slot not in ("g1", "g2", "g3") or not key:
                parser.error(f"--ring-pub {item!r} is not SLOT=B64")
            ring[slot] = key
        ring_source = "override (fixture)"
    else:
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        import winn3_descriptor_ring_defines as ring_defines  # noqa: E402
        ring = dict(ring_defines.RING)
        ring_source = "compiled ring (tools/winn3_descriptor_ring_defines.py)"

    try:
        payload_b64 = read_text(os.path.join(args.envelope_dir, "descriptor_payload_b64.txt"))
        sig_b64 = read_text(os.path.join(args.envelope_dir, "descriptor_sig_b64.txt"))
        payload_bytes = base64.b64decode(payload_b64, validate=True)
        sig_bytes = base64.b64decode(sig_b64, validate=True)
        decoded = json.loads(payload_bytes.decode("utf-8"))
    except (OSError, ValueError) as exc:
        print(f"REFUSED: cannot read the envelope: {type(exc).__name__}", file=sys.stderr)
        return 2

    failures = []
    hub = load_repo_hub(ring)
    try:
        normalized = hub.validate_winn3_descriptor_payload(decoded, slug=args.node.strip().lower())
        print("hub validate_winn3_descriptor_payload: ok")
    except hub.Winn3ContractError as exc:
        # Reason and field NAMES only, as the hub itself reports them.
        failures.append(f"hub validator refused: reason={exc.reason} fields={','.join(exc.keys) or '-'}")
        normalized = None
    if normalized is not None:
        try:
            slot = hub.winn3_verify_descriptor_signature(payload_bytes, sig_bytes, normalized["kid"])
            print(f"hub winn3_verify_descriptor_signature: ok accepted_slot={slot} ring={ring_source}")
        except hub.Winn3ContractError as exc:
            failures.append(f"signature refused: reason={exc.reason}")

    for field in PUBLIC_FIELDS:
        if field in decoded:
            print(f"payload {field} {decoded[field]}")
    print(f"payload endpoint_present {bool(decoded.get('endpoint'))}")
    print(f"payload admission_secret_b64_length {len(str(decoded.get('admission_secret', '')))}")

    if decoded.get("node") != args.node.strip().lower():
        failures.append("node does not match --node")
    if decoded.get("seq") != args.expect_seq:
        failures.append(f"seq is {decoded.get('seq')}, expected {args.expect_seq}")
    if decoded.get("admission_gen") != args.expect_admission_gen:
        failures.append(
            f"admission_gen is {decoded.get('admission_gen')}, expected {args.expect_admission_gen}")

    if args.staged_dir:
        for field, name in (("static_pub", "static_pub.b64"),
                            ("auth_ed25519", "auth_ed25519.b64"),
                            ("auth_mldsa65", "auth_mldsa65.b64")):
            try:
                staged = read_text(os.path.join(args.staged_dir, name))
            except OSError:
                failures.append(f"{name} missing from --staged-dir")
                continue
            same = decoded.get(field) == staged
            print(f"staged {field} matches payload: {'yes' if same else 'NO'}")
            if not same:
                failures.append(f"{field} differs from the staged {name}")
        try:
            same = decoded.get("admission_secret") == admission_b64_from_file(
                os.path.join(args.staged_dir, "admission.key"))
        except OSError:
            failures.append("admission.key missing from --staged-dir")
        else:
            print(f"staged admission.key matches payload: {'yes' if same else 'NO'}")
            if not same:
                failures.append("admission_secret differs from the staged admission.key")

    for failure in failures:
        print(f"FAIL: {failure}")
    print("VERDICT envelope " + ("ok" if not failures else "REFUSED"))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
