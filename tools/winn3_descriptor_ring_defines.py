#!/usr/bin/env python3
"""Single source of truth for the reviewed Winn3 descriptor ring build defines.

Every platform release producer needs the SAME four values, and until this file
existed each one got them from an operator's shell history:

  WINS_WINN3_DESCRIPTOR_PUBKEY_G1        base64, raw 32-byte Ed25519 public key
  WINS_WINN3_DESCRIPTOR_PUBKEY_G2        same
  WINS_WINN3_DESCRIPTOR_PUBKEY_G3        same
  WINS_WINN3_DESCRIPTOR_RING_SHA256      lowercase hex ring identity

Three keys typed by hand into six producers is three keys that will eventually
disagree between an APK and an IPA, and a ring that disagrees across platforms
is a fleet where some clients silently refuse every descriptor. So the bytes
live here once and every producer reads them from here.

# What the ring identity actually is

`WINS_WINN3_DESCRIPTOR_RING_SHA256` is NOT a hash of the ceremony manifest, and
it is NOT a hash of the key material. It is
`Winn3DescriptorKeyRing.identitySha256` in `lib/winn_protocol_dispatch.dart`:

    sha256( "g1=<hex32>\\n" "g2=<hex32>\\n" "g3=<hex32>\\n" )   # populated slots only

That algorithm has exactly one implementation in this repository,
`tools/winn3_descriptor_ring_identity.py`, and this file SHELLS OUT to it rather
than reimplementing six lines that would then be free to drift. The pinned
constant below is the reviewed answer; the tool is the authority; `verify`
refuses to emit anything when the two disagree.

The ceremony manifest carries its own `ring_sha256`, which is a digest of the
manifest JSON and a DIFFERENT number. Feeding that one to a build produces an
app that compiles, ships, reports `descriptor-verification-ring-identity-mismatch`
at run time, and rejects every descriptor it is handed. Both digests are
recorded below so nobody has to guess which is which again.

# Public, by design

These are public keys. Embedding them in a build is the entire point: a client
with no compiled key cannot tell a real descriptor from a forged one. The
matching private keys never appear here, are never needed by a build, and live
outside the repository. A build step that seems to want one is a design error,
not a missing export.

# Consuming this

    # bash / zsh producers (Android on macOS, Apple runtime smoke, Linux)
    eval "$(python3 tools/winn3_descriptor_ring_defines.py sh)"

    # PowerShell producers (Android on Windows, Windows installer + MSIX)
    & python tools/winn3_descriptor_ring_defines.py ps1 | Out-String | Invoke-Expression

    # GitHub Actions
    python3 tools/winn3_descriptor_ring_defines.py env >> "$GITHUB_ENV"

    # anything invoking flutter directly (flutter test, flutter run, CI matrix)
    flutter test $(python3 tools/winn3_descriptor_ring_defines.py dart-define)

`sh`/`ps1`/`env` export the three pubkeys plus
`WINS_EXPECTED_WINN3_DESCRIPTOR_RING_SHA256` -- the name the release producers
compare their own computed identity against before they will build. They
deliberately do NOT export `WINS_WINN3_DESCRIPTOR_RING_SHA256`: each producer
derives that from the pubkeys it actually collected, so the define always
describes the ring that got compiled rather than the ring somebody intended.
`dart-define` emits all four, for callers that drive flutter themselves and have
no such collector.

Setting `WINS_REQUIRE_WINN3_DESCRIPTOR_PUBKEY=1` alongside these is a per-platform
build policy decision and stays with the platform producer.
"""

from __future__ import annotations

import argparse
import base64
import json
import pathlib
import re
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
IDENTITY_TOOL = ROOT / "tools" / "winn3_descriptor_ring_identity.py"

PUBKEY_DEFINE = "WINS_WINN3_DESCRIPTOR_PUBKEY_{slot}"
RING_SHA256_DEFINE = "WINS_WINN3_DESCRIPTOR_RING_SHA256"
EXPECTED_RING_SHA256_ENV = "WINS_EXPECTED_WINN3_DESCRIPTOR_RING_SHA256"

PUBLIC_KEY_BYTES = 32

# --- reviewed ceremony output -------------------------------------------------
# Source: /Users/owner/xprize/v3-lane/ceremony/ring-manifest.json (Track B, B1).
# Public keys only. Standard base64 alphabet with padding, decoding to raw 32
# bytes, which is what `String.fromEnvironment` + `base64.decode` consume in
# lib/winn_protocol_dispatch.dart and what b64decode(validate=True) accepts in
# tools/winn3_descriptor_ring_identity.py.
CEREMONY_DOMAIN = "winsvpn-winn3-descriptor/v1"
CEREMONY_GENERATED_AT = "2026-08-18T21:42:23Z"

RING: dict[str, str] = {
    "g1": "L2mAYdYIXPCFuNoH5ntgBBubFSnnlzIAnXwKttpehaQ=",
    "g2": "eVCAHWXqUM1+m5nlVy2JR+Q4/mkYGTxlk119aiQh89M=",
    "g3": "53JhsQBxKH5DG145LcaBunOX4lbt+J7Js0oPyJnj9Q0=",
}

# The value the client compiles in and attests against at run time.
# = sha256(b"g1=<hex>\ng2=<hex>\ng3=<hex>\n")
REVIEWED_RING_SHA256 = (
    "52e91c72ca52d23059724e0a6c25c2f45bae574a85a84c884c5b7fd367cbf032"
)

# Provenance ONLY. Digest of the ceremony manifest JSON
# (sort_keys, compact separators, `ring_sha256` field removed), recorded here so
# this file can be traced back to the ceremony. This is NOT a build define and
# must never be passed as one -- see the module docstring.
CEREMONY_MANIFEST_SHA256 = (
    "29c66c18f5aef6eb064e065a5d7c3c98aa1548f758ac6d19b19a9d4a7863e7fb"
)
# ------------------------------------------------------------------------------

SLOT_ORDER = ("g1", "g2", "g3")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
# Base64 of 32 bytes is 44 characters ending in one '='. Anything with a quote,
# backslash, whitespace or shell metacharacter must never reach an `eval`.
SAFE_B64 = re.compile(r"^[A-Za-z0-9+/]{43}=$")


class RingError(SystemExit):
    def __init__(self, message: str) -> None:
        super().__init__(f"winn3_descriptor_ring_defines: {message}")


def _validate_pins() -> None:
    """Refuse to emit a ring that is malformed before anything computes on it."""
    if not HEX64.fullmatch(REVIEWED_RING_SHA256):
        raise RingError(f"REVIEWED_RING_SHA256 is not lowercase hex sha256: {REVIEWED_RING_SHA256!r}")
    if list(RING) != list(SLOT_ORDER):
        raise RingError(f"RING must carry exactly {SLOT_ORDER} in order, got {tuple(RING)}")
    seen: dict[bytes, str] = {}
    for slot in SLOT_ORDER:
        encoded = RING[slot]
        if not SAFE_B64.fullmatch(encoded):
            raise RingError(f"{slot}: not a bare 44-character standard-base64 32-byte key")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except ValueError as error:
            raise RingError(f"{slot}: invalid base64: {error}") from error
        if len(raw) != PUBLIC_KEY_BYTES:
            raise RingError(f"{slot}: decodes to {len(raw)} bytes, expected {PUBLIC_KEY_BYTES}")
        canonical = base64.b64encode(raw).decode("ascii")
        if canonical != encoded:
            # 43 base64 characters carry 258 bits for a 256-bit key, so the last
            # character has two slack bits that neither Python nor Dart looks at:
            # `...haQ=` and `...haR=` decode to the SAME key. Harmless to the
            # verifier, corrosive to review -- two producers would then ship
            # define strings that differ byte-for-byte for one identical ring.
            raise RingError(
                f"{slot}: non-canonical base64 (trailing bits set). "
                f"pinned={encoded} canonical={canonical}"
            )
        if raw in seen:
            # Two slots holding one key is a ring of size one wearing a costume:
            # it would still pass every length and base64 check.
            raise RingError(f"{slot}: duplicates the key already pinned for {seen[raw]}")
        seen[raw] = slot


def dart_define_arguments() -> list[str]:
    """The `--dart-define=` pubkey arguments, in g1 g2 g3 order."""
    return [
        f"--dart-define={PUBKEY_DEFINE.format(slot=slot.upper())}={RING[slot]}"
        for slot in SLOT_ORDER
    ]


def computed_identity() -> str:
    """Ring identity as the release producers compute it, from the one implementation."""
    if not IDENTITY_TOOL.is_file():
        raise RingError(f"missing ring identity tool: {IDENTITY_TOOL}")
    result = subprocess.run(
        [sys.executable, str(IDENTITY_TOOL), *dart_define_arguments()],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RingError(
            f"ring identity tool failed (exit {result.returncode}): {result.stderr.strip()}"
        )
    identity = result.stdout.strip()
    if not HEX64.fullmatch(identity):
        raise RingError(f"ring identity tool returned a non-sha256 value: {identity!r}")
    return identity


def verified_identity() -> str:
    """Recompute and confirm the pin. Every emitter goes through here."""
    _validate_pins()
    identity = computed_identity()
    if identity != REVIEWED_RING_SHA256:
        raise RingError(
            "reviewed ring identity does not match the pinned public keys. "
            f"computed={identity} pinned={REVIEWED_RING_SHA256}. "
            "Either the keys were edited without re-review, or the pin is stale. "
            "Do not build."
        )
    return identity


def _exported_pairs(identity: str) -> list[tuple[str, str]]:
    pairs = [(PUBKEY_DEFINE.format(slot=slot.upper()), RING[slot]) for slot in SLOT_ORDER]
    pairs.append((EXPECTED_RING_SHA256_ENV, identity))
    return pairs


def emit_sh(identity: str) -> str:
    # Single quotes are safe: SAFE_B64 and HEX64 already exclude quotes entirely.
    return "\n".join(f"export {name}='{value}'" for name, value in _exported_pairs(identity))


def emit_ps1(identity: str) -> str:
    return "\n".join(f"$env:{name} = '{value}'" for name, value in _exported_pairs(identity))


def emit_env(identity: str) -> str:
    return "\n".join(f"{name}={value}" for name, value in _exported_pairs(identity))


def emit_dart_define(identity: str) -> str:
    return "\n".join(
        [*dart_define_arguments(), f"--dart-define={RING_SHA256_DEFINE}={identity}"]
    )


def emit_json(identity: str) -> str:
    return json.dumps(
        {
            "domain": CEREMONY_DOMAIN,
            "generated_at": CEREMONY_GENERATED_AT,
            "slots": [{"id": slot, "pubkey_b64": RING[slot]} for slot in SLOT_ORDER],
            "ring_sha256": identity,
            "ceremony_manifest_sha256": CEREMONY_MANIFEST_SHA256,
            "defines": {
                **{PUBKEY_DEFINE.format(slot=slot.upper()): RING[slot] for slot in SLOT_ORDER},
                RING_SHA256_DEFINE: identity,
            },
        },
        indent=2,
        sort_keys=True,
    )


def emit_identity(identity: str) -> str:
    return identity


def emit_verify(identity: str) -> str:
    slots = " ".join(SLOT_ORDER)
    return (
        f"WINN3 RING DEFINES: PASS slots={slots} identity={identity} "
        f"domain={CEREMONY_DOMAIN}"
    )


FORMATS = {
    "sh": emit_sh,
    "ps1": emit_ps1,
    "env": emit_env,
    "dart-define": emit_dart_define,
    "json": emit_json,
    "identity": emit_identity,
    "verify": emit_verify,
}


def main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="winn3_descriptor_ring_defines.py",
        description=(
            "Emit the reviewed Winn3 descriptor ring build defines. Every format "
            "recomputes the ring identity from the pinned public keys first and "
            "emits nothing if it disagrees with the reviewed value."
        ),
    )
    parser.add_argument(
        "format",
        nargs="?",
        default="sh",
        choices=sorted(FORMATS),
        help=(
            "sh: POSIX exports for eval. ps1: PowerShell $env: assignments. "
            "env: NAME=value for $GITHUB_ENV. dart-define: all four "
            "--dart-define arguments, one per line. json: machine-readable. "
            "identity: the ring sha256 alone. verify: one-line receipt."
        ),
    )
    parsed = parser.parse_args(arguments)
    print(FORMATS[parsed.format](verified_identity()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
