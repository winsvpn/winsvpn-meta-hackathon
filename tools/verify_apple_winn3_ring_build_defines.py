#!/usr/bin/env python3
"""Assert the reviewed Winn3 descriptor ring reached THIS Xcode build.

# Why this runs inside the Xcode build and not next to the producer

`tools/apple_runtime_smoke.sh` turns `WINS_WINN3_DESCRIPTOR_PUBKEY_G1..G3` into
`--dart-define` arguments and hands them to `flutter build`. Everything after
that point is Flutter's business: the tool writes the defines into
`ios/Flutter/Generated.xcconfig` (and `macos/Flutter/ephemeral/
Flutter-Generated.xcconfig`) as `DART_DEFINES`, a comma-joined list of
base64-encoded `NAME=VALUE` pairs, and `gen_snapshot` freezes them into the AOT
payload as the `String.fromEnvironment` constants
`lib/winn_protocol_dispatch.dart` reads.

An argument on a command line is not evidence. `DART_DEFINES` in the build that
is actually compiling is. This gate reads that setting from the Xcode script
phase environment, which is the last point where the ring is still legible
before it becomes machine code, and refuses the build if what arrived is not
the reviewed ring.

It also covers the path no producer script guards at all: this repository
drives Xcode directly from `tools/run_apple_current_ios_build_only.applescript`
and friends. Those never touch `apple_runtime_smoke.sh`, so before this gate
existed an operator-driven archive could ship a Winn3 release with no ring
compiled in and nothing anywhere would say so.

# What "wrong ring" looks like

A build carrying no ring reports `descriptor-no-verification-keys-compiled` and
refuses every descriptor. A build carrying keys but no
`WINS_WINN3_DESCRIPTOR_RING_SHA256`, or the ceremony MANIFEST digest instead of
the ring identity, reports `descriptor-verification-ring-identity-mismatch` and
also refuses every descriptor -- `Winn3DescriptorKeyRing.attestsExpectedIdentity`
returns false for an empty string exactly as it does for a wrong one. All three
compile, sign, upload and install perfectly. The only symptom is a fleet that
silently cannot connect over standalone v3.

The manifest digest is a specific enough trap to name it: it is spelled
`ring_sha256` inside the ceremony manifest and is NOT the value the client
attests. This gate identifies it by name rather than reporting a generic
mismatch.

# Public material only

Descriptor verification keys are public by construction. Nothing here reads,
needs, or accepts a private key.
"""

from __future__ import annotations

import base64
import binascii
import os
import pathlib
import re
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
IDENTITY_TOOL = ROOT / "tools" / "winn3_descriptor_ring_identity.py"
RING_DEFINES_TOOL = ROOT / "tools" / "winn3_descriptor_ring_defines.py"

PUBKEY_DEFINE = re.compile(r"^WINS_WINN3_DESCRIPTOR_PUBKEY_(G[123])$")
RING_SHA256_DEFINE = "WINS_WINN3_DESCRIPTOR_RING_SHA256"
ENABLED_PLATFORMS_DEFINE = "WINS_WINN3_ENABLED_PLATFORMS"
HEX64 = re.compile(r"^[0-9a-f]{64}$")

# Xcode's own name for the SDK being built, mapped to the platform token the
# Dart side gates on. `iphonesimulator` is deliberately included: a simulator
# build of a Winn3 release is still an iOS build and must carry the same ring.
PLATFORM_NAME_TO_TOKEN = {
    "iphoneos": "ios",
    "iphonesimulator": "ios",
    "macosx": "macos",
}

EXIT_FAILURE = 65


class GateError(Exception):
    """A build that must not continue."""


def decode_dart_defines(raw: str) -> dict[str, str]:
    """Decode Xcode's `DART_DEFINES` into a NAME -> VALUE mapping.

    Flutter emits one base64 blob of `NAME=VALUE` per define, joined with
    commas. Anything that does not decode is a corrupted setting, not a define
    to skip quietly.
    """
    defines: dict[str, str] = {}
    for index, encoded in enumerate(raw.split(",")):
        encoded = encoded.strip()
        if not encoded:
            continue
        try:
            decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError) as error:
            raise GateError(
                f"DART_DEFINES entry {index} is not base64 of UTF-8 text: {error}"
            ) from error
        name, separator, value = decoded.partition("=")
        if not separator:
            raise GateError(f"DART_DEFINES entry {index} carries no '=': {name!r}")
        if name in defines and defines[name] != value:
            # Flutter keeps the last occurrence. Two disagreeing values for one
            # ring define means two callers each believed they set it.
            raise GateError(f"DART_DEFINES defines {name} twice with different values")
        defines[name] = value
    return defines


def run_tool(tool: pathlib.Path, arguments: list[str]) -> str:
    if not tool.is_file():
        raise GateError(f"missing required tool: {tool}")
    result = subprocess.run(
        [sys.executable, str(tool), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise GateError(
            f"{tool.name} failed (exit {result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout.strip()


def ceremony_manifest_sha256() -> str:
    """The digest that is NOT the ring identity, read from the one file that pins it."""
    import json

    payload = json.loads(run_tool(RING_DEFINES_TOOL, ["json"]))
    return str(payload.get("ceremony_manifest_sha256", "")).lower()


def check(defines: dict[str, str], platform_name: str) -> str:
    pubkeys: dict[str, str] = {}
    for name, value in defines.items():
        match = PUBKEY_DEFINE.fullmatch(name)
        if match:
            pubkeys[match.group(1)] = value
    if not pubkeys:
        raise GateError(
            "Winn3 descriptor verification ring ABSENT from this build: DART_DEFINES "
            "carries no WINS_WINN3_DESCRIPTOR_PUBKEY_G1..G3. The resulting app would "
            "report descriptor-no-verification-keys-compiled and refuse every "
            "descriptor. Source the ring from tools/winn3_descriptor_ring_defines.py."
        )

    compiled_identity = defines.get(RING_SHA256_DEFINE, "").strip().lower()
    if not compiled_identity:
        raise GateError(
            f"{RING_SHA256_DEFINE} is not in DART_DEFINES. Keys without an identity "
            "still fail attestsExpectedIdentity(), so the app would report "
            "descriptor-verification-ring-identity-mismatch and refuse every "
            "descriptor."
        )
    if not HEX64.fullmatch(compiled_identity):
        raise GateError(
            f"{RING_SHA256_DEFINE} is not a lowercase hex sha256: {compiled_identity!r}"
        )

    # Recomputed from the keys THIS build actually carries, through the single
    # implementation of the digest the client attests against. A swapped or
    # dropped slot changes this value and nothing else has to notice.
    computed_identity = run_tool(
        IDENTITY_TOOL,
        [
            f"--dart-define=WINS_WINN3_DESCRIPTOR_PUBKEY_{slot}={pubkeys[slot]}"
            for slot in sorted(pubkeys)
        ],
    )
    reviewed_identity = run_tool(RING_DEFINES_TOOL, ["identity"])

    if compiled_identity == ceremony_manifest_sha256():
        raise GateError(
            f"{RING_SHA256_DEFINE} is the ceremony MANIFEST digest, not the ring "
            "identity. The manifest spells it `ring_sha256`, which is the trap. "
            f"The client attests {reviewed_identity}; a build carrying the manifest "
            "digest rejects every descriptor at run time."
        )
    if computed_identity != compiled_identity:
        raise GateError(
            "Compiled ring identity does not describe the compiled keys. "
            f"{RING_SHA256_DEFINE}={compiled_identity} but the "
            f"{len(pubkeys)} compiled slot(s) hash to {computed_identity}."
        )
    if computed_identity != reviewed_identity:
        raise GateError(
            "This build carries a ring that is not the reviewed one. "
            f"compiled={computed_identity} reviewed={reviewed_identity}. "
            "Either the keys were substituted or the ceremony pin is stale. Do not ship."
        )

    token = PLATFORM_NAME_TO_TOKEN.get(platform_name)
    if token is None:
        raise GateError(
            f"cannot map PLATFORM_NAME={platform_name!r} to an ios/macos platform token"
        )
    enabled = [
        entry.strip()
        for entry in defines.get(ENABLED_PLATFORMS_DEFINE, "").split(",")
        if entry.strip()
    ]
    if token not in enabled:
        raise GateError(
            f"{ENABLED_PLATFORMS_DEFINE}={enabled} does not enable {token!r} for a "
            f"PLATFORM_NAME={platform_name} build. The ring would compile in and "
            "standalone v3 would still be off on this platform."
        )

    return (
        f"APPLE WINN3 RING BUILD DEFINES: PASS platform={token} "
        f"slots={len(pubkeys)} identity={computed_identity}"
    )


def main() -> int:
    platform_name = os.environ.get("PLATFORM_NAME", "").strip()
    raw_defines = os.environ.get("DART_DEFINES")
    if raw_defines is None:
        # Not "no defines": no setting at all. Under xcodebuild this means the
        # Flutter xcconfig was never included, so nothing about this build can
        # be attested.
        print(
            "APPLE WINN3 RING BUILD DEFINES: ERROR DART_DEFINES is unset. This gate "
            "must run inside an Xcode build phase that includes the Flutter "
            "Generated.xcconfig, or be given DART_DEFINES explicitly.",
            file=sys.stderr,
        )
        return EXIT_FAILURE
    try:
        print(check(decode_dart_defines(raw_defines), platform_name))
    except GateError as error:
        print(f"APPLE WINN3 RING BUILD DEFINES: ERROR {error}", file=sys.stderr)
        return EXIT_FAILURE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
