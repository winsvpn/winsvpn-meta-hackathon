#!/usr/bin/env python3
"""Compute the canonical public identity of Winn3 descriptor key defines."""

from __future__ import annotations

import base64
import hashlib
import re
import sys


DEFINE = re.compile(
    r"^--dart-define=WINS_WINN3_DESCRIPTOR_PUBKEY_(G[123])=(.+)$"
)


def main(arguments: list[str]) -> int:
    keys: dict[str, bytes] = {}
    for argument in arguments:
        match = DEFINE.fullmatch(argument)
        if not match:
            raise SystemExit(f"unexpected descriptor-ring argument: {argument}")
        slot = match.group(1).lower()
        try:
            raw = base64.b64decode(match.group(2), validate=True)
        except ValueError as error:
            raise SystemExit(f"invalid {slot} base64: {error}") from error
        if len(raw) != 32:
            raise SystemExit(f"invalid {slot} length: {len(raw)}")
        if slot in keys:
            raise SystemExit(f"duplicate descriptor-ring slot: {slot}")
        keys[slot] = raw
    if not keys:
        raise SystemExit("descriptor verification ring is empty")
    canonical = b"".join(
        slot.encode("ascii") + b"=" + keys[slot].hex().encode("ascii") + b"\n"
        for slot in ("g1", "g2", "g3")
        if slot in keys
    )
    print(hashlib.sha256(canonical).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
