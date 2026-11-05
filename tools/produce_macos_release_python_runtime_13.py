#!/usr/bin/env python3
"""Authenticate and execute the production macOS 13 ReleasePython producer."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import stat
import sys
import types


ROOT = Path(__file__).resolve().parents[1]
CUSTODY = ROOT / "tools/macos_release_python_runtime.custody.json"
IMPLEMENTATION = "tools/macos_release_python_runtime_production.py"
EXPECTED_CUSTODY_SHA256 = "1f8f366d9be1b803dd6bd3b778f2a919da3690ed5b48f40d8bbbf79d22d43025"
MAXIMUM_CLOSURE_FILE_SIZE = 8 * 1024 * 1024
REQUIRED_CLOSURE = {
    "tools/build_macos_release_python_inputs_manifest.py",
    "tools/install_macos_release_python_inputs.py",
    "tools/macos_release_python_entrypoint.c",
    "tools/macos_release_python_inputs.custody.json",
    "tools/macos_release_python_owner_launcher.c",
    "tools/macos_release_python_runtime_production.py",
    "tools/materialize_macos_release_python_psf_candidate.py",
    "tools/release_python_archive_custody.sh",
    "tools/test_macos_release_python_inputs_custody.py",
    "tools/test_macos_release_python_owner_launcher.py",
    "tools/test_macos_release_python_runtime_receipt.py",
    "tools/test_release_gate_determinism.py",
    "tools/test_release_python_archive_custody.py",
    "tools/toolchain-pins.json",
}


class EntrypointError(RuntimeError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def held_regular_bytes(path: Path, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size < 1
            or metadata.st_size > maximum
        ):
            raise EntrypointError(f"authenticated closure member is unsafe: {path}")
        blocks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 1024 * 1024))
            if not block:
                raise EntrypointError(f"authenticated closure member was truncated: {path}")
            blocks.append(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise EntrypointError(f"authenticated closure member grew while held: {path}")
        return b"".join(blocks)
    finally:
        os.close(descriptor)


def authenticated_closure() -> dict[str, bytes]:
    custody_bytes = held_regular_bytes(CUSTODY, 2 * 1024 * 1024)
    if digest(custody_bytes) != EXPECTED_CUSTODY_SHA256:
        raise EntrypointError("ReleasePython custody metadata digest is not the reviewed value")
    try:
        document = json.loads(custody_bytes.decode("ascii"))
        records = document["producer_closure"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise EntrypointError(f"ReleasePython producer closure is unreadable: {exc}") from exc
    if (
        document.get("contract") != "winsvpn-macos-release-python-runtime-v2"
        or document.get("schema_version") != 3
        or type(records) is not list
        or len(records) != len(REQUIRED_CLOSURE)
    ):
        raise EntrypointError("ReleasePython producer closure contract is invalid")
    sources = {"tools/macos_release_python_runtime.custody.json": custody_bytes}
    for record in records:
        if type(record) is not dict or set(record) != {"path", "sha256"}:
            raise EntrypointError("ReleasePython producer closure record is invalid")
        relative = record["path"]
        expected = record["sha256"]
        pure = PurePosixPath(relative) if isinstance(relative, str) else PurePosixPath(".")
        if (
            not isinstance(relative, str)
            or not isinstance(expected, str)
            or len(expected) != 64
            or any(character not in "0123456789abcdef" for character in expected)
            or pure.is_absolute()
            or not pure.parts
            or pure.parts[0] != "tools"
            or any(part in {"", ".", ".."} for part in pure.parts)
            or relative in sources
        ):
            raise EntrypointError("ReleasePython producer closure path or digest is invalid")
        payload = held_regular_bytes(ROOT.joinpath(*pure.parts), MAXIMUM_CLOSURE_FILE_SIZE)
        if digest(payload) != expected:
            raise EntrypointError(f"ReleasePython producer closure digest mismatch: {relative}")
        sources[relative] = payload
    if set(sources) - {"tools/macos_release_python_runtime.custody.json"} != REQUIRED_CLOSURE:
        raise EntrypointError("ReleasePython producer closure path inventory is not exact")
    return sources


def main() -> int:
    try:
        sources = authenticated_closure()
        implementation_path = ROOT / IMPLEMENTATION
        module = types.ModuleType("winsvpn_macos_release_python_runtime_production")
        module.__file__ = str(implementation_path)
        code = compile(sources[IMPLEMENTATION], str(implementation_path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
        return module.main(authenticated_sources=sources)
    except (EntrypointError, OSError, SyntaxError, ValueError) as exc:
        print(f"ReleasePython producer entrypoint: FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
