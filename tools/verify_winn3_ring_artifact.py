#!/usr/bin/env python3
"""Verify that release payload bytes carry the reviewed Winn3 ring identity."""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys
import tempfile
import zipfile


def raw_file_contains(path: pathlib.Path, needle: bytes) -> bool:
    if not path.is_file():
        return False
    try:
        with path.open("rb") as handle:
            overlap = b""
            while chunk := handle.read(1024 * 1024):
                window = overlap + chunk
                if needle in window:
                    return True
                overlap = window[-(len(needle) - 1) :] if len(needle) > 1 else b""
    except OSError:
        return False
    return False


def allowed_zip_member(name: str) -> bool:
    normalized = name.replace("\\", "/").lstrip("/")
    return bool(
        re.fullmatch(r"lib/[^/]+/libapp\.so", normalized)
        or re.fullmatch(r"base/lib/[^/]+/libapp\.so", normalized)
        or re.fullmatch(r"Payload/[^/]+\.app/Frameworks/App\.framework/App", normalized)
        or re.fullmatch(
            r"Payload/[^/]+\.app/Frameworks/App\.framework/Versions/A/App",
            normalized,
        )
        or normalized == "data/app.so"
    )


def allowed_macos_aot(path: pathlib.Path) -> bool:
    normalized = path.as_posix()
    return bool(
        re.search(r"\.app/Contents/Frameworks/App\.framework/App$", normalized)
        or re.search(
            r"\.app/Contents/Frameworks/App\.framework/Versions/A/App$",
            normalized,
        )
    )


def artifact_contains(path: pathlib.Path, needle: bytes) -> bool:
    if path.suffix.lower() in {".apk", ".aab", ".ipa", ".zip", ".msix"}:
        try:
            with zipfile.ZipFile(path) as archive:
                candidates = [name for name in archive.namelist() if allowed_zip_member(name)]
                return bool(candidates) and any(
                    needle in archive.read(name) for name in candidates
                )
        except (OSError, zipfile.BadZipFile):
            return False
    if path.suffix.lower() == ".pkg":
        with tempfile.TemporaryDirectory(prefix="wins-ring-pkg-") as temporary:
            expanded = pathlib.Path(temporary) / "expanded"
            result = subprocess.run(
                ["pkgutil", "--expand-full", str(path), str(expanded)],
                check=False,
                capture_output=True,
            )
            candidates = [
                item
                for item in expanded.rglob("App")
                if item.is_file() and allowed_macos_aot(item)
            ]
            return result.returncode == 0 and bool(candidates) and any(
                raw_file_contains(item, needle) for item in candidates
            )
    # Directory-wide scans are intentionally refused. A receipt or sidecar in
    # the release directory must never attest bytes absent from the compiled
    # Flutter AOT payload. Callers pass the exact app.so/libapp.so file.
    return raw_file_contains(path, needle)


def main(arguments: list[str]) -> int:
    if len(arguments) < 2 or not re.fullmatch(r"[0-9a-fA-F]{64}", arguments[0]):
        raise SystemExit("usage: verify_winn3_ring_artifact.py SHA256 ARTIFACT...")
    identity = arguments[0].lower()
    needle = identity.encode("ascii")
    for raw in arguments[1:]:
        artifact = pathlib.Path(raw).resolve()
        if not artifact.exists() or not artifact_contains(artifact, needle):
            raise SystemExit(f"ERROR: artifact lacks Winn3 ring identity {identity}: {artifact}")
        print(f"WINN3 RING ARTIFACT: PASS identity={identity} artifact={artifact}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
