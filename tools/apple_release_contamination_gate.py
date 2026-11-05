#!/usr/bin/env python3
"""Fail closed when an Apple release artifact contains live-smoke build state.

The gate is intentionally artifact-only. It does not consult the current process
environment, because an xcarchive can be produced by one process and exported or
uploaded by a later process. Distribution producers stamp the host Info.plist
with the reviewed contract below. The gate also scans the Flutter AOT image for
markers that are retained when the compile-time live-smoke branch is enabled.

The marker scan is a defence in depth check, not a general Dart define decoder.
Arbitrary Dart AOT constants cannot be reconstructed reliably after obfuscation.
The mandatory plist contract is therefore the primary proof that the producer
observed an empty smoke PIN and disabled live-smoke compilation. Missing or
malformed metadata is rejected, including archives made before this contract.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import os
import pathlib
import plistlib
import posixpath
import stat
import subprocess
import sys
import tempfile
import zipfile


CONTRACT_KEY = "WinsReleaseContaminationContract"
CONTRACT_VALUE = "apple-release-no-live-smoke-v1"
LIVE_SMOKE_KEY = "WinsReleaseLiveSmokeCompiled"
SMOKE_PIN_KEY = "WinsReleaseSmokePinEmbedded"

# These values live exclusively in the release live-smoke branch. A safe
# Flutter release build tree-shakes them from App.framework/App. Do not include
# a real or fixture PIN in this list or in diagnostic output.
FORBIDDEN_AOT_MARKERS = (
    b"WINS_APPLE_LIVE_TUNNEL_SMOKE_RESULT ",
    b"apple_live_tunnel_smoke_pin_missing_or_invalid",
    b"Apple live tunnel smoke gate scheduled.",
)
# The embedded Watch app's companion smoke hook (R22 Y3 D2) is compiled only
# where DEBUG is defined; a release Watch app must not carry its marker.
FORBIDDEN_WATCH_MARKERS = (b"wins_watch_companion_smoke",)
LIVE_SMOKE_DEFINE_PREFIXES = (
    "WINS_APPLE_LIVE_TUNNEL_SMOKE",
    "WINS_IOS_LIVE_TUNNEL_SMOKE",
)
MAX_MEMBERS = 200_000
MAX_MEMBER_BYTES = 4 * 1024**3
MAX_EXPANDED_BYTES = 16 * 1024**3


class AppleReleaseContaminationError(RuntimeError):
    """Raised when exact artifact bytes cannot prove release-safe state."""


def verify_dart_defines_xcconfig(path: pathlib.Path) -> None:
    """Verify the producer input that is represented by the plist attestation."""

    try:
        lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
    except (OSError, UnicodeError) as exc:
        raise AppleReleaseContaminationError(
            "Flutter generated build metadata is missing or invalid"
        ) from exc
    values = [
        line.split("=", 1)[1].strip()
        for line in lines
        if line.strip().startswith("DART_DEFINES=")
    ]
    if not values:
        return
    if len(values) != 1:
        raise AppleReleaseContaminationError(
            "Flutter generated build metadata must contain one DART_DEFINES value"
        )
    for encoded in values[0].split(","):
        encoded = encoded.strip()
        if not encoded or encoded == "$(inherited)":
            continue
        try:
            decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise AppleReleaseContaminationError(
                "Flutter generated DART_DEFINES contains an invalid entry"
            ) from exc
        key, separator, value = decoded.partition("=")
        if not separator or not key:
            raise AppleReleaseContaminationError(
                "Flutter generated DART_DEFINES contains a malformed entry"
            )
        if key == "WINS_ENABLE_EXTERNAL_PAYMENT_LINKS" and value.strip().lower() not in {"", "0", "false"}:
            raise AppleReleaseContaminationError(
                "Apple release build metadata enables external payment links"
            )
        if key in LIVE_SMOKE_DEFINE_PREFIXES:
            if value.strip().lower() not in {"", "0", "false"}:
                raise AppleReleaseContaminationError(
                    "Flutter build metadata enables Apple live-smoke compilation"
                )
            continue
        if key.startswith(tuple(prefix + "_" for prefix in LIVE_SMOKE_DEFINE_PREFIXES)):
            raise AppleReleaseContaminationError(
                "Flutter build metadata contains Apple live-smoke parameters"
            )


def _read_plist(path: pathlib.Path) -> dict[str, object]:
    try:
        value = plistlib.loads(path.read_bytes())
    except (OSError, plistlib.InvalidFileException) as exc:
        raise AppleReleaseContaminationError(
            "host Info.plist is missing or invalid"
        ) from exc
    if not isinstance(value, dict):
        raise AppleReleaseContaminationError("host Info.plist is not a dictionary")
    return value


def _require_clean_metadata(info: dict[str, object]) -> None:
    if info.get(CONTRACT_KEY) != CONTRACT_VALUE:
        raise AppleReleaseContaminationError(
            "release contamination contract is missing or unsupported"
        )
    false_values = (False, "NO", "false", "0")
    if info.get(LIVE_SMOKE_KEY) not in false_values:
        raise AppleReleaseContaminationError(
            "artifact metadata does not prove live-smoke compilation is disabled"
        )
    if info.get(SMOKE_PIN_KEY) not in false_values:
        raise AppleReleaseContaminationError(
            "artifact metadata does not prove smoke PIN material is absent"
        )


def _contains_marker(path: pathlib.Path, marker: bytes) -> bool:
    overlap = max(len(marker) - 1, 0)
    tail = b""
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    return False
                block = tail + chunk
                if marker in block:
                    return True
                tail = block[-overlap:] if overlap else b""
    except OSError as exc:
        raise AppleReleaseContaminationError(
            "Flutter AOT payload could not be inspected"
        ) from exc


def _require_clean_aot(app: pathlib.Path, platform: str) -> None:
    if platform == "ios":
        candidates = [app / "Frameworks" / "App.framework" / "App"]
    elif platform == "macos":
        candidates = [app / "Contents" / "Frameworks" / "App.framework" / "App"]
    else:
        raise AppleReleaseContaminationError("unsupported Apple platform")
    aot_images = [candidate for candidate in candidates if candidate.is_file()]
    if len(aot_images) != 1 or aot_images[0].stat().st_size <= 0:
        raise AppleReleaseContaminationError(
            "artifact does not contain exactly one non-empty Flutter AOT payload"
        )
    for marker in FORBIDDEN_AOT_MARKERS:
        if _contains_marker(aot_images[0], marker):
            raise AppleReleaseContaminationError(
                "Flutter AOT payload retains compiled live-smoke behavior"
            )


def _require_clean_watch(app: pathlib.Path) -> None:
    watch_root = app / "Watch"
    if not os.path.lexists(watch_root):
        return
    if watch_root.is_symlink() or not watch_root.is_dir():
        raise AppleReleaseContaminationError("embedded Watch directory is invalid")
    for directory, subdirectories, files in os.walk(watch_root, followlinks=False):
        # A symlink is never walked (directory links) or read (file links), so a
        # hook-carrying binary behind one would pass. A Watch app bundle has no
        # legitimate links, and verify_ios_release_artifact refuses them too.
        for name in (*subdirectories, *files):
            if (pathlib.Path(directory) / name).is_symlink():
                raise AppleReleaseContaminationError(
                    "embedded Watch app contains a symlink"
                )
        for name in files:
            path = pathlib.Path(directory) / name
            if not stat.S_ISREG(path.lstat().st_mode):
                continue
            for marker in FORBIDDEN_WATCH_MARKERS:
                if _contains_marker(path, marker):
                    raise AppleReleaseContaminationError(
                        "embedded Watch app retains the debug companion smoke hook"
                    )


def verify_app_bundle(app: pathlib.Path, platform: str) -> None:
    if not app.is_dir() or app.suffix != ".app":
        raise AppleReleaseContaminationError("Apple host app bundle is missing")
    info_path = app / ("Info.plist" if platform == "ios" else "Contents/Info.plist")
    _require_clean_metadata(_read_plist(info_path))
    _require_clean_aot(app, platform)
    if platform == "ios":
        _require_clean_watch(app)


def _safe_zip_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    members = archive.infolist()
    if not members or len(members) > MAX_MEMBERS:
        raise AppleReleaseContaminationError("Apple ZIP member count is invalid")
    names: set[str] = set()
    expanded = 0
    for member in members:
        raw_name = member.filename
        pure = pathlib.PurePosixPath(raw_name)
        if pure.is_absolute() or ".." in pure.parts or "\x00" in raw_name:
            raise AppleReleaseContaminationError("Apple ZIP contains an unsafe path")
        folded = raw_name.rstrip("/").casefold()
        if not folded or folded in names:
            raise AppleReleaseContaminationError(
                "Apple ZIP contains duplicate or empty paths"
            )
        names.add(folded)
        if member.flag_bits & 0x1:
            raise AppleReleaseContaminationError("Apple ZIP contains encrypted content")
        mode = member.external_attr >> 16
        if stat.S_ISLNK(mode):
            if "Watch" in pure.parts:
                # zipfile extracts a link member as a plain file holding its
                # target text, so a Watch binary behind it would never be scanned.
                raise AppleReleaseContaminationError(
                    "Apple ZIP embedded Watch app contains a symlink"
                )
            try:
                target = archive.read(member).decode("utf-8")
            except (RuntimeError, UnicodeDecodeError) as exc:
                raise AppleReleaseContaminationError(
                    "Apple ZIP symlink is invalid"
                ) from exc
            normalized = posixpath.normpath(
                posixpath.join(posixpath.dirname(raw_name), target)
            )
            if (
                not target
                or pathlib.PurePosixPath(target).is_absolute()
                or normalized == ".."
                or normalized.startswith("../")
            ):
                raise AppleReleaseContaminationError(
                    "Apple ZIP symlink escapes the artifact"
                )
        elif stat.S_IFMT(mode) and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise AppleReleaseContaminationError(
                "Apple ZIP contains a special filesystem entry"
            )
        expanded += member.file_size
        if member.file_size > MAX_MEMBER_BYTES or expanded > MAX_EXPANDED_BYTES:
            raise AppleReleaseContaminationError("Apple ZIP expansion limit exceeded")
    return members


def _extract_zip(path: pathlib.Path, destination: pathlib.Path) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            members = _safe_zip_members(archive)
            archive.extractall(destination, members=members)
    except (OSError, zipfile.BadZipFile) as exc:
        raise AppleReleaseContaminationError("Apple ZIP artifact is invalid") from exc


def _one_app(root: pathlib.Path, pattern: str) -> pathlib.Path:
    apps = sorted(path for path in root.glob(pattern) if path.is_dir())
    if len(apps) != 1:
        raise AppleReleaseContaminationError(
            f"artifact must contain exactly one host app, found {len(apps)}"
        )
    return apps[0]


def _expand_pkg(path: pathlib.Path, destination: pathlib.Path) -> pathlib.Path:
    try:
        completed = subprocess.run(
            ["/usr/sbin/pkgutil", "--expand-full", str(path), str(destination)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            check=False,
        )
    except OSError as exc:
        raise AppleReleaseContaminationError(
            "pkgutil is required for offline PKG inspection"
        ) from exc
    if completed.returncode != 0:
        raise AppleReleaseContaminationError("Apple PKG could not be expanded offline")
    return _one_app(destination, "**/*.app")


def _platform_for_app(app: pathlib.Path) -> str:
    return "macos" if (app / "Contents/Info.plist").is_file() else "ios"


def verify_artifact(path: pathlib.Path, expected_platform: str | None = None) -> None:
    path = path.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="wins-apple-contamination-") as temporary:
        scratch = pathlib.Path(temporary)
        lowered = path.name.lower()
        if path.is_dir() and lowered.endswith(".xcarchive"):
            app = _one_app(path / "Products/Applications", "*.app")
        elif path.is_dir() and lowered.endswith(".app"):
            app = path
        elif path.is_file() and lowered.endswith((".ipa", ".app.zip", ".zip")):
            _extract_zip(path, scratch)
            pattern = "Payload/*.app" if lowered.endswith(".ipa") else "**/*.app"
            app = _one_app(scratch, pattern)
        elif path.is_file() and lowered.endswith(".pkg"):
            app = _expand_pkg(path, scratch / "expanded")
        else:
            raise AppleReleaseContaminationError(
                "expected an IPA, PKG, app ZIP, app bundle, or xcarchive"
            )
        platform = _platform_for_app(app)
        if expected_platform is not None and platform != expected_platform:
            raise AppleReleaseContaminationError("Apple artifact platform does not match")
        verify_app_bundle(app, platform)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=pathlib.Path, nargs="?")
    parser.add_argument("--platform", choices=("ios", "macos"))
    parser.add_argument("--verify-xcconfig", type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        if args.verify_xcconfig is not None:
            if args.artifact is not None or args.platform is not None:
                raise AppleReleaseContaminationError(
                    "xcconfig verification cannot be combined with artifact verification"
                )
            verify_dart_defines_xcconfig(args.verify_xcconfig)
        elif args.artifact is None:
            raise AppleReleaseContaminationError("Apple release artifact is required")
        else:
            verify_artifact(args.artifact, args.platform)
    except (AppleReleaseContaminationError, OSError) as exc:
        print(f"APPLE RELEASE CONTAMINATION GATE: FAIL: {exc}", file=sys.stderr)
        return 1
    print("APPLE RELEASE CONTAMINATION GATE: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
