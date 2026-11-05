#!/usr/bin/env python3
"""Prove that a produced iOS IPA embeds the production WatchConnectivity client.

This gate inspects the shipped Watch Mach-O, not source files or debug-only
symbols. It requires the framework dependency, WCSession import, Objective-C
runtime selectors used by the pairing/message path, an executable Watch image,
and an app-store-safe stripped metadata surface on every architecture slice.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import plistlib
import re
import stat
import subprocess
import tempfile
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
WATCH_BUNDLE_ID = "org.winsvpn.app.watchkitapp"
COMPANION_BUNDLE_ID = "org.winsvpn.app"
WATCH_EXECUTABLE = "WinsWatch"
WATCH_PRIVACY_SOURCE = ROOT / "ios/WinsWatch Watch App/PrivacyInfo.xcprivacy"
WATCHCONNECTIVITY_DYLIB = (
    "/System/Library/Frameworks/WatchConnectivity.framework/WatchConnectivity"
)
ALLOWED_ARCHITECTURES = frozenset({"arm64", "arm64_32"})
REQUIRED_SELECTORS = frozenset(
    {
        "activationState",
        "isReachable",
        "receivedApplicationContext",
        # 705bedd (DESIGN_V17) moved Watch commands from transferUserInfo to
        # sendMessage, which reports delivery failure; the Watch no longer calls it.
        "sendMessage:replyHandler:errorHandler:",
        "session:activationDidCompleteWithState:error:",
        "sessionReachabilityDidChange:",
        "session:didReceiveApplicationContext:",
        "session:didReceiveMessage:",
    }
)
MAX_IPA_BYTES = 2 * 1024 * 1024 * 1024
MAX_WATCH_EXECUTABLE_BYTES = 128 * 1024 * 1024
MAX_PLIST_BYTES = 1024 * 1024
TOOL_TIMEOUT_SECONDS = 30
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
BUILD_RE = re.compile(r"^[1-9][0-9]*$")


class WatchArtifactError(RuntimeError):
    pass


def _safe_member_name(name: str) -> pathlib.PurePosixPath:
    path = pathlib.PurePosixPath(name)
    if (
        not name
        or name.startswith("/")
        or "\\" in name
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(ord(character) < 0x20 for character in name)
    ):
        raise WatchArtifactError("IPA contains an unsafe member path")
    return path


def _regular_member(info: zipfile.ZipInfo, label: str, maximum: int) -> None:
    mode = info.external_attr >> 16
    kind = stat.S_IFMT(mode)
    if kind not in {0, stat.S_IFREG} or stat.S_ISLNK(mode):
        raise WatchArtifactError(f"{label} is not a regular IPA member")
    if info.file_size <= 0 or info.file_size > maximum:
        raise WatchArtifactError(f"{label} size is outside the release bound")


def _read_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    label: str,
    maximum: int,
) -> bytes:
    _regular_member(info, label, maximum)
    with archive.open(info, "r") as stream:
        data = stream.read(maximum + 1)
        if len(data) > maximum or stream.read(1):
            raise WatchArtifactError(f"{label} exceeds the release bound")
    if len(data) != info.file_size:
        raise WatchArtifactError(f"{label} size does not match the IPA directory")
    return data


def _watch_members(
    archive: zipfile.ZipFile,
) -> tuple[
    zipfile.ZipInfo,
    zipfile.ZipInfo,
    dict[str, object],
    dict[str, object],
    bytes,
]:
    by_name: dict[str, zipfile.ZipInfo] = {}
    folded: dict[str, str] = {}
    for info in archive.infolist():
        path = _safe_member_name(info.filename.rstrip("/"))
        normalized = path.as_posix()
        if normalized in by_name:
            raise WatchArtifactError("IPA contains a duplicate member")
        key = normalized.casefold()
        if key in folded:
            raise WatchArtifactError("IPA contains a case-fold member collision")
        folded[key] = normalized
        by_name[normalized] = info

    candidates: list[tuple[zipfile.ZipInfo, dict[str, object]]] = []
    for name, info in by_name.items():
        parts = pathlib.PurePosixPath(name).parts
        if (
            len(parts) == 6
            and parts[0] == "Payload"
            and parts[1].endswith(".app")
            and parts[2] == "Watch"
            and parts[3].endswith(".app")
            and parts[4] == "Info.plist"
        ):
            # The expected path has five components; retain an explicit check
            # below so malformed nested lookalikes never become candidates.
            continue
        if (
            len(parts) == 5
            and parts[0] == "Payload"
            and parts[1].endswith(".app")
            and parts[2] == "Watch"
            and parts[3].endswith(".app")
            and parts[4] == "Info.plist"
        ):
            payload = _read_member(archive, info, "Watch Info.plist", MAX_PLIST_BYTES)
            try:
                value = plistlib.loads(payload)
            except (plistlib.InvalidFileException, ValueError) as exc:
                raise WatchArtifactError("Watch Info.plist is malformed") from exc
            if type(value) is not dict:
                raise WatchArtifactError("Watch Info.plist root is malformed")
            candidates.append((info, value))
    if len(candidates) != 1:
        raise WatchArtifactError("IPA must contain exactly one embedded Watch app")

    info_member, info = candidates[0]
    if info.get("CFBundleIdentifier") != WATCH_BUNDLE_ID:
        raise WatchArtifactError("embedded Watch bundle identifier is not current")
    if info.get("WKCompanionAppBundleIdentifier") != COMPANION_BUNDLE_ID:
        raise WatchArtifactError("embedded Watch app is not paired to the production iOS app")
    if info.get("WKRunsIndependentlyOfCompanionApp") is not False:
        raise WatchArtifactError("embedded Watch app must remain a paired remote control")
    if info.get("CFBundleExecutable") != WATCH_EXECUTABLE:
        raise WatchArtifactError("embedded Watch executable identity is not current")
    watch_version = info.get("CFBundleShortVersionString")
    watch_build = info.get("CFBundleVersion")
    if not isinstance(watch_version, str) or not VERSION_RE.fullmatch(watch_version):
        raise WatchArtifactError("embedded Watch marketing version is invalid")
    if not isinstance(watch_build, str) or not BUILD_RE.fullmatch(watch_build):
        raise WatchArtifactError("embedded Watch build number is invalid")

    watch_parts = pathlib.PurePosixPath(info_member.filename).parts
    parent_info_name = "/".join((*watch_parts[:2], "Info.plist"))
    parent_info_member = by_name.get(parent_info_name)
    if parent_info_member is None:
        raise WatchArtifactError("parent iOS Info.plist is missing")
    parent_payload = _read_member(
        archive, parent_info_member, "parent iOS Info.plist", MAX_PLIST_BYTES
    )
    try:
        parent_info = plistlib.loads(parent_payload)
    except (plistlib.InvalidFileException, ValueError) as exc:
        raise WatchArtifactError("parent iOS Info.plist is malformed") from exc
    if type(parent_info) is not dict:
        raise WatchArtifactError("parent iOS Info.plist root is malformed")
    if parent_info.get("CFBundleIdentifier") != COMPANION_BUNDLE_ID:
        raise WatchArtifactError("parent iOS bundle identifier is not current")
    if parent_info.get("CFBundleShortVersionString") != watch_version:
        raise WatchArtifactError("embedded Watch marketing version differs from its parent")
    if parent_info.get("CFBundleVersion") != watch_build:
        raise WatchArtifactError("embedded Watch build number differs from its parent")

    privacy_name = "/".join((*watch_parts[:-1], "PrivacyInfo.xcprivacy"))
    privacy_member = by_name.get(privacy_name)
    if privacy_member is None:
        raise WatchArtifactError("embedded Watch privacy manifest is missing")
    privacy_payload = _read_member(
        archive, privacy_member, "Watch PrivacyInfo.xcprivacy", MAX_PLIST_BYTES
    )
    try:
        produced_privacy = plistlib.loads(privacy_payload)
        reviewed_privacy = plistlib.loads(WATCH_PRIVACY_SOURCE.read_bytes())
    except (OSError, plistlib.InvalidFileException, ValueError) as exc:
        raise WatchArtifactError("Watch privacy manifest is malformed or unavailable") from exc
    if type(produced_privacy) is not dict or produced_privacy != reviewed_privacy:
        raise WatchArtifactError("embedded Watch privacy manifest differs from reviewed source")

    executable_name = "/".join(
        (*pathlib.PurePosixPath(info_member.filename).parts[:-1], WATCH_EXECUTABLE)
    )
    executable = by_name.get(executable_name)
    if executable is None:
        raise WatchArtifactError("embedded Watch executable is missing")
    return info_member, executable, info, parent_info, privacy_payload


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=TOOL_TIMEOUT_SECONDS,
            check=False,
            shell=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
        )
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
        raise WatchArtifactError(f"Watch Mach-O inspection tool failed: {argv[0]}") from exc
    return completed


def _require_success(completed: subprocess.CompletedProcess[str], label: str) -> str:
    if completed.returncode != 0:
        raise WatchArtifactError(f"{label} failed with exit {completed.returncode}")
    return completed.stdout


def _architectures(executable: pathlib.Path) -> tuple[str, ...]:
    output = _require_success(
        _run(["/usr/bin/lipo", "-archs", str(executable)]),
        "Watch architecture inspection",
    )
    architectures = tuple(output.split())
    if not architectures or len(architectures) != len(set(architectures)):
        raise WatchArtifactError("Watch architecture list is empty or duplicated")
    if not set(architectures).issubset(ALLOWED_ARCHITECTURES):
        raise WatchArtifactError("Watch executable contains a non-device architecture")
    return architectures


def _verify_architecture(executable: pathlib.Path, architecture: str) -> None:
    header = _require_success(
        _run(["/usr/bin/otool", "-arch", architecture, "-hv", str(executable)]),
        f"Watch {architecture} header inspection",
    )
    if not re.search(r"\bEXECUTE\b", header) or re.search(r"\b(?:DYLIB|BUNDLE)\b", header):
        raise WatchArtifactError(f"Watch {architecture} slice is not MH_EXECUTE")

    dependencies = _require_success(
        _run(["/usr/bin/otool", "-arch", architecture, "-L", str(executable)]),
        f"Watch {architecture} dependency inspection",
    )
    dependency_lines = {
        line.strip().split(" (", 1)[0]
        for line in dependencies.splitlines()[1:]
        if line.strip()
    }
    if WATCHCONNECTIVITY_DYLIB not in dependency_lines:
        raise WatchArtifactError(
            f"Watch {architecture} slice does not load WatchConnectivity"
        )

    imports = _run(["/usr/bin/nm", "-u", "-arch", architecture, str(executable)])
    imports_text = f"{imports.stdout}\n{imports.stderr}"
    if imports.returncode != 0 or "_OBJC_CLASS_$_WCSession" not in imports_text.split():
        raise WatchArtifactError(f"Watch {architecture} slice does not import WCSession")

    objective_c = _require_success(
        _run(["/usr/bin/otool", "-arch", architecture, "-ov", str(executable)]),
        f"Watch {architecture} Objective-C metadata inspection",
    )
    selectors = {
        match.group(1)
        for match in re.finditer(r"^\s*0x[0-9a-fA-F]+\s+(\S+)\s*$", objective_c, re.MULTILINE)
    }
    missing = sorted(REQUIRED_SELECTORS - selectors)
    if missing:
        raise WatchArtifactError(
            f"Watch {architecture} slice lacks pairing/message selectors: {', '.join(missing)}"
        )
    if "WCSessionDelegate" not in objective_c:
        raise WatchArtifactError(
            f"Watch {architecture} slice lacks WCSessionDelegate runtime conformance"
        )

    load_commands = _require_success(
        _run(["/usr/bin/otool", "-arch", architecture, "-l", str(executable)]),
        f"Watch {architecture} load-command inspection",
    )
    if re.search(r"(?:segname|sectname)\s+__(?:DWARF|debug\S*)", load_commands):
        raise WatchArtifactError(f"Watch {architecture} slice retains debug sections")
    if "sectname __objc_methname" not in load_commands or "sectname __objc_selrefs" not in load_commands:
        raise WatchArtifactError(
            f"Watch {architecture} slice lacks Objective-C selector metadata"
        )

    symbols = _run(["/usr/bin/nm", "-a", "-arch", architecture, str(executable)])
    symbol_text = f"{symbols.stdout}\n{symbols.stderr}"
    if symbols.returncode not in {0, 1}:
        raise WatchArtifactError(f"Watch {architecture} symbol inspection failed")
    if symbols.returncode == 1 and "no symbols" not in symbol_text.lower():
        raise WatchArtifactError(f"Watch {architecture} symbol table is malformed")
    if re.search(r"\bN_(?:OSO|SO|SOL|FUN|STSYM|LCSYM|BNSYM|ENSYM)\b", symbol_text):
        raise WatchArtifactError(f"Watch {architecture} slice retains private debug symbols")


def verify_ipa(path: pathlib.Path) -> dict[str, object]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise WatchArtifactError("iOS IPA is missing") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size <= 0
        or info.st_size > MAX_IPA_BYTES
    ):
        raise WatchArtifactError("iOS IPA is not a bounded regular file")
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        bound = os.fstat(descriptor)
        if (bound.st_dev, bound.st_ino) != (info.st_dev, info.st_ino):
            raise WatchArtifactError("iOS IPA changed while it was opened")
        with os.fdopen(descriptor, "rb", closefd=True) as ipa_stream:
            descriptor = -1
            digest = hashlib.sha256()
            while chunk := ipa_stream.read(1024 * 1024):
                digest.update(chunk)
            ipa_stream.seek(0)
            with zipfile.ZipFile(ipa_stream, "r") as archive:
                (
                    _info_member,
                    executable_member,
                    watch_info,
                    parent_info,
                    privacy_payload,
                ) = _watch_members(archive)
                executable_data = _read_member(
                    archive,
                    executable_member,
                    "Watch executable",
                    MAX_WATCH_EXECUTABLE_BYTES,
                )
            after = os.fstat(ipa_stream.fileno())
            stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if any(getattr(after, field) != getattr(bound, field) for field in stable_fields):
                raise WatchArtifactError("iOS IPA changed during inspection")
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        if isinstance(exc, WatchArtifactError):
            raise
        raise WatchArtifactError("iOS IPA could not be inspected") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    with tempfile.TemporaryDirectory(prefix="wins-watch-artifact-") as temporary:
        executable = pathlib.Path(temporary) / WATCH_EXECUTABLE
        descriptor = os.open(
            executable,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o500,
        )
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(executable_data)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        architectures = _architectures(executable)
        for architecture in architectures:
            _verify_architecture(executable, architecture)

    return {
        "schema_version": 1,
        "bundle_id": watch_info["CFBundleIdentifier"],
        "companion_bundle_id": watch_info["WKCompanionAppBundleIdentifier"],
        "version": watch_info["CFBundleShortVersionString"],
        "build_number": watch_info["CFBundleVersion"],
        "parent_version": parent_info["CFBundleShortVersionString"],
        "parent_build_number": parent_info["CFBundleVersion"],
        "ipa_sha256": digest.hexdigest(),
        "ipa_bytes": info.st_size,
        "executable": WATCH_EXECUTABLE,
        "executable_sha256": hashlib.sha256(executable_data).hexdigest(),
        "architectures": list(architectures),
        "watch_connectivity_dependency": WATCHCONNECTIVITY_DYLIB,
        "wc_session_import": "_OBJC_CLASS_$_WCSession",
        "required_selectors": sorted(REQUIRED_SELECTORS),
        "privacy_manifest_sha256": hashlib.sha256(privacy_payload).hexdigest(),
        "debug_sections": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("ipa", type=pathlib.Path)
    args = parser.parse_args()
    try:
        result = verify_ipa(args.ipa)
    except WatchArtifactError as exc:
        print(f"FAIL: {exc}", file=os.sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
