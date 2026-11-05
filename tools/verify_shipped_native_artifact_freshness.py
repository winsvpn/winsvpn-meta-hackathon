#!/usr/bin/env python3
"""Fail when a native artifact this repository SHIPS is older than its sources.

WHY THIS EXISTS
===============

On 2026-08-08 three separate lanes reported Winn v3 working on Android. All
three were reading `winn_protocol_experimental/`. None of them was reading the
binary in `android/app/src/release/jniLibs/`, which had been built 23 hours
earlier and did not contain the feature at all:

    android/app/src/release/jniLibs/arm64-v8a/libwinnengine.so
        built 2026-08-08 00:44, sha256 ec99928f...
        -print-contract emitted NO "payloads" key
        -> WinnV3Host.engineSupportsV3() == false on every handset
        -> NO_V3_ENGINE for every v3 session

The same shape hit the Apple c-archives, which were linked at 00:27 against a
`cdatapath/winn_datapath_winn3.go` that was not fixed until 01:53, and so
refused every create with a message that no longer existed in the source.

The tests could not catch either one. `WinnEngineInteropTest` resolves its
engine by running `go build` over `./cmd/winn-datapath` -- it drives the REAL
binary, exhaustively, and every assertion in it is sound. It simply never
looks at the file the app actually packages. A test that builds from source
while the app ships a binary is green precisely when the two disagree, which
is the only time the answer matters.

So this gate does the one thing that suite structurally cannot: it takes the
artifact IN THE TREE, rebuilds the same target from the sources as they are
right now, and compares the two by CONTENT. Timestamps are reported because
they are useful for a human reading a failure, but they are never the verdict:
mtimes in a tree that many lanes write is not evidence of anything.

WHAT "SAME CONTENT" MEANS, AND WHY IT IS NOT ALWAYS sha256
==========================================================

The executable targets are built with `-ldflags=-buildid=`, so two builds of
identical sources are byte-identical and a raw sha256 is the comparison. This
is not assumed -- it is why `--self-check` exists.

The Apple c-archive target may vary only in the authenticated 12-byte mtime
field of its ar `__.SYMDEF` member. Mach-O `__TEXT,__text` is executable code,
so every byte there, including a Go linker build ID, is compared raw. A producer
that cannot make those executable bytes reproducible is owner-blocked until it
emits separately authenticated non-executable build metadata. Widening the
non-executable metadata mask is how this gate would become a green light; don't.

USAGE
=====

    python3 tools/verify_shipped_native_artifact_freshness.py
    python3 tools/verify_shipped_native_artifact_freshness.py --only android
    python3 tools/verify_shipped_native_artifact_freshness.py --self-check

Go and its module cache come from the caller and are accepted only by the
reviewed pins and digests:

    WINS_FRESHNESS_GO_ROOT              pinned Go install root; bin/go sha256,
                                        install-tree sha256 for this host and
                                        `go version` must equal
                                        tools/toolchain-pins.json
    WINS_STORE_GOMODCACHE               sealed Go module cache (non-writable,
                                        regular single-link files only)
    WINS_STORE_GOMODCACHE_TREE_SHA256   its `winn_release.py digest --kind
                                        sealed` value, re-measured before and
                                        after the run

The Android NDK and Xcode are accepted the same way, by tools/toolchain-pins.json
alone (no /Library authority file, root ownership or immutable flag):

    WINS_FRESHNESS_NDK_ROOT             absolute NDK root (default
                                        ~/.local/android-sdk/ndk/<pin>); its
                                        Pkg.Revision and `winn_release.py
                                        digest --kind platform` tree digest
                                        must equal tools.android_ndk
    WINS_FRESHNESS_DEVELOPER_DIR        absolute Xcode developer directory
                                        (default `xcode-select -p`); its
                                        `xcodebuild -version` must equal
                                        tools.xcode version and build

`--artifact PATH` (repeatable) checks only those declared artifacts, e.g.
android/app/src/release/jniLibs/arm64-v8a/libwinnengine.so.

Exit 0 = every checked artifact is FRESH: its bytes equal a rebuild of the
bound source closure whose producer receipt authenticates the exact target.
Exit 1 = at least one artifact is stale, missing, invalid or blocked. Exit 2 =
the check could not be run. Exit 3 = `--self-check` diagnostics succeeded;
that proves the comparison, not any shipped artifact.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import io
import json
import os
import platform
import re
import select
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
import tarfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, NoReturn, Optional

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_SCRIPT = os.path.join(REPO_ROOT, "tools", "build_winn_protocol_engine.sh")
RELAY_BUILD_SCRIPT = os.path.join(REPO_ROOT, "tools", "build_windows_winn3_relay.sh")
APPLE_WRAPPER_BUILD_SCRIPT = os.path.join(REPO_ROOT, "tools", "build_apple_engine_wrappers.sh")
MODULE_DIR = os.path.join(REPO_ROOT, "winn_protocol_experimental")
RELAY_MODULE_DIR = os.path.join(REPO_ROOT, "windows", "winn3_engine")
APPLE_WRAPPER_SOURCE_DIR = os.path.join(REPO_ROOT, "apple", "EngineWrappers")
PIN_MANIFEST = os.path.join(REPO_ROOT, "tools", "toolchain-pins.json")
# The pinned Go install root. tools/toolchain-pins.json is the only authority
# for it: bin/go sha256, this host's install-tree digest and the exact
# `go version` line. No root-owned path, issuance file or signature is read.
REVIEWED_GO_ROOT_ENV = "WINS_FRESHNESS_GO_ROOT"
# The sealed Go module cache and its digest, measured exactly as
# `winn_release.py digest --kind sealed` (and the sealed builder) measure it.
SEALED_GOMODCACHE_ENV = "WINS_STORE_GOMODCACHE"
SEALED_GOMODCACHE_TREE_ENV = "WINS_STORE_GOMODCACHE_TREE_SHA256"
# The pinned Android NDK root. tools/toolchain-pins.json is the only authority
# for it: source.properties must carry the pinned Pkg.Revision and the tree
# must hash to this host's tools.android_ndk.install_tree_sha256 in the
# `winn_release.py digest --kind platform` encoding. Unset, it defaults to the
# root `winn_release.py prepare_ndk` uses: ~/.local/android-sdk/ndk/<version>.
ANDROID_NDK_ROOT_ENV = "WINS_FRESHNESS_NDK_ROOT"
# The Xcode developer directory; unset, `/usr/bin/xcode-select -p` names it.
# Its `xcodebuild -version` must report exactly tools.xcode.version and
# tools.xcode.build. No root-owned path or issuance file is read for either.
APPLE_DEVELOPER_DIR_ENV = "WINS_FRESHNESS_DEVELOPER_DIR"
APPLE_TOOL_TIMEOUT_SECONDS = 120
# What the sealed core builder reads besides itself and the pins. It measures
# sealed inputs with `winn_release.py digest`, and the driver's Go tree digest
# comes from release_go_archive_custody.tree_hash. The ReleaseGo/ReleasePython
# custody wrappers, provisioner and trust anchor are no longer producer inputs.
PRODUCTION_BUILDER_MATERIALS = tuple(
    os.path.join(REPO_ROOT, "tools", name)
    for name in (
        "winn_release.py",
        "release_go_archive_custody.py",
    )
)
SELF_CHECK_DIAGNOSTIC_EXIT = 3
PRODUCER_TIMEOUT_SECONDS = 300
PRODUCER_STREAM_LIMIT = 2 * 1024 * 1024
PRODUCER_TERMINATION_GRACE_SECONDS = 1.0
DARWIN_POSIX_SPAWN_SETSID = 0x0400
DARWIN_POSIX_SPAWN_CLOEXEC_DEFAULT = 0x4000
LINUX_RELEASE_CANDIDATE = "app_store/linux/artifacts/release_candidate.json"
LINUX_DEB_NON_UPLOAD = {
    "upload_target": False,
    "separate_cross_store_target": False,
    "derived_from": "linux-x64-package",
    "canonical_release": "1.0.16+33",
    "debian_version": "1.0.16-33",
    "architecture": "amd64",
    "filename": "wins-vpn_1.0.16-33_amd64.deb",
    "path": "build/linux-deb/wins-vpn_1.0.16-33_amd64.deb",
    "produced": False,
    "upload_performed": False,
    "publication_authorized": False,
}
SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
WINN_MARKER = b"winsvpn.local/winnprotocol/winn3"
RELAY_MARKER = b"winsvpn3"
SOURCE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".h", ".go", ".mod", ".s", ".S", ".sum"})
ANDROID_ABIS = {
    "arm64-v8a": (2, 183),
    "armeabi-v7a": (1, 40),
    "x86_64": (2, 62),
}
PE_MACHINES = {"amd64": 0x8664, "arm64": 0xAA64}
MACHO_CPUS = {"arm64": 0x0100000C, "x86_64": 0x01000007}
MACHO_PLATFORMS = {"macosx": 1, "iphoneos": 2, "iphonesimulator": 7}
APPLE_REQUIRED_SYMBOLS = (
    b"wins_winn_packet_engine_contract_version",
    b"wins_winn_packet_engine_create",
    b"wins_winn_packet_engine_start",
    b"wins_winn_packet_engine_stop",
    b"wins_winn_packet_engine_destroy",
    b"wins_winn_packet_engine_awg_seam_port",
    b"wins_winn_packet_engine_seam_stats",
    b"wins_winn_packet_engine_status_json",
    b"WinnTunnelCreateWinn3",
)
GO_PACKAGE_FILE_FIELDS = (
    "GoFiles",
    "CgoFiles",
    "CFiles",
    "CXXFiles",
    "MFiles",
    "HFiles",
    "FFiles",
    "SFiles",
    "SwigFiles",
    "SwigCXXFiles",
    "SysoFiles",
    "EmbedFiles",
)


@dataclass(frozen=True)
class Artifact:
    """One artifact that reaches a user, and the target that reproduces it."""

    path: str          # repo-relative
    target: str        # a tools/build_winn_protocol_engine.sh target
    group: str         # android | apple | windows | linux
    why: str           # what ships it, for a failure message
    kind: str = "raw"  # raw | android-package | linux-package | relay | apple-wrapper
    role: str = "core"
    arch: str = ""
    member: str = ""
    platform: str = ""
    closure: str = "core"


# Every native artifact in this tree that is packaged into something a user
# installs, or linked into something that is. Adding a shipped artifact
# without adding it here is how the next one of these goes unnoticed.
ANDROID_PACKAGE_PATHS: tuple[tuple[str, str], ...] = (
    # The first two phone names are neutral release-build stage names. The
    # publication phone names are separate copies. TV release producers use
    # the same path for stage and publication, so those paths appear once.
    ("build/app/outputs/flutter-apk/app-phone-release.apk", "APK stage, phone"),
    ("build/app/outputs/bundle/phoneRelease/app-phone-release.aab", "AAB stage, phone"),
    ("build/app/outputs/flutter-apk/app-tv-release.apk", "APK stage and publication, TV"),
    ("build/app/outputs/bundle/tvRelease/app-tv-release.aab", "AAB stage and publication, TV"),
    ("build/app/outputs/flutter-apk/app-release.apk", "published phone APK"),
    ("build/app/outputs/bundle/release/app-release.aab", "published phone AAB"),
)


def _android_package_artifacts() -> tuple[Artifact, ...]:
    items: list[Artifact] = []
    for path, why in ANDROID_PACKAGE_PATHS:
        is_aab = path.endswith(".aab")
        prefix = "base/" if is_aab else ""
        for abi, target_arch in (
            ("arm64-v8a", "arm64"),
            ("armeabi-v7a", "arm"),
            ("x86_64", "amd64"),
        ):
            items.append(
                Artifact(
                    path,
                    f"datapath-android-{target_arch}",
                    "android",
                    f"{why}, {abi}",
                    kind="android-package",
                    arch=target_arch,
                    member=f"{prefix}lib/{abi}/libwinnengine.so",
                )
            )
    return tuple(items)


ANDROID_QA_NATIVE_PATHS: tuple[tuple[str, str], ...] = (
    (
        "android/devicecheck/app/build/intermediates/merged_jni_libs/debug/"
        "mergeDebugJniLibFolders/out/arm64-v8a/libwinnengine.so",
        "DeviceCheck QA merged JNI debug output",
    ),
    (
        "android/devicecheck/app/build/intermediates/merged_native_libs/debug/"
        "mergeDebugNativeLibs/out/lib/arm64-v8a/libwinnengine.so",
        "DeviceCheck QA merged native debug output",
    ),
    (
        "android/devicecheck/app/build/intermediates/stripped_native_libs/debug/"
        "stripDebugDebugSymbols/out/lib/arm64-v8a/libwinnengine.so",
        "DeviceCheck QA stripped native debug output",
    ),
    (
        "android/devicecheck/app/build/intermediates/merged_jni_libs/release/"
        "mergeReleaseJniLibFolders/out/arm64-v8a/libwinnengine.so",
        "DeviceCheck QA merged JNI release output",
    ),
    (
        "android/devicecheck/app/build/intermediates/merged_native_libs/release/"
        "mergeReleaseNativeLibs/out/lib/arm64-v8a/libwinnengine.so",
        "DeviceCheck QA merged native release output",
    ),
    (
        "android/devicecheck/app/build/intermediates/stripped_native_libs/release/"
        "stripReleaseReleaseSymbols/out/lib/arm64-v8a/libwinnengine.so",
        "DeviceCheck QA stripped native release output",
    ),
)


def _android_qa_artifacts() -> tuple[Artifact, ...]:
    return tuple(
        Artifact(
            path,
            "datapath-android-arm64",
            "android",
            why,
            kind="elf",
            arch="arm64",
        )
        for path, why in ANDROID_QA_NATIVE_PATHS
    )


SHIPPED: tuple[Artifact, ...] = (
    # The Android engine. Six copies of two builds: AGP merges src/<variant>/
    # jniLibs into that variant only, so debug, profile and release each need
    # their own and all three are packaged.
    Artifact("android/app/src/debug/jniLibs/arm64-v8a/libwinnengine.so",
             "datapath-android-arm64", "android", "debug APK, arm64 handsets", arch="arm64"),
    Artifact("android/app/src/debug/jniLibs/armeabi-v7a/libwinnengine.so",
             "datapath-android-arm", "android", "debug APK, 32-bit ARM handsets", arch="arm"),
    Artifact("android/app/src/debug/jniLibs/x86_64/libwinnengine.so",
             "datapath-android-amd64", "android", "debug APK, x86_64 emulators", arch="amd64"),
    Artifact("android/app/src/profile/jniLibs/arm64-v8a/libwinnengine.so",
             "datapath-android-arm64", "android", "profile APK, arm64 handsets", arch="arm64"),
    Artifact("android/app/src/profile/jniLibs/armeabi-v7a/libwinnengine.so",
             "datapath-android-arm", "android", "profile APK, 32-bit ARM handsets", arch="arm"),
    Artifact("android/app/src/profile/jniLibs/x86_64/libwinnengine.so",
             "datapath-android-amd64", "android", "profile APK, x86_64 emulators", arch="amd64"),
    Artifact("android/app/src/release/jniLibs/arm64-v8a/libwinnengine.so",
             "datapath-android-arm64", "android", "RELEASE APK/AAB, arm64 handsets", arch="arm64"),
    Artifact("android/app/src/release/jniLibs/armeabi-v7a/libwinnengine.so",
             "datapath-android-arm", "android", "RELEASE APK/AAB, 32-bit ARM handsets", arch="arm"),
    Artifact("android/app/src/release/jniLibs/x86_64/libwinnengine.so",
             "datapath-android-amd64", "android", "RELEASE APK/AAB, x86_64 emulators", arch="amd64"),
    Artifact("android/devicecheck/app/src/main/jniLibs/arm64-v8a/libwinnengine.so",
             "datapath-android-arm64", "android",
             "devicecheck harness -- the only thing that exercises SCM_RIGHTS on hardware",
             arch="arm64"),

    # Devicecheck QA artifacts. The androidTest APK is an instrumentation
    # harness and intentionally contains no native Winn engine; these are the
    # application APKs that actually carry the QA engine.
    Artifact("android/devicecheck/app/build/outputs/apk/debug/app-debug.apk",
             "datapath-android-arm64", "android", "devicecheck QA debug APK",
             kind="android-package", arch="arm64", member="lib/arm64-v8a/libwinnengine.so"),
    Artifact("android/devicecheck/app/build/outputs/apk/release/app-release.apk",
             "datapath-android-arm64", "android", "devicecheck QA release APK",
             kind="android-package", arch="arm64", member="lib/arm64-v8a/libwinnengine.so"),

    # The Apple c-archives. These are linked into the macOS and iOS packet
    # tunnel appexes, so a stale one is shipped code exactly as much as the
    # .so above is.
    Artifact("tools/winn_conformance_build_out/libwinn-datapath-darwin-arm64.a",
             "datapath-archive-darwin-arm64", "apple", "macOS appex, Apple silicon",
             kind="apple-archive", arch="arm64", platform="macosx", closure="apple"),
    Artifact("tools/winn_conformance_build_out/libwinn-datapath-darwin-amd64.a",
             "datapath-archive-darwin-amd64", "apple", "macOS appex, Intel",
             kind="apple-archive", arch="x86_64", platform="macosx", closure="apple"),
    Artifact("tools/winn_conformance_build_out/libwinn-datapath-ios-arm64.a",
             "datapath-ios-arm64", "apple", "iOS device appex",
             kind="apple-archive", arch="arm64", platform="iphoneos", closure="apple"),
    Artifact("tools/winn_conformance_build_out/libwinn-datapath-iossimulator-arm64.a",
             "datapath-iossimulator-arm64", "apple", "iOS simulator, Apple silicon",
             kind="apple-archive", arch="arm64", platform="iphonesimulator", closure="apple"),
    Artifact("tools/winn_conformance_build_out/libwinn-datapath-iossimulator-amd64.a",
             "datapath-iossimulator-amd64", "apple", "iOS simulator, Intel",
             kind="apple-archive", arch="x86_64", platform="iphonesimulator", closure="apple"),

    # The wrapper is the Apple shipping surface. The archives above are also
    # retained because the wrapper producer consumes and ships them as a
    # separately staged input.
    Artifact("apple/EngineArtifacts/ios/iphoneos/libWinsWinnPacketEngine.dylib",
             "apple-wrapper-iphoneos", "apple", "iOS device Winn wrapper",
             kind="apple-wrapper", role="core+relay", arch="arm64", platform="iphoneos",
             closure="apple"),
    Artifact("apple/EngineArtifacts/ios/iphonesimulator/libWinsWinnPacketEngine.dylib",
             "apple-wrapper-iphonesimulator", "apple", "iOS simulator Winn wrapper",
             kind="apple-wrapper", role="core+relay", arch="arm64,x86_64",
             platform="iphonesimulator", closure="apple"),
    Artifact("apple/EngineArtifacts/macos/libWinsWinnPacketEngine.dylib",
             "apple-wrapper-macosx", "apple", "macOS Winn wrapper",
             kind="apple-wrapper", role="core+relay", arch="arm64,x86_64", platform="macosx",
             closure="apple"),

    # Architecture-scoped installer inputs. An unsuffixed basename is safe only
    # inside its exact architecture directory; neither one may authorize or be
    # copied into the other architecture's release transaction.
    Artifact("build/windows/winn3/x64/winn-datapath.exe", "datapath-windows-amd64",
             "windows", "Windows installer core payload, x64", arch="amd64", kind="pe"),
    Artifact("build/windows/winn3/x64/winsvpn_winn3_engine.exe", "relay-windows-amd64",
             "windows", "Windows installer relay payload, x64", arch="amd64", kind="pe",
             role="relay", closure="relay"),
    Artifact("build/windows/winn3/arm64/winn-datapath.exe", "datapath-windows-arm64",
             "windows", "Windows installer core payload, arm64", arch="arm64", kind="pe"),
    Artifact("build/windows/winn3/arm64/winsvpn_winn3_engine.exe", "relay-windows-arm64",
             "windows", "Windows installer relay payload, arm64", arch="arm64", kind="pe",
             role="relay", closure="relay"),
)

AR_MAGIC = b"!<arch>\n"


class ArtifactInvalid(RuntimeError):
    """The bytes are present but cannot be the declared Winn artifact."""


class ArtifactMissing(ArtifactInvalid):
    """The descriptor-bound artifact or one of its ancestors is absent."""


class _CStringArray:
    """Keep UTF-8 argv/env storage alive for one libc posix_spawn call."""

    def __init__(self, values: list[str]) -> None:
        encoded = [value.encode("utf-8", errors="strict") for value in values]
        array = (ctypes.c_char_p * (len(encoded) + 1))()
        for index, value in enumerate(encoded):
            array[index] = value
        array[len(encoded)] = None
        self._encoded = encoded
        self.array = array


def _descriptor_path(descriptor: int) -> str:
    if descriptor < 0:
        raise CustodyUnavailable("retained descriptor is unavailable")
    if sys.platform == "darwin":
        return f"/dev/fd/{descriptor}"
    if sys.platform.startswith("linux"):
        return f"/proc/self/fd/{descriptor}"
    raise CustodyUnavailable("retained descriptor paths are unsupported on this host")


def _descriptor_execution_path(descriptor: int) -> str:
    if descriptor < 0:
        raise CustodyUnavailable("descriptor-bound executable is unavailable")
    path = _descriptor_path(descriptor)
    try:
        opened = os.fstat(descriptor)
        resolved = os.stat(path, follow_symlinks=True)
    except OSError as exc:
        raise CustodyUnavailable(
            f"descriptor-bound executable path is unavailable: {exc}"
        ) from exc
    identity_matches = (opened.st_dev, opened.st_ino) == (
        resolved.st_dev,
        resolved.st_ino,
    )
    if sys.platform == "darwin":
        identity_matches = (
            opened.st_ino == resolved.st_ino
            and opened.st_size == resolved.st_size
            and opened.st_uid == resolved.st_uid
        )
    if not identity_matches:
        raise CustodyUnavailable(
            "descriptor-bound executable path does not resolve to the retained inode"
        )
    return path


def _decode_process_stream(payload: bytes) -> str:
    return payload.decode("utf-8", errors="replace")


def _process_group_exists(pid: int) -> bool:
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _kill_process_group(
    pid: int,
    poll: Callable[[], Optional[int]],
    *,
    immediate_kill: bool = False,
) -> int:
    # The session leader may exit before a forked descendant. A leader-only
    # poll is therefore not proof that the isolated process group is empty.
    # A deadline or stream overflow kills the group with SIGKILL at once; a
    # leader that exited on its own gets SIGTERM, then SIGKILL, for any
    # straggler still in its group.
    returncode = poll()
    signals = (signal.SIGKILL,) if immediate_kill else (signal.SIGTERM, signal.SIGKILL)
    for signum in signals:
        try:
            if _process_group_exists(pid):
                os.killpg(pid, signum)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + PRODUCER_TERMINATION_GRACE_SECONDS
        while time.monotonic() < deadline:
            observed = poll()
            if observed is not None:
                returncode = observed
            if not _process_group_exists(pid):
                if returncode is None:
                    # The leader can exit between the poll and the group
                    # probe; reap it once more before calling that a failure.
                    returncode = poll()
                if returncode is None:
                    raise CustodyUnavailable(
                        "producer process group disappeared before its leader was reaped"
                    )
                return returncode
            time.sleep(0.01)
    raise CustodyUnavailable(
        "producer process group still has surviving descendants after SIGKILL"
    )


def _collect_bounded_process(
    pid: int,
    stdout_fd: int,
    stderr_fd: int,
    *,
    argv: list[str],
    timeout: float,
    poll: Callable[[], Optional[int]],
) -> subprocess.CompletedProcess[str]:
    if timeout <= 0 or timeout > 3600:
        raise CustodyUnavailable("producer deadline is outside the safe bound")
    selector = selectors.DefaultSelector()
    streams = {
        stdout_fd: ("stdout", bytearray()),
        stderr_fd: ("stderr", bytearray()),
    }
    for descriptor in streams:
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    returncode: Optional[int] = None
    failure: Optional[str] = None
    try:
        while selector.get_map() or returncode is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = f"producer deadline exceeded after {timeout:g} seconds"
                break
            events = selector.select(min(0.1, remaining))
            for key, _ in events:
                descriptor = int(key.fd)
                label, payload = streams[descriptor]
                try:
                    block = os.read(descriptor, 65536)
                except BlockingIOError:
                    continue
                if not block:
                    selector.unregister(descriptor)
                    os.close(descriptor)
                    continue
                if len(payload) + len(block) > PRODUCER_STREAM_LIMIT:
                    failure = (
                        f"producer {label} exceeded {PRODUCER_STREAM_LIMIT} bytes"
                    )
                    break
                payload.extend(block)
            if failure is not None:
                break
            if returncode is None:
                returncode = poll()
        if failure is not None:
            _kill_process_group(pid, poll, immediate_kill=True)
            raise CustodyUnavailable(failure)
        if returncode is None:
            returncode = poll()
        # This is required on every exit, including a successful or failed
        # leader: an exited leader can leave descendants in the same session.
        returncode = _kill_process_group(pid, poll)
        return subprocess.CompletedProcess(
            argv,
            returncode,
            _decode_process_stream(bytes(streams[stdout_fd][1])),
            _decode_process_stream(bytes(streams[stderr_fd][1])),
        )
    except BaseException as exc:
        try:
            _kill_process_group(pid, poll, immediate_kill=True)
        except (CustodyUnavailable, ChildProcessError, ProcessLookupError) as cleanup:
            raise CustodyUnavailable(
                "producer failed and its isolated process group could not be proven empty"
            ) from cleanup
        raise
    finally:
        selector.close()
        for descriptor in (stdout_fd, stderr_fd):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _darwin_spawn_descriptor(
    executable_fd: int,
    arguments: list[str],
    *,
    immutable_path: str,
    cwd_fd: int,
    environment: Mapping[str, str],
    pass_fds: tuple[int, ...],
) -> tuple[int, int, int, Callable[[], Optional[int]], list[str]]:
    executable = immutable_path
    argv = [executable, *arguments]
    stdout_read, stdout_write = os.pipe()
    stderr_read, stderr_write = os.pipe()
    libc = ctypes.CDLL(None, use_errno=True)
    required = (
        "posix_spawn",
        "posix_spawnattr_init",
        "posix_spawnattr_destroy",
        "posix_spawnattr_setflags",
        "posix_spawn_file_actions_init",
        "posix_spawn_file_actions_destroy",
        "posix_spawn_file_actions_addopen",
        "posix_spawn_file_actions_adddup2",
        "posix_spawn_file_actions_addinherit_np",
        "posix_spawn_file_actions_addfchdir_np",
    )
    if any(not hasattr(libc, name) for name in required):
        for descriptor in (stdout_read, stdout_write, stderr_read, stderr_write):
            os.close(descriptor)
        raise CustodyUnavailable(
            "Darwin descriptor-bound posix_spawn API is unavailable"
        )

    def must(result: int, label: str) -> None:
        if result:
            raise CustodyUnavailable(f"{label} failed: {os.strerror(result)}")

    attr = ctypes.c_void_p()
    actions = ctypes.c_void_p()
    actions_initialized = False
    attr_initialized = False
    spawned = False
    try:
        must(libc.posix_spawnattr_init(ctypes.byref(attr)), "posix_spawnattr_init")
        attr_initialized = True
        must(
            libc.posix_spawnattr_setflags(
                ctypes.byref(attr),
                ctypes.c_short(
                    DARWIN_POSIX_SPAWN_SETSID
                    | DARWIN_POSIX_SPAWN_CLOEXEC_DEFAULT
                ),
            ),
            "posix_spawnattr_setflags",
        )
        must(
            libc.posix_spawn_file_actions_init(ctypes.byref(actions)),
            "posix_spawn_file_actions_init",
        )
        actions_initialized = True
        must(
            libc.posix_spawn_file_actions_addopen(
                ctypes.byref(actions), 0, b"/dev/null", os.O_RDONLY, 0
            ),
            "posix_spawn stdin",
        )
        must(
            libc.posix_spawn_file_actions_adddup2(
                ctypes.byref(actions), stdout_write, 1
            ),
            "posix_spawn stdout",
        )
        must(
            libc.posix_spawn_file_actions_adddup2(
                ctypes.byref(actions), stderr_write, 2
            ),
            "posix_spawn stderr",
        )
        inherited = tuple(sorted(set((executable_fd, cwd_fd, *pass_fds))))
        for descriptor in inherited:
            must(
                libc.posix_spawn_file_actions_addinherit_np(
                    ctypes.byref(actions), descriptor
                ),
                "posix_spawn retained descriptor inheritance",
            )
        must(
            libc.posix_spawn_file_actions_addfchdir_np(
                ctypes.byref(actions), cwd_fd
            ),
            "posix_spawn descriptor cwd",
        )
        pid = ctypes.c_int()
        argv_values = _CStringArray(argv)
        env_values = _CStringArray(
            [f"{name}={value}" for name, value in environment.items()]
        )
        must(
            libc.posix_spawn(
                ctypes.byref(pid),
                os.fsencode(executable),
                ctypes.byref(actions),
                ctypes.byref(attr),
                argv_values.array,
                env_values.array,
            ),
            "descriptor-bound posix_spawn",
        )
        spawned = True
    finally:
        if actions_initialized:
            libc.posix_spawn_file_actions_destroy(ctypes.byref(actions))
        if attr_initialized:
            libc.posix_spawnattr_destroy(ctypes.byref(attr))
        os.close(stdout_write)
        os.close(stderr_write)
        if not spawned:
            os.close(stdout_read)
            os.close(stderr_read)

    state: dict[str, Optional[int]] = {"returncode": None}

    def poll() -> Optional[int]:
        if state["returncode"] is not None:
            return state["returncode"]
        try:
            waited, status = os.waitpid(pid.value, os.WNOHANG)
        except ChildProcessError:
            return state["returncode"]
        if waited:
            state["returncode"] = os.waitstatus_to_exitcode(status)
        return state["returncode"]

    return pid.value, stdout_read, stderr_read, poll, argv


def _run_bounded_descriptor(
    executable_fd: int,
    arguments: list[str],
    *,
    cwd_fd: int,
    environment: Mapping[str, str],
    pass_fds: tuple[int, ...] = (),
    timeout: float = PRODUCER_TIMEOUT_SECONDS,
    darwin_immutable_path: Optional[str] = None,
) -> subprocess.CompletedProcess[str]:
    """Run one descriptor-bound executable under a bounded, isolated session.

    The child gets exactly `environment` (callers pass a scrubbed one), stdin
    from /dev/null, its own session and process group, and only the retained
    descriptors in `pass_fds`. stdout and stderr are each capped at
    PRODUCER_STREAM_LIMIT bytes; an overflow or the deadline kills the whole
    process group with SIGKILL and refuses. After a normal exit the group is
    killed again so no straggler outlives the run. The executable descriptor
    (and, on Darwin, the pathname it is spawned through) must keep the same
    identity before and after the run.

    Residual risk, accepted by the owner ruling of 2026-10-09: a process-group
    boundary is not a descendant-containment boundary. A descendant that calls
    setsid(2) leaves the group and can outlive every cleanup above.
    """
    if executable_fd < 0 or cwd_fd < 0:
        raise CustodyUnavailable(
            "descriptor-bound execution requires executable and cwd descriptors"
        )
    opened = os.fstat(executable_fd)
    if not stat.S_ISREG(opened.st_mode) or not stat.S_IMODE(opened.st_mode) & 0o111:
        raise CustodyUnavailable("descriptor-bound executable is not executable")
    cwd_info = os.fstat(cwd_fd)
    if not stat.S_ISDIR(cwd_info.st_mode):
        raise CustodyUnavailable("descriptor-bound cwd is not a directory")
    for value in arguments:
        if not isinstance(value, str) or "\0" in value:
            raise CustodyUnavailable("producer argument is not a safe string")
    safe_environment: dict[str, str] = {}
    for name, value in environment.items():
        if (
            not isinstance(name, str)
            or not isinstance(value, str)
            or not name
            or "=" in name
            or "\0" in name
            or "\0" in value
        ):
            raise CustodyUnavailable("producer environment is malformed")
        safe_environment[name] = value
    inherited = tuple(sorted(set((executable_fd, cwd_fd, *pass_fds))))
    if sys.platform == "darwin":
        if not darwin_immutable_path:
            raise CustodyUnavailable(
                "Darwin execution requires an authenticated immutable pathname"
            )
        current = os.lstat(darwin_immutable_path)
        if _file_identity(current) != _file_identity(opened):
            raise CustodyUnavailable(
                "Darwin immutable execution path differs from its retained descriptor"
            )
        pid, stdout_fd, stderr_fd, poll, argv = _darwin_spawn_descriptor(
            executable_fd,
            arguments,
            immutable_path=darwin_immutable_path,
            cwd_fd=cwd_fd,
            environment=safe_environment,
            pass_fds=inherited,
        )
        completed = _collect_bounded_process(
            pid,
            stdout_fd,
            stderr_fd,
            argv=argv,
            timeout=timeout,
            poll=poll,
        )
        _require_unchanged_executable(
            executable_fd, opened, darwin_immutable_path
        )
        return completed
    if not sys.platform.startswith("linux"):
        raise CustodyUnavailable(
            "descriptor-bound native execution is unsupported on this host"
        )
    executable = _descriptor_execution_path(executable_fd)
    cwd = _descriptor_execution_path(cwd_fd)
    argv = [executable, *arguments]
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=safe_environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        pass_fds=inherited,
        start_new_session=True,
        text=False,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise CustodyUnavailable("producer pipes were not created")
    stdout_fd = os.dup(process.stdout.fileno())
    stderr_fd = os.dup(process.stderr.fileno())
    process.stdout.close()
    process.stderr.close()
    completed = _collect_bounded_process(
        process.pid,
        stdout_fd,
        stderr_fd,
        argv=argv,
        timeout=timeout,
        poll=process.poll,
    )
    _require_unchanged_executable(executable_fd, opened, None)
    return completed


def _require_unchanged_executable(
    executable_fd: int,
    before: os.stat_result,
    darwin_path: Optional[str],
) -> None:
    """Refuse a run whose executable descriptor or spawn path changed."""
    after = os.fstat(executable_fd)
    if _file_identity(after) != _file_identity(before):
        raise CustodyUnavailable(
            "descriptor-bound executable changed while the producer ran"
        )
    if darwin_path is not None and _file_identity(os.lstat(darwin_path)) != _file_identity(before):
        raise CustodyUnavailable(
            "Darwin execution path changed while the producer ran"
        )


@dataclass(frozen=True)
class SourceClosure:
    name: str
    digest: str
    files: tuple[str, ...]
    dependency_digest: str = ""
    modules: tuple[str, ...] = ()


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


@dataclass(frozen=True)
class DescriptorNode:
    path: str
    fd: int
    identity: tuple[int, int, int, int, int, int, int, int]
    parent: Optional[str]
    name: str
    is_directory: bool


@dataclass(frozen=True)
class AuthenticatedPublicationHandoff:
    target: str
    output_path: str
    descriptor_identity: tuple[int, int, int, int, int, int, int, int]
    sha256: str
    input_sha256: str = ""
    input_size: int = 0
    receipt_path: str = ""
    receipt_sha256: str = ""
    sealed: bool = False
    custody: Any = field(default=None, compare=False, repr=False)


class DescriptorCustody:
    """Retain a file and every ancestor by descriptor until verification ends."""

    def __init__(self, label: str, error_type: type[RuntimeError] = ArtifactInvalid) -> None:
        self.label = label
        self.error_type = error_type
        self._nodes: dict[str, DescriptorNode] = {}
        self._closed = False
        self._failure_observed = False
        self._content_watches: set[str] = set()
        self._name_watches: set[str] = set()
        self._active_node_watches: set[int] = set()
        self._publication_started: dict[str, float] = {}
        self._event_queue = select.kqueue() if hasattr(select, "kqueue") else None
        self._inotify_fd = -1
        self._inotify_paths: dict[int, str] = {}
        if self._event_queue is None and sys.platform.startswith("linux"):
            libc = ctypes.CDLL(None, use_errno=True)
            init = libc.inotify_init1
            init.argtypes = [ctypes.c_int]
            init.restype = ctypes.c_int
            self._inotify_fd = init(os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
            if self._inotify_fd < 0:
                error = ctypes.get_errno()
                self._fail(f"cannot initialize Linux mutation custody: {os.strerror(error)}")
        if self._event_queue is None and self._inotify_fd < 0:
            self._fail("host has no supported descriptor mutation event facility")

    def _fail(self, detail: str) -> None:
        self._failure_observed = True
        raise self.error_type(f"{self.label}: {detail}")

    @staticmethod
    def _canonical(path: str) -> str:
        if not os.path.isabs(path):
            raise ValueError("descriptor custody requires an absolute path")
        absolute = os.path.normpath(path)
        if sys.platform == "darwin" or os.path.isdir("/private/var"):
            for alias, physical in (
                ("/var", "/private/var"),
                ("/tmp", "/private/tmp"),
                ("/etc", "/private/etc"),
            ):
                if absolute != alias and not absolute.startswith(alias + os.sep):
                    continue
                try:
                    target = os.readlink(alias)
                except OSError:
                    continue
                if os.path.normpath(os.path.join(os.sep, target)) != physical:
                    raise ValueError(f"system compatibility alias changed: {alias}")
                return physical + absolute[len(alias):]
        return absolute

    @staticmethod
    def _directory_flags() -> int:
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        directory = getattr(os, "O_DIRECTORY", 0)
        if not nofollow or not directory or os.open not in os.supports_dir_fd:
            raise OSError("descriptor-relative O_NOFOLLOW directory opens are required")
        return os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)

    @staticmethod
    def _file_flags() -> int:
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if not nofollow or os.open not in os.supports_dir_fd:
            raise OSError("descriptor-relative O_NOFOLLOW file opens are required")
        return os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)

    @staticmethod
    def _directory_identity(info: os.stat_result) -> tuple[int, int, int, int]:
        return (info.st_dev, info.st_ino, info.st_uid, info.st_mode)

    def _watch_node(
        self,
        node: DescriptorNode,
        watch_contents: bool = False,
        names_only: bool = False,
        enabled: bool = True,
    ) -> None:
        if self._event_queue is None and self._inotify_fd >= 0:
            mask = 0x00000004 | 0x00000800 | 0x00000400 | 0x00008000
            if not node.is_directory:
                mask |= 0x00000002 | 0x00000008
            if watch_contents:
                mask |= 0x00000100 | 0x00000200 | 0x00000040 | 0x00000080
                if not names_only:
                    mask |= 0x00000008
            libc = ctypes.CDLL(None, use_errno=True)
            add = libc.inotify_add_watch
            add.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
            add.restype = ctypes.c_int
            descriptor_path = f"/proc/self/fd/{node.fd}".encode("ascii")
            watch = add(self._inotify_fd, descriptor_path, mask | 0x20000000)
            if watch < 0:
                error = ctypes.get_errno()
                self._fail(
                    f"cannot install Linux mutation watch for {node.path}: "
                    f"{os.strerror(error)}"
                )
            self._inotify_paths[watch] = node.path
            self._active_node_watches.add(node.fd)
            return
        if self._event_queue is None:
            return
        flags = (
            select.KQ_NOTE_RENAME
            | select.KQ_NOTE_DELETE
            | select.KQ_NOTE_REVOKE
        )
        if not node.is_directory or watch_contents:
            flags |= select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND | select.KQ_NOTE_LINK
        if node.is_directory:
            flags |= select.KQ_NOTE_ATTRIB
        event = select.kevent(
            node.fd,
            filter=select.KQ_FILTER_VNODE,
            flags=(
                select.KQ_EV_ADD
                | select.KQ_EV_CLEAR
                | (0 if enabled else select.KQ_EV_DISABLE)
            ),
            fflags=flags,
        )
        try:
            self._event_queue.control([event], 0, 0)
        except OSError as exc:
            self._fail(f"cannot install descriptor mutation watch for {node.path}: {exc}")
        if enabled:
            self._active_node_watches.add(node.fd)
        else:
            self._active_node_watches.discard(node.fd)

    def _enable_node_watch(self, node: DescriptorNode) -> None:
        if self._event_queue is None:
            return
        event = select.kevent(
            node.fd,
            filter=select.KQ_FILTER_VNODE,
            flags=select.KQ_EV_ENABLE | select.KQ_EV_CLEAR,
        )
        try:
            self._event_queue.control([event], 0, 0)
        except OSError as exc:
            self._fail(f"cannot enable descriptor mutation watch for {node.path}: {exc}")
        self._active_node_watches.add(node.fd)

    def watch_directory_contents(self, path: str) -> None:
        absolute = self._canonical(path)
        node = self.bind_directory(absolute)
        if absolute not in self._content_watches:
            self._content_watches.add(absolute)
            self._watch_node(node, watch_contents=True)

    def watch_directory_names(self, path: str) -> None:
        """Watch child-name changes while allowing writes to an adopted child."""
        absolute = self._canonical(path)
        node = self.bind_directory(absolute)
        if absolute not in self._name_watches and absolute not in self._content_watches:
            self._name_watches.add(absolute)
            self._watch_node(node, watch_contents=True, names_only=True)

    def bind_directory(self, path: str) -> DescriptorNode:
        try:
            absolute = self._canonical(path)
            existing = self._nodes.get(absolute)
            if existing is not None:
                if not existing.is_directory:
                    self._fail(f"path was already bound as a file: {absolute}")
                return existing
            if absolute == os.sep:
                fd = os.open(os.sep, self._directory_flags())
                parent = None
                name = ""
            else:
                parent_path = os.path.dirname(absolute)
                parent_node = self.bind_directory(parent_path)
                name = os.path.basename(absolute)
                fd = os.open(name, self._directory_flags(), dir_fd=parent_node.fd)
                parent = parent_path
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode):
                os.close(fd)
                self._fail(f"ancestor is not a directory: {absolute}")
            node = DescriptorNode(
                absolute,
                fd,
                _file_identity(info),
                parent,
                name,
                True,
            )
            self._nodes[absolute] = node
            self._watch_node(node)
            return node
        except self.error_type:
            raise
        except FileNotFoundError as exc:
            if issubclass(self.error_type, ArtifactInvalid):
                raise ArtifactMissing(f"{self.label}: path is missing: {path}") from exc
            self._fail(f"cannot bind missing ancestor {path}: {exc}")
        except (OSError, ValueError) as exc:
            self._fail(f"cannot bind ancestor {path}: {exc}")
        raise AssertionError("unreachable")

    def bind_file(
        self,
        path: str,
        maximum: int = 512 * 1024 * 1024,
        *,
        require_owner: bool = False,
        require_readonly: bool = False,
    ) -> DescriptorNode:
        try:
            absolute = self._canonical(path)
            existing = self._nodes.get(absolute)
            if existing is not None:
                if existing.is_directory:
                    self._fail(f"path was already bound as a directory: {absolute}")
                if require_owner and existing.identity[2] != os.getuid():
                    self._fail(f"file is not owned by the current user: {absolute}")
                if require_readonly and stat.S_IMODE(existing.identity[3]) & 0o222:
                    self._fail(f"file is not sealed read-only: {absolute}")
                return existing
            parent_path = os.path.dirname(absolute)
            parent = self.bind_directory(parent_path)
            name = os.path.basename(absolute)
            fd = os.open(name, self._file_flags(), dir_fd=parent.fd)
            info = os.fstat(fd)
            unsafe = (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_size <= 0
                or info.st_size > maximum
            )
            if unsafe:
                os.close(fd)
                self._fail(f"file is missing, unsafe, or outside the size limit: {absolute}")
            if require_owner and info.st_uid != os.getuid():
                os.close(fd)
                self._fail(f"file is not owned by the current user: {absolute}")
            if require_readonly and stat.S_IMODE(info.st_mode) & 0o222:
                os.close(fd)
                self._fail(f"file is not sealed read-only: {absolute}")
            node = DescriptorNode(
                absolute,
                fd,
                _file_identity(info),
                parent_path,
                name,
                False,
            )
            self._nodes[absolute] = node
            self._watch_node(node)
            self.watch_directory_contents(parent_path)
            return node
        except self.error_type:
            raise
        except FileNotFoundError as exc:
            if issubclass(self.error_type, ArtifactInvalid):
                raise ArtifactMissing(f"{self.label}: path is missing: {path}") from exc
            self._fail(f"cannot bind missing file {path}: {exc}")
        except (OSError, ValueError) as exc:
            self._fail(f"cannot bind file {path}: {exc}")
        raise AssertionError("unreachable")

    def adopt_created_file(self, path: str, fd: int) -> DescriptorNode:
        """Take ownership of an O_EXCL descriptor before its pathname can be reopened."""
        try:
            absolute = self._canonical(path)
            if absolute in self._nodes:
                self._fail(f"created file was already bound: {absolute}")
            parent_path = os.path.dirname(absolute)
            parent = self.bind_directory(parent_path)
            name = os.path.basename(absolute)
            info = os.fstat(fd)
            current = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or _file_identity(info) != _file_identity(current)
            ):
                self._fail(f"new O_EXCL file identity is unsafe: {absolute}")
            node = DescriptorNode(
                absolute, fd, _file_identity(info), parent_path, name, False
            )
            self._nodes[absolute] = node
            self._publication_started[absolute] = time.time()
            # The claim inode itself is the publication boundary. Watching the
            # parent cannot distinguish one rename from two on Darwin because
            # vnode events coalesce, and legitimate generation sidecars also
            # mutate that directory. A retained claim inode records direct
            # writes while rename/delete/link events remain fatal.
            self._watch_node(node)
            return node
        except self.error_type:
            raise
        except (OSError, ValueError) as exc:
            self._fail(f"cannot adopt new O_EXCL file {path}: {exc}")
        raise AssertionError("unreachable")

    def seal_created_file(self, path: str) -> DescriptorNode:
        """Freeze the final identity of an adopted descriptor after its bounded write."""
        absolute = self._canonical(path)
        node = self._nodes.get(absolute)
        if node is None or node.is_directory:
            self._fail(f"created file descriptor is not retained: {absolute}")
        try:
            info = os.fstat(node.fd)
            parent = self._nodes[node.parent or ""]
            current = os.stat(node.name, dir_fd=parent.fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_size <= 0
                or _file_identity(info) != _file_identity(current)
            ):
                self._fail(f"created file changed before sealing: {absolute}")
            sealed = DescriptorNode(
                node.path, node.fd, _file_identity(info), node.parent,
                node.name, False,
            )
            self._nodes[absolute] = sealed
            watch_was_active = sealed.fd in self._active_node_watches
            if not watch_was_active and self._event_queue is not None:
                # Register disabled so a Darwin vnode NOTE_WRITE generated by
                # the producer's completed write cannot become a post-seal
                # mutation event. Revalidate the exact descriptor/name pair,
                # then enable the watch for every subsequent change.
                self._watch_node(sealed, enabled=False)
                latest = os.fstat(sealed.fd)
                named = os.stat(
                    sealed.name,
                    dir_fd=parent.fd,
                    follow_symlinks=False,
                )
                if (
                    _file_identity(latest) != sealed.identity
                    or _file_identity(named) != sealed.identity
                ):
                    self._fail(f"created file changed while sealing: {absolute}")
                self._enable_node_watch(sealed)
            elif not watch_was_active:
                self._watch_node(sealed)
                latest = os.fstat(sealed.fd)
                named = os.stat(
                    sealed.name,
                    dir_fd=parent.fd,
                    follow_symlinks=False,
                )
                if (
                    _file_identity(latest) != sealed.identity
                    or _file_identity(named) != sealed.identity
                ):
                    self._fail(f"created file changed while sealing: {absolute}")
            else:
                # Atomic publication installed an active watch before this
                # seal. Re-registering it disabled on Darwin can clear a real
                # post-publication vnode event. Preserve it and only rebind
                # the descriptor/name identity.
                latest = os.fstat(sealed.fd)
                named = os.stat(
                    sealed.name,
                    dir_fd=parent.fd,
                    follow_symlinks=False,
                )
                if (
                    _file_identity(latest) != sealed.identity
                    or _file_identity(named) != sealed.identity
                ):
                    self._fail(f"created file changed while sealing: {absolute}")
            return sealed
        except self.error_type:
            raise
        except OSError as exc:
            self._fail(f"cannot seal new O_EXCL file {absolute}: {exc}")
        raise AssertionError("unreachable")

    def verify_created_file_path(self, path: str) -> None:
        """Verify parent/source custody while permitting only this file's write."""
        if self._closed:
            self._fail("descriptor custody was closed before verification")
        absolute = self._canonical(path)
        created = self._nodes.get(absolute)
        if created is None or created.is_directory:
            self._fail(f"created file descriptor is not retained: {absolute}")
        self._verify_no_events(absolute)
        for node_path in sorted(
            self._nodes, key=lambda item: (item.count(os.sep), item)
        ):
            node = self._nodes[node_path]
            try:
                descriptor_info = os.fstat(node.fd)
                if node_path == absolute:
                    parent = self._nodes[node.parent or ""]
                    current = os.stat(
                        node.name,
                        dir_fd=parent.fd,
                        follow_symlinks=False,
                    )
                    if (
                        not stat.S_ISREG(descriptor_info.st_mode)
                        or descriptor_info.st_nlink != 1
                        or descriptor_info.st_dev != node.identity[0]
                        or descriptor_info.st_ino != node.identity[1]
                        or descriptor_info.st_uid != node.identity[2]
                        or _file_identity(current) != _file_identity(descriptor_info)
                    ):
                        self._fail(
                            f"created file descriptor/name changed before sealing: {absolute}"
                        )
                    continue
                descriptor_identity = self._directory_identity(descriptor_info)
                if descriptor_identity != self._directory_identity_from_tuple(node.identity):
                    self._fail(f"descriptor identity changed during custody: {node_path}")
                if node.parent is None:
                    current = os.lstat(os.sep)
                else:
                    parent = self._nodes[node.parent]
                    current = os.stat(
                        node.name,
                        dir_fd=parent.fd,
                        follow_symlinks=False,
                    )
                if (
                    self._directory_identity(current)
                    != self._directory_identity_from_tuple(node.identity)
                ):
                    self._fail(
                        f"descriptor-relative name changed during custody: {node_path}"
                    )
            except self.error_type:
                raise
            except OSError as exc:
                self._fail(f"cannot verify pre-seal custody for {node_path}: {exc}")
        self._verify_no_events(absolute)

    def bind_atomic_publication(
        self,
        path: str,
        handoff: AuthenticatedPublicationHandoff,
    ) -> DescriptorNode:
        """Bind one fresh exclusive producer generation after its receipt.

        The retained core producer does not accept a precreated output file.
        It builds in a private sibling directory, installs the staged inode by
        an exclusive hard link, retains that inode through receipt emission,
        and refuses any pre-existing destination. The caller records absence
        before launch. This method then opens the exact receipt identity once,
        under the already-retained parent descriptors, and never relabels or
        replaces its pathname.
        """
        absolute = self._canonical(path)
        if (
            handoff.output_path != path
            or absolute not in self._publication_started
            or absolute in self._nodes
            or re.fullmatch(r"[0-9a-f]{64}", handoff.sha256) is None
        ):
            self._fail(f"exclusive producer publication handoff is invalid: {absolute}")
        node = self.bind_file(absolute)
        started_ns = int(self._publication_started[absolute] * 1_000_000_000)
        if (
            node.identity != handoff.descriptor_identity
            or node.identity[7] < started_ns
            or hashlib.sha256(self.read_file(absolute)).hexdigest() != handoff.sha256
        ):
            self._fail(
                "exclusive producer publication differs from its fresh retained "
                f"generation receipt: {absolute}"
            )
        self.verify()
        return node

    def _verify_atomic_publication_event(
        self, parent: DescriptorNode, name: str
    ) -> None:
        """Accept one rename-to-name event and reject substitutions/restores."""
        if self._inotify_fd >= 0:
            try:
                payload = os.read(self._inotify_fd, 1024 * 1024)
            except BlockingIOError:
                payload = b""
            except OSError as exc:
                self._fail(f"cannot read Linux publication custody: {exc}")
            events: list[tuple[str, int, str]] = []
            cursor = 0
            while cursor < len(payload):
                if cursor + 16 > len(payload):
                    self._fail("Linux publication watch returned a truncated event")
                watch, mask, _, name_size = struct.unpack_from("iIII", payload, cursor)
                event_end = cursor + 16 + name_size
                if event_end > len(payload):
                    self._fail("Linux publication watch returned an invalid event")
                raw_name = payload[cursor + 16:event_end].split(b"\0", 1)[0]
                try:
                    event_name = os.fsdecode(raw_name)
                except UnicodeError:
                    event_name = ""
                events.append(
                    (self._inotify_paths.get(watch, f"watch {watch}"), mask, event_name)
                )
                cursor = event_end
            expected = [(parent.path, 0x00000080, name)]
            if events != expected:
                self._fail(
                    f"atomic publication observed unrelated substitution or swap/restore: "
                    f"{parent.path}/{name}"
                )
            return
        if self._event_queue is None:
            self._fail("host cannot authenticate atomic publication events")
        try:
            events = self._event_queue.control(None, max(2, len(self._nodes) + 1), 0)
        except OSError as exc:
            self._fail(f"cannot read Darwin publication custody: {exc}")
        unsafe = select.KQ_NOTE_RENAME | select.KQ_NOTE_DELETE | select.KQ_NOTE_REVOKE
        if not events or any(
            event.ident != parent.fd
            or event.fflags & unsafe
            or not event.fflags & select.KQ_NOTE_WRITE
            for event in events
        ):
            self._fail(
                f"atomic publication observed unrelated substitution or swap/restore: "
                f"{parent.path}/{name}"
            )

    def read_file(self, path: str, maximum: int = 512 * 1024 * 1024) -> bytes:
        absolute = self._canonical(path)
        node = self._nodes.get(absolute)
        if node is None:
            node = self.bind_file(absolute, maximum)
        if node.is_directory:
            self._fail(f"cannot read bound directory as a file: {absolute}")
        try:
            if _file_identity(os.fstat(node.fd)) != node.identity:
                self._fail(f"bound file changed before read: {absolute}")
            os.lseek(node.fd, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(node.fd, min(1 << 20, maximum + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > maximum:
                    self._fail(f"bound file exceeds the size limit: {absolute}")
            if _file_identity(os.fstat(node.fd)) != node.identity:
                self._fail(f"bound file changed while read: {absolute}")
            return b"".join(chunks)
        except self.error_type:
            raise
        except OSError as exc:
            self._fail(f"cannot read bound file {absolute}: {exc}")
        raise AssertionError("unreachable")

    def bind_tree(self, root: str, maximum_file: int = 512 * 1024 * 1024) -> None:
        pending = [self._canonical(root)]
        while pending:
            directory = pending.pop()
            node = self.bind_directory(directory)
            self.watch_directory_contents(directory)
            try:
                with os.scandir(node.fd) as scan:
                    entries = sorted(scan, key=lambda item: os.fsencode(item.name))
            except OSError as exc:
                self._fail(f"cannot enumerate bound tree directory {directory}: {exc}")
            for entry in entries:
                path = os.path.join(directory, entry.name)
                if entry.is_symlink():
                    self._fail(f"bound tree contains a symbolic link: {path}")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                elif entry.is_file(follow_symlinks=False):
                    self.bind_file(path, maximum_file)
                else:
                    self._fail(f"bound tree contains a non-regular entry: {path}")

    def verify(self) -> None:
        if self._closed:
            self._fail("descriptor custody was closed before verification")
        self._verify_no_events()
        for path in sorted(self._nodes, key=lambda item: (item.count(os.sep), item)):
            node = self._nodes[path]
            try:
                descriptor_info = os.fstat(node.fd)
                descriptor_changed = (
                    self._directory_identity(descriptor_info)
                    != self._directory_identity_from_tuple(node.identity)
                    if node.is_directory
                    else _file_identity(descriptor_info) != node.identity
                )
                if descriptor_changed:
                    self._fail(f"descriptor identity changed during custody: {path}")
                if node.parent is None:
                    current = os.lstat(os.sep)
                else:
                    parent = self._nodes[node.parent]
                    current = os.stat(
                        node.name,
                        dir_fd=parent.fd,
                        follow_symlinks=False,
                    )
                current_changed = (
                    self._directory_identity(current)
                    != self._directory_identity_from_tuple(node.identity)
                    if node.is_directory
                    else _file_identity(current) != node.identity
                )
                if current_changed:
                    self._fail(f"descriptor-relative name changed during custody: {path}")
            except self.error_type:
                raise
            except OSError as exc:
                self._fail(f"cannot revalidate descriptor custody for {path}: {exc}")
        self._verify_no_events()

    @staticmethod
    def _directory_identity_from_tuple(
        identity: tuple[int, int, int, int, int, int, int, int]
    ) -> tuple[int, int, int, int]:
        return identity[0], identity[1], identity[2], identity[3]

    def _verify_no_events(self, allowed_unsealed: Optional[str] = None) -> None:
        if self._inotify_fd >= 0:
            try:
                payload = os.read(self._inotify_fd, 1024 * 1024)
            except BlockingIOError:
                payload = b""
            except OSError as exc:
                self._fail(f"cannot read Linux mutation watches: {exc}")
            cursor = 0
            while cursor < len(payload):
                if cursor + 16 > len(payload):
                    self._fail("Linux mutation watch returned a truncated event")
                watch, mask, _, name_size = struct.unpack_from("iIII", payload, cursor)
                event_end = cursor + 16 + name_size
                if event_end > len(payload):
                    self._fail("Linux mutation watch returned an invalid event")
                raw_name = payload[cursor + 16:event_end].split(b"\0", 1)[0]
                try:
                    name = os.fsdecode(raw_name)
                except UnicodeError:
                    name = ""
                watched_path = self._inotify_paths.get(watch, f"watch {watch}")
                permitted = (
                    allowed_unsealed is not None
                    and watched_path == allowed_unsealed
                    and name == ""
                    and mask & ~(0x00000002 | 0x00000004 | 0x00000008) == 0
                )
                if not permitted:
                    self._fail(
                        f"descriptor mutation event observed during custody: {watched_path}"
                    )
                cursor = event_end
            return
        if self._event_queue is None:
            return
        try:
            events = self._event_queue.control(None, max(1, len(self._nodes)), 0)
        except OSError as exc:
            self._fail(f"cannot read descriptor mutation watches: {exc}")
        if events:
            by_fd = {node.fd: node.path for node in self._nodes.values()}
            allowed_flags = select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND
            if allowed_unsealed is not None and all(
                by_fd.get(event.ident) == allowed_unsealed
                and event.fflags
                and event.fflags & ~allowed_flags == 0
                for event in events
            ):
                return
            changed = by_fd.get(events[0].ident, f"fd {events[0].ident}")
            self._fail(f"descriptor mutation event observed during custody: {changed}")

    def close(self) -> None:
        if self._closed:
            return
        failure_was_already_observed = self._failure_observed
        failure: Optional[BaseException] = None
        try:
            # A close that simply discards kqueue/inotify state can erase the
            # last mutation event. Revalidate names/descriptors and drain the
            # pending queue while every descriptor is still held. This is a
            # final fail-closed check, not a cure for using a bare FRESH after
            # custody has ended; the consumer transaction below is what closes
            # that post-return gap.
            self.verify()
        except BaseException as exc:
            failure = exc
        finally:
            if self._event_queue is not None:
                self._event_queue.close()
            if self._inotify_fd >= 0:
                os.close(self._inotify_fd)
                self._inotify_fd = -1
                self._inotify_paths.clear()
            for node in sorted(
                self._nodes.values(),
                key=lambda item: item.path.count(os.sep),
                reverse=True,
            ):
                try:
                    os.close(node.fd)
                except OSError:
                    pass
            self._nodes.clear()
            self._active_node_watches.clear()
            self._publication_started.clear()
            self._closed = True
        if failure is not None and not failure_was_already_observed:
            raise failure

    def __enter__(self) -> "DescriptorCustody":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


def _darwin_immutable_executable(
    path: str,
    descriptor: int,
    *,
    label: str,
) -> None:
    if sys.platform != "darwin":
        return
    absolute = os.path.normpath(path)
    if not os.path.isabs(absolute):
        raise CustodyUnavailable(f"{label} path is not absolute")
    opened = os.fstat(descriptor)
    named = os.lstat(absolute)
    immutable = getattr(stat, "SF_IMMUTABLE", 0x00020000)
    restricted = 0x00080000
    if (
        _file_identity(opened) != _file_identity(named)
        or not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or opened.st_uid != 0
        or opened.st_gid != 0
        or not stat.S_IMODE(opened.st_mode) & 0o111
        or not opened.st_flags & (immutable | restricted)
    ):
        raise CustodyUnavailable(
            f"{label} is not one root-owned immutable executable"
        )
    current = os.path.dirname(absolute)
    while True:
        info = os.lstat(current)
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise CustodyUnavailable(
                f"{label} ancestor is mutable or not root-owned: {current}"
            )
        if current == os.sep:
            break
        current = os.path.dirname(current)


def _open_retained_executable(
    custody: DescriptorCustody,
    path: str,
    *,
    label: str,
) -> int:
    node = custody.bind_file(path)
    parent = custody._nodes.get(node.parent or "")
    if parent is None or not parent.is_directory:
        raise CustodyUnavailable(f"{label} parent descriptor is unavailable")
    flags = (
        getattr(os, "O_EXEC", os.O_RDONLY)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(node.name, flags, dir_fd=parent.fd)
    except OSError as exc:
        raise CustodyUnavailable(f"{label} executable open failed: {exc}") from exc
    opened = os.fstat(descriptor)
    if _file_identity(opened) != node.identity:
        os.close(descriptor)
        raise CustodyUnavailable(f"{label} changed before executable binding")
    _darwin_immutable_executable(path, descriptor, label=label)
    custody.verify()
    return descriptor


def _run_system_descriptor(
    executable: str,
    arguments: list[str],
    *,
    cwd: str,
    environment: Mapping[str, str],
    pass_fds: tuple[int, ...] = (),
    timeout: float = PRODUCER_TIMEOUT_SECONDS,
    retained_cwd_fd: Optional[int] = None,
) -> subprocess.CompletedProcess[str]:
    executable_custody = DescriptorCustody(
        "fixed producer executable", CustodyUnavailable
    )
    cwd_custody: Optional[DescriptorCustody] = None
    executable_fd = -1
    try:
        executable_fd = _open_retained_executable(
            executable_custody,
            executable,
            label="fixed producer executable",
        )
        if retained_cwd_fd is None:
            cwd_custody = DescriptorCustody("producer cwd", CustodyUnavailable)
            absolute_cwd = os.path.abspath(cwd)
            cwd_node = cwd_custody.bind_directory(absolute_cwd)
            cwd_custody.watch_directory_names(absolute_cwd)
            cwd_fd = cwd_node.fd
        else:
            cwd_fd = retained_cwd_fd
            if not stat.S_ISDIR(os.fstat(cwd_fd).st_mode):
                raise CustodyUnavailable("retained producer cwd is not a directory")
        completed = _run_bounded_descriptor(
            executable_fd,
            arguments,
            cwd_fd=cwd_fd,
            environment=environment,
            pass_fds=pass_fds,
            timeout=timeout,
            darwin_immutable_path=(executable if sys.platform == "darwin" else None),
        )
        executable_custody.verify()
        if cwd_custody is not None:
            cwd_custody.verify()
        return completed
    finally:
        if executable_fd >= 0:
            os.close(executable_fd)
        executable_custody.close()
        if cwd_custody is not None:
            cwd_custody.close()


def _assert_real_ancestors(path: str) -> None:
    absolute = os.path.abspath(path)
    repository = os.path.abspath(REPO_ROOT)
    try:
        if os.path.commonpath((repository, absolute)) != repository:
            return
    except ValueError:
        return
    current = repository
    relative = os.path.relpath(absolute, repository)
    for component in relative.split(os.sep)[:-1]:
        current = os.path.join(current, component)
        info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ArtifactInvalid(f"path ancestor is unsafe: {current}")


def _read_stable_file(path: str, label: str, maximum: int = 512 * 1024 * 1024) -> bytes:
    """Read one regular file while retaining every absolute path ancestor."""
    with DescriptorCustody(label) as custody:
        custody.bind_file(path, maximum)
        payload = custody.read_file(path, maximum)
        custody.verify()
        return payload


def _source_paths(root: str) -> list[str]:
    if os.path.islink(root) or not os.path.isdir(root):
        raise CustodyUnavailable(f"source root is missing, non-directory, or symbolic: {root}")
    files: list[str] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: os.fsencode(item.name))
        except OSError as exc:
            raise CustodyUnavailable(f"source root is unreadable: {directory}: {exc}") from exc
        for entry in entries:
            path = entry.path
            if entry.is_symlink():
                raise CustodyUnavailable(f"source closure contains a symlink: {path}")
            if entry.is_dir(follow_symlinks=False):
                pending.append(path)
                continue
            if not entry.is_file(follow_symlinks=False):
                raise CustodyUnavailable(f"source closure contains a non-regular leaf: {path}")
            if entry.name == ".DS_Store":
                continue
            if entry.name in ("go.mod", "go.sum") or os.path.splitext(entry.name)[1] in SOURCE_SUFFIXES:
                files.append(path)
    return sorted(files, key=lambda item: os.path.relpath(item, REPO_ROOT).replace(os.sep, "/"))


def _closure_digest(paths: list[str]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        relative = os.path.relpath(path, REPO_ROOT).replace(os.sep, "/")
        payload = _read_stable_file(path, f"source {relative}", 64 * 1024 * 1024)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(payload).hexdigest().encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _current_closure(name: str, roots: tuple[str, ...], files: tuple[str, ...] = ()) -> SourceClosure:
    paths: list[str] = []
    for root in roots:
        paths.extend(_source_paths(root))
    for path in files:
        if os.path.islink(path) or not os.path.isfile(path):
            raise CustodyUnavailable(f"source closure input is missing or symbolic: {path}")
        paths.append(path)
    unique = sorted(
        set(paths),
        key=lambda item: os.path.relpath(item, REPO_ROOT).replace(os.sep, "/"),
    )
    if len(unique) != len(paths):
        raise CustodyUnavailable(f"source closure {name} contains duplicate inputs")
    try:
        digest = _closure_digest(unique)
    except ArtifactInvalid as exc:
        raise CustodyUnavailable(f"source closure {name} could not be read: {exc}") from exc
    return SourceClosure(
        name,
        digest,
        tuple(os.path.relpath(path, REPO_ROOT).replace(os.sep, "/") for path in unique),
    )


@dataclass(frozen=True)
class GoTargetSpec:
    module_dir: str
    package: str
    goos: str
    goarch: str
    cgo_enabled: bool
    producer_files: tuple[str, ...]


@dataclass
class BoundSourceClosure:
    closure: SourceClosure
    custody: DescriptorCustody = field(repr=False)
    snapshot_root: str

    def verify(self) -> None:
        self.custody.verify()

    def close(self) -> None:
        self.custody.close()
        _discard_private_tree(self.snapshot_root)

    def path(self, repository_path: str) -> str:
        relative = os.path.relpath(repository_path, REPO_ROOT)
        if relative == os.pardir or relative.startswith(os.pardir + os.sep):
            raise CustodyUnavailable("producer path escaped the repository snapshot")
        return os.path.join(self.snapshot_root, relative)

    def retained_fd(self, repository_path: str) -> int:
        retained = self.custody._canonical(self.path(repository_path))
        node = self.custody._nodes.get(retained)
        if node is None or node.is_directory:
            raise CustodyUnavailable(
                "authenticated producer is absent from the retained source closure"
            )
        return node.fd

    def retained_root_fd(self) -> int:
        retained = self.custody._canonical(self.snapshot_root)
        node = self.custody._nodes.get(retained)
        if node is None or not node.is_directory:
            raise CustodyUnavailable(
                "authenticated source snapshot root descriptor is unavailable"
            )
        return node.fd

    def descriptor_path(self, repository_path: str) -> str:
        relative = os.path.relpath(repository_path, REPO_ROOT)
        if relative == os.pardir or relative.startswith(os.pardir + os.sep):
            raise CustodyUnavailable("producer path escaped the repository snapshot")
        return os.path.join(
            _descriptor_path(self.retained_root_fd()),
            relative,
        )


def _apple_producer_files(include_wrapper: bool) -> tuple[str, ...]:
    files = [BUILD_SCRIPT, PIN_MANIFEST, *PRODUCTION_BUILDER_MATERIALS]
    if include_wrapper:
        files.extend(
            (
                APPLE_WRAPPER_BUILD_SCRIPT,
                os.path.join(REPO_ROOT, "tools", "verify_winn_abi_conformance.sh"),
                os.path.join(REPO_ROOT, "tools", "apple_winn_v3_engine_provenance.schema.json"),
                os.path.join(APPLE_WRAPPER_SOURCE_DIR, "WinnTunnel.h"),
                os.path.join(APPLE_WRAPPER_SOURCE_DIR, "WinsWinnPacketEngine.m"),
                os.path.join(APPLE_WRAPPER_SOURCE_DIR, "WinnTunnelTestDouble.c"),
            )
        )
    return tuple(files)


def _target_specs(target: str) -> tuple[GoTargetSpec, ...]:
    if target.startswith("relay-windows-"):
        arch = target.rsplit("-", 1)[-1]
        if arch not in PE_MACHINES:
            raise CustodyUnavailable(f"unsupported relay source target: {target}")
        return tuple(
            GoTargetSpec(
                RELAY_MODULE_DIR,
                ".",
                "windows",
                producer_arch,
                False,
                (RELAY_BUILD_SCRIPT, PIN_MANIFEST),
            )
            for producer_arch in ("amd64", "arm64")
        )

    wrapper_platform = target.removeprefix("apple-wrapper-")
    if wrapper_platform != target:
        if wrapper_platform not in ("iphoneos", "iphonesimulator", "macosx"):
            raise CustodyUnavailable(f"unsupported Apple wrapper source target: {target}")
        variants = (
            ("darwin", "arm64"),
            ("darwin", "amd64"),
            ("ios", "arm64"),
            ("ios", "amd64"),
        )
        return tuple(
            GoTargetSpec(
                MODULE_DIR,
                "./cdatapath",
                goos,
                goarch,
                True,
                _apple_producer_files(True),
            )
            for goos, goarch in variants
        )

    apple_targets = {
        "datapath-ios-arm64": ("ios", "arm64"),
        "datapath-iossimulator-arm64": ("ios", "arm64"),
        "datapath-iossimulator-amd64": ("ios", "amd64"),
        "datapath-archive-darwin-arm64": ("darwin", "arm64"),
        "datapath-archive-darwin-amd64": ("darwin", "amd64"),
    }
    apple = apple_targets.get(target)
    if apple is not None:
        return (
            GoTargetSpec(
                MODULE_DIR,
                "./cdatapath",
                apple[0],
                apple[1],
                True,
                _apple_producer_files(False),
            ),
        )

    match = re.fullmatch(
        r"datapath-(android|windows|linux|darwin)-(arm64|arm|amd64)",
        target,
    )
    if match is None:
        raise CustodyUnavailable(f"unsupported Winn source target: {target}")
    platform_name, arch = match.groups()
    goos = {"android": "android", "windows": "windows", "linux": "linux", "darwin": "darwin"}[
        platform_name
    ]
    return (
        GoTargetSpec(
            MODULE_DIR,
            "./cmd/winn-datapath",
            goos,
            arch,
            platform_name == "android",
            (BUILD_SCRIPT, PIN_MANIFEST, *PRODUCTION_BUILDER_MATERIALS),
        ),
    )


def _json_stream(payload: str, label: str) -> list[dict[str, object]]:
    decoder = json.JSONDecoder(object_pairs_hook=_duplicate_keys_refused)
    cursor = 0
    values: list[dict[str, object]] = []
    while True:
        while cursor < len(payload) and payload[cursor].isspace():
            cursor += 1
        if cursor == len(payload):
            break
        try:
            value, cursor = decoder.raw_decode(payload, cursor)
        except (ValueError, json.JSONDecodeError) as exc:
            raise CustodyUnavailable(f"invalid {label} JSON stream: {exc}") from exc
        if not isinstance(value, dict):
            raise CustodyUnavailable(f"{label} emitted a non-object JSON value")
        values.append(value)
    if not values:
        raise CustodyUnavailable(f"{label} emitted no JSON objects")
    return values


def _target_environment(
    reviewed_go: ReviewedGo,
    workdir: str,
    spec: GoTargetSpec,
) -> dict[str, str]:
    environment = reviewed_go.build_environment(workdir)
    environment.update(
        {
            "GOOS": spec.goos,
            "GOARCH": spec.goarch,
            "CGO_ENABLED": "1" if spec.cgo_enabled else "0",
        }
    )
    if spec.goarch == "arm":
        environment["GOARM"] = "7"
    return environment


def _verify_module_dependencies(
    reviewed_go: ReviewedGo,
    spec: GoTargetSpec,
    workdir: str,
) -> None:
    environment = _target_environment(reviewed_go, workdir, spec)
    verification = reviewed_go.run(
        ["mod", "verify"],
        cwd=spec.module_dir,
        environment=environment,
    )
    if verification.returncode != 0:
        raise CustodyUnavailable(
            f"sealed Go dependencies failed module verification in {spec.module_dir}: "
            + ((verification.stderr or verification.stdout).strip()[:1500])
        )
    reviewed_go.tree_custody.verify()
    reviewed_go.module_custody.verify()


def _run_exact_go_list(
    reviewed_go: ReviewedGo,
    spec: GoTargetSpec,
    workdir: str,
) -> list[dict[str, object]]:
    environment = _target_environment(reviewed_go, workdir, spec)
    command = ["list", "-deps", "-json", spec.package]
    first = reviewed_go.run(command, cwd=spec.module_dir, environment=environment)
    if first.returncode != 0:
        raise CustodyUnavailable(
            f"retained Go could not derive {spec.goos}/{spec.goarch} source closure: "
            + ((first.stderr or first.stdout).strip()[:1500])
        )
    second = reviewed_go.run(command, cwd=spec.module_dir, environment=environment)
    if second.returncode != 0 or second.stdout != first.stdout:
        raise CustodyUnavailable(
            f"retained Go source listing drifted for {spec.goos}/{spec.goarch}"
        )
    packages = _json_stream(first.stdout, "go list -deps")
    expected_imports = {
        str(package.get("ImportPath", "")) for package in packages
    }
    if "" in expected_imports or len(expected_imports) != len(packages):
        raise CustodyUnavailable("go list -deps emitted missing/duplicate import paths")
    projection = reviewed_go.run(
        ["list", "-deps", "-f", "{{.ImportPath}}", spec.package],
        cwd=spec.module_dir,
        environment=environment,
    )
    projected_imports = {
        line.strip() for line in projection.stdout.splitlines() if line.strip()
    }
    if projection.returncode != 0 or projected_imports != expected_imports:
        raise CustodyUnavailable(
            f"independent Go package projection disagrees for {spec.goos}/{spec.goarch}"
        )
    return packages


def _safe_package_file(directory: str, name: object, label: str) -> str:
    if not isinstance(name, str) or not name or os.path.isabs(name):
        raise CustodyUnavailable(f"{label} contains an invalid package filename")
    path = os.path.normpath(os.path.join(directory, name))
    try:
        if os.path.commonpath((directory, path)) != os.path.normpath(directory):
            raise CustodyUnavailable(f"{label} package file escapes its directory")
    except ValueError as exc:
        raise CustodyUnavailable(f"{label} package file has incompatible roots") from exc
    return path


def _go_list_paths(
    packages: Iterable[dict[str, object]],
    reviewed_go: ReviewedGo,
) -> tuple[set[str], set[str], set[str]]:
    source_files: set[str] = set()
    dependency_files: set[str] = set()
    module_labels: set[str] = set()
    for package in packages:
        if package.get("Standard") is True:
            continue
        directory = package.get("Dir")
        module = package.get("Module")
        if not isinstance(directory, str) or not os.path.isabs(directory):
            raise CustodyUnavailable("go list package has no absolute source directory")
        if not isinstance(module, dict):
            raise CustodyUnavailable("non-standard go list package has no module metadata")
        main_module = module.get("Main") is True
        module_path = module.get("Path")
        version = module.get("Version", "")
        if not isinstance(module_path, str) or not module_path:
            raise CustodyUnavailable("go list module path is invalid")
        if module.get("Replace") is not None:
            raise CustodyUnavailable("Go module replacements are refused by freshness custody")
        module_labels.add(module_path if main_module else f"{module_path}@{version}")
        for field_name in GO_PACKAGE_FILE_FIELDS:
            names = package.get(field_name, [])
            if not isinstance(names, list):
                raise CustodyUnavailable(f"go list field {field_name} is not a list")
            for name in names:
                path = _safe_package_file(directory, name, field_name)
                if os.path.basename(path).endswith("_test.go"):
                    raise CustodyUnavailable("normal build closure unexpectedly contains a test file")
                (source_files if main_module else dependency_files).add(path)
        go_mod = module.get("GoMod")
        if isinstance(go_mod, str) and go_mod:
            (source_files if main_module else dependency_files).add(go_mod)
            if main_module:
                go_sum = os.path.join(os.path.dirname(go_mod), "go.sum")
                if not os.path.isfile(go_sum):
                    raise CustodyUnavailable(f"module metadata is missing: {go_sum}")
                source_files.add(go_sum)
    for path in dependency_files:
        try:
            if os.path.commonpath((reviewed_go.gomodcache, path)) != reviewed_go.gomodcache:
                raise CustodyUnavailable(
                    f"dependency escaped the sealed Go module cache: {path}"
                )
        except ValueError as exc:
            raise CustodyUnavailable("dependency has incompatible module-cache roots") from exc
    return source_files, dependency_files, module_labels


def _bind_source_closure(
    target: str,
    reviewed_go: ReviewedGo,
    workdir: str,
) -> BoundSourceClosure:
    source_files: set[str] = set()
    dependency_files: set[str] = set()
    modules: set[str] = set()
    producer_files: set[str] = set()
    discoveries: list[
        tuple[GoTargetSpec, set[str], set[str], set[str]]
    ] = []
    for spec in _target_specs(target):
        _verify_module_dependencies(reviewed_go, spec, workdir)
        packages = _run_exact_go_list(reviewed_go, spec, workdir)
        source, dependencies, listed_modules = _go_list_paths(packages, reviewed_go)
        discoveries.append((spec, source, dependencies, listed_modules))
        source_files.update(source)
        dependency_files.update(dependencies)
        modules.update(listed_modules)
        producer_files.update(spec.producer_files)
    source_files.update(producer_files)

    custody = DescriptorCustody(f"producer source closure {target}", CustodyUnavailable)
    snapshot_root = tempfile.mkdtemp(prefix=f".source-{target}.", dir=workdir)
    source_digest = hashlib.sha256()
    dependency_digest = hashlib.sha256()
    # The snapshot is written into this private mkdtemp directory first and
    # bound only after every file and directory is read-only: binding it
    # earlier made the snapshot's own writes and chmods look like mutations.
    # After binding, every snapshot file is re-read through its descriptor
    # and must carry exactly the bytes and mode taken from the bound source.
    expected_snapshot: dict[str, tuple[str, int]] = {}
    try:
        relative_sources: list[str] = []
        for path in sorted(
            source_files,
            key=lambda item: os.path.relpath(item, REPO_ROOT).replace(os.sep, "/"),
        ):
            try:
                if os.path.commonpath((REPO_ROOT, path)) != REPO_ROOT:
                    raise CustodyUnavailable(f"producer source escaped the repository: {path}")
            except ValueError as exc:
                raise CustodyUnavailable("producer source has incompatible roots") from exc
            node = custody.bind_file(path, 64 * 1024 * 1024)
            payload = custody.read_file(path, 64 * 1024 * 1024)
            relative = os.path.relpath(path, REPO_ROOT).replace(os.sep, "/")
            relative_sources.append(relative)
            source_digest.update(relative.encode("utf-8"))
            source_digest.update(b"\0")
            source_digest.update(hashlib.sha256(payload).digest())
            source_digest.update(node.identity[3].to_bytes(8, "big"))
            retained = os.path.join(snapshot_root, *relative.split("/"))
            os.makedirs(os.path.dirname(retained), mode=0o700, exist_ok=True)
            retained_mode = 0o500 if stat.S_IMODE(node.identity[3]) & 0o111 else 0o400
            output_fd = os.open(
                retained,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(output_fd, view)
                    if written <= 0:
                        raise CustodyUnavailable("short write while retaining source closure")
                    view = view[written:]
                os.fsync(output_fd)
                os.fchmod(output_fd, retained_mode)
            finally:
                os.close(output_fd)
            expected_snapshot[custody._canonical(retained)] = (
                hashlib.sha256(payload).hexdigest(),
                retained_mode,
            )
        for path in sorted(dependency_files):
            node = reviewed_go.module_custody.bind_file(
                path,
                64 * 1024 * 1024,
                require_owner=True,
                require_readonly=True,
            )
            current = os.path.dirname(path)
            while current.startswith(reviewed_go.gomodcache):
                directory_node = reviewed_go.module_custody.bind_directory(current)
                directory_info = os.fstat(directory_node.fd)
                if stat.S_IMODE(directory_info.st_mode) & 0o222:
                    raise CustodyUnavailable(
                        f"dependency cache directory is not sealed read-only: {current}"
                    )
                if current == reviewed_go.gomodcache:
                    break
                current = os.path.dirname(current)
            payload = reviewed_go.module_custody.read_file(path, 64 * 1024 * 1024)
            relative = os.path.relpath(path, reviewed_go.gomodcache).replace(os.sep, "/")
            dependency_digest.update(relative.encode("utf-8"))
            dependency_digest.update(b"\0")
            dependency_digest.update(hashlib.sha256(payload).digest())
            dependency_digest.update(node.identity[3].to_bytes(8, "big"))
        for directory, _, _ in os.walk(snapshot_root, topdown=False):
            os.chmod(directory, 0o500)
        custody.bind_tree(snapshot_root, 64 * 1024 * 1024)
        canonical_snapshot = custody._canonical(snapshot_root)
        snapshot_files = {
            path
            for path, item in custody._nodes.items()
            if not item.is_directory
            and path.startswith(canonical_snapshot + os.sep)
        }
        if snapshot_files != set(expected_snapshot):
            raise CustodyUnavailable(
                "producer source snapshot holds files outside the bound closure"
            )
        for path, (expected_digest, expected_mode) in sorted(expected_snapshot.items()):
            retained_node = custody._nodes[path]
            if (
                stat.S_IMODE(retained_node.identity[3]) != expected_mode
                or retained_node.identity[2] != os.getuid()
                or hashlib.sha256(
                    custody.read_file(path, 64 * 1024 * 1024)
                ).hexdigest() != expected_digest
            ):
                raise CustodyUnavailable(
                    f"producer source snapshot differs from the bound source: {path}"
                )
        for spec, expected_source, expected_dependencies, expected_modules in discoveries:
            snapshot_spec = GoTargetSpec(
                os.path.join(snapshot_root, os.path.relpath(spec.module_dir, REPO_ROOT)),
                spec.package,
                spec.goos,
                spec.goarch,
                spec.cgo_enabled,
                tuple(os.path.join(snapshot_root, os.path.relpath(path, REPO_ROOT))
                      for path in spec.producer_files),
            )
            _verify_module_dependencies(reviewed_go, snapshot_spec, workdir)
            repeated = _go_list_paths(
                _run_exact_go_list(reviewed_go, snapshot_spec, workdir),
                reviewed_go,
            )
            repeated_source, repeated_dependencies, repeated_modules = repeated
            expected_relative = {
                os.path.relpath(path, REPO_ROOT) for path in expected_source
            }
            repeated_relative = {
                os.path.relpath(path, snapshot_root) for path in repeated_source
            }
            if (repeated_relative, repeated_dependencies, repeated_modules) != (
                expected_relative, expected_dependencies, expected_modules):
                raise CustodyUnavailable(
                    f"producer source closure drifted after descriptor binding for "
                    f"{spec.goos}/{spec.goarch}"
                )
        custody.verify()
        reviewed_go.module_custody.verify()
        # Reported, not compared to an external per-target value: every
        # dependency byte is pinned by the sealed module-cache digest, and
        # `go mod verify` above checked each module against the bound go.sum.
        measured_dependency_digest = dependency_digest.hexdigest()
        closure = SourceClosure(
            target,
            source_digest.hexdigest(),
            tuple(relative_sources),
            measured_dependency_digest,
            tuple(sorted(modules)),
        )
        return BoundSourceClosure(closure, custody, snapshot_root)
    except Exception:
        try:
            custody.close()
        except (ArtifactInvalid, CustodyUnavailable):
            # Preserve the primary source-closure failure after still draining
            # close-time mutation events and releasing every descriptor.
            pass
        _discard_private_tree(snapshot_root)
        raise


def bind_source_closures(
    targets: Iterable[str],
    reviewed_go: ReviewedGo,
    workdir: str,
) -> dict[str, BoundSourceClosure]:
    bound: dict[str, BoundSourceClosure] = {}
    try:
        for target in sorted(set(targets)):
            bound[target] = _bind_source_closure(target, reviewed_go, workdir)
        return bound
    except Exception:
        for item in bound.values():
            item.close()
        raise


def current_source_closures(
    targets: Iterable[str],
    reviewed_go: ReviewedGo,
    workdir: str,
) -> dict[str, SourceClosure]:
    """Return retained-Go-derived, target-specific build source closures."""
    bound = bind_source_closures(targets, reviewed_go, workdir)
    try:
        return {target: item.closure for target, item in bound.items()}
    finally:
        for item in bound.values():
            item.close()


def _host_arch() -> str:
    value = platform.machine().lower()
    if value in ("x86_64", "amd64"):
        return "amd64"
    if value in ("arm64", "aarch64"):
        return "arm64"
    raise CustodyUnavailable(f"unsupported host architecture for matching Linux output: {value}")


def _linux_artifacts() -> tuple[Artifact, ...]:
    items: list[Artifact] = []
    for arch, label in (("amd64", "x64"), ("arm64", "arm64")):
        items.extend(
            (
                Artifact(
                    f"build/linux/{label}/release/bundle/winn-datapath",
                    f"datapath-linux-{arch}",
                    "linux",
                    f"Linux Flutter bundle, {label}",
                    kind="elf",
                    arch=arch,
                ),
                Artifact(
                    f"web/downloads/wins-vpn-linux-{label}.tar.gz",
                    f"datapath-linux-{arch}",
                    "linux",
                    f"Linux release tarball, {label}",
                    kind="linux-package",
                    arch=arch,
                    member="winn-datapath",
                ),
            )
        )
    return tuple(items)


SHIPPED += _android_package_artifacts() + _android_qa_artifacts() + _linux_artifacts()


def _consumer_source(relative: str) -> str:
    path = os.path.join(REPO_ROOT, *relative.split("/"))
    with DescriptorCustody(
        f"native consumer source {relative}", CustodyUnavailable
    ) as custody:
        custody.bind_file(path, 16 * 1024 * 1024)
        payload = custody.read_file(path, 16 * 1024 * 1024)
        custody.verify()
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CustodyUnavailable(f"native consumer source is not UTF-8: {relative}") from exc


def _consumer_authority_files() -> tuple[str, ...]:
    """Enumerate producer, installer, and staging authorities independently."""
    fixed = {
        "tools/build_winn_protocol_engine.sh",
        "tools/build_windows_winn_engine.sh",
        "tools/build_windows_winn3_relay.sh",
        "tools/build_apple_engine_wrappers.sh",
        "tools/stage_apple_engine_artifacts.sh",
        "tools/build_apple_release_candidates.sh",
        "tools/validate_release_artifact_privacy.py",
        "android/app/build.gradle.kts",
        "ios/Runner.xcodeproj/project.pbxproj",
        "macos/Runner.xcodeproj/project.pbxproj",
    }
    installer_root = os.path.join(REPO_ROOT, "installer", "windows")
    permitted = {".iss", ".json", ".ps1", ".py", ".wxs", ".yaml", ".yml"}
    for directory, names, files in os.walk(installer_root, followlinks=False):
        names[:] = sorted(
            name for name in names
            if name not in {"tests", "__pycache__"}
            and not os.path.islink(os.path.join(directory, name))
        )
        for name in sorted(files):
            full = os.path.join(directory, name)
            if (
                name.startswith("test_")
                or os.path.islink(full)
                or os.path.splitext(name)[1].lower() not in permitted
            ):
                continue
            fixed.add(os.path.relpath(full, REPO_ROOT).replace(os.sep, "/"))
    for platform_name in ("android", "apple", "linux", "windows"):
        candidate = f"app_store/{platform_name}/artifacts/release_candidate.json"
        if os.path.isfile(os.path.join(REPO_ROOT, *candidate.split("/"))):
            fixed.add(candidate)
    return tuple(sorted(fixed))


def _validate_consumer_authority_manifests() -> None:
    """Reject stale or incomplete native paths in any shipping authority."""
    try:
        linux_candidate = json.loads(
            _consumer_source(LINUX_RELEASE_CANDIDATE),
            object_pairs_hook=_duplicate_keys_refused,
            parse_constant=lambda value: (_ for _ in ()).throw(
                CustodyUnavailable(
                    f"Linux release candidate contains non-finite value {value}"
                )
            ),
        )
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise CustodyUnavailable("Linux release candidate is invalid JSON") from exc
    if not isinstance(linux_candidate, dict):
        raise CustodyUnavailable("Linux release candidate root is not an object")
    deb = linux_candidate.get("deb")
    if not isinstance(deb, dict) or deb != LINUX_DEB_NON_UPLOAD:
        raise CustodyUnavailable(
            "OWNER-BLOCKED: Linux Debian inventory must remain the exact derived "
            "amd64 non-upload declaration"
        )
    required_targets = linux_candidate.get("required_upload_targets")
    if (
        not isinstance(required_targets, list)
        or required_targets.count("linux-x64-package") != 1
        or required_targets.count("linux-arm64-package") != 1
        or any("deb" in str(target).lower() for target in required_targets)
    ):
        raise CustodyUnavailable(
            "OWNER-BLOCKED: Linux upload inventory does not reconcile the two "
            "native tarballs with the explicit Debian non-upload status"
        )
    canonical_windows = {
        f"build/windows/winn3/{arch}/{name}.exe"
        for arch in ("x64", "arm64")
        for name in ("winn-datapath", "winsvpn_winn3_engine")
    }
    observed_windows: set[str] = set()
    stale_windows: set[str] = set()
    native_reference_seen = False
    for relative in _consumer_authority_files():
        text = _consumer_source(relative)
        normalised = text.replace("\\", "/")
        if "winn-datapath.exe" in normalised or "winsvpn_winn3_engine.exe" in normalised:
            native_reference_seen = True
        observed_windows.update(
            re.findall(
                r"build/windows/winn3/(?:x64|arm64)/(?:winn-datapath|winsvpn_winn3_engine)\.exe",
                normalised,
            )
        )
        stale_windows.update(
            re.findall(
                r"build/windows/(?:x64|arm64)/runner/Release/(?:winn-datapath|winsvpn_winn3_engine)\.exe",
                normalised,
            )
        )
        if (
            "build/windows/winn3/winn-datapath_" in normalised
            or "build/windows/winn3/winsvpn_winn3_engine_" in normalised
            or (
                relative != "installer/windows/build_installer.ps1"
                and re.search(
                    r"Join-Path\s+\$ReleaseDir\s+['\"](?:winn-datapath|winsvpn_winn3_engine)\.exe['\"]",
                    text,
                    re.IGNORECASE,
                )
            )
        ):
            stale_windows.add(relative)
    if stale_windows:
        raise CustodyUnavailable(
            "OWNER-BLOCKED: stale Windows native consumer authority paths: "
            + ", ".join(sorted(stale_windows))
        )
    if not native_reference_seen or observed_windows != canonical_windows:
        missing = sorted(canonical_windows - observed_windows)
        extra = sorted(observed_windows - canonical_windows)
        raise CustodyUnavailable(
            "OWNER-BLOCKED: Windows producer/installer/staging manifests do not "
            "reconcile the exact architecture-scoped native consumers; missing="
            + ",".join(missing)
            + "; extra="
            + ",".join(extra)
        )


def _independent_consumer_inventory_paths() -> frozenset[str]:
    """Enumerate shipping consumers without consulting SHIPPED or its helpers."""
    _validate_consumer_authority_manifests()
    paths: set[str] = set()

    for relative in (
        "tools/validate_release_artifact_privacy.py",
        "tools/android_final_evidence_collector.py",
        "android/devicecheck/devicecheck_build_receipt.py",
        "tools/build_apple_release_candidates.sh",
    ):
        text = _consumer_source(relative)
        paths.update(
            re.findall(
                r'["\']('
                r'(?:build/app/outputs/(?:flutter-apk|bundle)/[^"\']+\.(?:apk|aab))|'
                r'(?:android/devicecheck/app/build/outputs/apk/(?:debug|release)/[^"\']+\.apk)|'
                r'(?:web/downloads/wins-vpn-linux-(?:x64|arm64)\.tar\.gz)|'
                r'(?:apple/EngineArtifacts/(?:macos|ios/(?:iphoneos|iphonesimulator))/'
                r'libWinsWinnPacketEngine\.dylib)'
                r')["\']',
                text,
            )
        )

    for project in (
        "ios/Runner.xcodeproj/project.pbxproj",
        "macos/Runner.xcodeproj/project.pbxproj",
    ):
        text = _consumer_source(project)
        for name in re.findall(r"libwinn-datapath-[a-z0-9-]+\.a", text):
            paths.add(f"tools/winn_conformance_build_out/{name}")
    wrapper_builder = _consumer_source("tools/build_apple_engine_wrappers.sh")
    for relative in re.findall(
        r'"((?:ios/(?:iphoneos|iphonesimulator)|macos)/'
        r'libWinsWinnPacketEngine\.dylib)"',
        wrapper_builder,
    ):
        paths.add(f"apple/EngineArtifacts/{relative}")

    android_roots = (
        "android/app/src/debug/jniLibs",
        "android/app/src/profile/jniLibs",
        "android/app/src/release/jniLibs",
        "android/devicecheck/app/src/main/jniLibs",
    )
    for relative in android_roots:
        root = os.path.join(REPO_ROOT, *relative.split("/"))
        for directory, names, files in os.walk(root, followlinks=False):
            names[:] = sorted(
                name for name in names
                if not os.path.islink(os.path.join(directory, name))
            )
            if "libwinnengine.so" in files:
                paths.add(
                    os.path.relpath(
                        os.path.join(directory, "libwinnengine.so"), REPO_ROOT
                    ).replace(os.sep, "/")
                )

    relay_builder = _consumer_source("tools/build_windows_winn3_relay.sh")
    core_builder = _consumer_source("tools/build_windows_winn_engine.sh")
    architecture_match = re.search(
        r'declare -a architectures=\(([^)]*)\)', core_builder
    )
    if architecture_match is None:
        raise CustodyUnavailable("Windows consumer architecture inventory is unavailable")
    architectures = re.findall(r'"(amd64|arm64)"', architecture_match.group(1))
    if architectures != ["amd64", "arm64"]:
        raise CustodyUnavailable("Windows consumer architecture inventory is not exact")
    if 'output_dir="${1:-${repo_root}/build/windows/winn3}"' not in relay_builder:
        raise CustodyUnavailable("Windows producer output directory changed")
    runner = _consumer_source("windows/runner/winn3_supervisor.cpp")
    runtime_names = set(
        re.findall(r'JoinModulePath\(L"(winn-datapath|winsvpn_winn3_engine)\.exe"\)', runner)
    )
    if runtime_names != {"winn-datapath", "winsvpn_winn3_engine"}:
        raise CustodyUnavailable("Windows runtime consumer inventory is not exact")
    for architecture in architectures:
        output_arch = "x64" if architecture == "amd64" else architecture
        for name in runtime_names:
            paths.add(f"build/windows/winn3/{output_arch}/{name}.exe")

    linux_builder = _consumer_source("tools/Dockerfile.linux-desktop")
    bundle_roots = set(
        re.findall(r"bundle_dir=(build/linux/(?:x64|arm64)/release/bundle)", linux_builder)
    )
    if bundle_roots != {
        "build/linux/x64/release/bundle",
        "build/linux/arm64/release/bundle",
    }:
        raise CustodyUnavailable("Linux runtime consumer inventory is not exact")
    paths.update(f"{root}/winn-datapath" for root in bundle_roots)
    return frozenset(paths)


def _independent_consumer_inventory() -> tuple[Artifact, ...]:
    """Project independently discovered consumer paths into their exact ABI contract."""
    items: list[Artifact] = []
    android_arches = (
        ("arm64-v8a", "arm64"),
        ("armeabi-v7a", "arm"),
        ("x86_64", "amd64"),
    )
    archive_contracts = {
        "libwinn-datapath-darwin-arm64.a": (
            "datapath-archive-darwin-arm64", "arm64", "macosx"
        ),
        "libwinn-datapath-darwin-amd64.a": (
            "datapath-archive-darwin-amd64", "x86_64", "macosx"
        ),
        "libwinn-datapath-ios-arm64.a": (
            "datapath-ios-arm64", "arm64", "iphoneos"
        ),
        "libwinn-datapath-iossimulator-arm64.a": (
            "datapath-iossimulator-arm64", "arm64", "iphonesimulator"
        ),
        "libwinn-datapath-iossimulator-amd64.a": (
            "datapath-iossimulator-amd64", "x86_64", "iphonesimulator"
        ),
    }
    wrapper_contracts = {
        "apple/EngineArtifacts/ios/iphoneos/libWinsWinnPacketEngine.dylib": (
            "apple-wrapper-iphoneos", "arm64", "iphoneos"
        ),
        "apple/EngineArtifacts/ios/iphonesimulator/libWinsWinnPacketEngine.dylib": (
            "apple-wrapper-iphonesimulator", "arm64,x86_64", "iphonesimulator"
        ),
        "apple/EngineArtifacts/macos/libWinsWinnPacketEngine.dylib": (
            "apple-wrapper-macosx", "arm64,x86_64", "macosx"
        ),
    }
    for path in sorted(_independent_consumer_inventory_paths()):
        why = "independently discovered native consumer"
        if path.endswith((".apk", ".aab")):
            selected = android_arches
            if path.startswith("android/devicecheck/"):
                selected = android_arches[:1]
            prefix = "base/" if path.endswith(".aab") else ""
            for abi, arch in selected:
                items.append(
                    Artifact(
                        path, f"datapath-android-{arch}", "android", why,
                        kind="android-package", arch=arch,
                        member=f"{prefix}lib/{abi}/libwinnengine.so",
                    )
                )
            continue
        if path.endswith("/libwinnengine.so"):
            match = re.search(r"/(arm64-v8a|armeabi-v7a|x86_64)/libwinnengine\.so$", path)
            if match is None:
                raise CustodyUnavailable(f"unclassified Android native consumer: {path}")
            arch = dict(android_arches)[match.group(1)]
            items.append(
                Artifact(path, f"datapath-android-{arch}", "android", why, arch=arch)
            )
            continue
        basename = os.path.basename(path)
        if basename in archive_contracts:
            target, arch, platform_name = archive_contracts[basename]
            items.append(
                Artifact(
                    path, target, "apple", why, kind="apple-archive", arch=arch,
                    platform=platform_name, closure="apple",
                )
            )
            continue
        if path in wrapper_contracts:
            target, arch, platform_name = wrapper_contracts[path]
            items.append(
                Artifact(
                    path, target, "apple", why, kind="apple-wrapper",
                    role="core+relay", arch=arch, platform=platform_name,
                    closure="apple",
                )
            )
            continue
        if path.endswith(".exe"):
            arch = "arm64" if ("_arm64.exe" in path or "/arm64/" in path) else "amd64"
            role = "relay" if "winsvpn_winn3_engine" in path else "core"
            target = (
                f"relay-windows-{arch}" if role == "relay"
                else f"datapath-windows-{arch}"
            )
            items.append(
                Artifact(
                    path, target, "windows", why, kind="pe", role=role,
                    arch=arch, closure="relay" if role == "relay" else "core",
                )
            )
            continue
        if path.endswith("/winn-datapath") or path.endswith(".tar.gz"):
            arch = "arm64" if "arm64" in path else "amd64"
            items.append(
                Artifact(
                    path, f"datapath-linux-{arch}", "linux", why,
                    kind="linux-package" if path.endswith(".tar.gz") else "elf",
                    arch=arch, member="winn-datapath" if path.endswith(".tar.gz") else "",
                )
            )
            continue
        items.append(
            Artifact(path, "UNCLASSIFIED", "UNCLASSIFIED", why, kind="UNCLASSIFIED")
        )
    return tuple(items)


def _artifact_contract(item: Artifact) -> tuple[str, ...]:
    return (
        item.path, item.target, item.group, item.kind, item.role, item.arch,
        item.member, item.platform, item.closure,
    )


REQUIRED_NATIVE_CONSUMER_PATHS = frozenset(
    {
        "android/app/src/debug/jniLibs/arm64-v8a/libwinnengine.so",
        "android/app/src/debug/jniLibs/armeabi-v7a/libwinnengine.so",
        "android/app/src/debug/jniLibs/x86_64/libwinnengine.so",
        "android/app/src/profile/jniLibs/arm64-v8a/libwinnengine.so",
        "android/app/src/profile/jniLibs/armeabi-v7a/libwinnengine.so",
        "android/app/src/profile/jniLibs/x86_64/libwinnengine.so",
        "android/app/src/release/jniLibs/arm64-v8a/libwinnengine.so",
        "android/app/src/release/jniLibs/armeabi-v7a/libwinnengine.so",
        "android/app/src/release/jniLibs/x86_64/libwinnengine.so",
        "android/devicecheck/app/src/main/jniLibs/arm64-v8a/libwinnengine.so",
        "android/devicecheck/app/build/outputs/apk/debug/app-debug.apk",
        "android/devicecheck/app/build/outputs/apk/release/app-release.apk",
        "build/app/outputs/flutter-apk/app-phone-release.apk",
        "build/app/outputs/bundle/phoneRelease/app-phone-release.aab",
        "build/app/outputs/flutter-apk/app-tv-release.apk",
        "build/app/outputs/bundle/tvRelease/app-tv-release.aab",
        "build/app/outputs/flutter-apk/app-release.apk",
        "build/app/outputs/bundle/release/app-release.aab",
        "tools/winn_conformance_build_out/libwinn-datapath-darwin-arm64.a",
        "tools/winn_conformance_build_out/libwinn-datapath-darwin-amd64.a",
        "tools/winn_conformance_build_out/libwinn-datapath-ios-arm64.a",
        "tools/winn_conformance_build_out/libwinn-datapath-iossimulator-arm64.a",
        "tools/winn_conformance_build_out/libwinn-datapath-iossimulator-amd64.a",
        "apple/EngineArtifacts/ios/iphoneos/libWinsWinnPacketEngine.dylib",
        "apple/EngineArtifacts/ios/iphonesimulator/libWinsWinnPacketEngine.dylib",
        "apple/EngineArtifacts/macos/libWinsWinnPacketEngine.dylib",
        "build/windows/winn3/x64/winn-datapath.exe",
        "build/windows/winn3/x64/winsvpn_winn3_engine.exe",
        "build/windows/winn3/arm64/winn-datapath.exe",
        "build/windows/winn3/arm64/winsvpn_winn3_engine.exe",
        "build/linux/x64/release/bundle/winn-datapath",
        "build/linux/arm64/release/bundle/winn-datapath",
        "web/downloads/wins-vpn-linux-x64.tar.gz",
        "web/downloads/wins-vpn-linux-arm64.tar.gz",
    }
)


def inventory() -> tuple[Artifact, ...]:
    """Return the reviewed inventory only after independent consumer reconciliation."""
    permitted_qa_intermediates = {path for path, _ in ANDROID_QA_NATIVE_PATHS}
    declared_items = [item for item in SHIPPED if item.path not in permitted_qa_intermediates]
    consumer_items = list(_independent_consumer_inventory())
    declared = {_artifact_contract(item) for item in declared_items}
    consumers = {_artifact_contract(item) for item in consumer_items}
    missing = sorted(consumers - declared)
    unconsumed = sorted(declared - consumers)
    if missing or unconsumed:
        detail: list[str] = []
        if missing:
            detail.append(
                "undeclared consumers or metadata mismatch: "
                + ", ".join("|".join(item) for item in missing)
            )
        if unconsumed:
            detail.append(
                "declarations absent from consumers or metadata mismatch: "
                + ", ".join("|".join(item) for item in unconsumed)
            )
        raise CustodyUnavailable("native shipping inventory mismatch: " + "; ".join(detail))
    consumer_paths = {item.path for item in consumer_items}
    if consumer_paths != REQUIRED_NATIVE_CONSUMER_PATHS:
        missing_paths = sorted(REQUIRED_NATIVE_CONSUMER_PATHS - consumer_paths)
        extra_paths = sorted(consumer_paths - REQUIRED_NATIVE_CONSUMER_PATHS)
        raise CustodyUnavailable(
            "native shipping inventory differs from the independent fixed consumer "
            "authority; missing=" + ",".join(missing_paths)
            + "; extra=" + ",".join(extra_paths)
        )
    return SHIPPED


@dataclass(frozen=True)
class ElfLayout:
    elf_class: int
    machine: int
    elf_type: int
    entry: int
    sections: tuple[tuple[str, int, int, int, int, int], ...]
    segments: tuple[tuple[int, int, int, int, int, int], ...]
    symbol_locations: tuple[tuple[str, int, int, int], ...]


def _parse_elf(blob: bytes, label: str) -> ElfLayout:
    if len(blob) < 16 or blob[:4] != b"\x7fELF":
        raise ArtifactInvalid(f"{label}: not an ELF file")
    elf_class = blob[4]
    if elf_class not in (1, 2) or blob[5] != 1 or blob[6] != 1:
        raise ArtifactInvalid(f"{label}: ELF is not little-endian ELF32/ELF64 v1")
    if elf_class == 1:
        header_size = 52
        header_format = "<16sHHIIIIIHHHHHH"
        program_size = 32
        section_size = 40
    else:
        header_size = 64
        header_format = "<16sHHIQQQIHHHHHH"
        program_size = 56
        section_size = 64
    if len(blob) < header_size:
        raise ArtifactInvalid(f"{label}: ELF header is truncated")
    values = struct.unpack_from(header_format, blob, 0)
    (
        _,
        elf_type,
        machine,
        version,
        entry,
        program_offset,
        section_offset,
        _,
        encoded_header_size,
        encoded_program_size,
        program_count,
        encoded_section_size,
        section_count,
        string_section_index,
    ) = values
    if version != 1 or encoded_header_size != header_size:
        raise ArtifactInvalid(f"{label}: ELF header version/size is invalid")
    if elf_type not in (2, 3):
        raise ArtifactInvalid(f"{label}: ELF is not an executable or shared object")
    if program_count in (0, 0xFFFF) or encoded_program_size != program_size:
        raise ArtifactInvalid(f"{label}: ELF has no bounded program-header table")
    program_end = program_offset + program_count * program_size
    if program_offset < header_size or program_end > len(blob):
        raise ArtifactInvalid(f"{label}: ELF program-header table is outside the file")

    executable_loads: list[tuple[int, int]] = []
    load_ranges: list[tuple[int, int]] = []
    segments: list[tuple[int, int, int, int, int, int]] = []
    for index in range(program_count):
        offset = program_offset + index * program_size
        if elf_class == 1:
            (
                program_type,
                file_offset,
                virtual_address,
                _,
                file_size,
                memory_size,
                flags,
                alignment,
            ) = struct.unpack_from("<IIIIIIII", blob, offset)
        else:
            (
                program_type,
                flags,
                file_offset,
                virtual_address,
                _,
                file_size,
                memory_size,
                alignment,
            ) = struct.unpack_from("<IIQQQQQQ", blob, offset)
        if file_size > memory_size or file_offset + file_size > len(blob):
            raise ArtifactInvalid(f"{label}: ELF program segment is outside the file")
        if alignment not in (0, 1) and alignment & (alignment - 1):
            raise ArtifactInvalid(f"{label}: ELF program alignment is invalid")
        segments.append(
            (program_type, flags, file_offset, file_size, virtual_address, memory_size)
        )
        if program_type == 1:
            if file_size == 0 or memory_size == 0:
                raise ArtifactInvalid(f"{label}: ELF contains an empty load segment")
            load_ranges.append((file_offset, file_offset + file_size))
            if flags & 0x1:
                if not flags & 0x4:
                    raise ArtifactInvalid(f"{label}: ELF executable segment is not readable")
                executable_loads.append(
                    (virtual_address, virtual_address + memory_size)
                )
    if not load_ranges or not executable_loads:
        raise ArtifactInvalid(f"{label}: ELF has no readable executable load segment")
    if machine == 183 and entry & 0x3:
        raise ArtifactInvalid(f"{label}: AArch64 ELF entry point is not 4-byte aligned")
    if not any(start <= entry < end for start, end in executable_loads):
        raise ArtifactInvalid(f"{label}: ELF entry point is outside executable memory")

    sections: list[tuple[str, int, int, int, int, int]] = []
    raw_sections: list[
        tuple[int, int, int, int, int, int, int, int, int, int]
    ] = []
    if section_count:
        if section_count == 0xFFFF or encoded_section_size != section_size:
            raise ArtifactInvalid(f"{label}: ELF extended/invalid section table is refused")
        section_end = section_offset + section_count * section_size
        if section_offset < header_size or section_end > len(blob):
            raise ArtifactInvalid(f"{label}: ELF section table is outside the file")
        if string_section_index >= section_count:
            raise ArtifactInvalid(f"{label}: ELF section-name table index is invalid")
        for index in range(section_count):
            offset = section_offset + index * section_size
            if elf_class == 1:
                values = struct.unpack_from("<IIIIIIIIII", blob, offset)
            else:
                values = struct.unpack_from("<IIQQQQIIQQ", blob, offset)
            (
                name_at, section_type, section_flags, address, file_offset, size,
                link, info, alignment, entry_size,
            ) = values
            if section_type != 8 and file_offset + size > len(blob):
                raise ArtifactInvalid(f"{label}: ELF section is outside the file")
            if alignment not in (0, 1) and alignment & (alignment - 1):
                raise ArtifactInvalid(f"{label}: ELF section alignment is invalid")
            raw_sections.append(
                (
                    name_at, section_type, section_flags, address, file_offset,
                    size, link, info, alignment, entry_size,
                )
            )
        first = raw_sections[0]
        if first != (0, 0, 0, 0, 0, 0, 0, 0, 0, 0):
            raise ArtifactInvalid(
                f"{label}: ELF section header 0 is not the required SHT_NULL entry"
            )
        (
            _, string_type, _, _, string_offset, string_size, _, _, _, _
        ) = raw_sections[string_section_index]
        if string_type != 3 or string_offset + string_size > len(blob):
            raise ArtifactInvalid(f"{label}: ELF section-name string table is invalid")
        names = blob[string_offset:string_offset + string_size]
        if not names or names[0] != 0 or names[-1] != 0:
            raise ArtifactInvalid(
                f"{label}: ELF section-name string table is not NUL bounded"
            )
        for (
            name_at, section_type, section_flags, address, file_offset, size,
            _, _, _, _,
        ) in raw_sections:
            if name_at >= len(names):
                raise ArtifactInvalid(f"{label}: ELF section name offset is invalid")
            name_end = names.find(b"\0", name_at)
            if name_end < 0:
                raise ArtifactInvalid(f"{label}: ELF section name is unterminated")
            try:
                name = names[name_at:name_end].decode("ascii")
            except UnicodeDecodeError as exc:
                raise ArtifactInvalid(f"{label}: ELF section name is not ASCII") from exc
            sections.append(
                (name, section_type, section_flags, address, file_offset, size)
            )
    symbol_locations: list[tuple[str, int, int, int]] = []
    symbol_size = 16 if elf_class == 1 else 24
    for (
        _, section_type, _, _, symbol_offset, symbol_bytes, link, _, _, entry_size,
    ) in raw_sections:
        if section_type not in (2, 11):
            continue
        if (
            link >= len(raw_sections)
            or entry_size != symbol_size
            or symbol_bytes == 0
            or symbol_bytes % symbol_size
            or symbol_offset + symbol_bytes > len(blob)
        ):
            raise ArtifactInvalid(f"{label}: ELF symbol table layout is invalid")
        linked = raw_sections[link]
        if linked[1] != 3 or linked[4] + linked[5] > len(blob):
            raise ArtifactInvalid(f"{label}: ELF symbol string table is invalid")
        symbol_strings = blob[linked[4]:linked[4] + linked[5]]
        for record in range(symbol_offset, symbol_offset + symbol_bytes, symbol_size):
            if elf_class == 1:
                name_at, value, size, info, _, section_index = struct.unpack_from(
                    "<IIIBBH", blob, record
                )
            else:
                name_at, info, _, section_index, value, size = struct.unpack_from(
                    "<IBBHQQ", blob, record
                )
            if info & 0xF != 2 or info >> 4 not in (1, 2) or size == 0:
                continue
            if section_index == 0 or section_index >= len(raw_sections):
                raise ArtifactInvalid(f"{label}: ELF executable symbol section is invalid")
            target = raw_sections[section_index]
            if (
                not target[2] & 0x4
                or target[1] == 8
                or not target[3] <= value
                or value + size > target[3] + target[5]
            ):
                raise ArtifactInvalid(
                    f"{label}: ELF function symbol is not executable section code"
                )
            if name_at >= len(symbol_strings):
                raise ArtifactInvalid(f"{label}: ELF symbol name offset is invalid")
            name_end = symbol_strings.find(b"\0", name_at)
            if name_end < 0:
                raise ArtifactInvalid(f"{label}: ELF symbol name is unterminated")
            try:
                name = symbol_strings[name_at:name_end].decode("ascii")
            except UnicodeDecodeError as exc:
                raise ArtifactInvalid(f"{label}: ELF symbol name is not ASCII") from exc
            code_offset = target[4] + value - target[3]
            if code_offset + size > len(blob):
                raise ArtifactInvalid(f"{label}: ELF symbol code exceeds the file")
            symbol_locations.append((name, value, size, code_offset))
    return ElfLayout(
        elf_class, machine, elf_type, entry, tuple(sections), tuple(segments),
        tuple(symbol_locations),
    )


def _validate_elf(blob: bytes, artifact: Artifact) -> None:
    layout = _parse_elf(blob, artifact.path)
    if artifact.arch == "arm":
        expected_class, expected_machine = 1, 40
    elif artifact.arch == "arm64":
        expected_class, expected_machine = 2, 183
    elif artifact.arch == "amd64":
        expected_class, expected_machine = 2, 62
    else:
        raise ArtifactInvalid(f"{artifact.path}: unsupported ELF architecture {artifact.arch}")
    if layout.elf_class != expected_class or layout.machine != expected_machine:
        raise ArtifactInvalid(
            f"{artifact.path}: ELF role/architecture mismatch, "
            f"expected class {expected_class} machine {expected_machine}, "
            f"got class {layout.elf_class} machine {layout.machine}")
    executable_files = [
        (offset, offset + size)
        for program_type, flags, offset, size, _, _ in layout.segments
        if program_type == 1 and flags & 0x1 and size
    ]
    executable_sections = [
        blob[offset:offset + size]
        for _, section_type, flags, _, offset, size in layout.sections
        if section_type != 8 and flags & 0x4 and size
    ]
    if (
        sum(len(code) for code in executable_sections) < 64
        or not any(any(code) for code in executable_sections)
    ):
        raise ArtifactInvalid(
            f"{artifact.path}: ELF has no substantive format-declared executable code"
        )

    def marker_is_executable(marker: bytes) -> bool:
        cursor = 0
        while True:
            found = blob.find(marker, cursor)
            if found < 0:
                return False
            if any(start <= found and found + len(marker) <= end for start, end in executable_files):
                return True
            cursor = found + 1

    if artifact.role == "core" and not marker_is_executable(WINN_MARKER):
        raise ArtifactInvalid(
            f"{artifact.path}: ELF Winn core marker is outside executable PT_LOAD"
        )
    if artifact.role == "relay":
        if not marker_is_executable(RELAY_MARKER) or WINN_MARKER in blob:
            raise ArtifactInvalid(f"{artifact.path}: ELF is not a Winn relay artifact")
    if layout.elf_type == 3:
        real_functions = [
            (offset, size)
            for _, _, size, offset in layout.symbol_locations
            if any(start <= offset and offset + size <= end for start, end in executable_files)
        ]
        if not real_functions or not any(
            len(set(blob[offset:offset + min(size, 32)])) >= 2
            for offset, size in real_functions
        ):
            raise ArtifactInvalid(
                f"{artifact.path}: ELF has no real exported executable symbol/code"
            )
    else:
        entry_offsets = [
            offset + layout.entry - address
            for program_type, flags, offset, size, address, _ in layout.segments
            if program_type == 1
            and flags & 0x1
            and address <= layout.entry < address + size
        ]
        if not entry_offsets or entry_offsets[0] >= len(blob):
            raise ArtifactInvalid(f"{artifact.path}: ELF entry has no executable code")
    build_info_sections = [
        (flags, offset, size)
        for name, section_type, flags, _, offset, size in layout.sections
        if name == ".go.buildinfo" and section_type == 1 and size
    ]
    if len(build_info_sections) != 1:
        raise ArtifactInvalid(
            f"{artifact.path}: ELF role has no unique authenticated Go build-info section"
        )
    build_flags, build_offset, build_size = build_info_sections[0]
    build_end = build_offset + build_size
    magic = b"\xff Go buildinf:"
    if (
        build_flags & 0x2 == 0
        or build_flags & 0x4
        or build_size < 34
        or blob[build_offset:build_offset + len(magic)] != magic
        or blob[build_offset + 14] not in (4, 8)
        or blob[build_offset + 15] & 0x2 == 0
    ):
        raise ArtifactInvalid(
            f"{artifact.path}: ELF authenticated Go build-info layout is invalid"
        )
    version, cursor = _decode_uvarint_string(blob, build_offset + 32, build_end)
    module_info, _ = _decode_uvarint_string(blob, cursor, build_end)
    if re.fullmatch(r"go[0-9]+\.[0-9]+(?:\.[0-9]+)?", version) is None:
        raise ArtifactInvalid(f"{artifact.path}: ELF Go build-info version is invalid")
    frame_start = bytes.fromhex("3077af0c9274080241e1c107e6d618e6").decode("latin1")
    frame_end = bytes.fromhex("f932433186182072008242104116d8f2").decode("latin1")
    if not module_info.startswith(frame_start) or not module_info.endswith(frame_end):
        raise ArtifactInvalid(f"{artifact.path}: ELF Go module-info framing is invalid")
    fields: dict[str, list[str]] = {}
    for line in module_info[16:-16].splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            fields.setdefault(parts[0], []).append(parts[1])
    expected_role = {
        "core": (
            "winsvpn.local/winnprotocol/cmd/winn-datapath",
            "winsvpn.local/winnprotocol",
        ),
    }.get(artifact.role)
    authenticated_main = any(
        name == "main.main" for name, _, _, _ in layout.symbol_locations
    ) or any(
        name == ".gopclntab"
        and section_type == 1
        and flags & 0x2
        and not flags & 0x4
        and blob[offset:offset + size].count(b"main.main\0") == 1
        for name, section_type, flags, _, offset, size in layout.sections
    )
    if (
        expected_role is None
        or fields.get("path") != [expected_role[0]]
        or fields.get("mod") != [expected_role[1]]
        or not authenticated_main
    ):
        raise ArtifactInvalid(
            f"{artifact.path}: ELF role does not derive from authenticated Go symbols"
        )


@dataclass(frozen=True)
class PeLayout:
    machine: int
    entry_rva: int
    sections: tuple[tuple[str, int, int, int, int, int], ...]


def _parse_pe(blob: bytes, label: str) -> PeLayout:
    if len(blob) < 0x40 or blob[:2] != b"MZ":
        raise ArtifactInvalid(f"{label}: not a PE file")
    pe_offset = struct.unpack_from("<I", blob, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset + 24 > len(blob):
        raise ArtifactInvalid(f"{label}: PE header offset is invalid")
    if blob[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        raise ArtifactInvalid(f"{label}: PE signature is invalid")
    machine, section_count, _, _, _, optional_size, characteristics = struct.unpack_from(
        "<HHIIIHH", blob, pe_offset + 4
    )
    if section_count == 0 or section_count > 96:
        raise ArtifactInvalid(f"{label}: PE section count is invalid")
    if not characteristics & 0x0002:
        raise ArtifactInvalid(f"{label}: PE is not marked executable")
    optional_offset = pe_offset + 24
    if optional_size < 240 or optional_offset + optional_size > len(blob):
        raise ArtifactInvalid(f"{label}: PE32+ optional header is truncated")
    if struct.unpack_from("<H", blob, optional_offset)[0] != 0x20B:
        raise ArtifactInvalid(f"{label}: PE is not a 64-bit image")
    entry_rva = struct.unpack_from("<I", blob, optional_offset + 16)[0]
    section_alignment = struct.unpack_from("<I", blob, optional_offset + 32)[0]
    file_alignment = struct.unpack_from("<I", blob, optional_offset + 36)[0]
    size_of_image = struct.unpack_from("<I", blob, optional_offset + 56)[0]
    size_of_headers = struct.unpack_from("<I", blob, optional_offset + 60)[0]
    number_of_directories = struct.unpack_from("<I", blob, optional_offset + 108)[0]
    if (
        section_alignment == 0
        or section_alignment & (section_alignment - 1)
        or file_alignment < 0x200
        or file_alignment > 0x10000
        or file_alignment & (file_alignment - 1)
        or section_alignment < file_alignment
    ):
        raise ArtifactInvalid(f"{label}: PE file/section alignment is invalid")
    if size_of_headers == 0 or size_of_headers > len(blob) or size_of_image == 0:
        raise ArtifactInvalid(f"{label}: PE image/header size is invalid")
    if number_of_directories > 16:
        raise ArtifactInvalid(f"{label}: PE data-directory count is invalid")
    if optional_size < 112 + number_of_directories * 8:
        raise ArtifactInvalid(f"{label}: PE optional header omits declared directories")
    section_table = optional_offset + optional_size
    complete_headers = section_table + section_count * 40
    rounded_headers = (complete_headers + file_alignment - 1) & -file_alignment
    if complete_headers > len(blob):
        raise ArtifactInvalid(f"{label}: PE section table is truncated")
    # The Go linker reserves header space beyond the rounded minimum (1536
    # bytes for 712 bytes of headers at FileAlignment 512), so SizeOfHeaders
    # must cover the rounded headers, not equal them. Every raw section is
    # still required below to start at or after SizeOfHeaders.
    if size_of_headers < rounded_headers or size_of_headers % file_alignment:
        raise ArtifactInvalid(
            f"{label}: PE SizeOfHeaders does not cover complete FileAlignment-rounded headers"
        )
    if section_alignment < 0x1000 and section_alignment != file_alignment:
        raise ArtifactInvalid(
            f"{label}: PE sub-page SectionAlignment/FileAlignment mismatch"
        )
    sections: list[tuple[str, int, int, int, int, int]] = []
    entry_in_code = False
    raw_ranges: list[tuple[int, int]] = []
    for index in range(section_count):
        offset = section_table + index * 40
        raw_name = blob[offset:offset + 8].split(b"\0", 1)[0]
        try:
            name = raw_name.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ArtifactInvalid(f"{label}: PE section name is not ASCII") from exc
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", blob, offset + 8
        )
        section_flags = struct.unpack_from("<I", blob, offset + 36)[0]
        if raw_size:
            if (
                raw_offset < size_of_headers
                or raw_offset % file_alignment
                or raw_size % file_alignment
                or raw_offset + raw_size > len(blob)
            ):
                raise ArtifactInvalid(f"{label}: PE section bytes are outside the file")
            raw_ranges.append((raw_offset, raw_offset + raw_size))
        mapped_size = max(virtual_size, raw_size)
        if mapped_size == 0 or virtual_address + mapped_size > size_of_image:
            raise ArtifactInvalid(f"{label}: PE section mapping is invalid")
        if (
            section_flags & 0x00000020
            and section_flags & 0x20000000
            and section_flags & 0x40000000
            and raw_size > 0
        ):
            # AddressOfEntryPoint is an RVA. VirtualSize may exceed
            # SizeOfRawData, in which case the tail is loader-created zero
            # fill and has no authenticated bytes in the PE file. A release
            # entry point must land in the file-backed executable range.
            if virtual_address <= entry_rva < virtual_address + raw_size:
                entry_in_code = True
        sections.append(
            (name, virtual_address, virtual_size, raw_offset, raw_size, section_flags)
        )
    if not entry_in_code:
        raise ArtifactInvalid(f"{label}: PE entry point is outside executable code")
    for (_, first_end), (second_start, _) in zip(
        sorted(raw_ranges), sorted(raw_ranges)[1:]
    ):
        if second_start < first_end:
            raise ArtifactInvalid(f"{label}: PE raw sections overlap")
    return PeLayout(machine, entry_rva, tuple(sections))


def _validate_pe(
    blob: bytes,
    artifact: Artifact,
) -> None:
    layout = _parse_pe(blob, artifact.path)
    expected = PE_MACHINES.get(artifact.arch)
    if expected is None:
        raise ArtifactInvalid(
            f"{artifact.path}: unsupported PE architecture {artifact.arch}"
        )
    if layout.machine != expected:
        raise ArtifactInvalid(
            f"{artifact.path}: PE role/architecture mismatch, expected "
            f"{artifact.arch}/{expected:#x}, got {layout.machine:#x}")
    if artifact.role not in {"core", "relay"}:
        raise ArtifactInvalid(f"{artifact.path}: OWNER-BLOCKED PE role identity mismatch")
    executable_code = b"".join(
        blob[raw_offset:raw_offset + raw_size]
        for _, _, _, raw_offset, raw_size, flags in layout.sections
        if raw_size
        and flags & 0x00000020
        and flags & 0x20000000
        and flags & 0x40000000
        and not flags & 0x80000000
    )
    if (
        len(executable_code) < 32
        or sum(byte != 0 for byte in executable_code) < 16
        or len(set(executable_code)) < 8
    ):
        raise ArtifactInvalid(
            f"{artifact.path}: PE role has no substantive authenticated executable code"
        )
    embedded_path, embedded_module = _pe_go_build_identity(
        blob, layout, artifact.path
    )
    expected_identity = {
        "core": (
            "winsvpn.local/winnprotocol/cmd/winn-datapath",
            "winsvpn.local/winnprotocol",
        ),
        "relay": (
            "winsvpn.local/winsvpnwinn3engine",
            "winsvpn.local/winsvpnwinn3engine",
        ),
    }[artifact.role]
    if (embedded_path, embedded_module) != expected_identity:
        raise ArtifactInvalid(
            f"{artifact.path}: PE embedded Go role identity does not match "
            f"the declared {artifact.role} target"
        )


def _decode_uvarint_string(blob: bytes, cursor: int, limit: int) -> tuple[str, int]:
    value = 0
    shift = 0
    while cursor < limit and shift < 64:
        byte = blob[cursor]
        cursor += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            end = cursor + value
            if end > limit:
                raise ArtifactInvalid("Go build-info string exceeds its PE section")
            return blob[cursor:end].decode("latin1"), end
        shift += 7
    raise ArtifactInvalid("Go build-info string length is malformed")


def _pe_go_build_identity(
    blob: bytes, layout: PeLayout, label: str
) -> tuple[str, str]:
    magic = b"\xff Go buildinf:"
    candidates: list[tuple[int, int]] = []
    for _, _, _, raw_offset, raw_size, flags in layout.sections:
        if not raw_size:
            continue
        substantive = flags & ~0x00F00000
        if substantive != 0xC0000040:
            continue
        section_end = raw_offset + raw_size
        cursor = (raw_offset + 15) & ~15
        while cursor + 32 <= section_end:
            if blob[cursor:cursor + len(magic)] == magic:
                candidates.append((cursor, section_end))
            cursor += 16
    if len(candidates) != 1:
        raise ArtifactInvalid(
            f"{label}: PE has no unique Go build-info header in authenticated data"
        )
    cursor, section_end = candidates[0]
    header = blob[cursor:cursor + 32]
    if header[14] not in (4, 8) or header[15] & 0x2 == 0:
        raise ArtifactInvalid(f"{label}: PE Go build-info is not inline format")
    version, cursor = _decode_uvarint_string(blob, cursor + 32, section_end)
    module_info, _ = _decode_uvarint_string(blob, cursor, section_end)
    if re.fullmatch(r"go[0-9]+\.[0-9]+(?:\.[0-9]+)?", version) is None:
        raise ArtifactInvalid(f"{label}: PE Go build-info version is invalid")
    start = bytes.fromhex("3077af0c9274080241e1c107e6d618e6").decode("latin1")
    end = bytes.fromhex("f932433186182072008242104116d8f2").decode("latin1")
    if not module_info.startswith(start) or not module_info.endswith(end):
        raise ArtifactInvalid(f"{label}: PE Go module-info framing is invalid")
    fields: dict[str, list[str]] = {}
    for line in module_info[16:-16].splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            fields.setdefault(parts[0], []).append(parts[1])
    paths = fields.get("path", [])
    modules = fields.get("mod", [])
    if len(paths) != 1 or len(modules) != 1:
        raise ArtifactInvalid(f"{label}: PE Go module identity is missing or ambiguous")
    return paths[0], modules[0]


def _require_pe_machine_architecture(blob: bytes, artifact: Artifact) -> None:
    """Derive a shipped PE's architecture from its PE machine, not metadata.

    A shipped Windows PE carries no role receipt of its own. Its role identity
    is authenticated in check() by raw byte equality with a fresh rebuild whose
    authenticated producer handoff binds the exact target, role, architecture
    and sha256. Before that, the PE machine must equal the declared
    architecture so caller metadata never selects the target being rebuilt.
    """
    parsed = _parse_pe(blob, artifact.path)
    actual_arch = next(
        (name for name, machine in PE_MACHINES.items() if machine == parsed.machine), ""
    )
    declared_machine = PE_MACHINES.get(artifact.arch)
    if not actual_arch or declared_machine != parsed.machine:
        raise ArtifactInvalid(
            f"{artifact.path}: Windows receipt architecture must derive from the PE "
            "machine, not caller metadata"
        )


@dataclass(frozen=True)
class MachoSectionLayout:
    segment: str
    name: str
    offset: int
    size: int
    address: int
    flags: int
    segment_initial_protection: int


@dataclass(frozen=True)
class MachoSliceLayout:
    arch: str
    filetype: int
    platform_id: Optional[int]
    offset: int
    size: int
    sections: tuple[MachoSectionLayout, ...]
    symbols: frozenset[str]
    symbol_locations: tuple[tuple[str, int, str, str], ...]
    defined_symbols: frozenset[str]
    defined_symbol_locations: tuple[tuple[str, int, str, str], ...]


def _macho_slice(blob: bytes, offset: int, size: int) -> MachoSliceLayout:
    end = offset + size
    if offset < 0 or size < 32 or end > len(blob):
        raise ArtifactInvalid("Mach-O slice is outside the file")
    magic = blob[offset:offset + 4]
    if magic == b"\xcf\xfa\xed\xfe":
        endian = "<"
    elif magic == b"\xfe\xed\xfa\xcf":
        endian = ">"
    else:
        raise ArtifactInvalid("Mach-O slice has an unsupported magic")
    _, cpu, _, filetype, ncmds, sizeofcmds, _, _ = struct.unpack_from(
        endian + "8I", blob, offset)
    if filetype not in (1, 6):
        raise ArtifactInvalid("Mach-O slice is not an object or dylib")
    if ncmds == 0 or ncmds > 4096:
        raise ArtifactInvalid("Mach-O load-command count is invalid")
    commands_start = offset + 32
    commands_end = commands_start + sizeofcmds
    if commands_end > end:
        raise ArtifactInvalid("Mach-O load commands exceed the slice")
    platform_id: Optional[int] = None
    sections: list[MachoSectionLayout] = []
    segment_count = 0
    has_executable_text = False
    has_dylib_identity = False
    symbol_table: Optional[tuple[int, int, int, int]] = None
    cursor = commands_start
    for _ in range(ncmds):
        if cursor + 8 > commands_end:
            raise ArtifactInvalid("Mach-O load command header is truncated")
        command, command_size = struct.unpack_from(endian + "2I", blob, cursor)
        if command_size < 8 or cursor + command_size > commands_end:
            raise ArtifactInvalid("Mach-O load command size is invalid")
        if command == 0x32:
            if command_size < 24:
                raise ArtifactInvalid("Mach-O build-version command is truncated")
            if platform_id is not None:
                raise ArtifactInvalid("Mach-O has duplicate build-version commands")
            platform_id = struct.unpack_from(endian + "I", blob, cursor + 8)[0]
        elif command == 0x2:
            if command_size != 24 or symbol_table is not None:
                raise ArtifactInvalid("Mach-O symbol-table command is invalid or duplicate")
            symbol_table = struct.unpack_from(endian + "4I", blob, cursor + 8)
        elif command == 0x19:
            if command_size < 72:
                raise ArtifactInvalid("Mach-O 64-bit segment command is truncated")
            (
                _,
                _,
                raw_segment_name,
                _,
                virtual_size,
                file_offset,
                file_size,
                maximum_protection,
                initial_protection,
                section_count,
                _,
            ) = struct.unpack_from(endian + "2I16s4Q4I", blob, cursor)
            if command_size != 72 + section_count * 80:
                raise ArtifactInvalid("Mach-O section table size is invalid")
            if file_size > virtual_size or file_offset + file_size > size:
                raise ArtifactInvalid("Mach-O segment bytes exceed the slice")
            if (
                maximum_protection & ~0x7
                or initial_protection & ~0x7
                or initial_protection & ~maximum_protection
            ):
                raise ArtifactInvalid(
                    "Mach-O segment initprot is not a valid subset of maxprot"
                )
            try:
                segment_name = raw_segment_name.split(b"\0", 1)[0].decode("ascii")
            except UnicodeDecodeError as exc:
                raise ArtifactInvalid("Mach-O segment name is not ASCII") from exc
            segment_count += 1
            if segment_name == "__TEXT" and initial_protection & 0x5 == 0x5:
                has_executable_text = True
            for section_index in range(section_count):
                section_at = cursor + 72 + section_index * 80
                (
                    raw_section_name,
                    raw_section_segment,
                    section_address,
                    section_size,
                    section_offset,
                    _,
                    _,
                    _,
                    section_flags,
                    _,
                    _,
                    _,
                ) = struct.unpack_from(endian + "16s16sQQIIIIIIII", blob, section_at)
                section_type = section_flags & 0xFF
                if section_type not in (0x1, 0xC, 0x12):
                    if section_offset + section_size > size:
                        raise ArtifactInvalid("Mach-O section bytes exceed the slice")
                    if (
                        section_offset < file_offset
                        or section_offset + section_size > file_offset + file_size
                    ):
                        raise ArtifactInvalid("Mach-O section bytes escape their segment")
                try:
                    section_name = raw_section_name.split(b"\0", 1)[0].decode("ascii")
                    section_segment = raw_section_segment.split(b"\0", 1)[0].decode("ascii")
                except UnicodeDecodeError as exc:
                    raise ArtifactInvalid("Mach-O section name is not ASCII") from exc
                if filetype == 6 and section_segment != segment_name:
                    raise ArtifactInvalid("Mach-O section/segment names disagree")
                sections.append(
                    MachoSectionLayout(
                        section_segment,
                        section_name,
                        offset + section_offset,
                        section_size,
                        section_address,
                        section_flags,
                        initial_protection,
                    )
                )
        elif command == 0xD:
            if command_size < 24:
                raise ArtifactInvalid("Mach-O dylib identity command is truncated")
            name_at = struct.unpack_from(endian + "I", blob, cursor + 8)[0]
            if name_at < 24 or name_at >= command_size:
                raise ArtifactInvalid("Mach-O dylib identity name offset is invalid")
            name_end = blob.find(b"\0", cursor + name_at, cursor + command_size)
            if name_end < 0:
                raise ArtifactInvalid("Mach-O dylib identity is unterminated")
            has_dylib_identity = True
        cursor += command_size
    if cursor != commands_end:
        raise ArtifactInvalid("Mach-O load commands do not fill sizeofcmds")
    if segment_count == 0 or not sections:
        raise ArtifactInvalid("Mach-O has no structurally loadable sections")
    file_backed = sorted(
        (item.offset, item.offset + item.size)
        for item in sections
        if item.flags & 0xFF not in (0x1, 0xC, 0x12) and item.size
    )
    for (_, first_end), (second_start, _) in zip(file_backed, file_backed[1:]):
        if second_start < first_end:
            raise ArtifactInvalid("Mach-O file-backed sections overlap")
    if filetype == 6 and (not has_executable_text or not has_dylib_identity):
        raise ArtifactInvalid("Mach-O dylib has no executable __TEXT/LC_ID_DYLIB")
    if symbol_table is None:
        if filetype == 6:
            raise ArtifactInvalid("Mach-O dylib has no LC_SYMTAB export evidence")
        symbols = set()
        symbol_offset = symbol_count = strings_offset = strings_size = 0
    else:
        symbol_offset, symbol_count, strings_offset, strings_size = symbol_table
    if symbol_table is not None and (
        symbol_count == 0
        or symbol_offset + symbol_count * 16 > size
        or strings_size == 0
        or strings_offset + strings_size > size
    ):
        raise ArtifactInvalid("Mach-O symbol or string table exceeds its slice")
    string_table = blob[offset + strings_offset:offset + strings_offset + strings_size]
    symbols = set()
    symbol_locations: list[tuple[str, int, str, str]] = []
    defined_symbols: set[str] = set()
    defined_symbol_locations: list[tuple[str, int, str, str]] = []
    for index in range(symbol_count):
        record = offset + symbol_offset + index * 16
        string_at, symbol_type, section_number, _, symbol_value = struct.unpack_from(
            endian + "IBBHQ", blob, record
        )
        if string_at >= strings_size:
            raise ArtifactInvalid("Mach-O symbol string offset is invalid")
        name_end = string_table.find(b"\0", string_at)
        if name_end < 0:
            raise ArtifactInvalid("Mach-O symbol name is unterminated")
        if (
            symbol_type & 0xE0
            or not symbol_type & 0x01
            or symbol_type & 0x0E != 0x0E
        ):
            continue
        if section_number == 0 or section_number > len(sections):
            raise ArtifactInvalid("Mach-O section-defined export has invalid section")
        section = sections[section_number - 1]
        if (
            (filetype == 6 and symbol_value == 0)
            or section.size == 0
            or not section.address <= symbol_value < section.address + section.size
        ):
            raise ArtifactInvalid(
                "Mach-O section-defined export value is outside its section"
            )
        try:
            name = string_table[string_at:name_end].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ArtifactInvalid("Mach-O exported symbol is not ASCII") from exc
        exported_name = name.removeprefix("_")
        defined_symbols.add(exported_name)
        defined_symbol_locations.append(
            (exported_name, symbol_value, section.segment, section.name)
        )
        if symbol_type & 0x01 and not symbol_type & 0x10:
            symbols.add(exported_name)
            symbol_locations.append(
                (exported_name, symbol_value, section.segment, section.name)
            )
    arch = next((name for name, value in MACHO_CPUS.items() if value == cpu), "")
    if not arch:
        raise ArtifactInvalid(f"Mach-O CPU type is unsupported: {cpu:#x}")
    return MachoSliceLayout(
        arch,
        filetype,
        platform_id,
        offset,
        size,
        tuple(sections),
        frozenset(symbols),
        tuple(symbol_locations),
        frozenset(defined_symbols),
        tuple(defined_symbol_locations),
    )


def _macho_slices(blob: bytes) -> list[MachoSliceLayout]:
    fat_magics = {
        b"\xca\xfe\xba\xbe": (">", 20, False),
        b"\xbe\xba\xfe\xca": ("<", 20, False),
        b"\xca\xfe\xba\xbf": (">", 32, True),
        b"\xbf\xba\xfe\xca": ("<", 32, True),
    }
    fat = fat_magics.get(blob[:4])
    if fat is not None:
        endian, record_size, is_64 = fat
        if len(blob) < 8:
            raise ArtifactInvalid("fat Mach-O header is truncated")
        count = struct.unpack_from(endian + "I", blob, 4)[0]
        if count == 0 or count > (len(blob) - 8) // record_size:
            raise ArtifactInvalid("fat Mach-O architecture table is truncated")
        table_end = 8 + count * record_size
        slices: list[MachoSliceLayout] = []
        seen: set[str] = set()
        ranges: list[tuple[int, int]] = []
        for index in range(count):
            record = 8 + index * record_size
            if is_64:
                cpu, _, slice_offset, slice_size, alignment, _ = struct.unpack_from(
                    endian + "2I2Q2I", blob, record
                )
            else:
                cpu, _, slice_offset, slice_size, alignment = struct.unpack_from(
                    endian + "5I", blob, record
                )
            if (
                alignment > 31
                or slice_offset % (1 << alignment)
                or slice_offset < table_end
                or slice_size < 32
                or slice_offset + slice_size > len(blob)
            ):
                raise ArtifactInvalid("fat Mach-O slice range is invalid")
            layout = _macho_slice(blob, slice_offset, slice_size)
            if MACHO_CPUS[layout.arch] != cpu:
                raise ArtifactInvalid("fat Mach-O record/slice CPU types disagree")
            if layout.arch in seen:
                raise ArtifactInvalid("fat Mach-O contains duplicate architectures")
            seen.add(layout.arch)
            ranges.append((slice_offset, slice_offset + slice_size))
            slices.append(layout)
        ordered = sorted(ranges)
        for (_, first_end), (second_start, _) in zip(ordered, ordered[1:]):
            if second_start < first_end:
                raise ArtifactInvalid("fat Mach-O slices overlap")
        return slices
    return [_macho_slice(blob, 0, len(blob))]


def _validate_macho(blob: bytes, artifact: Artifact) -> None:
    expected_arches = set(artifact.arch.split(","))
    if not expected_arches or "" in expected_arches:
        raise ArtifactInvalid(f"{artifact.path}: Mach-O architecture declaration is empty")
    slices = _macho_slices(blob)
    actual_arches = {item.arch for item in slices}
    if actual_arches != expected_arches:
        raise ArtifactInvalid(
            f"{artifact.path}: Mach-O architectures differ, expected "
            f"{sorted(expected_arches)}, got {sorted(actual_arches)}")
    expected_platform = MACHO_PLATFORMS.get(artifact.platform)
    if expected_platform is None:
        raise ArtifactInvalid(f"{artifact.path}: unsupported Apple platform {artifact.platform}")
    for item in slices:
        if item.filetype != 6 or item.platform_id != expected_platform:
            raise ArtifactInvalid(
                f"{artifact.path}: Mach-O role/platform mismatch for {item.arch}, "
                f"expected dylib platform {expected_platform}, got "
                f"type {item.filetype} platform {item.platform_id}")
        executable_code = [
            blob[section.offset:section.offset + section.size]
            for section in item.sections
            if section.segment == "__TEXT"
            and section.name == "__text"
            and section.size
            and section.segment_initial_protection & 0x5 == 0x5
        ]
        if (
            sum(len(code) for code in executable_code) < 64
            or not any(any(code) for code in executable_code)
        ):
            raise ArtifactInvalid(
                f"{artifact.path}: Mach-O has no substantive format-declared "
                f"executable code for {item.arch}"
            )
    if artifact.role == "core+relay":
        required = {symbol.decode("ascii") for symbol in APPLE_REQUIRED_SYMBOLS}
        for item in slices:
            missing = sorted(required - item.symbols)
            if missing:
                raise ArtifactInvalid(
                    f"{artifact.path}: Apple wrapper is missing exported {missing[0]}")
            required_locations = {
                name: (address, segment, section)
                for name, address, segment, section in item.symbol_locations
                if name in required
            }
            required_location_count = sum(
                1 for name, _, _, _ in item.symbol_locations if name in required
            )
            executable_text = [
                section
                for section in item.sections
                if section.segment == "__TEXT"
                and section.name == "__text"
                and section.size > 0
                and section.segment_initial_protection & 0x5 == 0x5
            ]
            implementation_ranges: list[tuple[int, int]] = []
            implementation_bytes_are_real = True
            instruction_width = 4
            for address, segment, section_name in required_locations.values():
                section = next(
                    (
                        candidate for candidate in executable_text
                        if candidate.segment == segment
                        and candidate.name == section_name
                        and candidate.address <= address
                        and address + instruction_width
                        <= candidate.address + candidate.size
                    ),
                    None,
                )
                if section is None or address % instruction_width:
                    implementation_bytes_are_real = False
                    continue
                start = section.offset + address - section.address
                end = start + instruction_width
                code = blob[start:end]
                if (
                    len(code) != instruction_width
                    or code in {
                        b"\x00" * instruction_width,
                        b"\xff" * instruction_width,
                    }
                    or len(set(code)) < 2
                    or all(0x20 <= byte <= 0x7E for byte in code)
                ):
                    implementation_bytes_are_real = False
                implementation_ranges.append((address, address + instruction_width))
            ordered_ranges = sorted(implementation_ranges)
            non_overlapping = all(
                second_start >= first_end
                for (_, first_end), (second_start, _) in zip(
                    ordered_ranges, ordered_ranges[1:]
                )
            )
            if (
                set(required_locations) != required
                or required_location_count != len(required)
                or len(executable_text) != 1
                or any(
                    segment != "__TEXT" or section != "__text"
                    for _, segment, section in required_locations.values()
                )
                or len({address for address, _, _ in required_locations.values()})
                != len(required)
                or len(implementation_ranges) != len(required)
                or not non_overlapping
                or not implementation_bytes_are_real
            ):
                raise ArtifactInvalid(
                    f"{artifact.path}: required Apple role exports must resolve to "
                    "distinct aligned non-overlapping executable implementations "
                    "in __TEXT,__text"
                )
        if WINN_MARKER not in blob:
            raise ArtifactInvalid(f"{artifact.path}: Apple wrapper has no Winn core marker")
    else:
        raise ArtifactInvalid(f"{artifact.path}: unsupported Mach-O role {artifact.role}")


@dataclass(frozen=True)
class ArchiveMember:
    name: str
    payload: bytes
    header_offset: int
    payload_offset: int
    stored_size: int


def _archive_members(blob: bytes) -> list[ArchiveMember]:
    if not blob.startswith(AR_MAGIC):
        raise ArtifactInvalid("Apple archive has no ar magic")
    members: list[ArchiveMember] = []
    cursor = len(AR_MAGIC)
    while cursor < len(blob):
        if cursor + 60 > len(blob):
            raise ArtifactInvalid("Apple archive member header is truncated")
        header = blob[cursor:cursor + 60]
        if header[58:60] != b"\x60\n":
            raise ArtifactInvalid("Apple archive member terminator is invalid")
        try:
            raw_name = header[:16].decode("ascii").rstrip()
            timestamp = header[16:28].decode("ascii").strip()
            owner = header[28:34].decode("ascii").strip()
            group = header[34:40].decode("ascii").strip()
            mode = header[40:48].decode("ascii").strip()
            size_text = header[48:58].decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise ArtifactInvalid("Apple archive member header is not ASCII") from exc
        if (
            timestamp and not timestamp.isdecimal()
            or owner and not owner.isdecimal()
            or group and not group.isdecimal()
            or mode and re.fullmatch(r"[0-7]+", mode) is None
            or not size_text.isdecimal()
        ):
            raise ArtifactInvalid("Apple archive member header fields are invalid")
        try:
            member_size = int(size_text)
        except ValueError as exc:
            raise ArtifactInvalid("Apple archive member size is invalid") from exc
        payload_start = cursor + 60
        payload_end = payload_start + member_size
        if member_size < 0 or payload_end > len(blob):
            raise ArtifactInvalid("Apple archive member exceeds the file")
        payload = blob[payload_start:payload_end]
        content_offset = payload_start
        if raw_name.startswith("#1/"):
            try:
                name_size = int(raw_name[3:])
            except ValueError as exc:
                raise ArtifactInvalid("Apple archive long member name is invalid") from exc
            if name_size <= 0 or name_size > len(payload):
                raise ArtifactInvalid("Apple archive long member name exceeds its member")
            name_bytes = payload[:name_size].rstrip(b"\x00")
            try:
                name = name_bytes.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ArtifactInvalid("Apple archive member name is not ASCII") from exc
            payload = payload[name_size:]
            content_offset += name_size
        else:
            name = raw_name.rstrip("/")
        if not name or "\0" in name or "/" in name:
            raise ArtifactInvalid("Apple archive member name is unsafe")
        members.append(
            ArchiveMember(name, payload, cursor, content_offset, member_size)
        )
        if member_size & 1:
            if payload_end >= len(blob) or blob[payload_end:payload_end + 1] != b"\n":
                raise ArtifactInvalid("Apple archive member padding is invalid")
        cursor = payload_end + (member_size & 1)
    if cursor != len(blob):
        raise ArtifactInvalid("Apple archive has trailing bytes")
    return members


def _validate_bsd_symbol_table(
    payload: bytes,
    member_layouts: dict[int, tuple[MachoSliceLayout, ...]],
    go_object_header: int,
) -> None:
    for endian in ("<", ">"):
        if len(payload) < 8:
            break
        table_bytes = struct.unpack_from(endian + "I", payload, 0)[0]
        if (
            table_bytes < 8
            or table_bytes % 8
            or table_bytes > 8 * 1024 * 1024
            or 4 + table_bytes + 4 > len(payload)
        ):
            continue
        strings_at = 4 + table_bytes
        string_bytes = struct.unpack_from(endian + "I", payload, strings_at)[0]
        if (
            string_bytes == 0
            or string_bytes > 16 * 1024 * 1024
            or strings_at + 4 + string_bytes != len(payload)
        ):
            continue
        strings = payload[strings_at + 4:]
        valid = True
        go_role_symbols = 0
        seen_records: set[tuple[int, int]] = set()
        for record in range(0, table_bytes, 8):
            string_at, member_at = struct.unpack_from(endian + "II", payload, 4 + record)
            if (
                string_at >= len(strings)
                or (string_at > 0 and strings[string_at - 1] != 0)
                or member_at not in member_layouts
                or (string_at, member_at) in seen_records
            ):
                valid = False
                break
            seen_records.add((string_at, member_at))
            string_end = strings.find(b"\0", string_at)
            if string_end <= string_at:
                valid = False
                break
            symbol = strings[string_at:string_end]
            try:
                symbol_name = symbol.decode("ascii").removeprefix("_")
            except UnicodeDecodeError:
                valid = False
                break
            target_layouts = member_layouts[member_at]
            matching_locations = [
                (address, segment, section)
                for layout in target_layouts
                for name, address, segment, section in layout.defined_symbol_locations
                if name == symbol_name
            ]
            if not matching_locations:
                valid = False
                break
            if symbol.startswith(b"__cgoexp_") and symbol.endswith(
                b"_WinnTunnelCreateWinn3"
            ):
                go_role_symbols += 1
                if member_at != go_object_header:
                    valid = False
                    break
                role_locations = [
                    (segment, section)
                    for _, segment, section in matching_locations
                ]
                if not role_locations or any(
                    segment != "__TEXT" or section != "__text"
                    for segment, section in role_locations
                ):
                    valid = False
                    break
        if valid and go_role_symbols == 1:
            return
    raise ArtifactInvalid("Apple archive symbol table is malformed")


def _validate_archive(blob: bytes, artifact: Artifact) -> None:
    members = _archive_members(blob)
    go_members = [member for member in members if member.name == "go.o"]
    if len(go_members) != 1:
        raise ArtifactInvalid(f"{artifact.path}: archive must have one go.o member")
    go_object_header = go_members[0].header_offset
    objects: list[tuple[str, str, int, Optional[int]]] = []
    names: set[str] = set()
    symbol_tables = 0
    symbol_table_payloads: list[bytes] = []
    go_objects = 0
    exported_symbols: set[str] = set()
    member_layouts: dict[int, tuple[MachoSliceLayout, ...]] = {}
    for member in members:
        name, payload = member.name, member.payload
        if name in names:
            raise ArtifactInvalid(f"{artifact.path}: duplicate archive member {name}")
        names.add(name)
        if name in ("__.SYMDEF", "__.SYMDEF SORTED"):
            symbol_tables += 1
            symbol_table_payloads.append(payload)
            continue
        if name == "__.PKGDEF":
            if b"go object " not in payload[:256]:
                raise ArtifactInvalid(f"{artifact.path}: malformed __.PKGDEF member")
            continue
        slices = tuple(_macho_slices(payload))
        member_layouts[member.header_offset] = slices
        if name == "go.o":
            go_objects += 1
        for item in slices:
            objects.append((name, item.arch, item.filetype, item.platform_id))
            exported_symbols.update(item.symbols)
    if symbol_tables != 1:
        raise ArtifactInvalid(f"{artifact.path}: archive must have one BSD symbol table")
    _validate_bsd_symbol_table(
        symbol_table_payloads[0], member_layouts, go_object_header
    )
    go_executable_code = [
        go_members[0].payload[section.offset:section.offset + section.size]
        for layout in member_layouts.get(go_object_header, ())
        for section in layout.sections
        if section.segment == "__TEXT"
        and section.name == "__text"
        and section.size
        and section.flags & 0x80000400 == 0x80000400
    ]
    if (
        sum(len(code) for code in go_executable_code) < 64
        or not any(any(code) for code in go_executable_code)
    ):
        raise ArtifactInvalid(
            f"{artifact.path}: Apple archive go.o has no substantive "
            "format-declared executable code"
        )
    if go_objects != 1:
        raise ArtifactInvalid(f"{artifact.path}: archive must have one go.o member")
    if not objects:
        raise ArtifactInvalid(f"{artifact.path}: Apple archive has no Mach-O object")
    actual_arches = {arch for _, arch, _, _ in objects}
    expected_arches = {artifact.arch}
    if actual_arches != expected_arches:
        raise ArtifactInvalid(
            f"{artifact.path}: archive architectures differ, expected "
            f"{sorted(expected_arches)}, got {sorted(actual_arches)}")
    expected_platform = MACHO_PLATFORMS.get(artifact.platform)
    if expected_platform is None:
        raise ArtifactInvalid(f"{artifact.path}: unsupported Apple platform {artifact.platform}")
    for name, arch, filetype, platform_id in objects:
        if filetype != 1 or platform_id != expected_platform:
            raise ArtifactInvalid(
                f"{artifact.path}: archive member {name} has wrong role/platform")
    if WINN_MARKER not in blob or "WinnTunnelCreateWinn3" not in exported_symbols:
        raise ArtifactInvalid(f"{artifact.path}: Apple archive is not a current Winn core archive")


def _normalise_member_name(name: str) -> str:
    if not name or "\x00" in name or "\\" in name or name.startswith("/"):
        raise ArtifactInvalid(f"package member path is unsafe: {name!r}")
    parts = [part for part in name.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise ArtifactInvalid(f"package member path traverses its root: {name!r}")
    normalised = "/".join(parts)
    if not normalised:
        raise ArtifactInvalid(f"package member path is empty: {name!r}")
    return normalised


def _package_expected_members(artifact: Artifact) -> set[str]:
    if "devicecheck" in artifact.path:
        return {artifact.member}
    prefix = "base/" if artifact.member.startswith("base/") else ""
    return {f"{prefix}lib/{abi}/libwinnengine.so" for abi in ANDROID_ABIS}


def _validate_android_resource_chunk(payload: bytes, expected_type: int, label: str) -> None:
    chunk_type, _, chunk_size = _android_chunk_header(
        payload, 0, len(payload), label
    )
    if chunk_type != expected_type or chunk_size != len(payload):
        raise ArtifactInvalid(f"{label}: Android resource chunk header is invalid")


def _android_chunk_header(
    payload: bytes,
    offset: int,
    limit: int,
    label: str,
) -> tuple[int, int, int]:
    if offset < 0 or limit > len(payload) or offset + 8 > limit:
        raise ArtifactInvalid(f"{label}: Android resource chunk is truncated")
    chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", payload, offset)
    if (
        header_size < 8
        or chunk_size < header_size
        or chunk_size & 3
        or offset + chunk_size > limit
    ):
        raise ArtifactInvalid(f"{label}: Android resource chunk bounds are invalid")
    return chunk_type, header_size, chunk_size


def _android_utf8_length(
    payload: bytes,
    cursor: int,
    limit: int,
    label: str,
) -> tuple[int, int]:
    if cursor >= limit:
        raise ArtifactInvalid(f"{label}: UTF-8 string length is truncated")
    first = payload[cursor]
    cursor += 1
    if first & 0x80:
        if cursor >= limit:
            raise ArtifactInvalid(f"{label}: UTF-8 string length is truncated")
        return ((first & 0x7F) << 8) | payload[cursor], cursor + 1
    return first, cursor


def _android_utf16_length(
    payload: bytes,
    cursor: int,
    limit: int,
    label: str,
) -> tuple[int, int]:
    if cursor + 2 > limit:
        raise ArtifactInvalid(f"{label}: UTF-16 string length is truncated")
    first = struct.unpack_from("<H", payload, cursor)[0]
    cursor += 2
    if first & 0x8000:
        if cursor + 2 > limit:
            raise ArtifactInvalid(f"{label}: UTF-16 string length is truncated")
        second = struct.unpack_from("<H", payload, cursor)[0]
        return ((first & 0x7FFF) << 16) | second, cursor + 2
    return first, cursor


def _android_string_pool(
    payload: bytes,
    offset: int,
    limit: int,
    label: str,
) -> tuple[str, ...]:
    chunk_type, header_size, chunk_size = _android_chunk_header(
        payload, offset, limit, label
    )
    if chunk_type != 0x0001 or header_size < 28:
        raise ArtifactInvalid(f"{label}: Android string pool header is invalid")
    string_count, style_count, flags, strings_start, styles_start = struct.unpack_from(
        "<5I", payload, offset + 8
    )
    offsets_end = header_size + 4 * (string_count + style_count)
    if (
        offsets_end > chunk_size
        or strings_start < offsets_end
        or strings_start > chunk_size
        or (style_count == 0 and styles_start != 0)
        or (style_count and (styles_start < strings_start or styles_start > chunk_size))
    ):
        raise ArtifactInvalid(f"{label}: Android string pool offsets are invalid")
    strings_limit = offset + (styles_start or chunk_size)
    strings: list[str] = []
    for index in range(string_count):
        relative = struct.unpack_from("<I", payload, offset + header_size + 4 * index)[0]
        cursor = offset + strings_start + relative
        if cursor >= strings_limit:
            raise ArtifactInvalid(f"{label}: Android string offset is invalid")
        try:
            if flags & 0x00000100:
                _, cursor = _android_utf8_length(payload, cursor, strings_limit, label)
                byte_length, cursor = _android_utf8_length(
                    payload, cursor, strings_limit, label
                )
                end = cursor + byte_length
                if end >= strings_limit or payload[end] != 0:
                    raise ArtifactInvalid(f"{label}: Android UTF-8 string is unterminated")
                value = payload[cursor:end].decode("utf-8")
            else:
                character_count, cursor = _android_utf16_length(
                    payload, cursor, strings_limit, label
                )
                end = cursor + character_count * 2
                if end + 2 > strings_limit or payload[end:end + 2] != b"\0\0":
                    raise ArtifactInvalid(f"{label}: Android UTF-16 string is unterminated")
                value = payload[cursor:end].decode("utf-16le")
        except UnicodeDecodeError as exc:
            raise ArtifactInvalid(f"{label}: Android string is malformed") from exc
        strings.append(value)
    return tuple(strings)


def _validate_binary_android_manifest(
    payload: bytes,
    label: str,
    expected_package: str,
) -> None:
    _validate_android_resource_chunk(payload, 0x0003, label)
    _, header_size, chunk_size = _android_chunk_header(payload, 0, len(payload), label)
    strings: Optional[tuple[str, ...]] = None
    stack: list[int] = []
    root_name = ""
    manifest_package = ""
    application_names: list[str] = []
    android_namespace = "http://schemas.android.com/apk/res/android"
    cursor = header_size
    while cursor < chunk_size:
        chunk_type, nested_header, nested_size = _android_chunk_header(
            payload, cursor, chunk_size, label
        )
        if chunk_type == 0x0001:
            if strings is not None:
                raise ArtifactInvalid(f"{label}: duplicate Android XML string pool")
            strings = _android_string_pool(payload, cursor, chunk_size, label)
        elif chunk_type == 0x0102:
            if strings is None or nested_header != 16 or nested_size < 36:
                raise ArtifactInvalid(f"{label}: Android start-element chunk is invalid")
            extension = cursor + 16
            _, name_index, attribute_start, attribute_size, attribute_count, _, _, _ = (
                struct.unpack_from("<II6H", payload, extension)
            )
            attributes_at = extension + attribute_start
            if (
                name_index >= len(strings)
                or attribute_start < 20
                or attribute_size < 20
                or attributes_at + attribute_count * attribute_size > cursor + nested_size
            ):
                raise ArtifactInvalid(f"{label}: Android start-element fields are invalid")
            attributes: dict[tuple[str, str], str] = {}
            for index in range(attribute_count):
                attribute = attributes_at + index * attribute_size
                namespace_index, attribute_name, raw_value = struct.unpack_from(
                    "<III", payload, attribute
                )
                value_size, value_zero, value_type, value_data = struct.unpack_from(
                    "<HBBI", payload, attribute + 12
                )
                if (
                    attribute_name >= len(strings)
                    or (namespace_index != 0xFFFFFFFF and namespace_index >= len(strings))
                    or (raw_value != 0xFFFFFFFF and raw_value >= len(strings))
                    or value_size != 8
                    or value_zero != 0
                ):
                    raise ArtifactInvalid(f"{label}: Android XML attribute is invalid")
                if raw_value != 0xFFFFFFFF:
                    value = strings[raw_value]
                elif value_type == 0x03 and value_data < len(strings):
                    value = strings[value_data]
                else:
                    continue
                namespace = (
                    "" if namespace_index == 0xFFFFFFFF else strings[namespace_index]
                )
                key = (namespace, strings[attribute_name])
                if key in attributes:
                    raise ArtifactInvalid(f"{label}: duplicate Android XML attribute")
                attributes[key] = value
            element_name = strings[name_index]
            if not stack and element_name == "manifest":
                manifest_package = attributes.get(("", "package"), "")
            elif (
                len(stack) == 1
                and strings[stack[0]] == "manifest"
                and element_name == "application"
            ):
                application_names.append(
                    attributes.get((android_namespace, "name"), "")
                )
            stack.append(name_index)
            if not root_name:
                root_name = element_name
        elif chunk_type == 0x0103:
            if strings is None or nested_header != 16 or nested_size != 24 or not stack:
                raise ArtifactInvalid(f"{label}: Android end-element chunk is invalid")
            _, name_index = struct.unpack_from("<II", payload, cursor + 16)
            if name_index >= len(strings) or stack.pop() != name_index:
                raise ArtifactInvalid(f"{label}: Android XML elements are unbalanced")
        elif chunk_type in (0x0100, 0x0101):
            if strings is None or nested_header != 16 or nested_size != 24:
                raise ArtifactInvalid(f"{label}: Android namespace chunk is invalid")
            prefix_index, uri_index = struct.unpack_from("<II", payload, cursor + 16)
            if any(index != 0xFFFFFFFF and index >= len(strings) for index in (
                prefix_index, uri_index
            )):
                raise ArtifactInvalid(f"{label}: Android namespace string is invalid")
        elif chunk_type == 0x0180:
            if nested_header != 8 or (nested_size - nested_header) & 3:
                raise ArtifactInvalid(f"{label}: Android resource map is invalid")
        else:
            raise ArtifactInvalid(
                f"{label}: unsupported Android XML chunk type {chunk_type:#x}"
            )
        cursor += nested_size
    if strings is None or stack or root_name != "manifest":
        raise ArtifactInvalid(f"{label}: Android XML has no balanced manifest root")
    if manifest_package != expected_package:
        raise ArtifactInvalid(
            f"{label}: Android manifest package is not {expected_package}"
        )
    if application_names != ["android.app.Application"]:
        raise ArtifactInvalid(
            f"{label}: Android manifest application identity is not exact"
        )


def _validate_android_package_resource(
    payload: bytes,
    offset: int,
    limit: int,
    label: str,
) -> None:
    chunk_type, header_size, chunk_size = _android_chunk_header(
        payload, offset, limit, label
    )
    if chunk_type != 0x0200 or header_size < 284 or chunk_size <= header_size:
        raise ArtifactInvalid(f"{label}: Android package resource header is invalid")
    package_id = struct.unpack_from("<I", payload, offset + 8)[0]
    raw_name = payload[offset + 12:offset + 268]
    try:
        package_name = raw_name.decode("utf-16le").split("\0", 1)[0]
    except UnicodeDecodeError as exc:
        raise ArtifactInvalid(f"{label}: Android package name is malformed") from exc
    type_strings = struct.unpack_from("<I", payload, offset + 268)[0]
    key_strings = struct.unpack_from("<I", payload, offset + 276)[0]
    if package_id == 0 or package_id > 0xFF or not package_name:
        raise ArtifactInvalid(f"{label}: Android package identity is invalid")
    children: dict[int, int] = {}
    cursor = offset + header_size
    while cursor < offset + chunk_size:
        nested_type, _, nested_size = _android_chunk_header(
            payload, cursor, offset + chunk_size, label
        )
        if nested_type == 0x0001:
            _android_string_pool(payload, cursor, offset + chunk_size, label)
            children[cursor - offset] = nested_type
        cursor += nested_size
    if cursor != offset + chunk_size or children.get(type_strings) != 0x0001 or (
        children.get(key_strings) != 0x0001
    ):
        raise ArtifactInvalid(f"{label}: Android package string pools are invalid")


def _validate_binary_android_resources(payload: bytes, label: str) -> None:
    _validate_android_resource_chunk(payload, 0x0002, label)
    _, header_size, chunk_size = _android_chunk_header(payload, 0, len(payload), label)
    if header_size < 12:
        raise ArtifactInvalid(f"{label}: Android resource table header is truncated")
    expected_packages = struct.unpack_from("<I", payload, 8)[0]
    string_pools = 0
    packages = 0
    cursor = header_size
    while cursor < chunk_size:
        chunk_type, _, nested_size = _android_chunk_header(
            payload, cursor, chunk_size, label
        )
        if chunk_type == 0x0001:
            _android_string_pool(payload, cursor, chunk_size, label)
            string_pools += 1
        elif chunk_type == 0x0200:
            _validate_android_package_resource(payload, cursor, chunk_size, label)
            packages += 1
        else:
            raise ArtifactInvalid(
                f"{label}: unsupported Android resource-table chunk {chunk_type:#x}"
            )
        cursor += nested_size
    if string_pools != 1 or packages == 0 or packages != expected_packages:
        raise ArtifactInvalid(f"{label}: Android resource table is incomplete")


def _validate_dex(payload: bytes, label: str) -> None:
    if (
        len(payload) < 0x70
        or payload[:4] != b"dex\n"
        or not payload[4:7].isdigit()
        or payload[7] != 0
    ):
        raise ArtifactInvalid(f"{label}: DEX header is invalid")
    checksum = struct.unpack_from("<I", payload, 8)[0]
    file_size, header_size, endian_tag = struct.unpack_from("<III", payload, 32)
    if file_size != len(payload) or header_size != 0x70 or endian_tag != 0x12345678:
        raise ArtifactInvalid(f"{label}: DEX size/header/endian fields are invalid")
    if hashlib.sha1(payload[32:]).digest() != payload[12:32]:
        raise ArtifactInvalid(f"{label}: DEX signature is invalid")
    if zlib.adler32(payload[12:]) & 0xFFFFFFFF != checksum:
        raise ArtifactInvalid(f"{label}: DEX checksum is invalid")
    link_size, link_offset, map_offset = struct.unpack_from("<III", payload, 44)
    if (link_size == 0) != (link_offset == 0):
        raise ArtifactInvalid(f"{label}: DEX link section size/offset disagree")
    if link_size and link_offset + link_size > len(payload):
        raise ArtifactInvalid(f"{label}: DEX link section exceeds the file")
    if map_offset < header_size or map_offset & 3 or map_offset + 4 > len(payload):
        raise ArtifactInvalid(f"{label}: DEX map offset is invalid")
    fixed_sections = (
        (56, 4),
        (64, 4),
        (72, 12),
        (80, 8),
        (88, 8),
        (96, 32),
    )
    for field_offset, item_size in fixed_sections:
        count, section_offset = struct.unpack_from("<II", payload, field_offset)
        if (count == 0) != (section_offset == 0):
            raise ArtifactInvalid(f"{label}: DEX section size/offset disagree")
        if count and (
            section_offset < header_size
            or section_offset & 3
            or section_offset + count * item_size > len(payload)
        ):
            raise ArtifactInvalid(f"{label}: DEX fixed section exceeds the file")
    data_size, data_offset = struct.unpack_from("<II", payload, 104)
    if (
        data_size == 0
        or data_offset < header_size
        or data_offset & 3
        or data_offset + data_size != len(payload)
        or not (data_offset <= map_offset < len(payload))
    ):
        raise ArtifactInvalid(f"{label}: DEX data section is invalid")
    map_count = struct.unpack_from("<I", payload, map_offset)[0]
    map_end = map_offset + 4 + map_count * 12
    if map_count < 2 or map_end > len(payload):
        raise ArtifactInvalid(f"{label}: DEX map list is truncated")
    map_items: dict[int, tuple[int, int]] = {}
    last_offset = -1
    for index in range(map_count):
        item_type, unused, count, offset = struct.unpack_from(
            "<HHII", payload, map_offset + 4 + index * 12
        )
        if unused != 0 or count == 0 or item_type in map_items:
            raise ArtifactInvalid(f"{label}: DEX map item is invalid or duplicate")
        if offset < last_offset or offset >= len(payload):
            raise ArtifactInvalid(f"{label}: DEX map offsets are invalid")
        map_items[item_type] = (count, offset)
        last_offset = offset
    if map_items.get(0x0000) != (1, 0) or map_items.get(0x1000) != (1, map_offset):
        raise ArtifactInvalid(f"{label}: DEX map omits its header or map list")


def _read_varint(payload: bytes, cursor: int, label: str) -> tuple[int, int]:
    value = 0
    for shift in range(0, 70, 7):
        if cursor >= len(payload):
            raise ArtifactInvalid(f"{label}: protobuf varint is truncated")
        byte = payload[cursor]
        cursor += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, cursor
    raise ArtifactInvalid(f"{label}: protobuf varint is too wide")


def _protobuf_fields(
    payload: bytes,
    label: str,
) -> tuple[tuple[int, int, object], ...]:
    if not payload:
        raise ArtifactInvalid(f"{label}: protobuf message is empty")
    cursor = 0
    fields: list[tuple[int, int, object]] = []
    while cursor < len(payload):
        key, cursor = _read_varint(payload, cursor, label)
        field_number, wire_type = key >> 3, key & 0x7
        if field_number == 0 or wire_type in (3, 4, 6, 7):
            raise ArtifactInvalid(f"{label}: protobuf field key is invalid")
        if wire_type == 0:
            value, cursor = _read_varint(payload, cursor, label)
        elif wire_type == 1:
            value = payload[cursor:cursor + 8]
            cursor += 8
        elif wire_type == 2:
            length, cursor = _read_varint(payload, cursor, label)
            value = payload[cursor:cursor + length]
            cursor += length
        else:
            value = payload[cursor:cursor + 4]
            cursor += 4
        if cursor > len(payload):
            raise ArtifactInvalid(f"{label}: protobuf field exceeds the message")
        fields.append((field_number, wire_type, value))
    if not fields:
        raise ArtifactInvalid(f"{label}: protobuf message contains no fields")
    return tuple(fields)


def _validate_protobuf(payload: bytes, label: str) -> None:
    _protobuf_fields(payload, label)


def _protobuf_bytes(
    fields: tuple[tuple[int, int, object], ...],
    number: int,
) -> tuple[bytes, ...]:
    return tuple(
        value
        for field_number, wire_type, value in fields
        if field_number == number and wire_type == 2 and isinstance(value, bytes)
    )


def _validate_bundle_config(payload: bytes, label: str) -> None:
    bundletools = _protobuf_bytes(_protobuf_fields(payload, label), 1)
    if len(bundletools) != 1:
        raise ArtifactInvalid(f"{label}: BundleConfig has no unique bundletool message")
    versions = _protobuf_bytes(
        _protobuf_fields(bundletools[0], label + ":bundletool"),
        2,
    )
    if len(versions) != 1:
        raise ArtifactInvalid(f"{label}: BundleConfig bundletool version is missing")
    try:
        version = versions[0].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ArtifactInvalid(f"{label}: bundletool version is not ASCII") from exc
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9._-]+)?", version) is None:
        raise ArtifactInvalid(f"{label}: bundletool version is malformed")


def _validate_aab_manifest(
    payload: bytes,
    label: str,
    expected_package: str,
) -> None:
    roots = _protobuf_bytes(_protobuf_fields(payload, label), 1)
    if len(roots) != 1:
        raise ArtifactInvalid(f"{label}: AAB manifest has no unique root element")
    element_fields = _protobuf_fields(roots[0], label + ":element")
    names = _protobuf_bytes(element_fields, 3)
    if names != (b"manifest",):
        raise ArtifactInvalid(f"{label}: AAB manifest root is not manifest")
    package_names: list[bytes] = []
    for attribute in _protobuf_bytes(element_fields, 4):
        attribute_fields = _protobuf_fields(attribute, label + ":attribute")
        if _protobuf_bytes(attribute_fields, 2) == (b"package",):
            package_names.extend(_protobuf_bytes(attribute_fields, 3))
    if package_names != [expected_package.encode("ascii")]:
        raise ArtifactInvalid(f"{label}: AAB manifest package attribute is invalid")
    applications: list[bytes] = []
    for child in _protobuf_bytes(element_fields, 5):
        child_elements = _protobuf_bytes(_protobuf_fields(child, label + ":child"), 1)
        if len(child_elements) != 1:
            raise ArtifactInvalid(f"{label}: AAB manifest child is not one element")
        child_fields = _protobuf_fields(child_elements[0], label + ":child-element")
        if _protobuf_bytes(child_fields, 3) != (b"application",):
            continue
        for attribute in _protobuf_bytes(child_fields, 4):
            attribute_fields = _protobuf_fields(
                attribute, label + ":application-attribute"
            )
            if (
                _protobuf_bytes(attribute_fields, 1)
                == (b"http://schemas.android.com/apk/res/android",)
                and _protobuf_bytes(attribute_fields, 2) == (b"name",)
            ):
                applications.extend(_protobuf_bytes(attribute_fields, 3))
    if applications != [b"android.app.Application"]:
        raise ArtifactInvalid(f"{label}: AAB manifest application identity is invalid")


def _validate_aab_resources(payload: bytes, label: str) -> None:
    packages = _protobuf_bytes(_protobuf_fields(payload, label), 2)
    if not packages:
        raise ArtifactInvalid(f"{label}: AAB resource table has no package")
    names: set[bytes] = set()
    for index, package in enumerate(packages):
        package_fields = _protobuf_fields(package, f"{label}:package[{index}]")
        package_names = _protobuf_bytes(package_fields, 2)
        if len(package_names) != 1 or not package_names[0] or package_names[0] in names:
            raise ArtifactInvalid(f"{label}: AAB resource package name is invalid")
        names.add(package_names[0])
        package_ids = _protobuf_bytes(package_fields, 1)
        if package_ids:
            if len(package_ids) != 1:
                raise ArtifactInvalid(f"{label}: AAB resource package ID is duplicated")
            id_fields = _protobuf_fields(package_ids[0], f"{label}:package-id")
            ids = [
                value
                for number, wire_type, value in id_fields
                if number == 1 and wire_type == 0 and isinstance(value, int)
            ]
            if len(ids) != 1 or not 0 <= ids[0] <= 0xFF:
                raise ArtifactInvalid(f"{label}: AAB resource package ID is invalid")


def _validate_android_package_structure(
    package: zipfile.ZipFile,
    entries: dict[str, zipfile.ZipInfo],
    artifact: Artifact,
) -> None:
    corrupt = package.testzip()
    if corrupt is not None:
        raise ArtifactInvalid(f"{artifact.path}: corrupt ZIP member {corrupt}")
    is_aab = artifact.path.endswith(".aab") or artifact.member.startswith("base/")
    expected_package = (
        "org.winsvpn.devicecheck"
        if artifact.path.startswith("android/devicecheck/")
        else "org.winsvpn.app"
    )
    if is_aab:
        required = (
            "BundleConfig.pb",
            "base/manifest/AndroidManifest.xml",
            "base/resources.pb",
            "base/dex/classes.dex",
        )
        missing = [name for name in required if name not in entries]
        if missing:
            raise ArtifactInvalid(f"{artifact.path}: AAB is missing {missing[0]}")
        _validate_bundle_config(
            package.read(entries["BundleConfig.pb"]),
            f"{artifact.path}:BundleConfig.pb",
        )
        _validate_aab_manifest(
            package.read(entries["base/manifest/AndroidManifest.xml"]),
            f"{artifact.path}:base/manifest/AndroidManifest.xml",
            expected_package,
        )
        _validate_aab_resources(
            package.read(entries["base/resources.pb"]),
            f"{artifact.path}:base/resources.pb",
        )
        _validate_dex(
            package.read(entries["base/dex/classes.dex"]),
            f"{artifact.path}:base/dex/classes.dex",
        )
        return

    required_apk = ("AndroidManifest.xml", "resources.arsc", "classes.dex")
    missing = [name for name in required_apk if name not in entries]
    if missing:
        raise ArtifactInvalid(f"{artifact.path}: APK is missing {missing[0]}")
    _validate_binary_android_manifest(
        package.read(entries["AndroidManifest.xml"]),
        f"{artifact.path}:AndroidManifest.xml",
        expected_package,
    )
    _validate_binary_android_resources(
        package.read(entries["resources.arsc"]),
        f"{artifact.path}:resources.arsc",
    )
    dex_names = sorted(
        name
        for name in entries
        if re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex", name)
    )
    if not dex_names:
        raise ArtifactInvalid(f"{artifact.path}: APK contains no DEX payload")
    for name in dex_names:
        _validate_dex(package.read(entries[name]), f"{artifact.path}:{name}")


def _read_zip_member(
    path: str,
    artifact: Artifact,
    archive: Optional[bytes] = None,
) -> bytes:
    if archive is None:
        archive = _read_stable_file(path, artifact.path, 512 * 1024 * 1024)
    entries: dict[str, zipfile.ZipInfo] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(archive), "r") as package:
            for info in package.infolist():
                name = _normalise_member_name(info.filename)
                if name in entries:
                    raise ArtifactInvalid(f"{artifact.path}: duplicate package member {name}")
                entries[name] = info
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    raise ArtifactInvalid(f"{artifact.path}: symbolic package member {name}")
                file_type = stat.S_IFMT(mode)
                if mode and not info.is_dir() and file_type not in (0, stat.S_IFREG):
                    raise ArtifactInvalid(f"{artifact.path}: non-regular package member {name}")
            _validate_android_package_structure(package, entries, artifact)
            expected = _package_expected_members(artifact)
            actual = {name for name in entries if name.endswith("/libwinnengine.so")}
            if actual != expected:
                raise ArtifactInvalid(
                    f"{artifact.path}: Winn package members differ, expected "
                    f"{sorted(expected)}, got {sorted(actual)}")
            info = entries.get(artifact.member)
            if info is None or info.is_dir():
                raise ArtifactInvalid(f"{artifact.path}: missing Winn member {artifact.member}")
            if info.file_size <= 0 or info.file_size > 512 * 1024 * 1024:
                raise ArtifactInvalid(f"{artifact.path}: Winn member size is invalid")
            return package.read(info)
    except ArtifactInvalid:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError, ValueError) as exc:
        raise ArtifactInvalid(f"{artifact.path}: invalid ZIP package: {exc}") from exc


def _read_tar_member(
    path: str,
    artifact: Artifact,
    archive: Optional[bytes] = None,
) -> bytes:
    if archive is None:
        archive = _read_stable_file(path, artifact.path, 512 * 1024 * 1024)
    entries: dict[str, tarfile.TarInfo] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as package:
            for info in package.getmembers():
                name = _normalise_member_name(info.name)
                if name in entries:
                    raise ArtifactInvalid(f"{artifact.path}: duplicate package member {name}")
                entries[name] = info
                if info.issym() or info.islnk() or not (info.isdir() or info.isfile()):
                    raise ArtifactInvalid(f"{artifact.path}: unsafe tar member {name}")
            info = entries.get(artifact.member)
            if info is None or not info.isfile():
                raise ArtifactInvalid(f"{artifact.path}: missing Winn member {artifact.member}")
            if info.size <= 0 or info.size > 512 * 1024 * 1024:
                raise ArtifactInvalid(f"{artifact.path}: Winn member size is invalid")
            extracted = package.extractfile(info)
            if extracted is None:
                raise ArtifactInvalid(f"{artifact.path}: Winn member cannot be read")
            payload = extracted.read(512 * 1024 * 1024 + 1)
            if len(payload) != info.size:
                raise ArtifactInvalid(f"{artifact.path}: Winn member changed while read")
            return payload
    except ArtifactInvalid:
        raise
    except (OSError, tarfile.TarError, EOFError, ValueError) as exc:
        raise ArtifactInvalid(f"{artifact.path}: invalid tar package: {exc}") from exc


def _artifact_payload(path: str, artifact: Artifact) -> bytes:
    if artifact.kind == "android-package":
        return _read_zip_member(path, artifact)
    if artifact.kind == "linux-package":
        return _read_tar_member(path, artifact)
    return _read_stable_file(path, artifact.path)


def _artifact_payload_bytes(blob: bytes, artifact: Artifact) -> bytes:
    if artifact.kind == "android-package":
        return _read_zip_member("", artifact, archive=blob)
    if artifact.kind == "linux-package":
        return _read_tar_member("", artifact, archive=blob)
    return blob


def _authenticated_target_contract(target: str) -> tuple[str, str, str, str]:
    match = re.fullmatch(
        r"datapath-(android|linux|windows)-(arm64|arm|amd64)", target
    )
    if match is not None:
        platform_name, arch = match.groups()
        if platform_name == "windows" and arch == "arm":
            raise ArtifactInvalid(f"unsupported authenticated producer target: {target}")
        return ("pe" if platform_name == "windows" else "elf", "core", arch, "")
    match = re.fullmatch(r"relay-windows-(arm64|amd64)", target)
    if match is not None:
        return "pe", "relay", match.group(1), ""
    archives = {
        "datapath-archive-darwin-arm64": ("arm64", "macosx"),
        "datapath-archive-darwin-amd64": ("x86_64", "macosx"),
        "datapath-ios-arm64": ("arm64", "iphoneos"),
        "datapath-iossimulator-arm64": ("arm64", "iphonesimulator"),
        "datapath-iossimulator-amd64": ("x86_64", "iphonesimulator"),
    }
    archive = archives.get(target)
    if archive is not None:
        return "apple-archive", "core", archive[0], archive[1]
    wrapper = target.removeprefix("apple-wrapper-")
    if wrapper != target and wrapper in MACHO_PLATFORMS:
        arches = "arm64" if wrapper == "iphoneos" else "arm64,x86_64"
        return "apple-wrapper", "core+relay", arches, wrapper
    raise ArtifactInvalid(f"unsupported authenticated producer target: {target}")


def _payload_format(artifact: Artifact) -> str:
    if artifact.kind in {"raw", "elf", "android-package", "linux-package"}:
        return "elf"
    return artifact.kind


def _validate_authenticated_role(
    blob: bytes,
    artifact: Artifact,
    receipt: Optional[object],
    *,
    allow_normalised_equivalent: bool,
    authoritative_source_closure: Optional[SourceClosure],
) -> None:
    if receipt is None:
        raise ArtifactInvalid(
            f"{artifact.path}: OWNER-BLOCKED role identity requires authenticated "
            "producer output or an owner-authorized producer receipt"
        )
    if isinstance(receipt, AuthenticatedPublicationHandoff):
        expected = _authenticated_target_contract(receipt.target)
        observed = (
            _payload_format(artifact), artifact.role, artifact.arch, artifact.platform
        )
        if (
            receipt.target != artifact.target
            or expected != observed
            or receipt.sha256 != hashlib.sha256(blob).hexdigest()
            or receipt.descriptor_identity[5] != len(blob)
        ):
            raise ArtifactInvalid(
                f"{artifact.path}: OWNER-BLOCKED authenticated producer handoff "
                "does not bind these bytes and exact role/target contract"
            )
        return
    raise ArtifactInvalid(
        f"{artifact.path}: OWNER-BLOCKED producer receipt is not externally "
        "authenticated; only an authenticated publication handoff is accepted "
        "and Windows producer receipts are retired"
    )

def _validate_binary(
    blob: bytes,
    artifact: Artifact,
    *,
    role_receipt: Optional[object] = None,
    allow_normalised_equivalent: bool = False,
    require_authenticated_role: bool = True,
    authoritative_source_closure: Optional[SourceClosure] = None,
) -> None:
    if artifact.kind in ("raw", "elf", "android-package", "linux-package"):
        _validate_elf(blob, artifact)
    elif artifact.kind == "pe":
        _validate_pe(blob, artifact)
    elif artifact.kind == "apple-wrapper":
        _validate_macho(blob, artifact)
    elif artifact.kind == "apple-archive":
        _validate_archive(blob, artifact)
    else:
        raise ArtifactInvalid(f"{artifact.path}: unsupported artifact kind {artifact.kind}")
    if require_authenticated_role:
        _validate_authenticated_role(
            blob,
            artifact,
            role_receipt,
            allow_normalised_equivalent=allow_normalised_equivalent,
            authoritative_source_closure=authoritative_source_closure,
        )


def _normalise_elf_build_id(blob: bytes) -> bytes:
    layout = _parse_elf(blob, "ELF normalization input")
    if layout.elf_class == 1:
        header_size = 52
        program_offset = struct.unpack_from("<I", blob, 28)[0]
        section_offset = struct.unpack_from("<I", blob, 32)[0]
        program_size, program_count = struct.unpack_from("<HH", blob, 42)
        section_size, section_count = struct.unpack_from("<HH", blob, 46)
    else:
        header_size = 64
        program_offset = struct.unpack_from("<Q", blob, 32)[0]
        section_offset = struct.unpack_from("<Q", blob, 40)[0]
        program_size, program_count = struct.unpack_from("<HH", blob, 54)
        section_size, section_count = struct.unpack_from("<HH", blob, 58)
    structural_ranges = [
        (0, header_size),
        (program_offset, program_offset + program_size * program_count),
    ]
    if section_count:
        structural_ranges.append(
            (section_offset, section_offset + section_size * section_count)
        )
    mutable_or_executable_files = [
        (offset, offset + size)
        for kind, flags, offset, size, _, _ in layout.segments
        if kind == 1 and flags & (0x1 | 0x2)
    ]
    mutable_or_executable_memory = [
        (address, address + memory)
        for kind, flags, _, _, address, memory in layout.segments
        if kind == 1 and flags & (0x1 | 0x2)
    ]
    found: list[tuple[int, int, int, int, int, int, int, int]] = []
    note_segments = [item for item in layout.segments if item[0] == 4]
    note_file_ranges = sorted(
        (offset, offset + size) for _, _, offset, size, _, _ in note_segments
    )
    if any(start == end for start, end in note_file_ranges):
        raise ArtifactInvalid("ELF PT_NOTE file range is empty")
    for (first_start, first_end), (second_start, second_end) in zip(
        note_file_ranges, note_file_ranges[1:]
    ):
        if second_start < first_end:
            raise ArtifactInvalid(
                "ELF PT_NOTE file ranges are empty or overlap normalization bytes"
            )
    for _, flags, segment_offset, segment_size, virtual_address, memory_size in note_segments:
        segment_end = segment_offset + segment_size
        if any(
            segment_offset < protected_end and protected_start < segment_end
            for protected_start, protected_end in structural_ranges
        ):
            raise ArtifactInvalid(
                "ELF Go build-ID PT_NOTE overlaps authenticated structural tables"
            )
        cursor = segment_offset
        while cursor < segment_end:
            if cursor + 12 > segment_end:
                raise ArtifactInvalid("ELF PT_NOTE header is truncated")
            name_size, description_size, note_type = struct.unpack_from("<III", blob, cursor)
            header_at = cursor
            cursor += 12
            name_end = cursor + name_size
            description_at = (name_end + 3) & ~3
            description_end = description_at + description_size
            record_end = (description_end + 3) & ~3
            if record_end > segment_end:
                raise ArtifactInvalid("ELF PT_NOTE record exceeds its segment")
            if blob[cursor:name_end] == b"Go\x00\x00" and note_type == 4:
                if flags & (0x1 | 0x2):
                    raise ArtifactInvalid("ELF Go build-ID PT_NOTE is writable or executable")
                if any(
                    segment_offset < end and start < segment_end
                    for start, end in mutable_or_executable_files
                ):
                    raise ArtifactInvalid(
                        "ELF Go build-ID PT_NOTE overlaps writable or executable file bytes"
                    )
                if any(
                    virtual_address < end and start < virtual_address + memory_size
                    for start, end in mutable_or_executable_memory
                ):
                    raise ArtifactInvalid(
                        "ELF Go build-ID PT_NOTE overlaps writable or executable memory"
                    )
                if virtual_address <= layout.entry < virtual_address + memory_size:
                    raise ArtifactInvalid("ELF entry point lies inside Go build-ID PT_NOTE")
                description = blob[description_at:description_end]
                if (
                    name_size != 4
                    or description_size == 0
                    or re.fullmatch(
                        rb"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)+", description
                    ) is None
                    or header_at != segment_offset
                    or record_end != segment_end
                ):
                    raise ArtifactInvalid(
                        "ELF Go build-ID PT_NOTE layout is not exact"
                    )
                found.append((
                    description_at, description_size, header_at, record_end,
                    segment_offset, segment_end, virtual_address, memory_size,
                ))
            cursor = record_end
    named_sections = [item for item in layout.sections if item[0] == ".note.go.buildid"]
    if len(named_sections) > 1:
        raise ArtifactInvalid("ELF has duplicate .note.go.buildid sections")
    if not found:
        if named_sections:
            raise ArtifactInvalid("ELF .note.go.buildid is not authenticated by PT_NOTE")
        return blob
    if len(found) != 1:
        raise ArtifactInvalid("ELF has duplicate Go build-ID notes")
    (
        description_at, description_size, record_at, record_end,
        segment_offset, segment_end, virtual_address, _,
    ) = found[0]
    if not named_sections:
        raise ArtifactInvalid("ELF Go build-ID PT_NOTE has no authenticated section")
    if named_sections:
        _, section_type, section_flags, section_address, section_offset, section_size = (
            named_sections[0]
        )
        if (
            section_type != 7
            or section_flags & 0x4
            or section_offset != segment_offset
            or section_offset + section_size != segment_end
            or section_offset != record_at
            or section_offset + section_size != record_end
            or (
                section_flags & 0x2
                and section_address != virtual_address + section_offset - segment_offset
            )
        ):
            raise ArtifactInvalid("ELF .note.go.buildid section conflicts with PT_NOTE")
        for other in layout.sections:
            if other is named_sections[0] or other == named_sections[0]:
                continue
            _, other_type, _, _, other_offset, other_size = other
            if (
                other_type != 8
                and other_size
                and section_offset < other_offset + other_size
                and other_offset < section_offset + section_size
            ):
                raise ArtifactInvalid(
                    "ELF Go build-ID section overlaps another authenticated section"
                )
    return (
        blob[:description_at]
        + b"_" * description_size
        + blob[description_at + description_size:]
    )


def _normalise_apple_archive(blob: bytes) -> bytes:
    members = _archive_members(blob)
    symbol_tables = [
        item for item in members if item.name in ("__.SYMDEF", "__.SYMDEF SORTED")
    ]
    go_objects = [item for item in members if item.name == "go.o"]
    if len(symbol_tables) != 1 or len(go_objects) != 1:
        raise ArtifactInvalid(
            "Go Apple archive normalization requires one symbol table and one go.o"
        )
    member_layouts = {
        item.header_offset: tuple(_macho_slices(item.payload))
        for item in members
        if item.name not in ("__.SYMDEF", "__.SYMDEF SORTED", "__.PKGDEF")
    }
    _validate_bsd_symbol_table(
        symbol_tables[0].payload, member_layouts, go_objects[0].header_offset
    )
    result = bytearray(blob)
    mtime_at = symbol_tables[0].header_offset + 16
    result[mtime_at:mtime_at + 12] = b" " * 12
    go_object = go_objects[0]
    return bytes(result)


def normalise(blob: bytes) -> bytes:
    """Normalize only authenticated format-specific linker metadata."""
    if blob.startswith(AR_MAGIC):
        return _normalise_apple_archive(blob)
    if blob.startswith(b"\x7fELF"):
        return _normalise_elf_build_id(blob)
    return blob


def fingerprint(path: str) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha256(normalise(handle.read())).hexdigest()


def raw_digest(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


class CustodyUnavailable(RuntimeError):
    """The exact reviewed Go runtime cannot be authenticated."""


def _duplicate_keys_refused(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CustodyUnavailable(f"duplicate toolchain pin key: {key}")
        result[key] = value
    return result


def _regular_file(path: str, label: str) -> os.stat_result:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise CustodyUnavailable(f"{label} is unavailable: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise CustodyUnavailable(f"{label} must be a regular non-symlink file")
    if info.st_nlink != 1 or info.st_uid not in {0, os.getuid()}:
        raise CustodyUnavailable(
            f"{label} must be release-owner-controlled and non-hardlinked")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise CustodyUnavailable(f"{label} must not be group/world writable")
    return info


def _reviewed_tree_hash(
    root: str,
    custody: Optional[DescriptorCustody] = None,
) -> str:
    """Hash the complete Go tree using the release-custody canonical format."""
    if not os.path.isabs(root) or (custody is None and os.path.islink(root)):
        raise CustodyUnavailable("reviewed Go root must be an absolute non-symlink directory")
    try:
        if custody is None:
            root = os.path.realpath(root)
            root_info = os.lstat(root)
        else:
            root = custody._canonical(root)
            root_node = custody._nodes.get(root)
            if root_node is None or not root_node.is_directory:
                raise CustodyUnavailable(
                    "reviewed Go root is not retained by descriptor custody"
                )
            root_info = os.fstat(root_node.fd)
    except OSError as exc:
        raise CustodyUnavailable(f"reviewed Go root is unavailable: {exc}") from exc
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid not in {0, os.getuid()}
    ):
        raise CustodyUnavailable("reviewed Go root must be release-owner-controlled")
    if stat.S_IMODE(root_info.st_mode) & 0o022:
        raise CustodyUnavailable("reviewed Go root must not be group/world writable")

    digest = hashlib.sha256()

    def feed(*parts: object) -> None:
        for part in parts:
            value = str(part).encode("utf-8", "surrogateescape")
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)

    def walk(directory: str) -> None:
        scan_target: object = directory
        if custody is not None:
            directory_node = custody._nodes.get(custody._canonical(directory))
            if directory_node is None or not directory_node.is_directory:
                raise CustodyUnavailable(
                    f"reviewed Go directory escaped retained custody: {directory}"
                )
            scan_target = directory_node.fd
        with os.scandir(scan_target) as scan:
            entries = sorted(scan, key=lambda item: os.fsencode(item.name))
        for entry in entries:
            path = os.path.join(directory, entry.name)
            relative = os.path.relpath(path, root).replace(os.sep, "/")
            if custody is None:
                info = entry.stat(follow_symlinks=False)
            else:
                retained = custody._nodes.get(custody._canonical(path))
                if retained is None:
                    raise CustodyUnavailable(
                        f"reviewed Go entry escaped retained custody: {relative}"
                    )
                info = os.fstat(retained.fd)
            mode = stat.S_IMODE(info.st_mode)
            if info.st_uid != root_info.st_uid:
                raise CustodyUnavailable(
                    f"unsafe reviewed Go tree ownership: {relative}")
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                try:
                    resolved = os.path.realpath(path)
                    common = os.path.commonpath((root, resolved))
                    resolved_info = os.stat(resolved)
                except (OSError, ValueError) as exc:
                    raise CustodyUnavailable(
                        f"unsafe reviewed Go symlink: {relative}") from exc
                if (
                    common != root
                    or not stat.S_ISREG(resolved_info.st_mode)
                    or resolved_info.st_uid != root_info.st_uid
                    or stat.S_IMODE(resolved_info.st_mode) & 0o022
                ):
                    raise CustodyUnavailable(
                        f"unsafe reviewed Go symlink target: {relative}")
                feed("L", relative, target)
            elif mode & 0o022:
                raise CustodyUnavailable(
                    f"unsafe reviewed Go tree mode: {relative}")
            elif stat.S_ISDIR(info.st_mode):
                feed("D", relative, 0o500)
                walk(path)
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    raise CustodyUnavailable(
                        f"hardlinked reviewed Go file rejected: {relative}")
                canonical_mode = 0o500 if mode & 0o111 else 0o400
                content_digest = (
                    raw_digest(path)
                    if custody is None
                    else hashlib.sha256(custody.read_file(path)).hexdigest()
                )
                feed("F", relative, canonical_mode, info.st_size, content_digest)
            else:
                raise CustodyUnavailable(
                    f"unsupported reviewed Go tree entry: {relative}")

    walk(root)
    if custody is not None:
        custody.verify()
    return digest.hexdigest()


@dataclass(frozen=True)
class PlatformToolchainCustody:
    custody: DescriptorCustody = field(compare=False, repr=False)
    environment: dict[str, str]


def _toolchain_pins() -> dict[str, object]:
    """Return the `tools` object of tools/toolchain-pins.json, read by descriptor."""
    try:
        with DescriptorCustody(
            "toolchain pin manifest", CustodyUnavailable
        ) as pin_custody:
            pin_custody.bind_file(PIN_MANIFEST, 1024 * 1024, require_owner=True)
            payload = pin_custody.read_file(PIN_MANIFEST, 1024 * 1024)
            pin_custody.verify()
        document = json.loads(
            payload.decode("utf-8"), object_pairs_hook=_duplicate_keys_refused
        )
        tools = document["tools"]
    except (KeyError, TypeError, ValueError) as exc:
        raise CustodyUnavailable(f"invalid toolchain pin manifest: {exc}") from exc
    if not isinstance(tools, dict):
        raise CustodyUnavailable("toolchain pin manifest has no tools object")
    return tools


def _toolchain_host_key() -> str:
    """The pin key for this host, the same one the Go install-tree pin uses."""
    host_os = {"darwin": "darwin", "linux": "linux"}.get(sys.platform)
    host_arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64"}.get(
        platform.machine().lower())
    if host_os is None or host_arch is None:
        raise CustodyUnavailable("this host has no toolchain platform pin")
    return f"{host_os}_{host_arch}"


def _platform_tree_digest(root: str) -> str:
    """Digest an installed toolchain tree exactly as `winn_release.py digest --kind platform`.

    The member lines are those of tools/winn_release.py platform_tree_digest
    (the winn_conformance_verify._external_platform_tree_sha256 encoding):
    "dir <st_mode> <st_uid> <path>", "symlink <target> <path>" and
    "file <size> <sha256> <path>", sorted and hashed. Links that escape the
    root and foreign or group/world-writable members are refused. This is not
    the _reviewed_tree_hash encoding the Go install-tree pin uses.
    """
    root_text = os.path.abspath(root)
    if os.path.islink(root_text) or not os.path.isdir(root_text):
        raise CustodyUnavailable(f"toolchain root is not a directory: {root}")
    root_real = os.path.realpath(root_text)
    owners = {0, os.getuid()}
    members: list[str] = []

    def walk_error(exc: OSError) -> None:
        raise exc

    def file_digest(path: str) -> str:
        digest = hashlib.sha256()
        fd = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            while True:
                block = os.read(fd, 1024 * 1024)
                if not block:
                    break
                digest.update(block)
        finally:
            os.close(fd)
        return digest.hexdigest()

    try:
        for dirpath, dirnames, filenames in os.walk(
            root_text, onerror=walk_error, followlinks=False
        ):
            dinfo = os.lstat(dirpath)
            if dinfo.st_uid not in owners or dinfo.st_mode & 0o022:
                raise CustodyUnavailable(
                    f"toolchain directory is writable by others or foreign: {dirpath}")
            relative_dir = os.path.relpath(dirpath, root_text).replace(os.sep, "/")
            members.append(f"dir {dinfo.st_mode} {dinfo.st_uid} {relative_dir}\n")
            dirnames.sort()
            for name in list(dirnames):
                path = os.path.join(dirpath, name)
                if os.path.islink(path):
                    if os.path.commonpath((root_real, os.path.realpath(path))) != root_real:
                        raise CustodyUnavailable(
                            f"toolchain directory link escapes its root: {path}")
                    relative = os.path.relpath(path, root_text).replace(os.sep, "/")
                    members.append(f"symlink {os.readlink(path)} {relative}\n")
                    dirnames.remove(name)
            for name in sorted(filenames):
                path = os.path.join(dirpath, name)
                finfo = os.lstat(path)
                relative = os.path.relpath(path, root_text).replace(os.sep, "/")
                if stat.S_ISLNK(finfo.st_mode):
                    if os.path.commonpath((root_real, os.path.realpath(path))) != root_real:
                        raise CustodyUnavailable(
                            f"toolchain file link escapes its root: {path}")
                    members.append(f"symlink {os.readlink(path)} {relative}\n")
                    continue
                if not stat.S_ISREG(finfo.st_mode):
                    raise CustodyUnavailable(f"toolchain holds a special file: {path}")
                if finfo.st_uid not in owners or finfo.st_mode & 0o022:
                    raise CustodyUnavailable(
                        f"toolchain file is writable by others or foreign: {path}")
                members.append(f"file {finfo.st_size} {file_digest(path)} {relative}\n")
    except (OSError, ValueError) as exc:
        raise CustodyUnavailable(f"toolchain tree is unreadable: {exc}") from exc
    members.sort()
    return hashlib.sha256("".join(members).encode("utf-8")).hexdigest()


def _apple_tool_output(argv: list[str], developer_dir: Optional[str]) -> str:
    """Run one Apple identity tool with a clean environment; return its stdout.

    The only subprocess call the Apple toolchain binding makes (tests stub
    it). The child sees PATH=/usr/bin:/bin:/usr/sbin:/sbin and, when given,
    DEVELOPER_DIR, nothing else.
    """
    environment = {"PATH": SYSTEM_PATH}
    if developer_dir is not None:
        environment["DEVELOPER_DIR"] = developer_dir
    try:
        completed = subprocess.run(
            argv,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=APPLE_TOOL_TIMEOUT_SECONDS,
            close_fds=True,
        )
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise CustodyUnavailable(
            f"{os.path.basename(argv[0])} could not run: {exc}") from exc
    if completed.returncode != 0:
        raise CustodyUnavailable(
            f"{' '.join(argv)} failed ({completed.returncode}): "
            f"{(completed.stderr or '').strip()[:500]}"
        )
    return completed.stdout or ""


def _bind_apple_toolchain_custody(platform_name: str) -> PlatformToolchainCustody:
    """Bind the pinned Xcode, its clang and the platform SDK.

    tools/toolchain-pins.json is the only authority, checked the way
    `winn_release.py prepare_xcode` checks it: `xcodebuild -version` in the
    developer directory (WINS_FRESHNESS_DEVELOPER_DIR, else `xcode-select -p`)
    must report exactly tools.xcode.version and tools.xcode.build. The SDK
    (`xcrun --sdk <platform> --show-sdk-path`) and clang (`xcrun -f clang`)
    must resolve inside that directory. No /Library authority file, root
    ownership or read-only seal is required. clang and the SDK's
    SDKSettings.json stay retained by descriptor, so a change during the build
    fails custody.verify().
    """
    if sys.platform != "darwin":
        raise CustodyUnavailable(
            "Apple freshness requires a Darwin host with the pinned Xcode"
        )
    if platform_name not in MACHO_PLATFORMS:
        raise CustodyUnavailable(f"unsupported Apple platform {platform_name}")
    xcode = _toolchain_pins().get("xcode")
    version = xcode.get("version") if isinstance(xcode, dict) else None
    build = xcode.get("build") if isinstance(xcode, dict) else None
    if (
        type(version) is not str
        or type(build) is not str
        or not version
        or not build
    ):
        raise CustodyUnavailable("toolchain pins do not name the Xcode version and build")
    developer_text = os.environ.get(APPLE_DEVELOPER_DIR_ENV, "").strip()
    if developer_text:
        if not os.path.isabs(developer_text):
            raise CustodyUnavailable(
                f"{APPLE_DEVELOPER_DIR_ENV} must name an absolute Xcode developer directory"
            )
    else:
        developer_text = _apple_tool_output(["/usr/bin/xcode-select", "-p"], None).strip()
        if not os.path.isabs(developer_text):
            raise CustodyUnavailable(
                "xcode-select did not name an absolute Xcode developer directory"
            )
    developer_dir = os.path.realpath(developer_text)
    xcodebuild = os.path.join(developer_dir, "usr", "bin", "xcodebuild")
    if not os.path.isfile(xcodebuild):
        raise CustodyUnavailable(f"no xcodebuild in the Xcode developer directory {developer_dir}")
    lines = _apple_tool_output([xcodebuild, "-version"], developer_dir).split("\n")
    reported_version = lines[0].removeprefix("Xcode ").strip()
    reported_build = (
        lines[1].removeprefix("Build version ").strip() if len(lines) > 1 else ""
    )
    if (reported_version, reported_build) != (version, build):
        raise CustodyUnavailable(
            f"Xcode {reported_version} ({reported_build}) at {developer_dir} is not "
            f"the pinned {version} ({build})"
        )
    sdk_text = _apple_tool_output(
        ["/usr/bin/xcrun", "--sdk", platform_name, "--show-sdk-path"], developer_dir
    ).strip()
    clang_text = _apple_tool_output(["/usr/bin/xcrun", "-f", "clang"], developer_dir).strip()
    resolved: dict[str, str] = {}
    for label, text in (("SDK", sdk_text), ("clang", clang_text)):
        if not os.path.isabs(text):
            raise CustodyUnavailable(f"xcrun did not name an absolute Apple {label} path")
        path = os.path.realpath(text)
        if path == developer_dir or os.path.commonpath((developer_dir, path)) != developer_dir:
            raise CustodyUnavailable(
                f"Apple {label} resolves outside the pinned developer directory: {path}"
            )
        resolved[label] = path
    sdk_path = resolved["SDK"]
    clang_path = resolved["clang"]
    custody = DescriptorCustody("pinned Apple toolchain custody", CustodyUnavailable)
    try:
        custody.bind_directory(developer_dir)
        custody.bind_file(clang_path, 512 * 1024 * 1024)
        custody.bind_directory(sdk_path)
        custody.bind_file(os.path.join(sdk_path, "SDKSettings.json"), 16 * 1024 * 1024)
        custody.verify()
        return PlatformToolchainCustody(
            custody,
            {
                "DEVELOPER_DIR": developer_dir,
                "SDKROOT": sdk_path,
                "CC": clang_path,
                "CXX": clang_path + "++",
                "WINS_APPLE_DEVELOPER_DIR": developer_dir,
            },
        )
    except Exception:
        custody.close()
        raise


def _bind_android_toolchain_custody(target: str) -> PlatformToolchainCustody:
    """Bind the pinned Android NDK and the target's API 24 clang.

    tools/toolchain-pins.json is the only authority, checked the way
    `winn_release.py prepare_ndk` checks it: the root (WINS_FRESHNESS_NDK_ROOT,
    else ~/.local/android-sdk/ndk/<pinned version>) must carry
    `Pkg.Revision = <tools.android_ndk.version>` and its
    `winn_release.py digest --kind platform` tree digest must equal
    tools.android_ndk.install_tree_sha256 for this host. No /Library authority
    file, root ownership or immutable flag is required. source.properties and
    the compiler stay retained by descriptor, so a change during the build
    fails custody.verify().
    """
    arch = target.removeprefix("datapath-android-")
    triples = {
        "arm64": "aarch64-linux-android",
        "arm": "armv7a-linux-androideabi",
        "amd64": "x86_64-linux-android",
    }
    if arch not in triples:
        raise CustodyUnavailable(f"unsupported Android freshness target {target}")
    host_tag = {
        ("darwin", "arm64"): "darwin-x86_64",
        ("darwin", "x86_64"): "darwin-x86_64",
        ("linux", "x86_64"): "linux-x86_64",
    }.get((sys.platform, platform.machine().lower()))
    if host_tag is None:
        raise CustodyUnavailable("the Android NDK has no prebuilt toolchain for this host")
    ndk = _toolchain_pins().get("android_ndk")
    version = ndk.get("version") if isinstance(ndk, dict) else None
    if type(version) is not str or re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", version) is None:
        raise CustodyUnavailable("toolchain pins do not name an exact Android NDK version")
    host_key = _toolchain_host_key()
    try:
        tree_pin = ndk["install_tree_sha256"][host_key]  # type: ignore[index]
    except (KeyError, TypeError) as exc:
        raise CustodyUnavailable(
            f"toolchain pins have no Android NDK tree digest for {host_key}") from exc
    if type(tree_pin) is not str or re.fullmatch(r"[0-9a-f]{64}", tree_pin) is None:
        raise CustodyUnavailable("Android NDK tree digest pin is invalid")
    root_text = os.environ.get(ANDROID_NDK_ROOT_ENV, "").strip()
    if not root_text:
        root_text = os.path.join(
            os.path.expanduser("~"), ".local", "android-sdk", "ndk", version
        )
    if not os.path.isabs(root_text):
        raise CustodyUnavailable(
            f"{ANDROID_NDK_ROOT_ENV} must name the absolute root of the pinned "
            f"Android NDK {version}"
        )
    ndk_root = os.path.realpath(root_text)
    properties = os.path.join(ndk_root, "source.properties")
    compiler = os.path.join(
        ndk_root, "toolchains", "llvm", "prebuilt", host_tag, "bin",
        f"{triples[arch]}24-clang",
    )
    custody = DescriptorCustody("pinned Android NDK custody", CustodyUnavailable)
    try:
        custody.bind_directory(ndk_root)
        custody.bind_file(properties, 1024 * 1024)
        try:
            text = custody.read_file(properties, 1024 * 1024).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CustodyUnavailable("Android NDK source.properties is not UTF-8") from exc
        revision = None
        for line in text.splitlines():
            match = re.fullmatch(r"\s*Pkg\.Revision\s*=\s*(\S+)\s*", line)
            if match:
                revision = match.group(1)
        if revision != version:
            raise CustodyUnavailable(
                f"Android NDK at {ndk_root} is {revision}, not the pinned {version}"
            )
        custody.bind_file(compiler, 512 * 1024 * 1024)
        measured = _platform_tree_digest(ndk_root)
        if measured != tree_pin:
            raise CustodyUnavailable(
                f"Android NDK tree digest {measured} is not the pinned {tree_pin}"
            )
        custody.verify()
        return PlatformToolchainCustody(
            custody,
            {
                "ANDROID_NDK_HOME": ndk_root,
                "ANDROID_NDK_ROOT": ndk_root,
                "WINS_ANDROID_NDK_ROOT": ndk_root,
            },
        )
    except Exception:
        custody.close()
        raise


def _private_directory(path: str) -> None:
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        info = os.lstat(path)
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
        ):
            raise CustodyUnavailable(f"private custody path is unsafe: {path}")
        # Only a mode change is written: a chmod of an already-private
        # directory still raises a vnode attribute event on every custody
        # that retains it as an ancestor.
        if stat.S_IMODE(info.st_mode) != 0o700:
            os.chmod(path, 0o700)


def _discard_private_tree(path: str) -> None:
    if not path:
        return
    try:
        for directory, dirs, _ in os.walk(path):
            os.chmod(directory, 0o700)
            dirs[:] = [name for name in dirs if not os.path.islink(os.path.join(directory, name))]
    except OSError:
        pass
    shutil.rmtree(path, ignore_errors=True)


def _retain_reviewed_go_tree(
    source: str,
    expected_tree_sha256: str,
    expected_binary_sha256: str,
) -> tuple[str, str, str, DescriptorCustody]:
    """Copy the pinned Go tree into a private read-only directory.

    Go only ever runs from this copy. Descriptor custody holds the copy's root
    and bin/go; the whole tree is re-measured against the pinned install-tree
    digest after every run (ReviewedGo.verify_unchanged). Binding every member
    by descriptor is not possible here: the official Go archive ships empty
    files, which DescriptorCustody refuses to bind.
    """
    custody_root = tempfile.mkdtemp(prefix="winn-reviewed-go.")
    retained_root = os.path.join(custody_root, "go")
    custody: Optional[DescriptorCustody] = None
    try:
        shutil.copytree(source, retained_root, symlinks=True)
        for directory, dirs, files in os.walk(retained_root, topdown=False):
            for name in files:
                path = os.path.join(directory, name)
                info = os.lstat(path)
                if stat.S_ISLNK(info.st_mode):
                    continue
                os.chmod(path, 0o500 if stat.S_IMODE(info.st_mode) & 0o111 else 0o400)
            for name in dirs:
                path = os.path.join(directory, name)
                if not os.path.islink(path):
                    os.chmod(path, 0o500)
        os.chmod(retained_root, 0o500)
        retained_binary = os.path.join(retained_root, "bin", "go")
        custody = DescriptorCustody("retained reviewed Go tree", CustodyUnavailable)
        custody.bind_directory(retained_root)
        custody.bind_file(
            retained_binary,
            512 * 1024 * 1024,
            require_owner=True,
            require_readonly=True,
        )
        if (
            hashlib.sha256(custody.read_file(retained_binary)).hexdigest()
            != expected_binary_sha256
        ):
            raise CustodyUnavailable(
                "retained Go executable differs from the pinned executable"
            )
        if _reviewed_tree_hash(retained_root) != expected_tree_sha256:
            raise CustodyUnavailable(
                "retained Go tree differs from the pinned install tree"
            )
        custody.verify()
        return custody_root, retained_root, retained_binary, custody
    except Exception:
        if custody is not None:
            custody.close()
        _discard_private_tree(custody_root)
        raise


def _run_pinned_go(
    executable: str,
    arguments: list[str],
    *,
    cwd: str,
    environment: Mapping[str, str],
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    """Run the retained copy of the pinned Go by path.

    The caller checked the copy's bin/go and install-tree digests against
    tools/toolchain-pins.json and re-checks both after the run. The copy sits
    in a private 0700 directory with read-only members; no root-owned or
    immutable path is required. The child gets its own session and the
    session is killed when the call returns, so no Go helper outlives it.
    """
    argv = [executable, *arguments]
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
            text=True,
        )
    except OSError as exc:
        raise CustodyUnavailable(f"pinned Go could not start: {exc}") from exc
    try:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise CustodyUnavailable(
                f"pinned Go {' '.join(arguments[:2])} exceeded {timeout:g} seconds"
            ) from exc
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        if process.returncode is None:
            process.kill()
            process.communicate()
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


@dataclass(frozen=True)
class ReviewedGo:
    root: str
    binary: str
    retained_root: str
    retained_binary: str
    custody_root: str
    version: str
    binary_sha256: str
    tree_sha256: str
    archive_sha256: str
    identity: str
    gomodcache: str
    tree_custody: DescriptorCustody = field(compare=False, repr=False)
    module_custody: DescriptorCustody = field(compare=False, repr=False)
    gomodcache_tree_sha256: str = ""

    def build_environment(self, custody_root: str) -> dict[str, str]:
        home = os.path.join(custody_root, ".freshness-home")
        gopath = os.path.join(custody_root, ".freshness-gopath")
        build_cache = os.path.join(custody_root, ".freshness-gocache")
        temporary = os.path.join(custody_root, ".freshness-tmp")
        for path in (home, gopath, build_cache, temporary):
            _private_directory(path)
        environment = {
            "HOME": home,
            "PATH": SYSTEM_PATH,
            "GOROOT": self.retained_root,
            "GOPATH": gopath,
            "GOMODCACHE": self.gomodcache,
            "GOCACHE": build_cache,
            "TMPDIR": temporary,
            "GOENV": "off",
            "GOTOOLCHAIN": "local",
            "GOPROXY": "off",
            "GOSUMDB": "off",
            "GOFLAGS": "-mod=readonly",
            "GOWORK": "off",
            "WINS_STORE_GOMODCACHE": self.gomodcache,
            "WINS_STORE_GOMODCACHE_TREE_SHA256": self.gomodcache_tree_sha256,
        }
        return environment

    def run(
        self,
        arguments: list[str],
        *,
        cwd: str,
        environment: dict[str, str],
        timeout: int = 120,
    ) -> subprocess.CompletedProcess[str]:
        self.tree_custody.verify()
        if (
            hashlib.sha256(self.tree_custody.read_file(self.retained_binary)).hexdigest()
            != self.binary_sha256
        ):
            raise CustodyUnavailable("reviewed Go executable changed before it ran")
        completed = _run_pinned_go(
            self.retained_binary,
            arguments,
            cwd=cwd,
            environment=environment,
            timeout=timeout,
        )
        self.verify_unchanged()
        return completed

    def verify_unchanged(self) -> None:
        self.tree_custody.verify()
        self.module_custody.verify()
        if hashlib.sha256(self.tree_custody.read_file(self.retained_binary)).hexdigest() != self.binary_sha256:
            raise CustodyUnavailable(
                "reviewed Go executable changed during freshness verification")
        if _reviewed_tree_hash(self.retained_root) != self.tree_sha256:
            raise CustodyUnavailable(
                "reviewed Go install tree changed during freshness verification")
        if raw_digest(self.binary) != self.binary_sha256:
            raise CustodyUnavailable(
                "reviewed Go external executable changed during freshness verification"
            )
        if _reviewed_tree_hash(self.root) != self.tree_sha256:
            raise CustodyUnavailable(
                "reviewed Go external install tree changed during freshness verification"
            )

    def verify_module_cache_unchanged(self) -> None:
        """Re-measure the sealed module cache against the digest it was bound with."""
        self.module_custody.verify()
        try:
            measured = _sealed_tree_digest(self.gomodcache)
        except OSError as exc:
            raise CustodyUnavailable(
                f"sealed Go module cache became unreadable: {exc}"
            ) from exc
        if measured != self.gomodcache_tree_sha256:
            raise CustodyUnavailable(
                "sealed Go module cache changed during freshness verification"
            )

    def close(self) -> None:
        self.tree_custody.close()
        self.module_custody.close()
        _discard_private_tree(self.custody_root)


def _authenticate_sealed_module_cache() -> tuple[str, str, DescriptorCustody]:
    """Bind the sealed Go module cache named by the caller, by content digest.

    WINS_STORE_GOMODCACHE names the cache and WINS_STORE_GOMODCACHE_TREE_SHA256
    its digest, in the `winn_release.py digest --kind sealed` encoding the
    sealed builder re-measures. The cache must belong to this user and hold
    only non-writable, regular, single-link files. With GOPROXY=off and
    -mod=readonly nothing outside it is fetched, and `go mod verify` checks
    every module it supplies against the go.sum in the bound source closure,
    so go.sum is the per-module pin and this digest pins the whole cache.
    """
    cache_text = os.environ.get(SEALED_GOMODCACHE_ENV, "").strip()
    expected = os.environ.get(SEALED_GOMODCACHE_TREE_ENV, "").strip()
    if not cache_text or not os.path.isabs(cache_text):
        raise CustodyUnavailable(
            f"{SEALED_GOMODCACHE_ENV} must name the absolute sealed Go module cache"
        )
    if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise CustodyUnavailable(
            f"{SEALED_GOMODCACHE_TREE_ENV} must be the cache's 64-hex sealed digest"
        )
    cache = os.path.realpath(cache_text)
    try:
        measured = _sealed_tree_digest(cache)
    except OSError as exc:
        raise CustodyUnavailable(f"sealed Go module cache is unreadable: {exc}") from exc
    if measured != expected:
        raise CustodyUnavailable(
            f"sealed Go module cache digest {measured} does not match "
            f"{SEALED_GOMODCACHE_TREE_ENV} {expected}"
        )
    custody = DescriptorCustody("sealed Go module cache", CustodyUnavailable)
    try:
        custody.bind_directory(cache)
        custody.watch_directory_contents(cache)
        if _sealed_tree_digest(cache) != expected:
            raise CustodyUnavailable(
                "sealed Go module cache changed while it was being bound"
            )
        custody.verify()
        return cache, expected, custody
    except Exception:
        custody.close()
        raise


def _go_executable_pin(go: object) -> str:
    if not isinstance(go, dict):
        raise CustodyUnavailable("toolchain pins have no Go entry")
    host = _toolchain_host_key()
    executable_pins = go.get("executable_sha256_by_platform", {})
    if not isinstance(executable_pins, dict):
        raise CustodyUnavailable("Go executable_sha256_by_platform must be an object")
    value = executable_pins.get(host)
    if host == "darwin_arm64" and host not in executable_pins:
        value = go.get("executable_sha256")
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise CustodyUnavailable(f"Go executable digest pin is missing or invalid for {host}")
    return value


def authenticate_reviewed_go() -> ReviewedGo:
    """Authenticate the pinned Go named by WINS_FRESHNESS_GO_ROOT.

    tools/toolchain-pins.json is the only authority: bin/go must hash to
    tools.go.executable_sha256_by_platform[<host>] (tools.go.executable_sha256
    on darwin_arm64 without its own entry), the install tree must hash to
    tools.go.install_tree_sha256[<host>] (the release_go_archive_custody
    tree_hash encoding that `winn_release.py digest --kind go-tree` prints),
    and `go version` must print exactly "go version go<pin> <host>". The
    sealed module cache is bound by its digest. Go then runs only from a
    private read-only copy that is re-measured after every run.
    """
    try:
        with DescriptorCustody(
            "Go toolchain pin manifest", CustodyUnavailable
        ) as pin_custody:
            pin_custody.bind_file(
                PIN_MANIFEST,
                1024 * 1024,
                require_owner=True,
            )
            pin_payload = pin_custody.read_file(PIN_MANIFEST, 1024 * 1024)
            pin_custody.verify()
        pins = json.loads(
            pin_payload.decode("utf-8"),
            object_pairs_hook=_duplicate_keys_refused,
        )
        go = pins["tools"]["go"]
        version = go["version"]
        executable_relative = go["executable"]
        expected_binary = _go_executable_pin(go)
    except (CustodyUnavailable, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        if isinstance(exc, CustodyUnavailable):
            raise
        raise CustodyUnavailable(f"invalid reviewed Go pin manifest: {exc}") from exc

    if not isinstance(version, str) or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None:
        raise CustodyUnavailable("reviewed Go version pin must be exact")
    if executable_relative != "bin/go":
        raise CustodyUnavailable("reviewed Go executable pin must remain bin/go")
    if not isinstance(expected_binary, str) or re.fullmatch(r"[0-9a-f]{64}", expected_binary) is None:
        raise CustodyUnavailable("reviewed Go executable digest pin is invalid")

    host_os = {"darwin": "darwin", "linux": "linux"}.get(sys.platform)
    host_arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64"}.get(
        platform.machine().lower())
    if host_os is None or host_arch is None:
        raise CustodyUnavailable("this host has no reviewed Go freshness platform pin")
    host_key = f"{host_os}_{host_arch}"
    try:
        tree_sha = go["install_tree_sha256"][host_key]
        archive_sha = go["archive_sha256"][host_key]
    except (KeyError, TypeError) as exc:
        raise CustodyUnavailable(
            f"reviewed Go tree/archive pins are unavailable for {host_key}") from exc
    for label, value in (("tree", tree_sha), ("archive", archive_sha)):
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise CustodyUnavailable(f"reviewed Go {label} digest pin is invalid")

    root_text = os.environ.get(REVIEWED_GO_ROOT_ENV, "").strip()
    if not root_text or not os.path.isabs(root_text):
        raise CustodyUnavailable(
            f"{REVIEWED_GO_ROOT_ENV} must name the absolute root of the pinned "
            f"go{version} install (for example the go_root that "
            "`winn_release.py prepare-go` prints)"
        )
    root = os.path.normpath(root_text)
    binary = os.path.join(root, executable_relative)
    _regular_file(binary, "reviewed Go executable")
    if raw_digest(binary) != expected_binary:
        raise CustodyUnavailable(
            "reviewed Go executable does not match tools/toolchain-pins.json")
    measured_tree = _reviewed_tree_hash(root)
    if measured_tree != tree_sha:
        raise CustodyUnavailable(
            "reviewed Go install tree does not match tools/toolchain-pins.json")

    gomodcache, gomodcache_tree_sha256, module_custody = (
        _authenticate_sealed_module_cache()
    )
    custody_root = ""
    tree_custody: Optional[DescriptorCustody] = None
    try:
        custody_root, retained_root, retained_binary, tree_custody = (
            _retain_reviewed_go_tree(root, tree_sha, expected_binary)
        )
    except Exception:
        module_custody.close()
        raise
    assert tree_custody is not None

    def refuse(detail: str, cause: Optional[BaseException] = None) -> NoReturn:
        tree_custody.close()
        module_custody.close()
        _discard_private_tree(custody_root)
        raise CustodyUnavailable(detail) from cause

    identity = f"go version go{version} {host_os}/{host_arch}"
    identity_home = os.path.join(custody_root, ".identity-home")
    identity_gopath = os.path.join(custody_root, ".identity-gopath")
    identity_cache = os.path.join(custody_root, ".identity-cache")
    for path in (identity_home, identity_gopath, identity_cache):
        _private_directory(path)
    environment = {
        "HOME": identity_home,
        "PATH": SYSTEM_PATH,
        "GOROOT": retained_root,
        "GOPATH": identity_gopath,
        "GOMODCACHE": gomodcache,
        "GOCACHE": identity_cache,
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "GOFLAGS": "-mod=readonly",
        "GOWORK": "off",
        "GOENV": "off",
        "GOTOOLCHAIN": "local",
    }
    try:
        completed = _run_pinned_go(
            retained_binary,
            ["version"],
            cwd=retained_root,
            environment=environment,
            timeout=30,
        )
    except CustodyUnavailable as exc:
        refuse(f"reviewed Go executable could not run: {exc}", exc)
    observed = (completed.stdout or "").strip()
    if completed.returncode != 0 or observed != identity:
        refuse(f"reviewed Go identity mismatch: expected {identity}; got {observed!r}")
    try:
        tree_custody.verify()
        module_custody.verify()
        retained_digest = hashlib.sha256(
            tree_custody.read_file(retained_binary)
        ).hexdigest()
    except CustodyUnavailable as exc:
        refuse(str(exc), exc)
    if retained_digest != expected_binary:
        refuse("reviewed Go descriptor bytes changed during identity validation")
    return ReviewedGo(
        root=root,
        binary=binary,
        retained_root=retained_root,
        retained_binary=retained_binary,
        custody_root=custody_root,
        version=version,
        binary_sha256=expected_binary,
        tree_sha256=tree_sha,
        archive_sha256=archive_sha,
        identity=identity,
        gomodcache=gomodcache,
        tree_custody=tree_custody,
        module_custody=module_custody,
        gomodcache_tree_sha256=gomodcache_tree_sha256,
    )


def newest_source_mtime() -> tuple[float, str]:
    """Newest .go file in the module. Reported only, never the verdict."""
    newest, where = 0.0, ""
    for root, dirs, files in os.walk(MODULE_DIR):
        dirs[:] = [d for d in dirs if d not in ("vendor", ".git", "evidence")]
        for name in files:
            if not name.endswith(".go"):
                continue
            full = os.path.join(root, name)
            try:
                stamp = os.path.getmtime(full)
            except OSError:
                continue
            if stamp > newest:
                newest, where = stamp, os.path.relpath(full, REPO_ROOT)
    return newest, where


def stamp(seconds: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(seconds))


@dataclass
class RetainedReference:
    path: str
    custody: DescriptorCustody = field(repr=False)
    publication_handoff: Optional[AuthenticatedPublicationHandoff] = field(
        default=None,
        repr=False,
    )

    def read(self) -> bytes:
        payload = self.custody.read_file(self.path)
        self.custody.verify()
        return payload

    def verify(self) -> None:
        self.custody.verify()

    def close(self) -> None:
        self.custody.close()


WINN_BUILD_RECEIPT_CONTRACT = "winsvpn-winn-core-build-v4"
WINN_BUILD_RECEIPT_KEYS = {
    "archive_mode", "artifact", "contract", "go", "module_cache_tree_sha256",
    "package", "platform", "role", "source_tree_sha256", "target",
}


def _sealed_tree_digest(root: str) -> str:
    """Digest a sealed tree exactly as `winn_release.py digest --kind sealed`.

    The builder recomputes this over WINS_WINN_SOURCE_ROOT and
    WINS_STORE_GOMODCACHE and refuses a mismatch, so the value passed here is
    only ever a claim the producer must independently reproduce. The tree must
    be this user's, non-writable, and hold only regular non-hardlinked files.
    """
    info = os.lstat(root)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise CustodyUnavailable(f"sealed tree root is not a directory: {root}")
    members: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        directory = os.lstat(dirpath)
        if directory.st_uid != os.getuid() or directory.st_mode & 0o222:
            raise CustodyUnavailable(f"sealed tree directory is writable or foreign: {dirpath}")
        dirnames.sort()
        for name in dirnames:
            child = os.lstat(os.path.join(dirpath, name))
            if stat.S_ISLNK(child.st_mode) or not stat.S_ISDIR(child.st_mode):
                raise CustodyUnavailable(
                    f"sealed tree holds a non-directory link: {os.path.join(dirpath, name)}"
                )
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            member = os.lstat(path)
            if stat.S_ISLNK(member.st_mode) or not stat.S_ISREG(member.st_mode):
                raise CustodyUnavailable(f"sealed tree holds a non-regular file: {path}")
            if member.st_uid != os.getuid() or member.st_mode & 0o222 or member.st_nlink != 1:
                raise CustodyUnavailable(
                    f"sealed tree file is writable, foreign or hard-linked: {path}"
                )
            relative = os.path.relpath(path, root).replace(os.sep, "/")
            members.append(f"file {member.st_size} {raw_digest(path)} {relative}\n")
    members.sort()
    return hashlib.sha256("".join(members).encode("utf-8")).hexdigest()


def _pinned_winn_toolchain() -> dict[str, str]:
    """Go and NDK identities the v4 receipt must name, from the reviewed pins."""
    try:
        document = json.loads(
            _read_stable_file(PIN_MANIFEST, "toolchain pins", 1024 * 1024).decode("utf-8"),
            object_pairs_hook=_duplicate_keys_refused,
        )
    except (ArtifactInvalid, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise CustodyUnavailable(f"toolchain pins are unreadable: {exc}") from exc
    tools = document.get("tools") if isinstance(document, dict) else None
    go = tools.get("go") if isinstance(tools, dict) else None
    ndk = tools.get("android_ndk") if isinstance(tools, dict) else None
    pinned = {
        "go_version": go.get("version") if isinstance(go, dict) else None,
        "go_executable_sha256": _go_executable_pin(go),
        "android_ndk_version": ndk.get("version") if isinstance(ndk, dict) else None,
    }
    if any(type(value) is not str or not value for value in pinned.values()):
        raise CustodyUnavailable("toolchain pins do not name Go and the Android NDK")
    return pinned  # type: ignore[return-value]


def _receipt_object(
    value: object, expected: set[str], label: str
) -> dict[str, object]:
    if type(value) is not dict or set(value) != expected:
        raise CustodyUnavailable(
            f"OWNER-BLOCKED: authenticated producer {label} keys are not exact"
        )
    return value


def _receipt_sha(value: object, label: str, *, allow_null: bool = False) -> object:
    if allow_null and value is None:
        return None
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise CustodyUnavailable(
            f"OWNER-BLOCKED: authenticated producer {label} is not an exact SHA-256"
        )
    return value


def _receipt_target_identity(target: str) -> tuple[dict[str, object], str, bool, str]:
    specs = _target_specs(target)
    if len(specs) != 1:
        raise CustodyUnavailable(
            "OWNER-BLOCKED: producer target has no single exact source identity"
        )
    spec = specs[0]
    archive_mode = target.startswith("datapath-ios") or target.startswith(
        "datapath-archive-darwin-"
    )
    if target.startswith("datapath-"):
        role = "datapath"
    elif target.startswith("server-"):
        role = "control-plane-server"
    elif target.startswith("carrier-"):
        role = "v1-carrier-server"
    elif target.startswith("winn3-gateway-"):
        role = "winn3-gateway"
    else:
        raise CustodyUnavailable(
            f"OWNER-BLOCKED: producer role is not integrated for {target}"
        )
    identity = {
        "cgo_enabled": spec.cgo_enabled,
        "goarch": spec.goarch,
        "goos": spec.goos,
        "id": target,
    }
    return identity, role, archive_mode, spec.package


def _receipt_platform_identity(
    target: str,
    value: object,
    pinned: Mapping[str, str],
    platform_toolchain: Optional[PlatformToolchainCustody],
) -> dict[str, object]:
    platform = _receipt_object(
        value,
        {"compiler_path", "compiler_sha256", "id", "ndk_version", "sdk_version"},
        "platform",
    )
    _receipt_sha(platform["compiler_sha256"], "platform compiler_sha256", allow_null=True)
    compiler = platform["compiler_path"]
    if compiler is not None and (
        type(compiler) is not str
        or not os.path.isabs(compiler)
        or os.path.normpath(compiler) != compiler
        or any(character in compiler for character in ("\x00", "\r", "\n", "\t"))
    ):
        raise CustodyUnavailable(
            "OWNER-BLOCKED: authenticated producer platform compiler_path is invalid"
        )
    if target.startswith("datapath-android-"):
        expected_id = "android-api-24"
        root_name = "WINS_ANDROID_NDK_ROOT"
    elif target.startswith("datapath-ios") or target.startswith("datapath-archive-darwin-"):
        expected_id = (
            "ios-device" if target == "datapath-ios-arm64"
            else "ios-simulator" if target.startswith("datapath-iossimulator-")
            else "macos"
        )
        root_name = "WINS_APPLE_DEVELOPER_DIR"
    else:
        expected_id = _receipt_target_identity(target)[0]["goos"]
        root_name = ""
    if platform["id"] != expected_id:
        raise CustodyUnavailable(
            "OWNER-BLOCKED: authenticated producer platform identity is invalid"
        )
    if not root_name:
        if any(platform[field] is not None for field in platform if field != "id"):
            raise CustodyUnavailable(
                "OWNER-BLOCKED: reviewed-Go platform receipt contains unbound fields"
            )
        return platform
    if root_name == "WINS_ANDROID_NDK_ROOT":
        if platform["sdk_version"] is not None or platform["ndk_version"] != pinned["android_ndk_version"]:
            raise CustodyUnavailable(
                "OWNER-BLOCKED: Android platform receipt does not name the pinned NDK"
            )
    elif (
        platform["ndk_version"] is not None
        or type(platform["sdk_version"]) is not str
        or re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,3}", platform["sdk_version"]) is None
    ):
        raise CustodyUnavailable(
            "OWNER-BLOCKED: Apple platform receipt does not name an exact SDK version"
        )
    toolchain_root = (
        platform_toolchain.environment.get(root_name) if platform_toolchain is not None else None
    )
    if not toolchain_root or compiler is None or platform["compiler_sha256"] is None:
        raise CustodyUnavailable(
            "OWNER-BLOCKED: external platform receipt differs from the retained toolchain"
        )
    root = os.path.realpath(toolchain_root)
    if os.path.commonpath((root, compiler)) != root:
        raise CustodyUnavailable(
            "OWNER-BLOCKED: platform compiler is outside the retained toolchain"
        )
    if raw_digest(compiler) != platform["compiler_sha256"]:
        raise CustodyUnavailable(
            "OWNER-BLOCKED: platform compiler bytes differ from the receipt"
        )
    if platform_toolchain is not None:
        platform_toolchain.custody.verify()
    return platform


def _authenticated_producer_publication_handoff(
    stdout: str,
    target: str,
    output_path: str,
    *,
    source_custody: BoundSourceClosure,
    reviewed_go: ReviewedGo,
    platform_toolchain: Optional[PlatformToolchainCustody],
    reference_custody: DescriptorCustody,
    expected_source_tree_sha256: str,
    expected_module_cache_tree_sha256: str = "",
) -> AuthenticatedPublicationHandoff:
    """Bind one fresh builder output to its v4 receipt.

    Every receipt field is checked against something this process holds: the
    sealed source digest it passed, the sealed module-cache digest it passed,
    the reviewed Go and NDK pins, the retained platform toolchain, and the
    output bytes it binds. The receipt carries no authority of its own.
    """
    prefix = "WINN_BUILD_RECEIPT "
    records = [
        line[len(prefix):]
        for line in stdout.splitlines()
        if line.startswith(prefix)
    ]
    if len(records) != 1:
        raise CustodyUnavailable(
            "OWNER-BLOCKED: authenticated producer publication handoff is absent or "
            "ambiguous"
        )
    payload = records[0]
    try:
        payload_bytes = payload.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise CustodyUnavailable(
            "OWNER-BLOCKED: authenticated producer publication handoff is not ASCII"
        ) from exc
    if not payload or len(payload_bytes) > 8192:
        raise CustodyUnavailable(
            "OWNER-BLOCKED: authenticated producer publication handoff is unbounded"
        )
    try:
        record = json.loads(
            payload,
            object_pairs_hook=_duplicate_keys_refused,
            parse_constant=lambda value: (_ for _ in ()).throw(
                CustodyUnavailable(f"non-finite receipt value: {value}")
            ),
        )
    except (
        UnicodeError, json.JSONDecodeError, TypeError, ValueError, CustodyUnavailable
    ) as exc:
        raise CustodyUnavailable(
            "OWNER-BLOCKED: authenticated producer publication handoff is invalid JSON"
        ) from exc
    if (
        not isinstance(record, dict)
        or set(record) != WINN_BUILD_RECEIPT_KEYS
        or json.dumps(
            record, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ) != payload
    ):
        raise CustodyUnavailable(
            "OWNER-BLOCKED: authenticated producer publication handoff schema is not exact"
        )
    record = _receipt_object(record, WINN_BUILD_RECEIPT_KEYS, "receipt")
    artifact = _receipt_object(
        record["artifact"], {"header_sha256", "output_path", "sha256"}, "artifact"
    )
    go = _receipt_object(record["go"], {"executable_sha256", "version"}, "Go custody")
    target_record = _receipt_object(
        record["target"], {"cgo_enabled", "goarch", "goos", "id"}, "target"
    )
    for label, value in (
        ("artifact SHA", artifact["sha256"]),
        ("Go executable SHA", go["executable_sha256"]),
        ("module-cache SHA", record["module_cache_tree_sha256"]),
        ("source tree SHA", record["source_tree_sha256"]),
    ):
        _receipt_sha(value, label)
    _receipt_sha(artifact["header_sha256"], "artifact header SHA", allow_null=True)
    if (
        record["contract"] != WINN_BUILD_RECEIPT_CONTRACT
        or target_record["id"] != target
        or artifact["output_path"] != output_path
        or type(record["archive_mode"]) is not bool
        or type(target_record["cgo_enabled"]) is not bool
        or type(go["version"]) is not str
    ):
        raise CustodyUnavailable(
            "OWNER-BLOCKED: authenticated producer publication identity is invalid"
        )
    expected_target, expected_role, expected_archive, expected_package = (
        _receipt_target_identity(target)
    )
    # An archive build publishes OUTPUT minus .a plus .h beside the archive and
    # names its digest; nothing else may carry a header digest.
    header_sha256 = artifact["header_sha256"]
    if (header_sha256 is not None) is not expected_archive or (
        expected_archive and not output_path.endswith(".a")
    ):
        raise CustodyUnavailable(
            "OWNER-BLOCKED: producer receipt header does not match the archive contract"
        )
    pinned = _pinned_winn_toolchain()
    if (
        target_record != expected_target
        or record["role"] != expected_role
        or record["archive_mode"] is not expected_archive
        or record["package"] != expected_package
        or go["version"] != pinned["go_version"]
        or go["executable_sha256"] != pinned["go_executable_sha256"]
        or record["source_tree_sha256"] != expected_source_tree_sha256
        or (
            expected_module_cache_tree_sha256
            and record["module_cache_tree_sha256"] != expected_module_cache_tree_sha256
        )
    ):
        raise CustodyUnavailable(
            "OWNER-BLOCKED: producer receipt differs from the sealed inputs and pins"
        )
    if isinstance(reviewed_go, ReviewedGo) and (
        reviewed_go.version != go["version"]
        or reviewed_go.binary_sha256 != go["executable_sha256"]
    ):
        raise CustodyUnavailable(
            "OWNER-BLOCKED: producer receipt differs from retained Go custody"
        )
    _receipt_platform_identity(target, record["platform"], pinned, platform_toolchain)

    absolute = reference_custody._canonical(output_path)
    try:
        published = os.lstat(output_path)
    except OSError as exc:
        raise CustodyUnavailable(
            "OWNER-BLOCKED: producer did not publish the exact fresh exclusive output"
        ) from exc
    handoff = AuthenticatedPublicationHandoff(
        target,
        output_path,
        _file_identity(published),
        str(artifact["sha256"]),
    )
    claim = reference_custody.bind_atomic_publication(output_path, handoff)
    if claim.parent is None:
        raise CustodyUnavailable("OWNER-BLOCKED: producer output parent is absent")
    reference_custody.verify_created_file_path(absolute)
    current = os.fstat(claim.fd)
    parent = reference_custody._nodes[claim.parent]
    named = os.stat(claim.name, dir_fd=parent.fd, follow_symlinks=False)
    current_identity = _file_identity(current)
    if (
        not stat.S_ISREG(current.st_mode)
        or current.st_nlink != 1
        or current.st_size <= 0
        or current_identity != _file_identity(named)
        or current_identity != handoff.descriptor_identity
    ):
        raise CustodyUnavailable(
            "OWNER-BLOCKED: producer did not publish the exact fresh exclusive output"
        )
    digest = hashlib.sha256()
    offset = 0
    while offset < current.st_size:
        block = os.pread(claim.fd, min(1 << 20, current.st_size - offset), offset)
        if not block:
            raise CustodyUnavailable(
                "OWNER-BLOCKED: exclusive producer output ended before its recorded size"
            )
        digest.update(block)
        offset += len(block)
    if digest.hexdigest() != artifact["sha256"] or _file_identity(os.fstat(claim.fd)) != current_identity:
        raise CustodyUnavailable(
            "OWNER-BLOCKED: exclusive producer output bytes differ from its receipt"
        )
    receipt_bytes = reference_custody.read_file(output_path + ".receipt.json", 8193)
    if receipt_bytes != (payload + "\n").encode("ascii"):
        raise CustodyUnavailable(
            "OWNER-BLOCKED: terminal and retained producer receipts differ"
        )
    if header_sha256 is not None:
        header_bytes = reference_custody.read_file(
            output_path[: -len(".a")] + ".h", 1024 * 1024
        )
        if hashlib.sha256(header_bytes).hexdigest() != header_sha256:
            raise CustodyUnavailable(
                "OWNER-BLOCKED: archive header bytes differ from the producer receipt"
            )
    source_custody.verify()
    reviewed_go.verify_unchanged()
    if platform_toolchain is not None:
        platform_toolchain.custody.verify()
    reference_custody.verify_created_file_path(absolute)
    return AuthenticatedPublicationHandoff(
        target,
        output_path,
        current_identity,
        str(artifact["sha256"]),
    )


def _isolate_attempt_module_cache(
    reviewed_go: ReviewedGo,
    reference_root: str,
    custody: DescriptorCustody,
) -> str:
    """Copy the sealed cache into one hash-bound, read-only build attempt.

    The copy is measured with the sealed-tree digest the builder re-measures,
    before and after its root is bound. Members are not bound one by one: real
    module caches hold empty files, which DescriptorCustody refuses.
    """
    if not reviewed_go.gomodcache_tree_sha256:
        raise CustodyUnavailable(
            "sealed Go module-cache tree identity is unavailable"
        )
    destination = os.path.join(reference_root, ".gomodcache")
    shutil.copytree(reviewed_go.gomodcache, destination, symlinks=True)
    for directory, dirs, files in os.walk(destination, topdown=False):
        for name in files:
            path = os.path.join(directory, name)
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode):
                raise CustodyUnavailable(
                    "OWNER-BLOCKED: isolated module cache contains a symbolic link"
                )
            os.chmod(path, 0o400)
        for name in dirs:
            path = os.path.join(directory, name)
            if os.path.islink(path):
                raise CustodyUnavailable(
                    "OWNER-BLOCKED: isolated module cache contains a symbolic link"
                )
            os.chmod(path, 0o500)
    os.chmod(destination, 0o500)
    if _sealed_tree_digest(destination) != reviewed_go.gomodcache_tree_sha256:
        raise CustodyUnavailable(
            "isolated Go module cache differs from the sealed module-cache digest"
        )
    custody.bind_directory(destination)
    custody.watch_directory_contents(destination)
    if _sealed_tree_digest(destination) != reviewed_go.gomodcache_tree_sha256:
        raise CustodyUnavailable(
            "retained isolated Go module cache changed before descriptor binding"
        )
    custody.verify()
    return destination


def build_reference(
    target: str,
    basename: str,
    into: str,
    reviewed_go: ReviewedGo,
    source_custody: Optional[BoundSourceClosure] = None,
) -> tuple[bool, Optional[RetainedReference], str]:
    """Build `target` and return descriptor custody, never a reopenable path."""
    if source_custody is None:
        return False, None, "descriptor-bound private source closure is required\n"
    platform_toolchain: Optional[PlatformToolchainCustody] = None
    if target.startswith("datapath-android-"):
        try:
            platform_toolchain = _bind_android_toolchain_custody(target)
        except CustodyUnavailable as exc:
            return False, None, f"OWNER-BLOCKED: Android toolchain: {exc}\n"
    if (
        target.startswith("datapath-archive-")
        or target.startswith("datapath-ios")
        or target.startswith("apple-wrapper-")
    ):
        platform_name = {
            "datapath-archive-darwin-arm64": "macosx",
            "datapath-archive-darwin-amd64": "macosx",
            "datapath-ios-arm64": "iphoneos",
            "datapath-iossimulator-arm64": "iphonesimulator",
            "datapath-iossimulator-amd64": "iphonesimulator",
            "apple-wrapper-iphoneos": "iphoneos",
            "apple-wrapper-iphonesimulator": "iphonesimulator",
            "apple-wrapper-macosx": "macosx",
        }.get(target)
        if platform_name is None:
            return False, None, f"unsupported Apple target: {target}\n"
        try:
            platform_toolchain = _bind_apple_toolchain_custody(platform_name)
        except CustodyUnavailable as exc:
            return False, None, f"OWNER-BLOCKED: {exc}\n"
    _private_directory(into)
    reference_root = tempfile.mkdtemp(prefix=f".reference-{target}.", dir=into)
    out = os.path.join(reference_root, basename)
    source_custody.verify()
    source_root = source_custody.snapshot_root
    environment = reviewed_go.build_environment(reference_root)
    for caller_controlled in (
        "ANDROID_HOME", "ANDROID_SDK_ROOT", "ANDROID_NDK_HOME",
        "ANDROID_NDK_ROOT", "NDK_HOME", "WINS_ANDROID_NDK_ROOT",
        "DEVELOPER_DIR", "SDKROOT", "CC", "CXX",
        "WINS_APPLE_DEVELOPER_DIR",
    ):
        environment.pop(caller_controlled, None)
    if platform_toolchain is not None:
        environment.update(platform_toolchain.environment)
    reference_custody = DescriptorCustody(
        "retained producer reference " + target, CustodyUnavailable
    )
    if isinstance(reviewed_go, ReviewedGo):
        isolated_cache = _isolate_attempt_module_cache(
            reviewed_go, reference_root, reference_custody
        )
        environment["GOMODCACHE"] = isolated_cache
        environment["WINS_STORE_GOMODCACHE"] = isolated_cache
        environment["WINS_STORE_GOMODCACHE_TREE_SHA256"] = (
            reviewed_go.gomodcache_tree_sha256
        )
    # Only the sealed core builder emits a v4 receipt; other producers leave
    # these empty and their publication handoff is refused.
    expected_source_tree_sha256 = ""
    expected_module_cache_tree_sha256 = ""

    def prepare_output(path: str) -> None:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        parent = reference_custody.bind_directory(os.path.dirname(path))
        generation_paths = (path, path + ".receipt.json") + (
            (path[: -len(".a")] + ".h",) if path.endswith(".a") else ()
        )
        for generation_path in generation_paths:
            if os.path.dirname(generation_path) != os.path.dirname(path):
                raise CustodyUnavailable(
                    "OWNER-BLOCKED: producer generation sidecar escaped output parent"
                )
            try:
                os.stat(
                    os.path.basename(generation_path),
                    dir_fd=parent.fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                continue
            raise CustodyUnavailable(
                "OWNER-BLOCKED: authenticated producer requires a fresh exclusive "
                f"generation destination: {generation_path}"
            )
        absolute = reference_custody._canonical(path)
        reference_custody._publication_started[absolute] = time.time()
        source_custody.verify()

    if target.startswith("relay-windows-"):
        arch = target.rsplit("-", 1)[-1]
        if arch not in PE_MACHINES:
            reference_custody.close()
            if platform_toolchain is not None:
                platform_toolchain.custody.close()
            return False, None, "unsupported relay target: " + target + "\n"
        out = os.path.join(reference_root, "winsvpn_winn3_engine_" + arch + ".exe")
        # The relay producer checks this executable's `go version` against the
        # pins; it is the private read-only copy whose bin/go and install tree
        # were measured against tools/toolchain-pins.json.
        environment["WINS_RELEASE_GO"] = str(
            getattr(reviewed_go, "retained_binary", "")
        )
        prepare_output(out)
        environment["WINS_FRESHNESS_OUTPUT_CONTRACT"] = (
            "winsvpn-exclusive-generation-path-v1"
        )
        environment["WINS_FRESHNESS_OUTPUT_PATH"] = out
        # Plain bash on the sealed snapshot copy, like the core builder: the
        # relay script locates its sources from its own path.
        try:
            proc = _run_system_descriptor(
                "/bin/bash",
                [source_custody.path(RELAY_BUILD_SCRIPT), reference_root],
                cwd=source_root,
                environment=environment,
                timeout=PRODUCER_TIMEOUT_SECONDS,
                retained_cwd_fd=source_custody.retained_root_fd(),
                pass_fds=(source_custody.retained_root_fd(),),
            )
        except (CustodyUnavailable, OSError) as exc:
            reference_custody.close()
            if platform_toolchain is not None:
                platform_toolchain.custody.close()
            return False, None, f"relay producer did not run: {exc}\n"
    elif target.startswith("apple-wrapper-"):
        platform_name = target[len("apple-wrapper-"):]
        relative = {
            "iphoneos": "ios/iphoneos/libWinsWinnPacketEngine.dylib",
            "iphonesimulator": "ios/iphonesimulator/libWinsWinnPacketEngine.dylib",
            "macosx": "macos/libWinsWinnPacketEngine.dylib",
        }.get(platform_name)
        if relative is None:
            reference_custody.close()
            if platform_toolchain is not None:
                platform_toolchain.custody.close()
            return False, None, "unsupported Apple wrapper target: " + target + "\n"
        out = os.path.join(reference_root, "apple-wrappers", relative)
        if sys.platform != "darwin":
            reference_custody.close()
            if platform_toolchain is not None:
                platform_toolchain.custody.close()
            return False, None, "Apple wrapper rebuild requires a Darwin host with Xcode\n"
        environment["APPLE_ENGINE_WRAPPER_OUTPUT_ROOT"] = os.path.join(
            reference_root, "apple-wrappers"
        )
        environment["WINN_DATAPATH_ARCHIVE_DIR"] = os.path.join(
            reference_root, "apple-archives"
        )
        environment["WINS_SKIP_APPLE_WG_GO_BUILD"] = "1"
        prepare_output(out)
        environment["WINS_FRESHNESS_OUTPUT_CONTRACT"] = (
            "winsvpn-exclusive-generation-path-v1"
        )
        environment["WINS_FRESHNESS_OUTPUT_PATH"] = out
        reference_custody.close()
        if platform_toolchain is not None:
            platform_toolchain.custody.verify()
            platform_toolchain.custody.close()
        return (
            False,
            None,
            "OWNER-BLOCKED: the Apple wrapper producer still reopens support "
            "inputs through mutable source-tree pathnames. Its retained script "
            "descriptor cannot safely authorize a build until that producer "
            "accepts a complete descriptor-rooted support closure.\n",
        )
    else:
        if target.startswith("datapath-archive-") and sys.platform != "darwin":
            reference_custody.close()
            if platform_toolchain is not None:
                platform_toolchain.custody.close()
            return False, None, "Apple archive rebuild requires a Darwin host with Xcode\n"
        prepare_output(out)
        # Sealed-mode builder contract (tools/build_winn_protocol_engine.sh):
        # the private snapshot's module directory is already a sealed tree,
        # the builder re-measures every digest passed here, and it runs Go only
        # from WINS_RELEASE_GO_ROOT after checking bin/go against the pins.
        builder_path = source_custody.path(BUILD_SCRIPT)
        source_module = os.path.realpath(source_custody.path(MODULE_DIR))
        try:
            source_tree_sha256 = _sealed_tree_digest(source_module)
            module_cache_tree_sha256 = (
                _sealed_tree_digest(environment["WINS_STORE_GOMODCACHE"])
                if environment.get("WINS_STORE_GOMODCACHE")
                else ""
            )
        except (CustodyUnavailable, OSError) as exc:
            reference_custody.close()
            if platform_toolchain is not None:
                platform_toolchain.custody.close()
            return False, None, f"OWNER-BLOCKED: sealed producer inputs: {exc}\n"
        producer_environment = {
            "HOME": environment.get("HOME", reference_root),
            "PATH": SYSTEM_PATH,
            "TMPDIR": environment.get("TMPDIR", reference_root),
            "WINS_WINN_SOURCE_ROOT": source_module,
            "WINS_WINN_SOURCE_TREE_SHA256": source_tree_sha256,
            "WINS_STORE_GOMODCACHE": environment.get(
                "WINS_STORE_GOMODCACHE", ""
            ),
            "WINS_STORE_GOMODCACHE_TREE_SHA256": module_cache_tree_sha256,
            "WINS_RELEASE_GO_ROOT": str(getattr(reviewed_go, "retained_root", "")),
        }
        if platform_toolchain is not None:
            for authority_name in (
                "ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "WINS_ANDROID_NDK_ROOT",
                "DEVELOPER_DIR", "SDKROOT", "CC", "CXX",
                "WINS_APPLE_DEVELOPER_DIR",
            ):
                authority_value = platform_toolchain.environment.get(authority_name)
                if authority_value:
                    producer_environment[authority_name] = authority_value
        producer_environment["WINS_FRESHNESS_OUTPUT_CONTRACT"] = (
            "winsvpn-exclusive-generation-path-v1"
        )
        producer_environment["WINS_FRESHNESS_OUTPUT_PATH"] = out
        try:
            proc = _run_system_descriptor(
                "/bin/bash",
                [builder_path, target, out],
                cwd=source_root,
                retained_cwd_fd=source_custody.retained_root_fd(),
                environment=producer_environment,
                timeout=PRODUCER_TIMEOUT_SECONDS,
                pass_fds=(source_custody.retained_root_fd(),),
            )
        except (CustodyUnavailable, OSError) as exc:
            reference_custody.close()
            if platform_toolchain is not None:
                platform_toolchain.custody.close()
            return False, None, f"core producer did not run: {exc}\n"
        expected_source_tree_sha256 = source_tree_sha256
        expected_module_cache_tree_sha256 = module_cache_tree_sha256
    log = (proc.stdout or "") + (proc.stderr or "")
    try:
        source_custody.verify()
        reviewed_go.verify_unchanged()
        if platform_toolchain is not None:
            platform_toolchain.custody.verify()
        if proc.returncode != 0:
            reference_custody.close()
            if platform_toolchain is not None:
                platform_toolchain.custody.close()
            return False, None, log
        publication_handoff = _authenticated_producer_publication_handoff(
            proc.stdout or "", target, out,
            source_custody=source_custody,
            reviewed_go=reviewed_go,
            platform_toolchain=platform_toolchain,
            reference_custody=reference_custody,
            expected_source_tree_sha256=expected_source_tree_sha256,
            expected_module_cache_tree_sha256=expected_module_cache_tree_sha256,
        )
        retained_output = reference_custody._nodes.get(
            reference_custody._canonical(out)
        )
        if (
            retained_output is None
            or retained_output.is_directory
            or publication_handoff.descriptor_identity != retained_output.identity
        ):
            raise CustodyUnavailable(
                "OWNER-BLOCKED: exclusive producer generation changed after receipt "
                "validation"
            )
    except (CustodyUnavailable, OSError) as exc:
        cleanup_detail = ""
        try:
            reference_custody.close()
        except CustodyUnavailable as cleanup_exc:
            cleanup_detail = f"; cleanup custody also refused: {cleanup_exc}"
        if platform_toolchain is not None:
            platform_toolchain.custody.close()
        return (
            False,
            None,
            log + f"\nreviewed Go custody changed: {exc}{cleanup_detail}\n",
        )
    try:
        reference_custody.seal_created_file(out)
        reference_payload = reference_custody.read_file(out)
        source_custody.verify()
        reference_custody.verify()
        if platform_toolchain is not None:
            platform_toolchain.custody.verify()
            platform_toolchain.custody.close()
        source_custody.verify()
        reference_custody.verify()
        return True, RetainedReference(
            out, reference_custody, publication_handoff
        ), log
    except (ArtifactMissing, ArtifactInvalid, CustodyUnavailable, OSError) as exc:
        reference_custody.close()
        if platform_toolchain is not None:
            platform_toolchain.custody.close()
        return False, None, log + f"\nreference descriptor custody failed: {exc}\n"


@dataclass
class Result:
    artifact: Artifact
    verdict: str  # FRESH | STALE | MISSING | INVALID | UNBUILDABLE | OWNER-BLOCKED
    detail: str = ""
    shipped_mtime: float = 0.0
    shipped_digest: str = ""
    rebuilt_digest: str = ""
    log: str = field(default="", repr=False)


@dataclass
class RetainedArtifactConsumer:
    """Descriptor-only input for an action completed while custody is held."""

    artifact: Artifact
    path: str
    custody: DescriptorCustody = field(repr=False)
    _reads: int = field(default=0, init=False, repr=False)
    _read_sha256: str = field(default="", init=False, repr=False)
    _read_size: int = field(default=0, init=False, repr=False)

    def read_archive(self) -> bytes:
        self.custody.verify()
        payload = self.custody.read_file(self.path)
        self.custody.verify()
        self._reads += 1
        self._read_sha256 = hashlib.sha256(payload).hexdigest()
        self._read_size = len(payload)
        return payload

    @property
    def consumed_descriptor_bytes(self) -> bool:
        return self._reads > 0

    @property
    def descriptor_read_binding(self) -> tuple[str, int]:
        return self._read_sha256, self._read_size


def _write_complete(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise ArtifactInvalid("descriptor publication write made no progress")
        offset += written


def _artifact_path(relative: str) -> str:
    if not relative or os.path.isabs(relative) or "\\" in relative:
        raise ArtifactInvalid(f"artifact path is not repository-relative: {relative!r}")
    parts = relative.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ArtifactInvalid(f"artifact path is not canonical: {relative!r}")
    full = os.path.abspath(os.path.join(REPO_ROOT, *parts))
    try:
        if os.path.commonpath((REPO_ROOT, full)) != REPO_ROOT:
            raise ArtifactInvalid(f"artifact path escapes the repository: {relative!r}")
    except ValueError as exc:
        raise ArtifactInvalid(f"artifact path has incompatible roots: {relative!r}") from exc
    return full


def fingerprint_bytes(blob: bytes) -> str:
    return hashlib.sha256(normalise(blob)).hexdigest()


def check(
    artifact: Artifact,
    workdir: str,
    reviewed_go: ReviewedGo,
    source_custody: Optional[BoundSourceClosure] = None,
    consumer: Optional[Callable[[RetainedArtifactConsumer], object]] = None,
) -> Result:
    # FRESH means: the shipped bytes were read under descriptor custody, the
    # target was rebuilt from the bound source closure with the pinned
    # toolchains, the producer's receipt bound that rebuild to the exact
    # target, role and sha256, and both sides agree after the format-specific
    # normalisation. A caller-supplied consumer is never invoked or trusted.
    del consumer
    try:
        full = _artifact_path(artifact.path)
    except ArtifactInvalid as exc:
        return Result(artifact, "INVALID", f"cannot inspect {artifact.path}: {exc}")
    custody = DescriptorCustody("shipped artifact " + artifact.path)
    reference: Optional[RetainedReference] = None
    result: Optional[Result] = None
    close_failures: list[BaseException] = []
    try:
        node = custody.bind_file(full)
        shipped_mtime = node.identity[6] / 1_000_000_000
        shipped_archive = custody.read_file(full)
        shipped_payload = _artifact_payload_bytes(shipped_archive, artifact)
        if artifact.kind == "pe":
            if source_custody is None:
                raise ArtifactInvalid(
                    f"{artifact.path}: OWNER-BLOCKED Windows producer receipt "
                    "requires the current authoritative source closure"
                )
            _require_pe_machine_architecture(shipped_payload, artifact)
        # Structure first; the role identity of the shipped bytes is proven
        # below by equality with the authenticated rebuild.
        _validate_binary(
            shipped_payload,
            artifact,
            require_authenticated_role=False,
            authoritative_source_closure=(
                source_custody.closure if source_custody is not None else None
            ),
        )
        if source_custody is not None:
            source_custody.verify()

        ok, reference, log = build_reference(
            artifact.target, os.path.basename(artifact.path), workdir, reviewed_go,
            source_custody)
        if source_custody is not None:
            source_custody.verify()
        if not ok or reference is None:
            custody.verify()
            result = Result(
                artifact,
                "OWNER-BLOCKED" if "OWNER-BLOCKED" in log else "UNBUILDABLE",
                (
                    "a sealed input, platform authority, receipt, or artifact "
                    "required by the authenticated producer is unavailable"
                    if "OWNER-BLOCKED" in log
                    else "the current source could not produce a valid reference artifact"
                ),
                shipped_mtime,
                log=log,
            )
        else:
            custody.verify()
            rebuilt_payload = reference.read()
            _validate_binary(
                rebuilt_payload,
                artifact,
                role_receipt=reference.publication_handoff,
                require_authenticated_role=True,
            )
            shipped = fingerprint_bytes(shipped_payload)
            rebuilt = fingerprint_bytes(rebuilt_payload)
            if shipped == rebuilt:
                # A PE is never normalised, so equality is raw equality and the
                # rebuild's handoff (target, role, arch, sha256, size) binds
                # the shipped bytes too.
                _validate_binary(
                    shipped_payload,
                    artifact,
                    role_receipt=(
                        reference.publication_handoff if artifact.kind == "pe" else None
                    ),
                    allow_normalised_equivalent=True,
                    require_authenticated_role=artifact.kind == "pe",
                    authoritative_source_closure=(
                        source_custody.closure if source_custody is not None else None
                    ),
                )
            if source_custody is not None:
                source_custody.verify()
            custody.verify()
            reference.verify()
            if shipped != rebuilt:
                result = Result(
                    artifact, "STALE", "", shipped_mtime, shipped, rebuilt, log
                )
            else:
                result = Result(
                    artifact,
                    "FRESH",
                    "shipped bytes equal an authenticated rebuild of the bound "
                    "source closure",
                    shipped_mtime,
                    shipped,
                    rebuilt,
                    log,
                )
    except ArtifactMissing as exc:
        result = Result(
            artifact,
            "OWNER-BLOCKED",
            "required shipped artifact authority is absent: " + str(exc),
        )
    except ArtifactInvalid as exc:
        result = Result(
            artifact,
            "OWNER-BLOCKED" if "OWNER-BLOCKED" in str(exc) else "INVALID",
            str(exc),
        )
    finally:
        if reference is not None:
            try:
                reference.close()
            except BaseException as exc:
                close_failures.append(exc)
        try:
            custody.close()
        except BaseException as exc:
            close_failures.append(exc)
    for failure in close_failures:
        if isinstance(failure, CustodyUnavailable):
            raise failure
    if close_failures:
        return Result(
            artifact,
            "INVALID",
            f"descriptor custody failed during final release: {close_failures[0]}",
        )
    if result is None:
        raise AssertionError("freshness transaction produced no result")
    return result


def _self_check_pairs() -> tuple[tuple[str, str, Artifact], ...]:
    if sys.platform.startswith("linux") or sys.platform == "darwin":
        pairs = (
            ("datapath-linux-amd64", "selfcheck-amd64", Artifact(
                "selfcheck-amd64", "datapath-linux-amd64", "linux", "self-check",
                arch="amd64")),
            ("datapath-linux-arm64", "selfcheck-arm64", Artifact(
                "selfcheck-arm64", "datapath-linux-arm64", "linux", "self-check",
                arch="arm64")),
            ("datapath-windows-amd64", "selfcheck-core-amd64.exe", Artifact(
                "selfcheck-core-amd64.exe", "datapath-windows-amd64", "windows",
                "self-check", kind="pe", arch="amd64")),
            ("datapath-windows-arm64", "selfcheck-core-arm64.exe", Artifact(
                "selfcheck-core-arm64.exe", "datapath-windows-arm64", "windows",
                "self-check", kind="pe", arch="arm64")),
            ("relay-windows-amd64", "selfcheck-relay-amd64.exe", Artifact(
                "selfcheck-relay-amd64.exe", "relay-windows-amd64", "windows",
                "self-check", kind="pe", role="relay", arch="amd64", closure="relay")),
            ("relay-windows-arm64", "selfcheck-relay-arm64.exe", Artifact(
                "selfcheck-relay-arm64.exe", "relay-windows-arm64", "windows",
                "self-check", kind="pe", role="relay", arch="arm64", closure="relay")),
            ("datapath-android-arm64", "selfcheck-android-arm64.so", Artifact(
                "selfcheck-android-arm64.so", "datapath-android-arm64", "android",
                "self-check", kind="elf", arch="arm64")),
            ("datapath-android-arm", "selfcheck-android-arm.so", Artifact(
                "selfcheck-android-arm.so", "datapath-android-arm", "android",
                "self-check", kind="elf", arch="arm")),
            ("datapath-android-amd64", "selfcheck-android-amd64.so", Artifact(
                "selfcheck-android-amd64.so", "datapath-android-amd64", "android",
                "self-check", kind="elf", arch="amd64")),
            ("datapath-archive-darwin-arm64", "selfcheck-darwin-arm64.a", Artifact(
                "selfcheck-darwin-arm64.a", "datapath-archive-darwin-arm64", "apple",
                "self-check", kind="apple-archive", arch="arm64", platform="macosx",
                closure="apple")),
            ("datapath-archive-darwin-amd64", "selfcheck-darwin-amd64.a", Artifact(
                "selfcheck-darwin-amd64.a", "datapath-archive-darwin-amd64", "apple",
                "self-check", kind="apple-archive", arch="x86_64", platform="macosx",
                closure="apple")),
            ("datapath-ios-arm64", "selfcheck-ios-arm64.a", Artifact(
                "selfcheck-ios-arm64.a", "datapath-ios-arm64", "apple", "self-check",
                kind="apple-archive", arch="arm64", platform="iphoneos", closure="apple")),
            ("datapath-iossimulator-arm64", "selfcheck-iossim-arm64.a", Artifact(
                "selfcheck-iossim-arm64.a", "datapath-iossimulator-arm64", "apple",
                "self-check", kind="apple-archive", arch="arm64",
                platform="iphonesimulator", closure="apple")),
            ("datapath-iossimulator-amd64", "selfcheck-iossim-amd64.a", Artifact(
                "selfcheck-iossim-amd64.a", "datapath-iossimulator-amd64", "apple",
                "self-check", kind="apple-archive", arch="x86_64",
                platform="iphonesimulator", closure="apple")),
            ("apple-wrapper-iphoneos", "selfcheck-iphoneos.dylib", Artifact(
                "selfcheck-iphoneos.dylib", "apple-wrapper-iphoneos", "apple",
                "self-check", kind="apple-wrapper", role="core+relay", arch="arm64",
                platform="iphoneos", closure="apple")),
            ("apple-wrapper-iphonesimulator", "selfcheck-iossim.dylib", Artifact(
                "selfcheck-iossim.dylib", "apple-wrapper-iphonesimulator", "apple",
                "self-check", kind="apple-wrapper", role="core+relay",
                arch="arm64,x86_64", platform="iphonesimulator", closure="apple")),
            ("apple-wrapper-macosx", "selfcheck-macos.dylib", Artifact(
                "selfcheck-macos.dylib", "apple-wrapper-macosx", "apple", "self-check",
                kind="apple-wrapper", role="core+relay", arch="arm64,x86_64",
                platform="macosx", closure="apple")),
        )
        if sys.platform.startswith("linux"):
            # Linux can cross-build the two Linux architectures, both Windows
            # architectures/roles, and all Android ABIs. Apple outputs need the
            # pinned Xcode, which runs only on Darwin, so they are not host builds here.
            return pairs[:9]
        return pairs
    return ()


def _authenticated_executable_code_offset(blob: bytes, artifact: Artifact) -> int:
    """Locate one real code byte through the parser for the declared format."""
    ranges: list[tuple[int, int]] = []
    if artifact.kind in {"raw", "elf"}:
        layout = _parse_elf(blob, artifact.path)
        for section in layout.sections:
            _, section_type, flags, _, offset, size = section
            if section_type != 8 and flags & 0x4 and size:
                ranges.append((offset, offset + size))
        if not ranges:
            for program_type, flags, offset, size, address, _ in layout.segments:
                if (
                    program_type == 1
                    and flags & 0x1
                    and size
                    and address <= layout.entry < address + size
                ):
                    entry_offset = offset + layout.entry - address
                    ranges.append((entry_offset, offset + size))
    elif artifact.kind == "pe":
        layout = _parse_pe(blob, artifact.path)
        ranges.extend(
            (offset, offset + size)
            for _, _, _, offset, size, flags in layout.sections
            if size
            and flags & 0x00000020
            and flags & 0x20000000
            and flags & 0x40000000
            and not flags & 0x80000000
        )
    elif artifact.kind == "apple-wrapper":
        for macho in _macho_slices(blob):
            ranges.extend(
                (section.offset, section.offset + section.size)
                for section in macho.sections
                if section.segment == "__TEXT"
                and section.name == "__text"
                and section.size
                and section.segment_initial_protection & 0x5 == 0x5
            )
    elif artifact.kind == "apple-archive":
        for member in _archive_members(blob):
            if member.name in ("__.SYMDEF", "__.SYMDEF SORTED", "__.PKGDEF"):
                continue
            for macho in _macho_slices(member.payload):
                ranges.extend(
                    (
                        member.payload_offset + section.offset,
                        member.payload_offset + section.offset + section.size,
                    )
                    for section in macho.sections
                    if section.segment == "__TEXT"
                    and section.name == "__text"
                    and section.size
                    and section.flags & 0x80000400 == 0x80000400
                )
    for start, end in ranges:
        if 0 <= start < end <= len(blob):
            return start + (end - start) // 2
    raise ArtifactInvalid(
        f"{artifact.path}: real format parser found no authenticated executable code"
    )


def self_check(
    workdir: str,
    reviewed_go: ReviewedGo,
    source_closures: Optional[dict[str, BoundSourceClosure]] = None,
) -> int:
    """Prove `normalise` is neither too tight nor too loose.

    Too tight (a fresh artifact reported stale) makes the gate noise that
    someone will switch off. Too loose (a stale artifact reported fresh) makes
    it the false green it exists to replace. Both are checked against real
    builds rather than argued about.
    """
    print("== self-check: two builds of identical source must agree ==")
    failures = 0
    pairs = _self_check_pairs()
    if not pairs:
        print("  FAIL: host declares no required self-check pairs")
        return 1
    declared = {target for target, _, _ in pairs}
    if len(declared) != len(pairs):
        print("  FAIL: host self-check declarations contain duplicate targets")
        return 1
    proven: set[str] = set()
    proven_digests: dict[str, str] = {}
    for target, base, artifact in pairs:
        closure = (source_closures or {}).get(target)
        first_ok, first, _ = build_reference(
            target, "1-" + base, workdir, reviewed_go, closure)
        second_ok, second, _ = build_reference(
            target, "2-" + base, workdir, reviewed_go, closure)
        if not (first_ok and second_ok) or first is None or second is None:
            if first is not None:
                first.close()
            if second is not None:
                second.close()
            print(f"  FAIL  {target}: a required reference-build pair failed")
            failures += 1
            continue
        try:
            first_blob = first.read()
            second_blob = second.read()
            _validate_binary(
                first_blob,
                artifact,
                role_receipt=first.publication_handoff,
                require_authenticated_role=True,
            )
            _validate_binary(
                second_blob,
                artifact,
                role_receipt=second.publication_handoff,
                require_authenticated_role=True,
            )
            raw_same = (
                hashlib.sha256(first_blob).digest()
                == hashlib.sha256(second_blob).digest()
            )
            norm_same = fingerprint_bytes(first_blob) == fingerprint_bytes(second_blob)
            output_digest = fingerprint_bytes(second_blob)
            print(
                f"  {target}: raw sha256 equal={raw_same}, "
                f"normalised equal={norm_same}"
            )
            if not norm_same:
                print("    FAIL: two builds of the same source do not agree even after "
                      "normalisation; this gate would report false staleness.")
                failures += 1

            # And the other direction: a single flipped byte outside the mask must
            # still be caught, so the mask cannot be hiding real change.
            body = bytearray(second_blob)
            code_offset = _authenticated_executable_code_offset(second_blob, artifact)
            body[code_offset] ^= 0xFF
            if fingerprint_bytes(bytes(body)) == fingerprint_bytes(second_blob):
                print("    FAIL: a flipped byte in compiled code survived "
                      "normalisation; the mask is too wide.")
                failures += 1
            else:
                print("    a flipped byte in compiled code is still caught")
                duplicate_target = proven_digests.get(output_digest)
                if duplicate_target is not None and duplicate_target != target:
                    print(
                        "    FAIL: required targets produced one identical "
                        f"normalised output: {duplicate_target}, {target}"
                    )
                    failures += 1
                elif norm_same:
                    proven_digests[output_digest] = target
                    proven.add(target)
            first.verify()
            second.verify()
        except (ArtifactInvalid, ArtifactMissing, CustodyUnavailable) as exc:
            print(f"  FAIL  {target}: required output is structurally invalid: {exc}")
            failures += 1
            continue
        finally:
            first.close()
            second.close()
    missing = sorted(declared - proven)
    if missing:
        print("  FAIL: host-required build proofs are incomplete: " + ", ".join(missing))
        if failures == 0:
            failures = len(missing)
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", choices=("android", "apple", "windows", "linux"),
                        help="check one platform group")
    parser.add_argument("--artifact", action="append", metavar="PATH",
                        help="check only this declared repository-relative "
                             "artifact path (repeatable)")
    parser.add_argument("--self-check", action="store_true",
                        help="prove the comparison itself is sound, then exit")
    args = parser.parse_args()

    for producer in (BUILD_SCRIPT, RELAY_BUILD_SCRIPT, APPLE_WRAPPER_BUILD_SCRIPT):
        if not os.path.isfile(producer) or os.path.islink(producer):
            print(f"FATAL: producer is missing or symbolic: {producer}", file=sys.stderr)
            return 2
    wanted: list[Artifact] = []
    if not args.self_check:
        try:
            if args.only == "linux":
                # The fixed Linux declaration can be checked without allowing
                # unrelated platform custody to mask collision/architecture
                # failures before producer authentication.
                wanted = list(_linux_artifacts())
            else:
                wanted = [
                    artifact
                    for artifact in inventory()
                    if not args.only or artifact.group == args.only
                ]
        except (ArtifactInvalid, ArtifactMissing, CustodyUnavailable) as exc:
            print(f"FATAL: native inventory preflight failed closed: {exc}", file=sys.stderr)
            return 2
        selected_paths = getattr(args, "artifact", None)
        if not isinstance(selected_paths, list):
            selected_paths = []
        if selected_paths:
            declared_paths = {artifact.path for artifact in wanted}
            unknown = sorted(set(selected_paths) - declared_paths)
            if unknown:
                print(
                    "FATAL: --artifact names no declared artifact in the selected "
                    "inventory: " + ", ".join(unknown),
                    file=sys.stderr,
                )
                return 2
            wanted = [artifact for artifact in wanted if artifact.path in selected_paths]
        if args.only == "linux" and not selected_paths and {
            artifact.target for artifact in wanted if artifact.group == "linux"
        } != {"datapath-linux-amd64", "datapath-linux-arm64"}:
            print(
                "FATAL: every declared Linux x64/arm64 target must be present "
                "before any producer or consumer transaction begins.",
                file=sys.stderr,
            )
            return 2
    try:
        reviewed_go = authenticate_reviewed_go()
    except CustodyUnavailable as exc:
        print(
            "FATAL: exact reviewed Go custody is unavailable, so no artifact "
            f"can be compared against current source: {exc}",
            file=sys.stderr,
        )
        return 2

    workdir = tempfile.mkdtemp(prefix="winn-freshness.")
    bound_closures: dict[str, BoundSourceClosure] = {}
    try:
        if args.self_check:
            self_check_targets = tuple(item[0] for item in _self_check_pairs())
            bound_closures = bind_source_closures(
                self_check_targets,
                reviewed_go,
                workdir,
            )
            failures = self_check(workdir, reviewed_go, bound_closures)
            for item in bound_closures.values():
                item.verify()
            reviewed_go.verify_unchanged()
            reviewed_go.verify_module_cache_unchanged()
            if failures:
                return 1
            print(
                "SELF-CHECK DIAGNOSTIC PASS: deterministic comparison and "
                "mutation detection succeeded, but no authenticated downstream "
                "output, receipt, or sealed publication was produced. This is "
                "not a release PASS.",
                file=sys.stderr,
            )
            return SELF_CHECK_DIAGNOSTIC_EXIT

        bound_closures = bind_source_closures(
            (artifact.target for artifact in wanted),
            reviewed_go,
            workdir,
        )
        newest, where = newest_source_mtime()
        print(f"Newest source in {os.path.relpath(MODULE_DIR, REPO_ROOT)}: "
              f"{stamp(newest)}  ({where})")
        for name in sorted(bound_closures):
            closure = bound_closures[name].closure
            print(f"Winn source closure {name}: {closure.digest} "
                  f"({len(closure.files)} files; dependencies "
                  f"{closure.dependency_digest}; {len(closure.modules)} modules)")
        print(f"Comparing {len(wanted)} shipped artifact(s) against a build of "
              f"that source.\n")

        results = []
        for artifact in wanted:
            results.append(
                check(
                    artifact,
                    workdir,
                    reviewed_go,
                    bound_closures[artifact.target],
                )
            )
        reviewed_go.verify_unchanged()
        reviewed_go.verify_module_cache_unchanged()
        for item in bound_closures.values():
            item.verify()

        width = max(len(r.artifact.path) for r in results)
        stale, broken = [], []
        for r in results:
            mark = {
                "FRESH": "ok",
                "STALE": "STALE",
                "MISSING": "MISSING",
                "INVALID": "INVALID",
                "UNBUILDABLE": "SKIPPED",
                "OWNER-BLOCKED": "BLOCKED",
            }[r.verdict]
            when = stamp(r.shipped_mtime) if r.shipped_mtime else "-"
            print(f"  [{mark:>7}] {r.artifact.path:<{width}}  built {when}")
            if r.verdict == "STALE":
                stale.append(r)
            elif r.verdict != "FRESH":
                broken.append(r)

        if stale:
            print("\n" + "=" * 72)
            print("STALE SHIPPED ARTIFACTS -- these do not match current source")
            print("=" * 72)
            for r in stale:
                print(f"\n  {r.artifact.path}")
                print(f"    ships as       : {r.artifact.why}")
                print(f"    built          : {stamp(r.shipped_mtime)}")
                print(f"    source now     : {stamp(newest)} ({where})")
                print(f"    in the tree    : {r.shipped_digest}")
                print(f"    current source : {r.rebuilt_digest}")
                print(f"    producer target: {r.artifact.target}")
            print("\nThe app would ship the first digest. Every test that builds "
                  "from source is testing the second.")

        for r in broken:
            print(f"\n  {r.artifact.path}: {r.verdict} -- {r.detail}")
            if r.log:
                print("    " + r.log.strip().replace("\n", "\n    ")[:1500])

        if stale:
            return 1
        if broken:
            print("\nSome artifacts could not be checked. That is not a pass.")
            return 1
        if not results or any(result.verdict != "FRESH" for result in results):
            print("\nFATAL: no artifact was proven FRESH.", file=sys.stderr)
            return 2
        print(
            f"\nPASS: all {len(results)} checked shipped native artifact(s) equal "
            "an authenticated rebuild of the bound source closure."
        )
        return 0
    except CustodyUnavailable as exc:
        print(f"FATAL: reviewed Go custody failed closed: {exc}", file=sys.stderr)
        return 2
    finally:
        for item in bound_closures.values():
            item.close()
        # Reference roots hold read-only module-cache copies; a plain
        # rmtree cannot remove them and leaked about 170 MB per rebuild.
        _discard_private_tree(workdir)
        reviewed_go.close()


if __name__ == "__main__":
    sys.exit(main())
