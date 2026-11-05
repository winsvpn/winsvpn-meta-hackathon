#!/usr/bin/env python3
"""Fail-closed verification for final Developer ID macOS release artifacts.

The verifier consumes two held objects: the final stapled application bundle and
the final stapled PKG or DMG that will be distributed. It never signs, packages,
notarizes, or staples anything. Missing owner credentials or missing produced
artifacts therefore remain blockers instead of being replaced with local or ad
hoc evidence.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import pathlib
import plistlib
import re
import select
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import types
import uuid
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


ROOT = pathlib.Path(__file__).resolve().parents[1]
OBFUSCATION_SOURCE_FILES = {
    "release_obfuscation_contract": ROOT / "tools/release_obfuscation_contract.py",
    "release_secret_scan_policy": ROOT / "tools/release_secret_scan_policy.py",
    "release_secret_inventory": ROOT / "tools/release_secret_inventory.py",
    "validate_release_artifact_privacy": ROOT / "tools/validate_release_artifact_privacy.py",
}
WINN_PROVENANCE_SCHEMA = ROOT / "tools/apple_winn_v3_engine_provenance.schema.json"
WINN_RELEASE_DRIVER = ROOT / "tools/winn_release.py"
WINN_RELEASE_AUTHORITY = ROOT / "tools/winn_release_authority.json"
TOOLCHAIN_PINS = ROOT / "tools/toolchain-pins.json"
# Reviewed AWG 3.1 bridge pins, mirrored from tools/build_apple_wg_go_bridge.sh
# (test_verify_macos_release_artifact keeps the two equal). An empty value is
# unpinned: it must be measured on a networked host and pinned in both places
# before any AWG provenance can authenticate. The three digests were measured
# on 2026-10-15 (official tag go.mod/go.sum, proxy.golang.org module ZIP).
REVIEWED_AWG_SOURCE_PINS = {
    "commit": "fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d",
    "go_mod_sha256": "790252dad6cad8aa668ccc4dafdfdac4f2fa3d3fbefce16ded750f0a46cabe0d",
    "go_sum_sha256": "1a806e7973118c0ce8832e15d246fea0c44335a31fc4a0abe36a2ed165fada9d",
    "repository": "https://github.com/amnezia-vpn/amneziawg-apple.git",
    "tag": "v3.1.20260814",
    "tree": "24183de0cc22b957ff9e34ac3494a80f515ac565",
}
REVIEWED_AWG_XRAY_REPLACEMENT_PINS = {
    "commit": "77e5d55a796bafe17c1b5f2a9d9c590fd2a9f5f3",
    "go_mod_sum": "h1:VwJOtL3vj2w+8TWa6MZE1q88NsfrWvOXGJ+5wZ2N2ro=",
    "module_sum": "h1:4PniqnMxVxC54OdTx3e73BOMH/GD6jf85iaRyApAwGQ=",
    "replaced_module": "github.com/xtls/xray-core",
    "source_module": "github.com/amnezia-vpn/amnezia-xray-core",
    "version": "v1.260924.0",
    "zip_sha256": "7df5ebc400da6cc4ab13f5578e2fd19b855f98807f1ef1d86a30afc2cd213c40",
}
TEAM_ID = "5YT8H4U72M"
OWNER_COMMON_NAME = "Win's VPN Inc"
HOST_BUNDLE_ID = "org.winsvpn.app"
TUNNEL_BUNDLE_ID = "org.winsvpn.app.PacketTunnel"
DMG_SIGNING_IDENTIFIER = "org.winsvpn.app.dmg"
APP_GROUP = TEAM_ID + ".group.org.winsvpn.app"
KEYCHAIN_GROUP = TEAM_ID + ".org.winsvpn.shared"
REQUIRED_ARCHITECTURES = frozenset(("arm64", "x86_64"))
DEVELOPER_ID_APPLICATION_OID = "1.2.840.113635.100.6.1.13"
REQUIRED_WINN3_TUNNEL_SYMBOLS = frozenset(
    (
        "WinnTunnelContractVersion",
        "WinnTunnelProtocolVersion",
        "WinnTunnelMaxDatagram",
        "WinnTunnelCreate",
        "WinnTunnelCreateWinn3",
        "WinnTunnelCreateWithCarrier",
        "WinnTunnelWriteInbound",
        "WinnTunnelReadOutbound",
        "WinnTunnelStatusJSON",
        "WinnTunnelClose",
        "WinnTunnelFreeString",
    )
)
REQUIRED_WINN3_BINARY_MARKERS = (
    b"winn-datapath/1+winn3",
    b"winn3_datapath_proof_",
    b"winn3_gate_state",
)

RUNTIME_CONTRACT_KEY = "WinsReleaseTunnelRuntimeContract"
RUNTIME_CONTRACT = {
    "schema_version": 1,
    "primary": "winn3",
    "fallback_protocol": "winn1",
    "fallback": ["awg", "xray"],
    "required_engine_components": [
        "winn_packet_engine",
        "amneziawg_packet_engine",
        "xray_vless_ws_transport",
    ],
}

ENGINE_FRAMEWORKS = {
    "winn_packet_engine": {
        "framework": "WinsWinnPacketEngine.framework",
        "identifier": "org.winsvpn.engine.winn",
        "symbols": frozenset(
            (
                "wins_winn_packet_engine_contract_version",
                "wins_winn_packet_engine_create",
                "wins_winn_packet_engine_start",
                "wins_winn_packet_engine_stop",
                "wins_winn_packet_engine_destroy",
                "wins_winn_packet_engine_awg_seam_port",
                "wins_winn_packet_engine_seam_stats",
                "wins_winn_packet_engine_status_json",
                "WinnTunnelCreateWinn3",
            )
        ),
        "privacy": {
            "NSPrivacyAccessedAPICategoryFileTimestamp": frozenset(("C617.1",)),
            "NSPrivacyAccessedAPICategorySystemBootTime": frozenset(("35F9.1",)),
        },
    },
    "amneziawg_packet_engine": {
        "framework": "WinsAmneziaWGPacketEngine.framework",
        "identifier": "org.winsvpn.engine.amneziawg",
        "symbols": frozenset(
            (
                "wins_amneziawg_packet_engine_contract_version",
                "wins_amneziawg_packet_engine_create",
                "wins_amneziawg_packet_engine_start",
                "wins_amneziawg_packet_engine_stop",
                "wins_amneziawg_packet_engine_destroy",
            )
        ),
        "privacy": {
            "NSPrivacyAccessedAPICategoryFileTimestamp": frozenset(("C617.1",)),
        },
    },
    "xray_vless_ws_transport": {
        "framework": "WinsXrayVlessWsTransport.framework",
        "identifier": "org.winsvpn.engine.xray-vless-ws",
        "symbols": frozenset(
            (
                "wins_xray_vless_ws_transport_contract_version",
                "wins_xray_vless_ws_transport_configure",
                "wins_xray_vless_ws_transport_start",
                "wins_xray_vless_ws_transport_stop",
            )
        ),
        "privacy": {
            "NSPrivacyAccessedAPICategoryFileTimestamp": frozenset(("C617.1",)),
        },
    },
}

HOST_PRIVACY_REASONS = {
    "NSPrivacyAccessedAPICategoryFileTimestamp": frozenset(("C617.1",)),
    "NSPrivacyAccessedAPICategoryUserDefaults": frozenset(("CA92.1",)),
    "NSPrivacyAccessedAPICategorySystemBootTime": frozenset(("35F9.1",)),
}
TUNNEL_PRIVACY_REASONS = {
    "NSPrivacyAccessedAPICategoryFileTimestamp": frozenset(("C617.1",)),
    "NSPrivacyAccessedAPICategorySystemBootTime": frozenset(("35F9.1",)),
}
HOST_COLLECTED_TYPES = frozenset(
    (
        "NSPrivacyCollectedDataTypeCoarseLocation",
        "NSPrivacyCollectedDataTypeDeviceID",
        "NSPrivacyCollectedDataTypeUserID",
        "NSPrivacyCollectedDataTypeProductInteraction",
    )
)
APP_FUNCTIONALITY_PURPOSE = "NSPrivacyCollectedDataTypePurposeAppFunctionality"

FORBIDDEN_ENTITLEMENTS = frozenset(
    (
        "com.apple.security.get-task-allow",
        "get-task-allow",
        "com.apple.security.cs.allow-jit",
        "com.apple.security.cs.allow-unsigned-executable-memory",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.disable-executable-page-protection",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.debugger",
        "com.apple.security.temporary-exception.files.absolute-path.read-only",
        "com.apple.security.temporary-exception.files.absolute-path.read-write",
        "com.apple.security.temporary-exception.mach-lookup.global-name",
    )
)
PRIVATE_SYMBOL_SUFFIXES = (
    ".bcsymbolmap",
    ".dbg",
    ".debug",
    ".dsym",
    ".dwo",
    ".dwp",
    ".gcda",
    ".gcno",
    ".map",
    ".pdb",
    ".profraw",
    ".sym",
    ".symbols",
)
FORBIDDEN_CODE_NAME_FRAGMENTS = (
    "runnerTests",
    "xctest",
    "preview.dylib",
    "debug.dylib",
)
MACHO_MAGICS = frozenset(
    (
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    )
)
CPU_TYPES = {0x01000007: "x86_64", 0x0100000C: "arm64"}
FAT_MAGICS = {
    b"\xca\xfe\xba\xbe": (">", False),
    b"\xbe\xba\xfe\xca": ("<", False),
    b"\xca\xfe\xba\xbf": (">", True),
    b"\xbf\xba\xfe\xca": ("<", True),
}
THIN_MAGICS = {
    b"\xfe\xed\xfa\xce": ">",
    b"\xce\xfa\xed\xfe": "<",
    b"\xfe\xed\xfa\xcf": ">",
    b"\xcf\xfa\xed\xfe": "<",
}
MAX_METADATA_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024 * 1024
# Provenance field beside "sha256" in each macOS wrapper record: the digest of
# the engine after its code signature is normalized away (see
# signature_normalized_sha256). Staging and Xcode export re-sign the engine
# frameworks after provenance is written, so only this digest can bind them.
SIGNATURE_NORMALIZED_FIELD = "signature_normalized_sha256"

CANONICAL_OBFUSCATION_ADAPTER = r'''
import hashlib
import json
import os
import pathlib
import stat
import sys
import types

namespace = pathlib.Path(sys.argv[1])
closure = json.loads(sys.argv[2])
logical_artifact_path = sys.argv[3]
arguments = sys.argv[4:]
expected_modules = {
    "release_obfuscation_contract",
    "release_secret_inventory",
    "release_secret_scan_policy",
    "validate_release_artifact_privacy",
}
if type(closure) is not dict or set(closure) != expected_modules:
    raise RuntimeError("canonical verifier source closure is not exact")
controlled_names = expected_modules | {"tools." + name for name in expected_modules}
if any(name in sys.modules for name in controlled_names):
    raise RuntimeError("canonical verifier module namespace was preloaded")
namespace_fd = os.open(
    namespace,
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0),
)
try:
    namespace_info = os.fstat(namespace_fd)
    if not stat.S_ISDIR(namespace_info.st_mode) or stat.S_IMODE(namespace_info.st_mode) != 0o700:
        raise RuntimeError("canonical verifier namespace custody is invalid")
    if set(os.listdir(namespace_fd)) != {name + ".py" for name in expected_modules}:
        raise RuntimeError("canonical verifier namespace inventory is not exact")

    def load_held_module(name):
        record = closure[name]
        if type(record) is not dict or set(record) != {"logical_path", "sha256", "size"}:
            raise RuntimeError("canonical verifier source record is invalid")
        expected_name = name + ".py"
        logical_path = pathlib.Path(record["logical_path"])
        if not logical_path.is_absolute() or logical_path.name != expected_name:
            raise RuntimeError("canonical verifier logical source path is invalid")
        descriptor = os.open(
            expected_name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=namespace_fd,
        )
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o400
                or info.st_size != record["size"]
                or info.st_size <= 0
            ):
                raise RuntimeError("canonical verifier held source custody is invalid")
            source = os.pread(descriptor, info.st_size, 0)
            if len(source) != info.st_size or os.pread(descriptor, 1, info.st_size):
                raise RuntimeError("canonical verifier held source changed while being read")
            if hashlib.sha256(source).hexdigest() != record["sha256"]:
                raise RuntimeError("canonical verifier held source digest is invalid")
        finally:
            os.close(descriptor)
        module = types.ModuleType(name)
        module.__file__ = str(logical_path)
        module.__package__ = ""
        module.__spec__ = None
        sys.modules[name] = module
        exec(compile(source, str(logical_path), "exec", dont_inherit=True), module.__dict__)
        return module

    load_held_module("release_secret_scan_policy")
    load_held_module("release_secret_inventory")
    contract = load_held_module("release_obfuscation_contract")
    load_held_module("validate_release_artifact_privacy")
    contract.CONTRACT_PATH = namespace / "release_obfuscation_contract.py"
finally:
    os.close(namespace_fd)

def retained_artifact_record(_resolved, size, digest):
    return {"path": logical_artifact_path, "size": size, "sha256": digest}

contract._artifact_record_entry = retained_artifact_record
platform = arguments[arguments.index("--platform") + 1]
symbols_dir = pathlib.Path(arguments[arguments.index("--symbols-dir") + 1])
manifest = pathlib.Path(arguments[arguments.index("--manifest") + 1])
artifact = pathlib.Path(arguments[arguments.index("--artifact") + 1])
try:
    contract.verify(platform, manifest, symbols_dir, [artifact])
except contract.ObfuscationError as exc:
    raise SystemExit(str(exc))
'''
MAX_TREE_ENTRIES = 20000
MAX_TREE_BYTES = 4 * 1024 * 1024 * 1024


class VerificationError(RuntimeError):
    """A release condition was missing, malformed, or contradicted by bytes."""


class DuplicateKeyError(ValueError):
    pass


class HeldFile:
    """Retain every ancestor and one regular leaf for one release decision."""

    def __init__(self, path: pathlib.Path, label: str):
        self.path = pathlib.Path(os.path.abspath(os.path.normpath(path)))
        self.label = label
        self.parents: List[Tuple[pathlib.Path, int, Tuple[int, ...], str, Tuple[int, ...]]] = []
        self.fd = -1
        self.directory_watch: Any = None
        current = pathlib.Path("/")
        current_fd = os.open(
            current,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            components = self.path.parts[1:]
            for index, component in enumerate(components):
                parent_info = os.fstat(current_fd)
                current_info = os.lstat(current)
                if self._identity(parent_info) != self._identity(current_info):
                    raise VerificationError(label + " ancestor changed while being bound: " + str(current))
                child = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
                if stat.S_ISLNK(child.st_mode):
                    raise VerificationError(label + " has a symbolic path component")
                custody_identity = self._full_identity if index >= max(0, len(components) - 9) else self._identity
                self.parents.append(
                    (current, current_fd, custody_identity(parent_info), component, custody_identity(child))
                )
                current_fd = -1
                current /= component
                if index == len(self.path.parts[1:]) - 1:
                    if not stat.S_ISREG(child.st_mode) or child.st_nlink != 1:
                        raise VerificationError(label + " must be one regular non-hardlinked file")
                    parent_fd = self.parents[-1][1]
                    self.fd = os.open(
                        component,
                        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=parent_fd,
                    )
                    if self._identity(os.fstat(self.fd)) != self.parents[-1][4]:
                        raise VerificationError(label + " changed before its descriptor was retained")
                    break
                if not stat.S_ISDIR(child.st_mode):
                    raise VerificationError(label + " ancestor is not a directory")
                current_fd = os.open(
                    component,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=self.parents[-1][1],
                )
            if hasattr(select, "kqueue"):
                self.directory_watch = select.kqueue()
                flags = (
                    select.KQ_NOTE_WRITE | select.KQ_NOTE_RENAME | select.KQ_NOTE_DELETE
                    | select.KQ_NOTE_ATTRIB | select.KQ_NOTE_LINK | select.KQ_NOTE_REVOKE
                )
                changes = [
                    select.kevent(
                        descriptor,
                        filter=select.KQ_FILTER_VNODE,
                        flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                        fflags=flags,
                    )
                    for _path, descriptor, _identity, _child, _child_identity in self.parents[-9:]
                ]
                self.directory_watch.control(changes, 0, 0)
        except BaseException as exc:
            if current_fd >= 0:
                os.close(current_fd)
            self.close()
            if isinstance(exc, VerificationError):
                raise
            raise VerificationError(label + " could not be retained without following links") from exc

    @staticmethod
    def _identity(info: os.stat_result) -> Tuple[int, ...]:
        stable = (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid)
        if stat.S_ISREG(info.st_mode):
            return stable + (info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        return stable

    @staticmethod
    def _full_identity(info: os.stat_result) -> Tuple[int, ...]:
        return (
            info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
        )

    @classmethod
    def _matching_identity(cls, info: os.stat_result, expected: Tuple[int, ...]) -> Tuple[int, ...]:
        return cls._full_identity(info) if len(expected) == 9 else cls._identity(info)

    def verify(self) -> None:
        if self.fd < 0 or not self.parents:
            raise VerificationError(self.label + " retained custody is closed")
        if self.directory_watch is not None and self.directory_watch.control([], 1, 0):
            raise VerificationError(self.label + " retained ancestor changed during the decision")
        for path, descriptor, identity, child_name, child_identity in self.parents:
            if self._matching_identity(os.fstat(descriptor), identity) != identity:
                raise VerificationError(self.label + " retained ancestor changed: " + str(path))
            child = os.stat(child_name, dir_fd=descriptor, follow_symlinks=False)
            if self._matching_identity(child, child_identity) != child_identity:
                raise VerificationError(
                    self.label + " pathname substitution or restoration rejected: " + str(path / child_name)
                )
        if self._matching_identity(os.fstat(self.fd), self.parents[-1][4]) != self.parents[-1][4]:
            raise VerificationError(self.label + " retained descriptor changed")

    def read(self, maximum: int) -> bytes:
        self.verify()
        size = os.fstat(self.fd).st_size
        if size <= 0 or size > maximum:
            raise VerificationError(self.label + " is empty or exceeds its size limit")
        payload = os.pread(self.fd, size, 0)
        if len(payload) != size or os.pread(self.fd, 1, size):
            raise VerificationError(self.label + " changed while being read")
        self.verify()
        return payload

    def sha256(self) -> str:
        digest = hashlib.sha256()
        self.verify()
        size = os.fstat(self.fd).st_size
        offset = 0
        while offset < size:
            block = os.pread(self.fd, min(1024 * 1024, size - offset), offset)
            if not block:
                raise VerificationError(self.label + " ended while being hashed")
            digest.update(block)
            offset += len(block)
        self.verify()
        return digest.hexdigest()

    def snapshot(self, destination: pathlib.Path) -> None:
        payload = self.read(MAX_FILE_BYTES)
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise VerificationError(self.label + " held snapshot write failed")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if sha256_file(destination) != self.sha256():
            raise VerificationError(self.label + " held snapshot digest mismatch")

    def close(self) -> None:
        if self.directory_watch is not None:
            self.directory_watch.close()
            self.directory_watch = None
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1
        for _path, descriptor, _identity, _child, _child_identity in reversed(self.parents):
            if descriptor >= 0:
                os.close(descriptor)
        self.parents = []

    def __enter__(self) -> "HeldFile":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


class HeldRecursiveInventory:
    """Retain and re-enumerate one recursive regular-file inventory by descriptor."""

    def __init__(self, root: pathlib.Path, root_descriptor: int, label: str):
        self.root = pathlib.Path(os.path.abspath(os.path.normpath(root)))
        self.label = label
        self.directories: Dict[
            str, Tuple[int, Tuple[int, ...], Dict[str, Tuple[int, ...]]]
        ] = {}
        self.files: Dict[str, Tuple[str, str, Tuple[int, ...]]] = {}
        self.directory_watch: Any = None
        self.entry_count = 0
        self.total_bytes = 0
        try:
            descriptor = os.dup(root_descriptor)
            os.set_inheritable(descriptor, False)
            root_info = os.fstat(descriptor)
            if not stat.S_ISDIR(root_info.st_mode):
                os.close(descriptor)
                raise VerificationError(label + " root descriptor is not a directory")
            self._capture_directory("", descriptor)
            self._start_watch()
            self.verify()
        except BaseException as exc:
            self.close()
            if isinstance(exc, VerificationError):
                raise
            raise VerificationError(label + " could not be retained and enumerated safely") from exc

    @staticmethod
    def _identity(info: os.stat_result) -> Tuple[int, ...]:
        return HeldFile._full_identity(info)

    def _names(self, descriptor: int) -> List[str]:
        names = os.listdir(descriptor)
        if any(
            type(name) is not str or not name or name in (".", "..") or "/" in name or "\x00" in name
            for name in names
        ):
            raise VerificationError(self.label + " contains an unsafe directory entry")
        if len(names) != len(set(names)):
            raise VerificationError(self.label + " contains duplicate directory entries")
        return sorted(names)

    def _capture_directory(self, relative: str, descriptor: int) -> None:
        before = self._identity(os.fstat(descriptor))
        names = self._names(descriptor)
        entries: Dict[str, Tuple[int, ...]] = {}
        child_directories: List[Tuple[str, int]] = []
        try:
            for name in names:
                info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                identity = self._identity(info)
                entries[name] = identity
                self.entry_count += 1
                if self.entry_count > MAX_TREE_ENTRIES:
                    raise VerificationError(self.label + " exceeds its entry limit")
                child_relative = name if not relative else relative + "/" + name
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(
                        name,
                        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=descriptor,
                    )
                    if self._identity(os.fstat(child)) != identity:
                        os.close(child)
                        raise VerificationError(
                            self.label + " directory changed while being retained: " + child_relative
                        )
                    child_directories.append((child_relative, child))
                elif stat.S_ISREG(info.st_mode):
                    if info.st_nlink != 1 or info.st_size <= 0:
                        raise VerificationError(
                            self.label + " contains an empty or hardlinked file: " + child_relative
                        )
                    self.total_bytes += info.st_size
                    if self.total_bytes > MAX_TREE_BYTES:
                        raise VerificationError(self.label + " exceeds its byte limit")
                    self.files[child_relative] = (relative, name, identity)
                else:
                    raise VerificationError(
                        self.label + " contains a link or special file: " + child_relative
                    )
            self.directories[relative] = (descriptor, before, entries)
            descriptor = -1
            self._verify_directory(relative)
            while child_directories:
                child_relative, child = child_directories.pop(0)
                self._capture_directory(child_relative, child)
            self._verify_directory(relative)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            for _child_relative, child in child_directories:
                os.close(child)

    def _verify_directory(self, relative: str) -> None:
        descriptor, identity, entries = self.directories[relative]
        display = self.root if not relative else self.root.joinpath(*relative.split("/"))
        if self._identity(os.fstat(descriptor)) != identity:
            raise VerificationError(self.label + " directory changed: " + str(display))
        names = self._names(descriptor)
        if names != sorted(entries):
            raise VerificationError(self.label + " complete entry set changed: " + str(display))
        for name in names:
            current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if self._identity(current) != entries[name]:
                raise VerificationError(
                    self.label + " entry was inserted, removed, or substituted: " + str(display / name)
                )
        if self._identity(os.fstat(descriptor)) != identity:
            raise VerificationError(self.label + " directory changed while being checked: " + str(display))

    def _start_watch(self) -> None:
        if not hasattr(select, "kqueue"):
            return
        self.directory_watch = select.kqueue()
        flags = (
            select.KQ_NOTE_WRITE | select.KQ_NOTE_RENAME | select.KQ_NOTE_DELETE
            | select.KQ_NOTE_ATTRIB | select.KQ_NOTE_LINK | select.KQ_NOTE_REVOKE
            | getattr(select, "KQ_NOTE_EXTEND", 0)
        )
        for descriptor, _identity, _entries in self.directories.values():
            self.directory_watch.control(
                [
                    select.kevent(
                        descriptor,
                        filter=select.KQ_FILTER_VNODE,
                        flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                        fflags=flags,
                    )
                ],
                0,
                0,
            )

    def verify(self) -> None:
        if not self.directories:
            raise VerificationError(self.label + " retained inventory is closed")
        if self.directory_watch is not None and self.directory_watch.control([], 1, 0):
            raise VerificationError(self.label + " changed during the release decision")
        for relative in sorted(self.directories, key=lambda item: (item.count("/"), item)):
            self._verify_directory(relative)

    def inventory(self) -> List[Dict[str, Any]]:
        self.verify()
        records: List[Dict[str, Any]] = []
        for relative in sorted(self.files):
            parent_relative, name, expected = self.files[relative]
            parent_descriptor = self.directories[parent_relative][0]
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_descriptor,
            )
            try:
                if self._identity(os.fstat(descriptor)) != expected:
                    raise VerificationError(self.label + " file changed while being opened: " + relative)
                size = expected[6]
                digest = hashlib.sha256()
                offset = 0
                while offset < size:
                    block = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
                    if not block:
                        raise VerificationError(self.label + " file ended while being hashed: " + relative)
                    digest.update(block)
                    offset += len(block)
                if os.pread(descriptor, 1, size):
                    raise VerificationError(self.label + " file grew while being hashed: " + relative)
                if self._identity(os.fstat(descriptor)) != expected:
                    raise VerificationError(self.label + " file changed while being hashed: " + relative)
                records.append({"path": relative, "size": size, "sha256": digest.hexdigest()})
            finally:
                os.close(descriptor)
        self.verify()
        return records

    def close(self) -> None:
        if self.directory_watch is not None:
            self.directory_watch.close()
            self.directory_watch = None
        for descriptor, _identity, _entries in reversed(list(self.directories.values())):
            if descriptor >= 0:
                os.close(descriptor)
        self.directories = {}
        self.files = {}

    def __enter__(self) -> "HeldRecursiveInventory":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


def _reject_duplicate_json_keys(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError("duplicate JSON key: " + key)
        result[key] = value
    return result


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    descriptor = _open_regular_nofollow(path, "release artifact")
    try:
        info = os.fstat(descriptor)
        remaining = info.st_size
        offset = 0
        while remaining:
            chunk = os.pread(descriptor, min(1024 * 1024, remaining), offset)
            if not chunk:
                raise VerificationError("release artifact changed while being hashed")
            digest.update(chunk)
            offset += len(chunk)
            remaining -= len(chunk)
        if os.pread(descriptor, 1, offset):
            raise VerificationError("release artifact changed while being hashed")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _open_regular_nofollow(
    path: pathlib.Path, label: str, require_nonempty: bool = True
) -> int:
    try:
        before = path.lstat()
    except OSError as exc:
        raise VerificationError(label + " is missing: " + str(path)) from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise VerificationError(label + " must be one regular non-symlink file")
    if before.st_nlink != 1 or (require_nonempty and before.st_size <= 0):
        raise VerificationError(
            label + (" must be non-empty and single-link" if require_nonempty else " must be single-link")
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    else:
        raise VerificationError("O_NOFOLLOW is required for release verification")
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise VerificationError(label + " could not be bound without following links") from exc
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or (before.st_dev, before.st_ino, before.st_size)
        != (opened.st_dev, opened.st_ino, opened.st_size)
    ):
        os.close(descriptor)
        raise VerificationError(label + " changed while it was bound")
    return descriptor


def stable_file_snapshot(path: pathlib.Path, destination: pathlib.Path) -> Tuple[str, int]:
    descriptor = _open_regular_nofollow(path, "distribution artifact")
    try:
        info = os.fstat(descriptor)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        output = os.open(destination, flags, 0o600)
        digest = hashlib.sha256()
        try:
            remaining = info.st_size
            offset = 0
            while remaining:
                chunk = os.pread(descriptor, min(1024 * 1024, remaining), offset)
                if not chunk:
                    raise VerificationError("distribution artifact changed during snapshot")
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(output, view)
                    if written <= 0:
                        raise VerificationError("distribution artifact snapshot write failed")
                    view = view[written:]
                remaining -= len(chunk)
                offset += len(chunk)
            if os.pread(descriptor, 1, offset):
                raise VerificationError("distribution artifact changed during snapshot")
            os.fsync(output)
        finally:
            os.close(output)
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        ):
            raise VerificationError("distribution artifact changed during snapshot")
        copied = sha256_file(destination)
        if copied != digest.hexdigest():
            raise VerificationError("distribution artifact snapshot digest mismatch")
        return copied, info.st_size
    finally:
        os.close(descriptor)


def _read_regular(
    path: pathlib.Path,
    label: str,
    maximum: int = MAX_METADATA_BYTES,
    allow_empty: bool = False,
) -> bytes:
    descriptor = _open_regular_nofollow(path, label, require_nonempty=not allow_empty)
    try:
        info = os.fstat(descriptor)
        if info.st_size > maximum:
            raise VerificationError(label + " exceeds the size limit")
        payload = os.pread(descriptor, info.st_size, 0)
        if len(payload) != info.st_size or os.pread(descriptor, 1, info.st_size):
            raise VerificationError(label + " changed while being read")
        return payload
    finally:
        os.close(descriptor)


def read_plist(path: pathlib.Path, label: str) -> Dict[str, Any]:
    try:
        value = plistlib.loads(_read_regular(path, label))
    except VerificationError:
        raise
    except (plistlib.InvalidFileException, ValueError, TypeError) as exc:
        raise VerificationError(label + " is not a valid property list") from exc
    if type(value) is not dict:
        raise VerificationError(label + " must be a property-list dictionary")
    return value


def read_json(path: pathlib.Path, label: str) -> Dict[str, Any]:
    try:
        value = json.loads(
            _read_regular(path, label).decode("utf-8", "strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except VerificationError:
        raise
    except (UnicodeError, json.JSONDecodeError, DuplicateKeyError) as exc:
        raise VerificationError(label + " is not exact JSON") from exc
    if type(value) is not dict:
        raise VerificationError(label + " must be one JSON object")
    return value


def _json_bytes(payload: bytes, label: str) -> Dict[str, Any]:
    try:
        value = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (UnicodeError, json.JSONDecodeError, DuplicateKeyError) as exc:
        raise VerificationError(label + " is not exact JSON") from exc
    if type(value) is not dict:
        raise VerificationError(label + " must be one JSON object")
    return value


class ReviewedWinnReleaseCustody:
    """Authenticate Winn provenance against the signed Winn release it names.

    The release directory written by tools/winn_release.py is verified in
    process by the held driver module, trusting exactly the Ed25519 key held
    from tools/winn_release_authority.json (never --allow-unsigned). The
    packaged provenance must then name that manifest digest and that key, and
    every Apple slice digest it records must be the manifest's reproducible
    (build A == build B) digest of the held release bytes.
    """

    ARCHIVES = {
        "iphoneos_arm64": "datapath-ios-arm64",
        "iphonesimulator_arm64": "datapath-iossimulator-arm64",
        "iphonesimulator_x86_64": "datapath-iossimulator-amd64",
        "macosx_arm64": "datapath-archive-darwin-arm64",
        "macosx_x86_64": "datapath-archive-darwin-amd64",
    }
    PRODUCER_FIELDS = {
        "builder_sha256": "build_winn_protocol_engine.sh",
        "driver_sha256": "winn_release.py",
        "toolchain_pins_sha256": "toolchain-pins.json",
    }

    def __init__(self, release_dir: Optional[pathlib.Path] = None) -> None:
        if release_dir is None and os.environ.get("WINS_WINN_RELEASE_DIR"):
            release_dir = pathlib.Path(os.environ["WINS_WINN_RELEASE_DIR"])
        self.release_dir = release_dir
        self.module_binding: Optional[HeldFile] = None
        self.authority_binding: Optional[HeldFile] = None
        self.module: Any = None
        self.module_name = ""
        self.trusted_key = ""
        self.release_bindings: List[HeldFile] = []

    def __enter__(self) -> "ReviewedWinnReleaseCustody":
        try:
            if self.release_dir is None:
                raise VerificationError(
                    "the signed Winn release directory is required (--winn-release DIR or WINS_WINN_RELEASE_DIR)"
                )
            release = pathlib.Path(os.path.abspath(os.path.normpath(self.release_dir)))
            if release.is_symlink() or not release.is_dir():
                raise VerificationError("the Winn release directory is missing or symbolic: " + str(release))
            self.release_dir = release
            self.authority_binding = HeldFile(WINN_RELEASE_AUTHORITY, "Winn release authority pin")
            authority = _json_bytes(
                self.authority_binding.read(MAX_METADATA_BYTES), "Winn release authority pin"
            )
            key = authority.get("public_key")
            if (
                authority.get("contract") != "winsvpn-winn-release-authority-v1"
                or authority.get("algorithm") != "ed25519"
                or type(key) is not str
                or re.fullmatch(r"[0-9a-f]{64}", key) is None
            ):
                raise VerificationError("Winn release authority pin is malformed")
            self.trusted_key = key
            self.module_binding = HeldFile(WINN_RELEASE_DRIVER, "Winn release driver")
            source = self.module_binding.read(MAX_FILE_BYTES)
            self.module_name = "_winsvpn_retained_winn_release_" + uuid.uuid4().hex
            self.module = types.ModuleType(self.module_name)
            self.module.__file__ = str(WINN_RELEASE_DRIVER)
            self.module.__package__ = ""
            sys.modules[self.module_name] = self.module
            exec(compile(source, str(WINN_RELEASE_DRIVER), "exec"), self.module.__dict__)
            self.module_binding.verify()
            return self
        except BaseException as exc:
            self.close()
            if isinstance(exc, VerificationError):
                raise
            raise VerificationError("the Winn release driver could not be retained: " + str(exc)) from exc

    def _hold(self, relative: Any, label: str) -> HeldFile:
        if type(relative) is not str or relative.startswith("/") or ".." in pathlib.PurePosixPath(relative).parts:
            raise VerificationError(label + " path is not release-relative")
        binding = HeldFile(self.release_dir / relative, label)
        self.release_bindings.append(binding)
        return binding

    def authenticate(
        self, provenance_bytes: bytes, awg_bytes: bytes, xray_bytes: bytes
    ) -> Dict[str, Any]:
        if self.module is None or self.module_binding is None or self.authority_binding is None:
            raise VerificationError("Winn release custody is not retained")
        provenance = _json_bytes(provenance_bytes, "Winn v3 provenance")
        try:
            manifest_binding = self._hold("manifest.json", "Winn release manifest")
            signature_binding = self._hold("manifest.sig.json", "Winn release signature")
            manifest_bytes = manifest_binding.read(MAX_METADATA_BYTES)
            signature_bytes = signature_binding.read(MAX_METADATA_BYTES)
            manifest = _json_bytes(manifest_bytes, "Winn release manifest")
            signature = _json_bytes(signature_bytes, "Winn release signature")
            entries = manifest.get("artifacts")
            if type(entries) is not list:
                raise VerificationError("Winn release manifest artifacts are malformed")
            by_target = {}
            for entry in entries:
                if type(entry) is not dict or entry.get("target") in by_target:
                    raise VerificationError("Winn release manifest artifacts are malformed")
                by_target[entry.get("target")] = entry
            held_slices = {}
            for key, target in self.ARCHIVES.items():
                entry = by_target.get(target)
                if type(entry) is not dict:
                    raise VerificationError("Winn release does not contain the Apple slice " + target)
                held_slices[key] = (
                    entry,
                    self._hold(entry.get("path"), "Winn release " + target),
                    self._hold(entry.get("header_path"), "Winn release " + target + " header"),
                )
            # The held driver checks the Ed25519 signature over exactly the
            # held manifest bytes with exactly the held pinned key, and the
            # manifest it returns is parsed from those same bytes; then every
            # artifact digest, size, and build A/B match on disk. Nothing is
            # re-read by path between the signature check and the decision.
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                verified = self.module.verify_manifest_payload(
                    manifest_bytes, signature_bytes, bytes.fromhex(self.trusted_key)
                )
                if verified != manifest:
                    raise VerificationError("the Winn release did not verify")
                self.module.verify_artifacts(self.release_dir, verified)
        except VerificationError:
            raise
        except Exception as exc:
            raise VerificationError("the Winn release did not verify: " + str(exc)) from exc

        manifest_sha256 = _sha256_bytes(manifest_bytes)
        if (
            signature.get("public_key") != self.trusted_key
            or signature.get("manifest_sha256") != manifest_sha256
        ):
            raise VerificationError("the Winn release is not signed by the pinned release authority")
        release = provenance.get("release")
        if type(release) is not dict:
            raise VerificationError("Winn provenance has no release record")
        if (
            release.get("signature_state") != "signed"
            or release.get("signature_public_key") != self.trusted_key
            or release.get("manifest_sha256") != manifest_sha256
            or release.get("contract") != "winsvpn-winn-release-manifest-v1"
        ):
            raise VerificationError(
                "Winn provenance is not bound to the signed release manifest and pinned key"
            )
        source = manifest.get("source") if type(manifest.get("source")) is dict else {}
        toolchains = manifest.get("toolchains") if type(manifest.get("toolchains")) is dict else {}
        go = toolchains.get("go") if type(toolchains.get("go")) is dict else {}
        producer = manifest.get("producer") if type(manifest.get("producer")) is dict else {}
        expected_release = {
            "contract": "winsvpn-winn-release-manifest-v1",
            "go": {
                field: go.get(field)
                for field in ("archive_sha256", "executable_sha256", "install_tree_sha256", "version")
            },
            "manifest_sha256": manifest_sha256,
            "producer": {
                field: producer.get(name, producer.get(field))
                for field, name in self.PRODUCER_FIELDS.items()
            },
            "signature_public_key": self.trusted_key,
            "signature_state": "signed",
            "source": {field: source.get(field) for field in ("binding", "commit", "tree_sha256")},
        }
        if release != expected_release:
            raise VerificationError("Winn provenance release record does not match the signed manifest")
        archives = provenance.get("archives")
        if type(archives) is not dict or set(archives) != set(self.ARCHIVES):
            raise VerificationError("Winn provenance archive closure is not exact")
        for key, (entry, archive, header) in held_slices.items():
            record = archives[key]
            digest = entry.get("sha256")
            if not (digest == entry.get("build_a_sha256") == entry.get("build_b_sha256")):
                raise VerificationError("Winn release slice was not reproduced: " + key)
            if archive.sha256() != digest or header.sha256() != entry.get("header_sha256"):
                raise VerificationError("Winn release slice bytes changed after verification: " + key)
            if type(record) is not dict or any(
                record.get(field) != value
                for field, value in (
                    ("build_a_sha256", digest),
                    ("build_b_sha256", digest),
                    ("header_sha256", entry.get("header_sha256")),
                    ("sha256", digest),
                    ("target", self.ARCHIVES[key]),
                )
            ):
                raise VerificationError("Winn provenance archive binding drifted: " + key)
        self.verify()
        awg = _json_bytes(awg_bytes, "AWG provenance")
        xray = _json_bytes(xray_bytes, "Xray provenance")
        # The Winn engine is now bound to the signed release. The AWG bridge
        # (and the Xray replacement it links) is bound to the reviewed source,
        # Go toolchain, and module pins; the caller then binds every packaged
        # engine's bytes to these digests.
        engine_sha256, engine_normalized_sha256 = self._authenticate_awg_xray(
            awg, xray, provenance
        )
        self.verify()
        return {
            "winn": provenance,
            "engine_sha256": engine_sha256,
            "engine_signature_normalized_sha256": engine_normalized_sha256,
        }

    @staticmethod
    def _reviewed_go_toolchain() -> Dict[str, Any]:
        with HeldFile(TOOLCHAIN_PINS, "toolchain pins") as held:
            pins = _json_bytes(held.read(MAX_METADATA_BYTES), "toolchain pins")
        tools = pins.get("tools") if type(pins.get("tools")) is dict else {}
        go = tools.get("go") if type(tools.get("go")) is dict else {}
        archives = go.get("archive_sha256") if type(go.get("archive_sha256")) is dict else {}
        expected = {
            "darwin_amd64_archive_sha256": archives.get("darwin_amd64"),
            "darwin_arm64_archive_sha256": archives.get("darwin_arm64"),
            "version": go.get("version"),
        }
        if (
            type(expected["version"]) is not str
            or re.fullmatch(r"[0-9]+\.[0-9]+(\.[0-9]+)?", expected["version"]) is None
            or any(
                type(expected[field]) is not str
                or re.fullmatch(r"[0-9a-f]{64}", expected[field]) is None
                for field in ("darwin_amd64_archive_sha256", "darwin_arm64_archive_sha256")
            )
        ):
            raise VerificationError(
                "unpinned Go toolchain: tools/toolchain-pins.json needs tools.go.version "
                "and tools.go.archive_sha256.darwin_amd64/darwin_arm64"
            )
        return expected

    def _authenticate_awg_xray(
        self, awg: Dict[str, Any], xray: Dict[str, Any], winn: Dict[str, Any]
    ) -> Tuple[Dict[str, str], Dict[str, Optional[str]]]:
        unpinned = sorted(
            group + "." + field
            for group, pins in (
                ("source", REVIEWED_AWG_SOURCE_PINS),
                ("xray_replacement", REVIEWED_AWG_XRAY_REPLACEMENT_PINS),
            )
            for field, value in pins.items()
            if type(value) is not str or not value
        )
        if unpinned:
            raise VerificationError(
                "unpinned AWG provenance: no reviewed pin for "
                + ", ".join(unpinned)
                + "; measure it on a networked host and pin it in "
                "tools/build_apple_wg_go_bridge.sh and tools/verify_macos_release_artifact.py"
            )
        expected = {
            "source": dict(REVIEWED_AWG_SOURCE_PINS),
            "go_toolchain": self._reviewed_go_toolchain(),
            "xray_replacement": dict(REVIEWED_AWG_XRAY_REPLACEMENT_PINS),
        }
        for key, value in expected.items():
            if awg.get(key) != value:
                raise VerificationError("AWG provenance " + key + " does not match its reviewed pin")
        bridge_digest = awg.get("bridge_provenance_sha256")
        if type(bridge_digest) is not str or re.fullmatch(r"[0-9a-f]{64}", bridge_digest) is None:
            raise VerificationError("AWG provenance bridge_provenance_sha256 is malformed")

        def macos_wrapper(document: Dict[str, Any], label: str) -> Dict[str, Any]:
            wrappers = document.get("wrappers")
            record = wrappers.get("macosx") if type(wrappers) is dict else None
            if type(record) is not dict:
                raise VerificationError(label + " provenance lacks its macOS wrapper record")
            return record

        macos_awg = macos_wrapper(awg, "AWG")
        macos_xray = macos_wrapper(xray, "Xray")
        macos_winn = macos_wrapper(winn, "Winn v3")
        awg_engine = macos_awg.get("amneziawg_packet_engine")
        awg_transport = macos_awg.get("xray_vless_ws_transport")
        records = {
            "amneziawg_packet_engine": awg_engine if type(awg_engine) is dict else {},
            "xray_vless_ws_transport": macos_xray,
            "winn_packet_engine": macos_winn,
        }
        digests = {component: record.get("sha256") for component, record in records.items()}
        for component, digest in digests.items():
            if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise VerificationError(component + " provenance digest is malformed")
        normalized = {
            component: record.get(SIGNATURE_NORMALIZED_FIELD)
            for component, record in records.items()
        }
        for component, digest in normalized.items():
            if digest is not None and (
                type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            ):
                raise VerificationError(
                    component + " signature-normalized provenance digest is malformed"
                )
        if (
            type(awg_transport) is not dict
            or awg_transport.get("sha256") != digests["xray_vless_ws_transport"]
            or awg_transport.get(SIGNATURE_NORMALIZED_FIELD)
            != normalized["xray_vless_ws_transport"]
        ):
            raise VerificationError(
                "Xray provenance is not the transport recorded by the pinned AWG wrapper build"
            )
        return digests, normalized

    def verify(self) -> None:
        if self.module_binding is None or self.authority_binding is None:
            raise VerificationError("Winn release custody is closed")
        self.module_binding.verify()
        self.authority_binding.verify()
        for binding in self.release_bindings:
            binding.verify()

    def close(self) -> None:
        for binding in reversed(self.release_bindings):
            binding.close()
        self.release_bindings = []
        for name in ("authority_binding", "module_binding"):
            binding = getattr(self, name)
            if binding is not None:
                binding.close()
                setattr(self, name, None)
        if self.module_name:
            sys.modules.pop(self.module_name, None)
            self.module_name = ""
        self.module = None

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


def _resolve_schema_node(schema: Mapping[str, Any], node: Mapping[str, Any]) -> Mapping[str, Any]:
    reference = node.get("$ref")
    if reference is None:
        return node
    if type(reference) is not str or not reference.startswith("#/$defs/"):
        raise VerificationError("Winn provenance schema contains an unsupported reference")
    name = reference.rsplit("/", 1)[-1]
    definitions = schema.get("$defs")
    if type(definitions) is not dict or type(definitions.get(name)) is not dict:
        raise VerificationError("Winn provenance schema reference is unresolved: " + reference)
    return definitions[name]


def _validate_json_schema(
    instance: Any,
    schema: Mapping[str, Any],
    raw_node: Mapping[str, Any],
    path: str,
) -> None:
    node = _resolve_schema_node(schema, raw_node)
    all_of = node.get("allOf", [])
    if type(all_of) is not list or any(type(item) is not dict for item in all_of):
        raise VerificationError("Winn provenance schema has malformed allOf at " + path)
    for index, subschema in enumerate(all_of):
        _validate_json_schema(instance, schema, subschema, path + ".allOf[" + str(index) + "]")

    expected_type = node.get("type")
    if expected_type == "object":
        if type(instance) is not dict:
            raise VerificationError(path + " must be an object")
        required = node.get("required", [])
        properties = node.get("properties", {})
        if type(required) is not list or type(properties) is not dict:
            raise VerificationError("Winn provenance schema object is malformed at " + path)
        for key in required:
            if type(key) is not str or key not in instance:
                raise VerificationError(path + " omits required field " + str(key))
        for key, value in instance.items():
            child = properties.get(key)
            if type(child) is dict:
                _validate_json_schema(value, schema, child, path + "." + key)
            elif node.get("additionalProperties", True) is False:
                raise VerificationError(path + " has extra field " + key)
    elif expected_type == "array":
        if type(instance) is not list:
            raise VerificationError(path + " must be an array")
        minimum_items = node.get("minItems")
        if type(minimum_items) is int and len(instance) < minimum_items:
            raise VerificationError(path + " has too few items")
        items = node.get("items")
        if type(items) is dict:
            for index, value in enumerate(instance):
                _validate_json_schema(value, schema, items, path + "[" + str(index) + "]")
    elif expected_type == "string":
        if type(instance) is not str:
            raise VerificationError(path + " must be a string")
        minimum_length = node.get("minLength")
        if type(minimum_length) is int and len(instance) < minimum_length:
            raise VerificationError(path + " is too short")
        pattern = node.get("pattern")
        if type(pattern) is str and re.search(pattern, instance) is None:
            raise VerificationError(path + " does not match its required pattern")
    elif expected_type == "integer":
        if type(instance) is not int:
            raise VerificationError(path + " must be an integer")
        minimum = node.get("minimum")
        if type(minimum) is int and instance < minimum:
            raise VerificationError(path + " is below its minimum")
    elif expected_type is not None:
        raise VerificationError("Winn provenance schema uses unsupported type " + str(expected_type))

    if "const" in node and (
        instance != node["const"] or type(instance) is not type(node["const"])
    ):
        raise VerificationError(path + " does not match its exact required value")
    enum = node.get("enum")
    if enum is not None and (type(enum) is not list or instance not in enum):
        raise VerificationError(path + " is outside its allowed values")


def _safe_relative_symlink(path: pathlib.Path, root: pathlib.Path) -> str:
    try:
        target = os.readlink(path)
    except OSError as exc:
        raise VerificationError("bundle symlink is unreadable: " + str(path)) from exc
    if not target or os.path.isabs(target):
        raise VerificationError("bundle contains an absolute or empty symlink: " + str(path))
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, RuntimeError, ValueError) as exc:
        raise VerificationError("bundle symlink is broken, cyclic, or escapes: " + str(path)) from exc
    return target


def tree_records(root: pathlib.Path) -> List[Dict[str, Any]]:
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise VerificationError("application bundle is missing: " + str(root)) from exc
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise VerificationError("application bundle must be a real directory")
    records: List[Dict[str, Any]] = []
    seen_casefold: Set[str] = set()
    seen_inodes: Dict[Tuple[int, int], str] = {}
    total_bytes = 0
    for directory, names, filenames in os.walk(root, topdown=True, followlinks=False):
        names.sort()
        filenames.sort()
        for name in list(names) + list(filenames):
            path = pathlib.Path(directory) / name
            relative = path.relative_to(root).as_posix()
            folded = relative.casefold()
            if folded in seen_casefold:
                raise VerificationError("bundle contains a case-colliding path: " + relative)
            seen_casefold.add(folded)
            try:
                info = path.lstat()
            except OSError as exc:
                raise VerificationError("bundle entry disappeared: " + relative) from exc
            mode = stat.S_IMODE(info.st_mode)
            record: Dict[str, Any] = {"path": relative, "mode": mode}
            if stat.S_ISLNK(info.st_mode):
                record.update({"type": "symlink", "target": _safe_relative_symlink(path, root)})
                if name in names:
                    names.remove(name)
            elif stat.S_ISDIR(info.st_mode):
                if mode & 0o022:
                    raise VerificationError("bundle code-bearing directory is group/world writable: " + relative)
                record.update({"type": "dir"})
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    previous = seen_inodes.get((info.st_dev, info.st_ino), "another path")
                    raise VerificationError("bundle contains hardlinked content: " + relative + " and " + previous)
                seen_inodes[(info.st_dev, info.st_ino)] = relative
                if info.st_size > MAX_FILE_BYTES:
                    raise VerificationError("bundle file exceeds the size limit: " + relative)
                payload = _read_regular(
                    path, "bundle file " + relative, MAX_FILE_BYTES, allow_empty=True
                )
                total_bytes += len(payload)
                record.update(
                    {
                        "type": "file",
                        "bytes": len(payload),
                        "sha256": _sha256_bytes(payload),
                    }
                )
            else:
                raise VerificationError("bundle contains a special file: " + relative)
            records.append(record)
            if len(records) > MAX_TREE_ENTRIES or total_bytes > MAX_TREE_BYTES:
                raise VerificationError("bundle exceeds the inspection budget")
    records.sort(key=lambda item: str(item["path"]))
    return records


def tree_digest(records: Sequence[Mapping[str, Any]]) -> str:
    canonical = json.dumps(list(records), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _sha256_bytes(canonical)


def _macho_architectures_from_bytes(data: bytes, label: str) -> Set[str]:
    if len(data) < 8:
        raise VerificationError(label + " is a truncated Mach-O")
    magic = data[:4]
    if magic in THIN_MAGICS:
        endian = THIN_MAGICS[magic]
        cputype = struct.unpack_from(endian + "I", data, 4)[0]
        architecture = CPU_TYPES.get(cputype)
        if architecture is None:
            raise VerificationError(label + " has an unsupported Mach-O architecture")
        return {architecture}
    if magic not in FAT_MAGICS:
        raise VerificationError(label + " is not Mach-O")
    endian, fat64 = FAT_MAGICS[magic]
    count = struct.unpack_from(endian + "I", data, 4)[0]
    if count <= 0 or count > 32:
        raise VerificationError(label + " has an invalid universal header")
    entry_size = 32 if fat64 else 20
    if len(data) < 8 + count * entry_size:
        raise VerificationError(label + " has a truncated universal header")
    architectures: Set[str] = set()
    ranges: List[Tuple[int, int]] = []
    for index in range(count):
        offset = 8 + index * entry_size
        cputype = struct.unpack_from(endian + "I", data, offset)[0]
        architecture = CPU_TYPES.get(cputype)
        if architecture is None or architecture in architectures:
            raise VerificationError(label + " has unsupported or duplicate architecture slices")
        architectures.add(architecture)
        if fat64:
            slice_offset, slice_size = struct.unpack_from(endian + "QQ", data, offset + 8)
        else:
            slice_offset, slice_size = struct.unpack_from(endian + "II", data, offset + 8)
        if slice_size <= 0 or slice_offset + slice_size > len(data):
            raise VerificationError(label + " has an out-of-bounds architecture slice")
        ranges.append((slice_offset, slice_offset + slice_size))
    ranges.sort()
    for previous, current in zip(ranges, ranges[1:]):
        if previous[1] > current[0]:
            raise VerificationError(label + " has overlapping architecture slices")
    return architectures


def macho_architectures(path: pathlib.Path, relative: str) -> Set[str]:
    payload = _read_regular(path, "Mach-O " + relative, MAX_FILE_BYTES)
    return _macho_architectures_from_bytes(payload, relative)


def _is_macho(path: pathlib.Path) -> bool:
    try:
        info = path.lstat()
    except OSError as exc:
        raise VerificationError("bundle file disappeared: " + str(path)) from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return False
    if info.st_size < 4:
        return False
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        return os.read(descriptor, 4) in MACHO_MAGICS
    finally:
        os.close(descriptor)


def _framework_executable(framework: pathlib.Path) -> pathlib.Path:
    info = read_plist(framework / "Versions/A/Resources/Info.plist", framework.name + " Info.plist")
    executable_name = info.get("CFBundleExecutable")
    if type(executable_name) is not str or not executable_name:
        raise VerificationError(framework.name + " has no CFBundleExecutable")
    executable = framework / "Versions" / "A" / executable_name
    if executable.is_symlink():
        raise VerificationError(framework.name + " canonical executable must not be a symlink")
    return executable


def audit_code_topology(app: pathlib.Path) -> Dict[str, Any]:
    contents = app / "Contents"
    host_info = read_plist(contents / "Info.plist", "host Info.plist")
    if host_info.get("CFBundleIdentifier") != HOST_BUNDLE_ID:
        raise VerificationError("host Info.plist bundle identifier is not exact")
    if host_info.get("CFBundlePackageType") != "APPL":
        raise VerificationError("host bundle type is not APPL")
    if host_info.get(RUNTIME_CONTRACT_KEY) != RUNTIME_CONTRACT:
        raise VerificationError("host runtime contract is absent or not exact")
    host_executable_name = host_info.get("CFBundleExecutable")
    if type(host_executable_name) is not str or not host_executable_name:
        raise VerificationError("host executable name is missing")
    host_executable = contents / "MacOS" / host_executable_name

    plugins = contents / "PlugIns"
    if not plugins.is_dir() or plugins.is_symlink():
        raise VerificationError("host must contain the PacketTunnel extension directory")
    children = sorted(path.name for path in plugins.iterdir())
    if children != ["PacketTunnel.appex"]:
        raise VerificationError("host must contain exactly one PacketTunnel.appex")
    tunnel = plugins / "PacketTunnel.appex"
    if tunnel.is_symlink() or not tunnel.is_dir():
        raise VerificationError("PacketTunnel must be one contained, real extension bundle")
    tunnel_info = read_plist(tunnel / "Contents/Info.plist", "PacketTunnel Info.plist")
    if tunnel_info.get("CFBundleIdentifier") != TUNNEL_BUNDLE_ID:
        raise VerificationError("PacketTunnel Info.plist bundle identifier is not exact")
    if tunnel_info.get("CFBundlePackageType") != "XPC!":
        raise VerificationError("PacketTunnel bundle type is not XPC!")
    extension = tunnel_info.get("NSExtension")
    if type(extension) is not dict or extension.get("NSExtensionPointIdentifier") != "com.apple.networkextension.packet-tunnel":
        raise VerificationError("PacketTunnel extension point is not exact")
    if tunnel_info.get(RUNTIME_CONTRACT_KEY) != RUNTIME_CONTRACT:
        raise VerificationError("PacketTunnel runtime contract is absent or not exact")
    tunnel_executable_name = tunnel_info.get("CFBundleExecutable")
    if type(tunnel_executable_name) is not str or not tunnel_executable_name:
        raise VerificationError("PacketTunnel executable name is missing")
    tunnel_executable = tunnel / "Contents/MacOS" / tunnel_executable_name

    frameworks_root = contents / "Frameworks"
    if not frameworks_root.is_dir() or frameworks_root.is_symlink():
        raise VerificationError("host Frameworks directory is missing")
    engines: Dict[str, pathlib.Path] = {}
    engine_framework_names = {str(spec["framework"]) for spec in ENGINE_FRAMEWORKS.values()}
    for component, spec in ENGINE_FRAMEWORKS.items():
        framework = frameworks_root / str(spec["framework"])
        if not framework.is_dir() or framework.is_symlink():
            raise VerificationError("required engine framework is missing or unsafe: " + framework.name)
        engine_info = read_plist(
            framework / "Versions/A/Resources/Info.plist", framework.name + " Info.plist"
        )
        if engine_info.get("CFBundleIdentifier") != spec["identifier"]:
            raise VerificationError("engine framework identifier is not exact: " + framework.name)
        engines[component] = _framework_executable(framework)

    forbidden_bundles: List[str] = []
    loose_dylibs: List[str] = []
    macho_files: List[pathlib.Path] = []
    executable_files: List[pathlib.Path] = []
    for record in tree_records(app):
        relative = str(record["path"])
        folded = relative.casefold()
        basename = pathlib.PurePosixPath(relative).name.casefold()
        if any(basename.endswith(suffix) for suffix in PRIVATE_SYMBOL_SUFFIXES):
            raise VerificationError("private symbol or profiling file is packaged: " + relative)
        if any(fragment.casefold() in folded for fragment in FORBIDDEN_CODE_NAME_FRAGMENTS):
            raise VerificationError("debug, profile, or test content is packaged: " + relative)
        if record["type"] != "file":
            continue
        path = app / pathlib.PurePosixPath(relative)
        mode = int(record["mode"])
        if mode & 0o111:
            executable_files.append(path)
            if mode & 0o022:
                raise VerificationError("executable content is group/world writable: " + relative)
        if basename.endswith(".dylib"):
            loose_dylibs.append(relative)
        if _is_macho(path):
            macho_files.append(path)
            if mode & 0o022:
                raise VerificationError("Mach-O content is group/world writable: " + relative)

    if loose_dylibs:
        raise VerificationError("loose dylibs are forbidden: " + ", ".join(sorted(loose_dylibs)))
    for path in app.rglob("*"):
        if path.is_symlink() or not path.is_dir():
            continue
        folded = path.name.casefold()
        if folded.endswith((".app", ".appex", ".xpc", ".plugin", ".bundle")):
            relative = path.relative_to(app).as_posix()
            if path != tunnel and not relative.startswith("Contents/Frameworks/"):
                forbidden_bundles.append(relative)
    if forbidden_bundles:
        raise VerificationError("unexpected nested code bundles are present: " + ", ".join(sorted(forbidden_bundles)))

    allowed_executable_paths: Set[pathlib.Path] = {host_executable, tunnel_executable}
    for path in macho_files:
        relative = path.relative_to(app).as_posix()
        if relative.startswith("Contents/Frameworks/"):
            allowed_executable_paths.add(path)
    unexpected_executable = [
        path.relative_to(app).as_posix()
        for path in executable_files
        if path not in allowed_executable_paths and not path.is_symlink()
    ]
    if unexpected_executable:
        raise VerificationError("unexpected executable content is present: " + ", ".join(sorted(unexpected_executable)))
    if host_executable not in macho_files or tunnel_executable not in macho_files:
        raise VerificationError("host or PacketTunnel executable is missing or not Mach-O")
    if not engine_framework_names.issubset({path.name for path in frameworks_root.iterdir()}):
        raise VerificationError("engine framework cardinality is incomplete")
    return {
        "host_info": host_info,
        "host_executable": host_executable,
        "tunnel": tunnel,
        "tunnel_info": tunnel_info,
        "tunnel_executable": tunnel_executable,
        "engines": engines,
        "macho_files": sorted(macho_files, key=lambda item: item.as_posix()),
    }


def _privacy_accessed_map(value: Mapping[str, Any], label: str) -> Dict[str, frozenset[str]]:
    accessed = value.get("NSPrivacyAccessedAPITypes", [])
    if type(accessed) is not list:
        raise VerificationError(label + " accessed API list is malformed")
    result: Dict[str, frozenset[str]] = {}
    for entry in accessed:
        if type(entry) is not dict:
            raise VerificationError(label + " accessed API entry is malformed")
        category = entry.get("NSPrivacyAccessedAPIType")
        reasons = entry.get("NSPrivacyAccessedAPITypeReasons")
        if type(category) is not str or type(reasons) is not list:
            raise VerificationError(label + " accessed API entry is malformed")
        if category in result or any(type(reason) is not str or not reason for reason in reasons):
            raise VerificationError(label + " accessed API entry is duplicated or malformed")
        if len(reasons) != len(set(reasons)):
            raise VerificationError(label + " accessed API reasons are duplicated")
        result[category] = frozenset(reasons)
    return result


def verify_privacy_manifest(
    path: pathlib.Path,
    label: str,
    expected_reasons: Mapping[str, frozenset[str]],
    expected_collected: frozenset[str],
) -> None:
    if path.is_symlink():
        raise VerificationError(label + " privacy manifest must not be a symlink")
    value = read_plist(path, label + " privacy manifest")
    if value.get("NSPrivacyTracking") is not False or value.get("NSPrivacyTrackingDomains") != []:
        raise VerificationError(label + " privacy manifest enables tracking")
    if _privacy_accessed_map(value, label) != dict(expected_reasons):
        raise VerificationError(label + " privacy API declarations are not exact")
    collected = value.get("NSPrivacyCollectedDataTypes")
    if type(collected) is not list:
        raise VerificationError(label + " privacy collected-data list is malformed")
    by_type: Dict[str, Dict[str, Any]] = {}
    for entry in collected:
        if type(entry) is not dict or type(entry.get("NSPrivacyCollectedDataType")) is not str:
            raise VerificationError(label + " privacy collected-data entry is malformed")
        data_type = str(entry["NSPrivacyCollectedDataType"])
        if data_type in by_type:
            raise VerificationError(label + " privacy collected-data entry is duplicated")
        by_type[data_type] = entry
    if frozenset(by_type) != expected_collected:
        raise VerificationError(label + " privacy collected-data declarations are not exact")
    for data_type, entry in by_type.items():
        if (
            entry.get("NSPrivacyCollectedDataTypeLinked") is not True
            or entry.get("NSPrivacyCollectedDataTypeTracking") is not False
            or entry.get("NSPrivacyCollectedDataTypePurposes") != [APP_FUNCTIONALITY_PURPOSE]
        ):
            raise VerificationError(label + " privacy declaration is not production-valid: " + data_type)


def verify_all_privacy(app: pathlib.Path, topology: Mapping[str, Any]) -> None:
    verify_privacy_manifest(
        app / "Contents/Resources/PrivacyInfo.xcprivacy",
        "host",
        HOST_PRIVACY_REASONS,
        HOST_COLLECTED_TYPES,
    )
    tunnel = pathlib.Path(topology["tunnel"])
    verify_privacy_manifest(
        tunnel / "Contents/Resources/PrivacyInfo.xcprivacy",
        "PacketTunnel",
        TUNNEL_PRIVACY_REASONS,
        frozenset(),
    )
    for component, spec in ENGINE_FRAMEWORKS.items():
        framework = app / "Contents/Frameworks" / str(spec["framework"])
        verify_privacy_manifest(
            framework / "Versions/A/Resources/PrivacyInfo.xcprivacy",
            component,
            spec["privacy"],
            frozenset(),
        )


def expected_entitlements(identifier: str, allow_server: bool) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "com.apple.application-identifier": TEAM_ID + "." + identifier,
        "com.apple.developer.team-identifier": TEAM_ID,
        "com.apple.developer.networking.networkextension": ["packet-tunnel-provider"],
        "com.apple.security.app-sandbox": True,
        "com.apple.security.application-groups": [APP_GROUP],
        "com.apple.security.network.client": True,
        "keychain-access-groups": [KEYCHAIN_GROUP],
    }
    if allow_server:
        result["com.apple.security.network.server"] = True
    return result


def verify_entitlements(actual: Mapping[str, Any], expected: Mapping[str, Any], label: str) -> None:
    forbidden = sorted(key for key in actual if key in FORBIDDEN_ENTITLEMENTS)
    if forbidden:
        raise VerificationError(label + " contains debug or unsafe entitlements: " + ", ".join(forbidden))
    if dict(actual) != dict(expected):
        raise VerificationError(label + " signed entitlements are not the exact production map")


def _extract_plist_from_output(output: str, label: str) -> Dict[str, Any]:
    start = output.find("<?xml")
    end = output.rfind("</plist>")
    if start < 0 or end < start:
        if not output.strip():
            return {}
        raise VerificationError(label + " entitlements output is malformed")
    end += len("</plist>")
    try:
        value = plistlib.loads(output[start:end].encode("utf-8", "strict"))
    except (UnicodeError, plistlib.InvalidFileException, ValueError, TypeError) as exc:
        raise VerificationError(label + " signed entitlements are malformed") from exc
    if type(value) is not dict:
        raise VerificationError(label + " signed entitlements are not a dictionary")
    return value


RunFunction = Callable[[Sequence[str], int], subprocess.CompletedProcess[str]]


def run_command(arguments: Sequence[str], timeout: int = 180) -> subprocess.CompletedProcess[str]:
    environment = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": "/var/empty",
        "LANG": "C",
        "LC_ALL": "C",
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
    }
    # The canonical obfuscation adapter's exact secret scan reads the inventory
    # this path names; only the path crosses into the scrubbed environment.
    inventory_path = os.environ.get("WINS_RELEASE_SECRET_INVENTORY")
    if inventory_path:
        environment["WINS_RELEASE_SECRET_INVENTORY"] = inventory_path
    try:
        return subprocess.run(
            list(arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
            shell=False,
            check=False,
            timeout=timeout,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise VerificationError("release tool failed: " + str(arguments[0])) from exc


def require_command(
    runner: RunFunction, arguments: Sequence[str], label: str, timeout: int = 180
) -> str:
    completed = runner(arguments, timeout)
    output = (completed.stdout or "") + (completed.stderr or "")
    if completed.returncode != 0:
        detail = output.strip().replace("\n", " ")[:500]
        raise VerificationError(label + " failed" + (": " + detail if detail else ""))
    return output


def _developer_id_requirement(identifier: Optional[str] = None) -> str:
    requirement = (
        "anchor apple generic and certificate leaf[field."
        + DEVELOPER_ID_APPLICATION_OID
        + "] exists and certificate leaf[subject.OU] = \""
        + TEAM_ID
        + "\""
    )
    if identifier is not None:
        requirement += " and identifier \"" + identifier + "\""
    return requirement


def parse_codesign_details(
    output: str, label: str, require_runtime: bool = True
) -> Dict[str, Any]:
    identifiers = re.findall(r"(?m)^Identifier=([^\r\n]+)$", output)
    teams = re.findall(r"(?m)^TeamIdentifier=([^\r\n]+)$", output)
    authorities = re.findall(r"(?m)^Authority=([^\r\n]+)$", output)
    flags = re.findall(r"(?m)^CodeDirectory[^\r\n]*flags=([^\r\n]+)$", output)
    timestamps = re.findall(r"(?m)^Timestamp=([^\r\n]+)$", output)
    if len(identifiers) != 1 or len(teams) != 1 or len(flags) != 1 or len(timestamps) != 1:
        raise VerificationError(label + " code-signing metadata is incomplete")
    expected_authority = "Developer ID Application: " + OWNER_COMMON_NAME + " (" + TEAM_ID + ")"
    if not authorities or authorities[0] != expected_authority:
        raise VerificationError(label + " is not signed by the exact Developer ID Application identity")
    if teams[0] != TEAM_ID:
        raise VerificationError(label + " is signed by the wrong team")
    if require_runtime and "runtime" not in flags[0]:
        raise VerificationError(label + " does not enable hardened runtime")
    lowered = output.casefold()
    if "signature=adhoc" in lowered or "timestamp=none" in lowered:
        raise VerificationError(label + " is ad hoc or lacks a secure timestamp")
    return {"identifier": identifiers[0], "team": teams[0], "timestamp": timestamps[0]}


def verify_signed_code(
    path: pathlib.Path,
    label: str,
    runner: RunFunction,
    expected_identifier: Optional[str] = None,
    entitlements: Optional[Mapping[str, Any]] = None,
    deep: bool = False,
    require_runtime: bool = True,
    inspect_entitlements: bool = True,
) -> Dict[str, Any]:
    verify_args = ["/usr/bin/codesign", "--verify"]
    if deep:
        verify_args.append("--deep")
    verify_args.extend(
        (
            "--strict=all",
            "--verbose=4",
            "-R=" + _developer_id_requirement(expected_identifier),
            str(path),
        )
    )
    require_command(runner, verify_args, label + " code-signature verification")
    details = require_command(
        runner,
        ["/usr/bin/codesign", "--display", "--verbose=4", str(path)],
        label + " code-signature display",
    )
    parsed = parse_codesign_details(details, label, require_runtime=require_runtime)
    if expected_identifier is not None and parsed["identifier"] != expected_identifier:
        raise VerificationError(label + " signed identifier is not exact")
    if inspect_entitlements:
        entitlement_output = require_command(
            runner,
            ["/usr/bin/codesign", "--display", "--entitlements", "-", "--xml", str(path)],
            label + " signed-entitlement inspection",
        )
        actual_entitlements = _extract_plist_from_output(entitlement_output, label)
        if entitlements is not None:
            verify_entitlements(actual_entitlements, entitlements, label)
        elif actual_entitlements:
            forbidden = sorted(key for key in actual_entitlements if key in FORBIDDEN_ENTITLEMENTS)
            if forbidden:
                raise VerificationError(label + " nested code has forbidden entitlements: " + ", ".join(forbidden))
    return parsed


def verify_all_macho(
    app: pathlib.Path, topology: Mapping[str, Any], runner: RunFunction
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    host = pathlib.Path(topology["host_executable"])
    tunnel_executable = pathlib.Path(topology["tunnel_executable"])
    host_bundle = app
    tunnel_bundle = pathlib.Path(topology["tunnel"])
    verify_signed_code(
        host_bundle,
        "host app",
        runner,
        HOST_BUNDLE_ID,
        # network.server: the App Store sandbox refuses bind(127.0.0.1) without
        # it (EPERM), and the browser-companion IPC listens on IPv4 loopback
        # only (lib/browser_bridge_app_ipc.dart). App Review note: local
        # browser-companion IPC bound to 127.0.0.1, never a public listener.
        expected_entitlements(HOST_BUNDLE_ID, allow_server=True),
        deep=True,
    )
    verify_signed_code(
        tunnel_bundle,
        "PacketTunnel extension",
        runner,
        TUNNEL_BUNDLE_ID,
        expected_entitlements(TUNNEL_BUNDLE_ID, allow_server=True),
        deep=True,
    )
    for path in topology["macho_files"]:
        code_path = pathlib.Path(path)
        relative = code_path.relative_to(app).as_posix()
        architectures = macho_architectures(code_path, relative)
        if architectures != set(REQUIRED_ARCHITECTURES):
            raise VerificationError(
                relative + " must contain exactly arm64 and x86_64; found " + ", ".join(sorted(architectures))
            )
        lipo_output = require_command(
            runner, ["/usr/bin/lipo", "-archs", str(code_path)], relative + " architecture inspection"
        )
        lipo_architectures = set(lipo_output.split())
        if lipo_architectures != set(REQUIRED_ARCHITECTURES):
            raise VerificationError(relative + " lipo architecture result is not exact")
        otool = require_command(
            runner, ["/usr/bin/otool", "-l", str(code_path)], relative + " load-command inspection"
        )
        if re.search(r"(?m)^\s*(?:segname __DWARF|sectname __debug_|sectname __llvm_(?:prf|cov))", otool):
            raise VerificationError(relative + " contains debug, coverage, or profiling sections")
        for value in re.findall(r"(?m)^\s+path\s+([^ ]+)\s+\(offset", otool):
            if value.startswith("/") and not value.startswith(("/System/", "/usr/lib/")):
                raise VerificationError(relative + " has an absolute non-system rpath")
            if value.startswith((".", "~")) or ".." in pathlib.PurePosixPath(value).parts:
                raise VerificationError(relative + " has an unsafe rpath")
        if code_path not in (host, tunnel_executable):
            expected_identifier = None
            for component, engine_path in topology["engines"].items():
                if code_path == pathlib.Path(engine_path):
                    expected_identifier = str(ENGINE_FRAMEWORKS[component]["identifier"])
                    break
            verify_signed_code(
                code_path,
                relative,
                runner,
                expected_identifier=expected_identifier,
                entitlements={},
            )
        results.append({"path": relative, "architectures": sorted(architectures)})
    return results


def signature_normalized_sha256(
    engine: HeldFile, scratch: pathlib.Path, label: str, runner: RunFunction
) -> str:
    """SHA-256 of a held Mach-O with its code signature normalized away.

    A private copy is re-signed ad hoc, which replaces any linker, ad hoc or
    distribution signature on every slice, and the signature is then removed,
    so the digest covers every code and data byte and no signature byte. The
    provenance producers and the cross-store gate run the same procedure.
    Code-signature validity and the Developer ID signer are verified separately.
    """
    copy = scratch / (label + ".signature-normalized")
    engine.snapshot(copy)
    try:
        require_command(
            runner,
            ["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", str(copy)],
            label + " signature normalization",
        )
        require_command(
            runner,
            ["/usr/bin/codesign", "--remove-signature", str(copy)],
            label + " signature removal",
        )
        return sha256_file(copy)
    finally:
        copy.unlink(missing_ok=True)


def _verify_engine_contract_after_external_authentication(
    app: pathlib.Path,
    topology: Mapping[str, Any],
    runner: RunFunction,
    custody: Any,
) -> Dict[str, Any]:
    tunnel_executable = pathlib.Path(topology["tunnel_executable"])
    tunnel_payload = _read_regular(
        tunnel_executable, "PacketTunnel Winn v3 runtime", MAX_FILE_BYTES
    )
    missing_markers = [
        marker.decode("ascii")
        for marker in REQUIRED_WINN3_BINARY_MARKERS
        if marker not in tunnel_payload
    ]
    if missing_markers:
        raise VerificationError(
            "PacketTunnel lacks Winn v3 primary runtime markers: "
            + ", ".join(missing_markers)
        )
    for architecture in sorted(REQUIRED_ARCHITECTURES):
        output = require_command(
            runner,
            ["/usr/bin/nm", "-arch", architecture, "-gjU", str(tunnel_executable)],
            "PacketTunnel Winn v3 " + architecture + " symbol inspection",
        )
        symbols = {line.strip().lstrip("_") for line in output.splitlines() if line.strip()}
        missing = REQUIRED_WINN3_TUNNEL_SYMBOLS - symbols
        if missing:
            raise VerificationError(
                "PacketTunnel Winn v3 "
                + architecture
                + " is missing primary ABI symbols: "
                + ", ".join(sorted(missing))
            )
    resources = app / "Contents/Resources"
    manifest_path = resources / "apple_engine_artifacts_manifest.json"
    awg_path = resources / "apple_awg_31_engine_provenance.json"
    winn_path = resources / "apple_winn_v3_engine_provenance.json"
    xray_path = resources / "apple_xray_vless_ws_engine_provenance.json"
    with tempfile.TemporaryDirectory(prefix="winsvpn-held-engines-") as snapshot_root, contextlib.ExitStack() as stack:
        held = {
            "manifest": stack.enter_context(HeldFile(manifest_path, "engine artifact manifest")),
            "awg": stack.enter_context(HeldFile(awg_path, "AWG provenance")),
            "winn": stack.enter_context(HeldFile(winn_path, "Winn v3 provenance")),
            "xray": stack.enter_context(HeldFile(xray_path, "Xray provenance")),
            "schema": stack.enter_context(HeldFile(WINN_PROVENANCE_SCHEMA, "Winn v3 provenance schema")),
        }
        engine_files = {
            component: stack.enter_context(HeldFile(pathlib.Path(executable), component + " engine"))
            for component, executable in topology["engines"].items()
        }
        custody = stack.enter_context(custody)
        manifest = _json_bytes(held["manifest"].read(MAX_METADATA_BYTES), "engine artifact manifest")
        awg = _json_bytes(held["awg"].read(MAX_METADATA_BYTES), "AWG provenance")
        xray = _json_bytes(held["xray"].read(MAX_METADATA_BYTES), "Xray provenance")
        winn_bytes = held["winn"].read(MAX_METADATA_BYTES)
        winn_schema = _json_bytes(held["schema"].read(MAX_METADATA_BYTES), "Winn v3 provenance schema")
        parsed_winn = _json_bytes(winn_bytes, "Winn v3 provenance")
        _validate_json_schema(parsed_winn, winn_schema, winn_schema, "Winn v3 provenance")
        authenticated = custody.authenticate(
            winn_bytes,
            held["awg"].read(MAX_METADATA_BYTES),
            held["xray"].read(MAX_METADATA_BYTES),
        )
        if type(authenticated) is not dict or set(authenticated) != {
            "winn",
            "engine_sha256",
            "engine_signature_normalized_sha256",
        }:
            raise VerificationError("authenticated Apple engine custody result is malformed")
        winn = authenticated["winn"]
        if winn != parsed_winn:
            raise VerificationError("authenticated Winn provenance bytes changed interpretation")
        authenticated_digests = authenticated["engine_sha256"]
        if (
            type(authenticated_digests) is not dict
            or set(authenticated_digests) != set(RUNTIME_CONTRACT["required_engine_components"])
            or any(type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None
                   for value in authenticated_digests.values())
        ):
            raise VerificationError("authenticated Apple engine digest closure is malformed")
        authenticated_normalized = authenticated["engine_signature_normalized_sha256"]
        if (
            type(authenticated_normalized) is not dict
            or set(authenticated_normalized) != set(RUNTIME_CONTRACT["required_engine_components"])
            or any(
                value is not None
                and (type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None)
                for value in authenticated_normalized.values()
            )
        ):
            raise VerificationError(
                "authenticated Apple engine signature-normalized digest closure is malformed"
            )
        expected_components = set(RUNTIME_CONTRACT["required_engine_components"])
        required_components = manifest.get("required_components")
        optional_components = manifest.get("optional_components")
        staged_components = manifest.get("staged_components")
        if any(
            type(value) is not list
            or any(type(item) is not str or not item for item in value)
            or len(value) != len(set(value))
            for value in (required_components, optional_components, staged_components)
        ):
            raise VerificationError("engine artifact manifest component lists are malformed")
        if (
            manifest.get("schema_version") != 1
            or manifest.get("platform_name") != "macosx"
            or set(required_components) != expected_components
            or optional_components != []
            or set(staged_components) != expected_components
            or manifest.get("secret_material_redacted") is not True
        ):
            raise VerificationError("engine artifact manifest does not require and stage the exact release engines")
        for key, field, label in (
            ("awg", "apple_awg_31_provenance_sha256", "AWG"),
            ("xray", "apple_xray_vless_ws_provenance_sha256", "Xray"),
            ("winn", "apple_winn_v3_provenance_sha256", "Winn v3"),
        ):
            if manifest.get(field) != held[key].sha256():
                raise VerificationError(label + " provenance is not bound by the engine manifest")
        if (
            awg.get("schema_version") != 2
            or awg.get("generation") != "3.1"
            or awg.get("component") != "amneziawg-apple-engine-wrappers"
        ):
            raise VerificationError("AWG provenance is not the production v3.1 contract")
        if xray.get("schema_version") != 1 or xray.get("component") != "xray-apple-vless-ws-engine-wrappers":
            raise VerificationError("Xray v1 fallback provenance is not exact")
        if (
            winn.get("schema_version") != 5
            or winn.get("component") != "winn-apple-engine-wrappers"
            or winn.get("generation") != "v3"
        ):
            raise VerificationError("Winn v3 provenance is not exact schema 5")

        macos_awg = awg.get("wrappers", {}).get("macosx") if type(awg.get("wrappers")) is dict else None
        macos_xray = xray.get("wrappers", {}).get("macosx") if type(xray.get("wrappers")) is dict else None
        macos_winn = winn.get("wrappers", {}).get("macosx") if type(winn.get("wrappers")) is dict else None
        if type(macos_awg) is not dict or type(macos_xray) is not dict or type(macos_winn) is not dict:
            raise VerificationError("engine provenance lacks exact macOS wrapper records")
        if (
            macos_winn.get("path") != "macos/libWinsWinnPacketEngine.dylib"
            or macos_winn.get("architectures") != sorted(REQUIRED_ARCHITECTURES)
            or macos_winn.get("platform") != "MACOS"
            or set(macos_winn.get("slices", {})) != REQUIRED_ARCHITECTURES
        ):
            raise VerificationError("Winn v3 provenance lacks the exact universal macOS slice closure")
        awg_record = macos_awg.get("amneziawg_packet_engine")
        if type(awg_record) is not dict:
            raise VerificationError("AWG provenance lacks its macOS engine record")
        expected_digests = {
            "amneziawg_packet_engine": awg_record.get("sha256"),
            "xray_vless_ws_transport": macos_xray.get("sha256"),
            "winn_packet_engine": macos_winn.get("sha256"),
        }
        expected_normalized = {
            "amneziawg_packet_engine": awg_record.get(SIGNATURE_NORMALIZED_FIELD),
            "xray_vless_ws_transport": macos_xray.get(SIGNATURE_NORMALIZED_FIELD),
            "winn_packet_engine": macos_winn.get(SIGNATURE_NORMALIZED_FIELD),
        }
        if expected_digests != authenticated_digests or expected_normalized != authenticated_normalized:
            raise VerificationError(
                "packaged Apple engine provenance is not bound to external authenticated custody"
            )
        bindings: Dict[str, Any] = {}
        for component, engine in engine_files.items():
            if component not in ENGINE_FRAMEWORKS:
                raise VerificationError("packaged Apple engine component is not recognized")
            else:
                digest = engine.sha256()
                normalized = signature_normalized_sha256(
                    engine, pathlib.Path(snapshot_root), component, runner
                )
                # Staging and Xcode export re-sign the frameworks after their
                # provenance was written, so the raw digest binds only an
                # unsigned copy. A re-signed engine is bound only by the
                # signature-normalized digest from the same authenticated
                # records; a missing or malformed one refuses.
                if expected_digests.get(component) != digest:
                    recorded = authenticated_normalized.get(component)
                    if (
                        type(recorded) is not str
                        or re.fullmatch(r"[0-9a-f]{64}", recorded) is None
                        or normalized != recorded
                    ):
                        raise VerificationError(component + " bytes are not bound to their production provenance")
                snapshot = pathlib.Path(snapshot_root) / component
                engine.snapshot(snapshot)
                for architecture in sorted(REQUIRED_ARCHITECTURES):
                    output = require_command(
                        runner,
                        ["/usr/bin/nm", "-arch", architecture, "-gjU", str(snapshot)],
                        component + " " + architecture + " exported-symbol inspection",
                    )
                    symbols = {line.strip().lstrip("_") for line in output.splitlines() if line.strip()}
                    missing = set(ENGINE_FRAMEWORKS[component]["symbols"]) - symbols
                    if missing:
                        raise VerificationError(
                            component + " " + architecture + " is missing ABI symbols: " + ", ".join(sorted(missing))
                        )
                    engine.verify()
                dependencies = require_command(
                    runner, ["/usr/bin/otool", "-L", str(snapshot)], component + " dependency inspection"
                )
                for dependency in re.findall(r"(?m)^\s+([^ ]+)\s+\(compatibility", dependencies):
                    if dependency.startswith("/") and not dependency.startswith(("/System/", "/usr/lib/")):
                        raise VerificationError(component + " has an absolute non-system dependency")
                if component == "xray_vless_ws_transport" and "@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine" not in dependencies:
                    raise VerificationError("Xray fallback is not chained through the packaged AWG framework")
                engine.verify()
                bindings[component] = {
                    "sha256": digest,
                    SIGNATURE_NORMALIZED_FIELD: normalized,
                    "architectures": sorted(REQUIRED_ARCHITECTURES),
                }
        custody.verify()
        for binding in held.values():
            binding.verify()
        for binding in engine_files.values():
            binding.verify()
        return bindings


def verify_engine_contract(
    app: pathlib.Path,
    topology: Mapping[str, Any],
    runner: RunFunction,
    winn_release: Optional[pathlib.Path] = None,
) -> Dict[str, Any]:
    """Verify engines only through the fixed reviewed external custody boundary."""
    return _verify_engine_contract_after_external_authentication(
        app, topology, runner, ReviewedWinnReleaseCustody(winn_release)
    )


def _parse_uuid_output(output: str, label: str) -> Set[Tuple[str, str]]:
    results: Set[Tuple[str, str]] = set()
    for match in re.finditer(r"(?m)^UUID: ([0-9A-Fa-f-]{36}) \((arm64|x86_64)\)", output):
        try:
            normalized = str(uuid.UUID(match.group(1))).upper()
        except ValueError as exc:
            raise VerificationError(label + " contains a malformed Mach-O UUID") from exc
        pair = (normalized, match.group(2))
        if pair in results:
            raise VerificationError(label + " contains a duplicate Mach-O UUID")
        results.add(pair)
    if not results:
        raise VerificationError(label + " contains no inspectable Mach-O UUIDs")
    return results


def macho_uuids(path: pathlib.Path, label: str, runner: RunFunction) -> Set[Tuple[str, str]]:
    output = require_command(
        runner, ["/usr/bin/dwarfdump", "--uuid", str(path)], label + " UUID inspection"
    )
    return _parse_uuid_output(output, label)


def verify_symbol_receipt(
    receipt_path: pathlib.Path,
    distribution: pathlib.Path,
    version: str,
    build: str,
    topology: Mapping[str, Any],
    runner: RunFunction,
) -> Dict[str, Any]:
    receipt = read_json(receipt_path, "Apple private symbol receipt")
    expected_keys = {
        "schema_version",
        "contract",
        "platform",
        "app_version",
        "build_number",
        "created_at_utc",
        "private_symbols_not_packaged",
        "artifact",
        "flutter_symbols",
        "xcarchive_dsyms",
    }
    if set(receipt) != expected_keys or receipt.get("schema_version") != 1:
        raise VerificationError("Apple private symbol receipt schema is not exact")
    if (
        receipt.get("contract") != "winsvpn-apple-private-symbol-custody-v1"
        or receipt.get("platform") != "macos"
        or receipt.get("app_version") != version
        or str(receipt.get("build_number")) != build
        or receipt.get("private_symbols_not_packaged") is not True
    ):
        raise VerificationError("Apple private symbol receipt identity is not exact")
    artifact = receipt.get("artifact")
    expected_artifact = {
        "filename": distribution.name,
        "size": distribution.stat().st_size,
        "sha256": sha256_file(distribution),
    }
    if artifact != expected_artifact:
        raise VerificationError("Apple private symbol receipt does not bind the final distribution bytes")
    private_root = (ROOT / ".artifacts/private-release-symbols").resolve()
    try:
        receipt_resolved = receipt_path.resolve(strict=True)
        receipt_resolved.relative_to(private_root)
    except (OSError, ValueError) as exc:
        raise VerificationError("Apple private symbol receipt is outside private custody") from exc
    if receipt_resolved.name != "manifest.json" or receipt_resolved.parent.name != expected_artifact["sha256"]:
        raise VerificationError("Apple private symbol receipt is not keyed by the final distribution SHA-256")
    dsym_root = receipt_resolved.parent / "dSYMs"
    with tempfile.TemporaryDirectory(
        prefix=".winsvpn-held-dsyms-", dir=private_root
    ) as temporary, contextlib.ExitStack() as stack:
        private = pathlib.Path(temporary)
        os.chmod(private, 0o700)
        held_receipt = stack.enter_context(
            HeldFile(receipt_resolved, "Apple private symbol receipt")
        )
        held_inventory = stack.enter_context(
            HeldRecursiveInventory(
                receipt_resolved.parent,
                held_receipt.parents[-1][1],
                "Apple private symbol recursive inventory",
            )
        )
        custodial_receipt = _json_bytes(
            held_receipt.read(MAX_METADATA_BYTES), "Apple private symbol receipt"
        )
        if custodial_receipt != receipt:
            raise VerificationError("Apple private symbol receipt changed while being retained")
        source_inventory = held_inventory.inventory()
        flutter_inventory = [
            {
                "path": str(item["path"])[len("flutter/"):],
                "size": item["size"],
                "sha256": item["sha256"],
            }
            for item in source_inventory
            if str(item["path"]).startswith("flutter/")
        ]
        dsym_inventory = [
            {
                "path": str(item["path"])[len("dSYMs/"):],
                "size": item["size"],
                "sha256": item["sha256"],
            }
            for item in source_inventory
            if str(item["path"]).startswith("dSYMs/")
        ]
        if receipt.get("flutter_symbols") != flutter_inventory:
            raise VerificationError("Flutter symbol files do not match the exact symbol receipt")
        if receipt.get("xcarchive_dsyms") != dsym_inventory:
            raise VerificationError("dSYM files do not match the exact symbol receipt")
        flutter_names = {
            pathlib.PurePosixPath(str(item["path"])).name for item in flutter_inventory
        }
        required_flutter = {"app.macos-arm64.symbols", "app.macos-x64.symbols"}
        if not required_flutter.issubset(flutter_names):
            raise VerificationError("private Flutter symbols do not cover arm64 and x86_64")
        dwarf_records = [
            item for item in dsym_inventory if "/Contents/Resources/DWARF/" in str(item["path"])
        ]
        held_inventory.verify()
        held_dwarf_snapshots: List[Tuple[Dict[str, Any], HeldFile, pathlib.Path]] = []
        for record in dwarf_records:
            relative = pathlib.PurePosixPath(str(record["path"]))
            if relative.is_absolute() or any(
                component in ("", ".", "..") for component in relative.parts
            ):
                raise VerificationError("private dSYM inventory path is unsafe")
            held_source = stack.enter_context(
                HeldFile(
                    dsym_root.joinpath(*relative.parts),
                    "private dSYM bytes " + str(record["path"]),
                )
            )
            destination = private.joinpath(*relative.parts)
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            held_source.snapshot(destination)
            os.chmod(destination, 0o400)
            held_dwarf_snapshots.append((record, held_source, destination))
        held_dwarfs = [
            (
                record,
                held_source,
                stack.enter_context(
                    HeldFile(
                        destination,
                        "private dSYM snapshot " + str(record["path"]),
                    )
                ),
            )
            for record, held_source, destination in held_dwarf_snapshots
        ]
        held_inventory.verify()
        command_error: Optional[BaseException] = None
        custody_error: Optional[BaseException] = None
        try:
            try:
                binary_uuids: Set[Tuple[str, str]] = set()
                for path in topology["macho_files"]:
                    binary_uuids.update(
                        macho_uuids(pathlib.Path(path), pathlib.Path(path).name, runner)
                    )
                dsym_uuids: Set[Tuple[str, str]] = set()
                for _record, _held_source, held_snapshot in held_dwarfs:
                    current = macho_uuids(
                        held_snapshot.path, "dSYM " + held_snapshot.path.name, runner
                    )
                    if dsym_uuids.intersection(current):
                        raise VerificationError("private dSYM inventory contains duplicate UUIDs")
                    dsym_uuids.update(current)
                if binary_uuids != dsym_uuids:
                    missing = sorted(binary_uuids - dsym_uuids)
                    orphaned = sorted(dsym_uuids - binary_uuids)
                    raise VerificationError(
                        "dSYM UUIDs are not exact for the final app; missing="
                        + repr(missing)
                        + " orphaned="
                        + repr(orphaned)
                    )
            except BaseException as exc:
                command_error = exc
        finally:
            try:
                held_inventory.verify()
                held_receipt.verify()
                for record, held_source, held_snapshot in held_dwarfs:
                    held_source.verify()
                    held_snapshot.verify()
                    if held_snapshot.sha256() != record["sha256"]:
                        raise VerificationError(
                            "private dSYM snapshot changed during verification: "
                            + str(record["path"])
                        )
            except BaseException as exc:
                custody_error = exc
        if custody_error is not None:
            context = ""
            if command_error is not None:
                detail = (
                    type(command_error).__name__ + ": " + str(command_error)
                ).replace("\n", " ")[:500]
                context = "; dwarfdump failure context: " + detail
            raise VerificationError(
                "Apple private symbol post-process custody failure: "
                + str(custody_error)
                + context
            ) from custody_error
        if command_error is not None:
            raise command_error.with_traceback(command_error.__traceback__)
        return {"artifact_sha256": expected_artifact["sha256"], "uuid_count": len(binary_uuids)}


def verify_obfuscation_receipt(
    receipt_path: pathlib.Path,
    distribution: pathlib.Path,
    version: str,
    build: str,
    runner: RunFunction = run_command,
) -> Dict[str, Any]:
    receipt_path = pathlib.Path(os.path.abspath(os.fspath(receipt_path)))
    distribution = pathlib.Path(os.path.abspath(os.fspath(distribution)))
    receipt_parent = receipt_path.parent
    private_symbol_root = ROOT / ".artifacts/private-release-symbols"
    with tempfile.TemporaryDirectory(
        prefix=".winsvpn-held-obfuscation-", dir=private_symbol_root
    ) as temporary, contextlib.ExitStack() as stack:
        private = pathlib.Path(temporary)
        os.chmod(private, 0o700)
        held_distribution = stack.enter_context(
            HeldFile(distribution, "release distribution artifact")
        )
        held_receipt = stack.enter_context(
            HeldFile(receipt_path, "release obfuscation receipt")
        )
        held_sources = {
            name: stack.enter_context(HeldFile(path, "release verifier source " + name))
            for name, path in OBFUSCATION_SOURCE_FILES.items()
        }
        held_contract = held_sources["release_obfuscation_contract"]
        held_inventory = stack.enter_context(
            HeldRecursiveInventory(
                receipt_parent,
                held_receipt.parents[-1][1],
                "release obfuscation recursive symbol inventory",
            )
        )
        source_inventory = held_inventory.inventory()
        source_symbol_records = [
            item for item in source_inventory if str(item["path"]).endswith(".symbols")
        ]
        held_symbols: List[Tuple[str, HeldFile]] = []
        for record in source_symbol_records:
            relative = pathlib.PurePosixPath(str(record["path"]))
            if relative.is_absolute() or not relative.parts or any(
                component in ("", ".", "..") for component in relative.parts
            ):
                raise VerificationError("release obfuscation symbol path is unsafe")
            source = receipt_parent.joinpath(*relative.parts)
            held_symbols.append(
                (
                    relative.as_posix(),
                    stack.enter_context(HeldFile(source, "private Flutter symbol " + relative.as_posix())),
                )
            )
        held_inventory.verify()
        artifact_snapshot = private / ("artifact" + distribution.suffix.casefold())
        receipt_snapshot = private / "manifest.json"
        namespace = private / "verifier-namespace"
        namespace.mkdir(mode=0o700)
        source_snapshot_paths: Dict[str, pathlib.Path] = {}
        for name, source in held_sources.items():
            destination = namespace / (name + ".py")
            source.snapshot(destination)
            os.chmod(destination, 0o400)
            source_snapshot_paths[name] = destination
        held_distribution.snapshot(artifact_snapshot)
        held_receipt.snapshot(receipt_snapshot)
        symbol_snapshots: List[Tuple[str, pathlib.Path, HeldFile]] = []
        for relative, held_symbol in held_symbols:
            destination = private.joinpath(*pathlib.PurePosixPath(relative).parts)
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            held_symbol.snapshot(destination)
            os.chmod(destination, 0o400)
            symbol_snapshots.append((relative, destination, held_symbol))
        os.chmod(artifact_snapshot, 0o400)
        os.chmod(receipt_snapshot, 0o400)
        receipt = _json_bytes(
            held_receipt.read(MAX_METADATA_BYTES), "release obfuscation receipt"
        )
        allowed_keys = {
            "schema_version",
            "contract",
            "contract_sha256",
            "platform",
            "app_version",
            "build_number",
            "created_at_utc",
            "private_symbols_not_packaged",
            "verification",
            "artifacts",
            "symbols",
            "target_id",
        }
        if not set(receipt).issubset(allowed_keys) or set(receipt) - {"target_id"} != allowed_keys - {"target_id"}:
            raise VerificationError("release obfuscation receipt schema is not exact")
        if (
            receipt.get("schema_version") != 2
            or receipt.get("contract") != "winsvpn-release-obfuscation-and-secret-free-v2"
            or receipt.get("contract_sha256") != held_contract.sha256()
            or receipt.get("platform") != "macos"
            or receipt.get("app_version") != version
            or str(receipt.get("build_number")) != build
            or receipt.get("private_symbols_not_packaged") is not True
        ):
            raise VerificationError("release obfuscation receipt identity is not exact")
        source_snapshots: Dict[str, Tuple[HeldFile, HeldFile]] = {
            name: (
                source,
                stack.enter_context(
                    HeldFile(source_snapshot_paths[name], "private verifier snapshot " + name)
                ),
            )
            for name, source in held_sources.items()
        }
        snapshot_distribution = stack.enter_context(
            HeldFile(artifact_snapshot, "private distribution snapshot")
        )
        snapshot_receipt = stack.enter_context(
            HeldFile(receipt_snapshot, "private obfuscation receipt snapshot")
        )
        held_symbol_snapshots = [
            (
                relative,
                stack.enter_context(HeldFile(destination, "private symbol snapshot " + relative)),
                held_symbol,
            )
            for relative, destination, held_symbol in symbol_snapshots
        ]
        target = receipt.get("target_id")
        if target is not None:
            raise VerificationError("release obfuscation receipt must bind the held PKG or DMG directly")
        distribution_info = os.fstat(held_distribution.fd)
        expected_record = {
            "path": distribution.relative_to(ROOT).as_posix()
            if distribution.is_relative_to(ROOT)
            else str(distribution),
            "size": distribution_info.st_size,
            "sha256": held_distribution.sha256(),
        }
        if receipt.get("artifacts") != [expected_record]:
            raise VerificationError("release obfuscation receipt does not bind the final distribution bytes")
        verification = receipt.get("verification")
        required_claims = {
            "inspected_artifact_symbol_files_absent",
            "inspected_blobs_long_lived_credentials_absent",
            "inspected_blobs_sensitive_internal_identifiers_absent",
            "inspected_native_debug_sections_absent",
            "flutter_obfuscation_flag_required",
            "private_flutter_symbols_verified",
            "producer_static_contract_verified",
            "split_debug_info_flag_required",
            "apple_dsym_separated",
            "apple_strip_style_all_required",
            "obfuscation_is_not_secret_protection",
            "durable_secrets_remain_server_side",
            "authenticated_receipt_required",
        }
        if type(verification) is not dict or set(verification) != required_claims or any(
            value is not True for value in verification.values()
        ):
            raise VerificationError("release obfuscation receipt verification claims are incomplete")
        symbols = receipt.get("symbols")
        if type(symbols) is not list or not symbols:
            raise VerificationError("release obfuscation receipt contains no private Flutter symbols")
        actual_by_path = [
            {
                "path": relative,
                "size": os.fstat(held_symbol.fd).st_size,
                "sha256": held_symbol.sha256(),
            }
            for relative, held_symbol in held_symbols
        ]
        if symbols != actual_by_path:
            raise VerificationError("release obfuscation private symbols do not match their receipt")
        for binding in (
            held_distribution,
            held_receipt,
            *(source for source, _snapshot in source_snapshots.values()),
            *(snapshot for _source, snapshot in source_snapshots.values()),
            snapshot_distribution,
            snapshot_receipt,
            *(held_symbol for _relative, held_symbol in held_symbols),
            *(snapshot for _relative, snapshot, _source in held_symbol_snapshots),
        ):
            binding.verify()
        held_inventory.verify()

        def revalidate_complete_closure() -> None:
            failures: List[str] = []

            def check(label: str, action: Callable[[], None]) -> None:
                try:
                    action()
                except BaseException as exc:
                    failures.append(label + ": " + str(exc))

            def verify_distribution_snapshot_bytes() -> None:
                if snapshot_distribution.sha256() != expected_record["sha256"]:
                    raise VerificationError("private distribution snapshot changed during verification")

            def verify_receipt_snapshot_bytes() -> None:
                if snapshot_receipt.read(MAX_METADATA_BYTES) != held_receipt.read(MAX_METADATA_BYTES):
                    raise VerificationError(
                        "private obfuscation receipt snapshot changed during verification"
                    )

            check("recursive symbol inventory", held_inventory.verify)
            for binding in (
                held_distribution,
                held_receipt,
                *(source for source, _snapshot in source_snapshots.values()),
                *(snapshot for _source, snapshot in source_snapshots.values()),
                snapshot_distribution,
                snapshot_receipt,
                *(held_symbol for _relative, held_symbol in held_symbols),
                *(snapshot for _relative, snapshot, _source in held_symbol_snapshots),
            ):
                check(binding.label, binding.verify)
            check("distribution snapshot bytes", verify_distribution_snapshot_bytes)
            check("obfuscation receipt snapshot bytes", verify_receipt_snapshot_bytes)
            for name, (source, snapshot) in source_snapshots.items():
                def verify_source_snapshot_bytes(
                    source: HeldFile = source,
                    snapshot: HeldFile = snapshot,
                    name: str = name,
                ) -> None:
                    if snapshot.read(MAX_FILE_BYTES) != source.read(MAX_FILE_BYTES):
                        raise VerificationError(
                            "private verifier source snapshot changed during verification: " + name
                        )

                check("private verifier source snapshot bytes " + name, verify_source_snapshot_bytes)
            for relative, snapshot, source in held_symbol_snapshots:
                def verify_symbol_snapshot_bytes(
                    snapshot: HeldFile = snapshot,
                    source: HeldFile = source,
                    relative: str = relative,
                ) -> None:
                    if snapshot.read(MAX_FILE_BYTES) != source.read(MAX_FILE_BYTES):
                        raise VerificationError(
                            "private symbol snapshot changed during verification: " + relative
                        )

                check(
                    "private symbol snapshot bytes " + relative,
                    verify_symbol_snapshot_bytes,
                )
            if failures:
                raise VerificationError("; ".join(failures))

        command_error: Optional[BaseException] = None
        custody_error: Optional[BaseException] = None
        try:
            try:
                require_command(
                    runner,
                    [
                        sys.executable,
                        "-I",
                        "-S",
                        "-c",
                        CANONICAL_OBFUSCATION_ADAPTER,
                        str(namespace),
                        json.dumps(
                            {
                                name: {
                                    "logical_path": str(OBFUSCATION_SOURCE_FILES[name]),
                                    "sha256": source.sha256(),
                                    "size": os.fstat(source.fd).st_size,
                                }
                                for name, (source, _snapshot) in sorted(source_snapshots.items())
                            },
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        expected_record["path"],
                        "verify",
                        "--platform",
                        "macos",
                        "--symbols-dir",
                        str(private),
                        "--manifest",
                        str(receipt_snapshot),
                        "--artifact",
                        str(artifact_snapshot),
                    ],
                    "canonical macOS obfuscation and secret-free verification",
                )
            except BaseException as exc:
                command_error = exc
        finally:
            try:
                revalidate_complete_closure()
            except BaseException as exc:
                custody_error = exc
        if custody_error is not None:
            context = ""
            if command_error is not None:
                detail = (type(command_error).__name__ + ": " + str(command_error)).replace("\n", " ")[:500]
                context = "; canonical verifier failure context: " + detail
            raise VerificationError(
                "canonical verifier post-process custody failure: " + str(custody_error) + context
            ) from custody_error
        if command_error is not None:
            raise command_error.with_traceback(command_error.__traceback__)
        source_closure = {
            name + ".py": source.sha256()
            for name, (source, _snapshot) in sorted(source_snapshots.items())
        }
        source_closure_sha256 = hashlib.sha256(
            json.dumps(source_closure, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()
        return {
            "artifact_sha256": expected_record["sha256"],
            "symbol_count": len(symbols),
            "source_closure": source_closure,
            "source_closure_sha256": source_closure_sha256,
        }


def verify_staple_and_gatekeeper(
    path: pathlib.Path, artifact_kind: str, runner: RunFunction
) -> None:
    stapler = require_command(
        runner, ["/usr/bin/stapler", "validate", "-v", str(path)], str(path) + " staple validation"
    )
    if "the validate action worked" not in stapler.casefold():
        raise VerificationError(str(path) + " does not carry a valid stapled ticket")
    spctl_arguments = ["/usr/sbin/spctl", "--assess", "--verbose=4", "--type", artifact_kind]
    if artifact_kind == "open":
        spctl_arguments.extend(("--context", "context:primary-signature"))
    spctl_arguments.append(str(path))
    assessment = require_command(runner, spctl_arguments, str(path) + " Gatekeeper assessment")
    if "source=notarized developer id" not in assessment.casefold():
        raise VerificationError(str(path) + " lacks notarized Developer ID assessment evidence")


def verify_pkg_identity(path: pathlib.Path, runner: RunFunction) -> None:
    output = require_command(
        runner, ["/usr/sbin/pkgutil", "--check-signature", str(path)], "PKG signature verification"
    )
    leaf = re.findall(r"(?m)^\s*1\.\s+(Developer ID Installer:[^\r\n]+)\s*$", output)
    expected = "Developer ID Installer: " + OWNER_COMMON_NAME + " (" + TEAM_ID + ")"
    if len(leaf) != 1 or leaf[0] != expected:
        raise VerificationError("PKG is not signed by the exact Developer ID Installer identity")
    lowered = output.casefold()
    if "status: signed by a developer certificate issued by apple for distribution" not in lowered and "status: signed by a developer id certificate" not in lowered:
        raise VerificationError("PKG installer signature is not release-valid")
    verify_staple_and_gatekeeper(path, "install", runner)


def verify_dmg_identity(path: pathlib.Path, runner: RunFunction) -> None:
    require_command(runner, ["/usr/bin/hdiutil", "verify", str(path)], "DMG checksum verification")
    verify_signed_code(
        path,
        "DMG",
        runner,
        DMG_SIGNING_IDENTIFIER,
        require_runtime=False,
        inspect_entitlements=False,
    )
    verify_staple_and_gatekeeper(path, "open", runner)


def _one_embedded_app(root: pathlib.Path) -> pathlib.Path:
    apps = sorted(path for path in root.rglob("*.app") if path.is_dir() and not path.is_symlink())
    top_level: List[pathlib.Path] = []
    for app in apps:
        if not any(parent.name.casefold().endswith(".app") for parent in app.parents if parent != root):
            top_level.append(app)
    if len(top_level) != 1:
        raise VerificationError("distribution must contain exactly one top-level .app")
    return top_level[0]


def audit_distribution_extraction(
    root: pathlib.Path, embedded: pathlib.Path, artifact_kind: str
) -> None:
    if artifact_kind not in ("pkg", "dmg"):
        raise VerificationError("unknown distribution extraction kind")
    if root.is_symlink() or not root.is_dir() or embedded.is_symlink() or not embedded.is_dir():
        raise VerificationError("distribution extraction is not a contained real directory tree")
    try:
        embedded.relative_to(root)
    except ValueError as exc:
        raise VerificationError("distribution app escapes its extraction root") from exc

    payload_roots: List[pathlib.Path] = []
    for directory, names, filenames in os.walk(root, topdown=True, followlinks=False):
        names.sort()
        filenames.sort()
        parent = pathlib.Path(directory)
        for name in list(names) + list(filenames):
            path = parent / name
            try:
                info = path.lstat()
            except OSError as exc:
                raise VerificationError("distribution entry disappeared: " + str(path)) from exc
            if stat.S_ISLNK(info.st_mode):
                if artifact_kind == "pkg":
                    _safe_relative_symlink(path, root)
                if name in names:
                    names.remove(name)
                continue
            if stat.S_ISDIR(info.st_mode):
                if path.name == "Payload":
                    payload_roots.append(path)
                if path.name == "Scripts" and artifact_kind == "pkg" and any(path.iterdir()):
                    raise VerificationError("PKG contains installer scripts outside the sealed app")
                if path.name.casefold().endswith((".app", ".appex", ".xpc", ".plugin")):
                    try:
                        path.relative_to(embedded)
                    except ValueError:
                        raise VerificationError(
                            "distribution contains unexpected code bundle outside the exact app: "
                            + str(path)
                        )
                continue
            if not stat.S_ISREG(info.st_mode):
                raise VerificationError("distribution contains a special file: " + str(path))
            try:
                path.relative_to(embedded)
                inside_app = True
            except ValueError:
                inside_app = False
            if inside_app:
                continue
            mode = stat.S_IMODE(info.st_mode)
            if mode & 0o111:
                raise VerificationError(
                    "distribution contains executable content outside the exact app: " + str(path)
                )
            if path.name.casefold().endswith((".dylib", ".pkg", ".app.zip")) or _is_macho(path):
                raise VerificationError(
                    "distribution contains loose code outside the exact app: " + str(path)
                )

    if artifact_kind == "pkg" and payload_roots:
        containing_payloads = []
        for payload in payload_roots:
            try:
                embedded.relative_to(payload)
                containing_payloads.append(payload)
            except ValueError:
                if any(payload.iterdir()):
                    raise VerificationError("PKG contains an additional non-app payload")
        if len(containing_payloads) != 1:
            raise VerificationError("PKG payload does not contain exactly the held app")
        payload = containing_payloads[0]
        for path in payload.rglob("*"):
            if path == embedded:
                continue
            try:
                path.relative_to(embedded)
                continue
            except ValueError:
                pass
            try:
                embedded.relative_to(path)
                continue
            except ValueError:
                raise VerificationError("PKG payload installs content outside the exact app")


def extract_pkg(path: pathlib.Path, destination: pathlib.Path, runner: RunFunction) -> pathlib.Path:
    require_command(
        runner,
        ["/usr/sbin/pkgutil", "--expand-full", str(path), str(destination)],
        "PKG payload expansion",
    )
    embedded = _one_embedded_app(destination)
    audit_distribution_extraction(destination, embedded, "pkg")
    return embedded


def attach_dmg(path: pathlib.Path, mountpoint: pathlib.Path, runner: RunFunction) -> pathlib.Path:
    require_command(
        runner,
        [
            "/usr/bin/hdiutil",
            "attach",
            "-readonly",
            "-nobrowse",
            "-noautoopen",
            "-mountpoint",
            str(mountpoint),
            str(path),
        ],
        "DMG read-only attachment",
    )
    embedded = _one_embedded_app(mountpoint)
    audit_distribution_extraction(mountpoint, embedded, "dmg")
    return embedded


def verify_provisioning_profile(
    profile: pathlib.Path, identifier: str, runner: RunFunction, label: str
) -> None:
    if profile.is_symlink() or not profile.is_file():
        raise VerificationError(label + " Developer ID provisioning profile is missing")
    output = require_command(
        runner, ["/usr/bin/security", "cms", "-D", "-i", str(profile)], label + " profile decoding"
    )
    try:
        value = plistlib.loads(output.encode("utf-8", "strict"))
    except (UnicodeError, plistlib.InvalidFileException, ValueError, TypeError) as exc:
        raise VerificationError(label + " provisioning profile is malformed") from exc
    if type(value) is not dict:
        raise VerificationError(label + " provisioning profile is malformed")
    entitlements = value.get("Entitlements")
    app_identifier = TEAM_ID + "." + identifier
    if (
        value.get("TeamIdentifier") != [TEAM_ID]
        or value.get("ProvisionsAllDevices") is not True
        or type(entitlements) is not dict
        or entitlements.get("com.apple.application-identifier") != app_identifier
        or entitlements.get("com.apple.developer.team-identifier") != TEAM_ID
        or entitlements.get("get-task-allow") is not False
    ):
        raise VerificationError(label + " provisioning profile identity is not production-valid")


def verify_app(
    app: pathlib.Path,
    version: str,
    build: str,
    runner: RunFunction,
    winn_release: Optional[pathlib.Path] = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], str]:
    before = tree_records(app)
    topology = audit_code_topology(app)
    host_info = topology["host_info"]
    tunnel_info = topology["tunnel_info"]
    for label, info in (("host", host_info), ("PacketTunnel", tunnel_info)):
        if info.get("CFBundleShortVersionString") != version or str(info.get("CFBundleVersion")) != build:
            raise VerificationError(label + " version/build does not match the exact release")
    verify_all_privacy(app, topology)
    macho = verify_all_macho(app, topology, runner)
    verify_engine_contract(app, topology, runner, winn_release)
    verify_provisioning_profile(
        app / "Contents/embedded.provisionprofile", HOST_BUNDLE_ID, runner, "host"
    )
    tunnel = pathlib.Path(topology["tunnel"])
    verify_provisioning_profile(
        tunnel / "Contents/embedded.provisionprofile", TUNNEL_BUNDLE_ID, runner, "PacketTunnel"
    )
    verify_staple_and_gatekeeper(app, "execute", runner)
    if pathlib.Path("/usr/bin/syspolicy_check").exists():
        require_command(
            runner,
            ["/usr/bin/syspolicy_check", "distribution", str(app)],
            "modern macOS distribution policy assessment",
        )
    after = tree_records(app)
    if before != after:
        raise VerificationError("application bundle changed during verification")
    return topology, macho, tree_digest(before)


def _parse_release_identity() -> Tuple[str, str]:
    try:
        text = (ROOT / "pubspec.yaml").read_text(encoding="utf-8")
    except OSError as exc:
        raise VerificationError("pubspec.yaml is unavailable for release identity") from exc
    match = re.search(r"(?m)^version:\s*([^+\s]+)\+(\d+)\s*$", text)
    if match is None:
        raise VerificationError("pubspec.yaml release identity is malformed")
    return match.group(1), match.group(2)


def verify_release(
    app: pathlib.Path,
    distribution: pathlib.Path,
    symbol_receipt: pathlib.Path,
    obfuscation_receipt: pathlib.Path,
    version: str,
    build: str,
    runner: RunFunction = run_command,
    winn_release: Optional[pathlib.Path] = None,
) -> Dict[str, Any]:
    app = pathlib.Path(os.path.abspath(os.fspath(app)))
    distribution = pathlib.Path(os.path.abspath(os.fspath(distribution)))
    suffix = distribution.suffix.casefold()
    if suffix not in (".pkg", ".dmg"):
        raise VerificationError("distribution artifact must be one held .pkg or .dmg")
    topology, macho, app_tree_sha256 = verify_app(app, version, build, runner, winn_release)
    with tempfile.TemporaryDirectory(prefix="winsvpn-macos-release-verify-") as temporary:
        private = pathlib.Path(temporary)
        os.chmod(private, 0o700)
        snapshot = private / ("distribution" + suffix)
        distribution_sha256, distribution_size = stable_file_snapshot(distribution, snapshot)
        if suffix == ".pkg":
            verify_pkg_identity(snapshot, runner)
            expanded = private / "expanded"
            embedded = extract_pkg(snapshot, expanded, runner)
            detach: Optional[pathlib.Path] = None
        else:
            verify_dmg_identity(snapshot, runner)
            mountpoint = private / "mount"
            mountpoint.mkdir(mode=0o700)
            embedded = attach_dmg(snapshot, mountpoint, runner)
            detach = mountpoint
        try:
            embedded_records = tree_records(embedded)
            if embedded.name != app.name or tree_digest(embedded_records) != app_tree_sha256:
                raise VerificationError("distribution does not contain the exact verified application bytes and modes")
        finally:
            if detach is not None:
                require_command(
                    runner, ["/usr/bin/hdiutil", "detach", str(detach)], "DMG detachment"
                )
        if sha256_file(snapshot) != distribution_sha256:
            raise VerificationError("distribution snapshot changed during verification")
    if sha256_file(distribution) != distribution_sha256 or distribution.stat().st_size != distribution_size:
        raise VerificationError("held distribution artifact changed during verification")
    symbol = verify_symbol_receipt(
        symbol_receipt, distribution, version, build, topology, runner
    )
    obfuscation = verify_obfuscation_receipt(
        obfuscation_receipt, distribution, version, build, runner
    )
    if symbol["artifact_sha256"] != distribution_sha256 or obfuscation["artifact_sha256"] != distribution_sha256:
        raise VerificationError("release receipts do not bind the same final distribution bytes")
    if tree_digest(tree_records(app)) != app_tree_sha256:
        raise VerificationError("held application bundle changed after release verification")
    return {
        "ok": True,
        "contract": "winsvpn-macos-release-artifact-verification-v1",
        "release": version + "+" + build,
        "app": {
            "path": str(app),
            "tree_sha256": app_tree_sha256,
            "bundle_id": HOST_BUNDLE_ID,
            "packet_tunnel_bundle_id": TUNNEL_BUNDLE_ID,
            "team_id": TEAM_ID,
            "architectures": sorted(REQUIRED_ARCHITECTURES),
            "macho_count": len(macho),
        },
        "distribution": {
            "path": str(distribution),
            "kind": suffix.lstrip("."),
            "size": distribution_size,
            "sha256": distribution_sha256,
            "stapled": True,
            "notarized": True,
        },
        "receipts": {
            "symbols": str(symbol_receipt),
            "obfuscation": str(obfuscation_receipt),
            "obfuscation_source_closure": obfuscation["source_closure"],
            "obfuscation_source_closure_sha256": obfuscation["source_closure_sha256"],
        },
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify an exact stapled Developer ID macOS app and its final PKG or DMG."
    )
    parser.add_argument("--app", required=True, help="Final stapled .app directory")
    parser.add_argument("--distribution", required=True, help="Final stapled .pkg or .dmg")
    parser.add_argument("--symbol-receipt", required=True, help="Exact private symbol custody manifest")
    parser.add_argument("--obfuscation-receipt", required=True, help="Exact obfuscation receipt manifest")
    parser.add_argument("--version", help="Expected CFBundleShortVersionString; defaults to pubspec.yaml")
    parser.add_argument("--build", help="Expected CFBundleVersion; defaults to pubspec.yaml")
    parser.add_argument(
        "--winn-release",
        help="Signed Winn release directory the packaged Winn engine was built from "
        "(defaults to WINS_WINN_RELEASE_DIR)",
    )
    parser.add_argument("--json", action="store_true", help="Emit the PASS receipt as JSON")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        current_version, current_build = _parse_release_identity()
        version = args.version or current_version
        build = args.build or current_build
        if (version, build) != (current_version, current_build):
            raise VerificationError("requested release identity does not match pubspec.yaml")
        result = verify_release(
            pathlib.Path(args.app),
            pathlib.Path(args.distribution),
            pathlib.Path(args.symbol_receipt),
            pathlib.Path(args.obfuscation_receipt),
            version,
            build,
            winn_release=pathlib.Path(args.winn_release) if args.winn_release else None,
        )
    except VerificationError as exc:
        print("MACOS RELEASE ARTIFACT: BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    except (KeyError, OSError, TypeError, ValueError, subprocess.SubprocessError) as exc:
        print(
            "MACOS RELEASE ARTIFACT: BLOCKED: malformed or unstable verification input: "
            + str(exc),
            file=sys.stderr,
        )
        return 1
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(
            "MACOS RELEASE ARTIFACT: PASS release="
            + result["release"]
            + " sha256="
            + result["distribution"]["sha256"]
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
