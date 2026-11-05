#!/usr/bin/env python3
"""Create and verify dependency-scoped release input manifests.

The shared revision is frozen independently from native platform inputs. A
native-only change therefore invalidates only that platform, while a change to
``lib/``, a Flutter-declared shared asset, or the Dart dependency locks
invalidates every artifact that references the shared manifest.

``android`` covers the phone and TV product flavors in one Gradle tree. Wear OS
and the browser extension are separate release platforms because they ship from
``wear_os/`` and ``extension/`` rather than from ``android/``.

Build outputs and Flutter-generated registrants are not hashed, but excluded
trees are still inspected for specials, links, and oversized sparse data.
APP_SOURCE_LOCK and toolchain pin bindings consume the same owner-issued
source-freeze trust contract as release_source_freeze.py. A candidate
transaction cannot mint or rewrite that trust.

Production freeze requires an immutable/clean Git worktree and hashes only
inputs that belong to the exact tracked HEAD tree. Untracked files such as
``xray-arm64.exe`` cannot enter a release fingerprint. Isolated fixture/test
mode exists only for local harnesses without Git; it never authorizes release
and cannot be selected from the production CLI.
"""

from __future__ import annotations

import sys as _bootstrap_sys


# Capture the interpreter module set before this controller imports any
# dependency. A reconstructed runpy worker necessarily leaves additional
# modules behind, even when it presents the reviewed source through /dev/fd.
_WORKER_BOOTSTRAP_MODULES = frozenset(_bootstrap_sys.modules)
_BOOTSTRAP_BUILTINS = _bootstrap_sys.modules.get("builtins")
_BOOTSTRAP_IMPORTLIB = _bootstrap_sys.modules.get("_frozen_importlib")
_BOOTSTRAP_IMPORTLIB_EXTERNAL = _bootstrap_sys.modules.get(
    "_frozen_importlib_external"
)
_BOOTSTRAP_MARSHAL = _bootstrap_sys.modules.get("marshal")
_BOOTSTRAP_POSIX = _bootstrap_sys.modules.get("posix")
_BOOTSTRAP_POSIX_WRITE = (
    _BOOTSTRAP_POSIX.__dict__.get("write")
    if _BOOTSTRAP_POSIX is not None
    else None
)
_BOOTSTRAP_IMPORT_GRAPH_PRISTINE = bool(
    _bootstrap_sys is _bootstrap_sys.modules.get("sys")
    and _BOOTSTRAP_IMPORTLIB is not None
    and _BOOTSTRAP_IMPORTLIB_EXTERNAL is not None
    and _bootstrap_sys.meta_path
    == [
        _BOOTSTRAP_IMPORTLIB.BuiltinImporter,
        _BOOTSTRAP_IMPORTLIB.FrozenImporter,
        _BOOTSTRAP_IMPORTLIB_EXTERNAL.PathFinder,
    ]
)
_BOOTSTRAP_BUILTIN_SPECS = (
    ("__import__", "builtins"),
    ("compile", "builtins"),
    ("exec", "builtins"),
    ("open", "_io"),
    ("print", "builtins"),
)
_BOOTSTRAP_BUILTINS_PRISTINE = bool(
    _BOOTSTRAP_BUILTINS is not None
    and all(
        value.__class__.__name__ == "builtin_function_or_method"
        and value.__self__ is _bootstrap_sys.modules.get(module_name)
        and value.__module__ == module_name
        and value.__name__ == name
        for name, module_name in _BOOTSTRAP_BUILTIN_SPECS
        for value in (_BOOTSTRAP_BUILTINS.__dict__.get(name),)
        if value is not None
    )
    and all(
        _BOOTSTRAP_BUILTINS.__dict__.get(name) is not None
        for name, _module_name in _BOOTSTRAP_BUILTIN_SPECS
    )
)


def _bootstrap_sha256(payload: bytes) -> str:
    """Hash bootstrap code without importing through a mutable finder."""

    constants = (
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    )
    state = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ]
    bit_length = payload.__len__() * 8
    message = payload + b"\x80"
    message += b"\0" * ((56 - message.__len__() % 64) % 64)
    message += bit_length.to_bytes(8, "big")
    block_offset = 0
    while block_offset < message.__len__():
        schedule: list[int] = []
        word_offset = 0
        while word_offset < 64:
            start = block_offset + word_offset
            schedule.append(int.from_bytes(message[start:start + 4], "big"))
            word_offset += 4
        while schedule.__len__() < 64:
            value_15 = schedule[-15]
            value_2 = schedule[-2]
            sigma0 = (
                ((value_15 >> 7) | (value_15 << 25))
                ^ ((value_15 >> 18) | (value_15 << 14))
                ^ (value_15 >> 3)
            ) & 0xFFFFFFFF
            sigma1 = (
                ((value_2 >> 17) | (value_2 << 15))
                ^ ((value_2 >> 19) | (value_2 << 13))
                ^ (value_2 >> 10)
            ) & 0xFFFFFFFF
            schedule.append(
                (schedule[-16] + sigma0 + schedule[-7] + sigma1) & 0xFFFFFFFF
            )
        a, b, c, d, e, f, g, h = state
        index = 0
        while index < 64:
            choice = (e & f) ^ ((~e) & g)
            majority = (a & b) ^ (a & c) ^ (b & c)
            upper0 = (
                ((a >> 2) | (a << 30))
                ^ ((a >> 13) | (a << 19))
                ^ ((a >> 22) | (a << 10))
            ) & 0xFFFFFFFF
            upper1 = (
                ((e >> 6) | (e << 26))
                ^ ((e >> 11) | (e << 21))
                ^ ((e >> 25) | (e << 7))
            ) & 0xFFFFFFFF
            first = (h + upper1 + choice + constants[index] + schedule[index]) & 0xFFFFFFFF
            second = (upper0 + majority) & 0xFFFFFFFF
            h, g, f, e, d, c, b, a = g, f, e, (d + first) & 0xFFFFFFFF, c, b, a, (first + second) & 0xFFFFFFFF
            index += 1
        values = (a, b, c, d, e, f, g, h)
        index = 0
        while index < 8:
            state[index] = (state[index] + values[index]) & 0xFFFFFFFF
            index += 1
        block_offset += 64
    return b"".join(value.to_bytes(4, "big") for value in state).hex()


_BOOTSTRAP_IMPORT_METHOD_DIGESTS = (
    (_BOOTSTRAP_IMPORTLIB, "BuiltinImporter", "create_module", "staticmethod", "c4a05e010a8edf19d5595f90e55b76440894884fe0fd23dd22b8a3db4f7f0e98", ()),
    (_BOOTSTRAP_IMPORTLIB, "BuiltinImporter", "exec_module", "staticmethod", "57f46ab2209ccd5c9ab0a049cf5eab59286ae8b90c6deda8294f44ee5bf87d1c", ()),
    (_BOOTSTRAP_IMPORTLIB, "BuiltinImporter", "find_spec", "classmethod", "a6e1e3fb34a6975d683a43675dd866ed9a28348344212c23a7989cc366f9f88c", ()),
    (_BOOTSTRAP_IMPORTLIB, "BuiltinImporter", "get_code", "classmethod", "8e2d4d6d1e8c6edb06177c7cfa4ff081a071a381b517e729a02f3261b926f897", ("fcdd2020fd82ed326ebb5b53f213ee8e402067e434af6840d5faf3bc0985a87a",)),
    (_BOOTSTRAP_IMPORTLIB, "BuiltinImporter", "get_source", "classmethod", "8e2d4d6d1e8c6edb06177c7cfa4ff081a071a381b517e729a02f3261b926f897", ("77ebb6a0c650ca32f2ffb3f06f2fbf58570c7b51a768ca952b9ff46420d0da20",)),
    (_BOOTSTRAP_IMPORTLIB, "BuiltinImporter", "is_package", "classmethod", "8e2d4d6d1e8c6edb06177c7cfa4ff081a071a381b517e729a02f3261b926f897", ("6774a489a99a5bfa90b8229febd8754d536c8e5679b0c05f597317e1d2adf452",)),
    (_BOOTSTRAP_IMPORTLIB, "BuiltinImporter", "load_module", "classmethod", "11147dfc48fc26f7bb1b7d850d3b7fc111eddd6bca7038579476a87c53ace395", ()),
    (_BOOTSTRAP_IMPORTLIB, "FrozenImporter", "_fix_up_module", "classmethod", "5eb7f3255e59993afd1b66069a596e4f83ae0f63fff0c3e05a3dca4af67317cb", ()),
    (_BOOTSTRAP_IMPORTLIB, "FrozenImporter", "_resolve_filename", "classmethod", "dad979a2ab67f9e374a088cfad2f8a6365e940462afc56db8fc6a7a3b7e65348", ()),
    (_BOOTSTRAP_IMPORTLIB, "FrozenImporter", "create_module", "staticmethod", "7874e669851ada999ce932a4904a2b94df6889f3a16fc986c5a36087410099ce", ()),
    (_BOOTSTRAP_IMPORTLIB, "FrozenImporter", "exec_module", "staticmethod", "0362e2487e7ecbb3c0aa4c4348f6526bc629bdff579c5388db51f096a6d6d86f", ()),
    (_BOOTSTRAP_IMPORTLIB, "FrozenImporter", "find_spec", "classmethod", "a5bf30842a7ff1e9e14786d6f997998b6483f581977ea2b135058d3ad8a5a7f3", ()),
    (_BOOTSTRAP_IMPORTLIB, "FrozenImporter", "get_code", "classmethod", "4e6cda9e0fdabb96fa70e0a68498bec3f867da9f31d3615152a81d967d2d96dc", ("16de4e38352124408c3c9ed5d596c2130a4baec03aca4f59fd0dbf480b76b9a7",)),
    (_BOOTSTRAP_IMPORTLIB, "FrozenImporter", "get_source", "classmethod", "4e6cda9e0fdabb96fa70e0a68498bec3f867da9f31d3615152a81d967d2d96dc", ("f3cd04d269d3e45a6d8ae02e115d98eacc3cf3ca787fdfe6aa43fc44d6343f19",)),
    (_BOOTSTRAP_IMPORTLIB, "FrozenImporter", "is_package", "classmethod", "4e6cda9e0fdabb96fa70e0a68498bec3f867da9f31d3615152a81d967d2d96dc", ("b5b75eb8bca52c701e51f94054c3f9a755a01194c0c2f3e1e242ee01ffc0decf",)),
    (_BOOTSTRAP_IMPORTLIB, "FrozenImporter", "load_module", "classmethod", "2b3117ec5770dd9c44bf192222e4ccb6aff8ee8f57da93a7008234ec1b4837c4", ()),
    (_BOOTSTRAP_IMPORTLIB_EXTERNAL, "PathFinder", "_get_spec", "classmethod", "3e7f34e11113976b0f7308e4d6e20cc4ba95656561eba8ec837c8e2054b20d97", ()),
    (_BOOTSTRAP_IMPORTLIB_EXTERNAL, "PathFinder", "_path_hooks", "staticmethod", "76f64bf0e3e7b458e00be59ffc72ae6d43e6dae346cb6c7895621482c0018cec", ()),
    (_BOOTSTRAP_IMPORTLIB_EXTERNAL, "PathFinder", "_path_importer_cache", "classmethod", "7b2d7d065500bbcfeac51b15f700b5e9350fb9be432635a4598a7fd6c59e3e4a", ()),
    (_BOOTSTRAP_IMPORTLIB_EXTERNAL, "PathFinder", "find_distributions", "staticmethod", "37023d69015605c789d99e95282745b6ab27ce5403680dc0de8036402ed9b03e", ()),
    (_BOOTSTRAP_IMPORTLIB_EXTERNAL, "PathFinder", "find_spec", "classmethod", "85c98d92f42ddb739eabce505cc3e336e0ee5a114737a6d0994f242a50a9e0d3", ()),
    (_BOOTSTRAP_IMPORTLIB_EXTERNAL, "PathFinder", "invalidate_caches", "staticmethod", "e26ad041d2ff8c44944bcf79a2464d20d93994855fa73b72e779d9a475b00eeb", ()),
)


def _bootstrap_import_methods_pristine() -> bool:
    dumps = (
        _BOOTSTRAP_MARSHAL.__dict__.get("dumps")
        if _BOOTSTRAP_MARSHAL is not None
        else None
    )
    if not (
        _BOOTSTRAP_MARSHAL is _bootstrap_sys.modules.get("marshal")
        and dumps is not None
        and dumps.__class__.__name__ == "builtin_function_or_method"
        and dumps.__self__ is _BOOTSTRAP_MARSHAL
        and dumps.__module__ == "marshal"
        and dumps.__name__ == "dumps"
    ):
        return False
    for module, class_name, method_name, descriptor_name, digest, closure_digests in _BOOTSTRAP_IMPORT_METHOD_DIGESTS:
        if module is None or module is not _bootstrap_sys.modules.get(module.__name__):
            return False
        importer = module.__dict__.get(class_name)
        descriptor = importer.__dict__.get(method_name) if importer is not None else None
        if descriptor is None or descriptor.__class__.__name__ != descriptor_name:
            return False
        function = descriptor.__func__
        if (
            function.__class__.__name__ != "function"
            or function.__globals__ is not module.__dict__
            or function.__module__ not in {
                "_frozen_importlib", "_frozen_importlib_external"
            }
            or _bootstrap_sha256(dumps(function.__code__)) != digest
        ):
            return False
        closure = function.__closure__ or ()
        if closure.__len__() != closure_digests.__len__():
            return False
        index = 0
        while index < closure.__len__():
            closed = closure[index].cell_contents
            if (
                closed.__class__.__name__ != "function"
                or closed.__globals__ is not module.__dict__
                or _bootstrap_sha256(dumps(closed.__code__)) != closure_digests[index]
            ):
                return False
            index += 1
    return True


_BOOTSTRAP_IMPORT_METHODS_PRISTINE = _bootstrap_import_methods_pristine()
_BOOTSTRAP_POSIX_WRITE_PRISTINE = bool(
    _BOOTSTRAP_POSIX is _bootstrap_sys.modules.get("posix")
    and _BOOTSTRAP_POSIX_WRITE is not None
    and _BOOTSTRAP_POSIX_WRITE.__class__.__name__ == "builtin_function_or_method"
    and _BOOTSTRAP_POSIX_WRITE.__self__ is _BOOTSTRAP_POSIX
    and _BOOTSTRAP_POSIX_WRITE.__module__ == "posix"
    and _BOOTSTRAP_POSIX_WRITE.__name__ == "write"
)

import argparse
import contextvars
import dataclasses
import datetime as dt
import fcntl
import functools
import hashlib
import io
import json
import math
import os
import pathlib
import plistlib
import re
try:
    import resource
except ImportError:  # pragma: no cover - Windows has no POSIX resource module.
    resource = None  # type: ignore[assignment]
import select
import secrets
import stat
import struct
import subprocess
import sys
import tarfile
import threading
import time
import types
import unicodedata
import xml.etree.ElementTree as etree
import zipfile
import zlib
from collections.abc import Iterable


_EXECUTING_MODULE_CODE = sys._getframe().f_code
_EXECUTING_SOURCE_PATH = pathlib.Path(__file__).resolve()
_EXECUTING_CODE_PATH = pathlib.Path(_EXECUTING_MODULE_CODE.co_filename).resolve()
SCHEMA_VERSION = 1
SHARED_CONTRACT = "winsvpn-shared-inputs-v1"
PLATFORM_CONTRACT = "winsvpn-platform-inputs-v1"
INDEX_CONTRACT = "winsvpn-release-input-index-v1"
# A scoped index freezes a proper subset of CANONICAL_FREEZE_PLATFORMS for a
# phased release. It is a different contract with a different key set and
# manifest_set_complete is always false, so every consumer that needs the full
# platform set (verify_release_index without a platform, the contract equality
# checks in gcp_client_release_binding.py and android_final_evidence_collector.py,
# the exact key set checks) refuses it by construction.
SCOPED_INDEX_CONTRACT = "winsvpn-release-input-index-scoped-v1"
INDEX_RECORD_KEYS = frozenset(
    {
        "schema_version",
        "contract",
        "release",
        "shared_revision",
        "created_utc",
        "shared_manifest",
        "platform_manifests",
        "sha256_anchor",
        "manifest_set_complete",
        "publication_authorized",
    }
)
SCOPED_INDEX_EXTRA_KEYS = frozenset({"platform_scope", "unfrozen_platforms"})
BUILD_BEGIN_CONTRACT = "winsvpn-build-begin-v1"
BUILD_RECEIPT_CONTRACT = "winsvpn-build-receipt-v1"
BUILD_ATTEMPT_CONTRACT = "winsvpn-witnessed-build-attempt-v2"
BUILD_ATTEMPT_COMMIT_CONTRACT = "winsvpn-build-attempt-commit-v2"
BUILD_ATTEMPT_MARKER = b"WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_V2"
BUILD_ATTEMPT_SWITCH = "--wins-release-dependency-build-attempt-v2"
NATIVE_BUILD_WITNESS_CONTRACT = "winsvpn-native-build-witness-v1"
NATIVE_BUILD_WITNESS_MARKER = b"WINS_RELEASE_DEPENDENCY_NATIVE_BUILD_WITNESS_V1"
NATIVE_BUILD_WITNESS_REQUIRED_ENV = (
    "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT",
    "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE",
    "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT",
    "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_PLATFORM",
)
NATIVE_BUILD_WITNESS_DESCRIPTOR_ENV = (
    "WINS_RELEASE_DEPENDENCY_REPOSITORY_FD",
    "WINS_RELEASE_DEPENDENCY_SOURCE_FD",
    "WINS_RELEASE_DEPENDENCY_ATTEMPT_FD",
    "WINS_RELEASE_DEPENDENCY_OUTPUT_FD",
)
BUILD_ATTEMPT_NONCE = re.compile(r"[0-9a-f]{64}\Z")
BUILD_ATTEMPT_TIMEOUT_SECONDS = 2 * 60 * 60
BUILD_ATTEMPT_DIAGNOSTIC_BYTES_LIMIT = 8192
BUILD_ATTEMPT_DIAGNOSTIC_TEXT_LIMIT = 512
BUILD_ATTEMPT_LIMIT = 64
BUILD_ATTEMPT_BYTES_LIMIT = 4 * 1024 * 1024 * 1024
BUILD_ATTEMPT_MAX_AGE_SECONDS = BUILD_ATTEMPT_TIMEOUT_SECONDS + 15 * 60
BUILD_ATTEMPT_RETIRED_LIMIT = 64
BUILD_ATTEMPT_JOURNAL_CONTRACT = "winsvpn-build-attempt-admission-v1"
BUILD_ATTEMPT_JOURNAL_NAME = ".journal"
ARCHIVE_EXPANDED_BYTES_LIMIT = 16 * 1024 * 1024 * 1024
ARCHIVE_ENTRY_LIMIT = 100_000
ARCHIVE_METADATA_BYTES_LIMIT = 16 * 1024 * 1024
PUBLICATION_TRANSACTION_CONTRACT = "winsvpn-release-publication-transaction-v1"
PUBLICATION_STAGE_LIMIT = 32
PUBLICATION_STAGE_BYTES_LIMIT = 16 * 1024 * 1024
_PRISTINE_RELEASE_PYTHON_BOOTSTRAP_MODULES = frozenset(
    {
        "__main__",
        "__future__",
        "_codecs",
        "_frozen_importlib",
        "_frozen_importlib_external",
        "_imp",
        "_io",
        "_signal",
        "_thread",
        "_warnings",
        "_weakref",
        "builtins",
        "codecs",
        "encodings",
        "encodings.aliases",
        "encodings.utf_8",
        "marshal",
        "posix",
        "sys",
        "time",
        "zipimport",
    }
)
REPARSE_POINT_ATTRIBUTE = 0x400
SHARED_ROOTS = ("lib", "pubspec.yaml", "pubspec.lock")
WINN_SOURCE_ROOT = "winn_protocol_experimental"
PLATFORM_ROOTS = {
    "android": ("android", WINN_SOURCE_ROOT),
    "wear_os": ("wear_os",),
    "extension": ("extension",),
    "windows": ("windows", "installer/windows", WINN_SOURCE_ROOT),
    "linux": ("linux", WINN_SOURCE_ROOT),
    "macos": (
        "macos",
        "apple/WinsTunnelCore",
        "apple/EngineWrappers",
        "apple/EngineArtifacts/macos",
        "winn_protocol_experimental",
    ),
    "ios": (
        "ios",
        "apple/WinsTunnelCore",
        "apple/EngineWrappers",
        "apple/EngineArtifacts/ios/iphoneos",
        "winn_protocol_experimental",
    ),
}
# Shipping native-messaging host inputs consumed by the Windows installer and
# the Windows artifact gate. Hash these regular files only: do not freeze all of
# tools/, generated host output, caches, harness sources, browser-specific
# manifest templates, or macOS-only installers. The committed store-id record
# decides the shipped Chrome/Edge allowed_origins, so it is hashed.
# host/lib files are relative symlinks into lib/. Bind their exact identities
# and relative targets on the Windows native capture used by verify-index;
# do not hash those aliases as regular blobs.
WINDOWS_NATIVE_HOST_INPUT_PATHS = (
    "tools/native_messaging/host/bin/wins_bridge_host.dart",
    "tools/native_messaging/host/pubspec.lock",
    "tools/native_messaging/host/pubspec.yaml",
    "tools/native_messaging/install_native_host.sh",
    "tools/native_messaging/manifests/store_ids.json",
    "tools/native_messaging/native_host_layout.py",
    "tools/native_messaging/render_host_manifest.py",
)
WINDOWS_NATIVE_HOST_LIB_SYMLINK_DIR = "tools/native_messaging/host/lib"
WINDOWS_NATIVE_HOST_LIB_SYMLINK_ALIASES = (
    (
        "tools/native_messaging/host/lib/browser_bridge_app_ipc.dart",
        "../../../../lib/browser_bridge_app_ipc.dart",
    ),
    (
        "tools/native_messaging/host/lib/browser_bridge_framing.dart",
        "../../../../lib/browser_bridge_framing.dart",
    ),
    (
        "tools/native_messaging/host/lib/browser_bridge_protocol.dart",
        "../../../../lib/browser_bridge_protocol.dart",
    ),
    (
        "tools/native_messaging/host/lib/browser_bridge_proxy.dart",
        "../../../../lib/browser_bridge_proxy.dart",
    ),
    (
        "tools/native_messaging/host/lib/vpn_config_validation.dart",
        "../../../../lib/vpn_config_validation.dart",
    ),
    (
        "tools/native_messaging/host/lib/windows_system_executable.dart",
        "../../../../lib/windows_system_executable.dart",
    ),
    (
        "tools/native_messaging/host/lib/winn_carrier_profile_keys.dart",
        "../../../../lib/winn_carrier_profile_keys.dart",
    ),
    (
        "tools/native_messaging/host/lib/winn_protocol_dispatch.dart",
        "../../../../lib/winn_protocol_dispatch.dart",
    ),
)
# Engine producers actually invoked by tools/build_linux_release.sh. Keep these
# off the hashed regular-file extra list; they are Linux byte producers.
LINUX_ENGINE_PRODUCER_PATHS = (
    "tools/verify_embedded_engine_runtime_versions.py",
    "tools/build_xray_engine.sh",
    "tools/build_winn_protocol_engine.sh",
    "tools/winn_release.py",
    "tools/build_linux_arm64_awg.sh",
)
WINN_DESCRIPTOR_PRODUCER_PATHS = (
    "tools/winn3_descriptor_ring_defines.py",
    "tools/winn3_descriptor_ring_identity.py",
    "tools/verify_winn3_ring_artifact.py",
)
WINN_STANDALONE_PRODUCER_PATH = "tools/verify_standalone_v3_artifact.py"
WEAR_PACKAGE_PROVENANCE_PATHS = (
    "app_store/android/wear/README.md",
    "app_store/android/wear/metadata/en-US/title.txt",
    "app_store/android/wear/metadata/en-US/short_description.txt",
    "app_store/android/wear/metadata/en-US/full_description.txt",
    "app_store/android/wear/metadata/en-US/whats_new.txt",
    "app_store/android/wear/review/play_console_notes.txt",
    "app_store/android/wear/review/data_safety.md",
    "app_store/android/wear/review/privacy_label_manifest.json",
    "app_store/android/wear/review/owner_signoff.json",
    "app_store/android/wear/artifacts/release_candidate.json",
)
PLATFORM_NATIVE_EXTRA_PATHS = {
    "android": (),
    "wear_os": WEAR_PACKAGE_PROVENANCE_PATHS,
    "extension": (),
    "windows": ("assets/icon/app_icon.png",) + WINDOWS_NATIVE_HOST_INPUT_PATHS,
    "linux": (
        "docs/THIRD_PARTY_NOTICES_AND_COMPONENT_INVENTORY.md",
        "web/icons/Icon-512.png",
    ),
    "macos": (
        "apple/ExportOptions/macos-app-store-local.plist",
        "apple/ExportOptions/macos-app-store-connect.plist",
        "apple/ExportOptions/macos-developer-id.plist",
        "assets/icon/Win Empire.png",
        "apple/EngineArtifacts/apple_winn_v3_engine_provenance.json",
    ),
    "ios": (
        "apple/ExportOptions/ios-release-testing.plist",
        "apple/ExportOptions/ios-app-store-local.plist",
        "apple/ExportOptions/ios-testflight-internal.plist",
        "apple/ExportOptions/ios-app-store-connect.plist",
        "assets/icon/Win Empire.png",
        "apple/EngineArtifacts/apple_winn_v3_engine_provenance.json",
    ),
}
COMMON_RELEASE_CONTROL_PATHS = (
    "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json",
    "tools/cross_store_gate_runner.py",
    "tools/cross_store_target_receipt.py",
    "tools/github_backup_only_policy.py",
    "tools/release_dependency_freeze.py",
    "tools/release_source_freeze.py",
    "tools/test_release_source_freeze.py",
    "tools/test_release_dependency_freeze.py",
    "tools/fin_release_gate.sh",
    "tools/release_python_archive_custody.sh",
    "tools/release_browser_archive_custody.py",
    "tools/release_browser_archive_custody.sh",
    "tools/release_go_archive_custody.py",
    "tools/release_go_archive_custody.sh",
    "tools/run_test_suite.py",
    "tools/toolchain-pins.json",
)
PLATFORM_PRODUCER_PATHS = {
    "android": COMMON_RELEASE_CONTROL_PATHS + (
        "tools/android_signing_preseed.ps1",
        "tools/build_android_release.ps1",
        "tools/build_android_release_macos.sh",
        "android/tools/prepare_android_winn_assets.sh",
        "tools/build_winn_protocol_engine.sh",
        "tools/winn_release.py",
        "tools/winn_release_authority.json",
        "tools/build_xray_engine.sh",
        "tools/verify_embedded_engine_runtime_versions.py",
        *WINN_DESCRIPTOR_PRODUCER_PATHS,
        WINN_STANDALONE_PRODUCER_PATH,
        "tools/release_android_toolchain_archive_custody.sh",
        "tools/android_release_publication.py",
        "tools/release_obfuscation_contract.py",
        "tools/private_release_symbol_custody.py",
        "tools/private_symbol_custody.ps1",
        "tools/validate_flutter_package_config.py",
        "tools/validate_release_artifact_privacy.py",
        "tools/verify_android_aab_page_alignment.py",
        "tools/verify_android_aab_signers.py",
        "tools/android_play_redemption_gate.py",
        "tools/wear_os_pairing_contract_check.py",
        "tools/cross_store_upload_readiness.py",
    ),
    "wear_os": COMMON_RELEASE_CONTROL_PATHS + (
        "tools/wear_os_pairing_contract_check.py",
        "wear_os/tools/prepare_release.sh",
        "wear_os/tools/assert_release_aab.py",
        "wear_os/tools/signed_aab_receipt.py",
        "wear_os/tools/create_signed_aab_receipt.py",
        "tools/build_android_release_macos.sh",
        "tools/verify_android_aab_page_alignment.py",
        "tools/verify_android_aab_signers.py",
        "tools/private_release_symbol_custody.py",
        "tools/validate_release_artifact_privacy.py",
        "tools/cross_store_upload_readiness.py",
    ),
    "extension": COMMON_RELEASE_CONTROL_PATHS + (
        "extension/build.py",
        "extension/tools/checks.py",
        "extension/tools/assert_chrome_zip.py",
        "extension/tools/assert_firefox_zip.py",
        "tools/native_messaging/render_host_manifest.py",
        "tools/native_messaging/native_host_layout.py",
        "tools/native_messaging/build_native_host.sh",
        "tools/native_messaging/build_native_host.ps1",
        "tools/release_obfuscation_contract.py",
        "tools/validate_release_artifact_privacy.py",
        "tools/cross_store_upload_readiness.py",
        "tools/release_freeze_client.py",
    ),
    "windows": COMMON_RELEASE_CONTROL_PATHS + (
        "tools/build_windows_awg_engine.ps1",
        "tools/build_windows_amneziawg_client.ps1",
        "tools/native_messaging/build_native_host.ps1",
        "tools/release_obfuscation_contract.py",
        "tools/verify_embedded_engine_runtime_versions.py",
        "tools/windows_winn3_artifact_provenance.py",
        "tools/build_winn_protocol_engine.sh",
        "tools/winn_release.py",
        "tools/winn_release_authority.json",
        *WINN_DESCRIPTOR_PRODUCER_PATHS,
        "installer/windows/build_installer.ps1",
        "tools/windows_cross_store_artifact_gate.py",
        "tools/windows_inno_sign.ps1",
        "tools/strip_image_metadata.py",
        "tools/release-python-requirements.txt",
        "tools/private_release_symbol_custody.py",
        "tools/private_symbol_custody.ps1",
        "tools/validate_release_artifact_privacy.py",
        "tools/cross_store_upload_readiness.py",
        "tools/release_remote_build.py",
        "tools/release_remote_attestation_check.py",
        # release_remote_build.py imports it to verify REMOTE_RUN.json host
        # key signatures, so it is a frozen input like the orchestrator.
        "tools/release_remote_run_record_signature.py",
        "tools/release_freeze_client.py",
    ),
    "linux": COMMON_RELEASE_CONTROL_PATHS + (
        "tools/build_linux_release.sh",
        *LINUX_ENGINE_PRODUCER_PATHS,
        # Pinned public key winn_release.py verify trusts for WINS_WINN_RELEASE_DIR.
        "tools/winn_release_authority.json",
        *WINN_DESCRIPTOR_PRODUCER_PATHS[:3],
        "tools/test_linux_arm64_fallback_elf.py",
        "tools/linux_cross_store_artifact_gate.py",
        "linux/packaging/flathub/manifest_artifact.py",
        "linux/packaging/snap/manifest_artifact.py",
        "tools/linux_release_signing.py",
        "tools/linux_apt_pins.json",
        "tools/verify_linux_apt_pins.py",
        "tools/create_cross_machine_source_archive.ps1",
        "tools/extract_cross_machine_source_archive.sh",
        "tools/release_obfuscation_contract.py",
        "tools/private_release_symbol_custody.py",
        "tools/validate_release_artifact_privacy.py",
        "tools/cross_store_upload_readiness.py",
        "tools/release_remote_build.py",
        "tools/release_remote_attestation_check.py",
        # release_remote_build.py imports it to verify REMOTE_RUN.json host
        # key signatures, so it is a frozen input like the orchestrator.
        "tools/release_remote_run_record_signature.py",
        "tools/release_freeze_client.py",
    ),
    "macos": COMMON_RELEASE_CONTROL_PATHS + (
        "tools/build_apple_release_candidates.sh",
        "tools/freeze_apple_release_candidates.py",
        "tools/validate_apple_submission_package.py",
        "tools/release_freeze_client.py",
        "tools/apple_runtime_smoke.sh",
        "tools/apple_profile_manager.py",
        "tools/ensure_macos_app_icon.sh",
        "tools/stage_apple_engine_artifacts.sh",
        "tools/build_apple_engine_wrappers.sh",
        "tools/build_apple_wg_go_bridge.sh",
        "tools/build_winn_protocol_engine.sh",
        "tools/winn_release.py",
        "tools/winn_release_authority.json",
        "tools/verify_embedded_engine_runtime_versions.py",
        "tools/apple_cross_store_artifact_gate.py",
        "tools/apple_upload_exact_release_candidates.py",
        "tools/native_messaging/build_native_host.sh",
        "tools/native_messaging/native_host_layout.py",
        "tools/native_messaging/render_host_manifest.py",
        *WINN_DESCRIPTOR_PRODUCER_PATHS,
        WINN_STANDALONE_PRODUCER_PATH,
        "tools/release_obfuscation_contract.py",
        "tools/apple_release_symbol_custody.py",
        "tools/validate_release_artifact_privacy.py",
        "tools/cross_store_upload_readiness.py",
    ),
    "ios": COMMON_RELEASE_CONTROL_PATHS + (
        "tools/build_apple_release_candidates.sh",
        "tools/freeze_apple_release_candidates.py",
        "tools/validate_apple_submission_package.py",
        "tools/release_freeze_client.py",
        "tools/apple_runtime_smoke.sh",
        "tools/apple_profile_manager.py",
        "tools/ensure_macos_app_icon.sh",
        "tools/stage_apple_engine_artifacts.sh",
        "tools/build_apple_engine_wrappers.sh",
        "tools/build_apple_wg_go_bridge.sh",
        "tools/build_winn_protocol_engine.sh",
        "tools/winn_release.py",
        "tools/winn_release_authority.json",
        "tools/verify_embedded_engine_runtime_versions.py",
        "tools/apple_cross_store_artifact_gate.py",
        "tools/apple_upload_exact_release_candidates.py",
        "tools/native_messaging/build_native_host.sh",
        "tools/native_messaging/native_host_layout.py",
        "tools/native_messaging/render_host_manifest.py",
        *WINN_DESCRIPTOR_PRODUCER_PATHS,
        "tools/release_obfuscation_contract.py",
        "tools/apple_release_symbol_custody.py",
        "tools/validate_release_artifact_privacy.py",
        "tools/cross_store_upload_readiness.py",
    ),
}
PLATFORM_BUILD_PRODUCERS = {
    "android": "tools/build_android_release.ps1",
    "wear_os": "wear_os/tools/signed_aab_receipt.py",
    "extension": "extension/build.py",
    "windows": "installer/windows/build_installer.ps1",
    "linux": "tools/build_linux_release.sh",
    "macos": "tools/apple_runtime_smoke.sh",
    "ios": "tools/apple_runtime_smoke.sh",
}
# Host-specific release producers. On a darwin host the Android release is
# built by tools/build_android_release_macos.sh itself, which then attests the
# exact artifact bytes it produced. Every other (platform, host) pair uses the
# platform producer above and the witnessed producer execution.
PRODUCER_EXECUTION_WITNESSED = "witnessed"
PRODUCER_EXECUTION_ATTESTED = "producer-attested"
PRODUCER_EXECUTION_HOSTS = ("darwin", "linux", "windows")
PLATFORM_BUILD_PRODUCERS_BY_HOST = {
    ("android", "darwin"): "tools/build_android_release_macos.sh",
    # tools/build_apple_release_candidates.sh archives, signs and exports the
    # IPA and PKG through tools/apple_runtime_smoke.sh with Xcode, which the
    # witnessed sandbox cannot read, so Apple receipts are producer-attested
    # like the macOS Android producer. The producer identity stays
    # tools/apple_runtime_smoke.sh, the identity the Apple cross-store gate
    # (PRODUCER_RELATIVE) and the readiness producer_ids already bind. Since
    # round R11a, _validate_release_artifact_bytes accepts only an IPA or PKG
    # whose code signature, seal, XAR checksum and signature verify to the
    # pinned Apple Root CA for the release team (_require_signed_apple_ipa,
    # _require_signed_apple_pkg).
    ("ios", "darwin"): "tools/apple_runtime_smoke.sh",
    ("macos", "darwin"): "tools/apple_runtime_smoke.sh",
    # extension/build.py compiles the real native host with Dart for its bridge
    # gate and minifies with the pinned esbuild cache, neither of which the
    # witnessed sandbox can read, so on darwin it builds the three store zips
    # itself between begin-build and finish-build (--release-build-receipts).
    ("extension", "darwin"): "extension/build.py",
    # wear_os/tools/prepare_release.sh runs the strict Gradle bundleRelease and
    # signs with the owner's upload key outside any sandbox, then attests the
    # exact AAB between begin-build and finish-build.
    ("wear_os", "darwin"): "wear_os/tools/prepare_release.sh",
}
PRODUCER_ATTESTED_PLATFORM_HOSTS = frozenset(
    {
        ("android", "darwin"),
        ("ios", "darwin"),
        ("macos", "darwin"),
        ("extension", "darwin"),
        ("wear_os", "darwin"),
    }
)
# Only the Apple producers ship a reviewed artifact name that carries an
# apostrophe (tools/build_apple_release_candidates.sh:70-73). Every witnessed
# producer re-checks the name it is handed with the narrower charset
# (tools/apple_runtime_smoke.sh:40, tools/build_android_release.ps1:156,
# installer/windows/build_installer.ps1:227), so accepting an apostrophe for a
# witnessed platform would only produce a name that its own producer refuses.
ARTIFACT_NAME_CHARSET = "A-Za-z0-9._+ -"
APPLE_ARTIFACT_NAME_CHARSET = "A-Za-z0-9._+' -"
ARTIFACT_NAME_APOSTROPHE_PLATFORMS = frozenset({"ios", "macos"})


def _artifact_name_pattern(platform: str) -> str:
    """Return the built-artifact filename pattern reviewed for ``platform``."""

    charset = (
        APPLE_ARTIFACT_NAME_CHARSET
        if platform in ARTIFACT_NAME_APOSTROPHE_PLATFORMS
        else ARTIFACT_NAME_CHARSET
    )
    return rf"[A-Za-z0-9][{charset}]{{0,191}}"


# Remote-attested producers (round R11a). The authenticated worker cannot start
# on Windows or Linux (sandbox-exec, libproc and fcntl are macOS only), so the
# macOS release host orchestrates: begin-build --remote-host binds a
# deterministic tar of the frozen revision's tracked files (every member checked
# against its Git blob and every manifest file checked against the tar), the
# remote native host runs the producer with tools/release_remote_attestation_check.py
# in place of its direct controller calls, and finish-build --remote-host on the
# Mac validates the copied-back artifact bytes and the remote run record against
# the begin record. Keys are (platform, remote host kind); the orchestrating
# host is always darwin.
PRODUCER_EXECUTION_REMOTE_ATTESTED = "remote-attested"
REMOTE_ATTESTATION_ORCHESTRATOR_HOST = "darwin"
REMOTE_ATTESTED_PLATFORM_HOSTS = {
    ("linux", "linux"): "tools/build_linux_release.sh",
    ("windows", "windows"): "installer/windows/build_installer.ps1",
}
REMOTE_ATTESTATION_CONTRACT = "winsvpn-remote-attested-build-v1"
REMOTE_SECRET_SCAN_DEFERRED = "deferred-to-release-host"
RELEASE_HOST_SECRET_SCAN_CONTRACT = "winsvpn-release-host-secret-scan-v2"
RELEASE_HOST_SECRET_SCANNER = "tools/validate_release_artifact_privacy.py"
RELEASE_HOST_SECRET_SCANNER_BYTES_LIMIT = 8 * 1024 * 1024
# Every module the scanner loads, dependencies first and the scanner itself last,
# with the digest the authenticated worker executes. The first two are in no
# platform manifest, so the worker pins the whole closure itself: it runs these
# exact bytes (held by descriptor, handed to the child over stdin) or refuses.
# tools/test_release_dependency_freeze.py keeps this table equal to the files.
RELEASE_HOST_SECRET_SCANNER_CLOSURE = {
    "tools/release_secret_scan_policy.py": "8c5e7732b589b4a459b7e7bca22109ac5c234aeca1f7f52deb96f72a4a0c1180",
    "tools/release_secret_inventory.py": "c0ffc1f731b0d82eaf95c594e651a2a55933d3db434f3c2f462b5ba934321ae1",
    "tools/release_obfuscation_contract.py": "002a2ba41e54d5d719279bd0021ecf6fceac509dc8234dbc9c94241c82a66ad7",
    "tools/validate_release_artifact_privacy.py": "5aa96f955256eed8349f72010aee0637607589f568b0a3e11c8506d6a8bc55ce",
}
# The scan target follows the installer's canonical file name (the scanner refuses
# any other pairing), and the architecture in the name must be the build's.
RELEASE_HOST_SECRET_SCAN_TARGETS = {
    "winsvpn-setup.exe": "windows-x64-installer",
    "winsvpn-unsigned-local-setup.exe": "windows-x64-installer",
    "winsvpn-partnercenter.exe": "windows-x64-partner-center",
    "winsvpn-unsigned-local-partnercenter.exe": "windows-x64-partner-center",
    "winsvpn-setup-arm64.exe": "windows-arm64-installer",
    "winsvpn-unsigned-local-setup-arm64.exe": "windows-arm64-installer",
    "winsvpn-partnercenter-arm64.exe": "windows-arm64-partner-center",
    "winsvpn-unsigned-local-partnercenter-arm64.exe": "windows-arm64-partner-center",
}
RELEASE_HOST_SECRET_SCAN_TIMEOUT_SECONDS = 600
RELEASE_HOST_SECRET_INVENTORY_PATH_LIMIT = 4096
RELEASE_HOST_SECRET_SCAN_REPORT = re.compile(
    r"RELEASE ARTIFACT PRIVACY: PASS\n"
    r"revision=(?P<revision>[^\n]{1,128})\n"
    r"labels=[^\n]*\n"
    r"label_count=(?P<labels>[0-9]+)\n"
    r"unique_value_count=(?P<values>[0-9]+)\n"
    r"inventory_sha256=(?P<inventory>[0-9a-f]{64})\n"
    r"target=(?P<target>[a-z0-9-]+)\n"
    r"artifact=(?P<artifact>[0-9a-f]{64})\n"
    r"matched_labels=\n?"
)
# Runs in the child interpreter. It executes the held bytes of the scanner closure
# (each digest checked again here) as the scanner's own modules, so the child
# imports nothing from the repository and nothing from the caller's environment.
_RELEASE_HOST_SECRET_SCAN_BOOTSTRAP = (
    "import binascii, hashlib, json, sys, types\n"
    "bundle = json.loads(sys.stdin.buffer.read().decode('utf-8'))\n"
    "repo, entry = bundle['repo'], bundle['entrypoint']\n"
    "sys.argv = [repo + '/' + entry] + bundle['arguments']\n"
    "for relative in bundle['order']:\n"
    "    raw = binascii.a2b_base64(bundle['files'][relative], strict_mode=True)\n"
    "    if hashlib.sha256(raw).hexdigest() != bundle['digests'][relative]:\n"
    "        raise SystemExit('secret scanner closure digest mismatch')\n"
    "    path = repo + '/' + relative\n"
    "    if relative == entry:\n"
    "        scope = {'__name__': '__main__', '__file__': path, '__package__': None, '__spec__': None}\n"
    "        exec(compile(raw, path, 'exec'), scope)\n"
    "    else:\n"
    "        module = types.ModuleType(relative.rsplit('/', 1)[-1][:-3])\n"
    "        module.__file__, module.__package__, module.__spec__ = path, '', None\n"
    "        sys.modules[module.__name__] = module\n"
    "        exec(compile(raw, path, 'exec'), module.__dict__)\n"
)
REMOTE_SOURCE_ARCHIVE_CONTRACT = "winsvpn-remote-source-archive-v1"
REMOTE_RUN_RECORD_CONTRACT = "winsvpn-remote-producer-run-v1"
REMOTE_SOURCE_ARCHIVE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.tar")
NATIVE_BUILD_WITNESS_ADAPTERS = {
    "tools/build_android_release.ps1": {
        "platforms": ("android",),
        "host": "windows",
        "systems": ("windows",),
        "runtime": "powershell-file",
    },
    "wear_os/tools/signed_aab_receipt.py": {
        "platforms": ("wear_os",),
        "host": "native-android-build-host",
        "systems": ("darwin",),
        "runtime": "isolated-python",
    },
    "extension/build.py": {
        "platforms": ("extension",),
        "host": "native-extension-build-host",
        "systems": ("darwin",),
        "runtime": "isolated-python",
    },
    "installer/windows/build_installer.ps1": {
        "platforms": ("windows",),
        "host": "windows",
        "systems": ("windows",),
        "runtime": "powershell-file",
    },
    "tools/build_linux_release.sh": {
        "platforms": ("linux",),
        "host": "linux",
        "systems": ("linux",),
        "runtime": "bash-file",
    },
    "tools/apple_runtime_smoke.sh": {
        "platforms": ("macos", "ios"),
        "host": "darwin",
        "systems": ("darwin",),
        "runtime": "bash-file",
    },
}
PLATFORM_ARTIFACT_PRODUCER_PATHS = {
    "android": ("tools/build_android_release.ps1",),
    "wear_os": ("wear_os/tools/signed_aab_receipt.py",),
    "extension": ("extension/build.py",),
    "windows": ("installer/windows/build_installer.ps1",),
    "linux": (
        "tools/build_linux_release.sh",
        "linux/packaging/flathub/manifest_artifact.py",
        "linux/packaging/snap/manifest_artifact.py",
    ),
    "macos": ("tools/apple_runtime_smoke.sh",),
    "ios": ("tools/apple_runtime_smoke.sh",),
}
CANONICAL_FREEZE_PLATFORMS = (
    "android",
    "wear_os",
    "ios",
    "macos",
    "windows",
    "linux",
    "extension",
)
PRIVACY_POLICY_URL = "https://www.winsvpn.org/privacy/"
PLATFORM_STORE_SURFACES = {
    "android": ("google-play-phone", "google-play-tv"),
    "wear_os": ("google-play-wear-os",),
    "ios": ("apple-app-store-iphone", "apple-app-store-watch-companion"),
    "macos": ("mac-app-store", "developer-id"),
    "windows": ("website-win32", "partner-center-win32"),
    "linux": ("website-tarball", "flathub-separate-manifest", "snap-separate-manifest"),
    "extension": ("chrome-web-store", "edge-add-ons", "firefox-amo"),
}
PLATFORM_ALLOWED_TARGETS = {
    "android": (
        "android-release-apk",
        "android-release-aab",
        "android-tv-release-apk",
        "android-tv-release-aab",
    ),
    "wear_os": ("wear-os-release-aab",),
    "extension": ("chrome-zip", "edge-zip", "firefox-zip"),
    "windows": (
        "windows-x64-inno-signed",
        "windows-x64-inno-unsigned",
        "windows-x64-inno-unsigned-prebuilt",
        "windows-arm64-inno-signed",
        "windows-arm64-inno-unsigned",
        "windows-arm64-inno-unsigned-prebuilt",
    ),
    "linux": ("linux-x64", "linux-arm64"),
    "macos": ("app-store-local", "app-store-connect", "developer-id"),
    "ios": (
        "app-store-local",
        "app-store-connect",
        "testflight-internal",
        "release-testing",
    ),
}
PLATFORM_REQUIRED_GATE_PRODUCERS = {
    "android": (
        "tools/release_dependency_freeze.py",
        "tools/release_python_archive_custody.sh",
        "tools/release_android_toolchain_archive_custody.sh",
        "tools/release_obfuscation_contract.py",
        "tools/verify_android_aab_signers.py",
        "tools/validate_flutter_package_config.py",
        "tools/validate_release_artifact_privacy.py",
        "tools/private_release_symbol_custody.py",
        "tools/cross_store_upload_readiness.py",
    ),
    "wear_os": (
        "tools/release_dependency_freeze.py",
        "tools/verify_android_aab_signers.py",
        "wear_os/tools/signed_aab_receipt.py",
        "tools/validate_release_artifact_privacy.py",
        "tools/cross_store_upload_readiness.py",
    ),
    "extension": (
        "tools/release_dependency_freeze.py",
        "extension/tools/assert_chrome_zip.py",
        "extension/tools/assert_firefox_zip.py",
        "tools/release_obfuscation_contract.py",
        "tools/validate_release_artifact_privacy.py",
        "tools/cross_store_upload_readiness.py",
    ),
    "windows": (
        "tools/release_dependency_freeze.py",
        "tools/windows_cross_store_artifact_gate.py",
        "tools/release_obfuscation_contract.py",
        "tools/validate_release_artifact_privacy.py",
        "tools/private_release_symbol_custody.py",
        "tools/cross_store_upload_readiness.py",
    ),
    "linux": (
        "tools/release_dependency_freeze.py",
        "tools/linux_cross_store_artifact_gate.py",
        "tools/release_obfuscation_contract.py",
        "tools/validate_release_artifact_privacy.py",
        "tools/private_release_symbol_custody.py",
        "tools/cross_store_upload_readiness.py",
    ),
    "macos": (
        "tools/release_dependency_freeze.py",
        "tools/apple_cross_store_artifact_gate.py",
        "tools/release_obfuscation_contract.py",
        "tools/validate_release_artifact_privacy.py",
        "tools/apple_release_symbol_custody.py",
        "tools/cross_store_upload_readiness.py",
    ),
    "ios": (
        "tools/release_dependency_freeze.py",
        "tools/apple_cross_store_artifact_gate.py",
        "tools/release_obfuscation_contract.py",
        "tools/validate_release_artifact_privacy.py",
        "tools/apple_release_symbol_custody.py",
        "tools/cross_store_upload_readiness.py",
    ),
}

# These paths are generated by Flutter, Gradle, CocoaPods, CMake, IDEs, or a
# build itself. They are outputs, not release-authorized source inputs.
EXCLUDED_DIR_NAMES = {
    ".cxx",
    ".dart_tool",
    ".gradle",
    ".idea",
    ".kotlin",
    ".plugin_symlinks",
    ".symlinks",
    ".vscode",
    "build",
    "deriveddata",
    "ephemeral",
    "pods",
    "xray-extract",
    "xcuserdata",
}
EXCLUDED_FILE_NAMES = {
    ".ds_store",
    # Flutter writes ios/Flutter/Flutter.podspec on every iOS build; its own header
    # says it is generated and must not be checked in.
    "flutter.podspec",
    "flutter_export_environment.sh",
    "generated.xcconfig",
    "generatedpluginregistrant.cc",
    "generatedpluginregistrant.h",
    "generatedpluginregistrant.java",
    "generatedpluginregistrant.kt",
    "generatedpluginregistrant.m",
    "generatedpluginregistrant.swift",
    "generated_plugin_registrant.cc",
    "generated_plugin_registrant.h",
    "generated_plugin_registrant.m",
    "generated_plugin_registrant.swift",
    "generated_plugins.cmake",
    "local.properties",
    "thumbs.db",
    "xray-windows-64.zip",
}
EXCLUDED_FILE_SUFFIXES = {".iml"}

# AppleDouble sidecars. macOS writes `._<name>` next to a real file to carry
# resource forks and extended attributes across filesystems that cannot store
# them. They are host filesystem metadata, never a build input: nothing in any
# platform build reads them, and their contents change when a file is merely
# copied between volumes.
#
# Measured 2026-08-05: 27 of the 52 files under `linux/` are AppleDouble
# sidecars -- 52 percent of that platform's entire native input set. Index r18
# recorded them as release inputs, which makes the release fingerprint depend on
# macOS xattr churn that has nothing to do with the software being shipped, and
# makes any "inputs changed" verdict from it uninterpretable.
#
# They are EXCLUDED here, not deleted: roughly 69,000 of them exist in this
# tree and removing them is explicitly out of bounds. The indexer simply stops
# claiming they are part of a release.
APPLEDOUBLE_PREFIX = "._"

# Credentials must be supplied outside the repository. Encountering one in an
# otherwise selected input scope is a hard failure rather than a silent omit.
FORBIDDEN_FILE_NAMES = {
    ".env",
    "google-services.json",
    "key.properties",
    "secrets.json",
}
FORBIDDEN_SUFFIXES = {
    ".jks",
    ".key",
    ".keystore",
    ".mobileprovision",
    ".p12",
    ".pem",
    ".pfx",
    ".ppk",
    ".provisionprofile",
}
MAX_DEPENDENCY_FILE_BYTES = 512 * 1024 * 1024
MAX_DEPENDENCY_JSON_BYTES = 16 * 1024 * 1024
MAX_DEPENDENCY_FILE_COUNT = 100_000
# Measured at release 1.0.16+33: the Android native set (android/ plus
# winn_protocol_experimental/) is 594.84 MiB in 1,875 files, 461.59 MiB of it
# the 12 tracked libxray.so copies (4 source sets x 3 ABIs). Every selected
# payload is held in memory until the command returns and the allocator keeps
# about half again on top, so the worst case at this bound is roughly 1.5 GiB
# resident (898 MiB measured for 594.84 MiB). The worker also keeps about 7.6
# descriptors open per selected file (14,283 for the Android set); a finish-build
# holds several such sets, so the soft limit is raised to REQUIRED_OPEN_FILES
# (131,072) before any input is held.
MAX_DEPENDENCY_AGGREGATE_BYTES = 1024 * 1024 * 1024
MAX_RECEIPT_AGE = dt.timedelta(hours=72)
MAX_RECEIPT_CLOCK_SKEW = dt.timedelta(minutes=5)
POSTMORTEM_MAX_AGE_NS = int(MAX_RECEIPT_AGE.total_seconds() * 1_000_000_000)
POSTMORTEM_CLOCK_SKEW_NS = int(
    MAX_RECEIPT_CLOCK_SKEW.total_seconds() * 1_000_000_000
)
ISSUANCE_ID = re.compile(r"[0-9a-f]{32}\Z")
APP_SOURCE_LOCK_NAME = "APP_SOURCE_LOCK.json"
APP_SOURCE_LOCK_CONTRACT = "winsvpn-app-source-lock-v1"
APP_SOURCE_CONTRACT = "winsvpn-native-app-sources-v1"
WEBSITE_SOURCE_CONTRACT = "winsvpn-website-staging-sources-v1"
SCOPE_FREEZE_NAME = "SCOPE_FREEZE.json"
SOURCE_FREEZE_RECEIPT_NAME = "SOURCE_FREEZE_RECEIPT.json"
SOURCE_FREEZE_RECEIPT_CONTRACT = "winsvpn-dependency-source-freeze-receipt-v1"
SOURCE_FREEZE_RECEIPT_ISSUER = "winsvpn-release-source-freeze"
TOOLCHAIN_CUSTODY_RECEIPT_NAME = "TOOLCHAIN_CUSTODY_RECEIPT.json"
TOOLCHAIN_CUSTODY_RECEIPT_CONTRACT = "winsvpn-dependency-toolchain-custody-receipt-v1"
TOOLCHAIN_CUSTODY_RECEIPT_ISSUER = "winsvpn-release-toolchain-custody"
TOOLCHAIN_PIN_PATH = "tools/toolchain-pins.json"
APP_SOURCE_LOCK_KEYS = {
    "schema_version",
    "contract",
    "release",
    "scope_frozen",
    "publication_locked",
    "scope_freeze_sha256",
    "frozen_combined_source_fingerprint_sha256",
    "frozen_combined_source_file_count",
    "app_source_contract",
    "app_source_fingerprint_sha256",
    "app_source_file_count",
    "website_source_contract",
    "website_source_fingerprint_sha256_at_freeze",
    "website_source_file_count_at_freeze",
    "website_index_sha256_at_freeze",
    "immutable_website_source_fingerprint_sha256_at_freeze",
    "immutable_website_source_file_count_at_freeze",
    "website_mutable_paths_after_scope_freeze",
    "website_staging_allowed_after_scope_freeze",
    "issuance_id",
    "created_utc",
}
SOURCE_FREEZE_RECEIPT_KEYS = {
    "schema_version",
    "contract",
    "release",
    "created_utc",
    "issuance_id",
    "authenticated",
    "issuer",
    "app_source_lock",
}
TOOLCHAIN_CUSTODY_RECEIPT_KEYS = {
    "schema_version",
    "contract",
    "release",
    "created_utc",
    "issuance_id",
    "authenticated",
    "issuer",
    "pin",
    "toolchain",
}
CUSTODY_BINDING_KEYS = {"path", "sha256", "issuance_id"}
_WRITABLE_MASK = stat.S_IWGRP | stat.S_IWOTH
# Tests may assign a callable after the first selected-set capture or after the
# first hashed capture. Production freeze leaves these unset.
_POST_SELECT_HOOK = None
_POST_INPUT_CAPTURE_HOOK = None
# Tests may assign a callable after each directory is bound through openat and
# before child lookup continues. Production freeze leaves this unset.
_POST_DIRECTORY_BIND_HOOK = None
# Tests may assign a callable after the last verification recapture and before
# the immediate pre-return revalidation. Production freeze leaves this unset.
_POST_FINAL_CAPTURE_HOOK = None
_SOURCE_FREEZE_MODULE = None
_SOURCE_FREEZE_TRUST_PATH = None
_SOURCE_FREEZE_SELF_AUTHORED_OVERRIDE = None
# Isolated fixture/test mode. Tests may set this True. Production freeze leaves
# it False. The CLI refuses it, and library freeze without Git never sets
# publication_authorized. Fixture mode cannot authorize a release.
_FIXTURE_MODE = False
# Set only by main() for the duration of a CLI invocation. Library harnesses
# without Git stay on the isolated fixture path; the CLI cannot.
_PRODUCTION_REQUIRED = False
_AUTHORITATIVE_WORKER_SWITCH = "--_wins-release-dependency-worker-fd"
_AUTHORITATIVE_WORKER_READY = False
_AUTHORITATIVE_CONTROLLER_PATH: pathlib.Path | None = None
# The authoritative worker runs on the release interpreter pinned for this host
# by tools/toolchain-pins.json: tools.python.reviewed_executable_path[<host>]
# whose bytes hash to tools.python.executable_sha256[<host>]. The worker reads
# that pin from the committed pins file and binds its own kernel process image
# to the pinned path and bytes before it grants production authority.
_RELEASE_PYTHON_PIN_MANIFEST = "tools/toolchain-pins.json"
_RELEASE_PYTHON_VERSION = (3, 14, 7)
_RELEASE_PYTHON_HOST_KEYS = {"arm64": "darwin_arm64", "x86_64": "darwin_amd64"}
_MAX_RELEASE_CONTROLLER_BYTES = 4 * 1024 * 1024
_GIT_TIMEOUT_SEC = 120
_REVIEWED_GIT_EXECUTABLE = pathlib.Path("/usr/bin/git")
_MAX_GIT_EXECUTABLE_BYTES = 64 * 1024 * 1024
GIT_UNTRACKED_INPUT = (
    "untracked filesystem file is not a tracked Git tree input"
)
GIT_STAGED_ONLY_INPUT = (
    "staged-only path is not in the exact tracked Git tree"
)
GIT_SYMLINK_INPUT = (
    "tracked Git symlink is forbidden as a hashed release input"
)
GIT_DIRTY_SOURCE = (
    "source state is not immutable/clean according to the local release policy"
)
GIT_INDEX_WORKTREE_SPLIT = (
    "Git index and exact HEAD tree do not identify the same release input"
)
GIT_METADATA_DRIFT = "tracked Git file mode differs from the release input"
GIT_OMITTED_INPUT = "tracked Git input is missing from the freeze denominator"
GIT_REQUIRED = "production release freeze requires a Git repository"
FIXTURE_CANNOT_AUTHORIZE = (
    "isolated fixture/test mode cannot authorize a production release freeze"
)
AUTHENTICATED_WORKER_LAUNCH_REQUIRED = (
    "production authority requires the pinned release Python worker launched "
    "by tools/run_release_dependency_freeze.sh with a caller-retained "
    "controller descriptor"
)
PINNED_RELEASE_PYTHON_REQUIRED = (
    "authoritative worker interpreter is not the release Python pinned by "
    "tools/toolchain-pins.json"
)


class DependencyFreezeError(RuntimeError):
    """Raised when a dependency manifest cannot be created or verified."""


class _CommittedPublicationError(DependencyFreezeError):
    """Raised when a durable record/anchor commit preceded a later failure."""


@dataclasses.dataclass(frozen=True)
class _GitTreeState:
    object_format: str
    git_executable_sha256: str
    head: str
    tree: str
    blobs: dict[str, tuple[str, str, str]]
    index: dict[str, tuple[str, str, str]]
    flags: dict[str, str]
    porcelain: tuple[tuple[str, str], ...]


@dataclasses.dataclass(frozen=True)
class _GitExecutableCustody:
    path: pathlib.Path
    descriptor: int
    identity: tuple[int, ...]
    sha256: str


@dataclasses.dataclass(frozen=True)
class _GitRepositoryCustody:
    repo: pathlib.Path
    repo_descriptor: int
    repo_identity: tuple[int, ...]
    metadata_components: tuple[object, ...]
    mutation_guard: object | None


def _collect_git_metadata_components(
    parent_fd: int,
    relative: str,
    allowed_owners: frozenset[int],
    components: list[object],
) -> None:
    if len(components) > 100_000:
        raise DependencyFreezeError("Git metadata tree is outside the accepted bound.")
    for name in _list_directory_names(parent_fd, relative):
        child_relative = _join_relative(relative, name)
        folded_relative = unicodedata.normalize("NFKC", child_relative).casefold()
        if folded_relative in {
            ".git/commondir",
            ".git/config.worktree",
            ".git/info/grafts",
            ".git/objects/info/alternates",
            ".git/objects/info/http-alternates",
            ".git/refs/replace",
        }:
            raise DependencyFreezeError(
                "Git metadata uses an external or replacement-object indirection."
            )
        path_before = _lstat_at(parent_fd, name, child_relative)
        if _is_reparse_stat(path_before):
            raise DependencyFreezeError(
                "Git metadata uses a symlink, junction, or reparse point."
            )
        if stat.S_ISDIR(path_before.st_mode):
            descriptor, info = _bind_directory_fd(
                parent_fd, name, child_relative, allowed_owners
            )
            component = _HeldPathComponent(
                parent_descriptor=parent_fd,
                name=name,
                relative=child_relative,
                descriptor=descriptor,
                identity=_file_identity(info),
                directory=True,
            )
            components.append(component)
            try:
                _collect_git_metadata_components(
                    descriptor, child_relative, allowed_owners, components
                )
            except Exception:
                raise
            continue
        if not stat.S_ISREG(path_before.st_mode):
            raise DependencyFreezeError("Git metadata contains a special filesystem node.")
        if path_before.st_nlink != 1:
            raise DependencyFreezeError("Git metadata file must have link count 1.")
        _require_owned_mode(
            child_relative, path_before, allowed_owners, kind="Git metadata file"
        )
        descriptor = _open_at(
            parent_fd, name, _nofollow_flags(), child_relative, "Git metadata"
        )
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or _file_identity(opened) != _file_identity(path_before)
            ):
                raise DependencyFreezeError("Git metadata identity changed while opening.")
            if folded_relative == ".git/config":
                if opened.st_size > MAX_DEPENDENCY_JSON_BYTES:
                    raise DependencyFreezeError("Git local configuration is too large.")
                os.lseek(descriptor, 0, os.SEEK_SET)
                config_payload = os.read(descriptor, opened.st_size + 1)
                os.lseek(descriptor, 0, os.SEEK_SET)
                if len(config_payload) != opened.st_size:
                    raise DependencyFreezeError(
                        "Git local configuration changed while opening."
                    )
                try:
                    config_text = config_payload.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise DependencyFreezeError(
                        "Git local configuration is not strict UTF-8."
                    ) from exc
                if (
                    config_payload.startswith(b"\xef\xbb\xbf")
                    or b"\r" in config_payload
                    or b"\0" in config_payload
                    or any(
                        byte < 0x20 and byte not in {0x09, 0x0A}
                        for byte in config_payload
                    )
                ):
                    raise DependencyFreezeError(
                        "Git local configuration uses unsupported control syntax."
                    )
                if re.search(
                    r"(?im)^[ \t]*\[[ \t]*include(?:if)?(?:[ \t\"]|\])",
                    config_text,
                ) or re.search(
                    r"(?im)^[ \t]*(?:worktree|gitdir|objectdirectory|"
                    r"alternates|attributesfile)[ \t]*=",
                    config_text,
                ):
                    raise DependencyFreezeError(
                        "Git local configuration uses an external path indirection."
                    )
            components.append(
                _HeldPathComponent(
                    parent_descriptor=parent_fd,
                    name=name,
                    relative=child_relative,
                    descriptor=descriptor,
                    identity=_file_identity(opened),
                    directory=False,
                )
            )
        except Exception:
            os.close(descriptor)
            raise


def _open_git_repository_custody(
    repo: pathlib.Path, allowed_owners: frozenset[int]
) -> _GitRepositoryCustody:
    repo_descriptor, repo_info = _open_repo_dir(repo, allowed_owners)
    components: list[object] = []
    guard: object | None = None
    try:
        git_descriptor, git_info = _bind_directory_fd(
            repo_descriptor, ".git", ".git", allowed_owners
        )
        components.append(
            _HeldPathComponent(
                parent_descriptor=repo_descriptor,
                name=".git",
                relative=".git",
                descriptor=git_descriptor,
                identity=_file_identity(git_info),
                directory=True,
            )
        )
        _collect_git_metadata_components(
            git_descriptor, ".git", allowed_owners, components
        )
        guarded_descriptors = (
            repo_descriptor,
            *(component.descriptor for component in components),
        )
        guard = _create_mutation_guard(
            guarded_descriptors,
            "Git repository custody",
            write_descriptors=guarded_descriptors,
        )
        custody = _GitRepositoryCustody(
            repo=repo,
            repo_descriptor=repo_descriptor,
            repo_identity=_file_identity(repo_info),
            metadata_components=tuple(components),
            mutation_guard=guard,
        )
        _rebind_git_repository_custody(custody)
        return custody
    except Exception:
        _close_mutation_guard(guard)
        for component in reversed(components):
            _close_quietly(component.descriptor)
        _close_quietly(repo_descriptor)
        raise


def _rebind_git_repository_custody(custody: _GitRepositoryCustody) -> None:
    _rebind_held_components(
        custody.repo,
        custody.repo_descriptor,
        custody.repo_identity,
        custody.metadata_components,
        "Git repository custody",
        custody.mutation_guard,
    )


def _close_git_repository_custody(custody: _GitRepositoryCustody) -> None:
    _close_mutation_guard(custody.mutation_guard)
    for component in reversed(custody.metadata_components):
        _close_quietly(component.descriptor)
    _close_quietly(custody.repo_descriptor)


def isolated_fixture_mode_active() -> bool:
    return _FIXTURE_MODE is True


def _native_build_witness_adoption_gaps(
    platform: str, producer_payload: bytes
) -> tuple[str, ...]:
    producer = PLATFORM_BUILD_PRODUCERS.get(platform)
    adapter = NATIVE_BUILD_WITNESS_ADAPTERS.get(producer or "")
    if adapter is None or platform not in adapter["platforms"]:
        return ("reviewed native adapter mapping",)
    required = (
        ("contract marker", NATIVE_BUILD_WITNESS_MARKER),
        ("private attempt marker", BUILD_ATTEMPT_MARKER),
        ("attempt switch", BUILD_ATTEMPT_SWITCH.encode("ascii")),
        ("attempt contract", BUILD_ATTEMPT_CONTRACT.encode("ascii")),
        (
            "streaming output capability",
            b"WINS_RELEASE_DEPENDENCY_OUTPUT_FD",
        ),
        ("native host contract", f"WINS_RELEASE_DEPENDENCY_NATIVE_HOST={adapter['host']}".encode("ascii")),
        ("native runtime contract", f"WINS_RELEASE_DEPENDENCY_NATIVE_RUNTIME={adapter['runtime']}".encode("ascii")),
        *((name, name.encode("ascii")) for name in NATIVE_BUILD_WITNESS_REQUIRED_ENV),
    )
    return tuple(label for label, token in required if token not in producer_payload)


def _platform_build_producer(platform: str, host: str) -> str:
    """Return the only producer accepted for ``platform`` built on ``host``."""

    if platform not in PLATFORM_BUILD_PRODUCERS or host not in PRODUCER_EXECUTION_HOSTS:
        raise DependencyFreezeError(
            f"Unsupported build producer host for {platform}: {host}"
        )
    return PLATFORM_BUILD_PRODUCERS_BY_HOST.get(
        (platform, host), PLATFORM_BUILD_PRODUCERS[platform]
    )


def _platform_build_execution(platform: str, host: str) -> str:
    """Return how the receipt for ``platform`` built on ``host`` is produced."""

    _platform_build_producer(platform, host)
    if (platform, host) in PRODUCER_ATTESTED_PLATFORM_HOSTS:
        return PRODUCER_EXECUTION_ATTESTED
    return PRODUCER_EXECUTION_WITNESSED


def _require_build_witness_boundary(repo: pathlib.Path, platform: str) -> None:
    """Require production authority and a reviewed regular producer file.

    The static token scan in ``_native_build_witness_adoption_gaps`` no longer
    refuses here: every darwin and linux producer lacked at least one token, so
    the scan refused every receipt on those hosts. The producer is still bound
    by SHA-256 in the build claim, executed only through the witnessed attempt
    (which itself requires ``BUILD_ATTEMPT_MARKER``), and its streamed output is
    the only artifact a receipt can record.
    """

    if isolated_fixture_mode_active():
        return
    if not (_PRODUCTION_REQUIRED and _AUTHORITATIVE_WORKER_READY):
        raise DependencyFreezeError(FIXTURE_CANNOT_AUTHORIZE)
    producer_relative = _platform_build_producer(platform, _native_process_host())
    held = _hold_repo_regular_file(
        repo,
        repo / producer_relative,
        _allowed_owners(repo),
        label=f"{platform} native build producer",
    )
    try:
        _rebind_held_regular_file(held)
    finally:
        _close_held_regular_file(held)


def _git_env() -> dict[str, str]:
    return {
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_KEY_0": "core.fsmonitor",
        "GIT_CONFIG_KEY_1": "core.hooksPath",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_VALUE_0": "false",
        "GIT_CONFIG_VALUE_1": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _open_reviewed_git_executable() -> _GitExecutableCustody:
    path = pathlib.Path("/usr/bin/git")
    if _REVIEWED_GIT_EXECUTABLE != path or not path.is_absolute():
        raise DependencyFreezeError("reviewed Git executable identity changed")
    try:
        path_before = os.lstat(path)
        descriptor = os.open(path, _nofollow_flags())
    except OSError as suc:
        raise DependencyFreezeError(GIT_REQUIRED) from suc
    try:
        before = os.fstat(descriptor)
        if (
            _is_reparse_stat(path_before)
            or not stat.S_ISREG(before.st_mode)
            or path_before.st_uid != 0
            or before.st_uid != 0
            or bool(before.st_mode & _WRITABLE_MASK)
            or not bool(before.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
            or before.st_size <= 0
            or before.st_size > _MAX_GIT_EXECUTABLE_BYTES
            or _file_identity(path_before) != _file_identity(before)
        ):
            raise DependencyFreezeError("reviewed Git executable custody is invalid")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                raise DependencyFreezeError("reviewed Git executable ended early")
            digest.update(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise DependencyFreezeError("reviewed Git executable grew while read")
        after = os.fstat(descriptor)
        path_after = os.lstat(path)
        if not (
            _file_identity(path_before)
            == _file_identity(before)
            == _file_identity(after)
            == _file_identity(path_after)
        ):
            raise DependencyFreezeError("reviewed Git executable changed during custody")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return _GitExecutableCustody(
            path=path,
            descriptor=descriptor,
            identity=_file_identity(before),
            sha256=digest.hexdigest(),
        )
    except Exception:
        os.close(descriptor)
        raise


def _rebind_reviewed_git_executable(custody: _GitExecutableCustody) -> None:
    try:
        held = os.fstat(custody.descriptor)
        path_now = os.lstat(custody.path)
        reopened = os.open(custody.path, _nofollow_flags())
    except OSError as suc:
        raise DependencyFreezeError("reviewed Git executable custody changed") from suc
    try:
        opened = os.fstat(reopened)
    finally:
        os.close(reopened)
    if not (
        stat.S_ISREG(held.st_mode)
        and _file_identity(held) == custody.identity
        and _file_identity(path_now) == custody.identity
        and _file_identity(opened) == custody.identity
    ):
        raise DependencyFreezeError("reviewed Git executable custody changed")


def _git_blob_oid(payload: bytes, object_format: str) -> str:
    header = f"blob {len(payload)}\0".encode("ascii")
    body = header + payload
    if object_format == "sha1":
        return hashlib.sha1(body, usedforsecurity=False).hexdigest()
    if object_format == "sha256":
        return hashlib.sha256(body).hexdigest()
    raise DependencyFreezeError("unsupported Git object format for release freeze")


def _git_metadata_kind(repo: pathlib.Path) -> str | None:
    git_dir = repo / ".git"
    try:
        info = git_dir.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise DependencyFreezeError("Unable to inspect Git metadata.") from exc
    if _is_reparse_stat(info):
        raise DependencyFreezeError(
            "Git metadata uses a symlink, junction, or reparse point."
        )
    if stat.S_ISDIR(info.st_mode):
        return "dir"
    if stat.S_ISREG(info.st_mode):
        return "file"
    raise DependencyFreezeError(
        "Git metadata must be a regular directory or gitfile."
    )


def _run_git(
    repo: pathlib.Path,
    *args: str,
    check: bool = True,
    custody: _GitExecutableCustody | None = None,
    repository_custody: _GitRepositoryCustody | None = None,
) -> bytes:
    owned_custody = custody is None
    if custody is None:
        custody = _open_reviewed_git_executable()
    owned_repository_custody = repository_custody is None
    try:
        if repository_custody is None:
            repository_custody = _open_git_repository_custody(
                repo, _allowed_owners(repo)
            )
    except Exception:
        if owned_custody:
            os.close(custody.descriptor)
        raise
    try:
        _rebind_reviewed_git_executable(custody)
        _rebind_git_repository_custody(repository_custody)
        if threading.active_count() != 1:
            raise DependencyFreezeError(
                "descriptor-bound Git execution requires a single-threaded process"
            )

        def _child_enter_retained_repo() -> None:
            os.fchdir(repository_custody.repo_descriptor)

        try:
            completed = subprocess.run(
                [str(custody.path), "--no-replace-objects", *args],
                executable=str(custody.path),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_git_env(),
                check=False,
                close_fds=True,
                pass_fds=(repository_custody.repo_descriptor,),
                preexec_fn=_child_enter_retained_repo,
                timeout=_GIT_TIMEOUT_SEC,
            )
        except FileNotFoundError as suc:
            raise DependencyFreezeError(GIT_REQUIRED) from suc
        except subprocess.TimeoutExpired as suc:
            raise DependencyFreezeError(
                "Git command timed out during release freeze"
            ) from suc
        finally:
            _rebind_reviewed_git_executable(custody)
            _rebind_git_repository_custody(repository_custody)
    finally:
        if owned_repository_custody:
            _close_git_repository_custody(repository_custody)
        if owned_custody:
            os.close(custody.descriptor)
    if check and completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise DependencyFreezeError(
            f"Git command failed during release freeze: {detail or 'no diagnostic'}"
        )
    return completed.stdout


def _parse_ls_tree_z(payload: bytes) -> dict[str, tuple[str, str, str]]:
    blobs: dict[str, tuple[str, str, str]] = {}
    for raw in payload.split(b"\0"):
        if not raw:
            continue
        meta, sep, path_bytes = raw.partition(b"\t")
        if not sep:
            raise DependencyFreezeError("Git ls-tree output is invalid.")
        parts = meta.split(b" ")
        if len(parts) != 3:
            raise DependencyFreezeError("Git ls-tree output is invalid.")
        try:
            mode = parts[0].decode("ascii")
            kind = parts[1].decode("ascii")
            oid = parts[2].decode("ascii")
        except UnicodeDecodeError as suc:
            raise DependencyFreezeError("Git ls-tree output is invalid.") from suc
        if not re.fullmatch(r"[0-7]{6}", mode) or not re.fullmatch(
            r"[0-9a-f]{40,64}", oid
        ):
            raise DependencyFreezeError("Git ls-tree output is invalid.")
        path = path_bytes.decode("utf-8", "surrogateescape")
        if "\\" in path:
            raise DependencyFreezeError("Git ls-tree path is not canonical.")
        if not path or path.startswith("/") or ".." in pathlib.PurePosixPath(path).parts:
            raise DependencyFreezeError("Git ls-tree path escapes the repository.")
        if path in blobs:
            raise DependencyFreezeError("Git ls-tree output has a duplicate path.")
        blobs[path] = (mode, kind, oid)
    return blobs


def _parse_ls_files_stage_z(payload: bytes) -> dict[str, tuple[str, str, str]]:
    entries: dict[str, tuple[str, str, str]] = {}
    for raw in payload.split(b"\0"):
        if not raw:
            continue
        meta, sep, path_bytes = raw.partition(b"\t")
        parts = meta.split(b" ")
        if not sep or len(parts) != 3 or parts[2] != b"0":
            raise DependencyFreezeError("Git index output is invalid.")
        try:
            mode = parts[0].decode("ascii")
            oid = parts[1].decode("ascii")
        except UnicodeDecodeError as suc:
            raise DependencyFreezeError("Git index output is invalid.") from suc
        if not re.fullmatch(r"[0-7]{6}", mode) or not re.fullmatch(
            r"[0-9a-f]{40,64}", oid
        ):
            raise DependencyFreezeError("Git index output is invalid.")
        path = path_bytes.decode("utf-8", "surrogateescape")
        if "\\" in path:
            raise DependencyFreezeError("Git index path is not canonical.")
        if (
            not path
            or path.startswith("/")
            or ".." in pathlib.PurePosixPath(path).parts
            or path in entries
        ):
            raise DependencyFreezeError("Git index path is invalid.")
        entries[path] = (mode, "blob", oid)
    return entries


def _parse_ls_files_verbose_z(payload: bytes) -> dict[str, str]:
    entries: dict[str, str] = {}
    for raw in payload.split(b"\0"):
        if not raw:
            continue
        if len(raw) < 3 or raw[1:2] != b" ":
            raise DependencyFreezeError("Git index flags output is invalid.")
        try:
            flag = raw[:1].decode("ascii")
        except UnicodeDecodeError as suc:
            raise DependencyFreezeError("Git index flags output is invalid.") from suc
        path = raw[2:].decode("utf-8", "surrogateescape")
        if "\\" in path:
            raise DependencyFreezeError("Git index flags path is not canonical.")
        if (
            not flag.isalpha()
            or not path
            or path.startswith("/")
            or ".." in pathlib.PurePosixPath(path).parts
            or path in entries
        ):
            raise DependencyFreezeError("Git index flags output is invalid.")
        entries[path] = flag
    return entries


def _parse_porcelain_z(payload: bytes) -> tuple[tuple[str, str], ...]:
    entries: list[tuple[str, str]] = []
    index = 0
    while index < len(payload):
        if payload[index : index + 1] == b"\0":
            index += 1
            continue
        if index + 3 > len(payload) or payload[index + 2 : index + 3] != b" ":
            raise DependencyFreezeError("Git status output is invalid.")
        try:
            xy = payload[index : index + 2].decode("ascii")
        except UnicodeDecodeError as suc:
            raise DependencyFreezeError("Git status output is invalid.") from suc
        index += 3
        nul = payload.find(b"\0", index)
        if nul < 0:
            raise DependencyFreezeError("Git status output is invalid.")
        path = payload[index:nul].decode("utf-8", "surrogateescape")
        if "\\" in path:
            raise DependencyFreezeError("Git status path is not canonical.")
        index = nul + 1
        if "R" in xy or "C" in xy:
            nul = payload.find(b"\0", index)
            if nul < 0:
                raise DependencyFreezeError("Git status output is invalid.")
            dest = payload[index:nul].decode("utf-8", "surrogateescape")
            if "\\" in dest:
                raise DependencyFreezeError("Git status path is not canonical.")
            index = nul + 1
            entries.append((xy, path))
            entries.append((xy, dest))
            continue
        entries.append((xy, path))
    return tuple(entries)


def _load_git_tree_state(
    repo: pathlib.Path,
    repository_custody: _GitRepositoryCustody | None = None,
) -> _GitTreeState:
    owned_repository_custody = repository_custody is None
    if repository_custody is None:
        repository_custody = _open_git_repository_custody(
            repo, _allowed_owners(repo)
        )
    try:
        custody = _open_reviewed_git_executable()
    except Exception:
        if owned_repository_custody:
            _close_git_repository_custody(repository_custody)
        raise
    try:
        prefix = _run_git(
            repo,
            "rev-parse",
            "--show-prefix",
            custody=custody,
            repository_custody=repository_custody,
        ).decode("utf-8").strip()
        inside = _run_git(
            repo,
            "rev-parse",
            "--is-inside-work-tree",
            custody=custody,
            repository_custody=repository_custody,
        ).decode("ascii").strip()
        if prefix or inside != "true":
            raise DependencyFreezeError(
                "production freeze must run from the retained Git worktree root"
            )
        head = _run_git(
            repo,
            "rev-parse",
            "--verify",
            "HEAD",
            custody=custody,
            repository_custody=repository_custody,
        ).decode("ascii").strip()
        tree = _run_git(
            repo,
            "rev-parse",
            "--verify",
            "HEAD^{tree}",
            custody=custody,
            repository_custody=repository_custody,
        ).decode("ascii").strip()
        if not re.fullmatch(r"[0-9a-f]{40,64}", head) or not re.fullmatch(
            r"[0-9a-f]{40,64}", tree
        ):
            raise DependencyFreezeError("Git HEAD or tree identity is invalid.")
        fmt_out = _run_git(
            repo,
            "rev-parse",
            "--show-object-format",
            check=False,
            custody=custody,
            repository_custody=repository_custody,
        ).decode("ascii", errors="replace").strip()
        object_format = fmt_out if fmt_out in {"sha1", "sha256"} else "sha1"
        blobs = _parse_ls_tree_z(
            _run_git(
                repo,
                "ls-tree",
                "-r",
                "--full-tree",
                "-z",
                "HEAD",
                custody=custody,
                repository_custody=repository_custody,
            )
        )
        index = _parse_ls_files_stage_z(
            _run_git(
                repo,
                "ls-files",
                "--stage",
                "-z",
                custody=custody,
                repository_custody=repository_custody,
            )
        )
        flags = _parse_ls_files_verbose_z(
            _run_git(
                repo,
                "ls-files",
                "-v",
                "-z",
                custody=custody,
                repository_custody=repository_custody,
            )
        )
        porcelain = _parse_porcelain_z(
            _run_git(
                repo,
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                custody=custody,
                repository_custody=repository_custody,
            )
        )
        _rebind_reviewed_git_executable(custody)
        return _GitTreeState(
            object_format=object_format,
            git_executable_sha256=custody.sha256,
            head=head,
            tree=tree,
            blobs=blobs,
            index=index,
            flags=flags,
            porcelain=porcelain,
        )
    finally:
        os.close(custody.descriptor)
        if owned_repository_custody:
            _close_git_repository_custody(repository_custody)


def _bind_production_git_tree(
    repo: pathlib.Path,
    repository_custody: _GitRepositoryCustody | None = None,
) -> _GitTreeState | None:
    if isolated_fixture_mode_active():
        return None
    kind = _git_metadata_kind(repo)
    if kind is None:
        if _PRODUCTION_REQUIRED:
            raise DependencyFreezeError(GIT_REQUIRED)
        return None
    return _load_git_tree_state(repo, repository_custody)


def _porcelain_by_path(tree: _GitTreeState) -> dict[str, str]:
    latest: dict[str, str] = {}
    for xy, path in tree.porcelain:
        latest[path] = xy
    return latest


def _path_in_roots(relative: str, roots: Iterable[str]) -> bool:
    posix = relative.replace("\\", "/")
    for root in roots:
        root_posix = root.replace("\\", "/").rstrip("/")
        if posix == root_posix or posix.startswith(root_posix + "/"):
            return True
    return False


def _excluded_from_git_denominator(relative: str) -> bool:
    return _is_excluded(pathlib.PurePosixPath(relative))


def _require_production_git_inputs(
    tree: _GitTreeState | None,
    selected: Iterable[str],
    payloads: dict[str, bytes],
    aliases: tuple[tuple[str, str], ...],
    roots: Iterable[str],
    identities: Iterable[tuple[str, tuple[int, ...]]],
) -> None:
    if tree is None:
        return
    selected_paths = tuple(selected)
    root_list = tuple(roots)
    identity_by_path = dict(identities)
    porcelain = _porcelain_by_path(tree)
    explained: set[str] = set()
    for relative in selected_paths:
        record = tree.blobs.get(relative)
        index_record = tree.index.get(relative)
        xy = porcelain.get(relative, "")
        flag = tree.flags.get(relative, "")
        in_head = record is not None
        if not in_head:
            explained.add(relative)
            if xy == "??" or xy == "":
                raise DependencyFreezeError(f"{GIT_UNTRACKED_INPUT}: {relative}")
            if xy[:1] == "A":
                raise DependencyFreezeError(f"{GIT_STAGED_ONLY_INPUT}: {relative}")
            raise DependencyFreezeError(f"{GIT_UNTRACKED_INPUT}: {relative}")
        mode, kind, oid = record
        if index_record != record or flag != "H":
            raise DependencyFreezeError(f"{GIT_INDEX_WORKTREE_SPLIT}: {relative}")
        if mode == "120000" or kind == "commit":
            raise DependencyFreezeError(f"{GIT_SYMLINK_INPUT}: {relative}")
        if mode not in {"100644", "100755"} or kind != "blob":
            raise DependencyFreezeError(
                f"release input is not a regular tracked Git blob: {relative}"
            )
        payload = payloads.get(relative)
        if payload is not None:
            actual = _git_blob_oid(payload, tree.object_format)
            if actual != oid:
                raise DependencyFreezeError(
                    f"release input does not match the exact tracked Git tree: {relative}"
                )
        identity = identity_by_path.get(relative)
        if identity is None:
            raise DependencyFreezeError(f"{GIT_OMITTED_INPUT}: {relative}")
        executable = bool(
            int(identity[2]) & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        )
        if executable != (mode == "100755"):
            raise DependencyFreezeError(f"{GIT_METADATA_DRIFT}: {relative}")
        if xy and (xy[0] in "MTDARC" or xy[1] in "MTD"):
            raise DependencyFreezeError(
                f"release input does not match the exact tracked Git tree: {relative}"
            )
        explained.add(relative)
    for alias, target in aliases:
        explained.add(alias)
        record = tree.blobs.get(alias)
        if record is None:
            xy = porcelain.get(alias, "")
            if xy[:1] == "A":
                raise DependencyFreezeError(f"{GIT_STAGED_ONLY_INPUT}: {alias}")
            raise DependencyFreezeError(f"{GIT_UNTRACKED_INPUT}: {alias}")
        mode, kind, oid = record
        if mode != "120000" or kind != "blob":
            raise DependencyFreezeError(f"{GIT_SYMLINK_INPUT}: {alias}")
        if tree.index.get(alias) != record or tree.flags.get(alias, "") != "H":
            raise DependencyFreezeError(f"{GIT_INDEX_WORKTREE_SPLIT}: {alias}")
        expected = _git_blob_oid(target.encode("utf-8"), tree.object_format)
        if oid != expected:
            raise DependencyFreezeError(
                f"release input does not match the exact tracked Git tree: {alias}"
            )
        resolved = _normalized_symlink_target(alias, target)
        target_record = tree.blobs.get(resolved)
        if (
            target_record is None
            or target_record[0] not in {"100644", "100755"}
            or target_record[1] != "blob"
        ):
            raise DependencyFreezeError(
                f"symlink alias target is not in the exact tracked Git tree: {alias}"
            )
    alias_paths = {alias for alias, _target in aliases}
    for relative, record in tree.blobs.items():
        if relative in explained or relative in alias_paths:
            continue
        if not _path_in_roots(relative, root_list):
            continue
        if _excluded_from_git_denominator(relative):
            continue
        if record[0] == "120000":
            raise DependencyFreezeError(f"{GIT_SYMLINK_INPUT}: {relative}")
        raise DependencyFreezeError(f"{GIT_OMITTED_INPUT}: {relative}")
    for relative, flag in tree.flags.items():
        if flag != "H":
            raise DependencyFreezeError(f"{GIT_INDEX_WORKTREE_SPLIT}: {relative}")
    # tree.porcelain holds (xy, path) pairs: report the dirty path, not its status code.
    leftover = [path for _xy, path in tree.porcelain if path not in explained]
    if leftover:
        raise DependencyFreezeError(f"{GIT_DIRTY_SOURCE}: {leftover[0]}")


def _is_reparse_stat(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & REPARSE_POINT_ATTRIBUTE
    )


def _is_reparse_point(path: pathlib.Path) -> bool:
    try:
        info = path.lstat()
    except OSError as exc:
        raise DependencyFreezeError(f"Unable to inspect path {path}: {exc}") from exc
    return _is_reparse_stat(info)


def _nofollow_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow == 0:
        raise DependencyFreezeError("dependency freeze requires O_NOFOLLOW")
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0) | nofollow


def _directory_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", 0)
    if directory == 0:
        raise DependencyFreezeError("dependency freeze requires O_DIRECTORY")
    return _nofollow_flags() | directory


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _fold_key(value: str) -> str:
    try:
        normalized = unicodedata.normalize("NFKC", value)
    except Exception as suc:
        raise DependencyFreezeError("dependency path is not a valid Unicode name") from suc
    return normalized.casefold()


def _is_special_node(info: os.stat_result) -> bool:
    mode = info.st_mode
    return bool(
        stat.S_ISFIFO(mode)
        or stat.S_ISCHR(mode)
        or stat.S_ISBLK(mode)
        or stat.S_ISSOCK(mode)
    )


def _allocated_bytes(info: os.stat_result) -> int:
    return int(getattr(info, "st_blocks", 0)) * 512


def _reject_oversized_file(relative: str, info: os.stat_result) -> None:
    if info.st_size < 0 or info.st_size > MAX_DEPENDENCY_FILE_BYTES:
        raise DependencyFreezeError(
            f"dependency input size is outside the accepted bound: {relative}"
        )
    allocated = _allocated_bytes(info)
    if allocated < 0 or allocated > MAX_DEPENDENCY_FILE_BYTES:
        raise DependencyFreezeError(
            f"dependency allocated size is outside the accepted bound: {relative}"
        )


def _require_executing_controller(
    repo: pathlib.Path,
    reviewed_payload: bytes | None = None,
) -> bytes:
    expected = repo / "tools/release_dependency_freeze.py"
    executing_source = (
        _AUTHORITATIVE_CONTROLLER_PATH
        if _AUTHORITATIVE_WORKER_READY
        else _EXECUTING_SOURCE_PATH
    )
    if (
        executing_source != expected
        or (
            not _AUTHORITATIVE_WORKER_READY
            and _EXECUTING_CODE_PATH != _EXECUTING_SOURCE_PATH
        )
    ):
        raise DependencyFreezeError(
            "executing release dependency controller is not the reviewed repository controller"
        )
    owners = _allowed_owners(repo)
    payload, _identity, _info = _stable_read_regular_file(
        expected,
        owners,
        label="Release dependency controller",
        repo=None if isolated_fixture_mode_active() else repo,
    )
    if reviewed_payload is not None and payload != reviewed_payload:
        raise DependencyFreezeError(
            "executing release dependency controller differs from hashed controller bytes"
        )
    try:
        reviewed_code = compile(
            payload,
            _EXECUTING_MODULE_CODE.co_filename,
            "exec",
            dont_inherit=True,
            optimize=sys.flags.optimize,
        )
    except (SyntaxError, ValueError, TypeError) as suc:
        raise DependencyFreezeError(
            "reviewed release dependency controller source is invalid"
        ) from suc
    if reviewed_code != _EXECUTING_MODULE_CODE:
        raise DependencyFreezeError(
            "executing release dependency controller code differs from reviewed source bytes"
        )
    return payload


def _require_reviewed_source_freeze_bytes(
    path: pathlib.Path,
    payload: bytes,
    identity: tuple[int, ...],
) -> _GitTreeState:
    repo = path.parents[1]
    relative = "tools/release_source_freeze.py"
    if path != repo / relative:
        raise DependencyFreezeError(
            "release source-freeze controller is outside the reviewed repository path"
        )
    _require_executing_controller(repo)
    tree = _bind_production_git_tree(repo)
    if tree is None:
        raise DependencyFreezeError(GIT_REQUIRED)
    _require_production_git_inputs(
        tree,
        (relative,),
        {relative: payload},
        (),
        (relative,),
        ((relative, identity),),
    )
    return tree


def _source_freeze_module():
    global _SOURCE_FREEZE_MODULE
    controller_path = (
        _AUTHORITATIVE_CONTROLLER_PATH
        if _AUTHORITATIVE_WORKER_READY
        else _EXECUTING_SOURCE_PATH
    )
    if controller_path is None:
        raise DependencyFreezeError(
            "executing release dependency controller is not authenticated"
        )
    path = controller_path.with_name("release_source_freeze.py")
    owners = _allowed_owners(path.parent)
    try:
        payload, identity, _info = _stable_read_regular_file(
            path,
            owners,
            label="Release source-freeze controller",
        )
        code = compile(
            payload,
            str(path),
            "exec",
            dont_inherit=True,
            optimize=sys.flags.optimize,
        )
    except (DependencyFreezeError, SyntaxError, ValueError, TypeError) as suc:
        raise DependencyFreezeError(
            "current externally authenticated source-freeze issuance identity is unavailable"
        ) from suc
    first_git = None
    if not isolated_fixture_mode_active():
        first_git = _require_reviewed_source_freeze_bytes(path, payload, identity)
    digest = hashlib.sha256(payload).hexdigest()
    module_name = f"_wins_release_source_freeze_{digest}_{id(code):x}"
    if module_name in sys.modules:
        raise DependencyFreezeError("isolated source-freeze namespace is poisoned")
    module = types.ModuleType(module_name)
    module.__file__ = str(path)
    module.__package__ = ""
    module.__loader__ = None
    module.__spec__ = None
    module.__cached__ = None
    sys.modules[module_name] = module
    poisoned = False
    try:
        exec(code, module.__dict__)
        poisoned = sys.modules.get(module_name) is not module
    except BaseException as suc:
        raise DependencyFreezeError(
            "current externally authenticated source-freeze issuance identity is unavailable"
        ) from suc
    finally:
        if sys.modules.get(module_name) is module:
            del sys.modules[module_name]
    if poisoned:
        raise DependencyFreezeError("isolated source-freeze namespace is poisoned")
    rebound, rebound_identity, _rebound_info = _stable_read_regular_file(
        path,
        owners,
        label="Release source-freeze controller",
    )
    if rebound != payload or rebound_identity != identity:
        raise DependencyFreezeError(
            "release source-freeze controller changed during isolated loading"
        )
    if not isolated_fixture_mode_active():
        second_git = _require_reviewed_source_freeze_bytes(
            path, rebound, rebound_identity
        )
        if first_git != second_git:
            raise DependencyFreezeError(GIT_DIRTY_SOURCE)
    if isolated_fixture_mode_active():
        trust_override = _SOURCE_FREEZE_TRUST_PATH
        if trust_override is not None:
            override_path = pathlib.Path(trust_override)
            if not override_path.is_absolute():
                raise DependencyFreezeError("fixture source-freeze trust path is invalid")
            module._EXTERNAL_TRUST_PATH = str(override_path)
        self_authored = _SOURCE_FREEZE_SELF_AUTHORED_OVERRIDE
        if self_authored is not None:
            if type(self_authored) is not bool:
                raise DependencyFreezeError("fixture source-freeze override is invalid")
            module._issuance_is_self_authored = lambda *_args: self_authored
    _SOURCE_FREEZE_MODULE = module
    return module


def _raise_source_freeze(exc: BaseException) -> None:
    raise DependencyFreezeError(str(exc)) from exc


def _join_relative(parent: str, name: str) -> str:
    return f"{parent}/{name}" if parent else name


def _parent_relative(relative: str) -> str:
    if not relative or "/" not in relative:
        return ""
    return relative.rsplit("/", 1)[0]


def _split_relative(relative: str) -> tuple[str, ...]:
    posix = relative.replace("\\", "/")
    if posix.startswith("/") or posix in {"", "."}:
        raise DependencyFreezeError(f"dependency path escapes the repository: {relative}")
    parts = pathlib.PurePosixPath(posix).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise DependencyFreezeError(f"dependency path escapes the repository: {relative}")
    for part in parts:
        _fold_key(part)
    return parts


def _split_link_components(relative: str, alias: str) -> tuple[str, ...]:
    posix = relative.replace("\\", "/")
    if posix.startswith("/") or posix in {"", "."}:
        raise DependencyFreezeError(
            f"Native-messaging host symlink alias target escapes the repository: {alias}"
        )
    parts = pathlib.PurePosixPath(posix).parts
    if not parts or any(part == "" for part in parts):
        raise DependencyFreezeError(
            f"Native-messaging host symlink alias target escapes the repository: {alias}"
        )
    return parts


def _is_group_or_world_writable(info: os.stat_result) -> bool:
    return bool(info.st_mode & _WRITABLE_MASK)


def _require_owned_mode(
    relative: str,
    info: os.stat_result,
    allowed_owners: frozenset[int],
    *,
    kind: str,
) -> None:
    if info.st_uid not in allowed_owners:
        raise DependencyFreezeError(
            f"{kind} is not owned by the current user or repository owner: {relative}"
        )
    if _is_group_or_world_writable(info):
        raise DependencyFreezeError(f"group/world-writable {kind}: {relative}")


def _allowed_owners(repo: pathlib.Path) -> frozenset[int]:
    owners: set[int] = set()
    getuid = getattr(os, "getuid", None)
    if getuid is not None:
        owners.add(int(getuid()))
    try:
        owners.add(int(os.lstat(repo).st_uid))
    except OSError as exc:
        raise DependencyFreezeError("Repository root could not be inspected.") from exc
    if not owners:
        raise DependencyFreezeError("dependency freeze requires an owner identity")
    return frozenset(owners)


def _fallback_owners(path: pathlib.Path) -> frozenset[int]:
    getuid = getattr(os, "getuid", None)
    if getuid is not None:
        return frozenset({int(getuid())})
    try:
        return frozenset({int(os.lstat(path).st_uid)})
    except OSError as exc:
        raise DependencyFreezeError(
            f"Unable to inspect dependency file owner {path}: {exc}"
        ) from exc


def _close_quietly(descriptor: int | None) -> None:
    if descriptor is None:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def _assert_regular_or_directory(info: os.stat_result, relative: str) -> None:
    if _is_reparse_stat(info):
        raise DependencyFreezeError(
            "Symlink, junction, or reparse point is forbidden in release inputs: "
            f"{relative}"
        )
    if stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode):
        return
    raise DependencyFreezeError(
        f"dependency path must be a regular file or directory: {relative}"
    )


def _rebind_path_by_name(
    path: pathlib.Path,
    expected: tuple[int, ...],
    *,
    kind: str,
    directory: bool,
) -> os.stat_result:
    flags = _directory_flags() if directory else _nofollow_flags()
    try:
        path_now = os.lstat(path)
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise DependencyFreezeError(
            f"{kind} path was replaced while a bound descriptor remained readable"
        ) from exc
    try:
        opened = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        _is_reparse_stat(path_now)
        or _file_identity(path_now) != expected
        or _file_identity(opened) != expected
        or (path_now.st_dev, path_now.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        raise DependencyFreezeError(
            f"{kind} path was replaced while a bound descriptor remained readable"
        )
    return opened


def _rebind_requested_path(
    path: pathlib.Path,
    bound_fd: int,
    bound_info: os.stat_result,
    *,
    kind: str,
    directory: bool,
) -> os.stat_result:
    """Reject pathname replacement of a bound descriptor before return."""

    replaced = f"{kind} path was replaced while a bound descriptor remained readable"
    try:
        rebound = os.fstat(bound_fd)
        path_now = os.lstat(path)
        flags = _directory_flags() if directory else _nofollow_flags()
        descriptor = os.open(path, flags)
    except OSError as suc:
        raise DependencyFreezeError(replaced) from suc
    try:
        opened = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    expected_dir = stat.S_ISDIR(rebound.st_mode)
    if (
        _is_reparse_stat(path_now)
        or (directory and not expected_dir)
        or (not directory and not stat.S_ISREG(opened.st_mode))
        or (path_now.st_dev, path_now.st_ino) != (rebound.st_dev, rebound.st_ino)
        or (opened.st_dev, opened.st_ino) != (rebound.st_dev, rebound.st_ino)
    ):
        raise DependencyFreezeError(replaced)
    if _file_identity(rebound) != _file_identity(bound_info):
        raise DependencyFreezeError(
            f"{kind} identity changed while a bound descriptor remained readable"
        )
    if (
        _file_identity(opened) != _file_identity(rebound)
        or _file_identity(path_now) != _file_identity(rebound)
    ):
        raise DependencyFreezeError(replaced)
    return rebound


def _rebind_relative_path(
    repo_fd: int,
    relative: str,
    expected: tuple[int, ...],
    allowed_owners: frozenset[int],
    *,
    directory: bool = False,
) -> os.stat_result:
    """Re-open the requested relative path through bound descriptors."""

    parts = _split_relative(relative)
    current = repo_fd
    owned: list[int] = []
    rel = ""
    try:
        for part in parts[:-1]:
            rel = _join_relative(rel, part)
            nxt, _info = _bind_directory_fd(current, part, rel, allowed_owners)
            owned.append(nxt)
            current = nxt
        leaf = parts[-1]
        flags = _directory_flags() if directory else _nofollow_flags()
        path_now = _lstat_at(current, leaf, relative)
        _assert_regular_or_directory(path_now, relative)
        if directory and not stat.S_ISDIR(path_now.st_mode):
            raise DependencyFreezeError(f"Required input root is missing: {relative}")
        if not directory and not stat.S_ISREG(path_now.st_mode):
            raise DependencyFreezeError(
                f"dependency path must be a regular file or directory: {relative}"
            )
        descriptor = _open_at(
            current, leaf, flags, relative, "dependency input"
        )
        try:
            opened = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if (
            _file_identity(path_now) != expected
            or _file_identity(opened) != expected
        ):
            raise DependencyFreezeError(
                "dependency input path was replaced while a bound descriptor "
                f"remained readable: {relative}"
            )
        return opened
    finally:
        for descriptor in reversed(owned):
            _close_quietly(descriptor)


def _open_repo_dir(
    repo: pathlib.Path,
    allowed_owners: frozenset[int],
) -> tuple[int, os.stat_result]:
    flags = _directory_flags()
    try:
        path_before = os.lstat(repo)
        descriptor = os.open(repo, flags)
    except OSError as exc:
        raise DependencyFreezeError(
            "Unable to read dependency input: repository root could not be inspected"
        ) from exc
    try:
        opened = os.fstat(descriptor)
    except OSError as suc:
        os.close(descriptor)
        raise DependencyFreezeError(
            "Unable to read dependency input: repository root could not be inspected"
        ) from suc
    if (
        _is_reparse_stat(path_before)
        or not stat.S_ISDIR(opened.st_mode)
        or (path_before.st_dev, path_before.st_ino) != (opened.st_dev, opened.st_ino)
        or _file_identity(path_before) != _file_identity(opened)
    ):
        os.close(descriptor)
        raise DependencyFreezeError("Repository root is missing or uses a reparse point.")
    try:
        _require_owned_mode(".", opened, allowed_owners, kind="dependency directory")
        hook = _POST_DIRECTORY_BIND_HOOK
        if callable(hook):
            hook(".")
        rebound = _rebind_requested_path(
            repo,
            descriptor,
            opened,
            kind="Repository root",
            directory=True,
        )
        _require_owned_mode(".", rebound, allowed_owners, kind="dependency directory")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, rebound


def _lstat_at(parent_fd: int, name: str, relative: str) -> os.stat_result:
    try:
        return os.lstat(name, dir_fd=parent_fd)
    except OSError as exc:
        raise DependencyFreezeError(
            f"Unable to inspect release input: {relative}"
        ) from exc


def _open_at(parent_fd: int, name: str, flags: int, relative: str, label: str) -> int:
    try:
        return os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        path_info = None
        try:
            path_info = os.lstat(name, dir_fd=parent_fd)
        except OSError:
            path_info = None
        if path_info is not None and _is_reparse_stat(path_info):
            raise DependencyFreezeError(
                "Symlink, junction, or reparse point is forbidden in release inputs: "
                f"{relative}"
            ) from exc
        raise DependencyFreezeError(
            f"Unable to read {label} {relative}: {exc}"
        ) from exc


def _bind_directory_fd(
    parent_fd: int,
    name: str,
    relative: str,
    allowed_owners: frozenset[int],
) -> tuple[int, os.stat_result]:
    _reject_casefold_lookup(parent_fd, _parent_relative(relative), name)
    path_before = _lstat_at(parent_fd, name, relative)
    if _is_reparse_stat(path_before):
        raise DependencyFreezeError(
            "Symlink, junction, or reparse point is forbidden in release inputs: "
            f"{relative}"
        )
    if not stat.S_ISDIR(path_before.st_mode):
        _assert_regular_or_directory(path_before, relative)
        raise DependencyFreezeError(f"Required input root is missing: {relative}")
    descriptor = _open_at(
        parent_fd, name, _directory_flags(), relative, "dependency input"
    )
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (path_before.st_dev, path_before.st_ino)
            != (opened.st_dev, opened.st_ino)
            or _file_identity(path_before) != _file_identity(opened)
        ):
            raise DependencyFreezeError(
                f"dependency directory identity changed while traversing: {relative}"
            )
        _require_owned_mode(relative, opened, allowed_owners, kind="dependency directory")
        hook = _POST_DIRECTORY_BIND_HOOK
        if callable(hook):
            hook(relative)
        path_after = _lstat_at(parent_fd, name, relative)
        rebound = os.fstat(descriptor)
        if _is_reparse_stat(path_after):
            raise DependencyFreezeError(
                "Symlink, junction, or reparse point is forbidden in release inputs: "
                f"{relative}"
            )
        if (
            _file_identity(opened) != _file_identity(rebound)
            or (path_after.st_dev, path_after.st_ino)
            != (opened.st_dev, opened.st_ino)
            or _file_identity(path_after) != _file_identity(rebound)
        ):
            raise DependencyFreezeError(
                f"dependency directory identity changed while traversing: {relative}"
            )
        _require_owned_mode(relative, rebound, allowed_owners, kind="dependency directory")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, rebound


def _walk_open_dir(
    repo_fd: int,
    relative: str,
    allowed_owners: frozenset[int],
) -> tuple[int, os.stat_result]:
    current = repo_fd
    owned: list[int] = []
    info: os.stat_result | None = None
    rel = ""
    try:
        for part in _split_relative(relative):
            rel = _join_relative(rel, part)
            nxt, info = _bind_directory_fd(current, part, rel, allowed_owners)
            owned.append(nxt)
            current = nxt
        if info is None:
            raise DependencyFreezeError(f"Unable to inspect release input: {relative}")
        owned.pop()
        return current, info
    finally:
        for descriptor in reversed(owned):
            _close_quietly(descriptor)


def _list_directory_names(dir_fd: int, relative: str) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    folded: dict[str, str] = {}
    try:
        iterator = os.scandir(dir_fd)
    except OSError as exc:
        raise DependencyFreezeError(
            f"Unable to inspect release input: {relative or '.'}"
        ) from exc
    with iterator:
        for entry in iterator:
            name = entry.name
            if name in {".", ".."}:
                continue
            if "\x00" in name or "/" in name or "\\" in name:
                raise DependencyFreezeError(
                    f"dependency directory has an unsafe entry name: {_join_relative(relative, name)}"
                )
            if name in seen:
                raise DependencyFreezeError(
                    f"dependency directory has a duplicate entry: {_join_relative(relative, name)}"
                )
            seen.add(name)
            key = _fold_key(name)
            previous = folded.get(key)
            if previous is not None and previous != name:
                left = _join_relative(relative, previous)
                right = _join_relative(relative, name)
                raise DependencyFreezeError(
                    "Case-colliding release input paths are forbidden: "
                    f"{left} and {right}"
                )
            folded[key] = name
            names.append(name)
    return names


def _reject_casefold_lookup(parent_fd: int, parent_rel: str, name: str) -> None:
    names = _list_directory_names(parent_fd, parent_rel)
    folded = _fold_key(name)
    for existing in names:
        if _fold_key(existing) == folded and existing != name:
            left = _join_relative(parent_rel, existing)
            right = _join_relative(parent_rel, name)
            raise DependencyFreezeError(
                "Case-colliding release input paths are forbidden: "
                f"{left} and {right}"
            )


def _reject_configured_path_components(
    repo_fd: int,
    paths: Iterable[str],
    allowed_owners: frozenset[int],
) -> None:
    """Enumerate every fixed path component from the repository root."""

    for relative in paths:
        parts = _split_relative(relative)
        current = repo_fd
        owned: list[int] = []
        rel = ""
        try:
            for index, part in enumerate(parts):
                _reject_casefold_lookup(current, rel, part)
                if index == len(parts) - 1:
                    break
                child_rel = _join_relative(rel, part)
                try:
                    info = os.lstat(part, dir_fd=current)
                except FileNotFoundError:
                    break
                except OSError as suc:
                    raise DependencyFreezeError(
                        f"Unable to inspect release input: {child_rel}"
                    ) from suc
                _assert_regular_or_directory(info, child_rel)
                if not stat.S_ISDIR(info.st_mode):
                    break
                nxt, _info = _bind_directory_fd(
                    current, part, child_rel, allowed_owners
                )
                owned.append(nxt)
                current = nxt
                rel = child_rel
        finally:
            for descriptor in reversed(owned):
                _close_quietly(descriptor)


def _stable_read_regular_file_at(
    parent_fd: int,
    name: str,
    relative: str,
    allowed_owners: frozenset[int],
    *,
    max_bytes: int = MAX_DEPENDENCY_FILE_BYTES,
    label: str = "dependency input",
) -> tuple[bytes, tuple[int, ...], os.stat_result]:
    flags = _nofollow_flags()
    _reject_casefold_lookup(parent_fd, _parent_relative(relative), name)
    path_before = _lstat_at(parent_fd, name, relative)
    if _is_reparse_stat(path_before):
        raise DependencyFreezeError(
            "Symlink, junction, or reparse point is forbidden in release inputs: "
            f"{relative}"
        )
    if not stat.S_ISREG(path_before.st_mode):
        _assert_regular_or_directory(path_before, relative)
        raise DependencyFreezeError(
            f"{label} must be a regular non-symlink file: {relative}"
        )
    descriptor = _open_at(parent_fd, name, flags, relative, label)
    try:
        before = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (path_before.st_dev, path_before.st_ino):
            raise DependencyFreezeError(
                f"{label} identity changed while opening: {relative}"
            )
        if _is_reparse_stat(path_before) or not stat.S_ISREG(before.st_mode):
            raise DependencyFreezeError(
                f"{label} must be a regular non-symlink file: {relative}"
            )
        if before.st_nlink != 1:
            raise DependencyFreezeError(f"{label} must have link count 1: {relative}")
        _require_owned_mode(relative, before, allowed_owners, kind="dependency file")
        if before.st_size < 0 or before.st_size > max_bytes:
            raise DependencyFreezeError(
                f"{label} size is outside the accepted bound: {relative}"
            )
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                raise DependencyFreezeError(
                    f"{label} ended before its declared size: {relative}"
                )
            remaining -= len(block)
            chunks.append(block)
        extra = os.read(descriptor, 1)
        if extra:
            raise DependencyFreezeError(f"{label} grew while it was read: {relative}")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        path_after = os.lstat(name, dir_fd=parent_fd)
    except OSError as exc:
        raise DependencyFreezeError(
            f"{label} disappeared after hashing: {relative}"
        ) from exc
    if not (
        _file_identity(path_before)
        == _file_identity(before)
        == _file_identity(after)
        == _file_identity(path_after)
    ):
        raise DependencyFreezeError(f"{label} changed while it was hashed: {relative}")
    payload = b"".join(chunks)
    if len(payload) != before.st_size:
        raise DependencyFreezeError(
            f"{label} size is outside the accepted bound: {relative}"
        )
    return payload, _file_identity(before), before


def _read_relative_file(
    repo_fd: int,
    relative: str,
    allowed_owners: frozenset[int],
    *,
    max_bytes: int = MAX_DEPENDENCY_FILE_BYTES,
    label: str = "dependency input",
) -> tuple[bytes, tuple[int, ...], os.stat_result]:
    parts = _split_relative(relative)
    current = repo_fd
    owned: list[int] = []
    rel = ""
    try:
        for part in parts[:-1]:
            rel = _join_relative(rel, part)
            nxt, _info = _bind_directory_fd(current, part, rel, allowed_owners)
            owned.append(nxt)
            current = nxt
        result = _stable_read_regular_file_at(
            current,
            parts[-1],
            relative,
            allowed_owners,
            max_bytes=max_bytes,
            label=label,
        )
        _rebind_relative_path(
            repo_fd,
            relative,
            result[1],
            allowed_owners,
            directory=False,
        )
        return result
    finally:
        for descriptor in reversed(owned):
            _close_quietly(descriptor)


def _read_repo_file(
    repo: pathlib.Path,
    path: pathlib.Path,
    allowed_owners: frozenset[int],
    *,
    max_bytes: int = MAX_DEPENDENCY_FILE_BYTES,
    label: str = "dependency input",
) -> tuple[bytes, tuple[int, ...], os.stat_result]:
    try:
        relative = path.relative_to(repo).as_posix()
    except ValueError as exc:
        raise DependencyFreezeError(f"{label} must stay inside the repository.") from exc
    if relative in {"", "."}:
        raise DependencyFreezeError(f"{label} must stay inside the repository.")
    repo_fd, repo_info = _open_repo_dir(repo, allowed_owners)
    try:
        result = _read_relative_file(
            repo_fd,
            relative,
            allowed_owners,
            max_bytes=max_bytes,
            label=label,
        )
        _rebind_requested_path(
            repo,
            repo_fd,
            repo_info,
            kind="Repository root",
            directory=True,
        )
        _rebind_relative_path(
            repo_fd,
            relative,
            result[1],
            allowed_owners,
            directory=False,
        )
        return result
    finally:
        os.close(repo_fd)


def _stable_read_regular_file(
    path: pathlib.Path,
    allowed_owners: frozenset[int],
    *,
    max_bytes: int = MAX_DEPENDENCY_FILE_BYTES,
    label: str = "dependency input",
    repo: pathlib.Path | None = None,
) -> tuple[bytes, tuple[int, ...], os.stat_result]:
    if repo is not None:
        return _read_repo_file(
            repo, path, allowed_owners, max_bytes=max_bytes, label=label
        )
    parent = path.parent
    parent_fd, parent_info = _open_repo_dir(parent, allowed_owners)
    try:
        result = _stable_read_regular_file_at(
            parent_fd,
            path.name,
            path.name,
            allowed_owners,
            max_bytes=max_bytes,
            label=label,
        )
        _rebind_requested_path(
            parent,
            parent_fd,
            parent_info,
            kind="dependency directory",
            directory=True,
        )
        _rebind_path_by_name(
            path, result[1], kind=label, directory=False
        )
        return result
    finally:
        os.close(parent_fd)


@dataclasses.dataclass(frozen=True)
class _HeldPathComponent:
    parent_descriptor: int
    name: str
    relative: str
    descriptor: int
    identity: tuple[int, ...]
    directory: bool


@dataclasses.dataclass(frozen=True)
class _HeldRegularFile:
    repo: pathlib.Path
    repo_descriptor: int
    repo_identity: tuple[int, ...]
    components: tuple[_HeldPathComponent, ...]
    payload: bytes
    identity: tuple[int, ...]
    info: os.stat_result
    label: str
    mutation_guard: object | None


@dataclasses.dataclass(frozen=True)
class _HeldDirectory:
    repo: pathlib.Path
    repo_descriptor: int
    repo_identity: tuple[int, ...]
    components: tuple[_HeldPathComponent, ...]
    label: str
    mutation_guard: object | None


@dataclasses.dataclass(frozen=True)
class _HeldAnchoredPayloads:
    record: _HeldRegularFile
    anchor: _HeldRegularFile
    label: str


@dataclasses.dataclass(frozen=True)
class _AuthoritativeWorkerCustody:
    controller: _HeldRegularFile
    pins: _HeldRegularFile
    executable: _HeldRegularFile
    executable_path: pathlib.Path


_ACTIVE_ANCHORED_CUSTODY: contextvars.ContextVar[
    list[_HeldAnchoredPayloads] | None
] = contextvars.ContextVar("release_dependency_anchored_custody", default=None)
_ACTIVE_RETURN_FILE_CUSTODY: contextvars.ContextVar[
    list[_HeldRegularFile] | None
] = contextvars.ContextVar("release_dependency_return_file_custody", default=None)
_ACTIVE_RETURN_DIRECTORY_CUSTODY: contextvars.ContextVar[
    list[_HeldDirectory] | None
] = contextvars.ContextVar(
    "release_dependency_return_directory_custody", default=None
)
_ACTIVE_PUBSPEC_CUSTODY: contextvars.ContextVar[object | None] = (
    contextvars.ContextVar("release_dependency_pubspec_custody", default=None)
)
_ACTIVE_AUTHORITATIVE_WORKER_CUSTODY: contextvars.ContextVar[
    _AuthoritativeWorkerCustody | None
] = contextvars.ContextVar(
    "release_dependency_authoritative_worker_custody", default=None
)


def _rebind_retained_result_custody(
    files: Iterable[_HeldRegularFile],
    anchored: Iterable[_HeldAnchoredPayloads],
    directories: Iterable[_HeldDirectory] = (),
) -> None:
    for held_directory in directories:
        _rebind_held_directory(held_directory)
    for held_file in files:
        _rebind_held_regular_file(held_file)
    for held in anchored:
        _rebind_held_anchored_file(held.record)
        _rebind_held_anchored_file(held.anchor)
        _assert_held_common_ancestors(held.record, held.anchor, held.label)


def _close_retained_result_custody(
    files: Iterable[_HeldRegularFile],
    anchored: Iterable[_HeldAnchoredPayloads],
    directories: Iterable[_HeldDirectory] = (),
) -> None:
    for held_file in reversed(tuple(files)):
        _close_held_regular_file(held_file)
    for held in reversed(tuple(anchored)):
        _close_held_regular_file(held.anchor)
        _close_held_regular_file(held.record)
    for held_directory in reversed(tuple(directories)):
        _close_held_directory(held_directory)


# The worker holds every selected input and its ancestor chain until it
# returns, several times over in one finish-build, while PowerShell on macOS
# hands its children a soft limit of 10240. Callers that import this module
# or run it without tools/run_release_dependency_freeze.sh get the same raise.
REQUIRED_OPEN_FILES = 131072


def _ensure_open_file_soft_limit(minimum: int = REQUIRED_OPEN_FILES) -> None:
    if resource is None or not hasattr(resource, "RLIMIT_NOFILE"):
        return
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (OSError, ValueError) as exc:
        raise DependencyFreezeError(
            f"Unable to read the open-file resource limit: {exc}"
        ) from exc
    infinity = getattr(resource, "RLIM_INFINITY", -1)
    if soft == infinity or (soft >= 0 and soft >= minimum):
        return
    hard_label = "unlimited" if hard == infinity else str(hard)
    if hard != infinity and 0 <= hard < minimum:
        raise DependencyFreezeError(
            f"cannot raise the open-file soft limit to {minimum} "
            f"(soft {soft}, hard {hard_label})"
        )
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (minimum, hard))
    except (OSError, ValueError) as exc:
        raise DependencyFreezeError(
            f"cannot raise the open-file soft limit to {minimum} "
            f"(soft {soft}, hard {hard_label}): {exc}"
        ) from exc


def _retain_anchored_inputs_until_return(operation: object) -> object:
    @functools.wraps(operation)
    def retained_operation(*args: object, **kwargs: object) -> object:
        active = _ACTIVE_ANCHORED_CUSTODY.get()
        outermost = active is None
        if outermost:
            _ensure_open_file_soft_limit()
        token: contextvars.Token[list[_HeldAnchoredPayloads] | None] | None = None
        file_token: contextvars.Token[list[_HeldRegularFile] | None] | None = None
        directory_token: contextvars.Token[list[_HeldDirectory] | None] | None = None
        pubspec_token: contextvars.Token[object | None] | None = None
        files = _ACTIVE_RETURN_FILE_CUSTODY.get()
        directories = _ACTIVE_RETURN_DIRECTORY_CUSTODY.get()
        if outermost:
            active = []
            token = _ACTIVE_ANCHORED_CUSTODY.set(active)
            files = []
            file_token = _ACTIVE_RETURN_FILE_CUSTODY.set(files)
            directories = []
            directory_token = _ACTIVE_RETURN_DIRECTORY_CUSTODY.set(directories)
        try:
            if outermost:
                if not args:
                    raise DependencyFreezeError(
                        "Authoritative operation repository is unavailable."
                    )
                pubspec_token = _establish_operation_pubspec_custody(
                    pathlib.Path(os.fspath(args[0]))
                )
            result = operation(*args, **kwargs)
            if outermost:
                _rebind_retained_result_custody(
                    files or (), active or (), directories or ()
                )
            return result
        finally:
            if outermost:
                _close_retained_result_custody(
                    files or (), active or (), directories or ()
                )
                if pubspec_token is not None:
                    _ACTIVE_PUBSPEC_CUSTODY.reset(pubspec_token)
                if directory_token is not None:
                    _ACTIVE_RETURN_DIRECTORY_CUSTODY.reset(directory_token)
                if token is not None:
                    _ACTIVE_ANCHORED_CUSTODY.reset(token)
                if file_token is not None:
                    _ACTIVE_RETURN_FILE_CUSTODY.reset(file_token)

    return retained_operation


def _retain_regular_file_until_return(held: _HeldRegularFile) -> None:
    active = _ACTIVE_RETURN_FILE_CUSTODY.get()
    if active is None:
        raise DependencyFreezeError(
            "Return-bound file custody requires an authoritative operation scope."
        )
    active.append(held)


def _retain_directory_until_return(held: _HeldDirectory) -> None:
    active = _ACTIVE_RETURN_DIRECTORY_CUSTODY.get()
    if active is None:
        raise DependencyFreezeError(
            "Return-bound directory custody requires an authoritative operation scope."
        )
    active.append(held)


def _create_mutation_guard(
    descriptors: Iterable[int],
    label: str,
    *,
    write_descriptors: Iterable[int] = (),
) -> object | None:
    if not hasattr(select, "kqueue") or not hasattr(select, "kevent"):
        if isolated_fixture_mode_active():
            return None
        raise DependencyFreezeError(
            f"{label} requires kernel-backed pathname mutation detection"
        )
    queue = select.kqueue()
    base_fflags = (
        select.KQ_NOTE_DELETE
        | select.KQ_NOTE_RENAME
        | select.KQ_NOTE_REVOKE
    )
    write_set = frozenset(write_descriptors)
    try:
        changes = [
            select.kevent(
                descriptor,
                filter=select.KQ_FILTER_VNODE,
                flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                fflags=(
                    base_fflags
                    | (
                        select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND
                        if descriptor in write_set
                        else 0
                    )
                ),
            )
            for descriptor in descriptors
        ]
        queue.control(changes, 0, 0)
        return queue
    except Exception:
        queue.close()
        raise


def _close_mutation_guard(guard: object | None) -> None:
    if guard is not None:
        guard.close()


def _assert_no_pathname_mutation(guard: object | None, label: str) -> None:
    if guard is None:
        return
    if guard.control(None, 64, 0):
        raise DependencyFreezeError(
            f"{label} path or ancestor was replaced after final capture "
            "(renamed, deleted, or revoked while held)"
        )


def _close_held_directory(held: _HeldDirectory) -> None:
    _close_mutation_guard(held.mutation_guard)
    for component in reversed(held.components):
        _close_quietly(component.descriptor)
    _close_quietly(held.repo_descriptor)


def _rebind_held_components(
    repo: pathlib.Path,
    repo_descriptor: int,
    repo_identity: tuple[int, ...],
    components: tuple[_HeldPathComponent, ...],
    label: str,
    mutation_guard: object | None,
    mutable_directories: frozenset[str] = frozenset(),
) -> None:
    _assert_no_pathname_mutation(mutation_guard, label)
    repo_info = os.fstat(repo_descriptor)
    if _file_identity(repo_info) != repo_identity:
        raise DependencyFreezeError(
            f"{label} repository ancestor identity changed while held"
        )
    _rebind_requested_path(
        repo,
        repo_descriptor,
        repo_info,
        kind=f"{label} repository ancestor",
        directory=True,
    )
    for component in components:
        try:
            retained = os.fstat(component.descriptor)
            path_now = os.lstat(component.name, dir_fd=component.parent_descriptor)
            reopened = os.open(
                component.name,
                _directory_flags() if component.directory else _nofollow_flags(),
                dir_fd=component.parent_descriptor,
            )
        except OSError as suc:
            raise DependencyFreezeError(
                f"{label} path or ancestor was replaced after final capture"
            ) from suc
        try:
            opened = os.fstat(reopened)
        finally:
            os.close(reopened)
        expected_kind = (
            stat.S_ISDIR(retained.st_mode)
            if component.directory
            else stat.S_ISREG(retained.st_mode)
        )
        retained_identity = _file_identity(retained)
        expected_identity = component.identity
        opened_identity = _file_identity(opened)
        path_identity = _file_identity(path_now)
        if component.directory and component.relative in mutable_directories:
            retained_identity = retained_identity[:5]
            expected_identity = expected_identity[:5]
            opened_identity = opened_identity[:5]
            path_identity = path_identity[:5]
        if not (
            expected_kind
            and not _is_reparse_stat(path_now)
            and retained_identity == expected_identity
            and path_identity == expected_identity
            and opened_identity == expected_identity
        ):
            raise DependencyFreezeError(
                f"{label} path or ancestor was replaced after final capture"
            )
    _assert_no_pathname_mutation(mutation_guard, label)


def _close_held_regular_file(held: _HeldRegularFile) -> None:
    _close_mutation_guard(held.mutation_guard)
    for component in reversed(held.components):
        _close_quietly(component.descriptor)
    _close_quietly(held.repo_descriptor)


def _rebind_held_regular_file(held: _HeldRegularFile) -> None:
    mutable_directories = frozenset(
        component.relative
        for component in held.components
        if component.directory
    )
    _rebind_held_components(
        held.repo,
        held.repo_descriptor,
        held.repo_identity,
        held.components,
        held.label,
        held.mutation_guard,
        mutable_directories,
    )


def _rebind_held_directory(held: _HeldDirectory) -> None:
    _rebind_held_components(
        held.repo,
        held.repo_descriptor,
        held.repo_identity,
        held.components,
        held.label,
        held.mutation_guard,
    )


def _rebind_publication_directory(held: _HeldDirectory) -> None:
    mutable = frozenset(
        component.relative
        for component in held.components
        if component.relative == ".artifacts"
        or component is held.components[-1]
    )
    _rebind_held_components(
        held.repo,
        held.repo_descriptor,
        held.repo_identity,
        held.components,
        held.label,
        held.mutation_guard,
        mutable,
    )


def _rebind_held_anchored_file(held: _HeldRegularFile) -> None:
    parent = next(
        (
            component.relative
            for component in reversed(held.components[:-1])
            if component.directory
        ),
        "",
    )
    mutable = frozenset(
        component.relative
        for component in held.components
        if component.directory
        and (component.relative == ".artifacts" or component.relative == parent)
    )
    _rebind_held_components(
        held.repo,
        held.repo_descriptor,
        held.repo_identity,
        held.components,
        held.label,
        held.mutation_guard,
        mutable,
    )


def _hold_repo_directory(
    repo: pathlib.Path,
    path: pathlib.Path,
    allowed_owners: frozenset[int],
    *,
    label: str,
    watch_writes: bool = False,
) -> _HeldDirectory:
    try:
        relative = path.relative_to(repo).as_posix()
    except ValueError as suc:
        raise DependencyFreezeError(f"{label} must stay inside the repository.") from suc
    parts = _split_relative(relative)
    repo_descriptor, repo_info = _open_repo_dir(repo, allowed_owners)
    components: list[_HeldPathComponent] = []
    current = repo_descriptor
    rel = ""
    try:
        for part in parts:
            rel = _join_relative(rel, part)
            descriptor, info = _bind_directory_fd(
                current, part, rel, allowed_owners
            )
            components.append(
                _HeldPathComponent(
                    parent_descriptor=current,
                    name=part,
                    relative=rel,
                    descriptor=descriptor,
                    identity=_file_identity(info),
                    directory=True,
                )
            )
            current = descriptor
        guard = _create_mutation_guard(
            (repo_descriptor, *(component.descriptor for component in components)),
            label,
            write_descriptors=(
                (components[-1].descriptor,)
                if watch_writes and components
                else ()
            ),
        )
        held = _HeldDirectory(
            repo=repo,
            repo_descriptor=repo_descriptor,
            repo_identity=_file_identity(repo_info),
            components=tuple(components),
            label=label,
            mutation_guard=guard,
        )
        _rebind_held_directory(held)
        return held
    except Exception:
        for component in reversed(components):
            _close_quietly(component.descriptor)
        _close_quietly(repo_descriptor)
        raise


def _hold_repo_root_directory(
    repo: pathlib.Path,
    allowed_owners: frozenset[int],
    *,
    label: str,
    watch_writes: bool,
) -> _HeldDirectory:
    repo_descriptor, repo_info = _open_repo_dir(repo, allowed_owners)
    try:
        guard = _create_mutation_guard(
            (repo_descriptor,),
            label,
            write_descriptors=(repo_descriptor,) if watch_writes else (),
        )
        held = _HeldDirectory(
            repo=repo,
            repo_descriptor=repo_descriptor,
            repo_identity=_file_identity(repo_info),
            components=(),
            label=label,
            mutation_guard=guard,
        )
        _rebind_held_directory(held)
        return held
    except Exception:
        _close_quietly(repo_descriptor)
        raise


def _establish_operation_pubspec_custody(
    repo: pathlib.Path,
) -> contextvars.Token[object | None]:
    repo = secure_repo_path(
        repo, pathlib.Path("."), "Repository root", must_exist=True
    )
    return _ACTIVE_PUBSPEC_CUSTODY.set(("pending", repo))


def _ensure_release_root_write_custody(repo: pathlib.Path) -> None:
    active = _ACTIVE_RETURN_DIRECTORY_CUSTODY.get()
    if active is None or any(not held.components for held in active):
        return
    root = _hold_repo_root_directory(
        repo,
        _allowed_owners(repo),
        label="Release-input repository root",
        watch_writes=True,
    )
    _retain_directory_until_return(root)


def _operation_pubspec(repo: pathlib.Path) -> _HeldRegularFile | None:
    state = _ACTIVE_PUBSPEC_CUSTODY.get()
    if state is None:
        return None
    if type(state) is tuple:
        if state != ("pending", repo):
            raise DependencyFreezeError("Retained pubspec.yaml repository changed.")
        held = _hold_repo_regular_file(
            repo,
            repo / "pubspec.yaml",
            _allowed_owners(repo),
            label="Retained pubspec.yaml",
        )
        _retain_regular_file_until_return(held)
        _ACTIVE_PUBSPEC_CUSTODY.set(held)
    elif isinstance(state, _HeldRegularFile):
        held = state
    else:
        raise DependencyFreezeError("Retained pubspec.yaml custody is invalid.")
    if held.repo != repo:
        raise DependencyFreezeError("Retained pubspec.yaml repository changed.")
    if (
        not held.components
        or held.components[-1].relative != "pubspec.yaml"
    ):
        raise DependencyFreezeError("Retained pubspec.yaml custody is invalid.")
    _rebind_held_regular_file(held)
    return held


def _hold_repo_regular_file(
    repo: pathlib.Path,
    path: pathlib.Path,
    allowed_owners: frozenset[int],
    *,
    label: str,
) -> _HeldRegularFile:
    try:
        relative = path.relative_to(repo).as_posix()
    except ValueError as suc:
        raise DependencyFreezeError(f"{label} must stay inside the repository.") from suc
    parts = _split_relative(relative)
    repo_descriptor, repo_info = _open_repo_dir(repo, allowed_owners)
    components: list[_HeldPathComponent] = []
    current = repo_descriptor
    rel = ""
    try:
        for part in parts[:-1]:
            rel = _join_relative(rel, part)
            descriptor, info = _bind_directory_fd(
                current, part, rel, allowed_owners
            )
            components.append(
                _HeldPathComponent(
                    parent_descriptor=current,
                    name=part,
                    relative=rel,
                    descriptor=descriptor,
                    identity=_file_identity(info),
                    directory=True,
                )
            )
            current = descriptor
        result = _stable_read_regular_file_at(
            current,
            parts[-1],
            relative,
            allowed_owners,
            label=label,
        )
        leaf_descriptor = _open_at(
            current,
            parts[-1],
            _nofollow_flags(),
            relative,
            label,
        )
        try:
            leaf_info = os.fstat(leaf_descriptor)
            if (
                not stat.S_ISREG(leaf_info.st_mode)
                or _file_identity(leaf_info) != result[1]
            ):
                raise DependencyFreezeError(
                    f"{label} changed before its final descriptor was retained"
                )
            components.append(
                _HeldPathComponent(
                    parent_descriptor=current,
                    name=parts[-1],
                    relative=relative,
                    descriptor=leaf_descriptor,
                    identity=result[1],
                    directory=False,
                )
            )
        except Exception:
            os.close(leaf_descriptor)
            raise
        guard = _create_mutation_guard(
            (repo_descriptor, *(component.descriptor for component in components)),
            label,
            write_descriptors=(leaf_descriptor,),
        )
        held = _HeldRegularFile(
            repo=repo,
            repo_descriptor=repo_descriptor,
            repo_identity=_file_identity(repo_info),
            components=tuple(components),
            payload=result[0],
            identity=result[1],
            info=result[2],
            label=label,
            mutation_guard=guard,
        )
        _rebind_held_regular_file(held)
        return held
    except Exception:
        for component in reversed(components):
            _close_quietly(component.descriptor)
        _close_quietly(repo_descriptor)
        raise


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    record: dict[str, object] = {}
    for key, value in pairs:
        if key in record:
            raise DependencyFreezeError(f"duplicate JSON key: {key}")
        record[key] = value
    return record


def _reject_non_finite_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON constant is forbidden: {value}")


def _require_finite_json(value: object, label: str) -> None:
    if type(value) is float and not math.isfinite(value):
        raise DependencyFreezeError(f"{label} contains a non-finite JSON number.")
    if type(value) is list:
        for item in value:
            _require_finite_json(item, label)
    elif type(value) is dict:
        for item in value.values():
            _require_finite_json(item, label)


def _load_json_object(payload: bytes, label: str) -> dict[str, object]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DependencyFreezeError(f"{label} is not valid UTF-8.") from exc
    try:
        record = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_constant,
        )
    except DependencyFreezeError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise DependencyFreezeError(f"Unable to read {label}: {exc}") from exc
    if type(record) is not dict:
        raise DependencyFreezeError(f"{label} must be a JSON object.")
    _require_finite_json(record, label)
    return record


def _read_json_file(
    path: pathlib.Path,
    allowed_owners: frozenset[int],
    label: str,
    *,
    repo: pathlib.Path | None = None,
) -> tuple[dict[str, object], str]:
    if repo is not None and _ACTIVE_RETURN_FILE_CUSTODY.get() is not None:
        held = _hold_repo_regular_file(repo, path, allowed_owners, label=label)
        if len(held.payload) > MAX_DEPENDENCY_JSON_BYTES:
            _close_held_regular_file(held)
            raise DependencyFreezeError(f"{label} exceeds the accepted size bound.")
        _retain_regular_file_until_return(held)
        return (
            _load_json_object(held.payload, label),
            hashlib.sha256(held.payload).hexdigest(),
        )
    payload, _identity, _info = _stable_read_regular_file(
        path,
        allowed_owners,
        max_bytes=MAX_DEPENDENCY_JSON_BYTES,
        label=label,
        repo=repo,
    )
    return _load_json_object(payload, label), hashlib.sha256(payload).hexdigest()


def _utf8_text(payload: bytes, label: str) -> str:
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DependencyFreezeError(f"{label} is not valid UTF-8.") from exc


def _require_bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise DependencyFreezeError(f"{label} must be a JSON boolean.")
    return value


def _require_int(value: object, label: str) -> int:
    if type(value) is not int:
        raise DependencyFreezeError(f"{label} must be a JSON integer.")
    return value


def _require_str(value: object, label: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str:
        raise DependencyFreezeError(f"{label} must be a JSON string.")
    if not allow_empty and not value:
        raise DependencyFreezeError(f"{label} must be a non-empty JSON string.")
    return value


def _require_list(value: object, label: str) -> list[object]:
    if type(value) is not list:
        raise DependencyFreezeError(f"{label} must be a JSON array.")
    return value


def _require_str_list(value: object, label: str) -> list[str]:
    items = _require_list(value, label)
    parsed: list[str] = []
    for item in items:
        parsed.append(_require_str(item, label))
    return parsed


def _require_sha256(value: object, label: str) -> str:
    digest = _require_str(value, label)
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise DependencyFreezeError(f"{label} is not a SHA-256 digest.")
    return digest


def _require_issuance(value: object, label: str) -> str:
    issuance = _require_str(value, label)
    if ISSUANCE_ID.fullmatch(issuance) is None:
        raise DependencyFreezeError(f"{label} must be a 32-hex issuance identity.")
    return issuance


def _require_fresh(created: dt.datetime, label: str) -> None:
    now = dt.datetime.now(tz=dt.timezone.utc)
    if created > now + MAX_RECEIPT_CLOCK_SKEW or now - created > MAX_RECEIPT_AGE:
        raise DependencyFreezeError(f"{label} is stale or future-dated.")


def _require_recent_postmortem_stat(info: os.stat_result, label: str) -> None:
    now_ns = int(dt.datetime.now(tz=dt.timezone.utc).timestamp() * 1_000_000_000)
    if (
        info.st_mtime_ns > now_ns + POSTMORTEM_CLOCK_SKEW_NS
        or now_ns - info.st_mtime_ns > POSTMORTEM_MAX_AGE_NS
    ):
        raise DependencyFreezeError(f"{label} is stale or future-dated.")


def _freeze_metadata_relative(release: str) -> str:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\+[0-9]+", release):
        raise DependencyFreezeError("Release identity is unsafe.")
    return f".artifacts/release-freeze-{release}"


def _path_digest_ref(
    path: str, digest: str, issuance_id: str
) -> dict[str, object]:
    return {
        "path": path,
        "sha256": digest,
        "issuance_id": issuance_id,
    }


def _read_required_json(
    repo: pathlib.Path,
    relative: str,
    label: str,
    missing_message: str,
) -> tuple[dict[str, object], str, pathlib.Path]:
    try:
        path = secure_repo_path(
            repo, pathlib.Path(relative), label, must_exist=True
        )
    except DependencyFreezeError as suc:
        raise DependencyFreezeError(missing_message) from suc
    owners = _allowed_owners(repo)
    record, digest = _read_json_file(
        path, owners, label, repo=repo
    )
    return record, digest, path


def _parse_app_source_lock(
    record: dict[str, object], release: str, issuance: object
) -> None:
    source = _source_freeze_module()
    try:
        source._parse_lock(record, release, issuance)
    except source.SourceFreezeError as suc:
        _raise_source_freeze(suc)


def _parse_scope_freeze(
    record: dict[str, object],
    release: str,
    frozen_fingerprint: object,
    issuance: object,
) -> None:
    source = _source_freeze_module()
    try:
        source._parse_scope(record, release, frozen_fingerprint, issuance)
    except source.SourceFreezeError as suc:
        _raise_source_freeze(suc)


@dataclasses.dataclass(frozen=True)
class _AuthenticatedCustody:
    source_freeze: dict[str, object]
    toolchain_custody: dict[str, object]
    issuance: object
    lock_relative: str
    lock_identity: tuple[int, ...]
    freeze_dir_relative: str
    freeze_dir_identity: tuple[int, ...]
    pin_identity: tuple[int, ...]
    scope_relative: str
    scope_identity: tuple[int, ...]


def _load_current_authenticated_custody(
    repo: pathlib.Path,
) -> _AuthenticatedCustody:
    """Bind current owner-issued source-freeze trust and reviewed toolchain pin."""

    source = _source_freeze_module()
    release = _release_identity(repo)
    try:
        issuance = source._bind_external_issuance(repo)
    except source.SourceFreezeError as suc:
        _raise_source_freeze(suc)
    if issuance.release != release:
        raise DependencyFreezeError(
            "current reviewed source-freeze issuance identity is unavailable"
        )
    freeze_dir = _freeze_metadata_relative(release)
    lock_relative = f"{freeze_dir}/{APP_SOURCE_LOCK_NAME}"
    scope_relative = f"{freeze_dir}/{SCOPE_FREEZE_NAME}"
    lock_record, lock_digest, lock_path = _read_required_json(
        repo,
        lock_relative,
        "APP_SOURCE_LOCK.json",
        "No immutable APP_SOURCE_LOCK.json exists for the current release.",
    )
    if lock_digest != issuance.app_source_lock_sha256:
        raise DependencyFreezeError(
            "mutated application or website sources cannot self-author replacement freeze receipts"
        )
    _parse_app_source_lock(lock_record, release, issuance)
    scope_record, scope_digest, scope_path = _read_required_json(
        repo,
        scope_relative,
        "SCOPE_FREEZE.json",
        "App source lock is not bound to the exact scope-freeze manifest.",
    )
    if scope_digest != issuance.scope_freeze_sha256:
        raise DependencyFreezeError(
            "mutated application or website sources cannot self-author replacement freeze receipts"
        )
    if lock_record.get("scope_freeze_sha256") != scope_digest:
        raise DependencyFreezeError(
            "App source lock is not bound to the exact scope-freeze manifest."
        )
    _parse_scope_freeze(
        scope_record,
        release,
        lock_record.get("frozen_combined_source_fingerprint_sha256"),
        issuance,
    )
    owners = _allowed_owners(repo)
    pin_path = secure_repo_path(
        repo, pathlib.Path(TOOLCHAIN_PIN_PATH), "Toolchain pin manifest", must_exist=True
    )
    pin_payload, pin_identity, _pin_info = _stable_read_regular_file(
        pin_path, owners, label="Toolchain pin manifest", repo=repo
    )
    pin_digest = hashlib.sha256(pin_payload).hexdigest()
    freeze_dir_path = repo / freeze_dir
    try:
        freeze_dir_info = os.lstat(freeze_dir_path)
        lock_info = os.lstat(lock_path)
        scope_info = os.lstat(scope_path)
    except OSError as suc:
        raise DependencyFreezeError(
            "No immutable APP_SOURCE_LOCK.json exists for the current release."
        ) from suc
    return _AuthenticatedCustody(
        source_freeze=_path_digest_ref(
            issuance.path, issuance.digest, issuance.issuance_id
        ),
        toolchain_custody=_path_digest_ref(
            TOOLCHAIN_PIN_PATH, pin_digest, issuance.issuance_id
        ),
        issuance=issuance,
        lock_relative=lock_relative,
        lock_identity=_file_identity(lock_info),
        freeze_dir_relative=freeze_dir,
        freeze_dir_identity=_file_identity(freeze_dir_info),
        pin_identity=pin_identity,
        scope_relative=scope_relative,
        scope_identity=_file_identity(scope_info),
    )


def _rebind_authenticated_custody(
    repo: pathlib.Path,
    custody: _AuthenticatedCustody,
) -> None:
    source = _source_freeze_module()
    owners = _allowed_owners(repo)
    repo_fd, repo_info = _open_repo_dir(repo, owners)
    try:
        _rebind_requested_path(
            repo,
            repo_fd,
            repo_info,
            kind="Repository root",
            directory=True,
        )
        try:
            source._rebind_external_issuance(custody.issuance)
        except source.SourceFreezeError as suc:
            _raise_source_freeze(suc)
        _rebind_relative_path(
            repo_fd,
            custody.freeze_dir_relative,
            custody.freeze_dir_identity,
            owners,
            directory=True,
        )
        _rebind_relative_path(
            repo_fd,
            custody.lock_relative,
            custody.lock_identity,
            owners,
            directory=False,
        )
        _rebind_relative_path(
            repo_fd,
            custody.scope_relative,
            custody.scope_identity,
            owners,
            directory=False,
        )
        _rebind_relative_path(
            repo_fd,
            TOOLCHAIN_PIN_PATH,
            custody.pin_identity,
            owners,
            directory=False,
        )
    finally:
        os.close(repo_fd)


def secure_repo_path(
    repo: pathlib.Path,
    path: pathlib.Path,
    label: str,
    *,
    must_exist: bool,
    allow_missing_leaf: bool = False,
) -> pathlib.Path:
    """Return a contained path after rejecting symlink/junction ancestors."""

    repo_lexical = pathlib.Path(os.path.abspath(repo))
    path_lexical = pathlib.Path(
        os.path.abspath(path if path.is_absolute() else repo_lexical / path)
    )
    try:
        relative = path_lexical.relative_to(repo_lexical)
    except ValueError as exc:
        raise DependencyFreezeError(f"{label} must stay inside the repository.") from exc
    cursor = repo_lexical
    if not cursor.exists() or not cursor.is_dir() or _is_reparse_point(cursor):
        raise DependencyFreezeError("Repository root is missing or uses a reparse point.")
    parts = relative.parts
    for index, part in enumerate(parts):
        cursor = cursor / part
        try:
            cursor.lstat()
            entry_exists = True
        except FileNotFoundError:
            entry_exists = False
        except OSError as exc:
            raise DependencyFreezeError(f"Unable to inspect {label}: {exc}") from exc
        if not entry_exists:
            if allow_missing_leaf and index == len(parts) - 1:
                break
            if not must_exist:
                break
            raise DependencyFreezeError(f"{label} does not exist: {path_lexical}")
        if _is_reparse_point(cursor):
            raise DependencyFreezeError(
                f"{label} uses a symlink, junction, or reparse point: {cursor}"
            )
    if must_exist and not path_lexical.exists():
        raise DependencyFreezeError(f"{label} does not exist: {path_lexical}")
    resolved_repo = repo_lexical.resolve()
    resolved_path = path_lexical.resolve(strict=must_exist)
    try:
        resolved_path.relative_to(resolved_repo)
    except ValueError as exc:
        raise DependencyFreezeError(f"{label} resolves outside the repository.") from exc
    return path_lexical


def _require_artifacts_output(
    repo: pathlib.Path,
    output: pathlib.Path,
    label: str,
    *,
    must_exist: bool = False,
    allow_missing_leaf: bool = True,
) -> pathlib.Path:
    """Return a contained .artifacts/ path after rejecting reparse ancestors."""

    candidate = pathlib.Path(
        os.path.abspath(output if output.is_absolute() else repo / output)
    )
    try:
        relative = candidate.relative_to(repo)
    except ValueError as exc:
        raise DependencyFreezeError(f"{label} must stay inside the repository.") from exc
    if not relative.parts or relative.parts[0] != ".artifacts":
        raise DependencyFreezeError(f"{label} must stay under .artifacts/.")
    if any(
        _fold_key(part).startswith((".build-attempt-", ".freeze-staging-"))
        for part in relative.parts[1:]
    ):
        raise DependencyFreezeError(
            f"{label} must not use a reserved release transaction namespace."
        )
    return secure_repo_path(
        repo,
        output,
        label,
        must_exist=must_exist,
        allow_missing_leaf=allow_missing_leaf,
    )


def _assert_canonical_platforms() -> None:
    if set(PLATFORM_ROOTS) != set(CANONICAL_FREEZE_PLATFORMS):
        raise DependencyFreezeError("Canonical freeze platform set drifted.")
    if set(PLATFORM_STORE_SURFACES) != set(CANONICAL_FREEZE_PLATFORMS):
        raise DependencyFreezeError("Store-surface map does not cover every freeze platform.")
    if set(PLATFORM_ALLOWED_TARGETS) != set(CANONICAL_FREEZE_PLATFORMS):
        raise DependencyFreezeError("Reviewed target map does not cover every freeze platform.")
    if set(PLATFORM_REQUIRED_GATE_PRODUCERS) != set(CANONICAL_FREEZE_PLATFORMS):
        raise DependencyFreezeError("Hardening-gate map does not cover every freeze platform.")
    if set(PLATFORM_BUILD_PRODUCERS) != set(CANONICAL_FREEZE_PLATFORMS):
        raise DependencyFreezeError("Build-producer map does not cover every freeze platform.")
    if set(PLATFORM_ARTIFACT_PRODUCER_PATHS) != set(CANONICAL_FREEZE_PLATFORMS):
        raise DependencyFreezeError(
            "Artifact-producer map does not cover every freeze platform."
        )
    for platform in CANONICAL_FREEZE_PLATFORMS:
        producer_paths = PLATFORM_PRODUCER_PATHS.get(platform, ())
        if len(producer_paths) != len(set(producer_paths)):
            raise DependencyFreezeError(
                f"{platform} freeze producer closure contains duplicate paths."
            )
        missing = [
            path
            for path in (*PLATFORM_ARTIFACT_PRODUCER_PATHS[platform], *required_gate_producers(platform))
            if path not in producer_paths
        ]
        if missing:
            raise DependencyFreezeError(
                f"{platform} freeze producer closure is incomplete: "
                + ", ".join(dict.fromkeys(missing))
            )
    for (platform, host), producer in PLATFORM_BUILD_PRODUCERS_BY_HOST.items():
        if (
            platform not in CANONICAL_FREEZE_PLATFORMS
            or host not in PRODUCER_EXECUTION_HOSTS
            or producer not in PLATFORM_PRODUCER_PATHS.get(platform, ())
        ):
            raise DependencyFreezeError(
                f"{platform} {host} build producer is not a frozen producer input."
            )
    if not PRODUCER_ATTESTED_PLATFORM_HOSTS <= set(PLATFORM_BUILD_PRODUCERS_BY_HOST):
        raise DependencyFreezeError(
            "Producer-attested execution requires a host-specific producer."
        )
    _assert_windows_native_host_lib_aliases()
    missing_linux_engines = [
        path
        for path in LINUX_ENGINE_PRODUCER_PATHS
        if path not in PLATFORM_PRODUCER_PATHS["linux"]
    ]
    if missing_linux_engines:
        raise DependencyFreezeError(
            "linux freeze producers omit required engine builders: "
            + ", ".join(missing_linux_engines)
        )


def _assert_windows_native_host_lib_aliases() -> None:
    aliases = WINDOWS_NATIVE_HOST_LIB_SYMLINK_ALIASES
    if len(aliases) != 8:
        raise DependencyFreezeError(
            "Windows native-messaging host/lib symlink alias set must contain exactly eight entries."
        )
    seen_alias: set[str] = set()
    seen_name: set[str] = set()
    extras = set(PLATFORM_NATIVE_EXTRA_PATHS["windows"])
    producers = set(PLATFORM_PRODUCER_PATHS["windows"])
    hashed_host = set(WINDOWS_NATIVE_HOST_INPUT_PATHS)
    for alias, target in aliases:
        alias_path = pathlib.PurePosixPath(alias)
        if str(alias_path.parent) != WINDOWS_NATIVE_HOST_LIB_SYMLINK_DIR:
            raise DependencyFreezeError(
                "Windows native-messaging host/lib symlink alias is outside the host/lib directory."
            )
        if alias in seen_alias or alias_path.name in seen_name:
            raise DependencyFreezeError(
                "Windows native-messaging host/lib symlink aliases are not unique."
            )
        seen_alias.add(alias)
        seen_name.add(alias_path.name)
        if target != f"../../../../lib/{alias_path.name}":
            raise DependencyFreezeError(
                "Windows native-messaging host/lib symlink alias target is not the exact expected relative path."
            )
        if alias in extras or alias in producers or alias in hashed_host:
            raise DependencyFreezeError(
                "Windows native-messaging host/lib symlink aliases must not be hashed as regular blobs."
            )


def required_gate_producers(platform: str) -> tuple[str, ...]:
    if platform not in PLATFORM_REQUIRED_GATE_PRODUCERS:
        raise DependencyFreezeError(f"Unsupported platform: {platform}")
    return PLATFORM_REQUIRED_GATE_PRODUCERS[platform]


def store_surfaces(platform: str) -> tuple[str, ...]:
    if platform not in PLATFORM_STORE_SURFACES:
        raise DependencyFreezeError(f"Unsupported platform: {platform}")
    return PLATFORM_STORE_SURFACES[platform]


def allowed_targets(platform: str) -> tuple[str, ...]:
    if platform not in PLATFORM_ALLOWED_TARGETS:
        raise DependencyFreezeError(f"Unsupported platform: {platform}")
    return PLATFORM_ALLOWED_TARGETS[platform]


def _assert_required_gate_producers(platform: str) -> None:
    present = set(PLATFORM_PRODUCER_PATHS[platform])
    missing = [path for path in required_gate_producers(platform) if path not in present]
    missing.extend(
        path
        for path in PLATFORM_ARTIFACT_PRODUCER_PATHS[platform]
        if path not in present and path not in missing
    )
    if missing:
        raise DependencyFreezeError(
            f"{platform} freeze producer closure omits required authorities: "
            + ", ".join(missing)
        )


def _assert_allowed_target(platform: str, target: str) -> None:
    if target not in allowed_targets(platform):
        raise DependencyFreezeError(
            f"{platform} build receipt target is not a reviewed store target."
        )


def _archive_member_name(name: str, label: str) -> str:
    if (
        type(name) is not str
        or not name
        or "\x00" in name
        or "\\" in name
        or unicodedata.normalize("NFC", name) != name
    ):
        raise DependencyFreezeError(f"{label} member name is unsafe.")
    pure = pathlib.PurePosixPath(name)
    if pure.is_absolute() or ".." in pure.parts or any(not part for part in pure.parts):
        raise DependencyFreezeError(f"{label} member escapes its archive.")
    return name


def _validated_zip_members(payload: bytes, label: str) -> dict[str, bytes]:
    if len(payload) < 22 or not payload.startswith(b"PK\x03\x04"):
        raise DependencyFreezeError(f"{label} is not a complete ZIP archive.")
    eocd_offset = payload.rfind(b"PK\x05\x06", max(0, len(payload) - 65_557))
    if eocd_offset < 0 or eocd_offset + 22 > len(payload):
        raise DependencyFreezeError(f"{label} ZIP end record is missing.")
    try:
        (
            _signature,
            disk_number,
            central_disk,
            disk_entries,
            total_entries,
            central_size,
            central_offset,
            comment_size,
        ) = struct.unpack_from("<4s4H2LH", payload, eocd_offset)
    except struct.error as exc:
        raise DependencyFreezeError(f"{label} ZIP end record is malformed.") from exc
    if (
        disk_number != 0
        or central_disk != 0
        or disk_entries != total_entries
        or total_entries < 1
        or total_entries > ARCHIVE_ENTRY_LIMIT
        or eocd_offset + 22 + comment_size != len(payload)
        or central_offset < 4
        or central_size < 1
        or central_offset + central_size > eocd_offset
    ):
        raise DependencyFreezeError(f"{label} ZIP topology is invalid.")
    members: dict[str, bytes] = {}
    casefolded: set[str] = set()
    expanded = 0
    try:
        with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
            infos = archive.infolist()
            if len(infos) != total_entries:
                raise DependencyFreezeError(f"{label} ZIP entry count changed.")
            for info in infos:
                name = _archive_member_name(info.filename, label)
                folded = name.casefold()
                if name in members or folded in casefolded:
                    raise DependencyFreezeError(f"{label} has duplicate archive members.")
                casefolded.add(folded)
                unix_mode = (info.external_attr >> 16) & 0o177777
                if (
                    info.flag_bits & 0x1
                    or info.file_size < 0
                    or info.compress_size < 0
                    or info.file_size > BUILD_ATTEMPT_BYTES_LIMIT
                    or stat.S_IFMT(unix_mode) in {stat.S_IFLNK, stat.S_IFBLK, stat.S_IFCHR, stat.S_IFIFO, stat.S_IFSOCK}
                ):
                    raise DependencyFreezeError(f"{label} contains an unsafe member.")
                expanded += info.file_size
                if expanded > ARCHIVE_EXPANDED_BYTES_LIMIT:
                    raise DependencyFreezeError(f"{label} expanded bytes exceed the bound.")
                if info.is_dir():
                    members[name] = b""
                    continue
                chunks: list[bytes] = []
                read_size = 0
                with archive.open(info, "r") as source:
                    while True:
                        block = source.read(1024 * 1024)
                        if not block:
                            break
                        read_size += len(block)
                        if read_size > info.file_size:
                            raise DependencyFreezeError(f"{label} member grew while read.")
                        if info.file_size <= ARCHIVE_METADATA_BYTES_LIMIT:
                            chunks.append(block)
                if read_size != info.file_size:
                    raise DependencyFreezeError(f"{label} member size changed.")
                members[name] = b"".join(chunks)
    except (OSError, RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
        raise DependencyFreezeError(f"{label} ZIP payload is malformed.") from exc
    return members


def _require_signed_android_archive(
    members: dict[str, bytes], target: str, label: str
) -> None:
    names = set(members)
    signer_suffixes = (".RSA", ".EC", ".DSA")
    signer = any(
        name.startswith("META-INF/") and name.upper().endswith(signer_suffixes)
        for name in names
    )
    signature_file = any(
        name.startswith("META-INF/") and name.upper().endswith(".SF")
        for name in names
    )
    if target.endswith("-apk"):
        required = {"AndroidManifest.xml", "classes.dex", "resources.arsc"}
    else:
        required = {
            "BundleConfig.pb",
            "base/manifest/AndroidManifest.xml",
            "base/dex/classes.dex",
        }
    if not required.issubset(names) or not signer or not signature_file:
        raise DependencyFreezeError(
            f"{label} lacks the required signed Android package structure."
        )
    if any(not members[name] for name in required):
        raise DependencyFreezeError(f"{label} contains an empty required package member.")


def _require_extension_zip(members: dict[str, bytes], label: str) -> None:
    manifest_payload = members.get("manifest.json")
    if not manifest_payload or len(manifest_payload) > ARCHIVE_METADATA_BYTES_LIMIT:
        raise DependencyFreezeError(f"{label} lacks a bounded manifest.json.")
    manifest = _load_json_object(manifest_payload, f"{label} manifest")
    version = manifest.get("manifest_version")
    if (
        type(version) is not int
        or version not in {2, 3}
        or type(manifest.get("name")) is not str
        or not manifest.get("name")
        or type(manifest.get("version")) is not str
        or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,3}", manifest.get("version", ""))
        or not any(name != "manifest.json" and payload for name, payload in members.items())
    ):
        raise DependencyFreezeError(f"{label} extension manifest is invalid.")


# The store zips extension/build.py writes, by receipt target. AMO also takes the
# Firefox ZIP renamed .xpi (a distinct-inode copy of the same bytes).
EXTENSION_RELEASE_ARTIFACT_NAMES = {
    "chrome-zip": ("wins-vpn-companion-chrome.zip",),
    "edge-zip": ("wins-vpn-companion-edge.zip",),
    "firefox-zip": (
        "wins-vpn-companion-firefox.zip",
        "wins-vpn-companion-firefox.xpi",
    ),
}
EXTENSION_FIREFOX_GECKO_ID = "companion@winsvpn.org"
# The reviewed store identity per receipt target. Chrome and Edge are both
# Chromium-shaped, so the manifest name is the field that distinguishes them;
# bind it so chrome bytes cannot be attested as an edge-zip receipt (or the
# reverse). These match extension/manifest/{chrome,edge,firefox}.jsonc and the
# EXPECTED_TARGET_NAMES / EXPECTED_NAME the cross-store zip gates already bind.
EXTENSION_STORE_NAMES = {
    "chrome-zip": "Win's VPN Proxy for Chrome",
    "edge-zip": "Win's VPN Proxy for Microsoft Edge",
    "firefox-zip": "Win's VPN Proxy",
}


def _require_extension_release_package(
    members: dict[str, bytes], target: str, artifact_name: str, label: str
) -> None:
    """Require the exact unsigned store zip extension/build.py ships for ``target``.

    Binds the canonical file name to the receipt target, requires Manifest V3
    with the browser family's own background entry point present in the
    archive, refuses an already signed or packed archive, and binds Firefox to
    its reviewed Gecko id. Chrome and Edge stay Chromium-shaped: no Gecko
    settings and no background script list.
    """

    if artifact_name not in EXTENSION_RELEASE_ARTIFACT_NAMES.get(target, ()):
        raise DependencyFreezeError(
            f"{label} is not the canonical {target} store package name."
        )
    _require_extension_zip(members, label)
    if any(
        part.casefold() in {"meta-inf", "_metadata"}
        for name in members
        for part in name.split("/")
    ):
        raise DependencyFreezeError(
            f"{label} is already signed or packed; store uploads take the unsigned zip."
        )
    manifest = _load_json_object(members["manifest.json"], f"{label} manifest")
    background = manifest.get("background")
    if type(manifest.get("manifest_version")) is not int or manifest.get(
        "manifest_version"
    ) != 3 or type(background) is not dict:
        raise DependencyFreezeError(
            f"{label} is not a Manifest V3 extension with a background entry."
        )
    settings = manifest.get("browser_specific_settings")
    if target == "firefox-zip":
        gecko = settings.get("gecko") if type(settings) is dict else None
        scripts = background.get("scripts")
        if (
            type(gecko) is not dict
            or gecko.get("id") != EXTENSION_FIREFOX_GECKO_ID
            or "service_worker" in background
            or type(scripts) is not list
            or not scripts
            or any(type(item) is not str or not members.get(item) for item in scripts)
        ):
            raise DependencyFreezeError(
                f"{label} is not the reviewed Firefox package (Gecko id and background scripts)."
            )
        if manifest.get("name") != EXTENSION_STORE_NAMES[target]:
            raise DependencyFreezeError(
                f"{label} does not carry the reviewed {target} store name."
            )
        return
    worker = background.get("service_worker")
    if (
        settings is not None
        or "scripts" in background
        or type(worker) is not str
        or not members.get(worker)
    ):
        raise DependencyFreezeError(
            f"{label} is not a Chromium package with a packaged service worker."
        )
    if manifest.get("name") != EXTENSION_STORE_NAMES[target]:
        raise DependencyFreezeError(
            f"{label} does not carry the reviewed {target} store name."
        )


WEAR_OS_APPLICATION_ID = "org.winsvpn.app"
WEAR_OS_WATCH_FEATURE = "android.hardware.type.watch"
ANDROID_RESOURCE_NAMESPACE = "http://schemas.android.com/apk/res/android"
_PROTO_MANIFEST_FIELD_LIMIT = 100_000


def _proto_message_fields(payload: bytes, label: str) -> list[tuple[int, int, object]]:
    """Decode one protobuf message level into (field, wire type, value) tuples.

    Only the wire types aapt2 emits are accepted; any truncation or overrun is
    a malformed manifest, never a partial parse.
    """

    fields: list[tuple[int, int, object]] = []
    offset = 0
    size = len(payload)

    def varint() -> int:
        nonlocal offset
        value = 0
        for shift in range(0, 70, 7):
            if offset >= size:
                raise DependencyFreezeError(f"{label} protobuf manifest is truncated.")
            byte = payload[offset]
            offset += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value
        raise DependencyFreezeError(f"{label} protobuf manifest varint is malformed.")

    while offset < size:
        if len(fields) >= _PROTO_MANIFEST_FIELD_LIMIT:
            raise DependencyFreezeError(f"{label} protobuf manifest is too large.")
        key = varint()
        number, wire = key >> 3, key & 0x7
        if number < 1:
            raise DependencyFreezeError(f"{label} protobuf manifest field is malformed.")
        if wire == 0:
            value: object = varint()
        elif wire == 2:
            length = varint()
            if length > size - offset:
                raise DependencyFreezeError(f"{label} protobuf manifest is truncated.")
            value = payload[offset:offset + length]
            offset += length
        elif wire in {1, 5}:
            width = 8 if wire == 1 else 4
            if width > size - offset:
                raise DependencyFreezeError(f"{label} protobuf manifest is truncated.")
            value = payload[offset:offset + width]
            offset += width
        else:
            raise DependencyFreezeError(f"{label} protobuf manifest wire type is unsupported.")
        fields.append((number, wire, value))
    return fields


def _proto_xml_element(node: bytes, label: str) -> bytes | None:
    """Return the XmlElement of an aapt2 XmlNode, or None for a text node."""

    elements = [
        value for number, wire, value in _proto_message_fields(node, label)
        if number == 1 and wire == 2
    ]
    if len(elements) > 1:
        raise DependencyFreezeError(f"{label} protobuf XML node is ambiguous.")
    return elements[0] if elements else None


def _proto_xml_string(value: object, label: str) -> str:
    if type(value) is not bytes:
        raise DependencyFreezeError(f"{label} protobuf XML string is malformed.")
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DependencyFreezeError(f"{label} protobuf XML string is not UTF-8.") from exc


def _proto_xml_summary(
    element: bytes, label: str
) -> tuple[str, dict[tuple[str, str], str], list[bytes]]:
    """Return (name, {(namespace, attribute): value}, child elements)."""

    name = ""
    attributes: dict[tuple[str, str], str] = {}
    children: list[bytes] = []
    for number, wire, value in _proto_message_fields(element, label):
        if number == 3 and wire == 2:
            name = _proto_xml_string(value, label)
        elif number == 4 and wire == 2:
            attribute: dict[int, str] = {}
            for field, field_wire, field_value in _proto_message_fields(value, label):
                if field in {1, 2, 3} and field_wire == 2:
                    attribute[field] = _proto_xml_string(field_value, label)
            key = (attribute.get(1, ""), attribute.get(2, ""))
            if key in attributes:
                raise DependencyFreezeError(f"{label} protobuf XML attribute repeats.")
            attributes[key] = attribute.get(3, "")
        elif number == 5 and wire == 2:
            child = _proto_xml_element(value, label)
            if child is not None:
                children.append(child)
    return name, attributes, children


def _android_bundle_declares_watch(members: dict[str, bytes], label: str) -> bool:
    """Return whether the AAB base manifest requires the watch hardware type.

    Reads the aapt2 protobuf base/manifest/AndroidManifest.xml: the root
    <manifest> for org.winsvpn.app and a direct <uses-feature
    android:name="android.hardware.type.watch"> that is not required="false".
    """

    payload = members.get("base/manifest/AndroidManifest.xml", b"")
    root = _proto_xml_element(payload, label) if payload else None
    if root is None:
        raise DependencyFreezeError(f"{label} lacks a protobuf base manifest.")
    name, attributes, children = _proto_xml_summary(root, label)
    if name != "manifest" or attributes.get(("", "package")) != WEAR_OS_APPLICATION_ID:
        raise DependencyFreezeError(
            f"{label} base manifest is not the {WEAR_OS_APPLICATION_ID} manifest."
        )
    for child in children:
        child_name, child_attributes, _grandchildren = _proto_xml_summary(child, label)
        if (
            child_name != "uses-feature"
            or child_attributes.get((ANDROID_RESOURCE_NAMESPACE, "name"))
            != WEAR_OS_WATCH_FEATURE
        ):
            continue
        # aapt2 parses a boolean attribute with ResourceUtils::ParseBool: it
        # trims whitespace and accepts only true, TRUE, True, false, FALSE and
        # False, and keeps that raw text. Any other value (a resource
        # reference, an empty raw value) is refused instead of guessed.
        required = child_attributes.get(
            (ANDROID_RESOURCE_NAMESPACE, "required"), "true"
        ).strip(" \t\n\v\f\r")
        if required in {"true", "TRUE", "True"}:
            return True
        if required not in {"false", "FALSE", "False"}:
            raise DependencyFreezeError(
                f"{label} {WEAR_OS_WATCH_FEATURE} required value is not a literal boolean."
            )
    return False


def _require_wear_os_bundle(
    payload: bytes, target: str, suffix: str, label: str
) -> None:
    """Require a signed Wear OS AAB: the Android AAB checks plus the watch feature.

    The signature itself is verified by the producer (jarsigner, the reviewed
    upload certificate and bundletool) before it attests; this binds the
    attested bytes to a signed bundle whose base manifest requires a watch, so
    a phone or TV bundle cannot be receipted as the Wear artifact.
    """

    if target != "wear-os-release-aab":
        raise DependencyFreezeError(f"{label} target is not the Wear OS release AAB.")
    _require_android_package(payload, target, suffix, label)
    if not _android_bundle_declares_watch(_validated_zip_members(payload, label), label):
        raise DependencyFreezeError(
            f"{label} is not a Wear OS bundle: its base manifest does not require "
            f"{WEAR_OS_WATCH_FEATURE}."
        )


def _require_msix(members: dict[str, bytes], label: str) -> None:
    required = {
        "[Content_Types].xml",
        "AppxManifest.xml",
        "AppxBlockMap.xml",
        "AppxSignature.p7x",
    }
    if not required.issubset(members) or any(not members[name] for name in required):
        raise DependencyFreezeError(f"{label} lacks signed MSIX package structure.")
    for name in ("[Content_Types].xml", "AppxManifest.xml", "AppxBlockMap.xml"):
        try:
            root = etree.fromstring(members[name])
        except (etree.ParseError, ValueError) as exc:
            raise DependencyFreezeError(f"{label} contains malformed MSIX XML.") from exc
        if not root.tag:
            raise DependencyFreezeError(f"{label} MSIX XML is empty.")


def _require_ipa(members: dict[str, bytes], label: str) -> None:
    app_roots = {
        "/".join(name.split("/")[:2])
        for name in members
        if name.startswith("Payload/") and len(name.split("/")) >= 3 and name.split("/")[1].endswith(".app")
    }
    if len(app_roots) != 1:
        raise DependencyFreezeError(f"{label} must contain exactly one top-level app.")
    app_root = next(iter(app_roots))
    info_name = f"{app_root}/Info.plist"
    code_resources = f"{app_root}/_CodeSignature/CodeResources"
    profile = f"{app_root}/embedded.mobileprovision"
    if not members.get(info_name) or not members.get(code_resources) or not members.get(profile):
        raise DependencyFreezeError(f"{label} lacks signed IPA app metadata.")
    try:
        info = plistlib.loads(members[info_name])
    except Exception as exc:
        raise DependencyFreezeError(f"{label} Info.plist is malformed.") from exc
    executable = info.get("CFBundleExecutable") if type(info) is dict else None
    if type(executable) is not str or not re.fullmatch(r"[A-Za-z0-9._+-]{1,127}", executable):
        raise DependencyFreezeError(f"{label} executable identity is invalid.")
    binary = members.get(f"{app_root}/{executable}")
    macho_magics = {
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    }
    if binary is None or len(binary) < 4096 or binary[:4] not in macho_magics:
        raise DependencyFreezeError(f"{label} app executable is not a complete Mach-O.")


def _require_pe_installer(payload: bytes, target: str, label: str) -> None:
    if len(payload) < 4096 or payload[:2] != b"MZ":
        raise DependencyFreezeError(f"{label} is not a complete PE installer.")
    try:
        pe_offset = struct.unpack_from("<I", payload, 0x3C)[0]
        if pe_offset < 0x40 or pe_offset + 24 > len(payload):
            raise ValueError
        if payload[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            raise ValueError
        machine, section_count, _timestamp, _symbols, _symbol_count, optional_size, characteristics = struct.unpack_from(
            "<HHIIIHH", payload, pe_offset + 4
        )
        optional_offset = pe_offset + 24
        section_table = optional_offset + optional_size
        # Inno Setup 7.1.0 ships x86 and x64 setup loaders only, so an ARM64 installer is the
        # x64 loader (winsvpn.iss [Setup] SetupArchitecture=x64) around the ARM64 payload,
        # which build_installer.ps1 machine-checks file by file; docs/CROSS_STORE_RELEASE_CHECKLIST.md
        # already says the bootstrap stub is not an ARM64 assertion.
        expected_machine = 0x8664
        if (
            machine != expected_machine
            or section_count < 1
            or section_count > 96
            or optional_size < 240
            or section_table + section_count * 40 > len(payload)
            or not characteristics & 0x0002
            or struct.unpack_from("<H", payload, optional_offset)[0] != 0x20B
        ):
            raise ValueError
        entry_point = struct.unpack_from("<I", payload, optional_offset + 16)[0]
        image_base = struct.unpack_from("<Q", payload, optional_offset + 24)[0]
        section_alignment = struct.unpack_from("<I", payload, optional_offset + 32)[0]
        file_alignment = struct.unpack_from("<I", payload, optional_offset + 36)[0]
        win32_version = struct.unpack_from("<I", payload, optional_offset + 52)[0]
        size_image = struct.unpack_from("<I", payload, optional_offset + 56)[0]
        size_headers = struct.unpack_from("<I", payload, optional_offset + 60)[0]
        loader_flags = struct.unpack_from("<I", payload, optional_offset + 104)[0]
        directory_count = struct.unpack_from("<I", payload, optional_offset + 108)[0]
        if (
            image_base % 0x10000
            or file_alignment < 512
            or file_alignment > 65536
            or file_alignment & (file_alignment - 1)
            or section_alignment < file_alignment
            or section_alignment & (section_alignment - 1)
            or win32_version != 0
            or loader_flags != 0
            or size_headers < section_table + section_count * 40
            or size_headers % file_alignment
            or size_headers > len(payload)
            or size_image < section_alignment
            or size_image % section_alignment
        ):
            raise ValueError
        raw_ranges: list[tuple[int, int]] = []
        image_ranges: list[tuple[int, int, int]] = []
        executable_entry = False
        for index in range(section_count):
            offset = section_table + index * 40
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", payload, offset + 8
            )
            section_flags = struct.unpack_from("<I", payload, offset + 36)[0]
            mapped_size = max(virtual_size, raw_size)
            if mapped_size < 1 or virtual_address % section_alignment:
                raise ValueError
            # A section with no raw bytes (.bss, .tls) is uninitialized data that only
            # exists in the mapped image; every real Inno loader carries both. It must
            # claim neither stored code (IMAGE_SCN_CNT_CODE) nor execution
            # (IMAGE_SCN_MEM_EXECUTE) and point at no file bytes.
            if raw_size:
                if (
                    raw_offset < size_headers
                    or raw_offset % file_alignment
                    or raw_offset + raw_size > len(payload)
                    or not any(payload[raw_offset : raw_offset + raw_size])
                ):
                    raise ValueError
                raw_ranges.append((raw_offset, raw_offset + raw_size))
            elif raw_offset != 0 or section_flags & 0x20000020:
                raise ValueError
            image_ranges.append((virtual_address, virtual_address + mapped_size, section_flags))
            # The entry point must lie in executable bytes the file stores, not in the
            # zero-filled tail of a section's virtual extent.
            stored_size = min(virtual_size, raw_size) if virtual_size else raw_size
            if virtual_address <= entry_point < virtual_address + stored_size and section_flags & 0x20000000:
                executable_entry = True
        if any(left[1] > right[0] for left, right in zip(sorted(raw_ranges), sorted(raw_ranges)[1:])):
            raise ValueError
        if any(left[1] > right[0] for left, right in zip(sorted(image_ranges), sorted(image_ranges)[1:])):
            raise ValueError
        if not executable_entry or b"Inno Setup" not in payload[size_headers:]:
            raise ValueError
        if target.endswith("-signed"):
            if directory_count < 5 or optional_offset + 112 + 8 * 5 > section_table:
                raise ValueError
            certificate_offset, certificate_size = struct.unpack_from(
                "<II", payload, optional_offset + 112 + 8 * 4
            )
            if (
                certificate_offset < size_headers
                or certificate_size < 8
                or certificate_offset + certificate_size > len(payload)
                or struct.unpack_from("<I", payload, certificate_offset)[0] > certificate_size
            ):
                raise ValueError
    except (struct.error, ValueError) as exc:
        raise DependencyFreezeError(f"{label} PE32+ structure is invalid.") from exc


def _require_tar_package(payload: bytes, name: str, label: str) -> None:
    if not (name.endswith(".tar") or name.endswith(".tar.gz") or name.endswith(".tgz")):
        raise DependencyFreezeError(f"{label} has no reviewed Linux package validator.")
    count = 0
    expanded = 0
    executable = False
    manifest = False
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
            for member in archive:
                count += 1
                if count > ARCHIVE_ENTRY_LIMIT:
                    raise DependencyFreezeError(f"{label} has too many members.")
                _archive_member_name(member.name, label)
                if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                    raise DependencyFreezeError(f"{label} contains an unsafe member.")
                if member.isdir():
                    continue
                if not member.isfile() or member.size < 0 or member.size > BUILD_ATTEMPT_BYTES_LIMIT:
                    raise DependencyFreezeError(f"{label} contains an invalid member.")
                expanded += member.size
                if expanded > ARCHIVE_EXPANDED_BYTES_LIMIT:
                    raise DependencyFreezeError(f"{label} expanded bytes exceed the bound.")
                source = archive.extractfile(member)
                if source is None:
                    raise DependencyFreezeError(f"{label} member is unreadable.")
                read_size = 0
                while True:
                    block = source.read(1024 * 1024)
                    if not block:
                        break
                    read_size += len(block)
                    if read_size > member.size:
                        raise DependencyFreezeError(f"{label} member grew while read.")
                if read_size != member.size:
                    raise DependencyFreezeError(f"{label} member size changed.")
                executable = executable or bool(member.mode & 0o111 and member.size >= 4096)
                base = pathlib.PurePosixPath(member.name).name.lower()
                manifest = manifest or base in {"manifest.json", "snapcraft.yaml", "metadata"}
    except (OSError, tarfile.TarError) as exc:
        raise DependencyFreezeError(f"{label} tar package is malformed.") from exc
    if count < 3 or not executable or not manifest:
        raise DependencyFreezeError(f"{label} tar package structure is incomplete.")


# The exact website tarball tools/build_linux_release.sh publishes: GNU tar
# --sort=name with numeric root ownership, gzip -n, an exhaustive
# release-manifest.sha256 written last, and ELF executables for the target.
_LINUX_RELEASE_TARBALL_ELF_MACHINES = {"linux-x64": 62, "linux-arm64": 183}
_LINUX_RELEASE_TARBALL_MANIFEST = "release-manifest.sha256"
_LINUX_RELEASE_TARBALL_REQUIRED = (
    "lib/libapp.so",
    "lib/libflutter_linux_gtk.so",
    "winn3-descriptor-ring-attestation.json",
    "winn3-dual-auth-release-attestation.json",
)
_LINUX_RELEASE_TARBALL_ELF_EXECUTABLES = (
    "wins_vpn",
    "xray",
    "amneziawg-go",
    "winn-datapath",
)
_LINUX_RELEASE_TARBALL_EXECUTABLES = _LINUX_RELEASE_TARBALL_ELF_EXECUTABLES + (
    "awg",
    "awg-quick",
    "install.sh",
)


def _require_linux_release_tarball(
    payload: bytes, target: str, name: str, label: str
) -> None:
    machine = _LINUX_RELEASE_TARBALL_ELF_MACHINES.get(target)
    if machine is None or name != f"wins-vpn-{target}.tar.gz":
        raise DependencyFreezeError(
            f"{label} is not the reviewed Linux release tarball for its target."
        )
    if len(payload) < 18 or payload[:3] != b"\x1f\x8b\x08" or payload[4:8] != b"\0\0\0\0":
        raise DependencyFreezeError(f"{label} is not a deterministic gzip stream.")
    names: list[str] = []
    digests: dict[str, str] = {}
    modes: dict[str, int] = {}
    heads: dict[str, bytes] = {}
    manifest_payload: bytes | None = None
    expanded = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            for member in archive:
                names.append(member.name)
                if len(names) > ARCHIVE_ENTRY_LIMIT:
                    raise DependencyFreezeError(f"{label} has too many members.")
                normalized = member.name.removeprefix("./")
                if normalized in {"", "."}:
                    if not member.isdir():
                        raise DependencyFreezeError(f"{label} root entry is unsafe.")
                    continue
                _archive_member_name(normalized.rstrip("/"), label)
                if member.uid != 0 or member.gid != 0:
                    raise DependencyFreezeError(
                        f"{label} member is not numerically root-owned."
                    )
                if member.isdir():
                    continue
                if (
                    not member.isfile()
                    or member.size < 0
                    or member.size > BUILD_ATTEMPT_BYTES_LIMIT
                ):
                    raise DependencyFreezeError(f"{label} contains an unsafe member.")
                if normalized in digests:
                    raise DependencyFreezeError(f"{label} repeats a member.")
                expanded += member.size
                if expanded > ARCHIVE_EXPANDED_BYTES_LIMIT:
                    raise DependencyFreezeError(f"{label} expanded bytes exceed the bound.")
                source = archive.extractfile(member)
                if source is None:
                    raise DependencyFreezeError(f"{label} member is unreadable.")
                digest = hashlib.sha256()
                head = b""
                kept = bytearray()
                read_size = 0
                while True:
                    block = source.read(1024 * 1024)
                    if not block:
                        break
                    if not head:
                        head = block[:64]
                    read_size += len(block)
                    if read_size > member.size:
                        raise DependencyFreezeError(f"{label} member grew while read.")
                    digest.update(block)
                    if normalized == _LINUX_RELEASE_TARBALL_MANIFEST:
                        if read_size > MAX_DEPENDENCY_JSON_BYTES:
                            raise DependencyFreezeError(
                                f"{label} release manifest exceeds its bound."
                            )
                        kept.extend(block)
                if read_size != member.size:
                    raise DependencyFreezeError(f"{label} member size changed.")
                digests[normalized] = digest.hexdigest()
                modes[normalized] = stat.S_IMODE(member.mode)
                heads[normalized] = head
                if normalized == _LINUX_RELEASE_TARBALL_MANIFEST:
                    manifest_payload = bytes(kept)
    except (OSError, EOFError, zlib.error, tarfile.TarError) as exc:
        raise DependencyFreezeError(f"{label} tar package is malformed.") from exc
    if names != sorted(names):
        raise DependencyFreezeError(f"{label} members are not in reviewed sorted order.")
    if manifest_payload is None:
        raise DependencyFreezeError(f"{label} omits {_LINUX_RELEASE_TARBALL_MANIFEST}.")
    try:
        manifest_text = manifest_payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DependencyFreezeError(f"{label} release manifest is not ASCII.") from exc
    recorded: dict[str, str] = {}
    for line in manifest_text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\x00\r\n]+)", line)
        if match is None:
            raise DependencyFreezeError(f"{label} release manifest record is malformed.")
        digest_text, relative = match.groups()
        if relative in recorded or relative == _LINUX_RELEASE_TARBALL_MANIFEST:
            raise DependencyFreezeError(f"{label} release manifest record is unsafe.")
        recorded[relative] = digest_text
    payload_digests = {
        path: value
        for path, value in digests.items()
        if path != _LINUX_RELEASE_TARBALL_MANIFEST
    }
    if recorded != payload_digests:
        raise DependencyFreezeError(
            f"{label} release manifest is not exhaustive and exact."
        )
    for required in _LINUX_RELEASE_TARBALL_REQUIRED + _LINUX_RELEASE_TARBALL_EXECUTABLES:
        if required not in digests:
            raise DependencyFreezeError(f"{label} omits required member {required}.")
    for executable in _LINUX_RELEASE_TARBALL_EXECUTABLES:
        if modes[executable] != 0o755:
            raise DependencyFreezeError(f"{label} member {executable} is not 0755.")
    for executable in _LINUX_RELEASE_TARBALL_ELF_EXECUTABLES:
        head = heads[executable]
        if (
            len(head) < 20
            or head[:4] != b"\x7fELF"
            or head[4] != 2
            or head[5] != 1
            or struct.unpack_from("<H", head, 18)[0] != machine
        ):
            raise DependencyFreezeError(
                f"{label} member {executable} is not a 64-bit ELF for {target}."
            )


def _remote_attested_build_producer(platform: str, remote_host: str) -> str:
    """Return the only remote producer accepted for ``platform`` on ``remote_host``."""

    producer = REMOTE_ATTESTED_PLATFORM_HOSTS.get((platform, remote_host))
    if producer is None:
        raise DependencyFreezeError(
            f"{platform} has no remote-attested producer on {remote_host}."
        )
    return producer


def _windows_scan_keys(record: object) -> set[str]:
    """The top-level scan binding a record carries, when it carries one.

    A remote-attested Windows receipt binds the worker's scan inside its remote
    block and its claim. Any other Windows receipt binds it at the top level, so no
    form of Windows receipt exists without one. Which receipts may carry the key,
    and that a Windows one must, is decided after the schema check, from the
    platform this call was asked to verify."""

    if type(record) is dict and "release_host_secret_scan" in record:
        return {"release_host_secret_scan"}
    return set()


def _remote_attestation_keys(record: object) -> set[str]:
    """Return the optional remote-attestation key a begin or build record carries."""

    if type(record) is dict and "remote_attestation" in record:
        return {"remote_attestation"}
    return set()


def _remote_source_listing(
    repo: pathlib.Path, revision: str
) -> tuple[str, int, list[tuple[str, str, str]]]:
    """Return (object format, commit time, sorted (path, mode, oid)) at ``revision``."""

    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision):
        raise DependencyFreezeError("Remote source revision must be a full commit id.")
    object_format = _run_git(repo, "rev-parse", "--show-object-format").decode(
        "ascii", "replace"
    ).strip()
    commit_time = _run_git(repo, "show", "-s", "--format=%ct", revision).strip()
    if not re.fullmatch(rb"[1-9][0-9]{0,11}", commit_time):
        raise DependencyFreezeError("Remote source revision time is invalid.")
    entries: list[tuple[str, str, str]] = []
    for raw in _run_git(repo, "ls-tree", "-r", "-z", "--full-tree", revision).split(b"\0"):
        if not raw:
            continue
        meta, separator, raw_path = raw.partition(b"\t")
        fields = meta.decode("ascii", "replace").split(" ")
        if not separator or len(fields) != 3:
            raise DependencyFreezeError("Remote source listing is malformed.")
        mode, kind, oid = fields
        try:
            path = raw_path.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DependencyFreezeError("Remote source path is not UTF-8.") from exc
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            raise DependencyFreezeError(
                f"Remote source tree holds an unsupported entry: {path}"
            )
        entries.append((_archive_member_name(path, "Remote source tree"), mode, oid))
    if not entries:
        raise DependencyFreezeError("Remote source tree is empty.")
    return object_format, int(commit_time), sorted(entries, key=lambda item: item[0].encode("utf-8"))


class _RemoteSourceArchiveWriter:
    """Write-through file object that hashes and counts the bytes tarfile emits."""

    def __init__(self, raw: io.BufferedWriter) -> None:
        self._raw = raw
        self.digest = hashlib.sha256()
        self.size = 0

    def write(self, data: bytes) -> int:
        block = bytes(data)
        self._raw.write(block)
        self.digest.update(block)
        self.size += len(block)
        return len(block)

    def tell(self) -> int:
        return self.size

    def flush(self) -> None:
        self._raw.flush()


def _write_remote_source_archive(
    repo: pathlib.Path, output: pathlib.Path, revision: str
) -> tuple[dict[str, object], dict[str, tuple[str, int]]]:
    """Write the deterministic tar of every tracked file of ``revision``.

    Each worktree member must hash to its Git blob at the frozen revision, so
    the tar carries exactly the frozen bytes whatever the checkout holds.
    Returns the archive record and a path -> (sha256, size) map of regular files.
    """

    owners = _allowed_owners(repo)
    object_format, commit_time, listing = _remote_source_listing(repo, revision)
    files: dict[str, tuple[str, int]] = {}
    listing_digest = hashlib.sha256()
    descriptor = os.open(
        output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _nofollow_flags(), 0o600
    )
    with os.fdopen(descriptor, "wb") as raw:
        writer = _RemoteSourceArchiveWriter(raw)
        with tarfile.open(fileobj=writer, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for path, mode, oid in listing:
                member = tarfile.TarInfo(path)
                member.uid = member.gid = 0
                member.uname = member.gname = ""
                member.mtime = commit_time
                if mode == "120000":
                    entry = os.lstat(repo / path)
                    if not stat.S_ISLNK(entry.st_mode):
                        raise DependencyFreezeError(
                            f"Remote source member is not the frozen symbolic link: {path}"
                        )
                    target = os.readlink(repo / path)
                    resolved = pathlib.PurePosixPath(
                        os.path.normpath(
                            str(pathlib.PurePosixPath(path).parent / target)
                        )
                    )
                    if (
                        pathlib.PurePosixPath(target).is_absolute()
                        or resolved.is_absolute()
                        or resolved.parts[:1] == ("..",)
                    ):
                        raise DependencyFreezeError(
                            f"Remote source symbolic link escapes the tree: {path}"
                        )
                    payload = os.fsencode(target)
                    member.type = tarfile.SYMTYPE
                    member.linkname = target
                    member.mode = 0o777
                else:
                    payload, _identity, _info = _stable_read_regular_file(
                        repo / path, owners, label="Remote source file", repo=repo
                    )
                    member.size = len(payload)
                    member.mode = 0o755 if mode == "100755" else 0o644
                if _git_blob_oid(payload, object_format) != oid:
                    raise DependencyFreezeError(
                        f"Remote source member differs from the frozen revision: {path}"
                    )
                if mode == "120000":
                    archive.addfile(member)
                else:
                    archive.addfile(member, io.BytesIO(payload))
                    files[path] = (hashlib.sha256(payload).hexdigest(), len(payload))
                listing_digest.update(f"{mode} {oid} {path}\n".encode("utf-8"))
        raw.flush()
        os.fsync(raw.fileno())
    record: dict[str, object] = {
        "contract": REMOTE_SOURCE_ARCHIVE_CONTRACT,
        "path": _relative_repo_path(repo, output),
        "sha256": writer.digest.hexdigest(),
        "size_bytes": writer.size,
        "revision": revision,
        "object_format": object_format,
        "file_count": len(listing),
        "listing_sha256": listing_digest.hexdigest(),
        "mtime": commit_time,
    }
    return record, files


def _stream_sha256(path: pathlib.Path, label: str) -> tuple[str, int]:
    descriptor = os.open(path, _nofollow_flags())
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise DependencyFreezeError(f"{label} is not a single-link regular file.")
        digest = hashlib.sha256()
        size = 0
        while True:
            block = os.read(descriptor, 4 * 1024 * 1024)
            if not block:
                break
            digest.update(block)
            size += len(block)
        if size != info.st_size:
            raise DependencyFreezeError(f"{label} changed while it was hashed.")
        return digest.hexdigest(), size
    finally:
        os.close(descriptor)


def prepare_remote_attested_begin(
    repo: pathlib.Path,
    index_path: pathlib.Path,
    platform: str,
    remote_host: str,
    source_archive: pathlib.Path,
) -> dict[str, object]:
    """Ship-side half of a remote begin: write and check the frozen source tar.

    Every shared, native and producer manifest file of ``platform`` must be in
    the tar with its manifest SHA-256 and size, so the remote host receives the
    exact bytes the release index verified on this Mac.
    """

    repo = secure_repo_path(repo, pathlib.Path("."), "Repository root", must_exist=True)
    if platform not in PLATFORM_ROOTS:
        raise DependencyFreezeError(f"Unsupported platform: {platform}")
    _require_build_witness_boundary(repo, platform)
    if _native_process_host() != REMOTE_ATTESTATION_ORCHESTRATOR_HOST:
        raise DependencyFreezeError(
            "Remote-attested builds are orchestrated only from the macOS release host."
        )
    producer = _remote_attested_build_producer(platform, remote_host)
    index_path = secure_repo_path(
        repo, index_path, "Release input index", must_exist=True
    )
    verified = verify_release_index(repo, index_path, platform)
    output = _require_artifacts_output(
        repo, source_archive, "Remote source archive", allow_missing_leaf=True
    )
    if not REMOTE_SOURCE_ARCHIVE_NAME.fullmatch(output.name):
        raise DependencyFreezeError("Remote source archive name is unsafe.")
    if output.exists() or output.is_symlink():
        raise DependencyFreezeError("Remote source archive must be a new path.")
    owners = _allowed_owners(repo)
    try:
        archive, files = _write_remote_source_archive(
            repo, output, _require_str(verified.get("shared_revision"), "Shared revision")
        )
        index, _index_digest = _read_json_file(
            index_path, owners, "Release input index", repo=repo
        )
        shared_reference = _require_exact_keys(
            index.get("shared_manifest"), {"path", "sha256"}, "Shared manifest reference"
        )
        platform_reference = _require_exact_keys(
            index.get("platform_manifests").get(platform)
            if type(index.get("platform_manifests")) is dict
            else None,
            {"path", "sha256", "artifact_input_fingerprint_sha256"},
            f"{platform} platform manifest",
        )
        checked: list[object] = []
        for reference, sections in (
            (shared_reference, ("inputs",)),
            (platform_reference, ("native_inputs", "producer_inputs")),
        ):
            manifest_path = secure_repo_path(
                repo,
                index_path.parent / _require_str(reference.get("path"), "Manifest path"),
                "Release manifest",
                must_exist=True,
            )
            manifest, manifest_digest = _read_json_file(
                manifest_path, owners, "Release manifest", repo=repo
            )
            if manifest_digest != reference.get("sha256"):
                raise DependencyFreezeError("Release manifest changed after verification.")
            for section in sections:
                block = manifest.get(section)
                entries = block.get("files") if type(block) is dict else None
                for entry in _require_list(entries, f"{section} files"):
                    record = _require_exact_keys(
                        entry, {"path", "sha256", "size"}, "Manifest file"
                    )
                    relative = _require_str(record.get("path"), "Manifest file path")
                    if files.get(relative) != (
                        _require_sha256(record.get("sha256"), "Manifest file digest"),
                        _require_int(record.get("size"), "Manifest file size"),
                    ):
                        raise DependencyFreezeError(
                            "Remote source archive does not carry the frozen bytes "
                            f"of {relative}."
                        )
                    checked.append(relative)
        if producer not in files:
            raise DependencyFreezeError("Remote producer is not in the source archive.")
    except BaseException:
        try:
            os.unlink(output)
        except FileNotFoundError:
            pass
        raise
    return {
        "contract": REMOTE_ATTESTATION_CONTRACT,
        "orchestrator_host": REMOTE_ATTESTATION_ORCHESTRATOR_HOST,
        "remote_host": remote_host,
        "producer": {"path": producer, "sha256": files[producer][0]},
        "source_archive": archive,
        "manifest_files_checked": len(checked),
    }


def _require_remote_attestation_block(value: object, platform: str) -> dict[str, object]:
    block = _require_exact_keys(
        value,
        {
            "contract",
            "orchestrator_host",
            "remote_host",
            "producer",
            "source_archive",
            "manifest_files_checked",
        },
        "Remote attestation",
    )
    remote_host = _require_str(block.get("remote_host"), "Remote host")
    producer = _require_exact_keys(
        block.get("producer"), {"path", "sha256"}, "Remote producer"
    )
    archive = _require_exact_keys(
        block.get("source_archive"),
        {
            "contract",
            "path",
            "sha256",
            "size_bytes",
            "revision",
            "object_format",
            "file_count",
            "listing_sha256",
            "mtime",
        },
        "Remote source archive",
    )
    if (
        block.get("contract") != REMOTE_ATTESTATION_CONTRACT
        or block.get("orchestrator_host") != REMOTE_ATTESTATION_ORCHESTRATOR_HOST
        or producer.get("path") != _remote_attested_build_producer(platform, remote_host)
        or archive.get("contract") != REMOTE_SOURCE_ARCHIVE_CONTRACT
        or _require_int(block.get("manifest_files_checked"), "Checked files") < 1
        or _require_int(archive.get("size_bytes"), "Source archive size") < 1
        or _require_int(archive.get("file_count"), "Source file count") < 1
    ):
        raise DependencyFreezeError("Remote attestation binding is invalid.")
    _require_sha256(producer.get("sha256"), "Remote producer digest")
    _require_sha256(archive.get("sha256"), "Source archive digest")
    _require_sha256(archive.get("listing_sha256"), "Source listing digest")
    relative = pathlib.PurePosixPath(_require_str(archive.get("path"), "Source archive path"))
    if relative.parts[:1] != (".artifacts",) or ".." in relative.parts:
        raise DependencyFreezeError("Remote source archive must stay under .artifacts/.")
    return block


def _release_host_secret_scan_target(artifact_name: object, toolchain: object) -> str:
    """The scan target for one canonical installer name, architecture checked."""

    target = toolchain.get("target") if isinstance(toolchain, dict) else None
    matched = re.fullmatch(r"windows-(x64|arm64)-inno-[a-z-]+", target) if isinstance(target, str) else None
    target_id = (
        RELEASE_HOST_SECRET_SCAN_TARGETS.get(artifact_name.casefold())
        if isinstance(artifact_name, str)
        else None
    )
    if matched is None or target_id not in {
        f"windows-{matched.group(1)}-installer",
        f"windows-{matched.group(1)}-partner-center",
    }:
        raise DependencyFreezeError(
            "The installer name does not match its architecture and release surface."
        )
    return target_id


def _release_host_secret_scan_required(
    platform: str, artifact_name: str, payload: bytes | None = None
) -> bool:
    """Decide whether the worker's own secret scan applies, from facts it holds.

    The answer comes from the platform this process was asked to finish or verify
    and from the installer it holds (its canonical file name, or an ``.exe`` that
    starts like a PE image), never from a field the receipt declares about itself:
    ``producer.execution``, ``producer.host``, the toolchain target and the presence
    of a remote-attestation block can all be rewritten to agree with each other, so
    none of them may switch the scan off. Every Windows installer is scanned, in
    whatever form its receipt claims to have been built. A Windows installer
    presented as another platform's artifact is refused, not skipped."""

    held_installer = artifact_name.casefold() in RELEASE_HOST_SECRET_SCAN_TARGETS or (
        payload is not None and payload[:2] == b"MZ" and artifact_name.casefold().endswith(".exe")
    )
    if platform == "windows":
        return True
    if held_installer:
        raise DependencyFreezeError(
            "A Windows installer is accepted only as a Windows receipt, with the "
            "worker's own secret scan."
        )
    return False


def _require_release_host_secret_scan(
    value: object,
    platform: str,
    toolchain: object,
    artifact: dict[str, object],
) -> dict[str, object]:
    """Require the secret scan identity a remote Windows receipt carries.

    A Windows build host cannot load the authenticated secret inventory, so the
    authenticated worker scans the copied-back installer on the macOS release
    host (_run_release_host_secret_scan) and binds the result into its claim.
    finish-build makes the record and verify-receipt re-derives every field a
    verifier can: the target from the installer name, the artifact from the
    receipt, the scanner closure from this worker's pinned table, the verdict.
    """

    scan = _require_exact_keys(
        value,
        {
            "contract",
            "platform",
            "target_id",
            "artifact",
            "scanner",
            "inventory",
            "result",
            "matched_labels",
            "scanned_utc",
        },
        "Release-host secret scan",
    )
    scanner = _require_exact_keys(
        scan.get("scanner"), {"path", "sha256", "closure"}, "Release-host secret scanner"
    )
    inventory = _require_exact_keys(
        scan.get("inventory"),
        {"revision", "label_count", "unique_value_count", "sha256"},
        "Release-host secret inventory",
    )
    if (
        platform != "windows"
        or scan.get("contract") != RELEASE_HOST_SECRET_SCAN_CONTRACT
        or scan.get("platform") != platform
        or scan.get("target_id")
        != _release_host_secret_scan_target(artifact.get("name"), toolchain)
        or scan.get("artifact")
        != {
            "name": artifact.get("name"),
            "size_bytes": artifact.get("size_bytes"),
            "sha256": artifact.get("sha256"),
        }
        or scanner.get("path") != RELEASE_HOST_SECRET_SCANNER
        or scanner.get("closure") != RELEASE_HOST_SECRET_SCANNER_CLOSURE
        or scanner.get("sha256") != RELEASE_HOST_SECRET_SCANNER_CLOSURE[RELEASE_HOST_SECRET_SCANNER]
        or scan.get("result") != "pass"
        or scan.get("matched_labels") != []
    ):
        raise DependencyFreezeError(
            "Release-host secret scan is invalid, failed, or does not bind the artifact."
        )
    _require_sha256(inventory.get("sha256"), "Release-host secret inventory digest")
    revision = _require_str(inventory.get("revision"), "Release-host inventory revision")
    if (
        len(revision) > 128
        or _require_int(inventory.get("label_count"), "Release-host inventory labels") < 1
        or _require_int(inventory.get("unique_value_count"), "Release-host inventory values") < 1
    ):
        raise DependencyFreezeError("Release-host secret scan inventory summary is invalid.")
    scanned = _parse_timestamp(scan.get("scanned_utc"), "Release-host secret scan")
    if scanned > dt.datetime.now(tz=dt.timezone.utc) + dt.timedelta(minutes=5):
        raise DependencyFreezeError("Release-host secret scan is dated in the future.")
    return scan


def _require_release_host_secret_scan_binding(
    value: object,
    platform: str,
    toolchain: object,
    artifact: dict[str, object],
) -> dict[str, object]:
    """Require {record, sha256}: the scan record and the digest of its canonical form."""

    binding = _require_exact_keys(
        value, {"record", "sha256"}, "Release-host secret scan binding"
    )
    scan = _require_release_host_secret_scan(
        binding.get("record"), platform, toolchain, artifact
    )
    if _require_sha256(binding.get("sha256"), "Release-host secret scan digest") != (
        hashlib.sha256(_canonical_json(scan)).hexdigest()
    ):
        raise DependencyFreezeError("Release-host secret scan digest changed.")
    return binding


def _require_release_host_secret_scan_rerun(
    fresh: dict[str, object], bound: object
) -> None:
    """Require a scan this process just ran to be the scan the receipt binds.

    Every field but the time is compared, so a receipt scanned under a different
    inventory, scanner closure, target or artifact is refused, and so is a receipt
    whose own record was rewritten to say something else. The record is parsed by
    the same validator the receipt is, so the comparison is against a well-formed one.
    """

    binding = _require_exact_keys(
        bound, {"record", "sha256"}, "Release-host secret scan binding"
    )
    record = binding.get("record")
    if type(record) is not dict or type(fresh) is not dict:
        raise DependencyFreezeError("Release-host secret scan binding is malformed.")
    fresh_inventory = fresh.get("inventory")
    bound_inventory = record.get("inventory")
    if type(bound_inventory) is dict and type(fresh_inventory) is dict:
        if bound_inventory.get("sha256") != fresh_inventory.get("sha256"):
            raise DependencyFreezeError(
                "The secret inventory supplied for verification is not the inventory "
                "the receipt's scan was made with."
            )
    comparable = {key: value for key, value in fresh.items() if key != "scanned_utc"}
    recorded = {key: value for key, value in record.items() if key != "scanned_utc"}
    if comparable != recorded:
        raise DependencyFreezeError(
            "The exact secret scan run for verification does not match the scan the "
            "receipt binds."
        )


def _run_release_host_secret_scan(
    repo: pathlib.Path,
    artifact_path: pathlib.Path,
    artifact: dict[str, object],
    toolchain: object,
    inventory_path: object,
    owners: frozenset[int],
) -> dict[str, object]:
    """Run the exact secret scan on the artifact the worker holds, in this worker.

    The scanner closure is held by descriptor, compared with this worker's pinned
    digests, and executed from those held bytes in a child that has no other
    import path. The inventory reaches the scanner as a path in its environment
    only, which is how every other authenticated gate receives it; the scanner's
    own loader authenticates it. The scan passes only if the scanner exits 0 with
    a PASS report whose artifact identity is the digest of the bytes this worker
    holds, whose target is the installer's exact target and whose match list is
    empty. No scan record is ever read from the caller.
    """

    import binascii  # Already loaded by zipfile and plistlib; no new module.

    target_id = _release_host_secret_scan_target(artifact.get("name"), toolchain)
    if (
        type(inventory_path) is not str
        or not 0 < len(inventory_path) <= RELEASE_HOST_SECRET_INVENTORY_PATH_LIMIT
        or "\0" in inventory_path
        or not inventory_path.startswith("/")
        or os.path.normpath(inventory_path) != inventory_path
    ):
        raise DependencyFreezeError(
            "The secret scan needs the authenticated inventory named by an absolute normalized path."
        )
    held: list[_HeldRegularFile] = []
    try:
        files: dict[str, str] = {}
        for relative, expected in RELEASE_HOST_SECRET_SCANNER_CLOSURE.items():
            member = _hold_repo_regular_file(
                repo, repo / relative, owners, label="Release-host secret scanner"
            )
            held.append(member)
            if (
                len(member.payload) > RELEASE_HOST_SECRET_SCANNER_BYTES_LIMIT
                or hashlib.sha256(member.payload).hexdigest() != expected
            ):
                raise DependencyFreezeError(
                    "Release-host secret scanner is not the frozen one."
                )
            files[relative] = binascii.b2a_base64(member.payload, newline=False).decode("ascii")
        bundle = json.dumps(
            {
                "repo": str(repo),
                "entrypoint": RELEASE_HOST_SECRET_SCANNER,
                "order": list(RELEASE_HOST_SECRET_SCANNER_CLOSURE),
                "files": files,
                "digests": RELEASE_HOST_SECRET_SCANNER_CLOSURE,
                "arguments": [
                    "--artifacts", "--target", target_id, "--artifact", str(artifact_path),
                ],
            }
        ).encode("utf-8")
        environment = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/private/tmp",
            "LANG": "C",
            "LC_ALL": "C",
            "TMPDIR": "/private/tmp",
            "PYTHONDONTWRITEBYTECODE": "1",
            "WINS_RELEASE_SECRET_INVENTORY": inventory_path,
        }
        try:
            completed = subprocess.run(
                [sys.executable, "-I", "-S", "-B", "-c", _RELEASE_HOST_SECRET_SCAN_BOOTSTRAP],
                input=bundle,
                capture_output=True,
                env=environment,
                cwd=str(repo),
                timeout=RELEASE_HOST_SECRET_SCAN_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise DependencyFreezeError(
                f"The release-host secret scan could not run: {type(exc).__name__}"
            ) from exc
        for member in held:
            _rebind_held_regular_file(member)
    finally:
        for member in reversed(held):
            _close_held_regular_file(member)
    stdout = completed.stdout.decode("utf-8", errors="replace")
    report = RELEASE_HOST_SECRET_SCAN_REPORT.fullmatch(stdout.strip() + "\n")
    if completed.returncode != 0 or report is None:
        # The scanner redacts by design; show its verdict line and first error line only,
        # and never the inventory path.
        lines = stdout.strip().splitlines()[:1] + (
            completed.stderr.decode("utf-8", errors="replace").strip().splitlines()[:1]
        )
        detail = " ".join(lines).replace(inventory_path, "(inventory)")[:240]
        raise DependencyFreezeError(
            f"The release-host secret scan refused the installer (exit {completed.returncode}): {detail}"
        )
    if (
        report["target"] != target_id
        or report["artifact"] != artifact.get("sha256")
        or int(report["labels"]) < 1
        or int(report["values"]) < 1
    ):
        raise DependencyFreezeError(
            "The release-host secret scan did not cover this installer and target."
        )
    return {
        "contract": RELEASE_HOST_SECRET_SCAN_CONTRACT,
        "platform": "windows",
        "target_id": target_id,
        "artifact": {
            "name": artifact.get("name"),
            "size_bytes": artifact.get("size_bytes"),
            "sha256": artifact.get("sha256"),
        },
        "scanner": {
            "path": RELEASE_HOST_SECRET_SCANNER,
            "sha256": RELEASE_HOST_SECRET_SCANNER_CLOSURE[RELEASE_HOST_SECRET_SCANNER],
            "closure": dict(RELEASE_HOST_SECRET_SCANNER_CLOSURE),
        },
        "inventory": {
            "revision": report["revision"],
            "label_count": int(report["labels"]),
            "unique_value_count": int(report["values"]),
            "sha256": report["inventory"],
        },
        "result": "pass",
        "matched_labels": [],
        "scanned_utc": _utc_now(),
    }


def _remote_attested_finish_identity(
    platform: str,
    remote_host: str | None,
    remote_run_record: pathlib.Path | None,
    begin: dict[str, object],
) -> tuple[str, str, str]:
    """Return (host, producer, execution) for a remote-attested finish-build."""

    if _native_process_host() != REMOTE_ATTESTATION_ORCHESTRATOR_HOST:
        raise DependencyFreezeError(
            "Remote-attested receipts are finished only on the macOS release host."
        )
    if remote_host is None or remote_run_record is None or "remote_attestation" not in begin:
        raise DependencyFreezeError(
            "A remote-attested receipt needs the remote host, the remote run "
            "record and a remote begin record."
        )
    block = _require_remote_attestation_block(begin.get("remote_attestation"), platform)
    if block.get("remote_host") != remote_host:
        raise DependencyFreezeError("Remote host differs from the begin record.")
    return (
        remote_host,
        _remote_attested_build_producer(platform, remote_host),
        PRODUCER_EXECUTION_REMOTE_ATTESTED,
    )


def _require_remote_run_record(
    repo: pathlib.Path,
    platform: str,
    begin: dict[str, object],
    begin_sha: str,
    run_record_path: pathlib.Path,
    artifact: dict[str, object],
    producer_record: dict[str, object],
    toolchain: dict[str, object],
    owners: frozenset[int],
) -> dict[str, object]:
    """Bind the remote producer's run record and the shipped tar to the begin record."""

    block = _require_remote_attestation_block(begin.get("remote_attestation"), platform)
    if block["producer"] != {
        "path": producer_record.get("path"),
        "sha256": producer_record.get("sha256"),
    }:
        raise DependencyFreezeError(
            "Remote producer bytes differ from the producer the begin record shipped."
        )
    archive = block["source_archive"]
    archive_path = secure_repo_path(
        repo, pathlib.Path(archive["path"]), "Remote source archive", must_exist=True
    )
    if _stream_sha256(archive_path, "Remote source archive") != (
        archive["sha256"],
        archive["size_bytes"],
    ):
        raise DependencyFreezeError(
            "Remote source archive no longer matches its begin record."
        )
    run_record_path = secure_repo_path(
        repo, run_record_path, "Remote run record", must_exist=True
    )
    if run_record_path.relative_to(repo).parts[0] != ".artifacts":
        raise DependencyFreezeError("Remote run record must stay under .artifacts/.")
    record, record_digest = _read_json_file(
        run_record_path, owners, "Remote run record", repo=repo
    )
    _require_remote_run_record_fields(
        record, platform, begin, begin_sha, block, toolchain, artifact
    )
    return {
        "begin": block,
        "run_record": {
            "path": _relative_repo_path(repo, run_record_path),
            "sha256": record_digest,
            "record": record,
        },
    }


def _require_remote_run_record_fields(
    record: object,
    platform: str,
    begin: dict[str, object],
    begin_sha: str,
    block: dict[str, object],
    toolchain: object,
    artifact: object,
) -> None:
    """Require a remote run record to match its begin record and artifact.

    finish-build applies this to REMOTE_RUN.json as read, and verify-receipt
    applies it again to the copy the receipt embeds, so a receipt cannot
    carry a run record that finish-build would have refused.
    """

    _require_exact_keys(
        record,
        {
            "contract",
            "release",
            "platform",
            "remote_host",
            "build_begin_sha256",
            "source_archive_sha256",
            "release_input_index_sha256",
            "platform_manifest_sha256",
            "producer",
            "toolchain",
            "artifact",
            "signing",
            "remote_system",
            "finished_utc",
        }
        | ({"secret_scan"} if platform == "windows" else set()),
        "Remote run record",
    )
    # A Windows build host cannot load the authenticated secret inventory, so its
    # run record must say finish-build on the release host runs the exact scan.
    if platform == "windows" and record.get("secret_scan") != REMOTE_SECRET_SCAN_DEFERRED:
        raise DependencyFreezeError(
            "Windows remote run record must defer its secret scan to the release host."
        )
    # "orchestrator": the remote producer stopped before signing and the macOS
    # release host signs the copied-back artifact (Linux cosign); "unsigned":
    # an unsigned rehearsal; "producer": the remote producer signed (Windows
    # Authenticode). A remote Linux host never holds the signing key.
    if record.get("signing") not in {"unsigned", "producer", "orchestrator"} or (
        platform == "linux" and record.get("signing") == "producer"
    ):
        raise DependencyFreezeError("Remote run record signing mode is not reviewed.")
    expected = {
        "contract": REMOTE_RUN_RECORD_CONTRACT,
        "release": begin.get("release"),
        "platform": platform,
        "remote_host": block["remote_host"],
        "build_begin_sha256": begin_sha,
        "source_archive_sha256": block["source_archive"]["sha256"],
        "release_input_index_sha256": begin["release_input_index"]["sha256"],
        "platform_manifest_sha256": begin["platform_manifest"]["sha256"],
        "producer": block["producer"],
        "toolchain": toolchain,
        "artifact": artifact,
    }
    for key, value in expected.items():
        if record.get(key) != value:
            raise DependencyFreezeError(
                f"Remote run record {key} does not match the begin record or the "
                "copied-back artifact."
            )
    system = _require_exact_keys(
        record.get("remote_system"), {"system", "machine"}, "Remote system"
    )
    _require_str(system.get("system"), "Remote system")
    _require_str(system.get("machine"), "Remote machine")
    finished = _parse_timestamp(record.get("finished_utc"), "Remote run finished")
    if finished > dt.datetime.now(tz=dt.timezone.utc) + dt.timedelta(minutes=5):
        raise DependencyFreezeError("Remote run record is dated in the future.")


def _verify_remote_attested_receipt(
    platform: str,
    record: dict[str, object],
    begin_record: dict[str, object],
    begin_sha: str,
) -> bool:
    """Return whether a build receipt is remote-attested, refusing partial bindings."""

    producer = record.get("producer") if type(record.get("producer")) is dict else {}
    remote = producer.get("execution") == PRODUCER_EXECUTION_REMOTE_ATTESTED
    if remote != ("remote_attestation" in record) or remote != (
        "remote_attestation" in begin_record
    ):
        raise DependencyFreezeError("Remote attestation binding is incomplete.")
    if not remote:
        return False
    block = _require_remote_attestation_block(
        begin_record.get("remote_attestation"), platform
    )
    binding = _require_exact_keys(
        record.get("remote_attestation"),
        {"begin", "run_record"}
        | ({"release_host_secret_scan"} if platform == "windows" else set()),
        "Remote binding",
    )
    run = _require_exact_keys(
        binding.get("run_record"), {"path", "sha256", "record"}, "Remote run binding"
    )
    run_record = run.get("record") if type(run.get("record")) is dict else {}
    artifact = record.get("artifact") if type(record.get("artifact")) is dict else {}
    _require_sha256(run.get("sha256"), "Remote run record digest")
    if (
        binding.get("begin") != block
        or producer.get("host") != block.get("remote_host")
        or run_record.get("contract") != REMOTE_RUN_RECORD_CONTRACT
        or run_record.get("platform") != platform
        or run_record.get("remote_host") != block.get("remote_host")
        or run_record.get("build_begin_sha256") != begin_sha
        or run_record.get("source_archive_sha256")
        != block["source_archive"].get("sha256")
        or run_record.get("producer") != block.get("producer")
        or {"path": producer.get("path"), "sha256": producer.get("sha256")}
        != block.get("producer")
        or run_record.get("toolchain") != record.get("toolchain")
        or run_record.get("artifact")
        != {
            "name": artifact.get("name"),
            "size_bytes": artifact.get("size_bytes"),
            "sha256": artifact.get("sha256"),
        }
    ):
        raise DependencyFreezeError("Remote attestation binding is invalid or changed.")
    _require_remote_run_record_fields(
        run.get("record"),
        platform,
        begin_record,
        begin_sha,
        block,
        record.get("toolchain"),
        {
            "name": artifact.get("name"),
            "size_bytes": artifact.get("size_bytes"),
            "sha256": artifact.get("sha256"),
        },
    )
    if platform == "windows":
        _require_release_host_secret_scan_binding(
            binding.get("release_host_secret_scan"),
            platform,
            record.get("toolchain"),
            {
                "name": artifact.get("name"),
                "size_bytes": artifact.get("size_bytes"),
                "sha256": artifact.get("sha256"),
            },
        )
    return True


def _require_xar_pkg(payload: bytes, label: str) -> None:
    if len(payload) < 64 or payload[:4] != b"xar!":
        raise DependencyFreezeError(f"{label} is not a complete XAR package.")
    try:
        header_size, version = struct.unpack_from(">HH", payload, 4)
        compressed_size, uncompressed_size = struct.unpack_from(">QQ", payload, 8)
        checksum = struct.unpack_from(">I", payload, 24)[0]
        if (
            header_size < 28
            or version != 1
            or compressed_size < 1
            or uncompressed_size < 1
            or uncompressed_size > ARCHIVE_METADATA_BYTES_LIMIT
            or checksum not in {0, 1, 2, 3}
            or header_size + compressed_size >= len(payload)
        ):
            raise ValueError
        inflater = zlib.decompressobj()
        toc = inflater.decompress(
            payload[header_size : header_size + compressed_size],
            ARCHIVE_METADATA_BYTES_LIMIT + 1,
        )
        if len(toc) > ARCHIVE_METADATA_BYTES_LIMIT or inflater.unconsumed_tail:
            raise ValueError
        toc += inflater.flush(ARCHIVE_METADATA_BYTES_LIMIT - len(toc) + 1)
        if (
            len(toc) != uncompressed_size
            or len(toc) > ARCHIVE_METADATA_BYTES_LIMIT
            or not inflater.eof
            or inflater.unused_data
        ):
            raise ValueError
        root = etree.fromstring(toc)
        files = root.findall(".//file")
        signatures = root.findall(".//signature")
        if root.tag != "xar" or not files or not signatures or not any(
            node.find("X509Certificate") is not None for node in signatures
        ):
            raise ValueError
    except (struct.error, zlib.error, etree.ParseError, ValueError) as exc:
        raise DependencyFreezeError(f"{label} XAR package structure is invalid.") from exc


# Apple release artifacts (round R11a). These validators replace the
# structural _require_ipa/_require_xar_pkg checks above, which Astra CE-04
# showed accepting placeholders. Without executing any tool they verify:
# every Mach-O slice's code pages against every CodeDirectory; the special
# slots that bind Info.plist, CodeResources, requirements and entitlements;
# the CMS signature over the primary CodeDirectory; the CodeResources seal
# over every bundle file and every nested code bundle; the XAR TOC checksum,
# every heap extent and archived checksum, and the RSA signature over the TOC
# checksum. Each signature must chain, by RSA signatures, to the pinned Apple
# Root CA, every issuer on the chain must be a certification authority
# (basicConstraints cA, pathLenConstraint, keyUsage keyCertSign), and the leaf
# must carry the release team and the role's common-name prefix. Not checked
# here: certificate validity dates, revocation, extended key usage,
# provisioning-profile CMS, and files that the CodeResources rules omit
# (Info.plist is bound by special slot 1; PkgInfo is omitted).
APPLE_ROOT_CA_SHA256 = "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"
APPLE_RELEASE_TEAM_IDENTIFIER = "5YT8H4U72M"
APPLE_IPA_SIGNER_PREFIXES = ("Apple Distribution: ", "iPhone Distribution: ")
APPLE_PKG_SIGNER_PREFIXES = (
    "3rd Party Mac Developer Installer: ",
    "Mac Installer Distribution: ",
)
APPLE_SIGNED_EXECUTABLE_BYTES_LIMIT = 1024 * 1024 * 1024
APPLE_BUNDLE_NESTING_LIMIT = 6
_APPLE_CODE_HASH_TYPES = {1: ("sha1", 20), 2: ("sha256", 32), 3: ("sha256", 20), 4: ("sha384", 48)}
_APPLE_RSA_SIGNATURE_DIGESTS = {
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
}
_APPLE_CMS_DIGESTS = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}
_APPLE_DIGEST_INFO_OIDS = {
    "sha1": bytes.fromhex("2b0e03021a"),
    "sha256": bytes.fromhex("608648016503040201"),
    "sha384": bytes.fromhex("608648016503040202"),
    "sha512": bytes.fromhex("608648016503040203"),
}
_APPLE_NESTED_BUNDLE = re.compile(
    r"(?:PlugIns/[^/]+\.appex|Watch/[^/]+\.app|Frameworks/[^/]+\.framework)"
)


def _asn1_element(data: bytes, offset: int, end: int, depth: int = 0) -> tuple[int, int, int, int]:
    """Return (tag, content start, content end, element end) of one BER TLV."""

    if depth > 32 or offset + 2 > end:
        raise ValueError("ASN.1 element is truncated")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise ValueError("ASN.1 high tag numbers are unsupported")
    first = data[offset + 1]
    position = offset + 2
    if first == 0x80:
        if not tag & 0x20:
            raise ValueError("indefinite length on a primitive ASN.1 element")
        cursor = position
        while True:
            if cursor + 2 > end:
                raise ValueError("indefinite ASN.1 element has no end marker")
            if data[cursor] == 0 and data[cursor + 1] == 0:
                return tag, position, cursor, cursor + 2
            cursor = _asn1_element(data, cursor, end, depth + 1)[3]
    if first & 0x80:
        count = first & 0x7F
        if count < 1 or count > 4 or position + count > end:
            raise ValueError("ASN.1 length is invalid")
        length = int.from_bytes(data[position : position + count], "big")
        position += count
    else:
        length = first
    if position + length > end:
        raise ValueError("ASN.1 element overruns its container")
    return tag, position, position + length, position + length


def _asn1_children(data: bytes, start: int, end: int) -> list[tuple[int, int, int, int, int]]:
    """Return (tag, content start, content end, element start, element end) children."""

    children: list[tuple[int, int, int, int, int]] = []
    cursor = start
    while cursor < end:
        if len(children) >= 4096:
            raise ValueError("ASN.1 container has too many elements")
        tag, content_start, content_end, element_end = _asn1_element(data, cursor, end)
        children.append((tag, content_start, content_end, cursor, element_end))
        cursor = element_end
    return children


def _asn1_oid(data: bytes) -> str:
    if not data or data[-1] & 0x80 or len(data) > 64:
        raise ValueError("ASN.1 object identifier is invalid")
    values: list[int] = []
    current = 0
    for byte in data:
        current = (current << 7) | (byte & 0x7F)
        if not byte & 0x80:
            values.append(current)
            current = 0
    first = values[0]
    head = [0, first] if first < 40 else [1, first - 40] if first < 80 else [2, first - 80]
    return ".".join(str(value) for value in head + values[1:])


@dataclasses.dataclass(frozen=True)
class _AppleCertificate:
    der: bytes
    tbs: bytes
    signature_algorithm: str
    signature: bytes
    serial: bytes
    issuer: bytes
    subject: bytes
    subject_values: tuple[tuple[str, str], ...]
    modulus: int
    exponent: int
    # basicConstraints cA and pathLenConstraint, and whether keyUsage (when
    # present) allows keyCertSign. A certificate without basicConstraints is
    # not a certification authority.
    certificate_authority: bool
    path_length: int | None
    certificate_signing: bool

    def values(self, oid: str) -> list[str]:
        return [value for key, value in self.subject_values if key == oid]


def _parse_apple_certificate(der: bytes, label: str) -> _AppleCertificate:
    try:
        tag, start, end, element_end = _asn1_element(der, 0, len(der))
        if tag != 0x30 or element_end != len(der):
            raise ValueError("certificate is not one DER SEQUENCE")
        parts = _asn1_children(der, start, end)
        if len(parts) != 3 or [part[0] for part in parts] != [0x30, 0x30, 0x03]:
            raise ValueError("certificate shape is invalid")
        algorithm = _asn1_children(der, parts[1][1], parts[1][2])
        if not algorithm or algorithm[0][0] != 0x06:
            raise ValueError("certificate signature algorithm is invalid")
        signature_algorithm = _asn1_oid(der[algorithm[0][1] : algorithm[0][2]])
        bits = der[parts[2][1] : parts[2][2]]
        if len(bits) < 2 or bits[0] != 0:
            raise ValueError("certificate signature is not a whole-byte BIT STRING")
        fields = _asn1_children(der, parts[0][1], parts[0][2])
        index = 1 if fields and fields[0][0] == 0xA0 else 0
        if len(fields) < index + 6:
            raise ValueError("certificate body is incomplete")
        serial, inner_algorithm, issuer, validity, subject, key_info = fields[index : index + 6]
        if [serial[0], inner_algorithm[0], issuer[0], validity[0], subject[0], key_info[0]] != [
            0x02, 0x30, 0x30, 0x30, 0x30, 0x30
        ]:
            raise ValueError("certificate body field types are invalid")
        inner = _asn1_children(der, inner_algorithm[1], inner_algorithm[2])
        if not inner or inner[0][0] != 0x06 or _asn1_oid(der[inner[0][1] : inner[0][2]]) != signature_algorithm:
            raise ValueError("certificate signature algorithms disagree")
        key_parts = _asn1_children(der, key_info[1], key_info[2])
        if len(key_parts) != 2 or key_parts[0][0] != 0x30 or key_parts[1][0] != 0x03:
            raise ValueError("certificate public key info is invalid")
        key_algorithm = _asn1_children(der, key_parts[0][1], key_parts[0][2])
        if (
            not key_algorithm
            or key_algorithm[0][0] != 0x06
            or _asn1_oid(der[key_algorithm[0][1] : key_algorithm[0][2]]) != "1.2.840.113549.1.1.1"
        ):
            raise ValueError("certificate key is not RSA")
        key_bits = der[key_parts[1][1] : key_parts[1][2]]
        if len(key_bits) < 2 or key_bits[0] != 0:
            raise ValueError("certificate RSA key BIT STRING is invalid")
        rsa = key_bits[1:]
        rsa_tag, rsa_start, rsa_end, rsa_element_end = _asn1_element(rsa, 0, len(rsa))
        numbers = _asn1_children(rsa, rsa_start, rsa_end)
        if (
            rsa_tag != 0x30
            or rsa_element_end != len(rsa)
            or len(numbers) != 2
            or any(number[0] != 0x02 for number in numbers)
        ):
            raise ValueError("certificate RSA key is malformed")
        modulus = int.from_bytes(rsa[numbers[0][1] : numbers[0][2]], "big")
        exponent = int.from_bytes(rsa[numbers[1][1] : numbers[1][2]], "big")
        subject_values: list[tuple[str, str]] = []
        for rdn in _asn1_children(der, subject[1], subject[2]):
            if rdn[0] != 0x31:
                raise ValueError("certificate subject RDN is invalid")
            for attribute in _asn1_children(der, rdn[1], rdn[2]):
                pair = _asn1_children(der, attribute[1], attribute[2])
                if attribute[0] != 0x30 or len(pair) != 2 or pair[0][0] != 0x06:
                    raise ValueError("certificate subject attribute is invalid")
                if pair[1][0] not in {0x0C, 0x13, 0x16}:
                    continue
                subject_values.append(
                    (
                        _asn1_oid(der[pair[0][1] : pair[0][2]]),
                        der[pair[1][1] : pair[1][2]].decode("utf-8"),
                    )
                )
        # v3 extensions: only basicConstraints (2.5.29.19) and keyUsage
        # (2.5.29.15) are read, because _require_apple_certificate_chain must
        # know whether an issuer is a certification authority. A repeated
        # extensions field or a repeated extension is refused (RFC 5280 4.2),
        # so no reader can pick a different copy than this one.
        certificate_authority = False
        path_length: int | None = None
        certificate_signing = True
        extension_fields = [field for field in fields[index + 6 :] if field[0] == 0xA3]
        if len(extension_fields) > 1:
            raise ValueError("certificate extensions repeat")
        seen_extensions: set[str] = set()
        for wrapper in extension_fields:
            sequence = _asn1_children(der, wrapper[1], wrapper[2])
            if len(sequence) != 1 or sequence[0][0] != 0x30:
                raise ValueError("certificate extensions are malformed")
            for extension in _asn1_children(der, sequence[0][1], sequence[0][2]):
                extension_parts = _asn1_children(der, extension[1], extension[2])
                if (
                    extension[0] != 0x30
                    or len(extension_parts) not in {2, 3}
                    or extension_parts[0][0] != 0x06
                    or extension_parts[-1][0] != 0x04
                    or (len(extension_parts) == 3 and extension_parts[1][0] != 0x01)
                ):
                    raise ValueError("certificate extension is malformed")
                extension_oid = _asn1_oid(der[extension_parts[0][1] : extension_parts[0][2]])
                if extension_oid in seen_extensions:
                    raise ValueError("certificate extension repeats")
                seen_extensions.add(extension_oid)
                value = der[extension_parts[-1][1] : extension_parts[-1][2]]
                if extension_oid == "2.5.29.19":
                    value_tag, value_start, value_end, value_element_end = _asn1_element(
                        value, 0, len(value)
                    )
                    if value_tag != 0x30 or value_element_end != len(value):
                        raise ValueError("certificate basic constraints are malformed")
                    constraints = _asn1_children(value, value_start, value_end)
                    position = 0
                    if position < len(constraints) and constraints[position][0] == 0x01:
                        flag = value[constraints[position][1] : constraints[position][2]]
                        if len(flag) != 1:
                            raise ValueError("certificate basic constraints are malformed")
                        certificate_authority = flag != b"\x00"
                        position += 1
                    if position < len(constraints) and constraints[position][0] == 0x02:
                        limit_bytes = value[constraints[position][1] : constraints[position][2]]
                        if not 1 <= len(limit_bytes) <= 4 or limit_bytes[0] & 0x80:
                            raise ValueError("certificate path length constraint is invalid")
                        path_length = int.from_bytes(limit_bytes, "big")
                        position += 1
                    if position != len(constraints):
                        raise ValueError("certificate basic constraints are malformed")
                elif extension_oid == "2.5.29.15":
                    value_tag, value_start, value_end, value_element_end = _asn1_element(
                        value, 0, len(value)
                    )
                    usage = value[value_start:value_end]
                    if (
                        value_tag != 0x03
                        or value_element_end != len(value)
                        or not usage
                        or usage[0] > 7
                    ):
                        raise ValueError("certificate key usage is malformed")
                    certificate_signing = len(usage) >= 2 and bool(usage[1] & 0x04)
    except (IndexError, ValueError, UnicodeDecodeError) as exc:
        raise DependencyFreezeError(f"{label} certificate is malformed: {exc}") from exc
    return _AppleCertificate(
        der=der,
        tbs=der[parts[0][3] : parts[0][4]],
        signature_algorithm=signature_algorithm,
        signature=bits[1:],
        serial=der[serial[1] : serial[2]],
        issuer=der[issuer[3] : issuer[4]],
        subject=der[subject[3] : subject[4]],
        subject_values=tuple(subject_values),
        modulus=modulus,
        exponent=exponent,
        certificate_authority=certificate_authority,
        path_length=path_length,
        certificate_signing=certificate_signing,
    )


def _apple_digest_info(algorithm: str, digest: bytes, with_null: bool) -> bytes:
    oid = _APPLE_DIGEST_INFO_OIDS[algorithm]
    identifier = b"\x06" + bytes([len(oid)]) + oid + (b"\x05\x00" if with_null else b"")
    body = b"\x30" + bytes([len(identifier)]) + identifier + b"\x04" + bytes([len(digest)]) + digest
    return b"\x30" + bytes([len(body)]) + body


def _apple_rsa_signature_verifies(
    certificate: _AppleCertificate, algorithm: str, digest: bytes, signature: bytes
) -> bool:
    """Verify an RSASSA-PKCS1-v1_5 signature over ``digest`` with ``certificate``."""

    modulus = certificate.modulus
    exponent = certificate.exponent
    size = (modulus.bit_length() + 7) // 8
    # The key comes from attacker-supplied DER, so its size bounds the cost of
    # pow() below: Apple issues 2048 to 4096-bit moduli with exponent 65537.
    if (
        modulus.bit_length() < 2048
        or modulus.bit_length() > 8192
        or exponent < 3
        or exponent.bit_length() > 32
        or exponent % 2 == 0
        or len(signature) != size
        or algorithm not in _APPLE_DIGEST_INFO_OIDS
        or len(digest) != hashlib.new(algorithm).digest_size
    ):
        return False
    value = int.from_bytes(signature, "big")
    if value >= modulus:
        return False
    encoded = pow(value, exponent, modulus).to_bytes(size, "big")
    for with_null in (True, False):
        info = _apple_digest_info(algorithm, digest, with_null)
        padding = size - 3 - len(info)
        if padding >= 8 and secrets.compare_digest(
            encoded, b"\x00\x01" + b"\xff" * padding + b"\x00" + info
        ):
            return True
    return False


def _require_apple_certificate_chain(
    leaf: _AppleCertificate,
    certificates: list[_AppleCertificate],
    signer_prefixes: tuple[str, ...],
    label: str,
) -> None:
    """Require ``leaf`` to chain by RSA signatures to the pinned Apple Root CA."""

    current = leaf
    depth = 1
    while hashlib.sha256(current.der).hexdigest() != APPLE_ROOT_CA_SHA256:
        issuers = [
            candidate
            for candidate in certificates
            if candidate.subject == current.issuer and candidate.der != current.der
        ]
        if depth > 6 or len(issuers) != 1:
            raise DependencyFreezeError(
                f"{label} certificate chain does not reach the pinned Apple Root CA."
            )
        issuer = issuers[0]
        # RFC 5280 6.1.4 (k), (l), (n): only a certification authority may
        # issue a certificate on this path, within its pathLenConstraint
        # (depth - 1 intermediates already lie below it). Without this, any
        # developer's end-entity certificate under the Apple root could issue
        # a leaf that names the release team.
        if (
            not issuer.certificate_authority
            or not issuer.certificate_signing
            or (issuer.path_length is not None and depth - 1 > issuer.path_length)
        ):
            raise DependencyFreezeError(
                f"{label} certificate issuer is not a certification authority."
            )
        algorithm = _APPLE_RSA_SIGNATURE_DIGESTS.get(current.signature_algorithm)
        if algorithm is None or not _apple_rsa_signature_verifies(
            issuer, algorithm, hashlib.new(algorithm, current.tbs).digest(), current.signature
        ):
            raise DependencyFreezeError(f"{label} certificate chain signature is invalid.")
        current = issuer
        depth += 1
    common_names = leaf.values("2.5.4.3")
    if (
        depth < 3
        or leaf.values("2.5.4.11") != [APPLE_RELEASE_TEAM_IDENTIFIER]
        or len(common_names) != 1
        or not common_names[0].startswith(signer_prefixes)
        or not common_names[0].endswith(f"({APPLE_RELEASE_TEAM_IDENTIFIER})")
    ):
        raise DependencyFreezeError(
            f"{label} is not signed by the release team's {signer_prefixes[0].strip(': ')} identity."
        )


def _require_apple_cms_signature(
    cms: bytes, content: bytes, signer_prefixes: tuple[str, ...], label: str
) -> None:
    """Verify a detached CMS SignedData over ``content`` and its Apple chain."""

    try:
        tag, start, end, element_end = _asn1_element(cms, 0, len(cms))
        content_info = _asn1_children(cms, start, end)
        if (
            tag != 0x30
            or len(content_info) != 2
            or content_info[0][0] != 0x06
            or _asn1_oid(cms[content_info[0][1] : content_info[0][2]]) != "1.2.840.113549.1.7.2"
            or content_info[1][0] != 0xA0
        ):
            raise ValueError("CMS is not SignedData")
        wrapper = _asn1_children(cms, content_info[1][1], content_info[1][2])
        if len(wrapper) != 1 or wrapper[0][0] != 0x30:
            raise ValueError("CMS SignedData wrapper is invalid")
        signed_data = _asn1_children(cms, wrapper[0][1], wrapper[0][2])
        if len(signed_data) < 4 or signed_data[0][0] != 0x02 or signed_data[2][0] != 0x30:
            raise ValueError("CMS SignedData shape is invalid")
        encapsulated = _asn1_children(cms, signed_data[2][1], signed_data[2][2])
        if (
            len(encapsulated) != 1
            or encapsulated[0][0] != 0x06
            or _asn1_oid(cms[encapsulated[0][1] : encapsulated[0][2]]) != "1.2.840.113549.1.7.1"
        ):
            raise ValueError("CMS content is not detached id-data")
        certificate_nodes = [node for node in signed_data[3:] if node[0] == 0xA0]
        signer_nodes = [node for node in signed_data[3:] if node[0] == 0x31]
        if len(certificate_nodes) != 1 or len(signer_nodes) != 1 or signed_data[-1] is not signer_nodes[0]:
            raise ValueError("CMS certificates or signer infos are missing")
        certificates = [
            _parse_apple_certificate(cms[node[3] : node[4]], label)
            for node in _asn1_children(cms, certificate_nodes[0][1], certificate_nodes[0][2])
            if node[0] == 0x30
        ]
        signers = _asn1_children(cms, signer_nodes[0][1], signer_nodes[0][2])
        if len(signers) != 1 or signers[0][0] != 0x30:
            raise ValueError("CMS must carry exactly one signer")
        signer = _asn1_children(cms, signers[0][1], signers[0][2])
        if len(signer) < 6 or [node[0] for node in signer[:6]] != [0x02, 0x30, 0x30, 0xA0, 0x30, 0x04]:
            raise ValueError("CMS signer info shape is invalid")
        identifier = _asn1_children(cms, signer[1][1], signer[1][2])
        if len(identifier) != 2 or identifier[0][0] != 0x30 or identifier[1][0] != 0x02:
            raise ValueError("CMS signer identifier is not issuer and serial")
        issuer = cms[identifier[0][3] : identifier[0][4]]
        serial = cms[identifier[1][1] : identifier[1][2]]
        leaves = [item for item in certificates if item.issuer == issuer and item.serial == serial]
        digest_algorithm = _asn1_children(cms, signer[2][1], signer[2][2])
        algorithm = _APPLE_CMS_DIGESTS.get(_asn1_oid(cms[digest_algorithm[0][1] : digest_algorithm[0][2]]))
        if len(leaves) != 1 or algorithm not in {"sha256", "sha384", "sha512"}:
            raise ValueError("CMS signer certificate or digest algorithm is unsupported")
        if cms[signer[3][3] + 1] == 0x80:
            raise ValueError("CMS signed attributes are not DER")
        attributes = bytearray(cms[signer[3][3] : signer[3][4]])
        attributes[0] = 0x31
        message_digests: list[bytes] = []
        content_types: list[str] = []
        for attribute in _asn1_children(cms, signer[3][1], signer[3][2]):
            pair = _asn1_children(cms, attribute[1], attribute[2])
            if attribute[0] != 0x30 or len(pair) != 2 or pair[0][0] != 0x06 or pair[1][0] != 0x31:
                raise ValueError("CMS signed attribute is invalid")
            oid = _asn1_oid(cms[pair[0][1] : pair[0][2]])
            values = _asn1_children(cms, pair[1][1], pair[1][2])
            if oid == "1.2.840.113549.1.9.4":
                if len(values) != 1 or values[0][0] != 0x04:
                    raise ValueError("CMS message digest attribute is invalid")
                message_digests.append(cms[values[0][1] : values[0][2]])
            elif oid == "1.2.840.113549.1.9.3":
                if len(values) != 1 or values[0][0] != 0x06:
                    raise ValueError("CMS content type attribute is invalid")
                content_types.append(_asn1_oid(cms[values[0][1] : values[0][2]]))
        signature_algorithm = _asn1_children(cms, signer[4][1], signer[4][2])
        signature_oid = _asn1_oid(cms[signature_algorithm[0][1] : signature_algorithm[0][2]])
        if signature_oid != "1.2.840.113549.1.1.1" and _APPLE_RSA_SIGNATURE_DIGESTS.get(signature_oid) != algorithm:
            raise ValueError("CMS signature algorithm is unsupported")
        signature = cms[signer[5][1] : signer[5][2]]
    except (IndexError, ValueError) as exc:
        raise DependencyFreezeError(f"{label} CMS signature is malformed: {exc}") from exc
    if element_end > len(cms) or any(cms[element_end:]):
        raise DependencyFreezeError(f"{label} CMS signature has trailing data.")
    if content_types != ["1.2.840.113549.1.7.1"] or message_digests != [
        hashlib.new(algorithm, content).digest()
    ]:
        raise DependencyFreezeError(f"{label} CMS signature does not sign its CodeDirectory.")
    if not _apple_rsa_signature_verifies(
        leaves[0], algorithm, hashlib.new(algorithm, bytes(attributes)).digest(), signature
    ):
        raise DependencyFreezeError(f"{label} CMS signature does not verify.")
    _require_apple_certificate_chain(leaves[0], certificates, signer_prefixes, label)


def _apple_macho_slices(binary: bytes, label: str) -> list[tuple[int, int]]:
    """Return the byte ranges of the little-endian slices of a Mach-O.

    watchOS executables carry a 32-bit arm64_32 slice beside arm64.
    """

    if len(binary) < 4096:
        raise DependencyFreezeError(f"{label} is not a complete Mach-O.")
    if binary[:4] in {b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"}:
        return [(0, len(binary))]
    magic = struct.unpack_from(">I", binary, 0)[0]
    if magic not in {0xCAFEBABE, 0xCAFEBABF}:
        raise DependencyFreezeError(f"{label} is not a 64-bit Mach-O or universal binary.")
    wide = magic == 0xCAFEBABF
    count = struct.unpack_from(">I", binary, 4)[0]
    entry_size = 32 if wide else 20
    header_end = 8 + count * entry_size
    if count < 1 or count > 8 or header_end > len(binary):
        raise DependencyFreezeError(f"{label} universal header is invalid.")
    ranges: list[tuple[int, int]] = []
    for index in range(count):
        base = 8 + index * entry_size
        if wide:
            _cpu, _subtype, offset, size, align, _reserved = struct.unpack_from(">IIQQII", binary, base)
        else:
            _cpu, _subtype, offset, size, align = struct.unpack_from(">IIIII", binary, base)
        if (
            align > 16
            or offset < header_end
            or offset % (1 << align)
            or size < 4096
            or offset + size > len(binary)
        ):
            raise DependencyFreezeError(f"{label} universal slice {index} is out of bounds.")
        ranges.append((offset, offset + size))
    ordered = sorted(ranges)
    if any(left[1] > right[0] for left, right in zip(ordered, ordered[1:])):
        raise DependencyFreezeError(f"{label} universal slices overlap.")
    return ranges


def _require_apple_signed_slice(
    image: bytes,
    label: str,
    info_plist: bytes | None,
    code_resources: bytes | None,
    signer_prefixes: tuple[str, ...],
) -> set[bytes]:
    """Verify one Mach-O slice's code signature; return its 20-byte cdhashes."""

    view = memoryview(image)
    try:
        if image[:4] == b"\xcf\xfa\xed\xfe":
            header_size, alignment = 32, 8
        elif image[:4] == b"\xce\xfa\xed\xfe":
            header_size, alignment = 28, 4
        else:
            raise ValueError("slice is not a little-endian Mach-O")
        _magic, _cpu, _subtype, _filetype, command_count, commands_size, _flags = (
            struct.unpack_from("<7I", image, 0)
        )
        commands_end = header_size + commands_size
        if command_count < 1 or command_count > 4096 or commands_end > len(image):
            raise ValueError("load commands are out of bounds")
        cursor = header_size
        signature_command: tuple[int, int] | None = None
        for _index in range(command_count):
            command, command_size = struct.unpack_from("<II", image, cursor)
            if command_size < 8 or command_size % alignment or cursor + command_size > commands_end:
                raise ValueError("load command size is invalid")
            if command == 0x1D:
                if signature_command is not None or command_size != 16:
                    raise ValueError("LC_CODE_SIGNATURE is duplicated or malformed")
                signature_command = struct.unpack_from("<II", image, cursor + 8)
            cursor += command_size
        if cursor != commands_end or signature_command is None:
            raise ValueError("LC_CODE_SIGNATURE is missing")
        data_offset, data_size = signature_command
        if data_offset < commands_end or data_size < 20 or data_offset + data_size > len(image):
            raise ValueError("code signature is out of bounds")
        blob = image[data_offset : data_offset + data_size]
        magic, length, count = struct.unpack_from(">III", blob, 0)
        if magic != 0xFADE0CC0 or count < 2 or count > 32 or 12 + 8 * count > length or length > data_size:
            raise ValueError("code signature SuperBlob is invalid")
        slots: dict[int, tuple[int, bytes]] = {}
        for index in range(count):
            slot, offset = struct.unpack_from(">II", blob, 12 + 8 * index)
            if slot in slots or offset < 12 + 8 * count or offset + 8 > length:
                raise ValueError("code signature index is invalid")
            sub_magic, sub_length = struct.unpack_from(">II", blob, offset)
            if sub_length < 8 or offset + sub_length > length:
                raise ValueError("code signature blob is out of bounds")
            slots[slot] = (sub_magic, blob[offset : offset + sub_length])
    except (struct.error, ValueError) as exc:
        raise DependencyFreezeError(f"{label} Mach-O code signature is invalid: {exc}") from exc
    directories = [
        slots[slot][1]
        for slot in (0, 0x1000, 0x1001, 0x1002, 0x1003, 0x1004)
        if slot in slots
    ]
    if 0 not in slots or any(directory[:4] != b"\xfa\xde\x0c\x02" for directory in directories):
        raise DependencyFreezeError(f"{label} has no CodeDirectory.")
    expected_blobs = {
        2: (0xFADE0C01, "requirements"),
        5: (0xFADE7171, "entitlements"),
        7: (0xFADE7172, "DER entitlements"),
    }
    for slot, (expected_magic, name) in expected_blobs.items():
        if slot in slots and slots[slot][0] != expected_magic:
            raise DependencyFreezeError(f"{label} {name} blob is invalid.")
    if set(slots) - {0, 2, 5, 7, 0x1000, 0x1001, 0x1002, 0x1003, 0x1004, 0x10000}:
        raise DependencyFreezeError(f"{label} code signature has an unreviewed slot.")
    bound = {
        1: info_plist,
        2: slots[2][1] if 2 in slots else None,
        3: code_resources,
        5: slots[5][1] if 5 in slots else None,
        7: slots[7][1] if 7 in slots else None,
    }
    cdhashes: set[bytes] = set()
    identities: set[tuple[str, str, int]] = set()
    for directory in directories:
        try:
            (
                _magic,
                length,
                version,
                _flags,
                hash_offset,
                ident_offset,
                special_count,
                code_count,
                code_limit,
                hash_size,
                hash_type,
                _platform,
                page_log,
                _spare,
            ) = struct.unpack_from(">9I4BI", directory, 0)
            if length != len(directory) or version < 0x20200:
                raise ValueError("CodeDirectory version or length is invalid")
            scatter_offset, team_offset = struct.unpack_from(">II", directory, 44)
            header_size = 52
            if version >= 0x20300:
                code_limit_64 = struct.unpack_from(">Q", directory, 56)[0]
                header_size = 64
                if code_limit_64:
                    code_limit = code_limit_64
            if version >= 0x20400:
                header_size = 88
            if version >= 0x20500:
                if struct.unpack_from(">I", directory, 92)[0]:
                    raise ValueError("pre-encryption hashes are unsupported")
                header_size = 96
            if scatter_offset or hash_type not in _APPLE_CODE_HASH_TYPES:
                raise ValueError("CodeDirectory hash type or scatter vector is unsupported")
            algorithm, expected_size = _APPLE_CODE_HASH_TYPES[hash_type]
            page = 1 << page_log if page_log else code_limit
            if (
                hash_size != expected_size
                or page_log not in {0, 12, 13, 14, 15, 16}
                or code_limit != data_offset
                or code_count != (code_limit + page - 1) // page
                or special_count > 16
                or hash_offset - special_count * hash_size < header_size
                or hash_offset + code_count * hash_size > length
            ):
                raise ValueError("CodeDirectory geometry is invalid")
            identifier_end = directory.index(b"\x00", ident_offset)
            team_end = directory.index(b"\x00", team_offset) if team_offset else -1
            identifier = directory[ident_offset:identifier_end].decode("utf-8")
            team = directory[team_offset:team_end].decode("utf-8") if team_offset else ""
        except (struct.error, ValueError, UnicodeDecodeError) as exc:
            raise DependencyFreezeError(f"{label} CodeDirectory is invalid: {exc}") from exc
        if team != APPLE_RELEASE_TEAM_IDENTIFIER or not identifier:
            raise DependencyFreezeError(f"{label} CodeDirectory is not the release team's.")
        identities.add((identifier, team, code_limit))
        for index in range(code_count):
            start = index * page
            stored = directory[hash_offset + index * hash_size : hash_offset + (index + 1) * hash_size]
            measured = hashlib.new(algorithm, view[start : min(start + page, code_limit)]).digest()
            if measured[:hash_size] != stored:
                raise DependencyFreezeError(
                    f"{label} code page {index} does not match its CodeDirectory hash."
                )
        for slot in range(1, 8):
            stored = (
                directory[hash_offset - slot * hash_size : hash_offset - (slot - 1) * hash_size]
                if slot <= special_count
                else None
            )
            data = bound.get(slot)
            if data is None:
                if stored is not None and any(stored):
                    raise DependencyFreezeError(f"{label} special slot {slot} names absent data.")
                continue
            if stored is None or hashlib.new(algorithm, data).digest()[:hash_size] != stored:
                raise DependencyFreezeError(f"{label} special slot {slot} does not bind its data.")
        cdhashes.add(hashlib.new(algorithm, directory).digest()[:20])
    if len(identities) != 1:
        raise DependencyFreezeError(f"{label} CodeDirectories disagree.")
    cms = slots.get(0x10000)
    if cms is None or cms[0] != 0xFADE0B01 or len(cms[1]) <= 8:
        raise DependencyFreezeError(f"{label} has no CMS signature (ad hoc or unsigned).")
    _require_apple_cms_signature(cms[1][8:], slots[0][1], signer_prefixes, label)
    return cdhashes


def _require_apple_signed_macho(
    binary: bytes,
    label: str,
    info_plist: bytes | None,
    code_resources: bytes | None,
    signer_prefixes: tuple[str, ...],
) -> set[bytes]:
    """Verify every slice of a signed Mach-O; return all of its cdhashes."""

    cdhashes: set[bytes] = set()
    for index, (start, end) in enumerate(_apple_macho_slices(binary, label)):
        cdhashes |= _require_apple_signed_slice(
            binary[start:end], f"{label} slice {index}", info_plist, code_resources, signer_prefixes
        )
    return cdhashes


def _apple_zip_member(
    archive: zipfile.ZipFile, infos: dict[str, zipfile.ZipInfo], name: str, label: str
) -> bytes:
    info = infos.get(name)
    if info is None or info.is_dir():
        raise DependencyFreezeError(f"{label} lacks {name}.")
    if info.file_size > APPLE_SIGNED_EXECUTABLE_BYTES_LIMIT:
        raise DependencyFreezeError(f"{label} member {name} exceeds the bound.")
    try:
        payload = archive.read(info)
    except (OSError, RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
        raise DependencyFreezeError(f"{label} member {name} is unreadable.") from exc
    if len(payload) != info.file_size:
        raise DependencyFreezeError(f"{label} member {name} size changed.")
    return payload


def _require_apple_bundle(
    archive: zipfile.ZipFile,
    infos: dict[str, zipfile.ZipInfo],
    bundle: str,
    label: str,
    depth: int,
) -> set[bytes]:
    """Verify one signed bundle and all nested code; return its cdhashes."""

    if depth > APPLE_BUNDLE_NESTING_LIMIT:
        raise DependencyFreezeError(f"{label} nests code bundles too deeply.")
    bundle_label = f"{label} {bundle}"
    info_plist = _apple_zip_member(archive, infos, f"{bundle}/Info.plist", label)
    code_resources = _apple_zip_member(
        archive, infos, f"{bundle}/_CodeSignature/CodeResources", label
    )
    try:
        info = plistlib.loads(info_plist)
        seal = plistlib.loads(code_resources)
    except Exception as exc:
        raise DependencyFreezeError(f"{bundle_label} Info.plist or CodeResources is malformed.") from exc
    executable = info.get("CFBundleExecutable") if type(info) is dict else None
    files = seal.get("files2") if type(seal) is dict else None
    if type(executable) is not str or not re.fullmatch(r"[A-Za-z0-9._+' -]{1,127}", executable):
        raise DependencyFreezeError(f"{bundle_label} executable identity is invalid.")
    # An empty files2 is a valid seal (a framework with no resources); the
    # unsealed-file scan below still refuses any file it does not list.
    if type(files) is not dict:
        raise DependencyFreezeError(f"{bundle_label} CodeResources has no files2 seal.")
    cdhashes = _require_apple_signed_macho(
        _apple_zip_member(archive, infos, f"{bundle}/{executable}", label),
        f"{bundle_label} executable",
        info_plist,
        code_resources,
        APPLE_IPA_SIGNER_PREFIXES,
    )
    nested_roots: set[str] = set()
    verified_nested: set[str] = set()
    for relative, entry in files.items():
        if (
            type(relative) is not str
            or type(entry) is not dict
            or not relative
            or relative.startswith("/")
            or ".." in relative.split("/")
            or "symlink" in entry
        ):
            raise DependencyFreezeError(f"{bundle_label} CodeResources entry is unsupported.")
        member = f"{bundle}/{relative}"
        if "cdhash" in entry:
            nested_roots.add(relative)
            expected = entry.get("cdhash")
            if member in infos and not infos[member].is_dir():
                nested = _require_apple_signed_macho(
                    _apple_zip_member(archive, infos, member, label),
                    f"{bundle_label} {relative}",
                    None,
                    None,
                    APPLE_IPA_SIGNER_PREFIXES,
                )
            else:
                nested = _require_apple_bundle(archive, infos, member, label, depth + 1)
                verified_nested.add(relative)
            if type(expected) is not bytes or expected not in nested:
                raise DependencyFreezeError(f"{bundle_label} nested code {relative} is not sealed.")
            continue
        expected = entry.get("hash2")
        if type(expected) is not bytes or len(expected) != 32:
            raise DependencyFreezeError(f"{bundle_label} CodeResources entry lacks SHA-256.")
        info_entry = infos.get(member)
        if info_entry is None or info_entry.is_dir():
            if entry.get("optional") is True:
                continue
            raise DependencyFreezeError(f"{bundle_label} sealed file {relative} is missing.")
        digest = hashlib.sha256()
        try:
            with archive.open(info_entry, "r") as source:
                while block := source.read(1024 * 1024):
                    digest.update(block)
        except (OSError, RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
            raise DependencyFreezeError(f"{bundle_label} sealed file {relative} is unreadable.") from exc
        if digest.digest() != expected:
            raise DependencyFreezeError(f"{bundle_label} sealed file {relative} was modified.")
    prefix = f"{bundle}/"
    for name, info_entry in infos.items():
        if info_entry.is_dir() or not name.startswith(prefix):
            continue
        relative = name[len(prefix) :]
        if (
            relative in files
            or relative in {executable, "Info.plist", "PkgInfo"}
            or relative.startswith("_CodeSignature/")
            or any(relative.startswith(f"{root}/") for root in nested_roots)
        ):
            continue
        raise DependencyFreezeError(f"{bundle_label} file {relative} is not sealed.")
    # Every app extension, Watch app and framework must verify as signed code
    # itself, whether the parent seals it as nested code or file by file.
    for name in sorted(infos):
        match = _APPLE_NESTED_BUNDLE.match(name[len(prefix) :]) if name.startswith(prefix) else None
        if match and match.group(0) not in verified_nested:
            verified_nested.add(match.group(0))
            _require_apple_bundle(archive, infos, f"{prefix}{match.group(0)}", label, depth + 1)
    return cdhashes


def _require_signed_apple_ipa(payload: bytes, label: str) -> None:
    """Require an App Store IPA whose app, extensions and Watch app verify."""

    members = _validated_zip_members(payload, label)
    roots = {
        "/".join(name.split("/")[:2])
        for name in members
        if name.startswith("Payload/") and len(name.split("/")) >= 3
    }
    if len(roots) != 1 or not next(iter(roots)).endswith(".app"):
        raise DependencyFreezeError(f"{label} must contain exactly one Payload/<name>.app.")
    app = next(iter(roots))
    watch_apps = {
        "/".join(name.split("/")[:4])
        for name in members
        if name.startswith(f"{app}/Watch/") and len(name.split("/")) >= 5
    }
    if any(not root.endswith(".app") for root in watch_apps) or len(watch_apps) > 1:
        raise DependencyFreezeError(f"{label} Watch payload must be exactly one Watch app.")
    for root in (app, *watch_apps):
        profile = members.get(f"{root}/embedded.mobileprovision", b"")
        if len(profile) < 64 or profile[:1] != b"\x30" or APPLE_RELEASE_TEAM_IDENTIFIER.encode() not in profile:
            raise DependencyFreezeError(f"{label} {root} lacks the release provisioning profile.")
    try:
        with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
            infos = {info.filename: info for info in archive.infolist()}
            _require_apple_bundle(archive, infos, app, label, 0)
    except DependencyFreezeError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
        raise DependencyFreezeError(f"{label} ZIP payload is malformed.") from exc


def _xar_integer(node: etree.Element | None, label: str) -> int:
    text = node.text.strip() if node is not None and node.text else ""
    if not re.fullmatch(r"[0-9]{1,15}", text):
        raise DependencyFreezeError(f"{label} XAR TOC integer is invalid.")
    return int(text)


def _require_signed_apple_pkg(payload: bytes, label: str) -> None:
    """Require a Mac App Store product archive signed by the release team."""

    import binascii  # Already loaded by zipfile and plistlib; no new module.

    if len(payload) < 64 or payload[:4] != b"xar!":
        raise DependencyFreezeError(f"{label} is not a complete XAR package.")
    try:
        header_size, version = struct.unpack_from(">HH", payload, 4)
        compressed_size, toc_size = struct.unpack_from(">QQ", payload, 8)
        checksum_code = struct.unpack_from(">I", payload, 24)[0]
        if checksum_code == 1:
            algorithm = "sha1"
        elif checksum_code == 3 and header_size > 28:
            algorithm = payload[28:header_size].split(b"\x00", 1)[0].decode("ascii")
        else:
            raise ValueError("TOC checksum algorithm is not SHA")
        heap_start = header_size + compressed_size
        if (
            version != 1
            or header_size < 28
            or header_size > 4096
            or algorithm not in {"sha1", "sha256", "sha512"}
            or compressed_size < 1
            or toc_size < 1
            or toc_size > ARCHIVE_METADATA_BYTES_LIMIT
            or heap_start >= len(payload)
        ):
            raise ValueError("XAR header is invalid")
        compressed = payload[header_size:heap_start]
        inflater = zlib.decompressobj()
        toc = inflater.decompress(compressed, ARCHIVE_METADATA_BYTES_LIMIT + 1)
        if inflater.unconsumed_tail or not inflater.eof or inflater.unused_data or len(toc) != toc_size:
            raise ValueError("XAR TOC is not one exact zlib stream")
        root = etree.fromstring(toc)
    except (struct.error, zlib.error, etree.ParseError, ValueError, UnicodeDecodeError) as exc:
        raise DependencyFreezeError(f"{label} XAR header or TOC is invalid: {exc}") from exc
    heap = memoryview(payload)[heap_start:]
    table = root.find("toc") if root.tag == "xar" else None
    if table is None:
        raise DependencyFreezeError(f"{label} XAR TOC is missing.")
    extents: list[tuple[int, int]] = []

    def extent(node: etree.Element | None, name: str, allow_empty: bool = False) -> tuple[int, int]:
        if node is None:
            raise DependencyFreezeError(f"{label} XAR {name} is missing.")
        offset = _xar_integer(node.find("offset"), label)
        size = _xar_integer(node.find("size") if node.find("length") is None else node.find("length"), label)
        if (size < 1 and not allow_empty) or offset + size > len(heap):
            raise DependencyFreezeError(f"{label} XAR {name} lies outside the heap.")
        if size:
            extents.append((offset, offset + size))
        return offset, size

    checksum_node = table.find("checksum")
    offset, size = extent(checksum_node, "TOC checksum")
    stored = bytes(heap[offset : offset + size])
    if (
        checksum_node.get("style") != algorithm
        or size != hashlib.new(algorithm).digest_size
        or stored != hashlib.new(algorithm, compressed).digest()
    ):
        raise DependencyFreezeError(f"{label} XAR TOC checksum does not match the TOC.")
    signature_node = table.find("signature")
    offset, size = extent(signature_node, "signature")
    if signature_node.get("style") != "RSA":
        raise DependencyFreezeError(f"{label} XAR signature is not RSA.")
    signature = bytes(heap[offset : offset + size])
    for other in table.findall("x-signature"):
        extent(other, "secondary signature")
    certificates: list[_AppleCertificate] = []
    for node in signature_node.iter():
        if node.tag.rsplit("}", 1)[-1] != "X509Certificate":
            continue
        try:
            der = binascii.a2b_base64("".join((node.text or "").split()), strict_mode=True)
        except (binascii.Error, ValueError) as exc:
            raise DependencyFreezeError(f"{label} XAR certificate is not base64.") from exc
        certificates.append(_parse_apple_certificate(der, label))
    if not certificates:
        raise DependencyFreezeError(f"{label} XAR signature has no certificate.")
    if not _apple_rsa_signature_verifies(certificates[0], algorithm, stored, signature):
        raise DependencyFreezeError(f"{label} XAR signature does not verify.")
    _require_apple_certificate_chain(certificates[0], certificates, APPLE_PKG_SIGNER_PREFIXES, label)
    top_level = {node.findtext("name") for node in table.findall("file")}
    if "Distribution" not in top_level:
        raise DependencyFreezeError(f"{label} is not a product archive with a Distribution.")
    file_count = 0
    for node in table.iter("file"):
        file_count += 1
        data = node.find("data")
        if file_count > ARCHIVE_ENTRY_LIMIT:
            raise DependencyFreezeError(f"{label} XAR has too many files.")
        if data is None:
            continue
        offset, size = extent(data, "file data", allow_empty=True)
        archived = data.find("archived-checksum")
        style = archived.get("style") if archived is not None else None
        if style not in {"sha1", "sha256", "sha512"} or (archived.text or "").strip() != hashlib.new(
            style, heap[offset : offset + size]
        ).hexdigest():
            raise DependencyFreezeError(f"{label} XAR file data does not match its archived checksum.")
    ordered = sorted(extents)
    if any(left[1] > right[0] for left, right in zip(ordered, ordered[1:])):
        raise DependencyFreezeError(f"{label} XAR heap extents overlap.")


def _validate_release_artifact_bytes(
    platform: str,
    target: str,
    artifact_name: str,
    payload: bytes,
) -> None:
    label = f"{platform} {target} artifact"
    suffix = artifact_name.lower()
    if platform == "android":
        _require_android_package(payload, target, suffix, label)
        if target.endswith("-aab"):
            members: dict[str, bytes] = {}
            try:
                members = _validated_zip_members(payload, label)
                watch = _android_bundle_declares_watch(members, label)
            except DependencyFreezeError:
                # The phone and TV validator has never required a parseable
                # protobuf manifest; refuse only a positively identified watch,
                # and a manifest that names the watch feature but cannot be
                # read (aapt2 stores attribute strings as raw UTF-8).
                if WEAR_OS_WATCH_FEATURE.encode("ascii") in members.get(
                    "base/manifest/AndroidManifest.xml", b""
                ):
                    raise
                watch = False
            if watch:
                raise DependencyFreezeError(
                    f"{label} is a Wear OS bundle, not a phone or TV release."
                )
        return
    if platform == "wear_os":
        _require_wear_os_bundle(payload, target, suffix, label)
        return
    if platform == "extension":
        if not suffix.endswith((".zip", ".xpi")):
            raise DependencyFreezeError(f"{label} must be a ZIP or XPI archive.")
        _require_extension_release_package(
            _validated_zip_members(payload, label), target, artifact_name, label
        )
        return
    if platform == "windows":
        if "msix" in target and suffix.endswith((".msix", ".appx")):
            raise DependencyFreezeError(
                f"{label} has no reviewed cryptographic MSIX validator."
            )
        if "inno" in target and suffix.endswith(".exe"):
            _require_pe_installer(payload, target, label)
            return
        raise DependencyFreezeError(f"{label} has no reviewed Windows validator.")
    if platform == "linux":
        _require_linux_release_tarball(payload, target, artifact_name, label)
        return
    if platform == "ios":
        if not target.startswith("app-store-") or not suffix.endswith(".ipa"):
            raise DependencyFreezeError(
                f"{label} has no reviewed cryptographic IPA validator."
            )
        _require_signed_apple_ipa(payload, label)
        return
    if platform == "macos":
        if not target.startswith("app-store-") or not suffix.endswith(".pkg"):
            raise DependencyFreezeError(
                f"{label} has no reviewed cryptographic PKG validator."
            )
        _require_signed_apple_pkg(payload, label)
        return
    raise DependencyFreezeError(f"{label} has no reviewed format validator.")


def _require_android_package(
    payload: bytes, target: str, suffix: str, label: str
) -> None:
    """Require a structurally complete, signed APK or AAB for ``target``.

    Signature validity is checked by the producer with the pinned apksigner and
    jarsigner before it attests the artifact; this binds the attested bytes to a
    package of the declared kind that carries a signature.
    """

    members = _validated_zip_members(payload, label)
    if target.endswith("-apk"):
        if not suffix.endswith(".apk"):
            raise DependencyFreezeError(f"{label} must be an .apk file.")
        manifest = members.get("AndroidManifest.xml", b"")
        dex = members.get("classes.dex", b"")
        if not manifest.startswith(b"\x03\x00\x08\x00") or not dex.startswith(b"dex\n"):
            raise DependencyFreezeError(
                f"{label} lacks a binary AndroidManifest.xml and classes.dex."
            )
        eocd_offset = payload.rfind(b"PK\x05\x06", max(0, len(payload) - 65_557))
        central_offset = struct.unpack_from("<L", payload, eocd_offset + 16)[0]
        if (
            central_offset < 32
            or payload[central_offset - 16:central_offset] != b"APK Sig Block 42"
        ):
            raise DependencyFreezeError(
                f"{label} lacks an APK Signature Scheme v2+ signing block."
            )
        return
    if target.endswith("-aab"):
        if not suffix.endswith(".aab"):
            raise DependencyFreezeError(f"{label} must be an .aab file.")
        signatures = [
            name
            for name in members
            if name.startswith("META-INF/")
            and name.upper().endswith((".RSA", ".EC", ".DSA"))
            and members[name]
        ]
        if (
            not members.get("base/manifest/AndroidManifest.xml")
            or not members.get("BundleConfig.pb")
            or not members.get("META-INF/MANIFEST.MF")
            or not any(
                name.startswith("META-INF/") and name.upper().endswith(".SF")
                for name in members
            )
            or not signatures
        ):
            raise DependencyFreezeError(
                f"{label} lacks the base manifest, bundle config or JAR signature."
            )
        return
    raise DependencyFreezeError(f"{label} target is not an APK or AAB release.")


@dataclasses.dataclass(frozen=True)
class InputFile:
    path: str
    size: int
    sha256: str


@dataclasses.dataclass(frozen=True)
class GitAudit:
    object_format: str
    git_executable_sha256: str
    head: str
    tree: str
    selected_blobs: tuple[tuple[str, str, str], ...]


@dataclasses.dataclass(frozen=True)
class InputState:
    fingerprint_sha256: str
    file_count: int
    total_bytes: int
    files: tuple[InputFile, ...]
    git_audit: GitAudit | None


@dataclasses.dataclass(frozen=True)
class _InputCapture:
    state: InputState
    selected: tuple[str, ...]
    identities: tuple[tuple[str, tuple[int, ...]], ...]
    directories: tuple[tuple[str, tuple[int, ...]], ...]
    aliases: tuple[tuple[str, str], ...]


def _release_identity(repo: pathlib.Path) -> str:
    held = _operation_pubspec(repo)
    if held is not None:
        payload = held.payload
    else:
        owners = _allowed_owners(repo)
        payload, _identity, _info = _stable_read_regular_file(
            repo / "pubspec.yaml",
            owners,
            label="dependency input",
            repo=repo,
        )
    text = _utf8_text(payload, "pubspec.yaml")
    match = re.search(r"(?m)^version:\s*([^+\s]+)\+(\d+)\s*$", text)
    if not match:
        raise DependencyFreezeError(
            "pubspec.yaml must contain version: <semver>+<integer>."
        )
    return f"{match.group(1)}+{match.group(2)}"


def _is_excluded(relative: pathlib.PurePath) -> bool:
    folded_parts = tuple(_fold_key(part) for part in relative.parts)
    excluded_dirs = {_fold_key(item) for item in EXCLUDED_DIR_NAMES}
    excluded_files = {_fold_key(item) for item in EXCLUDED_FILE_NAMES}
    excluded_suffixes = {_fold_key(item) for item in EXCLUDED_FILE_SUFFIXES}
    return (
        any(part in excluded_dirs for part in folded_parts[:-1])
        or _fold_key(relative.name) in excluded_files
        or _fold_key(relative.suffix) in excluded_suffixes
        # Case-sensitive on purpose: the AppleDouble prefix is literally "._",
        # and lowercasing would not change it. Matched on the basename so a
        # directory that legitimately begins with "._" cannot hide real inputs.
        or relative.name.startswith(APPLEDOUBLE_PREFIX)
    )


def _assert_not_forbidden(relative: pathlib.PurePath) -> None:
    name = _fold_key(relative.name)
    forbidden_names = {_fold_key(item) for item in FORBIDDEN_FILE_NAMES}
    forbidden_suffixes = {_fold_key(item) for item in FORBIDDEN_SUFFIXES}
    if (
        name in forbidden_names
        or name.startswith(_fold_key(".env."))
        or _fold_key(pathlib.PurePath(relative.name).suffix) in forbidden_suffixes
    ):
        raise DependencyFreezeError(
            f"Credential-like file is forbidden in release inputs: {relative.as_posix()}"
        )


def _yaml_without_comment(value: str) -> str:
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(value):
        char = value[index]
        if quote == '"':
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif quote == "'":
            if char == quote:
                if index + 1 < len(value) and value[index + 1] == quote:
                    index += 1
                else:
                    quote = None
        elif char in {"'", '"'}:
            quote = char
        elif char == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip()
        index += 1
    if quote is not None or escaped:
        raise DependencyFreezeError("pubspec.yaml contains an unterminated quoted scalar")
    return value.rstrip()


class _YamlFlowParser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.index = 0

    def parse(self) -> object:
        value = self._node()
        self._space()
        if self.index != len(self.text):
            raise DependencyFreezeError("pubspec.yaml flow collection is invalid")
        return value

    def _space(self) -> None:
        while self.index < len(self.text) and self.text[self.index].isspace():
            self.index += 1

    def _node(self) -> object:
        self._space()
        if self.index >= len(self.text):
            raise DependencyFreezeError("pubspec.yaml flow collection is incomplete")
        char = self.text[self.index]
        if char == "[":
            return self._sequence()
        if char == "{":
            return self._mapping()
        return self._scalar(stop_at_colon=False)

    def _sequence(self) -> list[object]:
        self.index += 1
        values: list[object] = []
        while True:
            self._space()
            if self.index >= len(self.text):
                raise DependencyFreezeError("pubspec.yaml flow sequence is incomplete")
            if self.text[self.index] == "]":
                self.index += 1
                return values
            values.append(self._node())
            self._space()
            if self.index >= len(self.text):
                raise DependencyFreezeError("pubspec.yaml flow sequence is incomplete")
            if self.text[self.index] == "]":
                self.index += 1
                return values
            if self.text[self.index] != ",":
                raise DependencyFreezeError("pubspec.yaml flow sequence is invalid")
            self.index += 1

    def _mapping(self) -> dict[str, object]:
        self.index += 1
        values: dict[str, object] = {}
        while True:
            self._space()
            if self.index >= len(self.text):
                raise DependencyFreezeError("pubspec.yaml flow mapping is incomplete")
            if self.text[self.index] == "}":
                self.index += 1
                return values
            key = self._scalar(stop_at_colon=True)
            self._space()
            if self.index >= len(self.text) or self.text[self.index] != ":":
                raise DependencyFreezeError("pubspec.yaml flow mapping is invalid")
            self.index += 1
            value = self._node()
            if key in values:
                raise DependencyFreezeError("pubspec.yaml flow mapping has a duplicate key")
            values[key] = value
            self._space()
            if self.index >= len(self.text):
                raise DependencyFreezeError("pubspec.yaml flow mapping is incomplete")
            if self.text[self.index] == "}":
                self.index += 1
                return values
            if self.text[self.index] != ",":
                raise DependencyFreezeError("pubspec.yaml flow mapping is invalid")
            self.index += 1

    def _scalar(self, *, stop_at_colon: bool) -> str:
        self._space()
        if self.index >= len(self.text):
            raise DependencyFreezeError("pubspec.yaml flow scalar is missing")
        quote = self.text[self.index]
        if quote in {"'", '"'}:
            start = self.index
            self.index += 1
            if quote == "'":
                value: list[str] = []
                while self.index < len(self.text):
                    char = self.text[self.index]
                    self.index += 1
                    if char != quote:
                        value.append(char)
                        continue
                    if self.index < len(self.text) and self.text[self.index] == quote:
                        value.append(quote)
                        self.index += 1
                        continue
                    return "".join(value)
                raise DependencyFreezeError("pubspec.yaml flow scalar is incomplete")
            escaped = False
            while self.index < len(self.text):
                char = self.text[self.index]
                self.index += 1
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    try:
                        value = json.loads(self.text[start:self.index])
                    except json.JSONDecodeError as suc:
                        raise DependencyFreezeError(
                            "pubspec.yaml double-quoted flow scalar is invalid"
                        ) from suc
                    if type(value) is not str:
                        raise DependencyFreezeError(
                            "pubspec.yaml flow asset path must be a string"
                        )
                    return value
            raise DependencyFreezeError("pubspec.yaml flow scalar is incomplete")
        start = self.index
        while self.index < len(self.text):
            char = self.text[self.index]
            if char in ",]}" or (stop_at_colon and char == ":"):
                break
            self.index += 1
        value = self.text[start:self.index].strip()
        if not value or value[0] in "&*!|>@`":
            raise DependencyFreezeError("pubspec.yaml flow scalar is invalid")
        return value


def _collect_yaml_flow(
    lines: list[str], start: int, initial: str
) -> tuple[str, int]:
    parts: list[str] = []
    stack: list[str] = []
    quote: str | None = None
    escaped = False
    line_index = start
    current = initial
    while True:
        clean = _yaml_without_comment(current).strip()
        parts.append(clean)
        index = 0
        while index < len(clean):
            char = clean[index]
            if quote == '"':
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
            elif quote == "'":
                if char == quote:
                    if index + 1 < len(clean) and clean[index + 1] == quote:
                        index += 1
                    else:
                        quote = None
            elif char in {"'", '"'}:
                quote = char
            elif char in "[{":
                stack.append(char)
            elif char in "]}":
                expected = "[" if char == "]" else "{"
                if not stack or stack.pop() != expected:
                    raise DependencyFreezeError("pubspec.yaml flow collection is invalid")
            index += 1
        if quote is None and not stack:
            return " ".join(parts), line_index
        line_index += 1
        if line_index >= len(lines):
            raise DependencyFreezeError("pubspec.yaml flow collection is incomplete")
        current = lines[line_index]


def _flow_font_asset_paths(value: object) -> list[str]:
    paths: list[str] = []
    if type(value) is list:
        for item in value:
            paths.extend(_flow_font_asset_paths(item))
    elif type(value) is dict:
        for key, item in value.items():
            if key == "asset":
                if type(item) is not str:
                    raise DependencyFreezeError(
                        "pubspec.yaml flow font asset path must be a string"
                    )
                paths.append(item)
            else:
                paths.extend(_flow_font_asset_paths(item))
    return paths


def _yaml_scalar_value(value: str) -> str:
    parser = _YamlFlowParser(_yaml_without_comment(value).strip())
    scalar = parser.parse()
    if type(scalar) is not str:
        raise DependencyFreezeError("pubspec.yaml asset path must be a string")
    return scalar


def _normalize_declared_asset_path(raw_value: str) -> str:
    value = raw_value.strip().replace("\\", "/")
    if not value or value.startswith("/"):
        raise DependencyFreezeError(f"Unsafe pubspec asset path: {value or '<empty>'}")
    parts = pathlib.PurePosixPath(value).parts
    if ".." in parts:
        raise DependencyFreezeError(f"Unsafe pubspec asset path: {value}")
    while value.startswith("./"):
        value = value[2:]
    value = value.rstrip("/")
    if not value or value in {".", ".."}:
        raise DependencyFreezeError(f"Unsafe pubspec asset path: {value or '<empty>'}")
    return value


def _declared_pubspec_assets(repo: pathlib.Path) -> tuple[str, ...]:
    """Return normalized Flutter asset/font/shader paths without a YAML package."""

    _ensure_release_root_write_custody(repo)
    overrides = repo / "pubspec_overrides.yaml"
    try:
        os.lstat(overrides)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise DependencyFreezeError(
            "Unable to inspect forbidden pubspec_overrides.yaml."
        ) from exc
    else:
        raise DependencyFreezeError(
            "pubspec_overrides.yaml is forbidden in release inputs"
        )

    held = _operation_pubspec(repo)
    if held is not None:
        payload = held.payload
    else:
        owners = _allowed_owners(repo)
        payload, _identity, _info = _stable_read_regular_file(
            repo / "pubspec.yaml",
            owners,
            label="dependency input",
            repo=repo,
        )
    lines = _utf8_text(payload, "pubspec.yaml").splitlines()
    top_level_flutter_blocks = 0
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if len(raw) != len(raw.lstrip(" ")):
            continue
        stripped = _yaml_without_comment(raw.strip()).strip()
        if re.match(r"^flutter:(?:\s*(.*))?$", stripped):
            top_level_flutter_blocks += 1
            if top_level_flutter_blocks > 1:
                raise DependencyFreezeError(
                    "pubspec.yaml contains duplicate top-level flutter mappings"
                )
    flutter_indent: int | None = None
    assets_indent: int | None = None
    fonts_indent: int | None = None
    assets: list[str] = []
    line_index = 0
    while line_index < len(lines):
        raw = lines[line_index]
        if not raw.strip() or raw.lstrip().startswith("#"):
            line_index += 1
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = _yaml_without_comment(raw.strip()).strip()
        if flutter_indent is None:
            top_flutter = re.match(r"^flutter:(?:\s*(.*))?$", stripped)
            if top_flutter and indent == 0:
                if (top_flutter.group(1) or "").strip():
                    raise DependencyFreezeError(
                        "pubspec.yaml top-level flutter flow mapping is unsupported"
                    )
                flutter_indent = 0
            line_index += 1
            continue
        if indent <= flutter_indent:
            break
        if assets_indent is not None and indent <= assets_indent:
            assets_indent = None
        if fonts_indent is not None and indent <= fonts_indent:
            fonts_indent = None
        declaration = re.match(r"^(assets|shaders|fonts):(?:\s*(.*))?$", stripped)
        if declaration:
            key = declaration.group(1)
            value = (declaration.group(2) or "").strip()
            if value:
                if not value.startswith("["):
                    raise DependencyFreezeError(
                        f"pubspec.yaml {key} must be a YAML sequence"
                    )
                flow, line_index = _collect_yaml_flow(lines, line_index, value)
                parsed = _YamlFlowParser(flow).parse()
                if type(parsed) is not list:
                    raise DependencyFreezeError(
                        f"pubspec.yaml {key} must be a YAML sequence"
                    )
                values = _flow_font_asset_paths(parsed) if key == "fonts" else parsed
                for item in values:
                    if type(item) is not str:
                        raise DependencyFreezeError(
                            f"pubspec.yaml {key} map-form asset entries are unsupported"
                        )
                    assets.append(_normalize_declared_asset_path(item))
                assets_indent = None
                fonts_indent = None
            elif key in {"assets", "shaders"}:
                assets_indent = indent
            else:
                fonts_indent = indent
            line_index += 1
            continue
        if assets_indent is not None and indent > assets_indent:
            match = re.match(r"^-\s+(.+?)\s*$", stripped)
            if match:
                item = match.group(1).strip()
                if item.startswith("{") or (
                    not item.startswith(("'", '"'))
                    and re.search(r":(?:\s|$)", item)
                ):
                    raise DependencyFreezeError(
                        "pubspec.yaml assets/shaders map-form entries are unsupported"
                    )
                assets.append(
                    _normalize_declared_asset_path(_yaml_scalar_value(item))
                )
                line_index += 1
                continue
        if fonts_indent is not None and indent > fonts_indent:
            font_match = re.match(r"^-?\s*asset:\s*(.+?)\s*$", stripped)
            if font_match:
                assets.append(
                    _normalize_declared_asset_path(
                        _yaml_scalar_value(font_match.group(1))
                    )
                )
                line_index += 1
                continue
        line_index += 1
    return tuple(dict.fromkeys(assets))


def shared_roots(repo: pathlib.Path) -> tuple[str, ...]:
    roots = list(SHARED_ROOTS)
    for asset in _declared_pubspec_assets(repo):
        roots.append(asset)
    return tuple(dict.fromkeys(roots))


def platform_native_paths(platform: str) -> tuple[str, ...]:
    if platform not in PLATFORM_ROOTS:
        raise DependencyFreezeError(f"Unsupported platform: {platform}")
    return PLATFORM_ROOTS[platform] + PLATFORM_NATIVE_EXTRA_PATHS[platform]


def _platform_native_input_state(repo: pathlib.Path, platform: str) -> InputState:
    return input_state(
        repo,
        platform_native_paths(platform),
        bind_windows_host_lib_aliases=(platform == "windows"),
    )


def _normalized_symlink_target(alias: str, link_text: str) -> str:
    alias_parent = str(pathlib.PurePosixPath(alias).parent)
    joined_parts = _split_relative(alias_parent) + _split_link_components(
        link_text, alias
    )
    normalized: list[str] = []
    for part in joined_parts:
        if part == "..":
            if not normalized:
                raise DependencyFreezeError(
                    "Native-messaging host symlink alias target escapes the repository: "
                    f"{alias}"
                )
            normalized.pop()
            continue
        if part in {"", "."}:
            continue
        normalized.append(part)
    target_rel = "/".join(normalized)
    if any(part in {"", ".", ".."} for part in pathlib.PurePosixPath(target_rel).parts):
        raise DependencyFreezeError(
            f"Native-messaging host symlink alias target escapes the repository: {alias}"
        )
    return target_rel


def _bind_windows_native_host_lib_aliases_at(
    repo_fd: int,
    allowed_owners: frozenset[int],
) -> tuple[tuple[str, str], ...]:
    _assert_windows_native_host_lib_aliases()
    alias_fd, _info = _walk_open_dir(
        repo_fd, WINDOWS_NATIVE_HOST_LIB_SYMLINK_DIR, allowed_owners
    )
    try:
        expected_by_name = {
            pathlib.PurePosixPath(alias).name: (alias, target)
            for alias, target in WINDOWS_NATIVE_HOST_LIB_SYMLINK_ALIASES
        }
        names = _list_directory_names(alias_fd, WINDOWS_NATIVE_HOST_LIB_SYMLINK_DIR)
        observed: set[str] = set()
        for name in names:
            observed.add(name)
            expected_name = expected_by_name.get(name)
            if expected_name is None:
                folded = _fold_key(name)
                for known in expected_by_name:
                    if _fold_key(known) == folded:
                        raise DependencyFreezeError(
                            "Case-colliding release input paths are forbidden: "
                            f"{_join_relative(WINDOWS_NATIVE_HOST_LIB_SYMLINK_DIR, known)} and "
                            f"{_join_relative(WINDOWS_NATIVE_HOST_LIB_SYMLINK_DIR, name)}"
                        )
                raise DependencyFreezeError(
                    "Native-messaging host symlink alias directory has an unexpected entry: "
                    f"{name}"
                )
            entry_rel = _join_relative(WINDOWS_NATIVE_HOST_LIB_SYMLINK_DIR, name)
            entry_info = _lstat_at(alias_fd, name, entry_rel)
            if not stat.S_ISLNK(entry_info.st_mode):
                alias, _target = expected_by_name[name]
                raise DependencyFreezeError(
                    f"Native-messaging host symlink alias must be a symbolic link: {alias}"
                )
        missing = set(expected_by_name) - observed
        if missing:
            name = sorted(missing)[0]
            raise DependencyFreezeError(
                f"Native-messaging host symlink alias is missing: {expected_by_name[name][0]}"
            )

        bound: list[tuple[str, str]] = []
        for alias, expected_target in WINDOWS_NATIVE_HOST_LIB_SYMLINK_ALIASES:
            alias_name = pathlib.PurePosixPath(alias).name
            alias_info = _lstat_at(alias_fd, alias_name, alias)
            if not stat.S_ISLNK(alias_info.st_mode):
                raise DependencyFreezeError(
                    f"Native-messaging host symlink alias must be a symbolic link: {alias}"
                )
            try:
                link_text = os.readlink(alias_name, dir_fd=alias_fd)
            except OSError as exc:
                raise DependencyFreezeError(
                    f"Native-messaging host symlink alias is unreadable: {alias}"
                ) from exc
            if isinstance(link_text, bytes):
                link_text = os.fsdecode(link_text)
            if os.path.isabs(link_text) or os.path.isabs(expected_target):
                raise DependencyFreezeError(
                    f"Native-messaging host symlink alias target must not be absolute: {alias}"
                )
            if link_text != expected_target:
                raise DependencyFreezeError(
                    "Native-messaging host symlink alias target is not the exact expected relative "
                    f"path: {alias}"
                )
            target_rel = _normalized_symlink_target(alias, link_text)
            expected_lib_rel = f"lib/{pathlib.PurePosixPath(alias).name}"
            if target_rel != expected_lib_rel:
                raise DependencyFreezeError(
                    "Native-messaging host symlink alias target is not the exact expected relative "
                    f"path: {alias}"
                )
            payload, _identity, target_info = _read_relative_file(
                repo_fd, expected_lib_rel, allowed_owners
            )
            del payload
            if not stat.S_ISREG(target_info.st_mode):
                raise DependencyFreezeError(
                    "Native-messaging host symlink alias target must be a regular file bound by lib: "
                    f"{alias}"
                )
            bound.append((alias, expected_target))
        return tuple(bound)
    finally:
        os.close(alias_fd)


def _add_selected(
    selected: dict[str, tuple[str, tuple[int, ...]]],
    relative: str,
    identity: tuple[int, ...],
    *,
    size: int,
    aggregate_bytes: int,
) -> int:
    if len(selected) + 1 > MAX_DEPENDENCY_FILE_COUNT:
        raise DependencyFreezeError(
            "dependency file count is outside the accepted bound"
        )
    added = aggregate_bytes + size
    if added > MAX_DEPENDENCY_AGGREGATE_BYTES:
        raise DependencyFreezeError(
            "dependency aggregate size is outside the accepted bound"
        )
    if size < 0 or size > MAX_DEPENDENCY_FILE_BYTES:
        raise DependencyFreezeError(
            f"dependency input size is outside the accepted bound: {relative}"
        )
    key = _fold_key(relative)
    existing = selected.get(key)
    if existing is not None and existing[0] != relative:
        raise DependencyFreezeError(
            "Case-colliding release input paths are forbidden: "
            f"{existing[0]} and {relative}"
        )
    selected[key] = (relative, identity)
    return added


def _inspect_unhashed_tree(
    dir_fd: int,
    dir_info: os.stat_result,
    relative: str,
    allowed_owners: frozenset[int],
    inspected: int = 0,
) -> int:
    """Reject unsafe nodes in excluded trees without hashing ordinary caches."""

    _require_owned_mode(relative, dir_info, allowed_owners, kind="dependency directory")
    names = _list_directory_names(dir_fd, relative)
    for name in names:
        inspected += 1
        if inspected > MAX_DEPENDENCY_FILE_COUNT:
            raise DependencyFreezeError(
                "dependency file count is outside the accepted bound"
            )
        child_rel = _join_relative(relative, name)
        child_info = _lstat_at(dir_fd, name, child_rel)
        if _is_reparse_stat(child_info):
            raise DependencyFreezeError(
                "Symlink, junction, or reparse point is forbidden in release inputs: "
                f"{child_rel}"
            )
        if _is_special_node(child_info):
            raise DependencyFreezeError(
                f"dependency path must be a regular file or directory: {child_rel}"
            )
        if stat.S_ISDIR(child_info.st_mode):
            child_fd, bound = _bind_directory_fd(
                dir_fd, name, child_rel, allowed_owners
            )
            try:
                inspected = _inspect_unhashed_tree(
                    child_fd,
                    bound,
                    child_rel,
                    allowed_owners,
                    inspected,
                )
            finally:
                os.close(child_fd)
            continue
        if not stat.S_ISREG(child_info.st_mode):
            raise DependencyFreezeError(
                f"dependency path must be a regular file or directory: {child_rel}"
            )
        if child_info.st_nlink != 1:
            raise DependencyFreezeError(
                f"dependency input must have link count 1: {child_rel}"
            )
        _require_owned_mode(child_rel, child_info, allowed_owners, kind="dependency file")
        _reject_oversized_file(child_rel, child_info)
    rebound = os.fstat(dir_fd)
    if _file_identity(rebound) != _file_identity(dir_info):
        raise DependencyFreezeError(
            f"dependency directory identity changed while traversing: {relative}"
        )
    return inspected


def _walk_dependency_directory(
    dir_fd: int,
    dir_info: os.stat_result,
    relative: str,
    allowed_owners: frozenset[int],
    selected: dict[str, tuple[str, tuple[int, ...]]],
    aggregate_bytes: int,
    directories: dict[str, tuple[int, ...]],
) -> int:
    names = _list_directory_names(dir_fd, relative)
    excluded_dirs = {_fold_key(item) for item in EXCLUDED_DIR_NAMES}
    for name in names:
        child_rel = _join_relative(relative, name)
        child_info = _lstat_at(dir_fd, name, child_rel)
        if _is_reparse_stat(child_info):
            raise DependencyFreezeError(
                "Symlink, junction, or reparse point is forbidden in release inputs: "
                f"{child_rel}"
            )
        if _is_special_node(child_info):
            raise DependencyFreezeError(
                f"dependency path must be a regular file or directory: {child_rel}"
            )
        if stat.S_ISDIR(child_info.st_mode):
            child_fd, bound = _bind_directory_fd(
                dir_fd, name, child_rel, allowed_owners
            )
            try:
                if _fold_key(name) in excluded_dirs or _is_excluded(
                    pathlib.PurePosixPath(child_rel) / ".keep"
                ):
                    _inspect_unhashed_tree(
                        child_fd, bound, child_rel, allowed_owners
                    )
                else:
                    directories[child_rel] = _file_identity(bound)
                    aggregate_bytes = _walk_dependency_directory(
                        child_fd,
                        bound,
                        child_rel,
                        allowed_owners,
                        selected,
                        aggregate_bytes,
                        directories,
                    )
            finally:
                os.close(child_fd)
            continue
        if not stat.S_ISREG(child_info.st_mode):
            raise DependencyFreezeError(
                f"dependency path must be a regular file or directory: {child_rel}"
            )
        if child_info.st_nlink != 1:
            raise DependencyFreezeError(
                f"dependency input must have link count 1: {child_rel}"
            )
        if _is_excluded(pathlib.PurePosixPath(child_rel)):
            _require_owned_mode(child_rel, child_info, allowed_owners, kind="dependency file")
            _reject_oversized_file(child_rel, child_info)
            continue
        _assert_not_forbidden(pathlib.PurePosixPath(child_rel))
        _reject_oversized_file(child_rel, child_info)
        aggregate_bytes = _add_selected(
            selected,
            child_rel,
            _file_identity(child_info),
            size=child_info.st_size,
            aggregate_bytes=aggregate_bytes,
        )
    rebound = os.fstat(dir_fd)
    if _file_identity(rebound) != _file_identity(dir_info):
        raise DependencyFreezeError(
            f"dependency directory identity changed while traversing: {relative}"
        )
    return aggregate_bytes


def _selected_paths(
    repo_fd: int,
    roots: Iterable[str],
    allowed_owners: frozenset[int],
) -> tuple[
    list[tuple[str, tuple[int, ...]]],
    tuple[tuple[str, tuple[int, ...]], ...],
]:
    selected: dict[str, tuple[str, tuple[int, ...]]] = {}
    directories: dict[str, tuple[int, ...]] = {}
    aggregate_bytes = 0
    path_list = tuple(roots)
    _reject_configured_path_components(repo_fd, path_list, allowed_owners)
    for raw_root in path_list:
        parts = _split_relative(raw_root)
        current = repo_fd
        owned: list[int] = []
        rel = ""
        try:
            try:
                root_info = os.lstat(parts[0], dir_fd=repo_fd)
            except FileNotFoundError:
                raise DependencyFreezeError(
                    f"Required input root is missing: {raw_root}"
                )
            except OSError as exc:
                raise DependencyFreezeError(
                    f"Unable to inspect release input: {raw_root}"
                ) from exc
            if _is_reparse_stat(root_info):
                raise DependencyFreezeError(
                    "Symlink, junction, or reparse point is forbidden in release inputs: "
                    f"{raw_root}"
                )
            _assert_regular_or_directory(root_info, parts[0])
            for part in parts[:-1]:
                rel = _join_relative(rel, part)
                nxt, _info = _bind_directory_fd(current, part, rel, allowed_owners)
                owned.append(nxt)
                current = nxt
                directories[rel] = _file_identity(_info)
            leaf = parts[-1]
            leaf_rel = raw_root.replace("\\", "/")
            leaf_info = _lstat_at(current, leaf, leaf_rel)
            _assert_regular_or_directory(leaf_info, leaf_rel)
            if _is_reparse_stat(leaf_info):
                raise DependencyFreezeError(
                    "Symlink, junction, or reparse point is forbidden in release inputs: "
                    f"{leaf_rel}"
                )
            if stat.S_ISREG(leaf_info.st_mode):
                _reject_casefold_lookup(current, _parent_relative(leaf_rel), leaf)
                if not _is_excluded(pathlib.PurePosixPath(leaf_rel)):
                    _assert_not_forbidden(pathlib.PurePosixPath(leaf_rel))
                    aggregate_bytes = _add_selected(
                        selected,
                        leaf_rel,
                        _file_identity(leaf_info),
                        size=leaf_info.st_size,
                        aggregate_bytes=aggregate_bytes,
                    )
                continue
            if not stat.S_ISDIR(leaf_info.st_mode):
                raise DependencyFreezeError(
                    f"dependency path must be a regular file or directory: {leaf_rel}"
                )
            leaf_fd, bound = _bind_directory_fd(
                current, leaf, leaf_rel, allowed_owners
            )
            owned.append(leaf_fd)
            directories[leaf_rel] = _file_identity(bound)
            aggregate_bytes = _walk_dependency_directory(
                leaf_fd,
                bound,
                leaf_rel,
                allowed_owners,
                selected,
                aggregate_bytes,
                directories,
            )
        finally:
            for descriptor in reversed(owned):
                _close_quietly(descriptor)
    return (
        sorted(selected.values(), key=lambda item: _fold_key(item[0])),
        tuple(sorted(directories.items(), key=lambda item: _fold_key(item[0]))),
    )


def _capture_input_state(
    repo: pathlib.Path,
    roots: Iterable[str],
    allowed_owners: frozenset[int],
    *,
    bind_windows_host_lib_aliases: bool = False,
) -> _InputCapture:
    repo_fd, repo_info = _open_repo_dir(repo, allowed_owners)
    git_repository_custody: _GitRepositoryCustody | None = None
    try:
        root_list = tuple(roots)
        if not isolated_fixture_mode_active() and _git_metadata_kind(repo) is not None:
            git_repository_custody = _open_git_repository_custody(
                repo, allowed_owners
            )
            if git_repository_custody.repo_identity != _file_identity(repo_info):
                raise DependencyFreezeError("Git repository root custody changed.")
        first_git = _bind_production_git_tree(repo, git_repository_custody)
        selected, directories = _selected_paths(
            repo_fd, root_list, allowed_owners
        )
        hook = _POST_SELECT_HOOK
        if callable(hook):
            hook()
        if not selected:
            raise DependencyFreezeError("No dependency inputs were selected.")
        if len(selected) > MAX_DEPENDENCY_FILE_COUNT:
            raise DependencyFreezeError(
                "dependency file count is outside the accepted bound"
            )
        aggregate = hashlib.sha256()
        aggregate.update(b"winsvpn-release-semantic-inputs-v2\0")
        files: list[InputFile] = []
        identities: list[tuple[str, tuple[int, ...]]] = []
        payloads: dict[str, bytes] = {}
        selected_blobs: list[tuple[str, str, str]] = []
        total_bytes = 0
        for relative, select_identity in selected:
            active_pubspec = (
                _operation_pubspec(repo)
                if relative == "pubspec.yaml"
                else None
            )
            if active_pubspec is not None:
                payload = active_pubspec.payload
                identity = active_pubspec.identity
                info = os.fstat(active_pubspec.components[-1].descriptor)
            else:
                payload, identity, info = _read_relative_file(
                    repo_fd,
                    relative,
                    allowed_owners,
                    label="dependency input",
                )
            if identity != select_identity or identity != _file_identity(info):
                raise DependencyFreezeError(
                    f"dependency input changed between selection and read: {relative}"
                )
            file_hash = hashlib.sha256(payload).hexdigest()
            size = len(payload)
            if total_bytes + size > MAX_DEPENDENCY_AGGREGATE_BYTES:
                raise DependencyFreezeError(
                    "dependency aggregate size is outside the accepted bound"
                )
            if len(files) + 1 > MAX_DEPENDENCY_FILE_COUNT:
                raise DependencyFreezeError(
                    "dependency file count is outside the accepted bound"
                )
            aggregate.update(relative.encode("utf-8"))
            aggregate.update(b"\0")
            if first_git is None:
                executable = bool(
                    info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                )
                git_mode = "100755" if executable else "100644"
                git_oid = _git_blob_oid(payload, "sha256")
            else:
                git_record = first_git.blobs.get(relative)
                git_mode = git_record[0] if git_record is not None else "untracked"
                git_oid = git_record[2] if git_record is not None else "untracked"
            aggregate.update(git_mode.encode("ascii"))
            aggregate.update(b"\0")
            aggregate.update(git_oid.encode("ascii"))
            aggregate.update(b"\0")
            aggregate.update(file_hash.encode("ascii"))
            aggregate.update(b"\0")
            aggregate.update(str(size).encode("ascii"))
            aggregate.update(b"\0")
            files.append(InputFile(relative, size, file_hash))
            identities.append((relative, identity))
            payloads[relative] = payload
            if first_git is not None:
                selected_blobs.append((relative, git_mode, git_oid))
            total_bytes += size
        aliases: tuple[tuple[str, str], ...] = ()
        if bind_windows_host_lib_aliases:
            aliases = _bind_windows_native_host_lib_aliases_at(
                repo_fd, allowed_owners
            )
            for alias, target in aliases:
                alias_record = (
                    first_git.blobs.get(alias) if first_git is not None else None
                )
                alias_mode = alias_record[0] if alias_record is not None else "untracked"
                alias_oid = alias_record[2] if alias_record is not None else "untracked"
                aggregate.update(b"symlink-alias\0")
                aggregate.update(alias.encode("utf-8"))
                aggregate.update(b"\0")
                aggregate.update(target.encode("utf-8"))
                aggregate.update(b"\0")
                aggregate.update(alias_mode.encode("ascii"))
                aggregate.update(b"\0")
                aggregate.update(alias_oid.encode("ascii"))
                aggregate.update(b"\0")
                if first_git is not None:
                    selected_blobs.append((alias, alias_mode, alias_oid))
        selected_paths = tuple(relative for relative, _identity in selected)
        controller_payload = payloads.get("tools/release_dependency_freeze.py")
        if not isolated_fixture_mode_active() and (
            _PRODUCTION_REQUIRED or controller_payload is not None
        ):
            _require_executing_controller(repo, controller_payload)
        _require_production_git_inputs(
            first_git,
            selected_paths,
            payloads,
            aliases,
            root_list,
            identities,
        )
        second_git = _bind_production_git_tree(repo, git_repository_custody)
        if first_git != second_git:
            raise DependencyFreezeError(GIT_DIRTY_SOURCE)
        rebound = _rebind_requested_path(
            repo,
            repo_fd,
            repo_info,
            kind="Repository root",
            directory=True,
        )
        if _file_identity(rebound) != _file_identity(repo_info):
            raise DependencyFreezeError(
                "Repository root identity changed during freeze capture."
            )
        return _InputCapture(
            state=InputState(
                fingerprint_sha256=aggregate.hexdigest(),
                file_count=len(files),
                total_bytes=total_bytes,
                files=tuple(files),
                git_audit=(
                    GitAudit(
                        object_format=first_git.object_format,
                        git_executable_sha256=first_git.git_executable_sha256,
                        head=first_git.head,
                        tree=first_git.tree,
                        selected_blobs=tuple(
                            sorted(selected_blobs, key=lambda item: item[0].casefold())
                        ),
                    )
                    if first_git is not None
                    else None
                ),
            ),
            selected=selected_paths,
            identities=tuple(identities),
            directories=directories,
            aliases=aliases,
        )
    finally:
        if git_repository_custody is not None:
            _close_git_repository_custody(git_repository_custody)
        os.close(repo_fd)


def input_state(
    repo: pathlib.Path,
    roots: Iterable[str],
    *,
    bind_windows_host_lib_aliases: bool = False,
) -> InputState:
    _ensure_open_file_soft_limit()
    repo = secure_repo_path(repo, pathlib.Path("."), "Repository root", must_exist=True)
    roots = tuple(roots)
    allowed_owners = _allowed_owners(repo)
    first = _capture_input_state(
        repo,
        roots,
        allowed_owners,
        bind_windows_host_lib_aliases=bind_windows_host_lib_aliases,
    )
    active_directories = _ACTIVE_RETURN_DIRECTORY_CUSTODY.get()
    local_directories: list[_HeldDirectory] = []
    retained_directories = (
        active_directories if active_directories is not None else local_directories
    )
    existing = {
        (
            held.components[-1].relative
            if held.components
            else "."
        ): held
        for held in retained_directories
    }
    try:
        for relative, expected_identity in first.directories:
            held_directory = existing.get(relative)
            if held_directory is None:
                held_directory = _hold_repo_directory(
                    repo,
                    repo / relative,
                    allowed_owners,
                    label=f"Retained compiler-input directory {relative}",
                    watch_writes=True,
                )
                retained_directories.append(held_directory)
                existing[relative] = held_directory
            if (
                not held_directory.components
                or held_directory.components[-1].identity != expected_identity
            ):
                raise DependencyFreezeError(
                    f"compiler-input directory changed before retention: {relative}"
                )
            _rebind_held_directory(held_directory)
        hook = _POST_INPUT_CAPTURE_HOOK
        if callable(hook):
            hook()
        second = _capture_input_state(
            repo,
            roots,
            allowed_owners,
            bind_windows_host_lib_aliases=bind_windows_host_lib_aliases,
        )
        if (
            first.state != second.state
            or first.selected != second.selected
            or first.identities != second.identities
            or first.directories != second.directories
            or first.aliases != second.aliases
        ):
            raise DependencyFreezeError(
                "dependency inputs changed during freeze capture"
            )
        for relative, _expected_identity in first.directories:
            _rebind_held_directory(existing[relative])
        repo_fd, repo_info = _open_repo_dir(repo, allowed_owners)
        try:
            _rebind_requested_path(
                repo,
                repo_fd,
                repo_info,
                kind="Repository root",
                directory=True,
            )
        finally:
            os.close(repo_fd)
        if _ACTIVE_RETURN_FILE_CUSTODY.get() is not None:
            for item in first.state.files:
                if item.path == "pubspec.yaml":
                    held_pubspec = _operation_pubspec(repo)
                    if held_pubspec is not None:
                        if (
                            held_pubspec.info.st_size != item.size
                            or hashlib.sha256(held_pubspec.payload).hexdigest()
                            != item.sha256
                        ):
                            raise DependencyFreezeError(
                                "dependency input changed before return-bound custody: "
                                "pubspec.yaml"
                            )
                        continue
                held = _hold_repo_regular_file(
                    repo,
                    repo / item.path,
                    allowed_owners,
                    label=f"Retained dependency input {item.path}",
                )
                if (
                    held.info.st_size != item.size
                    or hashlib.sha256(held.payload).hexdigest() != item.sha256
                ):
                    _close_held_regular_file(held)
                    raise DependencyFreezeError(
                        f"dependency input changed before return-bound custody: {item.path}"
                    )
                _retain_regular_file_until_return(held)
        return first.state
    finally:
        if active_directories is None:
            for held_directory in reversed(local_directories):
                _close_held_directory(held_directory)


def _utc_now() -> str:
    return dt.datetime.now(tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _state_record(state: InputState, *, include_files: bool = True) -> dict[str, object]:
    record: dict[str, object] = {
        "fingerprint_sha256": state.fingerprint_sha256,
        "file_count": state.file_count,
        "total_bytes": state.total_bytes,
        "git_audit": (
            {
                "object_format": state.git_audit.object_format,
                "git_executable_sha256": state.git_audit.git_executable_sha256,
                "binding_scope": "selected-blobs-semantic-v1",
                "selected_blobs": [
                    {"path": path, "mode": mode, "oid": oid}
                    for path, mode, oid in state.git_audit.selected_blobs
                ],
            }
            if state.git_audit is not None
            else None
        ),
    }
    if include_files:
        record["files"] = [dataclasses.asdict(item) for item in state.files]
    return record


def _validate_timestamp(value: object, label: str) -> None:
    _parse_timestamp(value, label)


def _parse_timestamp(value: object, label: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise DependencyFreezeError(f"{label} timestamp is invalid.")
    try:
        return dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise DependencyFreezeError(f"{label} timestamp is invalid.") from exc


def _require_exact_keys(record: object, expected: set[str], label: str) -> dict[str, object]:
    if type(record) is not dict or set(record) != expected:
        raise DependencyFreezeError(f"{label} schema fields are invalid.")
    return record


def _canonical_json(record: dict[str, object]) -> bytes:
    _require_finite_json(record, "JSON record")
    try:
        text = json.dumps(record, allow_nan=False, indent=2, sort_keys=True)
    except (TypeError, ValueError) as suc:
        raise DependencyFreezeError("JSON record is not serializable.") from suc
    return (text + "\n").encode("utf-8")


def _ensure_private_artifacts_parent(
    repo: pathlib.Path,
    parent: pathlib.Path,
    allowed_owners: frozenset[int],
) -> None:
    try:
        relative = parent.relative_to(repo)
    except ValueError as exc:
        raise DependencyFreezeError(
            "Dependency manifest parent must stay inside the repository."
        ) from exc
    if (
        not relative.parts
        or relative.parts[0] != ".artifacts"
        or any(
            _fold_key(part).startswith((".build-attempt-", ".freeze-staging-"))
            for part in relative.parts[1:]
        )
    ):
        raise DependencyFreezeError(
            "Dependency manifest parent must stay in a non-transaction .artifacts path."
        )
    repo_fd, _repo_info = _open_repo_dir(repo, allowed_owners)
    current = repo_fd
    owned: list[int] = []
    current_relative = ""
    try:
        for part in relative.parts:
            next_relative = _join_relative(current_relative, part)
            _reject_casefold_lookup(current, current_relative, part)
            created = False
            try:
                info = os.lstat(part, dir_fd=current)
            except FileNotFoundError:
                try:
                    os.mkdir(part, 0o700, dir_fd=current)
                    _fsync_directory(current, "dependency manifest parent")
                    created = True
                    info = os.lstat(part, dir_fd=current)
                except OSError as exc:
                    raise DependencyFreezeError(
                        "Unable to create private dependency manifest parent."
                    ) from exc
            if _is_reparse_stat(info) or not stat.S_ISDIR(info.st_mode):
                raise DependencyFreezeError(
                    "Dependency manifest parent contains an unsafe component."
                )
            descriptor, opened = _bind_directory_fd(
                current, part, next_relative, allowed_owners
            )
            if created and stat.S_IMODE(opened.st_mode) != 0o700:
                os.close(descriptor)
                raise DependencyFreezeError(
                    "Created dependency manifest parent mode changed."
                )
            owned.append(descriptor)
            current = descriptor
            current_relative = next_relative
    finally:
        for descriptor in reversed(owned):
            _close_quietly(descriptor)
        _close_quietly(repo_fd)


def _write_new(
    repo: pathlib.Path,
    path: pathlib.Path,
    record: dict[str, object],
    label: str,
) -> None:
    _write_new_bytes(repo, path, _canonical_json(record), label)


def _write_new_bytes(
    repo: pathlib.Path,
    path: pathlib.Path,
    payload: bytes,
    label: str,
) -> None:
    if not payload or len(payload) > MAX_DEPENDENCY_JSON_BYTES:
        raise DependencyFreezeError(f"{label} payload is outside the accepted bound.")
    owners = _allowed_owners(repo)
    _ensure_private_artifacts_parent(repo, path.parent, owners)
    held_parent = _hold_repo_directory(
        repo, path.parent, owners, label=f"{label} parent"
    )
    parent_fd = held_parent.components[-1].descriptor
    descriptor: int | None = None
    held_output: _HeldRegularFile | None = None
    identity: tuple[int, int] | None = None
    committed = False
    try:
        _reject_casefold_lookup(parent_fd, _relative_repo_path(repo, path.parent), path.name)
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(path.name, flags, 0o400, dir_fd=parent_fd)
        except FileExistsError as exc:
            raise DependencyFreezeError(
                f"Refusing to overwrite immutable {label.lower()}: {path}"
            ) from exc
        view = memoryview(payload)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise DependencyFreezeError(f"Unable to write {label.lower()} completely.")
            offset += written
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        path_info = os.lstat(path.name, dir_fd=parent_fd)
        identity = (int(info.st_dev), int(info.st_ino))
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size != len(payload)
            or stat.S_IMODE(info.st_mode) != 0o400
            or (path_info.st_dev, path_info.st_ino) != identity
        ):
            raise DependencyFreezeError(f"{label} publication custody is invalid.")
        _fsync_directory(parent_fd, f"{label} parent")
        committed = True
        held_output = _hold_repo_regular_file(repo, path, owners, label=label)
        if (
            held_output.payload != payload
            or (held_output.info.st_dev, held_output.info.st_ino) != identity
            or held_output.info.st_nlink != 1
            or stat.S_IMODE(held_output.info.st_mode) != 0o400
        ):
            raise DependencyFreezeError(f"{label} changed after durable publication.")
        _rebind_publication_directory(held_parent)
        _retain_regular_file_until_return(held_output)
        held_output = None
    except OSError as exc:
        raise DependencyFreezeError(f"Unable to publish {label.lower()}: {exc}") from exc
    except Exception:
        if not committed and identity is not None:
            _strict_unlink_if_same_inode(parent_fd, path.name, identity, label)
        raise
    finally:
        if held_output is not None:
            _close_held_regular_file(held_output)
        _close_quietly(descriptor)
        _close_held_directory(held_parent)


def _sha256_file(
    path: pathlib.Path,
    allowed_owners: frozenset[int] | None = None,
    *,
    max_bytes: int = MAX_DEPENDENCY_FILE_BYTES,
    label: str = "dependency manifest",
    repo: pathlib.Path | None = None,
) -> str:
    owners = allowed_owners if allowed_owners is not None else _fallback_owners(path)
    payload, _identity, _info = _stable_read_regular_file(
        path, owners, max_bytes=max_bytes, label=label, repo=repo
    )
    return hashlib.sha256(payload).hexdigest()


def _read_anchor_text(
    path: pathlib.Path,
    allowed_owners: frozenset[int],
    label: str,
    *,
    repo: pathlib.Path | None = None,
) -> str:
    payload, _identity, _info = _stable_read_regular_file(
        path,
        allowed_owners,
        max_bytes=MAX_DEPENDENCY_JSON_BYTES,
        label=label,
        repo=repo,
    )
    try:
        return payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DependencyFreezeError(f"{label} is not valid ASCII.") from exc


def _reviewed_flutter_toolchain(repo: pathlib.Path) -> tuple[str, str]:
    """Return the exact Flutter identity that a Flutter receipt must claim."""

    path = secure_repo_path(
        repo, pathlib.Path("tools/toolchain-pins.json"), "Toolchain pin manifest", must_exist=True
    )
    owners = _allowed_owners(repo)
    try:
        document, _digest = _read_json_file(
            path, owners, "Reviewed Flutter toolchain pin", repo=repo
        )
        tools = document.get("tools")
        if type(tools) is not dict:
            raise DependencyFreezeError("Reviewed Flutter toolchain pin is malformed.")
        flutter = tools.get("flutter")
        if type(flutter) is not dict:
            raise DependencyFreezeError("Reviewed Flutter toolchain pin is malformed.")
        version = flutter.get("version")
        revision = flutter.get("revision")
    except DependencyFreezeError:
        raise
    except (OSError, KeyError, TypeError) as exc:
        raise DependencyFreezeError(f"Reviewed Flutter toolchain pin is unreadable: {exc}") from exc
    if (
        type(version) is not str
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
        or type(revision) is not str
        or not re.fullmatch(r"[0-9a-f]{40}", revision)
    ):
        raise DependencyFreezeError("Reviewed Flutter toolchain pin is malformed.")
    return version, revision


def _reviewed_toolchain_pin(repo: pathlib.Path, key: str) -> dict[str, object]:
    """Return ``tools.<key>`` of tools/toolchain-pins.json, refusing a malformed pin."""

    path = secure_repo_path(
        repo, pathlib.Path("tools/toolchain-pins.json"), "Toolchain pin manifest", must_exist=True
    )
    document, _digest = _read_json_file(
        path, _allowed_owners(repo), f"Reviewed {key} toolchain pin", repo=repo
    )
    tools = document.get("tools")
    pin = tools.get(key) if type(tools) is dict else None
    if type(pin) is not dict:
        raise DependencyFreezeError(f"Reviewed {key} toolchain pin is malformed.")
    return pin


def _assert_toolchain_matches_reviewed_pin(
    repo: pathlib.Path, name: str, version: str, revision: str
) -> None:
    """Reject a receipt whose pinned toolchain label differs from its pin.

    Flutter, Xcode and Gradle have reviewed pins; other names (esbuild) have
    none in tools/toolchain-pins.json and are recorded as labels only.
    """

    folded = name.casefold()
    if folded == "flutter":
        expected_version, expected_revision = _reviewed_flutter_toolchain(repo)
        if version != expected_version or revision != expected_revision:
            raise DependencyFreezeError(
                "Flutter build receipt does not match the reviewed Flutter toolchain pin."
            )
        return
    if folded == "xcode":
        pin = _reviewed_toolchain_pin(repo, "xcode")
        if (
            type(pin.get("version")) is not str
            or type(pin.get("build")) is not str
            or version != pin["version"]
            or revision != pin["build"]
        ):
            raise DependencyFreezeError(
                "Xcode build receipt does not match the reviewed Xcode toolchain pin."
            )
        return
    if folded == "gradle":
        pin = _reviewed_toolchain_pin(repo, "gradle")
        flavours = pin.get("distribution_sha256_by_flavour")
        if (
            type(pin.get("distribution_version")) is not str
            or version != pin["distribution_version"]
            or type(flavours) is not dict
            or not re.fullmatch(r"[0-9a-f]{64}", revision)
            or revision not in flavours.values()
        ):
            raise DependencyFreezeError(
                "Gradle build receipt does not match the reviewed Gradle toolchain pin."
            )


@_retain_anchored_inputs_until_return
def create_shared_manifest(
    repo: pathlib.Path, output: pathlib.Path, revision: str
) -> dict[str, object]:
    repo = secure_repo_path(repo, pathlib.Path("."), "Repository root", must_exist=True)
    _assert_canonical_platforms()
    output = _require_artifacts_output(
        repo, output, "Shared manifest output", allow_missing_leaf=True
    )
    _ensure_private_artifacts_parent(repo, output.parent, _allowed_owners(repo))
    revision = revision.strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", revision):
        raise DependencyFreezeError(
            "Shared revision must use 1-64 letters, digits, dots, underscores, or dashes."
        )
    roots = shared_roots(repo)
    state = input_state(repo, roots)
    if list(shared_roots(repo)) != list(roots):
        raise DependencyFreezeError("Shared dependency roots changed during freeze capture.")
    record: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "contract": SHARED_CONTRACT,
        "release": _release_identity(repo),
        "shared_revision": revision,
        "created_utc": _utc_now(),
        "roots": list(roots),
        "generated_outputs_excluded": True,
        "publication_authorized": False,
        "inputs": _state_record(state),
    }
    _write_new(repo, output, record, "Shared dependency manifest")
    return record


def _load_shared_manifest(
    path: pathlib.Path, repo: pathlib.Path
) -> tuple[dict[str, object], str]:
    owners = _allowed_owners(repo)
    path = secure_repo_path(repo, path, "Shared dependency manifest", must_exist=True)
    try:
        record, digest = _read_json_file(
            path, owners, "Shared dependency manifest", repo=repo
        )
    except DependencyFreezeError:
        raise
    except OSError as exc:
        raise DependencyFreezeError(f"Unable to read shared manifest: {exc}") from exc
    return _parse_shared_manifest(record, repo), digest


def _parse_shared_manifest(record: dict[str, object], repo: pathlib.Path) -> dict[str, object]:
    _require_exact_keys(
        record,
        {
            "schema_version",
            "contract",
            "release",
            "shared_revision",
            "created_utc",
            "roots",
            "generated_outputs_excluded",
            "publication_authorized",
            "inputs",
        },
        "Shared dependency manifest",
    )
    _validate_timestamp(record.get("created_utc"), "Shared dependency manifest")
    shared_revision = _require_str(record.get("shared_revision"), "Shared revision")
    if (
        _require_int(record.get("schema_version"), "Shared schema version") != SCHEMA_VERSION
        or _require_str(record.get("contract"), "Shared contract") != SHARED_CONTRACT
        or _require_str(record.get("release"), "Shared release") != _release_identity(repo)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", shared_revision)
        or _require_str_list(record.get("roots"), "Shared roots") != list(shared_roots(repo))
        or _require_bool(record.get("generated_outputs_excluded"), "generated_outputs_excluded")
        is not True
        or _require_bool(record.get("publication_authorized"), "publication_authorized")
        is not False
    ):
        raise DependencyFreezeError("Shared dependency manifest contract is invalid.")
    _validate_state_record(record.get("inputs"), require_files=True)
    return record


def _validate_state_record(
    record: object, *, require_files: bool
) -> tuple[
    str,
    int,
    int,
    tuple[InputFile, ...] | None,
    GitAudit | None,
]:
    expected_keys = {"fingerprint_sha256", "file_count", "total_bytes", "git_audit"}
    if require_files:
        expected_keys.add("files")
    state = _require_exact_keys(record, expected_keys, "Dependency input state")
    fingerprint = _require_sha256(state.get("fingerprint_sha256"), "Input fingerprint")
    file_count = _require_int(state.get("file_count"), "Input file count")
    total_bytes = _require_int(state.get("total_bytes"), "Input total bytes")
    if file_count <= 0 or total_bytes < 0:
        raise DependencyFreezeError("Dependency manifest input identity is malformed.")
    raw_git_audit = state.get("git_audit")
    selected_blob_paths: set[str] | None = None
    if raw_git_audit is None:
        if not isolated_fixture_mode_active():
            raise DependencyFreezeError("Dependency input Git audit is absent.")
    else:
        git_audit = _require_exact_keys(
            raw_git_audit,
            {
                "object_format",
                "git_executable_sha256",
                "binding_scope",
                "selected_blobs",
            },
            "Dependency input Git audit",
        )
        object_format = _require_str(
            git_audit.get("object_format"), "Git object format"
        )
        if object_format not in {"sha1", "sha256"}:
            raise DependencyFreezeError(
                "Dependency input Git object format is invalid."
            )
        if git_audit.get("binding_scope") != "selected-blobs-semantic-v1":
            raise DependencyFreezeError(
                "Dependency input Git semantic binding scope is invalid."
            )
        _require_sha256(
            git_audit.get("git_executable_sha256"), "Git executable digest"
        )
        oid_length = 40 if object_format == "sha1" else 64
        selected = _require_list(
            git_audit.get("selected_blobs"), "Git selected blobs"
        )
        parsed_blobs: list[tuple[str, str, str]] = []
        for raw in selected:
            item = _require_exact_keys(
                raw, {"path", "mode", "oid"}, "Git selected blob"
            )
            path = _require_str(
                item.get("path"), "Git selected blob path"
            ).replace("\\", "/")
            mode = _require_str(item.get("mode"), "Git selected blob mode")
            oid = _require_str(item.get("oid"), "Git selected blob OID")
            if (
                path.startswith("/")
                or ".." in pathlib.PurePosixPath(path).parts
                or mode not in {"100644", "100755", "120000"}
                or not re.fullmatch(rf"[0-9a-f]{{{oid_length}}}", oid)
            ):
                raise DependencyFreezeError(
                    "Dependency input Git selected blob is invalid."
                )
            parsed_blobs.append((path, mode, oid))
        if parsed_blobs != sorted(
            parsed_blobs, key=lambda item: item[0].casefold()
        ) or len({item[0].casefold() for item in parsed_blobs}) != len(
            parsed_blobs
        ):
            raise DependencyFreezeError(
                "Dependency input Git selected blobs are not canonical."
            )
        selected_blob_paths = {item[0] for item in parsed_blobs}
        expected_git_audit = GitAudit(
            object_format=object_format,
            git_executable_sha256=_require_sha256(
                git_audit.get("git_executable_sha256"), "Git executable digest"
            ),
            head="",
            tree="",
            selected_blobs=tuple(parsed_blobs),
        )
    if raw_git_audit is None:
        expected_git_audit = None
    expected_files: tuple[InputFile, ...] | None = None
    if require_files:
        raw_files = _require_list(state.get("files"), "Dependency manifest file list")
        if len(raw_files) != file_count:
            raise DependencyFreezeError("Dependency manifest file list is invalid.")
        parsed: list[InputFile] = []
        for raw in raw_files:
            item = _require_exact_keys(raw, {"path", "size", "sha256"}, "Input file")
            path = _require_str(item.get("path"), "Input file path")
            size = _require_int(item.get("size"), "Input file size")
            sha256 = _require_sha256(item.get("sha256"), "Input file digest")
            if (
                path.startswith(("/", "\\"))
                or ".." in pathlib.PurePosixPath(path.replace("\\", "/")).parts
                or size < 0
            ):
                raise DependencyFreezeError("Dependency manifest file entry is invalid.")
            parsed.append(InputFile(path.replace("\\", "/"), size, sha256))
        if parsed != sorted(parsed, key=lambda item: item.path.casefold()):
            raise DependencyFreezeError("Dependency manifest file list is not canonical.")
        if len({item.path.casefold() for item in parsed}) != len(parsed):
            raise DependencyFreezeError("Dependency manifest file list contains duplicates.")
        expected_files = tuple(parsed)
        if selected_blob_paths is not None and not {
            item.path for item in expected_files
        }.issubset(selected_blob_paths):
            raise DependencyFreezeError(
                "Dependency file list is outside the Git audit."
            )
    return fingerprint, file_count, total_bytes, expected_files, expected_git_audit


def _assert_state_matches(
    label: str, expected: object, actual: InputState, *, require_files: bool
) -> None:
    fingerprint, count, total_bytes, files, expected_git_audit = _validate_state_record(
        expected, require_files=require_files
    )
    if (
        actual.fingerprint_sha256 != fingerprint
        or actual.file_count != count
        or actual.total_bytes != total_bytes
    ):
        raise DependencyFreezeError(f"{label} dependency inputs changed.")
    if require_files and files != actual.files:
        raise DependencyFreezeError(f"{label} dependency file details changed.")
    if expected_git_audit is None:
        if actual.git_audit is not None:
            raise DependencyFreezeError(f"{label} dependency Git audit changed.")
    elif (
        actual.git_audit is None
        or actual.git_audit.object_format != expected_git_audit.object_format
        or actual.git_audit.git_executable_sha256
        != expected_git_audit.git_executable_sha256
        or actual.git_audit.selected_blobs != expected_git_audit.selected_blobs
    ):
        raise DependencyFreezeError(f"{label} dependency Git audit changed.")


@_retain_anchored_inputs_until_return
def create_platform_manifest(
    repo: pathlib.Path,
    platform: str,
    shared_manifest_path: pathlib.Path,
    output: pathlib.Path,
) -> dict[str, object]:
    repo = secure_repo_path(repo, pathlib.Path("."), "Repository root", must_exist=True)
    if platform not in PLATFORM_ROOTS:
        raise DependencyFreezeError(f"Unsupported platform: {platform}")
    _assert_canonical_platforms()
    _assert_required_gate_producers(platform)
    shared_manifest_path = secure_repo_path(
        repo, shared_manifest_path, "Shared dependency manifest", must_exist=True
    )
    output = _require_artifacts_output(
        repo, output, "Platform manifest output", allow_missing_leaf=True
    )
    _ensure_private_artifacts_parent(repo, output.parent, _allowed_owners(repo))
    shared, shared_digest = _load_shared_manifest(shared_manifest_path, repo)
    shared_state = input_state(repo, shared_roots(repo))
    _assert_state_matches(
        "Shared", shared.get("inputs"), shared_state, require_files=True
    )
    native_state = _platform_native_input_state(repo, platform)
    producer_state = input_state(repo, PLATFORM_PRODUCER_PATHS[platform])
    artifact_digest = hashlib.sha256()
    for value in (
        PLATFORM_CONTRACT,
        str(shared.get("shared_revision")),
        shared_state.fingerprint_sha256,
        native_state.fingerprint_sha256,
        producer_state.fingerprint_sha256,
    ):
        artifact_digest.update(value.encode("utf-8") + b"\0")
    record: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "contract": PLATFORM_CONTRACT,
        "release": shared["release"],
        "platform": platform,
        "created_utc": _utc_now(),
        "shared": {
            "revision": shared["shared_revision"],
            "manifest_path": os.path.relpath(shared_manifest_path, output.parent).replace(
                "\\", "/"
            ),
            "manifest_sha256": shared_digest,
            **_state_record(shared_state, include_files=False),
        },
        "native_roots": list(PLATFORM_ROOTS[platform]),
        "native_extra_paths": list(PLATFORM_NATIVE_EXTRA_PATHS[platform]),
        "native_inputs": _state_record(native_state),
        "producer_paths": list(PLATFORM_PRODUCER_PATHS[platform]),
        "producer_inputs": _state_record(producer_state),
        "artifact_input_fingerprint_sha256": artifact_digest.hexdigest(),
        "generated_outputs_excluded": True,
        "native_only_change_invalidates_only_this_platform": True,
        "publication_authorized": False,
    }
    _write_new(repo, output, record, f"{platform} dependency manifest")
    return record


@_retain_anchored_inputs_until_return
def verify_manifest(repo: pathlib.Path, manifest_path: pathlib.Path) -> dict[str, object]:
    result, _digest, _record = _verify_manifest_authenticated(repo, manifest_path)
    return result


def _verify_manifest_authenticated(
    repo: pathlib.Path, manifest_path: pathlib.Path
) -> tuple[dict[str, object], str, dict[str, object]]:
    repo = secure_repo_path(repo, pathlib.Path("."), "Repository root", must_exist=True)
    owners = _allowed_owners(repo)
    manifest_path = secure_repo_path(
        repo, manifest_path, "Dependency manifest", must_exist=True
    )
    try:
        record, digest = _read_json_file(
            manifest_path, owners, "Dependency manifest", repo=repo
        )
    except DependencyFreezeError:
        raise
    except OSError as exc:
        raise DependencyFreezeError(f"Unable to read dependency manifest: {exc}") from exc
    contract = record.get("contract")
    if contract == SHARED_CONTRACT:
        record = _parse_shared_manifest(record, repo)
        actual = input_state(repo, shared_roots(repo))
        _assert_state_matches(
            "Shared", record.get("inputs"), actual, require_files=True
        )
        return (
            {
                "ok": True,
                "kind": "shared",
                "fingerprint_sha256": actual.fingerprint_sha256,
                "file_count": actual.file_count,
            },
            digest,
            record,
        )
    if contract != PLATFORM_CONTRACT:
        raise DependencyFreezeError("Unsupported dependency manifest contract.")
    _require_exact_keys(
        record,
        {
            "schema_version",
            "contract",
            "release",
            "platform",
            "created_utc",
            "shared",
            "native_roots",
            "native_extra_paths",
            "native_inputs",
            "producer_paths",
            "producer_inputs",
            "artifact_input_fingerprint_sha256",
            "generated_outputs_excluded",
            "native_only_change_invalidates_only_this_platform",
            "publication_authorized",
        },
        "Platform dependency manifest",
    )
    _validate_timestamp(record.get("created_utc"), "Platform dependency manifest")
    platform = _require_str(record.get("platform"), "Platform")
    if platform not in PLATFORM_ROOTS:
        raise DependencyFreezeError("Platform dependency manifest is invalid.")
    _assert_required_gate_producers(platform)
    if (
        _require_int(record.get("schema_version"), "Platform schema version") != SCHEMA_VERSION
        or _require_str(record.get("release"), "Platform release") != _release_identity(repo)
        or _require_str_list(record.get("native_roots"), "Native roots")
        != list(PLATFORM_ROOTS[platform])
        or _require_str_list(record.get("native_extra_paths"), "Native extra paths")
        != list(PLATFORM_NATIVE_EXTRA_PATHS[platform])
        or _require_str_list(record.get("producer_paths"), "Producer paths")
        != list(PLATFORM_PRODUCER_PATHS[platform])
        or _require_bool(record.get("generated_outputs_excluded"), "generated_outputs_excluded")
        is not True
        or _require_bool(
            record.get("native_only_change_invalidates_only_this_platform"),
            "native_only_change_invalidates_only_this_platform",
        )
        is not True
        or _require_bool(record.get("publication_authorized"), "publication_authorized")
        is not False
    ):
        raise DependencyFreezeError("Platform dependency manifest contract is invalid.")
    shared_record = record.get("shared")
    shared_record = _require_exact_keys(
        shared_record,
        {
            "revision",
            "manifest_path",
            "manifest_sha256",
            "fingerprint_sha256",
            "file_count",
            "total_bytes",
            "git_audit",
        },
        "Platform shared reference",
    )
    shared_relative = _require_str(shared_record.get("manifest_path"), "Shared path")
    relative_path = pathlib.PurePosixPath(shared_relative.replace("\\", "/"))
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise DependencyFreezeError("Platform manifest shared path escapes its directory.")
    shared_path = secure_repo_path(
        repo,
        manifest_path.parent / relative_path,
        "Platform shared manifest reference",
        must_exist=True,
    )
    if not shared_path.is_relative_to(manifest_path.parent):
        raise DependencyFreezeError("Platform manifest shared path escapes its directory.")
    shared, shared_digest = _load_shared_manifest(shared_path, repo)
    if shared_digest != _require_sha256(
        shared_record.get("manifest_sha256"), "Shared manifest digest"
    ):
        raise DependencyFreezeError("Shared manifest file identity changed.")
    if shared.get("shared_revision") != _require_str(
        shared_record.get("revision"), "Shared revision"
    ):
        raise DependencyFreezeError("Shared revision reference changed.")
    actual_shared = input_state(repo, shared_roots(repo))
    _assert_state_matches(
        "Shared", shared.get("inputs"), actual_shared, require_files=True
    )
    _assert_state_matches(
        "Platform shared",
        {
            "fingerprint_sha256": shared_record.get("fingerprint_sha256"),
            "file_count": shared_record.get("file_count"),
            "total_bytes": shared_record.get("total_bytes"),
            "git_audit": shared_record.get("git_audit"),
        },
        actual_shared,
        require_files=False,
    )
    actual_native = _platform_native_input_state(repo, platform)
    _assert_state_matches(
        "Native", record.get("native_inputs"), actual_native, require_files=True
    )
    actual_producer = input_state(repo, PLATFORM_PRODUCER_PATHS[platform])
    _assert_state_matches(
        "Producer",
        record.get("producer_inputs"),
        actual_producer,
        require_files=True,
    )
    artifact_digest = hashlib.sha256()
    for value in (
        PLATFORM_CONTRACT,
        str(shared.get("shared_revision")),
        actual_shared.fingerprint_sha256,
        actual_native.fingerprint_sha256,
        actual_producer.fingerprint_sha256,
    ):
        artifact_digest.update(value.encode("utf-8") + b"\0")
    if artifact_digest.hexdigest() != _require_sha256(
        record.get("artifact_input_fingerprint_sha256"),
        "Artifact input fingerprint",
    ):
        raise DependencyFreezeError("Artifact input fingerprint changed.")
    return (
        {
            "ok": True,
            "kind": "platform",
            "platform": platform,
            "shared_revision": shared.get("shared_revision"),
            "shared_fingerprint_sha256": actual_shared.fingerprint_sha256,
            "native_fingerprint_sha256": actual_native.fingerprint_sha256,
            "producer_fingerprint_sha256": actual_producer.fingerprint_sha256,
            "artifact_input_fingerprint_sha256": artifact_digest.hexdigest(),
        },
        digest,
        record,
    )


def _normalize_index_scope(platforms: object) -> tuple[str, ...]:
    """Return the sorted platform scope for a scoped release input index."""

    if type(platforms) is str or not isinstance(platforms, Iterable):
        raise DependencyFreezeError(
            "A scoped release input index needs a list of platforms."
        )
    requested = tuple(platforms)
    if (
        not requested
        or any(type(item) is not str for item in requested)
        or len(set(requested)) != len(requested)
        or any(item not in PLATFORM_ROOTS for item in requested)
    ):
        raise DependencyFreezeError(
            "A scoped release input index needs a unique, non-empty list of "
            "supported platforms."
        )
    if set(requested) == set(CANONICAL_FREEZE_PLATFORMS):
        raise DependencyFreezeError(
            "A scoped release input index must leave at least one platform "
            "unfrozen; omit the scope to create the complete index."
        )
    return tuple(sorted(requested))


def _validate_scoped_index_scope(record: dict[str, object]) -> tuple[str, ...]:
    """Validate the scope fields of a scoped index and return the scope."""

    scope = _require_str_list(record.get("platform_scope"), "Indexed platform scope")
    unfrozen = _require_str_list(
        record.get("unfrozen_platforms"), "Indexed unfrozen platforms"
    )
    canonical = set(CANONICAL_FREEZE_PLATFORMS)
    if (
        not scope
        or scope != sorted(set(scope))
        or not set(scope) < canonical
        or unfrozen != sorted(canonical - set(scope))
    ):
        raise DependencyFreezeError("Release input index platform scope is invalid.")
    return tuple(scope)


@_retain_anchored_inputs_until_return
def create_release_index(
    repo: pathlib.Path,
    manifest_dir: pathlib.Path,
    output: pathlib.Path,
    platforms: Iterable[str] | None = None,
) -> dict[str, object]:
    repo = secure_repo_path(repo, pathlib.Path("."), "Repository root", must_exist=True)
    _assert_canonical_platforms()
    scope = None if platforms is None else _normalize_index_scope(platforms)
    manifest_dir = secure_repo_path(
        repo, manifest_dir, "Release manifest directory", must_exist=True
    )
    if manifest_dir.relative_to(repo).parts[0] != ".artifacts":
        raise DependencyFreezeError("Release manifest directory must stay under .artifacts/.")
    output = _require_artifacts_output(
        repo, output, "Release input index output", allow_missing_leaf=True
    )
    shared_path = manifest_dir / "SHARED_INPUTS.json"
    shared, shared_digest = _load_shared_manifest(shared_path, repo)
    shared_result, shared_verify_digest, _shared_record = _verify_manifest_authenticated(
        repo, shared_path
    )
    if shared_digest != shared_verify_digest or not shared_result.get("ok"):
        raise DependencyFreezeError("Shared manifest file identity changed.")
    manifests: dict[str, dict[str, object]] = {}
    for platform in sorted(PLATFORM_ROOTS) if scope is None else scope:
        path = manifest_dir / f"{platform.upper()}_INPUTS.json"
        result, digest, _record = _verify_manifest_authenticated(repo, path)
        if result.get("platform") != platform:
            raise DependencyFreezeError(f"Wrong platform manifest at {path}.")
        manifests[platform] = {
            "path": path.name,
            "sha256": digest,
            "artifact_input_fingerprint_sha256": result[
                "artifact_input_fingerprint_sha256"
            ],
        }
    anchor_path = output.with_name(output.name + ".sha256")
    record: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "contract": INDEX_CONTRACT if scope is None else SCOPED_INDEX_CONTRACT,
        "release": shared["release"],
        "shared_revision": shared["shared_revision"],
        "created_utc": _utc_now(),
        "shared_manifest": {
            "path": shared_path.name,
            "sha256": shared_digest,
        },
        "platform_manifests": manifests,
        "sha256_anchor": anchor_path.name,
        "manifest_set_complete": scope is None,
        "publication_authorized": False,
    }
    if scope is not None:
        record["platform_scope"] = list(scope)
        record["unfrozen_platforms"] = sorted(
            set(CANONICAL_FREEZE_PLATFORMS) - set(scope)
        )
    _write_anchored_record(repo, output, record, "Release input index")
    return record


@_retain_anchored_inputs_until_return
def verify_release_index(
    repo: pathlib.Path,
    index_path: pathlib.Path,
    platform: str | None = None,
) -> dict[str, object]:
    repo = secure_repo_path(repo, pathlib.Path("."), "Repository root", must_exist=True)
    _assert_canonical_platforms()
    index_path = secure_repo_path(
        repo, index_path, "Release input index", must_exist=True
    )
    if index_path.relative_to(repo).parts[0] != ".artifacts":
        raise DependencyFreezeError("Release input index must stay under .artifacts/.")
    anchor_path = index_path.with_name(index_path.name + ".sha256")
    record, index_digest = _read_anchored_json(
        repo, index_path, "Release input index"
    )
    owners = _allowed_owners(repo)
    scoped = record.get("contract") == SCOPED_INDEX_CONTRACT
    _require_exact_keys(
        record,
        INDEX_RECORD_KEYS | (SCOPED_INDEX_EXTRA_KEYS if scoped else frozenset()),
        "Release input index",
    )
    _validate_timestamp(record.get("created_utc"), "Release input index")
    if (
        _require_int(record.get("schema_version"), "Index schema version") != SCHEMA_VERSION
        or _require_str(record.get("contract"), "Index contract")
        != (SCOPED_INDEX_CONTRACT if scoped else INDEX_CONTRACT)
        or _require_str(record.get("release"), "Index release") != _release_identity(repo)
        or _require_str(record.get("sha256_anchor"), "Index anchor name") != anchor_path.name
        or _require_bool(record.get("manifest_set_complete"), "manifest_set_complete")
        != (not scoped)
        or _require_bool(record.get("publication_authorized"), "publication_authorized")
        is not False
    ):
        raise DependencyFreezeError("Release input index contract is invalid.")
    indexed_platforms = (
        _validate_scoped_index_scope(record)
        if scoped
        else tuple(sorted(CANONICAL_FREEZE_PLATFORMS))
    )
    shared_ref = _require_exact_keys(
        record.get("shared_manifest"), {"path", "sha256"}, "Indexed shared manifest"
    )
    shared_name = _require_str(shared_ref.get("path"), "Indexed shared path")
    if shared_name != "SHARED_INPUTS.json":
        raise DependencyFreezeError("Indexed shared manifest path is invalid.")
    shared_path = secure_repo_path(
        repo,
        index_path.parent / shared_name,
        "Indexed shared manifest",
        must_exist=True,
    )
    shared_result, shared_digest, shared = _verify_manifest_authenticated(
        repo, shared_path
    )
    if shared_digest != _require_sha256(
        shared_ref.get("sha256"), "Indexed shared digest"
    ):
        raise DependencyFreezeError("Indexed shared manifest identity changed.")
    if not shared_result.get("ok"):
        raise DependencyFreezeError("Indexed shared manifest identity changed.")
    if shared.get("shared_revision") != _require_str(
        record.get("shared_revision"), "Indexed shared revision"
    ):
        raise DependencyFreezeError("Indexed shared revision changed.")
    platform_refs = record.get("platform_manifests")
    if (
        type(platform_refs) is not dict
        or set(platform_refs) != set(indexed_platforms)
        or (not scoped and set(platform_refs) != set(PLATFORM_ROOTS))
    ):
        raise DependencyFreezeError(
            "Release input index platform set does not match its declared scope."
            if scoped
            else "Release input index platform set is incomplete."
        )
    if platform is not None and platform not in PLATFORM_ROOTS:
        raise DependencyFreezeError(f"Unsupported platform: {platform}")
    if scoped and platform is None:
        raise DependencyFreezeError(
            "A scoped release input index cannot satisfy a full-set verification; "
            "name a platform inside its scope."
        )
    if scoped and platform not in indexed_platforms:
        raise DependencyFreezeError(
            f"Platform {platform} is outside the scope of this release input index."
        )
    verified: dict[str, str] = {}
    for candidate_platform in indexed_platforms:
        reference = _require_exact_keys(
            platform_refs.get(candidate_platform),
            {"path", "sha256", "artifact_input_fingerprint_sha256"},
            f"Indexed {candidate_platform} manifest",
        )
        expected_name = f"{candidate_platform.upper()}_INPUTS.json"
        if _require_str(reference.get("path"), "Indexed platform path") != expected_name:
            raise DependencyFreezeError(
                f"Indexed {candidate_platform} manifest path is invalid."
            )
        path = secure_repo_path(
            repo,
            index_path.parent / expected_name,
            f"Indexed {candidate_platform} manifest",
            must_exist=True,
        )
        recorded_digest = _require_sha256(
            reference.get("sha256"), f"Indexed {candidate_platform} digest"
        )
        recorded_fingerprint = _require_sha256(
            reference.get("artifact_input_fingerprint_sha256"),
            f"Indexed {candidate_platform} artifact fingerprint",
        )
        if platform is None or candidate_platform == platform:
            result, digest, _record = _verify_manifest_authenticated(repo, path)
            if digest != recorded_digest:
                raise DependencyFreezeError(
                    f"Indexed {candidate_platform} manifest identity changed."
                )
            fingerprint = result.get("artifact_input_fingerprint_sha256")
            if fingerprint != recorded_fingerprint:
                raise DependencyFreezeError(
                    f"Indexed {candidate_platform} artifact input fingerprint changed."
                )
        else:
            held_manifest = _hold_repo_regular_file(
                repo,
                path,
                owners,
                label=f"Indexed {candidate_platform} manifest",
            )
            try:
                if len(held_manifest.payload) > MAX_DEPENDENCY_JSON_BYTES:
                    raise DependencyFreezeError(
                        f"Indexed {candidate_platform} manifest is too large."
                    )
                digest = hashlib.sha256(held_manifest.payload).hexdigest()
                _retain_regular_file_until_return(held_manifest)
            except Exception:
                _close_held_regular_file(held_manifest)
                raise
            if digest != recorded_digest:
                raise DependencyFreezeError(
                    f"Indexed {candidate_platform} manifest identity changed."
                )
        verified[candidate_platform] = recorded_fingerprint
    result: dict[str, object] = {
        "ok": True,
        "kind": "release-index",
        "release": record.get("release"),
        "shared_revision": record.get("shared_revision"),
        "platforms": verified,
    }
    if scoped:
        result["scoped"] = True
        result["platform_scope"] = list(indexed_platforms)
    return result


def _relative_repo_path(repo: pathlib.Path, path: pathlib.Path) -> str:
    return path.relative_to(repo).as_posix()


def _fsync_directory(descriptor: int, label: str) -> None:
    try:
        os.fsync(descriptor)
    except OSError as suc:
        raise DependencyFreezeError(f"Unable to durably sync {label}.") from suc


def _bounded_publication_stage_names(
    stage_fd: int, relative: str
) -> set[str]:
    names: set[str] = set()
    folded: dict[str, str] = {}
    try:
        iterator = os.scandir(stage_fd)
    except OSError as exc:
        raise DependencyFreezeError(
            "Unable to inspect publication staging entries."
        ) from exc
    with iterator:
        for entry in iterator:
            name = entry.name
            if (
                name in {".", ".."}
                or "\x00" in name
                or "/" in name
                or "\\" in name
            ):
                raise DependencyFreezeError(
                    "Publication staging contains an unsafe entry name."
                )
            if name in names:
                raise DependencyFreezeError(
                    "Publication staging contains a duplicate entry."
                )
            previous = folded.get(name.casefold())
            if previous is not None and previous != name:
                raise DependencyFreezeError(
                    "Publication staging contains case-colliding entries."
                )
            names.add(name)
            folded[name.casefold()] = name
            if len(names) > 4:
                raise DependencyFreezeError(
                    f"Publication staging contains too many entries: {relative}"
                )
    return names


def _remove_publication_stage(
    artifacts_fd: int,
    stage_name: str,
    allowed_owners: frozenset[int],
    *,
    require_unlocked: bool,
) -> None:
    try:
        stage_path = os.lstat(stage_name, dir_fd=artifacts_fd)
    except FileNotFoundError:
        return
    except OSError as suc:
        raise DependencyFreezeError("Unable to inspect publication staging.") from suc
    if (
        _is_reparse_stat(stage_path)
        or not stat.S_ISDIR(stage_path.st_mode)
        or stage_path.st_uid not in allowed_owners
        or stat.S_IMODE(stage_path.st_mode) != 0o700
    ):
        raise DependencyFreezeError("Publication staging custody is invalid.")
    stage_fd = os.open(stage_name, _directory_flags(), dir_fd=artifacts_fd)
    lock_fd: int | None = None
    try:
        stage_info = os.fstat(stage_fd)
        if _file_identity(stage_path) != _file_identity(stage_info):
            raise DependencyFreezeError("Publication staging identity changed.")
        names = _bounded_publication_stage_names(stage_fd, stage_name)
        if set(names) - {".lock", "journal", "record", "anchor"}:
            raise DependencyFreezeError("Publication staging contains unknown entries.")
        if ".lock" in names:
            lock_fd = os.open(".lock", _nofollow_flags(), dir_fd=stage_fd)
            lock_info = os.fstat(lock_fd)
            if (
                not stat.S_ISREG(lock_info.st_mode)
                or lock_info.st_nlink != 1
                or lock_info.st_uid not in allowed_owners
                or stat.S_IMODE(lock_info.st_mode) != 0o400
            ):
                raise DependencyFreezeError("Publication staging lock is invalid.")
            if require_unlocked:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as suc:
                    raise DependencyFreezeError(
                        "A concurrent publication transaction is active."
                    ) from suc
        for name in ("record", "anchor", "journal", ".lock"):
            if name not in names:
                continue
            info = os.lstat(name, dir_fd=stage_fd)
            if (
                _is_reparse_stat(info)
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid not in allowed_owners
                or stat.S_IMODE(info.st_mode) != 0o400
            ):
                raise DependencyFreezeError("Publication staging entry is invalid.")
            os.unlink(name, dir_fd=stage_fd)
        _fsync_directory(stage_fd, "publication staging directory")
    finally:
        _close_quietly(lock_fd)
        os.close(stage_fd)
    try:
        os.rmdir(stage_name, dir_fd=artifacts_fd)
    except OSError as suc:
        raise DependencyFreezeError("Unable to remove publication staging.") from suc
    _fsync_directory(artifacts_fd, ".artifacts directory")


def _acquire_publication_lock(
    repo_fd: int,
    artifacts_fd: int,
    allowed_owners: frozenset[int],
) -> None:
    repo_locked = False
    artifacts_locked = False
    try:
        for descriptor, label in (
            (repo_fd, "repository publication lock"),
            (artifacts_fd, ".artifacts publication lock"),
        ):
            before = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(before.st_mode)
                or before.st_uid not in allowed_owners
                or _is_group_or_world_writable(before)
            ):
                raise DependencyFreezeError(
                    f"{label} custody is invalid."
                )
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise DependencyFreezeError(
                    "A concurrent publication transaction is active."
                ) from exc
            if descriptor == repo_fd:
                repo_locked = True
            else:
                artifacts_locked = True
            after = os.fstat(descriptor)
            if _file_identity(before) != _file_identity(after):
                raise DependencyFreezeError(f"{label} custody changed.")
    except OSError as exc:
        if artifacts_locked:
            try:
                fcntl.flock(artifacts_fd, fcntl.LOCK_UN)
            except OSError:
                pass
        if repo_locked:
            try:
                fcntl.flock(repo_fd, fcntl.LOCK_UN)
            except OSError:
                pass
        raise DependencyFreezeError("Unable to lock publication directory.") from exc
    except Exception:
        if artifacts_locked:
            try:
                fcntl.flock(artifacts_fd, fcntl.LOCK_UN)
            except OSError:
                pass
        if repo_locked:
            try:
                fcntl.flock(repo_fd, fcntl.LOCK_UN)
            except OSError:
                pass
        raise


def _read_publication_entry(
    parent_fd: int,
    name: str,
    allowed_owners: frozenset[int],
    *,
    label: str,
    allowed_links: frozenset[int] = frozenset({1}),
) -> tuple[bytes, os.stat_result]:
    try:
        path_before = os.lstat(name, dir_fd=parent_fd)
        descriptor = os.open(name, _nofollow_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise DependencyFreezeError(f"Unable to inspect {label}.") from exc
    try:
        before = os.fstat(descriptor)
        if (
            _is_reparse_stat(path_before)
            or not stat.S_ISREG(path_before.st_mode)
            or _is_reparse_stat(before)
            or not stat.S_ISREG(before.st_mode)
            or (path_before.st_dev, path_before.st_ino)
            != (before.st_dev, before.st_ino)
            or before.st_nlink not in allowed_links
            or before.st_uid not in allowed_owners
            or stat.S_IMODE(before.st_mode) != 0o400
            or before.st_size < 0
            or before.st_size > MAX_DEPENDENCY_JSON_BYTES
        ):
            raise DependencyFreezeError(f"{label} custody is invalid.")
        payload = os.pread(descriptor, before.st_size + 1, 0)
        after = os.fstat(descriptor)
        path_after = os.lstat(name, dir_fd=parent_fd)
        if (
            len(payload) != before.st_size
            or _file_identity(path_before)
            != _file_identity(before)
            or _file_identity(before) != _file_identity(after)
            or _file_identity(after) != _file_identity(path_after)
        ):
            raise DependencyFreezeError(f"{label} changed while it was read.")
        return payload, before
    finally:
        os.close(descriptor)


def _parse_publication_journal(
    payload: bytes,
    *,
    transaction_id: str,
    nonce: str,
) -> dict[str, object]:
    journal = _load_json_object(payload, "Publication transaction journal")
    _require_exact_keys(
        journal,
        {
            "schema_version",
            "contract",
            "transaction_id",
            "nonce",
            "output",
            "record_sha256",
            "record_size_bytes",
            "anchor_sha256",
            "anchor_size_bytes",
        },
        "Publication transaction journal",
    )
    output = _require_str(journal.get("output"), "Publication output")
    if (
        _require_int(journal.get("schema_version"), "Publication journal schema")
        != SCHEMA_VERSION
        or journal.get("contract") != PUBLICATION_TRANSACTION_CONTRACT
        or journal.get("transaction_id") != transaction_id
        or journal.get("nonce") != nonce
        or not BUILD_ATTEMPT_NONCE.fullmatch(nonce)
        or not output.startswith(".artifacts/")
        or ".." in pathlib.PurePosixPath(output).parts
        or _require_int(journal.get("record_size_bytes"), "Publication record size")
        < 1
        or _require_int(journal.get("anchor_size_bytes"), "Publication anchor size")
        < 1
    ):
        raise DependencyFreezeError("Publication transaction journal is invalid.")
    _require_sha256(journal.get("record_sha256"), "Publication record digest")
    _require_sha256(journal.get("anchor_sha256"), "Publication anchor digest")
    return journal


def _strict_unlink_at(parent_fd: int, name: str, label: str) -> None:
    try:
        os.unlink(name, dir_fd=parent_fd)
        _fsync_directory(parent_fd, label)
    except OSError as exc:
        raise DependencyFreezeError(f"Unable to durably remove {label}.") from exc


def _inspect_rollback_regular_entry(
    parent_fd: int,
    name: str,
    allowed_owners: frozenset[int],
    *,
    label: str,
    allowed_modes: frozenset[int],
    allowed_links: frozenset[int] = frozenset({1}),
    max_bytes: int = MAX_DEPENDENCY_JSON_BYTES,
) -> os.stat_result:
    """Bind one rollback-only entry without trusting its contents."""

    try:
        path_info = os.lstat(name, dir_fd=parent_fd)
        descriptor = os.open(name, _nofollow_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise DependencyFreezeError(f"Unable to inspect {label}.") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            _is_reparse_stat(path_info)
            or not stat.S_ISREG(path_info.st_mode)
            or _is_reparse_stat(opened)
            or not stat.S_ISREG(opened.st_mode)
            or _file_identity(path_info) != _file_identity(opened)
            or opened.st_uid not in allowed_owners
            or opened.st_nlink not in allowed_links
            or stat.S_IMODE(opened.st_mode) not in allowed_modes
            or opened.st_size < 0
            or opened.st_size > max_bytes
        ):
            raise DependencyFreezeError(f"{label} rollback custody is invalid.")
        return opened
    finally:
        os.close(descriptor)


def _rollback_unparseable_publication_stage(
    artifacts_fd: int,
    parent_fd: int,
    stage_fd: int,
    stage_name: str,
    names: set[str],
    relative: pathlib.Path,
    anchor_name: str,
    allowed_owners: frozenset[int],
) -> None:
    """Remove only a provably uncommitted malformed publication transaction."""

    try:
        os.lstat(anchor_name, dir_fd=parent_fd)
    except FileNotFoundError:
        pass
    else:
        raise DependencyFreezeError(
            "Malformed publication journal has a commit marker and requires owner review."
        )
    try:
        os.lstat(relative.name, dir_fd=parent_fd)
    except FileNotFoundError:
        pass
    else:
        if "record" not in names:
            raise DependencyFreezeError(
                "Malformed publication journal cannot bind its published record."
            )
        staged = _inspect_rollback_regular_entry(
            stage_fd,
            "record",
            allowed_owners,
            label="malformed staged publication record",
            allowed_modes=frozenset({0o400}),
            allowed_links=frozenset({1, 2}),
        )
        final = _inspect_rollback_regular_entry(
            parent_fd,
            relative.name,
            allowed_owners,
            label="malformed published record",
            allowed_modes=frozenset({0o400}),
            allowed_links=frozenset({1, 2}),
        )
        if (staged.st_dev, staged.st_ino) != (final.st_dev, final.st_ino):
            raise DependencyFreezeError(
                "Malformed publication journal cannot bind its published record."
            )
        _strict_unlink_at(
            parent_fd, relative.name, "malformed uncommitted publication record"
        )
    _remove_publication_stage(
        artifacts_fd, stage_name, allowed_owners, require_unlocked=True
    )


def _recover_publication_stage(
    artifacts_fd: int,
    parent_fd: int,
    stage_name: str,
    stage_prefix: str,
    relative: pathlib.Path,
    anchor_name: str,
    allowed_owners: frozenset[int],
) -> None:
    nonce = stage_name.removeprefix(stage_prefix)
    if not BUILD_ATTEMPT_NONCE.fullmatch(nonce):
        raise DependencyFreezeError("Publication staging name is invalid.")
    try:
        stage_fd = os.open(stage_name, _directory_flags(), dir_fd=artifacts_fd)
    except OSError as exc:
        raise DependencyFreezeError("Unable to open publication staging.") from exc
    try:
        names = _bounded_publication_stage_names(stage_fd, stage_name)
        if names - {".lock", "journal", "record", "anchor"}:
            raise DependencyFreezeError("Publication staging contains unknown entries.")
        if "journal" not in names:
            if names - {".lock"}:
                raise DependencyFreezeError(
                    "Publication staging lacks its rollback-only journal."
                )
            _remove_publication_stage(
                artifacts_fd, stage_name, allowed_owners, require_unlocked=True
            )
            return
        try:
            journal_payload, _journal_info = _read_publication_entry(
                stage_fd,
                "journal",
                allowed_owners,
                label="publication transaction journal",
            )
            transaction_id = stage_prefix.removeprefix(
                ".freeze-staging-"
            ).removesuffix("-")
            journal = _parse_publication_journal(
                journal_payload, transaction_id=transaction_id, nonce=nonce
            )
        except DependencyFreezeError:
            _rollback_unparseable_publication_stage(
                artifacts_fd,
                parent_fd,
                stage_fd,
                stage_name,
                names,
                relative,
                anchor_name,
                allowed_owners,
            )
            return
        if journal.get("output") != relative.as_posix():
            raise DependencyFreezeError(
                "Publication transaction targets another output."
            )
        record_payload: bytes | None = None
        record_info: os.stat_result | None = None
        anchor_payload: bytes | None = None
        anchor_info: os.stat_result | None = None
        if "record" in names:
            record_payload, record_info = _read_publication_entry(
                stage_fd,
                "record",
                allowed_owners,
                label="staged publication record",
                allowed_links=frozenset({1, 2}),
            )
        if "anchor" in names:
            anchor_payload, anchor_info = _read_publication_entry(
                stage_fd,
                "anchor",
                allowed_owners,
                label="staged publication anchor",
                allowed_links=frozenset({1, 2}),
            )
        for payload, size_key, digest_key, entry_label in (
            (record_payload, "record_size_bytes", "record_sha256", "record"),
            (anchor_payload, "anchor_size_bytes", "anchor_sha256", "anchor"),
        ):
            if payload is not None and (
                len(payload) != journal.get(size_key)
                or hashlib.sha256(payload).hexdigest() != journal.get(digest_key)
            ):
                raise DependencyFreezeError(
                    f"Staged publication {entry_label} does not match its journal."
                )
        try:
            final_record_path = os.lstat(relative.name, dir_fd=parent_fd)
        except FileNotFoundError:
            final_record_path = None
        try:
            final_anchor_path = os.lstat(anchor_name, dir_fd=parent_fd)
        except FileNotFoundError:
            final_anchor_path = None
        final_record: bytes | None = None
        final_record_info: os.stat_result | None = None
        final_anchor: bytes | None = None
        final_anchor_info: os.stat_result | None = None
        if final_record_path is not None:
            final_record, final_record_info = _read_publication_entry(
                parent_fd,
                relative.name,
                allowed_owners,
                label="incomplete publication record",
                allowed_links=frozenset({1, 2}),
            )
            if (
                len(final_record) != journal.get("record_size_bytes")
                or hashlib.sha256(final_record).hexdigest()
                != journal.get("record_sha256")
            ):
                raise DependencyFreezeError(
                    "Incomplete publication record is not journal-bound."
                )
        if final_anchor_path is not None:
            final_anchor, final_anchor_info = _read_publication_entry(
                parent_fd,
                anchor_name,
                allowed_owners,
                label="publication commit anchor",
                allowed_links=frozenset({1, 2}),
            )
            if (
                len(final_anchor) != journal.get("anchor_size_bytes")
                or hashlib.sha256(final_anchor).hexdigest()
                != journal.get("anchor_sha256")
                or final_record is None
                or final_anchor
                != f"{hashlib.sha256(final_record).hexdigest()}  {relative.name}\n".encode(
                    "ascii"
                )
            ):
                raise DependencyFreezeError(
                    "Publication commit marker is not a complete bound pair."
                )
        if final_anchor is None and final_record_info is not None:
            _strict_unlink_at(
                parent_fd, relative.name, "incomplete publication record"
            )
            _fsync_directory(parent_fd, "publication output parent")
            final_record_info = None
        if final_record_info is not None or final_anchor_info is not None:
            _fsync_directory(parent_fd, "publication output parent")
        for entry_name, staged_info, final_info in (
            ("record", record_info, final_record_info),
            ("anchor", anchor_info, final_anchor_info),
        ):
            if staged_info is None or final_info is None:
                continue
            if (staged_info.st_dev, staged_info.st_ino) != (
                final_info.st_dev,
                final_info.st_ino,
            ):
                raise DependencyFreezeError(
                    "Publication staging and final entry identities diverged."
                )
            _strict_unlink_at(
                stage_fd, entry_name, "committed publication staging link"
            )
        _remove_publication_stage(
            artifacts_fd, stage_name, allowed_owners, require_unlocked=True
        )
    finally:
        os.close(stage_fd)


def _remove_stale_publication_stages(
    artifacts_fd: int,
    parent_fd: int,
    stage_prefix: str,
    relative: pathlib.Path,
    anchor_name: str,
    allowed_owners: frozenset[int],
) -> None:
    transaction_id = stage_prefix.removeprefix(
        ".freeze-staging-"
    ).removesuffix("-")
    exact_name = re.compile(re.escape(stage_prefix) + r"[0-9a-f]{64}\Z")
    candidates: list[str] = []
    scanned = 0
    try:
        iterator = os.scandir(artifacts_fd)
    except OSError as exc:
        raise DependencyFreezeError(
            "Unable to inspect publication staging inventory."
        ) from exc
    with iterator:
        for entry in iterator:
            scanned += 1
            if scanned > MAX_DEPENDENCY_FILE_COUNT:
                raise DependencyFreezeError(
                    "Publication staging inventory exceeds its entry bound."
                )
            name = entry.name
            if not name.casefold().startswith(stage_prefix.casefold()):
                continue
            candidates.append(name)
            if len(candidates) > PUBLICATION_STAGE_LIMIT:
                raise DependencyFreezeError(
                    "Publication staging exceeds its transaction-count bound."
                )

    aggregate_bytes = 0
    for name in candidates:
        if exact_name.fullmatch(name) is None:
            raise DependencyFreezeError(
                "Publication staging contains a malformed prefix-shaped transaction."
            )
        try:
            stage_info = os.lstat(name, dir_fd=artifacts_fd)
            if (
                _is_reparse_stat(stage_info)
                or not stat.S_ISDIR(stage_info.st_mode)
                or stage_info.st_uid not in allowed_owners
                or stat.S_IMODE(stage_info.st_mode) != 0o700
            ):
                raise DependencyFreezeError(
                    "Publication staging custody is invalid."
                )
            stage_fd = os.open(name, _directory_flags(), dir_fd=artifacts_fd)
            try:
                names = _bounded_publication_stage_names(stage_fd, name)
                if ".lock" not in names or "journal" not in names or names - {
                    ".lock", "journal", "record", "anchor"
                }:
                    raise DependencyFreezeError(
                        "Publication staging contains malformed retained state."
                    )
                for entry_name in names:
                    info = os.lstat(entry_name, dir_fd=stage_fd)
                    if (
                        _is_reparse_stat(info)
                        or not stat.S_ISREG(info.st_mode)
                        or info.st_nlink not in {1, 2}
                        or info.st_uid not in allowed_owners
                        or stat.S_IMODE(info.st_mode) != 0o400
                    ):
                        raise DependencyFreezeError(
                            "Publication staging entry is invalid."
                        )
                    aggregate_bytes += info.st_size
                    if aggregate_bytes > PUBLICATION_STAGE_BYTES_LIMIT:
                        raise DependencyFreezeError(
                            "Publication staging exceeds its aggregate byte bound."
                        )
                journal_payload, _journal_info = _read_publication_entry(
                    stage_fd,
                    "journal",
                    allowed_owners,
                    label="publication transaction journal",
                )
                nonce = name.removeprefix(stage_prefix)
                try:
                    journal = _parse_publication_journal(
                        journal_payload,
                        transaction_id=transaction_id,
                        nonce=nonce,
                    )
                except DependencyFreezeError:
                    # Count and size malformed prefix-shaped state, but never
                    # interpret or delete a journal that cannot authenticate
                    # itself to this exact transaction. A separate random
                    # stage may still complete under the persistent lock.
                    continue
                if journal.get("output") != relative.as_posix():
                    raise DependencyFreezeError(
                        "Publication staging targets another output."
                    )
            finally:
                os.close(stage_fd)
        except DependencyFreezeError:
            raise
        except OSError as exc:
            raise DependencyFreezeError(
                "Unable to inspect publication staging transaction."
            ) from exc
        _recover_publication_stage(
            artifacts_fd,
            parent_fd,
            name,
            stage_prefix,
            relative,
            anchor_name,
            allowed_owners,
        )


def _create_publication_stage(
    artifacts_fd: int,
    stage_name: str,
    allowed_owners: frozenset[int],
) -> tuple[int, int]:
    _remove_publication_stage(
        artifacts_fd, stage_name, allowed_owners, require_unlocked=True
    )
    try:
        os.mkdir(stage_name, 0o700, dir_fd=artifacts_fd)
        stage_fd = os.open(stage_name, _directory_flags(), dir_fd=artifacts_fd)
    except FileExistsError as suc:
        raise DependencyFreezeError(
            "A concurrent publication transaction is active."
        ) from suc
    except OSError as suc:
        raise DependencyFreezeError("Unable to create publication staging.") from suc
    lock_fd: int | None = None
    try:
        os.fchmod(stage_fd, 0o700)
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        lock_fd = os.open(".lock", flags, 0o400, dir_fd=stage_fd)
        os.fchmod(lock_fd, 0o400)
        os.fsync(lock_fd)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _fsync_directory(stage_fd, "publication staging directory")
        _fsync_directory(artifacts_fd, ".artifacts directory")
        return stage_fd, lock_fd
    except Exception:
        _close_quietly(lock_fd)
        os.close(stage_fd)
        _remove_publication_stage(
            artifacts_fd, stage_name, allowed_owners, require_unlocked=True
        )
        raise


def _write_private_stage_file(stage_fd: int, name: str, payload: bytes) -> tuple[int, int]:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, 0o400, dir_fd=stage_fd)
    except OSError as suc:
        raise DependencyFreezeError("Unable to create private publication file.") from suc
    try:
        view = memoryview(payload)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise DependencyFreezeError("Publication staging write ended early.")
            offset += written
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o400
            or info.st_size != len(payload)
        ):
            raise DependencyFreezeError("Publication staging file custody is invalid.")
        return info.st_dev, info.st_ino
    finally:
        os.close(descriptor)


def _publish_stage_entry(
    stage_fd: int,
    stage_name: str,
    parent_fd: int,
    final_name: str,
) -> None:
    try:
        os.link(
            stage_name,
            final_name,
            src_dir_fd=stage_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
        _fsync_directory(parent_fd, "publication output directory")
    except FileExistsError as suc:
        raise DependencyFreezeError(
            "Refusing to overwrite immutable publication output."
        ) from suc
    except OSError as suc:
        raise DependencyFreezeError("Unable to publish immutable output.") from suc


def _unlink_if_same_inode(
    parent_fd: int, name: str, identity: tuple[int, int]
) -> None:
    try:
        info = os.lstat(name, dir_fd=parent_fd)
    except FileNotFoundError:
        return
    except OSError:
        return
    if (
        not _is_reparse_stat(info)
        and stat.S_ISREG(info.st_mode)
        and (info.st_dev, info.st_ino) == identity
    ):
        try:
            os.unlink(name, dir_fd=parent_fd)
            _fsync_directory(parent_fd, "publication rollback directory")
        except OSError:
            return


def _strict_unlink_if_same_inode(
    parent_fd: int,
    name: str,
    identity: tuple[int, int],
    label: str,
) -> None:
    try:
        info = os.lstat(name, dir_fd=parent_fd)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise DependencyFreezeError(f"Unable to inspect {label} rollback.") from exc
    if (
        _is_reparse_stat(info)
        or not stat.S_ISREG(info.st_mode)
        or (info.st_dev, info.st_ino) != identity
    ):
        raise DependencyFreezeError(f"Refusing to roll back changed {label}.")
    quarantine = f".rollback-quarantine-{secrets.token_hex(32)}"
    _exclusive_rename_at(parent_fd, name, quarantine, label)
    quarantined = os.lstat(quarantine, dir_fd=parent_fd)
    if (
        _is_reparse_stat(quarantined)
        or not stat.S_ISREG(quarantined.st_mode)
        or (quarantined.st_dev, quarantined.st_ino) != identity
    ):
        raise DependencyFreezeError(
            f"Refusing to delete a replaced {label}; quarantined state requires owner review."
        )
    _fsync_directory(parent_fd, f"{label} quarantine")
    _strict_unlink_at(parent_fd, quarantine, f"{label} rollback quarantine")


def _exclusive_rename_at(
    parent_fd: int, source: str, destination: str, label: str
) -> None:
    """Atomically quarantine without overwriting an attacker-created destination."""

    try:
        authenticated_ctypes = _late_authenticated_ctypes()
        libc = authenticated_ctypes.CDLL(None, use_errno=True)
        if sys.platform == "darwin":
            rename = libc.renameatx_np
            rename.argtypes = (
                authenticated_ctypes.c_int,
                authenticated_ctypes.c_char_p,
                authenticated_ctypes.c_int,
                authenticated_ctypes.c_char_p,
                authenticated_ctypes.c_uint,
            )
            rename.restype = authenticated_ctypes.c_int
            flags = 0x00000004 | 0x00000010
        elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
            rename = libc.renameat2
            rename.argtypes = (
                authenticated_ctypes.c_int,
                authenticated_ctypes.c_char_p,
                authenticated_ctypes.c_int,
                authenticated_ctypes.c_char_p,
                authenticated_ctypes.c_uint,
            )
            rename.restype = authenticated_ctypes.c_int
            flags = 0x00000001
        else:
            raise DependencyFreezeError(
                f"{label} rollback requires atomic no-replace rename support."
            )
        authenticated_ctypes.set_errno(0)
        result = rename(
            parent_fd,
            source.encode("utf-8"),
            parent_fd,
            destination.encode("utf-8"),
            flags,
        )
        if result != 0:
            error = authenticated_ctypes.get_errno()
            raise OSError(error, os.strerror(error))
    except DependencyFreezeError:
        raise
    except (AttributeError, OSError, UnicodeEncodeError) as exc:
        raise DependencyFreezeError(
            f"Unable to atomically quarantine {label} rollback."
        ) from exc


def _write_anchored_record(
    repo: pathlib.Path, output: pathlib.Path, record: dict[str, object], label: str
) -> tuple[pathlib.Path, str]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json", output.name):
        raise DependencyFreezeError(f"{label} filename is unsafe.")
    candidate = pathlib.Path(os.path.abspath(output if output.is_absolute() else repo / output))
    try:
        relative = candidate.relative_to(repo)
    except ValueError as exc:
        raise DependencyFreezeError(f"{label} must stay inside the repository.") from exc
    if not relative.parts or relative.parts[0] != ".artifacts":
        raise DependencyFreezeError(f"{label} must stay under .artifacts/.")
    output = candidate
    anchor_name = output.name + ".sha256"
    record_payload = _canonical_json(record)
    digest = hashlib.sha256(record_payload).hexdigest()
    anchor_payload = f"{digest}  {output.name}\n".encode("ascii")
    owners = _allowed_owners(repo)
    held_parent = _hold_repo_directory(
        repo, output.parent, owners, label=f"{label} output directory"
    )
    components = {component.relative: component for component in held_parent.components}
    artifacts = components.get(".artifacts")
    if artifacts is None:
        _close_held_directory(held_parent)
        raise DependencyFreezeError(f"{label} must stay under .artifacts/.")
    parent_fd = held_parent.components[-1].descriptor
    artifacts_fd = artifacts.descriptor
    transaction_id = hashlib.sha256(
        relative.as_posix().encode("utf-8")
    ).hexdigest()
    stage_prefix = f".freeze-staging-{transaction_id}-"
    transaction_nonce = secrets.token_hex(32)
    stage_name = stage_prefix + transaction_nonce
    stage_fd: int | None = None
    lock_fd: int | None = None
    publication_locked = False
    record_identity: tuple[int, int] | None = None
    anchor_identity: tuple[int, int] | None = None
    retained_record: _HeldRegularFile | None = None
    retained_anchor: _HeldRegularFile | None = None
    committed = False
    try:
        _acquire_publication_lock(
            held_parent.repo_descriptor, artifacts_fd, owners
        )
        publication_locked = True
        _remove_stale_publication_stages(
            artifacts_fd,
            parent_fd,
            stage_prefix,
            relative,
            anchor_name,
            owners,
        )
        stage_fd, lock_fd = _create_publication_stage(
            artifacts_fd, stage_name, owners
        )
        for final_name in (output.name, anchor_name):
            try:
                os.lstat(final_name, dir_fd=parent_fd)
            except FileNotFoundError:
                continue
            raise DependencyFreezeError(
                f"Refusing to overwrite immutable {label.lower()}."
            )
        journal = {
            "schema_version": SCHEMA_VERSION,
            "contract": PUBLICATION_TRANSACTION_CONTRACT,
            "transaction_id": transaction_id,
            "nonce": transaction_nonce,
            "output": relative.as_posix(),
            "record_sha256": digest,
            "record_size_bytes": len(record_payload),
            "anchor_sha256": hashlib.sha256(anchor_payload).hexdigest(),
            "anchor_size_bytes": len(anchor_payload),
        }
        _write_private_stage_file(stage_fd, "journal", _canonical_json(journal))
        record_identity = _write_private_stage_file(
            stage_fd, "record", record_payload
        )
        anchor_identity = _write_private_stage_file(
            stage_fd, "anchor", anchor_payload
        )
        _fsync_directory(stage_fd, "publication staging directory")
        _publish_stage_entry(stage_fd, "record", parent_fd, output.name)
        _publish_stage_entry(stage_fd, "anchor", parent_fd, anchor_name)
        committed = True
        _strict_unlink_at(
            stage_fd, "record", "committed publication staging record"
        )
        _strict_unlink_at(
            stage_fd, "anchor", "committed publication staging anchor"
        )
        _fsync_directory(stage_fd, "publication staging directory")
        retained_record = _hold_repo_regular_file(
            repo, output, owners, label=label
        )
        retained_anchor = _hold_repo_regular_file(
            repo,
            output.with_name(anchor_name),
            owners,
            label=f"{label} anchor",
        )
        if (
            retained_record.payload != record_payload
            or retained_anchor.payload != anchor_payload
            or stat.S_IMODE(retained_record.info.st_mode) != 0o400
            or stat.S_IMODE(retained_anchor.info.st_mode) != 0o400
            or (retained_record.info.st_dev, retained_record.info.st_ino)
            != record_identity
            or (retained_anchor.info.st_dev, retained_anchor.info.st_ino)
            != anchor_identity
        ):
            raise DependencyFreezeError("Published record custody changed.")
        _assert_held_common_ancestors(retained_record, retained_anchor, label)
        _rebind_publication_directory(held_parent)
    except Exception as exc:
        if not committed:
            if record_identity is not None:
                _strict_unlink_if_same_inode(
                    parent_fd, output.name, record_identity, label
                )
            if anchor_identity is not None:
                _strict_unlink_if_same_inode(
                    parent_fd, anchor_name, anchor_identity, f"{label} anchor"
                )
        if committed:
            raise _CommittedPublicationError(str(exc)) from exc
        raise
    finally:
        _close_quietly(lock_fd)
        if stage_fd is not None:
            os.close(stage_fd)
        try:
            _remove_publication_stage(
                artifacts_fd, stage_name, owners, require_unlocked=True
            )
        except Exception as exc:
            if committed:
                raise _CommittedPublicationError(str(exc)) from exc
            raise
        finally:
            if publication_locked:
                try:
                    fcntl.flock(artifacts_fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                try:
                    fcntl.flock(held_parent.repo_descriptor, fcntl.LOCK_UN)
                except OSError:
                    pass
            if sys.exc_info()[0] is not None:
                if retained_anchor is not None:
                    _close_held_regular_file(retained_anchor)
                    retained_anchor = None
                if retained_record is not None:
                    _close_held_regular_file(retained_record)
                    retained_record = None
            _close_held_directory(held_parent)
    if not committed:
        raise DependencyFreezeError("Publication transaction did not commit.")
    active = _ACTIVE_ANCHORED_CUSTODY.get()
    if active is not None and retained_record is not None and retained_anchor is not None:
        active.append(
            _HeldAnchoredPayloads(
                record=retained_record,
                anchor=retained_anchor,
                label=label,
            )
        )
        retained_record = None
        retained_anchor = None
    if retained_anchor is not None:
        _close_held_regular_file(retained_anchor)
    if retained_record is not None:
        _close_held_regular_file(retained_record)
    return output, digest


def _assert_held_common_ancestors(
    left: _HeldRegularFile, right: _HeldRegularFile, label: str
) -> None:
    if left.repo_identity != right.repo_identity:
        raise DependencyFreezeError(f"{label} repository ancestor changed.")
    left_dirs = {
        component.relative: component.identity
        for component in left.components
        if component.directory
    }
    right_dirs = {
        component.relative: component.identity
        for component in right.components
        if component.directory
    }
    if left_dirs != right_dirs:
        raise DependencyFreezeError(f"{label} path ancestors changed between reads.")


def _read_anchored_payloads(
    repo: pathlib.Path, path: pathlib.Path, label: str
) -> tuple[bytes, str]:
    owners = _allowed_owners(repo)
    path = pathlib.Path(os.path.abspath(path if path.is_absolute() else repo / path))
    anchor = path.with_name(path.name + ".sha256")
    held_record = _hold_repo_regular_file(repo, path, owners, label=label)
    held_anchor: _HeldRegularFile | None = None
    retained = False
    try:
        held_anchor = _hold_repo_regular_file(
            repo, anchor, owners, label=f"{label} anchor"
        )
        _assert_held_common_ancestors(held_record, held_anchor, label)
        if (
            stat.S_IMODE(held_record.info.st_mode) != 0o400
            or stat.S_IMODE(held_anchor.info.st_mode) != 0o400
        ):
            raise DependencyFreezeError(f"{label} custody mode is invalid.")
        digest = hashlib.sha256(held_record.payload).hexdigest()
        try:
            anchor_text = held_anchor.payload.decode("ascii")
        except UnicodeDecodeError as suc:
            raise DependencyFreezeError(f"{label} anchor is not ASCII.") from suc
        if anchor_text != f"{digest}  {path.name}\n":
            raise DependencyFreezeError(f"{label} SHA-256 anchor changed.")
        _rebind_held_regular_file(held_record)
        _rebind_held_regular_file(held_anchor)
        _assert_held_common_ancestors(held_record, held_anchor, label)
        active = _ACTIVE_ANCHORED_CUSTODY.get()
        if active is not None:
            active.append(
                _HeldAnchoredPayloads(
                    record=held_record,
                    anchor=held_anchor,
                    label=label,
                )
            )
            retained = True
        return held_record.payload, digest
    finally:
        if not retained:
            if held_anchor is not None:
                _close_held_regular_file(held_anchor)
            _close_held_regular_file(held_record)


def _verify_anchor(repo: pathlib.Path, path: pathlib.Path, label: str) -> str:
    _payload, digest = _read_anchored_payloads(repo, path, label)
    return digest


def _read_anchored_json(
    repo: pathlib.Path, path: pathlib.Path, label: str
) -> tuple[dict[str, object], str]:
    payload, digest = _read_anchored_payloads(repo, path, label)
    return _load_json_object(payload, label), digest


def _safe_toolchain_value(value: str, label: str, *, allow_empty: bool = False) -> str:
    value = value.strip()
    if allow_empty and not value:
        return ""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+:/() -]{0,127}", value):
        raise DependencyFreezeError(f"{label} contains unsafe metadata.")
    if re.search(r"(?i)(password|passwd|secret|token|credential|private[-_ ]?key)", value):
        raise DependencyFreezeError(f"{label} resembles secret material.")
    return value


def _build_attempt_directory_identity(info: os.stat_result) -> dict[str, int]:
    return {
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "uid": int(info.st_uid),
        "gid": int(info.st_gid),
        "mode": int(stat.S_IMODE(info.st_mode)),
    }


def _held_directory_identity(
    held: _HeldDirectory, relative: str, label: str
) -> dict[str, int]:
    component = next(
        (item for item in held.components if item.relative == relative), None
    )
    if component is None:
        raise DependencyFreezeError(f"{label} is outside retained directory custody.")
    return _build_attempt_directory_identity(os.fstat(component.descriptor))


def _parse_build_attempt(value: object) -> dict[str, object]:
    attempt = _require_exact_keys(
        value,
        {
            "contract",
            "nonce",
            "directory",
            "directory_identity",
            "artifacts_directory_identity",
            "begin_receipt",
        },
        "Build attempt",
    )
    nonce = _require_str(attempt.get("nonce"), "Build attempt nonce")
    directory = _require_str(attempt.get("directory"), "Build attempt directory")
    begin_receipt = _require_str(
        attempt.get("begin_receipt"), "Build attempt begin receipt"
    )
    identity = _require_exact_keys(
        attempt.get("directory_identity"),
        {"device", "inode", "uid", "gid", "mode"},
        "Build attempt directory identity",
    )
    artifacts_identity = _require_exact_keys(
        attempt.get("artifacts_directory_identity"),
        {"device", "inode", "uid", "gid", "mode"},
        "Build attempt artifacts-directory identity",
    )
    if (
        attempt.get("contract") != BUILD_ATTEMPT_CONTRACT
        or not BUILD_ATTEMPT_NONCE.fullmatch(nonce)
        or directory != f".artifacts/.build-attempt-{nonce}"
        or not re.fullmatch(r"\.artifacts/[A-Za-z0-9][A-Za-z0-9._/-]{0,255}\.json", begin_receipt)
        or any(type(identity.get(key)) is not int for key in identity)
        or identity.get("device", -1) < 0
        or identity.get("inode", 0) <= 0
        or identity.get("uid", -1) < 0
        or identity.get("gid", -1) < 0
        or identity.get("mode") != 0o700
        or any(type(artifacts_identity.get(key)) is not int for key in artifacts_identity)
        or artifacts_identity.get("device", -1) < 0
        or artifacts_identity.get("inode", 0) <= 0
        or artifacts_identity.get("uid", -1) < 0
        or artifacts_identity.get("gid", -1) < 0
        or artifacts_identity.get("mode", -1) < 0
        or artifacts_identity.get("mode", 0) > 0o777
        or artifacts_identity.get("mode", 0) & 0o022 != 0
    ):
        raise DependencyFreezeError("Build attempt binding is invalid.")
    return attempt


def _rebind_build_attempt_directory(held: _HeldDirectory) -> None:
    mutable = frozenset(
        component.relative
        for component in held.components
        if component.relative == ".artifacts" or component is held.components[-1]
    )
    _rebind_held_components(
        held.repo,
        held.repo_descriptor,
        held.repo_identity,
        held.components,
        held.label,
        held.mutation_guard,
        mutable,
    )


def _rebind_consumed_artifacts_parent(held: _HeldDirectory) -> None:
    _rebind_held_components(
        held.repo,
        held.repo_descriptor,
        held.repo_identity,
        held.components,
        held.label,
        held.mutation_guard,
        frozenset({".artifacts"}),
    )


def _parse_build_attempt_admission_journal(value: object) -> dict[str, object]:
    record = _require_exact_keys(
        value,
        {
            "schema_version",
            "contract",
            "nonce",
            "created_utc",
            "begin_receipt",
            "begin_receipt_sha256",
            "directory_identity",
            "artifacts_directory_identity",
        },
        "Build attempt admission journal",
    )
    nonce = _require_str(record.get("nonce"), "Build attempt journal nonce")
    begin_receipt = _require_str(
        record.get("begin_receipt"), "Build attempt journal receipt"
    )
    _parse_timestamp(record.get("created_utc"), "Build attempt journal creation")
    if (
        _require_int(record.get("schema_version"), "Build attempt journal schema")
        != SCHEMA_VERSION
        or record.get("contract") != BUILD_ATTEMPT_JOURNAL_CONTRACT
        or not BUILD_ATTEMPT_NONCE.fullmatch(nonce)
        or not begin_receipt.startswith(".artifacts/")
        or ".." in pathlib.PurePosixPath(begin_receipt).parts
    ):
        raise DependencyFreezeError("Build attempt admission journal is invalid.")
    _require_sha256(
        record.get("begin_receipt_sha256"), "Build attempt journal receipt digest"
    )
    for key in ("directory_identity", "artifacts_directory_identity"):
        identity = _require_exact_keys(
            record.get(key),
            {"device", "inode", "uid", "gid", "mode"},
            f"Build attempt journal {key}",
        )
        if any(type(identity.get(field)) is not int for field in identity):
            raise DependencyFreezeError("Build attempt journal identity is invalid.")
    return record


def _write_build_attempt_admission_journal(
    repo: pathlib.Path,
    held_attempt: _HeldDirectory,
    begin_path: pathlib.Path,
    begin_sha256: str,
    created_utc: str,
    owners: frozenset[int],
) -> None:
    attempt_info = os.fstat(held_attempt.components[-1].descriptor)
    nonce = held_attempt.components[-1].name.removeprefix(".build-attempt-")
    record: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "contract": BUILD_ATTEMPT_JOURNAL_CONTRACT,
        "nonce": nonce,
        "created_utc": created_utc,
        "begin_receipt": _relative_repo_path(repo, begin_path),
        "begin_receipt_sha256": begin_sha256,
        "directory_identity": _build_attempt_directory_identity(attempt_info),
        "artifacts_directory_identity": _held_directory_identity(
            held_attempt, ".artifacts", "Build attempt parent"
        ),
    }
    payload = _canonical_json(record)
    attempt_fd = held_attempt.components[-1].descriptor
    _write_private_stage_file(attempt_fd, BUILD_ATTEMPT_JOURNAL_NAME, payload)
    journal_path = repo / held_attempt.components[-1].relative / BUILD_ATTEMPT_JOURNAL_NAME
    held_journal = _hold_repo_regular_file(
        repo, journal_path, owners, label="Build attempt admission journal"
    )
    try:
        if held_journal.payload != payload or stat.S_IMODE(held_journal.info.st_mode) != 0o400:
            raise DependencyFreezeError("Build attempt admission journal changed.")
        _rebind_build_attempt_file(held_journal)
        _rebind_build_attempt_directory(held_attempt)
    finally:
        _close_held_regular_file(held_journal)


def _load_authenticated_attempt_journal(
    repo: pathlib.Path,
    held_attempt: _HeldDirectory,
    owners: frozenset[int],
) -> tuple[
    dict[str, object],
    pathlib.Path,
    _HeldRegularFile,
    _HeldRegularFile,
    _HeldRegularFile,
]:
    attempt_fd = held_attempt.components[-1].descriptor
    payload, journal_info = _read_publication_entry(
        attempt_fd,
        BUILD_ATTEMPT_JOURNAL_NAME,
        owners,
        label="build attempt admission journal",
    )
    journal = _parse_build_attempt_admission_journal(
        _load_json_object(payload, "Build attempt admission journal")
    )
    held_journal = _hold_repo_regular_file(
        repo,
        repo / held_attempt.components[-1].relative / BUILD_ATTEMPT_JOURNAL_NAME,
        owners,
        label="Build attempt admission journal",
    )
    if (
        held_journal.payload != payload
        or _file_identity(held_journal.info) != _file_identity(journal_info)
        or stat.S_IMODE(held_journal.info.st_mode) != 0o400
    ):
        _close_held_regular_file(held_journal)
        raise DependencyFreezeError("Build attempt admission journal changed.")
    nonce = held_attempt.components[-1].name.removeprefix(".build-attempt-")
    if (
        journal.get("nonce") != nonce
        or journal.get("directory_identity")
        != _build_attempt_directory_identity(os.fstat(attempt_fd))
        or journal.get("artifacts_directory_identity")
        != _held_directory_identity(held_attempt, ".artifacts", "Build attempt parent")
        or _file_identity(journal_info)
        != _file_identity(os.lstat(BUILD_ATTEMPT_JOURNAL_NAME, dir_fd=attempt_fd))
    ):
        raise DependencyFreezeError("Build attempt admission identity changed.")
    begin_path = secure_repo_path(
        repo,
        pathlib.Path(_require_str(journal.get("begin_receipt"), "Build attempt receipt")),
        "Build attempt begin receipt",
        must_exist=True,
    )
    try:
        held_begin = _hold_repo_regular_file(
            repo, begin_path, owners, label="Build attempt begin receipt"
        )
        held_anchor = _hold_repo_regular_file(
            repo,
            begin_path.with_name(begin_path.name + ".sha256"),
            owners,
            label="Build attempt begin receipt anchor",
        )
    except Exception:
        _close_held_regular_file(held_journal)
        raise
    try:
        begin_sha = hashlib.sha256(held_begin.payload).hexdigest()
        expected_anchor = f"{begin_sha}  {begin_path.name}\n".encode("ascii")
        begin_record = _load_json_object(
            held_begin.payload, "Build attempt begin receipt"
        )
        begin_attempt = _parse_build_attempt(begin_record.get("build_attempt"))
        if (
            held_begin.payload != _canonical_json(begin_record)
            or held_anchor.payload != expected_anchor
            or stat.S_IMODE(held_begin.info.st_mode) != 0o400
            or stat.S_IMODE(held_anchor.info.st_mode) != 0o400
            or begin_sha != journal.get("begin_receipt_sha256")
            or begin_record.get("schema_version") != SCHEMA_VERSION
            or begin_record.get("contract") != BUILD_BEGIN_CONTRACT
            or begin_record.get("begun_utc") != journal.get("created_utc")
            or begin_attempt.get("nonce") != nonce
            or begin_attempt.get("directory")
            != held_attempt.components[-1].relative
            or begin_attempt.get("directory_identity")
            != journal.get("directory_identity")
            or begin_attempt.get("artifacts_directory_identity")
            != journal.get("artifacts_directory_identity")
            or begin_attempt.get("begin_receipt") != journal.get("begin_receipt")
        ):
            raise DependencyFreezeError("Build attempt admission authority changed.")
        _assert_held_common_ancestors(
            held_begin, held_anchor, "Build attempt begin receipt"
        )
        _rebind_build_attempt_file(held_begin)
        _rebind_build_attempt_file(held_anchor)
        _rebind_build_attempt_file(held_journal)
        return journal, begin_path, held_begin, held_anchor, held_journal
    except Exception:
        _close_held_regular_file(held_anchor)
        _close_held_regular_file(held_begin)
        _close_held_regular_file(held_journal)
        raise


def _attempt_directory_bytes(
    attempt_fd: int,
    relative: str,
    owners: frozenset[int],
) -> int:
    total = 0
    for name in _list_directory_names(attempt_fd, relative):
        info = os.lstat(name, dir_fd=attempt_fd)
        if (
            _is_reparse_stat(info)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid not in owners
            or info.st_nlink not in {1, 2}
            or stat.S_IMODE(info.st_mode) not in {0o400, 0o600}
            or info.st_size < 0
            or info.st_size > BUILD_ATTEMPT_BYTES_LIMIT
        ):
            raise DependencyFreezeError(
                "Build attempt contains unknown or unsafe retained state."
            )
        total += info.st_size
        if total > BUILD_ATTEMPT_BYTES_LIMIT:
            raise DependencyFreezeError("Build attempt aggregate bytes exceed the bound.")
    return total


def _gc_authenticated_abandoned_attempt(
    repo: pathlib.Path,
    held_attempt: _HeldDirectory,
    owners: frozenset[int],
) -> None:
    (
        journal,
        begin_path,
        held_begin,
        held_anchor,
        held_journal,
    ) = _load_authenticated_attempt_journal(repo, held_attempt, owners)
    attempt_fd = held_attempt.components[-1].descriptor
    retained_identities: dict[str, tuple[int, int]] = {}
    try:
        names = set(_list_directory_names(attempt_fd, held_attempt.components[-1].relative))
        retained_identities[BUILD_ATTEMPT_JOURNAL_NAME] = (
            held_journal.info.st_dev,
            held_journal.info.st_ino,
        )
        if ".receipt" in names:
            raise DependencyFreezeError(
                "Committed abandoned build attempt requires owner review."
            )
        allowed = {BUILD_ATTEMPT_JOURNAL_NAME, ".claim", ".producer"}
        output_name: str | None = None
        claim_record: dict[str, object] | None = None
        if ".claim" in names:
            claim_payload, claim_info = _read_publication_entry(
                attempt_fd, ".claim", owners, label="abandoned build attempt claim"
            )
            retained_identities[".claim"] = (claim_info.st_dev, claim_info.st_ino)
            loaded_claim = _load_json_object(claim_payload, "Abandoned build attempt claim")
            claim_record = _require_exact_keys(
                loaded_claim,
                {
                    "schema_version", "contract", "claimed_utc", "release", "platform",
                    "nonce", "build_begin_sha256", "release_input_index",
                    "platform_manifest", "source_freeze", "toolchain_custody",
                    "producer", "toolchain", "artifact_path",
                }
                | (
                    {"release_host_secret_scan"}
                    if loaded_claim.get("platform") == "windows"
                    and "release_host_secret_scan" in loaded_claim
                    else set()
                ),
                "Abandoned build attempt claim",
            )
            artifact_path = pathlib.PurePosixPath(
                _require_str(claim_record.get("artifact_path"), "Abandoned artifact path")
            )
            if (
                claim_record.get("schema_version") != SCHEMA_VERSION
                or claim_record.get("contract") != BUILD_ATTEMPT_CONTRACT
                or claim_record.get("nonce") != journal.get("nonce")
                or artifact_path.is_absolute()
                or ".." in artifact_path.parts
                or artifact_path.name != artifact_path.parts[-1]
            ):
                raise DependencyFreezeError("Abandoned build attempt claim is invalid.")
            output_name = artifact_path.name
            allowed.add(output_name)
            final_path = secure_repo_path(
                repo, pathlib.Path(artifact_path.as_posix()), "Abandoned artifact", must_exist=False,
                allow_missing_leaf=True,
            )
            if final_path.exists() or final_path.is_symlink():
                raise DependencyFreezeError(
                    "Abandoned attempt has published artifact state requiring owner review."
                )
        if names - allowed or BUILD_ATTEMPT_JOURNAL_NAME not in names:
            raise DependencyFreezeError(
                "Abandoned build attempt contains unknown retained state."
            )
        if ".producer" in names:
            if claim_record is None:
                raise DependencyFreezeError("Abandoned producer lacks a bound claim.")
            producer = _require_exact_keys(
                claim_record.get("producer"), {"path", "sha256"}, "Abandoned producer"
            )
            producer_payload, producer_info = _read_publication_entry(
                attempt_fd, ".producer", owners, label="abandoned producer snapshot"
            )
            retained_identities[".producer"] = (
                producer_info.st_dev,
                producer_info.st_ino,
            )
            if hashlib.sha256(producer_payload).hexdigest() != _require_sha256(
                producer.get("sha256"), "Abandoned producer digest"
            ) or stat.S_IMODE(producer_info.st_mode) != 0o400:
                raise DependencyFreezeError("Abandoned producer custody changed.")
        if output_name is not None and output_name in names:
            output_info = _inspect_rollback_regular_entry(
                attempt_fd,
                output_name,
                owners,
                label="abandoned attempt output",
                allowed_modes=frozenset({0o600}),
                allowed_links=frozenset({1}),
                max_bytes=BUILD_ATTEMPT_BYTES_LIMIT,
            )
            retained_identities[output_name] = (
                output_info.st_dev,
                output_info.st_ino,
            )
        _rebind_build_attempt_file(held_begin)
        _rebind_build_attempt_file(held_anchor)
        _rebind_build_attempt_file(held_journal)
        _rebind_build_attempt_directory(held_attempt)
        nonce = _require_str(journal.get("nonce"), "Build attempt journal nonce")
        retired_name = (
            f".retired-build-attempt-{nonce}-{secrets.token_hex(32)}"
        )
        parent_fd = held_attempt.components[-1].parent_descriptor
        attempt_identity = _file_identity(os.fstat(attempt_fd))
        _exclusive_rename_at(
            parent_fd,
            held_attempt.components[-1].name,
            retired_name,
            "abandoned build attempt",
        )
        retired = os.lstat(retired_name, dir_fd=parent_fd)
        if (
            _is_reparse_stat(retired)
            or not stat.S_ISDIR(retired.st_mode)
            or _file_identity(retired)[:6] != attempt_identity[:6]
        ):
            raise DependencyFreezeError(
                "Refusing to collect a replaced abandoned attempt directory."
            )
        _fsync_directory(parent_fd, ".artifacts directory")
    finally:
        _close_held_regular_file(held_journal)
        _close_held_regular_file(held_anchor)
        _close_held_regular_file(held_begin)


def _admit_build_attempt(
    repo: pathlib.Path,
    held_parent: _HeldDirectory,
    owners: frozenset[int],
) -> None:
    parent_fd = held_parent.components[-1].descriptor
    exact_name = re.compile(r"\.build-attempt-([0-9a-f]{64})\Z")
    retired_name = re.compile(
        r"\.retired-build-attempt-([0-9a-f]{64})-([0-9a-f]{64})\Z"
    )
    attempt_count = 0
    retired_count = 0
    aggregate_bytes = 0
    now = dt.datetime.now(tz=dt.timezone.utc)
    namespace = _list_directory_names(parent_fd, ".artifacts")
    namespace.sort(
        key=lambda item: (
            not item.casefold().startswith(".retired-build-attempt-"),
            item,
        )
    )
    for name in namespace:
        if name.casefold().startswith(".retired-build-attempt-"):
            if retired_name.fullmatch(name) is None:
                raise DependencyFreezeError(
                    "Unknown retired build attempt namespace requires owner review."
                )
            held_retired = _hold_repo_directory(
                repo,
                repo / ".artifacts" / name,
                owners,
                label="Retired build attempt",
            )
            try:
                retired_count += 1
                aggregate_bytes += _attempt_directory_bytes(
                    held_retired.components[-1].descriptor,
                    held_retired.components[-1].relative,
                    owners,
                )
                if (
                    retired_count > BUILD_ATTEMPT_RETIRED_LIMIT
                    or aggregate_bytes > BUILD_ATTEMPT_BYTES_LIMIT
                ):
                    raise DependencyFreezeError(
                        "Retired build attempt custody exceeds the owner-review bound."
                    )
                _rebind_build_attempt_directory(held_retired)
            finally:
                _close_held_directory(held_retired)
            continue
        if not name.casefold().startswith(".build-attempt-"):
            continue
        match = exact_name.fullmatch(name)
        if match is None:
            raise DependencyFreezeError(
                "Unknown build attempt namespace requires owner review."
            )
        info = os.lstat(name, dir_fd=parent_fd)
        if (
            _is_reparse_stat(info)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid not in owners
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise DependencyFreezeError("Build attempt directory custody is invalid.")
        held_attempt = _hold_repo_directory(
            repo, repo / ".artifacts" / name, owners, label="Existing build attempt"
        )
        lock_fd: int | None = None
        try:
            lock_fd = _acquire_build_attempt_lock(held_attempt, owners)
            attempt_count += 1
            aggregate_bytes += _attempt_directory_bytes(
                held_attempt.components[-1].descriptor,
                held_attempt.components[-1].relative,
                owners,
            )
            if aggregate_bytes > BUILD_ATTEMPT_BYTES_LIMIT:
                raise DependencyFreezeError("Build attempt aggregate bytes exceed the bound.")
            try:
                journal, _begin_path, held_begin, held_anchor, held_journal = (
                    _load_authenticated_attempt_journal(repo, held_attempt, owners)
                )
            except DependencyFreezeError:
                journal = None
            else:
                _close_held_regular_file(held_journal)
                _close_held_regular_file(held_anchor)
                _close_held_regular_file(held_begin)
            if journal is None:
                age_seconds = now.timestamp() - info.st_mtime
                if age_seconds > BUILD_ATTEMPT_MAX_AGE_SECONDS:
                    raise DependencyFreezeError(
                        "Unknown expired build attempt requires owner review."
                    )
            else:
                created = _parse_timestamp(
                    journal.get("created_utc"), "Build attempt journal creation"
                )
                age_seconds = (now - created).total_seconds()
                if age_seconds < -300:
                    raise DependencyFreezeError("Build attempt journal is future-dated.")
                if age_seconds > BUILD_ATTEMPT_MAX_AGE_SECONDS:
                    if retired_count >= BUILD_ATTEMPT_RETIRED_LIMIT:
                        raise DependencyFreezeError(
                            "Retired build attempt custody requires owner review before GC."
                        )
                    _gc_authenticated_abandoned_attempt(repo, held_attempt, owners)
                    return _admit_build_attempt(repo, held_parent, owners)
            if attempt_count >= BUILD_ATTEMPT_LIMIT:
                raise DependencyFreezeError("Build attempt count exceeds the admission bound.")
        finally:
            _release_build_attempt_lock(lock_fd)
            _close_held_directory(held_attempt)


def _create_build_attempt_directory(
    repo: pathlib.Path, nonce: str, owners: frozenset[int]
) -> _HeldDirectory:
    artifacts = secure_repo_path(
        repo, repo / ".artifacts", "Build attempt parent", must_exist=True
    )
    held_parent = _hold_repo_directory(
        repo, artifacts, owners, label="Build attempt parent"
    )
    parent_fd = held_parent.components[-1].descriptor
    name = f".build-attempt-{nonce}"
    created = False
    publication_locked = False
    try:
        _acquire_publication_lock(
            held_parent.repo_descriptor, parent_fd, owners
        )
        publication_locked = True
        _admit_build_attempt(repo, held_parent, owners)
        _reject_casefold_lookup(parent_fd, ".artifacts", name)
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            created = True
        except FileExistsError as exc:
            raise DependencyFreezeError("Build attempt nonce already exists.") from exc
        except OSError as exc:
            raise DependencyFreezeError("Unable to create private build attempt.") from exc
        attempt_fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
        try:
            os.fchmod(attempt_fd, 0o700)
            info = os.fstat(attempt_fd)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid not in owners
                or stat.S_IMODE(info.st_mode) != 0o700
                or _list_directory_names(attempt_fd, f".artifacts/{name}")
            ):
                raise DependencyFreezeError("Private build attempt custody is invalid.")
            _fsync_directory(attempt_fd, "private build attempt")
            _fsync_directory(parent_fd, ".artifacts directory")
        finally:
            os.close(attempt_fd)
    finally:
        if publication_locked:
            try:
                fcntl.flock(parent_fd, fcntl.LOCK_UN)
            finally:
                fcntl.flock(held_parent.repo_descriptor, fcntl.LOCK_UN)
        _close_held_directory(held_parent)
    path = repo / ".artifacts" / name
    try:
        held = _hold_repo_directory(repo, path, owners, label="Build attempt")
        _rebind_build_attempt_directory(held)
        return held
    except Exception:
        if created:
            try:
                os.rmdir(path)
            except OSError:
                pass
        raise


def _remove_empty_build_attempt(held: _HeldDirectory) -> None:
    _rebind_build_attempt_directory(held)
    component = held.components[-1]
    descriptor = component.descriptor
    if _list_directory_names(descriptor, component.relative):
        raise DependencyFreezeError("Refusing to remove a nonempty build attempt.")
    try:
        os.rmdir(component.name, dir_fd=component.parent_descriptor)
        _fsync_directory(component.parent_descriptor, ".artifacts directory")
    except OSError as exc:
        raise DependencyFreezeError("Unable to roll back private build attempt.") from exc


@_retain_anchored_inputs_until_return
def begin_build_receipt(
    repo: pathlib.Path,
    index_path: pathlib.Path,
    platform: str,
    output: pathlib.Path,
    remote_attestation: dict[str, object] | None = None,
) -> dict[str, object]:
    repo = secure_repo_path(repo, pathlib.Path("."), "Repository root", must_exist=True)
    if platform not in PLATFORM_ROOTS:
        raise DependencyFreezeError(f"Unsupported platform: {platform}")
    _require_build_witness_boundary(repo, platform)
    index_path = secure_repo_path(
        repo, index_path, "Release input index", must_exist=True
    )
    verified = verify_release_index(repo, index_path, platform)
    owners = _allowed_owners(repo)
    index, index_digest = _read_json_file(
        index_path, owners, "Release input index", repo=repo
    )
    reference = _require_exact_keys(
        index.get("platform_manifests").get(platform)
        if type(index.get("platform_manifests")) is dict
        else None,
        {"path", "sha256", "artifact_input_fingerprint_sha256"},
        f"{platform} platform manifest",
    )
    manifest_path = secure_repo_path(
        repo,
        index_path.parent / _require_str(reference.get("path"), "Platform manifest path"),
        f"{platform} platform manifest",
        must_exist=True,
    )
    output = _require_artifacts_output(
        repo, output, "Build begin receipt output", allow_missing_leaf=True
    )
    nonce = secrets.token_hex(32)
    if not BUILD_ATTEMPT_NONCE.fullmatch(nonce):
        raise DependencyFreezeError("Unable to mint a build attempt nonce.")
    held_attempt = _create_build_attempt_directory(repo, nonce, owners)
    attempt_info = os.fstat(held_attempt.components[-1].descriptor)
    artifacts_identity = _held_directory_identity(
        held_attempt, ".artifacts", "Build attempt parent"
    )
    begun_utc = _utc_now()
    record: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "contract": BUILD_BEGIN_CONTRACT,
        "release": verified["release"],
        "platform": platform,
        "begun_utc": begun_utc,
        "build_attempt": {
            "contract": BUILD_ATTEMPT_CONTRACT,
            "nonce": nonce,
            "directory": f".artifacts/.build-attempt-{nonce}",
            "directory_identity": _build_attempt_directory_identity(attempt_info),
            "artifacts_directory_identity": artifacts_identity,
            "begin_receipt": _relative_repo_path(repo, output),
        },
        "release_input_index": {
            "path": _relative_repo_path(repo, index_path),
            "sha256": index_digest,
        },
        "platform_manifest": {
            "path": _relative_repo_path(repo, manifest_path),
            "sha256": _require_sha256(reference.get("sha256"), "Platform manifest digest"),
            "artifact_input_fingerprint_sha256": _require_sha256(
                reference.get("artifact_input_fingerprint_sha256"),
                "Platform artifact fingerprint",
            ),
        },
        "shared_revision": verified["shared_revision"],
        "sha256_anchor": pathlib.Path(str(output)).name + ".sha256",
        "publication_authorized": False,
    }
    if remote_attestation is not None:
        record["remote_attestation"] = _require_remote_attestation_block(
            remote_attestation, platform
        )
    publication_committed = False
    try:
        _rebind_build_attempt_directory(held_attempt)
        try:
            _published, begin_sha = _write_anchored_record(
                repo, output, record, "Build begin receipt"
            )
        except _CommittedPublicationError:
            publication_committed = True
            begin_sha = hashlib.sha256(_canonical_json(record)).hexdigest()
            _write_build_attempt_admission_journal(
                repo, held_attempt, output, begin_sha, begun_utc, owners
            )
            raise
        publication_committed = True
        _write_build_attempt_admission_journal(
            repo, held_attempt, output, begin_sha, begun_utc, owners
        )
        _rebind_build_attempt_directory(held_attempt)
        return record
    except Exception:
        if publication_committed:
            _rebind_build_attempt_directory(held_attempt)
        else:
            _remove_empty_build_attempt(held_attempt)
        raise
    finally:
        _close_held_directory(held_attempt)


def _load_build_begin(
    repo: pathlib.Path,
    begin_path: pathlib.Path,
    index_path: pathlib.Path,
    platform: str,
) -> tuple[dict[str, object], dt.datetime, str, dict[str, object]]:
    begin_path = secure_repo_path(repo, begin_path, "Build begin receipt", must_exist=True)
    if begin_path.relative_to(repo).parts[0] != ".artifacts":
        raise DependencyFreezeError("Build begin receipt must stay under .artifacts/.")
    record, begin_sha = _read_anchored_json(repo, begin_path, "Build begin receipt")
    _require_exact_keys(
        record,
        {
            "schema_version",
            "contract",
            "release",
            "platform",
            "begun_utc",
            "build_attempt",
            "release_input_index",
            "platform_manifest",
            "shared_revision",
            "sha256_anchor",
            "publication_authorized",
        }
        | _remote_attestation_keys(record),
        "Build begin receipt",
    )
    begun = _parse_timestamp(record.get("begun_utc"), "Build begin receipt")
    if begun > dt.datetime.now(tz=dt.timezone.utc) + dt.timedelta(minutes=5):
        raise DependencyFreezeError("Build begin receipt is dated in the future.")
    verified = verify_release_index(repo, index_path, platform)
    owners = _allowed_owners(repo)
    index, index_digest = _read_json_file(
        index_path, owners, "Release input index", repo=repo
    )
    reference = _require_exact_keys(
        index.get("platform_manifests").get(platform)
        if type(index.get("platform_manifests")) is dict
        else None,
        {"path", "sha256", "artifact_input_fingerprint_sha256"},
        f"{platform} platform manifest",
    )
    expected_index = {
        "path": _relative_repo_path(repo, index_path),
        "sha256": index_digest,
    }
    expected_manifest = {
        "path": _relative_repo_path(
            repo,
            index_path.parent
            / _require_str(reference.get("path"), "Platform manifest path"),
        ),
        "sha256": _require_sha256(reference.get("sha256"), "Platform manifest digest"),
        "artifact_input_fingerprint_sha256": _require_sha256(
            reference.get("artifact_input_fingerprint_sha256"),
            "Platform artifact fingerprint",
        ),
    }
    attempt = _parse_build_attempt(record.get("build_attempt"))
    attempt_path = secure_repo_path(
        repo,
        pathlib.Path(_require_str(attempt.get("directory"), "Build attempt directory")),
        "Build attempt",
        must_exist=True,
    )
    held_attempt = _hold_repo_directory(
        repo, attempt_path, owners, label="Build attempt"
    )
    try:
        attempt_info = os.fstat(held_attempt.components[-1].descriptor)
        if (
            _build_attempt_directory_identity(attempt_info)
            != attempt.get("directory_identity")
            or attempt.get("begin_receipt") != _relative_repo_path(repo, begin_path)
        ):
            raise DependencyFreezeError("Build attempt identity changed.")
        _rebind_build_attempt_directory(held_attempt)
    finally:
        _close_held_directory(held_attempt)
    if (
        _require_int(record.get("schema_version"), "Build begin schema version")
        != SCHEMA_VERSION
        or _require_str(record.get("contract"), "Build begin contract") != BUILD_BEGIN_CONTRACT
        or _require_str(record.get("release"), "Build begin release") != verified["release"]
        or _require_str(record.get("platform"), "Build begin platform") != platform
        or record.get("build_attempt") != attempt
        or record.get("release_input_index") != expected_index
        or record.get("platform_manifest") != expected_manifest
        or _require_str(record.get("shared_revision"), "Build begin shared revision")
        != verified["shared_revision"]
        or _require_str(record.get("sha256_anchor"), "Build begin anchor")
        != begin_path.name + ".sha256"
        or _require_bool(record.get("publication_authorized"), "publication_authorized")
        is not False
    ):
        raise DependencyFreezeError("Build begin receipt binding changed.")
    return record, begun, begin_sha, reference


def _rebind_build_attempt_file(held: _HeldRegularFile) -> None:
    mutable = frozenset(
        component.relative
        for component in held.components
        if component.directory
        and (
            component.relative == ".artifacts"
            or component.relative.startswith(".artifacts/.build-attempt-")
        )
    )
    _rebind_held_components(
        held.repo,
        held.repo_descriptor,
        held.repo_identity,
        held.components,
        held.label,
        held.mutation_guard,
        mutable,
    )


def _acquire_build_attempt_lock(
    held_attempt: _HeldDirectory, owners: frozenset[int]
) -> int:
    attempt_fd = held_attempt.components[-1].descriptor
    info = os.fstat(attempt_fd)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid not in owners
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise DependencyFreezeError("Build attempt lock custody is invalid.")
    try:
        descriptor = os.open(".", _directory_flags(), dir_fd=attempt_fd)
    except OSError as exc:
        raise DependencyFreezeError(
            "Build attempt lock descriptor could not be opened independently."
        ) from exc
    try:
        locked_info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(locked_info.st_mode)
            or (locked_info.st_dev, locked_info.st_ino)
            != (info.st_dev, info.st_ino)
        ):
            raise DependencyFreezeError(
                "Build attempt lock descriptor changed identity."
            )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise DependencyFreezeError(
                "Build attempt is active in another process."
            ) from exc
        _rebind_build_attempt_directory(held_attempt)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _release_build_attempt_lock(descriptor: int | None) -> None:
    if descriptor is None:
        return
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _retire_completed_build_attempt(
    held_attempt: _HeldDirectory,
    allowed_names: frozenset[str],
) -> None:
    _rebind_build_attempt_directory(held_attempt)
    component = held_attempt.components[-1]
    attempt_fd = component.descriptor
    names = set(_list_directory_names(attempt_fd, component.relative))
    if names - allowed_names:
        raise DependencyFreezeError(
            "Completed build attempt contains unknown retained state."
        )
    for name in (".claim", ".receipt", BUILD_ATTEMPT_JOURNAL_NAME):
        if name in names:
            _strict_unlink_at(attempt_fd, name, f"completed build attempt {name}")
    _fsync_directory(attempt_fd, "completed build attempt")
    if _list_directory_names(attempt_fd, component.relative):
        raise DependencyFreezeError(
            "Completed build attempt could not be retired completely."
        )
    try:
        os.rmdir(component.name, dir_fd=component.parent_descriptor)
        _fsync_directory(component.parent_descriptor, ".artifacts directory")
    except OSError as exc:
        raise DependencyFreezeError(
            "Unable to retire completed build attempt."
        ) from exc


def _write_build_attempt_claim(
    repo: pathlib.Path,
    held_attempt: _HeldDirectory,
    claim: dict[str, object],
    owners: frozenset[int],
) -> tuple[_HeldRegularFile, str]:
    payload = _canonical_json(claim)
    descriptor = held_attempt.components[-1].descriptor
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        claim_fd = os.open(".claim", flags, 0o400, dir_fd=descriptor)
    except FileExistsError as exc:
        raise DependencyFreezeError("Build attempt has already been claimed.") from exc
    except OSError as exc:
        raise DependencyFreezeError("Unable to claim private build attempt.") from exc
    try:
        view = memoryview(payload)
        offset = 0
        while offset < len(view):
            written = os.write(claim_fd, view[offset:])
            if written <= 0:
                raise DependencyFreezeError("Unable to write build attempt claim.")
            offset += written
        os.fchmod(claim_fd, 0o400)
        os.fsync(claim_fd)
        info = os.fstat(claim_fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o400
            or info.st_size != len(payload)
        ):
            raise DependencyFreezeError("Build attempt claim custody is invalid.")
    finally:
        os.close(claim_fd)
    _fsync_directory(descriptor, "private build attempt")
    claim_path = held_attempt.repo / held_attempt.components[-1].relative / ".claim"
    held_claim = _hold_repo_regular_file(
        repo, claim_path, owners, label="Build attempt claim"
    )
    if held_claim.payload != payload:
        _close_held_regular_file(held_claim)
        raise DependencyFreezeError("Build attempt claim changed after publication.")
    _rebind_build_attempt_file(held_claim)
    return held_claim, hashlib.sha256(payload).hexdigest()


def _write_build_attempt_commit(
    repo: pathlib.Path,
    held_attempt: _HeldDirectory,
    record: dict[str, object],
    owners: frozenset[int],
) -> tuple[_HeldRegularFile, str]:
    payload = _canonical_json(record)
    attempt_fd = held_attempt.components[-1].descriptor
    _write_private_stage_file(attempt_fd, ".receipt", payload)
    _fsync_directory(attempt_fd, "private build attempt")
    path = repo / held_attempt.components[-1].relative / ".receipt"
    held = _hold_repo_regular_file(
        repo, path, owners, label="Build attempt commit journal"
    )
    if held.payload != payload:
        _close_held_regular_file(held)
        raise DependencyFreezeError("Build attempt commit journal changed.")
    _rebind_build_attempt_file(held)
    return held, hashlib.sha256(payload).hexdigest()


def _parse_build_attempt_commit(value: object) -> dict[str, object]:
    record = _require_exact_keys(
        value,
        {
            "schema_version",
            "contract",
            "nonce",
            "build_begin_sha256",
            "claim_sha256",
            "build_receipt_path",
            "artifact",
        },
        "Build attempt commit journal",
    )
    artifact = _require_exact_keys(
        record.get("artifact"),
        {
            "path",
            "name",
            "size_bytes",
            "sha256",
            "modified_time_ns",
            "device",
            "inode",
        },
        "Build attempt commit artifact",
    )
    nonce = _require_str(record.get("nonce"), "Build attempt commit nonce")
    receipt_path = _require_str(
        record.get("build_receipt_path"), "Build attempt commit receipt path"
    )
    artifact_path = _require_str(
        artifact.get("path"), "Build attempt commit artifact path"
    )
    artifact_name = _require_str(
        artifact.get("name"), "Build attempt commit artifact name"
    )
    if (
        _require_int(record.get("schema_version"), "Build attempt commit schema")
        != SCHEMA_VERSION
        or record.get("contract") != BUILD_ATTEMPT_COMMIT_CONTRACT
        or not BUILD_ATTEMPT_NONCE.fullmatch(nonce)
        or not receipt_path.startswith(".artifacts/")
        or ".." in pathlib.PurePosixPath(receipt_path).parts
        or pathlib.PurePosixPath(artifact_path).name != artifact_name
        or pathlib.PurePosixPath(artifact_name).name != artifact_name
        or ".." in pathlib.PurePosixPath(artifact_path).parts
        or _require_int(artifact.get("size_bytes"), "Build attempt artifact size")
        <= 0
        or _require_int(artifact.get("modified_time_ns"), "Build attempt artifact mtime")
        <= 0
        or _require_int(artifact.get("device"), "Build attempt artifact device")
        < 0
        or _require_int(artifact.get("inode"), "Build attempt artifact inode")
        <= 0
    ):
        raise DependencyFreezeError("Build attempt commit journal is invalid.")
    _require_sha256(record.get("build_begin_sha256"), "Build begin digest")
    _require_sha256(record.get("claim_sha256"), "Build attempt claim digest")
    _require_sha256(artifact.get("sha256"), "Build attempt artifact digest")
    return record


def _create_attempt_output_descriptor(
    held_attempt: _HeldDirectory, output_name: str
) -> tuple[int, tuple[int, int]]:
    attempt_fd = held_attempt.components[-1].descriptor
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(output_name, flags, 0o600, dir_fd=attempt_fd)
    except OSError as exc:
        raise DependencyFreezeError(
            "Unable to create the witnessed producer output inode."
        ) from exc
    try:
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size != 0
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise DependencyFreezeError(
                "Witnessed producer output inode custody is invalid."
            )
        _fsync_directory(attempt_fd, "private build attempt")
        return descriptor, (int(info.st_dev), int(info.st_ino))
    except Exception:
        os.close(descriptor)
        raise


def _install_private_attempt_producer(
    repo: pathlib.Path,
    held_attempt: _HeldDirectory,
    held_producer: _HeldRegularFile,
    owners: frozenset[int],
) -> _HeldRegularFile:
    attempt_fd = held_attempt.components[-1].descriptor
    _write_private_stage_file(attempt_fd, ".producer", held_producer.payload)
    _fsync_directory(attempt_fd, "private build attempt")
    private_path = repo / held_attempt.components[-1].relative / ".producer"
    private = _hold_repo_regular_file(
        repo, private_path, owners, label="Private build producer snapshot"
    )
    if private.payload != held_producer.payload:
        _close_held_regular_file(private)
        raise DependencyFreezeError("Private build producer snapshot changed.")
    _rebind_build_attempt_file(private)
    _rebind_held_regular_file(held_producer)
    return private


def _producer_child_environment(
    held_attempt: _HeldDirectory,
    held_producer: _HeldRegularFile,
    platform: str,
    nonce: str,
    output_name: str,
    output_descriptor: int,
    actual_host: str,
) -> dict[str, str]:
    attempt_path = str(held_attempt.repo / held_attempt.components[-1].relative)
    release_python_fixture = bool(
        isolated_fixture_mode_active() and actual_host == "darwin"
    )
    if release_python_fixture:
        env = _worker_environment()
    elif isolated_fixture_mode_active() or actual_host == "linux":
        env = {
            "HOME": attempt_path,
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "TMPDIR": attempt_path,
        }
    elif actual_host == "darwin":
        env = _worker_environment()
    elif actual_host == "windows":
        env = {
            key: os.environ[key]
            for key in ("ComSpec", "PATHEXT", "SystemRoot", "WINDIR")
            if key in os.environ
        }
        env.update(
            {
                "HOME": attempt_path,
                "LANG": "C",
                "PATH": str(_windows_powershell_executable().parent),
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
                "TEMP": attempt_path,
                "TMP": attempt_path,
            }
        )
    else:
        raise DependencyFreezeError(
            "Witnessed producer host environment is unsupported."
        )
    env.update(
        {
            "HOME": attempt_path,
            "TMPDIR": attempt_path,
            "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT": BUILD_ATTEMPT_CONTRACT,
            "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE": nonce,
            "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT": output_name,
            "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_PLATFORM": platform,
        }
    )
    env.update(
        dict(
            zip(
                NATIVE_BUILD_WITNESS_DESCRIPTOR_ENV,
                (
                    str(held_attempt.repo_descriptor),
                    str(held_producer.components[-1].descriptor),
                    str(held_attempt.components[-1].descriptor),
                    str(output_descriptor),
                ),
                strict=True,
            )
        )
    )
    return env


def _native_process_host() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "darwin"
    return "unsupported"


def _windows_powershell_executable() -> pathlib.Path:
    system_root = os.environ.get("SystemRoot", "")
    if (
        not system_root
        or "\0" in system_root
        or "\n" in system_root
        or "\r" in system_root
        or not pathlib.PureWindowsPath(system_root).is_absolute()
    ):
        raise DependencyFreezeError(
            "Exact Windows PowerShell system-root custody is unavailable."
        )
    return pathlib.Path(system_root) / (
        "System32/WindowsPowerShell/v1.0/powershell.exe"
    )


def _native_witness_command(
    platform: str,
    producer_execution_path: pathlib.Path,
    actual_host: str,
    *,
    fixture: bool,
) -> tuple[pathlib.Path, list[str]]:
    adapter = NATIVE_BUILD_WITNESS_ADAPTERS[PLATFORM_BUILD_PRODUCERS[platform]]
    runtime = str(adapter["runtime"])
    if fixture:
        executable = _reviewed_release_python_executable()
        return executable, [
            str(executable),
            "-I",
            "-S",
            str(producer_execution_path),
            BUILD_ATTEMPT_SWITCH,
        ]
    systems = tuple(str(value) for value in adapter.get("systems", ()))
    if actual_host not in systems:
        raise DependencyFreezeError(
            f"{platform} witnessed producer requires its reviewed "
            f"{adapter['host']} host; refusing {actual_host} substitution."
        )
    if runtime == "powershell-file":
        executable = _windows_powershell_executable()
        return executable, [
            str(executable),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(producer_execution_path),
            BUILD_ATTEMPT_SWITCH,
        ]
    if runtime == "bash-file":
        executable = pathlib.Path("/bin/bash")
        return executable, [
            str(executable),
            "-p",
            str(producer_execution_path),
            BUILD_ATTEMPT_SWITCH,
        ]
    if runtime == "isolated-python":
        executable = _reviewed_release_python_executable()
        return executable, [
            str(executable),
            "-I",
            "-S",
            str(producer_execution_path),
            BUILD_ATTEMPT_SWITCH,
        ]
    raise DependencyFreezeError(
        f"{platform} producer execution runtime is not integrated with "
        f"{BUILD_ATTEMPT_CONTRACT}."
    )


def _reviewed_release_python_executable() -> pathlib.Path:
    """Return the pinned release Python held by the authenticated worker.

    Outside an authenticated worker (isolated fixtures and unit tests) this is
    the running interpreter, which cannot authorize a release.
    """

    custody = _ACTIVE_AUTHORITATIVE_WORKER_CUSTODY.get()
    if custody is not None:
        return custody.executable_path
    return pathlib.Path(sys.executable)


def _require_native_runtime_executable(
    executable: pathlib.Path,
    actual_host: str,
    *,
    allowed_owners: frozenset[int] = frozenset({0}),
) -> None:
    try:
        info = os.lstat(executable)
    except OSError as exc:
        raise DependencyFreezeError(
            f"Reviewed native producer runtime is unavailable: {executable}"
        ) from exc
    if (
        _is_reparse_stat(info)
        or not stat.S_ISREG(info.st_mode)
        or _is_group_or_world_writable(info)
        or not (info.st_mode & stat.S_IXUSR)
        or (actual_host != "windows" and info.st_uid not in allowed_owners)
    ):
        raise DependencyFreezeError(
            f"Reviewed native producer runtime custody is invalid: {executable}"
        )


def _sandbox_build_attempt_path(held_attempt: _HeldDirectory) -> str:
    path = os.path.realpath(
        held_attempt.repo / held_attempt.components[-1].relative
    )
    if "\0" in path or "\n" in path or "\r" in path:
        raise DependencyFreezeError("Build attempt sandbox path is unsafe.")
    return path.replace("\\", "\\\\").replace('"', '\\"')


def _sandbox_repo_path(held_attempt: _HeldDirectory) -> str:
    path = os.path.realpath(held_attempt.repo)
    if "\0" in path or "\n" in path or "\r" in path:
        raise DependencyFreezeError("Build repository sandbox path is unsafe.")
    return path.replace("\\", "\\\\").replace('"', '\\"')


def _sandbox_literal_path(path: pathlib.Path | str) -> str:
    value = os.path.realpath(os.fspath(path))
    if not value.startswith("/") or "\0" in value or "\n" in value or "\r" in value:
        raise DependencyFreezeError("Build-attempt sandbox dependency path is unsafe.")
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _producer_sandbox_profile(
    held_attempt: _HeldDirectory,
    executable: pathlib.Path,
) -> str:
    attempt = _sandbox_build_attempt_path(held_attempt)
    read_subpaths = {
        "/System",
        "/usr/lib",
        "/private/var/db/dyld",
        _sandbox_literal_path(pathlib.Path(sys.base_prefix)),
        _sandbox_literal_path(pathlib.Path(sys.exec_prefix)),
    }
    worker_custody = _ACTIVE_AUTHORITATIVE_WORKER_CUSTODY.get()
    if worker_custody is not None and executable == worker_custody.executable_path:
        read_subpaths.add(
            _sandbox_literal_path(worker_custody.executable_path.parent.parent)
        )
    if isolated_fixture_mode_active():
        read_subpaths.add(
            "/Applications/Xcode.app/Contents/Developer"
        )
    read_literals = {
        "/bin/bash",
        "/bin/sh",
        "/dev/null",
        "/dev/random",
        "/dev/urandom",
        "/usr/bin/env",
        _sandbox_literal_path(executable),
    }
    read_rules = "".join(
        f'(allow file-read* (subpath "{path}"))'
        for path in sorted(read_subpaths)
    ) + "".join(
        f'(allow file-read* (literal "{_sandbox_literal_path(path)}"))'
        for path in sorted(read_literals)
    )
    return (
        "(version 1)"
        "(deny default)"
        '(import "system.sb")'
        "(deny file-read*"
        ' (subpath "/Applications")'
        ' (subpath "/Library")'
        ' (subpath "/Network")'
        ' (subpath "/Users")'
        ' (subpath "/Volumes")'
        ' (subpath "/opt")'
        ' (subpath "/private/etc")'
        ' (subpath "/private/tmp")'
        ' (subpath "/private/var/tmp")'
        ' (subpath "/usr/local"))'
        "(allow process*)"
        "(allow signal (target self))"
        "(allow sysctl-read)"
        "(allow mach-lookup)"
        "(allow ipc-posix-shm)"
        "(allow file-read-metadata)"
        f'(allow file-read* (subpath "{attempt}"))'
        '(allow file-read* (subpath "/dev/fd"))'
        f"{read_rules}"
        # The producer receives only the write side of a controller-owned pipe.
        # It must never receive or reopen the final artifact inode by pathname.
        '(allow file-write* (subpath "/dev/fd"))'
    )


def _bounded_producer_diagnostic(diagnostics: bytes) -> str:
    """Return useful failure context without echoing untrusted secret material."""
    if type(diagnostics) is not bytes or not diagnostics:
        return "no diagnostic"
    bounded = diagnostics[:BUILD_ATTEMPT_DIAGNOSTIC_BYTES_LIMIT]
    digest = hashlib.sha256(bounded).hexdigest()
    text = bounded.decode("utf-8", errors="replace")
    text = " ".join(text.replace("\x00", " ").split())
    text = re.sub(
        r"(?i)\b(authorization|cookie|credential|password|secret|token|"
        r"api[_-]?key)\b\s*[:=]\s*\S+",
        r"\1=[REDACTED]",
        text,
    )
    text = re.sub(
        r"(?<![A-Za-z0-9])[A-Za-z0-9_+/=-]{32,}(?![A-Za-z0-9])",
        "[REDACTED]",
        text,
    )
    text = "".join(
        character if character == " " or 0x21 <= ord(character) <= 0x7E else "?"
        for character in text
    )
    text = text[:BUILD_ATTEMPT_DIAGNOSTIC_TEXT_LIMIT].strip()
    if not text:
        text = "non-text diagnostic"
    truncated = " truncated" if len(diagnostics) > len(bounded) else ""
    return f"{text}; bytes={len(diagnostics)}; sha256={digest}{truncated}"


def _darwin_sandboxed_command(
    sandbox: pathlib.Path,
    profile: str,
    command: list[str],
    child_environment: dict[str, str],
) -> tuple[list[str], dict[str, str]]:
    """Construct the child environment only after entering the macOS sandbox."""
    environment_tool = pathlib.Path("/usr/bin/env")
    _require_native_runtime_executable(environment_tool, "darwin")
    assignments: list[str] = []
    for key, value in sorted(child_environment.items()):
        if (
            type(key) is not str
            or type(value) is not str
            or not key
            or "=" in key
            or "\0" in key
            or "\0" in value
            or "\n" in key
            or "\r" in key
        ):
            raise DependencyFreezeError(
                "Witnessed producer child environment is unsafe."
            )
        assignments.append(f"{key}={value}")
    return (
        [
            str(sandbox),
            "-p",
            profile,
            str(environment_tool),
            "-i",
            *assignments,
            *command,
        ],
        {
            "HOME": "/private/tmp",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "TMPDIR": "/private/tmp",
        },
    )


def _readable_descriptors(descriptors: tuple[int, ...], timeout: float) -> list[int]:
    """Return the descriptors that are readable or at EOF within timeout seconds.

    select.select refuses any descriptor at or above FD_SETSIZE (1024), which the freeze
    reaches once it raises its open-file limit; poll has no such bound.
    """
    poller = select.poll()
    for descriptor in descriptors:
        poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
    return [descriptor for descriptor, _events in poller.poll(int(timeout * 1000))]


def _run_witnessed_producer(
    held_attempt: _HeldDirectory,
    held_producer: _HeldRegularFile,
    platform: str,
    nonce: str,
    output_name: str,
    output_descriptor: int,
    producer_runtime_suffix: str,
) -> int:
    if BUILD_ATTEMPT_MARKER not in held_producer.payload:
        raise DependencyFreezeError(
            f"{platform} producer is not integrated with {BUILD_ATTEMPT_CONTRACT}."
        )
    if threading.active_count() != 1:
        raise DependencyFreezeError("Witnessed producer execution requires one thread.")
    attempt_fd = held_attempt.components[-1].descriptor
    producer_execution_path = (
        held_attempt.repo / held_attempt.components[-1].relative / ".producer"
    )
    suffix = producer_runtime_suffix.lower()
    if suffix != pathlib.PurePosixPath(
        PLATFORM_BUILD_PRODUCERS[platform]
    ).suffix.lower():
        raise DependencyFreezeError(
            "Witnessed producer runtime identity changed."
        )
    actual_host = _native_process_host()
    worker_custody = _ACTIVE_AUTHORITATIVE_WORKER_CUSTODY.get()
    if not isolated_fixture_mode_active():
        if not (
            actual_host == "darwin"
            and _AUTHORITATIVE_WORKER_READY
            and worker_custody is not None
        ):
            raise DependencyFreezeError(
                "Witnessed producer execution remains OWNER-BLOCKED until an "
                "authenticated whole-job descendant supervisor is active."
            )
        _revalidate_authoritative_worker(worker_custody)
    executable, command = _native_witness_command(
        platform,
        producer_execution_path,
        actual_host,
        fixture=isolated_fixture_mode_active(),
    )
    if (
        worker_custody is not None
        and executable == worker_custody.executable_path
    ):
        # The pinned release Python is user-installed: its bytes were hashed
        # against tools/toolchain-pins.json and its inode is still the one the
        # worker holds, so ownership by the current user is accepted.
        _revalidate_authoritative_worker(worker_custody)
        _require_native_runtime_executable(
            executable,
            actual_host,
            allowed_owners=frozenset({0, os.geteuid()}),
        )
    elif not isolated_fixture_mode_active():
        _require_native_runtime_executable(executable, actual_host)
    if actual_host == "darwin":
        sandbox = pathlib.Path("/usr/bin/sandbox-exec")
        try:
            sandbox_info = os.lstat(sandbox)
        except OSError as exc:
            raise DependencyFreezeError(
                "macOS build-attempt sandbox is unavailable."
            ) from exc
        if (
            _is_reparse_stat(sandbox_info)
            or not stat.S_ISREG(sandbox_info.st_mode)
            or sandbox_info.st_uid != 0
            or _is_group_or_world_writable(sandbox_info)
            or not (sandbox_info.st_mode & stat.S_IXUSR)
        ):
            raise DependencyFreezeError(
                "macOS build-attempt sandbox custody is invalid."
            )
    pipe_read = -1
    pipe_write = -1
    artifact_read = -1
    artifact_write = -1
    try:
        pipe_read, pipe_write = os.pipe()
        artifact_read, artifact_write = os.pipe()
        os.set_blocking(pipe_read, False)
        os.set_blocking(artifact_read, False)
    except OSError as exc:
        for descriptor in (pipe_read, pipe_write, artifact_read, artifact_write):
            if descriptor >= 0:
                _close_quietly(descriptor)
        raise DependencyFreezeError(
            "Witnessed producer capability pipes could not be created."
        ) from exc
    child_environment = _producer_child_environment(
        held_attempt,
        held_producer,
        platform,
        nonce,
        output_name,
        artifact_write,
        actual_host,
    )
    if actual_host == "darwin":
        profile = _producer_sandbox_profile(held_attempt, executable)
        command, child_environment = _darwin_sandboxed_command(
            sandbox, profile, command, child_environment
        )
    try:
        fcntl.flock(output_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(artifact_write)
        os.close(artifact_read)
        os.close(pipe_write)
        os.close(pipe_read)
        raise DependencyFreezeError(
            "Witnessed producer output lock could not be established."
        ) from exc

    retained_descriptors = tuple(
        dict.fromkeys(
            (
                held_attempt.repo_descriptor,
                held_producer.components[-1].descriptor,
                attempt_fd,
                artifact_write,
                pipe_write,
            )
        )
    )
    try:
        if actual_host == "windows":
            inherited = tuple(
                (descriptor, os.get_inheritable(descriptor))
                for descriptor in retained_descriptors
            )
            try:
                for descriptor, _was_inheritable in inherited:
                    os.set_inheritable(descriptor, True)
                process = subprocess.Popen(
                    command,
                    close_fds=False,
                    creationflags=getattr(
                        subprocess, "CREATE_NEW_PROCESS_GROUP", 0
                    ),
                    cwd=producer_execution_path.parent,
                    env=child_environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=pipe_write,
                )
            finally:
                for descriptor, was_inheritable in inherited:
                    os.set_inheritable(descriptor, was_inheritable)
        else:
            def child_setup() -> None:
                os.fchdir(attempt_fd)
                os.umask(0o077)

            process = subprocess.Popen(
                command,
                close_fds=True,
                env=child_environment,
                pass_fds=retained_descriptors,
                preexec_fn=child_setup,
                start_new_session=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=pipe_write,
            )
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        os.close(artifact_write)
        os.close(artifact_read)
        os.close(pipe_write)
        os.close(pipe_read)
        raise DependencyFreezeError("Witnessed producer could not be started.") from exc
    os.close(pipe_write)
    pipe_write = -1
    os.close(artifact_write)
    artifact_write = -1
    deadline = time.monotonic() + BUILD_ATTEMPT_TIMEOUT_SECONDS
    pipe_eof = False
    artifact_eof = False
    artifact_bytes = 0
    diagnostics = bytearray()
    try:
        while True:
            for descriptor, is_artifact in (
                (pipe_read, False),
                (artifact_read, True),
            ):
                while True:
                    try:
                        block = os.read(descriptor, 1024 * 1024)
                    except BlockingIOError:
                        break
                    if not block:
                        if is_artifact:
                            artifact_eof = True
                        else:
                            pipe_eof = True
                        break
                    # A writer that never lets a channel run dry (including a
                    # descendant still writing after the leader exited) must
                    # not hold this drain past the attempt deadline.
                    if time.monotonic() >= deadline:
                        raise subprocess.TimeoutExpired(
                            command, BUILD_ATTEMPT_TIMEOUT_SECONDS
                        )
                    if is_artifact:
                        artifact_bytes += len(block)
                        if artifact_bytes > ARCHIVE_EXPANDED_BYTES_LIMIT:
                            raise DependencyFreezeError(
                                "Witnessed producer output exceeds its byte bound."
                            )
                        view = memoryview(block)
                        offset = 0
                        while offset < len(view):
                            written = os.write(output_descriptor, view[offset:])
                            if written <= 0:
                                raise DependencyFreezeError(
                                    "Witnessed producer output could not be retained."
                                )
                            offset += written
                    elif len(diagnostics) < BUILD_ATTEMPT_DIAGNOSTIC_BYTES_LIMIT:
                        diagnostics.extend(
                            block[
                                : BUILD_ATTEMPT_DIAGNOSTIC_BYTES_LIMIT
                                - len(diagnostics)
                            ]
                        )
            return_code = process.poll()
            if return_code is not None:
                if not pipe_eof or not artifact_eof:
                    readable = _readable_descriptors(
                        tuple(
                            descriptor
                            for descriptor, reached_eof in (
                                (pipe_read, pipe_eof),
                                (artifact_read, artifact_eof),
                            )
                            if not reached_eof
                        ),
                        0.05,
                    )
                    if readable:
                        continue
                    raise DependencyFreezeError(
                        "Witnessed producer left a detached output descriptor alive."
                    )
                break
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(command, BUILD_ATTEMPT_TIMEOUT_SECONDS)
            _readable_descriptors((pipe_read, artifact_read), 0.05)
    except (DependencyFreezeError, subprocess.TimeoutExpired, OSError) as exc:
        # The group is killed even when the leader already exited: a
        # descendant still in it may be the writer that caused this refusal.
        try:
            os.killpg(process.pid, 9)
        except OSError:
            if process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass
        process.wait()
        if isinstance(exc, subprocess.TimeoutExpired):
            raise DependencyFreezeError(
                "Witnessed producer exceeded its deadline."
            ) from exc
        if isinstance(exc, OSError):
            raise DependencyFreezeError(
                "Witnessed producer output could not be retained."
            ) from exc
        raise
    finally:
        os.close(pipe_read)
        os.close(artifact_read)
    descendants_alive = False
    try:
        os.killpg(process.pid, 0)
        descendants_alive = True
    except ProcessLookupError:
        pass
    except OSError:
        descendants_alive = True
    if descendants_alive:
        try:
            os.killpg(process.pid, 9)
        except OSError:
            pass
        raise DependencyFreezeError("Witnessed producer left descendant processes alive.")
    if worker_custody is not None:
        _revalidate_authoritative_worker(worker_custody)
    if return_code != 0:
        if (
            actual_host == "darwin"
            and return_code == 71
            and b"sandbox_apply" in diagnostics
            and b"Operation not permitted" in diagnostics
        ):
            raise DependencyFreezeError(
                "macOS witnessed producer sandbox creation is unavailable in "
                "the current parent confinement. Run the authenticated worker "
                "from the owner release host outside a containing sandbox, or "
                "provision a separately authenticated fixed-function sandbox "
                "helper; unsandboxed execution is refused."
            )
        raise DependencyFreezeError(
            f"Witnessed producer failed with exit status {return_code}: "
            f"{_bounded_producer_diagnostic(bytes(diagnostics))}."
        )
    if diagnostics:
        raise DependencyFreezeError(
            "Witnessed producer emitted diagnostics on its private lifetime channel."
        )
    os.fsync(output_descriptor)
    retained = os.fstat(output_descriptor)
    current = os.lstat(output_name, dir_fd=attempt_fd)
    if (
        not stat.S_ISREG(retained.st_mode)
        or _file_identity(retained) != _file_identity(current)
    ):
        raise DependencyFreezeError(
            "Witnessed producer output changed after execution."
        )
    return output_descriptor


def _validated_attempt_output(
    repo: pathlib.Path,
    held_attempt: _HeldDirectory,
    output_name: str,
    owners: frozenset[int],
    output_descriptor: int,
    expected_identity: tuple[int, int],
) -> _HeldRegularFile:
    descriptor = held_attempt.components[-1].descriptor
    relative = held_attempt.components[-1].relative
    names = _list_directory_names(descriptor, relative)
    if set(names) != {BUILD_ATTEMPT_JOURNAL_NAME, ".claim", output_name} or len(names) != 3:
        raise DependencyFreezeError(
            "Witnessed producer must create exactly one declared output."
        )
    descriptor_info = os.fstat(output_descriptor)
    if (
        not stat.S_ISREG(descriptor_info.st_mode)
        or (descriptor_info.st_dev, descriptor_info.st_ino) != expected_identity
        or descriptor_info.st_nlink != 1
        or descriptor_info.st_size <= 0
        or stat.S_IMODE(descriptor_info.st_mode) != 0o600
    ):
        raise DependencyFreezeError(
            "Witnessed producer did not populate its retained output inode."
        )
    os.fsync(output_descriptor)
    output_path = repo / relative / output_name
    held_output = _hold_repo_regular_file(
        repo, output_path, owners, label="Witnessed producer output"
    )
    if (
        held_output.info.st_size <= 0
        or held_output.info.st_nlink != 1
        or _is_group_or_world_writable(held_output.info)
        or (held_output.info.st_dev, held_output.info.st_ino) != expected_identity
        or held_output.payload != os.pread(
            output_descriptor, descriptor_info.st_size, 0
        )
    ):
        _close_held_regular_file(held_output)
        raise DependencyFreezeError("Witnessed producer output custody is invalid.")
    _rebind_build_attempt_file(held_output)
    return held_output


def _inspect_build_artifact_entry(
    parent_fd: int,
    name: str,
    owners: frozenset[int],
    label: str,
) -> os.stat_result:
    try:
        path_info = os.lstat(name, dir_fd=parent_fd)
        descriptor = os.open(name, _nofollow_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise DependencyFreezeError(f"Unable to inspect {label}.") from exc
    try:
        info = os.fstat(descriptor)
        if (
            _is_reparse_stat(path_info)
            or not stat.S_ISREG(path_info.st_mode)
            or _is_reparse_stat(info)
            or not stat.S_ISREG(info.st_mode)
            or (path_info.st_dev, path_info.st_ino) != (info.st_dev, info.st_ino)
            or info.st_uid not in owners
            or _is_group_or_world_writable(info)
            or info.st_nlink not in {1, 2}
            or info.st_size <= 0
        ):
            raise DependencyFreezeError(f"{label} custody is invalid.")
        return info
    finally:
        os.close(descriptor)


def _recover_incomplete_build_attempt(
    repo: pathlib.Path,
    held_attempt: _HeldDirectory,
    held_artifact_parent: _HeldDirectory,
    artifact_path: pathlib.Path,
    receipt_path: pathlib.Path,
    owners: frozenset[int],
    *,
    attested: bool = False,
) -> None:
    attempt_fd = held_attempt.components[-1].descriptor
    parent_fd = held_artifact_parent.components[-1].descriptor
    artifacts_component = next(
        (
            component
            for component in held_attempt.components
            if component.relative == ".artifacts"
        ),
        None,
    )
    if artifacts_component is None:
        raise DependencyFreezeError("Build attempt is outside .artifacts custody.")
    artifacts_fd = artifacts_component.descriptor
    _acquire_publication_lock(held_attempt.repo_descriptor, artifacts_fd, owners)
    try:
        names = set(
            _list_directory_names(
                attempt_fd, held_attempt.components[-1].relative
            )
        )
        allowed = (
            {BUILD_ATTEMPT_JOURNAL_NAME, ".claim", ".receipt"}
            if attested
            else {
                BUILD_ATTEMPT_JOURNAL_NAME,
                ".claim",
                ".producer",
                ".receipt",
                artifact_path.name,
            }
        )
        if names - allowed:
            raise DependencyFreezeError(
                "Build attempt contains unknown post-mortem state."
            )
        if not names:
            return
        receipt_anchor = receipt_path.with_name(receipt_path.name + ".sha256")
        receipt_parent = _hold_repo_directory(
            repo, receipt_path.parent, owners, label="Build receipt parent"
        )
        try:
            receipt_parent_fd = receipt_parent.components[-1].descriptor
            receipt_relative = pathlib.Path(
                _relative_repo_path(repo, receipt_path)
            )
            receipt_transaction_id = hashlib.sha256(
                receipt_relative.as_posix().encode("utf-8")
            ).hexdigest()
            receipt_stage_prefix = (
                f".freeze-staging-{receipt_transaction_id}-"
            )
            _remove_stale_publication_stages(
                artifacts_fd,
                receipt_parent_fd,
                receipt_stage_prefix,
                receipt_relative,
                receipt_path.name + ".sha256",
                owners,
            )
            try:
                os.lstat(receipt_path.name, dir_fd=receipt_parent_fd)
            except FileNotFoundError:
                receipt_record_exists = False
            else:
                receipt_record_exists = True
            try:
                os.lstat(receipt_anchor.name, dir_fd=receipt_parent_fd)
            except FileNotFoundError:
                receipt_anchor_exists = False
            else:
                receipt_anchor_exists = True
        finally:
            _close_held_directory(receipt_parent)
        if receipt_record_exists != receipt_anchor_exists:
            raise DependencyFreezeError(
                "Build receipt has an incomplete post-mortem commit marker."
            )
        if receipt_record_exists:
            raise DependencyFreezeError(
                "Committed post-mortem build state requires owner review and cannot be reused."
            )
        expected_artifact_path = _relative_repo_path(repo, artifact_path)
        expected_receipt_path = _relative_repo_path(repo, receipt_path)
        attempt_nonce = held_attempt.components[-1].name.removeprefix(
            ".build-attempt-"
        )
        claim_payload: bytes | None = None
        claim_binding: tuple[str, str] | None = None
        if ".claim" in names:
            try:
                claim_payload, _claim_info = _read_publication_entry(
                    attempt_fd,
                    ".claim",
                    owners,
                    label="post-mortem attempt claim",
                )
                claim_record = _load_json_object(
                    claim_payload, "Post-mortem attempt claim"
                )
                claim_binding = (
                    _require_str(
                        claim_record.get("nonce"), "Post-mortem claim nonce"
                    ),
                    _require_str(
                        claim_record.get("artifact_path"),
                        "Post-mortem claim artifact path",
                    ),
                )
            except DependencyFreezeError:
                claim_payload = None
                claim_binding = None
        if claim_binding is not None and claim_binding != (
            attempt_nonce,
            expected_artifact_path,
        ):
            raise DependencyFreezeError(
                "Build attempt claim belongs to another transaction."
            )
        commit_binding: tuple[str, str, str, str] | None = None
        if ".receipt" in names:
            try:
                commit_payload, _commit_info = _read_publication_entry(
                    attempt_fd,
                    ".receipt",
                    owners,
                    label="post-mortem attempt journal",
                )
                commit_record = _parse_build_attempt_commit(
                    _load_json_object(
                        commit_payload, "Post-mortem attempt journal"
                    )
                )
                commit_artifact = _require_exact_keys(
                    commit_record.get("artifact"),
                    {
                        "path",
                        "name",
                        "size_bytes",
                        "sha256",
                        "modified_time_ns",
                        "device",
                        "inode",
                    },
                    "Post-mortem attempt artifact",
                )
                commit_binding = (
                    _require_str(
                        commit_record.get("nonce"),
                        "Post-mortem commit nonce",
                    ),
                    _require_str(
                        commit_record.get("build_receipt_path"),
                        "Post-mortem receipt path",
                    ),
                    _require_str(
                        commit_artifact.get("path"),
                        "Post-mortem artifact path",
                    ),
                    _require_sha256(
                        commit_record.get("claim_sha256"),
                        "Post-mortem claim digest",
                    ),
                )
            except DependencyFreezeError:
                commit_binding = None
        if commit_binding is not None:
            expected_claim_sha = (
                hashlib.sha256(claim_payload).hexdigest()
                if claim_payload is not None
                else ""
            )
            if commit_binding != (
                attempt_nonce,
                expected_receipt_path,
                expected_artifact_path,
                expected_claim_sha,
            ):
                raise DependencyFreezeError(
                    "Build attempt journal belongs to another transaction."
                )
        attempt_output_info: os.stat_result | None = None
        final_info: os.stat_result | None = None
        if attested:
            # The producer owns its attested artifact; only the uncommitted
            # claim and journal of this transaction are rolled back.
            pass
        elif artifact_path.name in names:
            attempt_output_info = _inspect_rollback_regular_entry(
                attempt_fd,
                artifact_path.name,
                owners,
                label="post-mortem attempt output",
                allowed_modes=frozenset({0o600}),
                allowed_links=frozenset({1, 2}),
                max_bytes=BUILD_ATTEMPT_BYTES_LIMIT,
            )
        try:
            os.lstat(artifact_path.name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        else:
            if not attested:
                final_info = _inspect_build_artifact_entry(
                    parent_fd,
                    artifact_path.name,
                    owners,
                    "post-mortem published artifact",
                )
        if final_info is not None and attempt_output_info is None:
            raise DependencyFreezeError(
                "Uncommitted artifact lacks its retained attempt hardlink."
            )
        if final_info is not None and attempt_output_info is not None and (
            final_info.st_dev,
            final_info.st_ino,
        ) != (attempt_output_info.st_dev, attempt_output_info.st_ino):
            raise DependencyFreezeError(
                "Post-mortem artifact and attempt hardlink identities diverged."
            )
        if final_info is not None:
            _strict_unlink_at(
                parent_fd, artifact_path.name, "uncommitted built artifact"
            )
        if attempt_output_info is not None:
            _strict_unlink_at(
                attempt_fd, artifact_path.name, "uncommitted attempt output"
            )
        if ".producer" in names:
            _inspect_rollback_regular_entry(
                attempt_fd,
                ".producer",
                owners,
                label="uncommitted producer snapshot",
                allowed_modes=frozenset({0o400}),
                max_bytes=BUILD_ATTEMPT_BYTES_LIMIT,
            )
            _strict_unlink_at(
                attempt_fd, ".producer", "uncommitted producer snapshot"
            )
        if ".receipt" in names:
            _inspect_rollback_regular_entry(
                attempt_fd,
                ".receipt",
                owners,
                label="uncommitted attempt journal",
                allowed_modes=frozenset({0o400}),
            )
            _strict_unlink_at(
                attempt_fd, ".receipt", "uncommitted attempt journal"
            )
        if ".claim" in names:
            _inspect_rollback_regular_entry(
                attempt_fd,
                ".claim",
                owners,
                label="uncommitted attempt claim",
                allowed_modes=frozenset({0o400}),
            )
            _strict_unlink_at(
                attempt_fd, ".claim", "uncommitted attempt claim"
            )
        _rebind_build_attempt_directory(held_attempt)
        _rebind_publication_directory(held_artifact_parent)
        return
    finally:
        try:
            fcntl.flock(artifacts_fd, fcntl.LOCK_UN)
        finally:
            fcntl.flock(held_attempt.repo_descriptor, fcntl.LOCK_UN)


def _finish_producer_attested_build(
    *,
    repo: pathlib.Path,
    index_path: pathlib.Path,
    platform: str,
    begin: dict[str, object],
    begun: dt.datetime,
    begin_path: pathlib.Path,
    begin_sha: str,
    attempt: dict[str, object],
    held_attempt: _HeldDirectory,
    held_artifact_parent: _HeldDirectory,
    artifact_path: pathlib.Path,
    output: pathlib.Path,
    owners: frozenset[int],
    verified: dict[str, object],
    source_freeze: dict[str, object],
    toolchain_custody: dict[str, object],
    custody: object,
    held_producer: _HeldRegularFile,
    producer_record: dict[str, object],
    toolchain: dict[str, object],
    remote_run_record: pathlib.Path | None = None,
    secret_inventory_path: str | None = None,
) -> dict[str, object]:
    """Bind an artifact the host producer already built to a receipt.

    The producer is not re-run. The exact artifact is held by descriptor and
    hashed, and the receipt binds that digest together with the producer
    digest, the begin receipt and its single-use attempt, the toolchain pin and
    the verified release index, exactly as the witnessed path does.
    """

    remote = producer_record.get("execution") == PRODUCER_EXECUTION_REMOTE_ATTESTED
    if remote:
        if (
            remote_run_record is None
            or (platform, producer_record.get("host")) not in REMOTE_ATTESTED_PLATFORM_HOSTS
        ):
            raise DependencyFreezeError(
                f"{platform} build receipt cannot be remote-attested on "
                f"{producer_record.get('host')}."
            )
    elif (platform, producer_record.get("host")) not in PRODUCER_ATTESTED_PLATFORM_HOSTS:
        raise DependencyFreezeError(
            f"{platform} build receipt cannot be producer-attested on "
            f"{producer_record.get('host')}."
        )
    parent_fd = held_artifact_parent.components[-1].descriptor
    try:
        entry = os.lstat(artifact_path.name, dir_fd=parent_fd)
    except FileNotFoundError as exc:
        raise DependencyFreezeError(
            "Producer-attested artifact must already exist."
        ) from exc
    if _is_reparse_stat(entry) or not stat.S_ISREG(entry.st_mode):
        raise DependencyFreezeError(
            "Producer-attested artifact must be a regular non-symlink file."
        )
    held_artifact = _hold_repo_regular_file(
        repo, artifact_path, owners, label="Producer-attested artifact"
    )
    held_claim: _HeldRegularFile | None = None
    held_commit: _HeldRegularFile | None = None
    try:
        info = held_artifact.info
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size <= 0
            or info.st_size > BUILD_ATTEMPT_BYTES_LIMIT
            or (info.st_dev, info.st_ino) != (entry.st_dev, entry.st_ino)
        ):
            raise DependencyFreezeError(
                "Producer-attested artifact must be one non-empty single-link "
                "regular file."
            )
        artifact_modified = dt.datetime.fromtimestamp(
            info.st_mtime, tz=dt.timezone.utc
        )
        now = dt.datetime.now(tz=dt.timezone.utc)
        if artifact_modified <= begun or artifact_modified > now + dt.timedelta(minutes=5):
            raise DependencyFreezeError(
                "Producer-attested artifact modification time is outside its build attempt."
            )
        artifact_payload = held_artifact.payload
        artifact_digest = hashlib.sha256(artifact_payload).hexdigest()
        _validate_release_artifact_bytes(
            platform,
            _require_str(toolchain.get("target"), "Toolchain target"),
            artifact_path.name,
            artifact_payload,
        )
        remote_binding = (
            _require_remote_run_record(
                repo,
                platform,
                begin,
                begin_sha,
                remote_run_record,
                {
                    "name": artifact_path.name,
                    "size_bytes": info.st_size,
                    "sha256": artifact_digest,
                },
                producer_record,
                toolchain,
                owners,
            )
            if remote and remote_run_record is not None
            else None
        )
        # A Windows build host defers the exact secret scan to the release host, so
        # a remote Windows receipt is made only after this worker has run the scan on
        # the bytes it holds. The caller names the inventory by path and cannot supply
        # a scan result, and no other receipt takes an inventory.
        if (secret_inventory_path is not None) != (platform == "windows"):
            raise DependencyFreezeError(
                "A Windows receipt requires the authenticated secret inventory "
                "path, and no other receipt accepts one."
            )
        if platform == "windows" and remote_binding is None:
            raise DependencyFreezeError(
                "A producer-attested Windows receipt cannot carry the worker's secret scan."
            )
        scan_binding: dict[str, object] | None = None
        if secret_inventory_path is not None and remote_binding is not None:
            scan = _run_release_host_secret_scan(
                repo,
                artifact_path,
                {
                    "name": artifact_path.name,
                    "size_bytes": info.st_size,
                    "sha256": artifact_digest,
                },
                toolchain,
                secret_inventory_path,
                owners,
            )
            scan_binding = {
                "record": scan,
                "sha256": hashlib.sha256(_canonical_json(scan)).hexdigest(),
            }
            remote_binding["release_host_secret_scan"] = scan_binding
        claim_record: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "contract": BUILD_ATTEMPT_CONTRACT,
            "claimed_utc": _utc_now(),
            "release": verified["release"],
            "platform": platform,
            "nonce": attempt["nonce"],
            "build_begin_sha256": begin_sha,
            "release_input_index": begin["release_input_index"],
            "platform_manifest": begin["platform_manifest"],
            "source_freeze": source_freeze,
            "toolchain_custody": toolchain_custody,
            "producer": producer_record,
            "toolchain": toolchain,
            "artifact_path": _relative_repo_path(repo, artifact_path),
        }
        if scan_binding is not None:
            claim_record["release_host_secret_scan"] = scan_binding
        held_claim, claim_digest = _write_build_attempt_claim(
            repo, held_attempt, claim_record, owners
        )
        _rebind_held_regular_file(held_artifact)
        _rebind_held_regular_file(held_producer)
        _rebind_authenticated_custody(repo, custody)
        verify_release_index(repo, index_path, platform)
        source_identity = (int(info.st_dev), int(info.st_ino))
        finished_utc = _utc_now()
        commit_record: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "contract": BUILD_ATTEMPT_COMMIT_CONTRACT,
            "nonce": attempt["nonce"],
            "build_begin_sha256": begin_sha,
            "claim_sha256": claim_digest,
            "build_receipt_path": _relative_repo_path(repo, output),
            "artifact": {
                "path": _relative_repo_path(repo, artifact_path),
                "name": artifact_path.name,
                "size_bytes": info.st_size,
                "sha256": artifact_digest,
                "modified_time_ns": info.st_mtime_ns,
                "device": source_identity[0],
                "inode": source_identity[1],
            },
        }
        held_commit, commit_digest = _write_build_attempt_commit(
            repo, held_attempt, commit_record, owners
        )
        record: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "contract": BUILD_RECEIPT_CONTRACT,
            "release": verified["release"],
            "platform": platform,
            "begun_utc": begin["begun_utc"],
            "finished_utc": finished_utc,
            "build_begin_receipt": {
                "path": _relative_repo_path(repo, begin_path),
                "sha256": begin_sha,
            },
            "build_attempt": {
                **attempt,
                "claim_sha256": claim_digest,
                "commit_journal_sha256": commit_digest,
                "claim_record": claim_record,
                "commit_record": commit_record,
            },
            "release_input_index": begin["release_input_index"],
            "platform_manifest": begin["platform_manifest"],
            "shared_revision": begin["shared_revision"],
            "source_freeze": source_freeze,
            "toolchain_custody": toolchain_custody,
            "producer": producer_record,
            "toolchain": toolchain,
            "artifact": {
                "name": artifact_path.name,
                "size_bytes": info.st_size,
                "sha256": artifact_digest,
                "modified_time_ns": info.st_mtime_ns,
            },
            "sha256_anchor": output.name + ".sha256",
            "publication_authorized": False,
        }
        if remote_binding is not None:
            record["remote_attestation"] = remote_binding
        hook = _POST_FINAL_CAPTURE_HOOK
        if callable(hook):
            hook()
        _rebind_held_regular_file(held_artifact)
        _rebind_build_attempt_file(held_claim)
        _rebind_build_attempt_file(held_commit)
        _rebind_build_attempt_directory(held_attempt)
        _rebind_held_regular_file(held_producer)
        _rebind_authenticated_custody(repo, custody)
        _write_anchored_record(repo, output, record, "Build receipt")
        _rebind_held_regular_file(held_artifact)
        _rebind_build_attempt_file(held_claim)
        _rebind_build_attempt_file(held_commit)
        _rebind_build_attempt_directory(held_attempt)
        _close_held_regular_file(held_commit)
        held_commit = None
        _close_held_regular_file(held_claim)
        held_claim = None
        # Retiring the attempt directory consumes the begin nonce: a second
        # finish-build for the same begin receipt finds no attempt to claim.
        _retire_completed_build_attempt(
            held_attempt,
            frozenset({BUILD_ATTEMPT_JOURNAL_NAME, ".claim", ".receipt"}),
        )
        _retain_regular_file_until_return(held_artifact)
        held_artifact = None
        return record
    finally:
        if held_commit is not None:
            _close_held_regular_file(held_commit)
        if held_claim is not None:
            _close_held_regular_file(held_claim)
        if held_artifact is not None:
            _close_held_regular_file(held_artifact)


@_retain_anchored_inputs_until_return
def finish_build_receipt(
    repo: pathlib.Path,
    index_path: pathlib.Path,
    platform: str,
    begin_path: pathlib.Path,
    artifact_path: pathlib.Path,
    producer_path: str,
    toolchain_name: str,
    toolchain_version: str,
    toolchain_revision: str,
    target: str,
    output: pathlib.Path,
    remote_host: str | None = None,
    remote_run_record: pathlib.Path | None = None,
    secret_inventory_path: str | None = None,
) -> dict[str, object]:
    repo = secure_repo_path(repo, pathlib.Path("."), "Repository root", must_exist=True)
    if platform not in PLATFORM_ROOTS:
        raise DependencyFreezeError(f"Unsupported platform: {platform}")
    _require_build_witness_boundary(repo, platform)
    # Whether the worker scans is decided by the platform and the installer it will
    # hold, never by --remote-host, the begin record or any other declared mode. A
    # Windows finish in any mode takes the inventory path, and every other platform
    # refuses one, before anything is claimed or run.
    scan_required = _release_host_secret_scan_required(platform, pathlib.Path(artifact_path).name)
    if scan_required and secret_inventory_path is None:
        raise DependencyFreezeError(
            "A Windows build receipt is made only after the worker has run the exact "
            "secret scan, so finishing one requires the authenticated secret "
            "inventory path."
        )
    if not scan_required and secret_inventory_path is not None:
        raise DependencyFreezeError(
            "Only a Windows build receipt takes a secret inventory path."
        )
    index_path = secure_repo_path(
        repo, index_path, "Release input index", must_exist=True
    )
    begin_path = secure_repo_path(repo, begin_path, "Build begin receipt", must_exist=True)
    output = _require_artifacts_output(
        repo, output, "Build receipt output", allow_missing_leaf=True
    )
    begin, begun, begin_sha, reference = _load_build_begin(
        repo, begin_path, index_path, platform
    )
    artifact_path = secure_repo_path(
        repo,
        artifact_path,
        "Built artifact destination",
        must_exist=False,
        allow_missing_leaf=True,
    )
    artifact_parent = secure_repo_path(
        repo, artifact_path.parent, "Built artifact parent", must_exist=True
    )
    if (
        pathlib.PurePath(artifact_path.name).name != artifact_path.name
        or not re.fullmatch(_artifact_name_pattern(platform), artifact_path.name)
    ):
        raise DependencyFreezeError("Built artifact filename is unsafe.")
    owners = _allowed_owners(repo)
    producer_host = _native_process_host()
    expected_producer = _platform_build_producer(platform, producer_host)
    execution = _platform_build_execution(platform, producer_host)
    if remote_host is not None or remote_run_record is not None or "remote_attestation" in begin:
        producer_host, expected_producer, execution = _remote_attested_finish_identity(
            platform, remote_host, remote_run_record, begin
        )
    normalized_producer = producer_path.replace("\\", "/")
    if normalized_producer != expected_producer:
        raise DependencyFreezeError(
            f"{platform} build receipt on {producer_host} must use {expected_producer}."
        )
    producer = secure_repo_path(
        repo, pathlib.Path(normalized_producer), "Build producer", must_exist=True
    )
    held_producer = _hold_repo_regular_file(
        repo, producer, owners, label="Build producer"
    )
    producer_digest = hashlib.sha256(held_producer.payload).hexdigest()
    producer_record: dict[str, object] = {
        "path": normalized_producer,
        "sha256": producer_digest,
        "host": producer_host,
        "execution": execution,
    }
    toolchain = {
        "name": _safe_toolchain_value(toolchain_name, "Toolchain name"),
        "version": _safe_toolchain_value(toolchain_version, "Toolchain version"),
        "revision": _safe_toolchain_value(
            toolchain_revision, "Toolchain revision", allow_empty=True
        ),
        "target": _safe_toolchain_value(target, "Toolchain target"),
    }
    _assert_toolchain_matches_reviewed_pin(
        repo,
        str(toolchain["name"]),
        str(toolchain["version"]),
        str(toolchain["revision"]),
    )
    _assert_allowed_target(platform, str(toolchain["target"]))
    verified = verify_release_index(repo, index_path, platform)
    custody = _load_current_authenticated_custody(repo)
    source_freeze = custody.source_freeze
    toolchain_custody = custody.toolchain_custody
    if begin["platform_manifest"]["sha256"] != reference["sha256"]:
        _close_held_regular_file(held_producer)
        raise DependencyFreezeError("Platform manifest changed during build.")
    attempt = _parse_build_attempt(begin.get("build_attempt"))
    attempt_path = secure_repo_path(
        repo,
        pathlib.Path(_require_str(attempt.get("directory"), "Build attempt directory")),
        "Build attempt",
        must_exist=True,
    )
    held_attempt = _hold_repo_directory(
        repo, attempt_path, owners, label="Build attempt"
    )
    held_claim: _HeldRegularFile | None = None
    held_commit: _HeldRegularFile | None = None
    held_journal_begin: _HeldRegularFile | None = None
    held_journal_anchor: _HeldRegularFile | None = None
    held_journal: _HeldRegularFile | None = None
    held_private_producer: _HeldRegularFile | None = None
    held_output: _HeldRegularFile | None = None
    held_final: _HeldRegularFile | None = None
    held_artifact_parent: _HeldDirectory | None = None
    attempt_output_descriptor: int | None = None
    attempt_lock_descriptor: int | None = None
    final_identity: tuple[int, int] | None = None
    published_receipt: tuple[pathlib.Path, str] | None = None
    receipt_commit_reached = False
    try:
        attempt_info = os.fstat(held_attempt.components[-1].descriptor)
        if (
            _build_attempt_directory_identity(attempt_info)
            != attempt.get("directory_identity")
            or _held_directory_identity(
                held_attempt, ".artifacts", "Build attempt parent"
            )
            != attempt.get("artifacts_directory_identity")
        ):
            raise DependencyFreezeError(
                "Build attempt or persistent .artifacts identity changed."
            )
        attempt_lock_descriptor = _acquire_build_attempt_lock(
            held_attempt, owners
        )
        (
            _attempt_journal,
            _attempt_begin_path,
            held_journal_begin,
            held_journal_anchor,
            held_journal,
        ) = _load_authenticated_attempt_journal(repo, held_attempt, owners)
        held_artifact_parent = _hold_repo_directory(
            repo, artifact_parent, owners, label="Built artifact parent"
        )
        _recover_incomplete_build_attempt(
            repo,
            held_attempt,
            held_artifact_parent,
            artifact_path,
            output,
            owners,
            attested=execution
            in (PRODUCER_EXECUTION_ATTESTED, PRODUCER_EXECUTION_REMOTE_ATTESTED),
        )
        if (
            output.exists()
            or output.is_symlink()
            or output.with_name(output.name + ".sha256").exists()
            or output.with_name(output.name + ".sha256").is_symlink()
        ):
            raise DependencyFreezeError(
                "Refusing to overwrite immutable build receipt output."
            )
        if execution in (PRODUCER_EXECUTION_ATTESTED, PRODUCER_EXECUTION_REMOTE_ATTESTED):
            return _finish_producer_attested_build(
                repo=repo,
                index_path=index_path,
                platform=platform,
                begin=begin,
                begun=begun,
                begin_path=begin_path,
                begin_sha=begin_sha,
                attempt=attempt,
                held_attempt=held_attempt,
                held_artifact_parent=held_artifact_parent,
                artifact_path=artifact_path,
                output=output,
                owners=owners,
                verified=verified,
                source_freeze=source_freeze,
                toolchain_custody=toolchain_custody,
                custody=custody,
                held_producer=held_producer,
                producer_record=producer_record,
                toolchain=toolchain,
                remote_run_record=remote_run_record,
                secret_inventory_path=secret_inventory_path,
            )
        if artifact_path.exists() or artifact_path.is_symlink():
            raise DependencyFreezeError(
                "Built artifact destination must not preexist the witnessed attempt."
            )
        claim_record: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "contract": BUILD_ATTEMPT_CONTRACT,
            "claimed_utc": _utc_now(),
            "release": verified["release"],
            "platform": platform,
            "nonce": attempt["nonce"],
            "build_begin_sha256": begin_sha,
            "release_input_index": begin["release_input_index"],
            "platform_manifest": begin["platform_manifest"],
            "source_freeze": source_freeze,
            "toolchain_custody": toolchain_custody,
            "producer": producer_record,
            "toolchain": toolchain,
            "artifact_path": _relative_repo_path(repo, artifact_path),
        }
        held_claim, claim_digest = _write_build_attempt_claim(
            repo, held_attempt, claim_record, owners
        )
        held_private_producer = _install_private_attempt_producer(
            repo, held_attempt, held_producer, owners
        )
        attempt_output_descriptor, attempt_output_identity = (
            _create_attempt_output_descriptor(held_attempt, artifact_path.name)
        )
        _rebind_held_regular_file(held_producer)
        _rebind_authenticated_custody(repo, custody)
        attempt_output_descriptor = _run_witnessed_producer(
            held_attempt,
            held_private_producer,
            platform,
            _require_str(attempt.get("nonce"), "Build attempt nonce"),
            artifact_path.name,
            attempt_output_descriptor,
            producer.suffix,
        )
        _rebind_build_attempt_file(held_private_producer)
        _rebind_held_regular_file(held_producer)
        _strict_unlink_at(
            held_attempt.components[-1].descriptor,
            ".producer",
            "private producer snapshot",
        )
        _close_held_regular_file(held_private_producer)
        held_private_producer = None
        _rebind_build_attempt_directory(held_attempt)
        _rebind_build_attempt_file(held_claim)
        _rebind_held_regular_file(held_producer)
        _rebind_authenticated_custody(repo, custody)
        verify_release_index(repo, index_path, platform)
        held_output = _validated_attempt_output(
            repo,
            held_attempt,
            artifact_path.name,
            owners,
            attempt_output_descriptor,
            attempt_output_identity,
        )
        artifact_modified = dt.datetime.fromtimestamp(
            held_output.info.st_mtime, tz=dt.timezone.utc
        )
        now = dt.datetime.now(tz=dt.timezone.utc)
        if artifact_modified <= begun or artifact_modified > now + dt.timedelta(minutes=5):
            raise DependencyFreezeError(
                "Witnessed producer output modification time is outside its attempt."
            )
        artifact_payload = held_output.payload
        artifact_digest = hashlib.sha256(artifact_payload).hexdigest()
        _validate_release_artifact_bytes(
            platform,
            _require_str(toolchain.get("target"), "Toolchain target"),
            artifact_path.name,
            artifact_payload,
        )
        # The witnessed producer ran, but a Windows installer is accepted only after
        # the worker has scanned these exact bytes itself, whatever the producer did.
        witnessed_scan: dict[str, object] | None = None
        if scan_required:
            witnessed_scan_record = _run_release_host_secret_scan(
                repo,
                attempt_path / artifact_path.name,
                {
                    "name": artifact_path.name,
                    "size_bytes": held_output.info.st_size,
                    "sha256": artifact_digest,
                },
                toolchain,
                secret_inventory_path,
                owners,
            )
            witnessed_scan = {
                "record": witnessed_scan_record,
                "sha256": hashlib.sha256(
                    _canonical_json(witnessed_scan_record)
                ).hexdigest(),
            }
        _rebind_build_attempt_file(held_output)
        _rebind_held_regular_file(held_producer)
        _rebind_authenticated_custody(repo, custody)
        source_identity = (
            int(held_output.info.st_dev),
            int(held_output.info.st_ino),
        )
        parent_fd = held_artifact_parent.components[-1].descriptor
        attempt_fd = held_attempt.components[-1].descriptor
        _reject_casefold_lookup(
            parent_fd, _relative_repo_path(repo, artifact_parent), artifact_path.name
        )
        try:
            os.lstat(artifact_path.name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        else:
            raise DependencyFreezeError(
                "Built artifact destination must not preexist the witnessed attempt."
            )
        try:
            os.link(
                artifact_path.name,
                artifact_path.name,
                src_dir_fd=attempt_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
            final_identity = source_identity
            _fsync_directory(parent_fd, "built artifact parent")
        except FileExistsError as exc:
            raise DependencyFreezeError(
                "Built artifact destination appeared during publication."
            ) from exc
        except OSError as exc:
            raise DependencyFreezeError(
                "Unable to publish witnessed producer output."
            ) from exc
        final_fd = os.open(
            artifact_path.name, _nofollow_flags(), dir_fd=parent_fd
        )
        try:
            linked_info = os.fstat(final_fd)
            if (
                not stat.S_ISREG(linked_info.st_mode)
                or (linked_info.st_dev, linked_info.st_ino) != source_identity
                or linked_info.st_nlink != 2
            ):
                raise DependencyFreezeError(
                    "Witnessed artifact publication identity changed."
                )
        finally:
            os.close(final_fd)
        finished_utc = _utc_now()
        commit_record: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "contract": BUILD_ATTEMPT_COMMIT_CONTRACT,
            "nonce": attempt["nonce"],
            "build_begin_sha256": begin_sha,
            "claim_sha256": claim_digest,
            "build_receipt_path": _relative_repo_path(repo, output),
            "artifact": {
                "path": _relative_repo_path(repo, artifact_path),
                "name": artifact_path.name,
                "size_bytes": held_output.info.st_size,
                "sha256": artifact_digest,
                "modified_time_ns": held_output.info.st_mtime_ns,
                "device": source_identity[0],
                "inode": source_identity[1],
            },
        }
        held_commit, commit_digest = _write_build_attempt_commit(
            repo, held_attempt, commit_record, owners
        )
        record: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "contract": BUILD_RECEIPT_CONTRACT,
            "release": verified["release"],
            "platform": platform,
            "begun_utc": begin["begun_utc"],
            "finished_utc": finished_utc,
            "build_begin_receipt": {
                "path": _relative_repo_path(repo, begin_path),
                "sha256": begin_sha,
            },
            "build_attempt": {
                **attempt,
                "claim_sha256": claim_digest,
                "commit_journal_sha256": commit_digest,
                "claim_record": claim_record,
                "commit_record": commit_record,
            },
            "release_input_index": begin["release_input_index"],
            "platform_manifest": begin["platform_manifest"],
            "shared_revision": begin["shared_revision"],
            "source_freeze": source_freeze,
            "toolchain_custody": toolchain_custody,
            "producer": producer_record,
            "toolchain": toolchain,
            "artifact": {
                "name": artifact_path.name,
                "size_bytes": held_output.info.st_size,
                "sha256": artifact_digest,
                "modified_time_ns": held_output.info.st_mtime_ns,
            },
            "sha256_anchor": output.name + ".sha256",
            "publication_authorized": False,
        }
        if witnessed_scan is not None:
            record["release_host_secret_scan"] = witnessed_scan
        hook = _POST_FINAL_CAPTURE_HOOK
        if callable(hook):
            hook()
        linked_info = _inspect_build_artifact_entry(
            parent_fd, artifact_path.name, owners, "published built artifact"
        )
        attempt_link_info = os.fstat(attempt_output_descriptor)
        if (
            (linked_info.st_dev, linked_info.st_ino) != source_identity
            or linked_info.st_nlink != 2
            or (attempt_link_info.st_dev, attempt_link_info.st_ino)
            != source_identity
            or attempt_link_info.st_nlink != 2
        ):
            raise DependencyFreezeError(
                "Witnessed artifact hardlink custody changed before receipt commit."
            )
        _rebind_build_attempt_file(held_claim)
        _rebind_build_attempt_file(held_commit)
        _rebind_build_attempt_directory(held_attempt)
        _rebind_held_regular_file(held_producer)
        _rebind_authenticated_custody(repo, custody)
        try:
            published_receipt = _write_anchored_record(
                repo, output, record, "Build receipt"
            )
        except _CommittedPublicationError:
            receipt_commit_reached = True
            raise
        receipt_commit_reached = True
        _rebind_build_attempt_file(held_claim)
        _rebind_build_attempt_file(held_commit)
        _rebind_build_attempt_directory(held_attempt)
        _rebind_held_regular_file(held_producer)
        _rebind_authenticated_custody(repo, custody)
        _strict_unlink_at(
            attempt_fd,
            artifact_path.name,
            "committed build attempt output hardlink",
        )
        _close_held_regular_file(held_output)
        held_output = None
        _close_held_regular_file(held_commit)
        held_commit = None
        _close_held_regular_file(held_claim)
        held_claim = None
        _retire_completed_build_attempt(
            held_attempt,
            frozenset({BUILD_ATTEMPT_JOURNAL_NAME, ".claim", ".receipt"}),
        )
        held_final = _hold_repo_regular_file(
            repo, artifact_path, owners, label="Built artifact"
        )
        if (
            held_final.payload != artifact_payload
            or (held_final.info.st_dev, held_final.info.st_ino) != source_identity
            or held_final.info.st_nlink != 1
        ):
            raise DependencyFreezeError("Published built artifact changed.")
        _retain_regular_file_until_return(held_final)
        held_final = None
        return record
    except Exception:
        if (
            not receipt_commit_reached
            and final_identity is not None
            and held_artifact_parent is not None
        ):
            _strict_unlink_if_same_inode(
                held_artifact_parent.components[-1].descriptor,
                artifact_path.name,
                final_identity,
                "uncommitted built artifact",
            )
        raise
    finally:
        if held_journal is not None:
            _close_held_regular_file(held_journal)
        if held_journal_anchor is not None:
            _close_held_regular_file(held_journal_anchor)
        if held_journal_begin is not None:
            _close_held_regular_file(held_journal_begin)
        if held_final is not None:
            _close_held_regular_file(held_final)
        if attempt_output_descriptor is not None:
            _close_quietly(attempt_output_descriptor)
        if held_output is not None:
            _close_held_regular_file(held_output)
        if held_commit is not None:
            _close_held_regular_file(held_commit)
        if held_private_producer is not None:
            _close_held_regular_file(held_private_producer)
        if held_claim is not None:
            _close_held_regular_file(held_claim)
        if held_artifact_parent is not None:
            _close_held_directory(held_artifact_parent)
        _release_build_attempt_lock(attempt_lock_descriptor)
        _close_held_directory(held_attempt)
        _close_held_regular_file(held_producer)


def _validate_receipt_index_carry_forward(
    repo: pathlib.Path,
    current_index: dict[str, object],
    current_verified: dict[str, object],
    platform: str,
    recorded_index_value: object,
) -> tuple[dict[str, object], dict[str, object]]:
    """Validate a receipt's original index against current scoped inputs."""

    current_reference = current_index["platform_manifests"][platform]
    recorded_index_reference = _require_exact_keys(
        recorded_index_value,
        {"path", "sha256"},
        "Recorded release input index",
    )
    recorded_index_path = secure_repo_path(
        repo,
        pathlib.Path(
            _require_str(recorded_index_reference.get("path"), "Recorded index path")
        ),
        "Recorded release input index",
        must_exist=True,
    )
    recorded_index, recorded_index_sha = _read_anchored_json(
        repo, recorded_index_path, "Recorded release input index"
    )
    if (
        recorded_index_reference.get("path")
        != _relative_repo_path(repo, recorded_index_path)
        or recorded_index_reference.get("sha256") != recorded_index_sha
    ):
        raise DependencyFreezeError("Recorded release input index binding changed.")
    recorded_scoped = recorded_index.get("contract") == SCOPED_INDEX_CONTRACT
    _require_exact_keys(
        recorded_index,
        INDEX_RECORD_KEYS
        | (SCOPED_INDEX_EXTRA_KEYS if recorded_scoped else frozenset()),
        "Recorded release input index",
    )
    recorded_scope = (
        _validate_scoped_index_scope(recorded_index)
        if recorded_scoped
        else tuple(sorted(CANONICAL_FREEZE_PLATFORMS))
    )
    recorded_platforms = recorded_index.get("platform_manifests")
    if (
        type(recorded_platforms) is not dict
        or set(recorded_platforms) != set(recorded_scope)
        or (not recorded_scoped and set(recorded_platforms) != set(PLATFORM_ROOTS))
    ):
        raise DependencyFreezeError("Recorded release input index platform set is incomplete.")
    recorded_platform_reference = _require_exact_keys(
        recorded_platforms.get(platform),
        {"path", "sha256", "artifact_input_fingerprint_sha256"},
        f"Recorded {platform} manifest",
    )
    recorded_shared_reference = _require_exact_keys(
        recorded_index.get("shared_manifest"),
        {"path", "sha256"},
        "Recorded shared manifest",
    )
    recorded_manifest_path = secure_repo_path(
        repo,
        recorded_index_path.parent
        / _require_str(recorded_platform_reference.get("path"), "Recorded platform path"),
        f"Recorded {platform} manifest",
        must_exist=True,
    )
    recorded_shared_path = secure_repo_path(
        repo,
        recorded_index_path.parent
        / _require_str(recorded_shared_reference.get("path"), "Recorded shared path"),
        "Recorded shared manifest",
        must_exist=True,
    )
    recorded_expected_manifest: dict[str, object] = {
        "path": _relative_repo_path(repo, recorded_manifest_path),
        "sha256": _require_sha256(
            recorded_platform_reference.get("sha256"), "Recorded platform digest"
        ),
        "artifact_input_fingerprint_sha256": _require_sha256(
            recorded_platform_reference.get("artifact_input_fingerprint_sha256"),
            "Recorded platform fingerprint",
        ),
    }
    if (
        _require_int(recorded_index.get("schema_version"), "Recorded index schema")
        != SCHEMA_VERSION
        or _require_str(recorded_index.get("contract"), "Recorded index contract")
        != (SCOPED_INDEX_CONTRACT if recorded_scoped else INDEX_CONTRACT)
        or _require_str(recorded_index.get("release"), "Recorded index release")
        != current_verified["release"]
        or _require_str(recorded_index.get("shared_revision"), "Recorded index revision")
        != current_verified["shared_revision"]
        or _require_str(recorded_index.get("sha256_anchor"), "Recorded index anchor")
        != recorded_index_path.name + ".sha256"
        or _require_bool(recorded_index.get("manifest_set_complete"), "manifest_set_complete")
        != (not recorded_scoped)
        or _require_bool(recorded_index.get("publication_authorized"), "publication_authorized")
        is not False
        or recorded_platform_reference.get("path") != f"{platform.upper()}_INPUTS.json"
        or recorded_shared_reference.get("path") != "SHARED_INPUTS.json"
    ):
        raise DependencyFreezeError("Recorded release input index identity is invalid.")
    # A new scoped revision may regenerate immutable manifest containers (and
    # therefore their created_utc values and file hashes) even when the actual
    # shared and platform inputs are unchanged.  Re-verify the receipt's
    # original manifests against the current repository, then carry the receipt
    # forward by the semantic artifact-input fingerprint.  Comparing container
    # hashes here would incorrectly invalidate Windows/Linux/Apple artifacts
    # after an Android-only native change.
    try:
        _shared_result, shared_digest, _shared_record = _verify_manifest_authenticated(
            repo, recorded_shared_path
        )
        recorded_platform_verified, platform_digest, _platform_record = (
            _verify_manifest_authenticated(repo, recorded_manifest_path)
        )
    except DependencyFreezeError as exc:
        raise DependencyFreezeError(
            f"{platform} build receipt does not match the current shared/platform inputs."
        ) from exc
    if (
        shared_digest != _require_sha256(
            recorded_shared_reference.get("sha256"), "Recorded shared digest"
        )
        or platform_digest != recorded_expected_manifest["sha256"]
        or recorded_platform_verified.get("platform") != platform
        or recorded_platform_verified.get("artifact_input_fingerprint_sha256")
        != recorded_expected_manifest["artifact_input_fingerprint_sha256"]
        or recorded_expected_manifest["artifact_input_fingerprint_sha256"]
        != current_reference.get("artifact_input_fingerprint_sha256")
    ):
        raise DependencyFreezeError(
            f"{platform} build receipt does not match the current shared/platform inputs."
        )
    return recorded_index_reference, recorded_expected_manifest


def _verify_consumed_build_attempt(
    repo: pathlib.Path,
    begin_attempt_value: object,
    receipt_attempt_value: object,
    begin_sha: str,
    record: dict[str, object],
    receipt_path: pathlib.Path,
    artifact_path: pathlib.Path,
    begun: dt.datetime,
    finished: dt.datetime,
) -> None:
    begin_attempt = _parse_build_attempt(begin_attempt_value)
    receipt_attempt = _require_exact_keys(
        receipt_attempt_value,
        {
            "contract",
            "nonce",
            "directory",
            "directory_identity",
            "artifacts_directory_identity",
            "begin_receipt",
            "claim_sha256",
            "commit_journal_sha256",
            "claim_record",
            "commit_record",
        },
        "Consumed build attempt",
    )
    receipt_base = {
        key: receipt_attempt[key]
        for key in (
            "contract",
            "nonce",
            "directory",
            "directory_identity",
            "artifacts_directory_identity",
            "begin_receipt",
        )
    }
    _parse_build_attempt(receipt_base)
    claim_sha = _require_sha256(
        receipt_attempt.get("claim_sha256"), "Build attempt claim digest"
    )
    commit_sha = _require_sha256(
        receipt_attempt.get("commit_journal_sha256"),
        "Build attempt commit journal digest",
    )
    if receipt_base != begin_attempt:
        raise DependencyFreezeError("Build attempt does not match its begin receipt.")
    # The claim of a remote Windows receipt also carries the secret scan this worker
    # ran (see _run_release_host_secret_scan); no other claim has the field.
    producer_value = record.get("producer")
    scan_in_claim = (
        record.get("platform") == "windows"
        and type(producer_value) is dict
        and producer_value.get("execution") == PRODUCER_EXECUTION_REMOTE_ATTESTED
    )
    remote_value = record.get("remote_attestation")
    claim = _require_exact_keys(
        receipt_attempt.get("claim_record"),
        {
            "schema_version",
            "contract",
            "claimed_utc",
            "release",
            "platform",
            "nonce",
            "build_begin_sha256",
            "release_input_index",
            "platform_manifest",
            "source_freeze",
            "toolchain_custody",
            "producer",
            "toolchain",
            "artifact_path",
        }
        | ({"release_host_secret_scan"} if scan_in_claim else set()),
        "Embedded build attempt claim",
    )
    commit = _parse_build_attempt_commit(receipt_attempt.get("commit_record"))
    if (
        hashlib.sha256(_canonical_json(claim)).hexdigest() != claim_sha
        or hashlib.sha256(_canonical_json(commit)).hexdigest() != commit_sha
    ):
        raise DependencyFreezeError(
            "Embedded build attempt journal digest changed."
        )
    claimed = _parse_timestamp(claim.get("claimed_utc"), "Build attempt claim")
    commit_artifact = _require_exact_keys(
        commit.get("artifact"),
        {
            "path",
            "name",
            "size_bytes",
            "sha256",
            "modified_time_ns",
            "device",
            "inode",
        },
        "Build attempt commit artifact",
    )
    receipt_artifact = _require_exact_keys(
        record.get("artifact"),
        {"name", "size_bytes", "sha256", "modified_time_ns"},
        "Build artifact",
    )
    artifact_info = os.lstat(artifact_path)
    if (
        claimed < begun
        or claimed > finished
        or claim.get("schema_version") != SCHEMA_VERSION
        or claim.get("contract") != BUILD_ATTEMPT_CONTRACT
        or claim.get("release") != record.get("release")
        or claim.get("platform") != record.get("platform")
        or claim.get("nonce") != begin_attempt.get("nonce")
        or claim.get("build_begin_sha256") != begin_sha
        or claim.get("release_input_index") != record.get("release_input_index")
        or claim.get("platform_manifest") != record.get("platform_manifest")
        or claim.get("source_freeze") != record.get("source_freeze")
        or claim.get("toolchain_custody") != record.get("toolchain_custody")
        or claim.get("producer") != record.get("producer")
        or claim.get("toolchain") != record.get("toolchain")
        or claim.get("artifact_path") != _relative_repo_path(repo, artifact_path)
        or (
            scan_in_claim
            and claim.get("release_host_secret_scan")
            != (
                remote_value.get("release_host_secret_scan")
                if type(remote_value) is dict
                else None
            )
        )
        or commit.get("nonce") != begin_attempt.get("nonce")
        or commit.get("build_begin_sha256") != begin_sha
        or commit.get("claim_sha256") != claim_sha
        or commit.get("build_receipt_path")
        != _relative_repo_path(repo, receipt_path)
        or commit_artifact.get("path")
        != _relative_repo_path(repo, artifact_path)
        or commit_artifact.get("name") != receipt_artifact.get("name")
        or commit_artifact.get("size_bytes") != receipt_artifact.get("size_bytes")
        or commit_artifact.get("sha256") != receipt_artifact.get("sha256")
        or commit_artifact.get("modified_time_ns")
        != receipt_artifact.get("modified_time_ns")
        or commit_artifact.get("device") != int(artifact_info.st_dev)
        or commit_artifact.get("inode") != int(artifact_info.st_ino)
    ):
        raise DependencyFreezeError("Build attempt journal binding changed.")
    owners = _allowed_owners(repo)
    attempt_path = secure_repo_path(
        repo,
        pathlib.Path(_require_str(begin_attempt.get("directory"), "Build attempt directory")),
        "Build attempt",
        must_exist=False,
        allow_missing_leaf=True,
    )
    held_artifacts = _hold_repo_directory(
        repo, repo / ".artifacts", owners, label="Consumed build attempt parent"
    )
    if (
        _held_directory_identity(
            held_artifacts, ".artifacts", "Consumed build attempt parent"
        )
        != begin_attempt.get("artifacts_directory_identity")
    ):
        _close_held_directory(held_artifacts)
        raise DependencyFreezeError(
            "Consumed build attempt parent directory identity changed."
        )
    try:
        attempt_path_info = os.lstat(attempt_path)
    except FileNotFoundError:
        try:
            _rebind_consumed_artifacts_parent(held_artifacts)
        finally:
            _close_held_directory(held_artifacts)
        return
    except Exception:
        _close_held_directory(held_artifacts)
        raise
    if _is_reparse_stat(attempt_path_info) or not stat.S_ISDIR(attempt_path_info.st_mode):
        _close_held_directory(held_artifacts)
        raise DependencyFreezeError("Consumed build attempt custody is invalid.")
    try:
        held_attempt = _hold_repo_directory(
            repo, attempt_path, owners, label="Consumed build attempt"
        )
    except Exception:
        _close_held_directory(held_artifacts)
        raise
    held_claim: _HeldRegularFile | None = None
    held_commit: _HeldRegularFile | None = None
    held_journal_begin: _HeldRegularFile | None = None
    held_journal_anchor: _HeldRegularFile | None = None
    held_journal: _HeldRegularFile | None = None
    attempt_output_fd: int | None = None
    final_artifact_fd: int | None = None
    attempt_lock_descriptor: int | None = None
    try:
        attempt_lock_descriptor = _acquire_build_attempt_lock(
            held_attempt, owners
        )
        (
            _attempt_journal,
            _attempt_begin_path,
            held_journal_begin,
            held_journal_anchor,
            held_journal,
        ) = _load_authenticated_attempt_journal(repo, held_attempt, owners)
        attempt_info = os.fstat(held_attempt.components[-1].descriptor)
        names = _list_directory_names(
            held_attempt.components[-1].descriptor,
            _relative_repo_path(repo, attempt_path),
        )
        expected_names = {BUILD_ATTEMPT_JOURNAL_NAME, ".claim", ".receipt"}
        recovery_output_present = artifact_path.name in names
        accepted_names = expected_names | {artifact_path.name}
        if (
            _build_attempt_directory_identity(attempt_info)
            != begin_attempt.get("directory_identity")
            or _held_directory_identity(
                held_attempt, ".artifacts", "Consumed build attempt parent"
            )
            != begin_attempt.get("artifacts_directory_identity")
            or set(names) - accepted_names
        ):
            raise DependencyFreezeError(
                "Consumed build attempt custody is invalid or contains extra output."
            )
        if recovery_output_present:
            attempt_fd = held_attempt.components[-1].descriptor
            try:
                attempt_path_info = os.lstat(artifact_path.name, dir_fd=attempt_fd)
                attempt_output_fd = os.open(
                    artifact_path.name, _nofollow_flags(), dir_fd=attempt_fd
                )
                final_path_info = os.lstat(artifact_path)
                final_artifact_fd = os.open(artifact_path, _nofollow_flags())
            except OSError as exc:
                raise DependencyFreezeError(
                    "Committed attempt output could not be retained for recovery."
                ) from exc
            attempt_output_info = os.fstat(attempt_output_fd)
            final_output_info = os.fstat(final_artifact_fd)
            if (
                _is_reparse_stat(attempt_path_info)
                or _is_reparse_stat(final_path_info)
                or not stat.S_ISREG(attempt_output_info.st_mode)
                or not stat.S_ISREG(final_output_info.st_mode)
                or attempt_output_info.st_uid not in owners
                or final_output_info.st_uid not in owners
                or _is_group_or_world_writable(attempt_output_info)
                or _is_group_or_world_writable(final_output_info)
                or attempt_output_info.st_nlink != 2
                or final_output_info.st_nlink != 2
                or (attempt_path_info.st_dev, attempt_path_info.st_ino)
                != (attempt_output_info.st_dev, attempt_output_info.st_ino)
                or (final_path_info.st_dev, final_path_info.st_ino)
                != (final_output_info.st_dev, final_output_info.st_ino)
                or (attempt_output_info.st_dev, attempt_output_info.st_ino)
                != (final_output_info.st_dev, final_output_info.st_ino)
            ):
                raise DependencyFreezeError(
                    "Committed attempt output recovery custody is invalid."
                )
        if ".claim" in names:
            held_claim = _hold_repo_regular_file(
                repo, attempt_path / ".claim", owners, label="Build attempt claim"
            )
            if (
                stat.S_IMODE(held_claim.info.st_mode) != 0o400
                or held_claim.payload != _canonical_json(claim)
            ):
                raise DependencyFreezeError("Build attempt claim custody changed.")
            _rebind_build_attempt_file(held_claim)
        if ".receipt" in names:
            held_commit = _hold_repo_regular_file(
                repo,
                attempt_path / ".receipt",
                owners,
                label="Build attempt commit journal",
            )
            if (
                stat.S_IMODE(held_commit.info.st_mode) != 0o400
                or held_commit.payload != _canonical_json(commit)
            ):
                raise DependencyFreezeError(
                    "Build attempt commit journal custody changed."
                )
            _rebind_build_attempt_file(held_commit)
        _rebind_build_attempt_directory(held_attempt)
        if recovery_output_present:
            if final_artifact_fd is None:
                raise DependencyFreezeError(
                    "Committed attempt output recovery descriptor is unavailable."
                )
            final_before = os.fstat(final_artifact_fd)
            _strict_unlink_at(
                held_attempt.components[-1].descriptor,
                artifact_path.name,
                "committed post-crash attempt output hardlink",
            )
            final_after = os.fstat(final_artifact_fd)
            final_path_after = os.lstat(artifact_path)
            if (
                (final_after.st_dev, final_after.st_ino)
                != (final_before.st_dev, final_before.st_ino)
                or (final_path_after.st_dev, final_path_after.st_ino)
                != (final_after.st_dev, final_after.st_ino)
                or final_after.st_nlink != 1
                or final_after.st_size != final_before.st_size
                or final_after.st_mtime_ns != final_before.st_mtime_ns
            ):
                raise DependencyFreezeError(
                    "Committed post-crash artifact cleanup changed the final artifact."
                )
        if held_commit is not None:
            _close_held_regular_file(held_commit)
            held_commit = None
        if held_claim is not None:
            _close_held_regular_file(held_claim)
            held_claim = None
        _retire_completed_build_attempt(
            held_attempt,
            frozenset({BUILD_ATTEMPT_JOURNAL_NAME, ".claim", ".receipt"}),
        )
    finally:
        if held_journal is not None:
            _close_held_regular_file(held_journal)
        if held_journal_anchor is not None:
            _close_held_regular_file(held_journal_anchor)
        if held_journal_begin is not None:
            _close_held_regular_file(held_journal_begin)
        _close_quietly(final_artifact_fd)
        _close_quietly(attempt_output_fd)
        if held_commit is not None:
            _close_held_regular_file(held_commit)
        if held_claim is not None:
            _close_held_regular_file(held_claim)
        _release_build_attempt_lock(attempt_lock_descriptor)
        _close_held_directory(held_attempt)
        try:
            _rebind_consumed_artifacts_parent(held_artifacts)
        finally:
            _close_held_directory(held_artifacts)


@_retain_anchored_inputs_until_return
def verify_build_receipt(
    repo: pathlib.Path,
    index_path: pathlib.Path,
    platform: str,
    receipt_path: pathlib.Path,
    artifact_path: pathlib.Path | None = None,
    secret_inventory_path: str | None = None,
) -> dict[str, object]:
    repo = secure_repo_path(repo, pathlib.Path("."), "Repository root", must_exist=True)
    if platform not in PLATFORM_ROOTS:
        raise DependencyFreezeError(f"Unsupported platform: {platform}")
    _require_build_witness_boundary(repo, platform)
    index_path = secure_repo_path(
        repo, index_path, "Release input index", must_exist=True
    )
    receipt_path = secure_repo_path(repo, receipt_path, "Build receipt", must_exist=True)
    if receipt_path.relative_to(repo).parts[0] != ".artifacts":
        raise DependencyFreezeError("Build receipt must stay under .artifacts/.")
    record, receipt_sha = _read_anchored_json(repo, receipt_path, "Build receipt")
    receipt_identity = _file_identity(os.lstat(receipt_path))
    _require_exact_keys(
        record,
        {
            "schema_version",
            "contract",
            "release",
            "platform",
            "begun_utc",
            "finished_utc",
            "build_begin_receipt",
            "build_attempt",
            "release_input_index",
            "platform_manifest",
            "shared_revision",
            "producer",
            "toolchain",
            "source_freeze",
            "toolchain_custody",
            "artifact",
            "sha256_anchor",
            "publication_authorized",
        }
        | _remote_attestation_keys(record)
        | _windows_scan_keys(record),
        "Build receipt",
    )
    begun = _parse_timestamp(record.get("begun_utc"), "Build receipt begun")
    finished = _parse_timestamp(record.get("finished_utc"), "Build receipt finished")
    if finished < begun:
        raise DependencyFreezeError("Build receipt finish precedes build begin.")
    if finished > dt.datetime.now(tz=dt.timezone.utc) + dt.timedelta(minutes=5):
        raise DependencyFreezeError("Build receipt finish is dated in the future.")
    _require_fresh(begun, "Build receipt begun")
    _require_fresh(finished, "Build receipt finished")
    verified = verify_release_index(repo, index_path, platform)
    owners = _allowed_owners(repo)
    index, _index_digest = _read_json_file(
        index_path, owners, "Release input index", repo=repo
    )
    if type(index.get("platform_manifests")) is not dict:
        raise DependencyFreezeError("Release input index platform set is incomplete.")
    reference = _require_exact_keys(
        index.get("platform_manifests").get(platform),
        {"path", "sha256", "artifact_input_fingerprint_sha256"},
        f"{platform} platform manifest",
    )
    recorded_index_reference, recorded_expected_manifest = (
        _validate_receipt_index_carry_forward(
            repo,
            index,
            verified,
            platform,
            record.get("release_input_index"),
        )
    )
    begin_ref = _require_exact_keys(
        record.get("build_begin_receipt"), {"path", "sha256"}, "Build begin reference"
    )
    begin_path = secure_repo_path(
        repo,
        pathlib.Path(_require_str(begin_ref.get("path"), "Build begin path")),
        "Build begin receipt",
        must_exist=True,
    )
    if begin_path.relative_to(repo).parts[0] != ".artifacts":
        raise DependencyFreezeError("Build begin receipt must stay under .artifacts/.")
    begin_record, begin_sha = _read_anchored_json(repo, begin_path, "Build begin receipt")
    _require_exact_keys(
        begin_record,
        {
            "schema_version", "contract", "release", "platform", "begun_utc",
            "build_attempt",
            "release_input_index", "platform_manifest", "shared_revision",
            "sha256_anchor", "publication_authorized",
        }
        | _remote_attestation_keys(begin_record),
        "Build begin receipt",
    )
    recorded_begun = _parse_timestamp(
        begin_record.get("begun_utc"), "Build begin receipt"
    )
    if (
        _require_int(begin_record.get("schema_version"), "Build begin schema version")
        != SCHEMA_VERSION
        or _require_str(begin_record.get("contract"), "Build begin contract")
        != BUILD_BEGIN_CONTRACT
        or _require_str(begin_record.get("release"), "Build begin release")
        != verified["release"]
        or _require_str(begin_record.get("platform"), "Build begin platform") != platform
        or begin_record.get("release_input_index") != recorded_index_reference
        or begin_record.get("platform_manifest") != recorded_expected_manifest
        or _require_str(begin_record.get("shared_revision"), "Build begin shared revision")
        != verified["shared_revision"]
        or _require_str(begin_record.get("sha256_anchor"), "Build begin anchor")
        != begin_path.name + ".sha256"
        or _require_bool(begin_record.get("publication_authorized"), "publication_authorized")
        is not False
    ):
        raise DependencyFreezeError("Build begin receipt binding changed.")
    producer_record = _require_exact_keys(
        record.get("producer"),
        {"path", "sha256", "host", "execution"},
        "Build producer",
    )
    producer_host = _require_str(producer_record.get("host"), "Producer host")
    remote_receipt = _verify_remote_attested_receipt(
        platform, record, begin_record, begin_sha
    )
    if platform == "windows" and not remote_receipt:
        _require_release_host_secret_scan_binding(
            record.get("release_host_secret_scan"),
            platform,
            record.get("toolchain"),
            record.get("artifact") if type(record.get("artifact")) is dict else {},
        )
    elif "release_host_secret_scan" in record:
        raise DependencyFreezeError(
            "Only a Windows receipt that is not remote-attested carries a top-level "
            "secret scan binding."
        )
    expected_producer = (
        _remote_attested_build_producer(platform, producer_host)
        if remote_receipt
        else _platform_build_producer(platform, producer_host)
    )
    if _require_str(
        producer_record.get("execution"), "Producer execution"
    ) != (
        PRODUCER_EXECUTION_REMOTE_ATTESTED
        if remote_receipt
        else _platform_build_execution(platform, producer_host)
    ):
        raise DependencyFreezeError(
            f"{platform} build receipt producer execution is not accepted on "
            f"{producer_host}."
        )
    producer = secure_repo_path(
        repo, pathlib.Path(expected_producer), "Build producer", must_exist=True
    )
    producer_payload, _producer_identity, _producer_info = _stable_read_regular_file(
        producer, owners, label="Build producer", repo=repo
    )
    producer_digest = hashlib.sha256(producer_payload).hexdigest()
    toolchain = _require_exact_keys(
        record.get("toolchain"), {"name", "version", "revision", "target"}, "Build toolchain"
    )
    for key in ("name", "version", "revision", "target"):
        _safe_toolchain_value(
            _require_str(
                toolchain.get(key, ""),
                f"Toolchain {key}",
                allow_empty=key == "revision",
            ),
            f"Toolchain {key}",
            allow_empty=key == "revision",
        )
    _assert_toolchain_matches_reviewed_pin(
        repo,
        _require_str(toolchain.get("name"), "Toolchain name"),
        _require_str(toolchain.get("version"), "Toolchain version"),
        _require_str(toolchain.get("revision"), "Toolchain revision", allow_empty=True),
    )
    _assert_allowed_target(
        platform, _require_str(toolchain.get("target"), "Toolchain target")
    )
    custody = _load_current_authenticated_custody(repo)
    source_freeze = custody.source_freeze
    toolchain_custody = custody.toolchain_custody
    recorded_source_freeze = _require_exact_keys(
        record.get("source_freeze"), CUSTODY_BINDING_KEYS, "Build source-freeze"
    )
    recorded_toolchain_custody = _require_exact_keys(
        record.get("toolchain_custody"), CUSTODY_BINDING_KEYS, "Build toolchain-custody"
    )
    if recorded_source_freeze != source_freeze:
        raise DependencyFreezeError(
            "source-freeze receipt identity is not bound to the build transaction."
        )
    if recorded_toolchain_custody != toolchain_custody:
        raise DependencyFreezeError(
            "toolchain-custody receipt identity is not bound to the build transaction."
        )
    artifact = _require_exact_keys(
        record.get("artifact"),
        {"name", "size_bytes", "sha256", "modified_time_ns"},
        "Build artifact",
    )
    artifact_name = _require_str(artifact.get("name"), "Artifact name")
    size_bytes = _require_int(artifact.get("size_bytes"), "Artifact size")
    modified_ns = _require_int(artifact.get("modified_time_ns"), "Artifact mtime")
    artifact_digest = _require_sha256(artifact.get("sha256"), "Artifact digest")
    artifact_modified = dt.datetime.min.replace(tzinfo=dt.timezone.utc)
    try:
        artifact_modified = dt.datetime.fromtimestamp(
            modified_ns / 1_000_000_000, tz=dt.timezone.utc
        )
    except (OSError, OverflowError, ValueError):
        artifact_modified = dt.datetime.min.replace(tzinfo=dt.timezone.utc)
    if (
        _require_int(record.get("schema_version"), "Build receipt schema version")
        != SCHEMA_VERSION
        or _require_str(record.get("contract"), "Build receipt contract")
        != BUILD_RECEIPT_CONTRACT
        or _require_str(record.get("release"), "Build receipt release") != verified["release"]
        or _require_str(record.get("platform"), "Build receipt platform") != platform
        or begun != recorded_begun
        or _require_sha256(begin_ref.get("sha256"), "Build begin digest") != begin_sha
        or record.get("release_input_index") != recorded_index_reference
        or record.get("platform_manifest") != recorded_expected_manifest
        or _require_str(record.get("shared_revision"), "Build receipt shared revision")
        != verified["shared_revision"]
        or _require_str(producer_record.get("path"), "Producer path") != expected_producer
        or _require_sha256(producer_record.get("sha256"), "Producer digest") != producer_digest
        or recorded_source_freeze != source_freeze
        or recorded_toolchain_custody != toolchain_custody
        or pathlib.Path(artifact_name).name != artifact_name
        or size_bytes <= 0
        or artifact_modified <= begun
        or artifact_modified > finished + dt.timedelta(minutes=5)
        or _require_str(record.get("sha256_anchor"), "Build receipt anchor")
        != receipt_path.name + ".sha256"
        or _require_bool(record.get("publication_authorized"), "publication_authorized")
        is not False
    ):
        raise DependencyFreezeError("Build receipt binding is invalid or changed.")
    if artifact_path is None:
        raise DependencyFreezeError(
            "Exact built artifact bytes are required for receipt verification."
        )
    artifact_path = secure_repo_path(
        repo, artifact_path, "Built artifact", must_exist=True
    )
    _verify_consumed_build_attempt(
        repo,
        begin_record.get("build_attempt"),
        record.get("build_attempt"),
        begin_sha,
        record,
        receipt_path,
        artifact_path,
        begun,
        finished,
    )
    payload, artifact_identity, info = _stable_read_regular_file(
        artifact_path, owners, label="Built artifact", repo=repo
    )
    snapshot_digest = hashlib.sha256(payload).hexdigest()
    if (
        artifact_path.name != artifact_name
        or len(payload) != size_bytes
        or info.st_size != size_bytes
        or info.st_mtime_ns != modified_ns
        or snapshot_digest != artifact_digest
    ):
        raise DependencyFreezeError("Exact built artifact does not match its receipt.")
    _validate_release_artifact_bytes(
        platform,
        _require_str(toolchain.get("target"), "Toolchain target"),
        artifact_path.name,
        payload,
    )
    # A Windows receipt carries the scan its build was finished with, and every field
    # of that scan, the claim, the commit record and the anchor can be rewritten to
    # agree with each other once the attempt directory is gone. Agreement inside the
    # receipt therefore proves nothing about these bytes, and neither does any field
    # the receipt declares about how it was made: a receipt rewritten to look
    # witnessed, with its remote bindings removed, must not skip the scan. So the
    # decision is made here, from the platform this call was asked to verify and the
    # installer it holds. Every Windows installer is scanned again, under the same
    # pinned closure, with the owner's inventory named by path, and is accepted only
    # when that scan passes and equals what the receipt binds. No other platform
    # takes an inventory or runs a scan.
    scan_required = _release_host_secret_scan_required(platform, artifact_path.name, payload)
    if scan_required and secret_inventory_path is None:
        raise DependencyFreezeError(
            "A Windows receipt is verified by running the exact secret scan on the "
            "installer, so verification requires the authenticated secret inventory "
            "path."
        )
    if not scan_required and secret_inventory_path is not None:
        raise DependencyFreezeError(
            "Only a Windows receipt is verified with a secret inventory path."
        )
    held_artifact = _hold_repo_regular_file(
        repo, artifact_path, owners, label="Built artifact"
    )
    if held_artifact.payload != payload or held_artifact.identity != artifact_identity:
        _close_held_regular_file(held_artifact)
        raise DependencyFreezeError("Exact built artifact changed before final capture.")
    try:
        if scan_required:
            fresh_scan = _run_release_host_secret_scan(
                repo,
                artifact_path,
                {
                    "name": artifact_path.name,
                    "size_bytes": len(payload),
                    "sha256": snapshot_digest,
                },
                toolchain,
                secret_inventory_path,
                owners,
            )
            remote_binding = record.get("remote_attestation")
            bound_scan = (
                remote_binding.get("release_host_secret_scan")
                if type(remote_binding) is dict
                else record.get("release_host_secret_scan")
            )
            _require_release_host_secret_scan_rerun(fresh_scan, bound_scan)
        hook = _POST_FINAL_CAPTURE_HOOK
        if callable(hook):
            hook()
        _rebind_held_regular_file(held_artifact)
        _rebind_authenticated_custody(repo, custody)
        _rebind_path_by_name(
            receipt_path,
            receipt_identity,
            kind="Build receipt",
            directory=False,
        )
        _rebind_held_regular_file(held_artifact)
        _retain_regular_file_until_return(held_artifact)
        held_artifact = None
    finally:
        if held_artifact is not None:
            _close_held_regular_file(held_artifact)
    return {
        "ok": True,
        "fixture_only": isolated_fixture_mode_active(),
        "production_pass_allowed": bool(
            _PRODUCTION_REQUIRED and _AUTHORITATIVE_WORKER_READY
        ),
        "kind": "build-receipt",
        "release": verified["release"],
        "platform": platform,
        "receipt_sha256": receipt_sha,
        "shared_revision": verified["shared_revision"],
        "platform_manifest_sha256": reference["sha256"],
        "artifact_input_fingerprint_sha256": reference[
            "artifact_input_fingerprint_sha256"
        ],
        "artifact_sha256": snapshot_digest,
        "artifact_size_bytes": len(payload),
        "begun_utc": record["begun_utc"],
        "finished_utc": record["finished_utc"],
    }


def _production_seams_are_pristine() -> bool:
    return bool(
        _FIXTURE_MODE is False
        and _PRODUCTION_REQUIRED is False
        and _AUTHORITATIVE_WORKER_READY is False
        and _AUTHORITATIVE_CONTROLLER_PATH is None
        and _POST_SELECT_HOOK is None
        and _POST_INPUT_CAPTURE_HOOK is None
        and _POST_DIRECTORY_BIND_HOOK is None
        and _POST_FINAL_CAPTURE_HOOK is None
        and _SOURCE_FREEZE_MODULE is None
        and _SOURCE_FREEZE_TRUST_PATH is None
        and _SOURCE_FREEZE_SELF_AUTHORED_OVERRIDE is None
        and _ACTIVE_ANCHORED_CUSTODY.get() is None
        and _ACTIVE_RETURN_FILE_CUSTODY.get() is None
    )


def _absolute_repo_argument(value: str) -> pathlib.Path:
    if type(value) is not str or not value or "\0" in value or "\n" in value:
        raise DependencyFreezeError("Repository argument is unsafe.")
    return pathlib.Path(os.path.abspath(value))


def _worker_environment() -> dict[str, str]:
    return {
        "HOME": "/private/tmp",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "TMPDIR": "/private/tmp",
    }


def _read_worker_source_descriptor(descriptor: int) -> tuple[bytes, os.stat_result]:
    try:
        before = os.fstat(descriptor)
    except OSError as exc:
        raise DependencyFreezeError(
            "Authoritative worker source descriptor is unavailable."
        ) from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 1
        or before.st_size > _MAX_RELEASE_CONTROLLER_BYTES
        or _is_group_or_world_writable(before)
    ):
        raise DependencyFreezeError(
            "Authoritative worker source descriptor is not one reviewed regular file."
        )
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                raise DependencyFreezeError(
                    "Authoritative worker source ended before its declared size."
                )
            chunks.append(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise DependencyFreezeError(
                "Authoritative worker source grew while it was read."
            )
        after = os.fstat(descriptor)
    except OSError as exc:
        raise DependencyFreezeError(
            "Authoritative worker source descriptor could not be read."
        ) from exc
    if _file_identity(before) != _file_identity(after):
        raise DependencyFreezeError(
            "Authoritative worker source changed while it was read."
        )
    return b"".join(chunks), after


def _darwin_kernel_process_identity() -> tuple[str, tuple[str, ...]]:
    """Return the kernel-recorded process image and argv on Darwin.

    ``sys.argv`` and ``_NSGetArgv`` are writable process memory. They therefore
    cannot distinguish a directly launched worker from reviewed source rebuilt
    inside a hostile ``python -c`` process. KERN_PROCARGS2 and proc_pidpath read
    the kernel's launch record instead.
    """

    if not _bootstrap_import_methods_pristine():
        raise DependencyFreezeError(
            "Authoritative worker bootstrap importer methods were replaced."
        )
    try:
        import ctypes as authenticated_ctypes

        libc = authenticated_ctypes.CDLL(None, use_errno=True)
        sysctl = libc.sysctl
        sysctl.argtypes = (
            authenticated_ctypes.POINTER(authenticated_ctypes.c_int),
            authenticated_ctypes.c_uint,
            authenticated_ctypes.c_void_p,
            authenticated_ctypes.POINTER(authenticated_ctypes.c_size_t),
            authenticated_ctypes.c_void_p,
            authenticated_ctypes.c_size_t,
        )
        sysctl.restype = authenticated_ctypes.c_int
        mib = (authenticated_ctypes.c_int * 3)(1, 49, os.getpid())
        required = authenticated_ctypes.c_size_t(0)
        authenticated_ctypes.set_errno(0)
        if sysctl(mib, 3, None, authenticated_ctypes.byref(required), None, 0) != 0:
            raise OSError(authenticated_ctypes.get_errno(), "KERN_PROCARGS2 size query failed")
        if required.value < 8 or required.value > 16 * 1024 * 1024:
            raise ValueError("kernel process argument record is outside its bound")
        buffer = authenticated_ctypes.create_string_buffer(required.value)
        authenticated_ctypes.set_errno(0)
        if sysctl(
            mib, 3, buffer, authenticated_ctypes.byref(required), None, 0
        ) != 0:
            raise OSError(authenticated_ctypes.get_errno(), "KERN_PROCARGS2 query failed")
        payload = bytes(buffer.raw[: required.value])
        argc = int.from_bytes(payload[:4], sys.byteorder, signed=True)
        if argc < 1 or argc > 4096:
            raise ValueError("argument count is outside its bound")
        executable_end = payload.find(b"\0", 4)
        if executable_end <= 4 or executable_end - 4 > 1024 * 1024:
            raise ValueError("kernel executable path is missing or outside its bound")
        executable = payload[4:executable_end].decode("utf-8", errors="strict")
        cursor = executable_end
        while cursor < len(payload) and payload[cursor] == 0:
            cursor += 1
        values: list[str] = []
        for _index in range(argc):
            end = payload.find(b"\0", cursor)
            if end < cursor or end - cursor > 1024 * 1024:
                raise ValueError("argument is missing or outside its bound")
            values.append(payload[cursor:end].decode("utf-8", errors="strict"))
            cursor = end + 1

        libproc = authenticated_ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        proc_pidpath = libproc.proc_pidpath
        proc_pidpath.argtypes = (
            authenticated_ctypes.c_int,
            authenticated_ctypes.c_void_p,
            authenticated_ctypes.c_uint32,
        )
        proc_pidpath.restype = authenticated_ctypes.c_int
        path_buffer = authenticated_ctypes.create_string_buffer(4096)
        authenticated_ctypes.set_errno(0)
        path_size = proc_pidpath(os.getpid(), path_buffer, len(path_buffer))
        if path_size <= 0 or path_size >= len(path_buffer):
            raise OSError(authenticated_ctypes.get_errno(), "proc_pidpath failed")
        process_path = bytes(path_buffer.raw[:path_size]).decode(
            "utf-8", errors="strict"
        )
        if process_path != executable:
            raise ValueError("kernel process image records disagree")
        return process_path, tuple(values)
    except (
        AttributeError,
        IndexError,
        OSError,
        UnicodeDecodeError,
        ValueError,
    ) as exc:
        raise DependencyFreezeError(
            "Authoritative worker kernel process identity is unavailable."
        ) from exc


def _late_authenticated_ctypes() -> types.ModuleType:
    """Import ctypes only after the pristine worker boundary is defined."""

    import ctypes as authenticated_ctypes

    return authenticated_ctypes


def _require_runtime_import_path(
    runtime_prefix: pathlib.Path, entries: list[str]
) -> None:
    """Allow only the interpreter's own standard library on the import path.

    -I drops the script directory and PYTHONPATH and -S drops site-packages, so
    every remaining entry must normalize to a path under ``<prefix>/lib``.
    """

    expected = runtime_prefix / "lib"
    if not entries:
        raise DependencyFreezeError(
            "Authoritative release dependency worker import path escaped its runtime."
        )
    for entry in entries:
        if (
            type(entry) is not str
            or not entry.startswith("/")
            or os.path.normpath(entry) != entry
        ):
            raise DependencyFreezeError(
                "Authoritative release dependency worker import path escaped its runtime."
            )
        try:
            pathlib.Path(entry).relative_to(expected)
        except ValueError as exc:
            raise DependencyFreezeError(
                "Authoritative release dependency worker import path escaped its runtime."
            ) from exc


def _require_pristine_worker_process(descriptor: int) -> tuple[bytes, pathlib.Path]:
    """Authenticate the pristine worker process and return its source and image.

    The returned kernel process image is bound to the pinned release Python
    path and bytes by ``_authenticate_authoritative_worker`` before any
    production authority is granted.
    """

    if not _BOOTSTRAP_IMPORT_GRAPH_PRISTINE:
        raise DependencyFreezeError(
            "Authoritative worker bootstrap import graph was replaced."
        )
    if not _BOOTSTRAP_BUILTINS_PRISTINE:
        raise DependencyFreezeError(
            "Authoritative worker bootstrap builtins were replaced."
        )
    if not _BOOTSTRAP_IMPORT_METHODS_PRISTINE or not _bootstrap_import_methods_pristine():
        raise DependencyFreezeError(
            "Authoritative worker bootstrap importer methods were replaced."
        )
    if not (
        _BOOTSTRAP_POSIX_WRITE_PRISTINE
        and os.write is _BOOTSTRAP_POSIX_WRITE
        and "runpy" not in _WORKER_BOOTSTRAP_MODULES
        and "sitecustomize" not in _WORKER_BOOTSTRAP_MODULES
        and "usercustomize" not in _WORKER_BOOTSTRAP_MODULES
    ):
        raise DependencyFreezeError(
            "Authoritative worker bootstrap OS or startup seams were replaced."
        )
    expected_argv0 = f"/dev/fd/{descriptor}"
    kernel_process_path, kernel_process_argv = _darwin_kernel_process_identity()
    process_binary = pathlib.Path(kernel_process_path)
    expected_process_argv = (
        kernel_process_path,
        "-I",
        "-S",
        expected_argv0,
        *tuple(sys.argv[1:]),
    )
    if (
        not process_binary.is_absolute()
        or os.path.normpath(kernel_process_path) != kernel_process_path
        or kernel_process_argv != expected_process_argv
    ):
        raise DependencyFreezeError(
            "Authoritative worker kernel process identity changed."
        )
    runtime_prefix = process_binary.parent.parent
    if (
        sys.platform != "darwin"
        or _WORKER_BOOTSTRAP_MODULES
        != _PRISTINE_RELEASE_PYTHON_BOOTSTRAP_MODULES
        or tuple(sys.version_info[:3]) != _RELEASE_PYTHON_VERSION
        or sys.implementation.name != "cpython"
        or sys.flags.isolated != 1
        or sys.flags.no_site != 1
        or not sys.flags.safe_path
        or pathlib.Path(sys.executable) != process_binary
        or pathlib.Path(sys._base_executable) != process_binary
        or pathlib.Path(sys.prefix) != runtime_prefix
        or pathlib.Path(sys.base_prefix) != runtime_prefix
        or sys.argv[0] != expected_argv0
        or _EXECUTING_MODULE_CODE.co_filename != expected_argv0
        or threading.active_count() != 1
        or sys.gettrace() is not None
        or sys.getprofile() is not None
    ):
        raise DependencyFreezeError(
            "Authoritative release dependency worker is not pristine."
        )
    allowed_environment = set(_worker_environment()) | {
        "LC_CTYPE",
        "__CF_USER_TEXT_ENCODING",
    }
    if any(key not in allowed_environment for key in os.environ):
        raise DependencyFreezeError(
            "Authoritative release dependency worker environment is not scrubbed."
        )
    for key, expected in _worker_environment().items():
        if key in {"LANG", "LC_ALL"}:
            # macOS may consume these while establishing LC_CTYPE.
            continue
        if os.environ.get(key) != expected:
            raise DependencyFreezeError(
                "Authoritative release dependency worker environment is not scrubbed."
            )
    _require_runtime_import_path(runtime_prefix, sys.path)
    payload, _info = _read_worker_source_descriptor(descriptor)
    try:
        reviewed_code = compile(
            payload,
            _EXECUTING_MODULE_CODE.co_filename,
            "exec",
            dont_inherit=True,
            optimize=sys.flags.optimize,
        )
    except (SyntaxError, ValueError, TypeError) as exc:
        raise DependencyFreezeError(
            "Authoritative worker source is not valid reviewed Python."
        ) from exc
    if reviewed_code != _EXECUTING_MODULE_CODE:
        raise DependencyFreezeError(
            "Authoritative worker code differs from its retained source descriptor."
        )
    return payload, process_binary


def _authoritative_json_string(value: str) -> bytes:
    encoded = bytearray(b'"')
    for character in value:
        if character == '"':
            encoded.extend(b'\\"')
        elif character == "\\":
            encoded.extend(b"\\\\")
        elif character == "\b":
            encoded.extend(b"\\b")
        elif character == "\f":
            encoded.extend(b"\\f")
        elif character == "\n":
            encoded.extend(b"\\n")
        elif character == "\r":
            encoded.extend(b"\\r")
        elif character == "\t":
            encoded.extend(b"\\t")
        elif character < " ":
            codepoint = int.from_bytes(character.encode("utf-32-be"), "big")
            encoded.extend(f"\\u{codepoint:04x}".encode("ascii"))
        else:
            encoded.extend(character.encode("utf-8"))
    encoded.extend(b'"')
    return bytes(encoded)


def _authoritative_json_value(value: object, *, depth: int = 0) -> bytes:
    if depth > 64:
        raise DependencyFreezeError("Authoritative worker result is too deeply nested.")
    value_type = value.__class__
    if value is None:
        return b"null"
    if value_type is True.__class__:
        return b"true" if value else b"false"
    if value_type is (0).__class__:
        return f"{value:d}".encode("ascii")
    if value_type is "".__class__:
        return _authoritative_json_string(value)
    if value_type is [].__class__ or value_type is ().__class__:
        return b"[" + b",".join(
            _authoritative_json_value(item, depth=depth + 1) for item in value
        ) + b"]"
    if value_type is {}.__class__:
        if any(key.__class__ is not "".__class__ for key in value):
            raise DependencyFreezeError(
                "Authoritative worker result contains a non-string object key."
            )
        fields = []
        for key in sorted(value):
            fields.append(
                _authoritative_json_string(key)
                + b":"
                + _authoritative_json_value(value[key], depth=depth + 1)
            )
        return b"{" + b",".join(fields) + b"}"
    raise DependencyFreezeError(
        "Authoritative worker result contains an unsupported JSON value."
    )


def _authoritative_output_payload(
    result: dict[str, object], command: str
) -> bytes:
    reserved = {
        "authority_kind",
        "command",
        "production_authority_authenticated",
        "production_build_witness",
        "publication_authorized",
    }
    clean = {key: value for key, value in result.items() if key not in reserved}
    build_witness = (
        "PENDING_NATIVE_PRODUCER"
        if command == "begin-build"
        else "NATIVE_WITNESSED"
        if command in {"finish-build", "verify-receipt"}
        else "NOT_APPLICABLE"
    )
    clean.update(
        {
            "authority_kind": "winsvpn-release-dependency-freeze-authoritative-v1",
            "command": command,
            "production_authority_authenticated": True,
            "production_build_witness": build_witness,
            "publication_authorized": False,
        }
    )
    payload = _authoritative_json_value(clean) + b"\n"
    if len(payload) > MAX_DEPENDENCY_JSON_BYTES:
        raise DependencyFreezeError("Authoritative worker result is too large.")
    required = (
        b'"authority_kind":"winsvpn-release-dependency-freeze-authoritative-v1"',
        b'"production_authority_authenticated":true',
        f'"production_build_witness":"{build_witness}"'.encode("ascii"),
        b'"publication_authorized":false',
    )
    if any(field not in payload for field in required):
        raise DependencyFreezeError(
            "Authoritative worker result lost its fail-closed authority fields."
        )
    return payload


def _pinned_release_python(pins_payload: bytes) -> tuple[pathlib.Path, str]:
    """Return the reviewed release Python path and SHA-256 pinned for this host."""

    record = _load_json_object(pins_payload, "Release toolchain pins")
    tools = record.get("tools")
    python = tools.get("python") if type(tools) is dict else None
    if type(python) is not dict:
        raise DependencyFreezeError(
            "tools/toolchain-pins.json does not pin a release Python."
        )
    if (
        python.get("version") != ".".join(str(part) for part in _RELEASE_PYTHON_VERSION)
        or python.get("implementation") != "cpython"
    ):
        raise DependencyFreezeError(
            "tools/toolchain-pins.json release Python version pin drifted."
        )
    host_key = _RELEASE_PYTHON_HOST_KEYS.get(os.uname().machine)
    paths = python.get("reviewed_executable_path")
    digests = python.get("executable_sha256")
    if (
        host_key is None
        or type(paths) is not dict
        or type(digests) is not dict
        or host_key not in paths
        or host_key not in digests
    ):
        raise DependencyFreezeError(
            "tools/toolchain-pins.json does not pin a release Python for this host."
        )
    path = paths[host_key]
    digest = digests[host_key]
    if (
        type(path) is not str
        or not path.startswith("/")
        or "\0" in path
        or "\n" in path
        or "\r" in path
        or os.path.normpath(path) != path
    ):
        raise DependencyFreezeError(
            "tools/toolchain-pins.json release Python path pin is malformed."
        )
    if type(digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise DependencyFreezeError(
            "tools/toolchain-pins.json release Python SHA-256 pin is malformed."
        )
    return pathlib.Path(path), digest


def _authenticate_authoritative_worker(
    repo: pathlib.Path,
    descriptor: int,
) -> _AuthoritativeWorkerCustody:
    global _AUTHORITATIVE_CONTROLLER_PATH, _AUTHORITATIVE_WORKER_READY
    if not _production_seams_are_pristine():
        raise DependencyFreezeError(
            "Production release dependency worker contains fixture or hook state."
        )
    descriptor_payload, process_binary = _require_pristine_worker_process(descriptor)
    owners = _allowed_owners(repo)
    controller_path = repo / "tools/release_dependency_freeze.py"
    controller = _hold_repo_regular_file(
        repo, controller_path, owners, label="Release dependency controller"
    )
    pins: _HeldRegularFile | None = None
    executable: _HeldRegularFile | None = None
    try:
        source_info = os.fstat(descriptor)
        if (
            descriptor_payload != controller.payload
            or (source_info.st_dev, source_info.st_ino)
            != (controller.info.st_dev, controller.info.st_ino)
        ):
            raise DependencyFreezeError(
                "Authoritative worker source is not the retained repository controller."
            )
        pins = _hold_repo_regular_file(
            repo,
            repo / _RELEASE_PYTHON_PIN_MANIFEST,
            owners,
            label="Release toolchain pins",
        )
        pinned_path, pinned_sha256 = _pinned_release_python(pins.payload)
        if process_binary != pinned_path:
            raise DependencyFreezeError(PINNED_RELEASE_PYTHON_REQUIRED)
        # Hold the pinned interpreter from / without following any link and
        # hash the exact bytes the kernel is executing for this worker.
        executable = _hold_repo_regular_file(
            pathlib.Path("/"),
            pinned_path,
            owners | frozenset({0}),
            label="Pinned release Python executable",
        )
        if (
            not (executable.info.st_mode & stat.S_IXUSR)
            or hashlib.sha256(executable.payload).hexdigest() != pinned_sha256
        ):
            raise DependencyFreezeError(
                f"{PINNED_RELEASE_PYTHON_REQUIRED}: executable bytes do not "
                "match the pinned SHA-256"
            )
        tree = _bind_production_git_tree(repo)
        if tree is None:
            raise DependencyFreezeError(GIT_REQUIRED)
        relative = "tools/release_dependency_freeze.py"
        _require_production_git_inputs(
            tree,
            (relative, _RELEASE_PYTHON_PIN_MANIFEST),
            {
                relative: controller.payload,
                _RELEASE_PYTHON_PIN_MANIFEST: pins.payload,
            },
            (),
            (relative, _RELEASE_PYTHON_PIN_MANIFEST),
            (
                (relative, controller.identity),
                (_RELEASE_PYTHON_PIN_MANIFEST, pins.identity),
            ),
        )
        _AUTHORITATIVE_CONTROLLER_PATH = controller_path
        _AUTHORITATIVE_WORKER_READY = True
        _require_executing_controller(repo, controller.payload)
        custody = _AuthoritativeWorkerCustody(
            controller=controller,
            pins=pins,
            executable=executable,
            executable_path=pinned_path,
        )
        _revalidate_authoritative_worker(custody)
        return custody
    except Exception:
        _AUTHORITATIVE_WORKER_READY = False
        _AUTHORITATIVE_CONTROLLER_PATH = None
        if executable is not None:
            _close_held_regular_file(executable)
        if pins is not None:
            _close_held_regular_file(pins)
        _close_held_regular_file(controller)
        raise


def _revalidate_authoritative_worker(custody: _AuthoritativeWorkerCustody) -> None:
    if not (
        _bootstrap_import_methods_pristine()
        and _BOOTSTRAP_POSIX_WRITE_PRISTINE
        and os.write is _BOOTSTRAP_POSIX_WRITE
    ):
        raise DependencyFreezeError(
            "Authoritative worker import or output seams changed."
        )
    _rebind_held_regular_file(custody.controller)
    _rebind_held_regular_file(custody.pins)
    _rebind_held_regular_file(custody.executable)


def _close_authoritative_worker(custody: _AuthoritativeWorkerCustody) -> None:
    global _AUTHORITATIVE_CONTROLLER_PATH, _AUTHORITATIVE_WORKER_READY
    _AUTHORITATIVE_WORKER_READY = False
    _AUTHORITATIVE_CONTROLLER_PATH = None
    _close_held_regular_file(custody.executable)
    _close_held_regular_file(custody.pins)
    _close_held_regular_file(custody.controller)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create or verify dependency-scoped release input manifests."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    shared = subparsers.add_parser("freeze-shared")
    shared.add_argument("--repo", default=".")
    shared.add_argument("--revision", required=True)
    shared.add_argument("--output", required=True)

    platform = subparsers.add_parser("snapshot-platform")
    platform.add_argument("--repo", default=".")
    platform.add_argument("--platform", choices=sorted(PLATFORM_ROOTS), required=True)
    platform.add_argument("--shared-manifest", required=True)
    platform.add_argument("--output", required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--repo", default=".")
    verify.add_argument("--manifest", required=True)

    create_index = subparsers.add_parser("create-index")
    create_index.add_argument("--repo", default=".")
    create_index.add_argument("--manifest-dir", required=True)
    create_index.add_argument("--output", required=True)
    create_index.add_argument(
        "--platforms",
        help=(
            "Comma-separated proper subset of platforms for a scoped, "
            "never-complete index. Omit to create the complete index."
        ),
    )

    verify_index = subparsers.add_parser("verify-index")
    verify_index.add_argument("--repo", default=".")
    verify_index.add_argument("--index", required=True)
    verify_index.add_argument("--platform", choices=sorted(PLATFORM_ROOTS))

    begin_build = subparsers.add_parser("begin-build")
    begin_build.add_argument("--repo", default=".")
    begin_build.add_argument("--index", required=True)
    begin_build.add_argument("--platform", choices=sorted(PLATFORM_ROOTS), required=True)
    begin_build.add_argument("--output", required=True)
    begin_build.add_argument("--remote-host", choices=("linux", "windows"))
    begin_build.add_argument("--source-archive")

    finish_build = subparsers.add_parser("finish-build")
    finish_build.add_argument("--repo", default=".")
    finish_build.add_argument("--index", required=True)
    finish_build.add_argument("--platform", choices=sorted(PLATFORM_ROOTS), required=True)
    finish_build.add_argument("--begin", required=True)
    finish_build.add_argument("--artifact", required=True)
    finish_build.add_argument("--producer", required=True)
    finish_build.add_argument("--toolchain-name", required=True)
    finish_build.add_argument("--toolchain-version", required=True)
    finish_build.add_argument("--toolchain-revision", default="")
    finish_build.add_argument("--target", required=True)
    finish_build.add_argument("--output", required=True)
    finish_build.add_argument("--remote-host", choices=("linux", "windows"))
    finish_build.add_argument("--remote-run-record")
    finish_build.add_argument("--secret-inventory-path")

    verify_receipt = subparsers.add_parser("verify-receipt")
    verify_receipt.add_argument("--repo", default=".")
    verify_receipt.add_argument("--index", required=True)
    verify_receipt.add_argument("--platform", choices=sorted(PLATFORM_ROOTS), required=True)
    verify_receipt.add_argument("--receipt", required=True)
    verify_receipt.add_argument("--artifact", required=True)
    verify_receipt.add_argument("--secret-inventory-path")
    return parser


def _dispatch_command(args: argparse.Namespace) -> dict[str, object]:
    if args.command == "freeze-shared":
        return create_shared_manifest(
            pathlib.Path(args.repo), pathlib.Path(args.output), args.revision
        )
    if args.command == "snapshot-platform":
        return create_platform_manifest(
            pathlib.Path(args.repo),
            args.platform,
            pathlib.Path(args.shared_manifest),
            pathlib.Path(args.output),
        )
    if args.command == "create-index":
        return create_release_index(
            pathlib.Path(args.repo),
            pathlib.Path(args.manifest_dir),
            pathlib.Path(args.output),
            None if args.platforms is None else tuple(args.platforms.split(",")),
        )
    if args.command == "verify-index":
        return verify_release_index(
            pathlib.Path(args.repo), pathlib.Path(args.index), args.platform
        )
    if args.command == "begin-build":
        remote_attestation = None
        if args.remote_host is not None or args.source_archive is not None:
            if args.remote_host is None or args.source_archive is None:
                raise DependencyFreezeError(
                    "A remote begin-build needs --remote-host and --source-archive."
                )
            remote_attestation = prepare_remote_attested_begin(
                pathlib.Path(args.repo),
                pathlib.Path(args.index),
                args.platform,
                args.remote_host,
                pathlib.Path(args.source_archive),
            )
        return begin_build_receipt(
            pathlib.Path(args.repo),
            pathlib.Path(args.index),
            args.platform,
            pathlib.Path(args.output),
            remote_attestation,
        )
    if args.command == "finish-build":
        return finish_build_receipt(
            pathlib.Path(args.repo),
            pathlib.Path(args.index),
            args.platform,
            pathlib.Path(args.begin),
            pathlib.Path(args.artifact),
            args.producer,
            args.toolchain_name,
            args.toolchain_version,
            args.toolchain_revision,
            args.target,
            pathlib.Path(args.output),
            args.remote_host,
            None if args.remote_run_record is None else pathlib.Path(args.remote_run_record),
            args.secret_inventory_path,
        )
    if args.command == "verify-receipt":
        return verify_build_receipt(
            pathlib.Path(args.repo),
            pathlib.Path(args.index),
            args.platform,
            pathlib.Path(args.receipt),
            pathlib.Path(args.artifact),
            args.secret_inventory_path,
        )
    return verify_manifest(pathlib.Path(args.repo), pathlib.Path(args.manifest))


def _raw_repo_argument(argv: list[str]) -> pathlib.Path:
    values: list[str] = []
    index = 0
    while index < len(argv):
        value = argv[index]
        if value == "--repo":
            if index + 1 >= len(argv):
                raise DependencyFreezeError("--repo requires one value.")
            values.append(argv[index + 1])
            index += 2
            continue
        if value.startswith("--repo="):
            values.append(value.partition("=")[2])
        index += 1
    if len(values) > 1:
        raise DependencyFreezeError("--repo may be supplied only once.")
    return _absolute_repo_argument(values[0] if values else ".")


def _run_authoritative_worker(argv: list[str], descriptor: int) -> int:
    global _PRODUCTION_REQUIRED
    repo = _raw_repo_argument(argv)
    custody: _AuthoritativeWorkerCustody | None = None
    previous_production = _PRODUCTION_REQUIRED
    anchored: list[_HeldAnchoredPayloads] = []
    files: list[_HeldRegularFile] = []
    directories: list[_HeldDirectory] = []
    anchored_token: contextvars.Token[list[_HeldAnchoredPayloads] | None] | None = None
    file_token: contextvars.Token[list[_HeldRegularFile] | None] | None = None
    directory_token: contextvars.Token[list[_HeldDirectory] | None] | None = None
    pubspec_token: contextvars.Token[object | None] | None = None
    worker_token: contextvars.Token[_AuthoritativeWorkerCustody | None] | None = None
    try:
        custody = _authenticate_authoritative_worker(repo, descriptor)
        worker_token = _ACTIVE_AUTHORITATIVE_WORKER_CUSTODY.set(custody)
        _PRODUCTION_REQUIRED = True
        # argparse writes help and usage text itself; keep the authenticated
        # worker's only output the reviewed result or one failure line.
        saved_streams = (sys.stdout, sys.stderr)
        sys.stdout = sys.stderr = io.StringIO()
        try:
            args = _parser().parse_args(argv)
        except SystemExit as exc:
            raise DependencyFreezeError(
                "Authoritative worker arguments are invalid."
            ) from exc
        finally:
            sys.stdout, sys.stderr = saved_streams
        parsed_repo = _absolute_repo_argument(args.repo)
        if parsed_repo != repo:
            raise DependencyFreezeError(
                "Authoritative worker repository argument changed during parsing."
            )
        args.repo = str(repo)
        anchored_token = _ACTIVE_ANCHORED_CUSTODY.set(anchored)
        file_token = _ACTIVE_RETURN_FILE_CUSTODY.set(files)
        directory_token = _ACTIVE_RETURN_DIRECTORY_CUSTODY.set(directories)
        pubspec_token = _establish_operation_pubspec_custody(repo)
        result = _dispatch_command(args)
        if type(result) is not dict:
            raise DependencyFreezeError(
                "Authoritative worker result is not one strict object."
            )
        _rebind_retained_result_custody(files, anchored, directories)
        _revalidate_authoritative_worker(custody)
        payload = _authoritative_output_payload(result, args.command)
        _rebind_retained_result_custody(files, anchored, directories)
        _revalidate_authoritative_worker(custody)
        view = memoryview(payload)
        offset = 0
        while offset < len(view):
            written = _BOOTSTRAP_POSIX_WRITE(1, view[offset:])
            if written <= 0:
                raise DependencyFreezeError(
                    "Authoritative worker result could not be emitted completely."
                )
            offset += written
        _rebind_retained_result_custody(files, anchored, directories)
        _revalidate_authoritative_worker(custody)
    except DependencyFreezeError as exc:
        print(f"RELEASE DEPENDENCY FREEZE: FAIL: {exc}", file=sys.stderr)
        return 1
    finally:
        _close_retained_result_custody(files, anchored, directories)
        if worker_token is not None:
            _ACTIVE_AUTHORITATIVE_WORKER_CUSTODY.reset(worker_token)
        if pubspec_token is not None:
            _ACTIVE_PUBSPEC_CUSTODY.reset(pubspec_token)
        if directory_token is not None:
            _ACTIVE_RETURN_DIRECTORY_CUSTODY.reset(directory_token)
        if file_token is not None:
            _ACTIVE_RETURN_FILE_CUSTODY.reset(file_token)
        if anchored_token is not None:
            _ACTIVE_ANCHORED_CUSTODY.reset(anchored_token)
        _PRODUCTION_REQUIRED = previous_production
        if custody is not None:
            _close_authoritative_worker(custody)
    return 0


def main() -> int:
    """Refuse production authority from an imported controller namespace."""

    print(
        "RELEASE DEPENDENCY FREEZE: FAIL: imported library mode cannot "
        "start production authority",
        file=sys.stderr,
    )
    return 1


def _initial_script_entry(argv: list[str]) -> int:
    if isolated_fixture_mode_active():
        print(
            f"RELEASE DEPENDENCY FREEZE: FAIL: {FIXTURE_CANNOT_AUTHORIZE}",
            file=sys.stderr,
        )
        return 1
    try:
        if len(argv) >= 2 and argv[0] == _AUTHORITATIVE_WORKER_SWITCH:
            try:
                descriptor = int(argv[1], 10)
            except ValueError as exc:
                raise DependencyFreezeError(
                    "Authoritative worker descriptor is invalid."
                ) from exc
            if descriptor < 3:
                raise DependencyFreezeError(
                    "Authoritative worker descriptor is invalid."
                )
            return _run_authoritative_worker(argv[2:], descriptor)
        raise DependencyFreezeError(AUTHENTICATED_WORKER_LAUNCH_REQUIRED)
    except DependencyFreezeError as exc:
        print(f"RELEASE DEPENDENCY FREEZE: FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    # This dispatch executes only during the original reviewed-source script
    # evaluation. Imported callers can mutate module globals, including
    # ``__name__``, but cannot cause Python to re-enter this completed block.
    raise SystemExit(_initial_script_entry(list(sys.argv[1:])))
else:
    # Do not leave any alternate production dispatcher in an imported module.
    del _initial_script_entry
    del _run_authoritative_worker
