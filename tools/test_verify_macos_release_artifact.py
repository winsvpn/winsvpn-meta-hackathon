#!/usr/bin/env python3
"""Hostile tests for the final macOS release artifact verifier."""

from __future__ import annotations

import json
import copy
import hashlib
import importlib.util
import contextlib
import os
import pathlib
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import verify_macos_release_artifact as verifier


def _fat_macho(architectures=("arm64", "x86_64")):
    cpu_types = {"arm64": 0x0100000C, "x86_64": 0x01000007}
    header_size = 8 + 20 * len(architectures)
    slices = []
    entries = []
    offset = header_size
    for architecture in architectures:
        payload = struct.pack(">II", cpu_types[architecture], 0)
        entries.append(struct.pack(">IIIII", cpu_types[architecture], 0, offset, len(payload), 0))
        slices.append(payload)
        offset += len(payload)
    return struct.pack(">II", 0xCAFEBABE, len(architectures)) + b"".join(entries) + b"".join(slices)


def _write(path, payload, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(mode)


def _write_plist(path, value):
    _write(path, plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=True))


def _write_json(path, value):
    _write(path, (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))


def _privacy(reasons, collected=()):
    return {
        "NSPrivacyAccessedAPITypes": [
            {
                "NSPrivacyAccessedAPIType": category,
                "NSPrivacyAccessedAPITypeReasons": sorted(values),
            }
            for category, values in sorted(reasons.items())
        ],
        "NSPrivacyCollectedDataTypes": [
            {
                "NSPrivacyCollectedDataType": data_type,
                "NSPrivacyCollectedDataTypeLinked": True,
                "NSPrivacyCollectedDataTypePurposes": [verifier.APP_FUNCTIONALITY_PURPOSE],
                "NSPrivacyCollectedDataTypeTracking": False,
            }
            for data_type in sorted(collected)
        ],
        "NSPrivacyTracking": False,
        "NSPrivacyTrackingDomains": [],
    }


def _digest(label):
    return verifier._sha256_bytes(label.encode("ascii"))


def _binding(path, label):
    return {"path": path, "sha256": _digest(label)}


def _winn_slice(architecture, platform, minos, uuid_value):
    return {
        "architecture": architecture,
        "dependencies": ["/usr/lib/libSystem.B.dylib"],
        "filetype": "MH_DYLIB",
        "install_name": "@rpath/WinsWinnPacketEngine.framework/WinsWinnPacketEngine",
        "minos": minos,
        "platform": platform,
        "role_symbols": {
            "core": ["WinnTunnelCreateWinn3"],
            "relay": ["WinnTunnelCreate", "WinnTunnelCreateWithCarrier"],
        },
        "uuid": uuid_value,
    }


def _winn_wrapper(path, digest, architectures, platform, slices):
    return {
        "architectures": architectures,
        "filetype": "mach-o-dylib",
        "path": path,
        "platform": platform,
        "roles": ["core", "relay"],
        "sha256": digest,
        "slices": slices,
        "strip_state": "stripped",
    }


def _winn_release_provenance(macos_digest):
    archives = {}
    for key, architecture, platform, target in (
        ("iphoneos_arm64", "arm64", "IOS", "datapath-ios-arm64"),
        ("iphonesimulator_arm64", "arm64", "IOSSIMULATOR", "datapath-iossimulator-arm64"),
        ("iphonesimulator_x86_64", "x86_64", "IOSSIMULATOR", "datapath-iossimulator-amd64"),
        ("macosx_arm64", "arm64", "MACOS", "datapath-archive-darwin-arm64"),
        ("macosx_x86_64", "x86_64", "MACOS", "datapath-archive-darwin-amd64"),
    ):
        archives[key] = {
            "architectures": [architecture],
            "build_a_sha256": _digest(key + ":archive"),
            "build_b_sha256": _digest(key + ":archive"),
            "filetype": "ar-archive",
            "header_path": key + ".h",
            "header_sha256": _digest(key + ":header"),
            "path": key + ".a",
            "platform": platform,
            "sha256": _digest(key + ":archive"),
            "target": target,
        }
    return {
        "apple_toolchain": {
            "tools": {
                name: _binding("/usr/bin/" + name, "tool:" + name)
                for name in ("ar", "clang", "file", "lipo", "nm", "otool", "strip", "vtool")
            }
        },
        "archives": archives,
        "builders": {
            "wrapper_builder": _binding("tools/build_apple_engine_wrappers.sh", "wrapper-builder"),
            "wrapper_header": _binding("apple/EngineWrappers/WinnTunnel.h", "wrapper-header"),
        },
        "component": "winn-apple-engine-wrappers",
        "generation": "v3",
        "release": {
            "contract": "winsvpn-winn-release-manifest-v1",
            "go": {
                "archive_sha256": _digest("go-archive"),
                "executable_sha256": _digest("go-executable"),
                "install_tree_sha256": _digest("go-tree"),
                "version": "1.27.1",
            },
            "manifest_sha256": _digest("release-manifest"),
            "producer": {
                "builder_sha256": _digest("release-builder"),
                "driver_sha256": _digest("release-driver"),
                "toolchain_pins_sha256": _digest("toolchain-pins"),
            },
            "signature_public_key": _digest("release-public-key"),
            "signature_state": "signed",
            "source": {
                "binding": "git-archive",
                "commit": "260da56",
                "tree_sha256": _digest("source-tree"),
            },
        },
        "role_binding": {
            "core": {
                "entry_symbol": "WinnTunnelCreateWinn3",
                "payload_class": "ip-packet",
                "required_symbols": ["WinnTunnelCreateWinn3"],
            },
            "relay": {
                "entry_symbols": ["WinnTunnelCreate", "WinnTunnelCreateWithCarrier"],
                "payload_class": "awg-datagram",
                "required_symbols": ["WinnTunnelCreate", "WinnTunnelCreateWithCarrier"],
            },
        },
        "schema_version": 5,
        "source": {
            "module": "winsvpn.local/winnprotocol",
            "wrapper_path": "apple/EngineWrappers/WinsWinnPacketEngine.m",
            "wrapper_sha256": _digest("wrapper-source"),
        },
        "wrappers": {
            "iphoneos": _winn_wrapper(
                "ios/iphoneos/libWinsWinnPacketEngine.dylib",
                _digest("iphoneos-wrapper"),
                ["arm64"],
                "IOS",
                {"arm64": _winn_slice("arm64", "IOS", "13.0", "11111111-1111-1111-1111-111111111111")},
            ),
            "iphonesimulator": _winn_wrapper(
                "ios/iphonesimulator/libWinsWinnPacketEngine.dylib",
                _digest("iphonesimulator-wrapper"),
                ["arm64", "x86_64"],
                "IOSSIMULATOR",
                {
                    "arm64": _winn_slice("arm64", "IOSSIMULATOR", "14.0", "22222222-2222-2222-2222-222222222222"),
                    "x86_64": _winn_slice("x86_64", "IOSSIMULATOR", "13.0", "33333333-3333-3333-3333-333333333333"),
                },
            ),
            "macosx": _winn_wrapper(
                "macos/libWinsWinnPacketEngine.dylib",
                macos_digest,
                ["arm64", "x86_64"],
                "MACOS",
                {
                    "arm64": _winn_slice("arm64", "MACOS", "13.0", "44444444-4444-4444-4444-444444444444"),
                    "x86_64": _winn_slice("x86_64", "MACOS", "13.0", "55555555-5555-5555-5555-555555555555"),
                },
            ),
        },
    }


_RELEASE_SEED = bytes(range(7, 39))
_RELEASE_TARGETS = {
    "iphoneos_arm64": "datapath-ios-arm64",
    "iphonesimulator_arm64": "datapath-iossimulator-arm64",
    "iphonesimulator_x86_64": "datapath-iossimulator-amd64",
    "macosx_arm64": "datapath-archive-darwin-arm64",
    "macosx_x86_64": "datapath-archive-darwin-amd64",
}


def _release_driver():
    spec = importlib.util.spec_from_file_location(
        "winn_release_macos_fixture", verifier.WINN_RELEASE_DRIVER
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _make_signed_release(root, seed=_RELEASE_SEED, sign=True):
    """A driver-layout Winn release holding the five Apple slices.

    Returns the release directory, the authority pin path that trusts the
    fixture key, and the manifest dictionary.
    """
    driver = _release_driver()
    release = pathlib.Path(root) / "winn-release"
    artifacts = []
    for key, target in _RELEASE_TARGETS.items():
        directory = release / "artifacts" / target
        directory.mkdir(parents=True)
        archive = directory / "libwinn-datapath.a"
        header = directory / "libwinn-datapath.h"
        archive.write_bytes(("!<arch>\nfixture " + target + "\n").encode("ascii"))
        header.write_text("/* " + target + " */\n", encoding="ascii")
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        artifacts.append({
            "build_a_sha256": digest,
            "build_b_sha256": digest,
            "header_path": "artifacts/" + target + "/libwinn-datapath.h",
            "header_sha256": hashlib.sha256(header.read_bytes()).hexdigest(),
            "path": "artifacts/" + target + "/libwinn-datapath.a",
            "sha256": digest,
            "size": archive.stat().st_size,
            "target": target,
        })
    manifest = {
        "artifacts": artifacts,
        "contract": "winsvpn-winn-release-manifest-v1",
        "producer": {
            "build_winn_protocol_engine.sh": _digest("release-builder"),
            "toolchain-pins.json": _digest("toolchain-pins"),
            "winn_release.py": _digest("release-driver"),
        },
        "source": {
            "binding": "git-archive",
            "commit": "260da56",
            "path": "winn_protocol_experimental",
            "tree_sha256": _digest("source-tree"),
        },
        "toolchains": {
            "go": {
                "archive_sha256": _digest("go-archive"),
                "executable_sha256": _digest("go-executable"),
                "install_tree_sha256": _digest("go-tree"),
                "version": "1.27.1",
            }
        },
    }
    payload = driver.canonical_json(manifest)
    (release / "manifest.json").write_bytes(payload)
    public = driver.ed25519_public(seed).hex()
    if sign:
        (release / "manifest.sig.json").write_bytes(driver.canonical_json({
            "algorithm": "ed25519",
            "contract": driver.SIGNATURE_CONTRACT,
            "manifest_sha256": hashlib.sha256(payload).hexdigest(),
            "public_key": public,
            "signature": driver.ed25519_sign(seed, driver.SIGNATURE_DOMAIN + payload).hex(),
        }))
    pin = pathlib.Path(root) / "winn_release_authority.json"
    pin.write_text(json.dumps({
        "algorithm": "ed25519",
        "contract": "winsvpn-winn-release-authority-v1",
        "public_key": public,
    }), encoding="ascii")
    return release, pin, manifest


def _release_bound_provenance(macos_digest, release, manifest):
    """Winn provenance whose release record and slices name the release."""
    value = _winn_release_provenance(macos_digest)
    by_target = {entry["target"]: entry for entry in manifest["artifacts"]}
    signature = json.loads((release / "manifest.sig.json").read_text(encoding="ascii"))
    value["release"]["manifest_sha256"] = hashlib.sha256(
        (release / "manifest.json").read_bytes()
    ).hexdigest()
    value["release"]["signature_public_key"] = signature["public_key"]
    for key, target in _RELEASE_TARGETS.items():
        entry = by_target[target]
        for field in ("build_a_sha256", "build_b_sha256", "header_sha256", "sha256"):
            value["archives"][key][field] = entry[field]
    return value


FIXTURE_AWG_SOURCE_PINS = {
    "commit": "1" * 40,
    "go_mod_sha256": _digest("fixture-go.mod"),
    "go_sum_sha256": _digest("fixture-go.sum"),
    "repository": "https://example.invalid/amneziawg-apple.git",
    "tag": "v0.0.0-fixture",
    "tree": "2" * 40,
}
FIXTURE_AWG_XRAY_REPLACEMENT_PINS = {
    "commit": "3" * 40,
    "go_mod_sum": "h1:fixture-go-mod-sum=",
    "module_sum": "h1:fixture-module-sum=",
    "replaced_module": "github.com/xtls/xray-core",
    "source_module": "github.com/amnezia-vpn/amnezia-xray-core",
    "version": "v0.0.0-fixture",
    "zip_sha256": _digest("fixture-xray-zip"),
}
# Verifier pin field -> tools/build_apple_wg_go_bridge.sh variable.
BRIDGE_PIN_VARIABLES = {
    ("source", "commit"): "AMNEZIAWG_APPLE_COMMIT",
    ("source", "go_mod_sha256"): "AMNEZIAWG_APPLE_GO_MOD_SHA256",
    ("source", "go_sum_sha256"): "AMNEZIAWG_APPLE_GO_SUM_SHA256",
    ("source", "repository"): "AMNEZIAWG_APPLE_REPO",
    ("source", "tag"): "AMNEZIAWG_APPLE_TAG",
    ("source", "tree"): "AMNEZIAWG_APPLE_TREE",
    ("xray_replacement", "commit"): "AMNEZIA_XRAY_COMMIT",
    ("xray_replacement", "go_mod_sum"): "AMNEZIA_XRAY_GO_MOD_SUM",
    ("xray_replacement", "module_sum"): "AMNEZIA_XRAY_SUM",
    ("xray_replacement", "replaced_module"): "AMNEZIA_XRAY_REPLACED_MODULE",
    ("xray_replacement", "source_module"): "AMNEZIA_XRAY_MODULE",
    ("xray_replacement", "version"): "AMNEZIA_XRAY_VERSION",
    ("xray_replacement", "zip_sha256"): "AMNEZIA_XRAY_ZIP_SHA256",
}


NORMALIZED_FIELD = "signature_normalized_sha256"
DARWIN = sys.platform == "darwin"
TOOL_ENVIRONMENT = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}


def _tool(arguments):
    completed = subprocess.run(
        list(arguments),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=dict(TOOL_ENVIRONMENT, TMPDIR=tempfile.gettempdir()),
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(" ".join(arguments) + ": " + completed.stderr)
    return completed.stdout


def _compile_universal_engine(destination, marker="wins-normalized-engine"):
    """A real arm64 + x86_64 dylib as clang links it (arm64 linker-signed)."""
    source = destination.with_name(destination.name + ".c")
    source.write_text(
        "int wins_normalized_engine(int value) { return value * 7 + 3; }\n"
        'const char wins_normalized_marker[] = "' + marker + '";\n',
        encoding="ascii",
    )
    _tool(
        [
            "/usr/bin/clang", "-dynamiclib", "-Os", "-arch", "arm64", "-arch", "x86_64",
            "-o", str(destination), str(source),
        ]
    )
    source.unlink()
    destination.chmod(0o755)
    return destination


def _codesign_ad_hoc(path, *options):
    _tool(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", *options, str(path)])


def _flip_text_byte(path, architecture="arm64"):
    """Flip one byte of __TEXT,__text in one slice of a universal Mach-O."""
    data = bytearray(path.read_bytes())
    cputype = {"arm64": 0x0100000C, "x86_64": 0x01000007}[architecture]
    if struct.unpack_from(">I", data, 0)[0] != 0xCAFEBABE:
        raise AssertionError("not a universal Mach-O")
    for index in range(struct.unpack_from(">I", data, 4)[0]):
        cpu, _subtype, slice_offset, _size, _align = struct.unpack_from(">5I", data, 8 + index * 20)
        if cpu == cputype:
            break
    else:
        raise AssertionError("slice not found: " + architecture)
    commands = struct.unpack_from("<I", data, slice_offset + 16)[0]
    cursor = slice_offset + 32
    for _ in range(commands):
        command, size = struct.unpack_from("<II", data, cursor)
        if command == 0x19 and bytes(data[cursor + 8 : cursor + 24]).rstrip(b"\0") == b"__TEXT":
            for section in range(struct.unpack_from("<I", data, cursor + 64)[0]):
                base = cursor + 72 + section * 80
                if bytes(data[base : base + 16]).rstrip(b"\0") == b"__text":
                    data[slice_offset + struct.unpack_from("<I", data, base + 48)[0]] ^= 0xFF
                    path.write_bytes(bytes(data))
                    return
        cursor += size
    raise AssertionError("__TEXT,__text not found")


def _normalized_with_verifier(path, scratch):
    scratch.mkdir(mode=0o700, exist_ok=True)
    with verifier.HeldFile(path, "normalization fixture") as held:
        return verifier.signature_normalized_sha256(
            held, scratch, "fixture", verifier.run_command
        )


def _real_codesign_engine_runner(arguments, timeout):
    """Real codesign for normalization; the fixture symbol and load facts otherwise."""
    if arguments[0] == "/usr/bin/codesign":
        return verifier.run_command(arguments, timeout)
    return _engine_runner(arguments, timeout)


@contextlib.contextmanager
def _fixture_awg_pins():
    with mock.patch.dict(
        verifier.REVIEWED_AWG_SOURCE_PINS, FIXTURE_AWG_SOURCE_PINS, clear=True
    ), mock.patch.dict(
        verifier.REVIEWED_AWG_XRAY_REPLACEMENT_PINS,
        FIXTURE_AWG_XRAY_REPLACEMENT_PINS,
        clear=True,
    ):
        yield


@contextlib.contextmanager
def _unpinned_awg_pins():
    """The committed pins with the three network-measured digests blanked,
    which is the state the tree was in before they were measured."""
    source = dict(verifier.REVIEWED_AWG_SOURCE_PINS, go_mod_sha256="", go_sum_sha256="")
    xray = dict(verifier.REVIEWED_AWG_XRAY_REPLACEMENT_PINS, zip_sha256="")
    with mock.patch.dict(
        verifier.REVIEWED_AWG_SOURCE_PINS, source, clear=True
    ), mock.patch.dict(
        verifier.REVIEWED_AWG_XRAY_REPLACEMENT_PINS, xray, clear=True
    ):
        yield


class FixtureAuthenticatedFacts:
    """Post-authority test facts, not an authority or authorization issuer."""

    def __init__(self, expected):
        self.expected = copy.deepcopy(expected)

    def __enter__(self):
        return self

    def authenticate(self, payload, awg_payload, xray_payload):
        value = verifier._json_bytes(payload, "Winn v3 provenance")
        awg = verifier._json_bytes(awg_payload, "AWG provenance")
        xray = verifier._json_bytes(xray_payload, "Xray provenance")
        if value != self.expected["winn"] or awg != self.expected["awg"] or xray != self.expected["xray"]:
            raise verifier.VerificationError(
                "Apple engine provenance is internally consistent but is not externally authorized"
            )
        records = {
            "amneziawg_packet_engine": awg["wrappers"]["macosx"]["amneziawg_packet_engine"],
            "xray_vless_ws_transport": xray["wrappers"]["macosx"],
            "winn_packet_engine": value["wrappers"]["macosx"],
        }
        return {
            "winn": value,
            "engine_sha256": {
                component: record["sha256"] for component, record in records.items()
            },
            "engine_signature_normalized_sha256": {
                component: record.get(NORMALIZED_FIELD) for component, record in records.items()
            },
        }

    def verify(self):
        return None

    def __exit__(self, _type, _value, _traceback):
        return None


class ArtifactFixture:
    def __init__(self, root):
        self.root = pathlib.Path(root)
        self.app = self.root / "Win's VPN.app"
        self.contents = self.app / "Contents"
        self.tunnel = self.contents / "PlugIns/PacketTunnel.appex"
        self.engines = {}
        self.authenticated_apple = None
        self._create()

    def _create(self):
        _write_plist(
            self.contents / "Info.plist",
            {
                "CFBundleExecutable": "Win's VPN",
                "CFBundleIdentifier": verifier.HOST_BUNDLE_ID,
                "CFBundlePackageType": "APPL",
                "CFBundleShortVersionString": "1.2.3",
                "CFBundleVersion": "42",
                verifier.RUNTIME_CONTRACT_KEY: verifier.RUNTIME_CONTRACT,
            },
        )
        _write(self.contents / "MacOS/Win's VPN", _fat_macho(), 0o755)
        _write_plist(
            self.tunnel / "Contents/Info.plist",
            {
                "CFBundleExecutable": "PacketTunnel",
                "CFBundleIdentifier": verifier.TUNNEL_BUNDLE_ID,
                "CFBundlePackageType": "XPC!",
                "CFBundleShortVersionString": "1.2.3",
                "CFBundleVersion": "42",
                "NSExtension": {
                    "NSExtensionPointIdentifier": "com.apple.networkextension.packet-tunnel"
                },
                verifier.RUNTIME_CONTRACT_KEY: verifier.RUNTIME_CONTRACT,
            },
        )
        _write(
            self.tunnel / "Contents/MacOS/PacketTunnel",
            _fat_macho() + b"\0" + b"\0".join(verifier.REQUIRED_WINN3_BINARY_MARKERS),
            0o755,
        )
        _write(self.contents / "embedded.provisionprofile", b"host-profile")
        _write(self.tunnel / "Contents/embedded.provisionprofile", b"tunnel-profile")
        _write_plist(
            self.contents / "Resources/PrivacyInfo.xcprivacy",
            _privacy(verifier.HOST_PRIVACY_REASONS, verifier.HOST_COLLECTED_TYPES),
        )
        _write_plist(
            self.tunnel / "Contents/Resources/PrivacyInfo.xcprivacy",
            _privacy(verifier.TUNNEL_PRIVACY_REASONS),
        )
        for component, spec in verifier.ENGINE_FRAMEWORKS.items():
            framework = self.contents / "Frameworks" / spec["framework"]
            executable_name = pathlib.Path(spec["framework"]).stem
            _write_plist(
                framework / "Versions/A/Resources/Info.plist",
                {
                    "CFBundleExecutable": executable_name,
                    "CFBundleIdentifier": spec["identifier"],
                    "CFBundlePackageType": "FMWK",
                },
            )
            executable = framework / "Versions/A" / executable_name
            _write(executable, _fat_macho(), 0o755)
            _write_plist(
                framework / "Versions/A/Resources/PrivacyInfo.xcprivacy",
                _privacy(spec["privacy"]),
            )
            self.engines[component] = executable

    def topology(self):
        return verifier.audit_code_topology(self.app)

    def add_provenance(self, normalized=None):
        """Provenance for the current engine bytes.

        normalized maps a component to the signature_normalized_sha256 its
        macOS wrapper record carries; components it omits record none.
        """
        normalized = normalized or {}
        resources = self.contents / "Resources"
        digests = {name: verifier.sha256_file(path) for name, path in self.engines.items()}

        def record(component):
            value = {"sha256": digests[component]}
            if component in normalized:
                value[NORMALIZED_FIELD] = normalized[component]
            return value

        awg = {
            "schema_version": 2,
            "generation": "3.1",
            "component": "amneziawg-apple-engine-wrappers",
            "wrappers": {"macosx": {"amneziawg_packet_engine": record("amneziawg_packet_engine")}},
        }
        winn = _winn_release_provenance(digests["winn_packet_engine"])
        if "winn_packet_engine" in normalized:
            winn["wrappers"]["macosx"][NORMALIZED_FIELD] = normalized["winn_packet_engine"]
        xray = {
            "schema_version": 1,
            "component": "xray-apple-vless-ws-engine-wrappers",
            "wrappers": {"macosx": record("xray_vless_ws_transport")},
        }
        self.authenticated_apple = copy.deepcopy({"awg": awg, "winn": winn, "xray": xray})
        awg_path = resources / "apple_awg_31_engine_provenance.json"
        winn_path = resources / "apple_winn_v3_engine_provenance.json"
        xray_path = resources / "apple_xray_vless_ws_engine_provenance.json"
        _write_json(awg_path, awg)
        _write_json(winn_path, winn)
        _write_json(xray_path, xray)
        _write_json(
            resources / "apple_engine_artifacts_manifest.json",
            {
                "schema_version": 1,
                "platform_name": "macosx",
                "required_components": sorted(verifier.RUNTIME_CONTRACT["required_engine_components"]),
                "optional_components": [],
                "staged_components": sorted(verifier.RUNTIME_CONTRACT["required_engine_components"]),
                "secret_material_redacted": True,
                "apple_awg_31_provenance_sha256": verifier.sha256_file(awg_path),
                "apple_xray_vless_ws_provenance_sha256": verifier.sha256_file(xray_path),
                "apple_winn_v3_provenance_sha256": verifier.sha256_file(winn_path),
            },
        )

    def replace_winn_provenance(self, value):
        resources = self.contents / "Resources"
        winn_path = resources / "apple_winn_v3_engine_provenance.json"
        manifest_path = resources / "apple_engine_artifacts_manifest.json"
        _write_json(winn_path, value)
        manifest = json.loads(manifest_path.read_text(encoding="ascii"))
        manifest["apple_winn_v3_provenance_sha256"] = verifier.sha256_file(winn_path)
        _write_json(manifest_path, manifest)

    def replace_awg_provenance(self, value):
        resources = self.contents / "Resources"
        awg_path = resources / "apple_awg_31_engine_provenance.json"
        manifest_path = resources / "apple_engine_artifacts_manifest.json"
        _write_json(awg_path, value)
        manifest = json.loads(manifest_path.read_text(encoding="ascii"))
        manifest["apple_awg_31_provenance_sha256"] = verifier.sha256_file(awg_path)
        _write_json(manifest_path, manifest)

    def pinned_awg_provenance(self, normalized=None):
        """AWG provenance carrying the fixture pins and the real Go toolchain pins."""
        digests = {name: verifier.sha256_file(path) for name, path in self.engines.items()}
        pins = json.loads((verifier.ROOT / "tools/toolchain-pins.json").read_text(encoding="utf-8"))
        go = pins["tools"]["go"]
        value = {
            "schema_version": 2,
            "generation": "3.1",
            "component": "amneziawg-apple-engine-wrappers",
            "bridge_provenance_sha256": _digest("fixture-bridge-provenance"),
            "source": dict(FIXTURE_AWG_SOURCE_PINS),
            "go_toolchain": {
                "darwin_amd64_archive_sha256": go["archive_sha256"]["darwin_amd64"],
                "darwin_arm64_archive_sha256": go["archive_sha256"]["darwin_arm64"],
                "version": go["version"],
            },
            "xray_replacement": dict(FIXTURE_AWG_XRAY_REPLACEMENT_PINS),
            "wrappers": {
                "macosx": {
                    "amneziawg_packet_engine": {"sha256": digests["amneziawg_packet_engine"]},
                    "xray_vless_ws_transport": {"sha256": digests["xray_vless_ws_transport"]},
                }
            },
        }
        for component, digest in (normalized or {}).items():
            value["wrappers"]["macosx"][component][NORMALIZED_FIELD] = digest
        return value

    def authenticated_facts(self):
        expected = copy.deepcopy(self.authenticated_apple)
        return FixtureAuthenticatedFacts(expected)


def _completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)


def _engine_runner(arguments, _timeout):
    if arguments[0] == "/usr/bin/nm":
        symbols = sorted(
            set().union(
                verifier.REQUIRED_WINN3_TUNNEL_SYMBOLS,
                *(spec["symbols"] for spec in verifier.ENGINE_FRAMEWORKS.values()),
            )
        )
        return _completed("\n".join("_" + symbol for symbol in symbols) + "\n")
    if arguments[0] == "/usr/bin/otool" and arguments[1] == "-L":
        return _completed(
            "\t@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine "
            "(compatibility version 1.0.0, current version 1.0.0)\n"
        )
    return _completed()


def _signed_macho_runner(arguments, _timeout):
    tool = arguments[0]
    path = pathlib.Path(arguments[-1])
    if tool == "/usr/bin/lipo":
        return _completed("x86_64 arm64\n")
    if tool == "/usr/bin/otool":
        return _completed("")
    if tool != "/usr/bin/codesign":
        return _completed()
    if "--verify" in arguments:
        return _completed()
    if "--entitlements" in arguments:
        if path.name.casefold().endswith(".app"):
            value = verifier.expected_entitlements(verifier.HOST_BUNDLE_ID, True)
        elif path.name.casefold().endswith(".appex"):
            value = verifier.expected_entitlements(verifier.TUNNEL_BUNDLE_ID, True)
        else:
            value = {}
        return _completed(plistlib.dumps(value).decode("utf-8"))
    identifier = path.name
    if path.name.casefold().endswith(".app"):
        identifier = verifier.HOST_BUNDLE_ID
    elif path.name.casefold().endswith(".appex"):
        identifier = verifier.TUNNEL_BUNDLE_ID
    else:
        for spec in verifier.ENGINE_FRAMEWORKS.values():
            if path.name == pathlib.Path(spec["framework"]).stem:
                identifier = spec["identifier"]
                break
    authority = "Developer ID Application: " + verifier.OWNER_COMMON_NAME + " (" + verifier.TEAM_ID + ")"
    return _completed(
        "Identifier=" + identifier + "\n"
        "TeamIdentifier=" + verifier.TEAM_ID + "\n"
        "Authority=" + authority + "\n"
        "CodeDirectory v=20500 size=1 flags=0x10000(runtime) hashes=1+1 location=embedded\n"
        "Timestamp=Aug 25, 2026\n"
    )


def _plain_inventory(root):
    records = []
    for relative in sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    ):
        path = root.joinpath(*pathlib.PurePosixPath(relative).parts)
        records.append(
            {
                "path": relative,
                "size": path.stat().st_size,
                "sha256": verifier.sha256_file(path),
            }
        )
    return records


def _stable_uuid(seed, architecture):
    return str(uuid.UUID(verifier._sha256_bytes(seed.encode("ascii"))[:32]))


def _isolated_test_root():
    root = pathlib.Path(tempfile.gettempdir()).resolve()
    for component in (
        "winsvpn-verifier-custody",
        "depth-one",
        "depth-two",
        "depth-three",
        "depth-four",
        "depth-five",
        "depth-six",
        "depth-seven",
    ):
        root = root / component
        root.mkdir(mode=0o700, exist_ok=True)
    return root


_ISOLATED_TEST_ROOT = _isolated_test_root()


def _uuid_runner(arguments, _timeout):
    if arguments[0] == "/usr/bin/dwarfdump":
        name = pathlib.Path(arguments[-1]).name
        lines = [
            "UUID: " + _stable_uuid(name + ":" + architecture, architecture) + " (" + architecture + ")"
            for architecture in ("arm64", "x86_64")
        ]
        return _completed("\n".join(lines) + "\n")
    return _completed()


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="winsvpn-macos-verifier-test-", dir=_ISOLATED_TEST_ROOT
        )
        self.fixture = ArtifactFixture(pathlib.Path(self.temporary.name).resolve())
        private_root = verifier.ROOT / ".artifacts" / "private-release-symbols"
        private_root.mkdir(mode=0o700, parents=True, exist_ok=True)

    def tearDown(self):
        self.temporary.cleanup()

    def assertBlocked(self, function, text=None):
        with self.assertRaises(verifier.VerificationError) as context:
            function()
        if text is not None:
            self.assertIn(text, str(context.exception))

    def rewrite_info(self, path, update):
        value = plistlib.loads(path.read_bytes())
        update(value)
        _write_plist(path, value)

    def obfuscation_fixture(self, version="1.2.3", build="42"):
        distribution = self.fixture.root / "distribution/release.dmg"
        _write(distribution, b"held-dmg")
        receipt = self.fixture.root / "obfuscation/receipt.json"
        symbol = receipt.parent / "flutter/app.macos-arm64.symbols"
        _write(symbol, b"private-symbols")
        claims = {
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
        _write_json(
            receipt,
            {
                "schema_version": 2,
                "contract": "winsvpn-release-obfuscation-and-secret-free-v2",
                "contract_sha256": verifier.sha256_file(
                    verifier.OBFUSCATION_SOURCE_FILES["release_obfuscation_contract"]
                ),
                "platform": "macos",
                "app_version": version,
                "build_number": build,
                "created_at_utc": "2026-08-27T00:00:00Z",
                "private_symbols_not_packaged": True,
                "verification": {claim: True for claim in claims},
                "artifacts": [
                    {
                        "path": str(distribution),
                        "size": distribution.stat().st_size,
                        "sha256": verifier.sha256_file(distribution),
                    }
                ],
                "symbols": [
                    {
                        "path": symbol.relative_to(receipt.parent).as_posix(),
                        "size": symbol.stat().st_size,
                        "sha256": verifier.sha256_file(symbol),
                    }
                ],
            },
        )
        return distribution, receipt

    def symbol_receipt_fixture(self, version="1.2.3", build="42"):
        distribution = self.fixture.root / "distribution/release.dmg"
        _write(distribution, b"held-dmg")
        digest = verifier.sha256_file(distribution)
        custody = verifier.ROOT / ".artifacts" / "private-release-symbols" / digest
        receipt = custody / "manifest.json"
        shutil.rmtree(custody, ignore_errors=True)
        self.addCleanup(shutil.rmtree, custody, ignore_errors=True)
        flutter = custody / "flutter"
        _write(flutter / "app.macos-arm64.symbols", b"private-arm64-symbols")
        _write(flutter / "app.macos-x64.symbols", b"private-x64-symbols")
        dsyms = custody / "dSYMs"
        topology = self.fixture.topology()
        for path in topology["macho_files"]:
            name = pathlib.Path(path).name
            _write(
                dsyms / (name + ".dSYM") / "Contents/Resources/DWARF" / name,
                b"dwarf-" + name.encode("utf-8"),
            )
        _write_json(
            receipt,
            {
                "schema_version": 1,
                "contract": "winsvpn-apple-private-symbol-custody-v1",
                "platform": "macos",
                "app_version": version,
                "build_number": build,
                "created_at_utc": "2026-08-27T00:00:00Z",
                "private_symbols_not_packaged": True,
                "artifact": {
                    "filename": distribution.name,
                    "size": distribution.stat().st_size,
                    "sha256": digest,
                },
                "flutter_symbols": _plain_inventory(flutter),
                "xcarchive_dsyms": _plain_inventory(dsyms),
            },
        )
        return distribution, receipt, topology

    @contextlib.contextmanager
    def mirrored_obfuscation_sources(self):
        mirror = pathlib.Path(
            tempfile.mkdtemp(prefix="reviewed-verifier-sources-", dir=self.fixture.root)
        )
        mirror.chmod(0o700)
        mapping = {}
        for name, source in verifier.OBFUSCATION_SOURCE_FILES.items():
            destination = mirror / (name + ".py")
            _write(destination, source.read_bytes(), 0o600)
            mapping[name] = destination
        with mock.patch.object(verifier, "OBFUSCATION_SOURCE_FILES", mapping):
            yield mapping

    def verifier_namespace_from_arguments(self, arguments):
        command_index = arguments.index("-c")
        self.assertEqual(arguments[command_index - 2 : command_index], ["-I", "-S"])
        self.assertEqual(arguments[command_index + 1], verifier.CANONICAL_OBFUSCATION_ADAPTER)
        return pathlib.Path(arguments[command_index + 2])

    def assert_snapshot_arguments(
        self, arguments, distribution, receipt, artifact_bytes=None, receipt_bytes=None,
        symbol_bytes=None,
    ):
        artifact_snapshot = pathlib.Path(arguments[arguments.index("--artifact") + 1])
        receipt_snapshot = pathlib.Path(arguments[arguments.index("--manifest") + 1])
        symbols_dir = pathlib.Path(arguments[arguments.index("--symbols-dir") + 1])
        self.assertNotEqual(artifact_snapshot, distribution)
        self.assertNotEqual(receipt_snapshot, receipt)
        self.assertEqual(receipt_snapshot.parent, symbols_dir)
        self.assertEqual(
            artifact_snapshot.read_bytes(),
            distribution.read_bytes() if artifact_bytes is None else artifact_bytes,
        )
        self.assertEqual(
            receipt_snapshot.read_bytes(),
            receipt.read_bytes() if receipt_bytes is None else receipt_bytes,
        )
        if symbol_bytes is None:
            symbol_bytes = {
                path.relative_to(receipt.parent).as_posix(): path.read_bytes()
                for path in receipt.parent.rglob("*.symbols")
            }
        self.assertEqual(
            {
                path.relative_to(symbols_dir).as_posix(): path.read_bytes()
                for path in symbols_dir.rglob("*.symbols")
            },
            symbol_bytes,
        )
        namespace = self.verifier_namespace_from_arguments(arguments)
        self.assertEqual(
            {path.name: path.read_bytes() for path in namespace.iterdir()},
            {
                name + ".py": source.read_bytes()
                for name, source in verifier.OBFUSCATION_SOURCE_FILES.items()
            },
        )

    def mutate_private_symbol_snapshot_and_restore(self, arguments):
        symbols_dir = pathlib.Path(arguments[arguments.index("--symbols-dir") + 1])
        symbol = next(symbols_dir.rglob("*.symbols"))
        original = symbol.read_bytes()
        hostile = b"H" * len(original)
        symbol.chmod(0o600)
        with symbol.open("r+b", buffering=0) as handle:
            handle.write(hostile)
            os.fsync(handle.fileno())
            handle.seek(0)
            handle.write(original)
            os.fsync(handle.fileno())
        symbol.chmod(0o400)

    def test_valid_topology_and_privacy(self):
        topology = self.fixture.topology()
        verifier.verify_all_privacy(self.fixture.app, topology)
        self.assertEqual(set(topology["engines"]), set(verifier.ENGINE_FRAMEWORKS))

    def test_wrong_host_bundle_identifier_is_blocked(self):
        path = self.fixture.contents / "Info.plist"
        self.rewrite_info(path, lambda value: value.update(CFBundleIdentifier="org.attacker.app"))
        self.assertBlocked(self.fixture.topology, "bundle identifier")

    def test_wrong_tunnel_bundle_identifier_is_blocked(self):
        path = self.fixture.tunnel / "Contents/Info.plist"
        self.rewrite_info(path, lambda value: value.update(CFBundleIdentifier="org.attacker.tunnel"))
        self.assertBlocked(self.fixture.topology, "PacketTunnel")

    def test_runtime_fallback_reordering_is_blocked(self):
        path = self.fixture.contents / "Info.plist"
        def alter(value):
            value[verifier.RUNTIME_CONTRACT_KEY]["fallback"] = ["xray", "awg"]
        self.rewrite_info(path, alter)
        self.assertBlocked(self.fixture.topology, "runtime contract")

    def test_extra_extension_is_blocked(self):
        (self.fixture.contents / "PlugIns/Evil.appex").mkdir()
        self.assertBlocked(self.fixture.topology, "exactly one")

    def test_loose_dylib_is_blocked(self):
        _write(self.fixture.contents / "Frameworks/loose.dylib", _fat_macho(), 0o755)
        self.assertBlocked(self.fixture.topology, "loose dylibs")

    def test_executable_resource_is_blocked(self):
        _write(self.fixture.contents / "Resources/run-me", b"#!/bin/sh\nexit 0\n", 0o755)
        self.assertBlocked(self.fixture.topology, "unexpected executable")

    def test_group_writable_macho_is_blocked(self):
        (self.fixture.contents / "MacOS/Win's VPN").chmod(0o775)
        self.assertBlocked(self.fixture.topology, "writable")

    def test_packaged_test_content_is_blocked(self):
        _write(self.fixture.contents / "Resources/RunnerTests.symbols", b"private")
        self.assertBlocked(self.fixture.topology, "private symbol")

    def test_escaping_symlink_is_blocked(self):
        os.symlink("../../../../outside", self.fixture.contents / "Resources/escape")
        self.assertBlocked(lambda: verifier.tree_records(self.fixture.app), "symlink")

    def test_hardlink_is_blocked(self):
        source = self.fixture.contents / "Info.plist"
        os.link(source, self.fixture.contents / "Resources/hardlink")
        self.assertBlocked(lambda: verifier.tree_records(self.fixture.app), "hardlinked")

    def test_dmg_loose_executable_outside_app_is_blocked(self):
        mount = self.fixture.root / "mounted"
        embedded = mount / self.fixture.app.name
        shutil.copytree(self.fixture.app, embedded)
        _write(mount / "run-me", b"#!/bin/sh\nexit 0\n", 0o755)
        self.assertBlocked(
            lambda: verifier.audit_distribution_extraction(mount, embedded, "dmg"),
            "outside the exact app",
        )

    def test_pkg_extra_payload_content_is_blocked(self):
        expanded = self.fixture.root / "expanded"
        payload = expanded / "component.pkg/Payload/Applications"
        embedded = payload / self.fixture.app.name
        shutil.copytree(self.fixture.app, embedded)
        _write(expanded / "component.pkg/Payload/Library/rogue.conf", b"rogue")
        self.assertBlocked(
            lambda: verifier.audit_distribution_extraction(expanded, embedded, "pkg"),
            "outside the exact app",
        )

    def test_thin_macho_is_blocked(self):
        path = self.fixture.contents / "MacOS/Win's VPN"
        _write(path, _fat_macho(("arm64",)), 0o755)
        self.assertBlocked(
            lambda: verifier.verify_all_macho(
                self.fixture.app, self.fixture.topology(), _signed_macho_runner
            ),
            "exactly arm64 and x86_64",
        )

    def test_exact_universal_signed_macho_set_passes(self):
        results = verifier.verify_all_macho(
            self.fixture.app, self.fixture.topology(), _signed_macho_runner
        )
        self.assertEqual(len(results), 5)

    def test_unsealed_nested_code_is_blocked(self):
        def runner(arguments, timeout):
            path = pathlib.Path(arguments[-1])
            if (
                arguments[0] == "/usr/bin/codesign"
                and "--verify" in arguments
                and path.name == "WinsWinnPacketEngine"
            ):
                return _completed("", "code object is not signed at all", 1)
            return _signed_macho_runner(arguments, timeout)
        self.assertBlocked(
            lambda: verifier.verify_all_macho(self.fixture.app, self.fixture.topology(), runner),
            "code-signature verification failed",
        )

    def test_malformed_fat_macho_is_blocked(self):
        payload = struct.pack(">II", 0xCAFEBABE, 2) + b"\0" * 8
        self.assertBlocked(lambda: verifier._macho_architectures_from_bytes(payload, "bad"), "truncated")

    def test_tracking_privacy_manifest_is_blocked(self):
        path = self.fixture.contents / "Resources/PrivacyInfo.xcprivacy"
        self.rewrite_info(path, lambda value: value.update(NSPrivacyTracking=True))
        self.assertBlocked(
            lambda: verifier.verify_all_privacy(self.fixture.app, self.fixture.topology()),
            "tracking",
        )

    def test_missing_framework_privacy_manifest_is_blocked(self):
        spec = verifier.ENGINE_FRAMEWORKS["winn_packet_engine"]
        path = self.fixture.contents / "Frameworks" / spec["framework"] / "Versions/A/Resources/PrivacyInfo.xcprivacy"
        path.unlink()
        self.assertBlocked(
            lambda: verifier.verify_all_privacy(self.fixture.app, self.fixture.topology()),
            "missing",
        )

    def test_exact_entitlements_pass(self):
        value = verifier.expected_entitlements(verifier.HOST_BUNDLE_ID, False)
        verifier.verify_entitlements(value, value, "host")

    def test_debug_entitlement_is_blocked(self):
        expected = verifier.expected_entitlements(verifier.HOST_BUNDLE_ID, False)
        actual = dict(expected, **{"com.apple.security.get-task-allow": True})
        self.assertBlocked(lambda: verifier.verify_entitlements(actual, expected, "host"), "unsafe")

    def test_unexpected_server_entitlement_on_host_is_blocked(self):
        expected = verifier.expected_entitlements(verifier.HOST_BUNDLE_ID, False)
        actual = dict(expected, **{"com.apple.security.network.server": True})
        self.assertBlocked(lambda: verifier.verify_entitlements(actual, expected, "host"), "exact")

    def test_host_server_entitlement_is_exactly_what_production_expects(self):
        # The host app now needs network.server for its loopback-only browser
        # companion IPC. The map stays exact: dropping it, or adding anything
        # beside it, is still refused.
        expected = verifier.expected_entitlements(verifier.HOST_BUNDLE_ID, True)
        self.assertIs(expected.get("com.apple.security.network.server"), True)
        verifier.verify_entitlements(expected, expected, "host")
        missing = dict(expected)
        del missing["com.apple.security.network.server"]
        self.assertBlocked(lambda: verifier.verify_entitlements(missing, expected, "host"), "exact")
        extra = dict(expected, **{"com.apple.security.network.client.extra": True})
        self.assertBlocked(lambda: verifier.verify_entitlements(extra, expected, "host"), "exact")
        source = (verifier.ROOT / "tools/verify_macos_release_artifact.py").read_text(encoding="utf-8")
        self.assertIn("expected_entitlements(HOST_BUNDLE_ID, allow_server=True)", source)

    def signing_details(self, identifier=verifier.HOST_BUNDLE_ID, team=verifier.TEAM_ID,
                        authority=None, flags="0x10000(runtime)", timestamp="Aug 25, 2026"):
        if authority is None:
            authority = "Developer ID Application: " + verifier.OWNER_COMMON_NAME + " (" + verifier.TEAM_ID + ")"
        return (
            "Identifier=" + identifier + "\n"
            "TeamIdentifier=" + team + "\n"
            "Authority=" + authority + "\n"
            "CodeDirectory v=20500 size=1 flags=" + flags + " hashes=1+1 location=embedded\n"
            "Timestamp=" + timestamp + "\n"
        )

    def test_exact_developer_id_metadata_passes(self):
        parsed = verifier.parse_codesign_details(self.signing_details(), "host")
        self.assertEqual(parsed["identifier"], verifier.HOST_BUNDLE_ID)

    def test_wrong_team_signature_is_blocked(self):
        self.assertBlocked(
            lambda: verifier.parse_codesign_details(self.signing_details(team="BADTEAM000"), "host"),
            "wrong team",
        )

    def test_ad_hoc_signature_is_blocked(self):
        details = self.signing_details() + "Signature=adhoc\n"
        self.assertBlocked(lambda: verifier.parse_codesign_details(details, "host"), "ad hoc")

    def test_missing_hardened_runtime_is_blocked(self):
        self.assertBlocked(
            lambda: verifier.parse_codesign_details(self.signing_details(flags="0x0(none)"), "host"),
            "hardened runtime",
        )

    def test_missing_secure_timestamp_is_blocked(self):
        details = self.signing_details(timestamp="none")
        self.assertBlocked(lambda: verifier.parse_codesign_details(details, "host"), "timestamp")

    def test_exact_engine_provenance_and_symbols_pass(self):
        self.fixture.add_provenance()
        bindings = verifier._verify_engine_contract_after_external_authentication(
            self.fixture.app, self.fixture.topology(), _engine_runner, self.fixture.authenticated_facts()
        )
        self.assertEqual(set(bindings), set(verifier.ENGINE_FRAMEWORKS))

    def test_production_engine_verifier_requires_the_signed_winn_release(self):
        self.fixture.add_provenance()
        with mock.patch.dict(os.environ, {"WINS_WINN_RELEASE_DIR": ""}):
            self.assertBlocked(
                lambda: verifier.verify_engine_contract(
                    self.fixture.app, self.fixture.topology(), _engine_runner
                ),
                "signed Winn release directory is required",
            )

    def _release_case(
        self, mutate_release=None, mutate_provenance=None, sign=True, pin_seed=None, awg=None,
        normalized=None, before_verify=None, runner=_engine_runner,
    ):
        release, pin, manifest = _make_signed_release(self.fixture.root / "release-case", sign=sign)
        provenance_release = release
        if sign:
            value = _release_bound_provenance(
                verifier.sha256_file(self.fixture.engines["winn_packet_engine"]), release, manifest
            )
        else:
            value = _winn_release_provenance(
                verifier.sha256_file(self.fixture.engines["winn_packet_engine"])
            )
        if mutate_provenance is not None:
            mutate_provenance(value)
        self.fixture.add_provenance(normalized)
        self.fixture.replace_winn_provenance(value)
        if awg is not None:
            self.fixture.replace_awg_provenance(awg)
        if mutate_release is not None:
            mutate_release(provenance_release)
        if pin_seed is not None:
            driver = _release_driver()
            pin.write_text(json.dumps({
                "algorithm": "ed25519",
                "contract": "winsvpn-winn-release-authority-v1",
                "public_key": driver.ed25519_public(pin_seed).hex(),
            }), encoding="ascii")
        if before_verify is not None:
            before_verify()
        with mock.patch.object(verifier, "WINN_RELEASE_AUTHORITY", pin):
            return verifier.verify_engine_contract(
                self.fixture.app, self.fixture.topology(), runner, release
            )

    def test_signed_winn_release_refuses_unpinned_awg_provenance(self):
        # Winn is accepted against the signed release; while any AWG bridge pin
        # is empty the decision refuses as unpinned (never with an
        # unconditional owner block), even for exact AWG provenance. The
        # committed pins are complete, so the empty state is simulated.
        for value in (
            verifier.REVIEWED_AWG_SOURCE_PINS["go_mod_sha256"],
            verifier.REVIEWED_AWG_SOURCE_PINS["go_sum_sha256"],
            verifier.REVIEWED_AWG_XRAY_REPLACEMENT_PINS["zip_sha256"],
        ):
            self.assertRegex(value, r"^[0-9a-f]{64}$")
        for label, awg in (
            ("fixture", None),
            ("exact", self.fixture.pinned_awg_provenance()),
        ):
            with self.subTest(label=label):
                shutil.rmtree(self.fixture.root / "release-case", ignore_errors=True)
                with _unpinned_awg_pins(), self.assertRaises(verifier.VerificationError) as context:
                    self._release_case(awg=awg)
                message = str(context.exception)
                self.assertIn("unpinned AWG provenance", message)
                self.assertIn("source.go_mod_sha256", message)
                self.assertIn("xray_replacement.zip_sha256", message)
                self.assertNotIn("OWNER-BLOCKED", message)

    def test_pinned_awg_provenance_and_signed_winn_release_pass(self):
        awg = self.fixture.pinned_awg_provenance()
        with _fixture_awg_pins():
            bindings = self._release_case(awg=awg)
        self.assertEqual(set(bindings), set(verifier.ENGINE_FRAMEWORKS))
        for component, path in self.fixture.engines.items():
            self.assertEqual(bindings[component]["sha256"], verifier.sha256_file(path))

    def test_pinned_awg_provenance_returns_the_caller_shape(self):
        awg = self.fixture.pinned_awg_provenance()
        self.fixture.add_provenance()
        with _fixture_awg_pins():
            release, pin, manifest = _make_signed_release(self.fixture.root / "shape-case")
            winn = _release_bound_provenance(
                verifier.sha256_file(self.fixture.engines["winn_packet_engine"]), release, manifest
            )
            xray = self.fixture.authenticated_apple["xray"]
            encode = lambda value: json.dumps(value, sort_keys=True).encode("ascii")
            with mock.patch.object(verifier, "WINN_RELEASE_AUTHORITY", pin):
                with verifier.ReviewedWinnReleaseCustody(release) as custody:
                    result = custody.authenticate(encode(winn), encode(awg), encode(xray))
        self.assertEqual(
            set(result), {"winn", "engine_sha256", "engine_signature_normalized_sha256"}
        )
        self.assertEqual(result["winn"], winn)
        self.assertEqual(
            result["engine_sha256"],
            {
                "amneziawg_packet_engine": awg["wrappers"]["macosx"]["amneziawg_packet_engine"]["sha256"],
                "xray_vless_ws_transport": xray["wrappers"]["macosx"]["sha256"],
                "winn_packet_engine": winn["wrappers"]["macosx"]["sha256"],
            },
        )
        # Records without the field authenticate as None: a raw match still
        # binds them, and a raw mismatch then refuses.
        self.assertEqual(
            result["engine_signature_normalized_sha256"],
            {
                "amneziawg_packet_engine": None,
                "xray_vless_ws_transport": None,
                "winn_packet_engine": None,
            },
        )

    def test_custody_returns_the_signature_normalized_digests_it_authenticated(self):
        normalized = {
            "amneziawg_packet_engine": _digest("normalized-awg"),
            "xray_vless_ws_transport": _digest("normalized-xray"),
        }
        awg = self.fixture.pinned_awg_provenance(normalized)
        self.fixture.add_provenance(normalized)
        with _fixture_awg_pins():
            release, pin, manifest = _make_signed_release(self.fixture.root / "normalized-case")
            winn = _release_bound_provenance(
                verifier.sha256_file(self.fixture.engines["winn_packet_engine"]), release, manifest
            )
            winn["wrappers"]["macosx"][NORMALIZED_FIELD] = _digest("normalized-winn")
            xray = self.fixture.authenticated_apple["xray"]
            encode = lambda value: json.dumps(value, sort_keys=True).encode("ascii")
            with mock.patch.object(verifier, "WINN_RELEASE_AUTHORITY", pin):
                with verifier.ReviewedWinnReleaseCustody(release) as custody:
                    result = custody.authenticate(encode(winn), encode(awg), encode(xray))
        self.assertEqual(
            result["engine_signature_normalized_sha256"],
            {
                "amneziawg_packet_engine": _digest("normalized-awg"),
                "xray_vless_ws_transport": _digest("normalized-xray"),
                "winn_packet_engine": _digest("normalized-winn"),
            },
        )

    def test_pinned_awg_provenance_mismatches_are_blocked(self):
        def changed(update):
            value = self.fixture.pinned_awg_provenance()
            update(value)
            return value

        def foreign_xray_transport(value):
            value["wrappers"]["macosx"]["xray_vless_ws_transport"]["sha256"] = _digest("other-xray")

        cases = (
            ("source commit", lambda v: v["source"].update(commit="9" * 40), "source does not match"),
            ("source go.mod", lambda v: v["source"].update(go_mod_sha256=_digest("x")), "source does not match"),
            ("source missing", lambda v: v.pop("source"), "source does not match"),
            ("go version", lambda v: v["go_toolchain"].update(version="1.26.0"), "go_toolchain does not match"),
            (
                "go archive",
                lambda v: v["go_toolchain"].update(darwin_arm64_archive_sha256=_digest("go")),
                "go_toolchain does not match",
            ),
            ("xray zip", lambda v: v["xray_replacement"].update(zip_sha256=_digest("z")), "xray_replacement does not match"),
            ("xray module", lambda v: v["xray_replacement"].update(source_module="evil/xray"), "xray_replacement does not match"),
            ("bridge digest", lambda v: v.update(bridge_provenance_sha256="not-hex"), "bridge_provenance_sha256"),
            ("bridge missing", lambda v: v.pop("bridge_provenance_sha256"), "bridge_provenance_sha256"),
            ("xray transport", foreign_xray_transport, "transport recorded by the pinned AWG"),
            (
                "awg engine digest",
                lambda v: v["wrappers"]["macosx"]["amneziawg_packet_engine"].update(sha256="0" * 63),
                "amneziawg_packet_engine provenance digest is malformed",
            ),
            (
                "awg engine bytes",
                lambda v: v["wrappers"]["macosx"]["amneziawg_packet_engine"].update(sha256=_digest("o")),
                "amneziawg_packet_engine bytes are not bound to their production provenance",
            ),
            (
                "awg engine normalized digest",
                lambda v: v["wrappers"]["macosx"]["amneziawg_packet_engine"].update(
                    signature_normalized_sha256="0" * 63
                ),
                "amneziawg_packet_engine signature-normalized provenance digest is malformed",
            ),
            (
                "xray transport normalized digest",
                lambda v: v["wrappers"]["macosx"]["xray_vless_ws_transport"].update(
                    signature_normalized_sha256=_digest("other-normalized")
                ),
                "transport recorded by the pinned AWG",
            ),
        )
        for label, update, expected in cases:
            with self.subTest(label=label):
                shutil.rmtree(self.fixture.root / "release-case", ignore_errors=True)
                with _fixture_awg_pins():
                    self.assertBlocked(lambda: self._release_case(awg=changed(update)), expected)

    def test_unpinned_go_toolchain_is_refused(self):
        pins = self.fixture.root / "toolchain-pins.json"
        _write_json(pins, {"tools": {"go": {"version": "1.27.1", "archive_sha256": {}}}})
        with _fixture_awg_pins(), mock.patch.object(verifier, "TOOLCHAIN_PINS", pins):
            self.assertBlocked(
                lambda: self._release_case(awg=self.fixture.pinned_awg_provenance()),
                "unpinned Go toolchain",
            )

    def test_awg_pins_mirror_the_bridge_producer(self):
        bridge = (verifier.ROOT / "tools/build_apple_wg_go_bridge.sh").read_text(encoding="utf-8")
        groups = {
            "source": verifier.REVIEWED_AWG_SOURCE_PINS,
            "xray_replacement": verifier.REVIEWED_AWG_XRAY_REPLACEMENT_PINS,
        }
        self.assertEqual(
            {(group, field) for group, pins in groups.items() for field in pins},
            set(BRIDGE_PIN_VARIABLES),
        )
        for (group, field), variable in BRIDGE_PIN_VARIABLES.items():
            with self.subTest(variable=variable):
                values = re.findall(r'(?m)^' + variable + r'="([^"$`]*)"$', bridge)
                self.assertEqual(len(values), 1, variable)
                self.assertEqual(groups[group][field], values[0])

    def test_winn_release_is_verified_over_the_held_bytes_only(self):
        # The custody hands the held driver the manifest bytes it holds. The
        # path-based verify_release, which would read manifest.json again
        # after the custody read it, is never used.
        original = verifier.ReviewedWinnReleaseCustody.__enter__

        def enter(custody):
            result = original(custody)

            def refuse(_arguments):
                raise AssertionError("path-based verify_release was called")

            custody.module.verify_release = refuse
            return result

        with mock.patch.object(verifier.ReviewedWinnReleaseCustody, "__enter__", enter), _unpinned_awg_pins():
            self.assertBlocked(lambda: self._release_case(), "unpinned AWG provenance")

    def test_winn_release_mismatches_are_blocked(self):
        def tamper_slice(release):
            path = release / "artifacts/datapath-archive-darwin-arm64/libwinn-datapath.a"
            path.write_bytes(path.read_bytes() + b"tamper")

        def drift_archive(value):
            value["archives"]["macosx_x86_64"]["sha256"] = _digest("other-archive")

        def foreign_manifest(value):
            value["release"]["manifest_sha256"] = _digest("other-manifest")

        def unsigned_record(value):
            value["release"]["signature_state"] = "unsigned-dev"

        def drift_go(value):
            value["release"]["go"]["version"] = "1.26.0"

        cases = (
            ("unsigned release", {"sign": False}, "Winn release signature"),
            ("untrusted key", {"pin_seed": bytes(range(40, 72))}, "did not verify"),
            ("tampered slice", {"mutate_release": tamper_slice}, "did not verify"),
            ("archive drift", {"mutate_provenance": drift_archive}, "archive binding drifted"),
            ("foreign manifest", {"mutate_provenance": foreign_manifest}, "not bound to the signed release"),
            ("unsigned record", {"mutate_provenance": unsigned_record}, "not bound to the signed release"),
            ("go drift", {"mutate_provenance": drift_go}, "does not match the signed manifest"),
        )
        for label, options, expected in cases:
            with self.subTest(label=label):
                shutil.rmtree(self.fixture.root / "release-case", ignore_errors=True)
                self.assertBlocked(lambda: self._release_case(**options), expected)

    def test_symlinked_engine_provenance_is_blocked_before_authentication(self):
        self.fixture.add_provenance()
        path = self.fixture.contents / "Resources/apple_winn_v3_engine_provenance.json"
        retained = path.with_name("retained-winn-provenance.json")
        os.replace(path, retained)
        path.symlink_to(retained.name)
        self.assertBlocked(
            lambda: verifier._verify_engine_contract_after_external_authentication(
                self.fixture.app,
                self.fixture.topology(),
                _engine_runner,
                self.fixture.authenticated_facts(),
            ),
            "symbolic path component",
        )

    def test_consistent_release_manifest_key_and_archive_substitutions_are_blocked(self):
        for label, mutate in (
            ("manifest", lambda value: value["release"].update(manifest_sha256=_digest("cross-manifest"))),
            ("signature-key", lambda value: value["release"].update(signature_public_key=_digest("cross-key"))),
            ("archive", lambda value: value["archives"]["macosx_arm64"].update(sha256=_digest("cross-archive"))),
        ):
            with self.subTest(label=label):
                self.fixture.add_provenance()
                value = _winn_release_provenance(
                    verifier.sha256_file(self.fixture.engines["winn_packet_engine"])
                )
                mutate(value)
                self.fixture.replace_winn_provenance(value)
                self.assertBlocked(
                    lambda: verifier._verify_engine_contract_after_external_authentication(
                        self.fixture.app,
                        self.fixture.topology(),
                        _engine_runner,
                        self.fixture.authenticated_facts(),
                    ),
                    "externally authorized",
                )

    def test_engine_replace_and_restore_during_inspection_is_blocked(self):
        self.fixture.add_provenance()
        target = self.fixture.engines["winn_packet_engine"]
        backup = target.with_name(target.name + ".held")
        attacker = target.with_name(target.name + ".attacker")
        _write(attacker, _fat_macho() + b"attacker", 0o755)
        swapped = False

        def runner(arguments, timeout):
            nonlocal swapped
            if (
                not swapped
                and arguments[0] == "/usr/bin/nm"
                and "winsvpn-held-engines-" in arguments[-1]
            ):
                swapped = True
                os.replace(target, backup)
                os.replace(attacker, target)
                os.replace(target, attacker)
                os.replace(backup, target)
            return _engine_runner(arguments, timeout)

        self.assertBlocked(
            lambda: verifier._verify_engine_contract_after_external_authentication(
                self.fixture.app, self.fixture.topology(), runner, self.fixture.authenticated_facts()
            ),
            "ancestor changed",
        )

    def test_engine_parent_swap_and_restore_during_inspection_is_blocked(self):
        self.fixture.add_provenance()
        target = self.fixture.engines["winn_packet_engine"]
        parent = target.parent
        backup = parent.with_name(parent.name + ".held")
        attacker = parent.with_name(parent.name + ".attacker")
        _write(attacker / target.name, _fat_macho() + b"attacker", 0o755)
        swapped = False

        def runner(arguments, timeout):
            nonlocal swapped
            if (
                not swapped
                and arguments[0] == "/usr/bin/nm"
                and "winsvpn-held-engines-" in arguments[-1]
            ):
                swapped = True
                os.replace(parent, backup)
                os.replace(attacker, parent)
                os.replace(parent, attacker)
                os.replace(backup, parent)
            return _engine_runner(arguments, timeout)

        self.assertBlocked(
            lambda: verifier._verify_engine_contract_after_external_authentication(
                self.fixture.app, self.fixture.topology(), runner, self.fixture.authenticated_facts()
            ),
            "ancestor changed",
        )

    def test_legacy_winn_schema_one_is_blocked(self):
        self.fixture.add_provenance()
        self.fixture.replace_winn_provenance(
            {
                "schema_version": 1,
                "generation": "v3",
                "component": "winn-apple-engine-wrappers",
                "wrappers": {"macosx": {"sha256": verifier.sha256_file(self.fixture.engines["winn_packet_engine"])}},
            }
        )
        self.assertBlocked(
            lambda: verifier._verify_engine_contract_after_external_authentication(
                self.fixture.app, self.fixture.topology(), _engine_runner, self.fixture.authenticated_facts()
            ),
            "required field",
        )

    def test_winn_schema_four_missing_thin_and_extra_slice_closures_are_blocked(self):
        cases = {}
        missing = _winn_release_provenance(verifier.sha256_file(self.fixture.engines["winn_packet_engine"]))
        del missing["wrappers"]["macosx"]["slices"]["x86_64"]
        cases["missing"] = missing
        thin = _winn_release_provenance(verifier.sha256_file(self.fixture.engines["winn_packet_engine"]))
        thin["wrappers"]["macosx"]["architectures"] = ["arm64"]
        cases["thin"] = thin
        extra = _winn_release_provenance(verifier.sha256_file(self.fixture.engines["winn_packet_engine"]))
        extra["wrappers"]["iphoneos"]["slices"]["x86_64"] = _winn_slice(
            "x86_64", "IOS", "13.0", "66666666-6666-6666-6666-666666666666"
        )
        cases["extra"] = extra
        for label, provenance in cases.items():
            with self.subTest(label=label):
                self.fixture.add_provenance()
                self.fixture.replace_winn_provenance(provenance)
                self.assertBlocked(
                    lambda: verifier._verify_engine_contract_after_external_authentication(
                        self.fixture.app, self.fixture.topology(), _engine_runner, self.fixture.authenticated_facts()
                    ),
                    "Winn v3 provenance",
                )

    def test_unbound_xray_provenance_is_blocked(self):
        self.fixture.add_provenance()
        path = self.fixture.contents / "Resources/apple_xray_vless_ws_engine_provenance.json"
        value = json.loads(path.read_text(encoding="ascii"))
        value["fixture_drift"] = True
        _write_json(path, value)
        self.assertBlocked(
            lambda: verifier._verify_engine_contract_after_external_authentication(
                self.fixture.app, self.fixture.topology(), _engine_runner, self.fixture.authenticated_facts()
            ),
            "externally authorized",
        )

    def test_missing_winn_v3_primary_runtime_marker_is_blocked(self):
        self.fixture.add_provenance()
        tunnel = self.fixture.tunnel / "Contents/MacOS/PacketTunnel"
        _write(tunnel, _fat_macho() + b"winn-datapath/1+winn3", 0o755)
        self.assertBlocked(
            lambda: verifier._verify_engine_contract_after_external_authentication(
                self.fixture.app, self.fixture.topology(), _engine_runner, self.fixture.authenticated_facts()
            ),
            "primary runtime markers",
        )

    def test_changed_engine_bytes_are_blocked(self):
        self.fixture.add_provenance()
        path = self.fixture.engines["winn_packet_engine"]
        _write(path, path.read_bytes() + b"changed", 0o755)
        self.assertBlocked(
            lambda: verifier._verify_engine_contract_after_external_authentication(
                self.fixture.app, self.fixture.topology(), _engine_runner, self.fixture.authenticated_facts()
            ),
            "provenance",
        )

    def test_missing_per_architecture_engine_symbol_is_blocked(self):
        self.fixture.add_provenance()
        def runner(arguments, _timeout):
            if arguments[0] == "/usr/bin/nm":
                return _completed("")
            return _engine_runner(arguments, _timeout)
        self.assertBlocked(
            lambda: verifier._verify_engine_contract_after_external_authentication(
                self.fixture.app, self.fixture.topology(), runner, self.fixture.authenticated_facts()
            ),
            "missing",
        )

    def test_xray_without_awg_chain_is_blocked(self):
        self.fixture.add_provenance()
        def runner(arguments, _timeout):
            if arguments[0] == "/usr/bin/otool":
                return _completed("\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n")
            return _engine_runner(arguments, _timeout)
        self.assertBlocked(
            lambda: verifier._verify_engine_contract_after_external_authentication(
                self.fixture.app, self.fixture.topology(), runner, self.fixture.authenticated_facts()
            ),
            "not chained",
        )

    def _install_real_engines(self, fixture=None):
        """Install one real linker-signed universal dylib as every engine.

        Returns the signature-normalized digest the producers record for it.
        """
        fixture = fixture or self.fixture
        build = fixture.root / "engine-build"
        build.mkdir()
        built = _compile_universal_engine(build / "engine.dylib")
        for path in fixture.engines.values():
            _write(path, built.read_bytes(), 0o755)
        return _normalized_with_verifier(built, fixture.root / "engine-normalize")

    def test_custody_normalized_digests_must_match_the_packaged_records(self):
        self.fixture.add_provenance(
            {component: _digest("normalized-" + component) for component in self.fixture.engines}
        )

        def facts(value):
            class AlteredNormalizedFacts(FixtureAuthenticatedFacts):
                def authenticate(self, payload, awg_payload, xray_payload):
                    result = super().authenticate(payload, awg_payload, xray_payload)
                    result["engine_signature_normalized_sha256"]["winn_packet_engine"] = value
                    return result

            return AlteredNormalizedFacts(self.fixture.authenticated_apple)

        for label, value, expected in (
            ("foreign", _digest("foreign-normalized"), "not bound to external authenticated custody"),
            ("absent", None, "not bound to external authenticated custody"),
            ("malformed", "0" * 63, "signature-normalized digest closure is malformed"),
        ):
            with self.subTest(label=label):
                self.assertBlocked(
                    lambda: verifier._verify_engine_contract_after_external_authentication(
                        self.fixture.app, self.fixture.topology(), _engine_runner, facts(value)
                    ),
                    expected,
                )

    @unittest.skipUnless(DARWIN, "real codesign and clang are Darwin tools")
    def test_resigned_engines_bind_through_the_signed_release_custody(self):
        # Staging and Xcode export re-sign the frameworks after provenance was
        # written. AWG and Xray are re-signed here, Winn keeps its raw bytes.
        normalized_value = self._install_real_engines()
        normalized = {
            "amneziawg_packet_engine": normalized_value,
            "xray_vless_ws_transport": normalized_value,
        }
        awg = self.fixture.pinned_awg_provenance(normalized)
        raw = {
            component: verifier.sha256_file(path)
            for component, path in self.fixture.engines.items()
        }

        def resign():
            for component in normalized:
                _codesign_ad_hoc(self.fixture.engines[component], "--options", "runtime")

        with _fixture_awg_pins():
            bindings = self._release_case(
                awg=awg,
                normalized=normalized,
                before_verify=resign,
                runner=_real_codesign_engine_runner,
            )
        for component, path in self.fixture.engines.items():
            self.assertEqual(bindings[component]["sha256"], verifier.sha256_file(path))
            self.assertEqual(bindings[component][NORMALIZED_FIELD], normalized_value)
        for component in normalized:
            self.assertNotEqual(bindings[component]["sha256"], raw[component])
        self.assertEqual(bindings["winn_packet_engine"]["sha256"], raw["winn_packet_engine"])

    @unittest.skipUnless(DARWIN, "real codesign and clang are Darwin tools")
    def test_resigned_engine_with_matching_normalized_digest_is_bound(self):
        normalized_value = self._install_real_engines()
        self.fixture.add_provenance(
            {component: normalized_value for component in self.fixture.engines}
        )
        raw = verifier.sha256_file(self.fixture.engines["winn_packet_engine"])
        for path in self.fixture.engines.values():
            _codesign_ad_hoc(
                path, "--options", "runtime", "--identifier", "org.winsvpn.engine.resigned"
            )
        bindings = verifier._verify_engine_contract_after_external_authentication(
            self.fixture.app,
            self.fixture.topology(),
            _real_codesign_engine_runner,
            self.fixture.authenticated_facts(),
        )
        self.assertEqual(set(bindings), set(verifier.ENGINE_FRAMEWORKS))
        for component, path in self.fixture.engines.items():
            self.assertNotEqual(bindings[component]["sha256"], raw)
            self.assertEqual(bindings[component]["sha256"], verifier.sha256_file(path))
            self.assertEqual(bindings[component][NORMALIZED_FIELD], normalized_value)

    @unittest.skipUnless(DARWIN, "real codesign and clang are Darwin tools")
    def test_resigned_engine_without_a_matching_normalized_digest_is_blocked(self):
        def changed_code_byte(path):
            _flip_text_byte(path)
            _codesign_ad_hoc(path)

        def changed_slice_set(path):
            thin = path.with_name(path.name + ".thin")
            _tool(["/usr/bin/lipo", str(path), "-thin", "arm64", "-output", str(thin)])
            os.replace(thin, path)
            _codesign_ad_hoc(path)

        def resigned(path):
            _codesign_ad_hoc(path, "--options", "runtime")

        for label, mutate, recorded in (
            ("changed code byte", changed_code_byte, True),
            ("changed slice set", changed_slice_set, True),
            ("record without the normalized field", resigned, False),
        ):
            with self.subTest(label=label):
                fixture = ArtifactFixture(
                    pathlib.Path(tempfile.mkdtemp(prefix="normalized-", dir=self.fixture.root))
                )
                normalized_value = self._install_real_engines(fixture)
                fixture.add_provenance(
                    {component: normalized_value for component in fixture.engines}
                    if recorded
                    else None
                )
                mutate(fixture.engines["winn_packet_engine"])
                self.assertBlocked(
                    lambda: verifier._verify_engine_contract_after_external_authentication(
                        fixture.app,
                        fixture.topology(),
                        _real_codesign_engine_runner,
                        fixture.authenticated_facts(),
                    ),
                    "winn_packet_engine bytes are not bound to their production provenance",
                )

    def test_development_profile_is_blocked(self):
        profile = self.fixture.contents / "embedded.provisionprofile"
        value = {
            "TeamIdentifier": [verifier.TEAM_ID],
            "ProvisionsAllDevices": False,
            "Entitlements": {
                "com.apple.application-identifier": verifier.TEAM_ID + "." + verifier.HOST_BUNDLE_ID,
                "com.apple.developer.team-identifier": verifier.TEAM_ID,
                "get-task-allow": True,
            },
        }
        def runner(_arguments, _timeout):
            return _completed(plistlib.dumps(value).decode("utf-8"))
        self.assertBlocked(
            lambda: verifier.verify_provisioning_profile(profile, verifier.HOST_BUNDLE_ID, runner, "host"),
            "production-valid",
        )

    def test_failed_stapler_validation_is_blocked(self):
        def runner(arguments, _timeout):
            if arguments[0] == "/usr/bin/stapler":
                return _completed("", "ticket missing", 1)
            return _completed()
        self.assertBlocked(
            lambda: verifier.verify_staple_and_gatekeeper(self.fixture.app, "execute", runner),
            "staple validation failed",
        )

    def test_non_notarized_gatekeeper_source_is_blocked(self):
        def runner(arguments, _timeout):
            if arguments[0] == "/usr/bin/stapler":
                return _completed("The validate action worked!\n")
            return _completed("source=Developer ID\n")
        self.assertBlocked(
            lambda: verifier.verify_staple_and_gatekeeper(self.fixture.app, "execute", runner),
            "lacks notarized",
        )

    def test_symbol_receipt_must_bind_final_distribution(self):
        distribution = self.fixture.root / "release.dmg"
        _write(distribution, b"held-dmg")
        receipt = self.fixture.root / "symbols/receipt.json"
        _write_json(
            receipt,
            {
                "schema_version": 1,
                "contract": "winsvpn-apple-private-symbol-custody-v1",
                "platform": "macos",
                "app_version": "1.2.3",
                "build_number": "42",
                "created_at_utc": "2026-08-25T00:00:00Z",
                "private_symbols_not_packaged": True,
                "artifact": {"filename": "release.dmg", "size": 1, "sha256": "0" * 64},
                "flutter_symbols": [],
                "xcarchive_dsyms": [],
            },
        )
        self.assertBlocked(
            lambda: verifier.verify_symbol_receipt(
                receipt, distribution, "1.2.3", "42", self.fixture.topology(), _engine_runner
            ),
            "final distribution bytes",
        )

    def test_symbol_receipt_held_inventory_passes(self):
        distribution, receipt, topology = self.symbol_receipt_fixture()
        result = verifier.verify_symbol_receipt(
            receipt, distribution, "1.2.3", "42", topology, _uuid_runner
        )
        self.assertEqual(result["artifact_sha256"], verifier.sha256_file(distribution))
        self.assertEqual(result["uuid_count"], 2 * len(topology["macho_files"]))

    def test_symbol_receipt_insertion_at_enumeration_boundary_is_blocked(self):
        distribution, receipt, topology = self.symbol_receipt_fixture()
        late_symbol = receipt.parent / "flutter/late.symbols"
        original_listdir = os.listdir
        triggered = False

        def hostile_listdir(descriptor):
            nonlocal triggered
            names = original_listdir(descriptor)
            if not triggered and "app.macos-arm64.symbols" in names:
                _write(late_symbol, b"late-symbol")
                triggered = True
            return names

        with mock.patch.object(os, "listdir", side_effect=hostile_listdir):
            self.assertBlocked(
                lambda: verifier.verify_symbol_receipt(
                    receipt, distribution, "1.2.3", "42", topology, _uuid_runner
                ),
                "inventory",
            )
        self.assertTrue(triggered)

    def test_symbol_receipt_owner_blocked_exit_still_revalidates_custody(self):
        distribution, receipt, topology = self.symbol_receipt_fixture()
        mutated = False

        def runner(arguments, _timeout):
            nonlocal mutated
            if arguments[0] != "/usr/bin/dwarfdump":
                return _completed()
            if "winsvpn-held-dsyms-" not in arguments[-1]:
                return _uuid_runner(arguments, _timeout)
            if not mutated:
                mutated = True
                snapshot = pathlib.Path(arguments[-1])
                original = snapshot.read_bytes()
                snapshot.chmod(0o600)
                with snapshot.open("r+b", buffering=0) as handle:
                    handle.write(b"H" * len(original))
                    os.fsync(handle.fileno())
                    handle.seek(0)
                    handle.write(original)
                    os.fsync(handle.fileno())
                snapshot.chmod(0o400)
            return _completed("", "OWNER-BLOCKED: private symbol authority unavailable", 5)

        with self.assertRaises(verifier.VerificationError) as context:
            verifier.verify_symbol_receipt(receipt, distribution, "1.2.3", "42", topology, runner)
        message = str(context.exception)
        self.assertIn("post-process custody failure", message)
        self.assertIn("OWNER-BLOCKED: private symbol authority unavailable", message)
        self.assertTrue(mutated)

    def test_symbol_receipt_owner_blocked_exit_remains_fail_closed(self):
        distribution, receipt, topology = self.symbol_receipt_fixture()

        def runner(arguments, _timeout):
            if arguments[0] == "/usr/bin/dwarfdump":
                return _completed("", "OWNER-BLOCKED: private symbol authority unavailable", 5)
            return _completed()

        self.assertBlocked(
            lambda: verifier.verify_symbol_receipt(
                receipt, distribution, "1.2.3", "42", topology, runner
            ),
            "OWNER-BLOCKED: private symbol authority unavailable",
        )

    def test_obfuscation_receipt_must_bind_final_distribution(self):
        distribution = self.fixture.root / "release.dmg"
        _write(distribution, b"held-dmg")
        receipt = self.fixture.root / "obfuscation/receipt.json"
        _write_json(
            receipt,
            {
                "schema_version": 2,
                "contract": "winsvpn-release-obfuscation-and-secret-free-v2",
                "contract_sha256": verifier.sha256_file(
                    verifier.OBFUSCATION_SOURCE_FILES["release_obfuscation_contract"]
                ),
                "platform": "macos",
                "app_version": "1.2.3",
                "build_number": "42",
                "created_at_utc": "2026-08-25T00:00:00Z",
                "private_symbols_not_packaged": True,
                "verification": {},
                "artifacts": [],
                "symbols": [],
            },
        )
        self.assertBlocked(
            lambda: verifier.verify_obfuscation_receipt(receipt, distribution, "1.2.3", "42")
        )

    def test_obfuscation_external_verifier_receives_retained_snapshots(self):
        distribution, receipt = self.obfuscation_fixture()

        def runner(arguments, _timeout):
            self.assert_snapshot_arguments(arguments, distribution, receipt)
            return _completed()

        result = verifier.verify_obfuscation_receipt(
            receipt, distribution, "1.2.3", "42", runner
        )
        self.assertEqual(result["artifact_sha256"], verifier.sha256_file(distribution))
        self.assertEqual(
            result["source_closure"]["release_secret_scan_policy.py"],
            verifier.sha256_file(
                verifier.OBFUSCATION_SOURCE_FILES["release_secret_scan_policy"]
            ),
        )
        self.assertRegex(result["source_closure_sha256"], r"\A[0-9a-f]{64}\Z")

    def test_obfuscation_missing_secret_policy_source_is_blocked(self):
        with self.mirrored_obfuscation_sources() as sources:
            distribution, receipt = self.obfuscation_fixture()
            sources["release_secret_scan_policy"].unlink()
            self.assertBlocked(
                lambda: verifier.verify_obfuscation_receipt(
                    receipt, distribution, "1.2.3", "42", lambda _arguments, _timeout: _completed()
                ),
                "release_secret_scan_policy",
            )

    def test_obfuscation_secret_policy_in_place_mutation_restore_is_blocked(self):
        with self.mirrored_obfuscation_sources() as sources:
            distribution, receipt = self.obfuscation_fixture()
            policy = sources["release_secret_scan_policy"]
            original = policy.read_bytes()
            hostile = b"H" * len(original)

            def runner(_arguments, _timeout):
                with policy.open("r+b", buffering=0) as handle:
                    handle.write(hostile)
                    os.fsync(handle.fileno())
                    handle.seek(0)
                    handle.write(original)
                    os.fsync(handle.fileno())
                return _completed()

            self.assertBlocked(
                lambda: verifier.verify_obfuscation_receipt(
                    receipt, distribution, "1.2.3", "42", runner
                ),
                "post-process custody failure",
            )

    def test_obfuscation_secret_policy_path_substitution_restore_is_blocked(self):
        with self.mirrored_obfuscation_sources() as sources:
            distribution, receipt = self.obfuscation_fixture()
            policy = sources["release_secret_scan_policy"]
            held = policy.with_name("held-policy.py")
            substitute = policy.with_name("substitute-policy.py")
            _write(substitute, b"hostile-policy\n", 0o600)

            def runner(_arguments, _timeout):
                policy.rename(held)
                substitute.rename(policy)
                policy.rename(substitute)
                held.rename(policy)
                return _completed()

            self.assertBlocked(
                lambda: verifier.verify_obfuscation_receipt(
                    receipt, distribution, "1.2.3", "42", runner
                ),
                "post-process custody failure",
            )

    def test_obfuscation_secret_policy_same_byte_swap_restore_is_blocked(self):
        with self.mirrored_obfuscation_sources() as sources:
            distribution, receipt = self.obfuscation_fixture()
            policy = sources["release_secret_scan_policy"]
            held = policy.with_name("held-policy.py")
            substitute = policy.with_name("same-policy.py")
            _write(substitute, policy.read_bytes(), 0o600)

            def runner(_arguments, _timeout):
                policy.rename(held)
                substitute.rename(policy)
                policy.rename(substitute)
                held.rename(policy)
                return _completed()

            self.assertBlocked(
                lambda: verifier.verify_obfuscation_receipt(
                    receipt, distribution, "1.2.3", "42", runner
                ),
                "post-process custody failure",
            )

    def test_obfuscation_private_policy_snapshot_mutation_restore_is_blocked(self):
        distribution, receipt = self.obfuscation_fixture()

        def runner(arguments, _timeout):
            namespace = self.verifier_namespace_from_arguments(arguments)
            policy = namespace / "release_secret_scan_policy.py"
            original = policy.read_bytes()
            policy.chmod(0o600)
            with policy.open("r+b", buffering=0) as handle:
                handle.write(b"H" * len(original))
                os.fsync(handle.fileno())
                handle.seek(0)
                handle.write(original)
                os.fsync(handle.fileno())
            policy.chmod(0o400)
            return _completed()

        self.assertBlocked(
            lambda: verifier.verify_obfuscation_receipt(
                receipt, distribution, "1.2.3", "42", runner
            ),
            "post-process custody failure",
        )

    def test_obfuscation_policy_source_and_snapshot_revalidate_on_all_failure_paths(self):
        outcomes = ("nonzero", "timeout", "exception")
        locations = ("source", "snapshot")
        for location in locations:
            for outcome in outcomes:
                with self.subTest(location=location, outcome=outcome):
                    with self.mirrored_obfuscation_sources() as sources:
                        distribution, receipt = self.obfuscation_fixture()

                        def runner(arguments, timeout):
                            path = sources["release_secret_scan_policy"]
                            if location == "snapshot":
                                path = (
                                    self.verifier_namespace_from_arguments(arguments)
                                    / "release_secret_scan_policy.py"
                                )
                            original = path.read_bytes()
                            path.chmod(0o600)
                            with path.open("r+b", buffering=0) as handle:
                                handle.write(b"H" * len(original))
                                os.fsync(handle.fileno())
                                handle.seek(0)
                                handle.write(original)
                                os.fsync(handle.fileno())
                            path.chmod(0o400 if location == "snapshot" else 0o600)
                            if outcome == "nonzero":
                                return _completed("", "owner authorization missing", 7)
                            if outcome == "timeout":
                                raise subprocess.TimeoutExpired(arguments, timeout)
                            raise RuntimeError("policy runner exploded")

                        with self.assertRaises(verifier.VerificationError) as context:
                            verifier.verify_obfuscation_receipt(
                                receipt, distribution, "1.2.3", "42", runner
                            )
                        message = str(context.exception)
                        self.assertIn("post-process custody failure", message)
                        self.assertIn("canonical verifier failure context", message)

    def test_obfuscation_adapter_rejects_sys_modules_poisoning(self):
        distribution, receipt = self.obfuscation_fixture()

        def runner(arguments, timeout):
            poisoned = list(arguments)
            command_index = poisoned.index("-c")
            poisoned[command_index + 1] = (
                "import sys,types\n"
                "sys.modules['release_secret_scan_policy']="
                "types.ModuleType('release_secret_scan_policy')\n"
                + poisoned[command_index + 1]
            )
            return subprocess.run(
                poisoned, capture_output=True, text=True, timeout=timeout, check=False
            )

        self.assertBlocked(
            lambda: verifier.verify_obfuscation_receipt(
                receipt, distribution, "1.2.3", "42", runner
            ),
            "module namespace was preloaded",
        )

    def test_obfuscation_adapter_ignores_sys_path_poisoning(self):
        version, build = verifier._parse_release_identity()
        distribution, receipt = self.obfuscation_fixture(version, build)
        poison = self.fixture.root / "python-path-poison"
        poison.mkdir(mode=0o700)
        marker = poison / "poison-loaded"
        payload = (
            "from pathlib import Path\n"
            + "Path(" + repr(str(marker)) + ").write_text('loaded', encoding='ascii')\n"
        ).encode("ascii")
        _write(poison / "sitecustomize.py", payload)
        _write(poison / "release_secret_scan_policy.py", payload)

        def runner(arguments, timeout):
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(poison)
            return subprocess.run(
                arguments,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=environment,
            )

        self.assertBlocked(
            lambda: verifier.verify_obfuscation_receipt(
                receipt, distribution, version, build, runner
            ),
            "secret inventory",
        )
        self.assertFalse(marker.exists())

    def test_obfuscation_inventory_insertion_at_enumeration_boundary_is_blocked(self):
        distribution, receipt = self.obfuscation_fixture()
        late_symbol = receipt.parent / "flutter/late.symbols"
        original_listdir = os.listdir
        triggered = False

        def hostile_listdir(descriptor):
            nonlocal triggered
            names = original_listdir(descriptor)
            if not triggered and "app.macos-arm64.symbols" in names:
                _write(late_symbol, b"late-symbol")
                triggered = True
            return names

        with mock.patch.object(os, "listdir", side_effect=hostile_listdir):
            self.assertBlocked(
                lambda: verifier.verify_obfuscation_receipt(
                    receipt, distribution, "1.2.3", "42", lambda _arguments, _timeout: _completed()
                ),
                "inventory",
            )
        self.assertTrue(triggered)

    def test_obfuscation_inventory_removal_at_enumeration_boundary_is_blocked(self):
        distribution, receipt = self.obfuscation_fixture()
        symbol = next(receipt.parent.rglob("*.symbols"))
        original = symbol.read_bytes()
        original_listdir = os.listdir
        triggered = False

        def hostile_listdir(descriptor):
            nonlocal triggered
            names = original_listdir(descriptor)
            if not triggered and symbol.name in names:
                symbol.unlink()
                triggered = True
            return names

        try:
            with mock.patch.object(os, "listdir", side_effect=hostile_listdir):
                self.assertBlocked(
                    lambda: verifier.verify_obfuscation_receipt(
                        receipt, distribution, "1.2.3", "42", lambda _arguments, _timeout: _completed()
                    ),
                    "inventory",
                )
        finally:
            if not symbol.exists():
                _write(symbol, original)
        self.assertTrue(triggered)

    def test_obfuscation_inventory_swap_at_enumeration_boundary_is_blocked(self):
        distribution, receipt = self.obfuscation_fixture()
        symbol = next(receipt.parent.rglob("*.symbols"))
        held = self.fixture.root / "held-original.symbols"
        substitute = self.fixture.root / "same-bytes-substitute.symbols"
        _write(substitute, symbol.read_bytes())
        original_listdir = os.listdir
        triggered = False

        def hostile_listdir(descriptor):
            nonlocal triggered
            names = original_listdir(descriptor)
            if not triggered and symbol.name in names:
                symbol.rename(held)
                substitute.rename(symbol)
                triggered = True
            return names

        try:
            with mock.patch.object(os, "listdir", side_effect=hostile_listdir):
                self.assertBlocked(
                    lambda: verifier.verify_obfuscation_receipt(
                        receipt, distribution, "1.2.3", "42", lambda _arguments, _timeout: _completed()
                    ),
                    "inventory",
                )
        finally:
            if held.exists():
                if symbol.exists():
                    symbol.rename(substitute)
                held.rename(symbol)
        self.assertTrue(triggered)

    def test_obfuscation_success_path_always_revalidates_post_process_custody(self):
        distribution, receipt = self.obfuscation_fixture()

        def runner(arguments, _timeout):
            self.mutate_private_symbol_snapshot_and_restore(arguments)
            return _completed()

        self.assertBlocked(
            lambda: verifier.verify_obfuscation_receipt(
                receipt, distribution, "1.2.3", "42", runner
            ),
            "post-process custody failure",
        )

    def test_obfuscation_nonzero_path_prioritizes_post_process_custody(self):
        distribution, receipt = self.obfuscation_fixture()

        def runner(arguments, _timeout):
            self.mutate_private_symbol_snapshot_and_restore(arguments)
            return _completed("", "owner authorization missing", 7)

        with self.assertRaises(verifier.VerificationError) as context:
            verifier.verify_obfuscation_receipt(receipt, distribution, "1.2.3", "42", runner)
        message = str(context.exception)
        self.assertIn("post-process custody failure", message)
        self.assertIn("canonical verifier failure context", message)
        self.assertIn("owner authorization missing", message)

    def test_obfuscation_timeout_path_prioritizes_post_process_custody(self):
        distribution, receipt = self.obfuscation_fixture()

        def runner(arguments, timeout):
            self.mutate_private_symbol_snapshot_and_restore(arguments)
            raise subprocess.TimeoutExpired(arguments, timeout)

        with self.assertRaises(verifier.VerificationError) as context:
            verifier.verify_obfuscation_receipt(receipt, distribution, "1.2.3", "42", runner)
        message = str(context.exception)
        self.assertIn("post-process custody failure", message)
        self.assertIn("TimeoutExpired", message)

    def test_obfuscation_runner_exception_path_prioritizes_post_process_custody(self):
        distribution, receipt = self.obfuscation_fixture()

        def runner(arguments, _timeout):
            self.mutate_private_symbol_snapshot_and_restore(arguments)
            raise RuntimeError("runner exploded")

        with self.assertRaises(verifier.VerificationError) as context:
            verifier.verify_obfuscation_receipt(receipt, distribution, "1.2.3", "42", runner)
        message = str(context.exception)
        self.assertIn("post-process custody failure", message)
        self.assertIn("RuntimeError: runner exploded", message)

    def test_obfuscation_real_canonical_verifier_reaches_external_custody(self):
        version, build = verifier._parse_release_identity()
        distribution, receipt = self.obfuscation_fixture(version, build)
        self.assertBlocked(
            lambda: verifier.verify_obfuscation_receipt(
                receipt, distribution, version, build
            ),
            "secret inventory",
        )

    def test_obfuscation_artifact_parent_swap_restore_is_blocked(self):
        distribution, receipt = self.obfuscation_fixture()
        parent = distribution.parent
        held_parent = self.fixture.root / "distribution-held"
        substitute_parent = self.fixture.root / "distribution-substitute"
        shutil.copytree(parent, substitute_parent)
        artifact_bytes = distribution.read_bytes()
        receipt_bytes = receipt.read_bytes()
        _write(substitute_parent / distribution.name, b"evil-dmg")

        def runner(arguments, _timeout):
            parent.rename(held_parent)
            substitute_parent.rename(parent)
            self.assert_snapshot_arguments(
                arguments, distribution, receipt, artifact_bytes, receipt_bytes
            )
            parent.rename(substitute_parent)
            held_parent.rename(parent)
            return _completed()

        self.assertBlocked(
            lambda: verifier.verify_obfuscation_receipt(
                receipt, distribution, "1.2.3", "42", runner
            ),
            "ancestor changed",
        )

    def test_obfuscation_receipt_parent_swap_restore_is_blocked(self):
        distribution, receipt = self.obfuscation_fixture()
        parent = receipt.parent
        held_parent = self.fixture.root / "obfuscation-held"
        substitute_parent = self.fixture.root / "obfuscation-substitute"
        shutil.copytree(parent, substitute_parent)
        artifact_bytes = distribution.read_bytes()
        receipt_bytes = receipt.read_bytes()
        _write(substitute_parent / receipt.name, b"{}\n")

        def runner(arguments, _timeout):
            parent.rename(held_parent)
            substitute_parent.rename(parent)
            self.assert_snapshot_arguments(
                arguments, distribution, receipt, artifact_bytes, receipt_bytes
            )
            parent.rename(substitute_parent)
            held_parent.rename(parent)
            return _completed()

        self.assertBlocked(
            lambda: verifier.verify_obfuscation_receipt(
                receipt, distribution, "1.2.3", "42", runner
            ),
            "ancestor changed",
        )

    def test_obfuscation_receipt_leaf_swap_restore_is_blocked(self):
        distribution, receipt = self.obfuscation_fixture()
        held_receipt = receipt.parent / "held-receipt.json"
        substitute_receipt = receipt.parent / "substitute-receipt.json"
        artifact_bytes = distribution.read_bytes()
        receipt_bytes = receipt.read_bytes()
        _write(substitute_receipt, b"{}\n")

        def runner(arguments, _timeout):
            receipt.rename(held_receipt)
            substitute_receipt.rename(receipt)
            self.assert_snapshot_arguments(
                arguments, distribution, receipt, artifact_bytes, receipt_bytes
            )
            receipt.rename(substitute_receipt)
            held_receipt.rename(receipt)
            return _completed()

        self.assertBlocked(
            lambda: verifier.verify_obfuscation_receipt(
                receipt, distribution, "1.2.3", "42", runner
            ),
            "ancestor changed",
        )

    def test_obfuscation_artifact_in_place_mutation_restore_is_blocked(self):
        distribution, receipt = self.obfuscation_fixture()
        original = distribution.read_bytes()
        receipt_bytes = receipt.read_bytes()

        def runner(arguments, _timeout):
            with distribution.open("r+b", buffering=0) as handle:
                handle.write(b"evil-dmg")
                os.fsync(handle.fileno())
                self.assert_snapshot_arguments(
                    arguments, distribution, receipt, original, receipt_bytes
                )
                handle.seek(0)
                handle.write(original)
                os.fsync(handle.fileno())
            return _completed()

        self.assertBlocked(
            lambda: verifier.verify_obfuscation_receipt(
                receipt, distribution, "1.2.3", "42", runner
            ),
            "rejected",
        )

    def test_obfuscation_symbol_leaf_swap_restore_is_blocked(self):
        distribution, receipt = self.obfuscation_fixture()
        symbol = next(receipt.parent.rglob("*.symbols"))
        held_symbol = symbol.parent / "held.symbols"
        substitute_symbol = symbol.parent / "substitute.bin"
        artifact_bytes = distribution.read_bytes()
        receipt_bytes = receipt.read_bytes()
        symbol_bytes = {symbol.relative_to(receipt.parent).as_posix(): symbol.read_bytes()}
        _write(substitute_symbol, b"hostile-symbols")

        def runner(arguments, _timeout):
            symbol.rename(held_symbol)
            substitute_symbol.rename(symbol)
            self.assert_snapshot_arguments(
                arguments, distribution, receipt, artifact_bytes, receipt_bytes, symbol_bytes
            )
            symbol.rename(substitute_symbol)
            held_symbol.rename(symbol)
            return _completed()

        self.assertBlocked(
            lambda: verifier.verify_obfuscation_receipt(
                receipt, distribution, "1.2.3", "42", runner
            ),
            "ancestor changed",
        )

    def test_obfuscation_symbol_parent_swap_restore_is_blocked(self):
        distribution, receipt = self.obfuscation_fixture()
        symbol = next(receipt.parent.rglob("*.symbols"))
        parent = symbol.parent
        held_parent = receipt.parent / "flutter-held"
        substitute_parent = self.fixture.root / "flutter-substitute"
        shutil.copytree(parent, substitute_parent)
        artifact_bytes = distribution.read_bytes()
        receipt_bytes = receipt.read_bytes()
        symbol_bytes = {symbol.relative_to(receipt.parent).as_posix(): symbol.read_bytes()}
        _write(substitute_parent / symbol.name, b"hostile-symbols")

        def runner(arguments, _timeout):
            parent.rename(held_parent)
            substitute_parent.rename(parent)
            self.assert_snapshot_arguments(
                arguments, distribution, receipt, artifact_bytes, receipt_bytes, symbol_bytes
            )
            parent.rename(substitute_parent)
            held_parent.rename(parent)
            return _completed()

        self.assertBlocked(
            lambda: verifier.verify_obfuscation_receipt(
                receipt, distribution, "1.2.3", "42", runner
            ),
            "ancestor changed",
        )

    def test_obfuscation_symbol_in_place_mutation_restore_is_blocked(self):
        distribution, receipt = self.obfuscation_fixture()
        symbol = next(receipt.parent.rglob("*.symbols"))
        original = symbol.read_bytes()
        artifact_bytes = distribution.read_bytes()
        receipt_bytes = receipt.read_bytes()
        symbol_bytes = {symbol.relative_to(receipt.parent).as_posix(): original}

        def runner(arguments, _timeout):
            with symbol.open("r+b", buffering=0) as handle:
                handle.write(b"hostile-symbols")
                os.fsync(handle.fileno())
                self.assert_snapshot_arguments(
                    arguments, distribution, receipt, artifact_bytes, receipt_bytes, symbol_bytes
                )
                handle.seek(0)
                handle.write(original)
                os.fsync(handle.fileno())
            return _completed()

        self.assertBlocked(
            lambda: verifier.verify_obfuscation_receipt(
                receipt, distribution, "1.2.3", "42", runner
            ),
            "rejected",
        )

    def test_release_source_settings_are_fail_closed(self):
        project = (verifier.ROOT / "macos/Runner.xcodeproj/project.pbxproj").read_text(encoding="utf-8")
        runner_release = project.split("33CC10FD2044A3C60003C045 /* Release */ = {", 1)[1].split("\n\t\t};", 1)[0]
        tunnel_release = project.split("B10000000000000000000010 /* Release */ = {", 1)[1].split("\n\t\t};", 1)[0]
        for block in (runner_release, tunnel_release):
            self.assertIn("AD_HOC_CODE_SIGNING_ALLOWED = NO;", block)
            self.assertIn('CODE_SIGN_IDENTITY = "$(WINS_APPLE_CODE_SIGN_IDENTITY)";', block)
            self.assertIn("CODE_SIGN_INJECT_BASE_ENTITLEMENTS = NO;", block)
            self.assertIn("ENABLE_CODE_COVERAGE = NO;", block)
            self.assertIn("ENABLE_DEBUG_DYLIB = NO;", block)
            self.assertIn("ENABLE_TESTABILITY = NO;", block)
            self.assertIn("GENERATE_PROFILING_CODE = NO;", block)
            self.assertIn("ENABLE_HARDENED_RUNTIME = YES;", block)
            self.assertIn("ONLY_ACTIVE_ARCH = NO;", block)
            self.assertNotIn('CODE_SIGN_IDENTITY = "Apple Development";', block)
        self.assertIn("DART_OBFUSCATION = true;", runner_release)
        self.assertIn('EXTRA_GEN_SNAPSHOT_OPTIONS = "--strip";', runner_release)
        self.assertIn("SPLIT_DEBUG_INFO = ", runner_release)

    def test_release_entitlement_source_split_is_exact(self):
        host = plistlib.loads((verifier.ROOT / "macos/Runner/Release.entitlements").read_bytes())
        tunnel = plistlib.loads((verifier.ROOT / "macos/PacketTunnel/PacketTunnel.entitlements").read_bytes())
        # The host app listens only for the browser-companion IPC on IPv4
        # loopback (see test_app_listeners_bind_loopback_only).
        self.assertIs(host.get("com.apple.security.network.server"), True)
        self.assertIs(tunnel.get("com.apple.security.network.server"), True)
        for value in (host, tunnel):
            self.assertNotIn("com.apple.security.get-task-allow", value)
            self.assertNotIn("com.apple.security.cs.allow-jit", value)

    def test_app_listeners_bind_loopback_only(self):
        # network.server on the App Store host is justified only while every
        # listening socket in the Dart app binds 127.0.0.1. Any new listener
        # must be reviewed here before it ships.
        import re

        listeners = []
        for path in sorted((verifier.ROOT / "lib").rglob("*.dart")):
            text = path.read_text(encoding="utf-8")
            for match in re.finditer(r"\b(?:Raw)?(?:Server|Http)(?:Socket|Server)(?:Secure)?\.bind\(", text):
                head = text[match.end():match.end() + 200]
                first = head.split(",", 1)[0].strip()
                listeners.append((path.relative_to(verifier.ROOT).as_posix(), first))
        self.assertEqual(
            sorted(listeners),
            [
                ("lib/browser_bridge_app_ipc.dart", "InternetAddress.loopbackIPv4"),
                ("lib/browser_bridge_proxy.dart", "InternetAddress.loopbackIPv4"),
            ],
        )
        ipc = (verifier.ROOT / "lib/browser_bridge_app_ipc.dart").read_text(encoding="utf-8")
        self.assertIn("listener.address.address != kBrowserBridgeAppIpcLoopbackHost", ipc)
        self.assertIn("socket.remoteAddress.address != kBrowserBridgeAppIpcLoopbackHost", ipc)

    def test_source_runtime_contract_is_exact(self):
        for relative in ("macos/Runner/Info.plist", "macos/PacketTunnel/Info.plist"):
            value = plistlib.loads((verifier.ROOT / relative).read_bytes())
            self.assertEqual(value.get(verifier.RUNTIME_CONTRACT_KEY), verifier.RUNTIME_CONTRACT)


@unittest.skipUnless(DARWIN, "real codesign and clang are Darwin tools")
class SignatureNormalizedDigestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="winsvpn-normalized-test-", dir=_ISOLATED_TEST_ROOT
        )
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.built = _compile_universal_engine(self.root / "linked.dylib")

    def tearDown(self):
        self.temporary.cleanup()

    def _copy(self, name):
        path = self.root / name
        _write(path, self.built.read_bytes(), 0o755)
        return path

    def _normalized(self, path):
        return _normalized_with_verifier(path, self.root / ("scratch-" + path.name))

    def test_signatures_normalize_to_one_digest_on_a_universal_dylib(self):
        self.assertEqual(
            set(_tool(["/usr/bin/lipo", "-archs", str(self.built)]).split()), {"arm64", "x86_64"}
        )
        entitlements = self.root / "entitlements.plist"
        _write_plist(
            entitlements,
            {"com.apple.security.wins-fixture-" + str(index): "x" * 40 for index in range(120)},
        )
        self.assertGreater(entitlements.stat().st_size, 8 * 1024)
        ad_hoc = self._copy("ad-hoc.dylib")
        _codesign_ad_hoc(ad_hoc)
        hardened = self._copy("hardened.dylib")
        _codesign_ad_hoc(
            hardened,
            "--options", "runtime",
            "--identifier", "org.winsvpn." + "i" * 200,
            "--entitlements", str(entitlements),
        )
        variants = {"linker-signed": self.built, "ad hoc": ad_hoc, "hardened": hardened}
        raw = {label: verifier.sha256_file(path) for label, path in variants.items()}
        self.assertEqual(len(set(raw.values())), 3, raw)
        normalized = {label: self._normalized(path) for label, path in variants.items()}
        self.assertEqual(len(set(normalized.values())), 1, normalized)
        self.assertNotIn(normalized["ad hoc"], raw.values())

    def test_one_changed_code_byte_changes_the_normalized_digest(self):
        original = self._normalized(self.built)
        for architecture in ("arm64", "x86_64"):
            with self.subTest(architecture=architecture):
                flipped = self._copy("flipped-" + architecture + ".dylib")
                _flip_text_byte(flipped, architecture)
                _codesign_ad_hoc(flipped)
                self.assertNotEqual(self._normalized(flipped), original)

    def test_normalization_leaves_the_held_engine_unchanged(self):
        before = verifier.sha256_file(self.built)
        self._normalized(self.built)
        self.assertEqual(verifier.sha256_file(self.built), before)
        self.assertEqual(sorted(path.name for path in (self.root / "scratch-linked.dylib").iterdir()), [])


class ScrubbedChildEnvironmentTests(unittest.TestCase):
    """Only the secret-inventory path crosses into release tool children."""

    @staticmethod
    def _child_environment() -> dict:
        completed = verifier.run_command(["/usr/bin/env"], 30)
        if completed.returncode != 0:
            raise AssertionError("env child failed: " + completed.stderr)
        return dict(
            line.split("=", 1) for line in completed.stdout.splitlines() if "=" in line
        )

    def test_inventory_path_reaches_the_child_only_when_set(self) -> None:
        inventory = "/private/var/winsvpn-test/release-secret-inventory.json"
        caller = {
            "WINS_RELEASE_SECRET_INVENTORY": inventory,
            "WINS_LEAK_PROBE": "must-not-cross",
            "PYTHONPATH": "/nonexistent/poison",
            "DYLD_INSERT_LIBRARIES": "/nonexistent/poison.dylib",
        }
        with mock.patch.dict(os.environ, caller):
            child = self._child_environment()
        self.assertEqual(child.get("WINS_RELEASE_SECRET_INVENTORY"), inventory)
        self.assertEqual(
            set(child) - {"PWD", "SHLVL", "_", "__CF_USER_TEXT_ENCODING"},
            {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "WINS_RELEASE_SECRET_INVENTORY"},
        )
        for name in ("WINS_LEAK_PROBE", "PYTHONPATH", "DYLD_INSERT_LIBRARIES"):
            self.assertNotIn(name, child)

        with mock.patch.dict(os.environ, {"WINS_LEAK_PROBE": "must-not-cross"}):
            os.environ.pop("WINS_RELEASE_SECRET_INVENTORY", None)
            child = self._child_environment()
        self.assertNotIn("WINS_RELEASE_SECRET_INVENTORY", child)
        self.assertNotIn("WINS_LEAK_PROBE", child)
        self.assertEqual(
            set(child) - {"PWD", "SHLVL", "_", "__CF_USER_TEXT_ENCODING"},
            {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR"},
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
