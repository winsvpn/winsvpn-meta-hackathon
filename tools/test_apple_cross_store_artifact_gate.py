#!/usr/bin/env python3
"""Authenticated inner-payload tests for the macOS App Store PKG gate."""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import io
import json
import os
import pathlib
import plistlib
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import apple_cross_store_artifact_gate as apple_gate
import apple_release_contamination_gate as contamination

DARWIN = sys.platform == "darwin"


def _privacy(
    api_reasons: dict[str, frozenset[str]],
    *,
    host_collection: bool = False,
) -> bytes:
    collected = []
    if host_collection:
        collected = [
            {
                "NSPrivacyCollectedDataType": data_type,
                "NSPrivacyCollectedDataTypeLinked": True,
                "NSPrivacyCollectedDataTypeTracking": False,
                "NSPrivacyCollectedDataTypePurposes": [
                    apple_gate.PRIVACY_APP_FUNCTIONALITY_PURPOSE
                ],
            }
            for data_type in sorted(apple_gate.HOST_PRIVACY_COLLECTED_TYPES)
        ]
    return plistlib.dumps(
        {
            "NSPrivacyTracking": False,
            "NSPrivacyTrackingDomains": [],
            "NSPrivacyCollectedDataTypes": collected,
            "NSPrivacyAccessedAPITypes": [
                {
                    "NSPrivacyAccessedAPIType": api_type,
                    "NSPrivacyAccessedAPITypeReasons": sorted(reasons),
                }
                for api_type, reasons in sorted(api_reasons.items())
            ],
        }
    )


def _fixture_bounded_subprocess(argv, label, **kwargs):
    input_data = kwargs.pop("input_data", None)
    stdout_limit = kwargs.pop("stdout_limit", apple_gate.MAX_TOOL_OUTPUT_BYTES)
    stderr_limit = kwargs.pop("stderr_limit", apple_gate.MAX_TOOL_OUTPUT_BYTES)
    run_kwargs = {
        "cwd": kwargs.pop("cwd", "/"),
        "env": kwargs.pop("env", None),
        "stdout": kwargs.pop("stdout", subprocess.PIPE),
        "stderr": kwargs.pop("stderr", subprocess.PIPE),
        "timeout": kwargs.pop("timeout", 60),
        "pass_fds": kwargs.pop("pass_fds", ()),
        "preexec_fn": kwargs.pop("preexec_fn", None),
        "start_new_session": True,
        "check": False,
    }
    # Only the xcrun lookup warm-up runs without the boundary; the fixture
    # never adds one.
    kwargs.pop("descendant_boundary", None)
    stdin = kwargs.pop("stdin", subprocess.DEVNULL)
    if input_data is None:
        run_kwargs["stdin"] = stdin
    else:
        run_kwargs["input"] = input_data
    if kwargs:
        raise AssertionError(f"unsupported fixture bounded arguments: {kwargs}")
    try:
        completed = subprocess.run(list(argv), **run_kwargs)
    except subprocess.TimeoutExpired as exc:
        raise apple_gate.AppleArtifactGateError(
            f"{label} exceeded the time bound"
        ) from exc
    if completed.stdout is not None and len(completed.stdout) > stdout_limit:
        raise apple_gate.AppleArtifactGateError(
            f"{label} exceeded the stdout output bound"
        )
    if completed.stderr is not None and len(completed.stderr) > stderr_limit:
        raise apple_gate.AppleArtifactGateError(
            f"{label} exceeded the stderr output bound"
        )
    return completed


REAL_BOUNDED = _fixture_bounded_subprocess
def _bounded_test_run(argv, **kwargs):
    capture_output = bool(kwargs.pop("capture_output", False))
    text_mode = bool(kwargs.pop("text", False))
    encoding = kwargs.pop("encoding", "utf-8")
    errors = kwargs.pop("errors", "strict")
    check = bool(kwargs.pop("check", False))
    input_value = kwargs.pop("input", None)
    if isinstance(input_value, str):
        input_value = input_value.encode(encoding, errors)
    stdout = kwargs.pop("stdout", subprocess.PIPE if capture_output else None)
    stderr = kwargs.pop("stderr", subprocess.PIPE if capture_output else None)
    run_kwargs = {
        "cwd": str(kwargs.pop("cwd", "/")),
        "env": kwargs.pop("env", None),
        "stdout": stdout,
        "stderr": stderr,
        "timeout": int(kwargs.pop("timeout", 60)),
        "check": False,
    }
    stdin = kwargs.pop("stdin", subprocess.DEVNULL)
    if input_value is None:
        run_kwargs["stdin"] = stdin
    else:
        run_kwargs["input"] = input_value
    completed = subprocess.run(list(argv), **run_kwargs)
    kwargs.pop("start_new_session", None)
    kwargs.pop("preexec_fn", None)
    if kwargs:
        raise AssertionError(f"unsupported bounded test subprocess arguments: {kwargs}")
    if text_mode:
        result = subprocess.CompletedProcess(
            completed.args,
            completed.returncode,
            completed.stdout.decode(encoding, errors),
            completed.stderr.decode(encoding, errors),
        )
    else:
        result = completed
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode,
            result.args,
            output=result.stdout,
            stderr=result.stderr,
        )
    return result


REAL_RUN = _bounded_test_run
FLUTTER_AOT_EXPORTS = (
    "_kDartSnapshotData",
    "_kDartSnapshotText",
)


def _host_integrity_fixture_copy(destination: pathlib.Path) -> pathlib.Path:
    source = pathlib.Path("/usr/bin/true")
    destination.write_bytes(source.read_bytes())
    os.chmod(destination, 0o755)
    if hashlib.sha256(destination.read_bytes()).digest() != hashlib.sha256(
        source.read_bytes()
    ).digest():
        raise AssertionError("fixed host integrity fixture copy changed bytes")
    return destination


def _codesign_integrity_state(path: pathlib.Path) -> tuple[str, str]:
    completed = REAL_RUN(
        ["/usr/bin/codesign", "--verify", "--strict", str(path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
        check=False,
    )
    if completed.returncode == 0:
        return "integrity-accepted", completed.stderr
    if "CSSMERR_TP_NOT_TRUSTED" in completed.stderr:
        return "certificate-not-trusted", completed.stderr
    raise AssertionError(
        "fixed host codesign precondition has an unsupported state: "
        + completed.stderr.strip()
    )


def _plist(
    bundle_id: str,
    *,
    release_host: bool = False,
    short_version: str = "1.0.17",
    bundle_version: str = "34",
) -> bytes:
    value: dict[str, object] = {
        "CFBundleIdentifier": bundle_id,
        "CFBundleShortVersionString": short_version,
        "CFBundleVersion": bundle_version,
        "CFBundleExecutable": "Wins VPN",
    }
    if release_host:
        value.update(
            {
                contamination.CONTRACT_KEY: contamination.CONTRACT_VALUE,
                contamination.LIVE_SMOKE_KEY: False,
                contamination.SMOKE_PIN_KEY: False,
            }
        )
    return plistlib.dumps(value)


def _tool_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PATH"] = apple_gate.REVIEWED_SUBPROCESS_PATH
    return env


def _compile_execute(
    destination: pathlib.Path,
    *,
    debug: bool = False,
    archs: tuple[str, ...] = ("arm64", "x86_64"),
) -> None:
    source = destination.with_suffix(".c")
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    command = ["/usr/bin/clang"]
    for arch in archs:
        command.extend(["-arch", arch])
    command.extend(["-o", str(destination), str(source)])
    if debug:
        command.insert(1, "-g")
    else:
        command[1:1] = ["-Os", "-Wl,-dead_strip"]
    completed = REAL_RUN(
        command,
        cwd="/",
        env=_tool_env(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr or completed.stdout)
    if not debug:
        stripped = REAL_RUN(
            ["/usr/bin/strip", str(destination)],
            cwd="/",
            env=_tool_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if stripped.returncode != 0:
            raise AssertionError(stripped.stderr or stripped.stdout)


def _compile_dylib(
    destination: pathlib.Path,
    *,
    archs: tuple[str, ...] = ("arm64", "x86_64"),
    body: str = "int wins_fixture(void) { return 1; }\n",
    exported: tuple[str, ...] = (),
) -> None:
    source = destination.with_suffix(".c")
    source.write_text(body, encoding="utf-8")
    command = ["/usr/bin/clang", "-dynamiclib", "-Os", "-Wl,-dead_strip"]
    for arch in archs:
        command.extend(["-arch", arch])
    for symbol in exported:
        command.append(f"-Wl,-exported_symbol,{symbol}")
    command.extend(["-o", str(destination), str(source)])
    completed = REAL_RUN(
        command,
        cwd="/",
        env=_tool_env(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr or completed.stdout)
    stripped = REAL_RUN(
        ["/usr/bin/strip", "-x", str(destination)],
        cwd="/",
        env=_tool_env(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if stripped.returncode != 0:
        raise AssertionError(stripped.stderr or stripped.stdout)


def _compile_flutter_aot(
    destination: pathlib.Path,
    *,
    archs: tuple[str, ...] = ("arm64", "x86_64"),
    marker: int = 0,
    include_symbols: bool = True,
) -> None:
    symbols = ""
    exported = FLUTTER_AOT_EXPORTS if include_symbols else ()
    if include_symbols:
        symbols = f"""
#include <stdint.h>
#define KEEP __attribute__((used, visibility("default")))
KEEP const uint8_t kDartSnapshotData[] = {{ 0xf5, 0xf5, 0xdc, 0xdc, {marker} }};
KEEP const uint8_t kDartSnapshotText[] = {{ 0xf5, 0xf5, 0xdc, 0xdc, 0x01 }};
"""
    else:
        symbols = "int wins_generic_dylib(void) { return 0; }\n"
    _compile_dylib(destination, archs=archs, body=symbols, exported=exported)


def _codesign_ad_hoc(path: pathlib.Path, *options: str) -> None:
    completed = REAL_RUN(
        ["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", *options, str(path)],
        cwd="/",
        env=_tool_env(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr or completed.stdout)


def _flip_text_byte(path: pathlib.Path, architecture: str = "arm64") -> None:
    """Flip one byte of __TEXT,__text in one slice of a universal Mach-O."""
    data = bytearray(path.read_bytes())
    cputype = {"arm64": 0x0100000C, "x86_64": 0x01000007}[architecture]
    if struct.unpack_from(">I", data, 0)[0] != 0xCAFEBABE:
        raise AssertionError("not a universal Mach-O")
    for index in range(struct.unpack_from(">I", data, 4)[0]):
        cpu, _subtype, slice_offset, _size, _align = struct.unpack_from(
            ">5I", data, 8 + index * 20
        )
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


def _consumer_normalized_sha256(path: pathlib.Path, scratch: pathlib.Path) -> str:
    """The macOS verifier's signature-normalized digest of one file.

    The verifier holds the file and watches its nine nearest ancestors, so the
    copy it holds sits nine quiet directories deep under scratch.
    """
    import verify_macos_release_artifact as consumer

    scratch.mkdir(mode=0o700, parents=True, exist_ok=True)
    # The verifier refuses any symbolic path component (for example /var).
    scratch = scratch.resolve()
    held_dir = scratch.joinpath("held", *"abcdefgh")
    held_dir.mkdir(mode=0o700, parents=True)
    work = scratch / "work"
    work.mkdir(mode=0o700)
    copy = held_dir / "engine"
    copy.write_bytes(path.read_bytes())
    with consumer.HeldFile(copy, "fixture engine") as held:
        return consumer.signature_normalized_sha256(
            held, work, "engine", consumer.run_command
        )


def _write_macos_app(
    app: pathlib.Path,
    aot: pathlib.Path,
    host: pathlib.Path,
    *,
    extra_files: dict[str, bytes] | None = None,
    nested_app: bool = False,
    engine: pathlib.Path | None = None,
    hidden_app: bool = False,
    versioned_aot: bool = False,
) -> None:
    contents = app / "Contents"
    macos_dir = contents / "MacOS"
    extension = contents / "PlugIns" / "PacketTunnel.appex" / "Contents"
    (contents / "Resources").mkdir(parents=True)
    macos_dir.mkdir(parents=True)
    (extension / "MacOS").mkdir(parents=True)
    (extension / "Resources").mkdir(parents=True)
    (contents / "Info.plist").write_bytes(_plist(apple_gate.HOST_BUNDLE_ID, release_host=True))
    aot_path = contents / "Frameworks" / "App.framework" / "App"
    if versioned_aot:
        # Xcode's macOS framework layout: App -> Versions/Current/App, Current -> A.
        framework = aot_path.parent
        real = framework / "Versions" / "A" / "App"
        real.parent.mkdir(parents=True)
        real.write_bytes(aot.read_bytes())
        (framework / "Versions" / "Current").symlink_to("A")
        aot_path.symlink_to("Versions/Current/App")
        aot_path = real
    else:
        aot_path.parent.mkdir(parents=True)
        aot_path.write_bytes(aot.read_bytes())
    host_path = macos_dir / "Wins VPN"
    host_path.write_bytes(host.read_bytes())
    os.chmod(host_path, 0o755)
    os.chmod(aot_path, 0o755)
    (contents / "Resources" / "PrivacyInfo.xcprivacy").write_bytes(
        _privacy(apple_gate.HOST_PRIVACY_API_REASONS, host_collection=True)
    )
    (extension / "Info.plist").write_bytes(_plist(apple_gate.TUNNEL_BUNDLE_ID))
    (extension / "Resources" / "PrivacyInfo.xcprivacy").write_bytes(
        _privacy(apple_gate.TUNNEL_PRIVACY_API_REASONS)
    )
    tunnel = extension / "MacOS" / "PacketTunnel"
    tunnel.write_bytes(host.read_bytes())
    os.chmod(tunnel, 0o755)
    if nested_app:
        helper = contents / "Helpers" / "Helper.app" / "Contents" / "MacOS"
        helper.mkdir(parents=True)
        (helper / "Helper").write_bytes(host.read_bytes())
        (helper.parent / "Info.plist").write_bytes(_plist("org.winsvpn.app.Helper"))
        (helper.parent / "Resources").mkdir(parents=True)
        (helper.parent / "Resources" / "PrivacyInfo.xcprivacy").write_bytes(
            _privacy(apple_gate.HOST_PRIVACY_API_REASONS, host_collection=True)
        )
    if hidden_app:
        hidden = app.parent / ".Hidden.app" / "Contents"
        hidden.mkdir(parents=True)
        (hidden / "Info.plist").write_bytes(_plist("org.winsvpn.app.hidden", release_host=True))
        (hidden / "Resources").mkdir(parents=True)
        (hidden / "Resources" / "PrivacyInfo.xcprivacy").write_bytes(
            _privacy(apple_gate.HOST_PRIVACY_API_REASONS, host_collection=True)
        )
    if extra_files:
        for relative, payload in extra_files.items():
            path = app / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
    if engine is not None:
        binary = (
            contents
            / "Frameworks"
            / "WinsAmneziaWGPacketEngine.framework"
            / "Versions"
            / "A"
            / "WinsAmneziaWGPacketEngine"
        )
        binary.parent.mkdir(parents=True)
        binary.write_bytes(engine.read_bytes())
        os.chmod(binary, 0o755)
        privacy = binary.parent / "Resources" / "PrivacyInfo.xcprivacy"
        privacy.parent.mkdir(parents=True)
        privacy.write_bytes(
            _privacy(
                {
                    apple_gate.PRIVACY_FILE_TIMESTAMP_API: frozenset({"C617.1"}),
                }
            )
        )


def _stage_macos_engine_framework(
    app: pathlib.Path,
    framework_name: str,
    binary_name: str,
    binary: pathlib.Path,
    api_reasons: dict[str, frozenset[str]],
) -> None:
    version = app / "Contents" / "Frameworks" / framework_name / "Versions" / "A"
    executable = version / binary_name
    executable.parent.mkdir(parents=True, exist_ok=True)
    executable.write_bytes(binary.read_bytes())
    os.chmod(executable, 0o755)
    privacy = version / "Resources" / "PrivacyInfo.xcprivacy"
    privacy.parent.mkdir(parents=True, exist_ok=True)
    privacy.write_bytes(_privacy(api_reasons))


def _pkgbuild(root: pathlib.Path, package: pathlib.Path) -> None:
    component = package.with_name(package.stem + "-component.pkg")
    completed = REAL_RUN(
        [
            "/usr/bin/pkgbuild",
            "--root",
            str(root),
            "--identifier",
            "org.winsvpn.app",
            "--version",
            "1.0.17",
            "--install-location",
            "/",
            str(component),
        ],
        cwd="/",
        env=_tool_env(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr or completed.stdout)
    product = REAL_RUN(
        ["/usr/bin/productbuild", "--package", str(component), str(package)],
        cwd="/",
        env=_tool_env(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if product.returncode != 0:
        raise AssertionError(product.stderr or product.stdout)


class AppleCrossStorePkgInnerPayloadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="wins-apple-pkg-inner-", dir="/private/tmp"
        )
        self.repo = pathlib.Path(self.temporary.name)
        (self.repo / "artifacts").mkdir()
        identity = self.repo / apple_gate.RELEASE_IDENTITY_RELATIVE_PATH
        identity.parent.mkdir(parents=True)
        identity.write_bytes((ROOT / apple_gate.RELEASE_IDENTITY_RELATIVE_PATH).read_bytes())
        self.binaries = self.repo / "binaries"
        self.binaries.mkdir()
        self.host = self.binaries / "host"
        self.debug = self.binaries / "debug"
        self.x86 = self.binaries / "x86"
        self.aot = self.binaries / "aot"
        self.aot_other = self.binaries / "aot-other"
        self.engine = self.binaries / "engine"
        self.generic_dylib = self.binaries / "generic-dylib"
        self.thin_aot = self.binaries / "thin-aot"
        _compile_execute(self.host)
        _compile_execute(self.debug, debug=True)
        _compile_execute(self.x86, archs=("x86_64",))
        _compile_flutter_aot(self.aot, marker=0)
        _compile_flutter_aot(self.aot_other, marker=9)
        _compile_dylib(self.engine)
        _compile_flutter_aot(
            self.generic_dylib, archs=("arm64", "x86_64"), include_symbols=False
        )
        _compile_flutter_aot(self.thin_aot, archs=("arm64",))
        # The gate must never consult the owner-provisioned source-freeze trust
        # file; any call fails the test.
        self._freeze_patch = mock.patch.object(
            apple_gate.source_freeze,
            "verified_release_source_state",
            side_effect=AssertionError("gate consulted the source-freeze trust file"),
        )
        self._freeze_patch.start()
        self._descendant_patch = mock.patch.object(
            apple_gate,
            "_macos_descendant_boundary_argv",
            side_effect=lambda argv: list(argv),
        )
        self._descendant_patch.start()

    def tearDown(self) -> None:
        self._descendant_patch.stop()
        self._freeze_patch.stop()
        self.temporary.cleanup()

    @contextlib.contextmanager
    def _private_root(self):
        with tempfile.TemporaryDirectory(prefix="wins-apple-pkg-test-") as temporary:
            private = apple_gate._prepare_private_root(pathlib.Path(temporary))
            token = apple_gate._PRIVATE_ROOT.set(private)
            try:
                yield private
            finally:
                apple_gate._cleanup_private_root(private)
                apple_gate._PRIVATE_ROOT.reset(token)

    def _stage_pkg(
        self,
        name: str = "WinsVPN.pkg",
        *,
        extra_files: dict[str, bytes] | None = None,
        nested_app: bool = False,
        aot: pathlib.Path | None = None,
        host: pathlib.Path | None = None,
        second_app: bool = False,
        symlink: tuple[str, str] | None = None,
        engine: bool | None = None,
        provenance: bool | None = None,
        hidden_app: bool = False,
        engine_digest: str | None = None,
        staged_engine: pathlib.Path | None = None,
        normalized_digest: str | None = None,
        versioned_aot: bool = False,
    ) -> pathlib.Path:
        payload_root = self.repo / f"payload-{name}"
        app = payload_root / "Applications" / "Win's VPN.app"
        complete_engine_fixture = engine is None and provenance is None
        engine_binary = self.engine if engine is True or provenance is True else None
        _write_macos_app(
            app,
            aot or self.aot,
            host or self.host,
            extra_files=extra_files,
            nested_app=nested_app,
            engine=engine_binary,
            hidden_app=hidden_app,
            versioned_aot=versioned_aot,
        )
        if complete_engine_fixture:
            file_api = {
                apple_gate.PRIVACY_FILE_TIMESTAMP_API: frozenset({"C617.1"}),
            }
            # staged_engine stands in for the bytes staging and Xcode export
            # re-signed after the provenance below was written for self.engine.
            packaged_engine = staged_engine or self.engine
            _stage_macos_engine_framework(
                app,
                "WinsAmneziaWGPacketEngine.framework",
                "WinsAmneziaWGPacketEngine",
                packaged_engine,
                file_api,
            )
            _stage_macos_engine_framework(
                app,
                "WinsXrayVlessWsTransport.framework",
                "WinsXrayVlessWsTransport",
                packaged_engine,
                file_api,
            )
            _stage_macos_engine_framework(
                app,
                "WinsWinnPacketEngine.framework",
                "WinsWinnPacketEngine",
                packaged_engine,
                {
                    **file_api,
                    apple_gate.PRIVACY_SYSTEM_BOOT_TIME_API: frozenset({"35F9.1"}),
                },
            )
            digest = hashlib.sha256(self.engine.read_bytes()).hexdigest()
            record = {"sha256": digest}
            if normalized_digest is not None:
                record["signature_normalized_sha256"] = normalized_digest
            awg = {
                "generation": "3.1",
                "source": {
                    "commit": "fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d",
                    "tag": "v3.1.20260814",
                },
                "wrappers": {
                    "macosx": {
                        "amneziawg_packet_engine": dict(record),
                        "xray_vless_ws_transport": dict(record),
                    }
                },
            }
            winn = {"wrappers": {"macosx": dict(record)}}
            awg_bytes = (json.dumps(awg, sort_keys=True) + "\n").encode("utf-8")
            winn_bytes = (json.dumps(winn, sort_keys=True) + "\n").encode("utf-8")
            resources = app / "Contents" / "Resources"
            (resources / "apple_awg_31_engine_provenance.json").write_bytes(awg_bytes)
            (resources / "apple_winn_v3_engine_provenance.json").write_bytes(winn_bytes)
            manifest = {
                "schema_version": 1,
                "staged_components": [
                    "amneziawg_packet_engine",
                    "winn_packet_engine",
                    "xray_vless_ws_transport",
                ],
                "apple_awg_31_provenance_sha256": hashlib.sha256(awg_bytes).hexdigest(),
                "apple_winn_v3_provenance_sha256": hashlib.sha256(winn_bytes).hexdigest(),
            }
            (resources / "apple_engine_artifacts_manifest.json").write_text(
                json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
            )
        if provenance is True:
            digest = engine_digest or hashlib.sha256(self.engine.read_bytes()).hexdigest()
            awg = {
                "generation": "3.1",
                "source": {
                    "commit": "fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d",
                    "tag": "v3.1.20260814",
                },
                "wrappers": {
                    "macosx": {
                        "amneziawg_packet_engine": {
                            "architectures": ["arm64"],
                            "path": "macos/libWinsAmneziaWGPacketEngine.dylib",
                            "sha256": digest,
                        }
                    }
                },
            }
            awg_bytes = (json.dumps(awg, sort_keys=True) + "\n").encode("utf-8")
            awg_path = app / "Contents" / "Resources" / "apple_awg_31_engine_provenance.json"
            awg_path.write_bytes(awg_bytes)
            manifest = {
                "schema_version": 1,
                "staged_components": ["amneziawg_packet_engine"],
                "apple_awg_31_provenance_sha256": hashlib.sha256(awg_bytes).hexdigest(),
                "apple_winn_v3_provenance_sha256": None,
            }
            (
                app / "Contents" / "Resources" / "apple_engine_artifacts_manifest.json"
            ).write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
        if second_app:
            decoy = payload_root / "Applications" / "Decoy.app"
            _write_macos_app(decoy, aot or self.aot, host or self.host)
        if symlink is not None:
            link = app / symlink[0]
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to(symlink[1])
        package = self.repo / "artifacts" / name
        _pkgbuild(payload_root, package)
        return package

    def _authenticated_run(
        self,
        recorded: list[list[str]] | None = None,
        *,
        on_check_signature=None,
        env_holder: list[dict[str, str]] | None = None,
    ):
        def run(argv, _label, **kwargs):
            command = list(argv)
            if recorded is not None:
                recorded.append(command)
            self.assertEqual(kwargs["cwd"], "/")
            env = kwargs["env"]
            self.assertEqual(env["PATH"], apple_gate.REVIEWED_SUBPROCESS_PATH)
            self.assertEqual(set(env), {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"})
            if env_holder is not None:
                env_holder.append(dict(env))
            if command[:2] == ["/usr/sbin/pkgutil", "--check-signature"]:
                if on_check_signature is not None:
                    on_check_signature(command)
                return subprocess.CompletedProcess(
                    command,
                    0,
                    (
                        "Status: signed by a developer certificate issued by Apple (Development)\n"
                        "Certificate Chain:\n"
                        "    1. 3rd Party Mac Developer Installer: Win's VPN Inc "
                        f"({apple_gate.TEAM_ID})\n"
                        "    2. Apple Worldwide Developer Relations Certification Authority\n"
                        "    3. Apple Root CA\n"
                    ).encode("utf-8"),
                    b"",
                )
            if command[0] == "/usr/bin/codesign" and "--verify" in command:
                requirement = apple_gate._codesign_requirement_from_argv(command)
                self.assertIn(f'subject.OU] = "{apple_gate.TEAM_ID}"', requirement)
                self.assertIn("anchor apple generic", requirement)
                self.assertFalse(apple_gate._is_volfs_path(command[-1]), msg=command)
                return subprocess.CompletedProcess(command, 0, b"", b"")
            if command[0] == "/usr/bin/codesign" and "-d" in command:
                return subprocess.CompletedProcess(
                    command,
                    0,
                    b"",
                    (
                        "Authority=Apple Distribution: Win's VPN Inc "
                        f"({apple_gate.TEAM_ID})\nTeamIdentifier={apple_gate.TEAM_ID}\n"
                    ).encode("utf-8"),
                )
            return REAL_BOUNDED(argv, _label, **kwargs)

        return run

    def _verify_pkg(
        self,
        relative: str,
        recorded: list[list[str]] | None = None,
        *,
        on_check_signature=None,
        popen_side_effect=None,
        env_holder: list[dict[str, str]] | None = None,
    ):
        patches = [
            mock.patch.object(apple_gate, "ROOT", self.repo),
            mock.patch.object(
                apple_gate,
                "_bounded_subprocess",
                side_effect=self._authenticated_run(
                    recorded,
                    on_check_signature=on_check_signature,
                    env_holder=env_holder,
                ),
            ),
        ]
        if popen_side_effect is not None:
            patches.append(
                mock.patch.object(
                    apple_gate.subprocess, "Popen", side_effect=popen_side_effect
                )
            )
        with contextlib.ExitStack() as stack:
            for patcher in patches:
                stack.enter_context(patcher)
            return apple_gate.verify_signature("macos-app-store-pkg", relative)

    def test_reviewed_tools_reject_ambient_path_extractors(self) -> None:
        with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "PATH-relative"):
            apple_gate._run(["pkgutil", "--expand-full"], "ambient pkgutil")
        with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "unreviewed"):
            apple_gate._run(["/usr/bin/tar", "-tf", "x"], "ambient tar")
        with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "unreviewed"):
            apple_gate._run(["/opt/homebrew/bin/bsdtar", "-x"], "homebrew bsdtar")

    def test_subprocess_env_is_minimal_and_redacts_ambient_secrets(self) -> None:
        secret = "supersecret-ambient-token-value"
        with mock.patch.dict(
            os.environ,
            {"API_TOKEN": secret, "DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib"},
            clear=False,
        ):
            env = apple_gate._subprocess_env()
            self.assertEqual(set(env), {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"})
            self.assertNotIn(secret, env.values())
            self.assertNotIn("API_TOKEN", env)
            self.assertNotIn("DYLD_INSERT_LIBRARIES", env)
            def bounded(argv, label, **kwargs):
                if argv[:2] == [apple_gate.XCRUN, "--find"]:
                    return subprocess.CompletedProcess(argv, 0, b"/usr/bin/lipo\n", b"")
                return subprocess.CompletedProcess(
                    argv, 1, b"", f"tool leaked {secret}".encode("utf-8")
                )

            with mock.patch.object(
                apple_gate, "_bounded_subprocess", side_effect=bounded
            ):
                with self.assertRaises(apple_gate.AppleArtifactGateError) as raised:
                    apple_gate._run(
                        ["/usr/bin/lipo", "-archs", "x"],
                        "Mach-O architecture inspection",
                    )
        self.assertNotIn(secret, str(raised.exception))
        self.assertIn("<redacted>", str(raised.exception))

    def test_synthetic_pkg_binds_inner_aot_and_native_hashes(self) -> None:
        package = self._stage_pkg()
        recorded: list[list[str]] = []
        env_holder: list[dict[str, str]] = []
        stdout = io.StringIO()
        with mock.patch.object(sys, "stdout", stdout):
            self._verify_pkg("artifacts/WinsVPN.pkg", recorded, env_holder=env_holder)
        output = stdout.getvalue()
        self.assertIn("APPLE CROSS-STORE SIGNATURE GATE: PASS", output)
        self.assertIn("inner_payload_sha256=", output)
        self.assertIn("aot_sha256=", output)
        pkg_hash = hashlib.sha256(package.read_bytes()).hexdigest()
        self.assertIn(f"sha256={pkg_hash}", output)
        aot_hash = hashlib.sha256(self.aot.read_bytes()).hexdigest()
        self.assertIn(f"aot_sha256={aot_hash}", output)
        self.assertTrue(
            any(argv[:2] == ["/usr/sbin/pkgutil", "--check-signature"] for argv in recorded)
        )
        self.assertTrue(any(argv[0] == "/usr/bin/lipo" for argv in recorded))
        self.assertTrue(
            any(argv[:2] == [apple_gate.XCRUN, "otool-classic"] for argv in recorded)
        )
        self.assertTrue(any(argv[0] == "/usr/bin/nm" for argv in recorded))
        self.assertFalse(
            any(pathlib.Path(argv[0]).name in {"tar", "bsdtar", "xar"} for argv in recorded)
        )
        for argv in recorded:
            self.assertIn(argv[0], apple_gate.REVIEWED_APPLE_TOOLS)
            self.assertTrue(argv[0].startswith("/"))
        self.assertTrue(env_holder)
        for env in env_holder:
            self.assertEqual(set(env), {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"})

    def test_versioned_app_framework_counts_the_aot_once(self) -> None:
        # Rehearsal r42: the real macOS App.framework/App is a link to
        # Versions/A/App, so the link and the file are both Mach-O entries.
        self._stage_pkg(versioned_aot=True)
        stdout = io.StringIO()
        with mock.patch.object(sys, "stdout", stdout):
            self._verify_pkg("artifacts/WinsVPN.pkg")
        output = stdout.getvalue()
        self.assertIn("APPLE CROSS-STORE SIGNATURE GATE: PASS", output)
        aot_hash = hashlib.sha256(self.aot.read_bytes()).hexdigest()
        self.assertIn(f"aot_sha256={aot_hash}", output)

    def test_pkgutil_uses_authenticated_snapshot_not_original_path(self) -> None:
        package = self._stage_pkg()
        recorded: list[list[str]] = []
        original = str(package)

        real_popen = apple_gate.subprocess.Popen
        expand_targets: list[str] = []

        def popen(argv, **kwargs):
            command = list(argv)
            if command[:2] == ["/usr/sbin/pkgutil", "--expand-full"]:
                expand_targets.append(command[2])
                self.assertNotEqual(command[2], original)
                self.assertTrue(command[2].startswith("/.vol/"))
                self.assertTrue(stat.S_ISREG(os.lstat(command[2]).st_mode))
                self.assertTrue(command[3].startswith("/.vol/"))
                dest_parts = pathlib.PurePosixPath(command[3]).parts
                self.assertGreaterEqual(len(dest_parts), 4)
                dest_inode = f"/.vol/{dest_parts[2]}/{dest_parts[3]}"
                dest_info = os.lstat(dest_inode)
                self.assertTrue(stat.S_ISDIR(dest_info.st_mode))
                self.assertFalse(stat.S_ISLNK(dest_info.st_mode))
                self.assertEqual(kwargs.get("stdout"), subprocess.DEVNULL)
            return real_popen(argv, **kwargs)

        self._verify_pkg("artifacts/WinsVPN.pkg", recorded, popen_side_effect=popen)
        self.assertTrue(expand_targets)
        check_targets = [
            argv[2]
            for argv in recorded
            if argv[:2] == ["/usr/sbin/pkgutil", "--check-signature"]
        ]
        self.assertTrue(check_targets)
        for target in (*check_targets, *expand_targets):
            self.assertNotEqual(target, original)
            self.assertTrue(target.startswith("/.vol/"))

    def test_original_path_swap_restore_cannot_rebind_snapshot(self) -> None:
        first = self._stage_pkg(name="first.pkg")
        evil = self._stage_pkg(name="evil.pkg", aot=self.aot_other)
        original = first.read_bytes()
        evil_bytes = evil.read_bytes()
        self.assertNotEqual(original, evil_bytes)
        original_digest = hashlib.sha256(original).hexdigest()
        evil_digest = hashlib.sha256(evil_bytes).hexdigest()
        aot_digest = hashlib.sha256(self.aot.read_bytes()).hexdigest()
        evil_aot = hashlib.sha256(self.aot_other.read_bytes()).hexdigest()
        real_popen = apple_gate.subprocess.Popen

        def swap(_command):
            first.write_bytes(evil_bytes)

        def popen(argv, **kwargs):
            command = list(argv)
            proc = real_popen(argv, **kwargs)
            if command[:2] == ["/usr/sbin/pkgutil", "--expand-full"]:
                first.write_bytes(original)
            return proc

        stdout = io.StringIO()
        with mock.patch.object(sys, "stdout", stdout):
            self._verify_pkg(
                "artifacts/first.pkg",
                on_check_signature=swap,
                popen_side_effect=popen,
            )
        output = stdout.getvalue()
        self.assertIn(f"sha256={original_digest}", output)
        self.assertNotIn(f"sha256={evil_digest}", output)
        self.assertIn(f"aot_sha256={aot_digest}", output)
        self.assertNotIn(f"aot_sha256={evil_aot}", output)
        self.assertEqual(first.read_bytes(), original)

    def test_nested_helper_app_is_rejected_as_unallowlisted(self) -> None:
        self._stage_pkg(nested_app=True)
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "allowlist|hidden app"
        ):
            self._verify_pkg("artifacts/WinsVPN.pkg")

    def test_hidden_dot_app_is_rejected(self) -> None:
        package = self._stage_pkg()
        with self._private_root() as private:
            snapshot = apple_gate._snapshot_pkg(package, private.snapshot_file)
            expanded = private.root / "expanded"
            with mock.patch.object(
                apple_gate, "_bounded_subprocess", side_effect=self._authenticated_run()
            ):
                apple_gate._expand_pkg(snapshot, expanded)
            payload = apple_gate._payload_directories(expanded)[0]
            hidden = payload / "Applications" / ".Hidden.app" / "Contents"
            hidden.mkdir(parents=True)
            (hidden / "Info.plist").write_bytes(
                _plist("org.winsvpn.app.hidden", release_host=True)
            )
            (hidden / "Resources").mkdir()
            (hidden / "Resources" / "PrivacyInfo.xcprivacy").write_bytes(
                _privacy(apple_gate.HOST_PRIVACY_API_REASONS, host_collection=True)
            )
            with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "hidden app"):
                apple_gate._exact_payload_app(expanded)

    def test_duplicate_host_apps_fail_closed(self) -> None:
        self._stage_pkg(second_app=True)
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "exactly the allowlisted host app|exactly one host app",
        ):
            self._verify_pkg("artifacts/WinsVPN.pkg")

    def test_missing_aot_fails_closed(self) -> None:
        package = self._stage_pkg()
        with self._private_root() as private:
            snapshot = apple_gate._snapshot_pkg(package, private.snapshot_file)
            with mock.patch.object(
                apple_gate, "_bounded_subprocess", side_effect=self._authenticated_run()
            ):
                app, tree = apple_gate._expand_pkg(snapshot, private.root / "expanded")
            original_app = (private.root / "expanded") / apple_gate._lexical_relative(
                app, tree.root
            )
            aot = original_app / "Contents" / "Frameworks" / "App.framework" / "App"
            aot.unlink()
            with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "Flutter AOT"):
                apple_gate._inspect_macos_inner_payload(
                    original_app, private.root / "expanded"
                )

    def test_absolute_symlink_fails_closed(self) -> None:
        self._stage_pkg(symlink=("Contents/Resources/escape", "/etc/passwd"))
        with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "symlink"):
            self._verify_pkg("artifacts/WinsVPN.pkg")

    def test_escaping_symlink_fails_closed(self) -> None:
        self._stage_pkg(symlink=("Contents/Resources/escape", "../../../../../../tmp"))
        with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "symlink"):
            self._verify_pkg("artifacts/WinsVPN.pkg")

    def test_preexisting_expansion_destination_is_payload_substitution(self) -> None:
        package = self._stage_pkg()
        with self._private_root() as private:
            snapshot = apple_gate._snapshot_pkg(package, private.snapshot_file)
            destination = private.root / "expanded"
            destination.mkdir()
            (destination / "Win's VPN.app").mkdir()
            with mock.patch.object(
                apple_gate, "_bounded_subprocess", side_effect=self._authenticated_run()
            ):
                with self.assertRaisesRegex(
                    apple_gate.AppleArtifactGateError, "already exists"
                ):
                    apple_gate._expand_pkg(snapshot, destination)

    def test_duplicate_payload_directories_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            expanded = pathlib.Path(temporary)
            first = expanded / "one.pkg" / "Payload" / "Applications" / "Win's VPN.app"
            second = expanded / "two.pkg" / "Payload" / "Applications" / "Other.app"
            first.mkdir(parents=True)
            second.mkdir(parents=True)
            (first / "Contents").mkdir()
            (first / "Contents" / "Info.plist").write_bytes(b"a")
            (second / "Contents").mkdir()
            (second / "Contents" / "Info.plist").write_bytes(b"b")
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "exactly one expanded Payload"
            ):
                apple_gate._exact_payload_app(expanded)

    def test_nested_payload_root_is_enumerated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            expanded = pathlib.Path(temporary)
            payload = expanded / "one.pkg" / "Payload"
            nested = payload / "extra.pkg" / "Payload"
            nested.mkdir(parents=True)
            payload_dirs = apple_gate._payload_directories(expanded)
            self.assertEqual(len(payload_dirs), 2)
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "exactly one expanded Payload"
            ):
                apple_gate._exact_payload_app(expanded)

    def test_expanded_hardlink_is_rejected(self) -> None:
        package = self._stage_pkg()
        with self._private_root() as private:
            snapshot = apple_gate._snapshot_pkg(package, private.snapshot_file)
            expanded = private.root / "expanded"
            with mock.patch.object(
                apple_gate, "_bounded_subprocess", side_effect=self._authenticated_run()
            ):
                app, tree = apple_gate._expand_pkg(snapshot, expanded)
            original_app = expanded / apple_gate._lexical_relative(app, tree.root)
            target = original_app / "Contents" / "Resources" / "PrivacyInfo.xcprivacy"
            alias = original_app / "Contents" / "Resources" / "alias.plist"
            os.link(target, alias)
            with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "hardlink"):
                apple_gate._reject_unsafe_expansion(expanded)
            with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "hardlink"):
                apple_gate._inspect_macos_inner_payload(original_app, expanded)

    def test_special_file_in_expansion_is_rejected(self) -> None:
        package = self._stage_pkg()
        with self._private_root() as private:
            snapshot = apple_gate._snapshot_pkg(package, private.snapshot_file)
            expanded = private.root / "expanded"
            with mock.patch.object(
                apple_gate, "_bounded_subprocess", side_effect=self._authenticated_run()
            ):
                app, tree = apple_gate._expand_pkg(snapshot, expanded)
            original_app = expanded / apple_gate._lexical_relative(app, tree.root)
            fifo = original_app / "Contents" / "Resources" / "fifo"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "special filesystem entry"
            ):
                apple_gate._reject_unsafe_expansion(expanded)

    def test_unstripped_engine_fails_closed(self) -> None:
        unstripped = self.binaries / "engine-local"
        source = unstripped.with_suffix(".c")
        source.write_text(
            "static int wins_hidden(void) { return 7; }\n"
            "int wins_fixture(void) { return wins_hidden(); }\n",
            encoding="utf-8",
        )
        completed = REAL_RUN(
            [
                "/usr/bin/clang",
                "-dynamiclib",
                "-arch",
                "arm64",
                "-o",
                str(unstripped),
                str(source),
            ],
            cwd="/",
            env=_tool_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.engine = unstripped
        self._stage_pkg()
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "debug|symbol|unstripped",
        ):
            self._verify_pkg("artifacts/WinsVPN.pkg")

    def test_unstripped_aot_fails_closed(self) -> None:
        debug_aot = self.binaries / "debug-aot"
        source = debug_aot.with_suffix(".c")
        source.write_text(
            """
#include <stdint.h>
#define KEEP __attribute__((used, visibility("default")))
KEEP const uint8_t kDartSnapshotData[] = { 1 };
KEEP const uint8_t kDartSnapshotText[] = { 1 };
int unused_debug(void) { return 0; }
""",
            encoding="utf-8",
        )
        command = [
            "/usr/bin/clang",
            "-dynamiclib",
            "-g",
            "-arch",
            "arm64",
            "-arch",
            "x86_64",
            "-o",
            str(debug_aot),
            str(source),
        ]
        completed = REAL_RUN(
            command,
            cwd="/",
            env=_tool_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self._stage_pkg(aot=debug_aot)
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "debug|symbol",
        ):
            self._verify_pkg("artifacts/WinsVPN.pkg")

    def test_packaged_private_symbols_fail_closed(self) -> None:
        self._stage_pkg(
            extra_files={"Contents/Resources/app.macos.symbols": b"s" * 128}
        )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "private symbol"
        ):
            self._verify_pkg("artifacts/WinsVPN.pkg")

    def test_prohibited_secret_fails_closed(self) -> None:
        self._stage_pkg(
            extra_files={"Contents/Resources/leak.txt": b"AIza" + (b"A" * 35)}
        )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "credential|google_api_key"
        ):
            self._verify_pkg("artifacts/WinsVPN.pkg")

    def test_non_arm64_aot_fails_closed(self) -> None:
        x86_aot = self.binaries / "x86-aot"
        _compile_flutter_aot(x86_aot, archs=("x86_64",))
        self._stage_pkg(aot=x86_aot)
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "arm64|universal"
        ):
            self._verify_pkg("artifacts/WinsVPN.pkg")

    def test_mh_execute_aot_fixture_is_rejected(self) -> None:
        self._stage_pkg(aot=self.host)
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "MH_DYLIB|EXECUTE|exact arm64|Flutter AOT",
        ):
            self._verify_pkg("artifacts/WinsVPN.pkg")

    def test_thin_arm64_flutter_aot_is_rejected(self) -> None:
        self._stage_pkg(aot=self.thin_aot)
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "exact arm64 plus x86_64"
        ):
            self._verify_pkg("artifacts/WinsVPN.pkg")

    def test_generic_dylib_without_flutter_signature_is_rejected(self) -> None:
        self._stage_pkg(aot=self.generic_dylib)
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "Flutter AOT snapshot signature|section contract",
        ):
            self._verify_pkg("artifacts/WinsVPN.pkg")

    def test_pre_3_47_snapshot_symbol_names_are_rejected(self) -> None:
        # Rehearsal r43: the pinned Flutter 3.47.6 engine resolves only
        # kDartSnapshotData and kDartSnapshotText. An App built with the four
        # older kDartVm/kDartIsolate names could not start under it.
        legacy_names = (
            "kDartVmSnapshotData",
            "kDartIsolateSnapshotData",
            "kDartVmSnapshotInstructions",
            "kDartIsolateSnapshotInstructions",
        )
        legacy = self.binaries / "aot-legacy-names"
        _compile_dylib(
            legacy,
            body="#include <stdint.h>\n"
            + "".join(
                f'__attribute__((used, visibility("default"))) const uint8_t {name}[] = {{ 1 }};\n'
                for name in legacy_names
            ),
            exported=tuple(f"_{name}" for name in legacy_names),
        )
        self._stage_pkg(aot=legacy)
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "lacks the Flutter AOT snapshot signature: _kDartSnapshotData, _kDartSnapshotText",
        ):
            self._verify_pkg("artifacts/WinsVPN.pkg")

    def test_engine_without_provenance_fails_closed(self) -> None:
        self._stage_pkg(engine=True)
        with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "provenance"):
            self._verify_pkg("artifacts/WinsVPN.pkg")

    def test_incomplete_engine_set_fails_closed(self) -> None:
        self._stage_pkg(engine=True, provenance=True)
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "missing required engine framework"
        ):
            self._verify_pkg("artifacts/WinsVPN.pkg")

    def test_engine_digest_mismatch_fails_closed(self) -> None:
        self._stage_pkg(
            engine=True,
            provenance=True,
            engine_digest="0" * 64,
        )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "not bound to inner provenance"
        ):
            self._verify_pkg("artifacts/WinsVPN.pkg")

    def test_engine_hardlink_alias_cannot_hide_from_provenance(self) -> None:
        package = self._stage_pkg(engine=True, provenance=True)
        with self._private_root() as private:
            snapshot = apple_gate._snapshot_pkg(package, private.snapshot_file)
            expanded = private.root / "expanded"
            with mock.patch.object(
                apple_gate, "_bounded_subprocess", side_effect=self._authenticated_run()
            ):
                app, tree = apple_gate._expand_pkg(snapshot, expanded)
            original_app = expanded / apple_gate._lexical_relative(app, tree.root)
            engine = (
                original_app
                / "Contents"
                / "Frameworks"
                / "WinsAmneziaWGPacketEngine.framework"
                / "Versions"
                / "A"
                / "WinsAmneziaWGPacketEngine"
            )
            alias = (
                original_app
                / "Contents"
                / "Frameworks"
                / "libWinsAmneziaWGPacketEngine.dylib"
            )
            os.link(engine, alias)
            with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "hardlink"):
                apple_gate._inspect_macos_inner_payload(original_app, expanded)

    def test_second_engine_copy_with_different_digest_is_bound(self) -> None:
        other = self.binaries / "engine-other"
        _compile_dylib(
            other,
            body="int wins_other_engine(void) { return 2; }\n",
        )
        self._stage_pkg(
            engine=True,
            provenance=True,
            extra_files={
                "Contents/Frameworks/libWinsAmneziaWGPacketEngine.dylib": other.read_bytes()
            },
        )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "not bound to inner provenance"
        ):
            self._verify_pkg("artifacts/WinsVPN.pkg")

    def _resigned_engine(self, name: str, mutate=None) -> pathlib.Path:
        """A copy of self.engine re-signed the way staging and export re-sign it."""
        copy = self.binaries / name
        copy.write_bytes(self.engine.read_bytes())
        os.chmod(copy, 0o755)
        if mutate is not None:
            mutate(copy)
        _codesign_ad_hoc(copy, "--options", "runtime")
        return copy

    def _inner_provenance(self, package: pathlib.Path) -> dict[str, object]:
        # Inspect staged payload provenance independently of PKG expansion.
        app = self.repo / f"payload-{package.name}" / "Applications" / "Win's VPN.app"
        with self._private_root():
            with mock.patch.object(
                apple_gate, "_bounded_subprocess", side_effect=self._authenticated_run()
            ):
                return apple_gate._verify_inner_provenance(app)

    def test_gate_and_verifier_normalize_signatures_identically(self) -> None:
        resigned = self._resigned_engine("engine-resigned")
        flipped = self._resigned_engine("engine-flipped", _flip_text_byte)
        # As clang links it, before any strip: only the arm64 slice carries a
        # linker signature, which removing signatures alone cannot normalize.
        linked = self.binaries / "engine-linked"
        source = self.binaries / "engine-linked.c"
        source.write_text("int wins_linked_engine(int value) { return value + 7; }\n", encoding="utf-8")
        completed = REAL_RUN(
            ["/usr/bin/clang", "-dynamiclib", "-Os", "-arch", "arm64", "-arch", "x86_64",
             "-o", str(linked), str(source)],
            cwd="/", env=_tool_env(), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        linked_resigned = self.binaries / "engine-linked-resigned"
        linked_resigned.write_bytes(linked.read_bytes())
        _codesign_ad_hoc(linked_resigned, "--options", "runtime")
        self.assertNotEqual(
            hashlib.sha256(resigned.read_bytes()).digest(),
            hashlib.sha256(self.engine.read_bytes()).digest(),
        )
        engines = (self.engine, resigned, flipped, linked, linked_resigned)
        gate = {
            path.name: apple_gate._signature_normalized_sha256(path.read_bytes(), path.name)
            for path in engines
        }
        consumer = {
            path.name: _consumer_normalized_sha256(path, self.repo / ("consumer-" + path.name))
            for path in engines
        }
        self.assertEqual(gate, consumer)
        self.assertEqual(gate[self.engine.name], gate[resigned.name])
        self.assertEqual(gate[linked.name], gate[linked_resigned.name])
        self.assertNotEqual(gate[self.engine.name], gate[flipped.name])

    def test_resigned_engines_bind_through_their_signature_normalized_digest(self) -> None:
        normalized = apple_gate._signature_normalized_sha256(
            self.engine.read_bytes(), "fixture engine"
        )
        resigned = self._resigned_engine("engine-resigned")
        resigned_digest = hashlib.sha256(resigned.read_bytes()).hexdigest()
        self.assertNotEqual(resigned_digest, hashlib.sha256(self.engine.read_bytes()).hexdigest())
        package = self._stage_pkg(staged_engine=resigned, normalized_digest=normalized)
        provenance = self._inner_provenance(package)
        bindings = provenance["engine_bindings"]
        self.assertEqual(
            {binding["component"] for binding in bindings},
            {"amneziawg_packet_engine", "winn_packet_engine", "xray_vless_ws_transport"},
        )
        for binding in bindings:
            self.assertEqual(binding["sha256"], resigned_digest)
            self.assertEqual(binding["signature_normalized_sha256"], normalized)

    def test_unsigned_engine_binding_records_both_digests(self) -> None:
        package = self._stage_pkg()
        provenance = self._inner_provenance(package)
        raw = hashlib.sha256(self.engine.read_bytes()).hexdigest()
        normalized = apple_gate._signature_normalized_sha256(
            self.engine.read_bytes(), "fixture engine"
        )
        self.assertTrue(provenance["engine_bindings"])
        for binding in provenance["engine_bindings"]:
            self.assertEqual(binding["sha256"], raw)
            self.assertEqual(binding["signature_normalized_sha256"], normalized)

    def test_resigned_engine_without_a_matching_normalized_digest_fails_closed(self) -> None:
        normalized = apple_gate._signature_normalized_sha256(
            self.engine.read_bytes(), "fixture engine"
        )

        def thin(path: pathlib.Path) -> None:
            output = path.with_name(path.name + ".thin")
            completed = REAL_RUN(
                ["/usr/bin/lipo", str(path), "-thin", "arm64", "-output", str(output)],
                cwd="/", env=_tool_env(), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            os.replace(output, path)

        cases = (
            ("changed code byte", _flip_text_byte, normalized, "not bound to inner provenance"),
            ("changed slice set", thin, normalized, "not bound to inner provenance"),
            ("record without the normalized field", None, None, "not bound to inner provenance"),
            ("foreign normalized digest", None, "0" * 64, "not bound to inner provenance"),
            ("malformed normalized digest", None, "0" * 63, "signature-normalized digest is malformed"),
        )
        for index, (label, mutate, recorded, expected) in enumerate(cases):
            with self.subTest(label=label):
                staged = self._resigned_engine(f"engine-case-{index}", mutate)
                package = self._stage_pkg(
                    f"case-{index}.pkg", staged_engine=staged, normalized_digest=recorded
                )
                with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, expected):
                    self._inner_provenance(package)

    def test_outer_package_size_bound_fails_before_expand(self) -> None:
        self._stage_pkg()
        recorded: list[list[str]] = []
        with mock.patch.object(apple_gate, "MAX_PKG_BYTES", 16):
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "package bound|non-hardlinked"
            ):
                self._verify_pkg("artifacts/WinsVPN.pkg", recorded)
        self.assertFalse(
            any(argv[:2] == ["/usr/sbin/pkgutil", "--expand-full"] for argv in recorded)
        )

    def test_free_space_budget_fails_closed(self) -> None:
        self._stage_pkg()
        vfs = mock.Mock(f_frsize=4096, f_bavail=1)
        with mock.patch.object(apple_gate.os, "statvfs", return_value=vfs):
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "free-space"
            ):
                self._verify_pkg("artifacts/WinsVPN.pkg")

    def test_expand_child_is_resource_and_time_bounded(self) -> None:
        self._stage_pkg()
        captured: list[dict[str, object]] = []
        real_popen = apple_gate.subprocess.Popen

        def popen(argv, **kwargs):
            captured.append(dict(kwargs))
            return real_popen(argv, **kwargs)

        self._verify_pkg("artifacts/WinsVPN.pkg", popen_side_effect=popen)
        self.assertTrue(
            any(call.get("preexec_fn") is apple_gate._apply_child_rlimits for call in captured)
        )
        self.assertTrue(
            any(call.get("preexec_fn") is apple_gate._apply_tool_rlimits for call in captured)
        )
        self.assertTrue(all(call.get("start_new_session") for call in captured))
        self.assertTrue(
            all(
                call.get("env", {}).get("PATH") == apple_gate.REVIEWED_SUBPROCESS_PATH
                for call in captured
            )
        )
        self.assertTrue(
            all(
                set(call.get("env", {}))
                == {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"}
                for call in captured
            )
        )

    def test_ambient_path_extractor_is_not_invoked(self) -> None:
        evil = self.repo / "evil-bin"
        evil.mkdir()
        for name in ("pkgutil", "tar", "bsdtar", "xar", "cpio"):
            decoy = evil / name
            decoy.write_text("#!/bin/sh\necho PWNED >&2\nexit 99\n", encoding="utf-8")
            decoy.chmod(0o755)
        self._stage_pkg(name="path.pkg")
        recorded: list[list[str]] = []
        with mock.patch.dict(
            os.environ,
            {"PATH": f"{evil}{os.pathsep}{os.environ.get('PATH', '')}"},
            clear=False,
        ):
            self._verify_pkg("artifacts/path.pkg", recorded)
        self.assertTrue(recorded)
        for argv in recorded:
            self.assertNotEqual(pathlib.Path(argv[0]).parent, evil)

    def test_inner_payload_hash_changes_when_aot_changes(self) -> None:
        first = self._stage_pkg(name="first.pkg")
        second = self._stage_pkg(name="second.pkg", aot=self.aot_other)
        stdout = io.StringIO()
        with mock.patch.object(sys, "stdout", stdout):
            self._verify_pkg("artifacts/first.pkg")
            self._verify_pkg("artifacts/second.pkg")
        lines = [line for line in stdout.getvalue().splitlines() if "inner_payload_sha256=" in line]
        self.assertEqual(len(lines), 2)
        first_hash = [part for part in lines[0].split() if part.startswith("inner_payload_sha256=")][0]
        second_hash = [part for part in lines[1].split() if part.startswith("inner_payload_sha256=")][0]
        self.assertNotEqual(first_hash, second_hash)
        self.assertNotEqual(
            hashlib.sha256(first.read_bytes()).hexdigest(),
            hashlib.sha256(second.read_bytes()).hexdigest(),
        )

    def test_inner_payload_hash_binds_resources_plists_and_modes(self) -> None:
        first = self._stage_pkg(
            name="plist-a.pkg",
            extra_files={"Contents/Resources/note.txt": b"alpha"},
        )
        second = self._stage_pkg(
            name="plist-b.pkg",
            extra_files={"Contents/Resources/note.txt": b"bravo"},
        )
        stdout = io.StringIO()
        with mock.patch.object(sys, "stdout", stdout):
            self._verify_pkg("artifacts/plist-a.pkg")
            self._verify_pkg("artifacts/plist-b.pkg")
        lines = [line for line in stdout.getvalue().splitlines() if "inner_payload_sha256=" in line]
        self.assertEqual(len(lines), 2)
        hashes = [
            [part for part in line.split() if part.startswith("inner_payload_sha256=")][0]
            for line in lines
        ]
        self.assertNotEqual(hashes[0], hashes[1])

        with self._private_root() as private:
            snapshot = apple_gate._snapshot_pkg(first, private.snapshot_file)
            expanded = private.root / "expanded"
            with mock.patch.object(
                apple_gate, "_bounded_subprocess", side_effect=self._authenticated_run()
            ):
                app, tree = apple_gate._expand_pkg(snapshot, expanded)
            original_app = expanded / apple_gate._lexical_relative(app, tree.root)
            with mock.patch.object(
                apple_gate, "_bounded_subprocess", side_effect=self._authenticated_run()
            ):
                before = apple_gate._inspect_macos_inner_payload(original_app, expanded)
            note = original_app / "Contents" / "Resources" / "note.txt"
            os.chmod(note, 0o600)
            with mock.patch.object(
                apple_gate, "_bounded_subprocess", side_effect=self._authenticated_run()
            ):
                after = apple_gate._inspect_macos_inner_payload(original_app, expanded)
            self.assertNotEqual(before["inner_payload_sha256"], after["inner_payload_sha256"])
            tree_paths = {item["path"] for item in after["tree"]}
            self.assertTrue(any(path.endswith("Info.plist") for path in tree_paths))
            self.assertTrue(any(path.endswith("PrivacyInfo.xcprivacy") for path in tree_paths))
            self.assertTrue(any(path.endswith("note.txt") for path in tree_paths))
            note_records = [item for item in after["tree"] if str(item["path"]).endswith("note.txt")]
            self.assertEqual(len(note_records), 1)
            self.assertEqual(note_records[0]["type"], "file")
            self.assertEqual(note_records[0]["mode"], 0o600)
            self.assertEqual(note_records[0]["bytes"], len(b"alpha"))
            self.assertEqual(note_records[0]["sha256"], hashlib.sha256(b"alpha").hexdigest())
            for required in (
                "owner",
                "nlink",
                "device",
                "inode",
                "ctime_ns",
            ):
                self.assertIn(required, note_records[0])

    def test_snapshot_path_swap_restore_is_rejected_by_immutable_custody(self) -> None:
        first = self._stage_pkg(name="first.pkg")
        evil = self._stage_pkg(name="evil.pkg", aot=self.aot_other)
        original = first.read_bytes()
        evil_bytes = evil.read_bytes()
        original_digest = hashlib.sha256(original).hexdigest()
        evil_digest = hashlib.sha256(evil_bytes).hexdigest()
        aot_digest = hashlib.sha256(self.aot.read_bytes()).hexdigest()
        evil_aot = hashlib.sha256(self.aot_other.read_bytes()).hexdigest()
        real_expand = apple_gate._run_pkgutil_expand
        real_popen = apple_gate.subprocess.Popen

        def expand(snapshot, destination):
            def popen(argv, **kwargs):
                command = list(argv)
                if command[:2] != ["/usr/sbin/pkgutil", "--expand-full"]:
                    return real_popen(argv, **kwargs)
                path = snapshot.path
                os.chmod(path.parent, 0o700)
                backup = path.with_name("package.pkg.bak")
                os.rename(path, backup)
                path.write_bytes(evil_bytes)
                try:
                    return real_popen(argv, **kwargs)
                finally:
                    os.unlink(path)
                    os.rename(backup, path)
                    os.chmod(path.parent, 0o500)

            with mock.patch.object(apple_gate.subprocess, "Popen", side_effect=popen):
                return real_expand(snapshot, destination)

        stdout = io.StringIO()
        with mock.patch.object(sys, "stdout", stdout), mock.patch.object(
            apple_gate, "_run_pkgutil_expand", side_effect=expand
        ):
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError,
                "could not execute|identity|Operation not permitted",
            ):
                self._verify_pkg("artifacts/first.pkg")
        output = stdout.getvalue()
        self.assertNotIn("SIGNATURE GATE: PASS", output)
        self.assertNotIn(f"sha256={evil_digest}", output)
        self.assertNotIn(f"aot_sha256={evil_aot}", output)

    def test_uppercase_bundle_cannot_evade_allowlist(self) -> None:
        package = self._stage_pkg()
        with self._private_root() as private:
            snapshot = apple_gate._snapshot_pkg(package, private.snapshot_file)
            expanded = private.root / "expanded"
            with mock.patch.object(
                apple_gate, "_bounded_subprocess", side_effect=self._authenticated_run()
            ):
                apple_gate._expand_pkg(snapshot, expanded)
            payload = apple_gate._payload_directories(expanded)[0]
            helper = payload / "Applications" / "Helper.APP" / "Contents"
            helper.mkdir(parents=True)
            (helper / "Info.plist").write_bytes(_plist("org.winsvpn.app.Helper"))
            (helper / "Resources").mkdir()
            (helper / "Resources" / "PrivacyInfo.xcprivacy").write_bytes(
                _privacy(apple_gate.HOST_PRIVACY_API_REASONS, host_collection=True)
            )
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "allowlist|hidden app"
            ):
                apple_gate._exact_payload_app(expanded)

    def test_unreadable_directory_fails_closed(self) -> None:
        package = self._stage_pkg()
        with self._private_root() as private:
            snapshot = apple_gate._snapshot_pkg(package, private.snapshot_file)
            expanded = private.root / "expanded"
            with mock.patch.object(
                apple_gate, "_bounded_subprocess", side_effect=self._authenticated_run()
            ):
                apple_gate._expand_pkg(snapshot, expanded)
            locked = (
                apple_gate._payload_directories(expanded)[0]
                / "Applications"
                / "Win's VPN.app"
                / "Contents"
                / "Resources"
            )
            os.chmod(locked, 0o000)
            try:
                with self.assertRaisesRegex(
                    apple_gate.AppleArtifactGateError, "unreadable"
                ):
                    apple_gate._reject_unsafe_expansion(expanded)
            finally:
                os.chmod(locked, 0o755)

    def test_symlinked_engine_cannot_bypass_provenance(self) -> None:
        package = self._stage_pkg(engine=False, provenance=False)
        with self._private_root() as private:
            snapshot = apple_gate._snapshot_pkg(package, private.snapshot_file)
            expanded = private.root / "expanded"
            with mock.patch.object(
                apple_gate, "_bounded_subprocess", side_effect=self._authenticated_run()
            ):
                app, tree = apple_gate._expand_pkg(snapshot, expanded)
            original_app = expanded / apple_gate._lexical_relative(app, tree.root)
            engine_dir = (
                original_app
                / "Contents"
                / "Frameworks"
                / "WinsAmneziaWGPacketEngine.framework"
                / "Versions"
                / "A"
            )
            engine_dir.mkdir(parents=True)
            target = original_app / "Contents" / "Resources" / "hidden_engine"
            target.write_bytes(self.engine.read_bytes())
            os.chmod(target, 0o755)
            (engine_dir / "WinsAmneziaWGPacketEngine").symlink_to(
                "../../../../Resources/hidden_engine"
            )
            with mock.patch.object(
                apple_gate, "_bounded_subprocess", side_effect=self._authenticated_run()
            ):
                with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "provenance"):
                    apple_gate._inspect_macos_inner_payload(original_app, expanded)

    def test_one_slice_only_aot_symbols_fail_closed(self) -> None:
        arm = self.binaries / "aot-arm-only"
        x86 = self.binaries / "aot-x86-plain"
        mixed = self.binaries / "aot-one-slice"
        _compile_flutter_aot(arm, archs=("arm64",), include_symbols=True)
        _compile_flutter_aot(x86, archs=("x86_64",), include_symbols=False)
        completed = REAL_RUN(
            ["/usr/bin/lipo", "-create", str(arm), str(x86), "-output", str(mixed)],
            cwd="/",
            env=_tool_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self._stage_pkg(aot=mixed)
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "snapshot signature on x86_64|universal|Flutter AOT",
        ):
            self._verify_pkg("artifacts/WinsVPN.pkg")

    def test_expanded_tree_substitution_cannot_rebind_snapshot(self) -> None:
        package = self._stage_pkg()
        with self._private_root() as private:
            snapshot = apple_gate._snapshot_pkg(package, private.snapshot_file)
            expanded = private.root / "expanded"
            with mock.patch.object(
                apple_gate, "_bounded_subprocess", side_effect=self._authenticated_run()
            ):
                app, tree = apple_gate._expand_pkg(snapshot, expanded)
            original_app = expanded / apple_gate._lexical_relative(app, tree.root)
            original_aot = (
                original_app / "Contents" / "Frameworks" / "App.framework" / "App"
            )
            original_aot.write_bytes(self.aot_other.read_bytes())
            token = apple_gate._TREE_SNAPSHOT.set(tree)
            try:
                with mock.patch.object(
                    apple_gate,
                    "_bounded_subprocess",
                    side_effect=self._authenticated_run(),
                ):
                    inner = apple_gate._inspect_macos_inner_payload(app, tree.root)
            finally:
                apple_gate._TREE_SNAPSHOT.reset(token)
            self.assertEqual(
                inner["aot"]["sha256"], hashlib.sha256(self.aot.read_bytes()).hexdigest()
            )
            self.assertNotEqual(
                inner["aot"]["sha256"],
                hashlib.sha256(self.aot_other.read_bytes()).hexdigest(),
            )

    def test_duplicate_plist_keys_fail_closed(self) -> None:
        xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleIdentifier</key>
<string>org.winsvpn.app</string>
<key>CFBundleIdentifier</key>
<string>org.winsvpn.app.evil</string>
</dict>
</plist>
"""
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "Info.plist"
            path.write_bytes(xml)
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "duplicate key"
            ):
                apple_gate._read_plist(path, "host app")

    def test_expansion_bomb_fails_closed_before_pass(self) -> None:
        self._stage_pkg()
        recorded: list[list[str]] = []
        with mock.patch.object(apple_gate, "MAX_COMPRESSION_RATIO", 1), mock.patch.object(
            apple_gate, "MAX_OUTPUT_BYTES", 64
        ), mock.patch.object(apple_gate, "MAX_EXPANDED_BYTES", 64):
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError,
                "ratio|byte count|aggregate|package bound|free-space",
            ):
                self._verify_pkg("artifacts/WinsVPN.pkg", recorded)
        self.assertFalse(
            any("APPLE CROSS-STORE SIGNATURE GATE: PASS" in str(argv) for argv in recorded)
        )

    def test_unsigned_pkg_is_unverified_not_pass(self) -> None:
        self._stage_pkg(name="unsigned.pkg")
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(apple_gate, "ROOT", self.repo), mock.patch.object(
            sys, "stdout", stdout
        ), mock.patch.object(sys, "stderr", stderr), mock.patch.object(
            apple_gate,
            "_macos_descendant_boundary_argv",
            side_effect=lambda argv: list(argv),
        ):
            with self.assertRaises(apple_gate.AppleArtifactUnverified):
                apple_gate.verify_signature(
                    "macos-app-store-pkg", "artifacts/unsigned.pkg"
                )
            code = apple_gate.main(
                ["signature", "macos-app-store-pkg", "artifacts/unsigned.pkg"]
            )
        self.assertEqual(code, 2)
        self.assertIn("UNVERIFIED", stderr.getvalue())
        self.assertNotIn("SIGNATURE GATE: PASS", stdout.getvalue())

    def test_missing_volfs_is_owner_environment_blocked(self) -> None:
        package = self._stage_pkg()
        with self._private_root() as private:
            snapshot = apple_gate._snapshot_pkg(package, private.snapshot_file)
            with mock.patch.object(apple_gate, "VOLFS_ROOT", pathlib.Path("/no/such/vol")):
                with self.assertRaisesRegex(
                    apple_gate.AppleArtifactGateError, "owner/environment blocker"
                ):
                    snapshot.kernel_path()

    def test_private_snapshot_is_read_only_immutable_and_full_identity_bound(self) -> None:
        package = self._stage_pkg()
        with self._private_root() as private:
            snapshot = apple_gate._snapshot_pkg(package, private.snapshot_file)
            try:
                flags = fcntl.fcntl(snapshot.fd, fcntl.F_GETFL)
                info = os.fstat(snapshot.fd)
                parent = os.fstat(snapshot.parent_fd)
                self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o400)
                self.assertEqual(info.st_nlink, 1)
                self.assertEqual(
                    apple_gate._snapshot_file_identity(info), snapshot.identity
                )
                self.assertEqual(
                    apple_gate._snapshot_directory_identity(parent),
                    snapshot.parent_identity,
                )
                if apple_gate.UF_IMMUTABLE:
                    self.assertTrue(info.st_flags & apple_gate.UF_IMMUTABLE)
                    self.assertTrue(parent.st_flags & apple_gate.UF_IMMUTABLE)
                with self.assertRaises(OSError):
                    os.open(
                        snapshot.path,
                        os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                    )
                snapshot.rehash()
            finally:
                snapshot.close()

    def test_held_pkg_api_runs_full_gate_on_the_exact_private_snapshot(self) -> None:
        package = self._stage_pkg()
        source_fd = os.open(
            package, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        parent_fd = os.open(
            package.parent,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
        )
        info = os.fstat(source_fd)
        digest = hashlib.sha256(os.pread(source_fd, info.st_size, 0)).hexdigest()
        recorded: list[list[str]] = []
        macos_independent = {
            "contract": apple_gate.MACOS_INDEPENDENT_VERIFIER_CONTRACT,
            "artifact_sha256": digest,
            "verifier": {
                "path": "tools/verify_macos_release_artifact.py",
                "sha256": apple_gate.HELD_ARTIFACT_REVIEW_SOURCE_SHA256[
                    "verify_macos_release_artifact.py"
                ],
            },
            "result": {"artifact_sha256": digest},
            "result_sha256": _receipt_digest("held-live-independent"),
        }
        try:
            with mock.patch.object(apple_gate, "ROOT", self.repo), mock.patch.object(
                apple_gate,
                "_bounded_subprocess",
                side_effect=self._authenticated_run(recorded),
            ), mock.patch.object(
                apple_gate,
                "_verify_macos_independent_snapshot",
                return_value=macos_independent,
            ):
                held = apple_gate.verify_held_release_artifact(
                    target_id="macos-app-store-pkg",
                    source_fd=source_fd,
                    source_parent_fd=parent_fd,
                    source_name=package.name,
                    source_relative_path=package.relative_to(self.repo).as_posix(),
                    expected_identity=apple_gate._held_artifact_identity(info),
                    expected_size=info.st_size,
                    expected_sha256=digest,
                    frozen_release=apple_gate.CANONICAL_RELEASE,
                )
                result: dict[str, object] = {}
                held.consume(lambda evidence: result.update(evidence))
        finally:
            os.close(parent_fd)
            os.close(source_fd)
        self.assertEqual(result["contract"], apple_gate.HELD_ARTIFACT_CONTRACT)
        self.assertEqual(result["artifact_sha256"], digest)
        self.assertEqual(result["artifact_bytes"], info.st_size)
        self.assertIn("inner_payload", result)
        original = os.fspath(package)
        for command in recorded:
            if command[:2] in (
                ["/usr/sbin/pkgutil", "--check-signature"],
                ["/usr/sbin/pkgutil", "--expand-full"],
            ):
                self.assertNotIn(original, command)


def _receipt_digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _watch_verification(artifact_sha256: str, artifact_bytes: int) -> dict[str, object]:
    result = {
        "schema_version": 1,
        "bundle_id": apple_gate.WATCH_BUNDLE_ID,
        "companion_bundle_id": apple_gate.HOST_BUNDLE_ID,
        "version": apple_gate.CANONICAL_MARKETING_VERSION,
        "build_number": apple_gate.CANONICAL_BUNDLE_VERSION,
        "parent_version": apple_gate.CANONICAL_MARKETING_VERSION,
        "parent_build_number": apple_gate.CANONICAL_BUNDLE_VERSION,
        "ipa_sha256": artifact_sha256,
        "ipa_bytes": artifact_bytes,
        "executable": apple_gate.WATCH_EXECUTABLE,
        "executable_sha256": _receipt_digest("watch-exec"),
        "architectures": ["arm64", "arm64_32"],
        "watch_connectivity_dependency": "/System/Library/Frameworks/WatchConnectivity.framework/WatchConnectivity",
        "wc_session_import": "_OBJC_CLASS_$_WCSession",
        "required_selectors": ["activationState", "isReachable", "receivedApplicationContext", "sendMessage:replyHandler:errorHandler:", "session:activationDidCompleteWithState:error:", "session:didReceiveApplicationContext:", "session:didReceiveMessage:", "sessionReachabilityDidChange:"],
        "privacy_manifest_sha256": _receipt_digest("watch-privacy"),
        "debug_sections": False,
    }
    return {
        "contract": "winsvpn-watch-artifact-verification-v1",
        "artifact_sha256": artifact_sha256,
        "verifier": {
            "path": apple_gate.WATCH_ARTIFACT_VERIFIER_RELATIVE,
            "sha256": _receipt_digest("watch-verifier"),
            "reviewed_verifier": True,
        },
        "result": result,
        "result_sha256": apple_gate._canonical_json_sha256(result),
    }


def _dummy_authentication(
    target_id: str, *, digest: str, size: int, architectures: list[str]
) -> dict[str, object]:
    return {
        "authenticated": True,
        "issuer": apple_gate.UPLOAD_RECEIPT_ISSUER,
        "run_id": "a" * 64,
        "nonce": "b" * 64,
        "issued_at": apple_gate._upload_receipt_now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "challenge": "c" * 128,
        "target_id": target_id,
        "architectures": list(architectures),
        "release": apple_gate.CANONICAL_RELEASE,
        "artifact_sha256": digest,
        "artifact_bytes": size,
    }


class AppleHeldArtifactBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="wins-apple-held-boundary-", dir="/private/tmp"
        )
        self.repo = pathlib.Path(self.temporary.name)
        self.artifacts = self.repo / "artifacts"
        self.artifacts.mkdir()
        identity = self.repo / apple_gate.RELEASE_IDENTITY_RELATIVE_PATH
        identity.parent.mkdir(parents=True)
        identity.write_bytes(
            (ROOT / apple_gate.RELEASE_IDENTITY_RELATIVE_PATH).read_bytes()
        )
        self.pkg = self.artifacts / "WinsVPN-1.0.17+34-macos-app-store.pkg"
        self.pkg.write_bytes(b"synthetic-held-pkg-boundary\n")
        self.ipa = self.artifacts / "WinsVPN-1.0.17+34-ios-app-store.ipa"
        self.ipa.write_bytes(b"PK\x03\x04synthetic-held-ipa-boundary\n")
        # The gate must never consult the owner-provisioned source-freeze trust
        # file; any call fails the test.
        self._freeze_patch = mock.patch.object(
            apple_gate.source_freeze,
            "verified_release_source_state",
            side_effect=AssertionError("gate consulted the source-freeze trust file"),
        )
        self._freeze_patch.start()

    def tearDown(self) -> None:
        self._freeze_patch.stop()
        self.temporary.cleanup()

    @staticmethod
    def _inner_payload() -> dict[str, object]:
        return {
            "app": "Payload/Applications/Win's VPN.app",
            "inner_payload_sha256": _receipt_digest("held-inner-payload"),
            "aot": {"sha256": _receipt_digest("held-aot")},
            "native_messaging": {
                "incompatible": True,
                "delivered": False,
            },
        }

    def _verify(
        self,
        target_id: str,
        artifact: pathlib.Path,
        *,
        writable: bool = False,
        source_name: str | None = None,
        source_relative_path: str | None = None,
        expected_identity: tuple[int, ...] | None = None,
        expected_size: int | None = None,
        expected_sha256: str | None = None,
        frozen_release: str = apple_gate.CANONICAL_RELEASE,
        pkg_side_effect=None,
        extra_patches: tuple[object, ...] = (),
        return_held: bool = False,
    ) -> dict[str, object] | apple_gate.HeldAppleArtifactEvidence:
        flags = os.O_RDWR if writable else os.O_RDONLY
        source_fd = os.open(artifact, flags | os.O_CLOEXEC | os.O_NOFOLLOW)
        parent_fd = os.open(
            artifact.parent,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
        )
        info = os.fstat(source_fd)
        digest = hashlib.sha256(os.pread(source_fd, info.st_size, 0)).hexdigest()
        name = artifact.name if source_name is None else source_name
        relative = (
            artifact.relative_to(self.repo).as_posix()
            if source_relative_path is None
            else source_relative_path
        )

        def verify_pkg(_target_id, _artifact, _private, **_kwargs):
            if pkg_side_effect is not None:
                return pkg_side_effect(
                    _target_id, _artifact, _private, digest=digest, **_kwargs
                )
            return pathlib.Path("held.app"), self._inner_payload(), digest

        watch = _watch_verification(digest, info.st_size)
        watch["verifier"]["sha256"] = (
            apple_gate.HELD_ARTIFACT_REVIEW_SOURCE_SHA256[
                "apple_watch_artifact_verifier.py"
            ]
        )
        macos_independent = {
            "contract": apple_gate.MACOS_INDEPENDENT_VERIFIER_CONTRACT,
            "artifact_sha256": digest,
            "verifier": {
                "path": "tools/verify_macos_release_artifact.py",
                "sha256": apple_gate.HELD_ARTIFACT_REVIEW_SOURCE_SHA256[
                    "verify_macos_release_artifact.py"
                ],
            },
            "result": {"artifact_sha256": digest},
            "result_sha256": _receipt_digest("macos-independent"),
        }
        try:
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(apple_gate, "ROOT", self.repo))
                stack.enter_context(
                    mock.patch.object(
                        apple_gate, "_verify_pkg_target", side_effect=verify_pkg
                    )
                )
                stack.enter_context(mock.patch.object(apple_gate, "_extract_zip"))
                stack.enter_context(
                    mock.patch.object(
                        apple_gate, "_one_app", return_value=pathlib.Path("held.app")
                    )
                )
                stack.enter_context(mock.patch.object(apple_gate, "_verify_bundle"))
                stack.enter_context(
                    mock.patch.object(apple_gate, "_seal_extracted_bundle_tree")
                )
                stack.enter_context(mock.patch.object(apple_gate, "_verify_codesign"))
                stack.enter_context(
                    mock.patch.object(
                        apple_gate,
                        "_verify_macos_independent_snapshot",
                        return_value=macos_independent,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        apple_gate,
                        "verify_watch_artifact_snapshot",
                        return_value=watch,
                    )
                )
                for patcher in extra_patches:
                    stack.enter_context(patcher)
                held = apple_gate.verify_held_release_artifact(
                    target_id=target_id,
                    source_fd=source_fd,
                    source_parent_fd=parent_fd,
                    source_name=name,
                    source_relative_path=relative,
                    expected_identity=(
                        apple_gate._held_artifact_identity(info)
                        if expected_identity is None
                        else expected_identity
                    ),
                    expected_size=(info.st_size if expected_size is None else expected_size),
                    expected_sha256=(
                        digest if expected_sha256 is None else expected_sha256
                    ),
                    frozen_release=frozen_release,
                )
                if return_held:
                    return held
                result: dict[str, object] = {}
                held.consume(lambda evidence: result.update(evidence))
                return result
        finally:
            os.close(parent_fd)
            os.close(source_fd)

    def test_held_pkg_and_ipa_return_canonical_nonpublication_evidence(self) -> None:
        pkg = self._verify("macos-app-store-pkg", self.pkg)
        self.assertEqual(pkg["contract"], apple_gate.HELD_ARTIFACT_CONTRACT)
        self.assertEqual(pkg["release"], apple_gate.CANONICAL_RELEASE)
        self.assertEqual(pkg["platform"], "macos")
        self.assertEqual(pkg["publication_authorized"], False)
        self.assertEqual(pkg["upload_attempted"], False)
        self.assertEqual(pkg["owner_authorization"], "pending")
        self.assertEqual(
            pkg["artifact_sha256"], hashlib.sha256(self.pkg.read_bytes()).hexdigest()
        )
        self.assertIn("inner_payload", pkg)
        review = pkg["authenticated_source_closure"]["independent_review"]
        self.assertEqual(
            review,
            dict(sorted(apple_gate.HELD_ARTIFACT_REVIEW_SOURCE_SHA256.items())),
        )

        ipa = self._verify("ios-app-store-ipa", self.ipa)
        self.assertEqual(ipa["platform"], "ios")
        self.assertEqual(ipa["architectures"], ["arm64"])
        self.assertEqual(
            ipa["watchos"]["artifact_sha256"], ipa["artifact_sha256"]
        )

    def test_held_api_rejects_writable_fd_and_binding_drift(self) -> None:
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "exact O_RDONLY"
        ):
            self._verify("macos-app-store-pkg", self.pkg, writable=True)
        info = self.pkg.stat()
        identity = list(apple_gate._held_artifact_identity(info))
        identity[1] += 1
        cases = (
            {"expected_identity": tuple(identity)},
            {"expected_size": info.st_size + 1},
            {"expected_sha256": "0" * 64},
            {"frozen_release": "1.0.14+29"},
        )
        for arguments in cases:
            with self.subTest(arguments=arguments), self.assertRaises(
                apple_gate.AppleArtifactGateError
            ):
                self._verify("macos-app-store-pkg", self.pkg, **arguments)
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "unsupported exact held Apple"
        ):
            self._verify("macos-developer-id-app", self.pkg)

    def test_held_api_rejects_symlink_hardlink_and_cross_candidate(self) -> None:
        hardlink = self.artifacts / "hardlink.pkg"
        os.link(self.pkg, hardlink)
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "single-link|identity is not exact"
        ):
            self._verify("macos-app-store-pkg", self.pkg)
        hardlink.unlink()

        alias = self.artifacts / "alias.pkg"
        alias.symlink_to(self.pkg.name)
        source_fd = os.open(self.pkg, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        parent_fd = os.open(
            self.artifacts,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
        )
        info = os.fstat(source_fd)
        try:
            with mock.patch.object(apple_gate, "ROOT", self.repo), self.assertRaises(
                apple_gate.AppleArtifactGateError
            ):
                apple_gate.verify_held_release_artifact(
                    target_id="macos-app-store-pkg",
                    source_fd=source_fd,
                    source_parent_fd=parent_fd,
                    source_name=alias.name,
                    source_relative_path=alias.relative_to(self.repo).as_posix(),
                    expected_identity=apple_gate._held_artifact_identity(info),
                    expected_size=info.st_size,
                    expected_sha256=hashlib.sha256(self.pkg.read_bytes()).hexdigest(),
                    frozen_release=apple_gate.CANONICAL_RELEASE,
                )
        finally:
            os.close(parent_fd)
            os.close(source_fd)

        other = self.artifacts / "other.pkg"
        other.write_bytes(self.pkg.read_bytes())
        other_info = other.stat()
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "identity is not exact"
        ):
            self._verify(
                "macos-app-store-pkg",
                self.pkg,
                source_name=other.name,
                source_relative_path=other.relative_to(self.repo).as_posix(),
                expected_identity=apple_gate._held_artifact_identity(other_info),
            )

    def test_same_byte_name_swap_restore_is_rejected(self) -> None:
        payload = self.pkg.read_bytes()

        def swap(_target, _artifact, _private, *, digest, **_kwargs):
            backup = self.artifacts / "candidate.saved"
            os.rename(self.pkg, backup)
            self.pkg.write_bytes(payload)
            self.pkg.unlink()
            os.rename(backup, self.pkg)
            return pathlib.Path("held.app"), self._inner_payload(), digest

        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "changed|substituted|identity"
        ):
            self._verify(
                "macos-app-store-pkg", self.pkg, pkg_side_effect=swap
            )

    def test_parent_swap_restore_is_rejected(self) -> None:
        payload = self.pkg.read_bytes()

        def swap_parent(_target, _artifact, _private, *, digest, **_kwargs):
            backup = self.repo / "artifacts.saved"
            os.rename(self.artifacts, backup)
            self.artifacts.mkdir()
            (self.artifacts / self.pkg.name).write_bytes(payload)
            (self.artifacts / self.pkg.name).unlink()
            self.artifacts.rmdir()
            os.rename(backup, self.artifacts)
            return pathlib.Path("held.app"), self._inner_payload(), digest

        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "changed|substituted|ancestor"
        ):
            self._verify(
                "macos-app-store-pkg", self.pkg, pkg_side_effect=swap_parent
            )

    def test_final_evidence_window_mutation_is_rejected(self) -> None:
        original = self.pkg.read_bytes()
        artifact = self.pkg

        class MutatingDigests(dict):
            triggered = False

            def __getitem__(self, key):
                if not self.triggered:
                    self.triggered = True
                    artifact.write_bytes(b"X" * len(original))
                return super().__getitem__(key)

        poisoned = MutatingDigests(apple_gate._MODULE_DIGESTS)
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "changed|SHA-256|identity"
        ):
            self._verify(
                "macos-app-store-pkg",
                self.pkg,
                extra_patches=(
                    mock.patch.object(apple_gate, "_MODULE_DIGESTS", poisoned),
                ),
            )

    def test_tool_and_module_poisoning_cannot_replace_reviewed_closure(self) -> None:
        fake = type(sys)("verify_macos_release_artifact")
        fake.verify_release = lambda *_args, **_kwargs: {"ok": True}
        with mock.patch.dict(
            sys.modules, {"verify_macos_release_artifact": fake}, clear=False
        ), mock.patch.dict(
            os.environ,
            {"PATH": "/attacker/bin", "PYTHONPATH": "/attacker/python"},
            clear=False,
        ):
            result = self._verify("macos-app-store-pkg", self.pkg)
        review = result["authenticated_source_closure"]["independent_review"]
        self.assertEqual(
            review["verify_macos_release_artifact.py"],
            hashlib.sha256(
                (ROOT / "tools/verify_macos_release_artifact.py").read_bytes()
            ).hexdigest(),
        )
        with mock.patch.dict(
            apple_gate.HELD_ARTIFACT_REVIEW_SOURCE_SHA256,
            {"verify_macos_release_artifact.py": "0" * 64},
            clear=False,
        ), self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "review is stale"
        ):
            self._verify("macos-app-store-pkg", self.pkg)

    def test_held_api_does_not_reopen_caller_leaf_path(self) -> None:
        real_open = apple_gate.os.open
        forbidden = os.fspath(self.pkg)

        def guarded_open(path, *args, **kwargs):
            if isinstance(path, (str, bytes, os.PathLike)) and os.fspath(path) == forbidden:
                raise AssertionError("caller artifact pathname was reopened")
            return real_open(path, *args, **kwargs)

        result = self._verify(
            "macos-app-store-pkg",
            self.pkg,
            extra_patches=(mock.patch.object(apple_gate.os, "open", guarded_open),),
        )
        self.assertTrue(result["ok"])

    def test_returned_evidence_retains_custody_and_rejects_write_restore(self) -> None:
        held = self._verify(
            "macos-app-store-pkg", self.pkg, return_held=True
        )
        self.assertIsInstance(held, apple_gate.HeldAppleArtifactEvidence)
        self.assertFalse(held.closed)
        before = self.pkg.stat()
        original = self.pkg.read_bytes()
        self.pkg.write_bytes(b"R" * len(original))
        self.pkg.write_bytes(original)
        os.utime(
            self.pkg,
            ns=(before.st_atime_ns, before.st_mtime_ns),
            follow_symlinks=False,
        )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "changed|SHA-256|identity|verification",
        ):
            held.consume(lambda _evidence: None)
        self.assertTrue(held.closed)
        self.assertFalse(apple_gate._ACTIVE_HELD_EVIDENCE_KEYS)

    def test_returned_evidence_rejects_metadata_restore_and_overlap_replay(self) -> None:
        held = self._verify(
            "macos-app-store-pkg", self.pkg, return_held=True
        )
        self.assertIsInstance(held, apple_gate.HeldAppleArtifactEvidence)
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "overlap|replay"
        ):
            self._verify("ios-app-store-ipa", self.ipa, return_held=True)
        before = self.pkg.stat()
        os.chmod(self.pkg, 0o400)
        os.chmod(self.pkg, stat.S_IMODE(before.st_mode))
        os.utime(
            self.pkg,
            ns=(before.st_atime_ns, before.st_mtime_ns),
            follow_symlinks=False,
        )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "changed|identity|verification"
        ):
            held.close(verify=True)
        self.assertTrue(held.closed)
        self.assertFalse(apple_gate._ACTIVE_HELD_EVIDENCE_KEYS)

    def test_evidence_consume_is_one_shot_and_closes_all_descriptors(self) -> None:
        before_count = len(os.listdir("/dev/fd"))
        held = self._verify(
            "macos-app-store-pkg", self.pkg, return_held=True
        )
        self.assertIsInstance(held, apple_gate.HeldAppleArtifactEvidence)
        snapshot_fd = held._snapshot.fd
        digest = held.consume(lambda evidence: evidence["artifact_sha256"])
        self.assertEqual(digest, hashlib.sha256(self.pkg.read_bytes()).hexdigest())
        self.assertTrue(held.closed)
        with self.assertRaises(OSError):
            fcntl.fcntl(snapshot_fd, fcntl.F_GETFD)
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "already consumed"
        ):
            held.consume(lambda _evidence: None)
        self.assertEqual(len(os.listdir("/dev/fd")), before_count)
        self.assertFalse(apple_gate._ACTIVE_HELD_EVIDENCE_KEYS)


class ReviewedVerifierIsolationTests(unittest.TestCase):
    @staticmethod
    def _watch_namespace(result: dict[str, object]) -> dict[str, object]:
        namespace: dict[str, object] = {"RESULT": result}
        exec("def verify_ipa(_path):\n    return RESULT\n", namespace)
        return namespace

    @staticmethod
    def _bind_reviewed_watch_source(source: bytes):
        return mock.patch.dict(
            apple_gate.HELD_ARTIFACT_REVIEW_SOURCE_SHA256,
            {
                "apple_watch_artifact_verifier.py": hashlib.sha256(source).hexdigest()
            },
        )

    def test_watch_verifier_ignores_ambient_interpreter_and_module_poisoning(self) -> None:
        digest = _receipt_digest("isolated-watch-ipa")
        result = _watch_verification(digest, 41)["result"]
        source = b"reviewed-watch-test-source\n"
        namespace = self._watch_namespace(dict(result))
        fake_subprocess = type(sys)("subprocess")
        fake_subprocess.run = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("poisoned subprocess executed")
        )
        with mock.patch.object(
            apple_gate,
            "_isolated_reviewed_source_namespace",
            return_value=namespace,
        ), self._bind_reviewed_watch_source(
            source
        ), mock.patch.object(
            apple_gate.subprocess,
            "Popen",
            side_effect=AssertionError("ambient interpreter subprocess executed"),
        ), mock.patch.object(
            apple_gate.sys, "executable", "/attacker/fake-python"
        ), mock.patch.dict(
            sys.modules,
            {"subprocess": fake_subprocess},
            clear=False,
        ):
            evidence = apple_gate.verify_watch_artifact_snapshot(
                pathlib.Path("/held/ipa"),
                artifact_sha256=digest,
                artifact_size=41,
                verifier_source=source,
                expected_verifier_sha256=hashlib.sha256(source).hexdigest(),
            )
        self.assertEqual(evidence["artifact_sha256"], digest)
        self.assertEqual(evidence["result"], result)
        self.assertIs(evidence["verifier"]["reviewed_verifier"], True)

    def test_watch_verifier_requires_external_hash_and_rejects_self_hash_authority(
        self,
    ) -> None:
        source = b"reviewed-watch-required-hash\n"
        digest = _receipt_digest("required-watch-hash")
        with self.assertRaises(TypeError):
            apple_gate.verify_watch_artifact_snapshot(
                pathlib.Path("/held/ipa"),
                artifact_sha256=digest,
                verifier_source=source,
            )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "externally authenticated source closure",
        ):
            apple_gate.verify_watch_artifact_snapshot(
                pathlib.Path("/held/ipa"),
                artifact_sha256=digest,
                verifier_source=source,
                expected_verifier_sha256="0" * 64,
            )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "externally authenticated source closure",
        ):
            apple_gate.verify_watch_artifact_snapshot(
                pathlib.Path("/held/ipa"),
                artifact_sha256=digest,
                verifier_source=source,
                expected_verifier_sha256=hashlib.sha256(source).hexdigest(),
            )

    def test_watch_verifier_rejects_nonfinite_result_data(self) -> None:
        digest = _receipt_digest("watch-nonfinite")
        result = _watch_verification(digest, 31)["result"]
        result["ipa_bytes"] = float("nan")
        source = b"reviewed-watch-nonfinite-source\n"
        with mock.patch.object(
            apple_gate,
            "_isolated_reviewed_source_namespace",
            return_value=self._watch_namespace(result),
        ), self._bind_reviewed_watch_source(
            source
        ), self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "nonfinite"
        ):
            apple_gate.verify_watch_artifact_snapshot(
                pathlib.Path("/held/ipa"),
                artifact_sha256=digest,
                artifact_size=31,
                verifier_source=source,
                expected_verifier_sha256=hashlib.sha256(source).hexdigest(),
            )

    def test_watch_verifier_rejects_every_authoritative_field_substitution(self) -> None:
        digest = _receipt_digest("watch-semantic-fields")
        valid = _watch_verification(digest, 53)["result"]
        source = b"reviewed-watch-semantic-source\n"
        mutations = {
            "schema_version": 2,
            "bundle_id": "org.attacker.watch",
            "companion_bundle_id": "org.attacker.host",
            "version": "9.9.9",
            "build_number": "999",
            "parent_version": "9.9.9",
            "parent_build_number": "999",
            "ipa_sha256": "0" * 64,
            "ipa_bytes": 54,
            "executable": "FakeWatch",
            "executable_sha256": "not-a-digest",
            "architectures": [],
            "watch_connectivity_dependency": "/tmp/WatchConnectivity",
            "wc_session_import": "_OBJC_CLASS_$_FakeSession",
            "required_selectors": [],
            "privacy_manifest_sha256": "not-a-digest",
            "debug_sections": True,
        }
        for field, replacement in mutations.items():
            poisoned = dict(valid)
            poisoned[field] = replacement
            namespace = self._watch_namespace(poisoned)
            with self.subTest(field=field), mock.patch.object(
                apple_gate,
                "_isolated_reviewed_source_namespace",
                return_value=namespace,
            ), self._bind_reviewed_watch_source(
                source
            ), self.assertRaises(apple_gate.AppleArtifactGateError):
                apple_gate.verify_watch_artifact_snapshot(
                    pathlib.Path("/held/ipa"),
                    artifact_sha256=digest,
                    artifact_size=53,
                    verifier_source=source,
                    expected_verifier_sha256=hashlib.sha256(source).hexdigest(),
                )

    def test_exact_macos_review_source_executes_without_sys_path_or_pyc_lookup(self) -> None:
        custody = apple_gate._HeldSupportSources(
            (("verify_macos_release_artifact.py", "macos_release_artifact_verifier"),)
        )
        try:
            source = custody.payloads["verify_macos_release_artifact.py"]
            digest = custody.digests["verify_macos_release_artifact.py"]
            fake = type(sys)("verify_macos_release_artifact")
            fake.audit_code_topology = lambda *_args: {"ok": True}
            with tempfile.TemporaryDirectory(prefix="wins-pyc-poison-") as temporary:
                artifact = pathlib.Path(temporary, "held.pkg")
                artifact.write_bytes(b"exact held independent verifier bytes")
                pathlib.Path(
                    temporary, "verify_macos_release_artifact.pyc"
                ).write_bytes(b"poisoned-pyc")
                with mock.patch.dict(
                    sys.modules,
                    {"verify_macos_release_artifact": fake},
                    clear=False,
                ), mock.patch.object(
                    sys, "path", [temporary]
                ):
                    namespace = apple_gate._isolated_reviewed_source_namespace(
                        source,
                        logical_path=ROOT / "tools" / "verify_macos_release_artifact.py",
                        expected_sha256=digest,
                        label="macOS independent artifact verifier",
                    )
                    self.assertEqual(
                        namespace["sha256_file"](artifact),
                        hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    )
            entry = namespace["audit_code_topology"]
            self.assertIsInstance(entry, type(lambda: None))
            self.assertIs(entry.__globals__, namespace)
            self.assertIsNot(entry, fake.audit_code_topology)
            custody.verify()
        finally:
            custody.close(verify=True)


class MacOSExactArchitectureTests(unittest.TestCase):
    def _architectures(self, output: str) -> tuple[str, ...]:
        completed = subprocess.CompletedProcess(
            ["/usr/bin/lipo", "-archs"], 0, output, ""
        )
        with mock.patch.object(
            apple_gate, "_run_on_path", return_value=completed
        ):
            return apple_gate._macho_architectures(pathlib.Path("required-image"))

    def test_every_required_image_requires_exact_arm64_x86_64(self) -> None:
        self.assertEqual(
            set(self._architectures("arm64 x86_64\n")), {"arm64", "x86_64"}
        )
        for thin in ("arm64\n", "x86_64\n"):
            with self.subTest(thin=thin.strip()), self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError,
                "exact arm64 plus x86_64",
            ):
                self._architectures(thin)

    def test_mixed_thin_images_cannot_satisfy_a_union_inventory(self) -> None:
        hostile_images = {
            "host-executable": "arm64\n",
            "engine-framework": "x86_64\n",
        }
        accepted: list[str] = []
        for name, output in hostile_images.items():
            with self.subTest(image=name), self.assertRaises(
                apple_gate.AppleArtifactGateError
            ):
                accepted.extend(self._architectures(output))
        self.assertEqual(accepted, [])


class NativeHostAuthenticatedHandshakeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.host = pathlib.Path(self.temporary.name) / "wins_bridge_host"
        self.host.write_bytes(b"host")
        self.host.chmod(0o700)
        self.candidate = {
            "path": apple_gate.NATIVE_HOST_BASENAME,
            "sha256": hashlib.sha256(b"host").hexdigest(),
            "bytes": 4,
            "architectures": sorted(apple_gate.REQUIRED_MACOS_ARCHITECTURES),
            "installed_host_path": apple_gate.MACOS_NATIVE_HOST_SYSTEM_PATH,
            "source_closure_sha256": _receipt_digest("native-source"),
            "team_id": apple_gate.TEAM_ID,
            "notarized": True,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _run_handshake(self, reply_builder, *, before_reply=None):
        executed: list[str] = []

        def bounded(argv, _label, **kwargs):
            command = list(argv)
            executed.append(command[0])
            self.assertNotEqual(command[0], str(self.host))
            self.assertEqual(pathlib.Path(command[0]).read_bytes(), b"host")
            if before_reply is not None:
                before_reply(command)
            framed = kwargs["input_data"]
            size = struct.unpack("<I", framed[:4])[0]
            request = json.loads(framed[4 : 4 + size].decode("ascii"))
            reply = reply_builder(request)
            if type(reply) is bytes:
                payload = reply
            else:
                payload = json.dumps(
                    reply, separators=(",", ":"), ensure_ascii=True
                ).encode("ascii")
            return subprocess.CompletedProcess(
                [str(self.host)], 0, struct.pack("<I", len(payload)) + payload, b""
            )

        def verify(snapshot_path, **kwargs):
            self.assertNotEqual(snapshot_path, self.host)
            self.assertEqual(snapshot_path.read_bytes(), b"host")
            self.assertEqual(
                kwargs,
                {
                    "require_signature": True,
                    "require_notarization": True,
                    "require_source_closure": True,
                },
            )
            return dict(self.candidate)

        with mock.patch.object(
            apple_gate,
            "verify_macos_native_host_binary",
            side_effect=verify,
        ) as verify, mock.patch.object(
            apple_gate, "_bounded_subprocess", side_effect=bounded
        ):
            result = apple_gate.macos_native_host_handshake(self.host)
        verify.assert_called_once()
        self.assertEqual(len(executed), 1)
        return result

    def test_handshake_requires_authenticated_closure_and_exact_reply(self) -> None:
        def reply(request):
            return {
                **request,
                "accepted": True,
            }

        result = self._run_handshake(reply)
        self.assertEqual(result["protocol_version"], 1)
        self.assertRegex(result["request_id"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            result["candidate_binding"]["sha256"], self.candidate["sha256"]
        )

    def test_handshake_arm64_exception_is_release_scoped_and_exact(self) -> None:
        self.candidate["architectures"] = ["arm64"]
        with mock.patch.object(apple_gate, "native_host_release_line", return_value="1.0.17"):
            result = self._run_handshake(lambda request: {**request, "accepted": True})
        self.assertEqual(result["candidate_binding"]["architectures"], ["arm64"])
        with mock.patch.object(apple_gate, "native_host_release_line", return_value="1.0.18"):
            with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "binding is incomplete"):
                self._run_handshake(lambda request: {**request, "accepted": True})
        for architectures in (["x86_64"], ["arm64", "arm64"], ["arm64e"], []):
            self.candidate["architectures"] = architectures
            with self.subTest(architectures=architectures), mock.patch.object(
                apple_gate, "native_host_release_line", return_value="1.0.18"
            ):
                with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "binding is incomplete"):
                    self._run_handshake(lambda request: {**request, "accepted": True})

    def test_path_swap_cannot_change_the_executed_native_host_bytes(self) -> None:
        def reply(request):
            return {**request, "accepted": True}

        def swap_source(command):
            self.host.write_bytes(b"different-host-bytes")
            self.assertEqual(self.host.read_bytes(), b"different-host-bytes")
            self.assertEqual(pathlib.Path(command[0]).read_bytes(), b"host")

        result = self._run_handshake(reply, before_reply=swap_source)
        self.assertEqual(
            result["candidate_binding"]["sha256"], hashlib.sha256(b"host").hexdigest()
        )

    def test_handshake_rejects_extra_duplicate_nonfinite_and_unbound_replies(self) -> None:
        def exact(request):
            return {**request, "accepted": True}

        hostile = {
            "extra": lambda request: {**exact(request), "extra": True},
            "request": lambda request: {**exact(request), "request_id": "0" * 64},
            "protocol": lambda request: {**exact(request), "protocol_version": 2},
            "candidate": lambda request: {
                **exact(request),
                "candidate_binding": {**request["candidate_binding"], "bytes": 5},
            },
            "duplicate": lambda request: (
                b'{"type":"hello","type":"hello","request_id":"'
                + request["request_id"].encode("ascii")
                + b'","protocol_version":1,"candidate_binding":{},"accepted":true}'
            ),
            "nonfinite": lambda request: (
                b'{"type":"hello","request_id":"'
                + request["request_id"].encode("ascii")
                + b'","protocol_version":NaN,"candidate_binding":{},"accepted":true}'
            ),
        }
        for label, builder in hostile.items():
            with self.subTest(label=label), self.assertRaises(
                apple_gate.AppleArtifactGateError
            ):
                self._run_handshake(builder)


class BoundedAppleSubprocessTests(unittest.TestCase):
    @mock.patch.object(
        apple_gate,
        "_macos_descendant_boundary_argv",
        side_effect=lambda argv: list(argv),
    )
    def test_streaming_stdout_and_stderr_caps_close_processes(
        self, _boundary
    ) -> None:
        before_count = len(os.listdir("/dev/fd"))
        started = time.monotonic()
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "stdout output bound"
        ):
            apple_gate._bounded_subprocess(
                ["/usr/bin/yes"],
                "hostile stdout producer",
                timeout=5,
                stdout_limit=1024,
                stderr=subprocess.DEVNULL,
            )
        self.assertLess(time.monotonic() - started, 5)
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "stderr output bound"
        ):
            apple_gate._bounded_subprocess(
                ["/bin/sh", "-c", "while :; do echo hostile >&2; done"],
                "hostile stderr producer",
                timeout=5,
                stdout=subprocess.DEVNULL,
                stderr_limit=1024,
            )
        self.assertEqual(len(os.listdir("/dev/fd")), before_count)

    @mock.patch.object(
        apple_gate,
        "_macos_descendant_boundary_argv",
        side_effect=lambda argv: list(argv),
    )
    def test_deadline_closes_process_and_descriptors(self, _boundary) -> None:
        before_count = len(os.listdir("/dev/fd"))
        with tempfile.TemporaryDirectory(prefix="wins-deadline-pid-") as temporary:
            pid_file = pathlib.Path(temporary) / "pid"
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "time bound"
            ):
                apple_gate._bounded_subprocess(
                    [
                        "/bin/sh",
                        "-c",
                        'echo "$$" > "$1"; sleep 30',
                        "deadline-child",
                        str(pid_file),
                    ],
                    "hostile deadline producer",
                    timeout=1,
                    stdout_limit=128,
                    stderr_limit=128,
                )
            pid = int(pid_file.read_text(encoding="ascii").strip())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
        self.assertEqual(len(os.listdir("/dev/fd")), before_count)

    def test_macos_boundary_is_fixed_authenticated_and_denies_all_forks(self) -> None:
        with mock.patch.object(apple_gate.sys, "platform", "darwin"), mock.patch.object(
            apple_gate,
            "_authenticate_system_tool",
            return_value=apple_gate.MACOS_DESCENDANT_BOUNDARY,
        ) as authenticate:
            command = apple_gate._macos_descendant_boundary_argv(
                ["/usr/bin/true", "candidate"]
            )
        self.assertEqual(
            command,
            [
                apple_gate.MACOS_DESCENDANT_BOUNDARY,
                "-p",
                "(version 1)(allow default)(deny process-fork)",
                "/usr/bin/true",
                "candidate",
            ],
        )
        authenticate.assert_called_once_with(apple_gate.MACOS_DESCENDANT_BOUNDARY)

    def test_missing_complete_descendant_boundary_fails_before_spawn(self) -> None:
        blocker = apple_gate._owner_environment_blocker(
            "complete macOS descendant containment is unavailable"
        )
        with mock.patch.object(
            apple_gate,
            "_macos_descendant_boundary_argv",
            side_effect=blocker,
        ), mock.patch.object(apple_gate.subprocess, "Popen") as popen, self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "owner/environment blocker.*descendant containment",
        ):
            apple_gate._bounded_subprocess(["/usr/bin/true"], "boundary check")
        popen.assert_not_called()

    def test_pkgutil_expansion_enters_the_authenticated_no_fork_boundary(self) -> None:
        class FinishedProcess:
            pid = 424242
            returncode = None

            def wait(self, timeout=None):
                del timeout
                self.returncode = 0
                return 0

        with tempfile.TemporaryDirectory(prefix="wins-pkgutil-boundary-") as temporary:
            destination_fd = os.open(
                temporary,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
            )
            destination_identity = apple_gate._vnode_identity(
                os.fstat(destination_fd), directory=True
            )
            with tempfile.TemporaryFile() as stderr, mock.patch.object(
                apple_gate,
                "_macos_descendant_boundary_argv",
                side_effect=lambda argv: ["/fixed/no-fork", *argv],
            ) as boundary, mock.patch.object(
                apple_gate.subprocess,
                "Popen",
                return_value=FinishedProcess(),
            ) as popen:
                try:
                    returncode, output = apple_gate._spawn_pkgutil_expand(
                        [
                            "/usr/sbin/pkgutil",
                            "--expand-full",
                            "/.vol/1/2",
                            "/.vol/1/3",
                        ],
                        stderr.fileno(),
                        destination_fd,
                        destination_identity,
                        1024,
                    )
                finally:
                    os.close(destination_fd)
        self.assertEqual((returncode, output), (0, ""))
        boundary.assert_called_once_with(
            [
                "/usr/sbin/pkgutil",
                "--expand-full",
                "/.vol/1/2",
                "/.vol/1/3",
            ]
        )
        self.assertEqual(popen.call_args.args[0][0], "/fixed/no-fork")
        self.assertTrue(popen.call_args.kwargs["start_new_session"])


class ApplePackageUploadReceiptIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name)
        identity = self.repo / apple_gate.RELEASE_IDENTITY_RELATIVE_PATH
        identity.parent.mkdir(parents=True)
        identity.write_bytes((ROOT / apple_gate.RELEASE_IDENTITY_RELATIVE_PATH).read_bytes())
        self._root = mock.patch.object(apple_gate, "ROOT", self.repo)
        self._root.start()

    def tearDown(self) -> None:
        self._root.stop()
        self.temporary.cleanup()

    def _receipt(self, target_id: str, digest: str, size: int) -> dict[str, object]:
        spec = apple_gate.APPLE_PACKAGE_UPLOAD_TARGETS[target_id]
        suffix = apple_gate.TARGET_SUFFIXES[target_id][0]
        record: dict[str, object] = {
            "ok": True,
            "schema_version": 2,
            "contract": apple_gate.PACKAGE_UPLOAD_RECEIPT_CONTRACT,
            "release": "1.0.17+34",
            "target_id": target_id,
            "platform": spec["platform"],
            "artifact": {
                "path": f"artifacts/{target_id}{suffix}",
                "sha256": digest,
                "bytes": size,
            },
            "build_receipt": {
                "path": f".artifacts/{target_id}-build.json",
                "sha256": _receipt_digest(f"{target_id}-build"),
                "target": spec["build_receipt_target"],
            },
            "producer": {
                "id": "tools/apple_runtime_smoke.sh",
                "path": "tools/apple_runtime_smoke.sh",
                "sha256": _receipt_digest(f"{target_id}-producer"),
            },
            "bundle_ids": dict(spec["bundle_ids"]),
            "architectures": list(spec["architectures"]),
            "signing": {
                "contract": spec["signing_contract"],
                "authority": spec["expected_authority"],
                "team_id": apple_gate.TEAM_ID,
            },
            "store_evidence": {
                "surface": spec["store_surface"],
                "testflight": spec["testflight"],
                "app_store": spec["app_store"],
                "notarization": spec["notarization"],
            },
            "descriptor": {
                "path": apple_gate.DESCRIPTOR_RELATIVE,
                "sha256": _receipt_digest(f"{target_id}-descriptor"),
            },
            "source_freeze": {
                "path": ".artifacts/SOURCE_FREEZE_RECEIPT.json",
                "sha256": _receipt_digest(f"{target_id}-source"),
            },
            "obfuscation_privacy": {
                "path": apple_gate.OBFUSCATION_PRIVACY_RELATIVE,
                "sha256": _receipt_digest(f"{target_id}-privacy"),
            },
            "publication_authorized": False,
            "upload_attempted": False,
            "owner_authorization": {
                "contract": apple_gate.OWNER_AUTHORIZATION_CONTRACT,
                "schema_version": 2,
                "status": "pending",
                "credentials_authorized": False,
                "upload_authorized": False,
            },
            "authentication": _dummy_authentication(
                target_id,
                digest=digest,
                size=size,
                architectures=list(spec["architectures"]),
            ),
        }
        if target_id == "ios-app-store-ipa":
            record["watchos"] = {
                "bundle_id": apple_gate.WATCH_BUNDLE_ID,
                "companion_bundle_id": apple_gate.HOST_BUNDLE_ID,
                "version": "1.0.17",
                "build": "34",
                "executable": "WinsWatch",
                "executable_sha256": _receipt_digest("watch-exec"),
                "privacy_info_sha256": _receipt_digest("watch-privacy"),
                "artifact_verification": _watch_verification(digest, size),
            }
        return record

    def test_canonical_identity_and_pkg_receipt_bind_arm64_x86_64(self) -> None:
        marketing, build = apple_gate.reviewed_apple_release_identity()
        self.assertEqual((marketing, build), ("1.0.17", "34"))
        digest = _receipt_digest("macos-pkg-bytes")
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "not authenticated by the trusted issuer",
        ):
            apple_gate.bind_package_upload_receipt(
                "macos-app-store-pkg",
                self._receipt("macos-app-store-pkg", digest, 21),
                artifact_sha256=digest,
                artifact_bytes=21,
            )

    def test_codesign_identity_rejects_control_character_path_injection(self) -> None:
        artifact = self.repo / (
            "candidate\nAuthority=Apple Distribution: forged\n"
            "TeamIdentifier=5YT8H4U72M.app"
        )
        artifact.mkdir()
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "control characters"
        ), mock.patch.object(apple_gate, "_run") as run:
            apple_gate._verify_codesign_identity(
                artifact, "Authority=Apple Distribution:"
            )
        run.assert_not_called()

    def test_codesign_identity_uses_first_exact_authority_and_unique_team_line(self) -> None:
        artifact = self.repo / "candidate.app"
        artifact.mkdir()
        injected = subprocess.CompletedProcess(
            ["codesign"],
            0,
            "",
            "Authority=Apple System Integration 2 Signing\n"
            "TeamIdentifier=not set\n"
            "Authority=Apple Distribution: forged (5YT8H4U72M)\n"
            "TeamIdentifier=5YT8H4U72M\n",
        )
        with mock.patch.object(apple_gate, "_run_on_path", return_value=injected):
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "identity or team"
            ):
                apple_gate._verify_codesign_identity(
                    artifact, "Authority=Apple Distribution:"
                )

    def test_codesign_verify_uses_owner_designated_requirement(self) -> None:
        artifact = self.repo / "candidate.app"
        artifact.mkdir()
        (artifact / "Info.plist").write_bytes(b"plist")
        recorded: list[list[str]] = []

        def run(argv, *args, **kwargs):
            command = list(argv)
            recorded.append(command)
            if "--verify" in command:
                requirement = apple_gate._codesign_requirement_from_argv(command)
                self.assertIn(f'subject.OU] = "{apple_gate.TEAM_ID}"', requirement)
                self.assertIn("anchor apple generic", requirement)
                self.assertIn(apple_gate.APPLE_DISTRIBUTION_LEAF_OID, requirement)
                self.assertNotIn("Authority=", requirement)
                self.assertNotIn("-R", command)
                self.assertFalse(apple_gate._is_volfs_path(command[-1]), msg=command)
                return subprocess.CompletedProcess(command, 0, "", "")
            return subprocess.CompletedProcess(
                command,
                0,
                "",
                (
                    "Authority=Apple Distribution: Win's VPN Inc "
                    f"({apple_gate.TEAM_ID})\nTeamIdentifier={apple_gate.TEAM_ID}\n"
                ),
            )

        with mock.patch.object(apple_gate, "_run", side_effect=run):
            apple_gate._verify_codesign(
                artifact, "Authority=Apple Distribution:"
            )
        self.assertTrue(
            any(
                any(part.startswith("-R=") for part in command)
                for command in recorded
            )
        )

    def test_execution_tree_identity_ignores_only_root_ctime(self) -> None:
        base = (
            (".", (1, 2, 3, 4, 5, 6, 7, 8, 9, 10)),
            ("Info.plist", (11, 12, 13, 14, 15, 16, 17, 18, 19, 20)),
        )
        renamed_root = (
            (".", (1, 2, 3, 4, 5, 6, 7, 88, 9, 10)),
            ("Info.plist", (11, 12, 13, 14, 15, 16, 17, 18, 19, 20)),
        )
        self.assertEqual(
            apple_gate._execution_tree_identity(base),
            apple_gate._execution_tree_identity(renamed_root),
        )
        root_fields = (
            "dev",
            "ino",
            "uid",
            "mode",
            "nlink",
            "size",
            "mtime",
            "ctime",
            "flags",
            "gen",
        )
        for index, label in enumerate(root_fields):
            if label == "ctime":
                continue
            mutated_root = list(base[0][1])
            mutated_root[index] += 1
            mutated = ((".", tuple(mutated_root)), base[1])
            self.assertNotEqual(
                apple_gate._execution_tree_identity(base),
                apple_gate._execution_tree_identity(mutated),
                msg=label,
            )
        child_ctime = (
            base[0],
            ("Info.plist", (11, 12, 13, 14, 15, 16, 17, 180, 19, 20)),
        )
        self.assertNotEqual(
            apple_gate._execution_tree_identity(base),
            apple_gate._execution_tree_identity(child_ctime),
        )
        child_ino = (
            base[0],
            ("Info.plist", (11, 120, 13, 14, 15, 16, 17, 18, 19, 20)),
        )
        self.assertNotEqual(
            apple_gate._execution_tree_identity(base),
            apple_gate._execution_tree_identity(child_ino),
        )
        extra_child = base + (("Extra", (21, 22, 23, 24, 25, 26, 27, 28, 29, 30)),)
        self.assertNotEqual(
            apple_gate._execution_tree_identity(base),
            apple_gate._execution_tree_identity(extra_child),
        )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "tree was replaced"
        ):
            apple_gate._execution_tree_identity(
                (("Info.plist", (11, 12, 13, 14, 15, 16, 17, 18, 19, 20)),)
            )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "tree is unreadable"
        ):
            apple_gate._execution_tree_identity(((".", (1, 2, 3)),))

    def test_raw_tree_compare_rejects_root_ctime_stable_compare_ignores_it(
        self,
    ) -> None:
        base = (
            (".", (1, 2, 3, 4, 5, 6, 7, 8, 9, 10)),
            ("Info.plist", (11, 12, 13, 14, 15, 16, 17, 18, 19, 20)),
        )
        root_ctime = (
            (".", (1, 2, 3, 4, 5, 6, 7, 88, 9, 10)),
            ("Info.plist", (11, 12, 13, 14, 15, 16, 17, 18, 19, 20)),
        )
        apple_gate._require_execution_tree_unchanged(base, base, raw=True)
        apple_gate._require_execution_tree_unchanged(base, base, raw=False)
        apple_gate._require_execution_tree_unchanged(base, root_ctime, raw=False)
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "tree was replaced"
        ):
            apple_gate._require_execution_tree_unchanged(base, root_ctime, raw=True)
        root_mode = (
            (".", (1, 2, 3, 5, 5, 6, 7, 8, 9, 10)),
            ("Info.plist", (11, 12, 13, 14, 15, 16, 17, 18, 19, 20)),
        )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "tree was replaced"
        ):
            apple_gate._require_execution_tree_unchanged(base, root_mode, raw=False)
        child_ctime = (
            (".", (1, 2, 3, 4, 5, 6, 7, 8, 9, 10)),
            ("Info.plist", (11, 12, 13, 14, 15, 16, 17, 180, 19, 20)),
        )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "tree was replaced"
        ):
            apple_gate._require_execution_tree_unchanged(base, child_ctime, raw=True)
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "tree was replaced"
        ):
            apple_gate._require_execution_tree_unchanged(base, child_ctime, raw=False)

    def test_codesign_identity_rejects_unicode_bidi_bom_and_line_separators(
        self,
    ) -> None:
        valid = (
            "Authority=Apple Distribution: Win's VPN Inc "
            f"({apple_gate.TEAM_ID})\nTeamIdentifier={apple_gate.TEAM_ID}\n"
        )
        apple_gate._require_release_codesign_identity(
            valid, "Authority=Apple Distribution:"
        )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "identity or team"
        ):
            apple_gate._require_release_codesign_identity(
                "Authority=Apple Distribution: Attacker App "
                f"({apple_gate.TEAM_ID})\nTeamIdentifier={apple_gate.TEAM_ID}\n",
                "Authority=Apple Distribution:",
            )
        for injection in (
            "\u2028",
            "\u2029",
            "\u0085",
            "\u200e",
            "\u200f",
            "\u202a",
            "\u2066",
            "\ufeff",
            "\r",
            "\t",
        ):
            with self.subTest(codepoint=ord(injection)):
                with self.assertRaisesRegex(
                    apple_gate.AppleArtifactGateError,
                    "Unicode|control|bidi|BOM",
                ):
                    apple_gate._require_release_codesign_identity(
                        valid.replace("\n", injection + "\n", 1),
                        "Authority=Apple Distribution:",
                    )

    def test_pkg_installer_signature_binds_owner_team_and_rejects_decoys(
        self,
    ) -> None:
        good = (
            "Status: signed by a developer certificate issued by Apple (Development)\n"
            "Certificate Chain:\n"
            "    1. 3rd Party Mac Developer Installer: Win's VPN Inc "
            f"({apple_gate.TEAM_ID})\n"
            "    2. Apple Worldwide Developer Relations Certification Authority\n"
            "    3. Apple Root CA\n"
        )
        apple_gate._require_pkg_installer_signature(good, 0)
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "not release-valid"
        ):
            apple_gate._require_pkg_installer_signature(
                "Status: signed by a certificate trusted by Mac OS X.\n",
                0,
            )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "not release-valid|not the owner",
        ):
            apple_gate._require_pkg_installer_signature(
                "Status: signed by a developer ID certificate\n"
                "Certificate Chain:\n"
                "    1. Developer ID Installer: Other Team (ABCD123456)\n",
                0,
            )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "not the owner",
        ):
            apple_gate._require_pkg_installer_signature(
                "Status: signed by a developer certificate issued by Apple (Development)\n"
                "Certificate Chain:\n"
                "    1. 3rd Party Mac Developer Installer: Other Team "
                f"({apple_gate.TEAM_ID})\n",
                0,
            )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "not the owner",
        ):
            apple_gate._require_pkg_installer_signature(
                "Status: signed by a developer certificate issued by Apple (Development)\n"
                "Certificate Chain:\n"
                "    1. 3rd Party Mac Developer Installer: Win's VPN Inc "
                f"({apple_gate.TEAM_ID}) extra\n",
                0,
            )

    def test_plist_and_inner_metadata_ceilings_fail_closed(self) -> None:
        plist_path = self.repo / "huge.plist"
        plist_path.write_bytes(b"a" * (apple_gate.MAX_PLIST_BYTES + 1))
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "metadata bound"
        ):
            apple_gate._read_plist(plist_path, "host app")
        meta = self.repo / "huge.json"
        meta.write_bytes(b"{" + (b"a" * (apple_gate.MAX_INNER_METADATA_BYTES + 1)) + b"}")
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "missing or invalid"
        ):
            apple_gate._load_json_object(meta, "Apple engine artifact manifest")
        linked = self.repo / "linked.json"
        linked.write_bytes(b'{"k":1}')
        alias = self.repo / "alias.json"
        os.link(linked, alias)
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "missing or invalid"
        ):
            apple_gate._load_json_object(linked, "Apple engine artifact manifest")

    def test_receipt_and_zip_paths_reject_all_ascii_control_characters(self) -> None:
        for codepoint in (*range(0x20), 0x7F):
            character = chr(codepoint)
            with self.subTest(character=codepoint):
                with self.assertRaises(apple_gate.AppleArtifactGateError):
                    apple_gate._require_canonical_relative_path(
                        f"artifacts/candidate{character}.ipa", "artifact"
                    )
                member = zipfile.ZipInfo("Payload/Wins.app/file")
                member.filename = f"Payload/Wins{character}.app/file"
                with self.assertRaises(apple_gate.AppleArtifactGateError):
                    apple_gate._zip_member_name(member)

    def test_receipt_and_journal_json_reject_duplicate_keys(self) -> None:
        duplicate_receipt = b'{"ok":false,"ok":true}'
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "duplicate key"
        ):
            apple_gate._receipt_document(duplicate_receipt, "receipt")
        duplicate_journal = (
            b'{"schema":"winsvpn-apple-upload-receipt-journal-v1",'
            b'"schema":"winsvpn-apple-upload-receipt-journal-v1"}\n'
        )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "duplicate key"
        ):
            apple_gate._parse_upload_receipt_journal(duplicate_journal)
        for payload in (b'{"ok":NaN}', b'{"ok":Infinity}', b'{"ok":-Infinity}'):
            with self.subTest(payload=payload), self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "nonfinite"
            ):
                apple_gate._receipt_document(payload, "receipt")
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "finite exact JSON data"
        ):
            apple_gate._receipt_document({"ok": float("nan")}, "receipt")
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "nonfinite"
        ):
            apple_gate._parse_upload_receipt_journal(
                b'{"schema":"winsvpn-apple-upload-receipt-journal-v1",'
                b'"kind":"issued","artifact_bytes":NaN}\n'
            )

        target_id = "macos-app-store-pkg"
        receipt = self._receipt(target_id, _receipt_digest("artifact"), 8)
        duplicate_build = b'{"ok":false,"ok":true}'
        payloads: dict[str, bytes] = {
            str(receipt["artifact"]["path"]): b"artifact",
            str(receipt["producer"]["path"]): b"producer",
            str(receipt["descriptor"]["path"]): b"descriptor",
            str(receipt["obfuscation_privacy"]["path"]): b"privacy",
            str(receipt["source_freeze"]["path"]): b"source",
            str(receipt["build_receipt"]["path"]): duplicate_build,
        }
        for field in (
            "artifact",
            "producer",
            "descriptor",
            "obfuscation_privacy",
            "source_freeze",
            "build_receipt",
        ):
            binding = receipt[field]
            binding["sha256"] = hashlib.sha256(
                payloads[str(binding["path"])]
            ).hexdigest()
        receipt["artifact"]["bytes"] = len(payloads[str(receipt["artifact"]["path"])])

        def live_file(path, _label, *, max_bytes=apple_gate.MAX_PKG_BYTES):
            payload = payloads[path]
            self.assertLessEqual(len(payload), max_bytes)
            return hashlib.sha256(payload).hexdigest(), len(payload), payload

        with mock.patch.object(
            apple_gate, "_hash_live_repo_file", side_effect=live_file
        ), self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "duplicate key"
        ):
            apple_gate._require_live_upload_bindings(
                target_id,
                receipt,
                apple_gate.APPLE_PACKAGE_UPLOAD_TARGETS[target_id],
            )

    def test_receipt_requires_reviewed_watch_verifier_true(self) -> None:
        digest = _receipt_digest("reviewed-watch-receipt")
        receipt = self._receipt("ios-app-store-ipa", digest, 29)
        receipt["watchos"]["artifact_verification"]["verifier"][
            "reviewed_verifier"
        ] = False
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "does not bind the exact candidate",
        ):
            apple_gate._bind_package_upload_receipt_locked(
                "ios-app-store-ipa",
                receipt,
                artifact_sha256=digest,
                artifact_bytes=29,
            )

    def test_tool_output_and_live_receipt_reads_are_bounded(self) -> None:
        oversized = "x" * (apple_gate.MAX_TOOL_OUTPUT_BYTES + 1)
        completed = subprocess.CompletedProcess(
            ["/usr/bin/codesign"], 0, oversized.encode("ascii"), b""
        )
        with mock.patch.object(
            apple_gate, "_bounded_subprocess", return_value=completed
        ):
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "output bound"
            ):
                apple_gate._run(["/usr/bin/codesign"], "bounded tool")
        completed = subprocess.CompletedProcess(
            ["/usr/bin/codesign"], 0, b"", b"\xff"
        )
        with mock.patch.object(
            apple_gate, "_bounded_subprocess", return_value=completed
        ):
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "invalid UTF-8"
            ):
                apple_gate._run(["/usr/bin/codesign"], "UTF-8 tool")
        receipt = self.repo / "oversized-receipt.json"
        receipt.write_bytes(b"x" * (apple_gate.MAX_RECEIPT_FILE_BYTES + 1))
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "regular single-link"
        ):
            apple_gate._hash_live_repo_file(
                receipt.name,
                "oversized receipt",
                max_bytes=apple_gate.MAX_RECEIPT_FILE_BYTES,
            )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "live receipt input bound"
        ):
            apple_gate._receipt_document(
                b"x" * (apple_gate.MAX_RECEIPT_FILE_BYTES + 1),
                "oversized receipt",
            )
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "exact JSON"
        ):
            apple_gate._receipt_document(b"\xff", "invalid UTF-8 receipt")

    def test_ios_receipt_requires_watchos_and_refuses_publication(self) -> None:
        digest = _receipt_digest("ios-ipa-bytes")
        record = self._receipt("ios-app-store-ipa", digest, 19)
        record["publication_authorized"] = True
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "receipt binding is invalid"
        ):
            apple_gate.bind_package_upload_receipt(
                "ios-app-store-ipa",
                record,
                artifact_sha256=digest,
                artifact_bytes=19,
            )
        record["publication_authorized"] = False
        record["upload_attempted"] = True
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "receipt binding is invalid"
        ):
            apple_gate.bind_package_upload_receipt(
                "ios-app-store-ipa",
                record,
                artifact_sha256=digest,
                artifact_bytes=19,
            )

    def test_shipping_surfaces_must_include_watchos(self) -> None:
        identity_path = self.repo / apple_gate.RELEASE_IDENTITY_RELATIVE_PATH
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
        identity["platform_mappings"]["apple"]["shipping_surfaces"] = ["ios", "macos"]
        identity_path.write_text(json.dumps(identity) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "inconsistent"):
            apple_gate.reviewed_apple_release_identity()

    def test_tvos_identity_and_required_artifacts_fail_closed(self) -> None:
        identity_path = self.repo / apple_gate.RELEASE_IDENTITY_RELATIVE_PATH
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
        identity["platform_mappings"]["apple"]["shipping_surfaces"] = [
            "ios",
            "watchos",
            "macos",
            "tvos",
        ]
        identity_path.write_text(json.dumps(identity) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "tvOS is not a 1.0.17\\+34 shipping, upload, signing, or receipt surface",
        ):
            apple_gate.reviewed_apple_release_identity()
        identity["platform_mappings"]["apple"]["shipping_surfaces"] = [
            "ios",
            "watchos",
            "macos",
        ]
        identity["platform_mappings"]["apple"]["required_artifacts"] = [
            "ios_app_store_ipa_with_embedded_watchos"
        ]
        identity_path.write_text(json.dumps(identity) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "inconsistent"):
            apple_gate.reviewed_apple_release_identity()
        identity["platform_mappings"]["apple"]["required_artifacts"] = [
            "ios_app_store_ipa_with_embedded_watchos",
            "macos_app_store_pkg",
            "tvos_app_store_ipa",
        ]
        identity_path.write_text(json.dumps(identity) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError,
            "tvOS is not a 1.0.17\\+34 shipping, upload, signing, or receipt surface",
        ):
            apple_gate.reviewed_apple_release_identity()

    def test_placeholder_key_and_swapped_target_fail_closed(self) -> None:
        source = pathlib.Path(apple_gate.__file__).read_text(encoding="ascii")
        self.assertNotIn("UPLOAD_RECEIPT_ISSUER_PUBLIC_KEY_HEX", source)
        self.assertNotIn("Ed25519PublicKey", source)
        digest = _receipt_digest("macos-pkg-bytes")
        record = self._receipt("macos-app-store-pkg", digest, 21)
        record["authentication"]["public_key"] = "cafef00d" * 8
        with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "placeholder"):
            apple_gate.bind_package_upload_receipt(
                "macos-app-store-pkg",
                record,
                artifact_sha256=digest,
                artifact_bytes=21,
            )
        ios_digest = _receipt_digest("ios-ipa-bytes")
        ios = self._receipt("ios-app-store-ipa", ios_digest, 19)
        macos = self._receipt("macos-app-store-pkg", digest, 21)
        macos["authentication"] = dict(ios["authentication"])
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "swapped or does not bind"
        ):
            apple_gate.bind_package_upload_receipt(
                "macos-app-store-pkg",
                macos,
                artifact_sha256=digest,
                artifact_bytes=21,
            )

    def _issued_receipt_set(
        self,
    ) -> tuple[dict[str, dict[str, object]], dict[str, tuple[str, int]]]:
        records: dict[str, dict[str, object]] = {}
        artifacts: dict[str, tuple[str, int]] = {}
        for index, target_id in enumerate(apple_gate.REQUIRED_APPLE_UPLOAD_TARGETS):
            digest = _receipt_digest(f"transaction-{target_id}")
            size = 101 + index
            record = self._receipt(target_id, digest, size)
            record["authentication"] = apple_gate.issue_upload_receipt_challenge(
                target_id,
                artifact_sha256=digest,
                artifact_bytes=size,
                architectures=tuple(
                    apple_gate.APPLE_PACKAGE_UPLOAD_TARGETS[target_id][
                        "architectures"
                    ]
                ),
                release=apple_gate.CANONICAL_RELEASE,
            )
            records[target_id] = record
            artifacts[target_id] = (digest, size)
        first = records[apple_gate.REQUIRED_APPLE_UPLOAD_TARGETS[0]]
        for target_id in apple_gate.REQUIRED_APPLE_UPLOAD_TARGETS[1:]:
            for field in apple_gate.SHARED_UPLOAD_RECEIPT_PATH_FIELDS:
                records[target_id][field] = dict(first[field])
        return records, artifacts

    @mock.patch.object(
        apple_gate._UploadBindingTransaction,
        "held_file",
        return_value=mock.Mock(),
    )
    def test_receipt_set_consumption_commits_only_after_every_signature(
        self, _held_file
    ) -> None:
        records, artifacts = self._issued_receipt_set()
        signature_calls = 0

        def fail_second(*_args, **_kwargs):
            nonlocal signature_calls
            signature_calls += 1
            if signature_calls == 2:
                raise apple_gate.AppleArtifactGateError("owner signature failed")

        with mock.patch.object(
            apple_gate, "_require_live_upload_bindings"
        ), mock.patch.object(
            apple_gate,
            "_require_owner_issued_apple_signature",
            side_effect=fail_second,
        ), self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "owner signature failed"
        ):
            apple_gate.bind_apple_package_upload_receipts(records, artifacts)
        journal = self.repo / apple_gate.UPLOAD_RECEIPT_JOURNAL_RELATIVE
        failed_records = apple_gate._parse_upload_receipt_journal(
            journal.read_bytes()
        )
        self.assertFalse(
            any(record.get("kind") == "consumed-set" for record in failed_records)
        )

        with mock.patch.object(
            apple_gate, "_require_live_upload_bindings"
        ), mock.patch.object(
            apple_gate, "_require_owner_issued_apple_signature"
        ):
            result = apple_gate.bind_apple_package_upload_receipts(records, artifacts)
        self.assertTrue(result["ok"])
        committed = apple_gate._parse_upload_receipt_journal(journal.read_bytes())
        transactions = [
            record for record in committed if record.get("kind") == "consumed-set"
        ]
        self.assertEqual(len(transactions), 1)
        self.assertEqual(
            {item["target_id"] for item in transactions[0]["authentications"]},
            set(apple_gate.REQUIRED_APPLE_UPLOAD_TARGETS),
        )
        with mock.patch.object(
            apple_gate, "_require_live_upload_bindings"
        ), mock.patch.object(
            apple_gate, "_require_owner_issued_apple_signature"
        ), self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "already consumed"
        ):
            apple_gate.bind_apple_package_upload_receipts(records, artifacts)

    def test_transaction_write_failure_rolls_back_and_retry_commits(self) -> None:
        records, _artifacts = self._issued_receipt_set()
        authentications = tuple(
            records[target_id]["authentication"]
            for target_id in apple_gate.REQUIRED_APPLE_UPLOAD_TARGETS
        )
        journal = self.repo / apple_gate.UPLOAD_RECEIPT_JOURNAL_RELATIVE
        before = journal.read_bytes()
        real_write = os.write

        def partial_write(fd, payload):
            if b'"kind":"consumed-set"' in payload:
                return real_write(fd, payload[:-1])
            return real_write(fd, payload)

        with mock.patch.object(
            apple_gate.os, "write", side_effect=partial_write
        ), self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "write was truncated"
        ):
            apple_gate._commit_upload_receipt_challenges(authentications)
        self.assertEqual(journal.read_bytes(), before)
        apple_gate._commit_upload_receipt_challenges(authentications)
        parsed = apple_gate._parse_upload_receipt_journal(journal.read_bytes())
        self.assertEqual(
            sum(record.get("kind") == "consumed-set" for record in parsed), 1
        )

    def test_transaction_fsync_failure_rolls_back_and_retry_commits(self) -> None:
        records, _artifacts = self._issued_receipt_set()
        authentications = tuple(
            records[target_id]["authentication"]
            for target_id in apple_gate.REQUIRED_APPLE_UPLOAD_TARGETS
        )
        journal = self.repo / apple_gate.UPLOAD_RECEIPT_JOURNAL_RELATIVE
        before = journal.read_bytes()
        real_fsync = os.fsync
        calls = 0

        def fail_commit_fsync(fd):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("simulated commit durability failure")
            return real_fsync(fd)

        with mock.patch.object(
            apple_gate.os, "fsync", side_effect=fail_commit_fsync
        ), self.assertRaisesRegex(OSError, "durability failure"):
            apple_gate._commit_upload_receipt_challenges(authentications)
        self.assertEqual(journal.read_bytes(), before)
        apple_gate._commit_upload_receipt_challenges(authentications)
        parsed = apple_gate._parse_upload_receipt_journal(journal.read_bytes())
        self.assertEqual(
            sum(record.get("kind") == "consumed-set" for record in parsed), 1
        )

    def test_journal_parent_swap_cannot_redirect_challenge_consumption(self) -> None:
        records, _artifacts = self._issued_receipt_set()
        authentications = tuple(
            records[target_id]["authentication"]
            for target_id in apple_gate.REQUIRED_APPLE_UPLOAD_TARGETS
        )
        journal = self.repo / apple_gate.UPLOAD_RECEIPT_JOURNAL_RELATIVE
        parent = journal.parent
        displaced = parent.with_name(parent.name + "-displaced")
        substitute = parent.with_name(parent.name + "-substitute")
        substitute.mkdir()
        substitute_journal = substitute / journal.name
        substitute_journal.write_bytes(journal.read_bytes())
        real_write = os.write
        swapped = False

        def swap_parent(fd, payload):
            nonlocal swapped
            if not swapped and b'"kind":"consumed-set"' in payload:
                parent.rename(displaced)
                substitute.rename(parent)
                swapped = True
            return real_write(fd, payload)

        with mock.patch.object(
            apple_gate.os, "write", side_effect=swap_parent
        ), self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "journal ancestor was replaced"
        ):
            apple_gate._commit_upload_receipt_challenges(authentications)
        self.assertTrue(swapped)
        named = apple_gate._parse_upload_receipt_journal(journal.read_bytes())
        self.assertFalse(any(item.get("kind") == "consumed-set" for item in named))

    def test_repo_parent_swap_restore_breaks_retained_file_custody(self) -> None:
        artifact_parent = self.repo / "artifacts"
        artifact_parent.mkdir()
        artifact = artifact_parent / "candidate.ipa"
        artifact.write_bytes(b"exact-candidate")
        held = apple_gate._HeldLiveRepoFile(
            "artifacts/candidate.ipa", "held candidate", max_bytes=1024
        )
        displaced = self.repo / "artifacts-displaced"
        substitute = self.repo / "artifacts-substitute"
        substitute.mkdir()
        (substitute / artifact.name).write_bytes(artifact.read_bytes())
        try:
            artifact_parent.rename(displaced)
            substitute.rename(artifact_parent)
            artifact_parent.rename(substitute)
            displaced.rename(artifact_parent)
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "ancestor was replaced"
            ):
                held.verify()
        finally:
            held.close(verify=False)


class DarwinLiveAppleArtifactGateTests(unittest.TestCase):
    @unittest.skipUnless(DARWIN, "live Darwin codesign argv and inspect probes")
    def test_codesign_requirement_is_one_r_equals_token(self) -> None:
        requirement = apple_gate._codesign_requirement_for_authority(
            apple_gate.APP_STORE_DISTRIBUTION_AUTHORITY
        )
        argv = apple_gate._codesign_verify_argv(requirement, deep=True)
        self.assertEqual(apple_gate._codesign_requirement_from_argv(argv), requirement)
        self.assertNotIn("-R", argv)
        self.assertTrue(any(item.startswith("-R=") for item in argv))
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "one -R=<requirement>"
        ):
            apple_gate._codesign_requirement_from_argv(
                ["/usr/bin/codesign", "--verify", "-R", requirement, "/bin/ls"]
            )

    @unittest.skipUnless(DARWIN, "live Darwin codesign argv and inspect probes")
    def test_live_host_integrity_fixture_requirement_tokens_do_not_claim_trust(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-codesign-fixture-") as temporary:
            fixture = _host_integrity_fixture_copy(pathlib.Path(temporary) / "fixture")
            source_state, _source_detail = _codesign_integrity_state(
                pathlib.Path("/usr/bin/true")
            )
            fixture_state, _fixture_detail = _codesign_integrity_state(fixture)
            self.assertEqual(fixture_state, source_state)
            owner = apple_gate._codesign_requirement_for_authority(
                apple_gate.APP_STORE_DISTRIBUTION_AUTHORITY
            )
            attached = REAL_RUN(
                [
                    "/usr/bin/codesign",
                    "--verify",
                    "--strict",
                    "-R=" + owner,
                    str(fixture),
                ],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            self.assertNotEqual(attached.returncode, 0)
            gate_split = REAL_RUN(
                [
                    "/usr/bin/codesign",
                    "--verify",
                    "--strict",
                    "-R",
                    owner,
                    str(fixture),
                ],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            self.assertNotEqual(gate_split.returncode, 0)

    @unittest.skipUnless(DARWIN, "live Darwin codesign argv and inspect probes")
    def test_live_codesign_rejects_volfs_and_sealed_inspect_keeps_inode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-live-inspect-") as temporary:
            root = pathlib.Path(temporary)
            payload = _host_integrity_fixture_copy(root / "payload")
            source_state, _source_detail = _codesign_integrity_state(
                pathlib.Path("/usr/bin/true")
            )
            inspect = root / "q"
            inspect.mkdir(mode=0o700)
            src_fd = os.open(payload, os.O_RDONLY | os.O_CLOEXEC)
            inspect_fd = os.open(inspect, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                src = os.fstat(src_fd)
                kernel = apple_gate._authenticate_volfs(
                    src_fd,
                    apple_gate._vnode_identity(src, directory=False),
                    directory=False,
                )
                os.link(kernel, "held", dst_dir_fd=inspect_fd, follow_symlinks=False)
                held = os.lstat("held", dir_fd=inspect_fd)
                self.assertEqual(
                    (held.st_dev, held.st_ino), (src.st_dev, src.st_ino)
                )
                apple_gate._require_fchflags(inspect_fd, apple_gate.UF_IMMUTABLE)
                inspect_path = str(inspect / "held")
                self.assertFalse(apple_gate._is_volfs_path(inspect_path))
                with self.assertRaises(OSError):
                    os.rename(
                        "held",
                        "stolen",
                        src_dir_fd=inspect_fd,
                        dst_dir_fd=inspect_fd,
                    )
                display = REAL_RUN(
                    ["/usr/bin/codesign", "-d", "--verbose=4", inspect_path],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                verify = REAL_RUN(
                    [
                        "/usr/bin/codesign",
                        "--verify",
                        "--strict",
                        inspect_path,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                assess = REAL_RUN(
                    [
                        "/usr/sbin/spctl",
                        "--assess",
                        "--verbose=4",
                        "--type",
                        "execute",
                        inspect_path,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                after = os.lstat("held", dir_fd=inspect_fd)
                held_fd = os.fstat(src_fd)
                self.assertEqual(
                    (after.st_dev, after.st_ino), (held_fd.st_dev, held_fd.st_ino)
                )
                self.assertEqual(display.returncode, 0, msg=display.stderr)
                self.assertIn("Identifier=", display.stderr)
                if verify.returncode == 0:
                    verify_state = "integrity-accepted"
                elif "CSSMERR_TP_NOT_TRUSTED" in verify.stderr:
                    verify_state = "certificate-not-trusted"
                else:
                    self.fail(verify.stderr)
                self.assertEqual(verify_state, source_state)
                self.assertNotIn("No such file or directory", assess.stderr)
                apple_gate._clear_held_unlink_blocking_flags(inspect_fd)
                os.unlink("held", dir_fd=inspect_fd)
                restored = os.fstat(src_fd)
                self.assertEqual(
                    (restored.st_dev, restored.st_ino), (src.st_dev, src.st_ino)
                )
                self.assertEqual(restored.st_nlink, 1)
            finally:
                try:
                    apple_gate._clear_held_unlink_blocking_flags(inspect_fd)
                except Exception:
                    pass
                os.close(inspect_fd)
                os.close(src_fd)

    @unittest.skipUnless(DARWIN, "directory rename updates Darwin ctime")
    def test_directory_rename_changes_only_root_ctime(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-tree-ctime-") as temporary:
            root = pathlib.Path(temporary)
            app = root / "candidate.app"
            app.mkdir()
            child = app / "Info.plist"
            child.write_bytes(b"plist")
            inspect = root / "inspect"
            inspect.mkdir()
            fd = os.open(app, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                before = apple_gate._directory_tree_identities(fd)
                os.rename(app, inspect / "held")
                os.rename(inspect / "held", app)
                after = apple_gate._directory_tree_identities(fd)
                before_map = dict(before)
                after_map = dict(after)
                self.assertEqual(set(before_map), set(after_map))
                self.assertEqual(before_map["."][:7], after_map["."][:7])
                self.assertEqual(before_map["."][8:], after_map["."][8:])
                self.assertNotEqual(before_map["."][7], after_map["."][7])
                self.assertEqual(before_map["Info.plist"], after_map["Info.plist"])
                self.assertNotEqual(before, after)
                self.assertEqual(
                    apple_gate._execution_tree_identity(before),
                    apple_gate._execution_tree_identity(after),
                )
                os.chmod(app, 0o500)
                root_mode = apple_gate._directory_tree_identities(fd)
                self.assertNotEqual(
                    apple_gate._execution_tree_identity(after),
                    apple_gate._execution_tree_identity(root_mode),
                )
                os.chmod(app, stat.S_IMODE(after_map["."][3]))
                restored_mode = apple_gate._directory_tree_identities(fd)
                self.assertEqual(
                    apple_gate._execution_tree_identity(after),
                    apple_gate._execution_tree_identity(restored_mode),
                )
                os.chmod(child, stat.S_IMODE(child.stat().st_mode))
                child_ctime = apple_gate._directory_tree_identities(fd)
                self.assertEqual(
                    dict(restored_mode)["."][:7], dict(child_ctime)["."][:7]
                )
                self.assertEqual(
                    dict(restored_mode)["."][8:], dict(child_ctime)["."][8:]
                )
                self.assertNotEqual(
                    dict(restored_mode)["Info.plist"], dict(child_ctime)["Info.plist"]
                )
                self.assertNotEqual(
                    apple_gate._execution_tree_identity(restored_mode),
                    apple_gate._execution_tree_identity(child_ctime),
                )
            finally:
                os.close(fd)

    @unittest.skipUnless(DARWIN, "sealed inspect rename is Darwin-only")
    def test_run_on_path_rejects_child_restore_after_inspect(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-tree-child-") as temporary:
            root = pathlib.Path(temporary)
            app = root / "candidate.app"
            app.mkdir()
            child = app / "Info.plist"
            child.write_bytes(b"plist")

            def run(argv, *args, **kwargs):
                command = list(argv)
                payload = pathlib.Path(command[-1]) / "Info.plist"
                opened = os.open(
                    payload, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
                )
                try:
                    apple_gate._clear_held_unlink_blocking_flags(opened)
                    os.fchmod(opened, 0o600)
                finally:
                    os.close(opened)
                original = payload.read_bytes()
                payload.write_bytes(b"swapped")
                payload.write_bytes(original)
                return subprocess.CompletedProcess(command, 0, "", "")

            with mock.patch.object(apple_gate, "_run", side_effect=run):
                with self.assertRaisesRegex(
                    apple_gate.AppleArtifactGateError,
                    "tree was replaced",
                ):
                    apple_gate._run_on_path(
                        ["/usr/bin/codesign", "-d", "--verbose=4"],
                        app,
                        "Apple code-signature identity inspection",
                        directory=True,
                    )

    def _candidate_app(self, root: pathlib.Path) -> pathlib.Path:
        app = root / "candidate.app"
        app.mkdir()
        (app / "Info.plist").write_bytes(b"plist")
        return app

    def _clear_candidate_metadata(self, root: pathlib.Path) -> None:
        paths = [root, *root.rglob("*")]
        for path in paths:
            if not path.exists():
                continue
            REAL_RUN(
                ["/bin/chmod", "-N", str(path)],
                check=False,
                capture_output=True,
            )
            REAL_RUN(
                ["/usr/bin/xattr", "-c", str(path)],
                check=False,
                capture_output=True,
            )
            REAL_RUN(
                ["/usr/bin/chflags", "nouchg,nodump", str(path)],
                check=False,
                capture_output=True,
            )
            try:
                if path.is_symlink():
                    continue
                if path.is_dir():
                    os.chmod(path, 0o700)
                elif path.is_file():
                    os.chmod(path, 0o600)
            except OSError:
                continue

    def _directory_run_on_path(self, app: pathlib.Path, mutate=None):
        def run(argv, *args, **kwargs):
            command = list(argv)
            if mutate is not None:
                mutate(pathlib.Path(command[-1]))
            return subprocess.CompletedProcess(command, 0, "", "")

        with mock.patch.object(apple_gate, "_run", side_effect=run):
            return apple_gate._run_on_path(
                ["/usr/bin/codesign", "-d", "--verbose=4"],
                app,
                "Apple code-signature identity inspection",
                directory=True,
            )

    @unittest.skipUnless(DARWIN, "root xattr mutation is Darwin-only")
    def test_run_on_path_rejects_root_xattr_during_run(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-tree-xattr-") as temporary:
            root = pathlib.Path(temporary)
            app = self._candidate_app(root)
            fd = os.open(app, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                before = apple_gate._directory_tree_identities(fd)
                REAL_RUN(
                    ["/usr/bin/xattr", "-w", "user.audit", "1", str(app)],
                    check=True,
                    capture_output=True,
                )
                after = apple_gate._directory_tree_identities(fd)
                self.assertNotEqual(before, after)
                self.assertEqual(
                    apple_gate._execution_tree_identity(before),
                    apple_gate._execution_tree_identity(after),
                )
                REAL_RUN(
                    ["/usr/bin/xattr", "-d", "user.audit", str(app)],
                    check=True,
                    capture_output=True,
                )
            finally:
                os.close(fd)

            def mutate(held: pathlib.Path) -> None:
                REAL_RUN(
                    ["/usr/bin/xattr", "-w", "user.audit", "1", str(held)],
                    check=True,
                    capture_output=True,
                )

            try:
                with self.assertRaisesRegex(
                    apple_gate.AppleArtifactGateError,
                    "tree was replaced",
                ):
                    self._directory_run_on_path(app, mutate)
            finally:
                self._clear_candidate_metadata(root)

    @unittest.skipUnless(DARWIN, "root ACL mutation is Darwin-only")
    def test_run_on_path_rejects_root_acl_during_run(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-tree-acl-") as temporary:
            root = pathlib.Path(temporary)
            app = self._candidate_app(root)
            fd = os.open(app, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                before = apple_gate._directory_tree_identities(fd)
                REAL_RUN(
                    ["/bin/chmod", "+a", "everyone deny delete", str(app)],
                    check=True,
                    capture_output=True,
                )
                after = apple_gate._directory_tree_identities(fd)
                self.assertNotEqual(before, after)
                self.assertEqual(
                    apple_gate._execution_tree_identity(before),
                    apple_gate._execution_tree_identity(after),
                )
            finally:
                os.close(fd)
                REAL_RUN(
                    ["/bin/chmod", "-N", str(app)],
                    check=False,
                    capture_output=True,
                )

            def mutate(held: pathlib.Path) -> None:
                REAL_RUN(
                    ["/bin/chmod", "+a", "everyone deny delete", str(held)],
                    check=True,
                    capture_output=True,
                )

            try:
                with self.assertRaisesRegex(
                    apple_gate.AppleArtifactGateError,
                    "tree was replaced",
                ):
                    self._directory_run_on_path(app, mutate)
            finally:
                self._clear_candidate_metadata(root)

    @unittest.skipUnless(DARWIN, "child xattr mutation is Darwin-only")
    def test_run_on_path_rejects_child_xattr_during_run(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-tree-cxattr-") as temporary:
            root = pathlib.Path(temporary)
            app = self._candidate_app(root)

            def mutate(held: pathlib.Path) -> None:
                REAL_RUN(
                    [
                        "/usr/bin/xattr",
                        "-w",
                        "user.audit",
                        "1",
                        str(held / "Info.plist"),
                    ],
                    check=True,
                    capture_output=True,
                )

            try:
                with self.assertRaisesRegex(
                    apple_gate.AppleArtifactGateError,
                    "tree was replaced",
                ):
                    self._directory_run_on_path(app, mutate)
            finally:
                self._clear_candidate_metadata(root)

    @unittest.skipUnless(DARWIN, "root chmod mutation is Darwin-only")
    def test_run_on_path_rejects_root_chmod_during_run(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-tree-chmod-") as temporary:
            root = pathlib.Path(temporary)
            app = self._candidate_app(root)

            def mutate(held: pathlib.Path) -> None:
                os.chmod(held, 0o500)

            try:
                with self.assertRaisesRegex(
                    apple_gate.AppleArtifactGateError,
                    "tree was replaced",
                ):
                    self._directory_run_on_path(app, mutate)
            finally:
                self._clear_candidate_metadata(root)

    @unittest.skipUnless(DARWIN, "root flags mutation is Darwin-only")
    def test_run_on_path_rejects_root_flags_during_run(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-tree-flags-") as temporary:
            root = pathlib.Path(temporary)
            app = self._candidate_app(root)

            def mutate(held: pathlib.Path) -> None:
                os.chflags(held, stat.UF_NODUMP)

            try:
                with self.assertRaisesRegex(
                    apple_gate.AppleArtifactGateError,
                    "tree was replaced",
                ):
                    self._directory_run_on_path(app, mutate)
            finally:
                self._clear_candidate_metadata(root)

    @unittest.skipUnless(DARWIN, "sealed inspect rename is Darwin-only")
    def test_run_on_path_restore_only_rename_does_not_false_fail(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-tree-restore-") as temporary:
            root = pathlib.Path(temporary)
            app = self._candidate_app(root)
            completed = self._directory_run_on_path(app)
            self.assertEqual(completed.returncode, 0)
            self.assertTrue(app.is_dir())
            self.assertEqual((app / "Info.plist").read_bytes(), b"plist")
            leftover = list(root.glob(".wins-gate-inspect.*"))
            self.assertEqual(leftover, [])

    @unittest.skipUnless(DARWIN, "raw tree identity false-positive check is Darwin-only")
    def test_run_on_path_raw_tree_compare_has_no_false_positive(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-tree-stable-") as temporary:
            root = pathlib.Path(temporary)
            app = self._candidate_app(root)
            fd = os.open(app, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                first = apple_gate._directory_tree_identities(fd)
                second = apple_gate._directory_tree_identities(fd)
                apple_gate._require_execution_tree_unchanged(first, second, raw=True)
                apple_gate._require_execution_tree_unchanged(first, second, raw=False)
            finally:
                os.close(fd)
            completed = self._directory_run_on_path(app)
            self.assertEqual(completed.returncode, 0)
            self.assertTrue((app / "Info.plist").is_file())

    def test_codesign_verify_argv_never_uses_requirement_file_form(self) -> None:
        requirement = apple_gate._codesign_requirement_for_authority(
            apple_gate.DEVELOPER_ID_APPLICATION_AUTHORITY
        )
        argv = apple_gate._codesign_verify_argv(requirement, deep=False)
        self.assertEqual(argv[0], "/usr/bin/codesign")
        self.assertEqual(apple_gate._codesign_requirement_from_argv(argv), requirement)
        self.assertTrue(argv[-1].startswith("-R="))

    @unittest.skipUnless(DARWIN, "private-root vnode custody is Darwin-only")
    def test_private_gate_root_rejects_parent_swap_and_restore(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-private-parent-swap-") as temporary:
            private = apple_gate._prepare_private_root(pathlib.Path(temporary))
            root = private.root
            saved = root.with_name(root.name + ".saved")
            try:
                root.rename(saved)
                root.mkdir(mode=0o700)
                root.rmdir()
                saved.rename(root)
                with self.assertRaisesRegex(
                    apple_gate.AppleArtifactGateError, "ancestor|changed|substituted"
                ):
                    private.verify_ancestors()
            finally:
                apple_gate._cleanup_private_root(private)

    @unittest.skipUnless(DARWIN, "SIGALRM process-start deadline is Darwin-only")
    def test_bounded_subprocess_caps_blocked_process_start(self) -> None:
        def blocked_popen(*_args, **_kwargs):
            time.sleep(5)
            raise AssertionError("process start deadline did not interrupt Popen")

        started = time.monotonic()
        with mock.patch.object(
            apple_gate, "_macos_descendant_boundary_argv", side_effect=lambda value: value
        ), mock.patch.object(
            apple_gate.subprocess, "Popen", side_effect=blocked_popen
        ), self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "process-start time bound"
        ):
            apple_gate._bounded_subprocess(
                ["/usr/bin/true"], "blocked Popen", timeout=1
            )
        self.assertLess(time.monotonic() - started, 2.0)


class ReviewedSourcePinFreshnessTests(unittest.TestCase):
    """Every reviewed-source pin must equal the sha256 of the file it names."""

    @staticmethod
    def _digest(relative: str) -> str:
        return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()

    @staticmethod
    def _literal_constant(relative: str, name: str) -> object:
        import ast

        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        values = [
            ast.literal_eval(node.value)
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == name
                for target in node.targets
            )
        ]
        if len(values) != 1:
            raise AssertionError(f"{relative} must assign {name} exactly once")
        return values[0]

    def test_held_artifact_review_pins_match_the_reviewed_files(self) -> None:
        names = {filename for filename, _label in apple_gate.HELD_ARTIFACT_REVIEW_SOURCES}
        self.assertEqual(set(apple_gate.HELD_ARTIFACT_REVIEW_SOURCE_SHA256), names)
        for filename in sorted(names):
            with self.subTest(filename=filename):
                self.assertEqual(
                    apple_gate.HELD_ARTIFACT_REVIEW_SOURCE_SHA256[filename],
                    self._digest(f"tools/{filename}"),
                )

    def test_cross_store_gate_pins_match_the_gate_file(self) -> None:
        gate = self._digest(apple_gate.DESCRIPTOR_RELATIVE)
        for relative in (
            "tools/validate_apple_submission_package.py",
            "tools/release_obfuscation_contract.py",
        ):
            with self.subTest(relative=relative):
                self.assertEqual(
                    self._literal_constant(
                        relative, "APPLE_CROSS_STORE_GATE_HELPER_SHA256"
                    ),
                    gate,
                )

    def test_watch_verifier_pins_match_the_watch_verifier(self) -> None:
        watch = self._digest("tools/apple_watch_artifact_verifier.py")
        for relative in (
            "tools/apple_upload_exact_release_candidates.py",
            "tools/apple_final_evidence_collector.py",
        ):
            with self.subTest(relative=relative):
                self.assertEqual(
                    self._literal_constant(relative, "WATCH_ARTIFACT_VERIFIER_SHA256"),
                    watch,
                )



class XcrunLookupWarmupTests(unittest.TestCase):
    """The xcrun shims get their cache entry before the confined inspection."""

    def setUp(self) -> None:
        apple_gate._XCRUN_WARMED.clear()
        self.addCleanup(apple_gate._XCRUN_WARMED.clear)

    def test_shim_tool_is_warmed_once_unconfined_then_runs_confined(self) -> None:
        calls: list[tuple[list[str], dict]] = []

        def bounded(argv, label, **kwargs):
            calls.append((list(argv), dict(kwargs)))
            if argv[:2] == [apple_gate.XCRUN, "--find"]:
                return subprocess.CompletedProcess(argv, 0, b"/usr/bin/lipo\n", b"")
            return subprocess.CompletedProcess(argv, 0, b"arm64\n", b"")

        with mock.patch.object(apple_gate, "_bounded_subprocess", side_effect=bounded):
            apple_gate._run(["/usr/bin/lipo", "-archs", "x"], "Mach-O architecture inspection")
            apple_gate._run(["/usr/bin/lipo", "-archs", "y"], "Mach-O architecture inspection")
        self.assertEqual(
            [argv for argv, _kwargs in calls],
            [
                [apple_gate.XCRUN, "--find", "lipo"],
                ["/usr/bin/lipo", "-archs", "x"],
                ["/usr/bin/lipo", "-archs", "y"],
            ],
        )
        warm_kwargs = calls[0][1]
        self.assertIs(warm_kwargs["descendant_boundary"], False)
        self.assertNotIn("preexec_fn", warm_kwargs)
        self.assertEqual(warm_kwargs["env"], apple_gate._subprocess_env())
        for _argv, kwargs in calls[1:]:
            self.assertNotIn("descendant_boundary", kwargs)
            self.assertIs(kwargs["preexec_fn"], apple_gate._apply_tool_rlimits)

    def test_unresolved_lookup_fails_closed_before_the_tool_runs(self) -> None:
        calls: list[list[str]] = []

        def bounded(argv, label, **kwargs):
            calls.append(list(argv))
            return subprocess.CompletedProcess(argv, 1, b"", b"xcrun: error")

        with mock.patch.object(apple_gate, "_bounded_subprocess", side_effect=bounded):
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "xcrun cannot resolve the reviewed Xcode tool nm"
            ):
                apple_gate._run(["/usr/bin/nm", "-a", "x"], "Mach-O symbol-table inspection")
        self.assertEqual(calls, [[apple_gate.XCRUN, "--find", "nm"]])

    def test_lookup_result_must_be_a_root_owned_bin_tool_of_that_name(self) -> None:
        self.assertTrue(apple_gate._reviewed_xcrun_lookup("/usr/bin/lipo", "lipo"))
        for found, name in (
            ("", "lipo"),
            ("usr/bin/lipo", "lipo"),
            ("/usr/bin/../bin/lipo", "lipo"),
            ("/usr/bin/lipo", "nm"),
            ("/usr/bin/lipo\n", "lipo"),
            ("/usr/libexec/lipo", "lipo"),
            ("/nonexistent/bin/lipo", "lipo"),
        ):
            with self.subTest(found=found, name=name):
                self.assertFalse(apple_gate._reviewed_xcrun_lookup(found, name))
        with tempfile.TemporaryDirectory() as temporary:
            own = pathlib.Path(temporary) / "bin" / "lipo"
            own.parent.mkdir()
            own.write_bytes(b"")
            own.chmod(0o755)
            self.assertFalse(apple_gate._reviewed_xcrun_lookup(str(own), "lipo"))

    def test_xcrun_runs_only_the_reviewed_single_process_tools(self) -> None:
        with mock.patch.object(apple_gate, "_bounded_subprocess") as bounded:
            for argv in (
                [apple_gate.XCRUN],
                [apple_gate.XCRUN, "otool", "-l", "x"],
                [apple_gate.XCRUN, "--find", "lipo"],
                [apple_gate.XCRUN, "-r", "otool-classic", "-l", "x"],
            ):
                with self.subTest(argv=argv):
                    with self.assertRaisesRegex(
                        apple_gate.AppleArtifactGateError, "unreviewed xcrun tool"
                    ):
                        apple_gate._run(argv, "Mach-O load-command inspection")
            bounded.assert_not_called()


class RealPkgutilInstallerSignatureTests(unittest.TestCase):
    """The exact shape pkgutil printed for rehearsal r40's Mac App Store PKG."""

    NNBSP = "\u202f"

    def _output(self, status: str, expires_space: str) -> str:
        return (
            'Package "Win\'s VPN.pkg":\n'
            f"   Status: {status}\n"
            "   Certificate Chain:\n"
            "    1. 3rd Party Mac Developer Installer: Win's VPN Inc (5YT8H4U72M)\n"
            f"       Expires: 2027-08-31 3:48:47{expires_space}AM +0000\n"
            "       SHA256 Fingerprint:\n"
            "           C0 57 CD 46 30 C6 23 F2 52 C4 3F F2 DC BC AC 6F 98 88 1B 14 71 B6\n"
            "    2. Apple Worldwide Developer Relations Certification Authority\n"
            f"       Expires: 2030-02-20 12:00:00{expires_space}AM +0000\n"
            "    3. Apple Root CA\n"
            f"       Expires: 2035-02-09 9:40:36{expires_space}PM +0000\n"
        )

    def test_app_store_installer_status_and_icu_expiry_spacing_pass(self) -> None:
        output = self._output(
            "signed by a developer certificate issued by Apple (Development)", self.NNBSP
        )
        apple_gate._require_pkg_installer_signature(output, 0)

    def test_narrow_space_outside_an_expiry_time_is_still_refused(self) -> None:
        output = self._output(
            "signed by a developer certificate issued by Apple (Development)", self.NNBSP
        ).replace("Certificate Chain:", f"Certificate{self.NNBSP}Chain:")
        with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "forbidden Unicode"):
            apple_gate._require_pkg_installer_signature(output, 0)

    def test_developer_id_distribution_status_is_not_the_app_store_route(self) -> None:
        output = self._output(
            "signed by a developer certificate issued by Apple for distribution", " "
        )
        with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "not release-valid"):
            apple_gate._require_pkg_installer_signature(output, 0)


class RealCodesignIdentitySpacingTests(unittest.TestCase):
    """codesign --display --verbose=4 as rehearsal r41 printed it for the iOS app."""

    NNBSP = "\u202f"

    def _output(self, signed_time: str) -> str:
        return (
            "Identifier=org.winsvpn.app\n"
            "Authority=Apple Distribution: Win's VPN Inc (5YT8H4U72M)\n"
            "Authority=Apple Worldwide Developer Relations Certification Authority\n"
            "Authority=Apple Root CA\n"
            f"{signed_time}\n"
            "TeamIdentifier=5YT8H4U72M\n"
        )

    def test_icu_spacing_in_signed_time_and_timestamp_passes(self) -> None:
        for line in (
            f"Signed Time=17 Oct 2026 at 1:09:03{self.NNBSP}PM",
            f"Timestamp=Oct 17, 2026 at 1:09:03{self.NNBSP}PM",
        ):
            with self.subTest(line=line.split("=")[0]):
                authorities, teams = apple_gate._codesign_authority_and_team(self._output(line))
                self.assertIn("Authority=Apple Distribution: Win's VPN Inc (5YT8H4U72M)", authorities)
                self.assertEqual(teams, ["5YT8H4U72M"])

    def test_narrow_space_elsewhere_in_codesign_output_is_refused(self) -> None:
        output = self._output(f"Signed Time=17 Oct 2026 at 1:09:03{self.NNBSP}PM").replace(
            "Authority=Apple Root CA", f"Authority=Apple{self.NNBSP}Root CA"
        )
        with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "forbidden Unicode"):
            apple_gate._codesign_authority_and_team(output)

if __name__ == "__main__":
    unittest.main()
