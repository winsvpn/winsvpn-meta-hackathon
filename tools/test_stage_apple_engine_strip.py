#!/usr/bin/env python3
"""Hostile tests for Apple engine delivery stripping before signing."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
STAGING = ROOT / "tools" / "stage_apple_engine_artifacts.sh"
AWG_WRAPPER = ROOT / "apple" / "EngineWrappers" / "WinsAmneziaWGPacketEngine.m"

AWG = "amneziawg_packet_engine"
XRAY = "xray_vless_ws_transport"
WINN = "winn_packet_engine"

AWG_SOURCE = """\
int wins_amneziawg_packet_engine_contract_version(void) { return 1; }
void *wins_amneziawg_packet_engine_create(const char *launch_json, const void *packet_flow) { (void)launch_json; (void)packet_flow; return (void *)0; }
int wins_amneziawg_packet_engine_start(void *engine) { return engine == (void *)0 ? 0 : 1; }
int wins_amneziawg_packet_engine_listen_port(void *engine) { (void)engine; return 0; }
void wins_amneziawg_packet_engine_stop(void *engine) { (void)engine; }
void wins_amneziawg_packet_engine_destroy(void *engine) { (void)engine; }
"""
AWG_LOCAL_SOURCE = """\
static int wins_amneziawg_packet_engine_secret(void) { return 7; }
int wins_amneziawg_packet_engine_contract_version(void) { return wins_amneziawg_packet_engine_secret(); }
void *wins_amneziawg_packet_engine_create(const char *launch_json, const void *packet_flow) { (void)launch_json; (void)packet_flow; return (void *)0; }
int wins_amneziawg_packet_engine_start(void *engine) { return engine == (void *)0 ? 0 : 1; }
int wins_amneziawg_packet_engine_listen_port(void *engine) { (void)engine; return 0; }
void wins_amneziawg_packet_engine_stop(void *engine) { (void)engine; }
void wins_amneziawg_packet_engine_destroy(void *engine) { (void)engine; }
"""
XRAY_SOURCE = """\
int wins_xray_vless_ws_transport_contract_version(void) { return 1; }
int wins_xray_vless_ws_transport_configure(const char *config_json) { return config_json == (const char *)0 ? 0 : 1; }
int wins_xray_vless_ws_transport_start(void) { return 1; }
void wins_xray_vless_ws_transport_stop(void) {}
"""
WINN_SOURCE = """\
int wins_winn_packet_engine_contract_version(void) { return 1; }
void *wins_winn_packet_engine_create(const char *launch_json, const void *packet_flow) { (void)launch_json; (void)packet_flow; return (void *)0; }
int wins_winn_packet_engine_start(void *engine) { return engine == (void *)0 ? 0 : 1; }
void wins_winn_packet_engine_stop(void *engine) { (void)engine; }
void wins_winn_packet_engine_destroy(void *engine) { (void)engine; }
int wins_winn_packet_engine_awg_seam_port(void *engine) { (void)engine; return 0; }
int wins_winn_packet_engine_expect_awg_port(void *engine, int port) { (void)engine; (void)port; return 0; }
int wins_winn_packet_engine_seam_stats(void *engine, char *out, int capacity) { (void)engine; (void)out; (void)capacity; return 0; }
int wins_winn_packet_engine_status_json(void *engine, char *out, int capacity) { (void)engine; (void)out; (void)capacity; return 0; }
const char *WinnTunnelCreateWinn3(const char *doc, int fd, char **err) { (void)doc; (void)fd; (void)err; return 0; }
const char *WinnTunnelCreate(const char *doc, int fd, char **err) { (void)doc; (void)fd; (void)err; return 0; }
const char *WinnTunnelCreateWithCarrier(const char *doc, int fd, char **err) { (void)doc; (void)fd; (void)err; return 0; }
"""


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def clang() -> str:
    return subprocess.check_output(["xcrun", "-f", "clang"], text=True).strip()


def sdk(name: str) -> str:
    return subprocess.check_output(
        ["xcrun", "--sdk", name, "--show-sdk-path"], text=True
    ).strip()


def exported(path: pathlib.Path, arch: str | None = None) -> set[str]:
    command = ["/usr/bin/nm", "-gU"]
    if arch:
        command.extend(["-arch", arch])
    command.append(str(path))
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    names = set()
    for line in completed.stdout.splitlines():
        parts = line.split()
        if parts:
            names.add(parts[-1].lstrip("_"))
    return names


class StageAppleEngineStripTests(unittest.TestCase):
    def source(self) -> str:
        return STAGING.read_text(encoding="utf-8")

    def test_strip_runs_before_signing_and_keeps_required_exports(self) -> None:
        staging = self.source()
        stage_fn = staging.split("stage_artifact() {", 1)[1].split(
            "\napple_awg_engine_provenance_path() {", 1
        )[0]
        prepare_fn = staging.split("prepare_stripped_engine_delivery() {", 1)[1].split(
            "\nrequire_component_dependencies() {", 1
        )[0]
        self.assertIn('prepare_stripped_engine_delivery "${component}" "${executable_path}"', stage_fn)
        self.assertIn('require_stripped_engine_binary "${component}" "${executable_path}"', stage_fn)
        self.assertLess(
            stage_fn.index("prepare_stripped_engine_delivery"),
            stage_fn.index("codesign --force --sign"),
        )
        self.assertLess(
            stage_fn.index("require_stripped_engine_binary"),
            stage_fn.index("codesign --force --sign"),
        )
        self.assertIn('if engine_delivery_is_stripped "${executable}"; then', prepare_fn)
        self.assertLess(
            prepare_fn.index('if engine_delivery_is_stripped "${executable}"; then'),
            prepare_fn.index('"${WINS_STRIP_BIN}" -x -no_code_signature_warning'),
        )
        self.assertIn("destination hashes stay bound to provenance", prepare_fn)
        self.assertNotIn("-x -S", prepare_fn)
        self.assertIn("require_stripped_engine_binary", staging.split("require_valid_artifact() {", 1)[1].split("\nfind_component_artifact() {", 1)[0])
        self.assertIn("non-external", staging)
        self.assertIn("nlocalsym", staging)
        self.assertIn("reject_unstripped_native_blob", staging)

    def test_clean_macos_and_ios_destinations_keep_exports_and_source_hashes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-engine-strip-bind-") as raw:
            root = pathlib.Path(raw).resolve()
            macos_root = root / "macos"
            ios_root = root / "ios"
            macos = self._stage(
                macos_root,
                "macosx",
                extra_args=["-arch", "arm64", "-arch", "x86_64", "-mmacosx-version-min=13.0"],
                archs="arm64 x86_64",
            )
            ios = self._stage(
                ios_root,
                "iphoneos",
                extra_args=["-target", "arm64-apple-ios13.0", "-isysroot", sdk("iphoneos")],
                archs="arm64",
            )
            self.assertEqual(macos.returncode, 0, macos.stderr + macos.stdout)
            self.assertEqual(ios.returncode, 0, ios.stderr + ios.stdout)
            macos_src = macos_root / "src" / "libWinsAmneziaWGPacketEngine.dylib"
            macos_dst = (
                macos_root
                / "build"
                / "Runner.app"
                / "Frameworks"
                / "WinsAmneziaWGPacketEngine.framework"
                / "Versions"
                / "A"
                / "WinsAmneziaWGPacketEngine"
            )
            self.assertEqual(sha256(macos_src), sha256(macos_dst))
            self.assertTrue(
                {
                    "wins_amneziawg_packet_engine_contract_version",
                    "wins_amneziawg_packet_engine_create",
                    "wins_amneziawg_packet_engine_start",
                    "wins_amneziawg_packet_engine_stop",
                    "wins_amneziawg_packet_engine_destroy",
                }.issubset(exported(macos_dst))
            )
            macos_xray_src = macos_root / "src" / "libWinsXrayVlessWsTransport.dylib"
            macos_xray_dst = (
                macos_root
                / "build"
                / "Runner.app"
                / "Frameworks"
                / "WinsXrayVlessWsTransport.framework"
                / "Versions"
                / "A"
                / "WinsXrayVlessWsTransport"
            )
            self.assertEqual(sha256(macos_xray_src), sha256(macos_xray_dst))
            self.assertTrue(
                {
                    "wins_xray_vless_ws_transport_contract_version",
                    "wins_xray_vless_ws_transport_configure",
                    "wins_xray_vless_ws_transport_start",
                    "wins_xray_vless_ws_transport_stop",
                }.issubset(exported(macos_xray_dst))
            )
            ios_src = ios_root / "src" / "libWinsWinnPacketEngine.dylib"
            ios_dst = (
                ios_root
                / "build"
                / "Runner.app"
                / "Frameworks"
                / "WinsWinnPacketEngine.framework"
                / "WinsWinnPacketEngine"
            )
            self.assertEqual(sha256(ios_src), sha256(ios_dst))
            self.assertTrue(
                {
                    "wins_winn_packet_engine_contract_version",
                    "wins_winn_packet_engine_create",
                    "wins_winn_packet_engine_start",
                    "wins_winn_packet_engine_stop",
                    "wins_winn_packet_engine_destroy",
                    "wins_winn_packet_engine_awg_seam_port",
                    "wins_winn_packet_engine_seam_stats",
                    "wins_winn_packet_engine_status_json",
                    "WinnTunnelCreateWinn3",
                }.issubset(exported(ios_dst))
            )
            ios_xray_src = ios_root / "src" / "libWinsXrayVlessWsTransport.dylib"
            ios_xray_dst = (
                ios_root
                / "build"
                / "Runner.app"
                / "Frameworks"
                / "WinsXrayVlessWsTransport.framework"
                / "WinsXrayVlessWsTransport"
            )
            self.assertEqual(sha256(ios_xray_src), sha256(ios_xray_dst))
            self.assertTrue(
                {
                    "wins_xray_vless_ws_transport_contract_version",
                    "wins_xray_vless_ws_transport_configure",
                    "wins_xray_vless_ws_transport_start",
                    "wins_xray_vless_ws_transport_stop",
                }.issubset(exported(ios_xray_dst))
            )

    def test_local_debug_and_mixed_slice_symbols_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-engine-strip-hostile-") as raw:
            root = pathlib.Path(raw).resolve()
            local = self._stage(
                root / "local",
                "macosx",
                extra_args=["-arch", os.uname().machine, "-mmacosx-version-min=13.0"],
                awg_source=AWG_LOCAL_SOURCE,
                clean_awg=False,
            )
            self.assertNotEqual(local.returncode, 0, local.stdout)
            self.assertIn("non-public or local symbols", local.stderr + local.stdout)

            debug = self._stage(
                root / "debug",
                "macosx",
                extra_args=["-arch", os.uname().machine, "-mmacosx-version-min=13.0", "-g"],
                clean_awg=False,
            )
            self.assertNotEqual(debug.returncode, 0, debug.stdout)
            self.assertIn("non-public or local symbols", debug.stderr + debug.stdout)

            mixed = self._stage_mixed_slice(root / "mixed")
            self.assertNotEqual(mixed.returncode, 0, mixed.stdout)
            combined = mixed.stderr + mixed.stdout
            self.assertIn("non-public or local symbols", combined)

            ios_local = self._stage(
                root / "ios-local",
                "iphoneos",
                extra_args=["-target", "arm64-apple-ios13.0", "-isysroot", sdk("iphoneos")],
                archs="arm64",
                awg_source=AWG_LOCAL_SOURCE,
                clean_awg=False,
            )
            self.assertNotEqual(ios_local.returncode, 0, ios_local.stdout)
            self.assertIn("non-public or local symbols", ios_local.stderr + ios_local.stdout)

    def test_winn_producer_validates_link_output_without_rewriting_it(self) -> None:
        """`strip -x` over a Go-linked dylib inserts the ld64 `radr://5614542`
        stab (nlocalsym 1), which the strict staging check refuses. The Winn
        producer therefore links with -Wl,-x and only validates: it never
        rewrites the bytes, and it refuses any local or stab symbol."""
        wrappers_path = ROOT / "tools" / "build_apple_engine_wrappers.sh"
        wrappers = wrappers_path.read_text(encoding="utf-8")
        body = wrappers.split("\nstrip_and_validate_dylib() {\n", 1)[1].split("\n}\n", 1)[0]
        self.assertNotIn('"${STRIP_BIN}"', body)
        self.assertIn('require_stripped "${binary}"', body)
        self.assertIn("nlocalsym", body)
        link = wrappers.split('winn_slice="${temp_dir}/libWinsWinnPacketEngine-${arch}.dylib"', 1)[1]
        self.assertLess(link.index("-Wl,-x"), link.index('strip_and_validate_dylib "${winn_slice}"'))
        # The signed release c-archives keep DWARF in go.o; -Wl,-S keeps the
        # debug map (and its OSO path to the archive snapshot) out of the link.
        self.assertLess(link.index("-Wl,-S"), link.index('strip_and_validate_dylib "${winn_slice}"'))

        def function(name: str) -> str:
            start = wrappers.index("\n" + name + "() {\n") + 1
            return wrappers[start:wrappers.index("\n}\n", start) + 3]

        harness = "".join(
            function(name) for name in ("die", "require_stripped", "strip_and_validate_dylib")
        )
        with tempfile.TemporaryDirectory(prefix="wins-winn-strip-step-") as raw:
            root = pathlib.Path(raw)
            exports = "int wins_winn_probe(void) { return 1; }\n"
            with_local = (
                "static int wins_winn_local(void) { return 2; }\n"
                "int wins_winn_probe(void) { return wins_winn_local(); }\n"
            )
            cases = (
                ("linked-x", exports, ["-Wl,-x"], True, ""),
                ("debug-stabs", exports, ["-g", "-Wl,-x"], False, "retains local or stab symbols"),
                ("debug-linked-x-S", exports, ["-g", "-Wl,-x", "-Wl,-S"], True, ""),
                ("local-symbol", with_local, [], False, "non-external symbols"),
            )
            for name, source, flags, accepted, message in cases:
                c_file = root / f"{name}.c"
                c_file.write_text(source, encoding="utf-8")
                dylib = root / f"{name}.dylib"
                subprocess.run(
                    [clang(), "-dynamiclib", "-isysroot", sdk("macosx"),
                     "-arch", os.uname().machine, *flags,
                     str(c_file), "-o", str(dylib)],
                    check=True,
                    capture_output=True,
                )
                before = sha256(dylib)
                completed = subprocess.run(
                    ["/bin/bash", "-c",
                     "set -Eeuo pipefail\n" + harness + 'strip_and_validate_dylib "$1"\n',
                     "harness", str(dylib)],
                    env={
                        "PATH": "/usr/bin:/bin",
                        "NM_BIN": "/usr/bin/nm",
                        "OTOOL_BIN": "/usr/bin/otool",
                        "LIPO_BIN": "/usr/bin/lipo",
                        "STRIP_BIN": "/usr/bin/strip",
                    },
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(sha256(dylib), before, name)
                if accepted:
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                else:
                    self.assertNotEqual(completed.returncode, 0, name)
                    self.assertIn(message, completed.stderr, name)

    def _stage(
        self,
        root: pathlib.Path,
        platform: str,
        *,
        extra_args: list[str],
        archs: str | None = None,
        awg_source: str = AWG_SOURCE,
        reuse_awg: bool = False,
        clean_awg: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        src = root / "src"
        build = root / "build"
        src.mkdir(parents=True, exist_ok=True)
        fixture_awg_wrapper = (
            root / "apple" / "EngineWrappers" / "WinsAmneziaWGPacketEngine.m"
        )
        fixture_awg_wrapper.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(AWG_WRAPPER, fixture_awg_wrapper)
        awg = src / "libWinsAmneziaWGPacketEngine.dylib"
        xray = src / "libWinsXrayVlessWsTransport.dylib"
        winn = src / "libWinsWinnPacketEngine.dylib"
        if not reuse_awg:
            self._compile(
                awg,
                awg_source,
                "@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine",
                extra_args,
                clean=clean_awg,
            )
        self._compile(
            xray,
            XRAY_SOURCE,
            "@rpath/WinsXrayVlessWsTransport.framework/WinsXrayVlessWsTransport",
            extra_args,
            extra_link=[
                f"-L{src}",
                "-lWinsAmneziaWGPacketEngine",
                "-Wl,-rpath,@loader_path/..",
            ],
        )
        self._compile(
            winn,
            WINN_SOURCE,
            "@rpath/WinsWinnPacketEngine.framework/WinsWinnPacketEngine",
            extra_args,
        )
        (src / "apple_awg_31_engine_provenance.json").write_text(
            json.dumps(self._awg_provenance(platform, awg, xray), indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        self._write_xray_provenance(platform, src, xray)
        self._write_winn_provenance(platform, src, winn)
        environment = os.environ.copy()
        environment.update(
            {
                "PROJECT_ROOT": str(root),
                "APPLE_ENGINE_ARTIFACTS_DIR": str(src),
                "TARGET_BUILD_DIR": str(build),
                "FRAMEWORKS_FOLDER_PATH": "Runner.app/Frameworks",
                "UNLOCALIZED_RESOURCES_FOLDER_PATH": "Runner.app",
                "PLUGINS_FOLDER_PATH": "Runner.app/PlugIns",
                "PLATFORM_NAME": platform,
                "ARCHS": archs or os.uname().machine,
                "WINS_REQUIRE_APPLE_ENGINE": "1",
                "WINS_APPLE_WINN3_RELEASE": "0",
                "WINS_STAGE_APPLE_ENGINE_SELFTEST": "0",
                "CODE_SIGNING_ALLOWED": "NO",
            }
        )
        return subprocess.run(
            ["bash", str(STAGING)],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def _stage_mixed_slice(self, root: pathlib.Path) -> subprocess.CompletedProcess[str]:
        src = root / "src"
        src.mkdir(parents=True)
        dirty = src / "awg-arm64.dylib"
        clean = src / "awg-x86_64.dylib"
        self._compile(
            dirty,
            AWG_LOCAL_SOURCE,
            "@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine",
            ["-arch", "arm64"],
            clean=False,
        )
        self._compile(
            clean,
            AWG_SOURCE,
            "@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine",
            ["-arch", "x86_64"],
        )
        awg = src / "libWinsAmneziaWGPacketEngine.dylib"
        completed = subprocess.run(
            ["/usr/bin/lipo", "-create", str(dirty), str(clean), "-output", str(awg)],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise AssertionError(completed.stderr or completed.stdout)
        return self._stage(
            root,
            "macosx",
            extra_args=["-arch", os.uname().machine, "-mmacosx-version-min=13.0"],
            reuse_awg=True,
        )

    def _compile(
        self,
        output: pathlib.Path,
        source: str,
        install_name: str,
        extra_args: list[str],
        extra_link: list[str] | None = None,
        strip: bool = False,
        clean: bool = True,
    ) -> None:
        src = output.with_suffix(".c")
        src.write_text(source, encoding="utf-8")
        # The raw toolchain clang has no default SDK outside an Xcode build
        # environment; macOS fixtures name the macOS SDK the way the iOS
        # fixtures already pass the iPhoneOS SDK in extra_args.
        sysroot = [] if "-isysroot" in extra_args else ["-isysroot", sdk("macosx")]
        command = [
            clang(),
            "-dynamiclib",
            *sysroot,
            *(["-Wl,-x"] if clean else []),
            *extra_args,
            f"-Wl,-install_name,{install_name}",
            *(extra_link or []),
            str(src),
            "-o",
            str(output),
        ]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        src.unlink(missing_ok=True)
        if completed.returncode != 0:
            raise AssertionError(
                f"dylib compile failed for {output.name}: {completed.stderr}"
            )
        if strip:
            stripped = subprocess.run(
                [
                    "/usr/bin/strip",
                    "-x",
                    "-no_code_signature_warning",
                    str(output),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if stripped.returncode != 0:
                raise AssertionError(
                    f"strip failed for {output.name}: {stripped.stderr}"
                )

    def _awg_provenance(
        self, platform: str, awg: pathlib.Path, xray: pathlib.Path
    ) -> dict[str, object]:
        architectures = ["arm64"] if platform == "iphoneos" else ["arm64", "x86_64"]
        awg_wrapper = awg.parents[1] / "apple" / "EngineWrappers" / "WinsAmneziaWGPacketEngine.m"
        return {
            "awg_wrapper_source": {
                "path": "apple/EngineWrappers/WinsAmneziaWGPacketEngine.m",
                "sha256": sha256(awg_wrapper),
            },
            "bridge_provenance_sha256": "0" * 64,
            "component": "amneziawg-apple-engine-wrappers",
            "generation": "3.1",
            "go_toolchain": {
                "darwin_amd64_archive_sha256": "8f8f52c6649542cf027bbc9b9c68d1ec042f9f34808a40413f0b8b3f66f3caa4",
                "darwin_arm64_archive_sha256": "ee215d57e0ec269c60cc9ceca68e6bda321ba9ee5afe24f4b0988703c2d87d12",
                "version": "1.27.1",
            },
            "schema_version": 2,
            "source": {
                "commit": "fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d",
                "go_mod_sha256": "790252dad6cad8aa668ccc4dafdfdac4f2fa3d3fbefce16ded750f0a46cabe0d",
                "go_sum_sha256": "1a806e7973118c0ce8832e15d246fea0c44335a31fc4a0abe36a2ed165fada9d",
                "repository": "https://github.com/amnezia-vpn/amneziawg-apple.git",
                "tag": "v3.1.20260814",
                "tree": "24183de0cc22b957ff9e34ac3494a80f515ac565",
            },
            "wrappers": {
                platform: {
                    AWG: {
                        "architectures": architectures,
                        "path": "selftest/libWinsAmneziaWGPacketEngine.dylib",
                        "sha256": sha256(awg),
                    },
                    XRAY: {
                        "architectures": architectures,
                        "path": "selftest/libWinsXrayVlessWsTransport.dylib",
                        "sha256": sha256(xray),
                    },
                }
            },
            "xray_replacement": {
                "commit": "77e5d55a796bafe17c1b5f2a9d9c590fd2a9f5f3",
                "go_mod_sum": "h1:VwJOtL3vj2w+8TWa6MZE1q88NsfrWvOXGJ+5wZ2N2ro=",
                "module_sum": "h1:4PniqnMxVxC54OdTx3e73BOMH/GD6jf85iaRyApAwGQ=",
                "replaced_module": "github.com/xtls/xray-core",
                "source_module": "github.com/amnezia-vpn/amnezia-xray-core",
                "version": "v1.260924.0",
                "zip_sha256": "7df5ebc400da6cc4ab13f5578e2fd19b855f98807f1ef1d86a30afc2cd213c40",
            },
        }

    def _write_xray_provenance(
        self, platform: str, src: pathlib.Path, xray: pathlib.Path
    ) -> None:
        manifest = {
            "component": "xray-apple-vless-ws-engine-wrappers",
            "schema_version": 1,
            "wrappers": {platform: {"sha256": sha256(xray)}},
        }
        (src / "apple_xray_vless_ws_engine_provenance.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def _write_winn_provenance(
        self, platform: str, src: pathlib.Path, winn: pathlib.Path
    ) -> None:
        """Schema 5 Winn provenance whose staged-platform entry is measured from
        the fixture dylib; the other platforms carry fixed fixture slices."""
        digest = sha256(winn)
        install_name = "@rpath/WinsWinnPacketEngine.framework/WinsWinnPacketEngine"
        platform_name = {
            "iphoneos": "IOS",
            "iphonesimulator": "IOSSIMULATOR",
            "macosx": "MACOS",
        }[platform]
        macho_platforms = {
            "1": "MACOS", "2": "IOS", "7": "IOSSIMULATOR",
            "MACOS": "MACOS", "IOS": "IOS", "IOSSIMULATOR": "IOSSIMULATOR",
        }
        tools = {
            name: pathlib.Path("/usr/bin") / name
            for name in ("ar", "clang", "file", "lipo", "nm", "otool", "strip", "vtool")
        }
        roles = {
            "core": ["WinnTunnelCreateWinn3"],
            "relay": ["WinnTunnelCreate", "WinnTunnelCreateWithCarrier"],
        }

        def command(tool: str, *arguments: str) -> str:
            return subprocess.check_output([str(tools[tool]), *arguments], text=True)

        def values(text: str, field: str) -> list[str]:
            return [
                fields[1]
                for line in text.splitlines()
                if len(fields := line.strip().split()) >= 2 and fields[0] == field
            ]

        def platforms(text: str) -> list[str]:
            return sorted({
                macho_platforms[fields[1]]
                for line in text.splitlines()
                if len(fields := line.strip().split()) >= 2
                and fields[0] == "platform"
                and fields[1] in macho_platforms
            })

        def measured_slice(arch: str) -> dict[str, object]:
            load = command("otool", "-arch", arch, "-l", str(winn))
            self.assertEqual(platforms(load), [platform_name])
            uuids = values(load, "uuid")
            self.assertEqual(len(uuids), 1)
            minos = values(command("vtool", "-show-build", "-arch", arch, str(winn)), "minos")
            dependencies = sorted({
                value.split(" (", 1)[0]
                for line in command("otool", "-arch", arch, "-L", str(winn)).splitlines()
                if (value := line.strip())
                and not value.endswith(":")
                and not value.startswith(str(winn))
                and value.split(" (", 1)[0] != install_name
            })
            return {
                "architecture": arch,
                "dependencies": dependencies,
                "filetype": "MH_DYLIB",
                "install_name": install_name,
                "minos": minos[0],
                "platform": platform_name,
                "role_symbols": roles,
                "uuid": uuids[0].upper(),
            }

        def fixture_slice(arch: str, slice_platform: str, minos: str, uuid: str) -> dict[str, object]:
            return {
                "architecture": arch,
                "dependencies": ["/usr/lib/libSystem.B.dylib"],
                "filetype": "MH_DYLIB",
                "install_name": install_name,
                "minos": minos,
                "platform": slice_platform,
                "role_symbols": roles,
                "uuid": uuid,
            }

        def fixture_hash(label: str) -> str:
            return hashlib.sha256(f"winsvpn-strip-fixture:{label}".encode("ascii")).hexdigest()

        archives = {}
        for key, name, header, arch, archive_platform, target in (
            ("iphoneos_arm64", "libwinn-datapath-ios-arm64.a", "libwinn-datapath-ios-arm64.h", "arm64", "IOS", "datapath-ios-arm64"),
            ("macosx_arm64", "libwinn-datapath-darwin-arm64.a", "libwinn-datapath-darwin-arm64.h", "arm64", "MACOS", "datapath-archive-darwin-arm64"),
            ("macosx_x86_64", "libwinn-datapath-darwin-amd64.a", "libwinn-datapath-darwin-amd64.h", "x86_64", "MACOS", "datapath-archive-darwin-amd64"),
            ("iphonesimulator_arm64", "libwinn-datapath-iossimulator-arm64.a", "libwinn-datapath-iossimulator-arm64.h", "arm64", "IOSSIMULATOR", "datapath-iossimulator-arm64"),
            ("iphonesimulator_x86_64", "libwinn-datapath-iossimulator-amd64.a", "libwinn-datapath-iossimulator-amd64.h", "x86_64", "IOSSIMULATOR", "datapath-iossimulator-amd64"),
        ):
            archive = src / name
            header_path = src / header
            archive.write_bytes(f"selftest-archive:{key}\n".encode("ascii"))
            header_path.write_text(f"/* {name} */\n", encoding="utf-8")
            archives[key] = {
                "architectures": [arch],
                "build_a_sha256": sha256(archive),
                "build_b_sha256": sha256(archive),
                "filetype": "ar-archive",
                "header_path": header,
                "header_sha256": sha256(header_path),
                "path": name,
                "platform": archive_platform,
                "sha256": sha256(archive),
                "target": target,
            }
        wrappers = {
            "iphoneos": {
                "architectures": ["arm64"],
                "filetype": "mach-o-dylib",
                "path": "ios/iphoneos/libWinsWinnPacketEngine.dylib",
                "platform": "IOS",
                "roles": ["core", "relay"],
                "sha256": fixture_hash("iphoneos-wrapper"),
                "slices": {
                    "arm64": fixture_slice("arm64", "IOS", "13.0", "11111111-1111-1111-1111-111111111111"),
                },
                "strip_state": "stripped",
            },
            "iphonesimulator": {
                "architectures": ["arm64", "x86_64"],
                "filetype": "mach-o-dylib",
                "path": "ios/iphonesimulator/libWinsWinnPacketEngine.dylib",
                "platform": "IOSSIMULATOR",
                "roles": ["core", "relay"],
                "sha256": fixture_hash("iphonesimulator-wrapper"),
                "slices": {
                    "arm64": fixture_slice("arm64", "IOSSIMULATOR", "14.0", "22222222-2222-2222-2222-222222222222"),
                    "x86_64": fixture_slice("x86_64", "IOSSIMULATOR", "13.0", "33333333-3333-3333-3333-333333333333"),
                },
                "strip_state": "stripped",
            },
            "macosx": {
                "architectures": ["arm64", "x86_64"],
                "filetype": "mach-o-dylib",
                "path": "macos/libWinsWinnPacketEngine.dylib",
                "platform": "MACOS",
                "roles": ["core", "relay"],
                "sha256": fixture_hash("macos-wrapper"),
                "slices": {
                    "arm64": fixture_slice("arm64", "MACOS", "13.0", "44444444-4444-4444-4444-444444444444"),
                    "x86_64": fixture_slice("x86_64", "MACOS", "13.0", "55555555-5555-5555-5555-555555555555"),
                },
                "strip_state": "stripped",
            },
        }
        archs = sorted(command("lipo", "-archs", str(winn)).split())
        wrappers[platform] = {
            "architectures": archs,
            "filetype": "mach-o-dylib",
            "path": wrappers[platform]["path"],
            "platform": platform_name,
            "roles": ["core", "relay"],
            "sha256": digest,
            "slices": {arch: measured_slice(arch) for arch in archs},
            "strip_state": "stripped",
        }
        manifest = {
            "apple_toolchain": {
                "tools": {
                    name: {"path": str(path), "sha256": sha256(path)}
                    for name, path in tools.items()
                }
            },
            "archives": archives,
            "builders": {
                "wrapper_builder": {"path": "tools/build_apple_engine_wrappers.sh", "sha256": fixture_hash("wrapper-builder")},
                "wrapper_header": {"path": "apple/EngineWrappers/WinnTunnel.h", "sha256": fixture_hash("wrapper-header")},
            },
            "component": "winn-apple-engine-wrappers",
            "generation": "v3",
            "release": {
                "contract": "winsvpn-winn-release-manifest-v1",
                "go": {
                    "archive_sha256": "ee215d57e0ec269c60cc9ceca68e6bda321ba9ee5afe24f4b0988703c2d87d12",
                    "executable_sha256": fixture_hash("go-executable"),
                    "install_tree_sha256": fixture_hash("go-tree"),
                    "version": "1.27.1",
                },
                "manifest_sha256": fixture_hash("release-manifest"),
                "producer": {
                    "builder_sha256": fixture_hash("release-builder"),
                    "driver_sha256": fixture_hash("release-driver"),
                    "toolchain_pins_sha256": fixture_hash("toolchain-pins"),
                },
                "signature_public_key": "",
                "signature_state": "unsigned-dev",
                "source": {"binding": "export", "commit": "260da56", "tree_sha256": fixture_hash("source-tree")},
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
                "wrapper_sha256": fixture_hash("wrapper-source"),
            },
            "wrappers": wrappers,
        }
        (src / "apple_winn_v3_engine_provenance.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

if __name__ == "__main__":
    unittest.main()
