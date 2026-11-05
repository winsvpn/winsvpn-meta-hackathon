#!/usr/bin/env python3
"""Focused tests for custom-engine PrivacyInfo.xcprivacy staging."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
STAGING = ROOT / "tools" / "stage_apple_engine_artifacts.sh"

FILE_TIMESTAMP = "NSPrivacyAccessedAPICategoryFileTimestamp"
SYSTEM_BOOT_TIME = "NSPrivacyAccessedAPICategorySystemBootTime"
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


def extract_heredoc_containing(source: str, needle: str) -> str:
    for body in re.findall(r"<<'PY'\n(.*?)\nPY\n", source, re.DOTALL):
        if needle in body:
            return body
    raise AssertionError(f"missing Python heredoc containing {needle!r}")


def api_reasons(manifest: dict[str, object]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for item in manifest.get("NSPrivacyAccessedAPITypes") or []:
        if not isinstance(item, dict):
            raise AssertionError("privacy API entry must be a dict")
        api_type = item.get("NSPrivacyAccessedAPIType")
        reasons = item.get("NSPrivacyAccessedAPITypeReasons") or []
        if not isinstance(api_type, str) or not api_type:
            raise AssertionError("privacy API type must be a string")
        if api_type in result:
            raise AssertionError(f"duplicate privacy API type {api_type}")
        if not isinstance(reasons, list) or any(
            not isinstance(reason, str) for reason in reasons
        ):
            raise AssertionError("privacy API reasons are malformed")
        result[api_type] = set(reasons)
    return result


def require_engine_privacy(path: pathlib.Path, component: str) -> dict[str, object]:
    if not (path.is_file() and not path.is_symlink() and path.stat().st_size > 0):
        raise AssertionError(f"missing privacy manifest for {component}: {path}")
    with path.open("rb") as handle:
        manifest = plistlib.load(handle)
    if manifest.get("NSPrivacyTracking") is not False:
        raise AssertionError(f"{component} must disable tracking")
    if manifest.get("NSPrivacyTrackingDomains") not in ([], None):
        raise AssertionError(f"{component} tracking domains must be empty")
    if manifest.get("NSPrivacyCollectedDataTypes") not in ([], None):
        raise AssertionError(f"{component} must not declare collected data")
    expected = {FILE_TIMESTAMP: {"C617.1"}}
    if component == WINN:
        expected[SYSTEM_BOOT_TIME] = {"35F9.1"}
    actual = api_reasons(manifest)
    if actual != expected:
        raise AssertionError(
            f"{component} privacy API reasons {actual!r}, expected {expected!r}"
        )
    return manifest


class StageAppleEnginePrivacyTests(unittest.TestCase):
    def source(self) -> str:
        return STAGING.read_text(encoding="utf-8")

    def writer(self) -> str:
        return extract_heredoc_containing(
            self.source(), "unsupported Apple engine privacy component"
        )

    def write_privacy(self, path: pathlib.Path, component: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-c", self.writer(), str(path), component],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_privacy_is_written_at_platform_paths_before_signing(self) -> None:
        staging = self.source()
        stage_fn = staging.split("stage_artifact() {", 1)[1].split(
            "\napple_awg_engine_provenance_path() {", 1
        )[0]
        self.assertIn('privacy_path="$(framework_privacy_path "${dest_path}")"', stage_fn)
        self.assertIn(
            'write_framework_privacy_manifest "${privacy_path}" "${component}"',
            stage_fn,
        )
        self.assertIn('prepare_stripped_engine_delivery "${component}" "${executable_path}"', stage_fn)
        # Signing happens once, after every staged framework (privacy manifest
        # included) was verified against provenance and published.
        stage_only = stage_fn.split("\nsign_staged_engine_frameworks() {\n", 1)[0]
        self.assertNotIn("codesign", stage_only)
        self.assertLess(
            stage_fn.index("write_framework_privacy_manifest"),
            stage_fn.index("codesign --force --sign"),
        )
        self.assertLess(
            stage_fn.index("prepare_stripped_engine_delivery"),
            stage_fn.index("codesign --force --sign"),
        )
        path_fn = staging.split("framework_privacy_path() {", 1)[1].split(
            "\nwrite_framework_privacy_manifest() {", 1
        )[0]
        self.assertIn('"${dest_path}/PrivacyInfo.xcprivacy"', path_fn)
        self.assertIn(
            '"${dest_path}/Versions/A/Resources/PrivacyInfo.xcprivacy"',
            path_fn,
        )
        self.assertLess(path_fn.index("macos)"), path_fn.index("ios)"))
        writer = self.writer()
        self.assertIn("fmt=plistlib.FMT_XML", writer)
        self.assertIn("sort_keys=True", writer)
        self.assertIn('"C617.1"', writer)
        self.assertIn('"35F9.1"', writer)
        self.assertIn("winn_packet_engine", writer)
        self.assertIn("NSPrivacyTracking", writer)

    def test_selftest_pins_ios_macos_and_component_contracts(self) -> None:
        staging = self.source()
        for needle in (
            "Apple engine artifact staging self-test iOS privacy path is not the framework root.",
            "Apple engine artifact staging self-test macOS privacy path is not Versions/A/Resources.",
            "Apple engine artifact staging self-test privacy generation is not deterministic.",
            "Apple engine artifact staging self-test placed macOS AWG privacy at the iOS framework root.",
            '"${winn_framework}/Versions/A/Resources/PrivacyInfo.xcprivacy"',
            '"apple_xray_vless_ws_provenance_sha256"',
            "did not reject missing Xray provenance",
            "did not reject drifted Xray provenance",
        ):
            self.assertIn(needle, staging)

    def test_writer_is_deterministic_and_component_specific(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-engine-privacy-") as raw:
            root = pathlib.Path(raw)
            first = root / "winn-a.xcprivacy"
            second = root / "winn-b.xcprivacy"
            awg = root / "awg.xcprivacy"
            xray = root / "xray.xcprivacy"
            for path, component in (
                (first, WINN),
                (second, WINN),
                (awg, AWG),
                (xray, XRAY),
            ):
                completed = self.write_privacy(path, component)
                self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(awg.read_bytes(), xray.read_bytes())
            self.assertNotEqual(awg.read_bytes(), first.read_bytes())
            self.assertEqual(
                hashlib.sha256(first.read_bytes()).hexdigest(),
                hashlib.sha256(second.read_bytes()).hexdigest(),
            )
            require_engine_privacy(first, WINN)
            require_engine_privacy(awg, AWG)
            require_engine_privacy(xray, XRAY)
            unknown = self.write_privacy(root / "bad.xcprivacy", "not_an_engine")
            self.assertNotEqual(unknown.returncode, 0)
            self.assertIn("unsupported Apple engine privacy component", unknown.stderr)

    def test_shell_syntax_and_offline_self_test(self) -> None:
        subprocess.run(["bash", "-n", str(STAGING)], cwd=ROOT, check=True)
        environment = os.environ.copy()
        environment["WINS_STAGE_APPLE_ENGINE_SELFTEST"] = "1"
        subprocess.run(["bash", str(STAGING)], cwd=ROOT, env=environment, check=True)

    def test_selftest_python_launcher_requires_no_inherited_environment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-stage-isolated-python-") as raw:
            launcher = pathlib.Path(raw).resolve() / "isolated-python"
            launcher.write_text(
                "#!/bin/bash\n"
                "exec /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/python3 \"$@\"\n",
                encoding="ascii",
            )
            launcher.chmod(0o755)
            environment = os.environ.copy()
            environment.update(
                {
                    "PYTHON_BIN": str(launcher),
                    "WINS_STAGE_APPLE_ENGINE_SELFTEST": "1",
                }
            )
            environment.pop("STAGING_SCRIPT_DIR", None)
            completed = subprocess.run(
                ["bash", str(STAGING)],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
            self.assertIn("Apple engine artifact staging self-test passed.", completed.stdout)

    def _ios_fixture(self, root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, dict[str, str]]:
        """Builds stripped iOS engine dylibs plus matching AWG, Xray and Winn
        provenance, and the Xcode Run Script environment that stages them."""
        clang = subprocess.check_output(["xcrun", "-f", "clang"], text=True).strip()
        sdk = subprocess.check_output(
            ["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True
        ).strip()
        src = root / "src"
        build = root / "build"
        src.mkdir()
        wrapper_dir = root / "apple" / "EngineWrappers"
        wrapper_dir.mkdir(parents=True)
        awg_wrapper_source = wrapper_dir / "WinsAmneziaWGPacketEngine.m"
        shutil.copy2(
            ROOT / "apple" / "EngineWrappers" / "WinsAmneziaWGPacketEngine.m",
            awg_wrapper_source,
        )
        awg = src / "libWinsAmneziaWGPacketEngine.dylib"
        xray = src / "libWinsXrayVlessWsTransport.dylib"
        winn = src / "libWinsWinnPacketEngine.dylib"
        self._compile_ios_dylib(
            clang,
            sdk,
            awg,
            AWG_SOURCE,
            "@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine",
        )
        self._compile_ios_dylib(
            clang,
            sdk,
            xray,
            XRAY_SOURCE,
            "@rpath/WinsXrayVlessWsTransport.framework/WinsXrayVlessWsTransport",
            extra_args=[
                f"-L{src}",
                "-lWinsAmneziaWGPacketEngine",
                "-Wl,-rpath,@loader_path/..",
            ],
        )
        self._compile_ios_dylib(
            clang,
            sdk,
            winn,
            WINN_SOURCE,
            "@rpath/WinsWinnPacketEngine.framework/WinsWinnPacketEngine",
        )
        (src / "apple_awg_31_engine_provenance.json").write_text(
            json.dumps(
                self._awg_provenance(awg, xray, awg_wrapper_source),
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self._write_xray_provenance(src, xray, "iphoneos")
        self._write_ios_winn_provenance(src, winn)
        environment = os.environ.copy()
        environment.update(
            {
                "PROJECT_ROOT": str(root),
                "APPLE_ENGINE_ARTIFACTS_DIR": str(src),
                "TARGET_BUILD_DIR": str(build),
                "FRAMEWORKS_FOLDER_PATH": "Runner.app/Frameworks",
                "UNLOCALIZED_RESOURCES_FOLDER_PATH": "Runner.app",
                "PLUGINS_FOLDER_PATH": "Runner.app/PlugIns",
                "PLATFORM_NAME": "iphoneos",
                "ARCHS": "arm64",
                "WINS_REQUIRE_APPLE_ENGINE": "1",
                "WINS_APPLE_WINN3_RELEASE": "0",
                "WINS_STAGE_APPLE_ENGINE_SELFTEST": "0",
                "CODE_SIGNING_ALLOWED": "NO",
            }
        )
        return src, build, environment

    def test_normal_ios_staging_verifies_and_publishes_by_default(self) -> None:
        """The Xcode Run Script entry (plain `bash stage_apple_engine_artifacts.sh`,
        no opt-in variable) stages, verifies provenance and publishes the manifest."""
        with tempfile.TemporaryDirectory(prefix="wins-engine-privacy-ios-") as raw:
            root = pathlib.Path(raw).resolve()
            src, build, environment = self._ios_fixture(root)
            completed = subprocess.run(
                ["bash", str(STAGING)],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
            self.assertNotIn("OWNER-BLOCKED", completed.stderr + completed.stdout)
            self.assertIn(
                "Apple engine artifact staging completed for iphoneos", completed.stdout
            )
            resources = build / "Runner.app"
            staged_xray_provenance = resources / "apple_xray_vless_ws_engine_provenance.json"
            manifest = json.loads(
                (resources / "apple_engine_artifacts_manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                manifest["apple_xray_vless_ws_provenance_sha256"],
                hashlib.sha256(staged_xray_provenance.read_bytes()).hexdigest(),
            )
            frameworks = build / "Runner.app" / "Frameworks"
            awg_fw = frameworks / "WinsAmneziaWGPacketEngine.framework"
            xray_fw = frameworks / "WinsXrayVlessWsTransport.framework"
            winn_fw = frameworks / "WinsWinnPacketEngine.framework"
            for framework, component in (
                (awg_fw, AWG),
                (xray_fw, XRAY),
                (winn_fw, WINN),
            ):
                require_engine_privacy(framework / "PrivacyInfo.xcprivacy", component)
                self.assertFalse(
                    (framework / "Versions" / "A" / "Resources" / "PrivacyInfo.xcprivacy").exists()
                )
            for name in (
                "apple_awg_31_engine_provenance.json",
                "apple_winn_v3_engine_provenance.json",
            ):
                self.assertEqual(
                    (resources / name).read_bytes(), (src / name).read_bytes(), name
                )
            self.assertEqual(
                manifest["apple_awg_31_provenance_sha256"],
                hashlib.sha256(
                    (resources / "apple_awg_31_engine_provenance.json").read_bytes()
                ).hexdigest(),
            )
            self.assertEqual(
                manifest["apple_winn_v3_provenance_sha256"],
                hashlib.sha256(
                    (resources / "apple_winn_v3_engine_provenance.json").read_bytes()
                ).hexdigest(),
            )
            self.assertEqual(manifest["staged_components"], [AWG, XRAY, WINN])

            # The same default entry refuses drifted provenance for each engine
            # and leaves no manifest behind; nothing on this path skips the check.
            for name, mutate in (
                (
                    "apple_awg_31_engine_provenance.json",
                    lambda doc: doc["wrappers"]["iphoneos"][AWG].update(sha256="0" * 64),
                ),
                (
                    "apple_xray_vless_ws_engine_provenance.json",
                    lambda doc: doc["wrappers"]["iphoneos"].update(sha256="0" * 64),
                ),
                (
                    "apple_winn_v3_engine_provenance.json",
                    lambda doc: doc["wrappers"]["iphoneos"].update(sha256="0" * 64),
                ),
            ):
                provenance = src / name
                original = provenance.read_bytes()
                document = json.loads(original)
                mutate(document)
                provenance.write_text(
                    json.dumps(document, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                refused = subprocess.run(
                    ["bash", str(STAGING)],
                    cwd=ROOT,
                    env=environment,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                provenance.write_bytes(original)
                self.assertNotEqual(refused.returncode, 0, name)
                self.assertIn(
                    "Staging is refused until a verified rebuild",
                    refused.stderr + refused.stdout,
                    name,
                )
                self.assertFalse(
                    (resources / "apple_engine_artifacts_manifest.json").exists(), name
                )

    def test_go_archive_pins_come_from_toolchain_pins(self) -> None:
        """The staging Go archive digests are read from tools/toolchain-pins.json
        beside the script; a drifted, missing, or symbolic pin file refuses."""
        source = self.source()
        for digest in (
            "ee215d57e0ec269c60cc9ceca68e6bda321ba9ee5afe24f4b0988703c2d87d12",
            "8f8f52c6649542cf027bbc9b9c68d1ec042f9f34808a40413f0b8b3f66f3caa4",
        ):
            self.assertNotIn(digest, source)
        self.assertIn('"tools.go.archive_sha256.${key}"', source)
        pins = json.loads((ROOT / "tools" / "toolchain-pins.json").read_text(encoding="utf-8"))
        go_pins = pins["tools"]["go"]["archive_sha256"]
        with tempfile.TemporaryDirectory(prefix="wins-engine-go-pins-") as raw:
            root = pathlib.Path(raw).resolve()
            src, build, environment = self._ios_fixture(root)
            tools = root / "tools"
            shutil.copytree(
                ROOT / "tools",
                tools,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
            staging_copy = tools / "stage_apple_engine_artifacts.sh"
            pin_file = tools / "toolchain-pins.json"
            original_pins = pin_file.read_bytes()

            def run() -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["bash", str(staging_copy)],
                    cwd=root,
                    env=environment,
                    text=True,
                    capture_output=True,
                    check=False,
                )

            accepted = run()
            self.assertEqual(accepted.returncode, 0, accepted.stderr + accepted.stdout)

            for arch in ("darwin_arm64", "darwin_amd64"):
                drifted = json.loads(original_pins)
                drifted["tools"]["go"]["archive_sha256"][arch] = "a" * 64
                self.assertNotEqual(go_pins[arch], "a" * 64)
                pin_file.write_text(json.dumps(drifted, indent=2) + "\n", encoding="utf-8")
                refused = run()
                self.assertNotEqual(refused.returncode, 0, arch)
                self.assertIn(
                    "Apple AWG 3.1 engine provenance verification failed",
                    refused.stderr + refused.stdout,
                    arch,
                )

                for bad in (None, "A" * 64, "a" * 63):
                    broken = json.loads(original_pins)
                    if bad is None:
                        del broken["tools"]["go"]["archive_sha256"][arch]
                    else:
                        broken["tools"]["go"]["archive_sha256"][arch] = bad
                    pin_file.write_text(json.dumps(broken, indent=2) + "\n", encoding="utf-8")
                    refused = run()
                    self.assertNotEqual(refused.returncode, 0, (arch, bad))
                    self.assertIn(
                        f"does not pin a 64-hex tools.go.archive_sha256.{arch}",
                        refused.stderr,
                        (arch, bad),
                    )

            real_pins = root / "real-toolchain-pins.json"
            real_pins.write_bytes(original_pins)
            pin_file.unlink()
            pin_file.symlink_to(real_pins)
            refused = run()
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn(
                "does not pin a 64-hex tools.go.archive_sha256.darwin_arm64", refused.stderr
            )

    def test_default_entry_has_no_opt_in_bypass_or_owner_block(self) -> None:
        staging = self.source()
        for gone in (
            "WINS_APPLE_LOCAL_PROVEN_STAGING",
            "OWNER-BLOCKED",
            "_stage_engine_artifacts_fixture",
            "publish_nonauthoritative_fixture_transaction",
            "engine_delivery_is_stripped_nm",
            "engine_delivery_is_stripped_for_lane",
        ):
            self.assertNotIn(gone, staging)
        self.assertEqual(staging.count("\nstage_engine_artifacts() {\n"), 1)
        self.assertTrue(staging.rstrip().endswith("\nstage_engine_artifacts"))
        entry = staging.split("\nstage_engine_artifacts() {\n", 1)[1].split("\n}\n", 1)[0]
        ordered = [
            'require_valid_artifact "${component}" "${artifact_path}"',
            'stage_artifact "${component}" "${artifact_path}" "${dest_dir}"',
            "verify_and_stage_awg_provenance",
            "verify_and_stage_xray_provenance",
            "verify_and_stage_winn_provenance",
            "publish_engine_artifacts_transaction",
            'sign_staged_engine_frameworks "${dest_dir}" "${staged_components[@]}"',
        ]
        positions = [entry.index(needle) for needle in ordered]
        self.assertEqual(positions, sorted(positions))
        stage_fn = staging.split("\nstage_artifact() {\n", 1)[1].split(
            "\nsign_staged_engine_frameworks() {\n", 1
        )[0]
        self.assertNotIn("codesign", stage_fn)
        sign_fn = staging.split("\nsign_staged_engine_frameworks() {\n", 1)[1].split(
            "\n}\n", 1
        )[0]
        self.assertIn('"${CODE_SIGNING_ALLOWED:-YES}" == "NO"', sign_fn)
        self.assertIn('"${EXPANDED_CODE_SIGN_IDENTITY}" == "-"', sign_fn)
        self.assertIn(
            '"${dest_dir}/${framework_name}.framework"', sign_fn
        )
        self.assertIn("|| die", sign_fn)
        for project in ("ios", "macos"):
            pbx = (ROOT / project / "Runner.xcodeproj" / "project.pbxproj").read_text(
                encoding="utf-8"
            )
            self.assertIn(
                'shellScript = "/bin/bash \\"$SRCROOT/../tools/stage_apple_engine_artifacts.sh\\"\\n";',
                pbx,
            )
            self.assertNotIn("WINS_APPLE_LOCAL_PROVEN_STAGING", pbx)

    def _compile_ios_dylib(
        self,
        clang: str,
        sdk: str,
        output: pathlib.Path,
        source: str,
        install_name: str,
        extra_args: list[str] | None = None,
    ) -> None:
        src = output.with_suffix(".c")
        src.write_text(source, encoding="utf-8")
        command = [
            clang,
            "-dynamiclib",
            "-target",
            "arm64-apple-ios13.0",
            "-isysroot",
            sdk,
            "-Wl,-x",
            f"-Wl,-install_name,{install_name}",
            *(extra_args or []),
            str(src),
            "-o",
            str(output),
        ]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        src.unlink(missing_ok=True)
        if completed.returncode != 0:
            raise AssertionError(
                f"ios dylib compile failed for {output.name}: {completed.stderr}"
            )

    def _awg_provenance(
        self,
        awg: pathlib.Path,
        xray: pathlib.Path,
        awg_wrapper_source: pathlib.Path,
    ) -> dict[str, object]:
        return {
            "awg_wrapper_source": {
                "path": "apple/EngineWrappers/WinsAmneziaWGPacketEngine.m",
                "sha256": hashlib.sha256(awg_wrapper_source.read_bytes()).hexdigest(),
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
                "iphoneos": {
                    "amneziawg_packet_engine": {
                        "architectures": ["arm64"],
                        "path": "selftest/libWinsAmneziaWGPacketEngine.dylib",
                        "sha256": hashlib.sha256(awg.read_bytes()).hexdigest(),
                    },
                    "xray_vless_ws_transport": {
                        "architectures": ["arm64"],
                        "path": "selftest/libWinsXrayVlessWsTransport.dylib",
                        "sha256": hashlib.sha256(xray.read_bytes()).hexdigest(),
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
        self, src: pathlib.Path, xray: pathlib.Path, platform_name: str
    ) -> None:
        manifest = {
            "component": "xray-apple-vless-ws-engine-wrappers",
            "schema_version": 1,
            "wrappers": {
                platform_name: {
                    "sha256": hashlib.sha256(xray.read_bytes()).hexdigest(),
                }
            },
        }
        (src / "apple_xray_vless_ws_engine_provenance.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def _write_ios_winn_provenance(self, src: pathlib.Path, winn: pathlib.Path) -> None:
        digest = hashlib.sha256(winn.read_bytes()).hexdigest()

        def fixture_hash(label: str) -> str:
            return hashlib.sha256(f"winsvpn-privacy-fixture:{label}".encode("ascii")).hexdigest()

        def command(tool: pathlib.Path, *arguments: str) -> str:
            return subprocess.check_output(
                [str(tool), *arguments], text=True
            )

        def command_values(text: str, field: str) -> list[str]:
            values = []
            for line in text.splitlines():
                fields = line.strip().split()
                if len(fields) >= 2 and fields[0] == field:
                    values.append(fields[1])
            return values

        platform_names = {
            "1": "MACOS",
            "2": "IOS",
            "7": "IOSSIMULATOR",
            "MACOS": "MACOS",
            "IOS": "IOS",
            "IOSSIMULATOR": "IOSSIMULATOR",
        }

        def platforms(text: str) -> list[str]:
            found = []
            for line in text.splitlines():
                fields = line.strip().split()
                if len(fields) >= 2 and fields[0] == "platform":
                    mapped = platform_names.get(fields[1])
                    if mapped:
                        found.append(mapped)
            return sorted(set(found))

        tools = {
            name: pathlib.Path("/usr/bin") / name
            for name in ("ar", "clang", "file", "lipo", "nm", "otool", "strip", "vtool")
        }
        for name, path in tools.items():
            self.assertTrue(path.is_file(), f"missing Apple fixture tool {name}: {path}")

        install_name = "@rpath/WinsWinnPacketEngine.framework/WinsWinnPacketEngine"

        def inspect_slice(arch: str) -> dict[str, object]:
            load_commands = command(tools["otool"], "-arch", arch, "-l", str(winn))
            self.assertEqual(platforms(load_commands), ["IOS"])
            uuids = command_values(load_commands, "uuid")
            self.assertEqual(len(uuids), 1)
            build = command(tools["vtool"], "-show-build", "-arch", arch, str(winn))
            minos = command_values(build, "minos")
            self.assertEqual(minos, ["13.0"])
            self.assertEqual(platforms(build), ["IOS"])
            header = command(tools["otool"], "-arch", arch, "-hv", str(winn))
            self.assertRegex(header, r"\b(MH_DYLIB|DYLIB)\b")
            install = command(tools["otool"], "-arch", arch, "-D", str(winn))
            install_names = [
                line.strip()
                for line in install.splitlines()
                if line.strip() and not line.endswith(":") and line.strip() != str(winn)
            ]
            self.assertEqual(install_names[-1:], [install_name])
            dependency_output = command(tools["otool"], "-arch", arch, "-L", str(winn))
            dependencies = []
            for line in dependency_output.splitlines():
                value = line.strip()
                if not value or value.endswith(":") or value.startswith(str(winn)):
                    continue
                dependency = value.split(" (", 1)[0]
                if dependency != install_name:
                    dependencies.append(dependency)
            dependencies = sorted(set(dependencies))
            self.assertIn("/usr/lib/libSystem.B.dylib", dependencies)
            symbols_output = command(tools["nm"], "-arch", arch, "-gU", str(winn))
            symbols = {
                line.split()[-1].lstrip("_")
                for line in symbols_output.splitlines()
                if line.split()
            }
            roles = {
                "core": ["WinnTunnelCreateWinn3"],
                "relay": ["WinnTunnelCreate", "WinnTunnelCreateWithCarrier"],
            }
            self.assertTrue({symbol for group in roles.values() for symbol in group} <= symbols)
            return {
                "architecture": arch,
                "dependencies": dependencies,
                "filetype": "MH_DYLIB",
                "install_name": install_name,
                "minos": minos[0],
                "platform": "IOS",
                "role_symbols": roles,
                "uuid": uuids[0].upper(),
            }

        architectures = sorted(command(tools["lipo"], "-archs", str(winn)).split())
        self.assertEqual(architectures, ["arm64"])
        self.assertIn("Mach-O", command(tools["file"], "-b", str(winn)))
        ios_slices = {arch: inspect_slice(arch) for arch in architectures}

        def fixture_slice(
            arch: str, platform: str, minos: str, uuid: str
        ) -> dict[str, object]:
            return {
                "architecture": arch,
                "dependencies": ["/usr/lib/libSystem.B.dylib"],
                "filetype": "MH_DYLIB",
                "install_name": install_name,
                "minos": minos,
                "platform": platform,
                "role_symbols": {
                    "core": ["WinnTunnelCreateWinn3"],
                    "relay": ["WinnTunnelCreate", "WinnTunnelCreateWithCarrier"],
                },
                "uuid": uuid,
            }

        def binding(path: str, label: str) -> dict[str, str]:
            return {"path": path, "sha256": fixture_hash(label)}

        archives = {}
        for key, name, header, arch, platform, target in (
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
            archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
            archives[key] = {
                "architectures": [arch],
                "build_a_sha256": archive_sha,
                "build_b_sha256": archive_sha,
                "filetype": "ar-archive",
                "header_path": header,
                "header_sha256": hashlib.sha256(header_path.read_bytes()).hexdigest(),
                "path": name,
                "platform": platform,
                "sha256": archive_sha,
                "target": target,
            }

        # A deterministic unsigned-dev release record. Release mode remains
        # disabled; release-mode staging refuses any unsigned-dev record.
        release = {
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
            "source": {
                "binding": "export",
                "commit": "260da56",
                "tree_sha256": fixture_hash("source-tree"),
            },
        }
        manifest = {
            "apple_toolchain": {
                "tools": {
                    name: {
                        "path": str(path),
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    }
                    for name, path in tools.items()
                }
            },
            "archives": archives,
            "builders": {
                "wrapper_builder": binding("tools/build_apple_engine_wrappers.sh", "wrapper-builder"),
                "wrapper_header": binding("apple/EngineWrappers/WinnTunnel.h", "wrapper-header"),
            },
            "component": "winn-apple-engine-wrappers",
            "generation": "v3",
            "release": release,
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
            "wrappers": {
                "iphoneos": {
                    "architectures": architectures,
                    "filetype": "mach-o-dylib",
                    "path": "ios/iphoneos/libWinsWinnPacketEngine.dylib",
                    "platform": "IOS",
                    "roles": ["core", "relay"],
                    "sha256": digest,
                    "slices": ios_slices,
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
                        "arm64": fixture_slice(
                            "arm64", "IOSSIMULATOR", "14.0", "22222222-2222-2222-2222-222222222222"
                        ),
                        "x86_64": fixture_slice(
                            "x86_64", "IOSSIMULATOR", "13.0", "33333333-3333-3333-3333-333333333333"
                        ),
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
                        "arm64": fixture_slice(
                            "arm64", "MACOS", "13.0", "44444444-4444-4444-4444-444444444444"
                        ),
                        "x86_64": fixture_slice(
                            "x86_64", "MACOS", "13.0", "55555555-5555-5555-5555-555555555555"
                        ),
                    },
                    "strip_state": "stripped",
                },
            },
        }
        (src / "apple_winn_v3_engine_provenance.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    unittest.main()
