#!/usr/bin/env python3
"""App Store Connect error 90255: delivered Apple payloads must be readable by all users.

The release producer runs under umask 077 for its secrets. Xcode writes the signed bundle
(CodeResources, embedded provisioning profiles) with the caller's umask, so a 1.0.16 (33)
macOS PKG reached Transporter with mode 600 payload files and was refused, and the iOS IPA
from the same run carried the same 600 entries. These tests run the smoke's own shell
functions: the xcodebuild runners switch to umask 022 and restore the caller's umask, and
the PKG and IPA gates refuse a payload entry that others cannot read.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SMOKE = ROOT / "tools" / "apple_runtime_smoke.sh"
SYSTEM_BASH = pathlib.Path("/bin/bash")


def function(text: str, name: str) -> str:
    start = text.index("\n" + name + "() {\n") + 1
    return text[start:text.index("\n}\n", start) + 3]


HARNESS_PRELUDE = (
    "set -Eeuo pipefail\n"
    "die() { printf 'DIE:%s\\n' \"$*\" >&2; exit 70; }\n"
    "require_cmd() { command -v \"$1\" >/dev/null || die \"missing $1\"; }\n"
)


def clean_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.pop("BASH_ENV", None)
    for inherited in tuple(environment):
        if inherited.startswith("BASH_FUNC_"):
            environment.pop(inherited, None)
    return environment


@unittest.skipUnless(SYSTEM_BASH.is_file(), "system /bin/bash is required")
class XcodebuildUmaskTests(unittest.TestCase):
    def run_runner(self, runner: str, stub: str, stub_status: int) -> subprocess.CompletedProcess[str]:
        text = SMOKE.read_text(encoding="utf-8")
        harness = (
            HARNESS_PRELUDE
            + "APPLE_XCODE_AUTH_ARGS=()\n"
            + "APPLE_MACOS_DEVELOPMENT_SIGNING_ARGS=()\n"
            + f"{stub}() {{ printf 'INSIDE:%s ARGS:%s\\n' \"$(umask)\" \"$*\"; return {stub_status}; }}\n"
            + function(text, runner)
            + "umask 077\n"
            + "status=0\n"
            + f"{runner} -exportArchive __APPLE_XCODE_AUTH_ARGS__ -archivePath a || status=$?\n"
            + "printf 'AFTER:%s STATUS:%s\\n' \"$(umask)\" \"${status}\"\n"
        )
        return subprocess.run(
            [str(SYSTEM_BASH), "-c", harness],
            capture_output=True,
            text=True,
            env=clean_environment(),
            check=False,
        )

    def test_archive_and_export_runners_use_umask_022_and_restore_the_caller_umask(self) -> None:
        for runner, stub in (
            ("run_xcodebuild_with_signing_diagnostics", "run_with_signing_diagnostics"),
            ("run_xcodebuild_with_export_signing_diagnostics", "run_with_export_signing_diagnostics"),
        ):
            for stub_status in (0, 3):
                with self.subTest(runner=runner, status=stub_status):
                    result = self.run_runner(runner, stub, stub_status)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(
                        "INSIDE:0022 ARGS:xcodebuild -exportArchive -archivePath a", result.stdout
                    )
                    # A failing xcodebuild keeps its status and still restores umask 077.
                    self.assertIn(f"AFTER:0077 STATUS:{stub_status}", result.stdout)


@unittest.skipUnless(SYSTEM_BASH.is_file(), "system /bin/bash is required")
@unittest.skipUnless(
    all(shutil.which(tool) for tool in ("pkgbuild", "productbuild", "pkgutil", "lsbom")),
    "macOS package tools are required",
)
class MacosPkgPayloadPermissionGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="wins-pkg-modes-")
        self.base = pathlib.Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def build_component(
        self,
        name: str,
        modes: dict[str, int],
        dir_modes: dict[str, int] | None = None,
        identifier: str = "org.winsvpn.test.modes",
    ) -> pathlib.Path:
        root = self.base / f"{name}-root"
        contents = root / "Win's VPN.app" / "Contents"
        (contents / "_CodeSignature").mkdir(parents=True)
        for relative, mode in modes.items():
            path = contents / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(relative + "\n", encoding="utf-8")
            path.chmod(mode)
        for relative, mode in (dir_modes or {}).items():
            (contents / relative).chmod(mode)
        component = self.base / f"{name}-component.pkg"
        subprocess.run(
            [
                "pkgbuild",
                "--quiet",
                "--root",
                str(root),
                "--identifier",
                identifier,
                "--version",
                "1",
                "--install-location",
                "/Applications",
                str(component),
            ],
            capture_output=True,
            check=True,
        )
        for relative in (dir_modes or {}):
            (contents / relative).chmod(0o755)
        return component

    def build_product(self, name: str, components: list[pathlib.Path]) -> pathlib.Path:
        product = self.base / f"{name}.pkg"
        arguments = ["productbuild", "--quiet"]
        for component in components:
            arguments += ["--package", str(component)]
        subprocess.run(arguments + [str(product)], capture_output=True, check=True)
        return product

    def build_pkg(
        self, name: str, modes: dict[str, int], dir_modes: dict[str, int] | None = None
    ) -> pathlib.Path:
        return self.build_product(name, [self.build_component(name, modes, dir_modes)])

    def run_gate(
        self, pkg: pathlib.Path, path_prefix: pathlib.Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        text = SMOKE.read_text(encoding="utf-8")
        work = pathlib.Path(tempfile.mkdtemp(prefix=f"work-{pkg.stem}-", dir=self.base))
        harness = (
            HARNESS_PRELUDE
            + function(text, "verify_macos_pkg_payload_world_readable")
            + 'verify_macos_pkg_payload_world_readable "$1" "macOS App Store" "$2"\n'
            + "printf 'GATE-PASSED\\n'\n"
        )
        environment = clean_environment()
        if path_prefix is not None:
            environment["PATH"] = f"{path_prefix}:{environment.get('PATH', '/usr/bin:/bin')}"
        result = subprocess.run(
            [str(SYSTEM_BASH), "-c", harness, "gate", str(pkg), str(work)],
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )
        # The gate leaves nothing behind in the caller's work directory.
        self.assertEqual(list(work.iterdir()), [])
        return result

    def test_gate_accepts_a_payload_readable_by_all_users(self) -> None:
        pkg = self.build_pkg(
            "readable",
            {
                "Info.plist": 0o644,
                "embedded.provisionprofile": 0o644,
                "_CodeSignature/CodeResources": 0o644,
                "MacOS/Win's VPN": 0o755,
            },
        )
        result = self.run_gate(pkg)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("GATE-PASSED", result.stdout)

    def test_gate_refuses_a_payload_file_only_its_owner_can_read(self) -> None:
        pkg = self.build_pkg(
            "owner-only",
            {
                "Info.plist": 0o644,
                "embedded.provisionprofile": 0o600,
                "_CodeSignature/CodeResources": 0o600,
            },
        )
        result = self.run_gate(pkg)
        self.assertEqual(result.returncode, 70, result.stdout + result.stderr)
        self.assertNotIn("GATE-PASSED", result.stdout)
        self.assertIn("App Store Connect error 90255", result.stderr)
        self.assertIn("embedded.provisionprofile", result.stderr)
        self.assertIn("_CodeSignature/CodeResources", result.stderr)

    def test_gate_reports_many_unreadable_files_instead_of_dying_silently(self) -> None:
        # More than five findings: the report is cut to five without a broken pipe ending
        # the script under pipefail before the message.
        pkg = self.build_pkg(
            "many-owner-only",
            {f"Resources/private-{index}.txt": 0o600 for index in range(9)},
        )
        result = self.run_gate(pkg)
        self.assertEqual(result.returncode, 70, result.stdout + result.stderr)
        self.assertIn("App Store Connect error 90255", result.stderr)
        self.assertEqual(result.stderr.count("private-"), 5, result.stderr)

    def test_gate_refuses_a_package_that_cannot_be_expanded(self) -> None:
        bogus = self.base / "bogus.pkg"
        bogus.write_bytes(b"not a package")
        result = self.run_gate(bogus)
        self.assertEqual(result.returncode, 70)
        self.assertIn("could not be expanded", result.stderr)

    def test_gate_refuses_a_directory_other_users_cannot_search(self) -> None:
        # Review round 1 (Sol B-02): a 0744 directory is readable but not searchable by others.
        pkg = self.build_pkg(
            "unsearchable-dir",
            {"Info.plist": 0o644, "Resources/strings.txt": 0o644},
            dir_modes={"Resources": 0o744},
        )
        result = self.run_gate(pkg)
        self.assertEqual(result.returncode, 70, result.stdout + result.stderr)
        self.assertIn("App Store Connect error 90255", result.stderr)
        self.assertIn("Contents/Resources", result.stderr)

    def test_gate_accepts_two_readable_components(self) -> None:
        pkg = self.build_product(
            "two-readable",
            [
                self.build_component("first", {"Info.plist": 0o644}, identifier="org.winsvpn.test.a"),
                self.build_component("second", {"Info.plist": 0o644}, identifier="org.winsvpn.test.b"),
            ],
        )
        result = self.run_gate(pkg)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("GATE-PASSED", result.stdout)

    def test_gate_refuses_a_component_payload_without_its_bom(self) -> None:
        # Review round 1 (Sol B-02): one checked BOM must not vouch for a sibling component.
        product = self.build_product(
            "two-components",
            [
                self.build_component("first", {"Info.plist": 0o644}, identifier="org.winsvpn.test.a"),
                self.build_component("second", {"Info.plist": 0o600}, identifier="org.winsvpn.test.b"),
            ],
        )
        expanded = self.base / "two-components-expanded"
        subprocess.run(
            ["pkgutil", "--expand", str(product), str(expanded)], capture_output=True, check=True
        )
        boms = sorted(expanded.glob("*.pkg/Bom"))
        self.assertEqual(len(boms), 2, boms)
        payload_of_second = [
            bom for bom in boms if "second" in bom.parent.name
        ] or boms[-1:]
        payload_of_second[0].unlink()
        flattened = self.base / "missing-bom.pkg"
        subprocess.run(
            ["pkgutil", "--flatten", str(expanded), str(flattened)], capture_output=True, check=True
        )
        result = self.run_gate(flattened)
        self.assertEqual(result.returncode, 70, result.stdout + result.stderr)
        self.assertNotIn("GATE-PASSED", result.stdout)
        self.assertIn("Payload without a BOM", result.stderr)

    def test_gate_refuses_unparseable_or_unlistable_bom_output(self) -> None:
        pkg = self.build_pkg("parse", {"Info.plist": 0o644})
        for name, script, expected in (
            ("garbage", "#!/bin/sh\nprintf 'garbage-without-a-tab\\n'\n", "unparseable BOM entry"),
            ("failing", "#!/bin/sh\nexit 3\n", "could not be listed"),
        ):
            with self.subTest(lsbom=name):
                fake = self.base / f"fake-lsbom-{name}"
                fake.mkdir()
                (fake / "lsbom").write_text(script, encoding="ascii")
                (fake / "lsbom").chmod(0o755)
                result = self.run_gate(pkg, path_prefix=fake)
                self.assertEqual(result.returncode, 70, result.stdout + result.stderr)
                self.assertIn(expected, result.stderr)


    def test_gate_skips_only_the_modeless_bom_root_entry(self) -> None:
        # The rejected-then-rebuilt 1.0.16 macOS App Store export lists its BOM root as
        # "?---------\t." (no mode). That entry alone is not a payload file; a modeless
        # entry at any other path is still refused.
        pkg = self.build_pkg("root", {"Info.plist": 0o644})
        for name, lines, ok in (
            ("root", "?--------- \t.\ndrwxr-xr-x \t./Win's VPN.app\n-rw-r--r-- \t./Win's VPN.app/Info.plist\n", True),
            ("other", "?--------- \t.\n?--------- \t./Win's VPN.app/Info.plist\n", False),
        ):
            with self.subTest(listing=name):
                fake = self.base / f"fake-lsbom-root-{name}"
                fake.mkdir()
                (fake / "lsbom").write_text("#!/bin/sh\nprintf '" + lines.replace("'", "'\\''") + "'\n", encoding="utf-8")
                (fake / "lsbom").chmod(0o755)
                result = self.run_gate(pkg, path_prefix=fake)
                if ok:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                else:
                    self.assertEqual(result.returncode, 70, result.stdout + result.stderr)
                    self.assertIn("90255", result.stderr)


@unittest.skipUnless(SYSTEM_BASH.is_file(), "system /bin/bash is required")
class IosIpaPayloadPermissionGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="wins-ipa-modes-")
        self.base = pathlib.Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_ipa(self, name: str, entries: dict[str, int], create_system: int = 3) -> pathlib.Path:
        ipa = self.base / f"{name}.ipa"
        with zipfile.ZipFile(ipa, "w") as archive:
            for filename, mode in entries.items():
                info = zipfile.ZipInfo(filename)
                info.create_system = create_system
                is_directory = filename.endswith("/")
                info.external_attr = ((0o040000 if is_directory else 0o100000) | mode) << 16
                archive.writestr(info, b"" if is_directory else filename.encode("utf-8"))
        return ipa

    def run_gate(self, ipa: pathlib.Path) -> subprocess.CompletedProcess[str]:
        text = SMOKE.read_text(encoding="utf-8")
        harness = (
            HARNESS_PRELUDE
            + f"PYTHON_BIN={sys.executable!r}\n"
            + function(text, "verify_ios_ipa_payload_world_readable")
            + 'verify_ios_ipa_payload_world_readable "$1" "iOS App Store"\n'
            + "printf 'GATE-PASSED\\n'\n"
        )
        return subprocess.run(
            [str(SYSTEM_BASH), "-c", harness, "gate", str(ipa)],
            capture_output=True,
            text=True,
            env=clean_environment(),
            check=False,
        )

    READABLE = {
        "Payload/": 0o755,
        "Payload/BasicCalc.app/": 0o755,
        "Payload/BasicCalc.app/Info.plist": 0o644,
        "Payload/BasicCalc.app/embedded.mobileprovision": 0o644,
        "Payload/BasicCalc.app/_CodeSignature/CodeResources": 0o644,
        "Payload/BasicCalc.app/BasicCalc": 0o755,
    }

    def test_gate_accepts_an_ipa_readable_by_all_users(self) -> None:
        result = self.run_gate(self.write_ipa("readable", self.READABLE))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("GATE-PASSED", result.stdout)

    def test_gate_refuses_the_modes_of_the_rejected_1_0_16_ipa(self) -> None:
        # The delivered 1.0.16 (33) IPA had these four 600 files and a 700 Payload/ directory.
        entries = dict(self.READABLE)
        entries.update(
            {
                "Payload/": 0o700,
                "Payload/BasicCalc.app/embedded.mobileprovision": 0o600,
                "Payload/BasicCalc.app/_CodeSignature/CodeResources": 0o600,
            }
        )
        result = self.run_gate(self.write_ipa("owner-only", entries))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("GATE-PASSED", result.stdout)
        self.assertIn("App Store Connect error 90255", result.stderr)
        for name in (
            "Payload/,",
            "embedded.mobileprovision",
            "_CodeSignature/CodeResources",
        ):
            self.assertIn(name, result.stderr)

    def test_gate_refuses_a_directory_other_users_cannot_search(self) -> None:
        # Review round 1 (Sol B-02): a 0744 directory is readable but not searchable by others.
        entries = dict(self.READABLE)
        entries["Payload/BasicCalc.app/"] = 0o744
        result = self.run_gate(self.write_ipa("unsearchable", entries))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("App Store Connect error 90255", result.stderr)
        self.assertIn("Payload/BasicCalc.app/", result.stderr)

    def test_gate_refuses_entries_without_unix_modes_and_unreadable_archives(self) -> None:
        result = self.run_gate(self.write_ipa("dos", self.READABLE, create_system=0))
        self.assertEqual(result.returncode, 1)
        self.assertIn("App Store Connect error 90255", result.stderr)
        bogus = self.base / "bogus.ipa"
        bogus.write_bytes(b"not a zip")
        result = self.run_gate(bogus)
        self.assertEqual(result.returncode, 1)
        self.assertIn("could not be read", result.stderr)

    def test_ipa_and_pkg_verifiers_call_the_permission_gates(self) -> None:
        text = SMOKE.read_text(encoding="utf-8")
        self.assertIn(
            'verify_ios_ipa_payload_world_readable "${ipa_path}" "${print_label}"',
            function(text, "verify_ios_ipa_artifact"),
        )
        self.assertIn(
            'verify_macos_pkg_payload_world_readable "${pkg_path}" "${print_label}" "${extract_dir}"',
            function(text, "verify_macos_pkg_artifact"),
        )



@unittest.skipUnless(SYSTEM_BASH.is_file(), "system /bin/bash is required")
class IosBuiltBundleNameGateTests(unittest.TestCase):
    """Review round 1 (Sol A-01): the processed Watch and PacketTunnel names are checked."""

    NAMES = {
        "Info.plist": "Win's VPN",
        "Watch/WinsWatch.app/Info.plist": "Win's VPN",
        "PlugIns/PacketTunnel.appex/Info.plist": "Win's VPN Helper",
    }

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="wins-bundle-names-")
        self.app = pathlib.Path(self.temp.name) / "BasicCalc.app"
        for relative, name in self.NAMES.items():
            self.write_plist(relative, {"CFBundleDisplayName": name, "CFBundleName": name})

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_plist(self, relative: str, value: dict[str, object]) -> None:
        import plistlib

        path = self.app / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(plistlib.dumps(value))

    def run_gate(self) -> subprocess.CompletedProcess[str]:
        text = SMOKE.read_text(encoding="utf-8")
        harness = (
            HARNESS_PRELUDE
            + f"PYTHON_BIN={sys.executable!r}\n"
            + function(text, "verify_ios_bundle_names")
            + 'verify_ios_bundle_names "Exported iOS App Store local app" "$1"\n'
            + "printf 'GATE-PASSED\\n'\n"
        )
        return subprocess.run(
            [str(SYSTEM_BASH), "-c", harness, "gate", str(self.app)],
            capture_output=True,
            text=True,
            env=clean_environment(),
            check=False,
        )

    def test_gate_accepts_the_ruled_names(self) -> None:
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("GATE-PASSED", result.stdout)

    def test_gate_refuses_each_wrong_processed_name(self) -> None:
        subjects = {
            "Info.plist": "host app",
            "Watch/WinsWatch.app/Info.plist": "WinsWatch",
            "PlugIns/PacketTunnel.appex/Info.plist": "PacketTunnel",
        }
        for relative, name in self.NAMES.items():
            for key in ("CFBundleDisplayName", "CFBundleName"):
                for wrong in ("Calculator", "WinsWatch", None):
                    with self.subTest(bundle=relative, key=key, value=wrong):
                        value = {"CFBundleDisplayName": name, "CFBundleName": name}
                        if wrong is None:
                            del value[key]
                        else:
                            value[key] = wrong
                        self.write_plist(relative, value)
                        try:
                            result = self.run_gate()
                        finally:
                            self.write_plist(
                                relative, {"CFBundleDisplayName": name, "CFBundleName": name}
                            )
                        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                        self.assertNotIn("GATE-PASSED", result.stdout)
                        self.assertIn(f"{subjects[relative]} {key}", result.stderr)

    def test_gate_refuses_a_missing_embedded_plist(self) -> None:
        (self.app / "Watch/WinsWatch.app/Info.plist").unlink()
        result = self.run_gate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("WinsWatch Info.plist could not be read", result.stderr)

    def test_the_ios_bundle_verifier_calls_the_name_gate(self) -> None:
        text = SMOKE.read_text(encoding="utf-8")
        self.assertIn(
            '  if [[ "${bundle_layout}" == "ios" ]]; then\n'
            '    verify_ios_bundle_names "${label}" "${app_path}"\n'
            "  fi\n}\n",
            # The verifier embeds Python whose own "}" lines end function(); take the whole body.
            text[
                text.index("\nverify_apple_app_bundle() {\n")
                : text.index("\nverify_ios_bundle_names() {\n")
            ],
        )


@unittest.skipUnless(SYSTEM_BASH.is_file(), "system /bin/bash is required")
class DirectUploadRefusalTests(unittest.TestCase):
    """Review round 1 (Sol B-01): no export reaches Apple before the payload gates run."""

    LANES = (
        ("ios_testflight_internal_upload_smoke", "WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE"),
        ("ios_app_store_connect_upload_smoke", "WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE"),
        ("macos_app_store_connect_upload_smoke", "WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE"),
    )
    STUBS = (
        "section() { :; }\n"
        "require_app_store_connect_upload_auth() { printf 'AUTH\\n'; }\n"
        "probe_app_store_connect_upload_auth() { printf 'PROBE\\n'; }\n"
        "require_valid_apple_submission_package_for_upload() { printf 'VALIDATE\\n'; }\n"
        "require_owner_signoff_for_app_store_upload() { printf 'SIGNOFF\\n'; }\n"
        "run_xcodebuild_with_export_signing_diagnostics() { printf 'XCODEBUILD-UPLOAD\\n'; }\n"
        "signed_ios_archive_path() { printf '/nonexistent.xcarchive'; }\n"
        "signed_macos_archive_path() { printf '/nonexistent.xcarchive'; }\n"
        "create_signed_ios_archive() { printf 'ARCHIVE\\n'; }\n"
        "verify_signed_ios_archive() { :; }\n"
        "create_signed_macos_archive() { printf 'ARCHIVE\\n'; }\n"
        "verify_signed_macos_archive() { :; }\n"
        "verify_apple_release_contamination() { :; }\n"
    )

    def run_script(self, body: str, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        text = SMOKE.read_text(encoding="utf-8")
        harness = (
            HARNESS_PRELUDE
            + self.STUBS
            + function(text, "refuse_direct_app_store_connect_upload")
            + function(text, "app_store_connect_upload_lane_requested")
            + body
        )
        env = clean_environment()
        for _, flag in self.LANES:
            env[flag] = "0"
        env.update(environment)
        return subprocess.run(
            [str(SYSTEM_BASH), "-c", harness],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

    def test_each_upload_lane_refuses_before_auth_or_export(self) -> None:
        text = SMOKE.read_text(encoding="utf-8")
        for lane, flag in self.LANES:
            with self.subTest(lane=lane):
                result = self.run_script(function(text, lane) + f"{lane}\n", {flag: "1"})
                self.assertEqual(result.returncode, 70, result.stdout + result.stderr)
                self.assertIn("Direct App Store Connect upload is disabled", result.stderr)
                for marker in ("AUTH", "ARCHIVE", "XCODEBUILD-UPLOAD"):
                    self.assertNotIn(marker, result.stdout)

    def test_the_main_upload_gate_refuses_first(self) -> None:
        text = SMOKE.read_text(encoding="utf-8")
        start = text.index("\nif app_store_connect_upload_lane_requested; then\n") + 1
        block = text[start : text.index("\nfi\n", start) + 4]
        self.assertTrue(
            block.startswith(
                "if app_store_connect_upload_lane_requested; then\n"
                "  refuse_direct_app_store_connect_upload\n"
            ),
            block,
        )
        for _, flag in self.LANES:
            with self.subTest(flag=flag):
                result = self.run_script(block + "printf 'LANE-PASSED\\n'\n", {flag: "1"})
                self.assertEqual(result.returncode, 70, result.stdout + result.stderr)
                for marker in ("AUTH", "PROBE", "VALIDATE", "SIGNOFF", "LANE-PASSED"):
                    self.assertNotIn(marker, result.stdout)
        result = self.run_script(block + "printf 'LANE-PASSED\\n'\n", {})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("LANE-PASSED", result.stdout)


@unittest.skipUnless(SYSTEM_BASH.is_file(), "system /bin/bash is required")
class PrivateReleaseSymbolModeTests(unittest.TestCase):
    """Review round 1 (Argon F-01): umask 022 must not leave private .symbols readable."""

    def test_symbols_written_under_umask_022_end_private(self) -> None:
        import stat

        text = SMOKE.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix="wins-symbols-") as raw:
            root = pathlib.Path(raw).resolve()
            symbols = root / ".artifacts/private-release-symbols/apple/ios/1.0.16+33"
            harness = (
                HARNESS_PRELUDE
                + f"PYTHON_BIN={sys.executable!r}\n"
                + f"ROOT_DIR={str(root)!r}\n"
                + "apple_release_symbol_dir() { printf '%s\\n' "
                + f"{str(symbols)!r}; }}\n"
                + function(text, "prepare_apple_release_symbols")
                + function(text, "require_apple_release_symbols")
                + "umask 022\n"
                + 'dir="$(prepare_apple_release_symbols ios)"\n'
                + 'mkdir -p "${dir}/nested"\n'
                + "head -c 128 /dev/zero > \"${dir}/app.ios-arm64.symbols\"\n"
                + 'printf x > "${dir}/nested/extra.txt"\n'
                + "require_apple_release_symbols ios\n"
                + "printf 'DONE\\n'\n"
            )
            result = subprocess.run(
                [str(SYSTEM_BASH), "-c", harness],
                capture_output=True,
                text=True,
                env=clean_environment(),
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("DONE", result.stdout)
            for path, expected in (
                (symbols, 0o700),
                (symbols / "nested", 0o700),
                (symbols / "app.ios-arm64.symbols", 0o600),
                (symbols / "nested/extra.txt", 0o600),
            ):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected, path)


if __name__ == "__main__":
    unittest.main()
