#!/usr/bin/env python3
"""Regression contracts for the privacy-safe Android release producer."""

from __future__ import annotations

import fcntl
import hashlib
import io
import json
import os
import pathlib
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile


def powershell_executable() -> str | None:
    names = (
        ("powershell.exe", "pwsh")
        if os.name == "nt"
        else ("pwsh", "powershell.exe")
    )
    for name in names:
        value = shutil.which(name)
        if value:
            return value
    bundled = (
        pathlib.Path.home()
        / "Library"
        / "Application Support"
        / "WinsVPN"
        / "toolchains"
        / "powershell-7.6.4"
        / "pwsh"
    )
    return str(bundled) if bundled.is_file() else None


ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "tools" / "build_android_release.ps1"
SOURCE = SCRIPT_PATH.read_text(encoding="utf-8")
MAC_SCRIPT_PATH = ROOT / "tools" / "build_android_release_macos.sh"
MAC_SOURCE = MAC_SCRIPT_PATH.read_text(encoding="utf-8")
WRAPPER_PROPERTIES = (
    ROOT / "android" / "gradle" / "wrapper" / "gradle-wrapper.properties"
).read_text(encoding="utf-8")
DEVICECHECK_WRAPPER_PROPERTIES = (
    ROOT / "android" / "devicecheck" / "gradle" / "wrapper" / "gradle-wrapper.properties"
).read_text(encoding="utf-8")
TOOLCHAIN_PINS = json.loads(
    (ROOT / "tools/toolchain-pins.json").read_text(encoding="utf-8")
)["tools"]
EXPECTED_FLUTTER_REVISION = TOOLCHAIN_PINS["flutter"]["revision"]
EXPECTED_FLUTTER_VERSION = TOOLCHAIN_PINS["flutter"]["version"]
EXPECTED_GRADLE_VERSION = TOOLCHAIN_PINS["gradle"]["distribution_version"]
EXPECTED_GRADLE_ZIP_SHA256 = TOOLCHAIN_PINS["gradle"][
    "distribution_sha256_by_flavour"
]["all"]
EXPECTED_WRAPPER_JAR_SHA256 = TOOLCHAIN_PINS["gradle"]["wrapper_jar_sha256"]
EXPECTED_AGP_VERSION = TOOLCHAIN_PINS["android_gradle_plugin"]["version"]
AAPT2_RELEASE_HOSTS = ("linux", "osx", "windows")
ANDROID_LOCKFILES = tuple(
    sorted((ROOT / "android/gradle/dependency-locking").glob("*.lockfile"))
)
ANDROID_VERIFICATION_METADATA = (
    ROOT / "android/gradle/verification-metadata.xml"
)
APKSIGNER_RELATIVE = "build-tools/37.0.0/lib/apksigner.jar"


def _android_tools_version(agp_version: str) -> str:
    major, minor, patch = agp_version.split(".")
    if not (major.isdigit() and minor.isdigit() and patch.isdigit()):
        raise ValueError(f"AGP pin is not major.minor.patch: {agp_version}")
    # com.android.tools.* versions trail AGP by 23 on the major.
    return f"{int(major) + 23}.{minor}.{patch}"


def _stale_series_pattern(version: str) -> re.Pattern[str]:
    major, minor, patch = version.split(".")
    return re.compile(
        rf"(?<!\d){re.escape(major)}\.{re.escape(minor)}\."
        rf"(?!{re.escape(patch)}(?:\D|$))\d+"
    )


def _aapt2_proto_build_ids(lock_text: str, agp_version: str) -> set[str]:
    return set(
        re.findall(
            rf"com\.android\.tools\.build:aapt2-proto:{re.escape(agp_version)}-(\d+)=",
            lock_text,
        )
    )


def _neutral_input_files_assignment() -> str:
    start = SOURCE.index("$NeutralInputFiles = @(")
    end = SOURCE.index(")", start) + 1
    return SOURCE[start:end]


def _apksigner_hold_source() -> str:
    begin = MAC_SOURCE.index("# WINS_ANDROID_APKSIGNER_HOLD_BEGIN\n")
    begin += len("# WINS_ANDROID_APKSIGNER_HOLD_BEGIN\n")
    end = MAC_SOURCE.index("\n# WINS_ANDROID_APKSIGNER_HOLD_END")
    return MAC_SOURCE[begin:end]


def _mac_shell_function(name: str) -> str:
    match = re.search(r"(?m)^" + re.escape(name) + r"\(\) \{\n", MAC_SOURCE)
    if match is None:
        raise AssertionError(f"build_android_release_macos.sh does not define {name}()")
    end = MAC_SOURCE.index("\n}\n", match.start()) + 3
    return MAC_SOURCE[match.start() : end]


def _apksigner_hold_namespace() -> dict:
    namespace: dict = {"__name__": "apksigner_hold"}
    exec(compile(_apksigner_hold_source(), "apksigner_hold", "exec"), namespace)
    return namespace


class AndroidReleaseProducerTests(unittest.TestCase):
    def test_windows_play_redemption_gate_is_in_neutral_stage_and_runs_on_all_outputs(self) -> None:
        neutral_inputs = _neutral_input_files_assignment()
        self.assertIn("'tools/android_play_redemption_gate.py'", neutral_inputs)
        gate_call = SOURCE.index("$PlayRedemptionGate, '--repo', $RepoRoot,")
        self.assertLess(SOURCE.index("$ApkPath, $AabPath, $TvApkPath, $TvAabPath", gate_call), SOURCE.index("Copy-Item -LiteralPath $R8MappingPath"))
        self.assertGreater(gate_call, SOURCE.index("Android release artifacts lack the reviewed Winn3 ring identity."))

    def test_windows_privacy_scans_only_canonical_stage_or_published_paths(self) -> None:
        specs = re.findall(
            r"@\{ Target = 'android-(?:phone-tablet|tv)-(?:apk|aab)'; Artifact = \$([A-Za-z]+) \}",
            SOURCE,
        )
        self.assertEqual(len(specs), 8, specs)
        self.assertEqual(
            sorted(specs),
            sorted([
                "ApkPath", "AabPath", "TvApkPath", "TvAabPath",
                "destinationApk", "destinationAab", "destinationTvApk", "destinationTvAab",
            ]),
        )

    def test_exact_target_privacy_scans_only_canonical_artifact_paths(self) -> None:
        # The exact privacy target binds the canonical artifact filename. A
        # prepared publication copy is a sibling temporary and can never carry
        # it, so every exact-target scan names a staged or a published path.
        specs = re.findall(
            r'"(android-(?:phone-tablet|tv)-(?:apk|aab)):\$\{([A-Z_]+)\}"',
            MAC_SOURCE,
        )
        self.assertEqual(len(specs), 8, specs)
        variables = [variable for _target, variable in specs]
        self.assertFalse(
            [name for name in variables if not name.startswith(("STAGE_", "ROOT_"))],
            variables,
        )
        self.assertEqual(
            sorted(name for name in variables if name.startswith("STAGE_")),
            ["STAGE_AAB", "STAGE_APK", "STAGE_TV_AAB", "STAGE_TV_APK"],
        )
        self.assertEqual(
            sorted(name for name in variables if name.startswith("ROOT_")),
            ["ROOT_AAB", "ROOT_APK", "ROOT_TV_AAB", "ROOT_TV_APK"],
        )
        self.assertIn(
            '.winsvpn-android-publication-prepared-$$-${RANDOM}${extension}',
            _mac_shell_function("prepare_file"),
        )

    def test_macos_signing_secrets_are_never_xtraced(self) -> None:
        unexport = MAC_SOURCE.index(
            "export -n WINS_ANDROID_KEYSTORE WINS_ANDROID_KEY_ALIAS"
        )
        path_assign = MAC_SOURCE.index("PATH=/usr/bin:/bin:/usr/sbin:/sbin")
        disable = MAC_SOURCE.index("case \"$-\" in *x*) set +x ;; esac")
        load = MAC_SOURCE.index(
            "load_android_signing_env_if_unset\nassert_complete_android_signing_env"
        )
        assign = MAC_SOURCE.index(
            'WINS_ANDROID_KEYSTORE="$(assert_private_external_keystore'
        )
        self.assertLess(unexport, path_assign)
        self.assertLess(unexport, disable)
        self.assertLess(disable, load)
        self.assertLess(disable, assign)
        self.assertNotIn("set -x", MAC_SOURCE)

    def test_macos_keystore_rejects_hardlink_aliases(self) -> None:
        guard = MAC_SOURCE[
            MAC_SOURCE.index("assert_private_external_keystore()") :
            MAC_SOURCE.index('WINS_ANDROID_KEYSTORE="$(assert_private_external_keystore')
        ]
        self.assertIn("info.st_nlink != 1", guard)
        self.assertIn("must not be hard-linked", guard)

    def test_macos_toolchain_custody_requires_independent_tree_pins(self) -> None:
        # Owner rulings: the Android producer no longer runs ReleasePython
        # custody (the interpreter and runtime wheels are bound by their
        # pinned SHA-256s) and no longer sources the archive custody helper
        # or requires owner-provisioned /Library trees (the pinned home
        # Flutter and JDK are bound by version metadata and tree digests).
        for removed in (
            "release_python_archive_custody.sh",
            "wins_release_python_prepare",
            "wins_release_python_cleanup",
            "WINS_RELEASE_PYTHON_BIN",
            "WINS_RELEASE_PYTHON_RUNTIME",
            'export DYLD_FRAMEWORK_PATH=',
            'export DYLD_LIBRARY_PATH=',
            'source "${ROOT}/tools/release_android_toolchain_archive_custody.sh"',
            "wins_release_android_toolchains_require_sealed_execution",
            "wins_release_android_toolchains_cleanup",
            "WINS_RELEASE_ANDROID_OWNER",
            "/Library/WinsVPN",
            "previously root-provisioned",
        ):
            self.assertNotIn(removed, MAC_SOURCE)
        for marker in (
            "prepare_pinned_release_python",
            "release_python_cleanup || status=74",
            "wins_release_android_toolchains_prepare",
            "wins_release_android_toolchains_verify",
            "verify_home_toolchain_tree",
            "Toolchain pin manifest changed after custody was established",
        ):
            self.assertIn(marker, MAC_SOURCE)
        self.assertGreaterEqual(MAC_SOURCE.count("assert_reviewed_toolchain_custody"), 4)
        self.assertNotIn("install_tree_sha256", TOOLCHAIN_PINS["python"])
        self.assertRegex(
            TOOLCHAIN_PINS["java"]["install_tree_sha256"]["darwin_arm64"],
            r"^[0-9a-f]{64}$",
        )
        self.assertRegex(
            TOOLCHAIN_PINS["flutter"]["installed_tree_sha256"]["darwin_arm64"],
            r"^[0-9a-f]{64}$",
        )

    def test_macos_signing_env_loader_is_strict_and_non_executing(self) -> None:
        loader = MAC_SOURCE[
            MAC_SOURCE.index("assert_private_android_signing_env_file()") :
            MAC_SOURCE.index("# Winn3 descriptor verification key")
        ]
        for marker in (
            'path="${HOME}/.winsvpn/android-release.env"',
            '[[ -f "${path}" && -r "${path}" && ! -L "${path}" ]]',
            "must be owned by the current user",
            "mode 0600 or stricter without execute bits",
            "must not be hard-linked",
            "uses an unsupported key",
            "repeats ${key}",
            "WINS_ANDROID_KEYSTORE) WINS_ANDROID_KEYSTORE=",
            "assert_complete_android_signing_env",
        ):
            self.assertIn(marker, loader)
        self.assertNotIn("source ", loader)
        self.assertNotIn("eval ", loader)
        self.assertNotIn("bash -c", loader)
        self.assertLess(
            MAC_SOURCE.index("load_android_signing_env_if_unset"),
            MAC_SOURCE.index('WINS_ANDROID_KEYSTORE="$(assert_private_external_keystore'),
        )
        self.assertNotIn("/Users/winsvpn", MAC_SOURCE)

    @unittest.skipUnless(sys.platform == "darwin", "macOS signing-env loader test")
    def test_macos_signing_env_autoloads_without_executing_values(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as name:
            home = pathlib.Path(name)
            private = home / ".winsvpn"
            private.mkdir(mode=0o700)
            keystore = private / "android-release.keystore"
            keystore.write_bytes(b"test-only-keystore-placeholder")
            keystore.chmod(0o600)
            command_marker = home / "must-not-exist"
            secret_marker = "loader-secret-must-not-be-printed"
            env_file = private / "android-release.env"
            env_file.write_text(
                "# strict fixture\n"
                f'export WINS_ANDROID_KEYSTORE="{keystore}"\n'
                'export WINS_ANDROID_KEY_ALIAS="winsvpn-release"\n'
                f'export WINS_ANDROID_KEY_PASSWORD="$(touch {command_marker})"\n'
                f'export WINS_ANDROID_STORE_PASSWORD="{secret_marker}"\n',
                encoding="utf-8",
            )
            env_file.chmod(0o600)
            env = {
                "HOME": str(home),
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "WINS_ANDROID_MACOS_PS_ENTRYPOINT": "1",
            }
            completed = subprocess.run(
                [
                    "/bin/bash",
                    "-p",
                    "-x",
                    str(MAC_SCRIPT_PATH),
                    "--release-input-index",
                    "missing",
                ],
                cwd=ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = completed.stdout + completed.stderr
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("loaded four signing variables", completed.stdout)
            self.assertIn("Release input index is missing or symbolic", completed.stderr)
            self.assertFalse(command_marker.exists())
            self.assertNotIn(secret_marker, output)
            self.assertNotIn("touch", output)

    def test_macos_trusted_path_is_fixed_and_exported_before_root_invokes_dirname(
        self,
    ) -> None:
        unexport = MAC_SOURCE.index(
            "export -n WINS_ANDROID_KEYSTORE WINS_ANDROID_KEY_ALIAS"
        )
        path_assign = MAC_SOURCE.index("PATH=/usr/bin:/bin:/usr/sbin:/sbin")
        path_export = MAC_SOURCE.index("export PATH")
        root_dirname = MAC_SOURCE.index(
            'ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"'
        )
        first_dirname = MAC_SOURCE.index("dirname")
        self.assertLess(unexport, path_assign)
        self.assertLess(path_assign, path_export)
        self.assertLess(path_export, root_dirname)
        self.assertLess(path_export, first_dirname)
        self.assertGreater(first_dirname, root_dirname)
        self.assertIn(
            "PATH=/usr/bin:/bin:/usr/sbin:/sbin\nexport PATH\n",
            MAC_SOURCE[:root_dirname],
        )

    def test_macos_no_ambient_bare_python3_after_bootstrap(self) -> None:
        bootstrap = MAC_SOURCE.index('PIN_PYTHON_BIN="/usr/bin/python3"')
        self.assertLess(MAC_SOURCE.index("export PATH"), bootstrap)
        after = MAC_SOURCE[bootstrap:]
        self.assertNotRegex(
            after,
            r"(?m)(?:^|[\s;|&(`])python3(?:[\s\"';]|$)",
        )
        self.assertNotIn("command -v python3", after)
        self.assertNotIn("$(python3", after)
        self.assertIn('"${PIN_PYTHON_BIN}" -', after)
        self.assertNotIn(" python3 -", after)
        self.assertNotIn("\npython3 ", after)

    def test_macos_post_custody_python_operations_use_wins_release_python_run(
        self,
    ) -> None:
        prepare = MAC_SOURCE.index("\nprepare_pinned_release_python\n")
        post = MAC_SOURCE[prepare:]
        self.assertGreaterEqual(post.count("wins_release_python_run"), 20)
        self.assertNotIn("WINS_RELEASE_PYTHON_BIN", MAC_SOURCE)
        self.assertIn('PYTHON_BIN="${python_path}"', _mac_shell_function("prepare_pinned_release_python"))
        self.assertNotRegex(post, r'"\$\{PYTHON_BIN\}"\s+(?!\]\])')
        # The pinned interpreter is executed in exactly one place: the runner
        # behind wins_release_python_run. Its clean variant uses env -i; the
        # variant that carries the two signing passwords uses
        # run_with_exact_environment so the passwords never appear on the
        # command line of an env process.
        runner = _mac_shell_function("_wins_android_release_python_exec")
        self.assertEqual(runner.count('"${PYTHON_BIN}" "${startup_flags[@]}" "$@"'), 2)
        self.assertEqual(runner.count("/usr/bin/env -i"), 1)
        self.assertEqual(runner.count("run_with_exact_environment"), 1)
        privacy_branch = runner[
            runner.index('if [[ "${mode}" == android-privacy ]]; then'):runner.index("/usr/bin/env -i")
        ]
        self.assertIn("run_with_exact_environment", privacy_branch)
        self.assertIn("WINS_ANDROID_KEY_PASSWORD", privacy_branch)
        self.assertNotIn("/usr/bin/env", privacy_branch)
        outside_runner = MAC_SOURCE.replace(runner, "")
        self.assertNotIn('"${PYTHON_BIN}" -', outside_runner)
        self.assertNotIn('"${PYTHON_BIN}" "${', outside_runner)
        self.assertNotIn('"${PYTHON_BIN}" "${PUBLICATION_TOOL}"', MAC_SOURCE)
        self.assertNotIn('"${PYTHON_BIN}" "${DEPENDENCY_FREEZE}"', MAC_SOURCE)
        self.assertIn(
            'wins_release_python_run "${PUBLICATION_TOOL}" commit', MAC_SOURCE
        )
        # The freeze worker is launched only through its parent launcher,
        # which checks the pinned interpreter sha256; never run directly.
        self.assertIn(
            '/bin/bash "${DEPENDENCY_FREEZE_PARENT}" verify-index',
            MAC_SOURCE,
        )
        self.assertIn(
            'DEPENDENCY_FREEZE_PARENT="${ROOT}/tools/run_release_dependency_freeze.sh"',
            MAC_SOURCE,
        )
        self.assertNotIn('"${DEPENDENCY_FREEZE}" ', MAC_SOURCE)

    def test_macos_finish_build_names_the_macos_producer(self) -> None:
        # On darwin the freeze accepts only this producer for an Android
        # receipt (producer-attested); the PowerShell producer is windows-only.
        start = MAC_SOURCE.index("finish_receipt() {")
        body = MAC_SOURCE[start:MAC_SOURCE.index("\n}\n", start)]
        self.assertIn("--producer tools/build_android_release_macos.sh", body)
        self.assertNotIn("--producer tools/build_android_release.ps1", body)

    def test_macos_signer_verifier_receives_only_its_pinned_tool_locations(self) -> None:
        start = MAC_SOURCE.index("_wins_android_release_python_exec() {")
        runner = MAC_SOURCE[start:MAC_SOURCE.index("\n}\n", start)]
        verifier_case = runner[
            runner.index("tools/verify_android_aab_signers.py|"):runner.index("esac")
        ]
        for name in ("WINS_RELEASE_JAVA_HOME", "WINS_BUNDLETOOL_JAR", "ANDROID_SDK_ROOT"):
            self.assertIn(f'verifier_env+=("{name}=${{{name}}}")', verifier_case)
        self.assertIn("verifier_env=()", runner)
        self.assertEqual(runner.count('${verifier_env[@]+"${verifier_env[@]}"}'), 2)
        self.assertLess(runner.index("verifier_env=()"), runner.index("case \"${1:-}\" in"))

    def test_macos_release_python_forwards_only_the_secret_inventory_path(self) -> None:
        # release_obfuscation_contract record/verify run through this runner
        # under env -i; the exact secret scan reads the inventory that
        # WINS_RELEASE_SECRET_INVENTORY names, so that path (and nothing else
        # from the caller) must reach every pinned-Python child.
        start = MAC_SOURCE.index("_wins_android_release_python_exec() {")
        runner = MAC_SOURCE[start:MAC_SOURCE.index("\n}\n", start) + 3]
        with tempfile.TemporaryDirectory() as raw:
            tmp = pathlib.Path(raw)
            vendor = tmp / "vendor"
            vendor.mkdir()
            child = tmp / "python"
            child.write_text("#!/bin/sh\n/usr/bin/env\n", encoding="utf-8")
            child.chmod(0o700)
            script = (
                runner
                + f"RELEASE_PYTHON_VENDOR={shlex.quote(str(vendor))}\n"
                + f"PYTHON_BIN={shlex.quote(str(child))}\n"
                + "_wins_android_release_python_exec clean tools/release_obfuscation_contract.py verify\n"
            )
            base = {"PATH": "/usr/bin:/bin", "HOME": str(tmp), "WINS_LEAK_PROBE": "leak"}
            for value in ("/Volumes/Keys/release-secret-inventory.json", None):
                env = dict(base)
                if value is not None:
                    env["WINS_RELEASE_SECRET_INVENTORY"] = value
                completed = subprocess.run(
                    ["/bin/bash", "-c", script], env=env, capture_output=True,
                    text=True, check=False, timeout=30,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                lines = completed.stdout.splitlines()
                self.assertNotIn("WINS_LEAK_PROBE=leak", lines)
                forwarded = [line for line in lines if line.startswith("WINS_RELEASE_SECRET_INVENTORY=")]
                if value is None:
                    self.assertEqual(forwarded, [])
                else:
                    self.assertEqual(forwarded, [f"WINS_RELEASE_SECRET_INVENTORY={value}"])

    def test_macos_early_missing_index_signing_env_completes_within_existing_timeout(
        self,
    ) -> None:
        load = MAC_SOURCE.index(
            "load_android_signing_env_if_unset\n"
            "assert_complete_android_signing_env\n"
            "assert_owner_keystore_present"
        )
        resolve = MAC_SOURCE.index(
            'RELEASE_INDEX="$(resolve_repo_index "${RELEASE_INDEX}")"',
            load,
        )
        prepare = MAC_SOURCE.index("\nprepare_pinned_release_python\n", resolve)
        self.assertLess(load, resolve)
        self.assertLess(resolve, prepare)
        if sys.platform != "darwin":
            return
        with tempfile.TemporaryDirectory(dir="/private/tmp") as name:
            home = pathlib.Path(name)
            private = home / ".winsvpn"
            private.mkdir(mode=0o700)
            keystore_path = private / "android-release.keystore"
            keystore_path.write_bytes(b"test-only-keystore-placeholder")
            keystore_path.chmod(0o600)
            completed = subprocess.run(
                [
                    "/bin/bash",
                    "-p",
                    str(MAC_SCRIPT_PATH),
                    "--release-input-index",
                    "missing",
                ],
                cwd=ROOT,
                env={
                    "HOME": str(home),
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "WINS_ANDROID_MACOS_PS_ENTRYPOINT": "1",
                    "WINS_ANDROID_KEYSTORE": str(keystore_path),
                    "WINS_ANDROID_KEY_ALIAS": "winsvpn-release",
                    "WINS_ANDROID_KEY_PASSWORD": "password",
                    "WINS_ANDROID_STORE_PASSWORD": "password",
                },
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        output = completed.stdout + completed.stderr
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("Release input index is missing or symbolic", completed.stderr)
        self.assertNotIn("Pinned release Python", output)
        self.assertNotIn("release Python runtime wheels", output)
        self.assertNotIn("archive-derived Flutter/JDK preparation", output)

    @unittest.skipUnless(sys.platform == "darwin", "macOS missing-keystore blocker")
    def test_macos_missing_keystore_is_owner_blocked_before_index(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as name:
            completed = subprocess.run(
                [
                    "/bin/bash",
                    "-p",
                    str(MAC_SCRIPT_PATH),
                    "--release-input-index",
                    "missing",
                ],
                cwd=ROOT,
                env={
                    "HOME": name,
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "WINS_ANDROID_MACOS_PS_ENTRYPOINT": "1",
                    "WINS_ANDROID_KEYSTORE": "/outside/missing.keystore",
                    "WINS_ANDROID_KEY_ALIAS": "winsvpn-release",
                    "WINS_ANDROID_KEY_PASSWORD": "password",
                    "WINS_ANDROID_STORE_PASSWORD": "password",
                },
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("OWNER-BLOCKED: missing Android upload keystore", completed.stderr)
        self.assertNotIn("Release input index is missing or symbolic", completed.stderr)

    @unittest.skipUnless(sys.platform == "darwin", "macOS signing-env safety test")
    def test_macos_signing_env_refuses_unsafe_file_and_partial_override(self) -> None:
        cases = (
            (0o644, None, "mode 0600 or stricter"),
            (0o700, None, "mode 0600 or stricter"),
            (0o600, "WINS_ANDROID_UNKNOWN=value\n", "unsupported key"),
            (
                0o600,
                "WINS_ANDROID_KEY_ALIAS=one\nWINS_ANDROID_KEY_ALIAS=two\n",
                "repeats WINS_ANDROID_KEY_ALIAS",
            ),
            (0o600, "WINS_ANDROID_KEY_ALIAS=value\r\n", "carriage return"),
        )
        for mode, content, expected in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as name:
                home = pathlib.Path(name)
                private = home / ".winsvpn"
                private.mkdir(mode=0o700)
                env_file = private / "android-release.env"
                env_file.write_text(
                    content
                    or (
                        "WINS_ANDROID_KEYSTORE=/outside/test.keystore\n"
                        "WINS_ANDROID_KEY_ALIAS=winsvpn-release\n"
                        "WINS_ANDROID_KEY_PASSWORD=password\n"
                        "WINS_ANDROID_STORE_PASSWORD=password\n"
                    ),
                    encoding="utf-8",
                    newline="",
                )
                env_file.chmod(mode)
                completed = subprocess.run(
                    [
                        "/bin/bash",
                        "-p",
                        str(MAC_SCRIPT_PATH),
                        "--release-input-index",
                        "missing",
                    ],
                    cwd=ROOT,
                    env={
                        "HOME": str(home),
                        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                        "WINS_ANDROID_MACOS_PS_ENTRYPOINT": "1",
                    },
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(expected, completed.stderr)

        with tempfile.TemporaryDirectory() as name:
            home = pathlib.Path(name)
            private = home / ".winsvpn"
            private.mkdir(mode=0o700)
            env_file = private / "android-release.env"
            env_file.write_text("this file must not be parsed\n", encoding="utf-8")
            env_file.chmod(0o600)
            completed = subprocess.run(
                [
                    "/bin/bash",
                    "-p",
                    str(MAC_SCRIPT_PATH),
                    "--release-input-index",
                    "missing",
                ],
                cwd=ROOT,
                env={
                    "HOME": str(home),
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "WINS_ANDROID_MACOS_PS_ENTRYPOINT": "1",
                    "WINS_ANDROID_KEYSTORE": "/outside/partial.keystore",
                },
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("WINS_ANDROID_KEY_ALIAS is required", completed.stderr)
            self.assertNotIn("not KEY=VALUE", completed.stderr)

    def test_macos_entrypoint_delegates_without_loading_windows_signing_state(self) -> None:
        delegate = SOURCE.index("if ($RunningOnMacOS)")
        windows_default = SOURCE.index("$SigningStorePath = Join-Path $env:LOCALAPPDATA")
        self.assertLess(delegate, windows_default)
        for marker in (
            "tools/build_android_release_macos.sh",
            "WINS_ANDROID_MACOS_PS_ENTRYPOINT",
            "--release-input-index",
            "--build-receipt-directory",
        ):
            self.assertIn(marker, SOURCE[delegate:windows_default])

    def test_macos_producer_is_isolated_index_bound_and_receipt_owning(self) -> None:
        for marker in (
            "mktemp -d /private/tmp/winsvpn-android-neutral.XXXXXX",
            "source-inputs.json",
            "cmp -s \"${SOURCE_SNAPSHOT}\" \"${STAGE_SNAPSHOT}\"",
            "verify-index --repo \"${ROOT}\" --index \"${RELEASE_INDEX}\"",
            "ANDROID_APK_BUILD_BEGIN.json",
            "ANDROID_AAB_BUILD_BEGIN.json",
            "ANDROID_APK_BUILD_RECEIPT.json",
            "ANDROID_AAB_BUILD_RECEIPT.json",
            "finish-build --repo \"${ROOT}\"",
            "verify-receipt --repo \"${ROOT}\"",
        ):
            self.assertIn(marker, MAC_SOURCE)
        self.assertGreaterEqual(
            MAC_SOURCE.count(
                '"${DEPENDENCY_FREEZE_PARENT}" verify-index --repo "${ROOT}" --index "${RELEASE_INDEX}"'
            ),
            3,
        )

    def test_every_producer_index_verification_is_scoped_to_android(self) -> None:
        # A phased release freezes only the Android platform, so the index it
        # produces is a scoped index and a platform-less verify-index (which
        # needs the full seven-platform set) refuses it. Every verification in
        # both producers must name the platform it is allowed to rely on.
        mac_calls = [
            line.strip() for line in MAC_SOURCE.splitlines() if " verify-index " in line
        ]
        self.assertEqual(len(mac_calls), 3, mac_calls)
        for call in mac_calls:
            self.assertTrue(call.endswith(" --platform android"), call)
        starts = [match.start() for match in re.finditer(r"'verify-index'", SOURCE)]
        self.assertEqual(len(starts), 2)
        for start in starts:
            window = SOURCE[start:SOURCE.index("-FailureMessage", start)]
            self.assertIn("'--platform', 'android'", window)

    def test_macos_producer_protects_signing_and_private_symbols(self) -> None:
        for marker in (
            "must remain outside the repository",
            "mode 0600 or stricter",
            "EXPECTED_UPLOAD_CERTIFICATE_SHA256",
            "Unexpected Android upload signer",
            "Android APK and AAB signer certificates differ",
            "prepare_symbols",
            "find \"${temporary}\" -type f -exec chmod 0600",
            "private_release_symbol_custody.py",
            "android_release_publication.py",
        ):
            self.assertIn(marker, MAC_SOURCE)

    def test_macos_cleanup_guards_empty_arrays_for_bash_3_2_nounset(self) -> None:
        self.assertIn('if (( ${#PREPARED_PATHS[@]} > 0 )); then', MAC_SOURCE)
        completed = subprocess.run(
            [
                "/bin/bash",
                "-uc",
                'values=(); if (( ${#values[@]} > 0 )); then '
                'for value in "${values[@]}"; do :; done; fi',
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_macos_producer_obfuscates_and_revalidates_all_android_artifacts(self) -> None:
        for marker in (
            "build apk --no-pub --release --flavor phone --obfuscate",
            "build appbundle --no-pub --release --flavor phone --obfuscate",
            "build apk --no-pub --release --flavor tv --obfuscate",
            "build appbundle --no-pub --release --flavor tv --obfuscate",
            "STAGE_TV_AAB_SYMBOLS",
            "android-tv-aab",
            "proguard-mapping.txt",
            "native-debug-symbols.zip",
            "release_obfuscation_contract.py",
            "validate_release_artifact_privacy.py",
            "apksigner",
            "WINS_BUNDLETOOL_JAR",
            "--verify android-phone-tablet-aab",
            "--verify-apk android-phone-tablet-apk",
            "--verify-apk android-tv-apk",
            "--bind-r8 android-phone-tablet-aab",
            "--bind-r8 android-tv-apk",
            '-verify "${STAGE_AAB}"',
            "verify_exact_android_identity_and_r8",
            'cp "${R8_MAPPING}" "${STAGE_APK_SYMBOLS}/proguard-mapping.txt"',
            'cp "${STAGE_TV_MAPPING}" "${STAGE_TV_APK_SYMBOLS}/proguard-mapping.txt"',
            "Android TV R8 mapping exactly reuses the phone/tablet mapping bytes.",
            '"build/app/outputs/flutter-apk/app-release.apk"',
            '"build/app/outputs/bundle/release/app-release.aab"',
        ):
            self.assertIn(marker, MAC_SOURCE)
        self.assertGreaterEqual(MAC_SOURCE.count("verify_exact_android_identity_and_r8"), 3)

    def test_macos_producer_builds_phone_pair_without_unflavored_app_release_apk(self) -> None:
        self.assertIn(
            'STAGE_APK="${STAGE_REPO}/build/app/outputs/flutter-apk/app-phone-release.apk"',
            MAC_SOURCE,
        )
        self.assertIn(
            'STAGE_AAB="${STAGE_REPO}/build/app/outputs/bundle/phoneRelease/app-phone-release.aab"',
            MAC_SOURCE,
        )
        self.assertIn(
            'STAGE_TV_APK="${STAGE_REPO}/build/app/outputs/flutter-apk/app-tv-release.apk"',
            MAC_SOURCE,
        )
        self.assertIn(
            'STAGE_TV_AAB="${STAGE_REPO}/build/app/outputs/bundle/tvRelease/app-tv-release.aab"',
            MAC_SOURCE,
        )
        self.assertIn("mapping/phoneRelease/mapping.txt", MAC_SOURCE)
        self.assertIn("mapping/tvRelease/mapping.txt", MAC_SOURCE)
        self.assertIn(
            "native-debug-symbols/phoneRelease/native-debug-symbols.zip",
            MAC_SOURCE,
        )
        self.assertNotIn("mapping/release/mapping.txt", MAC_SOURCE)
        self.assertNotIn(
            "native-debug-symbols/release/native-debug-symbols.zip",
            MAC_SOURCE,
        )
        self.assertNotIn(
            "build/app/outputs/flutter-apk/app-release.apk build/app/outputs/bundle/release/app-release.aab",
            MAC_SOURCE,
        )
        self.assertNotIn(
            "build apk --release --obfuscate --split-debug-info",
            MAC_SOURCE,
        )
        self.assertNotIn(
            "build appbundle --release --obfuscate --split-debug-info",
            MAC_SOURCE,
        )
        self.assertIn(
            'ROOT_APK="${ROOT}/build/app/outputs/flutter-apk/app-release.apk"',
            MAC_SOURCE,
        )
        self.assertIn(
            'ROOT_AAB="${ROOT}/build/app/outputs/bundle/release/app-release.aab"',
            MAC_SOURCE,
        )
        self.assertIn(
            'ROOT_TV_APK="${ROOT}/build/app/outputs/flutter-apk/app-tv-release.apk"',
            MAC_SOURCE,
        )
        self.assertIn(
            'ROOT_TV_AAB="${ROOT}/build/app/outputs/bundle/tvRelease/app-tv-release.aab"',
            MAC_SOURCE,
        )
        self.assertIn("pass --flavor so Flutter does not look for those names", MAC_SOURCE)
        self.assertIn("build appbundle --no-pub --release --flavor tv", MAC_SOURCE)

    @unittest.skipUnless(sys.platform == "darwin", "macOS guard test")
    def test_macos_helper_refuses_bypassing_frozen_powershell_entrypoint(self) -> None:
        completed = subprocess.run(
            ["/bin/bash", "-p", str(MAC_SCRIPT_PATH), "--release-input-index", "missing"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env={
                "HOME": str(pathlib.Path.home()),
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            },
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("Invoke tools/build_android_release.ps1", completed.stderr)

    def test_release_build_is_forced_through_neutral_stage(self) -> None:
        self.assertIn("if (-not $InNeutralStage)", SOURCE)
        self.assertIn("Initialize-NeutralStage", SOURCE)
        self.assertIn("-InNeutralStage -SigningStorePath", SOURCE)
        self.assertIn("SkipPubGet is incompatible", SOURCE)
        self.assertIn("WVPAndroidRelease", SOURCE)

    def test_staged_inputs_are_hash_bound_and_source_is_rechecked(self) -> None:
        for marker in (
            "$sourceBefore = @(Get-NeutralInputSnapshot -Root $RepoRoot)",
            "$stageSnapshot = @(Get-NeutralInputSnapshot -Root $stage.Repo)",
            "$sourceAfterCopy = @(Get-NeutralInputSnapshot -Root $RepoRoot)",
            "$sourceAfterBuild = @(Get-NeutralInputSnapshot -Root $RepoRoot)",
            "Assert-IdenticalInputSnapshots",
        ):
            self.assertIn(marker, SOURCE)

    def test_stage_is_acl_hardened_cleaned_and_publication_is_reverified(self) -> None:
        self.assertIn("'/inheritance:r' '/grant:r'", SOURCE)
        self.assertIn("*S-1-5-18:(OI)(CI)F", SOURCE)
        self.assertIn("Remove-Item -LiteralPath $stage.Container -Recurse -Force", SOURCE)
        for failure in (
            "Published Android $($specification.Platform) obfuscation verification failed.",
            "Published Android release artifact privacy verification failed.",
            "Published Android $($specification.Platform) private-symbol custody verification failed.",
            "Android APK/AAB/symbol publication transaction failed.",
            "Android publication transaction finalization failed.",
            "Android publication rollback failed.",
        ):
            self.assertIn(failure, SOURCE)

    def test_both_producers_pin_the_exact_reviewed_flutter_revision(self) -> None:
        # Both producers now READ the reviewed revision from the pin at run
        # time (Read-WinsToolchainPin / read_wins_toolchain_pin) instead of
        # carrying a literal that would desynchronise on the next pin bump.
        self.assertIn("$RequiredFlutterRevision = Read-WinsToolchainPin", SOURCE)
        self.assertIn("-Key 'tools.flutter.revision'", SOURCE)
        self.assertIn(
            "$flutterRevision -cne $RequiredFlutterRevision",
            SOURCE,
        )
        self.assertLess(
            SOURCE.index("# ANDROID_WINDOWS_CUSTODY_RUNTIME_IDENTITY_AFTER_TREES"),
            SOURCE.index("$flutterRevision -cne $RequiredFlutterRevision"),
        )
        self.assertIn(
            'REQUIRED_FLUTTER_REVISION="$(read_wins_toolchain_pin tools.flutter.revision)"',
            MAC_SOURCE,
        )
        self.assertIn(
            '"${FLUTTER_REVISION}" == "${REQUIRED_FLUTTER_REVISION}"',
            MAC_SOURCE,
        )
        self.assertEqual(EXPECTED_FLUTTER_VERSION, "3.47.6")
        self.assertEqual(
            EXPECTED_FLUTTER_REVISION,
            "5fc346839b5d0eef006ed8404392afb4dfae428d",
        )

    def test_both_producers_reject_a_symlinked_or_non_application_flutter(self) -> None:
        # Both producers already pin the exact reviewed Flutter version and
        # revision (see the test above), but that check is only meaningful
        # if it is being run against one real, on-disk flutter binary --
        # otherwise a symlink, shell function, or alias could report
        # whatever the pinned strings expect without being the real thing.
        self.assertIn("function Resolve-ReviewedFlutter", SOURCE)
        self.assertIn(
            "Get-Command flutter -CommandType Application",
            SOURCE,
        )
        self.assertIn(
            "Resolve-TrustedApplication -Name 'Flutter' -CandidatePath $candidate",
            SOURCE,
        )
        self.assertIn("$command.CommandType -ne 'Application'", SOURCE)
        self.assertIn("$item.LinkType", SOURCE)
        self.assertIn("& $flutterItem.FullName --version --machine", SOURCE)
        # The verified binary must also be what's actually invoked for the
        # real build steps, not just what's checked once and then ignored.
        self.assertNotIn("-FilePath 'flutter'", SOURCE)
        self.assertEqual(SOURCE.count("$flutterItem.FullName"), 6)

        self.assertIn("wins_release_android_flutter --version --machine", MAC_SOURCE)
        self.assertIn(
            "wins_release_android_flutter pub get --offline --enforce-lockfile --no-precompile",
            MAC_SOURCE,
        )
        self.assertIn('wins_release_android_flutter_build "$@"', MAC_SOURCE)
        self.assertEqual(MAC_SOURCE.count("run_flutter_release_build build"), 4)

    def test_macos_producer_resolves_java_keytool_and_jarsigner_as_real_files(self) -> None:
        # java was existence+executable-checked only (no symlink rejection),
        # then version-gated by major-version string alone -- no proof the
        # binary reporting "17" is a real, untampered JDK, even though R8/D8
        # (which optimizes and dexes the shipped release bytecode) runs
        # inside it. keytool/jarsigner were existence-checked only, with no
        # resolution step at all. All three now get the same real-file,
        # not-a-symlink treatment already applied to Flutter above.
        self.assertNotIn('JAVA_HOME="${WINS_RELEASE_JAVA_HOME}"', MAC_SOURCE)
        self.assertIn("wins_release_android_keytool_with_store_password -list -v", MAC_SOURCE)
        self.assertIn("wins_release_android_jdk_tool jarsigner -verify", MAC_SOURCE)
        self.assertIn("wins_release_android_jdk_tool keytool -printcert", MAC_SOURCE)
        self.assertNotIn("wins_release_android_jdk_tool java -jar", MAC_SOURCE)
        self.assertIn("run_held_apksigner", MAC_SOURCE)
        self.assertIn("snapshot_jar", MAC_SOURCE)  # java -jar gets a private snapshot, not a passed descriptor
        self.assertIn("/dev/fd/", MAC_SOURCE)
        self.assertNotIn("WINS_RELEASE_ANDROID_OWNER_JAVA", MAC_SOURCE)
        self.assertNotIn("export JAVA_HOME", MAC_SOURCE)
        self.assertIn('[[ "${SEALED_JAVA}" == "${WINS_RELEASE_JAVA_HOME}/bin/java"', MAC_SOURCE)
        self.assertIn('--java "${SEALED_JAVA}"', MAC_SOURCE)
        self.assertIn('--jarsigner "${SEALED_JARSIGNER}"', MAC_SOURCE)
        self.assertIn('--keytool "${SEALED_KEYTOOL}"', MAC_SOURCE)
        self.assertNotIn("(keytool -list", MAC_SOURCE)
        self.assertNotIn("\njarsigner -verify", MAC_SOURCE)
        self.assertNotIn("(keytool -printcert", MAC_SOURCE)
        self.assertNotIn("shutil.which", MAC_SOURCE)

    def test_macos_apksigner_jar_is_held_and_hash_pinned(self) -> None:
        self.assertIn("REVIEWED_APKSIGNER_JAR_RELATIVE", MAC_SOURCE)
        self.assertIn("build-tools/37.0.0/lib/apksigner.jar", MAC_SOURCE)
        self.assertIn(
            "2defad215d7ff52968a409cde528cdaef7918b115e276b8e3378ca7a178e4180",
            MAC_SOURCE,
        )
        self.assertIn("run_held_apksigner", MAC_SOURCE)
        self.assertIn("anonymous_held_fd", MAC_SOURCE)
        self.assertIn("WINS_ANDROID_APKSIGNER_HOLD_BEGIN", MAC_SOURCE)
        self.assertNotIn("find_android_apksigner_jar", MAC_SOURCE)
        self.assertNotIn("materialize_android_apksigner_jar", MAC_SOURCE)
        signer = MAC_SOURCE[
            MAC_SOURCE.index("run_android_apksigner()") : MAC_SOURCE.index(
                "resolve_existing_path()"
            )
        ]
        self.assertNotIn("find_android_tool", signer)
        self.assertNotIn("sort -V", signer)
        self.assertIn("REVIEWED_APKSIGNER_JAR_SHA256", signer)
        self.assertIn("hold_bytes", signer)
        self.assertIn("anonymous_held_fd", signer)
        self.assertIn("snapshot_jar", signer)  # java -jar gets a private snapshot, not a passed descriptor
        self.assertIn("O_NOFOLLOW", signer)
        self.assertIn("O_NONBLOCK", signer)
        self.assertIn("F_GETFL", signer)
        self.assertIn("F_SETFL", signer)
        self.assertIn("/dev/fd/", signer)
        self.assertIn("winsvpn-apksigner-anon.", signer)
        self.assertNotIn("/private/tmp/winsvpn-apksigner-hold.", MAC_SOURCE)
        self.assertNotIn('java -jar "${APK_SIGNER_JAR}"', MAC_SOURCE)
        self.assertNotIn('java -jar "${ANDROID_SDK_ROOT}', MAC_SOURCE)
        self.assertIn(
            "launch_macos_release_android_toolchains.py",
            MAC_SOURCE,
        )
        self.assertNotIn("sudo", MAC_SOURCE)
        self.assertNotIn(
            "sudo /Library/WinsVPN/ReleasePython/3.14.7/launcher/python3.14 -I tools/launch_macos_release_android_toolchains.py",
            MAC_SOURCE,
        )
        files = MAC_SOURCE[
            MAC_SOURCE.index("files = [") : MAC_SOURCE.index("excluded_dirs")
        ]
        self.assertIn("'tools/launch_macos_release_android_toolchains.py'", files)
        self.assertIn("'tools/provision_macos_release_android_toolchains.sh'", files)
        begin = MAC_SOURCE.index("# WINS_ANDROID_APKSIGNER_HOLD_BEGIN\n")
        begin += len("# WINS_ANDROID_APKSIGNER_HOLD_BEGIN\n")
        end = MAC_SOURCE.index("\n# WINS_ANDROID_APKSIGNER_HOLD_END")
        hold_source = MAC_SOURCE[begin:end]
        namespace: dict = {"__name__": "apksigner_hold"}
        exec(compile(hold_source, "apksigner_hold", "exec"), namespace)
        work = pathlib.Path(tempfile.mkdtemp(prefix="wins-apksigner-hold-", dir="/private/tmp"))
        self.addCleanup(lambda: shutil.rmtree(work, ignore_errors=True))
        sdk = work / "sdk"
        relative = pathlib.Path("build-tools/37.0.0/lib")
        (sdk / relative).mkdir(parents=True)
        original = b"reviewed-apksigner-bytes\n" + (b"A" * 64)
        swapped = b"X" * len(original)
        self.assertEqual(len(original), len(swapped))
        self.assertNotEqual(original, swapped)
        jar = sdk / relative / "apksigner.jar"
        jar.write_bytes(original)
        expected = hashlib.sha256(original).hexdigest()
        held = namespace["hold_bytes"](
            str(sdk), "build-tools/37.0.0/lib/apksigner.jar", expected
        )
        self.assertEqual(held, original)
        jar.write_bytes(swapped)
        self.assertEqual(jar.read_bytes(), swapped)
        fd = namespace["anonymous_held_fd"](held, expected)
        try:
            jar.write_bytes(swapped)
            self.assertEqual(jar.read_bytes(), swapped)
            descriptor = namespace["descriptor_jar_path"](fd)
            self.assertTrue(descriptor.startswith("/dev/fd/"))
            with open(descriptor, "rb") as stream:
                self.assertEqual(stream.read(), original)
        finally:
            os.close(fd)
            fd = -1
        fake_java = work / "java"
        output = work / "java-seen.bin"
        fake_java.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            f"out = {str(output)!r}\n"
            "argv = sys.argv[1:]\n"
            "if not argv or argv[0] != '-jar' or len(argv) < 2:\n"
            "    raise SystemExit('fake java expected -jar')\n"
            "jar_arg = argv[1]\n"
            "import os\n"
            "if not os.path.basename(os.path.dirname(jar_arg)).startswith('winsvpn-apksigner-snapshot.'):\n"
            "    raise SystemExit('fake java did not receive the private snapshot')\n"
            "data = open(jar_arg, 'rb').read()\n"
            "open(out, 'wb').write(data)\n",
            encoding="ascii",
        )
        fake_java.chmod(0o700)
        jar.write_bytes(original)
        rc = namespace["run_held_apksigner"](
            str(fake_java),
            str(sdk),
            "build-tools/37.0.0/lib/apksigner.jar",
            expected,
            ["verify", "fixture.apk"],
        )
        self.assertEqual(rc, 0)
        self.assertEqual(output.read_bytes(), original)

    def test_macos_apksigner_descriptor_ignores_post_hold_replacement(self) -> None:
        begin = MAC_SOURCE.index("# WINS_ANDROID_APKSIGNER_HOLD_BEGIN\n")
        begin += len("# WINS_ANDROID_APKSIGNER_HOLD_BEGIN\n")
        end = MAC_SOURCE.index("\n# WINS_ANDROID_APKSIGNER_HOLD_END")
        hold_source = MAC_SOURCE[begin:end]
        namespace: dict = {"__name__": "apksigner_hold_replace"}
        exec(compile(hold_source, "apksigner_hold_replace", "exec"), namespace)
        work = pathlib.Path(
            tempfile.mkdtemp(prefix="wins-apksigner-replace-", dir="/private/tmp")
        )
        self.addCleanup(lambda: shutil.rmtree(work, ignore_errors=True))
        sdk = work / "sdk"
        relative = pathlib.Path("build-tools/37.0.0/lib")
        (sdk / relative).mkdir(parents=True)
        original = b"PK\x03\x04held-apksigner-original\n" + (b"A" * 32)
        hostile = b"EVIL" * 16
        hostile = hostile[: len(original)].ljust(len(original), b"Z")
        self.assertEqual(len(original), len(hostile))
        self.assertNotEqual(original, hostile)
        jar = sdk / relative / "apksigner.jar"
        jar.write_bytes(original)
        expected = hashlib.sha256(original).hexdigest()
        seen: list[bytes] = []

        def fake_run(argv: list[str], **kwargs: object) -> object:
            self.assertEqual(argv[1], "-jar")
            # The JVM cannot load classes from /dev/fd/N on macOS: java gets the
            # private 0o400 snapshot taken from the held descriptor.
            self.assertTrue(pathlib.Path(argv[2]).parent.name.startswith("winsvpn-apksigner-snapshot."))
            self.assertEqual(stat.S_IMODE(os.stat(argv[2]).st_mode), 0o400)
            self.assertEqual(stat.S_IMODE(os.stat(pathlib.Path(argv[2]).parent).st_mode), 0o500)
            with open(argv[2], "rb") as stream:
                seen.append(stream.read())
            completed = type("Completed", (), {"returncode": 0})()
            return completed

        fake_java = work / "java"
        fake_java.write_bytes(b"#!/bin/sh\nexit 0\n")
        fake_java.chmod(0o700)
        jar.write_bytes(original)
        with mock.patch.object(namespace["subprocess"], "run", fake_run):
            rc = namespace["run_held_apksigner"](
                str(fake_java),
                str(sdk),
                "build-tools/37.0.0/lib/apksigner.jar",
                expected,
                ["verify", "fixture.apk"],
            )
        self.assertEqual(rc, 0)
        self.assertEqual(seen, [original])

        def overwrite_then_run(argv: list[str], **kwargs: object) -> object:
            jar.write_bytes(hostile)
            self.assertEqual(jar.read_bytes(), hostile)
            self.assertEqual(argv[1], "-jar")
            self.assertTrue(pathlib.Path(argv[2]).parent.name.startswith("winsvpn-apksigner-snapshot."))
            with open(argv[2], "rb") as stream:
                seen.append(stream.read())
            return type("Completed", (), {"returncode": 0})()

        seen.clear()
        jar.write_bytes(original)
        with mock.patch.object(namespace["subprocess"], "run", overwrite_then_run):
            rc = namespace["run_held_apksigner"](
                str(fake_java),
                str(sdk),
                "build-tools/37.0.0/lib/apksigner.jar",
                expected,
                ["verify", "fixture.apk"],
            )
        self.assertEqual(rc, 0)
        self.assertEqual(seen, [original])
        self.assertEqual(jar.read_bytes(), hostile)
        env = namespace["java_exec_env"]()
        for name in (
            "JAVA_TOOL_OPTIONS",
            "_JAVA_OPTIONS",
            "JDK_JAVA_OPTIONS",
            "CLASSPATH",
            "JAVA_HOME",
            "DYLD_INSERT_LIBRARIES",
        ):
            self.assertNotIn(name, env)

    def test_live_harmless_java_descriptor_probe_on_darwin(self) -> None:
        begin = MAC_SOURCE.index("# WINS_ANDROID_APKSIGNER_HOLD_BEGIN\n")
        begin += len("# WINS_ANDROID_APKSIGNER_HOLD_BEGIN\n")
        end = MAC_SOURCE.index("\n# WINS_ANDROID_APKSIGNER_HOLD_END")
        hold_source = MAC_SOURCE[begin:end]
        namespace: dict = {"__name__": "apksigner_live_probe"}
        exec(compile(hold_source, "apksigner_live_probe", "exec"), namespace)
        work = pathlib.Path(
            tempfile.mkdtemp(prefix="wins-apksigner-live-", dir="/private/tmp")
        )
        self.addCleanup(lambda: shutil.rmtree(work, ignore_errors=True))
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr(
                "META-INF/MANIFEST.MF",
                "Manifest-Version: 1.0\nCreated-By: winsvpn-descriptor-probe\n",
            )
        original = payload.getvalue()
        hostile = b"EVIL-SUBSTITUTED-JAR-BYTES\n"
        self.assertNotEqual(original, hostile)
        sdk = work / "sdk"
        relative = pathlib.Path("build-tools/37.0.0/lib")
        (sdk / relative).mkdir(parents=True)
        jar = sdk / relative / "apksigner.jar"
        jar.write_bytes(original)
        expected = hashlib.sha256(original).hexdigest()
        held = namespace["hold_bytes"](
            str(sdk), "build-tools/37.0.0/lib/apksigner.jar", expected
        )
        fd = namespace["anonymous_held_fd"](held, expected)
        try:
            jar.write_bytes(hostile)
            descriptor = namespace["descriptor_jar_path"](fd)
            with open(descriptor, "rb") as stream:
                self.assertEqual(stream.read(), original)
            self.assertEqual(jar.read_bytes(), hostile)
        finally:
            os.close(fd)
        sealed = (
            pathlib.Path.home()
            / ".local"
            / "toolchains"
            / f"jdk-{TOOLCHAIN_PINS['java']['version']}"
            / "bin"
            / "java"
        )
        if not sealed.is_file() or sealed.is_symlink():
            return
        jar.write_bytes(original)
        fd = namespace["anonymous_held_fd"](original, expected)
        try:
            jar.write_bytes(hostile)
            descriptor = namespace["descriptor_jar_path"](fd)
            completed = subprocess.run(
                [str(sealed), "-jar", descriptor],
                env=namespace["java_exec_env"](),
                pass_fds=(fd,),
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        finally:
            os.close(fd)
        combined = (completed.stdout or "") + (completed.stderr or "")
        self.assertNotRegex(combined, r"(?i)invalid or corrupt jarfile")
        self.assertIn("no main manifest attribute", combined.lower())
        self.assertEqual(jar.read_bytes(), hostile)

    def test_macos_apksigner_hold_fails_closed_on_fifo_toctou_and_specials(self) -> None:
        hold_source = _apksigner_hold_source()
        self.assertIn("O_NONBLOCK", hold_source)
        self.assertIn("_clear_nonblock_if_needed", hold_source)
        self.assertIn("/dev/fd/", hold_source)
        self.assertIn("snapshot_jar", hold_source)  # java -jar gets a private snapshot, not a passed descriptor
        self.assertIn("winsvpn-apksigner-anon.", hold_source)
        namespace = _apksigner_hold_namespace()
        work = pathlib.Path(
            tempfile.mkdtemp(prefix="wins-apksigner-specials-", dir="/private/tmp")
        )
        self.addCleanup(lambda: shutil.rmtree(work, ignore_errors=True))
        sdk = work / "sdk"
        relative = pathlib.Path("build-tools/37.0.0/lib")
        (sdk / relative).mkdir(parents=True)
        jar = sdk / relative / "apksigner.jar"
        original = b"PK\x03\x04held-apksigner-original\n" + (b"A" * 32)
        expected = hashlib.sha256(original).hexdigest()
        fail_closed = (
            r"replaced before it was opened|not a readable regular file|"
            r"must be one regular non-symlink single-link file|"
            r"traverses a symbolic link"
        )

        jar.write_bytes(original)
        clears: list[bool] = []
        real_fcntl = fcntl.fcntl

        def spy_fcntl(fd: int, cmd: int, *args: object):
            if cmd == fcntl.F_SETFL:
                clears.append(stat.S_ISREG(os.fstat(fd).st_mode))
            return real_fcntl(fd, cmd, *args)

        with mock.patch.object(namespace["fcntl"], "fcntl", spy_fcntl):
            held = namespace["hold_bytes"](str(sdk), APKSIGNER_RELATIVE, expected)
        self.assertEqual(held, original)
        self.assertEqual(clears, [True])

        path_s = os.fspath(jar)
        probe = work / "fifo-toctou-probe.py"
        probe.write_text(
            "import os, sys\n"
            f"hold_source = {hold_source!r}\n"
            "ns = {'__name__': 'apk_fifo_toctou'}\n"
            "exec(compile(hold_source, 'hold', 'exec'), ns)\n"
            f"sdk = {str(sdk)!r}\n"
            f"relative = {APKSIGNER_RELATIVE!r}\n"
            f"expected = {expected!r}\n"
            f"path = {path_s!r}\n"
            "import fcntl, stat\n"
            "clears = []\n"
            "real_fcntl = fcntl.fcntl\n"
            "def spy_fcntl(fd, cmd, *args):\n"
            "    if cmd == fcntl.F_SETFL:\n"
            "        clears.append(stat.S_ISREG(os.fstat(fd).st_mode))\n"
            "    return real_fcntl(fd, cmd, *args)\n"
            "ns['fcntl'].fcntl = spy_fcntl\n"
            "real_open = os.open\n"
            "def raced_open(p, flags, *a, **k):\n"
            "    if os.fspath(p) == path:\n"
            "        if not (flags & os.O_NONBLOCK):\n"
            "            raise SystemExit('O_NONBLOCK missing from open flags')\n"
            "        os.unlink(path)\n"
            "        os.mkfifo(path)\n"
            "    return real_open(p, flags, *a, **k)\n"
            "os.open = raced_open\n"
            "try:\n"
            "    ns['hold_bytes'](sdk, relative, expected)\n"
            "except SystemExit as suc:\n"
            "    sys.stderr.write('SETFL_REGULAR=' + repr(clears) + '\\n')\n"
            "    raise suc\n"
            "raise SystemExit('hold_bytes returned after FIFO replace')\n",
            encoding="ascii",
        )
        raced = subprocess.run(
            [sys.executable, "-I", "-S", str(probe)],
            cwd=str(work),
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        combined = (raced.stdout or "") + (raced.stderr or "")
        self.assertNotEqual(raced.returncode, 0, combined)
        self.assertRegex(combined, fail_closed)
        self.assertIn("SETFL_REGULAR=[]", raced.stderr)
        self.assertNotIn("O_NONBLOCK missing from open flags", combined)

        if jar.exists() or jar.is_fifo() or jar.is_symlink():
            jar.unlink()
        os.mkfifo(jar)
        with self.assertRaisesRegex(SystemExit, fail_closed):
            namespace["hold_bytes"](str(sdk), APKSIGNER_RELATIVE, expected)

        if jar.exists() or jar.is_fifo() or jar.is_symlink():
            jar.unlink()
        target = sdk / relative / "apksigner-target.jar"
        target.write_bytes(original)
        jar.symlink_to(target)
        try:
            with self.assertRaisesRegex(SystemExit, fail_closed):
                namespace["hold_bytes"](str(sdk), APKSIGNER_RELATIVE, expected)
        finally:
            if jar.is_symlink() or jar.exists():
                jar.unlink()

        jar.write_bytes(original)
        hard = sdk / relative / "apksigner-hard.jar"
        if hard.exists():
            hard.unlink()
        os.link(jar, hard)
        try:
            with self.assertRaisesRegex(SystemExit, fail_closed):
                namespace["hold_bytes"](str(sdk), APKSIGNER_RELATIVE, expected)
        finally:
            hard.unlink()

        if jar.exists() or jar.is_fifo() or jar.is_symlink():
            jar.unlink()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.bind(str(jar))
            with self.assertRaisesRegex(SystemExit, fail_closed):
                namespace["hold_bytes"](str(sdk), APKSIGNER_RELATIVE, expected)
        finally:
            sock.close()
            if jar.exists():
                jar.unlink()

        jar.write_bytes(original)
        held_again = namespace["hold_bytes"](str(sdk), APKSIGNER_RELATIVE, expected)
        self.assertEqual(held_again, original)
        fd = namespace["anonymous_held_fd"](held_again, expected)
        try:
            descriptor = namespace["descriptor_jar_path"](fd)
            self.assertTrue(descriptor.startswith("/dev/fd/"))
            with open(descriptor, "rb") as stream:
                self.assertEqual(stream.read(), original)
        finally:
            os.close(fd)

    def test_windows_verify_passes_authenticated_jdk_tool_paths(self) -> None:
        self.assertIn("$script:JavaPath = $jdk.Java", SOURCE)
        self.assertIn("$javaPath = $script:JavaPath", SOURCE)
        self.assertIn("'--java', $javaPath", SOURCE)
        self.assertIn("'--jarsigner', $jarsignerPath", SOURCE)
        self.assertIn("'--keytool', $keytoolPath", SOURCE)
        jdk_fn = SOURCE[
            SOURCE.index("function Resolve-ReviewedJdk17") :
            SOURCE.index("function Get-AndroidToolchainRootFromExecutable")
        ]
        self.assertIn("bin\\java.exe", jdk_fn)
        self.assertIn("bin\\jarsigner.exe", jdk_fn)
        self.assertIn("bin\\keytool.exe", jdk_fn)
        self.assertIn("Resolve-TrustedApplication -Name 'java'", jdk_fn)
        self.assertIn("Resolve-TrustedApplication -Name 'jarsigner'", jdk_fn)
        self.assertIn("Resolve-TrustedApplication -Name 'keytool'", jdk_fn)
        self.assertLess(
            SOURCE.index("ANDROID_WINDOWS_CUSTODY_TREES_AUTHENTICATED"),
            SOURCE.index("'--java', $javaPath"),
        )
        phone = SOURCE[
            SOURCE.index("'--verify', 'android-phone-tablet-aab'") :
            SOURCE.index("Android phone/tablet AAB identity inspection failed.")
        ]
        tv = SOURCE[
            SOURCE.index("'--verify', 'android-tv-aab'") :
            SOURCE.index("Android TV AAB identity inspection failed.")
        ]
        phone_apk = SOURCE[
            SOURCE.index("'--verify-apk', 'android-phone-tablet-apk'") :
            SOURCE.index("Android phone/tablet APK identity inspection failed.")
        ]
        tv_apk = SOURCE[
            SOURCE.index("'--verify-apk', 'android-tv-apk'") :
            SOURCE.index("Android TV APK identity inspection failed.")
        ]
        for block in (phone, tv, phone_apk, tv_apk):
            self.assertIn("'--java', $javaPath", block)
            self.assertIn("'--jarsigner', $jarsignerPath", block)
            self.assertIn("'--keytool', $keytoolPath", block)
            self.assertNotIn("'--java', 'java'", block)
            self.assertNotIn("'--jarsigner', 'jarsigner'", block)
            self.assertNotIn("'--keytool', 'keytool'", block)
        self.assertEqual(SOURCE.count("'--java', $javaPath"), 4)
        self.assertEqual(SOURCE.count("'--jarsigner', $jarsignerPath"), 4)
        self.assertEqual(SOURCE.count("'--keytool', $keytoolPath"), 4)

    def test_windows_producer_resolves_jarsigner_and_keytool_as_trusted_applications(
        self,
    ) -> None:
        # jarsigner/keytool used to be existence-checked only (Get-Command
        # with no CommandType/symlink verification), then invoked by bare
        # name -- a function, alias, or symlink on PATH could stand in for
        # either without being caught, unlike flutter's already-hardened
        # resolution above. Both now go through the same shared resolver.
        self.assertIn("function Resolve-TrustedApplication", SOURCE)
        self.assertIn("$command.CommandType -ne 'Application'", SOURCE)
        self.assertIn("$item.LinkType", SOURCE)
        self.assertIn(
            "$jarsigner = Resolve-TrustedApplication -Name 'jarsigner' -CandidatePath",
            SOURCE,
        )
        self.assertIn(
            "$keytool = Resolve-TrustedApplication -Name 'keytool' -CandidatePath",
            SOURCE,
        )
        self.assertIn("$script:JarsignerPath = $jdk.Jarsigner", SOURCE)
        self.assertIn("$script:KeytoolPath = $jdk.Keytool", SOURCE)
        # The resolved paths must be what's actually invoked, not just
        # checked once and then ignored -- the same TOCTOU-style gap
        # already closed for flutter.
        self.assertNotIn("& jarsigner ", SOURCE)
        self.assertNotIn("& keytool ", SOURCE)
        self.assertIn("& $jarsignerPath -verify", SOURCE)
        self.assertIn("& $keytoolPath -printcert", SOURCE)
        self.assertIn("& $keytoolPath -list -v", SOURCE)

    def test_windows_signing_state_rejects_hardlink_aliases(self) -> None:
        identity = SOURCE[
            SOURCE.index("if (-not ('WinsVpn.ReleaseFileIdentity' -as [type]))") :
            SOURCE.index("function Resolve-ExternalSigningFile")
        ]
        self.assertIn("GetFileInformationByHandle", identity)
        self.assertIn("NumberOfLinks = information.NumberOfLinks", identity)
        self.assertIn("function Assert-SingleLinkFile", identity)
        self.assertIn("$before.NumberOfLinks -ne 1", identity)
        self.assertIn("Assert-SingleLinkFile -Path $item.FullName", identity)

        signing = SOURCE[
            SOURCE.index("function Import-AndroidSigningEnvironment") :
            SOURCE.index("function Clear-AndroidSigningEnvironment")
        ]
        self.assertEqual(signing.count("Assert-OwnerOnlyFile -Path"), 3)

    @unittest.skipUnless(sys.platform == "win32", "Windows hardlink test")
    def test_windows_file_identity_rejects_a_real_hardlink(self) -> None:
        shell = powershell_executable()
        self.assertIsNotNone(shell)
        functions = SOURCE[
            SOURCE.index("if (-not ('WinsVpn.ReleaseFileIdentity' -as [type]))") :
            SOURCE.index("function Resolve-ExternalSigningFile")
        ]
        with tempfile.TemporaryDirectory() as temporary:
            original = pathlib.Path(temporary) / "android-release.keystore"
            alias = pathlib.Path(temporary) / "android-release-alias.keystore"
            original.write_bytes(b"test-only-keystore")
            os.link(original, alias)
            environment = os.environ.copy()
            environment["WINS_TEST_HARDLINK"] = str(original)
            command = (
                "$ErrorActionPreference = 'Stop'\n"
                + functions
                + "\ntry { Assert-SingleLinkFile -Path $env:WINS_TEST_HARDLINK "
                "-Description 'test keystore'; exit 9 } "
                "catch { if ($_.Exception.Message -notmatch 'single-link file') "
                "{ Write-Error $_; exit 8 }; Write-Output 'HARDLINK_REJECTED' }\n"
            )
            completed = subprocess.run(
                [shell, "-NoProfile", "-NonInteractive", "-Command", command],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        self.assertEqual(
            completed.returncode, 0, completed.stdout + completed.stderr
        )
        self.assertIn("HARDLINK_REJECTED", completed.stdout)

    def test_real_windows_child_validates_upload_signer_before_build_mutation(self) -> None:
        child = SOURCE.index("Assert-NeutralStageRuntime -StageRepo $RepoRoot")
        import_signing = SOURCE.index("Import-AndroidSigningEnvironment", child)
        preflight_signer = SOURCE.index("Assert-ExpectedAndroidSigner", import_signing)
        delete_symbols = SOURCE.index("foreach ($directory in @($ApkSymbols", import_signing)
        pub_get = SOURCE.index("'pub', 'get', '--enforce-lockfile'", import_signing)
        build_apk = SOURCE.index("'build', 'apk', '--release'", import_signing)
        self.assertLess(import_signing, preflight_signer)
        self.assertLess(preflight_signer, delete_symbols)
        self.assertLess(preflight_signer, pub_get)
        self.assertLess(preflight_signer, build_apk)

    def test_macos_normalizes_and_exports_one_android_sdk_root(self) -> None:
        sdk_assignment = MAC_SOURCE.index('ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-')
        home_assignment = MAC_SOURCE.index('ANDROID_HOME="${ANDROID_SDK_ROOT}"')
        sdk_export = MAC_SOURCE.index("export ANDROID_SDK_ROOT ANDROID_HOME")
        first_flutter = MAC_SOURCE.index("wins_release_android_flutter --version --machine")
        self.assertLess(sdk_assignment, home_assignment)
        self.assertLess(home_assignment, sdk_export)
        self.assertLess(sdk_export, first_flutter)

    def test_macos_producer_uses_bsd_portable_file_commands(self) -> None:
        # macOS chmod/cp/mv do not consistently implement GNU's standalone
        # `--` operand separator. Every path here is producer-controlled and
        # absolute, so omitting it is both safe and portable on the declared
        # build host.
        for command in ("chmod", "cp", "mv", "rm"):
            self.assertNotRegex(MAC_SOURCE, rf"(?m)^\s*{command}\b[^\n]*\s--(?:\s|$)")

    def test_both_producers_use_one_recoverable_multi_output_transaction(self) -> None:
        for source in (SOURCE, MAC_SOURCE):
            with self.subTest(producer="powershell" if source is SOURCE else "macos"):
                for marker in (
                    "android_release_publication.py",
                    "android-release-publication.state.json",
                    "recover",
                    "commit",
                    "--pair",
                    "finalize",
                ):
                    self.assertIn(marker, source)
        self.assertIn("'rollback', '--state', $PublicationState", SOURCE)
        self.assertIn('PUBLICATION_ACTIVE=1', MAC_SOURCE)
        self.assertGreaterEqual(MAC_SOURCE.count('  --pair "${PREPARED_'), 8)
        self.assertGreaterEqual(SOURCE.count("@($preparedTvApk, $destinationTvApk)"), 1)
        self.assertGreaterEqual(SOURCE.count("@($preparedTvAab, $destinationTvAab)"), 1)

    def test_tv_aab_has_an_independent_formal_receipt_lifecycle(self) -> None:
        for source in (SOURCE, MAC_SOURCE):
            with self.subTest(producer="powershell" if source is SOURCE else "macos"):
                for marker in (
                    "ANDROID_TV_AAB_BUILD_BEGIN.json",
                    "ANDROID_TV_AAB_BUILD_RECEIPT.json",
                    "ANDROID_TV_APK_BUILD_BEGIN.json",
                    "ANDROID_TV_APK_BUILD_RECEIPT.json",
                    "android-tv-release-aab",
                    "android-tv-release-apk",
                    "app-tv-release.aab",
                    "app-tv-release.apk",
                ):
                    self.assertIn(marker, source)
        for marker in (
            "TvAabBegin",
            "TvAabReceipt",
            "TvApkBegin",
            "TvApkReceipt",
            "-ArtifactPath $TvAabPath",
            "-ArtifactPath $PublishedTvApkPath",
            "-Target 'android-tv-release-aab'",
            "-Target 'android-tv-release-apk'",
            "TvAabBytes",
            "TvAabSha256",
            "TvApkBytes",
            "TvApkSha256",
            "TvAabBuildReceiptSha256",
            "TvApkBuildReceiptSha256",
        ):
            self.assertIn(marker, SOURCE)
        for marker in (
            'finish_receipt "${TV_AAB_BEGIN}" "${ROOT_TV_AAB}" android-tv-release-aab "${TV_AAB_RECEIPT}"',
            'finish_receipt "${TV_APK_BEGIN}" "${ROOT_TV_APK}" android-tv-release-apk "${TV_APK_RECEIPT}"',
            "TV AAB: %s bytes=%s sha256=%s",
        ):
            self.assertIn(marker, MAC_SOURCE)

    def test_tv_aab_is_built_not_relabelled_from_phone_tablet(self) -> None:
        for source in (SOURCE, MAC_SOURCE):
            with self.subTest(producer="powershell" if source is SOURCE else "macos"):
                for marker in (
                    "org.winsvpn.app",
                    "exactly reuses the phone/tablet AAB bytes",
                    "WINS_BUNDLETOOL_JAR",
                    "current bytes changed during identity inspection",
                ):
                    self.assertIn(marker, source)
                self.assertNotIn("org.winsvpn.app.tv", source)
                self.assertNotIn("apkanalyzer", source)
                self.assertNotIn("manifest application-id", source)
                self.assertNotIn("manifest version-code", source)
                self.assertNotIn("manifest print", source)
        self.assertIn("--verify android-phone-tablet-aab", MAC_SOURCE)
        self.assertIn("--verify android-tv-aab", MAC_SOURCE)
        self.assertIn("'--verify', 'android-phone-tablet-aab'", SOURCE)
        self.assertIn("'--verify', 'android-tv-aab'", SOURCE)
        self.assertIn("cmp -s \"${STAGE_AAB}\" \"${STAGE_TV_AAB}\"", MAC_SOURCE)
        self.assertIn("Get-FileHash -Algorithm SHA256 -LiteralPath $TvAabPath", SOURCE)
        inspector = (ROOT / "tools/verify_android_aab_signers.py").read_text(encoding="utf-8")
        for marker in (
            "android.software.leanback",
            "android.hardware.touchscreen",
            "android.intent.category.LEANBACK_LAUNCHER",
            "@drawable/banner",
            "closed-format",
            "1.18.3",
        ):
            self.assertIn(marker, inspector)
        self.assertIn('BUILD_NUMBER="${VERSION_IDENTITY##*+}"', MAC_SOURCE)
        self.assertNotIn("Copy-Item -LiteralPath $AabPath -Destination $TvAabPath", SOURCE)
        self.assertNotIn('cp "${STAGE_AAB}" "${STAGE_TV_AAB}"', MAC_SOURCE)
        self.assertNotIn(
            'finish_receipt "${AAB_BEGIN}" "${ROOT_AAB}" android-tv-release-aab',
            MAC_SOURCE,
        )
        self.assertNotIn(
            'finish_receipt "${TV_AAB_BEGIN}" "${ROOT_AAB}"', MAC_SOURCE
        )

    def test_tv_aab_is_release_signed_obfuscated_and_has_private_symbols(self) -> None:
        for marker in (
            "'build', 'appbundle', '--release', '--flavor', 'tv', '--obfuscate'",
            "'build', 'apk', '--release', '--flavor', 'tv', '--obfuscate'",
            '"--split-debug-info=$TvAabSymbols"',
            '"--split-debug-info=$TvApkSymbols"',
            "$TvR8MappingPath",
            "$TvNativeDebugSymbolsPath",
            "$TvAabManifest",
            "$TvApkManifest",
            "'--verify', 'android-tv-aab'",
            "'--verify-apk', 'android-tv-apk'",
            "& $jarsignerPath -verify $TvAabPath",
            "& $keytoolPath -printcert -jarfile $TvAabPath",
            "$tvAabCertDigest",
            "$tvApkCertDigest",
            "Android TV AAB private-symbol custody verification failed.",
            "Android TV APK private-symbol custody verification failed.",
        ):
            self.assertIn(marker, SOURCE)
        for marker in (
            'build appbundle --no-pub --release --flavor tv --obfuscate --split-debug-info="${STAGE_TV_AAB_SYMBOLS}"',
            '"${STAGE_TV_MAPPING}" "${STAGE_TV_AAB_SYMBOLS}/proguard-mapping.txt"',
            '"${STAGE_TV_NATIVE_SYMBOLS}" "${STAGE_TV_AAB_SYMBOLS}/native-debug-symbols.zip"',
            "--verify android-tv-aab",
            "--verify-apk android-tv-apk",
            "--bind-r8 android-tv-aab",
            'wins_release_android_jdk_tool jarsigner -verify "${STAGE_TV_AAB}"',
            'wins_release_android_jdk_tool keytool -printcert -jarfile "${STAGE_TV_AAB}"',
            "TV_AAB_DIGEST",
        ):
            self.assertIn(marker, MAC_SOURCE)

    def test_windows_neutral_stage_contains_tv_aab_verification_tools(self) -> None:
        for marker in (
            "'tools/verify_standalone_v3_artifact.py'",
            "'tools/verify_winn3_ring_artifact.py'",
            "'tools/winn3_descriptor_ring_identity.py'",
            "'tools/toolchain-pins.json'",
            "Join-Path $RepoRoot 'tools/winn3_descriptor_ring_identity.py'",
            "Join-Path $RepoRoot 'tools/verify_standalone_v3_artifact.py'",
            "Join-Path $RepoRoot 'tools/verify_winn3_ring_artifact.py'",
        ):
            self.assertIn(marker, SOURCE)
        self.assertNotIn("Join-Path $Root 'tools/", SOURCE)
        self.assertIn("'tools/toolchain-pins.json'", _neutral_input_files_assignment())

    def test_neutral_stages_carry_the_winn_release_authority(self) -> None:
        # android/app/build.gradle.kts verifyWinnReleaseStamp reads
        # ../tools/winn_release_authority.json; a stage without it refuses every
        # engine stamp as an invalid release authority file.
        gradle = (ROOT / "android/app/build.gradle.kts").read_text(encoding="utf-8")
        self.assertIn('rootProject.file("../tools/winn_release_authority.json")', gradle)
        self.assertIn("'tools/winn_release_authority.json'", _neutral_input_files_assignment())
        start = MAC_SOURCE.index("files = [\n    '.metadata'")
        end = MAC_SOURCE.index("\n]\n", start)
        self.assertIn("'tools/winn_release_authority.json'", MAC_SOURCE[start:end])

    def test_neutral_stages_carry_every_module_level_sibling_import(self) -> None:
        # A staged tool that imports a sibling tools/ module at module level
        # dies with ModuleNotFoundError in the stage unless that module is
        # staged too (release_obfuscation_contract.py and
        # validate_release_artifact_privacy.py import the secret scan policy
        # and the secret inventory).
        import ast
        import re

        start = MAC_SOURCE.index("files = [\n    '.metadata'")
        mac = set(re.findall(r"'(tools/[^']+)'", MAC_SOURCE[start:MAC_SOURCE.index("\n]\n", start)]))
        windows = set(re.findall(r"'(tools/[^']+)'", _neutral_input_files_assignment()))
        for label, staged in (("macOS", mac), ("Windows", windows)):
            for relative in sorted(item for item in staged if item.endswith(".py")):
                tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                        node.body = []
                imported = set()
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        imported |= {alias.name.split(".")[0] for alias in node.names}
                    elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                        imported.add(node.module.split(".")[0])
                for module in sorted(imported):
                    sibling = f"tools/{module}.py"
                    if (ROOT / sibling).is_file():
                        self.assertIn(sibling, staged, f"{label} stage: {relative} imports {sibling}")

    def test_mac_stage_carries_every_file_the_obfuscation_static_contract_reads(self) -> None:
        # record and verify run release_obfuscation_contract.py inside the
        # neutral stage, and both call validate_static, which reads these
        # repository paths relative to the staged root.
        import re

        contract = (ROOT / "tools/release_obfuscation_contract.py").read_text(encoding="utf-8")
        start = contract.index("def validate_static() -> None:")
        body = contract[start:contract.index("\ndef ", start + 10)]
        read = set(re.findall(r'^\s{8}"([A-Za-z0-9_./-]+)": \(', body, flags=re.M))
        read |= set(re.findall(r'ROOT / "([^"]+)"', body))
        # Paths read through a variable (for example a tuple of Gradle files).
        read |= {
            literal
            for literal in re.findall(r'"([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+)"', body)
            if (ROOT / literal).exists()
        }
        self.assertIn("extension/src", read)
        files_start = MAC_SOURCE.index("files = [\n    '.metadata'")
        staged = set(re.findall(r"'([^']+)'", MAC_SOURCE[files_start:MAC_SOURCE.index("\n]\n", files_start)]))
        directories = re.search(r"for directory in \(([^)]*)\):", MAC_SOURCE).group(1)
        staged_dirs = set(re.findall(r"'([^']+)'", directories))
        for relative in sorted(read):
            covered = relative in staged or any(
                relative == root or relative.startswith(root + "/") for root in staged_dirs
            )
            self.assertTrue(covered, f"macOS stage lacks {relative}")

    def test_gradle_wrapper_distribution_is_content_pinned(self) -> None:
        for properties in (WRAPPER_PROPERTIES, DEVICECHECK_WRAPPER_PROPERTIES):
            self.assertIn(
                f"distributionUrl=https\\://services.gradle.org/distributions/gradle-{EXPECTED_GRADLE_VERSION}-all.zip",
                properties,
            )
            self.assertIn(
                f"distributionSha256Sum={EXPECTED_GRADLE_ZIP_SHA256}",
                properties,
            )

    def test_android_wrapper_bootstraps_are_official_and_checkout_complete(self) -> None:
        ignored = (ROOT / "android/.gitignore").read_text(encoding="utf-8")
        self.assertNotRegex(ignored, r"(?m)^gradle-wrapper\.jar$")
        self.assertNotRegex(ignored, r"(?m)^/gradlew(?:\.bat)?$")
        for relative in (
            "android/gradle/wrapper/gradle-wrapper.jar",
            "android/devicecheck/gradle/wrapper/gradle-wrapper.jar",
        ):
            digest = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            self.assertEqual(digest, EXPECTED_WRAPPER_JAR_SHA256, relative)

    def test_agp_aapt2_verification_covers_all_release_hosts(self) -> None:
        agp = EXPECTED_AGP_VERSION
        tools = _android_tools_version(agp)
        self.assertRegex(agp, r"^\d+\.\d+\.\d+$")
        stale_agp = _stale_series_pattern(agp)
        stale_tools = _stale_series_pattern(tools)
        major, minor, patch = agp.split(".")
        other_agp = f"{major}.{minor}.{int(patch) + 1}"
        other_tools = _android_tools_version(other_agp)
        self.assertIsNotNone(stale_agp.search(f"aapt2-{other_agp}-1-linux.jar"))
        self.assertIsNone(stale_agp.search(f"aapt2-{agp}-1-linux.jar"))
        self.assertIsNotNone(stale_tools.search(f"annotations-{other_tools}.jar"))
        self.assertIsNone(stale_tools.search(f"annotations-{tools}.jar"))
        if int(patch) > 0:
            previous_agp = f"{major}.{minor}.{int(patch) - 1}"
            previous_tools = _android_tools_version(previous_agp)
            self.assertIsNotNone(
                stale_agp.search(f"aapt2-{previous_agp}-1-linux.jar")
            )
            self.assertIsNotNone(
                stale_tools.search(f"annotations-{previous_tools}.jar")
            )

        self.assertGreaterEqual(len(ANDROID_LOCKFILES), 3)
        build_ids: set[str] | None = None
        for lock_path in ANDROID_LOCKFILES:
            lock_text = lock_path.read_text(encoding="utf-8")
            relative = lock_path.relative_to(ROOT).as_posix()
            stale = stale_agp.search(lock_text) or stale_tools.search(lock_text)
            self.assertIsNone(
                stale,
                f"{relative} still carries stale AGP/tools train "
                f"{stale.group(0) if stale else ''}",
            )
            found = _aapt2_proto_build_ids(lock_text, agp)
            self.assertEqual(
                len(found),
                1,
                f"{relative} must lock exactly one aapt2-proto build for AGP {agp}",
            )
            if build_ids is None:
                build_ids = found
            else:
                self.assertEqual(
                    found,
                    build_ids,
                    f"{relative} aapt2-proto build drifted from the other lockfiles",
                )

        self.assertIsNotNone(build_ids)
        build_id = next(iter(build_ids or ()))
        metadata = ANDROID_VERIFICATION_METADATA.read_text(encoding="utf-8")
        stale = stale_agp.search(metadata) or stale_tools.search(metadata)
        self.assertIsNone(
            stale,
            "android/gradle/verification-metadata.xml still carries stale "
            f"AGP/tools train {stale.group(0) if stale else ''}",
        )
        # Host coverage is name-only. Hashes in this file are Gradle-written
        # and must not authenticate the same artifacts they describe.
        for host in AAPT2_RELEASE_HOSTS:
            self.assertIn(f"aapt2-{agp}-{build_id}-{host}.jar", metadata)

    def test_release_build_requires_an_immutable_release_input_index(self) -> None:
        self.assertIn("[string]$ReleaseInputIndex = ''", SOURCE)
        self.assertIn(
            "ReleaseInputIndex is required for every Android release build.",
            SOURCE,
        )
        self.assertIn("'RELEASE_INPUT_INDEX.json'", SOURCE)
        self.assertIn("'verify-index'", SOURCE)
        self.assertIn("Enter-ReleaseBuildLock", SOURCE)
        self.assertLess(
            SOURCE.index("Enter-ReleaseBuildLock", SOURCE.index("if (-not $InNeutralStage)")),
            SOURCE.index("Initialize-FormalBuildReceipts", SOURCE.index("if (-not $InNeutralStage)")),
        )

    def test_apk_and_aab_have_distinct_formal_receipt_lifecycles(self) -> None:
        for marker in (
            "ANDROID_APK_BUILD_BEGIN.json",
            "ANDROID_AAB_BUILD_BEGIN.json",
            "ANDROID_APK_BUILD_RECEIPT.json",
            "ANDROID_AAB_BUILD_RECEIPT.json",
            "-BeginPath $formalReceipts.ApkBegin",
            "-ArtifactPath $PublishedApkPath",
            "-Target 'android-release-apk'",
            "-OutputPath $formalReceipts.ApkReceipt",
            "-BeginPath $formalReceipts.AabBegin",
            "-ArtifactPath $PublishedAabPath",
            "-Target 'android-release-aab'",
            "-OutputPath $formalReceipts.AabReceipt",
            "'finish-build'",
            "'verify-receipt'",
        ):
            self.assertIn(marker, SOURCE)
        self.assertNotIn(
            "-BeginPath $formalReceipts.ApkBegin `\n            -ArtifactPath $ApkPath",
            SOURCE,
        )
        self.assertNotIn(
            "-BeginPath $formalReceipts.AabBegin `\n            -ArtifactPath $AabPath",
            SOURCE,
        )
        outer_result = SOURCE[SOURCE.index("if (-not $InNeutralStage) {") : SOURCE.index("exit 0", SOURCE.index("if (-not $InNeutralStage) {"))]
        for marker in (
            "Apk = $PublishedApkPath",
            "Get-Item -LiteralPath $PublishedApkPath",
            "Get-FileHash -Algorithm SHA256 -LiteralPath $PublishedApkPath",
            "Aab = $PublishedAabPath",
            "Get-Item -LiteralPath $PublishedAabPath",
            "Get-FileHash -Algorithm SHA256 -LiteralPath $PublishedAabPath",
        ):
            self.assertIn(marker, outer_result)
        self.assertNotEqual(
            SOURCE.index("ANDROID_APK_BUILD_BEGIN.json"),
            SOURCE.index("ANDROID_AAB_BUILD_BEGIN.json"),
        )

    def test_neutral_child_cannot_forge_or_emit_formal_receipts(self) -> None:
        self.assertIn(
            "The neutral child build cannot create formal receipts; only the serialized outer producer owns them.",
            SOURCE,
        )
        child_invocation = SOURCE.index("-InNeutralStage -SigningStorePath")
        next_failure = SOURCE.index("The isolated neutral Android release build failed.", child_invocation)
        child_block = SOURCE[child_invocation:next_failure]
        self.assertNotIn("ReleaseInputIndex", child_block)
        self.assertNotIn("BuildReceiptDirectory", child_block)

    def test_apk_signer_lookup_uses_numeric_version_sort(self) -> None:
        # A plain string/path sort ranks "9.0" above "34.0" and would silently
        # select a stale build-tools version whenever more than one is installed
        # side by side. Get-ApkSigner sorts by numeric Version, newest first.
        signer = SOURCE[
            SOURCE.index("function Get-ApkSigner") : SOURCE.index("function Get-ZipAlign")
        ]
        self.assertIn("Sort-Object Version -Descending", signer)
        self.assertIn("[version]$_.Name", signer)
        self.assertNotIn("Sort-Object FullName", signer)

    def test_producers_inspect_held_aab_bytes_without_apkanalyzer(self) -> None:
        for source in (SOURCE, MAC_SOURCE):
            with self.subTest(producer="powershell" if source is SOURCE else "macos"):
                self.assertNotIn("apkanalyzer", source)
                self.assertNotIn("Get-ApkAnalyzer", source)
                self.assertIn("WINS_BUNDLETOOL_JAR", source)
                self.assertIn("1.18.3", source)
                self.assertIn(
                    "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29",
                    source,
                )
                self.assertIn("current bytes changed during identity inspection", source)
        self.assertIn("--verify android-phone-tablet-aab", MAC_SOURCE)
        self.assertIn("--verify android-tv-aab", MAC_SOURCE)
        self.assertIn("'--verify', 'android-phone-tablet-aab'", SOURCE)
        self.assertIn("'--verify', 'android-tv-aab'", SOURCE)
        self.assertIn(
            "bundletool-all-$BundletoolVersion.jar SHA-256 does not match the reviewed pin",
            SOURCE,
        )
        self.assertIn(
            'bundletool-all-${BUNDLETOOL_VERSION}.jar SHA-256 does not match the reviewed pin',
            MAC_SOURCE,
        )

    @unittest.skipUnless(sys.platform == "win32", "PowerShell ACL self-test is Windows-only")
    def test_neutral_staging_runtime_self_test(self) -> None:
        pwsh = shutil.which("pwsh")
        self.assertIsNotNone(pwsh)
        stage_base = pathlib.Path("C:/WVPAndroidRelease")
        before = {entry.name for entry in stage_base.iterdir()} if stage_base.exists() else set()
        completed = subprocess.run(
            [pwsh, "-NoProfile", "-File", str(SCRIPT_PATH), "-SelfTestNeutralStaging"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("ANDROID NEUTRAL STAGING SELF-TEST: PASS", completed.stdout)
        after = {entry.name for entry in stage_base.iterdir()} if stage_base.exists() else set()
        self.assertEqual(before, after, "neutral-stage self-test left a staging directory")

    @unittest.skipUnless(sys.platform == "win32", "PowerShell staged-mode test is Windows-only")
    def test_internal_staged_mode_rejects_the_user_home_checkout(self) -> None:
        pwsh = shutil.which("pwsh")
        self.assertIsNotNone(pwsh)
        completed = subprocess.run(
            [pwsh, "-NoProfile", "-File", str(SCRIPT_PATH), "-InNeutralStage"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("requires the producer-owned neutral path", completed.stderr)

    def test_windows_custody_preflight_runs_before_any_candidate_execution(self) -> None:
        helper = (ROOT / "tools" / "android_toolchain_custody.ps1").read_text(
            encoding="utf-8"
        )
        signing = SOURCE[
            SOURCE.index("if ($SelfTestSigningStore)") :
            SOURCE.index("ANDROID RELEASE SIGNING STORE SELF-TEST: PASS")
        ]
        python_resolve = SOURCE.index("$script:PythonPath = Resolve-ReviewedPython")
        main_preflight = SOURCE.rindex(
            "# ANDROID_WINDOWS_CUSTODY_PREFLIGHT_BEGIN", 0, python_resolve
        )
        jdk_resolve = SOURCE.index("$jdk = Resolve-ReviewedJdk17", python_resolve)
        trees = SOURCE.index(
            "# ANDROID_WINDOWS_CUSTODY_TREES_AUTHENTICATED", python_resolve
        )
        identity = SOURCE.index(
            "# ANDROID_WINDOWS_CUSTODY_RUNTIME_IDENTITY_AFTER_TREES", trees
        )
        runtime_confirm = SOURCE.index(
            "Confirm-ReviewedAndroidToolchainRuntimePins", identity
        )
        apk_signer = SOURCE.index("$apkSigner = Get-ApkSigner", identity)
        self.assertLess(main_preflight, python_resolve)
        self.assertLess(main_preflight, jdk_resolve)
        self.assertLess(python_resolve, trees)
        self.assertLess(jdk_resolve, trees)
        self.assertLess(trees, identity)
        self.assertLess(identity, runtime_confirm)
        self.assertLess(identity, apk_signer)
        self.assertIn("Assert-ReviewedAndroidToolchainCustodyPreflight", signing)
        self.assertLess(
            signing.index("Assert-ReviewedAndroidToolchainCustodyPreflight"),
            signing.index("Resolve-ReviewedJdk17"),
        )
        self.assertLess(
            signing.index("ANDROID_WINDOWS_CUSTODY_PREFLIGHT_END"),
            signing.index("Assert-WinsAndroidToolchainCustody"),
        )
        self.assertLess(
            signing.index("Assert-WinsAndroidToolchainRuntimePins"),
            signing.index("Assert-ExpectedAndroidSigner"),
        )
        self.assertLess(
            signing.index("Assert-WinsAndroidToolchainRuntimePins"),
            signing.index("gradlew.bat"),
        )
        python_fn = SOURCE[
            SOURCE.index("function Resolve-ReviewedPython") :
            SOURCE.index("function Resolve-ReviewedFlutter")
        ]
        jdk_fn = SOURCE[
            SOURCE.index("function Resolve-ReviewedJdk17") :
            SOURCE.index("function Get-AndroidToolchainRootFromExecutable")
        ]
        self.assertNotIn("& $resolved", python_fn)
        self.assertNotIn("import platform,sys", python_fn)
        self.assertNotIn("& $java -version", jdk_fn)
        self.assertNotIn("-XshowSettings:properties", jdk_fn)
        self.assertIn("ANDROID_WINDOWS_CUSTODY_PREFLIGHT_NO_CANDIDATE_EXECUTION", helper)
        self.assertIn(
            "ANDROID_WINDOWS_CUSTODY_TREE_AUTHENTICATED_BEFORE_RUNTIME_IDENTITY",
            helper,
        )
        self.assertLess(
            helper.index("Get-WinsAndroidToolchainTreeSha256"),
            helper.index(
                "ANDROID_WINDOWS_CUSTODY_TREE_AUTHENTICATED_BEFORE_RUNTIME_IDENTITY"
            ),
        )
        hash_fn = helper[
            helper.index("function Assert-WinsAndroidToolchainCustody {") :
        ]
        self.assertIn(
            "ANDROID_WINDOWS_CUSTODY_TREE_AUTHENTICATED_BEFORE_RUNTIME_IDENTITY",
            hash_fn,
        )
        self.assertNotIn("Assert-WinsAndroidToolchainRuntimePins", hash_fn)
        self.assertNotIn("python.exe", hash_fn)
        self.assertNotIn("java.exe", hash_fn)
        self.assertNotIn("flutter.bat", hash_fn)
        self.assertNotIn("keytool", hash_fn)
        self.assertNotIn("gradlew", hash_fn)
        self.assertIn("& $flutterItem.FullName --version --machine", SOURCE)
        self.assertEqual(SOURCE.count("$flutterItem.FullName"), 6)

    def test_windows_owner_inputs_required_is_not_weakened(self) -> None:
        manifest = json.loads(
            (ROOT / "tools" / "android-toolchain-custody.json").read_text(
                encoding="utf-8"
            )
        )
        windows = manifest["platforms"]["windows_amd64"]
        self.assertEqual(windows["status"], "owner_inputs_required")
        self.assertTrue(windows["owner_action"])
        required_fields = (
            "archive_environment",
            "archive_sha256",
            "install_tree_sha256",
            "version",
            "vendor",
            "architecture",
            "revision",
        )
        action = windows["owner_action"]
        for field in required_fields:
            self.assertIn(field, action)
        for marker in (
            "frameworkVersion",
            "frameworkRevision",
            "repositoryUrl",
            "CPython",
            "windows_amd64 archive_sha256 plus install_tree_sha256",
            "does not emit architecture",
        ):
            self.assertIn(marker, action)
        self.assertNotIn("flutterGitUrl", action)
        self.assertNotIn("dartTargetArch", action)
        for tool in ("python", "flutter", "jdk"):
            record = windows["tools"][tool]
            for field in required_fields:
                self.assertIn(field, record)
            self.assertIsNone(record["archive_sha256"])
            self.assertIsNone(record["install_tree_sha256"])
            self.assertIsNone(record["version"])
            self.assertIsNone(record["vendor"])
            self.assertIsNone(record["architecture"])
            self.assertIsNone(record["revision"])
        flutter = windows["tools"]["flutter"]
        self.assertIn("frameworkVersion", flutter["version_source"])
        self.assertIn("frameworkRevision", flutter["revision_source"])
        self.assertEqual(
            flutter["vendor_source"],
            "flutter --version --machine repositoryUrl",
        )
        self.assertIn("has no architecture field", flutter["architecture_source"])
        helper = (ROOT / "tools" / "android_toolchain_custody.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("owner_inputs_required", json.dumps(manifest))
        self.assertIn("$platformRecord.status -cne 'pinned'", helper)
        self.assertIn("OWNER INPUT REQUIRED", helper)
        self.assertNotRegex(
            helper,
            r"status\s+-eq\s+'owner_inputs_required'\s*\)\s*\{\s*return",
        )
        self.assertIn("Assert-ReviewedAndroidToolchainCustodyPreflight", SOURCE)
        self.assertNotIn("dartTargetArch", SOURCE)
        self.assertNotIn("dartPlatform", SOURCE)
        self.assertNotIn("flutterGitUrl", SOURCE)
        self.assertIn("FLUTTER_ARCHITECTURE_BINDING_RULE", SOURCE)
        self.assertIn("PinArchitecture", SOURCE)

    def test_windows_custody_helper_does_not_execute_candidates_when_incomplete_or_mismatched(
        self,
    ) -> None:
        shell = powershell_executable()
        if shell is None:
            self.skipTest("PowerShell is unavailable")
        helper = ROOT / "tools" / "android_toolchain_custody.ps1"
        with tempfile.TemporaryDirectory() as temp_name:
            temp = pathlib.Path(temp_name)
            marker = temp / "candidate-executed.marker"
            sentinel = temp / "sentinel.py"
            sentinel.write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
                encoding="utf-8",
            )
            archive = temp / "python-archive.bin"
            archive.write_bytes(b"archive-bytes")
            tree = temp / "python-tree"
            tree.mkdir()
            (tree / "python.exe").write_bytes(b"not-an-executable")
            archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
            wrong_tree_sha = "ab" * 32
            other_sha = "cd" * 32
            other_tree = "ef" * 32
            pinned = {
                "schema_version": 1,
                "contract": "winsvpn-android-toolchain-custody-v1",
                "platforms": {
                    "windows_amd64": {
                        "status": "pinned",
                        "owner_action": "unused",
                        "tools": {
                            "python": {
                                "version": "3.14.7",
                                "revision": "",
                                "vendor": "CPython",
                                "architecture": "AMD64",
                                "archive_environment": "WINS_ANDROID_PYTHON_ARCHIVE",
                                "archive_sha256": archive_sha,
                                "install_tree_sha256": wrong_tree_sha,
                            },
                            "flutter": {
                                "version": "3.47.6",
                                "revision": "a" * 40,
                                "vendor": "flutter",
                                "architecture": "x64",
                                "archive_environment": "WINS_ANDROID_FLUTTER_ARCHIVE",
                                "archive_sha256": other_sha,
                                "install_tree_sha256": other_tree,
                            },
                            "jdk": {
                                "version": "17.0.20",
                                "revision": "17.0.20+1",
                                "vendor": "Eclipse Adoptium",
                                "architecture": "amd64",
                                "archive_environment": "WINS_ANDROID_JDK_ARCHIVE",
                                "archive_sha256": "11" * 32,
                                "install_tree_sha256": "22" * 32,
                            },
                        },
                    }
                },
            }
            pinned_path = temp / "pinned.json"
            pinned_path.write_text(json.dumps(pinned), encoding="utf-8")
            incomplete = json.loads(json.dumps(pinned))
            del incomplete["platforms"]["windows_amd64"]["tools"]["python"]["vendor"]
            incomplete_path = temp / "incomplete.json"
            incomplete_path.write_text(json.dumps(incomplete), encoding="utf-8")
            owner_path = ROOT / "tools" / "android-toolchain-custody.json"
            script = f"""
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
function Assert-NoReparsePath {{ param($Path, $Description) }}
function Assert-SingleLinkFile {{ param($Path, $Description) }}
function Get-WinsFileIdentityFromStream {{
    param($Stream)
    [pscustomobject]@{{
        VolumeSerialNumber = 1
        FileIndexHigh = 0
        FileIndexLow = 1
        NumberOfLinks = 1
        FileSize = [uint64]$Stream.Length
        LastWriteFileTime = 1
    }}
}}
. '{helper}'
$marker = '{marker}'
try {{
    Assert-WinsAndroidToolchainCustodyManifestPreflight -ManifestPath '{owner_path}' -Platform 'windows_amd64'
    throw 'owner-inputs preflight unexpectedly succeeded'
}} catch {{
    if ($_.Exception.Message -notmatch 'OWNER INPUT REQUIRED') {{ throw }}
}}
try {{
    Assert-WinsAndroidToolchainCustodyManifestPreflight -ManifestPath '{incomplete_path}' -Platform 'windows_amd64'
    throw 'incomplete-pin preflight unexpectedly succeeded'
}} catch {{
    if ($_.Exception.Message -notmatch 'missing vendor') {{ throw }}
}}
$env:WINS_ANDROID_PYTHON_ARCHIVE = '{archive}'
try {{
    Assert-WinsAndroidToolchainCustody -ManifestPath '{pinned_path}' -RepoRoot '{ROOT}' -Platform 'windows_amd64' -Tool python -Root '{tree}'
    throw 'hash-mismatch custody unexpectedly succeeded'
}} catch {{
    if ($_.Exception.Message -notmatch 'installed-tree SHA-256') {{ throw }}
}}
if (Test-Path -LiteralPath $marker) {{
    throw 'a candidate sentinel ran while Android toolchain custody was incomplete or mismatched'
}}
& '{sys.executable}' '{sentinel}'
if (-not (Test-Path -LiteralPath $marker)) {{
    throw 'sentinel control did not run'
}}
Remove-Item -LiteralPath $marker -Force
Write-Output 'ANDROID_WINDOWS_CUSTODY_NO_CANDIDATE_EXECUTION: PASS'
"""
            completed = subprocess.run(
                [shell, "-NoProfile", "-NonInteractive", "-Command", script],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stdout + completed.stderr,
            )
            self.assertIn(
                "ANDROID_WINDOWS_CUSTODY_NO_CANDIDATE_EXECUTION: PASS",
                completed.stdout,
            )
            self.assertFalse(marker.exists())

    def test_flutter_machine_identity_uses_real_3471_fields_under_strictmode(
        self,
    ) -> None:
        shell = powershell_executable()
        if shell is None:
            self.skipTest("PowerShell is unavailable")
        helpers = SOURCE[
            SOURCE.index("function Get-RequiredPsObjectProperty {") : SOURCE.index(
                "function Get-ReviewedFlutterRuntimeIdentity {"
            )
        ]
        realistic = {
            "frameworkVersion": EXPECTED_FLUTTER_VERSION,
            "channel": "stable",
            "repositoryUrl": "https://github.com/flutter/flutter.git",
            "frameworkRevision": EXPECTED_FLUTTER_REVISION,
            "frameworkCommitDate": "2026-08-19 12:00:00 -0700",
            "engineRevision": "0" * 40,
            "dartSdkVersion": "3.13.5",
            "devToolsVersion": "2.51.1",
            "flutterVersion": EXPECTED_FLUTTER_VERSION,
            "flutterRoot": r"C:\flutter",
        }
        prefixed = (
            "Building flutter tool...\n"
            "Waiting for another flutter command to release the startup lock...\n"
            + json.dumps(realistic, indent=2)
            + "\n"
        )
        missing_version = dict(realistic)
        del missing_version["frameworkVersion"]
        missing_version["dartTargetArch"] = "x64"
        missing_version["flutterGitUrl"] = "https://example.invalid/flutter.git"
        script = f"""
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
{helpers}
$raw = @'
{prefixed}
'@
$identity = ConvertFrom-FlutterMachineIdentity -Raw $raw
if ($identity.Version -cne '{EXPECTED_FLUTTER_VERSION}') {{ throw "version=$($identity.Version)" }}
if ($identity.Revision -cne '{EXPECTED_FLUTTER_REVISION}') {{ throw "revision=$($identity.Revision)" }}
if ($identity.Vendor -cne 'https://github.com/flutter/flutter.git') {{ throw "vendor=$($identity.Vendor)" }}
if ($identity.PSObject.Properties['Architecture']) {{
    throw 'Flutter --version --machine must not bind Architecture'
}}
if ($identity.PSObject.Properties['dartTargetArch'] -or
    $identity.PSObject.Properties['flutterGitUrl']) {{
    throw 'Flutter identity leaked nonexistent --machine fields'
}}
try {{
    $null = ConvertFrom-FlutterMachineIdentity -Raw @'
{json.dumps(missing_version, indent=2)}
'@
    throw 'missing frameworkVersion unexpectedly succeeded'
}} catch {{
    if ($_.Exception.Message -notmatch 'frameworkVersion') {{ throw }}
}}
Write-Output 'FLUTTER_MACHINE_IDENTITY: PASS'
"""
        completed = subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-Command", script],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(
            completed.returncode, 0, completed.stdout + completed.stderr
        )
        self.assertIn("FLUTTER_MACHINE_IDENTITY: PASS", completed.stdout)

    def test_neutral_child_receives_toolchain_pins_file(self) -> None:
        shell = powershell_executable()
        if shell is None:
            self.skipTest("PowerShell is unavailable")
        files_block = _neutral_input_files_assignment()
        self.assertIn("'tools/toolchain-pins.json'", files_block)
        snapshot_fn = SOURCE[
            SOURCE.index("function Get-NeutralInputSnapshot {") : SOURCE.index(
                "function Assert-IdenticalInputSnapshots {"
            )
        ]
        copy_fn = SOURCE[
            SOURCE.index("function Copy-NeutralInputs {") : SOURCE.index(
                "function New-PreparedReleaseFile {"
            )
        ]
        pin_fn = SOURCE[
            SOURCE.index("function Read-WinsToolchainPin {") : SOURCE.index(
                "$RequiredFlutterVersion = Read-WinsToolchainPin"
            )
        ]
        with tempfile.TemporaryDirectory() as temp_name:
            source_root = pathlib.Path(temp_name) / "source"
            dest_root = pathlib.Path(temp_name) / "stage"
            source_root.mkdir()
            dest_root.mkdir()
            relative_files = re.findall(r"'([^']+)'", files_block)
            self.assertIn("tools/toolchain-pins.json", relative_files)
            pins = {
                "tools": {
                    "flutter": {
                        "version": EXPECTED_FLUTTER_VERSION,
                        "revision": EXPECTED_FLUTTER_REVISION,
                    },
                    "python": {
                        "version": TOOLCHAIN_PINS["python"]["version"],
                        "implementation": TOOLCHAIN_PINS["python"]["implementation"],
                    },
                }
            }
            for relative in relative_files:
                path = source_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                if relative == "tools/toolchain-pins.json":
                    path.write_text(json.dumps(pins), encoding="utf-8")
                else:
                    path.write_text(f"fixture:{relative}\n", encoding="utf-8")
            for directory in ("lib", "assets", "android"):
                (source_root / directory).mkdir()
            escaped_source = str(source_root).replace("'", "''")
            escaped_dest = str(dest_root).replace("'", "''")
            script = f"""
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
{files_block}
$NeutralInputDirectories = @('lib', 'assets', 'android')
{snapshot_fn}
{copy_fn}
{pin_fn}
$snapshot = @(Get-NeutralInputSnapshot -Root '{escaped_source}')
$relative = @($snapshot | ForEach-Object {{ $_.RelativePath }})
if ($relative -notcontains 'tools/toolchain-pins.json') {{
    throw "snapshot missing toolchain-pins.json: $($relative -join ',')"
}}
Copy-NeutralInputs -SourceRoot '{escaped_source}' -DestinationRoot '{escaped_dest}' -Snapshot $snapshot
$copied = Join-Path '{escaped_dest}' 'tools/toolchain-pins.json'
if (-not (Test-Path -LiteralPath $copied -PathType Leaf)) {{
    throw 'staged child did not receive tools/toolchain-pins.json'
}}
$version = Read-WinsToolchainPin -PinPath $copied -Key 'tools.flutter.version'
$revision = Read-WinsToolchainPin -PinPath $copied -Key 'tools.flutter.revision'
if ($version -cne '{EXPECTED_FLUTTER_VERSION}' -or $revision -cne '{EXPECTED_FLUTTER_REVISION}') {{
    throw "staged pins identity mismatch: $version $revision"
}}
Write-Output 'NEUTRAL_CHILD_TOOLCHAIN_PINS: PASS'
"""
            completed = subprocess.run(
                [shell, "-NoProfile", "-NonInteractive", "-Command", script],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stdout + completed.stderr,
            )
            self.assertIn("NEUTRAL_CHILD_TOOLCHAIN_PINS: PASS", completed.stdout)
            staged = dest_root / "tools" / "toolchain-pins.json"
            self.assertTrue(staged.is_file())
            copied = json.loads(staged.read_text(encoding="utf-8"))
            self.assertEqual(
                copied["tools"]["flutter"]["version"], EXPECTED_FLUTTER_VERSION
            )
            self.assertEqual(
                copied["tools"]["flutter"]["revision"], EXPECTED_FLUTTER_REVISION
            )

    def test_macos_release_refuses_stale_native_engines_and_debug_substitution(self) -> None:
        freshness = "run_reviewed_android_engine_freshness_gate"
        self.assertIn("prepare_reviewed_go_for_engine_freshness", MAC_SOURCE)
        self.assertIn(
            'REQUIRED_GO_VERSION="$(read_wins_toolchain_pin tools.go.version)"',
            MAC_SOURCE,
        )
        self.assertIn("tools.go.executable_sha256", MAC_SOURCE)
        self.assertIn('/bin/bash "${WINN_ENGINE_SOURCE_GATE}" --verify', MAC_SOURCE)
        self.assertIn("GOTOOLCHAIN=local GOPROXY=off", MAC_SOURCE)
        self.assertNotIn("verify_shipped_native_artifact_freshness.py", MAC_SOURCE)
        embedded_versions = MAC_SOURCE.index(
            'wins_release_python_run "${ROOT}/tools/verify_embedded_engine_runtime_versions.py"'
        )
        freshness_check = MAC_SOURCE.index(freshness, embedded_versions)
        receipt_begin = MAC_SOURCE.index(
            '/bin/bash "${DEPENDENCY_FREEZE_PARENT}" begin-build'
        )
        self.assertLess(embedded_versions, freshness_check)
        self.assertLess(freshness_check, receipt_begin)

        for form in ("phone", "tv", "wear"):
            candidate = json.loads(
                (
                    ROOT
                    / "app_store"
                    / "android"
                    / form
                    / "artifacts"
                    / "release_candidate.json"
                ).read_text(encoding="ascii")
            )
            artifact = candidate["artifact"]
            self.assertEqual(artifact["build_variant"], "release")
            self.assertIs(artifact["obfuscated"], True)
            self.assertIs(artifact["debug_artifact_allowed"], False)
            self.assertIs(artifact["owner_signing_required"], True)
            self.assertIs(artifact["produced"], False)

    def test_phone_and_tv_receipts_bind_canonical_identity_alignment_and_stay_pending(
        self,
    ) -> None:
        for source in (SOURCE, MAC_SOURCE):
            with self.subTest(producer="powershell" if source is SOURCE else "macos"):
                self.assertIn("verify_android_aab_page_alignment.py", source)
                self.assertIn("android-phone-tablet-aab", source)
                self.assertIn("android-tv-aab", source)
                self.assertIn("verify-receipt", source)
                self.assertNotIn("play.google.com", source)
        self.assertIn("No Play Console upload or publication occurred.", MAC_SOURCE)
        self.assertIn("assert_owner_keystore_present", MAC_SOURCE)
        self.assertIn("OWNER-BLOCKED: missing Android upload keystore", MAC_SOURCE)
        self.assertIn(
            "OWNER-BLOCKED: produced Android AAB/APK bytes are absent", MAC_SOURCE
        )
        self.assertIn(
            "OWNER-BLOCKED: produced Android AAB/APK bytes are absent", SOURCE
        )
        self.assertIn("OWNER-BLOCKED: missing Android upload keystore", SOURCE)
        self.assertIn("verify_exact_android_identity_and_r8", MAC_SOURCE)
        self.assertIn("--verify-apk android-phone-tablet-apk", MAC_SOURCE)
        self.assertIn("'--verify-apk', 'android-phone-tablet-apk'", SOURCE)
        self.assertIn("'--bind-r8', 'android-tv-apk'", SOURCE)
        self.assertIn("--bind-r8 android-phone-tablet-aab", MAC_SOURCE)
        self.assertIn(
            'STAGE_AAB_SYMBOLS="${STAGE_REPO}/.artifacts/private-release-symbols/android-aab/${VERSION_IDENTITY}"',
            MAC_SOURCE,
        )
        self.assertIn(
            'STAGE_TV_AAB_SYMBOLS="${STAGE_REPO}/.artifacts/private-release-symbols/android-tv-aab/${VERSION_IDENTITY}"',
            MAC_SOURCE,
        )
        self.assertIn('BUILD_NUMBER="${VERSION_IDENTITY##*+}"', MAC_SOURCE)
        self.assertIn(
            "wins_release_python_run \"${STAGE_REPO}/tools/verify_android_aab_page_alignment.py\" \"${STAGE_AAB}\"",
            MAC_SOURCE,
        )
        self.assertIn(
            "wins_release_python_run \"${STAGE_REPO}/tools/verify_android_aab_page_alignment.py\" \"${STAGE_TV_AAB}\"",
            MAC_SOURCE,
        )
        self.assertIn(
            'finish_receipt "${AAB_BEGIN}" "${ROOT_AAB}" android-release-aab "${AAB_RECEIPT}"',
            MAC_SOURCE,
        )
        self.assertIn(
            'finish_receipt "${TV_AAB_BEGIN}" "${ROOT_TV_AAB}" android-tv-release-aab "${TV_AAB_RECEIPT}"',
            MAC_SOURCE,
        )
        self.assertNotIn(
            'finish_receipt "${AAB_BEGIN}" "${ROOT_TV_AAB}"',
            MAC_SOURCE,
        )
        self.assertNotIn(
            'finish_receipt "${TV_AAB_BEGIN}" "${ROOT_AAB}"',
            MAC_SOURCE,
        )
        inspector = (ROOT / "tools/verify_android_aab_signers.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("RELEASE_IDENTITY_SOURCE_SHA256", inspector)
        self.assertIn("canonical_release", inspector)
        self.assertIn("another exact target", inspector)
        pubspec = (ROOT / "pubspec.yaml").read_text(encoding="utf-8")
        self.assertRegex(pubspec, r"(?m)^version:\s*1\.0\.16\+33\s*$")

    def test_windows_and_macos_refuse_absent_signing_or_produced_bytes(self) -> None:
        for source in (SOURCE, MAC_SOURCE):
            with self.subTest(producer="powershell" if source is SOURCE else "macos"):
                self.assertIn("OWNER-BLOCKED: missing Android upload keystore", source)
                self.assertIn(
                    "OWNER-BLOCKED: produced Android AAB/APK bytes are absent", source
                )
        self.assertIn(
            "Join-Path $TvApkSymbols 'proguard-mapping.txt'",
            SOURCE,
        )
        self.assertIn(
            'cp "${R8_MAPPING}" "${STAGE_APK_SYMBOLS}/proguard-mapping.txt"',
            MAC_SOURCE,
        )

    def test_publication_helper_requires_complete_phone_and_tv_set(self) -> None:
        helper = (ROOT / "tools/android_release_publication.py").read_text(encoding="utf-8")
        self.assertIn("COMPLETE_PAIR_COUNT = 8", helper)
        self.assertIn("eight complete phone-plus-TV pairs", helper)
        self.assertIn(
            "OWNER-BLOCKED: produced Android AAB/APK bytes are absent", helper
        )
        self.assertNotIn("PHONE_ROLES =", helper)
        self.assertNotIn("four phone pairs", helper)

    def test_final_evidence_collector_owner_blocks_absent_produced_bytes(self) -> None:
        tools_dir = ROOT / "tools"
        if str(tools_dir) not in sys.path:
            sys.path.insert(0, str(tools_dir))
        import android_final_evidence_collector as collector

        with tempfile.TemporaryDirectory() as name:
            repo = pathlib.Path(name)
            apk = repo / "build/app/outputs/flutter-apk/app-release.apk"
            apk.parent.mkdir(parents=True)
            with self.assertRaisesRegex(
                collector.CollectorError,
                "OWNER-BLOCKED: produced Android AAB/APK bytes are absent",
            ):
                collector.assert_held_produced_packages(repo, apk)
        source = (ROOT / "tools/android_final_evidence_collector.py").read_text(
            encoding="utf-8"
        )
        for marker in (
            "OWNER-BLOCKED: produced Android AAB/APK bytes are absent",
            "assert_held_produced_packages",
            "assert_obfuscation_symbol_evidence",
            "expected_android_identity",
            "android-tv-apk",
            "android-tv-aab",
        ):
            self.assertIn(marker, source)


_PINNED_PYTHON_FUNCTIONS = (
    "read_wins_toolchain_pin",
    "toolchain_platform_key",
    "custody_regular_file_sha256",
    "read_pinned_release_python_executable",
    "prepare_pinned_release_python",
    "run_with_exact_environment",
    "_wins_android_release_python_exec",
    "wins_release_python_run",
    "wins_release_python_run_with_android_privacy_secrets",
    "release_python_cleanup",
)
_PYTHON_IDENTITY_PROBE = (
    "import platform,sys; print(f\"{platform.python_implementation().lower()}|"
    "{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}\")"
)
_WORK_PREFIX = "wins-android-release-python."
# A process observer can read the command line of /usr/bin/env while it runs, so
# `env -i NAME=password command` exposes the value. Any call to /usr/bin/env that
# carries a fixture password in its arguments fails with exit status 97.
_ENV_ARGUMENT_GUARD = r"""/usr/bin/env() {
  local argument
  for argument in "$@"; do
    case "${argument}" in
      *key-password-fixture*|*store-password-fixture*)
        printf 'SECRET-IN-ENV-ARGUMENTS\n' >&2
        return 97
        ;;
    esac
  done
  command /usr/bin/env "$@"
}"""


@unittest.skipUnless(sys.platform == "darwin", "macOS Android producer functions")
class AndroidPinnedReleasePythonTests(unittest.TestCase):
    """Behaviour of the pinned release Python that replaced ReleasePython custody.

    The functions are extracted from build_android_release_macos.sh and run
    under /bin/bash against a fixture pin file, a fixture interpreter whose
    SHA-256 is pinned in that file, and fixture wheels built here.
    """

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._remove_temp)
        self.base = pathlib.Path(self._temp.name).resolve()
        self.root = self.base / "repo"
        (self.root / "tools").mkdir(parents=True)
        self.tmp = self.base / "tmp"
        self.tmp.mkdir()
        self.home = self.base / "home"
        self.home.mkdir()
        self.interpreter = self.base / "bin" / "fixture-python"
        self.interpreter.parent.mkdir()
        self.interpreter.write_text('#!/bin/sh\nexec /usr/bin/python3 "$@"\n', encoding="ascii")
        self.interpreter.chmod(0o755)
        self.key = {"arm64": "darwin_arm64", "x86_64": "darwin_amd64"}[os.uname().machine]
        identity = subprocess.run(
            ["/usr/bin/python3", "-I", "-S", "-c", _PYTHON_IDENTITY_PROBE],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
        self.implementation, self.version = identity.split("|")
        self.wheels = [
            self._wheel(
                "fixturemod-1.0-py3-none-any.whl",
                [
                    ("fixturemod/__init__.py", b"VALUE = 'wheel-ok'\n"),
                    ("fixturemod-1.0.dist-info/METADATA", b"Name: fixturemod\n"),
                ],
            ),
            self._wheel(
                "othermod-1.0-py3-none-any.whl",
                [("othermod.py", b"NAME = 'other'\n")],
            ),
        ]

    def _remove_temp(self) -> None:
        for current, directories, _files in os.walk(self.base):
            for name in directories:
                os.chmod(os.path.join(current, name), 0o700)
        os.chmod(self.base, 0o700)
        self._temp.cleanup()

    def _wheel(self, name: str, members: list) -> tuple[pathlib.Path, str]:
        path = self.base / "wheels" / name
        path.parent.mkdir(exist_ok=True)
        with zipfile.ZipFile(path, "w") as archive:
            for member in members:
                if isinstance(member, zipfile.ZipInfo):
                    archive.writestr(member, b"payload\n")
                else:
                    archive.writestr(member[0], member[1])
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def _write_pins(self, wheels: list, executable_sha256: str | None = None) -> None:
        executable = executable_sha256 or hashlib.sha256(
            self.interpreter.read_bytes()
        ).hexdigest()
        pinned = {str(index): {"path": str(path), "sha256": digest} for index, (path, digest) in enumerate(wheels)}
        foreign = len(wheels)
        pinned[str(foreign)] = {
            "path": "/nonexistent/foreign-1.0-cp314-cp314-win_amd64.whl",
            "sha256": "0" * 64,
        }
        pins = {
            "tools": {
                "python": {
                    "version": self.version,
                    "implementation": self.implementation,
                    "reviewed_executable_path": {self.key: str(self.interpreter)},
                    "executable_sha256": {self.key: executable},
                    "archive_custody": {
                        self.key: {
                            "runtime_wheel_count": len(wheels),
                            "wheel_count": len(wheels) + 1,
                            "wheels": pinned,
                        }
                    },
                }
            }
        }
        (self.root / "tools" / "toolchain-pins.json").write_text(
            json.dumps(pins), encoding="utf-8"
        )

    def _run(
        self, body: str, extra_functions: str = "", ambient_env: dict | None = None
    ) -> subprocess.CompletedProcess:
        functions = "\n".join(_mac_shell_function(name) for name in _PINNED_PYTHON_FUNCTIONS)
        harness = "\n".join(
            (
                "set -Eeuo pipefail",
                "die() { printf 'ANDROID MACOS RELEASE BUILD ERROR: %s\\n' \"$*\" >&2; exit 65; }",
                f"ROOT={shlex.quote(str(self.root))}",
                "PIN_PYTHON_BIN=/usr/bin/python3",
                "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
                'RELEASE_PYTHON_WORK=""',
                'RELEASE_PYTHON_WORK_PARENT=""',
                'RELEASE_PYTHON_VENDOR=""',
                'RELEASE_PYTHON_EXECUTABLE_PIN_SHA256=""',
                # Like the producer: the passwords are shell variables, never exported.
                "WINS_ANDROID_KEY_PASSWORD=key-password-fixture",
                "WINS_ANDROID_STORE_PASSWORD=store-password-fixture",
                "export FOO=ambient-foo",
                functions,
                extra_functions,
                'REQUIRED_PYTHON_VERSION="$(read_wins_toolchain_pin tools.python.version)"',
                'REQUIRED_PYTHON_IMPLEMENTATION="$(read_wins_toolchain_pin tools.python.implementation)"',
                "trap 'release_python_cleanup' EXIT",
                body,
            )
        )
        return subprocess.run(
            ["/bin/bash", "-c", harness],
            env={
                "HOME": str(self.home),
                "TMPDIR": str(self.tmp),
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                **(ambient_env or {}),
            },
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )

    def _work_dirs(self) -> list:
        return sorted(path.name for path in self.tmp.iterdir() if path.name.startswith(_WORK_PREFIX))

    def test_overrides_are_refused_because_pins_own_the_interpreter(self) -> None:
        self.assertIn(
            "for ambient_toolchain_override in PYTHON_BIN WINS_RELEASE_PYTHON; do", MAC_SOURCE
        )
        self.assertIn("tools/toolchain-pins.json owns the release Python interpreter", MAC_SOURCE)
        call = MAC_SOURCE.index("\nprepare_pinned_release_python\n")
        self.assertLess(MAC_SOURCE.index('RELEASE_INDEX="$(resolve_repo_index "${RELEASE_INDEX}")"'), call)
        self.assertLess(call, MAC_SOURCE.index("\nwins_release_android_toolchains_prepare "))

    def test_pinned_python_runs_pinned_wheels_with_stdin_and_no_site(self) -> None:
        self._write_pins(self.wheels)
        completed = self._run(
            "\n".join(
                (
                    "prepare_pinned_release_python",
                    'printf "PYTHON_BIN=%s\\n" "${PYTHON_BIN}"',
                    'printf "WRITABLE=%s\\n" "$(find "${RELEASE_PYTHON_VENDOR}" -perm -u+w | wc -l | tr -d " ")"',
                    "wins_release_python_run - heredoc-arg <<'PY'",
                    "import sys",
                    "import fixturemod",
                    "import othermod",
                    "print('HEREDOC', fixturemod.VALUE, othermod.NAME, sys.argv[1], sys.flags.no_site)",
                    "PY",
                    "printf 'piped-bytes' | wins_release_python_run -c 'import sys; print(\"PIPED\", sys.stdin.read())'",
                )
            )
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(f"PYTHON_BIN={self.interpreter}\n", completed.stdout)
        self.assertIn("WRITABLE=0\n", completed.stdout)
        self.assertIn("HEREDOC wheel-ok other heredoc-arg 1\n", completed.stdout)
        self.assertIn("PIPED piped-bytes\n", completed.stdout)
        self.assertEqual(self._work_dirs(), [])

    def test_interpreter_sha256_mismatch_is_refused(self) -> None:
        self._write_pins(self.wheels, executable_sha256=hashlib.sha256(b"other").hexdigest())
        completed = self._run("prepare_pinned_release_python\necho PREPARED")
        self.assertEqual(completed.returncode, 65, completed.stderr)
        self.assertNotIn("PREPARED", completed.stdout)
        self.assertIn(
            "Pinned release Python executable does not match tools/toolchain-pins.json",
            completed.stderr,
        )
        self.assertEqual(self._work_dirs(), [])

    def test_wheel_sha256_mismatch_is_refused_and_work_dir_removed(self) -> None:
        wheels = list(self.wheels)
        wheels[1] = (wheels[1][0], hashlib.sha256(b"not the wheel").hexdigest())
        self._write_pins(wheels)
        completed = self._run("prepare_pinned_release_python\necho PREPARED")
        self.assertEqual(completed.returncode, 65, completed.stderr)
        self.assertNotIn("PREPARED", completed.stdout)
        self.assertIn("SHA-256 mismatch", completed.stderr)
        self.assertIn("runtime wheels could not be authenticated", completed.stderr)
        self.assertEqual(self._work_dirs(), [])

    def _assert_wheels_refused(self, wheels: list, pattern: str) -> None:
        self._write_pins(wheels)
        completed = self._run("prepare_pinned_release_python\necho PREPARED")
        self.assertEqual(completed.returncode, 65, completed.stderr)
        self.assertNotIn("PREPARED", completed.stdout)
        self.assertRegex(completed.stderr, pattern)
        self.assertIn("runtime wheels could not be authenticated", completed.stderr)
        self.assertEqual(self._work_dirs(), [])

    def test_correctly_pinned_hard_linked_wheel_is_refused(self) -> None:
        os.link(self.wheels[1][0], self.base / "second-name.whl")
        self._assert_wheels_refused(self.wheels, "unsafe wheel file type, link count or permissions")

    def test_correctly_pinned_group_or_world_writable_wheel_is_refused(self) -> None:
        for mode in (0o666, 0o664, 0o646):
            with self.subTest(mode=oct(mode)):
                self.wheels[1][0].chmod(mode)
                self._assert_wheels_refused(
                    self.wheels, "unsafe wheel file type, link count or permissions"
                )
        self.wheels[1][0].chmod(0o644)

    def test_correctly_pinned_wheel_behind_a_symlinked_ancestor_is_refused(self) -> None:
        alias = self.base / "wheel-alias"
        alias.symlink_to(self.wheels[1][0].parent, target_is_directory=True)
        linked = (alias / self.wheels[1][0].name, self.wheels[1][1])
        self.assertEqual(hashlib.sha256(linked[0].read_bytes()).hexdigest(), linked[1])
        self._assert_wheels_refused(
            [self.wheels[0], linked],
            r"\[Errno \d+\] (Too many levels of symbolic links|Not a directory)",
        )

    def test_correctly_pinned_wheel_under_a_writable_ancestor_is_refused(self) -> None:
        directory = self.wheels[1][0].parent
        # Group- or world-writable, and a sticky directory not owned by root.
        for mode in (0o775, 0o757, 0o1777):
            with self.subTest(mode=oct(mode)):
                directory.chmod(mode)
                self._assert_wheels_refused(self.wheels, "unsafe wheel ancestor")
        directory.chmod(0o755)

    def test_wheel_metadata_change_while_held_is_refused(self) -> None:
        # fail() and hold_wheel() of the wheel-preparation heredoc only.
        hold_start = MAC_SOURCE.index("def hold_wheel(path, expected):\n")
        fail_start = MAC_SOURCE.rindex("def fail(message):\n", 0, hold_start)
        source = MAC_SOURCE[
            fail_start : MAC_SOURCE.index("\n\n\ndef reject_duplicates(", fail_start)
        ] + "\n\n\n" + MAC_SOURCE[
            hold_start : MAC_SOURCE.index("\n\n\ndef member_parts(", hold_start)
        ]
        path, digest = self.wheels[1]

        class ChangeOnFirstRead:
            def __init__(self, change) -> None:
                self.change = change

            def __getattr__(self, name: str):
                return getattr(os, name)

            def read(self, descriptor: int, size: int) -> bytes:
                if self.change is not None:
                    change, self.change = self.change, None
                    change()
                return os.read(descriptor, size)

        class OtherBuildUser(ChangeOnFirstRead):
            def getuid(self) -> int:
                return os.getuid() + 1

        def hold(change, system=ChangeOnFirstRead) -> bytes:
            namespace = {"os": system(change), "stat": stat, "hashlib": hashlib}
            exec(compile(source, "hold_wheel", "exec"), namespace)
            return namespace["hold_wheel"](str(path), digest)

        # Anti-vacuity: the extracted function accepts the untouched wheel.
        self.assertEqual(hold(None), path.read_bytes())
        # A path owned by neither root nor the build uid is refused.
        with self.assertRaisesRegex(SystemExit, "untrusted wheel path owner"):
            hold(None, OtherBuildUser)
        second = self.base / "late-link.whl"
        for label, change, undo in (
            ("hard link", lambda: os.link(path, second), second.unlink),
            ("group write", lambda: path.chmod(0o664), lambda: path.chmod(0o644)),
            ("ancestor write", lambda: path.parent.chmod(0o777), lambda: path.parent.chmod(0o755)),
        ):
            with self.subTest(change=label):
                try:
                    with self.assertRaisesRegex(SystemExit, "changed while read"):
                        hold(change)
                finally:
                    undo()

    def test_unsafe_wheel_members_and_foreign_platform_tags_are_refused(self) -> None:
        symlink = zipfile.ZipInfo("fixturemod/link.py")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        cases = {
            "traversal": ("evil-1.0-py3-none-any.whl", [("../escape.py", b"ESCAPED = 1\n")], "traversal member"),
            "nested-traversal": ("evil-1.0-py3-none-any.whl", [("pkg/../../escape.py", b"x\n")], "traversal member"),
            "absolute": ("evil-1.0-py3-none-any.whl", [("/escape.py", b"x\n")], "unsafe member name"),
            "backslash": ("evil-1.0-py3-none-any.whl", [("pkg\\escape.py", b"x\n")], "unsafe member name"),
            "symlink": ("evil-1.0-py3-none-any.whl", [symlink], "symlink member"),
            "duplicate": (
                "evil-1.0-py3-none-any.whl",
                [("dup.py", b"a = 1\n"), ("dup.py", b"a = 2\n")],
                "duplicate member",
            ),
            "startup-hook": ("evil-1.0-py3-none-any.whl", [("evil.pth", b"import os\n")], "startup hook"),
            "foreign-platform": (
                "evil-1.0-cp314-cp314-win_amd64.whl",
                [("evil.py", b"x\n")],
                "cannot run on",
            ),
        }
        for label, (name, members, message) in cases.items():
            with self.subTest(case=label):
                for leftover in (self.base / "wheels").glob("evil-*"):
                    leftover.unlink()
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    evil = self._wheel(name, members)
                self._write_pins([self.wheels[0], evil])
                completed = self._run("prepare_pinned_release_python\necho PREPARED")
                self.assertEqual(completed.returncode, 65, completed.stderr)
                self.assertNotIn("PREPARED", completed.stdout)
                self.assertIn(message, completed.stderr)
                self.assertEqual(self._work_dirs(), [])
                self.assertEqual(list(self.base.rglob("escape.py")), [])

    def test_clean_runner_strips_ambient_environment_and_only_privacy_gets_passwords(self) -> None:
        self._write_pins(self.wheels)
        dump = "import json,os; print(json.dumps(dict(os.environ), sort_keys=True))"
        completed = self._run(
            "\n".join(
                (
                    "prepare_pinned_release_python",
                    "export WINS_ANDROID_KEY_PASSWORD",
                    f"printf 'CLEAN=%s\\n' \"$(wins_release_python_run -c {shlex.quote(dump)})\"",
                    "export -n WINS_ANDROID_KEY_PASSWORD",
                    f"printf 'PRIVACY=%s\\n' \"$(wins_release_python_run_with_android_privacy_secrets -c {shlex.quote(dump)})\"",
                    "unset WINS_ANDROID_STORE_PASSWORD",
                    "if wins_release_python_run_with_android_privacy_secrets -c 'pass'; then echo PRIVACY-WITHOUT-PASSWORD; fi",
                    'printf "VENDOR=%s\\n" "${RELEASE_PYTHON_VENDOR}"',
                )
            )
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        lines = dict(
            line.split("=", 1) for line in completed.stdout.splitlines() if "=" in line
        )
        clean = json.loads(lines["CLEAN"])
        privacy = json.loads(lines["PRIVACY"])
        expected = {
            "HOME": str(self.home),
            "TMPDIR": str(self.tmp),
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "PYTHONPATH": lines["VENDOR"],
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        for name, value in expected.items():
            self.assertEqual(clean.get(name), value, name)
            self.assertEqual(privacy.get(name), value, name)
        self.assertNotIn("FOO", clean)
        self.assertNotIn("FOO", privacy)
        # Exported or not, the passwords never reach the clean variant.
        self.assertNotIn("WINS_ANDROID_KEY_PASSWORD", clean)
        self.assertNotIn("WINS_ANDROID_STORE_PASSWORD", clean)
        self.assertEqual(privacy.get("WINS_ANDROID_KEY_PASSWORD"), "key-password-fixture")
        self.assertEqual(privacy.get("WINS_ANDROID_STORE_PASSWORD"), "store-password-fixture")
        # Keys the fixture interpreter adds by itself under an empty
        # environment (/bin/sh adds PWD and SHLVL; the /usr/bin/python3
        # developer-tools shim adds SDKROOT and compiler paths).
        added_by_fixture = set(
            json.loads(
                subprocess.run(
                    ["/usr/bin/env", "-i", str(self.interpreter), "-S", "-c", dump],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=30,
                ).stdout
            )
        )
        allowed = set(expected) | added_by_fixture
        self.assertTrue(allowed.isdisjoint({"FOO", "WINS_ANDROID_KEY_PASSWORD", "WINS_ANDROID_STORE_PASSWORD"}))
        self.assertLessEqual(set(clean), allowed)
        self.assertLessEqual(
            set(privacy), allowed | {"WINS_ANDROID_KEY_PASSWORD", "WINS_ANDROID_STORE_PASSWORD"}
        )
        self.assertNotIn("PRIVACY-WITHOUT-PASSWORD", completed.stdout)
        self.assertIn("requires both signing passwords", completed.stderr)

    def test_privacy_runner_never_places_the_passwords_on_a_command_line(self) -> None:
        self._write_pins(self.wheels)
        dump = 'import os; print("KEY=" + os.environ["WINS_ANDROID_KEY_PASSWORD"]); print("STORE=" + os.environ["WINS_ANDROID_STORE_PASSWORD"])'
        completed = self._run(
            "\n".join(
                (
                    "prepare_pinned_release_python",
                    _ENV_ARGUMENT_GUARD,
                    f"wins_release_python_run_with_android_privacy_secrets -c {shlex.quote(dump)}",
                )
            )
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("SECRET-IN-ENV-ARGUMENTS", completed.stderr)
        self.assertIn("KEY=key-password-fixture\n", completed.stdout)
        self.assertIn("STORE=store-password-fixture\n", completed.stdout)

    def test_privacy_runner_child_environment_ignores_the_callers_shell_level_and_exports(self) -> None:
        # The child's whole environment, SHLVL included, must be the same
        # whatever the caller exported or its inherited shell level was.
        self._write_pins(self.wheels)
        dump = "import json,os; print(json.dumps(dict(os.environ), sort_keys=True))"
        body = "\n".join(
            (
                "prepare_pinned_release_python",
                f"wins_release_python_run_with_android_privacy_secrets -c {shlex.quote(dump)}",
            )
        )
        seen = []
        for ambient in (
            {},
            {"SHLVL": "73", "assignments": "ambient", "exported_name": "ambient", "FOO.BAR": "ambient", "_": "/ambient"},
        ):
            completed = self._run(body, ambient_env=ambient)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            child = json.loads(completed.stdout.splitlines()[-1])
            # Only the random name of the private vendor directory differs per run.
            child["PYTHONPATH"] = re.sub(r"release-python\.[A-Za-z0-9]+/", "release-python.X/", child["PYTHONPATH"])
            seen.append(child)
        self.assertEqual(seen[0], seen[1])
        self.assertIn("SHLVL", seen[0])
        self.assertEqual(seen[1]["WINS_ANDROID_KEY_PASSWORD"], "key-password-fixture")

    def test_custody_recheck_refuses_a_changed_interpreter(self) -> None:
        self._write_pins(self.wheels)
        extra = "\n".join(
            (
                "wins_release_android_toolchains_verify() { :; }",
                _mac_shell_function("assert_reviewed_toolchain_custody"),
            )
        )
        completed = self._run(
            "\n".join(
                (
                    'TOOLCHAIN_PINS_CUSTODY_SHA256="$(custody_regular_file_sha256 "${ROOT}/tools/toolchain-pins.json")"',
                    "prepare_pinned_release_python",
                    "assert_reviewed_toolchain_custody",
                    "echo RECHECK-PASSED",
                    f"printf '# drift\\n' >> {shlex.quote(str(self.interpreter))}",
                    "assert_reviewed_toolchain_custody",
                    "echo DRIFT-ACCEPTED",
                )
            ),
            extra_functions=extra,
        )
        self.assertEqual(completed.returncode, 65, completed.stderr)
        self.assertIn("RECHECK-PASSED", completed.stdout)
        self.assertNotIn("DRIFT-ACCEPTED", completed.stdout)
        self.assertIn("no longer matches tools/toolchain-pins.json", completed.stderr)
        self.assertEqual(self._work_dirs(), [])

    def test_cleanup_removes_only_its_own_work_dir(self) -> None:
        self._write_pins(self.wheels)
        sibling = self.tmp / f"{_WORK_PREFIX}sibling"
        sibling.mkdir()
        (sibling / "keep").write_text("keep\n", encoding="utf-8")
        elsewhere = self.base / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "keep").write_text("keep\n", encoding="utf-8")
        completed = self._run(
            "\n".join(
                (
                    "prepare_pinned_release_python",
                    'printf "WORK=%s\\n" "${RELEASE_PYTHON_WORK}"',
                    "release_python_cleanup",
                    'printf "AFTER=%s\\n" "${RELEASE_PYTHON_WORK}"',
                    f"RELEASE_PYTHON_WORK={shlex.quote(str(elsewhere))}",
                    "if release_python_cleanup; then echo FOREIGN-REMOVED; fi",
                    'RELEASE_PYTHON_WORK=""',
                )
            )
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        work = re.search(r"(?m)^WORK=(.*)$", completed.stdout).group(1)
        self.assertTrue(pathlib.Path(work).name.startswith(_WORK_PREFIX))
        self.assertFalse(pathlib.Path(work).exists())
        self.assertIn("AFTER=\n", completed.stdout)
        self.assertNotIn("FOREIGN-REMOVED", completed.stdout)
        self.assertIn("refusing to remove an unexpected release Python work path", completed.stderr)
        self.assertTrue((sibling / "keep").is_file())
        self.assertTrue((elsewhere / "keep").is_file())


_HOME_TOOLCHAIN_FUNCTIONS = (
    "read_wins_toolchain_pin",
    "toolchain_platform_key",
    "verify_home_toolchain_tree",
    "run_with_exact_environment",
    "wins_release_android_toolchains_prepare",
    "wins_release_android_toolchains_verify",
    "_wins_release_android_toolchain_exec",
    "wins_release_android_flutter",
    "wins_release_android_flutter_build",
    "wins_release_android_keytool_with_store_password",
    "wins_release_android_jdk_tool",
)
_FLUTTER_RUNTIME_STATE = (
    ".git",
    "bin/cache/lockfile",
    "bin/cache/flutter_version_check.stamp",
    "packages/flutter_tools/.dart_tool",
    "packages/flutter_tools/gradle/.gradle",
    "packages/flutter_tools/gradle/build",
    "packages/flutter_tools/gradle/.kotlin",
)
_SHELL_ADDED_ENV = {"PWD", "SHLVL", "_", "OLDPWD"}
_FIXTURE_JAVA = {
    "version": "21.0.9.1",
    "release_name": "jdk-21.0.9.1+3",
    "vendor": "Eclipse Adoptium",
    "architecture": "aarch64",
    "image_type": "jdk",
    "jvm": "hotspot",
}
_FIXTURE_FLUTTER = {
    "version": "9.8.7",
    "revision": "0123456789abcdef0123456789abcdef01234567",
    "dart_version": "4.5.6",
}


def _canonical_tree_sha256(root: pathlib.Path, skips: tuple[str, ...] = ()) -> str:
    """Independent implementation of the pinned tree encoding."""
    digest = hashlib.sha256()

    def feed(*parts: object) -> None:
        for part in parts:
            value = str(part).encode("utf-8", "surrogateescape")
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)

    def walk(directory: pathlib.Path) -> None:
        for name in sorted(os.listdir(directory), key=os.fsencode):
            path = directory / name
            relative = path.relative_to(root).as_posix()
            if any(relative == item or relative.startswith(item + "/") for item in skips):
                continue
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                feed("D", relative, 0o500)
                walk(path)
            elif stat.S_ISLNK(info.st_mode):
                feed("L", relative, os.readlink(path))
            else:
                mode = 0o500 if info.st_mode & 0o111 else 0o400
                feed("F", relative, mode, info.st_size, hashlib.sha256(path.read_bytes()).hexdigest())

    walk(root)
    return digest.hexdigest()


@unittest.skipUnless(sys.platform == "darwin", "macOS Android producer functions")
class AndroidPinnedHomeToolchainTests(unittest.TestCase):
    """The pinned home Flutter and JDK that replaced owner-sealed /Library custody.

    Functions are extracted from build_android_release_macos.sh and run under
    /bin/bash against fixture JDK and Flutter trees under a fixture HOME, with a
    fixture pin file whose digests are computed here independently.
    """

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._remove_temp)
        self.base = pathlib.Path(self._temp.name).resolve()
        self.key = {"arm64": "darwin_arm64", "x86_64": "darwin_amd64"}[os.uname().machine]
        self.tmp = self.base / "tmp"
        self.tmp.mkdir()
        self.records = self.base / "records"
        self.records.mkdir()
        self.sdk = self.base / "android-sdk"
        self.sdk.mkdir()
        self.home, self.java, self.flutter, self.root = self._build(self.base / "case")
        self._write_pins(self.root)
        import inspect

        (self.base / "digest.py").write_text(
            "import hashlib, os, pathlib, stat\n"
            + inspect.getsource(_canonical_tree_sha256)
            + f"\nprint(_canonical_tree_sha256(pathlib.Path({str(self.flutter)!r}), "
            + f"{_FLUTTER_RUNTIME_STATE!r}))\n",
            encoding="utf-8",
        )

    def _remove_temp(self) -> None:
        for current, directories, files in os.walk(self.base):
            for name in directories:
                os.chmod(os.path.join(current, name), 0o700, follow_symlinks=False)
        self._temp.cleanup()

    def _recording_tool(self, path: pathlib.Path, label: str, version_text: str = "") -> None:
        records = shlex.quote(str(self.records))
        version_branch = ""
        if version_text:
            version_branch = (
                'if [ "$1" = "-version" ]; then printf %s '
                + shlex.quote(version_text)
                + " >&2; exit 0; fi\n"
            )
        path.write_text(
            "#!/bin/sh\n"
            + version_branch
            + f'name={label}.$(printf %s "${{{"2" if label == "dart" else "1"}:-none}}" | tr -c "A-Za-z0-9" "_")\n'
            + f'/usr/bin/env > {records}/"$name".env\n'
            + f'for arg in "$0" "$@"; do printf "%s\\n" "$arg"; done > {records}/"$name".argv\n',
            encoding="ascii",
        )
        path.chmod(0o755)

    def _build(self, case: pathlib.Path):
        home = case / "home"
        java = home / ".local" / "toolchains" / f"jdk-{_FIXTURE_JAVA['version']}"
        flutter = home / ".local" / f"flutter-{_FIXTURE_FLUTTER['version']}"
        root = case / "repo"
        for directory in (java / "bin", java / "lib", java / "legal", flutter, root / "tools"):
            directory.mkdir(parents=True)
        (home / ".pub-cache").mkdir()
        (java / "release").write_text(
            'IMPLEMENTOR="Eclipse Adoptium"\n'
            f'JAVA_VERSION="{_FIXTURE_JAVA["version"]}"\n'
            'JAVA_RUNTIME_VERSION="21.0.9.1+3"\n'
            'OS_ARCH="aarch64"\n'
            'IMAGE_TYPE="JDK"\n'
            'JVM_VARIANT="Hotspot"\n',
            encoding="ascii",
        )
        identity = (
            'openjdk version "21.0.9.1" 2026-01-01\n'
            "OpenJDK Runtime Environment Temurin-21.0.9.1+3 (build 21.0.9.1+3)\n"
        )
        for name in ("java", "jarsigner", "keytool"):
            self._recording_tool(java / "bin" / name, name, identity if name == "java" else "")
        (java / "lib" / "modules").write_bytes(b"jdk-modules-payload\n" * 64)
        (java / "legal" / "LICENSE").write_text("license\n", encoding="ascii")
        os.symlink("modules", java / "lib" / "modules-link")
        files = {
            "bin/cache/flutter.version.json": json.dumps(
                {
                    "frameworkVersion": _FIXTURE_FLUTTER["version"],
                    "frameworkRevision": _FIXTURE_FLUTTER["revision"],
                    "dartSdkVersion": _FIXTURE_FLUTTER["dart_version"],
                    "channel": "stable",
                }
            ),
            "bin/cache/dart-sdk/version": _FIXTURE_FLUTTER["dart_version"] + "\n",
            "bin/cache/flutter_tools.snapshot": "snapshot-bytes\n",
            "bin/cache/engine.stamp": "engine-hash\n",
            "bin/cache/lockfile": "",
            "bin/cache/flutter_version_check.stamp": '{"lastTimeVersionWasChecked":"1"}\n',
            "bin/cache/artifacts/material_fonts/Roboto.ttf": "font\n",
            "packages/flutter/lib/flutter.dart": "library flutter;\n",
            "packages/flutter_tools/.dart_tool/package_config.json": "{}\n",
            "packages/flutter_tools/gradle/.gradle/buildOutputCleanup.lock": "lock\n",
            "packages/flutter_tools/gradle/build/plugin.class": "class\n",
            "packages/flutter_tools/gradle/.kotlin/session": "session\n",
            "packages/flutter_tools/gradle/build.gradle.kts": "plugins {}\n",
            ".git/HEAD": "ref: refs/heads/stable\n",
            ".agents/skills/README.md": "skills\n",
        }
        for relative, text in files.items():
            path = flutter / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        (flutter / "bin" / "flutter").write_text("#!/bin/sh\nexit 99\n", encoding="ascii")
        (flutter / "bin" / "flutter").chmod(0o755)
        dart = flutter / "bin" / "cache" / "dart-sdk" / "bin" / "dart"
        dart.parent.mkdir(parents=True)
        self._recording_tool(dart, "dart")
        (flutter / ".claude").mkdir()
        os.symlink("../.agents/skills", flutter / ".claude" / "skills")
        return home, java, flutter, root

    def _write_pins(self, root: pathlib.Path, *, java_sha: str | None = None,
                    flutter_sha: str | None = None, drop_flutter_tree: bool = False,
                    flutter_version: str | None = None) -> None:
        java_pin = dict(_FIXTURE_JAVA)
        java_pin["install_tree_sha256"] = {
            self.key: java_sha or _canonical_tree_sha256(self.java)
        }
        flutter_pin = dict(_FIXTURE_FLUTTER)
        if flutter_version:
            flutter_pin["version"] = flutter_version
        if not drop_flutter_tree:
            flutter_pin["installed_tree_sha256"] = {
                self.key: flutter_sha or _canonical_tree_sha256(self.flutter, _FLUTTER_RUNTIME_STATE)
            }
        (root / "tools" / "toolchain-pins.json").write_text(
            json.dumps({"tools": {"java": java_pin, "flutter": flutter_pin}}), encoding="utf-8"
        )

    def _run(self, body: str, *, root: pathlib.Path | None = None, home: pathlib.Path | None = None,
             extra_functions: tuple[str, ...] = (), prelude: str = "",
             ambient_env: dict | None = None) -> subprocess.CompletedProcess:
        functions = "\n".join(
            _mac_shell_function(name) for name in _HOME_TOOLCHAIN_FUNCTIONS + extra_functions
        )
        harness = "\n".join(
            (
                "set -Eeuo pipefail",
                "die() { printf 'ANDROID MACOS RELEASE BUILD ERROR: %s\\n' \"$*\" >&2; exit 65; }",
                f"ROOT={shlex.quote(str(root or self.root))}",
                "PIN_PYTHON_BIN=/usr/bin/python3",
                "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
                "export FOO=ambient-foo JAVA_TOOL_OPTIONS=-Dhostile=1 FLUTTER_ROOT=/hostile",
                f"ANDROID_SDK_ROOT={shlex.quote(str(self.sdk))}",
                'ANDROID_HOME="${ANDROID_SDK_ROOT}"',
                # Like the producer: signing values are shell variables, never exported.
                f"WINS_ANDROID_KEYSTORE={shlex.quote(str(self.base / 'upload.keystore'))}",
                "WINS_ANDROID_KEY_ALIAS=fixture-alias",
                "WINS_ANDROID_KEY_PASSWORD=key-password-fixture",
                "WINS_ANDROID_STORE_PASSWORD=store-password-fixture",
                functions,
                'REQUIRED_FLUTTER_VERSION="$(read_wins_toolchain_pin tools.flutter.version)"',
                prelude,
                body,
            )
        )
        return subprocess.run(
            ["/bin/bash", "-c", harness],
            env={
                "HOME": str(home or self.home),
                "TMPDIR": str(self.tmp),
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                **(ambient_env or {}),
            },
            check=False,
            capture_output=True,
            text=True,
            timeout=600,
        )

    def _prepare_body(self, *lines: str) -> str:
        return "\n".join(
            (
                'wins_release_android_toolchains_prepare "${ROOT}/tools/toolchain-pins.json"',
                *lines,
            )
        )

    def _record_raw(self, name: str) -> tuple[dict, list]:
        env = {}
        for line in (self.records / f"{name}.env").read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            env[key] = value
        argv = (self.records / f"{name}.argv").read_text(encoding="utf-8").splitlines()
        return env, argv

    def _record(self, name: str) -> tuple[dict, list]:
        env, argv = self._record_raw(name)
        for key in _SHELL_ADDED_ENV:
            env.pop(key, None)
        return env, argv

    def test_prepare_binds_pinned_home_roots_and_recheck_detects_drift(self) -> None:
        completed = self._run(
            self._prepare_body(
                'printf "JAVA_HOME=%s\\nJAVA_TREE=%s\\n" "${WINS_RELEASE_JAVA_HOME}" "${WINS_RELEASE_JAVA_TREE_SHA256}"',
                'printf "FLUTTER_ROOT=%s\\nFLUTTER_TREE=%s\\n" "${WINS_RELEASE_FLUTTER_ROOT}" "${WINS_RELEASE_FLUTTER_TREE_SHA256}"',
                'printf "FLUTTER_BIN=%s\\nPUB_CACHE=%s\\n" "${WINS_RELEASE_FLUTTER_BIN}" "${WINS_RELEASE_PUB_CACHE}"',
                "wins_release_android_toolchains_verify && echo RECHECK-1-PASSED",
                "printf 'X' >> " + shlex.quote(str(self.flutter / "packages/flutter/lib/flutter.dart")),
                "if wins_release_android_toolchains_verify; then echo FLUTTER-DRIFT-ACCEPTED; fi",
                "if wins_release_android_toolchains_prepare \"${ROOT}/tools/toolchain-pins.json\"; then echo PREPARED-TWICE; fi",
                "if wins_release_android_toolchains_prepare /elsewhere/toolchain-pins.json; then echo FOREIGN-PINS; fi",
            )
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        values = dict(line.split("=", 1) for line in completed.stdout.splitlines() if "=" in line)
        self.assertEqual(values["JAVA_HOME"], str(self.java))
        self.assertEqual(values["JAVA_TREE"], _canonical_tree_sha256(self.java))
        self.assertEqual(values["FLUTTER_ROOT"], str(self.flutter))
        self.assertEqual(values["FLUTTER_BIN"], str(self.flutter / "bin" / "flutter"))
        self.assertEqual(values["PUB_CACHE"], str(self.home / ".pub-cache"))
        self.assertIn("RECHECK-1-PASSED", completed.stdout)
        self.assertNotIn("FLUTTER-DRIFT-ACCEPTED", completed.stdout)
        self.assertIn("installed tree digest mismatch", completed.stderr)
        self.assertNotIn("PREPARED-TWICE", completed.stdout)
        self.assertNotIn("FOREIGN-PINS", completed.stdout)
        self._write_pins(self.root)
        drift = self._run(
            "\n".join(
                (
                    'wins_release_android_toolchains_prepare "${ROOT}/tools/toolchain-pins.json"',
                    "printf 'X' >> " + shlex.quote(str(self.java / "lib/modules")),
                    "if wins_release_android_toolchains_verify; then echo JAVA-DRIFT-ACCEPTED; fi",
                )
            )
        )
        self.assertEqual(drift.returncode, 0, drift.stderr)
        self.assertNotIn("JAVA-DRIFT-ACCEPTED", drift.stdout)
        self.assertIn("pinned home java toolchain refused: installed tree digest mismatch", drift.stderr)
        # A tree change paired with a matching pin rewrite after preparation is
        # still refused: the recheck compares with the digests bound at prepare.
        self._write_pins(self.root)
        pinned = self.root / "tools" / "toolchain-pins.json"
        repin = self._run(
            "\n".join(
                (
                    'wins_release_android_toolchains_prepare "${ROOT}/tools/toolchain-pins.json"',
                    "printf 'Z' >> " + shlex.quote(str(self.flutter / "packages/flutter/lib/flutter.dart")),
                    "/usr/bin/python3 -I -c " + shlex.quote(
                        "import json,sys; p=sys.argv[1]; d=json.load(open(p)); "
                        f"d['tools']['flutter']['installed_tree_sha256']['{self.key}']=sys.argv[2]; "
                        "open(p,'w').write(json.dumps(d))"
                    ) + " " + shlex.quote(str(pinned)) + ' "$(/usr/bin/python3 -I '
                    + shlex.quote(str(self.base / "digest.py")) + ")\"",
                    "if wins_release_android_toolchains_verify; then echo REPIN-ACCEPTED; fi",
                )
            )
        )
        self.assertEqual(repin.returncode, 0, repin.stderr)
        self.assertNotIn("REPIN-ACCEPTED", repin.stdout)
        self.assertIn("changed after it was verified", repin.stderr)

    def test_prepare_refuses_a_wrong_jdk_identity_and_an_unsafe_pub_cache(self) -> None:
        self._rewrite(self.java / "bin" / "java", "(build 21.0.9.1+3)", "(build 21.0.9.1+4)")
        self._write_pins(self.root)
        identity = self._run(self._prepare_body("echo PREPARED"))
        self.assertNotEqual(identity.returncode, 0)
        self.assertNotIn("PREPARED", identity.stdout)
        self.assertIn("pinned JDK identity mismatch", identity.stderr)
        self._rewrite(self.java / "bin" / "java", "(build 21.0.9.1+4)", "(build 21.0.9.1+3)")
        self._write_pins(self.root)
        (self.home / ".pub-cache").chmod(0o775)
        pub = self._run(self._prepare_body("echo PREPARED"))
        self.assertNotEqual(pub.returncode, 0)
        self.assertNotIn("PREPARED", pub.stdout)
        self.assertIn("Pub cache must be a current-user directory", pub.stderr)
        (self.home / ".pub-cache").chmod(0o755)
        ok = self._run(self._prepare_body("echo PREPARED"))
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertIn("PREPARED", ok.stdout)

    def test_tree_and_metadata_refusals(self) -> None:
        def java_file(case):
            return case["java"] / "lib" / "modules"

        cases = {
            "java-changed-byte": ("java", lambda c: java_file(c).write_bytes(java_file(c).read_bytes()[:-1] + b"Y"), "installed tree digest mismatch"),
            "java-group-writable-file": ("java", lambda c: java_file(c).chmod(0o664), "group or world writable"),
            "java-world-writable-dir": ("java", lambda c: (c["java"] / "lib").chmod(0o757), "group or world writable"),
            "java-hard-link": ("java", lambda c: os.link(java_file(c), c["java"] / "lib" / "modules-hard"), "hard-linked"),
            "java-absolute-symlink": ("java", lambda c: os.symlink("/etc/hosts", c["java"] / "lib" / "abs"), "absolute"),
            "java-escaping-symlink": ("java", lambda c: os.symlink("../../../../../..", c["java"] / "lib" / "up"), "escapes"),
            "java-fifo": ("java", lambda c: os.mkfifo(c["java"] / "lib" / "fifo"), "unsupported entry type"),
            "java-wrong-version": ("java", lambda c: self._rewrite(c["java"] / "release", 'JAVA_VERSION="21.0.9.1"', 'JAVA_VERSION="21.0.9.2"'), "JAVA_VERSION mismatch"),
            "java-wrong-runtime": ("java", lambda c: self._rewrite(c["java"] / "release", "+3", "+4"), "JAVA_RUNTIME_VERSION mismatch"),
            "java-wrong-vendor": ("java", lambda c: self._rewrite(c["java"] / "release", "Eclipse Adoptium", "Other Vendor"), "IMPLEMENTOR mismatch"),
            "java-wrong-arch": ("java", lambda c: self._rewrite(c["java"] / "release", "aarch64", "x86_64"), "OS_ARCH mismatch"),
            "java-wrong-image": ("java", lambda c: self._rewrite(c["java"] / "release", 'IMAGE_TYPE="JDK"', 'IMAGE_TYPE="JRE"'), "IMAGE_TYPE mismatch"),
            "java-non-executable-tool": ("java", lambda c: (c["java"] / "bin" / "keytool").chmod(0o644), "bin/keytool must be a single-link regular executable"),
            "java-symlinked-root": ("java", self._symlink_root, "without symlinks"),
            "java-writable-ancestor": ("java", lambda c: c["java"].parent.chmod(0o775), "ancestor"),
            "flutter-changed-byte": ("flutter", lambda c: (c["flutter"] / "packages/flutter/lib/flutter.dart").write_text("library evil;\n", encoding="utf-8"), "installed tree digest mismatch"),
            "flutter-changed-engine-stamp": ("flutter", lambda c: (c["flutter"] / "bin/cache/engine.stamp").write_text("other\n", encoding="utf-8"), "installed tree digest mismatch"),
            "flutter-group-writable-font": ("flutter", lambda c: (c["flutter"] / "bin/cache/artifacts/material_fonts/Roboto.ttf").chmod(0o664), "group or world writable"),
            "flutter-hard-link": ("flutter", lambda c: os.link(c["flutter"] / "bin/cache/engine.stamp", c["flutter"] / "bin/cache/engine.copy"), "hard-linked"),
            "flutter-absolute-symlink": ("flutter", lambda c: os.symlink(str(c["flutter"] / "bin"), c["flutter"] / "bin" / "abs"), "absolute"),
            "flutter-wrong-revision": ("flutter", lambda c: self._rewrite(c["flutter"] / "bin/cache/flutter.version.json", _FIXTURE_FLUTTER["revision"], "f" * 40), "frameworkRevision mismatch"),
            "flutter-wrong-framework": ("flutter", lambda c: self._rewrite(c["flutter"] / "bin/cache/flutter.version.json", '"9.8.7"', '"9.8.8"'), "frameworkVersion mismatch"),
            "flutter-wrong-dart-json": ("flutter", lambda c: self._rewrite(c["flutter"] / "bin/cache/flutter.version.json", '"4.5.6"', '"4.5.7"'), "dartSdkVersion mismatch"),
            "flutter-wrong-dart-sdk": ("flutter", lambda c: (c["flutter"] / "bin/cache/dart-sdk/version").write_text("4.5.7\n", encoding="ascii"), "dart-sdk/version"),
            "flutter-missing-snapshot": ("flutter", lambda c: (c["flutter"] / "bin/cache/flutter_tools.snapshot").unlink(), "cannot open"),
        }
        for label, (kind, mutate, message) in cases.items():
            with self.subTest(case=label):
                home, java, flutter, root = self._build(self.base / label)
                case = {"java": java, "flutter": flutter}
                self.java, self.flutter = java, flutter
                self._write_pins(root)
                mutate(case)
                completed = self._run(
                    self._prepare_body("echo PREPARED"), root=root, home=home
                )
                self.assertNotEqual(completed.returncode, 0, completed.stdout)
                self.assertNotIn("PREPARED", completed.stdout)
                self.assertIn(f"pinned home {kind} toolchain refused", completed.stderr)
                self.assertIn(message, completed.stderr)
        for label, kwargs, message in (
            ("pin-missing-flutter-tree", {"drop_flutter_tree": True}, "lacks the flutter pins"),
            ("pin-malformed-java-tree", {"java_sha": "Z" * 64}, "tree SHA-256 pin is malformed"),
            ("pin-other-flutter-version", {"flutter_version": "9.8.8"}, "toolchain root is missing"),
        ):
            with self.subTest(case=label):
                home, java, flutter, root = self._build(self.base / label)
                self.java, self.flutter = java, flutter
                self._write_pins(root, **kwargs)
                completed = self._run(self._prepare_body("echo PREPARED"), root=root, home=home)
                self.assertNotEqual(completed.returncode, 0, completed.stdout)
                self.assertNotIn("PREPARED", completed.stdout)
                self.assertIn(message, completed.stderr)
        misnamed = self._run(
            "verify_home_toolchain_tree java " + shlex.quote(str(self.flutter))
        )
        self.assertNotEqual(misnamed.returncode, 0)
        self.assertIn("does not name the pinned version", misnamed.stderr)

    def _rewrite(self, path: pathlib.Path, old: str, new: str) -> None:
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text)
        mode = stat.S_IMODE(path.stat().st_mode)
        path.write_text(text.replace(old, new), encoding="utf-8")
        path.chmod(mode)

    def _symlink_root(self, case: dict) -> None:
        moved = case["java"].parent / "moved-jdk"
        case["java"].rename(moved)
        os.symlink(moved, case["java"])

    def test_only_flutter_runtime_state_is_outside_the_digest(self) -> None:
        pinned = _canonical_tree_sha256(self.flutter, _FLUTTER_RUNTIME_STATE)
        for relative in (
            ".git/HEAD",
            ".git/FETCH_HEAD",
            "bin/cache/lockfile",
            "bin/cache/flutter_version_check.stamp",
            "packages/flutter_tools/.dart_tool/package_config.json",
            "packages/flutter_tools/gradle/.gradle/9.8.0/executionHistory.lock",
            "packages/flutter_tools/gradle/build/new.class",
            "packages/flutter_tools/gradle/.kotlin/errors.log",
        ):
            path = self.flutter / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"runtime write {relative}\n", encoding="utf-8")
        # Owner-only permission changes that keep the execute bit are not in
        # the digest; the execute bit is.
        (self.flutter / "packages/flutter/lib/flutter.dart").chmod(0o600)
        completed = self._run(
            self._prepare_body(
                'printf "FLUTTER_TREE=%s\\n" "${WINS_RELEASE_FLUTTER_TREE_SHA256}"',
                "chmod 0755 " + shlex.quote(str(self.flutter / "packages/flutter/lib/flutter.dart")),
                "if wins_release_android_toolchains_verify; then echo EXEC-BIT-ACCEPTED; fi",
            )
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(f"FLUTTER_TREE={pinned}\n", completed.stdout)
        self.assertNotIn("EXEC-BIT-ACCEPTED", completed.stdout)
        self.assertIn("installed tree digest mismatch", completed.stderr)
        self.assertEqual(
            _canonical_tree_sha256(self.java),
            _canonical_tree_sha256(self.java, _FLUTTER_RUNTIME_STATE),
        )
        (self.java / ".git").mkdir()
        (self.java / ".git" / "HEAD").write_text("java is never skipped\n", encoding="ascii")
        java_git = self._run(self._prepare_body("echo PREPARED"))
        self.assertNotEqual(java_git.returncode, 0)
        self.assertIn("pinned home java toolchain refused: installed tree digest mismatch", java_git.stderr)

    def test_runners_scrub_environment_and_route_signing_values(self) -> None:
        completed = self._run(
            self._prepare_body(
                "wins_release_android_flutter --version --machine",
                "wins_release_android_flutter_build build apk --no-pub --release --flavor phone",
                "wins_release_android_jdk_tool jarsigner -verify fixture.aab",
                "wins_release_android_keytool_with_store_password -list -storepass:env WINS_ANDROID_STORE_PASSWORD",
            )
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        java_bin = self.java / "bin"
        base = {
            "HOME": str(self.home),
            "TMPDIR": str(self.tmp),
            "PATH": f"{java_bin}:{self.flutter / 'bin'}:/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "C",
            "LC_ALL": "C",
            "JAVA_HOME": str(self.java),
        }
        flutter_env = dict(
            base,
            CI="true",
            FLUTTER_ROOT=str(self.flutter),
            FLUTTER_SUPPRESS_ANALYTICS="true",
            FLUTTER_ALREADY_LOCKED="true",
            PUB_CACHE=str(self.home / ".pub-cache"),
            ANDROID_SDK_ROOT=str(self.sdk),
            ANDROID_HOME=str(self.sdk),
        )
        signing = {
            "WINS_ANDROID_KEYSTORE": str(self.base / "upload.keystore"),
            "WINS_ANDROID_KEY_ALIAS": "fixture-alias",
            "WINS_ANDROID_KEY_PASSWORD": "key-password-fixture",
            "WINS_ANDROID_STORE_PASSWORD": "store-password-fixture",
        }
        dart = self.flutter / "bin/cache/dart-sdk/bin/dart"
        snapshot = self.flutter / "bin/cache/flutter_tools.snapshot"
        env, argv = self._record("dart.__version")
        self.assertEqual(env, flutter_env)
        self.assertEqual(argv, [str(dart), str(snapshot), "--version", "--machine"])
        env, argv = self._record("dart.build")
        self.assertEqual(env, dict(flutter_env, **signing))
        self.assertEqual(argv[:4], [str(dart), str(snapshot), "build", "apk"])
        env, argv = self._record("jarsigner._verify")
        self.assertEqual(env, base)
        self.assertEqual(argv, [str(java_bin / "jarsigner"), "-verify", "fixture.aab"])
        env, argv = self._record("keytool._list")
        self.assertEqual(
            env, dict(base, WINS_ANDROID_STORE_PASSWORD="store-password-fixture")
        )
        self.assertEqual(argv[0], str(java_bin / "keytool"))

    def test_flutter_build_signing_values_never_enter_a_command_line(self) -> None:
        completed = self._run(
            self._prepare_body(
                "wins_release_android_flutter_build build apk --no-pub --release --flavor phone",
            ),
            prelude=_ENV_ARGUMENT_GUARD,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("SECRET-IN-ENV-ARGUMENTS", completed.stderr)
        env, _argv = self._record("dart.build")
        self.assertEqual(env["WINS_ANDROID_KEY_PASSWORD"], "key-password-fixture")
        self.assertEqual(env["WINS_ANDROID_STORE_PASSWORD"], "store-password-fixture")

    def test_signing_runners_ignore_the_callers_shell_level_and_exports(self) -> None:
        body = self._prepare_body(
            "wins_release_android_flutter_build build apk --no-pub --release --flavor phone",
            "wins_release_android_keytool_with_store_password -list -storepass:env WINS_ANDROID_STORE_PASSWORD",
        )
        seen = []
        for ambient in (
            {},
            {"SHLVL": "73", "assignments": "ambient", "exported_name": "ambient", "FOO.BAR": "ambient", "_": "/ambient"},
        ):
            completed = self._run(body, ambient_env=ambient)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            seen.append({label: self._record_raw(label) for label in ("dart.build", "keytool._list")})
        # The raw records keep PWD, OLDPWD, SHLVL and _, which the recording
        # tool's own /bin/sh adds; they must not depend on the caller.
        self.assertEqual(seen[0], seen[1])
        self.assertIn("SHLVL", seen[0]["dart.build"][0])

    def test_keytool_store_password_never_enters_a_command_line(self) -> None:
        completed = self._run(
            self._prepare_body(
                "wins_release_android_keytool_with_store_password -list -storepass:env WINS_ANDROID_STORE_PASSWORD",
            ),
            prelude=_ENV_ARGUMENT_GUARD,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("SECRET-IN-ENV-ARGUMENTS", completed.stderr)
        env, _argv = self._record("keytool._list")
        self.assertEqual(env["WINS_ANDROID_STORE_PASSWORD"], "store-password-fixture")
        self.assertNotIn("WINS_ANDROID_KEY_PASSWORD", env)

    def test_flutter_build_and_jdk_tool_argument_policy(self) -> None:
        completed = self._run(
            self._prepare_body(
                "if wins_release_android_flutter_build build apk --release; then echo NO-NOPUB; fi",
                "if wins_release_android_flutter_build build apk --no-pub --no-pub; then echo TWO-NOPUB; fi",
                "if wins_release_android_flutter_build pub get; then echo NOT-BUILD; fi",
                "if wins_release_android_jdk_tool javac -version; then echo JAVAC; fi",
                "if wins_release_android_jdk_tool; then echo EMPTY-TOOL; fi",
                "if (ANDROID_HOME=/elsewhere; wins_release_android_flutter_build build apk --no-pub); then echo SPLIT-SDK; fi",
                "if (WINS_ANDROID_KEY_PASSWORD=; wins_release_android_flutter_build build apk --no-pub); then echo NO-KEY-PASSWORD; fi",
                "if (WINS_ANDROID_STORE_PASSWORD=; wins_release_android_keytool_with_store_password -list); then echo NO-STORE-PASSWORD; fi",
                "echo POLICY-DONE",
            )
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("POLICY-DONE", completed.stdout)
        for refused in (
            "NO-NOPUB", "TWO-NOPUB", "NOT-BUILD", "JAVAC", "EMPTY-TOOL",
            "SPLIT-SDK", "NO-KEY-PASSWORD", "NO-STORE-PASSWORD",
        ):
            self.assertNotIn(refused, completed.stdout)
        self.assertEqual(completed.stderr.count("exactly one --no-pub"), 2)
        self.assertIn("unapproved JDK tool rejected: javac", completed.stderr)
        self.assertIn("one absolute non-symlink Android SDK root", completed.stderr)
        self.assertIn("WINS_ANDROID_KEY_PASSWORD", completed.stderr)
        self.assertFalse(list(self.records.glob("dart.*")))
        self.assertFalse(list(self.records.glob("javac*")))

    def test_apksigner_binds_the_verified_home_java(self) -> None:
        completed = self._run(
            self._prepare_body(
                'REVIEWED_APKSIGNER_JAR_RELATIVE="build-tools/37.0.0/lib/apksigner.jar"',
                'REVIEWED_APKSIGNER_JAR_SHA256="2defad215d7ff52968a409cde528cdaef7918b115e276b8e3378ca7a178e4180"',
                "wins_release_python_run() { cat >/dev/null; printf 'RUNNER:%s\\n' \"$@\"; }",
                'SEALED_JAVA="${WINS_RELEASE_JAVA_HOME}/bin/java"',
                "run_android_apksigner verify -Werr fixture.apk",
                "SEALED_JAVA=/Library/WinsVPN/ReleaseAndroidToolchains/jdk-17.0.20.1/bin/java",
                "run_android_apksigner verify -Werr fixture.apk",
                "echo FOREIGN-JAVA-ACCEPTED",
            ),
            extra_functions=("run_android_apksigner",),
        )
        self.assertEqual(completed.returncode, 65, completed.stderr)
        lines = completed.stdout.splitlines()
        self.assertIn(f"RUNNER:{self.java / 'bin' / 'java'}", lines)
        self.assertIn("RUNNER:2defad215d7ff52968a409cde528cdaef7918b115e276b8e3378ca7a178e4180", lines)
        self.assertNotIn("FOREIGN-JAVA-ACCEPTED", completed.stdout)
        self.assertIn("apksigner must bind the pinned, digest-verified JDK java executable", completed.stderr)
        signer = _mac_shell_function("run_android_apksigner")
        self.assertIn("REVIEWED_APKSIGNER_JAR_SHA256", signer)
        self.assertNotIn("/Library", signer)

    def test_custody_recheck_refuses_a_changed_toolchain_tree(self) -> None:
        interpreter = self.base / "fixture-interpreter"
        interpreter.write_bytes(b"fixture interpreter bytes\n")
        completed = self._run(
            self._prepare_body(
                "assert_reviewed_toolchain_custody",
                "echo RECHECK-PASSED",
                "printf 'X' >> " + shlex.quote(str(self.flutter / "bin/cache/engine.stamp")),
                "assert_reviewed_toolchain_custody",
                "echo DRIFT-ACCEPTED",
            ),
            extra_functions=("custody_regular_file_sha256", "assert_reviewed_toolchain_custody"),
            prelude="\n".join(
                (
                    f"PYTHON_BIN={shlex.quote(str(interpreter))}",
                    'RELEASE_PYTHON_EXECUTABLE_PIN_SHA256="$(custody_regular_file_sha256 "${PYTHON_BIN}")"',
                    'TOOLCHAIN_PINS_CUSTODY_SHA256="$(custody_regular_file_sha256 "${ROOT}/tools/toolchain-pins.json")"',
                )
            ),
        )
        self.assertEqual(completed.returncode, 65, completed.stderr)
        self.assertIn("RECHECK-PASSED", completed.stdout)
        self.assertNotIn("DRIFT-ACCEPTED", completed.stdout)
        self.assertIn("Pinned home Flutter/JDK recheck failed", completed.stderr)

    def test_producer_main_flow_uses_the_pinned_home_toolchains(self) -> None:
        self.assertNotIn("release_android_toolchain_archive_custody.sh\"\n", MAC_SOURCE)
        self.assertNotRegex(MAC_SOURCE, r"(?m)^\s*(source|\.)\s+[\"$/]")
        prepare = MAC_SOURCE.index(
            'wins_release_android_toolchains_prepare "${ROOT}/tools/toolchain-pins.json"'
        )
        self.assertLess(MAC_SOURCE.index("\nprepare_pinned_release_python\n"), prepare)
        self.assertLess(prepare, MAC_SOURCE.index('FLUTTER_BIN="${WINS_RELEASE_FLUTTER_BIN}"'))
        self.assertLess(prepare, MAC_SOURCE.index("wins_release_android_flutter --version --machine"))
        self.assertNotIn("wins_release_android_toolchains_cleanup", _mac_shell_function("cleanup"))
        custody = _mac_shell_function("assert_reviewed_toolchain_custody")
        self.assertIn("wins_release_android_toolchains_verify", custody)
        self.assertIn('"${HOME}/.local/toolchains/jdk-${java_version}"', MAC_SOURCE)
        self.assertIn('"${HOME}/.local/flutter-${REQUIRED_FLUTTER_VERSION}"', MAC_SOURCE)
        self.assertIn("tools.flutter.installed_tree_sha256", MAC_SOURCE)
        runner = _mac_shell_function("_wins_release_android_toolchain_exec")
        # Only the JDK-tool branch, which carries no signing value, may use
        # env -i. Both branches that can carry a signing value (flutter-build
        # and keytool with the store password) go through
        # run_with_exact_environment, never through an env command line.
        self.assertEqual(runner.count("/usr/bin/env -i"), 1)
        self.assertEqual(runner.count("run_with_exact_environment"), 2)
        jdk_branch = runner[runner.index("    java|jarsigner|keytool)"):runner.index("    keytool-store-password)")]
        self.assertIn("/usr/bin/env -i", jdk_branch)
        self.assertNotIn("PASSWORD", jdk_branch)
        self.assertNotIn("/usr/bin/env", runner[runner.index("    keytool-store-password)"):])
        self.assertNotIn("bin/flutter\"", runner)

    def test_real_home_toolchains_match_their_pins(self) -> None:
        java = pathlib.Path.home() / ".local" / "toolchains" / f"jdk-{TOOLCHAIN_PINS['java']['version']}"
        flutter = pathlib.Path.home() / ".local" / f"flutter-{EXPECTED_FLUTTER_VERSION}"
        if not java.is_dir() or not flutter.is_dir():
            self.skipTest("pinned home JDK and Flutter are not installed on this host")
        java_pin = TOOLCHAIN_PINS["java"]["install_tree_sha256"][self.key]
        flutter_pin = TOOLCHAIN_PINS["flutter"]["installed_tree_sha256"][self.key]
        real = self._run(
            "verify_home_toolchain_tree java " + shlex.quote(str(java)), root=ROOT
        )
        self.assertEqual(real.returncode, 0, real.stderr)
        self.assertEqual(real.stdout.strip(), java_pin)
        unsafe = []
        for current, directories, files in os.walk(flutter):
            relative_dir = os.path.relpath(current, flutter)
            directories[:] = [
                name for name in directories
                if not any(
                    os.path.normpath(os.path.join(relative_dir, name)) == item
                    for item in _FLUTTER_RUNTIME_STATE
                )
            ]
            for name in files + directories:
                path = os.path.join(current, name)
                relative = os.path.normpath(os.path.relpath(path, flutter))
                if any(relative == item for item in _FLUTTER_RUNTIME_STATE):
                    continue
                info = os.lstat(path)
                if not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022:
                    unsafe.append(relative)
        real = self._run(
            "verify_home_toolchain_tree flutter " + shlex.quote(str(flutter)), root=ROOT
        )
        if not unsafe:
            self.assertEqual(real.returncode, 0, real.stderr)
            self.assertEqual(real.stdout.strip(), flutter_pin)
            return
        # The installed tree carries group-writable files; the verifier must
        # refuse them, and the same content with safe modes must match the pin.
        self.assertNotEqual(real.returncode, 0)
        self.assertIn("group or world writable", real.stderr)
        clone = self.base / "real-clone" / flutter.name
        clone.parent.mkdir()
        subprocess.run(["/bin/cp", "-cR", str(flutter), str(clone)], check=True, timeout=600)
        subprocess.run(["/bin/chmod", "-R", "go-w", str(clone)], check=True, timeout=600)
        cloned = self._run(
            "verify_home_toolchain_tree flutter " + shlex.quote(str(clone)), root=ROOT
        )
        self.assertEqual(cloned.returncode, 0, cloned.stderr)
        self.assertEqual(cloned.stdout.strip(), flutter_pin)
        stamp = clone / "bin" / "cache" / "engine.stamp"
        stamp.write_bytes(stamp.read_bytes() + b"\n")
        changed = self._run(
            "verify_home_toolchain_tree flutter " + shlex.quote(str(clone)), root=ROOT
        )
        self.assertNotEqual(changed.returncode, 0)
        self.assertIn("installed tree digest mismatch", changed.stderr)


@unittest.skipUnless(sys.platform == "darwin", "macOS Android producer functions")
class RunWithExactEnvironmentTests(unittest.TestCase):
    """run_with_exact_environment gives a command exactly the assignments it is given.

    The function is extracted from build_android_release_macos.sh and run under
    /bin/bash explicitly (3.2 on macOS) with set -Eeuo pipefail, like the
    producer, both plain and in privileged mode (-p). The reference behaviour is
    `env -i NAME=value command`, whose environment holds nothing else. Targets
    here are /usr/bin/env and /bin/sh builtins so no shell the test itself starts
    can add variables to what it reports.
    """

    SHELL_FLAG_SETS = ((), ("-p",))

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.base = pathlib.Path(self._temp.name).resolve()

    def _run(
        self,
        body: str,
        *,
        stdin: str = "",
        ambient_env: dict | None = None,
        flags: tuple = (),
        interpreter: str = "/usr/bin/python3",
    ) -> subprocess.CompletedProcess:
        harness = "\n".join(
            (
                "set -Eeuo pipefail",
                f"PIN_PYTHON_BIN={shlex.quote(interpreter)}",
                _mac_shell_function("run_with_exact_environment"),
                "export FOO=ambient-foo JAVA_TOOL_OPTIONS=-Dhostile=1",
                "UNEXPORTED=plain-shell-variable",
                "WINS_ANDROID_KEY_PASSWORD=key-password-fixture",
                body,
            )
        )
        return subprocess.run(
            ["/bin/bash", *flags, "-c", harness],
            env={"HOME": "/nonexistent-home", "PATH": "/usr/bin:/bin", **(ambient_env or {})},
            input=stdin,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )

    @staticmethod
    def _environment(stdout: str) -> dict:
        return dict(line.split("=", 1) for line in stdout.splitlines() if "=" in line)

    def test_child_receives_exactly_the_assignments_and_nothing_else(self) -> None:
        for flags in self.SHELL_FLAG_SETS:
            with self.subTest(flags=flags):
                completed = self._run(
                    "run_with_exact_environment A=1 'B=two words' 'C=x=y' "
                    "WINS_ANDROID_KEY_PASSWORD=\"${WINS_ANDROID_KEY_PASSWORD}\" -- /usr/bin/env",
                    flags=flags,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                # No PWD, OLDPWD, SHLVL or _ is excluded from this comparison.
                self.assertEqual(
                    self._environment(completed.stdout),
                    {
                        "A": "1",
                        "B": "two words",
                        "C": "x=y",
                        "WINS_ANDROID_KEY_PASSWORD": "key-password-fixture",
                    },
                )

    def test_ambient_variables_cannot_reach_shadow_or_break_the_helper(self) -> None:
        # Inherited names equal to the helper's own locals, to the shell level
        # counter, to the variables bash maintains, and names that are not valid
        # shell identifiers must neither reach the child nor change the outcome.
        for ambient in (
            {"assignments": "ambient-array"},
            {"exported_name": "ambient-name"},
            {"SHLVL": "73"},
            {"PWD": "/ambient/pwd", "OLDPWD": "/ambient/oldpwd", "_": "/ambient/underscore"},
            {"FOO.BAR": "ambient-invalid-name"},
            {"FOO-BAR": "ambient-dash", "1STARTS_WITH_DIGIT": "x"},
            {"BASH_FUNC_poison%%": "() { :; }"},
            {"PIN_PYTHON_BIN": "/nonexistent/hostile-python", "PYTHONPATH": "/ambient", "PYTHONHOME": "/ambient"},
        ):
            for flags in self.SHELL_FLAG_SETS:
                with self.subTest(ambient=ambient, flags=flags):
                    completed = self._run(
                        "run_with_exact_environment A=1 -- /usr/bin/env",
                        ambient_env=ambient,
                        flags=flags,
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertEqual(self._environment(completed.stdout), {"A": "1"})

    def test_the_helper_is_a_clean_bootstrap_and_not_a_shell_export_trick(self) -> None:
        # Structure that a regression to builtin exports would break: env -i starts
        # the bootstrap interpreter, which receives the assignments on a pipe and
        # builds the child environment explicitly. No assignment is ever
        # expanded on the env command line.
        helper = _mac_shell_function("run_with_exact_environment")
        self.assertEqual(helper.count("/usr/bin/env -i"), 1)
        self.assertIn('/usr/bin/env -i "${interpreter}" -I -S -c', helper)
        self.assertIn("os.execvpe(arguments[0], arguments, environment)", helper)
        self.assertIn("builtin printf '%s\\0' \"${assignments[@]}\"", helper)
        self.assertIn("<(", helper)
        for forbidden in ('exec "$@"', "compgen", "export -n", "export \"${assignments", "env -i \"${assignments"):
            self.assertNotIn(forbidden, helper)
        command = helper[helper.index("/usr/bin/env -i"):]
        command = command[command.index("<("):]
        # After the pipe, only the count and the caller's command words follow.
        self.assertTrue(command.rstrip().endswith('"${#assignments[@]}" "$@"\n}'.rstrip()))
        self.assertEqual(command.count('"${assignments[@]}"'), 1)

    def test_empty_assignment_set_has_an_empty_environment(self) -> None:
        for flags in self.SHELL_FLAG_SETS:
            with self.subTest(flags=flags):
                completed = self._run(
                    "run_with_exact_environment -- /usr/bin/env", ambient_env={"SHLVL": "9"}, flags=flags
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stdout, "")

    def test_an_unexported_shell_variable_is_not_passed_unless_assigned(self) -> None:
        completed = self._run("run_with_exact_environment A=1 -- /usr/bin/env")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        env = self._environment(completed.stdout)
        for name in ("UNEXPORTED", "WINS_ANDROID_KEY_PASSWORD", "FOO", "JAVA_TOOL_OPTIONS", "HOME", "PATH"):
            self.assertNotIn(name, env)

    def test_the_command_is_executed_directly_with_stdin_arguments_and_status(self) -> None:
        completed = self._run(
            "run_with_exact_environment A=1 -- /bin/sh -c 'cat; exit 7' ignored-name",
            stdin="piped-through-stdin\n",
        )
        self.assertEqual(completed.returncode, 7, completed.stderr)
        self.assertEqual(completed.stdout, "piped-through-stdin\n")

    def _status_line(self, invocation: str) -> str:
        completed = self._run(f"if {invocation}; then echo STATUS-0; else echo STATUS-$?; fi")
        lines = [line for line in completed.stdout.splitlines() if line.startswith("STATUS-")]
        self.assertEqual(len(lines), 1, completed.stderr)
        return lines[0]

    def test_exit_statuses_and_path_lookup_match_env_dash_i(self) -> None:
        script = self.base / "not-executable"
        script.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        script.chmod(0o600)
        expected = {
            "/nonexistent/command": "STATUS-127",
            shlex.quote(str(script)): "STATUS-126",
            "/bin/sh -c 'exit 3'": "STATUS-3",
            "/usr/bin/true": "STATUS-0",
            "/usr/bin/false": "STATUS-1",
        }
        for command, status in expected.items():
            with self.subTest(command=command):
                self.assertEqual(self._status_line(f"/usr/bin/env -i A=1 {command}"), status)
                self.assertEqual(
                    self._status_line(f"run_with_exact_environment A=1 -- {command}"), status
                )
        # A command name without a slash is looked up on the PATH that the
        # assignments carry, exactly as env -i does.
        reference = self._run("/usr/bin/env -i PATH=/bin:/usr/bin ls /dev/null")
        completed = self._run("run_with_exact_environment PATH=/bin:/usr/bin -- ls /dev/null")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, reference.stdout)

    def test_the_child_inherits_no_file_descriptor_beyond_the_callers(self) -> None:
        listing = "/bin/sh -c 'for fd in 0 1 2 3 4 5 6 7 8 9; do if [ -e /dev/fd/$fd ]; then echo fd$fd; fi; done'"
        reference = self._run(f"/usr/bin/env -i A=1 {listing}")
        completed = self._run(f"run_with_exact_environment A=1 -- {listing}")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, reference.stdout)

    def test_malformed_calls_are_refused_and_run_nothing(self) -> None:
        for call in (
            "run_with_exact_environment A=1 /usr/bin/env",
            "run_with_exact_environment A=1 --",
            "run_with_exact_environment --",
            "run_with_exact_environment justaname -- /usr/bin/env",
            "run_with_exact_environment 1BAD=1 -- /usr/bin/env",
            "run_with_exact_environment BAD-NAME=1 -- /usr/bin/env",
            "run_with_exact_environment FOO.BAR=1 -- /usr/bin/env",
        ):
            with self.subTest(call=call):
                completed = self._run(f"if {call}; then echo RAN; else echo REFUSED-$?; fi")
                self.assertNotIn("RAN", completed.stdout)
                self.assertRegex(completed.stdout, r"REFUSED-(64|126)")

    def test_an_unusable_bootstrap_interpreter_is_refused_and_runs_nothing(self) -> None:
        link = self.base / "linked-python"
        os.symlink("/usr/bin/python3", link)
        for interpreter in ("/nonexistent/python", str(self.base), str(link)):
            with self.subTest(interpreter=interpreter):
                completed = self._run(
                    "if run_with_exact_environment A=1 -- /usr/bin/env; then echo RAN; else echo REFUSED-$?; fi",
                    interpreter=interpreter,
                )
                self.assertNotIn("RAN", completed.stdout)
                self.assertRegex(completed.stdout, r"REFUSED-\d+")

    def test_transport_read_failure_returns_70_without_running_the_target(self) -> None:
        wrapper = self.base / "closed-transport-python"
        wrapper.write_text(
            "#!/usr/bin/python3\n"
            "import os, sys\n"
            "for argument in sys.argv[1:]:\n"
            "    if argument.startswith('/dev/fd/'):\n"
            "        os.close(int(argument.rsplit('/', 1)[1]))\n"
            "os.execv('/usr/bin/python3', ['/usr/bin/python3', *sys.argv[1:]])\n",
            encoding="ascii",
        )
        wrapper.chmod(0o700)
        completed = self._run(
            "run_with_exact_environment A=1 -- /bin/echo TARGET-RAN",
            interpreter=str(wrapper),
        )
        self.assertEqual(completed.returncode, 70, completed.stderr)
        self.assertEqual(completed.stdout, "")
        self.assertNotIn("Traceback", completed.stderr)

    def test_the_secret_value_is_never_an_argument_of_any_external_command(self) -> None:
        # Neither /usr/bin/env nor the bootstrap interpreter may see the value on
        # its command line: the interpreter here is a wrapper that records its
        # arguments before it hands over to the real one.
        log = self.base / "interpreter.argv"
        wrapper = self.base / "recording-python"
        wrapper.write_text(
            "#!/bin/sh\n"
            f'for argument in "$@"; do printf "%s\\n" "$argument"; done > {shlex.quote(str(log))}\n'
            'exec /usr/bin/python3 "$@"\n',
            encoding="ascii",
        )
        wrapper.chmod(0o755)
        completed = self._run(
            _ENV_ARGUMENT_GUARD
            + '\nrun_with_exact_environment WINS_ANDROID_KEY_PASSWORD="${WINS_ANDROID_KEY_PASSWORD}" '
            "-- /bin/sh -c 'printf \"%s\\n\" \"$WINS_ANDROID_KEY_PASSWORD\"'",
            interpreter=str(wrapper),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("SECRET-IN-ENV-ARGUMENTS", completed.stderr)
        self.assertEqual(completed.stdout, "key-password-fixture\n")
        recorded = log.read_text(encoding="utf-8")
        self.assertTrue(recorded)
        self.assertNotIn("key-password-fixture", recorded)
        self.assertRegex(recorded, r"/dev/fd/\d+")


if __name__ == "__main__":
    unittest.main()
