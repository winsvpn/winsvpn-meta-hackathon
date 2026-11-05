#!/usr/bin/env python3
"""Hostile tests for the fixed ReleasePython native owner bootstrap."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import textwrap
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/macos_release_python_owner_bootstrap.c"
BUILD = ROOT / "tools/build_macos_release_python_owner_bootstrap.sh"
BUILD_SUPPORT = ROOT / "tools/macos_release_python_owner_bootstrap_build_support.py"
PREFLIGHT = ROOT / "tools/install_macos_release_python_owner_provision.sh"
CONTROLLER_SOURCE = ROOT / "tools/macos_release_python_owner_provision.py"
CLANG = Path(
    "/Applications/Xcode.app/Contents/Developer/Toolchains/"
    "XcodeDefault.xctoolchain/usr/bin/clang"
)
CODESIGN = Path("/usr/bin/codesign")
DEVELOPER = Path("/Applications/Xcode.app/Contents/Developer")
ZERO = "0" * 64
EXACT_ENV = {"HOME": "/var/root", "TMPDIR": "/private/tmp"}
CUSTODY_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_uid",
    "st_gid",
    "st_size",
    "st_flags",
    "st_mtime_ns",
    "st_ctime_ns",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def custody(path: Path) -> tuple[object, ...]:
    info = path.stat()
    return tuple(getattr(info, field) for field in CUSTODY_FIELDS)


def clear_flags(path: Path) -> None:
    try:
        os.chflags(path, 0, follow_symlinks=False)
    except (FileNotFoundError, NotImplementedError, PermissionError):
        pass


class BootstrapFixture:
    def __init__(self, *, hook: bool = False, crash: bool = False) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".native-owner-bootstrap-", dir=ROOT
        )
        self.root = Path(self.temporary.name)
        self.authority = self.root / "Library/WinsVPN/ReleasePythonAuthority/v2"
        self.authority.mkdir(parents=True, mode=0o700)
        self.bootstrap = self.authority / "owner-installer-bootstrap"
        self.controller_destination = self.authority / "owner-provision"
        self.launcher_destination = self.authority / "owner-launcher"
        self.inputs = self.root / "owner-inputs"
        self.inputs.mkdir(mode=0o700)
        self.controller = self.inputs / "owner-provision.py"
        self.controller.write_bytes(CONTROLLER_SOURCE.read_bytes())
        self.controller.chmod(0o644)
        self.controller_hash = sha256(self.controller)
        self.launcher_source = self.inputs / "fixture-launcher.c"
        self.launcher = self.inputs / "owner-launcher"
        self.hook = self.root / "bootstrap-hook"
        self.sdk = subprocess.run(
            ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"],
            check=True,
            capture_output=True,
            text=True,
            env={"DEVELOPER_DIR": str(DEVELOPER)},
        ).stdout.strip()
        self._compile_launcher()
        self.launcher_hash = sha256(self.launcher)
        self.compile_bootstrap(hook=hook, crash=crash)

    def _compile_launcher(
        self,
        *,
        controller_hash: str | None = None,
        launcher_source: Path | None = None,
        launcher: Path | None = None,
    ) -> None:
        selected_controller_hash = controller_hash or self.controller_hash
        selected_launcher_source = launcher_source or self.launcher_source
        selected_launcher = launcher or self.launcher
        selected_launcher_source.write_text(
            textwrap.dedent(
                f"""
                #include <stdio.h>
                __attribute__((used)) static const char controller_sha256[] =
                    "{selected_controller_hash}";
                int main(void) {{
                    return puts(controller_sha256) < 0;
                }}
                """
            ),
            encoding="ascii",
        )
        subprocess.run(
            [
                str(CLANG),
                "-std=c17",
                "-Os",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                "-isysroot",
                self.sdk,
                "-mmacosx-version-min=13.0",
                "-Wl,-no_adhoc_codesign",
                str(selected_launcher_source),
                "-o",
                str(selected_launcher),
            ],
            check=True,
            cwd=ROOT,
            env={"PATH": "/usr/bin:/bin", "TMPDIR": "/private/tmp"},
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                str(CODESIGN),
                "--force",
                "--sign",
                "-",
                "--timestamp=none",
                "--identifier",
                "org.winsvpn.releasepython.owner-launcher-test",
                str(selected_launcher),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        selected_launcher.chmod(0o555)

    def compile_bootstrap(self, *, hook: bool = False, crash: bool = False) -> None:
        temporary = self.root / "owner-installer-bootstrap.new"
        defines = [
            f'-DWINS_BOOTSTRAP_PATH="{self.bootstrap}"',
            f'-DWINS_DESTINATION_PARENT="{self.authority}"',
            f"-DWINS_EXPECTED_UID={os.getuid()}",
            f"-DWINS_EXPECTED_GID={os.getgid()}",
            "-DWINS_REQUIRE_ROOT=0",
            "-DWINS_REQUIRE_SELF_IMMUTABLE=0",
            "-DWINS_ALLOW_EXPECTED_UID_ANCESTRY=1",
            "-DWINS_IMMUTABLE_FLAG=UF_IMMUTABLE",
            f'-DWINS_BUILD_SOURCE_SHA256="{ZERO}"',
            f'-DWINS_BUILD_SCRIPT_SHA256="{ZERO}"',
            f'-DWINS_BUILD_COMPILER_SHA256="{ZERO}"',
            f'-DWINS_BUILD_LINKER_SHA256="{ZERO}"',
            f'-DWINS_BUILD_CODESIGN_SHA256="{ZERO}"',
            f'-DWINS_BUILD_INPUT_CLOSURE_SHA256="{ZERO}"',
        ]
        if hook:
            defines.append(f'-DWINS_TEST_HOOK_PATH="{self.hook}"')
        if crash:
            defines.append("-DWINS_TEST_CRASH_AFTER_CONTROLLER=1")
        subprocess.run(
            [
                str(CLANG),
                "-std=c17",
                "-Os",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                "-isysroot",
                self.sdk,
                "-mmacosx-version-min=13.0",
                "-Wl,-no_adhoc_codesign",
                *defines,
                str(SOURCE),
                "-lproc",
                "-o",
                str(temporary),
            ],
            check=True,
            cwd=ROOT,
            env={"PATH": "/usr/bin:/bin", "TMPDIR": "/private/tmp"},
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                str(CODESIGN),
                "--force",
                "--sign",
                "-",
                "--timestamp=none",
                "--identifier",
                "org.winsvpn.releasepython.owner-bootstrap-test",
                str(temporary),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        temporary.chmod(0o555)
        temporary.replace(self.bootstrap)

    def command(
        self,
        controller: Path | None = None,
        controller_hash: str | None = None,
        launcher: Path | None = None,
        launcher_hash: str | None = None,
    ) -> list[str]:
        return [
            str(self.bootstrap),
            "install",
            str(controller or self.controller),
            controller_hash or self.controller_hash,
            str(launcher or self.launcher),
            launcher_hash or self.launcher_hash,
        ]

    def run(self, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self.command(**kwargs),
            cwd=ROOT,
            env=EXACT_ENV,
            capture_output=True,
            text=True,
            timeout=20,
        )

    def run_install_self(
        self, candidate: Path, expected: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(candidate), "install-self", str(candidate), expected or sha256(candidate)],
            cwd=ROOT,
            env=EXACT_ENV,
            capture_output=True,
            text=True,
            timeout=20,
        )

    def assert_installed(self, testcase: unittest.TestCase) -> None:
        for path, expected in (
            (self.controller_destination, self.controller_hash),
            (self.launcher_destination, self.launcher_hash),
        ):
            info = path.stat()
            testcase.assertEqual(sha256(path), expected)
            testcase.assertEqual(stat.S_IMODE(info.st_mode), 0o555)
            testcase.assertEqual(info.st_uid, os.getuid())
            testcase.assertEqual(info.st_gid, os.getgid())
            testcase.assertEqual(info.st_nlink, 1)
            testcase.assertTrue(info.st_flags & stat.UF_IMMUTABLE)

    def close(self) -> None:
        subprocess.run(
            ["/bin/chmod", "-RN", str(self.root)],
            check=False,
            capture_output=True,
            text=True,
        )
        for path in self.root.rglob("*"):
            clear_flags(path)
        clear_flags(self.root)
        self.temporary.cleanup()


@unittest.skipUnless(
    os.uname().sysname == "Darwin" and CLANG.is_file(),
    "native macOS bootstrap tests require Xcode clang",
)
class NativeOwnerBootstrapTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = BootstrapFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def assert_leaf_unchanged(
        self,
        path: Path,
        expected_bytes: bytes,
        expected_custody: tuple[object, ...],
    ) -> None:
        info = path.stat()
        self.assertEqual(path.read_bytes(), expected_bytes)
        self.assertEqual(custody(path), expected_custody)
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o555)
        self.assertEqual(info.st_uid, os.getuid())
        self.assertEqual(info.st_gid, os.getgid())
        self.assertEqual(info.st_nlink, 1)
        self.assertEqual(info.st_flags, stat.UF_IMMUTABLE)

    def assert_sources_unchanged(
        self,
        expected: dict[Path, tuple[bytes, tuple[object, ...]]],
    ) -> None:
        for path, (expected_bytes, expected_custody) in expected.items():
            self.assertEqual(path.read_bytes(), expected_bytes)
            self.assertEqual(custody(path), expected_custody)

    def test_install_self_is_create_only_digest_bound_and_self_sealing(self) -> None:
        candidate = self.fixture.inputs / "owner-installer-bootstrap-candidate"
        self.fixture.bootstrap.replace(candidate)
        candidate_hash = sha256(candidate)

        installed = self.fixture.run_install_self(candidate)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        info = self.fixture.bootstrap.stat()
        self.assertEqual(sha256(self.fixture.bootstrap), candidate_hash)
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o555)
        self.assertEqual(info.st_uid, os.getuid())
        self.assertEqual(info.st_gid, os.getgid())
        self.assertEqual(info.st_nlink, 1)
        self.assertEqual(info.st_flags, stat.UF_IMMUTABLE)
        installed_inode = info.st_ino

        retry = self.fixture.run_install_self(candidate)
        self.assertEqual(retry.returncode, 0, retry.stderr)
        self.assertIn("already installed", retry.stdout)
        self.assertEqual(self.fixture.bootstrap.stat().st_ino, installed_inode)

    def test_install_self_refuses_wrong_digest_and_preexisting_target(self) -> None:
        candidate = self.fixture.inputs / "owner-installer-bootstrap-candidate"
        self.fixture.bootstrap.replace(candidate)
        wrong = self.fixture.run_install_self(candidate, "1" * 64)
        self.assertNotEqual(wrong.returncode, 0)
        self.assertFalse(self.fixture.bootstrap.exists())

        self.fixture.bootstrap.write_text("unreviewed\n", encoding="ascii")
        self.fixture.bootstrap.chmod(0o555)
        refused = self.fixture.run_install_self(candidate)
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(self.fixture.bootstrap.read_text(encoding="ascii"), "unreviewed\n")

    def test_exact_install_and_idempotent_retry_preserve_inodes(self) -> None:
        completed = self.fixture.run()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.fixture.assert_installed(self)
        identities = {
            path: (path.stat().st_dev, path.stat().st_ino)
            for path in (
                self.fixture.controller_destination,
                self.fixture.launcher_destination,
            )
        }
        retry = self.fixture.run()
        self.assertEqual(retry.returncode, 0, retry.stderr)
        self.assertIn("already installed", retry.stdout)
        for path, expected in identities.items():
            self.assertEqual((path.stat().st_dev, path.stat().st_ino), expected)

    def test_wrong_arguments_hash_forms_environment_and_roles_refuse(self) -> None:
        commands = [
            [str(self.fixture.bootstrap)],
            self.fixture.command() + ["extra"],
            self.fixture.command(controller_hash="A" * 64),
            self.fixture.command(controller_hash=ZERO),
            self.fixture.command(controller=Path("relative-controller")),
            self.fixture.command(
                controller=self.fixture.launcher,
                controller_hash=self.fixture.launcher_hash,
                launcher=self.fixture.controller,
                launcher_hash=self.fixture.controller_hash,
            ),
        ]
        for command in commands:
            with self.subTest(command=command[1:3]):
                completed = subprocess.run(
                    command,
                    cwd=ROOT,
                    env=EXACT_ENV,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertFalse(self.fixture.controller_destination.exists())
                self.assertFalse(self.fixture.launcher_destination.exists())
        polluted = subprocess.run(
            self.fixture.command(),
            cwd=ROOT,
            env={**EXACT_ENV, "PATH": "/usr/bin:/bin"},
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(polluted.returncode, 0)
        self.assertIn("environment", polluted.stderr)

    def test_source_leaf_symlink_hardlink_and_ancestor_symlink_refuse(self) -> None:
        saved = self.fixture.controller.with_suffix(".saved")
        self.fixture.controller.rename(saved)
        self.fixture.controller.symlink_to(saved)
        symlinked = self.fixture.run()
        self.assertNotEqual(symlinked.returncode, 0)
        self.fixture.controller.unlink()
        saved.rename(self.fixture.controller)

        hardlink = self.fixture.inputs / "controller-hardlink"
        os.link(self.fixture.controller, hardlink)
        linked = self.fixture.run()
        self.assertNotEqual(linked.returncode, 0)
        hardlink.unlink()

        real_inputs = self.fixture.inputs.rename(self.fixture.root / "real-inputs")
        self.fixture.inputs.symlink_to(real_inputs, target_is_directory=True)
        ancestor = self.fixture.run(
            controller=self.fixture.inputs / self.fixture.controller.name,
            launcher=self.fixture.inputs / self.fixture.launcher.name,
        )
        self.assertNotEqual(ancestor.returncode, 0)
        self.assertFalse(self.fixture.controller_destination.exists())
        self.assertFalse(self.fixture.launcher_destination.exists())

    def test_destination_symlink_and_mismatched_existing_leaf_refuse(self) -> None:
        outside = self.fixture.root / "outside"
        outside.write_text("outside\n", encoding="ascii")
        self.fixture.controller_destination.symlink_to(outside)
        symbolic = self.fixture.run()
        self.assertNotEqual(symbolic.returncode, 0)
        self.fixture.controller_destination.unlink()
        self.fixture.controller_destination.write_text("wrong\n", encoding="ascii")
        self.fixture.controller_destination.chmod(0o555)
        mismatched = self.fixture.run()
        self.assertNotEqual(mismatched.returncode, 0)
        self.assertEqual(outside.read_text(encoding="ascii"), "outside\n")
        self.assertFalse(self.fixture.launcher_destination.exists())

    def test_sealed_mismatched_pair_refuses_without_partial_advance(self) -> None:
        installed = self.fixture.run()
        self.assertEqual(installed.returncode, 0, installed.stderr)
        self.fixture.assert_installed(self)
        destinations = (
            self.fixture.controller_destination,
            self.fixture.launcher_destination,
        )
        original = {path: (path.read_bytes(), custody(path)) for path in destinations}

        new_controller = self.fixture.inputs / "owner-provision-new.py"
        new_controller.write_bytes(
            CONTROLLER_SOURCE.read_bytes() + b"\n# sealed mismatch hostile fixture\n"
        )
        new_controller.chmod(0o644)
        new_controller_hash = sha256(new_controller)
        new_launcher_source = self.fixture.inputs / "fixture-launcher-new.c"
        new_launcher = self.fixture.inputs / "owner-launcher-new"
        self.fixture._compile_launcher(
            controller_hash=new_controller_hash,
            launcher_source=new_launcher_source,
            launcher=new_launcher,
        )
        new_launcher_hash = sha256(new_launcher)
        sources = {
            path: (path.read_bytes(), custody(path))
            for path in (
                self.fixture.controller,
                self.fixture.launcher,
                new_controller,
                new_launcher,
            )
        }
        authority_before = custody(self.fixture.authority)

        refused = self.fixture.run(
            controller=new_controller,
            controller_hash=new_controller_hash,
            launcher=new_launcher,
            launcher_hash=new_launcher_hash,
        )
        self.assertEqual(refused.returncode, 126, refused.stderr)
        self.assertIn(
            "installed leaf digest is not the owner-selected digest",
            refused.stderr,
        )
        for path, (expected_bytes, expected_custody) in original.items():
            self.assert_leaf_unchanged(path, expected_bytes, expected_custody)
        self.assert_sources_unchanged(sources)
        self.assertEqual(custody(self.fixture.authority), authority_before)
        self.assertEqual(
            sorted(child.name for child in self.fixture.authority.iterdir()),
            ["owner-installer-bootstrap", "owner-launcher", "owner-provision"],
        )

        clear_flags(self.fixture.controller_destination)
        self.fixture.controller_destination.unlink()
        launcher_bytes, launcher_custody = original[
            self.fixture.launcher_destination
        ]
        partial_authority_before = custody(self.fixture.authority)
        partial = self.fixture.run(
            controller=new_controller,
            controller_hash=new_controller_hash,
            launcher=new_launcher,
            launcher_hash=new_launcher_hash,
        )
        self.assertEqual(partial.returncode, 126, partial.stderr)
        self.assertIn(
            "installed leaf digest is not the owner-selected digest",
            partial.stderr,
        )
        self.assertFalse(self.fixture.controller_destination.exists())
        self.assert_leaf_unchanged(
            self.fixture.launcher_destination,
            launcher_bytes,
            launcher_custody,
        )
        self.assert_sources_unchanged(sources)
        self.assertEqual(custody(self.fixture.authority), partial_authority_before)
        self.assertEqual(
            sorted(child.name for child in self.fixture.authority.iterdir()),
            ["owner-installer-bootstrap", "owner-launcher"],
        )

        mixed = self.fixture.run(
            controller=new_controller,
            controller_hash=new_controller_hash,
            launcher=self.fixture.launcher,
            launcher_hash=self.fixture.launcher_hash,
        )
        self.assertEqual(mixed.returncode, 126, mixed.stderr)
        self.assertIn(
            "launcher bytes do not bind the selected controller SHA-256",
            mixed.stderr,
        )
        self.assertFalse(self.fixture.controller_destination.exists())
        self.assert_leaf_unchanged(
            self.fixture.launcher_destination,
            launcher_bytes,
            launcher_custody,
        )
        self.assert_sources_unchanged(sources)
        self.assertEqual(custody(self.fixture.authority), partial_authority_before)
        self.assertEqual(
            sorted(child.name for child in self.fixture.authority.iterdir()),
            ["owner-installer-bootstrap", "owner-launcher"],
        )

    def test_destination_acl_and_unexpected_pair_stage_entry_refuse(self) -> None:
        subprocess.run(
            [
                "/bin/chmod",
                "+a",
                "everyone allow add_file,delete_child",
                str(self.fixture.authority),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        acl = self.fixture.run()
        self.assertNotEqual(acl.returncode, 0)
        self.assertIn("ACL", acl.stderr)
        subprocess.run(
            ["/bin/chmod", "-N", str(self.fixture.authority)],
            check=True,
            capture_output=True,
            text=True,
        )
        pair = hashlib.sha256(
            (self.fixture.controller_hash + self.fixture.launcher_hash).encode("ascii")
        ).hexdigest()[:32]
        stage = self.fixture.authority / f".winsvpn-owner-bootstrap-stage-{pair}"
        stage.mkdir(mode=0o700)
        (stage / "unexpected").write_text("residue\n", encoding="ascii")
        residue = self.fixture.run()
        self.assertNotEqual(residue.returncode, 0)
        self.assertIn("unexpected entry", residue.stderr)
        self.assertFalse(self.fixture.controller_destination.exists())
        self.assertFalse(self.fixture.launcher_destination.exists())

    def test_path_replacement_after_descriptor_capture_refuses_before_publish(self) -> None:
        self.fixture.close()
        self.fixture = BootstrapFixture(hook=True)
        process = subprocess.Popen(
            self.fixture.command(),
            cwd=ROOT,
            env=EXACT_ENV,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(process.stdout.readline().strip(), "TEST_HOOK_READY")
        saved = self.fixture.controller.with_suffix(".held")
        original = self.fixture.controller.read_bytes()
        self.fixture.controller.rename(saved)
        self.fixture.controller.write_bytes(original)
        self.fixture.controller.chmod(0o644)
        Path(str(self.fixture.hook) + ".release").write_text("release\n", encoding="ascii")
        _stdout, stderr = process.communicate(timeout=10)
        self.assertNotEqual(process.returncode, 0)
        self.assertRegex(stderr, r"changed|identity")
        self.assertFalse(self.fixture.controller_destination.exists())
        self.assertFalse(self.fixture.launcher_destination.exists())

    def test_transient_in_place_mutation_is_detected_by_vnode_watch(self) -> None:
        self.fixture.close()
        self.fixture = BootstrapFixture(hook=True)
        process = subprocess.Popen(
            self.fixture.command(),
            cwd=ROOT,
            env=EXACT_ENV,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(process.stdout.readline().strip(), "TEST_HOOK_READY")
        original = self.fixture.controller.read_bytes()
        self.fixture.controller.write_bytes(original + b"# transient\n")
        self.fixture.controller.write_bytes(original)
        Path(str(self.fixture.hook) + ".release").write_text("release\n", encoding="ascii")
        _stdout, stderr = process.communicate(timeout=10)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("changed", stderr)
        self.assertFalse(self.fixture.controller_destination.exists())
        self.assertFalse(self.fixture.launcher_destination.exists())

    def test_exact_partial_crash_state_resumes_without_overwrite(self) -> None:
        self.fixture.close()
        self.fixture = BootstrapFixture(crash=True)
        crashed = self.fixture.run()
        self.assertEqual(crashed.returncode, 91, crashed.stderr)
        self.assertTrue(self.fixture.controller_destination.is_file())
        controller_inode = self.fixture.controller_destination.stat().st_ino
        self.assertFalse(self.fixture.launcher_destination.exists())
        self.fixture.compile_bootstrap()
        resumed = self.fixture.run()
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.fixture.assert_installed(self)
        self.assertEqual(self.fixture.controller_destination.stat().st_ino, controller_inode)

    def test_preflight_handoff_is_exact_native_cli_order(self) -> None:
        source = PREFLIGHT.read_text(encoding="utf-8")
        self.assertIn(
            "Bootstrap inputs: install %s %s %s %s\\n", source
        )
        self.assertIn(
            '"$source" "$controller_expected" "$launcher_source" "$launcher_expected"',
            source,
        )
        native = SOURCE.read_text(encoding="utf-8")
        self.assertIn('strcmp(argv[1], "install")', native)
        self.assertIn("argc != 6", native)
        self.assertIn('WINS_CONTROLLER_DESTINATION_NAME "owner-provision"', native)
        self.assertIn('WINS_LAUNCHER_DESTINATION_NAME "owner-launcher"', native)


@unittest.skipUnless(
    os.uname().sysname == "Darwin" and CLANG.is_file(),
    "deterministic producer test requires Xcode clang",
)
class NativeOwnerBootstrapProducerTest(unittest.TestCase):
    def test_warning_clean_deterministic_binary_and_full_manifest(self) -> None:
        producer = BUILD.read_text(encoding="utf-8")
        self.assertNotIn('"$SUPPORT" hold', producer)
        self.assertNotIn('"$SUPPORT" publish', producer)
        self.assertEqual(producer.count('os.lseek(4, 0, 0)'), 2)
        self.assertEqual(producer.count('os.read(4, 1048576)'), 2)
        with tempfile.TemporaryDirectory(
            prefix=".owner-bootstrap-producer-", dir=ROOT
        ) as temporary:
            root = Path(temporary)
            outputs: list[tuple[Path, Path, dict[str, str]]] = []
            for index in range(2):
                binary = root / f"owner-installer-bootstrap-{index}"
                manifest = root / f"owner-installer-bootstrap-{index}.manifest"
                completed = subprocess.run(
                    [str(BUILD), str(binary), str(manifest)],
                    check=True,
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    timeout=90,
                )
                self.assertEqual(completed.stderr, "")
                evidence = dict(
                    line.split("=", 1)
                    for line in completed.stdout.splitlines()
                    if "=" in line
                )
                self.assertEqual(evidence["bootstrap_sha256"], sha256(binary))
                self.assertEqual(evidence["manifest_sha256"], sha256(manifest))
                self.assertEqual(evidence["input_closure_sha256"], sha256(manifest))
                outputs.append((binary, manifest, evidence))
            self.assertEqual(outputs[0][0].read_bytes(), outputs[1][0].read_bytes())
            self.assertEqual(outputs[0][1].read_bytes(), outputs[1][1].read_bytes())
            lines = outputs[0][1].read_text(encoding="ascii").splitlines()
            self.assertEqual(
                lines[:4],
                [
                    "contract=winsvpn-macos-release-python-owner-bootstrap-build-closure-v1",
                    "schema_version=1",
                    "minimum_macos=13.0",
                    "codesign_identifier=org.winsvpn.releasepython.owner-installer-bootstrap",
                ],
            )
            records = lines[4:]
            self.assertTrue(records)
            paths = [line.split(" ", 3)[3] for line in records]
            self.assertEqual(paths, sorted(set(paths)))
            for required in (
                SOURCE,
                BUILD,
                BUILD_SUPPORT,
                CLANG,
                Path("/usr/bin/ld"),
                CODESIGN,
                Path("/bin/bash"),
                Path("/usr/bin/python3"),
                Path("/usr/bin/sort"),
            ):
                if required == Path("/usr/bin/ld"):
                    self.assertTrue(any(path.endswith("/usr/bin/ld") for path in paths))
                else:
                    self.assertIn(str(required), paths)
            self.assertTrue(any("MacOSX" in path and path.endswith(".h") for path in paths))

    def test_retained_closure_mutation_and_manifest_half_retry(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".owner-bootstrap-holder-", dir=ROOT
        ) as temporary:
            root = Path(temporary)
            retained = root / "retained-input"
            retained.write_bytes(b"retained\n")
            complete = root / "complete-inputs"
            leaves = root / "record-inputs"
            complete.write_text(f"{retained}\n", encoding="utf-8")
            leaves.write_text(f"{retained}\n", encoding="utf-8")
            closure = root / "closure.manifest"
            ready = root / "holder.ready"
            release = root / "holder.release"
            process = subprocess.Popen(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-S",
                    str(BUILD_SUPPORT),
                    "hold",
                    str(complete),
                    str(leaves),
                    str(closure),
                    str(ready),
                    str(release),
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and process.poll() is None:
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                self.assertIsNone(process.poll())
                original = closure.read_bytes()
                closure.chmod(0o600)
                closure.write_bytes(original + b"tampered\n")
                closure.write_bytes(original)
                closure.chmod(0o400)
                release.write_text("release\n", encoding="ascii")
                _stdout, stderr = process.communicate(timeout=5)
                self.assertNotEqual(process.returncode, 0)
                self.assertIn("vnode event", stderr)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

        with tempfile.TemporaryDirectory(
            prefix=".owner-bootstrap-half-retry-", dir=ROOT
        ) as temporary:
            root = Path(temporary)
            seed_binary = root / "seed-bootstrap"
            seed_manifest = root / "seed-bootstrap.manifest"
            subprocess.run(
                [str(BUILD), str(seed_binary), str(seed_manifest)],
                check=True,
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=90,
            )
            target_binary = root / "owner-installer-bootstrap"
            target_manifest = root / "owner-installer-bootstrap.manifest"
            shutil.copy2(seed_binary, target_binary)
            target_binary.chmod(0o555)
            retained_inode = target_binary.stat().st_ino
            completed = subprocess.run(
                [str(BUILD), str(target_binary), str(target_manifest)],
                check=True,
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=90,
            )
            evidence = dict(
                line.split("=", 1)
                for line in completed.stdout.splitlines()
                if "=" in line
            )
            self.assertEqual(target_binary.stat().st_ino, retained_inode)
            self.assertEqual(sha256(target_binary), evidence["bootstrap_sha256"])
            self.assertEqual(sha256(target_manifest), evidence["manifest_sha256"])

    def test_production_binary_refuses_non_root_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".owner-bootstrap-nonroot-", dir=ROOT
        ) as temporary:
            root = Path(temporary)
            binary = root / "owner-installer-bootstrap"
            manifest = root / "owner-installer-bootstrap.manifest"
            subprocess.run(
                [str(BUILD), str(binary), str(manifest)],
                check=True,
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=90,
            )
            completed = subprocess.run(
                [binary, "install", "/private/tmp/controller", "1" * 64,
                 "/private/tmp/launcher", "2" * 64],
                cwd=ROOT,
                env=EXACT_ENV,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("exact root:wheel", completed.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
