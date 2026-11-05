#!/usr/bin/env python3
"""Hostile tests for the fixed ReleasePython native owner updater."""

from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import os
from pathlib import Path
import resource
import shutil
import stat
import subprocess
import tempfile
import textwrap
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/macos_release_python_owner_updater.c"
CLANG = Path(
    "/Applications/Xcode.app/Contents/Developer/Toolchains/"
    "XcodeDefault.xctoolchain/usr/bin/clang"
)
CODESIGN = Path("/usr/bin/codesign")
DEVELOPER = Path("/Applications/Xcode.app/Contents/Developer")
EXACT_ENV = {"HOME": "/var/root", "TMPDIR": "/private/tmp"}
EVIDENCE = "1" * 64


def load_build_support() -> object:
    path = ROOT / "tools/macos_release_python_owner_updater_build_support.py"
    spec = importlib.util.spec_from_file_location("owner_updater_build_support", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load owner updater build support")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def clear_flags(path: Path) -> None:
    try:
        os.chflags(path, 0, follow_symlinks=False)
    except (FileNotFoundError, NotImplementedError, PermissionError):
        pass


def immutable(path: Path) -> bool:
    immutable_flags = stat.UF_IMMUTABLE | getattr(stat, "SF_IMMUTABLE", 0)
    return bool(getattr(os.lstat(path), "st_flags", 0) & immutable_flags)


class UpdaterFixture:
    def __init__(
        self,
        *,
        crash_at: int | None = None,
        hook: bool = False,
        wrong_old_controller: bool = False,
        mismatched_new_launcher: bool = False,
        production_boundary: bool = False,
        root_parent: Path | None = None,
    ) -> None:
        self.production_boundary = production_boundary
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".native-owner-updater-",
            dir=root_parent if root_parent is not None else ROOT,
        )
        self.root = Path(self.temporary.name)
        self.authority = self.root / "Library/WinsVPN/ReleasePythonAuthority/v1"
        self.authority.mkdir(parents=True, mode=0o700)
        self.updater = self.authority / "owner-updater"
        self.inputs = self.root / "inputs"
        self.inputs.mkdir(mode=0o700)
        self.old_controller = self.inputs / "owner-provision.old"
        self.new_controller = self.inputs / "owner-provision.new"
        self.old_launcher_source = self.inputs / "owner-launcher-old.c"
        self.new_launcher_source = self.inputs / "owner-launcher-new.c"
        self.old_launcher = self.inputs / "owner-launcher.old"
        self.new_launcher = self.inputs / "owner-launcher.new"
        self.updater_source = self.inputs / "owner-updater.input"
        self.crash_marker = self.root / "crash.marker"
        self.hook = self.root / "source-hook"
        self.sdk = subprocess.run(
            ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"],
            check=True,
            capture_output=True,
            text=True,
            env={"DEVELOPER_DIR": str(DEVELOPER)},
        ).stdout.strip()
        self.old_controller.write_text(
            "#!/usr/bin/env python3\n"
            '"""Fixed external owner boundary for ReleasePython receipt migration.\n'
            'old fixture\n"""\n',
            encoding="ascii",
        )
        self.new_controller.write_text(
            "#!/usr/bin/env python3\n"
            '"""Fixed external owner boundary for ReleasePython receipt migration.\n'
            'new fixture\n"""\n',
            encoding="ascii",
        )
        self.old_controller_hash = sha256(self.old_controller)
        self.new_controller_hash = sha256(self.new_controller)
        self._compile_launcher(
            self.old_launcher_source,
            self.old_launcher,
            self.old_controller_hash,
            "old",
        )
        self._compile_launcher(
            self.new_launcher_source,
            self.new_launcher,
            self.old_controller_hash
            if mismatched_new_launcher
            else self.new_controller_hash,
            "new",
        )
        self.old_launcher_hash = sha256(self.old_launcher)
        self.new_launcher_hash = sha256(self.new_launcher)
        self.compiled_old_controller_hash = (
            "f" * 64 if wrong_old_controller else self.old_controller_hash
        )
        self._install_old_pair()
        self._install_authority()
        self.authority_digest = sha256(self.authority / "authority.json")
        self.authority_inode = (self.authority / "authority.json").stat().st_ino
        self.old_controller_inode = (
            self.authority / "owner-provision"
        ).stat().st_ino
        self.old_launcher_inode = (
            self.authority / "owner-launcher"
        ).stat().st_ino
        self.compile_updater(crash_at=crash_at, hook=hook)

    def _compile_launcher(
        self, source: Path, output: Path, controller_hash: str, suffix: str
    ) -> None:
        source.write_text(
            textwrap.dedent(
                f"""
                #include <stdio.h>
                __attribute__((used)) static const char controller_sha256[] =
                    "{controller_hash}";
                int main(void) {{
                    return puts("{suffix}") < 0 || controller_sha256[0] == '\\0';
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
                str(source),
                "-o",
                str(output),
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
                f"org.winsvpn.releasepython.owner-updater-{suffix}-test",
                str(output),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        output.chmod(0o555)

    def _install_old_pair(self) -> None:
        controller = self.authority / "owner-provision"
        launcher = self.authority / "owner-launcher"
        shutil.copyfile(self.old_controller, controller)
        shutil.copyfile(self.old_launcher, launcher)
        controller.chmod(0o555)
        launcher.chmod(0o555)
        flag = stat.SF_IMMUTABLE if self.production_boundary else stat.UF_IMMUTABLE
        os.chflags(controller, flag)
        os.chflags(launcher, flag)

    def _install_authority(self) -> None:
        authority = self.authority / "authority.json"
        authority.write_text('{"fixture":"owner-updater"}\n', encoding="ascii")
        authority.chmod(0o444)
        flag = stat.SF_IMMUTABLE if self.production_boundary else stat.UF_IMMUTABLE
        os.chflags(authority, flag)

    def compile_updater(
        self, *, crash_at: int | None = None, hook: bool = False
    ) -> None:
        boundary_defines = (
            [
                "-DWINS_EXPECTED_UID=0",
                "-DWINS_EXPECTED_GID=0",
                "-DWINS_REQUIRE_ROOT=1",
                "-DWINS_REQUIRE_SELF_IMMUTABLE=1",
                "-DWINS_ALLOW_EXPECTED_UID_ANCESTRY=0",
                "-DWINS_IMMUTABLE_FLAG=SF_IMMUTABLE",
            ]
            if self.production_boundary
            else [
                f"-DWINS_EXPECTED_UID={os.getuid()}",
                f"-DWINS_EXPECTED_GID={os.getgid()}",
                "-DWINS_REQUIRE_ROOT=0",
                "-DWINS_REQUIRE_SELF_IMMUTABLE=0",
                "-DWINS_ALLOW_EXPECTED_UID_ANCESTRY=1",
                "-DWINS_IMMUTABLE_FLAG=UF_IMMUTABLE",
            ]
        )
        defines = [
            f'-DWINS_UPDATER_PATH="{self.updater}"',
            f'-DWINS_DESTINATION_PARENT="{self.authority}"',
            *boundary_defines,
            f'-DWINS_BUILD_SOURCE_SHA256="{EVIDENCE}"',
            f'-DWINS_BUILD_SCRIPT_SHA256="{EVIDENCE}"',
            f'-DWINS_BUILD_COMPILER_SHA256="{EVIDENCE}"',
            f'-DWINS_BUILD_LINKER_SHA256="{EVIDENCE}"',
            f'-DWINS_BUILD_CODESIGN_SHA256="{EVIDENCE}"',
            f'-DWINS_BUILD_INPUT_CLOSURE_SHA256="{EVIDENCE}"',
            f'-DWINS_OLD_CONTROLLER_SHA256="{self.compiled_old_controller_hash}"',
            f'-DWINS_OLD_LAUNCHER_SHA256="{self.old_launcher_hash}"',
            f'-DWINS_NEW_CONTROLLER_SHA256="{self.new_controller_hash}"',
            f'-DWINS_NEW_LAUNCHER_SHA256="{self.new_launcher_hash}"',
        ]
        if crash_at is not None:
            defines.extend(
                [
                    f"-DWINS_TEST_CRASH_AT={crash_at}",
                    f'-DWINS_TEST_CRASH_MARKER_PATH="{self.crash_marker}"',
                ]
            )
        if hook:
            defines.append(f'-DWINS_TEST_HOOK_PATH="{self.hook}"')
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
                str(self.updater_source),
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
                "org.winsvpn.releasepython.owner-updater-test",
                str(self.updater_source),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        self.updater_source.chmod(0o555)

    def install_updater(self) -> subprocess.CompletedProcess[str]:
        return self.run(
            self.updater_source,
            "install-self",
            str(self.updater_source),
            sha256(self.updater_source),
        )

    def run(
        self, executable: Path, *arguments: str, timeout: float = 30
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(executable), *arguments],
            cwd=ROOT,
            env=EXACT_ENV,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def update(self) -> subprocess.CompletedProcess[str]:
        return self.run(
            self.updater,
            "update",
            str(self.new_controller),
            str(self.new_launcher),
        )

    def replace_authority(self, payload: bytes) -> None:
        authority = self.authority / "authority.json"
        os.chflags(authority, 0)
        authority.unlink()
        authority.write_bytes(payload)
        authority.chmod(0o444)
        flag = stat.SF_IMMUTABLE if self.production_boundary else stat.UF_IMMUTABLE
        os.chflags(authority, flag)

    def stage_paths(self) -> list[Path]:
        return list(self.authority.glob(".winsvpn-owner-updater-stage-*"))

    def cleanup_paths(self) -> list[Path]:
        return list(self.authority.glob(".winsvpn-owner-updater-cleanup-*"))

    def residue_snapshot(self) -> tuple[tuple[str, int, str], ...]:
        result: list[tuple[str, int, str]] = []
        roots = sorted(self.stage_paths() + self.cleanup_paths())
        for root in roots:
            paths = [root]
            if root.is_dir():
                paths.extend(sorted(root.rglob("*")))
            for path in paths:
                digest = sha256(path) if path.is_file() else "directory"
                result.append(
                    (str(path.relative_to(self.authority)), path.stat().st_ino, digest)
                )
        return tuple(result)

    def close(self) -> None:
        for path in sorted(self.root.rglob("*"), reverse=True):
            clear_flags(path)
        clear_flags(self.root)
        self.temporary.cleanup()


class NativeOwnerUpdaterTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fixtures: list[UpdaterFixture] = []

    def fixture(self, **kwargs: object) -> UpdaterFixture:
        fixture = UpdaterFixture(**kwargs)
        self.fixtures.append(fixture)
        return fixture

    def tearDown(self) -> None:
        for fixture in reversed(self.fixtures):
            fixture.close()

    def test_exact_update_replaces_pair_and_is_idempotent(self) -> None:
        fixture = self.fixture()
        installed = fixture.install_updater()
        self.assertEqual(installed.returncode, 0, installed.stderr)
        self.assertTrue(immutable(fixture.updater))
        updated = fixture.update()
        self.assertEqual(updated.returncode, 0, updated.stderr)
        controller = fixture.authority / "owner-provision"
        launcher = fixture.authority / "owner-launcher"
        self.assertEqual(sha256(controller), fixture.new_controller_hash)
        self.assertEqual(sha256(launcher), fixture.new_launcher_hash)
        self.assertTrue(immutable(controller))
        self.assertTrue(immutable(launcher))
        self.assertNotEqual(controller.stat().st_ino, fixture.old_controller_inode)
        self.assertNotEqual(launcher.stat().st_ino, fixture.old_launcher_inode)
        self.assertEqual(fixture.stage_paths(), [])
        self.assertEqual(fixture.cleanup_paths(), [])
        self.assertEqual(sha256(fixture.authority / "authority.json"), fixture.authority_digest)
        second = fixture.run(fixture.updater, "update")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("already committed", second.stdout)

    def test_incompatible_first_writer_refuses_without_mutation(self) -> None:
        fixture = self.fixture(wrong_old_controller=True)
        completed = fixture.install_updater()
        self.assertEqual(completed.returncode, 126)
        self.assertIn("published pair is outside", completed.stderr)
        before = fixture.old_controller_inode
        self.assertEqual((fixture.authority / "owner-provision").stat().st_ino, before)
        self.assertFalse(fixture.updater.exists())
        self.assertEqual(fixture.stage_paths(), [])
        self.assertEqual(
            list(fixture.authority.glob(".winsvpn-owner-updater-install-*")), []
        )

    def test_first_install_requires_complete_fixed_pair(self) -> None:
        fixture = self.fixture()
        controller = fixture.authority / "owner-provision"
        os.chflags(controller, 0)
        controller.unlink()
        completed = fixture.install_updater()
        self.assertEqual(completed.returncode, 126)
        self.assertFalse(fixture.updater.exists())
        self.assertEqual(
            list(fixture.authority.glob(".winsvpn-owner-updater-install-*")), []
        )

    def test_mixed_published_pair_refuses_without_mutation(self) -> None:
        fixture = self.fixture()
        self.assertEqual(fixture.install_updater().returncode, 0)
        controller = fixture.authority / "owner-provision"
        os.chflags(controller, 0)
        controller.unlink()
        shutil.copyfile(fixture.new_controller, controller)
        controller.chmod(0o555)
        os.chflags(controller, stat.UF_IMMUTABLE)
        before = (
            controller.stat().st_ino,
            (fixture.authority / "owner-launcher").stat().st_ino,
            sha256(controller),
            sha256(fixture.authority / "owner-launcher"),
        )
        completed = fixture.update()
        self.assertEqual(completed.returncode, 126)
        self.assertIn("published pair is outside", completed.stderr)
        self.assertEqual(
            before,
            (
                controller.stat().st_ino,
                (fixture.authority / "owner-launcher").stat().st_ino,
                sha256(controller),
                sha256(fixture.authority / "owner-launcher"),
            ),
        )
        self.assertEqual(fixture.stage_paths(), [])

    def test_new_launcher_binding_mismatch_refuses_before_stage(self) -> None:
        fixture = self.fixture(mismatched_new_launcher=True)
        self.assertEqual(fixture.install_updater().returncode, 0)
        completed = fixture.update()
        self.assertEqual(completed.returncode, 126)
        self.assertIn("do not bind", completed.stderr)
        self.assertEqual(fixture.stage_paths(), [])

    def test_crash_after_each_phase_resumes_forward(self) -> None:
        for ordinal in range(1, 8):
            with self.subTest(ordinal=ordinal):
                fixture = self.fixture(crash_at=ordinal)
                self.assertEqual(fixture.install_updater().returncode, 0)
                crashed = fixture.update()
                self.assertEqual(crashed.returncode, 90 + ordinal)
                resumed = fixture.run(fixture.updater, "update")
                self.assertEqual(resumed.returncode, 0, resumed.stderr)
                self.assertEqual(
                    sha256(fixture.authority / "owner-provision"),
                    fixture.new_controller_hash,
                )
                self.assertEqual(
                    sha256(fixture.authority / "owner-launcher"),
                    fixture.new_launcher_hash,
                )
                self.assertEqual(fixture.stage_paths(), [])

    def test_crash_before_journal_leaves_recoverable_stage(self) -> None:
        fixture = self.fixture(crash_at=0)
        self.assertEqual(fixture.install_updater().returncode, 0)
        crashed = fixture.update()
        self.assertEqual(crashed.returncode, 90)
        status_result = fixture.run(fixture.updater, "status")
        self.assertEqual(status_result.returncode, 0, status_result.stderr)
        self.assertIn("state=CLEAN", status_result.stdout)
        self.assertIn("stage_residue=yes", status_result.stdout)
        resumed = fixture.update()
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertEqual(fixture.stage_paths(), [])

    def test_crash_between_journal_next_and_rename_resumes(self) -> None:
        fixture = self.fixture(crash_at=20)
        self.assertEqual(fixture.install_updater().returncode, 0)
        crashed = fixture.update()
        self.assertEqual(crashed.returncode, 110)
        self.assertTrue((fixture.stage_paths()[0] / "journal.next").exists())
        resumed = fixture.run(fixture.updater, "update")
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertEqual(fixture.stage_paths(), [])

    def test_crash_during_terminal_cleanup_resumes(self) -> None:
        for ordinal in (21, 22, 23, 24, 25):
            with self.subTest(ordinal=ordinal):
                fixture = self.fixture(crash_at=ordinal)
                self.assertEqual(fixture.install_updater().returncode, 0)
                crashed = fixture.update()
                self.assertEqual(crashed.returncode, 90 + ordinal)
                resumed = fixture.run(fixture.updater, "update")
                self.assertEqual(resumed.returncode, 0, resumed.stderr)
                self.assertEqual(
                    sha256(fixture.authority / "owner-provision"),
                    fixture.new_controller_hash,
                )
                self.assertEqual(
                    sha256(fixture.authority / "owner-launcher"),
                    fixture.new_launcher_hash,
                )
                self.assertEqual(fixture.stage_paths(), [])
                self.assertEqual(fixture.cleanup_paths(), [])

    def test_revert_refuses_committed_without_mutation(self) -> None:
        fixture = self.fixture(crash_at=21)
        self.assertEqual(fixture.install_updater().returncode, 0)
        self.assertEqual(fixture.update().returncode, 111)
        stage = fixture.stage_paths()[0]
        before = sorted(path.name for path in stage.iterdir())
        completed = fixture.run(fixture.updater, "revert")
        self.assertEqual(completed.returncode, 126)
        self.assertIn("revert refuses", completed.stderr)
        self.assertTrue(stage.exists())
        self.assertEqual(sorted(path.name for path in stage.iterdir()), before)

    def test_crash_midway_reverts_original_inodes(self) -> None:
        fixture = self.fixture(crash_at=3)
        self.assertEqual(fixture.install_updater().returncode, 0)
        self.assertEqual(fixture.update().returncode, 93)
        reverted = fixture.run(fixture.updater, "revert")
        self.assertEqual(reverted.returncode, 0, reverted.stderr)
        controller = fixture.authority / "owner-provision"
        launcher = fixture.authority / "owner-launcher"
        self.assertEqual(controller.stat().st_ino, fixture.old_controller_inode)
        self.assertEqual(launcher.stat().st_ino, fixture.old_launcher_inode)
        self.assertEqual(sha256(controller), fixture.old_controller_hash)
        self.assertEqual(sha256(launcher), fixture.old_launcher_hash)
        self.assertTrue(immutable(controller))
        self.assertTrue(immutable(launcher))
        self.assertEqual(fixture.stage_paths(), [])

    def test_revert_reseals_after_unseal_crashes(self) -> None:
        for ordinal in (2, 5):
            with self.subTest(ordinal=ordinal):
                fixture = self.fixture(crash_at=ordinal)
                self.assertEqual(fixture.install_updater().returncode, 0)
                self.assertEqual(fixture.update().returncode, 90 + ordinal)
                reverted = fixture.run(fixture.updater, "revert")
                self.assertEqual(reverted.returncode, 0, reverted.stderr)
                controller = fixture.authority / "owner-provision"
                launcher = fixture.authority / "owner-launcher"
                self.assertEqual(controller.stat().st_ino, fixture.old_controller_inode)
                self.assertEqual(launcher.stat().st_ino, fixture.old_launcher_inode)
                self.assertTrue(immutable(controller))
                self.assertTrue(immutable(launcher))
                self.assertEqual(fixture.stage_paths(), [])

    def test_status_is_read_only_in_intermediate_state(self) -> None:
        fixture = self.fixture(crash_at=3)
        self.assertEqual(fixture.install_updater().returncode, 0)
        self.assertEqual(fixture.update().returncode, 93)
        controller = fixture.authority / "owner-provision"
        launcher = fixture.authority / "owner-launcher"
        before = (
            controller.stat().st_ino,
            launcher.stat().st_ino,
            sha256(controller),
            sha256(launcher),
        )
        status_result = fixture.run(fixture.updater, "status")
        self.assertEqual(status_result.returncode, 0, status_result.stderr)
        self.assertIn("state=CONTROLLER_LIVE", status_result.stdout)
        after = (
            controller.stat().st_ino,
            launcher.stat().st_ino,
            sha256(controller),
            sha256(launcher),
        )
        self.assertEqual(before, after)

    def test_journal_tamper_refuses_recovery(self) -> None:
        fixture = self.fixture(crash_at=1)
        self.assertEqual(fixture.install_updater().returncode, 0)
        self.assertEqual(fixture.update().returncode, 91)
        journal = fixture.stage_paths()[0] / "journal"
        journal.chmod(0o600)
        data = journal.read_bytes().replace(b"phase=armed", b"phase=forged")
        journal.write_bytes(data)
        journal.chmod(0o400)
        status_result = fixture.run(fixture.updater, "status")
        self.assertEqual(status_result.returncode, 126)
        self.assertIn("invalid update journal", status_result.stderr)
        os.chflags(fixture.updater, 0)
        install_result = fixture.install_updater()
        self.assertEqual(install_result.returncode, 0, install_result.stderr)
        self.assertTrue(immutable(fixture.updater))
        completed = fixture.run(fixture.updater, "update")
        self.assertEqual(completed.returncode, 126)
        self.assertIn("journal", completed.stderr)
        self.assertEqual(
            sha256(fixture.authority / "owner-provision"),
            fixture.old_controller_hash,
        )
        discarded = fixture.run(fixture.updater, "discard")
        self.assertEqual(discarded.returncode, 0, discarded.stderr)
        self.assertEqual(fixture.stage_paths(), [])
        restarted = fixture.update()
        self.assertEqual(restarted.returncode, 0, restarted.stderr)

    def test_install_self_repairs_seal_with_bounded_residue(self) -> None:
        for ordinal in (0, 23, 24):
            with self.subTest(ordinal=ordinal):
                fixture = self.fixture(crash_at=ordinal)
                self.assertEqual(fixture.install_updater().returncode, 0)
                self.assertEqual(fixture.update().returncode, 90 + ordinal)
                os.chflags(fixture.updater, 0)
                repaired = fixture.install_updater()
                self.assertEqual(repaired.returncode, 0, repaired.stderr)
                self.assertTrue(immutable(fixture.updater))
                resumed = fixture.update()
                self.assertEqual(resumed.returncode, 0, resumed.stderr)
                self.assertEqual(fixture.stage_paths(), [])
                self.assertEqual(fixture.cleanup_paths(), [])

    def test_installed_updater_mutation_during_reseal_refuses(self) -> None:
        for initially_sealed in (False, True):
            with self.subTest(initially_sealed=initially_sealed):
                fixture = self.fixture(hook=True)
                self.assertEqual(fixture.install_updater().returncode, 0)
                expected = sha256(fixture.updater_source)
                if not initially_sealed:
                    os.chflags(fixture.updater, 0)
                process = subprocess.Popen(
                    [
                        str(fixture.updater_source),
                        "install-self",
                        str(fixture.updater_source),
                        expected,
                    ],
                    cwd=ROOT,
                    env=EXACT_ENV,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                deadline = time.monotonic() + 20
                ready = ""
                assert process.stdout is not None
                while time.monotonic() < deadline:
                    line = process.stdout.readline()
                    ready += line
                    if "TEST_HOOK_READY" in line:
                        break
                self.assertIn("TEST_HOOK_READY", ready)
                if initially_sealed:
                    os.chflags(fixture.updater, 0)
                changed = bytearray(fixture.updater.read_bytes())
                changed[-1] ^= 1
                fixture.updater.chmod(0o755)
                fixture.updater.write_bytes(changed)
                fixture.updater.chmod(0o555)
                if initially_sealed:
                    os.chflags(fixture.updater, stat.UF_IMMUTABLE)
                fixture.hook.with_suffix(".release").touch()
                stdout, stderr = process.communicate(timeout=20)
                self.assertEqual(process.returncode, 126, stdout + stderr)
                self.assertIn("repair exact updater seal", stderr)
                self.assertTrue(immutable(fixture.updater))
                self.assertNotEqual(sha256(fixture.updater), expected)

    def test_authority_replacement_across_crash_refuses_every_verb(self) -> None:
        original = b'{"fixture":"owner-updater"}\n'
        replacements = (
            b'{"fixture":"replacement-authority"}\n',
            original,
        )
        for ordinal in (1, 23, 24):
            for replacement in replacements:
                with self.subTest(
                    ordinal=ordinal, same_digest=replacement == original
                ):
                    fixture = self.fixture(crash_at=ordinal)
                    self.assertEqual(fixture.install_updater().returncode, 0)
                    self.assertEqual(
                        fixture.update().returncode, 90 + ordinal
                    )
                    journals = [
                        path
                        for path in (
                            [stage / "journal" for stage in fixture.stage_paths()]
                            + fixture.cleanup_paths()
                        )
                        if path.is_file()
                    ]
                    self.assertEqual(len(journals), 1)
                    journal = journals[0].read_text(encoding="ascii")
                    self.assertIn(
                        f"authority_sha256={fixture.authority_digest}", journal
                    )
                    self.assertIn(
                        f"authority_inode={fixture.authority_inode}", journal
                    )
                    pair_before = (
                        (fixture.authority / "owner-provision").stat().st_ino,
                        (fixture.authority / "owner-launcher").stat().st_ino,
                        sha256(fixture.authority / "owner-provision"),
                        sha256(fixture.authority / "owner-launcher"),
                    )
                    residue_before = fixture.residue_snapshot()
                    fixture.replace_authority(replacement)
                    current = fixture.authority / "authority.json"
                    self.assertNotEqual(current.stat().st_ino, fixture.authority_inode)
                    self.assertTrue(immutable(current))
                    operations = (
                        ("update", lambda: fixture.run(fixture.updater, "update")),
                        ("revert", lambda: fixture.run(fixture.updater, "revert")),
                        ("discard", lambda: fixture.run(fixture.updater, "discard")),
                        ("status", lambda: fixture.run(fixture.updater, "status")),
                        ("install-self", fixture.install_updater),
                    )
                    for verb, operation in operations:
                        completed = operation()
                        self.assertEqual(completed.returncode, 126, verb)
                        self.assertIn(
                            "journal-bound authority witness", completed.stderr
                        )
                        self.assertEqual(
                            pair_before,
                            (
                                (fixture.authority / "owner-provision").stat().st_ino,
                                (fixture.authority / "owner-launcher").stat().st_ino,
                                sha256(fixture.authority / "owner-provision"),
                                sha256(fixture.authority / "owner-launcher"),
                            ),
                        )
                        self.assertEqual(
                            residue_before, fixture.residue_snapshot()
                        )

    def test_journal_whitespace_inode_refuses(self) -> None:
        fixture = self.fixture(crash_at=1)
        self.assertEqual(fixture.install_updater().returncode, 0)
        self.assertEqual(fixture.update().returncode, 91)
        journal = fixture.stage_paths()[0] / "journal"
        journal.chmod(0o600)
        lines = journal.read_text(encoding="ascii").splitlines()
        lines = [
            line.replace("old_controller_inode=", "old_controller_inode= ")
            if line.startswith("old_controller_inode=")
            else line
            for line in lines
        ]
        journal.write_text("\n".join(lines) + "\n", encoding="ascii")
        journal.chmod(0o400)
        completed = fixture.run(fixture.updater, "update")
        self.assertEqual(completed.returncode, 126)
        self.assertIn("explicit discard", completed.stderr)

    def test_midtransition_journal_tamper_refuses_every_verb(self) -> None:
        fixture = self.fixture(crash_at=3)
        self.assertEqual(fixture.install_updater().returncode, 0)
        self.assertEqual(fixture.update().returncode, 93)
        stage = fixture.stage_paths()[0]
        journal = stage / "journal"
        journal.chmod(0o600)
        journal.write_bytes(
            journal.read_bytes().replace(
                b"phase=swapping-controller", b"phase=forged-controller-x"
            )
        )
        journal.chmod(0o400)
        controller = fixture.authority / "owner-provision"
        launcher = fixture.authority / "owner-launcher"
        before = (
            controller.stat().st_ino,
            launcher.stat().st_ino,
            sha256(controller),
            sha256(launcher),
            sorted(path.name for path in stage.iterdir()),
        )
        for verb in ("update", "revert", "discard", "status"):
            completed = fixture.run(fixture.updater, verb)
            self.assertEqual(completed.returncode, 126, verb)
            self.assertIn("state=UNRECOGNIZED", completed.stderr)
            self.assertIn("stage=", completed.stderr)
            after = (
                controller.stat().st_ino,
                launcher.stat().st_ino,
                sha256(controller),
                sha256(launcher),
                sorted(path.name for path in stage.iterdir()),
            )
            self.assertEqual(after, before)

    def test_inode_substitution_refuses_recovery(self) -> None:
        fixture = self.fixture(crash_at=3)
        self.assertEqual(fixture.install_updater().returncode, 0)
        self.assertEqual(fixture.update().returncode, 93)
        rollback = fixture.stage_paths()[0] / "owner-provision"
        data = rollback.read_bytes()
        old_inode = rollback.stat().st_ino
        rollback.unlink()
        rollback.write_bytes(data)
        rollback.chmod(0o555)
        self.assertNotEqual(rollback.stat().st_ino, old_inode)
        completed = fixture.run(fixture.updater, "update")
        self.assertEqual(completed.returncode, 126)
        self.assertIn("state=UNRECOGNIZED", completed.stderr)

    def test_discard_refuses_complete_transition(self) -> None:
        fixture = self.fixture(crash_at=3)
        self.assertEqual(fixture.install_updater().returncode, 0)
        self.assertEqual(fixture.update().returncode, 93)
        completed = fixture.run(fixture.updater, "discard")
        self.assertEqual(completed.returncode, 126)
        self.assertIn("refuses a complete transition", completed.stderr)
        self.assertNotEqual(fixture.stage_paths(), [])

    def test_stage_inventory_rejects_unexpected_entry(self) -> None:
        fixture = self.fixture(crash_at=1)
        self.assertEqual(fixture.install_updater().returncode, 0)
        self.assertEqual(fixture.update().returncode, 91)
        stage = fixture.stage_paths()[0]
        (stage / "extra").write_text("x", encoding="ascii")
        completed = fixture.run(fixture.updater, "update")
        self.assertEqual(completed.returncode, 126)
        self.assertIn("unexpected entry", completed.stderr)
        for name in ("journal", "owner-provision", "owner-launcher", "extra"):
            self.assertTrue((stage / name).exists())

    def test_discard_clears_flagged_stage_residue(self) -> None:
        fixture = self.fixture(crash_at=1)
        self.assertEqual(fixture.install_updater().returncode, 0)
        self.assertEqual(fixture.update().returncode, 91)
        stage = fixture.stage_paths()[0]
        os.chflags(stage / "owner-provision", stat.UF_APPEND)
        journal = stage / "journal"
        journal.chmod(0o600)
        journal.write_bytes(journal.read_bytes().replace(b"phase=armed", b"phase=badxx"))
        journal.chmod(0o400)
        self.assertEqual(fixture.run(fixture.updater, "update").returncode, 126)
        discarded = fixture.run(fixture.updater, "discard")
        self.assertEqual(discarded.returncode, 0, discarded.stderr)
        self.assertEqual(fixture.stage_paths(), [])

    def test_pending_controller_transaction_refuses(self) -> None:
        for name in (
            "owner-provision.transaction.json",
            "owner-provision.transaction.next",
            "authority.json.owner-provision.abc123.new",
        ):
            with self.subTest(name=name):
                fixture = self.fixture()
                self.assertEqual(fixture.install_updater().returncode, 0)
                residue = fixture.authority / name
                residue.write_text("{}\n", encoding="ascii")
                completed = fixture.update()
                self.assertEqual(completed.returncode, 126)
                self.assertIn("transaction requires recovery", completed.stderr)
                self.assertEqual(fixture.stage_paths(), [])

    def test_concurrent_authority_transaction_is_locked_out(self) -> None:
        fixture = self.fixture()
        self.assertEqual(fixture.install_updater().returncode, 0)
        descriptor = os.open(fixture.authority, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            completed = fixture.update()
        finally:
            os.close(descriptor)
        self.assertEqual(completed.returncode, 126)
        self.assertIn("authority lock", completed.stderr)
        self.assertEqual(fixture.stage_paths(), [])

    def test_source_mutation_during_hold_refuses_before_unseal(self) -> None:
        fixture = self.fixture(hook=True)
        self.assertEqual(fixture.install_updater().returncode, 0)
        process = subprocess.Popen(
            [
                str(fixture.updater),
                "update",
                str(fixture.new_controller),
                str(fixture.new_launcher),
            ],
            cwd=ROOT,
            env=EXACT_ENV,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 20
        ready = ""
        assert process.stdout is not None
        while time.monotonic() < deadline:
            line = process.stdout.readline()
            ready += line
            if "TEST_HOOK_READY" in line:
                break
        self.assertIn("TEST_HOOK_READY", ready)
        fixture.new_controller.write_text(
            fixture.new_controller.read_text(encoding="ascii") + "# changed\n",
            encoding="ascii",
        )
        fixture.hook.with_suffix(".release").touch()
        stdout, stderr = process.communicate(timeout=20)
        self.assertEqual(process.returncode, 126, stdout + stderr)
        self.assertIn("source changed", stderr)
        controller = fixture.authority / "owner-provision"
        self.assertEqual(sha256(controller), fixture.old_controller_hash)
        self.assertTrue(immutable(controller))
        self.assertEqual(fixture.stage_paths(), [])

    def test_foreign_existing_updater_refuses_first_install(self) -> None:
        fixture = self.fixture()
        fixture.updater.write_bytes(b"foreign updater")
        fixture.updater.chmod(0o555)
        os.chflags(fixture.updater, stat.UF_IMMUTABLE)
        completed = fixture.install_updater()
        self.assertEqual(completed.returncode, 126)
        self.assertIn("owner-selected immutable byte set", completed.stderr)
        self.assertEqual(fixture.updater.read_bytes(), b"foreign updater")
        self.assertEqual(
            list(fixture.authority.glob(".winsvpn-owner-updater-install-*")), []
        )

    def test_abandoned_install_stage_is_reaped(self) -> None:
        fixture = self.fixture()
        expected = sha256(fixture.updater_source)
        stage = fixture.authority / (
            ".winsvpn-owner-updater-install-" + expected[:32]
        )
        stage.write_bytes(b"partial install stage")
        stage.chmod(0o600)
        completed = fixture.install_updater()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(immutable(fixture.updater))
        self.assertFalse(stage.exists())

    def test_install_self_repairs_unsealed_updater(self) -> None:
        fixture = self.fixture()
        self.assertEqual(fixture.install_updater().returncode, 0)
        os.chflags(fixture.updater, 0)
        repaired = fixture.install_updater()
        self.assertEqual(repaired.returncode, 0, repaired.stderr)
        self.assertTrue(immutable(fixture.updater))
        self.assertEqual(sha256(fixture.updater), sha256(fixture.updater_source))
        self.assertEqual(fixture.update().returncode, 0)

    def test_install_self_repairs_seal_during_valid_transition(self) -> None:
        fixture = self.fixture(crash_at=3)
        self.assertEqual(fixture.install_updater().returncode, 0)
        self.assertEqual(fixture.update().returncode, 93)
        os.chflags(fixture.updater, 0)
        repaired = fixture.install_updater()
        self.assertEqual(repaired.returncode, 0, repaired.stderr)
        self.assertTrue(immutable(fixture.updater))
        resumed = fixture.run(fixture.updater, "update")
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertEqual(fixture.stage_paths(), [])
        self.assertEqual(fixture.cleanup_paths(), [])

    def test_install_self_recovers_rename_before_seal_crash(self) -> None:
        fixture = self.fixture(crash_at=30)
        crashed = fixture.install_updater()
        self.assertEqual(crashed.returncode, 120)
        self.assertFalse(immutable(fixture.updater))
        recovered = fixture.install_updater()
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertTrue(immutable(fixture.updater))

    def test_null_error_paths_report_specific_messages(self) -> None:
        fixture = self.fixture()
        self.assertEqual(fixture.install_updater().returncode, 0)
        clean_without_sources = fixture.run(fixture.updater, "update")
        self.assertEqual(clean_without_sources.returncode, 126)
        self.assertIn("requires ABSOLUTE_CONTROLLER", clean_without_sources.stderr)
        self.assertNotIn("(null)", clean_without_sources.stderr)
        wrong_path = fixture.run(fixture.updater_source, "status")
        self.assertEqual(wrong_path.returncode, 126)
        self.assertIn("reviewed fixed path", wrong_path.stderr)
        self.assertNotIn("(null)", wrong_path.stderr)

    def test_low_file_size_limit_refuses_before_staging(self) -> None:
        fixture = self.fixture()
        self.assertEqual(fixture.install_updater().returncode, 0)
        hard = resource.getrlimit(resource.RLIMIT_FSIZE)[1]

        def lower_limit() -> None:
            resource.setrlimit(resource.RLIMIT_FSIZE, (1024, hard))

        completed = subprocess.run(
            [
                str(fixture.updater),
                "update",
                str(fixture.new_controller),
                str(fixture.new_launcher),
            ],
            cwd=ROOT,
            env=EXACT_ENV,
            capture_output=True,
            text=True,
            timeout=30,
            preexec_fn=lower_limit,
        )
        self.assertEqual(completed.returncode, 126)
        self.assertIn("file-size limit", completed.stderr)
        self.assertEqual(fixture.stage_paths(), [])

    def test_low_file_size_limit_refuses_install_before_staging(self) -> None:
        fixture = self.fixture()
        hard = resource.getrlimit(resource.RLIMIT_FSIZE)[1]

        def lower_limit() -> None:
            resource.setrlimit(resource.RLIMIT_FSIZE, (1024, hard))

        completed = subprocess.run(
            [
                str(fixture.updater_source),
                "install-self",
                str(fixture.updater_source),
                sha256(fixture.updater_source),
            ],
            cwd=ROOT,
            env=EXACT_ENV,
            capture_output=True,
            text=True,
            timeout=30,
            preexec_fn=lower_limit,
        )
        self.assertEqual(completed.returncode, 126)
        self.assertIn("file-size limit", completed.stderr)
        self.assertEqual(
            list(fixture.authority.glob(".winsvpn-owner-updater-install-*")), []
        )

    def test_install_stage_cleanup_failure_is_reported(self) -> None:
        fixture = self.fixture()
        expected = sha256(fixture.updater_source)
        stage = fixture.authority / (
            ".winsvpn-owner-updater-install-" + expected[:32]
        )
        stage.mkdir(mode=0o700)
        completed = fixture.install_updater()
        self.assertEqual(completed.returncode, 126)
        self.assertIn("install residue custody", completed.stderr)

    def test_discard_without_residue_reports_nothing_present(self) -> None:
        fixture = self.fixture()
        self.assertEqual(fixture.install_updater().returncode, 0)
        completed = fixture.run(fixture.updater, "discard")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("no bounded terminal residue present", completed.stdout)

    def test_unsealed_clean_pair_refuses(self) -> None:
        fixture = self.fixture()
        self.assertEqual(fixture.install_updater().returncode, 0)
        controller = fixture.authority / "owner-provision"
        os.chflags(controller, 0)
        completed = fixture.update()
        self.assertEqual(completed.returncode, 126)
        self.assertIn("not exactly immutable", completed.stderr)
        self.assertEqual(fixture.stage_paths(), [])

    def test_static_contract_has_no_pathname_replacement_fallback(self) -> None:
        source = SOURCE.read_text(encoding="ascii")
        self.assertIn("RENAME_SWAP", source)
        self.assertIn("flock(parent_fd, LOCK_EX | LOCK_NB)", source)
        self.assertIn("WINS_OLD_CONTROLLER_SHA256", source)
        self.assertIn("WINS_NEW_LAUNCHER_SHA256", source)
        self.assertIn("owner-provision.transaction.json", source)
        self.assertIn("owner-provision.transaction.next", source)
        self.assertIn("ATTR_VOL_INFO | ATTR_VOL_CAPABILITIES", source)
        self.assertIn("signal(SIGXFSZ, SIG_IGN)", source)
        self.assertNotIn("system(", source)
        self.assertNotIn("/bin/chflags", source)
        self.assertNotIn("RENAME_UNLINK", source)

    def test_directory_enumeration_errors_fail_closed(self) -> None:
        source = SOURCE.read_text(encoding="ascii")
        self.assertEqual(
            source.count("errno = 0;\n    while ((entry = readdir(directory))"),
            2,
        )
        self.assertGreaterEqual(source.count("if (errno != 0)"), 2)


@unittest.skipUnless(
    os.geteuid() == 0
    and os.environ.get("WINS_RUN_ROOT_SF_IMMUTABLE_TEST") == "1",
    "requires explicit passwordless-root SF_IMMUTABLE matrix opt-in",
)
class NativeOwnerUpdaterRootBoundaryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fixtures: list[UpdaterFixture] = []
        self.root_parent = Path(
            tempfile.mkdtemp(
                prefix=".releasepython-owner-updater-matrix-",
                dir="/Library/WinsVPN",
            )
        )
        self.root_parent.chmod(0o700)

    def fixture(self, **kwargs: object) -> UpdaterFixture:
        fixture = UpdaterFixture(
            production_boundary=True,
            root_parent=self.root_parent,
            **kwargs,
        )
        self.fixtures.append(fixture)
        return fixture

    def tearDown(self) -> None:
        for fixture in reversed(self.fixtures):
            fixture.close()
        self.assertEqual(list(self.root_parent.iterdir()), [])
        self.root_parent.rmdir()

    def assert_system_immutable(self, path: Path) -> None:
        self.assertNotEqual(
            getattr(os.lstat(path), "st_flags", 0) & stat.SF_IMMUTABLE,
            0,
            str(path),
        )

    def test_root_wheel_system_immutable_update_and_recovery(self) -> None:
        fixture = self.fixture()
        installed = fixture.install_updater()
        self.assertEqual(installed.returncode, 0, installed.stderr)
        self.assert_system_immutable(fixture.updater)
        updated = fixture.update()
        self.assertEqual(updated.returncode, 0, updated.stderr)
        self.assert_system_immutable(fixture.authority / "owner-provision")
        self.assert_system_immutable(fixture.authority / "owner-launcher")
        self.assertEqual(fixture.stage_paths(), [])

        recovery = self.fixture(crash_at=3)
        self.assertEqual(recovery.install_updater().returncode, 0)
        self.assertEqual(recovery.update().returncode, 93)
        reverted = recovery.run(recovery.updater, "revert")
        self.assertEqual(reverted.returncode, 0, reverted.stderr)
        self.assert_system_immutable(recovery.authority / "owner-provision")
        self.assert_system_immutable(recovery.authority / "owner-launcher")
        self.assertEqual(recovery.stage_paths(), [])

        cleanup = self.fixture(crash_at=24)
        self.assertEqual(cleanup.install_updater().returncode, 0)
        self.assertEqual(cleanup.update().returncode, 114)
        self.assertEqual(cleanup.stage_paths(), [])
        self.assertEqual(len(cleanup.cleanup_paths()), 1)
        resumed = cleanup.run(cleanup.updater, "update")
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assert_system_immutable(cleanup.authority / "owner-provision")
        self.assert_system_immutable(cleanup.authority / "owner-launcher")
        self.assertEqual(cleanup.cleanup_paths(), [])


class NativeOwnerUpdaterBuildSupportTest(unittest.TestCase):
    def test_reaper_removes_only_exact_bounded_stage(self) -> None:
        support = load_build_support()
        with tempfile.TemporaryDirectory(
            prefix=".native-owner-updater-build-", dir=ROOT
        ) as temporary:
            parent = Path(temporary)
            stage = parent / (support.UPDATER_STAGE_PREFIX + "a" * 48)
            stage.mkdir(mode=0o700)
            binary = stage / "owner-updater"
            manifest = stage / "owner-updater.closure.manifest"
            binary.write_bytes(b"updater")
            manifest.write_bytes(b"manifest")
            binary.chmod(0o555)
            manifest.chmod(0o444)
            support.reap_abandoned_stages(
                str(parent), "owner-updater", "owner-updater.closure.manifest"
            )
            self.assertFalse(stage.exists())

    def test_reaper_refuses_unreviewed_stage_leaf(self) -> None:
        support = load_build_support()
        with tempfile.TemporaryDirectory(
            prefix=".native-owner-updater-build-", dir=ROOT
        ) as temporary:
            parent = Path(temporary)
            stage = parent / (support.UPDATER_STAGE_PREFIX + "b" * 48)
            stage.mkdir(mode=0o700)
            foreign = stage / "owner-updater"
            foreign.write_bytes(b"foreign")
            foreign.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "leaf custody is invalid"):
                support.reap_abandoned_stages(
                    str(parent), "owner-updater", "owner-updater.closure.manifest"
                )
            self.assertTrue(stage.exists())
            self.assertEqual(foreign.read_bytes(), b"foreign")

    def test_reaper_refuses_unexpected_exact_custody_leaf_name(self) -> None:
        support = load_build_support()
        with tempfile.TemporaryDirectory(
            prefix=".native-owner-updater-build-", dir=ROOT
        ) as temporary:
            parent = Path(temporary)
            stage = parent / (support.UPDATER_STAGE_PREFIX + "c" * 48)
            stage.mkdir(mode=0o700)
            foreign = stage / "evidence.txt"
            foreign.write_bytes(b"evidence")
            foreign.chmod(0o444)
            with self.assertRaisesRegex(RuntimeError, "unexpected entry"):
                support.reap_abandoned_stages(
                    str(parent), "owner-updater", "owner-updater.closure.manifest"
                )
            self.assertEqual(foreign.read_bytes(), b"evidence")

    def test_builder_binds_updater_contract_and_uses_positioned_read(self) -> None:
        builder = (
            ROOT / "tools/build_macos_release_python_owner_updater.sh"
        ).read_text(encoding="ascii")
        support = (
            ROOT / "tools/macos_release_python_owner_updater_build_support.py"
        ).read_text(encoding="ascii")
        self.assertIn("export LC_ALL=C", builder)
        self.assertIn("os.pread(4, os.fstat(4).st_size, 0)", builder)
        self.assertIn(
            "contract=winsvpn-macos-release-python-owner-updater-build-closure-v1",
            builder,
        )
        self.assertIn('UPDATER_STAGE_PREFIX = ".winsvpn-owner-updater-build-"', support)


if __name__ == "__main__":
    unittest.main(verbosity=2)
