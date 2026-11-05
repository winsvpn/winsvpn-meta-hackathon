#!/usr/bin/env python3
"""Adversarial fixture tests for release Node.js archive custody."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import lzma
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "release_node_archive_custody.py"
SHELL = ROOT / "tools" / "release_node_archive_custody.sh"
VERSION = "v22.14.0"
TOP = f"node-{VERSION}-darwin-arm64"

SPEC = importlib.util.spec_from_file_location("release_node_archive_custody", TOOL)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load release Node custody module")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_fields(output: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition("|")
        if not separator or key in result:
            raise AssertionError(f"malformed custody output: {line!r}")
        result[key] = value
    return result


@unittest.skipUnless(sys.platform == "darwin", "macOS arm64 Node custody target required")
class ReleaseNodeArchiveCustodyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if subprocess.run(["/usr/bin/uname", "-m"], capture_output=True, text=True).stdout.strip() != "arm64":
            raise unittest.SkipTest("arm64 host required")
        cls.base = Path(tempfile.mkdtemp(prefix="wins-node-custody-test.", dir="/private/tmp"))
        cls.base.chmod(0o700)
        cls.inputs = cls.base / "inputs"
        cls.inputs.mkdir(mode=0o700)
        cls.node = cls._compile_node_fixture()
        cls.archive = cls.inputs / f"{TOP}.tar.xz"
        cls._write_archive(cls.archive, cls._normal_entries())
        cls.archive.chmod(0o444)
        cls.reference = cls.base / "reference" / TOP
        cls._write_reference_tree(cls.reference)
        cls.tree_sha = MODULE.tree_hash(cls.reference)
        cls.node_sha = sha256(cls.node)

    @classmethod
    def tearDownClass(cls) -> None:
        for path in cls.base.rglob("*"):
            if not path.is_symlink():
                try:
                    path.chmod(path.stat().st_mode | stat.S_IWUSR | stat.S_IXUSR)
                except FileNotFoundError:
                    pass
        shutil.rmtree(cls.base, ignore_errors=True)

    @classmethod
    def _compile_node_fixture(cls) -> Path:
        source = cls.base / "node-fixture.c"
        binary = cls.base / "node"
        source.write_text(
            textwrap.dedent(
                """
                #include <stdio.h>
                #include <stdlib.h>
                #include <string.h>
                #include <sys/stat.h>

                int main(int argc, char **argv) {
                  if (argc == 2 && strcmp(argv[1], "--version") == 0) {
                    puts("v22.14.0");
                    return 0;
                  }
                  if (argc == 3 && strcmp(argv[1], "-p") == 0) {
                    puts("darwin|arm64");
                    return 0;
                  }
                  if (argc == 2 && strcmp(argv[1], "--probe-env") == 0) {
                    const char *home = getenv("HOME");
                    const char *tmp = getenv("TMPDIR");
                    const char *path = getenv("PATH");
                    if (getenv("NODE_OPTIONS") || getenv("NODE_PATH") || getenv("ATTACKER")) return 71;
                    if (!home || !tmp || !path) return 72;
                    if (strstr(home, "/private/tmp/wins-release-node.") != home) return 73;
                    if (strstr(tmp, "/private/tmp/wins-release-node.") != tmp) return 74;
                    puts("clean-node-env");
                    return 0;
                  }
                  if (argc == 2 && strcmp(argv[1], "--mutate-self") == 0) {
                    if (chmod(argv[0], 0700) != 0) return 75;
                    FILE *stream = fopen(argv[0], "ab");
                    if (!stream) return 76;
                    if (fputc(1, stream) == EOF || fclose(stream) != 0) return 77;
                    if (chmod(argv[0], 0500) != 0) return 78;
                    return 0;
                  }
                  return 79;
                }
                """
            ).lstrip(),
            encoding="ascii",
        )
        subprocess.run(
            ["/usr/bin/clang", "-Os", "-arch", "arm64", "-o", str(binary), str(source)],
            check=True,
            capture_output=True,
            text=True,
        )
        return binary

    @classmethod
    def _normal_entries(cls) -> list[tuple[str, str, bytes | str]]:
        return [
            (TOP, "dir", b""),
            (f"{TOP}/bin", "dir", b""),
            (f"{TOP}/share", "dir", b""),
            (f"{TOP}/lib", "dir", b""),
            (f"{TOP}/lib/node_modules", "dir", b""),
            (f"{TOP}/lib/node_modules/npm", "dir", b""),
            (f"{TOP}/lib/node_modules/npm/bin", "dir", b""),
            (f"{TOP}/bin/node", "file", cls.node.read_bytes()),
            (f"{TOP}/share/LICENSE", "file", b"synthetic fixture only\n"),
            (f"{TOP}/lib/node_modules/npm/bin/npx-cli.js", "file", b"fixture\n"),
            (f"{TOP}/bin/npx", "symlink", "../lib/node_modules/npm/bin/npx-cli.js"),
        ]

    @classmethod
    def _write_archive(
        cls, path: Path, entries: list[tuple[str, str, bytes | str]]
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(path, "w:xz", format=tarfile.USTAR_FORMAT) as bundle:
            for name, kind, payload in entries:
                member = tarfile.TarInfo(name)
                member.uid = 0
                member.gid = 0
                member.uname = "root"
                member.gname = "wheel"
                member.mtime = 0
                if kind == "dir":
                    member.type = tarfile.DIRTYPE
                    member.mode = 0o755
                    bundle.addfile(member)
                elif kind == "file":
                    data = bytes(payload)
                    member.type = tarfile.REGTYPE
                    member.mode = 0o755 if name.endswith("/node") else 0o644
                    member.size = len(data)
                    import io

                    bundle.addfile(member, io.BytesIO(data))
                elif kind == "symlink":
                    member.type = tarfile.SYMTYPE
                    member.linkname = str(payload)
                    bundle.addfile(member)
                elif kind == "hardlink":
                    member.type = tarfile.LNKTYPE
                    member.linkname = str(payload)
                    bundle.addfile(member)
                else:
                    raise AssertionError(f"unknown fixture kind: {kind}")

    @classmethod
    def _write_reference_tree(cls, root: Path) -> None:
        (root / "bin").mkdir(parents=True)
        (root / "share").mkdir()
        (root / "lib/node_modules/npm/bin").mkdir(parents=True)
        shutil.copyfile(cls.node, root / "bin/node")
        (root / "share/LICENSE").write_bytes(b"synthetic fixture only\n")
        (root / "lib/node_modules/npm/bin/npx-cli.js").write_bytes(b"fixture\n")
        (root / "bin/npx").symlink_to("../lib/node_modules/npm/bin/npx-cli.js")
        (root / "bin/node").chmod(0o500)
        (root / "share/LICENSE").chmod(0o400)
        (root / "lib/node_modules/npm/bin/npx-cli.js").chmod(0o400)
        (root / "bin").chmod(0o500)
        (root / "share").chmod(0o500)
        (root / "lib/node_modules/npm/bin").chmod(0o500)
        (root / "lib/node_modules/npm").chmod(0o500)
        (root / "lib/node_modules").chmod(0o500)
        (root / "lib").chmod(0o500)
        root.chmod(0o500)

    def setUp(self) -> None:
        self.case = Path(tempfile.mkdtemp(prefix="case.", dir=self.base))
        self.case.chmod(0o700)

    def tearDown(self) -> None:
        for path in self.case.rglob("*"):
            if not path.is_symlink():
                try:
                    path.chmod(path.stat().st_mode | stat.S_IWUSR | stat.S_IXUSR)
                except FileNotFoundError:
                    pass
        shutil.rmtree(self.case, ignore_errors=True)

    def _copy_archive(self, name: str | None = None) -> Path:
        destination = self.case / (name or self.archive.name)
        shutil.copyfile(self.archive, destination)
        destination.chmod(0o444)
        return destination

    def _manifest(
        self,
        archive: Path | None = None,
        *,
        archive_sha: str | None = None,
        tree_sha: str | None = None,
        binary_sha: str | None = None,
        archive_format: str = "tar.xz",
        version: str = VERSION,
    ) -> Path:
        archive = archive or self.archive
        data = {
            "tools": {
                "node": {
                    "version": version,
                    "platform": "darwin-arm64",
                    "architecture": "arm64",
                    "archive_format": archive_format,
                    "archive_path": {"darwin_arm64": str(archive)},
                    "archive_sha256": {"darwin_arm64": archive_sha or sha256(archive)},
                    "install_tree_sha256": {"darwin_arm64": tree_sha or self.tree_sha},
                    "top_level_root": TOP,
                    "executable": "bin/node",
                    "executable_sha256": binary_sha or self.node_sha,
                }
            }
        }
        manifest = self.case / "pins.json"
        manifest.write_text(json.dumps(data), encoding="utf-8")
        manifest.chmod(0o600)
        return manifest

    def _cli(
        self, *arguments: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(TOOL), *arguments],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def _prepare(self, manifest: Path) -> dict[str, str]:
        completed = self._cli("prepare", str(manifest))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        fields = parse_fields(completed.stdout)
        self.addCleanup(self._cleanup_if_present, fields)
        return fields

    def _verification(self, fields: dict[str, str]) -> list[str]:
        return [
            fields["RUNTIME"],
            fields["RUNTIME_ID"],
            fields["ROOT"],
            fields["TREE_SHA256"],
            fields["BINARY"],
            fields["BINARY_SHA256"],
        ]

    def _cleanup_if_present(self, fields: dict[str, str]) -> None:
        runtime = Path(fields["RUNTIME"])
        if runtime.exists() and not runtime.is_symlink():
            self._cli("cleanup", fields["RUNTIME"], fields["RUNTIME_ID"])

    def test_prepare_verify_run_and_cleanup(self) -> None:
        archive = self._copy_archive()
        fields = self._prepare(self._manifest(archive))
        verified = self._cli("verify", *self._verification(fields))
        self.assertEqual(verified.returncode, 0, verified.stderr)
        env = os.environ.copy()
        env.update(
            {
                "NODE_OPTIONS": "--require=/private/tmp/attacker.js",
                "NODE_PATH": "/private/tmp/attacker-modules",
                "ATTACKER": "must-not-reach-node",
                "PATH": "/private/tmp/fake-node-bin",
            }
        )
        ran = self._cli("run", *self._verification(fields), "--", "--probe-env", env=env)
        self.assertEqual(ran.returncode, 0, ran.stderr)
        self.assertEqual(ran.stdout.strip(), "clean-node-env")
        cleaned = self._cli("cleanup", fields["RUNTIME"], fields["RUNTIME_ID"])
        self.assertEqual(cleaned.returncode, 0, cleaned.stderr)
        self.assertFalse(Path(fields["RUNTIME"]).exists())

    def test_shell_wrapper_prepare_run_verify_and_cleanup(self) -> None:
        archive = self._copy_archive()
        manifest = self._manifest(archive)
        controller = self.case / "controller.py"
        shutil.copyfile(TOOL, controller)
        controller.chmod(0o600)
        script = textwrap.dedent(
            f"""
            set -euo pipefail
            source {shlex.quote(str(SHELL))}
            wins_release_python_run() {{ {shlex.quote(sys.executable)} "$@"; }}
            wins_release_node_prepare {shlex.quote(str(controller))} {shlex.quote(str(manifest))}
            trap wins_release_node_cleanup EXIT
            printf '%s\n' 'raise SystemExit("replacement controller executed")' > {shlex.quote(str(controller))}
            WINS_NODE_CUSTODY_TOOL=/usr/bin/false
            WINS_RELEASE_NODE_RUNTIME=/private/tmp/attacker
            WINS_RELEASE_NODE_RUNTIME_ID=attacker
            WINS_RELEASE_NODE_ROOT=/private/tmp/attacker
            WINS_RELEASE_NODE_TREE_SHA256={'0' * 64}
            WINS_RELEASE_NODE=/usr/bin/false
            WINS_RELEASE_NODE_SHA256={'0' * 64}
            wins_release_node_verify
            wins_release_node_run --probe-env
            """
        )
        env = os.environ.copy()
        env["NODE_OPTIONS"] = "--inspect"
        completed = subprocess.run(
            ["/bin/bash", "-c", script],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "clean-node-env")

    def test_xz_decoder_memory_limit_is_fail_closed(self) -> None:
        with mock.patch.object(MODULE, "MAX_DECODER_MEMORY", 1):
            with self.assertRaisesRegex(MODULE.Refused, "[Mm]emory usage limit"):
                MODULE.safe_extract(
                    self.archive, self.case / "expanded-memory-limit", TOP
                )

    def test_shell_requires_authenticated_python_function(self) -> None:
        script = f"source {shlex.quote(str(SHELL))}; _wins_rn_python verify"
        completed = subprocess.run(
            ["/bin/bash", "-c", script], capture_output=True, text=True
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("authenticated release Python custody is required", completed.stderr)

    def test_safe_relative_symlink_is_authenticated(self) -> None:
        destination = self.case / "expanded-safe-link"
        root = MODULE.safe_extract(self.archive, destination, TOP)
        link = root / "bin/npx"
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), "../lib/node_modules/npm/bin/npx-cli.js")
        self.assertEqual(MODULE.tree_hash(root), self.tree_sha)

    def test_escaping_symlink_and_hardlink_are_rejected(self) -> None:
        cases = (
            ("absolute-symlink", "symlink", "/private/tmp/attacker"),
            ("escaping-symlink", "symlink", "../../attacker"),
            ("hardlink", "hardlink", "bin/node"),
        )
        for label, kind, target in cases:
            with self.subTest(label=label):
                archive = self.case / f"{label}.tar.xz"
                entries = self._normal_entries()
                entries.append((f"{TOP}/unsafe-{label}", kind, target))
                self._write_archive(archive, entries)
                destination = self.case / f"expanded-{label}"
                with self.assertRaises(MODULE.Refused):
                    MODULE.safe_extract(archive, destination, TOP)

    def test_path_traversal_and_case_collision_are_rejected(self) -> None:
        cases = {
            "traversal": self._normal_entries() + [(f"{TOP}/../escape", "file", b"x")],
            "collision": self._normal_entries()
            + [(f"{TOP}/Readme", "file", b"a"), (f"{TOP}/README", "file", b"b")],
        }
        for label, entries in cases.items():
            with self.subTest(label=label):
                archive = self.case / f"{label}.tar.xz"
                self._write_archive(archive, entries)
                with self.assertRaises(MODULE.Refused):
                    MODULE.safe_extract(archive, self.case / f"expanded-{label}", TOP)

    def test_xz_trailing_data_and_nonzero_tar_trailer_are_rejected(self) -> None:
        trailing = self.case / "trailing.tar.xz"
        shutil.copyfile(self.archive, trailing)
        with trailing.open("ab") as stream:
            stream.write(b"archive-comment")
        with self.assertRaisesRegex(MODULE.Refused, "trailing data"):
            MODULE.safe_extract(trailing, self.case / "expanded-trailing", TOP)

        raw = bytearray(lzma.decompress(self.archive.read_bytes(), format=lzma.FORMAT_XZ))
        raw[-1] = 1
        nonzero = self.case / "nonzero.tar.xz"
        nonzero.write_bytes(lzma.compress(bytes(raw), format=lzma.FORMAT_XZ))
        with self.assertRaisesRegex(MODULE.Refused, "trailing data"):
            MODULE.safe_extract(nonzero, self.case / "expanded-nonzero", TOP)

    def test_member_size_limit_is_fail_closed(self) -> None:
        archive = self.case / "size-limit.tar.xz"
        self._write_archive(archive, self._normal_entries())
        with mock.patch.object(MODULE, "MAX_MEMBER", 8):
            with self.assertRaisesRegex(MODULE.Refused, "member exceeds"):
                MODULE.safe_extract(archive, self.case / "expanded-size", TOP)

    def test_writable_and_hardlinked_input_archives_are_rejected(self) -> None:
        writable = self._copy_archive()
        writable.chmod(0o644)
        with self.assertRaisesRegex(MODULE.Refused, "mode 0444"):
            MODULE.require_safe_input(writable, writable.name)
        hardlink = self.case / "hardlink.tar.xz"
        os.link(self.archive, hardlink)
        with self.assertRaisesRegex(MODULE.Refused, "one owner-controlled"):
            MODULE.require_safe_input(hardlink, hardlink.name)

    def test_wrong_archive_tree_and_binary_hashes_fail_closed(self) -> None:
        archive = self._copy_archive()
        cases = (
            {"archive_sha": "0" * 64},
            {"tree_sha": "1" * 64},
            {"binary_sha": "2" * 64},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                manifest = self._manifest(archive, **overrides)
                completed = self._cli("prepare", str(manifest))
                self.assertNotEqual(completed.returncode, 0)

    def test_zip_format_and_duplicate_manifest_keys_are_rejected(self) -> None:
        archive = self._copy_archive()
        manifest = self._manifest(archive, archive_format="zip")
        with self.assertRaisesRegex(MODULE.Refused, "tar.xz"):
            MODULE.load_pin(manifest)
        duplicate = self.case / "duplicate.json"
        duplicate.write_text(
            '{"tools":{"node":{"version":"v1.2.3","version":"v4.5.6"}}}',
            encoding="ascii",
        )
        duplicate.chmod(0o600)
        with self.assertRaisesRegex(MODULE.Refused, "duplicate JSON key"):
            MODULE.load_pin(duplicate)

    def test_oversized_manifest_is_rejected_before_json_parsing(self) -> None:
        oversized = self.case / "oversized.json"
        oversized.write_bytes(b" " * (MODULE.MAX_MANIFEST + 1))
        oversized.chmod(0o600)
        with self.assertRaisesRegex(MODULE.Refused, "manifest size"):
            MODULE.load_pin(oversized)

    def test_runtime_content_and_pointer_replacement_are_detected(self) -> None:
        archive = self._copy_archive()
        fields = self._prepare(self._manifest(archive))
        binary = Path(fields["BINARY"])
        binary.chmod(0o700)
        with binary.open("r+b") as stream:
            stream.seek(-1, os.SEEK_END)
            last = stream.read(1)
            stream.seek(-1, os.SEEK_END)
            stream.write(bytes([last[0] ^ 1]))
        binary.chmod(0o500)
        changed = self._cli("verify", *self._verification(fields))
        self.assertNotEqual(changed.returncode, 0)
        self.assertIn("changed", changed.stderr)
        pointers = self._verification(fields)
        pointers[2] = str(ROOT)
        escaped = self._cli("verify", *pointers)
        self.assertNotEqual(escaped.returncode, 0)

    def test_run_detects_child_mutation_during_execution(self) -> None:
        archive = self._copy_archive()
        fields = self._prepare(self._manifest(archive))
        completed = self._cli("run", *self._verification(fields), "--", "--mutate-self")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("changed", completed.stderr)

    def test_runtime_state_symlink_replacement_is_detected(self) -> None:
        archive = self._copy_archive()
        fields = self._prepare(self._manifest(archive))
        home = Path(fields["RUNTIME"]) / "state/home"
        home.rmdir()
        home.symlink_to(self.case)
        completed = self._cli("verify", *self._verification(fields))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("state directory", completed.stderr)
        home.unlink()
        home.mkdir(mode=0o700)

    def test_shell_and_python_syntax(self) -> None:
        shell = subprocess.run(
            ["/bin/bash", "-n", str(SHELL)], capture_output=True, text=True
        )
        self.assertEqual(shell.returncode, 0, shell.stderr)
        compiled = subprocess.run(
            [sys.executable, "-m", "py_compile", str(TOOL), str(Path(__file__).resolve())],
            capture_output=True,
            text=True,
        )
        self.assertEqual(compiled.returncode, 0, compiled.stderr)


if __name__ == "__main__":
    unittest.main()
