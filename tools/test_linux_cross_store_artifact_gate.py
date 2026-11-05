#!/usr/bin/env python3
"""Focused fail-closed tests for the Linux cross-store artifact gate and held-FD API."""

from __future__ import annotations

import contextlib
import copy
import gc
import gzip
import hashlib
import io
import json
import os
import pathlib
import pickle
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import types
import unittest
from collections.abc import Mapping
from unittest import mock

import tools.linux_cross_store_artifact_gate as gate
import tools.test_linux_cross_store_gate_adapters as adapter_tests
from tools.test_linux_cross_store_gate_adapters import (
    CHROME_ID,
    EDGE_ID,
    LinuxPackageGateFixtures,
    real_executable_elf,
    ring_bound_elf,
    winn3_attestation_document,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]


class _NoopProcessContainment:
    pass_fds: tuple[int, ...] = ()

    def enter_child(self) -> None:
        return None

    def populated(self) -> bool:
        return False

    def kill_all(self) -> None:
        return None

    def wait_empty(self) -> None:
        return None

    def close(self) -> None:
        return None


class _PidFileProcessContainment(_NoopProcessContainment):
    def __init__(self, pid_file: pathlib.Path) -> None:
        self.pid_file = pid_file

    def _pid(self) -> int | None:
        try:
            return int(self.pid_file.read_text(encoding="ascii"))
        except (FileNotFoundError, ValueError):
            return None

    def populated(self) -> bool:
        pid = self._pid()
        if pid is None:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True

    def kill_all(self) -> None:
        pid = self._pid()
        if pid is not None:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, 9)

    def wait_empty(self) -> None:
        deadline = time.monotonic() + 2.0
        while self.populated() and time.monotonic() < deadline:
            time.sleep(0.01)


def loadable_elf64(
    machine: int, *, shared: bool, marker: bytes
) -> bytes:
    names = (
        "",
        ".text",
        *((".dynamic", ".dynstr", ".dynsym") if shared else ()),
        ".shstrtab",
    )
    string_table = b""
    name_offsets: dict[str, int] = {}
    for name in names:
        name_offsets[name] = len(string_table)
        string_table += name.encode("ascii") + b"\0"
    phnum = 2 if shared else 1
    text_offset = 64 + (56 * phnum)
    text = (marker + b"\x90" * 32)[:32]
    dynamic = b""
    dynamic_offset = text_offset + len(text)
    dynstr = b""
    dynstr_offset = dynamic_offset
    dynsym = b""
    dynsym_offset = dynamic_offset
    if shared:
        dynstr = b"\0libc.so.6\0"
        dynsym = b"\0" * 24
        dynamic = b"".join(
            struct.pack("<QQ", tag, value)
            for tag, value in (
                (5, 0x400000 + dynamic_offset + 80),
                (6, 0x400000 + dynamic_offset + 80 + len(dynstr)),
                (10, len(dynstr)),
                (11, 24),
                (0, 0),
            )
        )
        dynstr_offset = dynamic_offset + len(dynamic)
        dynsym_offset = dynstr_offset + len(dynstr)
    shstr_offset = dynsym_offset + len(dynsym)
    shoff = shstr_offset + len(string_table)
    shoff += (8 - (shoff % 8)) % 8
    total_size = shoff + (len(names) * 64)
    payload = bytearray(total_size)
    payload[0:4] = b"\x7fELF"
    payload[4] = 2
    payload[5] = 1
    payload[6] = 1
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        payload,
        16,
        3 if shared else 2,
        machine,
        1,
        0 if shared else 0x400000 + text_offset,
        64,
        shoff,
        0,
        64,
        56,
        phnum,
        64,
        len(names),
        len(names) - 1,
    )
    struct.pack_into(
        "<IIQQQQQQ",
        payload,
        64,
        gate.PT_LOAD,
        gate.PF_R | gate.PF_X,
        0,
        0x400000,
        0x400000,
        total_size,
        total_size,
        0x1000,
    )
    if shared:
        struct.pack_into(
            "<IIQQQQQQ",
            payload,
            120,
            gate.PT_DYNAMIC,
            gate.PF_R,
            dynamic_offset,
            0x400000 + dynamic_offset,
            0x400000 + dynamic_offset,
            len(dynamic),
            len(dynamic),
            8,
        )
    payload[text_offset : text_offset + len(text)] = text
    payload[dynamic_offset : dynamic_offset + len(dynamic)] = dynamic
    payload[dynstr_offset : dynstr_offset + len(dynstr)] = dynstr
    payload[dynsym_offset : dynsym_offset + len(dynsym)] = dynsym
    payload[shstr_offset : shstr_offset + len(string_table)] = string_table
    section_data = {
        ".text": (1, text_offset, len(text)),
        ".dynamic": (6, dynamic_offset, len(dynamic)),
        ".dynstr": (3, dynstr_offset, len(dynstr)),
        ".dynsym": (11, dynsym_offset, len(dynsym)),
        ".shstrtab": (3, shstr_offset, len(string_table)),
    }
    for index, name in enumerate(names):
        header_offset = shoff + (index * 64)
        struct.pack_into("<I", payload, header_offset, name_offsets[name])
        if name:
            section_type, offset, size = section_data[name]
            struct.pack_into("<I", payload, header_offset + 4, section_type)
            struct.pack_into("<Q", payload, header_offset + 24, offset)
            struct.pack_into("<Q", payload, header_offset + 32, size)
    return bytes(payload)


class LinuxCrossStoreArtifactGateTests(LinuxPackageGateFixtures, unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()

    def _verify(
        self,
        target: str,
        artifact: pathlib.Path,
        *,
        bind_owner: bool = True,
        owner_ids: dict[str, str] | None = None,
    ) -> gate.VerificationResult:
        """Focused fixtures do not replace authenticated stdlib runtime objects."""
        issued = owner_ids or {"chrome": CHROME_ID, "edge": EDGE_ID}
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    gate, "_verify_signature", side_effect=self._signature_custody
                )
            )
            stack.enter_context(
                mock.patch.object(
                    gate, "_verify_build_provenance", side_effect=self._build_custody
                )
            )
            stack.enter_context(
                mock.patch.object(
                    gate,
                    "_bind_native_host_source_freeze_custody",
                    side_effect=self._source_freeze_custody,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    gate, "OWNER_COSIGN_TRUST_ANCHOR_SHA256", "a" * 64
                )
            )
            if bind_owner:
                stack.enter_context(
                    mock.patch.object(
                        gate, "_owner_issued_chromium_ids", return_value=issued
                    )
                )
            return gate.verify_package(
                target, artifact.relative_to(self.repo).as_posix()
            )

    def _held_overrides(self, machine: int) -> dict[str, bytes]:
        overrides = {
            name: loadable_elf64(
                machine,
                shared=False,
                marker=name.encode("ascii"),
            )
            for name in gate.REQUIRED_PROGRAM_ELFS
        }
        overrides.update(
            {
                name: loadable_elf64(
                    machine,
                    shared=True,
                    marker=name.encode("ascii"),
                )
                for name in gate.REQUIRED_LIBRARY_ELFS
            }
        )
        overrides[gate.WINN3_DESCRIPTOR_RING_VERIFIED_ARTIFACT] += (
            gate.REVIEWED_WINN3_DESCRIPTOR_RING_SHA256.encode("ascii")
        )
        overrides[gate.RUNTIME_PROTOCOL_ORDER_PATH] = (
            gate._canonical_runtime_protocol_order()
        )
        baseline = self._payloads(machine)
        provenance = json.loads(
            baseline[gate.NATIVE_HOST_PROVENANCE_PATH].decode("ascii")
        )
        native_host = overrides[gate.NATIVE_HOST_PATH]
        for record in provenance["packaged_assets"]:
            if record["path"] == gate.NATIVE_HOST_PATH:
                record["sha256"] = hashlib.sha256(native_host).hexdigest()
                record["bytes"] = len(native_host)
        overrides[gate.NATIVE_HOST_PROVENANCE_PATH] = (
            json.dumps(
                provenance,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            + "\n"
        ).encode("ascii")
        return overrides

    def _write_held_archive(
        self,
        arch: str = "x64",
        machine: int = 62,
        *,
        payload_overrides: dict[str, bytes] | None = None,
        unsafe_member: tarfile.TarInfo | None = None,
    ) -> pathlib.Path:
        overrides = self._held_overrides(machine)
        overrides.update(payload_overrides or {})
        return self._write_archive(
            arch,
            machine,
            payload_overrides=overrides,
            unsafe_member=unsafe_member,
        )

    def _held_verify(
        self,
        target_id: str,
        artifact: pathlib.Path,
        *,
        signature_side_effect: object = None,
        patch_signature: bool = True,
        bind_owner_pin: bool = True,
        writable: bool = False,
        expected_sha256: str | None = None,
        expected_size: int | None = None,
        expected_identity: tuple[int, ...] | None = None,
        frozen_release: str = gate.CANONICAL_RELEASE,
    ) -> gate.VerificationResult:
        flags = os.O_RDWR if writable else os.O_RDONLY
        source_fd = os.open(artifact, flags | os.O_CLOEXEC | os.O_NOFOLLOW)
        parent_fd = os.open(
            artifact.parent,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
        )
        info = os.fstat(source_fd)
        digest = hashlib.sha256(os.pread(source_fd, info.st_size, 0)).hexdigest()
        issued = {"chrome": CHROME_ID, "edge": EDGE_ID}
        owner_context = (
            mock.patch.object(
                gate,
                "OWNER_COSIGN_TRUST_ANCHOR_SHA256",
                "a" * 64,
            )
            if bind_owner_pin
            else contextlib.nullcontext()
        )
        try:
            with mock.patch.object(
                gate,
                "_bind_native_host_source_freeze_custody",
                side_effect=self._source_freeze_custody,
            ), mock.patch.object(
                gate,
                "_owner_issued_chromium_ids",
                return_value=issued,
            ), owner_context, mock.patch.object(
                gate,
                "_verify_checksum",
                return_value=artifact.with_name(artifact.name + ".sha256"),
            ), mock.patch.object(
                gate,
                "_verify_build_provenance",
                side_effect=self._build_custody,
            ):
                signature_patch = (
                    mock.patch.object(
                        gate,
                        "_verify_signature",
                        side_effect=signature_side_effect,
                    )
                    if patch_signature and signature_side_effect is not None
                    else mock.patch.object(
                        gate,
                        "_verify_signature",
                        side_effect=self._signature_custody,
                    )
                    if patch_signature
                    else contextlib.nullcontext()
                )
                with signature_patch:
                    return gate.verify_held_release_artifact(
                        target_id=target_id,
                        source_fd=source_fd,
                        source_parent_fd=parent_fd,
                        source_name=artifact.name,
                        source_relative_path=artifact.relative_to(self.repo).as_posix(),
                        expected_identity=(
                            gate._file_identity(info)
                            if expected_identity is None
                            else expected_identity
                        ),
                        expected_size=(info.st_size if expected_size is None else expected_size),
                        expected_sha256=(
                            digest if expected_sha256 is None else expected_sha256
                        ),
                        frozen_release=frozen_release,
                    )
        finally:
            os.close(parent_fd)
            os.close(source_fd)

    def _replace_archive_stream(
        self, artifact: pathlib.Path, uncompressed: bytes
    ) -> None:
        with artifact.open("wb") as output:
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=output, mtime=0
            ) as compressed:
                compressed.write(uncompressed)
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        artifact.with_name(artifact.name + ".sha256").write_text(
            f"{digest}  {artifact.name}\n", encoding="ascii"
        )

    @staticmethod
    def _first_tar_end(uncompressed: bytes) -> int:
        marker = b"\0" * 1024
        for offset in range(0, max(len(uncompressed) - 1023, 0), 512):
            if uncompressed[offset : offset + 1024] == marker:
                return offset
        raise AssertionError("fixture tar lacks a canonical two-block end marker")

    @staticmethod
    def _zip_bytes(members: dict[str, bytes]) -> bytes:
        output = io.BytesIO()
        with gate.REVIEWED_ZIPFILE.ZipFile(
            output,
            mode="w",
            compression=gate.REVIEWED_ZIPFILE.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            for name, payload in members.items():
                info = gate.REVIEWED_ZIPFILE.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(
                    info,
                    payload,
                    compress_type=gate.REVIEWED_ZIPFILE.ZIP_DEFLATED,
                    compresslevel=9,
                )
        return output.getvalue()

    @staticmethod
    def _fixture_service_account() -> bytes:
        return json.dumps(
            {
                "client_email": "fixture@example.invalid",
                "private_key": (
                    "-----BEGIN PRIVATE KEY-----\n"
                    "fixture-only-not-a-real-key\n"
                    "-----END PRIVATE KEY-----\n"
                ),
                "type": "service_account",
            },
            sort_keys=True,
        ).encode("ascii")

    def _load_temporary_module_custody(
        self, temporary: pathlib.Path, alias: str
    ) -> tuple[pathlib.Path, tuple[gate._BoundModuleSource, ...]]:
        source = temporary / f"{alias}.py"
        source.write_text("VALUE = 'reviewed'\n", encoding="ascii")
        _loaded, custody = gate._load_module_closure(
            ((source, alias, "", (alias,)),),
            source_root=temporary,
        )
        return source, custody

    @staticmethod
    def _close_temporary_module_custody(
        custody: tuple[gate._BoundModuleSource, ...], alias: str
    ) -> None:
        sys.modules.pop(alias, None)
        for source in custody:
            source.close()

    def test_pythonpath_cannot_substitute_required_modules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evil = pathlib.Path(tmp)
            (evil / "linux_release_signing.py").write_text(
                "raise SystemExit('poisoned-signing')\n", encoding="utf-8"
            )
            (evil / "release_source_freeze.py").write_text(
                "raise SystemExit('poisoned-freeze')\n", encoding="utf-8"
            )
            env = os.environ.copy()
            env["PYTHONPATH"] = str(evil)
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-c",
                    f"import sys; sys.path.insert(0, {str(ROOT)!r}); "
                    "import tools.linux_cross_store_artifact_gate as g; "
                    "print(g.linux_release_signing.COSIGN_VERSION); "
                    "print(g.source_freeze.LOCK_CONTRACT)",
                ],
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("v3.1.3", completed.stdout)
        self.assertIn("winsvpn-app-source-lock-v1", completed.stdout)
        self.assertNotIn("poisoned", completed.stdout + completed.stderr)

    def test_sitecustomize_and_sys_modules_poisoning_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evil = pathlib.Path(tmp) / "linux_release_signing.py"
            evil.write_text("COSIGN_VERSION = 'poisoned'\n", encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-c",
                    f"import sys; sys.path.insert(0, {str(ROOT)!r});"
                    "import types, pathlib;"
                    f"p = pathlib.Path({str(evil)!r});"
                    "fake = types.ModuleType('linux_release_signing');"
                    "fake.__file__ = str(p);"
                    "fake.COSIGN_VERSION = 'poisoned';"
                    "sys.modules['linux_release_signing'] = fake;"
                    "import tools.linux_cross_store_artifact_gate as g",
                ],
                cwd=ROOT,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            combined = (completed.stderr + completed.stdout).lower()
            self.assertIn("poisoned", combined)

        with tempfile.TemporaryDirectory() as tmp:
            injection = pathlib.Path(tmp)
            marker = injection / "sitecustomize-ran"
            (injection / "linux_release_signing.py").write_text(
                "COSIGN_VERSION = 'poisoned'\n", encoding="utf-8"
            )
            (injection / "sitecustomize.py").write_text(
                "import sys, types\n"
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed')\n"
                "fake = types.ModuleType('linux_release_signing')\n"
                f"fake.__file__ = {str(injection / 'linux_release_signing.py')!r}\n"
                "fake.COSIGN_VERSION = 'poisoned'\n"
                "sys.modules['linux_release_signing'] = fake\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env.pop("PYTHONSAFEPATH", None)
            env.pop("PYTHONNOUSERSITE", None)
            env["PYTHONPATH"] = str(injection)
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-c",
                    f"import sys; sys.path.insert(0, {str(ROOT)!r});"
                    "import tools.linux_cross_store_artifact_gate as g",
                ],
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertFalse(
                marker.exists(),
                "authenticated isolated Python unexpectedly executed sitecustomize",
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertNotIn(
                "poisoned", (completed.stderr + completed.stdout).lower()
            )

        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-c",
                (
                    "import sys, subprocess\n"
                    f"sys.path.insert(0, {str(ROOT)!r})\n"
                    "executed = False\n"
                    "def hostile(*args, **kwargs):\n"
                    " global executed\n"
                    " executed = True\n"
                    " raise AssertionError('startup poison executed')\n"
                    "subprocess.run = hostile\n"
                    "import tools.linux_cross_store_artifact_gate"
                ),
            ],
            cwd=ROOT,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("held source", (completed.stderr + completed.stdout).lower())
        self.assertNotIn("startup poison executed", completed.stderr + completed.stdout)

    def test_module_origin_bytes_match_repository_files(self) -> None:
        custody = {source.public_name: source for source in gate._MODULE_CUSTODY}
        self.assertEqual(set(custody), {name for _filename, name in gate.REQUIRED_MODULE_FILES})
        for filename, public_name in gate.REQUIRED_MODULE_FILES:
            module = gate._MODULES[public_name]
            origin = ROOT / "tools" / filename
            source = custody[public_name]
            self.assertEqual(pathlib.Path(module.__file__).resolve(), origin.resolve())
            self.assertGreaterEqual(source.fd, 0)
            self.assertEqual(
                hashlib.sha256(origin.read_bytes()).hexdigest(),
                source.digest,
            )
            self.assertEqual(source.payload, origin.read_bytes())
            self.assertIs(sys.modules[public_name], module)
            self.assertIs(sys.modules[f"tools.{public_name}"], module)
            source.revalidate()

    def test_bound_module_custody_rejects_mutation_unlink_replacement_and_poison(self) -> None:
        cases = ("mutation", "unlink", "replacement", "poison")
        for index, case in enumerate(cases):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                temporary = pathlib.Path(tmp)
                alias = f"winsvpn_linux_gate_hostile_{index}"
                source_path, custody = self._load_temporary_module_custody(
                    temporary, alias
                )
                original = source_path.read_bytes()
                moved = source_path.with_suffix(".reviewed")
                try:
                    if case == "mutation":
                        source_path.write_bytes(b"VALUE = 'mutated'\n")
                    elif case == "unlink":
                        source_path.unlink()
                    elif case == "replacement":
                        source_path.rename(moved)
                        source_path.write_bytes(original)
                    else:
                        sys.modules[alias] = types.ModuleType(alias)
                    with self.assertRaisesRegex(
                        gate.LinuxArtifactGateError,
                        r"changed|removed|replaced|poisoned",
                    ):
                        gate._verify_module_custody(custody)
                finally:
                    if source_path.exists():
                        source_path.unlink()
                    if moved.exists():
                        moved.rename(source_path)
                    elif not source_path.exists():
                        source_path.write_bytes(original)
                    self._close_temporary_module_custody(custody, alias)

    def test_module_custody_revalidates_after_runner_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temporary = pathlib.Path(tmp)
            alias = "winsvpn_linux_gate_runner_exception"
            source_path, custody = self._load_temporary_module_custody(
                temporary, alias
            )
            artifact = self._write_held_archive()

            def mutate_then_fail(_snapshot: gate.HeldArtifactSnapshot) -> pathlib.Path:
                source_path.write_bytes(b"VALUE = 'runner-mutated'\n")
                raise RuntimeError("runner-exception")

            try:
                with mock.patch.object(gate, "_MODULE_CUSTODY", custody):
                    with self.assertRaisesRegex(
                        gate.LinuxArtifactGateError,
                        r"required module .* changed",
                    ):
                        self._held_verify(
                            "linux-x64-package",
                            artifact,
                            signature_side_effect=mutate_then_fail,
                        )
            finally:
                self._close_temporary_module_custody(custody, alias)

    def test_module_loader_rejects_import_and_path_poisoning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temporary = pathlib.Path(tmp)
            source = temporary / "reviewed.py"
            source.write_text(
                "import winsvpn_unreviewed_dependency\nVALUE = 'bad'\n",
                encoding="ascii",
            )
            evil = temporary / "evil"
            evil.mkdir()
            marker = evil / "executed"
            (evil / "winsvpn_unreviewed_dependency.py").write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed')\n",
                encoding="ascii",
            )
            sys.path.insert(0, str(evil))
            try:
                with self.assertRaises(ModuleNotFoundError):
                    gate._load_module_closure(
                        ((source, "reviewed", "", ("reviewed",)),),
                        source_root=temporary,
                    )
            finally:
                sys.path.remove(str(evil))
                sys.modules.pop("reviewed", None)
                sys.modules.pop("winsvpn_unreviewed_dependency", None)
            self.assertFalse(marker.exists())

        class PoisonFinder:
            pass

        sys.meta_path.append(PoisonFinder())
        try:
            with self.assertRaisesRegex(
                gate.LinuxArtifactGateError, "import boundary is poisoned"
            ):
                gate._require_pristine_meta_path()
        finally:
            sys.meta_path.pop()

    def test_private_module_custody_recovers_only_bounded_authenticated_orphan(self) -> None:
        _root, root_fd = gate._open_module_custody_root()
        name = gate._module_custody_child_name()
        child_fd = -1
        try:
            os.mkdir(name, 0o700, dir_fd=root_fd)
            child_fd = gate._openat_child(
                root_fd,
                name,
                gate._dir_open_flags(),
                label="test module custody orphan",
            )
            file_fd = os.open(
                "00-orphan.py",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                0o400,
                dir_fd=child_fd,
            )
            try:
                os.write(file_fd, b"VALUE = 'orphan'\n")
                os.fsync(file_fd)
            finally:
                os.close(file_fd)
            old = time.time() - gate.MODULE_CUSTODY_STALE_SECONDS - 10
            os.utime(name, (old, old), dir_fd=root_fd, follow_symlinks=False)
            os.close(child_fd)
            child_fd = -1
            gate._recover_module_custody_orphans(root_fd)
            self.assertNotIn(name, os.listdir(root_fd))
        finally:
            if child_fd >= 0:
                os.close(child_fd)
            if name in os.listdir(root_fd):
                cleanup_fd = gate._openat_child(
                    root_fd,
                    name,
                    gate._dir_open_flags(),
                    label="test module custody cleanup",
                )
                try:
                    retained = os.fstat(cleanup_fd)
                    gate._remove_module_custody_child(
                        root_fd,
                        name,
                        cleanup_fd,
                        gate._module_custody_child_identity(retained),
                    )
                finally:
                    os.close(cleanup_fd)
            os.close(root_fd)

    def test_flutter_payload_identities_are_exact_and_distinct(self) -> None:
        artifact = self._write_archive()
        result = self._verify("linux-x64-package", artifact)
        identities = result["flutter_identities"]
        self.assertEqual(identities["lib/libapp.so"]["type"], "elf64-le")
        self.assertEqual(identities["lib/libflutter_linux_gtk.so"]["elf_machine"], 62)
        self.assertEqual(identities["data/icudtl.dat"]["type"], "data")
        self.assertEqual(identities["winsvpn-bypass-bpf"]["path"], "winsvpn-bypass-bpf")
        self.assertFalse(result["publication_authorized"])
        self.assertFalse(result["upload_attempted"])
        self.assertEqual(result["owner_authorization"], "pending")
        self.assertEqual(
            len(
                {
                    identities["lib/libapp.so"]["sha256"],
                    identities["lib/libflutter_linux_gtk.so"]["sha256"],
                    identities["winsvpn-bypass-bpf"]["sha256"],
                }
            ),
            3,
        )

    def test_duplicate_flutter_library_digest_fails_closed(self) -> None:
        shared = ring_bound_elf(62, marker=b"same-lib")
        artifact = self._write_archive(
            payload_overrides={
                "lib/libapp.so": shared,
                "lib/libflutter_linux_gtk.so": shared,
            }
        )
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "distinct"):
            self._verify("linux-x64-package", artifact)

    def test_zero_entry_program_elf_fails_closed(self) -> None:
        payload = bytearray(real_executable_elf(62, marker=b"wins_vpn"))
        payload[24:32] = b"\x00" * 8
        artifact = self._write_archive(payload_overrides={"wins_vpn": bytes(payload)})
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "entry point is zero"):
            self._verify("linux-x64-package", artifact)

    def test_nested_gzip_member_exceeds_depth_limit(self) -> None:
        artifact = self._write_archive(
            payload_overrides={"share/doc/wins-vpn/RECOVERY.md": b"\x1f\x8b" + b"\x00" * 20}
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"nesting depth|nested tar archive is malformed|privacy scan",
        ):
            self._verify("linux-x64-package", artifact)

    def test_nested_zip_service_account_json_fails_privacy_scan(self) -> None:
        nested = self._zip_bytes(
            {"credentials/service-account.json": self._fixture_service_account()}
        )
        artifact = self._write_archive(
            payload_overrides={"share/doc/wins-vpn/RECOVERY.md": nested}
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"privacy scan|service.account|credential|private key",
        ):
            self._verify("linux-x64-package", artifact)

    def test_nested_zip_bomb_is_rejected_before_member_expansion(self) -> None:
        nested = self._zip_bytes({"bomb.bin": b"\0" * (2 * 1024 * 1024)})
        artifact = self._write_archive(
            payload_overrides={"share/doc/wins-vpn/RECOVERY.md": nested}
        )
        with mock.patch.object(
            gate.REVIEWED_ZIPFILE.ZipFile,
            "open",
            side_effect=AssertionError("ZIP member expanded before budget rejection"),
        ), self.assertRaisesRegex(
            gate.LinuxArtifactGateError, r"compression ratio"
        ):
            self._verify("linux-x64-package", artifact)

    def test_nested_zstd_secret_is_recursively_scanned(self) -> None:
        nested = gate.REVIEWED_ZSTD.compress(self._fixture_service_account())
        artifact = self._write_archive(
            payload_overrides={"share/doc/wins-vpn/RECOVERY.md": nested}
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"privacy scan|service.account|credential|private key",
        ):
            self._verify("linux-x64-package", artifact)

    def test_nested_zstd_bomb_is_rejected_before_expansion(self) -> None:
        nested = gate.REVIEWED_ZSTD.compress(b"\0" * (2 * 1024 * 1024), level=19)
        artifact = self._write_archive(
            payload_overrides={"share/doc/wins-vpn/RECOVERY.md": nested}
        )
        with mock.patch.object(
            gate.REVIEWED_ZSTD,
            "ZstdDecompressor",
            side_effect=AssertionError("zstd expanded before budget rejection"),
        ), self.assertRaisesRegex(
            gate.LinuxArtifactGateError, r"compression ratio"
        ):
            self._verify("linux-x64-package", artifact)

    def test_source_does_not_reopen_caller_path_for_archive_bytes(self) -> None:
        source = (ROOT / "tools/linux_cross_store_artifact_gate.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("_snapshot_artifact", source)
        self.assertIn("_bind_repo_file", source)
        self.assertIn("_openat_child", source)
        self.assertIn("else _bind_repo_file(origin, label)", source)
        self.assertNotIn("identity_fd = os.open(identity_path, _open_flags())", source)
        self.assertNotIn('tarfile.open(path, "r:gz")', source)
        self.assertNotIn("archive.getmembers()", source)
        self.assertNotIn("spec_from_file_location", source)
        self.assertNotIn("atexit.register", source)
        self.assertNotIn("winsvpn-mod-", source)
        self.assertIn("_private_module_custody", source)
        self.assertIn("compile(", source)
        self.assertIn("source.revalidate()", source)
        self.assertIn("_scan_store_package_payloads", source)
        self.assertIn("bind_linux_package_upload_receipts", source)
        self.assertIn("remain pending without owner evidence", source)

    @unittest.skipUnless(hasattr(os, "fork"), "fork unavailable")
    def test_artifact_snapshot_startup_gc_recovers_os_exit_orphan(self) -> None:
        artifact = self._write_archive()
        pid = os.fork()
        if pid == 0:
            try:
                gate._snapshot_artifact(artifact.resolve(), "crash orphan artifact")
            finally:
                os._exit(0)
        waited, status = os.waitpid(pid, 0)
        self.assertEqual(waited, pid)
        self.assertEqual(status, 0)
        candidates = sorted(
            path
            for path in (self.repo / ".artifacts").iterdir()
            if path.name.startswith(gate.ARTIFACT_SNAPSHOT_PREFIX)
        )
        self.assertEqual(len(candidates), 1)
        orphan = candidates[0]
        stale = time.time() - gate.ARTIFACT_SNAPSHOT_STALE_SECONDS - 10
        os.utime(orphan, (stale, stale), follow_symlinks=False)
        replacement = gate._snapshot_artifact(
            artifact.resolve(), "post-crash artifact"
        )
        try:
            self.assertFalse(orphan.exists())
            replacement.ensure_bound()
        finally:
            replacement.close()
            shutil.rmtree(replacement.root, ignore_errors=True)

    def test_artifact_snapshot_startup_gc_preserves_locked_live_snapshot(self) -> None:
        artifact = self._write_archive()
        live = gate._snapshot_artifact(artifact.resolve(), "live artifact")
        stale = time.time() - gate.ARTIFACT_SNAPSHOT_STALE_SECONDS - 10
        os.utime(live.root, (stale, stale), follow_symlinks=False)
        second = gate._snapshot_artifact(artifact.resolve(), "second artifact")
        try:
            self.assertTrue(live.root.is_dir())
            live.ensure_bound()
        finally:
            second.close()
            live.close()
            shutil.rmtree(second.root, ignore_errors=True)
            shutil.rmtree(live.root, ignore_errors=True)

    def test_artifact_snapshot_startup_gc_bounds_orphan_count(self) -> None:
        artifacts = self.repo / ".artifacts"
        stale = time.time() - gate.ARTIFACT_SNAPSHOT_STALE_SECONDS - 10
        for index in range(gate.ARTIFACT_SNAPSHOT_MAX_ORPHANS + 1):
            orphan = artifacts / (
                gate.ARTIFACT_SNAPSHOT_PREFIX + f"{index:032x}"
            )
            orphan.mkdir(mode=0o700)
            os.utime(orphan, (stale, stale), follow_symlinks=False)
        artifact = self._write_archive()
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "orphan count exceeds"
        ):
            gate._snapshot_artifact(artifact.resolve(), "bounded orphan artifact")

    def test_artifact_snapshot_orphan_rejects_oversized_lease_before_read(self) -> None:
        artifacts = self.repo / ".artifacts"
        name = gate.ARTIFACT_SNAPSHOT_PREFIX + "f" * 32
        orphan = artifacts / name
        orphan.mkdir(mode=0o700)
        lease = orphan / gate.ARTIFACT_SNAPSHOT_LEASE
        lease.write_bytes(gate._artifact_snapshot_lease_payload(name))
        with lease.open("r+b") as stream:
            stream.truncate(1024 * 1024 * 1024)
        lease.chmod(0o400)
        stale = time.time() - gate.ARTIFACT_SNAPSHOT_STALE_SECONDS - 10
        os.utime(orphan, (stale, stale), follow_symlinks=False)
        artifact = self._write_archive()
        original_pread = gate.os.pread
        lease_fd_seen = -1

        def bounded_pread(fd: int, size: int, offset: int) -> bytes:
            nonlocal lease_fd_seen
            try:
                opened = os.fstat(fd)
                named = lease.stat()
            except OSError:
                pass
            else:
                if gate._file_identity(opened) == gate._file_identity(named):
                    lease_fd_seen = fd
                    self.fail("oversized orphan lease was read before size rejection")
            return original_pread(fd, size, offset)

        with (
            mock.patch.object(gate.os, "pread", side_effect=bounded_pread),
            self.assertRaisesRegex(gate.LinuxArtifactGateError, "lease is invalid"),
        ):
            gate._snapshot_artifact(artifact.resolve(), "oversized lease artifact")
        self.assertEqual(lease_fd_seen, -1)

    def test_snapshot_close_deletes_through_retained_fd_while_lease_locked(self) -> None:
        artifact = self._write_archive()
        snapshot = gate._snapshot_artifact(artifact.resolve(), "retained cleanup artifact")
        second_lease = os.open(
            snapshot.root / gate.ARTIFACT_SNAPSHOT_LEASE,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        original_remove = gate._remove_artifact_snapshot_tree
        observed_locked = False

        def remove_while_locked(directory_fd, *, depth, counters, preserve=frozenset()):
            nonlocal observed_locked
            with self.assertRaises(BlockingIOError):
                gate.fcntl.flock(second_lease, gate.fcntl.LOCK_EX | gate.fcntl.LOCK_NB)
            observed_locked = True
            return original_remove(
                directory_fd, depth=depth, counters=counters, preserve=preserve
            )

        root = snapshot.root
        try:
            with (
                mock.patch.object(
                    gate, "_remove_artifact_snapshot_tree", side_effect=remove_while_locked
                ),
                mock.patch.object(
                    gate.shutil,
                    "rmtree",
                    side_effect=AssertionError("pathname cleanup must not run"),
                ),
            ):
                snapshot.close()
        finally:
            os.close(second_lease)
        self.assertTrue(observed_locked)
        self.assertFalse(root.exists())

    @unittest.skipUnless(hasattr(os, "fork"), "fork unavailable")
    def test_active_extraction_os_exit_recovery_kills_holder_before_fd_cleanup(self) -> None:
        artifact = self._write_archive()
        pid_file = self.repo / ".artifacts/active-extractor.pid"
        child = os.fork()
        if child == 0:
            snapshot = gate._snapshot_artifact(artifact.resolve(), "active extraction orphan")
            gate._create_retained_extraction_directory(snapshot)
            holder = os.fork()
            if holder == 0:
                time.sleep(30)
                os._exit(0)
            pid_file.write_text(str(holder), encoding="ascii")
            os._exit(0)
        os.waitpid(child, 0)
        holder = int(pid_file.read_text(encoding="ascii"))
        candidates = sorted(
            path
            for path in (self.repo / ".artifacts").iterdir()
            if path.name.startswith(gate.ARTIFACT_SNAPSHOT_PREFIX)
        )
        self.assertEqual(len(candidates), 1)
        orphan = candidates[0]
        stale = time.time() - gate.ARTIFACT_SNAPSHOT_STALE_SECONDS - 10
        os.utime(orphan, (stale, stale), follow_symlinks=False)
        recovered: list[int] = []

        def recover_holder() -> None:
            os.kill(holder, signal.SIGKILL)
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                try:
                    os.kill(holder, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.01)
            recovered.append(holder)

        replacement = None
        try:
            with (
                mock.patch.object(gate.sys, "platform", "linux"),
                mock.patch.object(
                    gate, "_recover_linux_process_orphans", side_effect=recover_holder
                ),
            ):
                replacement = gate._snapshot_artifact(
                    artifact.resolve(), "post-active-extraction artifact"
                )
            self.assertEqual(recovered, [holder])
            self.assertFalse(orphan.exists())
        finally:
            with contextlib.suppress(ProcessLookupError):
                os.kill(holder, signal.SIGKILL)
            with contextlib.suppress(ChildProcessError):
                os.waitpid(holder, 0)
            if replacement is not None:
                replacement.close()

    def test_recursive_archive_modules_cannot_be_replaced_in_sys_modules(self) -> None:
        for name in ("zipfile", "tarfile", "compression", "compression.zstd", "fcntl"):
            with self.subTest(module=name), mock.patch.dict(
                sys.modules, {name: types.ModuleType(name)}
            ), self.assertRaisesRegex(
                gate.LinuxArtifactGateError, r"identity is poisoned"
            ):
                gate._scan_store_package_payloads({"plain.txt": b"safe\n"})

    def test_remote_attested_receipt_block_is_admitted_and_unknown_fields_are_not(self) -> None:
        # tools/release_remote_build.py finish adds one block, remote_attestation, to the
        # Linux build receipt. The gate's own key check refused it ("fields are incomplete
        # or unexpected") although freeze.verify_build_receipt accepts and requires it.
        base = json.loads(self.receipt.read_text(encoding="ascii"))
        self.assertIsNotNone(gate._load_receipt_record(self.receipt))
        remote = self.downloads / "REMOTE_BUILD_RECEIPT.json"
        adapter_tests._write_json_fixture(
            remote, dict(base, remote_attestation={"begin": {}, "run_record": {}})
        )
        self.assertIsNotNone(gate._load_receipt_record(remote))
        unknown = self.downloads / "UNKNOWN_FIELD_BUILD_RECEIPT.json"
        adapter_tests._write_json_fixture(unknown, dict(base, remote_attested="x"))
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, r"fields are incomplete or unexpected"
        ):
            gate._load_receipt_record(unknown)

    def test_gzip_member_that_is_text_is_expanded_and_scanned(self) -> None:
        # Flutter ships assets/flutter_assets/NOTICES.Z, one gzip-compressed text,
        # not a tarball. The gate must expand it and scan the expanded bytes.
        notices = gzip.compress(b"License notices\nThis package is MIT licensed.\n", mtime=0)
        gate._scan_store_package_payloads({"data/flutter_assets/NOTICES.Z": notices})

        leaking = gzip.compress(b"built in /Users/attacker/secret/key\n", mtime=0)
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, r"privacy scan failed"):
            gate._scan_store_package_payloads({"data/flutter_assets/NOTICES.Z": leaking})

    def test_gzip_member_that_is_not_inspectable_fails_closed(self) -> None:
        truncated = gzip.compress(b"License notices\n" * 64, mtime=0)[:-6]
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, r"nested tar archive is malformed|privacy scan"
        ):
            gate._scan_store_package_payloads({"data/flutter_assets/NOTICES.Z": truncated})

    def test_gzip_member_that_is_a_tarball_still_takes_the_tar_scan(self) -> None:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as inner:
            body = b"nested safe text\n"
            info = tarfile.TarInfo("inner/readme.txt")
            info.size = len(body)
            inner.addfile(info, io.BytesIO(body))
        gate._scan_store_package_payloads(
            {"data/nested.tar.gz": gzip.compress(buffer.getvalue(), mtime=0)}
        )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_ancestor_replacement_after_descriptor_bind_fails_closed(self) -> None:
        artifact = self._write_archive()
        relative = artifact.relative_to(self.repo).as_posix()
        bound = gate._secure_regular_repo_path(relative, "Linux package artifact")
        parent = bound.parent
        outside = pathlib.Path(str(self.temporary.name) + "-outside-linux-ancestor")
        outside.mkdir(exist_ok=True)
        evil = outside / bound.name
        evil.write_bytes(b"attacker-substituted-linux-archive\n" * 64)
        real = parent.with_name(parent.name + ".real")
        try:
            parent.rename(real)
            parent.symlink_to(outside)
            with self.assertRaisesRegex(
                gate.LinuxArtifactGateError,
                r"symlink ancestor|symbolic link|outside the bound Linux gate root|parent path was swapped",
            ) as raised:
                snapshot = gate._snapshot_artifact(bound, "Linux package artifact")
                try:
                    self.fail(
                        "ancestor replacement produced snapshot "
                        + snapshot.digest
                    )
                finally:
                    snapshot.close()
                    shutil.rmtree(snapshot.root, ignore_errors=True)
            self.assertNotIn("owner/environment blocker", str(raised.exception))
            self.assertNotEqual(
                hashlib.sha256(evil.read_bytes()).hexdigest(),
                hashlib.sha256((real / bound.name).read_bytes()).hexdigest(),
            )
        finally:
            if parent.is_symlink():
                parent.unlink()
            elif parent.exists() and parent != real:
                shutil.rmtree(parent, ignore_errors=True)
            if real.exists() and not parent.exists():
                real.rename(parent)
            shutil.rmtree(outside, ignore_errors=True)

    def test_source_does_not_pass_none_or_swallow_receipt_binding(self) -> None:
        source = (ROOT / "tools/linux_cross_store_artifact_gate.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn(
            'freeze.verify_build_receipt(root, index_path, "linux", receipt, None)',
            source,
        )
        self.assertNotIn(
            "except (OSError, ValueError, json.JSONDecodeError, freeze.DependencyFreezeError):",
            source,
        )
        self.assertIn("descriptor-bound immutable artifact snapshot origin", source)
        self.assertIn("does not bind the artifact", source)

    def test_canonical_targets_follow_current_repository_policy(self) -> None:
        self.assertEqual(gate.CANONICAL_RELEASE, "1.0.17+34")
        self.assertIs(gate.TEST_ONLY, False)
        self.assertEqual(
            set(gate.TARGETS),
            {"linux-x64-package", "linux-arm64-package"},
        )
        self.assertEqual(
            set(gate.STORE_MANIFEST_TARGETS),
            {"linux-flathub-manifest", "linux-snap-manifest"},
        )
        invented = {
            "linux-x64-deb",
            "linux-arm64-deb",
            "linux-x64-snap",
            "linux-arm64-snap",
            "linux-x64-flathub",
            "linux-arm64-flathub",
            "linux-x64-appimage",
            "linux-arm64-appimage",
        }
        defined = set(gate.TARGETS) | set(gate.STORE_MANIFEST_TARGETS)
        self.assertTrue(invented.isdisjoint(defined))
        self.assertEqual(
            tuple(gate.REQUIRED_LINUX_UPLOAD_TARGETS),
            (
                "linux-x64-package",
                "linux-arm64-package",
                "linux-flathub-manifest",
                "linux-snap-manifest",
            ),
        )
        self.assertEqual(
            set(gate.LINUX_PACKAGE_UPLOAD_TARGETS),
            set(gate.REQUIRED_LINUX_UPLOAD_TARGETS),
        )
        self.assertEqual(gate.LINUX_PACKAGE_UPLOAD_TARGETS["linux-x64-package"]["kind"], "DEB")
        self.assertEqual(gate.LINUX_PACKAGE_UPLOAD_TARGETS["linux-arm64-package"]["kind"], "DEB")
        self.assertEqual(
            gate.LINUX_PACKAGE_UPLOAD_TARGETS["linux-flathub-manifest"]["kind"], "Flatpak"
        )
        self.assertEqual(gate.LINUX_PACKAGE_UPLOAD_TARGETS["linux-snap-manifest"]["kind"], "Snap")
        self.assertFalse(gate.LINUX_APPIMAGE_UPLOAD_TARGET)
        self.assertEqual(gate.LINUX_APPIMAGE_FILENAME, "wins-vpn-1.0.17-x86_64.AppImage")
        self.assertEqual(gate.LINUX_DEB_FILENAME, "wins-vpn_1.0.17-34_amd64.deb")
        self.assertEqual(gate.CANONICAL_DEBIAN_VERSION, "1.0.17-34")
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "unsupported exact Linux package target"
        ):
            gate.verify_package("linux-x64-deb", "linux/packaging/install.sh")
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "unsupported exact Linux package/upload target"
        ):
            gate.bind_package_upload_receipt(
                "linux-x64-appimage",
                {},
                artifact_sha256="0" * 64,
                artifact_bytes=1,
            )
        appimage = self.downloads / gate.LINUX_APPIMAGE_FILENAME
        appimage.write_bytes(b"not-a-linux-upload-target\n")
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "AppImage is not a 1.0.17\\+33"
        ):
            gate.verify_package(
                "linux-x64-package",
                appimage.relative_to(self.repo).as_posix(),
            )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "unsupported exact Linux store manifest target"
        ):
            gate.verify_store_packages("linux-x64-flathub", "linux/packaging/install.sh")
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "unsupported exact Linux package/upload target"
        ):
            gate.bind_package_upload_receipt(
                "linux-x64-deb",
                {},
                artifact_sha256="0" * 64,
                artifact_bytes=1,
            )
        wrong_name = self.downloads / "wins-vpn-linux-arm64.tar.gz"
        wrong_name.write_bytes(b"wrong-exact-target-payload\n")
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "another exact target"
        ):
            gate.verify_package(
                "linux-x64-package",
                wrong_name.relative_to(self.repo).as_posix(),
            )

        x64 = self._write_archive("x64", 62)
        with self._verify("linux-x64-package", x64) as x64_result:
            x64_payload = x64_result.publication_payload()
        self.assertEqual(x64_payload["elf_machine"], 62)
        self.assertEqual(x64_payload["appstream_version"], "1.0.17")
        self.assertEqual(x64_payload["debian_version"], "1.0.17-34")
        x64.unlink()
        x64.with_name(x64.name + ".sha256").unlink()
        arm64 = self._write_archive("arm64", 183)
        with self._verify("linux-arm64-package", arm64) as arm64_result:
            arm64_payload = arm64_result.publication_payload()
        self.assertEqual(arm64_payload["elf_machine"], 183)
        self.assertNotEqual(
            x64_payload["flutter_identities"]["lib/libapp.so"]["sha256"],
            arm64_payload["flutter_identities"]["lib/libapp.so"]["sha256"],
        )

        migrated = (
            "test_stale_appstream_version_fails_closed",
            "test_schema_v2_receipt_identity_fails_closed_on_v1",
            "test_stale_debian_identity_mapping_fails_closed",
            "test_wrong_target_architecture_and_filename_fail_closed",
            "test_manifest_tamper_and_checksum_tamper_fail_closed",
            "test_native_host_and_both_browser_registration_assets_are_mandatory",
            "test_native_host_wrong_architecture_placeholder_and_provenance_tamper_fail_closed",
            "test_native_host_unstripped_or_nonexecutable_delivery_fails_closed",
            "test_sixty_four_byte_elf_header_is_rejected",
            "test_archive_size_ceiling_fails_before_decompression",
            "test_tar_traversal_and_special_members_fail_closed",
            "test_artifact_symlink_and_path_escape_fail_closed",
            "test_hard_linked_artifact_fails_closed",
            "test_missing_owner_identity_is_owner_blocked_even_with_packaged_ids",
            "test_chrome_only_store_ids_and_missing_edge_manifest_fail_closed",
            "test_arbitrary_valid_shape_ids_are_refused_when_they_are_not_owner_issued",
            "test_duplicate_store_id_json_keys_are_refused",
        )
        for method_name in migrated:
            with self.subTest(migrated_adapter=method_name):
                case = LinuxCrossStoreArtifactGateTests("runTest")
                case.setUp()
                try:
                    getattr(adapter_tests.LinuxPackageAdapterTests, method_name)(case)
                finally:
                    case.tearDown()

    def test_extra_elf_payload_fails_closed(self) -> None:
        artifact = self._write_archive(
            payload_overrides={
                "bin/extra-helper": real_executable_elf(62, marker=b"extra-helper")
            }
        )
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "extra ELF payloads"):
            self._verify("linux-x64-package", artifact)

    def test_test_only_cannot_emit_production_pass(self) -> None:
        artifact = self._write_archive()
        with mock.patch.object(gate, "TEST_ONLY", True):
            with self.assertRaisesRegex(gate.LinuxArtifactGateError, "TEST_ONLY"):
                self._verify("linux-x64-package", artifact)

    def test_missing_owner_signature_stays_pending(self) -> None:
        artifact = self._write_archive()
        snapshot = gate._snapshot_artifact(artifact.resolve(), "Linux package artifact")
        try:
            with self.assertRaisesRegex(
                gate.LinuxArtifactGateError,
                r"owner/environment blocker:.*OWNER-BLOCKED: ABSENT",
            ):
                gate._verify_signature(snapshot)
        finally:
            snapshot.close()
            shutil.rmtree(snapshot.root, ignore_errors=True)

    def test_mocked_signature_cannot_skip_owner_cosign_pin(self) -> None:
        artifact = self._write_archive()
        # The committed ceremony key is pinned (aca7fea); an unset pin must still
        # block even when signature verification itself is mocked.
        with (
            mock.patch.object(
                gate, "OWNER_COSIGN_TRUST_ANCHOR_SHA256", gate.OWNER_BLOCKED
            ),
            mock.patch.object(
                gate, "_verify_signature", side_effect=self._signature_custody
            ),
            mock.patch.object(
                gate, "_verify_build_provenance", side_effect=self._build_custody
            ),
            mock.patch.object(
                gate,
                "_bind_native_host_source_freeze_custody",
                side_effect=self._source_freeze_custody,
            ),
            mock.patch.object(
                gate, "_owner_issued_chromium_ids", return_value={"chrome": CHROME_ID, "edge": EDGE_ID}
            ),
            self.assertRaisesRegex(
                gate.LinuxArtifactGateError,
                r"owner/environment blocker:.*OWNER-BLOCKED: ABSENT",
            ),
        ):
            gate.verify_package(
                "linux-x64-package", artifact.relative_to(self.repo).as_posix()
            )

    def test_post_return_checksum_replacement_fails_final_consumption(self) -> None:
        artifact = self._write_archive()
        result = self._verify("linux-x64-package", artifact)
        checksum = artifact.with_name(artifact.name + ".sha256")
        reviewed = checksum.with_name(checksum.name + ".reviewed")
        checksum.rename(reviewed)
        checksum.write_bytes(reviewed.read_bytes())
        try:
            with self.assertRaisesRegex(
                gate.LinuxArtifactGateError,
                r"checksum|source identity changed|origin was swapped|replaced",
            ):
                result.publication_payload()
        finally:
            with contextlib.suppress(gate.LinuxArtifactGateError):
                result.close()
        self.assertTrue(result.closed)

    def test_post_return_sigstore_bundle_replacement_fails_final_consumption(self) -> None:
        artifact = self._write_archive()
        result = self._verify("linux-x64-package", artifact)
        reviewed = self.bundle.with_name(self.bundle.name + ".reviewed")
        self.bundle.rename(reviewed)
        self.bundle.write_bytes(reviewed.read_bytes())
        try:
            with self.assertRaisesRegex(
                gate.LinuxArtifactGateError,
                r"Sigstore|source identity changed|origin was swapped|replaced",
            ):
                result.publication_payload()
        finally:
            with contextlib.suppress(gate.LinuxArtifactGateError):
                result.close()
        self.assertTrue(result.closed)

    def test_consumer_exception_closes_all_retained_evidence(self) -> None:
        artifact = self._write_archive()
        result = self._verify("linux-x64-package", artifact)
        retained_origins = {snapshot.origin.resolve() for snapshot in result._snapshots}
        self.assertIn(self.source_freeze_receipt.resolve(), retained_origins)
        self.assertIn(self.receipt.resolve(), retained_origins)
        for snapshot in result._snapshots:
            self.assertIsNotNone(snapshot.origin_ancestor_chain)
            self.assertIsNotNone(snapshot.snapshot_ancestor_chain)
            snapshot.origin_ancestor_chain.revalidate()
            snapshot.snapshot_ancestor_chain.revalidate()
        descriptors = [snapshot.fd for snapshot in result._snapshots]
        descriptors.extend(
            snapshot.origin_fd
            for snapshot in result._snapshots
            if snapshot.origin_fd is not None
        )
        with self.assertRaisesRegex(RuntimeError, "consumer failed"):
            with result:
                result.publication_payload()
                raise RuntimeError("consumer failed")
        self.assertTrue(result.closed)
        for descriptor in descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_successful_consumer_context_has_no_fd_leaks(self) -> None:
        before = set(os.listdir("/dev/fd"))
        artifact = self._write_archive()
        result = self._verify("linux-x64-package", artifact)
        with result:
            self.assertTrue(result.publication_payload()["ok"])
        self.assertTrue(result.closed)
        self.assertEqual(set(os.listdir("/dev/fd")), before)

    def test_result_rejects_copy_deepcopy_pickle_and_stale_fd_reuse(self) -> None:
        artifact = self._write_archive()
        result = self._verify("linux-x64-package", artifact)
        retained_fds = [snapshot.fd for snapshot in result._snapshots]
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "cannot be copied"):
            copy.copy(result)
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "deep-copied"):
            copy.deepcopy(result)
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "serialized"):
            pickle.dumps(result)
        result.close()
        replacements = [os.open(os.devnull, os.O_RDONLY) for _ in retained_fds]
        try:
            gc.collect()
            for descriptor in replacements:
                os.fstat(descriptor)
        finally:
            for descriptor in replacements:
                os.close(descriptor)

    def test_result_payload_is_deeply_frozen_and_publication_copy_is_detached(self) -> None:
        artifact = self._write_archive()
        result = self._verify("linux-x64-package", artifact)
        try:
            identities = result["flutter_identities"]
            self.assertIsInstance(identities, Mapping)
            with self.assertRaises(TypeError):
                identities["attacker"] = {"sha256": "0" * 64}
            first = next(iter(identities.values()))
            with self.assertRaises(TypeError):
                first["sha256"] = "0" * 64
            detached = result.publication_payload()
            detached["flutter_identities"]["attacker"] = {"sha256": "0" * 64}
            self.assertNotIn("attacker", result["flutter_identities"])
        finally:
            result.close()

        accessors = (
            ("getitem", lambda current, nested, key: current["ok"]),
            ("iter", lambda current, nested, key: next(iter(current))),
            ("len", lambda current, nested, key: len(current)),
            ("dict", lambda current, nested, key: dict(current)),
            ("nested-getitem", lambda current, nested, key: nested[key]),
            ("nested-iter", lambda current, nested, key: next(iter(nested))),
            ("nested-len", lambda current, nested, key: len(nested)),
            ("nested-dict", lambda current, nested, key: dict(nested)),
        )
        for evidence in (self.source_freeze_receipt, self.receipt):
            artifact = self._write_archive()
            result = self._verify("linux-x64-package", artifact)
            nested = result["flutter_identities"]
            nested_key = next(iter(nested))
            original = evidence.read_bytes()
            evidence.write_bytes(original + b" ")
            try:
                for name, accessor in accessors:
                    with self.subTest(evidence=evidence.name, accessor=name), self.assertRaises(
                        gate.LinuxArtifactGateError
                    ):
                        accessor(result, nested, nested_key)
            finally:
                with contextlib.suppress(gate.LinuxArtifactGateError):
                    result.close()
                evidence.write_bytes(original)

    def test_snapshot_custody_cannot_be_reused_across_results(self) -> None:
        artifact = self._write_archive()
        result = self._verify("linux-x64-package", artifact)
        try:
            with self.assertRaisesRegex(
                gate.LinuxArtifactGateError, "already belongs to another result"
            ):
                gate.VerificationResult({"ok": True}, tuple(result._snapshots))
            self.assertTrue(result.publication_payload()["ok"])
        finally:
            result.close()

    def test_valid_origin_runtime_module_mutation_fails_before_behavior(self) -> None:
        cases = (
            (gate.os, "open"),
            (gate.fcntl, "fcntl"),
            (gate.stat, "S_ISREG"),
            (gate.REVIEWED_ZIPFILE, "ZipFile"),
            (gate.subprocess, "run"),
            (gate.privacy, "check_blob"),
            (gate.privacy, "_tar_open_mode"),
            (gate.privacy, "PrivacyError"),
            (gate.linux_release_signing, "open_authenticated_cosign"),
            (gate.linux_release_signing, "SigningError"),
            (gate.source_freeze, "verified_release_source_state"),
            (gate.source_freeze, "SourceFreezeError"),
            (gate.freeze, "verify_build_receipt"),
            (gate.freeze, "DependencyFreezeError"),
            (gate.obfuscation, "ObfuscationError"),
        )
        for module, attribute in cases:
            executed = False

            def hostile(*args, **kwargs):
                nonlocal executed
                executed = True
                raise AssertionError("poisoned runtime behavior executed")

            with self.subTest(module=getattr(module, "__name__", "privacy"), attribute=attribute):
                with mock.patch.object(module, attribute, hostile), self.assertRaisesRegex(
                    gate.LinuxArtifactGateError, r"runtime module .* poisoned"
                ):
                    gate._verify_all_module_custody()
                self.assertFalse(executed)

        for attribute in (
            "linux_release_signing", "source_freeze", "freeze", "obfuscation", "privacy"
        ):
            with self.subTest(global_edge=attribute), mock.patch.object(
                gate, attribute, types.SimpleNamespace()
            ), self.assertRaisesRegex(
                gate.LinuxArtifactGateError, r"support edge .* poisoned"
            ):
                gate._verify_all_module_custody()

        with mock.patch.dict(
            gate.freeze.PLATFORM_ALLOWED_TARGETS,
            {"linux": ("poisoned-target",)},
            clear=True,
        ), self.assertRaisesRegex(
            gate.LinuxArtifactGateError, r"constant was poisoned"
        ):
            gate._verify_all_module_custody()

    def test_valid_origin_sys_modules_substitute_is_rejected(self) -> None:
        authentic = gate.REVIEWED_ZIPFILE
        fake = types.ModuleType("zipfile")
        fake.__file__ = authentic.__file__
        fake.__spec__ = authentic.__spec__
        for name in ("ZipFile", "ZipInfo", "is_zipfile"):
            setattr(fake, name, getattr(authentic, name))
        with mock.patch.dict(sys.modules, {"zipfile": fake}), self.assertRaisesRegex(
            gate.LinuxArtifactGateError, r"zipfile identity is poisoned"
        ):
            gate._verify_all_module_custody()

    def test_artifact_checksum_and_bundle_snapshots_reject_o_rdwr(self) -> None:
        roles = (
            ("artifact", 0),
            ("source-freeze", 1),
            ("checksum", 2),
            ("bundle", 3),
            ("build-receipt", 4),
        )
        for role, index in roles:
            with self.subTest(role=role):
                artifact = self._write_archive()
                result = self._verify("linux-x64-package", artifact)
                snapshot = result._snapshots[index]
                os.close(snapshot.fd)
                os.chmod(snapshot.path, 0o600)
                snapshot.fd = os.open(
                    snapshot.path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
                )
                try:
                    with self.assertRaisesRegex(
                        gate.LinuxArtifactGateError, r"O_RDONLY"
                    ):
                        result.publication_payload()
                finally:
                    with contextlib.suppress(gate.LinuxArtifactGateError):
                        result.close()
                self.assertTrue(result.closed)

    def test_missing_produced_package_stays_owner_blocked(self) -> None:
        missing = ".artifacts/linux/wins-vpn-linux-x64.tar.gz"
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"owner/build-system blocker:.*OWNER-BLOCKED: ABSENT",
        ):
            gate.verify_package("linux-x64-package", missing)

    def test_owner_cosign_pin_is_the_committed_ceremony_key(self) -> None:
        committed = hashlib.sha256(
            (ROOT / gate.TRUSTED_LOCAL_COSIGN_KEY).read_bytes()
        ).hexdigest()
        self.assertEqual(gate.OWNER_COSIGN_TRUST_ANCHOR_SHA256, committed)
        self.assertEqual(gate.OWNER_UPLOAD_RECEIPT_TRUST_SHA256, committed)
        self.assertFalse(gate.owner_cosign_trust_anchor_blocked())
        self.assertFalse(gate.owner_upload_receipt_trust_blocked())
        gate._require_owner_cosign_trust_anchor()
        self.assertTrue(gate.owner_store_tool_pin_blocked("Flatpak"))
        self.assertTrue(gate.owner_store_tool_pin_blocked("Snap"))
        with mock.patch.object(
            gate, "OWNER_COSIGN_TRUST_ANCHOR_SHA256", gate.OWNER_BLOCKED
        ):
            self.assertTrue(gate.owner_cosign_trust_anchor_blocked())
            with self.assertRaisesRegex(
                gate.LinuxArtifactGateError,
                r"owner/environment blocker:.*OWNER-BLOCKED: ABSENT",
            ):
                gate._require_owner_cosign_trust_anchor()

    def test_packaged_home_path_fails_privacy_closure(self) -> None:
        artifact = self._write_archive(
            payload_overrides={
                "share/doc/wins-vpn/RECOVERY.md": b"/Users/attacker/secret/key\n"
            }
        )
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "privacy scan"):
            self._verify("linux-x64-package", artifact)

    def test_linux_upload_receipts_pending_and_signature_retries_do_not_leak(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            "pending without owner evidence",
        ):
            gate.bind_linux_package_upload_receipts({}, {})

        artifact = self._write_archive()
        receipts = {
            "linux-x64-package": {
                "artifact": {
                    "path": artifact.relative_to(self.repo).as_posix(),
                }
            }
        }
        private_pattern = ".artifacts/winsvpn-linux-gate-art-*"

        def leak_counters() -> tuple[frozenset[str], frozenset[pathlib.Path]]:
            return (
                frozenset(os.listdir("/dev/fd")),
                frozenset(self.repo.glob(private_pattern)),
            )

        returned: list[tuple[int, int | None, pathlib.Path]] = []

        def signature_custody(
            _snapshot: gate.AuthenticatedSnapshot,
        ) -> gate.AuthenticatedSnapshot:
            custody = self._signature_custody(_snapshot)
            returned.append((custody.fd, custody.origin_fd, custody.root))
            return custody

        def assert_returned_custody_closed() -> None:
            while returned:
                leaf_fd, origin_fd, private_root = returned.pop(0)
                for descriptor in (leaf_fd, origin_fd):
                    if descriptor is not None:
                        with self.assertRaises(OSError):
                            os.fstat(descriptor)
                self.assertFalse(private_root.exists())

        baseline = leak_counters()
        for retry in range(3):
            with self.subTest(path="success", retry=retry), mock.patch.object(
                gate, "_verify_signature", side_effect=signature_custody
            ):
                gate._require_required_upload_signatures(receipts)
            assert_returned_custody_closed()
            self.assertEqual(leak_counters(), baseline)

        with self.subTest(path="verifier-exception"), mock.patch.object(
            gate,
            "_verify_signature",
            side_effect=RuntimeError("hostile signature verifier"),
        ), self.assertRaisesRegex(RuntimeError, "hostile signature verifier"):
            gate._require_required_upload_signatures(receipts)
        self.assertEqual(leak_counters(), baseline)

        original_bundle = self.bundle.read_bytes()

        def mutated_return(
            snapshot: gate.AuthenticatedSnapshot,
        ) -> gate.AuthenticatedSnapshot:
            custody = signature_custody(snapshot)
            self.bundle.write_bytes(original_bundle + b" ")
            return custody

        try:
            with self.subTest(path="hostile-return"), mock.patch.object(
                gate, "_verify_signature", side_effect=mutated_return
            ), self.assertRaises(gate.LinuxArtifactGateError):
                gate._require_required_upload_signatures(receipts)
            assert_returned_custody_closed()
        finally:
            self.bundle.write_bytes(original_bundle)
        self.assertEqual(leak_counters(), baseline)

        with self.subTest(path="retry-after-hostile-return"), mock.patch.object(
            gate, "_verify_signature", side_effect=signature_custody
        ):
            gate._require_required_upload_signatures(receipts)
        assert_returned_custody_closed()
        self.assertEqual(leak_counters(), baseline)

    def test_canonical_module_alias_prevents_imported_call_bypass(self) -> None:
        import linux_cross_store_artifact_gate as imported

        self.assertIs(imported, gate)
        before = set(ROOT.glob("tools/.render_host_manifest.winsvpn-mod-*.py"))
        renderer = gate._native_host_renderer()
        origin = pathlib.Path(renderer.__file__)
        self.assertEqual(
            origin.resolve(),
            (ROOT / "tools/native_messaging/render_host_manifest.py").resolve(),
        )
        self.assertEqual(
            hashlib.sha256(
                (ROOT / "tools/native_messaging/render_host_manifest.py").read_bytes()
            ).hexdigest(),
            next(
                source.digest
                for source in gate._NATIVE_HOST_MODULE_CUSTODY
                if source.public_name == "render_host_manifest"
            ),
        )
        self.assertEqual(
            before,
            set(ROOT.glob("tools/.render_host_manifest.winsvpn-mod-*.py")),
        )
        gate._verify_module_custody(gate._NATIVE_HOST_MODULE_CUSTODY)

    def test_winn3_descriptor_ring_attestation_is_required_and_pin_bound(self) -> None:
        from tools.winn3_descriptor_ring_defines import (
            CEREMONY_MANIFEST_SHA256,
            REVIEWED_RING_SHA256,
        )

        self.assertEqual(gate.REVIEWED_WINN3_DESCRIPTOR_RING_SHA256, REVIEWED_RING_SHA256)
        self.assertNotEqual(
            gate.REVIEWED_WINN3_DESCRIPTOR_RING_SHA256, CEREMONY_MANIFEST_SHA256
        )
        self.assertIn(gate.WINN3_DESCRIPTOR_RING_ATTESTATION_NAME, gate.REQUIRED_FILES)
        self.assertEqual(
            gate.STORE_WINN3_DESCRIPTOR_RING_ATTESTATION_RELATIVE,
            "share/winsvpn/" + gate.WINN3_DESCRIPTOR_RING_ATTESTATION_NAME,
        )
        for spec in gate.STORE_MANIFEST_TARGETS.values():
            self.assertIn(
                gate.WINN3_DESCRIPTOR_RING_ATTESTATION_NAME, spec["recipe_markers"]
            )
        artifact = self._write_archive()
        result = self._verify("linux-x64-package", artifact)
        self.assertTrue(result["ok"])
        self.assertIn("lib/libapp.so", result["flutter_identities"])

    def test_missing_winn3_descriptor_ring_attestation_fails_closed(self) -> None:
        artifact = self._write_archive(omit={gate.WINN3_DESCRIPTOR_RING_ATTESTATION_NAME})
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"incomplete: winn3-descriptor-ring-attestation\.json",
        ):
            self._verify("linux-x64-package", artifact)

    def test_extra_winn3_descriptor_ring_attestation_fails_closed(self) -> None:
        extra = winn3_attestation_document()
        artifact = self._write_archive(
            payload_overrides={
                "share/winsvpn/" + gate.WINN3_DESCRIPTOR_RING_ATTESTATION_NAME: extra
            }
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"extra Winn3 descriptor ring attestation",
        ):
            self._verify("linux-x64-package", artifact)

    def test_stale_winn3_descriptor_ring_attestation_fails_closed(self) -> None:
        from tools.winn3_descriptor_ring_defines import CEREMONY_MANIFEST_SHA256

        artifact = self._write_archive(
            payload_overrides={
                gate.WINN3_DESCRIPTOR_RING_ATTESTATION_NAME: winn3_attestation_document(
                    CEREMONY_MANIFEST_SHA256
                )
            }
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"stale or unbound",
        ):
            self._verify("linux-x64-package", artifact)

    def test_winn3_descriptor_ring_attestation_hash_and_mode_binding_fail_closed(
        self,
    ) -> None:
        artifact = self._write_archive(
            payload_overrides={
                "lib/libapp.so": real_executable_elf(62, marker=b"libapp"),
            }
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"does not bind the verified artifact hash",
        ):
            self._verify("linux-x64-package", artifact)
        artifact.unlink()
        artifact.with_name(artifact.name + ".sha256").unlink()
        artifact = self._write_archive(
            mode_overrides={gate.WINN3_DESCRIPTOR_RING_ATTESTATION_NAME: 0o755}
        )
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, r"unsafe mode"):
            self._verify("linux-x64-package", artifact)

    def test_winn3_descriptor_ring_attestation_must_be_exact_regular_json(self) -> None:
        malformed_json = (
            b'{"outer":{"key":1,"key":2}}',
            b'{"outer":NaN}',
            b'{"outer":Infinity}',
            b'{"outer":-Infinity}',
        )
        for payload in malformed_json:
            with self.subTest(payload=payload), self.assertRaises(
                gate.LinuxArtifactGateError
            ):
                gate._exact_json(payload, "strict JSON fixture")
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value), self.assertRaises(
                gate.LinuxArtifactGateError
            ):
                gate._receipt_document(
                    {"authentication": {"score": value}},
                    "strict mapping fixture",
                )

        artifact = self._write_archive(
            payload_overrides={
                gate.WINN3_DESCRIPTOR_RING_ATTESTATION_NAME: real_executable_elf(
                    62, marker=b"attest"
                )
            }
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"extra ELF payloads: winn3-descriptor-ring-attestation\.json",
        ):
            self._verify("linux-x64-package", artifact)
        artifact.unlink()
        artifact.with_name(artifact.name + ".sha256").unlink()
        extra_keys = json.loads(winn3_attestation_document().decode("ascii"))
        extra_keys["extra"] = "field"
        artifact = self._write_archive(
            payload_overrides={
                gate.WINN3_DESCRIPTOR_RING_ATTESTATION_NAME: (
                    json.dumps(extra_keys, sort_keys=True) + "\n"
                ).encode("ascii")
            }
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"fields are incomplete or unexpected",
        ):
            self._verify("linux-x64-package", artifact)
        artifact.unlink()
        artifact.with_name(artifact.name + ".sha256").unlink()
        pretty = json.dumps(
            json.loads(winn3_attestation_document().decode("ascii")),
            indent=2,
            sort_keys=True,
        ).encode("ascii") + b"\n"
        artifact = self._write_archive(
            payload_overrides={gate.WINN3_DESCRIPTOR_RING_ATTESTATION_NAME: pretty}
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"exact canonical document",
        ):
            self._verify("linux-x64-package", artifact)

    def test_attested_libapp_wrong_architecture_fails_closed(self) -> None:
        artifact = self._write_archive(
            payload_overrides={
                "lib/libapp.so": ring_bound_elf(183, marker=b"libapp"),
            }
        )
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, r"ELF machine"):
            self._verify("linux-x64-package", artifact)

    def test_held_fd_x64_and_arm64_artifacts_bind_exact_release(self) -> None:
        x64 = self._write_held_archive("x64", 62)
        x64_result = self._held_verify("linux-x64-package", x64)
        with x64_result:
            self.assertEqual(x64_result["contract"], gate.HELD_ARTIFACT_CONTRACT)
            self.assertEqual(x64_result["release"], gate.CANONICAL_RELEASE)
            self.assertEqual(x64_result["elf_machine"], 62)
            self.assertEqual(
                x64_result["runtime_protocol_order"], ("winn-v3", "winn-v1")
            )
            self.assertEqual(
                x64_result["winn_v1_engines"],
                ("awg", "awg-quick", "amneziawg-go", "xray"),
            )
            x64_digest = x64_result["artifact_sha256"]
        x64.unlink()
        x64.with_name(x64.name + ".sha256").unlink()
        arm64 = self._write_held_archive("arm64", 183)
        arm64_result = self._held_verify("linux-arm64-package", arm64)
        with arm64_result:
            self.assertEqual(arm64_result["elf_machine"], 183)
            self.assertNotEqual(x64_digest, arm64_result["artifact_sha256"])

    def test_held_fd_rejects_identity_size_digest_release_and_target_drift(self) -> None:
        artifact = self._write_held_archive()
        info = artifact.stat()
        identity = list(gate._file_identity(info))
        identity[1] += 1
        cases = (
            {"expected_identity": tuple(identity)},
            {"expected_size": info.st_size + 1},
            {"expected_sha256": "0" * 64},
            {"frozen_release": "1.0.14+29"},
        )
        for arguments in cases:
            with self.subTest(arguments=arguments), self.assertRaises(
                gate.LinuxArtifactGateError
            ):
                self._held_verify("linux-x64-package", artifact, **arguments)
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "unsupported exact held Linux package target"
        ):
            self._held_verify("linux-x64-deb", artifact)

    def test_held_fd_rejects_cross_architecture_candidate(self) -> None:
        artifact = self._write_held_archive("arm64", 62)
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "ELF machine"):
            self._held_verify("linux-arm64-package", artifact)

    def test_held_fd_requires_exact_runtime_protocol_order(self) -> None:
        missing = self._write_archive(
            payload_overrides=self._held_overrides(62)
            | {gate.RUNTIME_PROTOCOL_ORDER_PATH: b""}
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "runtime protocol order"
        ):
            self._held_verify("linux-x64-package", missing)
        missing.unlink()
        missing.with_name(missing.name + ".sha256").unlink()
        drift = json.loads(gate._canonical_runtime_protocol_order().decode("ascii"))
        drift["ordered_protocols"].reverse()
        artifact = self._write_held_archive(
            payload_overrides={
                gate.RUNTIME_PROTOCOL_ORDER_PATH: (
                    json.dumps(drift, sort_keys=True, separators=(",", ":")) + "\n"
                ).encode("ascii")
            }
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "runtime protocol order"
        ):
            self._held_verify("linux-x64-package", artifact)

    def test_held_fd_rejects_header_only_and_nonloadable_elf(self) -> None:
        header_only = bytearray(64)
        header_only[:6] = b"\x7fELF\x02\x01"
        header_only[16:18] = gate.ET_DYN.to_bytes(2, "little")
        header_only[18:20] = (62).to_bytes(2, "little")
        artifact = self._write_held_archive(
            payload_overrides={"lib/libapp.so": bytes(header_only)}
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "truncated 64-byte ELF header"
        ):
            self._held_verify("linux-x64-package", artifact)
        artifact.unlink()
        artifact.with_name(artifact.name + ".sha256").unlink()
        no_dynamic = loadable_elf64(62, shared=False, marker=b"libapp") + (
            gate.REVIEWED_WINN3_DESCRIPTOR_RING_SHA256.encode("ascii")
        )
        artifact = self._write_held_archive(
            payload_overrides={"lib/libapp.so": no_dynamic}
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "shared object lacks loadable ET_DYN/PT_DYNAMIC"
        ):
            self._held_verify("linux-x64-package", artifact)

    def test_held_fd_rejects_archive_links_and_traversal(self) -> None:
        linked = tarfile.TarInfo("./linked")
        linked.type = tarfile.SYMTYPE
        linked.linkname = "wins_vpn"
        artifact = self._write_held_archive(unsafe_member=linked)
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "unsafe|link"):
            self._held_verify("linux-x64-package", artifact)
        artifact.unlink()
        artifact.with_name(artifact.name + ".sha256").unlink()
        traversal = tarfile.TarInfo("../escape")
        traversal.type = tarfile.REGTYPE
        traversal.size = 1
        artifact = self._write_held_archive(unsafe_member=traversal)
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "unsafe|ambiguous"):
            self._held_verify("linux-x64-package", artifact)

    def test_held_fd_rejects_single_tar_end_block(self) -> None:
        artifact = self._write_held_archive()
        uncompressed = gzip.decompress(artifact.read_bytes())
        end = self._first_tar_end(uncompressed)
        self._replace_archive_stream(artifact, uncompressed[: end + 512])
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"two zero end blocks",
        ):
            self._held_verify("linux-x64-package", artifact)

    def test_held_fd_rejects_nonzero_hidden_tar_tail(self) -> None:
        artifact = self._write_held_archive()
        uncompressed = gzip.decompress(artifact.read_bytes())
        end = self._first_tar_end(uncompressed)
        hostile = uncompressed[: end + 1024] + (b"hidden-unmanifested" * 32)
        self._replace_archive_stream(artifact, hostile)
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"nonzero unmanifested trailing payload",
        ):
            self._held_verify("linux-x64-package", artifact)

    def test_held_fd_rejects_concatenated_tar_archive(self) -> None:
        artifact = self._write_held_archive()
        uncompressed = gzip.decompress(artifact.read_bytes())
        end = self._first_tar_end(uncompressed)
        hostile = uncompressed[: end + 1024] + uncompressed
        self._replace_archive_stream(artifact, hostile)
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"nonzero unmanifested trailing payload",
        ):
            self._held_verify("linux-x64-package", artifact)

    def test_held_fd_rejects_malformed_zero_padding(self) -> None:
        artifact = self._write_held_archive()
        uncompressed = gzip.decompress(artifact.read_bytes())
        end = self._first_tar_end(uncompressed)
        self._replace_archive_stream(
            artifact,
            uncompressed[: end + 1024] + b"\0",
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"malformed noncanonical zero padding",
        ):
            self._held_verify("linux-x64-package", artifact)

    def test_held_fd_rejects_concatenated_gzip_member(self) -> None:
        artifact = self._write_held_archive()
        first = artifact.read_bytes()
        second_buffer = io.BytesIO()
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=second_buffer, mtime=0
        ) as compressed:
            compressed.write(b"\0" * 1024)
        artifact.write_bytes(first + second_buffer.getvalue())
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        artifact.with_name(artifact.name + ".sha256").write_text(
            f"{digest}  {artifact.name}\n", encoding="ascii"
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"truncated or concatenated gzip stream|gzip CRC",
        ):
            self._held_verify("linux-x64-package", artifact)

    def test_held_fd_rejects_source_name_swap(self) -> None:
        artifact = self._write_held_archive()
        original = artifact.with_name(artifact.name + ".original")

        def swap(_snapshot: gate.HeldArtifactSnapshot) -> pathlib.Path:
            artifact.rename(original)
            artifact.write_bytes(b"substituted unsigned payload\n")
            return self.bundle

        try:
            with self.assertRaisesRegex(
                gate.LinuxArtifactGateError,
                "held Linux artifact|retained parent identity changed",
            ):
                self._held_verify(
                    "linux-x64-package", artifact, signature_side_effect=swap
                )
        finally:
            if artifact.exists():
                artifact.unlink()
            if original.exists():
                original.rename(artifact)

    def test_held_higher_ancestor_swap_never_redirects_artifact_consumption(self) -> None:
        artifact = self._write_held_archive()
        authentic = artifact.read_bytes()
        artifacts_root = self.repo / ".artifacts"
        retained_root = self.repo / ".artifacts-authentic"
        real_inspect = gate._inspect_archive
        observed: list[bytes] = []

        def swap_restore(snapshot, *args, **kwargs):
            artifacts_root.rename(retained_root)
            substitute = artifacts_root / "linux" / artifact.name
            substitute.parent.mkdir(parents=True)
            substitute.write_bytes(b"attacker-substitute")
            try:
                observed.append(os.pread(snapshot.fd, len(authentic), 0))
                self.assertEqual(substitute.read_bytes(), b"attacker-substitute")
            finally:
                shutil.rmtree(artifacts_root)
                retained_root.rename(artifacts_root)
            return real_inspect(snapshot, *args, **kwargs)

        with mock.patch.object(gate, "_inspect_archive", side_effect=swap_restore):
            result = self._held_verify("linux-x64-package", artifact)
        with result:
            self.assertTrue(result.publication_payload()["ok"])
        self.assertEqual(observed, [authentic])

    def test_native_store_tool_consumes_only_retained_snapshot_fd(self) -> None:
        artifact = self._write_archive()
        snapshot = gate._snapshot_artifact(artifact.resolve(), "store package")
        snapshot_fd = snapshot.fd
        tool_path = self.repo / ".artifacts/fake-unsquashfs"
        tool_path.write_bytes(b"#!/bin/sh\nexit 0\n")
        tool_path.chmod(0o500)
        tool_fd = os.open(tool_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        tool_info = os.fstat(tool_fd)
        tool = gate._AuthenticatedStoreTool(
            kind="Snap",
            path=tool_path,
            fd=tool_fd,
            identity=gate._file_identity(tool_info),
            digest=hashlib.sha256(tool_path.read_bytes()).hexdigest(),
            ancestors=gate._retain_complete_directory_chain(
                tool_path.parent, "test retained store tool"
            ),
        )
        calls: list[tuple[list[str], dict[str, object]]] = []

        def run(argv, **kwargs):
            calls.append((list(argv), dict(kwargs)))
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        extracted = gate._create_retained_extraction_directory(snapshot)
        extracted_fd = extracted.fd
        try:
            with (
                mock.patch.object(
                    gate.linux_release_signing,
                    "_proc_fd_path",
                    side_effect=lambda fd, _label: f"/proc/self/fd/{fd}",
                ),
                mock.patch.object(gate, "_run_bounded_subprocess", side_effect=run),
            ):
                gate._run_store_tool("Snap", tool, snapshot, extracted)
        finally:
            extracted.close()
            tool.close()
            snapshot.close()
            shutil.rmtree(snapshot.root, ignore_errors=True)
        argv, kwargs = calls[0]
        self.assertIn(f"/proc/self/fd/{snapshot_fd}", argv)
        self.assertIn(f"/proc/self/fd/{extracted_fd}", argv)
        self.assertEqual(argv[0], f"/proc/self/fd/{tool_fd}")
        self.assertNotIn(str(tool_path), argv)
        self.assertNotIn(str(snapshot.path), argv)
        self.assertEqual(kwargs["cwd"], f"/proc/self/fd/{extracted_fd}")
        self.assertEqual(kwargs["pass_fds"], (tool_fd, snapshot_fd, extracted_fd))

    def test_native_store_tool_parent_substitution_cannot_change_executed_bytes(self) -> None:
        artifact = self._write_archive()
        snapshot = gate._snapshot_artifact(artifact.resolve(), "store package")
        tool_parent = self.repo / ".artifacts/tool-parent"
        tool_parent.mkdir()
        tool_path = tool_parent / "unsquashfs"
        authentic = b"#!/bin/sh\nexit 0\n"
        tool_path.write_bytes(authentic)
        tool_path.chmod(0o500)
        tool_fd = os.open(tool_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        info = os.fstat(tool_fd)
        custody = gate._AuthenticatedStoreTool(
            kind="Snap",
            path=tool_path,
            fd=tool_fd,
            identity=gate._file_identity(info),
            digest=hashlib.sha256(authentic).hexdigest(),
            ancestors=gate._retain_complete_directory_chain(
                tool_parent, "hostile retained store tool"
            ),
        )
        moved = tool_parent.with_name("tool-parent-authentic")
        observed: list[bytes] = []

        def run(argv, **kwargs):
            tool_parent.rename(moved)
            tool_parent.mkdir()
            substitute = tool_parent / "unsquashfs"
            substitute.write_bytes(b"#!/bin/sh\necho attacker\n")
            substitute.chmod(0o500)
            try:
                self.assertEqual(argv[0], f"/proc/self/fd/{tool_fd}")
                observed.append(os.pread(tool_fd, len(authentic), 0))
            finally:
                shutil.rmtree(tool_parent)
                moved.rename(tool_parent)
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        extracted = gate._create_retained_extraction_directory(snapshot)
        try:
            with (
                mock.patch.object(
                    gate.linux_release_signing,
                    "_proc_fd_path",
                    side_effect=lambda fd, _label: f"/proc/self/fd/{fd}",
                ),
                mock.patch.object(gate, "_run_bounded_subprocess", side_effect=run),
            ):
                gate._run_store_tool("Snap", custody, snapshot, extracted)
            self.assertEqual(observed, [authentic])
        finally:
            extracted.close()
            custody.close()
            snapshot.close()
            shutil.rmtree(snapshot.root, ignore_errors=True)

    def test_bounded_subprocess_caps_both_streams_and_kills_descendants(self) -> None:
        marker = self.repo / ".artifacts/subprocess-descendant-marker"
        child = (
            "import pathlib,time;"
            "time.sleep(0.8);"
            f"pathlib.Path({str(marker)!r}).write_text('escaped',encoding='ascii')"
        )
        parent = (
            "import os,subprocess,sys,time;"
            f"subprocess.Popen([sys.executable,'-I','-S','-c',{child!r}]);"
            "os.write(1,b'x'*8192);"
            "os.write(2,b'y'*8192);"
            "time.sleep(5)"
        )
        with (
            mock.patch.object(gate, "MAX_SUBPROCESS_STREAM_BYTES", 1024),
            mock.patch.object(gate, "SUBPROCESS_DEADLINE_SECONDS", 2.0),
            mock.patch.object(gate, "SUBPROCESS_TERMINATE_SECONDS", 0.2),
            mock.patch.object(
                gate, "_open_process_containment", return_value=_NoopProcessContainment()
            ),
            self.assertRaisesRegex(
                gate.LinuxArtifactGateError, r"stdout|stderr.*byte ceiling"
            ),
        ):
            gate._run_bounded_subprocess(
                [sys.executable, "-I", "-S", "-c", parent],
                cwd=self.repo,
                pass_fds=(),
                label="hostile bounded subprocess",
            )
        time.sleep(1.0)
        self.assertFalse(marker.exists())

    def test_bounded_subprocess_drains_honest_stdout_and_stderr(self) -> None:
        with mock.patch.object(
            gate, "_open_process_containment", return_value=_NoopProcessContainment()
        ):
            completed = gate._run_bounded_subprocess(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-c",
                    "import os;os.write(1,b'honest-out');os.write(2,b'honest-error')",
                ],
                cwd=self.repo,
                pass_fds=(),
                label="honest bounded subprocess",
            )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "honest-out")
        self.assertEqual(completed.stderr, "honest-error")

    def test_bounded_subprocess_enforces_deadline_and_process_isolation(self) -> None:
        real_popen = subprocess.Popen
        calls: list[dict[str, object]] = []

        def popen(argv, **kwargs):
            calls.append(dict(kwargs))
            return real_popen(argv, **kwargs)

        with (
            mock.patch.object(gate.subprocess, "Popen", side_effect=popen),
            mock.patch.object(
                gate, "_open_process_containment", return_value=_NoopProcessContainment()
            ),
            mock.patch.object(gate, "SUBPROCESS_DEADLINE_SECONDS", 0.1),
            mock.patch.object(gate, "SUBPROCESS_TERMINATE_SECONDS", 0.2),
            self.assertRaisesRegex(gate.LinuxArtifactGateError, "deadline"),
        ):
            gate._run_bounded_subprocess(
                [sys.executable, "-I", "-S", "-c", "import time;time.sleep(5)"],
                cwd=self.repo,
                pass_fds=(),
                label="hostile deadline subprocess",
            )
        self.assertTrue(calls[0]["start_new_session"])
        self.assertTrue(calls[0]["close_fds"])
        self.assertFalse(calls[0]["shell"])
        self.assertIs(calls[0]["stdout"], subprocess.PIPE)
        self.assertIs(calls[0]["stderr"], subprocess.PIPE)
        self.assertTrue(callable(calls[0]["preexec_fn"]))

    def test_bounded_subprocess_kills_setsid_descendant_with_retained_fd(self) -> None:
        pid_file = self.repo / ".artifacts/setsid-descendant.pid"
        marker = self.repo / ".artifacts/setsid-descendant-marker"
        child = (
            "import os,pathlib,time;"
            "os.setsid();"
            f"pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid()),encoding='ascii');"
            "time.sleep(1.0);"
            f"pathlib.Path({str(marker)!r}).write_text('escaped',encoding='ascii')"
        )
        parent = (
            "import os,subprocess,sys,time;"
            f"subprocess.Popen([sys.executable,'-I','-S','-c',{child!r}],"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,"
            "close_fds=False);"
            f"p={str(pid_file)!r};"
            "[(time.sleep(0.01)) for _ in range(100) if not os.path.exists(p)]"
        )
        containment = _PidFileProcessContainment(pid_file)
        with (
            mock.patch.object(
                gate, "_open_process_containment", return_value=containment
            ),
            self.assertRaisesRegex(
                gate.LinuxArtifactGateError, "left a descendant process running"
            ),
        ):
            gate._run_bounded_subprocess(
                [sys.executable, "-I", "-S", "-c", parent],
                cwd=self.repo,
                pass_fds=(),
                label="hostile setsid subprocess",
            )
        time.sleep(1.1)
        self.assertFalse(marker.exists())

    def test_namespace_wrapper_roots_tool_below_user_pid_and_cgroup_namespaces(self) -> None:
        containment = object.__new__(gate._LinuxCgroupContainment)
        containment._procs_fd = 16
        containment._namespace_files = [
            (pathlib.Path("/usr/bin/unshare"), 17, (), "", None),
            (pathlib.Path("/bin/sh"), 18, (), "", None),
            (pathlib.Path("/usr/bin/mount"), 20, (), "", None),
        ]
        self.assertEqual(containment.pass_fds, (16, 17, 18, 20))
        wrapped = containment.wrap_argv(["/proc/self/fd/41", "--inspect"], 19)
        self.assertEqual(wrapped[0], "/proc/self/fd/17")
        for required in (
            "--user",
            "--map-root-user",
            "--setgroups=deny",
            "--mount",
            "--propagation=private",
            "--pid",
            "--cgroup",
            "--fork",
            "--kill-child=KILL",
            "--mount-proc=/proc",
        ):
            self.assertIn(required, wrapped)
        separator = wrapped.index("--")
        self.assertEqual(wrapped[separator + 1], "/proc/self/fd/18")
        bootstrap = wrapped[separator + 3]
        self.assertIn(
            "/proc/self/fd/20 -t cgroup2 -o nosuid,nodev,noexec cgroup2 /sys/fs/cgroup",
            bootstrap,
        )
        self.assertIn("[ \"$winsvpn_cgroup_count\" -eq 1 ]", bootstrap)
        self.assertIn("[ \"$winsvpn_cgroup\" = '0::/' ]", bootstrap)
        self.assertIn(">&19", bootstrap)
        self.assertIn("exec 19>&-", bootstrap)
        self.assertIn("exec 17>&-", bootstrap)
        self.assertIn("exec 18>&-", bootstrap)
        self.assertIn("exec 20>&-", bootstrap)
        self.assertTrue(bootstrap.rstrip().endswith('exec "$@"'))
        self.assertEqual(wrapped[-2:], ["/proc/self/fd/41", "--inspect"])
        self.assertNotIn(str(gate.PROCESS_CGROUP_ROOT), wrapped)

    def test_preexec_subprocess_error_is_normalized_fail_closed(self) -> None:
        with (
            mock.patch.object(
                gate, "_open_process_containment", return_value=_NoopProcessContainment()
            ),
            mock.patch.object(
                gate.subprocess,
                "Popen",
                side_effect=subprocess.SubprocessError("Exception occurred in preexec_fn."),
            ),
            self.assertRaisesRegex(
                gate.LinuxArtifactGateError, "pre-exec containment failed closed"
            ),
        ):
            gate._run_bounded_subprocess(
                [sys.executable, "-I", "-S", "-c", "pass"],
                cwd=self.repo,
                pass_fds=(),
                label="hostile preexec subprocess",
            )

    @unittest.skipUnless(
        sys.platform == "linux"
        and gate.PROCESS_CGROUP_ROOT.is_dir()
        and gate.PROCESS_NAMESPACE_UNSHARE.is_file(),
        "production cgroup-v2 namespace boundary is unavailable",
    )
    def test_real_namespace_blocks_setsid_parent_cgroup_escape_with_retained_fd(self) -> None:
        marker = self.repo / ".artifacts/real-cgroup-namespace-result"
        marker_fd = os.open(
            marker,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        child = (
            "import os;"
            "os.setsid();"
            "[os.close(fd) for fd in (0,1,2)];"
            "result=b'blocked';"
            "\ntry:\n"
            f" fd=os.open({str(gate.PROCESS_CGROUP_ROOT / 'cgroup.procs')!r},os.O_WRONLY);"
            " os.write(fd,b'0\\n');os.close(fd);result=b'escaped'\n"
            "except OSError:\n pass\n"
            f"os.write({marker_fd},result)"
        )
        try:
            completed = gate._run_bounded_subprocess(
                [sys.executable, "-I", "-S", "-c", child],
                cwd=self.repo,
                pass_fds=(marker_fd,),
                label="real hostile cgroup namespace subprocess",
            )
            self.assertEqual(completed.returncode, 0)
        finally:
            os.close(marker_fd)
        self.assertEqual(marker.read_bytes(), b"blocked")

    def test_directory_child_open_tolerates_unrelated_sibling_churn(self) -> None:
        parent = self.repo / ".artifacts/directory-custody"
        child = parent / "child"
        child.mkdir(parents=True)
        parent_fd = os.open(parent, gate._dir_open_flags())
        original_open = gate.os.open
        churned = False

        def open_with_churn(path, flags, *args, **kwargs):
            nonlocal churned
            if path == "child" and not churned:
                churned = True
                child_fd = original_open("child", gate._dir_open_flags(), dir_fd=parent_fd)
                try:
                    sibling_fd = original_open(
                        "unrelated",
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                        0o600,
                        dir_fd=child_fd,
                    )
                    os.close(sibling_fd)
                finally:
                    os.close(child_fd)
            return original_open(path, flags, *args, **kwargs)

        opened = -1
        try:
            with mock.patch.object(gate.os, "open", side_effect=open_with_churn):
                opened = gate._openat_child(
                    parent_fd,
                    "child",
                    gate._dir_open_flags(),
                    label="sibling-churn fixture",
                )
            self.assertTrue(churned)
            self.assertTrue(stat.S_ISDIR(os.fstat(opened).st_mode))
        finally:
            if opened >= 0:
                os.close(opened)
            os.close(parent_fd)

    def test_held_fd_rejects_o_rdwr_source_descriptor(self) -> None:
        artifact = self._write_held_archive()
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, r"O_RDONLY"
        ):
            self._held_verify(
                "linux-x64-package",
                artifact,
                writable=True,
            )

    def test_held_fd_revalidates_mutation_on_success(self) -> None:
        artifact = self._write_held_archive()

        def mutate(snapshot: gate.HeldArtifactSnapshot) -> pathlib.Path:
            attacker_fd = os.open(
                artifact, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
            )
            try:
                os.pwrite(attacker_fd, b"X", 0)
            finally:
                os.close(attacker_fd)
            return self.bundle

        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "identity changed|digest changed"
        ):
            self._held_verify(
                "linux-x64-package",
                artifact,
                signature_side_effect=mutate,
            )

    def test_held_fd_revalidates_custody_on_timeout_and_exception(self) -> None:
        for failure in (
            subprocess.TimeoutExpired(["cosign"], 90),
            RuntimeError("runner-exception"),
            gate.LinuxArtifactGateError("signature-failed"),
        ):
            artifact = self._write_held_archive()

            def mutate_then_fail(
                snapshot: gate.HeldArtifactSnapshot,
                failure: BaseException = failure,
            ) -> pathlib.Path:
                attacker_fd = os.open(
                    artifact, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
                )
                try:
                    os.pwrite(attacker_fd, b"Y", 1)
                finally:
                    os.close(attacker_fd)
                raise failure

            with self.subTest(failure=type(failure).__name__), self.assertRaisesRegex(
                gate.LinuxArtifactGateError, "identity changed|digest changed"
            ):
                self._held_verify(
                    "linux-x64-package",
                    artifact,
                    signature_side_effect=mutate_then_fail,
                )
            artifact.unlink()
            artifact.with_name(artifact.name + ".sha256").unlink()

    def test_held_fd_unsigned_payload_remains_owner_blocked(self) -> None:
        artifact = self._write_held_archive()
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"owner/environment blocker:.*OWNER-BLOCKED: ABSENT",
        ):
            self._held_verify(
                "linux-x64-package",
                artifact,
                patch_signature=False,
                bind_owner_pin=False,
            )


if __name__ == "__main__":
    unittest.main()
