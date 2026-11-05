#!/usr/bin/env python3
"""Hostile build-boundary tests for build_gcp_proof_client.py."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import pathlib
import py_compile
import stat
import struct
import sys
import tempfile
import types
import unittest
from collections.abc import Callable, Mapping, Sequence
from unittest import mock


SCRIPT = pathlib.Path(__file__).with_name("build_gcp_proof_client.py").resolve()
WORKSPACE = SCRIPT.parent.parent
SPEC = importlib.util.spec_from_file_location("build_gcp_proof_client", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


DARWIN_ARM64 = {"cgo_enabled": False, "goarch": "arm64", "goos": "darwin"}
LINUX_AMD64 = {"cgo_enabled": False, "goarch": "amd64", "goos": "linux"}


def _host_darwin_arm64() -> object:
    return mock.patch.multiple(
        MODULE.platform,
        system=mock.Mock(return_value="Darwin"),
        machine=mock.Mock(return_value="arm64"),
    )


def _identity_output(defines: Mapping[str, str]) -> bytes:
    return (
        MODULE.IDENTITY_MARKER
        + json.dumps(
            dict(defines),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        + b"\n"
    )


def _metadata_json(goos: str, goarch: str, *, extra: object = None) -> bytes:
    architecture = "GOAMD64" if goarch == "amd64" else "GOARM64"
    level = "v1" if goarch == "amd64" else "v8.0"
    settings = [
        {"Key": "-buildmode", "Value": "exe"},
        {"Key": "-compiler", "Value": "gc"},
        {"Key": "-trimpath", "Value": "true"},
        {"Key": "CGO_ENABLED", "Value": "0"},
        {"Key": "GOARCH", "Value": goarch},
        {"Key": architecture, "Value": level},
        {"Key": "GOOS", "Value": goos},
    ]
    if extra is not None:
        settings.append(extra)
    return (
        json.dumps(
            {
                "GoVersion": "go1.27.1",
                "Main": {
                    "Path": "winsvpn.local/gcpproofclient",
                    "Version": "(devel)",
                },
                "Path": "winsvpn.local/gcpproofclient",
                "Settings": settings,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


def _fake_macho() -> bytes:
    total = 256
    commands = b"".join(
        (
            struct.pack(
                "<II16sQQQQiiII",
                0x19,
                72,
                b"__TEXT".ljust(16, b"\0"),
                0x100000000,
                176,
                0,
                176,
                7,
                5,
                0,
                0,
            ),
            struct.pack(
                "<II16sQQQQiiII",
                0x19,
                72,
                b"__LINKEDIT".ljust(16, b"\0"),
                0x1000000B0,
                total - 176,
                176,
                total - 176,
                7,
                1,
                0,
                0,
            ),
        )
    )
    header = MODULE.MACHO64_HEADER.pack(
        MODULE.MACHO64_MAGIC,
        MODULE.MACHO_ARM64_CPU,
        0,
        2,
        2,
        len(commands),
        0,
        0,
    )
    return (header + commands).ljust(total, b"M")


def _fake_elf(
    defines: Mapping[str, str],
    *,
    dynamic: bool = False,
    bad_buildinfo: bool = False,
    omit_identity: str | None = None,
) -> bytes:
    section_names = (
        "",
        ".text",
        ".rodata",
        ".go.buildinfo",
        ".gopclntab",
        ".data",
        ".shstrtab",
    )
    shstrtab = b"\0"
    name_offsets = {"": 0}
    for name in section_names[1:]:
        name_offsets[name] = len(shstrtab)
        shstrtab += name.encode("ascii") + b"\0"
    identity_values = []
    for key in sorted(defines):
        value = defines[key]
        if key == omit_identity:
            value = "x" * len(value)
        identity_values.append(value.encode("ascii"))
    rodata = b"\0".join(identity_values) + b"\0"
    if len(rodata) > 0x1C0:
        raise AssertionError("synthetic identity section is too large")
    buildinfo = (
        b"not-go-buildinfo" if bad_buildinfo else b"\xff Go buildinf:"
    ).ljust(0x20, b"\0")
    image = bytearray(0xA00)
    image[0x200:0x240] = b"T" * 0x40
    image[0x240 : 0x240 + len(rodata)] = rodata
    image[0x400:0x420] = buildinfo
    image[0x420:0x460] = b"P" * 0x40
    image[0x500:0x540] = b"D" * 0x40
    image[0x700 : 0x700 + len(shstrtab)] = shstrtab
    program_offset = MODULE.ELF_HEADER.size
    section_offset = 0x800
    ident = b"\x7fELF\x02\x01\x01\x00" + b"\0" * 8
    image[: MODULE.ELF_HEADER.size] = MODULE.ELF_HEADER.pack(
        ident,
        2,
        62,
        1,
        0x400200,
        program_offset,
        section_offset,
        0,
        MODULE.ELF_HEADER.size,
        MODULE.ELF_PROGRAM_HEADER.size,
        2,
        MODULE.ELF_SECTION_HEADER.size,
        len(section_names),
        6,
    )
    first_program = MODULE.ELF_PROGRAM_HEADER.pack(
        1,
        5,
        0,
        0x400000,
        0x400000,
        0x500,
        0x500,
        0x1000,
    )
    second_program = MODULE.ELF_PROGRAM_HEADER.pack(
        2 if dynamic else 1,
        6,
        0x500,
        0x401500,
        0x401500,
        0x100,
        0x100,
        0x1000,
    )
    image[program_offset : program_offset + len(first_program)] = first_program
    image[
        program_offset
        + len(first_program) : program_offset
        + len(first_program)
        + len(second_program)
    ] = second_program
    sections = (
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (name_offsets[".text"], 1, 0x6, 0x400200, 0x200, 0x40, 0, 0, 16, 0),
        (
            name_offsets[".rodata"],
            1,
            0x2,
            0x400240,
            0x240,
            len(rodata),
            0,
            0,
            16,
            0,
        ),
        (
            name_offsets[".go.buildinfo"],
            1,
            0x2,
            0x400400,
            0x400,
            0x20,
            0,
            0,
            16,
            0,
        ),
        (
            name_offsets[".gopclntab"],
            1,
            0x2,
            0x400420,
            0x420,
            0x40,
            0,
            0,
            16,
            0,
        ),
        (name_offsets[".data"], 1, 0x3, 0x401500, 0x500, 0x40, 0, 0, 16, 0),
        (
            name_offsets[".shstrtab"],
            3,
            0,
            0,
            0x700,
            len(shstrtab),
            0,
            0,
            1,
            0,
        ),
    )
    for index, fields in enumerate(sections):
        start = section_offset + index * MODULE.ELF_SECTION_HEADER.size
        image[start : start + MODULE.ELF_SECTION_HEADER.size] = (
            MODULE.ELF_SECTION_HEADER.pack(*fields)
        )
    return bytes(image)


class FakeSnapshot:
    def __init__(self, source: Mapping[str, bytes]) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="source-fixture-")
        self.path = pathlib.Path(self._temporary.name)
        self._expected = MODULE._snapshot_files(source)
        for name, data in self._expected.items():
            (self.path / name).write_bytes(data)
            (self.path / name).chmod(0o444)
        self.path.chmod(0o555)
        self._directory_fd = os.open(
            self.path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        self._identity = MODULE._file_identity(os.fstat(self._directory_fd))
        self.verify()

    @property
    def directory_fd(self) -> int:
        return self._directory_fd

    def verify(self) -> None:
        if MODULE._file_identity(os.fstat(self._directory_fd)) != self._identity:
            raise MODULE.ProofBuildError("Held proof source directory changed.")
        if {entry.name for entry in os.scandir(self._directory_fd)} != set(
            self._expected
        ):
            raise MODULE.ProofBuildError("Held proof source inventory changed.")
        for name, expected in self._expected.items():
            try:
                observed = (self.path / name).read_bytes()
                mode = stat.S_IMODE((self.path / name).lstat().st_mode)
            except OSError as exc:
                raise MODULE.ProofBuildError(
                    f"Held proof source changed: {name}."
                ) from exc
            if observed != expected or mode != 0o444:
                raise MODULE.ProofBuildError(f"Held proof source changed: {name}.")

    def close(self) -> None:
        if self._directory_fd >= 0:
            os.close(self._directory_fd)
            self._directory_fd = -1
        self.path.chmod(0o700)
        for path in self.path.iterdir():
            path.chmod(0o600)
        self._temporary.cleanup()

    def __enter__(self) -> "FakeSnapshot":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class FakeGo:
    def __init__(
        self,
        defines: Mapping[str, str],
        *,
        elf_factory: Callable[[Mapping[str, str]], bytes] | None = None,
        metadata_extra: object = None,
        nonreproducible: bool = False,
        hook: Callable[[tuple[str, ...], pathlib.Path], None] | None = None,
    ) -> None:
        self.defines = dict(defines)
        self.elf_factory = elf_factory or (lambda values: _fake_elf(values))
        self.metadata_extra = metadata_extra
        self.nonreproducible = nonreproducible
        self.hook = hook
        self.calls: list[tuple[tuple[str, ...], dict[str, str], pathlib.Path]] = []
        self.verifications = 0
        self.closed = False
        self.builds = 0

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: pathlib.Path,
        cwd_fd: int,
        env: Mapping[str, str],
    ) -> bytes:
        recorded = tuple(map(str, argv))
        self.calls.append((recorded, dict(env), pathlib.Path(cwd)))
        if recorded == ("version",):
            result = b"go version go1.27.1 darwin/arm64\n"
        elif recorded[:3] == ("version", "-m", "-json"):
            result = _metadata_json(
                env["GOOS"], env["GOARCH"], extra=self.metadata_extra
            )
        elif recorded[0] == "test" and "-c" in recorded:
            output = pathlib.Path(recorded[recorded.index("-o") + 1])
            output.write_bytes(_fake_macho())
            output.chmod(0o755)
            result = b""
        elif recorded[0] == "test":
            result = b"ok\n"
        elif recorded[0] == "build":
            output = pathlib.Path(recorded[recorded.index("-o") + 1])
            body = self.elf_factory(self.defines)
            if self.nonreproducible and self.builds:
                body += b"second-build"
            output.write_bytes(body)
            output.chmod(0o755)
            self.builds += 1
            result = b""
        else:
            raise AssertionError(f"unexpected Go argv: {recorded}")
        if self.hook is not None:
            self.hook(recorded, pathlib.Path(cwd))
        return result

    def verify(self) -> None:
        self.verifications += 1

    def __enter__(self) -> "FakeGo":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.closed = True


class ContractAndFormatTests(unittest.TestCase):
    DEFINES = {
        "attempt_broker_sha256": "1" * 64,
        "build_contract_sha256": "2" * 64,
        "build_identity": "3" * 64,
        "release": "1.0.15+30",
        "shared_revision": "4" * 40,
        "source_sha256": "5" * 64,
        "target": "linux/amd64",
        "toolchain_version": "go1.27.1",
    }

    def test_contract_versions_and_release_target_are_exact(self) -> None:
        self.assertEqual(MODULE.SCHEMA_VERSION, 3)
        self.assertEqual(
            MODULE.BUILD_CONTRACT,
            "winsvpn-gcp-proof-client-build-contract-v5",
        )
        self.assertEqual(
            MODULE.SOURCE_SNAPSHOT_CONTRACT,
            "winsvpn-root-immutable-proof-source-v1",
        )
        self.assertEqual(MODULE.RELEASE_TARGET, LINUX_AMD64)
        self.assertIn(b"func TestMain(m *testing.M)", MODULE.IDENTITY_PROBE_BYTES)
        self.assertIn(b"expectedAttemptBrokerSHA256", MODULE.IDENTITY_PROBE_BYTES)

    def test_ldflags_bind_all_and_only_eight_identities(self) -> None:
        flags = MODULE._ldflags(self.DEFINES)
        self.assertTrue(flags.startswith("-s -w -buildid="))
        for key, variable in MODULE.IDENTITY_DEFINE_NAMES:
            self.assertIn(f"-X=main.{variable}={self.DEFINES[key]}", flags)
        self.assertEqual(flags.count("-X=main."), 8)
        with self.assertRaisesRegex(MODULE.ProofBuildError, "keys are not exact"):
            MODULE._ldflags({**self.DEFINES, "extra": "value"})

    def test_native_identity_readback_is_exact_and_bounded(self) -> None:
        MODULE._parse_native_identity(_identity_output(self.DEFINES), self.DEFINES)
        for hostile in (
            b"noise\n" + _identity_output(self.DEFINES),
            _identity_output(self.DEFINES) + b"PASS\n",
            MODULE.IDENTITY_MARKER + b'{"release":"wrong"}\n',
        ):
            with self.subTest(hostile=hostile[:20]), self.assertRaises(
                MODULE.ProofBuildError
            ):
                MODULE._parse_native_identity(hostile, self.DEFINES)

    def test_structured_go_metadata_is_exact(self) -> None:
        MODULE._require_artifact_metadata(
            _metadata_json("linux", "amd64"),
            LINUX_AMD64,
            "go1.27.1",
        )
        hostile = (
            _metadata_json(
                "linux", "amd64", extra={"Key": "vcs", "Value": "git"}
            ),
            _metadata_json(
                "linux", "amd64", extra={"Key": "GOARM64", "Value": "v8.0"}
            ),
            _metadata_json(
                "linux",
                "amd64",
                extra={"Key": "DefaultGODEBUG", "Value": "hostile=1"},
            ),
        )
        for metadata in hostile:
            with self.subTest(metadata=metadata[-80:]), self.assertRaisesRegex(
                MODULE.ProofBuildError, "exact reviewed set"
            ):
                MODULE._require_artifact_metadata(
                    metadata, LINUX_AMD64, "go1.27.1"
                )

    def test_metadata_rejects_duplicate_setting_and_module_dependency(self) -> None:
        duplicate = json.loads(_metadata_json("linux", "amd64"))
        duplicate["Settings"].append({"Key": "GOOS", "Value": "linux"})
        with self.assertRaisesRegex(MODULE.ProofBuildError, "ambiguous"):
            MODULE._require_artifact_metadata(
                (json.dumps(duplicate) + "\n").encode("ascii"),
                LINUX_AMD64,
                "go1.27.1",
            )
        dependency = json.loads(_metadata_json("linux", "amd64"))
        dependency["Deps"] = [
            {"Path": "example.invalid/hostile", "Version": "v1.0.0"}
        ]
        with self.assertRaisesRegex(MODULE.ProofBuildError, "dependency"):
            MODULE._require_artifact_metadata(
                (json.dumps(dependency) + "\n").encode("ascii"),
                LINUX_AMD64,
                "go1.27.1",
            )

    def test_full_elf_validator_rejects_header_only_and_dynamic_files(self) -> None:
        valid = _fake_elf(self.DEFINES)
        MODULE._require_linux_amd64_elf(valid, self.DEFINES)
        with self.assertRaises(MODULE.ProofBuildError):
            MODULE._require_linux_amd64_elf(valid[:64], self.DEFINES)
        with self.assertRaisesRegex(MODULE.ProofBuildError, "dynamically linked"):
            MODULE._require_linux_amd64_elf(
                _fake_elf(self.DEFINES, dynamic=True), self.DEFINES
            )

    def test_elf_requires_go_magic_and_every_identity_including_broker(self) -> None:
        with self.assertRaisesRegex(MODULE.ProofBuildError, "build-info magic"):
            MODULE._require_linux_amd64_elf(
                _fake_elf(self.DEFINES, bad_buildinfo=True), self.DEFINES
            )
        with self.assertRaisesRegex(
            MODULE.ProofBuildError, "attempt_broker_sha256"
        ):
            MODULE._require_linux_amd64_elf(
                _fake_elf(self.DEFINES, omit_identity="attempt_broker_sha256"),
                self.DEFINES,
            )

    def test_native_macho_validator_rejects_plausible_headers(self) -> None:
        valid = _fake_macho()
        MODULE._require_native_probe_macho(valid)
        with self.assertRaises(MODULE.ProofBuildError):
            MODULE._require_native_probe_macho(valid[: MODULE.MACHO64_HEADER.size])
        wrong_cpu = bytearray(valid)
        struct.pack_into("<i", wrong_cpu, 4, 7)
        with self.assertRaises(MODULE.ProofBuildError):
            MODULE._require_native_probe_macho(bytes(wrong_cpu))


class ReleaseIndexScopeTests(unittest.TestCase):
    def test_proof_build_refuses_a_platform_scoped_release_index(self) -> None:
        # R22 Y3-07: freeze.verify_release_index accepts a scoped index for an
        # in-scope platform, but the proof fleet binds only the complete index,
        # so the builder refuses a scoped one before any build work.
        class Inputs:
            def __init__(self, payload: bytes) -> None:
                self.payload = payload

            def verify(self) -> None:
                return None

            def bytes(self, _relative: str) -> bytes:
                return self.payload

        complete_contract = "winsvpn-release-input-index-v1"
        verified = {"release": "1.0.16+33", "shared_revision": "a" * 64}
        fake_freeze = types.SimpleNamespace(
            INDEX_CONTRACT=complete_contract,
            DependencyFreezeError=RuntimeError,
            verify_release_index=lambda *_args: dict(verified),
        )
        repo = pathlib.Path("/fixture-repo")
        index = repo / ".artifacts/release-inputs/release.json"
        cases = {
            "scoped": (
                {
                    "contract": "winsvpn-release-input-index-scoped-v1",
                    "manifest_set_complete": False,
                },
                "complete release input index",
            ),
            "scoped contract claiming complete": (
                {
                    "contract": "winsvpn-release-input-index-scoped-v1",
                    "manifest_set_complete": True,
                },
                "complete release input index",
            ),
            "complete contract without the flag": (
                {"contract": complete_contract},
                "complete release input index",
            ),
            "complete": (
                {"contract": complete_contract, "manifest_set_complete": True},
                "reached the gcloud pin check",
            ),
        }
        with (
            mock.patch.object(MODULE, "freeze", fake_freeze),
            mock.patch.object(
                MODULE, "require_reviewed_builder_host", return_value={"host": "fixture"}
            ),
            mock.patch.object(
                MODULE,
                "_verify_generated_gcloud_pin",
                side_effect=MODULE.ProofBuildError("reached the gcloud pin check"),
            ),
        ):
            for label, (fields, message) in cases.items():
                record = {**verified, **fields}
                with (
                    self.subTest(case=label),
                    self.assertRaisesRegex(MODULE.ProofBuildError, message),
                ):
                    MODULE._expected_provenance(
                        repo,
                        index,
                        dict(MODULE.RELEASE_TARGET),
                        Inputs(json.dumps(record).encode("utf-8")),
                    )


class RepositoryFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name).resolve()
        for relative in (*MODULE.SOURCE_PATHS, MODULE.BUILDER_PATH, MODULE.PIN_PATH):
            source = WORKSPACE / relative
            destination = self.repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
        self.index = self.repo / ".artifacts/release-inputs/release.json"
        self.index.parent.mkdir(parents=True)
        self.index.write_text('{"release":"fixture"}\n', encoding="ascii")
        self.builder_patch = mock.patch.object(
            MODULE, "_validate_executing_builder", return_value=None
        )
        self.builder_patch.start()
        self.addCleanup(self.builder_patch.stop)

    def tearDown(self) -> None:
        for base, directories, files in os.walk(self.repo, topdown=False):
            for name in files:
                with contextlib.suppress(OSError):
                    (pathlib.Path(base) / name).chmod(0o600)
            for name in directories:
                with contextlib.suppress(OSError):
                    (pathlib.Path(base) / name).chmod(0o700)
        self.temporary.cleanup()

    def held_paths(self) -> tuple[str, ...]:
        return (
            *MODULE.SOURCE_PATHS,
            MODULE.BUILDER_PATH,
            MODULE.PIN_PATH,
            self.index.relative_to(self.repo).as_posix(),
        )


class DescriptorCustodyTests(RepositoryFixture):
    def test_helper_global_module_substitution_is_rejected(self) -> None:
        with MODULE._DescriptorRepoInputs(self.repo, self.held_paths()) as inputs:
            original = MODULE.go_custody
            MODULE.go_custody = types.ModuleType("release_go_archive_custody")
            try:
                with self.assertRaisesRegex(
                    MODULE.ProofBuildError, "helper module was substituted"
                ):
                    inputs.verify()
            finally:
                MODULE.go_custody = original

    def test_in_place_helper_function_substitution_is_rejected(self) -> None:
        with MODULE._DescriptorRepoInputs(self.repo, self.held_paths()) as inputs:
            original = MODULE.go_custody.verify_runtime
            MODULE.go_custody.verify_runtime = lambda _argv: None
            try:
                with self.assertRaisesRegex(
                    MODULE.ProofBuildError, "helper module was substituted"
                ):
                    inputs.verify()
            finally:
                MODULE.go_custody.verify_runtime = original

    def test_helper_runtime_file_and_sys_modules_substitution_are_rejected(self) -> None:
        with MODULE._DescriptorRepoInputs(self.repo, self.held_paths()) as inputs:
            helper = MODULE.gcloud_custody
            original_file = helper.__file__
            helper.__file__ = str(self.repo / "tools/__pycache__/gcloud_custody.pyc")
            try:
                with self.assertRaisesRegex(
                    MODULE.ProofBuildError, "helper module was substituted"
                ):
                    inputs.verify()
            finally:
                helper.__file__ = original_file
            replacement = types.ModuleType("gcloud_custody")
            sys.modules["gcloud_custody"] = replacement
            try:
                with self.assertRaisesRegex(
                    MODULE.ProofBuildError, "helper module was substituted"
                ):
                    inputs.verify()
            finally:
                sys.modules["gcloud_custody"] = helper

    def test_repository_parent_swap_is_rejected_while_descriptors_are_held(self) -> None:
        with MODULE._DescriptorRepoInputs(self.repo, self.held_paths()) as inputs:
            tools = self.repo / "tools"
            moved = self.repo / "tools-held"
            tools.rename(moved)
            tools.mkdir()
            with self.assertRaises(MODULE.ProofBuildError):
                inputs.verify()

    def test_unchecked_hash_pycache_builder_substitution_is_rejected(self) -> None:
        self.builder_patch.stop()
        honest = self.repo / MODULE.BUILDER_PATH
        hostile_source = self.repo / "hostile-builder.py"
        hostile_source.write_bytes(
            honest.read_bytes() + b"\nMALICIOUS_BUILDER_EXECUTED = True\n"
        )
        cache = pathlib.Path(importlib.util.cache_from_source(str(honest)))
        cache.parent.mkdir(parents=True, exist_ok=True)
        py_compile.compile(
            str(hostile_source),
            cfile=str(cache),
            doraise=True,
            invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
        )
        spec = importlib.util.spec_from_file_location("hostile_builder", honest)
        assert spec and spec.loader
        hostile = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(hostile)
        with self.assertRaisesRegex(
            hostile.ProofBuildError, "alternate pycache bytes"
        ):
            hostile._DescriptorRepoInputs(self.repo, self.held_paths())

    def test_real_builder_runtime_file_must_be_recorded_source(self) -> None:
        # The held copy of the real builder, executing from its .pyc name, is
        # refused. R23 F-W1-03: this used to hold an untracked .artifacts
        # index from one workstation, so a clean checkout failed earlier.
        self.builder_patch.stop()
        original_file = MODULE.__file__
        MODULE.__file__ = str((self.repo / MODULE.BUILDER_PATH).with_suffix(".pyc"))
        try:
            with self.assertRaisesRegex(
                MODULE.ProofBuildError, "outside repo_root"
            ):
                MODULE._DescriptorRepoInputs(self.repo, self.held_paths())
        finally:
            MODULE.__file__ = original_file


class SourceSnapshotTests(RepositoryFixture):
    def source(self) -> dict[str, bytes]:
        return {
            relative: (self.repo / relative).read_bytes()
            for relative in MODULE.PACKAGE_COMPILER_INPUTS
        }

    def test_missing_root_owned_sf_immutable_snapshot_is_owner_blocked(self) -> None:
        with mock.patch.object(
            MODULE,
            "SOURCE_SNAPSHOT_ROOT",
            self.repo / "unprovisioned/v1",
        ), self.assertRaisesRegex(MODULE.ProofBuildError, "OWNER-BLOCKED"):
            MODULE._HeldSourceSnapshot(self.source())

    def test_descriptor_bound_snapshot_detects_parent_substitution(self) -> None:
        source = self.source()
        root = self.repo / "immutable/v1"
        snapshot = root / MODULE._source_snapshot_id(source)
        snapshot.mkdir(parents=True)
        for name, data in MODULE._snapshot_files(source).items():
            (snapshot / name).write_bytes(data)
            (snapshot / name).chmod(0o444)
        snapshot.chmod(0o555)
        with mock.patch.object(MODULE, "SOURCE_SNAPSHOT_ROOT", root), mock.patch.object(
            MODULE, "_require_trusted_source_ancestor", return_value=None
        ), mock.patch.object(
            MODULE, "_require_system_immutable_source", return_value=None
        ):
            with MODULE._HeldSourceSnapshot(source) as held:
                moved = snapshot.with_name(snapshot.name + "-held")
                snapshot.rename(moved)
                snapshot.mkdir()
                with self.assertRaisesRegex(
                    MODULE.ProofBuildError, "escaped its held parent"
                ):
                    held.verify()

    def test_native_probe_same_inode_mutate_restore_is_rejected(self) -> None:
        binary = self.repo / "native.test"
        body = b"native-test-bytes"
        binary.write_bytes(body)
        binary.chmod(0o755)
        cwd = self.repo / "cwd"
        cwd.mkdir()
        cwd_fd = os.open(cwd, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))

        def mutate(*_args: object, **_kwargs: object) -> object:
            binary.write_bytes(b"x" * len(body))
            binary.write_bytes(body)
            binary.chmod(0o755)
            return types.SimpleNamespace(
                returncode=0,
                stdout=b"ignored",
                stderr=b"",
            )

        try:
            with mock.patch.object(MODULE.subprocess, "run", side_effect=mutate):
                with self.assertRaisesRegex(
                    MODULE.ProofBuildError, "execution failed"
                ):
                    MODULE._run_held_native_probe(
                        binary,
                        body,
                        cwd=cwd,
                        cwd_fd=cwd_fd,
                        env={},
                    )
        finally:
            os.close(cwd_fd)


class BuildBoundaryTests(RepositoryFixture):
    def setUp(self) -> None:
        super().setUp()
        self.provenance = self._provenance()
        self.provenance_patch = mock.patch.object(
            MODULE, "_expected_provenance", return_value=self.provenance
        )
        self.provenance_mock = self.provenance_patch.start()
        self.addCleanup(self.provenance_patch.stop)

    def _provenance(self) -> dict[str, object]:
        compiler_refs = []
        for relative in MODULE.PACKAGE_COMPILER_INPUTS:
            data = (self.repo / relative).read_bytes()
            compiler_refs.append(
                {
                    "bytes": len(data),
                    "path": relative,
                    "sha256": MODULE.sha256_bytes(data),
                }
            )
        defines = {
            "attempt_broker_sha256": MODULE.sha256_bytes(
                (self.repo / "tools/gcp_proof_attempt_broker.py").read_bytes()
            ),
            "build_contract_sha256": "2" * 64,
            "build_identity": "3" * 64,
            "release": "1.0.15+30",
            "shared_revision": "4" * 40,
            "source_sha256": "5" * 64,
            "target": "linux/amd64",
            "toolchain_version": "go1.27.1",
        }
        environment = {
            "CGO_ENABLED": "0",
            "GOARCH": "amd64",
            "GOAMD64": "v1",
            "GOENV": "off",
            "GOFIPS140": "off",
            "GOOS": "linux",
            "GOPROXY": "off",
            "GOSUMDB": "off",
            "GOTOOLCHAIN": "local",
            "GOWORK": "off",
        }
        test_environment = {
            "CGO_ENABLED": "0",
            "GOARCH": "arm64",
            "GOARM64": "v8.0",
            "GOENV": "off",
            "GOFIPS140": "off",
            "GOOS": "darwin",
            "GOPROXY": "off",
            "GOSUMDB": "off",
            "GOTOOLCHAIN": "local",
            "GOWORK": "off",
        }
        builder_data = (self.repo / MODULE.BUILDER_PATH).read_bytes()
        pin_data = (self.repo / MODULE.PIN_PATH).read_bytes()
        index_data = self.index.read_bytes()
        return {
            "build_contract": {
                "contract": MODULE.BUILD_CONTRACT,
                "environment": environment,
                "native_identity_probe": {
                    "source": {
                        "bytes": len(MODULE.IDENTITY_PROBE_BYTES),
                        "path": MODULE.IDENTITY_PROBE_NAME,
                        "sha256": MODULE.sha256_bytes(MODULE.IDENTITY_PROBE_BYTES),
                    }
                },
                "sha256": "2" * 64,
                "test_environment": test_environment,
            },
            "build_identity": defines["build_identity"],
            "builder": {
                "bytes": len(builder_data),
                "path": MODULE.BUILDER_PATH,
                "sha256": MODULE.sha256_bytes(builder_data),
            },
            "defines": defines,
            "release": defines["release"],
            "release_input_index": {
                "path": self.index.relative_to(self.repo).as_posix(),
                "sha256": MODULE.sha256_bytes(index_data),
            },
            "shared_revision": defines["shared_revision"],
            "source": {
                "compiler_inputs": compiler_refs,
                "contract": MODULE.SOURCE_CONTRACT,
                "package": MODULE.PROOF_PACKAGE,
                "reviewed_support": [],
                "schema_version": MODULE.SCHEMA_VERSION,
                "sha256": defines["source_sha256"],
            },
            "target": dict(LINUX_AMD64),
            "toolchain": {"platform": "darwin/arm64", "version": "1.27.1"},
            "toolchain_pin_manifest": {
                "bytes": len(pin_data),
                "path": MODULE.PIN_PATH,
                "sha256": MODULE.sha256_bytes(pin_data),
            },
        }

    def _paths(self) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        artifact = MODULE.labeled_artifact_name(LINUX_AMD64)
        bundle = self.repo / "published" / (artifact + MODULE.BUNDLE_SUFFIX)
        return (
            bundle / artifact,
            bundle / (artifact + ".receipt.json"),
            bundle,
        )

    def _build(
        self,
        fake: FakeGo,
        *,
        identity: bytes | None = None,
        rename: Callable[..., None] | None = None,
    ) -> dict[str, object]:
        output, receipt, _bundle = self._paths()
        with contextlib.ExitStack() as stack:
            stack.enter_context(_host_darwin_arm64())
            stack.enter_context(
                mock.patch.object(MODULE, "_HeldSourceSnapshot", FakeSnapshot)
            )
            stack.enter_context(
                mock.patch.object(MODULE, "_open_reviewed_go", return_value=fake)
            )
            stack.enter_context(
                mock.patch.object(
                    MODULE,
                    "_run_held_native_probe",
                    return_value=(
                        identity
                        if identity is not None
                        else _identity_output(self.provenance["defines"])
                    ),
                )
            )
            if rename is not None:
                stack.enter_context(
                    mock.patch.object(
                        MODULE, "_rename_noreplace", side_effect=rename
                    )
                )
            return MODULE.build(
                self.repo,
                self.index,
                output,
                receipt,
                goos="linux",
                goarch="amd64",
            )

    def test_build_proves_native_identity_and_publishes_one_exact_bundle(self) -> None:
        fake = FakeGo(self.provenance["defines"])
        result = self._build(fake)
        output, receipt, bundle = self._paths()
        anchor = receipt.with_name(receipt.name + ".sha256")
        self.assertEqual(result["target"], LINUX_AMD64)
        self.assertEqual(
            {path.name for path in bundle.iterdir()},
            {output.name, receipt.name, anchor.name},
        )
        self.assertEqual(stat.S_IMODE(bundle.lstat().st_mode), 0o500)
        self.assertEqual(stat.S_IMODE(output.lstat().st_mode), 0o555)
        self.assertEqual(stat.S_IMODE(receipt.lstat().st_mode), 0o444)
        self.assertEqual(json.loads(receipt.read_bytes()), result)
        self.assertEqual(
            anchor.read_bytes(),
            f"{MODULE.sha256_bytes(receipt.read_bytes())}  {receipt.name}\n".encode(
                "ascii"
            ),
        )
        native_calls = [
            argv
            for argv, _env, _cwd in fake.calls
            if argv[0] == "test" and "-c" in argv
        ]
        self.assertEqual(len(native_calls), 1)
        linker = next(
            item for item in native_calls[0] if item.startswith("-ldflags=")
        )
        self.assertEqual(
            linker.removeprefix("-ldflags="), MODULE._ldflags(result["defines"])
        )
        build_calls = [
            argv for argv, _env, _cwd in fake.calls if argv[0] == "build"
        ]
        self.assertEqual(len(build_calls), 2)
        self.assertEqual(fake.verifications, 8)
        self.assertTrue(fake.closed)

    def test_non_linux_release_target_is_rejected_before_provenance(self) -> None:
        artifact = MODULE.labeled_artifact_name(DARWIN_ARM64)
        bundle = self.repo / "published" / (artifact + MODULE.BUNDLE_SUFFIX)
        with _host_darwin_arm64(), self.assertRaisesRegex(
            MODULE.ProofBuildError, "exact linux/amd64"
        ):
            MODULE.build(
                self.repo,
                self.index,
                bundle / artifact,
                bundle / (artifact + ".receipt.json"),
                goos="darwin",
                goarch="arm64",
            )
        self.provenance_mock.assert_not_called()

    def test_old_split_output_layout_is_rejected(self) -> None:
        artifact = MODULE.labeled_artifact_name(LINUX_AMD64)
        output = self.repo / "build" / artifact
        receipt = self.repo / ".artifacts" / (artifact + ".receipt.json")
        with _host_darwin_arm64(), self.assertRaisesRegex(
            MODULE.ProofBuildError, "one new labeled .bundle"
        ):
            MODULE.build(
                self.repo,
                self.index,
                output,
                receipt,
                goos="linux",
                goarch="amd64",
            )

    def test_native_identity_mismatch_prevents_any_bundle(self) -> None:
        fake = FakeGo(self.provenance["defines"])
        with self.assertRaisesRegex(MODULE.ProofBuildError, "readback"):
            self._build(fake, identity=MODULE.IDENTITY_MARKER + b"{}\n")
        self.assertFalse(self._paths()[2].exists())

    def test_plausible_elf_header_cannot_publish(self) -> None:
        fake = FakeGo(
            self.provenance["defines"],
            elf_factory=lambda defines: _fake_elf(defines)[:64],
        )
        with self.assertRaisesRegex(MODULE.ProofBuildError, "ELF64"):
            self._build(fake)
        self.assertFalse(self._paths()[2].exists())

    def test_linux_artifact_without_broker_identity_cannot_publish(self) -> None:
        fake = FakeGo(
            self.provenance["defines"],
            elf_factory=lambda defines: _fake_elf(
                defines, omit_identity="attempt_broker_sha256"
            ),
        )
        with self.assertRaisesRegex(
            MODULE.ProofBuildError, "attempt_broker_sha256"
        ):
            self._build(fake)
        self.assertFalse(self._paths()[2].exists())

    def test_unreviewed_metadata_setting_cannot_publish(self) -> None:
        fake = FakeGo(
            self.provenance["defines"],
            metadata_extra={"Key": "vcs", "Value": "git"},
        )
        with self.assertRaisesRegex(MODULE.ProofBuildError, "exact reviewed set"):
            self._build(fake)
        self.assertFalse(self._paths()[2].exists())

    def test_nonreproducible_linux_bytes_cannot_publish(self) -> None:
        fake = FakeGo(self.provenance["defines"], nonreproducible=True)
        with self.assertRaisesRegex(MODULE.ProofBuildError, "not byte-reproducible"):
            self._build(fake)
        self.assertFalse(self._paths()[2].exists())

    def test_live_source_mutation_is_detected_before_publication(self) -> None:
        changed = False

        def mutate(argv: tuple[str, ...], _cwd: pathlib.Path) -> None:
            nonlocal changed
            if argv[0] == "build" and not changed:
                changed = True
                path = self.repo / "tools/gcp_proof_client/main.go"
                path.write_bytes(path.read_bytes() + b"\n// hostile drift\n")

        fake = FakeGo(self.provenance["defines"], hook=mutate)
        with self.assertRaisesRegex(MODULE.ProofBuildError, "changed while held"):
            self._build(fake)
        self.assertFalse(self._paths()[2].exists())

    def test_held_snapshot_mutation_is_detected_before_publication(self) -> None:
        changed = False

        def mutate(argv: tuple[str, ...], cwd: pathlib.Path) -> None:
            nonlocal changed
            if argv[0] == "build" and not changed:
                changed = True
                path = cwd / "main.go"
                path.chmod(0o644)
                path.write_bytes(path.read_bytes() + b"// hostile\n")

        fake = FakeGo(self.provenance["defines"], hook=mutate)
        with self.assertRaisesRegex(MODULE.ProofBuildError, "Held proof source"):
            self._build(fake)
        self.assertFalse(self._paths()[2].exists())

    def test_destination_race_preserves_foreign_bundle_and_no_partial_success(self) -> None:
        fake = FakeGo(self.provenance["defines"])
        real_rename = MODULE._rename_noreplace

        def race(
            source_fd: int,
            source_name: str,
            destination_fd: int,
            destination_name: str,
        ) -> None:
            os.mkdir(destination_name, 0o700, dir_fd=destination_fd)
            directory = os.open(
                destination_name,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                dir_fd=destination_fd,
            )
            try:
                marker = os.open(
                    "foreign",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=directory,
                )
                os.close(marker)
            finally:
                os.close(directory)
            real_rename(source_fd, source_name, destination_fd, destination_name)

        with self.assertRaisesRegex(MODULE.ProofBuildError, "already exists"):
            self._build(fake, rename=race)
        _output, _receipt, bundle = self._paths()
        self.assertEqual({item.name for item in bundle.iterdir()}, {"foreign"})
        self.assertEqual(list(bundle.parent.glob(".gcp-proof-stage-*")), [])

    def test_parent_swap_during_bundle_commit_is_detected(self) -> None:
        fake = FakeGo(self.provenance["defines"])
        real_rename = MODULE._rename_noreplace
        moved_parent = self.repo / "published-held"

        def swap(
            source_fd: int,
            source_name: str,
            destination_fd: int,
            destination_name: str,
        ) -> None:
            parent = self.repo / "published"
            parent.rename(moved_parent)
            parent.mkdir()
            real_rename(source_fd, source_name, destination_fd, destination_name)

        with self.assertRaises(MODULE.ProofBuildError):
            self._build(fake, rename=swap)
        output, _receipt, bundle = self._paths()
        self.assertFalse(bundle.exists())
        self.assertFalse(output.exists())
        held_bundle = moved_parent / bundle.name
        self.assertTrue(held_bundle.is_dir())
        self.assertEqual(len(list(held_bundle.iterdir())), 3)

    def test_main_emits_ascii_receipt(self) -> None:
        fake = FakeGo(self.provenance["defines"])
        output, receipt, _bundle = self._paths()
        stdout = mock.Mock()
        stdout.buffer = io.BytesIO()
        with _host_darwin_arm64(), mock.patch.object(
            MODULE, "_HeldSourceSnapshot", FakeSnapshot
        ), mock.patch.object(
            MODULE, "_open_reviewed_go", return_value=fake
        ), mock.patch.object(
            MODULE,
            "_run_held_native_probe",
            return_value=_identity_output(self.provenance["defines"]),
        ), mock.patch.object(MODULE.sys, "stdout", stdout):
            code = MODULE.main(
                [
                    "--repo-root",
                    str(self.repo),
                    "--release-input-index",
                    str(self.index),
                    "--output",
                    str(output),
                    "--receipt",
                    str(receipt),
                    "--goos",
                    "linux",
                    "--goarch",
                    "amd64",
                ]
            )
        self.assertEqual(code, 0)
        self.assertTrue(stdout.buffer.getvalue().isascii())
        self.assertEqual(json.loads(stdout.buffer.getvalue())["target"], LINUX_AMD64)


if __name__ == "__main__":
    unittest.main()
