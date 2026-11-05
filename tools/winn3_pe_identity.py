#!/usr/bin/env python3
"""Verify bounded Windows Winn v3 PE identity under retained custody.

Role authority comes only from an authenticated producer record containing the
exact artifact digest. Embedded strings, section names, filenames, and Go build
information are evidence checked against that record; none can self-authorize a
core or relay role.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import struct
from typing import Any, Iterator

from winn3_path_custody import CustodiedFile, CustodyError, open_custodied_file


CONTRACT = "winsvpn.windows-winn3-authenticated-artifact.v1"
IDENTITY_CONTRACT = "winsvpn.windows-winn3-pe-identity.v1"
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_IMAGE_BYTES = 512 * 1024 * 1024
MAX_HEADER_BYTES = 64 * 1024
MAX_BUILDINFO_STRING_BYTES = 1024 * 1024
BUILDINFO_MAGIC = b"\xff Go buildinf:"
BUILDINFO_START = bytes.fromhex("3077af0c9274080241e1c107e6d618e6")
BUILDINFO_END = bytes.fromhex("f932433186182072008242104116d8f2")
ARCH_MACHINES = {"x64": 0x8664, "arm64": 0xAA64}
ROLE_FILENAMES = {
    "core": "winn-datapath.exe",
    "relay": "winsvpn_winn3_engine.exe",
}
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
GO_VERSION_RE = re.compile(r"go[0-9]+\.[0-9]+(?:\.[0-9]+)?\Z")
GO_PATH_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~+/-]{0,511}\Z")


class PeIdentityError(RuntimeError):
    """PE bytes do not match the authenticated producer identity."""


@dataclass(frozen=True)
class AuthenticatedArtifact:
    """Exact role identity extracted from an already authenticated producer record."""

    contract: str
    role: str
    architecture: str
    filename: str
    sha256: str
    size_bytes: int
    go_version: str
    go_package_path: str
    go_module_path: str
    go_module_identity: str

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "AuthenticatedArtifact":
        expected = {
            "contract",
            "role",
            "architecture",
            "filename",
            "sha256",
            "size_bytes",
            "go_version",
            "go_package_path",
            "go_module_path",
            "go_module_identity",
        }
        if not isinstance(record, dict) or set(record) != expected:
            raise PeIdentityError("refusal:authenticated-artifact-fields-not-exact")
        value = cls(**record)
        value.validate()
        return value

    def validate(self) -> None:
        if self.contract != CONTRACT:
            raise PeIdentityError("refusal:authenticated-artifact-contract-invalid")
        if self.role not in ROLE_FILENAMES:
            raise PeIdentityError("refusal:role-invalid")
        if self.architecture not in ARCH_MACHINES:
            raise PeIdentityError("refusal:architecture-invalid")
        if self.filename != ROLE_FILENAMES[self.role]:
            raise PeIdentityError("refusal:role-filename-mismatch")
        if SHA256_RE.fullmatch(self.sha256) is None:
            raise PeIdentityError("refusal:artifact-digest-invalid")
        if type(self.size_bytes) is not int or not (1 <= self.size_bytes <= MAX_ARTIFACT_BYTES):
            raise PeIdentityError("refusal:size-out-of-range")
        if GO_VERSION_RE.fullmatch(self.go_version) is None:
            raise PeIdentityError("refusal:go-version-invalid")
        for value, label in (
            (self.go_package_path, "go-package"),
            (self.go_module_path, "go-module"),
        ):
            if not isinstance(value, str) or GO_PATH_RE.fullmatch(value) is None:
                raise PeIdentityError(f"refusal:{label}-invalid")
        if (
            not isinstance(self.go_module_identity, str)
            or not self.go_module_identity
            or len(self.go_module_identity.encode("utf-8")) > 4096
            or "\x00" in self.go_module_identity
            or "\n" in self.go_module_identity
            or "\r" in self.go_module_identity
        ):
            raise PeIdentityError("refusal:go-module-identity-invalid")


@dataclass(frozen=True)
class PeSection:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int


@dataclass(frozen=True)
class PeLayout:
    machine: int
    entry_rva: int
    size_of_image: int
    size_of_headers: int
    sections: tuple[PeSection, ...]


@dataclass(frozen=True)
class PeIdentity:
    contract: str
    role: str
    architecture: str
    filename: str
    sha256: str
    size_bytes: int
    machine: int
    go_version: str
    go_package_path: str
    go_module_path: str
    go_module_identity: str


class VerifiedPe:
    """A verified identity and the still-open file from which it was derived."""

    def __init__(self, held: CustodiedFile, identity: PeIdentity) -> None:
        self._held = held
        self.identity = identity

    @property
    def size(self) -> int:
        return self._held.size

    def fileno(self) -> int:
        return self._held.fd

    def read_at(self, offset: int, length: int) -> bytes:
        return self._held.read_at(offset, length)

    def iter_chunks(
        self, chunk_bytes: int = 1024 * 1024
    ) -> Iterator[tuple[int, bytes]]:
        return self._held.iter_chunks(chunk_bytes)

    def assert_unchanged(self) -> None:
        self._held.assert_unchanged()


class VerifiedPeTransaction:
    """Keep PE verification and downstream consumption in one custody lease."""

    def __init__(
        self,
        path: Path,
        expected: AuthenticatedArtifact,
        maximum_bytes: int,
    ) -> None:
        self._path = path
        self._expected = expected
        self._maximum_bytes = maximum_bytes
        self._held: CustodiedFile | None = None

    def __enter__(self) -> VerifiedPe:
        if self._held is not None:
            raise PeIdentityError("refusal:pe-transaction-already-entered")
        try:
            held = open_custodied_file(
                self._path,
                maximum_bytes=self._maximum_bytes,
                label=f"Windows Winn v3 {self._expected.role} artifact",
            )
            self._held = held
            return VerifiedPe(held, verify_custodied_pe(held, self._expected))
        except CustodyError as exc:
            if self._held is not None:
                self._held.close()
                self._held = None
            raise PeIdentityError(str(exc)) from exc
        except Exception:
            if self._held is not None:
                self._held.close()
                self._held = None
            raise

    def __exit__(self, kind: object, value: object, traceback: object) -> None:
        held = self._held
        self._held = None
        if held is None:
            return
        try:
            if kind is None:
                try:
                    held.assert_unchanged()
                except CustodyError as exc:
                    raise PeIdentityError(str(exc)) from exc
        finally:
            held.close()


def _power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _align_up(value: int, alignment: int) -> int:
    if value < 0 or not _power_of_two(alignment):
        raise PeIdentityError("refusal:pe-alignment-invalid")
    return (value + alignment - 1) & ~(alignment - 1)


def _range_end(start: int, size: int, limit: int, label: str) -> int:
    if start < 0 or size < 0 or start > limit or size > limit - start:
        raise PeIdentityError(f"refusal:pe-range-invalid:{label}")
    return start + size


def _rva_is_mapped(rva: int, size: int, layout: PeLayout) -> bool:
    if size <= 0:
        return False
    end = rva + size
    if end <= rva or end > layout.size_of_image:
        return False
    if rva < layout.size_of_headers and end <= layout.size_of_headers:
        return True
    for section in layout.sections:
        span = max(section.virtual_size, section.raw_size)
        if section.virtual_address <= rva and end <= section.virtual_address + span:
            return True
    return False


def _parse_layout(held: CustodiedFile) -> tuple[PeLayout, tuple[tuple[int, int], ...]]:
    if held.size < 0x40:
        raise PeIdentityError("refusal:pe-not-pe32plus")
    dos = held.read_at(0, 0x40)
    if dos[:2] != b"MZ":
        raise PeIdentityError("refusal:pe-not-pe32plus")
    pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset > MAX_HEADER_BYTES - 24:
        raise PeIdentityError("refusal:pe-header-offset-invalid")
    coff = held.read_at(pe_offset, 24)
    if coff[:4] != b"PE\0\0":
        raise PeIdentityError("refusal:pe-signature-invalid")
    machine, section_count, _timestamp, symbol_offset, symbol_count, optional_size, characteristics = struct.unpack_from(
        "<HHIIIHH", coff, 4
    )
    if machine not in ARCH_MACHINES.values():
        raise PeIdentityError("refusal:pe-machine-unsupported")
    if section_count < 1 or section_count > 96:
        raise PeIdentityError("refusal:pe-section-count-invalid")
    if symbol_offset != 0 or symbol_count != 0:
        raise PeIdentityError("refusal:pe-coff-symbol-table-forbidden")
    if characteristics & 0x0002 == 0 or characteristics & 0x2000:
        raise PeIdentityError("refusal:pe-not-executable-image")
    if optional_size < 112 or optional_size > 4096:
        raise PeIdentityError("refusal:pe-optional-header-invalid")
    section_table = pe_offset + 24 + optional_size
    table_end = section_table + section_count * 40
    if table_end > MAX_HEADER_BYTES or table_end > held.size:
        raise PeIdentityError("refusal:pe-section-table-truncated")
    header = held.read_at(pe_offset, table_end - pe_offset)
    optional = 24
    if struct.unpack_from("<H", header, optional)[0] != 0x20B:
        raise PeIdentityError("refusal:pe-not-pe32plus")
    entry_rva = struct.unpack_from("<I", header, optional + 16)[0]
    image_base = struct.unpack_from("<Q", header, optional + 24)[0]
    section_alignment, file_alignment = struct.unpack_from("<II", header, optional + 32)
    size_of_image, size_of_headers = struct.unpack_from("<II", header, optional + 56)
    directory_count = struct.unpack_from("<I", header, optional + 108)[0]
    if entry_rva == 0 or image_base == 0 or image_base % 0x10000:
        raise PeIdentityError("refusal:pe-image-geometry-invalid")
    if (
        not _power_of_two(file_alignment)
        or file_alignment < 0x200
        or file_alignment > 0x10000
        or not _power_of_two(section_alignment)
        or section_alignment < file_alignment
        or (section_alignment < 0x1000 and section_alignment != file_alignment)
    ):
        raise PeIdentityError("refusal:pe-alignment-invalid")
    if (
        size_of_image == 0
        or size_of_image > MAX_IMAGE_BYTES
        or image_base > (1 << 64) - size_of_image
        or size_of_image % section_alignment
        or size_of_headers < table_end
        or size_of_headers > held.size
        or size_of_headers % file_alignment
    ):
        raise PeIdentityError("refusal:pe-image-geometry-invalid")
    if directory_count > 16 or 112 + directory_count * 8 > optional_size:
        raise PeIdentityError("refusal:pe-data-directory-count-invalid")

    sections: list[PeSection] = []
    names: set[str] = set()
    raw_ranges: list[tuple[int, int]] = []
    virtual_ranges: list[tuple[int, int]] = []
    entry_in_code = False
    data_ranges: list[tuple[int, int]] = []
    expected_virtual_address = _align_up(size_of_headers, section_alignment)
    relative_table = section_table - pe_offset
    for index in range(section_count):
        offset = relative_table + index * 40
        raw_name = header[offset : offset + 8].split(b"\0", 1)[0]
        try:
            name = raw_name.decode("ascii")
        except UnicodeDecodeError as exc:
            raise PeIdentityError("refusal:pe-section-name-invalid") from exc
        if not name or name in names or any(ord(character) < 0x21 for character in name):
            raise PeIdentityError("refusal:pe-section-name-invalid")
        names.add(name)
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", header, offset + 8
        )
        section_characteristics = struct.unpack_from("<I", header, offset + 36)[0]
        mapped_size = max(virtual_size, raw_size)
        if (
            mapped_size == 0
            or virtual_address == 0
            or virtual_address % section_alignment
            or virtual_address != expected_virtual_address
            or virtual_address + mapped_size > size_of_image
        ):
            raise PeIdentityError("refusal:pe-section-mapping-invalid")
        expected_virtual_address = _align_up(
            virtual_address + mapped_size, section_alignment
        )
        virtual_ranges.append((virtual_address, virtual_address + mapped_size))
        if raw_size:
            if raw_offset < size_of_headers or raw_offset % file_alignment or raw_size % file_alignment:
                raise PeIdentityError("refusal:pe-section-file-alignment-invalid")
            raw_end = _range_end(raw_offset, raw_size, held.size, "section")
            raw_ranges.append((raw_offset, raw_end))
        code = bool(section_characteristics & 0x00000020)
        executable = bool(section_characteristics & 0x20000000)
        readable = bool(section_characteristics & 0x40000000)
        writable = bool(section_characteristics & 0x80000000)
        if code and executable and readable and virtual_address <= entry_rva < virtual_address + mapped_size:
            entry_in_code = True
        if raw_size and section_characteristics & 0x00000040 and readable and writable and not executable:
            data_ranges.append((raw_offset, raw_offset + raw_size))
        sections.append(
            PeSection(
                name,
                virtual_address,
                virtual_size,
                raw_offset,
                raw_size,
                section_characteristics,
            )
        )
    if expected_virtual_address != size_of_image:
        raise PeIdentityError("refusal:pe-image-geometry-invalid")
    for ranges, refusal in (
        (sorted(raw_ranges), "refusal:pe-raw-sections-overlap"),
        (sorted(virtual_ranges), "refusal:pe-virtual-sections-overlap"),
    ):
        for (_first_start, first_end), (second_start, _second_end) in zip(ranges, ranges[1:]):
            if second_start < first_end:
                raise PeIdentityError(refusal)
    if not entry_in_code:
        raise PeIdentityError("refusal:pe-entrypoint-invalid")
    if not data_ranges:
        raise PeIdentityError("refusal:go-buildinfo-section-absent")

    layout = PeLayout(machine, entry_rva, size_of_image, size_of_headers, tuple(sections))
    directory_offset = optional + 112
    for index in range(directory_count):
        address, size = struct.unpack_from("<II", header, directory_offset + index * 8)
        if address == 0 and size == 0:
            continue
        if address == 0 or size == 0:
            raise PeIdentityError("refusal:pe-data-directory-invalid")
        if index == 4:
            if address % 8 or address < size_of_headers:
                raise PeIdentityError("refusal:pe-certificate-directory-invalid")
            _range_end(address, size, held.size, "certificate directory")
        elif not _rva_is_mapped(address, size, layout):
            raise PeIdentityError("refusal:pe-data-directory-invalid")
    return layout, tuple(data_ranges)


def _candidate_buildinfo_offsets(
    held: CustodiedFile, data_ranges: tuple[tuple[int, int], ...]
) -> tuple[str, list[int]]:
    digest = hashlib.sha256()
    candidates: set[int] = set()
    tails: dict[tuple[int, int], bytes] = {item: b"" for item in data_ranges}
    overlap_bytes = len(BUILDINFO_MAGIC) - 1
    for offset, chunk in held.iter_chunks():
        digest.update(chunk)
        chunk_end = offset + len(chunk)
        for item in data_ranges:
            start, end = item
            overlap_start = max(offset, start)
            overlap_end = min(chunk_end, end)
            if overlap_start >= overlap_end:
                continue
            segment = chunk[overlap_start - offset : overlap_end - offset]
            prior = tails[item]
            window = prior + segment
            base = overlap_start - len(prior)
            cursor = 0
            while True:
                found = window.find(BUILDINFO_MAGIC, cursor)
                if found < 0:
                    break
                absolute = base + found
                if absolute % 16 == 0 and absolute + 32 <= end:
                    candidates.add(absolute)
                cursor = found + 1
            tails[item] = window[-overlap_bytes:] if len(window) > overlap_bytes else window
    return digest.hexdigest(), sorted(candidates)


def _read_uvarint_string(
    held: CustodiedFile,
    offset: int,
    limit: int,
    *,
    label: str,
) -> tuple[bytes, int]:
    value = 0
    shift = 0
    cursor = offset
    for _index in range(10):
        if cursor >= limit:
            raise PeIdentityError(f"refusal:go-buildinfo-{label}-truncated")
        byte = held.read_at(cursor, 1)[0]
        cursor += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            if value > MAX_BUILDINFO_STRING_BYTES or value > limit - cursor:
                raise PeIdentityError(f"refusal:go-buildinfo-{label}-oversized")
            return held.read_at(cursor, value), cursor + value
        shift += 7
    raise PeIdentityError(f"refusal:go-buildinfo-{label}-varint-invalid")


def _build_identity(
    held: CustodiedFile,
    candidates: list[int],
    data_ranges: tuple[tuple[int, int], ...],
) -> tuple[str, str, str, str]:
    if len(candidates) != 1:
        raise PeIdentityError("refusal:go-buildinfo-not-unique")
    offset = candidates[0]
    limit = next(end for start, end in data_ranges if start <= offset < end)
    header = held.read_at(offset, 32)
    if header[:14] != BUILDINFO_MAGIC or header[14] != 8 or header[15] != 2 or any(header[16:]):
        raise PeIdentityError("refusal:go-buildinfo-header-invalid")
    version_bytes, cursor = _read_uvarint_string(
        held, offset + 32, limit, label="version"
    )
    module_bytes, _cursor = _read_uvarint_string(
        held, cursor, limit, label="module"
    )
    try:
        version = version_bytes.decode("ascii")
        if GO_VERSION_RE.fullmatch(version) is None:
            raise ValueError("version")
        if not module_bytes.startswith(BUILDINFO_START) or not module_bytes.endswith(BUILDINFO_END):
            raise PeIdentityError("refusal:go-module-framing-invalid")
        module_text = module_bytes[len(BUILDINFO_START) : -len(BUILDINFO_END)].decode("utf-8")
    except (UnicodeDecodeError, ValueError) as exc:
        raise PeIdentityError("refusal:go-buildinfo-text-invalid") from exc
    if "\x00" in module_text or "\r" in module_text:
        raise PeIdentityError("refusal:go-buildinfo-text-invalid")
    package_values: list[str] = []
    module_values: list[tuple[str, str]] = []
    for line in module_text.splitlines():
        fields = line.split("\t")
        if fields[0] == "path" and len(fields) == 2:
            package_values.append(fields[1])
        elif fields[0] == "mod" and len(fields) >= 2:
            module_values.append((fields[1], "\t".join(fields[1:])))
    if len(package_values) != 1 or len(module_values) != 1:
        raise PeIdentityError("refusal:go-module-identity-ambiguous")
    package_path = package_values[0]
    module_path, module_identity = module_values[0]
    if GO_PATH_RE.fullmatch(package_path) is None or GO_PATH_RE.fullmatch(module_path) is None:
        raise PeIdentityError("refusal:go-module-path-invalid")
    return version, package_path, module_path, module_identity


def verify_custodied_pe(
    held: CustodiedFile, expected: AuthenticatedArtifact
) -> PeIdentity:
    """Verify one already custodied PE against an authenticated producer record."""

    expected.validate()
    if held.path.name != expected.filename:
        raise PeIdentityError("refusal:role-filename-mismatch")
    if held.size != expected.size_bytes:
        raise PeIdentityError("refusal:artifact-size-mismatch")
    layout, data_ranges = _parse_layout(held)
    if layout.machine != ARCH_MACHINES[expected.architecture]:
        raise PeIdentityError("refusal:pe-machine-mismatch")
    digest, candidates = _candidate_buildinfo_offsets(held, data_ranges)
    if digest != expected.sha256:
        raise PeIdentityError("refusal:artifact-digest-mismatch")
    version, package_path, module_path, module_identity = _build_identity(
        held, candidates, data_ranges
    )
    if version != expected.go_version:
        raise PeIdentityError("refusal:go-version-mismatch")
    if package_path != expected.go_package_path:
        raise PeIdentityError("refusal:go-package-mismatch")
    if module_path != expected.go_module_path or module_identity != expected.go_module_identity:
        raise PeIdentityError("refusal:go-module-mismatch")
    held.assert_unchanged()
    return PeIdentity(
        contract=IDENTITY_CONTRACT,
        role=expected.role,
        architecture=expected.architecture,
        filename=expected.filename,
        sha256=digest,
        size_bytes=held.size,
        machine=layout.machine,
        go_version=version,
        go_package_path=package_path,
        go_module_path=module_path,
        go_module_identity=module_identity,
    )


def verify_authenticated_pe(
    path: Path,
    expected: AuthenticatedArtifact,
    *,
    maximum_bytes: int = MAX_ARTIFACT_BYTES,
) -> VerifiedPeTransaction:
    """Return a transaction that retains custody through downstream use."""

    expected.validate()
    maximum = min(maximum_bytes, MAX_ARTIFACT_BYTES)
    if maximum < 1:
        raise PeIdentityError("refusal:size-out-of-range")
    return VerifiedPeTransaction(path, expected, maximum)
