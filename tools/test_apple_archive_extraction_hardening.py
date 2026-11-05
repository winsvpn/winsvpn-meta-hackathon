#!/usr/bin/env python3
"""Hostile no-network archive-extraction tests for the Apple cross-store gate.

These cases assert fail-closed behavior. They may fail against the current
gate; they must not write outside the test temporary directory.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import io
import os
import pathlib
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import apple_cross_store_artifact_gate as apple_gate

DARWIN = sys.platform == "darwin"
TEAM_ID = apple_gate.TEAM_ID
APPLE_DISTRIBUTION = (
    f"Authority=Apple Distribution: Win's VPN Inc ({TEAM_ID})\n"
    f"TeamIdentifier={TEAM_ID}\n"
)
DEVELOPER_ID = (
    f"Authority=Developer ID Application: Win's VPN Inc ({TEAM_ID})\n"
    f"TeamIdentifier={TEAM_ID}\n"
)


def _zip_info(name: str, mode: int) -> zipfile.ZipInfo:
    member = zipfile.ZipInfo(name)
    member.create_system = 3
    member.compress_type = zipfile.ZIP_STORED
    member.external_attr = mode << 16
    return member


def _zip_bytes(entries: list[tuple[str, bytes, int]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload, mode in entries:
            archive.writestr(_zip_info(name, mode), payload)
    return buffer.getvalue()


def _pad_zip(data: bytes, size: int) -> bytes:
    extra = size - len(data)
    if extra == 0:
        return data
    if extra < 0:
        raise AssertionError("zip is larger than the requested pad size")
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0:
        raise AssertionError("zip is missing EOCD")
    comment_len = struct.unpack_from("<H", data, eocd + 20)[0]
    if eocd + 22 + comment_len != len(data):
        raise AssertionError("zip EOCD comment is not at EOF")
    new_len = comment_len + extra
    if new_len > 0xFFFF:
        raise AssertionError("zip comment cannot absorb the pad")
    return (
        data[: eocd + 20]
        + struct.pack("<H", new_len)
        + data[eocd + 22 :]
        + (b"\x00" * extra)
    )


def _rewrite_local_filename(data: bytes, header_offset: int, new_name: str) -> bytes:
    encoded = new_name.encode("utf-8")
    name_len = struct.unpack_from("<H", data, header_offset + 26)[0]
    if len(encoded) != name_len:
        raise AssertionError(
            f"local filename length {name_len} does not match {len(encoded)}"
        )
    start = header_offset + 30
    rewritten = bytearray(data)
    rewritten[start : start + name_len] = encoded
    return bytes(rewritten)


def _local_header_names(data: bytes) -> list[str]:
    names: list[str] = []
    offset = 0
    while offset + 30 <= len(data) and data[offset : offset + 4] == b"PK\x03\x04":
        flags = struct.unpack_from("<H", data, offset + 6)[0]
        compressed_size = struct.unpack_from("<I", data, offset + 18)[0]
        name_len, extra_len = struct.unpack_from("<HH", data, offset + 26)
        name = data[offset + 30 : offset + 30 + name_len].decode("utf-8")
        names.append(name)
        offset += 30 + name_len + extra_len
        if flags & 0x8:
            raise AssertionError("data-descriptor local headers are not used here")
        offset += compressed_size
    return names


def _codesign_target_kind(target: str) -> str:
    lowered = target.casefold()
    if lowered.endswith(".ipa") or lowered.endswith(".app.zip"):
        return "wrapper"
    try:
        info = os.lstat(target)
    except OSError:
        return "missing"
    if stat.S_ISLNK(info.st_mode):
        return "wrapper"
    if stat.S_ISDIR(info.st_mode):
        return "directory"
    if stat.S_ISREG(info.st_mode):
        return "wrapper"
    return "other"


def _bounded_tool_fake(run):
    """Adapt a text-mode fake tool to the gate's single process funnel.

    Since ee48a2f every gate tool runs through _bounded_subprocess (Popen with
    byte caps under the no-fork boundary). A subprocess.run patch is never
    consulted there, and the real codesign then runs on the unsigned fixture."""

    def bounded(argv, _label, **kwargs):
        completed = run(list(argv), **kwargs)
        return subprocess.CompletedProcess(
            completed.args,
            completed.returncode,
            (completed.stdout or "").encode("utf-8"),
            (completed.stderr or "").encode("utf-8"),
        )

    return bounded


def _no_unfaked_tool(*args, **kwargs):
    raise AssertionError(f"a gate tool ran outside the faked funnel: {args!r}")


@contextlib.contextmanager
def _private_root():
    with tempfile.TemporaryDirectory(prefix="wins-apple-extract-hard-") as temporary:
        temp = pathlib.Path(temporary)
        root = temp / "private"
        root.mkdir(mode=0o700)
        private = apple_gate._prepare_private_root(root)
        token = apple_gate._PRIVATE_ROOT.set(private)
        try:
            yield private, temp
        finally:
            apple_gate._cleanup_private_root(private)
            apple_gate._PRIVATE_ROOT.reset(token)


class _SwappableReader:
    """A file object over the snapshot inode that reads `swapped` while active."""

    def __init__(self, real, swapped: bytes, active: list[bool]) -> None:
        self._real = real
        self._swapped = swapped
        self._active = active

    def read(self, size=-1):
        if not self._active[0]:
            return self._real.read(size)
        position = self._real.tell()
        end = len(self._swapped)
        if size is not None and size >= 0:
            end = min(end, position + size)
        payload = self._swapped[position:end]
        self._real.seek(position + len(payload))
        return payload

    def __getattr__(self, name):
        return getattr(self._real, name)


@contextlib.contextmanager
def _storage_swapped_snapshot(snapshot, swapped: bytes, active: list[bool]):
    """Serve `swapped` for every read of the snapshot inode while active[0].

    The snapshot custody (since ee48a2f) is an O_RDONLY descriptor on a 0400,
    UF_IMMUTABLE file in a sealed parent, so the test cannot write it, and any
    real write moves st_ctime and trips the identity check first. This models
    the case the digest recheck exists for: the bytes behind the inode change
    with no metadata change at all. Both read paths the gate uses see the
    swap: pread (digest) and the zip reader's file object (extraction)."""
    held = os.fstat(snapshot.fd)
    key = (held.st_dev, held.st_ino)
    real_pread = os.pread
    real_fdopen = os.fdopen

    def is_snapshot(fd) -> bool:
        info = os.fstat(fd)
        return (info.st_dev, info.st_ino) == key

    def pread(fd, length, offset):
        if active[0] and is_snapshot(fd):
            return swapped[offset : offset + length]
        return real_pread(fd, length, offset)

    def fdopen(fd, *args, **kwargs):
        handle = real_fdopen(fd, *args, **kwargs)
        if isinstance(fd, int) and is_snapshot(fd):
            return _SwappableReader(handle, swapped, active)
        return handle

    with mock.patch.object(apple_gate.os, "pread", side_effect=pread), (
        mock.patch.object(apple_gate.os, "fdopen", side_effect=fdopen)
    ):
        yield


class _FakePkgutil:
    def __init__(self) -> None:
        self.returncode: int | None = None
        self.pid = os.getpid()

    def wait(self, timeout=None):
        self.returncode = 0
        return 0

    def kill(self) -> None:
        return None


class AppleArchiveExtractionHardeningTests(unittest.TestCase):
    def _marker_files(self, root: pathlib.Path, marker: bytes) -> list[pathlib.Path]:
        found: list[pathlib.Path] = []
        if not root.exists():
            return found
        for path, _dirnames, filenames in os.walk(root, followlinks=False):
            directory = pathlib.Path(path)
            if directory.is_symlink():
                continue
            for name in filenames:
                candidate = directory / name
                if candidate.is_symlink():
                    continue
                try:
                    if candidate.read_bytes() == marker:
                        found.append(candidate)
                except OSError:
                    continue
        return found

    def test_zip_extract_refuses_intermediate_symlink_write(self) -> None:
        through = b"THROUGH-INTERMEDIATE-SYMLINK"
        with self.subTest(label="declared-zip-symlink-member"), tempfile.TemporaryDirectory(
            prefix="wins-apple-zip-symlink-declared-"
        ) as temporary:
            temp = pathlib.Path(temporary)
            archive_path = temp / "payload.zip"
            dest = temp / "dest"
            dest.mkdir(mode=0o700)
            archive_path.write_bytes(
                _zip_bytes(
                    [
                        ("Win's VPN.app/", b"", stat.S_IFDIR | 0o755),
                        ("link", b"Win's VPN.app", stat.S_IFLNK | 0o777),
                        ("link/Contents/Info.plist", through, stat.S_IFREG | 0o644),
                    ]
                )
            )
            error: BaseException | None = None
            with zipfile.ZipFile(archive_path) as archive:
                try:
                    members = apple_gate._safe_zip_members(archive)
                    apple_gate._extract_zip_members(archive, dest, members)
                except apple_gate.AppleArtifactGateError as exc:
                    error = exc
            followed = dest / "Win's VPN.app" / "Contents" / "Info.plist"
            wrote_through = followed.is_file() and followed.read_bytes() == through
            self.assertFalse(wrote_through)
            self.assertIsNotNone(error)
            self.assertRegex(str(error), r"symlink|intermediate|follow")
            self.assertEqual(self._marker_files(dest, through), [])

        with self.subTest(label="write-through-preexisting-intermediate"), tempfile.TemporaryDirectory(
            prefix="wins-apple-zip-symlink-planted-"
        ) as temporary:
            temp = pathlib.Path(temporary)
            dest = temp / "dest"
            dest.mkdir(mode=0o700)
            outside = temp / "outside"
            outside.mkdir(mode=0o700)
            (dest / "link").symlink_to(outside, target_is_directory=True)
            archive_path = temp / "payload.zip"
            archive_path.write_bytes(
                _zip_bytes(
                    [("link/pwned.bin", through, stat.S_IFREG | 0o644)]
                )
            )
            error = None
            with zipfile.ZipFile(archive_path) as archive:
                try:
                    members = apple_gate._safe_zip_members(archive)
                    apple_gate._extract_zip_members(archive, dest, members)
                except apple_gate.AppleArtifactGateError as exc:
                    error = exc
            escaped = outside / "pwned.bin"
            self.assertFalse(
                escaped.exists(),
                "zip extract wrote through a preexisting intermediate symlink",
            )
            self.assertIsNotNone(
                error,
                "zip extract accepted a write through an intermediate symlink",
            )
            self.assertRegex(str(error), r"symlink|intermediate|follow")
            self.assertEqual(self._marker_files(outside, through), [])
            self.assertEqual(self._marker_files(dest, through), [])

    def test_zip_crc_or_local_header_failure_never_publishes_final_name(self) -> None:
        central = "safe.app/Contents/Info.plist"
        local = "evil.app/Contents/Info.plist"
        self.assertEqual(len(central), len(local))
        raw = _zip_bytes(
            [
                ("safe-prefix.bin", b"must-not-publish", stat.S_IFREG | 0o644),
                (central, b"untrusted", stat.S_IFREG | 0o644),
            ]
        )
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            header_offset = archive.getinfo(central).header_offset
        divergent = _rewrite_local_filename(raw, header_offset, local)

        with tempfile.TemporaryDirectory(
            prefix="wins-apple-zip-unpublished-"
        ) as temporary:
            destination = pathlib.Path(temporary) / "destination"
            destination.mkdir(mode=0o700)
            with zipfile.ZipFile(io.BytesIO(divergent)) as archive:
                members = apple_gate._safe_zip_members(archive)
                with self.assertRaises((apple_gate.AppleArtifactGateError, zipfile.BadZipFile)):
                    apple_gate._extract_zip_members(archive, destination, members)
            self.assertFalse((destination / central).exists())
            self.assertFalse((destination / "safe-prefix.bin").exists())
            self.assertEqual(
                [path for path in destination.rglob("*") if path.is_file()],
                [],
                "failed ZIP member extraction published a named file",
            )

        crc_raw = _zip_bytes(
            [
                ("safe-prefix.bin", b"must-be-rolled-back", stat.S_IFREG | 0o644),
                ("crc-failure.bin", b"crc-protected", stat.S_IFREG | 0o644),
            ]
        )
        with zipfile.ZipFile(io.BytesIO(crc_raw)) as archive:
            bad = archive.getinfo("crc-failure.bin")
            local_name_len, local_extra_len = struct.unpack_from(
                "<HH", crc_raw, bad.header_offset + 26
            )
            data_offset = bad.header_offset + 30 + local_name_len + local_extra_len
        corrupted = bytearray(crc_raw)
        corrupted[data_offset] ^= 0x01
        with tempfile.TemporaryDirectory(
            prefix="wins-apple-zip-crc-rollback-"
        ) as temporary:
            destination = pathlib.Path(temporary) / "destination"
            destination.mkdir(mode=0o700)
            with zipfile.ZipFile(io.BytesIO(bytes(corrupted))) as archive:
                members = apple_gate._safe_zip_members(archive)
                with self.assertRaises((apple_gate.AppleArtifactGateError, zipfile.BadZipFile)):
                    apple_gate._extract_zip_members(archive, destination, members)
            self.assertEqual(
                [path for path in destination.rglob("*") if path.is_file()],
                [],
                "later CRC failure left an earlier published member",
            )

    def test_zip_depth_limit_refuses_before_creating_member_tree(self) -> None:
        name = "/".join(["level"] * (apple_gate.MAX_EXPANDED_DEPTH + 1)) + "/file"
        raw = _zip_bytes([(name, b"too-deep", stat.S_IFREG | 0o644)])
        with tempfile.TemporaryDirectory(prefix="wins-apple-zip-depth-") as temporary:
            destination = pathlib.Path(temporary) / "destination"
            destination.mkdir(mode=0o700)
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                with self.assertRaisesRegex(
                    apple_gate.AppleArtifactGateError, r"depth.*limit"
                ):
                    members = apple_gate._safe_zip_members(archive)
                    apple_gate._extract_zip_members(archive, destination, members)
            self.assertEqual(list(destination.iterdir()), [])

    def test_zip_final_tree_revalidation_rejects_unexpected_entry(self) -> None:
        raw = _zip_bytes(
            [("Payload/app.bin", b"expected", stat.S_IFREG | 0o644)]
        )
        with tempfile.TemporaryDirectory(
            prefix="wins-apple-zip-final-tree-"
        ) as temporary:
            destination = pathlib.Path(temporary) / "destination"
            (destination / "Payload").mkdir(parents=True)
            (destination / "Payload" / "app.bin").write_bytes(b"expected")
            (destination / "unexpected.bin").write_bytes(b"injected")
            destination_fd = os.open(
                destination, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            )
            try:
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    members = apple_gate._safe_zip_members(archive)
                    with self.assertRaisesRegex(
                        apple_gate.AppleArtifactGateError,
                        "authenticated member set",
                    ):
                        apple_gate._validate_extracted_zip_tree(
                            destination,
                            destination_fd,
                            members,
                            {
                                "Payload/app.bin": hashlib.sha256(
                                    b"expected"
                                ).hexdigest()
                            },
                        )
            finally:
                os.close(destination_fd)

    def test_zip_final_tree_revalidation_rejects_same_size_byte_swap(self) -> None:
        original = b"original"
        swapped = b"attacker"
        self.assertEqual(len(original), len(swapped))
        raw = _zip_bytes(
            [("Payload/app.bin", original, stat.S_IFREG | 0o644)]
        )
        with tempfile.TemporaryDirectory(
            prefix="wins-apple-zip-final-swap-"
        ) as temporary:
            destination = pathlib.Path(temporary) / "destination"
            (destination / "Payload").mkdir(parents=True)
            (destination / "Payload" / "app.bin").write_bytes(swapped)
            destination_fd = os.open(
                destination, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            )
            try:
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    members = apple_gate._safe_zip_members(archive)
                    with self.assertRaisesRegex(
                        apple_gate.AppleArtifactGateError,
                        "authenticated member",
                    ):
                        apple_gate._validate_extracted_zip_tree(
                            destination,
                            destination_fd,
                            members,
                            {
                                "Payload/app.bin": hashlib.sha256(
                                    original
                                ).hexdigest()
                            },
                        )
            finally:
                os.close(destination_fd)

    def test_cleanup_unlinks_private_hardlink_without_changing_external_mode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-apple-cleanup-hardlink-") as temporary:
            root = pathlib.Path(temporary)
            private = root / "private"
            private.mkdir(mode=0o700)
            victim = root / "victim"
            victim.write_bytes(b"external")
            victim.chmod(0o640)
            private_link = private / "linked"
            os.link(victim, private_link)
            directory_fd = os.open(private, os.O_RDONLY | os.O_DIRECTORY)
            try:
                apple_gate._cleanup_tree_fd(directory_fd)
            finally:
                os.close(directory_fd)
            self.assertFalse(private_link.exists())
            self.assertEqual(stat.S_IMODE(victim.stat().st_mode), 0o640)
            self.assertEqual(victim.read_bytes(), b"external")

    def test_hidden_temp_same_uid_replacement_cannot_rebind_held_inode(self) -> None:
        original = b"ORIGINAL-VERIFIED"
        replacement = b"REPLACED-AFTER-CRC"
        raw = _zip_bytes([("Payload/a.bin", original, stat.S_IFREG | 0o644)])
        with tempfile.TemporaryDirectory(
            prefix="wins-apple-zip-hidden-temp-race-"
        ) as temporary:
            root = pathlib.Path(temporary)
            destination = root / "destination"
            destination.mkdir(mode=0o700)
            victim = root / "victim"
            victim.write_bytes(replacement)
            victim.chmod(0o640)
            if hasattr(os, "chflags") and hasattr(stat, "UF_HIDDEN"):
                os.chflags(victim, stat.UF_HIDDEN)
            victim_before = os.lstat(victim)
            real_link = apple_gate.os.link

            def hostile_link(
                src,
                dst,
                *,
                src_dir_fd=None,
                dst_dir_fd=None,
                follow_symlinks=True,
            ):
                if dst == "a.bin" and dst_dir_fd is not None:
                    for name in os.listdir(dst_dir_fd):
                        if name.startswith(".") and name not in {".", ".."}:
                            try:
                                os.unlink(name, dir_fd=dst_dir_fd)
                            except FileNotFoundError:
                                pass
                            real_link(
                                os.fspath(victim),
                                name,
                                dst_dir_fd=dst_dir_fd,
                                follow_symlinks=False,
                            )
                return real_link(
                    src,
                    dst,
                    src_dir_fd=src_dir_fd,
                    dst_dir_fd=dst_dir_fd,
                    follow_symlinks=follow_symlinks,
                )

            with mock.patch.object(apple_gate.os, "link", side_effect=hostile_link):
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    members = apple_gate._safe_zip_members(archive)
                    try:
                        apple_gate._extract_zip_members(archive, destination, members)
                        published = True
                    except apple_gate.AppleArtifactGateError:
                        published = False

            named = destination / "Payload" / "a.bin"
            if published:
                self.assertEqual(named.read_bytes(), original)
            else:
                self.assertFalse(named.exists())
            self.assertEqual(self._marker_files(destination, replacement), [])
            victim_after = os.lstat(victim)
            self.assertEqual(victim.read_bytes(), replacement)
            self.assertEqual(stat.S_IMODE(victim_after.st_mode), 0o640)
            self.assertEqual(victim_after.st_nlink, 1)
            self.assertEqual(
                getattr(victim_after, "st_flags", 0),
                getattr(victim_before, "st_flags", 0),
            )
            self.assertEqual(
                (victim_after.st_dev, victim_after.st_ino),
                (victim_before.st_dev, victim_before.st_ino),
            )

    def test_hidden_temp_unlink_failure_removes_published_name(self) -> None:
        raw = _zip_bytes(
            [("Payload/a.bin", b"verified", stat.S_IFREG | 0o644)]
        )
        with tempfile.TemporaryDirectory(
            prefix="wins-apple-zip-hidden-temp-unlink-"
        ) as temporary:
            destination = pathlib.Path(temporary) / "destination"
            destination.mkdir(mode=0o700)
            real_unlink = apple_gate.os.unlink
            failed = False

            def hostile_unlink(path, *, dir_fd=None):
                nonlocal failed
                target = str(path)
                if not failed and (
                    target.startswith("/.vol/") or target.startswith(".")
                ):
                    failed = True
                    raise OSError(errno.EIO, "injected hidden-temp unlink failure")
                return real_unlink(path, dir_fd=dir_fd)

            with mock.patch.object(
                apple_gate.os, "unlink", side_effect=hostile_unlink
            ), zipfile.ZipFile(io.BytesIO(raw)) as archive:
                members = apple_gate._safe_zip_members(archive)
                with self.assertRaisesRegex(
                    apple_gate.AppleArtifactGateError,
                    "could not publish a verified member|could not be cleaned",
                ):
                    apple_gate._extract_zip_members(archive, destination, members)
            self.assertFalse((destination / "Payload" / "a.bin").exists())
            self.assertEqual(
                [path for path in destination.rglob("*") if path.is_file()], []
            )

    @unittest.skipUnless(
        DARWIN and hasattr(stat, "UF_IMMUTABLE"),
        "Darwin immutable-flag rollback",
    )
    def test_verified_inode_immutable_race_leaves_no_published_name(self) -> None:
        raw = _zip_bytes(
            [("Payload/a.bin", b"verified", stat.S_IFREG | 0o644)]
        )
        with tempfile.TemporaryDirectory(
            prefix="wins-apple-zip-immutable-held-"
        ) as temporary:
            destination = pathlib.Path(temporary) / "destination"
            destination.mkdir(mode=0o700)
            real_link = apple_gate.os.link

            def hostile_link(
                src,
                dst,
                *,
                src_dir_fd=None,
                dst_dir_fd=None,
                follow_symlinks=True,
            ):
                result = real_link(
                    src,
                    dst,
                    src_dir_fd=src_dir_fd,
                    dst_dir_fd=dst_dir_fd,
                    follow_symlinks=follow_symlinks,
                )
                if dst == "a.bin" and dst_dir_fd is not None:
                    planted_fd = os.open(
                        dst,
                        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=dst_dir_fd,
                    )
                    try:
                        apple_gate._fchflags(planted_fd, int(stat.UF_IMMUTABLE))
                    finally:
                        os.close(planted_fd)
                return result

            with mock.patch.object(
                apple_gate.os, "link", side_effect=hostile_link
            ), zipfile.ZipFile(io.BytesIO(raw)) as archive:
                members = apple_gate._safe_zip_members(archive)
                with self.assertRaises(apple_gate.AppleArtifactGateError):
                    apple_gate._extract_zip_members(archive, destination, members)
            self.assertEqual(
                [path for path in destination.rglob("*") if path.is_file()], []
            )

    @unittest.skipUnless(
        DARWIN and hasattr(stat, "UF_IMMUTABLE"),
        "Darwin immutable-flag rollback",
    )
    def test_immutable_foreign_final_is_not_mutated_by_publish_rollback(self) -> None:
        payload = b"foreign-final"
        raw = _zip_bytes(
            [("Payload/a.bin", b"verified", stat.S_IFREG | 0o644)]
        )
        with tempfile.TemporaryDirectory(
            prefix="wins-apple-zip-immutable-foreign-"
        ) as temporary:
            destination = pathlib.Path(temporary) / "destination"
            destination.mkdir(mode=0o700)
            real_link = apple_gate.os.link
            planted = False

            def hostile_link(
                src,
                dst,
                *,
                src_dir_fd=None,
                dst_dir_fd=None,
                follow_symlinks=True,
            ):
                nonlocal planted
                if not planted and dst == "a.bin" and dst_dir_fd is not None:
                    planted = True
                    planted_fd = os.open(
                        dst,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | os.O_CLOEXEC
                        | os.O_NOFOLLOW,
                        0o640,
                        dir_fd=dst_dir_fd,
                    )
                    try:
                        os.write(planted_fd, payload)
                        os.fchmod(planted_fd, 0o640)
                        apple_gate._fchflags(planted_fd, int(stat.UF_IMMUTABLE))
                    finally:
                        os.close(planted_fd)
                return real_link(
                    src,
                    dst,
                    src_dir_fd=src_dir_fd,
                    dst_dir_fd=dst_dir_fd,
                    follow_symlinks=follow_symlinks,
                )

            final = destination / "Payload" / "a.bin"
            try:
                with mock.patch.object(
                    apple_gate.os, "link", side_effect=hostile_link
                ), zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    members = apple_gate._safe_zip_members(archive)
                    with self.assertRaises(apple_gate.AppleArtifactGateError):
                        apple_gate._extract_zip_members(
                            archive, destination, members
                        )
                after = os.lstat(final)
                self.assertEqual(final.read_bytes(), payload)
                self.assertEqual(stat.S_IMODE(after.st_mode), 0o640)
                self.assertTrue(after.st_flags & int(stat.UF_IMMUTABLE))
                self.assertEqual(after.st_nlink, 1)
                hidden = [
                    path
                    for path in (destination / "Payload").iterdir()
                    if path.name.startswith(".")
                ]
                self.assertEqual(hidden, [])
            finally:
                if final.exists():
                    planted_fd = os.open(
                        final, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
                    )
                    try:
                        apple_gate._fchflags(planted_fd, 0)
                    finally:
                        os.close(planted_fd)
                    final.unlink()

    @unittest.skipUnless(DARWIN, "Apple snapshot identity uses /.vol")
    def test_zip_central_and_local_filename_divergence_is_refused_before_ditto(
        self,
    ) -> None:
        central = "safe.app/Contents/Info.plist"
        local = "evil.app/Contents/Info.plist"
        self.assertEqual(len(central), len(local))
        payload = b"central-policy-bytes"
        raw = _zip_bytes([(central, payload, stat.S_IFREG | 0o644)])
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            header_offset = archive.getinfo(central).header_offset
        divergent = _rewrite_local_filename(raw, header_offset, local)
        self.assertEqual(_local_header_names(divergent), [local])
        with zipfile.ZipFile(io.BytesIO(divergent)) as archive:
            self.assertEqual(archive.infolist()[0].filename, central)

        ditto_calls: list[list[str]] = []

        def run(argv, **kwargs):
            command = list(argv)
            if command and command[0] == "/usr/bin/ditto":
                ditto_calls.append(command)
            return subprocess.CompletedProcess(command, 0, "", "")

        for extractor, child in (
            (apple_gate._extract_app_zip, "app-zip"),
            (apple_gate._extract_zip, "ipa"),
        ):
            with self.subTest(extractor=extractor.__name__), _private_root() as (
                private,
                temp,
            ):
                source = temp / "divergent.app.zip"
                source.write_bytes(divergent)
                snapshot = apple_gate._snapshot_pkg(source, private.snapshot_file)
                destination = private.root / child
                error: BaseException | None = None
                try:
                    with mock.patch.object(
                        apple_gate.subprocess, "run", side_effect=run
                    ):
                        extractor(snapshot, destination)
                except apple_gate.AppleArtifactGateError as exc:
                    error = exc
                finally:
                    snapshot.close()
                self.assertEqual(
                    ditto_calls,
                    [],
                    "ditto ran before local/central filename agreement was enforced",
                )
                self.assertIsNotNone(
                    error,
                    f"{extractor.__name__} accepted central/local filename divergence",
                )
                self.assertRegex(
                    str(error),
                    r"header|filename|diverg|local|central|invalid Apple zip",
                    msg=str(error),
                )
                self.assertFalse((destination / "evil.app").exists())

    @unittest.skipUnless(DARWIN, "Apple snapshot identity uses /.vol")
    def test_outer_ipa_and_app_zip_codesign_is_refused_or_dispatched_to_inner_app(
        self,
    ) -> None:
        cases = (
            (
                "ios-app-store-ipa",
                "WinsVPN.ipa",
                [
                    (
                        "Payload/Win's VPN.app/Info.plist",
                        b"ios-inner",
                        stat.S_IFREG | 0o644,
                    ),
                    (
                        "Payload/Win's VPN.app/PlugIns/PacketTunnel.appex/Info.plist",
                        b"ios-tunnel",
                        stat.S_IFREG | 0o644,
                    ),
                    (
                        "Payload/Win's VPN.app/Watch/WinsWatch.app/Info.plist",
                        b"ios-watch",
                        stat.S_IFREG | 0o644,
                    ),
                    (
                        "Payload/Win's VPN.app/Frameworks/App.framework/App",
                        b"ios-aot",
                        stat.S_IFREG | 0o644,
                    ),
                ],
                APPLE_DISTRIBUTION,
            ),
            (
                "macos-developer-id-app",
                "WinsVPN.app.zip",
                [
                    (
                        "Win's VPN.app/Contents/Info.plist",
                        b"mac-inner",
                        stat.S_IFREG | 0o644,
                    ),
                    (
                        "Win's VPN.app/Contents/PlugIns/PacketTunnel.appex/Contents/Info.plist",
                        b"mac-tunnel",
                        stat.S_IFREG | 0o644,
                    ),
                    (
                        "Win's VPN.app/Contents/Frameworks/App.framework/App",
                        b"mac-aot",
                        stat.S_IFREG | 0o644,
                    ),
                ],
                DEVELOPER_ID,
            ),
        )
        for target_id, filename, entries, identity in cases:
            with self.subTest(target_id=target_id, phase="dispatch"):
                kinds = self._run_signature_codesign(
                    target_id,
                    filename,
                    entries,
                    identity,
                    inner_signed=True,
                )
                self.assertNotIn(
                    "wrapper",
                    kinds,
                    f"{target_id}: codesign inspected the outer archive {kinds}",
                )
                self.assertIn(
                    "directory",
                    kinds,
                    f"{target_id}: inner-app codesign was never dispatched ({kinds})",
                )
            with self.subTest(target_id=target_id, phase="wrapper-signed-inner-unsigned"):
                error: BaseException | None = None
                kinds = []
                try:
                    self._run_signature_codesign(
                        target_id,
                        filename,
                        entries,
                        identity,
                        inner_signed=False,
                        kinds=kinds,
                    )
                except apple_gate.AppleArtifactGateError as exc:
                    error = exc
                self.assertIsNotNone(
                    error,
                    f"{target_id}: wrapper-file codesign must not pass an unsigned inner app",
                )
                self.assertNotIn("wrapper", kinds)
                self.assertNotRegex(str(error), r"owner/environment blocker")

    def _run_signature_codesign(
        self,
        target_id: str,
        filename: str,
        entries: list[tuple[str, bytes, int]],
        identity: str,
        *,
        inner_signed: bool,
        kinds: list[str] | None = None,
    ) -> list[str]:
        # A caller-owned list keeps the codesign targets seen before a refusal.
        kinds = [] if kinds is None else kinds

        def run(argv, **kwargs):
            command = list(argv)
            if command and command[0] == "/usr/bin/ditto":
                with zipfile.ZipFile(command[-2]) as archive:
                    archive.extractall(command[-1])
                return subprocess.CompletedProcess(command, 0, "", "")
            if command and command[0] == "/usr/bin/codesign":
                target = command[-1]
                kind = _codesign_target_kind(target)
                kinds.append(kind)
                if kind == "wrapper":
                    if "--verify" in command:
                        return subprocess.CompletedProcess(command, 0, "", "")
                    return subprocess.CompletedProcess(command, 0, "", identity)
                if not inner_signed:
                    return subprocess.CompletedProcess(
                        command,
                        1,
                        "",
                        "code object is not signed at all\n",
                    )
                if "--verify" in command:
                    return subprocess.CompletedProcess(command, 0, "", "")
                return subprocess.CompletedProcess(command, 0, "", identity)
            if command and command[0] == "/usr/sbin/spctl":
                return subprocess.CompletedProcess(
                    command, 0, "", "source=Notarized Developer ID\n"
                )
            return subprocess.CompletedProcess(command, 0, "", "")

        with tempfile.TemporaryDirectory(prefix="wins-apple-codesign-hard-") as temporary:
            repo = pathlib.Path(temporary)
            artifacts = repo / "artifacts"
            artifacts.mkdir()
            artifact = artifacts / filename
            artifact.write_bytes(_zip_bytes(entries))
            relative = f"artifacts/{filename}"
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            size = artifact.stat().st_size
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(apple_gate, "ROOT", repo))
                stack.enter_context(
                    mock.patch.object(
                        apple_gate.source_freeze,
                        "verified_release_source_state",
                        side_effect=AssertionError(
                            "gate consulted the source-freeze trust file"
                        ),
                    )
                )
                stack.enter_context(mock.patch.object(apple_gate, "_verify_bundle"))
                stack.enter_context(
                    mock.patch.object(
                        apple_gate, "reject_packaged_native_messaging_host"
                    )
                )
                stack.enter_context(
                    mock.patch.object(apple_gate, "_assess_notarization")
                )
                stack.enter_context(
                    mock.patch.object(
                        apple_gate,
                        "_bounded_subprocess",
                        side_effect=_bounded_tool_fake(run),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        apple_gate.subprocess, "Popen", side_effect=_no_unfaked_tool
                    )
                )
                apple_gate.verify_signature(target_id, relative)
                # The receipt path also runs the reviewed Watch verifier on an
                # IPA; that verifier has its own suites and is not the property
                # here, so its custody and result are fixed for this call only.
                watch_evidence = {"fixture": "watch-verifier-not-under-test"}
                held = apple_gate._HeldLiveRepoFile(
                    relative,
                    f"{target_id} artifact",
                    max_bytes=apple_gate.MAX_PKG_BYTES,
                )
                stack.callback(held.close, verify=False)
                with contextlib.ExitStack() as receipt_stack:
                    receipt_stack.enter_context(
                        mock.patch.object(apple_gate, "_HeldSupportSources")
                    )
                    receipt_stack.enter_context(
                        mock.patch.object(
                            apple_gate,
                            "_validate_held_artifact_review_custody",
                            return_value={
                                "apple_watch_artifact_verifier.py": "0" * 64
                            },
                        )
                    )
                    receipt_stack.enter_context(
                        mock.patch.object(
                            apple_gate,
                            "verify_watch_artifact_snapshot",
                            return_value=dict(watch_evidence),
                        )
                    )
                    apple_gate._require_owner_issued_apple_signature(
                        target_id,
                        relative,
                        expected_sha256=digest,
                        expected_bytes=size,
                        expected_watch_verification=(
                            dict(watch_evidence)
                            if target_id == "ios-app-store-ipa"
                            else None
                        ),
                        held_artifact=held,
                    )
        return kinds

    @unittest.skipUnless(DARWIN, "Apple snapshot identity uses /.vol")
    def test_artifact_pathname_swap_cannot_rebind_authenticated_ipa(self) -> None:
        original_marker = b"AUTHENTICATED-IPA-BYTES"
        swapped_marker = b"SWAPPED-PATHNAME-BYTES"
        with _private_root() as (private, temp):
            repo = temp / "repo"
            artifacts = repo / "artifacts"
            artifacts.mkdir(parents=True)
            artifact = artifacts / "WinsVPN.ipa"
            artifact.write_bytes(
                _zip_bytes(
                    [
                        (
                            "Payload/Win's VPN.app/original.bin",
                            original_marker,
                            stat.S_IFREG | 0o644,
                        )
                    ]
                )
            )
            with mock.patch.object(apple_gate, "ROOT", repo):
                _lexical, snapshot = apple_gate._snapshot_canonical_artifact(
                    "ios-app-store-ipa",
                    "artifacts/WinsVPN.ipa",
                    private.snapshot_file,
                )
                artifact.unlink()
                artifact.write_bytes(
                    _zip_bytes(
                        [
                            (
                                "Payload/Win's VPN.app/swapped.bin",
                                swapped_marker,
                                stat.S_IFREG | 0o644,
                            )
                        ]
                    )
                )
                destination = private.root / "ipa"
                try:
                    apple_gate._extract_zip(snapshot, destination)
                finally:
                    snapshot.close()
            self.assertEqual(
                (destination / "Payload/Win's VPN.app/original.bin").read_bytes(),
                original_marker,
            )
            self.assertFalse(
                (destination / "Payload/Win's VPN.app/swapped.bin").exists()
            )

    @unittest.skipUnless(DARWIN, "Apple snapshot identity uses /.vol")
    def test_snapshot_digest_swap_cannot_rebind_extraction(self) -> None:
        original_marker = b"ORIGINAL-SNAPSHOT-BYTES"
        swapped_marker = b"SWAPPED-SNAPSHOT-BYTES!"
        original = _zip_bytes(
            [("Payload/a.bin", original_marker, stat.S_IFREG | 0o644)]
        )
        swapped = _zip_bytes(
            [("Payload/a.bin", swapped_marker, stat.S_IFREG | 0o644)]
        )
        size = max(len(original), len(swapped))
        original = _pad_zip(original, size)
        swapped = _pad_zip(swapped, size)
        self.assertEqual(len(original), len(swapped))
        self.assertNotEqual(
            hashlib.sha256(original).hexdigest(),
            hashlib.sha256(swapped).hexdigest(),
        )

        with self.subTest(path="ipa-extract"), _private_root() as (private, temp):
            source = temp / "original.ipa"
            source.write_bytes(original)
            snapshot = apple_gate._snapshot_pkg(source, private.snapshot_file)
            destination = private.root / "ipa"
            with self.assertRaises(OSError):
                os.pwrite(snapshot.fd, swapped, 0)
            active = [True]
            error: BaseException | None = None
            try:
                with _storage_swapped_snapshot(snapshot, swapped, active):
                    live = apple_gate._sha256_fd(snapshot.fd, snapshot.size)
                    self.assertEqual(live, hashlib.sha256(swapped).hexdigest())
                    self.assertNotEqual(live, snapshot.digest)
                    snapshot.ensure_bound()
                    apple_gate._extract_zip(snapshot, destination)
            except apple_gate.AppleArtifactGateError as exc:
                error = exc
            finally:
                snapshot.close()
            self.assertIsNotNone(error, "IPA extract accepted a swapped snapshot digest")
            self.assertRegex(
                str(error),
                r"digest changed|digest mismatch|mutated|swapped",
                msg=str(error),
            )
            self.assertEqual(self._marker_files(destination, swapped_marker), [])

        with self.subTest(path="app-zip-after-cd-policy"), _private_root() as (
            private,
            temp,
        ):
            source = temp / "original.app.zip"
            source.write_bytes(original)
            snapshot = apple_gate._snapshot_pkg(source, private.snapshot_file)
            destination = private.root / "app-zip"
            real_safe = apple_gate._safe_zip_members
            active = [False]
            swap_points: list[str] = []

            def safe_then_swap(archive):
                members = real_safe(archive)
                active[0] = True
                swap_points.append("after-cd-policy")
                return members

            error = None
            try:
                with _storage_swapped_snapshot(snapshot, swapped, active), (
                    mock.patch.object(
                        apple_gate, "_safe_zip_members", side_effect=safe_then_swap
                    )
                ):
                    apple_gate._extract_app_zip(snapshot, destination)
            except apple_gate.AppleArtifactGateError as exc:
                error = exc
            finally:
                snapshot.close()
            self.assertEqual(swap_points, ["after-cd-policy"])
            self.assertIsNotNone(
                error,
                "Developer ID extract accepted a snapshot digest swap after CD policy",
            )
            self.assertRegex(
                str(error),
                r"digest changed|digest mismatch|mutated|swapped",
                msg=str(error),
            )
            self.assertEqual(self._marker_files(destination, swapped_marker), [])

    @unittest.skipUnless(DARWIN, "Apple snapshot identity uses /.vol")
    def test_pkgutil_expand_destination_is_inode_bound(self) -> None:
        expand_calls: list[list[str]] = []
        with _private_root() as (private, temp):
            source = temp / "fixture.pkg"
            source.write_bytes(b"synthetic-pkg-bytes" + (b"\x00" * 256))
            outside = temp / "outside"
            outside.mkdir(mode=0o700)
            destination = private.root / "expanded"
            snapshot = apple_gate._snapshot_pkg(source, private.snapshot_file)

            def popen(argv, **kwargs):
                # The gate (since ee48a2f) runs pkgutil under the fixed no-fork
                # boundary; require that exact prefix, then check pkgutil's argv.
                boundary = [
                    apple_gate.MACOS_DESCENDANT_BOUNDARY,
                    "-p",
                    apple_gate.MACOS_DESCENDANT_BOUNDARY_PROFILE,
                ]
                self.assertEqual(list(argv)[:3], boundary)
                command = list(argv)[3:]
                expand_calls.append(command)
                self.assertEqual(command[:2], ["/usr/sbin/pkgutil", "--expand-full"])
                dest = command[-1]
                bound_inode = False
                if dest.startswith("/.vol/"):
                    try:
                        info = os.lstat(dest)
                        bound_inode = (
                            stat.S_ISDIR(info.st_mode)
                            and not stat.S_ISLNK(info.st_mode)
                            and len(pathlib.PurePosixPath(dest).parts) == 4
                        )
                    except OSError:
                        bound_inode = False
                if not bound_inode:
                    if destination.exists() or destination.is_symlink():
                        if destination.is_symlink() or destination.is_file():
                            destination.unlink()
                        elif destination.is_dir() and not any(destination.iterdir()):
                            destination.rmdir()
                    if not destination.exists():
                        destination.symlink_to(outside, target_is_directory=True)
                    (outside / "pwned.bin").write_bytes(b"ESCAPED-PKGUTIL-DEST")
                return _FakePkgutil()

            error: BaseException | None = None
            try:
                with mock.patch.object(
                    apple_gate.subprocess, "Popen", side_effect=popen
                ):
                    apple_gate._run_pkgutil_expand(snapshot, destination)
            except apple_gate.AppleArtifactGateError as exc:
                error = exc
            finally:
                snapshot.close()
            dest_args = [command[-1] for command in expand_calls]
            defects: list[str] = []
            if not expand_calls:
                defects.append("pkgutil --expand-full was not invoked")
            if (outside / "pwned.bin").exists():
                defects.append("pkgutil expand wrote through an unbound destination name")
            for argument in dest_args:
                parts = pathlib.PurePosixPath(argument).parts
                if not argument.startswith("/.vol/"):
                    defects.append(f"destination is not volfs: {argument}")
                    continue
                if argument == str(destination):
                    defects.append(f"destination reused the lexical path: {argument}")
                if len(parts) != 4:
                    defects.append(
                        "destination is a parent volfs path plus name, not a dest inode: "
                        f"{argument}"
                    )
                    continue
                try:
                    info = os.lstat(argument)
                except OSError as exc:
                    defects.append(f"destination inode is not bound: {argument} ({exc})")
                    continue
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                    defects.append(f"destination inode is not a directory: {argument}")
            self.assertEqual(defects, [], msg=f"error={error!r}")

    def test_pkgutil_stderr_flood_and_invalid_utf8_fail_controlled(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="wins-apple-pkgutil-output-"
        ) as temporary:
            destination = pathlib.Path(temporary) / "expanded"
            destination.mkdir(mode=0o700)
            destination_fd = os.open(
                destination, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            )
            identity = apple_gate._vnode_identity(
                os.fstat(destination_fd), directory=True
            )
            try:
                for label, payload, pattern in (
                    (
                        "flood",
                        b"x" * (apple_gate.MAX_TOOL_OUTPUT_BYTES + 1),
                        "output bound",
                    ),
                    ("invalid-utf8", b"\xff", "invalid UTF-8"),
                ):
                    with self.subTest(label=label), tempfile.TemporaryFile() as stderr:
                        def popen(_argv, **kwargs):
                            os.write(kwargs["stderr"], payload)
                            return _FakePkgutil()

                        with mock.patch.object(
                            apple_gate.subprocess, "Popen", side_effect=popen
                        ), self.assertRaisesRegex(
                            apple_gate.AppleArtifactGateError, pattern
                        ):
                            apple_gate._spawn_pkgutil_expand(
                                [
                                    "/usr/sbin/pkgutil",
                                    "--expand-full",
                                    "package",
                                    "destination",
                                ],
                                stderr.fileno(),
                                destination_fd,
                                identity,
                                apple_gate.MAX_OUTPUT_BYTES,
                            )
            finally:
                os.close(destination_fd)

    def test_descriptor_bound_publish_does_not_use_at_empty_path(self) -> None:
        self.assertFalse(bool(getattr(os, "AT_EMPTY_PATH", 0)))
        raw = _zip_bytes([("Payload/a.bin", b"held-bytes", stat.S_IFREG | 0o644)])
        with tempfile.TemporaryDirectory(
            prefix="wins-apple-zip-volfs-publish-"
        ) as temporary:
            destination = pathlib.Path(temporary) / "destination"
            destination.mkdir(mode=0o700)
            sources: list[str] = []
            real_link = apple_gate.os.link

            def record_link(
                src,
                dst,
                *,
                src_dir_fd=None,
                dst_dir_fd=None,
                follow_symlinks=True,
            ):
                sources.append(str(src))
                return real_link(
                    src,
                    dst,
                    src_dir_fd=src_dir_fd,
                    dst_dir_fd=dst_dir_fd,
                    follow_symlinks=follow_symlinks,
                )

            with mock.patch.object(
                apple_gate.os, "link", side_effect=record_link
            ), zipfile.ZipFile(io.BytesIO(raw)) as archive:
                members = apple_gate._safe_zip_members(archive)
                apple_gate._extract_zip_members(archive, destination, members)
            published = destination / "Payload" / "a.bin"
            self.assertEqual(published.read_bytes(), b"held-bytes")
            if DARWIN:
                self.assertTrue(
                    any(src.startswith("/.vol/") for src in sources),
                    msg=sources,
                )
            self.assertFalse(any(src == "" for src in sources))

    def test_identity_safe_unlink_does_not_delete_swapped_foreign_name(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="wins-apple-unlink-foreign-"
        ) as temporary:
            root = pathlib.Path(temporary)
            verified = root / "verified"
            foreign = root / "foreign"
            verified.write_bytes(b"verified-inode")
            foreign.write_bytes(b"foreign-inode")
            parent_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                held_fd = os.open(
                    "verified",
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=parent_fd,
                )
                try:
                    held = os.fstat(held_fd)
                    os.rename(
                        "verified",
                        "verified.moved",
                        src_dir_fd=parent_fd,
                        dst_dir_fd=parent_fd,
                    )
                    os.rename(
                        "foreign",
                        "verified",
                        src_dir_fd=parent_fd,
                        dst_dir_fd=parent_fd,
                    )
                    with self.assertRaisesRegex(
                        apple_gate.AppleArtifactGateError, "substituted name"
                    ):
                        apple_gate._identity_safe_unlink(
                            parent_fd,
                            "verified",
                            (held.st_dev, held.st_ino),
                            held_fd,
                        )
                    restored = os.lstat("verified", dir_fd=parent_fd)
                    self.assertEqual((root / "verified").read_bytes(), b"foreign-inode")
                    self.assertNotEqual(
                        (restored.st_dev, restored.st_ino),
                        (held.st_dev, held.st_ino),
                    )
                    self.assertTrue((root / "verified.moved").exists())
                    self.assertEqual(
                        (root / "verified.moved").read_bytes(), b"verified-inode"
                    )
                finally:
                    os.close(held_fd)
            finally:
                os.close(parent_fd)

    @unittest.skipUnless(DARWIN, "Apple codesign tree identity uses a sealed inspect path")
    def test_codesign_rename_restore_during_verify_fails_closed(self) -> None:
        ipa = None
        with tempfile.TemporaryDirectory(prefix="wins-apple-codesign-swap-") as temporary:
            repo = pathlib.Path(temporary)
            artifacts = repo / "artifacts"
            artifacts.mkdir()
            ipa = artifacts / "WinsVPN.ipa"
            inner = (
                "Payload/Win's VPN.app/Frameworks/App.framework/App",
                b"ORIGINAL-INNER",
                stat.S_IFREG | 0o644,
            )
            ipa.write_bytes(
                _zip_bytes(
                    [
                        (
                            "Payload/Win's VPN.app/Info.plist",
                            b"host",
                            stat.S_IFREG | 0o644,
                        ),
                        (
                            "Payload/Win's VPN.app/PlugIns/PacketTunnel.appex/Info.plist",
                            b"tunnel",
                            stat.S_IFREG | 0o644,
                        ),
                        (
                            "Payload/Win's VPN.app/Watch/WinsWatch.app/Info.plist",
                            b"watch",
                            stat.S_IFREG | 0o644,
                        ),
                        inner,
                    ]
                )
            )
            swapped = False

            def run(argv, **kwargs):
                nonlocal swapped
                command = list(argv)
                if command and command[0] == "/usr/bin/ditto":
                    with zipfile.ZipFile(command[-2]) as archive:
                        archive.extractall(command[-1])
                    return subprocess.CompletedProcess(command, 0, "", "")
                if command and command[0] == "/usr/bin/codesign" and "--verify" in command:
                    self.assertFalse(command[-1].startswith("/.vol/"), msg=command)
                    apple_gate._codesign_requirement_from_argv(command)
                    if not swapped:
                        swapped = True
                        app = pathlib.Path(command[-1])
                        payload = app / "Frameworks" / "App.framework" / "App"
                        if not payload.is_file():
                            matches = [
                                path
                                for path in app.rglob("App")
                                if path.is_file() and not path.is_symlink()
                            ]
                            self.assertTrue(matches, msg=list(app.rglob("*")))
                            payload = matches[0]
                        opened = os.open(
                            payload, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
                        )
                        try:
                            apple_gate._clear_held_unlink_blocking_flags(opened)
                            os.fchmod(opened, 0o600)
                        finally:
                            os.close(opened)
                        original = payload.read_bytes()
                        payload.write_bytes(b"SWAPPED-MALWARE")
                        payload.write_bytes(original)
                    return subprocess.CompletedProcess(command, 0, "", "")
                if command and command[0] == "/usr/bin/codesign" and "-d" in command:
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        "",
                        APPLE_DISTRIBUTION,
                    )
                return subprocess.CompletedProcess(command, 0, "", "")

            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(apple_gate, "ROOT", repo))
                stack.enter_context(
                    mock.patch.object(
                        apple_gate.source_freeze,
                        "verified_release_source_state",
                        side_effect=AssertionError(
                            "gate consulted the source-freeze trust file"
                        ),
                    )
                )
                stack.enter_context(mock.patch.object(apple_gate, "_verify_bundle"))
                stack.enter_context(
                    mock.patch.object(
                        apple_gate,
                        "_bounded_subprocess",
                        side_effect=_bounded_tool_fake(run),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        apple_gate.subprocess, "Popen", side_effect=_no_unfaked_tool
                    )
                )
                with self.assertRaisesRegex(
                    apple_gate.AppleArtifactGateError,
                    "tree was replaced|execution target",
                ):
                    apple_gate.verify_signature(
                        "ios-app-store-ipa", "artifacts/WinsVPN.ipa"
                    )

    @unittest.skipUnless(DARWIN, "identity unlink uses Darwin volfs")
    def test_identity_safe_unlink_hook_swap_does_not_delete_foreign_victim(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-apple-unlink-race-") as temporary:
            root = pathlib.Path(temporary)
            verified = root / "verified"
            foreign = root / "foreign"
            verified.write_bytes(b"verified-inode")
            foreign.write_bytes(b"foreign-inode")
            parent_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                held_fd = os.open(
                    "verified",
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=parent_fd,
                )
                try:
                    held = os.fstat(held_fd)
                    real_unlink = apple_gate.os.unlink

                    def racing_unlink(name, *, dir_fd=None):
                        if str(name).startswith("/.vol/"):
                            for qdir in os.listdir(parent_fd):
                                if not qdir.startswith(apple_gate.QUARANTINE_NAME_PREFIX):
                                    continue
                                qfd = os.open(
                                    qdir,
                                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
                                    dir_fd=parent_fd,
                                )
                                try:
                                    try:
                                        apple_gate._clear_held_unlink_blocking_flags(qfd)
                                    except Exception:
                                        pass
                                    os.rename(
                                        apple_gate.QUARANTINE_HELD_NAME,
                                        "quarantine.stolen",
                                        src_dir_fd=qfd,
                                        dst_dir_fd=parent_fd,
                                    )
                                    os.rename(
                                        "foreign",
                                        apple_gate.QUARANTINE_HELD_NAME,
                                        src_dir_fd=parent_fd,
                                        dst_dir_fd=qfd,
                                    )
                                finally:
                                    os.close(qfd)
                        return real_unlink(name, dir_fd=dir_fd)

                    with mock.patch.object(
                        apple_gate.os, "unlink", side_effect=racing_unlink
                    ):
                        try:
                            apple_gate._identity_safe_unlink(
                                parent_fd,
                                "verified",
                                (held.st_dev, held.st_ino),
                                held_fd,
                            )
                        except apple_gate.AppleArtifactGateError:
                            pass
                    remaining = []
                    for current, _dirs, files in os.walk(root):
                        for name in files:
                            remaining.append((pathlib.Path(current) / name).read_bytes())
                    self.assertIn(b"foreign-inode", remaining)
                    os.fstat(held_fd)
                finally:
                    os.close(held_fd)
            finally:
                os.close(parent_fd)

    @unittest.skipUnless(DARWIN, "UF_IMMUTABLE framework unseal")
    def test_immutable_framework_symlink_tree_unseals(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-apple-immut-fw-") as temporary:
            root = pathlib.Path(temporary) / "app"
            framework = root / "Frameworks" / "Foo.framework"
            version = framework / "Versions" / "A"
            version.mkdir(parents=True)
            (version / "Foo").write_bytes(b"dylib")
            os.symlink("Versions/A/Foo", framework / "Foo")
            os.symlink("A", framework / "Versions" / "Current")
            apple_gate._lock_tree(root)
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                apple_gate._cleanup_tree_fd(directory_fd)
                self.assertFalse((framework / "Foo").exists())
                self.assertFalse((framework / "Versions" / "Current").exists())
                os.unlink(version / "Foo")
            finally:
                os.close(directory_fd)


if __name__ == "__main__":
    unittest.main()
