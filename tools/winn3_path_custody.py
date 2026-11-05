#!/usr/bin/env python3
"""Retain filesystem custody for Windows Winn v3 release inputs.

The public open functions reject relative, non-normalized, linked, empty, and
oversized inputs. On POSIX, every component is opened relative to its retained
parent descriptor with O_NOFOLLOW. On Windows, every component is opened
relative to its retained parent handle with NtCreateFile and
FILE_OPEN_REPARSE_POINT, so symbolic links, junctions, and other reparse points
are inspected rather than traversed.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat
from typing import Iterator


CHUNK_BYTES = 1024 * 1024
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
TRUSTED_WINDOWS_OWNER_SIDS = frozenset({"S-1-5-18", "S-1-5-32-544"})
WINDOWS_WRITE_MASK = (
    0x10000000
    | 0x40000000
    | 0x00010000
    | 0x00040000
    | 0x00080000
    | 0x00000002
    | 0x00000004
    | 0x00000010
    | 0x00000040
    | 0x00000100
)


class CustodyError(RuntimeError):
    """A path could not be held without link or substitution ambiguity."""


@dataclass(frozen=True)
class FileIdentity:
    """Security-relevant identity captured from an open descriptor or handle."""

    platform: str
    device: int
    file_id: int
    mode: int
    uid: int
    gid: int
    nlink: int
    size: int
    mtime_ns: int
    ctime_ns: int
    attributes: int = 0

    def stable_directory_key(self) -> tuple[object, ...]:
        """Return fields that must not change while directory contents mutate."""

        return (
            self.platform,
            self.device,
            self.file_id,
            stat.S_IFMT(self.mode),
            self.mode & 0o7777,
            self.uid,
            self.gid,
            self.attributes,
        )


@dataclass(frozen=True)
class _Relation:
    parent: int
    name: str
    identity: FileIdentity


def _normalized_absolute(path: Path | str, label: str) -> Path:
    raw = os.fspath(path)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise CustodyError(f"refusal:path-invalid:{label}")
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise CustodyError(f"refusal:path-not-absolute:{label}")
    normalized = Path(os.path.normpath(raw))
    if normalized != candidate:
        raise CustodyError(f"refusal:path-not-normalized:{label}")
    if not normalized.anchor or normalized.name in {".", ".."}:
        raise CustodyError(f"refusal:path-invalid:{label}")
    return normalized


def _component(name: str, label: str) -> str:
    if not name or name in {".", ".."} or "/" in name or "\\" in name or "\x00" in name:
        raise CustodyError(f"refusal:path-component-invalid:{label}")
    return name


def _posix_identity(info: os.stat_result) -> FileIdentity:
    return FileIdentity(
        platform="posix",
        device=info.st_dev,
        file_id=info.st_ino,
        mode=info.st_mode,
        uid=info.st_uid,
        gid=info.st_gid,
        nlink=info.st_nlink,
        size=info.st_size,
        mtime_ns=info.st_mtime_ns,
        ctime_ns=info.st_ctime_ns,
    )


class _WindowsApi:
    """Small fixed-function Windows handle API, loaded only on Windows."""

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        self.ctypes = ctypes
        self.wintypes = wintypes
        self.INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.ntdll = ctypes.WinDLL("ntdll")
        self.advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

        class FILETIME(ctypes.Structure):
            _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

        class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("attributes", wintypes.DWORD),
                ("creation", FILETIME),
                ("last_access", FILETIME),
                ("last_write", FILETIME),
                ("volume_serial", wintypes.DWORD),
                ("size_high", wintypes.DWORD),
                ("size_low", wintypes.DWORD),
                ("links", wintypes.DWORD),
                ("index_high", wintypes.DWORD),
                ("index_low", wintypes.DWORD),
            ]

        class UNICODE_STRING(ctypes.Structure):
            _fields_ = [
                ("Length", wintypes.USHORT),
                ("MaximumLength", wintypes.USHORT),
                ("Buffer", wintypes.LPWSTR),
            ]

        class OBJECT_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("Length", wintypes.ULONG),
                ("RootDirectory", wintypes.HANDLE),
                ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
                ("Attributes", wintypes.ULONG),
                ("SecurityDescriptor", wintypes.LPVOID),
                ("SecurityQualityOfService", wintypes.LPVOID),
            ]

        class IO_STATUS_BLOCK(ctypes.Structure):
            _fields_ = [("Status", ctypes.c_void_p), ("Information", ctypes.c_size_t)]

        class ACL_SIZE_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("AceCount", wintypes.DWORD),
                ("AclBytesInUse", wintypes.DWORD),
                ("AclBytesFree", wintypes.DWORD),
            ]

        class ACE_HEADER(ctypes.Structure):
            _fields_ = [
                ("AceType", ctypes.c_ubyte),
                ("AceFlags", ctypes.c_ubyte),
                ("AceSize", wintypes.USHORT),
            ]

        class FILE_DISPOSITION_INFO(ctypes.Structure):
            _fields_ = [("DeleteFile", wintypes.BOOL)]

        self.FILETIME = FILETIME
        self.FILE_INFO = BY_HANDLE_FILE_INFORMATION
        self.UNICODE_STRING = UNICODE_STRING
        self.OBJECT_ATTRIBUTES = OBJECT_ATTRIBUTES
        self.IO_STATUS_BLOCK = IO_STATUS_BLOCK
        self.ACL_SIZE_INFORMATION = ACL_SIZE_INFORMATION
        self.ACE_HEADER = ACE_HEADER
        self.FILE_DISPOSITION_INFO = FILE_DISPOSITION_INFO

        self.kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        self.kernel32.CreateFileW.restype = wintypes.HANDLE
        self.kernel32.GetFileInformationByHandle.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(BY_HANDLE_FILE_INFORMATION),
        ]
        self.kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
        self.kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
        self.kernel32.FlushFileBuffers.restype = wintypes.BOOL
        self.kernel32.SetFileInformationByHandle.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
        ]
        self.kernel32.SetFileInformationByHandle.restype = wintypes.BOOL
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = wintypes.BOOL
        self.ntdll.NtCreateFile.argtypes = [
            ctypes.POINTER(wintypes.HANDLE),
            wintypes.ULONG,
            ctypes.POINTER(OBJECT_ATTRIBUTES),
            ctypes.POINTER(IO_STATUS_BLOCK),
            ctypes.POINTER(ctypes.c_longlong),
            wintypes.ULONG,
            wintypes.ULONG,
            wintypes.ULONG,
            wintypes.ULONG,
            wintypes.LPVOID,
            wintypes.ULONG,
        ]
        self.ntdll.NtCreateFile.restype = ctypes.c_long
        self.ntdll.RtlNtStatusToDosError.argtypes = [ctypes.c_long]
        self.ntdll.RtlNtStatusToDosError.restype = wintypes.ULONG
        self.advapi32.GetSecurityInfo.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self.advapi32.GetSecurityInfo.restype = wintypes.DWORD
        self.advapi32.GetSecurityDescriptorControl.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.USHORT),
            ctypes.POINTER(wintypes.DWORD),
        ]
        self.advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
        self.advapi32.GetAclInformation.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        self.advapi32.GetAclInformation.restype = wintypes.BOOL
        self.advapi32.GetAce.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self.advapi32.GetAce.restype = wintypes.BOOL
        self.advapi32.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.LPWSTR),
        ]
        self.advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
        self.kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        self.kernel32.LocalFree.restype = ctypes.c_void_p

    @staticmethod
    def _filetime(value: object) -> int:
        return (int(getattr(value, "high")) << 32) | int(getattr(value, "low"))

    def close(self, handle: int) -> None:
        if handle and handle != self.INVALID_HANDLE_VALUE:
            self.kernel32.CloseHandle(self.wintypes.HANDLE(handle))

    def identity(self, handle: int) -> FileIdentity:
        info = self.FILE_INFO()
        if not self.kernel32.GetFileInformationByHandle(
            self.wintypes.HANDLE(handle), self.ctypes.byref(info)
        ):
            error = self.ctypes.get_last_error()
            raise CustodyError(f"refusal:windows-identity-failed:{error}")
        directory = bool(info.attributes & FILE_ATTRIBUTE_DIRECTORY)
        return FileIdentity(
            platform="windows",
            device=int(info.volume_serial),
            file_id=(int(info.index_high) << 32) | int(info.index_low),
            mode=(stat.S_IFDIR if directory else stat.S_IFREG) | 0o400,
            uid=0,
            gid=0,
            nlink=int(info.links),
            size=(int(info.size_high) << 32) | int(info.size_low),
            mtime_ns=self._filetime(info.last_write) * 100,
            ctime_ns=self._filetime(info.creation) * 100,
            attributes=int(info.attributes),
        )

    def open_anchor(self, anchor: str, label: str) -> int:
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x1
        FILE_SHARE_WRITE = 0x2
        OPEN_EXISTING = 3
        FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
        FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
        handle = self.kernel32.CreateFileW(
            anchor,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        value = int(handle) if handle else 0
        if value == self.INVALID_HANDLE_VALUE or value == 0:
            error = self.ctypes.get_last_error()
            raise CustodyError(f"refusal:windows-anchor-open-failed:{label}:{error}")
        return value

    def open_child(self, parent: int, name: str, *, directory: bool, label: str) -> int:
        FILE_READ_DATA = 0x0001
        FILE_READ_ATTRIBUTES = 0x0080
        SYNCHRONIZE = 0x00100000
        FILE_SHARE_READ = 0x1
        FILE_SHARE_WRITE = 0x2
        FILE_OPEN = 1
        FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
        FILE_OPEN_FOR_BACKUP_INTENT = 0x00004000
        FILE_OPEN_REPARSE_POINT = 0x00200000
        OBJ_CASE_INSENSITIVE = 0x00000040

        buffer = self.ctypes.create_unicode_buffer(name)
        encoded_bytes = len(name.encode("utf-16-le"))
        unicode_name = self.UNICODE_STRING(
            encoded_bytes, encoded_bytes + 2, self.ctypes.cast(buffer, self.wintypes.LPWSTR)
        )
        attributes = self.OBJECT_ATTRIBUTES(
            self.ctypes.sizeof(self.OBJECT_ATTRIBUTES),
            self.wintypes.HANDLE(parent),
            self.ctypes.pointer(unicode_name),
            OBJ_CASE_INSENSITIVE,
            None,
            None,
        )
        io_status = self.IO_STATUS_BLOCK()
        result = self.wintypes.HANDLE()
        desired = FILE_READ_ATTRIBUTES | SYNCHRONIZE
        share = FILE_SHARE_READ | FILE_SHARE_WRITE
        options = FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT
        if directory:
            desired |= FILE_READ_DATA
            options |= FILE_OPEN_FOR_BACKUP_INTENT
        else:
            desired |= FILE_READ_DATA
            share = FILE_SHARE_READ
        status = int(
            self.ntdll.NtCreateFile(
                self.ctypes.byref(result),
                desired,
                self.ctypes.byref(attributes),
                self.ctypes.byref(io_status),
                None,
                0,
                share,
                FILE_OPEN,
                options,
                None,
                0,
            )
        )
        if status < 0:
            error = int(self.ntdll.RtlNtStatusToDosError(status))
            raise CustodyError(f"refusal:windows-relative-open-failed:{label}:{error}")
        return int(result.value)

    def create_child_file(self, parent: int, name: str, label: str) -> int:
        FILE_READ_DATA = 0x0001
        FILE_WRITE_DATA = 0x0002
        FILE_READ_ATTRIBUTES = 0x0080
        FILE_WRITE_ATTRIBUTES = 0x0100
        DELETE = 0x00010000
        SYNCHRONIZE = 0x00100000
        FILE_SHARE_READ = 0x1
        FILE_CREATE = 2
        FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
        FILE_NON_DIRECTORY_FILE = 0x00000040
        FILE_OPEN_REPARSE_POINT = 0x00200000
        OBJ_CASE_INSENSITIVE = 0x00000040
        buffer = self.ctypes.create_unicode_buffer(name)
        encoded_bytes = len(name.encode("utf-16-le"))
        unicode_name = self.UNICODE_STRING(
            encoded_bytes,
            encoded_bytes + 2,
            self.ctypes.cast(buffer, self.wintypes.LPWSTR),
        )
        attributes = self.OBJECT_ATTRIBUTES(
            self.ctypes.sizeof(self.OBJECT_ATTRIBUTES),
            self.wintypes.HANDLE(parent),
            self.ctypes.pointer(unicode_name),
            OBJ_CASE_INSENSITIVE,
            None,
            None,
        )
        io_status = self.IO_STATUS_BLOCK()
        result = self.wintypes.HANDLE()
        status = int(
            self.ntdll.NtCreateFile(
                self.ctypes.byref(result),
                FILE_READ_DATA
                | FILE_WRITE_DATA
                | FILE_READ_ATTRIBUTES
                | FILE_WRITE_ATTRIBUTES
                | DELETE
                | SYNCHRONIZE,
                self.ctypes.byref(attributes),
                self.ctypes.byref(io_status),
                None,
                0,
                FILE_SHARE_READ,
                FILE_CREATE,
                FILE_SYNCHRONOUS_IO_NONALERT
                | FILE_NON_DIRECTORY_FILE
                | FILE_OPEN_REPARSE_POINT,
                None,
                0,
            )
        )
        if status < 0:
            error = int(self.ntdll.RtlNtStatusToDosError(status))
            raise CustodyError(f"refusal:windows-create-new-failed:{label}:{error}")
        handle = int(result.value)
        identity = self.identity(handle)
        try:
            _reject_reparse(identity, label)
            if not stat.S_ISREG(identity.mode) or identity.nlink != 1 or identity.size != 0:
                raise CustodyError(f"refusal:windows-created-file-invalid:{label}")
        except BaseException:
            self.close(handle)
            raise
        return handle

    def flush(self, handle: int, label: str) -> None:
        if not self.kernel32.FlushFileBuffers(self.wintypes.HANDLE(handle)):
            error = self.ctypes.get_last_error()
            raise CustodyError(f"refusal:windows-flush-failed:{label}:{error}")

    def mark_delete_on_close(self, handle: int, label: str) -> None:
        disposition = self.FILE_DISPOSITION_INFO(True)
        if not self.kernel32.SetFileInformationByHandle(
            self.wintypes.HANDLE(handle),
            4,
            self.ctypes.byref(disposition),
            self.ctypes.sizeof(disposition),
        ):
            error = self.ctypes.get_last_error()
            raise CustodyError(f"refusal:windows-delete-on-close-failed:{label}:{error}")

    def _sid_string(self, sid: int, label: str) -> str:
        value = self.wintypes.LPWSTR()
        if not self.advapi32.ConvertSidToStringSidW(
            self.ctypes.c_void_p(sid), self.ctypes.byref(value)
        ):
            error = self.ctypes.get_last_error()
            raise CustodyError(f"refusal:windows-sid-invalid:{label}:{error}")
        try:
            return str(value.value)
        finally:
            self.kernel32.LocalFree(self.ctypes.cast(value, self.ctypes.c_void_p))

    def assert_sealed(self, handle: int, label: str) -> None:
        """Require a protected DACL writable only by SYSTEM/Administrators."""

        SE_FILE_OBJECT = 1
        OWNER_SECURITY_INFORMATION = 0x00000001
        DACL_SECURITY_INFORMATION = 0x00000004
        SE_DACL_PROTECTED = 0x1000
        ACL_SIZE_INFORMATION_CLASS = 2
        owner = self.ctypes.c_void_p()
        dacl = self.ctypes.c_void_p()
        descriptor = self.ctypes.c_void_p()
        status = self.advapi32.GetSecurityInfo(
            self.wintypes.HANDLE(handle),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            self.ctypes.byref(owner),
            None,
            self.ctypes.byref(dacl),
            None,
            self.ctypes.byref(descriptor),
        )
        if status != 0 or not descriptor.value or not owner.value or not dacl.value:
            if descriptor.value:
                self.kernel32.LocalFree(descriptor)
            raise CustodyError(f"refusal:windows-security-unavailable:{label}:{status}")
        try:
            if self._sid_string(int(owner.value), label) not in TRUSTED_WINDOWS_OWNER_SIDS:
                raise CustodyError(f"refusal:windows-owner-untrusted:{label}")
            control = self.wintypes.USHORT()
            revision = self.wintypes.DWORD()
            if not self.advapi32.GetSecurityDescriptorControl(
                descriptor, self.ctypes.byref(control), self.ctypes.byref(revision)
            ) or not control.value & SE_DACL_PROTECTED:
                raise CustodyError(f"refusal:windows-dacl-not-protected:{label}")
            information = self.ACL_SIZE_INFORMATION()
            if not self.advapi32.GetAclInformation(
                dacl,
                self.ctypes.byref(information),
                self.ctypes.sizeof(information),
                ACL_SIZE_INFORMATION_CLASS,
            ):
                raise CustodyError(f"refusal:windows-dacl-invalid:{label}")
            if information.AceCount == 0 or information.AceCount > 256:
                raise CustodyError(f"refusal:windows-dacl-entry-count-invalid:{label}")
            for index in range(information.AceCount):
                ace = self.ctypes.c_void_p()
                if not self.advapi32.GetAce(dacl, index, self.ctypes.byref(ace)):
                    raise CustodyError(f"refusal:windows-dacl-entry-invalid:{label}")
                header = self.ctypes.cast(ace, self.ctypes.POINTER(self.ACE_HEADER)).contents
                if header.AceSize < 12:
                    raise CustodyError(f"refusal:windows-dacl-entry-invalid:{label}")
                if header.AceType == 0:
                    mask = self.ctypes.c_uint32.from_address(int(ace.value) + 4).value
                    sid = self._sid_string(int(ace.value) + 8, label)
                    if mask & WINDOWS_WRITE_MASK and sid not in TRUSTED_WINDOWS_OWNER_SIDS:
                        raise CustodyError(f"refusal:windows-dacl-writable:{label}:{sid}")
                elif header.AceType in {5, 9, 11}:
                    raise CustodyError(f"refusal:windows-dacl-complex-allow-refused:{label}")
        finally:
            self.kernel32.LocalFree(descriptor)


_WINDOWS = _WindowsApi() if os.name == "nt" else None


def _reject_reparse(identity: FileIdentity, label: str) -> None:
    if identity.attributes & FILE_ATTRIBUTE_REPARSE_POINT:
        raise CustodyError(f"refusal:reparse-point:{label}")


class CustodiedDirectory:
    """A directory reached through retained, no-follow ancestor handles."""

    def __init__(
        self,
        path: Path,
        handle: int,
        identity: FileIdentity,
        handles: list[int],
        relations: list[_Relation],
        *,
        windows: bool,
        label: str,
    ) -> None:
        self.path = path
        self.handle = handle
        self.identity = identity
        self._handles = handles
        self._relations = relations
        self._windows = windows
        self._label = label
        self._closed = False

    @property
    def fd(self) -> int:
        if self._windows:
            raise CustodyError("refusal:directory-fd-unavailable-on-windows")
        if self._closed:
            raise CustodyError("refusal:custody-closed")
        return self.handle

    def list_names(self) -> list[str]:
        return sorted(os.listdir(self.fd))

    def fsync(self) -> None:
        os.fsync(self.fd)

    def assert_windows_sealed(self) -> None:
        if self._closed:
            raise CustodyError("refusal:custody-closed")
        if not self._windows or _WINDOWS is None:
            raise CustodyError("refusal:windows-seal-proof-requires-windows")
        _WINDOWS.assert_sealed(self.handle, self._label)
        for handle in self._handles:
            _WINDOWS.assert_sealed(handle, self._label)
        self.assert_unchanged()

    def assert_unchanged(self, *, allow_content_changes: bool = False) -> None:
        if self._closed:
            raise CustodyError("refusal:custody-closed")
        current = _handle_identity(self.handle, windows=self._windows)
        if allow_content_changes:
            same = current.stable_directory_key() == self.identity.stable_directory_key()
        else:
            same = current == self.identity
        if not same:
            raise CustodyError(f"refusal:custody-changed-during-verification:{self._label}")
        for relation in self._relations:
            reopened = _open_relative_directory(
                relation.parent, relation.name, windows=self._windows, label=self._label
            )
            try:
                observed = _handle_identity(reopened, windows=self._windows)
                if allow_content_changes:
                    same = observed.stable_directory_key() == relation.identity.stable_directory_key()
                else:
                    same = observed == relation.identity
                if not same:
                    raise CustodyError(
                        f"refusal:custody-changed-during-verification:{self._label}"
                    )
            finally:
                _close_handle(reopened, windows=self._windows)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for handle in reversed(self._handles):
            _close_handle(handle, windows=self._windows)

    def __enter__(self) -> "CustodiedDirectory":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


class CustodiedFile:
    """A bounded regular file and the retained directory chain that names it."""

    def __init__(
        self,
        path: Path,
        fd: int,
        identity: FileIdentity,
        parent: CustodiedDirectory,
        leaf: str,
        label: str,
    ) -> None:
        self.path = path
        self.fd = fd
        self.identity = identity
        self._parent = parent
        self._leaf = leaf
        self._label = label
        self._closed = False

    @property
    def size(self) -> int:
        return self.identity.size

    def read_at(self, offset: int, length: int) -> bytes:
        if self._closed:
            raise CustodyError("refusal:custody-closed")
        if offset < 0 or length < 0 or offset > self.size or length > self.size - offset:
            raise CustodyError(f"refusal:bounded-read-invalid:{self._label}")
        if hasattr(os, "pread"):
            data = os.pread(self.fd, length, offset)
        else:
            position = os.lseek(self.fd, 0, os.SEEK_CUR)
            try:
                os.lseek(self.fd, offset, os.SEEK_SET)
                data = os.read(self.fd, length)
            finally:
                os.lseek(self.fd, position, os.SEEK_SET)
        if len(data) != length:
            raise CustodyError(f"refusal:short-read:{self._label}")
        return data

    def iter_chunks(self, chunk_bytes: int = CHUNK_BYTES) -> Iterator[tuple[int, bytes]]:
        if chunk_bytes < 4096 or chunk_bytes > 16 * CHUNK_BYTES:
            raise CustodyError(f"refusal:chunk-size-invalid:{self._label}")
        offset = 0
        while offset < self.size:
            length = min(chunk_bytes, self.size - offset)
            data = self.read_at(offset, length)
            yield offset, data
            offset += length

    def read_all(self, maximum: int) -> bytes:
        if maximum < 0 or self.size > maximum:
            raise CustodyError(f"refusal:size-out-of-range:{self._label}")
        return b"".join(data for _offset, data in self.iter_chunks())

    def assert_unchanged(self) -> None:
        if self._closed:
            raise CustodyError("refusal:custody-closed")
        if _fd_identity(self.fd) != self.identity:
            raise CustodyError(f"refusal:custody-changed-during-verification:{self._label}")
        reopened = _open_relative_file(
            self._parent.handle,
            self._leaf,
            windows=self._parent._windows,
            label=self._label,
        )
        try:
            if _handle_identity(reopened, windows=self._parent._windows) != self.identity:
                raise CustodyError(
                    f"refusal:custody-changed-during-verification:{self._label}"
                )
        finally:
            _close_handle(reopened, windows=self._parent._windows)
        self._parent.assert_unchanged()

    def assert_windows_sealed(self) -> None:
        if self._closed:
            raise CustodyError("refusal:custody-closed")
        if not self._parent._windows or _WINDOWS is None:
            raise CustodyError("refusal:windows-seal-proof-requires-windows")
        import msvcrt

        _WINDOWS.assert_sealed(msvcrt.get_osfhandle(self.fd), self._label)
        self._parent.assert_windows_sealed()
        self.assert_unchanged()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            os.close(self.fd)
        finally:
            self._parent.close()

    def __enter__(self) -> "CustodiedFile":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


def _close_handle(handle: int, *, windows: bool) -> None:
    if windows:
        assert _WINDOWS is not None
        _WINDOWS.close(handle)
    else:
        os.close(handle)


def _handle_identity(handle: int, *, windows: bool) -> FileIdentity:
    if windows:
        assert _WINDOWS is not None
        identity = _WINDOWS.identity(handle)
        _reject_reparse(identity, "retained handle")
        return identity
    return _posix_identity(os.fstat(handle))


def _fd_identity(fd: int) -> FileIdentity:
    if os.name == "nt":
        import msvcrt

        assert _WINDOWS is not None
        return _WINDOWS.identity(msvcrt.get_osfhandle(fd))
    return _posix_identity(os.fstat(fd))


def _open_relative_directory(parent: int, name: str, *, windows: bool, label: str) -> int:
    _component(name, label)
    if windows:
        assert _WINDOWS is not None
        handle = _WINDOWS.open_child(parent, name, directory=True, label=label)
        identity = _WINDOWS.identity(handle)
        try:
            _reject_reparse(identity, label)
            if not stat.S_ISDIR(identity.mode):
                raise CustodyError(f"refusal:ancestor-not-directory:{label}")
        except Exception:
            _WINDOWS.close(handle)
            raise
        return handle
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise CustodyError("refusal:nofollow-directory-open-unavailable")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        handle = os.open(name, flags, dir_fd=parent)
    except OSError as exc:
        raise CustodyError(f"refusal:ancestor-open-failed:{label}") from exc
    if not stat.S_ISDIR(os.fstat(handle).st_mode):
        os.close(handle)
        raise CustodyError(f"refusal:ancestor-not-directory:{label}")
    return handle


def _open_relative_file(parent: int, name: str, *, windows: bool, label: str) -> int:
    _component(name, label)
    if windows:
        assert _WINDOWS is not None
        return _WINDOWS.open_child(parent, name, directory=False, label=label)
    if not hasattr(os, "O_NOFOLLOW"):
        raise CustodyError("refusal:nofollow-file-open-unavailable")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        return os.open(name, flags, dir_fd=parent)
    except OSError as exc:
        raise CustodyError(f"refusal:file-open-failed:{label}") from exc


def open_custodied_directory(path: Path | str, *, label: str) -> CustodiedDirectory:
    """Open an existing directory without traversing links or reparse points."""

    absolute = _normalized_absolute(path, label)
    windows = os.name == "nt"
    handles: list[int] = []
    relations: list[_Relation] = []
    try:
        if windows:
            assert _WINDOWS is not None
            current = _WINDOWS.open_anchor(absolute.anchor, label)
        else:
            if absolute.anchor != "/":
                raise CustodyError(f"refusal:path-anchor-invalid:{label}")
            if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
                raise CustodyError("refusal:nofollow-directory-open-unavailable")
            current = os.open(
                absolute.anchor,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0),
            )
        handles.append(current)
        root_identity = _handle_identity(current, windows=windows)
        if not stat.S_ISDIR(root_identity.mode):
            raise CustodyError(f"refusal:path-anchor-invalid:{label}")
        for part in absolute.parts[1:]:
            name = _component(part, label)
            child = _open_relative_directory(current, name, windows=windows, label=label)
            identity = _handle_identity(child, windows=windows)
            relations.append(_Relation(current, name, identity))
            handles.append(child)
            current = child
        identity = _handle_identity(current, windows=windows)
        return CustodiedDirectory(
            absolute,
            current,
            identity,
            handles,
            relations,
            windows=windows,
            label=label,
        )
    except Exception:
        for handle in reversed(handles):
            _close_handle(handle, windows=windows)
        raise


def open_custodied_file(
    path: Path | str,
    *,
    maximum_bytes: int,
    label: str,
    minimum_bytes: int = 1,
) -> CustodiedFile:
    """Open one bounded, single-link regular file under retained custody."""

    if minimum_bytes < 0 or maximum_bytes < minimum_bytes:
        raise CustodyError(f"refusal:size-policy-invalid:{label}")
    absolute = _normalized_absolute(path, label)
    parent_path = absolute.parent
    parent = open_custodied_directory(parent_path, label=f"{label} ancestors")
    raw_handle: int | None = None
    fd: int | None = None
    try:
        raw_handle = _open_relative_file(
            parent.handle, absolute.name, windows=parent._windows, label=label
        )
        identity = _handle_identity(raw_handle, windows=parent._windows)
        if not stat.S_ISREG(identity.mode):
            raise CustodyError(f"refusal:not-regular-file:{label}")
        if identity.nlink != 1:
            raise CustodyError(f"refusal:multiple-links:{label}")
        if identity.size < minimum_bytes or identity.size > maximum_bytes:
            raise CustodyError(f"refusal:size-out-of-range:{label}")
        if parent._windows:
            import msvcrt

            fd = msvcrt.open_osfhandle(
                raw_handle, os.O_RDONLY | getattr(os, "O_BINARY", 0)
            )
            raw_handle = None
        else:
            fd = raw_handle
            raw_handle = None
        if _fd_identity(fd) != identity:
            raise CustodyError(f"refusal:custody-changed-before-binding:{label}")
        return CustodiedFile(absolute, fd, identity, parent, absolute.name, label)
    except Exception:
        if fd is not None:
            os.close(fd)
        if raw_handle is not None:
            _close_handle(raw_handle, windows=parent._windows)
        parent.close()
        raise


def publish_windows_pair(
    directory_path: Path | str,
    *,
    core: bytes,
    relay: bytes,
) -> dict[str, tuple[int, int]]:
    """Create the two installer inputs together through one retained directory.

    This is a create-new operation. Existing destinations are never replaced.
    On failure, both created handles are marked delete-on-close before any
    handle is released, so cleanup cannot unlink a substituted pathname.
    """

    if os.name != "nt" or _WINDOWS is None:
        raise CustodyError("refusal:windows-pair-publication-requires-windows")
    if (
        not isinstance(core, bytes)
        or not isinstance(relay, bytes)
        or not core
        or not relay
        or len(core) > 512 * 1024 * 1024
        or len(relay) > 512 * 1024 * 1024
    ):
        raise CustodyError("refusal:windows-pair-publication-bytes-invalid")
    directory = open_custodied_directory(directory_path, label="Winn3 pair staging")
    created: list[tuple[str, int, int, bytes]] = []
    committed = False
    try:
        import msvcrt

        for name, data in (
            ("winn-datapath.exe", core),
            ("winsvpn_winn3_engine.exe", relay),
        ):
            handle = _WINDOWS.create_child_file(directory.handle, name, name)
            fd: int | None = None
            try:
                fd = msvcrt.open_osfhandle(
                    handle, os.O_RDWR | getattr(os, "O_BINARY", 0)
                )
                handle = 0
                offset = 0
                while offset < len(data):
                    written = os.write(fd, data[offset : offset + CHUNK_BYTES])
                    if written <= 0:
                        raise CustodyError("refusal:windows-pair-write-stalled")
                    offset += written
                os.fsync(fd)
                identity = _fd_identity(fd)
                if (
                    not stat.S_ISREG(identity.mode)
                    or identity.nlink != 1
                    or identity.size != len(data)
                ):
                    raise CustodyError("refusal:windows-pair-created-identity-invalid")
                os.lseek(fd, 0, os.SEEK_SET)
                observed = bytearray()
                while len(observed) < len(data):
                    chunk = os.read(fd, min(CHUNK_BYTES, len(data) - len(observed)))
                    if not chunk:
                        break
                    observed.extend(chunk)
                if bytes(observed) != data or os.read(fd, 1):
                    raise CustodyError("refusal:windows-pair-created-bytes-differ")
                created.append((name, fd, msvcrt.get_osfhandle(fd), data))
                fd = None
            except BaseException:
                if fd is not None:
                    try:
                        _WINDOWS.mark_delete_on_close(msvcrt.get_osfhandle(fd), name)
                    finally:
                        os.close(fd)
                if handle:
                    try:
                        _WINDOWS.mark_delete_on_close(handle, name)
                    finally:
                        _WINDOWS.close(handle)
                raise
        directory.assert_unchanged(allow_content_changes=True)
        for name, fd, _handle, data in created:
            if _fd_identity(fd).size != len(data):
                raise CustodyError(f"refusal:windows-pair-created-file-changed:{name}")
        result = {
            name: (len(data), _fd_identity(fd).file_id)
            for name, fd, _handle, data in created
        }
        committed = True
        return result
    finally:
        cleanup_error: BaseException | None = None
        for name, fd, handle, _data in reversed(created):
            if not committed:
                try:
                    _WINDOWS.mark_delete_on_close(handle, name)
                except BaseException as exc:
                    cleanup_error = cleanup_error or exc
            try:
                os.close(fd)
            except BaseException as exc:
                cleanup_error = cleanup_error or exc
        try:
            directory.close()
        except BaseException as exc:
            cleanup_error = cleanup_error or exc
        if cleanup_error is not None:
            raise CustodyError("refusal:windows-pair-publication-cleanup-failed") from cleanup_error
