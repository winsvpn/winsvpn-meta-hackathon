#!/usr/bin/env python3
"""Verify App Store Connect API access without exposing authentication material."""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
import re
import select
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_APP_ID = "6789417002"
EXPECTED_BUNDLE_ID = "org.winsvpn.app"
MAX_RESPONSE_BYTES = 1_048_576
READ_CHUNK_BYTES = 65_536
REQUEST_TIMEOUT_SECONDS = 30
SIGN_TIMEOUT_SECONDS = 30
SIGN_OUTPUT_LIMIT_BYTES = 8_192
SIGN_ERROR_LIMIT_BYTES = 65_536
SIGN_INPUT_LIMIT_BYTES = 16_384
MAX_PRIVATE_KEY_BYTES = 65_536
OPENSSL_CUSTODY_CONTROLLER_SHA256 = "b590042f5ab0d6e1ffc97654f275912d9ef35161a9e60113dbcf0dd3e7d49853"
OPENSSL_EXECUTABLE_SHA256 = "a6a9c103ac97ece042e018e8bc964dcce911997e6e51f223aee469f6a5c5a144"
OPENSSL_TREE_SHA256 = "b862d086d1a9da9dce66d662a4f6e97d969b4bb902e7d63768d6155da4a4108a"
MACOS_NO_FORK_BOUNDARY = Path("/usr/bin/sandbox-exec")
MACOS_NO_FORK_PROFILE = "(version 1)(allow default)(deny process-fork)"
MACOS_RESTRICTED_FLAG = 0x00080000
API_APPS_ENDPOINT = "https://api.appstoreconnect.apple.com/v1/apps"
API_PATH = "/v1/apps"
API_QUERY = urllib.parse.urlencode(
    {"filter[bundleId]": EXPECTED_BUNDLE_ID, "limit": "1"}
)
EXPECTED_API_URL = f"{API_APPS_ENDPOINT}?{API_QUERY}"


class ProbeError(RuntimeError):
    pass


def _owner_blocked(message: str) -> ProbeError:
    return ProbeError(f"OWNER-BLOCKED: {message}")


def _authenticated_no_fork_boundary() -> str:
    if sys.platform != "darwin":
        raise _owner_blocked("the macOS no-fork signing boundary is unavailable")
    try:
        info = MACOS_NO_FORK_BOUNDARY.lstat()
    except OSError as exc:
        raise _owner_blocked("the macOS no-fork signing boundary is absent") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o755
        or not (getattr(info, "st_flags", 0) & MACOS_RESTRICTED_FLAG)
    ):
        raise _owner_blocked(
            "the macOS no-fork signing boundary is not authenticated SSV evidence"
        )
    return os.fspath(MACOS_NO_FORK_BOUNDARY)


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_gid,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _hash_descriptor(descriptor: int, expected_size: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < expected_size:
        block = os.pread(descriptor, min(1_048_576, expected_size - offset), offset)
        if not block:
            raise ProbeError("custody descriptor ended before its declared size")
        digest.update(block)
        offset += len(block)
    return digest.hexdigest()


def _absolute_no_link_path(path_text: str, label: str) -> tuple[Path, tuple[tuple[str, tuple[int, ...]], ...]]:
    expanded = Path(path_text).expanduser()
    if not expanded.is_absolute():
        raise ProbeError(f"{label} must use an absolute path")
    path = Path(os.path.abspath(os.fspath(expanded)))
    current = Path(path.anchor)
    chain: list[tuple[str, tuple[int, ...]]] = []
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except OSError as exc:
            raise ProbeError(f"{label} is not readable") from exc
        if stat.S_ISLNK(info.st_mode):
            raise ProbeError(f"{label} must not traverse a symlink")
        chain.append((os.fspath(current), _file_identity(info)))
    return path, tuple(chain)


def _verify_path_chain(chain: tuple[tuple[str, tuple[int, ...]], ...], label: str) -> None:
    for path_text, expected in chain:
        try:
            current = os.lstat(path_text)
        except OSError as exc:
            raise ProbeError(f"{label} custody path disappeared") from exc
        if _file_identity(current) != expected:
            raise ProbeError(f"{label} custody path changed")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            "App Store Connect auth redirect refused",
            headers,
            fp,
        )


_AUTHENTICATED_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    _NoRedirectHandler(),
)


def _validate_expected_api_url() -> str:
    try:
        parsed = urllib.parse.urlsplit(EXPECTED_API_URL)
        port = parsed.port
    except ValueError as exc:
        raise ProbeError("refusing a malformed App Store Connect auth probe URL") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != "api.appstoreconnect.apple.com"
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != API_PATH
        or parsed.fragment
        or parsed.query != API_QUERY
        or urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        != [("filter[bundleId]", EXPECTED_BUNDLE_ID), ("limit", "1")]
    ):
        raise ProbeError("refusing a noncanonical App Store Connect auth probe URL")
    return EXPECTED_API_URL


def _json_object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProbeError("App Store Connect API response contains duplicate JSON keys")
        result[key] = value
    return result


def _parse_json(raw: bytes) -> object:
    if not raw:
        raise ProbeError("App Store Connect API returned an empty JSON body")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_json_object_no_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ProbeError(
                    f"App Store Connect API returned non-finite JSON value {value}"
                )
            ),
        )
    except ProbeError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProbeError("App Store Connect API returned invalid JSON") from exc


def _response_socket(response: Any) -> Any | None:
    candidates = [response]
    seen: set[int] = set()
    for _depth in range(6):
        next_candidates: list[Any] = []
        for candidate in candidates:
            if candidate is None or id(candidate) in seen:
                continue
            seen.add(id(candidate))
            if callable(getattr(candidate, "settimeout", None)) and callable(
                getattr(candidate, "fileno", None)
            ):
                return candidate
            for attribute in ("fp", "raw", "_sock"):
                next_candidates.append(getattr(candidate, attribute, None))
        candidates = next_candidates
    return None


def _read_capped_response(response: Any, deadline: float) -> bytes:
    raw_length = response.headers.get("Content-Length")
    if raw_length is not None:
        try:
            declared_length = int(raw_length, 10)
        except (TypeError, ValueError) as exc:
            raise ProbeError(
                "App Store Connect API returned an invalid Content-Length"
            ) from exc
        if declared_length < 0 or declared_length > MAX_RESPONSE_BYTES:
            raise ProbeError("App Store Connect API response exceeded the safety limit")
    chunks: list[bytes] = []
    total = 0
    response_socket = _response_socket(response)
    read_once = getattr(response, "read1", None)
    if not callable(read_once):
        read_once = response.read
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProbeError("App Store Connect API response exceeded the absolute deadline")
        if response_socket is not None:
            try:
                response_socket.settimeout(max(0.001, remaining))
            except OSError as exc:
                raise ProbeError("App Store Connect API response deadline could not be applied") from exc
        try:
            chunk = read_once(
                max(1, min(READ_CHUNK_BYTES, MAX_RESPONSE_BYTES + 1 - total))
            )
        except (TimeoutError, OSError) as exc:
            raise ProbeError("App Store Connect API response exceeded the absolute deadline") from exc
        if time.monotonic() > deadline:
            raise ProbeError("App Store Connect API response exceeded the absolute deadline")
        if not isinstance(chunk, bytes):
            raise ProbeError("App Store Connect API returned non-byte response data")
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise ProbeError("App Store Connect API response exceeded the safety limit")
        chunks.append(chunk)
    raw = b"".join(chunks)
    if raw_length is not None and len(raw) != declared_length:
        raise ProbeError(
            "App Store Connect API body length does not match Content-Length"
        )
    return raw


def b64url(value: bytes) -> bytes:
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def read_der_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ProbeError("invalid ECDSA signature length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0 or count > 4 or offset + count > len(data):
        raise ProbeError("invalid ECDSA signature length")
    length = int.from_bytes(data[offset : offset + count], "big")
    if length < 0x80:
        raise ProbeError("non-canonical ECDSA signature length")
    return length, offset + count


def der_ecdsa_to_raw(signature: bytes) -> bytes:
    if not signature or signature[0] != 0x30:
        raise ProbeError("invalid ECDSA signature sequence")
    sequence_length, offset = read_der_length(signature, 1)
    if offset + sequence_length != len(signature):
        raise ProbeError("invalid ECDSA signature sequence length")

    values: list[bytes] = []
    for _ in range(2):
        if offset >= len(signature) or signature[offset] != 0x02:
            raise ProbeError("invalid ECDSA signature integer")
        value_length, offset = read_der_length(signature, offset + 1)
        if value_length == 0 or offset + value_length > len(signature):
            raise ProbeError("invalid ECDSA signature integer length")
        encoded = signature[offset : offset + value_length]
        offset += value_length
        if encoded[0] & 0x80:
            raise ProbeError("negative ECDSA signature integer")
        if len(encoded) > 1 and encoded[0] == 0:
            encoded = encoded[1:]
        if len(encoded) > 32:
            raise ProbeError("oversized ECDSA signature integer")
        values.append(encoded.rjust(32, b"\0"))

    if offset != len(signature):
        raise ProbeError("trailing ECDSA signature data")
    return b"".join(values)


def require_private_external_key(path_text: str) -> Path:
    if not path_text:
        raise ProbeError("WINS_APPLE_AUTHENTICATION_KEY_PATH is required")
    path, chain = _absolute_no_link_path(
        path_text, "App Store Connect authentication key"
    )
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ProbeError("App Store Connect authentication key must be a regular file")
    try:
        path.relative_to(ROOT.resolve(strict=True))
    except ValueError:
        pass
    else:
        raise ProbeError("App Store Connect authentication key must live outside the project")
    if metadata.st_uid != os.getuid():
        raise ProbeError("App Store Connect authentication key must be owned by the current user")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ProbeError("App Store Connect authentication key must use owner-only permissions")
    if metadata.st_size <= 0 or metadata.st_size > MAX_PRIVATE_KEY_BYTES:
        raise ProbeError("App Store Connect authentication key size is invalid")
    _verify_path_chain(chain, "App Store Connect authentication key")
    return path


def require_key_id(value: str) -> str:
    if not re.fullmatch(r"[A-Z0-9]{10}", value):
        raise ProbeError("WINS_APPLE_AUTHENTICATION_KEY_ID is invalid")
    return value


def require_issuer_id(value: str) -> str:
    if not re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        value,
    ):
        raise ProbeError("WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID is invalid")
    return value


@contextlib.contextmanager
def _held_private_key(key_path: Path):
    validated = require_private_external_key(os.fspath(key_path))
    validated, chain = _absolute_no_link_path(
        os.fspath(validated), "App Store Connect authentication key"
    )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    source_descriptor = os.open(validated, flags)
    held_descriptor: int | None = None
    private_root: str | None = None
    try:
        before = os.fstat(source_descriptor)
        named = validated.lstat()
        if (
            _file_identity(before) != _file_identity(named)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_size <= 0
            or before.st_size > MAX_PRIVATE_KEY_BYTES
        ):
            raise ProbeError("App Store Connect authentication key custody is invalid")
        source_sha256 = _hash_descriptor(source_descriptor, before.st_size)
        if _file_identity(os.fstat(source_descriptor)) != _file_identity(before):
            raise ProbeError("App Store Connect authentication key changed while read")
        private_root = tempfile.mkdtemp(prefix="wins-apple-auth-key-", dir="/private/tmp")
        os.chmod(private_root, 0o700)
        held_path = Path(private_root) / "key"
        output_descriptor = os.open(
            held_path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        try:
            offset = 0
            while offset < before.st_size:
                block = os.pread(
                    source_descriptor,
                    min(65_536, before.st_size - offset),
                    offset,
                )
                if not block:
                    raise ProbeError("App Store Connect authentication key ended early")
                view = memoryview(block)
                while view:
                    written = os.write(output_descriptor, view)
                    if written <= 0:
                        raise ProbeError("private key custody copy failed")
                    view = view[written:]
                offset += len(block)
            os.fsync(output_descriptor)
        finally:
            os.close(output_descriptor)
        held_descriptor = os.open(held_path, flags)
        held_info = os.fstat(held_descriptor)
        if (
            not stat.S_ISREG(held_info.st_mode)
            or held_info.st_nlink != 1
            or stat.S_IMODE(held_info.st_mode) != 0o400
            or held_info.st_size != before.st_size
            or _hash_descriptor(held_descriptor, held_info.st_size) != source_sha256
        ):
            raise ProbeError("private key custody copy does not match its source")
        held_path.unlink()
        os.rmdir(private_root)
        private_root = None
        held_anonymous = os.fstat(held_descriptor)
        yield held_descriptor, source_descriptor, before, source_sha256, chain
        if (
            _file_identity(os.fstat(held_descriptor))
            != _file_identity(held_anonymous)
            or _hash_descriptor(held_descriptor, held_anonymous.st_size)
            != source_sha256
        ):
            raise ProbeError("anonymous private key custody changed during signing")
        if (
            _file_identity(os.fstat(source_descriptor)) != _file_identity(before)
            or _hash_descriptor(source_descriptor, before.st_size) != source_sha256
        ):
            raise ProbeError("App Store Connect authentication key changed during signing")
        _verify_path_chain(chain, "App Store Connect authentication key")
    finally:
        if held_descriptor is not None:
            os.close(held_descriptor)
        os.close(source_descriptor)
        if private_root is not None:
            held_path = Path(private_root) / "key"
            try:
                held_path.unlink(missing_ok=True)
                os.rmdir(private_root)
            except OSError:
                pass


def _load_openssl_custody_controller() -> dict[str, Any]:
    source_path = ROOT / "tools/release_openssl_archive_custody.py"
    source_path, chain = _absolute_no_link_path(
        os.fspath(source_path), "reviewed OpenSSL custody controller"
    )
    descriptor = os.open(
        source_path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size <= 0
            or info.st_size > 1_048_576
        ):
            raise ProbeError("reviewed OpenSSL custody controller identity is invalid")
        data = b""
        offset = 0
        while offset < info.st_size:
            block = os.pread(descriptor, min(65_536, info.st_size - offset), offset)
            if not block:
                raise ProbeError("reviewed OpenSSL custody controller ended early")
            data += block
            offset += len(block)
        if hashlib.sha256(data).hexdigest() != OPENSSL_CUSTODY_CONTROLLER_SHA256:
            raise ProbeError("reviewed OpenSSL custody controller digest mismatch")
        if _file_identity(os.fstat(descriptor)) != _file_identity(info):
            raise ProbeError("reviewed OpenSSL custody controller changed")
        _verify_path_chain(chain, "reviewed OpenSSL custody controller")
        namespace: dict[str, Any] = {
            "__file__": os.fspath(source_path),
            "__name__": "_winsvpn_reviewed_openssl_custody",
        }
        exec(compile(data, os.fspath(source_path), "exec"), namespace, namespace)
        return namespace
    except (UnicodeError, SyntaxError, OSError) as exc:
        raise ProbeError("reviewed OpenSSL custody controller could not load") from exc
    finally:
        os.close(descriptor)


@contextlib.contextmanager
def _held_reviewed_openssl():
    runtime = os.environ.get("WINS_RELEASE_OPENSSL_RUNTIME", "")
    runtime_id = os.environ.get("WINS_RELEASE_OPENSSL_RUNTIME_ID", "")
    root = os.environ.get("WINS_RELEASE_OPENSSL_ROOT", "")
    tree_sha256 = os.environ.get("WINS_RELEASE_OPENSSL_TREE_SHA256", "")
    binary = os.environ.get("WINS_RELEASE_OPENSSL", "")
    binary_sha256 = os.environ.get("WINS_RELEASE_OPENSSL_SHA256", "")
    if (
        not runtime
        or not runtime_id
        or root != f"{runtime}/extracted/openssl"
        or binary != f"{root}/bin/openssl"
        or tree_sha256 != OPENSSL_TREE_SHA256
        or binary_sha256 != OPENSSL_EXECUTABLE_SHA256
    ):
        raise ProbeError("authenticated OpenSSL 4.0.2 custody is required")
    controller = _load_openssl_custody_controller()
    try:
        controller["verify"](
            [runtime, runtime_id, root, OPENSSL_TREE_SHA256, binary, OPENSSL_EXECUTABLE_SHA256]
        )
    except Exception as exc:
        raise ProbeError("authenticated OpenSSL runtime verification failed") from exc
    binary_path, chain = _absolute_no_link_path(binary, "authenticated OpenSSL binary")
    descriptor = os.open(
        binary_path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    private_root: str | None = None
    held_descriptor: int | None = None
    private_root_descriptor: int | None = None
    watch: Any = None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o500
            or _hash_descriptor(descriptor, before.st_size) != OPENSSL_EXECUTABLE_SHA256
        ):
            raise ProbeError("authenticated OpenSSL binary identity mismatch")
        private_root = tempfile.mkdtemp(prefix="wins-apple-auth-openssl-", dir="/private/tmp")
        os.chmod(private_root, 0o700)
        held_path = Path(private_root) / "openssl"
        output_descriptor = os.open(
            held_path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o500,
        )
        try:
            offset = 0
            while offset < before.st_size:
                block = os.pread(descriptor, min(1_048_576, before.st_size - offset), offset)
                if not block:
                    raise ProbeError("authenticated OpenSSL binary ended early")
                view = memoryview(block)
                while view:
                    written = os.write(output_descriptor, view)
                    if written <= 0:
                        raise ProbeError("private OpenSSL custody copy failed")
                    view = view[written:]
                offset += len(block)
            os.fsync(output_descriptor)
        finally:
            os.close(output_descriptor)
        held_descriptor = os.open(
            held_path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        held_before = os.fstat(held_descriptor)
        held_named = held_path.lstat()
        if (
            _file_identity(held_before) != _file_identity(held_named)
            or held_before.st_nlink != 1
            or stat.S_IMODE(held_before.st_mode) != 0o500
            or _hash_descriptor(held_descriptor, held_before.st_size)
            != OPENSSL_EXECUTABLE_SHA256
        ):
            raise ProbeError("private OpenSSL custody copy identity mismatch")
        os.chmod(private_root, 0o500)
        if hasattr(select, "kqueue"):
            watch = select.kqueue()
            private_root_descriptor = os.open(private_root, os.O_RDONLY)
            flags = 0
            for name in ("KQ_NOTE_WRITE", "KQ_NOTE_RENAME", "KQ_NOTE_DELETE", "KQ_NOTE_ATTRIB", "KQ_NOTE_REVOKE"):
                flags |= int(getattr(select, name, 0))
            events = [
                select.kevent(
                    target,
                    filter=select.KQ_FILTER_VNODE,
                    flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                    fflags=flags,
                )
                for target in (held_descriptor, private_root_descriptor)
            ]
            watch.control(events, 0, 0)
        yield held_path, held_descriptor, held_before, chain, controller, (
            runtime,
            runtime_id,
            root,
            OPENSSL_TREE_SHA256,
            binary,
            OPENSSL_EXECUTABLE_SHA256,
        )
        if watch is not None and watch.control(None, 8, 0):
            raise ProbeError("private OpenSSL custody changed during signing")
        if (
            _file_identity(os.fstat(held_descriptor)) != _file_identity(held_before)
            or _file_identity(held_path.lstat()) != _file_identity(held_before)
            or _hash_descriptor(held_descriptor, held_before.st_size)
            != OPENSSL_EXECUTABLE_SHA256
        ):
            raise ProbeError("private OpenSSL custody changed during signing")
        if (
            _file_identity(os.fstat(descriptor)) != _file_identity(before)
            or _hash_descriptor(descriptor, before.st_size) != OPENSSL_EXECUTABLE_SHA256
        ):
            raise ProbeError("authenticated OpenSSL binary changed during signing")
        _verify_path_chain(chain, "authenticated OpenSSL binary")
        controller["verify"](
            [runtime, runtime_id, root, OPENSSL_TREE_SHA256, binary, OPENSSL_EXECUTABLE_SHA256]
        )
    except ProbeError:
        raise
    except Exception as exc:
        raise ProbeError("authenticated OpenSSL runtime changed during signing") from exc
    finally:
        if watch is not None:
            watch.close()
        if held_descriptor is not None:
            os.close(held_descriptor)
        if private_root_descriptor is not None:
            os.close(private_root_descriptor)
        if private_root is not None:
            try:
                os.chmod(private_root, 0o700)
                (Path(private_root) / "openssl").unlink(missing_ok=True)
                os.rmdir(private_root)
            except OSError:
                pass
        os.close(descriptor)


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        pass
    deadline = time.monotonic() + 2
    while True:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return
        except OSError:
            return
        if time.monotonic() >= deadline:
            raise ProbeError("OpenSSL descendant process group survived cleanup")
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        time.sleep(0.02)


def _sign_with_openssl(
    openssl_path: Path,
    openssl_descriptor: int,
    key_descriptor: int,
    signing_input: bytes,
) -> bytes:
    if (
        not isinstance(signing_input, bytes)
        or not signing_input
        or len(signing_input) > SIGN_INPUT_LIMIT_BYTES
    ):
        raise ProbeError("OpenSSL signing input is invalid or exceeds its safety limit")
    command = [
        _authenticated_no_fork_boundary(),
        "-p",
        MACOS_NO_FORK_PROFILE,
        os.fspath(openssl_path),
        "dgst",
        "-sha256",
        "-sign",
        f"/dev/fd/{key_descriptor}",
    ]
    environment = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": "/var/empty",
        "TMPDIR": "/private/tmp",
        "LANG": "C",
        "LC_ALL": "C",
        "OPENSSL_CONF": "/dev/null",
    }
    deadline = time.monotonic() + SIGN_TIMEOUT_SECONDS
    process: subprocess.Popen[bytes] | None = None
    streams: dict[int, tuple[Any, bytearray, int, str]] = {}
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    input_descriptor: int | None = None
    input_offset = 0
    previous_handler: Any = None
    timer_armed = False
    try:
        if threading.current_thread() is threading.main_thread() and hasattr(signal, "setitimer"):
            def timeout_handler(_signum: int, _frame: Any) -> None:
                raise TimeoutError("OpenSSL launch deadline expired")

            previous_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.setitimer(signal.ITIMER_REAL, SIGN_TIMEOUT_SECONDS)
            timer_armed = True
        process = subprocess.Popen(
            command,
            cwd="/",
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            shell=False,
            close_fds=True,
            pass_fds=(openssl_descriptor, key_descriptor),
            start_new_session=True,
        )
        if timer_armed:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)
            timer_armed = False
        assert process.stdin is not None
        if signing_input:
            input_descriptor = process.stdin.fileno()
            os.set_blocking(input_descriptor, False)
        else:
            process.stdin.close()
        for stream, label, limit in (
            (process.stdout, "stdout", SIGN_OUTPUT_LIMIT_BYTES),
            (process.stderr, "stderr", SIGN_ERROR_LIMIT_BYTES),
        ):
            assert stream is not None
            descriptor = stream.fileno()
            os.set_blocking(descriptor, False)
            streams[descriptor] = (stream, captured[label], limit, label)
        while streams or input_descriptor is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeError("OpenSSL signing exceeded the time bound")
            readable, writable, _exceptional = select.select(
                list(streams),
                [] if input_descriptor is None else [input_descriptor],
                [],
                min(0.1, remaining),
            )
            if input_descriptor is not None and input_descriptor in writable:
                try:
                    written = os.write(input_descriptor, signing_input[input_offset:])
                except BlockingIOError:
                    written = 0
                except BrokenPipeError as exc:
                    raise ProbeError(
                        "OpenSSL closed stdin before consuming the signing input"
                    ) from exc
                if written < 0:
                    raise ProbeError("OpenSSL signing input write failed")
                input_offset += written
                if input_offset == len(signing_input):
                    assert process.stdin is not None
                    process.stdin.close()
                    input_descriptor = None
            for descriptor in readable:
                stream, payload, limit, label = streams[descriptor]
                try:
                    block = os.read(
                        descriptor,
                        max(1, min(65_536, limit + 1 - len(payload))),
                    )
                except BlockingIOError:
                    continue
                if not block:
                    stream.close()
                    del streams[descriptor]
                    continue
                payload.extend(block)
                if len(payload) > limit:
                    raise ProbeError(f"OpenSSL {label} exceeded the safety limit")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProbeError("OpenSSL signing exceeded the time bound")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise ProbeError("OpenSSL signing exceeded the time bound") from exc
        if returncode != 0 or not captured["stdout"]:
            raise ProbeError("App Store Connect private key could not sign an authentication token")
        return bytes(captured["stdout"])
    except TimeoutError as exc:
        raise ProbeError("OpenSSL signing could not start within the time bound") from exc
    except OSError as exc:
        raise ProbeError("authenticated OpenSSL signing process failed") from exc
    finally:
        if timer_armed:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)
        cleanup_error: ProbeError | None = None
        if process is not None:
            try:
                _kill_process_group(process)
            except ProbeError as exc:
                cleanup_error = exc
        for stream, _payload, _limit, _label in list(streams.values()):
            try:
                stream.close()
            except OSError:
                pass
        if process is not None and process.stdin is not None and not process.stdin.closed:
            try:
                process.stdin.close()
            except OSError:
                pass
        if cleanup_error is not None:
            raise cleanup_error


def create_token(key_path: Path, key_id: str, issuer_id: str, now: int | None = None) -> str:
    issued_at = int(time.time()) if now is None else now
    header = b64url(
        json.dumps(
            {"alg": "ES256", "kid": key_id, "typ": "JWT"},
            separators=(",", ":"),
        ).encode("utf-8")
    )
    payload = b64url(
        json.dumps(
            {
                "iss": issuer_id,
                "iat": issued_at,
                "exp": issued_at + 600,
                "aud": "appstoreconnect-v1",
            },
            separators=(",", ":"),
        ).encode("utf-8")
    )
    signing_input = header + b"." + payload
    with _held_private_key(key_path) as key_custody, _held_reviewed_openssl() as openssl_custody:
        signature_der = _sign_with_openssl(
            openssl_custody[0], openssl_custody[1], key_custody[0], signing_input
        )
    signature = b64url(der_ecdsa_to_raw(signature_der))
    return (signing_input + b"." + signature).decode("ascii")


def validate_app_response(payload: object) -> None:
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise ProbeError("App Store Connect API returned an invalid app response")
    apps = payload["data"]
    if len(apps) != 1 or not isinstance(apps[0], dict):
        raise ProbeError("App Store Connect API did not return exactly one expected app")
    app = apps[0]
    if app.get("type") != "apps":
        raise ProbeError("App Store Connect API returned an unexpected resource type")
    attributes = app.get("attributes")
    if not isinstance(attributes, dict):
        raise ProbeError("App Store Connect API app attributes are missing")
    if app.get("id") != EXPECTED_APP_ID:
        raise ProbeError("App Store Connect API returned an unexpected Apple app ID")
    if attributes.get("bundleId") != EXPECTED_BUNDLE_ID:
        raise ProbeError("App Store Connect API returned an unexpected bundle ID")


def _probe_token(token: str) -> None:
    if (
        not isinstance(token, str)
        or re.fullmatch(
            r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token
        )
        is None
    ):
        raise ProbeError("refusing an invalid App Store Connect bearer token")
    url = _validate_expected_api_url()
    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "wins-vpn-release-auth-probe/1",
        },
    )
    deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
    try:
        response = _AUTHENTICATED_OPENER.open(
            request, timeout=REQUEST_TIMEOUT_SECONDS
        )
    except urllib.error.HTTPError as exc:
        try:
            if exc.geturl() != url:
                raise ProbeError(
                    "App Store Connect API error URL differs from the intended request"
                ) from exc
            if 300 <= exc.code <= 399:
                raise ProbeError(
                    f"App Store Connect API refused HTTP redirect {exc.code}"
                ) from exc
            raise ProbeError(
                f"App Store Connect API authentication failed with HTTP {exc.code}"
            ) from exc
        finally:
            exc.close()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ProbeError("App Store Connect API authentication request failed") from exc
    with response:
        if response.geturl() != url:
            raise ProbeError(
                "App Store Connect API response URL differs from the intended request"
            )
        status = getattr(response, "status", None)
        if type(status) is not int or status != 200:
            raise ProbeError(
                f"App Store Connect API authentication failed with HTTP {status}"
            )
        content_type = str(response.headers.get("Content-Type") or "")
        media_type = content_type.split(";", 1)[0].strip().lower()
        if media_type not in {"application/json", "application/vnd.api+json"}:
            raise ProbeError("App Store Connect API returned a non-JSON content type")
        raw = _read_capped_response(response, deadline)
    validate_app_response(_parse_json(raw))


def probe() -> None:
    key_path = require_private_external_key(
        os.environ.get("WINS_APPLE_AUTHENTICATION_KEY_PATH", "")
    )
    key_id = require_key_id(os.environ.get("WINS_APPLE_AUTHENTICATION_KEY_ID", ""))
    issuer_id = require_issuer_id(
        os.environ.get("WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID", "")
    )
    token = create_token(key_path, key_id, issuer_id)
    _probe_token(token)


def run_selftest() -> None:
    signature = der_ecdsa_to_raw(b"\x30\x06\x02\x01\x01\x02\x01\x02")
    if len(signature) != 64 or signature[-1] != 2:
        raise ProbeError("self-test ECDSA signature conversion mismatch")

    valid_response = {
        "data": [
            {
                "type": "apps",
                "id": EXPECTED_APP_ID,
                "attributes": {"bundleId": EXPECTED_BUNDLE_ID},
            }
        ]
    }
    validate_app_response(valid_response)
    for invalid in (
        {},
        {"data": []},
        {"data": [{"id": "wrong", "attributes": {"bundleId": EXPECTED_BUNDLE_ID}}]},
        {"data": [{"id": EXPECTED_APP_ID, "attributes": {"bundleId": "wrong"}}]},
    ):
        try:
            validate_app_response(invalid)
        except ProbeError:
            continue
        raise ProbeError("self-test accepted an invalid App Store Connect response")
    try:
        der_ecdsa_to_raw(b"not-a-signature")
    except ProbeError:
        pass
    else:
        raise ProbeError("self-test accepted a malformed ECDSA signature")
    print("PASS: App Store Connect auth probe self-test")
    print("SUMMARY: 1/1 checks passing")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    try:
        if args.selftest:
            run_selftest()
        else:
            probe()
            print("PASS: App Store Connect API authentication succeeded (HTTP 200)")
            print(
                "PASS: expected universal Win's VPN app record matched "
                f"(Apple ID {EXPECTED_APP_ID}; bundle ID {EXPECTED_BUNDLE_ID})"
            )
            print("SUMMARY: 2/2 checks passing")
    except ProbeError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
