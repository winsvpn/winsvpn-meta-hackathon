#!/usr/bin/env python3
"""Create one contract-bound website locale source without touching major.json.

The preferred provider is the official Google Cloud Translation API via the
GOOGLE_TRANSLATE_API_KEY environment variable. The public provider remains an
explicit pre-generation option. Production commands always select exactly one
contract locale and derive its output path from the accepted contract.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import math
import os
import re
import secrets
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any

API_URL = "https://translation.googleapis.com/language/translate/v2"
PUBLIC_API_URL = "https://translate.googleapis.com/translate_a/single"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
READ_CHUNK_BYTES = 1024 * 1024
ACCEPTED_CONTRACT_PATH = "localization/website/contract.json"
ACCEPTED_VALIDATOR_PATH = "tools/website_localization_contract.py"
ACCEPTED_AGGREGATE_PATH = "web/i18n/major.json"
ACCEPTED_LOCALE_DIRECTORY = "localization/website/locales"
ACCEPTED_CONTRACT_SHA256 = (
    "9ec1a8a461fb17ada914b0626a2561c3d85a1dc6a20585ffaac2ddb454b45b45"
)
ACCEPTED_VALIDATOR_SHA256 = (
    "9a70d57928e534da00f117ac168fb5bfacc5e321c6180be1c2346540e36e6172"
)
EXPECTED_TRANSLATABLE_KEY_COUNT = 379
PROTECTED_LITERALS = {"Win's VPN": "ZXQ742693851QXZ"}
LEAKED_PLACEHOLDER_RE = re.compile(
    r"(?:ZXQ742693851QXZ|ZXQWINSVPNBRANDQXZ|ZXQWINSVPNBMARQUEQXZ|"
    r"ZXQWINSVPN\u54c1\u724cQXZ|WinSVPNBRAND|"
    r"_+[\u200b\u200c\u200d\u2060\ufeff]*WINSVPN_BRAND_+)",
    re.IGNORECASE,
)
# Placeholder envelopes of unknown meaning. Machine translation has leaked
# ZZZWINVPPNPLAINZZZ, ZZWINNPROTOCOLZZZ, ZZZPAYPAYPALZZZ, ZZIOSZZZZ and the
# Cyrillic ZZZ-wrapped form, which stood for different protected names
# (Win's VPN, Winn Protocol, PayPal, iOS), plus glued BRAND markers and long
# capital runs such as iOSBRAND or ANDROIDMARKA. They cannot be restored
# safely, so a value that contains one is refused instead of rewritten. A
# token that also occurs in the English source is not a leak. Case
# sensitive: Italian and Hungarian words such as "utilizza" or "hozza" are
# legitimate.
PLACEHOLDER_ENVELOPE_RE = re.compile(
    r"ZXQ[0-9A-Z\u4e00-\u9fff]*QXZ"
    r"|(?<![A-Za-z\u0400-\u04ff0-9])[ZX\u0417\u0425]{2,}"
    r"[A-Z\u0410-\u042f\u04010-9]{2,}"
    r"|[A-Z\u0410-\u042f\u04010-9]{2,}[ZX\u0417\u0425]{2,}"
    r"(?![A-Za-z\u0400-\u04ff0-9])"
    r"|WINSVPN_?BRAND|WinSVPNBRAND|(?<![a-z])BRAND(?![a-z])"
    r"|(?<![A-Za-z])[A-Z\u00c0-\u00d6\u00d8-\u00de\u0130]{8,}"
)
ROMAN_NUMERAL_RE = re.compile(r"[IVXLCDM]+")
# A single capital Z glued to a protected brand or platform name, or left at
# the end of a Latin word (ZAndroid, ZiOS, ZWin's VPN, AndroidZ, Protocol\u00aeZ,
# layerZ). Z followed by a lowercase letter stays legal for German, Polish
# and Czech words.
STRAY_Z_RE = re.compile(
    r"(?<![A-Za-z])Z(?=Android|iOS|Windows|Linux|macOS|MacOS|Apple|Win|PayPal"
    r"|Coalition|[a-z]+-[a-z])"
    r"|(?<=[a-z\u00ae\u2122])Z(?![A-Za-z])"
)
# Two or more zero-width characters in a row, or one next to an ASCII space.
# Single joiners and separators are legitimate orthography in Persian (ZWNJ),
# Bengali (ZWJ), Khmer and Lao (ZWSP word separators).
ZERO_WIDTH_CONTAMINATION_RE = re.compile(
    r"[\u200b\u200c\u200d\u2060\ufeff]{2,}"
    r"|(?<= )[\u200b\u200c\u200d\u2060\ufeff]"
    r"|[\u200b\u200c\u200d\u2060\ufeff](?= )"
)
# Names that must appear in a translation exactly as often as in the English
# source. Longer forms of the same name are counted before shorter ones.
PROTECTED_NAME_PATTERNS = (
    ("Win's VPN Inc.", r"Win's VPN Inc\."),
    ("Win's VPN\u2122", r"Win's VPN\u2122"),
    ("Win's VPN\u00ae", r"Win's VPN\u00ae"),
    ("Win's VPN", r"Win's VPN(?![\u2122\u00ae]| Inc\.)"),
    ("Winn Protocol\u00ae", r"Winn Protocol\u00ae"),
    ("Win Empire LLC", r"Win Empire LLC"),
    ("PayPal", r"PayPal"),
    ("Coalition Inc.", r"Coalition Inc\."),
    ("Android", r"Android"),
    ("iOS", r"(?<![A-Za-z])iOS"),
    ("Windows", r"Windows"),
    ("macOS", r"macOS"),
    ("MacOS", r"MacOS"),
    ("Linux", r"Linux"),
    ("Apple Maps", r"Apple Maps"),
    ("Apple", r"Apple"),
    ("VpnService", r"VpnService"),
)
_PROTECTED_NAME_RES = tuple(
    (name, re.compile(pattern)) for name, pattern in PROTECTED_NAME_PATTERNS
)
# A bracketed name appended at the end of a translation, for example
# "... (Win's VPN)." or "... (Winn Protocol\u00ae).".
TRAILING_BRACKET_RE = re.compile(r"\(([^()]*)\)[\s.!?\u3002\u0964\u104b]*$")


def translation_integrity_defects(source: str, translated: str) -> list[str]:
    """Return every placeholder, contamination or brand defect in one value."""

    defects: list[str] = []
    for match in PLACEHOLDER_ENVELOPE_RE.finditer(translated):
        token = match.group(0)
        if token in source or ROMAN_NUMERAL_RE.fullmatch(token):
            continue
        defects.append(f"placeholder token {token!r}")
    for match in STRAY_Z_RE.finditer(translated):
        context = translated[max(0, match.start() - 8) : match.end() + 8]
        if context.strip() not in source:
            defects.append(f"stray Z in {context!r}")
    if ZERO_WIDTH_CONTAMINATION_RE.search(translated) is not None:
        defects.append("doubled or space-adjacent zero-width character")
    for name, pattern in _PROTECTED_NAME_RES:
        expected = len(pattern.findall(source))
        actual = len(pattern.findall(translated))
        if expected != actual:
            defects.append(
                f"{name!r} occurs {actual} times; English source has {expected}"
            )
    bracket = TRAILING_BRACKET_RE.search(translated)
    if bracket is not None and f"({bracket.group(1)})" not in source:
        inner = bracket.group(1)
        if any(pattern.search(inner) for _name, pattern in _PROTECTED_NAME_RES):
            defects.append(f"appended bracketed name ({inner})")
    return defects


class TranslationTransportError(RuntimeError):
    """Raised when a translation response crosses the reviewed transport boundary."""


@dataclass
class _DirectoryHandle:
    relative_path: str
    fd: int
    identity: tuple[int, int]
    fingerprint: tuple[int, ...]
    parent_path: str | None
    name: str | None


@dataclass
class _FileHandle:
    relative_path: str
    fd: int
    identity: tuple[int, int]
    fingerprint: tuple[int, ...]
    parent_path: str
    name: str
    payload: bytes


@dataclass(frozen=True)
class FillResult:
    mode: str
    locale: str
    output_path: str
    key_count: int
    seeded_count: int
    translated_count: int
    sanitized_count: int
    payload_size: int
    payload_sha256: str


@dataclass
class _BoundState:
    validator: ModuleType
    contract: dict[str, Any]
    aggregate: dict[str, dict[str, str]]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return (metadata.st_dev, metadata.st_ino)


def _fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _safe_relative_path(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise TranslationTransportError(f"{label} is not a safe relative path")
    parsed = PurePosixPath(value)
    if (
        parsed.is_absolute()
        or parsed.as_posix() != value
        or not parsed.parts
        or any(part in ("", ".", "..") for part in parsed.parts)
    ):
        raise TranslationTransportError(f"{label} is not a safe relative path")
    return value


def _directory_is_safe(metadata: os.stat_result) -> bool:
    return stat.S_ISDIR(metadata.st_mode) and not (
        metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    )


class _SecureRepository:
    """Retain no-follow descriptors and reject any input or path drift."""

    def __init__(self, repo: Path) -> None:
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory = getattr(os, "O_DIRECTORY", None)
        if nofollow is None or directory is None:
            raise TranslationTransportError(
                "this platform cannot enforce no-follow repository access"
            )
        try:
            raw_repo = os.fspath(repo)
        except TypeError as exc:
            raise TranslationTransportError(
                "repository root is not a filesystem path"
            ) from exc
        if not isinstance(raw_repo, str) or not raw_repo or "\x00" in raw_repo:
            raise TranslationTransportError("repository root is not a safe path")
        absolute = os.path.abspath(raw_repo)
        if absolute == "/" or os.path.normpath(absolute) != absolute:
            raise TranslationTransportError(
                "repository root must be a canonical non-root path"
            )
        flags = (
            os.O_RDONLY
            | nofollow
            | directory
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        root_fd = -1
        try:
            root_fd = os.open(absolute, flags)
            descriptor_metadata = os.fstat(root_fd)
            entry = os.stat(absolute, follow_symlinks=False)
        except OSError as exc:
            if root_fd >= 0:
                os.close(root_fd)
            raise TranslationTransportError(
                "repository root is unsafe or unavailable"
            ) from exc
        if (
            not _directory_is_safe(descriptor_metadata)
            or not _directory_is_safe(entry)
            or _identity(descriptor_metadata) != _identity(entry)
        ):
            os.close(root_fd)
            raise TranslationTransportError("repository root identity is unsafe")
        root = _DirectoryHandle(
            relative_path="",
            fd=root_fd,
            identity=_identity(descriptor_metadata),
            fingerprint=_fingerprint(descriptor_metadata),
            parent_path=None,
            name=None,
        )
        self.root_path = absolute
        self._nofollow = nofollow
        self._directory = directory
        self._cloexec = getattr(os, "O_CLOEXEC", 0)
        self._nonblock = getattr(os, "O_NONBLOCK", 0)
        self._directories: dict[str, _DirectoryHandle] = {"": root}
        self._files: list[_FileHandle] = []
        self._locked_directories: set[str] = set()
        self._closed = False

    def __enter__(self) -> _SecureRepository:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for handle in reversed(self._files):
            try:
                os.close(handle.fd)
            except OSError:
                pass
        for handle in reversed(list(self._directories.values())):
            try:
                if handle.relative_path in self._locked_directories:
                    fcntl.flock(handle.fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(handle.fd)
            except OSError:
                pass

    @staticmethod
    def _read_descriptor(fd: int, *, maximum: int, label: str) -> bytes:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, min(READ_CHUNK_BYTES, maximum + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > maximum:
                    raise TranslationTransportError(
                        f"repository file is too large: {label}"
                    )
            return b"".join(chunks)
        except TranslationTransportError:
            raise
        except OSError as exc:
            raise TranslationTransportError(
                f"unable to read descriptor-bound file: {label}"
            ) from exc

    def open_directory(self, relative_path: str) -> _DirectoryHandle:
        relative = _safe_relative_path(relative_path, label="repository directory")
        current_path = ""
        for component in PurePosixPath(relative).parts:
            child_path = f"{current_path}/{component}" if current_path else component
            if child_path in self._directories:
                current_path = child_path
                continue
            parent = self._directories[current_path]
            descriptor = -1
            try:
                descriptor = os.open(
                    component,
                    os.O_RDONLY
                    | self._nofollow
                    | self._directory
                    | self._cloexec
                    | self._nonblock,
                    dir_fd=parent.fd,
                )
                metadata = os.fstat(descriptor)
                entry = os.stat(component, dir_fd=parent.fd, follow_symlinks=False)
            except OSError as exc:
                if descriptor >= 0:
                    os.close(descriptor)
                raise TranslationTransportError(
                    f"repository directory is unsafe or unavailable: {child_path}"
                ) from exc
            if (
                not _directory_is_safe(metadata)
                or not _directory_is_safe(entry)
                or _identity(metadata) != _identity(entry)
            ):
                os.close(descriptor)
                raise TranslationTransportError(
                    f"repository directory identity is unsafe: {child_path}"
                )
            self._directories[child_path] = _DirectoryHandle(
                relative_path=child_path,
                fd=descriptor,
                identity=_identity(metadata),
                fingerprint=_fingerprint(metadata),
                parent_path=current_path,
                name=component,
            )
            current_path = child_path
        return self._directories[relative]

    def lock_directory(self, relative_path: str, *, exclusive: bool) -> _DirectoryHandle:
        handle = self.open_directory(relative_path)
        if relative_path not in self._locked_directories:
            operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            try:
                fcntl.flock(handle.fd, operation | fcntl.LOCK_NB)
            except OSError as exc:
                raise TranslationTransportError(
                    f"another translation process owns directory: {relative_path}"
                ) from exc
            self._locked_directories.add(relative_path)
        return handle

    def open_file(
        self,
        relative_path: str,
        *,
        maximum: int = MAX_INPUT_BYTES,
    ) -> _FileHandle:
        relative = _safe_relative_path(relative_path, label="repository file")
        parsed = PurePosixPath(relative)
        parent_path = parsed.parent.as_posix()
        if parent_path == ".":
            parent_path = ""
        parent = self._directories[""] if not parent_path else self.open_directory(parent_path)
        descriptor = -1
        try:
            descriptor = os.open(
                parsed.name,
                os.O_RDONLY | self._nofollow | self._cloexec | self._nonblock,
                dir_fd=parent.fd,
            )
            before = os.fstat(descriptor)
            entry = os.stat(parsed.name, dir_fd=parent.fd, follow_symlinks=False)
        except OSError as exc:
            if descriptor >= 0:
                os.close(descriptor)
            raise TranslationTransportError(
                f"repository file is unsafe or unavailable: {relative}"
            ) from exc
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(entry.st_mode)
            or before.st_nlink != 1
            or entry.st_nlink != 1
            or _identity(before) != _identity(entry)
            or before.st_size < 0
            or before.st_size > maximum
        ):
            os.close(descriptor)
            raise TranslationTransportError(
                f"repository file identity is unsafe: {relative}"
            )
        try:
            payload = self._read_descriptor(descriptor, maximum=maximum, label=relative)
            after = os.fstat(descriptor)
            current = os.stat(parsed.name, dir_fd=parent.fd, follow_symlinks=False)
        except Exception:
            os.close(descriptor)
            raise
        fingerprint = _fingerprint(before)
        if (
            _fingerprint(after) != fingerprint
            or _fingerprint(current) != fingerprint
            or len(payload) != after.st_size
        ):
            os.close(descriptor)
            raise TranslationTransportError(
                f"repository file changed while read: {relative}"
            )
        handle = _FileHandle(
            relative_path=relative,
            fd=descriptor,
            identity=_identity(after),
            fingerprint=fingerprint,
            parent_path=parent_path,
            name=parsed.name,
            payload=payload,
        )
        self._files.append(handle)
        return handle

    def assert_stable(self, *, changed_directories: set[str] | None = None) -> None:
        allowed = changed_directories or set()
        try:
            root_entry = os.stat(self.root_path, follow_symlinks=False)
        except OSError as exc:
            raise TranslationTransportError(
                "repository root changed during translation"
            ) from exc
        root = self._directories[""]
        if (
            not _directory_is_safe(root_entry)
            or _identity(root_entry) != root.identity
            or _fingerprint(root_entry) != root.fingerprint
        ):
            raise TranslationTransportError(
                "repository root changed during translation"
            )
        for relative, handle in self._directories.items():
            try:
                descriptor_metadata = os.fstat(handle.fd)
                if handle.parent_path is None:
                    entry = descriptor_metadata
                else:
                    parent = self._directories[handle.parent_path]
                    entry = os.stat(
                        handle.name,
                        dir_fd=parent.fd,
                        follow_symlinks=False,
                    )
            except OSError as exc:
                label = relative or "."
                raise TranslationTransportError(
                    f"repository directory changed during translation: {label}"
                ) from exc
            if (
                not _directory_is_safe(descriptor_metadata)
                or not _directory_is_safe(entry)
                or _identity(descriptor_metadata) != handle.identity
                or _identity(entry) != handle.identity
                or (
                    relative not in allowed
                    and (
                        _fingerprint(descriptor_metadata) != handle.fingerprint
                        or _fingerprint(entry) != handle.fingerprint
                    )
                )
            ):
                label = relative or "."
                raise TranslationTransportError(
                    f"repository directory changed during translation: {label}"
                )
        for handle in self._files:
            parent = self._directories[handle.parent_path]
            try:
                descriptor_metadata = os.fstat(handle.fd)
                entry = os.stat(
                    handle.name,
                    dir_fd=parent.fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise TranslationTransportError(
                    f"repository file changed during translation: {handle.relative_path}"
                ) from exc
            if (
                not stat.S_ISREG(descriptor_metadata.st_mode)
                or not stat.S_ISREG(entry.st_mode)
                or descriptor_metadata.st_nlink != 1
                or entry.st_nlink != 1
                or _identity(descriptor_metadata) != handle.identity
                or _identity(entry) != handle.identity
                or _fingerprint(descriptor_metadata) != handle.fingerprint
                or _fingerprint(entry) != handle.fingerprint
            ):
                raise TranslationTransportError(
                    f"repository file changed during translation: {handle.relative_path}"
                )
            current_payload = self._read_descriptor(
                handle.fd,
                maximum=max(len(handle.payload), 1),
                label=handle.relative_path,
            )
            if current_payload != handle.payload or _fingerprint(os.fstat(handle.fd)) != handle.fingerprint:
                raise TranslationTransportError(
                    f"repository file bytes changed during translation: {handle.relative_path}"
                )


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
        raise TranslationTransportError(f"translation redirect refused: HTTP {code}")


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise TranslationTransportError(f"duplicate JSON key: {key!r}")
        output[key] = value
    return output


def _reject_nonfinite(value: str) -> None:
    raise TranslationTransportError(f"non-finite JSON value: {value}")


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise TranslationTransportError(f"non-finite JSON value: {value}")
    return parsed


def strict_json_loads(payload: str) -> object:
    try:
        return json.loads(
            payload,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_nonfinite,
            parse_float=_parse_finite_float,
        )
    except TranslationTransportError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise TranslationTransportError("invalid translation JSON") from exc


def load_translation_map(path: Path) -> dict[str, dict[str, str]]:
    parsed = strict_json_loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise TranslationTransportError("website translations must be a JSON object")
    output: dict[str, dict[str, str]] = {}
    for locale, mapping in parsed.items():
        if not re.fullmatch(r"[a-z]{2,3}(?:-[A-Z]{2})?", locale):
            raise TranslationTransportError(f"invalid translation locale: {locale!r}")
        if not isinstance(mapping, dict):
            raise TranslationTransportError(
                f"translation locale {locale!r} must be an object"
            )
        checked: dict[str, str] = {}
        for key, value in mapping.items():
            if not isinstance(key, str) or not key:
                raise TranslationTransportError(
                    f"translation locale {locale!r} has an invalid source key"
                )
            if not isinstance(value, str):
                raise TranslationTransportError(
                    f"translation locale {locale!r} has a non-string value"
                )
            checked[key] = value
        output[locale] = checked
    return output


def _validate_url(
    url: str,
    *,
    expected_host: str,
    expected_path: str,
    allow_query: bool,
) -> None:
    parsed = urllib.parse.urlsplit(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise TranslationTransportError("translation URL port is invalid") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != expected_host
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.path != expected_path
        or parsed.fragment
        or (not allow_query and parsed.query)
    ):
        raise TranslationTransportError("translation URL is outside the reviewed HTTPS endpoint")


def _validate_api_key(api_key: str) -> None:
    if (
        not api_key
        or len(api_key) > 4096
        or api_key.strip() != api_key
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in api_key)
    ):
        raise TranslationTransportError("Google Translation API key is invalid")


def _validate_target(target: str) -> None:
    if not re.fullmatch(r"[a-z]{2,3}(?:-[A-Z]{2})?", target):
        raise TranslationTransportError("translation target locale is invalid")


def _build_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirectHandler(),
    )


def _header_values(headers: object, name: str) -> list[str]:
    get_all = getattr(headers, "get_all", None)
    if callable(get_all):
        values = get_all(name) or []
    else:
        get = getattr(headers, "get", None)
        value = get(name) if callable(get) else None
        values = [] if value is None else [value]
    return [str(value) for value in values]


def _read_exact_json(
    request: urllib.request.Request,
    *,
    expected_url: str,
    timeout: int,
) -> object:
    try:
        with _build_opener().open(request, timeout=timeout) as response:
            status = getattr(response, "status", response.getcode())
            if status != 200:
                raise TranslationTransportError(f"translation HTTP status refused: {status}")
            if response.geturl() != expected_url:
                raise TranslationTransportError("translation response URL drifted")
            content_types = _header_values(response.headers, "Content-Type")
            if len(content_types) != 1:
                raise TranslationTransportError(
                    "translation response Content-Type is missing or ambiguous"
                )
            content_type = content_types[0]
            media_type = content_type.split(";", 1)[0].strip().lower()
            if media_type != "application/json":
                raise TranslationTransportError("translation response is not application/json")
            content_lengths = _header_values(response.headers, "Content-Length")
            if len(content_lengths) > 1:
                raise TranslationTransportError(
                    "translation response Content-Length is ambiguous"
                )
            if content_lengths:
                try:
                    parsed_length = int(content_lengths[0])
                    if parsed_length < 0 or parsed_length > MAX_RESPONSE_BYTES:
                        raise TranslationTransportError("translation response is too large")
                except ValueError as exc:
                    raise TranslationTransportError(
                        "translation response Content-Length is invalid"
                    ) from exc
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise TranslationTransportError("translation response is too large")
    except TranslationTransportError:
        raise
    except urllib.error.HTTPError as exc:
        raise TranslationTransportError(
            f"translation HTTP status refused: {exc.code}"
        ) from exc
    except (OSError, urllib.error.URLError) as exc:
        raise TranslationTransportError("translation transport failed") from exc
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TranslationTransportError("translation response is not UTF-8") from exc
    return strict_json_loads(text)


def protect_literals(text: str) -> str:
    for literal, placeholder in PROTECTED_LITERALS.items():
        text = text.replace(literal, placeholder)
    return text


def restore_literals(text: str) -> str:
    for literal, placeholder in PROTECTED_LITERALS.items():
        text = re.sub(re.escape(placeholder), literal, text, flags=re.IGNORECASE)
    return LEAKED_PLACEHOLDER_RE.sub("Win's VPN", text)


def sanitize_translation_placeholders(translations: dict[str, object]) -> int:
    changed = 0
    for mapping in translations.values():
        if not isinstance(mapping, dict):
            continue
        for key, value in list(mapping.items()):
            if not isinstance(value, str):
                continue
            restored = restore_literals(value)
            if restored != value:
                mapping[key] = restored
                changed += 1
    return changed


def chunks(items: list[str], size: int) -> list[list[str]]:
    return [items[index : index + size] for index in range(0, len(items), size)]


def chunks_by_chars(
    items: list[str], *, max_items: int = 25, max_chars: int = 3500
) -> list[list[str]]:
    result: list[list[str]] = []
    current: list[str] = []
    current_chars = 0
    for item in items:
        item_len = len(item) + 1
        if current and (len(current) >= max_items or current_chars + item_len > max_chars):
            result.append(current)
            current = []
            current_chars = 0
        current.append(item)
        current_chars += item_len
    if current:
        result.append(current)
    return result


def translate_official(api_key: str, target: str, strings: list[str]) -> dict[str, str]:
    _validate_api_key(api_key)
    _validate_target(target)
    _validate_url(
        API_URL,
        expected_host="translation.googleapis.com",
        expected_path="/language/translate/v2",
        allow_query=False,
    )
    output: dict[str, str] = {}
    for chunk in chunks(strings, 80):
        body = json.dumps(
            {"q": chunk, "source": "en", "target": target, "format": "text"}
        ).encode("utf-8")
        request = urllib.request.Request(
            API_URL,
            data=body,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "X-Goog-Api-Key": api_key,
            },
            method="POST",
        )
        payload = _read_exact_json(request, expected_url=API_URL, timeout=45)
        if not isinstance(payload, dict):
            raise TranslationTransportError("official translation response must be an object")
        data = payload.get("data")
        if not isinstance(data, dict):
            raise TranslationTransportError("official translation response data is invalid")
        translated = data.get("translations")
        if not isinstance(translated, list) or len(translated) != len(chunk):
            raise TranslationTransportError(
                "official translation response count does not match request"
            )
        for source, item in zip(chunk, translated):
            if not isinstance(item, dict) or not isinstance(item.get("translatedText"), str):
                raise TranslationTransportError("official translation item is invalid")
            text = item["translatedText"].strip()
            if text and text != source:
                output[source] = text
    return output


def public_request(target: str, text: str, *, timeout: int = 45) -> list[list[object]]:
    _validate_target(target)
    params = urllib.parse.urlencode(
        {
            "client": "gtx",
            "sl": "en",
            "tl": target,
            "dt": "t",
            "q": text,
        }
    )
    url = f"{PUBLIC_API_URL}?{params}"
    _validate_url(
        url,
        expected_host="translate.googleapis.com",
        expected_path="/translate_a/single",
        allow_query=True,
    )
    request = urllib.request.Request(
        url, headers={"User-Agent": "wins-vpn-i18n-prefill"}
    )
    payload = _read_exact_json(request, expected_url=url, timeout=timeout)
    if not isinstance(payload, list) or not payload or not isinstance(payload[0], list):
        raise TranslationTransportError("public translation response is invalid")
    segments = payload[0]
    if not segments:
        raise TranslationTransportError("public translation response has no segments")
    for segment in segments:
        if (
            not isinstance(segment, list)
            or len(segment) < 2
            or not isinstance(segment[0], str)
            or not isinstance(segment[1], str)
        ):
            raise TranslationTransportError("public translation segment is invalid")
    return segments


def translate_public_batch(target: str, strings: list[str]) -> dict[str, str]:
    joined = "\n".join(strings)
    segments = public_request(target, joined)
    output: dict[str, str] = {}
    index = 0
    source_acc = ""
    target_acc = ""
    for segment in segments:
        translated = segment[0]
        source = segment[1]
        source_acc += source
        target_acc += translated
        if index < len(strings) and source_acc.strip() == strings[index].strip():
            text = target_acc.strip()
            if text and text != strings[index]:
                output[strings[index]] = text
            index += 1
            source_acc = ""
            target_acc = ""
    if index != len(strings):
        return {}
    return output


def translate_public(
    target: str, strings: list[str], *, delay: float = 0.08, retries: int = 2
) -> dict[str, str]:
    output: dict[str, str] = {}
    for chunk in chunks_by_chars(strings):
        translated = {}
        for attempt in range(retries + 1):
            try:
                translated = translate_public_batch(target, chunk)
                if len(translated) == len(chunk):
                    break
            except Exception:
                translated = {}
            time.sleep(delay * (attempt + 1))
        if len(translated) != len(chunk):
            translated = {}
            for source in chunk:
                for attempt in range(retries + 1):
                    try:
                        segments = public_request(target, source)
                        returned_source = "".join(segment[1] for segment in segments).strip()
                        text = "".join(segment[0] for segment in segments).strip()
                        if (
                            returned_source == source.strip()
                            and text
                            and text != source
                        ):
                            translated[source] = text
                            break
                    except Exception:
                        pass
                    time.sleep(delay * (attempt + 1))
        output.update(translated)
        time.sleep(delay)
    return output


def translate_strings(
    provider: str, api_key: str | None, target: str, strings: list[str], delay: float
) -> dict[str, str]:
    protected = {source: protect_literals(source) for source in strings}
    if len(set(protected.values())) != len(protected):
        raise TranslationTransportError(
            "protected translation inputs are not one-to-one"
        )
    protected_strings = [protected[source] for source in strings]
    if provider == "official":
        if not api_key:
            raise TranslationTransportError("GOOGLE_TRANSLATE_API_KEY is not set")
        translated = translate_official(api_key, target, protected_strings)
    elif provider == "public":
        translated = translate_public(target, protected_strings, delay=delay)
    elif api_key:
        translated = translate_official(api_key, target, protected_strings)
    else:
        translated = translate_public(target, protected_strings, delay=delay)
    output: dict[str, str] = {}
    for source, protected_source in protected.items():
        value = translated.get(protected_source)
        if value:
            restored = restore_literals(value)
            if restored and restored != source:
                output[source] = restored
    return output


def select_locales(
    requested: list[str] | None,
    translations: dict[str, dict[str, str]],
) -> list[str]:
    locales = requested or [code for code in translations if code != "en"]
    if len(locales) != len(set(locales)):
        raise TranslationTransportError("duplicate --locale selection")
    for locale in locales:
        _validate_target(locale)
        if locale not in translations:
            raise TranslationTransportError(
                f"--locale is not present in the translation file: {locale}"
            )
    return locales


def _validator_call(
    validator: ModuleType,
    operation: Any,
    *args: object,
    **kwargs: object,
) -> Any:
    try:
        return operation(*args, **kwargs)
    except validator.WebsiteLocalizationContractError as exc:
        raise TranslationTransportError(str(exc)) from exc


def _load_bound_validator(handle: _FileHandle) -> ModuleType:
    actual = _sha256(handle.payload)
    if actual != ACCEPTED_VALIDATOR_SHA256:
        raise TranslationTransportError(
            "website localization validator binding mismatch: "
            f"got {actual} expected {ACCEPTED_VALIDATOR_SHA256}"
        )
    module = ModuleType("_winsvpn_bound_website_localization_contract")
    module.__file__ = handle.relative_path
    module.__package__ = ""
    try:
        code = compile(
            handle.payload,
            handle.relative_path,
            "exec",
            dont_inherit=True,
        )
        exec(code, module.__dict__)
    except Exception as exc:
        raise TranslationTransportError(
            "unable to load the bound website localization validator"
        ) from exc
    required_api = (
        "AGGREGATE_PATH",
        "AUDIT_PATH",
        "CONTRACT_SCHEMA",
        "DEFAULT_CONTRACT_PATH",
        "INDEX_PATH",
        "INSTANT_LOCALE_RE",
        "LANGUAGES_PATH",
        "LOCALE_DOCUMENT_KEYS",
        "LOCALE_SOURCE_DIRECTORY",
        "LOCALE_SOURCE_SCHEMA",
        "WebsiteLocalizationContractError",
        "canonical_json_bytes",
        "canonical_value_sha256",
        "extract_audit_nontranslatable_keys",
        "extract_runtime_nontranslatable_keys",
        "extract_static_keys",
        "sha256_bytes",
        "strict_json_loads",
        "validate_contract_document",
        "validate_locale_document",
    )
    if any(not hasattr(module, name) for name in required_api):
        raise TranslationTransportError(
            "bound website localization validator API is incomplete"
        )
    if (
        module.DEFAULT_CONTRACT_PATH != ACCEPTED_CONTRACT_PATH
        or module.AGGREGATE_PATH != ACCEPTED_AGGREGATE_PATH
        or module.LOCALE_SOURCE_DIRECTORY != ACCEPTED_LOCALE_DIRECTORY
    ):
        raise TranslationTransportError(
            "bound website localization validator paths are not authoritative"
        )
    return module


def _parse_instant_locales(
    validator: ModuleType,
    payload: bytes,
) -> list[dict[str, object]]:
    document = _validator_call(
        validator,
        validator.strict_json_loads,
        payload,
        label=validator.LANGUAGES_PATH,
    )
    if not isinstance(document, list):
        raise TranslationTransportError(
            f"{validator.LANGUAGES_PATH} root must be an array"
        )
    seen: set[str] = set()
    instant: list[dict[str, object]] = []
    for index, item in enumerate(document):
        if not isinstance(item, dict) or tuple(item.keys()) != (
            "code",
            "name",
            "instant",
        ):
            raise TranslationTransportError(
                f"{validator.LANGUAGES_PATH}[{index}] keys or order are invalid"
            )
        code = item["code"]
        name = item["name"]
        enabled = item["instant"]
        if not isinstance(code, str) or not code:
            raise TranslationTransportError(
                f"locale code at index {index} must be a string"
            )
        if code in seen:
            raise TranslationTransportError(
                f"duplicate locale inventory code: {code}"
            )
        seen.add(code)
        if not isinstance(name, str) or not name or name != name.strip():
            raise TranslationTransportError(
                f"locale inventory name is invalid: {code}"
            )
        if type(enabled) is not bool:
            raise TranslationTransportError(
                f"locale inventory instant flag must be boolean: {code}"
            )
        if enabled:
            if validator.INSTANT_LOCALE_RE.fullmatch(code) is None:
                raise TranslationTransportError(
                    f"unsupported instant locale syntax: {code}"
                )
            instant.append({"code": code, "name": name})
    if not instant or instant[0]["code"] != "en":
        raise TranslationTransportError(
            "English must be the first supported instant locale"
        )
    if any(locale["code"] == "en" for locale in instant[1:]):
        raise TranslationTransportError(
            "English occurs more than once in the instant locale inventory"
        )
    return instant


def _serialization_contract(*, ensure_ascii: bool) -> dict[str, object]:
    return {
        "encoding": "UTF-8",
        "ensure_ascii": ensure_ascii,
        "indent": 2,
        "line_endings": "LF",
        "trailing_newline": True,
    }


def _build_expected_contract_from_bytes(
    validator: ModuleType,
    *,
    index_payload: bytes,
    audit_payload: bytes,
    languages_payload: bytes,
) -> dict[str, object]:
    locales = _parse_instant_locales(validator, languages_payload)
    try:
        translatable_context, translate_no_context = validator.extract_static_keys(
            index_payload
        )
        runtime_nontranslatable = validator.extract_runtime_nontranslatable_keys(
            index_payload
        )
        audit_nontranslatable = validator.extract_audit_nontranslatable_keys(
            audit_payload
        )
    except validator.WebsiteLocalizationContractError as exc:
        raise TranslationTransportError(str(exc)) from exc
    explicit_nontranslatable = runtime_nontranslatable | audit_nontranslatable
    translatable_keys = sorted(translatable_context - explicit_nontranslatable)
    nontranslatable_keys = sorted(translatable_context & explicit_nontranslatable)
    translate_no_only_keys = sorted(translate_no_context - translatable_context)
    mixed_context_keys = sorted(translate_no_context & translatable_context)
    visible_keys = translatable_context | translate_no_context
    drift_keys = sorted(
        (runtime_nontranslatable ^ audit_nontranslatable) & visible_keys
    )
    translatable_hash = validator.canonical_value_sha256(translatable_keys)
    nontranslatable_hash = validator.canonical_value_sha256(nontranslatable_keys)
    translate_no_hash = validator.canonical_value_sha256(translate_no_only_keys)
    mixed_hash = validator.canonical_value_sha256(mixed_context_keys)
    drift_hash = validator.canonical_value_sha256(drift_keys)
    index_hash = validator.sha256_bytes(index_payload)
    english_identity = validator.canonical_value_sha256(
        {
            "file_sha256": index_hash,
            "path": validator.INDEX_PATH,
            "translatable_static_keys_sha256": translatable_hash,
        }
    )
    inventory_identity = validator.canonical_value_sha256(locales)
    locale_codes = [str(item["code"]) for item in locales]
    targets = [
        {
            "locale": code,
            "path": f"{validator.LOCALE_SOURCE_DIRECTORY}/{code}.json",
        }
        for code in locale_codes
        if code != "en"
    ]
    return {
        "schema": validator.CONTRACT_SCHEMA,
        "english_source": {
            "path": validator.INDEX_PATH,
            "file_sha256": index_hash,
            "translatable_static_keys_sha256": translatable_hash,
            "identity_sha256": english_identity,
        },
        "instant_locale_inventory": {
            "path": validator.LANGUAGES_PATH,
            "file_sha256": validator.sha256_bytes(languages_payload),
            "locales": locales,
            "identity_sha256": inventory_identity,
        },
        "key_classification": {
            "normalization": (
                "html-character-references-decoded-whitespace-collapsed-v1"
            ),
            "translatable_static_keys": translatable_keys,
            "translatable_static_keys_sha256": translatable_hash,
            "nontranslatable_static_keys": nontranslatable_keys,
            "nontranslatable_static_keys_sha256": nontranslatable_hash,
            "inherited_translate_no_only_keys": translate_no_only_keys,
            "inherited_translate_no_only_keys_sha256": translate_no_hash,
            "mixed_translate_context_keys": mixed_context_keys,
            "mixed_translate_context_keys_sha256": mixed_hash,
            "runtime_audit_nontranslatable_drift": {
                "classification": "nontranslatable",
                "keys": drift_keys,
                "keys_sha256": drift_hash,
            },
        },
        "locale_sources": {
            "schema": validator.LOCALE_SOURCE_SCHEMA,
            "document_keys": list(validator.LOCALE_DOCUMENT_KEYS),
            "targets": targets,
            "translation_key_order": "translatable_static_keys",
            "translation_values": "nonempty-trimmed-non-english-strings",
            "serialization": _serialization_contract(ensure_ascii=False),
        },
        "compiler_output": {
            "path": validator.AGGREGATE_PATH,
            "locale_order": locale_codes,
            "mapping_key_order": "translatable_static_keys",
            "english_values": "source-key-identity",
            "target_values": "validated-locale-source-values",
            "serialization": _serialization_contract(ensure_ascii=False),
            "write_strategy": (
                "single-owner-same-directory-temp-fsync-replace-directory-fsync"
            ),
        },
    }


def _first_difference(actual: object, expected: object, location: str = "$") -> str | None:
    if type(actual) is not type(expected):
        return location
    if isinstance(expected, dict):
        if tuple(actual.keys()) != tuple(expected.keys()):
            return location
        for key in expected:
            difference = _first_difference(actual[key], expected[key], f"{location}.{key}")
            if difference is not None:
                return difference
        return None
    if isinstance(expected, list):
        if len(actual) != len(expected):
            return location
        for index, (actual_item, expected_item) in enumerate(zip(actual, expected)):
            difference = _first_difference(
                actual_item,
                expected_item,
                f"{location}[{index}]",
            )
            if difference is not None:
                return difference
        return None
    return None if actual == expected else location


def _validate_aggregate_document(
    validator: ModuleType,
    payload: bytes,
    contract: dict[str, Any],
) -> dict[str, dict[str, str]]:
    document = _validator_call(
        validator,
        validator.strict_json_loads,
        payload,
        label=ACCEPTED_AGGREGATE_PATH,
    )
    if not isinstance(document, dict):
        raise TranslationTransportError(
            f"{ACCEPTED_AGGREGATE_PATH} root must be an object"
        )
    if list(document.keys()) != contract["compiler_output"]["locale_order"]:
        raise TranslationTransportError(
            f"{ACCEPTED_AGGREGATE_PATH} locale order does not match the contract"
        )
    for locale, mapping in document.items():
        if not isinstance(mapping, dict):
            raise TranslationTransportError(
                f"{ACCEPTED_AGGREGATE_PATH} locale {locale!r} must be an object"
            )
        for source, translated in mapping.items():
            if not isinstance(source, str) or not source:
                raise TranslationTransportError(
                    f"{ACCEPTED_AGGREGATE_PATH} has an invalid source key"
                )
            if not isinstance(translated, str):
                raise TranslationTransportError(
                    f"{ACCEPTED_AGGREGATE_PATH} has a non-string value"
                )
    return document


def _load_bound_state(secure: _SecureRepository) -> _BoundState:
    validator_handle = secure.open_file(ACCEPTED_VALIDATOR_PATH)
    validator = _load_bound_validator(validator_handle)
    contract_handle = secure.open_file(ACCEPTED_CONTRACT_PATH)
    contract_hash = _sha256(contract_handle.payload)
    if contract_hash != ACCEPTED_CONTRACT_SHA256:
        raise TranslationTransportError(
            "website localization contract binding mismatch: "
            f"got {contract_hash} expected {ACCEPTED_CONTRACT_SHA256}"
        )
    document = _validator_call(
        validator,
        validator.strict_json_loads,
        contract_handle.payload,
        label=ACCEPTED_CONTRACT_PATH,
    )
    contract = _validator_call(
        validator,
        validator.validate_contract_document,
        document,
    )
    canonical_contract = _validator_call(
        validator,
        validator.canonical_json_bytes,
        contract,
        ensure_ascii=True,
    )
    if canonical_contract != contract_handle.payload:
        raise TranslationTransportError(
            "contract JSON is not in canonical ASCII/LF order"
        )
    index_handle = secure.open_file(validator.INDEX_PATH)
    audit_handle = secure.open_file(validator.AUDIT_PATH)
    languages_handle = secure.open_file(validator.LANGUAGES_PATH)
    expected = _build_expected_contract_from_bytes(
        validator,
        index_payload=index_handle.payload,
        audit_payload=audit_handle.payload,
        languages_payload=languages_handle.payload,
    )
    difference = _first_difference(contract, expected)
    if difference is not None:
        raise TranslationTransportError(
            f"contract does not match descriptor-bound source bytes at {difference}"
        )
    keys = contract["key_classification"]["translatable_static_keys"]
    if len(keys) != EXPECTED_TRANSLATABLE_KEY_COUNT:
        raise TranslationTransportError(
            "contract translatable key count is not the accepted 379"
        )
    aggregate_handle = secure.open_file(ACCEPTED_AGGREGATE_PATH)
    aggregate = _validate_aggregate_document(
        validator,
        aggregate_handle.payload,
        contract,
    )
    secure.assert_stable()
    return _BoundState(
        validator=validator,
        contract=contract,
        aggregate=aggregate,
    )


def _select_contract_locale(
    requested: list[str] | None,
    contract: dict[str, Any],
) -> tuple[str, str]:
    values = requested or []
    if len(values) != len(set(values)):
        raise TranslationTransportError("duplicate --locale selection")
    if len(values) != 1:
        raise TranslationTransportError(
            "exactly one non-English contract --locale is required"
        )
    locale = values[0]
    _validate_target(locale)
    if locale == "en":
        raise TranslationTransportError("English locale-source creation is refused")
    targets = {
        item["locale"]: item["path"]
        for item in contract["locale_sources"]["targets"]
    }
    path = targets.get(locale)
    expected_path = f"{ACCEPTED_LOCALE_DIRECTORY}/{locale}.json"
    if path is None:
        raise TranslationTransportError(
            f"unsupported contract locale: {locale}"
        )
    if path != expected_path:
        raise TranslationTransportError(
            f"locale-source path is not authoritative: {locale}"
        )
    return locale, path


def _validate_refresh_keys(
    requested: list[str],
    contract_keys: list[str],
) -> set[str]:
    if len(requested) != len(set(requested)):
        raise TranslationTransportError("duplicate --refresh-key selection")
    allowed = set(contract_keys)
    unknown = [key for key in requested if key not in allowed]
    if unknown:
        raise TranslationTransportError(
            "--refresh-key is outside the accepted contract: " + repr(unknown[0])
        )
    return set(requested)


def _translation_ready_value(source: str, value: object) -> tuple[str, bool]:
    if not isinstance(value, str):
        raise TranslationTransportError("translation value is not a string")
    restored = restore_literals(value)
    if (
        not restored
        or restored != restored.strip()
        or restored == source
        or LEAKED_PLACEHOLDER_RE.search(restored) is not None
    ):
        raise TranslationTransportError(
            "translation value is not nonempty, trimmed, and non-English"
        )
    if translation_integrity_defects(source, restored):
        raise TranslationTransportError(
            "translation value leaks a placeholder, zero-width contamination, "
            "or a changed protected name"
        )
    return restored, restored != value


def _build_locale_payload(
    state: _BoundState,
    *,
    locale: str,
    refresh_keys: set[str],
    provider: str,
    api_key: str | None,
    delay: float,
) -> tuple[bytes, int, int, int]:
    if provider not in ("auto", "official", "public"):
        raise TranslationTransportError("translation provider is unsupported")
    if not math.isfinite(delay) or delay < 0 or delay > 60:
        raise TranslationTransportError("translation delay is outside 0..60 seconds")
    keys = state.contract["key_classification"]["translatable_static_keys"]
    if len(keys) != EXPECTED_TRANSLATABLE_KEY_COUNT:
        raise TranslationTransportError(
            "contract translatable key count changed during translation"
        )
    source_mapping = state.aggregate[locale]
    seeded: dict[str, str] = {}
    sanitized_count = 0
    for key in keys:
        if key in refresh_keys or key not in source_mapping:
            continue
        try:
            value, sanitized = _translation_ready_value(key, source_mapping[key])
        except TranslationTransportError:
            continue
        seeded[key] = value
        sanitized_count += int(sanitized)
    missing = [key for key in keys if key not in seeded]
    translated: dict[str, str] = {}
    if missing:
        target = "he" if locale == "iw" else locale
        provider_values = translate_strings(
            provider,
            api_key,
            target,
            missing,
            delay,
        )
        if (
            not isinstance(provider_values, dict)
            or any(not isinstance(key, str) for key in provider_values)
            or set(provider_values) != set(missing)
        ):
            raise TranslationTransportError(
                "translation provider returned a partial or unexpected result"
            )
        for key in missing:
            value, sanitized = _translation_ready_value(key, provider_values[key])
            translated[key] = value
            sanitized_count += int(sanitized)
    translations = {
        key: seeded[key] if key in seeded else translated[key]
        for key in keys
    }
    if list(translations) != keys or len(translations) != EXPECTED_TRANSLATABLE_KEY_COUNT:
        raise TranslationTransportError(
            "locale source does not contain all 379 exact ordered contract keys"
        )
    contract = state.contract
    document = {
        "schema": state.validator.LOCALE_SOURCE_SCHEMA,
        "locale": locale,
        "english_source_identity_sha256": contract["english_source"][
            "identity_sha256"
        ],
        "instant_locale_inventory_sha256": contract["instant_locale_inventory"][
            "identity_sha256"
        ],
        "translatable_static_keys_sha256": contract["key_classification"][
            "translatable_static_keys_sha256"
        ],
        "translations": translations,
    }
    validated = _validator_call(
        state.validator,
        state.validator.validate_locale_document,
        document,
        expected_locale=locale,
        contract=contract,
    )
    first = _validator_call(
        state.validator,
        state.validator.canonical_json_bytes,
        validated,
        ensure_ascii=False,
    )
    second = _validator_call(
        state.validator,
        state.validator.canonical_json_bytes,
        validated,
        ensure_ascii=False,
    )
    if first != second or not first or len(first) > MAX_OUTPUT_BYTES:
        raise TranslationTransportError(
            "locale-source canonical serialization is unsafe or nondeterministic"
        )
    round_trip = _validator_call(
        state.validator,
        state.validator.strict_json_loads,
        first,
        label=f"locale source {locale}",
    )
    round_trip = _validator_call(
        state.validator,
        state.validator.validate_locale_document,
        round_trip,
        expected_locale=locale,
        contract=contract,
    )
    if (
        round_trip != validated
        or _validator_call(
            state.validator,
            state.validator.canonical_json_bytes,
            round_trip,
            ensure_ascii=False,
        )
        != first
    ):
        raise TranslationTransportError("locale-source canonical round trip drifted")
    return first, len(seeded), len(translated), sanitized_count


def _ensure_entry_absent(directory_fd: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise TranslationTransportError(
            "locale-source output availability cannot be determined"
        ) from exc
    raise TranslationTransportError(
        "create mode refuses to overwrite an existing locale source"
    )


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    offset = 0
    while offset < len(view):
        try:
            written = os.write(fd, view[offset:])
        except OSError as exc:
            raise TranslationTransportError(
                "unable to write locale-source temporary"
            ) from exc
        if written <= 0:
            raise TranslationTransportError(
                "locale-source temporary write made no progress"
            )
        offset += written


def _rename_exclusive(directory_fd: int, source: str, destination: str) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        operation = getattr(library, "renameatx_np", None)
        flag = 0x00000004
    elif sys.platform.startswith("linux"):
        operation = getattr(library, "renameat2", None)
        flag = 0x00000001
    else:
        operation = None
        flag = 0
    if operation is None:
        raise TranslationTransportError(
            "atomic no-replace publication is unsupported on this platform"
        )
    operation.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    operation.restype = ctypes.c_int
    result = operation(
        directory_fd,
        source.encode("utf-8", errors="strict"),
        directory_fd,
        destination.encode("utf-8", errors="strict"),
        flag,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise FileExistsError(error, os.strerror(error), destination)
    raise OSError(error, os.strerror(error), destination)


def _require_owned_entry(
    directory_fd: int,
    name: str,
    fd: int,
    *,
    expected_mode: int,
    expected_size: int,
    label: str,
) -> tuple[int, int]:
    try:
        descriptor_metadata = os.fstat(fd)
        entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise TranslationTransportError(f"{label} identity is unavailable") from exc
    identity = _identity(descriptor_metadata)
    if (
        not stat.S_ISREG(descriptor_metadata.st_mode)
        or not stat.S_ISREG(entry.st_mode)
        or descriptor_metadata.st_nlink != 1
        or entry.st_nlink != 1
        or _identity(entry) != identity
        or stat.S_IMODE(descriptor_metadata.st_mode) != expected_mode
        or stat.S_IMODE(entry.st_mode) != expected_mode
        or descriptor_metadata.st_size != expected_size
        or entry.st_size != expected_size
    ):
        raise TranslationTransportError(f"{label} identity is unsafe")
    return identity


def _cleanup_owned_entry(
    directory_fd: int,
    name: str,
    fd: int,
    identity: tuple[int, int] | None,
) -> None:
    if fd < 0 or identity is None:
        return
    try:
        held = os.fstat(fd)
        entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise TranslationTransportError(
            "unable to identify owned locale-source output during cleanup"
        ) from exc
    if (
        not stat.S_ISREG(held.st_mode)
        or not stat.S_ISREG(entry.st_mode)
        or _identity(held) != identity
        or _identity(entry) != identity
        or held.st_nlink != 1
        or entry.st_nlink != 1
    ):
        raise TranslationTransportError(
            "locale-source cleanup substitution was preserved"
        )
    try:
        os.unlink(name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except OSError as exc:
        raise TranslationTransportError(
            "unable to durably remove incomplete locale-source output"
        ) from exc


def _publish_new_output(
    secure: _SecureRepository,
    parent: _DirectoryHandle,
    output_name: str,
    payload: bytes,
) -> None:
    temporary_name = (
        f".{output_name}.fill.{os.getpid()}.{secrets.token_hex(16)}"
    )
    if (
        len(temporary_name) > 240
        or PurePosixPath(temporary_name).name != temporary_name
        or any(
            character
            not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
            for character in temporary_name
        )
    ):
        raise TranslationTransportError("locale-source temporary name is unsafe")
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    temporary_fd = -1
    owned_identity: tuple[int, int] | None = None
    cleanup_name: str | None = None
    operation_error: BaseException | None = None
    completed = False
    try:
        _ensure_entry_absent(parent.fd, output_name)
        try:
            temporary_fd = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=parent.fd,
            )
        except FileExistsError as exc:
            raise TranslationTransportError(
                "locale-source temporary name collided"
            ) from exc
        cleanup_name = temporary_name
        owned_identity = _require_owned_entry(
            parent.fd,
            temporary_name,
            temporary_fd,
            expected_mode=0o600,
            expected_size=0,
            label="locale-source temporary",
        )
        _write_all(temporary_fd, payload)
        try:
            os.fchmod(temporary_fd, 0o644)
            os.fsync(temporary_fd)
        except OSError as exc:
            raise TranslationTransportError(
                "unable to seal locale-source temporary"
            ) from exc
        if _require_owned_entry(
            parent.fd,
            temporary_name,
            temporary_fd,
            expected_mode=0o644,
            expected_size=len(payload),
            label="sealed locale-source temporary",
        ) != owned_identity:
            raise TranslationTransportError(
                "sealed locale-source temporary identity changed"
            )
        written = _SecureRepository._read_descriptor(
            temporary_fd,
            maximum=MAX_OUTPUT_BYTES,
            label="locale-source temporary",
        )
        if written != payload:
            raise TranslationTransportError(
                "locale-source temporary read-back mismatch"
            )
        secure.assert_stable(changed_directories={ACCEPTED_LOCALE_DIRECTORY})
        _ensure_entry_absent(parent.fd, output_name)
        try:
            _rename_exclusive(parent.fd, temporary_name, output_name)
        except FileExistsError as exc:
            raise TranslationTransportError(
                "create mode refuses to overwrite an existing locale source"
            ) from exc
        except OSError as exc:
            raise TranslationTransportError(
                "unable to publish locale source atomically without replacement"
            ) from exc
        cleanup_name = output_name
        if _require_owned_entry(
            parent.fd,
            output_name,
            temporary_fd,
            expected_mode=0o644,
            expected_size=len(payload),
            label="published locale source",
        ) != owned_identity:
            raise TranslationTransportError("published locale-source identity changed")
        try:
            os.fsync(parent.fd)
        except OSError as exc:
            raise TranslationTransportError(
                "unable to fsync locale-source directory"
            ) from exc
        secure.assert_stable(changed_directories={ACCEPTED_LOCALE_DIRECTORY})
        retained = _SecureRepository._read_descriptor(
            temporary_fd,
            maximum=MAX_OUTPUT_BYTES,
            label="published locale source",
        )
        if retained != payload:
            raise TranslationTransportError("published locale-source bytes changed")
        if _require_owned_entry(
            parent.fd,
            output_name,
            temporary_fd,
            expected_mode=0o644,
            expected_size=len(payload),
            label="published locale source",
        ) != owned_identity:
            raise TranslationTransportError("published locale-source identity changed")
        completed = True
        cleanup_name = None
    except BaseException as exc:
        operation_error = exc
    finally:
        cleanup_error: BaseException | None = None
        if not completed and cleanup_name is not None:
            try:
                _cleanup_owned_entry(
                    parent.fd,
                    cleanup_name,
                    temporary_fd,
                    owned_identity,
                )
            except BaseException as exc:
                cleanup_error = exc
        if temporary_fd >= 0:
            try:
                os.close(temporary_fd)
            except OSError as exc:
                if cleanup_error is None:
                    cleanup_error = TranslationTransportError(
                        "unable to close locale-source output descriptor"
                    )
                    cleanup_error.__cause__ = exc
        if cleanup_error is not None:
            if operation_error is not None:
                raise cleanup_error from operation_error
            raise cleanup_error
    if operation_error is not None:
        raise operation_error.with_traceback(operation_error.__traceback__)


def _verify_existing_source(
    secure: _SecureRepository,
    state: _BoundState,
    *,
    locale: str,
    output_path: str,
) -> FillResult:
    handle = secure.open_file(output_path, maximum=MAX_OUTPUT_BYTES)
    document = _validator_call(
        state.validator,
        state.validator.strict_json_loads,
        handle.payload,
        label=output_path,
    )
    source = _validator_call(
        state.validator,
        state.validator.validate_locale_document,
        document,
        expected_locale=locale,
        contract=state.contract,
    )
    canonical = _validator_call(
        state.validator,
        state.validator.canonical_json_bytes,
        source,
        ensure_ascii=False,
    )
    if canonical != handle.payload:
        raise TranslationTransportError(
            f"locale source is not canonical UTF-8/LF JSON: {locale}"
        )
    if len(source["translations"]) != EXPECTED_TRANSLATABLE_KEY_COUNT:
        raise TranslationTransportError(
            "locale source does not contain all 379 contract keys"
        )
    secure.assert_stable()
    return FillResult(
        mode="verify",
        locale=locale,
        output_path=output_path,
        key_count=len(source["translations"]),
        seeded_count=0,
        translated_count=0,
        sanitized_count=0,
        payload_size=len(handle.payload),
        payload_sha256=_sha256(handle.payload),
    )


def _run_operation(
    repo: Path,
    *,
    mode: str,
    requested_locales: list[str] | None,
    refresh_keys: list[str] | None = None,
    provider: str = "auto",
    api_key: str | None = None,
    delay: float = 0.08,
) -> FillResult:
    if mode not in ("dry-run", "create", "verify"):
        raise TranslationTransportError("translation mode is unsupported")
    with _SecureRepository(repo) as secure:
        state = _load_bound_state(secure)
        locale, output_path = _select_contract_locale(
            requested_locales,
            state.contract,
        )
        output = PurePosixPath(output_path)
        if output.parent.as_posix() != ACCEPTED_LOCALE_DIRECTORY:
            raise TranslationTransportError(
                "locale-source output directory is not authoritative"
            )
        parent = secure.lock_directory(
            ACCEPTED_LOCALE_DIRECTORY,
            exclusive=mode == "create",
        )
        if mode == "verify":
            if refresh_keys:
                raise TranslationTransportError(
                    "verify mode refuses translation refresh requests"
                )
            return _verify_existing_source(
                secure,
                state,
                locale=locale,
                output_path=output_path,
            )
        _ensure_entry_absent(parent.fd, output.name)
        contract_keys = state.contract["key_classification"][
            "translatable_static_keys"
        ]
        refresh = _validate_refresh_keys(refresh_keys or [], contract_keys)
        payload, seeded_count, translated_count, sanitized_count = _build_locale_payload(
            state,
            locale=locale,
            refresh_keys=refresh,
            provider=provider,
            api_key=api_key,
            delay=delay,
        )
        secure.assert_stable()
        _ensure_entry_absent(parent.fd, output.name)
        if mode == "create":
            _publish_new_output(secure, parent, output.name, payload)
        else:
            secure.assert_stable()
        return FillResult(
            mode=mode,
            locale=locale,
            output_path=output_path,
            key_count=len(contract_keys),
            seeded_count=seeded_count,
            translated_count=translated_count,
            sanitized_count=sanitized_count,
            payload_size=len(payload),
            payload_sha256=_sha256(payload),
        )


def _command_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    for mode, help_text in (
        ("dry-run", "Validate and translate one locale without writing."),
        ("create", "Create one canonical locale source only when absent."),
        ("verify", "Verify one canonical locale source without writing."),
    ):
        command = commands.add_parser(mode, help=help_text)
        command.add_argument(
            "--locale",
            action="append",
            required=True,
            help="One non-English locale declared by the accepted contract.",
        )
        if mode != "verify":
            command.add_argument(
                "--refresh-key",
                action="append",
                default=[],
                help="Re-translate one exact accepted contract key.",
            )
            command.add_argument(
                "--provider",
                choices=("auto", "official", "public"),
                default="auto",
                help=(
                    "Translation provider. auto uses the API key header when set "
                    "and otherwise uses the public endpoint."
                ),
            )
            command.add_argument(
                "--delay",
                type=float,
                default=0.08,
                help="Delay in seconds between public provider calls.",
            )
    return parser


def _refuse_legacy_or_path_options(arguments: list[str]) -> None:
    forbidden_paths = {
        "--contract",
        "--i18n",
        "--index",
        "--output",
        "--output-path",
        "--repo",
        "--validator",
    }
    for argument in arguments:
        option = argument.split("=", 1)[0]
        if option == "--write":
            raise TranslationTransportError(
                "legacy --write to web/i18n/major.json is permanently refused"
            )
        if option in forbidden_paths:
            raise TranslationTransportError(
                "caller-selected contract, input, repository, or output paths are refused"
            )


def _production_repository_root() -> Path:
    script = Path(os.path.abspath(__file__))
    try:
        metadata = os.lstat(script)
    except OSError as exc:
        raise TranslationTransportError(
            "translation filler path is unavailable"
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise TranslationTransportError(
            "translation filler must be one regular single-link file"
        )
    return script.parent.parent


def _ascii_text(value: object) -> str:
    return str(value).encode("ascii", errors="backslashreplace").decode("ascii")


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        _refuse_legacy_or_path_options(arguments)
        args = _command_parser().parse_args(arguments)
        result = _run_operation(
            _production_repository_root(),
            mode=args.mode,
            requested_locales=args.locale,
            refresh_keys=getattr(args, "refresh_key", []),
            provider=getattr(args, "provider", "auto"),
            api_key=(
                None
                if args.mode == "verify"
                else os.environ.get("GOOGLE_TRANSLATE_API_KEY")
            ),
            delay=getattr(args, "delay", 0.08),
        )
    except TranslationTransportError as exc:
        print(
            _ascii_text(f"website-translation-fill: {exc}"),
            file=sys.stderr,
        )
        return 1
    action = {
        "dry-run": "dry_run",
        "create": "created",
        "verify": "verified",
    }[result.mode]
    print(
        _ascii_text(
            f"locale_source_{action} path={result.output_path} "
            f"locale={result.locale} keys={result.key_count} "
            f"seeded={result.seeded_count} translated={result.translated_count} "
            f"sanitized={result.sanitized_count} bytes={result.payload_size} "
            f"sha256={result.payload_sha256}"
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
