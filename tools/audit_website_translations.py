#!/usr/bin/env python3
"""Audit contract-bound static website translations without changing content.

Dynamic runtime strings are outside this audit. The accepted localization
contract is the sole source of required static translation keys.
"""

from __future__ import annotations

import argparse
import builtins
import errno
import hashlib
import importlib.util
import json
import math
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any, TypedDict


AUDITOR_PATH = "tools/audit_website_translations.py"
CONTRACT_PATH = "localization/website/contract.json"
VALIDATOR_PATH = "tools/website_localization_contract.py"
INDEX_PATH = "web/index.html"
INVENTORY_PATH = "web/i18n/languages.json"
AGGREGATE_PATH = "web/i18n/major.json"
LOCALE_SOURCE_DIRECTORY = "localization/website/locales"
ACCEPTED_CONTRACT_SHA256 = (
    "9ec1a8a461fb17ada914b0626a2561c3d85a1dc6a20585ffaac2ddb454b45b45"
)
ACCEPTED_VALIDATOR_SHA256 = (
    "9a70d57928e534da00f117ac168fb5bfacc5e321c6180be1c2346540e36e6172"
)
ACCEPTED_INDEX_SHA256 = (
    "8f775c2446e9998c4ceba8021a1acc57c5a133b223c134c3a8153a096b964cc2"
)
ACCEPTED_INVENTORY_SHA256 = (
    "d84a285df24c9342d75a5a4d9c090819311cca87c68fa585a0e704db9305b1c9"
)
RELEASE_ROOT = "/Library/WinsVPN/ReleasePython/3.14.7"
RELEASE_LAUNCHER_PATH = f"{RELEASE_ROOT}/launcher/python3"
RELEASE_PREFIX = f"{RELEASE_ROOT}/Python.framework/Versions/3.14"
RELEASE_EXECUTABLE_PATH = f"{RELEASE_PREFIX}/bin/python3.14"
RELEASE_VERSION = (3, 14, 7)
MAX_BOUND_FILE_BYTES = 16 * 1024 * 1024
DEFAULT_REPO_ROOT = Path(__file__).parent.parent
_DIRECT_SCRIPT_ENTRY = __name__ == "__main__" and __spec__ is None

# The accepted contract validator reads this literal set when proving the
# current source classification. It is retained as source evidence only. The
# audit requirement itself comes exclusively from translatable_static_keys.
NON_TRANSLATABLE_KEYS = {
    "$0.99",
    "$11.88",
    "\U0001F1FA\U0001F1F8",
    "24/7/365 IDPS",
    "A+",
    "Android",
    "Aung Phone Myint",
    "CCSP",
    "CISA",
    "CISSP",
    "Coalition Inc.",
    "CySA+",
    "Hoppy",
    "HTB CPTS",
    "HTB CWES",
    "Linux",
    "Linux ARM64",
    "Linux x64",
    "MacBook (macOS)",
    "MacOS",
    "Mr / Mrs X",
    "Network+",
    "PenTest+",
    "S",
    "Sectigo",
    "Sectigo EV",
    "Security+",
    "SecurityX",
    "SSCP",
    "Tier III+",
    "Summary of Version 2026-08-31.v4. Owner approved 2026-08-31. Counsel review pending.",
    "Android Device or other ID disclosure.",
    "After the user accepts the bundled Privacy Policy, the Android app reads the app-scoped",
    "Settings.Secure.ANDROID_ID",
    "and transmits it to Win's VPN with account or free-access identity and device details. It may be linked to the account for app functionality, account management, the three-device limit, fraud prevention, security, and abuse prevention. It is not used for advertising or tracking, sold, or shared for advertising. The hub protects the retained device-limit value; it is deleted or overwritten when the device is deactivated, replaced, or no longer needed.",
    "Win Empire LLC logo",
    "Win's VPN home",
    "Win's VPN\u00ae",
    "Win's VPN\u00ae | AI-Powered No-Logs VPN Made in America",
    "Windows",
    "Windows ARM64",
    "Windows x64",
    "Winn Protocol\u00ae",
    "Ye Yint Myint Mo",
    "Zali Win",
    "iOS",
    "iPhone (iOS)",
    "\u00d7",
}


class TranslationAuditError(ValueError):
    """Raised when an input crosses the accepted static-audit boundary."""

    def __init__(self, message: str) -> None:
        super().__init__(_ascii_text(message))


class AuditSemantics(TypedDict):
    required: tuple[str, ...]
    nontranslatable: tuple[str, ...]
    translate_no_only: tuple[str, ...]
    mixed_context: tuple[str, ...]
    drift_classification: str
    drift_keys: tuple[str, ...]
    locale_order: tuple[str, ...]


class AuditFindings(TypedDict):
    english_missing: list[str]
    english_identity_mismatch: list[str]
    english_out_of_contract: list[str]
    targets: list[tuple[str, list[str], list[str], list[str]]]
    integrity: list[tuple[str, str, str]]


# Translation integrity. These checks cover every value in the aggregate,
# contract-bound or not, because every value ships in web/i18n/locales.
# Mirrors the refusal rules in tools/fill_website_translations.py.
#
# Placeholder envelopes leaked by machine translation: ZXQ...QXZ forms,
# ZZZWINVPPNPLAINZZZ, ZZWINNPROTOCOLZZZ, ZZZPAYPAYPALZZZ, ZZIOSZZZZ, the
# Cyrillic ZZZ-wrapped form, WINSVPN_BRAND forms, glued BRAND markers and
# long capital runs such as ANDROIDMARKA. Case sensitive, so Italian and
# Hungarian words such as "utilizza" or "hozza" stay legal. A token that
# also occurs in the English source is not a leak.
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
# the end of a Latin word (ZAndroid, ZiOS, ZWin's VPN, AndroidZ, Protocol(R)Z,
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
# source: never translated, transliterated, dropped, duplicated or mangled.
# Longer forms of the same name are counted separately from shorter ones.
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
# "... (Win's VPN)." or "... (Winn Protocol(R)).".
TRAILING_BRACKET_RE = re.compile(r"\(([^()]*)\)[\s.!?\u3002\u0964\u104b]*$")
# A long value that two locales share word for word was copied from one
# language into another (Spanish banner text shipped in 20 locales).
CROSS_LOCALE_COPY_MIN_CHARS = 40


def translation_integrity_defects(source: str, translated: str) -> list[str]:
    """Return every placeholder, contamination or protected-name defect."""

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


def catalog_integrity_findings(
    translations: dict[str, dict[str, str]],
) -> list[tuple[str, str, str]]:
    """Return (locale, defect, English key) for every defective target value."""

    findings: list[tuple[str, str, str]] = []
    for locale, mapping in translations.items():
        if locale == "en":
            continue
        for key, translated in mapping.items():
            for defect in translation_integrity_defects(key, translated):
                findings.append((locale, defect, key))
    shared: dict[tuple[str, str], list[str]] = {}
    for locale, mapping in translations.items():
        if locale == "en":
            continue
        for key, translated in mapping.items():
            if translated != key and len(translated) >= CROSS_LOCALE_COPY_MIN_CHARS:
                shared.setdefault((key, translated), []).append(locale)
    for (key, _translated), locales in shared.items():
        if len(locales) > 1:
            for locale in locales:
                others = ",".join(item for item in locales if item != locale)
                findings.append(
                    (locale, f"value copied word for word in {others}", key)
                )
    return findings


def _ascii_text(value: str) -> str:
    """Render text as printable deterministic ASCII without line injection."""

    output: list[str] = []
    for character in value:
        codepoint = ord(character)
        if 0x20 <= codepoint <= 0x7E:
            output.append(character)
        elif codepoint == 0x09:
            output.append("\\t")
        elif codepoint <= 0xFF:
            output.append(f"\\x{codepoint:02x}")
        elif codepoint <= 0xFFFF:
            output.append(f"\\u{codepoint:04x}")
        else:
            output.append(f"\\U{codepoint:08x}")
    return "".join(output)


def _ascii_repr(value: object) -> str:
    return _ascii_text(ascii(value))


def _emit_ascii(stream: object, message: str) -> None:
    stream.write(_ascii_text(message) + "\n")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise TranslationAuditError(
                f"duplicate JSON key: {_ascii_repr(key)}"
            )
        result[key] = value
    return result


def _reject_non_finite_constant(value: str) -> object:
    raise TranslationAuditError(f"non-finite JSON value is forbidden: {value}")


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise TranslationAuditError(f"non-finite JSON value is forbidden: {value}")
    return parsed


def _reject_surrogates(value: object, location: str = "$") -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise TranslationAuditError(f"Unicode surrogate is forbidden at {location}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _reject_surrogates(item, f"{location}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_surrogates(key, f"{location}.<key>")
            _reject_surrogates(item, f"{location}.{key}")


def strict_json_loads(payload: bytes | str, *, label: str) -> object:
    """Decode strict UTF-8 JSON with duplicate and non-finite rejection."""

    if isinstance(payload, bytes):
        if payload.startswith(b"\xef\xbb\xbf"):
            raise TranslationAuditError(f"{label} must not contain a BOM")
        try:
            text = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise TranslationAuditError(f"{label} is not strict UTF-8") from exc
    elif isinstance(payload, str):
        text = payload
    else:
        raise TranslationAuditError(f"{label} must be bytes or text")

    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_constant,
            parse_float=_parse_finite_float,
        )
    except TranslationAuditError:
        raise
    except json.JSONDecodeError as exc:
        raise TranslationAuditError(f"malformed {label}: {exc.msg}") from exc
    _reject_surrogates(document)
    return document


def _validate_translation_document(
    document: object,
    *,
    label: str,
) -> dict[str, dict[str, str]]:
    if not isinstance(document, dict):
        raise TranslationAuditError(f"{label} root must be an object")

    translations: dict[str, dict[str, str]] = {}
    for locale, mapping in document.items():
        if not isinstance(locale, str) or not locale:
            raise TranslationAuditError(f"{label} contains an invalid locale key")
        if not isinstance(mapping, dict):
            raise TranslationAuditError(
                f"locale {locale!r} translations must be an object"
            )
        for source, translated in mapping.items():
            if not isinstance(source, str) or not source:
                raise TranslationAuditError(
                    f"locale {locale!r} contains an invalid source key"
                )
            if not isinstance(translated, str):
                raise TranslationAuditError(
                    f"locale {locale!r} translation {source!r} must be a string"
                )
        translations[locale] = mapping
    return translations


def load_translations(i18n_json: Path) -> dict[str, dict[str, str]]:
    """Load a strict locale-to-string-map JSON document."""

    try:
        payload = i18n_json.read_bytes()
    except OSError as exc:
        raise TranslationAuditError("locale JSON is unavailable") from exc
    document = strict_json_loads(payload, label="locale JSON")
    return _validate_translation_document(document, label="locale JSON")


def _validate_relative_path(value: str, *, label: str) -> str:
    if not value or "\\" in value or "\x00" in value:
        raise TranslationAuditError(f"{label} is not a safe relative path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or not path.parts
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise TranslationAuditError(f"{label} is not a safe relative path")
    return value


def _stat_identity(metadata: os.stat_result) -> tuple[object, ...]:
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
        getattr(metadata, "st_flags", None),
    )


class _HeldDescriptor:
    def __init__(
        self,
        *,
        fd: int,
        parent_fd: int | None,
        name: str | None,
        display: str,
        metadata: os.stat_result,
        directory: bool,
    ) -> None:
        self.fd = fd
        self.parent_fd = parent_fd
        self.name = name
        self.display = display
        self.identity = _stat_identity(metadata)
        self.directory = directory


class BoundTree:
    """Hold a no-follow descriptor closure and detect any operation-time swap."""

    def __init__(
        self,
        root: Path,
        *,
        label: str,
        root_owned: bool = False,
    ) -> None:
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory_flag = getattr(os, "O_DIRECTORY", None)
        if nofollow is None or directory_flag is None:
            raise TranslationAuditError(
                "this platform cannot enforce no-follow descriptor reads"
            )
        raw_root = os.fspath(root)
        if not os.path.isabs(raw_root) or PurePosixPath(raw_root).as_posix() != raw_root:
            raise TranslationAuditError(f"{label} must be an exact absolute path")
        self.root_path = raw_root
        self.label = label
        self._root_owned = root_owned
        self._directory_flags = (
            os.O_RDONLY
            | os.O_NONBLOCK
            | getattr(os, "O_CLOEXEC", 0)
            | nofollow
            | directory_flag
        )
        self._file_flags = (
            os.O_RDONLY
            | os.O_NONBLOCK
            | getattr(os, "O_CLOEXEC", 0)
            | nofollow
        )
        self._entries: list[_HeldDescriptor] = []
        self._directories: dict[tuple[str, ...], _HeldDescriptor] = {}
        self._files: dict[str, _HeldDescriptor] = {}
        self._absences: dict[tuple[int, str], str] = {}
        self.payloads: dict[str, bytes] = {}
        self._closed = False
        try:
            self._open_absolute_root_chain()
        except BaseException:
            self.close()
            raise

    def __enter__(self) -> BoundTree:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def _validate_metadata(
        self,
        metadata: os.stat_result,
        *,
        display: str,
        directory: bool,
    ) -> None:
        expected_kind = stat.S_ISDIR if directory else stat.S_ISREG
        if not expected_kind(metadata.st_mode):
            kind = "directory" if directory else "regular file"
            raise TranslationAuditError(f"{display} is not a {kind}")
        if not directory and metadata.st_nlink != 1:
            raise TranslationAuditError(f"{display} must have exactly one hard link")
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise TranslationAuditError(f"{display} has unsafe writable permissions")
        allowed_owners = {0} if self._root_owned else {0, os.geteuid()}
        if metadata.st_uid not in allowed_owners:
            raise TranslationAuditError(f"{display} has an unsafe owner")

    def _register(
        self,
        fd: int,
        *,
        parent_fd: int | None,
        name: str | None,
        display: str,
        directory: bool,
    ) -> _HeldDescriptor:
        try:
            metadata = os.fstat(fd)
            self._validate_metadata(metadata, display=display, directory=directory)
        except BaseException:
            os.close(fd)
            raise
        entry = _HeldDescriptor(
            fd=fd,
            parent_fd=parent_fd,
            name=name,
            display=display,
            metadata=metadata,
            directory=directory,
        )
        self._entries.append(entry)
        return entry

    def _open_absolute_root_chain(self) -> None:
        try:
            root_fd = os.open("/", self._directory_flags)
        except OSError as exc:
            raise TranslationAuditError("filesystem root is unavailable or unsafe") from exc
        root_entry = self._register(
            root_fd,
            parent_fd=None,
            name=None,
            display="/",
            directory=True,
        )
        current = root_entry
        display = ""
        parts = PurePosixPath(self.root_path).parts[1:]
        for component in parts:
            display = f"{display}/{component}"
            try:
                directory_fd = os.open(
                    component,
                    self._directory_flags,
                    dir_fd=current.fd,
                )
            except OSError as exc:
                raise TranslationAuditError(
                    f"{self.label} ancestor is unavailable or unsafe: {display}"
                ) from exc
            current = self._register(
                directory_fd,
                parent_fd=current.fd,
                name=component,
                display=display,
                directory=True,
            )
        self._root = current
        self._directories[()] = current

    def _directory(self, parts: tuple[str, ...]) -> _HeldDescriptor:
        if parts in self._directories:
            return self._directories[parts]
        parent = self._directory(parts[:-1])
        component = parts[-1]
        display = f"{self.root_path}/{'/'.join(parts)}"
        try:
            directory_fd = os.open(
                component,
                self._directory_flags,
                dir_fd=parent.fd,
            )
        except OSError as exc:
            raise TranslationAuditError(
                f"repository parent is unavailable or unsafe: {display}"
            ) from exc
        entry = self._register(
            directory_fd,
            parent_fd=parent.fd,
            name=component,
            display=display,
            directory=True,
        )
        self._directories[parts] = entry
        return entry

    def optional_directory(self, relative_path: str, *, label: str) -> bool:
        relative = _validate_relative_path(relative_path, label=f"{label} path")
        parts = PurePosixPath(relative).parts
        parent = self._directory(parts[:-1])
        display = f"{self.root_path}/{relative}"
        try:
            directory_fd = os.open(
                parts[-1],
                self._directory_flags,
                dir_fd=parent.fd,
            )
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                self._absences[(parent.fd, parts[-1])] = display
                return False
            raise TranslationAuditError(f"{label} is unavailable or unsafe") from exc
        entry = self._register(
            directory_fd,
            parent_fd=parent.fd,
            name=parts[-1],
            display=display,
            directory=True,
        )
        self._directories[parts] = entry
        return True

    def open_file(
        self,
        relative_path: str,
        *,
        label: str,
        optional: bool = False,
    ) -> _HeldDescriptor | None:
        relative = _validate_relative_path(relative_path, label=f"{label} path")
        if relative in self._files:
            return self._files[relative]
        parts = PurePosixPath(relative).parts
        parent = self._directory(parts[:-1])
        display = f"{self.root_path}/{relative}"
        try:
            file_fd = os.open(parts[-1], self._file_flags, dir_fd=parent.fd)
        except OSError as exc:
            if optional and exc.errno == errno.ENOENT:
                self._absences[(parent.fd, parts[-1])] = display
                return None
            raise TranslationAuditError(f"{label} is missing or unsafe") from exc
        entry = self._register(
            file_fd,
            parent_fd=parent.fd,
            name=parts[-1],
            display=display,
            directory=False,
        )
        self._files[relative] = entry
        return entry

    def _read_entry(
        self,
        entry: _HeldDescriptor,
        *,
        label: str,
        max_bytes: int,
    ) -> bytes:
        before = os.fstat(entry.fd)
        if _stat_identity(before) != entry.identity:
            raise TranslationAuditError(f"{label} changed before it was read")
        if before.st_size > max_bytes:
            raise TranslationAuditError(f"{label} exceeds the size limit")
        os.lseek(entry.fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(entry.fd, min(1024 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise TranslationAuditError(f"{label} exceeds the size limit")
        after = os.fstat(entry.fd)
        if _stat_identity(after) != entry.identity:
            raise TranslationAuditError(f"{label} changed while it was read")
        payload = b"".join(chunks)
        if len(payload) != before.st_size:
            raise TranslationAuditError(f"{label} changed while it was read")
        return payload

    def read_file(
        self,
        relative_path: str,
        *,
        label: str,
        expected_sha256: str | None = None,
        optional: bool = False,
        max_bytes: int = MAX_BOUND_FILE_BYTES,
    ) -> bytes | None:
        entry = self.open_file(relative_path, label=label, optional=optional)
        if entry is None:
            return None
        payload = self._read_entry(entry, label=label, max_bytes=max_bytes)
        actual_sha256 = hashlib.sha256(payload).hexdigest()
        if expected_sha256 is not None and actual_sha256 != expected_sha256:
            raise TranslationAuditError(
                f"{label} SHA-256 mismatch: expected {expected_sha256}, "
                f"got {actual_sha256}"
            )
        self.payloads[relative_path] = payload
        return payload

    def list_directory(self, relative_path: str, *, label: str) -> tuple[str, ...]:
        relative = _validate_relative_path(relative_path, label=f"{label} path")
        entry = self._directory(PurePosixPath(relative).parts)
        before = os.fstat(entry.fd)
        try:
            names = os.listdir(entry.fd)
        except OSError as exc:
            raise TranslationAuditError(f"{label} cannot be inventoried") from exc
        after = os.fstat(entry.fd)
        if _stat_identity(before) != entry.identity or _stat_identity(after) != entry.identity:
            raise TranslationAuditError(f"{label} changed while it was inventoried")
        if not all(isinstance(name, str) for name in names):
            raise TranslationAuditError(f"{label} contains an invalid entry name")
        return tuple(sorted(names))

    def descriptor(self, relative_path: str) -> int:
        try:
            return self._files[relative_path].fd
        except KeyError as exc:
            raise TranslationAuditError(
                f"repository closure does not hold {relative_path}"
            ) from exc

    def revalidate(self) -> None:
        for entry in self._entries:
            try:
                current = os.fstat(entry.fd)
            except OSError as exc:
                raise TranslationAuditError(
                    f"held descriptor became unavailable: {entry.display}"
                ) from exc
            if _stat_identity(current) != entry.identity:
                raise TranslationAuditError(
                    f"held descriptor mutated during audit: {entry.display}"
                )
            if entry.parent_fd is None or entry.name is None:
                continue
            try:
                pathname = os.stat(
                    entry.name,
                    dir_fd=entry.parent_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise TranslationAuditError(
                    f"held path was removed or substituted: {entry.display}"
                ) from exc
            if _stat_identity(pathname) != entry.identity:
                raise TranslationAuditError(
                    f"held path was removed or substituted: {entry.display}"
                )
        for (parent_fd, name), display in self._absences.items():
            try:
                os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise TranslationAuditError(
                    f"absent path became unsafe during audit: {display}"
                ) from exc
            raise TranslationAuditError(f"absent path appeared during audit: {display}")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for entry in reversed(self._entries):
            try:
                os.close(entry.fd)
            except OSError:
                pass


def _require_authoritative_path(actual: str, expected: str, *, label: str) -> None:
    if actual != expected:
        raise TranslationAuditError(
            f"{label} path substitution rejected: expected {expected}"
        )


def _absolute_lexical_path(path: Path) -> Path:
    raw = os.fspath(path)
    candidate = raw if os.path.isabs(raw) else os.path.join(os.getcwd(), raw)
    return Path(os.path.normpath(candidate))


def _valid_instant_locale_code(value: str) -> bool:
    parts = value.split("-")
    language = parts[0]
    if (
        len(language) not in (2, 3)
        or any(character < "a" or character > "z" for character in language)
    ):
        return False
    return len(parts) == 1 or (
        len(parts) == 2
        and len(parts[1]) == 2
        and all("A" <= character <= "Z" for character in parts[1])
    )


def _contract_locale_order(document: dict[str, Any]) -> tuple[str, ...]:
    try:
        inventory = document["instant_locale_inventory"]
        compiler = document["compiler_output"]
        if not isinstance(inventory, dict) or not isinstance(compiler, dict):
            raise TypeError
        locale_items = inventory["locales"]
        compiler_order = compiler["locale_order"]
    except (KeyError, TypeError) as exc:
        raise TranslationAuditError("contract locale fields are incomplete") from exc
    if not isinstance(locale_items, list) or not locale_items:
        raise TranslationAuditError("contract locale inventory is invalid")

    inventory_order: list[str] = []
    for index, item in enumerate(locale_items):
        if not isinstance(item, dict) or tuple(item) != ("code", "name"):
            raise TranslationAuditError(
                f"contract instant locale descriptor is invalid at index {index}"
            )
        code = item["code"]
        name = item["name"]
        if (
            not isinstance(code, str)
            or not _valid_instant_locale_code(code)
            or not isinstance(name, str)
            or not name
            or name != name.strip()
        ):
            raise TranslationAuditError(
                f"contract instant locale descriptor is invalid at index {index}"
            )
        inventory_order.append(code)
    if (
        inventory_order[0] != "en"
        or len(inventory_order) != len(set(inventory_order))
        or not isinstance(compiler_order, list)
        or compiler_order != inventory_order
    ):
        raise TranslationAuditError("contract language/instant order is invalid")
    return tuple(inventory_order)


def _contract_locale_targets(
    document: object,
) -> tuple[tuple[str, str], ...]:
    if not isinstance(document, dict):
        raise TranslationAuditError("localization contract root must be an object")
    try:
        english = document["english_source"]
        inventory = document["instant_locale_inventory"]
        locale_sources = document["locale_sources"]
        compiler = document["compiler_output"]
        if not all(
            isinstance(item, dict)
            for item in (english, inventory, locale_sources, compiler)
        ):
            raise TypeError
        if (
            english["path"] != INDEX_PATH
            or english["file_sha256"] != ACCEPTED_INDEX_SHA256
            or inventory["path"] != INVENTORY_PATH
            or inventory["file_sha256"] != ACCEPTED_INVENTORY_SHA256
            or compiler["path"] != AGGREGATE_PATH
        ):
            raise TranslationAuditError("contract source paths or hashes are not accepted")
        target_items = locale_sources["targets"]
        if not isinstance(target_items, list):
            raise TypeError
    except (KeyError, TypeError) as exc:
        raise TranslationAuditError("contract source closure fields are incomplete") from exc
    locale_order = _contract_locale_order(document)
    targets: list[tuple[str, str]] = []
    for index, item in enumerate(target_items):
        if not isinstance(item, dict) or tuple(item) != ("locale", "path"):
            raise TranslationAuditError(
                f"locale-source descriptor is invalid at index {index}"
            )
        locale = item["locale"]
        path = item["path"]
        if not isinstance(locale, str) or not isinstance(path, str):
            raise TranslationAuditError(
                f"locale-source descriptor is invalid at index {index}"
            )
        _validate_relative_path(path, label=f"locale source {_ascii_repr(locale)}")
        if path != f"{LOCALE_SOURCE_DIRECTORY}/{locale}.json":
            raise TranslationAuditError(
                f"locale-source path is not deterministic: {_ascii_text(locale)}"
            )
        targets.append((locale, path))
    if tuple(locale for locale, _ in targets) != locale_order[1:]:
        raise TranslationAuditError(
            "locale-source descriptors do not match the locale inventory"
        )
    return tuple(targets)


def _capture_repository_inputs(
    tree: BoundTree,
) -> tuple[dict[str, Any], tuple[tuple[str, str], ...], tuple[str, ...]]:
    auditor_payload = tree.read_file(AUDITOR_PATH, label="audit source")
    validator_payload = tree.read_file(
        VALIDATOR_PATH,
        label="contract validator",
        expected_sha256=ACCEPTED_VALIDATOR_SHA256,
    )
    contract_payload = tree.read_file(
        CONTRACT_PATH,
        label="localization contract",
        expected_sha256=ACCEPTED_CONTRACT_SHA256,
    )
    index_payload = tree.read_file(
        INDEX_PATH,
        label="English source",
        expected_sha256=ACCEPTED_INDEX_SHA256,
    )
    inventory_payload = tree.read_file(
        INVENTORY_PATH,
        label="locale inventory",
        expected_sha256=ACCEPTED_INVENTORY_SHA256,
    )
    aggregate_payload = tree.read_file(
        AGGREGATE_PATH,
        label="translation aggregate",
    )
    if any(
        payload is None
        for payload in (
            auditor_payload,
            validator_payload,
            contract_payload,
            index_payload,
            inventory_payload,
            aggregate_payload,
        )
    ):
        raise TranslationAuditError("required repository closure is incomplete")
    contract_document = strict_json_loads(
        contract_payload,
        label=CONTRACT_PATH,
    )
    if not isinstance(contract_document, dict):
        raise TranslationAuditError("localization contract root must be an object")
    targets = _contract_locale_targets(contract_document)
    missing: list[str] = []
    if tree.optional_directory(
        LOCALE_SOURCE_DIRECTORY,
        label="locale-source directory",
    ):
        actual_names = tree.list_directory(
            LOCALE_SOURCE_DIRECTORY,
            label="locale-source directory",
        )
        expected_names = tuple(sorted(PurePosixPath(path).name for _, path in targets))
        unexpected = sorted(set(actual_names) - set(expected_names))
        if unexpected:
            detail = ", ".join(_ascii_text(name) for name in unexpected)
            raise TranslationAuditError(
                f"locale-source directory contains unexpected entries: {detail}"
            )
        for locale, path in targets:
            payload = tree.read_file(
                path,
                label=f"locale source {_ascii_text(locale)}",
                optional=True,
            )
            if payload is None:
                missing.append(locale)
    else:
        missing.extend(locale for locale, _ in targets)
    return contract_document, targets, tuple(missing)


def _load_accepted_validator(tree: BoundTree) -> Any:
    try:
        tree.revalidate()
    except BaseException as exc:
        raise TranslationAuditError(
            "accepted contract validator pre-load revalidation failed"
        ) from exc
    payload = tree.payloads.get(VALIDATOR_PATH)
    if (
        type(payload) is not bytes
        or hashlib.sha256(payload).hexdigest() != ACCEPTED_VALIDATOR_SHA256
    ):
        raise TranslationAuditError("accepted contract validator is not retained")
    source_origin = f"<retained:{VALIDATOR_PATH}>"
    name = "_winsvpn_retained_website_localization_contract"
    spec = importlib.util.spec_from_loader(name, loader=None, origin=source_origin)
    if spec is None:
        raise TranslationAuditError("accepted contract validator could not load")
    module = importlib.util.module_from_spec(spec)
    load_failure: BaseException | None = None
    try:
        code = builtins.compile(
            payload,
            source_origin,
            "exec",
            flags=0,
            dont_inherit=True,
            optimize=0,
        )
        builtins.exec(code, module.__dict__, module.__dict__)
        required_interface = (
            "WebsiteLocalizationContractError",
            "strict_json_loads",
            "canonical_json_bytes",
            "validate_contract_document",
            "build_expected_contract",
            "_first_difference",
            "validate_aggregate_envelope",
            "load_validated_locale_source",
            "validate_compiler_output",
        )
        if any(not hasattr(module, item) for item in required_interface):
            raise TranslationAuditError(
                "accepted contract validator interface is incomplete"
            )
    except BaseException as exc:
        load_failure = exc
    try:
        tree.revalidate()
    except BaseException as exc:
        raise TranslationAuditError(
            "accepted contract validator post-load revalidation failed"
        ) from exc
    if load_failure is not None:
        raise TranslationAuditError(
            "accepted contract validator could not load"
        ) from load_failure
    return module


def _configure_retained_validator(module: Any, tree: BoundTree) -> None:
    validator_error = module.WebsiteLocalizationContractError

    def retained_reader(
        repo: Path,
        relative_path: str,
        *,
        max_bytes: int = MAX_BOUND_FILE_BYTES,
    ) -> bytes:
        del repo
        try:
            payload = tree.payloads[relative_path]
        except (KeyError, TypeError) as exc:
            raise validator_error(
                f"repository closure has no retained file: {_ascii_repr(relative_path)}"
            ) from exc
        if len(payload) > max_bytes:
            raise validator_error(
                f"retained repository file is too large: {_ascii_text(relative_path)}"
            )
        return payload

    module.read_repository_file = retained_reader


def load_bound_contract_and_translations(
    repo: Path,
    *,
    contract_path: str = CONTRACT_PATH,
    validator_path: str = VALIDATOR_PATH,
    index_path: str = INDEX_PATH,
    aggregate_path: str = AGGREGATE_PATH,
) -> tuple[dict[str, Any], dict[str, dict[str, str]]]:
    """Load retained bytes for pure diagnostics, never production authority."""

    _require_authoritative_path(contract_path, CONTRACT_PATH, label="contract")
    _require_authoritative_path(
        validator_path,
        VALIDATOR_PATH,
        label="contract validator",
    )
    _require_authoritative_path(index_path, INDEX_PATH, label="English source")
    _require_authoritative_path(
        aggregate_path,
        AGGREGATE_PATH,
        label="translation aggregate",
    )
    root = _absolute_lexical_path(repo)
    with BoundTree(root, label="repository root") as tree:
        contract, _, _ = _capture_repository_inputs(tree)
        aggregate_payload = tree.payloads[AGGREGATE_PATH]
        aggregate = strict_json_loads(aggregate_payload, label=AGGREGATE_PATH)
        tree.revalidate()
    translations = _validate_translation_document(
        aggregate,
        label=AGGREGATE_PATH,
    )
    audit_translations(contract, translations)
    return contract, translations


def _validate_retained_repository(
    tree: BoundTree,
    contract_document: dict[str, Any],
    targets: tuple[tuple[str, str], ...],
    missing_locales: tuple[str, ...],
) -> tuple[dict[str, Any], dict[str, dict[str, str]], bool]:
    validator = _load_accepted_validator(tree)
    _configure_retained_validator(validator, tree)
    validator_error = validator.WebsiteLocalizationContractError
    contract_payload = tree.payloads[CONTRACT_PATH]
    aggregate_payload = tree.payloads[AGGREGATE_PATH]
    try:
        parsed_contract = validator.strict_json_loads(
            contract_payload,
            label=CONTRACT_PATH,
        )
        contract = validator.validate_contract_document(parsed_contract)
        if parsed_contract != contract_document:
            raise validator_error("retained contract parsers disagree")
        if contract_payload != validator.canonical_json_bytes(
            contract,
            ensure_ascii=True,
        ):
            raise validator_error("contract JSON is not in canonical ASCII/LF order")
        expected = validator.build_expected_contract(Path(tree.root_path))
        difference = validator._first_difference(contract, expected)
        if difference is not None:
            raise validator_error(
                f"contract does not match the retained source closure at {difference}"
            )
        aggregate = validator.validate_aggregate_envelope(
            Path(tree.root_path),
            contract,
        )
        missing = set(missing_locales)
        for locale, _ in targets:
            if locale not in missing:
                validator.load_validated_locale_source(
                    Path(tree.root_path),
                    locale=locale,
                    contract=contract,
                )
        compiler_validated = False
        if not missing_locales:
            validated_output = validator.validate_compiler_output(
                Path(tree.root_path),
                contract,
            )
            if aggregate_payload != validator.canonical_json_bytes(
                validated_output,
                ensure_ascii=False,
            ):
                raise validator_error(
                    "compiler output is not canonical UTF-8/LF JSON"
                )
            if validated_output != aggregate:
                raise validator_error("compiler validators returned different output")
            compiler_validated = True
    except validator_error as exc:
        raise TranslationAuditError(
            f"localization contract or compiler closure rejected: {_ascii_text(str(exc))}"
        ) from exc
    except BaseException as exc:
        raise TranslationAuditError(
            "localization contract validator failed closed"
        ) from exc
    translations = _validate_translation_document(aggregate, label=AGGREGATE_PATH)
    tree.revalidate()
    return contract, translations, compiler_validated


def _sorted_unique_strings(value: object, *, label: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not all(isinstance(item, str) and item for item in value)
    ):
        raise TranslationAuditError(f"{label} must be an array of strings")
    if value != sorted(value) or len(value) != len(set(value)):
        raise TranslationAuditError(f"{label} must be sorted and unique")
    return tuple(value)


def contract_audit_semantics(contract: dict[str, Any]) -> AuditSemantics:
    """Extract and independently check the static-audit contract semantics."""

    try:
        classification = contract["key_classification"]
        if not isinstance(classification, dict):
            raise TypeError
        required = _sorted_unique_strings(
            classification["translatable_static_keys"],
            label="translatable static keys",
        )
        nontranslatable = _sorted_unique_strings(
            classification["nontranslatable_static_keys"],
            label="nontranslatable static keys",
        )
        translate_no_only = _sorted_unique_strings(
            classification["inherited_translate_no_only_keys"],
            label="inherited translate=no-only keys",
        )
        mixed_context = _sorted_unique_strings(
            classification["mixed_translate_context_keys"],
            label="mixed translate-context keys",
        )
        drift = classification["runtime_audit_nontranslatable_drift"]
        if not isinstance(drift, dict):
            raise TypeError
        drift_keys = _sorted_unique_strings(
            drift["keys"],
            label="runtime/audit exclusion drift keys",
        )
    except (KeyError, TypeError) as exc:
        raise TranslationAuditError("contract audit fields are incomplete") from exc

    required_set = set(required)
    nontranslatable_set = set(nontranslatable)
    translate_no_only_set = set(translate_no_only)
    if (
        required_set & nontranslatable_set
        or required_set & translate_no_only_set
        or nontranslatable_set & translate_no_only_set
    ):
        raise TranslationAuditError("contract primary static classifications overlap")
    if not set(mixed_context).issubset(required_set):
        raise TranslationAuditError(
            "mixed translate-context keys are not all required translations"
        )
    unresolved_drift = sorted(
        (set(drift_keys) - nontranslatable_set)
        | (set(drift_keys) & required_set)
    )
    if drift.get("classification") != "nontranslatable" or unresolved_drift:
        detail = ", ".join(_ascii_text(key) for key in unresolved_drift)
        raise TranslationAuditError(
            "runtime/audit exclusion drift is unresolved"
            + (f": {detail}" if detail else "")
        )
    locale_order = _contract_locale_order(contract)
    return {
        "required": required,
        "nontranslatable": nontranslatable,
        "translate_no_only": translate_no_only,
        "mixed_context": mixed_context,
        "drift_classification": drift["classification"],
        "drift_keys": drift_keys,
        "locale_order": locale_order,
    }


def audit_translations(
    contract: dict[str, Any],
    translations: dict[str, dict[str, str]],
) -> tuple[AuditSemantics, AuditFindings]:
    """Return exact accepted-contract parity failures for every locale."""

    translations = _validate_translation_document(
        translations,
        label=AGGREGATE_PATH,
    )
    semantics = contract_audit_semantics(contract)
    locale_order = list(semantics["locale_order"])
    if list(translations) != locale_order:
        raise TranslationAuditError(
            "translation aggregate language order does not match the contract"
        )
    required = semantics["required"]
    required_set = set(required)
    english = translations["en"]
    english_missing = [key for key in required if key not in english]
    english_identity_mismatch = [
        key for key in required if key in english and english[key] != key
    ]
    english_out_of_contract = sorted(set(english) - required_set)
    results: list[tuple[str, list[str], list[str], list[str]]] = []
    for locale in locale_order[1:]:
        mapping = translations[locale]
        missing: list[str] = []
        english_fallback: list[str] = []
        for key in required:
            if key not in mapping:
                missing.append(key)
                continue
            translated = mapping[key]
            if not translated or translated != translated.strip():
                raise TranslationAuditError(
                    f"locale {_ascii_repr(locale)} required translation "
                    f"{_ascii_repr(key)} "
                    "must be nonempty and trimmed"
                )
            if translated == key:
                english_fallback.append(key)
        out_of_contract = sorted(set(mapping) - required_set)
        results.append((locale, missing, english_fallback, out_of_contract))
    return semantics, {
        "english_missing": english_missing,
        "english_identity_mismatch": english_identity_mismatch,
        "english_out_of_contract": english_out_of_contract,
        "targets": results,
        "integrity": catalog_integrity_findings(translations),
    }


def report_audit(
    contract: dict[str, Any],
    translations: dict[str, dict[str, str]],
    *,
    show: int,
) -> int:
    if show < 0:
        raise TranslationAuditError("--show must be zero or greater")
    semantics, findings = audit_translations(contract, translations)
    required = semantics["required"]
    nontranslatable = semantics["nontranslatable"]
    translate_no_only = semantics["translate_no_only"]
    mixed_context = semantics["mixed_context"]
    drift_keys = semantics["drift_keys"]
    visible_count = len(required) + len(nontranslatable) + len(translate_no_only)

    _emit_ascii(sys.stdout, f"visible_keys={visible_count} languages={len(translations)}")
    _emit_ascii(
        sys.stdout,
        "contract_bindings "
        f"contract_sha256={ACCEPTED_CONTRACT_SHA256} "
        f"validator_sha256={ACCEPTED_VALIDATOR_SHA256}",
    )
    _emit_ascii(
        sys.stdout,
        "contract_counts "
        f"translatable_static_keys={len(required)} "
        f"nontranslatable_static_keys={len(nontranslatable)} "
        f"inherited_translate_no_only_keys={len(translate_no_only)} "
        f"mixed_translate_context_keys={len(mixed_context)} "
        f"instant_locales={len(semantics['locale_order'])} "
        f"target_locales={len(semantics['locale_order']) - 1}",
    )
    _emit_ascii(
        sys.stdout,
        "runtime_audit_exclusion_drift "
        f"classification={semantics['drift_classification']} "
        f"keys={len(drift_keys)} unresolved=0",
    )
    for key in drift_keys:
        _emit_ascii(sys.stdout, f"  - {key}")
    _emit_ascii(
        sys.stdout,
        "scope=contract_bound_static_keys dynamic_runtime_strings=not_covered "
        "aggregate_extra_keys=out_of_contract_not_dynamic",
    )
    _emit_ascii(sys.stdout, "diagnostic_result_authority=NONE")

    english_missing = findings["english_missing"]
    english_identity_mismatch = findings["english_identity_mismatch"]
    english_out_of_contract = findings["english_out_of_contract"]
    english_contract_failures = (
        len(english_missing)
        + len(english_identity_mismatch)
        + len(english_out_of_contract)
    )
    _emit_ascii(
        sys.stdout,
        "en_contract_parity "
        f"failures={english_contract_failures} "
        f"missing={len(english_missing)} "
        f"identity_mismatch={len(english_identity_mismatch)} "
        f"out_of_contract={len(english_out_of_contract)}",
    )
    for key in (
        english_missing + english_identity_mismatch + english_out_of_contract
    )[:show]:
        _emit_ascii(sys.stdout, f"  - {key}")

    aggregate_missing = 0
    aggregate_fallback = 0
    aggregate_out_of_contract = len(english_out_of_contract)
    for locale, missing, english_fallback, out_of_contract in findings["targets"]:
        total = len(missing) + len(english_fallback)
        aggregate_missing += len(missing)
        aggregate_fallback += len(english_fallback)
        aggregate_out_of_contract += len(out_of_contract)
        _emit_ascii(
            sys.stdout,
            f"{locale}: untranslated={total} missing={len(missing)} "
            f"english_fallback={len(english_fallback)}",
        )
        for key in (missing + english_fallback)[:show]:
            _emit_ascii(sys.stdout, f"  - {key}")
        if out_of_contract:
            _emit_ascii(
                sys.stdout,
                f"{locale}_contract_parity out_of_contract={len(out_of_contract)}",
            )
            for key in out_of_contract[:show]:
                _emit_ascii(sys.stdout, f"  - {key}")
    aggregate_total = aggregate_missing + aggregate_fallback
    aggregate_contract_failures = (
        aggregate_total
        + len(english_missing)
        + len(english_identity_mismatch)
        + aggregate_out_of_contract
    )
    integrity = findings["integrity"]
    _emit_ascii(
        sys.stdout,
        f"translation_integrity failures={len(integrity)}",
    )
    for locale, defect, key in integrity[:show]:
        _emit_ascii(sys.stdout, f"  - {locale}: {defect}: {key}")
    _emit_ascii(
        sys.stdout,
        "aggregate_contract_parity "
        f"failures={aggregate_contract_failures} "
        f"english_missing={len(english_missing)} "
        f"english_identity_mismatch={len(english_identity_mismatch)} "
        f"out_of_contract={aggregate_out_of_contract}",
    )
    _emit_ascii(
        sys.stdout,
        f"aggregate: untranslated={aggregate_total} "
        f"missing={aggregate_missing} english_fallback={aggregate_fallback}",
    )
    return 1 if aggregate_contract_failures or integrity else 0


class _AuditArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise TranslationAuditError(f"invalid arguments: {_ascii_text(message)}")


def _release_runtime_is_authenticated() -> bool:
    flags = sys.flags
    return (
        sys.version_info[:3] == RELEASE_VERSION
        and sys.executable == RELEASE_EXECUTABLE_PATH
        and sys.prefix == RELEASE_PREFIX
        and sys.base_prefix == RELEASE_PREFIX
        and flags.isolated == 1
        and flags.no_site == 1
        and flags.no_user_site == 1
        and flags.safe_path
    )


def _enter_authenticated_release_runtime() -> None:
    if _release_runtime_is_authenticated():
        return
    if sys.executable == RELEASE_EXECUTABLE_PATH and sys.flags.isolated == 1:
        raise TranslationAuditError(
            "isolated release interpreter identity validation failed"
        )
    script_path = os.path.abspath(__file__)
    try:
        os.execv(
            RELEASE_LAUNCHER_PATH,
            [
                RELEASE_LAUNCHER_PATH,
                "-I",
                "-S",
                script_path,
                *sys.argv[1:],
            ],
        )
    except OSError as exc:
        raise TranslationAuditError(
            "authenticated release interpreter is unavailable"
        ) from exc
    raise TranslationAuditError("authenticated release interpreter did not start")


def _authoritative_main(args: argparse.Namespace) -> int:
    if not _DIRECT_SCRIPT_ENTRY:
        raise TranslationAuditError(
            "imported mode is diagnostic-only; production authority refused"
        )
    if not _release_runtime_is_authenticated():
        raise TranslationAuditError(
            "authenticated release interpreter boundary is absent"
        )
    _require_authoritative_path(args.contract, CONTRACT_PATH, label="contract")
    _require_authoritative_path(
        args.validator,
        VALIDATOR_PATH,
        label="contract validator",
    )
    _require_authoritative_path(args.index, INDEX_PATH, label="English source")
    _require_authoritative_path(
        args.i18n,
        AGGREGATE_PATH,
        label="translation aggregate",
    )
    if args.show < 0:
        raise TranslationAuditError("--show must be zero or greater")
    root = _absolute_lexical_path(args.repo)
    with BoundTree(root, label="repository root") as repository_tree:
        contract_document, targets, missing_locales = _capture_repository_inputs(
            repository_tree
        )
        source_sha256 = hashlib.sha256(
            repository_tree.payloads[AUDITOR_PATH]
        ).hexdigest()
        contract, translations, compiler_validated = _validate_retained_repository(
            repository_tree,
            contract_document,
            targets,
            missing_locales,
        )
        repository_tree.revalidate()
        _emit_ascii(
            sys.stdout,
            "authority_boundary interpreter=ReleasePython-3.14.7 "
            "runtime_isolation=VALIDATED authority=NONE native_launcher=REQUIRED "
            "source_runtime_prestart_authentication=ABSENT "
            f"retained_source_sha256={source_sha256}",
        )
        diagnostic_result = report_audit(
            contract,
            translations,
            show=args.show,
        )
        retained_count = len(targets) - len(missing_locales)
        if compiler_validated:
            _emit_ascii(
                sys.stdout,
                "compiler_closure=VALIDATED "
                f"retained_locale_sources={retained_count} "
                f"required_locale_sources={len(targets)} "
                "validator_method=validate_compiler_output",
            )
        else:
            _emit_ascii(
                sys.stdout,
                "compiler_closure=UNCOMPILED "
                f"retained_locale_sources={retained_count} "
                f"required_locale_sources={len(targets)} "
                f"missing_locale_sources={len(missing_locales)}",
            )
            _emit_ascii(
                sys.stdout,
                "missing_locale_codes=" + ",".join(missing_locales),
            )
        repository_tree.revalidate()
        if not compiler_validated:
            _emit_ascii(
                sys.stdout,
                "production_status=UNCOMPILED authority=NONE "
                "native_launcher=REQUIRED",
            )
            return 1
        if diagnostic_result:
            _emit_ascii(
                sys.stdout,
                "production_status=FAIL authority=NONE native_launcher=REQUIRED",
            )
            return 1
        _emit_ascii(
            sys.stdout,
            "production_status=NON_AUTHORITATIVE authority=NONE "
            "native_launcher=REQUIRED",
        )
        return 1


def main(argv: list[str] | None = None) -> int:
    if not _DIRECT_SCRIPT_ENTRY:
        _emit_ascii(
            sys.stderr,
            "website-translation-audit: imported mode is diagnostic-only; "
            "production authority refused",
        )
        _emit_ascii(sys.stderr, "production_status=FAIL authority=NONE")
        return 2
    try:
        _enter_authenticated_release_runtime()
        parser = _AuditArgumentParser(description=__doc__)
        parser.add_argument("--repo", type=Path, default=DEFAULT_REPO_ROOT)
        parser.add_argument("--contract", default=CONTRACT_PATH)
        parser.add_argument("--validator", default=VALIDATOR_PATH)
        parser.add_argument("--index", default=INDEX_PATH)
        parser.add_argument("--i18n", default=AGGREGATE_PATH)
        parser.add_argument("--show", type=int, default=12)
        args = parser.parse_args(argv)
        return _authoritative_main(args)
    except TranslationAuditError as exc:
        _emit_ascii(sys.stderr, f"website-translation-audit: {exc}")
        _emit_ascii(sys.stderr, "production_status=FAIL authority=NONE")
        return 2
    except BaseException:
        _emit_ascii(
            sys.stderr,
            "website-translation-audit: internal fail-closed error",
        )
        _emit_ascii(sys.stderr, "production_status=FAIL authority=NONE")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
