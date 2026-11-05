#!/usr/bin/env python3
"""Validate the fail-closed website localization source contract.

This tool is read-only. It does not translate, compile, or write localization
content. The existing translation audit remains the release-readiness gate.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
import os
import re
import stat
import sys
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from typing import Any


CONTRACT_SCHEMA = "winsvpn-website-localization-contract-v1"
LOCALE_SOURCE_SCHEMA = "winsvpn-website-locale-source-v1"
DEFAULT_CONTRACT_PATH = "localization/website/contract.json"
INDEX_PATH = "web/index.html"
LANGUAGES_PATH = "web/i18n/languages.json"
AGGREGATE_PATH = "web/i18n/major.json"
AUDIT_PATH = "tools/audit_website_translations.py"
LOCALE_SOURCE_DIRECTORY = "localization/website/locales"
MAX_JSON_BYTES = 16 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
INSTANT_LOCALE_RE = re.compile(r"^[a-z]{2,3}(?:-[A-Z]{2})?$")
RUNTIME_NONTRANSLATABLE_RE = re.compile(
    r"const\s+nonTranslatableKeys\s*=\s*new\s+Set\(\[(.*?)\]\);",
    re.DOTALL,
)

VOID_TAGS = {
    "area",
    "base",
    "br",
    "col",
    "embed",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "param",
    "source",
    "track",
    "wbr",
}
SKIP_TAGS = {"script", "style", "noscript"}
TRANSLATABLE_ATTRIBUTES = ("placeholder", "aria-label", "alt")

CONTRACT_KEYS = (
    "schema",
    "english_source",
    "instant_locale_inventory",
    "key_classification",
    "locale_sources",
    "compiler_output",
)
ENGLISH_SOURCE_KEYS = (
    "path",
    "file_sha256",
    "translatable_static_keys_sha256",
    "identity_sha256",
)
LOCALE_INVENTORY_KEYS = (
    "path",
    "file_sha256",
    "locales",
    "identity_sha256",
)
KEY_CLASSIFICATION_KEYS = (
    "normalization",
    "translatable_static_keys",
    "translatable_static_keys_sha256",
    "nontranslatable_static_keys",
    "nontranslatable_static_keys_sha256",
    "inherited_translate_no_only_keys",
    "inherited_translate_no_only_keys_sha256",
    "mixed_translate_context_keys",
    "mixed_translate_context_keys_sha256",
    "runtime_audit_nontranslatable_drift",
)
DRIFT_KEYS = ("classification", "keys", "keys_sha256")
LOCALE_SOURCES_KEYS = (
    "schema",
    "document_keys",
    "targets",
    "translation_key_order",
    "translation_values",
    "serialization",
)
LOCALE_DOCUMENT_KEYS = (
    "schema",
    "locale",
    "english_source_identity_sha256",
    "instant_locale_inventory_sha256",
    "translatable_static_keys_sha256",
    "translations",
)
COMPILER_OUTPUT_KEYS = (
    "path",
    "locale_order",
    "mapping_key_order",
    "english_values",
    "target_values",
    "serialization",
    "write_strategy",
)
SERIALIZATION_KEYS = (
    "encoding",
    "ensure_ascii",
    "indent",
    "line_endings",
    "trailing_newline",
)


class WebsiteLocalizationContractError(ValueError):
    """Raised when localization input crosses the reviewed contract boundary."""


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise WebsiteLocalizationContractError(f"duplicate JSON key: {key!r}")
        output[key] = value
    return output


def _reject_nonfinite_constant(value: str) -> object:
    raise WebsiteLocalizationContractError(
        f"non-finite JSON value is forbidden: {value}"
    )


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise WebsiteLocalizationContractError(
            f"non-finite JSON value is forbidden: {value}"
        )
    return parsed


def _reject_surrogates(value: object, location: str = "$") -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise WebsiteLocalizationContractError(
                f"Unicode surrogate is forbidden at {location}"
            )
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
    """Decode strict UTF-8 JSON, rejecting duplicates and non-finite numbers."""

    if isinstance(payload, bytes):
        if payload.startswith(b"\xef\xbb\xbf"):
            raise WebsiteLocalizationContractError(f"{label} must not contain a BOM")
        try:
            text = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise WebsiteLocalizationContractError(
                f"{label} is not strict UTF-8"
            ) from exc
    elif isinstance(payload, str):
        text = payload
    else:
        raise WebsiteLocalizationContractError(f"{label} must be bytes or text")
    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_nonfinite_constant,
            parse_float=_parse_finite_float,
        )
    except WebsiteLocalizationContractError:
        raise
    except json.JSONDecodeError as exc:
        raise WebsiteLocalizationContractError(
            f"malformed {label}: {exc.msg}"
        ) from exc
    _reject_surrogates(document)
    return document


def canonical_json_bytes(document: object, *, ensure_ascii: bool) -> bytes:
    try:
        rendered = json.dumps(
            document,
            ensure_ascii=ensure_ascii,
            allow_nan=False,
            indent=2,
        )
    except (TypeError, ValueError) as exc:
        raise WebsiteLocalizationContractError(
            "document cannot be serialized as canonical JSON"
        ) from exc
    return (rendered + "\n").encode("utf-8")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def canonical_value_sha256(value: object) -> str:
    try:
        payload = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise WebsiteLocalizationContractError(
            "value cannot be bound to canonical JSON"
        ) from exc
    return sha256_bytes(payload)


def validate_relative_path(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise WebsiteLocalizationContractError(f"{label} is not a safe relative path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or not path.parts
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise WebsiteLocalizationContractError(f"{label} is not a safe relative path")
    return value


def _repository_root(repo: Path) -> Path:
    candidate = repo if repo.is_absolute() else Path.cwd() / repo
    if candidate.is_symlink():
        raise WebsiteLocalizationContractError("repository root must not be a symlink")
    try:
        resolved = candidate.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise WebsiteLocalizationContractError(
            "repository root is unavailable"
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise WebsiteLocalizationContractError("repository root must be a directory")
    return resolved


def read_repository_file(
    repo: Path,
    relative_path: str,
    *,
    max_bytes: int = MAX_JSON_BYTES,
) -> bytes:
    """Read a regular file beneath repo without following path symlinks."""

    relative = validate_relative_path(relative_path, label="repository file path")
    root = _repository_root(repo)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory_flag is None:
        raise WebsiteLocalizationContractError(
            "this platform cannot enforce no-follow repository reads"
        )
    common_flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    descriptors: list[int] = []
    try:
        root_fd = os.open(root, common_flags | directory_flag)
        descriptors.append(root_fd)
        parts = PurePosixPath(relative).parts
        for component in parts[:-1]:
            directory_fd = os.open(
                component,
                common_flags | directory_flag,
                dir_fd=descriptors[-1],
            )
            if not stat.S_ISDIR(os.fstat(directory_fd).st_mode):
                raise WebsiteLocalizationContractError(
                    f"repository path component is not a directory: {component}"
                )
            descriptors.append(directory_fd)
        file_fd = os.open(parts[-1], common_flags, dir_fd=descriptors[-1])
        descriptors.append(file_fd)
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise WebsiteLocalizationContractError(
                f"repository path is not a regular file: {relative}"
            )
        if metadata.st_size > max_bytes:
            raise WebsiteLocalizationContractError(
                f"repository file is too large: {relative}"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(file_fd, min(1024 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise WebsiteLocalizationContractError(
                    f"repository file is too large: {relative}"
                )
        return b"".join(chunks)
    except WebsiteLocalizationContractError:
        raise
    except OSError as exc:
        raise WebsiteLocalizationContractError(
            f"unsafe or unavailable repository file: {relative}"
        ) from exc
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _normalized_static_key(value: str) -> str:
    return " ".join(value.split())


class _StaticKeyParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._stack: list[tuple[str, bool, bool]] = []
        self.translatable_context_keys: set[str] = set()
        self.translate_no_context_keys: set[str] = set()

    def _start(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
        *,
        push: bool,
    ) -> None:
        lowered = tag.lower()
        attributes = {name.lower(): value for name, value in attrs}
        parent_translate_no = self._stack[-1][1] if self._stack else False
        parent_skip = self._stack[-1][2] if self._stack else False
        translate_no = parent_translate_no or (
            (attributes.get("translate") or "").strip().lower() == "no"
        )
        skip = parent_skip or lowered in SKIP_TAGS
        if not skip:
            destination = (
                self.translate_no_context_keys
                if translate_no
                else self.translatable_context_keys
            )
            for attribute in TRANSLATABLE_ATTRIBUTES:
                value = attributes.get(attribute)
                if value is not None:
                    key = _normalized_static_key(value)
                    if key:
                        destination.add(key)
        if push and lowered not in VOID_TAGS:
            self._stack.append((lowered, translate_no, skip))

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        self._start(tag, attrs, push=True)

    def handle_startendtag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        self._start(tag, attrs, push=False)

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.lower()
        if lowered in VOID_TAGS:
            return
        for index in range(len(self._stack) - 1, -1, -1):
            if self._stack[index][0] == lowered:
                del self._stack[index:]
                break

    def handle_data(self, data: str) -> None:
        if self._stack and self._stack[-1][2]:
            return
        key = _normalized_static_key(data)
        if not key:
            return
        if self._stack and self._stack[-1][1]:
            self.translate_no_context_keys.add(key)
        else:
            self.translatable_context_keys.add(key)


def extract_static_keys(index_payload: bytes) -> tuple[set[str], set[str]]:
    try:
        source = index_payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise WebsiteLocalizationContractError(
            f"{INDEX_PATH} is not strict UTF-8"
        ) from exc
    parser = _StaticKeyParser()
    try:
        parser.feed(source)
        parser.close()
    except Exception as exc:
        raise WebsiteLocalizationContractError(
            f"unable to extract static keys from {INDEX_PATH}"
        ) from exc
    return parser.translatable_context_keys, parser.translate_no_context_keys


def extract_runtime_nontranslatable_keys(index_payload: bytes) -> set[str]:
    try:
        source = index_payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise WebsiteLocalizationContractError(
            f"{INDEX_PATH} is not strict UTF-8"
        ) from exc
    matches = RUNTIME_NONTRANSLATABLE_RE.findall(source)
    if len(matches) != 1:
        raise WebsiteLocalizationContractError(
            "runtime nonTranslatableKeys declaration must occur exactly once"
        )
    parsed = strict_json_loads(f"[{matches[0]}]", label="runtime nontranslatable keys")
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        raise WebsiteLocalizationContractError(
            "runtime nonTranslatableKeys must be an array of strings"
        )
    if len(parsed) != len(set(parsed)):
        raise WebsiteLocalizationContractError(
            "runtime nonTranslatableKeys contains a duplicate"
        )
    return set(parsed)


def extract_audit_nontranslatable_keys(audit_payload: bytes) -> set[str]:
    try:
        source = audit_payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise WebsiteLocalizationContractError(
            f"{AUDIT_PATH} is not strict UTF-8"
        ) from exc
    try:
        module = ast.parse(source, filename=AUDIT_PATH)
    except SyntaxError as exc:
        raise WebsiteLocalizationContractError(
            f"unable to parse {AUDIT_PATH}"
        ) from exc
    candidates: list[ast.AST] = []
    for statement in module.body:
        if isinstance(statement, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "NON_TRANSLATABLE_KEYS"
            for target in statement.targets
        ):
            candidates.append(statement.value)
        elif (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.target.id == "NON_TRANSLATABLE_KEYS"
            and statement.value is not None
        ):
            candidates.append(statement.value)
    if len(candidates) != 1 or not isinstance(candidates[0], ast.Set):
        raise WebsiteLocalizationContractError(
            "audit NON_TRANSLATABLE_KEYS must be one literal set"
        )
    values: list[str] = []
    for element in candidates[0].elts:
        try:
            value = ast.literal_eval(element)
        except (TypeError, ValueError, SyntaxError) as exc:
            raise WebsiteLocalizationContractError(
                "audit NON_TRANSLATABLE_KEYS must contain only literal strings"
            ) from exc
        if not isinstance(value, str):
            raise WebsiteLocalizationContractError(
                "audit NON_TRANSLATABLE_KEYS must contain only strings"
            )
        values.append(value)
    if len(values) != len(set(values)):
        raise WebsiteLocalizationContractError(
            "audit NON_TRANSLATABLE_KEYS contains a duplicate"
        )
    return set(values)


def _expect_exact_keys(
    value: object,
    expected: tuple[str, ...],
    *,
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WebsiteLocalizationContractError(f"{label} must be an object")
    actual = tuple(value.keys())
    if actual != expected:
        raise WebsiteLocalizationContractError(
            f"{label} keys or key order are invalid: expected {expected!r}"
        )
    return value


def _expect_string(value: object, *, label: str, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        raise WebsiteLocalizationContractError(f"{label} must be a string")
    return value


def _expect_sha256(value: object, *, label: str) -> str:
    text = _expect_string(value, label=label)
    if SHA256_RE.fullmatch(text) is None:
        raise WebsiteLocalizationContractError(f"{label} must be lowercase SHA-256")
    return text


def _validate_sorted_unique_strings(value: object, *, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise WebsiteLocalizationContractError(f"{label} must be an array of strings")
    if value != sorted(value) or len(value) != len(set(value)):
        raise WebsiteLocalizationContractError(
            f"{label} must be sorted and contain no duplicates"
        )
    return value


def _load_instant_locale_inventory(
    repo: Path,
) -> tuple[bytes, list[dict[str, object]]]:
    payload = read_repository_file(repo, LANGUAGES_PATH)
    document = strict_json_loads(payload, label=LANGUAGES_PATH)
    if not isinstance(document, list):
        raise WebsiteLocalizationContractError(f"{LANGUAGES_PATH} root must be an array")
    all_codes: set[str] = set()
    instant: list[dict[str, object]] = []
    for index, item in enumerate(document):
        entry = _expect_exact_keys(
            item,
            ("code", "name", "instant"),
            label=f"{LANGUAGES_PATH}[{index}]",
        )
        code = _expect_string(entry["code"], label=f"locale code at index {index}")
        name = _expect_string(entry["name"], label=f"locale name at index {index}")
        if code in all_codes:
            raise WebsiteLocalizationContractError(f"duplicate locale inventory code: {code}")
        all_codes.add(code)
        if name != name.strip():
            raise WebsiteLocalizationContractError(
                f"locale inventory name has surrounding whitespace: {code}"
            )
        if type(entry["instant"]) is not bool:
            raise WebsiteLocalizationContractError(
                f"locale inventory instant flag must be boolean: {code}"
            )
        if entry["instant"]:
            if INSTANT_LOCALE_RE.fullmatch(code) is None:
                raise WebsiteLocalizationContractError(
                    f"unsupported instant locale syntax: {code}"
                )
            instant.append({"code": code, "name": name})
    if not instant or instant[0]["code"] != "en":
        raise WebsiteLocalizationContractError(
            "English must be the first supported instant locale"
        )
    if any(item["code"] == "en" for item in instant[1:]):
        raise WebsiteLocalizationContractError(
            "English occurs more than once in the instant locale inventory"
        )
    return payload, instant


def _serialization_contract(*, ensure_ascii: bool) -> dict[str, object]:
    return {
        "encoding": "UTF-8",
        "ensure_ascii": ensure_ascii,
        "indent": 2,
        "line_endings": "LF",
        "trailing_newline": True,
    }


def build_expected_contract(repo: Path) -> dict[str, object]:
    """Build the exact contract snapshot expected for the current source tree."""

    index_payload = read_repository_file(repo, INDEX_PATH)
    audit_payload = read_repository_file(repo, AUDIT_PATH)
    languages_payload, locales = _load_instant_locale_inventory(repo)
    translatable_context, translate_no_context = extract_static_keys(index_payload)
    runtime_nontranslatable = extract_runtime_nontranslatable_keys(index_payload)
    audit_nontranslatable = extract_audit_nontranslatable_keys(audit_payload)
    explicit_nontranslatable = runtime_nontranslatable | audit_nontranslatable

    translatable_keys = sorted(translatable_context - explicit_nontranslatable)
    nontranslatable_keys = sorted(translatable_context & explicit_nontranslatable)
    translate_no_only_keys = sorted(translate_no_context - translatable_context)
    mixed_context_keys = sorted(translate_no_context & translatable_context)
    visible_keys = translatable_context | translate_no_context
    drift_keys = sorted((runtime_nontranslatable ^ audit_nontranslatable) & visible_keys)

    translatable_hash = canonical_value_sha256(translatable_keys)
    nontranslatable_hash = canonical_value_sha256(nontranslatable_keys)
    translate_no_hash = canonical_value_sha256(translate_no_only_keys)
    mixed_hash = canonical_value_sha256(mixed_context_keys)
    drift_hash = canonical_value_sha256(drift_keys)
    english_identity_input = {
        "file_sha256": sha256_bytes(index_payload),
        "path": INDEX_PATH,
        "translatable_static_keys_sha256": translatable_hash,
    }
    english_identity = canonical_value_sha256(english_identity_input)
    inventory_identity = canonical_value_sha256(locales)
    locale_codes = [str(item["code"]) for item in locales]
    targets = [
        {
            "locale": code,
            "path": f"{LOCALE_SOURCE_DIRECTORY}/{code}.json",
        }
        for code in locale_codes
        if code != "en"
    ]

    return {
        "schema": CONTRACT_SCHEMA,
        "english_source": {
            "path": INDEX_PATH,
            "file_sha256": sha256_bytes(index_payload),
            "translatable_static_keys_sha256": translatable_hash,
            "identity_sha256": english_identity,
        },
        "instant_locale_inventory": {
            "path": LANGUAGES_PATH,
            "file_sha256": sha256_bytes(languages_payload),
            "locales": locales,
            "identity_sha256": inventory_identity,
        },
        "key_classification": {
            "normalization": "html-character-references-decoded-whitespace-collapsed-v1",
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
            "schema": LOCALE_SOURCE_SCHEMA,
            "document_keys": list(LOCALE_DOCUMENT_KEYS),
            "targets": targets,
            "translation_key_order": "translatable_static_keys",
            "translation_values": "nonempty-trimmed-non-english-strings",
            "serialization": _serialization_contract(ensure_ascii=False),
        },
        "compiler_output": {
            "path": AGGREGATE_PATH,
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


def _validate_serialization_contract(
    value: object,
    *,
    ensure_ascii: bool,
    label: str,
) -> None:
    serialization = _expect_exact_keys(value, SERIALIZATION_KEYS, label=label)
    expected = _serialization_contract(ensure_ascii=ensure_ascii)
    if (
        type(serialization["encoding"]) is not str
        or type(serialization["ensure_ascii"]) is not bool
        or type(serialization["indent"]) is not int
        or type(serialization["line_endings"]) is not str
        or type(serialization["trailing_newline"]) is not bool
        or serialization != expected
    ):
        raise WebsiteLocalizationContractError(f"{label} is not the required format")


def validate_contract_document(document: object) -> dict[str, Any]:
    contract = _expect_exact_keys(document, CONTRACT_KEYS, label="contract")
    if contract["schema"] != CONTRACT_SCHEMA:
        raise WebsiteLocalizationContractError("unsupported contract schema")

    english = _expect_exact_keys(
        contract["english_source"],
        ENGLISH_SOURCE_KEYS,
        label="contract english_source",
    )
    if validate_relative_path(english["path"], label="English source path") != INDEX_PATH:
        raise WebsiteLocalizationContractError("English source path is not authoritative")
    english_file_hash = _expect_sha256(
        english["file_sha256"], label="English source file hash"
    )
    english_key_hash = _expect_sha256(
        english["translatable_static_keys_sha256"],
        label="English translatable key hash",
    )
    english_identity = _expect_sha256(
        english["identity_sha256"], label="English source identity"
    )
    expected_english_identity = canonical_value_sha256(
        {
            "file_sha256": english_file_hash,
            "path": INDEX_PATH,
            "translatable_static_keys_sha256": english_key_hash,
        }
    )
    if english_identity != expected_english_identity:
        raise WebsiteLocalizationContractError("English source identity hash is invalid")

    inventory = _expect_exact_keys(
        contract["instant_locale_inventory"],
        LOCALE_INVENTORY_KEYS,
        label="contract instant_locale_inventory",
    )
    if (
        validate_relative_path(inventory["path"], label="locale inventory path")
        != LANGUAGES_PATH
    ):
        raise WebsiteLocalizationContractError("locale inventory path is not authoritative")
    _expect_sha256(inventory["file_sha256"], label="locale inventory file hash")
    locale_items = inventory["locales"]
    if not isinstance(locale_items, list) or not locale_items:
        raise WebsiteLocalizationContractError("instant locale inventory must be a nonempty array")
    locale_codes: list[str] = []
    for index, item in enumerate(locale_items):
        locale = _expect_exact_keys(
            item,
            ("code", "name"),
            label=f"contract instant locale {index}",
        )
        code = _expect_string(locale["code"], label=f"instant locale code {index}")
        name = _expect_string(locale["name"], label=f"instant locale name {index}")
        if INSTANT_LOCALE_RE.fullmatch(code) is None:
            raise WebsiteLocalizationContractError(f"unsupported instant locale: {code}")
        if name != name.strip():
            raise WebsiteLocalizationContractError(
                f"instant locale name has surrounding whitespace: {code}"
            )
        locale_codes.append(code)
    if locale_codes[0] != "en" or len(locale_codes) != len(set(locale_codes)):
        raise WebsiteLocalizationContractError(
            "instant locale order must start with unique English"
        )
    inventory_identity = _expect_sha256(
        inventory["identity_sha256"], label="locale inventory identity"
    )
    if inventory_identity != canonical_value_sha256(locale_items):
        raise WebsiteLocalizationContractError("locale inventory identity hash is invalid")

    classification = _expect_exact_keys(
        contract["key_classification"],
        KEY_CLASSIFICATION_KEYS,
        label="contract key_classification",
    )
    if (
        classification["normalization"]
        != "html-character-references-decoded-whitespace-collapsed-v1"
    ):
        raise WebsiteLocalizationContractError("unsupported static-key normalization")
    translatable = _validate_sorted_unique_strings(
        classification["translatable_static_keys"],
        label="translatable static keys",
    )
    nontranslatable = _validate_sorted_unique_strings(
        classification["nontranslatable_static_keys"],
        label="nontranslatable static keys",
    )
    translate_no_only = _validate_sorted_unique_strings(
        classification["inherited_translate_no_only_keys"],
        label="inherited translate=no-only keys",
    )
    mixed_context = _validate_sorted_unique_strings(
        classification["mixed_translate_context_keys"],
        label="mixed translate context keys",
    )
    list_hash_pairs = (
        (
            translatable,
            classification["translatable_static_keys_sha256"],
            "translatable static key hash",
        ),
        (
            nontranslatable,
            classification["nontranslatable_static_keys_sha256"],
            "nontranslatable static key hash",
        ),
        (
            translate_no_only,
            classification["inherited_translate_no_only_keys_sha256"],
            "inherited translate=no-only key hash",
        ),
        (
            mixed_context,
            classification["mixed_translate_context_keys_sha256"],
            "mixed translate context key hash",
        ),
    )
    for values, claimed_hash, label in list_hash_pairs:
        actual_claim = _expect_sha256(claimed_hash, label=label)
        if actual_claim != canonical_value_sha256(values):
            raise WebsiteLocalizationContractError(f"{label} is invalid")
    if english_key_hash != classification["translatable_static_keys_sha256"]:
        raise WebsiteLocalizationContractError(
            "English source and key classification hashes differ"
        )
    primary_sets = [set(translatable), set(nontranslatable), set(translate_no_only)]
    if (
        primary_sets[0] & primary_sets[1]
        or primary_sets[0] & primary_sets[2]
        or primary_sets[1] & primary_sets[2]
    ):
        raise WebsiteLocalizationContractError(
            "primary static-key classifications must be disjoint"
        )
    if not set(mixed_context).issubset(primary_sets[0]):
        raise WebsiteLocalizationContractError(
            "mixed translate-context keys must remain translatable"
        )

    drift = _expect_exact_keys(
        classification["runtime_audit_nontranslatable_drift"],
        DRIFT_KEYS,
        label="runtime/audit nontranslatable drift",
    )
    if drift["classification"] != "nontranslatable":
        raise WebsiteLocalizationContractError(
            "runtime/audit drift must resolve as nontranslatable"
        )
    drift_values = _validate_sorted_unique_strings(
        drift["keys"], label="runtime/audit drift keys"
    )
    drift_hash = _expect_sha256(drift["keys_sha256"], label="runtime/audit drift hash")
    if drift_hash != canonical_value_sha256(drift_values):
        raise WebsiteLocalizationContractError("runtime/audit drift hash is invalid")
    if not set(drift_values).issubset(primary_sets[1]):
        raise WebsiteLocalizationContractError(
            "runtime/audit drift keys must be classified nontranslatable"
        )

    locale_sources = _expect_exact_keys(
        contract["locale_sources"],
        LOCALE_SOURCES_KEYS,
        label="contract locale_sources",
    )
    if locale_sources["schema"] != LOCALE_SOURCE_SCHEMA:
        raise WebsiteLocalizationContractError("unsupported locale-source schema")
    if locale_sources["document_keys"] != list(LOCALE_DOCUMENT_KEYS):
        raise WebsiteLocalizationContractError("locale-source document keys are invalid")
    targets = locale_sources["targets"]
    if not isinstance(targets, list):
        raise WebsiteLocalizationContractError("locale-source targets must be an array")
    expected_target_codes = [code for code in locale_codes if code != "en"]
    actual_target_codes: list[str] = []
    for index, item in enumerate(targets):
        target = _expect_exact_keys(
            item,
            ("locale", "path"),
            label=f"locale-source target {index}",
        )
        code = _expect_string(target["locale"], label=f"target locale {index}")
        path = validate_relative_path(target["path"], label=f"target path {code}")
        if path != f"{LOCALE_SOURCE_DIRECTORY}/{code}.json":
            raise WebsiteLocalizationContractError(
                f"locale-source path is not deterministic: {code}"
            )
        actual_target_codes.append(code)
    if actual_target_codes != expected_target_codes:
        raise WebsiteLocalizationContractError(
            "locale-source targets do not match the instant locale inventory"
        )
    if len(actual_target_codes) != len(set(actual_target_codes)):
        raise WebsiteLocalizationContractError("duplicate locale-source target")
    if locale_sources["translation_key_order"] != "translatable_static_keys":
        raise WebsiteLocalizationContractError("locale-source key order is invalid")
    if (
        locale_sources["translation_values"]
        != "nonempty-trimmed-non-english-strings"
    ):
        raise WebsiteLocalizationContractError("locale-source value policy is invalid")
    _validate_serialization_contract(
        locale_sources["serialization"],
        ensure_ascii=False,
        label="locale-source serialization",
    )

    compiler = _expect_exact_keys(
        contract["compiler_output"],
        COMPILER_OUTPUT_KEYS,
        label="contract compiler_output",
    )
    if (
        validate_relative_path(compiler["path"], label="compiler output path")
        != AGGREGATE_PATH
    ):
        raise WebsiteLocalizationContractError("compiler output path is not authoritative")
    if compiler["locale_order"] != locale_codes:
        raise WebsiteLocalizationContractError("compiler locale order is invalid")
    if compiler["mapping_key_order"] != "translatable_static_keys":
        raise WebsiteLocalizationContractError("compiler mapping key order is invalid")
    if compiler["english_values"] != "source-key-identity":
        raise WebsiteLocalizationContractError("compiler English value policy is invalid")
    if compiler["target_values"] != "validated-locale-source-values":
        raise WebsiteLocalizationContractError("compiler target value policy is invalid")
    _validate_serialization_contract(
        compiler["serialization"],
        ensure_ascii=False,
        label="compiler output serialization",
    )
    if (
        compiler["write_strategy"]
        != "single-owner-same-directory-temp-fsync-replace-directory-fsync"
    ):
        raise WebsiteLocalizationContractError("compiler write strategy is invalid")
    return contract


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


def validate_aggregate_envelope(
    repo: Path,
    contract: dict[str, Any],
) -> dict[str, dict[str, str]]:
    payload = read_repository_file(repo, AGGREGATE_PATH)
    document = strict_json_loads(payload, label=AGGREGATE_PATH)
    if not isinstance(document, dict):
        raise WebsiteLocalizationContractError(f"{AGGREGATE_PATH} root must be an object")
    expected_locales = contract["compiler_output"]["locale_order"]
    if list(document.keys()) != expected_locales:
        raise WebsiteLocalizationContractError(
            f"{AGGREGATE_PATH} locale order does not match the contract"
        )
    for locale, mapping in document.items():
        if not isinstance(mapping, dict):
            raise WebsiteLocalizationContractError(
                f"{AGGREGATE_PATH} locale {locale!r} must be an object"
            )
        for source, translated in mapping.items():
            if not isinstance(source, str) or not source:
                raise WebsiteLocalizationContractError(
                    f"{AGGREGATE_PATH} locale {locale!r} has an invalid source key"
                )
            if not isinstance(translated, str):
                raise WebsiteLocalizationContractError(
                    f"{AGGREGATE_PATH} locale {locale!r} has a non-string value"
                )
    return document


def load_validated_contract(
    repo: Path,
    contract_path: str = DEFAULT_CONTRACT_PATH,
) -> dict[str, Any]:
    relative_contract = validate_relative_path(contract_path, label="contract path")
    payload = read_repository_file(repo, relative_contract)
    document = strict_json_loads(payload, label=relative_contract)
    contract = validate_contract_document(document)
    if payload != canonical_json_bytes(contract, ensure_ascii=True):
        raise WebsiteLocalizationContractError(
            "contract JSON is not in canonical ASCII/LF order"
        )
    expected = build_expected_contract(repo)
    difference = _first_difference(contract, expected)
    if difference is not None:
        raise WebsiteLocalizationContractError(
            f"contract does not match the current source tree at {difference}"
        )
    validate_aggregate_envelope(repo, contract)
    return contract


def validate_locale_document(
    document: object,
    *,
    expected_locale: str,
    contract: dict[str, Any],
) -> dict[str, Any]:
    source = _expect_exact_keys(
        document,
        LOCALE_DOCUMENT_KEYS,
        label=f"locale source {expected_locale}",
    )
    targets = {
        item["locale"]: item["path"] for item in contract["locale_sources"]["targets"]
    }
    if expected_locale not in targets:
        raise WebsiteLocalizationContractError(
            f"unsupported locale source: {expected_locale}"
        )
    if source["schema"] != LOCALE_SOURCE_SCHEMA:
        raise WebsiteLocalizationContractError(
            f"unsupported locale-source schema for {expected_locale}"
        )
    if source["locale"] != expected_locale:
        raise WebsiteLocalizationContractError(
            f"locale-source identity mismatch for {expected_locale}"
        )
    expected_bindings = (
        (
            "english_source_identity_sha256",
            contract["english_source"]["identity_sha256"],
        ),
        (
            "instant_locale_inventory_sha256",
            contract["instant_locale_inventory"]["identity_sha256"],
        ),
        (
            "translatable_static_keys_sha256",
            contract["key_classification"]["translatable_static_keys_sha256"],
        ),
    )
    for field, expected in expected_bindings:
        actual = _expect_sha256(source[field], label=f"{expected_locale} {field}")
        if actual != expected:
            raise WebsiteLocalizationContractError(
                f"locale-source binding drift for {expected_locale}: {field}"
            )
    translations = source["translations"]
    if not isinstance(translations, dict):
        raise WebsiteLocalizationContractError(
            f"locale-source translations must be an object: {expected_locale}"
        )
    expected_keys = contract["key_classification"]["translatable_static_keys"]
    if list(translations.keys()) != expected_keys:
        raise WebsiteLocalizationContractError(
            f"locale-source translation keys or order differ: {expected_locale}"
        )
    for english, translated in translations.items():
        if (
            not isinstance(translated, str)
            or not translated.strip()
            or translated != translated.strip()
            or translated == english
        ):
            raise WebsiteLocalizationContractError(
                f"locale-source value is not translation-ready: {expected_locale} {english!r}"
            )
    return source


def load_validated_locale_source(
    repo: Path,
    *,
    locale: str,
    contract: dict[str, Any],
) -> dict[str, Any]:
    targets = {
        item["locale"]: item["path"] for item in contract["locale_sources"]["targets"]
    }
    if locale not in targets:
        raise WebsiteLocalizationContractError(f"unsupported locale source: {locale}")
    path = targets[locale]
    payload = read_repository_file(repo, path)
    document = strict_json_loads(payload, label=path)
    source = validate_locale_document(
        document,
        expected_locale=locale,
        contract=contract,
    )
    if payload != canonical_json_bytes(source, ensure_ascii=False):
        raise WebsiteLocalizationContractError(
            f"locale source is not canonical UTF-8/LF JSON: {locale}"
        )
    return source


def load_all_validated_locale_sources(
    repo: Path,
    contract: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for target in contract["locale_sources"]["targets"]:
        locale = target["locale"]
        output[locale] = load_validated_locale_source(
            repo,
            locale=locale,
            contract=contract,
        )
    return output


def validate_compiler_output_document(
    document: object,
    *,
    contract: dict[str, Any],
    locale_sources: dict[str, dict[str, Any]],
) -> dict[str, dict[str, str]]:
    if not isinstance(document, dict):
        raise WebsiteLocalizationContractError("compiler output root must be an object")
    locale_order = contract["compiler_output"]["locale_order"]
    if list(document.keys()) != locale_order:
        raise WebsiteLocalizationContractError("compiler output locale order is invalid")
    source_keys = contract["key_classification"]["translatable_static_keys"]
    for locale in locale_order:
        mapping = document[locale]
        if not isinstance(mapping, dict) or list(mapping.keys()) != source_keys:
            raise WebsiteLocalizationContractError(
                f"compiler output key order is invalid: {locale}"
            )
        if locale == "en":
            if any(mapping[key] != key for key in source_keys):
                raise WebsiteLocalizationContractError(
                    "compiler output English mapping is not source identity"
                )
            continue
        source = locale_sources.get(locale)
        if source is None or mapping != source["translations"]:
            raise WebsiteLocalizationContractError(
                f"compiler output does not match validated locale source: {locale}"
            )
    return document


def validate_compiler_output(
    repo: Path,
    contract: dict[str, Any],
) -> dict[str, dict[str, str]]:
    locale_sources = load_all_validated_locale_sources(repo, contract)
    payload = read_repository_file(repo, AGGREGATE_PATH)
    document = strict_json_loads(payload, label=AGGREGATE_PATH)
    validated = validate_compiler_output_document(
        document,
        contract=contract,
        locale_sources=locale_sources,
    )
    if payload != canonical_json_bytes(validated, ensure_ascii=False):
        raise WebsiteLocalizationContractError(
            "compiler output is not canonical UTF-8/LF JSON"
        )
    return validated


def _command_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    def add_common(command: argparse.ArgumentParser) -> None:
        command.add_argument("--repo", type=Path, default=Path("."))
        command.add_argument("--contract", default=DEFAULT_CONTRACT_PATH)

    validate_contract = commands.add_parser(
        "validate-contract",
        help="Validate the contract and current aggregate envelope only.",
    )
    add_common(validate_contract)
    validate_locale = commands.add_parser(
        "validate-locale",
        help="Validate one exact per-locale source document.",
    )
    add_common(validate_locale)
    validate_locale.add_argument("--locale", required=True)
    validate_all = commands.add_parser(
        "validate-all-locales",
        help="Validate every required per-locale source document.",
    )
    add_common(validate_all)
    validate_output = commands.add_parser(
        "validate-compiler-output",
        help="Validate all locale sources and the exact aggregate output.",
    )
    add_common(validate_output)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _command_parser().parse_args(argv)
    try:
        contract = load_validated_contract(args.repo, args.contract)
        if args.command == "validate-contract":
            classification = contract["key_classification"]
            locales = contract["instant_locale_inventory"]["locales"]
            print(
                "contract_valid "
                f"translatable_keys={len(classification['translatable_static_keys'])} "
                f"translate_no_only_keys={len(classification['inherited_translate_no_only_keys'])} "
                f"instant_locales={len(locales)} "
                "locale_sources=not_checked translation_readiness=not_checked"
            )
            return 0
        if args.command == "validate-locale":
            load_validated_locale_source(
                args.repo,
                locale=args.locale,
                contract=contract,
            )
            print(f"locale_source_valid locale={args.locale}")
            return 0
        if args.command == "validate-all-locales":
            sources = load_all_validated_locale_sources(args.repo, contract)
            print(f"locale_sources_valid count={len(sources)}")
            return 0
        if args.command == "validate-compiler-output":
            output = validate_compiler_output(args.repo, contract)
            payload = canonical_json_bytes(output, ensure_ascii=False)
            print(
                f"compiler_output_valid locales={len(output)} "
                f"sha256={sha256_bytes(payload)}"
            )
            return 0
        raise WebsiteLocalizationContractError("unsupported command")
    except WebsiteLocalizationContractError as exc:
        print(f"website-localization-contract: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
