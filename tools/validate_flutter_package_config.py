#!/usr/bin/env python3
"""Validate Flutter's generated package map against immutable release inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from urllib.parse import unquote, urlsplit

import yaml


MAX_BYTES = 2_000_000
MAX_NESTING = 16
MAX_YAML_NODES = 10_000
ROOT_PACKAGE = "wins_vpn"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PACKAGE_RE = re.compile(r"^[a-z][a-z0-9_]*$")
LANGUAGE_VERSION_RE = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
VERSION_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:[-+][0-9A-Za-z.]+)?$"
)
JSON_INT_RE = re.compile(r"^-?(?:0|[1-9][0-9]*)$")
CONFIG_KEYS = {
    "configVersion",
    "flutterRoot",
    "flutterVersion",
    "generator",
    "generatorVersion",
    "packages",
    "pubCache",
}
PACKAGE_KEYS = {"languageVersion", "name", "packageUri", "rootUri"}
HOSTED_DESCRIPTION_KEYS = {"name", "sha256", "url"}
SDK_ROOTS = {
    "flutter": Path("packages/flutter"),
    "flutter_localizations": Path("packages/flutter_localizations"),
    "flutter_test": Path("packages/flutter_test"),
    "sky_engine": Path("bin/cache/pkg/sky_engine"),
}


class Refused(ValueError):
    pass


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in result:
            raise Refused(f"duplicate or non-string JSON key: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise Refused(f"non-finite JSON number is forbidden: {value}")


def _reject_json_float(value: str) -> float:
    raise Refused(f"JSON floating-point numbers are forbidden: {value}")


def _parse_json_int(value: str) -> int:
    if not JSON_INT_RE.fullmatch(value):
        raise Refused(f"JSON integer is invalid: {value}")
    return int(value)


def _open_flags(*, directory: bool = False) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise Refused("O_NOFOLLOW is required")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
    if directory:
        directory_flag = getattr(os, "O_DIRECTORY", 0)
        if not directory_flag:
            raise Refused("O_DIRECTORY is required")
        flags |= directory_flag
    return flags


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _dir_identity(info: os.stat_result) -> tuple[int, int]:
    return (info.st_dev, info.st_ino)


def _already_canonical(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise Refused(f"{label} must be one absolute path")
    if Path(os.path.normpath(path)) != path:
        raise Refused(f"{label} must already be canonical")
    parts = path.parts[1:]
    if not parts:
        raise Refused(f"{label} must not be a filesystem root")
    current = Path(path.anchor)
    for index, part in enumerate(parts):
        if part in {".", ".."}:
            raise Refused(f"{label} contains a relative path component")
        current /= part
        try:
            info = current.lstat()
        except OSError as exc:
            raise Refused(f"{label} is missing") from exc
        if stat.S_ISLNK(info.st_mode):
            raise Refused(f"{label} contains a symbolic path component")
        last = index == len(parts) - 1
        if not last and not stat.S_ISDIR(info.st_mode):
            raise Refused(f"{label} contains a non-directory path component")
    return current


def _bind_regular_file(path: Path, label: str) -> tuple[Path, bytes]:
    path = _already_canonical(path, label)
    try:
        before = path.lstat()
    except OSError as exc:
        raise Refused(f"{label} must be one absolute regular non-symlink file") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise Refused(f"{label} must be one absolute regular non-symlink file with one link")
    if before.st_size <= 0 or before.st_size > MAX_BYTES:
        raise Refused(
            f"{label} exceeds the release size limit"
            if before.st_size > MAX_BYTES
            else f"{label} is empty"
        )
    fd = os.open(path, _open_flags())
    try:
        opened = os.fstat(fd)
        if _file_identity(opened) != _file_identity(before):
            raise Refused(f"{label} was replaced before it was opened")
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise Refused(f"{label} must be one absolute regular non-symlink file with one link")
        chunks: list[bytes] = []
        total = 0
        limit = opened.st_size
        while True:
            block = os.read(fd, min(65536, limit - total + 1))
            if not block:
                break
            total += len(block)
            if total > limit:
                raise Refused(f"{label} size changed while it was read")
            chunks.append(block)
        data = b"".join(chunks)
        if len(data) != limit:
            raise Refused(f"{label} size changed while it was read")
        after = os.fstat(fd)
        if _file_identity(after) != _file_identity(opened):
            raise Refused(f"{label} changed while it was read")
    finally:
        os.close(fd)
    latest = path.lstat()
    if _file_identity(latest) != _file_identity(opened):
        raise Refused(f"{label} was replaced after it was opened")
    return path, data


def _bind_real_directory(path: Path, label: str) -> Path:
    path = _already_canonical(path, label)
    try:
        before = path.lstat()
    except OSError as exc:
        raise Refused(f"{label} must be one absolute real directory") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise Refused(f"{label} must be one absolute real directory")
    fd = os.open(path, _open_flags(directory=True))
    try:
        opened = os.fstat(fd)
        if _dir_identity(opened) != _dir_identity(before) or not stat.S_ISDIR(opened.st_mode):
            raise Refused(f"{label} was replaced before it was opened")
    finally:
        os.close(fd)
    latest = path.lstat()
    if _dir_identity(latest) != _dir_identity(opened):
        raise Refused(f"{label} was replaced after it was opened")
    return path


def _reject_deep_json(text: str) -> None:
    depth = 0
    in_string = False
    escape = False
    for char in text:
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
            continue
        if char in "{[":
            depth += 1
            if depth > MAX_NESTING:
                raise Refused("JSON nesting exceeds the bound")
        elif char in "}]":
            if depth == 0:
                raise Refused("JSON structure is invalid")
            depth -= 1


def _load_json(raw: bytes) -> dict[str, object]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Refused("package config is not UTF-8") from exc
    _reject_deep_json(text)
    decoder = json.JSONDecoder(
        object_pairs_hook=_unique_pairs,
        parse_int=_parse_json_int,
        parse_float=_reject_json_float,
        parse_constant=_reject_json_constant,
    )
    try:
        document, index = decoder.raw_decode(text)
    except json.JSONDecodeError as exc:
        raise Refused("package config is not strict JSON") from exc
    if text[index:].strip(" \t\r\n"):
        raise Refused("package config contains trailing JSON data")
    if not isinstance(document, dict):
        raise Refused("package config root must be an object")
    if set(document) != CONFIG_KEYS:
        raise Refused("package config schema fields are invalid")
    return document


class _BoundedLoader(yaml.SafeLoader):
    def __init__(self, stream: object) -> None:
        super().__init__(stream)
        self._nesting = 0
        self._nodes = 0

    def compose_node(self, parent: yaml.Node | None, index: object) -> yaml.Node:
        if self.check_event(yaml.AliasEvent):
            raise Refused("YAML aliases are forbidden")
        event = self.peek_event()
        nested = isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent))
        if nested:
            self._nesting += 1
            if self._nesting > MAX_NESTING:
                raise Refused("YAML nesting exceeds the bound")
        self._nodes += 1
        if self._nodes > MAX_YAML_NODES:
            raise Refused("YAML node count exceeds the bound")
        try:
            return super().compose_node(parent, index)
        finally:
            if nested:
                self._nesting -= 1

    def flatten_mapping(self, node: yaml.MappingNode) -> None:
        for key_node, _value_node in node.value:
            if key_node.tag in {"tag:yaml.org,2002:merge", "tag:yaml.org,2002:value"}:
                raise Refused("YAML merge keys are forbidden")
        super().flatten_mapping(node)

    def construct_mapping(self, node: yaml.Node, deep: bool = True) -> dict[object, object]:
        if not isinstance(node, yaml.MappingNode):
            raise Refused("YAML mapping is invalid")
        self.flatten_mapping(node)
        result: dict[object, object] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in result:
                raise Refused(f"duplicate YAML key: {key!r}")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _load_lock(data: bytes) -> dict[str, dict[str, str]]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as suc:
        raise Refused("pubspec.lock is not UTF-8") from suc
    document = yaml.load(text, Loader=_BoundedLoader)
    if not isinstance(document, dict) or not isinstance(document.get("packages"), dict):
        raise Refused("pubspec.lock packages mapping is absent")
    result: dict[str, dict[str, str]] = {}
    for name, value in document["packages"].items():
        if not isinstance(name, str) or not PACKAGE_RE.fullmatch(name):
            raise Refused(f"invalid lock package name: {name!r}")
        if name == ROOT_PACKAGE:
            raise Refused("root package must not appear in pubspec.lock")
        if not isinstance(value, dict):
            raise Refused(f"invalid lock package entry: {name}")
        source = value.get("source")
        version = value.get("version")
        if source not in {"hosted", "sdk"} or not isinstance(version, str) or not VERSION_RE.fullmatch(version):
            raise Refused(f"unsupported lock package source or version: {name}")
        entry = {"source": source, "version": version}
        if source == "hosted":
            description = value.get("description")
            if not isinstance(description, dict) or set(description) != HOSTED_DESCRIPTION_KEYS:
                raise Refused(f"hosted lock identity is not canonical: {name}")
            digest = description.get("sha256")
            if description.get("name") != name or description.get("url") != "https://pub.dev":
                raise Refused(f"hosted lock identity is not canonical: {name}")
            if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
                raise Refused(f"hosted lock digest is invalid: {name}")
            entry["sha256"] = digest
        elif name not in SDK_ROOTS or version != "0.0.0" or value.get("description") != "flutter":
            raise Refused(f"unexpected SDK lock package: {name}")
        result[name] = entry
    if set(name for name, item in result.items() if item["source"] == "sdk") != set(SDK_ROOTS):
        raise Refused("lockfile Flutter SDK package set is incomplete")
    return result


def _posix_file_uri(uri: object, label: str) -> Path:
    if not isinstance(uri, str) or not uri or "\x00" in uri:
        raise Refused(f"{label} URI is invalid")
    parsed = urlsplit(uri)
    if parsed.query or parsed.fragment or parsed.netloc:
        raise Refused(f"{label} URI contains unsupported URL components")
    if parsed.scheme != "file":
        raise Refused(f"{label} must be an absolute file URI")
    decoded = unquote(parsed.path)
    if "\x00" in decoded or "\\" in decoded:
        raise Refused(f"{label} URI contains an illegal path character")
    if decoded != "/" and decoded.endswith("/"):
        decoded = decoded[:-1]
    if not decoded.startswith("/"):
        raise Refused(f"{label} file URI must be absolute")
    parts = decoded.split("/")
    if parts[0] != "" or any(part in {"", ".", ".."} for part in parts[1:]):
        raise Refused(f"{label} file URI must not contain relative or empty components")
    return Path(decoded)


def _decode_package_root(uri: object, name: str, config_dir: Path, expected: Path) -> Path:
    if name == ROOT_PACKAGE:
        if uri != "../":
            raise Refused(f"root package rootUri must be exactly ../: {name}")
        root = _bind_real_directory(config_dir.parent, f"{name} package root")
    else:
        root = _bind_real_directory(_posix_file_uri(uri, f"{name} rootUri"), f"{name} package root")
    expected_root = _bind_real_directory(expected, f"{name} expected root")
    if root != expected_root:
        raise Refused(f"package root mismatch: {name}")
    return root


def _exact_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise Refused(f"{label} schema fields are invalid")
    return value


def _validate(args: argparse.Namespace) -> str:
    project_root = _bind_real_directory(Path(args.project_root), "project root")
    flutter_root = _bind_real_directory(Path(args.flutter_root), "Flutter root")
    pub_cache = _bind_real_directory(Path(args.pub_cache), "Pub cache")
    config_path, raw = _bind_regular_file(Path(args.package_config), "package config")
    lock_path, lock_bytes = _bind_regular_file(Path(args.lockfile), "lockfile")
    expected_config = project_root / ".dart_tool/package_config.json"
    if config_path != expected_config:
        raise Refused("package config is not the project .dart_tool/package_config.json")
    expected_lock = project_root / "pubspec.lock"
    if lock_path != expected_lock:
        raise Refused("lockfile is not the project pubspec.lock")

    document = _load_json(raw)
    if document.get("configVersion") != 2 or type(document.get("configVersion")) is not int:
        raise Refused("package config metadata mismatch: configVersion")
    if document.get("generator") != "pub":
        raise Refused("package config metadata mismatch: generator")
    if document.get("generatorVersion") != args.dart_version:
        raise Refused("package config metadata mismatch: generatorVersion")
    if document.get("flutterVersion") != args.flutter_version:
        raise Refused("package config metadata mismatch: flutterVersion")
    config_flutter = _bind_real_directory(
        _posix_file_uri(document.get("flutterRoot"), "flutterRoot"),
        "package config Flutter root",
    )
    if config_flutter != flutter_root:
        raise Refused("package config Flutter root mismatch")
    config_cache = _bind_real_directory(
        _posix_file_uri(document.get("pubCache"), "pubCache"),
        "package config Pub cache",
    )
    if config_cache != pub_cache:
        raise Refused("package config Pub cache mismatch")

    locked = _load_lock(lock_bytes)
    packages = document.get("packages")
    if not isinstance(packages, list):
        raise Refused("package config packages must be a list")
    expected_names = set(locked) | {ROOT_PACKAGE}
    if len(packages) != len(expected_names):
        raise Refused("package config package count mismatch")
    observed: set[str] = set()
    config_dir = config_path.parent
    for item in packages:
        entry = _exact_keys(item, PACKAGE_KEYS, "package config entry")
        name = entry.get("name")
        if not isinstance(name, str) or not PACKAGE_RE.fullmatch(name):
            raise Refused(f"unexpected or duplicate package config name: {name!r}")
        if name not in expected_names or name in observed:
            raise Refused(f"unexpected or duplicate package config name: {name!r}")
        observed.add(name)
        if entry.get("packageUri") != "lib/":
            raise Refused(f"packageUri must be exactly lib/: {name}")
        language_version = entry.get("languageVersion")
        if not isinstance(language_version, str) or not LANGUAGE_VERSION_RE.fullmatch(language_version):
            raise Refused(f"package languageVersion is absent or invalid: {name}")
        if name == ROOT_PACKAGE:
            expected_root = project_root
        else:
            lock_entry = locked[name]
            if lock_entry["source"] == "sdk":
                expected_root = flutter_root / SDK_ROOTS[name]
            else:
                expected_root = pub_cache / "hosted" / "pub.dev" / f"{name}-{lock_entry['version']}"
                hash_path = (
                    pub_cache / "hosted-hashes" / "pub.dev" / f"{name}-{lock_entry['version']}.sha256"
                )
                _hash_path, hash_bytes = _bind_regular_file(hash_path, f"hosted hash for {name}")
                try:
                    hash_text = hash_bytes.decode("ascii")
                except UnicodeDecodeError as suc:
                    raise Refused(f"hosted cache digest disagrees with lockfile: {name}") from suc
                if hash_text not in {lock_entry["sha256"], lock_entry["sha256"] + "\n"}:
                    raise Refused(f"hosted cache digest disagrees with lockfile: {name}")
        root = _decode_package_root(entry.get("rootUri"), name, config_dir, expected_root)
        _bind_real_directory(root / "lib", f"{name} library root")
    if observed != expected_names:
        raise Refused("package config package set mismatch")
    digest = hashlib.sha256(raw).hexdigest()
    if args.expected_digest is not None:
        if not isinstance(args.expected_digest, str) or not SHA256_RE.fullmatch(args.expected_digest):
            raise Refused("expected package config digest is invalid")
        if digest != args.expected_digest:
            raise Refused("package config digest changed")
    return digest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package-config", required=True)
    parser.add_argument("--lockfile", required=True)
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--flutter-root", required=True)
    parser.add_argument("--pub-cache", required=True)
    parser.add_argument("--flutter-version", required=True)
    parser.add_argument("--dart-version", required=True)
    parser.add_argument("--expected-digest")
    return parser


def main() -> int:
    try:
        digest = _validate(_parser().parse_args())
    except (Refused, OSError, UnicodeError, json.JSONDecodeError, yaml.YAMLError, RecursionError) as exc:
        print(f"flutter-package-config: {exc}", file=sys.stderr)
        return 1
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
