#!/usr/bin/env python3
"""Fail-closed Apple Xray VLESS-WS delivered-artifact provenance.

Binds every delivered iOS / macOS / simulator libWinsXrayVlessWsTransport.dylib
to the exact WinsXrayVlessWsTransport.m SHA-256 and to the production imports
LibXraySetSockCallback, dup2, getifaddrs, and setsockopt. Compiling the wrapper
source in a test harness is not evidence that a provenance-bound dylib was
built from that source. Mutating the wrapper source after artifact creation
must fail closed.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SOURCE_RELATIVE = "apple/EngineWrappers/WinsXrayVlessWsTransport.m"
WRAPPER_BUILDER_RELATIVE = "tools/build_apple_engine_wrappers.sh"
TEXT_LIMIT = 2 * 1024 * 1024
ARTIFACT_LIMIT = 64 * 1024 * 1024
PROVENANCE_LIMIT = 1024 * 1024
REBUILD_REQUIRED = (
    "Apple Xray VLESS-WS engine provenance is missing, stale, malformed, "
    "symbolic, or not bound to the current wrapper source and delivered "
    "dylibs. Cached Xray dylibs are owner-blocked until a verified rebuild "
    "refreshes provenance."
)
REQUIRED_EXPORTED = (
    "wins_xray_vless_ws_transport_configure",
    "wins_xray_vless_ws_transport_contract_version",
    "wins_xray_vless_ws_transport_start",
    "wins_xray_vless_ws_transport_stop",
)
REQUIRED_UNDEFINED = (
    "LibXraySetSockCallback",
    "dup2",
    "getifaddrs",
    "setsockopt",
)
WRAPPER_SPECS = (
    ("iphoneos", "ios/iphoneos/libWinsXrayVlessWsTransport.dylib", "IOS"),
    (
        "iphonesimulator",
        "ios/iphonesimulator/libWinsXrayVlessWsTransport.dylib",
        "IOSSIMULATOR",
    ),
    ("macosx", "macos/libWinsXrayVlessWsTransport.dylib", "MACOS"),
)
MACHO_PLATFORMS = {
    "1": "MACOS",
    "2": "IOS",
    "7": "IOSSIMULATOR",
    "MACOS": "MACOS",
    "IOS": "IOS",
    "IOSSIMULATOR": "IOSSIMULATOR",
}
UNDEFINED_NAME = re.compile(r"(?:^|\s)_([A-Za-z_][A-Za-z0-9_]*)(?:\s|$)")


def fail(message: str) -> None:
    raise SystemExit(message)


def identity(info: os.stat_result) -> tuple[object, ...]:
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


def require_absolute_tool(path: str, label: str) -> str:
    tool = pathlib.Path(path)
    if (
        not str(tool).startswith("/")
        or tool.is_symlink()
        or not tool.is_file()
        or not os.access(tool, os.X_OK)
    ):
        fail(f"{label} must be an absolute regular non-symlink executable: {path}")
    return str(tool)


def reject_duplicate_keys(pairs: list[tuple[object, object]]) -> dict[object, object]:
    result: dict[object, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def stable_read(path: pathlib.Path, label: str, limit: int) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        fail("O_NOFOLLOW is required for Apple Xray VLESS-WS provenance")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_uid != os.getuid()
        ):
            fail(
                f"{label} must be a nonempty owner-only single-link regular file: {path}"
            )
        if before.st_size > limit:
            fail(f"{label} exceeds the {limit} byte snapshot limit: {path}")
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            chunks = []
            remaining = opened.st_size
            while remaining > 0:
                block = os.read(fd, min(1024 * 1024, remaining))
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
            finished = os.fstat(fd)
        finally:
            os.close(fd)
        after = path.lstat()
    except OSError as error:
        fail(f"{label} is unreadable: {path} ({error})")
    if (
        identity(before) != identity(opened)
        or identity(opened) != identity(finished)
        or identity(finished) != identity(after)
    ):
        fail(f"{label} changed while it was snapshotted: {path}")
    payload = b"".join(chunks)
    if not payload:
        fail(f"{label} is empty: {path}")
    return payload


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def expect_equal(actual: object, expected: object, label: str) -> None:
    if actual != expected:
        fail(f"{label} mismatch: expected {expected!r}, found {actual!r}")


def json_type_name(value: object) -> str:
    if value is None:
        return "null"
    if type(value) is bool:
        return "boolean"
    if type(value) is int:
        return "integer"
    if type(value) is float:
        return "number"
    if type(value) is str:
        return "string"
    if type(value) is list:
        return "array"
    if type(value) is dict:
        return "object"
    return type(value).__name__


def load_json_object(path: pathlib.Path, label: str, limit: int) -> dict[str, object]:
    payload = stable_read(path, label, limit)
    try:
        value = json.loads(
            payload.decode("utf-8"), object_pairs_hook=reject_duplicate_keys
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        fail(f"{label} is invalid JSON: {error}")
    if type(value) is not dict:
        fail(f"{label} must be a JSON object")
    return value


def resolve_schema_node(
    schema: dict[str, object], node: dict[str, object]
) -> dict[str, object]:
    ref = node.get("$ref") if type(node) is dict else None
    if not ref:
        return node
    if type(ref) is not str or not ref.startswith("#/$defs/"):
        fail(f"unsupported schema ref {ref!r}")
    name = ref.split("/")[-1]
    defs = schema.get("$defs")
    if type(defs) is not dict or name not in defs:
        fail(f"schema is missing $defs/{name}")
    resolved = defs[name]
    if type(resolved) is not dict:
        fail(f"schema $defs/{name} is invalid")
    return resolved


def validate_schema(
    instance: object,
    schema: dict[str, object],
    node: dict[str, object],
    path: str,
) -> None:
    node = resolve_schema_node(schema, node)
    expected_type = node.get("type")
    if expected_type == "object":
        if type(instance) is not dict:
            fail(f"{path} must be an object, found {json_type_name(instance)}")
        required = node.get("required", [])
        for key in required:
            if key not in instance:
                fail(f"{path} omits required field {key}")
        properties = node.get("properties", {})
        additional = node.get("additionalProperties", True)
        for key, value in instance.items():
            if type(key) is not str:
                fail(f"{path} has a non-string field name")
            if key in properties and type(properties[key]) is dict:
                validate_schema(value, schema, properties[key], f"{path}.{key}")
            elif additional is False:
                fail(f"{path} has extra field {key}")
    elif expected_type == "array":
        if type(instance) is not list:
            fail(f"{path} must be an array, found {json_type_name(instance)}")
        min_items = node.get("minItems")
        if type(min_items) is int and len(instance) < min_items:
            fail(f"{path} has too few items")
        max_items = node.get("maxItems")
        if type(max_items) is int and len(instance) > max_items:
            fail(f"{path} has too many items")
        if node.get("uniqueItems") is True:
            encoded = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in instance]
            if len(set(encoded)) != len(encoded):
                fail(f"{path} contains duplicate items")
        items = node.get("items")
        if type(items) is dict:
            for index, value in enumerate(instance):
                validate_schema(value, schema, items, f"{path}[{index}]")
    elif expected_type == "string":
        if type(instance) is not str:
            fail(f"{path} must be a string, found {json_type_name(instance)}")
        min_length = node.get("minLength")
        if type(min_length) is int and len(instance) < min_length:
            fail(f"{path} is shorter than {min_length}")
        pattern = node.get("pattern")
        if type(pattern) is str and re.search(pattern, instance) is None:
            fail(f"{path} does not match {pattern}")
    elif expected_type == "integer":
        if type(instance) is bool or type(instance) is not int:
            fail(f"{path} must be an integer, found {json_type_name(instance)}")
    if "const" in node:
        const = node["const"]
        if instance != const or type(instance) is not type(const) or type(instance) is bool:
            if type(const) is not bool and type(instance) is bool:
                fail(f"{path} rejects bool-as-int / bool-as-const {instance!r}")
            if instance != const:
                fail(f"{path} must be {const!r}, found {instance!r}")
            if type(instance) is not type(const):
                fail(f"{path} has the wrong scalar type for const {const!r}")
    if "enum" in node:
        allowed = node["enum"]
        if type(allowed) is list and instance not in allowed:
            fail(f"{path} is not one of {allowed!r}")


def run_absolute(tool: str, args: list[str], label: str) -> str:
    completed = subprocess.run([tool, *args], capture_output=True, check=False)
    if completed.returncode != 0:
        fail(f"{label} failed ({tool})")
    return completed.stdout.decode("utf-8", "replace")


def platforms_from_otool(otool_text: str) -> list[str]:
    found = []
    for line in otool_text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("platform "):
            continue
        mapped = MACHO_PLATFORMS.get(stripped.split()[1])
        if mapped:
            found.append(mapped)
    return sorted(set(found))


def inspect_binary(
    path: pathlib.Path,
    expected_platform: str,
    lipo: str,
    file_tool: str,
    otool: str,
) -> tuple[list[str], str, str]:
    file_text = run_absolute(file_tool, ["-b", str(path)], f"file {path}").strip()
    arch_text = run_absolute(lipo, ["-archs", str(path)], f"lipo {path}").strip()
    architectures = [item for item in arch_text.split() if item]
    if not architectures:
        fail(f"{path} has no inspectable architectures")
    if "dynamically linked shared library" not in file_text and "Mach-O" not in file_text:
        fail(f"{path} is not a Mach-O dylib: {file_text}")
    if "current ar archive" in file_text:
        fail(f"{path} is an archive, not a dylib: {file_text}")
    platforms = platforms_from_otool(
        run_absolute(otool, ["-l", str(path)], f"otool {path}")
    )
    if platforms != [expected_platform]:
        fail(f"{path} platform {platforms!r} does not match {expected_platform}")
    return architectures, expected_platform, "mach-o-dylib"


def names_from_nm(nm_text: str, *, undefined: bool) -> list[str]:
    found: set[str] = set()
    for line in nm_text.splitlines():
        lowered = line.lower()
        is_undefined = "undefined" in lowered
        if undefined and not is_undefined:
            continue
        if not undefined and is_undefined:
            continue
        match = UNDEFINED_NAME.search(line)
        if match:
            found.add(match.group(1))
    return sorted(found)


def slice_symbols(
    path: pathlib.Path, arch: str, nm: str
) -> tuple[list[str], list[str]]:
    completed = subprocess.run(
        [nm, "-m", "-arch", arch, str(path)],
        capture_output=True,
        check=False,
    )
    text = completed.stdout.decode("utf-8", "replace")
    combined = f"{text}{completed.stderr.decode('utf-8', 'replace')}"
    if completed.returncode not in (0, 1):
        fail(f"nm -m failed for {path} slice {arch}")
    if "truncated" in combined.lower() or "malformed" in combined.lower():
        fail(f"{path} slice {arch} is not a parseable Mach-O symbol table")
    exported = names_from_nm(text, undefined=False)
    imported = names_from_nm(text, undefined=True)
    return exported, imported


def require_production_symbols(
    path: pathlib.Path, architectures: list[str], nm: str
) -> tuple[list[str], list[str]]:
    exported_union: set[str] = set()
    imported_union: set[str] = set()
    for arch in architectures:
        exported, imported = slice_symbols(path, arch, nm)
        exported_union.update(exported)
        imported_union.update(imported)
        missing_exported = [name for name in REQUIRED_EXPORTED if name not in exported]
        if missing_exported:
            fail(
                f"{path} slice {arch} is missing required exported symbols: "
                f"{' '.join(missing_exported)}"
            )
        missing_imported = [name for name in REQUIRED_UNDEFINED if name not in imported]
        if missing_imported:
            fail(
                f"{path} slice {arch} is missing required production imports: "
                f"{' '.join(missing_imported)}"
            )
    return (
        sorted(name for name in exported_union if name in REQUIRED_EXPORTED),
        sorted(name for name in imported_union if name in REQUIRED_UNDEFINED),
    )


def inspect_snapshot(
    payload: bytes,
    expected_platform: str,
    label: str,
    lipo: str,
    file_tool: str,
    otool: str,
    nm: str,
) -> dict[str, object]:
    tmp_dir = tempfile.mkdtemp(prefix="wins-xray-inspect-")
    try:
        os.chmod(tmp_dir, 0o700)
        path = pathlib.Path(tmp_dir) / "artifact"
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        fd = os.open(path, flags, 0o600)
        try:
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    fail(f"short inspect snapshot write for {label}")
                view = view[written:]
            os.fsync(fd)
            info = os.fstat(fd)
            if info.st_nlink != 1 or not stat.S_ISREG(info.st_mode):
                fail(f"{label} inspect snapshot is not a single-link file")
        finally:
            os.close(fd)
        architectures, platform_name, filetype = inspect_binary(
            path, expected_platform, lipo, file_tool, otool
        )
        exported, imported = require_production_symbols(path, architectures, nm)
        return {
            "architectures": architectures,
            "exported_symbols": exported,
            "filetype": filetype,
            "platform": platform_name,
            "undefined_symbols": imported,
        }
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def signature_normalized_sha256(payload: bytes, label: str) -> str:
    """SHA-256 of Mach-O bytes with their code signature normalized away.

    Staging and Xcode export re-sign the framework after this provenance is
    written. A private copy is re-signed ad hoc, which replaces any linker, ad
    hoc or distribution signature on every slice, the signature is removed, and
    the result is hashed. The macOS verifier and the cross-store gate compute
    the same digest on the shipped engine.
    """
    tmp_dir = tempfile.mkdtemp(prefix="wins-xray-normalize-")
    try:
        os.chmod(tmp_dir, 0o700)
        path = pathlib.Path(tmp_dir) / "artifact"
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        fd = os.open(path, flags, 0o600)
        try:
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    fail(f"short normalization snapshot write for {label}")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        run_absolute(
            "/usr/bin/codesign",
            ["--force", "--sign", "-", "--timestamp=none", str(path)],
            f"codesign normalization {label}",
        )
        run_absolute(
            "/usr/bin/codesign",
            ["--remove-signature", str(path)],
            f"codesign signature removal {label}",
        )
        return sha256_bytes(path.read_bytes())
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def current_bindings(paths: dict[str, str]) -> dict[str, object]:
    source_bytes = stable_read(
        pathlib.Path(paths["wrapper_source"]),
        "Apple Xray wrapper source",
        TEXT_LIMIT,
    )
    builder_bytes = stable_read(
        pathlib.Path(paths["builder"]),
        "Apple Xray wrapper builder",
        TEXT_LIMIT * 4,
    )
    engine_root = pathlib.Path(paths["engine_root"])
    lipo = require_absolute_tool(paths["lipo"], "lipo")
    file_tool = require_absolute_tool(paths["file"], "file")
    otool = require_absolute_tool(paths["otool"], "otool")
    nm = require_absolute_tool(paths["nm"], "nm")
    wrappers: dict[str, object] = {}
    for key, relative, expected_platform in WRAPPER_SPECS:
        wrapper_path = engine_root / relative
        wrapper_bytes = stable_read(
            wrapper_path, f"Apple Xray wrapper {key}", ARTIFACT_LIMIT
        )
        inspected = inspect_snapshot(
            wrapper_bytes,
            expected_platform,
            f"Apple Xray wrapper {key}",
            lipo,
            file_tool,
            otool,
            nm,
        )
        wrappers[key] = {
            "architectures": inspected["architectures"],
            "exported_symbols": inspected["exported_symbols"],
            "filetype": inspected["filetype"],
            "path": relative,
            "platform": inspected["platform"],
            "sha256": sha256_bytes(wrapper_bytes),
            "undefined_symbols": inspected["undefined_symbols"],
        }
        if key == "macosx":
            wrappers[key]["signature_normalized_sha256"] = signature_normalized_sha256(
                wrapper_bytes, f"Apple Xray wrapper {key}"
            )
    return {
        "builders": {
            "wrapper_builder": {
                "path": WRAPPER_BUILDER_RELATIVE,
                "sha256": sha256_bytes(builder_bytes),
            }
        },
        "component": "xray-apple-vless-ws-engine-wrappers",
        "generation": "vless-ws",
        "required_exported_symbols": list(REQUIRED_EXPORTED),
        "required_undefined_symbols": list(REQUIRED_UNDEFINED),
        "schema_version": 1,
        "source": {
            "path": SOURCE_RELATIVE,
            "sha256": sha256_bytes(source_bytes),
        },
        "wrappers": wrappers,
    }


def load_and_validate_provenance(
    provenance_raw: str, schema_raw: str
) -> tuple[pathlib.Path, dict[str, object]]:
    path = pathlib.Path(provenance_raw)
    if path.is_symlink() or not path.is_file():
        fail(f"{REBUILD_REQUIRED} Provenance path: {path}")
    recorded = load_json_object(path, "Apple Xray VLESS-WS engine provenance", PROVENANCE_LIMIT)
    schema = load_json_object(
        pathlib.Path(schema_raw), "Apple Xray VLESS-WS provenance schema", TEXT_LIMIT
    )
    validate_schema(recorded, schema, schema, "$")
    return path, recorded


def verify_provenance(paths: dict[str, str]) -> dict[str, object]:
    _, recorded = load_and_validate_provenance(paths["provenance"], paths["schema"])
    expected = current_bindings(paths)
    expect_equal(recorded, expected, "Apple Xray VLESS-WS engine provenance")
    return expected


def publish_atomic(output: pathlib.Path, payload: bytes) -> None:
    if output.is_symlink():
        fail(f"Apple Xray VLESS-WS engine provenance path must not be symbolic: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | nofollow
    tmp = output.with_name(f".apple-xray-vless-ws-engine-provenance.{secrets.token_hex(16)}")
    fd = os.open(tmp, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                fail("short Apple Xray VLESS-WS provenance write")
            view = view[written:]
        os.fsync(fd)
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            fail("Apple Xray VLESS-WS provenance temp is not owner-only single-link")
    except Exception:
        os.close(fd)
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    os.close(fd)
    os.replace(tmp, output)
    dest = output.lstat()
    if (
        not stat.S_ISREG(dest.st_mode)
        or dest.st_nlink != 1
        or dest.st_uid != os.getuid()
        or dest.st_size != len(payload)
    ):
        fail("Apple Xray VLESS-WS provenance publication is not a single-link owner file")


def write_provenance(paths: dict[str, str]) -> dict[str, object]:
    manifest = current_bindings(paths)
    schema = load_json_object(
        pathlib.Path(paths["schema"]), "Apple Xray VLESS-WS provenance schema", TEXT_LIMIT
    )
    validate_schema(manifest, schema, schema, "$")
    payload = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    publish_atomic(pathlib.Path(paths["provenance"]), payload)
    verify_provenance(paths)
    return manifest


def parse_argv(argv: list[str]) -> tuple[str, dict[str, str]]:
    if len(argv) != 11:
        fail(
            "Apple Xray provenance requires: command provenance project_root "
            "wrapper_source engine_root schema builder lipo file otool nm"
        )
    (
        command,
        provenance,
        project_root,
        wrapper_source,
        engine_root,
        schema,
        builder,
        lipo,
        file_tool,
        otool,
        nm,
    ) = argv
    return command, {
        "provenance": provenance,
        "project_root": project_root,
        "wrapper_source": wrapper_source,
        "engine_root": engine_root,
        "schema": schema,
        "builder": builder,
        "lipo": lipo,
        "file": file_tool,
        "otool": otool,
        "nm": nm,
    }


def main(argv: list[str] | None = None) -> int:
    command, paths = parse_argv(sys.argv[1:] if argv is None else argv)
    if command == "verify":
        verify_provenance(paths)
        return 0
    if command == "write":
        write_provenance(paths)
        return 0
    fail(f"Unknown Apple Xray provenance command: {command}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
