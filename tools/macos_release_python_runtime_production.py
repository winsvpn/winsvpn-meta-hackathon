#!/usr/bin/env python3
"""Produce the signed and notarized macOS ReleasePython distribution.

The trusted Python.org package remains the provenance input.  This producer
materializes it through one authenticated source closure, fuses the matching
PyPI x86_64 wheel images with the pinned arm64 wheel images, removes every
LC_RPATH, makes in-tree load commands relocatable, applies the owner Developer
ID hardened-runtime seal, notarizes and staples one complete Developer ID
Installer-signed flat package, and emits pre-placement ceremony evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import xml.etree.ElementTree as ElementTree
import zipfile
from xml.parsers.expat import ExpatError


EXPECTED_MAXIMUM_MINIMUM = "13.0"
EXPECTED_SDK = "26.5"
FINAL_RUNTIME = "/Library/WinsVPN/ReleasePython/3.14.7"
INPUT_CUSTODY_CONTRACT = "winsvpn-release-python-input-custody-v1"
INPUT_DESTINATION_ROOT = Path("/Library/WinsVPN/ReleasePythonInputs/sha256")
MAX_INPUT_ARTIFACT = 256 * 1024 * 1024
PSF_INSTALLER = "Developer ID Installer: Python Software Foundation (BMM5U3QVKW)"
OWNER_APPLICATION = "Developer ID Application: Win's VPN Inc (5YT8H4U72M)"
OWNER_INSTALLER = "Developer ID Installer: Win's VPN Inc (5YT8H4U72M)"
OWNER_TEAM = "5YT8H4U72M"
PACKAGE_NAME = "WinsVPN-ReleasePython-3.14.7.pkg"
PACKAGE_IDENTIFIER = "org.winsvpn.releasepython.pkg"
PACKAGE_INSTALL_LOCATION = "/Library/WinsVPN"
PACKAGE_VERSION = "3.14.7"
SOURCE_ENTRYPOINT_MEMBER = "Python-3.14.7/Programs/python.c"
UNSIGNED_EXECUTABLE_MEMORY_ENTITLEMENT = (
    "com.apple.security.cs.allow-unsigned-executable-memory"
)
CS_RUNTIME = 0x00010000
ENTITLED_EXECUTABLES = frozenset(
    {
        "Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python",
        "Python.framework/Versions/3.14/bin/python3.14",
        "Python.framework/Versions/3.14/bin/python3.14-intel64",
    }
)

TOOLS = {
    "arch": Path("/usr/bin/arch"),
    "codesign": Path("/usr/bin/codesign"),
    "cpio": Path("/usr/bin/cpio"),
    "dot_clean": Path("/usr/sbin/dot_clean"),
    "file": Path("/usr/bin/file"),
    "gzip": Path("/usr/bin/gzip"),
    "install_name_tool": Path("/usr/bin/install_name_tool"),
    "lipo": Path("/usr/bin/lipo"),
    "lsbom": Path("/usr/bin/lsbom"),
    "otool": Path("/usr/bin/otool"),
    "pkgbuild": Path("/usr/bin/pkgbuild"),
    "pkgutil": Path("/usr/sbin/pkgutil"),
    "productsign": Path("/usr/bin/productsign"),
    "python3": Path("/usr/bin/python3"),
    "spctl": Path("/usr/sbin/spctl"),
    "xcrun": Path("/usr/bin/xcrun"),
}


class ProducerError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_release_pins(path: Path) -> dict[str, object]:
    try:
        document = json.loads(path.read_text(encoding="ascii"))
        custody = document["tools"]["python"]["archive_custody"]["darwin_arm64"]
        runtime_count = custody["runtime_wheel_count"]
        wheel_count = custody["wheel_count"]
        wheels = custody["wheels"]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ProducerError(f"authenticated pin manifest is invalid: {exc}") from exc
    if (
        type(runtime_count) is not int
        or runtime_count != 25
        or type(wheel_count) is not int
        or wheel_count != 28
        or type(wheels) is not dict
        or set(wheels) != {str(index) for index in range(wheel_count)}
        or custody.get("source_entrypoint_member") != SOURCE_ENTRYPOINT_MEMBER
    ):
        raise ProducerError("authenticated ReleasePython pin inventory is not exact")
    for key in (
        "package",
        "sigstore_bundle",
        "source_archive",
        "source_sigstore_bundle",
        "sigstore_trusted_root",
        "sigstore_verifier",
    ):
        record = custody.get(key)
        if (
            type(record) is not dict
            or set(record) != {"path", "sha256"}
            or not isinstance(record["path"], str)
            or not isinstance(record["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
        ):
            raise ProducerError(f"authenticated ReleasePython pin is invalid: {key}")
    entrypoint_digest = custody.get("source_entrypoint_sha256")
    if not isinstance(entrypoint_digest, str) or re.fullmatch(r"[0-9a-f]{64}", entrypoint_digest) is None:
        raise ProducerError("authenticated entrypoint-source pin is invalid")
    return custody


def stat_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def load_input_snapshot_records(path: Path) -> tuple[str, list[dict[str, str]]]:
    try:
        data = path.read_bytes()
        document = json.loads(data.decode("ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProducerError(f"authenticated input manifest is invalid: {exc}") from exc
    if (
        type(document) is not dict
        or set(document) != {
            "artifact_count",
            "artifacts",
            "contract",
            "destination_root",
            "pin_manifest_sha256",
            "schema_version",
        }
        or document.get("contract") != INPUT_CUSTODY_CONTRACT
        or document.get("schema_version") != 1
        or type(document.get("schema_version")) is not int
        or document.get("artifact_count") != 34
        or type(document.get("artifact_count")) is not int
        or document.get("destination_root") != str(INPUT_DESTINATION_ROOT)
        or type(document.get("artifacts")) is not list
        or len(document["artifacts"]) != 34
        or re.fullmatch(r"[0-9a-f]{64}", document.get("pin_manifest_sha256", "")) is None
    ):
        raise ProducerError("authenticated input manifest contract is not exact")
    records: list[dict[str, str]] = []
    kind_counts: dict[str, int] = {}
    for index, record in enumerate(document["artifacts"]):
        if (
            type(record) is not dict
            or set(record) != {"kind", "leaf", "mode", "path", "sha256"}
            or not all(type(value) is str for value in record.values())
        ):
            raise ProducerError(f"authenticated input record {index} is invalid")
        kind = record["kind"]
        leaf = record["leaf"]
        expected = record["sha256"]
        mode = record["mode"]
        expected_mode = "0555" if kind == "sigstore-verifier" else "0444"
        if (
            kind not in {
                "package",
                "sigstore-bundle",
                "source-archive",
                "source-sigstore-bundle",
                "sigstore-trusted-root",
                "sigstore-verifier",
                "wheel",
            }
            or leaf != Path(leaf).name
            or leaf in {"", ".", ".."}
            or re.fullmatch(r"[0-9a-f]{64}", expected) is None
            or mode != expected_mode
            or Path(record["path"]) != INPUT_DESTINATION_ROOT / expected / leaf
        ):
            raise ProducerError(f"authenticated input record {index} is not exact")
        kind_counts[kind] = kind_counts.get(kind, 0) + 1
        records.append(record)
    if (
        kind_counts
        != {
            "package": 1,
            "sigstore-bundle": 1,
            "source-archive": 1,
            "source-sigstore-bundle": 1,
            "sigstore-trusted-root": 1,
            "sigstore-verifier": 1,
            "wheel": 28,
        }
        or len({record["leaf"] for record in records}) != 34
    ):
        raise ProducerError("authenticated input record inventory is not exact")
    return hashlib.sha256(data).hexdigest(), records


def snapshot_release_inputs(
    source: Path,
    destination: Path,
    manifest: Path,
) -> dict[str, object]:
    manifest_sha256, records = load_input_snapshot_records(manifest)
    if (
        not source.is_absolute()
        or source.is_symlink()
        or not source.is_dir()
        or destination.exists()
        or destination.is_symlink()
    ):
        raise ProducerError("input snapshot endpoints are unsafe")
    source_before = source.lstat()
    destination.mkdir(mode=0o700)
    source_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    source_fd = os.open(source, source_flags)
    destination_fd = os.open(destination, source_flags)
    held: list[tuple[dict[str, str], int, os.stat_result]] = []
    expected_leaves = {record["leaf"] for record in records}
    try:
        opened_source = os.fstat(source_fd)
        opened_destination = os.fstat(destination_fd)
        if (
            not stat.S_ISDIR(opened_source.st_mode)
            or stat_identity(source_before) != stat_identity(opened_source)
            or not stat.S_ISDIR(opened_destination.st_mode)
            or opened_destination.st_uid != os.geteuid()
            or stat.S_IMODE(opened_destination.st_mode) != 0o700
            or os.listdir(destination_fd)
            or set(os.listdir(source_fd)) != expected_leaves
        ):
            raise ProducerError("input snapshot directory identity is invalid")
        for record in records:
            leaf = record["leaf"]
            before = os.stat(leaf, dir_fd=source_fd, follow_symlinks=False)
            descriptor = os.open(
                leaf,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=source_fd,
            )
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_size < 1
                or opened.st_size > MAX_INPUT_ARTIFACT
                or stat_identity(before) != stat_identity(opened)
            ):
                os.close(descriptor)
                raise ProducerError(f"input snapshot source is invalid: {leaf}")
            held.append((record, descriptor, opened))

        inventory: list[str] = []
        for record, descriptor, opened in held:
            destination_leaf = os.open(
                record["leaf"],
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=destination_fd,
            )
            digest = hashlib.sha256()
            copied = 0
            try:
                while copied < opened.st_size:
                    block = os.read(descriptor, min(1024 * 1024, opened.st_size - copied))
                    if not block:
                        raise ProducerError(f"input snapshot source was truncated: {record['leaf']}")
                    digest.update(block)
                    view = memoryview(block)
                    offset = 0
                    while offset < len(view):
                        offset += os.write(destination_leaf, view[offset:])
                    copied += len(block)
                if os.read(descriptor, 1):
                    raise ProducerError(f"input snapshot source grew: {record['leaf']}")
                os.fchmod(destination_leaf, int(record["mode"], 8))
                os.fsync(destination_leaf)
            finally:
                os.close(destination_leaf)
            if digest.hexdigest() != record["sha256"]:
                raise ProducerError(f"input snapshot digest mismatch: {record['leaf']}")
            inventory.append(f"{record['leaf']} {record['sha256']} {record['mode']}")

        if (
            stat_identity(opened_source) != stat_identity(os.fstat(source_fd))
            or stat_identity(opened_source) != stat_identity(source.lstat())
            or set(os.listdir(source_fd)) != expected_leaves
        ):
            raise ProducerError("input snapshot source directory changed while held")
        for record, descriptor, opened in held:
            current = os.stat(record["leaf"], dir_fd=source_fd, follow_symlinks=False)
            if (
                stat_identity(opened) != stat_identity(os.fstat(descriptor))
                or stat_identity(opened) != stat_identity(current)
            ):
                raise ProducerError(f"input snapshot source changed while held: {record['leaf']}")

        if set(os.listdir(destination_fd)) != expected_leaves:
            raise ProducerError("input snapshot destination inventory is not exact")
        for record in records:
            descriptor = os.open(
                record["leaf"],
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=destination_fd,
            )
            digest = hashlib.sha256()
            try:
                info = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != int(record["mode"], 8)
                    or info.st_size < 1
                    or info.st_size > MAX_INPUT_ARTIFACT
                ):
                    raise ProducerError(f"input snapshot destination is invalid: {record['leaf']}")
                while True:
                    block = os.read(descriptor, 1024 * 1024)
                    if not block:
                        break
                    digest.update(block)
            finally:
                os.close(descriptor)
            if digest.hexdigest() != record["sha256"]:
                raise ProducerError(f"input snapshot destination digest mismatch: {record['leaf']}")
        os.fchmod(destination_fd, 0o500)
        os.fsync(destination_fd)
        return {
            "artifact_count": len(records),
            "input_manifest_sha256": manifest_sha256,
            "inventory_sha256": hashlib.sha256(
                ("\n".join(sorted(inventory)) + "\n").encode("utf-8")
            ).hexdigest(),
        }
    finally:
        for _record, descriptor, _opened in held:
            os.close(descriptor)
        os.close(destination_fd)
        os.close(source_fd)


def pinned_leaf(custody: dict[str, object], key: str, source: Path) -> Path:
    record = custody[key]
    assert isinstance(record, dict)
    path = source / Path(record["path"]).name
    require_hash(path, record["sha256"])
    return path


def x86_wheel_pins(custody: dict[str, object]) -> dict[str, str]:
    runtime_count = custody["runtime_wheel_count"]
    wheel_count = custody["wheel_count"]
    wheels = custody["wheels"]
    assert isinstance(runtime_count, int) and isinstance(wheel_count, int)
    assert isinstance(wheels, dict)
    result: dict[str, str] = {}
    for index in range(runtime_count, wheel_count):
        record = wheels[str(index)]
        if type(record) is not dict or set(record) != {"path", "sha256"}:
            raise ProducerError(f"x86_64 wheel pin {index} is invalid")
        result[Path(record["path"]).name] = record["sha256"]
    if len(result) != 3:
        raise ProducerError("x86_64 wheel pin inventory is not exact")
    return result


def extract_authenticated_entrypoint(source_archive: Path, expected: str) -> bytes:
    seen: set[str] = set()
    selected: bytes | None = None
    with tarfile.open(source_archive, mode="r:xz") as archive:
        members = archive.getmembers()
        if not members or len(members) > 100000:
            raise ProducerError("CPython source archive member inventory is invalid")
        for member in members:
            pure = PurePosixPath(member.name)
            if (
                not member.name
                or "\\" in member.name
                or pure.is_absolute()
                or any(part in {"", ".", ".."} for part in pure.parts)
                or member.name in seen
                or not (member.isdir() or member.isreg())
            ):
                raise ProducerError(f"unsafe CPython source archive member: {member.name!r}")
            seen.add(member.name)
            if member.name == SOURCE_ENTRYPOINT_MEMBER:
                if not member.isreg() or member.size < 1 or member.size > 1024 * 1024:
                    raise ProducerError("CPython entrypoint member metadata is invalid")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ProducerError("CPython entrypoint member is unreadable")
                selected = stream.read(1024 * 1024 + 1)
    if selected is None or hashlib.sha256(selected).hexdigest() != expected:
        raise ProducerError("CPython entrypoint member provenance is not exact")
    return selected


def run(
    argv: list[str | Path],
    *,
    env: dict[str, str],
    timeout: int = 600,
    expected: set[int] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    command = [str(item) for item in argv]
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
        timeout=timeout,
    )
    accepted = {0} if expected is None else expected
    if completed.returncode not in accepted:
        output = (completed.stdout + completed.stderr).decode("utf-8", "replace")
        displayed = list(command)
        for index, item in enumerate(displayed[:-1]):
            if item in {"--issuer", "--password"}:
                displayed[index + 1] = "<redacted>"
        raise ProducerError(
            f"command failed with exit {completed.returncode}: {displayed!r}: {output[-4000:]}"
        )
    return completed


def run_pipeline(
    producer_argv: list[str | Path],
    consumer_argv: list[str | Path],
    *,
    env: dict[str, str],
    cwd: Path | None = None,
    timeout: int = 1800,
) -> bytes:
    producer_command = [str(item) for item in producer_argv]
    consumer_command = [str(item) for item in consumer_argv]
    producer = subprocess.Popen(
        producer_command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    if producer.stdout is None or producer.stderr is None:
        producer.kill()
        raise ProducerError("package payload pipeline could not be created")
    consumer = subprocess.Popen(
        consumer_command,
        stdin=producer.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        env=env,
    )
    producer.stdout.close()
    try:
        consumer_stdout, consumer_stderr = consumer.communicate(timeout=timeout)
        producer_stderr = producer.stderr.read()
        producer_returncode = producer.wait(timeout=30)
    except subprocess.TimeoutExpired as exc:
        consumer.kill()
        producer.kill()
        consumer.communicate()
        producer.communicate()
        raise ProducerError("package payload pipeline timed out") from exc
    if producer_returncode != 0 or consumer.returncode != 0:
        output = (producer_stderr + consumer_stdout + consumer_stderr).decode(
            "utf-8", "replace"
        )
        raise ProducerError(
            "package payload pipeline failed: "
            f"{producer_command!r} -> {consumer_command!r}: {output[-4000:]}"
        )
    return consumer_stdout


def require_hash(path: Path, expected: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise ProducerError(f"required input is not one regular file: {path}")
    actual = sha256(path)
    if actual != expected:
        raise ProducerError(f"SHA-256 mismatch for {path}: {actual}")


def text(completed: subprocess.CompletedProcess[bytes]) -> str:
    return (completed.stdout + completed.stderr).decode("utf-8", "strict")


def version_tuple(value: str) -> tuple[int, int, int]:
    try:
        parts = tuple(int(part) for part in value.split("."))
    except ValueError as exc:
        raise ProducerError(f"invalid macOS deployment version: {value!r}") from exc
    if not 1 <= len(parts) <= 3 or any(part < 0 or part > 65535 for part in parts):
        raise ProducerError(f"invalid macOS deployment version: {value!r}")
    return (parts + (0, 0, 0))[:3]


def is_macho(path: Path, env: dict[str, str]) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    with path.open("rb") as stream:
        magic = stream.read(4)
    if magic not in {
        b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
    }:
        return False
    description = text(run([TOOLS["file"], "-b", path], env=env))
    return "Mach-O" in description and "archive" not in description


def macho_paths(root: Path, env: dict[str, str]) -> list[Path]:
    return [path for path in sorted(root.rglob("*")) if is_macho(path, env)]


def architectures(path: Path, env: dict[str, str]) -> tuple[str, ...]:
    output = text(run([TOOLS["lipo"], "-archs", path], env=env)).strip()
    return tuple(output.split())


def validate_wheel_member(info: zipfile.ZipInfo) -> PurePosixPath:
    name = info.filename
    pure = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or pure.is_absolute()
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise ProducerError(f"unsafe wheel member: {name!r}")
    unix_mode = info.external_attr >> 16
    if stat.S_IFMT(unix_mode) == stat.S_IFLNK:
        raise ProducerError(f"wheel symbolic link rejected: {name}")
    return pure


def extract_wheel(wheel: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    with zipfile.ZipFile(wheel) as archive:
        infos = archive.infolist()
        if not infos:
            raise ProducerError(f"empty wheel: {wheel}")
        for info in infos:
            pure = validate_wheel_member(info)
            target = destination.joinpath(*pure.parts)
            if info.is_dir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if target.exists() or target.is_symlink():
                raise ProducerError(f"duplicate wheel member: {pure}")
            with archive.open(info) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output, 1024 * 1024)


def merge_x86_vendor(
    candidate: Path,
    scratch: Path,
    x86_inputs: Path,
    x86_wheels: dict[str, str],
    env: dict[str, str],
) -> list[str]:
    vendor = candidate / "vendor"
    extracted_root = scratch / "x86-wheels"
    extracted_root.mkdir(mode=0o700)
    merged: list[str] = []
    x86_images: list[tuple[Path, Path]] = []
    for index, (filename, expected) in enumerate(sorted(x86_wheels.items())):
        wheel = x86_inputs / filename
        require_hash(wheel, expected)
        extracted = extracted_root / str(index)
        extract_wheel(wheel, extracted)
        for source in macho_paths(extracted, env):
            x86_images.append((source, source.relative_to(extracted)))

    arm_images = {
        path.relative_to(vendor): path
        for path in macho_paths(vendor, env)
    }
    x86_relatives = {relative for _source, relative in x86_images}
    if x86_relatives != set(arm_images):
        missing = sorted(str(path) for path in set(arm_images) - x86_relatives)
        extra = sorted(str(path) for path in x86_relatives - set(arm_images))
        raise ProducerError(f"native wheel image closure differs: missing={missing} extra={extra}")

    for x86_source, relative in sorted(x86_images, key=lambda item: str(item[1])):
        arm_source = arm_images[relative]
        if architectures(arm_source, env) != ("arm64",):
            raise ProducerError(f"pinned vendor input is not thin arm64: {relative}")
        if architectures(x86_source, env) != ("x86_64",):
            raise ProducerError(f"counterpart vendor input is not thin x86_64: {relative}")
        temporary = arm_source.with_name(f".{arm_source.name}.relpy3-lipo")
        if temporary.exists() or temporary.is_symlink():
            raise ProducerError(f"temporary merge output already exists: {temporary}")
        mode = stat.S_IMODE(arm_source.stat().st_mode)
        run(
            [TOOLS["lipo"], "-create", arm_source, x86_source, "-output", temporary],
            env=env,
        )
        temporary.chmod(mode)
        os.replace(temporary, arm_source)
        if set(architectures(arm_source, env)) != {"arm64", "x86_64"}:
            raise ProducerError(f"universal2 merge failed: {relative}")
        merged.append(str(relative))
    return merged


def parse_load_command_records(
    path: Path,
    output: str,
) -> tuple[list[str], list[str], list[str], list[str], list[str]]:
    """Parse the security-relevant load commands from every reported slice."""
    lines = output.splitlines()
    minimums: list[str] = []
    rpaths: list[str] = []
    dependencies: list[str] = []
    dylib_ids: list[str] = []
    dylinkers: list[str] = []
    forbidden = {
        "cmd LC_DYLD_ENVIRONMENT",
        "cmd LC_LAZY_LOAD_DYLIB",
        "cmd LC_LOAD_UPWARD_DYLIB",
        "cmd LC_LOAD_WEAK_DYLIB",
    }

    def field_after(index: int, field: str, maximum: int) -> str:
        for candidate in lines[index + 1:index + maximum]:
            parts = candidate.strip().split()
            if len(parts) >= 2 and parts[0] == field:
                return parts[1]
        raise ProducerError(f"malformed {lines[index].strip()} in {path}")

    def name_after(index: int) -> str:
        for candidate in lines[index + 1:index + 8]:
            match = re.match(r"\s*name\s+(.+?)\s+\(offset\s+[0-9]+\)\s*$", candidate)
            if match:
                return match.group(1)
        raise ProducerError(f"malformed {lines[index].strip()} in {path}")

    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped in forbidden:
            raise ProducerError(f"forbidden load command in {path}: {stripped}")
        if stripped == "cmd LC_BUILD_VERSION":
            platform = field_after(index, "platform", 12).lower()
            if platform not in {"1", "macos"}:
                raise ProducerError(f"non-macOS LC_BUILD_VERSION in {path}: {platform}")
            minimums.append(field_after(index, "minos", 12))
        elif stripped == "cmd LC_VERSION_MIN_MACOSX":
            minimums.append(field_after(index, "version", 8))
        elif stripped == "cmd LC_RPATH":
            rpaths.append(field_after(index, "path", 8))
        elif stripped in {"cmd LC_LOAD_DYLIB", "cmd LC_REEXPORT_DYLIB"}:
            dependencies.append(name_after(index))
        elif stripped == "cmd LC_ID_DYLIB":
            dylib_ids.append(name_after(index))
        elif stripped == "cmd LC_LOAD_DYLINKER":
            dylinkers.append(name_after(index))
    return minimums, rpaths, dependencies, dylib_ids, dylinkers


def load_command_records(
    path: Path,
    env: dict[str, str],
) -> tuple[list[str], list[str], list[str], list[str], list[str]]:
    records = ([], [], [], [], [])
    for architecture in architectures(path, env):
        current = load_command_records_for_architecture(path, architecture, env)
        for aggregate, values in zip(records, current):
            aggregate.extend(values)
    return records


def load_command_records_for_architecture(
    path: Path,
    architecture: str,
    env: dict[str, str],
) -> tuple[list[str], list[str], list[str], list[str], list[str]]:
    output = text(run([TOOLS["otool"], "-arch", architecture, "-l", path], env=env))
    return parse_load_command_records(path, output)


def validate_dependency(candidate: Path, path: Path, dependency: str) -> None:
    if "\x00" in dependency:
        raise ProducerError(f"unsafe dependency in {path}: {dependency}")
    if dependency.startswith(("/usr/lib/", "/System/Library/")):
        if any(part in {".", ".."} for part in dependency.split("/")):
            raise ProducerError(f"unsafe system dependency in {path}: {dependency}")
        return
    if dependency.startswith("@loader_path/"):
        target = Path(os.path.normpath(path.parent / dependency[len("@loader_path/"):]))
    else:
        raise ProducerError(f"dependency escapes the runtime/system closure in {path}: {dependency}")
    try:
        candidate_root = candidate.resolve(strict=True)
        resolved = target.resolve(strict=True)
        resolved.relative_to(candidate_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ProducerError(f"relative dependency escapes candidate in {path}: {dependency}") from exc
    if not resolved.is_file() or resolved.is_symlink():
        raise ProducerError(f"relative dependency is not one retained file in {path}: {dependency}")


def delete_rpaths_per_slice(path: Path, env: dict[str, str]) -> None:
    archs = architectures(path, env)
    mode = stat.S_IMODE(path.stat().st_mode)
    if len(archs) == 1:
        _minimums, rpaths, _dependencies, _dylib_ids, _dylinkers = load_command_records(path, env)
        for rpath in rpaths:
            run([TOOLS["install_name_tool"], "-delete_rpath", rpath, path], env=env)
        if load_command_records(path, env)[1]:
            raise ProducerError(f"LC_RPATH survived thin-slice remediation: {path}:{archs[0]}")
        return

    thins: list[Path] = []
    for architecture in archs:
        thin = path.with_name(f".{path.name}.relpy3-{architecture}")
        run([TOOLS["lipo"], path, "-thin", architecture, "-output", thin], env=env)
        thin.chmod(mode)
        _minimums, rpaths, _dependencies, _dylib_ids, _dylinkers = load_command_records(thin, env)
        for rpath in rpaths:
            run([TOOLS["install_name_tool"], "-delete_rpath", rpath, thin], env=env)
        if load_command_records(thin, env)[1]:
            raise ProducerError(f"LC_RPATH survived thin-slice remediation: {path}:{architecture}")
        thins.append(thin)
    combined = path.with_name(f".{path.name}.relpy3-rpath")
    run([TOOLS["lipo"], "-create", *thins, "-output", combined], env=env)
    combined.chmod(mode)
    os.replace(combined, path)
    for thin in thins:
        thin.unlink()


def in_tree_dependency_target(candidate: Path, dependency: str) -> Path | None:
    framework = "/Library/Frameworks/Python.framework/"
    runtime = f"{FINAL_RUNTIME}/"
    if dependency.startswith(framework):
        return candidate / "Python.framework" / dependency[len(framework):]
    if dependency.startswith(runtime):
        return candidate / dependency[len(runtime):]
    return None


def canonical_dylib_id(candidate: Path, path: Path) -> str:
    path.relative_to(candidate)
    return f"@loader_path/{path.name}"


def rewrite_in_tree_dependencies(candidate: Path, env: dict[str, str]) -> list[str]:
    changed: list[str] = []
    for path in macho_paths(candidate, env):
        _minimums, _rpaths, dependencies, dylib_ids, _dylinkers = load_command_records(path, env)
        replacements: dict[str, str] = {}
        for dependency in dependencies:
            target = in_tree_dependency_target(candidate, dependency)
            if target is None:
                continue
            try:
                target.relative_to(candidate)
            except ValueError as exc:
                raise ProducerError(f"dependency target escapes candidate: {dependency}") from exc
            relative = os.path.relpath(target, path.parent)
            replacement = f"@loader_path/{relative}"
            replacements[dependency] = replacement
        for old, new in sorted(replacements.items()):
            run([TOOLS["install_name_tool"], "-change", old, new, path], env=env)
        id_changed = False
        if macho_filetype(path, env) == "DYLIB":
            expected_id = canonical_dylib_id(candidate, path)
            if not dylib_ids or any(item != expected_id for item in dylib_ids):
                run([TOOLS["install_name_tool"], "-id", expected_id, path], env=env)
                id_changed = True
        elif dylib_ids:
            raise ProducerError(f"non-dylib carries LC_ID_DYLIB: {path}")
        if replacements or id_changed:
            changed.append(str(path.relative_to(candidate)))
    for path in macho_paths(candidate, env):
        _minimums, _rpaths, dependencies, dylib_ids, dylinkers = load_command_records(path, env)
        if any(in_tree_dependency_target(candidate, item) is not None for item in dependencies):
            raise ProducerError(f"absolute in-tree dependency survived relocation: {path}")
        expected_ids = (
            [canonical_dylib_id(candidate, path)] * len(architectures(path, env))
            if macho_filetype(path, env) == "DYLIB"
            else []
        )
        if dylib_ids != expected_ids:
            raise ProducerError(f"LC_ID_DYLIB policy failed after relocation: {path}")
        expected_dylinkers = ["/usr/lib/dyld"] * len(architectures(path, env)) if (
            macho_filetype(path, env) == "EXECUTE"
        ) else []
        if dylinkers != expected_dylinkers:
            raise ProducerError(f"LC_LOAD_DYLINKER policy failed after relocation: {path}")
    return changed


def remove_rpaths(candidate: Path, env: dict[str, str]) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for path in macho_paths(candidate, env):
        relative = str(path.relative_to(candidate))
        minimums_before, rpaths, _dependencies, _dylib_ids, _dylinkers = load_command_records(path, env)
        if rpaths:
            delete_rpaths_per_slice(path, env)
        minimums_after, remaining, _dependencies, _dylib_ids, _dylinkers = load_command_records(path, env)
        if remaining or minimums_after != minimums_before:
            raise ProducerError(f"rpath removal changed deployment metadata: {relative}")
        records.append({
            "minimums": minimums_after,
            "path": relative,
            "removed_rpaths": rpaths,
        })
    return records


def remove_stale_bundle_seals(candidate: Path) -> list[str]:
    removed: list[str] = []
    for relative in (
        "Python.framework/Versions/3.14/_CodeSignature",
        "Python.framework/Versions/3.14/Resources/Python.app/Contents/_CodeSignature",
    ):
        path = candidate / relative
        if path.is_symlink():
            raise ProducerError(f"stale signature path is symbolic: {path}")
        if path.exists():
            if not path.is_dir():
                raise ProducerError(f"stale signature path is not a directory: {path}")
            shutil.rmtree(path)
            removed.append(relative)
    return removed


def remove_gui_closure(candidate: Path) -> list[str]:
    """Remove Tcl/Tk and the stdlib modules that would select that closure.

    Tk 9.0 contains LC_LOAD_WEAK_DYLIB even after its deployment target is
    raised.  The fixed native launcher forbids that load command.  The frozen
    ReleasePython worker is headless and has no Tcl/Tk consumer.
    """
    required = (
        "Python.framework/Versions/3.14/Frameworks/Tcl.framework",
        "Python.framework/Versions/3.14/Frameworks/Tk.framework",
        "Python.framework/Versions/3.14/lib/python3.14/lib-dynload/_tkinter.cpython-314-darwin.so",
    )
    optional = (
        "Python.framework/Versions/3.14/lib/python3.14/tkinter",
        "Python.framework/Versions/3.14/lib/python3.14/idlelib",
        "Python.framework/Versions/3.14/lib/python3.14/turtledemo",
        "Python.framework/Versions/3.14/lib/python3.14/turtle.py",
    )
    removed: list[str] = []
    for relative in (*required, *optional):
        path = candidate / relative
        if path.is_symlink():
            raise ProducerError(f"GUI closure root is symbolic: {path}")
        if not path.exists():
            if relative in required:
                raise ProducerError(f"required GUI closure input is absent: {path}")
            continue
        if path.is_dir():
            shutil.rmtree(path)
        elif path.is_file():
            path.unlink()
        else:
            raise ProducerError(f"GUI closure contains an unsupported root: {path}")
        removed.append(relative)
    return removed


def remove_development_closure(candidate: Path) -> list[str]:
    relative = "Python.framework/Versions/3.14/lib/python3.14/config-3.14-darwin"
    path = candidate / relative
    if path.is_symlink() or not path.is_dir():
        raise ProducerError(f"development closure root is absent or unsafe: {path}")
    shutil.rmtree(path)
    return [relative]


def build_direct_entrypoints(
    candidate: Path,
    scratch: Path,
    source: Path,
    expected_source_sha256: str,
    env: dict[str, str],
) -> dict[str, object]:
    require_hash(source, expected_source_sha256)
    clang = Path(text(run([TOOLS["xcrun"], "--find", "clang"], env=env)).strip())
    linker = Path(text(run([TOOLS["xcrun"], "--find", "ld"], env=env)).strip())
    sdk_reported = Path(text(run([
        TOOLS["xcrun"], "--sdk", "macosx", "--show-sdk-path",
    ], env=env)).strip())
    sdk_version = text(run([
        TOOLS["xcrun"], "--sdk", "macosx", "--show-sdk-version",
    ], env=env)).strip()
    try:
        sdk_reported_identity = stat_identity(sdk_reported.lstat())
        sdk = sdk_reported.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ProducerError("reported SDK path is unavailable") from exc
    if (
        not clang.is_file()
        or clang.is_symlink()
        or not linker.is_file()
        or linker.is_symlink()
        or not sdk.is_dir()
        or sdk.is_symlink()
        or sdk_version != EXPECTED_SDK
    ):
        raise ProducerError(
            f"compiler, linker, or SDK drift: clang={clang} linker={linker} "
            f"sdk={sdk} version={sdk_version}"
        )
    clang_sha256 = sha256(clang)
    linker_sha256 = sha256(linker)
    sdk_identity = stat_identity(sdk.lstat())
    built = scratch / "python-direct-universal2"
    first_build = scratch / "python-direct-universal2.first"
    command: list[str | Path] = [
        clang,
        "-arch", "arm64", "-arch", "x86_64",
        "-isysroot", sdk,
        f"-mmacosx-version-min={EXPECTED_MAXIMUM_MINIMUM}",
        "-Wl,-headerpad_max_install_names",
        "-I", candidate / "Python.framework/Headers",
        source,
        candidate / "Python.framework/Versions/3.14/Python",
        "-o", built,
    ]
    run(command, env=env)
    shutil.copyfile(built, first_build)
    built.unlink()
    run(command, env=env)
    if sha256(first_build) != sha256(built):
        raise ProducerError("direct interpreter entrypoint builds are not byte-identical")
    first_build.unlink()
    if (
        sha256(clang) != clang_sha256
        or sha256(linker) != linker_sha256
        or stat_identity(sdk_reported.lstat()) != sdk_reported_identity
        or stat_identity(sdk.lstat()) != sdk_identity
        or text(run([
            TOOLS["xcrun"], "--sdk", "macosx", "--show-sdk-version",
        ], env=env)).strip() != sdk_version
    ):
        raise ProducerError("compiler, linker, or SDK changed during entrypoint build")
    if set(architectures(built, env)) != {"arm64", "x86_64"}:
        raise ProducerError("direct interpreter entrypoint is not universal2")
    minimums, rpaths, _dependencies, _dylib_ids, _dylinkers = load_command_records(built, env)
    if minimums != [EXPECTED_MAXIMUM_MINIMUM, EXPECTED_MAXIMUM_MINIMUM] or rpaths:
        raise ProducerError(f"direct interpreter entrypoint metadata mismatch: {minimums} {rpaths}")

    app = candidate / "Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python"
    cli = candidate / "Python.framework/Versions/3.14/bin/python3.14"
    intel = candidate / "Python.framework/Versions/3.14/bin/python3.14-intel64"
    shutil.copyfile(built, app)
    shutil.copyfile(built, cli)
    app.chmod(0o700)
    cli.chmod(0o700)
    run([TOOLS["lipo"], built, "-thin", "x86_64", "-output", intel], env=env)
    intel.chmod(0o700)
    return {
        "clang": str(clang),
        "clang_sha256": clang_sha256,
        "linker": str(linker),
        "linker_sha256": linker_sha256,
        "reproducible_sha256": sha256(built),
        "sdk": str(sdk),
        "sdk_reported": str(sdk_reported),
        "sdk_version": sdk_version,
        "source": str(source),
        "source_sha256": sha256(source),
    }


def make_tree_mutable(candidate: Path) -> None:
    for path in sorted(candidate.rglob("*"), key=lambda item: len(item.parts)):
        if path.is_symlink():
            continue
        mode = stat.S_IMODE(path.stat().st_mode)
        path.chmod(mode | stat.S_IRUSR | stat.S_IWUSR | (stat.S_IXUSR if path.is_dir() else 0))
    candidate.chmod(0o700)


def macho_filetype(path: Path, env: dict[str, str]) -> str:
    output = text(run([TOOLS["otool"], "-hv", path], env=env))
    types = {
        line.split()[4]
        for line in output.splitlines()
        if line.startswith("MH_MAGIC") and len(line.split()) >= 5
    }
    if len(types) != 1 or not types <= {"EXECUTE", "DYLIB", "BUNDLE"}:
        raise ProducerError(f"Mach-O file type is invalid or inconsistent: {path}: {types}")
    return next(iter(types))


def make_tree_readonly(candidate: Path, env: dict[str, str]) -> None:
    for path in sorted(candidate.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if path.is_symlink():
            continue
        if path.is_dir():
            path.chmod(0o555)
        else:
            mode = stat.S_IMODE(path.stat().st_mode)
            if is_macho(path, env):
                path.chmod(0o555 if macho_filetype(path, env) == "EXECUTE" else 0o444)
            else:
                path.chmod(0o555 if mode & 0o111 else 0o444)
    candidate.chmod(0o555)


def owner_credential_env(env: dict[str, str]) -> tuple[dict[str, str], Path]:
    account = pwd.getpwuid(os.geteuid())
    home = Path(account.pw_dir)
    keychain = home / "Library/Keychains/login.keychain-db"
    if not home.is_absolute() or home.is_symlink() or not keychain.is_file() or keychain.is_symlink():
        raise ProducerError("owner signing keychain custody is unavailable")
    result = dict(env)
    result.update({"HOME": str(home), "USER": account.pw_name, "LOGNAME": account.pw_name})
    return result, keychain


def write_runtime_entitlements(scratch: Path) -> Path:
    path = scratch / "runtime-entitlements.plist"
    data = plistlib.dumps(
        {UNSIGNED_EXECUTABLE_MEMORY_ENTITLEMENT: True},
        fmt=plistlib.FMT_XML,
        sort_keys=True,
    )
    with path.open("xb") as stream:
        stream.write(data)
    path.chmod(0o400)
    return path


def require_hardened_runtime_detail(detail: str, label: str) -> None:
    matches = re.findall(
        r"(?m)^CodeDirectory\s+[^\n]*\sflags=0x([0-9a-fA-F]+)\(([^)\n]*)\)(?:\s|$)",
        detail,
    )
    if len(matches) != 1:
        raise ProducerError(f"CodeDirectory flags are missing or ambiguous: {label}")
    value = int(matches[0][0], 16)
    names = {item for item in matches[0][1].split(",") if item}
    if value != CS_RUNTIME or names != {"runtime"}:
        raise ProducerError(f"hardened-runtime flags are not exact: {label}")


def read_entitlements(
    path: Path,
    architecture: str,
    env: dict[str, str],
) -> dict[str, object]:
    completed = run(
        [
            TOOLS["codesign"], "--display", "--architecture", architecture,
            "--entitlements", "-", "--xml", path,
        ],
        env=env,
        expected={0, 1},
    )
    output = completed.stdout + completed.stderr
    marker = output.find(b"<?xml")
    if marker < 0:
        return {}
    end = output.find(b"</plist>", marker)
    if end < 0:
        raise ProducerError(f"signed entitlements are truncated: {path}")
    try:
        document = plistlib.loads(output[marker:end + len(b"</plist>")])
    except (ExpatError, plistlib.InvalidFileException) as exc:
        raise ProducerError(f"signed entitlements are unreadable: {path}") from exc
    if type(document) is not dict or not all(isinstance(key, str) for key in document):
        raise ProducerError(f"signed entitlements are not one exact dictionary: {path}")
    return document


def developer_id_seal(
    candidate: Path,
    runtime_entitlements: Path,
    env: dict[str, str],
) -> None:
    """Sign every Mach-O leaf, then the nested app and framework containers."""
    framework = candidate / "Python.framework"
    framework_executable = framework / "Versions/3.14/Python"
    app = framework / "Versions/3.14/Resources/Python.app"
    app_executable = app / "Contents/MacOS/Python"
    signing_env, keychain = owner_credential_env(env)
    common: list[str | Path] = [
        TOOLS["codesign"], "--force", "--sign", OWNER_APPLICATION,
        "--keychain", keychain,
        "--timestamp", "--options", "runtime", "--digest-algorithm=sha256",
    ]
    for path in sorted(macho_paths(candidate, env), key=lambda item: len(item.parts), reverse=True):
        if path in {app_executable, framework_executable}:
            continue
        entitlements: list[str | Path] = []
        if str(path.relative_to(candidate)) in ENTITLED_EXECUTABLES:
            entitlements = ["--entitlements", runtime_entitlements]
        run([*common, *entitlements, path], env=signing_env, timeout=300)
    run([*common, "--entitlements", runtime_entitlements, app], env=signing_env, timeout=300)
    run([*common, framework], env=signing_env, timeout=300)


def verify_developer_id(candidate: Path, env: dict[str, str]) -> None:
    framework = candidate / "Python.framework"
    app = framework / "Versions/3.14/Resources/Python.app"
    for bundle in (app, framework):
        run([TOOLS["codesign"], "--verify", "--strict", "--verbose=4", bundle], env=env)
    for path in macho_paths(candidate, env):
        run(
            [TOOLS["codesign"], "--verify", "--strict", "--all-architectures", path],
            env=env,
        )
        for architecture in architectures(path, env):
            detail = text(run(
                [
                    TOOLS["codesign"], "--display", "--architecture", architecture,
                    "--verbose=4", path,
                ],
                env=env,
            ))
            if (
                f"Authority={OWNER_APPLICATION}" not in detail
                or f"TeamIdentifier={OWNER_TEAM}" not in detail
                or "Hash type=sha256" not in detail
                or "Timestamp=" not in detail
            ):
                raise ProducerError(
                    f"Developer ID signature policy failed for {path}:{architecture}"
                )
            require_hardened_runtime_detail(detail, f"{path}:{architecture}")
            expected_entitlements = (
                {UNSIGNED_EXECUTABLE_MEMORY_ENTITLEMENT: True}
                if str(path.relative_to(candidate)) in ENTITLED_EXECUTABLES
                else {}
            )
            if read_entitlements(path, architecture, env) != expected_entitlements:
                raise ProducerError(f"unexpected entitlements on {path}:{architecture}")


def notary_authentication_arguments() -> list[str | Path]:
    account = pwd.getpwuid(os.geteuid())
    key_path = Path(account.pw_dir) / ".appstoreconnect/private_keys/AuthKey_REDACTEDKEY.p8"
    issuer = os.environ.get("WINS_NOTARY_ISSUER", "")
    try:
        key_info = key_path.lstat()
    except OSError as exc:
        raise ProducerError("fixed App Store Connect key is unavailable") from exc
    if (
        not key_path.is_absolute()
        or key_path.is_symlink()
        or not stat.S_ISREG(key_info.st_mode)
        or key_info.st_uid != os.geteuid()
        or key_info.st_nlink != 1
        or stat.S_IMODE(key_info.st_mode) & 0o077
    ):
        raise ProducerError("fixed App Store Connect key metadata is unsafe")
    if re.fullmatch(
            r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
            r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}",
            issuer,
        ) is None:
        raise ProducerError("App Store Connect issuer metadata is absent or malformed")
    return ["--key", key_path, "--key-id", "REDACTEDKEY", "--issuer", issuer]


def clean_notary_log(
    document: object,
    submission_id: str,
    expected_sha256: str,
) -> dict[str, object]:
    if type(document) is not dict:
        raise ProducerError("Apple notary log is not one JSON object")
    issues = document.get("issues")
    job_id = document.get("jobId")
    if (
        document.get("status") != "Accepted"
        or not isinstance(job_id, str)
        or job_id.lower() != submission_id.lower()
        or not isinstance(document.get("sha256"), str)
        or document["sha256"].lower() != expected_sha256
        or document.get("archiveFilename") != PACKAGE_NAME
        or issues not in (None, [])
    ):
        raise ProducerError("Apple notary log is not clean and Accepted")
    return document


def verify_package_signature(package: Path, env: dict[str, str]) -> str:
    detail = text(run([TOOLS["pkgutil"], "--check-signature", package], env=env))
    chain = re.findall(r"(?m)^\s*(\d+)\. ([^\r\n]+?)\s*$", detail)
    if (
        "Status: signed by a developer certificate issued by Apple for distribution"
        not in detail
        or "Signed with a trusted timestamp" not in detail
        or chain
        != [
            ("1", OWNER_INSTALLER),
            ("2", "Developer ID Certification Authority"),
            ("3", "Apple Root CA"),
        ]
    ):
        raise ProducerError("flat package Developer ID Installer signature policy failed")
    return detail.strip()


def notarize_and_staple(
    package: Path,
    notary_log: Path,
    expected_signed_sha256: str,
    authentication: list[str | Path],
    env: dict[str, str],
) -> dict[str, str]:
    if sha256(package) != expected_signed_sha256:
        raise ProducerError("signed distribution changed before notarization submission")
    credential_env, _keychain = owner_credential_env(env)
    command: list[str | Path] = [
        TOOLS["xcrun"], "notarytool", "submit", package,
        *authentication, "--wait", "--output-format", "json",
    ]
    submission = run(command, env=credential_env, timeout=3600)
    if submission.stderr:
        raise ProducerError("Apple notarization JSON response has unexpected stderr")
    result = json.loads(submission.stdout.decode("utf-8", "strict"))
    if (
        type(result) is not dict
        or result.get("status") != "Accepted"
        or not isinstance(result.get("id"), str)
    ):
        raise ProducerError("Apple notarization submission was not Accepted")
    submission_id = result["id"]
    run(
        [
            TOOLS["xcrun"], "notarytool", "log", submission_id,
            *authentication, notary_log,
        ],
        env=credential_env,
        timeout=600,
    )
    try:
        log_document = json.loads(notary_log.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProducerError(f"Apple notary log is unreadable: {exc}") from exc
    clean_notary_log(log_document, submission_id, expected_signed_sha256)
    pre_staple_sha256 = sha256(package)
    if pre_staple_sha256 != expected_signed_sha256:
        raise ProducerError("signed distribution changed before terminal stapling")
    run([TOOLS["xcrun"], "stapler", "staple", package], env=env, timeout=600)
    post_staple_sha256 = sha256(package)
    run(
        [TOOLS["xcrun"], "stapler", "validate", "-v", package],
        env=env,
        timeout=300,
    )
    return {
        "id": submission_id,
        "notary_log_sha256": sha256(notary_log),
        "post_staple_sha256": post_staple_sha256,
        "pre_staple_sha256": pre_staple_sha256,
        "status": result["status"],
    }


def enforce_slice_load_command_policy(
    candidate: Path,
    path: Path,
    architecture: str,
    filetype: str,
    records: tuple[list[str], list[str], list[str], list[str], list[str]],
) -> dict[str, object]:
    minimums, rpaths, dependencies, dylib_ids, dylinkers = records
    parsed_minimums = [version_tuple(item) for item in minimums]
    relative = str(path.relative_to(candidate))
    if (
        len(minimums) != 1
        or not any(parsed_minimums[0])
        or parsed_minimums[0] > version_tuple(EXPECTED_MAXIMUM_MINIMUM)
    ):
        raise ProducerError(
            f"deployment target policy failed for {relative}:{architecture}: {minimums}"
        )
    if rpaths:
        raise ProducerError(f"LC_RPATH policy failed for {relative}:{architecture}: {rpaths}")
    expected_ids = [canonical_dylib_id(candidate, path)] if filetype == "DYLIB" else []
    if dylib_ids != expected_ids:
        raise ProducerError(
            f"LC_ID_DYLIB policy failed for {relative}:{architecture}: {dylib_ids}"
        )
    expected_dylinkers = ["/usr/lib/dyld"] if filetype == "EXECUTE" else []
    if dylinkers != expected_dylinkers:
        raise ProducerError(
            f"LC_LOAD_DYLINKER policy failed for {relative}:{architecture}: {dylinkers}"
        )
    if not dependencies or len(dependencies) != len(set(dependencies)):
        raise ProducerError(
            f"Mach-O dependency inventory is empty or duplicated: {relative}:{architecture}"
        )
    for dependency in dependencies:
        validate_dependency(candidate, path, dependency)
    return {
        "dependencies": dependencies,
        "dylib_ids": dylib_ids,
        "dylinkers": dylinkers,
        "minimum": minimums[0],
        "rpaths": rpaths,
    }


def audit(candidate: Path, env: dict[str, str]) -> dict[str, object]:
    expected_children = {"Python.framework", "vendor", "launcher"}
    if (
        {path.name for path in candidate.iterdir()} != expected_children
        or any(
            not (candidate / name).is_dir() or (candidate / name).is_symlink()
            for name in expected_children
        )
    ):
        raise ProducerError("candidate root children are not exact")
    symlink_count = audit_symlink_closure(candidate)
    images: list[dict[str, object]] = []
    architecture_counts: dict[str, int] = {}
    for path in macho_paths(candidate, env):
        relative = str(path.relative_to(candidate))
        filetype = macho_filetype(path, env)
        expected_mode = 0o555 if filetype == "EXECUTE" else 0o444
        observed_mode = stat.S_IMODE(path.stat().st_mode)
        if observed_mode != expected_mode:
            raise ProducerError(
                f"Mach-O file type/mode policy failed for {relative}: {filetype} {observed_mode:o}"
            )
        archs = architectures(path, env)
        expected_archs = {"x86_64"} if relative == (
            "Python.framework/Versions/3.14/bin/python3.14-intel64"
        ) else {"arm64", "x86_64"}
        if set(archs) != expected_archs or len(archs) != len(expected_archs):
            raise ProducerError(f"architecture policy failed for {relative}: {archs}")
        architecture_key = " ".join(archs)
        architecture_counts[architecture_key] = architecture_counts.get(architecture_key, 0) + 1
        slice_evidence: dict[str, object] = {}
        for architecture in archs:
            slice_evidence[architecture] = enforce_slice_load_command_policy(
                candidate,
                path,
                architecture,
                filetype,
                load_command_records_for_architecture(path, architecture, env),
            )
        run(
            [TOOLS["codesign"], "--verify", "--strict", "--all-architectures", path],
            env=env,
        )
        for architecture in archs:
            detail = text(run(
                [
                    TOOLS["codesign"], "--display", "--architecture", architecture,
                    "--verbose=4", path,
                ],
                env=env,
            ))
            if (
                f"Authority={OWNER_APPLICATION}" not in detail
                or f"TeamIdentifier={OWNER_TEAM}" not in detail
                or "Hash type=sha256" not in detail
                or "Timestamp=" not in detail
            ):
                raise ProducerError(f"production signature policy failed for {relative}:{architecture}")
            require_hardened_runtime_detail(detail, f"{relative}:{architecture}")
        images.append({
            "architectures": list(archs),
            "filetype": filetype,
            "path": relative,
            "sha256": sha256(path),
            "slices": slice_evidence,
        })
    if not images:
        raise ProducerError("candidate contains no Mach-O images")
    return {
        "architecture_counts": dict(sorted(architecture_counts.items())),
        "macho_count": len(images),
        "images": images,
        "symlink_count": symlink_count,
    }


def smoke(
    candidate: Path,
    env: dict[str, str],
    architecture: str,
) -> dict[str, object]:
    python = candidate / "Python.framework/Versions/3.14/bin/python3.14"
    if architecture == "x86_64":
        python = candidate / "Python.framework/Versions/3.14/bin/python3.14-intel64"
    vendor = candidate / "vendor"
    program = (
        "import json,platform,sys;"
        f"sys.path.insert(0,{str(vendor)!r});"
        "import ssl,hashlib,sqlite3,lzma,bz2,zlib,ctypes,decimal,site,sysconfig;"
        "import PIL,yaml,pydantic_core;"
        "assert hashlib.sha256(b'winsvpn').hexdigest();"
        "assert sqlite3.connect(':memory:').execute('select 1').fetchone()==(1,);"
        "assert lzma.decompress(lzma.compress(b'x'))==b'x';"
        "assert bz2.decompress(bz2.compress(b'x'))==b'x';"
        "assert zlib.decompress(zlib.compress(b'x'))==b'x';"
        "assert ctypes.sizeof(ctypes.c_void_p)>0 and decimal.Decimal('1.25')*2==decimal.Decimal('2.50');"
        "assert ssl.create_default_context() and sysconfig.get_paths() and site.PREFIXES;"
        "print(json.dumps({'machine':platform.machine(),'version':platform.python_version(),"
        "'pillow':PIL.__version__,'pyyaml':yaml.__version__,'pydantic_core':pydantic_core.__version__},sort_keys=True))"
    )
    command: list[str | Path] = [python, "-I", "-S", "-c", program]
    if architecture == "x86_64":
        command = [TOOLS["arch"], "-x86_64", *command]
    smoke_env = {
        "HOME": env["HOME"],
        "TMPDIR": env["TMPDIR"],
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    }
    completed = run(command, env=smoke_env, timeout=120)
    line = completed.stdout.decode("utf-8", "strict").strip()
    result = json.loads(line)
    if result.get("version") != "3.14.7" or result.get("machine") != architecture:
        raise ProducerError(f"{architecture} smoke test returned unexpected identity: {result}")
    return result


def tree_manifest(candidate: Path) -> tuple[list[str], str]:
    records: list[str] = []
    for path in sorted(candidate.rglob("*")):
        relative = str(path.relative_to(candidate))
        if path.is_symlink():
            records.append(f"L {relative} {os.readlink(path)}")
        elif path.is_file():
            info = path.stat()
            records.append(
                f"F {stat.S_IMODE(info.st_mode):04o} {info.st_size} {relative} {sha256(path)}"
            )
        elif path.is_dir():
            records.append(f"D {stat.S_IMODE(path.stat().st_mode):04o} {relative}")
        else:
            raise ProducerError(f"special filesystem node rejected: {path}")
    encoded = ("\n".join(records) + "\n").encode("utf-8")
    return records, hashlib.sha256(encoded).hexdigest()


def audit_symlink_closure(candidate: Path) -> int:
    try:
        root = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ProducerError("candidate root is unavailable") from exc
    count = 0
    for path in sorted(candidate.rglob("*")):
        if not path.is_symlink():
            continue
        target = os.readlink(path)
        if not target or "\x00" in target or Path(target).is_absolute():
            raise ProducerError(f"unsafe symlink target in candidate: {path} -> {target!r}")
        try:
            resolved = (path.parent / target).resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise ProducerError(
                f"symlink escapes or dangles outside candidate: {path} -> {target!r}"
            ) from exc
        if not (resolved.is_file() or resolved.is_dir()):
            raise ProducerError(f"symlink target is not retained content: {path}")
        count += 1
    return count


def verify_expanded_distribution_layout(
    expanded: Path,
    expected_evidence_digest: str,
    env: dict[str, str],
) -> Path:
    package_info = expanded / "PackageInfo"
    bom = expanded / "Bom"
    payload_root = expanded / "Payload"
    if (
        {path.name for path in expanded.iterdir()} != {"Bom", "PackageInfo", "Payload"}
        or not package_info.is_file()
        or package_info.is_symlink()
        or not bom.is_file()
        or bom.is_symlink()
        or not payload_root.is_dir()
        or payload_root.is_symlink()
    ):
        raise ProducerError("expanded flat package structure is not exact")
    try:
        root = ElementTree.fromstring(package_info.read_bytes())
    except (OSError, ElementTree.ParseError) as exc:
        raise ProducerError(f"flat package metadata is unreadable: {exc}") from exc
    required_attributes = {
        "auth": "root",
        "identifier": PACKAGE_IDENTIFIER,
        "install-location": PACKAGE_INSTALL_LOCATION,
        "postinstall-action": "none",
        "relocatable": "false",
        "version": PACKAGE_VERSION,
    }
    relocations = root.findall("relocate")
    payloads = root.findall("payload")
    relocation = relocations[0] if len(relocations) == 1 else None
    payload_metadata = payloads[0] if len(payloads) == 1 else None
    bom_record_count = len(package_bom_records(bom, env))
    if (
        root.tag != "pkg-info"
        or any(root.attrib.get(key) != value for key, value in required_attributes.items())
        or payload_metadata is None
        or re.fullmatch(r"[0-9]+", payload_metadata.attrib.get("numberOfFiles", ""))
        is None
        or int(payload_metadata.attrib["numberOfFiles"]) != bom_record_count
        or relocation is None
        or len(relocation) != 0
    ):
        raise ProducerError("flat package metadata contract is not exact")
    payload = payload_root / "ReleasePython/3.14.7"
    evidence = payload_root / "evidence/pre-submission.json"
    release_root = payload_root / "ReleasePython"
    evidence_root = payload_root / "evidence"
    if (
        {path.name for path in payload_root.iterdir()} != {"ReleasePython", "evidence"}
        or any(
            not item.is_dir() or item.is_symlink()
            for item in (release_root, evidence_root, payload)
        )
        or {path.name for path in release_root.iterdir()} != {"3.14.7"}
        or {path.name for path in evidence_root.iterdir()} != {"pre-submission.json"}
        or not evidence.is_file()
        or evidence.is_symlink()
        or sha256(evidence) != expected_evidence_digest
    ):
        raise ProducerError("flat package payload layout is incomplete")
    verify_package_bom(bom, payload_root, env)
    return payload


def package_bom_records(
    bom: Path,
    env: dict[str, str],
) -> dict[str, tuple[str, str]]:
    output = text(run([TOOLS["lsbom"], "-p", "mUGsf", bom], env=env))
    observed: dict[str, tuple[str, str]] = {}
    for line in output.splitlines():
        fields = line.split("\t", 4)
        if len(fields) != 5:
            raise ProducerError("flat package BOM record is malformed")
        mode, user, group, size, relative = fields
        pure = PurePosixPath(relative[2:]) if relative.startswith("./") else PurePosixPath(".")
        mode_value = int(mode, 8) if re.fullmatch(r"[0-7]{5,6}", mode) else 0
        file_type = stat.S_IFMT(mode_value)
        if (
            relative in observed
            or user != "root"
            or group != "wheel"
            or file_type not in {stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK}
            or (
                not PurePosixPath(relative).name.startswith("._")
                and stat.S_ISDIR(mode_value)
                and size != ""
            )
            or (
                not stat.S_ISDIR(mode_value)
                and re.fullmatch(r"[0-9]+", size) is None
            )
            or (
                relative != "."
                and (
                    not relative.startswith("./")
                    or not pure.parts
                    or pure.is_absolute()
                    or any(part in {"", ".", ".."} for part in pure.parts)
                    or any(character in relative for character in "\t\n\r")
                )
            )
        ):
            raise ProducerError("flat package BOM identity is not exact")
        observed[relative] = (mode, size)
    if observed.get(".") != ("40755", ""):
        raise ProducerError("flat package BOM install-root metadata is not exact")
    for relative, metadata in observed.items():
        name = PurePosixPath(relative).name
        if not name.startswith("._"):
            continue
        native_name = name[2:]
        native = "./" + str(PurePosixPath(relative[2:]).with_name(native_name))
        if not native_name or metadata[1] != "0" or observed.get(native, (None,))[0] != metadata[0]:
            raise ProducerError("flat package AppleDouble BOM record is not exact")
    return observed


def verify_package_bom(bom: Path, payload_root: Path, env: dict[str, str]) -> None:
    expected: dict[str, tuple[str, str]] = {".": ("40755", "")}
    for path in sorted(payload_root.rglob("*")):
        relative = "./" + str(path.relative_to(payload_root))
        if "\t" in relative or "\n" in relative or "\r" in relative:
            raise ProducerError("flat package payload path is unsafe for BOM verification")
        info = path.lstat()
        size = "" if stat.S_ISDIR(info.st_mode) else str(info.st_size)
        expected[relative] = (f"{info.st_mode & 0o177777:o}", size)
    observed = {
        relative: metadata
        for relative, metadata in package_bom_records(bom, env).items()
        if not PurePosixPath(relative).name.startswith("._")
    }
    if observed != expected:
        raise ProducerError("flat package BOM metadata is not exact")


def restore_package_bom_modes(
    bom_records: dict[str, tuple[str, str]],
    payload_root: Path,
) -> None:
    semantic = {
        relative: metadata
        for relative, metadata in bom_records.items()
        if not PurePosixPath(relative).name.startswith("._")
    }
    for relative, (mode, _size) in sorted(
        semantic.items(),
        key=lambda item: len(PurePosixPath(item[0]).parts),
        reverse=True,
    ):
        path = payload_root if relative == "." else payload_root / relative[2:]
        mode_value = int(mode, 8)
        if path.is_symlink():
            if not stat.S_ISLNK(mode_value):
                raise ProducerError("flat package payload type differs from BOM")
            continue
        if not path.exists() or stat.S_IFMT(path.stat().st_mode) != stat.S_IFMT(mode_value):
            raise ProducerError("flat package payload type differs from BOM")
        path.chmod(stat.S_IMODE(mode_value))


def materialize_package_payload(expanded: Path, env: dict[str, str]) -> None:
    bom = expanded / "Bom"
    package_info = expanded / "PackageInfo"
    payload_archive = expanded / "Payload"
    if (
        {path.name for path in expanded.iterdir()} != {"Bom", "PackageInfo", "Payload"}
        or any(
            not item.is_file() or item.is_symlink()
            for item in (bom, package_info, payload_archive)
        )
    ):
        raise ProducerError("expanded flat package archive structure is not exact")
    bom_records = package_bom_records(bom, env)
    listing = run_pipeline(
        [TOOLS["gzip"], "-dc", payload_archive],
        [TOOLS["cpio"], "-it"],
        env=env,
    ).decode("utf-8", "strict").splitlines()
    if len(listing) != len(set(listing)) or set(listing) != set(bom_records):
        raise ProducerError("flat package payload archive inventory differs from BOM")
    held_archive = expanded.parent / f"{expanded.name}-payload.cpio.gz"
    if held_archive.exists() or held_archive.is_symlink():
        raise ProducerError("flat package held payload archive already exists")
    os.replace(payload_archive, held_archive)
    payload_root = expanded / "Payload"
    payload_root.mkdir(mode=0o700)
    try:
        run_pipeline(
            [TOOLS["gzip"], "-dc", held_archive],
            [TOOLS["cpio"], "-idm"],
            env=env,
            cwd=payload_root,
        )
    finally:
        held_archive.unlink(missing_ok=True)
    make_tree_mutable(payload_root)
    run([TOOLS["dot_clean"], "-m", payload_root], env=env, timeout=1800)
    restore_package_bom_modes(bom_records, payload_root)


def disable_bundle_relocation(component_plist: Path) -> list[str]:
    try:
        document = plistlib.loads(component_plist.read_bytes())
    except (OSError, plistlib.InvalidFileException) as exc:
        raise ProducerError(f"package component analysis is unreadable: {exc}") from exc
    if type(document) is not list:
        raise ProducerError("package component analysis is not one array")
    paths: list[str] = []

    def visit(records: object) -> None:
        if type(records) is not list:
            raise ProducerError("package component child inventory is invalid")
        for record in records:
            if type(record) is not dict:
                raise ProducerError("package component record is invalid")
            relative = record.get("RootRelativeBundlePath")
            pure = PurePosixPath(relative) if isinstance(relative, str) else PurePosixPath(".")
            if (
                not isinstance(relative, str)
                or not pure.parts
                or pure.is_absolute()
                or any(part in {"", ".", ".."} for part in pure.parts)
                or relative in paths
            ):
                raise ProducerError("package component bundle path is unsafe")
            paths.append(relative)
            record["BundleIsRelocatable"] = False
            record["BundleIsVersionChecked"] = False
            visit(record.get("ChildBundles", []))

    visit(document)
    required = {
        "ReleasePython/3.14.7/Python.framework",
        "ReleasePython/3.14.7/Python.framework/Versions/3.14/Resources/Python.app",
    }
    if set(paths) != required:
        raise ProducerError("package component bundle inventory is not exact")
    component_plist.write_bytes(
        plistlib.dumps(document, fmt=plistlib.FMT_XML, sort_keys=True)
    )
    component_plist.chmod(0o400)
    return sorted(paths)


def expand_distribution(
    package: Path,
    destination: Path,
    expected_payload_digest: str,
    expected_evidence_digest: str,
    env: dict[str, str],
    *,
    final: bool,
) -> dict[str, object]:
    if destination.exists() or destination.is_symlink():
        raise ProducerError("flat package expansion destination already exists")
    try:
        run(
            [TOOLS["pkgutil"], "--expand", package, destination],
            env=env,
            timeout=1800,
        )
        materialize_package_payload(destination, env)
        payload = verify_expanded_distribution_layout(
            destination,
            expected_evidence_digest,
            env,
        )
        _records, expanded_digest = tree_manifest(payload)
        if expanded_digest != expected_payload_digest:
            raise ProducerError("expanded flat package payload differs from signed source")
        result: dict[str, object] = {"payload_manifest_sha256": expanded_digest}
        if final:
            verify_developer_id(payload, env)
            result["audit"] = audit(payload, env)
            result["smoke"] = {
                "arm64": smoke(payload, env, "arm64"),
                "x86_64_thin_shim": smoke(payload, env, "x86_64"),
            }
            app = payload / "Python.framework/Versions/3.14/Resources/Python.app"
            gatekeeper = run(
                [TOOLS["spctl"], "--assess", "--type", "execute", "--verbose=4", app],
                env=env,
            )
            result["nested_app_gatekeeper"] = text(gatekeeper).strip()
        return result
    finally:
        if destination.is_dir() and not destination.is_symlink():
            make_tree_mutable(destination)
            shutil.rmtree(destination)


def stage_distribution_payload(
    candidate: Path,
    destination: Path,
    pre_submission: dict[str, object],
    payload_digest: str,
) -> str:
    payload = destination / "ReleasePython/3.14.7"
    evidence = destination / "evidence"
    if payload.exists() or payload.is_symlink() or evidence.exists() or evidence.is_symlink():
        raise ProducerError("distribution staging destination is not empty")
    if any(path.name.startswith("._") for path in candidate.rglob("*")):
        raise ProducerError("distribution payload contains an ambiguous AppleDouble path")
    payload.parent.mkdir(mode=0o755, parents=True)
    evidence.mkdir(mode=0o755)
    shutil.copytree(candidate, payload, symlinks=True)
    _records, copied_digest = tree_manifest(payload)
    if copied_digest != payload_digest:
        raise ProducerError("distribution staging copy changed payload identity")
    evidence_file = evidence / "pre-submission.json"
    evidence_file.write_text(
        json.dumps(pre_submission, sort_keys=True, indent=2) + "\n",
        encoding="ascii",
    )
    return sha256(evidence_file)


def build_signed_distribution(
    candidate: Path,
    output: Path,
    pre_submission: dict[str, object],
    payload_digest: str,
    env: dict[str, str],
) -> tuple[Path, dict[str, str]]:
    scratch = output / "scratch"
    package_root = scratch / "package-root"
    package_root.mkdir(mode=0o755)
    package_root.chmod(0o755)
    evidence_digest = stage_distribution_payload(
        candidate,
        package_root,
        pre_submission,
        payload_digest,
    )
    component_plist = scratch / "package-components.plist"
    run(
        [TOOLS["pkgbuild"], "--analyze", "--root", package_root, component_plist],
        env=env,
        timeout=1800,
    )
    disable_bundle_relocation(component_plist)
    unsigned = scratch / "unsigned-distribution.pkg"
    package = output / PACKAGE_NAME
    run(
        [
            TOOLS["pkgbuild"], "--root", package_root,
            "--identifier", PACKAGE_IDENTIFIER,
            "--version", PACKAGE_VERSION,
            "--install-location", PACKAGE_INSTALL_LOCATION,
            "--ownership", "recommended",
            "--component-plist", component_plist,
            unsigned,
        ],
        env=env,
        timeout=1800,
    )
    pre_sign_sha256 = sha256(unsigned)
    make_tree_mutable(package_root)
    shutil.rmtree(package_root)
    signing_env, keychain = owner_credential_env(env)
    run(
        [
            TOOLS["productsign"], "--sign", OWNER_INSTALLER,
            "--keychain", keychain, "--timestamp", unsigned, package,
        ],
        env=signing_env,
        timeout=600,
    )
    signed_sha256 = sha256(package)
    unsigned.unlink()
    verify_package_signature(package, env)
    expand_distribution(
        package,
        scratch / "pre-submit-expanded",
        payload_digest,
        evidence_digest,
        env,
        final=False,
    )
    return package, {
        "pre_sign_sha256": pre_sign_sha256,
        "signed_pre_submission_sha256": signed_sha256,
        "pre_submission_evidence_sha256": evidence_digest,
    }


def require_terminal_distribution_hash(package: Path, expected: str) -> str:
    actual = sha256(package)
    if actual != expected:
        raise ProducerError("distribution bytes changed after terminal stapling")
    return actual


def verify_final_distribution(
    package: Path,
    output: Path,
    payload_digest: str,
    evidence_digest: str,
    post_staple_sha256: str,
    env: dict[str, str],
) -> dict[str, object]:
    package_signature = verify_package_signature(package, env)
    gatekeeper = run(
        [
            TOOLS["spctl"], "--assess", "--type", "install", "--verbose=4", package,
        ],
        env=env,
    )
    gatekeeper_detail = text(gatekeeper).strip()
    if "source=Notarized Developer ID" not in gatekeeper_detail:
        raise ProducerError("flat package Gatekeeper notarization policy failed")
    expanded = expand_distribution(
        package,
        output / "scratch/post-staple-expanded",
        payload_digest,
        evidence_digest,
        env,
        final=True,
    )
    final_sha256 = require_terminal_distribution_hash(package, post_staple_sha256)
    return {
        "package_gatekeeper": gatekeeper_detail,
        "package_signature": package_signature,
        "final_sha256": final_sha256,
        **expanded,
    }


def materialize_authenticated_sources(
    root: Path,
    sources: dict[str, bytes],
) -> dict[str, Path]:
    if not sources:
        raise ProducerError("authenticated producer source closure is unavailable")
    paths: dict[str, Path] = {}
    for relative, data in sorted(sources.items()):
        pure = PurePosixPath(relative)
        if (
            pure.is_absolute()
            or not pure.parts
            or pure.parts[0] != "tools"
            or any(part in {"", ".", ".."} for part in pure.parts)
            or not isinstance(data, bytes)
            or not data
            or len(data) > 8 * 1024 * 1024
        ):
            raise ProducerError(f"authenticated producer source record is invalid: {relative!r}")
        target = root.joinpath(*pure.parts)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)
        target.chmod(0o400)
        paths[relative] = target
    return paths


def verify_sigstore(
    cosign: Path,
    trusted_root: Path,
    bundle: Path,
    artifact: Path,
    env: dict[str, str],
) -> None:
    result = text(run(
        [
            cosign, "verify-blob", "--trusted-root", trusted_root,
            "--certificate-identity", "hugo@python.org",
            "--certificate-oidc-issuer", "https://github.com/login/oauth",
            "--offline=true", "--max-workers=1", "--bundle", bundle, artifact,
        ],
        env=env,
    ))
    if "Verified OK" not in result:
        raise ProducerError(f"Sigstore verification did not report Verified OK: {artifact.name}")


def parse_base_policy_violations(path: Path, returncode: int) -> list[dict[str, object]]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 4 * 1024 * 1024:
        raise ProducerError("base producer violation evidence is unavailable or unbounded")
    try:
        document = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProducerError(f"base producer violation evidence is unreadable: {exc}") from exc
    if type(document) is not list or len(document) > 4096:
        raise ProducerError("base producer violation inventory is invalid")
    if (returncode == 0) != (not document) or returncode not in {0, 3}:
        raise ProducerError("base producer exit and violation inventory disagree")
    allowed_keys = {
        "minimum-macos": {"kind", "minimums", "path"},
        "lc-rpath": {"kind", "paths", "path"},
        "interpreter-architecture": {"kind", "reported"},
    }
    seen: set[tuple[str, str]] = set()
    for record in document:
        if type(record) is not dict or record.get("kind") not in allowed_keys:
            raise ProducerError("base producer reported a non-remediable policy violation")
        kind = record["kind"]
        if set(record) != allowed_keys[kind]:
            raise ProducerError(f"base producer {kind} violation keys are not exact")
        if kind == "interpreter-architecture":
            if not isinstance(record["reported"], str) or not record["reported"]:
                raise ProducerError("base producer interpreter architecture record is invalid")
            identity = (kind, record["reported"])
        else:
            relative = record["path"]
            pure = PurePosixPath(relative) if isinstance(relative, str) else PurePosixPath(".")
            values_key = "minimums" if kind == "minimum-macos" else "paths"
            values = record[values_key]
            if (
                not isinstance(relative, str)
                or pure.is_absolute()
                or not pure.parts
                or pure.parts[0] not in {"Python.framework", "vendor", "launcher"}
                or any(part in {"", ".", ".."} for part in pure.parts)
                or type(values) is not list
                or len(values) > 32
                or not all(isinstance(value, str) and value for value in values)
            ):
                raise ProducerError(f"base producer {kind} violation is invalid")
            if not values and not (
                kind == "minimum-macos"
                and relative
                == "Python.framework/Versions/3.14/lib/python3.14/"
                "config-3.14-darwin/python.o"
            ):
                raise ProducerError(f"base producer {kind} violation is invalid")
            identity = (kind, relative)
        if identity in seen:
            raise ProducerError("base producer violation inventory contains a duplicate")
        seen.add(identity)
    return document


def main(authenticated_sources: dict[str, bytes] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("work", type=Path)
    args = parser.parse_args()
    try:
        if sys.platform != "darwin" or os.uname().machine != "arm64" or os.geteuid() == 0:
            raise ProducerError("producer requires a non-root Apple-silicon macOS host")
        if (
            not args.source.is_absolute()
            or not args.work.is_absolute()
            or args.source.is_symlink()
            or args.work.is_symlink()
        ):
            raise ProducerError("source and work must be absolute non-symlink paths")
        source_inputs = args.source.resolve(strict=True)
        output = args.work.resolve(strict=True)
        if not source_inputs.is_dir() or not output.is_dir() or any(output.iterdir()):
            raise ProducerError("source must be a directory and work must be one empty directory")
        if output == source_inputs or source_inputs in output.parents or output in source_inputs.parents:
            raise ProducerError("source and work must be disjoint directories")
        for name, tool in TOOLS.items():
            if not tool.is_file() or tool.is_symlink() or not os.access(tool, os.X_OK):
                raise ProducerError(f"fixed tool is unavailable: {name}={tool}")
        notary_authentication = notary_authentication_arguments()

        scratch = output / "scratch"
        scratch.mkdir(mode=0o700)
        temporary = scratch / "tmp"
        temporary.mkdir(mode=0o700)
        build_home = scratch / "home"
        build_home.mkdir(mode=0o700)
        env = {
            "HOME": str(build_home),
            "TMPDIR": str(temporary),
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "C",
            "LC_ALL": "C",
        }

        closure = materialize_authenticated_sources(
            scratch / "authenticated-closure",
            authenticated_sources or {},
        )
        required_closure = {
            "tools/install_macos_release_python_inputs.py",
            "tools/macos_release_python_entrypoint.c",
            "tools/macos_release_python_inputs.custody.json",
            "tools/materialize_macos_release_python_psf_candidate.py",
            "tools/release_python_archive_custody.sh",
            "tools/toolchain-pins.json",
        }
        if not required_closure <= set(closure):
            missing = sorted(required_closure - set(closure))
            raise ProducerError(f"authenticated producer closure is incomplete: {missing}")
        closure_sha256 = {
            relative: sha256(path)
            for relative, path in sorted(closure.items())
        }
        input_manifest = closure["tools/macos_release_python_inputs.custody.json"]
        pin_manifest = closure["tools/toolchain-pins.json"]
        base_producer = closure["tools/materialize_macos_release_python_psf_candidate.py"]
        entrypoint_source = closure["tools/macos_release_python_entrypoint.c"]

        custody = load_release_pins(pin_manifest)
        snapshot_inputs = scratch / "input-snapshot"
        input_snapshot = snapshot_release_inputs(
            source_inputs,
            snapshot_inputs,
            input_manifest,
        )
        package = pinned_leaf(custody, "package", snapshot_inputs)
        package_bundle = pinned_leaf(custody, "sigstore_bundle", snapshot_inputs)
        source_archive = pinned_leaf(custody, "source_archive", snapshot_inputs)
        source_bundle = pinned_leaf(custody, "source_sigstore_bundle", snapshot_inputs)
        trusted_root = pinned_leaf(custody, "sigstore_trusted_root", snapshot_inputs)
        cosign = pinned_leaf(custody, "sigstore_verifier", snapshot_inputs)
        expected_entrypoint_sha256 = custody["source_entrypoint_sha256"]
        assert isinstance(expected_entrypoint_sha256, str)
        require_hash(entrypoint_source, expected_entrypoint_sha256)

        package_signature = text(run([TOOLS["pkgutil"], "--check-signature", package], env=env))
        if PSF_INSTALLER not in package_signature or "Notarization: trusted" not in package_signature:
            raise ProducerError("Python.org package is not the expected notarized PSF installer")
        verify_sigstore(cosign, trusted_root, package_bundle, package, env)
        verify_sigstore(cosign, trusted_root, source_bundle, source_archive, env)
        archive_entrypoint = extract_authenticated_entrypoint(
            source_archive,
            expected_entrypoint_sha256,
        )
        if archive_entrypoint != entrypoint_source.read_bytes():
            raise ProducerError("authenticated entrypoint source differs from the CPython archive")

        base = output / "base-producer"
        base.mkdir(mode=0o700)
        base_result = run(
            [TOOLS["python3"], "-I", "-S", base_producer, snapshot_inputs, base],
            env=env,
            timeout=900,
            expected={0, 3},
        )
        (output / "base-producer.log").write_bytes(base_result.stdout + base_result.stderr)
        base_violations = parse_base_policy_violations(
            base / "native-policy-violations.json",
            base_result.returncode,
        )
        base_candidate = base / "candidate"
        candidate = output / "candidate"
        if not base_candidate.is_dir() or base_candidate.is_symlink():
            raise ProducerError("reviewed base producer did not materialize a candidate")
        os.replace(base_candidate, candidate)

        make_tree_mutable(candidate)
        removed_gui = remove_gui_closure(candidate)
        removed_development = remove_development_closure(candidate)
        merged = merge_x86_vendor(
            candidate,
            scratch,
            snapshot_inputs,
            x86_wheel_pins(custody),
            env,
        )
        removed_seals = remove_stale_bundle_seals(candidate)
        direct_entrypoint = build_direct_entrypoints(
            candidate,
            scratch,
            entrypoint_source,
            expected_entrypoint_sha256,
            env,
        )
        rpath_removals = remove_rpaths(candidate, env)
        dependency_rewrites = rewrite_in_tree_dependencies(candidate, env)
        runtime_entitlements = write_runtime_entitlements(scratch)

        developer_id_seal(candidate, runtime_entitlements, env)
        verify_developer_id(candidate, env)
        make_tree_readonly(candidate, env)
        audit_result = audit(candidate, env)
        manifest, tree_digest = tree_manifest(candidate)
        (output / "tree.sha256").write_text("\n".join(manifest) + "\n", encoding="utf-8")

        pre_submission = {
            "candidate": str(candidate),
            "classification": "PRE-SUBMISSION-SIGNED-COMPLETE-DISTRIBUTION-PAYLOAD",
            "deployment_target_maximum": EXPECTED_MAXIMUM_MINIMUM,
            "direct_entrypoint_build": direct_entrypoint,
            "authenticated_producer_closure": closure_sha256,
            "base_policy_violations": {
                "count": len(base_violations),
                "kinds": sorted({record["kind"] for record in base_violations}),
                "sha256": sha256(base / "native-policy-violations.json"),
            },
            "framework_dependency_rewrite_count": len(dependency_rewrites),
            "final_runtime_path": FINAL_RUNTIME,
            "input_custody_manifest_sha256": sha256(input_manifest),
            "input_snapshot": input_snapshot,
            "merged_vendor_images": merged,
            "owner_signing_identity": OWNER_APPLICATION,
            "package_sha256": sha256(package),
            "package_signature_identity": PSF_INSTALLER,
            "package_sigstore": "Verified OK",
            "source_archive_sha256": sha256(source_archive),
            "source_sigstore": "Verified OK",
            "removed_development_closure": removed_development,
            "removed_gui_closure": removed_gui,
            "removed_stale_bundle_seals": removed_seals,
            "rpath_remediation": rpath_removals,
            "runtime_entitlements": {
                "executables": sorted(ENTITLED_EXECUTABLES),
                "plist_sha256": sha256(runtime_entitlements),
                "values": {UNSIGNED_EXECUTABLE_MEMORY_ENTITLEMENT: True},
            },
            "tree_manifest_sha256": tree_digest,
            **audit_result,
        }
        package, container_hashes = build_signed_distribution(
            candidate,
            output,
            pre_submission,
            tree_digest,
            env,
        )
        notarization = notarize_and_staple(
            package,
            output / "notary-log.json",
            container_hashes["signed_pre_submission_sha256"],
            notary_authentication,
            env,
        )
        final_verification = verify_final_distribution(
            package,
            output,
            tree_digest,
            container_hashes["pre_submission_evidence_sha256"],
            notarization["post_staple_sha256"],
            env,
        )
        require_terminal_distribution_hash(package, notarization["post_staple_sha256"])
        evidence = {
            **pre_submission,
            "classification": "PRODUCTION-SIGNED-NOTARIZED-STAPLED-PREPLACEMENT",
            "distribution": str(package),
            "distribution_container": "Developer ID Installer signed flat package",
            "distribution_hash_chain": {
                **container_hashes,
                "pre_staple_sha256": notarization["pre_staple_sha256"],
                "post_staple_sha256": notarization["post_staple_sha256"],
                "final_sha256": final_verification["final_sha256"],
            },
            "final_verification": final_verification,
            "notarization": notarization,
            "owner_bound_remaining": [
                "privileged placement and system-immutable sealing",
                "installed controller and launcher measurement",
                "external authority, schema-3 receipt authorization, and publication",
            ],
        }
        (output / "producer-evidence.json").write_text(
            json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="ascii"
        )
        print(json.dumps({
            "candidate": str(candidate),
            "distribution": str(package),
            "distribution_sha256": final_verification["final_sha256"],
            "macho_count": audit_result["macho_count"],
            "status": evidence["classification"],
            "tree_manifest_sha256": tree_digest,
        }, sort_keys=True))
        return 0
    except (
        OSError,
        ValueError,
        ProducerError,
        subprocess.SubprocessError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as exc:
        print(f"ReleasePython production producer: FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
