#!/usr/bin/env python3
"""Verify release engine inventories.

Android release artifacts carry standalone Winn v3 as the primary engine and
AmneziaWG as the Winn v1 fallback. Android refuses Xray mode at runtime
(VpnTunnelService.kt) and android/app/build.gradle.kts excludes libxray.so from
packaging, so libxray.so must not ship. Apple release artifacts stay dual-stack:
standalone Winn v3 is primary, while AmneziaWG plus Xray remains the Winn v1
fallback.
"""

from __future__ import annotations

import hashlib
import pathlib
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile


LEGACY_BASENAMES = {
    "libam-go.so",
    "libam-quick.so",
    "libam.so",
    "libxray.so",
    "winsamneziawgpacketengine",
    "winsxrayvlesswstransport",
    "libwinsamneziawgpacketengine.dylib",
    "libwinsxrayvlesswstransport.dylib",
}
LEGACY_PATH_MARKERS = {
    "winsamneziawgpacketengine.framework",
    "winsxrayvlesswstransport.framework",
}
ANDROID_ABIS = {"arm64-v8a", "armeabi-v7a", "x86_64"}
ANDROID_REQUIRED_ENGINES = {
    "libam-go.so": "Winn v1 AmneziaWG",
    "libwinnengine.so": "standalone Winn v3",
}
ANDROID_FORBIDDEN_BASENAMES = {"libam-quick.so", "libam.so", "libxray.so"}
ANDROID_ELF_ABIS = {
    "arm64-v8a": (2, 183),
    "armeabi-v7a": (1, 40),
    "x86_64": (2, 62),
}
ANDROID_64_BIT_PAGE_ALIGNMENT = 16 * 1024
APPLE_REQUIRED_FRAMEWORKS = {
    "WinsAmneziaWGPacketEngine.framework": "Winn v1 AmneziaWG",
    "WinsWinnPacketEngine.framework": "standalone Winn v3",
    "WinsXrayVlessWsTransport.framework": "Winn v1 Xray",
}


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def reject_legacy_paths(label: str, names: list[str]) -> None:
    rejected = []
    for name in names:
        lowered = name.lower().rstrip("/")
        basename = pathlib.PurePosixPath(lowered).name
        if basename in LEGACY_BASENAMES or any(
            marker in lowered for marker in LEGACY_PATH_MARKERS
        ):
            rejected.append(name)
    if rejected:
        fail(f"{label} contains legacy AWG/Xray payloads: {', '.join(sorted(rejected))}")


def _member_bytes(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    with archive.open(info) as source:
        return source.read()


def _is_zip_symlink(info: zipfile.ZipInfo) -> bool:
    return stat.S_IFMT(info.external_attr >> 16) == stat.S_IFLNK


def _verify_android_elf(member: str, abi: str, data: bytes) -> None:
    expected_class, expected_machine = ANDROID_ELF_ABIS[abi]
    if len(data) < 52 or data[:4] != b"\x7fELF":
        fail(f"{member} is not an ELF binary")
    elf_class, elf_data = data[4], data[5]
    if elf_data != 1:
        fail(f"{member} is not little-endian ELF")
    if elf_class != expected_class:
        fail(
            f"{member} has ELF class {elf_class}; ABI {abi} requires "
            f"class {expected_class}"
        )
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine != expected_machine:
        fail(
            f"{member} has ELF e_machine {machine}; ABI {abi} requires "
            f"{expected_machine}"
        )

    if elf_class == 2:
        if len(data) < 64:
            fail(f"{member} has a truncated ELF64 header")
        program_offset = struct.unpack_from("<Q", data, 32)[0]
        entry_size = struct.unpack_from("<H", data, 54)[0]
        entry_count = struct.unpack_from("<H", data, 56)[0]
        minimum_entry_size = 56
    else:
        program_offset = struct.unpack_from("<I", data, 28)[0]
        entry_size = struct.unpack_from("<H", data, 42)[0]
        entry_count = struct.unpack_from("<H", data, 44)[0]
        minimum_entry_size = 32

    if entry_count == 0 or entry_size < minimum_entry_size:
        fail(f"{member} has no valid ELF program-header table")
    table_end = program_offset + entry_size * entry_count
    if table_end > len(data):
        fail(f"{member} has a truncated ELF program-header table")

    load_segments = 0
    for index in range(entry_count):
        offset = program_offset + index * entry_size
        segment_type = struct.unpack_from("<I", data, offset)[0]
        if segment_type != 1:
            continue
        load_segments += 1
        if elf_class == 2:
            file_offset = struct.unpack_from("<Q", data, offset + 8)[0]
            virtual_address = struct.unpack_from("<Q", data, offset + 16)[0]
            alignment = struct.unpack_from("<Q", data, offset + 48)[0]
        else:
            file_offset = struct.unpack_from("<I", data, offset + 4)[0]
            virtual_address = struct.unpack_from("<I", data, offset + 8)[0]
            alignment = struct.unpack_from("<I", data, offset + 28)[0]
        if alignment == 0 or alignment & (alignment - 1):
            fail(f"{member} has a PT_LOAD segment with invalid alignment {alignment}")
        if elf_class == 2 and (
            alignment < ANDROID_64_BIT_PAGE_ALIGNMENT
            or (virtual_address - file_offset) % ANDROID_64_BIT_PAGE_ALIGNMENT != 0
        ):
            fail(
                f"{member} is not compatible with 16 KB Android pages: "
                f"PT_LOAD alignment={alignment} offset={file_offset} "
                f"vaddr={virtual_address}"
            )
    if load_segments == 0:
        fail(f"{member} has no ELF PT_LOAD segment")


def verify_android(path: pathlib.Path) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            prefix = "base/lib" if path.suffix.lower() == ".aab" else "lib"
            expected = {
                f"{prefix}/{abi}/{engine}": (abi, engine)
                for abi in ANDROID_ABIS
                for engine in ANDROID_REQUIRED_ENGINES
            }

            unsafe_paths = []
            forbidden = []
            unexpected_engine_paths = []
            required_by_name: dict[str, list[zipfile.ZipInfo]] = {
                name: [] for name in expected
            }
            for info in infos:
                pure = pathlib.PurePosixPath(info.filename)
                if pure.is_absolute() or ".." in pure.parts:
                    unsafe_paths.append(info.filename)
                basename = pure.name.lower()
                if basename in ANDROID_FORBIDDEN_BASENAMES:
                    forbidden.append(info.filename)
                if basename in ANDROID_REQUIRED_ENGINES:
                    if info.filename in required_by_name:
                        required_by_name[info.filename].append(info)
                    else:
                        unexpected_engine_paths.append(info.filename)

            if unsafe_paths:
                fail(f"{path} contains unsafe archive paths: {', '.join(sorted(unsafe_paths))}")
            if forbidden:
                fail(
                    f"{path} contains forbidden Android engines: "
                    f"{', '.join(sorted(forbidden))}"
                )
            if unexpected_engine_paths:
                fail(
                    f"{path} contains required engine names outside the exact declared ABI "
                    f"inventory: {', '.join(sorted(unexpected_engine_paths))}"
                )

            invalid = []
            inventory = []
            validated_members = set()
            for member, (abi, engine) in sorted(expected.items()):
                matches = required_by_name[member]
                if len(matches) != 1:
                    invalid.append(f"{member} (copies={len(matches)})")
                    continue
                info = matches[0]
                if info.is_dir() or info.file_size <= 0 or _is_zip_symlink(info):
                    invalid.append(
                        f"{member} (empty, directory, or symlink-like archive member)"
                    )
                    continue
                data = _member_bytes(archive, info)
                _verify_android_elf(member, abi, data)
                validated_members.add(member)
                inventory.append(
                    (
                        abi,
                        engine,
                        info.file_size,
                        hashlib.sha256(data).hexdigest(),
                    )
                )

            if invalid:
                fail(
                    f"{path} does not contain one safe non-empty copy of every Android "
                    f"release engine: {', '.join(invalid)}"
                )

            native_prefix = tuple(pathlib.PurePosixPath(prefix).parts)
            for info in infos:
                parts = pathlib.PurePosixPath(info.filename).parts
                if (
                    len(parts) != len(native_prefix) + 2
                    or tuple(parts[: len(native_prefix)]) != native_prefix
                    or not parts[-1].endswith(".so")
                    or info.filename in validated_members
                ):
                    continue
                abi = parts[-2]
                if abi not in ANDROID_ELF_ABIS:
                    fail(f"{path} contains a native library for undeclared ABI {abi}: {info.filename}")
                if info.is_dir() or info.file_size <= 0 or _is_zip_symlink(info):
                    fail(f"{info.filename} is empty, a directory, or a symlink-like member")
                _verify_android_elf(info.filename, abi, _member_bytes(archive, info))

            for abi, engine, size, digest in sorted(inventory):
                print(
                    f"ANDROID ENGINE INVENTORY: {path} abi={abi} engine={engine} "
                    f"role={ANDROID_REQUIRED_ENGINES[engine]!r} bytes={size} sha256={digest}"
                )
    except (OSError, zipfile.BadZipFile) as error:
        fail(f"cannot inspect Android artifact {path}: {error}")


def verify_apple_names(label: str, names: list[str]) -> None:
    lowered = [name.lower() for name in names]
    missing = [
        framework
        for framework in APPLE_REQUIRED_FRAMEWORKS
        if not any(framework.lower() in name for name in lowered)
    ]
    if missing:
        fail(
            f"{label} does not contain every required Apple release framework: "
            f"{', '.join(missing)}"
        )


def directory_names(root: pathlib.Path) -> list[str]:
    return [str(path.relative_to(root)).replace("\\", "/") for path in root.rglob("*")]


def verify_apple(path: pathlib.Path) -> None:
    if path.is_dir():
        verify_apple_names(str(path), directory_names(path))
        return
    if path.suffix.lower() == ".ipa":
        try:
            with zipfile.ZipFile(path) as archive:
                verify_apple_names(str(path), archive.namelist())
        except (OSError, zipfile.BadZipFile) as error:
            fail(f"cannot inspect Apple IPA {path}: {error}")
        return
    if path.suffix.lower() == ".pkg":
        pkgutil = shutil.which("pkgutil")
        if pkgutil is None:
            fail("pkgutil is required to inspect a macOS package")
        with tempfile.TemporaryDirectory(prefix="wins-v3-pkg-") as temporary:
            expanded = pathlib.Path(temporary) / "expanded"
            result = subprocess.run(
                [pkgutil, "--expand-full", str(path), str(expanded)],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                fail(f"pkgutil could not expand {path}: {result.stderr.strip()}")
            verify_apple_names(str(path), directory_names(expanded))
        return
    fail(f"unsupported Apple release artifact type: {path}")


def main(argv: list[str]) -> int:
    if not argv:
        fail("usage: verify_standalone_v3_artifact.py ARTIFACT [ARTIFACT ...]")
    for raw in argv:
        path = pathlib.Path(raw).resolve()
        if not path.exists():
            fail(f"artifact does not exist: {path}")
        if path.suffix.lower() in {".apk", ".aab"}:
            verify_android(path)
        else:
            verify_apple(path)
        if path.suffix.lower() in {".apk", ".aab"}:
            print(f"ANDROID DUAL-ENGINE ARTIFACT: PASS {path}")
        else:
            print(f"APPLE DUAL-STACK ARTIFACT: PASS {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
