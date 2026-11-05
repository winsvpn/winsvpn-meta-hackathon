#!/usr/bin/env python3
"""Fail closed unless extracted Windows payload bytes are standalone Winn v3."""

from __future__ import annotations

import argparse
from collections.abc import Iterable
import os
from pathlib import Path, PurePosixPath
import shutil
import struct
import subprocess
import sys
import zipfile


WINN3_MARKER = b"winsvpn.local/winnprotocol/winn3"
PE_MACHINE_X64 = 0x8664
PE_MACHINE_ARM64 = 0xAA64
ARCHITECTURE_MACHINES = {"x64": PE_MACHINE_X64, "arm64": PE_MACHINE_ARM64}
MAX_INNER_BYTES = 512 * 1024 * 1024

REQUIRED_BASENAMES = frozenset(
    {
        "wins_vpn.exe",
        "wins_vpn_tunnel_service.exe",
        "winn-datapath.exe",
        "winsvpn_winn3_engine.exe",
        "wintun.dll",
    }
)
REQUIRED_PE_BASENAMES = REQUIRED_BASENAMES
FORBIDDEN_BASENAMES = frozenset(
    {
        "amneziawg-amd64.msi",
        "amneziawg-arm64.msi",
        "amneziawg.exe",
        "awg.exe",
        "xray.exe",
        "mullvad-split-tunnel.sys",
        "mullvad-split-tunnel.cat",
        "mullvad-split-tunnel.inf",
        "winsvpn_awg_engine.exe",
    }
)
FORBIDDEN_NAME_MARKERS = ("amneziawg", "xray", "mullvad", "winsvpn_awg_engine")


class ArtifactError(RuntimeError):
    """The exact payload bytes could not prove the release contract."""


def _basename(name: str) -> str:
    return PurePosixPath(name.replace("\\", "/")).name.casefold()


def audit_names(names: Iterable[str]) -> list[str]:
    basenames = {_basename(name) for name in names if _basename(name)}
    errors: list[str] = []
    missing = sorted(REQUIRED_BASENAMES - basenames)
    forbidden = sorted(
        name
        for name in basenames
        if name in FORBIDDEN_BASENAMES
        or any(marker in name for marker in FORBIDDEN_NAME_MARKERS)
    )
    if missing:
        errors.append("missing required standalone Winn payload: " + ", ".join(missing))
    if forbidden:
        errors.append("forbidden legacy payload present: " + ", ".join(forbidden))
    return errors


def _parse_pe_machine(name: str, data: bytes) -> int:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ArtifactError(f"{name} is not a DOS/PE image")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset > len(data) - 6 or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ArtifactError(f"{name} has an invalid PE header")
    return struct.unpack_from("<H", data, pe_offset + 4)[0]


def _record_member(
    members: dict[str, tuple[str, bytes]], raw_name: str, data: bytes
) -> None:
    basename = _basename(raw_name)
    if not basename:
        return
    if len(data) > MAX_INNER_BYTES:
        raise ArtifactError(f"{raw_name} exceeds the inner-payload size ceiling")
    previous = members.get(basename)
    if previous is not None:
        raise ArtifactError(
            f"ambiguous duplicate packed basename {basename}: "
            f"{previous[0]} and {raw_name}"
        )
    members[basename] = (raw_name, data)


def _interesting(basename: str) -> bool:
    return (
        basename in REQUIRED_BASENAMES
        or basename in FORBIDDEN_BASENAMES
        or any(marker in basename for marker in FORBIDDEN_NAME_MARKERS)
    )


def _directory_members(path: Path) -> dict[str, tuple[str, bytes]]:
    members: dict[str, tuple[str, bytes]] = {}
    for item in path.rglob("*"):
        if item.is_symlink():
            raise ArtifactError(f"payload contains a symbolic link: {item}")
        if item.is_file():
            relative = str(item.relative_to(path))
            if _interesting(_basename(relative)):
                _record_member(members, relative, item.read_bytes())
    return members


def _zip_members(path: Path) -> dict[str, tuple[str, bytes]]:
    members: dict[str, tuple[str, bytes]] = {}
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            basename = _basename(info.filename)
            if not basename or info.is_dir():
                continue
            unix_mode = (info.external_attr >> 16) & 0o170000
            if unix_mode == 0o120000:
                raise ArtifactError(f"ZIP payload contains a symbolic link: {info.filename}")
            if _interesting(basename):
                if info.file_size > MAX_INNER_BYTES:
                    raise ArtifactError(
                        f"{info.filename} exceeds the inner-payload size ceiling"
                    )
                _record_member(members, info.filename, archive.read(info))
    return members


def _find_7zip() -> str:
    configured = os.environ.get("WINS_7ZIP", "").strip()
    if configured:
        candidate = Path(configured)
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
        raise ArtifactError(f"WINS_7ZIP is not an executable file: {configured}")
    for name in ("7z.exe", "7z", "7zz"):
        resolved = shutil.which(name)
        if resolved:
            return resolved
    raise ArtifactError(
        "7-Zip is required to extract and inspect the compiled Inno installer; "
        "set WINS_7ZIP to the reviewed executable"
    )


def _seven_zip_paths(path: Path, seven_zip: str) -> list[str]:
    completed = subprocess.run(
        [seven_zip, "l", "-slt", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise ArtifactError(f"7-Zip could not inspect {path}: {detail}")
    paths = [
        line.split("=", 1)[1].strip()
        for line in completed.stdout.splitlines()
        if line.startswith("Path = ")
    ]
    artifact_spellings = {str(path), path.name, str(path.resolve())}
    paths = [name for name in paths if name not in artifact_spellings]
    if not paths:
        raise ArtifactError(f"7-Zip returned no archive members for {path}")
    return paths


def _seven_zip_member_bytes(path: Path, seven_zip: str, member_name: str) -> bytes:
    completed = subprocess.run(
        [seven_zip, "x", "-so", "-spd", str(path), member_name],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ArtifactError(
            f"7-Zip could not extract exact member {member_name} from {path}: {detail}"
        )
    if not completed.stdout:
        raise ArtifactError(
            f"7-Zip returned no bytes for exact member {member_name} from {path}"
        )
    return completed.stdout


def _seven_zip_members(path: Path) -> dict[str, tuple[str, bytes]]:
    seven_zip = _find_7zip()
    selected: dict[str, str] = {}
    for raw_name in _seven_zip_paths(path, seven_zip):
        basename = _basename(raw_name)
        if _interesting(basename):
            if basename in selected:
                raise ArtifactError(
                    f"ambiguous duplicate packed basename {basename}: "
                    f"{selected[basename]} and {raw_name}"
                )
            selected[basename] = raw_name
    members: dict[str, tuple[str, bytes]] = {}
    for raw_name in selected.values():
        _record_member(
            members,
            raw_name,
            _seven_zip_member_bytes(path, seven_zip, raw_name),
        )
    return members


def artifact_members(path: Path) -> dict[str, tuple[str, bytes]]:
    if path.is_dir():
        return _directory_members(path)
    if not path.is_file():
        raise ArtifactError(f"artifact does not exist: {path}")
    if zipfile.is_zipfile(path):
        return _zip_members(path)
    if path.suffix.casefold() == ".exe":
        return _seven_zip_members(path)
    raise ArtifactError(f"unsupported Windows artifact type: {path}")


def _infer_expected_architecture(paths: tuple[Path, ...]) -> str | None:
    packed = [path for path in paths if path.is_file() and path.suffix.casefold() == ".exe"]
    if not packed:
        return None
    inferred = {"arm64" if "arm64" in path.name.casefold() else "x64" for path in packed}
    if len(inferred) != 1:
        raise ArtifactError("packed installers disagree on their filename architecture")
    return inferred.pop()


def verify(*paths: Path, expected_architecture: str | None = None) -> list[str]:
    if not paths:
        raise ArtifactError("at least one artifact is required")
    if expected_architecture not in {None, *ARCHITECTURE_MACHINES}:
        raise ArtifactError(f"unsupported expected architecture: {expected_architecture}")
    members: dict[str, tuple[str, bytes]] = {}
    for path in paths:
        for basename, record in artifact_members(path).items():
            if basename in members:
                raise ArtifactError(
                    f"ambiguous duplicate payload basename {basename} across artifacts"
                )
            members[basename] = record

    errors = audit_names(record[0] for record in members.values())
    if errors:
        return errors

    expected_architecture = expected_architecture or _infer_expected_architecture(paths)
    expected_machine = (
        ARCHITECTURE_MACHINES[expected_architecture]
        if expected_architecture is not None
        else None
    )
    observed_machines: set[int] = set()
    for basename in sorted(REQUIRED_PE_BASENAMES):
        raw_name, data = members[basename]
        machine = _parse_pe_machine(raw_name, data)
        observed_machines.add(machine)
        if expected_machine is not None and machine != expected_machine:
            errors.append(
                f"{basename} has PE machine 0x{machine:04X}; "
                f"{expected_architecture} requires 0x{expected_machine:04X}"
            )

    if expected_machine is None:
        if not observed_machines.issubset(set(ARCHITECTURE_MACHINES.values())):
            errors.append(
                "payload contains an unsupported PE machine: "
                + ", ".join(f"0x{machine:04X}" for machine in sorted(observed_machines))
            )
        if len(observed_machines) != 1:
            errors.append(
                "required payload PE machines are mixed: "
                + ", ".join(f"0x{machine:04X}" for machine in sorted(observed_machines))
            )

    if WINN3_MARKER not in members["winn-datapath.exe"][1]:
        errors.append("winn-datapath.exe bytes do not contain the Winn v3 carrier marker")
    for basename in sorted(REQUIRED_BASENAMES - {"winn-datapath.exe"}):
        if WINN3_MARKER in members[basename][1]:
            errors.append(
                f"{basename} unexpectedly contains the Winn v3 carrier marker; "
                "only winn-datapath.exe is the carrier"
            )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--architecture",
        choices=sorted(ARCHITECTURE_MACHINES),
        help="required PE machine; packed installers infer this from the filename",
    )
    parser.add_argument("artifact", type=Path, nargs="+")
    args = parser.parse_args(argv)
    try:
        errors = verify(*args.artifact, expected_architecture=args.architecture)
    except (OSError, ArtifactError, zipfile.BadZipFile) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    architecture = args.architecture or _infer_expected_architecture(tuple(args.artifact))
    suffix = f" ({architecture})" if architecture else ""
    print(
        "PASS: extracted standalone Winn v3 Windows payload bytes verified"
        + suffix
        + ": "
        + ", ".join(map(str, args.artifact))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
