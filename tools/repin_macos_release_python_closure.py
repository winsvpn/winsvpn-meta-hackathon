#!/usr/bin/env python3
"""Re-pin the complete 17-file ReleasePython closure as one operation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
METADATA = TOOLS / "macos_release_python_runtime.custody.json"
WRAPPER = TOOLS / "release_python_archive_custody.sh"
PROVISIONER = TOOLS / "provision_macos_release_python_runtime.sh"
PRODUCER = TOOLS / "produce_macos_release_python_runtime_13.py"
PRODUCER_RELATIVE = "tools/produce_macos_release_python_runtime_13.py"
PATH_KEYS = (
    "wrapper",
    "provisioner",
    "custody_controller",
    "receipt_test",
    "provision_test",
    "archive_test",
    "fin_g00_test",
    "fin_release_gate",
    "android_custody",
    "openssl_custody",
    "node_custody",
    "browser_custody",
    "go_custody",
    "gcp_proof_collector",
    "gcp_proof_live_probe",
    "pin_manifest",
)
WRAPPER_EMBEDDED = {
    "_WINS_RP_RECEIPT_MODULE_SHA256": "custody_controller",
    "_WINS_RP_RECEIPT_TEST_SHA256": "receipt_test",
    "_WINS_RP_GCP_COLLECTOR_SHA256": "gcp_proof_collector",
    "_WINS_RP_GCP_PROBE_SHA256": "gcp_proof_live_probe",
}
PROVISIONER_EMBEDDED = "_WINS_PR_REVIEWED_WRAPPER_SHA256"
PRODUCER_EMBEDDED = "EXPECTED_CUSTODY_SHA256"
PRODUCER_PATHS = (
    "tools/build_macos_release_python_inputs_manifest.py",
    "tools/install_macos_release_python_inputs.py",
    "tools/macos_release_python_entrypoint.c",
    "tools/macos_release_python_inputs.custody.json",
    "tools/macos_release_python_owner_launcher.c",
    "tools/macos_release_python_runtime_production.py",
    "tools/materialize_macos_release_python_psf_candidate.py",
    "tools/release_python_archive_custody.sh",
    "tools/test_macos_release_python_inputs_custody.py",
    "tools/test_macos_release_python_owner_launcher.py",
    "tools/test_macos_release_python_runtime_receipt.py",
    "tools/test_release_gate_determinism.py",
    "tools/test_release_python_archive_custody.py",
    "tools/toolchain-pins.json",
)
HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class RepinError(RuntimeError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def path_digest(relative: str) -> str:
    path = ROOT / relative
    if not path.is_file() or path.is_symlink():
        raise RepinError(f"closure path is absent or symbolic: {relative}")
    return digest(path.read_bytes())


def replace_assignment(data: bytes, name: str, value: str) -> bytes:
    pattern = re.compile(rb"(?m)^(readonly " + re.escape(name.encode("ascii")) + rb"=)[0-9a-f]{64}$")
    replaced, count = pattern.subn(rb"\g<1>" + value.encode("ascii"), data)
    if count != 1:
        raise RepinError(f"embedded digest assignment is not exact: {name}")
    return replaced


def replace_python_assignment(data: bytes, name: str, value: str) -> bytes:
    pattern = re.compile(
        rb'(?m)^(' + re.escape(name.encode("ascii")) + rb' = ")[0-9a-f]{64}("$)'
    )
    replaced, count = pattern.subn(rb"\g<1>" + value.encode("ascii") + rb"\g<2>", data)
    if count != 1:
        raise RepinError(f"embedded Python digest assignment is not exact: {name}")
    return replaced


def repin_producer_closure(
    metadata: dict[str, object], staged: dict[Path, bytes]
) -> None:
    records = metadata.get("producer_closure")
    if not isinstance(records, list):
        raise RepinError("producer closure is not a list")
    paths: list[str] = []
    for record in records:
        if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
            raise RepinError("producer closure record keys are not exact")
        path = record["path"]
        sha256 = record["sha256"]
        if not isinstance(path, str) or not isinstance(sha256, str) or not HEX_DIGEST.fullmatch(sha256):
            raise RepinError("producer closure record is malformed")
        paths.append(path)
    if len(paths) != len(set(paths)):
        raise RepinError("producer closure paths are not unique")
    if set(paths) != set(PRODUCER_PATHS):
        raise RepinError("producer closure path set is not exact")
    if PRODUCER_RELATIVE in paths:
        raise RepinError("producer entrypoint must remain outside its authenticated closure")
    for record in records:
        path = ROOT / record["path"]
        payload = staged.get(path)
        record["sha256"] = digest(payload) if payload is not None else path_digest(record["path"])


def normalized_metadata_pins(data: bytes) -> dict[str, object]:
    metadata = json.loads(data.decode("ascii"))
    repin_producer_closure(metadata, {})
    for key in PATH_KEYS:
        metadata[f"{key}_sha256"] = "0" * 64
    for record in metadata["producer_closure"]:
        record["sha256"] = "0" * 64
    return metadata


def head_bytes(path: Path) -> bytes:
    relative = str(path.relative_to(ROOT))
    result = subprocess.run(
        ["/usr/bin/git", "-C", str(ROOT), "show", f"HEAD:{relative}"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        raise RepinError(f"unable to read closure input from HEAD: {relative}")
    return result.stdout


def require_generated_drift_exact() -> None:
    current_wrapper = WRAPPER.read_bytes()
    reviewed_wrapper = head_bytes(WRAPPER)
    for assignment in WRAPPER_EMBEDDED:
        current_wrapper = replace_assignment(current_wrapper, assignment, "0" * 64)
        reviewed_wrapper = replace_assignment(reviewed_wrapper, assignment, "0" * 64)
    if current_wrapper != reviewed_wrapper:
        raise RepinError("wrapper differs from HEAD outside generated pins")

    current_provisioner = replace_assignment(
        PROVISIONER.read_bytes(), PROVISIONER_EMBEDDED, "0" * 64
    )
    reviewed_provisioner = replace_assignment(
        head_bytes(PROVISIONER), PROVISIONER_EMBEDDED, "0" * 64
    )
    if current_provisioner != reviewed_provisioner:
        raise RepinError("provisioner differs from HEAD outside generated pins")

    if normalized_metadata_pins(METADATA.read_bytes()) != normalized_metadata_pins(
        head_bytes(METADATA)
    ):
        raise RepinError("custody metadata differs from HEAD outside generated pins")

    current_producer = replace_python_assignment(
        PRODUCER.read_bytes(), PRODUCER_EMBEDDED, "0" * 64
    )
    reviewed_producer = replace_python_assignment(
        head_bytes(PRODUCER), PRODUCER_EMBEDDED, "0" * 64
    )
    if current_producer != reviewed_producer:
        raise RepinError("producer differs from HEAD outside its generated pin")


def build() -> tuple[bytes, bytes, bytes, bytes, dict[str, str]]:
    metadata = json.loads(METADATA.read_text(encoding="ascii"))
    if metadata.get("contract") != "winsvpn-macos-release-python-runtime-v2" or metadata.get("schema_version") != 3:
        raise RepinError("custody metadata is not the v2/schema-3 contract")
    if any(metadata.get(key) != f"tools/{Path(metadata.get(key, '')).name}" for key in PATH_KEYS):
        raise RepinError("custody metadata closure paths are not exact")

    wrapper = WRAPPER.read_bytes()
    for assignment, path_key in WRAPPER_EMBEDDED.items():
        wrapper = replace_assignment(wrapper, assignment, path_digest(metadata[path_key]))
    wrapper_sha = digest(wrapper)

    provisioner = replace_assignment(
        PROVISIONER.read_bytes(), PROVISIONER_EMBEDDED, wrapper_sha
    )
    staged: dict[Path, bytes] = {WRAPPER: wrapper, PROVISIONER: provisioner}
    repin_producer_closure(metadata, staged)
    closure: dict[str, str] = {}
    for key in PATH_KEYS:
        path = ROOT / metadata[key]
        payload = staged.get(path, path.read_bytes())
        closure[f"{key}_sha256"] = digest(payload)
        metadata[f"{key}_sha256"] = closure[f"{key}_sha256"]
    metadata_bytes = (
        json.dumps(metadata, ensure_ascii=True, indent=2) + "\n"
    ).encode("ascii")
    closure["custody_metadata_sha256"] = digest(metadata_bytes)
    # The reviewed producer is deliberately outside producer_closure so this
    # terminal metadata pin cannot form a self-referential digest cycle.
    producer = replace_python_assignment(
        PRODUCER.read_bytes(), PRODUCER_EMBEDDED, closure["custody_metadata_sha256"]
    )
    if len(closure) != 17:
        raise RepinError("complete closure is not exactly 17 files")
    return wrapper, provisioner, metadata_bytes, producer, dict(sorted(closure.items()))


def require_tracked_inputs_clean() -> None:
    metadata = json.loads(METADATA.read_text(encoding="ascii"))
    paths = {
        str(METADATA.relative_to(ROOT)),
        str(WRAPPER.relative_to(ROOT)),
        str(PROVISIONER.relative_to(ROOT)),
        str(PRODUCER.relative_to(ROOT)),
    }
    for key in PATH_KEYS:
        value = metadata.get(key)
        if isinstance(value, str):
            paths.add(value)
    for value in PRODUCER_PATHS:
        paths.add(value)
    generated = {
        str(METADATA.relative_to(ROOT)),
        str(WRAPPER.relative_to(ROOT)),
        str(PROVISIONER.relative_to(ROOT)),
        str(PRODUCER.relative_to(ROOT)),
    }
    for path in sorted(paths):
        tracked = subprocess.run(
            ["/usr/bin/git", "-C", str(ROOT), "ls-files", "--error-unmatch", "--", path],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if tracked.returncode != 0:
            raise RepinError(f"closure input is not tracked by HEAD: {path}")
    result = subprocess.run(
        [
            "/usr/bin/git",
            "-C",
            str(ROOT),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            *sorted(paths - generated),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RepinError("unable to verify tracked closure inputs against HEAD")
    if result.stdout:
        raise RepinError("tracked closure inputs differ from HEAD")
    require_generated_drift_exact()


def replace_file(path: Path, data: bytes) -> None:
    temporary = path.with_name(f".{path.name}.repin-{os.getpid()}")
    if temporary.exists() or temporary.is_symlink():
        raise RepinError(f"repin temporary path already exists: {temporary}")
    current = os.lstat(path)
    if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1:
        raise RepinError(f"repin target is not a one-link regular file: {path}")
    mode = stat.S_IMODE(current.st_mode)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            offset += os.write(descriptor, view[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


def sync_tools_directory() -> None:
    directory = os.open(TOOLS, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def replace_files_transactionally(expected: dict[Path, bytes]) -> None:
    original = {path: path.read_bytes() for path in expected}
    original_modes = {path: stat.S_IMODE(os.lstat(path).st_mode) for path in expected}
    replaced: list[Path] = []
    try:
        for path, data in expected.items():
            replace_file(path, data)
            replaced.append(path)
        sync_tools_directory()
        for path, data in expected.items():
            if path.read_bytes() != data:
                raise RepinError(f"post-write bytes differ: {path.relative_to(ROOT)}")
            if stat.S_IMODE(os.lstat(path).st_mode) != original_modes[path]:
                raise RepinError(f"post-write mode differs: {path.relative_to(ROOT)}")
        rebuilt = build()
        if (rebuilt[0], rebuilt[1], rebuilt[2], rebuilt[3]) != (
            expected[WRAPPER],
            expected[PROVISIONER],
            expected[METADATA],
            expected[PRODUCER],
        ):
            raise RepinError("post-write closure is not idempotent")
    except BaseException:
        for path in reversed(replaced):
            replace_file(path, original[path])
        sync_tools_directory()
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    try:
        require_tracked_inputs_clean()
        wrapper, provisioner, metadata, producer, closure = build()
        current = {
            WRAPPER: WRAPPER.read_bytes(),
            PROVISIONER: PROVISIONER.read_bytes(),
            METADATA: METADATA.read_bytes(),
            PRODUCER: PRODUCER.read_bytes(),
        }
        expected = {
            WRAPPER: wrapper,
            PROVISIONER: provisioner,
            METADATA: metadata,
            PRODUCER: producer,
        }
        stale = [str(path.relative_to(ROOT)) for path in expected if current[path] != expected[path]]
        if args.write:
            replace_files_transactionally(expected)
            print("ReleasePython 17-file closure re-pin: PASS")
        elif stale:
            raise RepinError("closure pins are stale: " + ", ".join(stale))
        else:
            print("ReleasePython 17-file closure check: PASS")
        print(json.dumps(closure, sort_keys=True, indent=2))
        return 0
    except (OSError, ValueError, RepinError) as exc:
        print(f"ReleasePython closure re-pin: FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
