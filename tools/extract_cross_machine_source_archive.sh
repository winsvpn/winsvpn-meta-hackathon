#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  printf 'Usage: %s ARCHIVE TARGET_DIRECTORY EXPECTED_SHA256\n' "$0" >&2
  exit 2
}

[[ "$#" -eq 3 ]] || usage
archive="$1"
target_directory="$2"
expected_sha256="$(printf '%s' "$3" | tr '[:upper:]' '[:lower:]')"

[[ -f "${archive}" && ! -L "${archive}" ]] \
  || { printf 'Archive is missing or is not a regular non-symlink file: %s\n' "${archive}" >&2; exit 1; }
[[ "${expected_sha256}" =~ ^[0-9a-f]{64}$ ]] \
  || { printf 'Expected SHA-256 must contain exactly 64 hexadecimal characters.\n' >&2; exit 2; }
command -v python3 >/dev/null 2>&1 \
  || { printf 'python3 is required for safe archive validation and extraction.\n' >&2; exit 127; }

if [[ -e "${target_directory}" || -L "${target_directory}" ]]; then
  [[ -d "${target_directory}" && ! -L "${target_directory}" ]] \
    || { printf 'Extraction target already exists and is not a regular directory.\n' >&2; exit 1; }
  [[ -z "$(find "${target_directory}" -mindepth 1 -maxdepth 1 -print -quit)" ]] \
    || { printf 'Extraction target must be empty before extraction.\n' >&2; exit 1; }
fi

# The helper reads and hashes one open archive descriptor, validates every
# logical member before writing anything, extracts into a private sibling
# stage, and only then atomically installs that stage as the empty target.
executable_count="$(python3 - "${archive}" "${target_directory}" "${expected_sha256}" <<'PY'
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tarfile
import tempfile


archive_path = Path(sys.argv[1])
target = Path(sys.argv[2]).absolute()
expected_sha256 = sys.argv[3]

allowed_roots = {
    ".github", "android", "app_store", "apple", "assets", "docs",
    "installer", "ios", "legal", "lib", "linux", "macos", "netlify",
    "server", "test", "tools", "web", "windows",
}
allowed_root_files = {
    ".metadata", "AGENTS.md", "analysis_options.yaml", "pubspec.lock",
    "pubspec.yaml", "README_FINAL_DEPLOYMENT.md",
}
forbidden_names = {
    "key.properties", "local.properties", ".env", "secrets.json",
    "google-services.json",
}
forbidden_extensions = {
    ".jks", ".keystore", ".p8", ".p12", ".pfx", ".pem", ".key",
    ".mobileprovision", ".provisionprofile",
}
executable_manifest_name = \
    ".artifacts/cross-machine-sync-stage/source-executables.txt"


def fail(message: str) -> None:
    raise RuntimeError(message)


def validate_name(raw_name: str, *, is_directory: bool) -> str:
    if not raw_name or "\x00" in raw_name or "\\" in raw_name:
        fail(f"Unsafe archive member path: {raw_name!r}")
    if raw_name.startswith(("/", "//")) or re.match(r"^[A-Za-z]:", raw_name):
        fail(f"Absolute archive member path is forbidden: {raw_name}")
    name = raw_name[:-1] if is_directory and raw_name.endswith("/") else raw_name
    parts = name.split("/")
    if not name or any(part in {"", ".", ".."} for part in parts):
        fail(f"Dot, dot-dot, or empty archive path component is forbidden: {raw_name}")
    if str(PurePosixPath(*parts)) != name:
        fail(f"Archive member path is not canonical: {raw_name}")
    if name == executable_manifest_name:
        if is_directory:
            fail("The portable executable manifest must be a regular file.")
        return name
    leaf = parts[-1]
    extension = PurePosixPath(leaf).suffix.lower()
    if not (parts[0] in allowed_roots or name in allowed_root_files):
        fail(f"Archive member escaped the approved source roots: {raw_name}")
    if leaf.lower() in forbidden_names or extension in forbidden_extensions:
        fail(f"Archive contains a forbidden credential or signing artifact: {raw_name}")
    return name


with archive_path.open("rb") as archive_file:
    archive_bytes = archive_file.read()
actual_sha256 = hashlib.sha256(archive_bytes).hexdigest()
if actual_sha256 != expected_sha256:
    fail("Cross-machine source archive SHA-256 mismatch.")

members: list[tuple[tarfile.TarInfo, str]] = []
member_by_name: dict[str, tarfile.TarInfo] = {}
casefold_names: set[str] = set()
with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as source:
    for member in source.getmembers():
        if not (member.isreg() or member.isdir()):
            fail(f"Archive member type is forbidden: {member.name}")
        # PAX/GNU extension records, sparse maps, links, devices, and special
        # permission bits are not part of this intentionally plain source tar.
        if member.pax_headers:
            fail(f"Unexpected PAX metadata is forbidden: {member.name}")
        if member.offset_data != member.offset + 512:
            fail(f"Unexpected tar extension metadata is forbidden: {member.name}")
        if getattr(member, "sparse", None):
            fail(f"Sparse archive members are forbidden: {member.name}")
        if member.linkname or member.devmajor or member.devminor:
            fail(f"Link or device metadata is forbidden: {member.name}")
        if member.mode & ~0o777:
            fail(f"Special archive permission bits are forbidden: {member.name}")
        canonical = validate_name(member.name, is_directory=member.isdir())
        folded = canonical.casefold()
        if canonical in member_by_name or folded in casefold_names:
            fail(f"Duplicate or case-colliding archive member is forbidden: {member.name}")
        member_by_name[canonical] = member
        casefold_names.add(folded)
        members.append((member, canonical))

    executable_manifest = member_by_name.get(executable_manifest_name)
    if executable_manifest is None or not executable_manifest.isreg():
        fail("Portable executable manifest is missing from the archive.")
    manifest_stream = source.extractfile(executable_manifest)
    if manifest_stream is None:
        fail("Portable executable manifest could not be read.")
    try:
        manifest_text = manifest_stream.read().decode("utf-8", errors="strict")
    finally:
        manifest_stream.close()

    executable_names: list[str] = []
    executable_seen: set[str] = set()
    for raw_line in manifest_text.splitlines():
        name = raw_line.removesuffix("\r")
        if not name:
            continue
        canonical = validate_name(name, is_directory=False)
        if canonical == executable_manifest_name:
            fail("The portable executable manifest cannot mark itself executable.")
        approved_member = member_by_name.get(canonical)
        if approved_member is None or not approved_member.isreg():
            fail(f"Executable manifest path is missing or not regular: {name}")
        if canonical in executable_seen:
            fail(f"Duplicate executable manifest path is forbidden: {name}")
        executable_seen.add(canonical)
        executable_names.append(canonical)

    target_parent = target.parent
    target_parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{target.name}.extract-", dir=target_parent))
    try:
        for member, canonical in members:
            destination = stage.joinpath(*canonical.split("/"))
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=False)
                destination.chmod(0o755)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            source_file = source.extractfile(member)
            if source_file is None:
                fail(f"Regular archive member could not be read: {canonical}")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(destination, flags, 0o600)
            try:
                with os.fdopen(descriptor, "wb", closefd=False) as output_file:
                    shutil.copyfileobj(source_file, output_file)
                    output_file.flush()
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
                source_file.close()
            destination.chmod(0o644)

        for name in executable_names:
            destination = stage.joinpath(*name.split("/"))
            if not destination.is_file() or destination.is_symlink():
                fail(f"Executable manifest path became unsafe: {name}")
            destination.chmod(0o755)

        if target.exists() or target.is_symlink():
            if target.is_symlink() or not target.is_dir() or any(target.iterdir()):
                fail("Extraction target changed or became nonempty during validation.")
            target.rmdir()
        stage.replace(target)
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise

print(len(executable_names))
PY
)"

printf 'CROSS_MACHINE_SOURCE_EXTRACT=PASS\n'
printf 'ARCHIVE_SHA256=%s\n' "${expected_sha256}"
printf 'EXECUTABLES_APPLIED=%s\n' "${executable_count}"
