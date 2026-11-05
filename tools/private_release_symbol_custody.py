#!/usr/bin/env python3
"""Create and verify tamper-evident manifests for private release symbols.

This tool never uploads symbols.  It keeps custody evidence beside the private,
git-ignored symbol material so a release artifact can be matched to the exact
symbols retained by the release operator.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import stat
import tempfile


ROOT = pathlib.Path(__file__).resolve().parent.parent
PRIVATE_ROOT = ROOT / ".artifacts" / "private-release-symbols"
MANIFEST_NAME = "custody-manifest.json"
SIDECAR_NAME = "custody-manifest.sha256"


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _absolute(path: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(os.path.abspath(os.fspath(path)))


def _validate_directory(path: pathlib.Path, description: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SystemExit(f"{description} cannot be inspected: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise SystemExit(f"{description} must be a real directory: {path}")
    if os.name != "nt":
        allowed_owners = {0, os.geteuid()}
        if metadata.st_uid not in allowed_owners:
            raise SystemExit(f"{description} is not owner-controlled: {path}")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise SystemExit(f"{description} must not be group/other writable: {path}")


def _validate_custody_directory_chain(
    path: pathlib.Path, private_root: pathlib.Path
) -> tuple[pathlib.Path, pathlib.Path]:
    root = _absolute(private_root)
    candidate = _absolute(path)
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise SystemExit(f"Symbols directory must be a child of private custody root: {root}") from exc
    # The repository root is the filesystem trust boundary for the canonical
    # <repo>/.artifacts/private-release-symbols layout. Checking only the
    # private root would still let a writable .artifacts or repository parent
    # rename and replace the entire custody tree after validation.
    boundary = root.parent.parent if root.parent.name == ".artifacts" else root.parent
    current = boundary
    _validate_directory(current, "Private custody trust boundary")
    for part in candidate.relative_to(boundary).parts:
        current /= part
        _validate_directory(current, "Private symbol custody parent")
    return root.resolve(strict=True), candidate.resolve(strict=True)


def _regular_file(path: pathlib.Path, description: str) -> pathlib.Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SystemExit(f"{description} cannot be inspected: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"{description} must be a regular, non-symlink file: {path}")
    if metadata.st_nlink != 1:
        raise SystemExit(f"{description} must have exactly one filesystem link: {path}")
    return path.resolve(strict=True)


def _confined_symbols_dir(path: pathlib.Path, private_root: pathlib.Path) -> pathlib.Path:
    root, resolved = _validate_custody_directory_chain(path, private_root)
    if resolved == root or root not in resolved.parents:
        raise SystemExit(f"Symbols directory must be a child of private custody root: {root}")
    return resolved


def _symbol_files(symbols_dir: pathlib.Path) -> list[pathlib.Path]:
    ignored = {MANIFEST_NAME, SIDECAR_NAME}
    files: list[pathlib.Path] = []
    for path in sorted(symbols_dir.rglob("*")):
        if path.name in ignored and path.parent == symbols_dir:
            continue
        if path.is_symlink():
            raise SystemExit(f"Private symbol custody refuses symlinks: {path}")
        if path.is_dir():
            _validate_directory(path, "Private symbol custody parent")
            continue
        files.append(_regular_file(path, "Private symbol file"))
    if not files:
        raise SystemExit(f"Private symbol directory contains no retained files: {symbols_dir}")
    return files


def _entry(path: pathlib.Path, base: pathlib.Path | None = None) -> dict[str, object]:
    path = _regular_file(path, "Custody-bound file")
    label = path.name if base is None else path.relative_to(base).as_posix()
    return {"path": label, "size": path.stat().st_size, "sha256": _sha256(path)}


def _version(repo_root: pathlib.Path) -> tuple[str, int]:
    for line in (repo_root / "pubspec.yaml").read_text(encoding="utf-8").splitlines():
        if line.startswith("version:"):
            identity = line.split(":", 1)[1].strip()
            version, build = identity.rsplit("+", 1)
            return version, int(build)
    raise SystemExit("Unable to read version: <semver>+<build> from pubspec.yaml.")


def _secure_posix_tree(symbols_dir: pathlib.Path, private_root: pathlib.Path) -> None:
    if os.name == "nt":
        return
    root = private_root.resolve()
    current = symbols_dir
    protected_directories = []
    while current == root or root in current.parents:
        protected_directories.append(current)
        if current == root:
            break
        current = current.parent
    for directory in reversed(protected_directories):
        directory.chmod(0o700)
    symbols_dir.chmod(0o700)
    for path in symbols_dir.rglob("*"):
        if path.is_dir():
            path.chmod(0o700)
        elif path.is_file():
            path.chmod(0o600)


def record(
    platform: str,
    symbols_dir: pathlib.Path,
    artifacts: list[pathlib.Path],
    *,
    private_root: pathlib.Path = PRIVATE_ROOT,
    repo_root: pathlib.Path = ROOT,
) -> pathlib.Path:
    symbols_dir = _confined_symbols_dir(symbols_dir, private_root)
    artifact_files = [_regular_file(path, "Release artifact") for path in artifacts]
    symbol_files = _symbol_files(symbols_dir)
    version, build = _version(repo_root)
    payload = {
        "schema_version": 1,
        "contract": "winsvpn-private-release-symbol-custody-v1",
        "platform": platform,
        "app_version": version,
        "build_number": build,
        "encrypted_off_host_backup_required_for_publication": True,
        "private_files": [_entry(path, symbols_dir) for path in symbol_files],
        "release_artifacts": [_entry(path) for path in artifact_files],
    }
    manifest = symbols_dir / MANIFEST_NAME
    sidecar = symbols_dir / SIDECAR_NAME
    serialized = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary = manifest.with_suffix(".json.tmp")
    temporary.write_bytes(serialized)
    os.replace(temporary, manifest)
    sidecar_bytes = f"{hashlib.sha256(serialized).hexdigest()}  {MANIFEST_NAME}\n".encode("ascii")
    sidecar_temporary = sidecar.with_suffix(".sha256.tmp")
    sidecar_temporary.write_bytes(sidecar_bytes)
    os.replace(sidecar_temporary, sidecar)
    _secure_posix_tree(symbols_dir, private_root)
    return manifest


def verify(
    platform: str,
    symbols_dir: pathlib.Path,
    artifacts: list[pathlib.Path],
    *,
    private_root: pathlib.Path = PRIVATE_ROOT,
) -> None:
    symbols_dir = _confined_symbols_dir(symbols_dir, private_root)
    manifest = _regular_file(symbols_dir / MANIFEST_NAME, "Custody manifest")
    sidecar = _regular_file(symbols_dir / SIDECAR_NAME, "Custody manifest checksum")
    expected_sidecar = f"{_sha256(manifest)}  {MANIFEST_NAME}"
    if sidecar.read_text(encoding="ascii").strip() != expected_sidecar:
        raise SystemExit("Private symbol custody manifest checksum mismatch.")
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    if payload.get("contract") != "winsvpn-private-release-symbol-custody-v1":
        raise SystemExit("Private symbol custody contract is unsupported.")
    if payload.get("platform") != platform:
        raise SystemExit("Private symbol custody platform does not match.")
    actual_symbols = [_entry(path, symbols_dir) for path in _symbol_files(symbols_dir)]
    if payload.get("private_files") != actual_symbols:
        raise SystemExit("Private symbol custody files changed after manifest creation.")
    recorded_artifacts = payload.get("release_artifacts")
    actual_artifacts = [_entry(_regular_file(path, "Release artifact")) for path in artifacts]
    if not isinstance(recorded_artifacts, list) or len(recorded_artifacts) != len(actual_artifacts):
        raise SystemExit("Release artifact does not match private symbol custody evidence.")
    # Publication deliberately renames a fully verified staged artifact first
    # to a private prepared path and then to its canonical output path. The
    # custody identity is the ordered size and SHA-256 tuple, not the mutable
    # filesystem basename. The manifest retains the original basename only as
    # operator-facing provenance.
    for recorded, actual in zip(recorded_artifacts, actual_artifacts, strict=True):
        if not isinstance(recorded, dict) or any(
            recorded.get(field) != actual[field] for field in ("size", "sha256")
        ):
            raise SystemExit("Release artifact does not match private symbol custody evidence.")
    _secure_posix_tree(symbols_dir, private_root)


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        repo = root / "repo"
        private = repo / ".artifacts" / "private-release-symbols"
        symbols = private / "test" / "1.0.0+1"
        symbols.mkdir(parents=True)
        (repo / "pubspec.yaml").write_text("version: 1.0.0+1\n", encoding="utf-8")
        (symbols / "app.symbols").write_bytes(b"private symbols")
        artifact = root / "release.bin"
        artifact.write_bytes(b"release")
        record("test", symbols, [artifact], private_root=private, repo_root=repo)
        verify("test", symbols, [artifact], private_root=private)
        renamed_artifact = root / "prepared-release.bin"
        renamed_artifact.write_bytes(artifact.read_bytes())
        verify("test", symbols, [renamed_artifact], private_root=private)
        (symbols / "app.symbols").write_bytes(b"tampered")
        try:
            verify("test", symbols, [artifact], private_root=private)
        except SystemExit:
            pass
        else:
            raise SystemExit("Custody self-test did not detect symbol tampering.")
    print("PRIVATE RELEASE SYMBOL CUSTODY SELF-TEST: PASS")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    subparsers = parser.add_subparsers(dest="command")
    for name in ("record", "verify"):
        command = subparsers.add_parser(name)
        command.add_argument("--platform", required=True)
        command.add_argument("--symbols-dir", type=pathlib.Path, required=True)
        command.add_argument("--artifact", type=pathlib.Path, action="append", required=True)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.command == "record":
        manifest = record(args.platform, args.symbols_dir, args.artifact)
        print(f"PRIVATE SYMBOL CUSTODY RECORD: PASS ({manifest})")
    elif args.command == "verify":
        verify(args.platform, args.symbols_dir, args.artifact)
        print("PRIVATE SYMBOL CUSTODY VERIFY: PASS")
    else:
        parser.error("a command or --self-test is required")


if __name__ == "__main__":
    main()
