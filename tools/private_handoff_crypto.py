#!/usr/bin/env python3
"""Encrypt or decrypt a Win's VPN machine-transfer archive.

The file format is intentionally small and self-contained:
  magic || salt || nonce || AES-256-GCM(ciphertext + tag)

A 256-bit key is derived with scrypt. The encrypted payload is a gzipped tar
whose extraction is validated against absolute paths, traversal, links, and
special files before any member is written.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import secrets
import shutil
import sys
import tarfile
import tempfile
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


MAGIC = b"WVPH1\x00"
SALT_BYTES = 16
NONCE_BYTES = 12
SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 1


def _password(args: argparse.Namespace) -> bytearray:
    if args.password_file:
        data = bytearray(Path(args.password_file).read_bytes().strip())
    else:
        data = bytearray(getpass.getpass("Private handoff password: ").encode("utf-8"))
    if len(data) < 24:
        raise ValueError("The private handoff password must contain at least 24 bytes")
    return data


def _derive(password: bytearray, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(bytes(password))


def _tar_directory(source: Path) -> bytes:
    if not source.is_dir():
        raise ValueError(f"Source directory does not exist: {source}")
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(source.rglob("*"), key=lambda item: item.as_posix().casefold()):
            if path.is_symlink():
                raise ValueError(f"Symbolic links are not allowed in a private handoff: {path}")
            relative = path.relative_to(source).as_posix()
            if path.is_dir():
                info = archive.gettarinfo(str(path), arcname=relative)
                archive.addfile(info)
            elif path.is_file():
                info = archive.gettarinfo(str(path), arcname=relative)
                with path.open("rb") as stream:
                    archive.addfile(info, stream)
            else:
                raise ValueError(f"Special files are not allowed in a private handoff: {path}")
    return output.getvalue()


def encrypt(source: Path, destination: Path, password: bytearray) -> None:
    payload = bytearray(_tar_directory(source))
    salt = secrets.token_bytes(SALT_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    key = bytearray(_derive(password, salt))
    try:
        aad = MAGIC + salt + nonce
        ciphertext = AESGCM(bytes(key)).encrypt(nonce, bytes(payload), aad)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(destination.name + ".tmp")
        temporary.write_bytes(aad + ciphertext)
        os.replace(temporary, destination)
    finally:
        for index in range(len(payload)):
            payload[index] = 0
        for index in range(len(key)):
            key[index] = 0


def _safe_members(archive: tarfile.TarFile, destination: Path) -> list[tarfile.TarInfo]:
    destination_resolved = destination.resolve()
    members: list[tarfile.TarInfo] = []
    for member in archive.getmembers():
        logical = PurePosixPath(member.name)
        if logical.is_absolute() or ".." in logical.parts or member.issym() or member.islnk():
            raise ValueError(f"Unsafe archive member: {member.name}")
        if not (member.isdir() or member.isfile()):
            raise ValueError(f"Unsupported archive member: {member.name}")
        target = (destination / Path(*logical.parts)).resolve()
        if target != destination_resolved and destination_resolved not in target.parents:
            raise ValueError(f"Archive member escapes destination: {member.name}")
        members.append(member)
    return members


def decrypt(source: Path, destination: Path, password: bytearray) -> None:
    blob = source.read_bytes()
    header_bytes = len(MAGIC) + SALT_BYTES + NONCE_BYTES
    if len(blob) <= header_bytes + 16 or blob[: len(MAGIC)] != MAGIC:
        raise ValueError("Not a supported Win's VPN private handoff archive")
    salt_start = len(MAGIC)
    salt = blob[salt_start : salt_start + SALT_BYTES]
    nonce = blob[salt_start + SALT_BYTES : header_bytes]
    aad = blob[:header_bytes]
    key = bytearray(_derive(password, salt))
    plaintext = bytearray()
    try:
        plaintext = bytearray(AESGCM(bytes(key)).decrypt(nonce, blob[header_bytes:], aad))
        destination.mkdir(parents=True, exist_ok=False)
        with tarfile.open(fileobj=io.BytesIO(bytes(plaintext)), mode="r:gz") as archive:
            members = _safe_members(archive, destination)
            archive.extractall(destination, members=members, filter="data")
    except Exception:
        if destination.exists():
            shutil.rmtree(destination, ignore_errors=True)
        raise
    finally:
        for index in range(len(plaintext)):
            plaintext[index] = 0
        for index in range(len(key)):
            key[index] = 0


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="wins-private-handoff-") as temporary:
        root = Path(temporary)
        source = root / "source"
        source.mkdir()
        (source / "nested").mkdir()
        (source / "nested" / "secret.txt").write_text("test-only-secret", encoding="utf-8")
        archive = root / "bundle.wvenc"
        destination = root / "restored"
        password = bytearray(secrets.token_urlsafe(32).encode("ascii"))
        encrypt(source, archive, password)
        decrypt(archive, destination, password)
        assert (destination / "nested" / "secret.txt").read_text(encoding="utf-8") == "test-only-secret"
        damaged = bytearray(archive.read_bytes())
        damaged[-1] ^= 1
        corrupt_path = root / "corrupt.wvenc"
        corrupt_path.write_bytes(damaged)
        try:
            decrypt(corrupt_path, root / "must-not-exist", password)
        except Exception:
            pass
        else:
            raise AssertionError("Tampered ciphertext was accepted")
        print("Private handoff crypto self-test passed")


def verify(source: Path, password: bytearray) -> None:
    with tempfile.TemporaryDirectory(prefix="wins-private-handoff-verify-") as temporary:
        destination = Path(temporary) / "restored"
        decrypt(source, destination, password)
        manifest_path = destination / "PRIVATE_HANDOFF_MANIFEST.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        checked = 0
        for entry in manifest.get("files", []):
            relative = PurePosixPath(entry["path"])
            target = destination.joinpath(*relative.parts)
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            if digest != entry["sha256"]:
                raise ValueError(f"Manifest hash mismatch: {entry['path']}")
            if target.stat().st_size != int(entry["bytes"]):
                raise ValueError(f"Manifest size mismatch: {entry['path']}")
            checked += 1
        print(f"Private handoff verification passed ({checked} payload files)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    encrypt_parser = subparsers.add_parser("encrypt")
    encrypt_parser.add_argument("--source-dir", required=True)
    encrypt_parser.add_argument("--output", required=True)
    encrypt_parser.add_argument("--password-file")
    decrypt_parser = subparsers.add_parser("decrypt")
    decrypt_parser.add_argument("--input", required=True)
    decrypt_parser.add_argument("--output-dir", required=True)
    decrypt_parser.add_argument("--password-file")
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--input", required=True)
    verify_parser.add_argument("--password-file")
    subparsers.add_parser("self-test")
    args = parser.parse_args()
    if args.command == "self-test":
        self_test()
        return 0
    password = _password(args)
    try:
        if args.command == "encrypt":
            encrypt(Path(args.source_dir), Path(args.output), password)
        elif args.command == "verify":
            verify(Path(args.input), password)
        else:
            decrypt(Path(args.input), Path(args.output_dir), password)
    finally:
        for index in range(len(password)):
            password[index] = 0
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"private handoff failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
