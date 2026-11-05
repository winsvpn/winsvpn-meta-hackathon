#!/usr/bin/env python3
"""Fail-closed local-key contract for Linux release signing.

Release signing is intentionally local-key-only. GitHub Actions OIDC, Fulcio,
and Rekor are not release authorities for Linux artifacts. The signer and
verifier use one owner-controlled key pair outside the repository, and the
installer verifies with the corresponding root-controlled trust anchor.

The exact Cosign 3.1.3 Linux executable is fixed at /usr/local/bin/cosign and
authenticated against a reviewed per-architecture SHA-256 before it executes.
It must be a single-link regular executable that is not group/other-writable
in a symlink-free directory chain owned by root or the current user; root
ownership of the executable itself is not required (the SHA-256 pin is the
authority).
Signing and immediate verification happen in one process while the key files
remain open. Cosign receives /proc/self/fd paths, so it cannot reopen a swapped
key pathname after preflight.

Release signing runs on the macOS release host (round R11a): remote Linux
builders never hold the key. On darwin the official Cosign 3.1.3 darwin
executable is accepted at any owner-controlled, symlink-free path passed with
--cosign, authenticated against COSIGN_DARWIN_SHA256_BY_MACHINE (the digest in
the official cosign_checksums.txt, whose Linux entries equal the reviewed Linux
pins above). It is executed by that path after its identity is rechecked
against the authenticated descriptor (macOS cannot exec /dev/fd/N); the key
files are passed as /dev/fd/N.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import hashlib
import json
import os
import pathlib
import platform
import stat
import subprocess
import sys
from collections.abc import Iterator


COSIGN_VERSION = "v3.1.3"
COSIGN_PATH = "/usr/local/bin/cosign"
OWNER_BLOCKED = "OWNER-BLOCKED: ABSENT"
COSIGN_SHA256_BY_MACHINE = {
    "x86_64": "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71",
    "amd64": "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71",
    "aarch64": "c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a",
    "arm64": "c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a",
}
COSIGN_DARWIN_SHA256_BY_MACHINE = {
    # https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-darwin-arm64
    # 139618946 bytes; cosign_checksums.txt sha256 aec2a6f68d307b09ae196e388dc691a146fa8bdba7fcce9ca4ca41b918adfa63
    "arm64": "5cf948c2f4dfe59687bdd0b8523709067383e03982cc543475c8a7dc70e92a76",
}
_DARWIN_COSIGN_PATHS: dict[int, pathlib.Path] = {}
STANDARD_BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
INSTALLER_TRUST_ANCHOR_ROUTE = "/etc/winsvpn/release-signing/cosign.pub"
RETIRED_OIDC_ENV = (
    "WINS_LINUX_SIGNER_IDENTITY",
    "WINS_LINUX_SIGNER_OIDC_ISSUER",
)


class SigningError(Exception):
    """Fail-closed signing-contract refusal."""


def _die(message: str) -> None:
    raise SigningError(message)


def _owner_environment_blocker(message: str) -> SigningError:
    if OWNER_BLOCKED in message:
        return SigningError(f"owner/environment blocker: {message}")
    return SigningError(f"owner/environment blocker: {OWNER_BLOCKED} {message}")


def env_nonempty(*names: str) -> list[str]:
    return [name for name in names if os.environ.get(name, "").strip()]


def _absolute_path(path_value: str, label: str) -> pathlib.Path:
    path = pathlib.Path(path_value).expanduser()
    if not path.is_absolute():
        _die(f"{label} must be an absolute path.")
    return pathlib.Path(os.path.normpath(os.fspath(path)))


def _path_chain(path: pathlib.Path) -> Iterator[pathlib.Path]:
    current = pathlib.Path(path.anchor)
    yield current
    for component in path.parts[1:]:
        current /= component
        yield current


def assert_owner_controlled_path_chain(
    path: pathlib.Path,
    label: str,
    *,
    include_leaf: bool,
    root_only: bool = False,
) -> None:
    """Reject symlinks and writable/unowned components without resolving them."""

    allowed_owners = {0} if root_only else {0, os.getuid()}
    components = list(_path_chain(path if include_leaf else path.parent))
    for index, component in enumerate(components):
        try:
            info = os.lstat(component)
        except OSError as exc:
            raise SigningError(f"{label} path component could not be inspected: {component}") from exc
        if stat.S_ISLNK(info.st_mode):
            _die(f"{label} path chain must not contain symbolic links: {component}")
        is_leaf = include_leaf and index == len(components) - 1
        if not is_leaf and not stat.S_ISDIR(info.st_mode):
            _die(f"{label} parent path is not a directory: {component}")
        if info.st_uid not in allowed_owners:
            owner = "root" if root_only else "root or the current user"
            _die(f"{label} path chain is not controlled by {owner}: {component}")
        if info.st_mode & 0o022:
            _die(f"{label} path chain is group/other-writable: {component}")


def _assert_outside_repo(path: pathlib.Path, repo: pathlib.Path, label: str) -> None:
    try:
        common = pathlib.Path(os.path.commonpath((path, repo)))
    except ValueError:
        return
    if common == repo:
        _die(f"{label} must stay outside the Git repository.")


def _validate_open_file(
    fd: int,
    path: pathlib.Path,
    label: str,
    *,
    private: bool,
    executable: bool = False,
) -> os.stat_result:
    info = os.fstat(fd)
    try:
        path_info = os.lstat(path)
    except OSError as exc:
        raise SigningError(f"{label} pathname could not be rechecked after open.") from exc
    if (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino):
        _die(f"{label} changed while it was being opened.")
    if not stat.S_ISREG(info.st_mode):
        _die(f"{label} must be a regular file.")
    if info.st_nlink != 1:
        _die(f"{label} must not be hard-linked.")
    if info.st_size <= 0:
        _die(f"{label} must not be empty.")
    if executable:
        if info.st_mode & 0o022:
            _die(f"{label} must not be writable by group or other.")
        if not info.st_mode & 0o111:
            _die(f"{label} must be executable.")
    else:
        if info.st_uid != os.getuid():
            _die(f"{label} must be owned by the current user.")
        mode = stat.S_IMODE(info.st_mode)
        if private:
            if mode & 0o177:
                _die(f"{label} must use mode 0600 or stricter without execute bits.")
        elif mode & 0o133:
            _die(
                f"{label} must not be executable or writable by group or other "
                "(0644 or stricter)."
            )
    return info


def _open_no_follow(path: pathlib.Path, label: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(path, flags)
    except OSError as exc:
        if getattr(exc, "errno", None) == errno.ENOENT:
            raise _owner_environment_blocker(f"{label} is absent at {path}") from exc
        raise SigningError(
            f"{label} could not be opened without following links."
        ) from exc


def _sha256_fd(fd: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        block = os.pread(fd, 1024 * 1024, offset)
        if not block:
            return digest.hexdigest()
        digest.update(block)
        offset += len(block)


def expected_cosign_sha256(machine: str | None = None) -> str:
    normalized = (machine or platform.machine()).lower()
    if sys.platform == "darwin":
        try:
            return COSIGN_DARWIN_SHA256_BY_MACHINE[normalized]
        except KeyError as exc:
            raise SigningError(
                f"Cosign has no reviewed darwin executable pin for architecture {normalized!r}."
            ) from exc
    try:
        return COSIGN_SHA256_BY_MACHINE[normalized]
    except KeyError as exc:
        raise SigningError(
            f"Cosign has no reviewed Linux executable pin for architecture {normalized!r}."
        ) from exc


def _proc_fd_path(fd: int, label: str) -> str:
    if sys.platform == "darwin":
        if not pathlib.Path("/dev/fd").is_dir():
            _die(f"{label} requires /dev/fd descriptor binding.")
        return f"/dev/fd/{fd}"
    path = f"/proc/self/fd/{fd}"
    if not pathlib.Path("/proc/self/fd").is_dir():
        _die(f"{label} requires Linux /proc/self/fd descriptor binding.")
    return path


def _cosign_executable(fd: int, label: str) -> str:
    """Return the path to execute for the authenticated Cosign descriptor."""

    # The descriptor names the authenticated inode, which an in-place write can
    # change without changing its identity, so its bytes are rehashed here.
    if _sha256_fd(fd) != expected_cosign_sha256():
        _die(f"{label}: Cosign executable bytes changed after authentication.")
    if sys.platform != "darwin":
        return _proc_fd_path(fd, label)
    path = _DARWIN_COSIGN_PATHS.get(fd)
    if path is None:
        _die(f"{label} has no authenticated darwin Cosign path.")
    info = os.fstat(fd)
    try:
        path_info = os.lstat(path)
    except OSError as exc:
        raise SigningError(f"{label} path disappeared after authentication.") from exc
    if stat.S_ISLNK(path_info.st_mode) or (path_info.st_dev, path_info.st_ino) != (
        info.st_dev,
        info.st_ino,
    ) or path_info.st_size != info.st_size or path_info.st_mtime_ns != info.st_mtime_ns:
        _die(f"{label} path no longer names the authenticated executable.")
    return os.fspath(path)


@contextlib.contextmanager
def open_authenticated_cosign(
    path_value: str = COSIGN_PATH,
) -> Iterator[int]:
    path = _absolute_path(path_value, "Cosign executable")
    if sys.platform != "darwin" and os.fspath(path) != COSIGN_PATH:
        _die(f"Cosign executable must use the fixed reviewed path {COSIGN_PATH}.")
    try:
        os.lstat(path)
    except OSError as error:
        if getattr(error, "errno", None) == errno.ENOENT:
            raise _owner_environment_blocker(
                f"Cosign executable is absent at {path}"
            ) from error
        raise SigningError("Cosign executable could not be inspected.") from error
    assert_owner_controlled_path_chain(
        path, "Cosign executable", include_leaf=False, root_only=False
    )
    fd = _open_no_follow(path, "Cosign executable")
    try:
        _validate_open_file(fd, path, "Cosign executable", private=False, executable=True)
        expected = expected_cosign_sha256()
        actual = _sha256_fd(fd)
        if actual != expected:
            _die(
                f"Cosign executable SHA-256 mismatch: expected {expected}, found {actual}."
            )
        if sys.platform == "darwin":
            _DARWIN_COSIGN_PATHS[fd] = path
        executable = _cosign_executable(fd, "Cosign authentication")
        completed = subprocess.run(
            [executable, "version"],
            pass_fds=(fd,),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="strict",
            shell=False,
            check=False,
            timeout=30,
        )
        expected_line = f"GitVersion: {COSIGN_VERSION}"
        # cosign version aligns its columns ("GitVersion:    v3.1.3"), so
        # compare whitespace-normalized lines.
        lines = [" ".join(line.split()) for line in completed.stdout.splitlines()]
        if completed.returncode != 0 or expected_line not in lines:
            _die(f"Expected exact Cosign {COSIGN_VERSION}; authenticated executable disagrees.")
        yield fd
    finally:
        _DARWIN_COSIGN_PATHS.pop(fd, None)
        os.close(fd)


def _open_key(path_value: str, repo: pathlib.Path, label: str, *, private: bool) -> int:
    path = _absolute_path(path_value, label)
    assert_owner_controlled_path_chain(path, label, include_leaf=False)
    _assert_outside_repo(path, repo, label)
    fd = _open_no_follow(path, label)
    try:
        _validate_open_file(fd, path, label, private=private)
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextlib.contextmanager
def open_key_pair(repo: pathlib.Path) -> Iterator[tuple[int, int]]:
    key_fd = _open_key(
        os.environ["WINS_LINUX_COSIGN_KEY"], repo, "WINS_LINUX_COSIGN_KEY", private=True
    )
    try:
        pubkey_fd = _open_key(
            os.environ["WINS_LINUX_COSIGN_PUBKEY"],
            repo,
            "WINS_LINUX_COSIGN_PUBKEY",
            private=False,
        )
        try:
            key_info = os.fstat(key_fd)
            pubkey_info = os.fstat(pubkey_fd)
            if (key_info.st_dev, key_info.st_ino) == (pubkey_info.st_dev, pubkey_info.st_ino):
                _die("WINS_LINUX_COSIGN_KEY and WINS_LINUX_COSIGN_PUBKEY must be different files.")
            yield key_fd, pubkey_fd
        finally:
            os.close(pubkey_fd)
    finally:
        os.close(key_fd)


def validate_installer_trust_anchor_route(value: str) -> None:
    if value != INSTALLER_TRUST_ANCHOR_ROUTE:
        _die(
            "WINS_LINUX_COSIGN_TRUST_ANCHOR must name the reviewed installer "
            f"route {INSTALLER_TRUST_ANCHOR_ROUTE}."
        )


def signing_mode() -> str:
    sign = os.environ.get("SIGN_LINUX_RELEASE", "0")
    if sign not in {"0", "1"}:
        _die("SIGN_LINUX_RELEASE must be 0 or 1.")
    if env_nonempty(*RETIRED_OIDC_ENV):
        _die("GitHub/OIDC Linux release signing is disabled; use the owner-held local key pair.")
    if sign == "0":
        return "unsigned"
    key_names = (
        "WINS_LINUX_COSIGN_KEY",
        "WINS_LINUX_COSIGN_PUBKEY",
        "WINS_LINUX_COSIGN_TRUST_ANCHOR",
    )
    key_vars = env_nonempty(*key_names)
    if len(key_vars) != len(key_names):
        raise _owner_environment_blocker(
            "SIGN_LINUX_RELEASE=1 requires WINS_LINUX_COSIGN_KEY, "
            "WINS_LINUX_COSIGN_PUBKEY, and WINS_LINUX_COSIGN_TRUST_ANCHOR together."
        )
    return "key"


def preflight(repo: pathlib.Path) -> str:
    mode = signing_mode()
    if mode == "unsigned":
        return mode
    with open_key_pair(repo):
        pass
    validate_installer_trust_anchor_route(os.environ["WINS_LINUX_COSIGN_TRUST_ANCHOR"])
    return mode


def _sign_arguments(archive: str, bundle: str, key_reference: str) -> list[str]:
    return [
        "sign-blob",
        archive,
        "--key",
        key_reference,
        "--bundle",
        bundle,
        # Cosign 3.x signs through a signing config by default and refuses
        # --tlog-upload=false with one; local-key offline signing opts out.
        "--use-signing-config=false",
        "--tlog-upload=false",
        "--yes",
    ]


def _verify_arguments(archive: str, bundle: str, public_key_reference: str) -> list[str]:
    return [
        "verify-blob",
        archive,
        "--key",
        public_key_reference,
        "--bundle",
        bundle,
        "--offline",
        "--insecure-ignore-tlog",
    ]


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _die(f"Sigstore bundle contains duplicate JSON key {key!r}.")
        result[key] = value
    return result


def validate_standard_bundle(path_value: str) -> None:
    path = _absolute_path(path_value, "Sigstore bundle")
    try:
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            _die("Sigstore bundle must be one regular non-symlink file.")
        payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_json_object)
    except SigningError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SigningError("Sigstore bundle is not valid UTF-8 JSON.") from exc
    if not isinstance(payload, dict):
        _die("Sigstore bundle root must be a JSON object.")
    if payload.get("mediaType") != STANDARD_BUNDLE_MEDIA_TYPE:
        _die(
            "Refusing a legacy or unsupported Sigstore bundle; expected "
            f"{STANDARD_BUNDLE_MEDIA_TYPE}."
        )
    if not isinstance(payload.get("verificationMaterial"), dict):
        _die("Standard Sigstore bundle lacks verificationMaterial.")
    content_fields = [
        name for name in ("messageSignature", "dsseEnvelope") if isinstance(payload.get(name), dict)
    ]
    if len(content_fields) != 1:
        _die("Standard Sigstore bundle must contain exactly one signature content type.")


def _run_cosign(cosign_fd: int, args: list[str], inherited_fds: tuple[int, ...]) -> None:
    executable = _cosign_executable(cosign_fd, "Cosign execution")
    completed = subprocess.run(
        [executable, *args],
        pass_fds=(cosign_fd, *inherited_fds),
        shell=False,
        check=False,
    )
    if completed.returncode != 0:
        _die(f"Cosign command failed with exit code {completed.returncode}.")


def _copy_fd_exclusive(source_fd: int, destination_value: str) -> None:
    destination = _absolute_path(destination_value, "Cosign public-key sidecar")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        destination_fd = os.open(destination, flags, 0o600)
    except OSError as exc:
        raise SigningError("Cosign public-key sidecar already exists or is unsafe.") from exc
    try:
        offset = 0
        while True:
            block = os.pread(source_fd, 1024 * 1024, offset)
            if not block:
                break
            view = memoryview(block)
            while view:
                view = view[os.write(destination_fd, view) :]
            offset += len(block)
        os.fsync(destination_fd)
        os.fchmod(destination_fd, 0o644)
    finally:
        os.close(destination_fd)


def run_sign_and_verify(
    repo: pathlib.Path,
    cosign_path: str,
    archive: str,
    bundle: str,
    public_key_output: str,
) -> None:
    if preflight(repo) != "key":
        _die("Unsigned Linux builds do not emit a Sigstore bundle.")
    with open_authenticated_cosign(cosign_path) as cosign_fd:
        with open_key_pair(repo) as (key_fd, pubkey_fd):
            key_reference = _proc_fd_path(key_fd, "Private signing key binding")
            pubkey_reference = _proc_fd_path(pubkey_fd, "Public verification key binding")
            _run_cosign(
                cosign_fd,
                _sign_arguments(archive, bundle, key_reference),
                (key_fd,),
            )
            validate_standard_bundle(bundle)
            _run_cosign(
                cosign_fd,
                _verify_arguments(archive, bundle, pubkey_reference),
                (pubkey_fd,),
            )
            _copy_fd_exclusive(pubkey_fd, public_key_output)


def run_verify(
    repo: pathlib.Path,
    cosign_path: str,
    archive: str,
    bundle: str,
) -> None:
    if preflight(repo) != "key":
        _die("Unsigned Linux builds have no signature to verify.")
    validate_standard_bundle(bundle)
    with open_authenticated_cosign(cosign_path) as cosign_fd:
        with open_key_pair(repo) as (_, pubkey_fd):
            pubkey_reference = _proc_fd_path(pubkey_fd, "Public verification key binding")
            _run_cosign(
                cosign_fd,
                _verify_arguments(archive, bundle, pubkey_reference),
                (pubkey_fd,),
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Linux release signing contract")
    parser.add_argument(
        "action",
        choices=(
            "preflight",
            "mode",
            "authenticate-cosign",
            "run-sign-verify",
            "run-verify",
            "validate-bundle",
        ),
    )
    parser.add_argument("--repo", default="")
    parser.add_argument("--archive", default="")
    parser.add_argument("--bundle", default="")
    parser.add_argument("--cosign", default=COSIGN_PATH)
    parser.add_argument("--public-key-output", default="")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo = pathlib.Path(args.repo).resolve() if args.repo else pathlib.Path(__file__).resolve().parents[1]
    try:
        if args.action in {"mode", "preflight"}:
            print(preflight(repo))
            return 0
        if args.action == "authenticate-cosign":
            with open_authenticated_cosign(args.cosign):
                pass
            print("AUTHENTICATED COSIGN: PASS")
            return 0
        if args.action == "validate-bundle":
            if not args.bundle:
                parser.error("--bundle is required")
            validate_standard_bundle(args.bundle)
            print("SIGSTORE STANDARD BUNDLE: PASS")
            return 0
        if not args.archive or not args.bundle:
            parser.error("--archive and --bundle are required")
        if args.action == "run-sign-verify":
            if not args.public_key_output:
                parser.error("--public-key-output is required")
            run_sign_and_verify(
                repo,
                args.cosign,
                args.archive,
                args.bundle,
                args.public_key_output,
            )
        else:
            run_verify(
                repo,
                args.cosign,
                args.archive,
                args.bundle,
            )
        return 0
    except SigningError as exc:
        print(str(exc), file=sys.stderr)
        return 65


if __name__ == "__main__":
    raise SystemExit(main())
