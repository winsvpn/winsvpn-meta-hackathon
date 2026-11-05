#!/usr/bin/env python3
"""Verify that deployment will consume the exact bytes of one approved commit.

This verifier deliberately does not trust the index stat cache. It enumerates
the approved commit tree and hashes the worktree bytes directly, so index flags
such as assume-unchanged or skip-worktree cannot hide a local substitution.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import re
import stat
import subprocess
import sys
from typing import Iterable, List, Sequence, Tuple


class VerificationError(RuntimeError):
    """The operator checkout is not the exact approved deployment tree."""


GIT_OPERATION_PATHS = (
    "MERGE_HEAD",
    "CHERRY_PICK_HEAD",
    "REVERT_HEAD",
    "REBASE_HEAD",
    "rebase-apply",
    "rebase-merge",
    "sequencer",
    "BISECT_LOG",
)
GIT_BINARY = "/usr/bin/git"
IGNORED_INTERPRETER_BASENAMES = (
    b"conftest.py",
    b"sitecustomize.py",
    b"usercustomize.py",
)


def _git_environment() -> dict:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith("GIT_"):
            environment.pop(name, None)
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["LC_ALL"] = "C"
    return environment


def _git(repo: pathlib.Path, arguments: Sequence[str]) -> bytes:
    completed = subprocess.run(
        [GIT_BINARY, "--no-replace-objects", "-C", os.fspath(repo), *arguments],
        check=False,
        env=_git_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        command = arguments[0] if arguments else "command"
        raise VerificationError(f"git {command} failed while verifying the checkout")
    return completed.stdout


def _one_line(repo: pathlib.Path, arguments: Sequence[str]) -> str:
    raw = _git(repo, arguments)
    try:
        return raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise VerificationError("Git returned non-ASCII repository metadata") from exc


def _require_repository_root(repo: pathlib.Path) -> None:
    if _one_line(repo, ("rev-parse", "--is-inside-work-tree")) != "true":
        raise VerificationError("the requested path is not a Git worktree")
    reported = _git(repo, ("rev-parse", "--show-toplevel")).rstrip(b"\n")
    reported_root = pathlib.Path(os.fsdecode(reported)).resolve()
    if reported_root != repo:
        raise VerificationError("--repo must name the exact worktree root")


def _require_no_git_operation(repo: pathlib.Path) -> None:
    for marker in GIT_OPERATION_PATHS:
        raw_path = _git(repo, ("rev-parse", "--git-path", marker)).rstrip(b"\n")
        marker_path = os.fsdecode(raw_path)
        if not os.path.isabs(marker_path):
            marker_path = os.path.join(os.fspath(repo), marker_path)
        if os.path.lexists(marker_path):
            raise VerificationError("a Git merge, rebase, cherry-pick, revert, or bisect is active")


def _require_clean_status(repo: pathlib.Path) -> None:
    status_bytes = _git(
        repo,
        (
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ),
    )
    if status_bytes:
        count = len([record for record in status_bytes.split(b"\0") if record])
        raise VerificationError(
            "checkout contains staged, unstaged, or untracked filesystem state "
            f"({count} status entr{'y' if count == 1 else 'ies'})"
        )


def _ignored_entries(repo: pathlib.Path) -> List[bytes]:
    status_bytes = _git(
        repo,
        (
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignored=traditional",
            "--ignore-submodules=none",
        ),
    )
    entries: List[bytes] = []
    for record in status_bytes.split(b"\0"):
        if not record:
            continue
        if not record.startswith(b"!! "):
            raise VerificationError(
                "checkout changed while ignored filesystem state was inventoried"
            )
        path = record[3:]
        if not path:
            raise VerificationError("Git reported an empty ignored path")
        entries.append(path)
    return entries


def _ignored_receipt(entries: Sequence[bytes]) -> Tuple[int, int, str]:
    digest = hashlib.sha256()
    bytecode_entries = 0
    for path in sorted(entries):
        components = path.rstrip(b"/").split(b"/")
        lowered = [component.lower() for component in components]
        basename = lowered[-1]
        if (
            b".git" in lowered
            or basename.endswith(b".pth")
            or basename in IGNORED_INTERPRETER_BASENAMES
        ):
            raise VerificationError(
                "ignored filesystem state contains a refused VCS or interpreter injection path"
            )
        if b"__pycache__" in lowered or basename.endswith((b".pyc", b".pyo")):
            bytecode_entries += 1
        digest.update(path)
        digest.update(b"\0")
    return len(entries), bytecode_entries, digest.hexdigest()


def _require_safe_index_flags(repo: pathlib.Path) -> None:
    flagged = 0
    for record in _git(repo, ("ls-files", "-v", "-z")).split(b"\0"):
        if not record:
            continue
        tag = record[:1]
        if tag == b"S" or (tag and tag.islower()):
            flagged += 1
    if flagged:
        raise VerificationError(
            "checkout index contains skip-worktree or assume-unchanged entries "
            f"({flagged} entr{'y' if flagged == 1 else 'ies'})"
        )


def _tree_entries(repo: pathlib.Path, approved_sha: str) -> List[Tuple[bytes, bytes, bytes, bytes]]:
    entries: List[Tuple[bytes, bytes, bytes, bytes]] = []
    raw = _git(repo, ("ls-tree", "-rz", "--full-tree", approved_sha))
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            header, path = record.split(b"\t", 1)
            mode, object_type, object_id = header.split(b" ", 2)
        except ValueError as exc:
            raise VerificationError("approved tree contains an unparsable entry") from exc
        components = path.split(b"/")
        if not path or path.startswith(b"/") or any(part in (b"", b".", b"..") for part in components):
            raise VerificationError("approved tree contains an unsafe path")
        if object_type == b"commit" or mode == b"160000":
            raise VerificationError("deployment checkout verifier refuses Git submodules")
        if object_type != b"blob" or mode not in (b"100644", b"100755", b"120000"):
            raise VerificationError("approved tree contains an unsupported object type or mode")
        entries.append((mode, object_type, object_id, path))
    if not entries:
        raise VerificationError("approved commit tree is empty")
    return entries


def _exact_entry_present(directory_fd: int, component: bytes) -> None:
    names = {os.fsencode(name) for name in os.listdir(directory_fd)}
    if component not in names:
        raise VerificationError("a tracked path is absent or its on-disk name is not byte-exact")


def _open_parent(root_fd: int, path: bytes) -> Tuple[int, bytes]:
    components = path.split(b"/")
    current_fd = os.dup(root_fd)
    try:
        for component in components[:-1]:
            _exact_entry_present(current_fd, component)
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=current_fd,
            )
            os.close(current_fd)
            current_fd = next_fd
        _exact_entry_present(current_fd, components[-1])
        return current_fd, components[-1]
    except Exception:
        os.close(current_fd)
        raise


def _blob_digest(algorithm: str, size: int, chunks: Iterable[bytes]) -> str:
    digest = hashlib.new(algorithm)
    digest.update(f"blob {size}\0".encode("ascii"))
    observed = 0
    for chunk in chunks:
        observed += len(chunk)
        digest.update(chunk)
    if observed != size:
        raise VerificationError("a tracked file changed size while it was hashed")
    return digest.hexdigest()


def _file_chunks(file_fd: int) -> Iterable[bytes]:
    while True:
        chunk = os.read(file_fd, 1024 * 1024)
        if not chunk:
            return
        yield chunk


def _stable_identity(file_stat: os.stat_result) -> Tuple[int, int, int, int, int, int]:
    return (
        file_stat.st_dev,
        file_stat.st_ino,
        file_stat.st_mode,
        file_stat.st_size,
        file_stat.st_mtime_ns,
        file_stat.st_ctime_ns,
    )


def _verify_entry(
    root_fd: int,
    algorithm: str,
    mode: bytes,
    expected_object_id: bytes,
    path: bytes,
) -> None:
    parent_fd, leaf = _open_parent(root_fd, path)
    try:
        before = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if mode == b"120000":
            if not stat.S_ISLNK(before.st_mode):
                raise VerificationError("a tracked symlink was replaced by another file type")
            target = os.readlink(leaf, dir_fd=parent_fd)
            if not isinstance(target, bytes):
                target = os.fsencode(target)
            observed = _blob_digest(algorithm, len(target), (target,))
            after = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        else:
            if not stat.S_ISREG(before.st_mode):
                raise VerificationError("a tracked regular file was replaced by another file type")
            expected_executable = mode == b"100755"
            if bool(before.st_mode & stat.S_IXUSR) != expected_executable:
                raise VerificationError("a tracked file has a different Git executable mode")
            file_fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
            try:
                opened = os.fstat(file_fd)
                if _stable_identity(opened) != _stable_identity(before):
                    raise VerificationError("a tracked file changed while it was opened")
                observed = _blob_digest(algorithm, opened.st_size, _file_chunks(file_fd))
                after = os.fstat(file_fd)
            finally:
                os.close(file_fd)
        if _stable_identity(before) != _stable_identity(after):
            raise VerificationError("a tracked path changed while it was verified")
        if observed.encode("ascii") != expected_object_id:
            raise VerificationError("tracked worktree bytes do not match the approved commit")
    finally:
        os.close(parent_fd)


def _manifest_digest(entries: Sequence[Tuple[bytes, bytes, bytes, bytes]]) -> str:
    digest = hashlib.sha256()
    for mode, _object_type, object_id, path in entries:
        digest.update(mode)
        digest.update(b"\0")
        digest.update(path)
        digest.update(b"\0")
        digest.update(object_id)
        digest.update(b"\0")
    return digest.hexdigest()


def verify(
    repo_argument: str,
    approved_sha: str,
    allow_ignored_paths: bool = False,
) -> Tuple[str, str, int, str, int, int, str]:
    try:
        repo = pathlib.Path(repo_argument).resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise VerificationError("--repo does not resolve to an existing path") from exc
    if not repo.is_dir():
        raise VerificationError("--repo must be a directory")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise VerificationError("this platform lacks no-follow directory traversal support")

    _require_repository_root(repo)
    object_format = _one_line(repo, ("rev-parse", "--show-object-format"))
    digest_lengths = {"sha1": 40, "sha256": 64}
    if object_format not in digest_lengths:
        raise VerificationError("repository uses an unsupported Git object format")
    expected_length = digest_lengths[object_format]
    if not re.fullmatch(rf"[0-9a-f]{{{expected_length}}}", approved_sha):
        raise VerificationError("approved SHA must be one full lowercase commit object ID")
    resolved = _one_line(repo, ("rev-parse", "--verify", f"{approved_sha}^{{commit}}"))
    if resolved != approved_sha:
        raise VerificationError("approved object ID does not name that exact commit")
    if _one_line(repo, ("rev-parse", "HEAD")) != approved_sha:
        raise VerificationError("checkout HEAD does not equal the approved commit")

    approved_tree = _one_line(repo, ("rev-parse", f"{approved_sha}^{{tree}}"))
    _require_no_git_operation(repo)
    _require_safe_index_flags(repo)
    _require_clean_status(repo)
    entries = _tree_entries(repo, approved_sha)

    root_fd = os.open(os.fspath(repo), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for mode, _object_type, object_id, path in entries:
            _verify_entry(root_fd, object_format, mode, object_id, path)
    finally:
        os.close(root_fd)

    if _one_line(repo, ("rev-parse", "HEAD")) != approved_sha:
        raise VerificationError("checkout HEAD changed during verification")
    if _one_line(repo, ("rev-parse", f"{approved_sha}^{{tree}}")) != approved_tree:
        raise VerificationError("approved tree changed during verification")
    _require_no_git_operation(repo)
    _require_safe_index_flags(repo)
    _require_clean_status(repo)
    ignored_entries = _ignored_entries(repo)
    if ignored_entries and not allow_ignored_paths:
        raise VerificationError(
            "checkout contains ignored filesystem state "
            f"({len(ignored_entries)} entr{'y' if len(ignored_entries) == 1 else 'ies'}); "
            "use --allow-ignored-paths only for the declared operator checkout"
        )
    ignored_count, bytecode_count, ignored_digest = _ignored_receipt(ignored_entries)
    _require_clean_status(repo)
    if sorted(_ignored_entries(repo)) != sorted(ignored_entries):
        raise VerificationError("ignored filesystem state changed while it was inventoried")
    return (
        approved_sha,
        approved_tree,
        len(entries),
        _manifest_digest(entries),
        ignored_count,
        bytecode_count,
        ignored_digest,
    )


def parse_args(arguments: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="exact operator worktree root")
    parser.add_argument("--approved-sha", required=True, help="full audit-approved commit ID")
    parser.add_argument(
        "--allow-ignored-paths",
        action="store_true",
        help="inventory but do not authenticate ordinary ignored operator artifacts",
    )
    return parser.parse_args(arguments)


def main(arguments: Sequence[str]) -> int:
    options = parse_args(arguments)
    try:
        (
            approved_sha,
            tree,
            file_count,
            manifest,
            ignored_count,
            bytecode_count,
            ignored_digest,
        ) = verify(options.repo, options.approved_sha, options.allow_ignored_paths)
    except VerificationError as exc:
        print(f"deployment checkout verification refused: {exc}", file=sys.stderr)
        return 1
    print("deployment_checkout_verified=1")
    print(f"approved_sha={approved_sha}")
    print(f"approved_tree={tree}")
    print(f"tracked_path_count={file_count}")
    print(f"tree_manifest_sha256={manifest}")
    print(f"ignored_paths_allowed={int(options.allow_ignored_paths)}")
    print(f"ignored_entry_count={ignored_count}")
    print(f"ignored_bytecode_entry_count={bytecode_count}")
    print(f"ignored_entries_sha256={ignored_digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
