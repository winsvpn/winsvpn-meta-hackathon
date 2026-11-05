#!/usr/bin/env python3
"""Pin and hold the operator main branch during an independent deployment audit."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


FREEZE_REF = "refs/winsvpn/deployment-audit-freeze"
PROTECTED_REF = "refs/heads/main"
HOOK_RELATIVE = ".githooks/reference-transaction"
IPSCRUB_HOOK_RELATIVE = "tools/ipscrub/pre-push"
TOOL_RELATIVE = "tools/deployment_audit_freeze.py"
RECEIPT_SCHEMA = "winsvpn-deployment-audit-freeze-v1"
HEX_OID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
VERDICT = re.compile(r"(?m)^VERDICT: DEPLOYMENT (GO|NO-GO)$")
RECEIPT_KEYS = {
    "schema",
    "created_at_utc",
    "repository_root",
    "freeze_ref",
    "protected_ref",
    "branch",
    "commit",
    "tree",
    "hook_path",
    "previous_local_hooks_path",
}


class FreezeError(RuntimeError):
    """The audit freeze contract was not satisfied."""


def _reject_inherited_git_config() -> None:
    """Refuse caller-supplied config layers that could disable both hooks."""
    exact = {
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_NOSYSTEM",
    }
    configured = sorted(
        name
        for name in os.environ
        if name in exact
        or name.startswith("GIT_CONFIG_KEY_")
        or name.startswith("GIT_CONFIG_VALUE_")
    )
    if configured:
        raise FreezeError(
            "inherited Git config overrides are forbidden while checking hook custody"
        )


def _git_environment() -> Dict[str, str]:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith("GIT_"):
            environment.pop(name, None)
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["LC_ALL"] = "C"
    return environment


def _git(
    repo: Path,
    arguments: Sequence[str],
    *,
    check: bool = True,
    input_bytes: Optional[bytes] = None,
) -> subprocess.CompletedProcess:
    completed = subprocess.run(
        ["/usr/bin/git", "--no-replace-objects", "-C", os.fspath(repo), *arguments],
        check=False,
        env=_git_environment(),
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and completed.returncode != 0:
        command = arguments[0] if arguments else "command"
        raise FreezeError("git {} failed while enforcing the audit freeze".format(command))
    return completed


def _one_line(repo: Path, arguments: Sequence[str]) -> str:
    raw = _git(repo, arguments).stdout
    try:
        value = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise FreezeError("Git returned non-ASCII repository metadata") from exc
    if not value or "\n" in value:
        raise FreezeError("Git returned invalid single-line repository metadata")
    return value


def _repo(path: str) -> Path:
    requested = Path(path)
    if not requested.is_absolute():
        requested = Path.cwd() / requested
    resolved = requested.resolve()
    if _one_line(resolved, ("rev-parse", "--is-inside-work-tree")) != "true":
        raise FreezeError("--repo must name a Git worktree")
    reported = Path(os.fsdecode(_git(resolved, ("rev-parse", "--show-toplevel")).stdout.rstrip(b"\n"))).resolve()
    if reported != resolved:
        raise FreezeError("--repo must name the exact worktree root")
    return resolved


def _oid(repo: Path, name: str) -> str:
    value = _one_line(repo, ("rev-parse", "--verify", "{}^{{commit}}".format(name)))
    if not HEX_OID.fullmatch(value):
        raise FreezeError("Git returned an invalid object ID")
    return value


def _optional_ref(repo: Path, name: str) -> Optional[str]:
    completed = _git(repo, ("rev-parse", "--verify", "{}^{{commit}}".format(name)), check=False)
    if completed.returncode != 0:
        return None
    try:
        value = completed.stdout.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise FreezeError("Git returned a non-ASCII freeze ref") from exc
    if not HEX_OID.fullmatch(value):
        raise FreezeError("the freeze ref is not a full commit object ID")
    return value


def _branch(repo: Path) -> str:
    completed = _git(repo, ("symbolic-ref", "--quiet", "--short", "HEAD"), check=False)
    if completed.returncode != 0:
        raise FreezeError("the operator checkout must be attached to main")
    return completed.stdout.decode("ascii").strip()


def _require_clean(repo: Path) -> None:
    status_bytes = _git(
        repo,
        ("status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"),
    ).stdout
    if status_bytes:
        count = len([entry for entry in status_bytes.split(b"\0") if entry])
        raise FreezeError("operator checkout is not clean ({} entries)".format(count))


def _config_value(repo: Path, *, local: bool) -> Optional[str]:
    scope = "--local" if local else "--get"
    arguments = ("config", scope, "--get", "core.hooksPath") if local else ("config", "--get", "core.hooksPath")
    completed = _git(repo, arguments, check=False)
    if completed.returncode == 1:
        return None
    if completed.returncode != 0:
        raise FreezeError("could not inspect core.hooksPath")
    try:
        value = completed.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise FreezeError("core.hooksPath is not UTF-8") from exc
    return value or None


def _tracked_bytes(repo: Path, commit: str, relative: str) -> bytes:
    return _git(repo, ("cat-file", "blob", "{}:{}".format(commit, relative))).stdout


def _tracked_executable(repo: Path, commit: str, relative: str) -> bytes:
    listing = _one_line(repo, ("ls-tree", commit, "--", relative))
    fields = listing.split(None, 3)
    if len(fields) != 4 or fields[0] != "100755" or fields[1] != "blob" or fields[3] != relative:
        raise FreezeError("tracked hook is not one exact executable blob")
    return _tracked_bytes(repo, commit, relative)


def _common_hooks_directory(repo: Path) -> Path:
    raw = _one_line(repo, ("rev-parse", "--git-common-dir"))
    common = Path(raw)
    if not common.is_absolute():
        common = repo / common
    common = common.resolve()
    hooks = common / "hooks"
    if hooks.exists():
        info = os.lstat(hooks)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise FreezeError("common Git hooks path is unsafe")
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise FreezeError("common Git hooks directory is not owner-controlled")
    else:
        hooks.mkdir(mode=0o700)
    return hooks


def _installed_reference_hook(repo: Path) -> Path:
    return _common_hooks_directory(repo) / "reference-transaction"


def _install_reference_hook(repo: Path, commit: str) -> bool:
    expected = _tracked_executable(repo, commit, HOOK_RELATIVE)
    destination = _installed_reference_hook(repo)
    if destination.exists() or destination.is_symlink():
        actual, info = _stable_file(destination, required_mode=0o755)
        if info.st_uid != os.geteuid() or actual != expected:
            raise FreezeError("existing common reference-transaction hook is not the reviewed freeze hook")
        return False
    directory_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    temporary = ".reference-transaction.{}.tmp".format(secrets.token_hex(12))
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o700,
            dir_fd=directory_fd,
        )
        try:
            offset = 0
            while offset < len(expected):
                written = os.write(descriptor, expected[offset:])
                if written <= 0:
                    raise FreezeError("short write while installing freeze hook")
                offset += written
            os.fchmod(descriptor, 0o755)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.rename(temporary, destination.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    except Exception:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except OSError:
            pass
        raise
    finally:
        os.close(directory_fd)
    actual, info = _stable_file(destination, required_mode=0o755)
    if info.st_uid != os.geteuid() or actual != expected:
        raise FreezeError("installed freeze hook failed byte or metadata verification")
    return True


def _remove_reference_hook(repo: Path, commit: str) -> None:
    destination = _installed_reference_hook(repo)
    expected = _tracked_executable(repo, commit, HOOK_RELATIVE)
    actual, info = _stable_file(destination, required_mode=0o755)
    if info.st_uid != os.geteuid() or actual != expected:
        raise FreezeError("installed freeze hook changed; refusing to remove it")
    destination.unlink()
    directory_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _stable_file(path: Path, *, required_mode: Optional[int] = None) -> Tuple[bytes, os.stat_result]:
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            before = os.fstat(descriptor)
            linked_before = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            identity = lambda item: (
                item.st_dev,
                item.st_ino,
                item.st_mode,
                item.st_nlink,
                item.st_uid,
                item.st_gid,
                item.st_size,
                item.st_mtime_ns,
                item.st_ctime_ns,
            )
            if (
                identity(before) != identity(linked_before)
                or not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or (required_mode is not None and stat.S_IMODE(before.st_mode) != required_mode)
            ):
                raise FreezeError("evidence path has unsafe file metadata")
            chunks: List[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > 16 * 1024 * 1024:
                    raise FreezeError("evidence file exceeds the bounded size")
                chunks.append(chunk)
            after = os.fstat(descriptor)
            linked_after = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            if identity(before) != identity(after) or identity(after) != identity(linked_after):
                raise FreezeError("evidence file changed while it was read")
            return b"".join(chunks), after
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise FreezeError("could not read stable evidence file") from exc
    finally:
        os.close(parent_fd)


def _write_receipt(path: Path, receipt: Mapping[str, Any]) -> None:
    if not path.is_absolute():
        raise FreezeError("--receipt must be an absolute external path")
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        parent = os.fstat(parent_fd)
        if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) & 0o022:
            raise FreezeError("receipt parent is not owner-controlled")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptor = os.open(path.name, flags, 0o600, dir_fd=parent_fd)
        try:
            payload = json.dumps(
                receipt,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii") + b"\n"
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise FreezeError("short write while creating freeze receipt")
                offset += written
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            info = os.fstat(descriptor)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise FreezeError("freeze receipt metadata is unsafe")
        finally:
            os.close(descriptor)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _load_receipt(path: Path) -> Mapping[str, Any]:
    data, info = _stable_file(path, required_mode=0o600)
    if info.st_uid != os.geteuid():
        raise FreezeError("freeze receipt is not owned by the current operator")
    try:
        value = json.loads(data.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FreezeError("freeze receipt is not valid ASCII JSON") from exc
    if not isinstance(value, dict) or set(value) != RECEIPT_KEYS:
        raise FreezeError("freeze receipt fields are invalid")
    for key in ("commit", "tree"):
        if not isinstance(value[key], str) or not HEX_OID.fullmatch(value[key]):
            raise FreezeError("freeze receipt {} is invalid".format(key))
    if value["schema"] != RECEIPT_SCHEMA or value["freeze_ref"] != FREEZE_REF:
        raise FreezeError("freeze receipt contract is invalid")
    if value["protected_ref"] != PROTECTED_REF or value["branch"] != "main":
        raise FreezeError("freeze receipt protected branch is invalid")
    if value["hook_path"] != HOOK_RELATIVE or not UTC.fullmatch(value["created_at_utc"]):
        raise FreezeError("freeze receipt hook or timestamp is invalid")
    if value["previous_local_hooks_path"] is not None:
        raise FreezeError("freeze receipt prior hook configuration is invalid")
    return value


def _validate_hook_closure(repo: Path, commit: str) -> None:
    expected_reference = _tracked_executable(repo, commit, HOOK_RELATIVE)
    reference, reference_info = _stable_file(_installed_reference_hook(repo), required_mode=0o755)
    if reference_info.st_uid != os.geteuid() or reference != expected_reference:
        raise FreezeError("the installed reference-transaction hook is not the pinned reviewed hook")
    if _config_value(repo, local=False) is not None:
        raise FreezeError("core.hooksPath must stay unset so the mandatory pre-push gate remains active")
    expected_prepush = _tracked_executable(repo, commit, IPSCRUB_HOOK_RELATIVE)
    prepush = _common_hooks_directory(repo) / "pre-push"
    actual_prepush, prepush_info = _stable_file(prepush, required_mode=0o755)
    if prepush_info.st_uid != os.geteuid() or actual_prepush != expected_prepush:
        raise FreezeError("the mandatory installed ipscrub pre-push hook is missing or stale")


def _receipt(repo: Path, previous_local_hooks_path: Optional[str]) -> Mapping[str, Any]:
    head = _oid(repo, "HEAD")
    return {
        "schema": RECEIPT_SCHEMA,
        "created_at_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repository_root": os.fspath(repo),
        "freeze_ref": FREEZE_REF,
        "protected_ref": PROTECTED_REF,
        "branch": "main",
        "commit": head,
        "tree": _one_line(repo, ("show", "-s", "--format=%T", head)),
        "hook_path": HOOK_RELATIVE,
        "previous_local_hooks_path": previous_local_hooks_path,
    }


def pin(repo: Path, receipt_path: Path) -> None:
    if _branch(repo) != "main":
        raise FreezeError("the operator checkout must be on main")
    _require_clean(repo)
    if _optional_ref(repo, FREEZE_REF) is not None:
        raise FreezeError("an audit freeze is already active")
    head = _oid(repo, "HEAD")
    if _oid(repo, PROTECTED_REF) != head:
        raise FreezeError("main and HEAD are not the same commit")
    if _config_value(repo, local=False) is not None:
        raise FreezeError("core.hooksPath must be unset before pinning; it can disable security gates")
    previous_local = _config_value(repo, local=True)
    if previous_local is not None:
        raise FreezeError("local core.hooksPath must be unset before pinning")
    receipt = _receipt(repo, previous_local)
    pinned = False
    hook_created = False
    try:
        hook_created = _install_reference_hook(repo, head)
        _validate_hook_closure(repo, head)
        _git(repo, ("update-ref", "--create-reflog", "-m", "deployment audit freeze", FREEZE_REF, head, ""))
        pinned = True
        _write_receipt(receipt_path, receipt)
        check_operator(repo, expected_sha=head, receipt_path=receipt_path)
    except Exception:
        if pinned:
            _git(repo, ("update-ref", "-d", FREEZE_REF, head), check=False)
        if hook_created:
            try:
                _remove_reference_hook(repo, head)
            except Exception:
                pass
        raise
    print("deployment_audit_freeze=PINNED")
    print("pinned_sha={}".format(head))
    print("pinned_tree={}".format(receipt["tree"]))
    print("receipt={}".format(receipt_path))


def check_operator(repo: Path, *, expected_sha: Optional[str], receipt_path: Optional[Path]) -> None:
    pinned = _optional_ref(repo, FREEZE_REF)
    if pinned is None:
        raise FreezeError("no deployment audit freeze is active")
    if _branch(repo) != "main":
        raise FreezeError("the operator checkout is not attached to main")
    head = _oid(repo, "HEAD")
    main = _oid(repo, PROTECTED_REF)
    if pinned != head or pinned != main:
        raise FreezeError("freeze ref, main, and operator HEAD differ")
    if expected_sha is not None and pinned != expected_sha:
        raise FreezeError("active freeze does not equal --expected-sha")
    _require_clean(repo)
    _validate_hook_closure(repo, pinned)
    if receipt_path is not None:
        receipt = _load_receipt(receipt_path)
        if receipt["commit"] != pinned or receipt["tree"] != _one_line(repo, ("show", "-s", "--format=%T", pinned)):
            raise FreezeError("freeze receipt does not match the active pin")
    print("deployment_audit_freeze=PASS")
    print("pinned_sha={}".format(pinned))


def verify_receipt(repo: Path, receipt_path: Path) -> None:
    receipt = _load_receipt(receipt_path)
    head = _oid(repo, "HEAD")
    if head != receipt["commit"]:
        raise FreezeError("audit checkout HEAD does not match the freeze receipt")
    if _one_line(repo, ("show", "-s", "--format=%T", head)) != receipt["tree"]:
        raise FreezeError("audit checkout tree does not match the freeze receipt")
    _require_clean(repo)
    print("deployment_audit_freeze_receipt=PASS")
    print("pinned_sha={}".format(head))


def release(repo: Path, receipt_path: Path, verdict_path: Path) -> None:
    receipt = _load_receipt(receipt_path)
    pinned = _optional_ref(repo, FREEZE_REF)
    if pinned is None or pinned != receipt["commit"]:
        raise FreezeError("active freeze does not match the receipt")
    pinned_commit = str(receipt["commit"])
    if _oid(repo, PROTECTED_REF) != pinned_commit:
        raise FreezeError("main no longer matches the freeze receipt")
    _validate_hook_closure(repo, pinned_commit)
    report, _ = _stable_file(verdict_path)
    try:
        text = report.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FreezeError("verdict report is not UTF-8") from exc
    matches = VERDICT.findall(text)
    if len(matches) != 1:
        raise FreezeError("verdict report must contain exactly one anchored deployment verdict")
    commit_patterns = (
        re.compile(r"(?m)^Audited commit: {}$".format(re.escape(pinned_commit))),
        re.compile(r"(?m)^Pinned audit SHA: {}$".format(re.escape(pinned_commit))),
    )
    tree_patterns = (
        re.compile(r"(?m)^Audited tree: {}$".format(re.escape(receipt["tree"]))),
        re.compile(r"(?m)^Pinned audit tree: {}$".format(re.escape(receipt["tree"]))),
    )
    if not any(pattern.search(text) for pattern in commit_patterns):
        raise FreezeError("verdict report does not name the pinned commit on an anchored line")
    if not any(pattern.search(text) for pattern in tree_patterns):
        raise FreezeError("verdict report does not name the pinned tree on an anchored line")
    _git(repo, ("update-ref", "-d", FREEZE_REF, pinned))
    _remove_reference_hook(repo, pinned_commit)
    print("deployment_audit_freeze=RELEASED")
    print("verdict={}".format(matches[0]))
    print("pinned_sha={}".format(pinned_commit))
    print("verdict_sha256={}".format(hashlib.sha256(report).hexdigest()))


def hook(repo: Path, state: str) -> None:
    if state not in {"prepared", "preparing"}:
        return
    updates = sys.stdin.buffer.read(1024 * 1024 + 1)
    if len(updates) > 1024 * 1024:
        raise FreezeError("reference transaction input exceeds the bound")
    pinned = _optional_ref(repo, FREEZE_REF)
    if pinned is None:
        return
    for raw_line in updates.splitlines():
        try:
            old, new, reference = raw_line.decode("ascii").split(" ", 2)
        except (UnicodeDecodeError, ValueError) as exc:
            raise FreezeError("reference transaction input is malformed") from exc
        if not HEX_OID.fullmatch(old) or not HEX_OID.fullmatch(new):
            raise FreezeError("reference transaction object ID is malformed")
        if reference == PROTECTED_REF and new != pinned:
            raise FreezeError("main is frozen at {} until the deployment audit verdict lands".format(pinned))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("pin", "check", "verify-receipt", "release", "hook"):
        child = subparsers.add_parser(name)
        child.add_argument("--repo", required=True)
        if name in {"pin", "check", "verify-receipt", "release"}:
            child.add_argument("--receipt", required=name != "check")
        if name == "check":
            child.add_argument("--expected-sha")
        if name == "release":
            child.add_argument("--verdict", required=True)
        if name == "hook":
            child.add_argument("--state", required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        _reject_inherited_git_config()
        repo = _repo(arguments.repo)
        if arguments.command == "pin":
            pin(repo, Path(arguments.receipt))
        elif arguments.command == "check":
            if arguments.expected_sha is not None and not HEX_OID.fullmatch(arguments.expected_sha):
                raise FreezeError("--expected-sha must be a full lowercase object ID")
            check_operator(
                repo,
                expected_sha=arguments.expected_sha,
                receipt_path=Path(arguments.receipt) if arguments.receipt else None,
            )
        elif arguments.command == "verify-receipt":
            verify_receipt(repo, Path(arguments.receipt))
        elif arguments.command == "release":
            release(repo, Path(arguments.receipt), Path(arguments.verdict))
        elif arguments.command == "hook":
            hook(repo, arguments.state)
        else:
            raise FreezeError("unknown command")
    except (FreezeError, OSError, subprocess.SubprocessError) as exc:
        print("deployment audit freeze refused: {}".format(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
