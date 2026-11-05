from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL = REPO_ROOT / "tools/deployment_audit_freeze.py"
HOOK = REPO_ROOT / ".githooks/reference-transaction"
IPSCRUB = REPO_ROOT / "tools/ipscrub"
FREEZE_REF = "refs/winsvpn/deployment-audit-freeze"


def _git(repo: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(repo), *arguments],
        check=check,
        text=True,
        capture_output=True,
    )


def _tool(repo: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(repo / "tools/deployment_audit_freeze.py"), *arguments],
        cwd=repo,
        check=False,
        text=True,
        capture_output=True,
    )


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-b", "main")
    (root / "tools").mkdir()
    (root / ".githooks").mkdir()
    shutil.copy2(TOOL, root / "tools/deployment_audit_freeze.py")
    shutil.copy2(HOOK, root / ".githooks/reference-transaction")
    shutil.copytree(IPSCRUB, root / "tools/ipscrub")
    (root / "tracked.txt").write_text("frozen bytes\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(
        root,
        "-c",
        "user.name=Freeze Test",
        "-c",
        "user.email=freeze@example.invalid",
        "commit",
        "-m",
        "test freeze source",
    )
    installed = subprocess.run(
        ["/bin/sh", str(root / "tools/ipscrub/install-hooks.sh")],
        cwd=root,
        check=False,
        text=True,
        capture_output=True,
    )
    assert installed.returncode == 0, installed.stderr
    return root


def _pin(repo: Path, receipt: Path) -> subprocess.CompletedProcess[str]:
    return _tool(repo, "pin", "--repo", str(repo), "--receipt", str(receipt))


def _detached_commit(repo: Path) -> str:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_NAME": "Freeze Test",
            "GIT_AUTHOR_EMAIL": "freeze@example.invalid",
            "GIT_COMMITTER_NAME": "Freeze Test",
            "GIT_COMMITTER_EMAIL": "freeze@example.invalid",
        }
    )
    result = subprocess.run(
        ["/usr/bin/git", "-C", str(repo), "commit-tree", "HEAD^{tree}", "-p", "HEAD"],
        input="attempted advancement\n",
        env=environment,
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout.strip()


def test_pin_blocks_main_until_exact_anchored_verdict(repo: Path, tmp_path: Path) -> None:
    receipt = tmp_path / "freeze.json"
    result = _pin(repo, receipt)
    assert result.returncode == 0, result.stderr
    payload = json.loads(receipt.read_text(encoding="ascii"))
    pinned = _git(repo, "rev-parse", "HEAD").stdout.strip()
    tree = _git(repo, "show", "-s", "--format=%T", "HEAD").stdout.strip()
    assert payload["commit"] == pinned
    assert payload["tree"] == tree
    assert stat.S_IMODE(receipt.stat().st_mode) == 0o600
    assert _git(repo, "config", "--local", "--get", "core.hooksPath", check=False).returncode == 1
    installed_reference = Path(_git(repo, "rev-parse", "--git-common-dir").stdout.strip()) / "hooks/reference-transaction"
    if not installed_reference.is_absolute():
        installed_reference = repo / installed_reference
    installed_prepush = installed_reference.with_name("pre-push")
    assert installed_reference.read_bytes() == (repo / ".githooks/reference-transaction").read_bytes()
    assert installed_prepush.read_bytes() == (repo / "tools/ipscrub/pre-push").read_bytes()

    candidate = _detached_commit(repo)
    refused = _git(repo, "update-ref", "refs/heads/main", candidate, pinned, check=False)
    assert refused.returncode != 0
    assert "main is frozen" in refused.stderr
    assert _git(repo, "rev-parse", "refs/heads/main").stdout.strip() == pinned

    vague = tmp_path / "vague-verdict.md"
    vague.write_text(
        f"VERDICT: DEPLOYMENT GO is not warranted\nAudited commit: {pinned}\nAudited tree: {tree}\n",
        encoding="utf-8",
    )
    vague.chmod(0o600)
    vague_result = _tool(
        repo,
        "release",
        "--repo",
        str(repo),
        "--receipt",
        str(receipt),
        "--verdict",
        str(vague),
    )
    assert vague_result.returncode != 0

    wrong = tmp_path / "wrong-verdict.md"
    wrong.write_text(
        f"VERDICT: DEPLOYMENT NO-GO\nAudited commit: {'0' * 40}\nAudited tree: {tree}\n",
        encoding="utf-8",
    )
    wrong.chmod(0o600)
    wrong_result = _tool(
        repo,
        "release",
        "--repo",
        str(repo),
        "--receipt",
        str(receipt),
        "--verdict",
        str(wrong),
    )
    assert wrong_result.returncode != 0

    verdict = tmp_path / "verdict.md"
    verdict.write_text(
        f"VERDICT: DEPLOYMENT NO-GO\nAudited commit: {pinned}\nAudited tree: {tree}\n",
        encoding="utf-8",
    )
    verdict.chmod(0o600)
    released = _tool(
        repo,
        "release",
        "--repo",
        str(repo),
        "--receipt",
        str(receipt),
        "--verdict",
        str(verdict),
    )
    assert released.returncode == 0, released.stderr
    assert _git(repo, "rev-parse", "--verify", FREEZE_REF, check=False).returncode != 0
    assert _git(repo, "config", "--local", "--get", "core.hooksPath", check=False).returncode == 1
    assert not installed_reference.exists()
    assert installed_prepush.read_bytes() == (repo / "tools/ipscrub/pre-push").read_bytes()
    advanced = _git(repo, "update-ref", "refs/heads/main", candidate, pinned, check=False)
    assert advanced.returncode == 0, advanced.stderr


def test_pin_refuses_dirty_checkout_without_partial_state(repo: Path, tmp_path: Path) -> None:
    (repo / "tracked.txt").write_text("dirty\n", encoding="utf-8")
    receipt = tmp_path / "dirty-freeze.json"
    result = _pin(repo, receipt)
    assert result.returncode != 0
    assert not receipt.exists()
    assert _git(repo, "rev-parse", "--verify", FREEZE_REF, check=False).returncode != 0
    assert _git(repo, "config", "--local", "--get", "core.hooksPath", check=False).returncode == 1


def test_detached_audit_clone_verifies_external_receipt(repo: Path, tmp_path: Path) -> None:
    receipt = tmp_path / "clone-freeze.json"
    assert _pin(repo, receipt).returncode == 0
    clone = tmp_path / "audit-clone"
    _git(tmp_path, "clone", "--no-local", str(repo), str(clone))
    _git(clone, "checkout", "--detach", "HEAD")
    result = _tool(
        clone,
        "verify-receipt",
        "--repo",
        str(clone),
        "--receipt",
        str(receipt),
    )
    assert result.returncode == 0, result.stderr
    assert "deployment_audit_freeze_receipt=PASS" in result.stdout


def test_pin_refuses_conflicting_hook_configuration(repo: Path, tmp_path: Path) -> None:
    _git(repo, "config", "--local", "core.hooksPath", "/tmp/unrelated-hooks")
    result = _pin(repo, tmp_path / "conflict-freeze.json")
    assert result.returncode != 0
    assert "core.hooksPath must be unset" in result.stderr


def test_pin_refuses_effective_environment_hook_override(repo: Path, tmp_path: Path) -> None:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": "/dev/null",
        }
    )
    result = subprocess.run(
        [
            sys.executable,
            str(repo / "tools/deployment_audit_freeze.py"),
            "pin",
            "--repo",
            str(repo),
            "--receipt",
            str(tmp_path / "environment-override-freeze.json"),
        ],
        cwd=repo,
        env=environment,
        check=False,
        text=True,
        capture_output=True,
    )
    assert result.returncode != 0
    assert "inherited Git config overrides are forbidden" in result.stderr
    assert _git(repo, "rev-parse", "--verify", FREEZE_REF, check=False).returncode != 0


def test_freeze_blocks_main_from_linked_worktree_and_preserves_ipscrub(repo: Path, tmp_path: Path) -> None:
    receipt = tmp_path / "linked-freeze.json"
    prepush = repo / ".git/hooks/pre-push"
    before = prepush.read_bytes()
    assert _pin(repo, receipt).returncode == 0
    prepush_run = _git(repo, "hook", "run", "pre-push", "--", "origin", "unused")
    assert prepush_run.returncode == 0, prepush_run.stderr
    assert "ipscrub: scanning the push delta" in prepush_run.stderr
    linked = tmp_path / "linked"
    _git(repo, "worktree", "add", "-b", "linked-repair", str(linked))
    pinned = _git(repo, "rev-parse", "refs/heads/main").stdout.strip()
    candidate = _detached_commit(linked)
    installed_reference = prepush.with_name("reference-transaction")
    no_op = subprocess.run(
        [str(installed_reference), "prepared"],
        cwd=repo,
        input=f"{pinned} {pinned} refs/heads/main\n",
        check=False,
        text=True,
        capture_output=True,
    )
    assert no_op.returncode == 0, no_op.stderr
    for terminal_state in ("committed", "aborted"):
        ignored = subprocess.run(
            [str(installed_reference), terminal_state],
            cwd=repo,
            input=f"{pinned} {candidate} refs/heads/main\n",
            check=False,
            text=True,
            capture_output=True,
        )
        assert ignored.returncode == 0, ignored.stderr
    refused = _git(linked, "update-ref", "refs/heads/main", candidate, pinned, check=False)
    assert refused.returncode != 0
    assert "main is frozen" in refused.stderr
    assert prepush.read_bytes() == before


def test_freeze_keeps_ipscrub_behaviorally_blocking_forbidden_push(repo: Path, tmp_path: Path) -> None:
    receipt = tmp_path / "behavioral-freeze.json"
    assert _pin(repo, receipt).returncode == 0
    linked = tmp_path / "forbidden-push"
    _git(repo, "worktree", "add", "-b", "forbidden-push", str(linked))
    unapproved_host = ".".join(("5", "6", "7", "8"))
    (linked / "forbidden.txt").write_text(f"node {unapproved_host}\n", encoding="ascii")
    _git(linked, "add", "forbidden.txt")
    _git(
        linked,
        "-c",
        "user.name=Freeze Test",
        "-c",
        "user.email=freeze@example.invalid",
        "commit",
        "-m",
        "hostile forbidden push candidate",
    )
    tip = _git(linked, "rev-parse", "HEAD").stdout.strip()
    attempted = subprocess.run(
        [
            "/usr/bin/git",
            "-C",
            str(linked),
            "hook",
            "run",
            "pre-push",
            "--",
            "origin",
            "unused",
        ],
        input=f"refs/heads/forbidden-push {tip} refs/heads/forbidden-push {'0' * len(tip)}\n",
        check=False,
        text=True,
        capture_output=True,
    )
    combined = attempted.stdout + attempted.stderr
    assert attempted.returncode == 1
    assert "PUSH BLOCKED" in combined
    assert _git(repo, "rev-parse", "refs/heads/main").stdout.strip() == json.loads(
        receipt.read_text(encoding="ascii")
    )["commit"]


def test_pin_refuses_missing_or_modified_ipscrub_hook(repo: Path, tmp_path: Path) -> None:
    prepush = repo / ".git/hooks/pre-push"
    prepush.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    prepush.chmod(0o755)
    result = _pin(repo, tmp_path / "unsafe-freeze.json")
    assert result.returncode != 0
    assert "ipscrub pre-push hook is missing or stale" in result.stderr
    assert _git(repo, "rev-parse", "--verify", FREEZE_REF, check=False).returncode != 0
