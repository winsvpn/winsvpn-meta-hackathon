#!/usr/bin/env python3
"""Run the authenticated dependency-freeze worker from another tool.

tools/release_dependency_freeze.py refuses production authority whenever it is
imported, so a tool that needs a verified build receipt cannot call
verify_build_receipt() in process. This client executes the reviewed parent,
tools/run_release_dependency_freeze.sh, as a child process, requires the
authenticated result envelope, and returns the parsed JSON object. It adds no
authority of its own: a refusal by the worker is a refusal here.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
import subprocess

import release_dependency_freeze as freeze
from release_dependency_freeze import DependencyFreezeError

PARENT_RELATIVE = "tools/run_release_dependency_freeze.sh"
REVIEWED_WORKER_SHA256 = {
    "tools/run_release_dependency_freeze.sh": "8fcf425d2f8edbe384e5e964f3491aeb28ec440ba6b007c692bb1f0535da169b",
    "tools/release_dependency_freeze.py": "b70e87144c7f30c7eac7b6ffeb6a4c7e5bc017c62d114e2d78f58c6c5427f609",
    "tools/toolchain-pins.json": "3615ddbd9cb8602c610e6c3bfed4804749b3d5de29f7c7436434f0da5c28e365",
}
AUTHORITY_KIND = "winsvpn-release-dependency-freeze-authoritative-v1"
BASH = "/bin/bash"
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_DIAGNOSTIC_CHARS = 400
TIMEOUT_SECONDS = 900


class FreezeClientError(DependencyFreezeError):
    """The worker refused, failed, timed out or answered outside its contract."""


def _parent(repo: pathlib.Path) -> pathlib.Path:
    parent = repo / PARENT_RELATIVE
    try:
        info = os.lstat(parent)
    except OSError as exc:
        raise FreezeClientError("dependency-freeze parent is unavailable.") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise FreezeClientError("dependency-freeze parent is not a regular file.")
    return parent


def run_worker(repo: pathlib.Path | str, arguments: list[str]) -> dict[str, object]:
    """Execute one worker command and return its authenticated JSON result."""

    result = _run_authenticated(repo, arguments)
    if (
        result.get("ok") is not True
        or result.get("fixture_only") is not False
        or result.get("production_pass_allowed") is not True
    ):
        raise FreezeClientError("dependency-freeze worker result lacks its authority envelope.")
    return result


# begin-build and finish-build return the anchored record they wrote, not a
# verification verdict, so their results carry no ok/fixture_only fields. The
# authenticated envelope, the build-witness phase and the record contract are
# required instead; a finished receipt is then checked by verify-receipt
# through run_worker.
BUILD_STEP_WITNESS = {
    "begin-build": ("PENDING_NATIVE_PRODUCER", "winsvpn-build-begin-v1"),
    "finish-build": ("NATIVE_WITNESSED", "winsvpn-build-receipt-v1"),
}


def run_build_step(repo: pathlib.Path | str, arguments: list[str]) -> dict[str, object]:
    """Execute begin-build or finish-build and return the authenticated record."""

    expected = BUILD_STEP_WITNESS.get(arguments[0] if arguments else "")
    if expected is None:
        raise FreezeClientError("dependency-freeze build step is not begin-build or finish-build.")
    result = _run_authenticated(repo, arguments)
    if (
        result.get("production_build_witness") != expected[0]
        or result.get("contract") != expected[1]
        or "ok" in result
        or "fixture_only" in result
    ):
        raise FreezeClientError("dependency-freeze build step result is outside its contract.")
    return result


def _run_authenticated(repo: pathlib.Path | str, arguments: list[str]) -> dict[str, object]:
    if not arguments or any(type(item) is not str or "\0" in item for item in arguments):
        raise FreezeClientError("dependency-freeze arguments are invalid.")
    repo_path = pathlib.Path(repo).resolve(strict=True)
    parent = _parent(repo_path)
    held_inputs = []
    pins_payload = None
    try:
        for relative, expected in REVIEWED_WORKER_SHA256.items():
            held = freeze._hold_repo_regular_file(
                repo_path, repo_path / relative, freeze._allowed_owners(repo_path),
                label="dependency-freeze launch input",
            )
            held_inputs.append(held)
            if hashlib.sha256(held.payload).hexdigest() != expected:
                raise FreezeClientError("dependency-freeze launch input is not reviewed.")
            if relative == "tools/toolchain-pins.json":
                pins_payload = held.payload
        if pins_payload is None:
            raise FreezeClientError("dependency-freeze release Python pins are missing.")
        executable_path, executable_digest = freeze._pinned_release_python(pins_payload)
        executable = freeze._hold_repo_regular_file(
            pathlib.Path("/"), executable_path,
            freeze._allowed_owners(repo_path) | frozenset({0}),
            label="dependency-freeze release Python executable",
        )
        held_inputs.append(executable)
        if (
            not executable.info.st_mode & stat.S_IXUSR
            or hashlib.sha256(executable.payload).hexdigest() != executable_digest
        ):
            raise FreezeClientError("dependency-freeze release Python executable is not reviewed.")
        for held in held_inputs:
            freeze._rebind_held_regular_file(held)
        try:
            completed = subprocess.run(
                [BASH, str(parent), arguments[0], "--repo", str(repo_path), *arguments[1:]],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"HOME": "/private/tmp", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                timeout=TIMEOUT_SECONDS,
                check=False,
            )
        finally:
            for held in held_inputs:
                freeze._rebind_held_regular_file(held)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FreezeClientError(f"dependency-freeze worker did not run: {exc}") from exc
    finally:
        for held in reversed(held_inputs):
            freeze._close_held_regular_file(held)
    if completed.returncode != 0:
        detail = " ".join(completed.stderr.decode("utf-8", "replace").split())
        raise FreezeClientError(
            f"dependency-freeze worker refused: {detail[:MAX_DIAGNOSTIC_CHARS] or 'no diagnostic'}"
        )
    if len(completed.stdout) > MAX_OUTPUT_BYTES:
        raise FreezeClientError("dependency-freeze worker output is too large.")
    try:
        result = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise FreezeClientError("dependency-freeze worker output is not JSON.") from exc
    if (
        type(result) is not dict
        or result.get("authority_kind") != AUTHORITY_KIND
        or result.get("production_authority_authenticated") is not True
        or result.get("publication_authorized") is not False
        or result.get("command") != arguments[0]
    ):
        raise FreezeClientError("dependency-freeze worker result lacks its authority envelope.")
    return result


def verify_build_receipt(
    repo: pathlib.Path | str,
    index: pathlib.Path | str,
    platform: str,
    receipt: pathlib.Path | str,
    artifact: pathlib.Path | str | None = None,
    secret_inventory_path: str | None = None,
) -> dict[str, object]:
    """Drop-in for release_dependency_freeze.verify_build_receipt().

    A remote Windows receipt is verified by the worker running the exact secret scan on
    the installer, so its caller names the authenticated inventory by path. The path
    is the only thing that travels; no scan result is ever an argument."""

    if artifact is None:
        raise FreezeClientError("verify-receipt requires the exact artifact.")
    return run_worker(
        repo,
        [
            "verify-receipt",
            "--index", str(index),
            "--platform", platform,
            "--receipt", str(receipt),
            "--artifact", str(artifact),
        ]
        + ([] if secret_inventory_path is None else ["--secret-inventory-path", secret_inventory_path]),
    )
