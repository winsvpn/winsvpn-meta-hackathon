#!/usr/bin/env python3
"""Hostile direct tests for the isolated extension build-attempt witness."""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import types
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent
EXTENSION = TOOLS.parent
BUILD = EXTENSION / "build.py"
SWITCH = "--wins-release-dependency-build-attempt-v2"
CONTRACT = "winsvpn-witnessed-build-attempt-v2"
NONCE = "4f" * 32
OUTPUT = "wins-vpn-companion-chrome.zip"
ENVIRONMENT = {
    "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT": CONTRACT,
    "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE": NONCE,
    "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT": OUTPUT,
    "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_PLATFORM": "extension",
}


def _load_builder():
    sys.path.insert(0, str(TOOLS))
    spec = importlib.util.spec_from_file_location(
        "extension_build_release_dependency_witness", BUILD
    )
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    return builder


BUILDER = _load_builder()


def _isolated_environment(attempt: Path, changes: dict[str, str | None]) -> dict[str, str]:
    environment = {
        "HOME": str(attempt),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "TMPDIR": str(attempt),
        **ENVIRONMENT,
    }
    runtime_prefix = Path(sys.base_prefix)
    if (
        runtime_prefix.parent.name == "Versions"
        and runtime_prefix.parent.parent.name == "Python.framework"
    ):
        environment["DYLD_FRAMEWORK_PATH"] = str(
            runtime_prefix.parent.parent.parent
        )
        environment["DYLD_LIBRARY_PATH"] = str(runtime_prefix / "lib")
    for name, value in changes.items():
        if value is None:
            environment.pop(name, None)
        else:
            environment[name] = value
    return environment


def _prepare_attempt(tmp_path: Path) -> tuple[Path, Path]:
    attempt = tmp_path / "attempt"
    attempt.mkdir(mode=0o700)
    attempt.chmod(0o700)
    producer = attempt / ".producer"
    shutil.copyfile(BUILD, producer)
    output = attempt / OUTPUT
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    output.chmod(0o600)
    return attempt, output


def _run(
    attempt: Path,
    *,
    arguments: list[str] | None = None,
    changes: dict[str, str | None] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            sys._base_executable,
            "-I",
            "-S",
            str(attempt / ".producer"),
            *(arguments if arguments is not None else [SWITCH]),
        ],
        cwd=attempt,
        env=_isolated_environment(attempt, changes or {}),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _assert_silent_failure(result: subprocess.CompletedProcess[bytes]) -> None:
    assert result.returncode != 0
    assert result.stdout == b""
    assert result.stderr == b""


def test_exact_isolated_interface_populates_only_precreated_inode(tmp_path: Path) -> None:
    attempt, output = _prepare_attempt(tmp_path)
    before = output.stat()

    result = _run(attempt)

    assert result.returncode == 0
    assert result.stdout == b""
    assert result.stderr == b""
    after = output.stat()
    assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
    assert after.st_nlink == 1
    assert stat.S_IMODE(after.st_mode) == 0o600
    assert sorted(path.name for path in attempt.iterdir()) == [".producer", OUTPUT]
    assert json.loads(output.read_text(encoding="ascii")) == {
        "contract": CONTRACT,
        "marker": "WINS_RELEASE_DEPENDENCY_NATIVE_BUILD_WITNESS_V1",
        "native_host": "native-extension-build-host",
        "nonce": NONCE,
        "platform": "extension",
        "runtime": "isolated-python",
    }


@pytest.mark.parametrize(
    ("name", "value"),
    (
        ("WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT", None),
        ("WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT", "wrong-contract"),
        ("WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE", None),
        ("WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE", "4F" * 32),
        ("WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE", "4f" * 31),
        ("WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT", None),
        ("WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT", "../artifact.zip"),
        ("WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT", "/tmp/artifact.zip"),
        ("WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT", "child/artifact.zip"),
        ("WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT", "child\\artifact.zip"),
        ("WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT", ".artifact.zip"),
        ("WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_PLATFORM", None),
        ("WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_PLATFORM", "chrome"),
        ("WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_EXTRA", "hostile"),
        ("wins_release_dependency_build_attempt_nonce", NONCE),
    ),
)
def test_invalid_missing_extra_duplicate_or_unsafe_inputs_are_silent(
    tmp_path: Path, name: str, value: str | None
) -> None:
    attempt, output = _prepare_attempt(tmp_path)

    result = _run(attempt, changes={name: value})

    _assert_silent_failure(result)
    assert output.read_bytes() == b""


@pytest.mark.parametrize(
    "arguments",
    (
        [SWITCH, SWITCH],
        [SWITCH, "extra"],
        ["extra", SWITCH],
    ),
)
def test_duplicate_or_extra_switch_arguments_are_silent(
    tmp_path: Path, arguments: list[str]
) -> None:
    attempt, output = _prepare_attempt(tmp_path)

    result = _run(attempt, arguments=arguments)

    _assert_silent_failure(result)
    assert output.read_bytes() == b""


@pytest.mark.parametrize(
    "mutation",
    ("missing", "symlink", "hardlink", "nonempty", "mode", "directory"),
)
def test_hostile_output_inode_is_rejected_without_substitution(
    tmp_path: Path, mutation: str
) -> None:
    attempt, output = _prepare_attempt(tmp_path)
    if mutation == "missing":
        output.unlink()
    elif mutation == "symlink":
        output.unlink()
        output.symlink_to("attacker")
    elif mutation == "hardlink":
        os.link(output, attempt / "attacker")
    elif mutation == "nonempty":
        output.write_bytes(b"attacker")
    elif mutation == "mode":
        output.chmod(0o644)
    elif mutation == "directory":
        output.unlink()
        output.mkdir()

    result = _run(attempt)

    _assert_silent_failure(result)
    if mutation in {"hardlink", "nonempty"}:
        assert output.read_bytes() in {b"", b"attacker"}


def test_path_swap_between_validation_and_open_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempt, output = _prepare_attempt(tmp_path)
    displaced = attempt / "displaced"
    real_open = os.open

    def substitute(path, flags, mode=0o777, *, dir_fd=None):
        if path == OUTPUT and dir_fd is not None:
            output.rename(displaced)
            attacker = real_open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(attacker)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(BUILDER.os, "open", substitute)
    monkeypatch.setattr(
        BUILDER,
        "sys",
        types.SimpleNamespace(flags=types.SimpleNamespace(isolated=1, no_site=1)),
    )
    monkeypatch.chdir(attempt)
    environment = dict(ENVIRONMENT)

    result = BUILDER._run_release_dependency_build_attempt(
        [str(attempt / ".producer"), SWITCH], environment
    )

    assert result != 0
    assert displaced.read_bytes() == b""
    assert output.read_bytes() == b""


def test_source_contains_exact_reviewed_release_freeze_tokens() -> None:
    payload = BUILD.read_bytes()
    required = (
        b"WINS_RELEASE_DEPENDENCY_NATIVE_BUILD_WITNESS_V1",
        b"WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_V2",
        b"--wins-release-dependency-build-attempt-v2",
        b"winsvpn-witnessed-build-attempt-v2",
        b"WINS_RELEASE_DEPENDENCY_NATIVE_HOST=native-extension-build-host",
        b"WINS_RELEASE_DEPENDENCY_NATIVE_RUNTIME=isolated-python",
        *(name.encode("ascii") for name in ENVIRONMENT),
    )
    for token in required:
        assert token in payload
