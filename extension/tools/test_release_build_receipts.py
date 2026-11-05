#!/usr/bin/env python3
"""extension/build.py --release-build-receipts: the producer-attested darwin path.

The dependency freeze maps ("extension", "darwin") to extension/build.py as a
producer-attested producer. These tests lock the producer side of that
contract: begin-build before any store zip exists, zips written outside the
frozen extension root, finish-build with the exact producer, toolchain and
target, verify-receipt through tools/release_freeze_client.py, and refusal of
every mode that cannot produce three fresh store zips.
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import types
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent
EXTENSION = TOOLS.parent
ROOT = EXTENSION.parent
BUILD = EXTENSION / "build.py"
FLAG = "--release-build-receipts"
INDEX = ".artifacts/release-inputs-test/RELEASE_INPUT_INDEX.json"
AUTHORITY = "winsvpn-release-dependency-freeze-authoritative-v1"


def _load_builder():
    sys.path.insert(0, str(TOOLS))
    spec = importlib.util.spec_from_file_location(
        "extension_build_release_build_receipts", BUILD
    )
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    return builder


def _load_freeze():
    spec = importlib.util.spec_from_file_location(
        "release_dependency_freeze_for_extension_tests",
        ROOT / "tools" / "release_dependency_freeze.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _envelope(command: str, **extra: object) -> bytes:
    record = {
        "authority_kind": AUTHORITY,
        "command": command,
        "production_authority_authenticated": True,
        "production_build_witness": "NOT_APPLICABLE",
        "publication_authorized": False,
        **extra,
    }
    return (json.dumps(record) + "\n").encode("utf-8")


def _run(argv: list[str], *, bytecode: bool = False) -> subprocess.CompletedProcess:
    flags = ["-I"] if bytecode else ["-I", "-B"]
    return subprocess.run(
        [sys.executable, *flags, str(BUILD), *argv],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.mark.parametrize(
    "extra",
    (
        [FLAG, INDEX, "--no-zip"],
        [FLAG, INDEX, "--verify", "chrome", "extension/dist/wins-vpn-companion-chrome.zip"],
        [FLAG, INDEX, "chrome"],
        [FLAG, INDEX, "chrome", "edge", "firefox", "safari"],
        ["--receipt-dir", ".artifacts/release-inputs-test/receipts"],
    ),
)
def test_flag_refuses_modes_without_three_fresh_store_zips(extra):
    completed = _run(extra)
    assert completed.returncode == 2
    assert "gate 1/4" not in completed.stdout
    assert "build:" in completed.stderr


def test_release_mode_requires_isolated_python_without_bytecode():
    completed = _run([FLAG, INDEX], bytecode=True)
    assert completed.returncode == 2
    assert "must run as python3 -I -B" in completed.stderr
    assert "gate 1/4" not in completed.stdout


def test_index_and_receipt_directory_stay_under_repository_artifacts(tmp_path):
    builder = _load_builder()
    with pytest.raises(builder.ReleaseReceiptError, match="inside the repository"):
        builder.release_artifacts_path(str(tmp_path / "INDEX.json"), "index", must_exist=True)
    with pytest.raises(builder.ReleaseReceiptError, match="under repository .artifacts"):
        builder.release_artifacts_path("pubspec.yaml", "index", must_exist=True)
    with pytest.raises(builder.ReleaseReceiptError, match="under repository .artifacts"):
        builder.release_artifacts_path(".artifacts", "receipts", must_exist=False)
    with pytest.raises(builder.ReleaseReceiptError, match="does not exist"):
        builder.release_artifacts_path(
            ".artifacts/release-inputs-absent-r2/RELEASE_INPUT_INDEX.json",
            "index",
            must_exist=True,
        )
    assert builder.release_artifacts_path(
        ".artifacts/release-inputs-absent-r2/receipts", "receipts", must_exist=False
    ) == ROOT / ".artifacts" / "release-inputs-absent-r2" / "receipts"
    # finish-build re-parses begin receipt paths with a narrower character set
    # than begin-build accepts; refuse such a directory before any begin.
    for unsafe in (
        ".artifacts/release-inputs-1.0.16+33/extension-build",
        ".artifacts/receipts with space",
        ".artifacts/-leading-dash",
    ):
        with pytest.raises(builder.ReleaseReceiptError, match="may use only letters"):
            builder.release_artifacts_path(unsafe, "receipts", must_exist=False)
    assert builder.RELEASE_RECEIPT_ROOT == ROOT / ".artifacts" / "release-build-receipts" / "extension"
    assert builder.RELEASE_RECEIPT_PATH.fullmatch(
        builder.RELEASE_RECEIPT_ROOT.relative_to(ROOT).as_posix() + "/20261015T120000Z-4242"
    )


def test_release_index_symlink_and_existing_receipt_directory_are_refused(monkeypatch, tmp_path):
    builder = _load_builder()
    repo = tmp_path / "repo"
    (repo / ".artifacts" / "inputs").mkdir(parents=True)
    index = repo / ".artifacts" / "inputs" / "RELEASE_INPUT_INDEX.json"
    real = repo / ".artifacts" / "inputs" / "real.json"
    real.write_text("{}\n", encoding="utf-8")
    index.symlink_to(real)
    monkeypatch.setattr(builder, "REPO_ROOT", repo)
    with pytest.raises(builder.ReleaseReceiptError, match="regular non-symlink"):
        builder.release_artifacts_path(str(index), "index", must_exist=True)
    with pytest.raises(builder.ReleaseReceiptError, match="must be a new path"):
        builder.release_artifacts_path(
            str(repo / ".artifacts" / "inputs"), "receipts", must_exist=False
        )


def test_release_zips_land_outside_every_frozen_input_root():
    builder = _load_builder()
    freeze = _load_freeze()
    relative = builder.RELEASE_DIST.relative_to(ROOT)
    assert relative.parts[0] == "build"
    for browser in builder.RELEASE_RECEIPT_TARGETS:
        member = pathlib.PurePosixPath(relative.as_posix(), f"wins-vpn-companion-{browser}.zip")
        assert freeze._is_excluded(member)
        for roots in freeze.PLATFORM_ROOTS.values():
            assert not freeze._path_in_roots(member.as_posix(), roots)
        assert not freeze._path_in_roots(member.as_posix(), freeze.SHARED_ROOTS)


def test_release_producer_matches_the_freeze_host_table():
    builder = _load_builder()
    freeze = _load_freeze()
    assert freeze.PLATFORM_BUILD_PRODUCERS_BY_HOST[("extension", "darwin")] == (
        builder.RELEASE_RECEIPT_PRODUCER
    )
    assert ("extension", "darwin") in freeze.PRODUCER_ATTESTED_PLATFORM_HOSTS
    assert (ROOT / builder.RELEASE_RECEIPT_PRODUCER).resolve() == BUILD
    assert tuple(builder.RELEASE_RECEIPT_TARGETS.values()) == freeze.PLATFORM_ALLOWED_TARGETS[
        "extension"
    ]
    for browser, target in builder.RELEASE_RECEIPT_TARGETS.items():
        assert f"wins-vpn-companion-{browser}.zip" in freeze.EXTENSION_RELEASE_ARTIFACT_NAMES[target]
    assert "tools/release_freeze_client.py" in freeze.PLATFORM_PRODUCER_PATHS["extension"]
    assert builder.DEPENDENCY_FREEZE_PARENT == ROOT / "tools" / "run_release_dependency_freeze.sh"


def test_parent_calls_use_exact_argv_and_a_minimal_environment(monkeypatch, tmp_path):
    builder = _load_builder()
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return types.SimpleNamespace(returncode=0, stdout=_envelope(argv[2]), stderr=b"")

    monkeypatch.setattr(builder.subprocess, "run", fake_run)
    index = ROOT / INDEX
    receipt_dir = tmp_path / "receipts"
    begins = builder.begin_release_receipts(index, receipt_dir)
    assert receipt_dir.is_dir() and (receipt_dir.stat().st_mode & 0o777) == 0o700
    parent = str(ROOT / "tools" / "run_release_dependency_freeze.sh")
    assert [argv[:5] for argv, _ in calls] == [
        ["/bin/bash", parent, command, "--repo", str(ROOT)]
        for command in ("verify-index", "begin-build", "begin-build", "begin-build")
    ]
    assert calls[0][0][5:] == ["--index", str(index), "--platform", "extension"]
    for (argv, kwargs), browser in zip(calls[1:], ("chrome", "edge", "firefox")):
        assert argv[5:] == [
            "--index", str(index), "--platform", "extension",
            "--output", str(receipt_dir / f"EXTENSION_{browser.upper()}_BUILD_BEGIN.json"),
        ]
        assert kwargs["env"] == {
            "HOME": "/private/tmp", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin",
        }
        assert kwargs["stdin"] == subprocess.DEVNULL
    assert begins == {
        browser: receipt_dir / f"EXTENSION_{browser.upper()}_BUILD_BEGIN.json"
        for browser in ("chrome", "edge", "firefox")
    }

    calls.clear()
    outputs = {}
    for browser in ("chrome", "edge", "firefox"):
        artifact = tmp_path / f"wins-vpn-companion-{browser}.zip"
        artifact.write_bytes(browser.encode("ascii"))
        outputs[browser] = artifact
    verified = []

    def fake_verify(index_path, receipt, artifact):
        verified.append((index_path, receipt, artifact))
        import hashlib

        return {"ok": True, "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}

    monkeypatch.setattr(builder, "verify_release_receipt", fake_verify)
    receipts = builder.finish_release_receipts(index, receipt_dir, begins, outputs)
    name, version, revision = builder.release_toolchain()
    assert (name, version) == ("esbuild", "0.28.2")
    assert revision == builder.store_js_minifier.pin_for_host()["binary_sha256"]
    for (argv, _kwargs), browser in zip(calls, ("chrome", "edge", "firefox")):
        receipt = receipt_dir / f"EXTENSION_{browser.upper()}_BUILD_RECEIPT.json"
        assert argv[2] == "finish-build"
        assert argv[5:] == [
            "--index", str(index), "--platform", "extension",
            "--begin", str(begins[browser]), "--artifact", str(outputs[browser]),
            "--producer", "extension/build.py",
            "--toolchain-name", name, "--toolchain-version", version,
            "--toolchain-revision", revision,
            "--target", f"{browser}-zip", "--output", str(receipt),
        ]
        assert receipts[browser] == receipt
    assert verified == [
        (index, receipt_dir / f"EXTENSION_{b.upper()}_BUILD_RECEIPT.json", outputs[b])
        for b in ("chrome", "edge", "firefox")
    ]


def test_parent_refusals_and_bad_envelopes_refuse(monkeypatch):
    builder = _load_builder()
    responses = [
        types.SimpleNamespace(returncode=1, stdout=b"", stderr=b"RELEASE DEPENDENCY FREEZE: FAIL: x\n"),
        types.SimpleNamespace(returncode=0, stdout=b"not json", stderr=b""),
        types.SimpleNamespace(returncode=0, stdout=_envelope("begin-build"), stderr=b""),
        types.SimpleNamespace(
            returncode=0,
            stdout=_envelope("verify-index", publication_authorized=True),
            stderr=b"",
        ),
        types.SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"command": "verify-index", "ok": True}).encode(),
            stderr=b"",
        ),
    ]
    reasons = ("refused: RELEASE DEPENDENCY FREEZE: FAIL: x", "not JSON",
               "authority envelope", "authority envelope", "authority envelope")
    for response, reason in zip(responses, reasons):
        monkeypatch.setattr(builder.subprocess, "run", lambda argv, response=response, **kw: response)
        with pytest.raises(builder.ReleaseReceiptError, match=reason):
            builder.run_dependency_freeze("verify-index", "--index", INDEX, "--platform", "extension")


def test_finish_refuses_a_receipt_that_binds_other_bytes(monkeypatch, tmp_path):
    builder = _load_builder()
    monkeypatch.setattr(
        builder.subprocess,
        "run",
        lambda argv, **kw: types.SimpleNamespace(returncode=0, stdout=_envelope(argv[2]), stderr=b""),
    )
    monkeypatch.setattr(
        builder, "verify_release_receipt", lambda *a: {"ok": True, "artifact_sha256": "0" * 64}
    )
    outputs = {}
    for browser in ("chrome", "edge", "firefox"):
        outputs[browser] = tmp_path / f"wins-vpn-companion-{browser}.zip"
        outputs[browser].write_bytes(b"zip")
    begins = {b: tmp_path / f"{b}.json" for b in outputs}
    with pytest.raises(builder.ReleaseReceiptError, match="chrome-zip build receipt binds other bytes"):
        builder.finish_release_receipts(ROOT / INDEX, tmp_path, begins, outputs)


def test_main_begins_before_staging_and_finishes_after_hardening(monkeypatch, tmp_path):
    builder = _load_builder()
    events: list[str] = []
    repo = tmp_path / "repo"
    index = repo / ".artifacts" / "inputs" / "RELEASE_INPUT_INDEX.json"
    index.parent.mkdir(parents=True)
    index.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(builder, "REPO_ROOT", repo)
    monkeypatch.setattr(builder, "RELEASE_DIST", repo / "build" / "extension" / "dist")
    monkeypatch.setattr(
        builder,
        "RELEASE_RECEIPT_ROOT",
        repo / ".artifacts" / "release-build-receipts" / "extension",
    )
    monkeypatch.setattr(builder, "DIST", builder.DIST)
    monkeypatch.setitem(
        sys.modules,
        "dev_bridge",
        types.SimpleNamespace(
            RealHostUnavailable=RuntimeError,
            find_real_host=lambda require: ["host"],
            contract_check=lambda host: 0,
        ),
    )
    monkeypatch.setattr(builder.leakscan, "selftest", lambda verbose: True)
    monkeypatch.setattr(builder.checks, "selftest", lambda: True)
    monkeypatch.setattr(
        builder.subprocess,
        "run",
        lambda argv, **kw: types.SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    def begin(index_path, receipt_dir):
        events.append("begin")
        assert index_path == index
        assert receipt_dir.parent == builder.RELEASE_RECEIPT_ROOT
        return {b: receipt_dir / f"{b}.json" for b in ("chrome", "edge", "firefox")}

    def stage(target):
        events.append(f"stage:{target}")
        assert builder.DIST == builder.RELEASE_DIST
        return tmp_path / target

    def zip_package(pkg, target):
        events.append(f"zip:{target}")
        out = builder.DIST / f"wins-vpn-companion-{target}.zip"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(target.encode("ascii"))
        if target == "firefox":
            out.with_suffix(".xpi").write_bytes(target.encode("ascii"))
        return out

    monkeypatch.setattr(builder, "begin_release_receipts", begin)
    monkeypatch.setattr(builder, "stage", stage)
    monkeypatch.setattr(builder, "gate", lambda pkg, target, verbose: True)
    monkeypatch.setattr(builder, "zip_package", zip_package)
    monkeypatch.setattr(
        builder, "record_release_hardening_receipts", lambda outputs: events.append("hardening")
    )
    monkeypatch.setattr(
        builder,
        "verify_existing_package",
        lambda archive, target: events.append(f"verify:{target}"),
    )

    def finish(index_path, receipt_dir, begins, outputs):
        events.append("finish")
        assert sorted(outputs) == ["chrome", "edge", "firefox"]
        return {b: receipt_dir / f"{b}-receipt.json" for b in outputs}

    monkeypatch.setattr(builder, "finish_release_receipts", finish)
    monkeypatch.setattr(
        builder,
        "sys",
        types.SimpleNamespace(
            flags=types.SimpleNamespace(isolated=1, dont_write_bytecode=1),
            executable=sys.executable,
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
    )
    monkeypatch.setattr(sys, "argv", ["build.py", FLAG, str(index)])
    monkeypatch.delenv("PYTHONDONTWRITEBYTECODE", raising=False)
    assert builder.main() == 0
    assert events == [
        "begin",
        "stage:chrome", "zip:chrome",
        "stage:edge", "zip:edge",
        "stage:firefox", "zip:firefox",
        "hardening",
        "verify:chrome", "verify:edge", "verify:firefox",
        "finish",
    ]
    assert os.environ.get("PYTHONDONTWRITEBYTECODE") == "1"

    events.clear()
    assert builder.main() == 2
    assert events == []
