#!/usr/bin/env python3
"""The producer records the exact receipt the cross-store hardening gate verifies.

`release_obfuscation_contract.py --verify <target-id> <zip>` refuses unless
`.artifacts/private-release-symbols/extension/<browser>/<version>+<build>/
manifest.json` exists for that exact target. Android, Linux and Windows
producers record their own receipts; these tests lock the extension producer's
opt-in record step to the contract's layout and exact argv.
"""
from __future__ import annotations

import importlib.util
import stat
import subprocess
import sys
import types
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent
EXTENSION = TOOLS.parent
ROOT = EXTENSION.parent
BUILD = EXTENSION / "build.py"
FLAG = "--release-hardening-receipts"


def _load_builder():
    sys.path.insert(0, str(TOOLS))
    spec = importlib.util.spec_from_file_location(
        "extension_build_release_hardening_receipts", BUILD
    )
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    return builder


def _load_contract():
    sys.path.insert(0, str(ROOT / "tools"))
    import release_obfuscation_contract

    return release_obfuscation_contract


def test_receipt_directory_is_the_contract_layout():
    builder = _load_builder()
    contract = _load_contract()
    assert set(builder.TARGET_IDS) == {"chrome", "edge", "firefox"}
    for browser, target_id in builder.TARGET_IDS.items():
        layout = contract.exact_obfuscation_layout(target_id)
        assert layout["platform"] == browser
        assert builder.release_hardening_receipt_dir(browser).resolve() == Path(
            str(layout["symbols_dir"])
        ).resolve()
        assert (
            builder.release_hardening_receipt_dir(browser) / "manifest.json"
        ).resolve() == Path(str(layout["manifest"])).resolve()
    assert builder.RELEASE_HARDENING_CONTRACT == ROOT / "tools" / "release_obfuscation_contract.py"


def test_record_runs_exact_contract_argv_per_store_zip(tmp_path, monkeypatch):
    builder = _load_builder()
    monkeypatch.setattr(builder, "PRIVATE_EXTENSION_RECEIPT_ROOT", tmp_path / "extension")
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(builder.subprocess, "run", fake_run)
    outputs = {
        "chrome": builder.DIST / "wins-vpn-companion-chrome.zip",
        "edge": builder.DIST / "wins-vpn-companion-edge.zip",
        "firefox": builder.DIST / "wins-vpn-companion-firefox.zip",
        "safari": builder.DIST / "wins-vpn-proxy-safari.zip",
    }
    builder.record_release_hardening_receipts(outputs)

    assert [argv[3:5] for argv, _ in calls] == [
        ["--platform", "chrome"],
        ["--platform", "edge"],
        ["--platform", "firefox"],
    ]
    for (argv, kwargs), browser in zip(calls, ("chrome", "edge", "firefox")):
        receipt_dir = builder.release_hardening_receipt_dir(browser)
        assert receipt_dir.parent.parent == tmp_path / "extension"
        assert argv == [
            sys.executable,
            str(ROOT / "tools" / "release_obfuscation_contract.py"),
            "record",
            "--platform",
            browser,
            "--symbols-dir",
            str(receipt_dir),
            "--manifest",
            str(receipt_dir / "manifest.json"),
            "--artifact",
            f"extension/dist/wins-vpn-companion-{browser}.zip",
            "--target-id",
            builder.TARGET_IDS[browser],
        ]
        assert kwargs["cwd"] == ROOT
        assert receipt_dir.is_dir()
        assert stat.S_IMODE(receipt_dir.stat().st_mode) == 0o700


def test_refused_record_refuses_the_build(tmp_path, monkeypatch):
    builder = _load_builder()
    monkeypatch.setattr(builder, "PRIVATE_EXTENSION_RECEIPT_ROOT", tmp_path / "extension")
    monkeypatch.setattr(
        builder.subprocess,
        "run",
        lambda argv, **kwargs: types.SimpleNamespace(
            returncode=1, stdout="", stderr="RELEASE OBFUSCATION: FAIL: fixture\n"
        ),
    )
    with pytest.raises(RuntimeError, match="edge-extension-package release hardening receipt was refused"):
        builder.record_release_hardening_receipts(
            {"edge": builder.DIST / "wins-vpn-companion-edge.zip"}
        )


@pytest.mark.parametrize(
    "extra",
    (
        ["--no-zip", "chrome"],
        ["--verify", "chrome", "extension/dist/wins-vpn-companion-chrome.zip"],
    ),
)
def test_flag_refuses_modes_without_fresh_store_zips(extra):
    completed = subprocess.run(
        [sys.executable, "-B", str(BUILD), FLAG, *extra],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 2
    assert "--release-hardening-receipts records only freshly built" in completed.stderr
    assert "gate 1/4" not in completed.stdout
