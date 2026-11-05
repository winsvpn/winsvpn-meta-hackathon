"""Hostile systemd dependency tests for optional local Gemma availability."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

import pytest


ROUTER_DIR = Path(__file__).resolve().parent.parent
UNIT = ROUTER_DIR / "wins-edge-router.service.example"
PROVIDER_UNIT = "vllm-gemma4.service"
HARD_DEPENDENCIES = {
    "Requires",
    "Requisite",
    "BindsTo",
    "PartOf",
    "Conflicts",
    "PropagatesStopTo",
    "PropagatesReloadTo",
}


def _unit_directives(path: Path, section: str) -> dict[str, set[str]]:
    current_section = ""
    directives: dict[str, set[str]] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1]
            continue
        if current_section != section or "=" not in line:
            continue
        name, value = line.split("=", 1)
        directives.setdefault(name, set()).update(value.split())
    return directives


def test_canonical_unit_weakly_orders_after_optional_provider() -> None:
    dependencies = _unit_directives(UNIT, "Unit")

    assert PROVIDER_UNIT in dependencies.get("Wants", set())
    assert PROVIDER_UNIT in dependencies.get("After", set())
    for directive in HARD_DEPENDENCIES:
        assert PROVIDER_UNIT not in dependencies.get(directive, set())


def _systemctl(
    binary: str,
    scope: tuple[str, ...],
    *arguments: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [binary, *scope, *arguments],
        text=True,
        capture_output=True,
        timeout=15,
        check=check,
    )


def _properties(
    binary: str,
    scope: tuple[str, ...],
    unit: str,
    *names: str,
) -> dict[str, str]:
    arguments = ["show"]
    arguments.extend(f"--property={name}" for name in names)
    arguments.append(unit)
    result = _systemctl(binary, scope, *arguments)
    return dict(
        line.split("=", 1)
        for line in result.stdout.splitlines()
        if "=" in line
    )


@pytest.mark.skipif(sys.platform != "linux", reason="requires a Linux systemd manager")
def test_systemd_transaction_survives_provider_failure_and_stop(tmp_path: Path) -> None:
    systemctl = shutil.which("systemctl")
    if systemctl is None:
        pytest.skip("systemctl is unavailable")
    if os.environ.get("WINSVPN_ROUTER_SYSTEMD_TEST_SCOPE") == "system":
        if os.geteuid() != 0 or not Path("/run/systemd/system").is_dir():
            pytest.skip("explicit system-manager test requires root under systemd")
        scope: tuple[str, ...] = ()
    else:
        scope = ("--user",)
    manager = _systemctl(systemctl, scope, "show-environment", check=False)
    if manager.returncode != 0:
        pytest.skip("systemd user manager is unavailable")

    token = f"{os.getpid()}-{uuid.uuid4().hex[:10]}"
    provider_name = f"wins-test-vllm-{token}.service"
    router_name = f"wins-test-router-{token}.service"
    provider_path = tmp_path / provider_name
    router_path = tmp_path / router_name
    provider_path.write_text(
        "[Unit]\n"
        "Description=Hostile failing provider fixture\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/bin/false\n",
        encoding="utf-8",
    )
    router_path.write_text(
        "[Unit]\n"
        "Description=Router weak-dependency fixture\n"
        f"After={provider_name}\n"
        f"Wants={provider_name}\n\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=/bin/sleep infinity\n",
        encoding="utf-8",
    )

    try:
        _systemctl(
            systemctl,
            scope,
            "link",
            "--runtime",
            str(provider_path),
            str(router_path),
        )
        _systemctl(systemctl, scope, "daemon-reload")
        _systemctl(systemctl, scope, "start", router_name)

        provider = _properties(
            systemctl,
            scope,
            provider_name,
            "ActiveState",
            "Result",
        )
        router = _properties(
            systemctl,
            scope,
            router_name,
            "ActiveState",
            "SubState",
            "Result",
            "MainPID",
            "Wants",
            "After",
            "Requires",
            "Requisite",
            "BindsTo",
            "PartOf",
            "Conflicts",
            "PropagatesStopTo",
            "PropagatesReloadTo",
        )
        original_pid = router["MainPID"]
        assert provider["ActiveState"] == "failed"
        assert provider["Result"] == "exit-code"
        assert router["ActiveState"] == "active"
        assert router["SubState"] == "running"
        assert router["Result"] == "success"
        assert int(original_pid) > 0
        assert provider_name in router["Wants"].split()
        assert provider_name in router["After"].split()
        for directive in HARD_DEPENDENCIES:
            assert provider_name not in router.get(directive, "").split()

        _systemctl(systemctl, scope, "stop", provider_name)
        stopped = _properties(
            systemctl,
            scope,
            router_name,
            "ActiveState",
            "MainPID",
        )
        assert stopped == {"MainPID": original_pid, "ActiveState": "active"}

        restarted_provider = _systemctl(
            systemctl,
            scope,
            "restart",
            provider_name,
            check=False,
        )
        assert restarted_provider.returncode != 0
        restarted = _properties(
            systemctl,
            scope,
            router_name,
            "ActiveState",
            "MainPID",
        )
        assert restarted == {"MainPID": original_pid, "ActiveState": "active"}
    finally:
        _systemctl(
            systemctl,
            scope,
            "stop",
            router_name,
            provider_name,
            check=False,
        )
        _systemctl(
            systemctl,
            scope,
            "reset-failed",
            router_name,
            provider_name,
            check=False,
        )
        _systemctl(
            systemctl,
            scope,
            "disable",
            "--runtime",
            router_name,
            provider_name,
            check=False,
        )
        _systemctl(systemctl, scope, "daemon-reload", check=False)
