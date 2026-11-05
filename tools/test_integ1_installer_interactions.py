"""Local cross-round installer checks using extracted gateway functions."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest


ROOT = Path(os.environ.get(
    "INTEG1_TEST_ROOT", Path(__file__).resolve().parents[1]
)).resolve()


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def gateway_sources(monkeypatch):
    manifest = ROOT / "input_manifest.json"
    if manifest.exists():
        for item in json.loads(manifest.read_text())["files"]:
            data = (ROOT / item["path"]).read_bytes()
            assert hashlib.sha256(data).hexdigest() == item["sha256"], item["path"]
    block = load_module("integ1_snapshot_block", ROOT / "tools/winn3_gateway_block.py")
    monkeypatch.setitem(sys.modules, "winn3_gateway_block", block)
    helper = load_module("integ1_snapshot_source", ROOT / "tools/winn3_gateway_test_source.py")
    installer = (ROOT / block.TARGET).read_text(encoding="utf-8")
    source = (ROOT / block.SOURCE).read_text(encoding="utf-8")
    return block, helper, installer, source


def run_bash(script, *args, overrides=None):
    executable = shutil.which("bash")
    assert executable, "bash is required"
    env = {"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C"}
    env.update(overrides or {})
    return subprocess.run(
        [executable, "-c", script, "integ1-fixture", *map(str, args)],
        env=env, capture_output=True, text=True, timeout=30,
    )


def emitted_values(text):
    return dict(re.findall(r"^([A-Z][A-Z0-9_]*)=(.*)$", text, re.M))


def test_integrated_unit_env_defaults_and_closed_firewall_allowlist(
    gateway_sources, tmp_path
):
    _, helper, installer, _ = gateway_sources
    fixture = tmp_path / "gateway-only.sh"
    fixture.write_text(helper.fixture(ROOT / "server/wins_data_plane_setup_ONETOUCH.sh"))
    meminfo = tmp_path / "meminfo"
    meminfo.write_text("MemTotal:       16777216 kB\n")
    common = {
        "WINN3_GATEWAY_ID": "synthetic-test",
        "WINN3_GATEWAY_PATH_MTU": "1400",
        "WINN3_GATEWAY_INNER_V4": "192.0.2.1",
        "WINN3_GATEWAY_PLAN": "udp",
        "WINN3_GATEWAY_MAX_SESSIONS": "64",
        "WINN3_GATEWAY_FORWARD": "1",
        "WINN3_GATEWAY_FORWARD_IF": "winn3gw0",
        "WINN3_GATEWAY_FORWARD_CIDR": "192.0.2.0/24",
        "WINN3_GATEWAY_MEMINFO": str(meminfo),
        "WINN3_GATEWAY_PAYMENT_UNIT": str(tmp_path / "absent-payment.service"),
    }
    harness = r'''
set -euo pipefail
source "$1"
emit_unit_text > "$2"
emit_env_text > "$3"
'''
    cases = [
        ({}, "100", "infinity", "infinity", "8192MiB"),
        ({"WINN3_GATEWAY_DEDICATED": "0"}, "100", "4304M", "3228M", "2707842662"),
        ({"WINS_FREE_MBIT": "150"}, "150", "infinity", "infinity", "8192MiB"),
        ({"WINS_FREE_MBIT": "150", "WINN3_GATEWAY_FREE_MBIT": "75"},
         "75", "infinity", "infinity", "8192MiB"),
    ]
    for index, (overrides, rate, maximum, high, gomem) in enumerate(cases):
        unit_path = tmp_path / f"unit-{index}"
        env_path = tmp_path / f"env-{index}"
        result = run_bash(harness, fixture, unit_path, env_path,
                          overrides={**common, **overrides})
        assert result.returncode == 0, result.stderr
        unit = unit_path.read_text()
        env_text = env_path.read_text()
        values = emitted_values(env_text)
        assert values["WINN3_GATEWAY_FREE_MBIT"] == rate
        assert values["WINN3_GATEWAY_FORWARD"] == "1"
        assert values["WINN3_GATEWAY_FORWARD_ASYNC"] == "0"
        assert values["WINN3_GATEWAY_MAX_SESSIONS"] == "64"
        assert values["GOMEMLIMIT"] == gomem
        assert f"\nMemoryMax={maximum}\n" in unit
        assert f"\nMemoryHigh={high}\n" in unit
        assert f"\nEnvironment=GOMEMLIMIT={gomem}\n" in unit
        assert "  -forward " in unit
        assert "  -max-sessions 64 " in unit
        assert "-forward-async-write" not in unit
        assert "-uplink-inbox-depth" not in unit
        assert "-tun-gso" not in unit
        assert "-free-mbps" not in unit

        parser = re.search(
            r'    case "\$\{line_name\}" in\n.*?    esac', installer, re.S
        )
        assert parser
        for name in [*values, "PATH", "LD_PRELOAD", "WINN3_UNKNOWN"]:
            checked = run_bash('env_file=fixture\nline_name="$1"\n' + parser.group(), name)
            assert checked.returncode == (0 if name in values else 1), name

    for emitter in ["emit_unit_text", "emit_env_text"]:
        refused = run_bash(
            'set -euo pipefail\nsource "$1"\n"$2"\n', fixture, emitter,
            overrides={**common, "WINN3_GATEWAY_FREE_MBIT": "100001"},
        )
        assert refused.returncode != 0
        assert refused.stdout == ""

    main = (ROOT / "winn_protocol_experimental/cmd/winn3-gateway/main.go").read_text()
    async_default = (ROOT / "winn_protocol_experimental/cmd/winn3-gateway/forward_async_default.go").read_text()
    assert 'flags.Bool("tun-gso", false,' in main
    assert "const gatewayTokenWindow = 32768" in main
    assert "const inboxDepth = gatewayTokenWindow / 4" in main
    assert "var defaultUplinkInboxDepth = inboxDepth" in main
    assert re.search(r'case "", "1":\s*return true, nil', async_default)


def test_integrated_block_equivalence_rejects_cross_round_semantic_loss(gateway_sources):
    block, _, installer, source = gateway_sources
    assert hashlib.sha256(source.encode()).hexdigest() == block.SOURCE_SHA256
    assert block.check(source, installer) == []
    changes = [
        ("OI5 boot isolation", '  iptables -w 10 -A WINN3GW-FORWARD -i "${iface}" -o "${iface}" -j DROP',
         '  iptables -w 10 -A WINN3GW-FORWARD -i "${iface}" -o "${iface}" -j ACCEPT'),
        ("TS2 session sizing", "max_kib=$((208 * 1024 + 65536 * n))",
         "max_kib=$((208 * 1024 + 40960 * n))"),
        ("TS2 async inheritance", 'WINN3_GATEWAY_FORWARD_ASYNC="${WINN3_GATEWAY_FORWARD_ASYNC:-0}"',
         'WINN3_GATEWAY_FORWARD_ASYNC="${WINN3_GATEWAY_FORWARD_ASYNC:-1}"'),
        ("FREECAP emitted rate", "WINN3_GATEWAY_FREE_MBIT=${WINN3_GATEWAY_FREE_MBIT}\n", ""),
    ]
    for label, old, new in changes:
        assert installer.count(old) == 1, label
        assert block.check(source, installer.replace(old, new, 1)), label
