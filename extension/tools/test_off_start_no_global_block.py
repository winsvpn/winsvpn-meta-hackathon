"""An OFF background start must not install the global block while it clears
routing it never held.

Honours EXTENSION_LIFECYCLE_SOURCE_ROOT like test_controller_lifecycle.py so the
same file can be pointed at a pristine or a patched extension tree.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from test_controller_lifecycle import _run_node as _run_controller

EXT = Path(__file__).resolve().parents[1]


def _run_adapter(tmp_path: Path, script: str) -> dict:
    node = shutil.which("node")
    if not node:
        pytest.skip("no local Node runtime")
    source = Path(os.environ.get("EXTENSION_LIFECYCLE_SOURCE_ROOT", str(EXT)))
    shutil.copytree(source / "src", tmp_path / "src")
    (tmp_path / "package.json").write_text('{"type":"module"}\n', encoding="ascii")
    (tmp_path / "test.mjs").write_text(script, encoding="utf-8")
    completed = subprocess.run(
        [node, "test.mjs"], cwd=tmp_path, check=False,
        capture_output=True, text=True, timeout=15,
        env={"PATH": "/usr/bin:/bin:/usr/local/bin"},
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr or completed.stdout)
    return json.loads(completed.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("mode", ["all", "listed"])
def test_off_start_without_held_routing_never_installs_a_block(tmp_path: Path, mode: str) -> None:
    got = _run_controller(tmp_path, """
const {controller, events} = fixture(MODE);
controller.adapter.holdsRouting = async () => false;
await controller.reconcile();
const first = events.slice();
events.length = 0;
await controller.onAlarm();
console.log(JSON.stringify({first, state: controller.current.state,
  complete: controller.offCleanupComplete, later: events}));
""".replace("MODE", json.dumps(mode)))
    assert got["first"] == ["clear", "release", "empty"]
    assert got["state"] == "off"
    assert got["complete"] is True
    assert got["later"] == []


def test_off_teardown_of_held_routing_keeps_block_first(tmp_path: Path) -> None:
    got = _run_controller(tmp_path, """
const {controller, events} = fixture();
controller.adapter.holdsRouting = async () => true;
await controller.reconcile();
console.log(JSON.stringify({events, state: controller.current.state}));
""")
    assert got == {"events": ["block", "clear", "release", "empty"], "state": "off"}


def test_adapter_without_the_answer_keeps_block_first(tmp_path: Path) -> None:
    got = _run_controller(tmp_path, """
const {controller, events} = fixture();
await controller.reconcile();
console.log(JSON.stringify({events, state: controller.current.state}));
""")
    assert got == {"events": ["block", "clear", "release", "empty"], "state": "off"}


CHROMIUM_SETUP = """
import assert from 'node:assert/strict';
let allowed = true;
let levels = {regular: 'controllable_by_this_extension', private: 'controllable_by_this_extension'};
let failRead = '';
const reads = [];
globalThis.chrome = {
  runtime: {}, extension: {isAllowedIncognitoAccess: async () => allowed},
  proxy: {settings: {get: async query => {
    const scope = query.incognito ? 'private' : 'regular';
    reads.push(scope);
    if (scope === failRead) throw new Error('scope read refused');
    return {levelOfControl: levels[scope]};
  }}},
};
const {ChromiumAdapter} = await import('./src/adapters/chromium.js');
const adapter = new ChromiumAdapter('chrome');
"""


def test_chromium_holds_routing_reads_every_scope(tmp_path: Path) -> None:
    got = _run_adapter(tmp_path, CHROMIUM_SETUP + """
const out = {};
out.fresh = await adapter.holdsRouting();
out.freshReads = reads.slice(); reads.length = 0;
levels.regular = 'controlled_by_this_extension';
out.regularOnly = await adapter.holdsRouting();
levels.regular = 'controllable_by_this_extension';
levels.private = 'controlled_by_this_extension';
out.privateOnly = await adapter.holdsRouting();
levels.private = 'controllable_by_this_extension';
allowed = false; reads.length = 0;
out.noIncognito = await adapter.holdsRouting();
out.noIncognitoReads = reads.slice();
allowed = null;
out.unknownPermission = await adapter.holdsRouting();
allowed = true; failRead = 'private';
out.failedRead = await adapter.holdsRouting();
failRead = ''; levels.regular = 'not_controllable';
out.policyOwned = await adapter.holdsRouting();
console.log(JSON.stringify(out));
""")
    assert got["fresh"] is False
    assert got["freshReads"] == ["regular", "private"]
    assert got["regularOnly"] is True
    assert got["privateOnly"] is True
    assert got["noIncognito"] is False
    assert got["noIncognitoReads"] == ["regular"]
    assert got["unknownPermission"] is True
    assert got["failedRead"] is True
    assert got["policyOwned"] is False


FIREFOX_SETUP = """
import assert from 'node:assert/strict';
let level = 'controllable_by_this_extension';
let failRead = false;
globalThis.browser = {
  runtime: {}, extension: {isAllowedIncognitoAccess: async () => true},
  proxy: {
    onRequest: {addListener: () => {}, removeListener: () => {}, hasListener: () => true},
    settings: {get: async () => { if (failRead) throw new Error('refused'); return {levelOfControl: level}; }},
  },
};
const {FirefoxAdapter} = await import('./src/adapters/firefox.js');
const adapter = new FirefoxAdapter();
"""


def test_firefox_holds_routing_sees_listener_and_settings(tmp_path: Path) -> None:
    got = _run_adapter(tmp_path, FIREFOX_SETUP + """
const out = {};
out.fresh = await adapter.holdsRouting();
level = 'controlled_by_this_extension';
out.settingsPac = await adapter.holdsRouting();
level = 'controllable_by_this_extension';
adapter._installOnRequest();
out.listener = await adapter.holdsRouting();
adapter._removeOnRequest();
failRead = true;
out.failedRead = await adapter.holdsRouting();
console.log(JSON.stringify(out));
""")
    assert got == {"fresh": False, "settingsPac": True, "listener": True, "failedRead": True}
