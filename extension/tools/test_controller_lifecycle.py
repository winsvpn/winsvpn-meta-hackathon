#!/usr/bin/env python3
"""Benign controller lifecycle regressions with local fake adapters."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

EXT = Path(__file__).resolve().parents[1]


def _run_node(tmp_path: Path, script: str) -> dict:
    node = shutil.which("node")
    if not node:
        pytest.skip("no local Node runtime")
    source = Path(os.environ.get("EXTENSION_LIFECYCLE_SOURCE_ROOT", str(EXT)))
    shutil.copytree(source / "src", tmp_path / "src")
    (tmp_path / "package.json").write_text('{"type":"module"}\n', encoding="ascii")
    (tmp_path / "test.mjs").write_text(COMMON + script, encoding="utf-8")
    completed = subprocess.run(
        [node, "test.mjs"], cwd=tmp_path, check=False,
        capture_output=True, text=True, timeout=15,
        env={"PATH": "/usr/bin:/bin:/usr/local/bin"},
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr or completed.stdout)
    return json.loads(completed.stdout.strip().splitlines()[-1])


COMMON = """
import assert from 'node:assert/strict';
globalThis.chrome = {runtime: {getManifest: () => ({version: '1.0.0'})}};
const {Controller} = await import('./src/background/controller.js');
const {defaultSettings} = await import('./src/core/rules.js');
const {PROTOCOL_VERSION} = await import('./src/core/constants.js');
function fixture(mode = 'all') {
  const controller = new Controller();
  const events = [];
  const faults = {clear: false, privacy: false, empty: false};
  let level = 'controllable_by_this_extension';
  controller.adapter = {
    name: 'fixture', blockTypesDropped: [], authStats: {},
    isAllowedIncognitoAccess: async () => false,
    proxyLevelOfControl: async () => level,
    blockLayerTypes: async () => ({ok: true, types: ['main_frame'], dropped: []}),
    setBlockRules: async rules => {
      events.push(rules.length ? 'block' : 'empty');
      if (!rules.length && faults.empty) throw new Error('empty update unavailable');
    },
    clearRouting: async () => {
      events.push('clear');
      if (faults.clear) throw new Error('routing clear unavailable');
      level = 'controllable_by_this_extension';
    },
    releasePrivacyProtections: async () => {
      events.push('release');
      if (faults.privacy) throw new Error('privacy release unavailable');
    },
    applyRouting: async () => {
      events.push('route'); level = 'controlled_by_this_extension'; return 'fixture';
    },
    applyPrivacyProtections: async () => {
      events.push('privacy'); return {webrtc: 'applied', prediction: 'applied'};
    },
    setCredential: () => {},
  };
  controller.settings = {...defaultSettings(), armed: false, mode,
    listed: ['example.test'], excluded: []};
  controller.blockLayer = {ok: true, error: '', dropped: []};
  return {controller, events, faults};
}
"""


def test_reconnect_backoff_waits_for_valid_host_response(tmp_path: Path) -> None:
    got = _run_node(tmp_path, """
const {controller} = fixture();
controller.settings.armed = true;
controller.reconcile = async () => {};
const timers = new Map();
const delays = [];
let seq = 0;
let callbacks;
globalThis.setTimeout = (fn, delay) => {
  const id = ++seq; timers.set(id, fn); delays.push(delay); return id;
};
globalThis.clearTimeout = id => timers.delete(id);
globalThis.setInterval = () => ++seq;
globalThis.clearInterval = () => {};
controller.adapter.connectNative = (_name, handlers) => {
  callbacks = handlers;
  return {postMessage: () => {}, disconnect: () => {}};
};
controller.openHost();
for (let i = 0; i < 3; i += 1) {
  callbacks.onDisconnect('native process ended normally before replying');
  const id = controller.reconnectTimer;
  const timer = timers.get(id); timers.delete(id); timer();
}
assert.deepEqual(delays, [1000, 2000, 5000]);
await callbacks.onMessage({v: PROTOCOL_VERSION, type: 'status', id: '1',
  status: 'disconnected', proxyReady: false});
callbacks.onDisconnect('native process ended normally after replying');
assert.deepEqual(delays, [1000, 2000, 5000, 1000]);
controller.closeHost();
assert.equal(timers.size, 0);
console.log(JSON.stringify({delays}));
""")
    assert got["delays"] == [1000, 2000, 5000, 1000]


def test_late_disconnect_from_closed_port_cannot_discard_new_session(tmp_path: Path) -> None:
    got = _run_node(tmp_path, """
const {controller} = fixture();
controller.settings.armed = true;
controller.reconcile = async () => {};
controller.startHeartbeat = () => {};
controller.stopHeartbeat = () => {};
controller.scheduleReconnect = () => {};
const sessions = [];
controller.adapter.connectNative = (_name, handlers) => {
  const port = {postMessage: () => {}, disconnect: () => {}};
  sessions.push({port, handlers});
  return port;
};
controller.openHost();
controller.closeHost();
controller.openHost();
const current = sessions[1].port;
controller.status = {status: 'connected', proxyReady: true, proxyPort: 45678};
controller.credential = {endpoint: {host: '127.0.0.1', port: 45678}, token: 'current'};
const messages = [];
controller.onHostMessage = raw => messages.push(raw);
sessions[0].handlers.onMessage('stale');
sessions[1].handlers.onMessage('current');
sessions[0].handlers.onDisconnect('late callback from closed port');
console.log(JSON.stringify({
  messages,
  keptPort: controller.port === current,
  hostConnected: controller.hostConnected,
  keptStatus: controller.status?.status === 'connected',
  keptToken: controller.credential?.token === 'current',
}));
""")
    assert got == {
        "messages": ["current"],
        "keptPort": True,
        "hostConnected": True,
        "keptStatus": True,
        "keptToken": True,
    }


@pytest.mark.parametrize("mode", ["all", "listed"])
def test_completed_off_cleanup_does_not_reinstall_blocks(tmp_path: Path, mode: str) -> None:
    got = _run_node(tmp_path, """
const {controller, events} = fixture(MODE);
await controller.reconcile();
assert.deepEqual(events, ['block', 'clear', 'release', 'empty']);
assert.equal(controller.current.state, 'off');
events.length = 0;
await controller.reconcile();
await controller.onAlarm();
assert.deepEqual(events, []);
assert.equal(controller.current.state, 'off');
console.log(JSON.stringify({state: controller.current.state, events}));
""".replace("MODE", json.dumps(mode)))
    assert got == {"state": "off", "events": []}


@pytest.mark.parametrize("fault", ["clear", "privacy", "empty"])
def test_failed_off_cleanup_is_retried(tmp_path: Path, fault: str) -> None:
    got = _run_node(tmp_path, """
const {controller, events, faults} = fixture();
faults[FAULT] = true;
let rejected = false;
try { await controller.reconcile(); } catch { rejected = true; }
assert.notEqual(controller.offCleanupComplete, true);
assert.equal(events[0], 'block');
assert.ok(events.includes('clear'));
assert.equal(events.includes('empty'), FAULT === 'empty');
if (FAULT === 'clear') assert.equal(controller.current.state, 'routing_failed');
else assert.equal(rejected, true);
faults[FAULT] = false;
events.length = 0;
await controller.reconcile();
assert.ok(events.includes('clear'));
assert.ok(events.includes('release'));
assert.ok(events.includes('empty'));
assert.equal(controller.current.state, 'off');
assert.equal(controller.offCleanupComplete, true);
events.length = 0;
await controller.reconcile();
assert.deepEqual(events, []);
console.log(JSON.stringify({recovered: true}));
""".replace("FAULT", json.dumps(fault)))
    assert got == {"recovered": True}


def test_active_routing_invalidates_completed_off_cleanup(tmp_path: Path) -> None:
    got = _run_node(tmp_path, """
const {controller, events} = fixture();
await controller.reconcile();
controller.settings.armed = true;
controller.hostConnected = true;
controller.hostSpoke = true;
controller.status = {status: 'connected', detail: 'none', proxyReady: true, proxyPort: 45678};
controller.statusAtMs = Date.now();
controller.credential = {endpoint: {kind: 'http', host: '127.0.0.1', port: 45678}, token: 'A'.repeat(43)};
controller.canAuthenticate = true;
await controller.reconcile();
assert.equal(controller.current.state, 'protected');
assert.equal(controller.offCleanupComplete, false);
assert.ok(events.includes('route'));
events.length = 0;
controller.settings.armed = false;
await controller.reconcile();
assert.deepEqual(events, ['block', 'clear', 'release', 'empty']);
assert.equal(controller.current.state, 'off');
console.log(JSON.stringify({transition: events}));
""")
    assert got["transition"] == ["block", "clear", "release", "empty"]


def test_superseded_off_cleanup_is_not_cached(tmp_path: Path) -> None:
    got = _run_node(tmp_path, """
const {controller, events} = fixture();
let release;
let started;
const entered = new Promise(resolve => { started = resolve; });
const pending = new Promise(resolve => { release = resolve; });
const ordinaryRelease = controller.adapter.releasePrivacyProtections;
controller.adapter.releasePrivacyProtections = async () => {
  await ordinaryRelease(); started(); await pending;
};
const first = controller.reconcile();
await entered;
assert.notEqual(controller.offCleanupComplete, true);
controller.settings = {...controller.settings, mode: 'listed'};
const second = controller.reconcile();
controller.adapter.releasePrivacyProtections = ordinaryRelease;
release();
await Promise.all([first, second]);
assert.deepEqual(events, ['block', 'clear', 'release', 'block', 'clear', 'release', 'empty']);
assert.equal(controller.offCleanupComplete, true);
events.length = 0;
await controller.reconcile();
assert.deepEqual(events, []);
console.log(JSON.stringify({supersededCleanupRetried: true}));
""")
    assert got == {"supersededCleanupRetried": True}
