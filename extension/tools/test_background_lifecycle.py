"""Initialization failure and retry tests for the real background entry point."""

import shutil
import subprocess
from pathlib import Path

import pytest


BACKGROUND = Path(__file__).resolve().parents[1] / "src/background/background.js"

HARNESS = """
import assert from 'node:assert/strict';
const listeners = {};
const event = (name) => ({ addListener(fn) { listeners[name] = fn; } });
globalThis.api = {
  runtime: {
    id: 'test-extension',
    onInstalled: event('installed'),
    onStartup: event('startup'),
    onMessage: event('message'),
  },
  alarms: { create() {}, onAlarm: event('alarm') },
};
const failure = new Error('injected initialization failure: private detail');
let fail = true;
let attempts = 0;
let actions = 0;
let controller;
globalThis.Controller = class {
  constructor() {
    controller = this;
    this.adapter = {
      name: 'chrome',
      installProxyAuth(fn) { listeners.auth = fn; },
    };
  }
  async init() { attempts++; if (fail) throw failure; }
  async onAlarm() { actions++; }
  async waitForCredential() { actions++; return 'credential'; }
  async reconcile() { actions++; }
  snapshot() { return { initialized: true }; }
};
const unhandled = [];
process.on('unhandledRejection', (error) => unhandled.push(error));
const flush = async () => {
  await new Promise(setImmediate);
  await new Promise(setImmediate);
};
await import('./background/background.js');
await flush();
assert.equal(attempts, 1);
assert.equal(controller.lastError, 'initialization failed and will be retried');
assert.deepEqual(unhandled, []);
assert.equal(typeof listeners.installed, 'function');
assert.equal(typeof listeners.startup, 'function');
"""


def run_background(tmp_path, script):
    node = shutil.which("node")
    if not node:
        pytest.skip("no local Node runtime")
    (tmp_path / "background").mkdir()
    (tmp_path / "adapters").mkdir()
    shutil.copyfile(BACKGROUND, tmp_path / "background/background.js")
    (tmp_path / "package.json").write_text('{"type":"module"}\n', encoding="ascii")
    (tmp_path / "background/controller.js").write_text(
        "export const Controller = globalThis.Controller;\n"
        "export const ALARM_NAME = 'test-alarm';\n"
        "export const ALARM_PERIOD_MINUTES = 1;\n", encoding="ascii")
    (tmp_path / "adapters/index.js").write_text(
        "export const api = globalThis.api;\n", encoding="ascii")
    (tmp_path / "test.mjs").write_text(HARNESS + script, encoding="utf-8")
    result = subprocess.run(
        [node, "--unhandled-rejections=strict", "test.mjs"],
        cwd=tmp_path, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr or result.stdout


@pytest.mark.parametrize("trigger", ["load", "installed", "startup"])
def test_startup_rejection_is_handled_and_later_event_retries(tmp_path, trigger):
    run_background(tmp_path, f"""
const trigger = '{trigger}';
if (trigger !== 'load') {{
  listeners[trigger]();
  await flush();
  assert.equal(attempts, 2);
  assert.equal(controller.lastError, 'initialization failed and will be retried');
  assert.deepEqual(unhandled, []);
}}
fail = false;
listeners[trigger === 'load' ? 'startup' : trigger]();
await flush();
assert.equal(attempts, trigger === 'load' ? 2 : 3);
await listeners.alarm({{ name: 'test-alarm' }});
assert.equal(actions, 1);
assert.equal(attempts, trigger === 'load' ? 2 : 3);
assert.deepEqual(unhandled, []);
""")


@pytest.mark.parametrize("handler", ["auth", "alarm", "message"])
def test_awaiting_handlers_preserve_rejection_and_retry(tmp_path, handler):
    run_background(tmp_path, f"""
const handler = '{handler}';
const invoke = () => {{
  if (handler === 'auth') return listeners.auth();
  if (handler === 'alarm') return listeners.alarm({{ name: 'test-alarm' }});
  return new Promise((resolve) => {{
    assert.equal(listeners.message(
      {{ type: 'getState' }}, {{ id: api.runtime.id }}, resolve), true);
  }});
}};
if (handler === 'message') {{
  assert.deepEqual(await invoke(), {{ error: failure.message }});
}} else if (handler === 'alarm') {{
  await invoke();
  assert.equal(controller.lastError, 'alarm reconciliation failed and will be retried');
}} else {{
  await assert.rejects(invoke(), (error) => error === failure);
}}
assert.equal(attempts, 2);
assert.equal(actions, 0);
fail = false;
const result = await invoke();
if (handler === 'auth') assert.equal(result, 'credential');
if (handler === 'message') assert.deepEqual(result, {{ initialized: true }});
assert.equal(attempts, 3);
assert.equal(actions, 1);
await flush();
assert.deepEqual(unhandled, []);
""")
