"""Execute the served dashboard script with a stalled local response."""
import json
from pathlib import Path
import shutil
import subprocess

import test_dashboard


def test_display_expires_while_refresh_is_pending():
    fixture = test_dashboard.DashboardTest()
    fixture.setUp()
    try:
        fixture.receipt('control-hub', fixture.all_dimensions('control-hub'))
        snapshot = fixture.snapshot()
    finally:
        fixture.doCleanups()
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const state = JSON.parse(fs.readFileSync(0, 'utf8'));
let now = Date.parse(state.generated_at);
const initial = now;
let timerId = 0;
const timers = new Map();
const nodes = new Map();
function element() {
  return {textContent: '', className: '', dataset: {}, style: {setProperty() {}},
    append() {}, replaceChildren() {}, setAttribute() {}};
}
const document = {
  getElementById(id) {if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id);},
  createElement: element, createTextNode: value => ({textContent: value}),
};
const window = {
  setTimeout(fn, delay) {const id = ++timerId; timers.set(id, {fn, at: now + delay}); return id;},
  clearTimeout(id) {timers.delete(id);},
};
class ClockDate extends Date {static now() {return now;}}
let requests = 0;
const fetch = async (_url, options) => {
  requests++;
  if (requests === 2) {
    return new Promise((_resolve, reject) => {
      options.signal?.addEventListener('abort', () => reject(new Error('request expired')));
    });
  }
  const fresh = {...state, generated_at: new Date(now).toISOString(),
    snapshot_expires_at: new Date(now + 15000).toISOString()};
  return {ok: true, json: async () => fresh};
};
const context = vm.createContext({document, window, fetch, Date: ClockDate, Error, AbortController});
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), context);
const settle = async () => {await new Promise(setImmediate); await new Promise(setImmediate);};
async function advance(target) {
  for (let steps = 0; steps < 20; steps++) {
    const due = [...timers].filter(([,t]) => t.at <= target).sort((a,b) => a[1].at - b[1].at)[0];
    if (!due) {now = target; await settle(); return;}
    now = due[1].at; timers.delete(due[0]); due[1].fn(); await settle();
  }
  throw new Error('timer budget exceeded');
}
await settle();
assert.match(nodes.get('connection').textContent, /^LIVE/);
const before = nodes.get('overall').textContent;
assert.notEqual(before, '0%');
await advance(initial + 16000);
const expired = nodes.get('connection').textContent;
const score = nodes.get('overall').textContent;
assert.equal(expired, 'EVIDENCE UNAVAILABLE');
assert.equal(score, '0%');
await advance(initial + 22000);
assert.match(nodes.get('connection').textContent, /^LIVE/);
assert.equal(nodes.get('overall').textContent, before);
console.log(JSON.stringify({expired, score, recovered: true}));
"""
    # Wrap in an async function because this harness uses CommonJS plus await.
    script = '(async () => {' + script + '})().catch(e => {console.error(e.message); process.exitCode = 1;});'
    completed = subprocess.run(
        [shutil.which('node'), '-e', script, str(Path(__file__).with_name('static') / 'app.js')],
        input=json.dumps(snapshot), text=True, capture_output=True, timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        'expired': 'EVIDENCE UNAVAILABLE', 'score': '0%', 'recovered': True,
    }
