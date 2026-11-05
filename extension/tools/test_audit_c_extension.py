#!/usr/bin/env python3
"""Seat C audit regressions (C-extension-1..3). Same harness as test_browser_enforcement_regressions.py."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

EXT = Path(__file__).resolve().parents[1]

CHROME_FAKE = r"""
const posted = [];
let lastIssueId = '';
const port = { msg: null, disc: null };
const auth = [];
const permListeners = { removed: [], added: [] };
const msgListeners = [];
let hostAccess = true;
const store = {};
Object.defineProperty(globalThis, 'navigator', { value: { userAgent: 'Chrome' }, configurable: true });
globalThis.chrome = {
  runtime: {
    id: 'abcdefghijklmnopabcdefghijklmnop',
    getURL: (p) => 'chrome-extension://abcdefghijklmnopabcdefghijklmnop' + p,
    getManifest: () => ({ version: '1.0.16' }),
    connectNative: () => ({
      postMessage: (m) => { posted.push(m.type); if (m.type === 'issue_proxy_credential') lastIssueId = m.id; }, disconnect() {},
      onMessage: { addListener: (f) => { port.msg = f; } },
      onDisconnect: { addListener: (f) => { port.disc = f; } },
    }),
    onInstalled: { addListener() {} }, onStartup: { addListener() {} },
    onMessage: { addListener: (f) => msgListeners.push(f) },
  },
  storage: { local: { get: async (k) => ({ [k]: store[k] }), set: async (o) => Object.assign(store, o), clear: async () => {} } },
  alarms: { create: async () => {}, onAlarm: { addListener() {} } },
  extension: { isAllowedIncognitoAccess: async () => false },
  permissions: {
    contains: async () => hostAccess,
    onRemoved: { addListener: (f) => permListeners.removed.push(f) },
    onAdded: { addListener: (f) => permListeners.added.push(f) },
  },
  webRequest: { onAuthRequired: { addListener: (f) => auth.push(f) } },
  declarativeNetRequest: (() => { let rules = []; return {
    updateDynamicRules: async ({ removeRuleIds = [], addRules = [] }) => { rules = rules.filter((r) => !removeRuleIds.includes(r.id)).concat(addRules); },
    getDynamicRules: async () => rules.filter((r) => r.id !== 9000) }; })(),
  proxy: { settings: (() => { let v = null; return {
    set: async ({ value }) => { v = value; }, clear: async () => { v = null; },
    get: async () => ({ value: v, levelOfControl: v ? 'controlled_by_this_extension' : 'controllable_by_this_extension' }) }; })() },
  privacy: { network: Object.fromEntries(['webRTCIPHandlingPolicy', 'networkPredictionEnabled'].map((n) => { let v; return [n, {
    set: async ({ value }) => { v = value; }, clear: async () => {}, get: async () => ({ value: v, levelOfControl: 'controlled_by_this_extension' }) }]; })) },
  action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {} },
};
const STATUS = { v: 1, id: '', type: 'status', ok: true, status: 'connected', detail: 'none',
  winn: 'unavailable_on_this_platform', selectedSlug: '', nodes: [], canRequestConnect: true,
  proxyReady: true, proxyPort: 50000, rxKib: 0, txKib: 0 };
const TOKEN = { v: 1, id: '4', type: 'proxy_credential', ok: true, proxyPort: 50000, token: 'A'.repeat(43) };
const token = () => ({ ...TOKEN, id: lastIssueId });
const tick = () => new Promise((r) => setTimeout(r, 20));
"""


def _run_node(tmp_path: Path, script: str) -> dict:
    node = shutil.which("node")
    if not node:
        pytest.skip("no local Node runtime")
    shutil.copytree(EXT / "src", tmp_path / "src")
    (tmp_path / "package.json").write_text('{"type":"module"}\n', encoding="ascii")
    (tmp_path / "test.mjs").write_text(script, encoding="utf-8")
    completed = subprocess.run(
        [node, "test.mjs"], cwd=tmp_path, check=False, capture_output=True,
        text=True, timeout=30, env={"PATH": "/usr/bin:/bin:/usr/local/bin"},
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr or completed.stdout)
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_unicode_rule_normalization(tmp_path: Path) -> None:
    got = _run_node(tmp_path, r"""
const { normaliseRule } = await import('./src/core/rules.js');
console.log(JSON.stringify({
  ordinary: normaliseRule('https://example.com/path').rule,
  burmese: normaliseRule('မြန်မာ.com').rule,
  numeric: normaliseRule('１２７.０.０.１').ok,
  backslash: normaliseRule('ဝင်.com\\evil').ok,
}));
""")
    assert got == {'ordinary': 'example.com', 'burmese': 'xn--7idjb0f4ck.com', 'numeric': False, 'backslash': False}


def test_unicode_rule_source_keeps_leakscan_clean() -> None:
    import sys
    sys.path.insert(0, str(EXT / 'tools'))
    import leakscan
    assert not leakscan.scan_tree(EXT / 'src')


def test_rejected_credential_is_reissued(tmp_path: Path) -> None:
    """C-extension-3: an expired/rejected proxy token must be replaced without user action."""
    got = _run_node(tmp_path, CHROME_FAKE + r"""
const { Controller } = await import('./src/background/controller.js');
const c = new Controller();
c.adapter.installProxyAuth(async () => c.credential);
await c.init();
await c.setSettings({ armed: true, mode: 'all', listed: [], excluded: [] });
await port.msg(STATUS); await port.msg(token()); await c.reconcile();
const before = c.current.state;
const ch = { isProxy: true, requestId: '77', scheme: 'basic', realm: 'wins-bridge', challenger: { host: '127.0.0.1', port: 50000 } };
await new Promise((r) => auth[0](ch, r));
await new Promise((r) => auth[0](ch, r));
const n0 = posted.filter((t) => t === 'issue_proxy_credential').length;
for (let i = 0; i < 3; i++) { await port.msg(STATUS); await c.reconcile(); }
const n1 = posted.filter((t) => t === 'issue_proxy_credential').length;
c.stopHeartbeat();
console.log(JSON.stringify({ before, reissued: n1 - n0 }));
process.exit(0);
""")
    assert got["before"] == "protected"
    assert got["reissued"] == 1


def test_chromium_host_permission_revocation_leaves_protected(tmp_path: Path) -> None:
    """C-extension-2: revoking <all_urls> on Chrome/Edge must leave PROTECTED promptly."""
    got = _run_node(tmp_path, CHROME_FAKE + r"""
await import('./src/background/background.js');
await tick();
const ask = (m) => new Promise((r) => msgListeners[0](m, { id: chrome.runtime.id }, r));
await ask({ type: 'setSettings', settings: { armed: true, mode: 'all', listed: [], excluded: [] } });
await port.msg(STATUS); await port.msg(token()); await tick();
const before = (await ask({ type: 'getState' })).state;
hostAccess = false;
for (const f of permListeners.removed) f({ origins: ['<all_urls>'] });
await tick(); await tick();
const afterEvent = (await ask({ type: 'getState' })).state;
console.log(JSON.stringify({ before, afterEvent, removedListeners: permListeners.removed.length }));
process.exit(0);
""")
    assert got["before"] == "protected"
    assert got["removedListeners"] >= 1
    assert got["afterEvent"] == "no_auth_capability"


def test_firefox_routes_before_init_and_never_direct_when_armed(tmp_path: Path) -> None:
    """C-extension-1: Firefox must own proxy.onRequest from the top level of the event page."""
    got = _run_node(tmp_path, r"""
const listeners = [];
let releaseStorage;
const storageGate = new Promise((r) => { releaseStorage = r; });
const noop = { addListener() {} };
globalThis.browser = {
  runtime: { id: 'companion@winsvpn.org', getURL: (p) => 'moz-extension://x' + p,
    getManifest: () => ({ version: '1.0.16' }), connectNative: () => { throw new Error('no host'); },
    onInstalled: noop, onStartup: noop, onMessage: noop },
  storage: { local: { get: async (k) => { await storageGate; return { [k]: { armed: true, mode: 'all', listed: [], excluded: [] } }; },
    set: async () => {}, clear: async () => {} } },
  alarms: { create: async () => {}, onAlarm: noop },
  extension: { isAllowedIncognitoAccess: async () => true },
  permissions: { contains: async () => true, onRemoved: noop, onAdded: noop },
  webRequest: { onAuthRequired: noop },
  declarativeNetRequest: { updateDynamicRules: async () => {}, getDynamicRules: async () => [] },
  proxy: { onRequest: { addListener: (f) => listeners.push(f), removeListener() {}, hasListener: (f) => listeners.includes(f) },
    settings: { set: async () => true, clear: async () => false, get: async () => ({ value: {}, levelOfControl: 'controllable_by_this_extension' }) } },
  privacy: { network: { webRTCIPHandlingPolicy: { set: async () => true, get: async () => ({}), clear: async () => true },
    networkPredictionEnabled: { set: async () => true, get: async () => ({}), clear: async () => true } } },
  action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {} },
};
await import('./src/background/background.js');
const registeredAtTopLevel = listeners.length;
let decision = null;
if (listeners.length) {
  const pending = Promise.resolve(listeners[0]({ url: 'https://example.com/' }));
  releaseStorage();
  decision = await pending;
}
console.log(JSON.stringify({ registeredAtTopLevel, decision }));
process.exit(0);
""")
    assert got["registeredAtTopLevel"] >= 1
    assert got["decision"] != {"type": "direct"}
    assert isinstance(got["decision"], list) and got["decision"][0]["port"] == 1


def test_fail_closed_applies_privacy_before_route_comes_off(tmp_path: Path) -> None:
    """Sol-extension-2: armed with no desktop app, prediction and WebRTC are still pinned."""
    got = _run_node(tmp_path, CHROME_FAKE + r"""
const order = [];
const dnr = chrome.declarativeNetRequest.updateDynamicRules;
chrome.declarativeNetRequest.updateDynamicRules = async (a) => { if ((a.addRules || []).length) order.push('block'); return dnr(a); };
const pset = chrome.privacy.network.networkPredictionEnabled.set;
chrome.privacy.network.networkPredictionEnabled.set = async (a) => { order.push('privacy'); return pset(a); };
const pclear = chrome.proxy.settings.clear;
chrome.proxy.settings.clear = async (a) => { order.push('clear'); return pclear(a); };
chrome.runtime.connectNative = () => { throw new Error('no host'); };
const { Controller } = await import('./src/background/controller.js');
const c = new Controller();
await c.init();
order.length = 0;
await c.setSettings({ armed: true, mode: 'all', listed: [], excluded: [] });
c.stopHeartbeat();
const first = (k) => order.indexOf(k);
console.log(JSON.stringify({ order: order.slice(0, 6), privacy: c.privacy, failClosed: c.current.failClosed,
  ok: first('block') >= 0 && first('privacy') > first('block') && first('clear') > first('privacy') }));
process.exit(0);
""")
    assert got["failClosed"] is True
    assert got["privacy"]["prediction"] == "applied"
    assert got["ok"] is True


def test_credential_latch_released_by_gate_close_and_refusal(tmp_path: Path) -> None:
    """Sol-extension-11: a pending issue request must not latch forever."""
    got = _run_node(tmp_path, CHROME_FAKE + r"""
const sent = [];
chrome.runtime.connectNative = () => ({
  postMessage: (m) => { posted.push(m.type); sent.push(m); }, disconnect() {},
  onMessage: { addListener: (f) => { port.msg = f; } },
  onDisconnect: { addListener: (f) => { port.disc = f; } },
});
const { Controller } = await import('./src/background/controller.js');
const c = new Controller();
await c.init();
await c.setSettings({ armed: true, mode: 'all', listed: [], excluded: [] });
const issues = () => sent.filter((m) => m.type === 'issue_proxy_credential');
await port.msg(STATUS);                          // request 1 goes out
await port.msg({ ...STATUS, proxyReady: false }); // gate shuts while pending
await port.msg(STATUS);                          // request 2 must go out
const afterGate = issues().length;
const pending = issues()[issues().length - 1].id;
await port.msg({ v: 1, id: 'other', type: 'error', code: 'internal' }); // unrelated refusal
await port.msg(STATUS);
const afterUnrelated = issues().length;
await port.msg({ v: 1, id: pending, type: 'error', code: 'rate_limited' }); // refusal of the pending one
await port.msg(STATUS);
const afterRefusal = issues().length;
c.stopHeartbeat();
console.log(JSON.stringify({ afterGate, afterUnrelated, afterRefusal }));
process.exit(0);
""")
    assert got["afterGate"] == 2
    assert got["afterUnrelated"] == 2
    assert got["afterRefusal"] == 3


def test_status_is_asked_every_second_while_the_tunnel_comes_up(tmp_path: Path) -> None:
    """New T2 performance finding: routing must not wait up to HEARTBEAT_MS for the next ask."""
    got = _run_node(tmp_path, CHROME_FAKE + r"""
const { Controller } = await import('./src/background/controller.js');
const c = new Controller();
await c.init();
await c.setSettings({ armed: true, mode: 'all', listed: [], excluded: [] });
await port.msg({ ...STATUS, status: 'connecting', proxyReady: false });
const n0 = posted.filter((t) => t === 'get_status').length;
await new Promise((r) => setTimeout(r, 2600));
const connecting = posted.filter((t) => t === 'get_status').length - n0;
await port.msg(STATUS); await port.msg(token()); await c.reconcile();
const n1 = posted.filter((t) => t === 'get_status').length;
await new Promise((r) => setTimeout(r, 2600));
const protectedAsks = posted.filter((t) => t === 'get_status').length - n1;
const state = c.current.state;
c.stopHeartbeat();
console.log(JSON.stringify({ connecting, protectedAsks, state }));
process.exit(0);
""")
    assert got["connecting"] >= 2
    assert got["state"] == "protected"
    assert got["protectedAsks"] == 0


def test_routing_rewrite_keeps_the_scope_blocked_until_the_route_is_in(tmp_path: Path) -> None:
    got = _run_node(tmp_path, CHROME_FAKE + r"""
const { Controller } = await import('./src/background/controller.js');
const c = new Controller();
await c.init();
await c.setSettings({ armed: true, mode: 'all', listed: [], excluded: ['c.test'] });
await port.msg(STATUS); await port.msg(token()); await c.reconcile();
const before = c.current.state;
let seenDuringRewrite = null;
const set = chrome.proxy.settings.set;
chrome.proxy.settings.set = async (a) => {
  seenDuringRewrite = (await chrome.declarativeNetRequest.getDynamicRules()).map((r) => `${r.action.type}:${r.condition.urlFilter}`);
  return set(a);
};
await c.setSettings({ armed: true, mode: 'all', listed: [], excluded: [] });
const after = (await chrome.declarativeNetRequest.getDynamicRules()).length;
c.stopHeartbeat();
console.log(JSON.stringify({ before, seenDuringRewrite, after, state: c.current.state }));
process.exit(0);
""")
    assert got["before"] == "protected"
    assert got["seenDuringRewrite"] == ["block:*"]
    assert got["after"] == 0
    assert got["state"] == "protected"


def test_privacy_refusal_on_the_fail_closed_path_is_its_own_state(tmp_path: Path) -> None:
    got = _run_node(tmp_path, CHROME_FAKE + r"""
let clears = 0;
chrome.proxy.settings.clear = async () => { clears += 1; };
chrome.privacy.network.webRTCIPHandlingPolicy.get = async () => ({ levelOfControl: 'controlled_by_other_extensions' });
chrome.runtime.connectNative = () => { throw new Error('no host'); };
const { Controller } = await import('./src/background/controller.js');
const c = new Controller();
await c.init();
clears = 0;
await c.setSettings({ armed: true, mode: 'all', listed: [], excluded: [] });
c.stopHeartbeat();
console.log(JSON.stringify({ state: c.current.state, failClosed: c.current.failClosed, privacy: c.privacy,
  rules: (await chrome.declarativeNetRequest.getDynamicRules()).map((r) => `${r.action.type}:${r.condition.urlFilter}`), clears }));
process.exit(0);
""")
    assert got["state"] == "privacy_failed"
    assert got["failClosed"] is True
    assert got["privacy"] == {"webrtc": "not_applied", "prediction": "not_applied"}
    assert got["rules"] == ["block:*"]
    assert got["clears"] == 0


def test_only_the_pending_credential_reply_is_accepted(tmp_path: Path) -> None:
    got = _run_node(tmp_path, CHROME_FAKE + r"""
const { Controller } = await import('./src/background/controller.js');
const c = new Controller();
await c.init();
await c.setSettings({ armed: true, mode: 'all', listed: [], excluded: [] });
await port.msg(STATUS);
const a = lastIssueId;
await port.msg({ ...STATUS, proxyReady: false });
await port.msg(STATUS);
const b = lastIssueId;
await port.msg({ ...token(), token: 'B'.repeat(43) });
await port.msg({ ...TOKEN, id: a });
await port.msg({ ...TOKEN, id: '999' });
const key = c.credential.token;
await port.msg({ ...STATUS, proxyReady: false });
await port.msg({ ...TOKEN, id: b });
c.stopHeartbeat();
console.log(JSON.stringify({ a, b, key, credential: c.credential }));
process.exit(0);
""")
    assert got["a"] != got["b"]
    assert got["key"] == "B" * 43
    assert got["credential"] is None
