#!/usr/bin/env python3
"""Hostile browser-adapter and reconciliation regressions."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

EXT = Path(__file__).resolve().parents[1]


def _run_node(tmp_path: Path, script: str) -> dict:
    node = shutil.which("node")
    if not node:
        pytest.skip("no local Node runtime")
    shutil.copytree(EXT / "src", tmp_path / "src")
    (tmp_path / "package.json").write_text('{"type":"module"}\n', encoding="ascii")
    (tmp_path / "test.mjs").write_text(script, encoding="utf-8")
    completed = subprocess.run(
        [node, "test.mjs"],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env={"PATH": "/usr/bin:/bin:/usr/local/bin"},
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr or completed.stdout)
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_dnr_update_requires_normalised_readback(tmp_path: Path) -> None:
    got = _run_node(
        tmp_path,
        """
globalThis.chrome = {
  runtime: {},
  declarativeNetRequest: {
    updateDynamicRules: async () => {},
    getDynamicRules: async () => [],
  },
};
const {BaseAdapter} = await import('./src/adapters/base.js');
const adapter = new BaseAdapter('test');
let error = '';
try {
  await adapter.setBlockRules([{
    id: 1,
    priority: 2,
    action: {type: 'block'},
    condition: {urlFilter: '||example.test^', resourceTypes: ['script', 'main_frame']},
  }]);
} catch (e) { error = String(e.message || e); }
console.log(JSON.stringify({error}));
""",
    )
    assert "readback differed" in got["error"]


def test_dnr_readback_tolerates_browser_defaults_and_order(tmp_path: Path) -> None:
    got = _run_node(
        tmp_path,
        """
const readBack = [{
  id: 7,
  priority: 1,
  action: {type: 'block'},
  condition: {
    urlFilter: '||example.test^',
    resourceTypes: ['script', 'main_frame'],
    isUrlFilterCaseSensitive: false,
  },
}];
globalThis.chrome = {
  runtime: {},
  declarativeNetRequest: {
    updateDynamicRules: async () => {},
    getDynamicRules: async () => readBack,
  },
};
const {BaseAdapter} = await import('./src/adapters/base.js');
await new BaseAdapter('test').setBlockRules([{
  id: 7,
  action: {type: 'block'},
  condition: {urlFilter: '||example.test^', resourceTypes: ['main_frame', 'script']},
}]);
console.log(JSON.stringify({ok: true}));
""",
    )
    assert got == {"ok": True}


def test_firefox_proxy_results_have_explicit_no_fallback(tmp_path: Path) -> None:
    got = _run_node(
        tmp_path,
        """
let listener = null;
globalThis.browser = {
  runtime: {},
  proxy: {
    onRequest: {
      addListener: fn => { listener = fn; },
      removeListener: () => {},
      hasListener: fn => fn === listener,
    },
    settings: {
      clear: async () => true,
      get: async () => ({levelOfControl: 'controllable_by_this_extension'}),
    },
  },
  permissions: {contains: async () => true},
};
const {FirefoxAdapter} = await import('./src/adapters/firefox.js');
const adapter = new FirefoxAdapter();
adapter._live = {
  settings: {mode: 'all', listed: [], excluded: []},
  endpoint: {host: '127.0.0.1', port: 45678},
};
adapter._installOnRequest();
const routed = listener({url: 'https://example.test/'});
const malformed = listener({url: 'not a url'});
console.log(JSON.stringify({routed, malformed}));
""",
    )
    assert got["routed"][-1] is None
    assert got["routed"][0]["port"] == 45678
    assert got["malformed"][-1] is None
    assert got["malformed"][0]["port"] == 1


def test_firefox_false_clear_without_stored_setting_allows_onrequest(tmp_path: Path) -> None:
    got = _run_node(
        tmp_path,
        """
let listener = null;
const order = [];
globalThis.browser = {
  runtime: {},
  proxy: {
    onRequest: {
      addListener: fn => { listener = fn; },
      removeListener: () => { order.push('remove'); },
      hasListener: fn => fn === listener,
    },
    settings: {
      clear: async () => { order.push('clear'); return false; },
      get: async () => {
        order.push('get');
        return {levelOfControl: 'controllable_by_this_extension'};
      },
    },
  },
  permissions: {contains: async () => true},
};
const {FirefoxAdapter} = await import('./src/adapters/firefox.js');
const adapter = new FirefoxAdapter();
const mechanism = await adapter.applyRouting(
  {mode: 'all', listed: [], excluded: []},
  {host: '127.0.0.1', port: 45678},
);
console.log(JSON.stringify({
  mechanism,
  routingMechanism: adapter.routingMechanism,
  listenerInstalled: Boolean(adapter._onRequest),
  order,
}));
""",
    )
    assert got == {
        "mechanism": "onRequest",
        "routingMechanism": "onRequest",
        "listenerInstalled": True,
        "order": ["clear", "get"],
    }


def test_firefox_clear_is_judged_by_verified_post_state(tmp_path: Path) -> None:
    got = _run_node(
        tmp_path,
        """
let active = null;
let listener = null;
let order = [];
globalThis.browser = {
  runtime: {},
  proxy: {
    onRequest: {
      addListener: fn => { listener = fn; },
      removeListener: fn => {
        order.push('remove');
        if (listener === fn) listener = null;
      },
      hasListener: fn => fn === listener,
    },
    settings: {
      clear: async () => {
        order.push('clear');
        if (active.clearError) throw new Error(active.clearError);
        return active.cleared;
      },
      get: async () => {
        order.push('get');
        if (active.getError) throw new Error(active.getError);
        return active.got;
      },
    },
  },
};
const {FirefoxAdapter} = await import('./src/adapters/firefox.js');

async function run(config) {
  active = config;
  listener = null;
  order = [];
  const adapter = new FirefoxAdapter();
  adapter._installOnRequest();
  adapter.routingMechanism = 'onRequest';
  let error = '';
  try { await adapter.clearRouting(); } catch (e) { error = String(e.message || e); }
  return {
    error,
    order: [...order],
    stillInstalled: Boolean(adapter._onRequest),
    routingMechanism: adapter.routingMechanism,
  };
}

const results = {};
for (const level of [
  'controllable_by_this_extension',
  'controlled_by_other_extensions',
  'not_controllable',
]) {
  results[level] = await run({cleared: false, got: {levelOfControl: level}});
}
results.falseSelf = await run({
  cleared: false,
  got: {levelOfControl: 'controlled_by_this_extension'},
});
results.trueSelf = await run({
  cleared: true,
  got: {levelOfControl: 'controlled_by_this_extension'},
});
results.getRejected = await run({cleared: false, getError: 'readback refused'});
results.clearRejected = await run({clearError: 'clear refused'});
results.missingLevel = await run({cleared: false, got: {}});
results.nonBoolean = await run({cleared: undefined, got: {
  levelOfControl: 'controllable_by_this_extension',
}});
console.log(JSON.stringify(results));
""",
    )
    for level in (
        "controllable_by_this_extension",
        "controlled_by_other_extensions",
        "not_controllable",
    ):
        assert got[level] == {
            "error": "",
            "order": ["clear", "get", "remove"],
            "stillInstalled": False,
            "routingMechanism": "none",
        }
    for case in ("falseSelf", "trueSelf", "getRejected", "clearRejected", "missingLevel", "nonBoolean"):
        assert got[case]["stillInstalled"] is True
        assert got[case]["routingMechanism"] == "onRequest"
        assert "remove" not in got[case]["order"]
    assert "not verifiably relinquished" in got["falseSelf"]["error"]
    assert "not verifiably relinquished" in got["trueSelf"]["error"]
    assert "readback refused" in got["getRejected"]["error"]
    assert got["getRejected"]["order"] == ["clear", "get"]
    assert "clear refused" in got["clearRejected"]["error"]
    assert got["clearRejected"]["order"] == ["clear"]
    assert "not verifiably relinquished" in got["missingLevel"]["error"]
    assert "invalid proxy.settings.clear result" in got["nonBoolean"]["error"]
    assert got["nonBoolean"]["order"] == ["clear"]


def test_firefox_false_clear_rejects_residual_extension_pac(tmp_path: Path) -> None:
    got = _run_node(
        tmp_path,
        """
let listener = null;
let written = null;
let removed = 0;
globalThis.browser = {
  runtime: {},
  proxy: {
    onRequest: {
      addListener: fn => { listener = fn; },
      removeListener: () => { removed += 1; },
      hasListener: fn => fn === listener,
    },
    settings: {
      set: async details => { written = details.value; return true; },
      clear: async () => false,
      get: async () => ({
        levelOfControl: 'controllable_by_this_extension',
        value: written,
      }),
    },
  },
};
const {FirefoxAdapter} = await import('./src/adapters/firefox.js');
const adapter = new FirefoxAdapter();
await adapter._setPacViaSettings(
  {mode: 'all', listed: [], excluded: []},
  {host: '127.0.0.1', port: 45678},
);
adapter._installOnRequest();
let error = '';
try { await adapter.clearRouting(); } catch (e) { error = String(e.message || e); }
console.log(JSON.stringify({error, removed, stillInstalled: Boolean(adapter._onRequest)}));
""",
    )
    assert "retained this extension's proxy.settings PAC" in got["error"]
    assert got["removed"] == 0
    assert got["stillInstalled"] is True


def test_chromium_private_scope_failure_is_not_swallowed(tmp_path: Path) -> None:
    got = _run_node(
        tmp_path,
        """
let value = null;
const scopes = [];
globalThis.chrome = {
  runtime: {},
  extension: {isAllowedIncognitoAccess: async () => true},
  proxy: {settings: {
    set: async details => {
      scopes.push(details.scope);
      if (details.scope === 'incognito_persistent') throw new Error('private refused');
      value = details.value;
    },
    get: async () => ({levelOfControl: 'controlled_by_this_extension', value}),
  }},
};
const {ChromiumAdapter} = await import('./src/adapters/chromium.js');
const adapter = new ChromiumAdapter('chrome');
let error = '';
try {
  await adapter.applyRouting(
    {mode: 'all', listed: [], excluded: []},
    {host: '127.0.0.1', port: 45678},
  );
} catch (e) { error = String(e.message || e); }
console.log(JSON.stringify({error, scopes, incognitoRouting: adapter.incognitoRouting}));
""",
    )
    assert "private refused" in got["error"]
    assert got["scopes"] == ["regular", "incognito_persistent"]
    assert got["incognitoRouting"]["ok"] is False


def test_repeated_auth_request_records_rejection_not_acceptance(tmp_path: Path) -> None:
    got = _run_node(
        tmp_path,
        """
let listener = null;
globalThis.chrome = {
  runtime: {},
  webRequest: {onAuthRequired: {
    addListener: fn => { listener = fn; },
    removeListener: () => {},
  }},
};
const {ChromiumAdapter} = await import('./src/adapters/chromium.js');
const adapter = new ChromiumAdapter('chrome');
const credential = {
  endpoint: {host: '127.0.0.1', port: 45678},
  token: 'secret',
};
adapter.setCredential(credential);
adapter.installProxyAuth(async () => credential);
const details = {
  requestId: 'same-request',
  isProxy: true,
  scheme: 'basic',
  realm: 'wins-bridge',
  challenger: {host: '127.0.0.1', port: 45678},
};
const invoke = () => new Promise(resolve => listener(details, resolve));
const first = await invoke();
const second = await invoke();
console.log(JSON.stringify({first, second, stats: adapter.authStats}));
""",
    )
    assert got["first"]["authCredentials"]["password"] == "secret"
    assert got["second"] == {"cancel": True}
    assert got["stats"]["credentialsAnswered"] == 1
    assert got["stats"]["credentialsRejected"] == 1
    assert "authenticated" not in got["stats"]


def test_reconciles_coalesce_and_never_mutate_concurrently(tmp_path: Path) -> None:
    got = _run_node(
        tmp_path,
        """
globalThis.chrome = {
  runtime: {id: 'a'.repeat(32), getManifest: () => ({version: '1.0.0'})},
  action: {setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {}},
};
const {Controller} = await import('./src/background/controller.js');
const {defaultSettings} = await import('./src/core/rules.js');
const controller = new Controller();
let releaseFirst;
const firstGate = new Promise(resolve => { releaseFirst = resolve; });
let applications = 0;
let active = 0;
let maxActive = 0;
controller.adapter = {
  name: 'chrome',
  authStats: {credentialsMissing: 0, credentialsRejected: 0},
  blockTypesDropped: [],
  isAllowedIncognitoAccess: async () => false,
  proxyLevelOfControl: async () => 'controlled_by_this_extension',
  applyRouting: async () => {
    applications += 1;
    active += 1;
    maxActive = Math.max(maxActive, active);
    if (applications === 1) await firstGate;
    active -= 1;
    return 'pac';
  },
  applyPrivacyProtections: async () => ({webrtc: 'applied', prediction: 'applied'}),
  blockLayerTypes: async () => ({ok: true, types: ['main_frame'], dropped: []}),
  setBlockRules: async () => {},
  clearRouting: async () => {},
};
controller.settings = {...defaultSettings(), armed: true};
controller.hostConnected = true;
controller.hostSpoke = true;
controller.status = {
  status: 'connected',
  detail: '',
  proxyReady: true,
  proxyPort: 45678,
};
controller.statusAtMs = Date.now();
controller.credential = {
  endpoint: {kind: 'http', host: '127.0.0.1', port: 45678},
  token: 'A'.repeat(43),
};
controller.canAuthenticate = true;
controller.blockLayer = {ok: true, error: '', dropped: []};
const first = controller.reconcile();
while (applications === 0) await new Promise(resolve => setTimeout(resolve, 0));
const second = controller.reconcile();
const third = controller.reconcile();
releaseFirst();
await Promise.all([first, second, third]);
console.log(JSON.stringify({applications, maxActive, state: controller.current.state}));
""",
    )
    assert got["maxActive"] == 1
    assert got["applications"] == 2
    assert got["state"] == "protected"


def test_firefox_privacy_requires_success_value_and_exclusive_control(tmp_path: Path) -> None:
    got = _run_node(tmp_path, """
const own = 'controlled_by_this_extension';
let active;
const setting = name => ({
  set: async ({value}) => {
    const state = active[name];
    if (state.setError) throw new Error('set refused');
    state.requested = value;
    return state.setResult;
  },
  get: async () => {
    if (active[name].getError) throw new Error('readback refused');
    return active[name].got;
  },
});
globalThis.browser = {runtime: {}, privacy: {network: {
  webRTCIPHandlingPolicy: setting('webrtc'),
  networkPredictionEnabled: setting('prediction'),
}}};
const {FirefoxAdapter} = await import('./src/adapters/firefox.js');
const good = () => ({
  webrtc: {setResult: true, got: {value: 'proxy_only', levelOfControl: own}},
  prediction: {setResult: true, got: {value: false, levelOfControl: own}},
});
const outcomes = [];
for (const name of ['webrtc', 'prediction']) {
  for (const fault of ['false', 'undefined', 'wrongValue', 'otherControl', 'unknown', 'setError', 'getError']) {
    active = good();
    const state = active[name];
    if (fault === 'false') state.setResult = false;
    if (fault === 'undefined') state.setResult = undefined;
    if (fault === 'wrongValue') state.got.value = 'wrong';
    if (fault === 'otherControl') state.got.levelOfControl = 'controlled_by_other_extensions';
    if (fault === 'unknown') state.got = undefined;
    if (fault === 'setError') state.setError = true;
    if (fault === 'getError') state.getError = true;
    let error = '';
    try { await new FirefoxAdapter().applyPrivacyProtections(); }
    catch (e) { error = String(e.message || e); }
    outcomes.push({name, fault, error});
  }
}
active = good();
const success = await new FirefoxAdapter().applyPrivacyProtections();
console.log(JSON.stringify({outcomes, success, active}));
""")
    assert len(got["outcomes"]) == 14
    for result in got["outcomes"]:
        assert result["error"], result
        if result["fault"] not in {"setError", "getError"}:
            expected = ("Firefox WebRTC protection did not take effect" if result["name"] == "webrtc"
                        else "Firefox network prediction remained enabled")
            assert result["error"] == expected
    assert got["success"] == {"webrtc": "applied", "prediction": "applied"}
    assert got["active"]["webrtc"]["requested"] == "proxy_only"
    assert got["active"]["prediction"]["requested"] is False


def test_controller_refuses_protected_state_when_privacy_rejects(tmp_path: Path) -> None:
    got = _run_node(tmp_path, """
globalThis.chrome = {
  runtime: {id: 'a'.repeat(32), getManifest: () => ({version: '1.0.0'})},
  action: {setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {}},
};
const {Controller} = await import('./src/background/controller.js');
const {defaultSettings} = await import('./src/core/rules.js');
const controller = new Controller();
let blocks = 0;
controller.adapter = {
  name: 'firefox', authStats: {}, blockTypesDropped: [],
  isAllowedIncognitoAccess: async () => false,
  proxyLevelOfControl: async () => 'controlled_by_this_extension',
  applyRouting: async () => 'onRequest',
  applyPrivacyProtections: async () => { throw new Error('Firefox WebRTC protection did not take effect'); },
  blockLayerTypes: async () => ({ok: true, types: ['main_frame'], dropped: []}),
  setBlockRules: async rules => { blocks = rules.length; },
  clearRouting: async () => {},
};
controller.settings = {...defaultSettings(), armed: true};
controller.hostConnected = true;
controller.hostSpoke = true;
controller.status = {status: 'connected', detail: '', proxyReady: true, proxyPort: 45678};
controller.statusAtMs = Date.now();
controller.credential = {endpoint: {kind: 'http', host: '127.0.0.1', port: 45678}, token: 'A'.repeat(43)};
controller.canAuthenticate = true;
controller.blockLayer = {ok: true, error: '', dropped: []};
await controller.reconcile();
console.log(JSON.stringify({state: controller.current.state, blocks}));
""")
    assert got["state"] != "protected"
    assert got["blocks"] > 0


def test_block_failure_uses_sink_without_clearing_prior_route(tmp_path: Path) -> None:
    got = _run_node(
        tmp_path,
        """
globalThis.chrome = {
  runtime: {id: 'a'.repeat(32), getManifest: () => ({version: '1.0.0'})},
  action: {setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {}},
};
const {Controller} = await import('./src/background/controller.js');
const {defaultSettings} = await import('./src/core/rules.js');
const controller = new Controller();
let clears = 0;
let sinks = 0;
controller.adapter = {
  name: 'chrome',
  authStats: {},
  blockTypesDropped: [],
  isAllowedIncognitoAccess: async () => false,
  proxyLevelOfControl: async () => 'controlled_by_this_extension',
  blockLayerTypes: async () => ({ok: true, types: ['main_frame'], dropped: []}),
  setBlockRules: async () => { throw new Error('DNR ignored'); },
  installFailClosedSink: async () => { sinks += 1; return 'pac-sink'; },
  clearRouting: async () => { clears += 1; },
};
controller.settings = {...defaultSettings(), armed: true};
await controller.reconcile();
console.log(JSON.stringify({clears, sinks, state: controller.current.state}));
""",
    )
    assert got["clears"] == 0
    assert got["sinks"] >= 1
    assert got["state"] == "not_enforcing"
