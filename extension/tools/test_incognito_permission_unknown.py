"""An unknown private-window permission is unprotected, on every adapter.

EXT2 Turn 2. `BaseAdapter.isAllowedIncognitoAccess()` used to turn a failed
permission query into `false`, which the Chromium adapter read as "private
windows are not this extension's business". After a private-scope takeover the
controller then checked only the regular scope, published PROTECTED with
failClosed false, and removed every block rule. The Firefox adapter never reads
the permission for control at all, so the fix has to hold in the controller as
well as in the adapters. Each scenario here runs the real adapter and the real
controller against a fake browser namespace.
"""
import json

import pytest

import test_browser_enforcement_regressions as fixture

UNVERIFIED = "private-window permission could not be verified"


def run_node(tmp_path, script):
    return fixture._run_node(tmp_path, script)


# `permission` is the value the browser's query resolves to; the string
# 'throw' makes it reject instead. `hits` counts queries so that a scenario can
# fail only one of them.
PERMISSION = """
let permission = true;
let failQuery = 0;
let hits = 0;
const isAllowedIncognitoAccess = async () => {
  hits += 1;
  if (permission === 'throw' || hits === failQuery) throw new Error('permission query failed');
  return permission;
};
"""

CONTROLLER = """
const {Controller} = await import('./src/background/controller.js');
const {defaultSettings} = await import('./src/core/rules.js');
let rules = [];
const writes = [];
adapter.blockLayerTypes = async () => ({ok: true, types: ['main_frame'], dropped: []});
adapter.setBlockRules = async value => { rules = value; writes.push(value.length); };
const controller = new Controller();
controller.adapter = adapter;
const painted = [];
controller.paintBadge = async () => {
  painted.push({state: controller.current.state, failClosed: controller.current.failClosed,
                rules: rules.length});
};
controller.settings = {...defaultSettings(), armed: true};
controller.hostConnected = true;
controller.hostSpoke = true;
controller.status = {status: 'connected', detail: 'none', proxyReady: true, proxyPort: 45678};
controller.statusAtMs = Date.now();
controller.credential = {endpoint: {kind: 'http', host: '127.0.0.1', port: 45678}, token: 'A'.repeat(43)};
controller.canAuthenticate = true;
controller.blockLayer = {ok: true, error: '', dropped: []};
const view = () => ({state: controller.current.state, failClosed: controller.current.failClosed,
                     detail: controller.current.detail, rules: rules.length,
                     allowed: controller.snapshot().incognitoAllowed,
                     routing: controller.routing, pacKey: controller.applied.pacKey});
"""

CHROMIUM = PERMISSION + """
let levels = {regular: 'controlled_by_this_extension', private: 'controlled_by_this_extension'};
let reads = [];
let scopeWrites = [];
const privacy = value => ({
  set: async ({scope}) => { scopeWrites.push(scope); }, clear: async () => {},
  get: async () => ({value, levelOfControl: 'controlled_by_this_extension'}),
});
globalThis.chrome = {
  runtime: {}, extension: {isAllowedIncognitoAccess},
  proxy: {settings: {
    get: async query => {
      const scope = query.incognito ? 'private' : 'regular';
      reads.push(scope);
      return {levelOfControl: levels[scope]};
    },
    set: async ({scope}) => { scopeWrites.push(scope); },
    clear: async ({scope}) => { scopeWrites.push(`clear:${scope}`); },
  }},
  privacy: {network: {
    webRTCIPHandlingPolicy: privacy('disable_non_proxied_udp'),
    networkPredictionEnabled: privacy(false),
  }},
};
const {ChromiumAdapter} = await import('./src/adapters/chromium.js');
const adapter = new ChromiumAdapter(BROWSER);
adapter.applyRouting = async () => 'pac';
adapter.clearRouting = async () => {};
"""

FIREFOX = PERMISSION + """
const listeners = new Set();
const privacy = value => ({
  set: async () => true, clear: async () => true,
  get: async () => ({value, levelOfControl: 'controlled_by_this_extension'}),
});
globalThis.browser = {
  runtime: {}, extension: {isAllowedIncognitoAccess},
  permissions: {contains: async () => true},
  proxy: {
    onRequest: {addListener: f => listeners.add(f), removeListener: f => listeners.delete(f),
                hasListener: f => listeners.has(f)},
    settings: {get: async () => ({levelOfControl: 'controllable_by_this_extension', value: {}}),
               set: async () => true, clear: async () => false},
  },
  privacy: {network: {webRTCIPHandlingPolicy: privacy('proxy_only'),
                      networkPredictionEnabled: privacy(false)}},
};
const {FirefoxAdapter} = await import('./src/adapters/firefox.js');
const adapter = new FirefoxAdapter();
"""


def chromium(browser):
    return CHROMIUM.replace("BROWSER", json.dumps(browser))


@pytest.mark.parametrize("answer,expected", [
    ("'throw'", None),
    ("undefined", None),
    ("null", None),
    ("'yes'", None),
    ("1", None),
    ("true", True),
    ("false", False),
])
def test_base_adapter_reports_unknown_permission_as_null(tmp_path, answer, expected):
    result = run_node(tmp_path, PERMISSION + f"""
permission = {answer};
globalThis.chrome = {{runtime: {{}}, extension: {{isAllowedIncognitoAccess}}}};
const {{BaseAdapter}} = await import('./src/adapters/base.js');
const got = await new BaseAdapter('test').isAllowedIncognitoAccess();
console.log(JSON.stringify({{got: got === undefined ? 'undefined' : got}}));
""")
    assert result["got"] is expected


def test_base_adapter_without_the_permission_api_is_unknown(tmp_path):
    result = run_node(tmp_path, """
globalThis.chrome = {runtime: {}};
const {BaseAdapter} = await import('./src/adapters/base.js');
console.log(JSON.stringify({got: await new BaseAdapter('test').isAllowedIncognitoAccess()}));
""")
    assert result["got"] is None


@pytest.mark.parametrize("browser", ["chrome", "edge"])
@pytest.mark.parametrize("failure", ["'throw'", "undefined"])
def test_chromium_private_takeover_with_unknown_permission_fails_closed(
        tmp_path, browser, failure):
    """Astra's reproduction: protected, then the private scope is taken over."""
    result = run_node(tmp_path, chromium(browser) + CONTROLLER + f"""
await controller.reconcile();
const initial = view();
levels.private = 'controlled_by_other_extensions';
permission = {failure};
reads = [];
await controller.reconcile();
console.log(JSON.stringify({{initial, after: view(), reads, private: adapter.incognitoRouting}}));
""")
    assert result["initial"]["state"] == "protected"
    assert result["initial"]["rules"] == 0
    after = result["after"]
    assert after["state"] != "protected"
    assert after["failClosed"] is True
    assert after["rules"] > 0
    assert after["allowed"] is None
    assert after["pacKey"] is None
    assert result["private"] == {"required": None, "ok": False, "error": UNVERIFIED}


@pytest.mark.parametrize("browser", ["chrome", "edge"])
def test_chromium_unknown_permission_allows_only_verified_regular_sink(
        tmp_path, browser):
    result = run_node(tmp_path, chromium(browser) + CONTROLLER + """
permission = 'throw';
let stored = null;
chrome.proxy.settings.set = async ({value, scope}) => {
  scopeWrites.push(scope);
  stored = value;
};
chrome.proxy.settings.get = async () => ({
  levelOfControl: 'controlled_by_this_extension',
  value: stored,
});
const errors = [];
for (const call of ['applyPrivacyProtections', 'releasePrivacyProtections']) {
  try { await adapter[call](); errors.push(''); }
  catch (error) { errors.push(error.message); }
}
const writesBeforeSink = scopeWrites.slice();
adapter.setBlockRules = async () => { throw new Error('rules refused'); };
await controller.reconcile();
console.log(JSON.stringify({
  errors, writesBeforeSink, scopeWrites, stored,
  after: view(), private: adapter.incognitoRouting,
  level: controller.snapshot().proxyLevelOfControl,
}));
""")
    assert result["errors"] == [UNVERIFIED] * 2
    assert result["writesBeforeSink"] == []
    assert result["scopeWrites"]
    assert set(result["scopeWrites"]) == {"regular"}
    assert result["stored"] == {
        "mode": "pac_script",
        "pacScript": {
            "data": 'function FindProxyForURL(){return "PROXY 127.0.0.1:1";}',
            "mandatory": True,
        },
    }
    assert result["after"]["state"] == "not_enforcing"
    assert result["after"]["rules"] == 0
    assert result["after"]["allowed"] is None
    assert result["level"] == "unknown"
    assert result["private"] == {
        "required": None,
        "ok": False,
        "error": UNVERIFIED,
    }


@pytest.mark.parametrize("browser", ["chrome", "edge"])
def test_chromium_unknown_permission_sink_is_partial_and_ordinary_writes_refused(
        tmp_path, browser):
    """EXT2 Turn 3: the regular-scope sink is verified, never reported complete."""
    result = run_node(tmp_path, chromium(browser).replace(
        "adapter.applyRouting = async () => 'pac';\n"
        "adapter.clearRouting = async () => {};\n", "") + CONTROLLER + """
permission = 'throw';
let stored = null;
let readbackDiffers = false;
chrome.proxy.settings.set = async ({value, scope}) => { scopeWrites.push(scope); stored = value; };
chrome.proxy.settings.get = async () => ({
  levelOfControl: 'controlled_by_this_extension',
  value: readbackDiffers ? {mode: 'direct'} : stored,
});
chrome.proxy.settings.clear = async ({scope}) => { scopeWrites.push(`clear:${scope}`); };
const ordinary = [];
for (const call of [
  () => adapter.applyRouting(controller.settings, controller.credential.endpoint),
  () => adapter.clearRouting(),
]) {
  try { await call(); ordinary.push(''); } catch (error) { ordinary.push(error.message); }
}
const writesBeforeSink = scopeWrites.slice();
let sinkError = '';
try { await adapter.installFailClosedSink(); } catch (error) { sinkError = error.message; }
const sinkWrites = scopeWrites.slice();
adapter.setBlockRules = async () => { throw new Error('rules refused'); };
await controller.reconcile();
const lastError = controller.lastError;
readbackDiffers = true;
let readbackError = '';
try { await adapter.installFailClosedSink(); } catch (error) { readbackError = error.message; }
console.log(JSON.stringify({ordinary, writesBeforeSink, sinkError, sinkWrites, lastError,
                            readbackError}));
""")
    assert result["ordinary"] == [UNVERIFIED, UNVERIFIED]
    assert result["writesBeforeSink"] == []
    assert result["sinkError"] == UNVERIFIED
    assert result["sinkWrites"] == ["regular"]
    assert "backup sink also failed" in result["lastError"]
    assert UNVERIFIED in result["lastError"]
    assert "verified sink" not in result["lastError"]
    assert "proxy scope regular readback differed" in result["readbackError"]


@pytest.mark.parametrize("family", ["chrome", "edge", "firefox"])
def test_unknown_permission_and_failed_block_rules_name_the_routing_failure(
        tmp_path, family):
    """EXT2 Turn 4: the detail never calls the situation underneath protected."""
    setup = FIREFOX if family == "firefox" else chromium(family)
    result = run_node(tmp_path, setup + CONTROLLER + """
permission = 'throw';
adapter.setBlockRules = async () => { throw new Error('rules refused'); };
await controller.reconcile();
await controller.reconcile();
console.log(JSON.stringify({after: view(), snapshot: controller.snapshot()}));
""")
    after = result["after"]
    assert after["state"] == "not_enforcing"
    assert after["failClosed"] is True
    assert after["detail"] == (
        "the block rules did not install: rules refused; "
        f"the situation underneath is routing_failed: {UNVERIFIED}"
    )
    assert "underneath is protected" not in after["detail"]
    assert result["snapshot"]["detail"] == after["detail"]


def test_failed_block_rules_report_the_whole_situation_underneath(tmp_path):
    """The ladder alone is not the situation underneath; routing and auth are."""
    result = run_node(tmp_path, f"const UNVERIFIED = {json.dumps(UNVERIFIED)};\n" + """
const {deriveState} = await import('./src/core/state.js');
const base = {
  armed: true, hostConnected: true, hostSpoke: true, hostOpenedAtMs: 1,
  status: {status: 'connected', detail: 'none', proxyReady: true, proxyPort: 45678},
  statusAtMs: 1000, nowMs: 1000, levelOfControl: 'controlled_by_this_extension',
  credential: {endpoint: {kind: 'http', host: '127.0.0.1', port: 45678}, token: 'A'.repeat(43)},
  canAuthenticate: true, routingSurface: {ok: true, reason: ''},
  blockLayer: {ok: false, error: 'refused'},
};
const derive = extra => deriveState({...base, ...extra});
console.log(JSON.stringify({
  unverified: derive({levelOfControl: 'unknown', routing: {ok: false, error: UNVERIFIED}}),
  refused: derive({routing: {ok: false, error: 'proxy.settings refused'}}),
  lost: derive({levelOfControl: 'controllable_by_this_extension', routing: {ok: true, error: ''}}),
  unauthenticated: derive({routing: {ok: true, error: ''},
                           authStats: {credentialsRejected: 2, credentialsMissing: 0}}),
  noHost: derive({hostConnected: false, routing: {ok: false, error: 'proxy.settings refused'}}),
  routed: derive({routing: {ok: true, error: ''}}),
  unrouted: derive({}),
  blockOk: derive({blockLayer: {ok: true, error: ''}, routing: {ok: false, error: 'x'}}),
}));
""")
    prefix = "the block rules did not install: refused; the situation underneath is "
    expected = {
        "unverified": f"routing_failed: {UNVERIFIED}",
        "refused": "routing_failed: proxy.settings refused",
        "lost": "routing_failed: proxy control changed to controllable_by_this_extension",
        "unauthenticated": (
            "routing_unauthenticated: 2 credential rejection(s) and 0 missing-credential "
            "request(s) were observed at the desktop proxy"
        ),
        "noHost": "no_host",
        "routed": "protected",
        "unrouted": "protected",
    }
    for name, tail in expected.items():
        assert result[name]["state"] == "not_enforcing", name
        assert result[name]["failClosed"] is True, name
        assert result[name]["endpoint"] is None, name
        assert result[name]["detail"] == prefix + tail, name
    assert result["blockOk"]["state"] == "routing_failed"
    assert result["blockOk"]["detail"] == "x"


@pytest.mark.parametrize("browser", ["chrome", "edge"])
def test_chromium_fresh_start_with_unknown_permission_never_protects(tmp_path, browser):
    result = run_node(tmp_path, chromium(browser).replace(
        "adapter.applyRouting = async () => 'pac';\n", "") + CONTROLLER + """
permission = 'throw';
for (let i = 0; i < 3; i += 1) await controller.reconcile();
console.log(JSON.stringify({after: view(), painted, writes, scopeWrites}));
""")
    assert result["after"]["failClosed"] is True
    assert result["after"]["rules"] > 0
    assert all(p["state"] != "protected" for p in result["painted"])
    assert 0 not in result["writes"]
    assert result["scopeWrites"] == []


def test_chromium_controller_query_failure_alone_fails_closed(tmp_path):
    """The adapter's own query succeeds; only the controller's second one fails."""
    result = run_node(tmp_path, chromium("chrome") + CONTROLLER + """
await controller.reconcile();
const initial = view().state;
hits = 0;
failQuery = 2;
await controller.reconcile();
console.log(JSON.stringify({initial, after: view()}))
""")
    assert result["initial"] == "protected"
    assert result["after"]["state"] != "protected"
    assert result["after"]["failClosed"] is True
    assert result["after"]["rules"] > 0


@pytest.mark.parametrize("failure", ["'throw'", "undefined"])
def test_firefox_unknown_permission_never_publishes_protected(tmp_path, failure):
    """Firefox's control check ignores the permission; the controller must not."""
    result = run_node(tmp_path, FIREFOX + CONTROLLER + f"""
permission = {failure};
for (let i = 0; i < 4; i += 1) await controller.reconcile();
console.log(JSON.stringify({{after: view(), painted, writes}}));
""")
    after = result["after"]
    assert after["state"] == "routing_failed"
    assert after["failClosed"] is True
    assert after["detail"] == UNVERIFIED
    assert after["rules"] > 0
    assert after["allowed"] is None
    assert all(p["state"] != "protected" for p in result["painted"])
    assert all(p["rules"] > 0 for p in result["painted"])
    assert 0 not in result["writes"]


def test_firefox_protected_then_unknown_permission_fails_closed(tmp_path):
    result = run_node(tmp_path, FIREFOX + CONTROLLER + """
await controller.reconcile();
const initial = view();
painted.length = 0;
writes.length = 0;
permission = 'throw';
await controller.reconcile();
await controller.reconcile();
console.log(JSON.stringify({initial, after: view(), painted, writes}));
""")
    assert result["initial"]["state"] == "protected"
    assert result["after"]["failClosed"] is True
    assert result["after"]["rules"] > 0
    assert all(p["state"] != "protected" for p in result["painted"])
    assert 0 not in result["writes"]


def test_firefox_unknown_permission_never_reports_proxy_control(tmp_path):
    """The block layer also fails, so the controller publishes the level it read."""
    result = run_node(tmp_path, FIREFOX + CONTROLLER + """
await controller.reconcile();
const initial = view().state;
permission = 'throw';
adapter.setBlockRules = async () => { throw new Error('rules refused'); };
await controller.reconcile();
const snap = controller.snapshot();
console.log(JSON.stringify({initial, state: snap.state, failClosed: snap.failClosed,
                            level: snap.proxyLevelOfControl, mechanism: snap.routingMechanism}));
""")
    assert result["initial"] == "protected"
    assert result["state"] != "protected"
    assert result["failClosed"] is True
    assert result["mechanism"] == "sink"
    assert result["level"] == "unknown"


@pytest.mark.parametrize("family", ["chrome", "edge", "firefox"])
def test_restored_permission_recovers_in_one_reconcile(tmp_path, family):
    setup = FIREFOX if family == "firefox" else chromium(family)
    result = run_node(tmp_path, setup + CONTROLLER + """
permission = 'throw';
await controller.reconcile();
await controller.reconcile();
const failed = view();
permission = true;
await controller.reconcile();
console.log(JSON.stringify({failed, recovered: view()}));
""")
    assert result["failed"]["failClosed"] is True
    assert result["failed"]["rules"] > 0
    recovered = result["recovered"]
    assert recovered["state"] == "protected"
    assert recovered["rules"] == 0
    assert recovered["allowed"] is True
    assert recovered["routing"] == {"ok": True, "error": ""}
    assert recovered["pacKey"] is not None


@pytest.mark.parametrize("family", ["chrome", "edge", "firefox"])
def test_confirmed_denial_keeps_regular_routing(tmp_path, family):
    setup = FIREFOX if family == "firefox" else chromium(family)
    result = run_node(tmp_path, setup + CONTROLLER + """
permission = false;
await controller.reconcile();
await controller.reconcile();
console.log(JSON.stringify(view()));
""")
    assert result["state"] == "protected"
    assert result["rules"] == 0
    assert result["allowed"] is False


def test_unknown_permission_while_disarmed_is_not_a_routing_failure(tmp_path):
    result = run_node(tmp_path, FIREFOX + CONTROLLER + """
permission = 'throw';
controller.settings = {...controller.settings, armed: false};
await controller.reconcile();
const first = view();
// The second pass takes the cached OFF cleanup, which resets nothing.
await controller.reconcile();
console.log(JSON.stringify({first, second: view(),
                            snapshotRouting: controller.snapshot().routing}));
""")
    for name in ("first", "second"):
        assert result[name]["state"] == "off"
        assert result[name]["rules"] == 0
        assert result[name]["routing"] == {"ok": None, "error": ""}
    assert result["snapshotRouting"] == {"ok": None, "error": ""}


def test_safari_unknown_permission_stays_without_a_routing_surface(tmp_path):
    """Safari routes nothing itself, so it is never protected and blocks nothing."""
    result = run_node(tmp_path, PERMISSION + """
permission = 'throw';
globalThis.browser = {
  runtime: {getURL: () => 'safari-web-extension://x/', sendNativeMessage: async () => ({
    v: 1, type: 'capability', routing: false, reason: 'native_app_managed',
    platform: 'macos', nativeAuthenticated: true, nativeRouting: true})},
  extension: {isAllowedIncognitoAccess},
};
const {SafariAdapter} = await import('./src/adapters/safari.js');
const adapter = new SafariAdapter();
""" + CONTROLLER + """
await controller.reconcile();
console.log(JSON.stringify(view()));
""")
    assert result["state"] == "no_routing_surface"
    assert result["failClosed"] is False
    assert result["allowed"] is None
    assert result["routing"] == {"ok": None, "error": ""}


FAKE_DOM = """
const elements = new Map();
const element = id => {
  if (!elements.has(id)) {
    elements.set(id, {
      id, textContent: '', className: '', hidden: false, disabled: false, value: '',
      checked: false, style: {}, dataset: {}, children: [],
      classList: {add() {}, remove() {}, toggle() {}},
      addEventListener() {}, appendChild(child) { this.children.push(child); return child; },
      replaceChildren(...kids) { this.children = kids; }, setAttribute() {}, removeAttribute() {},
      querySelectorAll: () => [], querySelector: () => null, append() {}, focus() {},
    });
  }
  return elements.get(id);
};
let created = 0;
globalThis.document = {
  documentElement: {lang: ''}, title: '',
  getElementById: element,
  createElement: () => element(`created-${created += 1}`),
  querySelectorAll: () => [], querySelector: () => null, addEventListener() {},
};
globalThis.window = globalThis;
"""

SNAPSHOT = """
const snapshot = {
  state: 'routing_failed', detail: 'x', failClosed: true,
  settings: {armed: true, mode: 'all', listed: [], excluded: []},
  routingSurface: {ok: true, reason: ''}, incognitoAllowed: ALLOWED,
  incognitoRouting: {required: null, ok: false, error: 'x'}, privacy: {},
  blockLayer: {ok: true, error: '', dropped: []}, routing: {ok: false, error: 'x'},
  browser: 'chrome', canAuthenticate: true, lastError: '', authStats: null,
  nodes: [], proxyLevelOfControl: 'unknown',
};
globalThis.chrome = {
  runtime: {getURL: () => 'chrome-extension://x/', sendMessage: async () => snapshot,
            onMessage: {addListener() {}}, openOptionsPage() {}},
  storage: {local: {get: async () => ({}), set: async () => {}},
            onChanged: {addListener() {}}},
  tabs: {query: async () => []},
  permissions: {contains: async () => true, request: async () => true},
};
"""


@pytest.mark.parametrize("page,element", [
    ("popup", "incognitoNote"),
    ("options", "liveIncognito"),
])
@pytest.mark.parametrize("allowed,expected", [
    ("null", "Private-window permission could not be verified."),
    ("false", "not covered"),
])
def test_ui_names_an_unverified_permission(tmp_path, page, element, allowed, expected):
    result = run_node(tmp_path, FAKE_DOM + SNAPSHOT.replace("ALLOWED", allowed) + f"""
await import('./src/ui/{page}.js');
for (let i = 0; i < 20; i += 1) await new Promise(resolve => setTimeout(resolve, 5));
console.log(JSON.stringify({{text: element({json.dumps(element)}).textContent}}));
""")
    assert expected in result["text"]
