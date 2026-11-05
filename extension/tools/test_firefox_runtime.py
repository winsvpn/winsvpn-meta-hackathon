"""Firefox adapter fixtures. These do not claim live browser or DNS capture proof."""
from pathlib import Path

from test_browser_enforcement_regressions import _run_node


ROUTING_FIXTURE = """
import assert from 'node:assert/strict';
let listener = null;
let registrations = 0;
let permitted = true;
let pac = '';
globalThis.browser = {
  runtime: {},
  dns: {resolve: () => { throw new Error('local DNS must not run'); }},
  permissions: {contains: async () => permitted},
  proxy: {
    onRequest: {
      addListener: fn => { listener = fn; registrations++; },
      removeListener: fn => { if (listener === fn) listener = null; },
      hasListener: fn => fn === listener,
    },
    settings: {
      set: async ({value}) => { pac = value.autoConfigUrl; return true; },
      clear: async () => { pac = ''; return true; },
      get: async () => ({levelOfControl: 'controllable_by_this_extension'}),
    },
  },
};
const {FirefoxAdapter} = await import('./src/adapters/firefox.js');
const adapter = new FirefoxAdapter();
const settings = {armed: true, mode: 'listed', listed: ['routed.test'], excluded: []};
const endpoint = {kind: 'http', host: '127.0.0.1', port: 45678};
const request = {url: 'https://sub.routed.test/path'};
const sink = [{type: 'http', host: '127.0.0.1', port: 1}, null];
"""


AUTH_FIXTURE = """
import assert from 'node:assert/strict';
let listener = null;
let failRegistration = false;
let permitted = true;
globalThis.browser = {
  runtime: {},
  permissions: {contains: async () => permitted},
  webRequest: {onAuthRequired: {
    addListener: (fn, filter, options) => {
      if (failRegistration) throw new Error('registration refused');
      assert.deepEqual(filter, {urls: ['<all_urls>']});
      assert.deepEqual(options, ['asyncBlocking']);
      listener = fn;
    },
    removeListener: fn => { if (listener === fn) listener = null; },
    hasListener: fn => fn === listener,
  }},
};
const {FirefoxAdapter} = await import('./src/adapters/firefox.js');
const adapter = new FirefoxAdapter();
const credential = {endpoint: {host: '127.0.0.1', port: 45678}, token: 'fixture-a'};
const challenge = {isProxy: true, requestId: 'request-1', scheme: 'basic',
  realm: 'wins-bridge', challenger: {host: '127.0.0.1', port: 45678}};
const ask = details => new Promise(resolve => listener(details, resolve));
"""


def test_firefox_onrequest_rejects_nonloopback_and_invalid_ports(tmp_path: Path) -> None:
    got = _run_node(tmp_path, ROUTING_FIXTURE + """
adapter._installOnRequest();
for (const bad of [
  {host: 'proxy.test', port: 45678},
  {host: '192.0.2.1', port: 45678},
  {host: '127.000.000.001', port: 45678},
  {host: '127.0.0.1', port: 0},
  {host: '127.0.0.1', port: 65536},
  {host: '127.0.0.1', port: '45678'},
]) {
  adapter._live = {settings, endpoint: bad};
  assert.deepEqual(listener(request), sink);
}
adapter._live = {settings, endpoint};
assert.deepEqual(listener(request), [{type: 'http', host: endpoint.host, port: endpoint.port}, null]);
assert.deepEqual(listener({url: 'bad URL'}), sink);
console.log(JSON.stringify({ok: true}));
""")
    assert got == {"ok": True}


def test_firefox_primed_routing_covers_startup_disconnect_and_reconnect(tmp_path: Path) -> None:
    got = _run_node(tmp_path, ROUTING_FIXTURE + """
let readySettings = settings;
let failReady = false;
assert.equal(adapter.installPrimedRouting(async () => {
  if (failReady) throw new Error('initialization failed');
  return readySettings;
}), true);
const primed = listener;
assert.deepEqual(await primed(request), sink);
await adapter.applyRouting(settings, endpoint);
assert.deepEqual(await primed(request), [{type: 'http', host: endpoint.host, port: endpoint.port}, null]);
assert.deepEqual(await primed({url: 'https://unlisted.test/'}), {type: 'direct'});
await adapter.clearRouting();
assert.deepEqual(await primed(request), sink);
const next = {...endpoint, port: endpoint.port + 1};
await adapter.applyRouting(settings, next);
assert.deepEqual(await primed(request), [{type: 'http', host: next.host, port: next.port}, null]);
await adapter.installFailClosedSink();
assert.deepEqual(await primed(request), sink);
await adapter.clearRouting();
failReady = true;
assert.deepEqual(await primed(request), sink);
failReady = false;
readySettings = {...settings, armed: false};
assert.deepEqual(await primed(request), {type: 'direct'});
assert.equal(registrations, 1);
console.log(JSON.stringify({ok: true}));
""")
    assert got == {"ok": True}


def test_firefox_permission_loss_pac_does_not_resolve_or_fall_back(tmp_path: Path) -> None:
    got = _run_node(tmp_path, ROUTING_FIXTURE + """
const vm = await import('node:vm');
await adapter.applyRouting(settings, endpoint);
permitted = false;
assert.equal(await adapter.applyRouting(settings, endpoint), 'settings');
assert.equal(listener, null);
assert.ok(pac.startsWith('data:application/x-ns-proxy-autoconfig;base64,'));
const context = {};
let dnsCalls = 0;
for (const name of ['dnsResolve', 'dnsResolveEx', 'isResolvable', 'isInNet', 'myIpAddress']) {
  context[name] = () => { dnsCalls++; throw new Error('DNS helper called'); };
}
vm.createContext(context);
vm.runInContext(atob(pac.split(',')[1]), context);
assert.equal(context.FindProxyForURL(request.url, 'sub.routed.test'), 'PROXY 127.0.0.1:45678');
assert.equal(context.FindProxyForURL('https://unlisted.test/', 'unlisted.test'), 'DIRECT');
assert.equal(dnsCalls, 0);
await adapter.applyRouting(settings, {host: 'proxy.test', port: 45678});
vm.runInContext(atob(pac.split(',')[1]), context);
assert.equal(context.FindProxyForURL(request.url, 'sub.routed.test'), 'PROXY 127.0.0.1:1');
permitted = true;
assert.equal(await adapter.applyRouting(settings, endpoint), 'onRequest');
assert.equal(pac, '');
assert.deepEqual(listener(request), [{type: 'http', host: endpoint.host, port: endpoint.port}, null]);
console.log(JSON.stringify({ok: true}));
""")
    assert got == {"ok": True}


def test_firefox_revoked_credential_cannot_return_from_pending_resolver(tmp_path: Path) -> None:
    got = _run_node(tmp_path, AUTH_FIXTURE + """
let finish;
adapter.setCredential(credential);
adapter.installProxyAuth(() => new Promise(resolve => { finish = resolve; }));
const pending = ask(challenge);
await Promise.resolve();
adapter.setCredential(null);
finish(credential);
assert.deepEqual(await pending, {cancel: true});
assert.equal(adapter.authStats.credentialsAnswered, 0);
assert.equal(adapter.authStats.credentialsMissing, 1);
console.log(JSON.stringify({ok: true}));
""")
    assert got == {"ok": True}


def test_firefox_reconnect_uses_current_credential_and_resets_rejection(tmp_path: Path) -> None:
    got = _run_node(tmp_path, AUTH_FIXTURE + """
let resolveCredential = async () => credential;
adapter.setCredential(credential);
adapter.installProxyAuth(() => resolveCredential());
assert.equal((await ask(challenge)).authCredentials.password, credential.token);
assert.deepEqual(await ask(challenge), {cancel: true});
let finish;
resolveCredential = () => new Promise(resolve => { finish = resolve; });
const pending = ask({...challenge, requestId: 'request-2'});
await Promise.resolve();
adapter.setCredential(null);
const next = {...credential, token: 'fixture-b'};
adapter.setCredential(next);
finish(credential);
assert.equal((await pending).authCredentials.password, next.token);
assert.equal(adapter.authStats.credentialsRejected, 0);
assert.deepEqual(await ask({...challenge, isProxy: false}), {});
console.log(JSON.stringify({ok: true}));
""")
    assert got == {"ok": True}


def test_firefox_auth_capability_requires_installed_listener_and_permission(tmp_path: Path) -> None:
    got = _run_node(tmp_path, AUTH_FIXTURE + """
failRegistration = true;
assert.equal(adapter.installProxyAuth(async () => credential), false);
assert.equal(await adapter.canAuthenticate(), false);
failRegistration = false;
assert.equal(adapter.installProxyAuth(async () => credential), true);
assert.equal(await adapter.canAuthenticate(), true);
permitted = false;
assert.equal(await adapter.canAuthenticate(), false);
permitted = true;
adapter.removeProxyAuth();
assert.equal(await adapter.canAuthenticate(), false);
console.log(JSON.stringify({ok: true}));
""")
    assert got == {"ok": True}
