"""Execute the merged Safari native-status integration in the shared sources."""
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def test_native_status_refresh_and_external_host_refusal(tmp_path):
    shutil.copytree(ROOT / 'extension/src', tmp_path / 'extension/src')
    script = r'''
import assert from 'node:assert/strict';
let reply, calls = 0, external = 0;
globalThis.chrome = {runtime: {
  getURL: () => 'safari-web-extension://fixture/',
  sendNativeMessage: async () => { calls++; return reply; },
  connectNative: () => { external++; throw Error('external host attempted'); },
}};
const {SafariAdapter, parseSafariCapability} = await import('./extension/src/adapters/safari.js');
const {Controller} = await import('./extension/src/background/controller.js');
const active = {v:1, type:'capability', routing:false, reason:'native_app_managed',
  platform:'macos', nativeAuthenticated:true, nativeRouting:true};
assert.equal(parseSafariCapability(active).ok, false);
assert.match(parseSafariCapability(active).reason, /checks|ready/);
for (const delta of [ {v:true}, {routing:true}, {nativeAuthenticated:1}, {nativeRouting:1},
  {nativeAuthenticated:false}, {platform:'ios'}, {platform:'other'} ]) {
  assert.equal(parseSafariCapability({...active,...delta}), null);
}
assert.match(parseSafariCapability({...active,platform:'ios',nativeAuthenticated:false,nativeRouting:false}).reason,
  /does not route traffic/);
assert.ok(parseSafariCapability({v:1,type:'capability',routing:false,reason:'no_native_routing_surface'}));
const adapter = new SafariAdapter();
reply = active;
assert.match((await adapter.routingSurface()).reason, /ready/);
reply = {...active,nativeAuthenticated:false,nativeRouting:false};
assert.match((await adapter.routingSurface()).reason, /No authenticated/);
assert.equal(calls,2);
const controller = new Controller();
controller.adapter = adapter;
controller.adapter.isAllowedIncognitoAccess = async () => false;
controller.paintBadge = async () => {};
await controller.reconcileOnce(controller.reconcileGeneration);
assert.match(controller.current.detail,/No authenticated/);
reply = active;
await controller.reconcileOnce(controller.reconcileGeneration);
assert.match(controller.current.detail,/ready/);
assert.equal(controller.current.failClosed,false);
assert.equal(controller.routingSurface.ok,false);
controller.openHost();
assert.equal(external,0);
assert.equal(calls,4);
console.log('PASS: native status schema, refreshed state and external-host refusal');
'''
    result = subprocess.run(['node', '--input-type=module', '--eval', script], cwd=tmp_path,
        capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert 'PASS:' in result.stdout
