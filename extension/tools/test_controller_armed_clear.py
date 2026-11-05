"""Regression proposed alongside the shared controller correction."""
import test_browser_enforcement_regressions as fixture


def test_armed_clear_failure_replaces_stale_protected_state(tmp_path):
    result = fixture._run_node(tmp_path, """
globalThis.chrome = {runtime: {}};
const {Controller} = await import('./src/background/controller.js');
const {defaultSettings} = await import('./src/core/rules.js');
const controller = new Controller();
let failClear = false;
let rules = [];
controller.adapter = {
  authStats: {},
  proxyLevelOfControl: async () => 'controlled_by_this_extension',
  isAllowedIncognitoAccess: async () => false,
  blockLayerTypes: async () => ({ok: true, types: ['main_frame'], dropped: []}),
  setBlockRules: async value => { rules = value; },
  applyRouting: async () => 'pac',
  applyPrivacyProtections: async () => ({webrtc: 'applied', prediction: 'applied'}),
  clearRouting: async () => { if (failClear) throw new Error('clear refused'); },
};
controller.paintBadge = async () => {};
controller.settings = {...defaultSettings(), armed: true};
controller.hostConnected = true;
controller.hostSpoke = true;
controller.status = {status: 'connected', detail: 'none', proxyReady: true, proxyPort: 45678};
controller.statusAtMs = Date.now();
controller.credential = {endpoint: {kind: 'http', host: '127.0.0.1', port: 45678}, token: 'A'.repeat(43)};
controller.canAuthenticate = true;
controller.blockLayer = {ok: true, error: '', dropped: []};
await controller.reconcile();
const before = controller.current.state;
controller.hostConnected = false;
failClear = true;
let rejected = '';
try { await controller.reconcile(); } catch (e) { rejected = e.message; }
const failed = {current: controller.current, routing: controller.routing, rules: rules.length,
                pacKey: controller.applied.pacKey, rejected};
failClear = false;
await controller.reconcile();
const recovered = {state: controller.current.state, failClosed: controller.current.failClosed};
controller.hostConnected = true;
await controller.reconcile();
console.log(JSON.stringify({before, failed, recovered, reconnected: controller.current.state}));
""")
    assert result["before"] == "protected"
    assert result["failed"]["rejected"] == ""
    assert result["failed"]["current"]["state"] == "routing_failed"
    assert result["failed"]["current"]["failClosed"] is True
    assert result["failed"]["routing"] == {"ok": False, "error": "clear refused"}
    assert result["failed"]["rules"] > 0
    assert result["failed"]["pacKey"] is None
    assert result["recovered"]["state"] != "protected"
    assert result["recovered"]["failClosed"] is True
    assert result["reconnected"] == "protected"
