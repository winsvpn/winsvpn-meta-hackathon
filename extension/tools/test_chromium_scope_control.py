"""A regular-window proxy readback cannot vouch for incognito routing."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "src"


def run_node(tmp_path, script):
    node = shutil.which("node")
    if not node:
        pytest.skip("no local Node runtime")
    shutil.copytree(SOURCE, tmp_path / "src")
    (tmp_path / "package.json").write_text('{"type":"module"}\n', encoding="ascii")
    (tmp_path / "test.mjs").write_text(script, encoding="utf-8")
    result = subprocess.run([node, "test.mjs"], cwd=tmp_path,
                            capture_output=True, text=True, timeout=30,
                            env={"PATH": "/usr/bin:/bin"})
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


SETUP = """
let allowed = true;
let levels = {regular: 'controlled_by_this_extension', private: 'controlled_by_this_extension'};
let failRead = '';
let failWrite = '';
let reads = [];
const privacy = value => ({
  set: async () => {}, clear: async () => {},
  get: async () => ({value, levelOfControl: 'controlled_by_this_extension'}),
});
globalThis.chrome = {
  runtime: {}, extension: {isAllowedIncognitoAccess: async () => allowed},
  proxy: {settings: {
    get: async query => {
      const scope = query.incognito ? 'private' : 'regular';
      reads.push(scope);
      if (scope === failRead) throw new Error('scope read refused');
      return {levelOfControl: levels[scope]};
    },
    set: async () => { if (failWrite) throw new Error(failWrite); },
  }},
  privacy: {network: {
    webRTCIPHandlingPolicy: privacy('disable_non_proxied_udp'),
    networkPredictionEnabled: privacy(false),
  }},
};
const {ChromiumAdapter} = await import('./src/adapters/chromium.js');
const adapter = new ChromiumAdapter('chrome');
"""


@pytest.mark.parametrize("level,expected", [
    ("not_controllable", "not_controllable"),
    ("controlled_by_other_extensions", "controlled_by_other_extensions"),
    ("controllable_by_this_extension", "controllable_by_this_extension"),
    ("controlled_by_this_extension", "controlled_by_this_extension"),
    ("future_control", "unknown"),
])
def test_every_enabled_scope_contributes_to_proxy_control(tmp_path, level, expected):
    result = run_node(tmp_path, SETUP + f"""
levels.private = {json.dumps(level)};
const level = await adapter.proxyLevelOfControl();
console.log(JSON.stringify({{level, reads, private: adapter.incognitoRouting}}));
""")
    assert result["level"] == expected
    assert result["reads"] == ["regular", "private"]
    assert result["private"]["ok"] is (level == "controlled_by_this_extension")


def test_disabled_incognito_does_not_require_private_control(tmp_path):
    result = run_node(tmp_path, SETUP + """
allowed = false;
failRead = 'private';
console.log(JSON.stringify({level: await adapter.proxyLevelOfControl(), reads}));
""")
    assert result == {"level": "controlled_by_this_extension", "reads": ["regular"]}


@pytest.mark.parametrize("scope", ["regular", "private"])
def test_proxy_read_failure_is_not_control(tmp_path, scope):
    result = run_node(tmp_path, SETUP + f"""
failRead = {json.dumps(scope)};
console.log(JSON.stringify({{level: await adapter.proxyLevelOfControl(), reads}}));
""")
    assert result == {"level": "unknown", "reads": ["regular", "private"]}


def test_privacy_success_does_not_erase_incognito_proxy_failure(tmp_path):
    result = run_node(tmp_path, SETUP + """
failRead = 'private';
await adapter.proxyLevelOfControl();
const before = {...adapter.incognitoRouting};
await adapter.applyPrivacyProtections();
await adapter.releasePrivacyProtections();
console.log(JSON.stringify({before, after: adapter.incognitoRouting}));
""")
    assert result["before"] == result["after"]
    assert result["after"] == {"required": True, "ok": False, "error": "scope read refused"}


def test_regular_write_failure_invalidates_previous_incognito_success(tmp_path):
    result = run_node(tmp_path, SETUP + """
await adapter.proxyLevelOfControl();
failWrite = 'regular write refused';
let error = '';
try { await adapter.installFailClosedSink(); } catch (e) { error = e.message; }
console.log(JSON.stringify({error, private: adapter.incognitoRouting}));
""")
    assert result["error"] == "regular write refused"
    assert result["private"] == {"required": True, "ok": None, "error": ""}


def test_incognito_only_takeover_blocks_an_already_protected_controller(tmp_path):
    result = run_node(tmp_path, SETUP + """
const {Controller} = await import('./src/background/controller.js');
const {defaultSettings} = await import('./src/core/rules.js');
let rules = [];
adapter.blockLayerTypes = async () => ({ok: true, types: ['main_frame'], dropped: []});
adapter.setBlockRules = async value => { rules = value; };
adapter.applyRouting = async () => 'pac';
adapter.clearRouting = async () => {};
const controller = new Controller();
controller.adapter = adapter;
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
const initial = {state: controller.current.state, rules: rules.length};
levels.private = 'controlled_by_other_extensions';
reads = [];
await controller.reconcile();
console.log(JSON.stringify({initial, current: controller.current, rules: rules.length, reads,
                           private: adapter.incognitoRouting}));
""")
    assert result["initial"] == {"state": "protected", "rules": 0}
    assert result["current"]["state"] == "not_in_control"
    assert result["current"]["failClosed"] is True
    assert result["rules"] > 0
    assert "private" in result["reads"]
    assert result["private"]["ok"] is False
