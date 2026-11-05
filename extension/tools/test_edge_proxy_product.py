#!/usr/bin/env python3
"""Microsoft Edge proxy-product identity and adapter regressions."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent
EXT = TOOLS.parent
sys.path.insert(0, str(TOOLS))

import assert_chrome_zip  # noqa: E402
import checks  # noqa: E402
import verify_chromium  # noqa: E402

EXPECTED_EDGE_NAME = "Win's VPN Proxy for Microsoft Edge"
EXPECTED_EDGE_DESCRIPTION = (
    "Routes chosen sites through the Win's VPN desktop proxy. Requires the "
    "desktop app running and connected; not a standalone VPN."
)


def _load_builder():
    spec = importlib.util.spec_from_file_location("edge_extension_build", EXT / "build.py")
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    return builder


def test_edge_proxy_product_identity_is_consistent() -> None:
    manifest = _load_builder().build_manifest("edge")
    listing = (EXT / "store_listings" / "edge.md").read_text(encoding="utf-8")
    identity = json.loads(
        (EXT / "store_listings" / "store_identity.json").read_text(encoding="utf-8")
    )
    store = identity["stores"]["edge-extension-package"]

    assert manifest["name"] == EXPECTED_EDGE_NAME
    assert manifest["description"] == EXPECTED_EDGE_DESCRIPTION
    assert len(manifest["name"]) <= 45
    assert len(manifest["description"]) <= 132
    assert checks.EXPECTED_TARGET_NAMES["edge"] == EXPECTED_EDGE_NAME
    assert assert_chrome_zip.EXPECTED_TARGET_NAMES["edge"] == EXPECTED_EDGE_NAME
    assert f"- Name: `{EXPECTED_EDGE_NAME}`" in listing
    assert f"- Short description: `{EXPECTED_EDGE_DESCRIPTION}`" in listing
    assert store["listing_name"] == EXPECTED_EDGE_NAME


def test_edge_rebrand_does_not_mutate_frozen_artifact_or_store_identity() -> None:
    identity = json.loads(
        (EXT / "store_listings" / "store_identity.json").read_text(encoding="utf-8")
    )
    store = identity["stores"]["edge-extension-package"]

    assert store["store_id"] == "glgihadopbjoandhoihghddecoibcldf"
    assert store["store_id_status"] == "owner_authenticated_draft"
    assert store["unsigned_archives"] == [
        "extension/dist/wins-vpn-companion-edge.zip"
    ]
    assert assert_chrome_zip.CANONICAL_EDGE.name == "wins-vpn-companion-edge.zip"


def test_shared_pages_present_the_proxy_product() -> None:
    popup = (EXT / "src" / "ui" / "popup.html").read_text(encoding="utf-8")
    options = (EXT / "src" / "ui" / "options.html").read_text(encoding="utf-8")
    copy = (EXT / "src" / "core" / "copy.js").read_text(encoding="utf-8")

    assert "<title>Win's VPN Proxy</title>" in popup
    assert "<title>Win's VPN Proxy: sites &amp; settings</title>" in options
    assert "VPN Proxy is a browser add-on" in copy
    assert "desktop app and browser bridge must be installed" in copy
    assert "It carries HTTPS connections only" in copy


@pytest.mark.parametrize("quote", ["'", '"'])
def test_edge_verifier_reads_minified_resource_types(
    tmp_path: Path, quote: str
) -> None:
    core = tmp_path / "src" / "core"
    core.mkdir(parents=True)
    (core / "constants.js").write_text(
        f"export const DNR_RESOURCE_TYPES=[{quote}main_frame{quote},"
        f"{quote}websocket{quote}];\n",
        encoding="ascii",
    )
    assert verify_chromium.resource_types_in(tmp_path) == ["main_frame", "websocket"]


def _adapter_name(tmp_path: Path, user_agent: str, *, firefox_api: bool = False) -> str:
    shutil.copytree(EXT / "src", tmp_path / "src")
    (tmp_path / "package.json").write_text('{"type":"module"}\n', encoding="ascii")
    (tmp_path / "adapter.mjs").write_text(
        """
globalThis.chrome = {runtime: {}};
if (process.env.TEST_FIREFOX === '1') {
  globalThis.browser = {runtime: {}, proxy: {onRequest: {}}};
}
Object.defineProperty(globalThis, 'navigator', {
  value: {userAgent: process.env.TEST_UA || ''},
  configurable: true,
});
const adapters = await import('./src/adapters/index.js');
console.log(adapters.createAdapter().name);
""",
        encoding="ascii",
    )
    node = shutil.which("node")
    if not node:
        pytest.skip("no local Node runtime for adapter selection test")
    completed = subprocess.run(
        [node, "adapter.mjs"],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env={
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "TEST_UA": user_agent,
            "TEST_FIREFOX": "1" if firefox_api else "0",
        },
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr or completed.stdout)
    return completed.stdout.strip().splitlines()[-1]


def _policy_battery(tmp_path: Path) -> dict:
    shutil.copytree(EXT / "src" / "core", tmp_path / "core")
    (tmp_path / "package.json").write_text('{"type":"module"}\n', encoding="ascii")
    (tmp_path / "policy.mjs").write_text(
        """
const K = await import('./core/constants.js');
const state = await import('./core/state.js');
const copy = await import('./core/copy.js');
const base = {
  armed: true,
  hostConnected: true,
  hostSpoke: true,
  hostOpenedAtMs: 1,
  status: {
    status: 'connected',
    detail: 'none',
    winn: 'unavailable_on_this_platform',
    proxyReady: true,
    proxyPort: 45678,
  },
  statusAtMs: 1000,
  nowMs: 1000,
  levelOfControl: 'controlled_by_this_extension',
  credential: {
    endpoint: {kind: 'http', host: '127.0.0.1', port: 45678},
    token: 'A'.repeat(43),
  },
  canAuthenticate: true,
  routingSurface: {ok: true, reason: ''},
};
const derive = extra => state.deriveState({...base, ...extra});
const managed = derive({levelOfControl: 'not_controllable'});
const other = derive({levelOfControl: 'controlled_by_other_extensions'});
const lost = derive({
  levelOfControl: 'controllable_by_this_extension',
  routing: {ok: true, error: ''},
});
const firstApply = derive({
  levelOfControl: 'controllable_by_this_extension',
  routing: {ok: null, error: ''},
});
console.log(JSON.stringify({
  managed,
  managedCopy: copy.STATE_COPY[managed.state],
  other,
  lost,
  firstApply,
  edgeNote: copy.edgeProxyControlNote('not_controllable', 'edge'),
  chromeNote: copy.edgeProxyControlNote('not_controllable', 'chrome'),
  expectedManagedState: K.STATE.PROXY_NOT_CONTROLLABLE,
  expectedOtherState: K.STATE.NOT_IN_CONTROL,
  expectedRoutingFailed: K.STATE.ROUTING_FAILED,
  expectedProtected: K.STATE.PROTECTED,
}));
""",
        encoding="ascii",
    )
    node = shutil.which("node")
    if not node:
        pytest.skip("no local Node runtime for proxy policy test")
    completed = subprocess.run(
        [node, "policy.mjs"],
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


def _clear_under_control(tmp_path: Path, control: str) -> dict:
    shutil.copytree(EXT / "src", tmp_path / "src")
    (tmp_path / "package.json").write_text('{"type":"module"}\n', encoding="ascii")
    (tmp_path / "clear.mjs").write_text(
        """
let clears = 0;
globalThis.chrome = {
  runtime: {},
  extension: {isAllowedIncognitoAccess: async () => false},
  proxy: {settings: {
    get: async () => ({levelOfControl: process.env.TEST_CONTROL}),
    clear: async () => { clears += 1; throw new Error('policy refused clear'); },
  }},
};
const {ChromiumAdapter} = await import('./src/adapters/chromium.js');
const adapter = new ChromiumAdapter('edge');
let ok = true;
let error = '';
try { await adapter.clearRouting(); }
catch (e) { ok = false; error = String(e && e.message || e); }
console.log(JSON.stringify({ok, error, clears}));
""",
        encoding="ascii",
    )
    node = shutil.which("node")
    if not node:
        pytest.skip("no local Node runtime for proxy clear test")
    completed = subprocess.run(
        [node, "clear.mjs"],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env={"PATH": "/usr/bin:/bin:/usr/local/bin", "TEST_CONTROL": control},
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr or completed.stdout)
    return json.loads(completed.stdout.strip().splitlines()[-1])


def _controller_post_set_battery(tmp_path: Path) -> dict:
    shutil.copytree(EXT / "src", tmp_path / "src")
    (tmp_path / "package.json").write_text('{"type":"module"}\n', encoding="ascii")
    (tmp_path / "controller.mjs").write_text(
        """
globalThis.chrome = {
  runtime: {id: 'a'.repeat(32), getManifest: () => ({version: '1.0.0'})},
  action: {
    setBadgeText: async () => {},
    setBadgeBackgroundColor: async () => {},
  },
};
const {Controller} = await import('./src/background/controller.js');
const {defaultSettings} = await import('./src/core/rules.js');
const controller = new Controller();
const controls = [
  'controllable_by_this_extension',
  'controllable_by_this_extension',
  'controllable_by_this_extension',
];
const events = [];
controller.adapter = {
  name: 'edge',
  authStats: {authenticated: 0, unauthenticated: 0},
  blockTypesDropped: [],
  proxyLevelOfControl: async () => controls.shift() || 'controllable_by_this_extension',
  applyRouting: async () => { events.push('apply-routing'); return 'pac'; },
  applyPrivacyProtections: async () => { events.push('privacy'); return {}; },
  blockLayerTypes: async () => ({ok: true, types: ['main_frame'], dropped: []}),
  setBlockRules: async rules => { events.push(rules.length ? 'block' : 'unblock'); },
  clearRouting: async () => { events.push('clear-routing'); },
};
controller.settings = {...defaultSettings(), armed: true};
controller.hostConnected = true;
controller.hostSpoke = true;
controller.status = {
  status: 'connected',
  detail: 'none',
  winn: 'unavailable_on_this_platform',
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
await controller.reconcile();
console.log(JSON.stringify({
  state: controller.current.state,
  failClosed: controller.current.failClosed,
  events,
  routing: controller.routing,
  enforcementChanged: controller.enforcementChanged,
}));
""",
        encoding="ascii",
    )
    node = shutil.which("node")
    if not node:
        pytest.skip("no local Node runtime for controller post-set test")
    completed = subprocess.run(
        [node, "controller.mjs"],
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


def test_edge_managed_proxy_policy_has_distinct_honest_state(tmp_path: Path) -> None:
    got = _policy_battery(tmp_path)
    assert got["managed"]["state"] == got["expectedManagedState"]
    assert got["managed"]["failClosed"] is True
    managed_copy = got["managedCopy"]
    assert "another extension" not in (
        managed_copy["detail"] + " " + managed_copy["action"]
    ).lower()
    assert "remove or disable" not in managed_copy["action"].lower()
    assert "blocked, not sent unprotected" in managed_copy["detail"]
    assert got["other"]["state"] == got["expectedOtherState"]
    assert got["edgeNote"].startswith("Microsoft Edge reports")
    assert "often set" in got["edgeNote"]
    assert "will not try to override" in got["edgeNote"]
    assert got["chromeNote"] == ""


def test_effective_proxy_control_is_required_after_apply(tmp_path: Path) -> None:
    got = _policy_battery(tmp_path)
    assert got["lost"]["state"] == got["expectedRoutingFailed"]
    assert got["lost"]["failClosed"] is True
    assert got["firstApply"]["state"] == got["expectedProtected"]


def test_edge_policy_refusal_does_not_hide_the_managed_state(tmp_path: Path) -> None:
    managed = _clear_under_control(tmp_path / "managed", "not_controllable")
    assert managed == {"ok": True, "error": "", "clears": 1}

    other = _clear_under_control(
        tmp_path / "other", "controlled_by_other_extensions"
    )
    assert other["ok"] is False
    assert other["clears"] == 1
    assert "policy refused clear" in other["error"]


def test_controller_blocks_and_clears_when_proxy_set_does_not_take_control(
    tmp_path: Path,
) -> None:
    got = _controller_post_set_battery(tmp_path)
    assert got["state"] == "routing_failed"
    assert got["failClosed"] is True
    assert got["events"] == ["block", "apply-routing", "privacy", "clear-routing"]
    assert got["routing"] == {"ok": None, "error": ""}
    assert got["enforcementChanged"] is False


@pytest.mark.parametrize(
    ("user_agent", "firefox_api", "expected"),
    [
        ("Mozilla/5.0 Chrome/151.0.0.0 Edg/151.0.0.0", False, "edge"),
        ("Mozilla/5.0 Chrome/151.0.0.0 Safari/537.36", False, "chrome"),
        ("Mozilla/5.0 Edge 151", False, "chrome"),
        ("Mozilla/5.0 Chrome/151 Edg/151", True, "firefox"),
    ],
)
def test_adapter_selection(
    tmp_path: Path, user_agent: str, firefox_api: bool, expected: str
) -> None:
    assert _adapter_name(tmp_path, user_agent, firefox_api=firefox_api) == expected
