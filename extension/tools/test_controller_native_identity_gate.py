#!/usr/bin/env python3
"""Runtime tests for the controller's Chromium native identity gate."""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent
EXTENSION = TOOLS.parent


def _load_tool(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


JSONC = _load_tool("controller_native_identity_jsonc", TOOLS / "jsonc.py")
CHECKS = _load_tool("controller_native_identity_checks", TOOLS / "checks.py")
CHECKS.jsonc = JSONC

VALID_ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
OTHER_ID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

BATTERY = rf"""
globalThis.chrome = {{
  runtime: {{
    id: '{VALID_ID}',
    getManifest: () => ({{ version: '1.0.0' }}),
  }},
}};

const {{ Controller }} = await import('./src/background/controller.js');

const validIdentity = () => ({{
  ok: true,
  extensionId: '{VALID_ID}',
  boundOrigin: 'chrome-extension://{VALID_ID}/',
}});

function runCase(name, identityFactory, includeIdentity = true) {{
  const events = [];
  const messages = [];
  const adapter = {{
    name,
    authStats: null,
    setCredential() {{}},
    connectNative(hostName) {{
      events.push('connect');
      return {{
        hostName,
        postMessage(message) {{ messages.push(message); }},
        disconnect() {{}},
      }};
    }},
  }};
  if (includeIdentity) {{
    adapter.nativeMessagingIdentity = () => {{
      events.push('identity');
      return identityFactory();
    }};
  }}

  const controller = new Controller();
  controller.adapter = adapter;
  controller.settings = {{ ...controller.settings, armed: true }};
  controller.startHeartbeat = () => {{}};
  controller.openHost();

  return {{
    events,
    connectCalls: events.filter((event) => event === 'connect').length,
    connected: controller.hostConnected,
    hasPort: Boolean(controller.port),
    messages: messages.length,
    lastError: controller.lastError,
    armed: controller.settings.armed,
  }};
}}

const unreadable = {{ ok: true, extensionId: '{VALID_ID}' }};
Object.defineProperty(unreadable, 'boundOrigin', {{
  get() {{ throw new Error('hostile boundOrigin getter'); }},
}});

const results = {{
  chromeValid: runCase('chrome', validIdentity),
  edgeValid: runCase('edge', validIdentity),
  firefoxNoHelper: runCase('firefox', () => {{
    throw new Error('Firefox identity helper must not run');
  }}),
  chromeMissingHelper: runCase('chrome', () => null, false),
  chromeThrowingHelper: runCase('chrome', () => {{
    throw new Error('identity read failed');
  }}),
  chromeNull: runCase('chrome', () => null),
  chromeArray: runCase('chrome', () => []),
  chromePromise: runCase('chrome', () => Promise.resolve(validIdentity())),
  chromeNotOk: runCase('chrome', () => ({{
    ok: false,
    extensionId: '{VALID_ID}',
    boundOrigin: 'chrome-extension://{VALID_ID}/',
  }})),
  chromeStringOk: runCase('chrome', () => ({{
    ok: 'true',
    extensionId: '{VALID_ID}',
    boundOrigin: 'chrome-extension://{VALID_ID}/',
  }})),
  chromeShortId: runCase('chrome', () => ({{
    ok: true,
    extensionId: 'aaaa',
    boundOrigin: 'chrome-extension://aaaa/',
  }})),
  chromeUppercaseId: runCase('chrome', () => ({{
    ok: true,
    extensionId: 'Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    boundOrigin: 'chrome-extension://Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/',
  }})),
  chromeNumericId: runCase('chrome', () => ({{
    ok: true,
    extensionId: '0123456789abcdef0123456789abcdef',
    boundOrigin: 'chrome-extension://0123456789abcdef0123456789abcdef/',
  }})),
  chromeMissingOrigin: runCase('chrome', () => ({{
    ok: true,
    extensionId: '{VALID_ID}',
  }})),
  chromeOtherOrigin: runCase('chrome', () => ({{
    ok: true,
    extensionId: '{VALID_ID}',
    boundOrigin: 'chrome-extension://{OTHER_ID}/',
  }})),
  chromeWildcardOrigin: runCase('chrome', () => ({{
    ok: true,
    extensionId: '{VALID_ID}',
    boundOrigin: 'chrome-extension://{VALID_ID}/*',
  }})),
  chromeNoSlashOrigin: runCase('chrome', () => ({{
    ok: true,
    extensionId: '{VALID_ID}',
    boundOrigin: 'chrome-extension://{VALID_ID}',
  }})),
  chromeUnreadableOrigin: runCase('chrome', () => unreadable),
}};

console.log(JSON.stringify(results));
"""


@pytest.fixture(scope="module")
def runtime_results(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict]:
    node = shutil.which("node")
    if not node:
        pytest.skip("no local node for controller runtime tests")

    root = tmp_path_factory.mktemp("controller-native-identity")
    shutil.copytree(EXTENSION / "src", root / "src")
    (root / "package.json").write_text('{"type":"module"}\n', encoding="utf-8")
    (root / "battery.mjs").write_text(BATTERY, encoding="utf-8")
    proc = subprocess.run(
        [node, "battery.mjs"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(
            "controller identity battery failed:\n"
            f"stdout={proc.stdout!r}\nstderr={proc.stderr!r}"
        )
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        raise AssertionError(
            f"controller identity battery did not emit JSON: {proc.stdout!r}"
        ) from exc


@pytest.mark.parametrize("case", ["chromeValid", "edgeValid"])
def test_valid_chromium_identity_is_checked_before_connect(
    runtime_results: dict[str, dict], case: str
) -> None:
    result = runtime_results[case]
    assert result["events"] == ["identity", "connect"]
    assert result["connectCalls"] == 1
    assert result["connected"] is True
    assert result["hasPort"] is True
    assert result["messages"] == 3
    assert result["lastError"] == ""
    assert result["armed"] is True


def test_firefox_behavior_does_not_require_or_call_identity_helper(
    runtime_results: dict[str, dict]
) -> None:
    result = runtime_results["firefoxNoHelper"]
    assert result["events"] == ["connect"]
    assert result["connectCalls"] == 1
    assert result["connected"] is True
    assert result["hasPort"] is True
    assert result["messages"] == 3
    assert result["lastError"] == ""


@pytest.mark.parametrize(
    "case",
    [
        "chromeMissingHelper",
        "chromeThrowingHelper",
        "chromeNull",
        "chromeArray",
        "chromePromise",
        "chromeNotOk",
        "chromeStringOk",
        "chromeShortId",
        "chromeUppercaseId",
        "chromeNumericId",
        "chromeMissingOrigin",
        "chromeOtherOrigin",
        "chromeWildcardOrigin",
        "chromeNoSlashOrigin",
        "chromeUnreadableOrigin",
    ],
)
def test_absent_malformed_or_mismatched_chromium_identity_fails_closed_before_connect(
    runtime_results: dict[str, dict], case: str
) -> None:
    result = runtime_results[case]
    assert result["connectCalls"] == 0
    assert result["connected"] is False
    assert result["hasPort"] is False
    assert result["messages"] == 0
    assert "Chromium package" in result["lastError"]
    assert "native-messaging" in result["lastError"]
    assert "bridge was not opened" in result["lastError"]
    assert result["armed"] is True


def test_chromium_preflight_rejects_duplicate_allowed_origins(
    tmp_path: Path,
) -> None:
    package = tmp_path / "package"
    shutil.copytree(EXTENSION / "src", package / "src")
    (package / "manifest.json").write_text(
        '{"manifest_version":3,"permissions":["nativeMessaging"]}\n',
        encoding="utf-8",
    )
    hostile_template = f"""{{
  // A valid last value must not overwrite an unauthorized first value.
  "name": "org.winsvpn.bridge",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://{OTHER_ID}/"],
  "allowed_origins": ["chrome-extension://{VALID_ID}/"],
}}
""".encode("utf-8")

    problems = CHECKS.check_native_messaging_wiring(
        package,
        "chrome",
        authenticated_host_template=hostile_template,
        allow_live_template=False,
    )

    assert len(problems) == 1
    assert "host template is not JSON" in problems[0].detail
    assert "duplicate JSON key: allowed_origins" in problems[0].detail


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
