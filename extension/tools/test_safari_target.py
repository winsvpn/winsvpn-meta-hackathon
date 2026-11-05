#!/usr/bin/env python3
"""Safari target contracts that do not require launching Safari."""

from __future__ import annotations

import sys
import subprocess
from pathlib import Path

import pytest

EXT = Path(__file__).resolve().parents[1]
ROOT = EXT.parent
sys.path.insert(0, str(EXT))

import build  # noqa: E402


def test_safari_manifest_uses_only_supported_surfaces() -> None:
    manifest = build.build_manifest("safari")
    assert manifest["name"] == "Win's VPN Proxy for Safari"
    assert manifest["permissions"] == [
        "nativeMessaging",
        "storage",
        "alarms",
    ]
    assert "optional_host_permissions" not in manifest
    assert manifest["background"] == {
        "page": "src/background/safari.html",
    }
    assert manifest["browser_specific_settings"]["safari"]["strict_min_version"] == "26.0"
    assert "open_in_tab" not in manifest["options_ui"]


def test_safari_adapter_cannot_fall_into_external_native_host() -> None:
    adapter = (EXT / "src/adapters/safari.js").read_text(encoding="utf-8")
    controller = (EXT / "src/background/controller.js").read_text(encoding="utf-8")
    index = (EXT / "src/adapters/index.js").read_text(encoding="utf-8")
    assert "api.runtime.sendNativeMessage(" in adapter
    assert "capability_probe" in adapter
    assert "no_native_routing_surface" in adapter
    assert "connectNative(" not in adapter
    assert "NATIVE_HOST_NAME" not in adapter
    assert "async setBlockRules() {}" in adapter
    assert index.index("safari-web-extension://") < index.index("proxy?.onRequest")
    assert controller.index("if (!this.routingSurface.ok) return;") < controller.index(
        "this.adapter.connectNative(NATIVE_HOST_NAME"
    )


def test_no_surface_state_executes_as_non_blocking_and_takes_precedence() -> None:
    script = r"""
import { deriveState, normaliseRoutingSurface } from './src/core/state.js';
import { STATE } from './src/core/constants.js';
const check = (condition, message) => { if (!condition) throw new Error(message); };
const unavailable = deriveState({
  armed: false,
  routingSurface: {ok: false, reason: 'measured unavailable'},
  blockLayer: {ok: false, error: 'must not override'},
});
check(unavailable.state === STATE.NO_ROUTING_SURFACE, 'wrong unavailable state');
check(unavailable.failClosed === false, 'unavailable state must be non-blocking');
check(unavailable.detail === 'measured unavailable', 'measured reason was lost');
check(deriveState({armed: false, routingSurface: {ok: true}}).state === STATE.OFF,
      'available unarmed state changed');
check(normaliseRoutingSurface(undefined).ok === false, 'missing report must fail unavailable');
"""
    subprocess.run(
        ["node", "--input-type=module", "--eval", script],
        cwd=EXT,
        check=True,
        capture_output=True,
        text=True,
    )


def test_honesty_copy_renders_before_background_reply() -> None:
    options = (EXT / "src/ui/options.js").read_text(encoding="utf-8")
    popup = (EXT / "src/ui/popup.html").read_text(encoding="utf-8")
    assert "const safariRuntime = isSafariRuntime();" in options
    assert "renderStatic(what = safariRuntime ? SAFARI_WHAT_THIS_IS : WHAT_THIS_IS)" in options
    assert options.rindex("renderStatic();") < options.rindex("refresh();")
    assert '<button id="toggle" disabled>Checking routing status</button>' in popup


def test_safari_native_handler_is_fixed_and_secret_free() -> None:
    handler = (EXT / "safari/SafariWebExtensionHandler.swift").read_text(encoding="utf-8")
    assert '"type": "capability"' in handler
    assert '"routing": false' in handler
    assert '"reason": "native_app_managed"' in handler
    assert "os_log" not in handler
    assert "print(" not in handler
    for forbidden in ("proxyPort", "token", "server", "account"):
        assert f'"{forbidden}"' not in handler


def test_safari_stage_passes_static_gates(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(build, "DIST", tmp_path / "dist")
    package = build.stage("safari")
    assert build.gate(package, "safari", verbose=False)


@pytest.mark.parametrize("target", ["safari", "safari-extension-source"])
def test_safari_source_cannot_mint_release_identity_receipt(target: str) -> None:
    with pytest.raises(build.PackageVerifyError, match="source-only development target"):
        build.resolve_browser(target)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
