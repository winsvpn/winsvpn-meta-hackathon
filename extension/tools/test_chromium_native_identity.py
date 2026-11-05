#!/usr/bin/env python3
"""Chromium-only regressions for native-messaging identity binding.

The Chrome and Edge packages identify themselves to the native-messaging host
by their extension id, and the host manifest's `allowed_origins` must name
exactly `chrome-extension://<id>/` for the browser to launch the bridge for
this extension. These tests pin:

  * the runtime identity helpers shipped in src/adapters/chromium.js
    (executed with the real Node engine against a faithful copy of the source,
    so the shipped bytes are what is asserted, not a re-derivation),
  * the identity of the produced Chrome and Edge zips (exact, target-bound,
    and distinct), and
  * the source-level wiring that carries those helpers.

None of these need a browser, a device, a signer, or the network.
"""
from __future__ import annotations

import importlib.util
import io
import json
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent
EXT = TOOLS.parent
sys.path.insert(0, str(TOOLS))

import assert_chrome_zip as chrome_gate  # noqa: E402
import checks  # noqa: E402

CHROMIUM_JS = EXT / "src" / "adapters" / "chromium.js"
DIST = EXT / "dist"

# The 6 source members needed to import chromium.js faithfully: it pulls in
# base.js (-> core/blockrules.js -> core/constants.js) and core/pac.js
# (-> core/constants.js, core/endpoint.js). Staged at their original relative
# paths so the nested relative imports in the shipped source resolve unchanged.
_IMPORT_CLOSURE = (
    ("src/adapters/chromium.js", "src/adapters/chromium.js"),
    ("src/adapters/base.js", "src/adapters/base.js"),
    ("src/core/blockrules.js", "src/core/blockrules.js"),
    ("src/core/constants.js", "src/core/constants.js"),
    ("src/core/pac.js", "src/core/pac.js"),
    ("src/core/endpoint.js", "src/core/endpoint.js"),
)

BATTERY = r"""
globalThis.chrome = { runtime: { id: process.env.WINS_EXT_ID || '' } };
const src = await import('./src/adapters/chromium.js');
const adapter = new src.ChromiumAdapter('native-identity-test');
const identity = adapter.nativeMessagingIdentity();
const result = {
  valid: src.isChromiumExtensionId('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
  invalidNonAlpha: src.isChromiumExtensionId('0123456789abcdef0123456789abcdef'),
  invalidShort: src.isChromiumExtensionId('aaaa'),
  invalidNonString: src.isChromiumExtensionId(12345),
  originValid: src.chromiumAllowedOrigin('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
  originNonAlpha: src.chromiumAllowedOrigin('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaZ'),
  originEmpty: src.chromiumAllowedOrigin(''),
  matchExact: src.nativeHostOriginMatches(
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/'),
  matchOtherId: src.nativeHostOriginMatches(
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/'),
  matchWildcard: src.nativeHostOriginMatches(
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa*'),
  matchNoSlash: src.nativeHostOriginMatches(
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
  matchNonOrigin: src.nativeHostOriginMatches(
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'https://example.com/'),
  matchAbsentId: src.nativeHostOriginMatches(
    '',
    'chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/'),
  identityOk: identity.ok,
  identityId: identity.extensionId,
  identityOrigin: identity.boundOrigin,
  controlLevels: [
    'not_controllable',
    'controlled_by_other_extensions',
    'controllable_by_this_extension',
    'controlled_by_this_extension',
    'future_value',
    null,
  ].map(value => src.normaliseChromiumProxyControlLevel(value)),
};
console.log(JSON.stringify(result));
"""

_VALID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
_OTHER = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def _write_host_identity(
    root: Path, browser: str, origins: list[str] | object
) -> None:
    relative = chrome_gate.CHROMIUM_HOST_MANIFEST_RELS[browser]
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "name": "org.winsvpn.bridge",
                "description": "Win's VPN browser bridge",
                "path": "PLACEHOLDER_ABSOLUTE_PATH_TO_HOST",
                "type": "stdio",
                "allowed_origins": origins,
            }
        ),
        encoding="utf-8",
    )


def _write_valid_host_identities(root: Path) -> None:
    _write_host_identity(
        root, "chrome", [f"chrome-extension://{_VALID}/"]
    )
    _write_host_identity(
        root, "edge", [f"chrome-extension://{_OTHER}/"]
    )


def _run_battery(tmp_path: Path, ext_id: str) -> dict:
    for relative, name in _IMPORT_CLOSURE:
        body = (EXT / relative).read_bytes()
        dest = tmp_path / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(body)
    (tmp_path / "package.json").write_text('{"type": "module"}\n', encoding="utf-8")
    (tmp_path / "battery.mjs").write_text(BATTERY, encoding="utf-8")
    exe = shutil.which("node")
    if not exe:
        pytest.skip("no local node for native-identity battery tests")
    proc = subprocess.run(
        [exe, "battery.mjs"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        # Invoked by absolute path, so a minimal PATH keeps node from picking up
        # anything outside the trusted directories without hiding it from lookup.
        env={"PATH": "/usr/bin:/bin:/usr/local/bin", "WINS_EXT_ID": ext_id},
        timeout=60,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"node battery failed:\nstdout={proc.stdout!r}\nstderr={proc.stderr!r}"
        )
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except json.JSONDecodeError as exc:  # pragma: no cover
        raise AssertionError(f"battery did not emit JSON: {proc.stdout!r}") from exc


# ---------------------------------------------------------------------------
# source-level wiring
# ---------------------------------------------------------------------------


def test_source_carries_identity_helpers() -> None:
    src = CHROMIUM_JS.read_text(encoding="utf-8")
    assert "export const CHROMIUM_EXTENSION_ID_RE" in src
    assert "export function isChromiumExtensionId" in src
    assert "export function chromiumAllowedOrigin" in src
    assert "export function nativeHostOriginMatches" in src
    assert "nativeMessagingIdentity()" in src
    assert "export function normaliseChromiumProxyControlLevel" in src
    assert re.search(r"export const CHROMIUM_EXTENSION_ID_RE = /\^\[a-p\]\{32\}\$/", src)
    assert "api.runtime.id" in src


def test_source_does_not_weaken_shared_native_pipe() -> None:
    src = CHROMIUM_JS.read_text(encoding="utf-8")
    assert "extends BaseAdapter" in src
    assert re.search(r"\bconnectNative\s*\(", src) is None
    assert "export const NATIVE_HOST_NAME" not in src


# ---------------------------------------------------------------------------
# behavioral: the shipped helpers, executed by Node
# ---------------------------------------------------------------------------


def test_shipped_extension_id_validator(tmp_path: Path) -> None:
    got = _run_battery(tmp_path, _VALID)
    assert got["valid"] is True
    assert got["invalidNonAlpha"] is False  # 0-9 is outside [a-p]
    assert got["invalidShort"] is False
    assert got["invalidNonString"] is False


def test_shipped_allowed_origin_construction(tmp_path: Path) -> None:
    got = _run_battery(tmp_path, _VALID)
    assert got["originValid"] == f"chrome-extension://{_VALID}/"
    assert got["originNonAlpha"] is None
    assert got["originEmpty"] is None


def test_shipped_host_origin_must_match_exactly(tmp_path: Path) -> None:
    got = _run_battery(tmp_path, _VALID)
    assert got["matchExact"] is True
    assert got["matchOtherId"] is False
    assert got["matchWildcard"] is False
    assert got["matchNoSlash"] is False
    assert got["matchNonOrigin"] is False
    assert got["matchAbsentId"] is False


def test_shipped_runtime_identity_fails_closed_on_bad_id(tmp_path: Path) -> None:
    good = _run_battery(tmp_path, _VALID)
    assert good["identityOk"] is True
    assert good["identityId"] == _VALID
    assert good["identityOrigin"] == f"chrome-extension://{_VALID}/"

    absent = _run_battery(tmp_path, "")
    assert absent["identityOk"] is False
    assert absent["identityOrigin"] is None


def test_shipped_proxy_control_level_normalizer_is_closed(tmp_path: Path) -> None:
    got = _run_battery(tmp_path, _VALID)
    assert got["controlLevels"] == [
        "not_controllable",
        "controlled_by_other_extensions",
        "controllable_by_this_extension",
        "controlled_by_this_extension",
        "unknown",
        "unknown",
    ]


def test_direct_zip_gate_binds_current_live_native_host_identity() -> None:
    result = chrome_gate.inspect_bytes(
        (DIST / "wins-vpn-companion-chrome.zip").read_bytes(), "chrome"
    )
    assert result["ok"] is True
    assert result["native_host_extension_id"] == "lnehjdblendkagjbmdclepjalahdhbbn"


def test_direct_zip_gate_binds_honest_distinct_canonical_identities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_valid_host_identities(tmp_path)
    monkeypatch.setattr(chrome_gate, "REPO_ROOT", tmp_path)

    result = chrome_gate.inspect_bytes(
        (DIST / "wins-vpn-companion-chrome.zip").read_bytes(), "chrome"
    )

    assert result["ok"] is True
    assert result["native_host_extension_id"] == _VALID


@pytest.mark.parametrize(
    ("browser", "origins", "expected"),
    [
        (
            "chrome",
            [
                f"chrome-extension://{_OTHER}/",
                f"chrome-extension://{_VALID}/",
            ],
            "exactly one",
        ),
        (
            "chrome",
            ["chrome-extension://PLACEHOLDER_CHROME_EXTENSION_ID/"],
            "placeholder",
        ),
        ("edge", None, "exactly one"),
    ],
)
def test_canonical_identity_rejects_ambiguous_placeholder_or_malformed_document(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    browser: str,
    origins: object,
    expected: str,
) -> None:
    _write_valid_host_identities(tmp_path)
    _write_host_identity(tmp_path, browser, origins)
    monkeypatch.setattr(chrome_gate, "REPO_ROOT", tmp_path)

    with pytest.raises(chrome_gate.PackageError, match=expected):
        chrome_gate.canonical_chromium_native_host_ids()


def test_canonical_identity_rejects_missing_document_and_cross_target_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_host_identity(
        tmp_path, "chrome", [f"chrome-extension://{_VALID}/"]
    )
    monkeypatch.setattr(chrome_gate, "REPO_ROOT", tmp_path)
    with pytest.raises(chrome_gate.PackageError, match="unavailable"):
        chrome_gate.canonical_chromium_native_host_ids()

    _write_host_identity(
        tmp_path, "edge", [f"chrome-extension://{_VALID}/"]
    )
    with pytest.raises(chrome_gate.PackageError, match="must be distinct"):
        chrome_gate.canonical_chromium_native_host_ids()


def test_direct_source_gate_rejects_disabled_identity_comparison() -> None:
    chromium = CHROMIUM_JS.read_text(encoding="utf-8")
    controller = (EXT / "src" / "background" / "controller.js").read_text(
        encoding="utf-8"
    )
    assert checks.check_chromium_native_identity_source(chromium, controller) == []
    weakened_adapter = chromium.replace("origin === expected", "true")
    assert checks.check_chromium_native_identity_source(weakened_adapter, controller)
    weakened_controller = controller.replace(
        "const identityError = chromiumNativeIdentityError(this.adapter);",
        "const identityError = '';",
        1,
    )
    assert checks.check_chromium_native_identity_source(
        chromium, weakened_controller
    )


# ---------------------------------------------------------------------------
# produced-zip identity (offline: the existing dist zips)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("browser", "expected_name"),
    [
        ("chrome", "Win's VPN Proxy for Chrome"),
        ("edge", "Win's VPN Proxy for Microsoft Edge"),
    ],
)
def test_produced_zip_binds_exact_manifest_identity(
    browser: str, expected_name: str
) -> None:
    path = DIST / f"wins-vpn-companion-{browser}.zip"
    assert path.is_file(), f"produced zip missing: {path}"
    with zipfile.ZipFile(path) as archive:
        manifest = json.loads(archive.read("manifest.json"))
    assert manifest["name"] == expected_name
    assert manifest["manifest_version"] == 3
    assert manifest["minimum_chrome_version"] == "116"
    assert "nativeMessaging" in manifest["permissions"]
    assert "webRequest" in manifest["permissions"]
    assert "webRequestAuthProvider" in manifest["permissions"]
    assert "key" not in manifest
    assert "update_url" not in manifest
    assert "browser_specific_settings" not in manifest
    assert manifest["background"]["service_worker"] == "src/background/background.js"


def test_produced_chrome_and_edge_zips_are_distinct_identities() -> None:
    chrome = DIST / "wins-vpn-companion-chrome.zip"
    edge = DIST / "wins-vpn-companion-edge.zip"
    with zipfile.ZipFile(chrome) as a, zipfile.ZipFile(edge) as b:
        m_chrome = json.loads(a.read("manifest.json"))
        m_edge = json.loads(b.read("manifest.json"))
    assert m_chrome["name"] != m_edge["name"]
    assert m_chrome["version"] == m_edge["version"]
    assert m_chrome["name"].startswith("Win's VPN Proxy for Chrome")
    assert m_edge["name"] == "Win's VPN Proxy for Microsoft Edge"


def _load_builder():
    spec = importlib.util.spec_from_file_location(
        "extension_build_chromium_identity", EXT / "build.py"
    )
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    return builder


def test_chromium_manifest_builder_preserves_jsonc_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    builder = _load_builder()
    manifest_dir = tmp_path / "manifest"
    manifest_dir.mkdir()
    (manifest_dir / "base.jsonc").write_text(
        """{
  // The reviewed fragments require comments to survive parsing.
  "manifest_version": 3,
  "permissions": ["nativeMessaging",],
}
""",
        encoding="utf-8",
    )
    (manifest_dir / "chrome.jsonc").write_text(
        """{
  "name": "Win's VPN Proxy for Chrome",
  "background": {"service_worker": "src/background/background.js",},
}
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(builder, "MANIFEST_DIR", manifest_dir)

    manifest = builder.build_manifest("chrome")

    assert manifest["manifest_version"] == 3
    assert manifest["permissions"] == ["nativeMessaging"]
    assert manifest["name"] == "Win's VPN Proxy for Chrome"
    assert manifest["background"] == {
        "service_worker": "src/background/background.js"
    }


@pytest.mark.parametrize(
    ("target", "expected_name"),
    [
        ("chrome", "Win's VPN Proxy for Chrome"),
        ("edge", "Win's VPN Proxy for Microsoft Edge"),
    ],
)
def test_chromium_manifest_builder_rejects_duplicate_jsonc_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    expected_name: str,
) -> None:
    builder = _load_builder()
    manifest_dir = tmp_path / "manifest"
    manifest_dir.mkdir()
    (manifest_dir / "base.jsonc").write_text("{}\n", encoding="utf-8")
    (manifest_dir / f"{target}.jsonc").write_text(
        f"""{{
  // An unauthorized first identity must not be hidden by a valid last value.
  "name": "Unauthorized Chromium package",
  "name": {json.dumps(expected_name)},
}}
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(builder, "MANIFEST_DIR", manifest_dir)

    with pytest.raises(json.JSONDecodeError, match="duplicate JSON key: name"):
        builder.build_manifest(target)

    (manifest_dir / f"{target}.jsonc").write_text(
        """{
  "background": {
    "service_worker": "src/background/unauthorized.js",
    "service_worker": "src/background/background.js",
  },
}
""",
        encoding="utf-8",
    )
    with pytest.raises(
        json.JSONDecodeError, match="duplicate JSON key: service_worker"
    ):
        builder.build_manifest(target)


@pytest.fixture(scope="module")
def fresh_chromium_zips(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, str]]:
    """Reproduce the produced Chrome/Edge zips from current source bytes.

    Uses build.py's own stage+zip path in an isolated DIST, so the assertion
    is against the bytes this tree would actually ship today, never against a
    possibly-stale dist/ artifact that could predate the identity hardening.
    The owner-blocked gate 4 (current identity receipt) is not involved here:
    that gate governs whether a placeholder may ship, not the wiring that the
    runtime identity helpers must be present in the package.
    """
    builder = _load_builder()
    root = tmp_path_factory.mktemp("fresh-chromium")
    original_dist = builder.DIST
    results: dict[str, dict[str, str]] = {}
    try:
        for target in ("chrome", "edge"):
            builder.DIST = root / "dist"
            pkg = builder.stage(target)
            archive = builder.zip_package(pkg, target)
            with zipfile.ZipFile(archive) as zf:
                chromium = zf.read("src/adapters/chromium.js").decode("utf-8")
                manifest = zf.read("manifest.json").decode("utf-8")
            results[target] = {"chromium": chromium, "manifest": manifest}
    finally:
        builder.DIST = original_dist
    return results


def test_produced_zip_ships_native_messaging_identity_helpers(
    fresh_chromium_zips: dict[str, dict[str, str]],
) -> None:
    for target in ("chrome", "edge"):
        chromium = fresh_chromium_zips[target]["chromium"]
        assert "export const CHROMIUM_EXTENSION_ID_RE" in chromium
        assert "export function isChromiumExtensionId" in chromium
        assert "export function chromiumAllowedOrigin" in chromium
        assert "export function nativeHostOriginMatches" in chromium
        assert "nativeMessagingIdentity()" in chromium
        assert "api.runtime.id" in chromium
        assert "proxyAuthDecision" in chromium
        assert "challengerMatchesWinsProxy" in chromium


def test_produced_zip_manifest_and_adapter_are_same_target(
    fresh_chromium_zips: dict[str, dict[str, str]],
) -> None:
    for target, expected_name in (
        ("chrome", "Win's VPN Proxy for Chrome"),
        ("edge", "Win's VPN Proxy for Microsoft Edge"),
    ):
        manifest = json.loads(fresh_chromium_zips[target]["manifest"])
        assert manifest["name"] == expected_name
        assert manifest["background"]["service_worker"] == "src/background/background.js"
        assert "nativeMessaging" in manifest["permissions"]
        assert "webRequestAuthProvider" in manifest["permissions"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
