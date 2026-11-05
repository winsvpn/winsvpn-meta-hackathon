#!/usr/bin/env python3
"""Release packaging contracts for the Chrome and Firefox browser packages.

These tests do not launch a browser. They lock the store-package invariants:
relative dist zip paths, native-host allowlists, gecko id alignment,
loopback-only bridge construction, no wildcard native origins, and
store-upload zip hygiene (no packed key, no already-signed META-INF).
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import sys
import tempfile
import zipfile
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent
EXT = TOOLS.parent
ROOT = EXT.parent
sys.path.insert(0, str(TOOLS))

import assert_chrome_zip  # noqa: E402
import assert_firefox_zip  # noqa: E402
import checks  # noqa: E402
import core_tests  # noqa: E402
import dev_bridge  # noqa: E402
import jsonc  # noqa: E402
import store_js_minifier as minifier  # noqa: E402

NATIVE_HOST_NAME = "org.winsvpn.bridge"
GECKO_ID = "companion@winsvpn.org"
HOST_DIR = ROOT / "tools" / "native_messaging" / "manifests"
ESBUILD_CACHE = Path("/tmp/winsvpn-extension-esbuild-test-cache")
# The operator-supplied offline cache, captured before any fixture redirects
# the environment to the private test cache. Archive bytes are re-verified.
CONFIGURED_ESBUILD_CACHE = os.environ.get(minifier.CACHE_ENV, "").strip()
_PRODUCER_ZIPS: dict[str, bytes] | None = None
NON_FINITE_JSON_NUMBERS = ("NaN", "Infinity", "-Infinity")
TEST_CHROME_EXTENSION_ID = "abcdefghijklmnopabcdefghijklmnop"
TEST_EDGE_EXTENSION_ID = "ponmlkjihgfedcbaponmlkjihgfedcba"
TEST_CHROMIUM_EXTENSION_IDS = {
    "chrome": TEST_CHROME_EXTENSION_ID,
    "edge": TEST_EDGE_EXTENSION_ID,
}


def _seed_esbuild_cache(cache: Path = ESBUILD_CACHE) -> None:
    pin = minifier.pin_for_host()
    slot = cache / minifier.host_platform_key() / str(pin["archive_sha256"])
    slot.mkdir(parents=True, exist_ok=True)
    dest = slot / str(pin["archive_name"])
    discovered = Path("/tmp/winsvpn-esbuild-discovery/archives") / str(pin["archive_name"])
    if dest.is_file() and minifier.sha256_file(dest) == pin["archive_sha256"]:
        return
    sources = [discovered]
    if CONFIGURED_ESBUILD_CACHE:
        sources.insert(0, (
            Path(CONFIGURED_ESBUILD_CACHE) / minifier.host_platform_key()
            / str(pin["archive_sha256"]) / str(pin["archive_name"])
        ))
    for source in sources:
        if source.is_file():
            payload = source.read_bytes()
            minifier.verify_archive_bytes(payload, pin)
            dest.write_bytes(payload)
            dest.chmod(0o444)
            return


@pytest.fixture(autouse=True)
def _esbuild_env(monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_esbuild_cache()
    monkeypatch.setenv(minifier.CACHE_ENV, str(ESBUILD_CACHE))
    monkeypatch.setenv(minifier.FETCH_ENV, "0")


def _test_chromium_host_document(browser: str) -> bytes:
    extension_id = TEST_CHROMIUM_EXTENSION_IDS[browser]
    document = {
        "name": NATIVE_HOST_NAME,
        "description": f"Win's VPN {browser} test identity",
        "path": "/test-only/winsvpn-native-host",
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{extension_id}/"],
    }
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )


@pytest.fixture(autouse=True)
def _canonical_test_chromium_identities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "canonical-native-host-identities"
    for browser, relative in assert_chrome_zip.CHROMIUM_HOST_MANIFEST_RELS.items():
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(_test_chromium_host_document(browser))
        destination.chmod(0o644)
    monkeypatch.setattr(assert_chrome_zip, "REPO_ROOT", root)


def _producer_zip(target: str) -> bytes:
    global _PRODUCER_ZIPS
    if _PRODUCER_ZIPS is None:
        _seed_esbuild_cache()
        os.environ[minifier.CACHE_ENV] = str(ESBUILD_CACHE)
        os.environ[minifier.FETCH_ENV] = "0"
        builder = _load_builder()
        dist = Path(tempfile.mkdtemp(prefix="winsvpn-packaging-producer-"))
        builder.DIST = dist
        packages: dict[str, bytes] = {}
        for name in ("chrome", "edge", "firefox"):
            artifact = builder.zip_package(builder.stage(name), name)
            packages[name] = artifact.read_bytes()
        _PRODUCER_ZIPS = packages
    return _PRODUCER_ZIPS[target]


def _write_producer(path: Path, target: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_producer_zip(target))
    os.chmod(path, 0o644)
    return path


def _write_zip(path: Path, members: dict[str, str | bytes]) -> Path:
    return _write_zip_entries(path, list(members.items()))


def _write_zip_entries(
    path: Path, members: list[tuple[str, str | bytes]]
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in members:
            data = body.encode("utf-8") if isinstance(body, str) else body
            zf.writestr(name, data)
    return path


def _chrome_manifest(*, target: str = "chrome", **overrides) -> dict:
    names = {
        "chrome": "Win's VPN Proxy for Chrome",
        "edge": "Win's VPN Proxy for Microsoft Edge",
    }
    manifest = {
        "manifest_version": 3,
        "name": names[target],
        "version": "1.0.0",
        "description": "Sends chosen sites through the Win's VPN desktop tunnel. Not a VPN on its own; it does nothing unless the desktop app is connected.",
        "minimum_chrome_version": "116",
        "permissions": [
            "proxy",
            "nativeMessaging",
            "webRequest",
            "webRequestAuthProvider",
        ],
        "background": {"service_worker": "src/background/background.js", "type": "module"},
        "content_security_policy": {
            "extension_pages": "default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; connect-src 'none'; img-src 'self'; style-src 'self'"
        },
    }
    manifest.update(overrides)
    return manifest


def _firefox_manifest(**overrides) -> dict:
    manifest = {
        "manifest_version": 3,
        "name": "Win's VPN Proxy",
        "version": "1.0.0",
        "description": "Sends chosen sites through the Win's VPN desktop tunnel. Not a VPN on its own; it does nothing unless the desktop app is connected.",
        "permissions": [
            "proxy",
            "nativeMessaging",
            "webRequest",
            "webRequestAuthProvider",
        ],
        "background": {"scripts": ["src/background/background.js"], "type": "module"},
        "browser_specific_settings": {
            "gecko": {
                "id": GECKO_ID,
                "strict_min_version": "140.0",
                "data_collection_permissions": {"required": ["none"]},
            }
        },
        "content_security_policy": {
            "extension_pages": "default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; connect-src 'none'; img-src 'self'; style-src 'self'"
        },
    }
    manifest.update(overrides)
    return manifest


def _package_members(manifest: dict, *, adapter: str) -> dict[str, str]:
    members = {
        "manifest.json": json.dumps(manifest),
        "src/background/background.js": "export {};\n",
        "src/background/controller.js": "export {};\n",
        f"src/adapters/{adapter}.js": "export {};\n",
    }
    return members


def test_canonical_zip_paths_are_inside_extension_dist():
    assert assert_chrome_zip.CANONICAL == EXT / "dist" / "wins-vpn-companion-chrome.zip"
    assert assert_firefox_zip.CANONICAL == EXT / "dist" / "wins-vpn-companion-firefox.zip"
    assert assert_chrome_zip.CANONICAL.is_relative_to(EXT)
    assert assert_firefox_zip.CANONICAL.is_relative_to(EXT)
    chrome_src = (TOOLS / "assert_chrome_zip.py").read_text(encoding="utf-8")
    firefox_src = (TOOLS / "assert_firefox_zip.py").read_text(encoding="utf-8")
    assert "/Users/owner/Documents/wins/" not in chrome_src
    assert "/Users/owner/Documents/wins/" not in firefox_src
    assert "Path(__file__)" in chrome_src
    assert "Path(__file__)" in firefox_src


def test_firefox_gecko_id_matches_host_allowlist():
    firefox = jsonc.load_file(EXT / "manifest" / "firefox.jsonc")
    gecko = ((firefox.get("browser_specific_settings") or {}).get("gecko") or {}).get("id")
    assert gecko == GECKO_ID
    assert gecko == assert_firefox_zip.GECKO_ID
    host = jsonc.load_file(HOST_DIR / f"{NATIVE_HOST_NAME}.firefox.json")
    assert host["name"] == NATIVE_HOST_NAME
    assert host["type"] == "stdio"
    assert gecko in host["allowed_extensions"]


def test_native_host_name_matches_extension_constant():
    constants = (EXT / "src" / "core" / "constants.js").read_text(encoding="utf-8")
    match = re.search(r"export const NATIVE_HOST_NAME = '([^']+)'", constants)
    assert match is not None
    assert match.group(1) == NATIVE_HOST_NAME
    for target in ("chrome", "edge", "firefox"):
        host = jsonc.load_file(HOST_DIR / f"{NATIVE_HOST_NAME}.{target}.json")
        assert host["name"] == NATIVE_HOST_NAME
        assert host["type"] == "stdio"


def test_chromium_host_origins_are_extension_scoped_and_not_wildcards():
    for target in ("chrome", "edge"):
        host = jsonc.load_file(HOST_DIR / f"{NATIVE_HOST_NAME}.{target}.json")
        origins = host.get("allowed_origins") or []
        assert origins
        for origin in origins:
            assert origin.startswith("chrome-extension://")
            assert "*" not in origin


def test_production_chromium_host_origins_bind_live_store_identities():
    expected = {
        "chrome": "lnehjdblendkagjbmdclepjalahdhbbn",
        "edge": "glgihadopbjoandhoihghddecoibcldf",
    }
    for target, extension_id in expected.items():
        host = jsonc.load_file(HOST_DIR / f"{NATIVE_HOST_NAME}.{target}.json")
        assert checks.validated_chromium_allowed_origin(host, target) == extension_id


def test_temporary_chromium_host_origins_are_exact_and_distinct():
    identities = assert_chrome_zip.canonical_chromium_native_host_ids()
    assert identities == TEST_CHROMIUM_EXTENSION_IDS
    assert identities["chrome"] != identities["edge"]


def test_bridge_is_loopback_only_and_ignores_wire_hosts():
    constants = (EXT / "src" / "core" / "constants.js").read_text(encoding="utf-8")
    protocol = (EXT / "src" / "core" / "protocol.js").read_text(encoding="utf-8")
    assert "export const LOOPBACK_HOST = '127.0.0.1'" in constants
    assert "from './constants.js'" in protocol
    assert "LOOPBACK_HOST" in protocol
    assert "raw.host" not in protocol
    assert "raw.hostname" not in protocol


def test_native_pipe_is_shared_and_not_redefined_per_browser():
    controller = (EXT / "src" / "background" / "controller.js").read_text(encoding="utf-8")
    base = (EXT / "src" / "adapters" / "base.js").read_text(encoding="utf-8")
    assert "this.adapter.connectNative(NATIVE_HOST_NAME" in controller
    assert "api.runtime.connectNative(" in base
    for name in ("chromium.js", "firefox.js"):
        text = (EXT / "src" / "adapters" / name).read_text(encoding="utf-8")
        assert "extends BaseAdapter" in text
        assert re.search(r"\bconnectNative\s*\(", text) is None


def test_base_manifest_refuses_page_detection_and_remote_code():
    base = jsonc.load_file(EXT / "manifest" / "base.jsonc")
    assert "web_accessible_resources" not in base
    assert "host_permissions" not in base
    assert "externally_connectable" not in base
    csp = (base.get("content_security_policy") or {}).get("extension_pages", "")
    assert "connect-src 'none'" in csp
    assert "script-src 'self'" in csp
    assert "unsafe-eval" not in csp
    assert "nativeMessaging" in base["permissions"]
    assert "proxy" in base["permissions"]
    assert base["optional_host_permissions"] == ["<all_urls>"]
    assert checks.OPTIONAL_HOST_PERMISSIONS == ["<all_urls>"]
    assert {
        "proxy",
        "nativeMessaging",
        "storage",
        "privacy",
        "declarativeNetRequest",
        "alarms",
        "activeTab",
        "webRequest",
        "webRequestAuthProvider",
    } <= set(checks.REQUIRED_PERMISSIONS)


def test_firefox_amo_requires_data_collection_none_and_esr_140():
    firefox = jsonc.load_file(EXT / "manifest" / "firefox.jsonc")
    gecko = (firefox.get("browser_specific_settings") or {}).get("gecko") or {}
    assert gecko.get("id") == GECKO_ID
    assert int(str(gecko.get("strict_min_version") or "0").split(".")[0]) >= 140
    assert gecko.get("data_collection_permissions") == {"required": ["none"]}
    assert gecko.get("id") == assert_firefox_zip.GECKO_ID
    assert assert_firefox_zip.GECKO_MIN_MAJOR == 140


def test_store_upload_fragments_do_not_pin_a_crx_key_or_update_url():
    for name in ("base.jsonc", "chrome.jsonc", "edge.jsonc", "firefox.jsonc"):
        manifest = jsonc.load_file(EXT / "manifest" / name)
        assert "key" not in manifest
        assert "update_url" not in manifest
        assert "applications" not in manifest


def _load_builder():
    spec = importlib.util.spec_from_file_location("extension_build", EXT / "build.py")
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    return builder


def test_chrome_and_edge_merged_manifests_have_exact_store_identity():
    builder = _load_builder()
    chrome = builder.build_manifest("chrome")
    edge = builder.build_manifest("edge")
    assert chrome["name"] == "Win's VPN Proxy for Chrome"
    assert edge["name"] == "Win's VPN Proxy for Microsoft Edge"
    assert chrome["name"] != edge["name"]
    assert len(chrome["name"]) <= 75
    assert len(edge["name"]) <= 45
    assert chrome["description"] == (
        "Routes chosen HTTPS sites through the Win's VPN desktop tunnel. "
        "Not a VPN on its own; requires the connected desktop app."
    )
    assert edge["description"] == (
        "Routes chosen sites through the Win's VPN desktop proxy. Requires the "
        "desktop app running and connected; not a standalone VPN."
    )
    shared_keys = set(chrome).intersection(edge) - {"name", "description"}
    assert {key: chrome[key] for key in shared_keys} == {
        key: edge[key] for key in shared_keys
    }


def test_firefox_merged_manifest_is_the_proxy_product_without_identity_drift():
    builder = _load_builder()
    firefox = builder.build_manifest("firefox")
    chrome = builder.build_manifest("chrome")
    edge = builder.build_manifest("edge")

    assert firefox["name"] == "Win's VPN Proxy"
    assert firefox["action"]["default_title"] == "Win's VPN Proxy"
    # Deliberately keep Firefox within the strictest store caps used by the
    # shared release gate even though AMO itself permits longer fields.
    assert len(firefox["name"]) <= 45
    assert len(firefox["description"]) <= 132
    assert "installed" in firefox["description"]
    assert "running" in firefox["description"]
    assert "connected" in firefox["description"]
    assert "Not a VPN on its own" in firefox["description"]
    assert firefox["browser_specific_settings"]["gecko"]["id"] == GECKO_ID
    assert chrome["name"] == "Win's VPN Proxy for Chrome"
    assert edge["name"] == "Win's VPN Proxy for Microsoft Edge"


def test_firefox_package_ui_names_the_proxy_and_requires_the_desktop_app():
    background = (EXT / "src" / "background" / "background.js").read_text(
        encoding="utf-8"
    )
    popup = (EXT / "src" / "ui" / "popup.html").read_text(encoding="utf-8")
    options = (EXT / "src" / "ui" / "options.html").read_text(encoding="utf-8")
    copy = (EXT / "src" / "core" / "copy.js").read_text(encoding="utf-8")

    assert "Win's VPN Proxy" in popup
    assert "Win's VPN Proxy" in options
    assert "Win’s VPN Proxy" in copy
    assert "desktop app and browser bridge must be installed" in copy
    assert "unless the desktop app is running and connected" in copy
    assert "It only affects this browser" in copy
    assert "api.permissions.onRemoved.addListener" in background
    assert "api.permissions.onAdded.addListener" in background


@pytest.mark.parametrize(
    ("target", "expected_name"),
    [
        ("chrome", "Win's VPN Proxy for Chrome"),
        ("edge", "Win's VPN Proxy for Microsoft Edge"),
        ("firefox", "Win's VPN Proxy"),
    ],
)
def test_producer_gate_rejects_cross_target_manifest_name(
    tmp_path: Path, target: str, expected_name: str
):
    builder = _load_builder()
    builder.DIST = tmp_path / "dist"
    package = builder.stage(target)
    assert builder.checks.check_manifest(package, target) == []
    manifest_path = package / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["name"] == expected_name
    manifest["name"] = (
        "Win's VPN Proxy for Microsoft Edge"
        if target == "chrome"
        else "Win's VPN Proxy for Chrome"
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    problems = builder.checks.check_manifest(package, target)
    assert any(
        "exact" in problem.detail and target in problem.detail
        for problem in problems
    )


@pytest.mark.parametrize("target", ["chrome", "edge", "firefox"])
def test_all_build_stage_and_final_gates_reject_version_9_9_9(
    tmp_path: Path, target: str
):
    builder = _load_builder()
    builder.DIST = tmp_path / "dist"
    package = builder.stage(target)
    manifest_path = package / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["version"] = "9.9.9"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    direct_problems = builder.checks.check_manifest(package, target)
    assert any(
        "version='9.9.9'" in problem.detail and "reviewed independent" in problem.detail
        for problem in direct_problems
    )
    aggregate_problems = builder.checks.run(
        package, target, EXT / "src" / "core" / "copy.js"
    )
    assert any("version='9.9.9'" in problem.detail for problem in aggregate_problems)
    assert builder.gate(package, target, verbose=False) is False

    artifact = builder.zip_package(package, target)
    if target == "firefox":
        final_result = assert_firefox_zip.inspect(artifact)
    else:
        final_result = assert_chrome_zip.inspect(artifact, target=target)
    assert final_result["ok"] is False
    assert any(
        "version='9.9.9'" in failure and "reviewed" in failure
        for failure in final_result["failures"]
    )


@pytest.mark.parametrize("target", ["chrome", "edge", "firefox"])
def test_build_stage_rejects_duplicate_manifest_version_key(
    tmp_path: Path, target: str
):
    builder = _load_builder()
    builder.DIST = tmp_path / "dist"
    package = builder.stage(target)
    manifest_path = package / "manifest.json"
    raw_manifest = manifest_path.read_text(encoding="utf-8")
    manifest_path.write_text(
        raw_manifest.replace(
            f'"version": "{builder.app_version()}"',
            f'"version": "{builder.app_version()}", "version": "9.9.9"',
            1,
        ),
        encoding="utf-8",
    )

    problems = builder.checks.check_manifest(package, target)
    assert any("duplicate JSON key: version" in problem.detail for problem in problems)
    assert builder.gate(package, target, verbose=False) is False


@pytest.mark.parametrize("constant", NON_FINITE_JSON_NUMBERS)
@pytest.mark.parametrize("target", ["chrome", "edge"])
def test_direct_chromium_manifest_gate_rejects_non_finite_json_number(
    tmp_path: Path, target: str, constant: str
):
    package = tmp_path / target
    package.mkdir()
    manifest = json.dumps(_chrome_manifest(target=target), indent=2).replace(
        '"manifest_version": 3',
        f'"manifest_version": {constant}',
        1,
    )
    (package / "manifest.json").write_text(manifest, encoding="utf-8")

    problems = checks.check_manifest(package, target)
    assert any(
        problem.detail == f"manifest.json is not valid JSON: invalid JSON number: {constant}"
        for problem in problems
    )


@pytest.mark.parametrize("constant", NON_FINITE_JSON_NUMBERS)
@pytest.mark.parametrize("target", ["chrome", "edge"])
def test_chromium_zip_gate_rejects_non_finite_manifest_number(
    tmp_path: Path, target: str, constant: str
):
    manifest = json.dumps(_chrome_manifest(target=target), indent=2).replace(
        '"manifest_version": 3',
        f'"manifest_version": {constant}',
        1,
    )
    members = _package_members(_chrome_manifest(target=target), adapter="chromium")
    members["manifest.json"] = manifest
    payload = _write_zip_entries(
        tmp_path / f"hostile-{target}.zip",
        list(members.items()),
    ).read_bytes()

    result = assert_chrome_zip.inspect_bytes(payload, target)
    assert result["ok"] is False
    assert any(
        failure == f"manifest not JSON: invalid JSON number: {constant}"
        for failure in result["failures"]
    )


@pytest.mark.parametrize("constant", NON_FINITE_JSON_NUMBERS)
def test_release_identity_loader_rejects_non_finite_json_number(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, constant: str
):
    raw_identity = checks.RELEASE_IDENTITY_MAP_PATH.read_text(encoding="utf-8")
    hostile_identity = raw_identity.replace(
        '"schema_version": 2',
        f'"schema_version": {constant}',
        1,
    )
    identity_path = tmp_path / "release-identity.json"
    identity_path.write_text(hostile_identity, encoding="utf-8")
    monkeypatch.setattr(checks, "RELEASE_IDENTITY_MAP_PATH", identity_path)

    with pytest.raises(ValueError) as error:
        checks.reviewed_extension_version("chrome")
    assert str(error.value) == f"invalid JSON number: {constant}"


@pytest.mark.parametrize("constant", NON_FINITE_JSON_NUMBERS)
def test_native_host_template_loader_rejects_non_finite_json_number(
    tmp_path: Path, constant: str
):
    builder = _load_builder()
    builder.DIST = tmp_path / "dist"
    package = builder.stage("chrome")
    template = (
        HOST_DIR / f"{NATIVE_HOST_NAME}.chrome.json"
    ).read_text(encoding="utf-8")
    hostile_template = template.replace(
        "{",
        f'{{\n  "hostile_number": {constant},',
        1,
    ).encode("utf-8")

    problems = builder.checks.check_native_messaging_wiring(
        package,
        "chrome",
        authenticated_host_template=hostile_template,
        allow_live_template=False,
    )
    assert any(
        problem.detail == f"host template is not JSON: invalid JSON number: {constant}"
        for problem in problems
    )


@pytest.mark.parametrize("constant", NON_FINITE_JSON_NUMBERS)
def test_native_wiring_manifest_loader_rejects_non_finite_json_number(
    tmp_path: Path, constant: str
):
    builder = _load_builder()
    builder.DIST = tmp_path / "dist"
    package = builder.stage("chrome")
    manifest_path = package / "manifest.json"
    hostile_manifest = manifest_path.read_text(encoding="utf-8").replace(
        '"manifest_version": 3',
        f'"manifest_version": {constant}',
        1,
    )
    manifest_path.write_text(hostile_manifest, encoding="utf-8")
    template = (HOST_DIR / f"{NATIVE_HOST_NAME}.chrome.json").read_bytes()

    problems = builder.checks.check_native_messaging_wiring(
        package,
        "chrome",
        authenticated_host_template=template,
        allow_live_template=False,
    )
    assert any(
        problem.detail == f"manifest.json is not valid JSON: invalid JSON number: {constant}"
        for problem in problems
    )


def test_build_stage_reads_version_from_canonical_release_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    builder = _load_builder()
    builder.DIST = tmp_path / "dist"
    identity = json.loads(
        builder.checks.RELEASE_IDENTITY_MAP_PATH.read_text(encoding="utf-8")
    )
    browser_identity = identity["platform_mappings"]["browser_extensions"]
    browser_identity["version"] = "9.9.9"
    browser_identity["target_versions"] = {
        target_id: "9.9.9"
        for target_id in builder.checks.EXTENSION_RELEASE_TARGETS.values()
    }
    mutated_identity = tmp_path / "release-identity.json"
    mutated_identity.write_text(json.dumps(identity), encoding="utf-8")
    monkeypatch.setattr(
        builder.checks, "RELEASE_IDENTITY_MAP_PATH", mutated_identity
    )

    package = builder.stage("chrome")
    problems = builder.checks.check_manifest(package, "chrome")
    assert any("must equal pubspec" in problem.detail for problem in problems)


def test_chrome_and_edge_zip_hashes_are_distinct_and_reproducible(
    tmp_path: Path,
):
    builder = _load_builder()
    builder.DIST = tmp_path / "dist"

    def produce() -> tuple[str, str]:
        chrome_zip = builder.zip_package(builder.stage("chrome"), "chrome")
        edge_zip = builder.zip_package(builder.stage("edge"), "edge")
        with zipfile.ZipFile(chrome_zip) as archive:
            chrome_manifest = json.loads(archive.read("manifest.json"))
        with zipfile.ZipFile(edge_zip) as archive:
            edge_manifest = json.loads(archive.read("manifest.json"))
        assert chrome_manifest["name"] == "Win's VPN Proxy for Chrome"
        assert edge_manifest["name"] == "Win's VPN Proxy for Microsoft Edge"
        return (
            hashlib.sha256(chrome_zip.read_bytes()).hexdigest(),
            hashlib.sha256(edge_zip.read_bytes()).hexdigest(),
        )

    first = produce()
    second = produce()
    assert first[0] != first[1]
    assert second == first


def test_zip_package_pins_host_independent_metadata_and_posix_names(
    tmp_path: Path,
):
    builder = _load_builder()
    builder.DIST = tmp_path / "dist"
    chrome = builder.zip_package(builder.stage("chrome"), "chrome")
    with zipfile.ZipFile(chrome) as archive:
        assert archive.comment == b""
        names = archive.namelist()
        assert names == sorted(names)
        assert all("\\" not in name for name in names)
        for info in archive.infolist():
            assert info.date_time == builder.ZIP_EPOCH
            assert info.create_system == builder.ZIP_CREATE_SYSTEM
            assert info.create_version == builder.ZIP_CREATE_VERSION
            assert info.extract_version == builder.ZIP_EXTRACT_VERSION
            assert info.compress_type == zipfile.ZIP_DEFLATED
            assert info.external_attr == builder.ZIP_UNIX_FILE_ATTR
            assert info.extra == b""
            assert info.flag_bits == 0


def test_firefox_xpi_is_byte_identical_unsigned_copy_not_hardlink(
    tmp_path: Path,
):
    builder = _load_builder()
    builder.DIST = tmp_path / "dist"
    firefox_zip = builder.zip_package(builder.stage("firefox"), "firefox")
    firefox_xpi = firefox_zip.with_suffix(".xpi")
    assert firefox_zip.name == "wins-vpn-companion-firefox.zip"
    assert firefox_xpi.is_file()
    assert firefox_xpi.read_bytes() == firefox_zip.read_bytes()
    zip_info = firefox_zip.lstat()
    xpi_info = firefox_xpi.lstat()
    assert (zip_info.st_dev, zip_info.st_ino) != (xpi_info.st_dev, xpi_info.st_ino)
    assert xpi_info.st_nlink == 1
    assert zip_info.st_nlink == 1
    assert assert_firefox_zip.inspect(firefox_xpi)["ok"] is True
    assert assert_firefox_zip.inspect(firefox_zip)["ok"] is True


def test_inspect_follows_canonical_release_identity_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    builder = _load_builder()
    identity = json.loads(
        builder.checks.RELEASE_IDENTITY_MAP_PATH.read_text(encoding="utf-8")
    )
    browser_identity = identity["platform_mappings"]["browser_extensions"]
    browser_identity["version"] = "9.9.9"
    browser_identity["target_versions"] = {
        target_id: "9.9.9"
        for target_id in builder.checks.EXTENSION_RELEASE_TARGETS.values()
    }
    mutated = tmp_path / "release-identity.json"
    mutated.write_text(json.dumps(identity), encoding="utf-8")
    monkeypatch.setattr(builder.checks, "RELEASE_IDENTITY_MAP_PATH", mutated)
    monkeypatch.setattr(assert_chrome_zip.checks, "RELEASE_IDENTITY_MAP_PATH", mutated)
    monkeypatch.setattr(assert_firefox_zip.checks, "RELEASE_IDENTITY_MAP_PATH", mutated)
    honest = _write_producer(tmp_path / "honest-chrome.zip", "chrome")
    chrome_result = assert_chrome_zip.inspect(honest, "chrome")
    assert chrome_result["ok"] is False
    assert any("must equal pubspec" in failure for failure in chrome_result["failures"])
    firefox = _write_producer(tmp_path / "honest-firefox.zip", "firefox")
    firefox_result = assert_firefox_zip.inspect(firefox)
    assert firefox_result["ok"] is False
    assert any("must equal pubspec" in failure for failure in firefox_result["failures"])


def test_producer_refuses_identical_final_chrome_and_edge_packages(
    tmp_path: Path,
):
    builder = _load_builder()
    chrome = tmp_path / "chrome.zip"
    edge = tmp_path / "edge.zip"
    chrome.write_bytes(b"identical deterministic package")
    edge.write_bytes(chrome.read_bytes())
    with pytest.raises(RuntimeError, match="byte-identical"):
        builder.require_distinct_chromium_packages({"chrome": chrome, "edge": edge})


def test_producer_accepts_distinct_final_chromium_packages(tmp_path: Path):
    builder = _load_builder()
    chrome = tmp_path / "chrome.zip"
    edge = tmp_path / "edge.zip"
    chrome.write_bytes(b"chrome deterministic package")
    edge.write_bytes(b"edge deterministic package")
    builder.require_distinct_chromium_packages({"chrome": chrome, "edge": edge})


def test_canonical_edge_zip_path_is_inside_extension_dist():
    assert assert_chrome_zip.CANONICAL_EDGE == EXT / "dist" / "wins-vpn-companion-edge.zip"
    assert assert_chrome_zip.CANONICAL_EDGE.is_relative_to(EXT)


def test_core_runtime_browser_resolution_requires_explicit_custody_path(
    tmp_path: Path,
):
    browser = tmp_path / "Google Chrome for Testing"
    browser.write_bytes(b"browser fixture")
    browser.chmod(0o755)
    assert core_tests.resolve_browser_bin({"BROWSER_BIN": str(browser)}) == str(browser)

    with pytest.raises(FileNotFoundError, match="BROWSER_BIN"):
        core_tests.resolve_browser_bin({})
    with pytest.raises(FileNotFoundError, match="absolute executable"):
        core_tests.resolve_browser_bin({"BROWSER_BIN": "relative-browser"})
    link = tmp_path / "browser-link"
    link.symlink_to(browser)
    with pytest.raises(FileNotFoundError, match="non-symlink"):
        core_tests.resolve_browser_bin({"BROWSER_BIN": str(link)})


def test_chrome_zip_assert_refuses_packed_key_and_signed_metadata(tmp_path: Path):
    honest = _write_producer(tmp_path / "honest-chrome.zip", "chrome")
    assert assert_chrome_zip.inspect(honest)["ok"] is True

    keyed = _chrome_manifest(key="MIIBIjANFake")
    packed = _write_zip(tmp_path / "keyed-chrome.zip", _package_members(keyed, adapter="chromium"))
    keyed_result = assert_chrome_zip.inspect(packed)
    assert keyed_result["ok"] is False
    assert any("key" in f for f in keyed_result["failures"])

    signed_members = _package_members(_chrome_manifest(), adapter="chromium")
    signed_members["META-INF/cose.manifest"] = "already-signed"
    signed = _write_zip(tmp_path / "signed-chrome.zip", signed_members)
    signed_result = assert_chrome_zip.inspect(signed)
    assert signed_result["ok"] is False
    assert any("META-INF" in f for f in signed_result["failures"])


def test_firefox_zip_assert_refuses_missing_amo_data_collection(tmp_path: Path):
    honest = _write_producer(tmp_path / "honest-firefox.zip", "firefox")
    assert assert_firefox_zip.inspect(honest)["ok"] is True

    gecko = {
        "id": GECKO_ID,
        "strict_min_version": "128.0",
    }
    stale = _firefox_manifest(browser_specific_settings={"gecko": gecko})
    stale_zip = _write_zip(
        tmp_path / "stale-firefox.zip", _package_members(stale, adapter="firefox")
    )
    stale_result = assert_firefox_zip.inspect(stale_zip)
    assert stale_result["ok"] is False
    assert any("data_collection_permissions" in f or "strict_min_version" in f
               for f in stale_result["failures"])



def test_staged_javascript_is_store_minified_for_all_targets(tmp_path: Path):
    builder = _load_builder()
    builder.DIST = tmp_path / "dist"
    sys.path.insert(0, str(TOOLS))
    import store_js_minifier as minifier

    intended = minifier.intended_javascript_members()
    assert "src/adapters/base.js" in intended
    maps = []
    for target in ("chrome", "edge", "firefox"):
        package = builder.stage(target)
        js_files = {
            path.relative_to(package).as_posix(): path.read_bytes()
            for path in sorted((package / "src").rglob("*.js"))
        }
        assert set(js_files) == intended
        for relative, payload in js_files.items():
            authored = (EXT / relative).read_bytes()
            minifier.reject_packaged_javascript(relative, payload.decode("utf-8"))
            assert payload != authored
            assert minifier.is_pretty_javascript(authored.decode("utf-8"))
            assert not minifier.is_pretty_javascript(payload.decode("utf-8"))
            assert b"sourceMappingURL" not in payload
            assert b"sourceURL" not in payload
        maps.append(js_files)
        with zipfile.ZipFile(builder.zip_package(package, target)) as archive:
            js_members = [
                name for name in archive.namelist() if name.endswith(".js")
            ]
            assert set(js_members) == intended
            for name in js_members:
                payload = archive.read(name)
                authored = (EXT / name).read_bytes()
                minifier.reject_packaged_javascript(name, payload.decode("utf-8"))
                assert payload != authored
    assert maps[0] == maps[1] == maps[2]


def test_store_listing_description_fits_chrome_web_store_limit():
    base = jsonc.load_file(EXT / "manifest" / "base.jsonc")
    assert len(base["name"]) <= 50
    assert len(base["description"]) <= 132


def test_chrome_zip_assert_refuses_overlong_description(tmp_path: Path):
    honest = _write_producer(tmp_path / "honest-chrome.zip", "chrome")
    assert assert_chrome_zip.inspect(honest)["ok"] is True
    long_desc = "x" * 133
    packed = _write_zip(
        tmp_path / "long-chrome.zip",
        _package_members(_chrome_manifest(description=long_desc), adapter="chromium"),
    )
    result = assert_chrome_zip.inspect(packed)
    assert result["ok"] is False
    assert any("132" in f for f in result["failures"])


def test_firefox_zip_assert_refuses_overlong_description(tmp_path: Path):
    honest = _write_producer(tmp_path / "honest-firefox.zip", "firefox")
    assert assert_firefox_zip.inspect(honest)["ok"] is True
    packed = _write_zip(
        tmp_path / "long-firefox.zip",
        _package_members(_firefox_manifest(description="y" * 133), adapter="firefox"),
    )
    result = assert_firefox_zip.inspect(packed)
    assert result["ok"] is False
    assert any("132" in f for f in result["failures"])


def test_inspect_bytes_refuses_unminified_javascript_and_keeps_minified_unsigned():
    import io

    pretty_js = "export function start() {\n  const ok = true;\n  return ok;\n}\n"

    def _replace(payload: bytes, name: str, body: str) -> bytes:
        source = zipfile.ZipFile(io.BytesIO(payload))
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dest:
            for info in source.infolist():
                data = body.encode("utf-8") if info.filename == name else source.read(info.filename)
                dest.writestr(info.filename, data)
        return out.getvalue()

    chrome_ok = assert_chrome_zip.inspect_bytes(_producer_zip("chrome"), "chrome")
    firefox_ok = assert_firefox_zip.inspect_bytes(_producer_zip("firefox"))
    assert chrome_ok["ok"] is True
    assert chrome_ok["trusted_signer"] == "none"
    assert firefox_ok["ok"] is True
    assert firefox_ok["trusted_signer"] == "none"
    chrome_pretty_result = assert_chrome_zip.inspect_bytes(
        _replace(_producer_zip("chrome"), "src/background/background.js", pretty_js),
        "chrome",
    )
    firefox_pretty_result = assert_firefox_zip.inspect_bytes(
        _replace(_producer_zip("firefox"), "src/background/background.js", pretty_js)
    )
    assert chrome_pretty_result["ok"] is False
    assert firefox_pretty_result["ok"] is False
    assert any("minified" in failure for failure in chrome_pretty_result["failures"])
    assert any("minified" in failure for failure in firefox_pretty_result["failures"])
    with zipfile.ZipFile(io.BytesIO(_producer_zip("chrome"))) as archive:
        constants = archive.read("src/core/constants.js").decode("utf-8")
    chrome_plus_one = assert_chrome_zip.inspect_bytes(
        _replace(
            _producer_zip("chrome"),
            "src/core/constants.js",
            constants + "\n",
        ),
        "chrome",
    )
    chrome_foreign = assert_chrome_zip.inspect_bytes(
        _replace(
            _producer_zip("chrome"),
            "src/core/constants.js",
            "const ok=true;function start(){return 1;}\n",
        ),
        "chrome",
    )
    assert chrome_plus_one["ok"] is False
    assert chrome_foreign["ok"] is False
    assert any("producer" in failure for failure in chrome_plus_one["failures"])
    assert any("producer" in failure for failure in chrome_foreign["failures"])


def test_inspect_bytes_refuses_store_signature_members():
    import io

    payload = _producer_zip("firefox")
    source = zipfile.ZipFile(io.BytesIO(payload))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in source.infolist():
            archive.writestr(info.filename, source.read(info.filename))
        archive.writestr("META-INF/mozilla.rsa", b"signature")
    result = assert_firefox_zip.inspect_bytes(buf.getvalue())
    assert result["ok"] is False
    assert any("already packed or already signed" in failure for failure in result["failures"])


@pytest.mark.parametrize("inspector,manifest,adapter", [
    (assert_chrome_zip, _chrome_manifest, "chromium"),
    (assert_firefox_zip, _firefox_manifest, "firefox"),
])
@pytest.mark.parametrize("unsafe_member", [
    "manifest.json",
    "/absolute.txt",
    "C:/absolute.txt",
    "C:\\absolute.txt",
    "src\\background\\controller.js",
    "./ambiguous.txt",
    "src/./ambiguous.txt",
    "src/../ambiguous.txt",
    "src//ambiguous.txt",
    "META-INF/signature.sf",
    "_METADATA/signature.json",
])
def test_zip_assert_refuses_duplicate_and_unsafe_member_paths(
    tmp_path: Path, inspector, manifest, adapter: str, unsafe_member: str
):
    members = list(_package_members(manifest(), adapter=adapter).items())
    if unsafe_member == "manifest.json":
        members.append((unsafe_member, json.dumps(manifest())))
        with pytest.warns(UserWarning, match="Duplicate name"):
            packed = _write_zip_entries(tmp_path / f"unsafe-{adapter}.zip", members)
    else:
        members.append((unsafe_member, "mutation"))
        packed = _write_zip_entries(tmp_path / f"unsafe-{adapter}.zip", members)
    result = inspector.inspect(packed)
    assert result["ok"] is False
    assert any(
        "duplicate" in failure
        or "unsafe" in failure
        or "backslash" in failure
        or "ambiguous" in failure
        or "META-INF" in failure
        or "_metadata" in failure.lower()
        for failure in result["failures"]
    )


def test_host_cache_inputs_cover_sources_and_resolution_metadata(tmp_path: Path):
    host = tmp_path / "host"
    for relative in (
        "pubspec.yaml",
        "pubspec.lock",
        "pubspec_overrides.yaml",
        ".dart_tool/package_config.json",
        "bin/wins_bridge_host_harness.dart",
        "bin/imported.dart",
        "lib/bridge.dart",
        "lib/nested/imported.dart",
    ):
        path = host / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("// input\n", encoding="utf-8")
    inputs = {Path(path).relative_to(host).as_posix() for path in dev_bridge._host_build_inputs(str(host))}
    assert inputs == {
        "pubspec.yaml",
        "pubspec.lock",
        "pubspec_overrides.yaml",
        ".dart_tool/package_config.json",
        "bin/wins_bridge_host_harness.dart",
        "bin/imported.dart",
        "lib/bridge.dart",
        "lib/nested/imported.dart",
    }


def _rewrite_zip_manifest(path: Path, mutate, *, suffix: str) -> Path:
    with zipfile.ZipFile(path) as source:
        members = {
            info.filename: source.read(info.filename)
            for info in source.infolist()
            if not info.is_dir()
        }
        manifest = json.loads(members["manifest.json"])
    mutate(manifest)
    members["manifest.json"] = json.dumps(manifest).encode("utf-8")
    rewritten = path.with_name(f"{path.stem}-{suffix}.zip")
    with zipfile.ZipFile(rewritten, "w", zipfile.ZIP_DEFLATED) as dest:
        for name, body in members.items():
            dest.writestr(name, body)
    return rewritten


@pytest.mark.parametrize("target", ["chrome", "edge", "firefox"])
def test_build_stage_requires_optional_host_permissions(tmp_path: Path, target: str):
    builder = _load_builder()
    builder.DIST = tmp_path / "dist"
    package = builder.stage(target)
    manifest_path = package / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.pop("optional_host_permissions", None)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    problems = builder.checks.check_manifest(package, target)
    assert any("optional_host_permissions" in problem.detail for problem in problems)
    assert builder.gate(package, target, verbose=False) is False


@pytest.mark.parametrize(
    ("inspector", "target"),
    [
        (assert_chrome_zip, "chrome"),
        (assert_chrome_zip, "edge"),
        (assert_firefox_zip, "firefox"),
    ],
)
def test_inspect_refuses_unreviewed_and_missing_permissions(
    tmp_path: Path, inspector, target: str
):
    honest = _write_producer(tmp_path / f"honest-{target}.zip", target)
    inspect = inspector.inspect if inspector is assert_firefox_zip else (
        lambda path: inspector.inspect(path, target)
    )
    assert inspect(honest)["ok"] is True

    def add_tabs(manifest: dict) -> None:
        manifest.setdefault("permissions", []).append("tabs")

    extra = _rewrite_zip_manifest(honest, add_tabs, suffix="tabs")
    extra_result = inspect(extra)
    assert extra_result["ok"] is False
    assert any("unreviewed permission" in failure for failure in extra_result["failures"])

    def drop_storage_and_host(manifest: dict) -> None:
        manifest["permissions"] = [
            name for name in manifest.get("permissions") or [] if name != "storage"
        ]
        manifest.pop("optional_host_permissions", None)

    stripped = _rewrite_zip_manifest(honest, drop_storage_and_host, suffix="stripped")
    stripped_result = inspect(stripped)
    assert stripped_result["ok"] is False
    assert any("missing permission 'storage'" in failure for failure in stripped_result["failures"])
    assert any(
        "optional_host_permissions" in failure for failure in stripped_result["failures"]
    )


def test_inspect_and_canonical_gate_refuse_missing_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    missing = tmp_path / "extension" / "dist" / "wins-vpn-companion-chrome.zip"
    missing.parent.mkdir(parents=True, exist_ok=True)
    result = assert_chrome_zip.inspect(missing, "chrome")
    assert result["ok"] is False
    assert any("missing" in failure.lower() for failure in result["failures"])
    firefox_missing = tmp_path / "extension" / "dist" / "wins-vpn-companion-firefox.xpi"
    firefox_result = assert_firefox_zip.inspect(firefox_missing)
    assert firefox_result["ok"] is False
    assert any("missing" in failure.lower() for failure in firefox_result["failures"])

    monkeypatch.setattr(assert_chrome_zip, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(assert_firefox_zip, "REPO_ROOT", tmp_path)
    with pytest.raises(assert_chrome_zip.PackageError, match="missing"):
        assert_chrome_zip.canonical_gate_verify(
            "chrome-extension-package",
            "extension/dist/wins-vpn-companion-chrome.zip",
        )
    with pytest.raises(assert_firefox_zip.PackageError, match="missing"):
        assert_firefox_zip.canonical_gate_verify(
            "firefox-extension-package",
            "extension/dist/wins-vpn-companion-firefox.xpi",
        )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
