#!/usr/bin/env python3
"""Adversarial tests for extension-only cross-store artifact adapters."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import unicodedata
import zipfile
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent
EXTENSION = TOOLS.parent
REPOSITORY = EXTENSION.parent
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(REPOSITORY / "tools"))

import assert_chrome_zip  # noqa: E402
import assert_firefox_zip  # noqa: E402
import store_js_minifier as minifier  # noqa: E402
import validate_release_artifact_privacy as privacy  # noqa: E402
import release_obfuscation_contract as obfuscation  # noqa: E402

ESBUILD_CACHE = Path("/tmp/winsvpn-extension-esbuild-test-cache")
# The operator-supplied offline cache, captured before any fixture redirects
# the environment to the private test cache. Archive bytes are re-verified.
CONFIGURED_ESBUILD_CACHE = os.environ.get(minifier.CACHE_ENV, "").strip()
_PRODUCER_ZIPS: dict[str, bytes] | None = None
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


def _load_builder():
    spec = importlib.util.spec_from_file_location(
        "extension_build_cross_store_producer", EXTENSION / "build.py"
    )
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    return builder


def _producer_zip(browser: str) -> bytes:
    global _PRODUCER_ZIPS
    if _PRODUCER_ZIPS is None:
        _seed_esbuild_cache()
        os.environ[minifier.CACHE_ENV] = str(ESBUILD_CACHE)
        os.environ[minifier.FETCH_ENV] = "0"
        builder = _load_builder()
        dist = Path(tempfile.mkdtemp(prefix="winsvpn-adapter-producer-"))
        builder.DIST = dist
        packages: dict[str, bytes] = {}
        for name in ("chrome", "edge", "firefox"):
            artifact = builder.zip_package(builder.stage(name), name)
            packages[name] = artifact.read_bytes()
        _PRODUCER_ZIPS = packages
    return _PRODUCER_ZIPS[browser]


def _write_producer(path: Path, browser: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_producer_zip(browser))
    os.chmod(path, 0o644)
    return path


def _manifest(browser: str) -> dict:
    return _load_builder().build_manifest(browser)


def _package(
    path: Path,
    browser: str,
    extra: dict[str, bytes] | None = None,
    manifest: dict | None = None,
) -> Path:
    adapter = "firefox" if browser == "firefox" else "chromium"
    members: dict[str, bytes] = {
        "manifest.json": json.dumps(manifest or _manifest(browser)).encode(),
        "src/background/background.js": b"export {};\n",
        "src/background/controller.js": b"export {};\n",
        f"src/adapters/{adapter}.js": b"export {};\n",
    }
    members.update(extra or {})
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    return path


def _passing_privacy_scan(target_id: str = "") -> privacy.ArtifactPrivacyScanResult:
    return privacy.ArtifactPrivacyScanResult(
        passed=True,
        revision="fixture",
        labels=(),
        label_count=0,
        unique_value_count=0,
        target_id=target_id,
        artifact_identity="fixture",
        matched_labels=(),
        blob_count=1,
    )


def _stub_privacy_inventory(monkeypatch: pytest.MonkeyPatch, mutate=None) -> None:
    monkeypatch.setattr(
        privacy,
        "load_authenticated_secret_inventory",
        lambda repository_root=None: object(),
    )

    def scan(paths, inventory, *, target_id="", require_target=False):
        if mutate is not None:
            mutate()
        return _passing_privacy_scan(target_id)

    monkeypatch.setattr(privacy, "scan_release_artifacts", scan)


def _test_chromium_host_document(browser: str) -> bytes:
    extension_id = TEST_CHROMIUM_EXTENSION_IDS[browser]
    document = {
        "name": "org.winsvpn.bridge",
        "description": f"Win's VPN {browser} test identity",
        "path": "/test-only/winsvpn-native-host",
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{extension_id}/"],
    }
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )


def _write_test_chromium_host_identities(root: Path) -> None:
    for browser, relative in assert_chrome_zip.CHROMIUM_HOST_MANIFEST_RELS.items():
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(_test_chromium_host_document(browser))
        destination.chmod(0o644)


def _configure_roots(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    _write_test_chromium_host_identities(root)
    for relative in (
        assert_firefox_zip.FIREFOX_FRAGMENT_REL,
        assert_firefox_zip.FIREFOX_HOST_MANIFEST_REL,
    ):
        source = REPOSITORY / relative
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())
        destination.chmod(0o644)
    monkeypatch.setattr(assert_chrome_zip, "REPO_ROOT", root)
    monkeypatch.setattr(assert_firefox_zip, "REPO_ROOT", root)
    monkeypatch.setattr(privacy, "ROOT", root)


def test_temporary_chromium_identities_are_distinct_and_production_is_live_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_test_chromium_host_identities(tmp_path)
    monkeypatch.setattr(assert_chrome_zip, "REPO_ROOT", tmp_path)
    assert assert_chrome_zip.canonical_chromium_native_host_ids() == (
        TEST_CHROMIUM_EXTENSION_IDS
    )

    production_ids = {
        "chrome": "lnehjdblendkagjbmdclepjalahdhbbn",
        "edge": "glgihadopbjoandhoihghddecoibcldf",
    }
    for browser, relative in assert_chrome_zip.CHROMIUM_HOST_MANIFEST_RELS.items():
        production = assert_chrome_zip.jsonc.loads(
            (REPOSITORY / relative).read_text(encoding="utf-8")
        )
        assert assert_chrome_zip.checks.validated_chromium_allowed_origin(
            production, browser
        ) == production_ids[browser]


@pytest.mark.parametrize(
    ("payload", "failure"),
    [
        (b'{"name":', "invalid"),
        (
            b'{"name":"org.winsvpn.bridge","type":"stdio",'
            b'"allowed_origins":["chrome-extension://abcdefghijklmnopabcdefghijklmnop/"],'
            b'"allowed_origins":["chrome-extension://ponmlkjihgfedcbaponmlkjihgfedcba/"]}',
            "duplicate",
        ),
        (
            b'{"name":"org.winsvpn.bridge","type":"stdio",'
            b'"allowed_origins":["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",'
            b'"chrome-extension://abcdefghijklmnopabcdefghijklmnop/"]}',
            "exactly one",
        ),
    ],
)
def test_temporary_chromium_identity_rejects_malformed_or_ambiguous_documents(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
    failure: str,
) -> None:
    _write_test_chromium_host_identities(tmp_path)
    chrome_path = tmp_path / assert_chrome_zip.CHROMIUM_HOST_MANIFEST_RELS["chrome"]
    chrome_path.write_bytes(payload)
    monkeypatch.setattr(assert_chrome_zip, "REPO_ROOT", tmp_path)
    with pytest.raises(assert_chrome_zip.PackageError, match=failure):
        assert_chrome_zip.canonical_chromium_native_host_ids()


@pytest.mark.parametrize(
    ("module", "target_id", "filename", "browser"),
    [
        (assert_chrome_zip, "chrome-extension-package", "wins-vpn-companion-chrome.zip", "chrome"),
        (assert_chrome_zip, "edge-extension-package", "wins-vpn-companion-edge.zip", "edge"),
        (assert_firefox_zip, "firefox-extension-package", "wins-vpn-companion-firefox.zip", "firefox"),
        (assert_firefox_zip, "firefox-extension-package", "wins-vpn-companion-firefox.xpi", "firefox"),
    ],
)
def test_package_adapters_accept_exact_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    module,
    target_id: str,
    filename: str,
    browser: str,
) -> None:
    _configure_roots(monkeypatch, tmp_path)
    artifact = _write_producer(tmp_path / "extension" / "dist" / filename, browser)
    module.canonical_gate_verify(target_id, artifact.relative_to(tmp_path).as_posix())
    output = capsys.readouterr().out
    assert f"target={target_id}" in output
    expected_version = _load_builder().build_manifest(browser)["version"]
    assert f"version={expected_version}" in output


@pytest.mark.parametrize(
    ("module", "target_id", "filename", "browser"),
    [
        (
            assert_chrome_zip,
            "chrome-extension-package",
            "wins-vpn-companion-chrome.zip",
            "chrome",
        ),
        (
            assert_chrome_zip,
            "edge-extension-package",
            "wins-vpn-companion-edge.zip",
            "edge",
        ),
        (
            assert_firefox_zip,
            "firefox-extension-package",
            "wins-vpn-companion-firefox.xpi",
            "firefox",
        ),
    ],
)
@pytest.mark.parametrize(
    "bad_version", ["9.9.9", "1.0.1", "1.0.0.0", "1.0.0 ", 1, None]
)
def test_package_adapters_reject_substituted_extension_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    module,
    target_id: str,
    filename: str,
    browser: str,
    bad_version: object,
) -> None:
    _configure_roots(monkeypatch, tmp_path)
    manifest = _manifest(browser)
    manifest["version"] = bad_version
    artifact = _package(
        tmp_path / "extension" / "dist" / filename,
        browser,
        manifest=manifest,
    )
    with pytest.raises(module.PackageError, match="version=.*reviewed"):
        module.canonical_gate_verify(
            target_id, artifact.relative_to(tmp_path).as_posix()
        )


@pytest.mark.parametrize(
    ("module", "target_id", "filename", "browser"),
    [
        (
            assert_chrome_zip,
            "chrome-extension-package",
            "wins-vpn-companion-chrome.zip",
            "chrome",
        ),
        (
            assert_chrome_zip,
            "edge-extension-package",
            "wins-vpn-companion-edge.zip",
            "edge",
        ),
        (
            assert_firefox_zip,
            "firefox-extension-package",
            "wins-vpn-companion-firefox.xpi",
            "firefox",
        ),
    ],
)
def test_package_adapters_reject_substituted_display_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    module,
    target_id: str,
    filename: str,
    browser: str,
) -> None:
    _configure_roots(monkeypatch, tmp_path)
    manifest = _manifest(browser)
    manifest["version_name"] = "9.9.9"
    artifact = _package(
        tmp_path / "extension" / "dist" / filename,
        browser,
        manifest=manifest,
    )
    with pytest.raises(module.PackageError, match="version_name=.*reviewed"):
        module.canonical_gate_verify(
            target_id, artifact.relative_to(tmp_path).as_posix()
        )


@pytest.mark.parametrize(
    ("module", "target_id", "filename", "browser"),
    [
        (
            assert_chrome_zip,
            "chrome-extension-package",
            "wins-vpn-companion-chrome.zip",
            "chrome",
        ),
        (
            assert_chrome_zip,
            "edge-extension-package",
            "wins-vpn-companion-edge.zip",
            "edge",
        ),
        (
            assert_firefox_zip,
            "firefox-extension-package",
            "wins-vpn-companion-firefox.xpi",
            "firefox",
        ),
    ],
)
def test_package_adapters_reject_duplicate_manifest_version_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    module,
    target_id: str,
    filename: str,
    browser: str,
) -> None:
    _configure_roots(monkeypatch, tmp_path)
    manifest = _manifest(browser)
    manifest_json = json.dumps(manifest)
    duplicate = manifest_json.replace(
        f'"version": "{manifest["version"]}"',
        f'"version": "{manifest["version"]}", "version": "9.9.9"',
        1,
    )
    adapter = "firefox" if browser == "firefox" else "chromium"
    artifact = tmp_path / "extension" / "dist" / filename
    artifact.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(artifact, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", duplicate)
        archive.writestr("src/background/background.js", "export {};\n")
        archive.writestr("src/background/controller.js", "export {};\n")
        archive.writestr(f"src/adapters/{adapter}.js", "export {};\n")
    with pytest.raises(module.PackageError, match="duplicate manifest key"):
        module.canonical_gate_verify(
            target_id, artifact.relative_to(tmp_path).as_posix()
        )


@pytest.mark.parametrize(
    ("module", "target_id", "filename", "browser"),
    [
        (assert_chrome_zip, "firefox-extension-package", "wins-vpn-companion-chrome.zip", "chrome"),
        (assert_firefox_zip, "chrome-extension-package", "wins-vpn-companion-firefox.xpi", "firefox"),
        (assert_chrome_zip, "chrome-extension-package", "wins-vpn-companion-edge.zip", "chrome"),
        (assert_chrome_zip, "edge-extension-package", "wins-vpn-companion-chrome.zip", "edge"),
        (assert_firefox_zip, "firefox-extension-package", "wins-vpn-companion-chrome.xpi", "firefox"),
    ],
)
def test_package_adapters_reject_unsupported_or_confused_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    module,
    target_id: str,
    filename: str,
    browser: str,
) -> None:
    _configure_roots(monkeypatch, tmp_path)
    artifact = _package(tmp_path / "extension" / "dist" / filename, browser)
    with pytest.raises(module.PackageError):
        module.canonical_gate_verify(target_id, artifact.relative_to(tmp_path).as_posix())


@pytest.mark.parametrize(
    ("target_id", "filename", "archive_browser"),
    [
        ("chrome-extension-package", "wins-vpn-companion-chrome.zip", "edge"),
        ("edge-extension-package", "wins-vpn-companion-edge.zip", "chrome"),
    ],
)
def test_chromium_adapter_rejects_renamed_cross_target_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_id: str,
    filename: str,
    archive_browser: str,
) -> None:
    _configure_roots(monkeypatch, tmp_path)
    artifact = _package(
        tmp_path / "extension" / "dist" / filename, archive_browser
    )
    with pytest.raises(assert_chrome_zip.PackageError, match="exact .* target identity"):
        assert_chrome_zip.canonical_gate_verify(
            target_id, artifact.relative_to(tmp_path).as_posix()
        )


@pytest.mark.parametrize(
    ("browser", "limit"), [("chrome", 75), ("edge", 45)]
)
def test_chromium_adapter_enforces_target_name_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    browser: str,
    limit: int,
) -> None:
    _configure_roots(monkeypatch, tmp_path)
    manifest = _manifest(browser)
    manifest["name"] = "x" * (limit + 1)
    artifact = tmp_path / "extension" / "dist" / f"wins-vpn-companion-{browser}.zip"
    members = {
        "manifest.json": json.dumps(manifest).encode(),
        "src/background/background.js": b"export {};\n",
        "src/background/controller.js": b"export {};\n",
        "src/adapters/chromium.js": b"export {};\n",
    }
    artifact.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(artifact, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    with pytest.raises(assert_chrome_zip.PackageError, match=f"limit is {limit}"):
        assert_chrome_zip.canonical_gate_verify(
            f"{browser}-extension-package", artifact.relative_to(tmp_path).as_posix()
        )


@pytest.mark.parametrize(
    "bad_path",
    [
        "",
        "/tmp/extension.zip",
        "../extension.zip",
        "extension/./chrome.zip",
        "extension//chrome.zip",
        r"extension\dist\chrome.zip",
        "C:/extension/chrome.zip",
    ],
)
def test_adapters_reject_non_relative_or_escaping_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_path: str
) -> None:
    _configure_roots(monkeypatch, tmp_path)
    with pytest.raises(assert_chrome_zip.PackageError):
        assert_chrome_zip.canonical_gate_verify("chrome-extension-package", bad_path)
    with pytest.raises(privacy.PrivacyError):
        privacy.canonical_extension_gate_verify("chrome-extension-package", bad_path)


def test_adapters_reject_symlink_empty_and_wrong_suffix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_roots(monkeypatch, tmp_path)
    dist = tmp_path / "extension" / "dist"
    real = _package(dist / "real-chrome.zip", "chrome")
    symlink = dist / "wins-vpn-companion-chrome.zip"
    symlink.symlink_to(real)
    with pytest.raises(assert_chrome_zip.PackageError):
        assert_chrome_zip.canonical_gate_verify(
            "chrome-extension-package", symlink.relative_to(tmp_path).as_posix()
        )
    empty = dist / "empty-edge.zip"
    empty.write_bytes(b"")
    with pytest.raises(assert_chrome_zip.PackageError):
        assert_chrome_zip.canonical_gate_verify(
            "edge-extension-package", empty.relative_to(tmp_path).as_posix()
        )
    wrong = dist / "wins-vpn-companion-firefox.crx"
    wrong.write_bytes(real.read_bytes())
    with pytest.raises(assert_firefox_zip.PackageError):
        assert_firefox_zip.canonical_gate_verify(
            "firefox-extension-package", wrong.relative_to(tmp_path).as_posix()
        )


def test_adapters_reject_symlinked_parent_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_roots(monkeypatch, tmp_path)
    real_dist = tmp_path / "real-dist"
    artifact = _package(real_dist / "wins-vpn-companion-edge.zip", "edge")
    extension = tmp_path / "extension"
    extension.mkdir(exist_ok=True)
    (extension / "dist").symlink_to(real_dist, target_is_directory=True)
    raw_path = "extension/dist/wins-vpn-companion-edge.zip"
    assert artifact.is_file()
    with pytest.raises(assert_chrome_zip.PackageError, match="symbolic link"):
        assert_chrome_zip.canonical_gate_verify("edge-extension-package", raw_path)
    with pytest.raises(privacy.PrivacyError, match="symbolic link"):
        privacy.canonical_extension_gate_verify("edge-extension-package", raw_path)


@pytest.mark.parametrize(
    ("member", "payload"),
    [
        ("native/wins_bridge_host.exe", b"MZ"),
        ("tools/native_messaging/host.json", b"{}"),
        ("private/signing-key.pem", b"private"),
        ("src/background/controller.js.map", b"{}"),
        ("lib/native.node", b"native"),
    ],
)
def test_privacy_adapter_rejects_native_host_and_private_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    member: str,
    payload: bytes,
) -> None:
    _configure_roots(monkeypatch, tmp_path)
    artifact = _package(
        tmp_path / "extension" / "dist" / "wins-vpn-companion-chrome.zip",
        "chrome",
        {member: payload},
    )
    with pytest.raises(privacy.PrivacyError, match="native-host or private material"):
        privacy.canonical_extension_gate_verify(
            "chrome-extension-package", artifact.relative_to(tmp_path).as_posix()
        )


@pytest.mark.parametrize(
    ("module", "target_id", "filename", "browser"),
    [
        (assert_chrome_zip, "chrome-extension-package", "wins-vpn-companion-chrome.zip", "chrome"),
        (assert_chrome_zip, "edge-extension-package", "wins-vpn-companion-edge.zip", "edge"),
        (assert_firefox_zip, "firefox-extension-package", "wins-vpn-companion-firefox.xpi", "firefox"),
    ],
)
def test_package_adapters_independently_reject_private_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    module,
    target_id: str,
    filename: str,
    browser: str,
) -> None:
    _configure_roots(monkeypatch, tmp_path)
    artifact = _package(
        tmp_path / "extension" / "dist" / filename,
        browser,
        {"private/controller.js.map": b"{}"},
    )
    with pytest.raises(module.PackageError, match="private material"):
        module.canonical_gate_verify(target_id, artifact.relative_to(tmp_path).as_posix())


@pytest.mark.parametrize(
    ("target_id", "filename", "browser"),
    [
        ("chrome-extension-package", "wins-vpn-companion-chrome.zip", "chrome"),
        ("edge-extension-package", "wins-vpn-companion-edge.zip", "edge"),
        ("firefox-extension-package", "wins-vpn-companion-firefox.xpi", "firefox"),
    ],
)
def test_privacy_adapter_accepts_exact_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_id: str,
    filename: str,
    browser: str,
) -> None:
    _configure_roots(monkeypatch, tmp_path)
    _stub_privacy_inventory(monkeypatch)
    artifact = _package(tmp_path / "extension" / "dist" / filename, browser)
    privacy.canonical_extension_gate_verify(
        target_id, artifact.relative_to(tmp_path).as_posix()
    )


def test_package_adapter_detects_artifact_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_roots(monkeypatch, tmp_path)
    artifact = _write_producer(
        tmp_path / "extension" / "dist" / "wins-vpn-companion-chrome.zip", "chrome"
    )
    original = assert_chrome_zip.inspect

    def mutate(path: Path, target: str = "chrome") -> dict:
        result = original(path, target)
        path.write_bytes(path.read_bytes() + b"mutation")
        return result

    monkeypatch.setattr(assert_chrome_zip, "inspect", mutate)
    with pytest.raises(assert_chrome_zip.PackageError, match="mutated"):
        assert_chrome_zip.canonical_gate_verify(
            "chrome-extension-package", artifact.relative_to(tmp_path).as_posix()
        )


def test_privacy_adapter_detects_artifact_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_roots(monkeypatch, tmp_path)
    artifact = _package(
        tmp_path / "extension" / "dist" / "wins-vpn-companion-edge.zip", "edge"
    )

    def mutate() -> None:
        artifact.write_bytes(artifact.read_bytes() + b"mutation")

    _stub_privacy_inventory(monkeypatch, mutate=mutate)
    with pytest.raises(privacy.PrivacyError, match="mutated"):
        privacy.canonical_extension_gate_verify(
            "edge-extension-package", artifact.relative_to(tmp_path).as_posix()
        )


@pytest.mark.parametrize(
    ("module", "argv"),
    [
        (assert_chrome_zip, ["--verify"]),
        (assert_firefox_zip, ["--verify", "firefox-extension-package"]),
    ],
)
def test_package_adapter_requires_exact_argv(module, argv: list[str]) -> None:
    with pytest.raises(module.PackageError, match="exactly --verify"):
        module.main(["adapter.py", *argv])


def test_privacy_adapter_requires_exact_argv() -> None:
    with pytest.raises(privacy.PrivacyError, match="exactly --verify"):
        privacy.main(["--verify", "chrome-extension-package"])


@pytest.mark.parametrize(
    ("target_id", "filename", "browser"),
    [
        ("chrome-extension-package", "wins-vpn-companion-chrome.zip", "chrome"),
        ("edge-extension-package", "wins-vpn-companion-edge.zip", "edge"),
        ("firefox-extension-package", "wins-vpn-companion-firefox.zip", "firefox"),
    ],
)
def test_builder_packages_pass_obfuscation_javascript_hardening(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_id: str,
    filename: str,
    browser: str,
) -> None:
    builder = _load_builder()
    builder.DIST = tmp_path / "extension" / "dist"
    artifact = builder.zip_package(builder.stage(browser), browser)
    assert artifact.name == filename
    with zipfile.ZipFile(artifact) as archive:
        js_members = [name for name in archive.namelist() if name.endswith(".js")]
        assert js_members
        for name in js_members:
            payload = archive.read(name)
            minifier.reject_packaged_javascript(name, payload.decode("utf-8"))
            obfuscation.reject_unminified_or_obfuscated_extension_js(name, payload)
    obfuscation.verify_extension_javascript_hardening(browser, [artifact])


def test_pretty_javascript_is_refused_by_store_minification_gate() -> None:
    pretty = b"function start() {\n  const ok = true;\n  return ok;\n}\n"
    with pytest.raises(minifier.MinifyError, match="not store-permitted minified"):
        minifier.reject_packaged_javascript("src/background/background.js", pretty.decode())
    with pytest.raises(obfuscation.ObfuscationError, match="not store-permitted minified"):
        obfuscation.reject_unminified_or_obfuscated_extension_js(
            "src/background/background.js", pretty
        )


def test_obfuscation_gate_refuses_hostile_producer_mutations(
    tmp_path: Path,
) -> None:
    chrome = _producer_zip("chrome")
    member = "src/core/constants.js"
    with zipfile.ZipFile(io.BytesIO(chrome)) as archive:
        original = archive.read(member)

    def rewrite(*, replace=None, comment=None):
        source = zipfile.ZipFile(io.BytesIO(chrome))
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dest:
            for info in source.infolist():
                data = source.read(info.filename)
                if replace and info.filename in replace:
                    data = replace[info.filename]
                dest.writestr(info.filename, data)
            if comment is not None:
                dest.comment = comment
        return out.getvalue()

    cases = (
        rewrite(comment=b"sourceMappingURL:hidden.js.map"),
        rewrite(replace={member: b" " + original}),
        rewrite(replace={member: original + b"\n"}),
        rewrite(replace={member: b"const ok=true;function start(){return 1;}\n"}),
    )
    for index, payload in enumerate(cases):
        artifact = tmp_path / f"hostile-{index}.zip"
        artifact.write_bytes(payload)
        os.chmod(artifact, 0o644)
        with pytest.raises(obfuscation.ObfuscationError):
            obfuscation.verify_extension_javascript_hardening("chrome", [artifact])


def _copy_zip(
    payload: bytes,
    *,
    comment: bytes | None = None,
    extra: dict[str, bytes] | None = None,
) -> bytes:
    source = zipfile.ZipFile(io.BytesIO(payload))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dest:
        for info in source.infolist():
            dest.writestr(info.filename, source.read(info.filename))
        if extra:
            for name, body in extra.items():
                dest.writestr(name, body)
        if comment is not None:
            dest.comment = comment
    return out.getvalue()


def test_inspect_enforces_producer_zip_hygiene_and_member_closure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_roots(monkeypatch, tmp_path)
    chrome = _producer_zip("chrome")
    assert assert_chrome_zip.inspect_bytes(chrome, "chrome")["ok"] is True
    commented = _copy_zip(chrome, comment=b"sourceMappingURL=evil.map")
    commented_result = assert_chrome_zip.inspect_bytes(commented, "chrome")
    assert commented_result["ok"] is False
    assert any("comment" in failure or "source-map" in failure for failure in commented_result["failures"])
    extra = _copy_zip(chrome, extra={"README.txt": b"extra"})
    extra_result = assert_chrome_zip.inspect_bytes(extra, "chrome")
    assert extra_result["ok"] is False
    assert any("extra" in failure for failure in extra_result["failures"])
    nfc_name = "src/cafe" + "\u0301" + ".js"
    assert unicodedata.normalize("NFC", nfc_name) != nfc_name
    nfc_result = assert_chrome_zip.inspect_bytes(
        _copy_zip(chrome, extra={nfc_name: b"export const x=1;\n"}), "chrome"
    )
    assert nfc_result["ok"] is False
    assert any("non-NFC" in failure for failure in nfc_result["failures"])
    nested = _copy_zip(
        _producer_zip("firefox"), extra={"src/META-INF/mozilla.rsa": b"nested"}
    )
    nested_result = assert_firefox_zip.inspect_bytes(nested)
    assert nested_result["ok"] is False
    assert any("already packed or already signed" in failure for failure in nested_result["failures"])
    mapped = _copy_zip(chrome, extra={"src/background/background.js.map": b"{}"})
    mapped_result = assert_chrome_zip.inspect_bytes(mapped, "chrome")
    assert mapped_result["ok"] is False
    assert any("source map" in failure for failure in mapped_result["failures"])
    assert nested_result["trusted_signer"] == "none"
    assert mapped_result["trusted_signer"] == "none"


def test_inspect_refuses_leaf_and_ancestor_symlinks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_roots(monkeypatch, tmp_path)
    payload = _producer_zip("chrome")
    hidden = tmp_path / "hidden.zip"
    hidden.write_bytes(payload)
    os.chmod(hidden, 0o644)
    dist = tmp_path / "extension" / "dist"
    dist.mkdir(parents=True)
    leaf = dist / "wins-vpn-companion-chrome.zip"
    leaf.symlink_to(hidden)
    leaf_result = assert_chrome_zip.inspect(leaf, "chrome")
    assert leaf_result["ok"] is False
    assert any("symbolic link" in failure for failure in leaf_result["failures"])
    hidden_dir = tmp_path / "hidden-dist"
    hidden_dir.mkdir()
    real = hidden_dir / "wins-vpn-companion-edge.zip"
    real.write_bytes(_producer_zip("edge"))
    os.chmod(real, 0o644)
    ancestor_dist = tmp_path / "extension" / "dist-edge"
    ancestor_dist.symlink_to(hidden_dir, target_is_directory=True)
    ancestor = ancestor_dist / "wins-vpn-companion-edge.zip"
    ancestor_result = assert_chrome_zip.inspect(ancestor, "edge")
    assert ancestor_result["ok"] is False
    assert any("symbolic link" in failure for failure in ancestor_result["failures"])
    firefox = _write_producer(
        tmp_path / "extension" / "dist" / "wins-vpn-companion-firefox.xpi", "firefox"
    )
    firefox_result = assert_firefox_zip.inspect(firefox)
    assert firefox_result["ok"] is True
    assert firefox_result["trusted_signer"] == "none"
    assert firefox_result["gecko_id"] == assert_firefox_zip.GECKO_ID
