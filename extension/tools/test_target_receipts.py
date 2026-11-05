#!/usr/bin/env python3
"""Exact Chrome, Edge, and Firefox zip receipts recheck leak and policy gates.

These tests drive the reusable verify-only producer entrypoint against already
built archives. They never rebuild, never trust a mutated unpacked source tree,
and fail closed for secret material, unsafe network APIs, CSP, permissions,
archive traversal, duplicate members, and target mismatch.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import zipfile
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent
EXT = TOOLS.parent
ROOT = EXT.parent
REPOSITORY = ROOT
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(ROOT / "tools"))

import checks  # noqa: E402
import cross_store_upload_readiness as readiness  # noqa: E402
import store_js_minifier as minifier  # noqa: E402

ESBUILD_CACHE = Path("/tmp/winsvpn-extension-esbuild-test-cache")
# The operator-supplied offline cache, captured before any fixture redirects
# the environment to the private test cache. Archive bytes are re-verified.
CONFIGURED_ESBUILD_CACHE = os.environ.get(minifier.CACHE_ENV, "").strip()
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
    import importlib.util

    spec = importlib.util.spec_from_file_location("extension_build_receipts", EXT / "build.py")
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    return builder


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


@pytest.fixture(autouse=True)
def _authenticated_chromium_test_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    builder = _load_builder()
    repository = tmp_path / "authenticated-verifier-repository"
    chromium_paths = {
        relative: browser
        for browser, relative in builder.NATIVE_HOST_TEMPLATE_PATHS.items()
        if browser in TEST_CHROMIUM_EXTENSION_IDS
    }
    for relative in builder._verifier_source_relatives():
        destination = repository.joinpath(*relative.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        browser = chromium_paths.get(relative)
        payload = (
            _test_chromium_host_document(browser)
            if browser is not None
            else (REPOSITORY / relative).read_bytes()
        )
        destination.write_bytes(payload)
        destination.chmod(0o644)
    monkeypatch.setitem(globals(), "ROOT", repository)


def _package_zip(tmp_path: Path, target: str) -> Path:
    builder = _load_builder()
    builder.DIST = tmp_path / "dist"
    return builder.zip_package(builder.stage(target), target)


def _rewrite_member(archive: Path, name: str, body: str | bytes) -> None:
    payload = body.encode("utf-8") if isinstance(body, str) else body
    with zipfile.ZipFile(archive, "a") as zf:
        zf.writestr(name, payload)


def _replace_member(archive: Path, name: str, body: str | bytes) -> None:
    payload = body.encode("utf-8") if isinstance(body, str) else body
    with zipfile.ZipFile(archive) as source:
        members = {
            info.filename: source.read(info.filename)
            for info in source.infolist()
            if not info.is_dir()
        }
    members[name] = payload
    tmp = archive.with_suffix(archive.suffix + ".replaced")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as dest:
        for member_name, data in members.items():
            dest.writestr(member_name, data)
    tmp.replace(archive)


def _rewrite_manifest(archive: Path, mutate) -> None:
    with zipfile.ZipFile(archive) as zf:
        manifest = json.loads(zf.read("manifest.json"))
        members = {info.filename: zf.read(info) for info in zf.infolist() if not info.is_dir()}
    mutate(manifest)
    members["manifest.json"] = json.dumps(manifest).encode("utf-8")
    tmp = archive.with_suffix(archive.suffix + ".rewritten")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    tmp.replace(archive)


@pytest.mark.parametrize("target", ["chrome", "edge", "firefox"])
def test_verify_only_accepts_exact_existing_zip(tmp_path: Path, target: str):
    builder = _load_builder()
    archive = _package_zip(tmp_path, target)
    called = {"stage": 0}

    def refuse_rebuild(*_args, **_kwargs):
        called["stage"] += 1
        raise AssertionError("verify-only must not rebuild")

    builder.stage = refuse_rebuild  # type: ignore[method-assign]
    result = builder.verify_existing_package(archive, target, repo=ROOT, verbose=False)
    assert result["ok"] is True
    assert result["rebuilt"] is False
    assert result["trusted_loose_source"] is False
    assert result["browser"] == target
    assert result["target_id"] == builder.TARGET_IDS[target]
    assert result["verifier_source_closure"] == builder.verifier_source_closure(ROOT)
    assert called["stage"] == 0


@pytest.mark.parametrize("target", ["chrome", "edge", "firefox"])
def test_verify_only_does_not_trust_mutated_loose_source(tmp_path: Path, target: str):
    builder = _load_builder()
    archive = _package_zip(tmp_path, target)
    loose = tmp_path / "src" / "core" / "copy.js"
    loose.parent.mkdir(parents=True)
    loose.write_text("You are protected.\nawait fetch(u);\n", encoding="utf-8")
    builder.SRC = tmp_path / "src"
    builder.DIST = tmp_path / "mutated-dist"
    result = builder.verify_existing_package(archive, target, repo=ROOT, verbose=False)
    assert result["ok"] is True


@pytest.mark.parametrize(
    ("target", "other"),
    [("chrome", "edge"), ("edge", "chrome"), ("firefox", "chrome")],
)
def test_verify_only_rejects_target_mismatch(tmp_path: Path, target: str, other: str):
    builder = _load_builder()
    archive = _package_zip(tmp_path, target)
    with pytest.raises(builder.PackageVerifyError, match="exact .* target"):
        builder.verify_existing_package(archive, other, repo=ROOT, verbose=False)


def test_verify_only_rejects_fetch_network_api(tmp_path: Path):
    builder = _load_builder()
    archive = _package_zip(tmp_path, "chrome")
    _rewrite_member(archive, "src/core/probe.js", "await fetch(u);\n")
    with pytest.raises(builder.PackageVerifyError, match="leak or policy|extra members"):
        builder.verify_existing_package(archive, "chrome", repo=ROOT, verbose=False)


def test_verify_only_rejects_secret_bearing_private_key(tmp_path: Path):
    builder = _load_builder()
    archive = _package_zip(tmp_path, "edge")
    _rewrite_member(
        archive,
        "src/core/secret.js",
        "const k = `-----BEGIN PRIVATE KEY-----\\nMII\\n-----END PRIVATE KEY-----`;\n",
    )
    with pytest.raises(builder.PackageVerifyError, match="secret-bearing"):
        builder.verify_existing_package(archive, "edge", repo=ROOT, verbose=False)


def test_verify_only_rejects_weak_csp(tmp_path: Path):
    builder = _load_builder()
    archive = _package_zip(tmp_path, "chrome")

    def weaken(manifest: dict) -> None:
        manifest["content_security_policy"] = {
            "extension_pages": "script-src 'self' 'unsafe-eval'; connect-src https:"
        }

    _rewrite_manifest(archive, weaken)
    with pytest.raises(builder.PackageVerifyError, match="leak or policy"):
        builder.verify_existing_package(archive, "chrome", repo=ROOT, verbose=False)


def test_verify_only_rejects_forbidden_permission(tmp_path: Path):
    builder = _load_builder()
    archive = _package_zip(tmp_path, "firefox")

    def add_tabs(manifest: dict) -> None:
        manifest.setdefault("permissions", []).append("tabs")

    _rewrite_manifest(archive, add_tabs)
    with pytest.raises(builder.PackageVerifyError, match="leak or policy"):
        builder.verify_existing_package(archive, "firefox", repo=ROOT, verbose=False)


def test_verify_only_rejects_duplicate_zip_members(tmp_path: Path):
    builder = _load_builder()
    archive = _package_zip(tmp_path, "chrome")
    with zipfile.ZipFile(archive) as zf:
        payload = zf.read("manifest.json")
    with pytest.warns(UserWarning, match="Duplicate name"):
        with zipfile.ZipFile(archive, "a") as zf:
            zf.writestr("manifest.json", payload)
    with pytest.raises(builder.PackageVerifyError, match="duplicate"):
        builder.verify_existing_package(archive, "chrome", repo=ROOT, verbose=False)


def test_verify_only_rejects_archive_traversal(tmp_path: Path):
    builder = _load_builder()
    archive = tmp_path / "wins-vpn-companion-chrome.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("manifest.json", "{}")
        zf.writestr("../escape.js", "export {};\n")
    with pytest.raises(builder.PackageVerifyError, match="ambiguous zip member path"):
        builder.verify_existing_package(archive, "chrome", repo=ROOT, verbose=False)


def test_verify_only_cli_does_not_rebuild(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    builder = _load_builder()
    monkeypatch.setattr(builder, "REPO_ROOT", ROOT)
    archive = _package_zip(tmp_path, "edge")
    monkeypatch.setattr(
        builder,
        "stage",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("rebuilt")),
    )
    captured = io.StringIO()
    monkeypatch.setattr(sys, "stdout", captured)
    monkeypatch.setattr(
        sys,
        "argv",
        ["build.py", "--verify", "edge-extension-package", str(archive), "--quiet"],
    )
    assert builder.main() == 0
    result = json.loads(captured.getvalue())
    assert result["ok"] is True
    assert result["rebuilt"] is False


def test_readiness_closure_matches_producer_closure():
    builder = _load_builder()
    assert tuple(builder.VERIFIER_SOURCE_PATHS) == readiness.EXTENSION_VERIFIER_SOURCE_PATHS
    assert builder.verifier_source_closure(
        REPOSITORY
    ) == readiness.extension_verifier_source_closure(
        REPOSITORY
    )
    assert checks.EXTENSION_RELEASE_TARGETS["chrome"] == "chrome-extension-package"


def test_authenticated_closure_detects_cross_target_identity_drift():
    builder = _load_builder()
    canonical = builder.verifier_source_closure(ROOT)
    chrome_relative = builder.NATIVE_HOST_TEMPLATE_PATHS["chrome"]
    edge_relative = builder.NATIVE_HOST_TEMPLATE_PATHS["edge"]
    chrome_path = ROOT / chrome_relative
    edge_path = ROOT / edge_relative
    chrome_payload = chrome_path.read_bytes()
    edge_payload = edge_path.read_bytes()
    chrome_path.write_bytes(edge_payload)
    edge_path.write_bytes(chrome_payload)
    drifted = builder.verifier_source_closure(ROOT)
    assert drifted["sha256"] != canonical["sha256"]
    assert drifted["inputs"] != canonical["inputs"]


def test_verify_only_binds_store_minified_javascript_and_exact_manifest(tmp_path: Path):
    import store_js_minifier as minifier

    archive = _package_zip(tmp_path, "chrome")
    with zipfile.ZipFile(archive) as zf:
        controller = zf.read("src/background/controller.js").decode("utf-8")
        manifest = json.loads(zf.read("manifest.json"))
        js_names = [name for name in zf.namelist() if name.endswith(".js")]
        for name in js_names:
            minifier.reject_packaged_javascript(name, zf.read(name).decode("utf-8"))
    assert js_names
    assert "export " in controller
    assert manifest["name"] == checks.EXPECTED_TARGET_NAMES["chrome"]
    assert manifest["version"] == checks.reviewed_extension_version("chrome")


def test_verify_only_keeps_chrome_and_edge_packages_distinct(tmp_path: Path):
    builder = _load_builder()
    chrome = _package_zip(tmp_path / "chrome", "chrome")
    edge = _package_zip(tmp_path / "edge", "edge")
    firefox = _package_zip(tmp_path / "firefox", "firefox")
    builder.require_distinct_chromium_packages({"chrome": chrome, "edge": edge})
    chrome_result = builder.verify_existing_package(chrome, "chrome", repo=ROOT, verbose=False)
    edge_result = builder.verify_existing_package(edge, "edge", repo=ROOT, verbose=False)
    firefox_result = builder.verify_existing_package(
        firefox, "firefox", repo=ROOT, verbose=False
    )
    hashes = {
        chrome_result["sha256"],
        edge_result["sha256"],
        firefox_result["sha256"],
    }
    assert len(hashes) == 3
    assert chrome_result["target_id"] == "chrome-extension-package"
    assert edge_result["target_id"] == "edge-extension-package"
    assert firefox_result["target_id"] == "firefox-extension-package"
    assert chrome.read_bytes() != edge.read_bytes()
    with zipfile.ZipFile(chrome) as zf:
        chrome_manifest = json.loads(zf.read("manifest.json"))
    with zipfile.ZipFile(edge) as zf:
        edge_manifest = json.loads(zf.read("manifest.json"))
    assert chrome_manifest["name"] == checks.EXPECTED_TARGET_NAMES["chrome"]
    assert edge_manifest["name"] == checks.EXPECTED_TARGET_NAMES["edge"]
    assert chrome_manifest["name"] != edge_manifest["name"]


def test_verify_only_rejects_chrome_bytes_reused_under_edge_filename(tmp_path: Path):
    builder = _load_builder()
    chrome = _package_zip(tmp_path, "chrome")
    swapped = tmp_path / "wins-vpn-companion-edge.zip"
    swapped.write_bytes(chrome.read_bytes())
    with pytest.raises(builder.PackageVerifyError, match="exact .* target|leak or policy"):
        builder.verify_existing_package(swapped, "edge", repo=ROOT, verbose=False)


def test_verify_only_reported_hash_rejects_stale_path_bytes(tmp_path: Path):
    builder = _load_builder()
    archive = _package_zip(tmp_path, "firefox")
    original = archive.read_bytes()
    result = builder.verify_existing_package(archive, "firefox", repo=ROOT, verbose=False)
    archive.write_bytes(original + b"\x00stale")
    assert result["sha256"] == hashlib.sha256(original).hexdigest()
    assert result["bytes"] == len(original)
    assert result["sha256"] != hashlib.sha256(archive.read_bytes()).hexdigest()


def test_verify_only_rejects_symlink_and_hardlink_artifacts(tmp_path: Path):
    builder = _load_builder()
    archive = _package_zip(tmp_path, "chrome")
    linked = tmp_path / "wins-vpn-companion-chrome-link.zip"
    linked.symlink_to(archive)
    with pytest.raises(builder.PackageVerifyError, match="symbolic link"):
        builder.verify_existing_package(linked, "chrome", repo=ROOT, verbose=False)

    hard = tmp_path / "wins-vpn-companion-chrome-hard.zip"
    try:
        os.link(archive, hard)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")
    with pytest.raises(builder.PackageVerifyError, match="hard link"):
        builder.verify_existing_package(hard, "chrome", repo=ROOT, verbose=False)


def test_verify_only_rejects_extra_source_map_and_unexpected_files(tmp_path: Path):
    builder = _load_builder()
    archive = _package_zip(tmp_path, "chrome")
    mapped = tmp_path / "wins-vpn-companion-chrome.zip"
    mapped.write_bytes(archive.read_bytes())
    _rewrite_member(mapped, "src/core/copy.js.map", '{"version":3}\n')
    with pytest.raises(builder.PackageVerifyError, match="secret-bearing|native-host"):
        builder.verify_existing_package(mapped, "chrome", repo=ROOT, verbose=False)

    extra = tmp_path / "extra-chrome.zip"
    extra.write_bytes(archive.read_bytes())
    _rewrite_member(extra, "README.txt", "unexpected extra file\n")
    with pytest.raises(builder.PackageVerifyError, match="leak or policy|extra members"):
        builder.verify_existing_package(extra, "chrome", repo=ROOT, verbose=False)


def test_verify_only_refuses_missing_artifact(tmp_path: Path):
    builder = _load_builder()
    missing = tmp_path / "wins-vpn-companion-chrome.zip"
    with pytest.raises(builder.PackageVerifyError, match="missing"):
        builder.verify_existing_package(missing, "chrome", repo=ROOT, verbose=False)


def test_verify_only_rejects_already_signed_members(tmp_path: Path):
    builder = _load_builder()
    archive = _package_zip(tmp_path, "firefox")
    _rewrite_member(archive, "META-INF/mozilla.rsa", b"signature")
    with pytest.raises(builder.PackageVerifyError, match="already packed or already signed"):
        builder.verify_existing_package(archive, "firefox", repo=ROOT, verbose=False)


def test_verify_only_rejects_unminified_javascript(tmp_path: Path):
    builder = _load_builder()
    archive = _package_zip(tmp_path, "chrome")
    pretty = "export function start() {\n  const ok = true;\n  return ok;\n}\n"
    _replace_member(archive, "src/background/background.js", pretty)
    with pytest.raises(
        builder.PackageVerifyError,
        match="minified|producer output",
    ):
        builder.verify_existing_package(archive, "chrome", repo=ROOT, verbose=False)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
