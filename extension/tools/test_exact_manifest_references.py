#!/usr/bin/env python3
"""Adversarial regressions for exact extension manifest resource paths.

Manifest-referenced service workers, scripts, icons, and content resources must
be contained relative paths that exist as exact ZIP members. Host paths such as
/etc/passwd must never be treated as package files.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import checks  # noqa: E402

NON_FINITE_JSON_NUMBERS = ("NaN", "Infinity", "-Infinity")
VALID_CHROMIUM_ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
OTHER_CHROMIUM_ID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def _chrome_manifest(**overrides) -> dict:
    manifest = {
        "manifest_version": 3,
        "name": "Win's VPN Proxy for Chrome",
        "version": "1.0.0",
        "description": "Sends chosen sites through the Win's VPN desktop tunnel.",
        "minimum_chrome_version": "116",
        "permissions": [
            "proxy",
            "nativeMessaging",
            "storage",
            "privacy",
            "declarativeNetRequest",
            "alarms",
            "activeTab",
            "webRequest",
            "webRequestAuthProvider",
        ],
        "optional_host_permissions": ["<all_urls>"],
        "background": {
            "service_worker": "src/background/background.js",
            "type": "module",
        },
        "action": {
            "default_popup": "src/ui/popup.html",
            "default_icon": {"16": "src/assets/icon16.png"},
        },
        "options_ui": {"page": "src/ui/options.html", "open_in_tab": True},
        "icons": {"16": "src/assets/icon16.png"},
        "content_security_policy": {
            "extension_pages": "default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; connect-src 'none'; img-src 'self'; style-src 'self'"
        },
    }
    manifest.update(overrides)
    return manifest


def _firefox_manifest(**overrides) -> dict:
    manifest = _chrome_manifest(
        name="Win's VPN Proxy",
        background={"scripts": ["src/background/background.js"], "type": "module"},
        browser_specific_settings={
            "gecko": {
                "id": "companion@winsvpn.org",
                "strict_min_version": "140.0",
                "data_collection_permissions": {"required": ["none"]},
            }
        },
    )
    manifest.pop("minimum_chrome_version", None)
    manifest.update(overrides)
    return manifest


def _write_package(root: Path, manifest: dict) -> Path:
    pkg = root / "pkg"
    files = {
        "src/background/background.js": "export {};\n",
        "src/ui/popup.html": "<html></html>\n",
        "src/ui/options.html": "<html></html>\n",
        "src/assets/icon16.png": b"\x89PNG\r\n\x1a\n",
    }
    for relative, body in files.items():
        path = pkg.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(body, bytes):
            path.write_bytes(body)
        else:
            path.write_text(body, encoding="utf-8")
    (pkg / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return pkg


def _member_set() -> frozenset[str]:
    return frozenset(
        {
            "manifest.json",
            "src/background/background.js",
            "src/ui/popup.html",
            "src/ui/options.html",
            "src/assets/icon16.png",
        }
    )


def _structure_details(pkg: Path, target: str, manifest: dict, members=None) -> list[str]:
    (pkg / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    problems = checks.check_manifest(pkg, target, zip_members=members)
    return [item.detail for item in problems if item.area == "structure"]


def _chromium_host_document(origins: object) -> dict:
    return {
        "name": "org.winsvpn.bridge",
        "description": "Win's VPN browser bridge",
        "path": "PLACEHOLDER_ABSOLUTE_PATH_TO_HOST",
        "type": "stdio",
        "allowed_origins": origins,
    }


def test_exact_chromium_native_host_identity_is_accepted() -> None:
    assert checks.validated_chromium_allowed_origin(
        _chromium_host_document(
            [f"chrome-extension://{VALID_CHROMIUM_ID}/"]
        ),
        "chrome",
    ) == VALID_CHROMIUM_ID


@pytest.mark.parametrize(
    ("origins", "expected"),
    [
        ([], "exactly one"),
        (
            [
                f"chrome-extension://{OTHER_CHROMIUM_ID}/",
                f"chrome-extension://{VALID_CHROMIUM_ID}/",
            ],
            "exactly one",
        ),
        (["chrome-extension://PLACEHOLDER_CHROME_EXTENSION_ID/"], "placeholder"),
        ([f"chrome-extension://{VALID_CHROMIUM_ID}*"], "must be exactly"),
        ([f"chrome-extension://{VALID_CHROMIUM_ID}"], "must be exactly"),
        (f"chrome-extension://{VALID_CHROMIUM_ID}/", "exactly one"),
    ],
)
def test_chromium_native_host_identity_rejects_fail_open_origin_shapes(
    origins: object, expected: str
) -> None:
    with pytest.raises(ValueError, match=expected):
        checks.validated_chromium_allowed_origin(
            _chromium_host_document(origins), "chrome"
        )


@pytest.mark.parametrize(
    "document",
    [
        None,
        [],
        {
            "name": "org.winsvpn.bridge",
            "description": "Win's VPN browser bridge",
            "type": "stdio",
            "allowed_origins": [f"chrome-extension://{VALID_CHROMIUM_ID}/"],
        },
        {
            "name": "org.winsvpn.other",
            "description": "Win's VPN browser bridge",
            "path": "PLACEHOLDER_ABSOLUTE_PATH_TO_HOST",
            "type": "stdio",
            "allowed_origins": [f"chrome-extension://{VALID_CHROMIUM_ID}/"],
        },
        {
            "name": "org.winsvpn.bridge",
            "description": "Win's VPN browser bridge",
            "path": "PLACEHOLDER_ABSOLUTE_PATH_TO_HOST",
            "type": "socket",
            "allowed_origins": [f"chrome-extension://{VALID_CHROMIUM_ID}/"],
        },
        {
            "name": "org.winsvpn.bridge",
            "description": "Win's VPN browser bridge",
            "path": "relative/native-host",
            "type": "stdio",
            "allowed_origins": [f"chrome-extension://{VALID_CHROMIUM_ID}/"],
        },
        {
            "name": "org.winsvpn.bridge",
            "description": "Win's VPN browser bridge",
            "path": "PLACEHOLDER_ABSOLUTE_PATH_TO_HOST",
            "type": "stdio",
            "allowed_origins": [f"chrome-extension://{VALID_CHROMIUM_ID}/"],
            "unexpected_identity_override": True,
        },
    ],
)
def test_chromium_native_host_identity_rejects_malformed_document(
    document: object,
) -> None:
    with pytest.raises(ValueError):
        checks.validated_chromium_allowed_origin(document, "chrome")


@pytest.mark.parametrize("constant", NON_FINITE_JSON_NUMBERS)
def test_direct_chromium_manifest_gate_rejects_non_finite_number(
    tmp_path: Path, constant: str
):
    pkg = _write_package(tmp_path, _chrome_manifest())
    manifest = json.dumps(_chrome_manifest(), allow_nan=False)
    hostile_manifest = manifest[:-1] + f', "hostile_number": {constant}' + "}"
    (pkg / "manifest.json").write_text(hostile_manifest, encoding="utf-8")

    problems = checks.check_manifest(pkg, "chrome", zip_members=_member_set())

    assert any(
        item.area == "manifest"
        and f"invalid JSON number: {constant}" in item.detail
        for item in problems
    )


@pytest.mark.parametrize("constant", NON_FINITE_JSON_NUMBERS)
def test_reviewed_extension_identity_rejects_non_finite_number(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, constant: str
):
    identity_path = tmp_path / "release-identity.json"
    identity_path.write_text(
        '{"schema_version": 2, "hostile_number": ' + constant + "}",
        encoding="utf-8",
    )
    monkeypatch.setattr(checks, "RELEASE_IDENTITY_MAP_PATH", identity_path)

    with pytest.raises(ValueError, match="invalid JSON number"):
        checks.reviewed_extension_version("chrome")


@pytest.mark.parametrize(
    "unsafe",
    [
        "/etc/passwd",
        "C:/Windows/System32/drivers/etc/hosts",
        r"C:\Windows\System32\config\SAM",
        "../escape.js",
        "src/../escape.js",
        "src//dup.js",
        "./background.js",
        r"src\background\background.js",
    ],
)
@pytest.mark.parametrize(
    ("field", "apply"),
    [
        (
            "service_worker",
            lambda manifest, value: manifest["background"].update(
                {"service_worker": value}
            ),
        ),
        (
            "scripts",
            lambda manifest, value: manifest.__setitem__(
                "background", {"scripts": [value], "type": "module"}
            ),
        ),
        (
            "icons",
            lambda manifest, value: manifest.__setitem__("icons", {"16": value}),
        ),
        (
            "content_scripts",
            lambda manifest, value: manifest.__setitem__(
                "content_scripts", [{"js": [value], "matches": ["<all_urls>"]}]
            ),
        ),
    ],
)
def test_manifest_resources_reject_host_and_escaping_paths(
    tmp_path: Path, unsafe: str, field: str, apply
):
    host_passwd = Path("/etc/passwd")
    pkg = _write_package(tmp_path, _chrome_manifest())
    manifest = json.loads((pkg / "manifest.json").read_text(encoding="utf-8"))
    apply(manifest, unsafe)
    details = _structure_details(pkg, "chrome", manifest, members=_member_set())
    assert details
    assert any(
        "absolute or host path" in detail
        or "contained relative path" in detail
        or "backslash" in detail
        for detail in details
    )
    if unsafe == "/etc/passwd" and host_passwd.exists():
        assert not any("missing file: /etc/passwd" in detail for detail in details)
        joined = pkg / unsafe
        assert joined == host_passwd


def test_pathlib_absolute_join_trap_is_closed(tmp_path: Path):
    pkg = _write_package(tmp_path, _chrome_manifest())
    assert Path("/etc/passwd").exists()
    assert (pkg / "/etc/passwd") == Path("/etc/passwd")
    manifest = _chrome_manifest()
    manifest["background"]["service_worker"] = "/etc/passwd"
    details = _structure_details(pkg, "chrome", manifest, members=_member_set())
    assert any("absolute or host path" in detail for detail in details)
    assert checks.normalize_manifest_resource_path.__doc__
    with pytest.raises(ValueError, match="absolute or host path"):
        checks.normalize_manifest_resource_path("/etc/passwd")


def test_content_and_icon_resources_must_be_exact_zip_members(tmp_path: Path):
    pkg = _write_package(tmp_path, _chrome_manifest())
    (pkg / "outside.js").write_text("export {};\n", encoding="utf-8")
    manifest = _chrome_manifest()
    manifest["background"]["service_worker"] = "outside.js"
    details = _structure_details(pkg, "chrome", manifest, members=_member_set())
    assert any("exact zip member: outside.js" in detail for detail in details)

    manifest = _chrome_manifest()
    manifest["icons"] = {"16": "src/assets/icon16.png"}
    details = _structure_details(
        pkg, "chrome", manifest, members=_member_set() | {"src/assets/icon16.png"}
    )
    assert not any("exact zip member" in detail for detail in details)

    manifest["content_scripts"] = [
        {"js": ["src/injected.js"], "matches": ["<all_urls>"]}
    ]
    details = _structure_details(pkg, "chrome", manifest, members=_member_set())
    assert any("exact zip member: src/injected.js" in detail for detail in details)


def test_web_accessible_and_content_css_are_normalized_relative(tmp_path: Path):
    pkg = _write_package(tmp_path, _chrome_manifest())
    manifest = _chrome_manifest()
    manifest["web_accessible_resources"] = [
        {"resources": ["/etc/passwd"], "matches": ["<all_urls>"]}
    ]
    details = _structure_details(pkg, "chrome", manifest, members=_member_set())
    assert any("absolute or host path" in detail for detail in details)

    manifest = _chrome_manifest()
    manifest["content_scripts"] = [
        {"css": ["../host.css"], "matches": ["<all_urls>"]}
    ]
    details = _structure_details(pkg, "chrome", manifest, members=_member_set())
    assert any("contained relative path" in detail for detail in details)


def test_missing_relative_member_is_still_reported(tmp_path: Path):
    pkg = _write_package(tmp_path, _chrome_manifest())
    manifest = _chrome_manifest()
    manifest["background"]["service_worker"] = "src/background/missing.js"
    details = _structure_details(pkg, "chrome", manifest, members=_member_set())
    assert any("exact zip member: src/background/missing.js" in detail for detail in details)
    details = _structure_details(pkg, "chrome", manifest, members=None)
    assert any("missing file: src/background/missing.js" in detail for detail in details)


@pytest.mark.parametrize(
    ("target", "manifest", "required", "forbidden"),
    [
        (
            "chrome",
            _chrome_manifest(),
            "Chromium targets need background.service_worker",
            "Chromium targets must not declare background.scripts",
        ),
        (
            "edge",
            _chrome_manifest(name="Win's VPN Proxy for Microsoft Edge"),
            "Chromium targets need background.service_worker",
            "Chromium targets must not declare background.scripts",
        ),
        (
            "firefox",
            _firefox_manifest(),
            "Firefox needs background.scripts",
            "Firefox does not run an MV3 service worker",
        ),
    ],
)
def test_per_browser_background_mappings_are_preserved(
    tmp_path: Path, target: str, manifest: dict, required: str, forbidden: str
):
    pkg = _write_package(tmp_path, manifest)
    honest = checks.check_manifest(pkg, target, zip_members=_member_set())
    assert not any(required in item.detail or forbidden in item.detail for item in honest)

    if target == "firefox":
        broken = dict(manifest)
        broken["background"] = {
            "service_worker": "src/background/background.js",
            "type": "module",
        }
    else:
        broken = dict(manifest)
        broken["background"] = {
            "scripts": ["src/background/background.js"],
            "type": "module",
        }
    (pkg / "manifest.json").write_text(json.dumps(broken), encoding="utf-8")
    problems = checks.check_manifest(pkg, target, zip_members=_member_set())
    details = [item.detail for item in problems]
    assert any(required in detail or forbidden in detail for detail in details)


def test_chrome_and_edge_manifest_identities_are_distinct():
    chrome = _chrome_manifest()
    edge = _chrome_manifest(name=checks.EXPECTED_TARGET_NAMES["edge"])
    firefox = _firefox_manifest()
    assert chrome["name"] == checks.EXPECTED_TARGET_NAMES["chrome"]
    assert edge["name"] == checks.EXPECTED_TARGET_NAMES["edge"]
    assert firefox["name"] == checks.EXPECTED_TARGET_NAMES["firefox"]
    assert chrome["name"] != edge["name"]
    assert len(chrome["name"]) <= 75
    assert len(edge["name"]) <= 45
    assert len(firefox["name"]) <= 50
    assert chrome["background"].get("service_worker")
    assert "scripts" not in chrome["background"]
    assert edge["background"].get("service_worker")
    assert firefox["background"]["scripts"]
    assert firefox["browser_specific_settings"]["gecko"]["id"] == "companion@winsvpn.org"


def test_optional_host_permissions_are_required_for_all_targets(tmp_path: Path):
    pkg = _write_package(tmp_path, _chrome_manifest())
    for target, manifest in (
        ("chrome", _chrome_manifest()),
        ("edge", _chrome_manifest(name=checks.EXPECTED_TARGET_NAMES["edge"])),
        ("firefox", _firefox_manifest()),
    ):
        (pkg / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        honest = checks.check_manifest(pkg, target, zip_members=_member_set())
        assert not any("optional_host_permissions" in item.detail for item in honest)
        stripped = dict(manifest)
        stripped.pop("optional_host_permissions", None)
        (pkg / "manifest.json").write_text(json.dumps(stripped), encoding="utf-8")
        problems = checks.check_manifest(pkg, target, zip_members=_member_set())
        assert any("optional_host_permissions" in item.detail for item in problems)


def test_extra_unlisted_file_cannot_satisfy_zip_member_binding(tmp_path: Path):
    pkg = _write_package(tmp_path, _chrome_manifest())
    extra = pkg / "src" / "injected.js"
    extra.parent.mkdir(parents=True, exist_ok=True)
    extra.write_text("export {};\n", encoding="utf-8")
    manifest = _chrome_manifest()
    manifest["content_scripts"] = [
        {"js": ["src/injected.js"], "matches": ["<all_urls>"]}
    ]
    details = _structure_details(pkg, "chrome", manifest, members=_member_set())
    assert any("exact zip member: src/injected.js" in detail for detail in details)
    loose_details = _structure_details(pkg, "chrome", manifest, members=None)
    assert not any("exact zip member: src/injected.js" in detail for detail in loose_details)


def test_normalize_rejects_nfc_and_control_chars():
    nfd = "src/cafe\u0301.js"
    with pytest.raises(ValueError, match="Unicode NFC"):
        checks.normalize_manifest_resource_path(nfd)
    with pytest.raises(ValueError, match="control character"):
        checks.normalize_manifest_resource_path("src/\nbackground.js")
    assert (
        checks.normalize_manifest_resource_path("src/background/background.js")
        == "src/background/background.js"
    )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
