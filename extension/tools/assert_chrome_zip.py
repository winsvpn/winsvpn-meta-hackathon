#!/usr/bin/env python3
"""Exit 0 only if the Chrome proxy package is a real MV3 service_worker zip.

The dashboard used to treat `ls dist/*chrome*.zip` as evidence. That is a
filename. This opens the zip, reads manifest.json, and refuses anything that
is not a Chromium MV3 service-worker package:

  - valid zip (testzip is None)
  - manifest_version 3
  - background.service_worker present, background.scripts absent
  - background.type == module
  - minimum_chrome_version present and >= 116
  - permissions includes proxy, nativeMessaging, webRequest, webRequestAuthProvider
  - no browser_specific_settings (that's Firefox)
  - no key / update_url / applications (store-issued ids, store-signed updates)
  - no META-INF or _metadata (already signed or already packed)
  - web_accessible_resources absent, host_permissions absent
  - connect-src 'none' CSP
  - every path the manifest names exists as zip member
  - no Firefox-only event page renamed *.chrome.zip

Default path is the canonical Chrome dist zip. The canonical cross-store mode
binds each archive to its reviewed Chrome or Microsoft Edge manifest identity.
Pass another path to mutation-test.
Use --native-identities to check the recorded Chrome/Edge build identities
against their exact native-host templates without an owner-receipt expiry gate.
Prints one JSON object to stdout. Exit 0 = pass, 1 = fail.
"""

from __future__ import annotations

import io
import json
import hashlib
import re
import stat
import sys
import zipfile
from pathlib import Path

import store_js_minifier
import checks
import jsonc

ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = ROOT.parent
CANONICAL = ROOT / "dist" / "wins-vpn-companion-chrome.zip"
CANONICAL_EDGE = ROOT / "dist" / "wins-vpn-companion-edge.zip"
CANONICAL_TARGETS = {
    "chrome-extension-package": "chrome",
    "edge-extension-package": "edge",
}
CHROMIUM_HOST_MANIFEST_RELS = {
    "chrome": Path(
        "tools/native_messaging/manifests/org.winsvpn.bridge.chrome.json"
    ),
    "edge": Path(
        "tools/native_messaging/manifests/org.winsvpn.bridge.edge.json"
    ),
}
EXPECTED_TARGET_NAMES = {
    "chrome": "Win's VPN Proxy for Chrome",
    "edge": "Win's VPN Proxy for Microsoft Edge",
}
TARGET_NAME_LIMITS = {"chrome": 75, "edge": 45}
REQUIRED_PERMS = tuple(sorted(checks.REQUIRED_PERMISSIONS))
OPTIONAL_HOST_PERMISSIONS = list(checks.OPTIONAL_HOST_PERMISSIONS)
STORE_FORBIDDEN_KEYS = ("key", "update_url", "applications", "browser_specific_settings")
FORBIDDEN_ZIP_TOP = ("META-INF", "_metadata")
FORBIDDEN_PRIVATE_SUFFIXES = frozenset(
    {
        ".a", ".dll", ".dylib", ".exe", ".jks", ".key", ".keystore",
        ".map", ".node", ".p12", ".pem", ".pfx", ".so", ".wasm",
    }
)
WINDOWS_DRIVE_ROOT = re.compile(r"^[A-Za-z]:[\\/]")


class PackageError(RuntimeError):
    pass


_PRODUCER_MODULE_NAME = "winsvpn_extension_build_producer"

def producer_manifest(target: str) -> dict:
    import importlib.util
    module = sys.modules.get(_PRODUCER_MODULE_NAME)
    if module is None:
        spec = importlib.util.spec_from_file_location(_PRODUCER_MODULE_NAME, ROOT / "build.py")
        if spec is None or spec.loader is None:
            raise PackageError("build.py producer is unavailable")
        module = importlib.util.module_from_spec(spec)
        sys.modules[_PRODUCER_MODULE_NAME] = module
        spec.loader.exec_module(module)
    try:
        return module.build_manifest(target)
    except SystemExit as exc:
        raise PackageError(f"producer manifest for {target} is unavailable: {exc}") from exc


def reviewed_packaged_version(target: str) -> str:
    return checks.reviewed_extension_version(target)


def __getattr__(name: str):
    if name == "REVIEWED_EXTENSION_VERSION":
        return reviewed_packaged_version("chrome")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate manifest key: {key}")
        result[key] = value
    return result


def _reject_non_finite_json_number(value: str) -> None:
    raise ValueError(f"invalid JSON number: {value}")


def canonical_chromium_native_host_ids() -> dict[str, str]:
    """Bind both Chromium targets to exact non-placeholder host identities."""
    identities: dict[str, str] = {}
    for browser, relative in CHROMIUM_HOST_MANIFEST_RELS.items():
        try:
            payload = store_js_minifier.read_regular_nofollow(
                REPO_ROOT / relative,
                f"{browser} canonical native-host identity",
                maximum=64 * 1024,
                root=REPO_ROOT,
            )
        except store_js_minifier.MinifyError as exc:
            raise PackageError(
                f"{browser} canonical native-host identity {relative} is unavailable: {exc}"
            ) from exc
        try:
            document = jsonc.loads(payload.decode("utf-8"))
            identities[browser] = checks.validated_chromium_allowed_origin(
                document, browser
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise PackageError(
                f"{browser} canonical native-host identity {relative} is invalid: {exc}"
            ) from exc
    if identities["chrome"] == identities["edge"]:
        raise PackageError(
            "Chrome and Edge canonical native-host identities must be distinct"
        )
    return identities


def build_native_identities() -> dict[str, str]:
    """Check recorded package identities without expiring a stable store id.

    This is a local build check, not installed-host or store-upload approval.
    Host allowlists remain exact, non-placeholder, and distinct, and must
    agree with the checked-in store record for each target.
    """
    identities = canonical_chromium_native_host_ids()
    try:
        payload = store_js_minifier.read_regular_nofollow(
            REPO_ROOT / "extension/store_listings/store_identity.json",
            "Chromium store identity record",
            maximum=64 * 1024,
            root=REPO_ROOT,
        )
        record = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_json_number,
        )
    except (store_js_minifier.MinifyError, UnicodeError, ValueError) as exc:
        raise PackageError(f"Chromium store identity record is unavailable or invalid: {exc}") from exc
    if (
        type(record) is not dict
        or record.get("contract") != "winsvpn-browser-extension-store-identity-v1"
        or type(record.get("schema_version")) is not int
        or record["schema_version"] != 1
        or record.get("native_host_name") != "org.winsvpn.bridge"
        or type(record.get("stores")) is not dict
    ):
        raise PackageError("Chromium store identity record has an invalid schema")
    for browser, extension_id in identities.items():
        entry = record["stores"].get(f"{browser}-extension-package")
        expected_origin = f"chrome-extension://{extension_id}/"
        if (
            type(entry) is not dict
            or entry.get("store_id") != extension_id
            or entry.get("listing_name") != EXPECTED_TARGET_NAMES[browser]
            or entry.get("native_host_template") != CHROMIUM_HOST_MANIFEST_RELS[browser].as_posix()
            or entry.get("native_host_allowlist") != [expected_origin]
        ):
            raise PackageError(f"{browser} store identity does not match its native-host template")
    return identities


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_gate_artifact(target_id: str, raw_path: str) -> Path:
    browser = CANONICAL_TARGETS.get(target_id)
    if browser is None:
        raise PackageError(f"unsupported exact Chromium extension target: {target_id}")
    relative = Path(raw_path)
    raw_parts = raw_path.split("/")
    if (
        not raw_path
        or "\\" in raw_path
        or WINDOWS_DRIVE_ROOT.match(raw_path)
        or relative.is_absolute()
        or any(part in {"", ".", ".."} for part in raw_parts)
    ):
        raise PackageError(
            "extension artifact path must be repository-relative and contained"
        )
    candidate = REPO_ROOT / relative
    current = REPO_ROOT
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise PackageError("extension artifact path must not contain a symbolic link")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(REPO_ROOT.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise PackageError("extension artifact is missing or escapes the repository") from exc
    info = resolved.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_size <= 0
        or resolved.suffix.lower() != ".zip"
    ):
        raise PackageError("Chromium extension artifact must be one non-empty .zip file")
    stem = resolved.stem.casefold()
    has_browser_token = re.search(
        rf"(?:^|[-_.]){re.escape(browser)}(?:[-_.]|$)", stem
    )
    has_other_token = any(
        re.search(rf"(?:^|[-_.]){re.escape(other)}(?:[-_.]|$)", stem)
        for other in ({"chrome", "edge"} - {browser})
    )
    if not has_browser_token or has_other_token:
        raise PackageError(
            "Chromium extension artifact filename belongs to another exact target"
        )
    return resolved


def canonical_gate_verify(target_id: str, raw_path: str) -> None:
    browser = CANONICAL_TARGETS.get(target_id)
    if browser is None:
        raise PackageError(f"unsupported exact Chromium extension target: {target_id}")
    path = _canonical_gate_artifact(target_id, raw_path)
    before = path.stat()
    before_hash = _sha256(path)
    result = inspect(path, browser)
    after_hash = _sha256(path)
    after = path.stat()
    if not result["ok"]:
        raise PackageError("; ".join(result["failures"]))
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before_hash,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after_hash,
    ):
        raise PackageError("extension artifact mutated during verification")
    print(
        f"CHROMIUM EXTENSION CROSS-STORE GATE: PASS target={target_id} "
        f"version={result['version']} "
        f"artifact={path.relative_to(REPO_ROOT)} sha256={after_hash}"
    )


def _manifest_paths(manifest: dict) -> list[str]:
    out: list[str] = []
    for size_map in (
        manifest.get("icons"),
        (manifest.get("action") or {}).get("default_icon"),
    ):
        if isinstance(size_map, dict):
            out.extend(str(v) for v in size_map.values())
    popup = (manifest.get("action") or {}).get("default_popup")
    if popup:
        out.append(str(popup))
    opts = (manifest.get("options_ui") or {}).get("page")
    if opts:
        out.append(str(opts))
    bg = manifest.get("background") or {}
    out.extend(str(s) for s in bg.get("scripts") or [])
    if bg.get("service_worker"):
        out.append(str(bg["service_worker"]))
    return out


def _hygiene_failures(names: list[str]) -> list[str]:
    failures: list[str] = []
    seen_names: set[str] = set()
    seen_normalized: dict[str, str] = {}
    for name in names:
        if name in seen_names:
            failures.append(f"duplicate zip member name: {name}")
            continue
        seen_names.add(name)
        if "\\" in name:
            failures.append(f"backslash zip member path: {name}")
            continue
        if name.startswith("/") or WINDOWS_DRIVE_ROOT.match(name):
            failures.append(f"unsafe zip member path: {name}")
            continue
        trailing_slash = name.endswith("/")
        parts = name[:-1].split("/") if trailing_slash else name.split("/")
        if not parts or any(part in ("", ".", "..") for part in parts):
            failures.append(f"ambiguous zip member path: {name}")
            continue
        normalized = "/".join(parts)
        if trailing_slash:
            normalized += "/"
        previous = seen_normalized.get(normalized)
        if previous is not None:
            failures.append(
                f"ambiguous normalized zip member paths: {previous} and {name}"
            )
            continue
        seen_normalized[normalized] = name
        top = normalized.rstrip("/").split("/", 1)[0]
        if top.casefold() in {entry.casefold() for entry in FORBIDDEN_ZIP_TOP}:
            failures.append(
                f"store-upload zip must not contain {top}/ "
                "(already packed or already signed)"
            )
        path = Path(normalized.rstrip("/"))
        folded_parts = {part.casefold() for part in path.parts}
        folded_name = path.name.casefold()
        if folded_parts & {entry.casefold() for entry in FORBIDDEN_ZIP_TOP}:
            failures.append(
                f"store-upload zip must not contain {name} "
                "(already packed or already signed)"
            )
        if (
            path.suffix.casefold() in FORBIDDEN_PRIVATE_SUFFIXES
            or "native_messaging" in folded_parts
            or "native-host" in folded_name
            or "native_host" in folded_name
            or folded_name.startswith("wins_bridge_host")
        ):
            failures.append(f"forbidden native-host or private material: {name}")
    return failures


def inspect_bytes(payload: bytes, target: str = "chrome") -> dict:
    """Inspect exact Chromium package bytes without reopening a pathname."""

    result: dict = {
        "path": "",
        "ok": False,
        "failures": [],
        "size_bytes": None,
        "members": None,
        "background": None,
        "name": None,
        "version": None,
        "native_host_extension_id": None,
        "trusted_signer": "none",
    }
    if type(payload) is not bytes:
        result["failures"].append("package bytes are missing")
        return result
    result["size_bytes"] = len(payload)
    if len(payload) < 64:
        result["failures"].append(f"too small: {len(payload)} bytes")
        return result
    buffer = io.BytesIO(payload)
    if not zipfile.is_zipfile(buffer):
        result["failures"].append("not a zip")
        return result
    buffer.seek(0)
    try:
        zf = zipfile.ZipFile(buffer)
    except zipfile.BadZipFile as e:
        result["failures"].append(f"BadZipFile: {e}")
        return result
    with zf:
        corrupt = zf.testzip()
        if corrupt is not None:
            result["failures"].append(f"corrupt member: {corrupt}")
            return result
        names = zf.namelist()
        result["members"] = len(names)
        try:
            result["failures"].extend(store_js_minifier.zip_hygiene_failures(zf))
        except store_js_minifier.MinifyError as exc:
            result["failures"].append(str(exc))
        if "manifest.json" not in names:
            result["failures"].append("no manifest.json")
            return result
        try:
            manifest = json.loads(
                zf.read("manifest.json"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_non_finite_json_number,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as e:
            result["failures"].append(f"manifest not JSON: {e}")
            return result
        if type(manifest) is not dict:
            result["failures"].append("manifest must be a JSON object")
            return result
        try:
            expected_manifest = producer_manifest(target)
        except (OSError, ValueError, PackageError) as exc:
            result["failures"].append(str(exc))
        else:
            if manifest != expected_manifest:
                result["failures"].append("manifest.json is not the producer manifest for this target")
        result["name"] = manifest.get("name")
        result["version"] = manifest.get("version")
        result["background"] = manifest.get("background")

        try:
            native_host_ids = canonical_chromium_native_host_ids()
        except PackageError as exc:
            result["failures"].append(str(exc))
        else:
            result["native_host_extension_id"] = native_host_ids.get(target)
            if result["native_host_extension_id"] is None:
                result["failures"].append(
                    f"unsupported Chromium native-host identity target: {target}"
                )

        expected_name = EXPECTED_TARGET_NAMES.get(target)
        if expected_name is None:
            result["failures"].append(f"unsupported Chromium target identity: {target}")
        name = manifest.get("name")
        if not isinstance(name, str) or not name.strip():
            result["failures"].append("name missing")
        else:
            name_limit = TARGET_NAME_LIMITS[target]
            if len(name) > name_limit:
                store = "Chrome Web Store" if target == "chrome" else "Edge Add-ons"
                result["failures"].append(
                    f"name is {len(name)} chars; {store} limit is {name_limit}"
                )
            if name != expected_name:
                result["failures"].append(
                    f"name does not match exact {target} target identity: "
                    f"expected {expected_name!r}"
                )
        description = manifest.get("description")
        if not isinstance(description, str) or not description.strip():
            result["failures"].append("description missing")
        elif len(description) > 132:
            result["failures"].append(
                f"description is {len(description)} chars; Chrome Web Store / Edge Add-ons limit is 132"
            )

        try:
            expected_version = reviewed_packaged_version(target)
        except (OSError, ValueError) as exc:
            result["failures"].append(str(exc))
            return result
        if result["version"] != expected_version:
            result["failures"].append(
                f"version={result['version']!r} want reviewed "
                f"{expected_version!r}"
            )
        if (
            "version_name" in manifest
            and manifest.get("version_name") != expected_version
        ):
            result["failures"].append(
                f"version_name={manifest.get('version_name')!r} must match reviewed "
                f"{expected_version!r}"
            )

        if manifest.get("manifest_version") != 3:
            result["failures"].append(f"manifest_version={manifest.get('manifest_version')!r} want 3")
        bg = manifest.get("background") or {}
        if "service_worker" not in bg:
            result["failures"].append("Chrome needs background.service_worker")
        if "scripts" in bg:
            result["failures"].append("Chrome must not have background.scripts (that's Firefox)")
        if bg.get("type") != "module":
            result["failures"].append(f"background.type={bg.get('type')!r} want module")
        mcv = manifest.get("minimum_chrome_version")
        if not isinstance(mcv, str) or not mcv:
            result["failures"].append("minimum_chrome_version missing")
        else:
            try:
                if int(mcv.split(".")[0]) < 116:
                    result["failures"].append(f"minimum_chrome_version {mcv!r} < 116")
            except ValueError:
                result["failures"].append(f"minimum_chrome_version unparsable: {mcv!r}")
        perms = manifest.get("permissions") or []
        if type(perms) is not list:
            result["failures"].append("permissions must be a JSON array")
            perms = []
        for p in REQUIRED_PERMS:
            if p not in perms:
                result["failures"].append(f"missing permission {p!r}")
        for p in perms:
            if p not in REQUIRED_PERMS:
                result["failures"].append(f"unreviewed permission {p!r}")
        if manifest.get("optional_host_permissions") != OPTIONAL_HOST_PERMISSIONS:
            result["failures"].append(
                "optional_host_permissions must be exactly ['<all_urls>']"
            )
        if "browser_specific_settings" in manifest:
            result["failures"].append("Chrome package must not have browser_specific_settings")
        if "web_accessible_resources" in manifest:
            result["failures"].append("web_accessible_resources must not be declared")
        if "host_permissions" in manifest:
            result["failures"].append("host_permissions must not be declared")
        for forbidden in STORE_FORBIDDEN_KEYS:
            if forbidden in manifest and forbidden != "browser_specific_settings":
                result["failures"].append(
                    f"{forbidden} must not ship in a store-upload zip"
                )
        csp = (manifest.get("content_security_policy") or {}).get("extension_pages", "")
        if "connect-src 'none'" not in csp:
            result["failures"].append("extension_pages CSP must set connect-src 'none'")
        if "script-src 'self'" not in csp:
            result["failures"].append("extension_pages CSP must pin script-src to 'self'")
        result["failures"].extend(_hygiene_failures(names))
        for ref in _manifest_paths(manifest):
            if ref not in names:
                result["failures"].append(f"manifest refs missing member: {ref}")
        if "src/adapters/chromium.js" not in names:
            result["failures"].append("src/adapters/chromium.js missing")
        if "src/background/controller.js" not in names:
            result["failures"].append("src/background/controller.js missing")
        if (
            "src/adapters/chromium.js" in names
            and "src/background/controller.js" in names
        ):
            try:
                chromium_text = zf.read("src/adapters/chromium.js").decode("utf-8")
                controller_text = zf.read("src/background/controller.js").decode(
                    "utf-8"
                )
            except UnicodeDecodeError as exc:
                result["failures"].append(
                    f"Chromium native-host identity source is not UTF-8: {exc}"
                )
            else:
                result["failures"].extend(
                    problem.detail
                    for problem in checks.check_chromium_native_identity_source(
                        chromium_text, controller_text
                    )
                )
        try:
            store_js_minifier.require_zip_javascript_matches_producer(zf)
            store_js_minifier.require_static_source_members(zf)
        except store_js_minifier.MinifyError as exc:
            result["failures"].append(str(exc))
    result["ok"] = not result["failures"]
    result["trusted_signer"] = "none"
    return result


def inspect(path: Path, target: str = "chrome") -> dict:
    missing = {
        "path": str(path),
        "ok": False,
        "failures": [f"not a file: {path}"],
        "size_bytes": None,
        "members": None,
        "background": None,
        "name": None,
        "version": None,
        "native_host_extension_id": None,
        "trusted_signer": "none",
    }
    try:
        payload = store_js_minifier.read_regular_nofollow(
            path,
            "Chromium extension package",
            root=REPO_ROOT,
        )
    except store_js_minifier.MinifyError as exc:
        missing["failures"] = [str(exc)]
        return missing
    result = inspect_bytes(payload, target)
    result["path"] = str(path)
    result["trusted_signer"] = "none"
    return result


def main(argv: list[str]) -> int:
    if argv[1:2] == ["--native-identities"]:
        if len(argv) != 2:
            raise PackageError("build identity usage is exactly --native-identities")
        json.dump({"ok": True, "identities": build_native_identities()}, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    if argv[1:2] == ["--verify"]:
        if len(argv) != 4:
            raise PackageError(
                "canonical cross-store usage is exactly --verify <target-id> <artifact-path>"
            )
        canonical_gate_verify(argv[2], argv[3])
        return 0
    path = Path(argv[1]) if len(argv) > 1 else CANONICAL
    result = inspect(path)
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except PackageError as exc:
        print(f"CHROMIUM EXTENSION GATE: FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
