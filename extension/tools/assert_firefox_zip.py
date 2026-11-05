#!/usr/bin/env python3
"""Exit 0 only if the Firefox companion package is a real XPI-shaped zip.

The dashboard used to treat `ls dist/*firefox*.zip` as evidence. That is a
filename. This file opens the zip, reads manifest.json from inside it, and
refuses anything that is not a Firefox MV3 event-page package:

  - valid zip (testzip is None)
  - manifest_version 3
  - browser_specific_settings.gecko.id == companion@winsvpn.org
  - that id also equals the canonical manifest fragment (extension/manifest/
    firefox.jsonc) and the single allowed_extensions of the shipped native-host
    manifest (tools/native_messaging/manifests/org.winsvpn.bridge.firefox.json);
    a drift that would make Firefox silently refuse the bridge fails the gate
  - gecko.strict_min_version major >= 140
  - gecko.data_collection_permissions.required == ["none"]
  - background.scripts present, background.service_worker absent
  - background.type == module
  - every path the manifest names exists as a zip member
  - webRequest + webRequestAuthProvider present (Firefox 407 path)
  - nativeMessaging present
  - no key / update_url / applications / META-INF / _metadata
  - no service-worker-only Chromium package renamed *.firefox.zip

Default path is the canonical dist zip. Pass another path to mutation-test.
Prints one JSON object to stdout. Exit 0 = pass, 1 = fail, 2 = usage.
"""

from __future__ import annotations

import io
import json
import hashlib
import math
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
CANONICAL = ROOT / "dist" / "wins-vpn-companion-firefox.zip"
CANONICAL_TARGET = "firefox-extension-package"
GECKO_ID = "companion@winsvpn.org"
GECKO_MIN_MAJOR = 140
# The two canonical sources of the Firefox native-messaging identity. The add-on
# declares its id in the manifest fragment; the desktop host manifest authorizes
# that exact id in allowed_extensions. Firefox authorizes the native-messaging
# bridge by joining the two: if the produced XPI's gecko.id is not the single id
# the shipped host manifest allows, Firefox refuses the bridge with no
# user-visible error. These checks bind the produced XPI to both sources so the
# gate cannot pass on an XPI whose identity has drifted from what the host that
# is actually installed will accept.
FIREFOX_FRAGMENT_REL = Path("extension/manifest/firefox.jsonc")
FIREFOX_HOST_MANIFEST_REL = Path(
    "tools/native_messaging/manifests/org.winsvpn.bridge.firefox.json"
)
NATIVE_HOST_NAME = "org.winsvpn.bridge"
NATIVE_HOST_TYPE = "stdio"
NATIVE_HOST_TEMPLATE_PATH = "PLACEHOLDER_ABSOLUTE_PATH_TO_HOST"
EXPECTED_NAME = "Win's VPN Proxy"
REQUIRED_PERMS = tuple(sorted(checks.REQUIRED_PERMISSIONS))
OPTIONAL_HOST_PERMISSIONS = list(checks.OPTIONAL_HOST_PERMISSIONS)
STORE_FORBIDDEN_KEYS = ("key", "update_url", "applications")
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


def reviewed_packaged_version() -> str:
    return checks.reviewed_extension_version("firefox")


def __getattr__(name: str):
    if name == "REVIEWED_EXTENSION_VERSION":
        return reviewed_packaged_version()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate manifest key: {key}")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> float:
    raise ValueError(f"non-finite JSON number: {value}")


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite JSON number: {value}")
    return parsed


def _strict_json_loads(payload: str | bytes) -> object:
    return json.loads(
        payload,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_non_finite,
        parse_float=_parse_finite_float,
    )


def _strict_jsonc_loads(payload: str) -> object:
    stripped = jsonc.strip_comments(payload)
    try:
        return _strict_json_loads(stripped)
    except json.JSONDecodeError:
        return _strict_json_loads(jsonc._drop_trailing_commas(stripped))


def _canonical_file_doc(relative: Path, what: str) -> dict:
    """Parse one required canonical repository identity document as strict JSONC."""
    path = REPO_ROOT / relative
    try:
        payload = store_js_minifier.read_regular_nofollow(
            path, what, maximum=64 * 1024, root=REPO_ROOT
        )
    except store_js_minifier.MinifyError as exc:
        raise PackageError(f"{what} {relative} is unavailable: {exc}") from exc
    try:
        doc = _strict_jsonc_loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise PackageError(f"{what} {relative} is unparseable: {exc}") from exc
    if type(doc) is not dict:
        raise PackageError(f"{what} {relative} must be a JSON object")
    return doc


def canonical_firefox_gecko_id() -> str:
    """The add-on id declared by the canonical Firefox manifest fragment."""
    doc = _canonical_file_doc(FIREFOX_FRAGMENT_REL, "Firefox manifest fragment")
    settings = doc.get("browser_specific_settings")
    if type(settings) is not dict:
        raise PackageError(
            f"Firefox manifest fragment {FIREFOX_FRAGMENT_REL} has malformed "
            "browser_specific_settings"
        )
    gecko = settings.get("gecko")
    if type(gecko) is not dict:
        raise PackageError(
            f"Firefox manifest fragment {FIREFOX_FRAGMENT_REL} has malformed "
            "browser_specific_settings.gecko"
        )
    value = gecko.get("id")
    if type(value) is not str or not value:
        raise PackageError(
            f"Firefox manifest fragment {FIREFOX_FRAGMENT_REL} has malformed gecko.id"
        )
    return value


def canonical_firefox_host_allowed_extensions() -> list[str]:
    """The allowed_extensions the canonical native-host manifest will accept."""
    doc = _canonical_file_doc(FIREFOX_HOST_MANIFEST_REL, "Firefox native-host manifest")
    if doc.get("name") != NATIVE_HOST_NAME:
        raise PackageError(
            f"Firefox native-host manifest {FIREFOX_HOST_MANIFEST_REL} must name "
            f"exactly {NATIVE_HOST_NAME!r}"
        )
    if doc.get("type") != NATIVE_HOST_TYPE:
        raise PackageError(
            f"Firefox native-host manifest {FIREFOX_HOST_MANIFEST_REL} must have "
            f"type {NATIVE_HOST_TYPE!r}"
        )
    if doc.get("path") != NATIVE_HOST_TEMPLATE_PATH:
        raise PackageError(
            f"Firefox native-host manifest {FIREFOX_HOST_MANIFEST_REL} must retain "
            "the canonical installer-owned path placeholder"
        )
    value = doc.get("allowed_extensions")
    if (
        type(value) is not list
        or len(value) != 1
        or type(value[0]) is not str
        or not value[0]
    ):
        raise PackageError(
            f"Firefox native-host manifest {FIREFOX_HOST_MANIFEST_REL} must have "
            "exactly one non-empty allowed_extensions identity"
        )
    return value


def identity_binding_failures(gecko_id: str) -> list[str]:
    """Cross-check a produced XPI's gecko.id against the shipped identity sources.

    Firefox refuses a native-messaging bridge whose add-on id is not the exact id
    the host manifest's allowed_extensions permits, and it does so silently. The
    produced package must therefore agree with both the canonical manifest
    fragment and the shipped host manifest. Either document being unavailable,
    malformed, ambiguous, or unparseable is itself a hard failure.
    """
    failures: list[str] = []
    try:
        canonical_id = canonical_firefox_gecko_id()
    except PackageError as exc:
        failures.append(str(exc))
    else:
        if gecko_id != canonical_id:
            failures.append(
                f"gecko.id={gecko_id!r} does not match the canonical fragment "
                f"{FIREFOX_FRAGMENT_REL} gecko.id={canonical_id!r}"
            )
    try:
        allowed = canonical_firefox_host_allowed_extensions()
    except PackageError as exc:
        failures.append(str(exc))
    else:
        if allowed[0] != gecko_id:
            failures.append(
                f"produced XPI gecko.id={gecko_id!r} is not the single identity the shipped "
                f"native-host manifest {FIREFOX_HOST_MANIFEST_REL} allows "
                f"(allowed_extensions={allowed!r}); Firefox would refuse the bridge silently"
            )
    return failures


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_gate_artifact(target_id: str, raw_path: str) -> Path:
    if target_id != CANONICAL_TARGET:
        raise PackageError(f"unsupported exact Firefox extension target: {target_id}")
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
        or resolved.suffix.lower() not in {".zip", ".xpi"}
    ):
        raise PackageError(
            "Firefox extension artifact must be one non-empty .zip or .xpi file"
        )
    stem = resolved.stem.casefold()
    has_firefox_token = re.search(r"(?:^|[-_.])firefox(?:[-_.]|$)", stem)
    has_other_token = any(
        re.search(rf"(?:^|[-_.]){browser}(?:[-_.]|$)", stem)
        for browser in ("chrome", "edge")
    )
    if not has_firefox_token or has_other_token:
        raise PackageError(
            "Firefox extension artifact filename belongs to another exact target"
        )
    return resolved


def canonical_gate_verify(target_id: str, raw_path: str) -> None:
    path = _canonical_gate_artifact(target_id, raw_path)
    before = path.stat()
    before_hash = _sha256(path)
    result = inspect(path)
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
        f"FIREFOX EXTENSION CROSS-STORE GATE: PASS target={target_id} "
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


def inspect_bytes(payload: bytes) -> dict:
    """Inspect exact Firefox package bytes without reopening a pathname."""

    result: dict = {
        "path": "",
        "ok": False,
        "failures": [],
        "size_bytes": None,
        "members": None,
        "gecko_id": None,
        "background": None,
        "name": None,
        "version": None,
        "trusted_signer": "none",
    }
    if type(payload) is not bytes:
        result["failures"].append("package bytes are missing")
        return result
    result["size_bytes"] = len(payload)
    if len(payload) < 64:
        result["failures"].append(f"too small to be a package: {len(payload)} bytes")
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
            result["failures"].append(f"corrupt zip member: {corrupt}")
            return result
        names = zf.namelist()
        result["members"] = len(names)
        try:
            result["failures"].extend(store_js_minifier.zip_hygiene_failures(zf))
        except store_js_minifier.MinifyError as exc:
            result["failures"].append(str(exc))
        if "manifest.json" not in names:
            result["failures"].append("zip has no manifest.json member")
            return result
        try:
            manifest = _strict_json_loads(zf.read("manifest.json"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as e:
            result["failures"].append(f"manifest.json is not JSON: {e}")
            return result
        if type(manifest) is not dict:
            result["failures"].append("manifest.json must be a JSON object")
            return result
        try:
            expected_manifest = producer_manifest("firefox")
        except (OSError, ValueError, PackageError) as exc:
            result["failures"].append(str(exc))
        else:
            if manifest != expected_manifest:
                result["failures"].append("manifest.json is not the producer manifest for this target")
        result["name"] = manifest.get("name")
        result["version"] = manifest.get("version")
        result["background"] = manifest.get("background")
        gecko = ((manifest.get("browser_specific_settings") or {}).get("gecko") or {})
        result["gecko_id"] = gecko.get("id")

        name = manifest.get("name")
        if not isinstance(name, str) or not name.strip():
            result["failures"].append("name missing")
        elif len(name) > 50:
            result["failures"].append(f"name is {len(name)} chars; AMO limit is 50")
        elif name != EXPECTED_NAME:
            result["failures"].append(
                f"name does not match exact firefox target identity: expected {EXPECTED_NAME!r}"
            )
        description = manifest.get("description")
        if not isinstance(description, str) or not description.strip():
            result["failures"].append("description missing")
        elif len(description) > 132:
            result["failures"].append(
                f"description is {len(description)} chars; Chrome Web Store / Edge Add-ons "
                "cap is 132, and AMO imports this field as the listing summary"
            )

        try:
            expected_version = reviewed_packaged_version()
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
            result["failures"].append(
                f"manifest_version={manifest.get('manifest_version')!r}, want 3"
            )
        if result["gecko_id"] != GECKO_ID:
            result["failures"].append(
                f"gecko.id={result['gecko_id']!r}, want {GECKO_ID!r}"
            )
        result["failures"].extend(identity_binding_failures(result["gecko_id"]))
        min_ver = str(gecko.get("strict_min_version") or "")
        try:
            min_major = int(min_ver.split(".")[0])
        except ValueError:
            min_major = 0
        if min_major < GECKO_MIN_MAJOR:
            result["failures"].append(
                f"gecko.strict_min_version={min_ver!r}, want major >= {GECKO_MIN_MAJOR}"
            )
        collection = gecko.get("data_collection_permissions") or {}
        if collection.get("required") != ["none"]:
            result["failures"].append(
                'gecko.data_collection_permissions.required must be ["none"] for AMO upload'
            )
        bg = manifest.get("background") or {}
        if "scripts" not in bg:
            result["failures"].append("Firefox needs background.scripts (event page)")
        if "service_worker" in bg:
            result["failures"].append(
                "Firefox package must not declare background.service_worker"
            )
        if bg.get("type") != "module":
            result["failures"].append(f"background.type={bg.get('type')!r} want module")
        if "minimum_chrome_version" in manifest:
            result["failures"].append("minimum_chrome_version must not appear in the Firefox package")
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
        if "web_accessible_resources" in manifest:
            result["failures"].append("web_accessible_resources must not be declared")
        if "host_permissions" in manifest:
            result["failures"].append("host_permissions must not be declared at install")
        for forbidden in STORE_FORBIDDEN_KEYS:
            if forbidden in manifest:
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
                result["failures"].append(f"manifest references missing zip member: {ref}")
        if "src/adapters/firefox.js" not in names:
            result["failures"].append("src/adapters/firefox.js missing from zip")
        if "src/background/controller.js" not in names:
            result["failures"].append("src/background/controller.js missing from zip")
        try:
            store_js_minifier.require_zip_javascript_matches_producer(zf)
            store_js_minifier.require_static_source_members(zf)
        except store_js_minifier.MinifyError as exc:
            result["failures"].append(str(exc))

    result["ok"] = not result["failures"]
    result["trusted_signer"] = "none"
    return result


def inspect(path: Path) -> dict:
    missing = {
        "path": str(path),
        "ok": False,
        "failures": [f"not a file: {path}"],
        "size_bytes": None,
        "members": None,
        "gecko_id": None,
        "background": None,
        "name": None,
        "version": None,
        "trusted_signer": "none",
    }
    try:
        payload = store_js_minifier.read_regular_nofollow(
            path,
            "Firefox extension package",
            root=REPO_ROOT,
        )
    except store_js_minifier.MinifyError as exc:
        missing["failures"] = [str(exc)]
        return missing
    result = inspect_bytes(payload)
    result["path"] = str(path)
    result["trusted_signer"] = "none"
    return result


def main(argv: list[str]) -> int:
    if argv[1:] == ["--check-host-identity"]:
        failures = identity_binding_failures(GECKO_ID)
        for failure in failures:
            print(f"FIREFOX HOST IDENTITY: FAIL: {failure}", file=sys.stderr)
        if failures:
            return 1
        print(f"FIREFOX HOST IDENTITY: PASS gecko.id={GECKO_ID}")
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
    if result["ok"]:
        return 0
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except PackageError as exc:
        print(f"FIREFOX EXTENSION GATE: FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
