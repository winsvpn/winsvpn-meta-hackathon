"""Static checks that run on every build, before anything is packaged.

Three families:

  manifest   -- the shipped manifest.json says what it is supposed to say for
                that browser, and says nothing it is not supposed to say
  structure  -- every file the manifest names exists, nothing unexpected ships
  copy       -- the user-facing strings do not assert protection the extension
                cannot deliver, AND still contain the qualifications that make
                them honest

The copy family is the one worth explaining. The obvious way to write it is a
list of forbidden words, and that version is worse than useless: the cheapest
way to satisfy "must not contain the word 'protected'" is to delete the sentence
that says what is NOT protected. So every absence assertion here is paired with
a presence assertion, and the forbidden-phrase matcher is negation-aware -- it
ignores a hit that has a negation attached within a short window, because the
disclaimers this file exists to require are exactly the sentences that mention
the forbidden words in order to deny them.

That design is copied from the antivirus lane's verdict-copy test, which found
the same trap the hard way.
"""

from __future__ import annotations

from html.parser import HTMLParser
from store_version import read_pubspec_manifest_version
import json
import os
import re
import stat
import sys
import unicodedata
from pathlib import Path, PurePosixPath

import jsonc  # noqa: E402  (same directory; the comment-tolerant manifest loader)

REPO_ROOT = Path(__file__).resolve().parents[2]
RELEASE_IDENTITY_MAP_PATH = (
    REPO_ROOT / "docs" / "rulings" / "RELEASE_IDENTITY_MAP_20260824.json"
)
EXTENSION_RELEASE_TARGETS = {
    "chrome": "chrome-extension-package",
    "edge": "edge-extension-package",
    "firefox": "firefox-extension-package",
}

PERMITTED_PERMISSIONS = {
    "proxy",
    "nativeMessaging",
    "storage",
    "privacy",
    "declarativeNetRequest",
    "alarms",
    "activeTab",
}
OPTIONAL_HOST_PERMISSIONS = ["<all_urls>"]

# The two permissions that let an extension answer the desktop proxy's 407.
#
# Chromium has always needed them via webRequest.onAuthRequired. Firefox used to
# return proxyAuthorizationHeader from proxy.onRequest over TLS, so it needed
# neither; permitting them there would have been a cost the browser did not have
# to pay. Ruling of 2026-08-07 removed the TLS/certificate path: a CA-classified
# trust record that survives uninstall is not acceptable, even with CA:FALSE and
# a neutral subject. Firefox now uses webRequest over plaintext, the same
# mechanism, so the permission is no longer Chromium-only.
#
# Narrowed per directive: Firefox is permitted exactly this pair, for
# onAuthRequired only. Chrome and Edge remain covered; they must still carry it.
AUTH_PERMISSIONS = {"webRequest", "webRequestAuthProvider"}
CHROMIUM_ONLY_PERMISSIONS = AUTH_PERMISSIONS  # alias kept; external callers reference it
REQUIRED_PERMISSIONS = frozenset(PERMITTED_PERMISSIONS) | AUTH_PERMISSIONS
SAFARI_REQUIRED_PERMISSIONS = frozenset(
    {"nativeMessaging", "storage", "alarms"}
)
EXPECTED_TARGET_NAMES = {
    "chrome": "Win's VPN Proxy for Chrome",
    "edge": "Win's VPN Proxy for Microsoft Edge",
    "firefox": "Win's VPN Proxy",
    "safari": "Win's VPN Proxy for Safari",
}


def required_permissions(target: str) -> frozenset[str]:
    if target == "safari":
        return SAFARI_REQUIRED_PERMISSIONS
    if target in {"chrome", "edge", "firefox"}:
        return REQUIRED_PERMISSIONS
    raise ValueError(f"unsupported extension target: {target}")

FORBIDDEN_MANIFEST_KEYS = [
    ("optional_permissions", "no API permission is reviewed for runtime request"),
    ("web_accessible_resources", "a website could use it to detect this extension"),
    ("host_permissions", "the extension makes no network request of its own"),
    ("externally_connectable", "no web page may message this extension"),
    ("content_scripts", "nothing is injected into pages"),
    ("devtools_page", "not needed"),
    ("chrome_url_overrides", "not needed"),
]

FORBIDDEN_PERMISSIONS = {
    "tabs": "would expose every tab's address at all times; activeTab covers the one place it is needed",
    "webRequestBlocking": "not available in MV3 and not needed",
    "history": "the extension has no reason to see browsing history",
    "cookies": "the extension has no reason to see cookies",
    "downloads": "not needed",
    "scripting": "nothing is injected into pages",
    "webNavigation": "not needed",
    "management": "not needed",
    "debugger": "not needed",
    "<all_urls>": "not a permission this extension takes at install time",
}
WINDOWS_DRIVE_ROOT = re.compile(r"^[A-Za-z]:[\\/]")
CHROMIUM_EXTENSION_ID_RE = re.compile(r"^[a-p]{32}$")
CHROMIUM_ALLOWED_ORIGIN_RE = re.compile(
    r"^chrome-extension://([a-p]{32})/$"
)
CHROMIUM_NATIVE_HOST_KEYS = frozenset(
    {"name", "description", "path", "type", "allowed_origins"}
)
NATIVE_HOST_PATH_PLACEHOLDER = "PLACEHOLDER_ABSOLUTE_PATH_TO_HOST"
MAX_MANIFEST_RESOURCE_DEPTH = 16
MAX_MANIFEST_RESOURCE_BYTES = 1024


class Problem:
    def __init__(self, area: str, detail: str):
        self.area, self.detail = area, detail

    def __str__(self) -> str:
        return f"[{self.area}] {self.detail}"


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_non_finite_json_number(value: str) -> None:
    raise ValueError(f"invalid JSON number: {value}")


def validated_chromium_allowed_origin(host: object, target: str) -> str:
    """Return one exact Chromium store id or refuse an ambiguous host identity."""
    if target not in {"chrome", "edge"}:
        raise ValueError(f"unsupported Chromium target identity: {target}")
    if type(host) is not dict:
        raise ValueError("native-host identity document must be a JSON object")
    origins = host.get("allowed_origins")
    if type(origins) is not list or len(origins) != 1 or type(origins[0]) is not str:
        raise ValueError(
            f"{target} native-host allowed_origins must contain exactly one string identity"
        )
    if set(host) != CHROMIUM_NATIVE_HOST_KEYS:
        raise ValueError(
            "native-host identity document fields are incomplete or unexpected"
        )
    if host.get("name") != "org.winsvpn.bridge":
        raise ValueError("native-host identity name must be 'org.winsvpn.bridge'")
    description = host.get("description")
    if (
        type(description) is not str
        or not description.strip()
        or description != description.strip()
        or len(description.encode("utf-8")) > 256
        or any(ord(character) < 0x20 for character in description)
    ):
        raise ValueError(
            "native-host identity description must be bounded plain text"
        )
    host_path = host.get("path")
    if (
        type(host_path) is not str
        or not host_path
        or "\x00" in host_path
        or "\n" in host_path
        or "\r" in host_path
        or (
            host_path != NATIVE_HOST_PATH_PLACEHOLDER
            and not host_path.startswith("/")
            and WINDOWS_DRIVE_ROOT.match(host_path) is None
        )
    ):
        raise ValueError(
            "native-host identity path must be an absolute host path or the exact installer placeholder"
        )
    if host.get("type") != "stdio":
        raise ValueError("native-host identity type must be 'stdio'")
    origin = origins[0]
    if "placeholder" in origin.casefold():
        raise ValueError(f"{target} native-host identity is still a placeholder")
    matched = CHROMIUM_ALLOWED_ORIGIN_RE.fullmatch(origin)
    if matched is None or CHROMIUM_EXTENSION_ID_RE.fullmatch(matched.group(1)) is None:
        raise ValueError(
            f"{target} native-host allowed_origins must be exactly "
            "['chrome-extension://<32 lowercase a-p letters>/']"
        )
    return matched.group(1)


def check_chromium_native_identity_source(
    chromium_text: str, controller_text: str
) -> list[Problem]:
    """Require the packaged Chromium runtime to gate connectNative on identity."""
    problems: list[Problem] = []
    if type(chromium_text) is not str or type(controller_text) is not str:
        return [Problem("nativeMessaging", "Chromium identity source is not UTF-8 text")]
    adapter = re.sub(r"\s+", "", chromium_text)
    controller = re.sub(r"\s+", "", controller_text)
    adapter_requirements = (
        "exportconstCHROMIUM_EXTENSION_ID_RE=/^[a-p]{32}$/;",
        "origin===expected",
        "nativeMessagingIdentity(){",
        "extensionId=api.runtime.id",
        "if(!isChromiumExtensionId(extensionId))",
        "boundOrigin:chromiumAllowedOrigin(extensionId)",
    )
    for required in adapter_requirements:
        if required not in adapter:
            problems.append(
                Problem(
                    "nativeMessaging",
                    "Chromium adapter does not enforce the reviewed runtime identity comparison",
                )
            )
            break
    gate = controller.find("chromiumNativeIdentityError(this.adapter)")
    connect = controller.find("this.adapter.connectNative(NATIVE_HOST_NAME")
    controller_requirements = (
        "if(identityError){",
        "if(ok!==true){",
        "if(boundOrigin!==`chrome-extension://${extensionId}/`){",
    )
    if (
        gate < 0
        or connect < 0
        or gate >= connect
        or any(required not in controller for required in controller_requirements)
    ):
        problems.append(
            Problem(
                "nativeMessaging",
                "Chromium controller does not fail closed on identity before connectNative",
            )
        )
    return problems


def reviewed_extension_version(target: str) -> str:
    """Read the target version from the canonical cross-platform release identity."""
    target_id = EXTENSION_RELEASE_TARGETS.get(target)
    if target_id is None and target != "safari":
        raise ValueError(f"unsupported extension target: {target}")

    identity = json.loads(
        RELEASE_IDENTITY_MAP_PATH.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_non_finite_json_number,
    )
    if type(identity) is not dict or identity.get("schema_version") != 2:
        raise ValueError("release identity must be a schema_version 2 JSON object")
    platforms = identity.get("platform_mappings")
    if type(platforms) is not dict:
        raise ValueError("release identity platform_mappings must be an object")
    browser_identity = platforms.get("browser_extensions")
    if type(browser_identity) is not dict:
        raise ValueError("release identity browser_extensions must be an object")
    if browser_identity.get("policy") != "pubspec":
        raise ValueError("browser extension release policy must be pubspec")
    expected = read_pubspec_manifest_version(REPO_ROOT / "pubspec.yaml")
    if browser_identity.get("version") != expected:
        raise ValueError("reviewed extension version must equal pubspec")
    reviewed = expected
    target_versions = browser_identity.get("target_versions")
    expected_target_ids = set(EXTENSION_RELEASE_TARGETS.values())
    if type(target_versions) is not dict or set(target_versions) != expected_target_ids:
        raise ValueError(
            "browser extension target_versions must exactly cover Chrome, Edge, and Firefox"
        )
    if any(type(value) is not str or value != reviewed for value in target_versions.values()):
        raise ValueError(
            "every browser extension target version must equal the pubspec version"
        )
    # Safari is a converter/Xcode development source target in this increment,
    # not a store-upload target. It shares the pubspec version but
    # is intentionally absent from target_versions until the owner creates and
    # approves the App Store identity.
    if target == "safari":
        return reviewed
    return target_versions[target_id]


# ---------------------------------------------------------------------------
# manifest + structure
# ---------------------------------------------------------------------------

REVIEWED_EXTENSION_PAGES_CSP = {
    "default-src": ["'none'"], "script-src": ["'self'"], "object-src": ["'none'"],
    "base-uri": ["'none'"], "form-action": ["'none'"], "connect-src": ["'none'"],
    "img-src": ["'self'"], "style-src": ["'self'"],
}

def parse_csp_directives(csp: str) -> dict[str, list[str]] | None:
    out: dict[str, list[str]] = {}
    for part in csp.split(";"):
        tokens = part.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name in out:
            return None
        out[name] = tokens[1:]
    return out

def check_manifest(
    pkg: Path,
    target: str,
    zip_members: frozenset[str] | set[str] | None = None,
) -> list[Problem]:
    problems: list[Problem] = []
    mpath = pkg / "manifest.json"
    if not mpath.exists():
        return [Problem("manifest", "manifest.json is missing")]

    try:
        m = json.loads(
            mpath.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_json_number,
        )
    except (json.JSONDecodeError, ValueError) as e:
        return [Problem("manifest", f"manifest.json is not valid JSON: {e}")]
    if type(m) is not dict:
        return [Problem("manifest", "manifest.json must be a JSON object")]

    if m.get("manifest_version") != 3:
        problems.append(Problem("manifest", "manifest_version must be 3"))

    try:
        reviewed_version = reviewed_extension_version(target)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        problems.append(
            Problem(
                "manifest",
                f"canonical extension release identity is invalid: {error}",
            )
        )
    else:
        if m.get("version") != reviewed_version:
            problems.append(
                Problem(
                    "manifest",
                    f"version={m.get('version')!r} must equal reviewed independent "
                    f"extension version {reviewed_version!r} for {target}",
                )
            )
        if "version_name" in m and m.get("version_name") != reviewed_version:
            problems.append(
                Problem(
                    "manifest",
                    f"version_name={m.get('version_name')!r} must equal reviewed "
                    f"independent extension version {reviewed_version!r} for {target}",
                )
            )

    # Chrome Web Store and Edge Add-ons refuse a description over 132
    # characters (developer.chrome.com/docs/extensions/reference/manifest).
    # AMO's imported summary is 250; the Chromium cap is the tighter one.
    name = m.get("name")
    if not isinstance(name, str) or not name.strip():
        problems.append(Problem("manifest", "name is required for store listing"))
    else:
        name_limit = {"chrome": 75, "edge": 45, "firefox": 50, "safari": 30}.get(target, 0)
        if len(name) > name_limit:
            problems.append(
                Problem(
                    "manifest",
                    f"name is {len(name)} characters; {target} store listing limit is {name_limit}",
                )
            )
        expected_name = EXPECTED_TARGET_NAMES.get(target)
        if expected_name is None or name != expected_name:
            problems.append(
                Problem(
                    "manifest",
                    f"name must bind the package to the exact {target} target: "
                    f"expected {expected_name!r}",
                )
            )
    description = m.get("description")
    if not isinstance(description, str) or not description.strip():
        problems.append(Problem("manifest", "description is required for store listing"))
    elif len(description) > 132:
        problems.append(
            Problem(
                "manifest",
                f"description is {len(description)} characters; Chrome Web Store and "
                "Edge Add-ons cap the manifest description at 132",
            )
        )

    for key, why in FORBIDDEN_MANIFEST_KEYS:
        if key in m:
            problems.append(Problem("manifest", f'"{key}" must not be declared: {why}'))

    # Store-upload zip hygiene. A CRX public key pins an unpacked id and AMO/CWS
    # both reject a self-hosted update_url on a first listing. The stores issue
    # the Chrome/Edge ids; this tree must not invent them via a packed key.
    if "key" in m:
        problems.append(
            Problem("manifest", '"key" must not ship: store listings issue the Chrome/Edge id; a packed key would disagree with native-host allowed_origins')
        )
    if "update_url" in m:
        problems.append(
            Problem("manifest", '"update_url" must not ship: store-signed updates are the distribution path')
        )
    if "applications" in m:
        problems.append(
            Problem("manifest", '"applications" is the legacy Firefox key; gecko.id lives in browser_specific_settings')
        )

    perms = m.get("permissions", [])
    if type(perms) is not list:
        problems.append(Problem("manifest", "permissions must be a JSON array"))
        perms = []
    try:
        required_for_target = required_permissions(target)
    except ValueError as error:
        problems.append(Problem("manifest", str(error)))
        required_for_target = frozenset()
    allowed = set(required_for_target)
    for p in perms:
        if p in FORBIDDEN_PERMISSIONS:
            problems.append(Problem("manifest", f'permission "{p}" is forbidden: {FORBIDDEN_PERMISSIONS[p]}'))
        elif p not in allowed:
            problems.append(
                Problem("manifest", f'permission "{p}" is not on the reviewed list for {target}; '
                                    "add it to checks.py with a reason")
            )
    # Chrome, Edge and Firefox answer the proxy's 407 via webRequest. Safari has
    # no proxy or auth-provider API and must not request permissions it cannot use.
    for required in sorted(required_for_target):
        if required not in perms:
            why = (
                "to answer the desktop proxy's authentication challenge"
                if required in AUTH_PERMISSIONS
                else "and missing"
            )
            problems.append(
                Problem("manifest", f'permission "{required}" is required {why}')
            )
    if target == "safari" and "optional_host_permissions" in m:
        problems.append(
            Problem(
                "manifest",
                "Safari must not request all-host access when this build cannot route or block sites",
            )
        )
    elif target != "safari" and m.get("optional_host_permissions") != OPTIONAL_HOST_PERMISSIONS:
        problems.append(
            Problem(
                "manifest",
                "optional_host_permissions must be exactly ['<all_urls>'] so "
                "webRequest.onAuthRequired can be granted after a user action "
                "and the extension fails closed until then",
            )
        )

    policy = m.get("content_security_policy") or {}
    if set(policy) != {"extension_pages"} or parse_csp_directives(policy.get("extension_pages", "")) != REVIEWED_EXTENSION_PAGES_CSP:
        problems.append(Problem("manifest", "extension_pages CSP differs from the reviewed policy"))

    bg = m.get("background") or {}
    if target in ("chrome", "edge"):
        if "service_worker" not in bg:
            problems.append(Problem("manifest", "Chromium targets need background.service_worker"))
        if "scripts" in bg:
            problems.append(Problem("manifest", "Chromium targets must not declare background.scripts"))
        if "browser_specific_settings" in m:
            problems.append(Problem("manifest", "browser_specific_settings belongs to the Firefox package only"))
    elif target == "firefox":
        # Firefox MV3 runs an event page, not a service worker. This is the
        # single largest structural difference between the targets and the one
        # most likely to be got wrong by copying the Chrome manifest.
        if "scripts" not in bg:
            problems.append(Problem("manifest", "Firefox needs background.scripts (an event page, not a service worker)"))
        if "service_worker" in bg:
            problems.append(Problem("manifest", "Firefox does not run an MV3 service worker; remove background.service_worker"))
        gecko = (m.get("browser_specific_settings") or {}).get("gecko") or {}
        if not gecko.get("id"):
            problems.append(
                Problem("manifest", "Firefox needs browser_specific_settings.gecko.id; the native host's allowed_extensions names it")
            )
        collection = gecko.get("data_collection_permissions") or {}
        if collection != {"required": ["none"]}:
            problems.append(
                Problem(
                    "manifest",
                    'Firefox needs gecko.data_collection_permissions.required exactly ["none"] '
                    "for AMO upload; this add-on does not transmit data off the machine",
                )
            )
        min_ver = str(gecko.get("strict_min_version") or "")
        try:
            min_major = int(min_ver.split(".")[0])
        except ValueError:
            min_major = 0
        if min_major < 140:
            problems.append(
                Problem(
                    "manifest",
                    "Firefox gecko.strict_min_version must be >= 140.0 (AMO data_collection_permissions / current ESR)",
                )
            )
        if "minimum_chrome_version" in m:
            problems.append(Problem("manifest", "minimum_chrome_version is meaningless in the Firefox package"))
    elif target == "safari":
        if bg.get("page") != "src/background/safari.html":
            problems.append(Problem("manifest", "Safari MV3 needs the reviewed module background page"))
        for unsupported_key in ("service_worker", "scripts", "type", "persistent"):
            if unsupported_key in bg:
                problems.append(
                    Problem(
                        "manifest",
                        f"Safari background must not declare {unsupported_key}; the reviewed page is nonpersistent by MV3 default",
                    )
                )
        safari = (m.get("browser_specific_settings") or {}).get("safari") or {}
        min_ver = str(safari.get("strict_min_version") or "")
        try:
            min_major = int(min_ver.split(".")[0])
        except ValueError:
            min_major = 0
        if min_major < 26:
            problems.append(
                Problem(
                    "manifest",
                    "Safari strict_min_version must be >= 26.0, the locally verified API floor",
                )
            )
        if "minimum_chrome_version" in m:
            problems.append(Problem("manifest", "minimum_chrome_version is meaningless in the Safari package"))
    else:
        problems.append(Problem("manifest", f"no background contract exists for target {target!r}"))

    members = frozenset(zip_members) if zip_members is not None else None
    for ref in _referenced_paths(m):
        problems.extend(_check_manifest_resource(pkg, ref, zip_members=members))

    return problems


def _referenced_paths(m: dict) -> list[object]:
    out: list[object] = []
    for size_map in (m.get("icons"), (m.get("action") or {}).get("default_icon")):
        if isinstance(size_map, dict):
            out += list(size_map.values())
        elif isinstance(size_map, str):
            out.append(size_map)
    popup = (m.get("action") or {}).get("default_popup")
    if popup:
        out.append(popup)
    opts = (m.get("options_ui") or {}).get("page")
    if opts:
        out.append(opts)
    bg = m.get("background") or {}
    if bg.get("page"):
        out.append(bg["page"])
    if bg.get("service_worker"):
        out.append(bg["service_worker"])
    scripts = bg.get("scripts")
    if isinstance(scripts, list):
        out += scripts
    elif scripts:
        out.append(scripts)
    for script in m.get("content_scripts") or []:
        if not isinstance(script, dict):
            out.append(script)
            continue
        for key in ("js", "css"):
            items = script.get(key)
            if isinstance(items, list):
                out += items
            elif items:
                out.append(items)
    for war in m.get("web_accessible_resources") or []:
        if isinstance(war, dict):
            resources = war.get("resources")
            if isinstance(resources, list):
                out += resources
            elif resources:
                out.append(resources)
        elif war:
            out.append(war)
    return out


def normalize_manifest_resource_path(ref: object) -> str:
    """Return a contained relative POSIX path, or raise ValueError."""
    if type(ref) is not str or not ref or "\x00" in ref:
        raise ValueError("manifest resource must be a non-empty relative path")
    if any(ord(character) < 32 for character in ref):
        raise ValueError(f"manifest resource contains a control character: {ref}")
    if unicodedata.normalize("NFC", ref) != ref:
        raise ValueError(f"manifest resource is not Unicode NFC: {ref}")
    if "\\" in ref:
        raise ValueError(f"manifest resource uses a backslash path: {ref}")
    if ref.startswith("/") or WINDOWS_DRIVE_ROOT.match(ref):
        raise ValueError(f"manifest resource is an absolute or host path: {ref}")
    parts = ref.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError(f"manifest resource is not a contained relative path: {ref}")
    if any(unicodedata.normalize("NFC", part) != part for part in parts):
        raise ValueError(f"manifest resource is not Unicode NFC: {ref}")
    if len(parts) > MAX_MANIFEST_RESOURCE_DEPTH:
        raise ValueError(f"manifest resource exceeds the path depth limit: {ref}")
    normalized = "/".join(parts)
    if len(normalized.encode("utf-8")) > MAX_MANIFEST_RESOURCE_BYTES:
        raise ValueError(f"manifest resource path is too long: {ref}")
    return normalized


def _check_manifest_resource(
    pkg: Path,
    ref: object,
    *,
    zip_members: frozenset[str] | None,
) -> list[Problem]:
    try:
        normalized = normalize_manifest_resource_path(ref)
    except ValueError as error:
        return [Problem("structure", str(error))]
    if zip_members is not None and normalized not in zip_members:
        return [
            Problem(
                "structure",
                f"manifest resource is not an exact zip member: {normalized}",
            )
        ]
    current = pkg
    for part in PurePosixPath(normalized).parts:
        current /= part
    try:
        current.relative_to(pkg)
    except ValueError:
        return [
            Problem(
                "structure",
                f"manifest resource is not a contained relative path: {normalized}",
            )
        ]
    try:
        info = current.lstat()
    except FileNotFoundError:
        return [Problem("structure", f"manifest references a missing file: {normalized}")]
    if _is_unsafe_extracted_file(info):
        return [
            Problem(
                "structure",
                f"manifest resource is not a regular file in the extracted root: {normalized}",
            )
        ]
    try:
        current.resolve(strict=True).relative_to(pkg.resolve(strict=True))
    except (OSError, ValueError):
        return [
            Problem(
                "structure",
                f"manifest resource is not a contained relative path: {normalized}",
            )
        ]
    return []


def _is_unsafe_extracted_file(info: os.stat_result) -> bool:
    return bool(
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
    )


class ScriptSourceCheck(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.invalid_scripts = 0

    def handle_starttag(self, tag, attrs) -> None:
        if tag.lower() != "script":
            return
        sources = [value for name, value in attrs if name.lower() == "src"]
        if len(sources) != 1 or not sources[0] or not sources[0].strip():
            self.invalid_scripts += 1

    def handle_startendtag(self, tag, attrs) -> None:
        self.handle_starttag(tag, attrs)

def check_structure(pkg: Path) -> list[Problem]:
    problems: list[Problem] = []
    allowed_suffixes = {".js", ".json", ".html", ".css", ".png"}
    for path in pkg.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in allowed_suffixes:
            problems.append(Problem("structure", f"unexpected file type in the package: {path.relative_to(pkg)}"))
    # Inline script would be blocked by the CSP at runtime; catching it here
    # means it is a build failure rather than a feature that mysteriously does
    # not work.
    for html in pkg.rglob("*.html"):
        text = html.read_text(encoding="utf-8", errors="replace")
        parser = ScriptSourceCheck()
        parser.feed(text)
        parser.close()
        for _ in range(parser.invalid_scripts):
            problems.append(
                Problem("structure", f"inline <script> in {html.relative_to(pkg)}")
            )
        if re.search(r"\son[a-z]+\s*=", text, re.IGNORECASE):
            problems.append(Problem("structure", f"inline event handler attribute in {html.relative_to(pkg)}"))
    return problems


# ---------------------------------------------------------------------------
# copy honesty
# ---------------------------------------------------------------------------

NEGATIONS = re.compile(
    r"\b(not|never|cannot|can't|does not|doesn't|no |without|nothing|refus|unless|is not)\b",
    re.IGNORECASE,
)

# A claim about something the extension cannot observe is acceptable when it is
# attributed in the same sentence to the party that can. "The desktop app
# reports X" is honest; "X" is not. This is the same distinction the app lanes
# settled on when they replaced verdict labels with statements about what the
# software had actually matched.
ATTRIBUTIONS = re.compile(
    r"\b(reports?|reported|says?|said|according to|told)\b",
    re.IGNORECASE,
)

# Each entry: phrase, and why it must not be asserted.
FORBIDDEN_ASSERTIONS = [
    (r"\byou are (safe|protected|anonymous|secure)\b", "the extension cannot verify any of this"),
    (r"\bfully protected\b", "nothing here is fully anything"),
    (r"\bcompletely (safe|secure|private|anonymous)\b", "an absolute claim the code cannot support"),
    (r"\bmilitary[- ]grade\b", "marketing, and meaningless"),
    (r"\bno one can (see|read|track)\b", "the extension has no way to know this"),
    (r"\buntraceable\b", "false"),
    (r"\b100%\b", "an absolute claim"),
    (r"\bguarantee[sd]?\b", "nothing here is guaranteed"),
    (r"\byour traffic is encrypted\b", "the desktop app encrypts; this extension cannot confirm it happened"),
    (r"\bhides your ip\b", "the extension does not do this; the tunnel might"),
    (r"\bbypass(es|ing)? (censorship|the firewall|blocks)\b", "describes a threat model, not a mechanism"),
    (r"\bwinn protocol v3\b",
     "the extension has no view of the wire; a claim about it must be attributed to the desktop app "
     "or negated, in the same sentence"),
]

# Paired presence assertions. Deleting the sentence to pass an absence check
# fails one of these instead.
REQUIRED_PHRASES = [
    ("not a VPN on its own", "the central limitation must be stated in the product, not only in a document"),
    ("blocked, not sent unprotected", "the fail-closed behaviour must be described where the user sees it"),
    ("Blocking is deliberate", "the user must be told the block is a choice, not a fault"),
    ("This is not a deliberate block",
     "the sentence above is shown in every fail-closed state, so there must be a counterpart for "
     "the one state where no block is happening; otherwise the popup reassures a user whose "
     "traffic nothing is stopping"),
    ("does nothing at all unless the desktop app is running", "the dependency on the desktop app must be explicit"),
    ("HTTPS connections only", "the CONNECT-only proxy scope must be visible in the product"),
    ("refused on this computer", "plain HTTP must be described as a local refusal, not as routed traffic"),
    ("your network can see them", "the limits of per-site routing must be stated plainly"),
    ("can be read by anyone who has this computer", "the storage risk must be stated, not implied"),
    ("held in memory only", "the credential's lifetime must be stated where the storage claim is made"),
    ("does not run on this operating system",
     "the platforms where Winn Protocol v3 is absent must be named, not glossed"),
    ("does not route or block Safari traffic",
     "the Safari capability boundary must be visible and guarded against copy drift"),
]


# ---------------------------------------------------------------------------
# The block-layer claim, which is the one this file did not cover.
#
# Every fail-closed state's copy ends with the same promise, and the checks above
# require that sentence to be present. That is necessary and it is not
# sufficient: on 2026-08-07 the first live Firefox run found the sentence intact,
# the checker green, and the mechanism that keeps the promise not installed at
# all -- the browser had discarded the entire rule set over two enum values, and
# in-scope traffic went out over the direct connection while the popup said it
# was being blocked. A string checker cannot see that. What it CAN see, and what
# it now asserts, is the structural precondition for the words being able to tell
# the truth:
#
#   1. Every state the machine can produce has copy of its own. `stateCopy()`
#      falls back to the STALE entry, which promises a block, so a state with no
#      copy is not a gap -- it is that promise made about a situation nobody
#      wrote copy for.
#   2. The state that exists for "the block layer is not installed" does NOT
#      carry the promise, and does say plainly that traffic is not being stopped.
#   3. The states that DO keep the promise still carry it, so that deleting the
#      sentence everywhere is not the cheapest way to satisfy (2).
#
# This is the same pairing rule as the rest of the file: no absence assertion
# without a presence assertion beside it.
# ---------------------------------------------------------------------------

BLOCK_PROMISE = "blocked, not sent unprotected"

# The state whose whole reason for existing is that the block layer did not
# install. Named here rather than derived, because the check must fail loudly if
# the state is ever renamed or removed rather than quietly finding nothing.
NOT_ENFORCING_STATE = "NOT_ENFORCING"
NO_ROUTING_SURFACE_STATE = "NO_ROUTING_SURFACE"
PRIVACY_FAILED_STATE = "PRIVACY_FAILED"

# States that route nothing and therefore make no promise about blocking.
NO_PROMISE_STATES = {
    "OFF",
    "PROTECTED",
    NO_ROUTING_SURFACE_STATE,
    NOT_ENFORCING_STATE,
    PRIVACY_FAILED_STATE,
}

# Phrases any one of which counts as saying plainly that traffic is NOT stopped.
# A list rather than one string so the wording can be improved without the check
# becoming a spelling test.
NOT_BLOCKING_PHRASES = [
    "not being stopped",
    "cannot prevent it",
    "not blocking",
    "there is nothing stopping them",
]


def _state_names(constants_js: Path) -> list[str]:
    """The keys of the STATE object in constants.js."""
    text = constants_js.read_text(encoding="utf-8")
    m = re.search(r"export const STATE\s*=\s*\{(.*?)\n\};", text, re.S)
    if not m:
        return []
    return re.findall(r"^\s*([A-Z_]+)\s*:", m.group(1), re.M)


def _state_copy_blocks(copy_js: Path) -> dict[str, str]:
    """Each `[STATE.KEY]: { ... }` entry in STATE_COPY, as raw text."""
    text = copy_js.read_text(encoding="utf-8")
    m = re.search(r"export const STATE_COPY\s*=\s*\{(.*?)\n\};", text, re.S)
    if not m:
        return {}
    body = m.group(1)
    starts = [(mm.group(1), mm.start()) for mm in re.finditer(r"\[STATE\.([A-Z_]+)\]\s*:", body)]
    out: dict[str, str] = {}
    for i, (name, start) in enumerate(starts):
        end = starts[i + 1][1] if i + 1 < len(starts) else len(body)
        out[name] = body[start:end]
    return out


def check_state_copy(copy_js: Path, constants_js: Path) -> list[Problem]:
    problems: list[Problem] = []
    if not constants_js.exists():
        return [Problem("copy", f"{constants_js} is missing; the state list cannot be checked")]

    names = _state_names(constants_js)
    if not names:
        return [Problem("copy", "no STATE object found in constants.js \u2014 the state-copy check is blind")]
    entries = _state_copy_blocks(copy_js)
    if not entries:
        return [Problem("copy", "no STATE_COPY object found in copy.js \u2014 the state-copy check is blind")]

    for name in names:
        if name not in entries:
            problems.append(
                Problem("copy", f'STATE.{name} has no copy of its own; stateCopy() would fall back to '
                                f'the STALE entry, which promises "{BLOCK_PROMISE}" about a state '
                                "nobody wrote copy for")
            )

    if NOT_ENFORCING_STATE not in names:
        problems.append(
            Problem("copy", f"STATE.{NOT_ENFORCING_STATE} is gone. It is the state a failed block "
                            "layer produces; without it a browser that refuses the rules is reported "
                            "with copy that promises the block anyway")
        )
    else:
        block = entries.get(NOT_ENFORCING_STATE, "")
        if BLOCK_PROMISE in block:
            problems.append(
                Problem("copy", f'STATE.{NOT_ENFORCING_STATE} asserts "{BLOCK_PROMISE}" \u2014 it is the '
                                "state for when nothing is being blocked")
            )
        if not any(p in block.lower() for p in NOT_BLOCKING_PHRASES):
            problems.append(
                Problem("copy", f"STATE.{NOT_ENFORCING_STATE} does not say plainly that traffic is not "
                                f"being stopped (expected one of: {', '.join(NOT_BLOCKING_PHRASES)})")
            )

    if NO_ROUTING_SURFACE_STATE not in names:
        problems.append(
            Problem(
                "copy",
                f"STATE.{NO_ROUTING_SURFACE_STATE} is gone. It is the non-blocking state "
                "for a browser build with no routing mechanism",
            )
        )
    else:
        block = entries.get(NO_ROUTING_SURFACE_STATE, "")
        if BLOCK_PROMISE in block:
            problems.append(
                Problem(
                    "copy",
                    f'STATE.{NO_ROUTING_SURFACE_STATE} asserts "{BLOCK_PROMISE}" even though '
                    "this state installs no block",
                )
            )
        if not any(p in block.lower() for p in NOT_BLOCKING_PHRASES):
            problems.append(
                Problem(
                    "copy",
                    f"STATE.{NO_ROUTING_SURFACE_STATE} does not say plainly that traffic is not "
                    f"being stopped (expected one of: {', '.join(NOT_BLOCKING_PHRASES)})",
                )
            )

    if PRIVACY_FAILED_STATE not in names:
        problems.append(
            Problem("copy", "STATE.PRIVACY_FAILED has no privacy-failure state")
        )
    else:
        block = entries.get(PRIVACY_FAILED_STATE, "")
        if BLOCK_PROMISE in block:
            problems.append(
                Problem(
                    "copy",
                    "STATE.PRIVACY_FAILED borrows the unconditional blocking promise",
                )
            )
        required = (
            "web requests are blocked",
            "video and voice",
            "may still open directly",
            "reveal this computer",
        )
        if not all(phrase in block.lower() for phrase in required):
            problems.append(
                Problem(
                    "copy",
                    "STATE.PRIVACY_FAILED must distinguish blocked web requests "
                    "from direct video and voice address exposure",
                )
            )

    # The paired presence assertion: deleting the promise from every state would
    # satisfy the check above, so the states that keep it must still carry it.
    promising = [n for n in names if n not in NO_PROMISE_STATES]
    silent = [n for n in promising if BLOCK_PROMISE not in entries.get(n, "")]
    if silent:
        problems.append(
            Problem("copy", f'these states block but no longer say so: {", ".join(silent)} \u2014 '
                            f'each must carry "{BLOCK_PROMISE}"')
        )
    return problems


_SENTENCE_BREAK = re.compile(r"[.!?\n\r]|['\u2019]\s*[,\]]|\", ")


def _sentence_around(text: str, start: int, end: int) -> str:
    """The sentence containing [start, end), bounded by sentence punctuation."""
    left = 0
    for m in _SENTENCE_BREAK.finditer(text, 0, start):
        left = m.end()
    right_match = _SENTENCE_BREAK.search(text, end)
    right = right_match.start() if right_match else len(text)
    return text[left:right]


def check_copy(copy_js: Path) -> list[Problem]:
    problems: list[Problem] = []
    if not copy_js.exists():
        return [Problem("copy", f"{copy_js} is missing")]
    text = copy_js.read_text(encoding="utf-8")

    for pattern, why in FORBIDDEN_ASSERTIONS:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            # Negation-aware, scoped to the SENTENCE the phrase sits in.
            #
            # The first version of this used a fixed 44-character window and its
            # own self-test caught it letting an overclaim through: the
            # preceding sentence ended in "does not run on this operating
            # system", and that negation -- attached to something else entirely
            # -- excused the assertion that followed it. A character window
            # cannot tell "not X" from "not Y. X". Sentence scope can, and the
            # neighbouring-sentence case is now pinned in the self-test.
            sentence = _sentence_around(text, m.start(), m.end())
            if NEGATIONS.search(sentence) or ATTRIBUTIONS.search(sentence):
                continue
            problems.append(Problem("copy", f'asserts "{m.group(0)}"; {why}'))

    for phrase, why in REQUIRED_PHRASES:
        if phrase.lower() not in text.lower():
            problems.append(Problem("copy", f'the phrase "{phrase}" is gone; {why}'))

    return problems


# ---------------------------------------------------------------------------

def check_native_messaging_wiring(
    pkg: Path,
    target: str,
    host_dir: Path | None = None,
    *,
    authenticated_host_template: bytes | None = None,
    allow_live_template: bool = True,
) -> list[Problem]:
    """The native-messaging pipe, as source, not as a permission string.

    A package can declare `nativeMessaging` and still never call connectNative,
    and a Firefox host template can name a different add-on id than gecko.id;
    Firefox then refuses to launch the host with no user-visible error. Measured
    2026-08-13: the dashboard grep for nativeMessaging|127.0.0.1: passed on a
    PAC comment while allowed_extensions was still wins-vpn-bridge@winsvpn.org.

    Standalone verify must pass `authenticated_host_template` from the already
    hashed verifier-source snapshot. Live template files are never re-read after
    that closure. Missing snapshots fail closed.
    """
    problems: list[Problem] = []
    if target == "safari":
        safari = pkg / "src" / "adapters" / "safari.js"
        controller = pkg / "src" / "background" / "controller.js"
        safari_text = safari.read_text(encoding="utf-8") if safari.is_file() else ""
        controller_text = controller.read_text(encoding="utf-8") if controller.is_file() else ""
        controller_compact = re.sub(r"\s+", "", controller_text)
        required = (
            "api.runtime.sendNativeMessage(",
            "capability_probe",
            "no_native_routing_surface",
            "class SafariAdapter extends BaseAdapter",
        )
        if any(marker not in safari_text for marker in required):
            problems.append(
                Problem(
                    "nativeMessaging",
                    "Safari adapter does not perform the fixed containing-app capability probe",
                )
            )
        if "connectNative(" in safari_text or "NATIVE_HOST_NAME" in safari_text:
            problems.append(
                Problem(
                    "nativeMessaging",
                    "Safari adapter must not attempt to launch the external native-messaging host",
                )
            )
        if (
            "if(!this.routingSurface.ok)return;" not in controller_compact
            or "STATE.NO_ROUTING_SURFACE" not in controller_compact
        ):
            problems.append(
                Problem(
                    "nativeMessaging",
                    "controller does not stop Safari before the external native-host path",
                )
            )
        return problems
    adapter = pkg / "src" / "adapters" / "base.js"
    if not adapter.is_file():
        return [Problem("nativeMessaging", "src/adapters/base.js is missing")]
    if "api.runtime.connectNative(" not in adapter.read_text(encoding="utf-8"):
        problems.append(
            Problem("nativeMessaging", "base adapter does not call api.runtime.connectNative(")
        )

    ctl = pkg / "src" / "background" / "controller.js"
    if not ctl.is_file() or "this.adapter.connectNative(NATIVE_HOST_NAME" not in ctl.read_text(encoding="utf-8"):
        problems.append(
            Problem("nativeMessaging", "controller does not call adapter.connectNative(NATIVE_HOST_NAME")
        )

    const_js = pkg / "src" / "core" / "constants.js"
    const_txt = const_js.read_text(encoding="utf-8") if const_js.is_file() else ""
    m = re.search(r"export const NATIVE_HOST_NAME = '([^']+)'", const_txt)
    host_name = m.group(1) if m else None
    if host_name != "org.winsvpn.bridge":
        problems.append(
            Problem("nativeMessaging", f"NATIVE_HOST_NAME is {host_name!r}, not 'org.winsvpn.bridge'")
        )

    for name in ("chromium.js", "firefox.js"):
        p = pkg / "src" / "adapters" / name
        text = p.read_text(encoding="utf-8") if p.is_file() else ""
        if "extends BaseAdapter" not in text:
            problems.append(Problem("nativeMessaging", f"{name} does not extend BaseAdapter"))
        if re.search(r"\bconnectNative\s*\(", text):
            problems.append(
                Problem("nativeMessaging", f"{name} redefines connectNative; the shared host pipe would be lost")
            )

    if target in {"chrome", "edge"}:
        chromium = pkg / "src" / "adapters" / "chromium.js"
        problems += check_chromium_native_identity_source(
            chromium.read_text(encoding="utf-8") if chromium.is_file() else "",
            ctl.read_text(encoding="utf-8") if ctl.is_file() else "",
        )

    host_text: str | None = None
    if isinstance(authenticated_host_template, (bytes, bytearray)):
        if not authenticated_host_template:
            problems.append(
                Problem(
                    "nativeMessaging",
                    "native-host identity requires an authenticated template snapshot",
                )
            )
            return problems
        try:
            host_text = bytes(authenticated_host_template).decode("utf-8")
        except UnicodeDecodeError as error:
            problems.append(
                Problem("nativeMessaging", f"authenticated host template is not UTF-8: {error}")
            )
            return problems
    elif allow_live_template:
        if host_dir is None:
            host_dir = Path(__file__).resolve().parent.parent.parent / "tools" / "native_messaging" / "manifests"
        host_file = host_dir / f"org.winsvpn.bridge.{target}.json"
        if not host_file.is_file() or host_file.is_symlink():
            problems.append(Problem("nativeMessaging", f"host template missing: {host_file}"))
            return problems
        try:
            host_text = host_file.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            problems.append(Problem("nativeMessaging", f"host template is not readable: {error}"))
            return problems
    else:
        problems.append(
            Problem(
                "nativeMessaging",
                "native-host identity requires an authenticated template snapshot",
            )
        )
        return problems
    try:
        # The templates carry // comments documenting the required value; the
        # same comment-tolerant loader the build already uses for the manifest
        # fragments.
        host = jsonc.loads(host_text)
    except (json.JSONDecodeError, ValueError) as e:
        problems.append(Problem("nativeMessaging", f"host template is not JSON: {e}"))
        return problems
    if type(host) is not dict:
        problems.append(
            Problem("nativeMessaging", "host template must be a JSON object")
        )
        return problems
    if host.get("name") != host_name:
        problems.append(
            Problem("nativeMessaging", f"host template name {host.get('name')!r} != NATIVE_HOST_NAME {host_name!r}")
        )
    if host.get("type") != "stdio":
        problems.append(Problem("nativeMessaging", f"host template type is {host.get('type')!r}, not 'stdio'"))

    mpath = pkg / "manifest.json"
    try:
        manifest = (
            json.loads(
                mpath.read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_non_finite_json_number,
            )
            if mpath.is_file()
            else {}
        )
    except (json.JSONDecodeError, ValueError) as error:
        problems.append(
            Problem("nativeMessaging", f"manifest.json is not valid JSON: {error}")
        )
        return problems
    if target == "firefox":
        gecko = ((manifest.get("browser_specific_settings") or {}).get("gecko") or {}).get("id")
        allowed = host.get("allowed_extensions") or []
        if gecko not in allowed:
            problems.append(
                Problem(
                    "nativeMessaging",
                    f"Firefox gecko id {gecko!r} is not in host allowed_extensions {allowed!r}; "
                    "Firefox will refuse the host with no user-visible error",
                )
            )
    else:
        try:
            validated_chromium_allowed_origin(host, target)
        except ValueError as error:
            problems.append(Problem("nativeMessaging", str(error)))
    return problems


def run(
    pkg: Path,
    target: str,
    copy_js: Path,
    *,
    zip_members: frozenset[str] | set[str] | None = None,
    authenticated_host_templates: dict[str, bytes] | None = None,
    require_authenticated_host_templates: bool = False,
) -> list[Problem]:
    members = frozenset(zip_members) if zip_members is not None else None
    problems = (
        check_manifest(pkg, target, zip_members=members)
        + check_structure(pkg)
        + check_copy(copy_js)
        + check_state_copy(copy_js, copy_js.parent / "constants.js")
    )
    if target == "safari":
        problems += check_native_messaging_wiring(pkg, target)
    elif require_authenticated_host_templates:
        snapshot = None
        if isinstance(authenticated_host_templates, dict):
            snapshot = authenticated_host_templates.get(target)
        if not isinstance(snapshot, (bytes, bytearray)) or not bytes(snapshot):
            problems.append(
                Problem(
                    "nativeMessaging",
                    "native-host identity requires an authenticated template snapshot",
                )
            )
        else:
            problems += check_native_messaging_wiring(
                pkg,
                target,
                authenticated_host_template=bytes(snapshot),
                allow_live_template=False,
            )
    else:
        problems += check_native_messaging_wiring(pkg, target)
    return problems


def selftest() -> bool:
    """Prove the copy checker fires, in both directions."""
    import tempfile

    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "copy.js"

        good = "\n".join(
            [
                "'It is not a VPN on its own.'",
                "'blocked, not sent unprotected'",
                "'Blocking is deliberate.'",
                "'This is not a deliberate block.'",
                "'it does nothing at all unless the desktop app is running and connected'",
                "'The proxy carries HTTPS connections only.'",
                "'Plain HTTP is refused on this computer.'",
                "'their names are looked up normally; your network can see them'",
                "'saved in this browser and can be read by anyone who has this computer'",
                "'the key is held in memory only and is gone when this browser closes'",
                "'Winn Protocol v3 does not run on this operating system.'",
                "'This build does not route or block Safari traffic.'",
                "'This add-on cannot tell you whether you are safe.'",
            ]
        )
        p.write_text(good)
        found = check_copy(p)
        if found:
            ok = False
            print(f"  SELFTEST FAIL  honest copy was rejected: {found[0]}", file=sys.stderr)
        else:
            print("  allowed  honest copy, including a negated forbidden phrase")

        bad = good.replace("'This add-on cannot tell you whether you are safe.'", "'You are protected.'")
        p.write_text(bad)
        found = check_copy(p)
        if not found:
            ok = False
            print("  SELFTEST FAIL  an overclaim was not caught", file=sys.stderr)
        else:
            print(f"  caught   overclaiming assertion -> {found[0].detail}")

        unattributed = good + "\n'This session is carrying Winn Protocol v3.'\n"
        p.write_text(unattributed)
        found = check_copy(p)
        if not found:
            ok = False
            print("  SELFTEST FAIL  an unattributed wire claim was not caught", file=sys.stderr)
        else:
            print(f"  caught   unattributed claim about the wire -> {found[0].detail}")

        attributed = good + "\n'The desktop app reports this session is carrying Winn Protocol v3.'\n"
        p.write_text(attributed)
        found = check_copy(p)
        if found:
            ok = False
            print(f"  SELFTEST FAIL  an attributed claim was rejected: {found[0]}", file=sys.stderr)
        else:
            print("  allowed  the same claim, attributed to the desktop app")

        # The case that broke the first version of this checker: a negation
        # sitting in the sentence BEFORE the assertion must not excuse it.
        neighbour = good.replace(
            "'This add-on cannot tell you whether you are safe.'",
            "'Nothing here is certain. You are protected.'",
        )
        p.write_text(neighbour)
        found = check_copy(p)
        if not found:
            ok = False
            print("  SELFTEST FAIL  a negation in the neighbouring sentence excused an overclaim",
                  file=sys.stderr)
        else:
            print(f"  caught   overclaim next to an unrelated negation -> {found[0].detail}")

        deleted = good.replace("'blocked, not sent unprotected'", "''")
        p.write_text(deleted)
        found = check_copy(p)
        if not found:
            ok = False
            print("  SELFTEST FAIL  deleting the disclaimer was not caught", file=sys.stderr)
        else:
            print(f"  caught   deleted disclaimer -> {found[0].detail}")

        ok = _selftest_state_copy(Path(tmp)) and ok
        ok = _selftest_native_messaging(Path(tmp)) and ok

    return ok


def _selftest_state_copy(tmp: Path) -> bool:
    """Prove the block-layer claim check fires in both non-blocking states.

    Written the same way as the rest of this file and for the same reason: this
    project has repeatedly found guards that had quietly stopped working, and the
    guard this one replaces was green on the night the extension shipped a state
    machine that reached PROTECTED with no block layer installed.
    """
    ok = True
    constants = tmp / "constants.js"
    copy_js = tmp / "state_copy.js"

    def write(states: list[str], entries: dict[str, str]) -> None:
        constants.write_text(
            "export const STATE = {\n"
            + "".join(f"  {s}: '{s.lower()}',\n" for s in states)
            + "};\n",
            encoding="utf-8",
        )
        copy_js.write_text(
            "export const STATE_COPY = {\n"
            + "".join(
                f"  [STATE.{name}]: {{ headline: 'h', detail: {json.dumps(detail)}, action: 'a' }},\n"
                for name, detail in entries.items()
            )
            + "};\n",
            encoding="utf-8",
        )

    states = [
        "OFF",
        "PROTECTED",
        "NO_ROUTING_SURFACE",
        "NO_HOST",
        "NOT_ENFORCING",
        "PRIVACY_FAILED",
    ]
    honest = {
        "OFF": "Nothing is being sent through the desktop app.",
        "PROTECTED": "The desktop app reports its tunnel is up.",
        "NO_ROUTING_SURFACE": "This extension is not blocking browser traffic.",
        "NO_HOST": "Your chosen sites are being blocked, not sent unprotected.",
        "NOT_ENFORCING": "They are not being stopped and this add-on cannot prevent it.",
        "PRIVACY_FAILED": "Your chosen web requests are blocked. Video and voice connections may still open directly and reveal this computer’s address.",
    }

    write(states, honest)
    found = check_state_copy(copy_js, constants)
    if found:
        ok = False
        print(f"  SELFTEST FAIL  honest state copy was rejected: {found[0]}", file=sys.stderr)
    else:
        print("  allowed  state copy where only the non-blocking state omits the promise")

    # 1. a state with no copy at all -- which silently inherits STALE's promise
    write(states + ["ROUTING_FAILED"], honest)
    found = check_state_copy(copy_js, constants)
    if not any("no copy of its own" in f.detail for f in found):
        ok = False
        print("  SELFTEST FAIL  a state with no copy was not caught", file=sys.stderr)
    else:
        print("  caught   a state with no copy of its own -> it would inherit the block promise")

    # 2. the non-blocking state borrowing the promise it cannot keep
    borrowed = dict(honest)
    borrowed["NOT_ENFORCING"] = "Your chosen sites are being blocked, not sent unprotected."
    write(states, borrowed)
    found = check_state_copy(copy_js, constants)
    if not any("it is the state for when nothing is being blocked" in f.detail for f in found):
        ok = False
        print("  SELFTEST FAIL  a borrowed block promise was not caught", file=sys.stderr)
    else:
        print("  caught   the non-blocking state promising a block")

    # 3. the same state going quiet instead of saying what is happening
    quiet = dict(honest)
    quiet["NOT_ENFORCING"] = "Something went wrong."
    write(states, quiet)
    found = check_state_copy(copy_js, constants)
    if not any("does not say plainly" in f.detail for f in found):
        ok = False
        print("  SELFTEST FAIL  silence about a missing block layer was not caught", file=sys.stderr)
    else:
        print("  caught   a missing block layer described without saying traffic is not stopped")

    # 4. deleting the promise everywhere, which is the cheapest way to pass (2)
    stripped = dict(honest)
    stripped["NO_HOST"] = "This add-on cannot reach the desktop app."
    write(states, stripped)
    found = check_state_copy(copy_js, constants)
    if not any("block but no longer say so" in f.detail for f in found):
        ok = False
        print("  SELFTEST FAIL  deleting the promise from a blocking state was not caught",
              file=sys.stderr)
    else:
        print("  caught   a blocking state that stopped saying so")

    # 5. the unavailable-routing state borrowing a block promise
    borrowed_surface = dict(honest)
    borrowed_surface["NO_ROUTING_SURFACE"] = (
        "Your chosen sites are being blocked, not sent unprotected."
    )
    write(states, borrowed_surface)
    found = check_state_copy(copy_js, constants)
    if not any("this state installs no block" in f.detail for f in found):
        ok = False
        print("  SELFTEST FAIL  an unavailable-routing block promise was not caught", file=sys.stderr)
    else:
        print("  caught   unavailable routing promising a block")

    # 6. the unavailable-routing state going quiet about direct traffic
    quiet_surface = dict(honest)
    quiet_surface["NO_ROUTING_SURFACE"] = "No routing mechanism is available."
    write(states, quiet_surface)
    found = check_state_copy(copy_js, constants)
    if not any("NO_ROUTING_SURFACE does not say plainly" in f.detail for f in found):
        ok = False
        print("  SELFTEST FAIL  unavailable routing did not have to say it is non-blocking",
              file=sys.stderr)
    else:
        print("  caught   unavailable routing silent about direct traffic")

    borrowed_privacy = dict(honest)
    borrowed_privacy["PRIVACY_FAILED"] += (
        " Your chosen sites are being blocked, not sent unprotected."
    )
    write(states, borrowed_privacy)
    found = check_state_copy(copy_js, constants)
    if not any("unconditional blocking promise" in f.detail for f in found):
        ok = False
        print(
            "  SELFTEST FAIL  privacy failure borrowed the blocking promise",
            file=sys.stderr,
        )

    quiet_privacy = dict(honest)
    quiet_privacy["PRIVACY_FAILED"] = "Your chosen web requests are blocked."
    write(states, quiet_privacy)
    found = check_state_copy(copy_js, constants)
    if not any("direct video and voice address exposure" in f.detail for f in found):
        ok = False
        print(
            "  SELFTEST FAIL  privacy failure omitted direct media exposure",
            file=sys.stderr,
        )

    return ok


def _selftest_native_messaging(tmp: Path) -> bool:
    """Prove the native-messaging wiring check fires both ways."""
    ok = True
    pkg = tmp / "nm_pkg"
    hosts = tmp / "nm_hosts"
    (pkg / "src" / "adapters").mkdir(parents=True)
    (pkg / "src" / "background").mkdir(parents=True)
    (pkg / "src" / "core").mkdir(parents=True)
    hosts.mkdir(parents=True)

    def write_pkg(connect_native: bool, gecko: str) -> None:
        (pkg / "src" / "adapters" / "base.js").write_text(
            ("port = api.runtime.connectNative(hostName);\n" if connect_native else "port = null;\n"),
            encoding="utf-8",
        )
        (pkg / "src" / "background" / "controller.js").write_text(
            "this.port = this.adapter.connectNative(NATIVE_HOST_NAME, {\n",
            encoding="utf-8",
        )
        (pkg / "src" / "core" / "constants.js").write_text(
            "export const NATIVE_HOST_NAME = 'org.winsvpn.bridge';\n",
            encoding="utf-8",
        )
        (pkg / "src" / "adapters" / "chromium.js").write_text(
            "export class ChromiumAdapter extends BaseAdapter {}\n", encoding="utf-8"
        )
        (pkg / "src" / "adapters" / "firefox.js").write_text(
            "export class FirefoxAdapter extends BaseAdapter {}\n", encoding="utf-8"
        )
        (pkg / "manifest.json").write_text(
            json.dumps({
                "permissions": ["nativeMessaging"],
                "browser_specific_settings": {"gecko": {"id": gecko}},
            }),
            encoding="utf-8",
        )
        (hosts / "org.winsvpn.bridge.firefox.json").write_text(
            json.dumps({
                "name": "org.winsvpn.bridge",
                "type": "stdio",
                "allowed_extensions": ["companion@winsvpn.org"],
            }),
            encoding="utf-8",
        )

    write_pkg(True, "companion@winsvpn.org")
    found = check_native_messaging_wiring(pkg, "firefox", hosts)
    if found:
        ok = False
        print(f"  SELFTEST FAIL  honest native-messaging wiring was rejected: {found[0]}", file=sys.stderr)
    else:
        print("  allowed  nativeMessaging + connectNative + matching Firefox gecko id")

    write_pkg(False, "companion@winsvpn.org")
    found = check_native_messaging_wiring(pkg, "firefox", hosts)
    if not any("connectNative" in f.detail for f in found):
        ok = False
        print("  SELFTEST FAIL  missing api.runtime.connectNative was not caught", file=sys.stderr)
    else:
        print("  caught   adapter without api.runtime.connectNative")

    write_pkg(True, "companion@winsvpn.org")
    (hosts / "org.winsvpn.bridge.firefox.json").write_text(
        json.dumps({
            "name": "org.winsvpn.bridge",
            "type": "stdio",
            "allowed_extensions": ["wins-vpn-bridge@winsvpn.org"],
        }),
        encoding="utf-8",
    )
    found = check_native_messaging_wiring(pkg, "firefox", hosts)
    if not any("allowed_extensions" in f.detail for f in found):
        ok = False
        print("  SELFTEST FAIL  Firefox add-on id mismatch was not caught", file=sys.stderr)
    else:
        print("  caught   Firefox gecko id missing from host allowed_extensions")

    return ok


if __name__ == "__main__":
    print("checks self-test")
    good = selftest()
    print("checks self-test:", "PASS" if good else "FAIL")
    sys.exit(0 if good else 1)
