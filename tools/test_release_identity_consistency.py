#!/usr/bin/env python3
"""Unified source, store-metadata, receipt, and dashboard release identity gate."""

from __future__ import annotations

import json
import plistlib
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
EXTENSION_TOOLS = ROOT / "extension" / "tools"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(EXTENSION_TOOLS))

import assert_chrome_zip
import assert_firefox_zip
import cross_store_upload_readiness as cross_store
import jsonc
from dashboard import server as dashboard


IDENTITY_MAP_PATH = ROOT / "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json"
EXTENSION_TARGET_IDS = frozenset(
    {
        "chrome-extension-package",
        "edge-extension-package",
        "firefox-extension-package",
    }
)
PLATFORM_MAPPING_FIELDS = {
    "android_phone": {"package", "version_name", "version_code"},
    "android_tv": {"package", "version_name", "version_code"},
    "wear_os": {"package", "version_name", "version_code"},
    "apple": {
        "short_version",
        "bundle_version",
        "required_artifacts",
        "optional_distribution",
        "required_upload_targets",
        "optional_evidence_targets",
        "shipping_surfaces",
    },
    "windows": {"product_version", "four_part_version"},
    "linux": {"appstream_version", "debian_version"},
    "browser_extensions": {"version", "policy", "target_versions"},
}
APPLE_LIST_FIELDS = {
    "required_artifacts": [
        "ios_app_store_ipa_with_embedded_watchos",
        "macos_app_store_pkg",
    ],
    "optional_distribution": ["macos_developer_id"],
    "required_upload_targets": ["ios-app-store-ipa", "macos-app-store-pkg"],
    "optional_evidence_targets": ["macos-developer-id-app"],
    "shipping_surfaces": ["ios", "watchos", "macos"],
}


class ReleaseIdentityError(ValueError):
    """Raised when the reviewed release identity ruling is not exact."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseIdentityError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _exact_dict(value: object, keys: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict:
        raise ReleaseIdentityError(f"{label} must be an object")
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        unexpected = sorted(actual - keys)
        raise ReleaseIdentityError(
            f"{label} keys are not exact: missing={missing} unexpected={unexpected}"
        )
    return value


def _require_string(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise ReleaseIdentityError(f"{label} must be a non-empty string")
    return value


def _require_integer(value: object, label: str) -> int:
    if type(value) is not int or value <= 0 or value > 65535:
        raise ReleaseIdentityError(f"{label} must be an integer from 1 through 65535")
    return value


def _require_string_list(value: object, label: str) -> list[str]:
    if (
        type(value) is not list
        or not value
        or any(type(item) is not str or not item for item in value)
        or len(value) != len(set(value))
    ):
        raise ReleaseIdentityError(
            f"{label} must be a non-empty list of unique non-empty strings"
        )
    return value


def load_release_identity_map(path: Path = IDENTITY_MAP_PATH) -> dict[str, object]:
    try:
        ruling = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseIdentityError(f"release identity map is unreadable: {exc}") from exc
    top = _exact_dict(
        ruling,
        {
            "schema_version",
            "canonical_release",
            "marketing_version",
            "build_number",
            "platform_mappings",
        },
        "release identity map",
    )
    if type(top["schema_version"]) is not int or top["schema_version"] != 2:
        raise ReleaseIdentityError("release identity schema_version must be integer 2")
    canonical = _require_string(top["canonical_release"], "canonical_release")
    marketing = _require_string(top["marketing_version"], "marketing_version")
    build = _require_integer(top["build_number"], "build_number")
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", marketing) is None:
        raise ReleaseIdentityError("marketing_version must be three-part numeric semver")
    if canonical != f"{marketing}+{build}":
        raise ReleaseIdentityError("canonical_release does not match version and build")

    mappings = _exact_dict(
        top["platform_mappings"], set(PLATFORM_MAPPING_FIELDS), "platform_mappings"
    )
    for platform, fields in PLATFORM_MAPPING_FIELDS.items():
        mapping = _exact_dict(mappings[platform], fields, platform)
        for key, value in mapping.items():
            if key == "version_code":
                _require_integer(value, f"{platform}.{key}")
            elif key == "target_versions":
                target_versions = _exact_dict(
                    value,
                    set(EXTENSION_TARGET_IDS),
                    "browser_extensions.target_versions",
                )
                for target_id, version in target_versions.items():
                    _require_string(
                        version, f"browser_extensions.target_versions.{target_id}"
                    )
            elif key in {
                "required_artifacts",
                "optional_distribution",
                "required_upload_targets",
                "optional_evidence_targets",
                "shipping_surfaces",
            }:
                _require_string_list(value, f"{platform}.{key}")
                if value != APPLE_LIST_FIELDS[key]:
                    raise ReleaseIdentityError(
                        f"{platform}.{key} does not match the reviewed list"
                    )
            else:
                _require_string(value, f"{platform}.{key}")

    expected_android = {
        "android_phone": {
            "package": "org.winsvpn.app",
            "version_name": marketing,
            "version_code": build,
        },
        "android_tv": {
            "package": "org.winsvpn.app",
            "version_name": marketing,
            "version_code": build * 100 + 2,
        },
        "wear_os": {
            "package": "org.winsvpn.app",
            "version_name": marketing,
            "version_code": build * 100 + 1,
        },
    }
    for platform, expected in expected_android.items():
        if mappings[platform] != expected:
            raise ReleaseIdentityError(f"{platform} release identity is inconsistent")
    expected_values = {
        "apple": {
            "short_version": marketing,
            "bundle_version": str(build),
            **APPLE_LIST_FIELDS,
        },
        "windows": {
            "product_version": marketing,
            "four_part_version": f"{marketing}.{build}",
        },
        "linux": {
            "appstream_version": marketing,
            "debian_version": f"{marketing}-{build}",
        },
        "browser_extensions": {
            "version": marketing,
            "policy": "pubspec",
            "target_versions": {
                target_id: marketing for target_id in EXTENSION_TARGET_IDS
            },
        },
    }
    for platform, expected in expected_values.items():
        if mappings[platform] != expected:
            raise ReleaseIdentityError(f"{platform} release identity is inconsistent")
    return top


def _strip_kotlin_comments(source: str) -> str:
    """Remove comments while preserving strings, newlines, and executable tokens."""

    output: list[str] = []
    index = 0
    state = "code"
    block_depth = 0
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "/" and following == "/":
                output.extend("  ")
                index += 2
                state = "line_comment"
                continue
            if char == "/" and following == "*":
                output.extend("  ")
                index += 2
                state = "block_comment"
                block_depth = 1
                continue
            if source.startswith('"""', index):
                output.extend('"""')
                index += 3
                state = "raw_string"
                continue
            if char == '"':
                state = "string"
            elif char == "'":
                state = "character"
            output.append(char)
            index += 1
            continue
        if state == "line_comment":
            if char == "\n":
                output.append(char)
                state = "code"
            else:
                output.append(" ")
            index += 1
            continue
        if state == "block_comment":
            if char == "/" and following == "*":
                output.extend("  ")
                index += 2
                block_depth += 1
            elif char == "*" and following == "/":
                output.extend("  ")
                index += 2
                block_depth -= 1
                if block_depth == 0:
                    state = "code"
            else:
                output.append("\n" if char == "\n" else " ")
                index += 1
            continue
        if state == "raw_string":
            if source.startswith('"""', index):
                output.extend('"""')
                index += 3
                state = "code"
            else:
                output.append(char)
                index += 1
            continue
        output.append(char)
        if char == "\\" and index + 1 < len(source):
            output.append(source[index + 1])
            index += 2
            continue
        if (state == "string" and char == '"') or (
            state == "character" and char == "'"
        ):
            state = "code"
        index += 1
    if state != "code" and state != "line_comment":
        raise ReleaseIdentityError(f"unterminated Kotlin lexical state: {state}")
    return "".join(output)


def _kotlin_code_positions(source: str) -> list[bool]:
    """Mark offsets that are Kotlin code rather than string-literal contents."""

    result = [False] * len(source)
    index = 0
    state = "code"
    while index < len(source):
        char = source[index]
        if state == "code":
            if source.startswith('"""', index):
                index += 3
                state = "raw_string"
                continue
            if char == '"':
                index += 1
                state = "string"
                continue
            if char == "'":
                index += 1
                state = "character"
                continue
            result[index] = True
            index += 1
            continue
        if state == "raw_string":
            if source.startswith('"""', index):
                index += 3
                state = "code"
            else:
                index += 1
            continue
        if char == "\\" and index + 1 < len(source):
            index += 2
            continue
        if (state == "string" and char == '"') or (
            state == "character" and char == "'"
        ):
            state = "code"
        index += 1
    if state != "code":
        raise ReleaseIdentityError(f"unterminated Kotlin lexical state: {state}")
    return result


def _named_block(source: str, pattern: str, label: str) -> str:
    code_positions = _kotlin_code_positions(source)
    matches = [
        match
        for match in re.finditer(pattern, source, re.MULTILINE)
        if code_positions[match.start()]
    ]
    if len(matches) != 1:
        raise ReleaseIdentityError(f"{label} block count must be exactly one")
    opening = source.find("{", matches[0].start(), matches[0].end())
    if opening < 0:
        raise ReleaseIdentityError(f"{label} block has no opening brace")
    depth = 0
    state = "code"
    index = opening
    while index < len(source):
        char = source[index]
        if state == "code":
            if source.startswith('"""', index):
                state = "raw_string"
                index += 3
                continue
            if char == '"':
                state = "string"
            elif char == "'":
                state = "character"
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return source[opening + 1 : index]
        elif state == "raw_string":
            if source.startswith('"""', index):
                state = "code"
                index += 3
                continue
        else:
            if char == "\\":
                index += 1
            elif (state == "string" and char == '"') or (
                state == "character" and char == "'"
            ):
                state = "code"
        index += 1
    raise ReleaseIdentityError(f"{label} block is unterminated")


def _string_assignment(source: str, name: str, label: str) -> str:
    values = re.findall(
        rf'(?m)^\s*{re.escape(name)}\s*=\s*"([^"\r\n]+)"\s*$', source
    )
    if len(values) != 1:
        raise ReleaseIdentityError(f"{label}.{name} assignment count must be one")
    return values[0]


def _integer_assignment(source: str, name: str, label: str) -> int:
    values = re.findall(rf"(?m)^\s*{re.escape(name)}\s*=\s*([0-9]+)\s*$", source)
    if len(values) != 1:
        raise ReleaseIdentityError(f"{label}.{name} assignment count must be one")
    return int(values[0])


def parse_android_release_identities(
    android_gradle: str, wear_gradle: str
) -> dict[str, dict[str, str | int]]:
    android_source = _strip_kotlin_comments(android_gradle)
    application = _named_block(
        android_source,
        r"\bextensions\.configure\s*<\s*ApplicationExtension\s*>\s*\{",
        "android ApplicationExtension",
    )
    default = _named_block(application, r"\bdefaultConfig\s*\{", "android defaultConfig")
    flavors = _named_block(
        application, r"\bproductFlavors\s*\{", "android productFlavors"
    )
    phone = _named_block(
        flavors, r'\bcreate\s*\(\s*"phone"\s*\)\s*\{', "android phone flavor"
    )
    television = _named_block(
        flavors, r'\bcreate\s*\(\s*"tv"\s*\)\s*\{', "android tv flavor"
    )
    if re.search(r"(?m)^\s*version(Code|Name)\s*=", phone):
        raise ReleaseIdentityError("android phone flavor must inherit default release identity")
    package = _string_assignment(default, "applicationId", "android defaultConfig")
    version_name = _string_assignment(default, "versionName", "android defaultConfig")
    phone_code = _integer_assignment(default, "versionCode", "android defaultConfig")
    tv_code = _integer_assignment(television, "versionCode", "android tv flavor")

    wear_source = _strip_kotlin_comments(wear_gradle)
    wear_android = _named_block(wear_source, r"(?m)^\s*android\s*\{", "Wear android")
    wear_default = _named_block(
        wear_android, r"\bdefaultConfig\s*\{", "Wear defaultConfig"
    )
    return {
        "android_phone": {
            "package": package,
            "version_name": version_name,
            "version_code": phone_code,
        },
        "android_tv": {
            "package": package,
            "version_name": version_name,
            "version_code": tv_code,
        },
        "wear_os": {
            "package": _string_assignment(
                wear_default, "applicationId", "Wear defaultConfig"
            ),
            "version_name": _string_assignment(
                wear_default, "versionName", "Wear defaultConfig"
            ),
            "version_code": _integer_assignment(
                wear_default, "versionCode", "Wear defaultConfig"
            ),
        },
    }


def validate_android_release_identities(
    android_gradle: str,
    wear_gradle: str,
    ruling: dict[str, object],
) -> dict[str, dict[str, str | int]]:
    identities = parse_android_release_identities(android_gradle, wear_gradle)
    mappings = ruling["platform_mappings"]
    for platform, identity in identities.items():
        if mappings[platform] != identity:
            raise ReleaseIdentityError(
                f"{platform} executable Gradle identity does not match the ruling"
            )
    return identities


class ReleaseIdentityConsistencyTest(unittest.TestCase):
    def test_every_release_identity_surface_is_exact_and_mapped(self) -> None:
        pubspec = (ROOT / "pubspec.yaml").read_text(encoding="utf-8")
        match = re.search(
            r"(?m)^version:\s*([0-9]+\.[0-9]+\.[0-9]+)\+([0-9]+)\s*$",
            pubspec,
        )
        self.assertIsNotNone(match)
        marketing, build_text = match.groups()
        build = int(build_text)
        release = f"{marketing}+{build}"
        self.assertEqual(release, "1.0.17+34")

        ruling = load_release_identity_map()
        self.assertEqual(ruling["canonical_release"], release)
        self.assertEqual(ruling["marketing_version"], marketing)
        self.assertEqual(ruling["build_number"], build)
        mappings = ruling["platform_mappings"]

        android_identities = validate_android_release_identities(
            (ROOT / "android/app/build.gradle.kts").read_text(encoding="utf-8"),
            (ROOT / "wear_os/app/build.gradle.kts").read_text(encoding="utf-8"),
            ruling,
        )
        self.assertEqual(
            android_identities,
            {
                "android_phone": {
                    "package": "org.winsvpn.app",
                    "version_name": marketing,
                    "version_code": build,
                },
                "android_tv": {
                    "package": "org.winsvpn.app",
                    "version_name": marketing,
                    "version_code": build * 100 + 2,
                },
                "wear_os": {
                    "package": "org.winsvpn.app",
                    "version_name": marketing,
                    "version_code": build * 100 + 1,
                },
            },
        )
        for plist in (
            "ios/Runner/Info.plist",
            "ios/PacketTunnel/Info.plist",
            "ios/WinsWatch Watch App/Info.plist",
            "macos/Runner/Info.plist",
            "macos/PacketTunnel/Info.plist",
        ):
            text = (ROOT / plist).read_text(encoding="utf-8")
            self.assertIn("$(FLUTTER_BUILD_NAME)", text, plist)
            self.assertIn("$(FLUTTER_BUILD_NUMBER)", text, plist)
        apple_metadata = json.loads(
            (ROOT / "app_store/apple/review/privacy_label_manifest.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(apple_metadata["app_version"], marketing)
        self.assertEqual(apple_metadata["build_number"], build_text)
        apple_information = (
            ROOT / "app_store/apple/metadata/app_information.md"
        ).read_text(encoding="utf-8")
        self.assertIn(f"Intended release: {release}.", apple_information)
        self.assertIn(f"Version: {marketing}", apple_information)
        self.assertIn(f"Build: {build}", apple_information)
        privacy_summary = apple_metadata["app_store_connect_summary"]
        self.assertEqual(
            privacy_summary["purchase_history_status"],
            "source_truth_not_collected_live_portal_over_declared",
        )
        self.assertNotIn(
            "Purchase History",
            {
                item["label"]
                for item in privacy_summary["data_linked_to_user"]
            },
        )
        live_privacy = apple_metadata["live_app_store_connect_sync"]
        self.assertIn("Purchase History", live_privacy["published_data_types"])
        self.assertIn("NOT re-synchronized", live_privacy["reconcile_note"])
        expected_apple_source_types = {
            "NSPrivacyCollectedDataTypeCoarseLocation",
            "NSPrivacyCollectedDataTypeDeviceID",
            "NSPrivacyCollectedDataTypeUserID",
            "NSPrivacyCollectedDataTypeProductInteraction",
        }
        for source_manifest in (
            "ios/Runner/PrivacyInfo.xcprivacy",
            "macos/Runner/PrivacyInfo.xcprivacy",
        ):
            with (ROOT / source_manifest).open("rb") as handle:
                source_privacy = plistlib.load(handle)
            self.assertEqual(
                {
                    entry["NSPrivacyCollectedDataType"]
                    for entry in source_privacy["NSPrivacyCollectedDataTypes"]
                },
                expected_apple_source_types,
                source_manifest,
            )
        downloads = json.loads(
            (ROOT / "web/releases/downloads.json").read_text(encoding="utf-8")
        )
        # The website download template names the release the website publishes,
        # which is shipped separately (its own custody, audit and deploy notices)
        # and can trail the app release. It must equal the website audit's
        # canonical release, never a value of its own.
        import website_security_audit as website_audit
        self.assertEqual(downloads["release_id"], website_audit.CANONICAL_WEBSITE_RELEASE_ID)
        for artifact in downloads["artifacts"]:
            self.assertIn(artifact["status"], {"verification_pending", "store_pending"})
            self.assertIsNone(artifact["delivery"]["url"])
            self.assertEqual(
                artifact["artifact"],
                {"filename": None, "sha256": None, "bytes": None},
            )
        self.assertEqual(
            mappings["apple"],
            {
                "short_version": marketing,
                "bundle_version": build_text,
                "required_artifacts": [
                    "ios_app_store_ipa_with_embedded_watchos",
                    "macos_app_store_pkg",
                ],
                "optional_distribution": ["macos_developer_id"],
                "required_upload_targets": [
                    "ios-app-store-ipa",
                    "macos-app-store-pkg",
                ],
                "optional_evidence_targets": ["macos-developer-id-app"],
                "shipping_surfaces": ["ios", "watchos", "macos"],
            },
        )

        windows_builder = (ROOT / "installer/windows/build_installer.ps1").read_text(
            encoding="utf-8"
        )
        windows_zip = (ROOT / "installer/windows/build_zip_installer.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "$AppVersion = $VersionLine.Matches[0].Groups[1].Value", windows_builder
        )
        self.assertIn('release = "$AppVersion+$BuildNumber"', windows_builder)
        self.assertIn(f"-AppVersion {marketing}.{build}", windows_zip)
        self.assertEqual(
            mappings["windows"],
            {
                "product_version": marketing,
                "four_part_version": f"{marketing}.{build}",
            },
        )

        linux_release = (ROOT / "tools/build_linux_release.sh").read_text(
            encoding="utf-8"
        )
        linux_deb = (ROOT / "tools/build_linux_deb.sh").read_text(encoding="utf-8")
        appstream = (
            ROOT / "linux/packaging/org.winsvpn.app.metainfo.xml"
        ).read_text(encoding="utf-8")
        provenance = (ROOT / "tools/package_release_artifacts.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('APP_VERSION="$(awk', linux_release)
        self.assertIn('DEB_VERSION="${APP_VERSION}-${BUILD_NUMBER}"', linux_deb)
        self.assertIn(f'<release version="{marketing}"', appstream)
        self.assertIn('printf "Win\'s VPN %s - Linux desktop bundle', provenance)
        self.assertNotIn("Win's VPN 1.0.14+29 - Linux desktop bundle", provenance)
        self.assertEqual(
            mappings["linux"],
            {
                "appstream_version": marketing,
                "debian_version": f"{marketing}-{build}",
            },
        )

        browser_mapping = mappings["browser_extensions"]
        extension_version = browser_mapping["version"]
        self.assertEqual(browser_mapping["policy"], "pubspec")
        self.assertEqual(extension_version, marketing)
        self.assertEqual(
            browser_mapping["target_versions"],
            {
                "chrome-extension-package": assert_chrome_zip.REVIEWED_EXTENSION_VERSION,
                "edge-extension-package": assert_chrome_zip.REVIEWED_EXTENSION_VERSION,
                "firefox-extension-package": assert_firefox_zip.REVIEWED_EXTENSION_VERSION,
            },
        )
        self.assertEqual(assert_chrome_zip.REVIEWED_EXTENSION_VERSION, extension_version)
        self.assertEqual(assert_firefox_zip.REVIEWED_EXTENSION_VERSION, extension_version)
        extension_gate_bindings = {
            "chrome-extension-package": (
                "chrome-package-verification",
                "extension/tools/assert_chrome_zip.py",
            ),
            "edge-extension-package": (
                "edge-package-verification",
                "extension/tools/assert_chrome_zip.py",
            ),
            "firefox-extension-package": (
                "firefox-package-verification",
                "extension/tools/assert_firefox_zip.py",
            ),
        }
        for target_id, (gate_id, verifier_path) in extension_gate_bindings.items():
            target = cross_store.TARGET_BY_ID[target_id]
            self.assertEqual(target.signing_gate_id, gate_id)
            self.assertEqual(cross_store.GATE_PRODUCER_IDS[gate_id], (verifier_path,))
        self.assertTrue(
            {"stdout", "stdout_sha256"}.issubset(cross_store.LOCAL_GATE_EVIDENCE_KEYS)
        )
        base_manifest = jsonc.load_file(ROOT / "extension/manifest/base.jsonc")
        self.assertEqual(base_manifest["version"], extension_version)

        receipt_source = (ROOT / "tools/cross_store_target_receipt.py").read_text(
            encoding="utf-8"
        )
        verifier_source = (ROOT / "tools/cross_store_upload_readiness.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('"release": freeze._release_identity(repo)', receipt_source)
        self.assertIn(
            'record.get("release") != freeze._release_identity(repo)', verifier_source
        )

        config = dashboard.load_config(ROOT / "dashboard/state.json")
        self.assertEqual(config["release"], release)
        configured_map = {
            target["id"]: tuple(target["upload_targets"])
            for target in config["targets"]
        }
        configured_optional_map = {
            target["id"]: tuple(target["optional_upload_targets"])
            for target in config["targets"]
        }
        self.assertEqual(configured_map, dashboard.DASHBOARD_UPLOAD_TARGET_MAP)
        self.assertEqual(
            configured_optional_map,
            dashboard.DASHBOARD_OPTIONAL_UPLOAD_TARGET_MAP,
        )
        represented = {item for values in configured_map.values() for item in values}
        self.assertEqual(represented, cross_store.REQUIRED_TARGET_IDS)
        represented_optional = {
            item for values in configured_optional_map.values() for item in values
        }
        self.assertEqual(represented_optional, cross_store.OPTIONAL_TARGET_IDS)
        self.assertFalse(represented & represented_optional)
        self.assertEqual(
            set(browser_mapping["target_versions"]),
            EXTENSION_TARGET_IDS & cross_store.REQUIRED_TARGET_IDS,
        )

        tv_evidence = (
            ROOT / "android/app/src/tv/tv_manifest_landscape_verify.txt"
        ).read_text(encoding="utf-8")
        self.assertIn("HISTORICAL", tv_evidence)
        self.assertIn("MUST NOT be used", tv_evidence)
        self.assertIn("Current release verdict: UNVERIFIED", tv_evidence)

    def test_built_extension_manifests_carry_the_release_version(self) -> None:
        # The built manifests exist only after `python3 extension/build.py`.
        # A clean checkout reports this test as skipped, never as passed, and a
        # partial build fails.
        manifests = [
            ROOT / "extension/dist/chrome/manifest.json",
            ROOT / "extension/dist/edge/manifest.json",
            ROOT / "extension/dist/firefox/manifest.json",
        ]
        present = [path for path in manifests if path.is_file()]
        if not present:
            self.skipTest(
                "extension/dist is not built; run python3 extension/build.py "
                "chrome edge firefox before relying on this check"
            )
        self.assertEqual(present, manifests, "extension/dist is a partial build")
        mappings = load_release_identity_map()["platform_mappings"]
        extension_version = mappings["browser_extensions"]["version"]
        for path in manifests:
            parsed = json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
            )
            self.assertEqual(parsed["version"], extension_version, str(path))

    def test_android_parser_ignores_comment_decoys(self) -> None:
        android = (ROOT / "android/app/build.gradle.kts").read_text(encoding="utf-8")
        wear = (ROOT / "wear_os/app/build.gradle.kts").read_text(encoding="utf-8")
        changed = android.replace(
            "        versionCode = 34\n",
            "        versionCode = 9999\n        // versionCode = 34\n",
            1,
        ).replace(
            "            versionCode = 3402\n",
            "            versionCode = 9998\n            // versionCode = 3402\n",
            1,
        ).replace(
            '        versionName = "1.0.17"\n',
            '        versionName = "9.9.9"\n        // versionName = "1.0.17"\n',
            1,
        )
        changed_wear = wear.replace(
            "        versionCode = 3401\n",
            "        versionCode = 9997\n        // versionCode = 3401\n",
            1,
        ).replace(
            '        versionName = "1.0.17"\n',
            '        versionName = "9.9.8"\n        /* versionName = "1.0.17" */\n',
            1,
        )
        parsed = parse_android_release_identities(changed, changed_wear)
        self.assertEqual(parsed["android_phone"]["version_code"], 9999)
        self.assertEqual(parsed["android_tv"]["version_code"], 9998)
        self.assertEqual(parsed["wear_os"]["version_code"], 9997)
        self.assertEqual(parsed["android_phone"]["version_name"], "9.9.9")
        self.assertEqual(parsed["wear_os"]["version_name"], "9.9.8")
        ruling = load_release_identity_map()
        with self.assertRaisesRegex(ReleaseIdentityError, "android_phone"):
            validate_android_release_identities(changed, wear, ruling)
        with self.assertRaisesRegex(ReleaseIdentityError, "wear_os"):
            validate_android_release_identities(android, changed_wear, ruling)

    def test_android_parser_ignores_raw_string_and_nested_comment_decoys(self) -> None:
        android = (ROOT / "android/app/build.gradle.kts").read_text(encoding="utf-8")
        wear = (ROOT / "wear_os/app/build.gradle.kts").read_text(encoding="utf-8")
        fake_block = '''
extensions.configure<ApplicationExtension> {
    defaultConfig {
        applicationId = "attacker.example"
        versionName = "9.9.9"
        versionCode = 9999
    }
}
'''
        raw_decoy = f'val releaseIdentityDecoy = """{fake_block}"""\n{android}'
        nested_comment_decoy = f'/* outer /* nested */ {fake_block} */\n{android}'
        expected = parse_android_release_identities(android, wear)
        self.assertEqual(parse_android_release_identities(raw_decoy, wear), expected)
        self.assertEqual(
            parse_android_release_identities(nested_comment_decoy, wear), expected
        )

    def test_android_parser_ignores_braces_inside_raw_strings(self) -> None:
        android = (ROOT / "android/app/build.gradle.kts").read_text(encoding="utf-8")
        wear = (ROOT / "wear_os/app/build.gradle.kts").read_text(encoding="utf-8")
        changed = android.replace(
            "extensions.configure<ApplicationExtension> {",
            'extensions.configure<ApplicationExtension> {\n    val braces = """} } }"""',
            1,
        )
        self.assertEqual(
            parse_android_release_identities(changed, wear),
            parse_android_release_identities(android, wear),
        )


class ReleaseIdentitySchemaAdversarialTest(unittest.TestCase):
    def setUp(self) -> None:
        self.valid = json.loads(IDENTITY_MAP_PATH.read_text(encoding="utf-8"))
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "identity.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _assert_rejected(self, value: object) -> None:
        self.path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(ReleaseIdentityError):
            load_release_identity_map(self.path)

    def test_duplicate_keys_are_rejected_at_every_depth(self) -> None:
        raw = IDENTITY_MAP_PATH.read_text(encoding="utf-8")
        top_duplicate = raw.replace(
            '  "schema_version": 2,',
            '  "schema_version": 2,\n  "schema_version": 2,',
            1,
        )
        nested_duplicate = raw.replace(
            '"version_code": 34}',
            '"version_code": 34, "version_code": 34}',
            1,
        )
        for candidate in (top_duplicate, nested_duplicate):
            with self.subTest(candidate=candidate[:80]):
                self.path.write_text(candidate, encoding="utf-8")
                with self.assertRaisesRegex(ReleaseIdentityError, "duplicate JSON key"):
                    load_release_identity_map(self.path)

    def test_wrong_schema_and_scalar_types_are_rejected(self) -> None:
        mutations = []
        for schema in (1, True, "2", 2.0):
            value = json.loads(json.dumps(self.valid))
            value["schema_version"] = schema
            mutations.append(value)
        value = json.loads(json.dumps(self.valid))
        value["build_number"] = True
        mutations.append(value)
        value = json.loads(json.dumps(self.valid))
        value["platform_mappings"]["android_phone"]["version_code"] = "34"
        mutations.append(value)
        value = json.loads(json.dumps(self.valid))
        value["platform_mappings"]["android_tv"]["version_code"] = 3402.0
        mutations.append(value)
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self._assert_rejected(mutation)

    def test_semantic_identity_substitutions_are_rejected(self) -> None:
        mutations = []
        for platform, field, replacement in (
            ("android_phone", "version_code", 35),
            ("android_tv", "version_code", 3401),
            ("wear_os", "package", "org.winsvpn.app.wear"),
            ("windows", "four_part_version", "1.0.17.35"),
            ("linux", "debian_version", "1.0.17+34"),
            ("browser_extensions", "version", "9.9.9"),
            ("browser_extensions", "policy", "aligned_with_app"),
        ):
            value = json.loads(json.dumps(self.valid))
            value["platform_mappings"][platform][field] = replacement
            mutations.append(value)
        value = json.loads(json.dumps(self.valid))
        value["platform_mappings"]["browser_extensions"]["target_versions"][
            "edge-extension-package"
        ] = "9.9.9"
        mutations.append(value)
        value = json.loads(json.dumps(self.valid))
        value["platform_mappings"]["apple"]["shipping_surfaces"] = [
            "ios",
            "watchos",
            "macos",
            "tvos",
        ]
        mutations.append(value)
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self._assert_rejected(mutation)

    def test_unknown_missing_and_incomplete_maps_are_rejected(self) -> None:
        mutations = []
        value = json.loads(json.dumps(self.valid))
        value["unknown"] = "not reviewed"
        mutations.append(value)
        value = json.loads(json.dumps(self.valid))
        del value["platform_mappings"]["linux"]
        mutations.append(value)
        value = json.loads(json.dumps(self.valid))
        value["platform_mappings"]["unexpected"] = {}
        mutations.append(value)
        value = json.loads(json.dumps(self.valid))
        del value["platform_mappings"]["android_tv"]["version_code"]
        mutations.append(value)
        value = json.loads(json.dumps(self.valid))
        del value["platform_mappings"]["browser_extensions"]["target_versions"][
            "edge-extension-package"
        ]
        mutations.append(value)
        value = json.loads(json.dumps(self.valid))
        value["platform_mappings"]["browser_extensions"]["target_versions"][
            "unexpected-extension-package"
        ] = "1.0.0"
        mutations.append(value)
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self._assert_rejected(mutation)


if __name__ == "__main__":
    unittest.main()
