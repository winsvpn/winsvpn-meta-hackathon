#!/usr/bin/env python3
"""Gradle plugin-repository policy guard.

WHY THIS EXISTS.

Finding S2 of `.spark_lanes/scratch/spk_supply/SUPPLY_CHAIN_AUDIT_20260810.md`
(HIGH): `source/wins_vpn/android/settings.gradle.kts` resolved build-time
plugins from `gradlePluginPortal()` with no byte-level verification, and a
plugin runs arbitrary code at build time before any artifact check applies.
A state adversary who can mirror the plugin portal to a build host replaces
the Android Gradle Plugin itself -- higher leverage than a single library.

The mitigation landed 2026-08-10 (lane `ds_pluginportal`): the plugin portal
is no longer listed in the pluginManagement of the shipping and validation
Gradle builds. Plugin byte-level hashing (Gradle `verification-metadata.xml`)
remains unpinnable piecemeal and is parked with finding S1 behind a
real-build-host hashing pass -- this guard exists so that removing the
portal itself cannot be regressed.

WHAT THIS GUARD ASSERTS.

  1. `android/settings.gradle.kts`, `android/devicecheck/settings.gradle.kts`
     and `wear_os/settings.gradle.kts` must NOT declare
     `gradlePluginPortal()` anywhere -- every plugin this tree resolves comes
     from `google()`, `mavenCentral()`, or the included Flutter composite
     build (`includeBuild(...)` in the android settings).
  2. Those three files must still declare `google()` and `mavenCentral()` in
     pluginManagement, and the shipping android settings must carry the
     Flutter `includeBuild`, so the assertion is not weakened to "no plugins
     at all".
  3. The shipping android settings must pin every declared plugin to an
     EXACT version (no version ranges / dynamic versions).
  4. If an optional historical sibling checkout still contains the old
     `Wifi & Cellular combo/settings.gradle.kts`, its retained portal must be
     content-filtered down to `org.gradle.toolchains`.

THE "TWO RULES" FROM THIS REPO'S OTHER GUARDS, BORROWED VERBATIM:

  * Accumulate. Every mismatch is collected and reported via subTest. A guard
    that dies on the first failure hides every check after it.
  * Assert the property, not a byte sequence. We search for the repository
    call sites, not for an exact indented source line, so reformatting a
    settings file does not produce a phantom failure while a genuine
    re-introduction of the portal still does.
"""

from __future__ import annotations

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Files that must not use the plugin portal at all.
# These canonical paths must exist in every fresh clone. They are never
# skipped: this is the shipping and validation surface the policy protects.
PORTAL_FREE_SETTINGS = (
    "android/settings.gradle.kts",
    "android/devicecheck/settings.gradle.kts",
    "wear_os/settings.gradle.kts",
)

# Files that must still carry the non-portal repo call sites even when the
# portal is (correctly, for the shipping build) absent.
REQUIRED_PLUGIN_REPOS = ("google()", "mavenCentral()")

# Projects that keep the portal, because foojay is portal-only; each must also
# content-filter it to the org.gradle.toolchains groups.
OPTIONAL_HISTORICAL_PORTAL_RESTRICTED_SETTINGS = (
    ROOT.parent / "wins_vpn" / "Wifi & Cellular combo" / "settings.gradle.kts",
    ROOT.parent / "wins_vpn_developer" / "Wifi & Cellular combo" / "settings.gradle.kts",
)

# Anchored to a line start so a *comment* that merely names the portal (like
# the citation in the android settings) is not mistaken for a declaration.
PLUGIN_PORTAL_CALL = re.compile(r"^[ \t]*gradlePluginPortal\s*\(", re.MULTILINE)
PLUGIN_LINE = re.compile(r'id\("([^"]+)"\)\s+version\s+"([^"]+)"')
DYNAMIC_VERSION = re.compile(r"[+\]\[]")


def _text(path: pathlib.Path, rel: str) -> str | None:
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="replace")


class GradlePluginRepositoryPolicyTests(unittest.TestCase):
    def test_settings_files_exist(self) -> None:
        for rel in PORTAL_FREE_SETTINGS:
            with self.subTest(path=rel):
                self.assertTrue(
                    (ROOT / rel).is_file(),
                    f"{rel} is enumerated but does not exist -- the guard may "
                    f"have been orphaned by a rename. Update it deliberately.",
                )

    def test_plugin_portal_is_absent_from_shipping_and_validation_builds(self) -> None:
        for rel in PORTAL_FREE_SETTINGS:
            text = _text(ROOT / rel, rel)
            with self.subTest(path=rel):
                self.assertIsNotNone(text, f"{rel} missing")
                if text is None:
                    continue
                self.assertFalse(
                    PLUGIN_PORTAL_CALL.search(text),
                    f"{rel} re-introduces gradlePluginPortal() in pluginManagement. "
                    f"This regresses supply-chain finding S2: every plugin this "
                    f"build resolves now comes only from google(), mavenCentral() "
                    f"and (for the Flutter plugins) the included composite build. "
                    f"If a new plugin genuinely needs the portal, pin it there "
                    f"with a content filter limited to its group AND record the "
                    f"decision in docs/handoff -- do not open the portal up "
                    f"unfiltered.",
                )

    def test_non_portal_repositories_still_declared_in_plugin_management(self) -> None:
        """The absence of the portal must not mean the absence of repositories."""
        for rel in PORTAL_FREE_SETTINGS:
            text = _text(ROOT / rel, rel)
            with self.subTest(path=rel):
                self.assertIsNotNone(text, f"{rel} missing")
                if text is None:
                    continue
                for repo in REQUIRED_PLUGIN_REPOS:
                    self.assertIn(
                        repo,
                        text,
                        f"{rel} no longer declares {repo} in pluginManagement. "
                        f"Removing the portal and the hosts in the same edit "
                        f"would leave plugins unresolvable; keep google() and "
                        f"mavenCentral() even while the portal stays out.",
                    )

    def test_flutter_composite_include_build_is_present_in_shipping_settings(self) -> None:
        """The two `dev.flutter.flutter-*` plugins come from the composite build."""
        rel = "android/settings.gradle.kts"
        text = _text(ROOT / rel, rel)
        with self.subTest(path=rel):
            self.assertIsNotNone(text, f"{rel} missing")
            if text is None:
                return
            self.assertIn(
                "includeBuild(",
                text,
                f"{rel} lost the flutter_tools/gradle includeBuild. The "
                f"dev.flutter.* plugins would then try to resolve from the "
                f"public repositories (dev.flutter.flutter-plugin-loader is NOT "
                f"on google() or mavenCentral(), measured 2026-08-10) and the "
                f"Flutter plugin loader would require the plugin portal back.",
            )

    def test_all_declared_plugin_versions_are_exact(self) -> None:
        """Every versioned `id(...) version "..."` in the shipping settings is a
        literal exact version, not a range or a dynamic marker."""
        rel = "android/settings.gradle.kts"
        text = _text(ROOT / rel, rel)
        with self.subTest(path=rel):
            self.assertIsNotNone(text, f"{rel} missing")
            if text is None:
                return
            found = list(PLUGIN_LINE.finditer(text))
            self.assertTrue(found, f"{rel} declares no versioned plugins to check")
            for match in found:
                plugin_id, version = match.group(1), match.group(2)
                with self.subTest(plugin=plugin_id, version=version):
                    self.assertRegex(
                        version,
                        r"^\d+(\.\d+)+(-[0-9A-Za-z.-]+)?$",
                        f"{rel} pins {plugin_id} to {version!r}, which is not an "
                        f"exact version literal. Dynamic/regex versions are "
                        f"unpinnable: use the exact version.",
                    )

    def test_retained_portal_is_content_restricted_in_combo_project(self) -> None:
        existing = [
            path
            for path in OPTIONAL_HISTORICAL_PORTAL_RESTRICTED_SETTINGS
            if path.is_file()
        ]
        if not existing:
            self.skipTest("optional historical combo-project checkouts are absent")
        for path in existing:
            rel = str(path)
            text = path.read_text(encoding="utf-8", errors="replace")
            with self.subTest(path=rel):
                portal_present = PLUGIN_PORTAL_CALL.search(text) is not None
                self.assertTrue(
                    portal_present, f"{rel} needs the portal for foojay"
                )
                include_group_toolchains = re.search(
                    r'includeGroup\("org\.gradle\.toolchains"\)', text
                )
                self.assertIsNotNone(
                    include_group_toolchains,
                    f"{rel} keeps gradlePluginPortal() but does not content-filter "
                    f"it to org.gradle.toolchains. The foojay resolver is the only "
                    f"plugin that exists solely on the portal; leaving the portal "
                    f"unfiltered re-opens finding S2 for this project.",
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
