#!/usr/bin/env python3
"""The Wear Gradle verification metadata covers the AGP lint-tool closure.

The phone project needed groovy-bom-4.0.29.pom and error_prone_annotations
2.27.0 in its metadata once strict verification resolved `androidLintTool`.
Wear uses the same Android Gradle plugin, so its metadata must carry the same
entries with the same digests. This test reads both files and fails if Wear
drops them or disagrees with the phone on a digest it shares.
"""

from __future__ import annotations

import pathlib
import unittest
import xml.etree.ElementTree as ET

WEAR_ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO = WEAR_ROOT.parent
NS = "{https://schema.gradle.org/dependency-verification}"
REQUIRED = (
    ("org.apache.groovy", "groovy-bom", "4.0.29", "groovy-bom-4.0.29.pom"),
    ("com.google.errorprone", "error_prone_annotations", "2.27.0", "error_prone_annotations-2.27.0.jar"),
    ("com.google.errorprone", "error_prone_annotations", "2.27.0", "error_prone_annotations-2.27.0.pom"),
)


def digests(path: pathlib.Path) -> dict[tuple[str, str, str, str], set[str]]:
    root = ET.parse(path).getroot()
    result: dict[tuple[str, str, str, str], set[str]] = {}
    for component in root.iter(NS + "component"):
        for artifact in component.findall(NS + "artifact"):
            key = (component.get("group"), component.get("name"), component.get("version"), artifact.get("name"))
            result[key] = {item.get("value") for item in artifact.findall(NS + "sha256")}
    return result


class WearVerificationMetadataTests(unittest.TestCase):
    def test_lint_tool_closure_entries_are_present_and_match_the_phone(self) -> None:
        wear = digests(WEAR_ROOT / "gradle/verification-metadata.xml")
        phone = digests(REPO / "android/gradle/verification-metadata.xml")
        for key in REQUIRED:
            with self.subTest(artifact=key[3]):
                self.assertTrue(key in wear, f"Wear metadata lacks {key[3]}")
                self.assertTrue(wear[key])
                self.assertEqual(wear[key], phone[key])

    def test_shared_artifacts_never_disagree_between_phone_and_wear(self) -> None:
        wear = digests(WEAR_ROOT / "gradle/verification-metadata.xml")
        phone = digests(REPO / "android/gradle/verification-metadata.xml")
        shared = set(wear) & set(phone)
        self.assertGreater(len(shared), 100)
        self.assertEqual([key for key in sorted(shared) if wear[key] != phone[key]], [])


if __name__ == "__main__":
    unittest.main()
