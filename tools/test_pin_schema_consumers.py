#!/usr/bin/env python3
"""Every strict consumer of tools/toolchain-pins.json accepts the live schema.

Two gates compare the `tools` object against an exact key set. When the pins
gained `xcode`, `android_ndk` and the Flutter `installed_tree_*` fields those
gates started refusing the live file on every call, which no pin-content test
noticed. This test loads the live file through each strict consumer and also
keeps both consumers fail-closed for an unknown field. The Go archive
custody controller compares tools.go against an exact key set with one
optional field (executable_sha256_by_platform), checked here as well.
"""

from __future__ import annotations

import json
import pathlib
import sys
import unittest

TOOLS = pathlib.Path(__file__).resolve().parent
ROOT = TOOLS.parent
for entry in (str(ROOT), str(TOOLS)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import release_browser_archive_custody as browser  # noqa: E402
import release_go_archive_custody as go_custody  # noqa: E402
import tools.linux_cross_store_artifact_gate as linux_gate  # noqa: E402

PINS = TOOLS / "toolchain-pins.json"


class PinSchemaConsumerTests(unittest.TestCase):
    def test_linux_gate_loads_the_live_pin_file(self) -> None:
        flutter = linux_gate._load_toolchain_pins()
        document = json.loads(PINS.read_text(encoding="utf-8"))
        self.assertEqual(flutter["version"], document["tools"]["flutter"]["version"])
        self.assertEqual(flutter["revision"], document["tools"]["flutter"]["revision"])

    def test_browser_custody_parses_the_live_pin_file(self) -> None:
        pin = browser.parse_production_manifest(PINS.read_bytes())
        document = json.loads(PINS.read_text(encoding="utf-8"))
        self.assertEqual(pin["version"], document["tools"]["browser"]["version"])

    def test_browser_custody_still_rejects_an_unknown_tool_field(self) -> None:
        document = json.loads(PINS.read_text(encoding="utf-8"))
        document["tools"]["unreviewed_tool"] = {"version": "1"}
        with self.assertRaises(browser.Refused) as caught:
            browser.parse_production_manifest(json.dumps(document).encode("utf-8"))
        self.assertIn("unexpected Chrome pin field rejected", str(caught.exception))

    def test_every_live_tools_key_is_named_by_the_browser_consumer(self) -> None:
        # The Linux gate's two key sets are literals inside
        # _load_toolchain_pins, so they are bound to the live file by
        # test_linux_gate_loads_the_live_pin_file above: importing that module
        # runs _FLUTTER_TOOLCHAIN = _load_toolchain_pins() at line 1932.
        live = set(json.loads(PINS.read_text(encoding="utf-8"))["tools"])
        self.assertEqual(set(browser.TOOLS_KEYS), live)

    def test_go_custody_parses_the_live_pin_file_and_stays_exact(self) -> None:
        pin = go_custody.parse_pin_bytes(PINS.read_bytes())
        document = json.loads(PINS.read_text(encoding="utf-8"))
        self.assertEqual(pin["version"], document["tools"]["go"]["version"])
        document["tools"]["go"]["unreviewed_field"] = "1"
        with self.assertRaises(go_custody.Refused) as caught:
            go_custody.parse_pin_bytes(json.dumps(document).encode("utf-8"))
        self.assertIn("unexpected Go pin field rejected", str(caught.exception))

    def test_linux_producer_pins_stay_out_of_the_darwin_custody_objects(self) -> None:
        # tools/release_android_toolchain_archive_custody.sh accepts exactly
        # darwin_arm64 in these objects, and tools.go.install_tree_sha256 uses
        # the release_go_archive_custody.tree_hash encoding; the Linux
        # producer's own pins live under tools.linux.
        tools = json.loads(PINS.read_text(encoding="utf-8"))["tools"]
        for owner in ("flutter", "flutter_pub_cache"):
            for field in ("archive_path", "archive_sha256", "install_tree_sha256"):
                with self.subTest(pin=f"tools.{owner}.{field}"):
                    self.assertEqual(set(tools[owner][field]), {"darwin_arm64"})
        self.assertEqual(set(tools["go"]["install_tree_sha256"]), {"darwin_arm64"})

    def test_linux_producer_pins_are_exact_digests(self) -> None:
        tools = json.loads(PINS.read_text(encoding="utf-8"))["tools"]
        linux = tools["linux"]
        hex64 = r"^[0-9a-f]{64}$"
        expected = {
            "tools.linux.flutter.archive_sha256.linux_amd64": linux["flutter"]["archive_sha256"]["linux_amd64"],
            "tools.linux.flutter.install_tree_sha256.linux_amd64": linux["flutter"]["install_tree_sha256"]["linux_amd64"],
            "tools.linux.arm64.clang_executable_sha256": linux["arm64"]["clang_executable_sha256"],
        }
        for platform in ("linux_amd64", "linux_arm64"):
            expected[f"tools.linux.flutter_pub_cache.archive_sha256.{platform}"] = (
                linux["flutter_pub_cache"]["archive_sha256"][platform]
            )
            expected[f"tools.linux.flutter_pub_cache.install_tree_sha256.{platform}"] = (
                linux["flutter_pub_cache"]["install_tree_sha256"][platform]
            )
            expected[f"tools.linux.go.install_tree_sha256.{platform}"] = (
                linux["go"]["install_tree_sha256"][platform]
            )
            expected[f"tools.go.executable_sha256_by_platform.{platform}"] = (
                tools["go"]["executable_sha256_by_platform"][platform]
            )
        for key, value in expected.items():
            with self.subTest(pin=key):
                self.assertRegex(value, hex64)
        for platform in ("linux_amd64", "linux_arm64"):
            for field in ("archive_sha256", "install_tree_sha256"):
                with self.subTest(pin=f"tools.linux.flutter.{field}.{platform}"):
                    self.assertRegex(linux["flutter"][field][platform], hex64)
        # The arm64 SDK is built from the official git tag; every file its
        # first run fetched is pinned by URL, size and sha256.
        source = linux["flutter"]["arm64_from_tag"]
        self.assertEqual(source["git_commit"], tools["flutter"]["revision"])
        self.assertEqual(source["git_tag"], tools["flutter"]["version"])
        self.assertTrue(source["fetched"])
        for record in source["fetched"]:
            with self.subTest(url=record["url"]):
                self.assertEqual(set(record), {"url", "size", "sha256"})
                self.assertTrue(
                    record["url"].startswith("https://storage.googleapis.com/flutter_infra_release/")
                )
                self.assertRegex(record["sha256"], hex64)
                self.assertIs(type(record["size"]), int)
                self.assertGreater(record["size"], 0)
        self.assertNotEqual(
            linux["flutter_pub_cache"]["archive_sha256"]["linux_amd64"],
            linux["flutter_pub_cache"]["install_tree_sha256"]["linux_amd64"],
        )


if __name__ == "__main__":
    unittest.main()
