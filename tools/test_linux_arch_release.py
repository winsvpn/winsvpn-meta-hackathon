#!/usr/bin/env python3
"""x86_64/arm64 Linux release-readiness contracts."""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import unittest
import xml.etree.ElementTree as ET


ROOT = pathlib.Path(__file__).resolve().parents[1]
METAINFO_PATH = ROOT / "linux/packaging/org.winsvpn.app.metainfo.xml"
CANONICAL_PRIVACY_URL = "https://www.winsvpn.org/privacy/"
CANONICAL_SUPPORT_URL = "https://www.winsvpn.org/support/"
APPSTREAM_URL_TYPES = frozenset(
    {
        "homepage",
        "bugtracker",
        "faq",
        "help",
        "donation",
        "translate",
        "contact",
        "vcs-browser",
        "contribute",
    }
)
OARS_1_1_IDS = frozenset(
    {
        "violence-cartoon",
        "violence-fantasy",
        "violence-realistic",
        "violence-bloodshed",
        "violence-sexual",
        "drugs-alcohol",
        "drugs-narcotics",
        "drugs-tobacco",
        "sex-nudity",
        "sex-themes",
        "language-profanity",
        "language-humor",
        "language-discrimination",
        "money-advertising",
        "money-gambling",
        "money-purchasing",
        "social-chat",
        "social-audio",
        "social-contacts",
        "social-info",
        "social-location",
        "sex-homosexuality",
        "sex-prostitution",
        "sex-adultery",
        "sex-appearance",
        "violence-worship",
        "violence-desecration",
        "violence-slavery",
    }
)
OARS_VALUES = frozenset({"none", "mild", "moderate", "intense"})
PRODUCER = (ROOT / "tools/build_linux_release.sh").read_text(encoding="utf-8")
INSTALLER = (ROOT / "linux/packaging/install.sh").read_text(encoding="utf-8")
BOOTSTRAP = (ROOT / "linux/packaging/install-winsvpn-linux.sh").read_text(
    encoding="utf-8"
)
BACKEND = (ROOT / "linux/runner/linux_tunnel_backend.cc").read_text(encoding="utf-8")
METAINFO = METAINFO_PATH.read_text(encoding="utf-8")
CMAKE = (ROOT / "linux/runner/CMakeLists.txt").read_text(encoding="utf-8")
MANIFEST = (ROOT / "tools/linux_installed_artifact_manifest.py").read_text(
    encoding="utf-8"
)
PUBSPEC = (ROOT / "pubspec.yaml").read_text(encoding="utf-8")
X64_XRAY = "09e63d5420f26db2bc6144f6d047601909541acf21792878d3859e4fc4980a12"
ARM64_XRAY = "868fcabbf9a08d1e453bc6dc82dd8ca27cfcf8cdb2b3a8ff31b824361966964b"
ARM64_AWG = "bbf94b3753fb7660897d102918de797a55d675bd66c12bda63a9887400e1876d"
ARM64_AWG_GO = "9083c92dbd16422cd590df8fcf2ebae2c604b43539bdd58dddaede74efd0642a"


def pubspec_version() -> str:
    match = re.search(r"^version:\s*([^+\s]+)\+", PUBSPEC, re.MULTILINE)
    assert match, "pubspec.yaml version is missing"
    return match.group(1)


class LinuxArchReleaseTests(unittest.TestCase):
    def test_producer_detects_x64_and_arm64(self) -> None:
        self.assertIn("LINUX_RELEASE_ARCH_LABEL=x64", PRODUCER)
        self.assertIn("LINUX_RELEASE_ARCH_LABEL=arm64", PRODUCER)
        self.assertIn("LINUX_RELEASE_GOARCH=amd64", PRODUCER)
        self.assertIn("LINUX_RELEASE_GOARCH=arm64", PRODUCER)

    def test_arm64_release_requires_winn_v3_and_awg_xray_fallback(self) -> None:
        self.assertNotIn("release builds are not possible from this", PRODUCER)
        self.assertNotIn("Omitting Xray from the linux-", PRODUCER)
        self.assertNotIn("Omitting AmneziaWG triple from the linux-", PRODUCER)
        self.assertIn("Winn Protocol v3 datapath is required for a Linux release", PRODUCER)
        self.assertIn("Building mandatory Winn Protocol v3 engine", PRODUCER)
        self.assertIn("tools/build_linux_arm64_awg.sh", PRODUCER)
        self.assertIn(ARM64_XRAY, PRODUCER)
        self.assertIn(ARM64_AWG, PRODUCER)
        self.assertIn(ARM64_AWG_GO, PRODUCER)
        self.assertIn(
            'if [[ "${LINUX_RELEASE_GOARCH}" != "amd64" ]]; then', PRODUCER
        )

    def test_required_binaries_are_chmodded_and_must_exist(self) -> None:
        self.assertIn(
            "for required_bin in xray awg awg-quick amneziawg-go winn-datapath; do",
            PRODUCER,
        )
        self.assertIn('"winn-datapath",', PRODUCER)
        self.assertIn("required_fallback_missing", PRODUCER)
        self.assertIn(
            '"$PACKAGE_ROOT/tools/native_messaging/host/wins_bridge_host"',
            PRODUCER,
        )
        self.assertIn(
            '--target-arch="${LINUX_RELEASE_ARCH_LABEL}"',
            PRODUCER,
        )
        native_function = PRODUCER.split("build_and_stage_linux_native_host()", 1)[1]
        self.assertIn("assert_release_elf_machine", native_function)
        self.assertIn('"${native_host_output}"', native_function)
        self.assertIn('"${LINUX_RELEASE_ELF_MACHINE}"', native_function)
        self.assertIn("assert_packaged_linux_elf_architecture", PRODUCER)
        self.assertIn("refusing mixed-architecture bundle", PRODUCER)
        self.assertIn("--self-test-bundle-architecture", PRODUCER)
        self.assertIn("lib/libapp.so", PRODUCER)
        self.assertIn("lib/libflutter_linux_gtk.so", PRODUCER)

    def test_bootstrap_and_installer_accept_both_arches(self) -> None:
        self.assertIn("x86_64|amd64|aarch64|arm64", BOOTSTRAP)
        self.assertIn("x86_64|amd64", INSTALLER)
        self.assertIn("aarch64|arm64", INSTALLER)
        self.assertIn("EXPECTED_ELF_MACHINE=62", INSTALLER)
        self.assertIn("EXPECTED_ELF_MACHINE=183", INSTALLER)
        self.assertNotIn('[[ "$(uname -m)" == x86_64 ]]', BOOTSTRAP)

    def test_xray_and_awg_pins_are_architecture_specific(self) -> None:
        self.assertIn(f"XRAY_SHA256={X64_XRAY}", INSTALLER)
        self.assertIn(f"XRAY_SHA256={X64_XRAY}", BACKEND)
        self.assertIn("verify_bundle_hash xray \"$XRAY_SHA256\"", BACKEND)
        self.assertNotIn(f"verify_bundle_hash xray {X64_XRAY}", BACKEND)
        installer_arm = INSTALLER[INSTALLER.index("aarch64|arm64") :]
        self.assertIn(f"XRAY_SHA256={ARM64_XRAY}", installer_arm.split(";;", 1)[0])
        self.assertNotIn(X64_XRAY, installer_arm.split(";;", 1)[0])
        self.assertIn(ARM64_AWG, installer_arm.split(";;", 1)[0])

    def test_metainfo_describes_current_app_version(self) -> None:
        version = pubspec_version()
        self.assertIn(f'<release version="{version}"', METAINFO)

    def test_winn_gate_test_is_in_the_linux_ctest_set(self) -> None:
        self.assertIn('add_executable(linux_winn_gate_test "linux_winn_gate_test.cc")', CMAKE)
        self.assertIn("NAME linux_winn_gate_test", CMAKE)

    def test_installed_manifest_treats_winn_datapath_as_executable(self) -> None:
        self.assertIn('"winn-datapath",', MANIFEST)

    def test_winn_gate_compiles_and_passes_on_this_host(self) -> None:
        binary = pathlib.Path("/tmp/linux_winn_gate_test.winsvpn")
        try:
            completed = subprocess.run(
                [
                    "c++",
                    "-std=c++17",
                    "-Wall",
                    "-Wextra",
                    "-o",
                    str(binary),
                    str(ROOT / "linux/runner/linux_winn_gate_test.cc"),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            ran = subprocess.run(
                [str(binary)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(ran.returncode, 0, ran.stderr)
            self.assertIn("linux_winn_gate_test: all checks passed", ran.stdout)
        finally:
            binary.unlink(missing_ok=True)


class LinuxAppStreamMetainfoTests(unittest.TestCase):
    def test_metainfo_is_ascii_xml_without_entities(self) -> None:
        raw = METAINFO_PATH.read_bytes()
        self.assertTrue(raw.isascii(), "AppStream metainfo must be ASCII")
        text = raw.decode("ascii")
        self.assertNotIn("<!DOCTYPE", text.upper())
        self.assertNotIn("<!ENTITY", text.upper())
        self.assertTrue(text.startswith('<?xml version="1.0" encoding="UTF-8"?>'))

    def test_metainfo_identity_urls_and_protocol_wording(self) -> None:
        component = ET.fromstring(METAINFO)
        self.assertEqual(component.tag, "component")
        self.assertEqual(component.get("type"), "desktop-application")
        self.assertEqual(component.findtext("id"), "org.winsvpn.app")
        self.assertEqual(
            component.findtext("launchable"), "org.winsvpn.app.desktop"
        )
        urls = {
            node.get("type"): (node.text or "").strip()
            for node in component.findall("url")
        }
        self.assertTrue(APPSTREAM_URL_TYPES.issuperset(urls))
        self.assertEqual(urls.get("homepage"), "https://winsvpn.org")
        self.assertEqual(urls.get("help"), CANONICAL_SUPPORT_URL)
        self.assertEqual(urls.get("contact"), CANONICAL_SUPPORT_URL)
        self.assertNotIn("privacy-policy", urls)
        paragraphs = [
            "".join(node.itertext()) for node in component.findall("description/p")
        ]
        description = "\n".join(paragraphs)
        self.assertGreaterEqual(len(paragraphs[0].strip()), 80)
        self.assertIn(CANONICAL_PRIVACY_URL, description)
        self.assertIn(CANONICAL_SUPPORT_URL, description)
        self.assertIn("Winn Protocol v3 is the primary tunnel protocol", description)
        self.assertIn("AWG then Xray", description)
        self.assertLess(description.find("AWG"), description.find("Xray"))
        self.assertIn("not an implicit fallback", description)
        self.assertNotIn("If a served Winn v3 attempt cannot complete", description)
        self.assertIsNone(component.find("screenshots"))
        self.assertEqual(component.findtext("provides/binary"), "wins_vpn")
        self.assertEqual(component.findtext("requires/internet"), "always")

    def test_metainfo_oars_and_current_release(self) -> None:
        component = ET.fromstring(METAINFO)
        rating = component.find("content_rating")
        self.assertIsNotNone(rating)
        self.assertEqual(rating.get("type"), "oars-1.1")
        attributes = {
            node.get("id"): (node.text or "").strip()
            for node in rating.findall("content_attribute")
        }
        self.assertEqual(set(attributes), OARS_1_1_IDS)
        self.assertTrue(OARS_VALUES.issuperset(attributes.values()))
        self.assertEqual(attributes["money-purchasing"], "mild")
        self.assertEqual(attributes["social-info"], "intense")
        self.assertEqual(attributes["social-location"], "none")
        self.assertEqual(attributes["money-gambling"], "none")
        releases = component.findall("releases/release")
        self.assertGreaterEqual(len(releases), 1)
        self.assertEqual(releases[0].get("version"), pubspec_version())
        self.assertEqual(releases[0].get("date"), "2026-09-13")
        current = "".join(releases[0].itertext())
        self.assertIn("Winn Protocol v3", current)
        self.assertIn("AWG then Xray", current)
        self.assertLess(current.find("AWG"), current.find("Xray"))
        self.assertIn("trusted served configuration", current)
        self.assertIn("not an implicit fallback", current)

    def test_metainfo_validates_with_available_appstream_tools(self) -> None:
        xmllint = shutil.which("xmllint")
        self.assertIsNotNone(xmllint, "xmllint is required to check metainfo XML")
        parsed = subprocess.run(
            [xmllint, "--noout", "--nonet", str(METAINFO_PATH)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(parsed.returncode, 0, parsed.stderr)
        appstreamcli = shutil.which("appstreamcli")
        if appstreamcli is None:
            return
        validated = subprocess.run(
            [
                appstreamcli,
                "validate",
                "--no-net",
                "--explain",
                "--pedantic",
                str(METAINFO_PATH),
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(
            validated.returncode,
            0,
            validated.stdout + validated.stderr,
        )


if __name__ == "__main__":
    unittest.main()
