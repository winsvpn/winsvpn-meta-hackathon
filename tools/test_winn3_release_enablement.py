#!/usr/bin/env python3
"""Release-gate: every enabled platform build must compile the reviewed ring.

The client freezes four compilation-environment declarations into the AOT
payload via Flutter `--dart-define` / Dart `String.fromEnvironment`
(https://dart.dev/libraries/core/environment-declarations,
https://api.dart.dev/dart-core/String/String.fromEnvironment.html):

  WINS_WINN3_DESCRIPTOR_PUBKEY_G1
  WINS_WINN3_DESCRIPTOR_PUBKEY_G2
  WINS_WINN3_DESCRIPTOR_PUBKEY_G3
  WINS_WINN3_DESCRIPTOR_RING_SHA256

plus the runtime platform gate:

  WINS_WINN3_ENABLED_PLATFORMS

`WINS_WINN3_DESCRIPTOR_RING_SHA256` is the WIRE-FORM identity
(sha256 of `g1=<hex>\\ng2=<hex>\\ng3=<hex>\\n`), computed by
`tools/winn3_descriptor_ring_identity.py` and attested by
`Winn3DescriptorKeyRing.identitySha256`. It is NOT the ceremony
manifest digest. The Track B/C briefing labeled the manifest digest
`RING_SHA256`; compiling that value makes every client report
`descriptor-verification-ring-identity-mismatch`. The canonical reviewed values
for this repository are in `tools/winn3_descriptor_ring_defines.py`.
"""

from __future__ import annotations

import base64
import binascii
import os
import pathlib
import re
import shutil
import subprocess
import sys
import unittest

TOOLS = pathlib.Path(__file__).resolve().parent
ROOT = TOOLS.parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from winn3_descriptor_ring_defines import (  # noqa: E402
    CEREMONY_MANIFEST_SHA256,
    RING,
    REVIEWED_RING_SHA256,
)

IDENTITY_TOOL = TOOLS / "winn3_descriptor_ring_identity.py"
DEFINES_TOOL = TOOLS / "winn3_descriptor_ring_defines.py"
# Ceremony public keys (Track B, public by design), frozen in the canonical
# current-repository define source as slots g1/g2/g3.
# RFC 8032 §5.1.5: Ed25519 public key is 32 octets.
# RFC 4648 §4: standard Base64 with padding; 32 bytes encode to 44 chars.
EXPECTED_RING = {
    "g1": "L2mAYdYIXPCFuNoH5ntgBBubFSnnlzIAnXwKttpehaQ=",
    "g2": "eVCAHWXqUM1+m5nlVy2JR+Q4/mkYGTxlk119aiQh89M=",
    "g3": "53JhsQBxKH5DG145LcaBunOX4lbt+J7Js0oPyJnj9Q0=",
}

# Briefing called this RING_SHA256. It is the digest of the ceremony
# manifest JSON (sort_keys, compact separators, `ring_sha256` removed).
# It must never be passed as WINS_WINN3_DESCRIPTOR_RING_SHA256.
BRIEFING_MANIFEST_DIGEST = (
    "29c66c18f5aef6eb064e065a5d7c3c98aa1548f758ac6d19b19a9d4a7863e7fb"
)

# sha256 of the 204-byte WIRE-FORM. FIPS 180-4 SHA-256 is 256 bits (64 hex).
# Recomputed by tools/winn3_descriptor_ring_identity.py from EXPECTED_RING.
WIRE_FORM_RING_SHA256 = (
    "52e91c72ca52d23059724e0a6c25c2f45bae574a85a84c884c5b7fd367cbf032"
)

PUBKEY_G1 = "WINS_WINN3_DESCRIPTOR_PUBKEY_G1"
PUBKEY_G2 = "WINS_WINN3_DESCRIPTOR_PUBKEY_G2"
PUBKEY_G3 = "WINS_WINN3_DESCRIPTOR_PUBKEY_G3"
RING_SHA256_DEFINE = "WINS_WINN3_DESCRIPTOR_RING_SHA256"
EXPECTED_RING_SHA256_ENV = "WINS_EXPECTED_WINN3_DESCRIPTOR_RING_SHA256"
ENABLED_PLATFORMS_DEFINE = "WINS_WINN3_ENABLED_PLATFORMS"
RELAY_PLATFORMS_DEFINE = "WINS_WINN3_RELAY_ENABLED_PLATFORMS"
DUAL_AUTH_DEFINE = "WINS_WINN3_DUAL_AUTH"
DUAL_AUTH_TRUE = f"{DUAL_AUTH_DEFINE}=true"
DUAL_AUTH_FALSE = f"{DUAL_AUTH_DEFINE}=false"
DUAL_AUTH_TRUE_BLOB = base64.b64encode(DUAL_AUTH_TRUE.encode("ascii")).decode(
    "ascii"
)
DUAL_AUTH_FALSE_BLOB = base64.b64encode(DUAL_AUTH_FALSE.encode("ascii")).decode(
    "ascii"
)
# Android C-8 injection, the encoding every other release producer must match.
ANDROID_DUAL_AUTH_TRUE_BLOB = "V0lOU19XSU5OM19EVUFMX0FVVEg9dHJ1ZQ=="
PUBLIC_KEY_BYTES = 32

_CMAKE_QUOTED_SET = re.compile(r'set\(\s*([A-Za-z0-9_]+)\s+"([^"]*)"\s*\)')

# Release producers that emit a standalone-v3 enabled-platform define.
ENABLED_PLATFORM_PRODUCERS = (
    ("tools/build_android_release_macos.sh", f"{ENABLED_PLATFORMS_DEFINE}=android"),
    ("tools/build_android_release.ps1", f"{ENABLED_PLATFORMS_DEFINE}=android"),
    (
        "tools/apple_runtime_smoke.sh",
        f"{ENABLED_PLATFORMS_DEFINE}=${{target_platform}}",
    ),
    (
        "installer/windows/build_installer.ps1",
        f"{ENABLED_PLATFORMS_DEFINE}=windows",
    ),
    (
        "installer/windows/build_store_msix.ps1",
        f"{ENABLED_PLATFORMS_DEFINE}=windows",
    ),
    ("tools/build_linux_release.sh", f"{ENABLED_PLATFORMS_DEFINE}=linux"),
)

REVIEWED_RING_LOADERS = (
    "tools/build_android_release_macos.sh",
    "tools/build_linux_release.sh",
)


_WINN3_BLOB_TOKEN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def _decode_winn3_blob(token: str) -> str | None:
    padded = token + ("=" * ((4 - len(token) % 4) % 4))
    try:
        text = base64.b64decode(padded, validate=True).decode("ascii")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    if not text.startswith("WINS_WINN3_"):
        return None
    name, separator, _value = text.partition("=")
    if not separator or not name:
        return None
    return text


def _winn3_define_entries_from_csv(csv: str) -> list[str]:
    """Decode comma-joined encodeDartDefines blobs, preserving duplicates."""
    entries: list[str] = []
    for token in csv.split(","):
        token = token.strip()
        if not token or "${" in token or token.startswith("$("):
            continue
        text = _decode_winn3_blob(token)
        if text is None:
            continue
        entries.append(text)
    return entries


def _winn3_defines_from_source(source: str) -> dict[str, str]:
    """Last-wins decode of Flutter encodeDartDefines blobs in a text file."""
    defines: dict[str, str] = {}
    for token in _WINN3_BLOB_TOKEN.findall(source):
        text = _decode_winn3_blob(token)
        if text is None:
            continue
        name, _separator, value = text.partition("=")
        defines[name] = value
    return defines


def _cmake_quoted_sets(source: str, name: str) -> list[str]:
    return [value for var, value in _CMAKE_QUOTED_SET.findall(source) if var == name]


def _dual_auth_true_entries(entries: list[str]) -> list[str]:
    return [entry for entry in entries if entry.startswith(f"{DUAL_AUTH_DEFINE}=")]


def _computed_ring_identity() -> str:
    defines = [
        f"--dart-define={PUBKEY_G1}={EXPECTED_RING['g1']}",
        f"--dart-define={PUBKEY_G2}={EXPECTED_RING['g2']}",
        f"--dart-define={PUBKEY_G3}={EXPECTED_RING['g3']}",
    ]
    result = subprocess.run(
        [sys.executable, str(IDENTITY_TOOL), *defines],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"ring identity tool failed (exit {result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout.strip()


def _run_defines_tool(fmt: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(DEFINES_TOOL), fmt],
        check=False,
        capture_output=True,
        text=True,
    )


class Winn3ReleaseEnablementTest(unittest.TestCase):
    def source(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_ceremony_pubkeys_decode_to_32_canonical_bytes(self):
        seen: set[bytes] = set()
        for slot, encoded in EXPECTED_RING.items():
            raw = base64.b64decode(encoded, validate=True)
            self.assertEqual(len(raw), PUBLIC_KEY_BYTES, slot)
            self.assertEqual(base64.b64encode(raw).decode("ascii"), encoded, slot)
            self.assertNotIn(raw, seen, slot)
            seen.add(raw)

    def test_reviewed_ring_pins_match_ceremony_public_keys(self):
        """The single compile-time pin must be the ceremony public keys.

        Producers that `eval` tools/winn3_descriptor_ring_defines.py compile
        whatever RING holds. A redacted or drifted pin ships a ringless
        (or wrong-ring) build.
        """
        defines_source = self.source("tools/winn3_descriptor_ring_defines.py")
        self.assertNotIn(
            "<REDACTED_WG_KEY>",
            defines_source,
            "ceremony public keys must not be scanner-redacted in the define source",
        )
        self.assertEqual(tuple(RING), ("g1", "g2", "g3"))
        for slot, expected in EXPECTED_RING.items():
            self.assertEqual(
                RING[slot],
                expected,
                f"RING[{slot!r}] is not the ceremony public key",
            )
            self.assertIn(expected, defines_source, slot)

    def test_defines_tool_emits_reviewed_ring(self):
        verify = _run_defines_tool("verify")
        self.assertEqual(
            verify.returncode,
            0,
            "defines tool refused to emit the reviewed ring: "
            f"{verify.stderr.strip()}",
        )
        self.assertIn(WIRE_FORM_RING_SHA256, verify.stdout)
        self.assertIn(REVIEWED_RING_SHA256, verify.stdout)
        self.assertNotIn(BRIEFING_MANIFEST_DIGEST, verify.stdout)

        dart_define = _run_defines_tool("dart-define")
        self.assertEqual(dart_define.returncode, 0, dart_define.stderr.strip())
        for slot, encoded in EXPECTED_RING.items():
            self.assertIn(
                f"--dart-define=WINS_WINN3_DESCRIPTOR_PUBKEY_{slot.upper()}={encoded}",
                dart_define.stdout,
            )
        self.assertIn(
            f"--dart-define={RING_SHA256_DEFINE}={WIRE_FORM_RING_SHA256}",
            dart_define.stdout,
        )
        self.assertNotIn(BRIEFING_MANIFEST_DIGEST, dart_define.stdout)

        sh_exports = _run_defines_tool("sh")
        self.assertEqual(sh_exports.returncode, 0, sh_exports.stderr.strip())
        for slot, encoded in EXPECTED_RING.items():
            self.assertIn(
                f"export WINS_WINN3_DESCRIPTOR_PUBKEY_{slot.upper()}='{encoded}'",
                sh_exports.stdout,
            )
        self.assertIn(
            f"export {EXPECTED_RING_SHA256_ENV}='{WIRE_FORM_RING_SHA256}'",
            sh_exports.stdout,
        )
        self.assertNotIn(f"{RING_SHA256_DEFINE}=", sh_exports.stdout)
        self.assertNotIn(BRIEFING_MANIFEST_DIGEST, sh_exports.stdout)

        identity = _run_defines_tool("identity")
        self.assertEqual(identity.returncode, 0, identity.stderr.strip())
        self.assertEqual(identity.stdout.strip(), WIRE_FORM_RING_SHA256)

    def test_reviewed_ring_identity_is_wire_form_not_manifest_digest(self):
        wire = _computed_ring_identity()
        self.assertEqual(len(wire), 64)
        self.assertRegex(wire, r"^[0-9a-f]{64}$")
        self.assertEqual(wire, WIRE_FORM_RING_SHA256)
        self.assertEqual(wire, REVIEWED_RING_SHA256)
        self.assertEqual(CEREMONY_MANIFEST_SHA256, BRIEFING_MANIFEST_DIGEST)
        self.assertNotEqual(wire, BRIEFING_MANIFEST_DIGEST)
        self.assertNotEqual(REVIEWED_RING_SHA256, BRIEFING_MANIFEST_DIGEST)

    def test_android_macos_and_linux_auto_load_reviewed_define_source(self):
        for relative in REVIEWED_RING_LOADERS:
            source = self.source(relative)
            self.assertIn("winn3_descriptor_ring_defines.py", source, relative)

    def test_client_compiles_all_four_ring_defines(self):
        dispatch = self.source("lib/winn_protocol_dispatch.dart")
        for name in (PUBKEY_G1, PUBKEY_G2, PUBKEY_G3, RING_SHA256_DEFINE):
            self.assertIn(f"'{name}'", dispatch, name)
            self.assertIn("String.fromEnvironment", dispatch)
        self.assertIn(f"'{ENABLED_PLATFORMS_DEFINE}'", dispatch)

    def test_winn3_enabled_platforms_gates_correctly(self):
        dispatch = self.source("lib/winn_protocol_dispatch.dart")
        self.assertIn("'android'", dispatch)
        self.assertIn("'ios'", dispatch)
        self.assertIn("'macos'", dispatch)
        self.assertIn("'windows'", dispatch)
        self.assertIn(
            "const Set<String> kWinn3StandaloneReleasePlatforms", dispatch
        )
        # Unknown tokens invalidate the entire define. Linux joined the
        # release set on 2026-08-21 (linux app-level live winn3 lane) next to
        # the android entry, so it is asserted IN below.
        self.assertIn("!kWinn3StandaloneReleasePlatforms.contains(part)", dispatch)
        self.assertIn("return <String>{};", dispatch)
        allowlist = dispatch.split(
            "const Set<String> kWinn3StandaloneReleasePlatforms = <String>{"
        )[1].split("};", 1)[0]
        self.assertIn("'android'", allowlist)
        self.assertIn("'ios'", allowlist)
        self.assertIn("'macos'", allowlist)
        self.assertIn("'windows'", allowlist)
        self.assertIn("'linux'", allowlist)

    def test_every_enabled_platform_build_carries_ring_defines(self):
        forbidden = f"{RING_SHA256_DEFINE}={BRIEFING_MANIFEST_DIGEST}"
        for relative, gate in ENABLED_PLATFORM_PRODUCERS:
            source = self.source(relative)
            self.assertIn("WINS_WINN3_DESCRIPTOR_PUBKEY_", source, relative)
            bash_loop = "for slot in G1 G2 G3" in source
            ps_loop = "@('G1','G2','G3')" in source
            literals = all(
                name in source for name in (PUBKEY_G1, PUBKEY_G2, PUBKEY_G3)
            )
            self.assertTrue(
                bash_loop or ps_loop or literals,
                f"{relative} must name G1 G2 G3 (loop or literals)",
            )
            self.assertIn(RING_SHA256_DEFINE, source, relative)
            self.assertIn(f"--dart-define={RING_SHA256_DEFINE}", source, relative)
            self.assertIn(gate, source, relative)
            self.assertNotIn(forbidden, source, relative)

    def test_ios_shipping_connect_path_installs_served_v3_config(self):
        main = self.source("lib/main.dart")
        self.assertIn("deliverWinnIosServedTunnelConfig", main)
        self.assertIn(
            "Platform.isIOS && protocolVersion == kWinnProtocolV3", main
        )
        self.assertIn("if (!delivery.accepted)", main)

    def test_android_release_producers_enable_android_and_require_ring(self):
        for relative in (
            "tools/build_android_release_macos.sh",
            "tools/build_android_release.ps1",
        ):
            source = self.source(relative)
            self.assertGreaterEqual(
                source.count(f"{ENABLED_PLATFORMS_DEFINE}=android"),
                2,
                relative,
            )
            self.assertIn("descriptor", source.lower(), relative)
            self.assertIn("requires", source.lower(), relative)

    def test_android_phone_release_builds_advertise_relay(self):
        relay = "--dart-define=WINS_WINN3_RELAY_ENABLED_PLATFORMS=android"
        mac = self.source("tools/build_android_release_macos.sh")
        phone = [line for line in mac.splitlines()
                 if "run_flutter_release_build build" in line and "--flavor phone" in line]
        tv = [line for line in mac.splitlines()
              if "run_flutter_release_build build" in line and "--flavor tv" in line]
        self.assertEqual(len(phone), 2)
        self.assertEqual(len(tv), 2)
        for line in phone:
            self.assertEqual(line.count(relay), 1, line)
        for line in tv:
            self.assertNotIn(relay, line)
        windows = self.source("tools/build_android_release.ps1")
        for kind in ("apk", "appbundle"):
            start = windows.index(f"'build', '{kind}', '--release', '--flavor', 'phone'")
            end = windows.index(") + $winn3PubkeyDefines", start)
            self.assertEqual(windows[start:end].count(relay), 1, kind)
            tv_start = windows.index(f"'build', '{kind}', '--release', '--flavor', 'tv'")
            tv_end = windows.index(") + $winn3PubkeyDefines", tv_start)
            self.assertNotIn(RELAY_PLATFORMS_DEFINE, windows[tv_start:tv_end], f"tv {kind}")

    def test_apple_candidate_keeps_native_winn_and_enables_exact_target(self):
        candidate = self.source("tools/build_apple_release_candidates.sh")
        runtime = self.source("tools/apple_runtime_smoke.sh")
        self.assertNotIn("Removed %s before archiving", candidate)
        self.assertIn(
            "Standalone v3 release artifact is missing or symbolic",
            candidate,
        )
        self.assertIn("WINS_APPLE_WINN3_RELEASE=1", candidate)
        self.assertIn("WINS_REQUIRE_WINN3_DESCRIPTOR_PUBKEY=1", candidate)
        self.assertIn(
            f"{ENABLED_PLATFORMS_DEFINE}=${{target_platform}}",
            runtime,
        )
        self.assertIn("ios|macos)", runtime)

    def test_unsigned_apple_release_shells_match_release_capability(self):
        runtime = self.source("tools/apple_runtime_smoke.sh")
        self.assertIn(f"{ENABLED_PLATFORMS_DEFINE}=${{target_platform}}", runtime)
        self.assertIn("ios|macos)", runtime)
        self.assertIn("for slot in G1 G2 G3", runtime)
        self.assertIn('var="WINS_WINN3_DESCRIPTOR_PUBKEY_${slot}"', runtime)

    def test_local_suite_exercises_each_shipping_define(self):
        dart = self.source("test/winn3_shipping_define_test.dart")
        self.assertIn("WINS_TEST_EXPECTED_WINN3_PLATFORM", dart)
        self.assertIn(ENABLED_PLATFORMS_DEFINE, dart)
        for platform in ("android", "ios", "macos", "windows", "linux"):
            self.assertIn(f"'{platform}'", dart)

    def test_windows_release_identity_is_reviewed_and_attested(self):
        for relative in (
            "installer/windows/build_installer.ps1",
            "installer/windows/build_store_msix.ps1",
        ):
            source = self.source(relative)
            self.assertIn("WINS_EXPECTED_WINN3_DESCRIPTOR_RING_SHA256", source)
            self.assertIn(RING_SHA256_DEFINE, source)
            self.assertIn("verify_winn3_ring_artifact.py", source)

    def test_linux_release_enables_standalone_v3(self):
        combined = (
            self.source("tools/build_linux_release.sh")
            + self.source("tools/Dockerfile.linux-desktop")
            + self.source("tools/build_linux_desktop_container.sh")
        )
        self.assertIn(f"{ENABLED_PLATFORMS_DEFINE}=linux", combined)
        linux_tree = (
            self.source("linux/flutter/CMakeLists.txt")
            + self.source("linux/flutter/Winn3DescriptorRing.cmake")
            + self.source("linux/flutter/winn3_tool_backend.sh")
        )
        linux = _winn3_defines_from_source(linux_tree)
        self.assertEqual(linux.get(ENABLED_PLATFORMS_DEFINE), "linux")

    def _assert_reviewed_ring(self, decoded: dict[str, str], relative: str) -> None:
        for slot, encoded in EXPECTED_RING.items():
            name = f"WINS_WINN3_DESCRIPTOR_PUBKEY_{slot.upper()}"
            self.assertEqual(
                decoded.get(name),
                encoded,
                f"{relative} {name}",
            )
        self.assertEqual(
            decoded.get(RING_SHA256_DEFINE),
            WIRE_FORM_RING_SHA256,
            f"{relative} {RING_SHA256_DEFINE} must be WIRE-FORM",
        )
        self.assertNotEqual(
            decoded.get(RING_SHA256_DEFINE),
            BRIEFING_MANIFEST_DIGEST,
            f"{relative} must not compile MANIFEST-FORM as {RING_SHA256_DEFINE}",
        )
        forbidden = f"{RING_SHA256_DEFINE}={BRIEFING_MANIFEST_DIGEST}"
        self.assertNotIn(forbidden, self.source(relative), relative)

    def test_android_release_gradle_appends_ring_to_flutter_task(self):
        relative = "android/app/build.gradle.kts"
        source = self.source(relative)
        self.assertIn("com.flutter.gradle.tasks.FlutterTask", source)
        self.assertIn("tasks.withType<FlutterTask>()", source)
        self.assertIn("dartDefines", source)
        self.assertIn("buildMode?.lowercase().orEmpty()", source)
        decoded = _winn3_defines_from_source(source)
        self._assert_reviewed_ring(decoded, relative)
        self.assertEqual(decoded.get(ENABLED_PLATFORMS_DEFINE), "android")

    def test_apple_release_xcconfig_appends_ring_to_dart_defines(self):
        for relative, platform in (
            ("ios/Flutter/Winn3DescriptorRing.xcconfig", "ios"),
            ("macos/Flutter/Winn3DescriptorRing.xcconfig", "macos"),
        ):
            decoded = _winn3_defines_from_source(self.source(relative))
            self._assert_reviewed_ring(decoded, relative)
            self.assertEqual(decoded.get(ENABLED_PLATFORMS_DEFINE), platform, relative)
        self.assertIn(
            '#include "Winn3DescriptorRing.xcconfig"',
            self.source("ios/Flutter/Release.xcconfig"),
        )
        self.assertIn(
            '#include "Winn3DescriptorRing.xcconfig"',
            self.source("macos/Flutter/Flutter-Release.xcconfig"),
        )

    def test_windows_linux_tool_backend_appends_ring_to_dart_defines(self):
        windows_cmake = self.source("windows/flutter/CMakeLists.txt")
        linux_cmake = self.source("linux/flutter/CMakeLists.txt")
        self.assertIn("winn3_tool_backend.cmd", windows_cmake)
        self.assertIn("winn3_tool_backend.sh", linux_cmake)
        self.assertIn("WINN3_RING_DART_DEFINES", windows_cmake)
        self.assertIn("WINN3_RING_DART_DEFINES", linux_cmake)
        self.assertIn("DART_DEFINES", self.source("windows/flutter/winn3_tool_backend.cmd"))
        self.assertIn("DART_DEFINES", self.source("linux/flutter/winn3_tool_backend.sh"))

        windows = _winn3_defines_from_source(
            self.source("windows/flutter/Winn3DescriptorRing.cmake")
            + self.source("windows/flutter/winn3_tool_backend.cmd")
        )
        self._assert_reviewed_ring(windows, "windows/flutter/Winn3DescriptorRing.cmake")
        self.assertEqual(windows.get(ENABLED_PLATFORMS_DEFINE), "windows")
        self.assertIn("Release", self.source("windows/flutter/winn3_tool_backend.cmd"))

        linux = _winn3_defines_from_source(
            self.source("linux/flutter/Winn3DescriptorRing.cmake")
            + self.source("linux/flutter/winn3_tool_backend.sh")
        )
        self._assert_reviewed_ring(linux, "linux/flutter/Winn3DescriptorRing.cmake")
        self.assertEqual(linux.get(ENABLED_PLATFORMS_DEFINE), "linux")


def _ps_statement(source: str, anchor: str) -> str:
    """The PowerShell statement that starts at `anchor`, joined over backtick continuations."""
    lines = source[source.index(anchor):].splitlines()
    statement: list[str] = []
    for line in lines:
        statement.append(line)
        if not line.rstrip().endswith("`"):
            break
    return "\n".join(statement)


def _relay_scan_files() -> list[pathlib.Path]:
    """Release producers and packaging inputs that could spell a dart-define.

    Test files, the Dart `lib/` and `test/` trees and generated or vendored
    output are not producers.
    """
    skip_dirs = {
        ".git", ".dart_tool", ".gradle", "build", "node_modules", "Pods",
        "ephemeral", "evidence", "__pycache__", "tests",
    }
    found: list[pathlib.Path] = []
    for top in (
        "tools", "installer", "linux", "windows", "ios", "macos", "android",
        "wear_os", "apple", ".github", "extension",
    ):
        for directory, names, files in os.walk(ROOT / top):
            names[:] = [name for name in names if name not in skip_dirs]
            for name in files:
                if name.startswith("test_") or name.endswith("_test.py"):
                    continue
                path = pathlib.Path(directory) / name
                if path.is_symlink() or path.stat().st_size > 8 * 1024 * 1024:
                    continue
                found.append(path)
    return found


class Winn3RelayReleaseProducersTest(unittest.TestCase):
    """Owner ruling 2026-10-24: the Double VPN ciphertext relay ships on every
    platform except the Android TV flavor (never) and Wear OS (no relay).

    Each shipped producer passes `--dart-define=WINS_WINN3_RELAY_ENABLED_PLATFORMS=<its
    platform>` exactly once per release build. Dart's compilation environment
    is a mapping, so a second spelling of the key is an unaudited duplicate.
    """

    RELAY_ARG = f"--dart-define={RELAY_PLATFORMS_DEFINE}="

    # producer -> how many times its source spells the define argument.
    PRODUCER_ARGUMENT_COUNTS = {
        # phone APK and phone AAB; the two TV commands carry none.
        "tools/build_android_release_macos.sh": 2,
        "tools/build_android_release.ps1": 2,
        # one printf for the ios|macos arm of flutter_build_define_args.
        "tools/apple_runtime_smoke.sh": 1,
        # one `flutter build windows` serves the x64 and the Windows-on-ARM release.
        "installer/windows/build_installer.ps1": 1,
        # one constant is the only spelling; the x64 and arm64 builds share the command.
        "tools/build_linux_release.sh": 1,
    }

    def source(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_relay_define_argument_exists_only_in_the_reviewed_producers(self):
        actual: dict[str, int] = {}
        for path in _relay_scan_files():
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            count = text.count(self.RELAY_ARG)
            if count:
                actual[path.relative_to(ROOT).as_posix()] = count
        self.assertEqual(
            actual,
            self.PRODUCER_ARGUMENT_COUNTS,
            "the relay define may be spelled only by the reviewed shipped producers. "
            "Android TV, Wear OS, MSIX, Flathub, Snap and the Linux container image are "
            "deliberately absent; adding one is an owner decision.",
        )

    def test_relay_define_has_no_second_in_tree_channel(self):
        # The in-tree Release blobs are base64, so a plain text scan cannot see them.
        for relative in (
            "android/app/build.gradle.kts",
            "windows/flutter/Winn3DescriptorRing.cmake",
            "windows/flutter/winn3_tool_backend.cmd",
            "linux/flutter/Winn3DescriptorRing.cmake",
            "linux/flutter/winn3_tool_backend.sh",
            "ios/Flutter/Winn3DescriptorRing.xcconfig",
            "macos/Flutter/Winn3DescriptorRing.xcconfig",
        ):
            source = self.source(relative)
            self.assertNotIn(RELAY_PLATFORMS_DEFINE, source, relative)
            decoded = _winn3_defines_from_source(source)
            self.assertNotIn(RELAY_PLATFORMS_DEFINE, decoded, relative)

    def test_android_tv_and_wear_never_carry_the_relay_define(self):
        mac = self.source("tools/build_android_release_macos.sh")
        tv_lines = [
            line for line in mac.splitlines()
            if "run_flutter_release_build build" in line and "--flavor tv" in line
        ]
        self.assertEqual(len(tv_lines), 2)
        for line in tv_lines:
            self.assertIn(f"{ENABLED_PLATFORMS_DEFINE}=android", line)
            self.assertNotIn(RELAY_PLATFORMS_DEFINE, line)
        for relative in (
            "tools/build_android_release.ps1",
            "tools/android_public_release_live_smoke.ps1",
        ):
            ps = self.source(relative)
            for match in re.finditer(r"'--flavor', 'tv'", ps):
                end = ps.find(") + $winn3PubkeyDefines", match.start())
                if end > 0:
                    self.assertNotIn(RELAY_PLATFORMS_DEFINE, ps[match.start():end], relative)
        # Wear OS is a Gradle-only app: it has no Flutter build and so no dart-define.
        for directory, names, files in os.walk(ROOT / "wear_os"):
            names[:] = [name for name in names if name not in {"build", ".gradle"}]
            for name in files:
                path = pathlib.Path(directory) / name
                try:
                    text = path.read_text(encoding="utf-8")
                except (UnicodeDecodeError, OSError):
                    continue
                self.assertNotIn(
                    RELAY_PLATFORMS_DEFINE, text, path.relative_to(ROOT).as_posix()
                )

    def _apple_define_args(self, target: str, **environment: str) -> subprocess.CompletedProcess[str]:
        text = self.source("tools/apple_runtime_smoke.sh")

        def function(name: str) -> str:
            start = text.index("\n" + name + "() {\n") + 1
            return text[start:text.index("\n}\n", start) + 3]

        harness = (
            "set -Eeuo pipefail\n"
            + function("winn3_descriptor_pubkey_define_args")
            + function("flutter_build_define_args")
            + 'flutter_build_define_args "$1"\n'
        )
        env = {
            "PATH": "/usr/bin:/bin",
            "WINS_APPLE_LIVE_TUNNEL_SMOKE": "0",
            "WINS_IOS_LIVE_TUNNEL_SMOKE": "0",
            "WINS_APPLE_FORCE_XRAY": "0",
        }
        env.update(environment)
        shell = "/bin/bash" if pathlib.Path("/bin/bash").is_file() else "bash"
        return subprocess.run(
            [shell, "-c", harness, "harness", target],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_apple_release_builds_pass_the_relay_define_once_for_their_own_target(self):
        for target in ("ios", "macos"):
            with self.subTest(target=target):
                completed = self._apple_define_args(target, WINS_APPLE_WINN3_RELEASE="1")
                self.assertEqual(completed.returncode, 0, completed.stderr)
                lines = completed.stdout.splitlines()
                self.assertEqual(
                    [line for line in lines if RELAY_PLATFORMS_DEFINE in line],
                    [f"{self.RELAY_ARG}{target}"],
                )
                self.assertEqual(
                    [line for line in lines if ENABLED_PLATFORMS_DEFINE in line],
                    [f"--dart-define={ENABLED_PLATFORMS_DEFINE}={target}"],
                )

    def test_apple_relay_define_is_release_only_and_never_for_other_targets(self):
        for release in ("0", ""):
            with self.subTest(release=release):
                environment = {"WINS_APPLE_WINN3_RELEASE": release} if release else {}
                for target in ("ios", "macos"):
                    completed = self._apple_define_args(target, **environment)
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertNotIn(RELAY_PLATFORMS_DEFINE, completed.stdout)
        for target in ("tvos", "watchos", "visionos", ""):
            with self.subTest(target=target):
                completed = self._apple_define_args(target, WINS_APPLE_WINN3_RELEASE="1")
                self.assertEqual(completed.returncode, 65, completed.stderr)
                self.assertNotIn(RELAY_PLATFORMS_DEFINE, completed.stdout)

    def test_apple_build_wrapper_stops_if_define_generation_fails(self):
        source = self.source("tools/apple_runtime_smoke.sh")
        def function(name: str) -> str:
            start = source.index("\n" + name + "() {\n") + 1
            return source[start:source.index("\n}\n", start) + 3]
        harness = "\n".join((
            "set -Eeuo pipefail",
            "winn3_descriptor_pubkey_define_args() { :; }",
            "log_winn3_descriptor_pubkey_status_for_defines() { :; }",
            'mock_py() { printf "%064d\\n" 0; }',
            "run() { echo FLUTTER_CALLED; }",
            "PYTHON_BIN=mock_py",
            "ROOT_DIR=.",
            "FLUTTER_BIN=flutter",
            "WINS_APPLE_WINN3_RELEASE=1",
            'WINS_EXPECTED_WINN3_DESCRIPTOR_RING_SHA256=$(printf "%064d" 0)',
            "WINS_APPLE_LIVE_TUNNEL_SMOKE=0",
            "WINS_IOS_LIVE_TUNNEL_SMOKE=0",
            "WINS_APPLE_FORCE_XRAY=0",
            function("flutter_build_define_args"),
            function("run_flutter_build"),
            "run_flutter_build build tvos --release",
        ))
        shell = "/bin/bash" if pathlib.Path("/bin/bash").is_file() else "bash"
        result = subprocess.run([shell, "-c", harness], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 65, result.stderr)
        self.assertNotIn("FLUTTER_CALLED", result.stdout)

    def test_apple_relay_define_is_not_duplicated_by_smoke_defines(self):
        completed = self._apple_define_args(
            "ios",
            WINS_APPLE_WINN3_RELEASE="1",
            WINS_APPLE_LIVE_TUNNEL_SMOKE="1",
            WINS_APPLE_LIVE_TUNNEL_SMOKE_TIMEOUT_SECONDS="60",
            WINS_APPLE_LIVE_TUNNEL_SMOKE_PIN="000000",
            WINS_APPLE_EXPECT_DOUBLE_VPN="1",
            WINS_APPLE_EXTERNAL_LEAK_AUDIT="0",
            WINS_APPLE_EXTERNAL_LEAK_AUDIT_URLS="",
            WINS_APPLE_EXTERNAL_LEAK_AUDIT_MINIMUM_ENDPOINTS="1",
            WINS_IOS_RELEASE_TESTING_EXPORT_SMOKE="0",
            WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE="0",
            WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE="0",
            WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE="0",
            WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE="0",
            WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE="0",
            WINS_MACOS_DEVELOPER_ID_EXPORT_SMOKE="0",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.count(RELAY_PLATFORMS_DEFINE), 1, completed.stdout)

    def test_apple_candidate_producer_delegates_the_relay_define(self):
        candidate = self.source("tools/build_apple_release_candidates.sh")
        runtime = self.source("tools/apple_runtime_smoke.sh")
        self.assertNotIn(RELAY_PLATFORMS_DEFINE, candidate)
        self.assertIn("export WINS_APPLE_WINN3_RELEASE=1", candidate)
        arm = runtime[runtime.index("      ios|macos)\n"):]
        arm = arm[:arm.index("        ;;")]
        self.assertEqual(arm.count(self.RELAY_ARG), 1)
        self.assertIn(f"{self.RELAY_ARG}${{target_platform}}", arm)

    def test_apple_in_build_ring_gate_accepts_the_relay_define(self):
        import verify_apple_winn3_ring_build_defines as apple_gate

        for platform_name, token in (("iphoneos", "ios"), ("macosx", "macos")):
            with self.subTest(platform=platform_name):
                entries = {
                    f"WINS_WINN3_DESCRIPTOR_PUBKEY_{slot.upper()}": value
                    for slot, value in EXPECTED_RING.items()
                }
                entries[RING_SHA256_DEFINE] = WIRE_FORM_RING_SHA256
                entries[ENABLED_PLATFORMS_DEFINE] = token
                entries[RELAY_PLATFORMS_DEFINE] = token
                raw = ",".join(
                    base64.b64encode(f"{name}={value}".encode("utf-8")).decode("ascii")
                    for name, value in entries.items()
                )
                result = apple_gate.check(apple_gate.decode_dart_defines(raw), platform_name)
                self.assertIn("PASS", result)

    def test_windows_installer_passes_the_relay_define_once_for_x64_and_arm64(self):
        source = self.source("installer/windows/build_installer.ps1")
        # Flutter has no target-platform override: this single command builds the
        # x64 release on an x64 host and the ARM64 release on a Windows-on-ARM host.
        self.assertEqual(source.count("& $script:FlutterCommand build windows"), 1)
        statement = _ps_statement(source, "& $script:FlutterCommand build windows")
        self.assertEqual(statement.count(self.RELAY_ARG), 1, statement)
        self.assertIn(f"'{self.RELAY_ARG}windows'", statement)
        self.assertIn(f"'--dart-define={ENABLED_PLATFORMS_DEFINE}=windows'", statement)
        self.assertIn("@winn3PubkeyDefines", statement)
        self.assertEqual(source.count(self.RELAY_ARG), 1)
        self.assertIn("arm64", source.lower())

    def test_windows_store_msix_is_not_a_shipped_target_and_stays_without_relay(self):
        readme = self.source("app_store/windows/README.md")
        self.assertIn("Production MSIX packaging stays fail-closed", readme)
        msix = self.source("installer/windows/build_store_msix.ps1")
        self.assertNotIn(RELAY_PLATFORMS_DEFINE, msix)
        self.assertIn(f"--dart-define={ENABLED_PLATFORMS_DEFINE}=windows", msix)

    def test_other_windows_packagers_do_not_build_flutter_or_own_the_define(self):
        for relative in (
            "installer/windows/build_zip_installer.ps1",
            "installer/windows/build_winn3_msi.ps1",
            "installer/windows/build_winn3_msi_arm64.ps1",
        ):
            source = self.source(relative)
            self.assertNotIn(RELAY_PLATFORMS_DEFINE, source, relative)
            self.assertNotRegex(source, r"build\s+windows\s+--release", relative)

    @unittest.skipUnless(shutil.which("pwsh"), "pwsh is required for the PowerShell parse check")
    def test_edited_powershell_producers_parse(self):
        script = (
            "$errors = $null; $tokens = $null; "
            "[void][System.Management.Automation.Language.Parser]::ParseFile("
            "$env:WINS_PARSE_TARGET, [ref]$tokens, [ref]$errors); "
            "if ($errors.Count -gt 0) { $errors | ForEach-Object { $_.ToString() }; exit 1 }"
        )
        for relative in (
            "installer/windows/build_installer.ps1",
            "tools/build_android_release.ps1",
        ):
            with self.subTest(script=relative):
                completed = subprocess.run(
                    [shutil.which("pwsh"), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                    env={**os.environ, "WINS_PARSE_TARGET": str(ROOT / relative)},
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_linux_release_has_one_producer_owned_relay_define_for_x64_and_arm64(self):
        source = self.source("tools/build_linux_release.sh")
        self.assertEqual(source.count(self.RELAY_ARG), 1)
        self.assertIn(
            f'LINUX_WINN3_RELAY_ENABLED_PLATFORMS_DEFINE_ARG="{self.RELAY_ARG}linux"',
            source,
        )
        # One flutter command serves both architectures; the arch label only picks paths.
        self.assertEqual(source.count('"${FLUTTER_COMMAND}" build linux --release'), 1)
        self.assertIn("LINUX_RELEASE_ARCH_LABEL", source)

    def test_local_suite_exercises_each_relay_shipping_define(self):
        dart = self.source("test/winn3_relay_shipping_define_test.dart")
        self.assertIn("WINS_TEST_EXPECTED_WINN3_PLATFORM", dart)
        self.assertIn(RELAY_PLATFORMS_DEFINE, dart)
        self.assertIn("winnClientAdvertisesRelay", dart)


class Winn3DualAuthReleaseEnablementTest(unittest.TestCase):
    """Release-only WINS_WINN3_DUAL_AUTH injection, fail-closed where blocked.

    Windows and Linux native parsers consume auth_ed25519 / auth_mldsa65 and
    bind both paths into the engine document. Apple's parser reads the pair
    then refuses start: cdatapath winn3Config has no DualAuth fields and
    decodes with DisallowUnknownFields. iOS and macOS stay BLOCKED.
    """

    def source(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def _assert_dual_auth_true_once(self, entries: list[str], label: str) -> None:
        dual = _dual_auth_true_entries(entries)
        self.assertEqual(
            dual,
            [DUAL_AUTH_TRUE],
            f"{label} must emit {DUAL_AUTH_TRUE} exactly once, got {dual!r}",
        )
        self.assertNotIn(DUAL_AUTH_FALSE, entries, label)

    def _assert_no_dual_auth_define(self, entries: list[str], label: str) -> None:
        dual = _dual_auth_true_entries(entries)
        self.assertEqual(
            dual,
            [],
            f"{label} must not compile {DUAL_AUTH_DEFINE}, got {dual!r}",
        )

    def test_dual_auth_true_blob_matches_android_c8_encoding(self):
        self.assertEqual(DUAL_AUTH_TRUE_BLOB, ANDROID_DUAL_AUTH_TRUE_BLOB)
        gradle = self.source("android/app/build.gradle.kts")
        self.assertIn(DUAL_AUTH_TRUE_BLOB, gradle)
        self.assertEqual(
            gradle.count(DUAL_AUTH_TRUE_BLOB),
            1,
            "Android must keep the dual-auth true blob unique",
        )

    def test_windows_release_enabled_blob_emits_dual_auth_true_once(self):
        cmake = self.source("windows/flutter/Winn3DescriptorRing.cmake")
        enabled_sets = _cmake_quoted_sets(cmake, "WINN3_WINDOWS_ENABLED_BLOB")
        self.assertEqual(len(enabled_sets), 1, enabled_sets)
        entries = _winn3_define_entries_from_csv(enabled_sets[0])
        self.assertEqual(
            [entry for entry in entries if entry.startswith(f"{ENABLED_PLATFORMS_DEFINE}=")],
            [f"{ENABLED_PLATFORMS_DEFINE}=windows"],
        )
        self._assert_dual_auth_true_once(entries, "windows Release WINN3_WINDOWS_ENABLED_BLOB")
        backend = self.source("windows/flutter/winn3_tool_backend.cmd")
        self.assertIn("WINN3_WINDOWS_ENABLED_BLOB", backend)
        self.assertRegex(
            backend,
            r'if /I "%~2"=="Release"',
            "dual-auth rides the Release-only ENABLED_BLOB append",
        )
        self.assertNotIn(DUAL_AUTH_TRUE_BLOB, backend)

    def test_windows_debug_ring_cannot_advertise_dual_auth(self):
        cmake = self.source("windows/flutter/Winn3DescriptorRing.cmake")
        ring_sets = _cmake_quoted_sets(cmake, "WINN3_RING_DART_DEFINES")
        self.assertEqual(len(ring_sets), 1, ring_sets)
        entries = _winn3_define_entries_from_csv(ring_sets[0])
        self._assert_no_dual_auth_define(
            entries, "windows WINN3_RING_DART_DEFINES (Debug/Profile)"
        )
        self.assertNotIn(DUAL_AUTH_TRUE_BLOB, ring_sets[0])
        self.assertNotIn(DUAL_AUTH_FALSE_BLOB, cmake)
        backend = self.source("windows/flutter/winn3_tool_backend.cmd")
        self.assertNotIn(DUAL_AUTH_TRUE_BLOB, backend)
        self.assertNotIn(DUAL_AUTH_FALSE_BLOB, backend)

    def test_linux_release_producer_owns_dual_auth_true_once(self):
        cmake = self.source("linux/flutter/Winn3DescriptorRing.cmake")
        self.assertNotIn(DUAL_AUTH_DEFINE, cmake)
        self.assertNotIn(DUAL_AUTH_TRUE_BLOB, cmake)
        backend = self.source("linux/flutter/winn3_tool_backend.sh")
        self.assertNotIn(DUAL_AUTH_TRUE_BLOB, backend)
        producer = self.source("tools/build_linux_release.sh")
        self.assertEqual(
            producer.count('WINN3_DUAL_AUTH_DEFINE_ARG="--dart-define=${WINN3_DUAL_AUTH_DEFINE_NAME}=true"'),
            1,
        )
        self.assertIn(
            'WINN3_DUAL_AUTH_RELEASE_DEFINES=("${WINN3_DUAL_AUTH_DEFINE_ARG}")',
            producer,
        )
        self.assertIn(
            'assert_linux_winn3_dual_auth_define_argv '
            '"${WINN3_DUAL_AUTH_RELEASE_DEFINES[@]}"',
            producer,
        )

    def test_linux_unconditional_ring_cannot_advertise_dual_auth(self):
        cmake = self.source("linux/flutter/Winn3DescriptorRing.cmake")
        ring_sets = _cmake_quoted_sets(cmake, "WINN3_RING_DART_DEFINES")
        self.assertGreaterEqual(len(ring_sets), 1, ring_sets)
        unconditional = ring_sets[0]
        self.assertNotIn("${", unconditional)
        entries = _winn3_define_entries_from_csv(unconditional)
        self._assert_no_dual_auth_define(
            entries, "linux unconditional WINN3_RING_DART_DEFINES (Debug/Profile)"
        )
        self.assertEqual(
            [entry for entry in entries if entry.startswith(f"{ENABLED_PLATFORMS_DEFINE}=")],
            [f"{ENABLED_PLATFORMS_DEFINE}=linux"],
        )
        self.assertNotIn(DUAL_AUTH_FALSE_BLOB, cmake)
        self.assertNotRegex(
            cmake,
            r'if\s*\(\s*CMAKE_BUILD_TYPE\s+STREQUAL\s+"(Debug|Profile)"\s*\)',
            "Debug/Profile must not grow a dual-auth append",
        )

    def test_apple_release_xcconfigs_stay_fail_closed_blocked(self):
        for relative, platform in (
            ("ios/Flutter/Winn3DescriptorRing.xcconfig", "ios"),
            ("macos/Flutter/Winn3DescriptorRing.xcconfig", "macos"),
        ):
            source = self.source(relative)
            decoded = _winn3_defines_from_source(source)
            self.assertEqual(
                decoded.get(ENABLED_PLATFORMS_DEFINE),
                platform,
                relative,
            )
            self.assertNotIn(
                DUAL_AUTH_DEFINE,
                decoded,
                f"{relative} is BLOCKED: Apple cdatapath cannot ingest DualAuth",
            )
            self.assertNotIn(DUAL_AUTH_TRUE_BLOB, source, relative)
            self.assertNotIn(DUAL_AUTH_FALSE_BLOB, source, relative)
            dart_defines_lines = [
                line for line in source.splitlines() if line.startswith("DART_DEFINES=")
            ]
            self.assertEqual(len(dart_defines_lines), 1, relative)
            entries = _winn3_define_entries_from_csv(
                dart_defines_lines[0].split("=", 1)[1]
            )
            self._assert_no_dual_auth_define(entries, relative)
            dual_mentions = [
                entry for entry in entries if "DUAL_AUTH" in entry
            ]
            self.assertEqual(dual_mentions, [], relative)

    def test_debug_xcconfigs_cannot_advertise_dual_auth(self):
        debug_files = (
            "ios/Flutter/Debug.xcconfig",
            "macos/Flutter/Flutter-Debug.xcconfig",
        )
        for relative in debug_files:
            source = self.source(relative)
            self.assertNotIn(
                "Winn3DescriptorRing.xcconfig",
                source,
                f"{relative} must not include the release ring",
            )
            self.assertNotIn(DUAL_AUTH_TRUE_BLOB, source, relative)
            self.assertNotIn(DUAL_AUTH_FALSE_BLOB, source, relative)
            decoded = _winn3_defines_from_source(source)
            self.assertNotIn(DUAL_AUTH_DEFINE, decoded, relative)
            self.assertNotIn(ENABLED_PLATFORMS_DEFINE, decoded, relative)

        profile = self.source("ios/Flutter/Profile.xcconfig")
        self.assertIn('#include "Winn3DescriptorRing.xcconfig"', profile)
        self.assertNotIn(DUAL_AUTH_TRUE_BLOB, profile)
        ring = self.source("ios/Flutter/Winn3DescriptorRing.xcconfig")
        self.assertNotIn(DUAL_AUTH_TRUE_BLOB, ring)


if __name__ == "__main__":
    unittest.main()
