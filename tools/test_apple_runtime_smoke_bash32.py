#!/usr/bin/env python3
"""macOS /bin/bash 3.2 runs the Apple smoke Flutter build define path."""

from __future__ import annotations

import base64
import hashlib
import pathlib
import subprocess
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SMOKE = ROOT / "tools" / "apple_runtime_smoke.sh"
SYSTEM_BASH = pathlib.Path("/bin/bash")
PUBKEY_G1 = base64.b64encode(bytes(range(32))).decode("ascii")
PUBKEY_G2 = base64.b64encode(bytes(range(32, 64))).decode("ascii")


def function(text: str, name: str) -> str:
    start = text.index("\n" + name + "() {\n") + 1
    return text[start:text.index("\n}\n", start) + 3]


def ring_identity(keys: dict[str, str]) -> str:
    canonical = b"".join(
        slot.encode("ascii") + b"=" + base64.b64decode(keys[slot]).hex().encode("ascii") + b"\n"
        for slot in ("g1", "g2", "g3")
        if slot in keys
    )
    return hashlib.sha256(canonical).hexdigest()


@unittest.skipUnless(SYSTEM_BASH.is_file(), "system /bin/bash is required")
class AppleRuntimeSmokeBash32Tests(unittest.TestCase):
    def setUp(self) -> None:
        version = subprocess.run(
            [str(SYSTEM_BASH), "-c", 'printf "%s" "${BASH_VERSINFO[0]}"'],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        self.bash_major = version

    def run_flutter_build(
        self, defines: list[str], **environment: str
    ) -> subprocess.CompletedProcess[str]:
        text = SMOKE.read_text(encoding="utf-8")
        harness = (
            "set -Eeuo pipefail\n"
            "STUB_DEFINES=(\"$@\")\n"
            "flutter_build_define_args() {\n"
            "  if [[ \"${#STUB_DEFINES[@]}\" -gt 0 ]]; then printf '%s\\n' \"${STUB_DEFINES[@]}\"; fi\n"
            "}\n"
            "run() { printf 'RUN:%s\\n' \"$@\"; }\n"
            + function(text, "log_winn3_descriptor_pubkey_status_for_defines")
            + function(text, "run_flutter_build")
            + 'run_flutter_build build ios --release\n'
        )
        env = {
            "PATH": "/usr/bin:/bin",
            "ROOT_DIR": str(ROOT),
            "PYTHON_BIN": sys.executable,
            "FLUTTER_BIN": "flutter-stub",
        }
        env.update(environment)
        return subprocess.run(
            [str(SYSTEM_BASH), "-c", harness, "harness", *defines],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_system_bash_parses_the_whole_smoke_script(self) -> None:
        completed = subprocess.run(
            [str(SYSTEM_BASH), "-n", str(SMOKE)], capture_output=True, text=True, check=False
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_ring_identity_path_has_no_bash4_syntax_or_unset_root(self) -> None:
        body = function(SMOKE.read_text(encoding="utf-8"), "run_flutter_build")
        self.assertNotIn(",,}", body)
        self.assertNotIn("^^}", body)
        self.assertNotIn("${ROOT}/", body)
        self.assertIn('"${ROOT_DIR}/tools/winn3_descriptor_ring_identity.py"', body)

    def test_release_ring_identity_matches_case_insensitively_under_bash32(self) -> None:
        keys = {"g1": PUBKEY_G1, "g2": PUBKEY_G2}
        expected = ring_identity(keys)
        defines = [
            f"--dart-define=WINS_WINN3_DESCRIPTOR_PUBKEY_G1={PUBKEY_G1}",
            f"--dart-define=WINS_WINN3_DESCRIPTOR_PUBKEY_G2={PUBKEY_G2}",
            "--dart-define=WINS_WINN3_ENABLED_PLATFORMS=ios",
            "--dart-define=WINS_APPLE_EXTERNAL_LEAK_AUDIT_URLS=https://a.example https://b.example",
        ]
        for supplied in (expected, expected.upper()):
            completed = self.run_flutter_build(
                defines,
                WINS_APPLE_WINN3_RELEASE="1",
                WINS_EXPECTED_WINN3_DESCRIPTOR_RING_SHA256=supplied,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            lines = completed.stdout.splitlines()
            self.assertIn("RUN:flutter-stub", lines)
            self.assertIn("RUN:ios", lines)
            self.assertIn(
                f"RUN:--dart-define=WINS_WINN3_DESCRIPTOR_RING_SHA256={expected}", lines
            )
            self.assertIn("RUN:--dart-define=WINS_WINN3_ENABLED_PLATFORMS=ios", lines)
            # A define containing a space stays one argument.
            self.assertIn(
                "RUN:--dart-define=WINS_APPLE_EXTERNAL_LEAK_AUDIT_URLS=https://a.example https://b.example",
                lines,
            )

    def test_release_ring_identity_mismatch_or_absence_refuses(self) -> None:
        defines = [f"--dart-define=WINS_WINN3_DESCRIPTOR_PUBKEY_G1={PUBKEY_G1}"]
        for supplied in ("", "0" * 64, ring_identity({"g1": PUBKEY_G1})[:-1]):
            completed = self.run_flutter_build(
                defines,
                WINS_APPLE_WINN3_RELEASE="1",
                WINS_EXPECTED_WINN3_DESCRIPTOR_RING_SHA256=supplied,
            )
            self.assertEqual(completed.returncode, 65, (supplied, completed.stderr))
            self.assertIn("Reviewed Winn3 descriptor ring identity mismatch", completed.stderr)
            self.assertNotIn("RUN:", completed.stdout)

    def test_no_defines_under_set_u_still_builds(self) -> None:
        completed = self.run_flutter_build([], WINS_APPLE_WINN3_RELEASE="0")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            completed.stdout.splitlines(),
            ["RUN:flutter-stub", "RUN:build", "RUN:ios", "RUN:--release"],
        )
        self.assertIn("ring ABSENT", completed.stderr)
        required = self.run_flutter_build(
            [], WINS_APPLE_WINN3_RELEASE="0", WINS_REQUIRE_WINN3_DESCRIPTOR_PUBKEY="1"
        )
        self.assertEqual(required.returncode, 65, required.stderr)
        self.assertNotIn("RUN:", required.stdout)

    def test_harness_really_is_bash_32(self) -> None:
        self.assertEqual(self.bash_major, "3")


if __name__ == "__main__":
    unittest.main()
