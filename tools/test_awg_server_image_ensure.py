#!/usr/bin/env python3
"""Exercise image producer mode control flow without Docker or network access."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


BUILDER = Path(__file__).resolve().parents[1] / "server/build_amneziawg_go_server_image.sh"


class AwgServerImageEnsureTests(unittest.TestCase):
    def probe(self, stage: str, mode: str = "--ensure") -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "-c", r'''
source "$1"
require_linux_host() { :; }
require_commands() { :; }
host_arch() { printf 'amd64\n'; }
docker() {
  [[ "$2" == "inspect" && "$AUDIT_STAGE" != "missing-image" ]] || return 1
  printf 'sha256:fixture\n'
}
if [[ "$2" != "missing-image" ]]; then
  verify_image_labels() { return 0; }
fi
verify_image_runtime() { [[ "$AUDIT_STAGE" != "runtime-mismatch" ]]; }
runtime_hash() { printf 'fixture-hash\n'; }
verify_receipt() { [[ "$AUDIT_STAGE" != "missing-receipt" ]]; }
build_image() { printf 'BUILD_CALLED\n'; }
AUDIT_STAGE="$2"
main "$3"
''', "probe", str(BUILDER), stage, mode],
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_ensure_rebuilds_on_each_verification_failure(self) -> None:
        for stage in ("missing-image", "runtime-mismatch", "missing-receipt"):
            with self.subTest(stage=stage):
                result = self.probe(stage)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "BUILD_CALLED\n")

    def test_ensure_keeps_a_verified_image(self) -> None:
        result = self.probe("valid")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "amneziavpn/amneziawg-go:v3.1.20260828\n")
        self.assertNotIn("BUILD_CALLED", result.stdout)

    def test_verify_still_fails_without_building(self) -> None:
        result = self.probe("missing-image", "--verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("BUILD_CALLED", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
