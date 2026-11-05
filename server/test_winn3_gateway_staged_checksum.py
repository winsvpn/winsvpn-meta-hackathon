import hashlib
import os
from pathlib import Path
from winn3_gateway_test_support import gateway_source
import subprocess
import tempfile
import unittest

INSTALLER = Path(__file__).with_name("wins_data_plane_setup_ONETOUCH.sh")
INSTALLER = gateway_source(INSTALLER, legacy=False)
HARNESS = r"""
set -euo pipefail
source "$1"
staged_gateway_sha256 "$2" "$3"
"""
VERIFY = r"""
set -euo pipefail
source "$1"
uname() { printf '%s\n' x86_64; }
file() { printf '%s\n' unexpected-file-command >&2; return 97; }
sha256sum() { printf '%s\n' unexpected-checksum-command >&2; return 97; }
WINN3_GATEWAY_STAGING_DIR="$2"
WINN3_GATEWAY_BIN_NAME=fixture-gateway
verify_staged_binary
"""


class StagedChecksumTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="checksum-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.artifact = self.root / "fixture-gateway"
        self.artifact.write_bytes(b"ordinary inert artifact fixture\n")
        self.sidecar = self.root / "fixture-gateway.sha256"
        self.digest = hashlib.sha256(self.artifact.read_bytes()).hexdigest()

    def invoke(self, data, harness=HARNESS):
        self.sidecar.write_bytes(data)
        args = [str(self.artifact), str(self.sidecar)] if harness == HARNESS else [str(self.root)]
        return subprocess.run(["/bin/bash", "-c", harness, "fixture", str(INSTALLER), *args],
                              env={"PATH": os.environ["PATH"], "LC_ALL": "C"},
                              capture_output=True, timeout=5)

    def record(self, name=None, mode=" ", ending="\n", digest=None):
        return ((digest or self.digest) + " " + mode +
                (name or self.artifact.name) + ending).encode()

    def test_supported_single_record_forms(self):
        for name in [self.artifact.name, "./" + self.artifact.name, str(self.artifact)]:
            for mode in [" ", "*"]:
                for ending in ["\n", "\r\n", ""]:
                    with self.subTest(name=name, mode=mode, ending=repr(ending)):
                        result = self.invoke(self.record(name, mode, ending, self.digest.upper()))
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stdout, (self.digest + "\n").encode())
                        self.assertEqual(result.stderr, b"")

    def test_record_shape_and_identity_validation(self):
        for raw in [b"", self.record("other-artifact"), self.record() + self.record(),
                    self.record(digest="0" * 64), self.record(mode="?"),
                    self.record() + b"\n", b" " * 4097,
                    b"SHA256 (fixture-gateway) = " + self.digest.encode() + b"\n"]:
            with self.subTest(size=len(raw)):
                result = self.invoke(raw)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
                self.assertNotIn(b"Traceback", result.stderr)

    def test_file_with_ordinary_spaces(self):
        renamed = self.root / "fixture gateway"
        self.artifact.rename(renamed)
        self.artifact = renamed
        result = self.invoke(self.record())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, (self.digest + "\n").encode())

    def test_empty_or_missing_artifact(self):
        self.artifact.write_bytes(b"")
        result = self.invoke(self.record())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.artifact.unlink()
        result = self.invoke(self.record())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_verifier_uses_bound_digest_for_success_log(self):
        # The architecture check reads the ELF header with od (design v17 2.2
        # item 7), so this fixture starts with an ELF64 x86-64 header.
        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        header[4], header[5], header[6] = 2, 1, 1
        header[18:20] = (0x3E).to_bytes(2, "little")
        self.artifact.write_bytes(bytes(header) + b"ordinary inert artifact fixture\n")
        self.digest = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        result = self.invoke(self.record(), VERIFY)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(self.digest[:16].encode(), result.stdout + result.stderr)
        self.assertNotIn(b"unexpected-checksum-command", result.stdout + result.stderr)
        self.assertNotIn(b"unexpected-file-command", result.stdout + result.stderr)
        self.assertIn(b"(x86_64)", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
