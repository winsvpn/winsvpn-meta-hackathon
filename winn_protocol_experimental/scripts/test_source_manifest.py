import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("source_manifest.sh")


class SourceManifestFailureTests(unittest.TestCase):
    def check_manifest(self, mode):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            module = root / "module"
            module.mkdir()
            (module / "go.mod").write_text("module example.invalid/audit\n")
            (module / "main.go").write_text("package main\nfunc main() {}\n")
            output = root / "manifest.sha256"
            output.write_text("previous verified manifest\n")
            fake_go = root / "go-fixture"
            fake_go.write_text(
                '#!/bin/sh\n'
                'if [ "$1" = env ]; then\n'
                '  printf "%s/go.mod\\n" "$MANIFEST_TEST_MODULE"\n'
                '  exit 0\n'
                'fi\n'
                'if [ "$MANIFEST_TEST_MODE" != empty_failure ]; then\n'
                '  printf "%s/main.go\\n" "$MANIFEST_TEST_MODULE"\n'
                'fi\n'
                'if [ "$MANIFEST_TEST_MODE" != success ]; then\n'
                '  echo "fixture: dependency discovery failed" >&2\n'
                '  exit 17\n'
                'fi\n'
            )
            fake_go.chmod(0o700)
            env = dict(os.environ, GO_BIN=str(fake_go), TMPDIR=str(root),
                       MANIFEST_TEST_MODULE=str(module), MANIFEST_TEST_MODE=mode)
            result = subprocess.run(
                ["sh", str(SCRIPT.resolve()), "./cmd/example", str(output)],
                cwd=module, env=env, capture_output=True, text=True, timeout=10,
            )
            if mode != "success":
                self.assertNotEqual(result.returncode, 0,
                                    "dependency failure was reported as success")
                self.assertEqual(output.read_text(), "previous verified manifest\n")
                self.assertEqual(result.stdout, "")
                self.assertIn("dependency discovery failed", result.stderr)
            else:
                self.assertEqual(result.returncode, 0, result.stderr)
                expected = "".join(
                    f"{hashlib.sha256((module / name).read_bytes()).hexdigest()}  {name}\n"
                    for name in ("go.mod", "main.go")
                )
                self.assertEqual(output.read_text(), expected)
                self.assertEqual(result.stdout.strip(),
                                 hashlib.sha256(expected.encode()).hexdigest())

    def test_empty_dependency_failure_preserves_manifest(self):
        self.check_manifest("empty_failure")

    def test_partial_dependency_failure_preserves_manifest(self):
        self.check_manifest("partial_failure")

    def test_success_commits_complete_manifest(self):
        self.check_manifest("success")


if __name__ == "__main__":
    unittest.main()
