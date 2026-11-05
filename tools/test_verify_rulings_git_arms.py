#!/usr/bin/env python3
"""The ReleasePython v2 arms of verify_rulings.sh must fail closed on git errors.

Both arms read git's index. They used to discard git's status, so outside a
work tree (an exported tree or an audit snapshot) `git grep` failed, `git
ls-files` printed nothing, and both arms printed "ok" without looking. Each
case runs the verifier's own block against a stub `git` on PATH; the real git
is never invoked.

Run: python3 tools/test_verify_rulings_git_arms.py
"""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "tools/verify_rulings.sh").read_text(encoding="utf-8")
BLOCK = SOURCE[SOURCE.index("releasepython_v2_failed=0\n"):SOURCE.index('\nif [ "$failed" -gt 0 ]; then')]

STUB_GIT = r"""#!/usr/bin/env bash
[[ "$1" == -C ]] && shift 2
case "$1" in
  rev-parse)
    if [[ "${STUB_WORKTREE}" == 1 ]]; then echo true; exit 0; fi
    echo "fatal: not a git repository (or any of the parent directories): .git" >&2
    exit 128
    ;;
  grep) exit "${STUB_GREP_RC}" ;;
  ls-files)
    [[ "${STUB_LS_RC}" == 0 ]] || { echo "fatal: ls-files failed" >&2; exit "${STUB_LS_RC}"; }
    printf '%s' "${STUB_LS_OUT}"
    ;;
  *) echo "unexpected git call: $*" >&2; exit 99 ;;
esac
"""


class ReleasePythonGitArmTests(unittest.TestCase):
    def run_block(self, worktree="1", grep_rc="1", ls_rc="0", ls_out="lib/main.dart\ntools/verify_rulings.sh\n"):
        with tempfile.TemporaryDirectory(prefix="winsvpn-rulings-git-") as directory:
            stub_dir = Path(directory) / "bin"
            stub_dir.mkdir()
            stub = stub_dir / "git"
            stub.write_text(STUB_GIT, encoding="utf-8")
            stub.chmod(0o700)
            env = dict(
                os.environ,
                PATH=f"{stub_dir}:{os.environ['PATH']}",
                STUB_WORKTREE=worktree,
                STUB_GREP_RC=grep_rc,
                STUB_LS_RC=ls_rc,
                STUB_LS_OUT=ls_out,
            )
            script = 'set -u\nset -o pipefail\nROOT="$1"\n' + BLOCK + "\nexit 0\n"
            return subprocess.run(["bash", "-c", script, "verify-rulings-block", directory],
                                  capture_output=True, text=True, env=env, timeout=20)

    def test_clean_work_tree_passes_both_arms(self):
        result = self.run_block()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ok   no tracked content contains a v2 updater path", result.stdout)
        self.assertIn("ok   no tracked v2 updater tool pathname exists", result.stdout)

    def test_outside_a_work_tree_fails_instead_of_printing_ok(self):
        result = self.run_block(worktree="0", grep_rc="128", ls_rc="128")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("is not a git work tree", result.stdout)
        self.assertNotIn("RULINGS(releasepython): ok", result.stdout)

    def test_git_grep_error_is_a_failure_not_an_absence(self):
        result = self.run_block(grep_rc="2")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("FAIL git grep exited 2", result.stdout)

    def test_git_ls_files_error_is_a_failure_not_an_empty_index(self):
        result = self.run_block(ls_rc="128")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("FAIL git ls-files failed", result.stdout)

    def test_forbidden_content_and_pathname_are_still_refused(self):
        content = self.run_block(grep_rc="0")
        self.assertEqual(content.returncode, 1, content.stdout + content.stderr)
        self.assertIn("FAIL tracked content contains forbidden v2 updater path", content.stdout)
        pathname = self.run_block(ls_out="tools/releasepython_v2_owner_updater.py\n")
        self.assertEqual(pathname.returncode, 1, pathname.stdout + pathname.stderr)
        self.assertIn("FAIL tracked v2 updater tool pathname exists", pathname.stdout)


if __name__ == "__main__":
    unittest.main()
