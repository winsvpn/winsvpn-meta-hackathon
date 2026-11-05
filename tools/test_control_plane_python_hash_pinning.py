#!/usr/bin/env python3
"""Regression contracts for the control-plane's hash-pinned Python deps.

M-3: server/control-plane-requirements.lock must be a *complete*
`pip-compile --generate-hashes` lock (every direct and transitive dependency
carries at least one --hash=sha256:... entry), server/control-plane-requirements.in
is its source of truth, and setup_python() in
server/wins_control_plane_setup_ONETOUCH.sh must embed that exact lock
content and install it with `pip install --require-hashes --only-binary=:all:`
-- with no separate, unpinned `pip install --upgrade pip wheel` step that
would reopen the same dependency-substitution gap --require-hashes closes
for every other package.

These tests check the source-level contract (heredoc/lock drift, presence of
--require-hashes, absence of the unpinned upgrade step, every requirement
block actually carrying a hash) and, using a hand-built local wheel served
via --no-index --find-links (no network, no PyPI, no Docker), that pip's
--require-hashes mode really does enforce hash correctness end to end: a
correct hash installs, a corrupted one fails closed. The real
control-plane-requirements.lock was separately validated once, end-to-end,
with --require-hashes --only-binary=:all: inside a container matching the
reviewed Ubuntu 24.04/py3.12/amd64 production target (including a live
tamper/corruption check against the real fastapi wheel hash); that manual
proof is what justifies trusting the *actual* lock file's content, while
this suite guards the mechanism and the contract going forward without
depending on network access.
"""

from __future__ import annotations

import hashlib
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SETUP_SCRIPT_PATH = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"
LOCK_PATH = ROOT / "server" / "control-plane-requirements.lock"
IN_PATH = ROOT / "server" / "control-plane-requirements.in"

SETUP_SCRIPT = SETUP_SCRIPT_PATH.read_text(encoding="utf-8")
LOCK_CONTENT = LOCK_PATH.read_text(encoding="utf-8")
IN_CONTENT = IN_PATH.read_text(encoding="utf-8")

PIN_RE = r"[A-Za-z0-9_.\-]+(?:\[[A-Za-z0-9_,\-]+\])?==[A-Za-z0-9_.\-]+"


def _setup_python_body() -> str:
    match = re.search(r"\nsetup_python\(\) \{\n(.*?)\n\}\n", SETUP_SCRIPT, re.DOTALL)
    assert match, "could not find setup_python() in the control-plane setup script"
    return match.group(1)


def _embedded_lock_heredoc() -> str:
    match = re.search(r"<<'REQLOCKEOF'\n(.*?)\nREQLOCKEOF\n", SETUP_PYTHON, re.DOTALL)
    assert match, "could not find the embedded control-plane-requirements.lock heredoc"
    return match.group(1) + "\n"


SETUP_PYTHON = _setup_python_body()


class SourceContractTests(unittest.TestCase):
    def test_embedded_lock_matches_source_repo_lock_file_byte_for_byte(self) -> None:
        self.assertEqual(
            _embedded_lock_heredoc(),
            LOCK_CONTENT,
            "setup_python()'s embedded control-plane-requirements.lock heredoc has "
            "drifted from server/control-plane-requirements.lock -- regenerate the "
            "heredoc from the source-repo lock file instead of hand-editing either.",
        )

    def test_install_uses_require_hashes_and_binary_only(self) -> None:
        self.assertIn(
            '"${VENV_DIR}/bin/python" -I -m pip install --require-hashes --only-binary=:all: '
            '-r "${requirements_lock}"',
            SETUP_PYTHON,
        )

    def test_no_unpinned_pip_or_wheel_upgrade_step(self) -> None:
        for banned in (
            "pip install --upgrade pip",
            "pip install --upgrade wheel",
            "pip install -U pip",
            "pip install -U wheel",
        ):
            self.assertNotIn(
                banned,
                SETUP_PYTHON,
                f"setup_python() must not run an unpinned/unverified {banned!r} -- "
                "it would bypass --require-hashes for pip/wheel themselves.",
            )

    def test_lock_file_top_level_pins_match_the_in_file(self) -> None:
        in_pins = re.findall(rf"^({PIN_RE})$", IN_CONTENT, re.MULTILINE)
        self.assertGreaterEqual(
            len(in_pins), 6, "expected at least the 6 direct control-plane dependencies"
        )
        for pin in in_pins:
            self.assertIn(
                pin + " \\",
                LOCK_CONTENT,
                f"top-level pin {pin!r} from control-plane-requirements.in is missing "
                "(or unhashed/unpinned) in control-plane-requirements.lock -- "
                "regenerate the lock with pip-compile --generate-hashes.",
            )

    def test_lock_file_is_fully_hash_pinned(self) -> None:
        """Every requirement block must carry >=1 well-formed sha256 hash.

        --require-hashes itself fails closed on a *missing* hash line (pip's
        resolver simply refuses to run at all in that mode), but a
        malformed hash entry, or a requirement that silently lost its only
        hash line during a hand-edit, deserves a clear failure message
        here rather than surfacing only as an opaque pip resolver error.
        """
        hash_re = re.compile(r"--hash=sha256:[0-9a-f]{64}\b")
        lines = LOCK_CONTENT.splitlines()
        checked = 0
        index = 0
        while index < len(lines):
            if not re.match(rf"^{PIN_RE}", lines[index]):
                index += 1
                continue
            block = [lines[index]]
            index += 1
            while index < len(lines) and lines[index][:1] in (" ", "\t"):
                block.append(lines[index])
                if not lines[index].rstrip().endswith("\\"):
                    index += 1
                    break
                index += 1
            block_text = "\n".join(block)
            self.assertRegex(
                block_text,
                hash_re,
                f"requirement block has no valid --hash=sha256:<64 hex> entry: {block[0]!r}",
            )
            checked += 1
        self.assertGreaterEqual(
            checked, 6, "expected at least the 6 direct control-plane dependencies"
        )

    def test_lock_file_documents_its_own_regeneration_command(self) -> None:
        self.assertIn("pip-compile", LOCK_CONTENT)
        self.assertIn("--generate-hashes", LOCK_CONTENT)


class OfflineRequireHashesMechanismTests(unittest.TestCase):
    """Prove the exact `pip install --require-hashes --only-binary=:all:`
    mode setup_python() now uses really does fail closed on a wrong hash and
    succeed on a correct one -- hermetically, via a hand-built local wheel
    served through --no-index --find-links, with no network or Docker
    dependency. This exercises the *mechanism*, not the real control-plane
    dependency set (see the module docstring for how that was validated).
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp_path = pathlib.Path(self._tmp.name)
        self.wheel_dir = self.tmp_path / "wheelhouse"
        self.wheel_dir.mkdir()
        self.wheel_path = self._build_minimal_wheel(self.wheel_dir)
        self.real_hash = hashlib.sha256(self.wheel_path.read_bytes()).hexdigest()

    @staticmethod
    def _build_minimal_wheel(directory: pathlib.Path) -> pathlib.Path:
        name, version = "winsvpntestpkg", "0.0.1"
        wheel_path = directory / f"{name}-{version}-py3-none-any.whl"
        dist_info = f"{name}-{version}.dist-info"
        with zipfile.ZipFile(wheel_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f"{name}/__init__.py", "VALUE = 1\n")
            zf.writestr(
                f"{dist_info}/METADATA",
                f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
            )
            zf.writestr(
                f"{dist_info}/WHEEL",
                "Wheel-Version: 1.0\nGenerator: winsvpn-test\n"
                "Root-Is-Purelib: true\nTag: py3-none-any\n",
            )
            zf.writestr(f"{dist_info}/RECORD", "")
        return wheel_path

    def _pip_install(self, req_hash: str) -> subprocess.CompletedProcess:
        req_file = self.tmp_path / "req.txt"
        req_file.write_text(
            f"winsvpntestpkg==0.0.1 \\\n    --hash=sha256:{req_hash}\n",
            encoding="utf-8",
        )
        install_dir = self.tmp_path / f"install_{req_hash[:8]}"
        install_dir.mkdir(exist_ok=True)
        return subprocess.run(
            [
                sys.executable, "-m", "pip", "install",
                "--require-hashes",
                "--no-index",
                f"--find-links={self.wheel_dir}",
                f"--target={install_dir}",
                "-r", str(req_file),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_require_hashes_accepts_a_correct_hash(self) -> None:
        result = self._pip_install(self.real_hash)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_require_hashes_rejects_a_corrupted_hash(self) -> None:
        wrong_hash = "0" * 64
        self.assertNotEqual(wrong_hash, self.real_hash)
        result = self._pip_install(wrong_hash)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DO NOT MATCH THE HASHES", result.stderr.upper())

    def test_require_hashes_rejects_a_missing_hash_entirely(self) -> None:
        req_file = self.tmp_path / "req_nohash.txt"
        req_file.write_text("winsvpntestpkg==0.0.1\n", encoding="utf-8")
        install_dir = self.tmp_path / "install_nohash"
        install_dir.mkdir(exist_ok=True)
        result = subprocess.run(
            [
                sys.executable, "-m", "pip", "install",
                "--require-hashes",
                "--no-index",
                f"--find-links={self.wheel_dir}",
                f"--target={install_dir}",
                "-r", str(req_file),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HASH", result.stderr.upper())


if __name__ == "__main__":
    unittest.main()
