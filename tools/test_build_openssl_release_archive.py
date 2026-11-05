#!/usr/bin/env python3
"""Hostile fail-closed tests for tools/build_openssl_release_archive.sh."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools" / "build_openssl_release_archive.sh"
CUSTODY = ROOT / "tools" / "release_openssl_archive_custody.py"
PIN_MANIFEST = ROOT / "tools" / "toolchain-pins.json"
SOURCE = SCRIPT.read_text(encoding="utf-8")
CUSTODY_SOURCE = CUSTODY.read_text(encoding="utf-8")
OFFICIAL_SOURCE_SHA256 = "736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8"
OFFICIAL_SOURCE_NAME = "openssl-4.0.2.tar.gz"
OFFICIAL_ARCHIVE_NAME = "wins-openssl-4.0.2-darwin-arm64.zip"
OFFICIAL_SOURCE_PATH = f"/Users/owner/Downloads/{OFFICIAL_SOURCE_NAME}"
OFFICIAL_OUTPUT_PATH = f"/Users/owner/Downloads/{OFFICIAL_ARCHIVE_NAME}"
PRESERVED_401_SOURCE = "/Users/owner/Downloads/openssl-4.0.1.tar.gz"
PRESERVED_401_ZIP = "/Users/owner/Downloads/wins-openssl-4.0.1-darwin-arm64.zip"


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="ascii")
    path.chmod(0o755)


def _write_path_trap(path: Path, marker: Path) -> None:
    _write_executable(
        path,
        "#!/bin/sh\n"
        f"printf 'invoked argv:%s\\n' \"$*\" >{shlex.quote(str(marker))}\n"
        "exit 0\n",
    )


def _run_producer(
    tmp: Path,
    *,
    env_updates: dict[str, str] | None = None,
    extra_path: Path | None = None,
    unset: tuple[str, ...] = (),
) -> subprocess.CompletedProcess[str]:
    home = tmp / "home"
    work_tmp = tmp / "tmp"
    home.mkdir(exist_ok=True)
    work_tmp.mkdir(exist_ok=True)
    path = "/usr/bin:/bin:/usr/sbin:/sbin"
    if extra_path is not None:
        path = f"{extra_path}:{path}"
    env = {
        "HOME": str(home),
        "TMPDIR": str(work_tmp),
        "PATH": path,
        "LC_ALL": "C",
        "LANG": "C",
    }
    if env_updates:
        env.update(env_updates)
    for name in unset:
        env.pop(name, None)
    return subprocess.run(
        ["/bin/bash", str(SCRIPT)],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


class BuildOpensslReleaseArchiveTests(unittest.TestCase):
    def test_shell_syntax(self) -> None:
        completed = subprocess.run(
            ["/bin/bash", "-n", str(SCRIPT)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_ascii_and_fail_closed_source_contract(self) -> None:
        self.assertTrue(SOURCE.isascii())
        self.assertTrue(CUSTODY_SOURCE.isascii())
        self.assertIn("darwin64-arm64-cc no-shared no-tests no-docs", SOURCE)
        self.assertIn(OFFICIAL_SOURCE_SHA256, SOURCE)
        self.assertIn("openssl-4.0.2", SOURCE)
        self.assertIn("https://www.openssl.org/source/openssl-4.0.2.tar.gz", SOURCE)
        self.assertNotIn("github.com", SOURCE)
        self.assertNotIn("sudo", SOURCE)
        self.assertNotIn("/Library", SOURCE)
        self.assertNotIn("WINS_OPENSSL_BUILD_RECEIPT", SOURCE)
        self.assertIn('authenticated": False', SOURCE)
        self.assertIn("candidate-producer", SOURCE)
        self.assertIn("never writes an owner build receipt", SOURCE.lower())
        self.assertIn("never overwrites", SOURCE.lower())
        self.assertIn("O_NOFOLLOW", SOURCE)
        self.assertIn("fstat", SOURCE)
        self.assertIn("SOURCE_DATE_EPOCH=1787658262", SOURCE)
        self.assertIn("ZERO_AR_DATE=1", SOURCE)
        self.assertIn("/usr/bin/env -i", SOURCE)
        self.assertIn('FIRST_OUT="$(build_one "$STAGE")"', SOURCE)
        self.assertIn('SECOND_OUT="$(build_one "$STAGE")"', SOURCE)
        self.assertIn("/bin/rm -rf -- \"$STAGE\"", SOURCE)
        self.assertIn("identity-proven rebuild mismatch", SOURCE)
        self.assertIn("O_EXCL", SOURCE)
        self.assertIn("no-shared no-tests no-docs", SOURCE)
        self.assertNotIn("command -v clang", SOURCE)
        self.assertNotIn("command -v openssl", SOURCE)
        self.assertNotIn("brew ", SOURCE)
        self.assertIn("was replaced after it was opened", SOURCE)
        self.assertIn("O_NOFOLLOW", CUSTODY_SOURCE)

    def test_constants_match_adopted_custody_and_preserve_401_outputs(self) -> None:
        self.assertIn('OFFICIAL_VERSION = "4.0.2"', CUSTODY_SOURCE)
        self.assertIn(OFFICIAL_SOURCE_SHA256, CUSTODY_SOURCE)
        self.assertIn(OFFICIAL_ARCHIVE_NAME, CUSTODY_SOURCE)
        self.assertIn(OFFICIAL_SOURCE_NAME, CUSTODY_SOURCE)
        pins = json.loads(PIN_MANIFEST.read_text(encoding="utf-8"))
        live = pins["tools"]["openssl"]
        self.assertEqual(live["version"], "4.0.2")
        self.assertEqual(live["source_archive_name"], OFFICIAL_SOURCE_NAME)
        self.assertEqual(live["source_archive_sha256"], OFFICIAL_SOURCE_SHA256)
        self.assertIs(live["discovered_latest_stable"]["adopted"], True)
        self.assertEqual(
            live["discovered_latest_stable"]["source_archive_sha256"],
            OFFICIAL_SOURCE_SHA256,
        )
        self.assertTrue(Path(PRESERVED_401_SOURCE).is_file())
        self.assertTrue(Path(PRESERVED_401_ZIP).is_file())
        self.assertEqual(stat.S_IMODE(Path(PRESERVED_401_SOURCE).stat().st_mode), 0o444)
        self.assertEqual(stat.S_IMODE(Path(PRESERVED_401_ZIP).stat().st_mode), 0o444)

    def test_refuses_arguments_and_unapproved_output_path(self) -> None:
        extra = subprocess.run(
            ["/bin/bash", str(SCRIPT), "extra"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=10,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        self.assertNotEqual(extra.returncode, 0)
        self.assertIn("usage:", extra.stderr)
        with tempfile.TemporaryDirectory(dir="/private/tmp") as name:
            tmp = Path(name)
            completed = _run_producer(
                tmp,
                env_updates={
                    "WINS_OPENSSL_OUTPUT_ARCHIVE": str(tmp / OFFICIAL_ARCHIVE_NAME),
                    "WINS_OPENSSL_SOURCE_ARCHIVE": str(tmp / OFFICIAL_SOURCE_NAME),
                },
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("owner-approved location", completed.stderr)

    def test_wrong_source_digest_fails_before_compile(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-openssl-build.", dir="/private/tmp") as name:
            tmp = Path(name)
            source = tmp / OFFICIAL_SOURCE_NAME
            source.write_bytes(b"not-official-openssl-source")
            source.chmod(0o444)
            output = tmp / OFFICIAL_ARCHIVE_NAME
            completed = _run_producer(
                tmp,
                env_updates={
                    "WINS_OPENSSL_SOURCE_ARCHIVE": str(source),
                    "WINS_OPENSSL_OUTPUT_ARCHIVE": str(output),
                },
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertRegex(completed.stderr, r"source archive digest is not the official OpenSSL 4.0.2 digest")
            self.assertFalse(output.exists())
            self.assertNotIn("CANDIDATE_RECORD|", completed.stdout)

    def test_refuses_to_overwrite_incomplete_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-openssl-build.", dir="/private/tmp") as name:
            tmp = Path(name)
            source = tmp / OFFICIAL_SOURCE_NAME
            source.write_bytes(b"not-official-openssl-source")
            source.chmod(0o444)
            output = tmp / OFFICIAL_ARCHIVE_NAME
            output.write_bytes(b"PK")
            output.chmod(0o444)
            completed = _run_producer(
                tmp,
                env_updates={
                    "WINS_OPENSSL_SOURCE_ARCHIVE": str(source),
                    "WINS_OPENSSL_OUTPUT_ARCHIVE": str(output),
                },
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertRegex(completed.stderr, r"overwrite")
            self.assertEqual(output.read_bytes(), b"PK")

    def test_path_clang_and_openssl_traps_are_not_invoked(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-openssl-build.", dir="/private/tmp") as name:
            tmp = Path(name)
            trap_dir = tmp / "trap-bin"
            trap_dir.mkdir()
            clang_marker = tmp / "path-clang-invoked"
            openssl_marker = tmp / "path-openssl-invoked"
            cc_marker = tmp / "path-cc-invoked"
            brew_marker = tmp / "path-brew-invoked"
            _write_path_trap(trap_dir / "clang", clang_marker)
            _write_path_trap(trap_dir / "openssl", openssl_marker)
            _write_path_trap(trap_dir / "cc", cc_marker)
            _write_path_trap(trap_dir / "brew", brew_marker)
            source = tmp / OFFICIAL_SOURCE_NAME
            source.write_bytes(b"not-official-openssl-source")
            source.chmod(0o444)
            output = tmp / OFFICIAL_ARCHIVE_NAME
            completed = _run_producer(
                tmp,
                extra_path=trap_dir,
                env_updates={
                    "WINS_OPENSSL_SOURCE_ARCHIVE": str(source),
                    "WINS_OPENSSL_OUTPUT_ARCHIVE": str(output),
                    "HOMEBREW_PREFIX": "/opt/homebrew",
                    "PKG_CONFIG_PATH": str(trap_dir),
                },
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(clang_marker.exists(), clang_marker.read_text() if clang_marker.exists() else "")
            self.assertFalse(openssl_marker.exists())
            self.assertFalse(cc_marker.exists())
            self.assertFalse(brew_marker.exists())
            self.assertFalse(output.exists())

    def test_missing_non_official_source_does_not_fetch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-openssl-build.", dir="/private/tmp") as name:
            tmp = Path(name)
            trap_dir = tmp / "trap-bin"
            trap_dir.mkdir()
            curl_marker = tmp / "path-curl-invoked"
            _write_path_trap(trap_dir / "curl", curl_marker)
            output = tmp / OFFICIAL_ARCHIVE_NAME
            completed = _run_producer(
                tmp,
                extra_path=trap_dir,
                env_updates={
                    "WINS_OPENSSL_SOURCE_ARCHIVE": str(tmp / OFFICIAL_SOURCE_NAME),
                    "WINS_OPENSSL_OUTPUT_ARCHIVE": str(output),
                },
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("absent", completed.stderr)
            self.assertFalse(curl_marker.exists())
            self.assertFalse(output.exists())

    def test_does_not_write_owner_receipt_or_touch_pins(self) -> None:
        before = PIN_MANIFEST.read_bytes()
        mtime = PIN_MANIFEST.stat().st_mtime_ns
        with tempfile.TemporaryDirectory(prefix="wins-openssl-build.", dir="/private/tmp") as name:
            tmp = Path(name)
            source = tmp / OFFICIAL_SOURCE_NAME
            source.write_bytes(b"not-official-openssl-source")
            source.chmod(0o444)
            output = tmp / OFFICIAL_ARCHIVE_NAME
            completed = _run_producer(
                tmp,
                env_updates={
                    "WINS_OPENSSL_SOURCE_ARCHIVE": str(source),
                    "WINS_OPENSSL_OUTPUT_ARCHIVE": str(output),
                    "WINS_OPENSSL_BUILD_RECEIPT": str(tmp / "forged-receipt.json"),
                },
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse((tmp / "forged-receipt.json").exists())
            self.assertNotIn('"issuer":"winsvpn-owner"', completed.stdout)
            self.assertNotIn('"authenticated":true', completed.stdout.replace(" ", ""))
        self.assertEqual(PIN_MANIFEST.read_bytes(), before)
        self.assertEqual(PIN_MANIFEST.stat().st_mtime_ns, mtime)

    def test_official_downloads_paths_are_the_only_external_outputs(self) -> None:
        self.assertIn('OFFICIAL_SOURCE_PATH="/Users/owner/Downloads/${OFFICIAL_SOURCE_NAME}"', SOURCE)
        self.assertIn('OFFICIAL_OUTPUT_PATH="/Users/owner/Downloads/${OFFICIAL_ARCHIVE_NAME}"', SOURCE)
        self.assertEqual(
            f"/Users/owner/Downloads/{OFFICIAL_SOURCE_NAME}",
            OFFICIAL_SOURCE_PATH,
        )
        self.assertEqual(
            f"/Users/owner/Downloads/{OFFICIAL_ARCHIVE_NAME}",
            OFFICIAL_OUTPUT_PATH,
        )
        self.assertIn("OpenSSL 4.0.2", CUSTODY_SOURCE)
        self.assertNotIn("may still freeze 4.0.1", CUSTODY_SOURCE)
        self.assertNotIn("rm -f -- \"$OFFICIAL_SOURCE_PATH\"", SOURCE)
        self.assertNotIn("rm -f -- \"$OFFICIAL_OUTPUT_PATH\"", SOURCE)


if __name__ == "__main__":
    unittest.main()
