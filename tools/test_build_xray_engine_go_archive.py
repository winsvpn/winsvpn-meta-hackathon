#!/usr/bin/env python3
"""tools/build_xray_engine.sh takes pinned Go without ReleaseGo custody.

Go comes from a caller-defined wins_release_go_run (the Linux producer's local
pinned-checksum wrapper) or from the official archive, bound to the pinned
archive SHA-256. WINS_WINN_GO_ARCHIVE names a local copy of that archive so
the Go stage runs offline; nothing requires /Library/WinsVPN/ReleaseGo.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
XRAY = ROOT / "tools" / "build_xray_engine.sh"
PINS = ROOT / "tools" / "toolchain-pins.json"


def pinned_go_archive() -> pathlib.Path | None:
    candidates = [os.environ.get("WINS_WINN_GO_ARCHIVE", "")]
    try:
        paths = json.loads(PINS.read_text(encoding="utf-8"))["tools"]["go"].get("archive_path", {})
        candidates.extend(paths.values() if isinstance(paths, dict) else ())
    except (OSError, KeyError, ValueError):
        pass
    for candidate in candidates:
        if candidate and pathlib.Path(candidate).expanduser().is_file():
            return pathlib.Path(candidate).expanduser()
    return None


def path_python_has_data_filter() -> bool:
    python = shutil.which("python3")
    if python is None:
        return False
    probe = subprocess.run(
        [python, "-I", "-c", "import tarfile,sys; sys.exit(0 if hasattr(tarfile, 'data_filter') else 1)"],
        check=False,
    )
    return probe.returncode == 0


class XrayGoArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory(prefix="wins-xray-go-archive-")
        self.temp = pathlib.Path(self._temp.name).resolve()
        self.work_tmp = self.temp / "tmp"
        self.work_tmp.mkdir()
        fake_bin = self.temp / "fake-bin"
        fake_bin.mkdir()
        self.curl_marker = self.temp / "curl-called"
        curl = fake_bin / "curl"
        curl.write_text(f"#!/bin/sh\necho called > '{self.curl_marker}'\nexit 7\n", encoding="utf-8")
        curl.chmod(0o755)
        self.fake_bin = fake_bin

    def tearDown(self) -> None:
        subprocess.run(["chmod", "-R", "u+w", str(self.temp)], check=False)
        self._temp.cleanup()

    def run_xray(self, **extra: str) -> subprocess.CompletedProcess:
        environment = os.environ.copy()
        for name in list(environment):
            if name.startswith("BASH_FUNC_") or name in {
                "BASH_ENV",
                "WINS_ENGINE_SOURCE_ROOT",
                "WINS_WINN_GO_ARCHIVE",
                "XRAY_SOURCE_DIR",
                "XRAY_SOURCE_TREE_SHA256",
                "LINUX_REVIEWED_GO_BIN",
            }:
                environment.pop(name, None)
        environment["PATH"] = f"{self.fake_bin}:{environment.get('PATH', '/usr/bin:/bin')}"
        environment["TMPDIR"] = str(self.work_tmp)
        # A missing source directory stops the script right after the Go
        # stage, before any clone or module download.
        environment["XRAY_SOURCE_DIR"] = str(self.temp / "no-xray-source")
        environment.update(extra)
        return subprocess.run(
            ["bash", str(XRAY), "linux-amd64", str(self.temp / "out" / "xray")],
            cwd=self.temp,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_go_pins_match_toolchain_pins_and_checksum_gate_stays(self) -> None:
        text = XRAY.read_text(encoding="utf-8")
        go = json.loads(PINS.read_text(encoding="utf-8"))["tools"]["go"]
        self.assertIn(f'REVIEWED_GO_VERSION="{go["version"]}"', text)
        for host in ("darwin_arm64", "darwin_amd64", "linux_amd64", "linux_arm64"):
            self.assertIn(f'GO_HOST_SHA256_{host.upper()}="{go["archive_sha256"][host]}"', text)
        self.assertIn("if hasher.hexdigest() != expected:", text)
        self.assertIn('Pinned Go host toolchain SHA-256 verification failed.', text)
        self.assertIn('filter="data"', text)
        for retired in (
            "release_go_archive_custody",
            "wins_release_go_verify",
            "wins_release_go_prepare",
            "/Library/WinsVPN",
            "ReleaseGo",
        ):
            self.assertNotIn(retired, text, retired)
        # wins_release_go_run is used only when a caller defined it.
        for line in text.splitlines():
            code = line.strip()
            if code.startswith("#"):
                continue
            if "wins_release_go_run" in code and "declare -F wins_release_go_run" not in code:
                self.assertRegex(code, r"^(wins_release_go_run build|version_check=\"\$\(wins_release_go_run version)")
        self.assertEqual(len(re.findall(r"declare -F wins_release_go_run", text)), 2)

    def test_local_archive_off_the_pin_is_refused_without_network(self) -> None:
        archive = self.temp / "go-tampered.tar.gz"
        archive.write_bytes(b"not the pinned Go archive")
        completed = self.run_xray(WINS_WINN_GO_ARCHIVE=str(archive))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("Pinned Go host toolchain SHA-256 verification failed.", completed.stderr)
        self.assertIn("Pinned Go host toolchain archive was refused.", completed.stderr)
        self.assertFalse(self.curl_marker.exists(), "a local archive must not trigger a download")
        self.assertEqual(list(self.work_tmp.iterdir()), [])

    def test_local_archive_must_be_an_absolute_regular_file(self) -> None:
        for value in ("go.tar.gz", str(self.temp / "absent.tar.gz")):
            completed = self.run_xray(WINS_WINN_GO_ARCHIVE=value)
            self.assertNotEqual(completed.returncode, 0, value)
            self.assertIn("WINS_WINN_GO_ARCHIVE must be an absolute path to a regular file", completed.stderr)
            self.assertFalse(self.curl_marker.exists())

    def test_store_mode_still_requires_an_archive_bound_go(self) -> None:
        completed = self.run_xray(WINS_ENGINE_SOURCE_ROOT=str(self.temp))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("declared Go SDK must be archive-bound before Xray build", completed.stderr)
        self.assertFalse(self.curl_marker.exists())

    @unittest.skipUnless(sys.platform == "darwin" or sys.platform.startswith("linux"), "unsupported host")
    def test_pinned_local_archive_prepares_go_offline(self) -> None:
        archive = pinned_go_archive()
        if archive is None:
            self.skipTest("pinned Go archive unavailable; set WINS_WINN_GO_ARCHIVE")
        if not path_python_has_data_filter():
            self.skipTest("python3 on PATH lacks tarfile.data_filter, which the extractor requires")
        host = "darwin" if sys.platform == "darwin" else "linux"
        machine = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64"}[os.uname().machine]
        if f"{host}-{machine}" not in archive.name:
            self.skipTest(f"{archive.name} is not this host's Go archive")
        for extra in ({}, {"WINS_ENGINE_SOURCE_ROOT": str(self.temp)}):
            completed = self.run_xray(WINS_WINN_GO_ARCHIVE=str(archive), **extra)
            self.assertNotEqual(completed.returncode, 0)
            # Past the Go archive checksum, extraction and `go version`
            # identity checks, stopped by the absent source directory.
            self.assertIn("XRAY_SOURCE_DIR must be a regular directory.", completed.stderr, completed.stderr)
            self.assertNotIn("Pinned Go", completed.stderr)
            self.assertFalse(self.curl_marker.exists())
            self.assertEqual(list(self.work_tmp.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
