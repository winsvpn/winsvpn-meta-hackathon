#!/usr/bin/env python3
"""Refuse the unauthenticated Windows ZIP install and publication paths."""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD = ROOT / "installer/windows/build_zip_installer.ps1"
INSTALL = ROOT / "installer/windows/install_winsvpn_zip.ps1"


class ZipRouteRetirementTests(unittest.TestCase):
    def test_privileged_zip_route_refuses_before_touching_a_host(self) -> None:
        shell = shutil.which("pwsh") or shutil.which("powershell")
        if shell is None:
            self.skipTest("PowerShell is unavailable")
        for script, marker in (
            (BUILD, "no authenticated bootstrap"),
            (INSTALL, "Privileged installation from an unsigned ZIP is disabled"),
        ):
            with self.subTest(script=script.name):
                command = [shell, "-NoProfile"]
                if pathlib.Path(shell).stem.lower() == "powershell":
                    command.extend(["-ExecutionPolicy", "Bypass"])
                command.extend(["-File", str(script)])
                result = subprocess.run(
                    command,
                    cwd=ROOT,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(marker, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
