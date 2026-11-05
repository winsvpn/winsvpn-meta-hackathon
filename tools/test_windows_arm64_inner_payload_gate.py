#!/usr/bin/env python3
"""Executable negative controls for Windows ARM64 inner-payload verification."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import verify_windows_standalone_v3_artifact as verifier  # noqa: E402


POWERSHELL_VERIFIER = ROOT / "installer/windows/verify_arm64_msi_payload.ps1"
MSI_PRODUCER = ROOT / "installer/windows/build_winn3_msi_arm64.ps1"
XCOMPILE = ROOT / "tools/build_windows_tunnel_service_xcompile.sh"
PINNED_WINTUN = ROOT / "installer/windows/dependencies/wintun-arm64.dll"


def pe(machine: int, *, marker: bool = False) -> bytes:
    data = bytearray(256)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, machine)
    if marker:
        data.extend(verifier.WINN3_MARKER)
    return bytes(data)


class PackedInstallerExtractionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.payload = self.root / "payload"
        self.payload.mkdir()
        self.installer = self.root / "WinsVPN-Setup-arm64.exe"
        self.installer.write_bytes(b"MZ-not-a-zip-fixture")
        self.fake_7z = self.root / "fake-7z"
        fake_interpreter = Path(
            getattr(sys, "_base_executable", sys.executable)
        ).resolve(strict=True)
        self.fake_7z.write_text(
            f"#!{fake_interpreter}\n"
            "from pathlib import Path\n"
            "import sys\n"
            f"payload = Path({str(self.payload)!r})\n"
            "if sys.argv[1] == 'l':\n"
            "    print('Path = ' + sys.argv[-1])\n"
            "    for item in sorted(payload.iterdir()):\n"
            "        print('Path = payload/' + item.name)\n"
            "    raise SystemExit(0)\n"
            "if sys.argv[1] == 'x':\n"
            "    if '-spd' not in sys.argv:\n"
            "        print('wildcard matching was not disabled', file=sys.stderr)\n"
            "        raise SystemExit(3)\n"
            "    requested = Path(sys.argv[-1].replace('\\\\', '/')).name\n"
            "    candidate = payload / requested\n"
            "    if not candidate.is_file():\n"
            "        print('missing requested member', file=sys.stderr)\n"
            "        raise SystemExit(2)\n"
            "    sys.stdout.buffer.write(candidate.read_bytes())\n"
            "    raise SystemExit(0)\n"
            "raise SystemExit(2)\n",
            encoding="utf-8",
        )
        self.fake_7z.chmod(self.fake_7z.stat().st_mode | stat.S_IXUSR)

    def _write_payload(self, machine: int, *, datapath_marker: bool = True) -> None:
        for name in verifier.REQUIRED_BASENAMES:
            (self.payload / name).write_bytes(
                pe(
                    machine,
                    marker=(name == "winn-datapath.exe" and datapath_marker),
                )
            )

    def _verify(self) -> list[str]:
        with mock.patch.dict(
            os.environ,
            {"WINS_7ZIP": str(self.fake_7z)},
        ):
            return verifier.verify(self.installer)

    def test_exact_extracted_arm64_inner_bytes_pass(self) -> None:
        self._write_payload(verifier.PE_MACHINE_ARM64)
        self.assertEqual(self._verify(), [])

    def test_x64_bytes_under_arm64_installer_name_fail(self) -> None:
        self._write_payload(verifier.PE_MACHINE_X64)
        errors = self._verify()
        self.assertEqual(len([error for error in errors if "arm64 requires" in error]), 5)

    def test_member_names_cannot_replace_marker_bytes(self) -> None:
        self._write_payload(verifier.PE_MACHINE_ARM64, datapath_marker=False)
        errors = self._verify()
        self.assertTrue(any("bytes do not contain" in error for error in errors), errors)

    def test_absent_extractor_is_fail_closed(self) -> None:
        self._write_payload(verifier.PE_MACHINE_ARM64)
        with mock.patch.dict(
            os.environ,
            {"WINS_7ZIP": str(self.root / "missing-7z")},
            clear=False,
        ):
            with self.assertRaisesRegex(verifier.ArtifactError, "not an executable"):
                verifier.verify(self.installer)


class Arm64MsiPayloadPowerShellTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pwsh = shutil.which("pwsh") or shutil.which("powershell")

    def setUp(self) -> None:
        if not self.pwsh:
            self.skipTest("PowerShell is unavailable")
        if not PINNED_WINTUN.is_file():
            self.skipTest("pinned ARM64 Wintun fixture is unavailable")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.payload = Path(self.temp.name) / "payload"
        self.payload.mkdir()

    def _write_payload(self, relay_machine: int, *, relay_marker: bool = False) -> None:
        (self.payload / "winn-datapath.exe").write_bytes(
            pe(verifier.PE_MACHINE_ARM64, marker=True)
        )
        (self.payload / "winsvpn_winn3_engine.exe").write_bytes(
            pe(relay_machine, marker=relay_marker)
        )
        shutil.copyfile(PINNED_WINTUN, self.payload / "wintun.dll")
        entries = []
        for path in sorted(self.payload.iterdir()):
            data = path.read_bytes()
            entries.append(
                {"name": path.name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            )
        (self.payload / "payload-manifest.json").write_text(
            json.dumps({"architecture": "arm64", "files": entries}),
            encoding="ascii",
        )

    def _run(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                self.pwsh,
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(POWERSHELL_VERIFIER),
                "-PayloadDir",
                str(self.payload),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_relay_needs_arm64_but_not_the_datapath_marker(self) -> None:
        self._write_payload(verifier.PE_MACHINE_ARM64)
        completed = self._run()
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_x64_relay_renamed_as_arm64_is_rejected(self) -> None:
        self._write_payload(verifier.PE_MACHINE_X64)
        completed = self._run()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("COFF 0x8664", completed.stderr)

    def test_relay_marker_is_rejected(self) -> None:
        self._write_payload(verifier.PE_MACHINE_ARM64, relay_marker=True)
        completed = self._run()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unexpectedly contains the Winn v3 marker", completed.stderr)
        self.assertIn("winn-datapath.exe is the carrier", completed.stderr)

    def test_manifest_byte_substitution_is_rejected(self) -> None:
        self._write_payload(verifier.PE_MACHINE_ARM64)
        with (self.payload / "winsvpn_winn3_engine.exe").open("ab") as stream:
            stream.write(b"substitution")
        completed = self._run()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("does not match payload manifest", completed.stderr)


class Arm64MsiProducerPortableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pwsh = shutil.which("pwsh") or shutil.which("powershell")

    def setUp(self) -> None:
        if not self.pwsh:
            self.skipTest("PowerShell is unavailable")
        if not PINNED_WINTUN.is_file():
            self.skipTest("pinned ARM64 Wintun fixture is unavailable")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.release = self.root / "release"
        self.release.mkdir()
        self.stage = self.root / "stage"
        self.out = self.root / "out"
        self.fake_bin = self.root / "bin"
        self.fake_bin.mkdir()
        self.fake_wix = self.fake_bin / "wix"
        self.fake_wix.write_text(
            """#!/usr/bin/env bash
set -eu
output=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = '-o' ]; then
    shift
    output="$1"
    break
  fi
  shift
done
if [ -z "$output" ]; then
  exit 2
fi
printf 'fake portable MSI' > "$output"
""",
            encoding="ascii",
        )
        self.fake_wix.chmod(self.fake_wix.stat().st_mode | stat.S_IXUSR)

    def _run(self, relay_machine: int, *, relay_marker: bool = False) -> subprocess.CompletedProcess[str]:
        (self.release / "winn-datapath.exe").write_bytes(
            pe(verifier.PE_MACHINE_ARM64, marker=True)
        )
        (self.release / "winsvpn_winn3_engine.exe").write_bytes(
            pe(relay_machine, marker=relay_marker)
        )
        environment = os.environ.copy()
        environment["PATH"] = str(self.fake_bin) + os.pathsep + environment["PATH"]
        for name in (
            "WINS_WINDOWS_ARTIFACT_SIGNING_METADATA",
            "WINS_WINDOWS_SIGN_CERT_SHA1",
            "WINS_WINDOWS_SIGN_PFX",
            "WINS_WINDOWS_SIGN_PFX_PASSWORD",
        ):
            environment.pop(name, None)
        return subprocess.run(
            [
                self.pwsh,
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(MSI_PRODUCER),
                "-ReleaseDir",
                str(self.release),
                "-DependenciesDir",
                str(PINNED_WINTUN.parent),
                "-LicensesDir",
                str(ROOT / "installer/windows/licenses"),
                "-OutDir",
                str(self.out),
                "-StageDir",
                str(self.stage),
                "-AppVersion",
                "1.0.0.0",
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

    def test_producer_accepts_arm64_relay_without_marker(self) -> None:
        completed = self._run(verifier.PE_MACHINE_ARM64)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue((self.out / "WinsVPN-Winn3-Engines-1.0.0.0-arm64.msi").is_file())
        verified = subprocess.run(
            [
                self.pwsh,
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(POWERSHELL_VERIFIER),
                "-PayloadDir",
                str(self.stage / "payload"),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(verified.returncode, 0, verified.stderr)

    def test_producer_rejects_x64_relay_under_arm64_name(self) -> None:
        completed = self._run(verifier.PE_MACHINE_X64)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("not PE32+ AArch64", completed.stderr)
        self.assertFalse(self.out.exists() and any(self.out.glob("*.msi")))

    def test_producer_rejects_relay_carrier_marker(self) -> None:
        completed = self._run(verifier.PE_MACHINE_ARM64, relay_marker=True)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unexpectedly contains", completed.stderr)
        self.assertIn("winn-datapath.exe is the Winn", completed.stderr)
        self.assertFalse(self.out.exists() and any(self.out.glob("*.msi")))


class ProducerSourceContracts(unittest.TestCase):
    def test_explicit_cross_compile_fails_closed_without_architecture_tools(self) -> None:
        source = XCOMPILE.read_text(encoding="utf-8")
        self.assertIn('if [[ "${output_dir}" != /* ]]', source)
        self.assertIn("if ! command -v file", source)
        self.assertIn("file architecture inspector is required", source)
        for marker in (
            "clang-cl not found",
            "lld-link not found",
            "no xwin-fetched Windows SDK/CRT found",
        ):
            at = source.index(marker)
            self.assertIn("exit 1", source[at : at + 300])
        self.assertNotIn("SKIPPED: clang-cl", source)

    def test_cross_compile_really_fails_when_file_tool_is_absent(self) -> None:
        clang = Path("/Users/owner/.homebrew/Homebrew/opt/llvm/bin/clang-cl")
        linker = Path("/Users/owner/.homebrew/Homebrew/opt/lld/bin/lld-link")
        sdk = Path.home() / ".xwin-sdk"
        if not (clang.is_file() and linker.is_file() and (sdk / "crt/include").is_dir()):
            self.skipTest("reviewed cross toolchain is unavailable")
        dirname = shutil.which("dirname")
        if not dirname:
            self.skipTest("dirname is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            shim = Path(temporary) / "bin"
            shim.mkdir()
            (shim / "dirname").symlink_to(dirname)
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": str(shim),
                    "WINS_CLANG_CL": str(clang),
                    "WINS_LLD_LINK": str(linker),
                    "WINS_XWIN_SDK_DIR": str(sdk),
                }
            )
            completed = subprocess.run(
                ["/bin/bash", str(XCOMPILE)],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("file architecture inspector is required", completed.stdout)

    def test_arm64_msi_producer_checks_only_datapath_for_carrier_marker(self) -> None:
        source = MSI_PRODUCER.read_text(encoding="utf-8")
        gate = source[source.index("$datapath =") : source.index("# ---- payload manifest")]
        self.assertIn("Test-FileContainsMarker -Path $datapath", gate)
        self.assertNotIn("Test-FileContainsMarker -Path $relay", gate)
        self.assertIn("foreach ($nonCarrier in @($relay", gate)
        self.assertIn("only winn-datapath.exe is the Winn v3 carrier", gate)
        self.assertIn("foreach ($p in @($datapath, $relay", gate)


if __name__ == "__main__":
    unittest.main()
