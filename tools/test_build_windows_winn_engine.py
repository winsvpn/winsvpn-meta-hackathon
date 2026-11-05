#!/usr/bin/env python3
"""Tests for Windows Winn engine staging from a Winn release directory.

Covers tools/build_windows_winn_engine.sh (release and dev modes, run against a
stand-in tools/winn_release.py) and the compiled-role checker
tools/windows_winn3_artifact_provenance.py.
"""

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


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "build_windows_winn_engine.sh"
ROLE_TOOL = ROOT / "tools" / "windows_winn3_artifact_provenance.py"
INSTALLER = ROOT / "installer" / "windows" / "build_installer.ps1"
PYTHON = "/usr/bin/python3"

sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "tools"))
import windows_winn3_artifact_provenance as provenance  # noqa: E402


COMMIT = "0123456789abcdef0123456789abcdef01234567"
ARCHES = {"amd64": "x64", "arm64": "arm64"}
# (target prefix, file name, role) for every Windows release image staged.
IMAGES = (
    ("datapath-windows", "winn-datapath.exe", "core"),
    ("winn3-relay-windows", "winsvpn_winn3_engine.exe", "relay"),
)
STAGE_ORDER = [
    f"{prefix}-{arch}" for arch in ARCHES for prefix, _name, _role in IMAGES
]


def _uvarint(value: int) -> bytes:
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def compiled_go_pe(role: str, architecture: str, *, build_id: bool = True,
                   malformed_build_id: bool = False) -> bytes:
    """A minimal PE32+ image carrying Go build-info for ROLE."""

    data = bytearray(8192)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, provenance.ARCH_MACHINES[architecture],
                     3, 0, 0, 0, 112, 0x0002)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x4000, 0x200)
    struct.pack_into("<I", data, optional + 108, 0)
    section = optional + 112
    data[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x400, 0x1000, 0x400, 0x400)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    rdata = section + 40
    data[rdata:rdata + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", data, rdata + 8, 0x1000, 0x2000, 0x1000, 0x800)
    struct.pack_into("<I", data, rdata + 36, 0x40000040)
    writable = rdata + 40
    data[writable:writable + 8] = b".data\0\0\0"
    struct.pack_into("<IIII", data, writable + 8, 0x400, 0x3000, 0x400, 0x1800)
    struct.pack_into("<I", data, writable + 36, 0xC0000040)
    for index in range(0x400, 0x800):
        data[index] = ((index * 29) % 251) + 1
    header = b'\xff Go build ID: "abcdefghijklmnopqrstuvwxyz0123456789/ABCDEFGHIJKLMNO"\n'
    if malformed_build_id:
        header = b'\xff Go build ID: "short"\n'
    if build_id:
        data[0x400:0x400 + len(header)] = header
    pcln = 0x800
    function_count = 128
    struct.pack_into("<IBBBB8Q", data, pcln, 0xFFFFFFF1, 0, 0, 1, 8,
                     function_count, 16, 0, 72, 128, 256, 384, 768)
    for index in range(function_count):
        struct.pack_into("<II", data, pcln + 768 + index * 8, index * 16, 1024 + index)
    struct.pack_into("<II", data, pcln + 768 + function_count * 8, function_count * 16, 0)
    expected_path, expected_module = provenance.GO_ROLE_IDENTITIES[role]
    start = bytes.fromhex("3077af0c9274080241e1c107e6d618e6")
    end = bytes.fromhex("f932433186182072008242104116d8f2")
    module = (start + f"path\t{expected_path}\nmod\t{expected_module}\tv0.0.0\n".encode()
              + end)
    build_info = (b"\xff Go buildinf:" + bytes((8, 2)) + bytes(16)
                  + _uvarint(len(b"go1.27.1")) + b"go1.27.1"
                  + _uvarint(len(module)) + module)
    data[0x1800:0x1800 + len(build_info)] = build_info
    return bytes(data)


FAKE_DRIVER = r'''#!/usr/bin/env python3
"""Stand-in for tools/winn_release.py: logs argv and follows FAKE_WINN_SCENARIO."""
import hashlib, json, os, shutil, sys
from pathlib import Path
scenario = os.environ.get("FAKE_WINN_SCENARIO", "ok")
with open(os.environ["FAKE_WINN_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(sys.argv[1:]) + "\n")
command = sys.argv[1]
args = sys.argv[2:]
def value(flag):
    return args[args.index(flag) + 1]
if command == "build":
    if scenario == "build_toolchain_missing":
        print("TOOLCHAIN-MISSING: pinned Go archive is absent", file=sys.stderr)
        sys.exit(3)
    if scenario == "build_fail":
        print("build failed", file=sys.stderr)
        sys.exit(1)
    out = Path(value("--out"))
    out.mkdir(parents=False)
    rows = []
    for arch in ("amd64", "arm64"):
        for prefix, name, source in (("datapath-windows", "winn-datapath.exe", f"{arch}.exe"),
                                     ("winn3-relay-windows", "winsvpn_winn3_engine.exe", f"relay-{arch}.exe")):
            target = f"{prefix}-{arch}"
            dest = out / "artifacts" / target / name
            dest.parent.mkdir(parents=True)
            shutil.copyfile(Path(os.environ["FAKE_WINN_SOURCE"]) / source, dest)
            digest = hashlib.sha256(dest.read_bytes()).hexdigest()
            rows.append({"target": target, "path": str(dest.relative_to(out)), "sha256": digest})
    (out / "manifest.json").write_text(json.dumps({"artifacts": rows}))
    sys.exit(0)
if command == "verify":
    release = Path(value("--release"))
    if "--print-manifest" not in args or "--print-artifact" in args:
        print("staging must verify once with --print-manifest", file=sys.stderr)
        sys.exit(2)
    if "--allow-unsigned" in args:
        print("UNSIGNED: dev use only", file=sys.stderr)
    elif not (release / "manifest.sig.json").is_file():
        print("signature missing", file=sys.stderr)
        sys.exit(1)
    if scenario.startswith("verify_fail_"):
        print("digest mismatch " + scenario[len("verify_fail_"):], file=sys.stderr)
        sys.exit(1)
    manifest = json.dumps(json.loads((release / "manifest.json").read_text()), sort_keys=True)
    if scenario == "verify_two_lines":
        print(manifest)
    print(manifest)
    sys.exit(0)
sys.exit(2)
'''

FAKE_GO = r'''#!/usr/bin/env python3
import os, shutil, sys
args = sys.argv[1:]
if args[:1] != ["build"]:
    sys.exit(2)
out = args[args.index("-o") + 1]
shutil.copyfile(os.path.join(os.environ["FAKE_WINN_SOURCE"], "fixture-" + os.environ["GOARCH"] + ".exe"), out)
'''


class RoleCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def write(self, name: str, data: bytes) -> Path:
        directory = self.tmp / hashlib.sha256(data + name.encode()).hexdigest()[:12]
        directory.mkdir()
        path = directory / name
        path.write_bytes(data)
        return path

    def run_tool(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([PYTHON, "-I", "-B", str(ROLE_TOOL), "check-role", *args],
                              capture_output=True, text=True, check=False)

    def test_core_and_relay_pass_on_both_architectures(self) -> None:
        for arch in ("x64", "arm64"):
            for role, name in (("core", "winn-datapath.exe"), ("relay", "winsvpn_winn3_engine.exe")):
                data = compiled_go_pe(role, arch)
                path = self.write(name, data)
                result = self.run_tool("--role", role, "--architecture", arch,
                                       "--expect-sha256", hashlib.sha256(data).hexdigest(), str(path))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertRegex(result.stdout,
                                 rf"^PASS: windows winn3 {role} {arch} sha256=[0-9a-f]{{64}} "
                                 r"build_identity=[0-9a-f]{64}\n$")

    def test_release_link_without_build_id_is_accepted(self) -> None:
        path = self.write("winn-datapath.exe", compiled_go_pe("core", "x64", build_id=False))
        result = self.run_tool("--role", "core", "--architecture", "x64", str(path))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_malformed_build_id_is_refused(self) -> None:
        path = self.write("winn-datapath.exe",
                          compiled_go_pe("core", "x64", malformed_build_id=True))
        result = self.run_tool("--role", "core", "--architecture", "x64", str(path))
        self.assertEqual(result.returncode, 1)
        self.assertIn("Go build ID is invalid", result.stderr)

    def test_relay_bytes_under_the_datapath_name_are_refused(self) -> None:
        path = self.write("winn-datapath.exe", compiled_go_pe("relay", "x64"))
        result = self.run_tool("--role", "core", "--architecture", "x64", str(path))
        self.assertEqual(result.returncode, 1)
        self.assertIn("compiled Go role identity is invalid", result.stderr)

    def test_wrong_architecture_is_refused(self) -> None:
        path = self.write("winn-datapath.exe", compiled_go_pe("core", "x64"))
        result = self.run_tool("--role", "core", "--architecture", "arm64", str(path))
        self.assertEqual(result.returncode, 1)
        self.assertIn("PE machine does not match", result.stderr)

    def test_wrong_name_digest_and_symlink_are_refused(self) -> None:
        data = compiled_go_pe("core", "x64")
        wrong_name = self.write("engine.exe", data)
        self.assertEqual(self.run_tool("--role", "core", "--architecture", "x64",
                                       str(wrong_name)).returncode, 1)
        path = self.write("winn-datapath.exe", data)
        mismatch = self.run_tool("--role", "core", "--architecture", "x64",
                                 "--expect-sha256", "0" * 64, str(path))
        self.assertEqual(mismatch.returncode, 1)
        self.assertIn("does not match the expected", mismatch.stderr)
        link_dir = self.tmp / "link"
        link_dir.mkdir()
        (link_dir / "winn-datapath.exe").symlink_to(path)
        self.assertEqual(self.run_tool("--role", "core", "--architecture", "x64",
                                       str(link_dir / "winn-datapath.exe")).returncode, 1)

    def test_non_pe_is_refused(self) -> None:
        path = self.write("winn-datapath.exe", b"#!/bin/sh\necho not a PE\n" * 10)
        result = self.run_tool("--role", "core", "--architecture", "x64", str(path))
        self.assertEqual(result.returncode, 1)
        self.assertIn("not a DOS/PE image", result.stderr)


class StagingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.repo = self.tmp / "repo"
        tools = self.repo / "tools"
        tools.mkdir(parents=True)
        shutil.copy2(SCRIPT, tools / SCRIPT.name)
        shutil.copy2(ROLE_TOOL, tools / ROLE_TOOL.name)
        self._exe(tools / "winn_release.py", FAKE_DRIVER)
        self._exe(tools / "verify_winn_framing_conformance.sh", "#!/bin/bash\necho conformance ok\n")
        fixture = self.repo / "windows" / "winn_framing_fixture"
        fixture.mkdir(parents=True)
        (fixture / "main.go").write_text("package main\n")
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self._exe(self.bin / "go", FAKE_GO.replace("#!/usr/bin/env python3", f"#!{PYTHON}"))
        self.source = self.tmp / "source"
        self.source.mkdir()
        for arch, out_arch in ARCHES.items():
            (self.source / f"{arch}.exe").write_bytes(compiled_go_pe("core", out_arch, build_id=False))
            (self.source / f"relay-{arch}.exe").write_bytes(compiled_go_pe("relay", out_arch))
            (self.source / f"fixture-{arch}.exe").write_bytes(compiled_go_pe("core", out_arch))
        self.log = self.tmp / "driver.log"
        self.engine_root = self.repo / "build" / "windows" / "winn3"

    @staticmethod
    def _exe(path: Path, text: str) -> None:
        path.write_text(text)
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def source_bytes(self, target: str) -> bytes:
        arch = target.rsplit("-", 1)[1]
        prefix = "relay-" if target.startswith("winn3-relay-") else ""
        return (self.source / f"{prefix}{arch}.exe").read_bytes()

    def make_release(self, *, signed: bool = True, swap: dict[str, bytes] | None = None) -> Path:
        """SWAP maps a target to bytes written after the manifest is computed."""
        release = self.tmp / "release"
        rows = []
        for arch in ARCHES:
            for prefix, name, _role in IMAGES:
                target = f"{prefix}-{arch}"
                path = release / "artifacts" / target / name
                path.parent.mkdir(parents=True)
                data = self.source_bytes(target)
                path.write_bytes(data)
                rows.append({"target": target, "path": f"artifacts/{target}/{name}",
                             "sha256": hashlib.sha256(data).hexdigest()})
                if swap and target in swap:
                    path.write_bytes(swap[target])
        (release / "manifest.json").write_text(json.dumps({"artifacts": rows}))
        if signed:
            (release / "manifest.sig.json").write_text("{}")
        return release

    def run_script(self, *args: str, scenario: str = "ok") -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "HOME": str(self.tmp),
            "TMPDIR": str(self.tmp),
            "FAKE_WINN_SCENARIO": scenario,
            "FAKE_WINN_LOG": str(self.log),
            "FAKE_WINN_SOURCE": str(self.source),
        }
        return subprocess.run(["bash", str(self.repo / "tools" / SCRIPT.name), *args],
                              capture_output=True, text=True, env=env, check=False)

    def driver_calls(self) -> list[list[str]]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def staged(self, out_arch: str, name: str = "winn-datapath.exe") -> Path:
        return self.engine_root / out_arch / name

    def assert_all_staged(self) -> None:
        for arch, out_arch in ARCHES.items():
            for prefix, name, _role in IMAGES:
                self.assertEqual(self.staged(out_arch, name).read_bytes(),
                                 self.source_bytes(f"{prefix}-{arch}"))

    def assert_none_staged(self) -> None:
        if self.engine_root.exists():
            self.assertEqual([p for p in self.engine_root.rglob("*") if p.is_file()], [])

    def test_signed_release_stages_both_architectures(self) -> None:
        release = self.make_release()
        result = self.run_script("--release", str(release))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_all_staged()
        calls = self.driver_calls()
        # One verification; every digest comes from the manifest it printed.
        self.assertEqual(calls, [["verify", "--release", str(release.resolve()), "--print-manifest"]])
        self.assertIn("signed release, engine + relay", result.stdout)
        self.assertEqual(sorted(p.name for p in self.engine_root.rglob("*")),
                         ["arm64", "winn-datapath.exe", "winn-datapath.exe",
                          "winsvpn_winn3_engine.exe", "winsvpn_winn3_engine.exe", "x64"])
        fixtures = self.repo / "build" / "windows" / "winn"
        self.assertTrue((fixtures / "winn_framing_fixture_amd64.exe").is_file())
        self.assertTrue((fixtures / "winn_framing_fixture_arm64.exe").is_file())

    def test_unsigned_release_is_refused_in_release_mode(self) -> None:
        release = self.make_release(signed=False)
        result = self.run_script("--release", str(release))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release verification failed", result.stderr)
        self.assert_none_staged()

    def test_verification_failure_on_one_architecture_publishes_neither(self) -> None:
        release = self.make_release()
        self.staged("x64").parent.mkdir(parents=True)
        self.staged("x64").write_bytes(b"previous engine")
        result = self.run_script("--release", str(release),
                                 scenario="verify_fail_datapath-windows-arm64")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("datapath-windows-arm64", result.stderr)
        self.assertFalse(self.staged("arm64").exists())
        self.assertEqual(self.staged("x64").read_bytes(), b"previous engine")
        self.assertEqual([p.name for p in self.staged("x64").parent.iterdir()],
                         ["winn-datapath.exe"], "no temporary stage may be left behind")

    def test_relay_failure_publishes_nothing(self) -> None:
        result = self.run_script("--release", str(self.make_release()),
                                 scenario="verify_fail_winn3-relay-windows-arm64")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("winn3-relay-windows-arm64", result.stderr)
        self.assert_none_staged()

    def test_datapath_bytes_under_the_relay_target_are_refused(self) -> None:
        (self.source / "relay-amd64.exe").write_bytes(compiled_go_pe("core", "x64"))
        result = self.run_script("--release", str(self.make_release()))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("compiled-role check failed for winn3-relay-windows-amd64", result.stderr)
        self.assert_none_staged()

    def test_ambiguous_verify_output_is_refused(self) -> None:
        result = self.run_script("--release", str(self.make_release()), scenario="verify_two_lines")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("authenticated manifest digest for datapath-windows-amd64 is unavailable",
                      result.stderr)
        self.assert_none_staged()

    def test_bytes_that_differ_from_the_manifest_are_refused(self) -> None:
        other = compiled_go_pe("core", "x64", build_id=True)
        release = self.make_release(swap={"datapath-windows-amd64": other})
        result = self.run_script("--release", str(release))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the expected", result.stderr)
        self.assert_none_staged()

    def test_wrong_machine_and_wrong_role_are_refused(self) -> None:
        for swapped in (compiled_go_pe("core", "arm64", build_id=False),
                        compiled_go_pe("relay", "x64", build_id=False)):
            with self.subTest(swapped=hashlib.sha256(swapped).hexdigest()[:8]):
                shutil.rmtree(self.tmp / "release", ignore_errors=True)
                self.log.unlink(missing_ok=True)
                (self.source / "amd64.exe").write_bytes(swapped)
                result = self.run_script("--release", str(self.make_release()))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("compiled-role check failed for datapath-windows-amd64", result.stderr)
                self.assert_none_staged()

    def test_release_bytes_are_bound_to_the_verified_manifest_only(self) -> None:
        # Astra Turn 1 finding 2. The real driver verifies a genuinely signed
        # release; before and after that read, the directory holds other valid
        # engines and a manifest naming them. Digests read from the directory
        # after verification would accept those engines.
        tools = self.repo / "tools"
        sys.path.insert(0, str(ROOT / "tools"))
        import winn_release_testkit as testkit
        testkit.install_racing_driver(tools)
        genuine, attacker = {}, {}
        for arch, out_arch in ARCHES.items():
            genuine[f"datapath-windows-{arch}"] = ("winn-datapath.exe", self.source_bytes(f"datapath-windows-{arch}"))
            attacker[f"datapath-windows-{arch}"] = ("winn-datapath.exe", compiled_go_pe("core", out_arch, build_id=True))
            genuine[f"winn3-relay-windows-{arch}"] = ("winsvpn_winn3_engine.exe", self.source_bytes(f"winn3-relay-windows-{arch}"))
            attacker[f"winn3-relay-windows-{arch}"] = ("winsvpn_winn3_engine.exe", compiled_go_pe("relay", out_arch, build_id=False))
        release, genuine_dir, attacker_dir = testkit.prepare_race(self.tmp / "race", genuine, attacker)
        env_extra = testkit.race_environment(genuine_dir, attacker_dir, self.log)
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin", "HOME": str(self.tmp), "TMPDIR": str(self.tmp),
            "FAKE_WINN_SOURCE": str(self.source), **env_extra,
        }
        result = subprocess.run(["bash", str(tools / SCRIPT.name), "--release", str(release)],
                                capture_output=True, text=True, env=env, check=False)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_none_staged()
        # The same racing driver with the directory left genuine stages fine.
        shutil.rmtree(self.tmp / "race")
        release, genuine_dir, _ = testkit.prepare_race(self.tmp / "race", genuine, attacker)
        env.update(testkit.race_environment(genuine_dir, genuine_dir, self.log))
        result = subprocess.run(["bash", str(tools / SCRIPT.name), "--release", str(release)],
                                capture_output=True, text=True, env=env, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_all_staged()

    def test_destination_that_became_a_directory_is_refused(self) -> None:
        # Astra SEALED-T2 follow-up: `mv -f` moved the image inside a directory
        # at the destination and staging still passed. rename(2) refuses.
        release = self.make_release()
        blocker = self.staged("arm64", "winsvpn_winn3_engine.exe")
        blocker.mkdir(parents=True)
        result = self.run_script("--release", str(release))
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("STAGING: PASS", result.stdout)
        self.assertEqual(list(blocker.iterdir()), [])
        hidden = [p for p in self.engine_root.rglob(".*") if p.is_file()]
        self.assertEqual(hidden, [], "pending copies must not be left behind")

    def test_pending_copies_are_created_exclusively(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        function = text[text.index("exclusive_pending_copy() {"):]
        function = function[:function.index("\n}\n") + 3]
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        source = tmp / "image.exe"
        source.write_bytes(b"MZ verified image")
        destination = tmp / "dest"
        destination.mkdir()
        probe = 'python_bin=/usr/bin/python3\n' + function + 'exclusive_pending_copy "$1" "$2" "$3"\n'
        result = subprocess.run(["bash", "-c", probe, "probe", str(source), str(destination), "winn-datapath.exe"],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        staged = Path(result.stdout.strip())
        self.assertEqual(staged.parent, destination)
        self.assertTrue(staged.name.startswith(".winn-datapath.exe."))
        self.assertEqual(staged.read_bytes(), b"MZ verified image")
        link_dir = tmp / "linked"
        link_dir.symlink_to(destination, target_is_directory=True)
        result = subprocess.run(["bash", "-c", probe, "probe", str(source), str(link_dir), "winn-datapath.exe"],
                                capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)

    def test_release_mode_rejects_dev_arguments(self) -> None:
        result = self.run_script("--release", str(self.make_release()), "--source-commit", COMMIT)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.driver_calls(), [])

    def test_dev_mode_builds_through_the_driver_and_stages_unsigned(self) -> None:
        result = self.run_script("--source-commit", COMMIT, "--", "--jobs", "2")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.driver_calls()
        self.assertEqual(calls[0][:4], ["build", "--set", "windows", "--out"])
        out = calls[0][4]
        self.assertTrue(out.startswith(str(self.tmp)) and out.endswith("/rel"), out)
        self.assertEqual(calls[0][5:], ["--source-commit", COMMIT, "--jobs", "2"])
        self.assertEqual(calls[1:], [["verify", "--release", out, "--allow-unsigned", "--print-manifest"]])
        self.assert_all_staged()
        self.assertFalse(Path(out).exists(), "the unsigned dev release must be cleaned up")
        self.assertIn("UNSIGNED dev build", result.stdout)

    def test_dev_build_failure_fails_with_the_driver_status(self) -> None:
        for scenario, status in (("build_toolchain_missing", 3), ("build_fail", 1)):
            with self.subTest(scenario=scenario):
                result = self.run_script("--source-commit", COMMIT, scenario=scenario)
                self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                self.assertIn("release driver build failed", result.stderr)
                self.assert_none_staged()

    def test_malformed_source_commit_is_refused(self) -> None:
        result = self.run_script("--source-commit", "HEAD")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.driver_calls(), [])


class SourceContractTests(unittest.TestCase):
    def test_build_failure_is_never_ignored(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn(">/dev/null 2>&1 || true", text)
        self.assertNotIn("build_winn_protocol_engine.sh\" \\", text)
        self.assertIn('declare -a architectures=("amd64" "arm64")', text)

    def test_dropped_gate_is_gone_from_the_windows_path(self) -> None:
        for retired in (
            "tools/produce_windows_winn3_artifacts.sh",
            "tools/windows_winn3_owner_authorization.py",
            "tools/test_windows_winn3_owner_authorization.py",
            "tools/windows_winn3_producer_witness.py",
            "tools/build_macos_windows_winn3_ledger_bootstrap.sh",
            "tools/macos_windows_winn3_ledger_bootstrap.c",
            "tools/windows_winn3_owner_authorization.trust.json",
            "tools/winn3_authorization_ledger.py",
            "tools/windows_winn3_fixed_loader.c",
            "tools/build_windows_winn3_fixed_loader.sh",
            "tools/windows_winn3_release_python_custody.py",
        ):
            self.assertFalse((ROOT / retired).exists(), retired)
        for path in (SCRIPT, ROLE_TOOL, INSTALLER):
            text = path.read_text(encoding="utf-8")
            for dropped in (
                "WINS_RETAINED_",
                "ReleaseWindowsWinn3Authority",
                "authorization-ledger",
                "consumption-ledger",
                "/dev/fd/",
                "owner_authorization",
                "verify-sealed-pair",
            ):
                self.assertNotIn(dropped, text, f"{path.name}: {dropped}")

    def test_installer_pins_the_role_checker_and_verifies_the_release(self) -> None:
        text = INSTALLER.read_text(encoding="utf-8")
        digest = hashlib.sha256(ROLE_TOOL.read_bytes()).hexdigest()
        self.assertIn(f"$Winn3ArtifactProvenanceToolSha256 = '{digest}'", text)
        self.assertIn("$releaseTool.Path, 'verify', '--release', $releaseRoot, '--print-manifest'", text)
        self.assertNotIn("'--print-artifact'", text)
        # Digests come from the verified stdout, never from a reread manifest.
        self.assertIn("$manifest = ([string]$verification.Stdout[0]) | ConvertFrom-Json", text)
        self.assertNotIn("Join-Path $releaseRoot 'manifest.json'", text)
        self.assertEqual(text.count("Invoke-Winn3PythonTool -Python $python -Arguments $verifyArguments"), 1)
        self.assertIn('$relayTarget = "winn3-relay-windows-$($script:WindowsAwgGoArch)"', text)
        self.assertNotIn("Winn3RelayDir", text)
        self.assertIn("-AllowUnsignedWinnRelease is refused on a build that must be signed.", text)
        self.assertIn("Assert-Winn3CompiledRole -Python $python -Tool $roleTool.Path -Role 'core'", text)
        self.assertIn("Assert-Winn3CompiledRole -Python $python -Tool $roleTool.Path -Role 'relay'", text)

    def test_signed_installer_requires_a_psf_signed_verifier_python(self) -> None:
        text = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("$python = Get-Winn3VerifierPython -RequirePsfSignature $mustSign", text)
        function = text[text.index("function Get-Winn3VerifierPython {"):]
        function = function[:function.index("\n}\n") + 3]
        for needle in (
            "Get-AuthenticodeSignature -LiteralPath $pythonPath",
            "[Management.Automation.SignatureStatus]::Valid",
            "(^|, )(CN|O)=Python Software Foundation(,|$)",
            "\\\\WindowsApps\\\\",
        ):
            self.assertIn(needle, function, needle)

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell is needed")
    def test_verifier_python_selection_runs_in_powershell(self) -> None:
        # The real function, with a stand-in Get-AuthenticodeSignature (absent
        # off Windows) and a stand-in python.exe on PATH.
        text = INSTALLER.read_text(encoding="utf-8")
        function = text[text.index("function Get-Winn3VerifierPython {"):]
        function = function[:function.index("\n}\n") + 3]
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        python = tmp / "python.exe"
        python.write_text("#!/bin/sh\n")
        python.chmod(0o755)
        script = tmp / "probe.ps1"
        script.write_text(function + r"""
$ErrorActionPreference = 'Stop'
function Get-AuthenticodeSignature { param([string]$LiteralPath)
    [pscustomobject]@{ Status = [Management.Automation.SignatureStatus]$env:PROBE_STATUS;
                       SignerCertificate = [pscustomobject]@{ Subject = $env:PROBE_SUBJECT } } }
try { $p = Get-Winn3VerifierPython -RequirePsfSignature ([bool]::Parse($env:PROBE_REQUIRE)); "OK $p" }
catch { "REFUSED $($_.Exception.Message)" }
""")
        cases = (
            ("False", "NotSigned", "", "OK "),
            ("True", "Valid", "CN=Python Software Foundation, O=Python Software Foundation", "OK "),
            ("True", "NotSigned", "", "REFUSED "),
            ("True", "Valid", "CN=Someone Else, O=Someone Else", "REFUSED "),
            ("True", "HashMismatch", "CN=Python Software Foundation", "REFUSED "),
        )
        for require, status, subject, expected in cases:
            with self.subTest(require=require, status=status, subject=subject):
                env = {"PATH": f"{tmp}:/usr/bin:/bin", "HOME": str(tmp), "PROBE_REQUIRE": require,
                       "PROBE_STATUS": status, "PROBE_SUBJECT": subject}
                result = subprocess.run([shutil.which("pwsh") or "pwsh", "-NoProfile", "-NonInteractive", "-File", str(script)],
                                        capture_output=True, text=True, env=env, check=False, timeout=120)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(result.stdout.strip().startswith(expected), result.stdout + result.stderr)

    def test_installer_stages_winn_images_with_exclusive_creation(self) -> None:
        text = INSTALLER.read_text(encoding="utf-8")
        self.assertNotIn("Copy-Item -LiteralPath $verifiedImages['core'].Path", text)
        self.assertNotIn("Copy-Item -LiteralPath $verifiedImages['relay'].Path", text)
        self.assertIn("Copy-WinsExclusiveFile -Source $verifiedImages['core'].Path -Destination $WinnEngineArtifact", text)
        self.assertIn("Copy-WinsExclusiveFile -Source $verifiedImages['relay'].Path -Destination $Winn3RelayArtifact", text)

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell is needed")
    def test_exclusive_stage_copy_runs_in_powershell(self) -> None:
        text = INSTALLER.read_text(encoding="utf-8")
        function = text[text.index("function Copy-WinsExclusiveFile {"):]
        function = function[:function.index("\n}\n") + 3]
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        source = tmp / "source.exe"
        source.write_bytes(b"MZ verified")
        existing = tmp / "existing.exe"
        existing.write_bytes(b"existing")
        victim = tmp / "victim"
        victim.write_bytes(b"victim")
        link = tmp / "link.exe"
        link.symlink_to(victim)
        dangling = tmp / "dangling.exe"
        dangling.symlink_to(tmp / "nowhere")
        script = tmp / "probe.ps1"
        script.write_text(function + r"""
$ErrorActionPreference = 'Stop'
foreach ($name in @('fresh.exe', 'existing.exe', 'link.exe', 'dangling.exe')) {
    try { Copy-WinsExclusiveFile -Source (Join-Path $env:PROBE_DIR 'source.exe') -Destination (Join-Path $env:PROBE_DIR $name); "OK $name" }
    catch { "REFUSED $name" }
}
""")
        result = subprocess.run([shutil.which("pwsh") or "pwsh", "-NoProfile", "-NonInteractive", "-File", str(script)],
                                capture_output=True, text=True, env={"PATH": "/usr/bin:/bin", "HOME": str(tmp),
                                                                     "PROBE_DIR": str(tmp)},
                                check=False, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.split(), ["OK", "fresh.exe", "REFUSED", "existing.exe", "REFUSED",
                                                 "link.exe", "REFUSED", "dangling.exe"])
        self.assertEqual((tmp / "fresh.exe").read_bytes(), b"MZ verified")
        self.assertEqual(existing.read_bytes(), b"existing")
        self.assertEqual(victim.read_bytes(), b"victim")
        self.assertFalse((tmp / "nowhere").exists())

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell is needed")
    def test_installer_parses(self) -> None:
        command = ("$e = $null; $t = $null; [void][System.Management.Automation.Language.Parser]::ParseFile("
                   f"'{INSTALLER}', [ref]$t, [ref]$e); $e.Count")
        result = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-Command", command],
                                capture_output=True, text=True, check=False, timeout=300)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "0")

    def test_no_long_dashes_in_lane_files(self) -> None:
        dashes = (chr(0x2013), chr(0x2014))
        for path in (SCRIPT, ROLE_TOOL, Path(__file__), INSTALLER):
            text = path.read_text(encoding="utf-8")
            for dash in dashes:
                self.assertNotIn(dash, text, path.name)

if __name__ == "__main__":
    unittest.main()
