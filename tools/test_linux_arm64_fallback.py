#!/usr/bin/env python3
"""Source and artifact contracts for Linux arm64 Winn v3 + AWG/Xray fallback.

Owner contract: Linux x86_64 and arm64 both ship standalone Winn v3 primary
plus trusted-hub Winn v1 AmneziaWG/Xray fallback. Silently omitting the
fallback on arm64 is a refusal, not a valid release.
"""

from __future__ import annotations

import calendar
import contextlib
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import test_linux_arm64_fallback_elf as elf  # noqa: E402
from test_linux_arm64_fallback_elf import (  # noqa: E402
    AWG_GO_LINUX_AMD64_SHA256,
    AWG_GO_LINUX_ARM64_SHA256,
    AWG_LINUX_ARM64_SHA256,
    AWG_QUICK_SOURCE_SHA256,
    AWG_QUICK_SHA256,
    EM_AARCH64,
    ET_DYN,
    FallbackElfError,
    XRAY_LINUX_ARM64_SHA256,
    _structural_elf64_fixture,
    verify_awg_quick,
)

PRODUCER = (ROOT / "tools/build_linux_release.sh").read_text(encoding="utf-8")
XRAY_ENGINE = (ROOT / "tools/build_xray_engine.sh").read_text(encoding="utf-8")
AWG_PRODUCER = (ROOT / "tools/build_linux_arm64_awg.sh").read_text(encoding="utf-8")
INSTALLER = (ROOT / "linux/packaging/install.sh").read_text(encoding="utf-8")
BACKEND = (ROOT / "linux/runner/linux_tunnel_backend.cc").read_text(encoding="utf-8")
APT_PINS = (ROOT / "tools/linux_apt_pins.json").read_text(encoding="utf-8")
GO_HOST_LINUX_ARM64 = (
    "3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec"
)
AWG_TOOLS_SOURCE_SHA256 = (
    "dbd8ce0748d835d18f30bb76720246b7bfc80bd09cd17c379b1c59f683a18493"
)
X64_XRAY = "09e63d5420f26db2bc6144f6d047601909541acf21792878d3859e4fc4980a12"
CLANG_PIN_KEY = "tools.linux.arm64.clang_executable_sha256"
INDEX_CREATED_UTC = "2026-10-09T11:22:33.987654Z"
INDEX_EPOCH = calendar.timegm((2026, 10, 9, 11, 22, 33, 0, 0, 0))


def _awg_functions() -> str:
    """Every top-level shell function of the arm64 AWG producer, verbatim."""
    return "".join(
        match.group(0)
        for match in re.finditer(
            r"^[a-z_][a-z0-9_]*\(\) \{\n.*?^\}\n", AWG_PRODUCER, re.M | re.S
        )
    )


def _awg_constants() -> str:
    """Every top-level quoted constant assignment of the arm64 AWG producer."""
    return "".join(
        match.group(0)
        for match in re.finditer(r'^[A-Z][A-Z0-9_]*="[^"$`]*"\n', AWG_PRODUCER, re.M)
    )


def _awg_reproduce_block() -> str:
    start = AWG_PRODUCER.index('if [[ "${WINS_LINUX_ARM64_AWG_REPRODUCE:-0}" == "1" ]]; then\n')
    end = AWG_PRODUCER.index("\nfi\n", start) + len("\nfi\n")
    return AWG_PRODUCER[start:end]


def _release_index(created_utc: str = INDEX_CREATED_UTC, **extra: object) -> dict[str, object]:
    record: dict[str, object] = {
        "schema_version": 1,
        "contract": "winsvpn-release-input-index-v1",
        "release": "fixture",
        "shared_revision": "0" * 40,
        "created_utc": created_utc,
        "shared_manifest": {"path": "shared.json", "sha256": "1" * 64},
        "platform_manifests": {"linux": {"path": "linux.json", "sha256": "2" * 64}},
        "sha256_anchor": "index.json.sha256",
        "manifest_set_complete": True,
        "publication_authorized": False,
    }
    record.update(extra)
    return record


class AwgProducerFixture:
    """A copy of the arm64 AWG producer next to fixture pins and a stub PATH."""

    def __init__(self, root: pathlib.Path, *, clang_pin: object = None, pins_text: str | None = None) -> None:
        self.root = root
        tools = root / "tools"
        tools.mkdir()
        self.script = tools / "build_linux_arm64_awg.sh"
        shutil.copyfile(ROOT / "tools/build_linux_arm64_awg.sh", self.script)
        if pins_text is None:
            document: dict[str, object] = {"schema_version": 1, "tools": {}}
            if clang_pin is not None:
                document["tools"] = {"linux": {"arm64": {"clang_executable_sha256": clang_pin}}}
            pins_text = json.dumps(document)
        (tools / "toolchain-pins.json").write_text(pins_text, encoding="utf-8")
        self.index = root / "index.json"
        self.write_index(_release_index())
        self.bin = root / "bin"
        self.bin.mkdir()
        stub = self.bin / "uname"
        stub.write_text("#!/bin/sh\nprintf 'FixtureOS\\n'\n", encoding="utf-8")
        stub.chmod(0o755)

    def write_index(self, record: dict[str, object]) -> None:
        self.index.write_text(json.dumps(record), encoding="utf-8")
        self.index.chmod(0o644)

    def run(self, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
        environment = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "HOME": str(self.root),
            "TMPDIR": str(self.root),
            "WINS_RELEASE_INPUT_INDEX": str(self.index),
        }
        environment.update(env)
        environment = {key: value for key, value in environment.items() if value is not None}
        return subprocess.run(
            ["/bin/bash", str(self.script), *args],
            cwd=self.root,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )


class LinuxArm64FallbackContractTests(unittest.TestCase):
    def test_producer_no_longer_omits_arm64_fallback(self) -> None:
        self.assertNotIn("Omitting Xray from the linux-", PRODUCER)
        self.assertNotIn("Omitting AmneziaWG triple from the linux-", PRODUCER)
        self.assertIn('bash "$ROOT/tools/build_xray_engine.sh" "linux-${LINUX_RELEASE_GOARCH}"', PRODUCER)
        self.assertIn("tools/build_linux_arm64_awg.sh", PRODUCER)
        self.assertIn(XRAY_LINUX_ARM64_SHA256, PRODUCER)
        self.assertIn(AWG_LINUX_ARM64_SHA256, PRODUCER)
        self.assertIn(AWG_GO_LINUX_ARM64_SHA256, PRODUCER)
        self.assertIn(AWG_QUICK_SHA256, PRODUCER)
        self.assertIn(AWG_QUICK_SOURCE_SHA256, PRODUCER)
        self.assertIn('GO_VERSION="1.27.1"', PRODUCER)
        self.assertIn('AWG_GO_COMMIT="b5928efb6ca19f0153958460c3d141f04abc5c2e"', PRODUCER)
        self.assertIn('AWG_TOOLS_VERSION="v3.1.20260812"', PRODUCER)
        self.assertIn(
            'AWG_TOOLS_COMMIT="ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"',
            PRODUCER,
        )

    def test_xray_engine_has_linux_arm64_host_go_pin(self) -> None:
        self.assertIn(f'GO_HOST_SHA256_LINUX_ARM64="{GO_HOST_LINUX_ARM64}"', XRAY_ENGINE)
        self.assertIn("linux-arm64) printf 'linux arm64 %s\\n' \"${GO_HOST_SHA256_LINUX_ARM64}\"", XRAY_ENGINE)
        self.assertIn("test_linux_arm64_fallback_elf.py", XRAY_ENGINE)

    def test_awg_producer_pins_source_and_output(self) -> None:
        real_pin = (
            json.loads((ROOT / "tools/toolchain-pins.json").read_text(encoding="utf-8"))
            .get("tools", {})
            .get("linux", {})
            .get("arm64", {})
            .get("clang_executable_sha256")
        )
        self.assertIn('readonly LINUX_SYSTEM_PYTHON="/usr/bin/python3"', AWG_PRODUCER)
        self.assertIn('readonly -f python3', AWG_PRODUCER)
        hostile = subprocess.run(
            [
                "bash",
                "-c",
                "python3(){ printf 'WINSVPN_HOSTILE_PYTHON_EXECUTED\\n' >&2; "
                "exit 0; }; export -f python3; exec bash \"$1\" --self-test-pins",
                "_",
                str(ROOT / "tools/build_linux_arm64_awg.sh"),
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(hostile.returncode, 65 if real_pin is None else 0, hostile.stderr)
        self.assertNotIn("WINSVPN_HOSTILE_PYTHON_EXECUTED", hostile.stderr)
        if real_pin is None:
            self.assertNotIn("PASS", hostile.stdout + hostile.stderr)

        self.assertIn(f'AWG_TOOLS_VERSION="v3.1.20260812"', AWG_PRODUCER)
        self.assertIn('AWG_TOOLS_COMMIT="ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"', AWG_PRODUCER)
        self.assertIn(f'AWG_TOOLS_SOURCE_SHA256="{AWG_TOOLS_SOURCE_SHA256}"', AWG_PRODUCER)
        self.assertIn(
            'AWG_TOOLS_UBUNTU_ZIP_SHA256="919e9d0a367c7c72f9c16b7d0a9e4840b943628353b2210a33cb4b582785ba56"',
            AWG_PRODUCER,
        )
        self.assertIn('AWG_GO_TAG="v3.1.20260828"', AWG_PRODUCER)
        self.assertIn(
            'AWG_GO_COMMIT="b5928efb6ca19f0153958460c3d141f04abc5c2e"',
            AWG_PRODUCER,
        )
        self.assertIn(
            'AWG_GO_SOURCE_SHA256="10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4"',
            AWG_PRODUCER,
        )
        self.assertIn(f'AWG_BINARY_SHA256="{AWG_LINUX_ARM64_SHA256}"', AWG_PRODUCER)
        self.assertIn(f'AWG_QUICK_SHA256="{AWG_QUICK_SHA256}"', AWG_PRODUCER)
        self.assertIn(
            f'AWG_QUICK_SOURCE_SHA256="{AWG_QUICK_SOURCE_SHA256}"', PRODUCER
        )
        self.assertIn("HPK requires the exact in-bundle reviewed userspace engine", AWG_PRODUCER)
        self.assertNotIn("run_with_retained_source_custody", AWG_PRODUCER)
        self.assertIn(
            "Compiler-consumed amneziawg-tools source does not match the authenticated source tree.",
            AWG_PRODUCER,
        )
        self.assertIn('\\tcmd "$implementation" "$INTERFACE"', AWG_PRODUCER)
        self.assertIn('local implementation="${{SELF%/*}}/amneziawg-go"', AWG_PRODUCER)
        self.assertNotIn('WG_QUICK_USERSPACE_IMPLEMENTATION:-', AWG_PRODUCER)
        self.assertIn('CC="${CLANG_HELD_PATH}"', AWG_PRODUCER)
        self.assertIn("Cross-compiling would change the pinned bytes", AWG_PRODUCER)
        self.assertIn("Environment CFLAGS so Makefile CFLAGS += still adds", AWG_PRODUCER)
        self.assertNotIn("--emit-owner-release-controls", AWG_PRODUCER)
        # Real host and pin checks refuse plainly with exit 65; no owner-blocked 78 path remains.
        self.assertNotIn("OWNER-BLOCKED", AWG_PRODUCER)
        self.assertIsNone(re.search(r"\b(?:exit|return)\s+78\b", AWG_PRODUCER))
        self.assertNotIn('bash "${SCRIPT_DIR}/build_linux_release.sh"', AWG_PRODUCER)
        self.assertIn('"${SCRIPT_DIR}/toolchain-pins.json"', AWG_PRODUCER)
        completed = subprocess.run(
            ["bash", str(ROOT / "tools/build_linux_arm64_awg.sh"), "--self-test-pins"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotIn("OWNER-BLOCKED", completed.stdout + completed.stderr)
        if real_pin is None:
            # Not measured yet: refuse plainly and name the missing pin.
            self.assertEqual(completed.returncode, 65, completed.stderr)
            self.assertIn(
                f"missing pin: {CLANG_PIN_KEY} is absent from tools/toolchain-pins.json",
                completed.stderr,
            )
            self.assertNotIn("PASS", completed.stdout + completed.stderr)
        else:
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn(f"REVIEWED_CLANG_SHA256={real_pin}", completed.stdout)
        arbitrary = subprocess.run(
            ["bash", str(ROOT / "tools/build_linux_arm64_awg.sh"), "--self-test-pins"],
            cwd=ROOT,
            env={**os.environ, "WINS_LINUX_ARM64_CLANG_SHA256": "0" * 64},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(arbitrary.returncode, 65, arbitrary.stderr)
        self.assertNotIn("PASS", arbitrary.stdout + arbitrary.stderr)

    def test_installer_and_runtime_pin_arm64_hashes_but_remain_owner_blocked(self) -> None:
        installer_arm = INSTALLER[INSTALLER.index("aarch64|arm64") :].split(";;", 1)[0]
        self.assertIn(f"AWG_SHA256={AWG_LINUX_ARM64_SHA256}", installer_arm)
        self.assertIn(f"AWG_GO_SHA256={AWG_GO_LINUX_ARM64_SHA256}", installer_arm)
        self.assertIn(f"XRAY_SHA256={XRAY_LINUX_ARM64_SHA256}", installer_arm)
        self.assertNotIn(X64_XRAY, installer_arm)
        self.assertIn(f"AWG_SHA256={AWG_LINUX_ARM64_SHA256}", BACKEND)
        self.assertIn(f"AWG_GO_SHA256={AWG_GO_LINUX_ARM64_SHA256}", BACKEND)
        self.assertIn(f"XRAY_SHA256={XRAY_LINUX_ARM64_SHA256}", BACKEND)
        self.assertNotIn("AmneziaWG/Xray pins deliberately left empty", BACKEND)
        self.assertNotIn("WG_QUICK_USERSPACE_IMPLEMENTATION", AWG_PRODUCER)
        self.assertIn('WG_QUICK_USERSPACE_IMPLEMENTATION="$BUNDLE_DIR/amneziawg-go"', BACKEND)
        self.assertIn("export WG_QUICK_USERSPACE_IMPLEMENTATION", BACKEND)
        checked = subprocess.run(
            ["bash", str(ROOT / "tools/build_linux_release.sh"), "--self-test-userspace-awg-runtime-pin"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn("LINUX USERSPACE AWG RUNTIME PIN: PASS", checked.stdout)
        self.assertNotIn("OWNER-BLOCKED", checked.stdout + checked.stderr)

    def test_installer_requires_complete_fallback_on_every_arch(self) -> None:
        self.assertNotIn("none bundled (arch with no AmneziaWG build)", INSTALLER)
        self.assertIn("Linux x86_64 and arm64 both require the AmneziaWG triple", INSTALLER)
        self.assertIn('die "The extracted release is missing the required Xray runtime."', INSTALLER)
        self.assertIn(
            "for required_executable in xray awg awg-quick amneziawg-go winn-datapath",
            INSTALLER,
        )

    def test_producer_requires_fallback_executables_in_the_archive(self) -> None:
        self.assertIn("required_fallback_missing", PRODUCER)
        self.assertIn("for required_bin in xray awg awg-quick amneziawg-go winn-datapath", PRODUCER)
        self.assertIn("assert_mandatory_dependencies_available_for_arch", PRODUCER)
        self.assertIn("amd64|arm64) return 0", PRODUCER)
        self.assertIn(
            'test_linux_arm64_fallback_elf.py" verify awg-quick',
            PRODUCER,
        )

    def test_apt_pins_keep_the_awg_compile_host_packages(self) -> None:
        self.assertIn('"make"', APT_PINS)
        self.assertIn('"libc6-dev"', APT_PINS)

    def test_elf_self_test(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(ROOT / "tools/test_linux_arm64_fallback_elf.py"), "--self-test"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)

    def test_final_artifact_pass_is_structure_plus_pinned_sha256(self) -> None:
        self.assertNotIn("WINS_TEST_REAL_LINUX_ARM64_FALLBACK", AWG_PRODUCER)

        def run_cli(argv: list[str]) -> tuple[int, str, str]:
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = elf._cli(argv)
            return code, out.getvalue(), err.getvalue()

        with tempfile.TemporaryDirectory() as name:
            path = pathlib.Path(name) / "awg"
            data = _structural_elf64_fixture(
                machine=EM_AARCH64, elf_type=ET_DYN, interp=b"/lib/ld-linux-aarch64.so.1"
            ) + b"3.1.20260812"
            path.write_bytes(data)
            path.chmod(0o755)
            digest = hashlib.sha256(data).hexdigest()
            with mock.patch.object(elf, "AWG_LINUX_ARM64_SHA256", digest):
                code, out, err = run_cli(["verify", "awg", str(path), "--sha256", digest])
                self.assertEqual(code, 0, err)
                self.assertIn(f"LINUX ARM64 FALLBACK awg: PASS sha256={digest}", out)
                code, out, err = run_cli(["verify", "awg", str(path)])
                self.assertEqual(code, 0, err)
                self.assertIn("PASS", out)
            code, out, err = run_cli(["verify", "awg", str(path)])
            self.assertEqual(code, 65)
            self.assertIn("SHA-256 drift", err)
            self.assertNotIn("PASS", out)
            with mock.patch.object(elf, "verify_linux_arm64_fallback_dir", return_value={}) as checked:
                code, out, err = run_cli(["verify-dir", name])
            self.assertEqual(code, 0, err)
            self.assertIn("LINUX ARM64 FALLBACK DIR: PASS", out)
            checked.assert_called_once_with(pathlib.Path(name), check_hashes=True)
            refused = mock.Mock(side_effect=FallbackElfError("SHA-256 drift: fixture"))
            with mock.patch.object(elf, "verify_linux_arm64_fallback_dir", refused):
                code, out, err = run_cli(["verify-dir", name])
            self.assertEqual(code, 65)
            self.assertNotIn("PASS", out)

        elf_source = (ROOT / "tools/test_linux_arm64_fallback_elf.py").read_text(
            encoding="utf-8"
        )
        # The gate code without its unittest class, which names retired options
        # only to prove argparse now rejects them.
        elf_gate = (
            elf_source[: elf_source.index("class LinuxArm64FallbackElfTests")]
            + elf_source[elf_source.index("def _cli(") :]
        )
        for retired in (
            "linux-physical-execution",
            "/etc/winsvpn/release-signing",
            "consumption-ledger",
            "highest_consumed_sequence",
            "timedelta(minutes=15)",
            "--linux-execution-receipt",
            "--release-index-sha256",
            "OWNER-BLOCKED",
        ):
            self.assertNotIn(retired, elf_gate)
        for retired in (
            "linux-physical-execution",
            "--linux-execution-receipt",
            "--linux-execution-bundle",
            "--release-index-sha256",
        ):
            self.assertNotIn(retired, AWG_PRODUCER)
        self.assertIn(
            'test_linux_arm64_fallback_elf.py" verify awg \\\n'
            '  "${WORK_ROOT}/build1/awg" --sha256 "${AWG_BINARY_SHA256}"\n',
            AWG_PRODUCER,
        )

    def test_awg_self_test_pins_reads_the_clang_pin_directly(self) -> None:
        pin = "a" * 64
        with tempfile.TemporaryDirectory() as name:
            fixture = AwgProducerFixture(pathlib.Path(name), clang_pin=pin)
            passed = fixture.run("--self-test-pins")
            self.assertEqual(passed.returncode, 0, passed.stderr)
            self.assertIn("LINUX ARM64 AWG PINS: PASS", passed.stdout)
            self.assertIn(f"REVIEWED_CLANG_SHA256={pin}", passed.stdout)
            self.assertIn(f"AWG_GO_BINARY_SHA256_ARM64={AWG_GO_LINUX_ARM64_SHA256}", passed.stdout)
            matching = fixture.run("--self-test-pins", WINS_LINUX_ARM64_CLANG_SHA256=pin)
            self.assertEqual(matching.returncode, 0, matching.stderr)
            caller = fixture.run("--self-test-pins", WINS_LINUX_ARM64_CLANG_SHA256="b" * 64)
            self.assertEqual(caller.returncode, 65, caller.stderr)
            self.assertIn("does not match tools.linux.arm64.clang_executable_sha256", caller.stderr)
            self.assertNotIn("PASS", caller.stdout + caller.stderr)
        with tempfile.TemporaryDirectory() as name:
            fixture = AwgProducerFixture(pathlib.Path(name))
            missing = fixture.run("--self-test-pins")
            self.assertEqual(missing.returncode, 65, missing.stderr)
            self.assertIn(f"missing pin: {CLANG_PIN_KEY} is absent", missing.stderr)
            self.assertNotIn("OWNER-BLOCKED", missing.stderr)
            self.assertNotIn("PASS", missing.stdout + missing.stderr)
        for label, pins_text in (
            ("malformed", '{"tools":{"linux":{"arm64":{"clang_executable_sha256":"XYZ"}}}}'),
            ("duplicate", '{"tools":{},"tools":{"linux":{"arm64":{"clang_executable_sha256":"' + pin + '"}}}}'),
            ("nonfinite", '{"tools":{"linux":{"arm64":{"clang_executable_sha256":NaN}}}}'),
        ):
            with self.subTest(pins=label), tempfile.TemporaryDirectory() as name:
                fixture = AwgProducerFixture(pathlib.Path(name), pins_text=pins_text)
                refused = fixture.run("--self-test-pins")
                self.assertEqual(refused.returncode, 65, refused.stderr)
                self.assertNotIn("PASS", refused.stdout + refused.stderr)
        with tempfile.TemporaryDirectory() as name:
            fixture = AwgProducerFixture(pathlib.Path(name), clang_pin=pin)
            pins = fixture.root / "tools/toolchain-pins.json"
            real = fixture.root / "real-pins.json"
            pins.rename(real)
            pins.symlink_to(real)
            linked = fixture.run("--self-test-pins")
            self.assertEqual(linked.returncode, 65, linked.stderr)
            self.assertIn("not a single-link regular file", linked.stderr)

    def test_awg_producer_accepts_only_the_index_derived_source_date_epoch(self) -> None:
        reached = "must be compiled on Linux, not FixtureOS"
        with tempfile.TemporaryDirectory() as name:
            fixture = AwgProducerFixture(pathlib.Path(name), clang_pin="a" * 64)
            output = str(fixture.root / "out/awg")
            for caller_epoch in (None, str(INDEX_EPOCH)):
                with self.subTest(caller_epoch=caller_epoch):
                    completed = fixture.run(output, SOURCE_DATE_EPOCH=caller_epoch)
                    self.assertEqual(completed.returncode, 65, completed.stderr)
                    self.assertIn(f"BUILD LINUX ARM64 AWG ERROR: linux-arm64 awg {reached}", completed.stderr)
                    self.assertNotIn("OWNER-BLOCKED", completed.stderr)
                    self.assertNotIn("SOURCE_DATE_EPOCH", completed.stderr)
            for caller_epoch in (str(INDEX_EPOCH + 1), "0" + str(INDEX_EPOCH), ""):
                with self.subTest(caller_epoch=caller_epoch):
                    completed = fixture.run(output, SOURCE_DATE_EPOCH=caller_epoch)
                    self.assertEqual(completed.returncode, 65, completed.stderr)
                    self.assertIn(
                        f"differs from {INDEX_EPOCH} derived from the release input index created_utc",
                        completed.stderr,
                    )
                    self.assertNotIn(reached, completed.stderr)
            fixture.write_index(_release_index("2026-10-09T11:22:33Z"))
            whole = fixture.run(output, SOURCE_DATE_EPOCH=str(INDEX_EPOCH))
            self.assertEqual(whole.returncode, 65, whole.stderr)
            self.assertIn(reached, whole.stderr)

    def test_awg_producer_refuses_a_malformed_release_index_or_missing_pin(self) -> None:
        reached = "must be compiled on Linux, not FixtureOS"
        with tempfile.TemporaryDirectory() as name:
            fixture = AwgProducerFixture(pathlib.Path(name), clang_pin="a" * 64)
            output = str(fixture.root / "out/awg")
            no_index = fixture.run(output, WINS_RELEASE_INPUT_INDEX="")
            self.assertEqual(no_index.returncode, 65, no_index.stderr)
            self.assertIn("WINS_RELEASE_INPUT_INDEX is required", no_index.stderr)
            for label, record in (
                ("extra key", _release_index(extra_field=True)),
                ("not utc", _release_index("2026-10-09T11:22:33+02:00")),
                ("bad contract", _release_index(contract="other")),
                ("pre-epoch", _release_index("1969-12-31T23:59:59Z")),
            ):
                with self.subTest(index=label):
                    fixture.write_index(record)
                    refused = fixture.run(output)
                    self.assertEqual(refused.returncode, 65, refused.stderr)
                    self.assertIn("SOURCE_DATE_EPOCH", refused.stderr)
                    self.assertNotIn(reached, refused.stderr)
            fixture.index.write_text(
                json.dumps(_release_index())[:-1] + ', "created_utc": "2026-10-09T11:22:33Z"}',
                encoding="utf-8",
            )
            duplicate = fixture.run(output)
            self.assertEqual(duplicate.returncode, 65, duplicate.stderr)
            self.assertIn("duplicate release index key", duplicate.stderr)
            fixture.write_index(_release_index())
            for mode in (0o664, 0o646):
                with self.subTest(index_mode=oct(mode)):
                    fixture.index.chmod(mode)
                    writable = fixture.run(output)
                    self.assertEqual(writable.returncode, 65, writable.stderr)
                    self.assertIn("release input index is group/other-writable", writable.stderr)
                    self.assertNotIn(reached, writable.stderr)
            fixture.index.chmod(0o644)
            alias = fixture.root / "index-alias.json"
            os.link(fixture.index, alias)
            hard_linked = fixture.run(output)
            self.assertEqual(hard_linked.returncode, 65, hard_linked.stderr)
            self.assertIn("not a single-link regular file", hard_linked.stderr)
            alias.unlink()
            link = fixture.root / "index-link.json"
            link.symlink_to(fixture.index)
            symlinked = fixture.run(output, WINS_RELEASE_INPUT_INDEX=str(link))
            self.assertEqual(symlinked.returncode, 65, symlinked.stderr)
            self.assertIn("not a single-link regular file", symlinked.stderr)
            caller = fixture.run(output, WINS_LINUX_ARM64_CLANG_SHA256="b" * 64)
            self.assertEqual(caller.returncode, 65, caller.stderr)
            self.assertIn("does not match tools.linux.arm64.clang_executable_sha256", caller.stderr)
            self.assertNotIn(reached, caller.stderr)
        with tempfile.TemporaryDirectory() as name:
            fixture = AwgProducerFixture(pathlib.Path(name))
            missing = fixture.run(str(fixture.root / "out/awg"), SOURCE_DATE_EPOCH=str(INDEX_EPOCH))
            self.assertEqual(missing.returncode, 65, missing.stderr)
            self.assertIn(f"missing pin: {CLANG_PIN_KEY} is absent from tools/toolchain-pins.json", missing.stderr)
            self.assertNotIn("OWNER-BLOCKED", missing.stderr)
            self.assertNotIn(reached, missing.stderr)

    def _run_awg_harness(self, root: pathlib.Path, body: str, **env: str) -> subprocess.CompletedProcess[str]:
        harness = root / "harness.sh"
        harness.write_text(
            "set -Eeuo pipefail\n"
            'LINUX_SYSTEM_PYTHON="/usr/bin/python3"\n'
            'python3() { "${LINUX_SYSTEM_PYTHON}" -I "$@"; }\n'
            + _awg_constants()
            + _awg_functions()
            + body,
            encoding="utf-8",
        )
        environment = {
            "PATH": f"{root / 'bin'}:/usr/bin:/bin",
            "HOME": str(root),
            "TMPDIR": str(root),
            "FIXTURE": str(root),
            "MAKE_LOG": str(root / "make.log"),
        }
        environment.update(env)
        return subprocess.run(
            ["/bin/bash", str(harness)],
            cwd=root,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )

    def _awg_build_fixture(self, root: pathlib.Path) -> None:
        (root / "bin").mkdir()
        make = root / "bin/make"
        make.write_text(
            "#!/bin/sh\n"
            'printf \'%s|%s|%s\\n\' "$PWD" "$SOURCE_DATE_EPOCH" "$*" >> "$MAKE_LOG"\n'
            "printf 'awg-fixture-binary\\n' > wg\n"
            'if [ -n "${MAKE_NONDETERMINISTIC:-}" ]; then printf \'%s\\n\' "$$" >> wg; fi\n'
            "chmod 0755 wg\n",
            encoding="utf-8",
        )
        make.chmod(0o755)
        source = root / "src"
        (source / "uapi").mkdir(parents=True)
        (source / "wg.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
        (source / "uapi/wireguard.h").write_text("/* fixture */\n", encoding="utf-8")
        quick = root / "awg-quick-userspace"
        quick.write_text("#!/bin/bash\n", encoding="utf-8")
        quick.chmod(0o755)

    BUILD_PRELUDE = (
        'src="${FIXTURE}/src"\n'
        'userspace_quick="${FIXTURE}/awg-quick-userspace"\n'
        "SOURCE_DATE_EPOCH_PINNED=1791000000\n"
        'CLANG_HELD_PATH="${FIXTURE}/held-clang"\n'
        'WORK_ROOT="${FIXTURE}/work"\n'
        'source_tree_sha256="$(tree_sha256 "${src}")"\n'
    )

    def test_awg_compiler_runs_make_directly_with_input_pin_and_two_build_compare(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            self._awg_build_fixture(root)
            completed = self._run_awg_harness(
                root,
                self.BUILD_PRELUDE
                + 'build_one "${WORK_ROOT}/build1"\n'
                + "WINS_LINUX_ARM64_AWG_REPRODUCE=1\n"
                + _awg_reproduce_block(),
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("LINUX ARM64 AWG REPRODUCE: PASS", completed.stdout)
            calls = (root / "make.log").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(calls), 2, calls)
            for build, call in zip(("build1", "build2"), calls):
                cwd, epoch, argv = call.split("|")
                self.assertTrue(cwd.endswith(f"/work/{build}/src"), cwd)
                self.assertEqual(epoch, "1791000000")
                self.assertEqual(
                    argv,
                    "PLATFORM=linux WITH_WGQUICK=no WITH_BASHCOMPLETION=no "
                    f"WITH_SYSTEMDUNITS=no CC={root}/held-clang",
                )
            awg = root / "work/build1/awg"
            self.assertEqual(awg.read_bytes(), b"awg-fixture-binary\n")
            self.assertEqual(awg.stat().st_mode & 0o777, 0o755)
            self.assertEqual((root / "work/build1/awg-quick").read_bytes(), b"#!/bin/bash\n")

    def test_awg_compiler_refuses_changed_input_and_nonreproducible_output(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            self._awg_build_fixture(root)
            tampered = self._run_awg_harness(
                root,
                self.BUILD_PRELUDE
                + "printf 'tampered\\n' >> \"${src}/wg.c\"\n"
                + 'build_one "${WORK_ROOT}/build1"\n',
            )
            self.assertNotEqual(tampered.returncode, 0)
            self.assertIn(
                "Compiler-consumed amneziawg-tools source does not match the authenticated source tree.",
                tampered.stderr,
            )
            self.assertFalse((root / "make.log").exists())
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            self._awg_build_fixture(root)
            drifting = self._run_awg_harness(
                root,
                self.BUILD_PRELUDE
                + 'build_one "${WORK_ROOT}/build1"\n'
                + "WINS_LINUX_ARM64_AWG_REPRODUCE=1\n"
                + _awg_reproduce_block(),
                MAKE_NONDETERMINISTIC="1",
            )
            self.assertNotEqual(drifting.returncode, 0)
            self.assertIn("Two clean linux-arm64 awg builds were not byte-identical.", drifting.stderr)
            self.assertNotIn("REPRODUCE: PASS", drifting.stdout)

    def test_awg_quick_embeds_the_reviewed_arm64_engine_pin(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            source = root / "linux.bash"
            source.write_text(
                "#!/bin/bash\nset -e\n# ~~ function override insertion point ~~\ncmd() { :; }\n",
                encoding="utf-8",
            )
            destination = root / "awg-quick"
            completed = self._run_awg_harness(
                root,
                f'write_userspace_only_awg_quick "{source}" "{destination}"\n',
                PATH="/usr/bin:/bin",
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = destination.read_bytes()
            self.assertEqual(completed.stdout.strip(), hashlib.sha256(payload).hexdigest())
            self.assertIn(
                f'\t\taarch64|arm64) expected_engine_sha256="{AWG_GO_LINUX_ARM64_SHA256}" ;;\n'.encode(),
                payload,
            )
            self.assertIn(
                f'\t\tx86_64|amd64) expected_engine_sha256="{AWG_GO_LINUX_AMD64_SHA256}" ;;\n'.encode(),
                payload,
            )
            destination.chmod(0o755)
            verify_awg_quick(destination, expected_sha256=None)
        self.assertIn(f'AWG_GO_BINARY_SHA256_ARM64="{AWG_GO_LINUX_ARM64_SHA256}"', AWG_PRODUCER)
        self.assertIn(f'AWG_GO_BINARY_SHA256_ARM64="{AWG_GO_LINUX_ARM64_SHA256}"', PRODUCER)
        self.assertIn(f'AWG_GO_BINARY_SHA256_AMD64="{AWG_GO_LINUX_AMD64_SHA256}"', AWG_PRODUCER)


if __name__ == "__main__":
    unittest.main()
