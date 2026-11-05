#!/usr/bin/env python3
"""Hostile tests for the fixed macOS ReleasePython native launcher."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import tempfile
import textwrap
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/macos_release_python_owner_launcher.c"
BUILD = ROOT / "tools/build_macos_release_python_owner_launcher.sh"
RUNTIME = Path("/Library/WinsVPN/ReleasePython/3.14.7")
RUNTIME_PYTHON = RUNTIME / "Python.framework/Versions/3.14/bin/python3.14"
RUNTIME_LAUNCHER = RUNTIME / "launcher/python3.14"
CLANG = Path(
    "/Applications/Xcode.app/Contents/Developer/Toolchains/"
    "XcodeDefault.xctoolchain/usr/bin/clang"
)
LINKER = CLANG.with_name("ld")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def receipt_tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()

    def feed(*parts: object) -> None:
        for part in parts:
            value = str(part).encode("utf-8", "surrogateescape")
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)

    def walk(directory: Path) -> None:
        with os.scandir(directory) as scan:
            entries = sorted(scan, key=lambda item: os.fsencode(item.name))
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            info = os.stat(entry, follow_symlinks=False)
            mode = stat.S_IMODE(info.st_mode)
            flags = int(getattr(info, "st_flags", 0))
            if stat.S_ISLNK(info.st_mode):
                feed("L", relative, os.readlink(path))
            elif stat.S_ISDIR(info.st_mode):
                feed("D", relative, mode, flags)
                walk(path)
            elif stat.S_ISREG(info.st_mode):
                feed("F", relative, mode, info.st_size, sha256(path), flags)
            else:
                raise AssertionError(f"unexpected fixture node: {path}")

    walk(root)
    return digest.hexdigest()


CONTROLLER = r'''#!/usr/bin/env python3
import json
import os
import socket
import struct
import sys

cap_fd = int(os.environ.pop("WINS_OWNER_CAPABILITY_FD"))
controller_fd = int(os.environ.pop("WINS_OWNER_CONTROLLER_FD"))
if cap_fd != 198 or controller_fd != 199:
    raise SystemExit("descriptor mismatch")
if sys.argv[1:] == ["recover"]:
    os.close(cap_fd)
    left, right = socket.socketpair()
    os.dup2(left.fileno(), cap_fd)
    raise SystemExit(0)
channel = socket.socket(fileno=cap_fd)
header = channel.recv(4)
if len(header) != 4:
    raise SystemExit("short capability header")
length = struct.unpack("!I", header)[0]
payload = b""
while len(payload) < length:
    chunk = channel.recv(length - len(payload))
    if not chunk:
        raise SystemExit("short capability payload")
    payload += chunk
record = dict(line.split("=", 1) for line in payload.decode("ascii").splitlines())
print(json.dumps(record, sort_keys=True, separators=(",", ":")), flush=True)
channel.sendall(("READY " + record["nonce"] + "\n").encode("ascii"))
expected = ("GO " + record["nonce"] + "\n").encode("ascii")
if channel.recv(len(expected)) != expected:
    raise SystemExit("missing capability grant")
channel.sendall(("PING " + record["nonce"] + "\n").encode("ascii"))
expected = ("PONG " + record["nonce"] + "\n").encode("ascii")
if channel.recv(len(expected)) != expected:
    raise SystemExit("missing capability liveness")
channel.close()
'''

FIXTURE_RUNTIME_SOURCE = r'''
#define _DARWIN_C_SOURCE 1
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static void exact_read(int fd, void *buffer, size_t length) {
    unsigned char *cursor = buffer;
    while (length > 0) {
        ssize_t count = read(fd, cursor, length);
        if (count <= 0) _exit(90);
        cursor += count;
        length -= (size_t)count;
    }
}

static void exact_write(int fd, const void *buffer, size_t length) {
    const unsigned char *cursor = buffer;
    while (length > 0) {
        ssize_t count = write(fd, cursor, length);
        if (count <= 0) _exit(91);
        cursor += count;
        length -= (size_t)count;
    }
}

static void read_line(int fd, char *buffer, size_t capacity) {
    size_t used = 0;
    while (used + 1 < capacity) {
        exact_read(fd, buffer + used, 1);
        if (buffer[used++] == '\n') break;
    }
    buffer[used] = '\0';
}

int main(int argc, char **argv) {
    const char *capability_text = getenv("WINS_OWNER_CAPABILITY_FD");
    const char *controller_text = getenv("WINS_OWNER_CONTROLLER_FD");
    const char *runtime_text = getenv("WINS_OWNER_RUNTIME_FD");
    int capability, controller, runtime;
    uint32_t network_length, length;
    char payload[4096], nonce[65], ready[96], line[96];
    const char *nonce_field, *end, *action, *plan = "";
    if (argc < 5 || capability_text == NULL || controller_text == NULL ||
        runtime_text == NULL) return 92;
    capability = atoi(capability_text);
    controller = atoi(controller_text);
    runtime = atoi(runtime_text);
    if (capability != 198 || controller != 199 || runtime != 197 ||
        fcntl(controller, F_GETFD) < 0 || fcntl(runtime, F_GETFD) < 0) return 93;
    action = argv[4];
    if (argc > 5) plan = argv[5];
    exact_read(capability, &network_length, sizeof(network_length));
    length = ntohl(network_length);
    if (length == 0 || length >= sizeof(payload)) return 94;
    exact_read(capability, payload, length);
    payload[length] = '\0';
    nonce_field = strstr(payload, "nonce=");
    if (nonce_field == NULL) return 95;
    nonce_field += 6;
    end = strchr(nonce_field, '\n');
    if (end == NULL || (size_t)(end - nonce_field) != 64) return 96;
    memcpy(nonce, nonce_field, 64);
    nonce[64] = '\0';
    exact_write(STDOUT_FILENO, payload, length);
    if (strcmp(action, "apply") == 0 && strcmp(plan, "/slowloris") == 0) {
        size_t index;
        snprintf(ready, sizeof(ready), "READY %s\n", nonce);
        for (index = 0; ready[index] != '\0'; ++index) {
            exact_write(capability, ready + index, 1);
            usleep(100000);
        }
    } else {
        snprintf(ready, sizeof(ready), "READY %s\n", nonce);
        exact_write(capability, ready, strlen(ready));
    }
    read_line(capability, line, sizeof(line));
    snprintf(ready, sizeof(ready), "GO %s\n", nonce);
    if (strcmp(line, ready) != 0) return 97;
    if (strcmp(action, "apply") == 0 && strcmp(plan, "/ping-flood") == 0) {
        unsigned int index;
        snprintf(line, sizeof(line), "PING %s\n", nonce);
        for (index = 0; index < 128; ++index) exact_write(capability, line, strlen(line));
        pause();
    }
    if (strcmp(action, "apply") == 0 && strcmp(plan, "/stdout-flood") == 0) {
        char block[4096];
        unsigned int index;
        memset(block, 'o', sizeof(block));
        for (index = 0; index < 80; ++index) exact_write(STDOUT_FILENO, block, sizeof(block));
    }
    if (strcmp(action, "apply") == 0 && strcmp(plan, "/stderr-flood") == 0) {
        char block[4096];
        unsigned int index;
        memset(block, 'e', sizeof(block));
        for (index = 0; index < 80; ++index) exact_write(STDERR_FILENO, block, sizeof(block));
    }
    snprintf(line, sizeof(line), "PING %s\n", nonce);
    exact_write(capability, line, strlen(line));
    read_line(capability, line, sizeof(line));
    snprintf(ready, sizeof(ready), "PONG %s\n", nonce);
    if (strcmp(line, ready) != 0) return 98;
    if (strcmp(action, "apply") == 0 && strcmp(plan, "/grandchild") == 0) {
        pid_t grandchild = fork();
        if (grandchild < 0) return 99;
        if (grandchild == 0) { sleep(30); _exit(0); }
        dprintf(STDOUT_FILENO, "GRANDCHILD %ld\n", (long)grandchild);
    }
    if (strcmp(action, "apply") == 0 && strcmp(plan, "/setsid-grandchild") == 0) {
        pid_t grandchild = fork();
        if (grandchild < 0) return 100;
        if (grandchild == 0) {
            if (setsid() < 0) _exit(101);
            sleep(30);
            _exit(0);
        }
        dprintf(STDOUT_FILENO, "SETSID_GRANDCHILD %ld\n", (long)grandchild);
        usleep(300000);
    }
    if (strcmp(action, "apply") == 0 && strcmp(plan, "/crash") == 0) _exit(73);
    exact_write(STDOUT_FILENO, "FIXTURE_OK\n", 11);
    return 0;
}
'''


class NativeLauncherTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not CLANG.is_file():
            raise unittest.SkipTest("reviewed Xcode clang is absent")
        cls.temporary = tempfile.TemporaryDirectory(
            prefix=".native-owner-launcher-", dir=ROOT
        )
        cls.root = Path(cls.temporary.name)
        cls.root.chmod(0o700)
        cls.controller = cls.root / "owner-provision"
        cls.launcher = cls.root / "owner-launcher"
        cls.runtime = cls.root / "runtime"
        cls.runtime_framework = cls.runtime / "Python.framework"
        cls.runtime_framework_versions = cls.runtime_framework / "Versions"
        cls.runtime_framework_version = cls.runtime_framework_versions / "3.14"
        cls.runtime_bin = cls.runtime_framework_version / "bin"
        cls.runtime_launcher_dir = cls.runtime / "launcher"
        cls.runtime_lib = cls.runtime_framework_version / "lib"
        cls.runtime_vendor = cls.runtime / "vendor"
        for directory in (
            cls.runtime_bin,
            cls.runtime_framework_version,
            cls.runtime_framework_versions,
            cls.runtime_framework,
            cls.runtime_launcher_dir,
            cls.runtime_lib,
            cls.runtime_vendor,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        cls.runtime_python = cls.runtime_bin / "python3.14"
        cls.runtime_intel_shim = cls.runtime_bin / "python3.14-intel64"
        cls.runtime_launcher = cls.runtime_launcher_dir / "python3.14"
        cls.runtime_launcher.write_text("#!/bin/sh\nexit 126\n", encoding="ascii")
        cls.runtime_launcher.chmod(0o555)
        cls.controller.write_text(CONTROLLER, encoding="ascii")
        cls.controller.chmod(0o555)
        sdk = subprocess.run(
            ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"],
            check=True,
            capture_output=True,
            text=True,
            env={"DEVELOPER_DIR": "/Applications/Xcode.app/Contents/Developer"},
        ).stdout.strip()
        cls.sdk = sdk
        runtime_source = cls.root / "fixture-runtime.c"
        runtime_source.write_text(FIXTURE_RUNTIME_SOURCE, encoding="ascii")
        subprocess.run(
            [
                str(CLANG),
                "-std=c17",
                "-Os",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                "-isysroot",
                sdk,
                "-mmacosx-version-min=13.0",
                str(runtime_source),
                "-o",
                str(cls.runtime_python),
            ],
            check=True,
            cwd=ROOT,
            env={"PATH": "/usr/bin:/bin", "TMPDIR": "/private/tmp"},
            capture_output=True,
            text=True,
        )
        cls.runtime_python.chmod(0o555)
        runtime_source.unlink()
        cls.compile_fixture_runtime(cls.runtime_intel_shim, "-arch", "x86_64")
        subprocess.run(
            [
                "/usr/bin/codesign",
                "--force",
                "--sign",
                "-",
                "--timestamp=none",
                "--options",
                "runtime",
                "--identifier",
                "org.winsvpn.releasepython.intel-shim.test",
                str(cls.runtime_intel_shim),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        cls.runtime_intel_shim.chmod(0o555)
        for directory in (
            cls.runtime_bin,
            cls.runtime_framework_version,
            cls.runtime_framework_versions,
            cls.runtime_framework,
            cls.runtime_launcher_dir,
            cls.runtime_lib,
            cls.runtime_vendor,
            cls.runtime,
        ):
            directory.chmod(0o555)
        cls.source_hash = sha256(SOURCE)
        cls.build_hash = sha256(BUILD)
        cls.compiler_hash = sha256(CLANG)
        cls.compile_launcher(cls.launcher)

    @classmethod
    def compile_launcher(
        cls,
        destination: Path,
        *,
        runtime_python: Path | None = None,
        extra_defines: tuple[str, ...] = (),
    ) -> None:
        selected_runtime = runtime_python or cls.runtime_python
        command = [
            str(CLANG),
            "-std=c17",
            "-Os",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-isysroot",
            cls.sdk,
            "-mmacosx-version-min=13.0",
            "-fno-ident",
            "-fvisibility=hidden",
            "-Wl,-dead_strip",
            "-Wl,-no_adhoc_codesign",
            "-Wl,-fatal_warnings",
            "-lproc",
            f'-DWINS_BUILD_SOURCE_SHA256="{cls.source_hash}"',
            f'-DWINS_BUILD_SCRIPT_SHA256="{cls.build_hash}"',
            f'-DWINS_BUILD_COMPILER_SHA256="{cls.compiler_hash}"',
            f'-DWINS_BUILD_LINKER_SHA256="{sha256(LINKER)}"',
            '-DWINS_BUILD_SDK_CLOSURE_SHA256="'
            f'{hashlib.sha256(cls.sdk.encode("utf-8")).hexdigest()}"',
            f'-DWINS_CONTROLLER_SHA256="{sha256(cls.controller)}"',
            f'-DWINS_RUNTIME_LAUNCHER_SHA256="{sha256(cls.runtime_launcher)}"',
            f'-DWINS_RUNTIME_PYTHON_SHA256="{sha256(selected_runtime)}"',
            f'-DWINS_OWNER_LAUNCHER_PATH="{destination}"',
            f'-DWINS_CONTROLLER_PATH="{cls.controller}"',
            f'-DWINS_RUNTIME_ROOT="{cls.runtime}"',
            f'-DWINS_RUNTIME_LAUNCHER="{cls.runtime_launcher}"',
            f'-DWINS_RUNTIME_PYTHON="{selected_runtime}"',
            f'-DWINS_RUNTIME_LIBRARY="{cls.runtime_lib}"',
            f'-DWINS_RUNTIME_VENDOR="{cls.runtime_vendor}"',
            f"-DWINS_EXPECTED_UID={os.getuid()}",
            f"-DWINS_RUNTIME_EXPECTED_UID={os.getuid()}",
            "-DWINS_REQUIRE_IMMUTABLE=0",
            "-DWINS_PROTOCOL_TIMEOUT_MS=5000",
            *extra_defines,
            str(SOURCE),
            "-o",
            str(destination),
        ]
        subprocess.run(
            command,
            check=True,
            cwd=ROOT,
            env={"PATH": "/usr/bin:/bin", "TMPDIR": "/private/tmp"},
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                "/usr/bin/codesign",
                "--force",
                "--sign",
                "-",
                "--timestamp=none",
                "--identifier",
                "org.winsvpn.releasepython.owner-launcher.test",
                str(destination),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        destination.chmod(0o555)

    @classmethod
    def compile_fixture_runtime(
        cls,
        destination: Path,
        *extra_arguments: str,
        deployment_target: str = "13.0",
    ) -> None:
        source = cls.root / f"{destination.name}.c"
        source.write_text(FIXTURE_RUNTIME_SOURCE, encoding="ascii")
        try:
            subprocess.run(
                [
                    str(CLANG),
                    "-std=c17",
                    "-Os",
                    "-Wall",
                    "-Wextra",
                    "-Wpedantic",
                    "-Werror",
                    "-isysroot",
                    cls.sdk,
                    f"-mmacosx-version-min={deployment_target}",
                    *extra_arguments,
                    str(source),
                    "-o",
                    str(destination),
                ],
                check=True,
                cwd=ROOT,
                env={"PATH": "/usr/bin:/bin", "TMPDIR": "/private/tmp"},
                capture_output=True,
                text=True,
            )
            destination.chmod(0o555)
        finally:
            source.unlink(missing_ok=True)

    @classmethod
    def create_universal_fixture_runtime(
        cls,
        destination: Path,
        *,
        arm64_arguments: tuple[str, ...] = (),
        x86_64_arguments: tuple[str, ...] = (),
        arm64_deployment_target: str = "13.0",
        x86_64_deployment_target: str = "13.0",
    ) -> None:
        arm64 = cls.root / f"{destination.name}.arm64"
        x86_64 = cls.root / f"{destination.name}.x86_64"
        try:
            cls.compile_fixture_runtime(
                arm64,
                "-arch",
                "arm64",
                *arm64_arguments,
                deployment_target=arm64_deployment_target,
            )
            cls.compile_fixture_runtime(
                x86_64,
                "-arch",
                "x86_64",
                *x86_64_arguments,
                deployment_target=x86_64_deployment_target,
            )
            subprocess.run(
                ["/usr/bin/lipo", "-create", str(arm64), str(x86_64), "-output", str(destination)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [
                    "/usr/bin/codesign",
                    "--force",
                    "--sign",
                    "-",
                    "--timestamp=none",
                    "--options",
                    "runtime",
                    "--identifier",
                    "org.winsvpn.releasepython.universal-fixture.test",
                    str(destination),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            destination.chmod(0o555)
        finally:
            arm64.unlink(missing_ok=True)
            x86_64.unlink(missing_ok=True)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.root.chmod(0o700)
        for current, directories, files in os.walk(cls.root, topdown=False):
            for name in files:
                (Path(current) / name).chmod(0o600)
            for name in directories:
                (Path(current) / name).chmod(0o700)
        cls.temporary.cleanup()

    def invoke(
        self,
        *arguments: str,
        env: dict[str, str] | None = None,
        executable: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(executable or self.launcher), *arguments],
            cwd=ROOT,
            env=env or {"HOME": "/var/root", "TMPDIR": "/private/tmp"},
            capture_output=True,
            text=True,
            timeout=30,
        )

    @staticmethod
    def capability_record(stdout: str) -> dict[str, str]:
        lines = stdout.splitlines()
        if not lines or lines[-1] != "FIXTURE_OK":
            raise AssertionError(f"fixture completion is absent: {stdout!r}")
        return dict(line.split("=", 1) for line in lines[:-1])

    def test_real_native_launch_and_live_capability(self) -> None:
        completed = self.invoke("selftest")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        record = self.capability_record(completed.stdout)
        self.assertEqual(
            record["contract"],
            "winsvpn-macos-release-python-native-capability-v1",
        )
        self.assertEqual(record["launcher_sha256"], sha256(self.launcher))
        self.assertEqual(record["launcher_source_sha256"], self.source_hash)
        self.assertEqual(record["launcher_build_sha256"], self.build_hash)
        self.assertEqual(record["launcher_compiler_sha256"], self.compiler_hash)
        self.assertEqual(int(record["launcher_device"]), self.launcher.stat().st_dev)
        self.assertEqual(int(record["launcher_inode"]), self.launcher.stat().st_ino)
        self.assertEqual(record["controller_sha256"], sha256(self.controller))
        self.assertEqual(
            record["runtime_launcher_sha256"], sha256(self.runtime_launcher)
        )
        self.assertEqual(record["runtime_python_sha256"], sha256(self.runtime_python))
        self.assertGreaterEqual(int(record["runtime_closure_nodes"]), 6)
        self.assertGreaterEqual(int(record["runtime_macho_files"]), 1)
        self.assertEqual(
            record["runtime_framework_tree_sha256"],
            receipt_tree_sha256(self.runtime_framework),
        )
        self.assertEqual(
            record["runtime_vendor_tree_sha256"],
            receipt_tree_sha256(self.runtime_vendor),
        )
        self.assertEqual(
            record["runtime_launcher_tree_sha256"],
            receipt_tree_sha256(self.runtime_launcher_dir),
        )
        self.assertEqual(
            int(record["runtime_executable_inode"]), self.runtime_python.stat().st_ino
        )
        self.assertRegex(record["nonce"], r"\A[0-9a-f]{64}\Z")

    def test_universal2_runtime_selects_and_authenticates_arm64_slice(self) -> None:
        original = self.runtime_python.read_bytes()
        original_mode = stat.S_IMODE(self.runtime_python.stat().st_mode)
        launcher = self.root / "owner-launcher-universal2"
        self.runtime_bin.chmod(0o755)
        try:
            self.runtime_python.unlink()
            self.create_universal_fixture_runtime(self.runtime_python)
            self.runtime_bin.chmod(0o555)
            self.compile_launcher(launcher, runtime_python=self.runtime_python)
            completed = self.invoke("selftest", executable=launcher)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                self.capability_record(completed.stdout)["runtime_python_sha256"],
                sha256(self.runtime_python),
            )
        finally:
            self.runtime_bin.chmod(0o755)
            self.runtime_python.unlink(missing_ok=True)
            self.runtime_python.write_bytes(original)
            self.runtime_python.chmod(original_mode)
            self.runtime_bin.chmod(0o555)

    def test_universal2_x86_64_slice_policy_is_not_hidden_by_clean_arm64(self) -> None:
        original = self.runtime_python.read_bytes()
        original_mode = stat.S_IMODE(self.runtime_python.stat().st_mode)
        cases = (
            (
                "rpath",
                {"x86_64_arguments": ("-Wl,-rpath,/private/tmp/hostile-x86-rpath",)},
                "LC_RPATH",
            ),
            (
                "minos",
                {"x86_64_deployment_target": "14.0"},
                "platform or macOS 13 compatibility is invalid",
            ),
        )
        for slug, options, expected in cases:
            with self.subTest(slug=slug):
                launcher = self.root / f"owner-launcher-universal2-x86-{slug}"
                self.runtime_bin.chmod(0o755)
                try:
                    self.runtime_python.unlink()
                    self.create_universal_fixture_runtime(self.runtime_python, **options)
                    self.runtime_bin.chmod(0o555)
                    self.compile_launcher(launcher, runtime_python=self.runtime_python)
                    completed = self.invoke("selftest", executable=launcher)
                    self.assertNotEqual(completed.returncode, 0, completed.stdout)
                    self.assertIn(expected, completed.stderr)
                finally:
                    self.runtime_bin.chmod(0o755)
                    self.runtime_python.unlink(missing_ok=True)
                    self.runtime_python.write_bytes(original)
                    self.runtime_python.chmod(original_mode)
                    self.runtime_bin.chmod(0o555)

    def test_universal2_legacy_x86_minimum_command_is_authenticated(self) -> None:
        original = self.runtime_python.read_bytes()
        original_mode = stat.S_IMODE(self.runtime_python.stat().st_mode)
        launcher = self.root / "owner-launcher-universal2-x86-legacy-minimum"
        self.runtime_bin.chmod(0o755)
        try:
            self.runtime_python.unlink()
            self.create_universal_fixture_runtime(
                self.runtime_python,
                x86_64_deployment_target="10.12",
            )
            commands = subprocess.run(
                ["/usr/bin/otool", "-arch", "x86_64", "-l", str(self.runtime_python)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            self.assertIn("LC_VERSION_MIN_MACOSX", commands)
            self.assertNotIn("LC_BUILD_VERSION", commands)
            self.runtime_bin.chmod(0o555)
            self.compile_launcher(launcher, runtime_python=self.runtime_python)
            completed = self.invoke("selftest", executable=launcher)
            self.assertEqual(completed.returncode, 0, completed.stderr)
        finally:
            self.runtime_bin.chmod(0o755)
            self.runtime_python.unlink(missing_ok=True)
            self.runtime_python.write_bytes(original)
            self.runtime_python.chmod(original_mode)
            self.runtime_bin.chmod(0o555)

    def test_transitive_x86_64_dependency_rejects_second_hop_thin_arm64(self) -> None:
        first = self.runtime_lib / "libfirst.dylib"
        second = self.runtime_lib / "libsecond.dylib"
        shim_original = self.runtime_intel_shim.read_bytes()
        shim_mode = stat.S_IMODE(self.runtime_intel_shim.stat().st_mode)
        source_second = self.root / "second.c"
        source_first = self.root / "first.c"
        source_shim = self.root / "intel-shim.c"
        arm_first = self.root / "libfirst.arm64.dylib"
        x86_first = self.root / "libfirst.x86_64.dylib"
        arm_second = self.root / "libsecond.arm64.dylib"
        x86_second = self.root / "libsecond.x86_64.dylib"
        source_second.write_text("int wins_second(void) { return 2; }\n", encoding="ascii")
        source_first.write_text(
            "extern int wins_second(void); int wins_first(void) { return wins_second(); }\n",
            encoding="ascii",
        )
        source_shim.write_text(
            "extern int wins_first(void); int main(void) { return wins_first() == 2 ? 0 : 1; }\n",
            encoding="ascii",
        )

        def compile_image(
            output: Path,
            architecture: str,
            source: Path,
            *arguments: str,
        ) -> None:
            subprocess.run(
                [
                    str(CLANG),
                    "-arch",
                    architecture,
                    "-isysroot",
                    self.sdk,
                    "-mmacosx-version-min=13.0",
                    str(source),
                    *arguments,
                    "-o",
                    str(output),
                ],
                check=True,
                cwd=ROOT,
                env={"PATH": "/usr/bin:/bin", "TMPDIR": "/private/tmp"},
                capture_output=True,
                text=True,
            )

        self.runtime_lib.chmod(0o755)
        self.runtime_bin.chmod(0o755)
        try:
            compile_image(
                arm_second,
                "arm64",
                source_second,
                "-dynamiclib",
                "-Wl,-install_name,@loader_path/libsecond.dylib",
            )
            compile_image(
                x86_second,
                "x86_64",
                source_second,
                "-dynamiclib",
                "-Wl,-install_name,@loader_path/libsecond.dylib",
            )
            compile_image(
                arm_first,
                "arm64",
                source_first,
                str(arm_second),
                "-dynamiclib",
                "-Wl,-install_name,@loader_path/../lib/libfirst.dylib",
            )
            compile_image(
                x86_first,
                "x86_64",
                source_first,
                str(x86_second),
                "-dynamiclib",
                "-Wl,-install_name,@loader_path/../lib/libfirst.dylib",
            )
            subprocess.run(
                ["/usr/bin/lipo", "-create", str(arm_first), str(x86_first), "-output", str(first)],
                check=True,
                capture_output=True,
                text=True,
            )
            shutil.copyfile(arm_second, second)
            self.runtime_intel_shim.unlink()
            compile_image(
                self.runtime_intel_shim,
                "x86_64",
                source_shim,
                str(x86_first),
            )
            for path, mode in ((first, 0o444), (second, 0o444), (self.runtime_intel_shim, 0o555)):
                subprocess.run(
                    [
                        "/usr/bin/codesign",
                        "--force",
                        "--sign",
                        "-",
                        "--timestamp=none",
                        "--options",
                        "runtime",
                        str(path),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                path.chmod(mode)
            self.runtime_lib.chmod(0o555)
            self.runtime_bin.chmod(0o555)
            completed = self.invoke("selftest")
            self.assertNotEqual(completed.returncode, 0, completed.stdout)
            self.assertIn(
                "x86_64 execution dependency is not exact universal2 Mach-O",
                completed.stderr,
            )
        finally:
            self.runtime_lib.chmod(0o755)
            self.runtime_bin.chmod(0o755)
            first.unlink(missing_ok=True)
            second.unlink(missing_ok=True)
            self.runtime_intel_shim.unlink(missing_ok=True)
            self.runtime_intel_shim.write_bytes(shim_original)
            self.runtime_intel_shim.chmod(shim_mode)
            self.runtime_lib.chmod(0o555)
            self.runtime_bin.chmod(0o555)
            for path in (
                source_second,
                source_first,
                source_shim,
                arm_first,
                x86_first,
                arm_second,
                x86_second,
            ):
                path.unlink(missing_ok=True)

    def test_exact_thin_x86_64_intel_shim_is_mandatory(self) -> None:
        completed = self.invoke("selftest")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            subprocess.run(
                ["/usr/bin/lipo", "-archs", str(self.runtime_intel_shim)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip(),
            "x86_64",
        )

        original = self.runtime_intel_shim.read_bytes()
        original_mode = stat.S_IMODE(self.runtime_intel_shim.stat().st_mode)
        self.runtime_bin.chmod(0o755)
        try:
            self.runtime_intel_shim.unlink()
            self.runtime_bin.chmod(0o555)
            missing = self.invoke("selftest")
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("requires exactly one thin x86_64 Intel shim", missing.stderr)
        finally:
            self.runtime_bin.chmod(0o755)
            self.runtime_intel_shim.write_bytes(original)
            self.runtime_intel_shim.chmod(original_mode)
            self.runtime_bin.chmod(0o555)

    def test_thin_x86_64_is_rejected_at_every_nonshim_path(self) -> None:
        hostile = self.runtime_lib / "nonshim-thin-x86"
        self.runtime_lib.chmod(0o755)
        try:
            self.compile_fixture_runtime(hostile, "-arch", "x86_64")
            self.runtime_lib.chmod(0o555)
            completed = self.invoke("selftest")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("CPU type or subtype is not exact arm64/all", completed.stderr)
        finally:
            self.runtime_lib.chmod(0o755)
            hostile.unlink(missing_ok=True)
            self.runtime_lib.chmod(0o555)

    def test_intel_shim_rejects_dylib_and_x86_64h_subtype(self) -> None:
        original = self.runtime_intel_shim.read_bytes()
        original_mode = stat.S_IMODE(self.runtime_intel_shim.stat().st_mode)
        cases = (
            (
                "dylib",
                ("-arch", "x86_64", "-dynamiclib"),
                0o444,
                "Intel shim is not exact MH_EXECUTE",
            ),
            (
                "x86_64h",
                ("-arch", "x86_64h"),
                0o555,
                "Intel shim CPU type or subtype is not exact x86_64/all",
            ),
        )
        for slug, arguments, mode, expected in cases:
            with self.subTest(slug=slug):
                self.runtime_bin.chmod(0o755)
                try:
                    self.runtime_intel_shim.unlink()
                    self.compile_fixture_runtime(self.runtime_intel_shim, *arguments)
                    self.runtime_intel_shim.chmod(mode)
                    self.runtime_bin.chmod(0o555)
                    completed = self.invoke("selftest")
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn(expected, completed.stderr)
                finally:
                    self.runtime_bin.chmod(0o755)
                    self.runtime_intel_shim.unlink(missing_ok=True)
                    self.runtime_intel_shim.write_bytes(original)
                    self.runtime_intel_shim.chmod(original_mode)
                    self.runtime_bin.chmod(0o555)

    def test_intel_shim_rejects_universal2_and_cannot_be_runtime_target(self) -> None:
        original = self.runtime_intel_shim.read_bytes()
        original_mode = stat.S_IMODE(self.runtime_intel_shim.stat().st_mode)
        selected_launcher = self.root / "owner-launcher-selected-intel-shim"
        self.runtime_bin.chmod(0o755)
        try:
            self.runtime_intel_shim.unlink()
            self.create_universal_fixture_runtime(self.runtime_intel_shim)
            self.runtime_bin.chmod(0o555)
            universal = self.invoke("selftest")
            self.assertNotEqual(universal.returncode, 0)
            self.assertIn("Intel shim is not exact thin x86_64", universal.stderr)
        finally:
            self.runtime_bin.chmod(0o755)
            self.runtime_intel_shim.unlink(missing_ok=True)
            self.runtime_intel_shim.write_bytes(original)
            self.runtime_intel_shim.chmod(original_mode)
            self.runtime_bin.chmod(0o555)

        self.compile_launcher(selected_launcher, runtime_python=self.runtime_intel_shim)
        selected = self.invoke("selftest", executable=selected_launcher)
        self.assertNotEqual(selected.returncode, 0)
        self.assertIn("Intel shim cannot be the selected runtime interpreter", selected.stderr)

    def test_universal2_runtime_rejects_malformed_architecture_inventory(self) -> None:
        original = self.runtime_python.read_bytes()
        original_mode = stat.S_IMODE(self.runtime_python.stat().st_mode)
        launcher = self.root / "owner-launcher-universal2-malformed"
        self.runtime_bin.chmod(0o755)
        try:
            self.runtime_python.unlink()
            self.create_universal_fixture_runtime(self.runtime_python)
            data = bytearray(self.runtime_python.read_bytes())
            self.assertIn(bytes(data[:4]), {b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"})
            struct.pack_into(">I", data, 4, 3)
            self.runtime_python.chmod(0o755)
            self.runtime_python.write_bytes(data)
            self.runtime_python.chmod(0o555)
            self.runtime_bin.chmod(0o555)
            self.compile_launcher(launcher, runtime_python=self.runtime_python)
            completed = self.invoke("selftest", executable=launcher)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(
                "universal2 Mach-O architecture inventory is not exact",
                completed.stderr,
            )
        finally:
            self.runtime_bin.chmod(0o755)
            self.runtime_python.unlink(missing_ok=True)
            self.runtime_python.write_bytes(original)
            self.runtime_python.chmod(original_mode)
            self.runtime_bin.chmod(0o555)

    def test_installed_universal2_python_copy_cannot_bypass_runtime_custody(self) -> None:
        if not RUNTIME_PYTHON.is_file():
            self.skipTest("installed universal2 ReleasePython is absent")
        installed_framework = RUNTIME_PYTHON.parents[1] / "Python"
        if not installed_framework.is_file():
            self.skipTest("installed universal2 ReleasePython framework image is absent")
        installed = RUNTIME_PYTHON.read_bytes()
        self.assertIn(installed[:4], {b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"})
        original = self.runtime_python.read_bytes()
        original_mode = stat.S_IMODE(self.runtime_python.stat().st_mode)
        launcher = self.root / "owner-launcher-installed-universal2-copy"
        framework_copy = self.runtime_framework_version / "Python"
        self.runtime_bin.chmod(0o755)
        self.runtime_framework_version.chmod(0o755)
        try:
            self.runtime_python.unlink()
            self.runtime_python.write_bytes(installed)
            self.runtime_python.chmod(0o555)
            framework_copy.write_bytes(installed_framework.read_bytes())
            framework_copy.chmod(0o444)
            self.assertEqual(sha256(self.runtime_python), sha256(RUNTIME_PYTHON))
            self.runtime_bin.chmod(0o555)
            self.runtime_framework_version.chmod(0o555)
            self.compile_launcher(launcher, runtime_python=self.runtime_python)
            completed = self.invoke("selftest", executable=launcher)
            self.assertNotEqual(completed.returncode, 0)
            self.assertRegex(
                completed.stderr,
                r"code signature invalid|Mach-O dependency escapes|incomplete capability",
            )
        finally:
            self.runtime_bin.chmod(0o755)
            self.runtime_framework_version.chmod(0o755)
            framework_copy.unlink(missing_ok=True)
            self.runtime_python.unlink(missing_ok=True)
            self.runtime_python.write_bytes(original)
            self.runtime_python.chmod(original_mode)
            self.runtime_bin.chmod(0o555)
            self.runtime_framework_version.chmod(0o555)
    def test_nonce_is_not_replayed(self) -> None:
        first = self.capability_record(self.invoke("selftest").stdout)
        second = self.capability_record(self.invoke("selftest").stdout)
        self.assertNotEqual(first["nonce"], second["nonce"])

    def test_argv_and_environment_are_exact(self) -> None:
        for arguments in (
            ("-c", "pass"),
            ("-m", "module"),
            ("apply", "relative", "/absolute"),
            ("publish-authority", "relative", "/absolute"),
            ("recover", "extra"),
        ):
            with self.subTest(arguments=arguments):
                completed = self.invoke(*arguments)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("argv must be exactly", completed.stderr)
        completed = self.invoke(
            "selftest",
            env={
                "HOME": "/var/root",
                "TMPDIR": "/private/tmp",
                "PYTHONPATH": "/private/tmp/hostile",
            },
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unexpected input environment", completed.stderr)
        published = self.invoke("publish-authority", "/authority", "/envelope")
        self.assertEqual(published.returncode, 0, published.stderr)
        record = self.capability_record(published.stdout)
        expected = hashlib.sha256()
        for value in ("publish-authority", "/authority", "/envelope"):
            encoded = value.encode("ascii")
            expected.update(len(encoded).to_bytes(8, "big"))
            expected.update(encoded)
        self.assertEqual(record["argv_sha256"], expected.hexdigest())

    def test_path_substitution_is_rejected(self) -> None:
        copied = self.root / "owner-launcher-copy"
        shutil.copyfile(self.launcher, copied)
        copied.chmod(0o555)
        completed = self.invoke("selftest", executable=copied)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("path is not the reviewed fixed path", completed.stderr)

    def test_macho_rpath_escape_is_rejected(self) -> None:
        escaped_runtime = self.runtime_bin / "python-rpath"
        escaped_launcher = self.root / "owner-launcher-rpath"
        self.runtime_bin.chmod(0o755)
        try:
            self.compile_fixture_runtime(
                escaped_runtime, "-Wl,-rpath,/private/tmp/hostile-rpath"
            )
            self.runtime_bin.chmod(0o555)
            self.compile_launcher(escaped_launcher, runtime_python=escaped_runtime)
            completed = self.invoke("selftest", executable=escaped_launcher)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("LC_RPATH", completed.stderr)
        finally:
            self.runtime_bin.chmod(0o755)
            escaped_runtime.unlink(missing_ok=True)
            self.runtime_bin.chmod(0o555)

    def assert_hostile_runtime_is_rejected(
        self,
        slug: str,
        expected_error: str,
        *,
        compile_arguments: tuple[str, ...] = (),
        deployment_target: str = "13.0",
        final_mode: int = 0o555,
        mutate=None,
    ) -> None:
        hostile_runtime = self.runtime_bin / f"python-{slug}"
        hostile_launcher = self.root / f"owner-launcher-{slug}"
        self.runtime_bin.chmod(0o755)
        try:
            self.compile_fixture_runtime(
                hostile_runtime,
                *compile_arguments,
                deployment_target=deployment_target,
            )
            if mutate is not None:
                hostile_runtime.chmod(0o755)
                mutate(hostile_runtime)
            hostile_runtime.chmod(final_mode)
            self.runtime_bin.chmod(0o555)
            self.compile_launcher(hostile_launcher, runtime_python=hostile_runtime)
            completed = self.invoke("selftest", executable=hostile_launcher)
            self.assertNotEqual(completed.returncode, 0, completed.stdout)
            self.assertIn(expected_error, completed.stderr)
        finally:
            self.runtime_bin.chmod(0o755)
            hostile_runtime.chmod(0o600) if hostile_runtime.exists() else None
            hostile_runtime.unlink(missing_ok=True)
            self.runtime_bin.chmod(0o555)

    def test_macho_contract_rejects_wrong_arch_filetype_and_minos(self) -> None:
        cases = (
            (
                "x86",
                "CPU type or subtype is not exact arm64/all",
                ("-arch", "x86_64"),
                "13.0",
                0o555,
            ),
            (
                "dylib",
                "interpreter is not exact MH_EXECUTE",
                ("-dynamiclib",),
                "13.0",
                0o444,
            ),
            (
                "minos",
                "platform or macOS 13 compatibility is invalid",
                (),
                "14.0",
                0o555,
            ),
        )
        for slug, error, arguments, target, mode in cases:
            with self.subTest(slug=slug):
                self.assert_hostile_runtime_is_rejected(
                    slug,
                    error,
                    compile_arguments=arguments,
                    deployment_target=target,
                    final_mode=mode,
                )

    def test_macho_contract_rejects_unsigned_and_tampered_code(self) -> None:
        self.assert_hostile_runtime_is_rejected(
            "unsigned",
            "signature, linker, or dependency inventory is incomplete",
            compile_arguments=("-Wl,-no_adhoc_codesign",),
        )

        def tamper(path: Path) -> None:
            descriptor = os.open(path, os.O_RDWR)
            try:
                original = os.pread(descriptor, 1, 4096)
                if len(original) != 1:
                    raise AssertionError("fixture Mach-O has no second code page")
                os.pwrite(descriptor, bytes((original[0] ^ 1,)), 4096)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

        self.assert_hostile_runtime_is_rejected(
            "tampered",
            "CodeDirectory page hash mismatch",
            mutate=tamper,
        )

        def corrupt_signature_bounds(path: Path) -> None:
            data = bytearray(path.read_bytes())
            command_count = struct.unpack_from("<I", data, 16)[0]
            offset = 32
            for _index in range(command_count):
                command, command_size = struct.unpack_from("<II", data, offset)
                if command == 0x1D:
                    struct.pack_into("<I", data, offset + 8, len(data) + 4096)
                    path.write_bytes(data)
                    return
                offset += command_size
            raise AssertionError("fixture Mach-O has no LC_CODE_SIGNATURE")

        self.assert_hostile_runtime_is_rejected(
            "signature-bounds",
            "LC_CODE_SIGNATURE bounds are not exact",
            mutate=corrupt_signature_bounds,
        )

    def test_runtime_rejects_setid_and_sticky_modes(self) -> None:
        original_mode = stat.S_IMODE(self.runtime_python.stat().st_mode)
        try:
            for hostile_mode in (0o4555, 0o2555, 0o1555):
                with self.subTest(mode=oct(hostile_mode)):
                    self.runtime_python.chmod(hostile_mode)
                    observed_mode = stat.S_IMODE(self.runtime_python.stat().st_mode)
                    if observed_mode != hostile_mode:
                        self.assertIn(
                            "S_ISUID | S_ISGID | S_ISVTX",
                            SOURCE.read_text(encoding="ascii"),
                        )
                        self.runtime_python.chmod(original_mode)
                        continue
                    completed = self.invoke("selftest")
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn("setid or sticky mode", completed.stderr)
                    self.runtime_python.chmod(original_mode)
            self.runtime_python.chmod(0o755)
            writable = self.invoke("selftest")
            self.assertNotEqual(writable.returncode, 0)
            self.assertIn("identity, owner, mode", writable.stderr)
        finally:
            self.runtime_python.chmod(original_mode)

    def assert_runtime_swap_is_rejected(self, target: Path, slug: str) -> None:
        marker = self.root / f"{slug}.marker"
        race_launcher = self.root / f"owner-launcher-{slug}"
        marker.unlink(missing_ok=True)
        self.compile_launcher(
            race_launcher,
            extra_defines=(
                "-DWINS_TEST_PREEXEC_DELAY_US=1000000",
                f'-DWINS_TEST_PREEXEC_MARKER="{marker}"',
            ),
        )
        process = subprocess.Popen(
            [str(race_launcher), "selftest"],
            cwd=ROOT,
            env={"HOME": "/var/root", "TMPDIR": "/private/tmp"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 5.0
        while not marker.exists() and process.poll() is None:
            if time.monotonic() >= deadline:
                process.kill()
                self.fail("race launcher did not reach its retained pre-exec state")
            time.sleep(0.01)
        original = target.read_bytes()
        original_mode = stat.S_IMODE(target.stat().st_mode)
        parent = target.parent
        replacement = parent / f".{target.name}.replacement"
        parent.chmod(0o755)
        replacement.write_bytes(original)
        replacement.chmod(original_mode)
        os.replace(replacement, target)
        parent.chmod(0o555)
        stdout, stderr = process.communicate(timeout=10)
        self.assertNotEqual(process.returncode, 0, stdout)
        self.assertIn("sealed runtime changed", stderr)

    def test_runtime_pathname_substitution_is_rejected_during_preexec(self) -> None:
        self.assert_runtime_swap_is_rejected(self.runtime_python, "runtime-swap")

    def test_unrelated_ancestor_sibling_churn_does_not_invalidate_custody(
        self,
    ) -> None:
        marker = self.root / "sibling-churn.marker"
        sibling = self.root / "unrelated-sibling.tmp"
        launcher = self.root / "owner-launcher-sibling-churn"
        marker.unlink(missing_ok=True)
        sibling.unlink(missing_ok=True)
        self.compile_launcher(
            launcher,
            extra_defines=(
                "-DWINS_TEST_PREEXEC_DELAY_US=1000000",
                f'-DWINS_TEST_PREEXEC_MARKER="{marker}"',
            ),
        )
        process = subprocess.Popen(
            [str(launcher), "selftest"],
            cwd=ROOT,
            env={"HOME": "/var/root", "TMPDIR": "/private/tmp"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 5.0
        while not marker.exists() and process.poll() is None:
            if time.monotonic() >= deadline:
                process.kill()
                self.fail("churn launcher did not reach retained pre-exec state")
            time.sleep(0.01)
        sibling.write_bytes(b"unrelated ancestor sibling churn\n")
        sibling.write_bytes(b"unrelated ancestor sibling churn updated\n")
        sibling.unlink()
        stdout, stderr = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 0, stderr)
        self.capability_record(stdout)

    def test_dylib_only_substitution_is_rejected_during_preexec(self) -> None:
        dylib = self.runtime_lib / "unused-hostile-target.dylib"
        source = self.root / "unused-hostile-target.c"
        source.write_text("int wins_fixture(void) { return 7; }\n", encoding="ascii")
        self.runtime_lib.chmod(0o755)
        try:
            subprocess.run(
                [
                    str(CLANG),
                    "-dynamiclib",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-isysroot",
                    self.sdk,
                    "-mmacosx-version-min=13.0",
                    str(source),
                    "-o",
                    str(dylib),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            dylib.chmod(0o444)
            self.runtime_lib.chmod(0o555)
            self.assert_runtime_swap_is_rejected(dylib, "dylib-swap")
        finally:
            self.runtime_lib.chmod(0o755)
            dylib.unlink(missing_ok=True)
            self.runtime_lib.chmod(0o555)
            source.unlink(missing_ok=True)

    def test_hardlinked_controller_inode_is_rejected(self) -> None:
        linked = self.root / "owner-provision-link"
        os.link(self.controller, linked)
        try:
            completed = self.invoke("selftest")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("link count", completed.stderr)
        finally:
            linked.unlink()

    def test_controller_byte_substitution_is_rejected_before_exec(self) -> None:
        original = self.controller.read_text(encoding="ascii")
        hostile = textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import os
            import socket
            cap = int(os.environ["WINS_OWNER_CAPABILITY_FD"])
            os.close(cap)
            left, right = socket.socketpair()
            os.dup2(left.fileno(), cap)
            raise SystemExit(0)
            """
        )
        self.controller.chmod(0o755)
        self.controller.write_text(hostile, encoding="ascii")
        self.controller.chmod(0o555)
        try:
            completed = self.invoke("selftest")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("not the reviewed build input", completed.stderr)
        finally:
            self.controller.chmod(0o755)
            self.controller.write_text(original, encoding="ascii")
            self.controller.chmod(0o555)

    def test_extra_top_level_runtime_content_is_rejected(self) -> None:
        extra = self.runtime / "unreceipted"
        self.runtime.chmod(0o755)
        extra.write_bytes(b"unreceipted\n")
        extra.chmod(0o444)
        self.runtime.chmod(0o555)
        try:
            completed = self.invoke("selftest")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("top-level closure is not exact", completed.stderr)
        finally:
            self.runtime.chmod(0o755)
            extra.unlink()
            self.runtime.chmod(0o555)

    def test_recover_completes_the_same_ready_nonce_ping_handshake(self) -> None:
        completed = self.invoke("recover")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(self.capability_record(completed.stdout)["argv_sha256"], hashlib.sha256(
            len("recover").to_bytes(8, "big") + b"recover"
        ).hexdigest())

    def test_ping_flood_and_slowloris_are_bounded(self) -> None:
        flood = self.invoke("apply", "/ping-flood", "/authorization")
        self.assertNotEqual(flood.returncode, 0)
        self.assertIn("PING cap", flood.stderr)
        slow = self.invoke("apply", "/slowloris", "/authorization")
        self.assertNotEqual(slow.returncode, 0)
        self.assertIn("absolute protocol deadline", slow.stderr)

    def test_stdout_and_stderr_floods_are_bounded_while_streaming(self) -> None:
        stdout = self.invoke("apply", "/stdout-flood", "/authorization")
        self.assertNotEqual(stdout.returncode, 0)
        self.assertIn("stdout exceeded", stdout.stderr)
        stderr = self.invoke("apply", "/stderr-flood", "/authorization")
        self.assertNotEqual(stderr.returncode, 0)
        self.assertIn("stderr exceeded", stderr.stderr)

    def test_child_crash_and_grandchild_cleanup_are_bounded(self) -> None:
        crash = self.invoke("apply", "/crash", "/authorization")
        self.assertEqual(crash.returncode, 73, crash.stderr)
        grandchild = self.invoke("apply", "/grandchild", "/authorization")
        self.assertEqual(grandchild.returncode, 0, grandchild.stderr)
        pid_line = next(
            line for line in grandchild.stdout.splitlines() if line.startswith("GRANDCHILD ")
        )
        pid = int(pid_line.split()[1])
        for _attempt in range(50):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.02)
        else:
            self.fail("launcher left a grandchild running")

        escaped = self.invoke("apply", "/setsid-grandchild", "/authorization")
        self.assertEqual(escaped.returncode, 0, escaped.stderr)
        escaped_line = next(
            line
            for line in escaped.stdout.splitlines()
            if line.startswith("SETSID_GRANDCHILD ")
        )
        escaped_pid = int(escaped_line.split()[1])
        for _attempt in range(50):
            try:
                os.kill(escaped_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.02)
        else:
            self.fail("launcher left a setsid-escaped grandchild running")

    def test_build_script_is_deterministic_and_warning_clean(self) -> None:
        first = self.root / "production-one"
        second = self.root / "production-two"
        for output in (first, second):
            completed = subprocess.run(
                ["/bin/bash", str(BUILD), str(output)],
                cwd=ROOT,
                env={"PATH": "/usr/bin:/bin", "TMPDIR": "/private/tmp"},
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(sha256(first), sha256(second))
        self.assertTrue(stat.S_ISREG(first.stat().st_mode))
        self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o555)

    def test_build_rejects_reserved_transaction_namespace_as_output(self) -> None:
        output = self.root / (
            ".winsvpn-owner-launcher-stage-" + "a" * 48
        )
        completed = subprocess.run(
            ["/bin/bash", str(BUILD), str(output)],
            cwd=ROOT,
            env={"PATH": "/usr/bin:/bin", "TMPDIR": "/private/tmp"},
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("reserved launcher transaction namespace", completed.stderr)
        self.assertFalse(output.exists())

    def test_current_installed_runtime_is_accepted_by_exact_native_parser(self) -> None:
        if not RUNTIME.is_dir() or not RUNTIME_PYTHON.is_file():
            self.skipTest("installed ReleasePython runtime is absent")
        auditor_source = self.root / "installed-runtime-auditor.c"
        auditor = self.root / "installed-runtime-auditor"
        auditor_source.write_text(
            "#define main winsvpn_unreachable_native_launcher_main\n"
            f'#include "{SOURCE}"\n'
            "#undef main\n"
            "int main(void) {\n"
            "  retained_ancestry ancestry; runtime_tree tree;\n"
            "  memset(&ancestry, 0, sizeof(ancestry));\n"
            "  retain_ancestors(WINS_RUNTIME_ROOT, &ancestry);\n"
            "  tree = open_runtime_tree(&ancestry);\n"
            "  close_runtime_tree(&tree); close_ancestry(&ancestry);\n"
            "  return 0;\n"
            "}\n",
            encoding="ascii",
        )
        try:
            compiled = subprocess.run(
                [
                    str(CLANG),
                    "-std=c17",
                    "-Os",
                    "-Wall",
                    "-Wextra",
                    "-Wpedantic",
                    "-Werror",
                    "-isysroot",
                    self.sdk,
                    "-mmacosx-version-min=13.0",
                    "-DWINS_REQUIRE_IMMUTABLE=0",
                    '-DWINS_BUILD_SOURCE_SHA256="' + "0" * 64 + '"',
                    '-DWINS_BUILD_SCRIPT_SHA256="' + "0" * 64 + '"',
                    '-DWINS_BUILD_COMPILER_SHA256="' + "0" * 64 + '"',
                    '-DWINS_BUILD_LINKER_SHA256="' + "0" * 64 + '"',
                    '-DWINS_BUILD_SDK_CLOSURE_SHA256="' + "0" * 64 + '"',
                    '-DWINS_CONTROLLER_SHA256="' + "0" * 64 + '"',
                    '-DWINS_RUNTIME_LAUNCHER_SHA256="' + "0" * 64 + '"',
                    '-DWINS_RUNTIME_PYTHON_SHA256="' + "0" * 64 + '"',
                    str(auditor_source),
                    "-o",
                    str(auditor),
                    "-lproc",
                ],
                cwd=ROOT,
                env={"PATH": "/usr/bin:/bin", "TMPDIR": "/private/tmp"},
                capture_output=True,
                text=True,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            completed = subprocess.run(
                [str(auditor)],
                cwd=ROOT,
                env={"PATH": "/usr/bin:/bin", "TMPDIR": "/private/tmp"},
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stderr, "")
            build_versions = subprocess.run(
                ["/usr/bin/vtool", "-show-build", str(RUNTIME_PYTHON)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            self.assertRegex(
                build_versions,
                r"architecture x86_64[\s\S]*?minos 13[.]0",
            )
            self.assertRegex(
                build_versions,
                r"architecture arm64[\s\S]*?minos 13[.]0",
            )
            pillow_jpeg = (
                RUNTIME / "vendor/PIL/.dylibs/libjpeg.62.4.0.dylib"
            )
            self.assertTrue(pillow_jpeg.is_file())
            load_commands = subprocess.run(
                ["/usr/bin/otool", "-l", str(pillow_jpeg)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            self.assertNotIn(
                "/Users/runner/work/Pillow/Pillow/build/deps/darwin/lib",
                load_commands,
            )
        finally:
            auditor.unlink(missing_ok=True)
            auditor_source.unlink(missing_ok=True)

    def test_build_publication_is_exactly_retryable(self) -> None:
        output = self.root / "production-retry"
        first = subprocess.run(
            ["/bin/bash", str(BUILD), str(output)],
            cwd=ROOT,
            env={"PATH": "/usr/bin:/bin", "TMPDIR": "/private/tmp"},
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        digest = sha256(output)
        identity = (output.stat().st_dev, output.stat().st_ino)
        retry = subprocess.run(
            ["/bin/bash", str(BUILD), str(output)],
            cwd=ROOT,
            env={"PATH": "/usr/bin:/bin", "TMPDIR": "/private/tmp"},
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(retry.returncode, 0, retry.stderr)
        self.assertEqual(sha256(output), digest)
        self.assertEqual((output.stat().st_dev, output.stat().st_ino), identity)
        self.assertFalse(
            any(
                path.name.startswith(".winsvpn-owner-launcher-stage-")
                for path in self.root.iterdir()
            )
        )

    def test_build_startup_recovers_exact_hard_crash_stages(self) -> None:
        injections = (
            (
                "empty",
                "stage_dir=os.open(stage_name,flags,dir_fd=parent); stage_fd=None",
                "stage_dir=os.open(stage_name,flags,dir_fd=parent); "
                "stage_fd=None; "
                '(open("{marker}","wb").close(),os._exit(91)) '
                'if not os.path.exists("{marker}") else None',
            ),
            (
                "complete",
                "os.fchmod(stage_fd,0o555); os.fsync(stage_fd); "
                "os.close(stage_fd); stage_fd=None",
                "os.fchmod(stage_fd,0o555); os.fsync(stage_fd); "
                "os.close(stage_fd); stage_fd=None; "
                '(open("{marker}","wb").close(),os._exit(92)) '
                'if not os.path.exists("{marker}") else None',
            ),
        )
        for slug, needle, replacement in injections:
            with self.subTest(stage=slug):
                fixture = self.root / f"publication-hard-crash-{slug}"
                fixture.mkdir()
                shutil.copyfile(SOURCE, fixture / SOURCE.name)
                shutil.copyfile(
                    ROOT / "tools/macos_release_python_owner_provision.py",
                    fixture / "macos_release_python_owner_provision.py",
                )
                marker = fixture / "crashed.once"
                build = fixture / BUILD.name
                build_text = BUILD.read_text(encoding="ascii")
                self.assertEqual(build_text.count(needle), 1)
                build_text = build_text.replace(
                    needle,
                    replacement.format(marker=str(marker)),
                    1,
                )
                build.write_text(build_text, encoding="ascii")
                build.chmod(0o755)
                output = fixture / "owner-launcher"
                first = subprocess.run(
                    ["/bin/bash", str(build), str(output)],
                    cwd=fixture,
                    env={"PATH": "/usr/bin:/bin", "TMPDIR": "/private/tmp"},
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                self.assertEqual(
                    first.returncode,
                    91 if slug == "empty" else 92,
                    first.stderr,
                )
                residue = [
                    path
                    for path in fixture.iterdir()
                    if path.name.startswith(".winsvpn-owner-launcher-stage-")
                ]
                self.assertEqual(len(residue), 1)
                retry = subprocess.run(
                    ["/bin/bash", str(build), str(output)],
                    cwd=fixture,
                    env={"PATH": "/usr/bin:/bin", "TMPDIR": "/private/tmp"},
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                self.assertEqual(retry.returncode, 0, retry.stderr)
                self.assertTrue(output.is_file())
                self.assertFalse(
                    any(
                        path.name.startswith(".winsvpn-owner-launcher-stage-")
                        for path in fixture.iterdir()
                    )
                )

    def test_build_startup_rejects_unauthenticated_stage_residue(self) -> None:
        stage = self.root / (".winsvpn-owner-launcher-stage-" + "a" * 48)
        stage.mkdir(mode=0o700)
        hostile = stage / "unexpected"
        hostile.write_bytes(b"not an authenticated launcher stage\n")
        output = self.root / "production-hostile-stage"
        try:
            completed = subprocess.run(
                ["/bin/bash", str(BUILD), str(output)],
                cwd=ROOT,
                env={"PATH": "/usr/bin:/bin", "TMPDIR": "/private/tmp"},
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("abandoned launcher stage shape is invalid", completed.stderr)
            self.assertTrue(hostile.is_file())
            self.assertFalse(output.exists())
        finally:
            hostile.unlink(missing_ok=True)
            stage.rmdir()

    def test_build_publication_rejects_a_different_preexisting_leaf(self) -> None:
        output = self.root / "production-hostile-existing"
        output.write_bytes(b"not the reviewed launcher\n")
        output.chmod(0o555)
        completed = subprocess.run(
            ["/bin/bash", str(BUILD), str(output)],
            cwd=ROOT,
            env={"PATH": "/usr/bin:/bin", "TMPDIR": "/private/tmp"},
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("existing publication is not an exact retry", completed.stderr)
        self.assertEqual(output.read_bytes(), b"not the reviewed launcher\n")

    def test_post_rename_publication_failure_rolls_back_for_retry(self) -> None:
        fixture = self.root / "publication-crash"
        fixture.mkdir()
        shutil.copyfile(SOURCE, fixture / SOURCE.name)
        shutil.copyfile(
            ROOT / "tools/macos_release_python_owner_provision.py",
            fixture / "macos_release_python_owner_provision.py",
        )
        build = fixture / BUILD.name
        build_text = BUILD.read_text(encoding="ascii").replace(
            "committed=True; os.fsync(parent); published_fd=",
            'committed=True; raise RuntimeError("simulated post-rename crash"); '
            "os.fsync(parent); published_fd=",
            1,
        )
        self.assertIn("simulated post-rename crash", build_text)
        build.write_text(build_text, encoding="ascii")
        build.chmod(0o755)
        output = fixture / "owner-launcher"
        completed = subprocess.run(
            ["/bin/bash", str(build), str(output)],
            cwd=fixture,
            env={"PATH": "/usr/bin:/bin", "TMPDIR": "/private/tmp"},
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("simulated post-rename crash", completed.stderr)
        self.assertFalse(output.exists())
        self.assertFalse(
            any(
                path.name.startswith(".winsvpn-owner-launcher-stage-")
                for path in fixture.iterdir()
            )
        )

    def test_compiler_ancestor_swap_and_restore_is_rejected(self) -> None:
        fixture = self.root / "build-ancestor"
        toolchain = fixture / "Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin"
        toolchain.mkdir(parents=True)
        source = fixture / SOURCE.name
        controller = fixture / "macos_release_python_owner_provision.py"
        build = fixture / BUILD.name
        compiler = toolchain / "clang"
        marker = fixture / "compiler.started"
        counter = fixture / "compiler.count"
        output = fixture / "owner-launcher"
        shutil.copyfile(SOURCE, source)
        shutil.copyfile(ROOT / "tools/macos_release_python_owner_provision.py", controller)
        compiler.write_text(
            "#!/bin/bash\n"
            f"count=0; [[ ! -f {str(counter)!r} ]] || count=$(/bin/cat {str(counter)!r})\n"
            "count=$((count + 1))\n"
            f"printf '%s\\n' \"$count\" > {str(counter)!r}\n"
            f"if [[ \"$count\" -ge 2 ]]; then /usr/bin/touch {str(marker)!r}; /bin/sleep 1; fi\n"
            f"exec {str(CLANG)!r} \"$@\"\n",
            encoding="ascii",
        )
        compiler.chmod(0o755)
        build_text = BUILD.read_text(encoding="ascii").replace(
            "readonly EXPECTED_CLANG=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
            f"readonly EXPECTED_CLANG={compiler}",
        ).replace(
            'clang="$(DEVELOPER_DIR="$DEVELOPER" "$XCRUN" --find clang)"',
            'clang="$EXPECTED_CLANG"',
        ).replace(
            "'0:755:1:Regular File'",
            f"'{os.getuid()}:755:1:Regular File'",
            1,
        )
        build.write_text(build_text, encoding="ascii")
        build.chmod(0o755)
        process = subprocess.Popen(
            ["/bin/bash", str(build), str(output)],
            cwd=fixture,
            env={"PATH": "/usr/bin:/bin", "TMPDIR": "/private/tmp"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 20
        while not marker.exists() and process.poll() is None:
            if time.monotonic() >= deadline:
                process.kill()
                self.fail("ancestor fixture did not reach retained compiler execution")
            time.sleep(0.01)
        xcode = fixture / "Xcode.app"
        displaced = fixture / "Xcode.displaced"
        os.rename(xcode, displaced)
        os.rename(displaced, xcode)
        stdout, stderr = process.communicate(timeout=30)
        self.assertNotEqual(process.returncode, 0, stdout)
        self.assertRegex(stderr, r"retained input vnode event|changed while retained")

    def run_hostile_build_swap(self, target_kind: str) -> subprocess.CompletedProcess[str]:
        fixture = self.root / f"build-{target_kind}"
        fixture.mkdir()
        source = fixture / SOURCE.name
        controller = fixture / "macos_release_python_owner_provision.py"
        build = fixture / BUILD.name
        compiler = fixture / "clang-fixture"
        linker = fixture / "ld-fixture"
        marker = fixture / "compiler.started"
        output = fixture / "owner-launcher"
        shutil.copyfile(SOURCE, source)
        shutil.copyfile(ROOT / "tools/macos_release_python_owner_provision.py", controller)
        selected_tool = linker if target_kind == "linker" else compiler
        real_tool = str(LINKER if target_kind == "linker" else CLANG)
        tool_text = (
            "#!/bin/bash\n"
            f"/usr/bin/touch {str(marker)!r}\n"
            "/bin/sleep 1\n"
            f"exec {real_tool!r} \"$@\"\n"
        )
        selected_tool.write_text(tool_text, encoding="ascii")
        selected_tool.chmod(0o755)
        build_text = BUILD.read_text(encoding="ascii")
        if target_kind == "linker":
            build_text = build_text.replace(
                "readonly EXPECTED_LINKER=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/ld",
                f"readonly EXPECTED_LINKER={linker}",
            ).replace(
                'linker="$(DEVELOPER_DIR="$DEVELOPER" "$XCRUN" --find ld)"',
                'linker="$EXPECTED_LINKER"',
            )
            first_custody = build_text.index("'0:755:1:Regular File'")
            second_custody = build_text.index(
                "'0:755:1:Regular File'", first_custody + 1
            )
            build_text = (
                build_text[:second_custody]
                + f"'{os.getuid()}:755:1:Regular File'"
                + build_text[
                    second_custody + len("'0:755:1:Regular File'") :
                ]
            )
        else:
            build_text = build_text.replace(
                "readonly EXPECTED_CLANG=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
                f"readonly EXPECTED_CLANG={compiler}",
            ).replace(
                'clang="$(DEVELOPER_DIR="$DEVELOPER" "$XCRUN" --find clang)"',
                'clang="$EXPECTED_CLANG"',
            ).replace(
                "'0:755:1:Regular File'",
                f"'{os.getuid()}:755:1:Regular File'",
                1,
            )
        build.write_text(build_text, encoding="ascii")
        build.chmod(0o755)
        process = subprocess.Popen(
            ["/bin/bash", str(build), str(output)],
            cwd=fixture,
            env={"PATH": "/usr/bin:/bin", "TMPDIR": "/private/tmp"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 10
        while not marker.exists() and process.poll() is None:
            if time.monotonic() >= deadline:
                process.kill()
                self.fail("hostile build fixture never executed its retained compiler")
            time.sleep(0.01)
        if target_kind == "source":
            source.write_bytes(source.read_bytes())
        else:
            selected_tool.write_text(tool_text, encoding="ascii")
            selected_tool.chmod(0o755)
        stdout, stderr = process.communicate(timeout=30)
        return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)

    def test_source_transient_substitution_is_rejected(self) -> None:
        completed = self.run_hostile_build_swap("source")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("source changed", completed.stderr)

    def test_compiler_transient_substitution_is_rejected(self) -> None:
        completed = self.run_hostile_build_swap("compiler")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("compiler changed", completed.stderr)

    def test_linker_transient_substitution_is_rejected(self) -> None:
        completed = self.run_hostile_build_swap("linker")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("linker changed", completed.stderr)


if __name__ == "__main__":
    unittest.main()
