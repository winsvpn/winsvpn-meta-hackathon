#!/usr/bin/env python3
"""wear_os/tools/prepare_release.sh attests its AAB through the dependency freeze.

tools/release_dependency_freeze.py maps ("wear_os", "darwin") to this script as
a producer-attested producer. The script must take its single-use begin receipt
before Gradle can write the AAB, and finish and verify the build receipt only
after every Wear gate and the permission-frozen signed-AAB receipt passed, with
the exact producer path, target and Gradle distribution identity.

It also owns its toolchains the way the Android phone producer does: the
current user's pinned Python and JDK, verified against tools/toolchain-pins.json,
with no root custody tree and no release Python authority. The second half of
this file holds those tests.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile

WEAR = pathlib.Path(__file__).resolve().parents[1]
ROOT = WEAR.parent
PREPARE = WEAR / "tools" / "prepare_release.sh"


def _load_freeze():
    spec = importlib.util.spec_from_file_location(
        "release_dependency_freeze_for_wear_tests",
        ROOT / "tools" / "release_dependency_freeze.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PrepareReleaseBuildReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.script = PREPARE.read_text(encoding="utf-8")

    def _index(self, needle: str) -> int:
        self.assertEqual(self.script.count(needle), 1, needle)
        return self.script.index(needle)

    def test_script_parses(self) -> None:
        completed = subprocess.run(
            ["/bin/bash", "-n", str(PREPARE)], capture_output=True, text=True, check=False
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_begin_precedes_gradle_and_finish_follows_every_gate(self) -> None:
        verify_index = self._index('"${DEPENDENCY_FREEZE}" verify-index')
        begin = self._index('"${DEPENDENCY_FREEZE}" begin-build')
        gradle = self._index(":app:bundleRelease")
        receipt_verify = self._index('wins_release_python_run "${RECEIPT_TOOL}" verify')
        finish = self._index('"${DEPENDENCY_FREEZE}" finish-build')
        verify_receipt = self._index('"${DEPENDENCY_FREEZE}" verify-receipt')
        passed = self._index("WEAR OS RELEASE: PASS")
        self.assertLess(verify_index, begin)
        self.assertLess(begin, gradle)
        for gate in (
            'wins_release_python_run "${ASSERT_AAB}"',
            'wins_release_python_run "${SIGNER_TOOL}"',
            'wins_release_python_run "${PRIVACY_TOOL}"',
            'wins_release_python_run "${CUSTODY_TOOL}" verify',
        ):
            self.assertLess(gradle, self._index(gate))
            self.assertLess(self._index(gate), finish)
        self.assertLess(receipt_verify, finish)
        self.assertLess(finish, verify_receipt)
        self.assertLess(verify_receipt, passed)

    def test_finish_names_the_freeze_producer_target_and_platform(self) -> None:
        freeze = _load_freeze()
        producer = freeze.PLATFORM_BUILD_PRODUCERS_BY_HOST[("wear_os", "darwin")]
        self.assertEqual(ROOT / producer, PREPARE)
        self.assertIn(("wear_os", "darwin"), freeze.PRODUCER_ATTESTED_PLATFORM_HOSTS)
        finish = self.script[self._index('"${DEPENDENCY_FREEZE}" finish-build'):]
        finish = finish[: finish.index("|| die")]
        self.assertIn(f"--producer {producer} ", finish)
        self.assertIn("--platform wear_os ", finish)
        self.assertIn('--begin "${WEAR_AAB_BEGIN}"', finish)
        self.assertIn('--artifact "${CANONICAL_AAB}"', finish)
        self.assertIn("--target wear-os-release-aab ", finish)
        self.assertEqual(freeze.PLATFORM_ALLOWED_TARGETS["wear_os"], ("wear-os-release-aab",))
        self.assertIn("--toolchain-name Gradle", finish)
        self.assertIn('--toolchain-version "${GRADLE_VERSION}"', finish)
        self.assertIn('--toolchain-revision "${GRADLE_DISTRIBUTION_SHA256}"', finish)
        self.assertIn('--output "${WEAR_AAB_RECEIPT}"', finish)
        self.assertIn(
            'WEAR_AAB_BEGIN="${FREEZE_RECEIPT_DIR}/WEAR_OS_AAB_BUILD_BEGIN.json"', self.script
        )
        self.assertIn(
            'WEAR_AAB_RECEIPT="${FREEZE_RECEIPT_DIR}/WEAR_OS_AAB_BUILD_RECEIPT.json"', self.script
        )
        # The permission-frozen signed-AAB receipt directory must stay a new
        # path for create_signed_aab_receipt.py, so the freeze receipts sit
        # beside it, never inside it.
        self.assertIn('FREEZE_RECEIPT_DIR="${RECEIPT_DIR}-dependency-freeze"', self.script)

    def test_gradle_identity_reader_matches_the_wrapper_and_toolchain_pin(self) -> None:
        match = re.search(
            r'GRADLE_IDENTITY="\$\(wins_release_python_run - "\$\{WEAR\}/gradle/wrapper/'
            r"gradle-wrapper.properties\" <<'PY'\n(.*?)\nPY\n",
            self.script,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        completed = subprocess.run(
            [sys.executable, "-I", "-B", "-", str(WEAR / "gradle/wrapper/gradle-wrapper.properties")],
            input=match.group(1),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        version, digest = completed.stdout.split()
        pins = json.loads((ROOT / "tools/toolchain-pins.json").read_text(encoding="utf-8"))
        gradle = pins["tools"]["gradle"]
        self.assertEqual(version, gradle["distribution_version"])
        self.assertEqual(digest, gradle["distribution_sha256_by_flavour"]["all"])


PHONE_PRODUCER = ROOT / "tools" / "build_android_release_macos.sh"
SHARED_BEGIN = "# BEGIN functions shared verbatim with the phone producer\n"
SHARED_END = "# END functions shared verbatim with the phone producer\n"
SHARED_FUNCTIONS = (
    "read_wins_toolchain_pin",
    "read_pinned_release_python_executable",
    "prepare_pinned_release_python",
    "release_python_cleanup",
    "toolchain_platform_key",
    "custody_regular_file_sha256",
    "verify_home_toolchain_tree",
    "run_with_exact_environment",
)
GLUE_FUNCTIONS = (
    "prepare_wear_toolchains",
    "assert_reviewed_wear_toolchains",
    "wins_release_python_run",
)
ENV_ARGUMENT_GUARD = r"""/usr/bin/env() {
  local argument
  for argument in "$@"; do
    case "${argument}" in
      *key-password-fixture*|*store-password-fixture*)
        printf 'SECRET-IN-ENV-ARGUMENTS\n' >&2
        return 97
        ;;
    esac
  done
  command /usr/bin/env "$@"
}"""
FIXTURE_JAVA = {
    "version": "21.0.9.1",
    "release_name": "jdk-21.0.9.1+3",
    "vendor": "Eclipse Adoptium",
    "architecture": "aarch64",
    "image_type": "jdk",
    "jvm": "hotspot",
}
JAVA_IDENTITY = (
    'openjdk version "21.0.9.1" 2026-01-01\n'
    "OpenJDK Runtime Environment Temurin-21.0.9.1+3 (build 21.0.9.1+3)\n"
)
PYTHON_IDENTITY_PROBE = (
    'import platform,sys; print(f"{platform.python_implementation().lower()}|'
    '{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")'
)


def _shell_function(source: str, name: str) -> str:
    """One top-level shell function: from `name() {` to the first closing brace line."""
    match = re.search(r"(?m)^" + re.escape(name) + r"\(\) \{\n", source)
    if match is None:
        raise AssertionError(f"shell function {name}() is not defined")
    end = source.index("\n}\n", match.start()) + 3
    return source[match.start():end]


def _canonical_tree_sha256(root: pathlib.Path) -> str:
    """Independent implementation of the pinned tree encoding (D, L and F records)."""
    digest = hashlib.sha256()

    def feed(*parts: object) -> None:
        for part in parts:
            value = str(part).encode("utf-8", "surrogateescape")
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)

    def walk(directory: pathlib.Path) -> None:
        for name in sorted(os.listdir(directory), key=os.fsencode):
            path = directory / name
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                feed("D", relative, 0o500)
                walk(path)
            elif stat.S_ISLNK(info.st_mode):
                feed("L", relative, os.readlink(path))
            else:
                mode = 0o500 if info.st_mode & 0o111 else 0o400
                feed("F", relative, mode, info.st_size, hashlib.sha256(path.read_bytes()).hexdigest())

    walk(root)
    return digest.hexdigest()


class PinnedToolchainSourceTests(unittest.TestCase):
    """Static properties of the toolchain section of the Wear producer."""

    def setUp(self) -> None:
        self.script = PREPARE.read_text(encoding="utf-8")
        self.phone = PHONE_PRODUCER.read_text(encoding="utf-8")

    def test_pinned_toolchain_functions_match_the_phone_producer(self) -> None:
        # The phone producer cannot be sourced (it runs the build when read), so
        # the Wear producer carries copies. Any drift from the phone producer's
        # verification functions fails here, so Wear is never verified more
        # loosely than the phone build is.
        begin = self.script.index(SHARED_BEGIN) + len(SHARED_BEGIN)
        end = self.script.index(SHARED_END)
        region = self.script[begin:end]
        self.assertEqual(
            re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_]*)\(\) \{$", region),
            list(SHARED_FUNCTIONS),
        )
        for name in SHARED_FUNCTIONS:
            with self.subTest(function=name):
                self.assertEqual(_shell_function(self.script, name), _shell_function(self.phone, name))
        self.assertEqual(region, "\n".join(_shell_function(self.phone, name) for name in SHARED_FUNCTIONS))

    def test_no_root_custody_tree_or_authority_remains(self) -> None:
        for forbidden in (
            "release_python_archive_custody",
            "release_android_toolchain_archive_custody",
            "wins_release_python_prepare",
            "wins_release_android_toolchains_prepare",
            "wins_release_android_toolchains_cleanup",
            "wins_release_python_cleanup",
            "/Library/WinsVPN",
            "ReleasePython",
            "sudo",
            "build_android_release_macos.sh",
        ):
            self.assertNotIn(forbidden, self.script, forbidden)
        self.assertIn('"$(/usr/bin/id -u)" != "0"', self.script)

    def test_toolchains_are_verified_before_any_gate_and_rechecked_around_gradle(self) -> None:
        lines = self.script.splitlines()

        def first(prefix: str, start: int = 0) -> int:
            for number in range(start, len(lines)):
                if lines[number].startswith(prefix):
                    return number
            raise AssertionError(prefix)

        trap = first("trap cleanup EXIT")
        prepare = lines.index("prepare_wear_toolchains")
        self.assertEqual(prepare, trap + 2)
        source_freeze = first('wins_release_python_run "${SOURCE_FREEZE}"')
        self.assertLess(prepare, source_freeze)
        rechecks = [n for n, line in enumerate(lines) if line == "assert_reviewed_wear_toolchains"]
        self.assertEqual(len(rechecks), 3)
        begin = first('/bin/bash "${DEPENDENCY_FREEZE}" begin-build')
        gradle = first('  exec /bin/bash "${GRADLEW}"')
        first_gate = first('wins_release_python_run "${ASSERT_AAB}"')
        last_gate = first('wins_release_python_run "${RECEIPT_TOOL}" verify')
        finish = first('/bin/bash "${DEPENDENCY_FREEZE}" finish-build')
        self.assertTrue(begin < rechecks[0] < gradle < rechecks[1] < first_gate)
        self.assertTrue(last_gate < rechecks[2] < finish)

    def test_python_gate_runner_never_uses_an_env_command_line(self) -> None:
        runner = _shell_function(self.script, "wins_release_python_run")
        self.assertNotIn("/usr/bin/env", runner)
        self.assertEqual(runner.count("run_with_exact_environment"), 1)
        self.assertIn('-- "${PYTHON_BIN}" "${startup_flags[@]}" "$@"', runner)

    def test_privacy_scan_names_the_signing_secrets_like_the_phone_producer(self) -> None:
        # The phone producer scans its artifacts for the two signing passwords by
        # naming them with --secret-env (names only). The Wear scan must name the
        # same two, so an AAB that embeds either password is refused.
        phone_names = re.findall(r"--secret-env (\w+)", self.phone)
        self.assertEqual(sorted(set(phone_names)), ["WINS_ANDROID_KEY_PASSWORD", "WINS_ANDROID_STORE_PASSWORD"])
        match = re.search(
            r'(?m)^wins_release_python_run "\$\{PRIVACY_TOOL\}"((?: [^\n]*\\\n)*[^\n]*)$', self.script
        )
        self.assertIsNotNone(match)
        invocation = match.group(0)
        self.assertEqual(invocation.count("--secret-env"), 2)
        self.assertEqual(sorted(re.findall(r"--secret-env (\w+)", invocation)), sorted(set(phone_names)))
        self.assertIn("--artifacts --target wear-os-aab --artifact", invocation)
        self.assertNotRegex(invocation, r"--secret-env \S*=")

    def test_ambient_toolchain_overrides_are_refused_before_anything_is_read(self) -> None:
        for name in (
            "PYTHON_BIN",
            "WINS_RELEASE_PYTHON",
            "JAVA_HOME",
            "WINS_BUNDLETOOL_JAR",
            "ANDROID_SDK_ROOT",
            "ANDROID_HOME",
            "WINS_RELEASE_OPENSSL",
            "WINS_RELEASE_KEYTOOL",
            "WINS_RELEASE_JARSIGNER",
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as home:
                completed = subprocess.run(
                    ["/bin/bash", "-p", str(PREPARE)],
                    env={"HOME": home, "PATH": "/usr/bin:/bin", name: "/hostile"},
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=30,
                )
                self.assertEqual(completed.returncode, 1, completed.stderr)
                self.assertIn(f"ambient {name} is forbidden", completed.stderr)


@unittest.skipUnless(sys.platform == "darwin", "macOS Wear producer functions")
class PinnedWearToolchainTests(unittest.TestCase):
    """The producer's toolchain functions run under /bin/bash against fixtures.

    Fixtures: a pin file whose digests are computed here independently, an
    interpreter whose SHA-256 is pinned, runtime wheels built here, a JDK tree
    under a fixture HOME and a bundletool stand-in. The functions are extracted
    from the producer text, so what runs is what the producer contains.
    """

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._remove_temp)
        self.base = pathlib.Path(self._temp.name).resolve()
        self.key = {"arm64": "darwin_arm64", "x86_64": "darwin_amd64"}[os.uname().machine]
        self.root = self.base / "repo"
        (self.root / "tools").mkdir(parents=True)
        self.tmp = self.base / "tmp"
        self.tmp.mkdir()
        self.home = self.base / "home"
        self.home.mkdir()
        self.records = self.base / "records"
        self.records.mkdir()
        self.sdk = self.base / "android-sdk"
        self.sdk.mkdir()
        self.bundletool = self.base / "bundletool-all-fixture.jar"
        self.bundletool.write_bytes(b"bundletool-fixture-bytes\n")
        self.interpreter = self.base / "bin" / "fixture-python"
        self.interpreter.parent.mkdir()
        self.interpreter.write_text('#!/bin/sh\nexec /usr/bin/python3 "$@"\n', encoding="ascii")
        self.interpreter.chmod(0o755)
        identity = subprocess.run(
            ["/usr/bin/python3", "-I", "-S", "-c", PYTHON_IDENTITY_PROBE],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
        self.implementation, self.version = identity.split("|")
        self.wheels = [
            self._wheel("fixturemod-1.0-py3-none-any.whl", [("fixturemod/__init__.py", b"VALUE = 'wheel-ok'\n")]),
            self._wheel("othermod-1.0-py3-none-any.whl", [("othermod.py", b"NAME = 'other'\n")]),
        ]
        self.java = self.home / ".local" / "toolchains" / f"jdk-{FIXTURE_JAVA['version']}"
        self._build_jdk()
        self._write_pins()

    def _remove_temp(self) -> None:
        for current, directories, _files in os.walk(self.base):
            for name in directories:
                os.chmod(os.path.join(current, name), 0o700, follow_symlinks=False)
        os.chmod(self.base, 0o700)
        self._temp.cleanup()

    def _wheel(self, name: str, members: list) -> tuple[pathlib.Path, str]:
        path = self.base / "wheels" / name
        path.parent.mkdir(exist_ok=True)
        with zipfile.ZipFile(path, "w") as archive:
            for member_name, data in members:
                archive.writestr(member_name, data)
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def _build_jdk(self) -> None:
        for directory in ("bin", "lib", "legal"):
            (self.java / directory).mkdir(parents=True, exist_ok=True)
        (self.java / "release").write_text(
            'IMPLEMENTOR="Eclipse Adoptium"\n'
            f'JAVA_VERSION="{FIXTURE_JAVA["version"]}"\n'
            'JAVA_RUNTIME_VERSION="21.0.9.1+3"\n'
            'OS_ARCH="aarch64"\n'
            'IMAGE_TYPE="JDK"\n'
            'JVM_VARIANT="Hotspot"\n',
            encoding="ascii",
        )
        self._java_tool("java", f"if [ \"$1\" = \"-version\" ]; then printf %s {shlex.quote(JAVA_IDENTITY)} >&2; exit 0; fi\n")
        self._java_tool("jarsigner")
        self._java_tool("keytool")
        (self.java / "lib" / "modules").write_bytes(b"jdk-modules-payload\n" * 64)
        (self.java / "legal" / "LICENSE").write_text("license\n", encoding="ascii")
        os.symlink("modules", self.java / "lib" / "modules-link")

    def _java_tool(self, name: str, body: str = "") -> None:
        path = self.java / "bin" / name
        path.unlink(missing_ok=True)
        path.write_text("#!/bin/sh\n" + body + "exit 0\n", encoding="ascii")
        path.chmod(0o755)

    def _write_pins(
        self,
        *,
        interpreter: pathlib.Path | None = None,
        executable_sha256: str | None = None,
        java_sha256: str | None = None,
    ) -> None:
        interpreter = interpreter or self.interpreter
        pinned = {
            str(index): {"path": str(path), "sha256": digest}
            for index, (path, digest) in enumerate(self.wheels)
        }
        pinned[str(len(self.wheels))] = {
            "path": "/nonexistent/foreign-1.0-cp314-cp314-win_amd64.whl",
            "sha256": "0" * 64,
        }
        java = dict(FIXTURE_JAVA)
        java["install_tree_sha256"] = {self.key: java_sha256 or _canonical_tree_sha256(self.java)}
        pins = {
            "tools": {
                "python": {
                    "version": self.version,
                    "implementation": self.implementation,
                    "reviewed_executable_path": {self.key: str(interpreter)},
                    "executable_sha256": {
                        self.key: executable_sha256 or hashlib.sha256(self.interpreter.read_bytes()).hexdigest()
                    },
                    "archive_custody": {
                        self.key: {
                            "runtime_wheel_count": len(self.wheels),
                            "wheel_count": len(self.wheels) + 1,
                            "wheels": pinned,
                        }
                    },
                },
                "java": java,
            }
        }
        (self.root / "tools" / "toolchain-pins.json").write_text(json.dumps(pins), encoding="utf-8")

    def _recorder(self) -> pathlib.Path:
        recorder = self.base / "bin" / "recording-python"
        records = shlex.quote(str(self.records))
        recorder.write_text(
            "#!/bin/sh\n"
            f'/usr/bin/env > {records}/env.$$\n'
            f'for arg in "$@"; do printf "%s\\n" "$arg"; done > {records}/argv.$$\n',
            encoding="ascii",
        )
        recorder.chmod(0o755)
        return recorder

    def _run(self, body: str, ambient_env: dict | None = None) -> subprocess.CompletedProcess:
        source = PREPARE.read_text(encoding="utf-8")
        begin = source.index(SHARED_END) + len(SHARED_END)
        initializers = source[begin:source.index("# Binds the pinned release Python")]
        functions = "\n".join(
            _shell_function(source, name) for name in ("die",) + SHARED_FUNCTIONS + GLUE_FUNCTIONS
        )
        digest = hashlib.sha256(self.bundletool.read_bytes()).hexdigest()
        harness = "\n".join(
            (
                "set -Eeuo pipefail",
                f"ROOT={shlex.quote(str(self.root))}",
                "PIN_PYTHON_BIN=/usr/bin/python3",
                "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
                f"BUNDLETOOL_PATH={shlex.quote(str(self.bundletool))}",
                f"BUNDLETOOL_SHA256={digest}",
                f"ANDROID_SDK_ROOT={shlex.quote(str(self.sdk))}",
                f"SIGNER_TOOL={shlex.quote(str(self.root / 'tools' / 'verify_android_aab_signers.py'))}",
                f"ASSERT_AAB={shlex.quote(str(self.root / 'wear_os' / 'tools' / 'assert_release_aab.py'))}",
                f"PRIVACY_TOOL={shlex.quote(str(self.root / 'tools' / 'validate_release_artifact_privacy.py'))}",
                f"RECEIPT_TOOL={shlex.quote(str(self.root / 'wear_os' / 'tools' / 'create_signed_aab_receipt.py'))}",
                "WINS_RELEASE_OPENSSL=/usr/bin/openssl",
                f"WINS_RELEASE_KEYTOOL={shlex.quote(str(self.java / 'bin' / 'keytool'))}",
                f"WINS_RELEASE_JARSIGNER={shlex.quote(str(self.java / 'bin' / 'jarsigner'))}",
                # Like the producer: the passwords are shell variables, never exported.
                "WINS_ANDROID_KEY_PASSWORD=key-password-fixture",
                "WINS_ANDROID_STORE_PASSWORD=store-password-fixture",
                "export FOO=ambient-foo JAVA_TOOL_OPTIONS=-Dhostile=1",
                functions,
                initializers,
                "trap 'release_python_cleanup' EXIT",
                body,
            )
        )
        return subprocess.run(
            ["/bin/bash", "-c", harness],
            env={
                "HOME": str(self.home),
                "TMPDIR": str(self.tmp),
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                **(ambient_env or {}),
            },
            check=False,
            capture_output=True,
            text=True,
            timeout=300,
        )

    def _work_dirs(self) -> list:
        return sorted(p.name for p in self.tmp.iterdir() if p.name.startswith("wins-android-release-python."))

    def test_good_pins_bind_the_pinned_python_and_home_jdk(self) -> None:
        completed = self._run(
            "\n".join(
                (
                    "prepare_wear_toolchains",
                    'printf "PYTHON_BIN=%s\\n" "${PYTHON_BIN}"',
                    'printf "JAVA_HOME=%s\\nJAVA_TREE=%s\\n" "${WINS_RELEASE_JAVA_HOME}" "${WINS_RELEASE_JAVA_TREE_SHA256}"',
                    "assert_reviewed_wear_toolchains && echo RECHECK-PASSED",
                    "wins_release_python_run - heredoc-arg <<'PY'",
                    "import sys",
                    "import fixturemod, othermod",
                    "print('RUN', fixturemod.VALUE, othermod.NAME, sys.argv[1], sys.flags.no_site)",
                    "PY",
                )
            )
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(f"PYTHON_BIN={self.interpreter}\n", completed.stdout)
        self.assertIn(f"JAVA_HOME={self.java}\n", completed.stdout)
        self.assertIn(f"JAVA_TREE={_canonical_tree_sha256(self.java)}\n", completed.stdout)
        self.assertIn("RECHECK-PASSED", completed.stdout)
        self.assertIn("RUN wheel-ok other heredoc-arg 1\n", completed.stdout)
        self.assertEqual(self._work_dirs(), [])

    def _assert_refused(self, completed: subprocess.CompletedProcess, message: str) -> None:
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertNotIn("PREPARED", completed.stdout)
        self.assertIn("WEAR OS RELEASE: FAIL:", completed.stderr)
        self.assertIn(message, completed.stderr)
        self.assertEqual(self._work_dirs(), [])

    def test_wrong_python_executable_digest_is_refused(self) -> None:
        self._write_pins(executable_sha256=hashlib.sha256(b"another interpreter").hexdigest())
        completed = self._run("prepare_wear_toolchains\necho PREPARED")
        self._assert_refused(
            completed, "Pinned release Python executable does not match tools/toolchain-pins.json"
        )

    def test_symlinked_python_is_refused_even_with_the_right_digest(self) -> None:
        link = self.base / "bin" / "linked-python"
        os.symlink(self.interpreter, link)
        self._write_pins(interpreter=link)
        completed = self._run("prepare_wear_toolchains\necho PREPARED")
        self._assert_refused(completed, "Pinned release Python must be a regular non-symlink executable")

    def test_missing_python_is_refused(self) -> None:
        self._write_pins(interpreter=self.base / "bin" / "absent-python")
        completed = self._run("prepare_wear_toolchains\necho PREPARED")
        self._assert_refused(completed, "Pinned release Python must be a regular non-symlink executable")

    def test_wrong_python_wheel_digest_is_refused_and_the_work_directory_removed(self) -> None:
        self.wheels[1] = (self.wheels[1][0], hashlib.sha256(b"not the wheel").hexdigest())
        self._write_pins()
        completed = self._run("prepare_wear_toolchains\necho PREPARED")
        self._assert_refused(completed, "SHA-256 mismatch")

    def test_wrong_jdk_tree_digest_is_refused(self) -> None:
        self._write_pins(java_sha256=hashlib.sha256(b"another jdk").hexdigest())
        completed = self._run("prepare_wear_toolchains\necho PREPARED")
        self._assert_refused(completed, "pinned home java toolchain refused: installed tree digest mismatch")

    def test_changed_jdk_file_is_refused(self) -> None:
        with (self.java / "lib" / "modules").open("ab") as handle:
            handle.write(b"tampered")
        completed = self._run("prepare_wear_toolchains\necho PREPARED")
        self._assert_refused(completed, "pinned home java toolchain refused: installed tree digest mismatch")

    def test_symlinked_jdk_tool_is_refused_even_with_the_right_tree_digest(self) -> None:
        (self.java / "bin" / "keytool").unlink()
        os.symlink("java", self.java / "bin" / "keytool")
        self._write_pins()
        completed = self._run("prepare_wear_toolchains\necho PREPARED")
        self._assert_refused(completed, "bin/keytool must be a single-link regular executable file")

    def test_missing_jdk_is_refused(self) -> None:
        for current, directories, _files in os.walk(self.java):
            for name in directories:
                os.chmod(os.path.join(current, name), 0o700, follow_symlinks=False)
        shutil.rmtree(self.java)
        completed = self._run("prepare_wear_toolchains\necho PREPARED")
        self._assert_refused(completed, "toolchain root is missing")

    def test_jdk_that_reports_another_version_is_refused(self) -> None:
        self._java_tool("java", "if [ \"$1\" = \"-version\" ]; then printf %s 'openjdk version \"17.0.1\"' >&2; exit 0; fi\n")
        self._write_pins()
        completed = self._run("prepare_wear_toolchains\necho PREPARED")
        self._assert_refused(completed, "OWNER-BLOCKED: pinned home JDK identity mismatch")

    def test_preparing_twice_is_refused(self) -> None:
        completed = self._run("prepare_wear_toolchains\nprepare_wear_toolchains\necho PREPARED")
        self._assert_refused(completed, "pinned Wear toolchains were already prepared")

    def _assert_recheck_refuses(self, mutation: str, message: str) -> None:
        completed = self._run(
            "\n".join(
                (
                    "prepare_wear_toolchains",
                    "assert_reviewed_wear_toolchains && echo RECHECK-1-PASSED",
                    mutation,
                    "assert_reviewed_wear_toolchains",
                    "echo RECHECK-ACCEPTED-A-CHANGE",
                )
            )
        )
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn("RECHECK-1-PASSED", completed.stdout)
        self.assertNotIn("RECHECK-ACCEPTED-A-CHANGE", completed.stdout)
        self.assertIn(message, completed.stderr)

    def test_recheck_detects_a_jdk_change_after_preparation(self) -> None:
        self._assert_recheck_refuses(
            f"printf X >> {shlex.quote(str(self.java / 'lib' / 'modules'))}",
            "pinned home java toolchain refused: installed tree digest mismatch",
        )

    def test_recheck_detects_a_python_change_after_preparation(self) -> None:
        self._assert_recheck_refuses(
            f"printf '\\n# changed\\n' >> {shlex.quote(str(self.interpreter))}",
            "pinned release Python executable no longer matches tools/toolchain-pins.json",
        )

    def test_recheck_detects_a_pin_manifest_change_after_preparation(self) -> None:
        self._assert_recheck_refuses(
            f"printf ' ' >> {shlex.quote(str(self.root / 'tools' / 'toolchain-pins.json'))}",
            "toolchain pin manifest changed after custody was established",
        )

    def test_recheck_detects_a_bundletool_change_after_preparation(self) -> None:
        self._assert_recheck_refuses(
            f"printf X >> {shlex.quote(str(self.bundletool))}",
            "bundletool-all jar no longer matches the reviewed pin",
        )

    def test_python_gates_receive_only_the_environment_their_tool_verifies(self) -> None:
        recorder = self._recorder()
        vendor = self.base / "vendor"
        vendor.mkdir()
        calls = {
            "signer": '"${SIGNER_TOOL}" aab',
            "assert": '"${ASSERT_AAB}" aab',
            "receipt": '"${RECEIPT_TOOL}" record',
            "other": "/some/other/tool.py arg",
        }
        body = [
            f"PYTHON_BIN={shlex.quote(str(recorder))}",
            f"RELEASE_PYTHON_VENDOR={shlex.quote(str(vendor))}",
            f"WINS_RELEASE_JAVA_HOME={shlex.quote(str(self.java))}",
            "export WINS_RELEASE_SECRET_INVENTORY=/inventory.json WINS_RELEASE_JAVA_HOME",
        ]
        for label, call in calls.items():
            body.append(f"wins_release_python_run {call}")
            body.append(f"mv {shlex.quote(str(self.records))}/env.* {shlex.quote(str(self.records))}/{label}.env")
            body.append(f"mv {shlex.quote(str(self.records))}/argv.* {shlex.quote(str(self.records))}/{label}.argv")
        completed = self._run("\n".join(body))
        self.assertEqual(completed.returncode, 0, completed.stderr)

        def record(label: str) -> tuple[dict, list]:
            env = {}
            for line in (self.records / f"{label}.env").read_text(encoding="utf-8").splitlines():
                key, _, value = line.partition("=")
                env[key] = value
            for key in ("PWD", "SHLVL", "_", "OLDPWD"):
                env.pop(key, None)
            return env, (self.records / f"{label}.argv").read_text(encoding="utf-8").splitlines()

        common = {"HOME", "TMPDIR", "PATH", "PYTHONPATH", "PYTHONNOUSERSITE", "PYTHONDONTWRITEBYTECODE", "WINS_RELEASE_SECRET_INVENTORY"}
        for label in calls:
            env, argv = record(label)
            self.assertEqual(env["PYTHONPATH"], str(vendor), label)
            self.assertEqual(env["PYTHONNOUSERSITE"], "1", label)
            self.assertEqual(env["PYTHONDONTWRITEBYTECODE"], "1", label)
            self.assertEqual(env["WINS_RELEASE_SECRET_INVENTORY"], "/inventory.json", label)
            for hostile in ("FOO", "JAVA_TOOL_OPTIONS", "WINS_ANDROID_KEY_PASSWORD", "WINS_ANDROID_STORE_PASSWORD"):
                self.assertNotIn(hostile, env, label)
            self.assertTrue(common.issubset(env), label)
        env, argv = record("signer")
        self.assertEqual(argv[:2], ["-I", "-S"])
        self.assertEqual(
            set(env) - common,
            {"WINS_RELEASE_JAVA_HOME", "WINS_BUNDLETOOL_JAR", "ANDROID_SDK_ROOT"},
        )
        self.assertEqual(env["WINS_BUNDLETOOL_JAR"], str(self.bundletool))
        self.assertEqual(env["WINS_RELEASE_JAVA_HOME"], str(self.java))
        self.assertEqual(env["ANDROID_SDK_ROOT"], str(self.sdk))
        env, argv = record("assert")
        self.assertEqual(argv[0], "-S")
        self.assertEqual(set(env) - common, {"WINS_RELEASE_JAVA_HOME"})
        env, argv = record("receipt")
        self.assertEqual(argv[0], "-S")
        self.assertEqual(
            set(env) - common,
            {
                "WINS_RELEASE_JAVA_HOME",
                "ANDROID_SDK_ROOT",
                "WINS_RELEASE_OPENSSL",
                "WINS_RELEASE_KEYTOOL",
                "WINS_RELEASE_JARSIGNER",
            },
        )
        self.assertNotIn("WINS_BUNDLETOOL_JAR", env)
        self.assertEqual(env["WINS_RELEASE_JAVA_HOME"], str(self.java))
        self.assertEqual(env["ANDROID_SDK_ROOT"], str(self.sdk))
        self.assertEqual(env["WINS_RELEASE_KEYTOOL"], str(self.java / "bin" / "keytool"))
        env, argv = record("other")
        self.assertEqual(argv[0], "-S")
        self.assertEqual(set(env) - common, set())

    def _recorded_privacy_run(self, *arguments: str, setup: str = "") -> tuple[subprocess.CompletedProcess, dict]:
        recorder = self._recorder()
        vendor = self.base / "vendor"
        vendor.mkdir(exist_ok=True)
        completed = self._run(
            "\n".join(
                (
                    f"PYTHON_BIN={shlex.quote(str(recorder))}",
                    f"RELEASE_PYTHON_VENDOR={shlex.quote(str(vendor))}",
                    f"WINS_RELEASE_JAVA_HOME={shlex.quote(str(self.java))}",
                    setup,
                    'wins_release_python_run "${PRIVACY_TOOL}" --artifacts --target wear-os-aab --artifact /aab '
                    + " ".join(arguments),
                )
            )
        )
        env: dict[str, str] = {}
        for path in self.records.glob("env.*"):
            for line in path.read_text(encoding="utf-8").splitlines():
                key, _, value = line.partition("=")
                env[key] = value
        return completed, env

    def test_privacy_passwords_never_enter_external_command_lines(self) -> None:
        # A process observer can read the command line of /usr/bin/env while it
        # runs, so `env -i NAME=password command` exposes the value. Any call to
        # /usr/bin/env that carries a fixture password in its arguments fails
        # here; the child must still receive both values.
        completed, env = self._recorded_privacy_run(
            "--secret-env WINS_ANDROID_KEY_PASSWORD",
            "--secret-env WINS_ANDROID_STORE_PASSWORD",
            setup=ENV_ARGUMENT_GUARD,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("SECRET-IN-ENV-ARGUMENTS", completed.stderr)
        self.assertEqual(env["WINS_ANDROID_KEY_PASSWORD"], "key-password-fixture")
        self.assertEqual(env["WINS_ANDROID_STORE_PASSWORD"], "store-password-fixture")

    def test_gate_child_environment_ignores_the_callers_shell_level_and_exports(self) -> None:
        # The child's whole environment, SHLVL included (the recording tool is a
        # /bin/sh script, which adds its own), must be the same whatever the
        # caller exported or its inherited shell level was.
        recorder = self._recorder()
        vendor = self.base / "vendor"
        vendor.mkdir()
        body = "\n".join(
            (
                f"PYTHON_BIN={shlex.quote(str(recorder))}",
                f"RELEASE_PYTHON_VENDOR={shlex.quote(str(vendor))}",
                f"WINS_RELEASE_JAVA_HOME={shlex.quote(str(self.java))}",
                'wins_release_python_run "${PRIVACY_TOOL}" --artifacts --target wear-os-aab --artifact /aab '
                "--secret-env WINS_ANDROID_KEY_PASSWORD --secret-env WINS_ANDROID_STORE_PASSWORD",
            )
        )
        seen = []
        for ambient in (
            {},
            {"SHLVL": "73", "assignments": "ambient", "exported_name": "ambient", "FOO.BAR": "ambient", "_": "/ambient"},
        ):
            for stale in self.records.glob("env.*"):
                stale.unlink()
            completed = self._run(body, ambient_env=ambient)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            (path,) = self.records.glob("env.*")
            seen.append(dict(line.partition("=")[::2] for line in path.read_text(encoding="utf-8").splitlines()))
        self.assertEqual(seen[0], seen[1])
        self.assertIn("SHLVL", seen[0])
        self.assertEqual(seen[1]["WINS_ANDROID_KEY_PASSWORD"], "key-password-fixture")

    def test_privacy_scan_receives_the_two_signing_passwords_and_nothing_else(self) -> None:
        completed, env = self._recorded_privacy_run(
            "--secret-env WINS_ANDROID_KEY_PASSWORD", "--secret-env WINS_ANDROID_STORE_PASSWORD",
            setup="export WINS_RELEASE_SECRET_INVENTORY=/inventory.json",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(env["WINS_ANDROID_KEY_PASSWORD"], "key-password-fixture")
        self.assertEqual(env["WINS_ANDROID_STORE_PASSWORD"], "store-password-fixture")
        self.assertEqual(env["WINS_RELEASE_SECRET_INVENTORY"], "/inventory.json")
        for hostile in ("FOO", "JAVA_TOOL_OPTIONS", "WINS_BUNDLETOOL_JAR", "WINS_RELEASE_JAVA_HOME", "ANDROID_SDK_ROOT"):
            self.assertNotIn(hostile, env)

    def test_privacy_scan_forwards_only_the_passwords_it_is_told_to_scan_for(self) -> None:
        completed, env = self._recorded_privacy_run(
            "--secret-env WINS_ANDROID_KEY_PASSWORD",
            "--secret-env WINS_ANDROID_KEYSTORE",
            "--secret-env FOO",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(env["WINS_ANDROID_KEY_PASSWORD"], "key-password-fixture")
        for other in ("WINS_ANDROID_STORE_PASSWORD", "WINS_ANDROID_KEYSTORE", "FOO"):
            self.assertNotIn(other, env)

    def test_privacy_scan_without_secret_env_names_receives_no_password(self) -> None:
        completed, env = self._recorded_privacy_run()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("WINS_ANDROID_KEY_PASSWORD", env)
        self.assertNotIn("WINS_ANDROID_STORE_PASSWORD", env)

    def test_privacy_scan_refuses_to_run_when_a_named_password_is_missing(self) -> None:
        completed, env = self._recorded_privacy_run(
            "--secret-env WINS_ANDROID_KEY_PASSWORD",
            "--secret-env WINS_ANDROID_STORE_PASSWORD",
            setup="WINS_ANDROID_STORE_PASSWORD=",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("the privacy scan needs WINS_ANDROID_STORE_PASSWORD", completed.stderr)
        self.assertEqual(env, {})

    def test_python_gates_refuse_to_run_before_python_is_prepared(self) -> None:
        completed = self._run("wins_release_python_run -c 'print(1)'\necho RAN")
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn("RAN", completed.stdout)
        self.assertIn("pinned release Python was not prepared", completed.stderr)


class PruneGeneratedWearOutputsTests(unittest.TestCase):
    """Gradle's report residue must not stay inside the frozen wear_os source root."""

    def setUp(self) -> None:
        self.script = PREPARE.read_text(encoding="utf-8")
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.wear = pathlib.Path(self._temp.name).resolve() / "wear_os"

    def _write(self, relative: str, data: bytes = b"x\n") -> pathlib.Path:
        path = self.wear / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def _run(self) -> subprocess.CompletedProcess:
        harness = "\n".join(
            (
                "set -Eeuo pipefail",
                f"WEAR={shlex.quote(str(self.wear))}",
                _shell_function(self.script, "die"),
                _shell_function(self.script, "prune_generated_wear_outputs"),
                "prune_generated_wear_outputs",
                "echo PRUNED",
            )
        )
        return subprocess.run(
            ["/bin/bash", "-c", harness],
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )

    def _remaining(self) -> set:
        return {
            path.relative_to(self.wear).as_posix()
            for path in self.wear.rglob("*")
            if path.is_file() or path.is_symlink()
        }

    def test_only_the_signed_aab_directory_survives_among_generated_trees(self) -> None:
        aab = "app/build/outputs/bundle/release/app-release.aab"
        sources = (
            "app/src/main/kotlin/Main.kt",
            "app/src/main/AndroidManifest.xml",
            "app/build.gradle.kts",
            "gradle/wrapper/gradle-wrapper.properties",
            "tools/prepare_release.sh",
        )
        residue = (
            "app/build/outputs/mapping/release/configanalyzer.html",
            "app/build/outputs/mapping/release/mapping.txt",
            "app/build/reports/lint-results-release.html",
            "app/build/intermediates/Generated.java",
            "app/build/.hidden/note.kt",
            "build/reports/problems/problems-report.html",
            ".gradle/9.8.0/gc.properties",
            ".kotlin/errors/error.log",
        )
        for relative in (aab,) + sources + residue:
            self._write(relative)
        completed = self._run()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("PRUNED", completed.stdout)
        self.assertEqual(self._remaining(), {aab, *sources})
        self.assertEqual((self.wear / aab).read_bytes(), b"x\n")

    def test_missing_generated_trees_are_not_an_error(self) -> None:
        self._write("app/src/main/kotlin/Main.kt")
        completed = self._run()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(self._remaining(), {"app/src/main/kotlin/Main.kt"})

    def test_symbolic_generated_tree_is_refused_and_its_target_untouched(self) -> None:
        outside = self.wear.parent / "outside"
        outside.mkdir()
        (outside / "keep.html").write_text("keep\n", encoding="ascii")
        self.wear.mkdir(parents=True)
        os.symlink(outside, self.wear / "build")
        completed = self._run()
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertNotIn("PRUNED", completed.stdout)
        self.assertIn("generated Wear output must not be a symbolic link", completed.stderr)
        self.assertTrue((outside / "keep.html").is_file())

    def test_symbolic_app_parent_is_refused_without_deleting_external_files(self) -> None:
        outside = self.wear.parent / "outside"
        (outside / "build" / "reports").mkdir(parents=True)
        victims = (
            outside / "build" / "keep.txt",
            outside / "build" / "reports" / "keep.html",
        )
        for victim in victims:
            victim.write_bytes(b"outside-build-data")
        self.wear.mkdir()
        os.symlink(outside, self.wear / "app")
        completed = self._run()
        self.assertNotEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("PRUNED", completed.stdout)
        self.assertIn("generated Wear output must not be a symbolic link", completed.stderr)
        for victim in victims:
            self.assertEqual(victim.read_bytes(), b"outside-build-data")

    def test_pruning_follows_mapping_custody_and_precedes_every_gate(self) -> None:
        text = self.script
        copy = text.index('cp -R "${MAPPING_SRC}/." "${SYMBOLS}/"')
        prune = text.index("\nprune_generated_wear_outputs\n")
        survive = text.index("did not survive pruning of generated outputs")
        first_gate = text.index('wins_release_python_run "${ASSERT_AAB}"')
        self.assertTrue(copy < prune < survive < first_gate)


if __name__ == "__main__":
    unittest.main()
