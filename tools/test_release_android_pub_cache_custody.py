#!/usr/bin/env python3
"""Fixture tests for immutable Flutter pub-cache archive custody.

The shell helper requires an authenticated wins_release_python_run contract
before any Android toolchain action. This fixture supplies a runner that
actually executes the in-helper custody Python. It does not stub a successful
prepare, rewrite production pins, or self-authorize replacement manifests.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
from unittest import mock
import warnings
import zipfile


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools" / "release_android_toolchain_archive_custody.sh"
PYTHON_SHELL = ROOT / "tools" / "release_python_archive_custody.sh"
PIN_MANIFEST = ROOT / "tools" / "toolchain-pins.json"
FLUTTER_ARCHIVE_NAME = "flutter_macos_arm64_3.47.6-stable.zip"
JAVA_ARCHIVE_NAME = "OpenJDK17U-jdk_aarch64_mac_hotspot_17.0.20.1_1.tar.gz"
JAVA_RELEASE_NAME = "jdk-17.0.20.1+1"
PUB_CACHE_ARCHIVE_NAME = "wins-flutter-pub-cache-fixture.zip"
PRIVATE_TMP = Path("/private/tmp")
FLUTTER_VERSION = "3.47.6"
FLUTTER_REVISION = "5fc346839b5d0eef006ed8404392afb4dfae428d"


def _load_module():
    text = HELPER.read_text(encoding="ascii")
    begin = text.index("# WINS_ANDROID_TOOLCHAIN_PYTHON_BEGIN\n")
    begin += len("# WINS_ANDROID_TOOLCHAIN_PYTHON_BEGIN\n")
    end = text.index("\n# WINS_ANDROID_TOOLCHAIN_PYTHON_END")
    source = text[begin:end]
    directory = Path(
        tempfile.mkdtemp(prefix="wins-android-pub-cache-mod.", dir=str(PRIVATE_TMP))
    )
    directory.chmod(0o700)
    path = directory / "android_toolchain_custody.py"
    path.write_text(source, encoding="ascii")
    spec = importlib.util.spec_from_file_location("android_toolchain_custody", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Android toolchain custody module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module._module_dir = directory
    return module


MODULE = _load_module()
MODULE.LIVE_HELPER = HELPER


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verification(fields: dict[str, str]) -> list[str]:
    return [
        fields["RUNTIME"],
        fields["RUNTIME_ID"],
        fields["MANIFEST"],
        fields["MANIFEST_SHA256"],
        fields["FLUTTER_ROOT"],
        fields["FLUTTER_SHA256"],
        fields["JAVA_HOME"],
        fields["JAVA_SHA256"],
        fields["FLUTTER_ID"],
        fields["JAVA_ID"],
        fields["PUB_CACHE"],
        fields["PUB_CACHE_SHA256"],
    ]


def python_run_exec() -> str:
    return "wins_release_python_run() { " + shlex.quote(sys.executable) + ' "$@"; }\n'


def write_zip_file(
    archive: zipfile.ZipFile, name: str, data: bytes, mode: int = 0o644
) -> None:
    member = zipfile.ZipInfo(name)
    member.create_system = 3
    member.compress_type = zipfile.ZIP_DEFLATED
    member.external_attr = (stat.S_IFREG | mode) << 16
    archive.writestr(member, data)


def thaw_tree(root: Path) -> None:
    for path in root.rglob("*"):
        if not path.is_symlink():
            try:
                path.chmod(path.stat().st_mode | stat.S_IWUSR | stat.S_IXUSR)
            except FileNotFoundError:
                pass
    if root.exists() and not root.is_symlink():
        root.chmod(root.stat().st_mode | stat.S_IWUSR | stat.S_IXUSR)


def freeze_fixture_tree(root: Path, executable_paths: set[str] | None = None) -> None:
    executable_paths = executable_paths or set()
    directories = [root]
    for base_text, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        base = Path(base_text)
        directories.append(base)
        for filename in filenames:
            path = base / filename
            if path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix()
            path.chmod(0o500 if relative in executable_paths else 0o400)
    for directory in reversed(directories):
        directory.chmod(0o500)


def zip_tree(source_parent: Path, archive_path: Path) -> None:
    with zipfile.ZipFile(archive_path, "w") as archive:
        for path in sorted(source_parent.rglob("*"), key=lambda item: os.fsencode(str(item))):
            relative = path.relative_to(source_parent).as_posix()
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                member = zipfile.ZipInfo(relative + "/")
                member.create_system = 3
                member.compress_type = zipfile.ZIP_STORED
                member.external_attr = (stat.S_IFDIR | stat.S_IMODE(info.st_mode)) << 16
                archive.writestr(member, b"")
            elif stat.S_ISLNK(info.st_mode):
                member = zipfile.ZipInfo(relative)
                member.create_system = 3
                member.compress_type = zipfile.ZIP_STORED
                member.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(member, os.readlink(path).encode("utf-8"))
            else:
                member = zipfile.ZipInfo(relative)
                member.create_system = 3
                member.compress_type = zipfile.ZIP_DEFLATED
                member.external_attr = (stat.S_IFREG | stat.S_IMODE(info.st_mode)) << 16
                archive.writestr(member, path.read_bytes())


def tar_tree(source_parent: Path, archive_path: Path) -> None:
    def normalized(info: tarfile.TarInfo) -> tarfile.TarInfo:
        info.uid = 0
        info.gid = 0
        info.uname = ""
        info.gname = ""
        info.mtime = 0
        return info

    with tarfile.open(archive_path, "w:gz", dereference=False) as archive:
        archive.add(
            source_parent / JAVA_RELEASE_NAME,
            arcname=JAVA_RELEASE_NAME,
            filter=normalized,
        )


@unittest.skipUnless(
    platform.system() == "Darwin" and platform.machine() == "arm64",
    "exact darwin_arm64 fixture host required",
)
class ReleaseAndroidPubCacheCustodyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.base = Path(
            tempfile.mkdtemp(prefix="wins-android-pub-cache-custody-", dir=str(PRIVATE_TMP))
        )
        cls.base.chmod(0o700)
        cls.sources = cls.base / "sources"
        cls.inputs = cls.base / "inputs"
        cls.sources.mkdir(mode=0o700)
        cls.inputs.mkdir(mode=0o700)
        cls.flutter_parent, cls.flutter_root = cls._make_flutter_tree()
        cls.java_parent, cls.java_home = cls._make_java_tree()
        cls.pub_parent, cls.pub_root = cls._make_pub_cache_tree()
        cls.flutter_archive = cls.inputs / FLUTTER_ARCHIVE_NAME
        cls.java_archive = cls.inputs / JAVA_ARCHIVE_NAME
        cls.pub_archive = cls.inputs / PUB_CACHE_ARCHIVE_NAME
        zip_tree(cls.flutter_parent, cls.flutter_archive)
        tar_tree(cls.java_parent, cls.java_archive)
        zip_tree(cls.pub_parent, cls.pub_archive)
        cls.flutter_archive.chmod(0o444)
        cls.java_archive.chmod(0o444)
        cls.pub_archive.chmod(0o444)
        extracted = cls.base / "hash-reference"
        extracted.mkdir(mode=0o700)
        MODULE.extract_zip(cls.flutter_archive, extracted / "flutter-archive", "flutter")
        MODULE.extract_tar(cls.java_archive, extracted / "java-archive", JAVA_RELEASE_NAME)
        MODULE.extract_zip(
            cls.pub_archive,
            extracted / "pub-cache-archive",
            "pub-cache",
            allow_symlinks=False,
        )
        flutter_root = extracted / "flutter-archive" / "flutter"
        java_home = extracted / "java-archive" / JAVA_RELEASE_NAME / "Contents" / "Home"
        pub_root = extracted / "pub-cache-archive" / "pub-cache"
        MODULE.normalize_modes(flutter_root, flutter_tree=True)
        MODULE.normalize_modes(java_home)
        MODULE.normalize_modes(pub_root / "hosted")
        MODULE.normalize_modes(pub_root / "hosted-hashes")
        cls.flutter_tree_sha = MODULE.tree_hash(
            flutter_root, require_frozen=True, flutter_tree=True
        )
        cls.java_tree_sha = MODULE.tree_hash(java_home, require_frozen=True)
        cls.pub_payload_sha = MODULE.pub_cache_payload_hash(
            pub_root, require_frozen=True, permit_active_roots=False
        )
        thaw_tree(extracted)
        shutil.rmtree(extracted)

    @classmethod
    def tearDownClass(cls) -> None:
        thaw_tree(cls.base)
        shutil.rmtree(cls.base, ignore_errors=True)
        module_dir = getattr(MODULE, "_module_dir", None)
        if module_dir is not None:
            shutil.rmtree(module_dir, ignore_errors=True)

    @classmethod
    def _compile(cls, source: str, output: Path) -> None:
        source_path = output.with_suffix(".c")
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_text(source, encoding="ascii")
        subprocess.run(
            ["/usr/bin/clang", "-arch", "arm64", "-Os", "-o", str(output), str(source_path)],
            check=True,
            capture_output=True,
            text=True,
        )
        source_path.unlink()

    @classmethod
    def _make_flutter_tree(cls) -> tuple[Path, Path]:
        parent = cls.sources / "flutter-archive"
        root = parent / "flutter"
        flutter = root / "bin" / "flutter"
        dart = root / "bin" / "cache" / "dart-sdk" / "bin" / "dart"
        dart.parent.mkdir(parents=True)
        flutter.write_text(
            textwrap.dedent(
                """\
                #!/bin/sh
                if [ "${1:-}" = "--version" ] && [ "${2:-}" = "--machine" ]; then
                  printf '%s\\n' '{"frameworkVersion":"3.47.6","frameworkRevision":"5fc346839b5d0eef006ed8404392afb4dfae428d","dartSdkVersion":"3.13.5","channel":"stable","repositoryUrl":"https://github.com/flutter/flutter.git"}'
                  exit 0
                fi
                exit 74
                """
            ),
            encoding="ascii",
        )
        cls._compile("#include <stdio.h>\nint main(void) { return 0; }\n", dart)
        cache = root / "bin" / "cache"
        (cache / "flutter_tools.snapshot").write_bytes(b"fixture snapshot\n")
        (cache / "lockfile").write_bytes(b"")
        (root / "LICENSE").write_text("fixture license\n", encoding="ascii")
        tools = root / "packages" / "flutter_tools"
        (tools / "lib").mkdir(parents=True)
        (tools / "pubspec.yaml").write_text("name: flutter_tools\n", encoding="ascii")
        (tools / "lib" / "flutter_tools.dart").write_text(
            "// fixture flutter_tools\n",
            encoding="ascii",
        )
        freeze_fixture_tree(root, {"bin/flutter", "bin/cache/dart-sdk/bin/dart"})
        (cache / "lockfile").chmod(0o600)
        return parent, root

    @classmethod
    def _make_java_tree(cls) -> tuple[Path, Path]:
        parent = cls.sources / "java-archive"
        home = parent / JAVA_RELEASE_NAME / "Contents" / "Home"
        java = home / "bin" / "java"
        java.parent.mkdir(parents=True)
        cls._compile("#include <stdio.h>\nint main(void) { return 0; }\n", java)
        shutil.copy2(java, home / "bin" / "keytool")
        shutil.copy2(java, home / "bin" / "jarsigner")
        (home / "lib").mkdir()
        shutil.copy2(java, home / "lib" / "jspawnhelper")
        (home / "release").write_text(
            'IMPLEMENTOR="Eclipse Adoptium"\n'
            'JAVA_VERSION="17.0.20.1"\n'
            'JAVA_RUNTIME_VERSION="17.0.20.1+1"\n'
            'OS_ARCH="aarch64"\n'
            'JVM_VARIANT="Hotspot"\n'
            'IMAGE_TYPE="JDK"\n',
            encoding="ascii",
        )
        freeze_fixture_tree(
            home,
            {"bin/java", "bin/keytool", "bin/jarsigner", "lib/jspawnhelper"},
        )
        return parent, home

    @classmethod
    def _make_pub_cache_tree(cls) -> tuple[Path, Path]:
        parent = cls.sources / "pub-cache-archive"
        root = parent / "pub-cache"
        package = root / "hosted" / "pub.dev" / "fixture_pkg-1.0.0"
        (package / "lib").mkdir(parents=True)
        (package / "pubspec.yaml").write_text(
            "name: fixture_pkg\nversion: 1.0.0\n",
            encoding="ascii",
        )
        (package / "lib" / "fixture_pkg.dart").write_text(
            "void marker() {}\n",
            encoding="ascii",
        )
        hashes = root / "hosted-hashes" / "pub.dev"
        hashes.mkdir(parents=True)
        (hashes / "fixture_pkg-1.0.0.sha256").write_text("a" * 64 + "\n", encoding="ascii")
        freeze_fixture_tree(root / "hosted")
        freeze_fixture_tree(root / "hosted-hashes")
        return parent, root

    def setUp(self) -> None:
        self.case = Path(tempfile.mkdtemp(prefix="case-", dir=self.base))
        self.case.chmod(0o700)
        self.flutter = self.case / FLUTTER_ARCHIVE_NAME
        self.java = self.case / JAVA_ARCHIVE_NAME
        self.pub = self.case / PUB_CACHE_ARCHIVE_NAME
        shutil.copy2(self.flutter_archive, self.flutter)
        shutil.copy2(self.java_archive, self.java)
        shutil.copy2(self.pub_archive, self.pub)
        self.flutter.chmod(0o444)
        self.java.chmod(0o444)
        self.pub.chmod(0o444)
        self.manifest = self.case / "toolchain-pins.json"
        self._write_manifest()

    def tearDown(self) -> None:
        thaw_tree(self.case)
        shutil.rmtree(self.case, ignore_errors=True)

    def _pins(self) -> dict:
        return {
            "schema_version": 1,
            "tools": {
                "flutter": {
                    "version": FLUTTER_VERSION,
                    "revision": FLUTTER_REVISION,
                    "dart_version": "3.13.5",
                    "archive_path": {"darwin_arm64": str(self.flutter)},
                    "archive_sha256": {"darwin_arm64": sha256(self.flutter)},
                    "install_tree_sha256": {"darwin_arm64": self.flutter_tree_sha},
                },
                "java": {
                    "version": "17.0.20.1",
                    "distribution": "eclipse-temurin",
                    "release_name": JAVA_RELEASE_NAME,
                    "vendor": "Eclipse Adoptium",
                    "jvm": "hotspot",
                    "architecture": "aarch64",
                    "image_type": "jdk",
                    "release_type": "ga",
                    "archive_path": {"darwin_arm64": str(self.java)},
                    "archive_sha256": {"darwin_arm64": sha256(self.java)},
                    "install_tree_sha256": {"darwin_arm64": self.java_tree_sha},
                },
                "flutter_pub_cache": {
                    "top_level_root": "pub-cache",
                    "archive_path": {"darwin_arm64": str(self.pub)},
                    "archive_sha256": {"darwin_arm64": sha256(self.pub)},
                    "install_tree_sha256": {"darwin_arm64": self.pub_payload_sha},
                },
            },
        }

    def _write_manifest(self, pins: dict | None = None) -> None:
        self.manifest.write_text(
            json.dumps(pins or self._pins(), sort_keys=True), encoding="ascii"
        )
        self.manifest.chmod(0o600)

    def _flutter_pin(self) -> dict:
        return {
            "path": self.flutter,
            "archive_sha": sha256(self.flutter),
            "tree_sha": self.flutter_tree_sha,
        }

    def _java_pin(self) -> dict:
        return {
            "path": self.java,
            "archive_sha": sha256(self.java),
            "tree_sha": self.java_tree_sha,
        }

    def _pub_pin(self) -> dict:
        return {
            "path": self.pub,
            "archive_sha": sha256(self.pub),
            "tree_sha": self.pub_payload_sha,
            "top_level_root": "pub-cache",
        }

    def _install(self) -> dict[str, str]:
        self._write_manifest()
        fields = MODULE.install_extracted_runtime(
            self._flutter_pin(),
            self._java_pin(),
            self._pub_pin(),
            manifest_path=str(self.manifest),
            manifest_sha=sha256(self.manifest),
        )
        self.addCleanup(self._cleanup_if_present, fields)
        return fields

    def _cleanup_if_present(self, fields: dict[str, str]) -> None:
        runtime_text = fields.get("RUNTIME")
        if not runtime_text:
            return
        runtime = Path(runtime_text)
        if runtime.exists() or runtime.is_symlink():
            MODULE.cleanup_runtime([runtime_text, fields["RUNTIME_ID"]])

    def _export_shell_state(self, fields: dict[str, str]) -> str:
        env_map = {
            "WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME": fields["RUNTIME"],
            "WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME_ID": fields["RUNTIME_ID"],
            "WINS_RELEASE_ANDROID_TOOLCHAIN_MANIFEST": fields["MANIFEST"],
            "WINS_RELEASE_ANDROID_TOOLCHAIN_MANIFEST_SHA256": fields["MANIFEST_SHA256"],
            "WINS_RELEASE_FLUTTER_ROOT": fields["FLUTTER_ROOT"],
            "WINS_RELEASE_FLUTTER_TREE_SHA256": fields["FLUTTER_SHA256"],
            "WINS_RELEASE_JAVA_HOME": fields["JAVA_HOME"],
            "WINS_RELEASE_JAVA_TREE_SHA256": fields["JAVA_SHA256"],
            "WINS_RELEASE_ANDROID_TOOLCHAIN_STATE": fields["STATE"],
            "WINS_RELEASE_FLUTTER_ROOT_ID": fields["FLUTTER_ID"],
            "WINS_RELEASE_JAVA_HOME_ID": fields["JAVA_ID"],
            "WINS_RELEASE_PUB_CACHE": fields["PUB_CACHE"],
            "WINS_RELEASE_PUB_CACHE_PAYLOAD_SHA256": fields["PUB_CACHE_SHA256"],
        }
        lines = [f"export {name}={shlex.quote(value)}" for name, value in env_map.items()]
        lines.append(
            'export WINS_RELEASE_FLUTTER_BIN="${WINS_RELEASE_FLUTTER_ROOT}/bin/flutter"'
        )
        lines.append('export WINS_RELEASE_JAVA_BIN="${WINS_RELEASE_JAVA_HOME}/bin/java"')
        return "\n".join(lines) + "\n"

    def _hide_live_owner_trees(self):
        missing = self.case / "absent-owner-prefix"
        return mock.patch.multiple(
            MODULE,
            OWNER_PREFIX=missing,
            OWNER_FLUTTER=missing / MODULE.OWNER_FLUTTER.name,
            OWNER_JAVA=missing / MODULE.OWNER_JAVA.name,
        )

    def _run(
        self,
        body: str,
        *,
        python: str = "exec",
        hostile_environment: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        if hostile_environment:
            environment.update(
                {
                    "PATH": str(self.case),
                    "PYTHONPATH": str(self.case / "python"),
                    "PYTHONHOME": str(self.case / "python-home"),
                    "JAVA_TOOL_OPTIONS": "-javaagent:/evil",
                    "_JAVA_OPTIONS": "-Xbootclasspath/a:/evil",
                    "JDK_JAVA_OPTIONS": "--add-opens=java.base/java.lang=ALL-UNNAMED",
                    "DYLD_INSERT_LIBRARIES": str(self.case / "evil.dylib"),
                    "BASH_ENV": str(self.case / "bash-env"),
                    "ENV": str(self.case / "shell-env"),
                    "PUB_CACHE": str(self.case / "hostile-pub-cache"),
                }
            )
        prefix = ""
        if python == "exec":
            prefix = python_run_exec()
        elif python == "noop":
            prefix = "wins_release_python_run() { :; }\n"
        elif python == "authenticated":
            prefix = f"source {shlex.quote(str(PYTHON_SHELL))}\n"
        elif python != "absent":
            raise AssertionError(f"unknown python contract fixture: {python}")
        script = f"source {shlex.quote(str(HELPER))}\n{prefix}{body}\n"
        return subprocess.run(
            ["/bin/bash", "-c", script],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
        )

    def _extract_pub(self) -> Path:
        self._extract_count = getattr(self, "_extract_count", 0) + 1
        destination = self.case / f"extracted-pub-{self._extract_count}"
        MODULE.extract_zip(
            self.pub, destination, "pub-cache", allow_symlinks=False
        )
        return destination / "pub-cache"

    def test_unauthenticated_system_python_is_refused(self) -> None:
        completed = self._run(
            f"wins_release_android_toolchains_prepare {shlex.quote(str(PIN_MANIFEST))}",
            python="absent",
        )
        self.assertNotEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("authenticated release Python custody is required", completed.stderr)
        self.assertNotIn("RUNTIME|", completed.stdout)
        helper_text = HELPER.read_text(encoding="ascii")
        self.assertNotIn("/usr/bin/python3", helper_text)
        self.assertNotIn('"/usr/bin/env"', helper_text)
        self.assertIn("wins_release_python_run", helper_text)

    def test_self_authored_manifest_cannot_prepare(self) -> None:
        completed = self._run(
            f"wins_release_android_toolchains_prepare {shlex.quote(str(self.manifest))}"
        )
        self.assertNotEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("cannot self-authorize", completed.stderr)
        self.assertNotIn("RUNTIME|", completed.stdout)
        with self.assertRaisesRegex(MODULE.Refused, "cannot self-authorize"):
            MODULE.authorize_custody_inputs(HELPER, self.manifest)
        with self.assertRaisesRegex(MODULE.Refused, "cannot self-authorize"):
            MODULE.prepare(str(self.manifest), str(HELPER))

    def test_noop_python_run_cannot_false_pass_production_prepare(self) -> None:
        completed = self._run(
            f"wins_release_android_toolchains_prepare {shlex.quote(str(PIN_MANIFEST))}",
            python="noop",
        )
        self.assertNotEqual(completed.returncode, 0, completed.stderr)
        self.assertRegex(
            completed.stderr,
            r"incomplete custody result rejected|unexpected custody result field",
        )
        self.assertNotIn("RUNTIME|", completed.stdout)
        self.assertNotIn("frameworkVersion", completed.stdout)

    def test_sourced_python_custody_without_prepare_fails_closed(self) -> None:
        completed = self._run(
            f"wins_release_android_toolchains_prepare {shlex.quote(str(PIN_MANIFEST))}",
            python="authenticated",
        )
        self.assertNotEqual(completed.returncode, 0, completed.stderr)
        self.assertRegex(
            completed.stderr,
            r"release Python custody is not prepared|owner-blocked|owner/environment blocker",
        )
        self.assertNotIn("RUNTIME|", completed.stdout)
        self.assertNotIn("frameworkVersion", completed.stdout)

    def test_happy_path_exports_private_pub_cache_and_isolates_launchers(self) -> None:
        fields = self._install()
        pub = Path(fields["PUB_CACHE"])
        self.assertEqual(fields["PUB_CACHE_SHA256"], self.pub_payload_sha)
        self.assertTrue((pub / "hosted").is_dir())
        self.assertTrue((pub / "hosted-hashes").is_dir())
        self.assertTrue((pub / "active_roots").is_dir())
        self.assertEqual(stat.S_IMODE(pub.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((pub / "hosted").stat().st_mode), 0o500)
        self.assertEqual(stat.S_IMODE((pub / "hosted-hashes").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((pub / "active_roots").stat().st_mode), 0o700)
        tools = Path(fields["FLUTTER_ROOT"]) / "packages" / "flutter_tools"
        self.assertTrue((tools / ".dart_tool" / "package_config.json").is_file())
        self.assertEqual(stat.S_IMODE(tools.stat().st_mode), 0o500)
        (pub / "active_roots" / "ok").write_text("root\n", encoding="ascii")
        MODULE.verify_runtime(verification(fields))
        env = MODULE.cloned_environment(
            Path(fields["RUNTIME"]),
            Path(fields["FLUTTER_ROOT"]),
            Path(fields["JAVA_HOME"]),
            None,
            pub,
        )
        self.assertEqual(env["PUB_CACHE"], str(pub))
        self.assertNotIn("PYTHONPATH", env)
        self.assertNotIn("BASH_ENV", env)
        self.assertNotIn("DYLD_INSERT_LIBRARIES", env)
        runtime = Path(fields["RUNTIME"])
        MODULE.cleanup_runtime([fields["RUNTIME"], fields["RUNTIME_ID"]])
        self.assertFalse(runtime.exists())
        fields.pop("RUNTIME", None)

    def test_build_wrapper_requires_exactly_one_no_pub_and_forwards_pub_cache(self) -> None:
        fields = self._install()
        sdk = self.case / "android-sdk"
        sdk.mkdir(mode=0o700)
        setup = (
            self._export_shell_state(fields)
            + f"export ANDROID_SDK_ROOT={shlex.quote(str(sdk))} "
            f"ANDROID_HOME={shlex.quote(str(sdk))}\n"
            f"export WINS_ANDROID_KEYSTORE={shlex.quote(str(self.case / 'upload.jks'))}\n"
            "export WINS_ANDROID_KEY_ALIAS=upload WINS_ANDROID_KEY_PASSWORD=key-secret "
            "WINS_ANDROID_STORE_PASSWORD=store-secret\n"
        )
        completed = self._run(setup + "wins_release_android_flutter_build build probe-env --no-pub\n")
        self.assertNotEqual(completed.returncode, 0, completed.stdout)
        self.assertTrue(
            MODULE.EXECUTION_BLOCKER in completed.stderr
            or "does not match the authenticated pin" in completed.stderr,
            completed.stderr,
        )
        self.assertNotIn("build-env-isolated", completed.stdout)
        self.assertNotIn("isolated", completed.stdout)
        for args, needle in (
            ("build probe-env", "exactly one --no-pub"),
            ("build probe-env --no-pub --no-pub", "exactly one --no-pub"),
            ("build probe-env --no-pub-get", "exactly one --no-pub"),
        ):
            with self.subTest(args=args):
                completed = self._run(setup + f"wins_release_android_flutter_build {args}\n")
                self.assertNotEqual(completed.returncode, 0, completed.stdout)
                self.assertIn(needle, completed.stderr)
                self.assertNotIn("build-env-isolated", completed.stdout)

    def test_flutter_run_is_owner_blocked_not_a_mocked_pass(self) -> None:
        fields = self._install()
        with self._hide_live_owner_trees():
            with self.assertRaisesRegex(MODULE.Refused, MODULE.EXECUTION_BLOCKER):
                MODULE.run_from_verified(
                    [*verification(fields), "--", "probe-env"],
                    kind="flutter",
                )
        MODULE.verify_runtime(verification(fields))

    def test_unapproved_execution_environment_is_rejected(self) -> None:
        fields = self._install()
        with self.assertRaisesRegex(MODULE.Refused, "unapproved execution environment"):
            MODULE.cloned_environment(
                Path(fields["RUNTIME"]),
                Path(fields["FLUTTER_ROOT"]),
                Path(fields["JAVA_HOME"]),
                {"BASH_ENV": "/evil", "PYTHONPATH": "/evil"},
                Path(fields["PUB_CACHE"]),
            )

    def test_generic_manifest_fields_must_be_exact_darwin_arm64_pub_cache_pins(self) -> None:
        for mutation in (
            "missing-path",
            "wrong-platform",
            "relative",
            "wrong-root",
            "missing-root",
            "non-zip",
        ):
            with self.subTest(mutation=mutation):
                pins = self._pins()
                pub = pins["tools"]["flutter_pub_cache"]
                if mutation == "missing-path":
                    del pub["archive_path"]
                elif mutation == "wrong-platform":
                    pub["archive_path"] = {"darwin_amd64": str(self.pub)}
                elif mutation == "relative":
                    pub["archive_path"]["darwin_arm64"] = PUB_CACHE_ARCHIVE_NAME
                elif mutation == "wrong-root":
                    pub["top_level_root"] = "pub_cache"
                elif mutation == "missing-root":
                    del pub["top_level_root"]
                else:
                    pub["archive_path"]["darwin_arm64"] = str(self.java)
                self._write_manifest(pins)
                document = json.loads(self.manifest.read_text(encoding="ascii"))
                try:
                    flutter_pin, java_pin, pub_pin = MODULE.validate_exact_pins(document)
                except MODULE.Refused:
                    continue
                self.assertIsNotNone(pub_pin)
                with self.assertRaises(MODULE.Refused):
                    MODULE.install_extracted_runtime(
                        flutter_pin,
                        java_pin,
                        pub_pin,
                        manifest_path=str(self.manifest),
                        manifest_sha=sha256(self.manifest),
                    )

    def test_wrong_archive_or_payload_hash_fails_closed(self) -> None:
        for key in ("archive_sha256", "install_tree_sha256"):
            with self.subTest(key=key):
                pins = self._pins()
                pins["tools"]["flutter_pub_cache"][key]["darwin_arm64"] = "a" * 64
                self._write_manifest(pins)
                document = json.loads(self.manifest.read_text(encoding="ascii"))
                flutter_pin, java_pin, pub_pin = MODULE.validate_exact_pins(document)
                with self.assertRaisesRegex(
                    MODULE.Refused, r"SHA-256 mismatch|must be read-only"
                ):
                    MODULE.install_extracted_runtime(
                        flutter_pin,
                        java_pin,
                        pub_pin,
                        manifest_path=str(self.manifest),
                        manifest_sha=sha256(self.manifest),
                    )

    def test_payload_hash_is_verified_before_flutter_identity_can_run(self) -> None:
        mutable = self.case / "flutter-identity-would-fail"
        shutil.copytree(self.flutter_parent, mutable, symlinks=True)
        thaw_tree(mutable)
        root = mutable / "flutter"
        launcher = root / "bin" / "flutter"
        launcher.write_text(
            launcher.read_text(encoding="ascii").replace(
                '"channel":"stable"', '"channel":"beta"'
            ),
            encoding="ascii",
        )
        freeze_fixture_tree(root, {"bin/flutter", "bin/cache/dart-sdk/bin/dart"})
        (root / "bin" / "cache" / "lockfile").chmod(0o600)
        mutated_flutter_sha = MODULE.tree_hash(
            root, require_frozen=True, flutter_tree=True
        )
        self.flutter.chmod(0o600)
        self.flutter.unlink()
        zip_tree(mutable, self.flutter)
        self.flutter.chmod(0o444)
        pub_pin = self._pub_pin()
        pub_pin["tree_sha"] = "b" * 64
        with self.assertRaisesRegex(
            MODULE.Refused, r"Flutter pub-cache.*SHA-256 mismatch|SHA-256 mismatch"
        ):
            MODULE.install_extracted_runtime(
                {
                    "path": self.flutter,
                    "archive_sha": sha256(self.flutter),
                    "tree_sha": mutated_flutter_sha,
                },
                self._java_pin(),
                pub_pin,
                manifest_path=str(self.manifest),
                manifest_sha=sha256(self.manifest),
            )

    def test_writable_symlink_and_hardlinked_pub_cache_archives_fail(self) -> None:
        self.pub.chmod(0o644)
        with self.assertRaisesRegex(MODULE.Refused, "must be read-only"):
            MODULE.install_extracted_runtime(
                self._flutter_pin(),
                self._java_pin(),
                self._pub_pin(),
                manifest_path=str(self.manifest),
                manifest_sha=sha256(self.manifest),
            )

        self.pub.chmod(0o444)
        self.pub.unlink()
        self.pub.symlink_to(self.pub_archive)
        with self.assertRaisesRegex(MODULE.Refused, r"regular non-symlink|symlink"):
            MODULE.install_extracted_runtime(
                self._flutter_pin(),
                self._java_pin(),
                self._pub_pin(),
                manifest_path=str(self.manifest),
                manifest_sha=sha256(self.manifest),
            )

        self.pub.unlink()
        private_copy = self.case / "private-copy.zip"
        shutil.copy2(self.pub_archive, private_copy)
        private_copy.chmod(0o444)
        os.link(private_copy, self.pub)
        with self.assertRaisesRegex(MODULE.Refused, r"single-link|hardlink"):
            MODULE.install_extracted_runtime(
                self._flutter_pin(),
                self._java_pin(),
                self._pub_pin(),
                manifest_path=str(self.manifest),
                manifest_sha=sha256(self.manifest),
            )

    def test_traversal_absolute_duplicate_case_and_unicode_members_fail(self) -> None:
        nfc = "caf" + "\u00e9"
        nfd = "cafe" + "\u0301"
        cases = (
            ("traversal", ("pub-cache/../escape", b"x"), None),
            ("absolute", ("/pub-cache/hosted/x", b"x"), None),
            ("duplicate", ("pub-cache/hosted/file", b"one"), ("pub-cache/hosted/file", b"two")),
            ("case", ("pub-cache/hosted/file", b"one"), ("pub-cache/hosted/FILE", b"two")),
            (
                "unicode",
                (f"pub-cache/hosted/{nfc}", b"one"),
                (f"pub-cache/hosted/{nfd}", b"two"),
            ),
        )
        for kind, first, second in cases:
            with self.subTest(kind=kind):
                self.pub.chmod(0o600)
                self.pub.unlink()
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    with zipfile.ZipFile(self.pub, "w") as archive:
                        write_zip_file(archive, first[0], first[1])
                        if second is not None:
                            write_zip_file(archive, second[0], second[1])
                self.pub.chmod(0o444)
                with self.assertRaises(MODULE.Refused):
                    self._extract_pub()

    def test_symlink_special_file_depth_and_extra_payload_fail(self) -> None:
        cases = ("symlink", "fifo", "depth", "readme", "missing-hashes")
        for kind in cases:
            with self.subTest(kind=kind):
                self.pub.chmod(0o600)
                self.pub.unlink()
                with zipfile.ZipFile(self.pub, "w") as archive:
                    write_zip_file(archive, "pub-cache/hosted/pub.dev/keep/file", b"x")
                    if kind == "symlink":
                        member = zipfile.ZipInfo("pub-cache/hosted/link")
                        member.create_system = 3
                        member.external_attr = (stat.S_IFLNK | 0o777) << 16
                        archive.writestr(member, b"../../../escape")
                    elif kind == "fifo":
                        member = zipfile.ZipInfo("pub-cache/hosted/fifo")
                        member.create_system = 3
                        member.external_attr = (stat.S_IFIFO | 0o644) << 16
                        archive.writestr(member, b"x")
                    elif kind == "depth":
                        write_zip_file(
                            archive, "pub-cache/" + "/".join(["deep"] * 129), b"x"
                        )
                    elif kind == "readme":
                        write_zip_file(archive, "pub-cache/README.md", b"extra\n")
                        write_zip_file(
                            archive,
                            "pub-cache/hosted-hashes/pub.dev/keep.sha256",
                            b"x",
                        )
                self.pub.chmod(0o444)
                if kind == "readme":
                    root = self._extract_pub()
                    with self.assertRaisesRegex(MODULE.Refused, "unsupported metadata"):
                        MODULE.pub_cache_payload_hash(
                            root, require_frozen=False, permit_active_roots=False
                        )
                elif kind == "missing-hashes":
                    root = self._extract_pub()
                    scratch = self.case / f"runtime-{kind}"
                    scratch.mkdir(mode=0o700)
                    with self.assertRaisesRegex(
                        MODULE.Refused, r"hosted/ and hosted-hashes"
                    ):
                        MODULE.install_pub_cache_runtime(
                            root, scratch, self.pub_payload_sha
                        )
                else:
                    with self.assertRaises(MODULE.Refused):
                        self._extract_pub()

    def test_zip_prefix_and_trailer_fail(self) -> None:
        original = self.pub.read_bytes()
        for label, payload in (("prefix", b"prefix" + original), ("trailer", original + b"trailer")):
            with self.subTest(mutation=label):
                self.pub.chmod(0o600)
                self.pub.write_bytes(payload)
                self.pub.chmod(0o444)
                with self.assertRaisesRegex(
                    MODULE.Refused, r"noncanonical prefix|trailer is noncanonical"
                ):
                    self._extract_pub()
                self.pub.chmod(0o600)
                self.pub.write_bytes(original)
                self.pub.chmod(0o444)

    def test_active_roots_metadata_is_permitted_but_payload_mutation_is_not(self) -> None:
        fields = self._install()
        pub = Path(fields["PUB_CACHE"])
        (pub / "active_roots" / "session").write_text("ok\n", encoding="ascii")
        MODULE.verify_runtime(verification(fields))
        payload = pub / "hosted" / "pub.dev" / "fixture_pkg-1.0.0" / "lib" / "fixture_pkg.dart"
        os.chmod(payload, 0o600)
        with payload.open("ab") as stream:
            stream.write(b"mutated\n")
        os.chmod(payload, 0o400)
        with self.assertRaisesRegex(MODULE.Refused, "pub-cache payload"):
            MODULE.verify_runtime(verification(fields))

        fields = self._install()
        pub = Path(fields["PUB_CACHE"])
        os.chmod(pub, 0o700)
        (pub / "evil").write_text("evil\n", encoding="ascii")
        with self.assertRaisesRegex(MODULE.Refused, "unsupported metadata"):
            MODULE.verify_runtime(verification(fields))

    def test_exported_payload_digest_repin_is_rejected(self) -> None:
        fields = self._install()
        args = verification(fields)
        args[-1] = "a" * 64
        with self.assertRaisesRegex(MODULE.Refused, "authoritative manifest pin"):
            MODULE.verify_runtime(args)

    def test_hosted_hash_rewrite_and_temp_lifecycle_are_restored_before_verify(self) -> None:
        original = "a" * 64 + "\n"
        rewritten = "b" * 64 + "\n"
        fields = self._install()
        pub = Path(fields["PUB_CACHE"])
        hash_path = pub / "hosted-hashes" / "pub.dev" / "fixture_pkg-1.0.0.sha256"
        hash_path.write_text(rewritten, encoding="ascii")
        (pub / "_temp" / "nested").mkdir(parents=True)
        (pub / "_temp" / "nested" / "scratch").write_text("scratch\n", encoding="ascii")
        (
            pub / "hosted-hashes" / "pub.dev" / "file_testing-3.0.2.sha256"
        ).write_text("c" * 64 + "\n", encoding="ascii")
        MODULE.verify_runtime(verification(fields))
        self.assertFalse((pub / "_temp").exists())
        self.assertFalse(
            (pub / "hosted-hashes" / "pub.dev" / "file_testing-3.0.2.sha256").exists()
        )
        self.assertEqual(hash_path.read_text(encoding="ascii"), original)
        self.assertEqual(stat.S_IMODE((pub / "hosted-hashes").stat().st_mode), 0o700)

    def test_command_failure_still_cleans_pub_cache_metadata(self) -> None:
        fields = self._install()
        pub = Path(fields["PUB_CACHE"])
        hash_path = pub / "hosted-hashes" / "pub.dev" / "fixture_pkg-1.0.0.sha256"
        hash_path.write_text("b" * 64 + "\n", encoding="ascii")
        (pub / "_temp").mkdir()
        (pub / "_temp" / "scratch").write_text("scratch\n", encoding="ascii")
        (
            pub / "hosted-hashes" / "pub.dev" / "file_testing-3.0.2.sha256"
        ).write_text("c" * 64 + "\n", encoding="ascii")
        with self._hide_live_owner_trees():
            with self.assertRaisesRegex(MODULE.Refused, MODULE.EXECUTION_BLOCKER):
                MODULE.run_from_verified(
                    [*verification(fields), "--", "fail-after-cache-write"],
                    kind="flutter",
                )
        self.assertFalse((pub / "_temp").exists())
        self.assertFalse(
            (pub / "hosted-hashes" / "pub.dev" / "file_testing-3.0.2.sha256").exists()
        )
        self.assertEqual(hash_path.read_text(encoding="ascii").strip(), "a" * 64)

    def test_temp_and_hash_symlinks_are_rejected(self) -> None:
        fields = self._install()
        pub = Path(fields["PUB_CACHE"])
        os.symlink("hosted", pub / "_temp")
        with self.assertRaisesRegex(MODULE.Refused, r"_temp"):
            MODULE.verify_runtime(verification(fields))
        (pub / "_temp").unlink()

        fields = self._install()
        pub = Path(fields["PUB_CACHE"])
        hash_path = pub / "hosted-hashes" / "pub.dev" / "fixture_pkg-1.0.0.sha256"
        hash_path.unlink()
        os.symlink(
            "../../hosted/pub.dev/fixture_pkg-1.0.0/lib/fixture_pkg.dart",
            hash_path,
        )
        with self.assertRaisesRegex(MODULE.Refused, r"symlink|link"):
            MODULE.verify_runtime(verification(fields))
        hash_path.unlink()

        fields = self._install()
        pub = Path(fields["PUB_CACHE"])
        (pub / "_temp").mkdir()
        os.symlink("../hosted", pub / "_temp" / "escape")
        with self.assertRaisesRegex(MODULE.Refused, "symlink"):
            MODULE.verify_runtime(verification(fields))
        (pub / "_temp" / "escape").unlink()

        fields = self._install()
        pub = Path(fields["PUB_CACHE"])
        hard = pub / "_temp" / "hard"
        payload = (
            pub / "hosted" / "pub.dev" / "fixture_pkg-1.0.0" / "lib" / "fixture_pkg.dart"
        )
        (pub / "_temp").mkdir()
        os.link(payload, hard)
        try:
            with self.assertRaisesRegex(MODULE.Refused, r"link|hardlink|hard"):
                MODULE.verify_runtime(verification(fields))
        finally:
            if hard.exists() or hard.is_symlink():
                hard.unlink()

        fields = self._install()
        tools = Path(fields["FLUTTER_ROOT"]) / "packages" / "flutter_tools"
        os.chmod(tools, 0o700)
        dart_tool = tools / ".dart_tool"
        os.chmod(dart_tool, 0o700)
        os.chmod(dart_tool / "package_config.json", 0o600)
        shutil.rmtree(dart_tool)
        os.symlink("hosted", dart_tool)
        with self.assertRaisesRegex(MODULE.Refused, "symlink"):
            MODULE.verify_runtime(verification(fields))
        dart_tool.unlink()

        fields = self._install()
        tools = Path(fields["FLUTTER_ROOT"]) / "packages" / "flutter_tools"
        os.chmod(tools, 0o700)
        dart_tool = tools / ".dart_tool"
        os.chmod(dart_tool, 0o700)
        (dart_tool / "evil").write_text("evil\n", encoding="ascii")
        with self.assertRaisesRegex(MODULE.Refused, "unsupported metadata"):
            MODULE.verify_runtime(verification(fields))
        (dart_tool / "evil").unlink()

    def test_helper_shell_syntax_is_valid(self) -> None:
        syntax = subprocess.run(
            ["/bin/bash", "-n", str(HELPER)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        python_syntax = subprocess.run(
            ["/bin/bash", "-n", str(PYTHON_SHELL)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(python_syntax.returncode, 0, python_syntax.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
