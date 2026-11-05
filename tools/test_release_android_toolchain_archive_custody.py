#!/usr/bin/env python3
"""Adversarial fixture tests for Android release toolchain archive custody."""

from __future__ import annotations

import copy
import errno
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools" / "release_android_toolchain_archive_custody.sh"
PROVISIONER = ROOT / "tools" / "provision_macos_release_android_toolchains.sh"
LAUNCHER = ROOT / "tools" / "launch_macos_release_android_toolchains.py"
WINDOWS_HELPER = ROOT / "tools" / "android_toolchain_custody.ps1"
CONTRACT = ROOT / "tools" / "android-toolchain-custody.json"
PIN_MANIFEST = ROOT / "tools" / "toolchain-pins.json"
FLUTTER_ARCHIVE_NAME = "flutter_macos_arm64_3.47.6-stable.zip"
JAVA_ARCHIVE_NAME = "OpenJDK17U-jdk_aarch64_mac_hotspot_17.0.20.1_1.tar.gz"
JAVA_RELEASE_NAME = "jdk-17.0.20.1+1"
FLUTTER_VERSION = "3.47.6"
FLUTTER_REVISION = "5fc346839b5d0eef006ed8404392afb4dfae428d"
REAL_FLUTTER = Path("/Users/owner/Downloads") / FLUTTER_ARCHIVE_NAME
REAL_FLUTTER_SHA256 = "a1946d3b6b3de15ce247dc89649df9035ce29e6b4e7ebe91919a25890ea2e79a"
REAL_JAVA = Path("/Users/owner/Downloads") / JAVA_ARCHIVE_NAME
REAL_JAVA_SHA256 = "196d13ba5f10414bef7f6a05a9b3f00edacb18ebacef2b99485db9e2ee18f0e8"
PRIVATE_TMP = Path("/private/tmp")
RUNTIME_PREFIX = "wins-release-android-toolchains."


def _load_module():
    text = HELPER.read_text(encoding="ascii")
    begin = text.index("# WINS_ANDROID_TOOLCHAIN_PYTHON_BEGIN\n")
    begin += len("# WINS_ANDROID_TOOLCHAIN_PYTHON_BEGIN\n")
    end = text.index("\n# WINS_ANDROID_TOOLCHAIN_PYTHON_END")
    source = text[begin:end]
    directory = Path(tempfile.mkdtemp(prefix="wins-android-custody-mod.", dir=str(PRIVATE_TMP)))
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


def _load_bootstrap():
    text = PROVISIONER.read_text(encoding="ascii")
    begin = text.index("# WINS_ANDROID_ROOT_TRUST_BOOTSTRAP_BEGIN\n")
    begin += len("# WINS_ANDROID_ROOT_TRUST_BOOTSTRAP_BEGIN\n")
    end = text.index("\n# WINS_ANDROID_ROOT_TRUST_BOOTSTRAP_END")
    source = text[begin:end]
    directory = Path(
        tempfile.mkdtemp(prefix="wins-android-bootstrap-mod.", dir=str(PRIVATE_TMP))
    )
    directory.chmod(0o700)
    path = directory / "android_root_trust_bootstrap.py"
    path.write_text(source, encoding="ascii")
    spec = importlib.util.spec_from_file_location("android_root_trust_bootstrap", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Android root-trust bootstrap module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module._module_dir = directory
    return module


BOOTSTRAP = _load_bootstrap()


def _load_launcher():
    spec = importlib.util.spec_from_file_location(
        "wins_android_toolchain_launcher", LAUNCHER
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Android toolchain launcher")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LAUNCHER_MODULE = _load_launcher()


def embedded_provisioner_digest(kind: str) -> str:
    text = PROVISIONER.read_text(encoding="ascii")
    marker = f"readonly _WINS_PRAT_{kind}_SHA256='"
    start = text.index(marker) + len(marker)
    digest = text[start : start + 64]
    if len(digest) != 64:
        raise RuntimeError(f"embedded {kind} digest is malformed")
    return digest


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def loader_copy_sources() -> tuple[tuple[str, str], ...]:
    launcher = LAUNCHER_MODULE.ANDROID_TOOLCHAIN_LAUNCHER_LOADER_TEMPLATE
    helper = MODULE.ANDROID_TOOLCHAIN_LAUNCHER_LOADER_TEMPLATE
    provisioner = PROVISIONER.read_text(encoding="ascii")
    start = provisioner.index("cat <<'WINS_ANDROID_LAUNCHER_LOADER'\n") + len(
        "cat <<'WINS_ANDROID_LAUNCHER_LOADER'\n"
    )
    end = provisioner.index("WINS_ANDROID_LAUNCHER_LOADER\n", start)
    bash = provisioner[start:end]
    return (
        ("launcher", launcher),
        ("provisioner", bash),
        ("helper", helper),
    )


def verification(fields: dict[str, str]) -> list[str]:
    args = [
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
    ]
    if "PUB_CACHE" in fields:
        args.extend([fields["PUB_CACHE"], fields["PUB_CACHE_SHA256"]])
    return args


def thaw_tree(root: Path) -> None:
    for path in root.rglob("*"):
        if not path.is_symlink():
            try:
                path.chmod(path.stat().st_mode | stat.S_IWUSR | stat.S_IXUSR)
            except FileNotFoundError:
                pass
    if root.exists() and not root.is_symlink():
        root.chmod(root.stat().st_mode | stat.S_IWUSR | stat.S_IXUSR)


def freeze_fixture_tree(root: Path, executable_paths: set[str]) -> None:
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
class ReleaseAndroidToolchainArchiveCustodyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.base = Path(
            tempfile.mkdtemp(prefix="wins-android-toolchain-custody-", dir=str(PRIVATE_TMP))
        )
        cls.base.chmod(0o700)
        cls.sources = cls.base / "sources"
        cls.inputs = cls.base / "inputs"
        cls.sources.mkdir(mode=0o700)
        cls.inputs.mkdir(mode=0o700)
        cls.flutter_parent, cls.flutter_root = cls._make_flutter_tree()
        cls.java_parent, cls.java_home = cls._make_java_tree()
        cls.flutter_archive = cls.inputs / FLUTTER_ARCHIVE_NAME
        cls.java_archive = cls.inputs / JAVA_ARCHIVE_NAME
        zip_tree(cls.flutter_parent, cls.flutter_archive)
        tar_tree(cls.java_parent, cls.java_archive)
        cls.flutter_archive.chmod(0o444)
        cls.java_archive.chmod(0o444)
        cls.flutter_archive_sha = sha256(cls.flutter_archive)
        cls.java_archive_sha = sha256(cls.java_archive)
        extracted = cls.base / "hash-reference"
        extracted.mkdir(mode=0o700)
        MODULE.extract_zip(cls.flutter_archive, extracted / "flutter-archive", "flutter")
        MODULE.extract_tar(cls.java_archive, extracted / "java-archive", JAVA_RELEASE_NAME)
        flutter_root = extracted / "flutter-archive" / "flutter"
        java_home = extracted / "java-archive" / JAVA_RELEASE_NAME / "Contents" / "Home"
        MODULE.normalize_modes(flutter_root, flutter_tree=True)
        MODULE.normalize_modes(java_home)
        cls.flutter_tree_sha = MODULE.tree_hash(
            flutter_root, require_frozen=True, flutter_tree=True
        )
        cls.java_tree_sha = MODULE.tree_hash(java_home, require_frozen=True)
        thaw_tree(extracted)
        shutil.rmtree(extracted)

    @classmethod
    def tearDownClass(cls) -> None:
        thaw_tree(cls.base)
        shutil.rmtree(cls.base, ignore_errors=True)
        module_dir = getattr(MODULE, "_module_dir", None)
        if module_dir is not None:
            shutil.rmtree(module_dir, ignore_errors=True)
        bootstrap_dir = getattr(BOOTSTRAP, "_module_dir", None)
        if bootstrap_dir is not None:
            shutil.rmtree(bootstrap_dir, ignore_errors=True)

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
        flutter.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        cls._compile(
            "#include <stdio.h>\nint main(void) { return 0; }\n",
            dart,
        )
        cache = root / "bin" / "cache"
        (cache / "flutter_tools.snapshot").write_bytes(b"fixture snapshot\n")
        (cache / "lockfile").write_bytes(b"")
        framework = (
            root
            / "bin"
            / "cache"
            / "artifacts"
            / "engine"
            / "darwin-x64-profile"
            / "FlutterMacOS.xcframework"
            / "macos-arm64_x86_64"
            / "FlutterMacOS.framework"
        )
        resources = framework / "Versions" / "A" / "Resources"
        resources.mkdir(parents=True)
        (resources / "Info.plist").write_text("fixture framework resource\n", encoding="ascii")
        (framework / "Versions" / "Current").symlink_to("A")
        (framework / "Resources").symlink_to("Versions/Current/Resources")
        (root / "LICENSE").write_text("fixture license\n", encoding="ascii")
        freeze_fixture_tree(
            root,
            {"bin/flutter", "bin/cache/dart-sdk/bin/dart"},
        )
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

    def setUp(self) -> None:
        self.case = Path(tempfile.mkdtemp(prefix="case-", dir=self.base))
        self.case.chmod(0o700)
        self.flutter = self.case / FLUTTER_ARCHIVE_NAME
        self.java = self.case / JAVA_ARCHIVE_NAME
        shutil.copy2(self.flutter_archive, self.flutter)
        shutil.copy2(self.java_archive, self.java)
        self.flutter.chmod(0o444)
        self.java.chmod(0o444)
        self.manifest = self.case / "toolchain-pins.json"
        self._write_manifest()

    def tearDown(self) -> None:
        thaw_tree(self.case)
        shutil.rmtree(self.case, ignore_errors=True)

    def _pins_document(self) -> dict:
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
            },
        }

    def _write_manifest(self, document: dict | None = None) -> None:
        self.manifest.write_text(
            json.dumps(document or self._pins_document()), encoding="ascii"
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

    def _install(self) -> dict[str, str]:
        self._write_manifest()
        fields = MODULE.install_extracted_runtime(
            self._flutter_pin(),
            self._java_pin(),
            None,
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

    def _shell(self, body: str, *, with_python: bool = True) -> subprocess.CompletedProcess[str]:
        stub = ""
        if with_python:
            stub = (
                "wins_release_python_run() { "
                + shlex.quote(sys.executable)
                + ' "$@"; }\n'
            )
        script = f"source {shlex.quote(str(HELPER))}\n{stub}{body}\n"
        return subprocess.run(
            ["/bin/bash", "-c", script],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            check=False,
        )

    def test_00_cleanup_refuses_paths_outside_the_exact_prefix(self) -> None:
        outside = PRIVATE_TMP / "wins-android-cleanup-outside"
        outside.mkdir(mode=0o700)
        self.addCleanup(lambda: shutil.rmtree(outside, ignore_errors=True))
        (outside / "keep").write_text("keep\n", encoding="ascii")
        with self.assertRaisesRegex(MODULE.Refused, "refusing cleanup outside the private runtime prefix"):
            MODULE.cleanup_runtime([str(outside), "0:0:0:0"])
        self.assertTrue((outside / "keep").exists())

        aliased = PRIVATE_TMP / "wins-release-android-toolchains.symlink-cleanup"
        if aliased.exists() or aliased.is_symlink():
            aliased.unlink()
        aliased.symlink_to(outside)
        self.addCleanup(lambda: aliased.unlink() if aliased.is_symlink() else None)
        with self.assertRaisesRegex(MODULE.Refused, "refusing cleanup"):
            MODULE.cleanup_runtime([str(aliased), "0:0:0:0"])
        self.assertTrue((outside / "keep").exists())

        nodot = PRIVATE_TMP / "wins-release-android-toolchains-nodot"
        nodot.mkdir(mode=0o700)
        self.addCleanup(lambda: shutil.rmtree(nodot, ignore_errors=True))
        with self.assertRaisesRegex(MODULE.Refused, "refusing cleanup outside the private runtime prefix"):
            MODULE.cleanup_runtime([str(nodot), "0:0:0:0"])

        tmp_alias = Path("/tmp") / f"{RUNTIME_PREFIX}not-private"
        if tmp_alias.exists() or tmp_alias.is_symlink():
            if tmp_alias.is_symlink() or tmp_alias.is_file():
                tmp_alias.unlink()
            else:
                shutil.rmtree(tmp_alias, ignore_errors=True)
        tmp_alias.symlink_to(outside)
        self.addCleanup(
            lambda: tmp_alias.unlink() if tmp_alias.exists() or tmp_alias.is_symlink() else None
        )
        resolved = tmp_alias.resolve()
        if resolved.parent == PRIVATE_TMP and resolved.name.startswith(RUNTIME_PREFIX):
            self.fail("test setup used the private runtime prefix")
        with self.assertRaisesRegex(MODULE.Refused, "refusing cleanup outside the private runtime prefix"):
            MODULE.cleanup_runtime([str(tmp_alias), "0:0:0:0"])

        with self.assertRaisesRegex(
            MODULE.Refused,
            r"refusing cleanup of an owner-provisioned or foreign sealed toolchain|"
            r"refusing cleanup outside the private runtime prefix",
        ):
            MODULE.cleanup_runtime(
                [str(MODULE.OWNER_FLUTTER), "0:0:0:0"]
            )
        with self.assertRaisesRegex(
            MODULE.Refused, "refusing cleanup of an owner-provisioned or foreign sealed toolchain"
        ):
            MODULE._destroy_clone_tree(MODULE.OWNER_FLUTTER)
        with self.assertRaisesRegex(
            MODULE.Refused, "refusing cleanup of an owner-provisioned or foreign sealed toolchain"
        ):
            MODULE._destroy_clone_tree(Path("/Library/WinsVPN/ReleasePython/3.14.7"))
        with self.assertRaisesRegex(
            MODULE.Refused, "refusing cleanup of an owner-provisioned or foreign sealed toolchain"
        ):
            MODULE.cleanup_runtime([str(MODULE.OWNER_BOOTSTRAP), "0:0:0:0"])
        with self.assertRaisesRegex(
            MODULE.Refused, "refusing cleanup of an owner-provisioned or foreign sealed toolchain"
        ):
            MODULE._destroy_clone_tree(MODULE.OWNER_BOOTSTRAP)

    def test_00_cleanup_of_exact_prefix_succeeds_and_reports_residue(self) -> None:
        fields = self._install()
        runtime = Path(fields["RUNTIME"])
        self.assertEqual(runtime.parent, PRIVATE_TMP)
        self.assertTrue(runtime.name.startswith(RUNTIME_PREFIX))
        MODULE.verify_runtime(verification(fields))
        MODULE.cleanup_runtime([fields["RUNTIME"], fields["RUNTIME_ID"]])
        self.assertFalse(runtime.exists())
        fields.pop("RUNTIME", None)

        fields = self._install()
        runtime = Path(fields["RUNTIME"])
        with mock.patch("os.unlink", side_effect=lambda name, dir_fd=None: None):
            with self.assertRaisesRegex(MODULE.Refused, "cleanup residue:"):
                MODULE._destroy_runtime(runtime)
        self.assertTrue(runtime.exists())

    def test_00_cleanup_refuses_hardlinked_runtime_files(self) -> None:
        fields = self._install()
        runtime = Path(fields["RUNTIME"])
        victim = self.case / "external-victim"
        internal = Path(fields["JAVA_HOME"]) / "release"
        original_mode = stat.S_IMODE(internal.lstat().st_mode)
        original_bytes = internal.read_bytes()
        os.chmod(internal, original_mode | stat.S_IWUSR)
        os.link(internal, victim)
        os.chmod(internal, original_mode)
        try:
            with self.assertRaisesRegex(MODULE.Refused, r"hardlink|external"):
                MODULE.cleanup_runtime([fields["RUNTIME"], fields["RUNTIME_ID"]])
            self.assertTrue(runtime.exists())
            self.assertEqual(victim.read_bytes(), original_bytes)
        finally:
            if victim.exists():
                victim.unlink()

    def test_malicious_self_authored_archive_and_pins_cannot_authorize(self) -> None:
        completed = self._shell(
            f"wins_release_android_toolchains_prepare {shlex.quote(str(self.manifest))}"
        )
        self.assertNotEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("cannot self-authorize", completed.stderr)
        self.assertNotIn("RUNTIME|", completed.stdout)

        with self.assertRaisesRegex(MODULE.Refused, "cannot self-authorize"):
            MODULE.authorize_custody_inputs(HELPER, self.manifest)

        with self.assertRaisesRegex(MODULE.Refused, "cannot self-authorize"):
            MODULE.prepare(str(self.manifest), str(HELPER))

    def test_helper_and_manifest_substitution_are_rejected(self) -> None:
        nested = self.case / "tools"
        nested.mkdir(mode=0o700)
        replacement = nested / "release_android_toolchain_archive_custody.sh"
        shutil.copy2(HELPER, replacement)
        replacement.chmod(0o600)
        script = textwrap.dedent(
            f"""
            source {shlex.quote(str(replacement))}
            wins_release_python_run() {{ {shlex.quote(sys.executable)} "$@"; }}
            wins_release_android_toolchains_prepare {shlex.quote(str(PIN_MANIFEST))}
            """
        )
        completed = subprocess.run(
            ["/bin/bash", "-c", script],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0, completed.stderr)
        self.assertRegex(
            completed.stderr,
            r"malicious or substituted Android toolchain helper rejected|"
            r"Android toolchain contract is absent|"
            r"cannot self-authorize",
        )
        self.assertNotIn("RUNTIME|", completed.stdout)

        with self.assertRaisesRegex(
            MODULE.Refused,
            r"substituted Android toolchain helper|"
            r"Android toolchain contract is absent",
        ):
            MODULE.bind_live_helper(str(replacement))

        with self.assertRaisesRegex(MODULE.Refused, "cannot self-authorize"):
            MODULE.authorize_custody_inputs(HELPER, self.manifest)

    def test_unauthenticated_system_python_is_refused(self) -> None:
        completed = self._shell(
            f"wins_release_android_toolchains_prepare {shlex.quote(str(PIN_MANIFEST))}",
            with_python=False,
        )
        self.assertNotEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("authenticated release Python custody is required", completed.stderr)
        helper_text = HELPER.read_text(encoding="ascii")
        self.assertNotIn("/usr/bin/python3", helper_text)
        self.assertNotIn("/usr/bin/uname", helper_text)
        self.assertNotIn("/usr/bin/lipo", helper_text)
        self.assertNotIn('"/usr/bin/env"', helper_text)
        self.assertNotIn("$_WINS_RAT_ENV", helper_text)
        self.assertIn("wins_release_python_run", helper_text)
        self.assertIn("fclonefileat", helper_text)
        self.assertIn("SF_IMMUTABLE", helper_text)
        self.assertIn("UF_IMMUTABLE is insufficient", helper_text)
        self.assertIn("posix_spawn", helper_text)
        self.assertIn("provision_macos_release_android_toolchains.sh", helper_text)
        self.assertIn("/Library/WinsVPN/ReleaseAndroidToolchains", helper_text)
        self.assertNotRegex(helper_text, r"(?m)^\s*sudo\b")
        self.assertNotIn("sudo -S", helper_text)

    def test_stale_extra_bool_and_wrong_type_contract_fields_fail(self) -> None:
        original = json.loads(CONTRACT.read_text(encoding="ascii"))
        MODULE.parse_contract_bytes(CONTRACT.read_bytes())

        stale = copy.deepcopy(original)
        stale["created_utc"] = "2000-01-01T00:00:00Z"
        with self.assertRaisesRegex(MODULE.Refused, "created_utc is stale"):
            MODULE.parse_contract_bytes(json.dumps(stale).encode("ascii"))

        extra = copy.deepcopy(original)
        extra["attacker"] = "field"
        with self.assertRaisesRegex(MODULE.Refused, "unexpected extra field rejected"):
            MODULE.parse_contract_bytes(json.dumps(extra).encode("ascii"))

        extra_flutter = copy.deepcopy(original)
        extra_flutter["platforms"]["darwin_arm64"]["flutter"]["attacker"] = "x"
        with self.assertRaisesRegex(MODULE.Refused, "unexpected extra field rejected"):
            MODULE.parse_contract_bytes(json.dumps(extra_flutter).encode("ascii"))

        bool_schema = copy.deepcopy(original)
        bool_schema["schema_version"] = True
        with self.assertRaisesRegex(MODULE.Refused, "must be an integer, not bool-as-int"):
            MODULE.parse_contract_bytes(json.dumps(bool_schema).encode("ascii"))

        bool_count = copy.deepcopy(original)
        bool_count["platforms"]["darwin_arm64"]["flutter_pub_cache"]["package_count"] = True
        with self.assertRaisesRegex(MODULE.Refused, "must be an integer, not bool-as-int"):
            MODULE.parse_contract_bytes(json.dumps(bool_count).encode("ascii"))

        wrong_type = copy.deepcopy(original)
        wrong_type["platforms"]["darwin_arm64"]["flutter_pub_cache"]["package_count"] = "78"
        with self.assertRaisesRegex(MODULE.Refused, "has the wrong type"):
            MODULE.parse_contract_bytes(json.dumps(wrong_type).encode("ascii"))

        wrong_version = copy.deepcopy(original)
        wrong_version["platforms"]["darwin_arm64"]["flutter"]["version"] = "3.44.6"
        with self.assertRaisesRegex(MODULE.Refused, "flutter version must be exactly 3.47.6"):
            MODULE.parse_contract_bytes(json.dumps(wrong_version).encode("ascii"))

        bool_manifest = self.case / "bool-manifest.json"
        document = self._pins_document()
        document["schema_version"] = True
        bool_manifest.write_text(json.dumps(document), encoding="ascii")
        bool_manifest.chmod(0o600)
        with self.assertRaisesRegex(MODULE.Refused, "must be an integer, not bool-as-int"):
            MODULE.read_manifest(str(bool_manifest))

    def test_jdk_home_swap_and_restore_cannot_pass(self) -> None:
        fields = self._install()
        MODULE.verify_runtime(verification(fields))
        java_home = Path(fields["JAVA_HOME"])
        original_id = fields["JAVA_ID"]
        parked = java_home.parent / "Home.original"
        os.rename(java_home, parked)
        shutil.copytree(parked, java_home, symlinks=True)
        try:
            with self.assertRaisesRegex(
                MODULE.Refused, "Java Home identity changed after custody preparation"
            ):
                MODULE.verify_runtime(verification(fields))
        finally:
            thaw_tree(java_home)
            shutil.rmtree(java_home)
            os.rename(parked, java_home)
        self.assertEqual(MODULE.encode_root_identity(java_home), original_id)
        MODULE.verify_runtime(verification(fields))

    def test_framework_and_runtime_swap_are_detected(self) -> None:
        fields = self._install()
        flutter_root = Path(fields["FLUTTER_ROOT"])
        framework = (
            flutter_root
            / "bin"
            / "cache"
            / "artifacts"
            / "engine"
            / "darwin-x64-profile"
            / "FlutterMacOS.xcframework"
            / "macos-arm64_x86_64"
            / "FlutterMacOS.framework"
            / "Versions"
            / "A"
            / "Resources"
            / "Info.plist"
        )
        mode = stat.S_IMODE(framework.lstat().st_mode)
        os.chmod(framework, mode | stat.S_IWUSR)
        framework.write_text("swapped framework\n", encoding="ascii")
        os.chmod(framework, mode)
        with self.assertRaisesRegex(MODULE.Refused, "private Flutter tree changed"):
            MODULE.verify_runtime(verification(fields))
        os.chmod(framework, mode | stat.S_IWUSR)
        framework.write_text("fixture framework resource\n", encoding="ascii")
        os.chmod(framework, mode)
        MODULE.verify_runtime(verification(fields))

        dart = flutter_root / "bin" / "cache" / "dart-sdk" / "bin" / "dart"
        dart_mode = stat.S_IMODE(dart.lstat().st_mode)
        replacement = self.case / "evil-dart"
        self._compile("#include <stdio.h>\nint main(void) { return 1; }\n", replacement)
        original_bytes = dart.read_bytes()
        os.chmod(dart, dart_mode | stat.S_IWUSR)
        dart.write_bytes(replacement.read_bytes())
        os.chmod(dart, dart_mode)
        with self.assertRaisesRegex(MODULE.Refused, "private Flutter tree changed"):
            MODULE.verify_runtime(verification(fields))
        os.chmod(dart, dart_mode | stat.S_IWUSR)
        dart.write_bytes(original_bytes)
        os.chmod(dart, dart_mode)

    def test_install_verify_run_fail_closed_and_cleanup(self) -> None:
        fields = self._install()
        MODULE.verify_runtime(verification(fields))
        missing = self.case / "absent-owner-prefix"
        with mock.patch.object(MODULE, "OWNER_PREFIX", missing), mock.patch.object(
            MODULE, "OWNER_FLUTTER", missing / "flutter-3.47.6"
        ), mock.patch.object(MODULE, "OWNER_JAVA", missing / "jdk-17.0.20.1"):
            with self.assertRaises(MODULE.Refused) as raised:
                MODULE.run_from_verified(
                    [*verification(fields), "--", "--version"],
                    kind="java",
                )
        self.assertIn(MODULE.EXECUTION_BLOCKER, str(raised.exception))
        self.assertIn("/usr/bin/sudo -H --", str(raised.exception))
        self.assertIn("/Library/WinsVPN/ReleasePython/3.14.7/launcher/python3.14", str(raised.exception))
        self.assertIn("-I -S -c", str(raised.exception))
        self.assertIn("launch_macos_release_android_toolchains.py", str(raised.exception))
        self.assertNotIn("sudo /Library/WinsVPN/ReleasePython/3.14.7/launcher/python3.14 -I ", str(raised.exception))
        helper_text = HELPER.read_text(encoding="ascii")
        self.assertIn("owner/environment blocker: this host cannot make the Android toolchain", helper_text)
        self.assertIn("immutable against same-user path replacement through execution", helper_text)
        self.assertEqual(
            MODULE.EXECUTION_BLOCKER,
            "owner/environment blocker: this host cannot make the Android toolchain "
            "tree immutable against same-user path replacement through execution",
        )
        MODULE.cleanup_runtime([fields["RUNTIME"], fields["RUNTIME_ID"]])
        self.assertFalse(Path(fields["RUNTIME"]).exists())
        fields.pop("RUNTIME", None)

    def test_live_darwin_uf_immutable_is_owner_clearable_and_sf_is_eperm(self) -> None:
        probe = self.case / "flag-probe"
        probe.write_bytes(b"x")
        uf_clearable, sf_errno = MODULE.live_darwin_uf_vs_sf_probe(probe)
        self.assertTrue(uf_clearable)
        self.assertEqual(sf_errno, errno.EPERM)
        probe.write_bytes(b"y")
        self.assertFalse(MODULE._same_user_cannot_replace(probe))
        helper_text = HELPER.read_text(encoding="ascii")
        self.assertIn("UF_IMMUTABLE is insufficient", helper_text)
        self.assertIn("SF_IMMUTABLE is required", helper_text)
        self.assertIn("unprivileged", helper_text)
        os.chflags(probe, stat.UF_IMMUTABLE)
        self.assertFalse(MODULE._same_user_cannot_replace(probe))
        os.chflags(probe, 0)

    def test_hostile_same_user_replacement_is_detected_and_user_owned_is_not_sealed(
        self,
    ) -> None:
        fields = self._install()
        MODULE.verify_runtime(verification(fields))
        flutter = Path(fields["FLUTTER_ROOT"])
        parked = flutter.parent / "flutter.original"
        os.rename(flutter, parked)
        shutil.copytree(parked, flutter, symlinks=True)
        try:
            with self.assertRaisesRegex(
                MODULE.Refused, "Flutter root identity changed after custody preparation"
            ):
                MODULE.run_from_verified(
                    [*verification(fields), "--", "--version"],
                    kind="java",
                )
        finally:
            thaw_tree(flutter)
            shutil.rmtree(flutter)
            os.rename(parked, flutter)
        MODULE.verify_runtime(verification(fields))
        with self.assertRaisesRegex(
            MODULE.Refused,
            r"owner-sealed path is not root-owned|group/world-writable|"
            r"UF_IMMUTABLE is insufficient|" + MODULE.EXECUTION_BLOCKER,
        ):
            MODULE._kernel_seal_tree(Path(fields["JAVA_HOME"]))
        self.assertNotEqual(Path(fields["JAVA_HOME"]).lstat().st_uid, 0)

    def test_run_from_verified_executes_java_after_owner_sealed_bind(self) -> None:
        fields = self._install()
        MODULE.verify_runtime(verification(fields))
        flutter = Path(fields["FLUTTER_ROOT"])
        java = Path(fields["JAVA_HOME"])

        def fake_bind(
            flutter_root: Path,
            java_home: Path,
            flutter_expected: tuple[int, ...],
            java_expected: tuple[int, ...],
            flutter_sha: str,
            java_sha: str,
        ) -> tuple[Path, Path]:
            self.assertEqual(flutter_root, flutter)
            self.assertEqual(java_home, java)
            self.assertEqual(flutter_sha, fields["FLUTTER_SHA256"])
            self.assertEqual(java_sha, fields["JAVA_SHA256"])
            return flutter, java

        with mock.patch.object(MODULE, "sealed_execution_trees", fake_bind):
            rc = MODULE.run_from_verified(
                [*verification(fields), "--", "-version"],
                kind="java",
            )
        self.assertEqual(rc, 0)

    def test_provisioner_without_root_does_not_mutate_and_prints_owner_command(self) -> None:
        prefix_existed = MODULE.OWNER_PREFIX.exists()
        before = (
            list(Path("/Library/WinsVPN").glob("**/*"))
            if Path("/Library/WinsVPN").exists()
            else []
        )
        python_before = Path("/Library/WinsVPN/ReleasePython/3.14.7")
        python_existed = python_before.exists()
        completed = subprocess.run(
            ["/bin/bash", str(PROVISIONER), str(PIN_MANIFEST)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        after = (
            list(Path("/Library/WinsVPN").glob("**/*"))
            if Path("/Library/WinsVPN").exists()
            else []
        )
        self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn(MODULE.EXECUTION_BLOCKER, completed.stderr)
        self.assertIn("/usr/bin/sudo -H --", completed.stderr)
        self.assertIn("/Library/WinsVPN/ReleasePython/3.14.7/launcher/python3.14", completed.stderr)
        self.assertIn("-I -S -c", completed.stderr)
        self.assertIn("launch_macos_release_android_toolchains.py", completed.stderr)
        self.assertIn("O_NONBLOCK", completed.stderr)
        self.assertNotIn("sudo /Library/WinsVPN/ReleasePython/3.14.7/launcher/python3.14 -I ", completed.stderr)
        self.assertNotIn(" tools/launch_macos_release_android_toolchains.py", completed.stderr)
        self.assertEqual(before, after)
        self.assertEqual(python_before.exists(), python_existed)
        self.assertEqual(MODULE.OWNER_PREFIX.exists(), prefix_existed)
        provisioner = PROVISIONER.read_text(encoding="ascii")
        self.assertIn("never invokes sudo", provisioner)
        self.assertIn("never reads a password", provisioner)
        self.assertIn("visible sudo password prompt", provisioner)
        self.assertIn("SUDO_UID", provisioner)
        self.assertNotRegex(provisioner, r"(?m)^\s*sudo\b")
        self.assertNotRegex(provisioner, r"sudo\s+-S\b")
        with self.assertRaisesRegex(MODULE.Refused, MODULE.EXECUTION_BLOCKER):
            MODULE.provision_owner_toolchains(str(PIN_MANIFEST), HELPER)
        self.assertEqual(MODULE.OWNER_PREFIX.exists(), prefix_existed)

    def test_extracted_helper_python_without_main_guard_does_not_provision(self) -> None:
        source = MODULE.extract_helper_python(HELPER.read_text(encoding="ascii"))
        self.assertIn('if __name__ == "__main__":', source)
        self.assertIn("raise SystemExit(main())", source)
        guard = '\nif __name__ == "__main__":\n'
        index = source.rfind(guard)
        self.assertGreaterEqual(index, 0)
        stripped = source[:index]
        namespace: dict = {"__name__": "__main__"}
        exec(compile(stripped, "repro-no-main", "exec"), namespace)
        called: list[str] = []
        namespace["provision_owner_toolchains"] = (
            lambda *args, **kwargs: called.append("provision")
        )
        self.assertEqual(called, [])
        self.assertIn("main", namespace)
        self.assertIn("provision_owner_toolchains", namespace)

        captured = io.StringIO()
        with mock.patch.object(
            sys,
            "argv",
            [
                "release_android_toolchain_archive_custody",
                "--helper",
                str(HELPER),
                "provision",
                str(PIN_MANIFEST),
            ],
        ):
            with mock.patch("sys.stderr", captured):
                with self.assertRaises(SystemExit) as raised:
                    exec(compile(source, "sealed-helper", "exec"), {"__name__": "__main__"})
        self.assertEqual(raised.exception.code, 1)
        self.assertIn(MODULE.EXECUTION_BLOCKER, captured.getvalue())
        try:
            MODULE.invoke_provision_main(source, HELPER, PIN_MANIFEST)
        except Exception as suc:
            self.assertIn(MODULE.EXECUTION_BLOCKER, str(suc))
        else:
            self.fail("invoke_provision_main must fail closed without root")
        with self.assertRaisesRegex(MODULE.Refused, "no exact provisioned result"):
            MODULE.require_exact_provisioned_result("")
        MODULE.require_exact_provisioned_result(
            f"provisioned {MODULE.OWNER_FLUTTER} and {MODULE.OWNER_JAVA}\n"
        )
        MODULE.require_exact_provisioned_result(
            f"already provisioned at {MODULE.OWNER_FLUTTER} and {MODULE.OWNER_JAVA}\n"
        )

    def test_held_fd_copy_survives_helper_swap_between_hash_and_exec(self) -> None:
        original = HELPER.read_bytes()
        probe = self.case / "helper-swap"
        probe.write_bytes(original)
        probe.chmod(0o600)
        fd, data, digest = MODULE.hold_regular_file(
            probe, max_size=MODULE.MAX_HELPER_BYTES, label="swap probe"
        )
        try:
            self.assertEqual(data, original)
            self.assertEqual(digest, sha256(HELPER))
            probe.write_bytes(b"EVIL-HELPER-SWAP\n" * 50)
            dest = self.case / "copied-helper"
            MODULE.copy_held_fd(fd, data, dest, digest, mode=0o444, label="swap probe")
            self.assertEqual(dest.read_bytes(), original)
            self.assertNotEqual(probe.read_bytes(), original)
        finally:
            os.close(fd)
        provisioner = PROVISIONER.read_text(encoding="ascii")
        self.assertNotIn("helper.read_text", provisioner)
        self.assertIn("os.lseek", provisioner)
        self.assertIn("O_NOFOLLOW", provisioner)
        self.assertIn("O_NONBLOCK", provisioner)
        self.assertIn("_clear_nonblock_if_needed", provisioner)
        self.assertIn("invoke_sealed_provision", provisioner)
        helper_text = HELPER.read_text(encoding="ascii")
        self.assertIn("O_NONBLOCK", helper_text)
        self.assertIn("_clear_nonblock_if_needed", helper_text)
        self.assertIn("_nonblock_flag", helper_text)
        launcher_text = LAUNCHER.read_text(encoding="ascii")
        self.assertIn("O_NONBLOCK", launcher_text)
        self.assertIn("_clear_nonblock_if_needed", launcher_text)
        self.assertRegex(
            helper_text,
            r"destination_flags\s*=\s*\([\s\S]{0,400}O_NOFOLLOW",
        )

    def test_later_hold_regular_file_copies_fail_closed_on_fifo_toctou(self) -> None:
        original = b"held-regular-original\n" + (b"A" * 32)
        expected = hashlib.sha256(original).hexdigest()
        fail_closed = (
            r"replaced before it was opened|not a readable regular file|"
            r"must be one regular non-symlink single-link file"
        )
        copies = (
            ("launcher", LAUNCHER_MODULE, LAUNCHER, 2 * 1024 * 1024),
            (
                "provisioner",
                BOOTSTRAP,
                BOOTSTRAP._module_dir / "android_root_trust_bootstrap.py",
                2 * 1024 * 1024,
            ),
            (
                "helper",
                MODULE,
                MODULE._module_dir / "android_toolchain_custody.py",
                MODULE.MAX_HELPER_BYTES,
            ),
        )
        self.assertEqual(len(copies), 3)
        for name, module, mod_path, max_size in copies:
            hold_source = Path(mod_path).read_text(encoding="ascii")
            self.assertIn("O_NONBLOCK", hold_source)
            self.assertIn("_clear_nonblock_if_needed", hold_source)
            work = self.case / f"hold-fifo-{name}"
            work.mkdir(mode=0o700)
            probe_file = work / "held.txt"
            with self.subTest(copy=name, case="regular_held_bytes"):
                probe_file.write_bytes(original)
                probe_file.chmod(0o600)
                clears: list[bool] = []
                real_fcntl = fcntl.fcntl

                def spy_fcntl(fd: int, cmd: int, *args: object):
                    if cmd == fcntl.F_SETFL:
                        clears.append(stat.S_ISREG(os.fstat(fd).st_mode))
                    return real_fcntl(fd, cmd, *args)

                with mock.patch.object(module.fcntl, "fcntl", spy_fcntl):
                    held = module.hold_regular_file(
                        probe_file, max_size=max_size, label="fifo probe"
                    )
                if name == "launcher":
                    data, digest = held
                else:
                    fd, data, digest = held
                    os.close(fd)
                self.assertEqual(data, original)
                self.assertEqual(digest, expected)
                self.assertEqual(clears, [True])

            with self.subTest(copy=name, case="fifo_toctou"):
                if probe_file.exists() or probe_file.is_fifo() or probe_file.is_symlink():
                    probe_file.unlink()
                probe_file.write_bytes(original)
                probe_file.chmod(0o600)
                raced = self._run_hold_fifo_toctou(
                    mod_path, probe_file, max_size, work
                )
                combined = (raced.stdout or "") + (raced.stderr or "")
                self.assertNotEqual(raced.returncode, 0, combined)
                self.assertRegex(combined, fail_closed)
                self.assertIn("SETFL_REGULAR=[]", raced.stderr)
                self.assertNotIn("O_NONBLOCK missing from open flags", combined)
                self.assertNotIn("hold_regular_file returned after FIFO replace", combined)

    def _run_hold_fifo_toctou(
        self,
        mod_path: Path,
        target: Path,
        max_size: int,
        work: Path,
    ) -> subprocess.CompletedProcess[str]:
        probe = work / "hold-fifo-toctou-probe.py"
        probe.write_text(
            "import fcntl, importlib.util, os, stat, sys\n"
            "from pathlib import Path\n"
            "path = Path(sys.argv[1])\n"
            "mod_path = sys.argv[2]\n"
            "max_size = int(sys.argv[3])\n"
            "clears = []\n"
            "real_fcntl = fcntl.fcntl\n"
            "def spy_fcntl(fd, cmd, *args):\n"
            "    if cmd == fcntl.F_SETFL:\n"
            "        clears.append(stat.S_ISREG(os.fstat(fd).st_mode))\n"
            "    return real_fcntl(fd, cmd, *args)\n"
            "fcntl.fcntl = spy_fcntl\n"
            "spec = importlib.util.spec_from_file_location('hold_fifo_mod', mod_path)\n"
            "mod = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(mod)\n"
            "real_open = os.open\n"
            "def raced_open(p, flags, *a, **k):\n"
            "    if os.fspath(p) == os.fspath(path):\n"
            "        if not (flags & os.O_NONBLOCK):\n"
            "            raise SystemExit('O_NONBLOCK missing from open flags')\n"
            "        os.unlink(path)\n"
            "        os.mkfifo(path)\n"
            "    return real_open(p, flags, *a, **k)\n"
            "os.open = raced_open\n"
            "try:\n"
            "    held = mod.hold_regular_file(path, max_size=max_size, label='fifo probe')\n"
            "except Exception as suc:\n"
            "    sys.stderr.write('SETFL_REGULAR=' + repr(clears) + '\\n')\n"
            "    sys.stderr.write(str(suc) + '\\n')\n"
            "    raise SystemExit(2) from suc\n"
            "if isinstance(held, tuple) and held and isinstance(held[0], int):\n"
            "    os.close(held[0])\n"
            "raise SystemExit('hold_regular_file returned after FIFO replace')\n",
            encoding="ascii",
        )
        return subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                str(probe),
                str(target),
                str(mod_path),
                str(max_size),
            ],
            cwd=str(work),
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )

    def test_same_user_bundle_race_is_bound_to_held_fds(self) -> None:
        repo = self.case / "bundle-repo"
        dest = self.case / "sealed-bundle"
        repo.mkdir(mode=0o700)
        names = {
            "provisioner": (PROVISIONER, "provision_macos_release_android_toolchains.sh"),
            "helper": (HELPER, "release_android_toolchain_archive_custody.sh"),
            "contract": (CONTRACT, "android-toolchain-custody.json"),
            "manifest": (PIN_MANIFEST, "toolchain-pins.json"),
        }
        copies = {}
        originals = {}
        for label, (src, name) in names.items():
            target = repo / name
            shutil.copy2(src, target)
            target.chmod(0o600)
            copies[label] = target
            originals[label] = src.read_bytes()

        original_hold = BOOTSTRAP.hold_regular_file

        def hold_then_swap(path: Path, **kwargs):
            result = original_hold(path, **kwargs)
            path.write_bytes(b"EVIL-BUNDLE-" + path.name.encode("ascii") + b"\n" * 32)
            return result

        with mock.patch.object(BOOTSTRAP, "hold_regular_file", hold_then_swap):
            BOOTSTRAP.bootstrap_and_provision(
                copies["provisioner"],
                copies["helper"],
                copies["contract"],
                copies["manifest"],
                sha256(HELPER),
                sha256(CONTRACT),
                sha256(PIN_MANIFEST),
                sha256(PROVISIONER),
                dest,
                apply_kernel_seal=False,
                require_root=False,
                execute_provision=False,
            )
        for label, name in (
            ("provisioner", "provision_macos_release_android_toolchains.sh"),
            ("helper", "release_android_toolchain_archive_custody.sh"),
            ("contract", "android-toolchain-custody.json"),
            ("manifest", "toolchain-pins.json"),
        ):
            published = dest / name
            self.assertEqual(published.read_bytes(), originals[label])
            self.assertNotEqual(copies[label].read_bytes(), originals[label])
        with self.assertRaisesRegex(BOOTSTRAP.Refused, "foreign bootstrap staging"):
            BOOTSTRAP._destroy_staging(
                Path("/private/tmp/evil-bootstrap"), BOOTSTRAP.OWNER_BOOTSTRAP
            )
        with self.assertRaisesRegex(BOOTSTRAP.Refused, "foreign bootstrap staging"):
            BOOTSTRAP._destroy_staging(
                PRIVATE_TMP / "wins-release-android-toolchains.foreign",
                dest,
            )

    def test_sealed_bootstrap_exact_hashes_match_authenticated_pins(self) -> None:
        self.assertEqual(embedded_provisioner_digest("HELPER"), sha256(HELPER))
        self.assertEqual(embedded_provisioner_digest("CONTRACT"), sha256(CONTRACT))
        self.assertEqual(embedded_provisioner_digest("MANIFEST"), sha256(PIN_MANIFEST))
        contract = MODULE.parse_contract_bytes(CONTRACT.read_bytes())
        self.assertEqual(contract["helper_sha256"], sha256(HELPER))
        self.assertEqual(contract["manifest_sha256"], sha256(PIN_MANIFEST))
        dest = self.case / "hash-bundle"
        BOOTSTRAP.bootstrap_and_provision(
            PROVISIONER,
            HELPER,
            CONTRACT,
            PIN_MANIFEST,
            sha256(HELPER),
            sha256(CONTRACT),
            sha256(PIN_MANIFEST),
            sha256(PROVISIONER),
            dest,
            apply_kernel_seal=False,
            require_root=False,
            execute_provision=False,
        )
        self.assertEqual(
            sha256(dest / "release_android_toolchain_archive_custody.sh"),
            sha256(HELPER),
        )
        self.assertEqual(
            sha256(dest / "android-toolchain-custody.json"),
            sha256(CONTRACT),
        )
        self.assertEqual(
            sha256(dest / "toolchain-pins.json"),
            sha256(PIN_MANIFEST),
        )
        self.assertEqual(
            sha256(dest / "provision_macos_release_android_toolchains.sh"),
            sha256(PROVISIONER),
        )
        self.assertEqual(
            stat.S_IMODE((dest / "release_android_toolchain_archive_custody.sh").stat().st_mode),
            0o555,
        )
        self.assertEqual(
            stat.S_IMODE((dest / "android-toolchain-custody.json").stat().st_mode),
            0o444,
        )
        provisioner = PROVISIONER.read_text(encoding="ascii")
        self.assertIn("SF_IMMUTABLE", provisioner)
        self.assertIn("os.chflags", provisioner)
        self.assertIn(str(MODULE.OWNER_BOOTSTRAP), provisioner)

    def test_root_trust_bootstrap_does_not_run_flutter_java_gradle_or_signing(self) -> None:
        text = PROVISIONER.read_text(encoding="ascii")
        begin = text.index("# WINS_ANDROID_ROOT_TRUST_BOOTSTRAP_BEGIN\n")
        end = text.index("\n# WINS_ANDROID_ROOT_TRUST_BOOTSTRAP_END")
        bootstrap = text[begin:end]
        for forbidden in (
            "posix_spawn",
            "subprocess",
            "jarsigner",
            "keytool",
            "apksigner",
            "/usr/bin/java",
            "gradle",
            "lib/apksigner.jar",
        ):
            self.assertNotIn(forbidden, bootstrap)
        self.assertNotRegex(bootstrap, r"(?m)^\s*sudo\b")
        self.assertIn("SUDO_ASKPASS is refused", bootstrap)
        self.assertIn("provision_owner_toolchains", bootstrap)
        self.assertIn("require_exact_provisioned_result", bootstrap)
        fake_helper = (
            MODULE.PYTHON_BEGIN
            + "def main():\n    return 0\n"
            + "def provision_owner_toolchains(a, b):\n    return None\n"
            + 'if __name__ == "__main__":\n    raise SystemExit(main())\n'
            + MODULE.PYTHON_END
        )
        with self.assertRaisesRegex(BOOTSTRAP.Refused, "no exact provisioned result"):
            BOOTSTRAP.invoke_sealed_provision(
                fake_helper.encode("ascii"), HELPER, PIN_MANIFEST
            )
        producer = (ROOT / "tools" / "build_android_release_macos.sh").read_text(
            encoding="utf-8"
        )
        self.assertNotIn('JAVA_HOME="${WINS_RELEASE_JAVA_HOME}"', producer)
        self.assertNotIn("wins_release_android_jdk_tool java -jar", producer)
        self.assertIn("run_android_apksigner", producer)
        self.assertIn("run_held_apksigner", producer)
        self.assertIn("anonymous_held_fd", producer)
        # The JVM cannot run a jar from /dev/fd here, so the held descriptor's
        # bytes are copied into a private digest-checked snapshot that java runs.
        self.assertNotIn("pass_fds", producer)
        self.assertIn("/dev/fd/", producer)
        self.assertIn("snapshot_jar", producer)
        self.assertIn("snapshot_digest", producer)
        self.assertIn("remove_snapshot", producer)
        self.assertNotIn("materialize_android_apksigner_jar", producer)
        self.assertNotIn("find_android_apksigner_jar", producer)
        self.assertIn("REVIEWED_APKSIGNER_JAR_SHA256", producer)
        self.assertIn("build-tools/37.0.0/lib/apksigner.jar", producer)
        self.assertNotIn("run_android_sdk_tool_clean", producer)
        self.assertIn("run_android_sdk_native_tool", producer)
        self.assertIn('JAVA_TOOLCHAIN_ROOT="${WINS_RELEASE_JAVA_HOME}"', producer)
        # The producer binds the pinned, digest-verified home JDK (owner
        # ruling 2026-10-09) instead of this helper's /Library owner tree.
        self.assertNotIn("WINS_RELEASE_ANDROID_OWNER_JAVA", producer)
        self.assertNotIn(
            'source "${ROOT}/tools/release_android_toolchain_archive_custody.sh"', producer
        )
        self.assertIn('[[ "${SEALED_JAVA}" == "${WINS_RELEASE_JAVA_HOME}/bin/java"', producer)
        self.assertIn('--java "${SEALED_JAVA}"', producer)

    def test_official_pins_and_contract_preserve_flutter_and_temurin(self) -> None:
        contract = MODULE.parse_contract_bytes(CONTRACT.read_bytes())
        darwin = contract["platforms"]["darwin_arm64"]
        self.assertEqual(darwin["status"], "pinned")
        self.assertEqual(darwin["flutter"]["version"], FLUTTER_VERSION)
        self.assertEqual(darwin["flutter"]["revision"], FLUTTER_REVISION)
        self.assertEqual(darwin["flutter"]["archive_name"], FLUTTER_ARCHIVE_NAME)
        self.assertEqual(darwin["java"]["version"], "17.0.20.1")
        self.assertEqual(darwin["java"]["release_name"], JAVA_RELEASE_NAME)
        self.assertEqual(darwin["java"]["vendor"], "Eclipse Adoptium")
        self.assertEqual(contract["platforms"]["windows_amd64"]["status"], "owner_inputs_required")
        bound = MODULE.authorize_custody_inputs(HELPER, PIN_MANIFEST)
        self.assertEqual(bound["pins"]["flutter"]["path"].name, FLUTTER_ARCHIVE_NAME)
        self.assertEqual(bound["pins"]["java"]["path"].name, JAVA_ARCHIVE_NAME)
        self.assertEqual(sha256(HELPER), contract["helper_sha256"])
        self.assertEqual(sha256(PIN_MANIFEST), contract["manifest_sha256"])
        self.assertEqual(contract["provisioner"], "tools/provision_macos_release_android_toolchains.sh")
        self.assertEqual(sha256(WINDOWS_HELPER), contract["windows_helper_sha256"])
        self.assertEqual(MODULE.OWNER_JAVA, Path("/Library/WinsVPN/ReleaseAndroidToolchains/jdk-17.0.20.1"))

    def test_pre_hold_provisioner_substitution_is_rejected(self) -> None:
        dest = self.case / "substituted-provisioner"
        mutated = bytearray(PROVISIONER.read_bytes())
        marker = b"never logs a password"
        index = bytes(mutated).find(marker)
        self.assertGreaterEqual(index, 0)
        mutated[index] = ord("N")
        hostile = self.case / "hostile-provisioner.sh"
        hostile.write_bytes(bytes(mutated))
        hostile.chmod(0o700)
        self.assertEqual(hostile.stat().st_size, PROVISIONER.stat().st_size)
        self.assertNotEqual(sha256(hostile), sha256(PROVISIONER))
        with self.assertRaisesRegex(
            BOOTSTRAP.Refused, "substituted Android toolchain provisioner"
        ):
            BOOTSTRAP.bootstrap_and_provision(
                hostile,
                HELPER,
                CONTRACT,
                PIN_MANIFEST,
                sha256(HELPER),
                sha256(CONTRACT),
                sha256(PIN_MANIFEST),
                sha256(PROVISIONER),
                dest,
                apply_kernel_seal=False,
                require_root=False,
                execute_provision=False,
            )
        self.assertFalse(dest.exists())
        self.assertFalse(dest.is_symlink())
        provisioner = PROVISIONER.read_text(encoding="ascii")
        self.assertNotIn("_WINS_PRAT_PROVISIONER_SHA256=\"$(_wins_prat_sha256", provisioner)
        self.assertNotIn("$_WINS_PRAT_PYTHON\" -I -S -", provisioner)
        self.assertIn("authenticate_bootstrap_payloads", provisioner)
        self.assertIn("expected_provisioner", provisioner)

    def test_all_four_sealed_digests_are_reverified(self) -> None:
        dest = self.case / "four-digest-bundle"
        expected = {
            "provisioner": sha256(PROVISIONER),
            "helper": sha256(HELPER),
            "contract": sha256(CONTRACT),
            "manifest": sha256(PIN_MANIFEST),
        }
        BOOTSTRAP.bootstrap_and_provision(
            PROVISIONER,
            HELPER,
            CONTRACT,
            PIN_MANIFEST,
            expected["helper"],
            expected["contract"],
            expected["manifest"],
            expected["provisioner"],
            dest,
            apply_kernel_seal=False,
            require_root=False,
            execute_provision=False,
        )
        names = {
            "provisioner": "provision_macos_release_android_toolchains.sh",
            "helper": "release_android_toolchain_archive_custody.sh",
            "contract": "android-toolchain-custody.json",
            "manifest": "toolchain-pins.json",
        }
        payloads = {label: (dest / name).read_bytes() for label, name in names.items()}
        BOOTSTRAP.authenticate_bootstrap_payloads(payloads, expected)
        MODULE.authenticate_bootstrap_payloads(payloads)
        for label in names:
            mutated = bytearray(payloads[label])
            mutated[-2] ^= 0x01
            hostile = dict(payloads)
            hostile[label] = bytes(mutated)
            with self.assertRaisesRegex(BOOTSTRAP.Refused, "substituted"):
                BOOTSTRAP.authenticate_bootstrap_payloads(hostile, expected)
        helper_text = HELPER.read_text(encoding="ascii")
        self.assertIn("authenticate_bootstrap_payloads", helper_text)
        self.assertIn("provisioner_embedded_pins", helper_text)

    def test_partial_sf_immutable_failure_rolls_back_bootstrap_dest(self) -> None:
        dest = self.case / "partial-seal"
        calls = {"n": 0}

        def flaky(path, flags, *args, **kwargs):
            del path, args, kwargs
            if flags:
                calls["n"] += 1
                if calls["n"] >= 2:
                    raise OSError(errno.EPERM, "partial SF_IMMUTABLE")
            return None

        with mock.patch.object(os, "chflags", flaky):
            with self.assertRaises(OSError):
                BOOTSTRAP.bootstrap_and_provision(
                    PROVISIONER,
                    HELPER,
                    CONTRACT,
                    PIN_MANIFEST,
                    sha256(HELPER),
                    sha256(CONTRACT),
                    sha256(PIN_MANIFEST),
                    sha256(PROVISIONER),
                    dest,
                    apply_kernel_seal=True,
                    require_root=False,
                    execute_provision=False,
                )
        self.assertFalse(dest.exists())
        self.assertFalse(dest.is_symlink())
        with self.assertRaisesRegex(BOOTSTRAP.Refused, "foreign bootstrap occupant"):
            BOOTSTRAP._rollback_published_dest(
                Path("/Library/WinsVPN"),
                (1, 1),
                {
                    "provisioner": ("provision_macos_release_android_toolchains.sh", 0o555),
                    "helper": ("release_android_toolchain_archive_custody.sh", 0o555),
                    "contract": ("android-toolchain-custody.json", 0o444),
                    "manifest": ("toolchain-pins.json", 0o444),
                },
                chown_root=False,
            )

    def test_partial_sf_immutable_failure_rolls_back_live_trees(self) -> None:
        flutter_src = self.case / "flutter-src"
        java_src = self.case / "java-src"
        flutter_src.mkdir()
        java_src.mkdir()
        (flutter_src / "keep").write_text("flutter\n", encoding="ascii")
        (java_src / "keep").write_text("java\n", encoding="ascii")
        owner_flutter = self.case / "owner-flutter"
        owner_java = self.case / "owner-java"
        calls = {"n": 0}

        def flaky(path, flags, *args, **kwargs):
            del path, args, kwargs
            if flags:
                calls["n"] += 1
                if calls["n"] >= 1:
                    raise OSError(errno.EPERM, "partial SF_IMMUTABLE")
            return None

        with (
            mock.patch.object(MODULE, "OWNER_FLUTTER", owner_flutter),
            mock.patch.object(MODULE, "OWNER_JAVA", owner_java),
            mock.patch.object(os, "chflags", flaky),
        ):
            with self.assertRaises(OSError):
                MODULE._commit_owner_live_trees(flutter_src, java_src)
        self.assertFalse(owner_flutter.exists())
        self.assertFalse(owner_java.exists())
        foreign = self.case / "foreign-tree"
        foreign.mkdir()
        (foreign / "keep").write_text("keep\n", encoding="ascii")
        with mock.patch.object(MODULE, "OWNER_FLUTTER", owner_flutter):
            with self.assertRaisesRegex(MODULE.Refused, "foreign toolchain occupant"):
                MODULE._rollback_published_owner_tree(foreign, (1, 1))
        self.assertTrue(foreign.exists())
        self.assertEqual((foreign / "keep").read_text(encoding="ascii"), "keep\n")

    def test_zz_real_flutter_archive_identity_without_extract(self) -> None:
        if not REAL_FLUTTER.is_file() or REAL_FLUTTER.is_symlink():
            self.skipTest("real Flutter 3.47.6 archive is unavailable")
        info = REAL_FLUTTER.lstat()
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(info.st_nlink, 1)
        self.assertGreater(info.st_size, 2 * 1024 * 1024 * 1024)
        self.assertEqual(sha256(REAL_FLUTTER), REAL_FLUTTER_SHA256)
        contract = MODULE.parse_contract_bytes(CONTRACT.read_bytes())
        self.assertEqual(
            contract["platforms"]["darwin_arm64"]["flutter"]["archive_sha256"],
            REAL_FLUTTER_SHA256,
        )
        if REAL_JAVA.is_file() and not REAL_JAVA.is_symlink():
            self.assertEqual(sha256(REAL_JAVA), REAL_JAVA_SHA256)
            self.assertEqual(
                contract["platforms"]["darwin_arm64"]["java"]["archive_sha256"],
                REAL_JAVA_SHA256,
            )

    def test_unknown_jdk_tool_is_rejected_without_path_fallback(self) -> None:
        completed = self._shell("wins_release_android_jdk_tool javac -version")
        self.assertNotEqual(completed.returncode, 0, completed.stdout)
        self.assertIn("unapproved JDK tool", completed.stderr)

    def test_helper_is_source_only_and_shell_syntax_is_valid(self) -> None:
        syntax = subprocess.run(
            ["/bin/bash", "-n", str(HELPER)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        provisioner_syntax = subprocess.run(
            ["/bin/bash", "-n", str(PROVISIONER)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(provisioner_syntax.returncode, 0, provisioner_syntax.stderr)
        direct = subprocess.run(
            ["/bin/bash", str(HELPER)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(direct.returncode, 64)
        self.assertIn("must be sourced", direct.stderr)


    def test_launcher_identity_is_externally_pinned_and_not_self_hashed(self) -> None:
        launcher = LAUNCHER.read_text(encoding="ascii")
        provisioner = PROVISIONER.read_text(encoding="ascii")
        helper = HELPER.read_text(encoding="ascii")
        contract = CONTRACT.read_text(encoding="ascii")
        obfuscation = (ROOT / "tools" / "release_obfuscation_contract.py").read_text(
            encoding="ascii"
        )
        self.assertTrue(LAUNCHER.is_file())
        self.assertFalse(LAUNCHER.is_symlink())
        self.assertEqual(LAUNCHER_MODULE.REVIEWED_PROVISIONER_SHA256, sha256(PROVISIONER))
        self.assertIn(sha256(LAUNCHER), obfuscation)
        self.assertIn("ANDROID_TOOLCHAIN_LAUNCHER_SHA256", obfuscation)
        self.assertNotIn(sha256(LAUNCHER), provisioner)
        self.assertNotIn(sha256(LAUNCHER), helper)
        self.assertNotIn(sha256(LAUNCHER), contract)
        self.assertNotIn(sha256(LAUNCHER), launcher)
        self.assertNotIn("launcher_sha256", contract)
        self.assertNotIn("Path(__file__).read_bytes", launcher)
        self.assertNotIn("open(__file__", launcher)
        self.assertNotIn("inspect.getsource", launcher)
        self.assertNotIn("python3 -I -S -", launcher)
        self.assertIn('sys.argv[0] in {"-", "-c"}', launcher)
        self.assertIn("require_loaded_cpython_314_identity", launcher)
        self.assertIn("/Library/WinsVPN/ReleasePython/3.14.7/launcher/python3.14", launcher)
        self.assertIn("/usr/bin/sudo -H --", launcher)
        self.assertIn("-I -S -c", launcher)
        self.assertIn("O_NOFOLLOW", launcher)
        self.assertIn("O_CLOEXEC", launcher)
        self.assertIn("O_NONBLOCK", launcher)
        self.assertIn("F_GETFL", launcher)
        self.assertIn("F_SETFL", launcher)
        self.assertIn("SUDO_UID", launcher)
        self.assertIn("SUDO_GID", launcher)
        self.assertNotIn("/usr/bin/python3", launcher)
        self.assertNotIn("sudo /bin/bash -p tools/provision_macos_release_android_toolchains.sh", launcher)
        self.assertNotIn("sudo /bin/bash -p tools/provision_macos_release_android_toolchains.sh", provisioner)
        self.assertNotIn("sudo /Library/WinsVPN/ReleasePython/3.14.7/launcher/python3.14 -I ", launcher)
        self.assertNotIn("sudo /Library/WinsVPN/ReleasePython/3.14.7/launcher/python3.14 -I ", provisioner)
        self.assertNotIn("sudo /Library/WinsVPN/ReleasePython/3.14.7/launcher/python3.14 -I ", helper)
        self.assertEqual(
            MODULE.ANDROID_TOOLCHAIN_LAUNCHER_LOADER_TEMPLATE,
            LAUNCHER_MODULE.ANDROID_TOOLCHAIN_LAUNCHER_LOADER_TEMPLATE,
        )
        bash_loader = provisioner[
            provisioner.index("cat <<'WINS_ANDROID_LAUNCHER_LOADER'\n")
            + len("cat <<'WINS_ANDROID_LAUNCHER_LOADER'\n") : provisioner.index(
                "WINS_ANDROID_LAUNCHER_LOADER\n",
                provisioner.index("cat <<'WINS_ANDROID_LAUNCHER_LOADER'\n")
                + len("cat <<'WINS_ANDROID_LAUNCHER_LOADER'\n"),
            )
        ]
        self.assertEqual(
            bash_loader,
            LAUNCHER_MODULE.ANDROID_TOOLCHAIN_LAUNCHER_LOADER_TEMPLATE,
        )
        for name, source in loader_copy_sources():
            self.assertEqual(
                source,
                LAUNCHER_MODULE.ANDROID_TOOLCHAIN_LAUNCHER_LOADER_TEMPLATE,
                name,
            )
            self.assertNotIn("'", source)
            self.assertIn("O_NONBLOCK", source)
            self.assertIn("fcntl", source)
        command = MODULE.owner_provision_command(HELPER)
        self.assertIn("/usr/bin/sudo -H --", command)
        self.assertIn("-I -S -c", command)
        self.assertIn(str(LAUNCHER), command)
        self.assertIn(str(PIN_MANIFEST), command)
        self.assertIn(sha256(LAUNCHER), command)
        self.assertIn("O_NONBLOCK", command)
        self.assertIn(f" {os.getuid()} {os.getgid()}", command)
        self.assertNotIn(" tools/launch_macos_release_android_toolchains.py", command)
        self.assertNotRegex(command, r"-I\s+['\"]?/")
        self.assertIn("LAUNCHER_NAME", helper)
        bundle_names = tuple(item[1] for item in MODULE.BOOTSTRAP_BUNDLE)
        self.assertNotIn(LAUNCHER.name, bundle_names)
        self.assertNotIn("release_obfuscation_contract.py", bundle_names)

    def test_post_launch_same_inode_overwrite_does_not_execute_hostile_bash(self) -> None:
        tools = self.case / "tools"
        tools.mkdir(mode=0o700)
        names = (
            (LAUNCHER, LAUNCHER.name),
            (PROVISIONER, PROVISIONER.name),
            (HELPER, HELPER.name),
            (CONTRACT, CONTRACT.name),
            (PIN_MANIFEST, PIN_MANIFEST.name),
        )
        copies: dict[str, Path] = {}
        originals: dict[str, bytes] = {}
        for src, name in names:
            target = tools / name
            target.write_bytes(src.read_bytes())
            target.chmod(0o600)
            copies[name] = target
            originals[name] = src.read_bytes()
        original_launcher = originals[LAUNCHER.name]
        namespace: dict = {"__name__": "wins_android_toolchain_launcher_held"}
        exec(compile(original_launcher, str(copies[LAUNCHER.name]), "exec"), namespace)
        namespace["__file__"] = str(copies[LAUNCHER.name])
        hostile_launcher = (
            b"print('LAUNCHER_PWNED')\nraise SystemExit('LAZY_PARSE_PWNED')\n"
        )
        hostile_provisioner = (
            b"#!/bin/bash\necho LAZY_PARSE_PWNED\nexit 0\n"
        )
        copies[LAUNCHER.name].write_bytes(hostile_launcher)
        copies[PROVISIONER.name].write_bytes(hostile_provisioner)
        self.assertEqual(copies[LAUNCHER.name].read_bytes(), hostile_launcher)
        self.assertEqual(copies[PROVISIONER.name].read_bytes(), hostile_provisioner)
        spawned: list[object] = []

        def refuse_spawn(*args: object, **kwargs: object) -> None:
            spawned.append((args, kwargs))
            raise AssertionError("overwritten Bash must not be executed")

        dest = self.case / "post-launch-bundle"
        with mock.patch.object(subprocess, "Popen", refuse_spawn), mock.patch.object(
            subprocess, "run", refuse_spawn
        ):
            with self.assertRaisesRegex(
                namespace["Refused"], "substituted Android toolchain provisioner"
            ):
                namespace["launch_authenticated_provisioner"](
                    copies[PIN_MANIFEST.name],
                    require_root=False,
                    dest=dest,
                    execute_provision=False,
                    tools_dir=tools,
                )
        self.assertEqual(spawned, [])
        self.assertFalse(dest.exists())
        copies[PROVISIONER.name].write_bytes(originals[PROVISIONER.name])
        copies[LAUNCHER.name].write_bytes(hostile_launcher)
        published = namespace["launch_authenticated_provisioner"](
            copies[PIN_MANIFEST.name],
            require_root=False,
            dest=dest,
            execute_provision=False,
            tools_dir=tools,
        )
        self.assertTrue(published)
        sealed_provisioner = dest / PROVISIONER.name
        self.assertEqual(sealed_provisioner.read_bytes(), originals[PROVISIONER.name])
        self.assertNotIn(b"LAZY_PARSE_PWNED", sealed_provisioner.read_bytes())
        self.assertEqual(copies[LAUNCHER.name].read_bytes(), hostile_launcher)

    def test_bash_lazy_parse_contrast_fixture_observes_post_start_overwrite(self) -> None:
        probe = self.case / "lazy-parse-contrast.sh"
        flag = self.case / "lazy-parse-checkpoint"
        original_tail = "echo ORIGINAL_TAIL_XXXX\n"
        hostile_tail = "echo LAZY_PARSE_PWNED__\n"
        self.assertEqual(len(original_tail.encode("ascii")), len(hostile_tail.encode("ascii")))
        header = (
            "#!/bin/bash\n"
            f"printf 'CHECKPOINT\\n' > {shlex.quote(str(flag))}\n"
            "sleep 6\n"
        )
        probe.write_bytes((header + original_tail).encode("ascii"))
        probe.chmod(0o700)
        proc = subprocess.Popen(
            ["/bin/bash", str(probe)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            waited = 0.0
            while not flag.exists():
                if proc.poll() is not None:
                    stdout, stderr = proc.communicate()
                    self.fail((stdout or "") + (stderr or "") + "contrast exited before checkpoint")
                if waited > 8:
                    proc.kill()
                    self.fail("contrast checkpoint was not created")
                waited += 0.05
                time.sleep(0.05)
            probe.write_bytes((header + hostile_tail).encode("ascii"))
            stdout, stderr = proc.communicate(timeout=20)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
        combined = (stdout or "") + (stderr or "")
        self.assertIn("LAZY_PARSE_PWNED", combined)
        command = MODULE.owner_provision_command(HELPER)
        self.assertNotIn("sudo /bin/bash -p " + str(PROVISIONER), command)
        self.assertIn("python3.14", command)
        self.assertIn(LAUNCHER.name, command)
        self.assertIn("/usr/bin/sudo -H --", command)
        self.assertIn("-I -S -c", command)
        self.assertIn(str(LAUNCHER), command)

    def _run_inline_loader(
        self,
        launcher: Path,
        manifest: Path,
        expected: str,
        *,
        uid: str | None = None,
        gid: str | None = None,
        extra: list[str] | None = None,
        cwd: Path | None = None,
        loader: str | None = None,
        timeout: float = 20,
    ) -> subprocess.CompletedProcess[str]:
        source = (
            loader
            if loader is not None
            else LAUNCHER_MODULE.android_toolchain_launcher_loader(expected)
        )
        if LAUNCHER_MODULE.LAUNCHER_SHA_PLACEHOLDER in source:
            source = source.replace(
                LAUNCHER_MODULE.LAUNCHER_SHA_PLACEHOLDER, expected
            )
        argv = [sys.executable, "-I", "-S", "-c", source, str(launcher), str(manifest)]
        if extra is not None:
            argv.extend(extra)
        else:
            argv.extend(
                [
                    str(os.getuid() if uid is None else uid),
                    str(os.getgid() if gid is None else gid),
                ]
            )
        return subprocess.run(
            argv,
            cwd=str(cwd or self.case),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def _run_fifo_toctou_loader(
        self,
        loader: str,
        launcher: Path,
        manifest: Path,
        expected: str,
        work: Path,
    ) -> subprocess.CompletedProcess[str]:
        source = loader.replace(LAUNCHER_MODULE.LAUNCHER_SHA_PLACEHOLDER, expected)
        probe = work / "fifo-toctou-probe.py"
        probe.write_text(
            "import fcntl, os, stat, sys\n"
            "path = sys.argv[1]\n"
            "manifest = sys.argv[2]\n"
            "uid = sys.argv[3]\n"
            "gid = sys.argv[4]\n"
            "clears = []\n"
            "real_fcntl = fcntl.fcntl\n"
            "def spy_fcntl(fd, cmd, *args):\n"
            "    if cmd == fcntl.F_SETFL:\n"
            "        clears.append(stat.S_ISREG(os.fstat(fd).st_mode))\n"
            "    return real_fcntl(fd, cmd, *args)\n"
            "fcntl.fcntl = spy_fcntl\n"
            "real_open = os.open\n"
            "def raced_open(p, flags, *a, **k):\n"
            "    if os.fspath(p) == path:\n"
            "        if not (flags & os.O_NONBLOCK):\n"
            "            raise SystemExit('O_NONBLOCK missing from open flags')\n"
            "        os.unlink(path)\n"
            "        os.mkfifo(path)\n"
            "    return real_open(p, flags, *a, **k)\n"
            "os.open = raced_open\n"
            "sys.argv = ['-c', path, manifest, uid, gid]\n"
            "try:\n"
            f"    exec(compile({source!r}, '-c', 'exec'), {{'__name__': 'fifo_toctou'}})\n"
            "except SystemExit as suc:\n"
            "    sys.stderr.write('SETFL_REGULAR=' + repr(clears) + '\\n')\n"
            "    raise suc\n"
            "raise SystemExit('loader returned without SystemExit')\n",
            encoding="ascii",
        )
        return subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                str(probe),
                str(launcher),
                str(manifest),
                str(os.getuid()),
                str(os.getgid()),
            ],
            cwd=str(work),
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )

    def test_authenticated_inline_loader_reproduces_hostile_prestart_paths(self) -> None:
        work = self.case / "inline-loader"
        work.mkdir(mode=0o700)
        manifest = work / "toolchain-pins.json"
        manifest.write_text("{}\n", encoding="ascii")
        payload = b"print('LOADED_OK')\n"
        expected = hashlib.sha256(payload).hexdigest()
        launcher = work / "launch_macos_release_android_toolchains.py"
        launcher.write_bytes(payload)
        launcher.chmod(0o644)

        completed = self._run_inline_loader(launcher, manifest, expected)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("LOADED_OK", completed.stdout)

        launcher.write_bytes(b"print('LAUNCHER_PWNED')\n")
        replaced = self._run_inline_loader(launcher, manifest, expected)
        self.assertNotEqual(replaced.returncode, 0)
        self.assertIn("stale or substituted Android toolchain launcher rejected", replaced.stderr)
        self.assertNotIn("LAUNCHER_PWNED", replaced.stdout)

        launcher.write_bytes(payload)
        launcher.chmod(0o644)
        linked = work / "launch-symlink.py"
        linked.symlink_to(launcher)
        sym = self._run_inline_loader(linked, manifest, expected)
        self.assertNotEqual(sym.returncode, 0)
        self.assertIn("launcher identity is unsafe", sym.stderr)

        hard = work / "launch-hardlink.py"
        os.link(launcher, hard)
        hardlink = self._run_inline_loader(launcher, manifest, expected)
        self.assertNotEqual(hardlink.returncode, 0)
        self.assertIn("launcher identity is unsafe", hardlink.stderr)
        hard.unlink()

        fifo = work / "launch-fifo.py"
        os.mkfifo(fifo)
        fifo_run = self._run_inline_loader(fifo, manifest, expected, timeout=2)
        self.assertNotEqual(fifo_run.returncode, 0)
        self.assertIn("launcher identity is unsafe", fifo_run.stderr)

        sock_dir = Path(tempfile.mkdtemp(prefix="wls.", dir=str(PRIVATE_TMP)))
        sock_dir.chmod(0o700)
        self.addCleanup(lambda: shutil.rmtree(sock_dir, ignore_errors=True))
        sock_path = sock_dir / "s"
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.bind(str(sock_path))
            sock_run = self._run_inline_loader(sock_path, manifest, expected, timeout=2)
        finally:
            sock.close()
        self.assertNotEqual(sock_run.returncode, 0)
        self.assertIn("launcher identity is unsafe", sock_run.stderr)

        writable = work / "launch-groupwrite.py"
        writable.write_bytes(payload)
        writable.chmod(0o664)
        group = self._run_inline_loader(writable, manifest, expected)
        self.assertNotEqual(group.returncode, 0)
        self.assertIn("launcher identity is unsafe", group.stderr)

        missing = self._run_inline_loader(launcher, manifest, expected, extra=["0", "20"])
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("SUDO_UID is missing", missing.stderr)
        omitted = self._run_inline_loader(launcher, manifest, expected, extra=[])
        self.assertNotEqual(omitted.returncode, 0)
        self.assertIn("authenticated launcher loader arguments are malformed", omitted.stderr)

        relative = self._run_inline_loader(
            Path("launch_macos_release_android_toolchains.py"),
            manifest,
            expected,
            cwd=work,
        )
        self.assertNotEqual(relative.returncode, 0)
        self.assertIn("absolute launcher and manifest paths are required", relative.stderr)

        launcher.write_bytes(payload)
        launcher.chmod(0o644)
        real_read = os.read

        def overwrite_during_read(fd: int, n: int) -> bytes:
            launcher.write_bytes(b"print('SAME_INODE_PWNED')\n")
            return real_read(fd, n)

        with mock.patch.object(os, "read", overwrite_during_read):
            with mock.patch.object(
                sys,
                "argv",
                ["-c", str(launcher), str(manifest), str(os.getuid()), str(os.getgid())],
            ):
                with self.assertRaises(SystemExit) as raised:
                    exec(
                        compile(
                            LAUNCHER_MODULE.android_toolchain_launcher_loader(expected),
                            "-c",
                            "exec",
                        ),
                        {"__name__": "wins_inline_loader"},
                    )
        self.assertRegex(
            str(raised.exception).lower(),
            r"launcher (changed while it was read|was replaced after it was opened|current bytes could not be held|identity is unsafe)",
        )
        self.assertNotIn("SAME_INODE_PWNED", str(raised.exception))

        launcher.write_bytes(payload)
        launcher.chmod(0o644)
        after_hold = self._run_inline_loader(launcher, manifest, expected)
        self.assertEqual(after_hold.returncode, 0, after_hold.stderr)
        self.assertIn("LOADED_OK", after_hold.stdout)
        launcher.write_bytes(b"print('POST_HOLD_PWNED')\n")
        held_again = self._run_inline_loader(
            launcher,
            manifest,
            hashlib.sha256(payload).hexdigest(),
        )
        self.assertNotEqual(held_again.returncode, 0)
        self.assertNotIn("POST_HOLD_PWNED", held_again.stdout)

    def test_loader_copies_fail_closed_on_fifo_toctou_and_specials(self) -> None:
        payload = b"print('LOADED_OK')\n"
        expected = hashlib.sha256(payload).hexdigest()
        copies = loader_copy_sources()
        self.assertEqual(len(copies), 3)
        for left, right in zip(copies, copies[1:]):
            self.assertEqual(left[1], right[1])
        fail_closed = (
            r"replaced before it was opened|not a readable regular file|"
            r"identity is unsafe"
        )
        for name, source in copies:
            work = self.case / f"loader-copies-{name}"
            work.mkdir(mode=0o700)
            manifest = work / "toolchain-pins.json"
            manifest.write_text("{}\n", encoding="ascii")
            launcher = work / "launch_macos_release_android_toolchains.py"

            def write_regular_launcher() -> None:
                if launcher.exists() or launcher.is_fifo() or launcher.is_symlink():
                    launcher.unlink()
                launcher.write_bytes(payload)
                launcher.chmod(0o644)

            with self.subTest(copy=name, case="regular_held_bytes"):
                write_regular_launcher()
                held = self._run_inline_loader(
                    launcher,
                    manifest,
                    expected,
                    loader=source,
                    timeout=8,
                )
                self.assertEqual(held.returncode, 0, held.stderr)
                self.assertIn("LOADED_OK", held.stdout)
                in_proc_clears: list[bool] = []
                real_fcntl = fcntl.fcntl

                def spy_fcntl_inproc(fd: int, cmd: int, *args: object):
                    if cmd == fcntl.F_SETFL:
                        in_proc_clears.append(stat.S_ISREG(os.fstat(fd).st_mode))
                    return real_fcntl(fd, cmd, *args)

                with mock.patch.object(fcntl, "fcntl", spy_fcntl_inproc):
                    with mock.patch.object(
                        sys,
                        "argv",
                        [
                            "-c",
                            str(launcher),
                            str(manifest),
                            str(os.getuid()),
                            str(os.getgid()),
                        ],
                    ):
                        exec(
                            compile(
                                source.replace(
                                    LAUNCHER_MODULE.LAUNCHER_SHA_PLACEHOLDER,
                                    expected,
                                ),
                                "-c",
                                "exec",
                            ),
                            {"__name__": f"wins_loader_{name}_regular"},
                        )
                self.assertEqual(in_proc_clears, [True])

            with self.subTest(copy=name, case="fifo_toctou"):
                write_regular_launcher()
                raced = self._run_fifo_toctou_loader(
                    source, launcher, manifest, expected, work
                )
                combined = (raced.stdout or "") + (raced.stderr or "")
                self.assertNotEqual(raced.returncode, 0, combined)
                self.assertRegex(combined, fail_closed)
                self.assertIn("SETFL_REGULAR=[]", raced.stderr)
                self.assertNotIn("LOADED_OK", raced.stdout)
                self.assertNotIn("O_NONBLOCK missing from open flags", combined)

            with self.subTest(copy=name, case="static_fifo"):
                fifo = work / "static-fifo"
                if fifo.exists() or fifo.is_fifo():
                    fifo.unlink()
                os.mkfifo(fifo)
                static_fifo = self._run_inline_loader(
                    fifo, manifest, expected, loader=source, timeout=2
                )
                self.assertNotEqual(static_fifo.returncode, 0)
                self.assertIn("launcher identity is unsafe", static_fifo.stderr)

            with self.subTest(copy=name, case="symlink"):
                write_regular_launcher()
                linked = work / "launch-symlink.py"
                if linked.exists() or linked.is_symlink():
                    linked.unlink()
                linked.symlink_to(launcher)
                sym = self._run_inline_loader(
                    linked, manifest, expected, loader=source, timeout=2
                )
                self.assertNotEqual(sym.returncode, 0)
                self.assertIn("launcher identity is unsafe", sym.stderr)

            with self.subTest(copy=name, case="hardlink"):
                write_regular_launcher()
                hard = work / "launch-hardlink.py"
                if hard.exists():
                    hard.unlink()
                os.link(launcher, hard)
                try:
                    hardlink = self._run_inline_loader(
                        launcher, manifest, expected, loader=source, timeout=2
                    )
                finally:
                    hard.unlink()
                self.assertNotEqual(hardlink.returncode, 0)
                self.assertIn("launcher identity is unsafe", hardlink.stderr)

            with self.subTest(copy=name, case="socket"):
                sock_dir = Path(tempfile.mkdtemp(prefix="wls.", dir=str(PRIVATE_TMP)))
                sock_dir.chmod(0o700)
                sock_path = sock_dir / "s"
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    sock.bind(str(sock_path))
                    sock_run = self._run_inline_loader(
                        sock_path, manifest, expected, loader=source, timeout=2
                    )
                finally:
                    sock.close()
                    shutil.rmtree(sock_dir, ignore_errors=True)
                self.assertNotEqual(sock_run.returncode, 0)
                self.assertIn("launcher identity is unsafe", sock_run.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
