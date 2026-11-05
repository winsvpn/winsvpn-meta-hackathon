#!/usr/bin/env python3
"""Hostile tests for root-provisioned macOS Go custody."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "release_go_archive_custody.py"
PROVISIONER = ROOT / "tools" / "provision_macos_release_go_runtime.sh"
SPEC = importlib.util.spec_from_file_location("release_go_owner_runtime", TOOL)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Go custody controller")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def thaw_remove(path: Path) -> None:
    if not path.exists():
        return
    for base, directories, files in os.walk(path, topdown=False, followlinks=False):
        base_path = Path(base)
        for name in files + directories:
            child = base_path / name
            if child.is_symlink():
                continue
            try:
                child.chmod(0o700 if child.is_dir() else 0o600)
            except FileNotFoundError:
                pass
        try:
            base_path.chmod(0o700)
        except FileNotFoundError:
            pass
    shutil.rmtree(path, ignore_errors=True)


def clear_extended_attributes(path: Path) -> None:
    paths = [path]
    if path.is_dir():
        paths.extend(
            Path(base) / name
            for base, directories, files in os.walk(path)
            for name in directories + files
        )
    for current in paths:
        if current.is_symlink():
            continue
        original_mode = stat.S_IMODE(current.lstat().st_mode)
        current.chmod(original_mode | stat.S_IWUSR)
        try:
            subprocess.run(
                ["/usr/bin/xattr", "-c", str(current)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        finally:
            current.chmod(original_mode)


class OwnerRuntimeProvisioningTest(unittest.TestCase):
    def setUp(self) -> None:
        self.case = Path(
            tempfile.mkdtemp(prefix="wins-go-owner-runtime.", dir="/private/tmp")
        )
        self.case.chmod(0o700)
        self.addCleanup(thaw_remove, self.case)
        self.library = self.case / "Library" / "WinsVPN"
        self.library.mkdir(parents=True, mode=0o755)
        os.chown(self.library, os.getuid(), os.getgid())
        self.runtime_prefix = self.library / "ReleaseGo"
        self.bootstrap_prefix = self.library / "ReleaseGoBootstrap"
        self.bootstrap = self.bootstrap_prefix / ("b" * 64)
        self.bootstrap.mkdir(parents=True, mode=0o755)
        self.archive = self.bootstrap / "go1.27.1.darwin-arm64.tar.gz"
        self._write_archive(self.archive)
        clear_extended_attributes(self.archive)
        self.archive.chmod(0o444)
        self.reference_parent = self.case / "reference"
        self.reference = MODULE.safe_extract(self.archive, self.reference_parent, "go")
        self.tree_sha = MODULE.tree_hash(self.reference)
        self.binary_sha = digest(self.reference / "bin/go")
        self.pin = {
            "version": "1.27.1",
            "platform": "darwin-arm64",
            "architecture": "arm64",
            "archive_format": "tar.gz",
            "archive": str(self.case / "decoy-download.tar.gz"),
            "archive_sha": digest(self.archive),
            "tree_sha": self.tree_sha,
            "root": "go",
            "executable": "bin/go",
            "executable_sha": self.binary_sha,
        }
        self.authorized = (b"controller", b"wrapper", b"manifest", b"trust")
        self.issuance = {
            "issuance_id": "a" * 32,
            "source_freeze_producer_sha256": "f" * 64,
        }
        self.materials = {
            "controller_sha256": hashlib.sha256(b"controller").hexdigest(),
            "wrapper_sha256": hashlib.sha256(b"wrapper").hexdigest(),
            "provisioner_sha256": hashlib.sha256(b"provisioner").hexdigest(),
            "manifest_sha256": hashlib.sha256(b"manifest").hexdigest(),
            "trust_anchor_sha256": hashlib.sha256(b"trust").hexdigest(),
            "source_freeze_producer_sha256": "f" * 64,
        }
        self.repo = self.case / "repo"
        (self.repo / "tools").mkdir(parents=True)
        self.manifest = self.repo / "tools/toolchain-pins.json"
        self.provisioner = self.repo / "tools/provision_macos_release_go_runtime.sh"
        self.manifest.write_bytes(b"manifest")
        self.provisioner.write_bytes(b"provisioner")

    def _write_archive(self, archive: Path) -> None:
        tar_path = archive.with_suffix(".tar")
        entries = (
            ("go", "dir", b"", 0o755),
            ("go/bin", "dir", b"", 0o755),
            ("go/src", "dir", b"", 0o755),
            ("go/bin/go", "file", b"synthetic-go-executable\n", 0o755),
            ("go/src/LICENSE", "file", b"synthetic-license\n", 0o644),
        )
        with tarfile.open(tar_path, "w", format=tarfile.USTAR_FORMAT) as bundle:
            for name, kind, payload, mode in entries:
                member = tarfile.TarInfo(name)
                member.uid = 0
                member.gid = 0
                member.uname = ""
                member.gname = ""
                member.mtime = 0
                member.mode = mode
                if kind == "dir":
                    member.type = tarfile.DIRTYPE
                    bundle.addfile(member)
                else:
                    member.type = tarfile.REGTYPE
                    member.size = len(payload)
                    bundle.addfile(member, io.BytesIO(payload))
        with tar_path.open("rb") as raw, archive.open("wb") as output:
            with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as gz:
                gz.write(raw.read())
        tar_path.unlink()

    def _patches(self):
        uid = os.getuid()
        gid = os.getgid()
        return (
            mock.patch.object(MODULE, "OWNER_LIBRARY_ROOT", self.library),
            mock.patch.object(MODULE, "OWNER_RUNTIME_PREFIX", self.runtime_prefix),
            mock.patch.object(MODULE, "OWNER_BOOTSTRAP_PREFIX", self.bootstrap_prefix),
            mock.patch.object(MODULE, "_owner_identity", return_value=(uid, gid)),
            mock.patch.object(MODULE, "_verify_owner_ancestors", return_value=None),
            mock.patch.object(MODULE, "_require_system_immutable", return_value=None),
            mock.patch.object(MODULE, "authorize_repo", return_value=self.authorized),
            mock.patch.object(MODULE, "_bind_external_issuance", return_value=self.issuance),
            mock.patch.object(MODULE, "parse_pin_bytes", return_value=self.pin),
            mock.patch.object(MODULE, "_owner_material_digests", return_value=self.materials),
            mock.patch.object(
                MODULE,
                "verify_sealed_bootstrap",
                return_value={"path": str(self.bootstrap), "identity": "b" * 64},
            ),
            mock.patch.object(MODULE, "_publish_directory_exclusive", side_effect=os.rename),
            mock.patch.object(MODULE, "_clear_allowed_owner_xattrs", return_value=None),
            mock.patch.object(MODULE, "reject_all_acl_and_xattr", return_value=None),
        )

    def _provision(self) -> str:
        patches = self._patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], patches[10], patches[11], patches[12], patches[13]:
            return MODULE.provision_owner_runtime(
                str(self.repo),
                str(self.manifest),
                str(self.provisioner),
                require_root=False,
                apply_kernel_seal=False,
            )

    def test_provision_is_exact_and_idempotent(self) -> None:
        first = self._provision()
        second = self._provision()
        runtime = self.runtime_prefix / "1.27.1"
        self.assertEqual(first, f"provisioned {runtime}")
        self.assertEqual(second, f"already provisioned at {runtime}")
        self.assertEqual(stat.S_IMODE(runtime.stat().st_mode), 0o555)
        self.assertEqual(stat.S_IMODE((runtime / "extracted/go/bin/go").stat().st_mode), 0o555)
        self.assertEqual(stat.S_IMODE((runtime / "extracted/go/src/LICENSE").stat().st_mode), 0o444)
        self.assertEqual(digest(runtime / "archive" / self.archive.name), self.pin["archive_sha"])
        self.assertFalse((self.case / "decoy-download.tar.gz").exists())

    def test_preprovision_squat_is_refused_without_replacement(self) -> None:
        self.runtime_prefix.mkdir(parents=True, mode=0o755)
        destination = self.runtime_prefix / "1.27.1"
        destination.write_bytes(b"decoy\n")
        original = destination.read_bytes()
        with self.assertRaisesRegex(MODULE.Refused, "refusing to replace"):
            self._provision()
        self.assertEqual(destination.read_bytes(), original)

    def test_copy_failure_rolls_back_only_private_staging(self) -> None:
        patches = self._patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], patches[10], patches[11], patches[12], patches[13], mock.patch.object(
            MODULE, "copy_stable", side_effect=MODULE.Refused("injected copy failure")
        ):
            with self.assertRaisesRegex(MODULE.Refused, "injected copy failure"):
                MODULE.provision_owner_runtime(
                    str(self.repo),
                    str(self.manifest),
                    str(self.provisioner),
                    require_root=False,
                    apply_kernel_seal=False,
                )
        self.assertFalse((self.runtime_prefix / "1.27.1").exists())
        self.assertEqual(list(self.runtime_prefix.glob(".go-provisioning.*")), [])

    def test_mid_publish_decoy_is_preserved_and_staging_removed(self) -> None:
        patches = self._patches()

        def inject(staging: Path, destination: Path) -> None:
            destination.write_bytes(b"attacker-decoy\n")
            raise MODULE.Refused("injected exclusive publication race")

        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], patches[10], patches[13], mock.patch.object(
            MODULE, "_publish_directory_exclusive", side_effect=inject
        ):
            with self.assertRaisesRegex(MODULE.Refused, "publication race"):
                MODULE.provision_owner_runtime(
                    str(self.repo),
                    str(self.manifest),
                    str(self.provisioner),
                    require_root=False,
                    apply_kernel_seal=False,
                )
        destination = self.runtime_prefix / "1.27.1"
        self.assertEqual(destination.read_bytes(), b"attacker-decoy\n")
        self.assertEqual(list(self.runtime_prefix.glob(".go-provisioning.*")), [])

    def test_library_cleanup_is_categorically_refused(self) -> None:
        for path in (Path("/Library/WinsVPN/ReleaseGo/1.27.1"), Path("/Library/decoy")):
            with self.assertRaisesRegex(MODULE.Refused, "categorically refuses"):
                MODULE._destroy_runtime(path)
            with self.assertRaisesRegex(MODULE.Refused, "categorically refuses"):
                MODULE.cleanup(str(path), "decoy")

    def test_owner_tree_rejects_symlink_and_cross_device(self) -> None:
        root = self.reference
        clear_extended_attributes(root)
        for base, directories, files in os.walk(root, topdown=False):
            base_path = Path(base)
            for name in files:
                path = base_path / name
                path.chmod(0o555 if path == root / "bin/go" else 0o444)
            for name in directories:
                (base_path / name).chmod(0o555)
            base_path.chmod(0o555)
        with mock.patch.object(MODULE, "_owner_identity", return_value=(os.getuid(), 0)), mock.patch.object(
            MODULE, "_require_system_immutable", return_value=None
        ), mock.patch.object(MODULE, "reject_all_acl_and_xattr", return_value=None):
            expected = MODULE.tree_hash(root, owner_runtime=True)
            self.assertEqual(expected, self.tree_sha)
            (root / "src").chmod(0o755)
            (root / "src/link").symlink_to("LICENSE")
            (root / "src").chmod(0o555)
            with self.assertRaisesRegex(MODULE.Refused, "symbolic link"):
                MODULE.tree_hash(root, owner_runtime=True)


class ReleaseGoEnvironmentTest(unittest.TestCase):
    def setUp(self) -> None:
        self.case = Path(tempfile.mkdtemp(prefix="wins-go-env.", dir="/private/tmp"))
        self.addCleanup(shutil.rmtree, self.case, True)
        (self.case / "state/home").mkdir(parents=True)
        (self.case / "state/tmp").mkdir()

    def test_cross_abi_allowlist_and_offline_default(self) -> None:
        selected = {
            "GOOS": "ios",
            "GOARCH": "arm64",
            "GOARM": "7",
            "CGO_ENABLED": "1",
            "CC": "/usr/bin/xcrun --sdk iphoneos clang",
            "CXX": "/usr/bin/xcrun --sdk iphoneos clang++",
            "CGO_CFLAGS": "-O2 -fembed-bitcode",
            "CGO_LDFLAGS": "-Wl,-dead_strip",
            "GOMODCACHE": str(self.case / "gomodcache"),
        }
        with mock.patch.dict(os.environ, selected, clear=True):
            result = MODULE._validated_go_environment(self.case, Path("/sealed/go"))
        for key, value in selected.items():
            self.assertEqual(result[key], value)
        self.assertEqual(result["GOFLAGS"], "-mod=readonly")
        self.assertEqual(result["GOPROXY"], "off")
        self.assertEqual(result["GOTOOLCHAIN"], "local")
        self.assertEqual(result["GOENV"], "off")
        self.assertEqual(result["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")

    def test_hostile_ambient_go_and_invalid_cross_values_fail(self) -> None:
        cases = (
            ({"WINS_RELEASE_GO": "/tmp/go"}, "WINS_RELEASE_GO"),
            ({"GOROOT": "/tmp/ambient"}, "GOROOT"),
            ({"CGO_ENABLED": "yes"}, "CGO_ENABLED"),
            ({"GOARCH": "arm64;evil"}, "GOARCH"),
            ({"GOMODCACHE": "relative/cache"}, "GOMODCACHE"),
        )
        for environment, message in cases:
            with self.subTest(environment=environment), mock.patch.dict(
                os.environ, environment, clear=True
            ), self.assertRaisesRegex(MODULE.Refused, message):
                MODULE._validated_go_environment(self.case, Path("/sealed/go"))

    def test_unapproved_go_environment_is_not_forwarded(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"GOOGLE_APPLICATION_CREDENTIALS": "/secret"},
            clear=True,
        ):
            result = MODULE._validated_go_environment(self.case, Path("/sealed/go"))
        self.assertNotIn("GOOGLE_APPLICATION_CREDENTIALS", result)
        with mock.patch.dict(os.environ, {"GOBIN": ""}, clear=True):
            with self.assertRaisesRegex(MODULE.Refused, "GOBIN"):
                MODULE._validated_go_environment(self.case, Path("/sealed/go"))

    def test_timeout_contract_exceeds_old_300_second_limit(self) -> None:
        self.assertGreater(MODULE.DEFAULT_RUN_TIMEOUT, 300)
        self.assertGreaterEqual(MODULE.MAX_RUN_TIMEOUT, MODULE.DEFAULT_RUN_TIMEOUT)
        source = (ROOT / "tools/release_go_archive_custody.sh").read_text(encoding="utf-8")
        self.assertIn("WINS_RELEASE_GO_TIMEOUT_SECONDS", source)
        self.assertIn('"$timeout" -- "$@"', source)

    def test_darwin_private_clone_is_never_an_execution_fallback(self) -> None:
        with mock.patch.object(MODULE.sys, "platform", "darwin"):
            with self.assertRaisesRegex(MODULE.Refused, "root-provisioned sealed tree"):
                MODULE.clone_execution_tree(self.case, self.case)


class ProvisionerContractTest(unittest.TestCase):
    def test_shell_is_syntax_valid_and_never_invokes_sudo(self) -> None:
        result = os.spawnv(os.P_WAIT, "/bin/bash", ["bash", "-n", str(PROVISIONER)])
        self.assertEqual(result, 0)
        source = PROVISIONER.read_text(encoding="utf-8")
        self.assertIn("/usr/bin/sudo -H --", source)
        self.assertNotIn("sudo -S", source)
        self.assertNotIn("osascript", source)
        self.assertNotIn("SUDO_ASKPASS=", source)
        self.assertIn("ReleaseGoBootstrap", source)
        self.assertIn("/Library/WinsVPN/ReleaseGoInputs/sha256", source)
        self.assertIn("declared_archive_path", source)
        self.assertIn("SF_IMMUTABLE", source)
        self.assertIn('libc.listxattr.restype = ctypes.c_ssize_t', source)
        self.assertIn('hasattr(os, "listxattr")', source)
        self.assertIn("renameatx_np", source)
        self.assertIn("sealed_controller", source)
        self.assertIn('source = bind(\n        sealed_controller,', source)
        self.assertIn("sealed Go controller digest mismatch before execution", source)
        self.assertEqual(source.count("subprocess.run("), 1)
        self.assertIn('exec(compile(source, str(sealed_controller), "exec"), namespace)', source)

    def test_controller_has_no_live_darwin_clone_or_library_cleanup(self) -> None:
        source = TOOL.read_text(encoding="utf-8")
        clone_start = source.index("def clone_execution_tree(")
        clone_end = source.index("\n\nclass BoundParent", clone_start)
        darwin_branch = source[clone_start:clone_end]
        self.assertNotIn("fclonefileat", darwin_branch)
        self.assertIn("root-provisioned sealed tree", darwin_branch)
        self.assertIn("Go cleanup categorically refuses every /Library path", source)


if __name__ == "__main__":
    unittest.main()
